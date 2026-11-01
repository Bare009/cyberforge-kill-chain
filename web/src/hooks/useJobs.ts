import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { CurrentJob, Job, JobRequest, RunList, UploadListing } from '@/types/jobs'

/** GET /uploads: logs already in the API's raw folder, partial uploads, defaults. */
export function useUploads() {
  return useQuery({
    queryKey: ['uploads'],
    queryFn: async () => (await api.get<UploadListing>('/uploads')).data,
    staleTime: 5_000,
  })
}

/** GET /runs: the analysed runs, the served one first. */
export function useRuns() {
  return useQuery({
    queryKey: ['runs'],
    queryFn: async () => (await api.get<RunList>('/runs')).data,
    staleTime: 5_000,
  })
}

/** GET /jobs/current, every second while a job runs. */
export function useCurrentJob() {
  return useQuery({
    queryKey: ['job'],
    queryFn: async () => (await api.get<CurrentJob>('/jobs/current', { timeout: 10_000 })).data,
    refetchInterval: (q) => (q.state.data?.job?.state === 'running' ? 1_000 : false),
    staleTime: 0,
  })
}

export function useStartJob() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: JobRequest) => (await api.post<Job>('/jobs', body)).data,
    onSuccess: (job) => qc.setQueryData<CurrentJob>(['job'], { enabled: true, job }),
  })
}

export function useCancelJob() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () => (await api.post<Job>('/jobs/current/cancel')).data,
    onSuccess: (job) => qc.setQueryData<CurrentJob>(['job'], { enabled: true, job }),
  })
}

/**
 * Every query of the old run is stale once the API serves another one. Keep the job and
 * upload lists (they are not per run) and refetch the rest.
 */
export function invalidateRunData(qc: ReturnType<typeof useQueryClient>) {
  return qc.invalidateQueries({ predicate: (q) => !['job'].includes(String(q.queryKey[0])) })
}

/** POST /runs/select: serve another run, then reload every page's data. */
export function useSelectRun() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (run: string) => (await api.post<{ active: string }>('/runs/select', { run })).data,
    onSuccess: () => invalidateRunData(qc),
  })
}
