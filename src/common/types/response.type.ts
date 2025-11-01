export type APIResponse<T> = {
  status: Status;
  data: T;
  errors?: any;
  message?: string;
  metadata?: Metadata;
};

export type Metadata = {
  total?: number;
  page?: number;
  lastPage?: number;
  limit?: number;
  queryTotal?: number;
  filename?: string;
  messages?: string[] | string;
};

export enum Status {
  SUCCESS = 'success',
  ERROR = 'error',
  WARNING = 'warning',
  INFO = 'info',
}
