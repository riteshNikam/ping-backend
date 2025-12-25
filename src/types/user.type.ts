export interface User {
  id: string;
  username: string;
  email: string;
  password_hash: string; // Always exclude this when sending data to the client
  display_name?: string;
  avatar_url?: string;
  bio?: string;
  status_text?: string;
  created_at: Date;
  updated_at: Date;
  deleted: Boolean;
}

// Type for creating a new user (Registration)
export type CreateUserInput = Pick<User, 'username' | 'email' | 'password_hash'>;

// Type for public profile (Searching/Discovery)
export type PublicUser = Pick<User, 'id' | 'username' | 'display_name' | 'avatar_url' >;