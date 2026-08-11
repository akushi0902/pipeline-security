import { setupServer } from 'msw/node';
import { catalogueHandlers } from './handlers/catalogue';
import { adminHandlers } from './handlers/admin';

export const server = setupServer(...catalogueHandlers, ...adminHandlers);
