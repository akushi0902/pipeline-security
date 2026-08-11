import { setupServer } from 'msw/node';
import { catalogueHandlers } from './handlers/catalogue';

export const server = setupServer(...catalogueHandlers);
