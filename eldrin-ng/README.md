# Eldrin Angular Frontend

This is the Angular frontend application for the Eldrin project. It provides a user interface for interacting with the Eldrin modular backend system.

## Features

- User authentication (Email/Password, Google, GitHub)
- Protected dashboard area
- About page with project information
- Integration with Eldrin Core backend

## Getting Started

### Prerequisites

- Node.js (v18.x or later)
- npm (v9.x or later)
- Eldrin Core backend running

### Installation

1. Clone the repository
2. Navigate to the project directory
3. Install dependencies:

```bash
npm install
```

### Development

To start the development server:

```bash
npm start
```

This will launch the application at `http://localhost:4200/` and automatically open it in your default browser.

### Building for Production

To build the application for production:

```bash
npm run build
```

The build artifacts will be stored in the `dist/` directory.

## Project Structure

- `src/app/components/` - All application components
- `src/app/services/` - Services for API communication and authentication
- `src/app/models/` - Data models and interfaces
- `src/app/guards/` - Route guards for protected routes

## Integration with Eldrin Core

This Angular application is designed to work with the Eldrin Core backend. The API communication is handled through the `AuthService` which makes HTTP requests to the backend endpoints.

## License

This project is licensed under the same license as the Eldrin project.