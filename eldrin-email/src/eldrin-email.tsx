/**
 * Single-spa entry point for Eldrin shell integration.
 *
 * The CSS import below is needed for production builds (Vite extracts it
 * as a separate file for the shell's loadAppStyles() pipeline). In dev mode,
 * devShellCompat strips this import to prevent Vite HMR from injecting
 * unscoped CSS into the shell — instead the CSS endpoint serves processed
 * CSS that the shell fetches and wraps with @scope.
 */

import './index.css';
import React from 'react';
import ReactDOMClient from 'react-dom/client';
import singleSpaReact from 'single-spa-react';
import {
  createApp,
  combineLifecycles,
  DatabaseProvider,
} from '@eldrin-project/eldrin-app-react';
import { Root, type RootProps } from './root.component';

function getOrCreateContainer(): HTMLElement {
  const containerId = 'single-spa-application:eldrin-email';
  let container = document.getElementById(containerId);

  if (!container) {
    container = document.createElement('div');
    container.id = containerId;
    const mainContent = document.querySelector('main .p-6') || document.body;
    mainContent.appendChild(container);
  }

  return container;
}

const eldrinLifecycle = createApp({
  name: 'eldrin-email',
  onMigrationsComplete: (result) => {
    console.log('[eldrin-email] Migrations complete:', result.executed);
  },
});

const reactLifecycle = singleSpaReact({
  React,
  ReactDOMClient,
  rootComponent: (props: RootProps) => (
    <DatabaseProvider>
      <Root {...props} />
    </DatabaseProvider>
  ),
  domElementGetter: getOrCreateContainer,
  errorBoundary(err, _info, _props) {
    return (
      <div className="p-4 bg-red-50 text-red-700 rounded">
        Error loading Email app: {err.message}
      </div>
    );
  },
});

const lifecycles = combineLifecycles(eldrinLifecycle, reactLifecycle);

export const { bootstrap, mount, unmount } = lifecycles;
