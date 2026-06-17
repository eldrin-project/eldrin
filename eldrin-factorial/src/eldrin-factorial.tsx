import './index.css';
import React from 'react';
import ReactDOMClient from 'react-dom/client';
import singleSpaReact from 'single-spa-react';
import { createApp, combineLifecycles, DatabaseProvider } from '@eldrin-project/eldrin-app-react';
import { Root, type RootProps } from './root.component';

function getOrCreateContainer(): HTMLElement {
  const containerId = 'single-spa-application:eldrin-factorial';
  let container = document.getElementById(containerId);
  if (!container) {
    container = document.createElement('div');
    container.id = containerId;
    const mainContent = document.querySelector('main .p-6') || document.body;
    mainContent.appendChild(container);
  }
  return container;
}

const eldrinLifecycle = createApp({ name: 'eldrin-factorial' });

const reactLifecycle = singleSpaReact({
  React,
  ReactDOMClient,
  rootComponent: (props: RootProps) => (
    <DatabaseProvider>
      <Root {...props} />
    </DatabaseProvider>
  ),
  domElementGetter: getOrCreateContainer,
  errorBoundary(err) {
    return <div className="p-4 bg-red-50 text-red-700 rounded">Error loading Factorial app: {err.message}</div>;
  },
});

const lifecycles = combineLifecycles(eldrinLifecycle, reactLifecycle);
export const bootstrap = lifecycles.bootstrap;
export const mount = lifecycles.mount;
export const unmount = lifecycles.unmount;
