# elm_practice
elm練習用
import {
  computed,
  DestroyRef,
  effect,
  EffectRef,
  inject,
  Injector,
  Signal,
  signal,
  untracked,
  ValueEqualityFn,
} from '@angular/core';

export type ResourceStatus18 =
  | 'idle'
  | 'error'
  | 'loading'
  | 'reloading'
  | 'resolved';

export interface ResourceLoaderParams18<R> {
  params: Exclude<R, undefined>;
  previous: {status: ResourceStatus18};
  abortSignal: AbortSignal;
}

export interface ResourceOptions18<T, R> {
  params: () => R | undefined;
  loader: (params: ResourceLoaderParams18<R>) => PromiseLike<T>;
  defaultValue?: T;
  equal?: ValueEqualityFn<T>;
  injector?: Injector;
}

export interface ResourceRef18<T> {
  readonly value: Signal<T>;
  readonly status: Signal<ResourceStatus18>;
  readonly error: Signal<Error | undefined>;
  readonly isLoading: Signal<boolean>;
  hasValue(
    this: T extends undefined ? this : never,
  ): this is ResourceRef18<Exclude<T, undefined>>;
  hasValue(): boolean;
  reload(): boolean;
  destroy(): void;
}

interface ResourceState18<T, R> {
  request: R | undefined;
  handledReload: number;
  destroyed: boolean;
  status: ResourceStatus18;
  value: T | undefined;
  error: Error | undefined;
}

export function resource18<T, R>(
  options: ResourceOptions18<T, R> & {defaultValue: T},
): ResourceRef18<T>;
export function resource18<T, R>(
  options: ResourceOptions18<T, R>,
): ResourceRef18<T | undefined>;
export function resource18<T, R>(
  options: ResourceOptions18<T, R>,
): ResourceRef18<T | undefined> {
  const injector = options.injector ?? inject(Injector);
  const params = computed(options.params);
  const reloadTrigger = signal(0);
  const state = signal<ResourceState18<T, R>>({
    request: undefined,
    handledReload: 0,
    destroyed: false,
    status: 'idle',
    value: options.defaultValue,
    error: undefined,
  });

  // Angular 18 has no linkedSignal. Projecting a request mismatch here makes
  // loading/idle visible synchronously, before the effect starts the loader.
  const visibleState = computed<ResourceState18<T, R>>(() => {
    const current = state();
    if (current.destroyed) {
      return current;
    }

    const request = params();
    const reload = reloadTrigger();

    if (!Object.is(request, current.request)) {
      return {
        request,
        handledReload: reload,
        destroyed: false,
        status: request === undefined ? 'idle' : 'loading',
        value: options.defaultValue,
        error: undefined,
      };
    }

    if (current.handledReload !== reload) {
      return {
        request,
        handledReload: reload,
        destroyed: false,
        status: 'reloading',
        value:
          current.status === 'resolved' ? current.value : options.defaultValue,
        error: undefined,
      };
    }

    return current;
  });

  const valueEqual: ValueEqualityFn<T | undefined> = (left, right) => {
    if (left === undefined || right === undefined) {
      return Object.is(left, right);
    }
    return options.equal?.(left, right) ?? Object.is(left, right);
  };

  const value = computed(
    () => {
      const current = visibleState();
      if (current.status === 'error') {
        throw current.error;
      }
      return current.value;
    },
    {equal: valueEqual},
  );
  const status = computed(() => visibleState().status);
  const error = computed(() => visibleState().error);
  const isLoading = computed(() => {
    const current = status();
    return current === 'loading' || current === 'reloading';
  });

  let destroyed = false;
  let effectRef: EffectRef;
  let unregisterOnDestroy: (() => void) | undefined;

  const destroy = (): void => {
    if (destroyed) {
      return;
    }

    destroyed = true;
    effectRef.destroy();
    unregisterOnDestroy?.();
    unregisterOnDestroy = undefined;
    state.set({
      request: undefined,
      handledReload: untracked(reloadTrigger),
      destroyed: true,
      status: 'idle',
      value: options.defaultValue,
      error: undefined,
    });
  };

  effectRef = effect(
    (onCleanup) => {
      const request = params();
      const reload = reloadTrigger();

      if (request === undefined) {
        state.set({
          request: undefined,
          handledReload: reload,
          destroyed: false,
          status: 'idle',
          value: options.defaultValue,
          error: undefined,
        });
        return;
      }

      const previous = untracked(state);
      const previousStatus = previous.status;
      const isReload =
        Object.is(previous.request, request) &&
        previous.handledReload !== reload &&
        previous.status !== 'idle' &&
        previous.status !== 'loading' &&
        previous.status !== 'reloading';
      const controller = new AbortController();
      const isCurrentLoad = (): boolean =>
        !destroyed &&
        !controller.signal.aborted &&
        Object.is(untracked(params), request) &&
        untracked(reloadTrigger) === reload;

      state.set({
        request,
        handledReload: reload,
        destroyed: false,
        status: isReload ? 'reloading' : 'loading',
        value:
          isReload && previous.status === 'resolved'
            ? previous.value
            : options.defaultValue,
        error: undefined,
      });

      onCleanup(() => controller.abort());

      let result: PromiseLike<T>;
      try {
        result = untracked(() =>
          options.loader({
            params: request as Exclude<R, undefined>,
            previous: {status: previousStatus},
            abortSignal: controller.signal,
          }),
        );
      } catch (caught) {
        result = Promise.reject(caught);
      }

      Promise.resolve(result).then(
        (nextValue) => {
          if (!isCurrentLoad()) {
            return;
          }

          state.set({
            request,
            handledReload: reload,
            destroyed: false,
            status: 'resolved',
            value: nextValue,
            error: undefined,
          });
        },
        (caught: unknown) => {
          if (!isCurrentLoad()) {
            return;
          }

          state.set({
            request,
            handledReload: reload,
            destroyed: false,
            status: 'error',
            value: options.defaultValue,
            error: toError(caught),
          });
        },
      );
    },
    {allowSignalWrites: true, injector, manualCleanup: true},
  );

  unregisterOnDestroy = injector.get(DestroyRef).onDestroy(destroy);

  const hasValue = (): boolean => {
    const current = visibleState();
    return current.status !== 'error' && current.value !== undefined;
  };

  const reload = (): boolean => {
    const current = visibleState();
    if (
      current.request === undefined ||
      current.status === 'idle' ||
      current.status === 'loading' ||
      current.status === 'reloading'
    ) {
      return false;
    }

    reloadTrigger.update((reloadCount) => reloadCount + 1);
    return true;
  };

  return {
    value,
    status,
    error,
    isLoading,
    hasValue,
    reload,
    destroy,
  } as ResourceRef18<T | undefined>;
}

function toError(caught: unknown): Error {
  return caught instanceof Error
    ? caught
    : new Error(String(caught), {cause: caught});
}