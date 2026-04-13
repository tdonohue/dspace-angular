import { title } from 'process';
import {
  IMPERSONATING_COOKIE,
  REDIRECT_COOKIE,
} from '../auth/auth.service';
import { TOKENITEM } from '../auth/models/auth-token-info.model';
import {
  CAPTCHA_COOKIE,
  CAPTCHA_NAME,
} from '../google-recaptcha/google-recaptcha.service';
import { LANG_COOKIE } from '../locale/locale.service';
import { NativeWindowRef } from '../services/window.service';
import { ACCESSIBILITY_COOKIE } from './accessibility-cookie';

/**
 * Cookie for has_agreed_end_user
 */
export const HAS_AGREED_END_USER = 'dsHasAgreedEndUser';

export const ANONYMOUS_STORAGE_NAME_OREJIME = 'orejime-anonymous';

export const GOOGLE_ANALYTICS_OREJIME_KEY = 'google-analytics';

export const MATOMO_OREJIME_KEY = 'matomo';

export const MATOMO_COOKIE = 'dsMatomo';

export const CORRELATION_ID_OREJIME_KEY = 'correlation-id';

export const CORRELATION_ID_COOKIE = 'CORRELATION-ID';

/**
 * Orejime configuration
 * For more information see https://github.com/empreinte-digitale/orejime
 */

export function getOrejimeConfiguration(_window: NativeWindowRef): any {
  return {
    privacyPolicyUrl: './info/privacy',

    cookie: {
      name: ANONYMOUS_STORAGE_NAME_OREJIME,
      // Optional. You can set a custom expiration time for the Orejime cookie, in days.
      // defaults to 365.
      duration: 365,
      // Custom function to serialize the cookie contents.
      stringify: (contents: any) => {
        return (typeof contents === 'string') ? contents : JSON.stringify(contents);
      },
      // custom function to unserialize the cookie contents
      parse: (cookie: string) => {
        if (typeof cookie === 'string') {
          cookie = decodeURIComponent(cookie);
          return JSON.parse(cookie);
        }
        return cookie;
      },
    },

    /*
    The appElement selector is used by Orejime to determine where to insert the consent
     */
    orejimeElement: 'ds-app',

    /*
    You can overwrite existing translations and add translations for your app
    descriptions and purposes. See `src/translations/` for a full list of
    translations that can be overwritten:
    https://github.com/empreinte-digitale/orejime/blob/master/src/translations/en.yml
    */
    /*translations: {*/
      /*
        The `zz` key contains default translations that will be used as fallback values.
        This can e.g. be useful for defining a fallback privacy policy URL.
        FOR DSPACE: We use 'zz' to map to our own i18n translations for orejime, see
        translateConfiguration() in browser-orejime.service.ts. All the below i18n keys are specified
        in your /src/assets/i18n/*.json5 translation pack.
      */
    /*  zz: {
        acceptAll: 'cookies.consent.accept-all',
        acceptSelected: 'cookies.consent.accept-selected',
        close: 'cookies.consent.close',
        consentModal: {
          title: 'cookies.consent.content-modal.title',
          description: 'cookies.consent.content-modal.description',
          privacyPolicy: {
            name: 'cookies.consent.content-modal.privacy-policy.name',
            text: 'cookies.consent.content-modal.privacy-policy.text',
          },
        },
        consentNotice: {
          changeDescription: 'cookies.consent.update',
          description: 'cookies.consent.content-notice.description',
          learnMore: 'cookies.consent.content-notice.learnMore',
        },
        decline: 'cookies.consent.decline',
        declineAll: 'cookies.consent.decline-all',
        accept: 'cookies.consent.ok',
        save: 'cookies.consent.save',
        purposes: {},
        app: {
          optOut: {
            description: 'cookies.consent.app.opt-out.description',
            title: 'cookies.consent.app.opt-out.title',
          },
          purpose: 'cookies.consent.app.purpose',
          purposes: 'cookies.consent.app.purposes',
          required: {
            title: 'cookies.consent.app.required.title',
            description: 'cookies.consent.app.required.description',
          },
        },
      },
    },*/
    /** 
     * TODO: NOTE that Orejime seems to have a bug with listing more than 4-5 purposes.
     * That's why we currently only have 4 purposes listed here. We may need to log
     * a ticket with Orejime if this doesn't get fixed soon.
     */
    purposes: [
      {
        id: 'authentication',
        title: 'Authentication',
        description: 'These cookies are required to keep you authenticated after you login.',
        isMandatory: true,
        cookies: [
          TOKENITEM,
          IMPERSONATING_COOKIE,
          REDIRECT_COOKIE,
        ],
      },
      {
        id: 'preferences',
        title: 'Preferences',
        description: 'These cookies are required to store your preferences.',
        isMandatory: true,
        cookies: [
          LANG_COOKIE,
        ],
      },
      {
        id: 'acknowledgement',
        title: 'Acknowledgement',
        description: 'These cookies are required to store your acknowledgements and consents.',
        isMandatory: true,
        cookies: [
          [/^orejime-.+$/],
          HAS_AGREED_END_USER,
        ],
      },
      {
        id: CAPTCHA_NAME,
        title: 'CAPTCHA',
        description: 'These cookies are used to store CAPTCHA data.',
        isMandatory: true,
        cookies: [
          CAPTCHA_COOKIE,
        ],
        /*  TODO: Replace callback
        callback: (consent: boolean) => {
          _window?.nativeWindow.refreshCaptchaScript?.call();
        },*/
        runsOnce: true,
      },
      {
        id: 'accessibility',
        title: 'Accessibility',
        description: 'These cookies are used to store your accessibility preferences.',
        cookies: [
          ACCESSIBILITY_COOKIE,
        ],
        default: true,
      },
      {
        id: CORRELATION_ID_OREJIME_KEY,
        title: 'Correlation ID',
        description: 'This cookie is used to store a unique identifier for each visitor for error tracking.',
        cookies: [
          CORRELATION_ID_COOKIE
        ],
        /* TODO: Replace callback
        callback: () => {
          _window?.nativeWindow.initCorrelationId();
        },*/
        default: true,
      },
      {
        id: MATOMO_OREJIME_KEY,
        title: 'Analytics (Matomo)',
        description: 'These cookies are used to track visitor interactions with the site for analytics purposes.',
        cookies: [
          MATOMO_COOKIE,
        ],
        default: true,
        runsOnce: true,
        /* TODO: Replace callback
        callback: (consent: boolean) => {
          _window?.nativeWindow.changeMatomoConsent(consent);
        },*/
      },
      {
        id: GOOGLE_ANALYTICS_OREJIME_KEY,
        title: 'Analytics (Google Analytics)',
        description: 'These cookies are used to track visitor interactions with the site for analytics purposes.',
        cookies: [
          [/^_ga.?$/],
          [/^_gid$/],
        ],
        default: true,
        /* If runsOnce is true, the app will only be executed once regardless
          how often the user toggles it on and off. This is relevant e.g. for tracking
          scripts that would generate new page view events every time Orejime disables and
          re-enables them due to a consent change by the user.*/
        runsOnce: true,
      },
      
    ],
  };
}
