// ***********************************************
// This File is for Custom Cypress commands.
// See docs at https://docs.cypress.io/api/cypress-api/custom-commands
// ***********************************************

import { AuthTokenInfo, TOKENITEM } from 'src/app/core/auth/models/auth-token-info.model';
import { DSPACE_XSRF_COOKIE, XSRF_REQUEST_HEADER } from 'src/app/core/xsrf/xsrf.constants';
import { v4 as uuidv4 } from 'uuid';

// Flag to mark e2e content to be deleted/cleaned up
const TYPE_E2E_CONTENT = 'e2e-content-to-delete';

// Declare Cypress namespace to help with Intellisense & code completion in IDEs
// ALL custom commands MUST be listed here for code completion to work
declare global {
    // eslint-disable-next-line @typescript-eslint/no-namespace
    namespace Cypress {
        interface Chainable<Subject = any> {
            /**
             * Login to backend before accessing the next page. Ensures that the next
             * call to "cy.visit()" will be authenticated as this user.
             * @param email email to login as
             * @param password password to login as
             */
            login(email: string, password: string): typeof login;

            /**
             * Login via form before accessing the next page. Useful to fill out login
             * form when a cy.visit() call is to an a page which requires authentication.
             * @param email email to login as
             * @param password password to login as
             */
             loginViaForm(email: string, password: string): typeof loginViaForm;

            /**
             * Generate view event for given object. Useful for testing statistics pages with
             * pre-generated statistics. This just generates a single "hit", but can be called multiple times to
             * generate multiple hits.
             * @param uuid  UUID of object
             * @param dsoType type of DSpace Object (e.g. "item", "collection", "community")
             */
            generateViewEvent(uuid: string, dsoType: string): typeof generateViewEvent;

            /**
             * Create a new CSRF token and add to required Cookie. CSRF Token is returned
             * in chainable in order to allow it to be sent also in required CSRF header.
             * @returns Chainable reference to allow CSRF token to also be sent in header.
             */
            createCSRFCookie(): Chainable<string>;

            /**
             * Create a new DSpace Community with given name and optional parent Community index.
             *
             * If name is not specified, a default name is given.
             * @param name name of Community
             * @param parentIndex index of a previously created community to create this community under.
             */
            createCommunity(name?: string, parentIndex?: number): Chainable<any>;

            /**
             * Delete any test content created
             */
            cleanupTestContent(): typeof cleanupTestContent;
        }
    }
}

/**
 * Login user via REST API directly, and pass authentication token to UI via
 * the UI's dsAuthInfo cookie.
 * WARNING: WHILE THIS METHOD WORKS, OCCASIONALLY RANDOM AUTHENTICATION ERRORS OCCUR.
 * At this time "loginViaForm()" seems more consistent/stable.
 * @param email email to login as
 * @param password password to login as
 */
function login(email: string, password: string): void {
    // Create a fake CSRF cookie/token to use in POST
    cy.createCSRFCookie().as('csrf_token');

    // get our REST API's base URL, also needed for POST
    cy.task('getRestBaseURL').then((baseRestUrl: string) => {
        // Now, send login POST request including that CSRF token
        cy.request({
            method: 'POST',
            url: baseRestUrl + '/api/authn/login',
            headers: { [XSRF_REQUEST_HEADER]: this.csrf_token},
            form: true, // indicates the body should be form urlencoded
            body: { user: email, password: password }
        }).then((resp) => {
            // We expect a successful login
            expect(resp.status).to.eq(200);
            // We expect to have a valid authorization header returned (with our auth token)
            expect(resp.headers).to.have.property('authorization');

            // Initialize our AuthTokenInfo object from the authorization header.
            const authheader = resp.headers.authorization as string;
            const authinfo: AuthTokenInfo = new AuthTokenInfo(authheader);

            // Save our AuthTokenInfo object to our dsAuthInfo UI cookie
            // This ensures the UI will recognize we are logged in on next "visit()"
            cy.setCookie(TOKENITEM, JSON.stringify(authinfo));

            cy.setCookie('AUTH_HEADER', authheader);
        });
    });
}
// Add as a Cypress command (i.e. assign to 'cy.login')
Cypress.Commands.add('login', login);

/**
 * Login user via displayed login form
 * @param email email to login as
 * @param password password to login as
 */
function loginViaForm(email: string, password: string): void {
    // Enter email
    cy.get('ds-log-in [data-test="email"]').type(email);
    // Enter password
    cy.get('ds-log-in [data-test="password"]').type(password);
    // Click login button
    cy.get('ds-log-in [data-test="login-button"]').click();
}
// Add as a Cypress command (i.e. assign to 'cy.loginViaForm')
Cypress.Commands.add('loginViaForm', loginViaForm);


/**
 * Generate statistic view event for given object. Useful for testing statistics pages with
 * pre-generated statistics. This just generates a single "hit", but can be called multiple times to
 * generate multiple hits.
 *
 * NOTE: This requires that "solr-statistics.autoCommit=false" be set on the DSpace backend
 * (as it is in our docker-compose-ci.yml used in CI).
 * Otherwise, by default, new statistical events won't be saved until Solr's autocommit next triggers.
 * @param uuid UUID of object
 * @param dsoType type of DSpace Object (e.g. "item", "collection", "community")
 */
function generateViewEvent(uuid: string, dsoType: string): void {
    // Create a fake CSRF cookie/token to use in POST
    cy.createCSRFCookie().as('csrf_token');

    // get our REST API's base URL, needed for POST
    cy.task('getRestBaseURL').then((baseRestUrl: string) => {
        // Now, send 'statistics/viewevents' POST request including that fake CSRF token in required header
        cy.request({
            method: 'POST',
            url: baseRestUrl + '/api/statistics/viewevents',
            headers: {
                [XSRF_REQUEST_HEADER] : this.csrf_token,
                // use a known public IP address to avoid being seen as a "bot"
                'X-Forwarded-For': '1.1.1.1',
                // Use a user-agent of a Firefox browser on Windows. This again avoids being seen as a "bot"
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            },
            //form: true, // indicates the body should be form urlencoded
            body: { targetId: uuid, targetType: dsoType },
        }).then((resp) => {
            // We expect a 201 (which means statistics event was created)
            expect(resp.status).to.eq(201);
        });
    });
}
// Add as a Cypress command (i.e. assign to 'cy.generateViewEvent')
Cypress.Commands.add('generateViewEvent', generateViewEvent);


/**
 * Can be used by tests to generate a random XSRF/CSRF token and save it to
 * the required XSRF/CSRF cookie for usage when sending POST requests or similar.
 * The generated CSRF token is returned in a Chainable to allow it to be also sent
 * in the CSRF HTTP Header.
 * @returns a Cypress Chainable which can be used to get the generated CSRF Token
 */
function createCSRFCookie(): Cypress.Chainable {
    // Generate a new token which is a random UUID
    const csrfToken: string = uuidv4();

    // Save it to our required cookie
    cy.task('getRestBaseDomain').then((baseDomain: string) => {
        // Create a fake CSRF Token.  Set it in the required server-side cookie
        cy.setCookie(DSPACE_XSRF_COOKIE, csrfToken, { 'domain': baseDomain });
    });

    // return the generated token wrapped in a chainable
    return cy.wrap(csrfToken);
}
// Add as a Cypress command (i.e. assign to 'cy.createCSRFCookie')
Cypress.Commands.add('createCSRFCookie', createCSRFCookie);


//TODO FIX THIS TIM TO CREATE TEST DATA!
export function createCommunity(name?: string, parentIndex?: number): void {
    // First login as an Admin
    cy.login(Cypress.env('DSPACE_TEST_ADMIN_USER'), Cypress.env('DSPACE_TEST_ADMIN_PASSWORD'));

    cy.getCookie('AUTH_HEADER').as('auth_cookie');

    cy.createCSRFCookie().as('csrf_token');

    // get our REST API's base URL, also needed for POST
    cy.task('getRestBaseURL').then((baseRestUrl: string) => {
        // Get the "new_community.json" fixture which can be sent to create a community
        cy.fixture('new_community.json').then((json) => {
            // if name specified, override dc.title value in fixture
            if (name !== undefined) { json.metadata['dc.title'][0].value = name; }

            let postUrl = baseRestUrl + '/api/core/communities';
            if (parentIndex !== undefined) {
                postUrl += '?parent=' + String(Cypress.env('communities')[parentIndex].uuid);
            } else {
                // If top level community, save 'dc.type' flag to note this
                // community was created by e2e tests & can be deleted later
                json.metadata['dc.type'] = [{value:TYPE_E2E_CONTENT}];
            }

            cy.request({
                method: 'POST',
                url: postUrl,
                headers: {
                    [XSRF_REQUEST_HEADER] : this.csrf_token,
                    // use a known public IP address to avoid being seen as a "bot"
                    'X-Forwarded-For': '1.1.1.1',
                    'Authorization': this.auth_cookie.value,
                },
                //form: true, // indicates the body should be form urlencoded
                body: json,
            }).then((resp) => {
                // We expect a 201 (which means community was created)
                expect(resp.status).to.eq(201);

                // Save this response body to our list of created communities
                // in our environment (this is initialized in e2e.ts)
                cy.task('saveCommunityData', JSON.stringify(resp.body));
            });

        });
    });
}
// Add as a Cypress command (i.e. assign to 'cy.createCommunity')
Cypress.Commands.add('createCommunity', createCommunity);

// TODO create "deleteContent"
// Loop through 'e2e_test_communities' and look for ones flagged "to_delete"=true in JSON
// SEND DELETE request for each!!!

/**
 * Cleanup all test content by looping through created test communities
 * looking for those with our "dc.type" flag with the "delete" flag
 */
export function cleanupTestContent(): void {
    // First login as an Admin
    cy.login(Cypress.env('DSPACE_TEST_ADMIN_USER'), Cypress.env('DSPACE_TEST_ADMIN_PASSWORD'));

    cy.getCookie('AUTH_HEADER').as('auth_cookie');

    cy.createCSRFCookie().as('csrf_token');

    // Loop through all test communities
    cy.task('getCommunityData').then((communities: string[]) => {
        for (const community of communities) {
            const object = JSON.parse(community);
            // Get id of community to delete
            const id: string = object.id;
            const type: string = object.metadata['dc.type'][0].value;

            if (id !== null && type === TYPE_E2E_CONTENT) {
                console.log('Deleting test Community ' + id);
                // get our REST API's base URL, neded for delete
                cy.task('getRestBaseURL').then((baseRestUrl: string) => {
                    cy.request({
                        method: 'DELETE',
                        url: baseRestUrl + '/api/core/communities/' + id,
                        headers: {
                            [XSRF_REQUEST_HEADER] : this.csrf_token,
                            // use a known public IP address to avoid being seen as a "bot"
                            'X-Forwarded-For': '1.1.1.1',
                            'Authorization': this.auth_cookie.value,
                        },
                        failOnStatusCode: false,
                    });
                });
            }
        }
    });

    cy.task('resetCommunityData');
}
// Add as a Cypress command (i.e. assign to 'cy.cleanupTestContent')
Cypress.Commands.add('cleanupTestContent', cleanupTestContent);
