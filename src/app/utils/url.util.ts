import { RemoteData } from "@dspace/core/data/remote-data";
import { ConfigurationProperty } from "@dspace/core/shared/configuration-property.model";
import { getFirstCompletedRemoteData } from "@dspace/core/shared/operators";
import { map, of } from "rxjs";
import { environment } from "src/environments/environment";
import { ConfigurationDataService } from "@dspace/core/data/configuration-data.service";
import { Observable } from "rxjs";

/**
 * Get the URL of our DSpace frontend as an Observable.
 * Returns the 'ui.baseUrl' frontend configuration or the 'dspace.ui.url' backend configuration.
 * Throws an error if neither is set.
 * The `ui.baseUrl` environment variable can be used to override the `dspace.ui.url` backend property.
 * @param configurationService - The ConfigurationDataService instance
 * @returns Observable<string> URL as a string, never undefined.
 * @throws Error if URL cannot be determined
 */
export function getBaseUrl(configurationService: ConfigurationDataService): Observable<string> {
    
    // If set, return baseUrl from environment
    const baseUrl = environment.ui.baseUrl;
    if (baseUrl) {
        return of(baseUrl);
    }
    
    // Otherwise, obtain "dspace.ui.url" from backend configuration
    return configurationService.findByPropertyName('dspace.ui.url').pipe(
        getFirstCompletedRemoteData(),
        map((configurationPropertyRD: RemoteData<ConfigurationProperty>) => {
            if (configurationPropertyRD.hasSucceeded && configurationPropertyRD.payload.values.length >= 1) {
                return configurationPropertyRD.payload.values[0];
            }
            throw new Error('Unable to determine DSpace frontend URL. Please configure ui.baseUrl (on frontend) or dspace.ui.url (on backend).');
        })
    );
}


/**
 * Get the Hostname of our DSpace frontend.
 * Returns the hostname of the URL passed in.
 * @param url - The frontend URL string
 * @returns Hostname as string
 */
export function getHostname(url: string): string {
    return new URL(url).hostname;
}