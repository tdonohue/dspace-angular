import { inject } from '@angular/core';
import {
  ActivatedRouteSnapshot,
  CanActivateFn,
  Router,
  RouterStateSnapshot,
  UrlTree,
} from '@angular/router';
import { BitstreamDataService } from '@dspace/core/data/bitstream-data.service';
import { ConfigurationDataService } from '@dspace/core/data/configuration-data.service';
import { RemoteData } from '@dspace/core/data/remote-data';
import { PAGE_NOT_FOUND_PATH } from '@dspace/core/router/core-routing-paths';
import { getBitstreamDownloadRoute } from '@dspace/core/router/utils/dso-route.utils';
import { HardRedirectService } from '@dspace/core/services/hard-redirect.service';
import { Bitstream } from '@dspace/core/shared/bitstream.model';
import { getFirstCompletedRemoteData } from '@dspace/core/shared/operators';
import { hasNoValue } from '@dspace/shared/utils/empty.util';
import { getBaseUrl } from '@dspace/shared/utils/url.util';
import { Observable, of } from 'rxjs';
import { map, switchMap } from 'rxjs/operators';

/**
 * Redirects to a bitstream based on the handle of the item, and the sequence id or the filename of the
 * bitstream. In production mode the status code will also be set the status code to 301 marking it as a permanent URL
 * redirect for bots to the regular bitstream download Page.
 *
 * @returns Either a {@link UrlTree} to the 404 page when the url isn't a valid format or false in order to make the
 * user wait until the {@link HardRedirectService#redirect} was performed
 */
export const legacyBitstreamURLRedirectGuard: CanActivateFn = (
  route: ActivatedRouteSnapshot,
  state: RouterStateSnapshot,
  bitstreamDataService: BitstreamDataService = inject(BitstreamDataService),
  configurationDataService: ConfigurationDataService = inject(ConfigurationDataService),
  serverHardRedirectService: HardRedirectService = inject(HardRedirectService),
  router: Router = inject(Router),
): Observable<UrlTree | false> => {
  const prefix = route.params.prefix;
  const suffix = route.params.suffix;
  const filename = route.params.filename;
  let sequenceId = route.params.sequence_id;
  if (hasNoValue(sequenceId)) {
    sequenceId = route.queryParams.sequenceId;
  }
  return bitstreamDataService.findByItemHandle(
    `${prefix}/${suffix}`,
    sequenceId,
    filename,
  ).pipe(
    getFirstCompletedRemoteData(),
    switchMap((rd: RemoteData<Bitstream>) => {
      if (rd.hasSucceeded && !rd.hasNoContent) {
        return getBaseUrl(configurationDataService).pipe(
          map((baseUrl) => ({ baseUrl, bitstream: rd.payload })),
        );
      } else {
        return of({ baseUrl: null, bitstream: null });
      }
    }),
    map(({ baseUrl, bitstream }) => {
      if (baseUrl && bitstream) {
        serverHardRedirectService.redirect(new URL(getBitstreamDownloadRoute(bitstream), baseUrl).href, 301);
        return false;
      } else {
        return router.createUrlTree([PAGE_NOT_FOUND_PATH]);
      }
    }),
  );
};
