import {
  Component,
  Input,
} from '@angular/core';

import { Bitstream } from '../../../core/shared/bitstream.model';
import { MediaViewerItem } from '../../../core/shared/media-viewer-item.model';
import { ThemedComponent } from '../../../shared/theme-support/themed.component';
import { MediaViewerVideoComponent } from './media-viewer-video.component';

/**
 * Themed wrapper for {@link MediaViewerVideoComponent}.
 */
@Component({
  selector: 'ds-media-viewer-video',
  styleUrls: [],
  templateUrl: '../../../shared/theme-support/themed.component.html',
  standalone: true,
  imports: [
    MediaViewerVideoComponent,
  ],
})
export class ThemedMediaViewerVideoComponent extends ThemedComponent<MediaViewerVideoComponent> {

  @Input() medias: MediaViewerItem[];

  @Input() captions: Bitstream[];

  protected inAndOutputNames: (keyof MediaViewerVideoComponent & keyof this)[] = [
    'medias',
    'captions',
  ];

  protected getComponentName(): string {
    return 'MediaViewerVideoComponent';
  }

  protected importThemedComponent(themeName: string): Promise<any> {
    return import(`../../../../themes/${themeName}/app/item-page/media-viewer/media-viewer-video/media-viewer-video.component`);
  }

  protected importUnthemedComponent(): Promise<any> {
    return import('./media-viewer-video.component');
  }

}
