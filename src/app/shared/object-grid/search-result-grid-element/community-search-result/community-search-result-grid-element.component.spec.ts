import { HttpClient } from '@angular/common/http';
import {
  ChangeDetectionStrategy,
  NO_ERRORS_SCHEMA,
} from '@angular/core';
import {
  ComponentFixture,
  TestBed,
  waitForAsync,
} from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { ActivatedRoute } from '@angular/router';
import { Store } from '@ngrx/store';
import { TranslateModule } from '@ngx-translate/core';
import { of } from 'rxjs';

import { AuthService } from '../../../../core/auth/auth.service';
import { LinkService } from '../../../../core/cache/builders/link.service';
import { RemoteDataBuildService } from '../../../../core/cache/builders/remote-data-build.service';
import { ObjectCacheService } from '../../../../core/cache/object-cache.service';
import { BitstreamDataService } from '../../../../core/data/bitstream-data.service';
import { BitstreamFormatDataService } from '../../../../core/data/bitstream-format-data.service';
import { CommunityDataService } from '../../../../core/data/community-data.service';
import { DefaultChangeAnalyzer } from '../../../../core/data/default-change-analyzer.service';
import { DSOChangeAnalyzer } from '../../../../core/data/dso-change-analyzer.service';
import { Community } from '../../../../core/shared/community.model';
import { HALEndpointService } from '../../../../core/shared/hal-endpoint.service';
import { UUIDService } from '../../../../core/shared/uuid.service';
import { XSRFService } from '../../../../core/xsrf/xsrf.service';
import { AuthServiceMock } from '../../../../shared/mocks/auth.service.mock';
import { getMockThemeService } from '../../../../shared/mocks/theme-service.mock';
import { StoreMock } from '../../../../shared/testing/store.mock';
import { ThemeService } from '../../../../shared/theme-support/theme.service';
import { NotificationsService } from '../../../notifications/notifications.service';
import { CommunitySearchResult } from '../../../object-collection/shared/community-search-result.model';
import { ActivatedRouteStub } from '../../../testing/active-router.stub';
import { TruncatableService } from '../../../truncatable/truncatable.service';
import { TruncatePipe } from '../../../utils/truncate.pipe';
import { CommunitySearchResultGridElementComponent } from './community-search-result-grid-element.component';

let communitySearchResultGridElementComponent: CommunitySearchResultGridElementComponent;
let fixture: ComponentFixture<CommunitySearchResultGridElementComponent>;

const truncatableServiceStub: any = {
  isCollapsed: (id: number) => of(true),
};

const mockCommunityWithAbstract: CommunitySearchResult = new CommunitySearchResult();
mockCommunityWithAbstract.hitHighlights = {};
mockCommunityWithAbstract.indexableObject = Object.assign(new Community(), {
  metadata: {
    'dc.description.abstract': [
      {
        language: 'en_US',
        value: 'Short description',
      },
    ],
  },
});

const mockCommunityWithoutAbstract: CommunitySearchResult = new CommunitySearchResult();
mockCommunityWithoutAbstract.hitHighlights = {};
mockCommunityWithoutAbstract.indexableObject = Object.assign(new Community(), {
  metadata: {
    'dc.title': [
      {
        language: 'en_US',
        value: 'Test title',
      },
    ],
  },
});
const linkService = jasmine.createSpyObj('linkService', {
  resolveLink: mockCommunityWithAbstract,
});

describe('CommunitySearchResultGridElementComponent', () => {
  beforeEach(waitForAsync(() => {
    TestBed.configureTestingModule({
      imports: [
        TranslateModule.forRoot(),
        TruncatePipe,
        CommunitySearchResultGridElementComponent,
      ],
      providers: [
        { provide: TruncatableService, useValue: truncatableServiceStub },
        { provide: 'objectElementProvider', useValue: (mockCommunityWithAbstract) },
        { provide: ObjectCacheService, useValue: {} },
        { provide: UUIDService, useValue: {} },
        { provide: Store, useValue: StoreMock },
        { provide: RemoteDataBuildService, useValue: {} },
        { provide: BitstreamDataService, useValue: {} },
        { provide: CommunityDataService, useValue: {} },
        { provide: HALEndpointService, useValue: {} },
        { provide: NotificationsService, useValue: {} },
        { provide: HttpClient, useValue: {} },
        { provide: DSOChangeAnalyzer, useValue: {} },
        { provide: DefaultChangeAnalyzer, useValue: {} },
        { provide: BitstreamFormatDataService, useValue: {} },
        { provide: LinkService, useValue: linkService },
        { provide: ActivatedRoute, useValue: new ActivatedRouteStub() },
        { provide: ThemeService, useValue: getMockThemeService() },
        { provide: AuthService, useValue: new AuthServiceMock() },
        { provide: XSRFService, useValue: {} },
      ],
      schemas: [NO_ERRORS_SCHEMA],
    }).overrideComponent(CommunitySearchResultGridElementComponent, {
      set: { changeDetection: ChangeDetectionStrategy.Default },
    }).compileComponents();
  }));

  beforeEach(waitForAsync(() => {
    fixture = TestBed.createComponent(CommunitySearchResultGridElementComponent);
    communitySearchResultGridElementComponent = fixture.componentInstance;
  }));

  describe('When the community has an abstract', () => {
    beforeEach(() => {
      communitySearchResultGridElementComponent.dso = mockCommunityWithAbstract.indexableObject;
      fixture.detectChanges();
    });

    it('should show the description paragraph', () => {
      const communityAbstractField = fixture.debugElement.query(By.css('p.card-text'));
      expect(communityAbstractField).not.toBeNull();
    });
  });

  describe('When the community has no abstract', () => {
    beforeEach(() => {
      communitySearchResultGridElementComponent.dso = mockCommunityWithoutAbstract.indexableObject;
      fixture.detectChanges();
    });

    it('should not show the description paragraph', () => {
      const communityAbstractField = fixture.debugElement.query(By.css('p.card-text'));
      expect(communityAbstractField).toBeNull();
    });
  });
});
