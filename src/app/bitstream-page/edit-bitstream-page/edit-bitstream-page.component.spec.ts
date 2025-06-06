import {
  ChangeDetectorRef,
  NO_ERRORS_SCHEMA,
} from '@angular/core';
import {
  ComponentFixture,
  TestBed,
  waitForAsync,
} from '@angular/core/testing';
import {
  UntypedFormControl,
  UntypedFormGroup,
} from '@angular/forms';
import {
  ActivatedRoute,
  Router,
} from '@angular/router';
import { RouterTestingModule } from '@angular/router/testing';
import {
  DynamicFormControlModel,
  DynamicFormService,
} from '@ng-dynamic-forms/core';
import { TranslateModule } from '@ngx-translate/core';
import { of } from 'rxjs';

import { DSONameService } from '../../core/breadcrumbs/dso-name.service';
import { BitstreamDataService } from '../../core/data/bitstream-data.service';
import { BitstreamFormatDataService } from '../../core/data/bitstream-format-data.service';
import { PrimaryBitstreamService } from '../../core/data/primary-bitstream.service';
import { Bitstream } from '../../core/shared/bitstream.model';
import { BitstreamFormat } from '../../core/shared/bitstream-format.model';
import { BitstreamFormatSupportLevel } from '../../core/shared/bitstream-format-support-level';
import { Item } from '../../core/shared/item.model';
import { MetadataValueFilter } from '../../core/shared/metadata.models';
import { getEntityEditRoute } from '../../item-page/item-page-routing-paths';
import { hasValue } from '../../shared/empty.util';
import {
  INotification,
  Notification,
} from '../../shared/notifications/models/notification.model';
import { NotificationType } from '../../shared/notifications/models/notification-type';
import { NotificationsService } from '../../shared/notifications/notifications.service';
import {
  createSuccessfulRemoteDataObject,
  createSuccessfulRemoteDataObject$,
} from '../../shared/remote-data.utils';
import { createPaginatedList } from '../../shared/testing/utils.test';
import { FileSizePipe } from '../../shared/utils/file-size-pipe';
import { VarDirective } from '../../shared/utils/var.directive';
import { EditBitstreamPageComponent } from './edit-bitstream-page.component';

const infoNotification: INotification = new Notification('id', NotificationType.Info, 'info');
const warningNotification: INotification = new Notification('id', NotificationType.Warning, 'warning');
const successNotification: INotification = new Notification('id', NotificationType.Success, 'success');

let notificationsService: NotificationsService;
let formService: DynamicFormService;
let bitstreamService: BitstreamDataService;
let primaryBitstreamService: PrimaryBitstreamService;
let bitstreamFormatService: BitstreamFormatDataService;
let dsoNameService: DSONameService;
let bitstream: Bitstream;
let bitstreamID: string;
let selectedFormat: BitstreamFormat;
let allFormats: BitstreamFormat[];
let router: Router;
let currentPrimary: string;
let differentPrimary: string;
let bundle;
let comp: EditBitstreamPageComponent;
let fixture: ComponentFixture<EditBitstreamPageComponent>;

describe('EditBitstreamPageComponent', () => {

  beforeEach(() => {
    bitstreamID = 'current-bitstream-id';
    currentPrimary = bitstreamID;
    differentPrimary = '12345-abcde-54321-edcba';

    allFormats = [
      Object.assign({
        id: '1',
        shortDescription: 'Unknown',
        description: 'Unknown format',
        supportLevel: BitstreamFormatSupportLevel.Unknown,
        mimetype: 'application/octet-stream',
        _links: {
          self: { href: 'format-selflink-1' },
        },
      }),
      Object.assign({
        id: '2',
        shortDescription: 'PNG',
        description: 'Portable Network Graphics',
        supportLevel: BitstreamFormatSupportLevel.Known,
        mimetype: 'image/png',
        _links: {
          self: { href: 'format-selflink-2' },
        },
      }),
      Object.assign({
        id: '3',
        shortDescription: 'GIF',
        description: 'Graphics Interchange Format',
        supportLevel: BitstreamFormatSupportLevel.Known,
        mimetype: 'image/gif',
        _links: {
          self: { href: 'format-selflink-3' },
        },
      }),
    ] as BitstreamFormat[];
    selectedFormat = allFormats[1];

    formService = Object.assign({
      createFormGroup: (fModel: DynamicFormControlModel[]) => {
        const controls = {};
        if (hasValue(fModel)) {
          fModel.forEach((controlModel) => {
            controls[controlModel.id] = new UntypedFormControl((controlModel as any).value);
          });
          return new UntypedFormGroup(controls);
        }
        return undefined;
      },
    });

    bitstreamFormatService = jasmine.createSpyObj('bitstreamFormatService', {
      findAll: createSuccessfulRemoteDataObject$(createPaginatedList(allFormats)),
    });

    notificationsService = jasmine.createSpyObj('notificationsService',
      {
        info: infoNotification,
        warning: warningNotification,
        success: successNotification,
      },
    );

    bundle = {
      _links: {
        primaryBitstream: {
          href: 'bundle-selflink',
        },
      },
      item: createSuccessfulRemoteDataObject$(Object.assign(new Item(), {
        uuid: 'some-uuid',
        firstMetadataValue(keyOrKeys: string | string[], valueFilter?: MetadataValueFilter): string {
          return undefined;
        },
      })),
    };

    const result = createSuccessfulRemoteDataObject$(bundle);
    primaryBitstreamService = jasmine.createSpyObj('PrimaryBitstreamService',
      {
        put: result,
        create: result,
        delete: result,
      });

  });

  describe('EditBitstreamPageComponent no IIIF fields', () => {

    beforeEach(waitForAsync(() => {
      bundle = {
        _links: {
          primaryBitstream: {
            href: 'bundle-selflink',
          },
        },
        item: createSuccessfulRemoteDataObject$(Object.assign(new Item(), {
          uuid: 'some-uuid',
          firstMetadataValue(keyOrKeys: string | string[], valueFilter?: MetadataValueFilter): string {
            return undefined;
          },
        })),
      };
      const bundleName = 'ORIGINAL';

      bitstream = Object.assign(new Bitstream(), {
        uuid: bitstreamID,
        id: bitstreamID,
        metadata: {
          'dc.description': [
            {
              value: 'Bitstream description',
            },
          ],
          'dc.title': [
            {
              value: 'Bitstream title',
            },
          ],
        },
        format: createSuccessfulRemoteDataObject$(selectedFormat),
        _links: {
          self: 'bitstream-selflink',
        },
        bundle: createSuccessfulRemoteDataObject$(bundle),
      });
      bitstreamService = jasmine.createSpyObj('bitstreamService', {
        findById: createSuccessfulRemoteDataObject$(bitstream),
        findByHref: createSuccessfulRemoteDataObject$(bitstream),
        update: createSuccessfulRemoteDataObject$(bitstream),
        updateFormat: createSuccessfulRemoteDataObject$(bitstream),
        commitUpdates: {},
        patch: {},
      });
      bitstreamFormatService = jasmine.createSpyObj('bitstreamFormatService', {
        findAll: createSuccessfulRemoteDataObject$(createPaginatedList(allFormats)),
      });
      dsoNameService = jasmine.createSpyObj('dsoNameService', {
        getName: bundleName,
      });

      TestBed.configureTestingModule({
        imports: [TranslateModule.forRoot(), RouterTestingModule, EditBitstreamPageComponent, FileSizePipe, VarDirective],
        providers: [
          { provide: NotificationsService, useValue: notificationsService },
          { provide: DynamicFormService, useValue: formService },
          {
            provide: ActivatedRoute,
            useValue: {
              data: of({ bitstream: createSuccessfulRemoteDataObject(bitstream) }),
              snapshot: { queryParams: {} },
            },
          },
          { provide: BitstreamDataService, useValue: bitstreamService },
          { provide: DSONameService, useValue: dsoNameService },
          { provide: BitstreamFormatDataService, useValue: bitstreamFormatService },
          { provide: PrimaryBitstreamService, useValue: primaryBitstreamService },
          ChangeDetectorRef,
        ],
        schemas: [NO_ERRORS_SCHEMA],
      }).compileComponents();

    }));

    beforeEach(() => {
      fixture = TestBed.createComponent(EditBitstreamPageComponent);
      comp = fixture.componentInstance;
      fixture.detectChanges();
      router = TestBed.inject(Router);
      spyOn(router, 'navigate');
    });

    describe('on startup', () => {
      let rawForm;

      beforeEach(() => {
        rawForm = comp.formGroup.getRawValue();
      });

      it('should fill in the bitstream\'s title', () => {
        expect(rawForm.fileNamePrimaryContainer.fileName).toEqual(bitstream.name);
      });

      it('should fill in the bitstream\'s description', () => {
        expect(rawForm.descriptionContainer.description).toEqual(bitstream.firstMetadataValue('dc.description'));
      });

      it('should select the correct format', () => {
        expect(rawForm.formatContainer.selectedFormat).toEqual(selectedFormat.shortDescription);
      });

      it('should put the \"New Format\" input on invisible', () => {
        expect(comp.formLayout.newFormat.grid.host).toContain('invisible');
      });
      describe('when the bitstream is the primary bitstream on the bundle', () => {
        beforeEach(() => {
          (comp as any).primaryBitstreamUUID = currentPrimary;
          comp.setForm();
          rawForm = comp.formGroup.getRawValue();

        });
        it('should enable the primary bitstream toggle', () => {
          expect(rawForm.fileNamePrimaryContainer.primaryBitstream).toEqual(true);
        });
      });
      describe('when the bitstream is not the primary bitstream on the bundle', () => {
        beforeEach(() => {
          (comp as any).primaryBitstreamUUID = differentPrimary;
          comp.setForm();
          rawForm = comp.formGroup.getRawValue();
        });
        it('should disable the primary bitstream toggle', () => {
          expect(rawForm.fileNamePrimaryContainer.primaryBitstream).toEqual(false);
        });
      });
    });

    describe('when an unknown format is selected', () => {
      beforeEach(() => {
        comp.onChange({
          model: {
            id: 'selectedFormat',
            value: allFormats[0],
          },
        });
        comp.updateNewFormatLayout();
      });

      it('should remove the invisible class from the \"New Format\" input', () => {
        expect(comp.formLayout.newFormat.grid.host).not.toContain('invisible');
      });
    });

    describe('onSubmit', () => {
      describe('when the primaryBitstream changed', () => {
        describe('to the current bitstream', () => {
          beforeEach(() => {
            const rawValue = Object.assign(comp.formGroup.getRawValue(), { fileNamePrimaryContainer: { primaryBitstream: true } });
            spyOn(comp.formGroup, 'getRawValue').and.returnValue(rawValue);
          });

          describe('from a different primary bitstream', () => {
            beforeEach(() => {
              (comp as any).primaryBitstreamUUID = differentPrimary;
              comp.onSubmit();
            });

            it('should call put with the correct bitstream on the PrimaryBitstreamService', () => {
              expect(primaryBitstreamService.put).toHaveBeenCalledWith(jasmine.objectContaining({ uuid: currentPrimary }), bundle);
            });
          });

          describe('from no primary bitstream', () => {
            beforeEach(() => {
              (comp as any).primaryBitstreamUUID = null;
              comp.onSubmit();
            });

            it('should call create with the correct bitstream on the PrimaryBitstreamService', () => {
              expect(primaryBitstreamService.create).toHaveBeenCalledWith(jasmine.objectContaining({ uuid: currentPrimary }), bundle);
            });
          });
        });
        describe('to no primary bitstream', () => {
          beforeEach(() => {
            const rawValue = Object.assign(comp.formGroup.getRawValue(), { fileNamePrimaryContainer: { primaryBitstream: false } });
            spyOn(comp.formGroup, 'getRawValue').and.returnValue(rawValue);
          });

          describe('from the current bitstream', () => {
            beforeEach(() => {
              (comp as any).primaryBitstreamUUID = currentPrimary;
              comp.onSubmit();
            });

            it('should call delete on the PrimaryBitstreamService', () => {
              expect(primaryBitstreamService.delete).toHaveBeenCalledWith(jasmine.objectContaining(bundle));
            });
          });
        });
      });
      describe('when the primaryBitstream did not change', () => {
        describe('the current bitstream stayed the primary bitstream', () => {
          beforeEach(() => {
            const rawValue = Object.assign(comp.formGroup.getRawValue(), { fileNamePrimaryContainer: { primaryBitstream: true } });
            spyOn(comp.formGroup, 'getRawValue').and.returnValue(rawValue);
            (comp as any).primaryBitstreamUUID = currentPrimary;
            comp.onSubmit();
          });
          it('should not call anything on the PrimaryBitstreamService', () => {
            expect(primaryBitstreamService.put).not.toHaveBeenCalled();
            expect(primaryBitstreamService.delete).not.toHaveBeenCalled();
            expect(primaryBitstreamService.create).not.toHaveBeenCalled();
          });
        });

        describe('the bitstream was not and did not become the primary bitstream', () => {
          beforeEach(() => {
            const rawValue = Object.assign(comp.formGroup.getRawValue(), { fileNamePrimaryContainer: { primaryBitstream: false } });
            spyOn(comp.formGroup, 'getRawValue').and.returnValue(rawValue);
            (comp as any).primaryBitstreamUUID = differentPrimary;
            comp.onSubmit();
          });
          it('should not call anything on the PrimaryBitstreamService', () => {
            expect(primaryBitstreamService.put).not.toHaveBeenCalled();
            expect(primaryBitstreamService.delete).not.toHaveBeenCalled();
            expect(primaryBitstreamService.create).not.toHaveBeenCalled();
          });
        });
      });

      describe('when selected format hasn\'t changed', () => {
        beforeEach(() => {
          comp.onSubmit();
        });

        it('should call update', () => {
          expect(bitstreamService.update).toHaveBeenCalled();
        });

        it('should commit the updates', () => {
          expect(bitstreamService.commitUpdates).toHaveBeenCalled();
        });
      });

      describe('when selected format has changed', () => {
        beforeEach(() => {
          comp.onChange({
            model: {
              id: 'selectedFormat',
              value: allFormats[2],
            },
          });
          fixture.detectChanges();
          comp.onSubmit();
        });

        it('should call update', () => {
          expect(bitstreamService.update).toHaveBeenCalled();
        });

        it('should call updateFormat', () => {
          expect(bitstreamService.updateFormat).toHaveBeenCalled();
        });

        it('should commit the updates', () => {
          expect(bitstreamService.commitUpdates).toHaveBeenCalled();
        });
      });
    });
    describe('when the cancel button is clicked', () => {
      it('should call navigateToItemEditBitstreams method', () => {
        spyOn(comp, 'navigateToItemEditBitstreams');
        comp.onCancel();
        expect(comp.navigateToItemEditBitstreams).toHaveBeenCalled();
      });
    });
    describe('when navigateToItemEditBitstreams is called', () => {
      it('should redirect to the item edit page on the bitstreams tab with the itemId from the component', () => {
        comp.itemId = 'some-uuid1';
        comp.navigateToItemEditBitstreams();
        expect(router.navigate).toHaveBeenCalledWith([getEntityEditRoute(null, 'some-uuid1'), 'bitstreams']);
      });
    });
  });

  describe('EditBitstreamPageComponent with IIIF fields', () => {

    const bundleName = 'ORIGINAL';

    beforeEach(waitForAsync(() => {

      bitstream = Object.assign(new Bitstream(), {
        metadata: {
          'dc.description': [
            {
              value: 'Bitstream description',
            },
          ],
          'dc.title': [
            {
              value: 'Bitstream title',
            },
          ],
          'iiif.label': [
            {
              value: 'chapter one',
            },
          ],
          'iiif.toc': [
            {
              value: 'chapter one',
            },
          ],
          'iiif.image.width': [
            {
              value: '2400',
            },
          ],
          'iiif.image.height': [
            {
              value: '2800',
            },
          ],
        },
        format: createSuccessfulRemoteDataObject$(allFormats[1]),
        _links: {
          self: 'bitstream-selflink',
        },
        bundle: createSuccessfulRemoteDataObject$({
          _links: {
            primaryBitstream: {
              href: 'bundle-selflink',
            },
          },
          item: createSuccessfulRemoteDataObject$(Object.assign(new Item(), {
            uuid: 'some-uuid',
            firstMetadataValue(keyOrKeys: string | string[], valueFilter?: MetadataValueFilter): string {
              return 'True';
            },
          })),
        }),
      });
      bitstreamService = jasmine.createSpyObj('bitstreamService', {
        findById: createSuccessfulRemoteDataObject$(bitstream),
        findByHref: createSuccessfulRemoteDataObject$(bitstream),
        update: createSuccessfulRemoteDataObject$(bitstream),
        updateFormat: createSuccessfulRemoteDataObject$(bitstream),
        commitUpdates: {},
        patch: {},
      });

      dsoNameService = jasmine.createSpyObj('dsoNameService', {
        getName: bundleName,
      });

      TestBed.configureTestingModule({
        imports: [TranslateModule.forRoot(), RouterTestingModule, EditBitstreamPageComponent, FileSizePipe, VarDirective],
        providers: [
          { provide: NotificationsService, useValue: notificationsService },
          { provide: DynamicFormService, useValue: formService },
          {
            provide: ActivatedRoute,
            useValue: {
              data: of({ bitstream: createSuccessfulRemoteDataObject(bitstream) }),
              snapshot: { queryParams: {} },
            },
          },
          { provide: BitstreamDataService, useValue: bitstreamService },
          { provide: DSONameService, useValue: dsoNameService },
          { provide: BitstreamFormatDataService, useValue: bitstreamFormatService },
          { provide: PrimaryBitstreamService, useValue: primaryBitstreamService },
          ChangeDetectorRef,
        ],
        schemas: [NO_ERRORS_SCHEMA],
      }).compileComponents();
    }));

    beforeEach(() => {
      fixture = TestBed.createComponent(EditBitstreamPageComponent);
      comp = fixture.componentInstance;
      fixture.detectChanges();
      router = TestBed.inject(Router);
      spyOn(router, 'navigate');
    });

    describe('on startup', () => {
      let rawForm;

      beforeEach(() => {
        rawForm = comp.formGroup.getRawValue();
      });
      it('should set isIIIF to true', () => {
        expect(comp.isIIIF).toBeTrue();
      });
      it('should fill in the iiif label', () => {
        expect(rawForm.iiifLabelContainer.iiifLabel).toEqual('chapter one');
      });
      it('should fill in the iiif toc', () => {
        expect(rawForm.iiifTocContainer.iiifToc).toEqual('chapter one');
      });
      it('should fill in the iiif width', () => {
        expect(rawForm.iiifWidthContainer.iiifWidth).toEqual('2400');
      });
      it('should fill in the iiif height', () => {
        expect(rawForm.iiifHeightContainer.iiifHeight).toEqual('2800');
      });
    });
  });

  describe('ignore OTHERCONTENT bundle', () => {

    const bundleName = 'OTHERCONTENT';

    beforeEach(waitForAsync(() => {

      bitstream = Object.assign(new Bitstream(), {
        metadata: {
          'dc.description': [
            {
              value: 'Bitstream description',
            },
          ],
          'dc.title': [
            {
              value: 'Bitstream title',
            },
          ],
          'iiif.label': [
            {
              value: 'chapter one',
            },
          ],
          'iiif.toc': [
            {
              value: 'chapter one',
            },
          ],
          'iiif.image.width': [
            {
              value: '2400',
            },
          ],
          'iiif.image.height': [
            {
              value: '2800',
            },
          ],
        },
        format: createSuccessfulRemoteDataObject$(allFormats[2]),
        _links: {
          self: 'bitstream-selflink',
        },
        bundle: createSuccessfulRemoteDataObject$({
          _links: {
            primaryBitstream: {
              href: 'bundle-selflink',
            },
          },
          item: createSuccessfulRemoteDataObject$(Object.assign(new Item(), {
            uuid: 'some-uuid',
            firstMetadataValue(keyOrKeys: string | string[], valueFilter?: MetadataValueFilter): string {
              return 'True';
            },
          })),
        }),
      });
      bitstreamService = jasmine.createSpyObj('bitstreamService', {
        findById: createSuccessfulRemoteDataObject$(bitstream),
        findByHref: createSuccessfulRemoteDataObject$(bitstream),
        update: createSuccessfulRemoteDataObject$(bitstream),
        updateFormat: createSuccessfulRemoteDataObject$(bitstream),
        commitUpdates: {},
        patch: {},
      });

      dsoNameService = jasmine.createSpyObj('dsoNameService', {
        getName: bundleName,
      });

      TestBed.configureTestingModule({
        imports: [TranslateModule.forRoot(), RouterTestingModule, EditBitstreamPageComponent, FileSizePipe, VarDirective],
        providers: [
          { provide: NotificationsService, useValue: notificationsService },
          { provide: DynamicFormService, useValue: formService },
          { provide: ActivatedRoute,
            useValue: {
              data: of({ bitstream: createSuccessfulRemoteDataObject(bitstream) }),
              snapshot: { queryParams: {} },
            },
          },
          { provide: BitstreamDataService, useValue: bitstreamService },
          { provide: DSONameService, useValue: dsoNameService },
          { provide: BitstreamFormatDataService, useValue: bitstreamFormatService },
          { provide: PrimaryBitstreamService, useValue: primaryBitstreamService },
          ChangeDetectorRef,
        ],
        schemas: [NO_ERRORS_SCHEMA],
      }).compileComponents();
    }));

    beforeEach(() => {
      fixture = TestBed.createComponent(EditBitstreamPageComponent);
      comp = fixture.componentInstance;
      fixture.detectChanges();
      router = TestBed.inject(Router);
      spyOn(router, 'navigate');
    });

    describe('EditBitstreamPageComponent with IIIF fields', () => {
      let rawForm;

      beforeEach(() => {
        rawForm = comp.formGroup.getRawValue();
      });

      it('should NOT set is IIIF to true', () => {
        expect(comp.isIIIF).toBeFalse();
      });
      it('should put the \"IIIF Label\" input not to be shown', () => {
        expect(rawForm.iiifLabelContainer).toBeFalsy();
      });
    });
  });

});
