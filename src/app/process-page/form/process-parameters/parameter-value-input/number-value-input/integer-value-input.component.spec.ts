import {
  ComponentFixture,
  fakeAsync,
  TestBed,
  tick,
  waitForAsync,
} from '@angular/core/testing';
import { FormsModule } from '@angular/forms';
import { By } from '@angular/platform-browser';
import {
  TranslateLoader,
  TranslateModule,
} from '@ngx-translate/core';

import { TranslateLoaderMock } from '../../../../../shared/mocks/translate-loader.mock';
import { IntegerValueInputComponent } from './integer-value-input.component';

describe('IntegerValueInputComponent', () => {
  let component: IntegerValueInputComponent;
  let fixture: ComponentFixture<IntegerValueInputComponent>;

  beforeEach(waitForAsync(() => {
    TestBed.configureTestingModule({
      imports: [
        FormsModule,
        TranslateModule.forRoot({
          loader: {
            provide: TranslateLoader,
            useClass: TranslateLoaderMock,
          },
        }),
        IntegerValueInputComponent,
      ],
      providers: [],
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(IntegerValueInputComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should not show a validation error if the input field was left untouched but left empty', () => {
    const validationError = fixture.debugElement.query(By.css('.validation-error'));
    expect(validationError).toBeFalsy();
  });

  it('should show a validation error if the input field was touched but left empty', fakeAsync(() => {
    component.value = undefined;
    fixture.detectChanges();
    tick();

    const input = fixture.debugElement.query(By.css('input'));
    input.triggerEventHandler('blur', null);

    fixture.detectChanges();

    const validationError = fixture.debugElement.query(By.css('.validation-error'));
    expect(validationError).toBeTruthy();
  }));

  it('should not show a validation error if the input field was touched but not left empty', fakeAsync(() => {
    component.value = 1;
    fixture.detectChanges();
    tick();

    const input = fixture.debugElement.query(By.css('input'));
    input.triggerEventHandler('blur', null);

    fixture.detectChanges();

    const validationError = fixture.debugElement.query(By.css('.validation-error'));
    expect(validationError).toBeFalsy();
  }));
});
