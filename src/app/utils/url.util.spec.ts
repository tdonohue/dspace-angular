import { of } from 'rxjs';
import { ConfigurationProperty } from '@dspace/core/shared/configuration-property.model';
import { ConfigurationDataService } from '@dspace/core/data/configuration-data.service';
import { getBaseUrl, getHostname } from './url.util';
import { createFailedRemoteDataObject$, createSuccessfulRemoteDataObject$ } from '@dspace/core/utilities/remote-data.utils';
import { environment } from 'src/environments/environment';

describe('URL Utils', () => {
  describe('getBaseUrl', () => {
    let configurationService: jasmine.SpyObj<ConfigurationDataService>;
    let originalBaseUrl;

    beforeEach(() => {
      // Store original environment variable to restore after tests
      originalBaseUrl = environment.ui.baseUrl;

      // Clear environment variable for tests
      environment.ui.baseUrl = '';

      configurationService = jasmine.createSpyObj('ConfigurationDataService', {
        findByPropertyName: of(null),
      });
    });

    afterEach(() => {
      // Restore original environment variable after tests
      environment.ui.baseUrl = originalBaseUrl;
    });

    describe('when environment.ui.baseUrl is set', () => {
      beforeEach(() => {
        environment.ui.baseUrl = 'http://localhost:4000';
      });

      it('should return the environment.ui.baseUrl as an Observable', (done) => {
        const expectedUrl = 'http://localhost:4000';
        
        getBaseUrl(configurationService).subscribe((url) => {
          expect(url).toBe(expectedUrl);
          done();
        });
      });

      it('should not call configurationService', (done) => {
        getBaseUrl(configurationService).subscribe(() => {
          expect(configurationService.findByPropertyName).not.toHaveBeenCalled();
          done();
        });
      });
    });

    describe('when environment.ui.baseUrl is not set', () => {
      beforeEach(() => {
        // Explicitly set baseUrl to undefined to simulate it not being set
        environment.ui.baseUrl = undefined;

        const mockRemoteData = createSuccessfulRemoteDataObject$({
                      ... new ConfigurationProperty(),
                      name: 'dspace.ui.url',
                      values: ['https://dspace.example.com'],
                    });
        configurationService.findByPropertyName.and.returnValue(mockRemoteData);
      });

      it('should call findByPropertyName with the correct property name', (done) => {
        getBaseUrl(configurationService).subscribe(() => {
          expect(configurationService.findByPropertyName).toHaveBeenCalledWith('dspace.ui.url');
          done();
        });
      });

      it('should return the dspace.ui.url configuration value', (done) => {
        const expectedUrl = 'https://dspace.example.com';
        
        getBaseUrl(configurationService).subscribe((url) => {
          expect(url).toBe(expectedUrl);
          done();
        });
      });
    });

    describe('when both environment.ui.baseUrl and dspace.ui.url are not configured', () => {
      beforeEach(() => {
        // Explicitly set baseUrl to undefined to simulate it not being set
        environment.ui.baseUrl = undefined;

        const mockRemoteData = createSuccessfulRemoteDataObject$({
                      ... new ConfigurationProperty(),
                      name: 'dspace.ui.url',
                      values: [],
                    });
        configurationService.findByPropertyName.and.returnValue(mockRemoteData);
      });

      it('should throw an error', (done) => {
        getBaseUrl(configurationService).subscribe({
          error: (error: unknown) => {
            expect(error).toBeDefined();
            done();
          },
        });
      });
    });

    describe('when configuration service fails', () => {
      beforeEach(() => {
        configurationService.findByPropertyName.and.returnValue(createFailedRemoteDataObject$());
      });

      it('should throw an error', (done) => {
        getBaseUrl(configurationService).subscribe({
          error: (error: unknown) => {
            expect(error).toBeDefined();
            done();
          },
        });
      });
    });
  });

  describe('getHostname', () => {
    it('should extract hostname from a simple URL', () => {
      const url = 'https://dspace.example.com';
      const result = getHostname(url);

      expect(result).toBe('dspace.example.com');
    });

    it('should extract hostname from URL with port', () => {
      const url = 'https://dspace.example.com:4000';
      const result = getHostname(url);

      expect(result).toBe('dspace.example.com');
    });

    it('should extract hostname from URL with path', () => {
      const url = 'https://dspace.example.com/community-list';
      const result = getHostname(url);

      expect(result).toBe('dspace.example.com');
    });

    it('should extract hostname from URL with query parameters', () => {
      const url = 'https://dspace.example.com/search?query=test&spc.page=1';
      const result = getHostname(url);

      expect(result).toBe('dspace.example.com');
    });

    it('should extract hostname from localhost URL', () => {
      const url = 'http://localhost:4000';
      const result = getHostname(url);

      expect(result).toBe('localhost');
    });

    it('should throw an error for invalid URL', () => {
      const invalidUrl = 'not-a-valid-url';

      expect(() => {
        getHostname(invalidUrl);
      }).toThrowError();
    });
  });
});