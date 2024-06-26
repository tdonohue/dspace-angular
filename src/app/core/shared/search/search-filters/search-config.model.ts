import {
  autoserialize,
  deserialize,
} from 'cerialize';

import { FilterType } from '../../../../shared/search/models/filter-type.model';
import { typedObject } from '../../../cache/builders/build-decorators';
import { CacheableObject } from '../../../cache/cacheable-object.model';
import { HALLink } from '../../hal-link.model';
import { ResourceType } from '../../resource-type';
import { SEARCH_CONFIG } from './search-config.resource-type';

/**
 * The configuration for a search
 */
@typedObject
export class SearchConfig implements CacheableObject {
  static type = SEARCH_CONFIG;

  /**
   * The id of this search configuration.
   */
  @autoserialize
  id: string;

  /**
   * The configured filters.
   */
  @autoserialize
  filters: FilterConfig[];

  /**
   * The configured sort options.
   */
  @autoserialize
  sortOptions: SortConfig[];

  /**
   * The object type.
   */
  @autoserialize
  type: ResourceType;

  /**
   * The {@link HALLink}s for this Item
   */
  @deserialize
  _links: {
    facets: HALLink;
    objects: HALLink;
    self: HALLink;
  };
}

/**
 * Interface to model filter's configuration.
 */
export interface FilterConfig {
  filter: string;
  hasFacets: boolean;
  operators: OperatorConfig[];
  openByDefault: boolean;
  pageSize: number;
  type: FilterType;
}

/**
 * Interface to model sort option's configuration.
 */
export interface SortConfig {
  name: string;
  sortOrder: string;
}

/**
 * Interface to model operator's configuration.
 */
export interface OperatorConfig {
  operator: string;
}
