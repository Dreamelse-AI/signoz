import { QueryData } from 'types/api/widgets/getQuery';

/**
 * Alert charts evaluate exactly one query/formula (the condition's selected
 * query), but the query_range response carries series for every query in the
 * composite query — including the raw inputs feeding a formula (e.g. `used` /
 * `total` bytes next to a `used/total*100` percentage formula). Plotting all
 * of them mixes incompatible units on one Y axis and flattens the evaluated
 * line into noise, so the preview must keep only the series the threshold is
 * evaluated against.
 *
 * Strict on purpose: when the selected query has no rows the chart stays
 * empty — it must NOT fall back to plotting the raw input queries.
 */
export function filterSeriesBySelectedQuery(
	result: QueryData[],
	selectedQueryName?: string,
): QueryData[] {
	if (!selectedQueryName) {
		return result;
	}
	return result.filter((series) => series.queryName === selectedQueryName);
}

/**
 * Extracts the selected query name from the alert definition's condition.
 * Rules keep it at `condition.selectedQueryName`; it is optional for
 * condition shapes without that field.
 */
export function getSelectedQueryName(condition: unknown): string | undefined {
	if (
		condition &&
		typeof condition === 'object' &&
		'selectedQueryName' in condition
	) {
		const value = (condition as { selectedQueryName?: unknown })
			.selectedQueryName;
		if (typeof value === 'string' && value !== '') {
			return value;
		}
	}
	return undefined;
}

/**
 * Narrows a query_range payload's result list down to the series the alert
 * condition evaluates. Generic over the payload shape so callers keep their
 * concrete type (legacy MetricRangePayloadProps included). Shared by both
 * alert chart previews (FormAlertRules + CreateAlertV2) so edit and details
 * views stay consistent.
 */
export function filterAlertChartSeries<
	T extends { data: { result: QueryData[] } },
>(payload: T | null, selectedQueryName?: string): T | null {
	if (!payload?.data?.result) {
		return payload;
	}
	return {
		...payload,
		data: {
			...payload.data,
			result: filterSeriesBySelectedQuery(payload.data.result, selectedQueryName),
		},
	};
}
