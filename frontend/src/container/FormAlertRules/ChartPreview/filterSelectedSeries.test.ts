import { QueryData } from 'types/api/widgets/getQuery';

import {
	filterAlertChartSeries,
	filterSeriesBySelectedQuery,
} from './filterSelectedSeries';

const buildSeries = (queryName: string, value: string): QueryData => ({
	metric: { 'k8s.node.name': 'node-1' },
	queryName,
	values: [
		[1789021140, value],
		[1789021200, value],
	],
});

describe('filterSeriesBySelectedQuery', () => {
	const rawUsed = buildSeries('used', '474387750912');
	const rawTotal = buildSeries('total', '588395765760');
	const pct = buildSeries('disk_used_pct', '80.624');
	const result = [rawUsed, rawTotal, pct];

	it('keeps only the series matching the selected query name', () => {
		expect(filterSeriesBySelectedQuery(result, 'disk_used_pct')).toStrictEqual([
			pct,
		]);
	});

	it('returns all series when no selected query name is provided', () => {
		expect(filterSeriesBySelectedQuery(result, undefined)).toStrictEqual(result);
		expect(filterSeriesBySelectedQuery(result, '')).toStrictEqual(result);
	});

	it('shows nothing when the selected query has no rows (no raw-input fallback)', () => {
		expect(filterSeriesBySelectedQuery(result, 'missing_query')).toStrictEqual(
			[],
		);
	});

	it('keeps every per-group series of the selected query', () => {
		const pctNode2 = buildSeries('disk_used_pct', '77.379');
		const multiNode = [rawUsed, rawTotal, pct, pctNode2];
		expect(filterSeriesBySelectedQuery(multiNode, 'disk_used_pct')).toStrictEqual(
			[pct, pctNode2],
		);
	});
});

describe('filterAlertChartSeries', () => {
	it('filters the result list inside the payload', () => {
		const payload = {
			data: {
				result: [buildSeries('used', '1'), buildSeries('mem_used_pct', '59')],
			},
		};
		const filtered = filterAlertChartSeries(payload, 'mem_used_pct');
		expect(filtered?.data.result.map((s) => s.queryName)).toStrictEqual([
			'mem_used_pct',
		]);
	});

	it('passes through null payloads untouched', () => {
		expect(filterAlertChartSeries(null, 'A')).toBeNull();
	});

	it('passes through payloads without a result list untouched', () => {
		const payload = { data: { result: [] } };
		expect(filterAlertChartSeries(payload, 'A')).toStrictEqual(payload);
	});
});
