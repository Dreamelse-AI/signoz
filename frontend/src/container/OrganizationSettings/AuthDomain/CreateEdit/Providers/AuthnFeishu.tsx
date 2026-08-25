import { useCallback, useState } from 'react';
import { Style } from '@signozhq/design-tokens';
import { CircleHelp } from '@signozhq/icons';
import { Callout } from '@signozhq/ui/callout';
import { Checkbox } from '@signozhq/ui/checkbox';
import { Input } from '@signozhq/ui/input';
import { Form, Tooltip } from 'antd';

import RoleMappingSection from './components/RoleMappingSection';

import './Providers.styles.scss';

function ConfigureFeishuAuthnProvider({
	isCreate,
}: {
	isCreate: boolean;
}): JSX.Element {
	const form = Form.useFormInstance();

	const [isRoleMappingExpanded, setIsRoleMappingExpanded] =
		useState<boolean>(false);

	const handleRoleMappingChange = useCallback((expanded: boolean): void => {
		setIsRoleMappingExpanded(expanded);
	}, []);

	return (
		<div className="authn-provider">
			<section className="authn-provider__header">
				<h3 className="authn-provider__title">Edit Feishu Authentication</h3>
				<p className="authn-provider__description">
					Enter the App ID and App Secret of your Feishu (Lark) app obtained from the
					Feishu Open Platform. The app needs the email scopes so SigNoz can match
					users by their enterprise email.
				</p>
			</section>

			<div className="authn-provider__columns">
				{/* Left Column - Core OAuth Settings */}
				<div className="authn-provider__left">
					<div className="authn-provider__field-group">
						<label className="authn-provider__label" htmlFor="feishu-domain">
							Domain
							<Tooltip title="The email domain for users who should use SSO (e.g., `example.com` for users with `@example.com` emails)">
								<CircleHelp size={14} color={Style.L3_FOREGROUND} cursor="help" />
							</Tooltip>
						</label>
						<Form.Item
							name="name"
							className="authn-provider__form-item"
							rules={[
								{ required: true, message: 'Domain is required', whitespace: true },
							]}
						>
							<Input id="feishu-domain" disabled={!isCreate} />
						</Form.Item>
					</div>

					<div className="authn-provider__field-group">
						<label className="authn-provider__label" htmlFor="feishu-client-id">
							App ID
							<Tooltip title="The App ID of your Feishu app. For example, cli_a1b2c3d4e5f6g7h8.">
								<CircleHelp size={14} color={Style.L3_FOREGROUND} cursor="help" />
							</Tooltip>
						</label>
						<Form.Item
							name={['feishuConfig', 'clientId']}
							className="authn-provider__form-item"
							rules={[
								{ required: true, message: 'App ID is required', whitespace: true },
							]}
						>
							<Input id="feishu-client-id" />
						</Form.Item>
					</div>

					<div className="authn-provider__field-group">
						<label className="authn-provider__label" htmlFor="feishu-client-secret">
							App Secret
							<Tooltip title="The App Secret of your Feishu app.">
								<CircleHelp size={14} color={Style.L3_FOREGROUND} cursor="help" />
							</Tooltip>
						</label>
						<Form.Item
							name={['feishuConfig', 'clientSecret']}
							className="authn-provider__form-item"
							rules={[
								{
									required: true,
									message: 'App Secret is required',
									whitespace: true,
								},
							]}
						>
							<Input id="feishu-client-secret" />
						</Form.Item>
					</div>

					<div className="authn-provider__checkbox-row">
						<Form.Item
							name={['feishuConfig', 'useLark']}
							valuePropName="value"
							noStyle
						>
							<Checkbox
								id="feishu-use-lark"
								onChange={(checked: boolean): void => {
									form.setFieldValue(['feishuConfig', 'useLark'], checked);
								}}
							>
								Use Lark (International)
							</Checkbox>
						</Form.Item>
						<Tooltip title="Use the Lark (larksuite.com) endpoints instead of the Feishu (feishu.cn) endpoints. Enable this if your organization is on Lark International.">
							<CircleHelp size={14} color={Style.L3_FOREGROUND} cursor="help" />
						</Tooltip>
					</div>

					<div className="authn-provider__callout-wrapper">
						<Callout type="warning" size="small" showIcon className="callout">
							Feishu OAuth2 won&apos;t be enabled unless you enter all the attributes
							above
						</Callout>
					</div>
				</div>

				{/* Right Column - Advanced Settings */}
				<div className="authn-provider__right">
					<RoleMappingSection
						fieldNamePrefix={['roleMapping']}
						isExpanded={isRoleMappingExpanded}
						onExpandChange={handleRoleMappingChange}
					/>
				</div>
			</div>
		</div>
	);
}

export default ConfigureFeishuAuthnProvider;
