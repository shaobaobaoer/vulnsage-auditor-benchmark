# VulnSage Benchmark Evaluation Report

**Line tolerance**: ±5
**Total effective samples**: 187
**HIT rate**: 103/187 (55.1%)

## Summary

| Metric | Count | Rate |
|--------|-------|------|
| Has results file | 181/187 | 96.8% |
| Has non-empty findings | 177/187 | 94.7% |
| **HIT (path match)** | **103/187** | **55.1%** |
| Vuln type also matched | 101/187 | 54.0% |

## By Language

| Language | Total | HIT | Rate |
|----------|-------|-----|------|
| go | 41 | 21 | 51.2% |
| java | 52 | 27 | 51.9% |
| js | 43 | 22 | 51.2% |
| python | 51 | 33 | 64.7% |

## Detailed Results

| # | Sample | HIT | Type | Δ | Detail |
|---|--------|-----|------|---|--------|
| 1 | go-sast-CVE-2022-0870 | ✗ | ✗ | - | MISS (no file match: actual={'internal/db/webhook.go', 'internal/db/repo.go'}, gt={'internal/route/repo/webhook.go'}) |
| 2 | go-sast-CVE-2022-1058 | ✗ | ✗ | - | MISS (file match but line Δ220 > 5) |
| 3 | go-sast-CVE-2022-1464 | ✓ | ✓ | 1 | Type: ✓ xss \| File: ✓ internal/cmd/web.go \| Line: ✓ Δ1 |
| 4 | go-sast-CVE-2022-1883 | ✓ | ✓ | 0 | Type: ✓ sql-injection \| File: ✓ db/db.go \| Line: ✓ Δ0 |
| 5 | go-sast-CVE-2022-1928 | ✗ | ✗ | - | MISS (no file match: actual={'routers/web/repo/blame.go', 'routers/web/repo/lfs.go'}, gt={'routers/common/repo.go', 'modules/typesniffer/typesniffer.go'}) |
| 6 | go-sast-CVE-2022-1993 | ✗ | ✗ | - | MISS (no file match: actual={'internal/lfsutil/storage.go', 'internal/db/repo_editor.go'}, gt={'internal/route/repo/http.go'}) |
| 7 | go-sast-CVE-2022-2024 | ✗ | ✗ | - | MISS (no file match: actual={'internal/cmd/hook.go'}, gt={'internal/db/repo_editor.go'}) |
| 8 | go-sast-CVE-2022-24753 | ✓ | ✓ | 0 | Type: ✓ command-injection \| File: ✓ pkg/config/config.go \| Line: ✓ Δ0 |
| 9 | go-sast-CVE-2022-31036 | ✗ | ✗ | - | MISS (no file match: actual={'util/io/files/tar.go'}, gt={'reposerver/repository/repository.go', 'util/helm/helm.go', 'util/io/path/resolved.go'}) |
| 10 | go-sast-CVE-2022-31038 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ templates/repo/issue/list.tmpl \| Line: ✓ Δ0 |
| 11 | go-sast-CVE-2022-32171 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ web/src/views/Template.vue \| Line: ✓ Δ0 |
| 12 | go-sast-CVE-2022-32172 | ✓ | ✓ | 4 | Type: ✓ xss \| File: ✓ web/src/views/Template.vue \| Line: ✓ Δ4 |
| 13 | go-sast-CVE-2022-35919 | ✓ | ✓ | 1 | Type: ✓ path-traversal \| File: ✓ cmd/update.go \| Line: ✓ Δ1 |
| 14 | go-sast-CVE-2022-3751 | ✓ | ✓ | 0 | Type: ✓ sql-injection \| File: ✓ core/chat/persistence.go \| Line: ✓ Δ0 |
| 15 | go-sast-CVE-2022-41920 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ fileutil/file.go \| Line: ✓ Δ0 |
| 16 | go-sast-CVE-2022-4609 | ✗ | ✗ | - | MISS (no file match: actual={'server/rss.go'}, gt={'server/resource.go'}) |
| 17 | go-sast-CVE-2022-4690 | ✗ | ✗ | - | MISS (no file match: actual={'server/rss.go'}, gt={'server/resource.go'}) |
| 18 | go-sast-CVE-2022-4691 | ✗ | ✗ | - | MISS (no file match: actual={'server/rss.go'}, gt={'server/resource.go'}) |
| 19 | go-sast-CVE-2022-4692 | ✗ | ✗ | - | MISS (no file match: actual={'server/rss.go'}, gt={'server/resource.go'}) |
| 20 | go-sast-CVE-2025-27088 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ templates/folder-list.tpl \| Line: ✓ Δ0 |
| 21 | go-sast-CVE-2025-30223 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ server/web/templatefunc.go \| Line: ✓ Δ0 |
| 22 | go-sast-CVE-2025-52477 | ✓ | ✓ | 0 | Type: ✓ ssrf \| File: ✓ pkg/provider/provider.go \| Line: ✓ Δ0 |
| 23 | go-sast-CVE-2025-54386 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ pkg/plugins/client.go \| Line: ✓ Δ0 |
| 24 | go-sast-CVE-2025-64101 | ✗ | ✗ | - | MISS (no file match: actual={'internal/api/ui/login/init_password_handler.go'}, gt={'internal/api/http/middleware/origin_interceptor.go', 'internal/api/http/request_context.go'}) |
| 25 | go-sast-CVE-2025-64346 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ extractor.go \| Line: ✓ Δ0 |
| 26 | go-sast-CVE-2025-64522 | ✗ | ✗ | - | MISS (file match but line Δ49 > 5) |
| 27 | go-sast-CVE-2026-23644 | ✗ | ✗ | - | NO RESULTS |
| 28 | go-sast-CVE-2026-25059 | ✗ | ✗ | - | MISS (no file match: actual={'server/handles/fsmanage.go'}, gt={'server/handles/archive.go'}) |
| 29 | go-sast-CVE-2026-25145 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ pkg/config/config.go \| Line: ✓ Δ0 |
| 30 | go-sast-CVE-2026-26187 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ pkg/block/local/adapter.go \| Line: ✓ Δ0 |
| 31 | go-sast-CVE-2026-27018 | ✗ | ✗ | - | MISS (no file match: actual={'pkg/modules/chromium/browser.go'}, gt={'pkg/modules/chromium/events.go', 'pkg/gotenberg/filter.go'}) |
| 32 | go-sast-CVE-2026-32241 | ✗ | ✗ | - | MISS (file match but line Δ54 > 5) |
| 33 | go-sast-CVE-2026-32758 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ http/resource.go \| Line: ✓ Δ0 |
| 34 | go-sast-CVE-2026-32805 | ✓ | ✓ | 2 | Type: ✓ path-traversal \| File: ✓ webserver/api/v1/decoder.go \| Line: ✓ Δ2 |
| 35 | go-sast-CVE-2026-33675 | ✗ | ✗ | - | MISS (file match but line Δ13 > 5) |
| 36 | go-sast-CVE-2026-33679 | ✓ | ✓ | 0 | Type: ✓ ssrf \| File: ✓ pkg/utils/avatar.go \| Line: ✓ Δ0 |
| 37 | go-sast-CVE-2026-33758 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ builtin/credential/jwt/html_responses.go \| Line: ✓ Δ0 |
| 38 | go-sast-CVE-2026-34041 | ✗ | ✗ | - | MISS (file match but line Δ17 > 5) |
| 39 | go-sast-CVE-2026-34206 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ main.go \| Line: ✓ Δ0 |
| 40 | go-sast-CVE-2026-34585 | ✗ | ✗ | - | MISS (no file match: actual={'kernel/model/blockial.go'}, gt={'kernel/model/file.go', 'kernel/go.mod'}) |
| 41 | go-sast-CVE-2026-34783 | ✗ | ✗ | - | MISS (no file match: actual={'pkg/stdlib/io/fs/write.go'}, gt={'pkg/stdlib/io/fs/read.go'}) |
| 42 | java-sast-CVE-2022-1722 | ✓ | ✓ | 1 | Type: ✓ ssrf \| File: ✓ src/main/java/com/mxgraph/online/ProxyServlet.java \| Line: ✓ Δ1 |
| 43 | java-sast-CVE-2022-21675 | ✗ | ✗ | - | EMPTY FINDINGS |
| 44 | java-sast-CVE-2022-23060 | ✗ | ✗ | - | MISS (no file match: actual={'sm-shop/src/main/java/com/salesmanager/shop/admin/controller/content/StaticContentController.java'}, gt={'sm-core/src/main/java/com/salesmanager/core/business/modules/cms/product/ProductFileManagerImpl.java', 'sm-core/src/main/java/com/salesmanager/core/business/services/catalog/product/image/ProductImageServiceImpl.java', 'sm-shop/src/main/java/com/salesmanager/shop/admin/controller/products/ProductImagesController.java'}) |
| 45 | java-sast-CVE-2022-23082 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ src/main/java/io/whitesource/cure/FileSecurityUtils.java \| Line: ✓ Δ0 |
| 46 | java-sast-CVE-2022-23544 | ✗ | ✗ | - | MISS (no file match: actual={'test-track/backend/src/main/java/io/metersphere/service/wapper/IssueProxyResourceService.java'}, gt={'test-track/backend/src/main/java/io/metersphere/service/issue/platform/ZentaoPlatform.java'}) |
| 47 | java-sast-CVE-2022-23612 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ web/src/main/java/org/openmrs/web/filter/StartupFilter.java \| Line: ✓ Δ0 |
| 48 | java-sast-CVE-2022-23618 | ✗ | ✗ | - | NO RESULTS |
| 49 | java-sast-CVE-2022-23620 | ✗ | ✗ | - | MISS (file match but line Δ6 > 5) |
| 50 | java-sast-CVE-2022-23622 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ xwiki-platform-core/xwiki-platform-web/xwiki-platform-web-templates/src/main/resources/templates/registerinline.vm \| Line: ✓ Δ0 |
| 51 | java-sast-CVE-2022-24816 | ✓ | ✓ | 5 | Type: ✓ code-injection \| File: ✓ jt-jiffle/jt-jiffle-language/src/main/java/it/geosolutions/jaiext/jiffle/Jiffle.java \| Line: ✓ Δ5 |
| 52 | java-sast-CVE-2022-24848 | ✗ | ✗ | - | MISS (file match but line Δ7 > 5) |
| 53 | java-sast-CVE-2022-24861 | ✓ | ✓ | 0 | Type: ✓ code-injection \| File: ✓ core/src/main/java/com/databasir/core/infrastructure/driver/DriverResources.java \| Line: ✓ Δ0 |
| 54 | java-sast-CVE-2022-29251 | ✗ | ✗ | - | MISS (file match but line Δ6 > 5) |
| 55 | java-sast-CVE-2022-29253 | ✓ | ✓ | 4 | Type: ✓ path-traversal \| File: ✓ xwiki-platform-core/xwiki-platform-oldcore/src/main/java/com/xpn/xwiki/internal/template/InternalTemplateManager.java \| Line: ✓ Δ4 |
| 56 | java-sast-CVE-2022-31192 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ dspace-jspui/src/main/webapp/requestItem/request-letter.jsp \| Line: ✓ Δ0 |
| 57 | java-sast-CVE-2022-31193 | ✓ | ✓ | 0 | Type: ✓ open-redirect \| File: ✓ dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java \| Line: ✓ Δ0 |
| 58 | java-sast-CVE-2022-31194 | ✗ | ✗ | - | MISS (file match but line Δ1303 > 5) |
| 59 | java-sast-CVE-2022-31196 | ✓ | ✓ | 0 | Type: ✓ ssrf \| File: ✓ core/src/main/java/com/databasir/core/infrastructure/driver/DriverResources.java \| Line: ✓ Δ0 |
| 60 | java-sast-CVE-2022-36094 | ✗ | ✗ | - | NO RESULTS |
| 61 | java-sast-CVE-2022-36096 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ xwiki-platform-core/xwiki-platform-index/xwiki-platform-index-ui/src/main/resources/XWiki/DeletedAttachments.xml \| Line: ✓ Δ0 |
| 62 | java-sast-CVE-2022-36097 | ✗ | ✗ | - | NO RESULTS |
| 63 | java-sast-CVE-2022-36098 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ xwiki-platform-core/xwiki-platform-mentions/xwiki-platform-mentions-ui/src/main/resources/XWiki/Mentions/MentionsMacro.xml \| Line: ✓ Δ0 |
| 64 | java-sast-CVE-2022-36100 | ✓ | ✓ | 0 | Type: ✓ code-injection \| File: ✓ xwiki-platform-core/xwiki-platform-tag/xwiki-platform-tag-ui/src/main/resources/Main/Tags.xml \| Line: ✓ Δ0 |
| 65 | java-sast-CVE-2022-39367 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ qtiworks-engine/src/main/java/uk/ac/ed/ph/qtiworks/services/AssessmentPackageFileImporter.java \| Line: ✓ Δ0 |
| 66 | java-sast-CVE-2022-4065 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ testng-core/src/main/java/org/testng/JarFileUtils.java \| Line: ✓ Δ0 |
| 67 | java-sast-CVE-2022-41931 | ✓ | ✓ | 1 | Type: ✓ code-injection \| File: ✓ xwiki-platform-core/xwiki-platform-icon/xwiki-platform-icon-ui/src/main/resources/IconThemesCode/IconPickerMacro.xml \| Line: ✓ Δ1 |
| 68 | java-sast-CVE-2022-41965 | ✗ | ✗ | - | MISS (no file match: actual={'modules/engage-ui/src/main/java/org/opencastproject/engage/ui/PlayerRedirect.java'}, gt={'modules/engage-paella-player/src/main/paella-opencast/ui/auth.html'}) |
| 69 | java-sast-CVE-2022-4454 | ✓ | ✓ | 0 | Type: ✓ sql-injection \| File: ✓ src/main/java/custom/application/search.java \| Line: ✓ Δ0 |
| 70 | java-sast-CVE-2022-4493 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ src/test/java/io/scif/util/DefaultSampleFilesService.java \| Line: ✓ Δ0 |
| 71 | java-sast-CVE-2022-4494 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ src/main/java/bspkrs/mmv/RemoteZipHandler.java \| Line: ✓ Δ0 |
| 72 | java-sast-CVE-2022-4520 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ components/registry/org.wso2.carbon.registry.search.ui/src/main/resources/web/search/advancedSearchForm-ajaxprocessor.jsp \| Line: ✓ Δ0 |
| 73 | java-sast-CVE-2022-4521 | ✗ | ✗ | - | MISS (no file match: actual={'components/registry/org.wso2.carbon.registry.common/src/main/java/org/wso2/carbon/registry/common/utils/CommonUtil.java'}, gt={'components/registry/org.wso2.carbon.registry.profiles.ui/src/main/resources/web/userprofiles/profiles_add_ajaxprocessor.jsp'}) |
| 74 | java-sast-CVE-2022-4593 | ✗ | ✗ | - | MISS (no file match: actual={'src/main/java/cz/softinel/uaf/vc/tag/VisualComponentTag.java'}, gt={'src/main/java/cz/softinel/uaf/filter/FilterHelper.java', 'src/main/java/cz/softinel/retra/invoice/web/InvoiceController.java', 'src/main/webapp/WEB-INF/jsp/retra/InvoiceList.jsp'}) |
| 75 | java-sast-CVE-2022-4594 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ 1.x/src/rogatkin/web/WarRoller.java \| Line: ✓ Δ0 |
| 76 | java-sast-CVE-2022-46166 | ✗ | ✗ | - | MISS (no file match: actual={'spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/MicrosoftTeamsNotifier.java', 'spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/TelegramNotifier.java', 'spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/SlackNotifier.java'}, gt={'spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/DingTalkNotifier.java'}) |
| 77 | java-sast-CVE-2022-4725 | ✗ | ✗ | - | MISS (no file match: actual={'aws-android-sdk-core/src/main/java/com/amazonaws/util/XpathUtils.java'}, gt={'aws-android-sdk-core/src/main/java/com/amazonaws/regions/RegionMetadataParser.java'}) |
| 78 | java-sast-CVE-2022-4772 | ✗ | ✗ | - | MISS (file match but line Δ9 > 5) |
| 79 | java-sast-CVE-2022-4878 | ✓ | ✓ | 3 | Type: ✓ path-traversal \| File: ✓ modules/common/app/utils/common/ZipUtil.java \| Line: ✓ Δ3 |
| 80 | java-sast-CVE-2022-4963 | ✓ | ✓ | 2 | Type: ✓ sql-injection \| File: ✓ tenant/src/main/java/org/folio/spring/tenant/hibernate/HibernateSchemaService.java \| Line: ✓ Δ2 |
| 81 | java-sast-CVE-2025-21621 | ✗ | ✗ | - | NO RESULTS |
| 82 | java-sast-CVE-2025-52472 | ✓ | ✓ | 3 | Type: ✓ sql-injection \| File: ✓ xwiki-platform-core/xwiki-platform-rest/xwiki-platform-rest-server/src/main/java/org/xwiki/rest/internal/resources/BaseSearchResult.java \| Line: ✓ Δ3 |
| 83 | java-sast-CVE-2025-55727 | ✗ | ✗ | - | MISS (no file match: actual={'ConfluenceColumn.xml'}, gt={'xwiki-pro-macros-confluence-bridges/xwiki-pro-macros-confluence-bridges-ui/src/main/resources/Confluence/Macros/ConfluenceColumn.xml'}) |
| 84 | java-sast-CVE-2025-62422 | ✗ | ✗ | - | MISS (no file match: actual={'core/core-backend/src/main/java/io/dataease/datasource/provider/CalciteProvider.java'}, gt={'core/core-backend/src/main/java/io/dataease/datasource/server/DatasourceServer.java', 'core/core-backend/src/main/java/io/dataease/datasource/provider/EsProvider.java'}) |
| 85 | java-sast-CVE-2025-66472 | ✗ | ✗ | - | MISS (no file match: actual={'xwiki-platform-core/xwiki-platform-flamingo/xwiki-platform-flamingo-skin/xwiki-platform-flamingo-skin-resources/src/main/resources/flamingo/delete.vm'}, gt={'xwiki-platform-core/xwiki-platform-appwithinminutes/xwiki-platform-appwithinminutes-ui/src/main/resources/AppWithinMinutes/DeleteApplication.xml', 'xwiki-platform-core/xwiki-platform-flamingo/xwiki-platform-flamingo-skin/xwiki-platform-flamingo-skin-resources/src/main/resources/flamingo/macros.vm'}) |
| 86 | java-sast-CVE-2025-66474 | ✗ | ✗ | - | MISS (no file match: actual={'xwiki-platform-core/xwiki-platform-rendering/xwiki-platform-rendering-macros/xwiki-platform-rendering-macro-script/src/main/java/org/xwiki/rendering/macro/script/AbstractJSR223ScriptMacro.java'}, gt={'xwiki-platform-core/xwiki-platform-oldcore/src/main/java/com/xpn/xwiki/doc/XWikiDocument.java'}) |
| 87 | java-sast-CVE-2025-7763 | ✗ | ✗ | - | MISS (no file match: actual={'modules/core/src/main/java/com/jeesite/modules/sys/web/SsoController.java'}, gt={'modules/cms/src/main/java/com/jeesite/modules/cms/web/SiteController.java'}) |
| 88 | java-sast-CVE-2025-7785 | ✓ | ✓ | 0 | Type: ✓ open-redirect \| File: ✓ modules/core/src/main/java/com/jeesite/modules/sys/web/SsoController.java \| Line: ✓ Δ0 |
| 89 | java-sast-CVE-2025-7949 | ✗ | ✗ | - | MISS (no file match: actual={'publiccms-parent/publiccms/src/main/resources/templates/admin/cmsDiy/preview.html'}, gt={'publiccms-parent/publiccms/src/main/webapp/resource/plugins/pdfjs/viewer.html'}) |
| 90 | java-sast-CVE-2025-7953 | ✓ | ✓ | 0 | Type: ✓ open-redirect \| File: ✓ publiccms-parent/publiccms/src/main/webapp/resource/plugins/pdfjs/viewer.html \| Line: ✓ Δ0 |
| 91 | java-sast-CVE-2025-8551 | ✗ | ✗ | - | MISS (no file match: actual={'src/main/resources/templates/theme/default/search.ftl'}, gt={'src/main/java/co/yiiu/pybbs/controller/admin/TopicAdminController.java', 'src/main/resources/templates/admin/topic/list.ftl'}) |
| 92 | java-sast-CVE-2025-8555 | ✗ | ✗ | - | MISS (no file match: actual={'src/main/resources/templates/theme/default/search.ftl'}, gt={'src/main/java/co/yiiu/pybbs/controller/admin/TopicAdminController.java'}) |
| 93 | java-sast-CVE-2025-8813 | ✓ | ✓ | 0 | Type: ✓ open-redirect \| File: ✓ src/main/java/co/yiiu/pybbs/controller/front/BaseController.java \| Line: ✓ Δ0 |
| 94 | js-sast-CVE-2022-0841 | ✓ | ✓ | 0 | Type: ✓ command-injection \| File: ✓ getLockfile.js \| Line: ✓ Δ0 |
| 95 | js-sast-CVE-2022-24723 | ✓ | ✓ | 1 | Type: ✓ open-redirect \| File: ✓ src/URI.js \| Line: ✓ Δ1 |
| 96 | js-sast-CVE-2022-24796 | ✓ | ✓ | 0 | Type: ✓ command-injection \| File: ✓ buildroot-external/patches/occu/0031-WebUI-Fix-FileUpload/occu/WebUI/www/config/fileupload.ccc \| Line: ✓ Δ0 |
| 97 | js-sast-CVE-2022-24876 | ✓ | ✓ | 1 | Type: ✓ xss \| File: ✓ js/modules/Kanban/Kanban.js \| Line: ✓ Δ1 |
| 98 | js-sast-CVE-2022-2494 | ✗ | ✗ | - | MISS (no file match: actual={'library/custom_template/ajax_code.php'}, gt={'portal/patient/scripts/app/patientdata.js'}) |
| 99 | js-sast-CVE-2022-25916 | ✓ | ✓ | 0 | Type: ✓ command-injection \| File: ✓ index.js \| Line: ✓ Δ0 |
| 100 | js-sast-CVE-2022-25923 | ✓ | ✓ | 0 | Type: ✓ command-injection \| File: ✓ index.js \| Line: ✓ Δ0 |
| 101 | js-sast-CVE-2022-25926 | ✓ | ✓ | 0 | Type: ✓ command-injection \| File: ✓ index.js \| Line: ✓ Δ0 |
| 102 | js-sast-CVE-2022-25937 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ index.js \| Line: ✓ Δ0 |
| 103 | js-sast-CVE-2022-25978 | ✗ | ✗ | - | MISS (no file match: actual={'server/rss.go'}, gt={'web/src/components/MemoResource.tsx', 'web/src/utils/resource.ts', 'server/resource.go', 'web/src/components/CreateResourceDialog.tsx'}) |
| 104 | js-sast-CVE-2022-25979 | ✗ | ✗ | - | MISS (file match but line Δ135 > 5) |
| 105 | js-sast-CVE-2022-2653 | ✗ | ✗ | - | MISS (no file match: actual={'server/api/controllers/attachments/download.js'}, gt={'server/api/controllers/attachments/download-thumbnail.js'}) |
| 106 | js-sast-CVE-2022-2900 | ✓ | ✓ | 0 | Type: ✓ ssrf \| File: ✓ lib/index.js \| Line: ✓ Δ0 |
| 107 | js-sast-CVE-2022-2932 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ src/js/views/tooltip.ts \| Line: ✓ Δ0 |
| 108 | js-sast-CVE-2022-31035 | ✗ | ✗ | - | MISS (no file match: actual={'ui/src/app/applications/components/application-summary/application-summary.tsx'}, gt={'ui/src/app/applications/components/applications-list/applications-tiles.tsx', 'ui/src/app/applications/components/utils.tsx', 'ui/src/app/applications/components/application-urls.tsx'}) |
| 109 | js-sast-CVE-2022-31094 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ features/recently-viewed-projects.js \| Line: ✓ Δ0 |
| 110 | js-sast-CVE-2022-3211 | ✗ | ✗ | - | MISS (no file match: actual={'bundles/AdminBundle/Controller/Admin/TagsController.php'}, gt={'bundles/AdminBundle/Resources/public/js/pimcore/element/properties.js'}) |
| 111 | js-sast-CVE-2022-35942 | ✗ | ✗ | - | MISS (file match but line Δ410 > 5) |
| 112 | js-sast-CVE-2022-35949 | ✓ | ✓ | 0 | Type: ✓ ssrf \| File: ✓ index.js \| Line: ✓ Δ0 |
| 113 | js-sast-CVE-2022-3950 | ✗ | ✗ | - | MISS (file match but line Δ11 > 5) |
| 114 | js-sast-CVE-2022-4456 | ✗ | ✗ | - | MISS (no file match: actual={'app/views/layouts/application.html.erb', 'app/views/locations/_sidebar.html.erb'}, gt={'app/controllers/imports_controller.rb', 'app/views/imports/show.html.erb'}) |
| 115 | js-sast-CVE-2022-4695 | ✗ | ✗ | - | MISS (no file match: actual={'plugin/http_getter/html_meta.go', 'server/rss.go', 'plugin/http_getter/image.go'}, gt={'web/src/labs/marked/parser/Link.ts', 'web/src/components/MemoContent.tsx', 'web/src/labs/marked/parser/Bold.ts', 'web/src/labs/marked/parser/PlainText.ts'}) |
| 116 | js-sast-CVE-2022-4735 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ static/js/media.js \| Line: ✓ Δ0 |
| 117 | js-sast-CVE-2022-4839 | ✗ | ✗ | - | MISS (no file match: actual={'server/rss.go'}, gt={'web/src/components/MemoContent.tsx', 'web/src/labs/marked/index.ts'}) |
| 118 | js-sast-CVE-2022-4840 | ✗ | ✗ | - | MISS (no file match: actual={'server/rss.go'}, gt={'web/src/labs/marked/index.ts'}) |
| 119 | js-sast-CVE-2022-4841 | ✗ | ✗ | - | MISS (no file match: actual={'server/rss.go'}, gt={'web/src/labs/marked/index.ts'}) |
| 120 | js-sast-CVE-2022-4865 | ✗ | ✗ | - | MISS (no file match: actual={'web/src/components/MemoContent.tsx'}, gt={'web/src/labs/marked/parser/Bold.ts'}) |
| 121 | js-sast-CVE-2022-4866 | ✗ | ✗ | - | MISS (no file match: actual={'web/src/components/MemoContent.tsx'}, gt={'web/src/labs/marked/parser/Link.ts', 'web/src/labs/marked/index.ts'}) |
| 122 | js-sast-CVE-2022-4942 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ lib/template-generator.js \| Line: ✓ Δ0 |
| 123 | js-sast-CVE-2022-4953 | ✗ | ✗ | - | MISS (no file match: actual={'assets/dev/js/editor/components/template-library/views/parts/preview.js'}, gt={'assets/dev/js/frontend/utils/lightbox/lightbox.js', 'assets/dev/js/frontend/utils/video-api/base-loader.js'}) |
| 124 | js-sast-CVE-2022-4966 | ✗ | ✗ | - | MISS (no file match: actual={'vendor/jquery.compat/jquery-1.11.1.js', 'avAdmin/elections-api-service.js'}, gt={'avAdmin/admin-directives/create/create.js', 'avAdmin/admin-directives/create/create.html'}) |
| 125 | js-sast-CVE-2025-11202 | ✗ | ✗ | - | MISS (no file match: actual={'src/utils/ssh.ts', 'src/index.ts'}, gt={'src/utils/validation.ts'}) |
| 126 | js-sast-CVE-2025-25300 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ src/smartbanner.js \| Line: ✓ Δ0 |
| 127 | js-sast-CVE-2025-27155 | ✓ | ✓ | 2 | Type: ✓ xss \| File: ✓ cmd/pineconesim/ui/modules/graph.js \| Line: ✓ Δ2 |
| 128 | js-sast-CVE-2025-27793 | ✗ | ✗ | - | MISS (no file match: actual={'packages/vega-expression/src/codegen.js'}, gt={'packages/vega-functions/src/functions/sequence.js'}) |
| 129 | js-sast-CVE-2025-31128 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ src/gifplayer.js \| Line: ✓ Δ0 |
| 130 | js-sast-CVE-2025-31476 | ✓ | ✗ | 1 | Type: xss→code-injection \| File: ✓ tarteaucitron.js \| Line: ✓ Δ1 |
| 131 | js-sast-CVE-2025-52573 | ✓ | ✓ | 0 | Type: ✓ command-injection \| File: ✓ src/index.ts \| Line: ✓ Δ0 |
| 132 | js-sast-CVE-2025-54128 | ✓ | ✓ | 1 | Type: ✓ xss \| File: ✓ src/app.js \| Line: ✓ Δ1 |
| 133 | js-sast-CVE-2025-61788 | ✗ | ✗ | - | MISS (no file match: actual={'modules/engage-ui/src/main/java/org/opencastproject/engage/ui/PlayerRedirect.java'}, gt={'modules/engage-paella-player-7/src/plugins/org.opencast.paella.descriptionPlugin.js'}) |
| 134 | js-sast-CVE-2025-62366 | ✓ | ✓ | 4 | Type: ✓ xss \| File: ✓ index.js \| Line: ✓ Δ4 |
| 135 | js-sast-CVE-2025-66400 | ✓ | ✓ | 1 | Type: ✓ xss \| File: ✓ lib/handlers/code.js \| Line: ✓ Δ1 |
| 136 | js-sast-CVE-2025-8267 | ✗ | ✗ | - | MISS (file match but line Δ30 > 5) |
| 137 | python-sast-CVE-2022-31020 | ✗ | ✗ | - | MISS (no file match: actual={'indy_node/utils/node_control_util.py'}, gt={'indy_node/server/upgrader.py', 'indy_node/utils/node_control_utils.py', 'indy_node/server/request_handlers/config_req_handlers/pool_upgrade_handler.py'}) |
| 138 | python-sast-CVE-2022-31040 | ✗ | ✗ | - | MISS (no file match: actual={'src/openforms/urls.py'}, gt={'src/openforms/templates/cookie_consent/_cookie_group.html', 'src/openforms/templates/cookie_consent/cookiegroup_list.html'}) |
| 139 | python-sast-CVE-2022-31136 | ✗ | ✗ | - | MISS (no file match: actual={'bookwyrm/templatetags/utilities.py'}, gt={'bookwyrm/views/status.py', 'bookwyrm/sanitize_html.py', 'bookwyrm/templates/snippets/trimmed_text.html'}) |
| 140 | python-sast-CVE-2022-31137 | ✗ | ✗ | - | MISS (no file match: actual={'app/funct.py', 'api/api_funct.py'}, gt={'app/options.py'}) |
| 141 | python-sast-CVE-2022-35918 | ✓ | ✓ | 1 | Type: ✓ path-traversal \| File: ✓ lib/streamlit/components/v1/components.py \| Line: ✓ Δ1 |
| 142 | python-sast-CVE-2022-36080 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ wiki.py \| Line: ✓ Δ0 |
| 143 | python-sast-CVE-2022-36081 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ wiki.py \| Line: ✓ Δ0 |
| 144 | python-sast-CVE-2022-36082 | ✓ | ✓ | 2 | Type: ✓ path-traversal \| File: ✓ mangadex_downloader/cli/validator.py \| Line: ✓ Δ2 |
| 145 | python-sast-CVE-2022-36087 | ✓ | ✓ | 1 | Type: ✓ dos \| File: ✓ oauthlib/oauth2/rfc6749/grant_types/base.py \| Line: ✓ Δ1 |
| 146 | python-sast-CVE-2022-39348 | ✓ | ✓ | 3 | Type: ✓ xss \| File: ✓ src/twisted/web/resource.py \| Line: ✓ Δ3 |
| 147 | python-sast-CVE-2022-3988 | ✓ | ✓ | 1 | Type: ✓ xss \| File: ✓ frappe/templates/includes/navbar/navbar_search.html \| Line: ✓ Δ1 |
| 148 | python-sast-CVE-2022-4105 | ✗ | ✗ | - | MISS (no file match: actual={'tcms/core/templatetags/extra_filters.py', 'tcms/testplans/templates/testplans/get.html'}, gt={'tcms/core/history.py'}) |
| 149 | python-sast-CVE-2022-4495 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ src/collective/dms/basecontent/browser/column.py \| Line: ✓ Δ0 |
| 150 | python-sast-CVE-2022-4526 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ photologue/templates/photologue/photo_detail.html \| Line: ✓ Δ0 |
| 151 | python-sast-CVE-2022-4572 | ✓ | ✓ | 1 | Type: ✓ path-traversal \| File: ✓ ubireader/ubifs/output.py \| Line: ✓ Δ1 |
| 152 | python-sast-CVE-2022-4589 | ✓ | ✓ | 0 | Type: ✓ open-redirect \| File: ✓ termsandconditions/views.py \| Line: ✓ Δ0 |
| 153 | python-sast-CVE-2022-4595 | ✓ | ✓ | 1 | Type: ✓ xss \| File: ✓ openipam/report/templates/report/exposed_hosts.html \| Line: ✓ Δ1 |
| 154 | python-sast-CVE-2022-4638 | ✗ | ✗ | - | MISS (file match but line Δ189 > 5) |
| 155 | python-sast-CVE-2022-4729 | ✓ | ✓ | 3 | Type: ✓ xss \| File: ✓ webapp/graphite/dashboard/views.py \| Line: ✓ Δ3 |
| 156 | python-sast-CVE-2022-4860 | ✓ | ✓ | 0 | Type: ✓ sql-injection \| File: ✓ daily_cron_jobs/methods_upload_user_stats.py \| Line: ✓ Δ0 |
| 157 | python-sast-CVE-2022-4885 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ src/scripts/jefferson \| Line: ✓ Δ0 |
| 158 | python-sast-CVE-2025-23211 | ✓ | ✓ | 0 | Type: ✓ code-injection \| File: ✓ cookbook/helper/template_helper.py \| Line: ✓ Δ0 |
| 159 | python-sast-CVE-2025-24372 | ✓ | ✗ | 0 | Type: xss→code-injection \| File: ✓ ckan/lib/uploader.py \| Line: ✓ Δ0 |
| 160 | python-sast-CVE-2025-25295 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ src/label_studio_sdk/converter/utils.py \| Line: ✓ Δ0 |
| 161 | python-sast-CVE-2025-3046 | ✗ | ✗ | - | NO RESULTS |
| 162 | python-sast-CVE-2025-31116 | ✓ | ✓ | 0 | Type: ✓ ssrf \| File: ✓ mobsf/MobSF/utils.py \| Line: ✓ Δ0 |
| 163 | python-sast-CVE-2025-31490 | ✓ | ✓ | 1 | Type: ✓ ssrf \| File: ✓ autogpt_platform/backend/backend/util/request.py \| Line: ✓ Δ1 |
| 164 | python-sast-CVE-2025-46335 | ✗ | ✗ | - | MISS (file match but line Δ54 > 5) |
| 165 | python-sast-CVE-2025-46571 | ✓ | ✓ | 2 | Type: ✓ xss \| File: ✓ backend/open_webui/routers/files.py \| Line: ✓ Δ2 |
| 166 | python-sast-CVE-2025-46719 | ✗ | ✗ | - | MISS (no file match: actual={'frontend/src/lib/components/chat/Messages.svelte'}, gt={'src/lib/components/chat/Messages/Markdown/MarkdownInlineTokens.svelte'}) |
| 167 | python-sast-CVE-2025-50181 | ✗ | ✗ | - | MISS (no file match: actual={'src/urllib3/connection.py'}, gt={'src/urllib3/poolmanager.py', 'src/urllib3/util/retry.py'}) |
| 168 | python-sast-CVE-2025-52895 | ✗ | ✗ | - | MISS (no file match: actual={'frappe/database/database.py'}, gt={'frappe/model/db_query.py'}) |
| 169 | python-sast-CVE-2025-54072 | ✓ | ✓ | 0 | Type: ✓ command-injection \| File: ✓ yt_dlp/postprocessor/exec.py \| Line: ✓ Δ0 |
| 170 | python-sast-CVE-2025-54381 | ✓ | ✓ | 2 | Type: ✓ ssrf \| File: ✓ src/_bentoml_impl/serde.py \| Line: ✓ Δ2 |
| 171 | python-sast-CVE-2025-54384 | ✓ | ✓ | 2 | Type: ✓ xss \| File: ✓ ckan/lib/helpers.py \| Line: ✓ Δ2 |
| 172 | python-sast-CVE-2025-54415 | ✗ | ✗ | - | MISS (no file match: actual={'dagfactory/dagfactory.py', 'dagfactory/utils.py'}, gt={'.github/workflows/cicd.yaml'}) |
| 173 | python-sast-CVE-2025-54430 | ✗ | ✗ | - | MISS (file match but line Δ7 > 5) |
| 174 | python-sast-CVE-2025-54433 | ✓ | ✓ | 5 | Type: ✓ path-traversal \| File: ✓ ingest/filestore.py \| Line: ✓ Δ5 |
| 175 | python-sast-CVE-2025-55156 | ✓ | ✓ | 1 | Type: ✓ sql-injection \| File: ✓ src/pyload/core/database/file_database.py \| Line: ✓ Δ1 |
| 176 | python-sast-CVE-2025-60249 | ✗ | ✗ | - | EMPTY FINDINGS |
| 177 | python-sast-CVE-2025-6166 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ python/api/image_get.py \| Line: ✓ Δ0 |
| 178 | python-sast-CVE-2025-61784 | ✓ | ✓ | 1 | Type: ✓ path-traversal \| File: ✓ src/llamafactory/api/chat.py \| Line: ✓ Δ1 |
| 179 | python-sast-CVE-2025-6210 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ llama-index-integrations/readers/llama-index-readers-obsidian/llama_index/readers/obsidian/base.py \| Line: ✓ Δ0 |
| 180 | python-sast-CVE-2025-64104 | ✗ | ✗ | - | EMPTY FINDINGS |
| 181 | python-sast-CVE-2025-64496 | ✗ | ✗ | - | MISS (no file match: actual={'backend/open_webui/main.py', 'backend/open_webui/utils/plugin.py'}, gt={'backend/open_webui/socket/main.py', 'backend/open_webui/utils/middleware.py'}) |
| 182 | python-sast-CVE-2025-66040 | ✓ | ✓ | 0 | Type: ✓ xss \| File: ✓ spotipy/oauth2.py \| Line: ✓ Δ0 |
| 183 | python-sast-CVE-2025-66205 | ✗ | ✗ | - | EMPTY FINDINGS |
| 184 | python-sast-CVE-2025-6773 | ✗ | ✗ | - | MISS (file match but line Δ134 > 5) |
| 185 | python-sast-CVE-2025-6776 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ app/plugins/oss/app/controller.py \| Line: ✓ Δ0 |
| 186 | python-sast-CVE-2025-8729 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ backend/service/upload_service.py \| Line: ✓ Δ0 |
| 187 | python-sast-CVE-2025-8917 | ✓ | ✓ | 0 | Type: ✓ path-traversal \| File: ✓ clearml/storage/util.py \| Line: ✓ Δ0 |

## MISS Analysis (78 samples)

### go-sast-CVE-2022-0870

- **Language**: go
- **GT vuln type**: ssrf
- **GT path points**: 3
  - `internal/route/repo/webhook.go:121`
  - `internal/route/repo/webhook.go:147`
  - `internal/route/repo/webhook.go:129`
- **Detail**: MISS (no file match: actual={'internal/db/webhook.go', 'internal/db/repo.go'}, gt={'internal/route/repo/webhook.go'})
- **Issues**: no_file_match

### go-sast-CVE-2022-1058

- **Language**: go
- **GT vuln type**: open-redirect
- **GT path points**: 3
  - `routers/web/auth/auth.go:132`
  - `modules/context/context.go:177`
  - `routers/web/auth/auth.go:141`
- **Detail**: MISS (file match but line Δ220 > 5)
- **Issues**: closest_line_distance=220

### go-sast-CVE-2022-1928

- **Language**: go
- **GT vuln type**: xss
- **GT path points**: 5
  - `routers/common/repo.go:45`
  - `routers/common/repo.go:89`
  - `routers/common/repo.go:67`
  - `modules/typesniffer/typesniffer.go:70`
  - `modules/typesniffer/typesniffer.go:44`
- **Detail**: MISS (no file match: actual={'routers/web/repo/blame.go', 'routers/web/repo/lfs.go'}, gt={'routers/common/repo.go', 'modules/typesniffer/typesniffer.go'})
- **Issues**: no_file_match

### go-sast-CVE-2022-1993

- **Language**: go
- **GT vuln type**: path-traversal
- **GT path points**: 5
  - `internal/route/repo/http.go:396`
  - `internal/route/repo/http.go:222`
  - `internal/route/repo/http.go:415`
  - `internal/route/repo/http.go:416`
  - `internal/route/repo/http.go:386`
- **Detail**: MISS (no file match: actual={'internal/lfsutil/storage.go', 'internal/db/repo_editor.go'}, gt={'internal/route/repo/http.go'})
- **Issues**: no_file_match

### go-sast-CVE-2022-2024

- **Language**: go
- **GT vuln type**: command-injection
- **GT path points**: 3
  - `internal/db/repo_editor.go:121`
  - `internal/db/repo_editor.go:180`
  - `internal/db/repo_editor.go:488`
- **Detail**: MISS (no file match: actual={'internal/cmd/hook.go'}, gt={'internal/db/repo_editor.go'})
- **Issues**: no_file_match

### go-sast-CVE-2022-31036

- **Language**: go
- **GT vuln type**: path-traversal
- **GT path points**: 4
  - `reposerver/repository/repository.go:1469`
  - `util/helm/helm.go:148`
  - `util/io/path/resolved.go:133`
  - `util/helm/helm.go:138`
- **Detail**: MISS (no file match: actual={'util/io/files/tar.go'}, gt={'reposerver/repository/repository.go', 'util/helm/helm.go', 'util/io/path/resolved.go'})
- **Issues**: no_file_match

### go-sast-CVE-2022-4609

- **Language**: go
- **GT vuln type**: xss
- **GT path points**: 4
  - `server/resource.go:44`
  - `server/resource.go:265`
  - `server/resource.go:58`
  - `server/resource.go:159`
- **Detail**: MISS (no file match: actual={'server/rss.go'}, gt={'server/resource.go'})
- **Issues**: no_file_match

### go-sast-CVE-2022-4690

- **Language**: go
- **GT vuln type**: xss
- **GT path points**: 2
  - `server/resource.go:44`
  - `server/resource.go:158`
- **Detail**: MISS (no file match: actual={'server/rss.go'}, gt={'server/resource.go'})
- **Issues**: no_file_match

### go-sast-CVE-2022-4691

- **Language**: go
- **GT vuln type**: xss
- **GT path points**: 4
  - `server/resource.go:46`
  - `server/resource.go:269`
  - `server/resource.go:61`
  - `server/resource.go:161`
- **Detail**: MISS (no file match: actual={'server/rss.go'}, gt={'server/resource.go'})
- **Issues**: no_file_match

### go-sast-CVE-2022-4692

- **Language**: go
- **GT vuln type**: xss
- **GT path points**: 4
  - `server/resource.go:45`
  - `server/resource.go:265`
  - `server/resource.go:59`
  - `server/resource.go:159`
- **Detail**: MISS (no file match: actual={'server/rss.go'}, gt={'server/resource.go'})
- **Issues**: no_file_match

### go-sast-CVE-2025-64101

- **Language**: go
- **GT vuln type**: header-injection
- **GT path points**: 4
  - `internal/api/http/middleware/origin_interceptor.go:63`
  - `internal/api/http/request_context.go:32`
  - `internal/api/http/middleware/origin_interceptor.go:69`
  - `internal/api/http/middleware/origin_interceptor.go:28`
- **Detail**: MISS (no file match: actual={'internal/api/ui/login/init_password_handler.go'}, gt={'internal/api/http/middleware/origin_interceptor.go', 'internal/api/http/request_context.go'})
- **Issues**: no_file_match

### go-sast-CVE-2025-64522

- **Language**: go
- **GT vuln type**: ssrf
- **GT path points**: 3
  - `pkg/ssh/cmd/webhooks.go:126`
  - `pkg/webhook/webhook.go:97`
  - `pkg/backend/webhooks.go:21`
- **Detail**: MISS (file match but line Δ49 > 5)
- **Issues**: closest_line_distance=49

### go-sast-CVE-2026-25059

- **Language**: go
- **GT vuln type**: path-traversal
- **GT path points**: 3
  - `server/handles/archive.go:243`
  - `server/handles/archive.go:269`
  - `server/handles/archive.go:254`
- **Detail**: MISS (no file match: actual={'server/handles/fsmanage.go'}, gt={'server/handles/archive.go'})
- **Issues**: no_file_match

### go-sast-CVE-2026-27018

- **Language**: go
- **GT vuln type**: path-traversal
- **GT path points**: 4
  - `pkg/modules/chromium/events.go:55`
  - `pkg/gotenberg/filter.go:40`
  - `pkg/gotenberg/filter.go:18`
  - `pkg/gotenberg/filter.go:37`
- **Detail**: MISS (no file match: actual={'pkg/modules/chromium/browser.go'}, gt={'pkg/modules/chromium/events.go', 'pkg/gotenberg/filter.go'})
- **Issues**: no_file_match

### go-sast-CVE-2026-32241

- **Language**: go
- **GT vuln type**: command-injection
- **GT path points**: 4
  - `pkg/lease/lease.go:42`
  - `pkg/backend/extension/extension.go:144`
  - `pkg/backend/extension/extension.go:65`
  - `pkg/backend/extension/extension_network.go:91`
- **Detail**: MISS (file match but line Δ54 > 5)
- **Issues**: closest_line_distance=54

### go-sast-CVE-2026-33675

- **Language**: go
- **GT vuln type**: ssrf
- **GT path points**: 3
  - `pkg/modules/migration/todoist/todoist.go:121`
  - `pkg/modules/migration/helpers.go:38`
  - `pkg/modules/migration/todoist/todoist.go:433`
- **Detail**: MISS (file match but line Δ13 > 5)
- **Issues**: closest_line_distance=13

### go-sast-CVE-2026-34041

- **Language**: go
- **GT vuln type**: command-injection
- **GT path points**: 4
  - `pkg/runner/action.go:390`
  - `pkg/runner/command.go:124`
  - `pkg/runner/command.go:36`
  - `pkg/runner/command.go:87`
- **Detail**: MISS (file match but line Δ17 > 5)
- **Issues**: closest_line_distance=17

### go-sast-CVE-2026-34585

- **Language**: go
- **GT vuln type**: xss
- **GT path points**: 4
  - `kernel/model/file.go:1732`
  - `kernel/go.mod:11`
  - `kernel/model/file.go:1733`
  - `kernel/model/file.go:1803`
- **Detail**: MISS (no file match: actual={'kernel/model/blockial.go'}, gt={'kernel/model/file.go', 'kernel/go.mod'})
- **Issues**: no_file_match

### go-sast-CVE-2026-34783

- **Language**: go
- **GT vuln type**: path-traversal
- **GT path points**: 2
  - `pkg/stdlib/io/fs/read.go:14`
  - `pkg/stdlib/io/fs/read.go:20`
- **Detail**: MISS (no file match: actual={'pkg/stdlib/io/fs/write.go'}, gt={'pkg/stdlib/io/fs/read.go'})
- **Issues**: no_file_match

### java-sast-CVE-2022-21675

- **Language**: java
- **GT vuln type**: path-traversal
- **GT path points**: 4
  - `src/main/java/the/bytecode/club/bytecodeviewer/util/ZipUtils.java:66`
  - `src/main/java/the/bytecode/club/bytecodeviewer/util/ZipUtils.java:82`
  - `src/main/java/the/bytecode/club/bytecodeviewer/util/ZipUtils.java:68`
  - `src/main/java/the/bytecode/club/bytecodeviewer/util/ZipUtils.java:71`
- **Detail**: EMPTY FINDINGS
- **Issues**: 

### java-sast-CVE-2022-23060

- **Language**: java
- **GT vuln type**: xss
- **GT path points**: 3
  - `sm-shop/src/main/java/com/salesmanager/shop/admin/controller/products/ProductImagesController.java:308`
  - `sm-core/src/main/java/com/salesmanager/core/business/modules/cms/product/ProductFileManagerImpl.java:65`
  - `sm-core/src/main/java/com/salesmanager/core/business/services/catalog/product/image/ProductImageServiceImpl.java:63`
- **Detail**: MISS (no file match: actual={'sm-shop/src/main/java/com/salesmanager/shop/admin/controller/content/StaticContentController.java'}, gt={'sm-core/src/main/java/com/salesmanager/core/business/modules/cms/product/ProductFileManagerImpl.java', 'sm-core/src/main/java/com/salesmanager/core/business/services/catalog/product/image/ProductImageServiceImpl.java', 'sm-shop/src/main/java/com/salesmanager/shop/admin/controller/products/ProductImagesController.java'})
- **Issues**: no_file_match

### java-sast-CVE-2022-23544

- **Language**: java
- **GT vuln type**: xss
- **GT path points**: 3
  - `test-track/backend/src/main/java/io/metersphere/service/issue/platform/ZentaoPlatform.java:545`
  - `test-track/backend/src/main/java/io/metersphere/service/issue/platform/ZentaoPlatform.java:579`
  - `test-track/backend/src/main/java/io/metersphere/service/issue/platform/ZentaoPlatform.java:549`
- **Detail**: MISS (no file match: actual={'test-track/backend/src/main/java/io/metersphere/service/wapper/IssueProxyResourceService.java'}, gt={'test-track/backend/src/main/java/io/metersphere/service/issue/platform/ZentaoPlatform.java'})
- **Issues**: no_file_match

### java-sast-CVE-2022-23620

- **Language**: java
- **GT vuln type**: path-traversal
- **GT path points**: 4
  - `xwiki-platform-core/xwiki-platform-skin/xwiki-platform-skin-skinx/src/main/java/org/xwiki/skinx/internal/AbstractSxExportURLFactoryActionHandler.java:83`
  - `xwiki-platform-core/xwiki-platform-skin/xwiki-platform-skin-skinx/src/main/java/org/xwiki/skinx/internal/AbstractSxExportURLFactoryActionHandler.java:131`
  - `xwiki-platform-core/xwiki-platform-skin/xwiki-platform-skin-skinx/src/main/java/org/xwiki/skinx/internal/AbstractSxExportURLFactoryActionHandler.java:91`
  - `xwiki-platform-core/xwiki-platform-skin/xwiki-platform-skin-skinx/src/main/java/org/xwiki/skinx/internal/AbstractSxExportURLFactoryActionHandler.java:103`
- **Detail**: MISS (file match but line Δ6 > 5)
- **Issues**: closest_line_distance=6

### java-sast-CVE-2022-24848

- **Language**: java
- **GT vuln type**: sql-injection
- **GT path points**: 5
  - `dhis-2/dhis-web/dhis-web-api/src/main/java/org/hisp/dhis/webapi/controller/event/ProgramController.java:122`
  - `dhis-2/dhis-services/dhis-service-core/src/main/java/org/hisp/dhis/association/ProgramOrganisationUnitAssociationsQueryBuilder.java:200`
  - `dhis-2/dhis-services/dhis-service-core/src/main/java/org/hisp/dhis/program/DefaultProgramService.java:200`
  - `dhis-2/dhis-services/dhis-service-core/src/main/java/org/hisp/dhis/program/jdbc/JdbcProgramOrgUnitAssociationsStore.java:71`
  - `dhis-2/dhis-services/dhis-service-core/src/main/java/org/hisp/dhis/association/ProgramOrganisationUnitAssociationsQueryBuilder.java:195`
- **Detail**: MISS (file match but line Δ7 > 5)
- **Issues**: closest_line_distance=7

### java-sast-CVE-2022-29251

- **Language**: java
- **GT vuln type**: xss
- **GT path points**: 3
  - `xwiki-platform-core/xwiki-platform-flamingo/xwiki-platform-flamingo-theme/xwiki-platform-flamingo-theme-ui/src/main/resources/FlamingoThemesCode/WebHomeSheet.xml:54`
  - `xwiki-platform-core/xwiki-platform-flamingo/xwiki-platform-flamingo-theme/xwiki-platform-flamingo-theme-ui/src/main/resources/FlamingoThemesCode/WebHomeSheet.xml:290`
  - `xwiki-platform-core/xwiki-platform-flamingo/xwiki-platform-flamingo-theme/xwiki-platform-flamingo-theme-ui/src/main/resources/FlamingoThemesCode/WebHomeSheet.xml:281`
- **Detail**: MISS (file match but line Δ6 > 5)
- **Issues**: closest_line_distance=6

### java-sast-CVE-2022-31194

- **Language**: java
- **GT vuln type**: path-traversal
- **GT path points**: 5
  - `dspace-jspui/src/main/java/org/dspace/app/webui/servlet/SubmissionController.java:1601`
  - `dspace-jspui/src/main/java/org/dspace/app/webui/servlet/SubmissionController.java:1729`
  - `dspace-jspui/src/main/java/org/dspace/app/webui/servlet/SubmissionController.java:1606`
  - `dspace-jspui/src/main/java/org/dspace/app/webui/servlet/SubmissionController.java:1615`
  - `dspace-jspui/src/main/java/org/dspace/app/webui/servlet/SubmissionController.java:1723`
- **Detail**: MISS (file match but line Δ1303 > 5)
- **Issues**: closest_line_distance=1303

### java-sast-CVE-2022-41965

- **Language**: java
- **GT vuln type**: open-redirect
- **GT path points**: 3
  - `modules/engage-paella-player/src/main/paella-opencast/ui/auth.html:14`
  - `modules/engage-paella-player/src/main/paella-opencast/ui/auth.html:23`
  - `modules/engage-paella-player/src/main/paella-opencast/ui/auth.html:19`
- **Detail**: MISS (no file match: actual={'modules/engage-ui/src/main/java/org/opencastproject/engage/ui/PlayerRedirect.java'}, gt={'modules/engage-paella-player/src/main/paella-opencast/ui/auth.html'})
- **Issues**: no_file_match

### java-sast-CVE-2022-4521

- **Language**: java
- **GT vuln type**: xss
- **GT path points**: 2
  - `components/registry/org.wso2.carbon.registry.profiles.ui/src/main/resources/web/userprofiles/profiles_add_ajaxprocessor.jsp:22`
  - `components/registry/org.wso2.carbon.registry.profiles.ui/src/main/resources/web/userprofiles/profiles_add_ajaxprocessor.jsp:67`
- **Detail**: MISS (no file match: actual={'components/registry/org.wso2.carbon.registry.common/src/main/java/org/wso2/carbon/registry/common/utils/CommonUtil.java'}, gt={'components/registry/org.wso2.carbon.registry.profiles.ui/src/main/resources/web/userprofiles/profiles_add_ajaxprocessor.jsp'})
- **Issues**: no_file_match

### java-sast-CVE-2022-4593

- **Language**: java
- **GT vuln type**: xss
- **GT path points**: 3
  - `src/main/java/cz/softinel/uaf/filter/FilterHelper.java:68`
  - `src/main/webapp/WEB-INF/jsp/retra/InvoiceList.jsp:17`
  - `src/main/java/cz/softinel/retra/invoice/web/InvoiceController.java:65`
- **Detail**: MISS (no file match: actual={'src/main/java/cz/softinel/uaf/vc/tag/VisualComponentTag.java'}, gt={'src/main/java/cz/softinel/uaf/filter/FilterHelper.java', 'src/main/java/cz/softinel/retra/invoice/web/InvoiceController.java', 'src/main/webapp/WEB-INF/jsp/retra/InvoiceList.jsp'})
- **Issues**: no_file_match

### java-sast-CVE-2022-46166

- **Language**: java
- **GT vuln type**: code-injection
- **GT path points**: 3
  - `spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/DingTalkNotifier.java:148`
  - `spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/DingTalkNotifier.java:106`
  - `spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/DingTalkNotifier.java:104`
- **Detail**: MISS (no file match: actual={'spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/MicrosoftTeamsNotifier.java', 'spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/TelegramNotifier.java', 'spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/SlackNotifier.java'}, gt={'spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/DingTalkNotifier.java'})
- **Issues**: no_file_match

### java-sast-CVE-2022-4725

- **Language**: java
- **GT vuln type**: xxe
- **GT path points**: 3
  - `aws-android-sdk-core/src/main/java/com/amazonaws/regions/RegionMetadataParser.java:57`
  - `aws-android-sdk-core/src/main/java/com/amazonaws/regions/RegionMetadataParser.java:115`
  - `aws-android-sdk-core/src/main/java/com/amazonaws/regions/RegionMetadataParser.java:112`
- **Detail**: MISS (no file match: actual={'aws-android-sdk-core/src/main/java/com/amazonaws/util/XpathUtils.java'}, gt={'aws-android-sdk-core/src/main/java/com/amazonaws/regions/RegionMetadataParser.java'})
- **Issues**: no_file_match

### java-sast-CVE-2022-4772

- **Language**: java
- **GT vuln type**: path-traversal
- **GT path points**: 3
  - `src/main/java/widoco/WidocoUtils.java:259`
  - `src/main/java/widoco/WidocoUtils.java:273`
  - `src/main/java/widoco/WidocoUtils.java:260`
- **Detail**: MISS (file match but line Δ9 > 5)
- **Issues**: closest_line_distance=9

### java-sast-CVE-2025-55727

- **Language**: java
- **GT vuln type**: code-injection
- **GT path points**: 3
  - `xwiki-pro-macros-confluence-bridges/xwiki-pro-macros-confluence-bridges-ui/src/main/resources/Confluence/Macros/ConfluenceColumn.xml:517`
  - `xwiki-pro-macros-confluence-bridges/xwiki-pro-macros-confluence-bridges-ui/src/main/resources/Confluence/Macros/ConfluenceColumn.xml:395`
  - `xwiki-pro-macros-confluence-bridges/xwiki-pro-macros-confluence-bridges-ui/src/main/resources/Confluence/Macros/ConfluenceColumn.xml:392`
- **Detail**: MISS (no file match: actual={'ConfluenceColumn.xml'}, gt={'xwiki-pro-macros-confluence-bridges/xwiki-pro-macros-confluence-bridges-ui/src/main/resources/Confluence/Macros/ConfluenceColumn.xml'})
- **Issues**: no_file_match

### java-sast-CVE-2025-62422

- **Language**: java
- **GT vuln type**: sql-injection
- **GT path points**: 3
  - `core/core-backend/src/main/java/io/dataease/datasource/server/DatasourceServer.java:791`
  - `core/core-backend/src/main/java/io/dataease/datasource/provider/EsProvider.java:96`
  - `core/core-backend/src/main/java/io/dataease/datasource/server/DatasourceServer.java:821`
- **Detail**: MISS (no file match: actual={'core/core-backend/src/main/java/io/dataease/datasource/provider/CalciteProvider.java'}, gt={'core/core-backend/src/main/java/io/dataease/datasource/server/DatasourceServer.java', 'core/core-backend/src/main/java/io/dataease/datasource/provider/EsProvider.java'})
- **Issues**: no_file_match

### java-sast-CVE-2025-66472

- **Language**: java
- **GT vuln type**: xss
- **GT path points**: 3
  - `xwiki-platform-core/xwiki-platform-appwithinminutes/xwiki-platform-appwithinminutes-ui/src/main/resources/AppWithinMinutes/DeleteApplication.xml:94`
  - `xwiki-platform-core/xwiki-platform-flamingo/xwiki-platform-flamingo-skin/xwiki-platform-flamingo-skin-resources/src/main/resources/flamingo/macros.vm:48`
  - `xwiki-platform-core/xwiki-platform-appwithinminutes/xwiki-platform-appwithinminutes-ui/src/main/resources/AppWithinMinutes/DeleteApplication.xml:100`
- **Detail**: MISS (no file match: actual={'xwiki-platform-core/xwiki-platform-flamingo/xwiki-platform-flamingo-skin/xwiki-platform-flamingo-skin-resources/src/main/resources/flamingo/delete.vm'}, gt={'xwiki-platform-core/xwiki-platform-appwithinminutes/xwiki-platform-appwithinminutes-ui/src/main/resources/AppWithinMinutes/DeleteApplication.xml', 'xwiki-platform-core/xwiki-platform-flamingo/xwiki-platform-flamingo-skin/xwiki-platform-flamingo-skin-resources/src/main/resources/flamingo/macros.vm'})
- **Issues**: no_file_match

### java-sast-CVE-2025-66474

- **Language**: java
- **GT vuln type**: xss
- **GT path points**: 3
  - `xwiki-platform-core/xwiki-platform-oldcore/src/main/java/com/xpn/xwiki/doc/XWikiDocument.java:3937`
  - `xwiki-platform-core/xwiki-platform-oldcore/src/main/java/com/xpn/xwiki/doc/XWikiDocument.java:4065`
  - `xwiki-platform-core/xwiki-platform-oldcore/src/main/java/com/xpn/xwiki/doc/XWikiDocument.java:4060`
- **Detail**: MISS (no file match: actual={'xwiki-platform-core/xwiki-platform-rendering/xwiki-platform-rendering-macros/xwiki-platform-rendering-macro-script/src/main/java/org/xwiki/rendering/macro/script/AbstractJSR223ScriptMacro.java'}, gt={'xwiki-platform-core/xwiki-platform-oldcore/src/main/java/com/xpn/xwiki/doc/XWikiDocument.java'})
- **Issues**: no_file_match

### java-sast-CVE-2025-7763

- **Language**: java
- **GT vuln type**: open-redirect
- **GT path points**: 3
  - `modules/cms/src/main/java/com/jeesite/modules/cms/web/SiteController.java:160`
  - `modules/cms/src/main/java/com/jeesite/modules/cms/web/SiteController.java:167`
  - `modules/cms/src/main/java/com/jeesite/modules/cms/web/SiteController.java:165`
- **Detail**: MISS (no file match: actual={'modules/core/src/main/java/com/jeesite/modules/sys/web/SsoController.java'}, gt={'modules/cms/src/main/java/com/jeesite/modules/cms/web/SiteController.java'})
- **Issues**: no_file_match

### java-sast-CVE-2025-7949

- **Language**: java
- **GT vuln type**: open-redirect
- **GT path points**: 3
  - `publiccms-parent/publiccms/src/main/webapp/resource/plugins/pdfjs/viewer.html:30`
  - `publiccms-parent/publiccms/src/main/webapp/resource/plugins/pdfjs/viewer.html:32`
  - `publiccms-parent/publiccms/src/main/webapp/resource/plugins/pdfjs/viewer.html:31`
- **Detail**: MISS (no file match: actual={'publiccms-parent/publiccms/src/main/resources/templates/admin/cmsDiy/preview.html'}, gt={'publiccms-parent/publiccms/src/main/webapp/resource/plugins/pdfjs/viewer.html'})
- **Issues**: no_file_match

### java-sast-CVE-2025-8551

- **Language**: java
- **GT vuln type**: xss
- **GT path points**: 4
  - `src/main/java/co/yiiu/pybbs/controller/admin/TopicAdminController.java:43`
  - `src/main/resources/templates/admin/topic/list.ftl:35`
  - `src/main/java/co/yiiu/pybbs/controller/admin/TopicAdminController.java:44`
  - `src/main/java/co/yiiu/pybbs/controller/admin/TopicAdminController.java:52`
- **Detail**: MISS (no file match: actual={'src/main/resources/templates/theme/default/search.ftl'}, gt={'src/main/java/co/yiiu/pybbs/controller/admin/TopicAdminController.java', 'src/main/resources/templates/admin/topic/list.ftl'})
- **Issues**: no_file_match

### java-sast-CVE-2025-8555

- **Language**: java
- **GT vuln type**: xss
- **GT path points**: 2
  - `src/main/java/co/yiiu/pybbs/controller/admin/TopicAdminController.java:71`
  - `src/main/java/co/yiiu/pybbs/controller/admin/TopicAdminController.java:74`
- **Detail**: MISS (no file match: actual={'src/main/resources/templates/theme/default/search.ftl'}, gt={'src/main/java/co/yiiu/pybbs/controller/admin/TopicAdminController.java'})
- **Issues**: no_file_match

### js-sast-CVE-2022-2494

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 2
  - `portal/patient/scripts/app/patientdata.js:125`
  - `portal/patient/scripts/app/patientdata.js:130`
- **Detail**: MISS (no file match: actual={'library/custom_template/ajax_code.php'}, gt={'portal/patient/scripts/app/patientdata.js'})
- **Issues**: no_file_match

### js-sast-CVE-2022-25978

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 5
  - `web/src/components/CreateResourceDialog.tsx:53`
  - `web/src/components/MemoResource.tsx:10`
  - `web/src/components/CreateResourceDialog.tsx:129`
  - `server/resource.go:35`
  - `web/src/utils/resource.ts:1`
- **Detail**: MISS (no file match: actual={'server/rss.go'}, gt={'web/src/components/MemoResource.tsx', 'web/src/utils/resource.ts', 'server/resource.go', 'web/src/components/CreateResourceDialog.tsx'})
- **Issues**: no_file_match

### js-sast-CVE-2022-25979

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 2
  - `src/plugins/editor.js:53`
  - `src/plugins/editor.js:120`
- **Detail**: MISS (file match but line Δ135 > 5)
- **Issues**: closest_line_distance=135

### js-sast-CVE-2022-2653

- **Language**: js
- **GT vuln type**: path-traversal
- **GT path points**: 3
  - `server/api/controllers/attachments/download-thumbnail.js:17`
  - `server/api/controllers/attachments/download-thumbnail.js:67`
  - `server/api/controllers/attachments/download-thumbnail.js:53`
- **Detail**: MISS (no file match: actual={'server/api/controllers/attachments/download.js'}, gt={'server/api/controllers/attachments/download-thumbnail.js'})
- **Issues**: no_file_match

### js-sast-CVE-2022-31035

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 6
  - `ui/src/app/applications/components/utils.tsx:668`
  - `ui/src/app/applications/components/application-urls.tsx:53`
  - `ui/src/app/applications/components/applications-list/applications-tiles.tsx:143`
  - `ui/src/app/applications/components/application-urls.tsx:20`
  - `ui/src/app/applications/components/application-urls.tsx:4`
  - `ui/src/app/applications/components/application-urls.tsx:44`
- **Detail**: MISS (no file match: actual={'ui/src/app/applications/components/application-summary/application-summary.tsx'}, gt={'ui/src/app/applications/components/applications-list/applications-tiles.tsx', 'ui/src/app/applications/components/utils.tsx', 'ui/src/app/applications/components/application-urls.tsx'})
- **Issues**: no_file_match

### js-sast-CVE-2022-3211

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 3
  - `bundles/AdminBundle/Resources/public/js/pimcore/element/properties.js:108`
  - `bundles/AdminBundle/Resources/public/js/pimcore/element/properties.js:440`
  - `bundles/AdminBundle/Resources/public/js/pimcore/element/properties.js:33`
- **Detail**: MISS (no file match: actual={'bundles/AdminBundle/Controller/Admin/TagsController.php'}, gt={'bundles/AdminBundle/Resources/public/js/pimcore/element/properties.js'})
- **Issues**: no_file_match

### js-sast-CVE-2022-35942

- **Language**: js
- **GT vuln type**: sql-injection
- **GT path points**: 5
  - `lib/postgresql.js:667`
  - `lib/postgresql.js:548`
  - `lib/postgresql.js:700`
  - `lib/postgresql.js:801`
  - `lib/postgresql.js:703`
- **Detail**: MISS (file match but line Δ410 > 5)
- **Issues**: closest_line_distance=410

### js-sast-CVE-2022-3950

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 4
  - `publiccms-parent/publiccms/src/main/webapp/resource/js/dwz.min.js:1975`
  - `publiccms-parent/publiccms/src/main/webapp/resource/js/dwz.min.js:3021`
  - `publiccms-parent/publiccms/src/main/webapp/resource/js/dwz.min.js:2002`
  - `publiccms-parent/publiccms/src/main/webapp/resource/js/dwz.min.js:2995`
- **Detail**: MISS (file match but line Δ11 > 5)
- **Issues**: closest_line_distance=11

### js-sast-CVE-2022-4456

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 2
  - `app/controllers/imports_controller.rb:17`
  - `app/views/imports/show.html.erb:29`
- **Detail**: MISS (no file match: actual={'app/views/layouts/application.html.erb', 'app/views/locations/_sidebar.html.erb'}, gt={'app/controllers/imports_controller.rb', 'app/views/imports/show.html.erb'})
- **Issues**: no_file_match

### js-sast-CVE-2022-4695

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 6
  - `web/src/components/MemoContent.tsx:14`
  - `web/src/components/MemoContent.tsx:100`
  - `web/src/components/MemoContent.tsx:101`
  - `web/src/labs/marked/parser/Bold.ts:17`
  - `web/src/labs/marked/parser/Link.ts:20`
  - `web/src/labs/marked/parser/PlainText.ts:16`
- **Detail**: MISS (no file match: actual={'plugin/http_getter/html_meta.go', 'server/rss.go', 'plugin/http_getter/image.go'}, gt={'web/src/labs/marked/parser/Link.ts', 'web/src/components/MemoContent.tsx', 'web/src/labs/marked/parser/Bold.ts', 'web/src/labs/marked/parser/PlainText.ts'})
- **Issues**: no_file_match

### js-sast-CVE-2022-4839

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 3
  - `web/src/labs/marked/index.ts:3`
  - `web/src/components/MemoContent.tsx:100`
  - `web/src/labs/marked/index.ts:48`
- **Detail**: MISS (no file match: actual={'server/rss.go'}, gt={'web/src/components/MemoContent.tsx', 'web/src/labs/marked/index.ts'})
- **Issues**: no_file_match

### js-sast-CVE-2022-4840

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 3
  - `web/src/labs/marked/index.ts:3`
  - `web/src/labs/marked/index.ts:50`
  - `web/src/labs/marked/index.ts:48`
- **Detail**: MISS (no file match: actual={'server/rss.go'}, gt={'web/src/labs/marked/index.ts'})
- **Issues**: no_file_match

### js-sast-CVE-2022-4841

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 4
  - `web/src/labs/marked/index.ts:3`
  - `web/src/labs/marked/index.ts:50`
  - `web/src/labs/marked/index.ts:32`
  - `web/src/labs/marked/index.ts:48`
- **Detail**: MISS (no file match: actual={'server/rss.go'}, gt={'web/src/labs/marked/index.ts'})
- **Issues**: no_file_match

### js-sast-CVE-2022-4865

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 2
  - `web/src/labs/marked/parser/Bold.ts:11`
  - `web/src/labs/marked/parser/Bold.ts:17`
- **Detail**: MISS (no file match: actual={'web/src/components/MemoContent.tsx'}, gt={'web/src/labs/marked/parser/Bold.ts'})
- **Issues**: no_file_match

### js-sast-CVE-2022-4866

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 3
  - `web/src/labs/marked/parser/Link.ts:15`
  - `web/src/labs/marked/parser/Link.ts:20`
  - `web/src/labs/marked/index.ts:3`
- **Detail**: MISS (no file match: actual={'web/src/components/MemoContent.tsx'}, gt={'web/src/labs/marked/parser/Link.ts', 'web/src/labs/marked/index.ts'})
- **Issues**: no_file_match

### js-sast-CVE-2022-4953

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 6
  - `assets/dev/js/frontend/utils/lightbox/lightbox.js:205`
  - `assets/dev/js/frontend/utils/video-api/base-loader.js:44`
  - `assets/dev/js/frontend/utils/lightbox/lightbox.js:209`
  - `assets/dev/js/frontend/utils/lightbox/lightbox.js:131`
  - `assets/dev/js/frontend/utils/lightbox/lightbox.js:171`
  - `assets/dev/js/frontend/utils/lightbox/lightbox.js:254`
- **Detail**: MISS (no file match: actual={'assets/dev/js/editor/components/template-library/views/parts/preview.js'}, gt={'assets/dev/js/frontend/utils/lightbox/lightbox.js', 'assets/dev/js/frontend/utils/video-api/base-loader.js'})
- **Issues**: no_file_match

### js-sast-CVE-2022-4966

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 3
  - `avAdmin/admin-directives/create/create.js:1075`
  - `avAdmin/admin-directives/create/create.html:37`
  - `avAdmin/admin-directives/create/create.js:71`
- **Detail**: MISS (no file match: actual={'vendor/jquery.compat/jquery-1.11.1.js', 'avAdmin/elections-api-service.js'}, gt={'avAdmin/admin-directives/create/create.js', 'avAdmin/admin-directives/create/create.html'})
- **Issues**: no_file_match

### js-sast-CVE-2025-11202

- **Language**: js
- **GT vuln type**: command-injection
- **GT path points**: 2
  - `src/utils/validation.ts:7`
  - `src/utils/validation.ts:9`
- **Detail**: MISS (no file match: actual={'src/utils/ssh.ts', 'src/index.ts'}, gt={'src/utils/validation.ts'})
- **Issues**: no_file_match

### js-sast-CVE-2025-27793

- **Language**: js
- **GT vuln type**: code-injection
- **GT path points**: 3
  - `packages/vega-functions/src/functions/sequence.js:27`
  - `packages/vega-functions/src/functions/sequence.js:29`
  - `packages/vega-functions/src/functions/sequence.js:28`
- **Detail**: MISS (no file match: actual={'packages/vega-expression/src/codegen.js'}, gt={'packages/vega-functions/src/functions/sequence.js'})
- **Issues**: no_file_match

### js-sast-CVE-2025-61788

- **Language**: js
- **GT vuln type**: xss
- **GT path points**: 2
  - `modules/engage-paella-player-7/src/plugins/org.opencast.paella.descriptionPlugin.js:38`
  - `modules/engage-paella-player-7/src/plugins/org.opencast.paella.descriptionPlugin.js:96`
- **Detail**: MISS (no file match: actual={'modules/engage-ui/src/main/java/org/opencastproject/engage/ui/PlayerRedirect.java'}, gt={'modules/engage-paella-player-7/src/plugins/org.opencast.paella.descriptionPlugin.js'})
- **Issues**: no_file_match

### js-sast-CVE-2025-8267

- **Language**: js
- **GT vuln type**: ssrf
- **GT path points**: 3
  - `src/cli.js:7`
  - `src/is-private-ip.js:51`
  - `src/index.js:55`
- **Detail**: MISS (file match but line Δ30 > 5)
- **Issues**: closest_line_distance=30

### python-sast-CVE-2022-31020

- **Language**: python
- **GT vuln type**: command-injection
- **GT path points**: 6
  - `indy_node/server/request_handlers/config_req_handlers/pool_upgrade_handler.py:56`
  - `indy_node/utils/node_control_utils.py:169`
  - `indy_node/server/request_handlers/config_req_handlers/pool_upgrade_handler.py:64`
  - `indy_node/server/upgrader.py:224`
  - `indy_node/utils/node_control_utils.py:274`
  - `indy_node/utils/node_control_utils.py:202`
- **Detail**: MISS (no file match: actual={'indy_node/utils/node_control_util.py'}, gt={'indy_node/server/upgrader.py', 'indy_node/utils/node_control_utils.py', 'indy_node/server/request_handlers/config_req_handlers/pool_upgrade_handler.py'})
- **Issues**: no_file_match

### python-sast-CVE-2022-31040

- **Language**: python
- **GT vuln type**: open-redirect
- **GT path points**: 4
  - `src/openforms/templates/cookie_consent/cookiegroup_list.html:6`
  - `src/openforms/templates/cookie_consent/_cookie_group.html:19`
  - `src/openforms/templates/cookie_consent/cookiegroup_list.html:25`
  - `src/openforms/templates/cookie_consent/cookiegroup_list.html:26`
- **Detail**: MISS (no file match: actual={'src/openforms/urls.py'}, gt={'src/openforms/templates/cookie_consent/_cookie_group.html', 'src/openforms/templates/cookie_consent/cookiegroup_list.html'})
- **Issues**: no_file_match

### python-sast-CVE-2022-31136

- **Language**: python
- **GT vuln type**: xss
- **GT path points**: 3
  - `bookwyrm/views/status.py:266`
  - `bookwyrm/templates/snippets/trimmed_text.html:8`
  - `bookwyrm/sanitize_html.py:31`
- **Detail**: MISS (no file match: actual={'bookwyrm/templatetags/utilities.py'}, gt={'bookwyrm/views/status.py', 'bookwyrm/sanitize_html.py', 'bookwyrm/templates/snippets/trimmed_text.html'})
- **Issues**: no_file_match

### python-sast-CVE-2022-31137

- **Language**: python
- **GT vuln type**: command-injection
- **GT path points**: 3
  - `app/options.py:135`
  - `app/options.py:139`
  - `app/options.py:136`
- **Detail**: MISS (no file match: actual={'app/funct.py', 'api/api_funct.py'}, gt={'app/options.py'})
- **Issues**: no_file_match

### python-sast-CVE-2022-4105

- **Language**: python
- **GT vuln type**: xss
- **GT path points**: 4
  - `tcms/core/history.py:21`
  - `tcms/core/history.py:123`
  - `tcms/core/history.py:23`
  - `tcms/core/history.py:102`
- **Detail**: MISS (no file match: actual={'tcms/core/templatetags/extra_filters.py', 'tcms/testplans/templates/testplans/get.html'}, gt={'tcms/core/history.py'})
- **Issues**: no_file_match

### python-sast-CVE-2022-4638

- **Language**: python
- **GT vuln type**: xss
- **GT path points**: 3
  - `src/collective/contact/widget/widgets.py:71`
  - `src/collective/contact/widget/widgets.py:84`
  - `src/collective/contact/widget/widgets.py:72`
- **Detail**: MISS (file match but line Δ189 > 5)
- **Issues**: closest_line_distance=189

### python-sast-CVE-2025-46335

- **Language**: python
- **GT vuln type**: xss
- **GT path points**: 4
  - `mobsf/MobSF/views/home.py:457`
  - `mobsf/MobSF/views/home.py:468`
  - `mobsf/MobSF/views/home.py:458`
  - `mobsf/MobSF/views/home.py:466`
- **Detail**: MISS (file match but line Δ54 > 5)
- **Issues**: closest_line_distance=54

### python-sast-CVE-2025-46719

- **Language**: python
- **GT vuln type**: xss
- **GT path points**: 3
  - `src/lib/components/chat/Messages/Markdown/MarkdownInlineTokens.svelte:22`
  - `src/lib/components/chat/Messages/Markdown/MarkdownInlineTokens.svelte:29`
  - `src/lib/components/chat/Messages/Markdown/MarkdownInlineTokens.svelte:25`
- **Detail**: MISS (no file match: actual={'frontend/src/lib/components/chat/Messages.svelte'}, gt={'src/lib/components/chat/Messages/Markdown/MarkdownInlineTokens.svelte'})
- **Issues**: no_file_match

### python-sast-CVE-2025-50181

- **Language**: python
- **GT vuln type**: ssrf
- **GT path points**: 5
  - `src/urllib3/poolmanager.py:206`
  - `src/urllib3/util/retry.py:284`
  - `src/urllib3/poolmanager.py:435`
  - `src/urllib3/poolmanager.py:461`
  - `src/urllib3/poolmanager.py:484`
- **Detail**: MISS (no file match: actual={'src/urllib3/connection.py'}, gt={'src/urllib3/poolmanager.py', 'src/urllib3/util/retry.py'})
- **Issues**: no_file_match

### python-sast-CVE-2025-52895

- **Language**: python
- **GT vuln type**: sql-injection
- **GT path points**: 5
  - `frappe/model/db_query.py:141`
  - `frappe/model/db_query.py:225`
  - `frappe/model/db_query.py:306`
  - `frappe/model/db_query.py:1099`
  - `frappe/model/db_query.py:307`
- **Detail**: MISS (no file match: actual={'frappe/database/database.py'}, gt={'frappe/model/db_query.py'})
- **Issues**: no_file_match

### python-sast-CVE-2025-54415

- **Language**: python
- **GT vuln type**: code-injection
- **GT path points**: 3
  - `.github/workflows/cicd.yaml:27`
  - `.github/workflows/cicd.yaml:40`
  - `.github/workflows/cicd.yaml:25`
- **Detail**: MISS (no file match: actual={'dagfactory/dagfactory.py', 'dagfactory/utils.py'}, gt={'.github/workflows/cicd.yaml'})
- **Issues**: no_file_match

### python-sast-CVE-2025-54430

- **Language**: python
- **GT vuln type**: command-injection
- **GT path points**: 3
  - `.github/workflows/benchmark-bot.yml:10`
  - `.github/workflows/benchmark-bot.yml:65`
  - `.github/workflows/benchmark-bot.yml:15`
- **Detail**: MISS (file match but line Δ7 > 5)
- **Issues**: closest_line_distance=7

### python-sast-CVE-2025-60249

- **Language**: python
- **GT vuln type**: xss
- **GT path points**: 4
  - `website/web/templates/bundles/bundles.html:42`
  - `website/web/templates/bundles/bundles.html:71`
  - `website/web/templates/bundles/bundles.html:65`
  - `website/web/templates/bundles/bundles.html:40`
- **Detail**: EMPTY FINDINGS
- **Issues**: 

### python-sast-CVE-2025-64104

- **Language**: python
- **GT vuln type**: sql-injection
- **GT path points**: 3
  - `libs/checkpoint-sqlite/langgraph/store/sqlite/base.py:374`
  - `libs/checkpoint-sqlite/langgraph/store/sqlite/base.py:385`
  - `libs/checkpoint-sqlite/langgraph/store/sqlite/base.py:386`
- **Detail**: EMPTY FINDINGS
- **Issues**: 

### python-sast-CVE-2025-64496

- **Language**: python
- **GT vuln type**: code-injection
- **GT path points**: 3
  - `backend/open_webui/utils/middleware.py:2321`
  - `backend/open_webui/socket/main.py:659`
  - `backend/open_webui/utils/middleware.py:2340`
- **Detail**: MISS (no file match: actual={'backend/open_webui/main.py', 'backend/open_webui/utils/plugin.py'}, gt={'backend/open_webui/socket/main.py', 'backend/open_webui/utils/middleware.py'})
- **Issues**: no_file_match

### python-sast-CVE-2025-66205

- **Language**: python
- **GT vuln type**: sql-injection
- **GT path points**: 3
  - `frappe/model/db_query.py:85`
  - `frappe/model/db_query.py:431`
  - `frappe/model/db_query.py:134`
- **Detail**: EMPTY FINDINGS
- **Issues**: 

### python-sast-CVE-2025-6773

- **Language**: python
- **GT vuln type**: path-traversal
- **GT path points**: 2
  - `lightrag/api/routers/document_routes.py:867`
  - `lightrag/api/routers/document_routes.py:869`
- **Detail**: MISS (file match but line Δ134 > 5)
- **Issues**: closest_line_distance=134

