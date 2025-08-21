from . import models, views
from django.urls import include, path
from netbox.views.generic import ObjectChangeLogView
from utilities.urls import get_model_urls

urlpatterns = (
    path('findings/', include(get_model_urls('d3c', 'devicefinding', detail=False))),
    path('findings/<int:pk>/', include(get_model_urls('d3c', 'devicefinding'))),

    path('findings/delete/', views.DeviceFindingBulkDeleteView.as_view(), name='devicefinding_bulk_delete'),
    path('findings/createdevice/', views.DeviceFindingCreateDeviceView.as_view(), name='devicefinding_createdevice'),
    path('findings/apply/', views.DeviceFindingApply.as_view(), name='devicefinding_apply'),
    path('findings/lookup/', views.DeviceFindingLookupView.as_view(), name='devicefinding_lookup'),
    path('findings/import/', views.FindingImportView.as_view(), name='devicefinding_import'),
    path('findings/stdimport/', views.FindingStdImportView.as_view(), name='devicefinding_std_import'),
    path('findings/map/', views.DeviceFindingMap.as_view(), name='devicefinding_bulk_map'),
    path('findings/reject/', views.DeviceFindingReject.as_view(), name='devicefinding_bulk_reject'),
    path('findings/split/', views.DeviceFindingSplit.as_view(), name='devicefinding_bulk_split'),

    path('software/', include(get_model_urls('d3c', 'software', detail=False))),
    path('software/<int:pk>/', include(get_model_urls('d3c', 'software'))),

    path('productrelationship/', include(get_model_urls('d3c', 'productrelationship', detail=False))),
    path('productrelationship/<int:pk>/', include(get_model_urls('d3c', 'productrelationship'))),

    path('xgenericuri/', include(get_model_urls('d3c', 'xgenericuri', detail=False))),
    path('xgenericuri/<int:pk>/', include(get_model_urls('d3c', 'xgenericuri'))),

    path('hash/', include(get_model_urls('d3c', 'hash', detail=False))),
    path('hash/<int:pk>/', include(get_model_urls('d3c', 'hash'))),

    path('filehash/', include(get_model_urls('d3c', 'filehash', detail=False))),
    path('filehash/<int:pk>/', include(get_model_urls('d3c', 'filehash'))),

    path('communication/', include(get_model_urls('d3c', 'communication', detail=False))),
    path('communication/<int:pk>/', include(get_model_urls('d3c', 'communication'))),
    path('communication/import/', views.CommunicationImportView.as_view(), name='communication_import'),
    path('communication/map/', views.CommunicationFindingMap.as_view(), name='communicationfinding_bulk_map'),
    path('communication/reject/', views.CommunicationFindingReject.as_view(), name='communicationfinding_bulk_reject'),

    path('communication_finding/', include(get_model_urls('d3c', 'communicationfinding', detail=False))),
    path('communication_finding/<int:pk>/', include(get_model_urls('d3c', 'communicationfinding'))),
    path('communication_finding/import/', views.CommunicationFindingImportView.as_view(),
         name='communicationfinding_import'),

    path('mapping/', include(get_model_urls('d3c', 'mapping', detail=False))),
    path('mapping/<int:pk>/', include(get_model_urls('d3c', 'mapping'))),

    path('devicefindingimport', views.DeviceFindingImport, name='DeviceFindingImport'),
    path('communicationfindingimport', views.CommunicationFindingImport, name='CommunicationFindingImport'),
)
