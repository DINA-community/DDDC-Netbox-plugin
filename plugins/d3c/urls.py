from . import models, views
from django.urls import path
from netbox.views.generic import ObjectChangeLogView

urlpatterns = (
    path('findings/', views.DeviceFindingListView.as_view(), name='devicefinding_list'),
    path('findings/add/', views.DeviceFindingCreateView.as_view(), name='devicefinding_add'),
    path('findings/delete/', views.DeviceFindingBulkDeleteView.as_view(), name='devicefinding_bulk_delete'),
    path('findings/<int:pk>/', views.DeviceFindingView.as_view(), name='devicefinding'),
    path('findings/<int:pk>/edit/', views.DeviceFindingEditView.as_view(), name='devicefinding_edit'),
    path('findings/<int:pk>/delete/', views.DeviceFindingDeleteView.as_view(), name='devicefinding_delete'),
    path('findings/createdevice/', views.DeviceFindingCreateDeviceView.as_view(), name='devicefinding_createdevice'),
    path('findings/apply/', views.DeviceFindingApply.as_view(), name='devicefinding_apply'),
    path('findings/lookup/', views.DeviceFindingLookupView.as_view(), name='devicefinding_lookup'),
    path('findings/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='devicefinding_changelog', kwargs={
        'model': models.DeviceFinding
    }),
    path('findings/import/', views.FindingImportView.as_view(), name='devicefinding_import'),
    path('findings/stdimport/', views.FindingStdImportView.as_view(), name='devicefinding_std_import'),
    path('findings/map/', views.DeviceFindingMap.as_view(), name='devicefinding_bulk_map'),
    path('findings/reject/', views.DeviceFindingReject.as_view(), name='devicefinding_bulk_reject'),
    path('findings/split/', views.DeviceFindingSplit.as_view(), name='devicefinding_bulk_split'),

    path('device/<int:pk>/findings/', views.FindingListForDeviceView.as_view(), name='findinglistfordevice'),
    path('device/<int:pk>/software/', views.SoftwareListForDeviceView.as_view(), name='softwarelistfordevice'),

    path('software/', views.SoftwareListView.as_view(), name='software_list'),
    path('software/add/', views.SoftwareEditView.as_view(), name='software_add'),
    path('software/<int:pk>/', views.SoftwareView.as_view(), name='software'),
    path('software/<int:pk>/devices/', views.DeviceListForSoftwareView.as_view(), name='deviceslistforsoftware'),
    path('software/<int:pk>/edit/', views.SoftwareEditView.as_view(), name='software_edit'),
    path('software/<int:pk>/delete/', views.SoftwareDeleteView.as_view(), name='software_delete'),
    path('software/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='software_changelog', kwargs={
        'model': models.Software
    }),

    path('productrelationship/', views.ProductRelationshipListView.as_view(), name='productrelationship_list'),
    path('productrelationship/add/', views.ProductRelationshipEditView.as_view(), name='productrelationship_add'),
    path('productrelationship/<int:pk>/', views.ProductRelationshipView.as_view(), name='productrelationship'),
    path('productrelationship/<int:pk>/edit/', views.ProductRelationshipEditView.as_view(), name='productrelationship_edit'),
    path('productrelationship/<int:pk>/delete/', views.ProductRelationshipDeleteView.as_view(), name='productrelationship_delete'),
    path('productrelationship/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='productrelationship_changelog', kwargs={
        'model': models.ProductRelationship
    }),

    path('xgenericuri/', views.XGenericUriListView.as_view(), name='xgenericuri_list'),
    path('xgenericuri/add/', views.XGenericUriEditView.as_view(), name='xgenericuri_add'),
    path('xgenericuri/<int:pk>/', views.XGenericUriView.as_view(), name='xgenericuri'),
    path('xgenericuri/<int:pk>/edit/', views.XGenericUriEditView.as_view(), name='xgenericuri_edit'),
    path('xgenericuri/<int:pk>/delete/', views.XGenericUriDeleteView.as_view(), name='xgenericuri_delete'),
    path('xgenericuri/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='xgenericuri_changelog', kwargs={
        'model': models.XGenericUri
    }),

    path('hash/', views.HashListView.as_view(), name='hash_list'),
    path('hash/add/', views.HashEditView.as_view(), name='hash_add'),
    path('hash/<int:pk>/', views.HashView.as_view(), name='hash'),
    path('hash/<int:pk>/edit/', views.HashEditView.as_view(), name='hash_edit'),
    path('hash/<int:pk>/delete/', views.HashDeleteView.as_view(), name='hash_delete'),
    path('hash/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='hash_changelog', kwargs={
        'model': models.Hash
    }),

    path('filehash/', views.FileHashListView.as_view(), name='filehash_list'),
    path('filehash/add/', views.FileHashEditView.as_view(), name='filehash_add'),
    path('filehash/<int:pk>/', views.FileHashView.as_view(), name='filehash'),
    path('filehash/<int:pk>/edit/', views.FileHashEditView.as_view(), name='filehash_edit'),
    path('filehash/<int:pk>/delete/', views.FileHashDeleteView.as_view(), name='filehash_delete'),
    path('filehash/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='filehash_changelog', kwargs={
        'model': models.FileHash
    }),

    path('communication/', views.CommunicationListView.as_view(), name='communication_list'),
    path('communication/add/', views.CommunicationEditView.as_view(), name='communication_add'),
    path('communication/<int:pk>/', views.CommunicationView.as_view(), name='communication'),
    path('communication/<int:pk>/devices/', views.DeviceListForCommunicationView.as_view(),
         name='deviceslistforcommunication'),
    path('communication/<int:pk>/edit/', views.CommunicationEditView.as_view(), name='communication_edit'),
    path('communication/<int:pk>/delete/', views.CommunicationDeleteView.as_view(), name='communication_delete'),
    path('communication/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='communication_changelog',
         kwargs={'model': models.Communication}),
    path('communication/import/', views.CommunicationImportView.as_view(), name='communication_import'),

    path('communication_finding/', views.CommunicationFindingListView.as_view(), name='communicationfinding_list'),
    path('communication_finding/add/', views.CommunicationFindingEditView.as_view(), name='communicationfinding_add'),
    path('communication_finding/<int:pk>/', views.CommunicationFindingView.as_view(), name='communicationfinding'),
    path('communication_finding/<int:pk>/edit/', views.CommunicationFindingEditView.as_view(),
         name='communicationfinding_edit'),
    path('communication_finding/<int:pk>/delete/', views.CommunicationFindingDeleteView.as_view(),
         name='communicationfinding_delete'),
    path('communication_finding/<int:pk>/changelog/', ObjectChangeLogView.as_view(),
         name='communicationfinding_changelog', kwargs={'model': models.CommunicationFinding}),
    path('communication_finding/import/', views.CommunicationFindingImportView.as_view(),
         name='communicationfinding_import'),
    path('communication/map/', views.CommunicationFindingMap.as_view(), name='communicationfinding_bulk_map'),
    path('communication/reject/', views.CommunicationFindingReject.as_view(), name='communicationfinding_bulk_reject'),

    path('mapping/', views.MappingListView.as_view(), name='Mapping_list'),
    path('mapping/add/', views.MappingEditView.as_view(), name='Mapping_add'),
    path('mapping/<int:pk>/', views.MappingView.as_view(), name='Mapping'),
    path('mapping/<int:pk>/edit/', views.MappingEditView.as_view(), name='Mapping_edit'),
    path('mapping/<int:pk>/delete/', views.MappingDeleteView.as_view(), name='Mapping_delete'),

    path('devicefindingimport', views.DeviceFindingImport, name='DeviceFindingImport'),
    path('communicationfindingimport', views.CommunicationFindingImport, name='CommunicationFindingImport'),
)
