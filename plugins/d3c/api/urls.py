from netbox.api.routers import NetBoxRouter
from . import views

app_name = 'd3c-api'

router = NetBoxRouter()
router.register('devicefindings-list', views.DeviceFindingViewSet)
router.register('software-list', views.SoftwareViewSet)
router.register('communication-list', views.CommunicationViewSet)
router.register('communicationfinding-list', views.CommunicationFindingViewSet)
router.register('mapping-list', views.MappingViewSet)

urlpatterns = router.urls

