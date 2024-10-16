"""
URL configuration for cylvarkana project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    path('core/', include('core.urls')),
    path('core/', include('django.contrib.auth.urls')),
    path('accounts/', include('django.contrib.auth.urls')),
    path('', RedirectView.as_view(url='accounts/login')),
]

# Add dynamic URLs for enabled modules with 'has_urls'
for module_name, static_files, has_urls, uses_api in settings.MODULES:
    if has_urls:
        urlpatterns.append(path(f'{module_name}/', include(f'{module_name}.urls')))

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
