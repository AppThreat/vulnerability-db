import os
import tarfile

import oras.client
import oras.provider
from oras.logger import setup_logger


setup_logger(quiet=True, debug=False)


class VdbDistributionRegistry(oras.provider.Registry):
    """
    We override the default registry to make things compatible with ghcr. Without this, the below error is thrown.

    jsonschema.exceptions.ValidationError: Additional properties are not allowed ('artifactType' was unexpected)
    """

    def get_manifest(self, container, allowed_media_type=None, refresh_headers=True):
        """
        Retrieve a manifest for a package.

        :param container:  parsed container URI
        :type container: oras.container.Container or str
        :param allowed_media_type: one or more allowed media types
        :type allowed_media_type: str
        """
        if not allowed_media_type:
            allowed_media_type = [oras.defaults.default_manifest_media_type]
        headers = {"Accept": ";".join(allowed_media_type)}

        get_manifest = f"{self.prefix}://{container.manifest_url()}"  # type: ignore
        response = self.do_request(get_manifest, "GET", headers=headers)
        self._check_200_response(response)
        manifest = response.json()
        return manifest


def download_image(target, outdir):
    """
    Method to download vdb files from a oci registry
    """
    oras_client = oras.client.OrasClient(registry=VdbDistributionRegistry())
    paths_list = oras_client.pull(
        target=target,
        outdir=outdir,
        allowed_media_type=[],
        overwrite=True,
    )
    for apath in paths_list:
        if apath.endswith(".tar.gz") or apath.endswith(".tar.xz"):
            with tarfile.open(apath, "r") as tarf:
                tarf.extractall(path=outdir)
            try:
                os.remove(apath)
            except OSError:
                pass
    return paths_list
