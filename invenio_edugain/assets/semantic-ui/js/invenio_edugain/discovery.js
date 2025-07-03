// Copyright (C) 2025 Graz University of Technology.
//
// invenio-edugain is free software; you can redistribute it and/or modify it
// under the terms of the MIT License; see LICENSE file for more details.

import PropTypes from "prop-types";
import React from "react";
import ReactDOM from "react-dom";
import { Form } from "semantic-ui-react";

function redirectToIdp(idpId) {
  let url = new URL(
    "/saml/login/authn-request", // TODO: make configurable; prefix with /api ?
    document.location.origin
  );
  const currentSearchParams = new URLSearchParams(document.location.search);
  const next = currentSearchParams.get("next", "/"); // TODO: configurable default; handle default here or in backend?
  url.searchParams.set("id", idpId);
  if (next) {
    url.searchParams.set("next", next);
  }
  window.location.href = url.toString();
}

// TODO: sort entries somehow
// TODO: consider computing options in backend already
// TODO: this re-renders Form.Dropdown unnecessarily often due to `options` being recomputed all the time
function IdpDiscovery({ idpData }) {
  const options = Object.entries(idpData).map(([key, { displayname }]) => ({
    // TODO: image: logoUrl,  // this doesn't load due to content-security policy...
    key,
    text: displayname,
    value: key,
  }));
  return (
    <Form.Dropdown
      clearable
      fluid
      noResultsMessage="No results found." // TODO: translate
      // TODO: this automatically selects first item when clicking out of the dropdown
      onChange={(_event, { value }) => {
        if (value) redirectToIdp(value);
      }}
      options={options}
      placeholder="Select your institution." // TODO: translate
      search
      selection
      style={{ width: 600 }}
    />
  );
}

IdpDiscovery.propTypes = {
  idpData: PropTypes.object.isRequired,
};

const edugainDiscoveryElement = document.getElementById("edugain-discovery");
const idpData = JSON.parse(edugainDiscoveryElement.dataset.idpDataJson);

ReactDOM.render(<IdpDiscovery idpData={idpData} />, edugainDiscoveryElement);
