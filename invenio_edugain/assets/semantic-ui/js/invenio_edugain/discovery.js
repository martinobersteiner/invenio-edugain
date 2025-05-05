// Copyright (C) 2025 Graz University of Technology.
//
// invenio-edugain is free software; you can redistribute it and/or modify it
// under the terms of the MIT License; see LICENSE file for more details.

import React from "react";
import ReactDOM from "react-dom";
import { Container, Form } from "semantic-ui-react";

// TODO: sort entries somehow
// TODO: consider computing options in backend already
function IdpDiscovery({ idpData }) {
  console.log(idpData);
  const options = Object.entries(idpData).map(
    ([key, { displayname, logo_url: logoUrl }]) => ({
      // TODO: image: logoUrl,  // this doesn't load due to content-security policy...
      key,
      text: displayname,
      value: key,
    }),
  );
  return (
    <Container>
      <Form.Dropdown // consider Dropdown over Form.Dropdown...
        clearable // TODO: remove as it is non-sensical
        fluid
        noResultsMessage="No results found." // TODO: translate
        onChange={(_event, { value }) => {
          if (value) {
            let url = new URL(
              "/edugain/authn-request", // TODO: prefix with /api ?, TODO: make configurable
              document.location.origin,
            );
            const currentSearchParams = new URLSearchParams(
              document.location.search,
            );
            const next = currentSearchParams.get("next", "/");
            url.searchParams.set("id", value);
            if (next) {
              url.searchParams.set("next", next);
            }
            window.location.href = url.toString();
          }
        }}
        options={options}
        placeholder="Select your IdP." // TODO: translate
        search
        selection
      ></Form.Dropdown>
    </Container>
  );
}

const edugain_discovery_element = document.getElementById("edugain-discovery");
const idpData = JSON.parse(edugain_discovery_element.dataset.idpDataJson);

ReactDOM.render(<IdpDiscovery idpData={idpData} />, edugain_discovery_element);
