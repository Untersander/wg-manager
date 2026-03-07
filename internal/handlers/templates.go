package handlers

import "html/template"

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>wg-manager login</title>
  <link rel="stylesheet" href="/static/style.css"/>
</head>
<body>
  <main class="centered">
    <section class="card small">
      <div class="logo" style="justify-content:center;margin-bottom:1rem">
        <img src="/static/wireguard.svg" alt="WireGuard"/>
        <span>wg-manager</span>
      </div>
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      <form method="post" action="/login">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" required />
        <button type="submit">Sign in</button>
      </form>
    </section>
  </main>
</body>
</html>`))

var dashboardTemplate = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>wg-manager</title>
  <link rel="stylesheet" href="/static/style.css"/>
</head>
<body>
<header>
  <a class="logo" href="/">
    <img src="/static/wireguard-noname.svg" alt="WireGuard"/>
    <span>wg-manager</span>
  </a>
  <form method="post" action="/logout"><button type="submit">Logout</button></form>
</header>
<main class="layout">
  <section class="card">
    <h2>Interface Settings</h2>
    <form method="post" action="/settings">
      <label>Listen Port</label>
      <input name="listen_port" value="{{.ListenPort}}" type="number" min="1" max="65535" required />
      <label>MTU</label>
      <input name="mtu" value="{{.MTU}}" type="number" min="1280" max="9000" required />
      <label>Egress Interface</label>
      <input name="egress_interface" value="{{.EgressInterface}}" required />
      <button type="submit">Save Interface Settings</button>
    </form>
  </section>

  <section class="card">
    <h2>Create Peer</h2>
    <form method="post" action="/peers">
      <label>Name</label>
      <input name="name" required />
      <label>Address</label>
      <input name="address" placeholder="10.8.0.2/32, fd42::2/128" required />
      <label>Persistent Keepalive</label>
      <input name="keepalive" type="number" min="0" value="{{.DefaultKeepalive}}"/>
      <button type="submit">Create Peer</button>
    </form>
  </section>

  <section class="card">
    <h2>Peers</h2>
    <table>
      <thead>
        <tr><th>Name</th><th>Allowed IPs</th><th>Handshake</th><th>Rx</th><th>Tx</th><th>Actions</th></tr>
      </thead>
      <tbody>
      {{range .Peers}}
        <tr>
          <td>{{.Name}}</td>
          <td>{{.AllowedIPs}}</td>
          <td>{{.Handshake}}</td>
          <td>{{.Rx}}</td>
          <td>{{.Tx}}</td>
          <td>
            <a href="/peers/{{.Name}}">Details</a>
            <form class="inline" method="post" action="/peers/{{.Name}}/delete">
              <button type="submit">Delete</button>
            </form>
          </td>
        </tr>
      {{else}}
        <tr><td colspan="6">No peers yet</td></tr>
      {{end}}
      </tbody>
    </table>
    {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  </section>
</main>
</body>
</html>`))

var peerTemplate = template.Must(template.New("peer").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Peer {{.Name}}</title>
  <link rel="stylesheet" href="/static/style.css"/>
</head>
<body>
<header>
  <a class="logo" href="/">
    <img src="/static/wireguard-noname.svg" alt="WireGuard"/>
    <span>Peer {{.Name}}</span>
  </a>
  <a href="/">Back</a>
</header>
<main class="layout">
  <section class="card">
    <h2>Config</h2>
    <p><a href="/peers/{{.Name}}/config">Download config</a></p>
    <textarea rows="16" readonly>{{.Config}}</textarea>
  </section>
  <section class="card">
    <h2>QR Code</h2>
    <img alt="peer qr" src="data:image/png;base64,{{.QRCode}}"/>
  </section>
</main>
</body>
</html>`))
