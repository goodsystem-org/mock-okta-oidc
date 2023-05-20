const express = require('express');
const { Provider } = require('oidc-provider');
const { renderFile } = require('ejs');

const port = 3000;
const app = express();

const provider = new Provider('http://localhost:3000', {
  clients: [
    {
      client_id: 'client1',
      client_secret: 'secret1',
      redirect_uris: ['http://localhost:3000/callback'],
      response_types: ['code'],
      grant_types: ['authorization_code'],
    },
  ],
  cookies: {
    keys: ['secret1'],
  },
});

app.set('views', './views');
app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.render('index');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (username === 'user1' && password === 'password1') {
    const accountId = 'account1';
    const account = await provider.Account.findAccount({}, accountId);
    const { AccessToken } = provider;
    const token = new AccessToken({
      accountId,
      clientId: 'client1',
      grantId: undefined,
      scope: 'openid',
    });
    const jwt = await token.save();
    res.cookie('session', jwt);
    res.redirect('/dashboard');
  } else {
    res.render('index', { error: 'Invalid username or password' });
  }
});

app.get('/dashboard', async (req, res) => {
  const session = req.cookies.session;
  if (!session) {
    res.redirect('/');
    return;
  }
  const { AccessToken } = provider;
  const token = await AccessToken.find(session);
  if (!token) {
    res.redirect('/');
    return;
  }
  const { account } = await provider.interactionDetails(req, res);
  res.render('dashboard', { username: account.accountId });
});

app.get('/authorize', async (req, res) => {
  const details = await provider.interactionDetails(req, res);
  const { prompt } = details.params;
  if (prompt.includes('none')) {
    const result = await provider.interactionFinished(req, res, {
      login: {
        account: details.params.login_hint,
      },
      consent: {},
    });
    res.redirect(result.redirectUri);
    return;
  }
  res.render('authorize', { details });
});

app.post('/authorize', async (req, res) => {
  const { prompt } = req.body;
  const details = await provider.interactionDetails(req, res);
  if (prompt.includes('none')) {
    const result = await provider.interactionFinished(req, res, {
      login: {
        account: details.params.login_hint,
      },
      consent: {},
    });
    res.redirect(result.redirectUri);
    return;
  }
  const result = await provider.interactionFinished(req, res, {
    consent: {},
  });
  res.redirect(result.redirectUri);
});

app.get('/callback', async (req, res) => {
  const { code } = req.query;
  const { AccessToken } = provider;
  const token = await AccessToken.find(code);
  const { client } = await provider.interactionDetails(req, res);
  const { id_token: idToken, access_token: accessToken } = await client.callback(
    'http://localhost:3000/callback',
    { code },
    { exchangeBody: { code } }
  );
  res.render('callback', { idToken, accessToken });
});

app.get('/userinfo', async (req, res) => {
  const session = req.cookies.session;
  if (!session) {
    res.status(401).send('Unauthorized');
    return;
  }
  const { AccessToken } = provider;
  const token = await AccessToken.find(session);
  if (!token) {
    res.status(401).send('Unauthorized');
    return;
  }
  const { account } = await provider.interactionDetails(req, res);
  res.json({ sub: account.accountId });
});

app.get('/logout', async (req, res) => {
  res.clearCookie('session');
  res.redirect('/');
});

app.get('/.well-known/openid-configuration', (req, res) => {
  const config = provider.configuration();
  res.json(config);
});

provider.initialize({ adapter: {} }).then(() => {
  app.listen(port, () => {
    console.log(`Mock server listening on port ${port}`);
  });
});