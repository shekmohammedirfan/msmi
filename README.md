# MSMI Supabase Account Portal

A beginner-friendly HTML/CSS/JavaScript registration and login page using Supabase Auth and a PostgreSQL `profiles` table.

## Files
- `index.html` — responsive MSMI red/white user interface, registration, login, logout, password-reset email, profile display and username update.
- `schema.sql` — database table, row-level security policies and automatic profile-creation trigger.

## 1. Create a Supabase project
1. Visit https://supabase.com/ and sign in.
2. Create a new project.
3. Save the database password somewhere safe.

## 2. Create the database table and security policies
1. Open your Supabase project.
2. Select **SQL Editor** in the left menu.
3. Choose **New query**.
4. Open `schema.sql`, copy all its contents, paste into the SQL Editor.
5. Click **Run**.
6. Confirm that the query completes successfully.

The SQL enables Row Level Security (RLS). Each authenticated user can select/update only their own profile. Profile rows are created by a database trigger when an Auth user is created.

## 3. Enable email authentication
1. Open **Authentication** → **Sign In / Providers** (the menu wording may vary).
2. Ensure **Email** is enabled.
3. For a real public website, keep email confirmation enabled.
4. In **Authentication** → **URL Configuration**, set:
   - Site URL: your deployed website origin, for example `https://your-domain.example`
   - Redirect URLs: add your exact website URL. During local development, add the local URL you use, such as `http://localhost:5500/**`.
5. Configure SMTP/custom email delivery if you need reliable production email delivery. Supabase's default email service has sending limits.

## 4. Copy the browser-safe project values
1. Open **Project Settings** → **API Keys** (or **API** in older dashboards).
2. Copy the **Project URL**.
3. Copy the **Publishable key** (usually begins `sb_publishable_`). In older projects, the legacy `anon` key is also a browser-safe public key.
4. Open `index.html` in a code editor.
5. Near the bottom, replace:
   `YOUR_SUPABASE_PROJECT_URL`
   `YOUR_SUPABASE_PUBLISHABLE_KEY`
   with your real values.

Never put a `service_role` key or a Supabase secret key in this HTML file. The publishable/anon key is designed to be public; RLS is what protects the data.

## 5. Run the website on your computer
Do not rely on opening the file directly as `file://`.
- In VS Code, install/use the Live Server extension, right-click `index.html`, choose **Open with Live Server**; or
- With Python installed, open a terminal in this folder and run:
  `python -m http.server 5500`
  Then visit `http://localhost:5500`.
Add that local URL to Supabase Auth redirect URLs if you use email confirmation or password reset.

## 6. Test it
1. Open the page.
2. Choose **Create account**.
3. Enter a username (3–24 letters, numbers or underscores), email and password (minimum 8 characters).
4. If email confirmation is enabled, open the confirmation email and follow its link.
5. Sign in with the email and password.
6. The dashboard displays the profile username, email and Auth user ID.
7. Try changing the username and signing out/in again.

## 7. Deploy online
You can host the static site on a static hosting provider such as GitHub Pages, Netlify or Cloudflare Pages. Upload `index.html`, then set the deployed origin in Supabase **Authentication → URL Configuration**. HTTPS is recommended.

## Security notes
- Passwords are handled by Supabase Auth; this project does not save readable passwords in `profiles`.
- Do not create your own table containing plain-text passwords.
- The SQL enables RLS and allows each user to read/update only their own profile.
- The browser uses only the publishable key. Never expose secret/service-role keys.
- This starter project does not implement admin privileges or public user-directory search.
- For production, use a custom SMTP provider, review Supabase Auth settings, add abuse protection/rate limits, and publish a privacy policy.
- If registration reports a duplicate username, choose another username. Usernames are case-insensitive unique.
