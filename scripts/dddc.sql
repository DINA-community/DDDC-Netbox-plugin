
-- DDDC Preset data


COPY public.auth_group (id, name) FROM stdin;
1	administrator
\.


COPY public.auth_user (id, password, last_login, is_superuser, username, first_name, last_name, email, is_staff, is_active, date_joined) FROM stdin;
2	pbkdf2_sha256$390000$D4rGF4DyjHifhtlKcRoz2E$EecTIBg8bENDjrBrR2UoOTxPAHogoBGos7LrvjcA7gk=	2023-05-26 06:53:00.266885+00	f	admin				f	t	2023-05-26 06:52:00+00
\.

COPY public.django_admin_log (id, action_time, object_id, object_repr, action_flag, change_message, content_type_id, user_id) FROM stdin;
1	2023-05-26 06:50:44.565627+00	1	DDDCClasses	1	[{"added": {}}]	106	1
2	2023-05-26 06:51:42.903669+00	1	administrator	1	[{"added": {}}, {"added": {"name": "objectpermission-group relationship", "object": "ObjectPermission_groups object (1)"}}]	3	1
3	2023-05-26 06:52:00.751385+00	2	admin	1	[{"added": {}}]	4	1
4	2023-05-26 06:52:42.22715+00	2	admin	2	[{"added": {"name": "objectpermission-user relationship", "object": "ObjectPermission_users object (1)"}}]	4	1
\.

COPY public.users_objectpermission (id, name, description, enabled, actions, constraints) FROM stdin;
1	DDDCClasses		t	{view,change}	\N
\.


COPY public.users_objectpermission_groups (id, objectpermission_id, group_id) FROM stdin;
1	1	1
\.

COPY public.users_objectpermission_object_types (id, objectpermission_id, contenttype_id) FROM stdin;
1	1	32
2	1	36
3	1	116
4	1	117
5	1	25
6	1	28
7	1	29
8	1	62
\.

COPY public.users_objectpermission_users (id, objectpermission_id, user_id) FROM stdin;
1	1	2
\.


COPY public.users_token (id, created, expires, key, write_enabled, description, user_id, allowed_ips, last_used) FROM stdin;
1	2023-03-30 14:18:54.655775+00	\N	478c32a432bba53dae813685f0fd7546873131a1	t		1	{}	\N
\.

COPY public.users_userconfig (id, data, user_id) FROM stdin;
2	{}	2
\.

