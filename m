Return-Path: <kasan-dev+bncBCZJFLUA24DBB3OTX23AMGQEW3MU3SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DF55963506
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 00:51:27 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5d5b62ee8b9sf39728eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 15:51:26 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724885486; x=1725490286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O3a0YV4r+aUQKR9mInksenJ416Apb/pFpVOm54MHCSw=;
        b=anH7WHi2FIYUYLUSHHmdNkYU4rADNYd0USGlB7d+/4rVDKDpCxYLD+zt1yxk+7tz7Z
         NG0oZ3OhukYNQGzrDjimWNduPiv3RjwG8xNp97ft4YrgKl6jh6dWcLJJjao77tjOVnjm
         6AXit+phOppHN/xUBjxYwsqoCdUEgZbdHz6us00dvUyRBcyM1opyrFf0QowNEsuTamPY
         BDaQ3g7dc7gtO/I3aBGhwf3W46QAQ1gvLWpBfc0lox0LDrJ742OvMysy2nDvW6ePxSjB
         YjGB7y2eqrYZ7M0f5KYbSV4dnL092joZx3xUU7VpicuD3uTax3I+LMeb06jdy5mxhyFD
         VZrg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724885486; x=1725490286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O3a0YV4r+aUQKR9mInksenJ416Apb/pFpVOm54MHCSw=;
        b=H034T2zXAxLyn9I1wW/M4We5BzNlQlhuGHC2sRo13YQwgQtr6MLmw0IyXyV2/zywMr
         lmVDdykMyDrNbxGJBO0R8GnYWGR+cM55fQC1sBdWYperEzdCeFKmDPROAt5vD+uxZRjw
         W0lZ3/KNObRzAXo9NNV3/uwn3ycSl9xlPUb92ntH9WcKH+RMOkODNQupkNpy0TjLxf9W
         23Dgu4H4m/VdVhaEdFidDPJZZNRMFZPPWl4kNqaUlY1sxbFanbO7iX2daBoKRDKCsc3e
         2IxOmtVV2r5U5Uq0LKo0f7ZL9HACp942ZNpd3M2h6Z8WO8MjXAQ2v86o6cpb+VjM6V//
         gMsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724885486; x=1725490286;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O3a0YV4r+aUQKR9mInksenJ416Apb/pFpVOm54MHCSw=;
        b=tni3xXKRNcg3QAuNk993+TQNt8Bea8PnwoZVKLE8NBy0jCtJyQG9nMSPa8cWXhCFCU
         XAyINBzdZZr82EoSNFHiwx0XRGcQdgiE7tBpOhDNhKl3nZ8q6cr45LNyvTxlNuURjA41
         gQgSgiqlvJP/lvdiwhTxqN2LLuaheHF1LcEemE+x6RbsJrTDESq2ASIXQr0VxnZx9OOD
         rQaN4NUiwRdIVy05qVU9EqKcHPZgchCFmGMMfa7x7/LffIuWEA19tN59EXJIIllRNYV8
         uTMRpOfKSH1W2BkNgTIPkWzN67B3F+mUffN1V33aW29qQcYxzIhbELbYsS8/lVcCzhG1
         iq3g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCXcWsV4U6uD4abT9JiZ6omtVpkn5+0eCF6FzFinzuJ/AwSc+H9KUSmOnQkRzyxJCzL2FLZmCA==@lfdr.de
X-Gm-Message-State: AOJu0Yysc2BSpNf/B3oAKls7GuXpDDxQvGfAQkEzJxFmMtAhWZPdEH2F
	8/ge4Qds+d+NWIypdND2sR208XavqBFmcdJI6V9N00KryAu9uuLO
X-Google-Smtp-Source: AGHT+IEpTZccH1+9FS08rkYtTSU0dSyyjDIWyOYEL5JjB6HfdiaH8295tVqOB/GLyI/X6LUU/tpWMw==
X-Received: by 2002:a05:6870:a34d:b0:25e:d90:fe70 with SMTP id 586e51a60fabf-2779035f8a2mr1149172fac.43.1724885485757;
        Wed, 28 Aug 2024 15:51:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1ec3:b0:24f:6f0d:5f4a with SMTP id
 586e51a60fabf-2778f0b1d63ls457732fac.0.-pod-prod-01-us; Wed, 28 Aug 2024
 15:51:25 -0700 (PDT)
X-Received: by 2002:a05:6808:3093:b0:3da:a763:4718 with SMTP id 5614622812f47-3df05e63e78mr929059b6e.45.1724885484660;
        Wed, 28 Aug 2024 15:51:24 -0700 (PDT)
Date: Wed, 28 Aug 2024 15:51:23 -0700 (PDT)
From: Eliam Klump <eliamklump893@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <a429e3f9-b654-4868-83cd-9d99a4925fe5n@googlegroups.com>
Subject: =?UTF-8?B?2YjYp9iq2LPYp9ioICs0MTc5OTU2OTk=?=
 =?UTF-8?B?NjIg2LTYsdin2KEg2KfZhNiv2YjZhNin2LEg2Kc=?=
 =?UTF-8?B?2YTYo9mF2LHZitmD2Yog2LnYqNixINin2YTYpdmG2Ko=?=
 =?UTF-8?B?2LHZhtiqINmB2Yog2KfZhNmD2YjZitiqINin2YTZhdmF?=
 =?UTF-8?B?2YTZg9ipINin2YTYudix2KjZitipINin2YTYs9i52Yg=?=
 =?UTF-8?B?2K/ZitipINmC2LfYsSDYp9mE2KjYrdix2YrZhiDYpw==?=
 =?UTF-8?B?2YTYo9ix2K/ZhiDYp9mE2KXZhdin2LHYp9iqINin2YQ=?=
 =?UTF-8?B?2LnYsdio2YrYqSDYp9mE2YXYqtit2K/YqSDYudmF2KfZhg==?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_16800_331888009.1724885483991"
X-Original-Sender: eliamklump893@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_16800_331888009.1724885483991
Content-Type: multipart/alternative; 
	boundary="----=_Part_16801_1361919243.1724885483991"

------=_Part_16801_1361919243.1724885483991
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2LHZgtmFINin2YTYqtmI2KfYtdmEOiArNDE3OTk1Njk5NjIKV2hhdHNBcHA6ICs4NTUxODM5NzE4
MjUK2KXYsNinINmD2YbYqiDZhdmH2KrZhdmL2Kcg2KjYpdis2LHYp9ihINij2LnZhdin2YQg2KrY
rNin2LHZitipINmF2LnZhtin2Iwg2YHYp9iq2LXZhCDYqNmG2Kcg2LnYqNixINin2LPZhSDZhdiz
2KrYrtiv2YUgVGVsZWdyYW06IApAUFJJVkFURUlOVkVTVE8KV2hhdHNBcHA6ICs4NDc3NjMyNjM4
MgrYtNix2KfYoSDYp9mE2K/ZiNmE2KfYsSDYp9mE2KPZhdix2YrZg9mKINin2YTYo9i12YTZiiDY
udio2LEg2KfZhNil2YbYqtix2YbYqiDZgdmKINi52YXYp9mGINmI2KfZhNmD2YjZitiqINmI2KfZ
hNmF2YXZhNmD2Kkg2KfZhNi52LHYqNmK2KkgCtin2YTYs9i52YjYr9mK2Kkg2YjZgti32LEg2YjY
p9mE2KjYrdix2YrZhiDZiNin2YTYo9ix2K/ZhiDZiNin2YTYpdmF2KfYsdin2Kog2KfZhNi52LHY
qNmK2Kkg2KfZhNmF2KrYrdiv2Kkg2YjYudmF2KfZhiDZiNin2YTZitmF2YYgCtmI2KfZhNi52LHY
p9mCINi02LHYp9ihINin2YTYo9mI2LHYp9mCINin2YTZhtmC2K/ZitipINio2KzZhdmK2Lkg2KfZ
hNi52YXZhNin2Kog2LnYqNixINin2YTYpdmG2KrYsdmG2Kog2LTYsdin2KEg2KPYs9mE2KfZgyDZ
htit2KfYs9mK2KkgCtiw2YfYqNmK2KkgU1NEINi52KjYsSDYp9mE2KXZhtiq2LHZhtiqINmG2YLY
r9mFINmF2KzZhdmI2LnYqSDZhdiq2YbZiNi52Kkg2YXZhiDYp9mE2K7Yr9mF2KfYqiDZhNis2YXZ
iti5INin2YTZhdiz2KrYq9mF2LHZitmGCtmG2K3ZhiDZh9mK2KbYqSDZhdin2YTZitipINmF2LHY
rti12Kkg2KrZgti5INmB2Yog2YLYp9ix2KfYqiDZhdiu2KrZhNmB2Kkg2YHZiiDYo9mI2LHZiNio
2Kcg2YjYo9mF2LHZitmD2Kcg2YjYo9mF2LHZitmD2Kcg2KfZhNi02YXYp9mE2YrYqSAK2YjYutmK
2LHZh9inLi4uINmG2K3ZhiDZh9mK2KbYqSDZhdin2YTZitipINiv2YjZhNmK2Kkg2YXYsdiu2LXY
qSDZhNiq2YjZgdmK2LEg2LXZhtiv2YjZgiDZgtix2LYg2KfYs9iq2KvZhdin2LHZiiDZiNil2YrY
rNin2LEg2YjYtNix2KfYoSAK2KjYo9mB2LbZhCDYs9i52LEg2YHYp9im2K/YqSDZhdi52YLZiNmE
2Iwg2YjZhtmC2K/ZhSDYo9iv2KfYqSDZhdi12LHZgdmK2Kkg2YXYudiq2YXYr9ipINmI2YLYp9io
2YTYqSDZhNmE2KrYrdmC2YIg2LnYqNixINmG2YXZiNiw2KwgCtin2YTYpdix2LPYp9mEINin2YTY
s9ix2YrYudiMINmI2YfZiCDZhdiy2YjYryDYudio2YLYsdmKINmC2KfYr9ixINi52YTZiSDYpdis
2LHYp9ihINin2YTYpdmK2KzYp9ixINmI2KfZhNi02LHYp9ihINio2LPYudixINmF2YbYrtmB2LYg
NiAKKyAyLiAg2YbYrdmGINmH2YrYptipINmC2LHZiNi2INmF2LHYrti12Kkg2YXYp9mE2YrZi9in
INix2KfYptiv2Kkg2YHZiiDYp9mE2LnYp9mE2YXYjCDZiNmG2YLYr9mFINis2YXZiti5INij2YbZ
iNin2Lkg2KrZhdmI2YrZhCAK2KfZhNmF2LTYp9ix2YrYuSDYp9mE2YXYp9mE2YrYqdiMINmI2YLY
sdmI2LYg2KfZhNin2LPYqtir2YXYp9ix2Iwg2YjZgtix2YjYtiDYp9mE2KPYudmF2KfZhNiMINmI
2YLYsdmI2LYg2KfZhNiz2YrYp9ix2KfYqtiMINmI2KfZhNmC2LHZiNi2IArYp9mE2LTYrti12YrY
qdiMINmI2YLYsdmI2LYg2KfZhNix2YfZhiDYp9mE2LnZgtin2LHZiiDZhNmE2LTYsdmD2KfYqtiM
INmI2KfZhNmC2LHZiNi2INi32YjZitmE2Kkg2KfZhNij2KzZhCDZiNmC2LXZitix2Kkg2KfZhNij
2KzZhCAK2LPZhtmI2YrZi9inINmE2YXYr9ipINiq2KrYsdin2YjYrSDZhdmGIDIg2KXZhNmJIDIw
INi52KfZhdmL2Kcg2KjZgdin2KbYr9ipINiz2YbZiNmK2KkuINmD2YXYpyDZhtiv2YHYuSDYudmF
2YjZhNipINio2YbYs9io2KkgMSUgCtmE2YTZiNiz2LfYp9ihL9in2YTZhdiz2KrYtNin2LHZitmG
L9in2YTYrtio2LHYp9ihLi4uINmE2YXYstmK2K8g2YXZhiDYp9mE2YXYudmE2YjZhdin2Kov2KfZ
hNin2LPYqtmB2LPYp9ix2KfYqtiMINmK2LHYrNmJINin2YTYp9iq2LXYp9mEIArYqNmG2Kcg2YTZ
hdiy2YrYryDZhdmGINin2YTZhdiz2KfYudiv2Kkg2K3YqtmJINij2KrZhdmD2YYg2YXZhiDYpdix
2LTYp9iv2YMg2KjYs9mH2YjZhNipINio2LTYo9mG2YfYpy4KDQotLSAKWW91IHJlY2VpdmVkIHRo
aXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3Vw
cyAia2FzYW4tZGV2IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFuZCBz
dG9wIHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byBrYXNhbi1kZXYr
dW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24gb24g
dGhlIHdlYiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2
L2E0MjllM2Y5LWI2NTQtNDg2OC04M2NkLTlkOTlhNDkyNWZlNW4lNDBnb29nbGVncm91cHMuY29t
Lgo=
------=_Part_16801_1361919243.1724885483991
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

PGRpdj7YsdmC2YUg2KfZhNiq2YjYp9i12YQ6ICs0MTc5OTU2OTk2MjxiciAvPldoYXRzQXBwOiAr
ODU1MTgzOTcxODI1PGJyIC8+2KXYsNinINmD2YbYqiDZhdmH2KrZhdmL2Kcg2KjYpdis2LHYp9ih
INij2LnZhdin2YQg2KrYrNin2LHZitipINmF2LnZhtin2Iwg2YHYp9iq2LXZhCDYqNmG2Kcg2LnY
qNixINin2LPZhSDZhdiz2KrYrtiv2YUgVGVsZWdyYW06IEBQUklWQVRFSU5WRVNUTzxiciAvPldo
YXRzQXBwOiArODQ3NzYzMjYzODI8YnIgLz7YtNix2KfYoSDYp9mE2K/ZiNmE2KfYsSDYp9mE2KPZ
hdix2YrZg9mKINin2YTYo9i12YTZiiDYudio2LEg2KfZhNil2YbYqtix2YbYqiDZgdmKINi52YXY
p9mGINmI2KfZhNmD2YjZitiqINmI2KfZhNmF2YXZhNmD2Kkg2KfZhNi52LHYqNmK2Kkg2KfZhNiz
2LnZiNiv2YrYqSDZiNmC2LfYsSDZiNin2YTYqNit2LHZitmGINmI2KfZhNij2LHYr9mGINmI2KfZ
hNil2YXYp9ix2KfYqiDYp9mE2LnYsdio2YrYqSDYp9mE2YXYqtit2K/YqSDZiNi52YXYp9mGINmI
2KfZhNmK2YXZhiDZiNin2YTYudix2KfZgiDYtNix2KfYoSDYp9mE2KPZiNix2KfZgiDYp9mE2YbZ
gtiv2YrYqSDYqNis2YXZiti5INin2YTYudmF2YTYp9iqINi52KjYsSDYp9mE2KXZhtiq2LHZhtiq
INi02LHYp9ihINij2LPZhNin2YMg2YbYrdin2LPZitipINiw2YfYqNmK2KkgU1NEINi52KjYsSDY
p9mE2KXZhtiq2LHZhtiqINmG2YLYr9mFINmF2KzZhdmI2LnYqSDZhdiq2YbZiNi52Kkg2YXZhiDY
p9mE2K7Yr9mF2KfYqiDZhNis2YXZiti5INin2YTZhdiz2KrYq9mF2LHZitmGPGJyIC8+2YbYrdmG
INmH2YrYptipINmF2KfZhNmK2Kkg2YXYsdiu2LXYqSDYqtmC2Lkg2YHZiiDZgtin2LHYp9iqINmF
2K7YqtmE2YHYqSDZgdmKINij2YjYsdmI2KjYpyDZiNij2YXYsdmK2YPYpyDZiNij2YXYsdmK2YPY
pyDYp9mE2LTZhdin2YTZitipINmI2LrZitix2YfYpy4uLiDZhtit2YYg2YfZitim2Kkg2YXYp9mE
2YrYqSDYr9mI2YTZitipINmF2LHYrti12Kkg2YTYqtmI2YHZitixINi12YbYr9mI2YIg2YLYsdi2
INin2LPYqtir2YXYp9ix2Yog2YjYpdmK2KzYp9ixINmI2LTYsdin2KEg2KjYo9mB2LbZhCDYs9i5
2LEg2YHYp9im2K/YqSDZhdi52YLZiNmE2Iwg2YjZhtmC2K/ZhSDYo9iv2KfYqSDZhdi12LHZgdmK
2Kkg2YXYudiq2YXYr9ipINmI2YLYp9io2YTYqSDZhNmE2KrYrdmC2YIg2LnYqNixINmG2YXZiNiw
2Kwg2KfZhNil2LHYs9in2YQg2KfZhNiz2LHZiti52Iwg2YjZh9mIINmF2LLZiNivINi52KjZgtix
2Yog2YLYp9iv2LEg2LnZhNmJINil2KzYsdin2KEg2KfZhNil2YrYrNin2LEg2YjYp9mE2LTYsdin
2KEg2KjYs9i52LEg2YXZhtiu2YHYtiA2ICsgMi4gwqDZhtit2YYg2YfZitim2Kkg2YLYsdmI2LYg
2YXYsdiu2LXYqSDZhdin2YTZitmL2Kcg2LHYp9im2K/YqSDZgdmKINin2YTYudin2YTZhdiMINmI
2YbZgtiv2YUg2KzZhdmK2Lkg2KPZhtmI2KfYuSDYqtmF2YjZitmEINin2YTZhdi02KfYsdmK2Lkg
2KfZhNmF2KfZhNmK2KnYjCDZiNmC2LHZiNi2INin2YTYp9iz2KrYq9mF2KfYsdiMINmI2YLYsdmI
2LYg2KfZhNij2LnZhdin2YTYjCDZiNmC2LHZiNi2INin2YTYs9mK2KfYsdin2KrYjCDZiNin2YTZ
gtix2YjYtiDYp9mE2LTYrti12YrYqdiMINmI2YLYsdmI2LYg2KfZhNix2YfZhiDYp9mE2LnZgtin
2LHZiiDZhNmE2LTYsdmD2KfYqtiMINmI2KfZhNmC2LHZiNi2INi32YjZitmE2Kkg2KfZhNij2KzZ
hCDZiNmC2LXZitix2Kkg2KfZhNij2KzZhCDYs9mG2YjZitmL2Kcg2YTZhdiv2Kkg2KrYqtix2KfZ
iNitINmF2YYgMiDYpdmE2YkgMjAg2LnYp9mF2YvYpyDYqNmB2KfYptiv2Kkg2LPZhtmI2YrYqS4g
2YPZhdinINmG2K/Zgdi5INi52YXZiNmE2Kkg2KjZhtiz2KjYqSAxJSDZhNmE2YjYs9i32KfYoS/Y
p9mE2YXYs9iq2LTYp9ix2YrZhi/Yp9mE2K7YqNix2KfYoS4uLiDZhNmF2LLZitivINmF2YYg2KfZ
hNmF2LnZhNmI2YXYp9iqL9in2YTYp9iz2KrZgdiz2KfYsdin2KrYjCDZitix2KzZiSDYp9mE2KfY
qti12KfZhCDYqNmG2Kcg2YTZhdiy2YrYryDZhdmGINin2YTZhdiz2KfYudiv2Kkg2K3YqtmJINij
2KrZhdmD2YYg2YXZhiDYpdix2LTYp9iv2YMg2KjYs9mH2YjZhNipINio2LTYo9mG2YfYpy48YnIg
Lz48L2Rpdj4NCg0KPHA+PC9wPgoKLS0gPGJyIC8+CllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2Ug
YmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgJnF1b3Q7a2Fz
YW4tZGV2JnF1b3Q7IGdyb3VwLjxiciAvPgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAg
YW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIDxhIGhy
ZWY9Im1haWx0bzprYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbSI+a2FzYW4t
ZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb208L2E+LjxiciAvPgpUbyB2aWV3IHRoaXMg
ZGlzY3Vzc2lvbiBvbiB0aGUgd2ViIHZpc2l0IDxhIGhyZWY9Imh0dHBzOi8vZ3JvdXBzLmdvb2ds
ZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvYTQyOWUzZjktYjY1NC00ODY4LTgzY2QtOWQ5OWE0OTI1
ZmU1biU0MGdvb2dsZWdyb3Vwcy5jb20/dXRtX21lZGl1bT1lbWFpbCZ1dG1fc291cmNlPWZvb3Rl
ciI+aHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9hNDI5ZTNmOS1i
NjU0LTQ4NjgtODNjZC05ZDk5YTQ5MjVmZTVuJTQwZ29vZ2xlZ3JvdXBzLmNvbTwvYT4uPGJyIC8+
Cg==
------=_Part_16801_1361919243.1724885483991--

------=_Part_16800_331888009.1724885483991--
