Return-Path: <kasan-dev+bncBC36BFVD6MNBBW5O5TCQMGQESNAEAPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D0655B45F80
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 19:01:18 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-30cce50fe7dsf849614fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 10:01:18 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757091677; x=1757696477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pcdqUfQ2Ydn6RdUvPvZkd+sbe/ItJwYdAgOdlIVoL/E=;
        b=qdhvxnW4w7P28Sxr/FN1VKBbukSletm27GzFkuPVPNZRjBZJkS6oYEj75Tf+GblyAt
         No1N+D2sJ4glRuRR0zg8oDZIsKa+JBJGupdMzFVlfykXBcci0Rrt9IZiBhb+IgAUc2jw
         12T1/H2na9NuqM50FepwTSaFBD7vFuqoRLYVgM7pEF4xa4V6Hsb3FWpV0eL7CNtDL3Wm
         ek5pk6va+upPJuL8ej4/Urmv10n+NOmCPAhe8zcqWCkwe/+nSX9MFJ9nluKWgN1/ZeG5
         ltcGDRaECnrBovfUMYgI+M0Xxho94p8Hsf93vdEcwA43Kt4wpKTHnfJQrPkLZR6GhDbM
         6P9A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757091677; x=1757696477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pcdqUfQ2Ydn6RdUvPvZkd+sbe/ItJwYdAgOdlIVoL/E=;
        b=kjlelCG1U4MolTNVwLiO0ShecCDuMuE6Dp41/m1pZw4zoyRv4VOcNIM0h1446kTIsB
         7HcM+OQjx8WF2J4s6jh9VnDmVDlvlrU7WFihq53JYhWJHQ0bXXrN7u+m33rKIfLaLnAv
         IBRG2U/6OsU3cpNgeC4sERkDMubhgKqYuhv3g7GghKp6Tuq/jrTdhtmtenLkE8nOjR6y
         3sVY2ADkhXuztn9SdK9nByVDbr49RsApcmJYsCNKrDpAe379xxIc1f4HlTOLbic+n3ct
         fqsqAT+GO/UcYwiL9ASnvvpkkM48hzuG8i5ENn8aYFk/PZzrqNVzxVSsM0MWbhWxYYXS
         vR3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757091677; x=1757696477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pcdqUfQ2Ydn6RdUvPvZkd+sbe/ItJwYdAgOdlIVoL/E=;
        b=w/cvqAp+poGiHbka5MPTvKXutRnBJ4+eKHHhkoeMvk8FeDcaJw1n825vXYIe80JGHr
         ZqEaHVaCNBsWZUMDHtbY/AP+M7W1O4Dy+CHXlpaFFCjWs1yOQImxs+xd10qHin96qE5N
         FzwYT9iEdoQNxL+wkzwcbV2IFrT8veCgztVWtD0kh9AluByh3WbqO27euqQ5DR60zjvt
         htt3GUfv6/7JUAggkiSXg0ZIMacaAYObHbi0LM+7dZeqcpw0WERGfPTL9ozGjOwMHapH
         Ml/WQ6++5ZQy+ZtfubYyh45TRjT1vtAL9cMQTsKNA/kXbSSda39CCl38NSRfZ7k973+q
         7JSw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCW2sgaoRbPaPFnPxSl8z6aq2Mht/bGsvqvggSiTpfVoM0CkXmeA35RVsVplKhYvk0JkVBivOw==@lfdr.de
X-Gm-Message-State: AOJu0YyCOiIYcDF1sfnR6OlZKKWcbioTr13g2dS+zqN2HxW/if6ZLSsb
	9HwPq4nMQzq3csIZ+aJeJ4jk3liB7YBuudVmVtihUhiOuI7GCMypaoM0
X-Google-Smtp-Source: AGHT+IH/tvP9f+zUjR9FeWMPvxPlgENCgZCScVlNdp4MXdfYWitEaSejttx98wlrh+df361VrGxCtQ==
X-Received: by 2002:a05:6871:2210:b0:315:30b7:404b with SMTP id 586e51a60fabf-319633d8f5fmr9820600fac.40.1757091675934;
        Fri, 05 Sep 2025 10:01:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf4vIgPj1OuaA8hqaDFSYoeXEVjlLuqx4Dz9CQIlr4NCA==
Received: by 2002:a05:687c:2058:10b0:31f:ea45:fb21 with SMTP id
 586e51a60fabf-32126ff924dls664918fac.2.-pod-prod-03-us; Fri, 05 Sep 2025
 10:01:14 -0700 (PDT)
X-Received: by 2002:a05:6808:6508:b0:438:22cd:2996 with SMTP id 5614622812f47-43822cd2b93mr5833078b6e.5.1757091674286;
        Fri, 05 Sep 2025 10:01:14 -0700 (PDT)
Date: Fri, 5 Sep 2025 10:01:13 -0700 (PDT)
From: =?UTF-8?B?2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg4oCT?=
 =?UTF-8?B?INmG2LPYqNipINmG2KzYp9itIDk12ao=?= <hayatannas967@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <26b4071e-9689-4466-8ac2-1bcfc583d2e6n@googlegroups.com>
In-Reply-To: <36dacae4-ca3c-47cb-90bc-f74023c8b4dfn@googlegroups.com>
References: <412ffb42-69a2-4d34-9ea5-6aa53dd58711n@googlegroups.com>
 <36dacae4-ca3c-47cb-90bc-f74023c8b4dfn@googlegroups.com>
Subject: =?UTF-8?B?UmU6INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNix2YrYp9i2?=
 =?UTF-8?B?IDA1Mzc0NjY1MzkgI9in2YTYs9i52YjYr9mK2Kk=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_38778_1622527695.1757091673274"
X-Original-Sender: hayatannas967@gmail.com
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

------=_Part_38778_1622527695.1757091673274
Content-Type: multipart/alternative; 
	boundary="----=_Part_38779_1797926142.1757091673274"

------=_Part_38779_1797926142.1757091673274
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

CgrYs9in2YrYqtmI2KrZitmDKNi12YrYr9mE2YrYqSktMDUzNzQ2NjUzOS8vINit2KjZiNioINiz
2KfZitiq2YjYqtmDINin2YTYsdmK2KfYtgoKCtiz2KfZitiq2YjYqtmK2YMgKNin2YTYsdmK2KfY
tsKuKTA1Mzc0NjY1Mzkg2LPYudmI2K/ZitipCgpOZXcgCjxodHRwczovL2ZvcnVtLmRqaS5jb20v
Zm9ydW0ucGhwP21vZD1yZWRpcmVjdCZ0aWQ9MzM3NTY1JmdvdG89bGFzdHBvc3QjbGFzdHBvc3Q+
CgoK2LPYp9mK2KrZiNiq2YrZgyjYs9mE2LfZhtipINi52YXYp9mGwq4pLSAwNTM3NDY2NTM5IAoK
TmV3IAo8aHR0cHM6Ly9mb3J1bS5kamkuY29tL2ZvcnVtLnBocD9tb2Q9cmVkaXJlY3QmdGlkPTMz
NzU2NiZnb3RvPWxhc3Rwb3N0I2xhc3Rwb3N0PgoKCtiz2KfZitiq2YjYqtmK2YMo2LXZitiv2YTZ
itipKS0wNTM3NDY2NTM5INin2YTYsdmK2KfYtgoKTmV3IAo8aHR0cHM6Ly9mb3J1bS5kamkuY29t
L2ZvcnVtLnBocD9tb2Q9cmVkaXJlY3QmdGlkPTMzNzU2NyZnb3RvPWxhc3Rwb3N0I2xhc3Rwb3N0
PgoK2YXZg9ipICjYs9in2YrYqtmI2KrZitmDwq4p2YXZitiy2YjYqNix2LPYqtmI2YQgLSAwNTM3
NDY2NTM5IAoKwq7Ys9in2YrYqtmI2KrZitmDKNi12YrYr9mE2YrYqSktMDUzNzQ2NjUzOSDYrNiv
2KkKCgrZgdmKIEZyaWRheSwgU2VwdGVtYmVyIDUsIDIwMjUg2YHZiiDYqtmF2KfZhSDYp9mE2LPY
p9i52KkgMTA6MDE6MDHigK9BTSBVVEMtN9iMINmD2KrYqCDYrdio2YjYqCAK2LPYp9mK2KrZiNiq
2YMg4oCTINmG2LPYqNipINmG2KzYp9itIDk12aog2LHYs9in2YTYqSDZhti12YfYpzoKCj4g2LPY
p9mK2KrZiNiq2YrZgyjYtdmK2K/ZhNmK2KkpLTA1Mzc0NjY1MzkvLyDYrdio2YjYqCDYs9in2YrY
qtmI2KrZgyDYp9mE2LHZitin2LYKPgo+Cj4g2LPYp9mK2KrZiNiq2YrZgyAo2KfZhNix2YrYp9i2
wq4pMDUzNzQ2NjUzOSDYs9i52YjYr9mK2KkKPgo+IE5ldyAKPiA8aHR0cHM6Ly9mb3J1bS5kamku
Y29tL2ZvcnVtLnBocD9tb2Q9cmVkaXJlY3QmdGlkPTMzNzU2NSZnb3RvPWxhc3Rwb3N0I2xhc3Rw
b3N0Pgo+Cj4KPiDYs9in2YrYqtmI2KrZitmDKNiz2YTYt9mG2Kkg2LnZhdin2YbCriktIDA1Mzc0
NjY1MzkgCj4KPiBOZXcgCj4gPGh0dHBzOi8vZm9ydW0uZGppLmNvbS9mb3J1bS5waHA/bW9kPXJl
ZGlyZWN0JnRpZD0zMzc1NjYmZ290bz1sYXN0cG9zdCNsYXN0cG9zdD4KPgo+Cj4g2LPYp9mK2KrZ
iNiq2YrZgyjYtdmK2K/ZhNmK2KkpLTA1Mzc0NjY1Mzkg2KfZhNix2YrYp9i2Cj4KPiBOZXcgCj4g
PGh0dHBzOi8vZm9ydW0uZGppLmNvbS9mb3J1bS5waHA/bW9kPXJlZGlyZWN0JnRpZD0zMzc1Njcm
Z290bz1sYXN0cG9zdCNsYXN0cG9zdD4KPgo+INmF2YPYqSAo2LPYp9mK2KrZiNiq2YrZg8KuKdmF
2YrYstmI2KjYsdiz2KrZiNmEIC0gMDUzNzQ2NjUzOSAKPgo+IMKu2LPYp9mK2KrZiNiq2YrZgyjY
tdmK2K/ZhNmK2KkpLTA1Mzc0NjY1Mzkg2KzYr9ipCj4KPgo+INmB2YogU3VuZGF5LCBBdWd1c3Qg
MTcsIDIwMjUg2YHZiiDYqtmF2KfZhSDYp9mE2LPYp9i52KkgMToxOToyOeKAr0FNIFVUQy032Iwg
2YPYqtioINit2KjZiNioIAo+INiz2KfZitiq2YjYqtmDIOKAkyDZhtiz2KjYqSDZhtis2KfYrSA5
NdmqINix2LPYp9mE2Kkg2YbYtdmH2Kc6Cj4KPj4g2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LHZ
itin2LYgMDUzNzQ2NjUzOSAj2KfZhNiz2LnZiNiv2YrYqSDZhNmE2KXYrNmH2KfYtiDYp9mE2KLZ
hdmGINmF2Lkg2K8uINmG2YrYsdmF2YrZhiB8IHwgCj4+INin2YTYsdmK2KfYtiDYrNiv2Kkg2YXZ
g9ipINin2YTYr9mF2KfZhQo+Pgo+PiDYp9mD2KrYtNmB2Yog2YXYuSDYry4g2YbZitix2YXZitmG
2Iwg2KfZhNmI2YPZitmEINin2YTYsdiz2YXZiiDZhNit2KjZiNioINiz2KfZitiq2YjYqtmDINmB
2Yog2KfZhNiz2LnZiNiv2YrYqdiMINmD2YrZgdmK2KkgCj4+INin2YTYpdis2YfYp9i2INin2YTY
t9io2Yog2KfZhNii2YXZhiDYqNin2LPYqtiu2K/Yp9mFINiz2KfZitiq2YjYqtmDIDIwMCAoTWlz
b3Byb3N0b2wpINio2KXYtNix2KfZgSDYt9io2Yog2YjYs9ix2ZHZitipIAo+PiDYqtin2YXYqS4g
2KrZiNi12YrZhCDYs9ix2YrYuSDZgdmKINin2YTYsdmK2KfYttiMINis2K/YqdiMINmF2YPYqdiM
INin2YTYr9mF2KfZhSDZiNio2KfZgtmKINin2YTZhdiv2YYuIPCfk54gMDUzNzQ2NjUzOQo+Pgo+
PiDZgdmKINin2YTYs9mG2YjYp9iqINin2YTYo9iu2YrYsdip2Iwg2KPYtdio2K3YqiDYrdio2YjY
qCDYs9in2YrYqtmI2KrZgyA8aHR0cHM6Ly9rc2FjeXRvdGVjLmNvbS8+IAo+PiAoTWlzb3Byb3N0
b2wpINiu2YrYp9ix2YvYpyDYt9io2YrZi9inINmF2LnYsdmI2YHZi9inINmI2YHYudmR2KfZhNmL
2Kcg2YTYpdmG2YfYp9ihINin2YTYrdmF2YQg2KfZhNmF2KjZg9ixINio2LfYsdmK2YLYqSAKPj4g
2KLZhdmG2Kkg2KrYrdiqINil2LTYsdin2YEg2YXYrtiq2LXZitmGLiDZiNmF2Lkg2KfZhtiq2LTY
p9ixINin2YTZhdmG2KrYrNin2Kog2KfZhNmF2YLZhNiv2KnYjCDYo9i12KjYrSDZhdmGINin2YTY
ttix2YjYsdmKINin2YTYrdi12YjZhCAKPj4g2LnZhNmJINin2YTYr9mI2KfYoSDZhdmGINmF2LXY
r9ixINmF2YjYq9mI2YIg2YjZhdi52KrZhdivLgo+PiDYry4g2YbZitix2YXZitmG2Iwg2KjYtdmB
2KrZh9inINin2YTZiNmD2YrZhCDYp9mE2LHYs9mF2Yog2YTYrdio2YjYqCDYs9in2YrYqtmI2KrZ
gyDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDYqtmC2K/ZhSDZhNmD2ZAgCj4+INmF2YbYqtis2YvY
pyDYo9i12YTZitmL2Kcg2KjYrNmI2K/YqSDZhdi22YXZiNmG2KnYjCDZhdi5INin2LPYqti02KfY
sdipINi32KjZitipINmF2KrYrti12LXYqSDZiNiz2LHZkdmK2Kkg2KrYp9mF2Kkg2YHZiiDYp9mE
2KrYudin2YXZhCAKPj4g2YjYp9mE2KrZiNi12YrZhC4KPj4KPj4gLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tCj4+Cj4+INmF2Kcg2YfZiCDYr9mI2KfYoSDYs9in2YrYqtmI2KrZg9ifCj4+
Cj4+INiz2KfZitiq2YjYqtmDICjYp9mE2YXYp9iv2Kkg2KfZhNmB2LnYp9mE2Kkg2YXZitiy2YjY
qNix2YjYs9iq2YjZhCkg2K/ZiNin2KEg2YXZj9i52KrZhdivINmB2Yog2KfZhNmF2KzYp9mEINin
2YTYt9io2YrYjCAKPj4g2YjZitmP2LPYqtiu2K/ZhSDYqNis2LHYudin2Kog2K/ZgtmK2YLYqSDZ
hNil2YbZh9in2KEg2KfZhNit2YXZhCDYp9mE2YXYqNmD2LHYjCDZiNi52YTYp9isINit2KfZhNin
2Kog2LfYqNmK2Kkg2KPYrtix2Ykg2YXYq9mEINmC2LHYrdipIAo+PiDYp9mE2YXYudiv2KkuINi5
2YbYryDYp9iz2KrYrtiv2KfZhdmHINmE2YTYpdis2YfYp9i22Iwg2YrYudmF2YQg2LnZhNmJINiq
2K3ZgdmK2LIg2KrZgtmE2LXYp9iqINin2YTYsdit2YUg2YjYpdmB2LHYp9i6INmF2K3YqtmI2YrY
p9iq2YcgCj4+INiu2YTYp9mEINmB2KrYsdipINmC2LXZitix2KnYjCDZhdmF2Kcg2YrYrNi52YTZ
hyDYrtmK2KfYsdmL2Kcg2YHYudin2YTZi9inINmI2KLZhdmG2YvYpyDYudmG2K8g2KXYtNix2KfZ
gSDYt9io2YrYqCDZhdiu2KrYtS4KPj4KPj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
Cj4+Cj4+INij2YfZhdmK2Kkg2KfZhNit2LXZiNmEINi52YTZiSDYs9in2YrYqtmI2KrZgyDZhdmG
INmF2LXYr9ixINmF2YjYq9mI2YIKPj4KPj4g2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2KrYqtmI
2KfYrNivINin2YTZg9ir2YrYsSDZhdmGINin2YTZgtmG2YjYp9iqINi62YrYsSDYp9mE2YXZiNir
2YjZgtipINin2YTYqtmKINiq2KjZiti5INmF2YbYqtis2KfYqiAKPj4g2YXYrNmH2YjZhNipINin
2YTZhdi12K/YsSDZgtivINiq2KTYr9mKINil2YTZiSDZhdiu2KfYt9ixINi12K3ZitipINis2LPZ
itmF2KkuCj4+INivLiDZhtmK2LHZhdmK2YYg2KrYttmF2YYg2YTZgzoKPj4g4pyU77iPINit2KjZ
iNioINiz2KfZitiq2YjYqtmDINij2LXZhNmK2KkgMTAwJQo+PiDinJTvuI8g2KrYp9ix2YrYriDY
tdmE2KfYrdmK2Kkg2K3Yr9mK2KsKPj4g4pyU77iPINil2LHYtNin2K/Yp9iqINi32KjZitipINiv
2YLZitmC2Kkg2YTZhNin2LPYqtiu2K/Yp9mFCj4+IOKclO+4jyDYs9ix2ZHZitipINiq2KfZhdip
INmB2Yog2KfZhNiq2YjYtdmK2YQKPj4g4pyU77iPINiv2LnZhSDZiNin2LPYqti02KfYsdipINi5
2YTZiSDZhdiv2KfYsSDYp9mE2LPYp9i52KkKPj4KPj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tCj4+Cj4+INmE2YXYp9iw2Kcg2KrYrtiq2KfYsdmK2YYg2K8uINmG2YrYsdmF2YrZhtif
Cj4+ICAgIAo+PiAgICAtIAo+PiAgICAKPj4gICAg2KfZhNiu2KjYsdipINin2YTYt9io2YrYqTog
2K8uINmG2YrYsdmF2YrZhiDZhdiq2K7Ytdi12Kkg2YHZiiDYp9mE2KfYs9iq2LTYp9ix2KfYqiDY
p9mE2LfYqNmK2Kkg2KfZhNmG2LPYp9im2YrYqdiMINmI2KrZgtiv2YUgCj4+ICAgINmE2YPZkCDY
r9i52YXZi9inINmF2YfZhtmK2YvYpyDZgtio2YQg2YjYo9ir2YbYp9ihINmI2KjYudiv2KfYs9iq
2K7Yr9in2YUg2LPYp9mK2KrZiNiq2YMgCj4+ICAgIDxodHRwczovL3NhdWRpZXJzYWEuY29tLz4u
Cj4+ICAgIAo+PiAgICAtIAo+PiAgICAKPj4gICAg2KfZhNiq2YjYtdmK2YQg2KfZhNiz2LHZiti5
OiDYqti62LfZitipINmE2KzZhdmK2Lkg2KfZhNmF2K/ZhiDYp9mE2LPYudmI2K/Zitip2Iwg2KjZ
hdinINmB2Yog2LDZhNmDINin2YTYsdmK2KfYttiMINis2K/YqdiMIAo+PiAgICDZhdmD2KnYjCDY
p9mE2K/Zhdin2YXYjCDYp9mE2K7YqNix2Iwg2KfZhNi32KfYptmBINmI2LrZitix2YfYpy4KPj4g
ICAgCj4+ICAgIC0gCj4+ICAgIAo+PiAgICDYrdmF2KfZitipINiu2LXZiNi12YrYqtmDOiDZitiq
2YUg2KfZhNiq2LrZhNmK2YEg2KjYt9ix2YrZgtipINiq2LbZhdmGINin2YTYs9ix2ZHZitipINin
2YTZg9in2YXZhNipLgo+PiAgICAKPj4gICAgLSAKPj4gICAgCj4+ICAgINin2YTYqtmI2YPZitmE
INin2YTYsdiz2YXZijog2LTYsdin2KHZgyDZitiq2YUg2YXYqNin2LTYsdipINmF2YYg2KfZhNmF
2LXYr9ixINin2YTZhdi52KrZhdiv2Iwg2KjYudmK2K/Zi9inINi52YYg2KfZhNmF2K7Yp9i32LEu
Cj4+ICAgIAo+PiAgICAKPj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4+Cj4+INmD
2YrZgdmK2Kkg2LfZhNioINit2KjZiNioINiz2KfZitiq2YjYqtmDINmF2YYg2K8uINmG2YrYsdmF
2YrZhgo+PiAgICAKPj4gICAgMS4gCj4+ICAgIAo+PiAgICDYp9mE2KrZiNin2LXZhCDYudio2LEg
2YjYp9iq2LPYp9ioINi52YTZiSDYp9mE2LHZgtmFOiDwn5OeIDA1Mzc0NjY1MzkKPj4gICAgCj4+
ICAgIDIuIAo+PiAgICAKPj4gICAg2LTYsditINin2YTYrdin2YTYqSDYp9mE2LXYrdmK2Kkg2YjZ
gdiq2LHYqSDYp9mE2K3ZhdmELgo+PiAgICAKPj4gICAgMy4gCj4+ICAgIAo+PiAgICDYp9iz2KrZ
hNin2YUg2KfZhNil2LHYtNin2K/Yp9iqINin2YTYt9io2YrYqSDYp9mE2YXZhtin2LPYqNipINmI
2KfZhNis2LHYudipINin2YTZhdmI2LXZiSDYqNmH2KcuCj4+ICAgIAo+PiAgICA0LiAKPj4gICAg
Cj4+ICAgINin2LPYqtmE2KfZhSDYp9mE2K3YqNmI2Kgg2K7ZhNin2YQg2YHYqtix2Kkg2YLYtdmK
2LHYqSDYudio2LEg2K7Yr9mF2Kkg2KrZiNi12YrZhCDYotmF2YbYqSDZiNiz2LHZitipLgo+PiAg
ICAKPj4gICAgCj4+IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Pgo+PiDYqtmG2KjZ
itmHINi32KjZiiDZhdmH2YUKPj4gICAgCj4+ICAgIC0gCj4+ICAgIAo+PiAgICDZitis2Kgg2KfY
s9iq2K7Yr9in2YUg2LPYp9mK2KrZiNiq2YMg2YHZgti3INiq2K3YqiDYpdi02LHYp9mBINi32KjZ
iiDZhdiu2KrYtS4KPj4gICAgCj4+ICAgIC0gCj4+ICAgIAo+PiAgICDZhNinINmK2Y/Zhti12K0g
2KjYp9iz2KrYrtiv2KfZhdmHINmB2Yog2K3Yp9mE2KfYqiDYp9mE2K3ZhdmEINin2YTZhdiq2KPY
rtixLgo+PiAgICAKPj4gICAgLSAKPj4gICAgCj4+ICAgINmB2Yog2K3Yp9mEINmI2KzZiNivINij
2YXYsdin2LYg2YXYstmF2YbYqSDYo9mIINit2KfZhNin2Kog2K7Yp9i12KnYjCDZitis2Kgg2KfY
s9iq2LTYp9ix2Kkg2KfZhNi32KjZitioINmC2KjZhCAKPj4gICAg2KfZhNin2LPYqtiu2K/Yp9mF
Lgo+PiAgICAKPj4gICAgCj4+IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Pgo+PiDY
rtiv2YXYp9iqINil2LbYp9mB2YrYqSDZhdmGINivLiDZhtmK2LHZhdmK2YYKPj4gICAgCj4+ICAg
IC0gCj4+ICAgIAo+PiAgICDZhdiq2KfYqNi52Kkg2KfZhNit2KfZhNipINio2LnYryDYp9mE2KfY
s9iq2K7Yr9in2YUuCj4+ICAgIAo+PiAgICAtIAo+PiAgICAKPj4gICAg2KrZiNmB2YrYsSDZhdi5
2YTZiNmF2KfYqiDYrdmI2YQg2KfZhNii2KvYp9ixINin2YTYrNin2YbYqNmK2Kkg2KfZhNi32KjZ
iti52YrYqSDZiNmD2YrZgdmK2Kkg2KfZhNiq2LnYp9mF2YQg2YXYudmH2KcuCj4+ICAgIAo+PiAg
ICAtIAo+PiAgICAKPj4gICAg2KXYsdi02KfYryDYp9mE2YXYsdmK2LbYqSDYpdmE2Ykg2KPZgdi2
2YQg2YXZhdin2LHYs9in2Kog2KfZhNiz2YTYp9mF2Kkg2KfZhNi32KjZitipLgo+PiAgICAKPj4g
ICAgCj4+IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Pgo+PiDYrtmE2KfYtdipCj4+
Cj4+INin2K7YqtmK2KfYsSDYp9mE2YXYtdiv2LEg2KfZhNmF2YjYq9mI2YIg2LnZhtivINi02LHY
p9ihINit2KjZiNioINiz2KfZitiq2YjYqtmDIAo+PiA8aHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNv
bS9hL2Nocm9taXVtLm9yZy9nL3NlY3VyaXR5LWRldi9jL3JoclBwaXZDUUdNL20vWGloVUJpU0xB
QUFKPiAKPj4g2YHZiiDYp9mE2LPYudmI2K/ZitipINmH2Ygg2KfZhNi22YXYp9mGINin2YTZiNit
2YrYryDZhNiz2YTYp9mF2KrZg9mQLgo+PiDZhdi5INivLiDZhtmK2LHZhdmK2YbYjCDYs9iq2K3Y
tdmE2YrZhiDYudmE2Ykg2KfZhNmF2YbYqtisINin2YTYo9i12YTZitiMINin2YTYpdix2LTYp9iv
INin2YTYt9io2Yog2KfZhNmF2KrYrti12LXYjCDZiNin2YTYqtmI2LXZitmEIAo+PiDYp9mE2LPY
sdmKINij2YrZhtmF2Kcg2YPZhtiq2ZAg2YHZiiDYp9mE2YXZhdmE2YPYqS4KPj4KPj4g8J+TniDZ
hNmE2KrZiNin2LXZhCDZiNin2YTYt9mE2Kgg2LnYqNixINmI2KfYqtiz2KfYqDogMDUzNzQ2NjUz
OQo+PiDYp9mE2YXYr9mGINin2YTZhdi62LfYp9ipOiDYp9mE2LHZitin2LYg4oCTINis2K/YqSDi
gJMg2YXZg9ipIOKAkyDYp9mE2K/Zhdin2YUg4oCTINin2YTYrtio2LEg4oCTINin2YTYt9in2KbZ
gSDigJMg2KfZhNmF2K/ZitmG2KkgCj4+INin2YTZhdmG2YjYsdipIOKAkyDYo9io2YfYpyDigJMg
2KzYp9iy2KfZhiDigJMg2KrYqNmI2YMuCj4+Cj4+IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLQo+Pgo+PiAgCj4+Cj4+INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqdiM
INiz2KfZitiq2YjYqtmDINin2YTYsdmK2KfYttiMINiz2KfZitiq2YjYqtmDINis2K/YqdiMINiz
2KfZitiq2YjYqtmDINmF2YPYqdiMINiz2KfZitiq2YjYqtmDIAo+PiDYp9mE2K/Zhdin2YXYjCDY
tNix2KfYoSDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDYrdio2YjYqCDY
s9in2YrYqtmI2KrZgyDZhNmE2KXYrNmH2KfYttiMINiz2KfZitiq2YjYqtmDINij2LXZhNmK2Iwg
Cj4+INiz2KfZitiq2YjYqtmDIDIwMNiMIE1pc29wcm9zdG9sINin2YTYs9i52YjYr9mK2KnYjCDY
s9in2YrYqtmI2KrZgyDYp9mE2YbZh9iv2YrYjCAKPj4gaHR0cHM6Ly9rc2FjeXRvdGVjLmNvbS8g
2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2K/Zg9iq2YjYsdipINmG2YrYsdmF2YrZhiDYs9in2YrY
qtmI2KrZgy4KPj4KPj4g2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2LPY
p9mK2KrZiNiq2YMg2KfZhNix2YrYp9i22Iwg2LPYp9mK2KrZiNiq2YMg2KzYr9ip2Iwg2LPYp9mK
2KrZiNiq2YMg2YXZg9ip2Iwg2LPYp9mK2KrZiNiq2YMgCj4+INin2YTYr9mF2KfZhdiMINi02LHY
p9ihINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqdiMINit2KjZiNioINiz2KfZ
itiq2YjYqtmDINmE2YTYpdis2YfYp9i22Iwg2LPYp9mK2KrZiNiq2YMg2KPYtdmE2YrYjCAKPj4g
2LPYp9mK2KrZiNiq2YMgMjAw2IwgTWlzb3Byb3N0b2wg2KfZhNiz2LnZiNiv2YrYqdiMINiz2KfZ
itiq2YjYqtmDINin2YTZhtmH2K/ZitiMINin2YTYpdis2YfYp9i2INin2YTYt9io2Yog2YHZiiAK
Pj4g2KfZhNiz2LnZiNiv2YrYqdiMINiv2YPYqtmI2LHYqSDZhtmK2LHZhdmK2YYg2LPYp9mK2KrZ
iNiq2YMuCj4+Cj4+DQoNCi0tIApZb3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91
IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICJrYXNhbi1kZXYiIGdyb3VwLgpU
byB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBm
cm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91
cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29n
bGUuY29tL2QvbXNnaWQva2FzYW4tZGV2LzI2YjQwNzFlLTk2ODktNDQ2Ni04YWMyLTFiY2ZjNTgz
ZDJlNm4lNDBnb29nbGVncm91cHMuY29tLgo=
------=_Part_38779_1797926142.1757091673274
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: =
0pt;"><span style=3D"font-size: 15pt; font-family: Arial, sans-serif; color=
: rgb(0, 0, 0); font-weight: 700; font-variant-numeric: normal; font-varian=
t-east-asian: normal; font-variant-alternates: normal; font-variant-positio=
n: normal; font-variant-emoji: normal; vertical-align: baseline; white-spac=
e-collapse: preserve;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83(=D8=
=B5=D9=8A=D8=AF=D9=84=D9=8A=D8=A9)-0537466539// =D8=AD=D8=A8=D9=88=D8=A8 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=
=D8=B6</span></p><br /><br /><p dir=3D"rtl" style=3D"line-height: 1.2; marg=
in-top: 4pt; margin-bottom: 0pt;"><span style=3D"font-size: 13.5pt; font-fa=
mily: &quot;Microsoft Yahei&quot;; color: rgb(0, 0, 0); background-color: r=
gb(245, 245, 245); font-weight: 700; font-variant-numeric: normal; font-var=
iant-east-asian: normal; font-variant-alternates: normal; font-variant-posi=
tion: normal; font-variant-emoji: normal; vertical-align: baseline; white-s=
pace-collapse: preserve;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83 =
(=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=C2=AE)</span><span style=3D"font-size=
: 16pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); font-weight: 7=
00; font-variant-numeric: normal; font-variant-east-asian: normal; font-var=
iant-alternates: normal; font-variant-position: normal; font-variant-emoji:=
 normal; vertical-align: baseline; white-space-collapse: preserve;">0537466=
539 =D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9</span></p><p dir=3D"rtl" style=3D"=
line-height: 1.2; margin-top: 2pt; margin-bottom: 0pt;"><a href=3D"https://=
forum.dji.com/forum.php?mod=3Dredirect&amp;tid=3D337565&amp;goto=3Dlastpost=
#lastpost"><span style=3D"font-size: 9pt; font-family: &quot;Microsoft Yahe=
i&quot;; color: rgb(242, 108, 79); background-color: rgb(245, 245, 245); fo=
nt-weight: 700; font-variant-numeric: normal; font-variant-east-asian: norm=
al; font-variant-alternates: normal; font-variant-position: normal; font-va=
riant-emoji: normal; vertical-align: baseline; white-space-collapse: preser=
ve;">New</span></a></p><br /><br /><p dir=3D"rtl" style=3D"line-height: 1.2=
; margin-top: 4pt; margin-bottom: 0pt;"><span style=3D"font-size: 13.5pt; f=
ont-family: &quot;Microsoft Yahei&quot;; color: rgb(242, 108, 79); backgrou=
nd-color: rgb(245, 245, 245); font-weight: 700; font-variant-numeric: norma=
l; font-variant-east-asian: normal; font-variant-alternates: normal; font-v=
ariant-position: normal; font-variant-emoji: normal; vertical-align: baseli=
ne; white-space-collapse: preserve;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=8A=D9=83(=D8=B3=D9=84=D8=B7=D9=86=D8=A9 =D8=B9=D9=85=D8=A7=D9=86=C2=AE)=
- </span><span style=3D"font-size: 16pt; font-family: Arial, sans-serif; co=
lor: rgb(0, 0, 0); font-weight: 700; font-variant-numeric: normal; font-var=
iant-east-asian: normal; font-variant-alternates: normal; font-variant-posi=
tion: normal; font-variant-emoji: normal; vertical-align: baseline; white-s=
pace-collapse: preserve;">0537466539=C2=A0</span></p><p dir=3D"rtl" style=
=3D"line-height: 1.2; margin-top: 2pt; margin-bottom: 0pt;"><a href=3D"http=
s://forum.dji.com/forum.php?mod=3Dredirect&amp;tid=3D337566&amp;goto=3Dlast=
post#lastpost"><span style=3D"font-size: 9pt; font-family: &quot;Microsoft =
Yahei&quot;; color: rgb(242, 108, 79); background-color: rgb(245, 245, 245)=
; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: =
normal; font-variant-alternates: normal; font-variant-position: normal; fon=
t-variant-emoji: normal; vertical-align: baseline; white-space-collapse: pr=
eserve;">New</span></a></p><br /><br /><p dir=3D"rtl" style=3D"line-height:=
 1.2; margin-top: 4pt; margin-bottom: 0pt;"><span style=3D"font-size: 13.5p=
t; font-family: &quot;Microsoft Yahei&quot;; color: rgb(0, 0, 0); backgroun=
d-color: rgb(245, 245, 245); font-weight: 700; font-variant-numeric: normal=
; font-variant-east-asian: normal; font-variant-alternates: normal; font-va=
riant-position: normal; font-variant-emoji: normal; vertical-align: baselin=
e; white-space-collapse: preserve;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=8A=D9=83(=D8=B5=D9=8A=D8=AF=D9=84=D9=8A=D8=A9)-</span><span style=3D"font-=
size: 16pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); font-weigh=
t: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font=
-variant-alternates: normal; font-variant-position: normal; font-variant-em=
oji: normal; vertical-align: baseline; white-space-collapse: preserve;">053=
7466539 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6</span></p><p dir=3D"rtl" style=
=3D"line-height: 1.2; margin-top: 2pt; margin-bottom: 0pt;"><a href=3D"http=
s://forum.dji.com/forum.php?mod=3Dredirect&amp;tid=3D337567&amp;goto=3Dlast=
post#lastpost"><span style=3D"font-size: 9pt; font-family: &quot;Microsoft =
Yahei&quot;; color: rgb(242, 108, 79); background-color: rgb(245, 245, 245)=
; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: =
normal; font-variant-alternates: normal; font-variant-position: normal; fon=
t-variant-emoji: normal; vertical-align: baseline; white-space-collapse: pr=
eserve;">New</span></a></p><p dir=3D"rtl" style=3D"line-height: 1.38; margi=
n-top: 0pt; margin-bottom: 0pt;"><span style=3D"font-size: 31.5pt; font-fam=
ily: &quot;Microsoft Yahei&quot;; color: rgb(68, 68, 68); font-weight: 700;=
 font-variant-numeric: normal; font-variant-east-asian: normal; font-varian=
t-alternates: normal; font-variant-position: normal; font-variant-emoji: no=
rmal; vertical-align: baseline; white-space-collapse: preserve;">=D9=85=D9=
=83=D8=A9 (=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83=C2=AE)=D9=85=D9=
=8A=D8=B2=D9=88=D8=A8=D8=B1=D8=B3=D8=AA=D9=88=D9=84 - </span><span style=3D=
"font-size: 16pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); font=
-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal=
; font-variant-alternates: normal; font-variant-position: normal; font-vari=
ant-emoji: normal; vertical-align: baseline; white-space-collapse: preserve=
;">0537466539=C2=A0</span></p><br /><p dir=3D"rtl" style=3D"line-height: 1.=
2; margin-top: 4pt; margin-bottom: 0pt;"><span style=3D"font-size: 13.5pt; =
font-family: &quot;Microsoft Yahei&quot;; color: rgb(0, 0, 0); background-c=
olor: rgb(245, 245, 245); font-weight: 700; font-variant-numeric: normal; f=
ont-variant-east-asian: normal; font-variant-alternates: normal; font-varia=
nt-position: normal; font-variant-emoji: normal; vertical-align: baseline; =
white-space-collapse: preserve;">=C2=AE=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=8A=D9=83(=D8=B5=D9=8A=D8=AF=D9=84=D9=8A=D8=A9)-</span><span style=3D"fo=
nt-size: 16pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); font-we=
ight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; f=
ont-variant-alternates: normal; font-variant-position: normal; font-variant=
-emoji: normal; vertical-align: baseline; white-space-collapse: preserve;">=
0537466539 =D8=AC=D8=AF=D8=A9</span></p><br /><br /><div class=3D"gmail_quo=
te"><div dir=3D"auto" class=3D"gmail_attr">=D9=81=D9=8A Friday, September 5=
, 2025 =D9=81=D9=8A =D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=
=D8=A9 10:01:01=E2=80=AFAM UTC-7=D8=8C =D9=83=D8=AA=D8=A8 =D8=AD=D8=A8=D9=
=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =E2=80=93 =D9=86=D8=B3=
=D8=A8=D8=A9 =D9=86=D8=AC=D8=A7=D8=AD 95=D9=AA =D8=B1=D8=B3=D8=A7=D9=84=D8=
=A9 =D9=86=D8=B5=D9=87=D8=A7:<br/></div><blockquote class=3D"gmail_quote" s=
tyle=3D"margin: 0 0 0 0.8ex; border-right: 1px solid rgb(204, 204, 204); pa=
dding-right: 1ex;"><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;=
margin-bottom:0pt"><span style=3D"font-size:15pt;font-family:Arial,sans-ser=
if;color:rgb(0,0,0);font-weight:700;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"=
>=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83(=D8=B5=D9=8A=D8=AF=D9=84=
=D9=8A=D8=A9)-0537466539// =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6</span></p><br><b=
r><p dir=3D"rtl" style=3D"line-height:1.2;margin-top:4pt;margin-bottom:0pt"=
><span style=3D"font-size:13.5pt;font-family:&quot;Microsoft Yahei&quot;;co=
lor:rgb(0,0,0);background-color:rgb(245,245,245);font-weight:700;font-varia=
nt-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:no=
rmal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=
=83 (=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=C2=AE)</span><span style=3D"font-=
size:16pt;font-family:Arial,sans-serif;color:rgb(0,0,0);font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">0537466539 =D8=B3=D8=B9=D9=88=D8=AF=D9=
=8A=D8=A9</span></p><p dir=3D"rtl" style=3D"line-height:1.2;margin-top:2pt;=
margin-bottom:0pt"><a href=3D"https://forum.dji.com/forum.php?mod=3Dredirec=
t&amp;tid=3D337565&amp;goto=3Dlastpost#lastpost" target=3D"_blank" rel=3D"n=
ofollow" data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar-SA&amp;=
q=3Dhttps://forum.dji.com/forum.php?mod%3Dredirect%26tid%3D337565%26goto%3D=
lastpost%23lastpost&amp;source=3Dgmail&amp;ust=3D1757178062451000&amp;usg=
=3DAOvVaw1oJx3whsfmB-QLKlaTe0Rn"><span style=3D"font-size:9pt;font-family:&=
quot;Microsoft Yahei&quot;;color:rgb(242,108,79);background-color:rgb(245,2=
45,245);font-weight:700;font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;vertical-align:baseline">New</span><=
/a></p><br><br><p dir=3D"rtl" style=3D"line-height:1.2;margin-top:4pt;margi=
n-bottom:0pt"><span style=3D"font-size:13.5pt;font-family:&quot;Microsoft Y=
ahei&quot;;color:rgb(242,108,79);background-color:rgb(245,245,245);font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=8A=D9=83(=D8=B3=D9=84=D8=B7=D9=86=D8=A9 =D8=B9=D9=85=D8=A7=D9=
=86=C2=AE)- </span><span style=3D"font-size:16pt;font-family:Arial,sans-ser=
if;color:rgb(0,0,0);font-weight:700;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"=
>0537466539=C2=A0</span></p><p dir=3D"rtl" style=3D"line-height:1.2;margin-=
top:2pt;margin-bottom:0pt"><a href=3D"https://forum.dji.com/forum.php?mod=
=3Dredirect&amp;tid=3D337566&amp;goto=3Dlastpost#lastpost" target=3D"_blank=
" rel=3D"nofollow" data-saferedirecturl=3D"https://www.google.com/url?hl=3D=
ar-SA&amp;q=3Dhttps://forum.dji.com/forum.php?mod%3Dredirect%26tid%3D337566=
%26goto%3Dlastpost%23lastpost&amp;source=3Dgmail&amp;ust=3D1757178062451000=
&amp;usg=3DAOvVaw2DwibyC4hQp6pqfaF1RTix"><span style=3D"font-size:9pt;font-=
family:&quot;Microsoft Yahei&quot;;color:rgb(242,108,79);background-color:r=
gb(245,245,245);font-weight:700;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">New=
</span></a></p><br><br><p dir=3D"rtl" style=3D"line-height:1.2;margin-top:4=
pt;margin-bottom:0pt"><span style=3D"font-size:13.5pt;font-family:&quot;Mic=
rosoft Yahei&quot;;color:rgb(0,0,0);background-color:rgb(245,245,245);font-=
weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=8A=D9=83(=D8=B5=D9=8A=D8=AF=D9=84=D9=8A=D8=A9)-</span><span=
 style=3D"font-size:16pt;font-family:Arial,sans-serif;color:rgb(0,0,0);font=
-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline">0537466539 =D8=A7=D9=84=
=D8=B1=D9=8A=D8=A7=D8=B6</span></p><p dir=3D"rtl" style=3D"line-height:1.2;=
margin-top:2pt;margin-bottom:0pt"><a href=3D"https://forum.dji.com/forum.ph=
p?mod=3Dredirect&amp;tid=3D337567&amp;goto=3Dlastpost#lastpost" target=3D"_=
blank" rel=3D"nofollow" data-saferedirecturl=3D"https://www.google.com/url?=
hl=3Dar-SA&amp;q=3Dhttps://forum.dji.com/forum.php?mod%3Dredirect%26tid%3D3=
37567%26goto%3Dlastpost%23lastpost&amp;source=3Dgmail&amp;ust=3D17571780624=
51000&amp;usg=3DAOvVaw2uxtFMhdJGaXaNDdWL4X45"><span style=3D"font-size:9pt;=
font-family:&quot;Microsoft Yahei&quot;;color:rgb(242,108,79);background-co=
lor:rgb(245,245,245);font-weight:700;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
">New</span></a></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt=
;margin-bottom:0pt"><span style=3D"font-size:31.5pt;font-family:&quot;Micro=
soft Yahei&quot;;color:rgb(68,68,68);font-weight:700;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline">=D9=85=D9=83=D8=A9 (=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=8A=D9=83=C2=AE)=D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D8=B3=D8=AA=D9=88=
=D9=84 - </span><span style=3D"font-size:16pt;font-family:Arial,sans-serif;=
color:rgb(0,0,0);font-weight:700;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline">05=
37466539=C2=A0</span></p><br><p dir=3D"rtl" style=3D"line-height:1.2;margin=
-top:4pt;margin-bottom:0pt"><span style=3D"font-size:13.5pt;font-family:&qu=
ot;Microsoft Yahei&quot;;color:rgb(0,0,0);background-color:rgb(245,245,245)=
;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline">=C2=AE=D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83(=D8=B5=D9=8A=D8=AF=D9=84=D9=8A=D8=A9)-=
</span><span style=3D"font-size:16pt;font-family:Arial,sans-serif;color:rgb=
(0,0,0);font-weight:700;font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;vertical-align:baseline">0537466539 =
=D8=AC=D8=AF=D8=A9</span></p><br><br><div class=3D"gmail_quote"><div dir=3D=
"auto" class=3D"gmail_attr">=D9=81=D9=8A Sunday, August 17, 2025 =D9=81=D9=
=8A =D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=D8=A9 1:19:29=
=E2=80=AFAM UTC-7=D8=8C =D9=83=D8=AA=D8=A8 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =E2=80=93 =D9=86=D8=B3=D8=A8=D8=A9 =D9=
=86=D8=AC=D8=A7=D8=AD 95=D9=AA =D8=B1=D8=B3=D8=A7=D9=84=D8=A9 =D9=86=D8=B5=
=D9=87=D8=A7:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0 =
0 0 0.8ex;border-right:1px solid rgb(204,204,204);padding-right:1ex"><p dir=
=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt"><spa=
n style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);bac=
kground-color:transparent;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=
=A7=D8=B6 0537466539 #=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =D9=
=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=A2=D9=85=D9=86 =D9=
=85=D8=B9 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 | | =D8=A7=D9=84=D8=
=B1=D9=8A=D8=A7=D8=B6 =D8=AC=D8=AF=D8=A9 =D9=85=D9=83=D8=A9 =D8=A7=D9=84=D8=
=AF=D9=85=D8=A7=D9=85</span></p><p dir=3D"rtl" style=3D"line-height:1.38;ma=
rgin-top:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-family=
:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline">=D8=A7=D9=83=D8=AA=D8=B4=D9=81=D9=8A =D9=85=D8=
=B9 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=D8=8C =D8=A7=D9=84=D9=88=
=D9=83=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A =D9=84=D8=AD=D8=A8=
=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=
=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D9=83=D9=8A=D9=81=D9=8A=
=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=B7=D8=A8=
=D9=8A =D8=A7=D9=84=D8=A2=D9=85=D9=86 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=
=D8=A7=D9=85 </span><span style=3D"font-size:11pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 2=
00 (Misoprostol)</span><span style=3D"font-size:11pt;font-family:Arial,sans=
-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline"> =D8=A8=D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A =
=D9=88=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9. =D8=AA=D9=88=
=D8=B5=D9=8A=D9=84 =D8=B3=D8=B1=D9=8A=D8=B9 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=
=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =
=D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85 =D9=88=D8=A8=D8=A7=D9=82=D9=8A =D8=A7=
=D9=84=D9=85=D8=AF=D9=86. =F0=9F=93=9E 0537466539</span></p><p dir=3D"rtl" =
style=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt"><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">=D9=81=D9=8A =D8=
=A7=D9=84=D8=B3=D9=86=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=A3=D8=AE=D9=8A=D8=
=B1=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD=D8=AA</span><a href=3D"https://ksa=
cytotec.com/" rel=3D"nofollow" target=3D"_blank" data-saferedirecturl=3D"ht=
tps://www.google.com/url?hl=3Dar-SA&amp;q=3Dhttps://ksacytotec.com/&amp;sou=
rce=3Dgmail&amp;ust=3D1757178062451000&amp;usg=3DAOvVaw3jiACCkbFv2gjXD1ze1F=
3H"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,=
0,0);background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"> =
</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb=
(17,85,204);background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;text-decoration-lin=
e:underline;vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 </span><span =
style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(17,85,204);b=
ackground-color:transparent;font-weight:700;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;text-decoration-=
line:underline;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83</span></a><span style=3D"font-size:11pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline"> (Misoprostol)</span><span style=3D"font-siz=
e:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:trans=
parent;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;vertical-align:baseline"> =D8=AE=D9=8A=D8=A7=D8=B1=D9=
=8B=D8=A7 =D8=B7=D8=A8=D9=8A=D9=8B=D8=A7 =D9=85=D8=B9=D8=B1=D9=88=D9=81=D9=
=8B=D8=A7 =D9=88=D9=81=D8=B9=D9=91=D8=A7=D9=84=D9=8B=D8=A7 =D9=84=D8=A5=D9=
=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=
=A8=D9=83=D8=B1 =D8=A8=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A2=D9=85=D9=86=D8=
=A9 =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D9=85=D8=AE=D8=AA=D8=
=B5=D9=8A=D9=86. =D9=88=D9=85=D8=B9 =D8=A7=D9=86=D8=AA=D8=B4=D8=A7=D8=B1 =
=D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=AC=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D9=82=
=D9=84=D8=AF=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD =D9=85=D9=86 =D8=A7=D9=84=
=D8=B6=D8=B1=D9=88=D8=B1=D9=8A =D8=A7=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=
=D9=84=D9=89 =D8=A7=D9=84=D8=AF=D9=88=D8=A7=D8=A1 =D9=85=D9=86 =D9=85=D8=B5=
=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82 =D9=88=D9=85=D8=B9=D8=AA=D9=85=
=D8=AF.</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;co=
lor:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline"><br></span><span style=3D"font-size:11pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=
</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb=
(0,0,0);background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
">=D8=8C =D8=A8=D8=B5=D9=81=D8=AA=D9=87=D8=A7 =D8=A7=D9=84=D9=88=D9=83=D9=
=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A =D9=84=D8=AD=D8=A8=D9=88=D8=
=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=
=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AA=D9=82=D8=AF=D9=85 =D9=84=D9=
=83=D9=90 =D9=85=D9=86=D8=AA=D8=AC=D9=8B=D8=A7 =D8=A3=D8=B5=D9=84=D9=8A=D9=
=8B=D8=A7 =D8=A8=D8=AC=D9=88=D8=AF=D8=A9 =D9=85=D8=B6=D9=85=D9=88=D9=86=D8=
=A9=D8=8C =D9=85=D8=B9 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=B7=D8=
=A8=D9=8A=D8=A9 =D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=88=D8=B3=D8=B1=D9=
=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=
=B9=D8=A7=D9=85=D9=84 =D9=88=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84.</sp=
an></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-botto=
m:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-to=
p:14pt;margin-bottom:4pt"><span style=3D"font-size:13pt;font-family:Arial,s=
ans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">=D9=85=D8=A7 =D9=87=D9=88 =D8=AF=D9=88=
=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=D8=9F</span></span>=
<p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt=
"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,=
0);background-color:transparent;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 (=D8=A7=D9=84=D9=85=D8=A7=D8=AF=D8=
=A9 =D8=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84=D8=A9 </span><span style=3D"font-s=
ize:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tra=
nsparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=85=D9=
=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=88=D9=84</span><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">) =D8=AF=D9=88=
=D8=A7=D8=A1 =D9=85=D9=8F=D8=B9=D8=AA=D9=85=D8=AF =D9=81=D9=8A =D8=A7=D9=84=
=D9=85=D8=AC=D8=A7=D9=84 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=8C =D9=88=D9=8A=
=D9=8F=D8=B3=D8=AA=D8=AE=D8=AF=D9=85 =D8=A8=D8=AC=D8=B1=D8=B9=D8=A7=D8=AA =
=D8=AF=D9=82=D9=8A=D9=82=D8=A9 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=
=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1=D8=8C =D9=88=
=D8=B9=D9=84=D8=A7=D8=AC =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=B7=D8=A8=D9=8A=
=D8=A9 =D8=A3=D8=AE=D8=B1=D9=89 =D9=85=D8=AB=D9=84 =D9=82=D8=B1=D8=AD=D8=A9=
 =D8=A7=D9=84=D9=85=D8=B9=D8=AF=D8=A9. =D8=B9=D9=86=D8=AF =D8=A7=D8=B3=D8=
=AA=D8=AE=D8=AF=D8=A7=D9=85=D9=87 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=
=B6=D8=8C =D9=8A=D8=B9=D9=85=D9=84 =D8=B9=D9=84=D9=89 =D8=AA=D8=AD=D9=81=D9=
=8A=D8=B2 =D8=AA=D9=82=D9=84=D8=B5=D8=A7=D8=AA =D8=A7=D9=84=D8=B1=D8=AD=D9=
=85 =D9=88=D8=A5=D9=81=D8=B1=D8=A7=D8=BA =D9=85=D8=AD=D8=AA=D9=88=D9=8A=D8=
=A7=D8=AA=D9=87 =D8=AE=D9=84=D8=A7=D9=84 =D9=81=D8=AA=D8=B1=D8=A9 =D9=82=D8=
=B5=D9=8A=D8=B1=D8=A9=D8=8C =D9=85=D9=85=D8=A7 =D9=8A=D8=AC=D8=B9=D9=84=D9=
=87 =D8=AE=D9=8A=D8=A7=D8=B1=D9=8B=D8=A7 =D9=81=D8=B9=D8=A7=D9=84=D9=8B=D8=
=A7 =D9=88=D8=A2=D9=85=D9=86=D9=8B=D8=A7 =D8=B9=D9=86=D8=AF =D8=A5=D8=B4=D8=
=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A=D8=A8 =D9=85=D8=AE=D8=AA=D8=B5.</span></=
p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt=
"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-top:14p=
t;margin-bottom:4pt"><span style=3D"font-size:13pt;font-family:Arial,sans-s=
erif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:=
normal;vertical-align:baseline">=D8=A3=D9=87=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=
=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=D9=84=D9=89 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=
=D9=82</span></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12p=
t;margin-bottom:12pt"><span style=3D"font-size:11pt;font-family:Arial,sans-=
serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=
=A9=D8=8C =D8=AA=D8=AA=D9=88=D8=A7=D8=AC=D8=AF =D8=A7=D9=84=D9=83=D8=AB=D9=
=8A=D8=B1 =D9=85=D9=86 =D8=A7=D9=84=D9=82=D9=86=D9=88=D8=A7=D8=AA =D8=BA=D9=
=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=88=D8=AB=D9=88=D9=82=D8=A9 =D8=A7=D9=84=D8=
=AA=D9=8A =D8=AA=D8=A8=D9=8A=D8=B9 =D9=85=D9=86=D8=AA=D8=AC=D8=A7=D8=AA =D9=
=85=D8=AC=D9=87=D9=88=D9=84=D8=A9 =D8=A7=D9=84=D9=85=D8=B5=D8=AF=D8=B1 =D9=
=82=D8=AF =D8=AA=D8=A4=D8=AF=D9=8A =D8=A5=D9=84=D9=89 =D9=85=D8=AE=D8=A7=D8=
=B7=D8=B1 =D8=B5=D8=AD=D9=8A=D8=A9 =D8=AC=D8=B3=D9=8A=D9=85=D8=A9.</span><s=
pan style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline"><br></s=
pan><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,=
0,0);background-color:transparent;font-weight:700;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span><span sty=
le=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgrou=
nd-color:transparent;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline"> =D8=AA=D8=B6=
=D9=85=D9=86 =D9=84=D9=83:</span><span style=3D"font-size:11pt;font-family:=
Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline"><br></span><span style=3D"font-size:11pt;font-f=
amily:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline">=E2=9C=94=EF=B8=8F </span><span style=3D"=
font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-col=
or:transparent;font-weight:700;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=
=B5=D9=84=D9=8A=D8=A9 100%</span><span style=3D"font-size:11pt;font-family:=
Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:=
700;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant=
-alternates:normal;vertical-align:baseline"><br></span><span style=3D"font-=
size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline">=E2=9C=94=EF=B8=8F </span=
><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0=
);background-color:transparent;font-weight:700;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline">=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE =D8=B5=D9=84=D8=A7=D8=AD=D9=8A=
=D8=A9 =D8=AD=D8=AF=D9=8A=D8=AB</span><span style=3D"font-size:11pt;font-fa=
mily:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-we=
ight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline"><br></span><span style=3D"=
font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">=E2=9C=94=EF=B8=8F <=
/span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(=
0,0,0);background-color:transparent;font-weight:700;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline">=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF=D8=A7=D8=AA =D8=B7=D8=A8=D9=
=8A=D8=A9 =D8=AF=D9=82=D9=8A=D9=82=D8=A9 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=
=AE=D8=AF=D8=A7=D9=85</span><span style=3D"font-size:11pt;font-family:Arial=
,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;vertical-align:baseline"><br></span><span style=3D"font-size:=
11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transpa=
rent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline">=E2=9C=94=EF=B8=8F </span><spa=
n style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);bac=
kground-color:transparent;font-weight:700;font-variant-numeric:normal;font-=
variant-east-asian:normal;font-variant-alternates:normal;vertical-align:bas=
eline">=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=81=D9=8A=
 =D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84</span><span style=3D"font-size:=
11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transpa=
rent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline"><br></span><sp=
an style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);ba=
ckground-color:transparent;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline">=E2=9C=
=94=EF=B8=8F </span><span style=3D"font-size:11pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline">=D8=AF=D8=B9=D9=85 =D9=88=D8=A7=D8=B3=D8=AA=
=D8=B4=D8=A7=D8=B1=D8=A9 =D8=B9=D9=84=D9=89 =D9=85=D8=AF=D8=A7=D8=B1 =D8=A7=
=D9=84=D8=B3=D8=A7=D8=B9=D8=A9</span></p><p dir=3D"rtl" style=3D"line-heigh=
t:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" s=
tyle=3D"line-height:1.38;margin-top:14pt;margin-bottom:4pt"><span style=3D"=
font-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-col=
or:transparent;font-weight:700;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=
=84=D9=85=D8=A7=D8=B0=D8=A7 =D8=AA=D8=AE=D8=AA=D8=A7=D8=B1=D9=8A=D9=86 =D8=
=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=D8=9F</span></span><ul style=3D"m=
argin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:d=
isc;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline;white-space:pre">=
<p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:12pt;m=
argin-bottom:0pt" role=3D"presentation"><span style=3D"font-size:11pt;backg=
round-color:transparent;font-weight:700;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine">=D8=A7=D9=84=D8=AE=D8=A8=D8=B1=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=
=A9</span><span style=3D"font-size:11pt;background-color:transparent;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline">: =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=
=D9=86 =D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=A7=
=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=
=D8=A9 =D8=A7=D9=84=D9=86=D8=B3=D8=A7=D8=A6=D9=8A=D8=A9=D8=8C =D9=88=D8=AA=
=D9=82=D8=AF=D9=85 =D9=84=D9=83=D9=90 =D8=AF=D8=B9=D9=85=D9=8B=D8=A7 =D9=85=
=D9=87=D9=86=D9=8A=D9=8B=D8=A7 =D9=82=D8=A8=D9=84 =D9=88=D8=A3=D8=AB=D9=86=
=D8=A7=D8=A1 =D9=88=D8=A8=D8=B9=D8=AF</span><a href=3D"https://saudiersaa.c=
om/" rel=3D"nofollow" target=3D"_blank" data-saferedirecturl=3D"https://www=
.google.com/url?hl=3Dar-SA&amp;q=3Dhttps://saudiersaa.com/&amp;source=3Dgma=
il&amp;ust=3D1757178062451000&amp;usg=3DAOvVaw2Sb1R2pkMFm5um5pXvWaxX"><span=
 style=3D"font-size:11pt;color:rgb(17,85,204);background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;text-decoration-line:underline;vertical-align:baseline">=D8=
=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83</span></a><span style=3D"font-size:11pt;background-color:transpar=
ent;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant=
-alternates:normal;vertical-align:baseline">.</span><span style=3D"font-siz=
e:11pt;background-color:transparent;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"=
><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font=
-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:t=
ransparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=
=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-b=
ottom:0pt" role=3D"presentation"><span style=3D"font-size:11pt;background-c=
olor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A=
=D8=B9</span><span style=3D"font-size:11pt;background-color:transparent;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">: =D8=AA=D8=BA=D8=B7=D9=8A=D8=A9 =D9=
=84=D8=AC=D9=85=D9=8A=D8=B9 =D8=A7=D9=84=D9=85=D8=AF=D9=86 =D8=A7=D9=84=D8=
=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=A8=D9=85=D8=A7 =D9=81=D9=8A =D8=
=B0=D9=84=D9=83 </span><span style=3D"font-size:11pt;background-color:trans=
parent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=
=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=A9=
=D8=8C =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=A7=D9=84=D8=AE=D8=A8=
=D8=B1=D8=8C =D8=A7=D9=84=D8=B7=D8=A7=D8=A6=D9=81</span><span style=3D"font=
-size:11pt;background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine"> =D9=88=D8=BA=D9=8A=D8=B1=D9=87=D8=A7.</span><span style=3D"font-size:=
11pt;background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"><=
br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-s=
ize:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"=
rtl" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-botto=
m:0pt" role=3D"presentation"><span style=3D"font-size:11pt;background-color=
:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=AD=
=D9=85=D8=A7=D9=8A=D8=A9 =D8=AE=D8=B5=D9=88=D8=B5=D9=8A=D8=AA=D9=83</span><=
span style=3D"font-size:11pt;background-color:transparent;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline">: =D9=8A=D8=AA=D9=85 =D8=A7=D9=84=D8=AA=D8=BA=D9=84=
=D9=8A=D9=81 =D8=A8=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=AA=D8=B6=D9=85=D9=86 =
=D8=A7=D9=84=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=A7=D9=84=D9=83=D8=A7=D9=85=
=D9=84=D8=A9.</span><span style=3D"font-size:11pt;background-color:transpar=
ent;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant=
-alternates:normal;vertical-align:baseline"><br><br></span></p></li><li dir=
=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;font-family:Arial,san=
s-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38=
;text-align:right;margin-top:0pt;margin-bottom:12pt" role=3D"presentation">=
<span style=3D"font-size:11pt;background-color:transparent;font-weight:700;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline">=D8=A7=D9=84=D8=AA=D9=88=D9=83=D9=
=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A</span><span style=3D"font-si=
ze:11pt;background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
">: =D8=B4=D8=B1=D8=A7=D8=A1=D9=83 =D9=8A=D8=AA=D9=85 =D9=85=D8=A8=D8=A7=D8=
=B4=D8=B1=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B5=D8=AF=D8=B1 =D8=A7=D9=
=84=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=8C =D8=A8=D8=B9=D9=8A=D8=AF=D9=8B=D8=
=A7 =D8=B9=D9=86 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1.</span><span st=
yle=3D"font-size:11pt;background-color:transparent;font-variant-numeric:nor=
mal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-=
align:baseline"><br><br></span></p></li></ul><p dir=3D"rtl" style=3D"line-h=
eight:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rt=
l" style=3D"line-height:1.38;margin-top:14pt;margin-bottom:4pt"><span style=
=3D"font-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-weight:700;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=B7=D9=84=D8=A8 =D8=AD=D8=A8=D9=88=D8=A8 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=86 =D8=AF. =D9=86=D9=
=8A=D8=B1=D9=85=D9=8A=D9=86</span></span><ol style=3D"margin-top:0px;margin=
-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:decimal;font-size:11p=
t;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparen=
t;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-a=
lternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" st=
yle=3D"line-height:1.38;text-align:right;margin-top:12pt;margin-bottom:0pt"=
 role=3D"presentation"><span style=3D"font-size:11pt;background-color:trans=
parent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=
=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D8=B9=D8=A8=D8=B1 =D9=88=D8=A7=D8=AA=D8=B3=
=D8=A7=D8=A8</span><span style=3D"font-size:11pt;background-color:transpare=
nt;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline"> =D8=B9=D9=84=D9=89 =D8=A7=D9=84=
=D8=B1=D9=82=D9=85: </span><span style=3D"font-size:11pt;background-color:t=
ransparent;font-weight:700;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline">=F0=9F=
=93=9E 0537466539</span><span style=3D"font-size:11pt;background-color:tran=
sparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;vertical-align:baseline"><br><br></s=
pan></p></li><li dir=3D"rtl" style=3D"list-style-type:decimal;font-size:11p=
t;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparen=
t;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-a=
lternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" st=
yle=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt" =
role=3D"presentation"><span style=3D"font-size:11pt;background-color:transp=
arent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">=D8=B4=D8=B1=D8=AD =D8=A7=D9=
=84=D8=AD=D8=A7=D9=84=D8=A9 =D8=A7=D9=84=D8=B5=D8=AD=D9=8A=D8=A9 =D9=88=D9=
=81=D8=AA=D8=B1=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=84.</span><span style=3D"=
font-size:11pt;background-color:transparent;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:d=
ecimal;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgro=
und-color:transparent;font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;vertical-align:baseline;white-space:pr=
e"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:0pt=
;margin-bottom:0pt" role=3D"presentation"><span style=3D"font-size:11pt;bac=
kground-color:transparent;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=D8=
=B3=D8=AA=D9=84=D8=A7=D9=85 =D8=A7=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF=D8=
=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D8=
=A7=D8=B3=D8=A8=D8=A9 =D9=88=D8=A7=D9=84=D8=AC=D8=B1=D8=B9=D8=A9 =D8=A7=D9=
=84=D9=85=D9=88=D8=B5=D9=89 =D8=A8=D9=87=D8=A7.</span><span style=3D"font-s=
ize:11pt;background-color:transparent;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;vertical-align:baselin=
e"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:decimal=
;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-co=
lor:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;=
font-variant-alternates:normal;vertical-align:baseline;white-space:pre"><p =
dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margi=
n-bottom:12pt" role=3D"presentation"><span style=3D"font-size:11pt;backgrou=
nd-color:transparent;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=D8=B3=
=D8=AA=D9=84=D8=A7=D9=85 =D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=AE=D9=84=
=D8=A7=D9=84 =D9=81=D8=AA=D8=B1=D8=A9 =D9=82=D8=B5=D9=8A=D8=B1=D8=A9 =D8=B9=
=D8=A8=D8=B1 =D8=AE=D8=AF=D9=85=D8=A9 =D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A2=
=D9=85=D9=86=D8=A9 =D9=88=D8=B3=D8=B1=D9=8A=D8=A9.</span><span style=3D"fon=
t-size:11pt;background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line"><br><br></span></p></li></ol><p dir=3D"rtl" style=3D"line-height:1.38=
;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=
=3D"line-height:1.38;margin-top:14pt;margin-bottom:4pt"><span style=3D"font=
-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:t=
ransparent;font-weight:700;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=AA=
=D9=86=D8=A8=D9=8A=D9=87 =D8=B7=D8=A8=D9=8A =D9=85=D9=87=D9=85</span></span=
><ul style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"li=
st-style-type:disc;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,=
0,0);background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline;wh=
ite-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;ma=
rgin-top:12pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"font-=
size:11pt;background-color:transparent;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne">=D9=8A=D8=AC=D8=A8 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=82=D8=B7 =D8=AA=D8=AD=D8=AA =D8=
=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A =D9=85=D8=AE=D8=AA=D8=B5.</s=
pan><span style=3D"font-size:11pt;background-color:transparent;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=
=3D"list-style-type:disc;font-size:11pt;font-family:Arial,sans-serif;color:=
rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:ri=
ght;margin-top:0pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"=
font-size:11pt;background-color:transparent;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline">=D9=84=D8=A7 =D9=8A=D9=8F=D9=86=D8=B5=D8=AD =D8=A8=D8=A7=D8=B3=D8=
=AA=D8=AE=D8=AF=D8=A7=D9=85=D9=87 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=
=AA =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=D8=A3=D8=AE=D8=
=B1.</span><span style=3D"font-size:11pt;background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" =
style=3D"list-style-type:disc;font-size:11pt;font-family:Arial,sans-serif;c=
olor:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-ali=
gn:right;margin-top:0pt;margin-bottom:12pt" role=3D"presentation"><span sty=
le=3D"font-size:11pt;background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline">=D9=81=D9=8A =D8=AD=D8=A7=D9=84 =D9=88=D8=AC=D9=88=D8=AF =D8=
=A3=D9=85=D8=B1=D8=A7=D8=B6 =D9=85=D8=B2=D9=85=D9=86=D8=A9 =D8=A3=D9=88 =D8=
=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=AE=D8=A7=D8=B5=D8=A9=D8=8C =D9=8A=D8=AC=D8=
=A8 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=
=8A=D8=A8 =D9=82=D8=A8=D9=84 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=
=A7=D9=85.</span><span style=3D"font-size:11pt;background-color:transparent=
;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-al=
ternates:normal;vertical-align:baseline"><br><br></span></p></li></ul><p di=
r=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><=
hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-top:14pt;margi=
n-bottom:4pt"><span style=3D"font-size:13pt;font-family:Arial,sans-serif;co=
lor:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline">=D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=A5=D8=B6=D8=A7=
=D9=81=D9=8A=D8=A9 =D9=85=D9=86 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=
=86</span></span><ul style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"=
rtl" style=3D"list-style-type:disc;font-size:11pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;tex=
t-align:right;margin-top:12pt;margin-bottom:0pt" role=3D"presentation"><spa=
n style=3D"font-size:11pt;background-color:transparent;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =D8=A7=D9=84=D8=AD=
=D8=A7=D9=84=D8=A9 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=
=D8=AF=D8=A7=D9=85.</span><span style=3D"font-size:11pt;background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline"><br><br></span></p></li><=
li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;font-family:Ari=
al,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-heigh=
t:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt" role=3D"presentat=
ion"><span style=3D"font-size:11pt;background-color:transparent;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline">=D8=AA=D9=88=D9=81=D9=8A=D8=B1 =D9=85=D8=B9=D9=
=84=D9=88=D9=85=D8=A7=D8=AA =D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=A2=D8=AB=D8=
=A7=D8=B1 =D8=A7=D9=84=D8=AC=D8=A7=D9=86=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D8=
=B7=D8=A8=D9=8A=D8=B9=D9=8A=D8=A9 =D9=88=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=
=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=85=D8=B9=D9=87=D8=A7.</span><sp=
an style=3D"font-size:11pt;background-color:transparent;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-=
style-type:disc;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0=
);background-color:transparent;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;font-variant-alternates:normal;vertical-align:baseline;white=
-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margi=
n-top:0pt;margin-bottom:12pt" role=3D"presentation"><span style=3D"font-siz=
e:11pt;background-color:transparent;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"=
>=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF =D8=A7=D9=84=D9=85=D8=B1=D9=8A=D8=B6=D8=A9 =
=D8=A5=D9=84=D9=89 =D8=A3=D9=81=D8=B6=D9=84 =D9=85=D9=85=D8=A7=D8=B1=D8=B3=
=D8=A7=D8=AA =D8=A7=D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=A9 =D8=A7=D9=84=D8=B7=
=D8=A8=D9=8A=D8=A9.</span><span style=3D"font-size:11pt;background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline"><br><br></span></p></li><=
/ul><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0=
pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-top:1=
4pt;margin-bottom:4pt"><span style=3D"font-size:13pt;font-family:Arial,sans=
-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline">=D8=AE=D9=84=D8=A7=D8=B5=D8=A9</span></sp=
an><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margin-bottom:1=
2pt"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0=
,0,0);background-color:transparent;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=A7=D8=AE=D8=AA=D9=8A=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=D8=B5=D8=AF=D8=B1 =
=D8=A7=D9=84=D9=85=D9=88=D8=AB=D9=88=D9=82 =D8=B9=D9=86=D8=AF</span><a href=
=3D"https://groups.google.com/a/chromium.org/g/security-dev/c/rhrPpivCQGM/m=
/XihUBiSLAAAJ" rel=3D"nofollow" target=3D"_blank" data-saferedirecturl=3D"h=
ttps://www.google.com/url?hl=3Dar-SA&amp;q=3Dhttps://groups.google.com/a/ch=
romium.org/g/security-dev/c/rhrPpivCQGM/m/XihUBiSLAAAJ&amp;source=3Dgmail&a=
mp;ust=3D1757178062451000&amp;usg=3DAOvVaw2Qh_yVknCnw89KLSECzbpZ"><span sty=
le=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgrou=
nd-color:transparent;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline"> </span><span =
style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(17,85,204);b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;text-decoration-line:underline;v=
ertical-align:baseline">=D8=B4=D8=B1=D8=A7=D8=A1 </span><span style=3D"font=
-size:11pt;font-family:Arial,sans-serif;color:rgb(17,85,204);background-col=
or:transparent;font-weight:700;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;font-variant-alternates:normal;text-decoration-line:underlin=
e;vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size:11pt;font-family:A=
rial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-=
numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norma=
l;vertical-align:baseline"> =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=
=AF=D9=8A=D8=A9 =D9=87=D9=88 =D8=A7=D9=84=D8=B6=D9=85=D8=A7=D9=86 =D8=A7=D9=
=84=D9=88=D8=AD=D9=8A=D8=AF =D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=AA=D9=83=D9=
=90.</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line"><br></span><span style=3D"font-size:11pt;font-family:Arial,sans-serif=
;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline">=D9=85=D8=B9 </span><span style=3D"font-size:11pt;font-family:A=
rial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:7=
00;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=
=D9=8A=D9=86</span><span style=3D"font-size:11pt;font-family:Arial,sans-ser=
if;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-al=
ign:baseline">=D8=8C =D8=B3=D8=AA=D8=AD=D8=B5=D9=84=D9=8A=D9=86 =D8=B9=D9=
=84=D9=89 =D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=AC =D8=A7=D9=84=D8=A3=D8=B5=D9=
=84=D9=8A=D8=8C =D8=A7=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF =D8=A7=D9=84=D8=
=B7=D8=A8=D9=8A =D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=8C =D9=88=D8=
=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A =D8=
=A3=D9=8A=D9=86=D9=85=D8=A7 =D9=83=D9=86=D8=AA=D9=90 =D9=81=D9=8A =D8=A7=D9=
=84=D9=85=D9=85=D9=84=D9=83=D8=A9.</span></p><p dir=3D"rtl" style=3D"line-h=
eight:1.38;margin-top:12pt;margin-bottom:12pt"><span style=3D"font-size:11p=
t;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparen=
t;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-a=
lternates:normal;vertical-align:baseline">=F0=9F=93=9E =D9=84=D9=84=D8=AA=
=D9=88=D8=A7=D8=B5=D9=84 =D9=88=D8=A7=D9=84=D8=B7=D9=84=D8=A8 =D8=B9=D8=A8=
=D8=B1 =D9=88=D8=A7=D8=AA=D8=B3=D8=A7=D8=A8: </span><span style=3D"font-siz=
e:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:trans=
parent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline">0537466539</=
span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0=
,0,0);background-color:transparent;font-weight:700;font-variant-numeric:nor=
mal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-=
align:baseline"><br></span><span style=3D"font-size:11pt;font-family:Arial,=
sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;vertical-align:baseline">=D8=A7=D9=84=D9=85=D8=AF=D9=86 =D8=A7=
=D9=84=D9=85=D8=BA=D8=B7=D8=A7=D8=A9</span><span style=3D"font-size:11pt;fo=
nt-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;vertical-align:baseline">: =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=
=B6 =E2=80=93 =D8=AC=D8=AF=D8=A9 =E2=80=93 =D9=85=D9=83=D8=A9 =E2=80=93 =D8=
=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85 =E2=80=93 =D8=A7=D9=84=D8=AE=D8=A8=D8=B1 =
=E2=80=93 =D8=A7=D9=84=D8=B7=D8=A7=D8=A6=D9=81 =E2=80=93 =D8=A7=D9=84=D9=85=
=D8=AF=D9=8A=D9=86=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D9=88=D8=B1=D8=A9 =E2=80=
=93 =D8=A3=D8=A8=D9=87=D8=A7 =E2=80=93 =D8=AC=D8=A7=D8=B2=D8=A7=D9=86 =E2=
=80=93 =D8=AA=D8=A8=D9=88=D9=83.</span></p><p dir=3D"rtl" style=3D"line-hei=
ght:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl"=
 style=3D"line-height:1.38;margin-top:18pt;margin-bottom:4pt"><span style=
=3D"font-size:17pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-weight:700;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=C2=A0</span></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12p=
t;margin-bottom:12pt"><span style=3D"font-size:11pt;font-family:Arial,sans-=
serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =
=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=
=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AC=D8=AF=D8=A9=D8=8C =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=83=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=
=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=B4=
=D8=B1=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =
=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AD=D8=A8=D9=88=
=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=A5=D8=AC=
=D9=87=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A3=
=D8=B5=D9=84=D9=8A=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200=D8=
=8C Misoprostol =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D9=86=D9=87=D8=AF=D9=
=8A=D8=8C</span><a href=3D"https://ksacytotec.com/" rel=3D"nofollow" target=
=3D"_blank" data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar-SA&a=
mp;q=3Dhttps://ksacytotec.com/&amp;source=3Dgmail&amp;ust=3D175717806245100=
0&amp;usg=3DAOvVaw3jiACCkbFv2gjXD1ze1F3H"><span style=3D"font-size:11pt;fon=
t-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline"> </span><span style=3D"font-size:11pt;=
font-family:Arial,sans-serif;color:rgb(17,85,204);background-color:transpar=
ent;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant=
-alternates:normal;text-decoration-line:underline;vertical-align:baseline">=
https://ksacytotec.com/</span></a><span style=3D"font-size:11pt;font-family=
:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline"> =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=
=D8=AF=D9=8A=D8=A9=D8=8C =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=
=D8=B1=D9=85=D9=8A=D9=86 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83.</span>=
</p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0=
pt"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,=
0,0);background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=
=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D8=AC=D8=AF=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 =D9=85=D9=83=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=B4=D8=B1=D8=A7=D8=A1 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=
=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=
=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=B5=D9=84=D9=8A=
=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200=D8=8C Misoprostol =D8=
=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D9=86=D9=87=D8=AF=D9=8A=D8=8C =D8=A7=D9=
=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A =D9=81=D9=
=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AF=D9=83=D8=
=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83.</span></p><br></blockquote></div></blockquote>=
</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/26b4071e-9689-4466-8ac2-1bcfc583d2e6n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/26b4071e-9689-4466-8ac2-1bcfc583d2e6n%40googlegroups.com</a>.<br />

------=_Part_38779_1797926142.1757091673274--

------=_Part_38778_1622527695.1757091673274--
