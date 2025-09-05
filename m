Return-Path: <kasan-dev+bncBC36BFVD6MNBBT5O5TCQMGQEPGGRVKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 257F5B45F7F
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 19:01:06 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-31962614250sf3639379fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 10:01:06 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757091664; x=1757696464; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=hVvq52474gBYp6R3X2XV48Nrl95IJib+WSDbLcESoN8=;
        b=suh+VNVcMvd91AosBZGda3E+T+Mr2GKkeozKp+YqH4VR4XCK0NFJvcqYQOd+oF8tfh
         959n/cfH0gsgu5/7InTMt6VFB4oqSb5qTHiMWp3cJmpWyGClANaoTUFfACovUwaHsqhK
         0+fTje7tO9GGuOgzRpUNSf5M8/YQLMF3xxp+JRPe8ppkNUaKtE4RdYJLJ0ZZwdKOB53Y
         O+UMwf/KtDRaIUjLiyb9aTPSVwdmbDdQIQofIdeyKF7hnZKxwrx6l6bOI6A/u5Qu/I8H
         WtZZjka5b5KKTyiq3QHna/xIU94v8WSbf3pHA2SfTr7/vJd6empSO3PcSN4elapXDEpG
         AWOw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757091664; x=1757696464; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hVvq52474gBYp6R3X2XV48Nrl95IJib+WSDbLcESoN8=;
        b=eY+P5PYwuQg8Ik+CeKWwT2H5EwLshV+RAe3mrFTArIHn+GFtr1HEM8Lra4cA3T1+jK
         wLoL6cc/YRUbJg8mxmvvz/ksHbC7a4nje/mfb2daSrQIMvYxJzxPsSrY22i/YRd5N3VI
         C3rTyonLg9Oz8RHCuU3CxsKcn4pIUx+Km96i9OXniY82SOa+XnP0gpFRuPzpg21aTgKh
         lJs8VAXsaRPCBAODM2aYMBSKwdDr3RWr0pZsAZReTfiy88OUC4lXel9Hpat1GTVa5OUS
         8RhI1iITc8DI9V2Tr/6jL9B0m9UQDGXBEJ+EHpZ2yD/smAnMpSgohF+PzMsAxu47SUhn
         LVAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757091664; x=1757696464;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=hVvq52474gBYp6R3X2XV48Nrl95IJib+WSDbLcESoN8=;
        b=Y7qau4WKGhxXyNezdhgdMgpGZpRruWNgCeEW4UNvQdG8HySLgV0QYXKw0LXo6IyalG
         U1C21nqZsYDjJ/fBxmEtVNNBHb7wsQ9T+38YrofxjiiWsOoBb1WOxaddX73f3K3w3gph
         N6YonWxzlYJ6Cpol8K8GyM5oact7wiJUIlLl0AJaZbs5jkJiQtEv3ymUOqtFpKef9BRZ
         DAQdEpIH9q49/fDVYerUCQXU67p9PhE89WZ6W6CDfVluKB+ZtiTLCefA6erPcMrGEcmL
         bdSMw/khCC4jmy6+rrt63CWLUcq/E0w7LhDj1BEJF8lJ7xLHiq/z8SzQfL2FiQj+ikNB
         OMuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCVvMnbnRl6tqFgo2N/pZCLfKxoJB8+qjNZkjNnjqk1Nv6t9sVnbTB6RvNzTlVcFXDduWaiSuA==@lfdr.de
X-Gm-Message-State: AOJu0YzlZnf+Ej3uSXkKZPGAA4jkFK/HfA2V8taMc8H0ECxpWy6R2+lp
	A2h51boGnjPsRsCRYwIDQTHl3rkikX1H5Tv4plMIC78QcFBY9xrZ5l57
X-Google-Smtp-Source: AGHT+IF5MhlfSb5yz6uysx7vRT4CH8XNQ1Bseyd8VZzzU8bLI5bT0tVWQksbV7CIhmzkAYlmg0p8Hg==
X-Received: by 2002:a05:6870:6488:b0:315:9da9:aeed with SMTP id 586e51a60fabf-3196345d35emr10725912fac.43.1757091663500;
        Fri, 05 Sep 2025 10:01:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfzQjql6RnDqfWdV9o6QhkW8cx22DjpVvEDg/gM5HZMXg==
Received: by 2002:a05:6871:181:10b0:310:f792:61cc with SMTP id
 586e51a60fabf-32126ea8540ls406745fac.0.-pod-prod-05-us; Fri, 05 Sep 2025
 10:01:01 -0700 (PDT)
X-Received: by 2002:a05:6808:1907:b0:438:4312:ab9d with SMTP id 5614622812f47-4384312ad1dmr3771737b6e.45.1757091661628;
        Fri, 05 Sep 2025 10:01:01 -0700 (PDT)
Date: Fri, 5 Sep 2025 10:01:00 -0700 (PDT)
From: =?UTF-8?B?2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg4oCT?=
 =?UTF-8?B?INmG2LPYqNipINmG2KzYp9itIDk12ao=?= <hayatannas967@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <36dacae4-ca3c-47cb-90bc-f74023c8b4dfn@googlegroups.com>
In-Reply-To: <412ffb42-69a2-4d34-9ea5-6aa53dd58711n@googlegroups.com>
References: <412ffb42-69a2-4d34-9ea5-6aa53dd58711n@googlegroups.com>
Subject: =?UTF-8?B?UmU6INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNix2YrYp9i2?=
 =?UTF-8?B?IDA1Mzc0NjY1MzkgI9in2YTYs9i52YjYr9mK2Kk=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_44548_1416103113.1757091660818"
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

------=_Part_44548_1416103113.1757091660818
Content-Type: multipart/alternative; 
	boundary="----=_Part_44549_1988308951.1757091660818"

------=_Part_44549_1988308951.1757091660818
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
2KkKCgrZgdmKIFN1bmRheSwgQXVndXN0IDE3LCAyMDI1INmB2Yog2KrZhdin2YUg2KfZhNiz2KfY
udipIDE6MTk6MjnigK9BTSBVVEMtN9iMINmD2KrYqCDYrdio2YjYqCAK2LPYp9mK2KrZiNiq2YMg
4oCTINmG2LPYqNipINmG2KzYp9itIDk12aog2LHYs9in2YTYqSDZhti12YfYpzoKCj4g2LPYp9mK
2KrZiNiq2YMg2YHZiiDYp9mE2LHZitin2LYgMDUzNzQ2NjUzOSAj2KfZhNiz2LnZiNiv2YrYqSDZ
hNmE2KXYrNmH2KfYtiDYp9mE2KLZhdmGINmF2Lkg2K8uINmG2YrYsdmF2YrZhiB8IHwgCj4g2KfZ
hNix2YrYp9i2INis2K/YqSDZhdmD2Kkg2KfZhNiv2YXYp9mFCj4KPiDYp9mD2KrYtNmB2Yog2YXY
uSDYry4g2YbZitix2YXZitmG2Iwg2KfZhNmI2YPZitmEINin2YTYsdiz2YXZiiDZhNit2KjZiNio
INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqdiMINmD2YrZgdmK2KkgCj4g2KfZ
hNil2KzZh9in2LYg2KfZhNi32KjZiiDYp9mE2KLZhdmGINio2KfYs9iq2K7Yr9in2YUg2LPYp9mK
2KrZiNiq2YMgMjAwIChNaXNvcHJvc3RvbCkg2KjYpdi02LHYp9mBINi32KjZiiDZiNiz2LHZkdmK
2KkgCj4g2KrYp9mF2KkuINiq2YjYtdmK2YQg2LPYsdmK2Lkg2YHZiiDYp9mE2LHZitin2LbYjCDY
rNiv2KnYjCDZhdmD2KnYjCDYp9mE2K/Zhdin2YUg2YjYqNin2YLZiiDYp9mE2YXYr9mGLiDwn5Oe
IDA1Mzc0NjY1MzkKPgo+INmB2Yog2KfZhNiz2YbZiNin2Kog2KfZhNij2K7Zitix2KnYjCDYo9i1
2KjYrdiqINit2KjZiNioINiz2KfZitiq2YjYqtmDIDxodHRwczovL2tzYWN5dG90ZWMuY29tLz4g
Cj4gKE1pc29wcm9zdG9sKSDYrtmK2KfYsdmL2Kcg2LfYqNmK2YvYpyDZhdi52LHZiNmB2YvYpyDZ
iNmB2LnZkdin2YTZi9inINmE2KXZhtmH2KfYoSDYp9mE2K3ZhdmEINin2YTZhdio2YPYsSDYqNi3
2LHZitmC2KkgCj4g2KLZhdmG2Kkg2KrYrdiqINil2LTYsdin2YEg2YXYrtiq2LXZitmGLiDZiNmF
2Lkg2KfZhtiq2LTYp9ixINin2YTZhdmG2KrYrNin2Kog2KfZhNmF2YLZhNiv2KnYjCDYo9i12KjY
rSDZhdmGINin2YTYttix2YjYsdmKINin2YTYrdi12YjZhCAKPiDYudmE2Ykg2KfZhNiv2YjYp9ih
INmF2YYg2YXYtdiv2LEg2YXZiNir2YjZgiDZiNmF2LnYqtmF2K8uCj4g2K8uINmG2YrYsdmF2YrZ
htiMINio2LXZgdiq2YfYpyDYp9mE2YjZg9mK2YQg2KfZhNix2LPZhdmKINmE2K3YqNmI2Kgg2LPY
p9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2KrZgtiv2YUg2YTZg9mQIAo+INmF
2YbYqtis2YvYpyDYo9i12YTZitmL2Kcg2KjYrNmI2K/YqSDZhdi22YXZiNmG2KnYjCDZhdi5INin
2LPYqti02KfYsdipINi32KjZitipINmF2KrYrti12LXYqSDZiNiz2LHZkdmK2Kkg2KrYp9mF2Kkg
2YHZiiDYp9mE2KrYudin2YXZhCAKPiDZiNin2YTYqtmI2LXZitmELgo+Cj4gLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tCj4KPiDZhdinINmH2Ygg2K/ZiNin2KEg2LPYp9mK2KrZiNiq2YPY
nwo+Cj4g2LPYp9mK2KrZiNiq2YMgKNin2YTZhdin2K/YqSDYp9mE2YHYudin2YTYqSDZhdmK2LLZ
iNio2LHZiNiz2KrZiNmEKSDYr9mI2KfYoSDZhdmP2LnYqtmF2K8g2YHZiiDYp9mE2YXYrNin2YQg
2KfZhNi32KjZitiMIAo+INmI2YrZj9iz2KrYrtiv2YUg2KjYrNix2LnYp9iqINiv2YLZitmC2Kkg
2YTYpdmG2YfYp9ihINin2YTYrdmF2YQg2KfZhNmF2KjZg9ix2Iwg2YjYudmE2KfYrCDYrdin2YTY
p9iqINi32KjZitipINij2K7YsdmJINmF2KvZhCDZgtix2K3YqSAKPiDYp9mE2YXYudiv2KkuINi5
2YbYryDYp9iz2KrYrtiv2KfZhdmHINmE2YTYpdis2YfYp9i22Iwg2YrYudmF2YQg2LnZhNmJINiq
2K3ZgdmK2LIg2KrZgtmE2LXYp9iqINin2YTYsdit2YUg2YjYpdmB2LHYp9i6INmF2K3YqtmI2YrY
p9iq2YcgCj4g2K7ZhNin2YQg2YHYqtix2Kkg2YLYtdmK2LHYqdiMINmF2YXYpyDZitis2LnZhNmH
INiu2YrYp9ix2YvYpyDZgdi52KfZhNmL2Kcg2YjYotmF2YbZi9inINi52YbYryDYpdi02LHYp9mB
INi32KjZitioINmF2K7Yqti1Lgo+Cj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4K
PiDYo9mH2YXZitipINin2YTYrdi12YjZhCDYudmE2Ykg2LPYp9mK2KrZiNiq2YMg2YXZhiDZhdi1
2K/YsSDZhdmI2KvZiNmCCj4KPiDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDYqtiq2YjYp9is2K8g
2KfZhNmD2KvZitixINmF2YYg2KfZhNmC2YbZiNin2Kog2LrZitixINin2YTZhdmI2KvZiNmC2Kkg
2KfZhNiq2Yog2KrYqNmK2Lkg2YXZhtiq2KzYp9iqINmF2KzZh9mI2YTYqSAKPiDYp9mE2YXYtdiv
2LEg2YLYryDYqtik2K/ZiiDYpdmE2Ykg2YXYrtin2LfYsSDYtdit2YrYqSDYrNiz2YrZhdipLgo+
INivLiDZhtmK2LHZhdmK2YYg2KrYttmF2YYg2YTZgzoKPiDinJTvuI8g2K3YqNmI2Kgg2LPYp9mK
2KrZiNiq2YMg2KPYtdmE2YrYqSAxMDAlCj4g4pyU77iPINiq2KfYsdmK2K4g2LXZhNin2K3Zitip
INit2K/ZitirCj4g4pyU77iPINil2LHYtNin2K/Yp9iqINi32KjZitipINiv2YLZitmC2Kkg2YTZ
hNin2LPYqtiu2K/Yp9mFCj4g4pyU77iPINiz2LHZkdmK2Kkg2KrYp9mF2Kkg2YHZiiDYp9mE2KrZ
iNi12YrZhAo+IOKclO+4jyDYr9i52YUg2YjYp9iz2KrYtNin2LHYqSDYudmE2Ykg2YXYr9in2LEg
2KfZhNiz2KfYudipCj4KPiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KPgo+INmE2YXY
p9iw2Kcg2KrYrtiq2KfYsdmK2YYg2K8uINmG2YrYsdmF2YrZhtifCj4gICAgCj4gICAgLSAKPiAg
ICAKPiAgICDYp9mE2K7YqNix2Kkg2KfZhNi32KjZitipOiDYry4g2YbZitix2YXZitmGINmF2KrY
rti12LXYqSDZgdmKINin2YTYp9iz2KrYtNin2LHYp9iqINin2YTYt9io2YrYqSDYp9mE2YbYs9in
2KbZitip2Iwg2YjYqtmC2K/ZhSAKPiAgICDZhNmD2ZAg2K/YudmF2YvYpyDZhdmH2YbZitmL2Kcg
2YLYqNmEINmI2KPYq9mG2KfYoSDZiNio2LnYr9in2LPYqtiu2K/Yp9mFINiz2KfZitiq2YjYqtmD
IAo+ICAgIDxodHRwczovL3NhdWRpZXJzYWEuY29tLz4uCj4gICAgCj4gICAgLSAKPiAgICAKPiAg
ICDYp9mE2KrZiNi12YrZhCDYp9mE2LPYsdmK2Lk6INiq2LrYt9mK2Kkg2YTYrNmF2YrYuSDYp9mE
2YXYr9mGINin2YTYs9i52YjYr9mK2KnYjCDYqNmF2Kcg2YHZiiDYsNmE2YMg2KfZhNix2YrYp9i2
2Iwg2KzYr9ip2IwgCj4gICAg2YXZg9ip2Iwg2KfZhNiv2YXYp9mF2Iwg2KfZhNiu2KjYsdiMINin
2YTYt9in2KbZgSDZiNi62YrYsdmH2KcuCj4gICAgCj4gICAgLSAKPiAgICAKPiAgICDYrdmF2KfZ
itipINiu2LXZiNi12YrYqtmDOiDZitiq2YUg2KfZhNiq2LrZhNmK2YEg2KjYt9ix2YrZgtipINiq
2LbZhdmGINin2YTYs9ix2ZHZitipINin2YTZg9in2YXZhNipLgo+ICAgIAo+ICAgIC0gCj4gICAg
Cj4gICAg2KfZhNiq2YjZg9mK2YQg2KfZhNix2LPZhdmKOiDYtNix2KfYodmDINmK2KrZhSDZhdio
2KfYtNix2Kkg2YXZhiDYp9mE2YXYtdiv2LEg2KfZhNmF2LnYqtmF2K/YjCDYqNi52YrYr9mL2Kcg
2LnZhiDYp9mE2YXYrtin2LfYsS4KPiAgICAKPiAgICAKPiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0KPgo+INmD2YrZgdmK2Kkg2LfZhNioINit2KjZiNioINiz2KfZitiq2YjYqtmDINmF
2YYg2K8uINmG2YrYsdmF2YrZhgo+ICAgIAo+ICAgIDEuIAo+ICAgIAo+ICAgINin2YTYqtmI2KfY
tdmEINi52KjYsSDZiNin2KrYs9in2Kgg2LnZhNmJINin2YTYsdmC2YU6IPCfk54gMDUzNzQ2NjUz
OQo+ICAgIAo+ICAgIDIuIAo+ICAgIAo+ICAgINi02LHYrSDYp9mE2K3Yp9mE2Kkg2KfZhNi12K3Z
itipINmI2YHYqtix2Kkg2KfZhNit2YXZhC4KPiAgICAKPiAgICAzLiAKPiAgICAKPiAgICDYp9iz
2KrZhNin2YUg2KfZhNil2LHYtNin2K/Yp9iqINin2YTYt9io2YrYqSDYp9mE2YXZhtin2LPYqNip
INmI2KfZhNis2LHYudipINin2YTZhdmI2LXZiSDYqNmH2KcuCj4gICAgCj4gICAgNC4gCj4gICAg
Cj4gICAg2KfYs9iq2YTYp9mFINin2YTYrdio2YjYqCDYrtmE2KfZhCDZgdiq2LHYqSDZgti12YrY
sdipINi52KjYsSDYrtiv2YXYqSDYqtmI2LXZitmEINii2YXZhtipINmI2LPYsdmK2KkuCj4gICAg
Cj4gICAgCj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4KPiDYqtmG2KjZitmHINi3
2KjZiiDZhdmH2YUKPiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINmK2KzYqCDYp9iz2KrYrtiv2KfZ
hSDYs9in2YrYqtmI2KrZgyDZgdmC2Lcg2KrYrdiqINil2LTYsdin2YEg2LfYqNmKINmF2K7Yqti1
Lgo+ICAgIAo+ICAgIC0gCj4gICAgCj4gICAg2YTYpyDZitmP2YbYtditINio2KfYs9iq2K7Yr9in
2YXZhyDZgdmKINit2KfZhNin2Kog2KfZhNit2YXZhCDYp9mE2YXYqtij2K7YsS4KPiAgICAKPiAg
ICAtIAo+ICAgIAo+ICAgINmB2Yog2K3Yp9mEINmI2KzZiNivINij2YXYsdin2LYg2YXYstmF2YbY
qSDYo9mIINit2KfZhNin2Kog2K7Yp9i12KnYjCDZitis2Kgg2KfYs9iq2LTYp9ix2Kkg2KfZhNi3
2KjZitioINmC2KjZhCAKPiAgICDYp9mE2KfYs9iq2K7Yr9in2YUuCj4gICAgCj4gICAgCj4gLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4KPiDYrtiv2YXYp9iqINil2LbYp9mB2YrYqSDZ
hdmGINivLiDZhtmK2LHZhdmK2YYKPiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINmF2KrYp9io2LnY
qSDYp9mE2K3Yp9mE2Kkg2KjYudivINin2YTYp9iz2KrYrtiv2KfZhS4KPiAgICAKPiAgICAtIAo+
ICAgIAo+ICAgINiq2YjZgdmK2LEg2YXYudmE2YjZhdin2Kog2K3ZiNmEINin2YTYotir2KfYsSDY
p9mE2KzYp9mG2KjZitipINin2YTYt9io2YrYudmK2Kkg2YjZg9mK2YHZitipINin2YTYqti52KfZ
hdmEINmF2LnZh9inLgo+ICAgIAo+ICAgIC0gCj4gICAgCj4gICAg2KXYsdi02KfYryDYp9mE2YXY
sdmK2LbYqSDYpdmE2Ykg2KPZgdi22YQg2YXZhdin2LHYs9in2Kog2KfZhNiz2YTYp9mF2Kkg2KfZ
hNi32KjZitipLgo+ICAgIAo+ICAgIAo+IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+
Cj4g2K7ZhNin2LXYqQo+Cj4g2KfYrtiq2YrYp9ixINin2YTZhdi12K/YsSDYp9mE2YXZiNir2YjZ
giDYudmG2K8g2LTYsdin2KEg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMgCj4gPGh0dHBzOi8vZ3Jv
dXBzLmdvb2dsZS5jb20vYS9jaHJvbWl1bS5vcmcvZy9zZWN1cml0eS1kZXYvYy9yaHJQcGl2Q1FH
TS9tL1hpaFVCaVNMQUFBSj4gCj4g2YHZiiDYp9mE2LPYudmI2K/ZitipINmH2Ygg2KfZhNi22YXY
p9mGINin2YTZiNit2YrYryDZhNiz2YTYp9mF2KrZg9mQLgo+INmF2Lkg2K8uINmG2YrYsdmF2YrZ
htiMINiz2KrYrdi12YTZitmGINi52YTZiSDYp9mE2YXZhtiq2Kwg2KfZhNij2LXZhNmK2Iwg2KfZ
hNil2LHYtNin2K8g2KfZhNi32KjZiiDYp9mE2YXYqtiu2LXYtdiMINmI2KfZhNiq2YjYtdmK2YQg
Cj4g2KfZhNiz2LHZiiDYo9mK2YbZhdinINmD2YbYqtmQINmB2Yog2KfZhNmF2YXZhNmD2KkuCj4K
PiDwn5OeINmE2YTYqtmI2KfYtdmEINmI2KfZhNi32YTYqCDYudio2LEg2YjYp9iq2LPYp9ioOiAw
NTM3NDY2NTM5Cj4g2KfZhNmF2K/ZhiDYp9mE2YXYuti32KfYqTog2KfZhNix2YrYp9i2IOKAkyDY
rNiv2Kkg4oCTINmF2YPYqSDigJMg2KfZhNiv2YXYp9mFIOKAkyDYp9mE2K7YqNixIOKAkyDYp9mE
2LfYp9im2YEg4oCTINin2YTZhdiv2YrZhtipIAo+INin2YTZhdmG2YjYsdipIOKAkyDYo9io2YfY
pyDigJMg2KzYp9iy2KfZhiDigJMg2KrYqNmI2YMuCj4KPiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0KPgo+ICAKPgo+INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqdiM
INiz2KfZitiq2YjYqtmDINin2YTYsdmK2KfYttiMINiz2KfZitiq2YjYqtmDINis2K/YqdiMINiz
2KfZitiq2YjYqtmDINmF2YPYqdiMINiz2KfZitiq2YjYqtmDIAo+INin2YTYr9mF2KfZhdiMINi0
2LHYp9ihINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqdiMINit2KjZiNioINiz
2KfZitiq2YjYqtmDINmE2YTYpdis2YfYp9i22Iwg2LPYp9mK2KrZiNiq2YMg2KPYtdmE2YrYjCAK
PiDYs9in2YrYqtmI2KrZgyAyMDDYjCBNaXNvcHJvc3RvbCDYp9mE2LPYudmI2K/Zitip2Iwg2LPY
p9mK2KrZiNiq2YMg2KfZhNmG2YfYr9mK2IwgaHR0cHM6Ly9rc2FjeXRvdGVjLmNvbS8gCj4g2YHZ
iiDYp9mE2LPYudmI2K/Zitip2Iwg2K/Zg9iq2YjYsdipINmG2YrYsdmF2YrZhiDYs9in2YrYqtmI
2KrZgy4KPgo+INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqdiMINiz2KfZitiq
2YjYqtmDINin2YTYsdmK2KfYttiMINiz2KfZitiq2YjYqtmDINis2K/YqdiMINiz2KfZitiq2YjY
qtmDINmF2YPYqdiMINiz2KfZitiq2YjYqtmDIAo+INin2YTYr9mF2KfZhdiMINi02LHYp9ihINiz
2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqdiMINit2KjZiNioINiz2KfZitiq2YjY
qtmDINmE2YTYpdis2YfYp9i22Iwg2LPYp9mK2KrZiNiq2YMg2KPYtdmE2YrYjCAKPiDYs9in2YrY
qtmI2KrZgyAyMDDYjCBNaXNvcHJvc3RvbCDYp9mE2LPYudmI2K/Zitip2Iwg2LPYp9mK2KrZiNiq
2YMg2KfZhNmG2YfYr9mK2Iwg2KfZhNil2KzZh9in2LYg2KfZhNi32KjZiiDZgdmKIAo+INin2YTY
s9i52YjYr9mK2KnYjCDYr9mD2KrZiNix2Kkg2YbZitix2YXZitmGINiz2KfZitiq2YjYqtmDLgo+
Cj4NCg0KLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNj
cmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2Ny
aWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNl
bmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRv
IHZpZXcgdGhpcyBkaXNjdXNzaW9uIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9t
c2dpZC9rYXNhbi1kZXYvMzZkYWNhZTQtY2EzYy00N2NiLTkwYmMtZjc0MDIzYzhiNGRmbiU0MGdv
b2dsZWdyb3Vwcy5jb20uCg==
------=_Part_44549_1988308951.1757091660818
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
te"><div dir=3D"auto" class=3D"gmail_attr">=D9=81=D9=8A Sunday, August 17, =
2025 =D9=81=D9=8A =D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=
=D8=A9 1:19:29=E2=80=AFAM UTC-7=D8=8C =D9=83=D8=AA=D8=A8 =D8=AD=D8=A8=D9=88=
=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =E2=80=93 =D9=86=D8=B3=D8=
=A8=D8=A9 =D9=86=D8=AC=D8=A7=D8=AD 95=D9=AA =D8=B1=D8=B3=D8=A7=D9=84=D8=A9 =
=D9=86=D8=B5=D9=87=D8=A7:<br/></div><blockquote class=3D"gmail_quote" style=
=3D"margin: 0 0 0 0.8ex; border-right: 1px solid rgb(204, 204, 204); paddin=
g-right: 1ex;"><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;mar=
gin-bottom:12pt"><span style=3D"font-size:11pt;font-family:Arial,sans-serif=
;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=
=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 0537466539 #=D8=A7=D9=84=D8=B3=D8=B9=D9=88=
=D8=AF=D9=8A=D8=A9 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=
=D8=A2=D9=85=D9=86 =D9=85=D8=B9 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=
=86 | | =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =D8=AC=D8=AF=D8=A9 =D9=85=D9=
=83=D8=A9 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85</span></p><p dir=3D"rtl" sty=
le=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt"><span style=3D"f=
ont-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-colo=
r:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">=D8=A7=D9=83=D8=AA=D8=
=B4=D9=81=D9=8A =D9=85=D8=B9 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=
=D8=8C =D8=A7=D9=84=D9=88=D9=83=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=
=D9=8A =D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =
=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =
=D8=A7=D9=84=D8=B7=D8=A8=D9=8A =D8=A7=D9=84=D8=A2=D9=85=D9=86 =D8=A8=D8=A7=
=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 </span><span style=3D"font-size:11pt;f=
ont-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;f=
ont-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=
=D8=AA=D9=88=D8=AA=D9=83 200 (Misoprostol)</span><span style=3D"font-size:1=
1pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transpar=
ent;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant=
-alternates:normal;vertical-align:baseline"> =D8=A8=D8=A5=D8=B4=D8=B1=D8=A7=
=D9=81 =D8=B7=D8=A8=D9=8A =D9=88=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=
=D9=85=D8=A9. =D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=B3=D8=B1=D9=8A=D8=B9 =D9=
=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=
=8C =D9=85=D9=83=D8=A9=D8=8C =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85 =D9=88=D8=
=A8=D8=A7=D9=82=D9=8A =D8=A7=D9=84=D9=85=D8=AF=D9=86. =F0=9F=93=9E 05374665=
39</span></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margi=
n-bottom:12pt"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;c=
olor:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D9=86=D9=88=D8=A7=D8=AA =D8=A7=D9=
=84=D8=A3=D8=AE=D9=8A=D8=B1=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD=D8=AA</spa=
n><a href=3D"https://ksacytotec.com/" target=3D"_blank" rel=3D"nofollow" da=
ta-saferedirecturl=3D"https://www.google.com/url?hl=3Dar-SA&amp;q=3Dhttps:/=
/ksacytotec.com/&amp;source=3Dgmail&amp;ust=3D1757178048271000&amp;usg=3DAO=
vVaw38Levr-BsTEPYH-umtSeUC"><span style=3D"font-size:11pt;font-family:Arial=
,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline"> </span><span style=3D"font-size:11pt;font-family:Ar=
ial,sans-serif;color:rgb(17,85,204);background-color:transparent;font-varia=
nt-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:no=
rmal;text-decoration-line:underline;vertical-align:baseline">=D8=AD=D8=A8=
=D9=88=D8=A8 </span><span style=3D"font-size:11pt;font-family:Arial,sans-se=
rif;color:rgb(17,85,204);background-color:transparent;font-weight:700;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;text-decoration-line:underline;vertical-align:baseline">=D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size:11pt;f=
ont-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;f=
ont-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline"> (Misoprostol)</span=
><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0=
);background-color:transparent;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;font-variant-alternates:normal;vertical-align:baseline"> =D8=
=AE=D9=8A=D8=A7=D8=B1=D9=8B=D8=A7 =D8=B7=D8=A8=D9=8A=D9=8B=D8=A7 =D9=85=D8=
=B9=D8=B1=D9=88=D9=81=D9=8B=D8=A7 =D9=88=D9=81=D8=B9=D9=91=D8=A7=D9=84=D9=
=8B=D8=A7 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1 =D8=A8=D8=B7=D8=B1=D9=8A=D9=82=D8=
=A9 =D8=A2=D9=85=D9=86=D8=A9 =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=
=81 =D9=85=D8=AE=D8=AA=D8=B5=D9=8A=D9=86. =D9=88=D9=85=D8=B9 =D8=A7=D9=86=
=D8=AA=D8=B4=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=AC=D8=A7=D8=AA =
=D8=A7=D9=84=D9=85=D9=82=D9=84=D8=AF=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD =
=D9=85=D9=86 =D8=A7=D9=84=D8=B6=D8=B1=D9=88=D8=B1=D9=8A =D8=A7=D9=84=D8=AD=
=D8=B5=D9=88=D9=84 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=AF=D9=88=D8=A7=D8=A1 =
=D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82 =D9=88=
=D9=85=D8=B9=D8=AA=D9=85=D8=AF.</span><span style=3D"font-size:11pt;font-fa=
mily:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline"><br></span><span style=3D"font-size:11pt;f=
ont-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;f=
ont-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">=D8=AF. =D9=86=D9=8A=
=D8=B1=D9=85=D9=8A=D9=86</span><span style=3D"font-size:11pt;font-family:Ar=
ial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline">=D8=8C =D8=A8=D8=B5=D9=81=D8=AA=D9=87=D8=A7 =D8=
=A7=D9=84=D9=88=D9=83=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A =D9=
=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=
=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AA=D9=
=82=D8=AF=D9=85 =D9=84=D9=83=D9=90 =D9=85=D9=86=D8=AA=D8=AC=D9=8B=D8=A7 =D8=
=A3=D8=B5=D9=84=D9=8A=D9=8B=D8=A7 =D8=A8=D8=AC=D9=88=D8=AF=D8=A9 =D9=85=D8=
=B6=D9=85=D9=88=D9=86=D8=A9=D8=8C =D9=85=D8=B9 =D8=A7=D8=B3=D8=AA=D8=B4=D8=
=A7=D8=B1=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9 =D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=
=A9 =D9=88=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=81=D9=
=8A =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=88=D8=A7=D9=84=D8=AA=D9=
=88=D8=B5=D9=8A=D9=84.</span></p><p dir=3D"rtl" style=3D"line-height:1.38;m=
argin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"=
line-height:1.38;margin-top:14pt;margin-bottom:4pt"><span style=3D"font-siz=
e:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:trans=
parent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline">=D9=85=D8=A7=
 =D9=87=D9=88 =D8=AF=D9=88=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83=D8=9F</span></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-t=
op:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-family:Arial=
,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 (=D8=A7=
=D9=84=D9=85=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84=D8=A9 <=
/span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(=
0,0,0);background-color:transparent;font-weight:700;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline">=D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=
=88=D9=84</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;=
color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline">) =D8=AF=D9=88=D8=A7=D8=A1 =D9=85=D9=8F=D8=B9=D8=AA=D9=85=D8=AF =
=D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=AC=D8=A7=D9=84 =D8=A7=D9=84=D8=B7=D8=A8=
=D9=8A=D8=8C =D9=88=D9=8A=D9=8F=D8=B3=D8=AA=D8=AE=D8=AF=D9=85 =D8=A8=D8=AC=
=D8=B1=D8=B9=D8=A7=D8=AA =D8=AF=D9=82=D9=8A=D9=82=D8=A9 =D9=84=D8=A5=D9=86=
=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=
=D9=83=D8=B1=D8=8C =D9=88=D8=B9=D9=84=D8=A7=D8=AC =D8=AD=D8=A7=D9=84=D8=A7=
=D8=AA =D8=B7=D8=A8=D9=8A=D8=A9 =D8=A3=D8=AE=D8=B1=D9=89 =D9=85=D8=AB=D9=84=
 =D9=82=D8=B1=D8=AD=D8=A9 =D8=A7=D9=84=D9=85=D8=B9=D8=AF=D8=A9. =D8=B9=D9=
=86=D8=AF =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=D9=87 =D9=84=D9=84=D8=
=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=8C =D9=8A=D8=B9=D9=85=D9=84 =D8=B9=D9=84=D9=
=89 =D8=AA=D8=AD=D9=81=D9=8A=D8=B2 =D8=AA=D9=82=D9=84=D8=B5=D8=A7=D8=AA =D8=
=A7=D9=84=D8=B1=D8=AD=D9=85 =D9=88=D8=A5=D9=81=D8=B1=D8=A7=D8=BA =D9=85=D8=
=AD=D8=AA=D9=88=D9=8A=D8=A7=D8=AA=D9=87 =D8=AE=D9=84=D8=A7=D9=84 =D9=81=D8=
=AA=D8=B1=D8=A9 =D9=82=D8=B5=D9=8A=D8=B1=D8=A9=D8=8C =D9=85=D9=85=D8=A7 =D9=
=8A=D8=AC=D8=B9=D9=84=D9=87 =D8=AE=D9=8A=D8=A7=D8=B1=D9=8B=D8=A7 =D9=81=D8=
=B9=D8=A7=D9=84=D9=8B=D8=A7 =D9=88=D8=A2=D9=85=D9=86=D9=8B=D8=A7 =D8=B9=D9=
=86=D8=AF =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A=D8=A8 =D9=85=D8=
=AE=D8=AA=D8=B5.</span></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-=
top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-h=
eight:1.38;margin-top:14pt;margin-bottom:4pt"><span style=3D"font-size:13pt=
;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent=
;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline">=D8=A3=D9=87=D9=85=
=D9=8A=D8=A9 =D8=A7=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=D9=84=D9=89 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =
=D9=85=D9=88=D8=AB=D9=88=D9=82</span></span><p dir=3D"rtl" style=3D"line-he=
ight:1.38;margin-top:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt=
;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent=
;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-al=
ternates:normal;vertical-align:baseline">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=
=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AA=D8=AA=D9=88=D8=A7=D8=AC=D8=AF =D8=
=A7=D9=84=D9=83=D8=AB=D9=8A=D8=B1 =D9=85=D9=86 =D8=A7=D9=84=D9=82=D9=86=D9=
=88=D8=A7=D8=AA =D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=88=D8=AB=D9=88=D9=
=82=D8=A9 =D8=A7=D9=84=D8=AA=D9=8A =D8=AA=D8=A8=D9=8A=D8=B9 =D9=85=D9=86=D8=
=AA=D8=AC=D8=A7=D8=AA =D9=85=D8=AC=D9=87=D9=88=D9=84=D8=A9 =D8=A7=D9=84=D9=
=85=D8=B5=D8=AF=D8=B1 =D9=82=D8=AF =D8=AA=D8=A4=D8=AF=D9=8A =D8=A5=D9=84=D9=
=89 =D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =D8=B5=D8=AD=D9=8A=D8=A9 =D8=AC=D8=B3=D9=
=8A=D9=85=D8=A9.</span><span style=3D"font-size:11pt;font-family:Arial,sans=
-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline"><br></span><span style=3D"font-size:11pt;font-family:Aria=
l,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=
=8A=D9=86</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;=
color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline"> =D8=AA=D8=B6=D9=85=D9=86 =D9=84=D9=83:</span><span style=3D"fon=
t-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:=
transparent;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline"><br></span><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">=E2=9C=94=EF=B8=
=8F </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D8=A3=D8=B5=D9=84=D9=8A=D8=A9 100%</span><span style=3D"fo=
nt-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color=
:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline"><br></=
span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0=
,0,0);background-color:transparent;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=E2=9C=94=EF=B8=8F </span><span style=3D"font-size:11pt;font-family:Arial,s=
ans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE =D8=B5=
=D9=84=D8=A7=D8=AD=D9=8A=D8=A9 =D8=AD=D8=AF=D9=8A=D8=AB</span><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-weight:700;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
<br></span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line">=E2=9C=94=EF=B8=8F </span><span style=3D"font-size:11pt;font-family:A=
rial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:7=
00;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline">=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF=
=D8=A7=D8=AA =D8=B7=D8=A8=D9=8A=D8=A9 =D8=AF=D9=82=D9=8A=D9=82=D8=A9 =D9=84=
=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85</span><span style=3D"font-=
size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tr=
ansparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline"><br></spa=
n><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,=
0);background-color:transparent;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=E2=
=9C=94=EF=B8=8F </span><span style=3D"font-size:11pt;font-family:Arial,sans=
-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline">=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=
=A7=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84</sp=
an><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0=
,0);background-color:transparent;font-weight:700;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-al=
ign:baseline"><br></span><span style=3D"font-size:11pt;font-family:Arial,sa=
ns-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=E2=9C=94=EF=B8=8F </span><span style=3D"font-size:11pt=
;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent=
;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline">=D8=AF=D8=B9=D9=85=
 =D9=88=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=B9=D9=84=D9=89 =D9=85=
=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=D8=A9</span></p><p dir=3D=
"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><=
p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-top:14pt;margin-bo=
ttom:4pt"><span style=3D"font-size:13pt;font-family:Arial,sans-serif;color:=
rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline">=D9=84=D9=85=D8=A7=D8=B0=D8=A7 =D8=AA=D8=AE=D8=AA=D8=
=A7=D8=B1=D9=8A=D9=86 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=D8=9F</s=
pan></span><ul style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" s=
tyle=3D"list-style-type:disc;font-size:11pt;font-family:Arial,sans-serif;co=
lor:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-alig=
n:right;margin-top:12pt;margin-bottom:0pt" role=3D"presentation"><span styl=
e=3D"font-size:11pt;background-color:transparent;font-weight:700;font-varia=
nt-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:no=
rmal;vertical-align:baseline">=D8=A7=D9=84=D8=AE=D8=A8=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=B7=D8=A8=D9=8A=D8=A9</span><span style=3D"font-size:11pt;backgrou=
nd-color:transparent;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline">: =D8=AF. =D9=
=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=
=81=D9=8A =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=
=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D9=86=D8=B3=D8=A7=D8=A6=D9=
=8A=D8=A9=D8=8C =D9=88=D8=AA=D9=82=D8=AF=D9=85 =D9=84=D9=83=D9=90 =D8=AF=D8=
=B9=D9=85=D9=8B=D8=A7 =D9=85=D9=87=D9=86=D9=8A=D9=8B=D8=A7 =D9=82=D8=A8=D9=
=84 =D9=88=D8=A3=D8=AB=D9=86=D8=A7=D8=A1 =D9=88=D8=A8=D8=B9=D8=AF</span><a =
href=3D"https://saudiersaa.com/" target=3D"_blank" rel=3D"nofollow" data-sa=
feredirecturl=3D"https://www.google.com/url?hl=3Dar-SA&amp;q=3Dhttps://saud=
iersaa.com/&amp;source=3Dgmail&amp;ust=3D1757178048271000&amp;usg=3DAOvVaw2=
3UfgcUuxH_sETrg2chhRS"><span style=3D"font-size:11pt;color:rgb(17,85,204);b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;text-decoration-line:underline;v=
ertical-align:baseline">=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size:11p=
t;background-color:transparent;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;font-variant-alternates:normal;vertical-align:baseline">.</s=
pan><span style=3D"font-size:11pt;background-color:transparent;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=
=3D"list-style-type:disc;font-size:11pt;font-family:Arial,sans-serif;color:=
rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:ri=
ght;margin-top:0pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"=
font-size:11pt;background-color:transparent;font-weight:700;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline">=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A7=
=D9=84=D8=B3=D8=B1=D9=8A=D8=B9</span><span style=3D"font-size:11pt;backgrou=
nd-color:transparent;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline">: =D8=AA=D8=BA=
=D8=B7=D9=8A=D8=A9 =D9=84=D8=AC=D9=85=D9=8A=D8=B9 =D8=A7=D9=84=D9=85=D8=AF=
=D9=86 =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=A8=D9=85=
=D8=A7 =D9=81=D9=8A =D8=B0=D9=84=D9=83 </span><span style=3D"font-size:11pt=
;background-color:transparent;font-weight:700;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline">=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=
=8C =D9=85=D9=83=D8=A9=D8=8C =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=
=A7=D9=84=D8=AE=D8=A8=D8=B1=D8=8C =D8=A7=D9=84=D8=B7=D8=A7=D8=A6=D9=81</spa=
n><span style=3D"font-size:11pt;background-color:transparent;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline"> =D9=88=D8=BA=D9=8A=D8=B1=D9=87=D8=A7.</span><spa=
n style=3D"font-size:11pt;background-color:transparent;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-s=
tyle-type:disc;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0)=
;background-color:transparent;font-variant-numeric:normal;font-variant-east=
-asian:normal;font-variant-alternates:normal;vertical-align:baseline;white-=
space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin=
-top:0pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"font-size:=
11pt;background-color:transparent;font-weight:700;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline">=D8=AD=D9=85=D8=A7=D9=8A=D8=A9 =D8=AE=D8=B5=D9=88=D8=B5=D9=
=8A=D8=AA=D9=83</span><span style=3D"font-size:11pt;background-color:transp=
arent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">: =D9=8A=D8=AA=D9=85 =D8=A7=
=D9=84=D8=AA=D8=BA=D9=84=D9=8A=D9=81 =D8=A8=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =
=D8=AA=D8=B6=D9=85=D9=86 =D8=A7=D9=84=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=A7=
=D9=84=D9=83=D8=A7=D9=85=D9=84=D8=A9.</span><span style=3D"font-size:11pt;b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline"><br><br=
></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11=
pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transpare=
nt;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" s=
tyle=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:12pt=
" role=3D"presentation"><span style=3D"font-size:11pt;background-color:tran=
sparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=D9=
=84=D8=AA=D9=88=D9=83=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A</spa=
n><span style=3D"font-size:11pt;background-color:transparent;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline">: =D8=B4=D8=B1=D8=A7=D8=A1=D9=83 =D9=8A=D8=AA=D9=
=85 =D9=85=D8=A8=D8=A7=D8=B4=D8=B1=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=
=B5=D8=AF=D8=B1 =D8=A7=D9=84=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=8C =D8=A8=D8=
=B9=D9=8A=D8=AF=D9=8B=D8=A7 =D8=B9=D9=86 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=
=B7=D8=B1.</span><span style=3D"font-size:11pt;background-color:transparent=
;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-al=
ternates:normal;vertical-align:baseline"><br><br></span></p></li></ul><p di=
r=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><=
hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-top:14pt;margi=
n-bottom:4pt"><span style=3D"font-size:13pt;font-family:Arial,sans-serif;co=
lor:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline">=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=B7=D9=84=D8=A8 =
=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=
=D9=86 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span></span><ol style=
=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"list-style-t=
ype:decimal;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);ba=
ckground-color:transparent;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline;white-spa=
ce:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-to=
p:12pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"font-size:11=
pt;background-color:transparent;font-weight:700;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline">=D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D8=B9=D8=A8=D8=B1 =
=D9=88=D8=A7=D8=AA=D8=B3=D8=A7=D8=A8</span><span style=3D"font-size:11pt;ba=
ckground-color:transparent;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline"> =D8=B9=
=D9=84=D9=89 =D8=A7=D9=84=D8=B1=D9=82=D9=85: </span><span style=3D"font-siz=
e:11pt;background-color:transparent;font-weight:700;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline">=F0=9F=93=9E 0537466539</span><span style=3D"font-size:11p=
t;background-color:transparent;font-weight:700;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-typ=
e:decimal;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);back=
ground-color:transparent;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline;white-space=
:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:=
0pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"font-size:11pt;=
background-color:transparent;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=B4=
=D8=B1=D8=AD =D8=A7=D9=84=D8=AD=D8=A7=D9=84=D8=A9 =D8=A7=D9=84=D8=B5=D8=AD=
=D9=8A=D8=A9 =D9=88=D9=81=D8=AA=D8=B1=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=84.=
</span><span style=3D"font-size:11pt;background-color:transparent;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" styl=
e=3D"list-style-type:decimal;font-size:11pt;font-family:Arial,sans-serif;co=
lor:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-alig=
n:right;margin-top:0pt;margin-bottom:0pt" role=3D"presentation"><span style=
=3D"font-size:11pt;background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline">=D8=A7=D8=B3=D8=AA=D9=84=D8=A7=D9=85 =D8=A7=D9=84=D8=A5=D8=B1=
=D8=B4=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=
=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=A9 =D9=88=D8=A7=D9=84=D8=AC=D8=B1=
=D8=B9=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=B5=D9=89 =D8=A8=D9=87=D8=A7.</span=
><span style=3D"font-size:11pt;background-color:transparent;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"l=
ist-style-type:decimal;font-size:11pt;font-family:Arial,sans-serif;color:rg=
b(0,0,0);background-color:transparent;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;vertical-align:baselin=
e;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:righ=
t;margin-top:0pt;margin-bottom:12pt" role=3D"presentation"><span style=3D"f=
ont-size:11pt;background-color:transparent;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">=D8=A7=D8=B3=D8=AA=D9=84=D8=A7=D9=85 =D8=A7=D9=84=D8=AD=D8=A8=D9=88=
=D8=A8 =D8=AE=D9=84=D8=A7=D9=84 =D9=81=D8=AA=D8=B1=D8=A9 =D9=82=D8=B5=D9=8A=
=D8=B1=D8=A9 =D8=B9=D8=A8=D8=B1 =D8=AE=D8=AF=D9=85=D8=A9 =D8=AA=D9=88=D8=B5=
=D9=8A=D9=84 =D8=A2=D9=85=D9=86=D8=A9 =D9=88=D8=B3=D8=B1=D9=8A=D8=A9.</span=
><span style=3D"font-size:11pt;background-color:transparent;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline"><br><br></span></p></li></ol><p dir=3D"rtl" style=
=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span=
 dir=3D"rtl" style=3D"line-height:1.38;margin-top:14pt;margin-bottom:4pt"><=
span style=3D"font-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);=
background-color:transparent;font-weight:700;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline">=D8=AA=D9=86=D8=A8=D9=8A=D9=87 =D8=B7=D8=A8=D9=8A =D9=85=D9=87=D9=
=85</span></span><ul style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"=
rtl" style=3D"list-style-type:disc;font-size:11pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;tex=
t-align:right;margin-top:12pt;margin-bottom:0pt" role=3D"presentation"><spa=
n style=3D"font-size:11pt;background-color:transparent;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=D9=8A=D8=AC=D8=A8 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=
=D9=85 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=82=D8=B7 =D8=AA=
=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A =D9=85=D8=AE=
=D8=AA=D8=B5.</span><span style=3D"font-size:11pt;background-color:transpar=
ent;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant=
-alternates:normal;vertical-align:baseline"><br><br></span></p></li><li dir=
=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;font-family:Arial,san=
s-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38=
;text-align:right;margin-top:0pt;margin-bottom:0pt" role=3D"presentation"><=
span style=3D"font-size:11pt;background-color:transparent;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline">=D9=84=D8=A7 =D9=8A=D9=8F=D9=86=D8=B5=D8=AD =D8=A8=
=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=D9=87 =D9=81=D9=8A =D8=AD=D8=A7=
=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=
=D8=A3=D8=AE=D8=B1.</span><span style=3D"font-size:11pt;background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline"><br><br></span></p></li><=
li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;font-family:Ari=
al,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-heigh=
t:1.38;text-align:right;margin-top:0pt;margin-bottom:12pt" role=3D"presenta=
tion"><span style=3D"font-size:11pt;background-color:transparent;font-varia=
nt-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:no=
rmal;vertical-align:baseline">=D9=81=D9=8A =D8=AD=D8=A7=D9=84 =D9=88=D8=AC=
=D9=88=D8=AF =D8=A3=D9=85=D8=B1=D8=A7=D8=B6 =D9=85=D8=B2=D9=85=D9=86=D8=A9 =
=D8=A3=D9=88 =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=AE=D8=A7=D8=B5=D8=A9=D8=8C =
=D9=8A=D8=AC=D8=A8 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=
=D8=B7=D8=A8=D9=8A=D8=A8 =D9=82=D8=A8=D9=84 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=
=D8=AE=D8=AF=D8=A7=D9=85.</span><span style=3D"font-size:11pt;background-co=
lor:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;=
font-variant-alternates:normal;vertical-align:baseline"><br><br></span></p>=
</li></ul><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bo=
ttom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin=
-top:14pt;margin-bottom:4pt"><span style=3D"font-size:13pt;font-family:Aria=
l,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline">=D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=
=A5=D8=B6=D8=A7=D9=81=D9=8A=D8=A9 =D9=85=D9=86 =D8=AF. =D9=86=D9=8A=D8=B1=
=D9=85=D9=8A=D9=86</span></span><ul style=3D"margin-top:0px;margin-bottom:0=
px"><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;font-famil=
y:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-varia=
nt-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:no=
rmal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-=
height:1.38;text-align:right;margin-top:12pt;margin-bottom:0pt" role=3D"pre=
sentation"><span style=3D"font-size:11pt;background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">=D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =D8=
=A7=D9=84=D8=AD=D8=A7=D9=84=D8=A9 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A7=D8=
=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85.</span><span style=3D"font-size:11pt;back=
ground-color:transparent;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline"><br><br></=
span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;=
font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" styl=
e=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt" ro=
le=3D"presentation"><span style=3D"font-size:11pt;background-color:transpar=
ent;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant=
-alternates:normal;vertical-align:baseline">=D8=AA=D9=88=D9=81=D9=8A=D8=B1 =
=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =D8=AD=D9=88=D9=84 =D8=A7=D9=84=
=D8=A2=D8=AB=D8=A7=D8=B1 =D8=A7=D9=84=D8=AC=D8=A7=D9=86=D8=A8=D9=8A=D8=A9 =
=D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=B9=D9=8A=D8=A9 =D9=88=D9=83=D9=8A=D9=81=
=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=85=D8=B9=D9=87=
=D8=A7.</span><span style=3D"font-size:11pt;background-color:transparent;fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rt=
l" style=3D"list-style-type:disc;font-size:11pt;font-family:Arial,sans-seri=
f;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-=
align:right;margin-top:0pt;margin-bottom:12pt" role=3D"presentation"><span =
style=3D"font-size:11pt;background-color:transparent;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline">=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF =D8=A7=D9=84=D9=85=D8=B1=
=D9=8A=D8=B6=D8=A9 =D8=A5=D9=84=D9=89 =D8=A3=D9=81=D8=B6=D9=84 =D9=85=D9=85=
=D8=A7=D8=B1=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=A9 =
=D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9.</span><span style=3D"font-size:11pt;b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline"><br><br=
></span></p></li></ul><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0=
pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height=
:1.38;margin-top:14pt;margin-bottom:4pt"><span style=3D"font-size:13pt;font=
-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font=
-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline">=D8=AE=D9=84=D8=A7=D8=
=B5=D8=A9</span></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:=
12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-family:Arial,sa=
ns-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=D8=A7=D8=AE=D8=AA=D9=8A=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=
=D8=B5=D8=AF=D8=B1 =D8=A7=D9=84=D9=85=D9=88=D8=AB=D9=88=D9=82 =D8=B9=D9=86=
=D8=AF</span><a href=3D"https://groups.google.com/a/chromium.org/g/security=
-dev/c/rhrPpivCQGM/m/XihUBiSLAAAJ" target=3D"_blank" rel=3D"nofollow" data-=
saferedirecturl=3D"https://www.google.com/url?hl=3Dar-SA&amp;q=3Dhttps://gr=
oups.google.com/a/chromium.org/g/security-dev/c/rhrPpivCQGM/m/XihUBiSLAAAJ&=
amp;source=3Dgmail&amp;ust=3D1757178048271000&amp;usg=3DAOvVaw2Gykiq0mwC41u=
LiJBdmWWL"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line"> </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;co=
lor:rgb(17,85,204);background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;text-decorat=
ion-line:underline;vertical-align:baseline">=D8=B4=D8=B1=D8=A7=D8=A1 </span=
><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(17,85=
,204);background-color:transparent;font-weight:700;font-variant-numeric:nor=
mal;font-variant-east-asian:normal;font-variant-alternates:normal;text-deco=
ration-line:underline;vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size:=
11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transpa=
rent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline"> =D9=81=D9=8A =D8=A7=D9=84=D8=
=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =D9=87=D9=88 =D8=A7=D9=84=D8=B6=D9=85=D8=
=A7=D9=86 =D8=A7=D9=84=D9=88=D8=AD=D9=8A=D8=AF =D9=84=D8=B3=D9=84=D8=A7=D9=
=85=D8=AA=D9=83=D9=90.</span><span style=3D"font-size:11pt;font-family:Aria=
l,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline"><br></span><span style=3D"font-size:11pt;font-famil=
y:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-varia=
nt-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:no=
rmal;vertical-align:baseline">=D9=85=D8=B9 </span><span style=3D"font-size:=
11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transpa=
rent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline">=D8=AF. =D9=86=
=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span><span style=3D"font-size:11pt;font-fam=
ily:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:=
normal;vertical-align:baseline">=D8=8C =D8=B3=D8=AA=D8=AD=D8=B5=D9=84=D9=8A=
=D9=86 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=AC =D8=A7=D9=84=
=D8=A3=D8=B5=D9=84=D9=8A=D8=8C =D8=A7=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF =
=D8=A7=D9=84=D8=B7=D8=A8=D9=8A =D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5=
=D8=8C =D9=88=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=
=D8=B1=D9=8A =D8=A3=D9=8A=D9=86=D9=85=D8=A7 =D9=83=D9=86=D8=AA=D9=90 =D9=81=
=D9=8A =D8=A7=D9=84=D9=85=D9=85=D9=84=D9=83=D8=A9.</span></p><p dir=3D"rtl"=
 style=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt"><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">=F0=9F=93=9E =D9=
=84=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=88=D8=A7=D9=84=D8=B7=D9=84=D8=
=A8 =D8=B9=D8=A8=D8=B1 =D9=88=D8=A7=D8=AA=D8=B3=D8=A7=D8=A8: </span><span s=
tyle=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgr=
ound-color:transparent;font-weight:700;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne">0537466539</span><span style=3D"font-size:11pt;font-family:Arial,sans-s=
erif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:=
normal;vertical-align:baseline"><br></span><span style=3D"font-size:11pt;fo=
nt-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=D9=85=D8=
=AF=D9=86 =D8=A7=D9=84=D9=85=D8=BA=D8=B7=D8=A7=D8=A9</span><span style=3D"f=
ont-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-colo=
r:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">: =D8=A7=D9=84=D8=B1=
=D9=8A=D8=A7=D8=B6 =E2=80=93 =D8=AC=D8=AF=D8=A9 =E2=80=93 =D9=85=D9=83=D8=
=A9 =E2=80=93 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85 =E2=80=93 =D8=A7=D9=84=
=D8=AE=D8=A8=D8=B1 =E2=80=93 =D8=A7=D9=84=D8=B7=D8=A7=D8=A6=D9=81 =E2=80=93=
 =D8=A7=D9=84=D9=85=D8=AF=D9=8A=D9=86=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D9=88=
=D8=B1=D8=A9 =E2=80=93 =D8=A3=D8=A8=D9=87=D8=A7 =E2=80=93 =D8=AC=D8=A7=D8=
=B2=D8=A7=D9=86 =E2=80=93 =D8=AA=D8=A8=D9=88=D9=83.</span></p><p dir=3D"rtl=
" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></=
p><span dir=3D"rtl" style=3D"line-height:1.38;margin-top:18pt;margin-bottom=
:4pt"><span style=3D"font-size:17pt;font-family:Arial,sans-serif;color:rgb(=
0,0,0);background-color:transparent;font-weight:700;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline">=C2=A0</span></span><p dir=3D"rtl" style=3D"line-height:1.=
38;margin-top:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-f=
amily:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=
=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AC=D8=AF=D8=A9=D8=
=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=83=D8=A9=D8=8C =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=
=85=D8=8C =D8=B4=D8=B1=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=
=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=
=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D8=A3=D8=B5=D9=84=D9=8A=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 200=D8=8C Misoprostol =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=
=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D9=86=
=D9=87=D8=AF=D9=8A=D8=8C</span><a href=3D"https://ksacytotec.com/" target=
=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"https://www.google.com=
/url?hl=3Dar-SA&amp;q=3Dhttps://ksacytotec.com/&amp;source=3Dgmail&amp;ust=
=3D1757178048271000&amp;usg=3DAOvVaw38Levr-BsTEPYH-umtSeUC"><span style=3D"=
font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline"> </span><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(17,85,204);backgr=
ound-color:transparent;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;text-decoration-line:underline;vertic=
al-align:baseline">https://ksacytotec.com/</span></a><span style=3D"font-si=
ze:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tran=
sparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline"> =D9=81=D9=8A =D8=A7=D9=84=
=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AF=D9=83=D8=AA=D9=88=D8=B1=
=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83.</span></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top=
:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial,san=
s-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =
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
=8A=D8=8C =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=B7=D8=
=A8=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=
=8C =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=
=86 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83.</span></p><br></blockquote>=
</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/36dacae4-ca3c-47cb-90bc-f74023c8b4dfn%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/36dacae4-ca3c-47cb-90bc-f74023c8b4dfn%40googlegroups.com</a>.<br />

------=_Part_44549_1988308951.1757091660818--

------=_Part_44548_1416103113.1757091660818--
