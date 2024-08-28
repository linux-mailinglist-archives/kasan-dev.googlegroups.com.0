Return-Path: <kasan-dev+bncBC46NCNX4YDRBKNQX23AMGQEYPEU4SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id B34229633F5
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 23:35:38 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id 5614622812f47-3db16c5eabesf438637b6e.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 14:35:38 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724880937; x=1725485737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j4h4IhJxR7kcermlZzHJ4lJZOlQwmJdM0dF7uYKUB94=;
        b=c3YQ13a2FUK+OjDkanGUNVIzA+v0NoNIfjUQyg6WFKEdVgij71Fbnp3PIN8XlNlAeb
         DOTuGKlrD9kJ+lbXlz1iTQZEgRmvNrccO0zI/yHhGBX6OD3mOnFY9vZuX54GI9v1O7la
         UNT2Xx4+wSpRG4rfbGxv42rGMaaR24e2AdSMLF+tF4iuRzBzSUdw9yginavqIJ8MVrLg
         azxpeka/G+0RqHvClQCrDQEK34VFmkFC8drA9rVYSEfSVZTMvcAkZzbttzSmbRo8dKMu
         HVvqTAqy2kKf2+b/zNT31LtmBcuHmgMmSoy9V8dhqjOuBbGEbhJACC8KHNeQlTYuF1PV
         z8WQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724880937; x=1725485737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j4h4IhJxR7kcermlZzHJ4lJZOlQwmJdM0dF7uYKUB94=;
        b=L8RxVofqQmM91JIJkev6pcwo4d0EAZrLqdU1wtO4tciNBd9jPW0l6nCiJK1ZIulcG4
         KLXCkHg/N8Ds1W7RsTntTAxqznHtql1U2x9NnMdXfNX5JZhL6AECzEVPvIfN7AL2gCKb
         osyPhYcqoVCcdkl+6v/HmJdBYmyt9Na+nDFAknBmrH5rZK1AAMXyFWVuU9+mS6mq8cbm
         4HqBEbJXoWVJXomYevL3wQHxqiOitgOic5KCgBm9FwY9jt8XDSlWA37NDiJ9nkZaQuia
         /FgvzXK/T5AhY+YBUAfFUzCWTQ17IUYwn+3Ymu9p6wkpCVaYM73A2w9kYnUy53m7q+IG
         3F4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724880937; x=1725485737;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j4h4IhJxR7kcermlZzHJ4lJZOlQwmJdM0dF7uYKUB94=;
        b=T98pxdJOHGeHVhahA2tJpJJ+mqz1LTGGLDA8i/xw0pHebpG4NN5mmAVrxn+CQkKknJ
         fI4HUyXCpxAwnUaTgk8TyQpW1opzUhGYM2SFbhDgsuVtza1CyJjoi09HpCPJrC5pyA+5
         fdE414+BLgOJzzVc7rnJm0/4hpmJtG3BfPU3o5dhipSXvQw0ieXFCdw0Kq8+uiZ3E+FX
         2GOQC6+euECMHYN/WKIFFVi9J+sbayilO/F8zQ6k8u8QDsqtmAfTkodT7/fFe+jQ/62U
         cKb7Xu19DwBeHfUbxyXz2Nws7WUjdgOmkC8jAQqDZMj9/HGH6AIBRVDMsJZVzQpudTze
         c/Sg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCVULTBxr8sDwXquFH/3Uz8uMcV+vV0sXzpBX26AzFs2jS7I438FTtWthH9NK54Tfv0UWVBT+Q==@lfdr.de
X-Gm-Message-State: AOJu0YxZCmXgU920UtyxqFprxmdXl1lAfJnUGJAcrcmvIQeTjQx/neId
	GkO+nK3xnyIgLbir5lueWqypE48mmk+1rsARbLtMdAJ98ooZ5gpr
X-Google-Smtp-Source: AGHT+IEz22wsQf2TDb9DbJLWNJHEyRJyyVSzoDUZtibiKE+xPEI0BjbtrHb/hWIJj21iSPekQOWHug==
X-Received: by 2002:a05:6870:b491:b0:26f:df8d:fc13 with SMTP id 586e51a60fabf-27790082bd9mr591629fac.2.1724880937282;
        Wed, 28 Aug 2024 14:35:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:758c:b0:24f:f6d5:2d15 with SMTP id
 586e51a60fabf-2778f0c2720ls162376fac.0.-pod-prod-00-us; Wed, 28 Aug 2024
 14:35:36 -0700 (PDT)
X-Received: by 2002:a05:6808:2213:b0:3dd:1eec:6517 with SMTP id 5614622812f47-3df0673083emr194932b6e.3.1724880936357;
        Wed, 28 Aug 2024 14:35:36 -0700 (PDT)
Date: Wed, 28 Aug 2024 14:35:35 -0700 (PDT)
From: Kerry Crook <crook9994@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <b94d0994-b44c-459c-a186-9f6f727e391dn@googlegroups.com>
Subject: =?UTF-8?B?2YjYp9iq2LPYp9ioICs5NzEgNTggNjI2IDc5ODEg2LQ=?=
 =?UTF-8?B?2LHYp9ihINiz2YPZiNiq2LEg2YPZhw==?=
 =?UTF-8?B?2LHYqNin2KbZiiDZhdiq2K3YsdmDINi5?=
 =?UTF-8?B?2KjYsSDYp9mE2KXZhtiq2LHZhtiqIA==?=
 =?UTF-8?B?2YHZiiDYp9mE2YPZiNmK2Kog2KfZhNmF?=
 =?UTF-8?B?2YXZhNmD2Kkg2KfZhNi52LHYqNmK2Kk=?=
 =?UTF-8?B?INin2YTYs9i52YjYr9mK2Kkg2YLYt9ix?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_19870_1902375699.1724880935611"
X-Original-Sender: crook9994@gmail.com
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

------=_Part_19870_1902375699.1724880935611
Content-Type: multipart/alternative; 
	boundary="----=_Part_19871_1947442992.1724880935611"

------=_Part_19871_1947442992.1724880935611
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YjYp9iq2LPYp9ioICs5NzEgNTggNjI2IDc5ODEg2LTYsdin2KEg2LPZg9mI2KrYsSDZhdiq2K3Y
sdmDINi52KjYsSDYp9mE2KXZhtiq2LHZhtiqINmB2Yog2KfZhNmD2YjZitiqINin2YTZhdmF2YTZ
g9ipIArYp9mE2LnYsdio2YrYqSDYp9mE2LPYudmI2K/ZitipINmC2LfYsSDYp9mE2KjYrdix2YrZ
hiDYp9mE2KPYsdiv2YYg2KfZhNil2YXYp9ix2KfYqiDYp9mE2LnYsdio2YrYqSDYp9mE2YXYqtit
2K/YqQoKLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNj
cmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2Ny
aWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNl
bmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRv
IHZpZXcgdGhpcyBkaXNjdXNzaW9uIG9uIHRoZSB3ZWIgdmlzaXQgaHR0cHM6Ly9ncm91cHMuZ29v
Z2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9iOTRkMDk5NC1iNDRjLTQ1OWMtYTE4Ni05ZjZmNzI3
ZTM5MWRuJTQwZ29vZ2xlZ3JvdXBzLmNvbS4K
------=_Part_19871_1947442992.1724880935611
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

2YjYp9iq2LPYp9ioICs5NzEgNTggNjI2IDc5ODEg2LTYsdin2KEg2LPZg9mI2KrYsSDZhdiq2K3Y
sdmDINi52KjYsSDYp9mE2KXZhtiq2LHZhtiqINmB2Yog2KfZhNmD2YjZitiqINin2YTZhdmF2YTZ
g9ipINin2YTYudix2KjZitipINin2YTYs9i52YjYr9mK2Kkg2YLYt9ixINin2YTYqNit2LHZitmG
INin2YTYo9ix2K/ZhiDYp9mE2KXZhdin2LHYp9iqINin2YTYudix2KjZitipINin2YTZhdiq2K3Y
r9ipPGJyIC8+PGRpdj48YnIgLz48L2Rpdj4NCg0KPHA+PC9wPgoKLS0gPGJyIC8+CllvdSByZWNl
aXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2ds
ZSBHcm91cHMgJnF1b3Q7a2FzYW4tZGV2JnF1b3Q7IGdyb3VwLjxiciAvPgpUbyB1bnN1YnNjcmli
ZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5k
IGFuIGVtYWlsIHRvIDxhIGhyZWY9Im1haWx0bzprYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xl
Z3JvdXBzLmNvbSI+a2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb208L2E+Ljxi
ciAvPgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiBvbiB0aGUgd2ViIHZpc2l0IDxhIGhyZWY9Imh0
dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvYjk0ZDA5OTQtYjQ0Yy00
NTljLWExODYtOWY2ZjcyN2UzOTFkbiU0MGdvb2dsZWdyb3Vwcy5jb20/dXRtX21lZGl1bT1lbWFp
bCZ1dG1fc291cmNlPWZvb3RlciI+aHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2th
c2FuLWRldi9iOTRkMDk5NC1iNDRjLTQ1OWMtYTE4Ni05ZjZmNzI3ZTM5MWRuJTQwZ29vZ2xlZ3Jv
dXBzLmNvbTwvYT4uPGJyIC8+Cg==
------=_Part_19871_1947442992.1724880935611--

------=_Part_19870_1902375699.1724880935611--
