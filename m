Return-Path: <kasan-dev+bncBDYPL74CXAOBBZ4DWHCQMGQENJG5INY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id EE7E0B33D61
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 12:58:49 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-31532a92431sf228281fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 03:58:49 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756119528; x=1756724328; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=EcwH1D3fpC0c4yqh48xjI9YRHTkqedLwqPzUW0wv1SI=;
        b=L9rcLgds0sS4rrWv9X9dhiEyIIj/j35SC1Fvmx1UVEYd0+iQLI7ssDZKnRW3Uq2ndr
         5X+ONnwYwjZl3qxWoKkiGwakBNchieiUtRNSJ8RbRrJjFikmR+v3ImsuXFDbBI7GdwT9
         9nb48R5u+i2Vb9iYG/HCjxN73ZomysjqEnrFewxDGbXXVv6f+4q77hOLK1Ze+p5eXu79
         KYjMOudztgQHO62r+keNdlYf6wTxPvkiQyItVzBKdmQ3tgAB9jv3la+Dd8ZbZysgBME/
         KkOBgYMw+D/1Kpzxvy+/y5HyspnvstLokeg2/f0eZU8a4VRYsOPhf8QPdKUwhOtWk/HB
         EJgQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756119528; x=1756724328; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EcwH1D3fpC0c4yqh48xjI9YRHTkqedLwqPzUW0wv1SI=;
        b=dtkD7Qy6dCUD/p8vguV0FOUzf50LZ0kGUFLOyJq+BNZknetc29fLGl+Y78eUA1X8MI
         tDfXxme2gwwDUSaoryExJwwQBdR0yzdBmHwRfKOaHGh+7R5iCqL66O43hAwh2pYGYlwI
         UGdKqNOuQb4zzCOY8tc3kV5JSNF7dl6Z/v+s8qWc5wZfmR50xbc5/Q6nvHyVNn0GeUVd
         p6jeHlsfF4Igqlj7JAcxHWVvzYqYDcS2kCBQVPz/sVMgL8/v6BxVw0v3iiPicCuJUbbR
         8Qibp+2rUscKuYM5IcJ32FeM8VrDTIvUMsEaeX3rcnJoRMH0+3jZd2eb8Zb7Sg8advxd
         g9ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756119528; x=1756724328;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=EcwH1D3fpC0c4yqh48xjI9YRHTkqedLwqPzUW0wv1SI=;
        b=uuSMmT3DaQlBWuBmPxNGrwZDnUT0n9L8sQaldjx93jvUd5yTnUidzF101k914vt1PP
         RMYsRBLWsMdfj5ArDMDrhNd1EdVqwAs5fmsARjdjtA/aOsTwJaQyi6DrGKbWg+HvuGPB
         U8dXtapIPTaNU8vLrVH16E6bTlm4NUUzZSQkRW56Gqwi92jv/nUAgMk4G3k+1EkDSDHC
         FWN2Ge/XuYZybKVOroRB2aNJGeo9cypA1v9Lx7GCHQ4PBw5c3Gl+rhvbd4wUA/BaZqYk
         6qLNDtMM/r2SEUmSLRCBoz9oZqL1A412vmQWw/lpPyqTThI4IlBLSJJZhvr8P1nXLucX
         Ltag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCXteb0U6I687CqfVQh/YohuSc7t8XNJmi4WCY5FqlGLiqd8EyRRBz/1M4JWQIM9pfpF5fAkHQ==@lfdr.de
X-Gm-Message-State: AOJu0YwpLjFj9lCfMaXYCI0ahg9JWCyMh3qYxYQuM9Pc6ilFikAEpOrs
	3kYxSo0zc3Vl6h0CqNjfOqeWXNSpBMugbQgVDmsDA7YsIUhwxVs1vw8U
X-Google-Smtp-Source: AGHT+IFAIZmbqHiPXF1DtYSkTpEzLekc31EVqMdp5B19T8xn4jN0/8TlS6IxEOcD5tG6kCL1Hof3VQ==
X-Received: by 2002:a05:6820:1ca9:b0:61b:7ce1:87d6 with SMTP id 006d021491bc7-61db9b7b61emr5062008eaf.6.1756119528022;
        Mon, 25 Aug 2025 03:58:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfDLixDeocBjw6ohjfQPpDJACmIUImVULkCvGnUvE0G3Q==
Received: by 2002:a05:6820:a85:b0:61b:d155:e334 with SMTP id
 006d021491bc7-61da8a88d9als101453eaf.0.-pod-delta-03-us; Mon, 25 Aug 2025
 03:58:46 -0700 (PDT)
X-Received: by 2002:a05:6808:f16:b0:42b:5945:63db with SMTP id 5614622812f47-43785358157mr2477815b6e.6.1756119526161;
        Mon, 25 Aug 2025 03:58:46 -0700 (PDT)
Date: Mon, 25 Aug 2025 03:58:45 -0700 (PDT)
From: =?UTF-8?B?2LPYp9mK2KrZiNiq2YMg2KfZhNiz2LnZiNiv2YrZhw==?=
 =?UTF-8?B?INiz2KfZitiq2YjYqtmDINio2K7YtdmFIDIwJQ==?=
 <mnalmagtereb@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <6176715f-7263-48f1-863c-85b8f345520dn@googlegroups.com>
In-Reply-To: <412ffb42-69a2-4d34-9ea5-6aa53dd58711n@googlegroups.com>
References: <412ffb42-69a2-4d34-9ea5-6aa53dd58711n@googlegroups.com>
Subject: =?UTF-8?B?UmU6INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNix2YrYp9i2?=
 =?UTF-8?B?IDA1Mzc0NjY1MzkgI9in2YTYs9i52YjYr9mK2Kk=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_510754_1948628365.1756119525394"
X-Original-Sender: mnalmagtereb@gmail.com
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

------=_Part_510754_1948628365.1756119525394
Content-Type: multipart/alternative; 
	boundary="----=_Part_510755_362896.1756119525394"

------=_Part_510755_362896.1756119525394
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2K/Zg9iq2YjYsdipINin2KzZh9in2LYg2YHZiiDYp9mE2LPYudmI2K/ZitmHIHwgMDA5NjY1Mzgx
NTk3NDcgfNi52YrYp9iv2Kkg2LPYp9mK2KrZiNiq2YMgCgog2K/Zg9iq2YjYsdipINmG2YrYsdmF
2YrZhiDZhNmE2KfYs9iq2LTYp9ix2KfYqiDYp9mE2LfYqNmK2KkK2K3YqNmI2Kgg2KfZhNin2KzZ
h9in2LYg4oCTINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqSAgfCDYr9mD2KrZ
iNix2Kkg2YbZitix2YXZitmGIDAwOTY2NTM4MTU5NzQ3IOKAkyAK2KfYs9iq2LTYp9ix2KfYqiDZ
iNi52YTYp9isINii2YXZhgrYqti52LHZgdmKINi52YTZiSDZg9mEINmF2Kcg2YrZh9mF2YMg2LnZ
hiDYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiDYjCDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i5
2YjYr9mK2YcgCjxodHRwczovL2hheWF0YW5uYXMuY29tLz9zcnNsdGlkPUFmbUJPb29yWFR2Nndj
dGJZN29DYmRfelJCTXhORFBtVDBGNURQUnd6TWlmQ01nREROTnAxY2JWPiAK2KfZhNix2YrYp9i2
2Iwg2KzYr9ip2Iwg2YXZg9ip2Iwg2KzYp9iy2KfZhtiMINmI2K7ZhdmK2LMg2YXYtNmK2LfYjCDZ
hdi5INiv2YPYqtmI2LHYqSDZhtmK2LHZhdmK2YYg2YTZhNin2LPYqti02KfYsdin2Kog2KfZhNi3
2KjZitipIArZiNi32YTYqCDYp9mE2LnZhNin2Kwg2KjYs9ix2YrYqSDYqtin2YXYqS4K2KrYrdiw
2YrYsdin2Kog2YXZh9mF2KkKCtmK2YXZhti5INin2LPYqtiu2K/Yp9mFINit2KjZiNioINiz2KfZ
itiq2YjYqtmDINmB2Yog2K3Yp9mE2KfYqiDYp9mE2K3ZhdmEINin2YTZhdiq2YLYr9mFINio2LnY
ryDYp9mE2KPYs9io2YjYuSAxMiDYpdmE2Kcg2KjYo9mF2LEgCtin2YTYt9io2YrYqCDZiNin2YTY
p9iz2KrZhdin2Lkg2KfZhNmKINiq2YjYrNmK2YfYp9iq2YcgLgoKCiDYrdio2YjYqCDYs9in2YrY
qtmI2KrZgyB8IDAwOTY2NTM4MTU5NzQ3ICB8INmB2Yog2KfZhNiz2LnZiNiv2YrYqSDigJMg2K/Z
g9iq2YjYsdipINmG2YrYsdmF2YrZhiDZhNmE2KfYs9iq2LTYp9ix2KfYqiAK2KfZhNi32KjZitip
INin2YTYpdis2YfYp9i2ICDZgdmKINin2YTYs9mG2YjYp9iqINin2YTYo9iu2YrYsdip2Iwg2KPY
tdio2K0g2YXZiNi22YjYuSDYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiDYs9in2YrYqtmI2KrZgyAK
PGh0dHBzOi8vc2F1ZGllcnNhYS5jb20vPiDZgdmKINin2YTYs9i52YjYr9mK2Kkg2YXZhiDYo9mD
2KvYsSDYp9mE2YXZiNin2LbZiti5INin2YTYqtmKINiq2KjYrdirINi52YbZh9inIArYp9mE2LPZ
itiv2KfYqtiMINiu2KfYtdipINmB2Yog2YXYr9mGINmF2KvZhCDYp9mE2LHZitin2LbYjCDYrNiv
2KnYjCDZhdmD2KnYjCDYrNin2LLYp9mG2Iwg2YjYrtmF2YrYsyDZhdi02YrYt9iMINmI2YPYsNmE
2YMg2YHZiiAK2YXZhtin2LfZgiDYp9mE2K7ZhNmK2Kwg2YXYq9mEINin2YTYqNit2LHZitmGINmI
2KfZhNmD2YjZitiqINmI2KfZhNi02KfYsdmC2KkuINmG2LjYsdmL2Kcg2YTYrdiz2KfYs9mK2Kkg
2KfZhNmF2YjYttmI2Lkg2YjYo9mH2YXZitiq2YfYjCAK2KrZgtiv2YUg2K/Zg9iq2YjYsdipINmG
2YrYsdmF2YrZhiDYp9mE2K/YudmFINin2YTYt9io2Yog2YjYp9mE2KfYs9iq2LTYp9ix2KfYqiDY
p9mE2YXYqtiu2LXYtdipINmE2YTZhtiz2KfYoSDYp9mE2YTZiNin2KrZiiDZitit2KrYrNmGIArY
pdmE2Ykg2KfZhNiq2YjYrNmK2Ycg2KfZhNi12K3ZititINmI2LfZhNioINin2YTYudmE2KfYrCDZ
hdmGINmF2LXYr9ixINmF2YjYq9mI2YLYjCDYudio2LEg2KfZhNin2KrYtdin2YQg2LnZhNmJINin
2YTYsdmC2YU6IDAwOTY2NTM4MTU5NzQ3IAoKCtmB2Yog2KfZhNij2K3Yr9iMIDE3INij2LrYs9i3
2LMgMjAyNSDZgdmKINiq2YXYp9mFINin2YTYs9in2LnYqSAxMToxOToyOSDYtSBVVEMrM9iMINmD
2KrYqCDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDigJMgCtmG2LPYqNipINmG2KzYp9itIDk12aog
2LHYs9in2YTYqSDZhti12YfYpzoKCj4g2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LHZitin2LYg
MDUzNzQ2NjUzOSAj2KfZhNiz2LnZiNiv2YrYqSDZhNmE2KXYrNmH2KfYtiDYp9mE2KLZhdmGINmF
2Lkg2K8uINmG2YrYsdmF2YrZhiB8IHwgCj4g2KfZhNix2YrYp9i2INis2K/YqSDZhdmD2Kkg2KfZ
hNiv2YXYp9mFCj4KPiDYp9mD2KrYtNmB2Yog2YXYuSDYry4g2YbZitix2YXZitmG2Iwg2KfZhNmI
2YPZitmEINin2YTYsdiz2YXZiiDZhNit2KjZiNioINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz
2LnZiNiv2YrYqdiMINmD2YrZgdmK2KkgCj4g2KfZhNil2KzZh9in2LYg2KfZhNi32KjZiiDYp9mE
2KLZhdmGINio2KfYs9iq2K7Yr9in2YUg2LPYp9mK2KrZiNiq2YMgMjAwIChNaXNvcHJvc3RvbCkg
2KjYpdi02LHYp9mBINi32KjZiiDZiNiz2LHZkdmK2KkgCj4g2KrYp9mF2KkuINiq2YjYtdmK2YQg
2LPYsdmK2Lkg2YHZiiDYp9mE2LHZitin2LbYjCDYrNiv2KnYjCDZhdmD2KnYjCDYp9mE2K/Zhdin
2YUg2YjYqNin2YLZiiDYp9mE2YXYr9mGLiDwn5OeIDA1Mzc0NjY1MzkKPgo+INmB2Yog2KfZhNiz
2YbZiNin2Kog2KfZhNij2K7Zitix2KnYjCDYo9i12KjYrdiqINit2KjZiNioINiz2KfZitiq2YjY
qtmDIDxodHRwczovL2tzYWN5dG90ZWMuY29tLz4gCj4gKE1pc29wcm9zdG9sKSDYrtmK2KfYsdmL
2Kcg2LfYqNmK2YvYpyDZhdi52LHZiNmB2YvYpyDZiNmB2LnZkdin2YTZi9inINmE2KXZhtmH2KfY
oSDYp9mE2K3ZhdmEINin2YTZhdio2YPYsSDYqNi32LHZitmC2KkgCj4g2KLZhdmG2Kkg2KrYrdiq
INil2LTYsdin2YEg2YXYrtiq2LXZitmGLiDZiNmF2Lkg2KfZhtiq2LTYp9ixINin2YTZhdmG2KrY
rNin2Kog2KfZhNmF2YLZhNiv2KnYjCDYo9i12KjYrSDZhdmGINin2YTYttix2YjYsdmKINin2YTY
rdi12YjZhCAKPiDYudmE2Ykg2KfZhNiv2YjYp9ihINmF2YYg2YXYtdiv2LEg2YXZiNir2YjZgiDZ
iNmF2LnYqtmF2K8uCj4g2K8uINmG2YrYsdmF2YrZhtiMINio2LXZgdiq2YfYpyDYp9mE2YjZg9mK
2YQg2KfZhNix2LPZhdmKINmE2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI
2K/Zitip2Iwg2KrZgtiv2YUg2YTZg9mQIAo+INmF2YbYqtis2YvYpyDYo9i12YTZitmL2Kcg2KjY
rNmI2K/YqSDZhdi22YXZiNmG2KnYjCDZhdi5INin2LPYqti02KfYsdipINi32KjZitipINmF2KrY
rti12LXYqSDZiNiz2LHZkdmK2Kkg2KrYp9mF2Kkg2YHZiiDYp9mE2KrYudin2YXZhCAKPiDZiNin
2YTYqtmI2LXZitmELgo+Cj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4KPiDZhdin
INmH2Ygg2K/ZiNin2KEg2LPYp9mK2KrZiNiq2YPYnwo+Cj4g2LPYp9mK2KrZiNiq2YMgKNin2YTZ
hdin2K/YqSDYp9mE2YHYudin2YTYqSDZhdmK2LLZiNio2LHZiNiz2KrZiNmEKSDYr9mI2KfYoSDZ
hdmP2LnYqtmF2K8g2YHZiiDYp9mE2YXYrNin2YQg2KfZhNi32KjZitiMIAo+INmI2YrZj9iz2KrY
rtiv2YUg2KjYrNix2LnYp9iqINiv2YLZitmC2Kkg2YTYpdmG2YfYp9ihINin2YTYrdmF2YQg2KfZ
hNmF2KjZg9ix2Iwg2YjYudmE2KfYrCDYrdin2YTYp9iqINi32KjZitipINij2K7YsdmJINmF2KvZ
hCDZgtix2K3YqSAKPiDYp9mE2YXYudiv2KkuINi52YbYryDYp9iz2KrYrtiv2KfZhdmHINmE2YTY
pdis2YfYp9i22Iwg2YrYudmF2YQg2LnZhNmJINiq2K3ZgdmK2LIg2KrZgtmE2LXYp9iqINin2YTY
sdit2YUg2YjYpdmB2LHYp9i6INmF2K3YqtmI2YrYp9iq2YcgCj4g2K7ZhNin2YQg2YHYqtix2Kkg
2YLYtdmK2LHYqdiMINmF2YXYpyDZitis2LnZhNmHINiu2YrYp9ix2YvYpyDZgdi52KfZhNmL2Kcg
2YjYotmF2YbZi9inINi52YbYryDYpdi02LHYp9mBINi32KjZitioINmF2K7Yqti1Lgo+Cj4gLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4KPiDYo9mH2YXZitipINin2YTYrdi12YjZhCDY
udmE2Ykg2LPYp9mK2KrZiNiq2YMg2YXZhiDZhdi12K/YsSDZhdmI2KvZiNmCCj4KPiDZgdmKINin
2YTYs9i52YjYr9mK2KnYjCDYqtiq2YjYp9is2K8g2KfZhNmD2KvZitixINmF2YYg2KfZhNmC2YbZ
iNin2Kog2LrZitixINin2YTZhdmI2KvZiNmC2Kkg2KfZhNiq2Yog2KrYqNmK2Lkg2YXZhtiq2KzY
p9iqINmF2KzZh9mI2YTYqSAKPiDYp9mE2YXYtdiv2LEg2YLYryDYqtik2K/ZiiDYpdmE2Ykg2YXY
rtin2LfYsSDYtdit2YrYqSDYrNiz2YrZhdipLgo+INivLiDZhtmK2LHZhdmK2YYg2KrYttmF2YYg
2YTZgzoKPiDinJTvuI8g2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KPYtdmE2YrYqSAxMDAlCj4g
4pyU77iPINiq2KfYsdmK2K4g2LXZhNin2K3ZitipINit2K/ZitirCj4g4pyU77iPINil2LHYtNin
2K/Yp9iqINi32KjZitipINiv2YLZitmC2Kkg2YTZhNin2LPYqtiu2K/Yp9mFCj4g4pyU77iPINiz
2LHZkdmK2Kkg2KrYp9mF2Kkg2YHZiiDYp9mE2KrZiNi12YrZhAo+IOKclO+4jyDYr9i52YUg2YjY
p9iz2KrYtNin2LHYqSDYudmE2Ykg2YXYr9in2LEg2KfZhNiz2KfYudipCj4KPiAtLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0KPgo+INmE2YXYp9iw2Kcg2KrYrtiq2KfYsdmK2YYg2K8uINmG
2YrYsdmF2YrZhtifCj4gICAgCj4gICAgLSAKPiAgICAKPiAgICDYp9mE2K7YqNix2Kkg2KfZhNi3
2KjZitipOiDYry4g2YbZitix2YXZitmGINmF2KrYrti12LXYqSDZgdmKINin2YTYp9iz2KrYtNin
2LHYp9iqINin2YTYt9io2YrYqSDYp9mE2YbYs9in2KbZitip2Iwg2YjYqtmC2K/ZhSAKPiAgICDZ
hNmD2ZAg2K/YudmF2YvYpyDZhdmH2YbZitmL2Kcg2YLYqNmEINmI2KPYq9mG2KfYoSDZiNio2LnY
r9in2LPYqtiu2K/Yp9mFINiz2KfZitiq2YjYqtmDIAo+ICAgIDxodHRwczovL3NhdWRpZXJzYWEu
Y29tLz4uCj4gICAgCj4gICAgLSAKPiAgICAKPiAgICDYp9mE2KrZiNi12YrZhCDYp9mE2LPYsdmK
2Lk6INiq2LrYt9mK2Kkg2YTYrNmF2YrYuSDYp9mE2YXYr9mGINin2YTYs9i52YjYr9mK2KnYjCDY
qNmF2Kcg2YHZiiDYsNmE2YMg2KfZhNix2YrYp9i22Iwg2KzYr9ip2IwgCj4gICAg2YXZg9ip2Iwg
2KfZhNiv2YXYp9mF2Iwg2KfZhNiu2KjYsdiMINin2YTYt9in2KbZgSDZiNi62YrYsdmH2KcuCj4g
ICAgCj4gICAgLSAKPiAgICAKPiAgICDYrdmF2KfZitipINiu2LXZiNi12YrYqtmDOiDZitiq2YUg
2KfZhNiq2LrZhNmK2YEg2KjYt9ix2YrZgtipINiq2LbZhdmGINin2YTYs9ix2ZHZitipINin2YTZ
g9in2YXZhNipLgo+ICAgIAo+ICAgIC0gCj4gICAgCj4gICAg2KfZhNiq2YjZg9mK2YQg2KfZhNix
2LPZhdmKOiDYtNix2KfYodmDINmK2KrZhSDZhdio2KfYtNix2Kkg2YXZhiDYp9mE2YXYtdiv2LEg
2KfZhNmF2LnYqtmF2K/YjCDYqNi52YrYr9mL2Kcg2LnZhiDYp9mE2YXYrtin2LfYsS4KPiAgICAK
PiAgICAKPiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KPgo+INmD2YrZgdmK2Kkg2LfZ
hNioINit2KjZiNioINiz2KfZitiq2YjYqtmDINmF2YYg2K8uINmG2YrYsdmF2YrZhgo+ICAgIAo+
ICAgIDEuIAo+ICAgIAo+ICAgINin2YTYqtmI2KfYtdmEINi52KjYsSDZiNin2KrYs9in2Kgg2LnZ
hNmJINin2YTYsdmC2YU6IPCfk54gMDUzNzQ2NjUzOQo+ICAgIAo+ICAgIDIuIAo+ICAgIAo+ICAg
INi02LHYrSDYp9mE2K3Yp9mE2Kkg2KfZhNi12K3ZitipINmI2YHYqtix2Kkg2KfZhNit2YXZhC4K
PiAgICAKPiAgICAzLiAKPiAgICAKPiAgICDYp9iz2KrZhNin2YUg2KfZhNil2LHYtNin2K/Yp9iq
INin2YTYt9io2YrYqSDYp9mE2YXZhtin2LPYqNipINmI2KfZhNis2LHYudipINin2YTZhdmI2LXZ
iSDYqNmH2KcuCj4gICAgCj4gICAgNC4gCj4gICAgCj4gICAg2KfYs9iq2YTYp9mFINin2YTYrdio
2YjYqCDYrtmE2KfZhCDZgdiq2LHYqSDZgti12YrYsdipINi52KjYsSDYrtiv2YXYqSDYqtmI2LXZ
itmEINii2YXZhtipINmI2LPYsdmK2KkuCj4gICAgCj4gICAgCj4gLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tCj4KPiDYqtmG2KjZitmHINi32KjZiiDZhdmH2YUKPiAgICAKPiAgICAtIAo+
ICAgIAo+ICAgINmK2KzYqCDYp9iz2KrYrtiv2KfZhSDYs9in2YrYqtmI2KrZgyDZgdmC2Lcg2KrY
rdiqINil2LTYsdin2YEg2LfYqNmKINmF2K7Yqti1Lgo+ICAgIAo+ICAgIC0gCj4gICAgCj4gICAg
2YTYpyDZitmP2YbYtditINio2KfYs9iq2K7Yr9in2YXZhyDZgdmKINit2KfZhNin2Kog2KfZhNit
2YXZhCDYp9mE2YXYqtij2K7YsS4KPiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINmB2Yog2K3Yp9mE
INmI2KzZiNivINij2YXYsdin2LYg2YXYstmF2YbYqSDYo9mIINit2KfZhNin2Kog2K7Yp9i12KnY
jCDZitis2Kgg2KfYs9iq2LTYp9ix2Kkg2KfZhNi32KjZitioINmC2KjZhCAKPiAgICDYp9mE2KfY
s9iq2K7Yr9in2YUuCj4gICAgCj4gICAgCj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
Cj4KPiDYrtiv2YXYp9iqINil2LbYp9mB2YrYqSDZhdmGINivLiDZhtmK2LHZhdmK2YYKPiAgICAK
PiAgICAtIAo+ICAgIAo+ICAgINmF2KrYp9io2LnYqSDYp9mE2K3Yp9mE2Kkg2KjYudivINin2YTY
p9iz2KrYrtiv2KfZhS4KPiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINiq2YjZgdmK2LEg2YXYudmE
2YjZhdin2Kog2K3ZiNmEINin2YTYotir2KfYsSDYp9mE2KzYp9mG2KjZitipINin2YTYt9io2YrY
udmK2Kkg2YjZg9mK2YHZitipINin2YTYqti52KfZhdmEINmF2LnZh9inLgo+ICAgIAo+ICAgIC0g
Cj4gICAgCj4gICAg2KXYsdi02KfYryDYp9mE2YXYsdmK2LbYqSDYpdmE2Ykg2KPZgdi22YQg2YXZ
hdin2LHYs9in2Kog2KfZhNiz2YTYp9mF2Kkg2KfZhNi32KjZitipLgo+ICAgIAo+ICAgIAo+IC0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Cj4g2K7ZhNin2LXYqQo+Cj4g2KfYrtiq2YrY
p9ixINin2YTZhdi12K/YsSDYp9mE2YXZiNir2YjZgiDYudmG2K8g2LTYsdin2KEg2K3YqNmI2Kgg
2LPYp9mK2KrZiNiq2YMgCj4gPGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vYS9jaHJvbWl1bS5v
cmcvZy9zZWN1cml0eS1kZXYvYy9yaHJQcGl2Q1FHTS9tL1hpaFVCaVNMQUFBSj4gCj4g2YHZiiDY
p9mE2LPYudmI2K/ZitipINmH2Ygg2KfZhNi22YXYp9mGINin2YTZiNit2YrYryDZhNiz2YTYp9mF
2KrZg9mQLgo+INmF2Lkg2K8uINmG2YrYsdmF2YrZhtiMINiz2KrYrdi12YTZitmGINi52YTZiSDY
p9mE2YXZhtiq2Kwg2KfZhNij2LXZhNmK2Iwg2KfZhNil2LHYtNin2K8g2KfZhNi32KjZiiDYp9mE
2YXYqtiu2LXYtdiMINmI2KfZhNiq2YjYtdmK2YQgCj4g2KfZhNiz2LHZiiDYo9mK2YbZhdinINmD
2YbYqtmQINmB2Yog2KfZhNmF2YXZhNmD2KkuCj4KPiDwn5OeINmE2YTYqtmI2KfYtdmEINmI2KfZ
hNi32YTYqCDYudio2LEg2YjYp9iq2LPYp9ioOiAwNTM3NDY2NTM5Cj4g2KfZhNmF2K/ZhiDYp9mE
2YXYuti32KfYqTog2KfZhNix2YrYp9i2IOKAkyDYrNiv2Kkg4oCTINmF2YPYqSDigJMg2KfZhNiv
2YXYp9mFIOKAkyDYp9mE2K7YqNixIOKAkyDYp9mE2LfYp9im2YEg4oCTINin2YTZhdiv2YrZhtip
IAo+INin2YTZhdmG2YjYsdipIOKAkyDYo9io2YfYpyDigJMg2KzYp9iy2KfZhiDigJMg2KrYqNmI
2YMuCj4KPiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KPgo+ICAKPgo+INiz2KfZitiq
2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqdiMINiz2KfZitiq2YjYqtmDINin2YTYsdmK2KfY
ttiMINiz2KfZitiq2YjYqtmDINis2K/YqdiMINiz2KfZitiq2YjYqtmDINmF2YPYqdiMINiz2KfZ
itiq2YjYqtmDIAo+INin2YTYr9mF2KfZhdiMINi02LHYp9ihINiz2KfZitiq2YjYqtmDINmB2Yog
2KfZhNiz2LnZiNiv2YrYqdiMINit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2YTYpdis2YfYp9i2
2Iwg2LPYp9mK2KrZiNiq2YMg2KPYtdmE2YrYjCAKPiDYs9in2YrYqtmI2KrZgyAyMDDYjCBNaXNv
cHJvc3RvbCDYp9mE2LPYudmI2K/Zitip2Iwg2LPYp9mK2KrZiNiq2YMg2KfZhNmG2YfYr9mK2Iwg
aHR0cHM6Ly9rc2FjeXRvdGVjLmNvbS8gCj4g2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2K/Zg9iq
2YjYsdipINmG2YrYsdmF2YrZhiDYs9in2YrYqtmI2KrZgy4KPgo+INiz2KfZitiq2YjYqtmDINmB
2Yog2KfZhNiz2LnZiNiv2YrYqdiMINiz2KfZitiq2YjYqtmDINin2YTYsdmK2KfYttiMINiz2KfZ
itiq2YjYqtmDINis2K/YqdiMINiz2KfZitiq2YjYqtmDINmF2YPYqdiMINiz2KfZitiq2YjYqtmD
IAo+INin2YTYr9mF2KfZhdiMINi02LHYp9ihINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZ
iNiv2YrYqdiMINit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2YTYpdis2YfYp9i22Iwg2LPYp9mK
2KrZiNiq2YMg2KPYtdmE2YrYjCAKPiDYs9in2YrYqtmI2KrZgyAyMDDYjCBNaXNvcHJvc3RvbCDY
p9mE2LPYudmI2K/Zitip2Iwg2LPYp9mK2KrZiNiq2YMg2KfZhNmG2YfYr9mK2Iwg2KfZhNil2KzZ
h9in2LYg2KfZhNi32KjZiiDZgdmKIAo+INin2YTYs9i52YjYr9mK2KnYjCDYr9mD2KrZiNix2Kkg
2YbZitix2YXZitmGINiz2KfZitiq2YjYqtmDLgo+Cj4NCg0KLS0gCllvdSByZWNlaXZlZCB0aGlz
IG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMg
Imthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3Rv
cCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vu
c3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIHZpc2l0
IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvNjE3NjcxNWYtNzI2
My00OGYxLTg2M2MtODViOGYzNDU1MjBkbiU0MGdvb2dsZWdyb3Vwcy5jb20uCg==
------=_Part_510755_362896.1756119525394
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<span dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; margin-botto=
m: 4pt;"><span style=3D"font-size: 13pt; font-family: Arial, sans-serif; co=
lor: rgb(73, 80, 87); background-color: transparent; font-weight: 700; font=
-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alt=
ernates: normal; font-variant-position: normal; font-variant-emoji: normal;=
 vertical-align: baseline; white-space-collapse: preserve;">=D8=AF=D9=83=D8=
=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=
=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 | </span><span style=3D"font-size: =
12pt; font-family: Arial, sans-serif; color: rgb(51, 51, 51); font-weight: =
700; font-variant-numeric: normal; font-variant-east-asian: normal; font-va=
riant-alternates: normal; font-variant-position: normal; font-variant-emoji=
: normal; vertical-align: baseline; white-space-collapse: preserve;">009665=
38159747 </span><span style=3D"font-size: 13pt; font-family: Arial, sans-se=
rif; color: rgb(73, 80, 87); background-color: transparent; font-weight: 70=
0; font-variant-numeric: normal; font-variant-east-asian: normal; font-vari=
ant-alternates: normal; font-variant-position: normal; font-variant-emoji: =
normal; vertical-align: baseline; white-space-collapse: preserve;">|=D8=B9=
=D9=8A=D8=A7=D8=AF=D8=A9 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=C2=A0</=
span></span><p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; mar=
gin-bottom: 12pt;"><span style=3D"font-size: 11.5pt; font-family: Arial, sa=
ns-serif; color: rgb(73, 80, 87); background-color: transparent; font-weigh=
t: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font=
-variant-alternates: normal; font-variant-position: normal; font-variant-em=
oji: normal; vertical-align: baseline; white-space-collapse: preserve;">=C2=
=A0=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=
=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=
=84=D8=B7=D8=A8=D9=8A=D8=A9</span><span style=3D"font-size: 11.5pt; font-fa=
mily: Arial, sans-serif; color: rgb(73, 80, 87); background-color: transpar=
ent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asia=
n: normal; font-variant-alternates: normal; font-variant-position: normal; =
font-variant-emoji: normal; vertical-align: baseline; white-space-collapse:=
 preserve;"><br /></span><span style=3D"font-size: 11.5pt; font-family: Ari=
al, sans-serif; color: rgb(73, 80, 87); background-color: transparent; font=
-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal=
; font-variant-alternates: normal; font-variant-position: normal; font-vari=
ant-emoji: normal; vertical-align: baseline; white-space-collapse: preserve=
;">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =E2=
=80=93 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=
=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=C2=A0 | =D8=AF=D9=83=D8=AA=D9=88=D8=B1=
=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 </span><span style=3D"font-size=
: 12pt; font-family: Arial, sans-serif; color: rgb(51, 51, 51); font-weight=
: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-=
variant-alternates: normal; font-variant-position: normal; font-variant-emo=
ji: normal; vertical-align: baseline; white-space-collapse: preserve;">0096=
6538159747 </span><span style=3D"font-size: 11.5pt; font-family: Arial, san=
s-serif; color: rgb(73, 80, 87); background-color: transparent; font-weight=
: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-=
variant-alternates: normal; font-variant-position: normal; font-variant-emo=
ji: normal; vertical-align: baseline; white-space-collapse: preserve;">=E2=
=80=93 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D9=88=D8=B9=D9=84=
=D8=A7=D8=AC =D8=A2=D9=85=D9=86</span><span style=3D"font-size: 11.5pt; fon=
t-family: Arial, sans-serif; color: rgb(73, 80, 87); background-color: tran=
sparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-=
asian: normal; font-variant-alternates: normal; font-variant-position: norm=
al; font-variant-emoji: normal; vertical-align: baseline; white-space-colla=
pse: preserve;"><br /></span><span style=3D"font-size: 11.5pt; font-family:=
 Arial, sans-serif; color: rgb(73, 80, 87); background-color: transparent; =
font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: no=
rmal; font-variant-alternates: normal; font-variant-position: normal; font-=
variant-emoji: normal; vertical-align: baseline; white-space-collapse: pres=
erve;">=D8=AA=D8=B9=D8=B1=D9=81=D9=8A =D8=B9=D9=84=D9=89 =D9=83=D9=84 =D9=
=85=D8=A7 =D9=8A=D9=87=D9=85=D9=83 =D8=B9=D9=86 =D8=AD=D8=A8=D9=88=D8=A8 =
=D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=8C </span><a href=3D"https:/=
/hayatannas.com/?srsltid=3DAfmBOoorXTv6wctbY7oCbd_zRBMxNDPmT0F5DPRwzMifCMgD=
DNNp1cbV"><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif;=
 color: rgb(255, 152, 0); background-color: transparent; font-weight: 700; =
font-variant-numeric: normal; font-variant-east-asian: normal; font-variant=
-alternates: normal; font-variant-position: normal; font-variant-emoji: nor=
mal; vertical-align: baseline; white-space-collapse: preserve;">=D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=
=88=D8=AF=D9=8A=D9=87</span></a><span style=3D"font-size: 11.5pt; font-fami=
ly: Arial, sans-serif; color: rgb(73, 80, 87); background-color: transparen=
t; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian:=
 normal; font-variant-alternates: normal; font-variant-position: normal; fo=
nt-variant-emoji: normal; vertical-align: baseline; white-space-collapse: p=
reserve;"> =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=
=8C =D9=85=D9=83=D8=A9=D8=8C =D8=AC=D8=A7=D8=B2=D8=A7=D9=86=D8=8C =D9=88=D8=
=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7=D8=8C =D9=85=D8=B9 =D8=AF=D9=
=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=84=D9=
=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=
=A8=D9=8A=D8=A9 =D9=88=D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=
=AC =D8=A8=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9.</span></p><spa=
n dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; margin-bottom: 4=
pt;"><span style=3D"font-size: 17pt; font-family: Arial, sans-serif; color:=
 rgb(255, 0, 0); background-color: transparent; font-weight: 700; font-vari=
ant-numeric: normal; font-variant-east-asian: normal; font-variant-alternat=
es: normal; font-variant-position: normal; font-variant-emoji: normal; vert=
ical-align: baseline; white-space-collapse: preserve;">=D8=AA=D8=AD=D8=B0=
=D9=8A=D8=B1=D8=A7=D8=AA =D9=85=D9=87=D9=85=D8=A9</span></span><p dir=3D"rt=
l" style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 12pt;"><span=
 style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(255=
, 0, 0); background-color: transparent; font-weight: 700; font-variant-nume=
ric: normal; font-variant-east-asian: normal; font-variant-alternates: norm=
al; font-variant-position: normal; font-variant-emoji: normal; vertical-ali=
gn: baseline; white-space-collapse: preserve;">=D9=8A=D9=85=D9=86=D8=B9 =D8=
=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=
=AA =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=D9=
=85 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 12 =D8=A5=
=D9=84=D8=A7 =D8=A8=D8=A3=D9=85=D8=B1 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =
=D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=85=D8=A7=D8=B9 =D8=A7=D9=84=D9=8A =
=D8=AA=D9=88=D8=AC=D9=8A=D9=87=D8=A7=D8=AA=D9=87 .</span></p><br /><br /><s=
pan dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; margin-bottom:=
 2pt;"><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; colo=
r: rgb(73, 80, 87); background-color: transparent; font-weight: 700; font-v=
ariant-numeric: normal; font-variant-east-asian: normal; font-variant-alter=
nates: normal; font-variant-position: normal; font-variant-emoji: normal; v=
ertical-align: baseline; white-space-collapse: preserve;">=C2=A0=D8=AD=D8=
=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 | </span><span s=
tyle=3D"font-size: 12pt; font-family: Arial, sans-serif; color: rgb(51, 51,=
 51); font-weight: 700; font-variant-numeric: normal; font-variant-east-asi=
an: normal; font-variant-alternates: normal; font-variant-position: normal;=
 font-variant-emoji: normal; vertical-align: baseline; white-space-collapse=
: preserve;">00966538159747 </span><span style=3D"font-size: 11pt; font-fam=
ily: Arial, sans-serif; color: rgb(73, 80, 87); background-color: transpare=
nt; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian=
: normal; font-variant-alternates: normal; font-variant-position: normal; f=
ont-variant-emoji: normal; vertical-align: baseline; white-space-collapse: =
preserve;">=C2=A0| =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=
=D8=A9 =E2=80=93 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=
=85=D9=8A=D9=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=
=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=
=A7=D8=B6=C2=A0=C2=A0</span></span><span style=3D"font-size: 11.5pt; font-f=
amily: Arial, sans-serif; color: rgb(73, 80, 87); background-color: transpa=
rent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asi=
an: normal; font-variant-alternates: normal; font-variant-position: normal;=
 font-variant-emoji: normal; vertical-align: baseline; white-space-collapse=
: preserve;">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D9=86=D9=88=D8=A7=D8=AA =D8=A7=
=D9=84=D8=A3=D8=AE=D9=8A=D8=B1=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD =D9=85=
=D9=88=D8=B6=D9=88=D8=B9 </span><a href=3D"https://saudiersaa.com/"><span s=
tyle=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(255, =
152, 0); background-color: transparent; font-weight: 700; font-variant-nume=
ric: normal; font-variant-east-asian: normal; font-variant-alternates: norm=
al; font-variant-position: normal; font-variant-emoji: normal; vertical-ali=
gn: baseline; white-space-collapse: preserve;">=D8=AD=D8=A8=D9=88=D8=A8 =D8=
=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83</span></a><span style=3D"font-size: 11.5pt; font-family: Arial, s=
ans-serif; color: rgb(73, 80, 87); background-color: transparent; font-weig=
ht: 700; font-variant-numeric: normal; font-variant-east-asian: normal; fon=
t-variant-alternates: normal; font-variant-position: normal; font-variant-e=
moji: normal; vertical-align: baseline; white-space-collapse: preserve;"> =
=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =D9=85=D9=86 =
=D8=A3=D9=83=D8=AB=D8=B1 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B6=D9=8A=D8=B9 =
=D8=A7=D9=84=D8=AA=D9=8A =D8=AA=D8=A8=D8=AD=D8=AB =D8=B9=D9=86=D9=87=D8=A7 =
=D8=A7=D9=84=D8=B3=D9=8A=D8=AF=D8=A7=D8=AA=D8=8C =D8=AE=D8=A7=D8=B5=D8=A9 =
=D9=81=D9=8A =D9=85=D8=AF=D9=86 =D9=85=D8=AB=D9=84 =D8=A7=D9=84=D8=B1=D9=8A=
=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =D8=AC=
=D8=A7=D8=B2=D8=A7=D9=86=D8=8C =D9=88=D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=
=D9=8A=D8=B7=D8=8C =D9=88=D9=83=D8=B0=D9=84=D9=83 =D9=81=D9=8A =D9=85=D9=86=
=D8=A7=D8=B7=D9=82 =D8=A7=D9=84=D8=AE=D9=84=D9=8A=D8=AC =D9=85=D8=AB=D9=84 =
=D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D9=83=D9=88=
=D9=8A=D8=AA =D9=88=D8=A7=D9=84=D8=B4=D8=A7=D8=B1=D9=82=D8=A9. =D9=86=D8=B8=
=D8=B1=D9=8B=D8=A7 =D9=84=D8=AD=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9 =D8=A7=D9=84=
=D9=85=D9=88=D8=B6=D9=88=D8=B9 =D9=88=D8=A3=D9=87=D9=85=D9=8A=D8=AA=D9=87=
=D8=8C =D8=AA=D9=82=D8=AF=D9=85 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=
=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=A7=D9=84=D8=AF=D8=B9=D9=85 =D8=A7=D9=84=
=D8=B7=D8=A8=D9=8A =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=
=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=84=D9=84=
=D9=86=D8=B3=D8=A7=D8=A1 =D8=A7=D9=84=D9=84=D9=88=D8=A7=D8=AA=D9=8A =D9=8A=
=D8=AD=D8=AA=D8=AC=D9=86 =D8=A5=D9=84=D9=89 =D8=A7=D9=84=D8=AA=D9=88=D8=AC=
=D9=8A=D9=87 =D8=A7=D9=84=D8=B5=D8=AD=D9=8A=D8=AD =D9=88=D8=B7=D9=84=D8=A8 =
=D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =
=D9=85=D9=88=D8=AB=D9=88=D9=82=D8=8C =D8=B9=D8=A8=D8=B1 =D8=A7=D9=84=D8=A7=
=D8=AA=D8=B5=D8=A7=D9=84 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=B1=D9=82=D9=85:=
 </span><span style=3D"font-size: 12pt; font-family: Arial, sans-serif; col=
or: rgb(51, 51, 51); font-weight: 700; font-variant-numeric: normal; font-v=
ariant-east-asian: normal; font-variant-alternates: normal; font-variant-po=
sition: normal; font-variant-emoji: normal; vertical-align: baseline; white=
-space-collapse: preserve;">00966538159747 </span><br /><br /><div class=3D=
"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">=D9=81=D9=8A =D8=A7=D9=
=84=D8=A3=D8=AD=D8=AF=D8=8C 17 =D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 2025 =D9=81=
=D9=8A =D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=D8=A9 11:19:=
29 =D8=B5 UTC+3=D8=8C =D9=83=D8=AA=D8=A8 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =E2=80=93 =D9=86=D8=B3=D8=A8=D8=A9 =D9=86=
=D8=AC=D8=A7=D8=AD 95=D9=AA =D8=B1=D8=B3=D8=A7=D9=84=D8=A9 =D9=86=D8=B5=D9=
=87=D8=A7:<br/></div><blockquote class=3D"gmail_quote" style=3D"margin: 0 0=
 0 0.8ex; border-right: 1px solid rgb(204, 204, 204); padding-right: 1ex;">=
<p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt=
"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,=
0);background-color:transparent;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=
=8A=D8=A7=D8=B6 0537466539 #=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=
=A9 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=A2=D9=85=D9=
=86 =D9=85=D8=B9 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 | | =D8=A7=D9=
=84=D8=B1=D9=8A=D8=A7=D8=B6 =D8=AC=D8=AF=D8=A9 =D9=85=D9=83=D8=A9 =D8=A7=D9=
=84=D8=AF=D9=85=D8=A7=D9=85</span></p><p dir=3D"rtl" style=3D"line-height:1=
.38;margin-top:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-=
family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">=D8=A7=D9=83=D8=AA=D8=B4=D9=81=D9=8A =D9=
=85=D8=B9 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=D8=8C =D8=A7=D9=84=
=D9=88=D9=83=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A =D9=84=D8=AD=
=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =
=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D9=83=D9=8A=D9=81=
=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=B7=
=D8=A8=D9=8A =D8=A7=D9=84=D8=A2=D9=85=D9=86 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=
=D8=AF=D8=A7=D9=85 </span><span style=3D"font-size:11pt;font-family:Arial,s=
ans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83 200 (Misoprostol)</span><span style=3D"font-size:11pt;font-family:Ar=
ial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline"> =D8=A8=D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=
=A8=D9=8A =D9=88=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9. =
=D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=B3=D8=B1=D9=8A=D8=B9 =D9=81=D9=8A =D8=A7=
=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=
=D8=A9=D8=8C =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85 =D9=88=D8=A8=D8=A7=D9=82=
=D9=8A =D8=A7=D9=84=D9=85=D8=AF=D9=86. =F0=9F=93=9E 0537466539</span></p><p=
 dir=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt">=
<span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0)=
;background-color:transparent;font-variant-numeric:normal;font-variant-east=
-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=
=81=D9=8A =D8=A7=D9=84=D8=B3=D9=86=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=A3=D8=
=AE=D9=8A=D8=B1=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD=D8=AA</span><a href=3D=
"https://ksacytotec.com/" target=3D"_blank" rel=3D"nofollow" data-saferedir=
ecturl=3D"https://www.google.com/url?hl=3Dar&amp;q=3Dhttps://ksacytotec.com=
/&amp;source=3Dgmail&amp;ust=3D1756205891416000&amp;usg=3DAOvVaw1R3qLaExWJW=
75bjTKCEA7w"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;col=
or:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline"> </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;=
color:rgb(17,85,204);background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;text-decor=
ation-line:underline;vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 </sp=
an><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(17,=
85,204);background-color:transparent;font-weight:700;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;text-de=
coration-line:underline;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size:11pt;font-family:Aria=
l,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline"> (Misoprostol)</span><span style=3D=
"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-co=
lor:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;=
font-variant-alternates:normal;vertical-align:baseline"> =D8=AE=D9=8A=D8=A7=
=D8=B1=D9=8B=D8=A7 =D8=B7=D8=A8=D9=8A=D9=8B=D8=A7 =D9=85=D8=B9=D8=B1=D9=88=
=D9=81=D9=8B=D8=A7 =D9=88=D9=81=D8=B9=D9=91=D8=A7=D9=84=D9=8B=D8=A7 =D9=84=
=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=
=D9=85=D8=A8=D9=83=D8=B1 =D8=A8=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A2=D9=85=
=D9=86=D8=A9 =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D9=85=D8=AE=
=D8=AA=D8=B5=D9=8A=D9=86. =D9=88=D9=85=D8=B9 =D8=A7=D9=86=D8=AA=D8=B4=D8=A7=
=D8=B1 =D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=AC=D8=A7=D8=AA =D8=A7=D9=84=D9=85=
=D9=82=D9=84=D8=AF=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD =D9=85=D9=86 =D8=A7=
=D9=84=D8=B6=D8=B1=D9=88=D8=B1=D9=8A =D8=A7=D9=84=D8=AD=D8=B5=D9=88=D9=84 =
=D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=AF=D9=88=D8=A7=D8=A1 =D9=85=D9=86 =D9=85=
=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82 =D9=88=D9=85=D8=B9=D8=AA=
=D9=85=D8=AF.</span><span style=3D"font-size:11pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline"><br></span><span style=3D"font-size:11pt;font-family:Arial,s=
ans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=
=D9=86</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;col=
or:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">=D8=8C =D8=A8=D8=B5=D9=81=D8=AA=D9=87=D8=A7 =D8=A7=D9=84=D9=88=D9=
=83=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A =D9=84=D8=AD=D8=A8=D9=
=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=
=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AA=D9=82=D8=AF=D9=85 =D9=
=84=D9=83=D9=90 =D9=85=D9=86=D8=AA=D8=AC=D9=8B=D8=A7 =D8=A3=D8=B5=D9=84=D9=
=8A=D9=8B=D8=A7 =D8=A8=D8=AC=D9=88=D8=AF=D8=A9 =D9=85=D8=B6=D9=85=D9=88=D9=
=86=D8=A9=D8=8C =D9=85=D8=B9 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=
=B7=D8=A8=D9=8A=D8=A9 =D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=88=D8=B3=D8=
=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=
=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=88=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=
=84.</span></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;marg=
in-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;m=
argin-top:14pt;margin-bottom:4pt"><span style=3D"font-size:13pt;font-family=
:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight=
:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline">=D9=85=D8=A7 =D9=87=D9=88 =D8=
=AF=D9=88=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=D8=9F</spa=
n></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margin-bo=
ttom:12pt"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 (=D8=A7=D9=84=D9=85=D8=A7=
=D8=AF=D8=A9 =D8=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84=D8=A9 </span><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-weight:700;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=88=D9=84</span><s=
pan style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">) =D8=
=AF=D9=88=D8=A7=D8=A1 =D9=85=D9=8F=D8=B9=D8=AA=D9=85=D8=AF =D9=81=D9=8A =D8=
=A7=D9=84=D9=85=D8=AC=D8=A7=D9=84 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=8C =D9=
=88=D9=8A=D9=8F=D8=B3=D8=AA=D8=AE=D8=AF=D9=85 =D8=A8=D8=AC=D8=B1=D8=B9=D8=
=A7=D8=AA =D8=AF=D9=82=D9=8A=D9=82=D8=A9 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=
=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1=D8=
=8C =D9=88=D8=B9=D9=84=D8=A7=D8=AC =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=B7=D8=
=A8=D9=8A=D8=A9 =D8=A3=D8=AE=D8=B1=D9=89 =D9=85=D8=AB=D9=84 =D9=82=D8=B1=D8=
=AD=D8=A9 =D8=A7=D9=84=D9=85=D8=B9=D8=AF=D8=A9. =D8=B9=D9=86=D8=AF =D8=A7=
=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=D9=87 =D9=84=D9=84=D8=A5=D8=AC=D9=87=
=D8=A7=D8=B6=D8=8C =D9=8A=D8=B9=D9=85=D9=84 =D8=B9=D9=84=D9=89 =D8=AA=D8=AD=
=D9=81=D9=8A=D8=B2 =D8=AA=D9=82=D9=84=D8=B5=D8=A7=D8=AA =D8=A7=D9=84=D8=B1=
=D8=AD=D9=85 =D9=88=D8=A5=D9=81=D8=B1=D8=A7=D8=BA =D9=85=D8=AD=D8=AA=D9=88=
=D9=8A=D8=A7=D8=AA=D9=87 =D8=AE=D9=84=D8=A7=D9=84 =D9=81=D8=AA=D8=B1=D8=A9 =
=D9=82=D8=B5=D9=8A=D8=B1=D8=A9=D8=8C =D9=85=D9=85=D8=A7 =D9=8A=D8=AC=D8=B9=
=D9=84=D9=87 =D8=AE=D9=8A=D8=A7=D8=B1=D9=8B=D8=A7 =D9=81=D8=B9=D8=A7=D9=84=
=D9=8B=D8=A7 =D9=88=D8=A2=D9=85=D9=86=D9=8B=D8=A7 =D8=B9=D9=86=D8=AF =D8=A5=
=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A=D8=A8 =D9=85=D8=AE=D8=AA=D8=B5.=
</span></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-b=
ottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margi=
n-top:14pt;margin-bottom:4pt"><span style=3D"font-size:13pt;font-family:Ari=
al,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700=
;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-al=
ternates:normal;vertical-align:baseline">=D8=A3=D9=87=D9=85=D9=8A=D8=A9 =D8=
=A7=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=D9=84=D9=89 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=
=AB=D9=88=D9=82</span></span><p dir=3D"rtl" style=3D"line-height:1.38;margi=
n-top:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-family:Ar=
ial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=
=D9=8A=D8=A9=D8=8C =D8=AA=D8=AA=D9=88=D8=A7=D8=AC=D8=AF =D8=A7=D9=84=D9=83=
=D8=AB=D9=8A=D8=B1 =D9=85=D9=86 =D8=A7=D9=84=D9=82=D9=86=D9=88=D8=A7=D8=AA =
=D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=88=D8=AB=D9=88=D9=82=D8=A9 =D8=A7=
=D9=84=D8=AA=D9=8A =D8=AA=D8=A8=D9=8A=D8=B9 =D9=85=D9=86=D8=AA=D8=AC=D8=A7=
=D8=AA =D9=85=D8=AC=D9=87=D9=88=D9=84=D8=A9 =D8=A7=D9=84=D9=85=D8=B5=D8=AF=
=D8=B1 =D9=82=D8=AF =D8=AA=D8=A4=D8=AF=D9=8A =D8=A5=D9=84=D9=89 =D9=85=D8=
=AE=D8=A7=D8=B7=D8=B1 =D8=B5=D8=AD=D9=8A=D8=A9 =D8=AC=D8=B3=D9=8A=D9=85=D8=
=A9.</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line"><br></span><span style=3D"font-size:11pt;font-family:Arial,sans-serif=
;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</s=
pan><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,=
0,0);background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"> =
=D8=AA=D8=B6=D9=85=D9=86 =D9=84=D9=83:</span><span style=3D"font-size:11pt;=
font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline"><br></span><span style=3D"font-size=
:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transp=
arent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">=E2=9C=94=EF=B8=8F </span><sp=
an style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);ba=
ckground-color:transparent;font-weight:700;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=
 =D8=A3=D8=B5=D9=84=D9=8A=D8=A9 100%</span><span style=3D"font-size:11pt;fo=
nt-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline"><br></span><span styl=
e=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgroun=
d-color:transparent;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">=E2=9C=94=EF=B8=
=8F </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline">=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE =D8=B5=D9=84=D8=A7=D8=
=AD=D9=8A=D8=A9 =D8=AD=D8=AF=D9=8A=D8=AB</span><span style=3D"font-size:11p=
t;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparen=
t;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline"><br></span><span =
style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backg=
round-color:transparent;font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;vertical-align:baseline">=E2=9C=94=
=EF=B8=8F </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif=
;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline">=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF=D8=A7=D8=AA =D8=
=B7=D8=A8=D9=8A=D8=A9 =D8=AF=D9=82=D9=8A=D9=82=D8=A9 =D9=84=D9=84=D8=A7=D8=
=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85</span><span style=3D"font-size:11pt;font-=
family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-=
weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline"><br></span><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">=E2=9C=94=EF=B8=
=8F </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline">=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=
=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84</span><span sty=
le=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgrou=
nd-color:transparent;font-weight:700;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
"><br></span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;col=
or:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">=E2=9C=94=EF=B8=8F </span><span style=3D"font-size:11pt;font-family=
:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight=
:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline">=D8=AF=D8=B9=D9=85 =D9=88=D8=
=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=B9=D9=84=D9=89 =D9=85=D8=AF=D8=
=A7=D8=B1 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=D8=A9</span></p><p dir=3D"rtl" sty=
le=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><sp=
an dir=3D"rtl" style=3D"line-height:1.38;margin-top:14pt;margin-bottom:4pt"=
><span style=3D"font-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0=
);background-color:transparent;font-weight:700;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline">=D9=84=D9=85=D8=A7=D8=B0=D8=A7 =D8=AA=D8=AE=D8=AA=D8=A7=D8=B1=
=D9=8A=D9=86 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=D8=9F</span></spa=
n><ul style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"l=
ist-style-type:disc;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0=
,0,0);background-color:transparent;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline;w=
hite-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;m=
argin-top:12pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"font=
-size:11pt;background-color:transparent;font-weight:700;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline">=D8=A7=D9=84=D8=AE=D8=A8=D8=B1=D8=A9 =D8=A7=D9=84=D8=
=B7=D8=A8=D9=8A=D8=A9</span><span style=3D"font-size:11pt;background-color:=
transparent;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline">: =D8=AF. =D9=86=D9=8A=
=D8=B1=D9=85=D9=8A=D9=86 =D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=81=D9=8A =
=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=
=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D9=86=D8=B3=D8=A7=D8=A6=D9=8A=D8=A9=
=D8=8C =D9=88=D8=AA=D9=82=D8=AF=D9=85 =D9=84=D9=83=D9=90 =D8=AF=D8=B9=D9=85=
=D9=8B=D8=A7 =D9=85=D9=87=D9=86=D9=8A=D9=8B=D8=A7 =D9=82=D8=A8=D9=84 =D9=88=
=D8=A3=D8=AB=D9=86=D8=A7=D8=A1 =D9=88=D8=A8=D8=B9=D8=AF</span><a href=3D"ht=
tps://saudiersaa.com/" target=3D"_blank" rel=3D"nofollow" data-saferedirect=
url=3D"https://www.google.com/url?hl=3Dar&amp;q=3Dhttps://saudiersaa.com/&a=
mp;source=3Dgmail&amp;ust=3D1756205891416000&amp;usg=3DAOvVaw07ZVvMrwhkMtq6=
OVKBb1vi"><span style=3D"font-size:11pt;color:rgb(17,85,204);background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;text-decoration-line:underline;vertical-align=
:baseline">=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size:11pt;background-co=
lor:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;=
font-variant-alternates:normal;vertical-align:baseline">.</span><span style=
=3D"font-size:11pt;background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-ty=
pe:disc;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgr=
ound-color:transparent;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline;white-space:p=
re"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:0p=
t;margin-bottom:0pt" role=3D"presentation"><span style=3D"font-size:11pt;ba=
ckground-color:transparent;font-weight:700;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=D8=B1=
=D9=8A=D8=B9</span><span style=3D"font-size:11pt;background-color:transpare=
nt;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline">: =D8=AA=D8=BA=D8=B7=D9=8A=D8=A9=
 =D9=84=D8=AC=D9=85=D9=8A=D8=B9 =D8=A7=D9=84=D9=85=D8=AF=D9=86 =D8=A7=D9=84=
=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=A8=D9=85=D8=A7 =D9=81=D9=8A =
=D8=B0=D9=84=D9=83 </span><span style=3D"font-size:11pt;background-color:tr=
ansparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=D9=
=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=
=A9=D8=8C =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=A7=D9=84=D8=AE=D8=
=A8=D8=B1=D8=8C =D8=A7=D9=84=D8=B7=D8=A7=D8=A6=D9=81</span><span style=3D"f=
ont-size:11pt;background-color:transparent;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline"> =D9=88=D8=BA=D9=8A=D8=B1=D9=87=D8=A7.</span><span style=3D"font-si=
ze:11pt;background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;fon=
t-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:=
transparent;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=
=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-b=
ottom:0pt" role=3D"presentation"><span style=3D"font-size:11pt;background-c=
olor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=AD=D9=85=D8=A7=D9=8A=D8=A9 =D8=AE=D8=B5=D9=88=D8=B5=D9=8A=D8=AA=D9=83</=
span><span style=3D"font-size:11pt;background-color:transparent;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline">: =D9=8A=D8=AA=D9=85 =D8=A7=D9=84=D8=AA=D8=BA=
=D9=84=D9=8A=D9=81 =D8=A8=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=AA=D8=B6=D9=85=
=D9=86 =D8=A7=D9=84=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=A7=D9=84=D9=83=D8=A7=
=D9=85=D9=84=D8=A9.</span><span style=3D"font-size:11pt;background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline"><br><br></span></p></li><=
li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;font-family:Ari=
al,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-heigh=
t:1.38;text-align:right;margin-top:0pt;margin-bottom:12pt" role=3D"presenta=
tion"><span style=3D"font-size:11pt;background-color:transparent;font-weigh=
t:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=D8=AA=D9=88=D9=
=83=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A</span><span style=3D"f=
ont-size:11pt;background-color:transparent;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">: =D8=B4=D8=B1=D8=A7=D8=A1=D9=83 =D9=8A=D8=AA=D9=85 =D9=85=D8=A8=D8=
=A7=D8=B4=D8=B1=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B5=D8=AF=D8=B1 =D8=
=A7=D9=84=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=8C =D8=A8=D8=B9=D9=8A=D8=AF=D9=
=8B=D8=A7 =D8=B9=D9=86 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1.</span><s=
pan style=3D"font-size:11pt;background-color:transparent;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline"><br><br></span></p></li></ul><p dir=3D"rtl" style=3D"=
line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=
=3D"rtl" style=3D"line-height:1.38;margin-top:14pt;margin-bottom:4pt"><span=
 style=3D"font-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);back=
ground-color:transparent;font-weight:700;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line">=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=B7=D9=84=D8=A8 =D8=AD=D8=A8=D9=88=
=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=86 =D8=AF. =D9=
=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span></span><ol style=3D"margin-top:0px;=
margin-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:decimal;font-si=
ze:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tran=
sparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"r=
tl" style=3D"line-height:1.38;text-align:right;margin-top:12pt;margin-botto=
m:0pt" role=3D"presentation"><span style=3D"font-size:11pt;background-color=
:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=
=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D8=B9=D8=A8=D8=B1 =D9=88=D8=A7=D8=AA=
=D8=B3=D8=A7=D8=A8</span><span style=3D"font-size:11pt;background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline"> =D8=B9=D9=84=D9=89 =D8=A7=
=D9=84=D8=B1=D9=82=D9=85: </span><span style=3D"font-size:11pt;background-c=
olor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=F0=9F=93=9E 0537466539</span><span style=3D"font-size:11pt;background-colo=
r:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east=
-asian:normal;font-variant-alternates:normal;vertical-align:baseline"><br><=
br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:decimal;font-si=
ze:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tran=
sparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"r=
tl" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom=
:0pt" role=3D"presentation"><span style=3D"font-size:11pt;background-color:=
transparent;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline">=D8=B4=D8=B1=D8=AD =D8=
=A7=D9=84=D8=AD=D8=A7=D9=84=D8=A9 =D8=A7=D9=84=D8=B5=D8=AD=D9=8A=D8=A9 =D9=
=88=D9=81=D8=AA=D8=B1=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=84.</span><span sty=
le=3D"font-size:11pt;background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-=
type:decimal;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline;white-sp=
ace:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-t=
op:0pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"font-size:11=
pt;background-color:transparent;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=A7=D8=B3=D8=AA=D9=84=D8=A7=D9=85 =D8=A7=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=
=AF=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D9=
=86=D8=A7=D8=B3=D8=A8=D8=A9 =D9=88=D8=A7=D9=84=D8=AC=D8=B1=D8=B9=D8=A9 =D8=
=A7=D9=84=D9=85=D9=88=D8=B5=D9=89 =D8=A8=D9=87=D8=A7.</span><span style=3D"=
font-size:11pt;background-color:transparent;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:d=
ecimal;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgro=
und-color:transparent;font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;vertical-align:baseline;white-space:pr=
e"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:0pt=
;margin-bottom:12pt" role=3D"presentation"><span style=3D"font-size:11pt;ba=
ckground-color:transparent;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=
=D8=B3=D8=AA=D9=84=D8=A7=D9=85 =D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=AE=
=D9=84=D8=A7=D9=84 =D9=81=D8=AA=D8=B1=D8=A9 =D9=82=D8=B5=D9=8A=D8=B1=D8=A9 =
=D8=B9=D8=A8=D8=B1 =D8=AE=D8=AF=D9=85=D8=A9 =D8=AA=D9=88=D8=B5=D9=8A=D9=84 =
=D8=A2=D9=85=D9=86=D8=A9 =D9=88=D8=B3=D8=B1=D9=8A=D8=A9.</span><span style=
=3D"font-size:11pt;background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline"><br><br></span></p></li></ol><p dir=3D"rtl" style=3D"line-heig=
ht:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" =
style=3D"line-height:1.38;margin-top:14pt;margin-bottom:4pt"><span style=3D=
"font-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-co=
lor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=AA=D9=86=D8=A8=D9=8A=D9=87 =D8=B7=D8=A8=D9=8A =D9=85=D9=87=D9=85</span></s=
pan><ul style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D=
"list-style-type:disc;font-size:11pt;font-family:Arial,sans-serif;color:rgb=
(0,0,0);background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right=
;margin-top:12pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"fo=
nt-size:11pt;background-color:transparent;font-variant-numeric:normal;font-=
variant-east-asian:normal;font-variant-alternates:normal;vertical-align:bas=
eline">=D9=8A=D8=AC=D8=A8 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=82=D8=B7 =D8=AA=D8=AD=D8=AA =
=D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A =D9=85=D8=AE=D8=AA=D8=B5.=
</span><span style=3D"font-size:11pt;background-color:transparent;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" styl=
e=3D"list-style-type:disc;font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:r=
ight;margin-top:0pt;margin-bottom:0pt" role=3D"presentation"><span style=3D=
"font-size:11pt;background-color:transparent;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline">=D9=84=D8=A7 =D9=8A=D9=8F=D9=86=D8=B5=D8=AD =D8=A8=D8=A7=D8=B3=D8=
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
/XihUBiSLAAAJ" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"h=
ttps://www.google.com/url?hl=3Dar&amp;q=3Dhttps://groups.google.com/a/chrom=
ium.org/g/security-dev/c/rhrPpivCQGM/m/XihUBiSLAAAJ&amp;source=3Dgmail&amp;=
ust=3D1756205891416000&amp;usg=3DAOvVaw0WNiXpsdhAXLwbeUOAGc7V"><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline"> </span><span st=
yle=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(17,85,204);bac=
kground-color:transparent;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;text-decoration-line:underline;ver=
tical-align:baseline">=D8=B4=D8=B1=D8=A7=D8=A1 </span><span style=3D"font-s=
ize:11pt;font-family:Arial,sans-serif;color:rgb(17,85,204);background-color=
:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;text-decoration-line:underline;=
vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size:11pt;font-family:Aria=
l,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline"> =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=
=D9=8A=D8=A9 =D9=87=D9=88 =D8=A7=D9=84=D8=B6=D9=85=D8=A7=D9=86 =D8=A7=D9=84=
=D9=88=D8=AD=D9=8A=D8=AF =D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=AA=D9=83=D9=90.<=
/span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(=
0,0,0);background-color:transparent;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"=
><br></span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;colo=
r:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-=
variant-east-asian:normal;font-variant-alternates:normal;vertical-align:bas=
eline">=D9=85=D8=B9 </span><span style=3D"font-size:11pt;font-family:Arial,=
sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;vertical-align:baseline">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=
=8A=D9=86</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;=
color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline">=D8=8C =D8=B3=D8=AA=D8=AD=D8=B5=D9=84=D9=8A=D9=86 =D8=B9=D9=84=
=D9=89 =D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=AC =D8=A7=D9=84=D8=A3=D8=B5=D9=84=
=D9=8A=D8=8C =D8=A7=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF =D8=A7=D9=84=D8=B7=
=D8=A8=D9=8A =D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=8C =D9=88=D8=A7=
=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A =D8=A3=
=D9=8A=D9=86=D9=85=D8=A7 =D9=83=D9=86=D8=AA=D9=90 =D9=81=D9=8A =D8=A7=D9=84=
=D9=85=D9=85=D9=84=D9=83=D8=A9.</span></p><p dir=3D"rtl" style=3D"line-heig=
ht:1.38;margin-top:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;f=
ont-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;vertical-align:baseline">=F0=9F=93=9E =D9=84=D9=84=D8=AA=D9=
=88=D8=A7=D8=B5=D9=84 =D9=88=D8=A7=D9=84=D8=B7=D9=84=D8=A8 =D8=B9=D8=A8=D8=
=B1 =D9=88=D8=A7=D8=AA=D8=B3=D8=A7=D8=A8: </span><span style=3D"font-size:1=
1pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transpar=
ent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">0537466539</spa=
n><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,=
0);background-color:transparent;font-weight:700;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline"><br></span><span style=3D"font-size:11pt;font-family:Arial,san=
s-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">=D8=A7=D9=84=D9=85=D8=AF=D9=86 =D8=A7=D9=
=84=D9=85=D8=BA=D8=B7=D8=A7=D8=A9</span><span style=3D"font-size:11pt;font-=
family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">: =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =
=E2=80=93 =D8=AC=D8=AF=D8=A9 =E2=80=93 =D9=85=D9=83=D8=A9 =E2=80=93 =D8=A7=
=D9=84=D8=AF=D9=85=D8=A7=D9=85 =E2=80=93 =D8=A7=D9=84=D8=AE=D8=A8=D8=B1 =E2=
=80=93 =D8=A7=D9=84=D8=B7=D8=A7=D8=A6=D9=81 =E2=80=93 =D8=A7=D9=84=D9=85=D8=
=AF=D9=8A=D9=86=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D9=88=D8=B1=D8=A9 =E2=80=93 =
=D8=A3=D8=A8=D9=87=D8=A7 =E2=80=93 =D8=AC=D8=A7=D8=B2=D8=A7=D9=86 =E2=80=93=
 =D8=AA=D8=A8=D9=88=D9=83.</span></p><p dir=3D"rtl" style=3D"line-height:1.=
38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=
=3D"line-height:1.38;margin-top:18pt;margin-bottom:4pt"><span style=3D"font=
-size:17pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:t=
ransparent;font-weight:700;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline">=C2=A0</=
span></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margin=
-bottom:12pt"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;co=
lor:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=
=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AC=D8=AF=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 =D9=85=D9=83=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=B4=D8=B1=D8=
=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=
=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AD=D8=A8=D9=88=D8=A8 =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=
=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=B5=D9=
=84=D9=8A=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200=D8=8C Misopr=
ostol =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D9=86=D9=87=D8=AF=D9=8A=D8=8C</=
span><a href=3D"https://ksacytotec.com/" target=3D"_blank" rel=3D"nofollow"=
 data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar&amp;q=3Dhttps:/=
/ksacytotec.com/&amp;source=3Dgmail&amp;ust=3D1756205891416000&amp;usg=3DAO=
vVaw1R3qLaExWJW75bjTKCEA7w"><span style=3D"font-size:11pt;font-family:Arial=
,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline"> </span><span style=3D"font-size:11pt;font-family:Ar=
ial,sans-serif;color:rgb(17,85,204);background-color:transparent;font-varia=
nt-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:no=
rmal;text-decoration-line:underline;vertical-align:baseline">https://ksacyt=
otec.com/</span></a><span style=3D"font-size:11pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline"> =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=
=A9=D8=8C =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=
=8A=D9=86 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83.</span></p><p dir=3D"r=
tl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=
=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=
=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 =D8=AC=D8=AF=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=
=85=D9=83=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=
=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=B4=D8=B1=D8=A7=D8=A1 =D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=
=AF=D9=8A=D8=A9=D8=8C =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=8C =D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=B5=D9=84=D9=8A=D8=8C =D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200=D8=8C Misoprostol =D8=A7=D9=84=D8=B3=
=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83 =D8=A7=D9=84=D9=86=D9=87=D8=AF=D9=8A=D8=8C =D8=A7=D9=84=D8=A5=D8=AC=
=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A =D9=81=D9=8A =D8=A7=D9=84=
=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AF=D9=83=D8=AA=D9=88=D8=B1=
=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83.</span></p><br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/6176715f-7263-48f1-863c-85b8f345520dn%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/6176715f-7263-48f1-863c-85b8f345520dn%40googlegroups.com</a>.<br />

------=_Part_510755_362896.1756119525394--

------=_Part_510754_1948628365.1756119525394--
