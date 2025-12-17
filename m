Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBFOPRHFAMGQEBRJ7NWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FAFDCC6855
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 09:19:34 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-477a0ddd1d4sf37371125e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 00:19:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765959574; cv=pass;
        d=google.com; s=arc-20240605;
        b=gs1EnYtVjJR33tq+EWHxoAks691T+pwXccj+ws8b+Amo+bnisVP1xPU+qQ0+cycypn
         0xHphYM6CH7H32LkqZ3lMR/pzP450w4esMlsQICkx4K2Kj/eB7Cs5xi+6aNiKSEPZciF
         LIZGPrpMs68lejTGhR+TnqNFEdApQxCC3UdIHWsd1C2vAxhBrN2pY71rpEeXFi7K2uxo
         MfZ8s+gjGuxqQd4ofFfYf690Uev1pypthdr7rW2kcGhuXF/sWJ+fPuzF9q42ibkf/9D/
         SzftX0AJefORLonx6I9C2gdfwrLiu/2++E/p4UgHuwZH9dlleao9DVkU7QrnUDtrgFDr
         rbvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=oa5ZQoy2/EwpmPnnlyRf9kxTAxHNKs0jr019uoIeiKs=;
        fh=V3mGw75jV//kq8xH5s56f7byMIiPZGZ+PTJOd7VO6LY=;
        b=SaFrTYrjNFtcfbbgda4LzJl8cqXjQ0gSFTXfhiYcZb6PURGUxozjy0Pa1wFWjfF0Rn
         vLKez7T1laPc1WtgNGWJFfFYYWQ07uCJXBR2QdugVJWH6/dpiUfVP2Lzg5Xn3Vmb4f88
         /zU0Q1TwsAAcQsGyNrDDH9rGGmkbvovyGgcbjAXJqvsURVjHXpToABOGtRyV4WAb0yc3
         eHUmdj46eLP7Pk+BHefFZVEl3El5c4tXPAyaKKTiwjg/qanlJr540Lky/3J4WIvaKqRo
         4pxrJXL2Bdf/3Y42v0X9JS3fM6CjHDk3QvQCUFt6BZiwWo8NyEZKoJhV5HTR/9ORuuCA
         Iy6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KaQNZZIJ;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765959574; x=1766564374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oa5ZQoy2/EwpmPnnlyRf9kxTAxHNKs0jr019uoIeiKs=;
        b=kbMYHc2gm5O47BVDKwj6ucHnKx84n7vYMUOvYM/UTHyHulZsH954IUbkUMD0xW319j
         k58Yw2NOxGiOvcJuUa9ZUCJjozNVdrVE8ntzsRXac03hbqX8cuxnoVBpRvSNgaoFuy0c
         Xd/h15MFdpqSisTng3imSfzydCfLDtALEdXVxexa78dQUHonnjtkBjOlTxWZkvusHpua
         G+NAiZnB5HitKYtPRgrpsgiOnZtEBfFHJYOpLh9olVKZ0MBVbzfL27/TD9cVMtnU5o09
         ofsnSngH+tJ8aoY22ODJca4C2m1ZCu6gtWRNKiQfmApWyH0fZ36zqO+V5P/V2pXncJHZ
         dPAQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765959574; x=1766564374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=oa5ZQoy2/EwpmPnnlyRf9kxTAxHNKs0jr019uoIeiKs=;
        b=V13bbHzhUb/W+oejjFN9l7Ty8RzjD2oT1QPXWrXRwwv0aXwzMPDj5xUEBsBFBE1SZs
         mrYGfzBDxhZtzpkkEFIOruuMGj6491JBtUVsiU6o+718b7k0KLtTvXINv+tq7epTTBjX
         lfgDnAJGA7yzJWB3Oy8ICvuXfDfEOaDmnDLCGxnJrAjAikgFz6sLGJ7fLYjtGKxg6LDz
         P325cnCY9S04qRF//G8Qwa0Iuz7x9UdxggymP4Maq12cpi/l21CuOR2KLMlA7F2IMlq8
         wzVdEVUWV7RocBsJlBsSc30Q/ZCTlAXvBPhykA2Iqynt9E4jBugAAfGv8YXd2/9Ef1oI
         bJvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765959574; x=1766564374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oa5ZQoy2/EwpmPnnlyRf9kxTAxHNKs0jr019uoIeiKs=;
        b=vzr/BwZ8kv5ts2RLtAvCGUxTtby6iXSoa8+N6Y3UcTjr6IYBHWuzSLHXQ93qFnCm7J
         RIM2svGD82McJjhwhEgZPF0DoWfGKQOa215Sf+O23gaFLuhqU4RPmCgwdqqhmnzkL94t
         9eEhGVHlrlb++Jg7JIkCJOmR3Kk6u/rWFeLLyM/vJl+zaMv6phCSKCV7uDApKW7JtXq1
         /D1sbcu+fOT0AxRwlr4U/rqn0Nz6uXdQ++0IeCw1QTFXK/mwI5acc/Efqq4t7I/kGgwW
         Qygtb37QcTewtXRmw6E2j1YOeMNmobzh0TJzQfR+7dXGuYOffJfY9qAHGprqXq1xeJ50
         XFZQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV4DMVgmyUPEN8QqMSqrvaPj5NUI6c1RmEAJi9xV9XpG/Yk6MpHUXtD4ZFqLw4OLqha3Lk+tQ==@lfdr.de
X-Gm-Message-State: AOJu0YxYxwMiOJrPP45R7OQe4rtE6wx8/dt0UugvvZrCpZQD2JsDagVX
	HQZL92R9D6k0lgkDIYKcnUa5rxvG21JsOVJICE6zWHk6KD/jLGG4ETBj
X-Google-Smtp-Source: AGHT+IGC/obO+0KCjGajf+Jq1O23WE+ofz0v+jnA4thE5UycLfWp7CQlF9uT2ZYGLQLm6L//nJ2pCA==
X-Received: by 2002:a05:600c:64c6:b0:477:639d:bca2 with SMTP id 5b1f17b1804b1-47a8f89bc56mr183728255e9.4.1765959573826;
        Wed, 17 Dec 2025 00:19:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaqO3Op29K1q9KQUeaE6/1XSA/rU0F/WSt/P+8BGnYtUA=="
Received: by 2002:a05:6000:144d:b0:42b:52c4:6640 with SMTP id
 ffacd0b85a97d-42fb2c86417ls3281534f8f.1.-pod-prod-05-eu; Wed, 17 Dec 2025
 00:19:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVAhaKDpi2bXT/MT7Va/ODz+lDvUXmmuy/a0T/Z51boRRQczfY2B7cStc+5Xu8zne/90mfTibOxFwM=@googlegroups.com
X-Received: by 2002:a05:6000:420a:b0:430:ff0c:3612 with SMTP id ffacd0b85a97d-430ff0c37fbmr9062498f8f.41.1765959571007;
        Wed, 17 Dec 2025 00:19:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765959570; cv=none;
        d=google.com; s=arc-20240605;
        b=fsCcl3CJT+YL3ko+5k/TbfVG2g3EX1rIWUWAkhmHcuXKI/iRpA1LAiLwhieVDw6Sn1
         NifvnkTdCa3U4C+6O7TJ54STy+V42isQBSxG/T0EAQky7TAb2eRveUrOjHojtoaHbsEN
         +fQvOK3cDiFZRvCUvqMKL15agQ+hctSW/G5fK+s83uSifqP+HezP8mxtoMJTfm16QxcT
         mBTX0APEt0GX60wkmjc0254Np+vcUqbR0nA0yQKuPQtTUHRyiHzDxLNmn3bnA3cqFoUE
         Bl3btheaLWig3OJ7WqdX1hDJG/KHWrxSaA7iZexe9safd2qRunQ13VrR75zI1xrPx2AX
         h1qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=Bzxh7U2Al8XkDvblscZcOsbnsS/2lRJCvcFXNqFdB2M=;
        fh=OTPi8sIfvahHOrND/w1CVkBcvHPNCRHApA0erkObAQU=;
        b=HbP7kDPywiczxho9TobCVXAa81RfLxjPDXHCP3c8S0PQLVb2JI8WiwhdAKONQKuLdR
         k7hwFhLtveI5snFpkB/3PXpjw67rgoMqnUQhgtcAV8scBK2c43m83KHejRn/WCBFCKnu
         HMOZouSuZBKefr38b581oX2M4WAdpTrQbGUpFbSPSkBNDARW7l5wMpDPtnvX+6Nv1HvP
         P7RBIQ+6OSrlMzYrhxDMYOUD/JcswjxXVOxI2Yfh63tBYD3Y7gCJIDBpddxqG0rtH/YU
         fjXbUuGoycLMCfOtxw3NRY/mfAt7W23HP04Ld6hQ1fMd/edYxQaBgRNzdrH8E5vam+OC
         YVPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KaQNZZIJ;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4310adefabfsi26491f8f.10.2025.12.17.00.19.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Dec 2025 00:19:30 -0800 (PST)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id 4fb4d7f45d1cf-64180bd67b7so7355535a12.0
        for <kasan-dev@googlegroups.com>; Wed, 17 Dec 2025 00:19:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX0QiNhJ5x72Srw5nREBQtqQxdrtBMJDxE9FfaS0ZPERrBNvmLPaL+YBeZRLLZOidO/Ni2QNgrMUXU=@googlegroups.com
X-Gm-Gg: AY/fxX4F9cP6hRfZeKVNBW2fUGg46hiYvAdCmtyts3iAJwvna0uWvOLHoLxGEmBmjlo
	cVk93li7c/JE9Ze4QnzV71qZmoB9vCRysWCN2SDu2fx20prmeLG9XIXIx5Ek1N6MCLxmFD+ABd9
	PBEyTRMwHHr1CRUnbi3mD9yhi/FHc16dyvZrxbnDldCIhciXFGXfazhF+SJdRSF1otCkNA62M67
	bt9A26gspFQ5RlNZTTXEBQbi3d9ywbwLFVraK5Sb4eIY2BrV0k5cB+njI+JxNZZbgPaZTTiBaXv
	T04=
X-Received: by 2002:a50:fb02:0:b0:649:a8de:786b with SMTP id
 4fb4d7f45d1cf-649a8de78c7mr12459983a12.5.1765959569873; Wed, 17 Dec 2025
 00:19:29 -0800 (PST)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Wed, 17 Dec 2025 10:19:18 +0200
X-Gm-Features: AQt7F2oB_G14wojZ0aovM3DSMx3QQl_xjBWxZpfhRFwvKQ5ozB0laJsCuXPAbZs
Message-ID: <CADj1ZKkoGgycLa=-Lz4pcqvjjMmRMi9WONYECK5FGh_Y=0xNCQ@mail.gmail.com>
Subject: =?UTF-8?B?2KfZhNiv2KjZhNmI2YUgwqDYp9mE2YXZh9mG2Yog2KfZhNmF2KrZg9in2YXZhCDZgdmK?=
	=?UTF-8?B?2KXYr9in2LHYqSDYp9mE2YXZiNin2LHYryDYp9mE2KjYtNix2YrYqSDZiNmC2KfZhtmI2YbYp9mE2Lk=?=
	=?UTF-8?B?2YXZhCDZiNin2YTYqtij2YXZitmG2KfYqiDYp9mE2KfYrNiq2YXYp9i52YrYqSAo2LnYp9mFKSBQcm9m?=
	=?UTF-8?B?ZXNzaW9uYWxEaXBsb21hIGluIEh1bWFuIFJlc291cmNlcywgTGFib3IgTGF3ICYgU29jaWFsIEluc3Vy?=
	=?UTF-8?B?YW5jZdiu2YDZgNmA2YDZgNmE2KfZhCDYp9mE2YHYqtix2Kkg2YXZhiA0IOKAkyAxNdmK2YbZgNmA2YA=?=
	=?UTF-8?B?2YDZgNmA2YDYp9mK2LEyMDI22YXYp9mE2YLYp9mH2LHYqSDigJMg2KzZhdmH2YjYsdmK2Kkg2YXYtdix?=
	=?UTF-8?B?INin2YTYudix2KjZitip?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000d99ffc0646218050"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=KaQNZZIJ;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::534
 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--000000000000d99ffc0646218050
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YrYs9ix2ZEg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE2KXY
r9in2LHZitipINiq2YLYr9mK2YUg2KfZhNiv2KjZhNmI2YUg2KfZhNmF2YfZhtmKINin2YTZhdiq
2K7Ytdi1INmB2YogKtil2K/Yp9ix2KkNCtin2YTZhdmI2KfYsdivINin2YTYqNi02LHZitipINmI
2YLYp9mG2YjZhiDYp9mE2LnZhdmEINmI2KfZhNiq2KPZhdmK2YbYp9iqINin2YTYp9is2KrZhdin
2LnZitipKtiMINio2LXZiti62KkgKti52KfZhdipINmI2LTYp9mF2YTYqSoNCg0KINiq2LHYp9i5
2Yog2KfZhNmB2LHZiNmC2KfYqiDYp9mE2KrYtNix2YrYudmK2Kkg2KjZitmGINin2YTYr9mI2YTY
jCDZiNiq2Y/YsdmD2ZHYsiDYudmE2Ykg2KfZhNmF2KjYp9iv2KYg2KfZhNiv2YjZhNmK2Kkg2YjY
p9mE2YXYudin2YrZitixDQrYp9mE2YXZgtin2LHZhtipINin2YTZhdi52KrZhdiv2Kkg2LnYp9mE
2YXZitmL2KfYjCDYqNmF2Kcg2YrYqtmK2K0g2KrYt9io2YrZgtmHINmB2YogKtis2YXZiti5INin
2YTYr9mI2YQg2KfZhNi52LHYqNmK2Kkg2YjYp9mE2K/ZiNmE2YrYqSoNCg0KDQoNCirYp9mE2K/Y
qNmE2YjZhSAg2KfZhNmF2YfZhtmKINin2YTZhdiq2YPYp9mF2YQg2YHZiioNCg0K2KXYr9in2LHY
qSDYp9mE2YXZiNin2LHYryDYp9mE2KjYtNix2YrYqSDZiNmC2KfZhtmI2YYg2KfZhNi52YXZhCDZ
iNin2YTYqtij2YXZitmG2KfYqiDYp9mE2KfYrNiq2YXYp9i52YrYqSAo2LnYp9mFKQ0KKlByb2Zl
c3Npb25hbCBEaXBsb21hIGluIEh1bWFuIFJlc291cmNlcywgTGFib3IgTGF3ICYgU29jaWFsIElu
c3VyYW5jZSoNCg0K2K7ZgNmA2YDZgNmA2YTYp9mEINin2YTZgdiq2LHYqSDZhdmGIDQg4oCTIDE1
INmK2YbZgNmA2YDZgNmA2YDZgNin2YrYsTIwMjbZhQ0KDQrYp9mE2YLYp9mH2LHYqSDigJMg2KzZ
hdmH2YjYsdmK2Kkg2YXYtdixINin2YTYudix2KjZitipDQoNCtin2KrYp9it2Kkg2KfZhNi52YXZ
hCDYudmGINio2LnYryDZgdmKINit2KfZhCDYqti52LDYsSDYp9mE2K3YttmI2LEg2KfZhNmI2KzY
p9mH2YoNCg0KKti02YfYp9iv2KfYqiDZhdi52KrZhdiv2Kkg2YXZiNir2YLYqSDZgtin2KjZhNip
INmE2YTYqti12K/ZitmCINmF2YYg2YPYp9mB2Kkg2KfZhNiz2YHYp9ix2KfYqioNCg0KKtij2YfY
r9in2YEg2KfZhNiv2KjZhNmI2YUqKjoqDQoNCsKnICAgICAgINiq2KPZh9mK2YQg2YPZiNin2K/Y
sSDYp9mE2YXZiNin2LHYryDYp9mE2KjYtNix2YrYqSDZiNmB2YIg2KfZhNmF2LnYp9mK2YrYsSDY
p9mE2K/ZiNmE2YrYqS4NCg0KwqcgICAgICAg2YHZh9mFINin2YTYo9i32LEg2KfZhNi52KfZhdip
INmE2YLZiNin2YbZitmGINin2YTYudmF2YQg2YjYp9mE2KrYo9mF2YrZhtin2Kog2KfZhNin2KzY
qtmF2KfYudmK2Kkg2LnYp9mE2YXZitmL2KcuDQoNCsKnICAgICAgINix2KjYtyDYs9mK2KfYs9in
2Kog2KfZhNmF2YjYp9ix2K8g2KfZhNio2LTYsdmK2Kkg2KjYp9mE2KfZhdiq2KvYp9mEINin2YTZ
gtin2YbZiNmG2YouDQoNCsKnICAgICAgINiq2YLZhNmK2YQg2KfZhNmF2K7Yp9i32LEg2KfZhNmC
2KfZhtmI2YbZitipINmI2KfZhNmG2LLYp9i52KfYqiDYp9mE2LnZhdin2YTZitipLg0KDQrCpyAg
ICAgICDYr9i52YUg2KfZhNil2K/Yp9ix2KfYqiDZgdmKINin2YTYqti52KfZhdmEINmF2Lkg2KfZ
hNis2YfYp9iqINin2YTYsdmC2KfYqNmK2Kkg2YjYp9mE2KrYo9mF2YrZhtmK2KkuDQoNCg0KDQoN
Cg0KDQoq2YXYrdin2YjYsSDYp9mE2K/YqNmE2YjZhSDYp9mE2LHYptmK2LPZitipKio6Kg0KDQoN
Cg0KKtij2YjZhNin2Ys6INil2K/Yp9ix2Kkg2KfZhNmF2YjYp9ix2K8g2KfZhNio2LTYsdmK2Kkg
2KfZhNiv2YjZhNmK2KkqDQoNCsKnICAgICAgINiq2K7Yt9mK2Lcg2KfZhNmC2YjZiSDYp9mE2LnY
p9mF2YTYqSDZiNil2K/Yp9ix2Kkg2KfZhNmI2LjYp9im2YENCg0KwqcgICAgICAg2KfZhNin2LPY
qtmC2LfYp9ioINmI2KfZhNiq2YjYuNmK2YEg2YjZgdmCINin2YTZhdi52KfZitmK2LEg2KfZhNiv
2YjZhNmK2KkNCg0KwqcgICAgICAg2KrZgtmK2YrZhSDYp9mE2KPYr9in2KEg2YjYpdiv2KfYsdip
INin2YTZg9mB2KfYodin2KoNCg0KwqcgICAgICAg2KfZhNiq2K/YsdmK2Kgg2YjYp9mE2KrYt9mI
2YrYsSDZiNio2YbYp9ihINin2YTZhdiz2KfYsSDYp9mE2YjYuNmK2YHZig0KDQrCpyAgICAgICDZ
hti42YUg2KfZhNij2KzZiNixINmI2KfZhNit2YjYp9mB2LIg2YjYp9mE2YXYstin2YrYpw0KDQrC
pyAgICAgICDYpdiv2KfYsdipINi52YTYp9mC2KfYqiDYp9mE2LnZhdmEINmI2KfZhNmG2LLYp9i5
2KfYqiDYp9mE2LnZhdin2YTZitipDQoNCirYq9in2YbZitmL2Kc6INmC2KfZhtmI2YYg2KfZhNi5
2YXZhCAo2KXYt9in2LEg2LnYp9mFINmF2YLYp9ix2YYpKg0KDQrCpyAgICAgICDYp9mE2YXYqNin
2K/YpiDYp9mE2LnYp9mF2Kkg2YTZgtmI2KfZhtmK2YYg2KfZhNi52YXZhCDYp9mE2K/ZiNmE2YrY
qQ0KDQrCpyAgICAgICDYudmC2YjYryDYp9mE2LnZhdmEINmI2KPZhtmI2KfYudmH2Kcg2YjYrdmC
2YjZgiDZiNmI2KfYrNio2KfYqiDYp9mE2KPYt9ix2KfZgQ0KDQrCpyAgICAgICDYs9in2LnYp9iq
INin2YTYudmF2YTYjCDYp9mE2KXYrNin2LLYp9iq2Iwg2YjYp9mE2KzYstin2KHYp9iqDQoNCsKn
ICAgICAgINil2YbZh9in2KEg2KfZhNiu2K/ZhdipINmI2KfZhNiq2LPZiNmK2KfYqiDYp9mE2LnZ
hdin2YTZitipDQoNCsKnICAgICAgINin2YTYqtmB2KrZiti0INin2YTYudmF2KfZhNmKINmI2KfZ
hNmF2LPYpNmI2YTZitin2Kog2KfZhNmC2KfZhtmI2YbZitipDQoNCsKnICAgICAgINin2YTZhtiy
2KfYudin2Kog2KfZhNi52YXYp9mE2YrYqSDZiNii2YTZitin2Kog2KfZhNiq2LPZiNmK2Kkg2YjY
p9mE2KrYrdmD2YrZhQ0KDQoq2KvYp9mE2KvZi9inOiDYp9mE2KrYo9mF2YrZhtin2Kog2KfZhNin
2KzYqtmF2KfYudmK2KkgKNil2LfYp9ixINi52KfZhSDYr9mI2YTZiikqDQoNCsKnICAgICAgINin
2YTZhdmB2KfZh9mK2YUg2KfZhNij2LPYp9iz2YrYqSDZhNmG2LjZhSDYp9mE2KrYo9mF2YrZhtin
2Kog2KfZhNin2KzYqtmF2KfYudmK2KkNCg0KwqcgICAgICAg2KfZhNin2LTYqtix2KfZg9in2Kog
2YjYp9mE2YXYstin2YrYpyDYp9mE2KrYo9mF2YrZhtmK2KkNCg0KwqcgICAgICAg2KXYtdin2KjY
p9iqINin2YTYudmF2YQg2YjYp9mE2KPZhdix2KfYtiDYp9mE2YXZh9mG2YrYqQ0KDQrCpyAgICAg
ICDZhdi52KfYtNin2Kog2KfZhNiq2YLYp9i52K8g2YjYp9mE2KrYudmI2YrYttin2KoNCg0Kwqcg
ICAgICAg2KfZhNiq2LLYp9mF2KfYqiDYtdin2K3YqCDYp9mE2LnZhdmEINmI2KfZhNi52KfZhdmE
DQoNCsKnICAgICAgINin2YTYudmE2KfZgtipINio2YrZhiDYp9mE2KrYo9mF2YrZhtin2Kog2YjY
pdiv2KfYsdipINin2YTZhdmI2KfYsdivINin2YTYqNi02LHZitipDQoNCirYsdin2KjYudmL2Kc6
INin2YTYrdmI2YPZhdipINmI2KfZhNin2YXYqtir2KfZhCDZgdmKINin2YTZhdmI2KfYsdivINin
2YTYqNi02LHZitipKg0KDQrCpyAgICAgICDYp9mE2KfZhdiq2KvYp9mEINin2YTYqti02LHZiti5
2Yog2YHZiiDYs9mK2KfYs9in2Kog2KfZhNmF2YjYp9ix2K8g2KfZhNio2LTYsdmK2KkNCg0Kwqcg
ICAgICAg2KXYr9in2LHYqSDYp9mE2YXYrtin2LfYsSDYp9mE2YLYp9mG2YjZhtmK2KkNCg0Kwqcg
ICAgICAg2K3Zhdin2YrYqSDYp9mE2KjZitin2YbYp9iqINmI2KfZhNiu2LXZiNi12YrYqQ0KDQrC
pyAgICAgICDYo9iu2YTYp9mC2YrYp9iqINin2YTZhdmH2YbYqSDZgdmKINil2K/Yp9ix2Kkg2KfZ
hNmF2YjYp9ix2K8g2KfZhNio2LTYsdmK2KkNCg0KDQoNCg0KKtin2YTZgdim2Kkg2KfZhNmF2LPY
qtmH2K/ZgdipKio6Kg0KDQrCpyAgICAgICDZhdiv2LHYp9ihINin2YTZhdmI2KfYsdivINin2YTY
qNi02LHZitipDQoNCsKnICAgICAgINmF2LPYpNmI2YTZiCDYtNik2YjZhiDYp9mE2LnYp9mF2YTZ
itmGDQoNCsKnICAgICAgINmF2LPYpNmI2YTZiCDYp9mE2KrZiNi42YrZgSDZiNin2YTYsdmI2KfY
qtioDQoNCsKnICAgICAgINmF2K/Ysdin2KEg2KfZhNil2K/Yp9ix2KfYqiDYp9mE2YLYp9mG2YjZ
htmK2KkNCg0KwqcgICAgICAg2YXYs9ik2YjZhNmIINin2YTYp9mF2KrYq9in2YQg2YjYp9mE2K3Z
iNmD2YXYqQ0KDQrCpyAgICAgICDYp9mE2LnYp9mF2YTZiNmGINmB2Yog2KfZhNis2YfYp9iqINin
2YTYrdmD2YjZhdmK2Kkg2YjYp9mE2LTYsdmD2KfYqiDYp9mE2K/ZiNmE2YrYqQ0KDQoq2KfZhNi0
2YDZgNmA2YDZh9in2K/YqSoqOioNCg0KwqcgICAgICAg2K/YqNmE2YjZhSDZhdmH2YbZiiDZhdi5
2KrZhdivINmF2YYg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE
2KXYr9in2LHZitipDQoNCsKnICAgICAgINi02YfYp9iv2Kkg2K/ZiNmE2YrYqSDYqNi12YrYutip
INi52KfZhdipINi12KfZhNit2Kkg2YTZhNin2LPYqtiu2K/Yp9mFINmB2Yog2KzZhdmK2Lkg2KfZ
hNiv2YjZhA0KDQoNCg0K2KjZitin2YbYp9iqINin2YTYqtmI2KfYtdmEINmE2YTYqtiz2KzZitmE
INmI2KfZhNin2LPYqtmB2LPYp9ixOg0KDQoq2KMvINiz2KfYsdipINi52KjYryDYp9mE2KzZiNin
2K8g4oCTINmF2K/ZitixINin2YTYqtiv2LHZitioKg0K2KfZhNmH2KfYqtmBOg0KDQoNCiowMDIw
MTA2OTk5NDM5OSAwMDIwMTA2Mjk5MjUxMCAwMDIwMTA5Njg0MTYyNioNCtin2YTYrNmH2Kk6INin
2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNil2K/Yp9ix2YrYqQ0K
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQoNCi0tIApZb3UgcmVjZWl2ZWQgdGhpcyBt
ZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICJr
YXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3Ag
cmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRldit1bnN1
YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiB2aXNpdCBo
dHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L0NBRGoxWktrb0dneWNM
YSUzRC1MejRwY3F2ampNbVJNaTlXT05ZRUNLNUZHaF9ZJTNEMHhOQ1ElNDBtYWlsLmdtYWlsLmNv
bS4K
--000000000000d99ffc0646218050
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:jus=
tify;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;f=
ont-size:12pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D=
"font-size:18pt;line-height:115%;font-family:Arial,sans-serif">=D9=8A=D8=B3=
=D8=B1=D9=91 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=
=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=
=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D8=AA=D9=82=D8=AF=D9=8A=D9=85 =D8=A7=D9=84=
=D8=AF=D8=A8=D9=84=D9=88=D9=85 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D8=A7=
=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5 =D9=81=D9=8A
<b>=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=
=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9 =D9=88=D9=82=D8=A7=D9=86=D9=
=88=D9=86 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=88=D8=A7=D9=84=D8=AA=D8=A3=D9=
=85=D9=8A=D9=86=D8=A7=D8=AA =D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=
=B9=D9=8A=D8=A9</b>=D8=8C =D8=A8=D8=B5=D9=8A=D8=BA=D8=A9 <b>=D8=B9=D8=A7=D9=
=85=D8=A9
=D9=88=D8=B4=D8=A7=D9=85=D9=84=D8=A9</b></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;direction:rt=
l;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;fon=
t-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:18pt;l=
ine-height:115%;font-family:Arial,sans-serif">=C2=A0=D8=AA=D8=B1=D8=A7=D8=
=B9=D9=8A =D8=A7=D9=84=D9=81=D8=B1=D9=88=D9=82=D8=A7=D8=AA =D8=A7=D9=84=D8=
=AA=D8=B4=D8=B1=D9=8A=D8=B9=D9=8A=D8=A9 =D8=A8=D9=8A=D9=86
=D8=A7=D9=84=D8=AF=D9=88=D9=84=D8=8C =D9=88=D8=AA=D9=8F=D8=B1=D9=83=D9=91=
=D8=B2 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=D8=A8=D8=A7=D8=AF=D8=A6 =D8=A7=
=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=B9=D8=A7=
=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=82=D8=A7=D8=B1=D9=86=D8=A9 =D8=A7=
=D9=84=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =D8=B9=D8=A7=D9=84=D9=85=D9=8A=
=D9=8B=D8=A7=D8=8C =D8=A8=D9=85=D8=A7
=D9=8A=D8=AA=D9=8A=D8=AD =D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D9=87 =D9=81=D9=8A =
<b>=D8=AC=D9=85=D9=8A=D8=B9 =D8=A7=D9=84=D8=AF=D9=88=D9=84 =D8=A7=D9=84=D8=
=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=
=A9</b></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;direction:rt=
l;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;fon=
t-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:18p=
t;line-height:115%;font-family:Arial,sans-serif">=C2=A0</span></b></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;direction:rt=
l;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;fon=
t-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=3D"font-size:18p=
t;line-height:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=AF=D8=A8=
=D9=84=D9=88=D9=85 =C2=A0=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D8=A7=D9=84=
=D9=85=D8=AA=D9=83=D8=A7=D9=85=D9=84 =D9=81=D9=8A</span></b><b><span dir=3D=
"LTR" style=3D"font-size:18pt;line-height:115%"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:28pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,=
sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=A7=
=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9 =D9=88=D9=82=D8=A7=
=D9=86=D9=88=D9=86
=D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=88=D8=A7=D9=84=D8=AA=D8=A3=D9=85=D9=8A=
=D9=86=D8=A7=D8=AA =D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D9=8A=
=D8=A9 (=D8=B9=D8=A7=D9=85)</span><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><span lang=3D"AR-SA" dir=3D"LTR" style=3D"font-size:28pt;line-heig=
ht:115%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> </span><span di=
r=3D"LTR" style=3D"font-size:18pt;line-height:115%"><br>
</span><i><span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%;font-f=
amily:&quot;Times New Roman&quot;,serif">Professional
Diploma in Human Resources, Labor Law &amp; Social Insurance</span></i><spa=
n dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><a name=3D"_Hlk216682368"><spa=
n lang=3D"AR-EG" style=3D"font-size:18pt;line-height:115%;font-family:Arial=
,sans-serif">=D8=AE=D9=80=D9=80=D9=80=D9=80=D9=80=D9=84=D8=A7=D9=84 =D8=A7=
=D9=84=D9=81=D8=AA=D8=B1=D8=A9 =D9=85=D9=86 4 =E2=80=93 15
=D9=8A=D9=86=D9=80=D9=80=D9=80=D9=80=D9=80=D9=80=D9=80=D8=A7=D9=8A=D8=B1202=
6=D9=85</span></a></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=3D"=
font-size:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=
=D9=82=D8=A7=D9=87=D8=B1=D8=A9 =E2=80=93 =D8=AC=D9=85=D9=87=D9=88=D8=B1=D9=
=8A=D8=A9 =D9=85=D8=B5=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9</sp=
an></p>



<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=3D"=
font-size:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=A7=D8=AA=
=D8=A7=D8=AD=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=B9=D9=86 =D8=A8=D8=B9=
=D8=AF =D9=81=D9=8A =D8=AD=D8=A7=D9=84 =D8=AA=D8=B9=D8=B0=D8=B1 =D8=A7=D9=
=84=D8=AD=D8=B6=D9=88=D8=B1 =D8=A7=D9=84=D9=88=D8=AC=D8=A7=D9=87=D9=8A</spa=
n></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><u><span lang=3D"AR-EG" style=
=3D"font-size:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=B4=D9=
=87=D8=A7=D8=AF=D8=A7=D8=AA =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =D9=85=D9=
=88=D8=AB=D9=82=D8=A9 =D9=82=D8=A7=D8=A8=D9=84=D8=A9 =D9=84=D9=84=D8=AA=D8=
=B5=D8=AF=D9=8A=D9=82 =D9=85=D9=86 =D9=83=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=D8=
=B3=D9=81=D8=A7=D8=B1=D8=A7=D8=AA</span></u><u><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%"></span></u></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;=
font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=A3=D9=87=D8=AF=
=D8=A7=D9=81 =D8=A7=D9=84=D8=AF=D8=A8=D9=84=D9=88=D9=85</span></b><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font=
-size:20pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,sans=
-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 54pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-size:=
12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-hei=
ght:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;font-si=
ze-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stretch:=
normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&q=
uot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=AA=D8=A3=D9=87=
=D9=8A=D9=84 =D9=83=D9=88=D8=A7=D8=AF=D8=B1 =D8=A7=D9=84=D9=85=D9=88=D8=A7=
=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9 =D9=88=D9=81=D9=82 =
=D8=A7=D9=84=D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D8=AF=D9=88=
=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 54pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-size=
:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-he=
ight:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;font-s=
ize-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stretch=
:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&=
quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D9=81=D9=87=D9=85 =
=D8=A7=D9=84=D8=A3=D8=B7=D8=B1 =D8=A7=D9=84=D8=B9=D8=A7=D9=85=D8=A9 =D9=84=
=D9=82=D9=88=D8=A7=D9=86=D9=8A=D9=86 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=88=
=D8=A7=D9=84=D8=AA=D8=A3=D9=85=D9=8A=D9=86=D8=A7=D8=AA =D8=A7=D9=84=D8=A7=
=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D9=8A=D8=A9 =D8=B9=D8=A7=D9=84=D9=85=D9=8A=
=D9=8B=D8=A7</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"><span dir=3D"LTR"></s=
pan><span dir=3D"LTR"></span>.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 54pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-size=
:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-he=
ight:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;font-s=
ize-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stretch=
:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&=
quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=B1=D8=A8=D8=B7 =
=D8=B3=D9=8A=D8=A7=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=
=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9 =D8=A8=D8=A7=D9=84=D8=A7=
=D9=85=D8=AA=D8=AB=D8=A7=D9=84 =D8=A7=D9=84=D9=82=D8=A7=D9=86=D9=88=D9=86=
=D9=8A</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:18pt;line-height:115%"><span dir=3D"LTR"></span><s=
pan dir=3D"LTR"></span>.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 54pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-size=
:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-he=
ight:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;font-s=
ize-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stretch=
:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&=
quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=AA=D9=82=D9=84=
=D9=8A=D9=84 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =D8=A7=D9=84=D9=82=
=D8=A7=D9=86=D9=88=D9=86=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=86=D8=B2=D8=A7=
=D8=B9=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D=
"font-size:18pt;line-height:115%"><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span>.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 54pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-size:1=
2pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-heig=
ht:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;font-siz=
e-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stretch:n=
ormal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&qu=
ot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=AF=D8=B9=D9=85 =
=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A7=D8=AA =D9=81=D9=8A =D8=A7=D9=84=
=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=85=D8=B9 =D8=A7=D9=84=D8=AC=D9=87=D8=A7=
=D8=AA =D8=A7=D9=84=D8=B1=D9=82=D8=A7=D8=A8=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=
=D8=AA=D8=A3=D9=85=D9=8A=D9=86=D9=8A=D8=A9</span><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:18pt;line-heig=
ht:115%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif">

</p><table cellpadding=3D"0" cellspacing=3D"0" align=3D"left">
 <tbody><tr>
  <td width=3D"25" height=3D"23"></td>
 </tr>
 <tr>
  <td></td>
  <td><img width=3D"600" height=3D"2"></td>
 </tr>
</tbody></table>

<span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%">=C2=A0</span><p=
></p>

<br clear=3D"ALL">

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;=
font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </spa=
n></b></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;=
font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D9=85=D8=AD=D8=A7=
=D9=88=D8=B1 =D8=A7=D9=84=D8=AF=D8=A8=D9=84=D9=88=D9=85 =D8=A7=D9=84=D8=B1=
=D8=A6=D9=8A=D8=B3=D9=8A=D8=A9</span></b><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:20pt;line-height:11=
5%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif"><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span>:</span></b><b><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif"></span></b></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><span dir=3D"LTR" style=3D"font-family:&quot;AlSharkTitle Blac=
k&quot;,sans-serif">=C2=A0</span></b></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><u><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:11=
5%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=A3=D9=88=D9=
=84=D8=A7=D9=8B: =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=
=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9
=D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9</span></u></b><b><u><span dir=3D=
"LTR" style=3D"font-size:22pt;line-height:115%;font-family:&quot;AlSharkTit=
le Black&quot;,sans-serif"></span></u></b></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D8=A7=D9=84=D9=
=82=D9=88=D9=89 =D8=A7=D9=84=D8=B9=D8=A7=D9=85=D9=84=D8=A9
=D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=88=D8=B8=D8=A7=D8=A6=
=D9=81</span><span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=82=D8=B7=D8=
=A7=D8=A8 =D9=88=D8=A7=D9=84=D8=AA=D9=88=D8=B8=D9=8A=D9=81
=D9=88=D9=81=D9=82 =D8=A7=D9=84=D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =D8=A7=
=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-=
size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=AA=D9=82=D9=8A=D9=8A=D9=85 =D8=A7=D9=84=D8=
=A3=D8=AF=D8=A7=D8=A1 =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
=D8=A7=D9=84=D9=83=D9=81=D8=A7=D8=A1=D8=A7=D8=AA</span><span dir=3D"LTR" st=
yle=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D9=
=88=D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1
=D9=88=D8=A8=D9=86=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=
=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A</span><span dir=3D"LTR" style=3D"font-=
size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D9=86=D8=B8=D9=85 =D8=A7=D9=84=D8=A3=D8=AC=D9=
=88=D8=B1 =D9=88=D8=A7=D9=84=D8=AD=D9=88=D8=A7=D9=81=D8=B2
=D9=88=D8=A7=D9=84=D9=85=D8=B2=D8=A7=D9=8A=D8=A7</span><span dir=3D"LTR" st=
yle=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-si=
ze:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-=
height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font=
-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stret=
ch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roma=
n&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fon=
t-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=B9=D9=84=D8=
=A7=D9=82=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D9=85=D9=84
=D9=88=D8=A7=D9=84=D9=86=D8=B2=D8=A7=D8=B9=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=
=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:1=
8pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><u><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:11=
5%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=AB=D8=A7=D9=
=86=D9=8A=D9=8B=D8=A7: =D9=82=D8=A7=D9=86=D9=88=D9=86 =D8=A7=D9=84=D8=B9=D9=
=85=D9=84 (=D8=A5=D8=B7=D8=A7=D8=B1 =D8=B9=D8=A7=D9=85
=D9=85=D9=82=D8=A7=D8=B1=D9=86)</span></u></b><b><u><span dir=3D"LTR" style=
=3D"font-size:22pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif"></span></u></b></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D8=A7=D9=84=D9=85=D8=A8=D8=A7=D8=AF=D8=A6 =D8=
=A7=D9=84=D8=B9=D8=A7=D9=85=D8=A9
=D9=84=D9=82=D9=88=D8=A7=D9=86=D9=8A=D9=86 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =
=D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D=
"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=B9=D9=82=D9=88=D8=AF =D8=A7=D9=84=D8=B9=D9=
=85=D9=84 =D9=88=D8=A3=D9=86=D9=88=D8=A7=D8=B9=D9=87=D8=A7
=D9=88=D8=AD=D9=82=D9=88=D9=82 =D9=88=D9=88=D8=A7=D8=AC=D8=A8=D8=A7=D8=AA =
=D8=A7=D9=84=D8=A3=D8=B7=D8=B1=D8=A7=D9=81</span><span dir=3D"LTR" style=3D=
"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=B3=D8=A7=D8=B9=D8=A7=D8=AA =D8=A7=D9=84=D8=
=B9=D9=85=D9=84=D8=8C
=D8=A7=D9=84=D8=A5=D8=AC=D8=A7=D8=B2=D8=A7=D8=AA=D8=8C =D9=88=D8=A7=D9=84=
=D8=AC=D8=B2=D8=A7=D8=A1=D8=A7=D8=AA</span><span dir=3D"LTR" style=3D"font-=
size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=
=AE=D8=AF=D9=85=D8=A9
=D9=88=D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=
=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:1=
8pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D8=AA=D9=81=D8=AA=D9=8A=D8=B4 =D8=
=A7=D9=84=D8=B9=D9=85=D8=A7=D9=84=D9=8A
=D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=8A=D8=A7=D8=AA =D8=A7=
=D9=84=D9=82=D8=A7=D9=86=D9=88=D9=86=D9=8A=D8=A9</span><span dir=3D"LTR" st=
yle=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-si=
ze:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-=
height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font=
-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stret=
ch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roma=
n&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fon=
t-family:Arial,sans-serif">=D8=A7=D9=84=D9=86=D8=B2=D8=A7=D8=B9=D8=A7=D8=AA=
 =D8=A7=D9=84=D8=B9=D9=85=D8=A7=D9=84=D9=8A=D8=A9
=D9=88=D8=A2=D9=84=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=
=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=83=D9=8A=D9=85</span><span dir=3D"=
LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><u><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:11=
5%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=AB=D8=A7=D9=
=84=D8=AB=D9=8B=D8=A7: =D8=A7=D9=84=D8=AA=D8=A3=D9=85=D9=8A=D9=86=D8=A7=D8=
=AA =D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D9=8A=D8=A9 (=D8=A5=D8=
=B7=D8=A7=D8=B1
=D8=B9=D8=A7=D9=85 =D8=AF=D9=88=D9=84=D9=8A)</span></u></b><b><u><span dir=
=3D"LTR" style=3D"font-size:22pt;line-height:115%;font-family:&quot;AlShark=
Title Black&quot;,sans-serif"></span></u></b></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D8=A7=D9=84=D9=85=D9=81=D8=A7=D9=87=D9=8A=D9=
=85 =D8=A7=D9=84=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9
=D9=84=D9=86=D8=B8=D9=85 =D8=A7=D9=84=D8=AA=D8=A3=D9=85=D9=8A=D9=86=D8=A7=
=D8=AA =D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D9=8A=D8=A9</span><=
span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D8=A7=D8=B4=D8=AA=D8=B1=D8=A7=D9=
=83=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D9=85=D8=B2=D8=A7=D9=8A=D8=A7
=D8=A7=D9=84=D8=AA=D8=A3=D9=85=D9=8A=D9=86=D9=8A=D8=A9</span><span dir=3D"L=
TR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=A5=D8=B5=D8=A7=D8=A8=D8=A7=D8=AA =D8=A7=D9=
=84=D8=B9=D9=85=D9=84
=D9=88=D8=A7=D9=84=D8=A3=D9=85=D8=B1=D8=A7=D8=B6 =D8=A7=D9=84=D9=85=D9=87=
=D9=86=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:18pt;line-hei=
ght:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D9=85=D8=B9=D8=A7=D8=B4=D8=A7=D8=AA =D8=A7=D9=
=84=D8=AA=D9=82=D8=A7=D8=B9=D8=AF
=D9=88=D8=A7=D9=84=D8=AA=D8=B9=D9=88=D9=8A=D8=B6=D8=A7=D8=AA</span><span di=
r=3D"LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=A7=D9=84=D8=AA=D8=B2=D8=A7=D9=85=D8=A7=D8=
=AA =D8=B5=D8=A7=D8=AD=D8=A8 =D8=A7=D9=84=D8=B9=D9=85=D9=84
=D9=88=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D9=84</span><span dir=3D"LTR" style=3D=
"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-si=
ze:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-=
height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font=
-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stret=
ch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roma=
n&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fon=
t-family:Arial,sans-serif">=D8=A7=D9=84=D8=B9=D9=84=D8=A7=D9=82=D8=A9 =D8=
=A8=D9=8A=D9=86
=D8=A7=D9=84=D8=AA=D8=A3=D9=85=D9=8A=D9=86=D8=A7=D8=AA =D9=88=D8=A5=D8=AF=
=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=
=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span><span lang=3D"AR-EG" style=3D"font-siz=
e:18pt;line-height:115%;font-family:Arial,sans-serif"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><u><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:11=
5%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=B1=D8=A7=D8=
=A8=D8=B9=D9=8B=D8=A7: =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=88=D8=
=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=84 =D9=81=D9=8A
=D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=
=D9=8A=D8=A9</span></u></b><b><u><span dir=3D"LTR" style=3D"font-size:22pt;=
line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif"></s=
pan></u></b></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 120.15pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D8=A7=D9=84=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=
=84 =D8=A7=D9=84=D8=AA=D8=B4=D8=B1=D9=8A=D8=B9=D9=8A =D9=81=D9=8A
=D8=B3=D9=8A=D8=A7=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=
=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" s=
tyle=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 120.15pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=
=85=D8=AE=D8=A7=D8=B7=D8=B1
=D8=A7=D9=84=D9=82=D8=A7=D9=86=D9=88=D9=86=D9=8A=D8=A9</span><span dir=3D"L=
TR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 120.15pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D8=AD=D9=85=D8=A7=D9=8A=D8=A9 =D8=A7=D9=84=D8=
=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA
=D9=88=D8=A7=D9=84=D8=AE=D8=B5=D9=88=D8=B5=D9=8A=D8=A9</span><span dir=3D"L=
TR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 120.15pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-si=
ze:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-=
height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font=
-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stret=
ch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roma=
n&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fon=
t-family:Arial,sans-serif">=D8=A3=D8=AE=D9=84=D8=A7=D9=82=D9=8A=D8=A7=D8=AA=
 =D8=A7=D9=84=D9=85=D9=87=D9=86=D8=A9 =D9=81=D9=8A
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =
=D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D=
"font-size:18pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif">

</p><table cellpadding=3D"0" cellspacing=3D"0" align=3D"left">
 <tbody><tr>
  <td width=3D"21" height=3D"17"></td>
 </tr>
 <tr>
  <td></td>
  <td><img width=3D"600" height=3D"2"></td>
 </tr>
</tbody></table>

<b><span dir=3D"LTR" style=3D"font-size:20pt;line-height:115%;font-family:&=
quot;AlSharkTitle Black&quot;,sans-serif">=C2=A0</span></b><p></p>

<br clear=3D"ALL">

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;=
font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=A7=D9=84=D9=81=
=D8=A6=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9</span><=
/b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" s=
tyle=3D"font-size:20pt;line-height:115%;font-family:&quot;AlSharkTitle Blac=
k&quot;,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</sp=
an></b></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 120.15pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=D9=
=85=D9=88=D8=A7=D8=B1=D8=AF
=D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D=
"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 120.15pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88 =D8=B4=D8=
=A4=D9=88=D9=86 =D8=A7=D9=84=D8=B9=D8=A7=D9=85=D9=84=D9=8A=D9=86</span><spa=
n dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 120.15pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88 =D8=A7=D9=
=84=D8=AA=D9=88=D8=B8=D9=8A=D9=81
=D9=88=D8=A7=D9=84=D8=B1=D9=88=D8=A7=D8=AA=D8=A8</span><span dir=3D"LTR" st=
yle=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 120.15pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=D8=
=A5=D8=AF=D8=A7=D8=B1=D8=A7=D8=AA
=D8=A7=D9=84=D9=82=D8=A7=D9=86=D9=88=D9=86=D9=8A=D8=A9</span><span dir=3D"L=
TR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 120.15pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"=
RTL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;f=
ont-family:Arial,sans-serif">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88 =D8=A7=D9=
=84=D8=A7=D9=85=D8=AA=D8=AB=D8=A7=D9=84
=D9=88=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9</span><span dir=3D"LTR" st=
yle=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 120.15pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-si=
ze:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-=
height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font=
-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stret=
ch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roma=
n&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fon=
t-family:Arial,sans-serif">=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D9=84=D9=88=D9=86=
 =D9=81=D9=8A =D8=A7=D9=84=D8=AC=D9=87=D8=A7=D8=AA
=D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=B4=
=D8=B1=D9=83=D8=A7=D8=AA =D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9</span><=
span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:24pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">=D8=A7=D9=84=D8=B4=D9=80=D9=80=D9=80=D9=80=D9=87=D8=A7=D8=
=AF=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><s=
pan dir=3D"LTR" style=3D"font-size:24pt;line-height:115%;font-family:&quot;=
AlSharkTitle Black&quot;,sans-serif"><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span>:</span></b></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 127.2pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-si=
ze:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-=
height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font=
-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stret=
ch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roma=
n&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=AF=D8=A8=D9=84=
=D9=88=D9=85 =D9=85=D9=87=D9=86=D9=8A =D9=85=D8=B9=D8=AA=D9=85=D8=AF =D9=85=
=D9=86 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=
=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:18pt;li=
ne-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 127.2pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-siz=
e:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-h=
eight:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font-=
size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stretc=
h:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman=
&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=B4=D9=87=D8=A7=
=D8=AF=D8=A9 =D8=AF=D9=88=D9=84=D9=8A=D8=A9 =D8=A8=D8=B5=D9=8A=D8=BA=D8=A9 =
=D8=B9=D8=A7=D9=85=D8=A9 =D8=B5=D8=A7=D9=84=D8=AD=D8=A9 =D9=84=D9=84=D8=A7=
=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D9=81=D9=8A =D8=AC=D9=85=D9=8A=D8=B9 =
=D8=A7=D9=84=D8=AF=D9=88=D9=84</span><span dir=3D"LTR" style=3D"font-size:1=
8pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0cm 127=
.2pt 8pt 0cm;text-align:center;direction:rtl;unicode-bidi:embed;line-height=
:115%;font-size:12pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" styl=
e=3D"font-size:18pt;line-height:115%">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:22pt;line-height:115%;font-family:Arial,sans-serif">=D8=A8=D9=8A=
=D8=A7=D9=86=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84
=D9=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=
=D8=AA=D9=81=D8=B3=D8=A7=D8=B1</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:22pt;line-height:115%"><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:22pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">=D8=A3/ =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=
=D9=84=D8=AC=D9=88=D8=A7=D8=AF =E2=80=93 =D9=85=D8=AF=D9=8A=D8=B1
=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8</span></b><span dir=3D"LTR" styl=
e=3D"font-size:18pt;line-height:115%"><br>
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;font-f=
amily:Arial,sans-serif">=D8=A7=D9=84=D9=87=D8=A7=D8=AA=D9=81</span><span di=
r=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-s=
ize:18pt;line-height:115%"><span dir=3D"LTR"></span><span dir=3D"LTR"></spa=
n>:<br>
</span><i><span dir=3D"LTR" style=3D"font-size:20pt;line-height:115%;font-f=
amily:&quot;Times New Roman&quot;,serif">00201069994399<br>
00201062992510<br>
00201096841626</span></i><span dir=3D"LTR" style=3D"font-size:22pt;line-hei=
ght:115%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif"><br>
</span><span lang=3D"AR-SA" style=3D"font-size:22pt;line-height:115%;font-f=
amily:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=A7=D9=84=D8=AC=D9=87=
=D8=A9: =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=
=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:18pt;li=
ne-height:115%"></span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;=
font-size:12pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=3D"=
font-size:18pt;line-height:115%;font-family:Arial,sans-serif">=C2=A0</span>=
</p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKkoGgycLa%3D-Lz4pcqvjjMmRMi9WONYECK5FGh_Y%3D0xNCQ%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CADj1ZKkoGgycLa%3D-Lz4pcqvjjMmRMi9WONYECK5FGh_Y%3D0xNCQ%40=
mail.gmail.com</a>.<br />

--000000000000d99ffc0646218050--
