Return-Path: <kasan-dev+bncBDM2ZIVFZQPBB5WGZHCAMGQE6AKRYUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A5EA8B1BB41
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 22:03:04 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-3325c145d34sf18660961fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 13:03:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754424184; cv=pass;
        d=google.com; s=arc-20240605;
        b=VAm7Zlz2IUipZoJem+hriiNDyjFTwAtI5ot+3yItJGd3KcO/xyKOSyj12AWk6Ezz21
         LWoWu9vcOuRbdAIoi0ISV5M/BI2mrdOh3q0fd3fdaLH4BPqJam6ehzKQYKNj60wBYDzi
         BRu5vvISreJjxWqxqsS+nNclRl57vBGS9FDkmwj9GNIIfpmR2kw1NrkF561qRfSn3T1Q
         m8V32fFMF/iEZQtNfGeZO/ubE/ZJC1ZEpYULjqKlJWKPTzC8tZYylLOQfh6hbnzDFCcT
         sXWRyq0ozRKhDz3C6UaI65OOCaS7ZMpZIKUGczHFJ+f5sTCRMQuB+oYeW/3eD0D4H4Es
         kBTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=CRLGCm+QhpGwRXhdor/pW65RxbEZ1s1D3GRw4OqjfB8=;
        fh=svj1H/+ruL8uRuK9toSLG40P92jf7AcfS+Sk43XAkgE=;
        b=HswJbV7Lyo8eFSUkDNd4xd73CalGZ1nDp0jACmd3RQcY2cF3PZzMK4TdhMe8ViMHr1
         6fjJ4wd6Bg5eTom65OAzqEYypMHdhky6ncSKEt6Xnc289zmdWQGyAGEfnB0pjiU24H0C
         1wc2okwIwp9Mx7x8Sx3+r+xbmBHZLAHEjPyAy7H7aTOkY09Wxigm/dzUUckO/YOteitc
         mF0tr0PpX2YbN4wahADLgp9IbLVemmUdYWTISL/XS8slnzck1tRrX7aSidWitaiC8TGo
         j5F9AF8SjBqok4yR21F2JEInrvH3Nqb6AKBd+Bopg0tFIWFua0yxr78+Kv5aGmeLkito
         YSQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZQXzfYXM;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754424184; x=1755028984; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CRLGCm+QhpGwRXhdor/pW65RxbEZ1s1D3GRw4OqjfB8=;
        b=hBiGpiWy1CDgWsBooE3FIirt9X5FDAVQNPGJcVi5pUxCwcKt2wZpyrXW3KwAS4wHXp
         97jPECTS/vJJupTL0yAnHrH2gH6cuHcDWNkgN42WCZadY8AKqQ3AMUPi4Rfy2M+ENinb
         e3M5X0VXFbHzlduqM6IDiwiZZzz3ar5ecOgtvpDf8XbQoOFAWPNrSXVXi2B1IUANhurl
         T/1TQLFARl2nkFoyNWl2HxBwY4+K4P4ojyA0e0ZJby859hAKNaXWipCFaZ1iIfiM43HT
         M2iNGp13fs3OS7rnw5G1IsKNYHGpKVh+EQpyOLD1NP/lZOx2d3eYAq5StfjYcdvSTB3f
         Iwgg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754424184; x=1755028984; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=CRLGCm+QhpGwRXhdor/pW65RxbEZ1s1D3GRw4OqjfB8=;
        b=VxRkKdHMIxJNBzOpMv7k/raekaPUOanIpvxwd4Dsej2NafIwurABLZk14Sean2oJGo
         0BdMb8pxjYpP78EcoQcJ2QzxMRBXhooJeOvuBlfU0gM2ewoz22QLAQlA72BsHs+DEuWD
         Z7aLQr11FvC12umk2VewTGNG1o8i/GE9Ipsu8Zoy4hQ003pucaqlO8Qic1XySJ6fXIXK
         3IGFhmaXwMtxytzNUBrFIFqG1GOd2PGaKFaRpc2184UQr4sfIojwRUq5hDovpJCv9uZ4
         9KsEGoZaQbt3GKVBklKlO6Ivv8F4QAXgIQZqitInTG39zrqxRDGg5pfUiLzWqYX6dfvp
         pPow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754424184; x=1755028984;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CRLGCm+QhpGwRXhdor/pW65RxbEZ1s1D3GRw4OqjfB8=;
        b=cmDJMQhaaBoSIO7YFdNYhNCAoJHxS1Apyd733bYme9LAVwC3fC7OiqN068ngX6UVex
         xPh/xGVROf/xSbTS++5LUcrK3DbWzyZDZpdEj1qmd5C4ngO1Qkgl1vBflT2a1AmfBe76
         cb4vGS6X54PFE6MQttxBQOpNy0VOF/xs9lHW4V5TIJF40W+QgLtiPCB2zAZiFigqByY/
         Z1yItjIMMKejeZivIx2iwlXNGdp06Bo7K2nxaD/rlo9ajPmMXFWJB675JEW27bQ1hfrA
         ZA+mGG2/VpreAzw2wSzBkeOnTRmvk9/M2qQwG6F2d8kkORygdtks3f4iqvVJhBqSbLAP
         bruQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW4TozfISJqeZacsIIDalVBxzadIOqyC2h3v/knLsOOhTEDQLxTMd7RvjKaAh/h92yQgJjUng==@lfdr.de
X-Gm-Message-State: AOJu0YzQ2uO++HsEtlkOC5v0ocC2iFrNligoSAgJum7nZFkJDWcM8QKZ
	xJ8fsRnSw3qNYlHjmWBi32rHBqawlGDXInWSdCzRs1lTji0rzzKot2DE
X-Google-Smtp-Source: AGHT+IGNKPUBXVa+ThTjzRVOBFNeJL6nWv290GUZVXzh1mNzNIxQ3KWm36v5jRxu/wd4k/0mZh/nVw==
X-Received: by 2002:a2e:bea0:0:b0:32b:9220:8020 with SMTP id 38308e7fff4ca-3338143b308mr296351fa.34.1754424183478;
        Tue, 05 Aug 2025 13:03:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfIsdpDzug6uak49Pyob/eZ+hkBAdS4IoNldZO61uwc4A==
Received: by 2002:a05:651c:2204:b0:32f:4573:b6ba with SMTP id
 38308e7fff4ca-33238203005ls15392341fa.0.-pod-prod-09-eu; Tue, 05 Aug 2025
 13:03:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVF0fe4YLwySf+xRN/18w4dWT08GWsvTWTVU0Lug/cmelac4NC+sGtymkGDPSAn8XFotnhnUCUY+8E=@googlegroups.com
X-Received: by 2002:a05:651c:2113:b0:332:6b5e:b1a0 with SMTP id 38308e7fff4ca-333813c3645mr277571fa.22.1754424180661;
        Tue, 05 Aug 2025 13:03:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754424180; cv=none;
        d=google.com; s=arc-20240605;
        b=SInUtNmWOYIvDUm5s43p92jFKpG2C828igAPFn+lUo0U6cTYVL6kwHxjWWfy/QevT/
         JMQc8ZT1AzjmV7lno2pzfxiOAu5VNunSP/idQ3bq3DePs0JbYqgaRzplLP6ag/jmojDH
         WnkSIU3FrquacPvqhKLLwPhpW3aeTR4PGQyH0skqaIxsjW1DQHIZLJa95txpiXN1G1fY
         5Ek3dv5I2bkPs/xq4Di0vmeesxhzksxkwluWue6U2qD8QtEClpU+gDKWPzLbzGa3jVk6
         TR1gJo1T5Vce6h6ct4FGh+9bN5qJuEo9TeZnJMitqHSLO4kNZEDvvc1T91sXEhz0VmEE
         2v1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=iytQDNMh744X4M5es5CP+KdtSElCAv7sbIZ/Wc152Ks=;
        fh=x1ZnMLAankWvmGqCV06ecMzods08nn/apYw75EhiVSA=;
        b=ABE5B/LwVcdBs6QjrI4TXYOB5y3CFfyTsCzxCfxFMREaMnILAtdibFTyFR4//eVT5R
         v1gktTrLV4N/D6o50ESJ4DdFL0Lach0czgieBVBziQJ7qjsWJtPCOIWrJp3R9QRTk7vs
         qHYCWKAOTBcLCIaPV6Gr/22onzPGDeXHtZ7JRH28XgtXLADiFFbM6bTiLsGChXt9oXty
         JEd9NLDexWgYF03sCzo3z+95xQuRRU6PYptJWIXS3bqEnK2WE8ulZEE4DyBNTCMEPjDg
         sr7zuQHLg96yvies7WJPGtuXEwmO3WH4qh0Xz7k3Lw07yulBsWp92h4jVPsPCCZnDvEF
         C/uQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZQXzfYXM;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-33237ffc702si3789011fa.3.2025.08.05.13.03.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 13:03:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id a640c23a62f3a-af949bdf36cso637776566b.0
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 13:03:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXXxu3tFRJEocxeG9VAibGtw0c6KBe5IP0BhYgyT8Egzj1ADz38ZDfApFYCrn9IbHJo/cfwmPUPuUA=@googlegroups.com
X-Gm-Gg: ASbGncs7RRgmwNDE3XX114fZc9xZbYLgowYZr08SnqsLmU+HfGPvIkVwGAtoNTfPY/c
	q1FqclkXIRe6PI3EAA4BUJpluRt8bOFiZKkYYFAaO146oWwFyJ9FHMQZVAwHFX+XX7GRch8RpqG
	B0pSM4LgF25jbiqKX/NNvk2hpIaXJGBJJ9qkFyZrXP8sOdE01X5mMyPheeO1ImRZbSilPmNYw7W
	i5wL1Vqt6rxKOEl9EU=
X-Received: by 2002:a17:907:7287:b0:ae0:afb7:6060 with SMTP id
 a640c23a62f3a-af9900375f7mr32233666b.19.1754424179573; Tue, 05 Aug 2025
 13:02:59 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Wed, 6 Aug 2025 00:08:53 +0300
X-Gm-Features: Ac12FXynNM9Z254Uyd7cNHjBIyDExbwJ1uGQaWW5A8eG85wik8CBcOixqHsRYo0
Message-ID: <CADj1ZKnDsZ8-uBALn6sWG34a=4C+ae_jXpLL571fJUpdqXcD+Q@mail.gmail.com>
Subject: =?UTF-8?B?2KzYr9mI2YQg2KjYsdin2YXYrCDYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKIA==?=
	=?UTF-8?B?2YTZg9in2YHYqSDYp9mE2YXYrNin2YTYp9iqINiu2YTYp9mEINin2YTZgdiq2LHYqSDZhdmGIDE3INij?=
	=?UTF-8?B?2LrYs9i32LMg2KXZhNmJIDMxINiv2YrYs9mF2KjYsSAyMDI12Iwg2KjYrdmK2Ksg2YrYrdiq2YjZiiA=?=
	=?UTF-8?B?2YPZhCDYqNix2YbYp9mF2Kwg2LnZhNmJIDgwINiz2KfYudipINiq2K/YsdmK2KjZitipINmF2LnYqtmF?=
	=?UTF-8?B?2K/YqTo=?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000024bc6063ba3b6ff"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZQXzfYXM;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62b
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

--000000000000024bc6063ba3b6ff
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

Ktin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNin2K/Yp9ix2YrY
qSAtICoqQUhBRCoNCg0K2YXYpyDZh9mIINin2YTZhdin2KzYs9iq2YrYsSDYp9mE2YXZh9mG2YrY
nw0KDQrYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKINmH2Ygg2K/Ysdis2Kkg2K/Ysdin
2LPYp9iqINi52YTZitinINiq2LHZg9iyINi52YTZiSDYp9mE2KrYt9io2YrZgiDYp9mE2LnZhdmE
2Yog2YjYp9mE2YbZiNin2K3Zig0K2KfZhNmF2YfZhtmK2KnYjCDZiNiq2YfYr9mBINil2YTZiSDY
qtij2YfZitmEINin2YTYo9mB2LHYp9ivINmE2YTYudmF2YQg2KjZg9mB2KfYodipINi52KfZhNmK
2Kkg2YHZiiDYqtiu2LXYtdin2KrZh9mFLiDYutin2YTYqNmL2Kcg2YXYpw0K2YrYqtmFINiq2YLY
r9mK2YUg2YfYsNmHINin2YTYqNix2KfZhdisINmF2YYg2YLYqNmEINis2KfZhdi52KfYqiDZhdit
2YTZitipINmI2K/ZiNmE2YrYqSDZhdix2YXZiNmC2KnYjCDZiNiq2LTZhdmEINmF2LLZitis2YvY
pyDZhdmGDQrYp9mE2YXYrdin2LbYsdin2Kog2KfZhNmG2LjYsdmK2KnYjCDZiNin2YTZhdi02KfY
sdmK2Lkg2KfZhNi52YXZhNmK2KnYjCDZiNin2YTYqtiv2LHZitioINin2YTZhdmK2K/Yp9mG2You
DQoNCtmI2KrYsdmD2LIg2YfYsNmHINin2YTYqNix2KfZhdisINi52YTZiSDYqti32YjZitixINin
2YTZhdmH2KfYsdin2Kog2KfZhNmC2YrYp9iv2YrYqdiMINmI2KfZhNil2K/Yp9ix2YrYqdiMINmI
2KfZhNiq2K3ZhNmK2YTZitipINin2YTYqtmKDQrZitit2KrYp9is2YfYpyDYp9mE2KPZgdix2KfY
ryDZhNmE2YbYrNin2K0g2YHZiiDYqNmK2KbYp9iqINin2YTYudmF2YQg2KfZhNmF2KrYutmK2LHY
qS4NCg0K2KfZhNmB2LHZgiDYqNmK2YYg2KfZhNmF2KfYrNiz2KrZitixINin2YTZhdmH2YbZiiDZ
iNin2YTYo9mD2KfYr9mK2YXZig0KDQrYp9mE2YfYr9mBOiDZitmH2K/ZgSDYp9mE2YXYp9is2LPY
qtmK2LEg2KfZhNmF2YfZhtmKINil2YTZiSDYqtmG2YXZitipINin2YTZhdmH2KfYsdin2Kog2KfZ
hNi52YXZhNmK2Kkg2YjYp9mE2KrYt9io2YrZgtmK2KnYjCDYqNmK2YbZhdinDQrZitix2YPYsiDY
p9mE2KPZg9in2K/ZitmF2Yog2LnZhNmJINin2YTYqNit2Ksg2KfZhNi52YTZhdmKINmI2KXZhtiq
2KfYrCDYp9mE2YXYudix2YHYqS4NCg0K2KfZhNis2YXZh9mI2LEg2KfZhNmF2LPYqtmH2K/ZgTog
2KfZhNio2LHYp9mF2Kwg2KfZhNmF2YfZhtmK2Kkg2KrZj9i12YXZhSDYrti12YrYtdmL2Kcg2YTZ
hNmF2YjYuNmB2YrZhiDZiNij2LXYrdin2Kgg2KfZhNiu2KjYsdipDQrYp9mE2LnZhdmE2YrYqSDY
p9mE2LDZitmGINmK2LHYutio2YjZhiDZgdmKINin2YTYqtix2YLZitipINij2Ygg2KfZhNiq2LrZ
itmK2LEg2KfZhNmF2YfZhtmK2Iwg2LnZhNmJINi52YPYsyDYp9mE2KPZg9in2K/ZitmF2Yog2KfZ
hNiw2YoNCtmK2Y/Zhtin2LPYqCDYp9mE2KjYp9it2KvZitmGINmI2KfZhNmF2YfYqtmF2YrZhiDY
qNin2YTYr9mD2KrZiNix2KfZhy4NCg0K2KfZhNmF2K3YqtmI2Yk6INiq2KrYttmF2YYg2KfZhNio
2LHYp9mF2Kwg2KfZhNmF2YfZhtmK2Kkg2K/Ysdin2LPYp9iqINit2KfZhNip2Iwg2YjYqtiv2LHZ
itioINi52YXZhNmK2Iwg2YjZhdmH2KfZhSDZhdmK2K/Yp9mG2YrYqdiMDQrYqNmK2YbZhdinINmK
2LnYqtmF2K8g2KfZhNij2YPYp9iv2YrZhdmKINi52YTZiSDYp9mE2KPYt9ixINin2YTZhti42LHZ
itipINmI2KfZhNij2KjYrdin2KsuDQoNCtin2YTZhdiu2LHYrCDYp9mE2YbZh9in2KbZijog2YHZ
iiDYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNij2YPYp9iv2YrZhdmKINmK2Y/Yt9mE2Kgg2LnYp9iv
2KnZiyDYqtmC2K/ZitmFINix2LPYp9mE2Kkg2LnZhNmF2YrYqdiMINio2YrZhtmF2KcNCtmB2Yog
2KfZhNmF2YfZhtmKINmK2YPZiNmGINin2YTZhdi02LHZiNi5INin2YTZhtmH2KfYptmKINi52YXZ
hNmK2ZHZi9inINmK2Y/Yt9io2YIg2YHZiiDYqNmK2KbYqSDYp9mE2LnZhdmELg0KDQoNCirYrNiv
2YjZhCDYqNix2KfZhdisINin2YTZhdin2KzYs9iq2YrYsSDYp9mE2YXZh9mG2YoqINmE2YPYp9mB
2Kkg2KfZhNmF2KzYp9mE2KfYqiDYrtmE2KfZhCDYp9mE2YHYqtix2Kkg2YXZhiAqMTcgKirYo9i6
2LPYt9izINil2YTZiQ0KMzEg2K/Zitiz2YXYqNixIDIwMjUq2Iwg2KjYrdmK2Ksg2YrYrdiq2YjZ
iiDZg9mEINio2LHZhtin2YXYrCDYudmE2YkgKjgwICoq2LPYp9i52Kkg2KrYr9ix2YrYqNmK2Kkg
2YXYudiq2YXYr9ipKjoNCg0KDQoNCirYrNiv2YjZhCDYqNix2KfZhdisINin2YTZhdin2KzYs9iq
2YrYsSDYp9mE2YXZh9mG2YogfCDYo9i62LPYt9izIOKAkyDYr9mK2LPZhdio2LEgMjAyNSoNCg0K
KtmFKg0KDQoq2KfYs9mFINin2YTYqNix2YbYp9mF2KwqDQoNCirYp9mE2YXYrNin2YQqDQoNCirY
p9mE2YXYr9ipINin2YTYstmF2YbZitipKg0KDQoq2KrYp9ix2YrYriDYp9mE2KfZhti52YLYp9iv
Kg0KDQoq2KfZhNiv2YjZhNipIC8g2KfZhNmF2K/ZitmG2KkqDQoNCjENCg0K2KfZhNmF2KfYrNiz
2KrZitixINin2YTZhdmH2YbZiiDZgdmKINil2K/Yp9ix2Kkg2KfZhNij2LnZhdin2YQg2KfZhNiq
2YbZgdmK2LDZitipIChFTUJBKQ0KDQrYpdiv2KfYsdipINin2YTYo9i52YXYp9mEDQoNCjgwINiz
2KfYudipINmF2LnYqtmF2K/YqQ0KDQoxNyAtIDI4INij2LrYs9i32LMgMjAyNQ0KDQrYp9mE2YLY
p9mH2LHYqSDigJMg2YXYtdixDQoNCjINCg0K2KfZhNmF2KfYrNiz2KrZitixINin2YTZhdmH2YbZ
iiDZgdmKINin2YTZhdmI2KfYsdivINin2YTYqNi02LHZitipDQoNCtin2YTZhdmI2KfYsdivINin
2YTYqNi02LHZitipDQoNCjgwINiz2KfYudipINmF2LnYqtmF2K/YqQ0KDQoxIC0gMTIg2LPYqNiq
2YXYqNixIDIwMjUNCg0K2K/YqNmKIOKAkyDYp9mE2KXZhdin2LHYp9iqDQoNCjMNCg0K2KfZhNmF
2KfYrNiz2KrZitixINin2YTZhdmH2YbZiiDZgdmKINin2YTZhdit2KfYs9io2Kkg2YjYp9mE2YXY
p9mE2YrYqQ0KDQrYp9mE2YXYp9mE2YrYqSDZiNin2YTZhdit2KfYs9io2KkNCg0KODAg2LPYp9i5
2Kkg2YXYudiq2YXYr9ipDQoNCjE1IC0gMjYg2LPYqNiq2YXYqNixIDIwMjUNCg0K2KfYs9i32YbY
qNmI2YQg4oCTINiq2LHZg9mK2KcNCg0KNA0KDQrYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZ
htmKINmB2Yog2KXYr9in2LHYqSDYp9mE2YXYtNin2LHZiti5IFBNUA0KDQrYpdiv2KfYsdipINin
2YTZhdi02KfYsdmK2LkNCg0KODAg2LPYp9i52Kkg2YXYudiq2YXYr9ipDQoNCjYgLSAxNyDYo9mD
2KrZiNio2LEgMjAyNQ0KDQrYp9mE2YLYp9mH2LHYqSDigJMg2YXYtdixDQoNCjUNCg0K2KfZhNmF
2KfYrNiz2KrZitixINin2YTZhdmH2YbZiiDZgdmKINin2YTZgtmK2KfYr9ipINmI2KfZhNiq2K3Z
iNmEINin2YTZhdik2LPYs9mKDQoNCtin2YTZgtmK2KfYr9ipINmI2KfZhNiq2K3ZiNmEINin2YTZ
hdik2LPYs9mKDQoNCjgwINiz2KfYudipINmF2LnYqtmF2K/YqQ0KDQoyMCAtIDMxINij2YPYqtmI
2KjYsSAyMDI1DQoNCtiv2KjZiiDigJMg2KfZhNil2YXYp9ix2KfYqg0KDQo2DQoNCtin2YTZhdin
2KzYs9iq2YrYsSDYp9mE2YXZh9mG2Yog2YHZiiDYpdiv2KfYsdipINin2YTYqti62YrZitixINmI
2YLZitin2K/YqSDYp9mE2KPYstmF2KfYqg0KDQrYp9mE2KXYr9in2LHYqSDYp9mE2KfYs9iq2LHY
p9iq2YrYrNmK2KkNCg0KODAg2LPYp9i52Kkg2YXYudiq2YXYr9ipDQoNCjMgLSAxNCDZhtmI2YHZ
hdio2LEgMjAyNQ0KDQrYp9mE2YLYp9mH2LHYqSDigJMg2YXYtdixDQoNCjcNCg0K2KfZhNmF2KfY
rNiz2KrZitixINin2YTZhdmH2YbZiiDZgdmKINin2YTYqtiz2YjZitmCINin2YTYsdmC2YXZiiDZ
iNil2K/Yp9ix2Kkg2KfZhNi52YTYp9mF2KfYqiDYp9mE2KrYrNin2LHZitipDQoNCtin2YTYqtiz
2YjZitmCINmI2KfZhNil2LnZhNin2YUNCg0KODAg2LPYp9i52Kkg2YXYudiq2YXYr9ipDQoNCjE3
IC0gMjgg2YbZiNmB2YXYqNixIDIwMjUNCg0K2KfYs9i32YbYqNmI2YQg4oCTINiq2LHZg9mK2KcN
Cg0KOA0KDQrYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKINmB2Yog2KXYr9in2LHYqSDY
p9mE2KzZiNiv2Kkg2YjYp9mE2K3ZiNmD2YXYqQ0KDQrYp9mE2KzZiNiv2Kkg2YjYp9mE2K3ZiNmD
2YXYqQ0KDQo4MCDYs9in2LnYqSDZhdi52KrZhdiv2KkNCg0KMSAtIDEyINiv2YrYs9mF2KjYsSAy
MDI1DQoNCtiv2KjZiiDigJMg2KfZhNil2YXYp9ix2KfYqg0KDQo5DQoNCtin2YTZhdin2KzYs9iq
2YrYsSDYp9mE2YXZh9mG2Yog2YHZiiDYpdiv2KfYsdipINin2YTZhdi02KrYsdmK2KfYqiDZiNiz
2YTYp9iz2YQg2KfZhNil2YXYr9in2K8NCg0K2KfZhNmF2LTYqtix2YrYp9iqINmI2KfZhNmE2YjY
rNiz2KrZitin2KoNCg0KODAg2LPYp9i52Kkg2YXYudiq2YXYr9ipDQoNCjE1IC0gMjYg2K/Zitiz
2YXYqNixIDIwMjUNCg0K2KfZhNmC2KfZh9ix2Kkg4oCTINmF2LXYsQ0KDQoxMA0KDQrYp9mE2YXY
p9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKINmB2Yog2KfZhNil2K/Yp9ix2Kkg2KfZhNi12K3Zitip
DQoNCtin2YTYtdit2Kkg2YjYp9mE2YXYs9iq2LTZgdmK2KfYqg0KDQo4MCDYs9in2LnYqSDZhdi5
2KrZhdiv2KkNCg0KMjIgLSAzMSDYr9mK2LPZhdio2LEgMjAyNQ0KDQrYp9mE2YLYp9mH2LHYqSDi
gJMg2YXYtdixDQoNCg0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQoNCirwn5OdKiAq
2YXZhNin2K3YuNin2Kog2YXZh9mF2KkqKjoqDQoNCiAgIC0g2KzZhdmK2Lkg2KfZhNio2LHYp9mF
2Kwg2KrZhdmG2K0g2LTZh9in2K/YqSDZhdmI2KvZgtipINmI2YXYudiq2YXYr9ipINmI2YLYp9io
2YTYqSDZhNmE2KrYtdiv2YrZgiDZhdmGINin2YTYrtin2LHYrNmK2KkuDQogICAtINin2YTZhNi6
2Kk6INin2YTYudix2KjZitipICjZhdi5INiq2YjZgdixINmF2KrYsdis2YUg2LnZhtivINin2YTY
rdin2KzYqSDZhNmE2KjYsdin2YXYrCDYp9mE2K/ZiNmE2YrYqSkuDQogICAtINin2YTZgdim2Kkg
2KfZhNmF2LPYqtmH2K/ZgdipOiDYp9mE2YXYr9mK2LHZiNmGINin2YTYqtmG2YHZitiw2YrZiNmG
2Iwg2YXYs9ik2YjZhNmIINin2YTYqti32YjZitix2Iwg2YXYs9ik2YjZhNmIINin2YTYrNmI2K/Y
qdiMDQogICDZgtin2K/YqSDYp9mE2YHYsdmC2Iwg2LHYpNiz2KfYoSDYp9mE2KPZgtiz2KfZhdiM
INmI2LDZiNmIINin2YTYt9mF2YjYrdin2Kog2KfZhNmC2YrYp9iv2YrYqS4NCiAgIC0g2YrZhdmD
2YYg2KrZhtmB2YrYsCDYp9mE2KjYsdin2YXYrCAq2KPZiNmG2YTYp9mK2YYg2LnYqNixKiogWm9v
bSog2KPZiCAq2K3YttmI2LHZiiog2K3Ys9ioINix2LrYqNipINin2YTZhdi02KfYsdmD2YrZhi4N
Cg0KwrcgICAgICAgICAq2YTZhNiq2LPYrNmK2YQg2YjYp9mE2KfYs9iq2YHYs9in2LEqDQoNCsK3
ICAgICAgICAgKtmI2KjZh9iw2Ycg2KfZhNmF2YbYp9iz2KjYqSDZitiz2LnYr9mG2Kcg2K/YudmI
2KrZg9mFINmE2YTZhdi02KfYsdmD2Kkg2YjYqti52YXZitmFINiu2LfYp9io2YbYpyDYudmE2Ykg
2KfZhNmF2YfYqtmF2YrZhg0K2KjZhdmA2YDZiNi22YDZiNi5ICoq2KfZhNi02YfYp9iv2Kkg2KfZ
hNin2K3Yqtix2KfZgdmK2KkgKirZiNil2YHYp9iv2KrZhtinINio2YXZhiDYqtmC2KrYsdit2YjZ
hiDYqtmI2KzZitmHINin2YTYr9i52YjYqSDZhNmH2YUqDQoNCsK3ICAgICAgICAgKtmE2YXYstmK
2K8g2YXZhiDYp9mE2YXYudmE2YjZhdin2Kog2YrZhdmD2YbZgyDYp9mE2KrZiNin2LXZhCDZhdi5
INijIC8g2LPYp9ix2Kkg2LnYqNivINin2YTYrNmI2KfYryDigJMg2YbYp9im2KgNCtmF2K/Zitix
INin2YTYqtiv2LHZitioIOKAkyDYp9mE2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG2YXZ
itipINin2YTYp9iv2KfYsdmK2KkqDQoNCsK3ICAgICAgICAgKtis2YjYp9mEIOKAkyDZiNin2KrY
syDYp9ioIDoqDQoNCsK3ICAgICAgICAgKjAwMjAxMDY5OTk0Mzk5IC0wMDIwMTA2Mjk5MjUxMCAt
IDAwMjAxMDk2ODQxNjI2Kg0KDQotLSAKWW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNl
IHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAia2FzYW4tZGV2IiBncm91
cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFuZCBzdG9wIHJlY2VpdmluZyBlbWFp
bHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byBrYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xl
Z3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24gdmlzaXQgaHR0cHM6Ly9ncm91cHMu
Z29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9DQURqMVpLbkRzWjgtdUJBTG42c1dHMzRhJTNE
NEMlMkJhZV9qWHBMTDU3MWZKVXBkcVhjRCUyQlElNDBtYWlsLmdtYWlsLmNvbS4K
--000000000000024bc6063ba3b6ff
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"margin:9pt 0in 0in;text-align:center;line-height:normal;background-imag=
e:initial;background-position:initial;background-size:initial;background-re=
peat:initial;background-origin:initial;background-clip:initial;direction:rt=
l;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><b><u><=
span lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Segoe UI&quot=
;,sans-serif;color:rgb(0,176,80)">=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=
=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=
=A9 =D8=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 - </span></u></b><b><u=
><span dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Segoe UI&quot;=
,sans-serif;color:rgb(0,176,80)">AHAD</span></u></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0in;text-align:center;line-height:normal;background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" styl=
e=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,sans-serif;color:rgb(4=
0,40,40)">=D9=85=D8=A7 =D9=87=D9=88 =D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=
=AA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=9F</span><span dir=
=3D"LTR" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,sans-seri=
f;color:rgb(40,40,40)"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0in;text-align:center;line-height:normal;background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" styl=
e=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,sans-serif;color:rgb(4=
0,40,40)">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=D9=
=84=D9=85=D9=87=D9=86=D9=8A =D9=87=D9=88 =D8=AF=D8=B1=D8=AC=D8=A9 =D8=AF=D8=
=B1=D8=A7=D8=B3=D8=A7=D8=AA =D8=B9=D9=84=D9=8A=D8=A7 =D8=AA=D8=B1=D9=83=D8=
=B2 =D8=B9=D9=84=D9=89
=D8=A7=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=D9=82 =D8=A7=D9=84=D8=B9=D9=85=D9=84=
=D9=8A =D9=88=D8=A7=D9=84=D9=86=D9=88=D8=A7=D8=AD=D9=8A =D8=A7=D9=84=D9=85=
=D9=87=D9=86=D9=8A=D8=A9=D8=8C =D9=88=D8=AA=D9=87=D8=AF=D9=81 =D8=A5=D9=84=
=D9=89 =D8=AA=D8=A3=D9=87=D9=8A=D9=84 =D8=A7=D9=84=D8=A3=D9=81=D8=B1=D8=A7=
=D8=AF =D9=84=D9=84=D8=B9=D9=85=D9=84 =D8=A8=D9=83=D9=81=D8=A7=D8=A1=D8=A9 =
=D8=B9=D8=A7=D9=84=D9=8A=D8=A9 =D9=81=D9=8A
=D8=AA=D8=AE=D8=B5=D8=B5=D8=A7=D8=AA=D9=87=D9=85. =D8=BA=D8=A7=D9=84=D8=A8=
=D9=8B=D8=A7 =D9=85=D8=A7 =D9=8A=D8=AA=D9=85 =D8=AA=D9=82=D8=AF=D9=8A=D9=85=
 =D9=87=D8=B0=D9=87 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D9=85=D9=86=
 =D9=82=D8=A8=D9=84 =D8=AC=D8=A7=D9=85=D8=B9=D8=A7=D8=AA =D9=85=D8=AD=D9=84=
=D9=8A=D8=A9 =D9=88=D8=AF=D9=88=D9=84=D9=8A=D8=A9 =D9=85=D8=B1=D9=85=D9=88=
=D9=82=D8=A9=D8=8C
=D9=88=D8=AA=D8=B4=D9=85=D9=84 =D9=85=D8=B2=D9=8A=D8=AC=D9=8B=D8=A7 =D9=85=
=D9=86 =D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B6=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=
=D9=86=D8=B8=D8=B1=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=D9=84=D9=85=D8=B4=D8=A7=
=D8=B1=D9=8A=D8=B9 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A9=D8=8C =D9=88=
=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D8=A7=D9=84=D9=85=D9=8A=D8=AF=
=D8=A7=D9=86=D9=8A</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,=
sans-serif;color:rgb(40,40,40)"><span dir=3D"LTR"></span><span dir=3D"LTR">=
</span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0in;text-align:center;line-height:normal;background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" styl=
e=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,sans-serif;color:rgb(4=
0,40,40)">=D9=88=D8=AA=D8=B1=D9=83=D8=B2 =D9=87=D8=B0=D9=87 =D8=A7=D9=84=D8=
=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=B9=D9=84=D9=89 =D8=AA=D8=B7=D9=88=D9=8A=D8=
=B1 =D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=82=D9=
=8A=D8=A7=D8=AF=D9=8A=D8=A9=D8=8C
=D9=88=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=
=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D9=8A =
=D9=8A=D8=AD=D8=AA=D8=A7=D8=AC=D9=87=D8=A7 =D8=A7=D9=84=D8=A3=D9=81=D8=B1=
=D8=A7=D8=AF =D9=84=D9=84=D9=86=D8=AC=D8=A7=D8=AD =D9=81=D9=8A =D8=A8=D9=8A=
=D8=A6=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=
=D8=BA=D9=8A=D8=B1=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span><span dir=3D"LTR" style=3D"font-size:12pt;font-family:&quot;Segoe UI&=
quot;,sans-serif;color:rgb(40,40,40)"><span dir=3D"LTR"></span><span dir=3D=
"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0in;text-align:center;line-height:normal;background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" styl=
e=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,sans-serif;color:rgb(4=
0,40,40)">=D8=A7=D9=84=D9=81=D8=B1=D9=82 =D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D9=
=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=
=8A =D9=88=D8=A7=D9=84=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=D9=85=D9=8A</span><spa=
n dir=3D"LTR" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,sans=
-serif;color:rgb(40,40,40)"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0in;text-align:center;line-height:normal;background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" styl=
e=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,sans-serif;color:rgb(4=
0,40,40)">=D8=A7=D9=84=D9=87=D8=AF=D9=81: =D9=8A=D9=87=D8=AF=D9=81 =D8=A7=
=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=
=D9=86=D9=8A =D8=A5=D9=84=D9=89 =D8=AA=D9=86=D9=85=D9=8A=D8=A9
=D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D9=85=
=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D9=8A=
=D8=A9=D8=8C =D8=A8=D9=8A=D9=86=D9=85=D8=A7 =D9=8A=D8=B1=D9=83=D8=B2 =D8=A7=
=D9=84=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=D9=85=D9=8A =D8=B9=D9=84=D9=89 =D8=A7=
=D9=84=D8=A8=D8=AD=D8=AB =D8=A7=D9=84=D8=B9=D9=84=D9=85=D9=8A =D9=88=D8=A5=
=D9=86=D8=AA=D8=A7=D8=AC
=D8=A7=D9=84=D9=85=D8=B9=D8=B1=D9=81=D8=A9</span><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:12pt;font-fami=
ly:&quot;Segoe UI&quot;,sans-serif;color:rgb(40,40,40)"><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0in;text-align:center;line-height:normal;background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" styl=
e=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,sans-serif;color:rgb(4=
0,40,40)">=D8=A7=D9=84=D8=AC=D9=85=D9=87=D9=88=D8=B1 =D8=A7=D9=84=D9=85=D8=
=B3=D8=AA=D9=87=D8=AF=D9=81: =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=
=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9 =D8=AA=D9=8F=D8=B5=D9=85=D9=85 =D8=
=AE=D8=B5=D9=8A=D8=B5=D9=8B=D8=A7
=D9=84=D9=84=D9=85=D9=88=D8=B8=D9=81=D9=8A=D9=86 =D9=88=D8=A3=D8=B5=D8=AD=
=D8=A7=D8=A8 =D8=A7=D9=84=D8=AE=D8=A8=D8=B1=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=
=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=B0=D9=8A=D9=86 =D9=8A=D8=B1=D8=BA=D8=A8=
=D9=88=D9=86 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B1=D9=82=D9=8A=D8=A9 =D8=A3=
=D9=88 =D8=A7=D9=84=D8=AA=D8=BA=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=
=D9=86=D9=8A=D8=8C =D8=B9=D9=84=D9=89
=D8=B9=D9=83=D8=B3 =D8=A7=D9=84=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=D9=85=D9=8A =
=D8=A7=D9=84=D8=B0=D9=8A =D9=8A=D9=8F=D9=86=D8=A7=D8=B3=D8=A8 =D8=A7=D9=84=
=D8=A8=D8=A7=D8=AD=D8=AB=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D9=85=D9=87=D8=AA=
=D9=85=D9=8A=D9=86 =D8=A8=D8=A7=D9=84=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A7=
=D9=87</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,sans-serif;c=
olor:rgb(40,40,40)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</sp=
an></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0in;text-align:center;line-height:normal;background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" styl=
e=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,sans-serif;color:rgb(4=
0,40,40)">=D8=A7=D9=84=D9=85=D8=AD=D8=AA=D9=88=D9=89: =D8=AA=D8=AA=D8=B6=D9=
=85=D9=86 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D9=85=D9=
=87=D9=86=D9=8A=D8=A9 =D8=AF=D8=B1=D8=A7=D8=B3=D8=A7=D8=AA =D8=AD=D8=A7=D9=
=84=D8=A9=D8=8C
=D9=88=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D8=B9=D9=85=D9=84=D9=8A=D8=8C =D9=88=
=D9=85=D9=87=D8=A7=D9=85 =D9=85=D9=8A=D8=AF=D8=A7=D9=86=D9=8A=D8=A9=D8=8C =
=D8=A8=D9=8A=D9=86=D9=85=D8=A7 =D9=8A=D8=B9=D8=AA=D9=85=D8=AF =D8=A7=D9=84=
=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=D9=85=D9=8A =D8=B9=D9=84=D9=89 =D8=A7=D9=84=
=D8=A3=D8=B7=D8=B1 =D8=A7=D9=84=D9=86=D8=B8=D8=B1=D9=8A=D8=A9 =D9=88=D8=A7=
=D9=84=D8=A3=D8=A8=D8=AD=D8=A7=D8=AB</span><span dir=3D"LTR"></span><span d=
ir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:12pt;font-family:&qu=
ot;Segoe UI&quot;,sans-serif;color:rgb(40,40,40)"><span dir=3D"LTR"></span>=
<span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0in;text-align:center;line-height:normal;background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial;direction:rtl;unicode-bidi:emb=
ed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" styl=
e=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,sans-serif;color:rgb(4=
0,40,40)">=D8=A7=D9=84=D9=85=D8=AE=D8=B1=D8=AC =D8=A7=D9=84=D9=86=D9=87=D8=
=A7=D8=A6=D9=8A: =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=
=8A=D8=B1 =D8=A7=D9=84=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=D9=85=D9=8A =D9=8A=D9=
=8F=D8=B7=D9=84=D8=A8
=D8=B9=D8=A7=D8=AF=D8=A9=D9=8B =D8=AA=D9=82=D8=AF=D9=8A=D9=85 =D8=B1=D8=B3=
=D8=A7=D9=84=D8=A9 =D8=B9=D9=84=D9=85=D9=8A=D8=A9=D8=8C =D8=A8=D9=8A=D9=86=
=D9=85=D8=A7 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=8A=D9=83=
=D9=88=D9=86 =D8=A7=D9=84=D9=85=D8=B4=D8=B1=D9=88=D8=B9 =D8=A7=D9=84=D9=86=
=D9=87=D8=A7=D8=A6=D9=8A =D8=B9=D9=85=D9=84=D9=8A=D9=91=D9=8B=D8=A7 =D9=8A=
=D9=8F=D8=B7=D8=A8=D9=82 =D9=81=D9=8A
=D8=A8=D9=8A=D8=A6=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84</span><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:1=
2pt;font-family:&quot;Segoe UI&quot;,sans-serif;color:rgb(40,40,40)"><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"fon=
t-size:18pt;line-height:107%;font-family:&quot;Segoe UI&quot;,sans-serif;co=
lor:rgb(40,40,40);background-image:initial;background-position:initial;back=
ground-size:initial;background-repeat:initial;background-origin:initial;bac=
kground-clip:initial"><br>
</span><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;fon=
t-family:Arial,sans-serif">=D8=AC=D8=AF=D9=88=D9=84 =D8=A8=D8=B1=D8=A7=D9=
=85=D8=AC =D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=D9=
=84=D9=85=D9=87=D9=86=D9=8A</span></b><span lang=3D"AR-SA" style=3D"font-si=
ze:16pt;line-height:107%;font-family:Arial,sans-serif"> =D9=84=D9=83=D8=A7=
=D9=81=D8=A9
=D8=A7=D9=84=D9=85=D8=AC=D8=A7=D9=84=D8=A7=D8=AA =D8=AE=D9=84=D8=A7=D9=84 =
=D8=A7=D9=84=D9=81=D8=AA=D8=B1=D8=A9 =D9=85=D9=86 </span><span dir=3D"LTR">=
</span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:16p=
t;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>17 </=
span></b><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;f=
ont-family:Arial,sans-serif">=D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 =D8=A5=D9=84=D9=
=89 31 =D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 2025</span></b><span lang=3D"AR=
-SA" style=3D"font-size:16pt;line-height:107%;font-family:Arial,sans-serif"=
>=D8=8C =D8=A8=D8=AD=D9=8A=D8=AB
=D9=8A=D8=AD=D8=AA=D9=88=D9=8A =D9=83=D9=84 =D8=A8=D8=B1=D9=86=D8=A7=D9=85=
=D8=AC =D8=B9=D9=84=D9=89 </span><span dir=3D"LTR"></span><span dir=3D"LTR"=
></span><b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:107%"><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span>80 </span></b><b><span lang=
=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;font-family:Arial,sans-=
serif">=D8=B3=D8=A7=D8=B9=D8=A9 =D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9 =
=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span></b><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:16pt;line-height=
:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR">=C2=A0</span=
></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=AC=D8=
=AF=D9=88=D9=84 =D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D9=85=D8=A7=D8=
=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A | =D8=A3=
=D8=BA=D8=B3=D8=B7=D8=B3 =E2=80=93 =D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1
2025</span></b><b><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107=
%"></span></b></p>

<table class=3D"gmail-MsoNormalTable" border=3D"0" cellpadding=3D"0" align=
=3D"left" style=3D"margin-left:6.75pt;margin-right:6.75pt">
 <thead>
  <tr>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D9=85<=
/span></b><b><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></=
span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=
=D8=B3=D9=85
   =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC</span></b><b><span dir=
=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=
=D9=84=D9=85=D8=AC=D8=A7=D9=84</span></b><b><span dir=3D"LTR" style=3D"font=
-size:14pt;line-height:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=
=D9=84=D9=85=D8=AF=D8=A9
   =D8=A7=D9=84=D8=B2=D9=85=D9=86=D9=8A=D8=A9</span></b><b><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=AA=
=D8=A7=D8=B1=D9=8A=D8=AE
   =D8=A7=D9=84=D8=A7=D9=86=D8=B9=D9=82=D8=A7=D8=AF</span></b><b><span dir=
=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" sty=
le=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=
=D9=84=D8=AF=D9=88=D9=84=D8=A9
   / =D8=A7=D9=84=D9=85=D8=AF=D9=8A=D9=86=D8=A9</span></b><b><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></b></p>
   </td>
  </tr>
 </thead>
 <tbody><tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">1</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
  =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=
=B1=D8=A9 =D8=A7=D9=84=D8=A3=D8=B9=D9=85=D8=A7=D9=84 =D8=A7=D9=84=D8=AA=D9=
=86=D9=81=D9=8A=D8=B0=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"=
><span dir=3D"LTR"></span><span dir=3D"LTR"></span> (EMBA)</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A5=D8=
=AF=D8=A7=D8=B1=D8=A9
  =D8=A7=D9=84=D8=A3=D8=B9=D9=85=D8=A7=D9=84</span><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" style=3D"fon=
t-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=A7=D8=
=B9=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">17 - 28 </span><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A3=D8=
=BA=D8=B3=D8=B7=D8=B3
  2025</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></=
span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9
  =E2=80=93 =D9=85=D8=B5=D8=B1</span><span dir=3D"LTR" style=3D"font-size:1=
4pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">2</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
  =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=
=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span><spa=
n dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF
  =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" style=3D"fon=
t-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=A7=D8=
=B9=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">1 - 12 </span><span lang=3D"AR-SA" style=3D=
"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=A8=
=D8=AA=D9=85=D8=A8=D8=B1
  2025</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></=
span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=AF=D8=
=A8=D9=8A
  =E2=80=93 =D8=A7=D9=84=D8=A5=D9=85=D8=A7=D8=B1=D8=A7=D8=AA</span><span di=
r=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">3</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
  =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=
=AD=D8=A7=D8=B3=D8=A8=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=
=A9</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></spa=
n></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9
  =D9=88=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9</span><span dir=3D=
"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" style=3D"fon=
t-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=A7=D8=
=B9=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">15 - 26 </span><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=
=A8=D8=AA=D9=85=D8=A8=D8=B1
  2025</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></=
span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D8=
=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84
  =E2=80=93 =D8=AA=D8=B1=D9=83=D9=8A=D8=A7</span><span dir=3D"LTR" style=3D=
"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">4</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
  =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=
=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=8A=D8=B9</span><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:14pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
> PMP</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A5=D8=
=AF=D8=A7=D8=B1=D8=A9
  =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=8A=D8=B9</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" style=3D"fon=
t-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=A7=D8=
=B9=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">6 - 17 </span><span lang=3D"AR-SA" style=3D=
"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A3=D9=83=
=D8=AA=D9=88=D8=A8=D8=B1
  2025</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></=
span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9
  =E2=80=93 =D9=85=D8=B5=D8=B1</span><span dir=3D"LTR" style=3D"font-size:1=
4pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">5</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
  =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=82=D9=
=8A=D8=A7=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=
=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A</span><span dir=3D"LTR" style=3D"font-siz=
e:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9
  =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=
=D8=B3=D9=8A</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:10=
7%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" style=3D"fon=
t-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=A7=D8=
=B9=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">20 - 31 </span><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A3=D9=
=83=D8=AA=D9=88=D8=A8=D8=B1
  2025</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></=
span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=AF=D8=
=A8=D9=8A
  =E2=80=93 =D8=A7=D9=84=D8=A5=D9=85=D8=A7=D8=B1=D8=A7=D8=AA</span><span di=
r=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">6</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
  =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=
=B1=D8=A9 =D8=A7=D9=84=D8=AA=D8=BA=D9=8A=D9=8A=D8=B1 =D9=88=D9=82=D9=8A=D8=
=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=A3=D8=B2=D9=85=D8=A7=D8=AA</span><span dir=
=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
  =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9<=
/span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></=
p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" style=3D"fon=
t-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=A7=D8=
=B9=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">3 - 14 </span><span lang=3D"AR-SA" style=3D=
"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D9=86=D9=88=
=D9=81=D9=85=D8=A8=D8=B1
  2025</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></=
span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9
  =E2=80=93 =D9=85=D8=B5=D8=B1</span><span dir=3D"LTR" style=3D"font-size:1=
4pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">7</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
  =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=
=B3=D9=88=D9=8A=D9=82 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =D9=88=D8=A5=D8=
=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D9=85=D8=A7=D8=AA =D8=
=A7=D9=84=D8=AA=D8=AC=D8=A7=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D8=AA=D8=B3=D9=88=D9=8A=D9=82
  =D9=88=D8=A7=D9=84=D8=A5=D8=B9=D9=84=D8=A7=D9=85</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" style=3D"fon=
t-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=A7=D8=
=B9=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">17 - 28 </span><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D9=86=D9=
=88=D9=81=D9=85=D8=A8=D8=B1
  2025</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></=
span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D8=
=B3=D8=B7=D9=86=D8=A8=D9=88=D9=84
  =E2=80=93 =D8=AA=D8=B1=D9=83=D9=8A=D8=A7</span><span dir=3D"LTR" style=3D=
"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">8</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
  =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=
=B1=D8=A9 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=AD=D9=
=88=D9=83=D9=85=D8=A9</span><span dir=3D"LTR" style=3D"font-size:14pt;line-=
height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D8=AC=D9=88=D8=AF=D8=A9
  =D9=88=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" style=3D"fon=
t-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=A7=D8=
=B9=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">1 - 12 </span><span lang=3D"AR-SA" style=3D=
"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=AF=D9=8A=
=D8=B3=D9=85=D8=A8=D8=B1
  2025</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></=
span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=AF=D8=
=A8=D9=8A
  =E2=80=93 =D8=A7=D9=84=D8=A5=D9=85=D8=A7=D8=B1=D8=A7=D8=AA</span><span di=
r=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">9</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
  =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=
=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B4=D8=AA=D8=B1=D9=8A=D8=A7=D8=AA =D9=88=D8=
=B3=D9=84=D8=A7=D8=B3=D9=84 =D8=A7=D9=84=D8=A5=D9=85=D8=AF=D8=A7=D8=AF</spa=
n><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=B4=D8=AA=D8=B1=D9=8A=D8=A7=D8=AA
  =D9=88=D8=A7=D9=84=D9=84=D9=88=D8=AC=D8=B3=D8=AA=D9=8A=D8=A7=D8=AA</span>=
<span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" style=3D"fon=
t-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=A7=D8=
=B9=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">15 - 26 </span><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=AF=D9=
=8A=D8=B3=D9=85=D8=A8=D8=B1
  2025</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></=
span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9
  =E2=80=93 =D9=85=D8=B5=D8=B1</span><span dir=3D"LTR" style=3D"font-size:1=
4pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">10</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
  =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=A5=D8=
=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B5=D8=AD=D9=8A=D8=A9</span><span dir=
=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D8=B5=D8=AD=D8=A9
  =D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D8=B4=D9=81=D9=8A=D8=A7=D8=AA</span>=
<span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" style=3D"fon=
t-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=B3=D8=A7=D8=
=B9=D8=A9
  =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">22 - 31 </span><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=AF=D9=
=8A=D8=B3=D9=85=D8=A8=D8=B1
  2025</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></=
span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=
=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9
  =E2=80=93 =D9=85=D8=B5=D8=B1</span><span dir=3D"LTR" style=3D"font-size:1=
4pt;line-height:107%"></span></p>
  </td>
 </tr>
</tbody></table>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%"><br clear=3D"all">
</span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:14pt;line-height:107%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><span dir=3D"LTR" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;Segoe UI Symbol&quot;,san=
s-serif">=F0=9F=93=9D</span></b><b><span dir=3D"LTR" style=3D"font-size:14p=
t;line-height:107%"> </span></b><b><span lang=3D"AR-SA" style=3D"font-size:=
14pt;line-height:107%;font-family:Arial,sans-serif">=D9=85=D9=84=D8=A7=D8=
=AD=D8=B8=D8=A7=D8=AA
=D9=85=D9=87=D9=85=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LT=
R"></span><b><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:107%"></span></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size=
:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=AC=D9=85=D9=8A=D8=
=B9
     =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=AA=D9=85=D9=86=D8=AD =
=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D9=88=D8=AB=D9=82=D8=A9 =D9=88=D9=85=
=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =D9=88=D9=82=D8=A7=D8=A8=D9=84=D8=A9 =D9=84=
=D9=84=D8=AA=D8=B5=D8=AF=D9=8A=D9=82 =D9=85=D9=86 =D8=A7=D9=84=D8=AE=D8=A7=
=D8=B1=D8=AC=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size=
:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=84=D8=
=BA=D8=A9:
     =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 (=D9=85=D8=B9 =D8=AA=D9=88=
=D9=81=D8=B1 =D9=85=D8=AA=D8=B1=D8=AC=D9=85 =D8=B9=D9=86=D8=AF =D8=A7=D9=84=
=D8=AD=D8=A7=D8=AC=D8=A9 =D9=84=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=
=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9)</span><span dir=3D"LTR"></span><span =
dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:10=
7%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size=
:14pt;line-height:107%;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=81=D8=
=A6=D8=A9
     =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9: =D8=A7=D9=84=
=D9=85=D8=AF=D9=8A=D8=B1=D9=88=D9=86 =D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=
=D8=B0=D9=8A=D9=88=D9=86=D8=8C =D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88 =D8=A7=
=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1=D8=8C =D9=85=D8=B3=D8=A4=D9=88=D9=84=
=D9=88 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9=D8=8C =D9=82=D8=A7=D8=AF=D8=A9 =
=D8=A7=D9=84=D9=81=D8=B1=D9=82=D8=8C
     =D8=B1=D8=A4=D8=B3=D8=A7=D8=A1 =D8=A7=D9=84=D8=A3=D9=82=D8=B3=D8=A7=D9=
=85=D8=8C =D9=88=D8=B0=D9=88=D9=88 =D8=A7=D9=84=D8=B7=D9=85=D9=88=D8=AD=D8=
=A7=D8=AA =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D9=8A=D8=A9</span><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-si=
ze:14pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span=
>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size=
:14pt;line-height:107%;font-family:Arial,sans-serif">=D9=8A=D9=85=D9=83=D9=
=86
     =D8=AA=D9=86=D9=81=D9=8A=D8=B0 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=
=AC <b>=D8=A3=D9=88=D9=86=D9=84=D8=A7=D9=8A=D9=86 =D8=B9=D8=A8=D8=B1</b></s=
pan><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%"><span dir=3D"LTR"></span><span di=
r=3D"LTR"></span> Zoom</span></b><span dir=3D"LTR" style=3D"font-size:14pt;=
line-height:107%"> </span><span lang=3D"AR-SA" style=3D"font-size:14pt;line=
-height:107%;font-family:Arial,sans-serif">=D8=A3=D9=88 <b>=D8=AD=D8=B6=D9=
=88=D8=B1=D9=8A</b>
     =D8=AD=D8=B3=D8=A8 =D8=B1=D8=BA=D8=A8=D8=A9 =D8=A7=D9=84=D9=85=D8=B4=
=D8=A7=D8=B1=D9=83=D9=8A=D9=86</span><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initial=
;background-position:initial;background-size:initial;background-repeat:init=
ial;background-origin:initial;background-clip:initial;direction:rtl;unicode=
-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,sans-serif"=
><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span style=3D"fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings:n=
ormal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quo=
t;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,sans-serif;color:red">=D9=84=D9=84=D8=AA=D8=
=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=81=D8=B3=D8=
=A7=D8=B1</span></b><span lang=3D"AR-SA"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initia=
l;background-position:initial;background-size:initial;background-repeat:ini=
tial;background-origin:initial;background-clip:initial;direction:rtl;unicod=
e-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,sans-serif=
"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span style=3D"fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,sans-serif">=D9=88=D8=A8=D9=87=D8=B0=D9=87 =
=D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=A9 =D9=8A=D8=B3=D8=B9=D8=AF=
=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=83=D9=85 =D9=84=D9=84=D9=85=D8=B4=
=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=B9=D9=85=D9=8A=D9=85
=D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=
=D9=87=D8=AA=D9=85=D9=8A=D9=86 =D8=A8=D9=85=D9=80=D9=80=D9=88=D8=B6=D9=80=
=D9=88=D8=B9=C2=A0</span></b><b><span lang=3D"AR-EG" style=3D"font-size:16p=
t;font-family:Arial,sans-serif">=D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A9
=D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9=C2=A0</span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,sans-se=
rif">=D9=88=D8=A5=D9=81=D8=A7=D8=AF=D8=AA=D9=86=D8=A7 =D8=A8=D9=85=D9=86 =
=D8=AA=D9=82=D8=AA=D8=B1=D8=AD=D9=88=D9=86 =D8=AA=D9=88=D8=AC=D9=8A=D9=87 =
=D8=A7=D9=84=D8=AF=D8=B9=D9=88=D8=A9 =D9=84=D9=87=D9=85</span></b><span lan=
g=3D"AR-SA"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initia=
l;background-position:initial;background-size:initial;background-repeat:ini=
tial;background-origin:initial;background-clip:initial;direction:rtl;unicod=
e-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,sans-serif=
"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span style=3D"fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,sans-serif">=D9=84=D9=85=D8=B2=D9=8A=D8=AF =
=D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =D9=8A=
=D9=85=D9=83=D9=86=D9=83 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=85=
=D8=B9 =D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9
=D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=A7=D8=AF =E2=80=93 =D9=86=D8=
=A7=D8=A6=D8=A8 =D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=
=8A=D8=A8 =E2=80=93 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=
=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=
=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></b><span lang=3D"AR-SA"></span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initia=
l;background-position:initial;background-size:initial;background-repeat:ini=
tial;background-origin:initial;background-clip:initial;direction:rtl;unicod=
e-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,sans-serif=
"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span style=3D"fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,sans-serif">=D8=AC=D9=88=D8=A7=D9=84 =E2=80=
=93 =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=A8 :</span></b><span lang=3D"AR-SA">=
</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initial;=
background-position:initial;background-size:initial;background-repeat:initi=
al;background-origin:initial;background-clip:initial;direction:rtl;unicode-=
bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,sans-serif">=
<span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span style=3D"font=
-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alterna=
tes:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings:no=
rmal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot=
;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:16pt"><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span>00201069994399
-00201062992510 - 00201096841626</span></b><span lang=3D"AR-SA"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"fon=
t-size:14pt;line-height:107%">=C2=A0</span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKnDsZ8-uBALn6sWG34a%3D4C%2Bae_jXpLL571fJUpdqXcD%2BQ%40mail.=
gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com=
/d/msgid/kasan-dev/CADj1ZKnDsZ8-uBALn6sWG34a%3D4C%2Bae_jXpLL571fJUpdqXcD%2B=
Q%40mail.gmail.com</a>.<br />

--000000000000024bc6063ba3b6ff--
