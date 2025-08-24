Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBYGFVPCQMGQEBRGBCRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 32E5AB32EE5
	for <lists+kasan-dev@lfdr.de>; Sun, 24 Aug 2025 12:01:07 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-55f3942f104sf730691e87.0
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Aug 2025 03:01:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756029666; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wp8kAGWcjO63vI7t5CWUo0y2J7AeOGNOJ+QIeLuMc6sQU0s2u2Zalg3bnchxwG21Pm
         omzuu64j9IQ9UQzwCntRKNDxpNU/eUqFRG34iFmXiKsv/t7csGM1BN7usJP4q4CAD1M5
         z0oNbTmi11G2LvkKk6RbmTJUYVOWIgg56a9G9oS4Kgp1hLkiE0Xe2Z18mst/pUo8qoVR
         1NhovDh1rugUhFDhugZH5o1MFVL8SURtQYzf4XVQeqknmqJWHD2qEJUIWFwTvyb41+MX
         gUv2EMluomJNz96OB9Wmm1sayGFaKofUbfLoGal8lmhgwMrNsxrBMxvtS2aMmp5NnriS
         6eHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=SIhCZ71Wwp4qFZOrMu+4PZUlV356O2BgfHk1H1cgONM=;
        fh=i4p2avMQ7Xx/V2ls3Zwp57hYGRxTiJpXjwbSSRHDCRQ=;
        b=KhMzgnf3hCSilHAO4SJfWxdU19Dv4Z6YEgISJmr4Sfl1v+q0L7JibaZIyifZzb+vu4
         NAIuRSN0+ua7Y3dYclbnXQaxk1xN/9WjP8G1HuAkNSIU5cloFoma7RqYJe4QlHdpbyK5
         tai1rsNmNVLm72eepcTXFqxHspVTtlYIlhM0+lywIT3e+AGjuJH9L3E2N4kxV6xIKIET
         Hyg2C9ja3MGqeUPhXhA/eSRP0XJzY0JupWkaO2GbuFgcvg4wU4Le/Vi0kWkjrw8ot8tq
         aip7SHimVFKBNNeR55sAck2aIl4bfH89eU8FzPiw4o8zAMhNIcDP2Ehuvyi1fnzTyugq
         er5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dFR0BWu6;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756029666; x=1756634466; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SIhCZ71Wwp4qFZOrMu+4PZUlV356O2BgfHk1H1cgONM=;
        b=f5Z1Ho6z8sVrOc3rCbaBwhmNnPtvDKW41DDvvr9gTFeS++Q9awEzwSd6/dGNmYZfH/
         5ugOIonaQofT5O2BIrfCupN4iYs9Z7QPSlG/pOGgbMDFt0wDLNXzmZgXcZt+8OvRE9Ot
         wWFxSsHEaug7zkfCa9OnikeTCMLmk8HF1Dc7vkx1dzEMoGxFPEUYnWroAx88QfcQAa3Z
         Kplu+HWvMjrkjzRoJk/pfTNeJhqzwU5OTuciiKBHHFy+LidJ6HEAJDaYduAX7ryuwwq8
         Dx1Kc3nBjPTFpPcRqXKYUVPrPvxdcTqBpOJaMXwLk11Hh48H08nc9EsTKpIGNavEySgm
         nvUw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756029666; x=1756634466; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=SIhCZ71Wwp4qFZOrMu+4PZUlV356O2BgfHk1H1cgONM=;
        b=g/Vmpj73hJYUxAaHzMKOQ9OjsM4Sum9X0UEl4cQeLqI2xIMfLXw4d8SNKD/J7pBWMp
         2uxFpzZL/Z2c1qmMgXcbId1T2KwnViQBD5Rjzs/4FYreg3GRhdLK+9agS5ZVKQSjh+jR
         qGd1xm8rLuzOw8j+c5UhPgraW59z3DHkRjpG/enPKpIMn8Z6Um2d1a9ohg5pUNyWAJ3A
         8HX4bEWMkiVs0xQkbVZZJG/HWwGbKl3E/OBRfOtcp+gev/Nubc5x5hEn9k+t98yJb21c
         Ro/vzq1O33T2UbQURHCqPzis3BJGg17j3HCebGEqj7fQkfID5I9u/p1huJnzF6wdXWgH
         7rBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756029666; x=1756634466;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SIhCZ71Wwp4qFZOrMu+4PZUlV356O2BgfHk1H1cgONM=;
        b=dHoZFt28Eh0xwi+BqO6pPvWiNG98CAseqdB2VUPysl1PJxtSk4GE/SlOxKvuTxYdZs
         VYcrmZ2pLCr1EkbFpSh+a6gV70/hwGXPojG4ZF1GA3SL3Demb9TRGK+PDqk3UX5aHH1a
         EZKsSCW81bim193934HwbX67HpwACQEHKzO4iTOiFuUytpu73k2rFVzC1QjqlKW3xg4A
         EE1SeE4Y7hIPpniCJr8pnsH5DRd+fmHVGKSE3l/0EaHS2JURZ3SRxk+TdDHRQIJX4nTn
         2H/ersbxb7OTEFkv87I1uHkla9gOKDr6fq85auUBym7fJwcBwk5Zhy6IGjT3oqjv8VXy
         Tezg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXvAgMB/fWn9c/JkjBHswq9qVTbGKjAUpx3n5LTvKhnKQCZTOPpCbifyeuN5ir2Iknj5J0zJw==@lfdr.de
X-Gm-Message-State: AOJu0Yw6w2H9kXDq54nuIrIYQHQJhK10FBDTGHZ9iiRgxYGQT2iCs9Yq
	N/WA5i6PckZVv6HqjPMrgbFqc2aeaayl77RSkyCbriv2WdC39ANFvSjF
X-Google-Smtp-Source: AGHT+IG5SjMclO1Pi5irvnkYgL+6QwXmSdFxra1+2XXnEjcQnHpEg+2ZtmrO8vOWYnRluuGd329rOg==
X-Received: by 2002:a2e:bc1b:0:b0:336:7432:ace3 with SMTP id 38308e7fff4ca-3367432d8d0mr1988081fa.11.1756029665439;
        Sun, 24 Aug 2025 03:01:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfzxlPfKlXZo7MzCPCSIeioPKmXysl81wgXsF9UTvyrRA==
Received: by 2002:a05:651c:31c7:b0:329:947:b67d with SMTP id
 38308e7fff4ca-3354697b215ls7154441fa.0.-pod-prod-03-eu; Sun, 24 Aug 2025
 03:00:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUxP8S2NywjDfsjLA4V/F3tRyCty4OdlFfs0DAuAyJW9uHEaKlhxbUQ8u515q6zjZv2L180K5x98J8=@googlegroups.com
X-Received: by 2002:a05:6512:640a:b0:55b:96b0:63f9 with SMTP id 2adb3069b0e04-55f0d39442dmr2220260e87.55.1756029659513;
        Sun, 24 Aug 2025 03:00:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756029659; cv=none;
        d=google.com; s=arc-20240605;
        b=gCb8I5VjDVKVJCS5meEPdwWH3BqG0XtS0sWuGatG1vVdyfN91QekzYSL0r0peBo81x
         Cg+d2ufhc6NVSJYkJULy8d6l9WexXpEh1Uf2nFqQxxiW8EYJZ5Hy9TB8oiGQEXt5CAE6
         zODweTe0cf9HKOQyP86Ok/VKW/iriJhCFDDctIoQqy4a1iPKS9u/I/PN2vrOaEcnKt5s
         90V2PUkZ1dvlX8V/2c/iak/WVJIPMn4hhFLZg4SQjTs+eC20eoR3IO4q4ZpZQIr308nh
         fN07tQfGxQEdmQJYur3IrC1/TmtVvNHBXtL7ubbGx1bqjhGgX2R+uwm1xrnqlaFdV44J
         K+xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=mNeTyYy+SJQXPo4tRQeq/s2uSOYwA7L3H/Zyy5O+XAk=;
        fh=JRqIk6AsrYjg9mL+K/Y7aQUedN3O6vGCjtfFZb4jeZ4=;
        b=Pw9Ee/eG6jT/K925/wZde9c5Z8c/OB0I4Qmorro6KVrdGpY/I36EuWeRbfAprO5NZ6
         1Mr0Ayia9U5ooGbjJwDlp3+chViptTI5Gt4w1RHK/bzhjXdkdOr3RoLfwLcycZ3kxrIO
         1H+h0u3xlRmVYNC2/0tELacjOPl1vjKWR69X/uZwvt6tKqcqjLeCBxxaHoQg9kG425rd
         OapR4BK/d1HyzyGNr4mcGaLQuVDYw605M7KUPgXHuJkdFjKFfjWc115fXiAOOu7F1p/B
         Kg7vkVMmCAawajaMXybUFCSr8dI7IRQACfZGwU/o79waK7cbFJmL80NBaI7eVIqbVjHP
         mPhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dFR0BWu6;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3365e072748si854341fa.0.2025.08.24.03.00.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 24 Aug 2025 03:00:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id 4fb4d7f45d1cf-6188b5b113eso4434312a12.0
        for <kasan-dev@googlegroups.com>; Sun, 24 Aug 2025 03:00:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVjLQGqcFLbIdfBfbeBgb+rICxhrWYLDqgxiBpm1RT3OKpDSaFfSHFbq1jEzSGXqs/tYgorYCvv7dU=@googlegroups.com
X-Gm-Gg: ASbGnctaMKIMMpv7xAH0Po57jDhyZLxslK9nRLiKP14f081Uf5vw4oK9OZ+74dFufIo
	dABV5rL09XGDm6QwD1YQkOH6nxtw5IAuPZKS0yk4itZUmYBA8cFt8iSuk443uYEWP1+by7W0LkD
	pyoOlbvwsxvgwjg0jeRftgvLccj8CwEhU27woOTek64cvvbTvfEMkK85GsLZzDtkdcyymRuhqsL
	Yg2SxaaKEHQ
X-Received: by 2002:a05:6402:46ca:b0:61c:15e4:ae7f with SMTP id
 4fb4d7f45d1cf-61c1b4a1d88mr7614900a12.16.1756029658057; Sun, 24 Aug 2025
 03:00:58 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Sun, 24 Aug 2025 13:00:00 +0300
X-Gm-Features: Ac12FXy6S4ZjViYsLvZiGqfRSZ_dClwPTrjmg09dNJ1HWeILfK58nVfLX8kUPdg
Message-ID: <CADj1ZKmJa_cibVD6BecNG127f6Byh5Ufz6Kt3pG5KntFTzHhhA@mail.gmail.com>
Subject: =?UTF-8?B?8J+OryDYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKINin2YTZhdi12LrYsSDZgQ==?=
	=?UTF-8?B?2Yog2KfZhNiq2YbZhdmK2Kkg2KfZhNio2LTYsdmK2KkgTWluaSBQcm9mZXNzaW9uYWwgTWFzdGVyJ3Mg?=
	=?UTF-8?B?aW4gSHVtYW4gRGV2ZWxvcG1lbnQg2YrYqNiv2KMg2YHZiiAzMSDYo9i62LPYt9izIDIwMjUgODAg2LM=?=
	=?UTF-8?B?2KfYudipINiq2K/YsdmK2KjZitipINin2YTZgtin2YfYsdipIOKAkyDYrNmF2YfZiNix2YrYqSDZhdi1?=
	=?UTF-8?B?2LEg2KfZhNi52LHYqNmK2Kkg2KPZiCDYudmGINio2Y/YudivINi52KjYsSBab29tICjZgdmKINit2Kc=?=
	=?UTF-8?B?2YQg2KrYudiw2LEg2KfZhNit2LbZiNixKSDZhdmC2K/ZhSDZhdmGOiDYp9mE2K/Yp9ixINin2YTYudix?=
	=?UTF-8?B?2KjZitipINmE2YTYqtmG2YXZitipINin2YTYpdiv2KfYsdmK2Kkg4oCTIEFIQUQg2LTZh9in2K/YqSA=?=
	=?UTF-8?B?2YXZh9mG2YrYqSDZhdi52KrZhdiv2KnYjCDZgtin2KjZhNipINmE2YTYqtmI2KvZitmCINmF2YYg2Yg=?=
	=?UTF-8?B?2LLYp9ix2Kkg2KfZhNiu2KfYsdis2YrYqSDZiNmD2KfZgdipINin2YTYs9mB2KfYsdin2Kog2KfZhNi5?=
	=?UTF-8?B?2LHYqNmK2KkuINin2YTZhdmC2K/ZhdipOiDZitmH2K/ZgSDZh9iw2Kcg2KfZhNio2LHZhtin2YXYrCA=?=
	=?UTF-8?B?2KfZhNmF2KrYrti12LUg2KXZhNmJINiq2KPZh9mK2YQg2KfZhNmF2LTYp9ix2YPZitmGINio2KfZhNmF?=
	=?UTF-8?B?2YfYp9ix2KfYqiDYp9mE2KfYrdiq2LHYp9mB2YrYqSDZiNin2YTYo9iv2YjYp9iqINin2YTYudmF2YQ=?=
	=?UTF-8?B?2YrYqSDZhNiq2LfZiNmK2LEg2KfZhNiw2KfYqiDZiNin2YTYotiu2LHZitmG2Iwg2YjYqtit2YLZitmC?=
	=?UTF-8?B?INin2YTYqtmF2YrYsiDZgdmKINin2YTYo9iv2KfYoSDYp9mE2LTYrti12Yog2YjYp9mE2YXZh9mG2Yo=?=
	=?UTF-8?B?2Iwg2KjYp9mE2KfYudiq2YXYp9ivINi52YTZiSDYo9it2K/YqyDYo9iz2KfZhNmK2Kgg2LnZhNmFINin?=
	=?UTF-8?B?2YTZhtmB2LMg2KfZhNil2YrYrNin2KjZitiMINmI2KfZhNiq2K/YsdmK2KjYjCDZiNin2YTYqtit2YE=?=
	=?UTF-8?B?2YrYstiMINmI2KfZhNmC2YrYp9iv2KkuINin2YTYo9mH2K/Yp9mBOiDigKIg2YHZh9mF?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000fbd366063d1983ad"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dFR0BWu6;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52c
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

--000000000000fbd366063d1983ad
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

KvCfjq8qKiDYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKINin2YTZhdi12LrYsSDZgdmK
INin2YTYqtmG2YXZitipINin2YTYqNi02LHZitipKg0KDQoqTWluaSBQcm9mZXNzaW9uYWwgTWFz
dGVyJ3MgaW4gSHVtYW4gRGV2ZWxvcG1lbnQqDQoq2YrYqNiv2KMg2YHZiiAzMSDYo9i62LPYt9iz
IDIwMjUgODAg2LPYp9i52Kkg2KrYr9ix2YrYqNmK2KkqDQoq2KfZhNmC2KfZh9ix2Kkg4oCTINis
2YXZh9mI2LHZitipINmF2LXYsSDYp9mE2LnYsdio2YrYqSoNCtij2Ygg2LnZhirwn46vKiog2KfZ
hNmF2KfYrNiz2KrZitixINin2YTZhdmH2YbZiiDYp9mE2YXYtdi62LEg2YHZiiDYp9mE2KrZhtmF
2YrYqSDYp9mE2KjYtNix2YrYqSoNCg0KKk1pbmkgUHJvZmVzc2lvbmFsIE1hc3RlcidzIGluIEh1
bWFuIERldmVsb3BtZW50Kg0KKtmK2KjYr9ijINmB2YogMzEg2KPYutiz2LfYsyAyMDI1IDgwINiz
2KfYudipINiq2K/YsdmK2KjZitipKg0KKtin2YTZgtin2YfYsdipIOKAkyDYrNmF2YfZiNix2YrY
qSDZhdi12LEg2KfZhNi52LHYqNmK2KkqDQrYo9mIINi52YYg2KjZj9i52K8g2LnYqNixIFpvb20g
KNmB2Yog2K3Yp9mEINiq2LnYsNixINin2YTYrdi22YjYsSkNCtmF2YLYr9mFINmF2YY6ICrYp9mE
2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG2YXZitipINin2YTYpdiv2KfYsdmK2KkqKiDi
gJMgQUhBRCoNCti02YfYp9iv2Kkg2YXZh9mG2YrYqSDZhdi52KrZhdiv2KnYjCDZgtin2KjZhNip
INmE2YTYqtmI2KvZitmCINmF2YYg2YjYstin2LHYqSDYp9mE2K7Yp9ix2KzZitipINmI2YPYp9mB
2Kkg2KfZhNiz2YHYp9ix2KfYqiDYp9mE2LnYsdio2YrYqS4NCg0KDQoNCirYp9mE2YXZgtiv2YXY
qSoqOioNCg0K2YrZh9iv2YEg2YfYsNinINin2YTYqNix2YbYp9mF2Kwg2KfZhNmF2KrYrti12LUg
2KXZhNmJINiq2KPZh9mK2YQg2KfZhNmF2LTYp9ix2YPZitmGINio2KfZhNmF2YfYp9ix2KfYqiDY
p9mE2KfYrdiq2LHYp9mB2YrYqSDZiNin2YTYo9iv2YjYp9iqDQrYp9mE2LnZhdmE2YrYqSDZhNiq
2LfZiNmK2LEg2KfZhNiw2KfYqiDZiNin2YTYotiu2LHZitmG2Iwg2YjYqtit2YLZitmCINin2YTY
qtmF2YrYsiDZgdmKINin2YTYo9iv2KfYoSDYp9mE2LTYrti12Yog2YjYp9mE2YXZh9mG2YrYjA0K
2KjYp9mE2KfYudiq2YXYp9ivINi52YTZiSDYo9it2K/YqyDYo9iz2KfZhNmK2Kgg2LnZhNmFINin
2YTZhtmB2LMg2KfZhNil2YrYrNin2KjZitiMINmI2KfZhNiq2K/YsdmK2KjYjCDZiNin2YTYqtit
2YHZitiy2Iwg2YjYp9mE2YLZitin2K/YqS4NCg0KDQoNCirYp9mE2KPZh9iv2KfZgSoqOioNCg0K
ICAgLSDZgdmH2YUg2KPYs9in2LPZitin2Kog2YjZhdmB2KfZh9mK2YUg2KfZhNiq2YbZhdmK2Kkg
2KfZhNio2LTYsdmK2Kkg2YjYo9ir2LHZh9inINmB2Yog2KjZitim2Kkg2KfZhNi52YXZhCDZiNin
2YTYrdmK2KfYqS4NCiAgIC0g2KfZg9iq2LPYp9ioINmF2YfYp9ix2KfYqiDYqti32YjZitixINin
2YTYsNin2KrYjCDZiNiq2K3Ys9mK2YYg2KfZhNil2YbYqtin2KzZitip2Iwg2YjYqNmG2KfYoSDY
p9mE2KvZgtipINio2KfZhNmG2YHYsy4NCiAgIC0g2KfZhNiq2LnYsdmBINi52YTZiSDZhdmG2YfY
rNmK2KfYqiDYp9mE2KrYr9ix2YrYqCDZiNin2YTYqtij2KvZitixINin2YTYpdmK2KzYp9io2Yog
2YHZiiDYp9mE2KLYrtix2YrZhi4NCiAgIC0g2KrZhtmF2YrYqSDYp9mE2YXZh9in2LHYp9iqINin
2YTZgtmK2KfYr9mK2Kkg2YjYp9mE2YLYr9ix2Kkg2LnZhNmJINil2K/Yp9ix2Kkg2YHYsdmCINin
2YTYudmF2YQg2YjYqtit2YLZitmCINin2YTYo9mH2K/Yp9mBLg0KICAgLSDYqti32KjZitmCINij
2K/ZiNin2Kog2KfZhNiq2K3ZhNmK2YQg2KfZhNmG2YHYs9mKINmI2KfZhNiz2YTZiNmD2Yog2YTY
qti32YjZitixINin2YTYo9iv2KfYoSDYp9mE2KjYtNix2YouDQoNCi0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLQ0KDQoq8J+RpSogKtin2YTZgdim2KfYqiDYp9mE2YXYs9iq2YfYr9mB2Kkq
KjoqDQoNCiAgIC0g2KfZhNmF2K/Ysdio2YjZhiDZiNin2YTYp9iz2KrYtNin2LHZitmI2YYg2YHZ
iiDZhdis2KfZhNin2Kog2KfZhNiq2YbZhdmK2Kkg2KfZhNio2LTYsdmK2KkuDQogICAtINin2YTZ
gtmK2KfYr9mK2YjZhiDZiNin2YTZhdiv2LHYp9ihINin2YTYsdin2LrYqNmI2YYg2YHZiiDYqti3
2YjZitixINmD2YHYp9ih2KfYqtmH2YUg2KfZhNi02K7YtdmK2Kkg2YjYp9mE2YXZh9mG2YrYqS4N
CiAgIC0g2KfZhNmF2YfYqtmF2YjZhiDYqNin2YTYqti32YjZitixINin2YTYsNin2KrZiiDZiNin
2YTYudmF2YQg2YHZiiDZhdis2KfZhCDYp9mE2KrYr9ix2YrYqCDYo9mIINin2YTYpdix2LTYp9iv
Lg0KICAgLSDYp9mE2LnYp9mF2YTZiNmGINmB2Yog2KfZhNmF2YjYp9ix2K8g2KfZhNio2LTYsdmK
2Kkg2YjYp9mE2KrYt9mI2YrYsSDYp9mE2YXYpNiz2LPZii4NCiAgIC0g2YPYp9mB2Kkg2KfZhNix
2KfYutio2YrZhiDZgdmKINil2K3Yr9in2Ksg2YbZgtmE2Kkg2YbZiNi52YrYqSDZgdmKINmF2LPY
p9ix2YfZhSDYp9mE2LTYrti12Yog2KPZiCDYp9mE2YXZh9mG2YouDQoNCsK3ICAgICAgICAgKtmE
2YTYqtiz2KzZitmEINmI2KfZhNin2LPYqtmB2LPYp9ixKg0KDQrCtyAgICAgICAgICrZiNio2YfY
sNmHINin2YTZhdmG2KfYs9io2Kkg2YrYs9i52K/ZhtinINiv2LnZiNiq2YPZhSDZhNmE2YXYtNin
2LHZg9ipINmI2KrYudmF2YrZhSDYrti32KfYqNmG2Kcg2LnZhNmJINin2YTZhdmH2KrZhdmK2YYN
Ctio2YXZgNmA2YjYttmA2YjYuSAqKtin2YTYtNmH2KfYr9ipINin2YTYp9it2KrYsdin2YHZitip
ICoq2YjYpdmB2KfYr9iq2YbYpyDYqNmF2YYg2KrZgtiq2LHYrdmI2YYg2KrZiNis2YrZhyDYp9mE
2K/YudmI2Kkg2YTZh9mFKg0KDQrCtyAgICAgICAgICrZhNmF2LLZitivINmF2YYg2KfZhNmF2LnZ
hNmI2YXYp9iqINmK2YXZg9mG2YMg2KfZhNiq2YjYp9i12YQg2YXYuSDYoyAvINiz2KfYsdipINi5
2KjYryDYp9mE2KzZiNin2K8g4oCTINmG2KfYptioDQrZhdiv2YrYsSDYp9mE2KrYr9ix2YrYqCDi
gJMg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE2KfYr9in2LHZ
itipKg0KDQrCtyAgICAgICAgICrYrNmI2KfZhCDigJMg2YjYp9iq2LMg2KfYqCA6Kg0KDQrCtyAg
ICAgICAgICowMDIwMTA2OTk5NDM5OSAtMDAyMDEwNjI5OTI1MTAg4oCTIDAwMjAxMDk2ODQxNjI2
Kg0KDQoq2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE2KfYr9in
2LHZitipIC0gKipBSEFEKg0KDQrZhdinINmH2Ygg2KfZhNmF2KfYrNiz2KrZitixINin2YTZhdmH
2YbZitifDQoNCtin2YTZhdin2KzYs9iq2YrYsSDYp9mE2YXZh9mG2Yog2YfZiCDYr9ix2KzYqSDY
r9ix2KfYs9in2Kog2LnZhNmK2Kcg2KrYsdmD2LIg2LnZhNmJINin2YTYqti32KjZitmCINin2YTY
udmF2YTZiiDZiNin2YTZhtmI2KfYrdmKDQrYp9mE2YXZh9mG2YrYqdiMINmI2KrZh9iv2YEg2KXZ
hNmJINiq2KPZh9mK2YQg2KfZhNij2YHYsdin2K8g2YTZhNi52YXZhCDYqNmD2YHYp9ih2Kkg2LnY
p9mE2YrYqSDZgdmKINiq2K7Ytdi12KfYqtmH2YUuINi62KfZhNio2YvYpyDZhdinDQrZitiq2YUg
2KrZgtiv2YrZhSDZh9iw2Ycg2KfZhNio2LHYp9mF2Kwg2YXZhiDZgtio2YQg2KzYp9mF2LnYp9iq
INmF2K3ZhNmK2Kkg2YjYr9mI2YTZitipINmF2LHZhdmI2YLYqdiMINmI2KrYtNmF2YQg2YXYstmK
2KzZi9inINmF2YYNCtin2YTZhdit2KfYttix2KfYqiDYp9mE2YbYuNix2YrYqdiMINmI2KfZhNmF
2LTYp9ix2YrYuSDYp9mE2LnZhdmE2YrYqdiMINmI2KfZhNiq2K/YsdmK2Kgg2KfZhNmF2YrYr9in
2YbZii4NCg0K2YjYqtix2YPYsiDZh9iw2Ycg2KfZhNio2LHYp9mF2Kwg2LnZhNmJINiq2LfZiNmK
2LEg2KfZhNmF2YfYp9ix2KfYqiDYp9mE2YLZitin2K/Zitip2Iwg2YjYp9mE2KXYr9in2LHZitip
2Iwg2YjYp9mE2KrYrdmE2YrZhNmK2Kkg2KfZhNiq2YoNCtmK2K3Yqtin2KzZh9inINin2YTYo9mB
2LHYp9ivINmE2YTZhtis2KfYrSDZgdmKINio2YrYptin2Kog2KfZhNi52YXZhCDYp9mE2YXYqti6
2YrYsdipLg0KDQrYp9mE2YHYsdmCINio2YrZhiDYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZ
htmKINmI2KfZhNij2YPYp9iv2YrZhdmKDQoNCtin2YTZh9iv2YE6INmK2YfYr9mBINin2YTZhdin
2KzYs9iq2YrYsSDYp9mE2YXZh9mG2Yog2KXZhNmJINiq2YbZhdmK2Kkg2KfZhNmF2YfYp9ix2KfY
qiDYp9mE2LnZhdmE2YrYqSDZiNin2YTYqti32KjZitmC2YrYqdiMINio2YrZhtmF2KcNCtmK2LHZ
g9iyINin2YTYo9mD2KfYr9mK2YXZiiDYudmE2Ykg2KfZhNio2K3YqyDYp9mE2LnZhNmF2Yog2YjY
pdmG2KrYp9isINin2YTZhdi52LHZgdipLg0KDQrYp9mE2KzZhdmH2YjYsSDYp9mE2YXYs9iq2YfY
r9mBOiDYp9mE2KjYsdin2YXYrCDYp9mE2YXZh9mG2YrYqSDYqtmP2LXZhdmFINiu2LXZiti12YvY
pyDZhNmE2YXZiNi42YHZitmGINmI2KPYtdit2KfYqCDYp9mE2K7YqNix2KkNCtin2YTYudmF2YTZ
itipINin2YTYsNmK2YYg2YrYsdi62KjZiNmGINmB2Yog2KfZhNiq2LHZgtmK2Kkg2KPZiCDYp9mE
2KrYutmK2YrYsSDYp9mE2YXZh9mG2YrYjCDYudmE2Ykg2LnZg9izINin2YTYo9mD2KfYr9mK2YXZ
iiDYp9mE2LDZig0K2YrZj9mG2KfYs9ioINin2YTYqNin2K3Yq9mK2YYg2YjYp9mE2YXZh9iq2YXZ
itmGINio2KfZhNiv2YPYqtmI2LHYp9mHLg0KDQrYp9mE2YXYrdiq2YjZiTog2KrYqti22YXZhiDY
p9mE2KjYsdin2YXYrCDYp9mE2YXZh9mG2YrYqSDYr9ix2KfYs9in2Kog2K3Yp9mE2KnYjCDZiNiq
2K/YsdmK2Kgg2LnZhdmE2YrYjCDZiNmF2YfYp9mFINmF2YrYr9in2YbZitip2IwNCtio2YrZhtmF
2Kcg2YrYudiq2YXYryDYp9mE2KPZg9in2K/ZitmF2Yog2LnZhNmJINin2YTYo9i32LEg2KfZhNmG
2LjYsdmK2Kkg2YjYp9mE2KPYqNit2KfYqy4NCg0K2KfZhNmF2K7YsdisINin2YTZhtmH2KfYptmK
OiDZgdmKINin2YTZhdin2KzYs9iq2YrYsSDYp9mE2KPZg9in2K/ZitmF2Yog2YrZj9i32YTYqCDY
udin2K/YqdmLINiq2YLYr9mK2YUg2LHYs9in2YTYqSDYudmE2YXZitip2Iwg2KjZitmG2YXYpw0K
2YHZiiDYp9mE2YXZh9mG2Yog2YrZg9mI2YYg2KfZhNmF2LTYsdmI2Lkg2KfZhNmG2YfYp9im2Yog
2LnZhdmE2YrZkdmL2Kcg2YrZj9i32KjZgiDZgdmKINio2YrYptipINin2YTYudmF2YQuDQoNCg0K
Ktis2K/ZiNmEINio2LHYp9mF2Kwg2KfZhNmF2KfYrNiz2KrZitixINin2YTZhdmH2YbZiiog2YTZ
g9in2YHYqSDYp9mE2YXYrNin2YTYp9iqINiu2YTYp9mEINin2YTZgdiq2LHYqSDZhdmGICoxICoq
2LPYqNmF2KrZhdio2LEqKg0K2KXZhNmJIDMxINiv2YrYs9mF2KjYsSAyMDI1KtiMINio2K3Zitir
INmK2K3YqtmI2Yog2YPZhCDYqNix2YbYp9mF2Kwg2LnZhNmJICo4MCAqKtiz2KfYudipINiq2K/Y
sdmK2KjZitipINmF2LnYqtmF2K/YqSo6DQoNCg0KDQoq2KzYr9mI2YQg2KjYsdin2YXYrCDYp9mE
2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKIHwg2KPYutiz2LfYsyDigJMg2K/Zitiz2YXYqNix
IDIwMjUqDQoNCirZhSoNCg0KKtin2LPZhSDYp9mE2KjYsdmG2KfZhdisKg0KDQoq2KfZhNmF2KzY
p9mEKg0KDQoq2KfZhNmF2K/YqSDYp9mE2LLZhdmG2YrYqSoNCg0KKtiq2KfYsdmK2K4g2KfZhNin
2YbYudmC2KfYryoNCg0KMg0KDQrYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKINmB2Yog
2KfZhNmF2YjYp9ix2K8g2KfZhNio2LTYsdmK2KkNCg0K2KfZhNmF2YjYp9ix2K8g2KfZhNio2LTY
sdmK2KkNCg0KODAg2LPYp9i52Kkg2YXYudiq2YXYr9ipDQoNCjEgLSAxMiDYs9io2KrZhdio2LEg
MjAyNQ0KDQozDQoNCtin2YTZhdin2KzYs9iq2YrYsSDYp9mE2YXZh9mG2Yog2YHZiiDYp9mE2YXY
rdin2LPYqNipINmI2KfZhNmF2KfZhNmK2KkNCg0K2KfZhNmF2KfZhNmK2Kkg2YjYp9mE2YXYrdin
2LPYqNipDQoNCjgwINiz2KfYudipINmF2LnYqtmF2K/YqQ0KDQoxNSAtIDI2INiz2KjYqtmF2KjY
sSAyMDI1DQoNCjQNCg0K2KfZhNmF2KfYrNiz2KrZitixINin2YTZhdmH2YbZiiDZgdmKINil2K/Y
p9ix2Kkg2KfZhNmF2LTYp9ix2YrYuSBQTVANCg0K2KXYr9in2LHYqSDYp9mE2YXYtNin2LHZiti5
DQoNCjgwINiz2KfYudipINmF2LnYqtmF2K/YqQ0KDQo2IC0gMTcg2KPZg9iq2YjYqNixIDIwMjUN
Cg0KNQ0KDQrYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKINmB2Yog2KfZhNmC2YrYp9iv
2Kkg2YjYp9mE2KrYrdmI2YQg2KfZhNmF2KTYs9iz2YoNCg0K2KfZhNmC2YrYp9iv2Kkg2YjYp9mE
2KrYrdmI2YQg2KfZhNmF2KTYs9iz2YoNCg0KODAg2LPYp9i52Kkg2YXYudiq2YXYr9ipDQoNCjIw
IC0gMzEg2KPZg9iq2YjYqNixIDIwMjUNCg0KNg0KDQrYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF
2YfZhtmKINmB2Yog2KXYr9in2LHYqSDYp9mE2KrYutmK2YrYsSDZiNmC2YrYp9iv2Kkg2KfZhNij
2LLZhdin2KoNCg0K2KfZhNil2K/Yp9ix2Kkg2KfZhNin2LPYqtix2KfYqtmK2KzZitipDQoNCjgw
INiz2KfYudipINmF2LnYqtmF2K/YqQ0KDQozIC0gMTQg2YbZiNmB2YXYqNixIDIwMjUNCg0KNw0K
DQrYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKINmB2Yog2KfZhNiq2LPZiNmK2YIg2KfZ
hNix2YLZhdmKINmI2KXYr9in2LHYqSDYp9mE2LnZhNin2YXYp9iqINin2YTYqtis2KfYsdmK2KkN
Cg0K2KfZhNiq2LPZiNmK2YIg2YjYp9mE2KXYudmE2KfZhQ0KDQo4MCDYs9in2LnYqSDZhdi52KrZ
hdiv2KkNCg0KMTcgLSAyOCDZhtmI2YHZhdio2LEgMjAyNQ0KDQo4DQoNCtin2YTZhdin2KzYs9iq
2YrYsSDYp9mE2YXZh9mG2Yog2YHZiiDYpdiv2KfYsdipINin2YTYrNmI2K/YqSDZiNin2YTYrdmI
2YPZhdipDQoNCtin2YTYrNmI2K/YqSDZiNin2YTYrdmI2YPZhdipDQoNCjgwINiz2KfYudipINmF
2LnYqtmF2K/YqQ0KDQoxIC0gMTIg2K/Zitiz2YXYqNixIDIwMjUNCg0KOQ0KDQrYp9mE2YXYp9is
2LPYqtmK2LEg2KfZhNmF2YfZhtmKINmB2Yog2KXYr9in2LHYqSDYp9mE2YXYtNiq2LHZitin2Kog
2YjYs9mE2KfYs9mEINin2YTYpdmF2K/Yp9ivDQoNCtin2YTZhdi02KrYsdmK2KfYqiDZiNin2YTZ
hNmI2KzYs9iq2YrYp9iqDQoNCjgwINiz2KfYudipINmF2LnYqtmF2K/YqQ0KDQoxNSAtIDI2INiv
2YrYs9mF2KjYsSAyMDI1DQoNCjEwDQoNCtin2YTZhdin2KzYs9iq2YrYsSDYp9mE2YXZh9mG2Yog
2YHZiiDYp9mE2KXYr9in2LHYqSDYp9mE2LXYrdmK2KkNCg0K2KfZhNi12K3YqSDZiNin2YTZhdiz
2KrYtNmB2YrYp9iqDQoNCjgwINiz2KfYudipINmF2LnYqtmF2K/YqQ0KDQoyMiAtIDMxINiv2YrY
s9mF2KjYsSAyMDI1DQoNCg0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQoNCirwn5Od
KiAq2YXZhNin2K3YuNin2Kog2YXZh9mF2KkqKjoqDQoNCiAgIC0g2KzZhdmK2Lkg2KfZhNio2LHY
p9mF2Kwg2KrZhdmG2K0g2LTZh9in2K/YqSDZhdmI2KvZgtipINmI2YXYudiq2YXYr9ipINmI2YLY
p9io2YTYqSDZhNmE2KrYtdiv2YrZgiDZhdmGINin2YTYrtin2LHYrNmK2KkuDQogICAtINin2YTZ
hNi62Kk6INin2YTYudix2KjZitipICjZhdi5INiq2YjZgdixINmF2KrYsdis2YUg2LnZhtivINin
2YTYrdin2KzYqSDZhNmE2KjYsdin2YXYrCDYp9mE2K/ZiNmE2YrYqSkuDQogICAtINin2YTZgdim
2Kkg2KfZhNmF2LPYqtmH2K/ZgdipOiDYp9mE2YXYr9mK2LHZiNmGINin2YTYqtmG2YHZitiw2YrZ
iNmG2Iwg2YXYs9ik2YjZhNmIINin2YTYqti32YjZitix2Iwg2YXYs9ik2YjZhNmIINin2YTYrNmI
2K/YqdiMDQogICDZgtin2K/YqSDYp9mE2YHYsdmC2Iwg2LHYpNiz2KfYoSDYp9mE2KPZgtiz2KfZ
hdiMINmI2LDZiNmIINin2YTYt9mF2YjYrdin2Kog2KfZhNmC2YrYp9iv2YrYqS4NCiAgIC0g2YrZ
hdmD2YYg2KrZhtmB2YrYsCDYp9mE2KjYsdin2YXYrCAq2KPZiNmG2YTYp9mK2YYg2LnYqNixKiog
Wm9vbSog2KPZiCAq2K3YttmI2LHZiiog2K3Ys9ioINix2LrYqNipINin2YTZhdi02KfYsdmD2YrZ
hi4NCg0KwrcgICAgICAgICAq2YTZhNiq2LPYrNmK2YQg2YjYp9mE2KfYs9iq2YHYs9in2LEqDQoN
CsK3ICAgICAgICAgKtmI2KjZh9iw2Ycg2KfZhNmF2YbYp9iz2KjYqSDZitiz2LnYr9mG2Kcg2K/Y
udmI2KrZg9mFINmE2YTZhdi02KfYsdmD2Kkg2YjYqti52YXZitmFINiu2LfYp9io2YbYpyDYudmE
2Ykg2KfZhNmF2YfYqtmF2YrZhg0K2KjZhdmA2YDZiNi22YDZiNi5ICoq2KfZhNi02YfYp9iv2Kkg
2KfZhNin2K3Yqtix2KfZgdmK2KkgKirZiNil2YHYp9iv2KrZhtinINio2YXZhiDYqtmC2KrYsdit
2YjZhiDYqtmI2KzZitmHINin2YTYr9i52YjYqSDZhNmH2YUqDQoNCsK3ICAgICAgICAgKtmE2YXY
stmK2K8g2YXZhiDYp9mE2YXYudmE2YjZhdin2Kog2YrZhdmD2YbZgyDYp9mE2KrZiNin2LXZhCDZ
hdi5INijIC8g2LPYp9ix2Kkg2LnYqNivINin2YTYrNmI2KfYryDigJMg2YbYp9im2KgNCtmF2K/Z
itixINin2YTYqtiv2LHZitioIOKAkyDYp9mE2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG
2YXZitipINin2YTYp9iv2KfYsdmK2KkqDQoNCsK3ICAgICAgICAgKtis2YjYp9mEIOKAkyDZiNin
2KrYsyDYp9ioIDoqDQoNCsK3ICAgICAgICAgKjAwMjAxMDY5OTk0Mzk5IC0wMDIwMTA2Mjk5MjUx
MCAtIDAwMjAxMDk2ODQxNjI2Kg0KDQoNCg0KICDYqNmP2LnYryDYudio2LEgWm9vbSAo2YHZiiDY
rdin2YQg2KrYudiw2LEg2KfZhNit2LbZiNixKQ0K2YXZgtiv2YUg2YXZhjogKtin2YTYr9in2LEg
2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNil2K/Yp9ix2YrYqSoqIOKAkyBBSEFE
Kg0K2LTZh9in2K/YqSDZhdmH2YbZitipINmF2LnYqtmF2K/YqdiMINmC2KfYqNmE2Kkg2YTZhNiq
2YjYq9mK2YIg2YXZhiDZiNiy2KfYsdipINin2YTYrtin2LHYrNmK2Kkg2YjZg9in2YHYqSDYp9mE
2LPZgdin2LHYp9iqINin2YTYudix2KjZitipLg0KDQoNCg0KKtin2YTZhdmC2K/ZhdipKio6Kg0K
DQrZitmH2K/ZgSDZh9iw2Kcg2KfZhNio2LHZhtin2YXYrCDYp9mE2YXYqtiu2LXYtSDYpdmE2Ykg
2KrYo9mH2YrZhCDYp9mE2YXYtNin2LHZg9mK2YYg2KjYp9mE2YXZh9in2LHYp9iqINin2YTYp9it
2KrYsdin2YHZitipINmI2KfZhNij2K/ZiNin2KoNCtin2YTYudmF2YTZitipINmE2KrYt9mI2YrY
sSDYp9mE2LDYp9iqINmI2KfZhNii2K7YsdmK2YbYjCDZiNiq2K3ZgtmK2YIg2KfZhNiq2YXZitiy
INmB2Yog2KfZhNij2K/Yp9ihINin2YTYtNiu2LXZiiDZiNin2YTZhdmH2YbZitiMDQrYqNin2YTY
p9i52KrZhdin2K8g2LnZhNmJINij2K3Yr9irINij2LPYp9mE2YrYqCDYudmE2YUg2KfZhNmG2YHY
syDYp9mE2KXZitis2KfYqNmK2Iwg2YjYp9mE2KrYr9ix2YrYqNiMINmI2KfZhNiq2K3ZgdmK2LLY
jCDZiNin2YTZgtmK2KfYr9ipLg0KDQoNCg0KKtin2YTYo9mH2K/Yp9mBKio6Kg0KDQogICAtINmB
2YfZhSDYo9iz2KfYs9mK2KfYqiDZiNmF2YHYp9mH2YrZhSDYp9mE2KrZhtmF2YrYqSDYp9mE2KjY
tNix2YrYqSDZiNij2KvYsdmH2Kcg2YHZiiDYqNmK2KbYqSDYp9mE2LnZhdmEINmI2KfZhNit2YrY
p9ipLg0KICAgLSDYp9mD2KrYs9in2Kgg2YXZh9in2LHYp9iqINiq2LfZiNmK2LEg2KfZhNiw2KfY
qtiMINmI2KrYrdiz2YrZhiDYp9mE2KXZhtiq2KfYrNmK2KnYjCDZiNio2YbYp9ihINin2YTYq9mC
2Kkg2KjYp9mE2YbZgdizLg0KICAgLSDYp9mE2KrYudix2YEg2LnZhNmJINmF2YbZh9is2YrYp9iq
INin2YTYqtiv2LHZitioINmI2KfZhNiq2KPYq9mK2LEg2KfZhNil2YrYrNin2KjZiiDZgdmKINin
2YTYotiu2LHZitmGLg0KICAgLSDYqtmG2YXZitipINin2YTZhdmH2KfYsdin2Kog2KfZhNmC2YrY
p9iv2YrYqSDZiNin2YTZgtiv2LHYqSDYudmE2Ykg2KXYr9in2LHYqSDZgdix2YIg2KfZhNi52YXZ
hCDZiNiq2K3ZgtmK2YIg2KfZhNij2YfYr9in2YEuDQogICAtINiq2LfYqNmK2YIg2KPYr9mI2KfY
qiDYp9mE2KrYrdmE2YrZhCDYp9mE2YbZgdiz2Yog2YjYp9mE2LPZhNmI2YPZiiDZhNiq2LfZiNmK
2LEg2KfZhNij2K/Yp9ihINin2YTYqNi02LHZii4NCg0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tDQoNCirwn5GlKiAq2KfZhNmB2KbYp9iqINin2YTZhdiz2KrZh9iv2YHYqSoqOioNCg0K
ICAgLSDYp9mE2YXYr9ix2KjZiNmGINmI2KfZhNin2LPYqti02KfYsdmK2YjZhiDZgdmKINmF2KzY
p9mE2KfYqiDYp9mE2KrZhtmF2YrYqSDYp9mE2KjYtNix2YrYqS4NCiAgIC0g2KfZhNmC2YrYp9iv
2YrZiNmGINmI2KfZhNmF2K/Ysdin2KEg2KfZhNix2KfYutio2YjZhiDZgdmKINiq2LfZiNmK2LEg
2YPZgdin2KHYp9iq2YfZhSDYp9mE2LTYrti12YrYqSDZiNin2YTZhdmH2YbZitipLg0KICAgLSDY
p9mE2YXZh9iq2YXZiNmGINio2KfZhNiq2LfZiNmK2LEg2KfZhNiw2KfYqtmKINmI2KfZhNi52YXZ
hCDZgdmKINmF2KzYp9mEINin2YTYqtiv2LHZitioINij2Ygg2KfZhNil2LHYtNin2K8uDQogICAt
INin2YTYudin2YXZhNmI2YYg2YHZiiDYp9mE2YXZiNin2LHYryDYp9mE2KjYtNix2YrYqSDZiNin
2YTYqti32YjZitixINin2YTZhdik2LPYs9mKLg0KICAgLSDZg9in2YHYqSDYp9mE2LHYp9i62KjZ
itmGINmB2Yog2KXYrdiv2KfYqyDZhtmC2YTYqSDZhtmI2LnZitipINmB2Yog2YXYs9in2LHZh9mF
INin2YTYtNiu2LXZiiDYo9mIINin2YTZhdmH2YbZii4NCg0KwrcgICAgICAgICAq2YTZhNiq2LPY
rNmK2YQg2YjYp9mE2KfYs9iq2YHYs9in2LEqDQoNCsK3ICAgICAgICAgKtmI2KjZh9iw2Ycg2KfZ
hNmF2YbYp9iz2KjYqSDZitiz2LnYr9mG2Kcg2K/YudmI2KrZg9mFINmE2YTZhdi02KfYsdmD2Kkg
2YjYqti52YXZitmFINiu2LfYp9io2YbYpyDYudmE2Ykg2KfZhNmF2YfYqtmF2YrZhg0K2KjZhdmA
2YDZiNi22YDZiNi5ICoq2KfZhNi02YfYp9iv2Kkg2KfZhNin2K3Yqtix2KfZgdmK2KkgKirZiNil
2YHYp9iv2KrZhtinINio2YXZhiDYqtmC2KrYsdit2YjZhiDYqtmI2KzZitmHINin2YTYr9i52YjY
qSDZhNmH2YUqDQoNCsK3ICAgICAgICAgKtmE2YXYstmK2K8g2YXZhiDYp9mE2YXYudmE2YjZhdin
2Kog2YrZhdmD2YbZgyDYp9mE2KrZiNin2LXZhCDZhdi5INijIC8g2LPYp9ix2Kkg2LnYqNivINin
2YTYrNmI2KfYryDigJMg2YbYp9im2KgNCtmF2K/ZitixINin2YTYqtiv2LHZitioIOKAkyDYp9mE
2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG2YXZitipINin2YTYp9iv2KfYsdmK2KkqDQoN
CsK3ICAgICAgICAgKtis2YjYp9mEIOKAkyDZiNin2KrYsyDYp9ioIDoqDQoNCsK3ICAgICAgICAg
KjAwMjAxMDY5OTk0Mzk5IC0wMDIwMTA2Mjk5MjUxMCDigJMgMDAyMDEwOTY4NDE2MjYqDQoNCirY
p9mE2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG2YXZitipINin2YTYp9iv2KfYsdmK2Kkg
LSAqKkFIQUQqDQoNCtmF2Kcg2YfZiCDYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmK2J8N
Cg0K2KfZhNmF2KfYrNiz2KrZitixINin2YTZhdmH2YbZiiDZh9mIINiv2LHYrNipINiv2LHYp9iz
2KfYqiDYudmE2YrYpyDYqtix2YPYsiDYudmE2Ykg2KfZhNiq2LfYqNmK2YIg2KfZhNi52YXZhNmK
INmI2KfZhNmG2YjYp9it2YoNCtin2YTZhdmH2YbZitip2Iwg2YjYqtmH2K/ZgSDYpdmE2Ykg2KrY
o9mH2YrZhCDYp9mE2KPZgdix2KfYryDZhNmE2LnZhdmEINio2YPZgdin2KHYqSDYudin2YTZitip
INmB2Yog2KrYrti12LXYp9iq2YfZhS4g2LrYp9mE2KjZi9inINmF2KcNCtmK2KrZhSDYqtmC2K/Z
itmFINmH2LDZhyDYp9mE2KjYsdin2YXYrCDZhdmGINmC2KjZhCDYrNin2YXYudin2Kog2YXYrdmE
2YrYqSDZiNiv2YjZhNmK2Kkg2YXYsdmF2YjZgtip2Iwg2YjYqti02YXZhCDZhdiy2YrYrNmL2Kcg
2YXZhg0K2KfZhNmF2K3Yp9i22LHYp9iqINin2YTZhti42LHZitip2Iwg2YjYp9mE2YXYtNin2LHZ
iti5INin2YTYudmF2YTZitip2Iwg2YjYp9mE2KrYr9ix2YrYqCDYp9mE2YXZitiv2KfZhtmKLg0K
DQrZiNiq2LHZg9iyINmH2LDZhyDYp9mE2KjYsdin2YXYrCDYudmE2Ykg2KrYt9mI2YrYsSDYp9mE
2YXZh9in2LHYp9iqINin2YTZgtmK2KfYr9mK2KnYjCDZiNin2YTYpdiv2KfYsdmK2KnYjCDZiNin
2YTYqtit2YTZitmE2YrYqSDYp9mE2KrZig0K2YrYrdiq2KfYrNmH2Kcg2KfZhNij2YHYsdin2K8g
2YTZhNmG2KzYp9itINmB2Yog2KjZitim2KfYqiDYp9mE2LnZhdmEINin2YTZhdiq2LrZitix2Kku
DQoNCtin2YTZgdix2YIg2KjZitmGINin2YTZhdin2KzYs9iq2YrYsSDYp9mE2YXZh9mG2Yog2YjY
p9mE2KPZg9in2K/ZitmF2YoNCg0K2KfZhNmH2K/ZgTog2YrZh9iv2YEg2KfZhNmF2KfYrNiz2KrZ
itixINin2YTZhdmH2YbZiiDYpdmE2Ykg2KrZhtmF2YrYqSDYp9mE2YXZh9in2LHYp9iqINin2YTY
udmF2YTZitipINmI2KfZhNiq2LfYqNmK2YLZitip2Iwg2KjZitmG2YXYpw0K2YrYsdmD2LIg2KfZ
hNij2YPYp9iv2YrZhdmKINi52YTZiSDYp9mE2KjYrdirINin2YTYudmE2YXZiiDZiNil2YbYqtin
2Kwg2KfZhNmF2LnYsdmB2KkuDQoNCtin2YTYrNmF2YfZiNixINin2YTZhdiz2KrZh9iv2YE6INin
2YTYqNix2KfZhdisINin2YTZhdmH2YbZitipINiq2Y/YtdmF2YUg2K7YtdmK2LXZi9inINmE2YTZ
hdmI2LjZgdmK2YYg2YjYo9i12K3Yp9ioINin2YTYrtio2LHYqQ0K2KfZhNi52YXZhNmK2Kkg2KfZ
hNiw2YrZhiDZitix2LrYqNmI2YYg2YHZiiDYp9mE2KrYsdmC2YrYqSDYo9mIINin2YTYqti62YrZ
itixINin2YTZhdmH2YbZitiMINi52YTZiSDYudmD2LMg2KfZhNij2YPYp9iv2YrZhdmKINin2YTY
sNmKDQrZitmP2YbYp9iz2Kgg2KfZhNio2KfYrdir2YrZhiDZiNin2YTZhdmH2KrZhdmK2YYg2KjY
p9mE2K/Zg9iq2YjYsdin2YcuDQoNCtin2YTZhdit2KrZiNmJOiDYqtiq2LbZhdmGINin2YTYqNix
2KfZhdisINin2YTZhdmH2YbZitipINiv2LHYp9iz2KfYqiDYrdin2YTYqdiMINmI2KrYr9ix2YrY
qCDYudmF2YTZitiMINmI2YXZh9in2YUg2YXZitiv2KfZhtmK2KnYjA0K2KjZitmG2YXYpyDZiti5
2KrZhdivINin2YTYo9mD2KfYr9mK2YXZiiDYudmE2Ykg2KfZhNij2LfYsSDYp9mE2YbYuNix2YrY
qSDZiNin2YTYo9io2K3Yp9irLg0KDQrYp9mE2YXYrtix2Kwg2KfZhNmG2YfYp9im2Yo6INmB2Yog
2KfZhNmF2KfYrNiz2KrZitixINin2YTYo9mD2KfYr9mK2YXZiiDZitmP2LfZhNioINi52KfYr9ip
2Ysg2KrZgtiv2YrZhSDYsdiz2KfZhNipINi52YTZhdmK2KnYjCDYqNmK2YbZhdinDQrZgdmKINin
2YTZhdmH2YbZiiDZitmD2YjZhiDYp9mE2YXYtNix2YjYuSDYp9mE2YbZh9in2KbZiiDYudmF2YTZ
itmR2YvYpyDZitmP2LfYqNmCINmB2Yog2KjZitim2Kkg2KfZhNi52YXZhC4NCg0KDQoq2KzYr9mI
2YQg2KjYsdin2YXYrCDYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKKiDZhNmD2KfZgdip
INin2YTZhdis2KfZhNin2Kog2K7ZhNin2YQg2KfZhNmB2KrYsdipINmF2YYgKjEgKirYs9io2YXY
qtmF2KjYsSoqDQrYpdmE2YkgMzEg2K/Zitiz2YXYqNixIDIwMjUq2Iwg2KjYrdmK2Ksg2YrYrdiq
2YjZiiDZg9mEINio2LHZhtin2YXYrCDYudmE2YkgKjgwICoq2LPYp9i52Kkg2KrYr9ix2YrYqNmK
2Kkg2YXYudiq2YXYr9ipKjoNCg0KDQoNCirYrNiv2YjZhCDYqNix2KfZhdisINin2YTZhdin2KzY
s9iq2YrYsSDYp9mE2YXZh9mG2YogfCDYo9i62LPYt9izIOKAkyDYr9mK2LPZhdio2LEgMjAyNSoN
Cg0KKtmFKg0KDQoq2KfYs9mFINin2YTYqNix2YbYp9mF2KwqDQoNCirYp9mE2YXYrNin2YQqDQoN
CirYp9mE2YXYr9ipINin2YTYstmF2YbZitipKg0KDQoq2KrYp9ix2YrYriDYp9mE2KfZhti52YLY
p9ivKg0KDQoyDQoNCtin2YTZhdin2KzYs9iq2YrYsSDYp9mE2YXZh9mG2Yog2YHZiiDYp9mE2YXZ
iNin2LHYryDYp9mE2KjYtNix2YrYqQ0KDQrYp9mE2YXZiNin2LHYryDYp9mE2KjYtNix2YrYqQ0K
DQo4MCDYs9in2LnYqSDZhdi52KrZhdiv2KkNCg0KMSAtIDEyINiz2KjYqtmF2KjYsSAyMDI1DQoN
CjMNCg0K2KfZhNmF2KfYrNiz2KrZitixINin2YTZhdmH2YbZiiDZgdmKINin2YTZhdit2KfYs9io
2Kkg2YjYp9mE2YXYp9mE2YrYqQ0KDQrYp9mE2YXYp9mE2YrYqSDZiNin2YTZhdit2KfYs9io2KkN
Cg0KODAg2LPYp9i52Kkg2YXYudiq2YXYr9ipDQoNCjE1IC0gMjYg2LPYqNiq2YXYqNixIDIwMjUN
Cg0KNA0KDQrYp9mE2YXYp9is2LPYqtmK2LEg2KfZhNmF2YfZhtmKINmB2Yog2KXYr9in2LHYqSDY
p9mE2YXYtNin2LHZiti5IFBNUA0KDQrYpdiv2KfYsdipINin2YTZhdi02KfYsdmK2LkNCg0KODAg
2LPYp9i52Kkg2YXYudiq2YXYr9ipDQoNCjYgLSAxNyDYo9mD2KrZiNio2LEgMjAyNQ0KDQo1DQoN
Ctin2YTZhdin2KzYs9iq2YrYsSDYp9mE2YXZh9mG2Yog2YHZiiDYp9mE2YLZitin2K/YqSDZiNin
2YTYqtit2YjZhCDYp9mE2YXYpNiz2LPZig0KDQrYp9mE2YLZitin2K/YqSDZiNin2YTYqtit2YjZ
hCDYp9mE2YXYpNiz2LPZig0KDQo4MCDYs9in2LnYqSDZhdi52KrZhdiv2KkNCg0KMjAgLSAzMSDY
o9mD2KrZiNio2LEgMjAyNQ0KDQo2DQoNCtin2YTZhdin2KzYs9iq2YrYsSDYp9mE2YXZh9mG2Yog
2YHZiiDYpdiv2KfYsdipINin2YTYqti62YrZitixINmI2YLZitin2K/YqSDYp9mE2KPYstmF2KfY
qg0KDQrYp9mE2KXYr9in2LHYqSDYp9mE2KfYs9iq2LHYp9iq2YrYrNmK2KkNCg0KODAg2LPYp9i5
2Kkg2YXYudiq2YXYr9ipDQoNCjMgLSAxNCDZhtmI2YHZhdio2LEgMjAyNQ0KDQo3DQoNCtin2YTZ
hdin2KzYs9iq2YrYsSDYp9mE2YXZh9mG2Yog2YHZiiDYp9mE2KrYs9mI2YrZgiDYp9mE2LHZgtmF
2Yog2YjYpdiv2KfYsdipINin2YTYudmE2KfZhdin2Kog2KfZhNiq2KzYp9ix2YrYqQ0KDQrYp9mE
2KrYs9mI2YrZgiDZiNin2YTYpdi52YTYp9mFDQoNCjgwINiz2KfYudipINmF2LnYqtmF2K/YqQ0K
DQoxNyAtIDI4INmG2YjZgdmF2KjYsSAyMDI1DQoNCjgNCg0K2KfZhNmF2KfYrNiz2KrZitixINin
2YTZhdmH2YbZiiDZgdmKINil2K/Yp9ix2Kkg2KfZhNis2YjYr9ipINmI2KfZhNit2YjZg9mF2KkN
Cg0K2KfZhNis2YjYr9ipINmI2KfZhNit2YjZg9mF2KkNCg0KODAg2LPYp9i52Kkg2YXYudiq2YXY
r9ipDQoNCjEgLSAxMiDYr9mK2LPZhdio2LEgMjAyNQ0KDQo5DQoNCtin2YTZhdin2KzYs9iq2YrY
sSDYp9mE2YXZh9mG2Yog2YHZiiDYpdiv2KfYsdipINin2YTZhdi02KrYsdmK2KfYqiDZiNiz2YTY
p9iz2YQg2KfZhNil2YXYr9in2K8NCg0K2KfZhNmF2LTYqtix2YrYp9iqINmI2KfZhNmE2YjYrNiz
2KrZitin2KoNCg0KODAg2LPYp9i52Kkg2YXYudiq2YXYr9ipDQoNCjE1IC0gMjYg2K/Zitiz2YXY
qNixIDIwMjUNCg0KMTANCg0K2KfZhNmF2KfYrNiz2KrZitixINin2YTZhdmH2YbZiiDZgdmKINin
2YTYpdiv2KfYsdipINin2YTYtdit2YrYqQ0KDQrYp9mE2LXYrdipINmI2KfZhNmF2LPYqti02YHZ
itin2KoNCg0KODAg2LPYp9i52Kkg2YXYudiq2YXYr9ipDQoNCjIyIC0gMzEg2K/Zitiz2YXYqNix
IDIwMjUNCg0KDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCg0KKvCfk50qICrZhdmE
2KfYrdi42KfYqiDZhdmH2YXYqSoqOioNCg0KICAgLSDYrNmF2YrYuSDYp9mE2KjYsdin2YXYrCDY
qtmF2YbYrSDYtNmH2KfYr9ipINmF2YjYq9mC2Kkg2YjZhdi52KrZhdiv2Kkg2YjZgtin2KjZhNip
INmE2YTYqti12K/ZitmCINmF2YYg2KfZhNiu2KfYsdis2YrYqS4NCiAgIC0g2KfZhNmE2LrYqTog
2KfZhNi52LHYqNmK2KkgKNmF2Lkg2KrZiNmB2LEg2YXYqtix2KzZhSDYudmG2K8g2KfZhNit2KfY
rNipINmE2YTYqNix2KfZhdisINin2YTYr9mI2YTZitipKS4NCiAgIC0g2KfZhNmB2KbYqSDYp9mE
2YXYs9iq2YfYr9mB2Kk6INin2YTZhdiv2YrYsdmI2YYg2KfZhNiq2YbZgdmK2LDZitmI2YbYjCDZ
hdiz2KTZiNmE2Ygg2KfZhNiq2LfZiNmK2LHYjCDZhdiz2KTZiNmE2Ygg2KfZhNis2YjYr9ip2IwN
CiAgINmC2KfYr9ipINin2YTZgdix2YLYjCDYsdik2LPYp9ihINin2YTYo9mC2LPYp9mF2Iwg2YjY
sNmI2Ygg2KfZhNi32YXZiNit2KfYqiDYp9mE2YLZitin2K/ZitipLg0KICAgLSDZitmF2YPZhiDY
qtmG2YHZitiwINin2YTYqNix2KfZhdisICrYo9mI2YbZhNin2YrZhiDYudio2LEqKiBab29tKiDY
o9mIICrYrdi22YjYsdmKKiDYrdiz2Kgg2LHYutio2Kkg2KfZhNmF2LTYp9ix2YPZitmGLg0KDQrC
tyAgICAgICAgICrZhNmE2KrYs9is2YrZhCDZiNin2YTYp9iz2KrZgdiz2KfYsSoNCg0KwrcgICAg
ICAgICAq2YjYqNmH2LDZhyDYp9mE2YXZhtin2LPYqNipINmK2LPYudiv2YbYpyDYr9i52YjYqtmD
2YUg2YTZhNmF2LTYp9ix2YPYqSDZiNiq2LnZhdmK2YUg2K7Yt9in2KjZhtinINi52YTZiSDYp9mE
2YXZh9iq2YXZitmGDQrYqNmF2YDZgNmI2LbZgNmI2LkgKirYp9mE2LTZh9in2K/YqSDYp9mE2KfY
rdiq2LHYp9mB2YrYqSAqKtmI2KXZgdin2K/YqtmG2Kcg2KjZhdmGINiq2YLYqtix2K3ZiNmGINiq
2YjYrNmK2Ycg2KfZhNiv2LnZiNipINmE2YfZhSoNCg0KwrcgICAgICAgICAq2YTZhdiy2YrYryDZ
hdmGINin2YTZhdi52YTZiNmF2KfYqiDZitmF2YPZhtmDINin2YTYqtmI2KfYtdmEINmF2Lkg2KMg
LyDYs9in2LHYqSDYudio2K8g2KfZhNis2YjYp9ivIOKAkyDZhtin2KbYqA0K2YXYr9mK2LEg2KfZ
hNiq2K/YsdmK2Kgg4oCTINin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg
2KfZhNin2K/Yp9ix2YrYqSoNCg0KwrcgICAgICAgICAq2KzZiNin2YQg4oCTINmI2KfYqtizINin
2KggOioNCg0KwrcgICAgICAgICAqMDAyMDEwNjk5OTQzOTkgLTAwMjAxMDYyOTkyNTEwIC0gMDAy
MDEwOTY4NDE2MjYqDQoNCi0tIApZb3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91
IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICJrYXNhbi1kZXYiIGdyb3VwLgpU
byB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBm
cm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91
cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29n
bGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L0NBRGoxWkttSmFfY2liVkQ2QmVjTkcxMjdmNkJ5aDVV
Zno2S3QzcEc1S250RlR6SGhoQSU0MG1haWwuZ21haWwuY29tLgo=
--000000000000fbd366063d1983ad
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;m=
argin:0in 0in 8pt;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;=
"><b><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Segoe UI S=
ymbol&quot;,&quot;sans-serif&quot;">=F0=9F=8E=AF</span></b><span dir=3D"RTL=
"></span><span dir=3D"RTL"></span><b><span style=3D"font-size:26pt;font-fam=
ily:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"RTL"></span=
><span dir=3D"RTL"></span>
<span lang=3D"AR-SA">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1=
 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D8=A7=D9=84=D9=85=D8=B5=D8=BA=D8=B1 =
=D9=81=D9=8A =D8=A7=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A8=
=D8=B4=D8=B1=D9=8A=D8=A9</span></span></b><b><span dir=3D"LTR" style=3D"fon=
t-size:26pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></sp=
an></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">Mini Professional Master&#39;s in Human
Development</span></b><span dir=3D"LTR" style=3D"font-size:20pt;font-family=
:&quot;Times New Roman&quot;,&quot;serif&quot;"><br>
</span><i><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D9=8A=D8=A8=D8=AF=D8=A3 =D9=81=D9=
=8A 31 =D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 2025 80 =D8=B3=D8=A7=D8=B9=D8=A9
=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9</span></i><span dir=3D"LTR" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;"><br>
</span><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=
=D8=A9 =E2=80=93 =D8=AC=D9=85=D9=87=D9=88=D8=B1=D9=8A=D8=A9 =D9=85=D8=B5=D8=
=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9</span></b><span dir=3D"LTR" =
style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif=
&quot;"><br>
</span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;">=D8=A3=D9=88 =D8=B9=D9=86</span><b styl=
e=3D"font-size:11pt"><span dir=3D"LTR" style=3D"font-size:20pt;font-family:=
&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;">=F0=9F=8E=AF</span></b>=
<span dir=3D"RTL" style=3D"font-size:11pt"></span><span dir=3D"RTL" style=
=3D"font-size:11pt"></span><b style=3D"font-size:11pt"><span style=3D"font-=
size:26pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span =
dir=3D"RTL"></span><span dir=3D"RTL"></span>
<span lang=3D"AR-SA">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1=
 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D8=A7=D9=84=D9=85=D8=B5=D8=BA=D8=B1 =
=D9=81=D9=8A =D8=A7=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A8=
=D8=B4=D8=B1=D9=8A=D8=A9</span></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">Mini Professional Master&#39;s in Human
Development</span></b><span dir=3D"LTR" style=3D"font-size:20pt;font-family=
:&quot;Times New Roman&quot;,&quot;serif&quot;"><br>
</span><i><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D9=8A=D8=A8=D8=AF=D8=A3 =D9=81=D9=
=8A 31 =D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 2025 80 =D8=B3=D8=A7=D8=B9=D8=A9
=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9</span></i><span dir=3D"LTR" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;"><br>
</span><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=
=D8=A9 =E2=80=93 =D8=AC=D9=85=D9=87=D9=88=D8=B1=D9=8A=D8=A9 =D9=85=D8=B5=D8=
=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9</span></b><span dir=3D"LTR" =
style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif=
&quot;"><br>
</span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;">=D8=A3=D9=88 =D8=B9=D9=86 =D8=A8=D9=8F=
=D8=B9=D8=AF =D8=B9=D8=A8=D8=B1</span><span dir=3D"LTR"></span><span dir=3D=
"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span>
Zoom (</span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot=
;Times New Roman&quot;,&quot;serif&quot;">=D9=81=D9=8A =D8=AD=D8=A7=D9=84 =
=D8=AA=D8=B9=D8=B0=D8=B1 =D8=A7=D9=84=D8=AD=D8=B6=D9=88=D8=B1</span><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span>)<br>
</span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;">=D9=85=D9=82=D8=AF=D9=85 =D9=85=D9=86</=
span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" st=
yle=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&q=
uot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:
</span><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=
=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=
=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></b><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"f=
ont-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span> =E2=80=93 AHAD</span></b><=
span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&=
quot;,&quot;serif&quot;"><br>
</span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=
=D9=87=D9=86=D9=8A=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9=D8=8C =D9=82=
=D8=A7=D8=A8=D9=84=D8=A9 =D9=84=D9=84=D8=AA=D9=88=D8=AB=D9=8A=D9=82 =D9=85=
=D9=86
=D9=88=D8=B2=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AE=D8=A7=D8=B1=D8=AC=D9=8A=
=D8=A9 =D9=88=D9=83=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=D8=B3=D9=81=D8=A7=D8=B1=
=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9</span><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:2=
0pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=85=D9=82=D8=AF=D9=85=D8=A9</span></b><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"f=
ont-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=D9=8A=D9=87=D8=AF=D9=81 =D9=87=D8=B0=D8=A7 =D8=A7=D9=84=D8=A8=
=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5 =
=D8=A5=D9=84=D9=89 =D8=AA=D8=A3=D9=87=D9=8A=D9=84
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D8=A8=D8=A7=D9=84=
=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=
=D8=A7=D9=81=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=A3=D8=AF=D9=88=D8=A7=D8=AA =
=D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=84=D8=AA=D8=B7=D9=88=D9=8A=
=D8=B1 =D8=A7=D9=84=D8=B0=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=A2=D8=AE=D8=B1=
=D9=8A=D9=86=D8=8C =D9=88=D8=AA=D8=AD=D9=82=D9=8A=D9=82
=D8=A7=D9=84=D8=AA=D9=85=D9=8A=D8=B2 =D9=81=D9=8A =D8=A7=D9=84=D8=A3=D8=AF=
=D8=A7=D8=A1 =D8=A7=D9=84=D8=B4=D8=AE=D8=B5=D9=8A =D9=88=D8=A7=D9=84=D9=85=
=D9=87=D9=86=D9=8A=D8=8C =D8=A8=D8=A7=D9=84=D8=A7=D8=B9=D8=AA=D9=85=D8=A7=
=D8=AF =D8=B9=D9=84=D9=89 =D8=A3=D8=AD=D8=AF=D8=AB =D8=A3=D8=B3=D8=A7=D9=84=
=D9=8A=D8=A8 =D8=B9=D9=84=D9=85 =D8=A7=D9=84=D9=86=D9=81=D8=B3 =D8=A7=D9=84=
=D8=A5=D9=8A=D8=AC=D8=A7=D8=A8=D9=8A=D8=8C
=D9=88=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D8=8C =D9=88=D8=A7=D9=84=
=D8=AA=D8=AD=D9=81=D9=8A=D8=B2=D8=8C =D9=88=D8=A7=D9=84=D9=82=D9=8A=D8=A7=
=D8=AF=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;=
,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</sp=
an></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D8=A3=D9=87=D8=AF=D8=A7=D9=81</span></b><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"f=
ont-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=81=D9=87=D9=85
     =D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA =D9=88=D9=85=D9=81=D8=A7=D9=
=87=D9=8A=D9=85 =D8=A7=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=
=A8=D8=B4=D8=B1=D9=8A=D8=A9 =D9=88=D8=A3=D8=AB=D8=B1=D9=87=D8=A7 =D9=81=D9=
=8A =D8=A8=D9=8A=D8=A6=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=88=D8=A7=D9=
=84=D8=AD=D9=8A=D8=A7=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times =
New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LT=
R"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=83=D8=AA=D8=B3=D8=A7=D8=A8
     =D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =
=D8=A7=D9=84=D8=B0=D8=A7=D8=AA=D8=8C =D9=88=D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =
=D8=A7=D9=84=D8=A5=D9=86=D8=AA=D8=A7=D8=AC=D9=8A=D8=A9=D8=8C =D9=88=D8=A8=
=D9=86=D8=A7=D8=A1 =D8=A7=D9=84=D8=AB=D9=82=D8=A9 =D8=A8=D8=A7=D9=84=D9=86=
=D9=81=D8=B3</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;=
,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</sp=
an></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D8=AA=D8=B9=D8=B1=D9=81
     =D8=B9=D9=84=D9=89 =D9=85=D9=86=D9=87=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=
=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D9=88=D8=A7=D9=84=D8=AA=D8=A3=D8=AB=
=D9=8A=D8=B1 =D8=A7=D9=84=D8=A5=D9=8A=D8=AC=D8=A7=D8=A8=D9=8A =D9=81=D9=8A =
=D8=A7=D9=84=D8=A2=D8=AE=D8=B1=D9=8A=D9=86</span><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span>=
<span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=AA=D9=86=D9=85=D9=8A=D8=A9
     =D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=82=D9=
=8A=D8=A7=D8=AF=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=82=D8=AF=D8=B1=D8=A9 =D8=
=B9=D9=84=D9=89 =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D9=81=D8=B1=D9=82 =D8=A7=D9=
=84=D8=B9=D9=85=D9=84 =D9=88=D8=AA=D8=AD=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=
=A3=D9=87=D8=AF=D8=A7=D9=81</span><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times =
New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LT=
R"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=AA=D8=B7=D8=A8=D9=8A=D9=82
     =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=
=84 =D8=A7=D9=84=D9=86=D9=81=D8=B3=D9=8A =D9=88=D8=A7=D9=84=D8=B3=D9=84=D9=
=88=D9=83=D9=8A =D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D8=A3=D8=
=AF=D8=A7=D8=A1 =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A</span><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt=
;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:20pt;font-family:&quot;Segoe UI Symbol&quot;,&quot;=
sans-serif&quot;">=F0=9F=91=A5</span></b><b><span dir=3D"LTR" style=3D"font=
-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"> </sp=
an></b><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=81=D8=A6=D8=A7=D8=AA
=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9</span></b><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font=
-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span=
 dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D9=85=D8=AF=D8=B1=D8=A8=D9=88=D9=86
     =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D9=8A=D9=88=D9=
=86 =D9=81=D9=8A =D9=85=D8=AC=D8=A7=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=
=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"fo=
nt-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D9=8A=D9=88=D9=86
     =D9=88=D8=A7=D9=84=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=D8=B1=D8=
=A7=D8=BA=D8=A8=D9=88=D9=86 =D9=81=D9=8A =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D9=
=83=D9=81=D8=A7=D8=A1=D8=A7=D8=AA=D9=87=D9=85 =D8=A7=D9=84=D8=B4=D8=AE=D8=
=B5=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9</span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"fo=
nt-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D9=85=D9=87=D8=AA=D9=85=D9=88=D9=86
     =D8=A8=D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D8=B0=D8=
=A7=D8=AA=D9=8A =D9=88=D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=81=D9=8A =D9=85=D8=
=AC=D8=A7=D9=84 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D8=A3=D9=88 =D8=
=A7=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF</span><span dir=3D"LTR"></span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;font-family:=
&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D9=84=D9=88=D9=86
     =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=
=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=
=D8=B1 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A</span><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;fo=
nt-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR">=
</span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=83=D8=A7=D9=81=D8=A9
     =D8=A7=D9=84=D8=B1=D8=A7=D8=BA=D8=A8=D9=8A=D9=86 =D9=81=D9=8A =D8=A5=
=D8=AD=D8=AF=D8=A7=D8=AB =D9=86=D9=82=D9=84=D8=A9 =D9=86=D9=88=D8=B9=D9=8A=
=D8=A9 =D9=81=D9=8A =D9=85=D8=B3=D8=A7=D8=B1=D9=87=D9=85 =D8=A7=D9=84=D8=B4=
=D8=AE=D8=B5=D9=8A =D8=A3=D9=88 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A</span>=
<span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=
=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot=
;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 0.5in 8pt 0in;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-ser=
if&quot;"><span style=3D"font-size:10pt;line-height:115%;font-family:Symbol=
">=C2=B7<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:au=
to;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-heig=
ht:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:20pt;line-height:115%;font-family:Arial,&quot;sans-serif&quot;">=D9=
=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=
=AA=D9=81=D8=B3=D8=A7=D8=B1</span></b><span dir=3D"LTR" style=3D"font-size:=
16pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;line-height:115%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-se=
rif&quot;"><span style=3D"font-size:10pt;line-height:115%;font-family:Symbo=
l">=C2=B7<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:a=
uto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-hei=
ght:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:20pt;line-height:115%;font-family:Arial,&quot;sans-serif&quot;">=D9=
=88=D8=A8=D9=87=D8=B0=D9=87 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=
=A9 =D9=8A=D8=B3=D8=B9=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=83=D9=
=85
=D9=84=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=B9=D9=85=
=D9=8A=D9=85 =D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=89 =D8=A7=
=D9=84=D9=85=D9=87=D8=AA=D9=85=D9=8A=D9=86 =D8=A8=D9=85=D9=80=D9=80=D9=88=
=D8=B6=D9=80=D9=88=D8=B9=C2=A0</span></b><b><span lang=3D"AR-EG" style=3D"f=
ont-size:20pt;line-height:115%;font-family:Arial,&quot;sans-serif&quot;">=
=D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A9
=D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9=C2=A0</span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;font-fam=
ily:Arial,&quot;sans-serif&quot;">=D9=88=D8=A5=D9=81=D8=A7=D8=AF=D8=AA=D9=
=86=D8=A7
=D8=A8=D9=85=D9=86 =D8=AA=D9=82=D8=AA=D8=B1=D8=AD=D9=88=D9=86 =D8=AA=D9=88=
=D8=AC=D9=8A=D9=87 =D8=A7=D9=84=D8=AF=D8=B9=D9=88=D8=A9 =D9=84=D9=87=D9=85<=
/span></b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:115%"></=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;line-height:115%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-se=
rif&quot;"><span style=3D"font-size:10pt;line-height:115%;font-family:Symbo=
l">=C2=B7<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:a=
uto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-hei=
ght:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:20pt;line-height:115%;font-family:Arial,&quot;sans-serif&quot;">=D9=
=84=D9=85=D8=B2=D9=8A=D8=AF =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D9=84=D9=
=88=D9=85=D8=A7=D8=AA =D9=8A=D9=85=D9=83=D9=86=D9=83 =D8=A7=D9=84=D8=AA=D9=
=88=D8=A7=D8=B5=D9=84 =D9=85=D8=B9
=D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=
=88=D8=A7=D8=AF =E2=80=93 =D9=86=D8=A7=D8=A6=D8=A8 =D9=85=D8=AF=D9=8A=D8=B1=
 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =E2=80=93 =D8=A7=D9=84=D8=AF=D8=
=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=
=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</spa=
n></b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:115%"></span=
></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;line-height:115%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-se=
rif&quot;"><span style=3D"font-size:10pt;line-height:115%;font-family:Symbo=
l">=C2=B7<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:a=
uto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-hei=
ght:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:20pt;line-height:115%;font-family:Arial,&quot;sans-serif&quot;">=D8=
=AC=D9=88=D8=A7=D9=84 =E2=80=93 =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=A8 :</sp=
an></b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:115%"></spa=
n></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 0.5in 8pt 0in;text-align:center;line-height:115%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-seri=
f&quot;"><span style=3D"font-size:10pt;line-height:115%;font-family:Symbol"=
>=C2=B7<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:aut=
o;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-heigh=
t:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:20pt;line-height:11=
5%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>00201069994399 -00201=
062992510 =E2=80=93 00201096841626</span></b><span dir=3D"LTR" style=3D"fon=
t-size:16pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><u><s=
pan lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Segoe UI&quot;=
,&quot;sans-serif&quot;;color:rgb(0,176,80)">=D8=A7=D9=84=D8=AF=D8=A7=D8=B1=
 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=
=D9=8A=D8=A9
=D8=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 - </span></u></b><b><u><sp=
an dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Segoe UI&quot;,&qu=
ot;sans-serif&quot;;color:rgb(0,176,80)">AHAD</span></u></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D9=85=D8=A7 =D9=87=D9=88 =D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=9F</span><span dir=3D"LTR" style=3D=
"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot;sans-serif&quot;;col=
or:rgb(40,40,40)"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=
=D8=AA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=87=D9=88
=D8=AF=D8=B1=D8=AC=D8=A9 =D8=AF=D8=B1=D8=A7=D8=B3=D8=A7=D8=AA =D8=B9=D9=84=
=D9=8A=D8=A7 =D8=AA=D8=B1=D9=83=D8=B2 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=AA=
=D8=B7=D8=A8=D9=8A=D9=82 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A =D9=88=D8=A7=
=D9=84=D9=86=D9=88=D8=A7=D8=AD=D9=8A =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=
=D8=A9=D8=8C =D9=88=D8=AA=D9=87=D8=AF=D9=81 =D8=A5=D9=84=D9=89 =D8=AA=D8=A3=
=D9=87=D9=8A=D9=84
=D8=A7=D9=84=D8=A3=D9=81=D8=B1=D8=A7=D8=AF =D9=84=D9=84=D8=B9=D9=85=D9=84 =
=D8=A8=D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D8=B9=D8=A7=D9=84=D9=8A=D8=A9 =D9=81=
=D9=8A =D8=AA=D8=AE=D8=B5=D8=B5=D8=A7=D8=AA=D9=87=D9=85. =D8=BA=D8=A7=D9=84=
=D8=A8=D9=8B=D8=A7 =D9=85=D8=A7 =D9=8A=D8=AA=D9=85 =D8=AA=D9=82=D8=AF=D9=8A=
=D9=85 =D9=87=D8=B0=D9=87 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D9=85=
=D9=86 =D9=82=D8=A8=D9=84
=D8=AC=D8=A7=D9=85=D8=B9=D8=A7=D8=AA =D9=85=D8=AD=D9=84=D9=8A=D8=A9 =D9=88=
=D8=AF=D9=88=D9=84=D9=8A=D8=A9 =D9=85=D8=B1=D9=85=D9=88=D9=82=D8=A9=D8=8C =
=D9=88=D8=AA=D8=B4=D9=85=D9=84 =D9=85=D8=B2=D9=8A=D8=AC=D9=8B=D8=A7 =D9=85=
=D9=86 =D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B6=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=
=D9=86=D8=B8=D8=B1=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=D9=84=D9=85=D8=B4=D8=A7=
=D8=B1=D9=8A=D8=B9
=D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=D9=84=D8=AA=
=D8=AF=D8=B1=D9=8A=D8=A8 =D8=A7=D9=84=D9=85=D9=8A=D8=AF=D8=A7=D9=86=D9=8A</=
span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" st=
yle=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot;sans-serif&quo=
t;;color:rgb(40,40,40)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.=
</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D9=88=D8=AA=D8=B1=D9=83=D8=B2 =D9=
=87=D8=B0=D9=87 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=B9=D9=84=D9=
=89
=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=
=D8=AA =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=
=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=D9=84=D8=AA=
=D8=AD=D9=84=D9=8A=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D9=8A =D9=8A=D8=AD=
=D8=AA=D8=A7=D8=AC=D9=87=D8=A7 =D8=A7=D9=84=D8=A3=D9=81=D8=B1=D8=A7=D8=AF =
=D9=84=D9=84=D9=86=D8=AC=D8=A7=D8=AD =D9=81=D9=8A
=D8=A8=D9=8A=D8=A6=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=
=D9=85=D8=AA=D8=BA=D9=8A=D8=B1=D8=A9</span><span dir=3D"LTR"></span><span d=
ir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:12pt;font-family:&qu=
ot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(40,40,40)"><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D9=81=D8=B1=D9=82 =D8=
=A8=D9=8A=D9=86 =D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=88=D8=A7=D9=84=D8=A3=D9=83=D8=A7=
=D8=AF=D9=8A=D9=85=D9=8A</span><span dir=3D"LTR" style=3D"font-size:12pt;fo=
nt-family:&quot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(40,40,40)">=
</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D9=87=D8=AF=D9=81: =D9=
=8A=D9=87=D8=AF=D9=81 =D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=
=B1
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D8=A5=D9=84=D9=89 =D8=AA=D9=86=D9=85=
=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=
=D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=
=D9=82=D9=8A=D8=A9=D8=8C =D8=A8=D9=8A=D9=86=D9=85=D8=A7 =D9=8A=D8=B1=D9=83=
=D8=B2 =D8=A7=D9=84=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=D9=85=D9=8A =D8=B9=D9=84=
=D9=89 =D8=A7=D9=84=D8=A8=D8=AD=D8=AB
=D8=A7=D9=84=D8=B9=D9=84=D9=85=D9=8A =D9=88=D8=A5=D9=86=D8=AA=D8=A7=D8=AC =
=D8=A7=D9=84=D9=85=D8=B9=D8=B1=D9=81=D8=A9</span><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:12pt;font-fami=
ly:&quot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(40,40,40)"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D8=AC=D9=85=D9=87=D9=88=
=D8=B1 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81:
=D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D9=85=D9=87=D9=86=
=D9=8A=D8=A9 =D8=AA=D9=8F=D8=B5=D9=85=D9=85 =D8=AE=D8=B5=D9=8A=D8=B5=D9=8B=
=D8=A7 =D9=84=D9=84=D9=85=D9=88=D8=B8=D9=81=D9=8A=D9=86 =D9=88=D8=A3=D8=B5=
=D8=AD=D8=A7=D8=A8 =D8=A7=D9=84=D8=AE=D8=A8=D8=B1=D8=A9 =D8=A7=D9=84=D8=B9=
=D9=85=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=B0=D9=8A=D9=86 =D9=8A=D8=B1=D8=BA=
=D8=A8=D9=88=D9=86 =D9=81=D9=8A
=D8=A7=D9=84=D8=AA=D8=B1=D9=82=D9=8A=D8=A9 =D8=A3=D9=88 =D8=A7=D9=84=D8=AA=
=D8=BA=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=8C =D8=B9=
=D9=84=D9=89 =D8=B9=D9=83=D8=B3 =D8=A7=D9=84=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=
=D9=85=D9=8A =D8=A7=D9=84=D8=B0=D9=8A =D9=8A=D9=8F=D9=86=D8=A7=D8=B3=D8=A8 =
=D8=A7=D9=84=D8=A8=D8=A7=D8=AD=D8=AB=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D9=85=
=D9=87=D8=AA=D9=85=D9=8A=D9=86
=D8=A8=D8=A7=D9=84=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A7=D9=87</span><span di=
r=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-s=
ize:12pt;font-family:&quot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(=
40,40,40)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D9=85=D8=AD=D8=AA=D9=88=
=D9=89: =D8=AA=D8=AA=D8=B6=D9=85=D9=86 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=
=D8=AC
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9 =D8=AF=D8=B1=D8=A7=D8=B3=D8=A7=
=D8=AA =D8=AD=D8=A7=D9=84=D8=A9=D8=8C =D9=88=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =
=D8=B9=D9=85=D9=84=D9=8A=D8=8C =D9=88=D9=85=D9=87=D8=A7=D9=85 =D9=85=D9=8A=
=D8=AF=D8=A7=D9=86=D9=8A=D8=A9=D8=8C =D8=A8=D9=8A=D9=86=D9=85=D8=A7 =D9=8A=
=D8=B9=D8=AA=D9=85=D8=AF =D8=A7=D9=84=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=D9=85=
=D9=8A =D8=B9=D9=84=D9=89
=D8=A7=D9=84=D8=A3=D8=B7=D8=B1 =D8=A7=D9=84=D9=86=D8=B8=D8=B1=D9=8A=D8=A9 =
=D9=88=D8=A7=D9=84=D8=A3=D8=A8=D8=AD=D8=A7=D8=AB</span><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:12pt;fon=
t-family:&quot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(40,40,40)"><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D9=85=D8=AE=D8=B1=D8=AC=
 =D8=A7=D9=84=D9=86=D9=87=D8=A7=D8=A6=D9=8A: =D9=81=D9=8A
=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=D9=84=D8=A3=
=D9=83=D8=A7=D8=AF=D9=8A=D9=85=D9=8A =D9=8A=D9=8F=D8=B7=D9=84=D8=A8 =D8=B9=
=D8=A7=D8=AF=D8=A9=D9=8B =D8=AA=D9=82=D8=AF=D9=8A=D9=85 =D8=B1=D8=B3=D8=A7=
=D9=84=D8=A9 =D8=B9=D9=84=D9=85=D9=8A=D8=A9=D8=8C =D8=A8=D9=8A=D9=86=D9=85=
=D8=A7 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=8A=D9=83=D9=88=
=D9=86 =D8=A7=D9=84=D9=85=D8=B4=D8=B1=D9=88=D8=B9
=D8=A7=D9=84=D9=86=D9=87=D8=A7=D8=A6=D9=8A =D8=B9=D9=85=D9=84=D9=8A=D9=91=
=D9=8B=D8=A7 =D9=8A=D9=8F=D8=B7=D8=A8=D9=82 =D9=81=D9=8A =D8=A8=D9=8A=D8=A6=
=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84</span><span dir=3D"LTR"></span><span =
dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:12pt;font-family:&q=
uot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(40,40,40)"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" =
style=3D"font-size:18pt;line-height:107%;font-family:&quot;Segoe UI&quot;,&=
quot;sans-serif&quot;;color:rgb(40,40,40);background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial"><br>
</span><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;fon=
t-family:Arial,&quot;sans-serif&quot;">=D8=AC=D8=AF=D9=88=D9=84 =D8=A8=D8=
=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=
=B1 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A</span></b><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;line-height:107%;font-family:Arial,&quot;sans-serif&qu=
ot;"> =D9=84=D9=83=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=D9=85=D8=AC=D8=A7=D9=84=
=D8=A7=D8=AA =D8=AE=D9=84=D8=A7=D9=84 =D8=A7=D9=84=D9=81=D8=AA=D8=B1=D8=A9 =
=D9=85=D9=86 </span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><s=
pan dir=3D"LTR" style=3D"font-size:16pt;line-height:107%"><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span>1 </span></b><b><span lang=3D"AR-EG" style=
=3D"font-size:16pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=B3=D8=A8=D9=85=D8=AA=D9=85=D8=A8=D8=B1</span></b><b><span lang=3D"AR=
-SA" style=3D"font-size:16pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;"> =D8=A5=D9=84=D9=89 31 =D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 20=
25</span></b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;=
font-family:Arial,&quot;sans-serif&quot;">=D8=8C =D8=A8=D8=AD=D9=8A=D8=AB =
=D9=8A=D8=AD=D8=AA=D9=88=D9=8A =D9=83=D9=84 =D8=A8=D8=B1=D9=86=D8=A7=D9=85=
=D8=AC =D8=B9=D9=84=D9=89 </span><span dir=3D"LTR"></span><span dir=3D"LTR"=
></span><b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:107%"><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span>80 </span></b><b><span lang=
=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=
=D9=8A=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span></b><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:16p=
t;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</sp=
an></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR">=
=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"A=
R-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans=
-serif&quot;">=D8=AC=D8=AF=D9=88=D9=84 =D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=
=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A | =D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 =E2=
=80=93 =D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 2025</span></b><b><span dir=3D"=
LTR" style=3D"font-size:14pt;line-height:107%"></span></b></p>

<table class=3D"gmail-MsoNormalTable" border=3D"0" cellpadding=3D"0" align=
=3D"left" style=3D"margin-left:6.75pt;margin-right:6.75pt">
 <thead>
  <tr>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D9=85</span></b><b><span dir=3D"LTR" style=3D"font-size=
:14pt;line-height:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D8=A7=D8=B3=D9=85 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=
=D9=85=D8=AC</span></b><b><span dir=3D"LTR" style=3D"font-size:14pt;line-he=
ight:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D8=A7=D9=84=D9=85=D8=AC=D8=A7=D9=84</span></b><b><span =
dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D8=A7=D9=84=D9=85=D8=AF=D8=A9 =D8=A7=D9=84=D8=B2=D9=85=
=D9=86=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:14pt;l=
ine-height:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE =D8=A7=D9=84=D8=A7=D9=86=
=D8=B9=D9=82=D8=A7=D8=AF</span></b><b><span dir=3D"LTR" style=3D"font-size:=
14pt;line-height:107%"></span></b></p>
   </td>
  </tr>
 </thead>
 <tbody><tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">2</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=88=D8=A7=
=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span><span dir=3D"=
LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=
=D8=B4=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">1 - 12 </span><span lang=3D"AR-=
SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">3</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=AD=D8=A7=
=D8=B3=D8=A8=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span><=
span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=
=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9</span><span dir=3D"LTR" style=3D"font-=
size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">15 - 26 </span><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">4</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=8A=D8=B9</span><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;lin=
e-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> PMP</span=
></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=
=D8=B1=D9=8A=D8=B9</span><span dir=3D"LTR" style=3D"font-size:14pt;line-hei=
ght:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">6 - 17 </span><span lang=3D"AR-=
SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=A3=D9=83=D8=AA=D9=88=D8=A8=D8=B1 2025</span><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">5</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=82=D9=8A=D8=A7=
=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D9=85=
=D8=A4=D8=B3=D8=B3=D9=8A</span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=
=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A</span><=
span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">20 - 31 </span><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A3=D9=83=D8=AA=D9=88=D8=A8=D8=B1 2025</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">6</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D8=AA=D8=BA=D9=8A=D9=8A=D8=B1 =D9=88=D9=82=D9=8A=D8=A7=D8=AF=
=D8=A9
  =D8=A7=D9=84=D8=A3=D8=B2=D9=85=D8=A7=D8=AA</span><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A7=
=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">3 - 14 </span><span lang=3D"AR-=
SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-s=
erif&quot;">=D9=86=D9=88=D9=81=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">7</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B3=D9=88=
=D9=8A=D9=82 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =D9=88=D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9
  =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=AC=
=D8=A7=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D9=82 =D9=88=D8=A7=D9=84=
=D8=A5=D8=B9=D9=84=D8=A7=D9=85</span><span dir=3D"LTR" style=3D"font-size:1=
4pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">17 - 28 </span><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D9=86=D9=88=D9=81=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">8</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=AD=D9=88=D9=83=
=D9=85=D8=A9</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:10=
7%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=AD=
=D9=88=D9=83=D9=85=D8=A9</span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">1 - 12 </span><span lang=3D"AR-=
SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">9</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D9=85=D8=B4=D8=AA=D8=B1=D9=8A=D8=A7=D8=AA =D9=88=D8=B3=D9=84=
=D8=A7=D8=B3=D9=84
  =D8=A7=D9=84=D8=A5=D9=85=D8=AF=D8=A7=D8=AF</span><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=B4=D8=AA=D8=B1=D9=8A=D8=A7=D8=AA =D9=88=
=D8=A7=D9=84=D9=84=D9=88=D8=AC=D8=B3=D8=AA=D9=8A=D8=A7=D8=AA</span><span di=
r=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">15 - 26 </span><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">10</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9 =D8=A7=D9=84=D8=B5=D8=AD=D9=8A=D8=A9</span><span dir=3D"LTR" s=
tyle=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D8=B5=D8=AD=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=B3=
=D8=AA=D8=B4=D9=81=D9=8A=D8=A7=D8=AA</span><span dir=3D"LTR" style=3D"font-=
size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">22 - 31 </span><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
</tbody></table>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%"><br clear=3D"all">
</span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:107%;font-family:&quot;Segoe UI Symb=
ol&quot;,&quot;sans-serif&quot;">=F0=9F=93=9D</span></b><b><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%"> </span></b><b><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D9=85=D9=84=D8=A7=D8=AD=D8=B8=D8=A7=D8=AA =D9=85=D9=87=D9=85=
=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span=
 dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span>:</span></b><span dir=3D"LTR" style=3D"font-s=
ize:14pt;line-height:107%"></span></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=AC=D9=85=D9=8A=D8=B9 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=
=AA=D9=85=D9=86=D8=AD =D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D9=88=D8=AB=D9=
=82=D8=A9 =D9=88=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =D9=88=D9=82=D8=A7=D8=
=A8=D9=84=D8=A9 =D9=84=D9=84=D8=AA=D8=B5=D8=AF=D9=8A=D9=82 =D9=85=D9=86
     =D8=A7=D9=84=D8=AE=D8=A7=D8=B1=D8=AC=D9=8A=D8=A9</span><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14p=
t;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</sp=
an></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D9=84=D8=BA=D8=A9: =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=
=A9 (=D9=85=D8=B9 =D8=AA=D9=88=D9=81=D8=B1 =D9=85=D8=AA=D8=B1=D8=AC=D9=85 =
=D8=B9=D9=86=D8=AF =D8=A7=D9=84=D8=AD=D8=A7=D8=AC=D8=A9 =D9=84=D9=84=D8=A8=
=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9)</span>=
<span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D9=81=D8=A6=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=
=AF=D9=81=D8=A9: =D8=A7=D9=84=D9=85=D8=AF=D9=8A=D8=B1=D9=88=D9=86 =D8=A7=D9=
=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A=D9=88=D9=86=D8=8C =D9=85=D8=B3=D8=
=A4=D9=88=D9=84=D9=88 =D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1=D8=8C =D9=
=85=D8=B3=D8=A4=D9=88=D9=84=D9=88
     =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9=D8=8C =D9=82=D8=A7=D8=AF=D8=A9 =
=D8=A7=D9=84=D9=81=D8=B1=D9=82=D8=8C =D8=B1=D8=A4=D8=B3=D8=A7=D8=A1 =D8=A7=
=D9=84=D8=A3=D9=82=D8=B3=D8=A7=D9=85=D8=8C =D9=88=D8=B0=D9=88=D9=88 =D8=A7=
=D9=84=D8=B7=D9=85=D9=88=D8=AD=D8=A7=D8=AA =D8=A7=D9=84=D9=82=D9=8A=D8=A7=
=D8=AF=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D9=8A=D9=85=D9=83=D9=86 =D8=AA=D9=86=D9=81=D9=8A=D8=B0 =D8=A7=D9=84=D8=
=A8=D8=B1=D8=A7=D9=85=D8=AC <b>=D8=A3=D9=88=D9=86=D9=84=D8=A7=D9=8A=D9=86 =
=D8=B9=D8=A8=D8=B1</b></span><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan><b><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"><span di=
r=3D"LTR"></span><span dir=3D"LTR"></span> Zoom</span></b><span dir=3D"LTR"=
 style=3D"font-size:14pt;line-height:107%"> </span><span lang=3D"AR-SA" sty=
le=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif&qu=
ot;">=D8=A3=D9=88 <b>=D8=AD=D8=B6=D9=88=D8=B1=D9=8A</b> =D8=AD=D8=B3=D8=A8 =
=D8=B1=D8=BA=D8=A8=D8=A9 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=
=D9=86</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:14pt;line-height:107%"><span dir=3D"LTR"></span><s=
pan dir=3D"LTR"></span>.</span></li>
</ul>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initial=
;background-position:initial;background-size:initial;background-repeat:init=
ial;background-origin:initial;background-clip:initial;direction:rtl;unicode=
-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,&quot;sans-=
serif&quot;"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span =
style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featur=
e-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;font=
-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,&quot;sans-serif&quot;;color:red">=D9=84=D9=
=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=
=81=D8=B3=D8=A7=D8=B1</span></b><span lang=3D"AR-SA"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initia=
l;background-position:initial;background-size:initial;background-repeat:ini=
tial;background-origin:initial;background-clip:initial;direction:rtl;unicod=
e-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,&quot;sans=
-serif&quot;"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,&quot;sans-serif&quot;">=D9=88=D8=A8=D9=87=D8=
=B0=D9=87 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=A9 =D9=8A=D8=B3=D8=
=B9=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=83=D9=85 =D9=84=D9=84=D9=
=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=B9=D9=85=D9=8A=D9=85
=D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=
=D9=87=D8=AA=D9=85=D9=8A=D9=86 =D8=A8=D9=85=D9=80=D9=80=D9=88=D8=B6=D9=80=
=D9=88=D8=B9=C2=A0</span></b><b><span lang=3D"AR-EG" style=3D"font-size:16p=
t;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=B4=D9=87=D8=A7=
=D8=AF=D8=A9
=D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9=C2=A0</span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,&quot;s=
ans-serif&quot;">=D9=88=D8=A5=D9=81=D8=A7=D8=AF=D8=AA=D9=86=D8=A7 =D8=A8=D9=
=85=D9=86 =D8=AA=D9=82=D8=AA=D8=B1=D8=AD=D9=88=D9=86 =D8=AA=D9=88=D8=AC=D9=
=8A=D9=87 =D8=A7=D9=84=D8=AF=D8=B9=D9=88=D8=A9 =D9=84=D9=87=D9=85</span></b=
><span lang=3D"AR-SA"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initia=
l;background-position:initial;background-size:initial;background-repeat:ini=
tial;background-origin:initial;background-clip:initial;direction:rtl;unicod=
e-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,&quot;sans=
-serif&quot;"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,&quot;sans-serif&quot;">=D9=84=D9=85=D8=B2=D9=
=8A=D8=AF =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=
=AA =D9=8A=D9=85=D9=83=D9=86=D9=83 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=
=84 =D9=85=D8=B9 =D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9
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
e-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,&quot;sans=
-serif&quot;"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,&quot;sans-serif&quot;">=D8=AC=D9=88=D8=A7=D9=
=84 =E2=80=93 =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=A8 :</span></b><span lang=
=3D"AR-SA"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initial;=
background-position:initial;background-size:initial;background-repeat:initi=
al;background-origin:initial;background-clip:initial;direction:rtl;unicode-=
bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,&quot;sans-s=
erif&quot;"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span s=
tyle=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-feature=
-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:16pt"><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span>00201069994399
-00201062992510 - 00201096841626</span></b><span lang=3D"AR-SA"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;"><span style=3D"font-size:16pt;font-family:Calibri,&quot;sans-s=
erif&quot;">=C2=A0</span>=C2=A0=D8=A8=D9=8F=D8=B9=D8=AF =D8=B9=D8=A8=D8=B1<=
/span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" s=
tyle=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&=
quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>
Zoom (</span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot=
;Times New Roman&quot;,&quot;serif&quot;">=D9=81=D9=8A =D8=AD=D8=A7=D9=84 =
=D8=AA=D8=B9=D8=B0=D8=B1 =D8=A7=D9=84=D8=AD=D8=B6=D9=88=D8=B1</span><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-=
size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span>)<br>
</span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;">=D9=85=D9=82=D8=AF=D9=85 =D9=85=D9=86</=
span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" st=
yle=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&q=
uot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:
</span><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=
=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=
=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></b><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"f=
ont-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span> =E2=80=93 AHAD</span></b><=
span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&=
quot;,&quot;serif&quot;"><br>
</span><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=
=D9=87=D9=86=D9=8A=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9=D8=8C =D9=82=
=D8=A7=D8=A8=D9=84=D8=A9 =D9=84=D9=84=D8=AA=D9=88=D8=AB=D9=8A=D9=82 =D9=85=
=D9=86
=D9=88=D8=B2=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AE=D8=A7=D8=B1=D8=AC=D9=8A=
=D8=A9 =D9=88=D9=83=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=D8=B3=D9=81=D8=A7=D8=B1=
=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9</span><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:2=
0pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=85=D9=82=D8=AF=D9=85=D8=A9</span></b><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"f=
ont-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=D9=8A=D9=87=D8=AF=D9=81 =D9=87=D8=B0=D8=A7 =D8=A7=D9=84=D8=A8=
=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5 =
=D8=A5=D9=84=D9=89 =D8=AA=D8=A3=D9=87=D9=8A=D9=84
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D8=A8=D8=A7=D9=84=
=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=
=D8=A7=D9=81=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=A3=D8=AF=D9=88=D8=A7=D8=AA =
=D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=84=D8=AA=D8=B7=D9=88=D9=8A=
=D8=B1 =D8=A7=D9=84=D8=B0=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=A2=D8=AE=D8=B1=
=D9=8A=D9=86=D8=8C =D9=88=D8=AA=D8=AD=D9=82=D9=8A=D9=82
=D8=A7=D9=84=D8=AA=D9=85=D9=8A=D8=B2 =D9=81=D9=8A =D8=A7=D9=84=D8=A3=D8=AF=
=D8=A7=D8=A1 =D8=A7=D9=84=D8=B4=D8=AE=D8=B5=D9=8A =D9=88=D8=A7=D9=84=D9=85=
=D9=87=D9=86=D9=8A=D8=8C =D8=A8=D8=A7=D9=84=D8=A7=D8=B9=D8=AA=D9=85=D8=A7=
=D8=AF =D8=B9=D9=84=D9=89 =D8=A3=D8=AD=D8=AF=D8=AB =D8=A3=D8=B3=D8=A7=D9=84=
=D9=8A=D8=A8 =D8=B9=D9=84=D9=85 =D8=A7=D9=84=D9=86=D9=81=D8=B3 =D8=A7=D9=84=
=D8=A5=D9=8A=D8=AC=D8=A7=D8=A8=D9=8A=D8=8C
=D9=88=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D8=8C =D9=88=D8=A7=D9=84=
=D8=AA=D8=AD=D9=81=D9=8A=D8=B2=D8=8C =D9=88=D8=A7=D9=84=D9=82=D9=8A=D8=A7=
=D8=AF=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;=
,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</sp=
an></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D8=A3=D9=87=D8=AF=D8=A7=D9=81</span></b><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"f=
ont-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=81=D9=87=D9=85
     =D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA =D9=88=D9=85=D9=81=D8=A7=D9=
=87=D9=8A=D9=85 =D8=A7=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=
=A8=D8=B4=D8=B1=D9=8A=D8=A9 =D9=88=D8=A3=D8=AB=D8=B1=D9=87=D8=A7 =D9=81=D9=
=8A =D8=A8=D9=8A=D8=A6=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=88=D8=A7=D9=
=84=D8=AD=D9=8A=D8=A7=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times =
New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LT=
R"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=83=D8=AA=D8=B3=D8=A7=D8=A8
     =D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =
=D8=A7=D9=84=D8=B0=D8=A7=D8=AA=D8=8C =D9=88=D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =
=D8=A7=D9=84=D8=A5=D9=86=D8=AA=D8=A7=D8=AC=D9=8A=D8=A9=D8=8C =D9=88=D8=A8=
=D9=86=D8=A7=D8=A1 =D8=A7=D9=84=D8=AB=D9=82=D8=A9 =D8=A8=D8=A7=D9=84=D9=86=
=D9=81=D8=B3</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span =
dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;=
,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</sp=
an></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D8=AA=D8=B9=D8=B1=D9=81
     =D8=B9=D9=84=D9=89 =D9=85=D9=86=D9=87=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=
=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D9=88=D8=A7=D9=84=D8=AA=D8=A3=D8=AB=
=D9=8A=D8=B1 =D8=A7=D9=84=D8=A5=D9=8A=D8=AC=D8=A7=D8=A8=D9=8A =D9=81=D9=8A =
=D8=A7=D9=84=D8=A2=D8=AE=D8=B1=D9=8A=D9=86</span><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span>=
<span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=AA=D9=86=D9=85=D9=8A=D8=A9
     =D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=82=D9=
=8A=D8=A7=D8=AF=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=82=D8=AF=D8=B1=D8=A9 =D8=
=B9=D9=84=D9=89 =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D9=81=D8=B1=D9=82 =D8=A7=D9=
=84=D8=B9=D9=85=D9=84 =D9=88=D8=AA=D8=AD=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=
=A3=D9=87=D8=AF=D8=A7=D9=81</span><span dir=3D"LTR"></span><span dir=3D"LTR=
"></span><span dir=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times =
New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LT=
R"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=AA=D8=B7=D8=A8=D9=8A=D9=82
     =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=
=84 =D8=A7=D9=84=D9=86=D9=81=D8=B3=D9=8A =D9=88=D8=A7=D9=84=D8=B3=D9=84=D9=
=88=D9=83=D9=8A =D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D8=A3=D8=
=AF=D8=A7=D8=A1 =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A</span><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt=
;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:20pt;font-family:&quot;Segoe UI Symbol&quot;,&quot;=
sans-serif&quot;">=F0=9F=91=A5</span></b><b><span dir=3D"LTR" style=3D"font=
-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"> </sp=
an></b><b><span lang=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;Ti=
mes New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=81=D8=A6=D8=A7=D8=AA
=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9</span></b><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font=
-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span=
 dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D9=85=D8=AF=D8=B1=D8=A8=D9=88=D9=86
     =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D9=8A=D9=88=D9=
=86 =D9=81=D9=8A =D9=85=D8=AC=D8=A7=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=
=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"fo=
nt-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D9=8A=D9=88=D9=86
     =D9=88=D8=A7=D9=84=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=D8=B1=D8=
=A7=D8=BA=D8=A8=D9=88=D9=86 =D9=81=D9=8A =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D9=
=83=D9=81=D8=A7=D8=A1=D8=A7=D8=AA=D9=87=D9=85 =D8=A7=D9=84=D8=B4=D8=AE=D8=
=B5=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9</span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"fo=
nt-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D9=85=D9=87=D8=AA=D9=85=D9=88=D9=86
     =D8=A8=D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D8=B0=D8=
=A7=D8=AA=D9=8A =D9=88=D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=81=D9=8A =D9=85=D8=
=AC=D8=A7=D9=84 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D8=A3=D9=88 =D8=
=A7=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF</span><span dir=3D"LTR"></span><spa=
n dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;font-family:=
&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR"></span><sp=
an dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D9=84=D9=88=D9=86
     =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=
=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=
=D8=B1 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A</span><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:20pt;fo=
nt-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"LTR">=
</span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=83=D8=A7=D9=81=D8=A9
     =D8=A7=D9=84=D8=B1=D8=A7=D8=BA=D8=A8=D9=8A=D9=86 =D9=81=D9=8A =D8=A5=
=D8=AD=D8=AF=D8=A7=D8=AB =D9=86=D9=82=D9=84=D8=A9 =D9=86=D9=88=D8=B9=D9=8A=
=D8=A9 =D9=81=D9=8A =D9=85=D8=B3=D8=A7=D8=B1=D9=87=D9=85 =D8=A7=D9=84=D8=B4=
=D8=AE=D8=B5=D9=8A =D8=A3=D9=88 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A</span>=
<span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=
=3D"font-size:20pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot=
;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></li>
</ul>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 0.5in 8pt 0in;text-align:center;line-height:115%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-ser=
if&quot;"><span style=3D"font-size:10pt;line-height:115%;font-family:Symbol=
">=C2=B7<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:au=
to;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-heig=
ht:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:20pt;line-height:115%;font-family:Arial,&quot;sans-serif&quot;">=D9=
=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=
=AA=D9=81=D8=B3=D8=A7=D8=B1</span></b><span dir=3D"LTR" style=3D"font-size:=
16pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;line-height:115%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-se=
rif&quot;"><span style=3D"font-size:10pt;line-height:115%;font-family:Symbo=
l">=C2=B7<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:a=
uto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-hei=
ght:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:20pt;line-height:115%;font-family:Arial,&quot;sans-serif&quot;">=D9=
=88=D8=A8=D9=87=D8=B0=D9=87 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=
=A9 =D9=8A=D8=B3=D8=B9=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=83=D9=
=85
=D9=84=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=B9=D9=85=
=D9=8A=D9=85 =D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=89 =D8=A7=
=D9=84=D9=85=D9=87=D8=AA=D9=85=D9=8A=D9=86 =D8=A8=D9=85=D9=80=D9=80=D9=88=
=D8=B6=D9=80=D9=88=D8=B9=C2=A0</span></b><b><span lang=3D"AR-EG" style=3D"f=
ont-size:20pt;line-height:115%;font-family:Arial,&quot;sans-serif&quot;">=
=D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A9
=D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9=C2=A0</span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;font-fam=
ily:Arial,&quot;sans-serif&quot;">=D9=88=D8=A5=D9=81=D8=A7=D8=AF=D8=AA=D9=
=86=D8=A7
=D8=A8=D9=85=D9=86 =D8=AA=D9=82=D8=AA=D8=B1=D8=AD=D9=88=D9=86 =D8=AA=D9=88=
=D8=AC=D9=8A=D9=87 =D8=A7=D9=84=D8=AF=D8=B9=D9=88=D8=A9 =D9=84=D9=87=D9=85<=
/span></b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:115%"></=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;line-height:115%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-se=
rif&quot;"><span style=3D"font-size:10pt;line-height:115%;font-family:Symbo=
l">=C2=B7<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:a=
uto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-hei=
ght:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:20pt;line-height:115%;font-family:Arial,&quot;sans-serif&quot;">=D9=
=84=D9=85=D8=B2=D9=8A=D8=AF =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D9=84=D9=
=88=D9=85=D8=A7=D8=AA =D9=8A=D9=85=D9=83=D9=86=D9=83 =D8=A7=D9=84=D8=AA=D9=
=88=D8=A7=D8=B5=D9=84 =D9=85=D8=B9
=D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=
=88=D8=A7=D8=AF =E2=80=93 =D9=86=D8=A7=D8=A6=D8=A8 =D9=85=D8=AF=D9=8A=D8=B1=
 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =E2=80=93 =D8=A7=D9=84=D8=AF=D8=
=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=
=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</spa=
n></b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:115%"></span=
></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;line-height:115%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-se=
rif&quot;"><span style=3D"font-size:10pt;line-height:115%;font-family:Symbo=
l">=C2=B7<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:a=
uto;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-hei=
ght:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:20pt;line-height:115%;font-family:Arial,&quot;sans-serif&quot;">=D8=
=AC=D9=88=D8=A7=D9=84 =E2=80=93 =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=A8 :</sp=
an></b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:115%"></spa=
n></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 0.5in 8pt 0in;text-align:center;line-height:115%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-seri=
f&quot;"><span style=3D"font-size:10pt;line-height:115%;font-family:Symbol"=
>=C2=B7<span style=3D"font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:aut=
o;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-heigh=
t:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:20pt;line-height:11=
5%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>00201069994399 -00201=
062992510 =E2=80=93 00201096841626</span></b><span dir=3D"LTR" style=3D"fon=
t-size:16pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><u><s=
pan lang=3D"AR-SA" style=3D"font-size:22pt;font-family:&quot;Segoe UI&quot;=
,&quot;sans-serif&quot;;color:rgb(0,176,80)">=D8=A7=D9=84=D8=AF=D8=A7=D8=B1=
 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=
=D9=8A=D8=A9
=D8=A7=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 - </span></u></b><b><u><sp=
an dir=3D"LTR" style=3D"font-size:22pt;font-family:&quot;Segoe UI&quot;,&qu=
ot;sans-serif&quot;;color:rgb(0,176,80)">AHAD</span></u></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D9=85=D8=A7 =D9=87=D9=88 =D8=A7=D9=
=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=9F</span><span dir=3D"LTR" style=3D=
"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot;sans-serif&quot;;col=
or:rgb(40,40,40)"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=
=D8=AA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=87=D9=88
=D8=AF=D8=B1=D8=AC=D8=A9 =D8=AF=D8=B1=D8=A7=D8=B3=D8=A7=D8=AA =D8=B9=D9=84=
=D9=8A=D8=A7 =D8=AA=D8=B1=D9=83=D8=B2 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=AA=
=D8=B7=D8=A8=D9=8A=D9=82 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A =D9=88=D8=A7=
=D9=84=D9=86=D9=88=D8=A7=D8=AD=D9=8A =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=
=D8=A9=D8=8C =D9=88=D8=AA=D9=87=D8=AF=D9=81 =D8=A5=D9=84=D9=89 =D8=AA=D8=A3=
=D9=87=D9=8A=D9=84
=D8=A7=D9=84=D8=A3=D9=81=D8=B1=D8=A7=D8=AF =D9=84=D9=84=D8=B9=D9=85=D9=84 =
=D8=A8=D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D8=B9=D8=A7=D9=84=D9=8A=D8=A9 =D9=81=
=D9=8A =D8=AA=D8=AE=D8=B5=D8=B5=D8=A7=D8=AA=D9=87=D9=85. =D8=BA=D8=A7=D9=84=
=D8=A8=D9=8B=D8=A7 =D9=85=D8=A7 =D9=8A=D8=AA=D9=85 =D8=AA=D9=82=D8=AF=D9=8A=
=D9=85 =D9=87=D8=B0=D9=87 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D9=85=
=D9=86 =D9=82=D8=A8=D9=84
=D8=AC=D8=A7=D9=85=D8=B9=D8=A7=D8=AA =D9=85=D8=AD=D9=84=D9=8A=D8=A9 =D9=88=
=D8=AF=D9=88=D9=84=D9=8A=D8=A9 =D9=85=D8=B1=D9=85=D9=88=D9=82=D8=A9=D8=8C =
=D9=88=D8=AA=D8=B4=D9=85=D9=84 =D9=85=D8=B2=D9=8A=D8=AC=D9=8B=D8=A7 =D9=85=
=D9=86 =D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B6=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=
=D9=86=D8=B8=D8=B1=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=D9=84=D9=85=D8=B4=D8=A7=
=D8=B1=D9=8A=D8=B9
=D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=D9=84=D8=AA=
=D8=AF=D8=B1=D9=8A=D8=A8 =D8=A7=D9=84=D9=85=D9=8A=D8=AF=D8=A7=D9=86=D9=8A</=
span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" st=
yle=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot;sans-serif&quo=
t;;color:rgb(40,40,40)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.=
</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D9=88=D8=AA=D8=B1=D9=83=D8=B2 =D9=
=87=D8=B0=D9=87 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=B9=D9=84=D9=
=89
=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=
=D8=AA =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=
=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=D9=84=D8=AA=
=D8=AD=D9=84=D9=8A=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D9=8A =D9=8A=D8=AD=
=D8=AA=D8=A7=D8=AC=D9=87=D8=A7 =D8=A7=D9=84=D8=A3=D9=81=D8=B1=D8=A7=D8=AF =
=D9=84=D9=84=D9=86=D8=AC=D8=A7=D8=AD =D9=81=D9=8A
=D8=A8=D9=8A=D8=A6=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=
=D9=85=D8=AA=D8=BA=D9=8A=D8=B1=D8=A9</span><span dir=3D"LTR"></span><span d=
ir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:12pt;font-family:&qu=
ot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(40,40,40)"><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D9=81=D8=B1=D9=82 =D8=
=A8=D9=8A=D9=86 =D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=88=D8=A7=D9=84=D8=A3=D9=83=D8=A7=
=D8=AF=D9=8A=D9=85=D9=8A</span><span dir=3D"LTR" style=3D"font-size:12pt;fo=
nt-family:&quot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(40,40,40)">=
</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D9=87=D8=AF=D9=81: =D9=
=8A=D9=87=D8=AF=D9=81 =D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=
=B1
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D8=A5=D9=84=D9=89 =D8=AA=D9=86=D9=85=
=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=
=D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=
=D9=82=D9=8A=D8=A9=D8=8C =D8=A8=D9=8A=D9=86=D9=85=D8=A7 =D9=8A=D8=B1=D9=83=
=D8=B2 =D8=A7=D9=84=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=D9=85=D9=8A =D8=B9=D9=84=
=D9=89 =D8=A7=D9=84=D8=A8=D8=AD=D8=AB
=D8=A7=D9=84=D8=B9=D9=84=D9=85=D9=8A =D9=88=D8=A5=D9=86=D8=AA=D8=A7=D8=AC =
=D8=A7=D9=84=D9=85=D8=B9=D8=B1=D9=81=D8=A9</span><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:12pt;font-fami=
ly:&quot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(40,40,40)"><span d=
ir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D8=AC=D9=85=D9=87=D9=88=
=D8=B1 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81:
=D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D9=85=D9=87=D9=86=
=D9=8A=D8=A9 =D8=AA=D9=8F=D8=B5=D9=85=D9=85 =D8=AE=D8=B5=D9=8A=D8=B5=D9=8B=
=D8=A7 =D9=84=D9=84=D9=85=D9=88=D8=B8=D9=81=D9=8A=D9=86 =D9=88=D8=A3=D8=B5=
=D8=AD=D8=A7=D8=A8 =D8=A7=D9=84=D8=AE=D8=A8=D8=B1=D8=A9 =D8=A7=D9=84=D8=B9=
=D9=85=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=B0=D9=8A=D9=86 =D9=8A=D8=B1=D8=BA=
=D8=A8=D9=88=D9=86 =D9=81=D9=8A
=D8=A7=D9=84=D8=AA=D8=B1=D9=82=D9=8A=D8=A9 =D8=A3=D9=88 =D8=A7=D9=84=D8=AA=
=D8=BA=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=8C =D8=B9=
=D9=84=D9=89 =D8=B9=D9=83=D8=B3 =D8=A7=D9=84=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=
=D9=85=D9=8A =D8=A7=D9=84=D8=B0=D9=8A =D9=8A=D9=8F=D9=86=D8=A7=D8=B3=D8=A8 =
=D8=A7=D9=84=D8=A8=D8=A7=D8=AD=D8=AB=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D9=85=
=D9=87=D8=AA=D9=85=D9=8A=D9=86
=D8=A8=D8=A7=D9=84=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A7=D9=87</span><span di=
r=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-s=
ize:12pt;font-family:&quot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(=
40,40,40)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D9=85=D8=AD=D8=AA=D9=88=
=D9=89: =D8=AA=D8=AA=D8=B6=D9=85=D9=86 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=
=D8=AC
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9 =D8=AF=D8=B1=D8=A7=D8=B3=D8=A7=
=D8=AA =D8=AD=D8=A7=D9=84=D8=A9=D8=8C =D9=88=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =
=D8=B9=D9=85=D9=84=D9=8A=D8=8C =D9=88=D9=85=D9=87=D8=A7=D9=85 =D9=85=D9=8A=
=D8=AF=D8=A7=D9=86=D9=8A=D8=A9=D8=8C =D8=A8=D9=8A=D9=86=D9=85=D8=A7 =D9=8A=
=D8=B9=D8=AA=D9=85=D8=AF =D8=A7=D9=84=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=D9=85=
=D9=8A =D8=B9=D9=84=D9=89
=D8=A7=D9=84=D8=A3=D8=B7=D8=B1 =D8=A7=D9=84=D9=86=D8=B8=D8=B1=D9=8A=D8=A9 =
=D9=88=D8=A7=D9=84=D8=A3=D8=A8=D8=AD=D8=A7=D8=AB</span><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:12pt;fon=
t-family:&quot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(40,40,40)"><=
span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:9pt 0in=
 0.0001pt;text-align:center;line-height:normal;background-image:initial;bac=
kground-position:initial;background-size:initial;background-repeat:initial;=
background-origin:initial;background-clip:initial;direction:rtl;unicode-bid=
i:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span la=
ng=3D"AR-SA" style=3D"font-size:12pt;font-family:&quot;Segoe UI&quot;,&quot=
;sans-serif&quot;;color:rgb(40,40,40)">=D8=A7=D9=84=D9=85=D8=AE=D8=B1=D8=AC=
 =D8=A7=D9=84=D9=86=D9=87=D8=A7=D8=A6=D9=8A: =D9=81=D9=8A
=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=D9=84=D8=A3=
=D9=83=D8=A7=D8=AF=D9=8A=D9=85=D9=8A =D9=8A=D9=8F=D8=B7=D9=84=D8=A8 =D8=B9=
=D8=A7=D8=AF=D8=A9=D9=8B =D8=AA=D9=82=D8=AF=D9=8A=D9=85 =D8=B1=D8=B3=D8=A7=
=D9=84=D8=A9 =D8=B9=D9=84=D9=85=D9=8A=D8=A9=D8=8C =D8=A8=D9=8A=D9=86=D9=85=
=D8=A7 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=8A=D9=83=D9=88=
=D9=86 =D8=A7=D9=84=D9=85=D8=B4=D8=B1=D9=88=D8=B9
=D8=A7=D9=84=D9=86=D9=87=D8=A7=D8=A6=D9=8A =D8=B9=D9=85=D9=84=D9=8A=D9=91=
=D9=8B=D8=A7 =D9=8A=D9=8F=D8=B7=D8=A8=D9=82 =D9=81=D9=8A =D8=A8=D9=8A=D8=A6=
=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84</span><span dir=3D"LTR"></span><span =
dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:12pt;font-family:&q=
uot;Segoe UI&quot;,&quot;sans-serif&quot;;color:rgb(40,40,40)"><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span>.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" =
style=3D"font-size:18pt;line-height:107%;font-family:&quot;Segoe UI&quot;,&=
quot;sans-serif&quot;;color:rgb(40,40,40);background-image:initial;backgrou=
nd-position:initial;background-size:initial;background-repeat:initial;backg=
round-origin:initial;background-clip:initial"><br>
</span><b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;fon=
t-family:Arial,&quot;sans-serif&quot;">=D8=AC=D8=AF=D9=88=D9=84 =D8=A8=D8=
=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=
=B1 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A</span></b><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;line-height:107%;font-family:Arial,&quot;sans-serif&qu=
ot;"> =D9=84=D9=83=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=D9=85=D8=AC=D8=A7=D9=84=
=D8=A7=D8=AA =D8=AE=D9=84=D8=A7=D9=84 =D8=A7=D9=84=D9=81=D8=AA=D8=B1=D8=A9 =
=D9=85=D9=86 </span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><s=
pan dir=3D"LTR" style=3D"font-size:16pt;line-height:107%"><span dir=3D"LTR"=
></span><span dir=3D"LTR"></span>1 </span></b><b><span lang=3D"AR-EG" style=
=3D"font-size:16pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=B3=D8=A8=D9=85=D8=AA=D9=85=D8=A8=D8=B1</span></b><b><span lang=3D"AR=
-SA" style=3D"font-size:16pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;"> =D8=A5=D9=84=D9=89 31 =D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 20=
25</span></b><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;=
font-family:Arial,&quot;sans-serif&quot;">=D8=8C =D8=A8=D8=AD=D9=8A=D8=AB =
=D9=8A=D8=AD=D8=AA=D9=88=D9=8A =D9=83=D9=84 =D8=A8=D8=B1=D9=86=D8=A7=D9=85=
=D8=AC =D8=B9=D9=84=D9=89 </span><span dir=3D"LTR"></span><span dir=3D"LTR"=
></span><b><span dir=3D"LTR" style=3D"font-size:16pt;line-height:107%"><spa=
n dir=3D"LTR"></span><span dir=3D"LTR"></span>80 </span></b><b><span lang=
=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=
=D9=8A=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span></b><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:16p=
t;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</sp=
an></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR">=
=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D"A=
R-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans=
-serif&quot;">=D8=AC=D8=AF=D9=88=D9=84 =D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=
=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A | =D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 =E2=
=80=93 =D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 2025</span></b><b><span dir=3D"=
LTR" style=3D"font-size:14pt;line-height:107%"></span></b></p>

<table class=3D"gmail-MsoNormalTable" border=3D"0" cellpadding=3D"0" align=
=3D"left" style=3D"margin-left:6.75pt;margin-right:6.75pt">
 <thead>
  <tr>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D9=85</span></b><b><span dir=3D"LTR" style=3D"font-size=
:14pt;line-height:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D8=A7=D8=B3=D9=85 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=
=D9=85=D8=AC</span></b><b><span dir=3D"LTR" style=3D"font-size:14pt;line-he=
ight:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D8=A7=D9=84=D9=85=D8=AC=D8=A7=D9=84</span></b><b><span =
dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D8=A7=D9=84=D9=85=D8=AF=D8=A9 =D8=A7=D9=84=D8=B2=D9=85=
=D9=86=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:14pt;l=
ine-height:107%"></span></b></p>
   </td>
   <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
   <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:=
center;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%=
;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot=
;sans-serif&quot;">=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE =D8=A7=D9=84=D8=A7=D9=86=
=D8=B9=D9=82=D8=A7=D8=AF</span></b><b><span dir=3D"LTR" style=3D"font-size:=
14pt;line-height:107%"></span></b></p>
   </td>
  </tr>
 </thead>
 <tbody><tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">2</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=88=D8=A7=
=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</span><span dir=3D"=
LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=
=D8=B4=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">1 - 12 </span><span lang=3D"AR-=
SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">3</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=AD=D8=A7=
=D8=B3=D8=A8=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9</span><=
span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=
=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D8=A9</span><span dir=3D"LTR" style=3D"font-=
size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">15 - 26 </span><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=B3=D8=A8=D8=AA=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">4</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=8A=D8=B9</span><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14pt;lin=
e-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span> PMP</span=
></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=
=D8=B1=D9=8A=D8=B9</span><span dir=3D"LTR" style=3D"font-size:14pt;line-hei=
ght:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">6 - 17 </span><span lang=3D"AR-=
SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=A3=D9=83=D8=AA=D9=88=D8=A8=D8=B1 2025</span><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">5</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D9=82=D9=8A=D8=A7=
=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D9=85=
=D8=A4=D8=B3=D8=B3=D9=8A</span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=
=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A</span><=
span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">20 - 31 </span><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A3=D9=83=D8=AA=D9=88=D8=A8=D8=B1 2025</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">6</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D8=AA=D8=BA=D9=8A=D9=8A=D8=B1 =D9=88=D9=82=D9=8A=D8=A7=D8=AF=
=D8=A9
  =D8=A7=D9=84=D8=A3=D8=B2=D9=85=D8=A7=D8=AA</span><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A7=
=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">3 - 14 </span><span lang=3D"AR-=
SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-s=
erif&quot;">=D9=86=D9=88=D9=81=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">7</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B3=D9=88=
=D9=8A=D9=82 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A =D9=88=D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9
  =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=AC=
=D8=A7=D8=B1=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D9=82 =D9=88=D8=A7=D9=84=
=D8=A5=D8=B9=D9=84=D8=A7=D9=85</span><span dir=3D"LTR" style=3D"font-size:1=
4pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">17 - 28 </span><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D9=86=D9=88=D9=81=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">8</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=AD=D9=88=D9=83=
=D9=85=D8=A9</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:10=
7%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=AD=
=D9=88=D9=83=D9=85=D8=A9</span><span dir=3D"LTR" style=3D"font-size:14pt;li=
ne-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">1 - 12 </span><span lang=3D"AR-=
SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-s=
erif&quot;">=D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">9</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D9=85=D8=B4=D8=AA=D8=B1=D9=8A=D8=A7=D8=AA =D9=88=D8=B3=D9=84=
=D8=A7=D8=B3=D9=84
  =D8=A7=D9=84=D8=A5=D9=85=D8=AF=D8=A7=D8=AF</span><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=B4=D8=AA=D8=B1=D9=8A=D8=A7=D8=AA =D9=88=
=D8=A7=D9=84=D9=84=D9=88=D8=AC=D8=B3=D8=AA=D9=8A=D8=A7=D8=AA</span><span di=
r=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">15 - 26 </span><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
 <tr>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">10</span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D9=85=D8=A7=D8=AC=D8=B3=D8=AA=D9=8A=D8=B1 =D8=A7=
=D9=84=D9=85=D9=87=D9=86=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9 =D8=A7=D9=84=D8=B5=D8=AD=D9=8A=D8=A9</span><span dir=3D"LTR" s=
tyle=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=A7=D9=84=D8=B5=D8=AD=D8=A9 =D9=88=D8=A7=D9=84=D9=85=D8=B3=
=D8=AA=D8=B4=D9=81=D9=8A=D8=A7=D8=AA</span><span dir=3D"LTR" style=3D"font-=
size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">80 </span><span lang=3D"AR-SA" =
style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif=
&quot;">=D8=B3=D8=A7=D8=B9=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9</span=
><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
  <td style=3D"border:4.5pt double windowtext;padding:0.75pt">
  <p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">22 - 31 </span><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D8=AF=D9=8A=D8=B3=D9=85=D8=A8=D8=B1 2025</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%"></span></p>
  </td>
 </tr>
</tbody></table>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%"><br clear=3D"all">
</span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"LT=
R" style=3D"font-size:14pt;line-height:107%;font-family:&quot;Segoe UI Symb=
ol&quot;,&quot;sans-serif&quot;">=F0=9F=93=9D</span></b><b><span dir=3D"LTR=
" style=3D"font-size:14pt;line-height:107%"> </span></b><b><span lang=3D"AR=
-SA" style=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-=
serif&quot;">=D9=85=D9=84=D8=A7=D8=AD=D8=B8=D8=A7=D8=AA =D9=85=D9=87=D9=85=
=D8=A9</span></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span=
 dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span>:</span></b><span dir=3D"LTR" style=3D"font-s=
ize:14pt;line-height:107%"></span></p>

<ul style=3D"margin-top:0in;margin-bottom:0in" type=3D"disc">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=AC=D9=85=D9=8A=D8=B9 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=
=AA=D9=85=D9=86=D8=AD =D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D9=88=D8=AB=D9=
=82=D8=A9 =D9=88=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =D9=88=D9=82=D8=A7=D8=
=A8=D9=84=D8=A9 =D9=84=D9=84=D8=AA=D8=B5=D8=AF=D9=8A=D9=82 =D9=85=D9=86
     =D8=A7=D9=84=D8=AE=D8=A7=D8=B1=D8=AC=D9=8A=D8=A9</span><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:14p=
t;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</sp=
an></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D9=84=D8=BA=D8=A9: =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=
=A9 (=D9=85=D8=B9 =D8=AA=D9=88=D9=81=D8=B1 =D9=85=D8=AA=D8=B1=D8=AC=D9=85 =
=D8=B9=D9=86=D8=AF =D8=A7=D9=84=D8=AD=D8=A7=D8=AC=D8=A9 =D9=84=D9=84=D8=A8=
=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9)</span>=
<span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:107%"><span dir=3D"LTR"></span><span dir=3D"=
LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D8=A7=D9=84=D9=81=D8=A6=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=
=AF=D9=81=D8=A9: =D8=A7=D9=84=D9=85=D8=AF=D9=8A=D8=B1=D9=88=D9=86 =D8=A7=D9=
=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A=D9=88=D9=86=D8=8C =D9=85=D8=B3=D8=
=A4=D9=88=D9=84=D9=88 =D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1=D8=8C =D9=
=85=D8=B3=D8=A4=D9=88=D9=84=D9=88
     =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9=D8=8C =D9=82=D8=A7=D8=AF=D8=A9 =
=D8=A7=D9=84=D9=81=D8=B1=D9=82=D8=8C =D8=B1=D8=A4=D8=B3=D8=A7=D8=A1 =D8=A7=
=D9=84=D8=A3=D9=82=D8=B3=D8=A7=D9=85=D8=8C =D9=88=D8=B0=D9=88=D9=88 =D8=A7=
=D9=84=D8=B7=D9=85=D9=88=D8=AD=D8=A7=D8=AA =D8=A7=D9=84=D9=82=D9=8A=D8=A7=
=D8=AF=D9=8A=D8=A9</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=
<span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span>.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;direction:rtl;unicode-bidi:embed;line-height:107%;font-size:1=
1pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif&quot=
;">=D9=8A=D9=85=D9=83=D9=86 =D8=AA=D9=86=D9=81=D9=8A=D8=B0 =D8=A7=D9=84=D8=
=A8=D8=B1=D8=A7=D9=85=D8=AC <b>=D8=A3=D9=88=D9=86=D9=84=D8=A7=D9=8A=D9=86 =
=D8=B9=D8=A8=D8=B1</b></span><span dir=3D"LTR"></span><span dir=3D"LTR"></s=
pan><b><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%"><span di=
r=3D"LTR"></span><span dir=3D"LTR"></span> Zoom</span></b><span dir=3D"LTR"=
 style=3D"font-size:14pt;line-height:107%"> </span><span lang=3D"AR-SA" sty=
le=3D"font-size:14pt;line-height:107%;font-family:Arial,&quot;sans-serif&qu=
ot;">=D8=A3=D9=88 <b>=D8=AD=D8=B6=D9=88=D8=B1=D9=8A</b> =D8=AD=D8=B3=D8=A8 =
=D8=B1=D8=BA=D8=A8=D8=A9 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=
=D9=86</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D=
"LTR" style=3D"font-size:14pt;line-height:107%"><span dir=3D"LTR"></span><s=
pan dir=3D"LTR"></span>.</span></li>
</ul>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initial=
;background-position:initial;background-size:initial;background-repeat:init=
ial;background-origin:initial;background-clip:initial;direction:rtl;unicode=
-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,&quot;sans-=
serif&quot;"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span =
style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featur=
e-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;font=
-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,&quot;sans-serif&quot;;color:red">=D9=84=D9=
=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=
=81=D8=B3=D8=A7=D8=B1</span></b><span lang=3D"AR-SA"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initia=
l;background-position:initial;background-size:initial;background-repeat:ini=
tial;background-origin:initial;background-clip:initial;direction:rtl;unicod=
e-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,&quot;sans=
-serif&quot;"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,&quot;sans-serif&quot;">=D9=88=D8=A8=D9=87=D8=
=B0=D9=87 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=A9 =D9=8A=D8=B3=D8=
=B9=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=83=D9=85 =D9=84=D9=84=D9=
=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=B9=D9=85=D9=8A=D9=85
=D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=
=D9=87=D8=AA=D9=85=D9=8A=D9=86 =D8=A8=D9=85=D9=80=D9=80=D9=88=D8=B6=D9=80=
=D9=88=D8=B9=C2=A0</span></b><b><span lang=3D"AR-EG" style=3D"font-size:16p=
t;font-family:Arial,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=B4=D9=87=D8=A7=
=D8=AF=D8=A9
=D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9=C2=A0</span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:Arial,&quot;s=
ans-serif&quot;">=D9=88=D8=A5=D9=81=D8=A7=D8=AF=D8=AA=D9=86=D8=A7 =D8=A8=D9=
=85=D9=86 =D8=AA=D9=82=D8=AA=D8=B1=D8=AD=D9=88=D9=86 =D8=AA=D9=88=D8=AC=D9=
=8A=D9=87 =D8=A7=D9=84=D8=AF=D8=B9=D9=88=D8=A9 =D9=84=D9=87=D9=85</span></b=
><span lang=3D"AR-SA"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initia=
l;background-position:initial;background-size:initial;background-repeat:ini=
tial;background-origin:initial;background-clip:initial;direction:rtl;unicod=
e-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,&quot;sans=
-serif&quot;"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,&quot;sans-serif&quot;">=D9=84=D9=85=D8=B2=D9=
=8A=D8=AF =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=
=AA =D9=8A=D9=85=D9=83=D9=86=D9=83 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=
=84 =D9=85=D8=B9 =D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9
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
e-bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,&quot;sans=
-serif&quot;"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"fon=
t-size:16pt;font-family:Arial,&quot;sans-serif&quot;">=D8=AC=D9=88=D8=A7=D9=
=84 =E2=80=93 =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=A8 :</span></b><span lang=
=3D"AR-SA"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 0.5in 8pt 0in;text-align:center;background-image:initial;=
background-position:initial;background-size:initial;background-repeat:initi=
al;background-origin:initial;background-clip:initial;direction:rtl;unicode-=
bidi:embed;line-height:107%;font-size:11pt;font-family:Calibri,&quot;sans-s=
erif&quot;"><span style=3D"font-size:10pt;font-family:Symbol">=C2=B7<span s=
tyle=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-feature=
-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:16pt"><span dir=3D"=
LTR"></span><span dir=3D"LTR"></span>00201069994399
-00201062992510 - 00201096841626</span></b><span lang=3D"AR-SA"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:115%;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:16pt;line-height:115%">=C2=A0</span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKmJa_cibVD6BecNG127f6Byh5Ufz6Kt3pG5KntFTzHhhA%40mail.gmail.=
com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msg=
id/kasan-dev/CADj1ZKmJa_cibVD6BecNG127f6Byh5Ufz6Kt3pG5KntFTzHhhA%40mail.gma=
il.com</a>.<br />

--000000000000fbd366063d1983ad--
