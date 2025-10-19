Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBQFU2TDQMGQEMEG656I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id AC0D4BEEA81
	for <lists+kasan-dev@lfdr.de>; Sun, 19 Oct 2025 19:05:06 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-47111dc7bdbsf28093465e9.0
        for <lists+kasan-dev@lfdr.de>; Sun, 19 Oct 2025 10:05:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760893506; cv=pass;
        d=google.com; s=arc-20240605;
        b=XHcCEhx9amOuEYia7TWqN7+nCsE/v9l7LSbKjiofEIHV/J0ePeXBBeqEECVUQuG1HT
         Qhm//UxItFiiPGHwg1BTIjrYpsPvaJahJBw9I/DsRgE/UhB1H6zh0ybaLfp2FRmO2/za
         wCLUVt+53B3R2W/TcHF3QOZg2Mkj9ymU/YVC+PVE6w3ptJ3NBJHKc4pW5xuEUb3uYSK9
         MIxeXPlBi7A3Rs4NuLl9sAhcfE4DzB3ZAhNMbavvvIqL2Cs1g01bIT41oJnhZALsgmjh
         XL2HgwcvF9K7XQ8+W8Hl+PgiUmk6CCDhhI+1fsJgCaYXDAKPwUNrkC0y5b5r/5LwTKp7
         2gnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=FSeLeQxMA0WGMZpYsSOqq471w6GYrtGXI+oprzLBj6g=;
        fh=30VKfzbqsX1g+w/rIRcA13yWKunCejFzlK7sts2o9s4=;
        b=JixQSYHwvZ+ZaTYZjQ6hyH3LGMkIyYwp/Bh84L9vpQDTugkyzAwHq2J2K3tuLk9ot7
         FKfIPFDaSbnhg62GWhqIkv9ymIj953iYYKaO8q1NqbHzgS09FtQmlI7lg7b0VeY+U0s1
         K9eEaRrUf11AB6e0kF+A4CRJwcZF3HOjhBmDu2gHC+d+D6tRcjCGAvkUP3GwDh52q+QK
         /SPvucjx8reqM8K8Hfyb5483VyfJBKdUUEV0jzxA4nL88z8rd2tejrJ2X8JMGKkVEVA9
         gaWEDbjIwJYbk5O5sE2l1lT0d54l/mbTKmHL3np1Xv0oC5t0LEid+JI/SPCRZ0MbUy8u
         RBaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U8ayyJq2;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760893506; x=1761498306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FSeLeQxMA0WGMZpYsSOqq471w6GYrtGXI+oprzLBj6g=;
        b=rhKMyyg4EeyHJiYubE31QVkUNS8ek59uWolHuZ6mKO2/6tUY+2rKjBa1OjFx8N8FRc
         6WBorD4u5nLoTb4SQtyN5qQ23rA3/m8sXSA8n0YetgfCyMRc+iloZ998SWeZneGYbXyx
         +WwKD8HseKAbcc5f0kPdgMANlAVZN0ZYnKxijYZilfY5guJlH0J6ZttZUeEWdaMI4e29
         +Cfm4g4quHb0Rvxqzmm3qMyC5YejsFMy5zFszq1x3kI6xIgpVQ/vF9yBRrljRAkThGPG
         reE9z3J19LXLj+7VozoDPI6/KjR3Ngkk4RHCCtSnqqHSp74kVXdz4B/sSSVMfRxIUjFm
         Eyfw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760893506; x=1761498306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=FSeLeQxMA0WGMZpYsSOqq471w6GYrtGXI+oprzLBj6g=;
        b=cgnjDwDluqSOF9AykHM6rnA5ZTlOgvGfrICKILygblx7itbkInBXqDUKl4YSbivq6M
         KFx+euaJyYdqsVreQ/06lBUAvydwrAvDN3wDytAmU9VRbdQFGG3NAoIuSuA8s/MRNe68
         D9GBYmGPycofmK60DeU0p+vsazI8XqC+bKvdH3a317YGzwHmV5yfBW28BC/bOIHmcbKi
         ZUJ9CSpemkvXkTI500gBmL/PCEGgjyf51sRNbHv3RLfcttWlkoS1+78vyiG1OD62yxgy
         7v0VbgHtTLW+eu/noad4aucZUYvfgtlF0dofudRa75+/T2To0i8hGb7Q9OrtULqFMo4D
         F1CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760893506; x=1761498306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FSeLeQxMA0WGMZpYsSOqq471w6GYrtGXI+oprzLBj6g=;
        b=cAh8GM0M3RHpRJVZbjmVJa4sCGPL5uWhBDEtSBj+69x3nc+T0ilKvGn/saZcIXTZ5H
         j/ypWZuMqVrG0E3kqImVQKz6BmDEc/avgltoPYQ+gZzHDL8nkrFrkAbgmUdP7urempvd
         2Py5F++crIOcC6xc2+GYKNsdPkKlbv1YayqbwR/VIZCJEvqttRO/Y7jJXgXOKYmC3wWm
         bkN4BTOBrzSwERZWR8G8iytYOMJfPnCIib2H49Y7q7qqaUe9n6cBc+xYABiRBlq4GdFf
         z19glG132lvqHQYN2qBVcvsSZiSnyHM7U0kOXlgI9/Ch43yRnmz4gFHoFojpchFwbWbI
         B/Nw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVPojpEe0nUvI8ktqzjlWXVNC/ZSwaVOpmatzNkFV034zFUuoH6+aA0hjW07ajjmIIbNqOi5Q==@lfdr.de
X-Gm-Message-State: AOJu0YyAt8iNDrdEArtBaKuVTY9j6ITPy9A5748IK4Oi3SbH71kIk8wH
	JiocvXPKnm4IQRyrOaL2ivKqdgsrwcUgH8+r4kyvQQpXT/I0THIxSzPM
X-Google-Smtp-Source: AGHT+IE6xEzeRo9qrUUUwtqxQbslvFBWAKTzaJXjJj8p6x6U8mhSs8wdVCz+33cpSPqkDkN9VAce6A==
X-Received: by 2002:a05:600c:64cf:b0:46e:3dad:31ea with SMTP id 5b1f17b1804b1-471178af7cemr67767335e9.17.1760893505663;
        Sun, 19 Oct 2025 10:05:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6hb+MLyhUM7jFK6yR4dHA3TIaz7GCvjMXsgqOnZ1jO6w=="
Received: by 2002:adf:f84e:0:b0:426:fef2:c9f0 with SMTP id ffacd0b85a97d-426ff46934fls1588239f8f.0.-pod-prod-01-eu;
 Sun, 19 Oct 2025 10:05:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5E1uTOT0pN4LNlZfdW8LF9BrlroRFDIW9+wyvVxrCG8TpbiSnml0UYUOdtCXhS5lTtZ7y6aGHINs=@googlegroups.com
X-Received: by 2002:a5d:5d0b:0:b0:426:d582:14a3 with SMTP id ffacd0b85a97d-42704d830e0mr5744538f8f.9.1760893503143;
        Sun, 19 Oct 2025 10:05:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760893503; cv=none;
        d=google.com; s=arc-20240605;
        b=ifiV7REpm0Mebgkxc3CXzFdVuUMQQ80afjOgPK2KVQ5YqCJYjkWEMqsi8IYd3ExUdw
         s2jXMGyLQplmTagwnev08QqvgqfuJgsjb0JMRoN1afnC0jo5gdMzbiDtolPtawNNEbJX
         kJSvYl1FREH7r471o4Bk56ocSzzJQtmagYmrPgW3x6mcWGDLR2r510LblByYl6Jo3rah
         vlxymu1IEh1BmWYnxfkfDnzCJapMZ9huB3OZfNh5efRor7pT0ISV+00uPEIhvW0IdtVu
         Lz15RscT2bq14h8czRR/bnpIsKhawp3IlirDQ/UgsD8GZI2h47Skc4ofnL6JqklpoE31
         YvsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=Dik8VSwxeg3d0Tskrzr8lewb6RIMZhSWQAQ+J068weA=;
        fh=rRQtaelLd/mG1acWkqnKrrHRjzPJ8NFp0YvCp0V+yuU=;
        b=AT3SU9gBBkW6/MBfIIJyby3GJybuDMcAyr7BRR4Xqs1+Ew35p6S2+6fSSFjXJciU0Q
         OlN/oxlfTrsSYpnoYC4kOaIWohNFzMcdB5+K6J+X6Wjx88VpbYsp6V7sPe9TnohHauA0
         Ng0MZ2EblOoY6GVadZnw05++OA2BCDWhQIEEmepmy5KYSlgj2IXzNcPq4lmWHN4+sVEY
         apwa2n2OjGUC4dzhXsyOqZuOWK9U0ZMTE+iD+LmCOHL6KJe9ycrQEtsxQBeO44OAmk11
         aCcN/NfTWasNh4Rg8LtdFx/UBqbYne8IIhBVyvEV4+t6GD/MjZzX0E/cSwqAAjbWA8rO
         iZTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U8ayyJq2;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-427ea5e1456si144736f8f.3.2025.10.19.10.05.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 19 Oct 2025 10:05:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id 4fb4d7f45d1cf-637e9f9f9fbso6688381a12.0
        for <kasan-dev@googlegroups.com>; Sun, 19 Oct 2025 10:05:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVs/MqaOjj2H7V4DZQRG6a7J4h2YILn7RqMT1onnpB6MjEWKX4B/VZeUef7A5J74ZvbrseT7JX5QzE=@googlegroups.com
X-Gm-Gg: ASbGncvLKsjACSaCEW7aAQgiknOgpPbeIRInLLdVWFgLzZk9mkpLUJ0qDAn1HRM7rDI
	I2BuOpuLUHQeowZBTw1GRFxinrx0qRMJhyEAFgqi4rZCYN4Ybj95H5QT7cPevWBU0CO5QdzzwyW
	mt8dn77DiDa0/1zijQsdHtKhdICzVRbAtxBhV/QJChe5hBRhA0CCD7H/S9rLyYBxoj9yl7J544h
	SUlojl8iCnY/NHmuYMPwHYPOqotWbEbwv7ILPtVbTzpLDsZDgTzUv6MNQ6YrDVZDrdVCAvpRMvR
	dg==
X-Received: by 2002:a05:6402:3485:b0:639:f548:686e with SMTP id
 4fb4d7f45d1cf-63c1f580d94mr9923543a12.0.1760893502012; Sun, 19 Oct 2025
 10:05:02 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Sun, 19 Oct 2025 21:11:10 +0300
X-Gm-Features: AS18NWCk9rcUpdFWvVNL_4XRYX5zkSlNMWeOCDD9IkJfQSvKtysZr0WfzsBPCe4
Message-ID: <CADj1ZKm8QtenmN0jnLYfOkb1Frgqyfw=gK_E=SO9UHBZLbnUcg@mail.gmail.com>
Subject: =?UTF-8?B?2KrYrdmE2YrZhMKg2KfZhNmC2YjYp9im2YXCoNin2YTZhdin2YTZitipwqAgRmluYW5jaQ==?=
	=?UTF-8?B?YWwgU3RhdGVtZW50cyBBbmFseXNpc8KgINin2YTYqtin2LHZitiuOjI1IOKAkzMwINij2YPYqtmI2Kg=?=
	=?UTF-8?B?2LEyMDI1INmF2YPYp9mG2KfZhNin2YbYudmC2KfYrzrYp9mE2YLYp9mH2LHYqeKAk9is2YXZh9mI2LE=?=
	=?UTF-8?B?2YrYqdmF2LXYsdin2YTYudix2KjZitipwqDYp9mE2YXYr9ipOjUg2KPZitin2YXYqtiv2LHZitio2Yo=?=
	=?UTF-8?B?2Kkg2LTZh9in2K/YqdmF2YfZhtmK2KnZhdi52KrZhdiv2KnZhdmI2KvZgtip2YjYqNin2LnYqtmF2Kc=?=
	=?UTF-8?B?2K/Yr9mI2YTZitmF2LnYqtix2YHYqNmH2KfZgdmK2YPYp9mB2KnYp9mE2K/ZiNmEwqAg2KfZhNiv2Kc=?=
	=?UTF-8?B?2LEg2KfZhNi52LHYqNmK2KnZhNmE2KrZhtmF2YrYqdin2YTYpdiv2KfYsdmK2KnigJNBSEFEwqAg2YQ=?=
	=?UTF-8?B?2YTYqtmI2KfYtdmE2YjYp9mE2KfYs9iq2YHYs9in2LE6MDAyMDEwNjI5OTI1MTAg4oCTIDAwMjAxMDY5?=
	=?UTF-8?B?OTk0Mzk5IOKAkzAwMjAxMDk2ODQxNjI2?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000acc31d064185f718"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=U8ayyJq2;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::536
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

--000000000000acc31d064185f718
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YfZhCDZgtix2KPYqiDZgtmI2KfYptmF2YMg2KfZhNmF2KfZhNmK2Kkg2YrZiNmF2YvYpyDZiNmE
2YUg2KrZgdmH2YUg2KfZhNmC2LXYqSDYp9mE2K3ZgtmK2YLZitipINmI2LHYp9ihINin2YTYo9ix
2YLYp9mF2J8NCg0K2KfZhNij2LHZgtin2YUg2YTYpyDYqtiq2K3Yr9ir4oCmINil2YTYpyDZhNmF
2YYg2YrYudix2YEg2YTYutiq2YfYpy4NCg0K2YjYqtit2YTZitmEINin2YTZgtmI2KfYptmFINin
2YTZhdin2YTZitipINmH2Ygg2YXZgdiq2KfYrSDZgdmH2YUg2KPYr9in2KEg2KfZhNi02LHZg9in
2KrYjCDZiNin2KrYrtin2LAg2YLYsdin2LHYp9iqINmF2KfZhNmK2Kkg2LDZg9mK2KkNCtiq2YLZ
iNivINil2YTZiSDYp9mE2YbZhdmIINmI2KfZhNin2LPYqtiv2KfZhdipLg0KDQrYqNix2YbYp9mF
2Kwg2KrYrdmE2YrZhCDYp9mE2YLZiNin2KbZhSDYp9mE2YXYp9mE2YrYqSDZhdmGINin2YTYr9in
2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNil2K/Yp9ix2YrYqSDZitmF2YbY
rdmDINin2YTZgtiv2LHYqQ0K2LnZhNmJINmC2LHYp9ih2Kkg2KfZhNmC2YjYp9im2YUg2KfZhNmF
2KfZhNmK2Kkg2YPYrtio2YrYsdiMINmI2KfYqtiu2KfYsCDZgtix2KfYsdin2Kog2YXYqNmG2YrY
qSDYudmE2Ykg2KrYrdmE2YrZhCDZiNin2YLYudmKINmI2K/ZgtmK2YIuDQoNCtiq2K3ZhNmK2YQg
2KfZhNmC2YjYp9im2YUg2KfZhNmF2KfZhNmK2KkNCg0KKkZpbmFuY2lhbCBTdGF0ZW1lbnRzIEFu
YWx5c2lzKg0KDQoq2KfZhNiq2KfYsdmK2K4qKjogMjUg4oCTIDMwICoq2KPZg9iq2YjYqNixIDIw
MjUqDQoq2YXZg9in2YYg2KfZhNin2YbYudmC2KfYryoqOiAqKtin2YTZgtin2YfYsdipIOKAkyDY
rNmF2YfZiNix2YrYqSDZhdi12LEg2KfZhNi52LHYqNmK2KkqDQogKtin2YTZhdiv2KkqKjogNSAq
Ktij2YrYp9mFKg0KDQoq2LTZh9in2K/YqSDZhdmH2YbZitipINmF2LnYqtmF2K/YqSDigJMg2YXZ
iNir2YLYqSDZiNio2KfYudiq2YXYp9ivINiv2YjZhNmKKiAq2YXYudiq2LHZgSDYqNmH2Kcg2YHZ
iiDZg9in2YHYqSDYp9mE2K/ZiNmEKg0KDQoq2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE
2KrZhtmF2YrYqSDYp9mE2KfYr9in2LHZitipIOKAkyAqKkFIQUQqDQoNCirYqtit2YrYqSDYt9mK
2KjYqSDZiCDYqNi52K8g2IzYjNiMKg0KDQoq2KPYt9mK2Kgg2KfZhNij2YXZhtmK2KfYqiDZiNin
2YTYqtit2YrYp9iqINiq2YfYr9mK2YfYpyDZhNmD2YUg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrY
qSDZhNmE2KrZhtmF2YrYqSDYp9mE2KfYr9in2LHZitipKiog2KjYtNmH2KfYr9ipDQrZhdi52KrZ
hdivIC0gKipBSEFEKg0KDQoNCg0KKj8gICAgICAgICAgICAgICAq2KfZhNmF2YbZh9isINin2YTY
qti32KjZitmC2Yog2YTZhNio2LHZhtin2YXYrCA6DQoNCtmK2Y/Zgtiv2ZHZjtmFINmH2LDYpyDY
p9mE2KjYsdmG2KfZhdisINmD2YXZhtmH2Kwg2KrYt9io2YrZgtmKINmF2KrZg9in2YXZhCDZitmH
2K/ZgSDYpdmE2Ykg2KrZhdmD2YrZhiDYp9mE2YXYtNin2LHZg9mK2YYg2YXZhiDZgtix2KfYodip
2IwNCtiq2K3ZhNmK2YTYjCDZiNiq2YHYs9mK2LEg2KfZhNmC2YjYp9im2YUg2KfZhNmF2KfZhNmK
2Kkg2KjYp9it2KrYsdin2YHYjA0KDQrZiNin2LPYqtiu2K/Yp9mFINmG2KrYp9im2Kwg2KfZhNiq
2K3ZhNmK2YQg2YHZiiDYp9mE2KrYrti32YrYtyDYp9mE2YXYp9mE2YrYjCDYqtmC2YrZitmFINin
2YTYo9iv2KfYodiMINmI2KfYqtiu2KfYsCDYp9mE2YLYsdin2LENCtin2YTYp9iz2KrYsdin2KrZ
itis2YouDQoNCio/ICAgICAgICAgICAgKtin2YTYo9mH2K/Yp9mBINin2YTYudin2YXYqQ0KDQoq
wqggICAgICrYqtmF2YPZitmGINin2YTZhdi02KfYsdmD2YrZhiDZhdmGINmB2YfZhSDZhdmD2YjZ
htin2Kog2KfZhNmC2YjYp9im2YUg2KfZhNmF2KfZhNmK2Kkg2KfZhNij2LPYp9iz2YrYqSAo2YLY
p9im2YXYqQ0K2KfZhNiv2K7ZhNiMINin2YTZhdmK2LLYp9mG2YrYqSDYp9mE2LnZhdmI2YXZitip
2Iwg2KfZhNiq2K/ZgdmC2KfYqiDYp9mE2YbZgtiv2YrYqSkuDQoNCirCqCAgICAgKtiq2LfZiNmK
2LEg2YXZh9in2LHYqSDYqtit2YTZitmEINin2YTYo9iv2KfYoSDYp9mE2YXYp9mE2Yog2KjYp9iz
2KrYrtiv2KfZhSDZhdik2LTYsdin2Kog2KfZhNiz2YrZiNmE2KnYjCDYp9mE2LHYqNit2YrYqdiM
DQrZiNin2YTZg9mB2KfYodipLg0KDQoqwqggICAgICrYqNmG2KfYoSDYp9mE2YLYr9ix2Kkg2LnZ
hNmJINiq2YLZitmK2YUg2KfZhNmF2YjZgtmBINin2YTZhdin2YTZiiDZiNin2KrYrtin2LAg2KfZ
hNmC2LHYp9ix2KfYqiDYqNmG2KfYodmLINi52YTZiQ0K2KfZhNiq2K3ZhNmK2YQg2KfZhNmI2KfZ
gti52Yog2YTZhNij2LHZgtin2YUuDQoNCirCqCAgICAgKtin2YTYqti52LHZgSDYudmE2Ykg2KPZ
h9mFINin2YTZhdi52KfZitmK2LEg2KfZhNmF2K3Yp9iz2KjZitipINin2YTYr9mI2YTZitipIChJ
RlJTKSDYp9mE2YXYpNir2LHYqSDZgdmKINil2LnYr9in2K8NCtin2YTZgtmI2KfYptmFLg0KDQoq
wqggICAgICrYqti32KjZitmCINij2K/ZiNin2Kog2KfZhNiq2K3ZhNmK2YQg2KfZhNmF2KfZhNmK
INi52YTZiSDYrdin2YTYp9iqINmI2KfZgti52YrYqSDZiNi02LHZg9in2Kog2K3ZgtmK2YLZitip
INio2KfYs9iq2K7Yr9in2YUNCtio2LHYp9mF2Kwg2KrYrdmE2YrZhCDZhdiq2K7Ytdi12KkNCg0K
Kj8gICAgICAgICAgICAq2KfZhNmB2KbYqSAg2KfZhNmF2LPYqtmH2K/ZgdipOg0KDQoqwqggICAg
ICrYp9mE2YXYrdin2LPYqNmI2YYg2YjYp9mE2YXYr9mC2YLZiNmGINin2YTZhdin2YTZitmI2YYu
DQoNCirCqCAgICAgKtmF2K3ZhNmE2Ygg2KfZhNij2LnZhdin2YQg2YjZhdiv2YrYsdmIINin2YTY
pdiv2KfYsdin2Kog2KfZhNmF2KfZhNmK2KkuDQoNCirCqCAgICAgKtin2YTZhdiz2KrYq9mF2LHZ
iNmGINmI2LHZiNin2K8g2KfZhNij2LnZhdin2YQg2KfZhNiw2YrZhiDZitix2LrYqNmI2YYg2YHZ
iiDZgtix2KfYodipINin2YTZgtmI2KfYptmFINin2YTZhdin2YTZitipDQrYqNiw2YPYp9ihINin
2LPYqtir2YXYp9ix2YouDQoNCirCqCAgICAgKtmF2K/Ysdin2KEg2KfZhNmF2LTYp9ix2YrYuSDZ
iNin2YTZhdiz2KTZiNmE2YjZhiDYp9mE2KrZhtmB2YrYsNmK2YjZhiDYp9mE2LDZitmGINmK2K3Y
qtin2KzZiNmGINil2YTZiSDYqtmB2LPZitixDQrYp9mE2YbYqtin2KbYrCDYp9mE2YXYp9mE2YrY
qSDZhNin2KrYrtin2LAg2YLYsdin2LHYp9iqINin2LPYqtix2KfYqtmK2KzZitipLg0KDQoqwqgg
ICAgICrYt9mE2KfYqCDZg9mE2YrYp9iqINil2K/Yp9ix2Kkg2KfZhNij2LnZhdin2YQg2YjYp9mE
2KfZgtiq2LXYp9ivINin2YTYsdin2LrYqNmI2YYg2YHZiiDYqti32YjZitixINmF2LPYp9ixINmF
2YfZhtmKDQrYp9it2KrYsdin2YHZiiDZgdmKINin2YTYqtit2YTZitmEINin2YTZhdin2YTZii4N
Cg0KDQoNCg0KDQoqPyAgICAgICAgICAgICrwn5OaINmF2K3Yp9mI2LEg2KfZhNio2LHZhtin2YXY
rCDYp9mE2KPYs9in2LPZitipOg0KDQrwn6epINin2YTZhdit2YjYsSDYp9mE2KPZiNmEOiDZhdiv
2K7ZhCDYpdmE2Ykg2KfZhNmC2YjYp9im2YUg2KfZhNmF2KfZhNmK2KkNCg0KwqggICAgINmF2KfZ
h9mK2Kkg2KfZhNmC2YjYp9im2YUg2KfZhNmF2KfZhNmK2Kkg2YjYo9mH2YXZitiq2YfYpyDZgdmK
INin2KrYrtin2LAg2KfZhNmC2LHYp9ixLg0KDQrCqCAgICAg2KfZhNmB2LHZgiDYqNmK2YYg2KfZ
hNmC2YjYp9im2YUg2KfZhNmF2KfZhNmK2Kkg2YjYp9mE2KrZgtin2LHZitixINin2YTZhdin2YTZ
itipLg0KDQrCqCAgICAg2KPZhtmI2KfYuSDYp9mE2YLZiNin2KbZhSDYp9mE2YXYp9mE2YrYqSAo
2KfZhNiv2K7ZhNiMINin2YTZhdmK2LLYp9mG2YrYqdiMINin2YTYqtiv2YHZgtin2Kog2KfZhNmG
2YLYr9mK2KnYjCDYp9mE2KrYutmK2LEg2YHZig0K2K3ZgtmI2YIg2KfZhNmF2YTZg9mK2KkpLg0K
DQoNCg0K8J+SoSDYp9mE2YXYrdmI2LEg2KfZhNir2KfZhtmKOiDYp9mE2KXYt9in2LEg2KfZhNmF
2K3Yp9iz2KjZiiDZiNin2YTZhdi52KfZitmK2LEg2KfZhNiv2YjZhNmK2KkNCg0KwqggICAgINin
2YTZhdio2KfYr9imINmI2KfZhNmF2LnYp9mK2YrYsSDYp9mE2YXYrdin2LPYqNmK2Kkg2KfZhNmF
2KTYq9ix2KkgKElGUlMpLg0KDQrCqCAgICAg2KPYs9izINil2LnYr9in2K8g2KfZhNmC2YjYp9im
2YUg2KfZhNmF2KfZhNmK2Kkg2YjYp9mE2KXZgdi12KfYrSDYp9mE2YXYrdin2LPYqNmKLg0KDQrC
qCAgICAg2KzZiNiv2Kkg2KfZhNmF2LnZhNmI2YXYp9iqINin2YTZhdin2YTZitipINmI2KPYq9ix
2YfYpyDYudmE2Ykg2KfZhNmF2YjYq9mI2YLZitipLg0KDQoNCg0K8J+TiiDYp9mE2YXYrdmI2LEg
2KfZhNir2KfZhNirOiDYp9mE2KrYrdmE2YrZhCDYp9mE2YXYp9mE2Yog2KfZhNiq2LfYqNmK2YLZ
ig0KDQrCqCAgICAg2KfYs9iq2K7Yr9in2YUg2KfZhNmG2LPYqCDZiNin2YTZhdik2LTYsdin2Kog
2KfZhNmF2KfZhNmK2Kkg2YTYqtit2YTZitmEINin2YTYo9iv2KfYoS4NCg0KwqggICAgINiq2K3Z
hNmK2YQg2KfZhNiz2YrZiNmE2Kkg2YjYp9mE2LHYqNit2YrYqSDZiNin2YTZg9mB2KfYodipINmI
2YfZitmD2YQg2KfZhNiq2YXZiNmK2YQuDQoNCsKoICAgICDYqtit2YTZitmEINin2YTYp9iq2KzY
p9mH2KfYqiAoVHJlbmQgQW5hbHlzaXMpINmI2KfZhNmF2YLYp9ix2YbYp9iqINin2YTYo9mB2YLZ
itipINmI2KfZhNix2KPYs9mK2KkuDQoNCsKoICAgICDYqti32KjZitmC2KfYqiDYudmF2YTZitip
INio2KfYs9iq2K7Yr9in2YUg2KjZitin2YbYp9iqINi02LHZg9in2Kog2K3ZgtmK2YLZitipLg0K
DQoNCg0K8J+SsCDYp9mE2YXYrdmI2LEg2KfZhNix2KfYqNi5OiDYqtmB2LPZitixINin2YTZhtiq
2KfYptisINmI2KfYqtiu2KfYsCDYp9mE2YLYsdin2LENCg0KwqggICAgINix2KjYtyDZhtiq2KfY
ptisINin2YTYqtit2YTZitmEINio2KfZhNij2YfYr9in2YEg2KfZhNin2LPYqtix2KfYqtmK2KzZ
itipINmE2YTZhdik2LPYs9ipLg0KDQrCqCAgICAg2YLYsdin2KHYqSDYp9mE2KrYrdmE2YrZhCDY
p9mE2YXYp9mE2Yog2YHZiiDYttmI2KEg2KfZhNio2YrYptipINin2YTYp9mC2KrYtdin2K/Zitip
INmI2KfZhNiz2YjZgtmK2KkuDQoNCsKoICAgICDYpdi52K/Yp9ivINin2YTYqtmC2KfYsdmK2LEg
2KfZhNiq2K3ZhNmK2YTZitipINin2YTZhdmI2KzZh9ipINmE2YTYpdiv2KfYsdipINin2YTYudmE
2YrYpyDZiNin2YTZhdiz2KrYq9mF2LHZitmGLg0KDQoNCg0K4pqZ77iPINin2YTZhdit2YjYsSDY
p9mE2K7Yp9mF2LM6INin2LPYqtiu2K/Yp9mFINij2K/ZiNin2Kog2KfZhNiq2K3ZhNmK2YQg2KfZ
hNit2K/Zitir2KkNCg0KKsKoICAgICAq2KfZhNiq2K3ZhNmK2YQg2KjYp9iz2KrYrtiv2KfZhSDY
qNix2KfZhdisINmF2KfZhNmK2Kkg2YXYqtmC2K/ZhdipICjZhdir2YQgRXhjZWwg2YhERVhFRiku
DQoNCirCqCAgICAgKtil2LnYr9in2K8g2KrZgtin2LHZitixINmF2KfZhNmK2Kkg2KfYrdiq2LHY
p9mB2YrYqSDZgtin2KjZhNipINmE2YTYudix2LYg2KfZhNiq2YbZgdmK2LDZii4NCg0KKsKoICAg
ICAq2YXYpNi02LHYp9iqINin2YTZgtmK2YXYqSDYp9mE2YXYttin2YHYqSDYp9mE2KfZgtiq2LXY
p9iv2YrYqSAoRVZBKSDZiNin2YTYudin2KbYryDYudmE2Ykg2KfZhNin2LPYqtir2YXYp9ixIChS
T0kpLg0KDQoNCg0K2YXYrtix2KzYp9iqINin2YTYqti52YTZhSDYp9mE2YXYqtmI2YLYudipDQoN
Ctio2YbZh9in2YrYqSDYp9mE2KjYsdmG2KfZhdis2Iwg2LPZitmD2YjZhiDYp9mE2YXYqtiv2LHY
qCDZgtin2K/YsdmL2Kcg2LnZhNmJOg0KDQoqwqggICAgICrinIUg2KXYudiv2KfYryDZiNmC2LHY
p9ih2Kkg2KfZhNmC2YjYp9im2YUg2KfZhNmF2KfZhNmK2Kkg2KjYp9it2KrYsdin2YEuDQoNCirC
qCAgICAgKuKchSDYqti32KjZitmCINij2K/ZiNin2Kog2KfZhNiq2K3ZhNmK2YQg2KfZhNmF2KfZ
hNmKINi52YTZiSDYrdin2YTYp9iqINi52YXZhNmK2KkuDQoNCirCqCAgICAgKuKchSDYqtmC2YrZ
itmFINin2YTYo9iv2KfYoSDYp9mE2YXYp9mE2Yog2YTZhNmF2KTYs9iz2KfYqiDYqNmF2KTYtNix
2KfYqiDYr9mC2YrZgtipLg0KDQoqwqggICAgICrinIUg2KXYudiv2KfYryDYqtmC2KfYsdmK2LEg
2KrYrdmE2YrZhNmK2Kkg2KrYqNix2LIg2YbZgtin2Lcg2KfZhNmC2YjYqSDZiNin2YTYtti52YEu
DQoNCirCqCAgICAgKuKchSDYqtmC2K/ZitmFINiq2YjYtdmK2KfYqiDZhdin2YTZitipINmF2K/Y
sdmI2LPYqSDYqtiv2LnZhSDYp9iq2K7Yp9iwINin2YTZgtix2KfYsSDYp9mE2KXYr9in2LHZiiDZ
iNin2YTYp9iz2KrYq9mF2KfYsdmKDQoNCti32LHZgiDYp9mE2KrYr9ix2YrYqA0KDQrCqCAgICAg
ICDZhdit2KfYttix2KfYqiDYqtmB2KfYudmE2YrYqdiMINiv2LHYp9iz2KfYqiDYrdin2YTYqSDZ
hdit2YTZitipLg0KDQrCqCAgICAgICDZiNix2LQg2LnZhdmEINiq2LfYqNmK2YLZitip2Iwg2YXY
rdin2YPYp9ipINiq2K/ZgtmK2YLYjCDYqtmF2KfYsdmK2YYg2KzZhdin2LnZitipLg0KDQrCqCAg
ICAgICDZgtmI2KfZhNioINi52YXZhNmK2Kkg2YjZhtmF2KfYsNisINmC2KfYqNmE2Kkg2YTZhNiq
2LnYr9mK2YQgKFNPUHMsIENoZWNrbGlzdHMsIEZvcm1zKS4NCg0KwqggICAgICAg2LTYsdin2KbY
rSDYqtmC2K/ZitmF2YrYqSAoUG93ZXJQb2ludCkg2YTZg9mEINis2YTYs9ipLg0KDQrCqCAgICAg
ICDYrdin2YTYp9iqINiv2LHYp9iz2YrYqSDZiNin2YLYudmK2Kkg2YjYqtmF2KfYsdmK2YYg2YXZ
itiv2KfZhtmK2Kkg2YLYtdmK2LHYqS4NCg0K2KrZhtmI2YrYqQ0KDQrCqCAgICAg2KzZhdmK2Lkg
2KfZhNi02YfYp9iv2KfYqiDYqti02YXZhCDYtNmH2KfYr9ipINmF2LnYqtmF2K/YqdiMINit2YLZ
itio2Kkg2KrYr9ix2YrYqNmK2KkuDQoNCsKoICAgICDZitmF2YPZhiDYqtmG2YHZitiwINin2YTY
qNix2KfZhdisINit2LbZiNix2YrZi9inINij2Ygg2KPZiNmG2YTYp9mK2YYg2LnYqNixIFpvb20u
DQoNCsKoICAgICDYpdmF2YPYp9mG2YrYqSDYqtiu2LXZiti1INij2Yog2LTZh9in2K/YqSDZhNiq
2YPZiNmGINiv2KfYrtmEINin2YTYtNix2YPYqSAoSW4tSG91c2UpLg0KDQrCqCAgICAg2K7YtdmF
IDIwJSDZhNmE2YXYrNmF2YjYudin2KogKDMg2KPYtNiu2KfYtSDYo9mIINij2YPYq9ixKS4NCg0K
2YrZj9i52K8g2YfYsNinINin2YTYqNix2YbYp9mF2Kwg2LHZg9mK2LLYqSDYo9iz2KfYs9mK2Kkg
2YTZg9mEINmF2YYg2YrYs9i52Ykg2KXZhNmJINin2YTYqtmF2YrYsiDYp9mE2YXYp9mE2Yog2YjY
p9mE2KXYr9in2LHZitiMINmB2YfZiA0K2YTYpyDZitmD2KrZgdmKINio2KfZhNis2KfZhtioINin
2YTZhti42LHZitiMINio2YQg2YrYr9mF2Kwg2KfZhNiq2K3ZhNmK2YQg2KfZhNiq2LfYqNmK2YLZ
iiDZiNin2YTYqtmB2YPZitixINin2YTZhtmC2K/ZiiDZgdmKINio2YrYptipDQrZhdin2YTZitip
INmF2KrYutmK2LHYqS4NCg0K2YjYqNmB2LbZhCDYr9mF2Kwg2KfZhNmF2LnYsdmB2Kkg2KfZhNmF
2K3Yp9iz2KjZitipINio2KfZhNiq2YLZhtmK2KfYqiDYp9mE2K3Yr9mK2KvYqdiMINmK2LXYqNit
INin2YTZhdi02KfYsdmD2YjZhiDZhdik2YfZhNmK2YYg2YTZgtmK2KfYr9ipDQrYp9mE2KrYrdmE
2YrZhCDYp9mE2YXYp9mE2Yog2YHZiiDZhdik2LPYs9in2KrZh9mFINio2YPZgdin2KHYqSDZiNin
2K3Yqtix2KfZgdmK2Kkg2LnYp9mE2YrYqS4g2KfZhti22YUg2KXZhNmJINio2LHZhtin2YXYrCDY
qtit2YTZitmEDQrYp9mE2YLZiNin2KbZhSDYp9mE2YXYp9mE2YrYqSDZhNiq2YPYqti02YEg2YXY
pyDZiNix2KfYoSDYp9mE2KPYsdmC2KfZhdiMINmI2KrYrdmI2ZHZhCDYp9mE2KjZitin2YbYp9iq
INil2YTZiSDZgtix2KfYsdin2KouDQoNCtiu2LfZiNipINmG2K3ZiCDYp9it2KrYsdin2YEg2KfZ
hNiq2K3ZhNmK2YQg2KfZhNmF2KfZhNmKINmI2LXZhtin2LnYqSDYp9mE2YLYsdin2LEg2KjYq9mC
2KkuDQoNCtmE2YTYqtiz2KzZitmEINij2Ygg2YTYt9mE2Kgg2KfZhNi52LHYtiDYp9mE2KrYr9ix
2YrYqNmKINin2YTZg9in2YXZhNiMINmK2LHYrNmJINin2YTYqtmI2KfYtdmEINmF2LnZhtinOg0K
DQrYoyAvINiz2KfYsdipINi52KjYryDYp9mE2KzZiNin2K8g4oCT2YXYr9mK2LEg2KfZhNiq2K/Y
sdmK2KgNCg0KwqgNCg0KwqggICAgW9ix2YLZhSDYp9mE2YfYp9iq2YEgLyDZiNin2KrYsyDYp9io
XSAgICAwMDIwMTA2OTk5NDM5OSAtMDAyMDEwNjI5OTI1MTAgLQ0KMDAyMDEwOTY4NDE2MjYNCg0K
LS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQg
dG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJlIGZy
b20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4g
ZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHZpZXcg
dGhpcyBkaXNjdXNzaW9uIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9r
YXNhbi1kZXYvQ0FEajFaS204UXRlbm1OMGpuTFlmT2tiMUZyZ3F5ZnclM0RnS19FJTNEU085VUhC
WkxiblVjZyU0MG1haWwuZ21haWwuY29tLgo=
--000000000000acc31d064185f718
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:normal;margin:0in 0in 8pt;direction:rtl;u=
nicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=
=3D"AR-SA" style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quo=
t;,sans-serif;color:rgb(192,0,0);background-image:initial;background-positi=
on:initial;background-size:initial;background-repeat:initial;background-ori=
gin:initial;background-clip:initial">=D9=87=D9=84 =D9=82=D8=B1=D8=A3=D8=AA =
=D9=82=D9=88=D8=A7=D8=A6=D9=85=D9=83 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=
=D8=A9 =D9=8A=D9=88=D9=85=D9=8B=D8=A7 =D9=88=D9=84=D9=85 =D8=AA=D9=81=D9=87=
=D9=85 =D8=A7=D9=84=D9=82=D8=B5=D8=A9
=D8=A7=D9=84=D8=AD=D9=82=D9=8A=D9=82=D9=8A=D8=A9 =D9=88=D8=B1=D8=A7=D8=A1 =
=D8=A7=D9=84=D8=A3=D8=B1=D9=82=D8=A7=D9=85=D8=9F</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;margin:0in 0in 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;co=
lor:rgb(64,64,64);background-image:initial;background-position:initial;back=
ground-size:initial;background-repeat:initial;background-origin:initial;bac=
kground-clip:initial">=D8=A7=D9=84=D8=A3=D8=B1=D9=82=D8=A7=D9=85 =D9=84=D8=
=A7 =D8=AA=D8=AA=D8=AD=D8=AF=D8=AB=E2=80=A6 =D8=A5=D9=84=D8=A7 =D9=84=D9=85=
=D9=86 =D9=8A=D8=B9=D8=B1=D9=81 =D9=84=D8=BA=D8=AA=D9=87=D8=A7.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;margin:0in 0in 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;co=
lor:rgb(64,64,64);background-image:initial;background-position:initial;back=
ground-size:initial;background-repeat:initial;background-origin:initial;bac=
kground-clip:initial">=D9=88=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D9=
=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=
=87=D9=88 =D9=85=D9=81=D8=AA=D8=A7=D8=AD =D9=81=D9=87=D9=85 =D8=A3=D8=AF=D8=
=A7=D8=A1
=D8=A7=D9=84=D8=B4=D8=B1=D9=83=D8=A7=D8=AA=D8=8C =D9=88=D8=A7=D8=AA=D8=AE=
=D8=A7=D8=B0 =D9=82=D8=B1=D8=A7=D8=B1=D8=A7=D8=AA =D9=85=D8=A7=D9=84=D9=8A=
=D8=A9 =D8=B0=D9=83=D9=8A=D8=A9 =D8=AA=D9=82=D9=88=D8=AF =D8=A5=D9=84=D9=89=
 =D8=A7=D9=84=D9=86=D9=85=D9=88 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AF=
=D8=A7=D9=85=D8=A9.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;margin:0in 0in 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=
=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;co=
lor:rgb(64,64,64);background-image:initial;background-position:initial;back=
ground-size:initial;background-repeat:initial;background-origin:initial;bac=
kground-clip:initial">=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D8=AA=D8=AD=D9=
=84=D9=8A=D9=84 =D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=D9=
=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=
=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9
=D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D9=8A=D8=A9 =D9=8A=D9=85=D9=86=D8=AD=D9=83 =D8=A7=D9=84=D9=82=D8=AF=
=D8=B1=D8=A9 =D8=B9=D9=84=D9=89 =D9=82=D8=B1=D8=A7=D8=A1=D8=A9 =D8=A7=D9=84=
=D9=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =
=D9=83=D8=AE=D8=A8=D9=8A=D8=B1=D8=8C =D9=88=D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =
=D9=82=D8=B1=D8=A7=D8=B1=D8=A7=D8=AA
=D9=85=D8=A8=D9=86=D9=8A=D8=A9 =D8=B9=D9=84=D9=89 =D8=AA=D8=AD=D9=84=D9=8A=
=D9=84 =D9=88=D8=A7=D9=82=D8=B9=D9=8A =D9=88=D8=AF=D9=82=D9=8A=D9=82.</span=
></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;background:black;margin:0in 0in 8pt;line-height:107%;direction:rtl;unic=
ode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D=
"AR-SA" style=3D"font-size:36pt;line-height:107%;font-family:&quot;Aref Ruq=
aa&quot;;color:white">=D8=AA=D8=AD=D9=84=D9=8A=D9=84
=D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=D9=85=D8=A7=D9=84=
=D9=8A=D8=A9</span><i><span dir=3D"LTR" style=3D"font-size:20pt;line-height=
:107%;font-family:&quot;Aref Ruqaa&quot;;color:rgb(56,86,35)"></span></i></=
p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><i><span dir=3D"LTR" style=3D"=
font-size:16pt;line-height:107%;font-family:&quot;Aref Ruqaa&quot;;color:rg=
b(192,0,0)">Financial
Statements Analysis</span></i></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><i><span lang=3D"AR-SA" style=
=3D"font-size:16pt;line-height:107%;font-family:&quot;Barada Reqa&quot;;col=
or:black">=D8=A7=D9=84=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE</span></i><span dir=3D=
"LTR"></span><span dir=3D"LTR"></span><i><span dir=3D"LTR" style=3D"font-si=
ze:16pt;line-height:107%;font-family:&quot;Aref Ruqaa&quot;;color:black"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span>:=C2=A0<b>25 =E2=80=93 30=
=C2=A0</b></span></i><b><i><span lang=3D"AR-SA" style=3D"font-size:16pt;lin=
e-height:107%;font-family:&quot;Barada Reqa&quot;;color:black">=D8=A3=D9=83=
=D8=AA=D9=88=D8=A8=D8=B1 2025</span></i></b><i><span dir=3D"LTR" style=3D"f=
ont-size:16pt;line-height:107%;font-family:&quot;Aref Ruqaa&quot;;color:bla=
ck"><br>
</span></i><i><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:107%=
;font-family:&quot;Barada Reqa&quot;;color:black">=D9=85=D9=83=D8=A7=D9=86 =
=D8=A7=D9=84=D8=A7=D9=86=D8=B9=D9=82=D8=A7=D8=AF</span></i><span dir=3D"LTR=
"></span><span dir=3D"LTR"></span><i><span dir=3D"LTR" style=3D"font-size:1=
6pt;line-height:107%;font-family:&quot;Aref Ruqaa&quot;;color:black"><span =
dir=3D"LTR"></span><span dir=3D"LTR"></span>:=C2=A0</span></i><b><i><span l=
ang=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;font-family:&quot;Ba=
rada Reqa&quot;;color:black">=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9 =E2=
=80=93
=D8=AC=D9=85=D9=87=D9=88=D8=B1=D9=8A=D8=A9 =D9=85=D8=B5=D8=B1 =D8=A7=D9=84=
=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9</span></i></b><i><span dir=3D"LTR" style=3D"=
font-size:16pt;line-height:107%;font-family:&quot;Aref Ruqaa&quot;;color:bl=
ack"><br>
=C2=A0</span></i><i><span lang=3D"AR-SA" style=3D"font-size:16pt;line-heigh=
t:107%;font-family:&quot;Barada Reqa&quot;;color:black">=D8=A7=D9=84=D9=85=
=D8=AF=D8=A9</span></i><span dir=3D"LTR"></span><span dir=3D"LTR"></span><i=
><span dir=3D"LTR" style=3D"font-size:16pt;line-height:107%;font-family:&qu=
ot;Aref Ruqaa&quot;;color:black"><span dir=3D"LTR"></span><span dir=3D"LTR"=
></span>:=C2=A0<b>5=C2=A0</b></span></i><b><i><span lang=3D"AR-SA" style=3D=
"font-size:16pt;line-height:107%;font-family:&quot;Barada Reqa&quot;;color:=
black">=D8=A3=D9=8A=D8=A7=D9=85</span></i></b><i><span dir=3D"LTR" style=3D=
"font-size:16pt;line-height:107%;font-family:&quot;Aref Ruqaa&quot;;color:b=
lack"></span></i></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><i><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;line-height:107%;font-family:&quot;Barada Reqa&quot;;c=
olor:black">=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D9=87=D9=86=D9=8A=D8=A9 =
=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =E2=80=93 =D9=85=D9=88=D8=AB=D9=82=D8=
=A9 =D9=88=D8=A8=D8=A7=D8=B9=D8=AA=D9=85=D8=A7=D8=AF =D8=AF=D9=88=D9=84=D9=
=8A</span></i></b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><i><=
span dir=3D"LTR" style=3D"font-size:16pt;line-height:107%;font-family:&quot=
;Aref Ruqaa&quot;;color:black"><span dir=3D"LTR"></span><span dir=3D"LTR"><=
/span>=C2=A0</span></i></b><b><i><span lang=3D"AR-SA" style=3D"font-size:16=
pt;line-height:107%;font-family:&quot;Barada Reqa&quot;;color:black">=D9=85=
=D8=B9=D8=AA=D8=B1=D9=81 =D8=A8=D9=87=D8=A7
=D9=81=D9=8A =D9=83=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=D8=AF=D9=88=D9=84</span>=
</i></b><i><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;fo=
nt-family:&quot;Barada Reqa&quot;;color:black"></span></i></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><b><i><span lang=3D"AR-SA" sty=
le=3D"font-size:16pt;line-height:107%;font-family:&quot;Barada Reqa&quot;;c=
olor:black">=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=
=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=
=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =E2=80=93=C2=A0</span></i></b><b><i><span di=
r=3D"LTR" style=3D"font-size:16pt;line-height:107%;font-family:&quot;Aref R=
uqaa&quot;;color:black">AHAD</span></i></b><i><span lang=3D"AR-SA" style=3D=
"font-size:16pt;line-height:107%;font-family:&quot;Barada Reqa&quot;;color:=
black"></span></i></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><i><span lang=3D"AR-SA" style=
=3D"font-size:16pt;line-height:107%;font-family:&quot;Barada Reqa&quot;;col=
or:black">=D8=AA=D8=AD=D9=8A=D8=A9 =D8=B7=D9=8A=D8=A8=D8=A9 =D9=88 =D8=A8=
=D8=B9=D8=AF =D8=8C=D8=8C=D8=8C</span></i></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><i><span lang=3D"AR-SA" style=
=3D"font-size:16pt;line-height:107%;font-family:&quot;Barada Reqa&quot;;col=
or:black">=D8=A3=D8=B7=D9=8A=D8=A8 =D8=A7=D9=84=D8=A3=D9=85=D9=86=D9=8A=D8=
=A7=D8=AA =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=8A=D8=A7=D8=AA=C2=A0=D8=AA=D9=
=87=D8=AF=D9=8A=D9=87=D8=A7
=D9=84=D9=83=D9=85=C2=A0=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=
=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=
=D9=84=D8=A7=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></i><i><span lang=3D"AR-JO=
" style=3D"font-size:16pt;line-height:107%;font-family:&quot;Barada Reqa&qu=
ot;;color:black">=C2=A0=D8=A8=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D8=B9=D8=
=AA=D9=85=D8=AF -=C2=A0</span></i><i><span dir=3D"LTR" style=3D"font-size:1=
6pt;line-height:107%;font-family:&quot;Aref Ruqaa&quot;;color:black">AHAD</=
span></i><i><span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;f=
ont-family:&quot;Barada Reqa&quot;;color:black"></span></i></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><i><span lang=3D"AR-SA" style=
=3D"font-size:16pt;line-height:107%;font-family:&quot;Barada Reqa&quot;;col=
or:rgb(192,0,0)">=C2=A0</span></i></p>

<p class=3D"gmail-MsoListParagraph" align=3D"center" dir=3D"RTL" style=3D"m=
argin:0in 14.15pt 8pt 0in;text-align:center;line-height:107%;direction:rtl;=
unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><b><span =
style=3D"font-size:20pt;line-height:107%;font-family:Wingdings;color:rgb(19=
2,0,0)">?<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:a=
uto;font-feature-settings:normal;font-weight:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-EG" style=3D"fo=
nt-size:24pt;line-height:107%;font-family:&quot;Tholoth Rounded&quot;;color=
:rgb(56,86,35)">=D8=A7=D9=84=D9=85=D9=86=D9=87=D8=AC
=D8=A7=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D9=8A =D9=84=D9=84=D8=A8=D8=B1=
=D9=86=D8=A7=D9=85=D8=AC :</span><span lang=3D"AR-SA" style=3D"font-size:14=
pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;c=
olor:rgb(64,64,64);background-image:initial;background-position:initial;bac=
kground-size:initial;background-repeat:initial;background-origin:initial;ba=
ckground-clip:initial"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,=
sans-serif;color:rgb(64,64,64);background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial">=D9=8A=D9=8F=D9=82=D8=AF=D9=91=D9=8E=D9=
=85 =D9=87=D8=B0=D8=A7 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D9=
=83=D9=85=D9=86=D9=87=D8=AC =D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D9=8A =D9=85=D8=
=AA=D9=83=D8=A7=D9=85=D9=84 =D9=8A=D9=87=D8=AF=D9=81
=D8=A5=D9=84=D9=89 =D8=AA=D9=85=D9=83=D9=8A=D9=86 =D8=A7=D9=84=D9=85=D8=B4=
=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D9=85=D9=86 =D9=82=D8=B1=D8=A7=D8=A1=D8=A9=
=D8=8C =D8=AA=D8=AD=D9=84=D9=8A=D9=84=D8=8C =D9=88=D8=AA=D9=81=D8=B3=D9=8A=
=D8=B1 =D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=D9=85=D8=A7=
=D9=84=D9=8A=D8=A9 =D8=A8=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D8=8C</span><=
/p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,=
sans-serif;color:rgb(64,64,64);background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial">=D9=88=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=
=A7=D9=85 =D9=86=D8=AA=D8=A7=D8=A6=D8=AC =D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=
=8A=D9=84 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D8=A7=D9=
=84=D9=85=D8=A7=D9=84=D9=8A=D8=8C =D8=AA=D9=82=D9=8A=D9=8A=D9=85
=D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1=D8=8C =D9=88=D8=A7=D8=AA=D8=AE=D8=A7=
=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=
=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A.</span><span dir=3D"LTR" style=3D"font=
-size:20pt;line-height:107%;font-family:AMoshref-Thulth;color:rgb(83,129,53=
);background-image:initial;background-position:initial;background-size:init=
ial;background-repeat:initial;background-origin:initial;background-clip:ini=
tial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><=
b><span style=3D"font-size:20pt;line-height:107%;font-family:Wingdings;colo=
r:rgb(192,0,0)">?<span style=3D"font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;font-size-adjust:none;font-k=
erning:auto;font-feature-settings:normal;font-weight:normal;font-stretch:no=
rmal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quo=
t;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-EG" style=3D"fo=
nt-size:24pt;line-height:107%;font-family:&quot;Tholoth Rounded&quot;;color=
:rgb(56,86,35)">=D8=A7=D9=84=D8=A3=D9=87=D8=AF=D8=A7=D9=81
=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D8=A9</span><span lang=3D"AR-SA" style=3D"fo=
nt-size:20pt;line-height:107%;font-family:AMoshref-Thulth;color:rgb(83,129,=
53);background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:rgb(64,64,64);background-image:initial;background-position:i=
nitial;background-size:initial;background-repeat:initial;background-origin:=
initial;background-clip:initial">=D8=AA=D9=85=D9=83=D9=8A=D9=86 =D8=A7=D9=
=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D9=85=D9=86 =D9=81=D9=87=D9=
=85 =D9=85=D9=83=D9=88=D9=86=D8=A7=D8=AA =D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=
=A6=D9=85 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9
=D8=A7=D9=84=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9 (=D9=82=D8=A7=D8=A6=D9=85=
=D8=A9 =D8=A7=D9=84=D8=AF=D8=AE=D9=84=D8=8C =D8=A7=D9=84=D9=85=D9=8A=D8=B2=
=D8=A7=D9=86=D9=8A=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=88=D9=85=D9=8A=D8=A9=
=D8=8C =D8=A7=D9=84=D8=AA=D8=AF=D9=81=D9=82=D8=A7=D8=AA =D8=A7=D9=84=D9=86=
=D9=82=D8=AF=D9=8A=D8=A9).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:rgb(64,64,64);background-image:initial;background-position:i=
nitial;background-size:initial;background-repeat:initial;background-origin:=
initial;background-clip:initial">=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D9=85=D9=
=87=D8=A7=D8=B1=D8=A9 =D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A3=D8=
=AF=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D8=A8=D8=A7=D8=B3=D8=
=AA=D8=AE=D8=AF=D8=A7=D9=85 =D9=85=D8=A4=D8=B4=D8=B1=D8=A7=D8=AA
=D8=A7=D9=84=D8=B3=D9=8A=D9=88=D9=84=D8=A9=D8=8C =D8=A7=D9=84=D8=B1=D8=A8=
=D8=AD=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=D9=84=D9=83=D9=81=D8=A7=D8=A1=D8=A9.<=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:rgb(64,64,64);background-image:initial;background-position:i=
nitial;background-size:initial;background-repeat:initial;background-origin:=
initial;background-clip:initial">=D8=A8=D9=86=D8=A7=D8=A1 =D8=A7=D9=84=D9=
=82=D8=AF=D8=B1=D8=A9 =D8=B9=D9=84=D9=89 =D8=AA=D9=82=D9=8A=D9=8A=D9=85 =D8=
=A7=D9=84=D9=85=D9=88=D9=82=D9=81 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D9=
=88=D8=A7=D8=AA=D8=AE=D8=A7=D8=B0
=D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1=D8=A7=D8=AA =D8=A8=D9=86=D8=A7=D8=A1=
=D9=8B =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=
=D9=84=D9=88=D8=A7=D9=82=D8=B9=D9=8A =D9=84=D9=84=D8=A3=D8=B1=D9=82=D8=A7=
=D9=85.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:rgb(64,64,64);background-image:initial;background-position:i=
nitial;background-size:initial;background-repeat:initial;background-origin:=
initial;background-clip:initial">=D8=A7=D9=84=D8=AA=D8=B9=D8=B1=D9=81 =D8=
=B9=D9=84=D9=89 =D8=A3=D9=87=D9=85 =D8=A7=D9=84=D9=85=D8=B9=D8=A7=D9=8A=D9=
=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D9=8A=D8=A9 =D8=A7=D9=
=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9 (</span><span dir=3D"LTR" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-s=
erif;color:rgb(64,64,64);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">IFRS</span><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:10=
7%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:rgb(64,64,64=
);background-image:initial;background-position:initial;background-size:init=
ial;background-repeat:initial;background-origin:initial;background-clip:ini=
tial"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>)
=D8=A7=D9=84=D9=85=D8=A4=D8=AB=D8=B1=D8=A9 =D9=81=D9=8A =D8=A5=D8=B9=D8=AF=
=D8=A7=D8=AF =D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:rgb(64,64,64);background-image:initial;background-position:i=
nitial;background-size:initial;background-repeat:initial;background-origin:=
initial;background-clip:initial">=D8=AA=D8=B7=D8=A8=D9=8A=D9=82 =D8=A3=D8=
=AF=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=
=84=D9=85=D8=A7=D9=84=D9=8A =D8=B9=D9=84=D9=89 =D8=AD=D8=A7=D9=84=D8=A7=D8=
=AA =D9=88=D8=A7=D9=82=D8=B9=D9=8A=D8=A9
=D9=88=D8=B4=D8=B1=D9=83=D8=A7=D8=AA =D8=AD=D9=82=D9=8A=D9=82=D9=8A=D8=A9 =
=D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=A8=D8=B1=D8=A7=D9=85=
=D8=AC =D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9<=
/span><span dir=3D"LTR" style=3D"font-size:20pt;line-height:107%;font-famil=
y:AMoshref-Thulth;color:rgb(83,129,53);background-image:initial;background-=
position:initial;background-size:initial;background-repeat:initial;backgrou=
nd-origin:initial;background-clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:20pt;line-height:107%;font-family:Wingdings;col=
or:rgb(192,0,0)">?<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;font-size-adjust:none;font-=
kerning:auto;font-feature-settings:normal;font-weight:normal;font-stretch:n=
ormal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&qu=
ot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-EG" style=3D"fo=
nt-size:24pt;line-height:107%;font-family:&quot;Tholoth Rounded&quot;;color=
:rgb(56,86,35)">=D8=A7=D9=84=D9=81=D8=A6=D8=A9
=C2=A0=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9:</span><span d=
ir=3D"LTR" style=3D"font-size:20pt;line-height:107%;font-family:AMoshref-Th=
ulth;color:rgb(83,129,53);background-image:initial;background-position:init=
ial;background-size:initial;background-repeat:initial;background-origin:ini=
tial;background-clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:black;background-image:initial;background-position:initial;b=
ackground-size:initial;background-repeat:initial;background-origin:initial;=
background-clip:initial">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D9=88=
=D9=86 =D9=88=D8=A7=D9=84=D9=85=D8=AF=D9=82=D9=82=D9=88=D9=86
=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D9=88=D9=86.</span><span lang=3D"AR-SA=
" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle B=
lack&quot;,sans-serif;background-image:initial;background-position:initial;=
background-size:initial;background-repeat:initial;background-origin:initial=
;background-clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:black;background-image:initial;background-position:initial;b=
ackground-size:initial;background-repeat:initial;background-origin:initial;=
background-clip:initial">=D9=85=D8=AD=D9=84=D9=84=D9=88 =D8=A7=D9=84=D8=A3=
=D8=B9=D9=85=D8=A7=D9=84 =D9=88=D9=85=D8=AF=D9=8A=D8=B1=D9=88
=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=A7=
=D9=84=D9=8A=D8=A9.</span><span lang=3D"AR-SA" style=3D"font-size:14pt;line=
-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;backgrou=
nd-image:initial;background-position:initial;background-size:initial;backgr=
ound-repeat:initial;background-origin:initial;background-clip:initial"></sp=
an></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:black;background-image:initial;background-position:initial;b=
ackground-size:initial;background-repeat:initial;background-origin:initial;=
background-clip:initial">=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D8=AB=D9=85=D8=B1=
=D9=88=D9=86 =D9=88=D8=B1=D9=88=D8=A7=D8=AF =D8=A7=D9=84=D8=A3=D8=B9=D9=85=
=D8=A7=D9=84
=D8=A7=D9=84=D8=B0=D9=8A=D9=86 =D9=8A=D8=B1=D8=BA=D8=A8=D9=88=D9=86 =D9=81=
=D9=8A =D9=82=D8=B1=D8=A7=D8=A1=D8=A9 =D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=
=D9=85 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D8=A8=D8=B0=D9=83=D8=A7=
=D8=A1 =D8=A7=D8=B3=D8=AA=D8=AB=D9=85=D8=A7=D8=B1=D9=8A.</span><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSha=
rkTitle Black&quot;,sans-serif;background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:black;background-image:initial;background-position:initial;b=
ackground-size:initial;background-repeat:initial;background-origin:initial;=
background-clip:initial">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=
=D8=B4=D8=A7=D8=B1=D9=8A=D8=B9
=D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88=D9=86 =D8=A7=D9=84=
=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A=D9=88=D9=86 =D8=A7=D9=84=D8=B0=D9=8A=
=D9=86 =D9=8A=D8=AD=D8=AA=D8=A7=D8=AC=D9=88=D9=86 =D8=A5=D9=84=D9=89 =D8=AA=
=D9=81=D8=B3=D9=8A=D8=B1 =D8=A7=D9=84=D9=86=D8=AA=D8=A7=D8=A6=D8=AC =D8=A7=
=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=84=D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =
=D9=82=D8=B1=D8=A7=D8=B1=D8=A7=D8=AA
=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9.</span><span l=
ang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:&quot;Al=
SharkTitle Black&quot;,sans-serif;background-image:initial;background-posit=
ion:initial;background-size:initial;background-repeat:initial;background-or=
igin:initial;background-clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 0.25in 8pt 0in;text-align:center;line-height:107%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><b=
><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<=
span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-f=
eature-settings:normal;font-weight:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:black;background-image:initial;background-position:initial;b=
ackground-size:initial;background-repeat:initial;background-origin:initial;=
background-clip:initial">=D8=B7=D9=84=D8=A7=D8=A8 =D9=83=D9=84=D9=8A=D8=A7=
=D8=AA =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A3=D8=B9=D9=85=D8=A7=
=D9=84
=D9=88=D8=A7=D9=84=D8=A7=D9=82=D8=AA=D8=B5=D8=A7=D8=AF =D8=A7=D9=84=D8=B1=
=D8=A7=D8=BA=D8=A8=D9=88=D9=86 =D9=81=D9=8A =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =
=D9=85=D8=B3=D8=A7=D8=B1 =D9=85=D9=87=D9=86=D9=8A =D8=A7=D8=AD=D8=AA=D8=B1=
=D8=A7=D9=81=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =
=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A.</span><span dir=3D"LTR" style=3D"font=
-size:20pt;line-height:107%;font-family:AMoshref-Thulth;color:rgb(83,129,53=
);background-image:initial;background-position:initial;background-size:init=
ial;background-repeat:initial;background-origin:initial;background-clip:ini=
tial"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:20pt;line-height:107%;font-family:AMoshref-Thulth;color:rgb(83,12=
9,53);background-image:initial;background-position:initial;background-size:=
initial;background-repeat:initial;background-origin:initial;background-clip=
:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"fon=
t-size:20pt;line-height:107%;font-family:AMoshref-Thulth;color:rgb(83,129,5=
3);background-image:initial;background-position:initial;background-size:ini=
tial;background-repeat:initial;background-origin:initial;background-clip:in=
itial">=C2=A0</span></p>

<p class=3D"gmail-MsoListParagraph" align=3D"center" dir=3D"RTL" style=3D"m=
argin:0in 0.25in 8pt 0in;text-align:center;line-height:107%;direction:rtl;u=
nicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><b><span s=
tyle=3D"font-size:20pt;line-height:107%;font-family:Wingdings;color:rgb(192=
,0,0)">?<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:au=
to;font-feature-settings:normal;font-weight:normal;font-stretch:normal;font=
-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-EG" style=3D"fo=
nt-size:24pt;line-height:107%;font-family:&quot;Segoe UI Symbol&quot;,sans-=
serif;color:rgb(56,86,35)">=F0=9F=93=9A</span><span lang=3D"AR-EG" style=3D=
"font-size:24pt;line-height:107%;font-family:&quot;Tholoth Rounded&quot;;co=
lor:rgb(56,86,35)">
=D9=85=D8=AD=D8=A7=D9=88=D8=B1 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=
=D8=AC =D8=A7=D9=84=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9:</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 7.1=
pt 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,sans-seri=
f;background:lightgrey">=F0=9F=A7=A9 =D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =
=D8=A7=D9=84=D8=A3=D9=88=D9=84: =D9=85=D8=AF=D8=AE=D9=84 =D8=A5=D9=84=D9=89=
 =D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=D9=85=D8=A7=D9=84=
=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"text-align:center;margin:0in 0.5in 0in 0in;line-height:107%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><s=
pan style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<spa=
n style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-feat=
ure-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fo=
nt-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></sp=
an><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;li=
ne-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:=
rgb(64,64,64);background-image:initial;background-position:initial;backgrou=
nd-size:initial;background-repeat:initial;background-origin:initial;backgro=
und-clip:initial">=D9=85=D8=A7=D9=87=D9=8A=D8=A9
=D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=D9=85=D8=A7=D9=84=
=D9=8A=D8=A9 =D9=88=D8=A3=D9=87=D9=85=D9=8A=D8=AA=D9=87=D8=A7 =D9=81=D9=8A =
=D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1.</span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"text-align:center;margin:0in 0.5in 0in 0in;line-height:107%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><=
span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<sp=
an style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-fea=
ture-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;f=
ont-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></s=
pan><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;l=
ine-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color=
:rgb(64,64,64);background-image:initial;background-position:initial;backgro=
und-size:initial;background-repeat:initial;background-origin:initial;backgr=
ound-clip:initial">=D8=A7=D9=84=D9=81=D8=B1=D9=82
=D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=
=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D9=82=D8=A7=D8=B1=
=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"text-align:center;margin:0in 0.5in 8pt 0in;line-height:107%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><sp=
an style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></spa=
n><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;lin=
e-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:r=
gb(64,64,64);background-image:initial;background-position:initial;backgroun=
d-size:initial;background-repeat:initial;background-origin:initial;backgrou=
nd-clip:initial">=D8=A3=D9=86=D9=88=D8=A7=D8=B9
=D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=D9=85=D8=A7=D9=84=
=D9=8A=D8=A9 (=D8=A7=D9=84=D8=AF=D8=AE=D9=84=D8=8C =D8=A7=D9=84=D9=85=D9=8A=
=D8=B2=D8=A7=D9=86=D9=8A=D8=A9=D8=8C =D8=A7=D9=84=D8=AA=D8=AF=D9=81=D9=82=
=D8=A7=D8=AA =D8=A7=D9=84=D9=86=D9=82=D8=AF=D9=8A=D8=A9=D8=8C =D8=A7=D9=84=
=D8=AA=D8=BA=D9=8A=D8=B1 =D9=81=D9=8A =D8=AD=D9=82=D9=88=D9=82 =D8=A7=D9=84=
=D9=85=D9=84=D9=83=D9=8A=D8=A9).</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,=
sans-serif;color:rgb(64,64,64);background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 7.1=
pt 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Segoe UI Symbol&quot;,sans-serif;b=
ackground:lightgrey">=F0=9F=92=A1</span><span lang=3D"AR-SA" style=3D"font-=
size:16pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;background:=
lightgrey"> =D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=AB=D8=A7=
=D9=86=D9=8A: =D8=A7=D9=84=D8=A5=D8=B7=D8=A7=D8=B1
=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D9=8A =D9=88=D8=A7=D9=84=D9=85=
=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D8=AF=D9=88=D9=84=D9=8A=D8=A9</=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"text-align:center;margin:0in 0.5in 0in 0in;line-height:107%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><s=
pan style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<spa=
n style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-feat=
ure-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fo=
nt-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></sp=
an><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;li=
ne-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:=
rgb(64,64,64);background-image:initial;background-position:initial;backgrou=
nd-size:initial;background-repeat:initial;background-origin:initial;backgro=
und-clip:initial">=D8=A7=D9=84=D9=85=D8=A8=D8=A7=D8=AF=D8=A6
=D9=88=D8=A7=D9=84=D9=85=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=
=D8=AD=D8=A7=D8=B3=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=A4=D8=AB=D8=B1=
=D8=A9 (</span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;f=
ont-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:rgb(64,64,64);ba=
ckground-image:initial;background-position:initial;background-size:initial;=
background-repeat:initial;background-origin:initial;background-clip:initial=
">IFRS</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSha=
rkTitle Black&quot;,sans-serif;color:rgb(64,64,64);background-image:initial=
;background-position:initial;background-size:initial;background-repeat:init=
ial;background-origin:initial;background-clip:initial"><span dir=3D"RTL"></=
span><span dir=3D"RTL"></span>).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"text-align:center;margin:0in 0.5in 0in 0in;line-height:107%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><=
span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<sp=
an style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-fea=
ture-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;f=
ont-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></s=
pan><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;l=
ine-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color=
:rgb(64,64,64);background-image:initial;background-position:initial;backgro=
und-size:initial;background-repeat:initial;background-origin:initial;backgr=
ound-clip:initial">=D8=A3=D8=B3=D8=B3
=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85 =
=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=A5=D9=81=
=D8=B5=D8=A7=D8=AD =D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D9=8A.</span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"text-align:center;margin:0in 0.5in 8pt 0in;line-height:107%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><sp=
an style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></spa=
n><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;lin=
e-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:r=
gb(64,64,64);background-image:initial;background-position:initial;backgroun=
d-size:initial;background-repeat:initial;background-origin:initial;backgrou=
nd-clip:initial">=D8=AC=D9=88=D8=AF=D8=A9
=D8=A7=D9=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D9=85=
=D8=A7=D9=84=D9=8A=D8=A9 =D9=88=D8=A3=D8=AB=D8=B1=D9=87=D8=A7 =D8=B9=D9=84=
=D9=89 =D8=A7=D9=84=D9=85=D9=88=D8=AB=D9=88=D9=82=D9=8A=D8=A9.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,=
sans-serif;color:rgb(64,64,64);background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 7.1=
pt 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Segoe UI Symbol&quot;,sans-serif;b=
ackground:lightgrey">=F0=9F=93=8A</span><span lang=3D"AR-SA" style=3D"font-=
size:16pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;background:=
lightgrey"> =D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=AB=D8=A7=
=D9=84=D8=AB: =D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84
=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D8=A7=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=
=D9=82=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"text-align:center;margin:0in 0.5in 0in 0in;line-height:107%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><s=
pan style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<spa=
n style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-feat=
ure-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fo=
nt-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></sp=
an><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;li=
ne-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:=
rgb(64,64,64);background-image:initial;background-position:initial;backgrou=
nd-size:initial;background-repeat:initial;background-origin:initial;backgro=
und-clip:initial">=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85
=D8=A7=D9=84=D9=86=D8=B3=D8=A8 =D9=88=D8=A7=D9=84=D9=85=D8=A4=D8=B4=D8=B1=
=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=84=D8=AA=D8=AD=
=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"text-align:center;margin:0in 0.5in 0in 0in;line-height:107%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><=
span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<sp=
an style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-fea=
ture-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;f=
ont-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></s=
pan><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;l=
ine-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color=
:rgb(64,64,64);background-image:initial;background-position:initial;backgro=
und-size:initial;background-repeat:initial;background-origin:initial;backgr=
ound-clip:initial">=D8=AA=D8=AD=D9=84=D9=8A=D9=84
=D8=A7=D9=84=D8=B3=D9=8A=D9=88=D9=84=D8=A9 =D9=88=D8=A7=D9=84=D8=B1=D8=A8=
=D8=AD=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D9=88=
=D9=87=D9=8A=D9=83=D9=84 =D8=A7=D9=84=D8=AA=D9=85=D9=88=D9=8A=D9=84.</span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"text-align:center;margin:0in 0.5in 0in 0in;line-height:107%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><=
span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<sp=
an style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-fea=
ture-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;f=
ont-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></s=
pan><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;l=
ine-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color=
:rgb(64,64,64);background-image:initial;background-position:initial;backgro=
und-size:initial;background-repeat:initial;background-origin:initial;backgr=
ound-clip:initial">=D8=AA=D8=AD=D9=84=D9=8A=D9=84
=D8=A7=D9=84=D8=A7=D8=AA=D8=AC=D8=A7=D9=87=D8=A7=D8=AA (</span><span dir=3D=
"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTit=
le Black&quot;,sans-serif;color:rgb(64,64,64);background-image:initial;back=
ground-position:initial;background-size:initial;background-repeat:initial;b=
ackground-origin:initial;background-clip:initial">Trend
Analysis</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=
=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSha=
rkTitle Black&quot;,sans-serif;color:rgb(64,64,64);background-image:initial=
;background-position:initial;background-size:initial;background-repeat:init=
ial;background-origin:initial;background-clip:initial"><span dir=3D"RTL"></=
span><span dir=3D"RTL"></span>)
=D9=88=D8=A7=D9=84=D9=85=D9=82=D8=A7=D8=B1=D9=86=D8=A7=D8=AA =D8=A7=D9=84=
=D8=A3=D9=81=D9=82=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=B1=D8=A3=D8=B3=D9=8A=
=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"text-align:center;margin:0in 0.5in 8pt 0in;line-height:107%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><sp=
an style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></spa=
n><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;lin=
e-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:r=
gb(64,64,64);background-image:initial;background-position:initial;backgroun=
d-size:initial;background-repeat:initial;background-origin:initial;backgrou=
nd-clip:initial">=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA
=D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=
=D9=85 =D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D8=B4=D8=B1=D9=83=D8=A7=D8=AA =
=D8=AD=D9=82=D9=8A=D9=82=D9=8A=D8=A9.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,=
sans-serif;color:rgb(64,64,64);background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 7.1=
pt 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Segoe UI Symbol&quot;,sans-serif;b=
ackground:lightgrey">=F0=9F=92=B0</span><span lang=3D"AR-SA" style=3D"font-=
size:16pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;background:=
lightgrey"> =D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=B1=D8=A7=
=D8=A8=D8=B9: =D8=AA=D9=81=D8=B3=D9=8A=D8=B1
=D8=A7=D9=84=D9=86=D8=AA=D8=A7=D8=A6=D8=AC =D9=88=D8=A7=D8=AA=D8=AE=D8=A7=
=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"text-align:center;margin:0in 0.5in 0in 0in;line-height:107%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><s=
pan style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<spa=
n style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-feat=
ure-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fo=
nt-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></sp=
an><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;li=
ne-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:=
rgb(64,64,64);background-image:initial;background-position:initial;backgrou=
nd-size:initial;background-repeat:initial;background-origin:initial;backgro=
und-clip:initial">=D8=B1=D8=A8=D8=B7
=D9=86=D8=AA=D8=A7=D8=A6=D8=AC =D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =
=D8=A8=D8=A7=D9=84=D8=A3=D9=87=D8=AF=D8=A7=D9=81 =D8=A7=D9=84=D8=A7=D8=B3=
=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9 =D9=84=D9=84=D9=85=D8=A4=
=D8=B3=D8=B3=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"text-align:center;margin:0in 0.5in 0in 0in;line-height:107%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><=
span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<sp=
an style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-fea=
ture-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;f=
ont-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></s=
pan><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;l=
ine-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color=
:rgb(64,64,64);background-image:initial;background-position:initial;backgro=
und-size:initial;background-repeat:initial;background-origin:initial;backgr=
ound-clip:initial">=D9=82=D8=B1=D8=A7=D8=A1=D8=A9
=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D9=85=D8=A7=D9=84=
=D9=8A =D9=81=D9=8A =D8=B6=D9=88=D8=A1 =D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D8=A9=
 =D8=A7=D9=84=D8=A7=D9=82=D8=AA=D8=B5=D8=A7=D8=AF=D9=8A=D8=A9 =D9=88=D8=A7=
=D9=84=D8=B3=D9=88=D9=82=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"text-align:center;margin:0in 0.5in 8pt 0in;line-height:107%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><sp=
an style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featu=
re-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;fon=
t-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></spa=
n><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;lin=
e-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:r=
gb(64,64,64);background-image:initial;background-position:initial;backgroun=
d-size:initial;background-repeat:initial;background-origin:initial;backgrou=
nd-clip:initial">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
=D8=A7=D9=84=D8=AA=D9=82=D8=A7=D8=B1=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AD=
=D9=84=D9=8A=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=AC=D9=87=D8=A9 =
=D9=84=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B9=D9=84=D9=8A=
=D8=A7 =D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D8=AB=D9=85=D8=B1=D9=8A=D9=86.<=
/span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,=
sans-serif;color:rgb(64,64,64);background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 7.1=
pt 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" s=
tyle=3D"font-size:16pt;font-family:&quot;Segoe UI Symbol&quot;,sans-serif;b=
ackground:lightgrey">=E2=9A=99=EF=B8=8F</span><span lang=3D"AR-SA" style=3D=
"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;backg=
round:lightgrey"> =D8=A7=D9=84=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=AE=
=D8=A7=D9=85=D8=B3: =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=A3=D8=AF=
=D9=88=D8=A7=D8=AA
=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=
=D8=AB=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><=
b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8=
<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-=
feature-settings:normal;font-weight:normal;font-stretch:normal;font-size:7p=
t;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:rgb(64,64,64);background-image:initial;background-position:i=
nitial;background-size:initial;background-repeat:initial;background-origin:=
initial;background-clip:initial">=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84=
 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=A8=D8=B1=D8=A7=D9=85=
=D8=AC =D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=85=D8=AA=D9=82=D8=AF=D9=85=D8=A9 =
(=D9=85=D8=AB=D9=84 </span><span dir=3D"LTR" style=3D"font-size:14pt;line-h=
eight:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:rgb(=
64,64,64);background-image:initial;background-position:initial;background-s=
ize:initial;background-repeat:initial;background-origin:initial;background-=
clip:initial">Excel</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span=
><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:=
&quot;AlSharkTitle Black&quot;,sans-serif;color:rgb(64,64,64);background-im=
age:initial;background-position:initial;background-size:initial;background-=
repeat:initial;background-origin:initial;background-clip:initial"><span dir=
=3D"RTL"></span><span dir=3D"RTL"></span> =D9=88</span><span dir=3D"LTR" st=
yle=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black=
&quot;,sans-serif;color:rgb(64,64,64);background-image:initial;background-p=
osition:initial;background-size:initial;background-repeat:initial;backgroun=
d-origin:initial;background-clip:initial">DEXEF</span><span dir=3D"RTL"></s=
pan><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;l=
ine-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color=
:rgb(64,64,64);background-image:initial;background-position:initial;backgro=
und-size:initial;background-repeat:initial;background-origin:initial;backgr=
ound-clip:initial"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>).</sp=
an></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:rgb(64,64,64);background-image:initial;background-position:i=
nitial;background-size:initial;background-repeat:initial;background-origin:=
initial;background-clip:initial">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=AA=D9=
=82=D8=A7=D8=B1=D9=8A=D8=B1 =D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D8=A7=D8=AD=D8=
=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9 =D9=82=D8=A7=D8=A8=D9=84=D8=A9 =D9=84=D9=
=84=D8=B9=D8=B1=D8=B6
=D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 0.25in 8pt 0in;text-align:center;line-height:107%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><b=
><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<=
span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-f=
eature-settings:normal;font-weight:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sa=
ns-serif;color:rgb(64,64,64);background-image:initial;background-position:i=
nitial;background-size:initial;background-repeat:initial;background-origin:=
initial;background-clip:initial">=D9=85=D8=A4=D8=B4=D8=B1=D8=A7=D8=AA =D8=
=A7=D9=84=D9=82=D9=8A=D9=85=D8=A9 =D8=A7=D9=84=D9=85=D8=B6=D8=A7=D9=81=D8=
=A9 =D8=A7=D9=84=D8=A7=D9=82=D8=AA=D8=B5=D8=A7=D8=AF=D9=8A=D8=A9 (</span><s=
pan dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;=
AlSharkTitle Black&quot;,sans-serif;color:rgb(64,64,64);background-image:in=
itial;background-position:initial;background-size:initial;background-repeat=
:initial;background-origin:initial;background-clip:initial">EVA</span><span=
 dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,=
sans-serif;color:rgb(64,64,64);background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial"><span dir=3D"RTL"></span><span dir=3D"RT=
L"></span>)
=D9=88=D8=A7=D9=84=D8=B9=D8=A7=D8=A6=D8=AF =D8=B9=D9=84=D9=89 =D8=A7=D9=84=
=D8=A7=D8=B3=D8=AA=D8=AB=D9=85=D8=A7=D8=B1 (</span><span dir=3D"LTR" style=
=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif;color:rgb(64,64,64);background-image:initial;background-posi=
tion:initial;background-size:initial;background-repeat:initial;background-o=
rigin:initial;background-clip:initial">ROI</span><span dir=3D"RTL"></span><=
span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-h=
eight:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:rgb(=
64,64,64);background-image:initial;background-position:initial;background-s=
ize:initial;background-repeat:initial;background-origin:initial;background-=
clip:initial"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>).</span><s=
pan dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;=
AlSharkTitle Black&quot;,sans-serif;color:rgb(64,64,64);background-image:in=
itial;background-position:initial;background-size:initial;background-repeat=
:initial;background-origin:initial;background-clip:initial"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,=
sans-serif;color:rgb(64,64,64);background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=3D"=
font-size:24pt;line-height:107%;font-family:&quot;Tholoth Rounded&quot;;col=
or:rgb(56,86,35)">=D9=85=D8=AE=D8=B1=D8=AC=D8=A7=D8=AA
=D8=A7=D9=84=D8=AA=D8=B9=D9=84=D9=85 =D8=A7=D9=84=D9=85=D8=AA=D9=88=D9=82=
=D8=B9=D8=A9</span><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height=
:107%;font-family:AMoshref-Thulth;color:rgb(83,129,53);background-image:ini=
tial;background-position:initial;background-size:initial;background-repeat:=
initial;background-origin:initial;background-clip:initial"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,=
sans-serif;color:rgb(64,64,64);background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial">=D8=A8=D9=86=D9=87=D8=A7=D9=8A=D8=A9 =D8=
=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC=D8=8C =D8=B3=D9=8A=D9=83=D9=
=88=D9=86 =D8=A7=D9=84=D9=85=D8=AA=D8=AF=D8=B1=D8=A8 =D9=82=D8=A7=D8=AF=D8=
=B1=D9=8B=D8=A7 =D8=B9=D9=84=D9=89:</span><span dir=3D"LTR" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-s=
erif;color:rgb(64,64,64);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><=
span dir=3D"RTL"></span><b><span style=3D"font-size:14pt;line-height:107%;f=
ont-family:Symbol">=C2=A8<span style=3D"font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;font-size-adjust:non=
e;font-kerning:auto;font-feature-settings:normal;font-weight:normal;font-st=
retch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New R=
oman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0 </span></span></b><span dir=3D"RTL"></=
span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA"=
 style=3D"font-size:14pt;line-height:107%;font-family:&quot;Segoe UI Symbol=
&quot;,sans-serif;color:rgb(64,64,64);background-image:initial;background-p=
osition:initial;background-size:initial;background-repeat:initial;backgroun=
d-origin:initial;background-clip:initial"><span dir=3D"RTL"></span><span di=
r=3D"RTL"></span>=E2=9C=85</span><span lang=3D"AR-SA" style=3D"font-size:14=
pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;c=
olor:rgb(64,64,64);background-image:initial;background-position:initial;bac=
kground-size:initial;background-repeat:initial;background-origin:initial;ba=
ckground-clip:initial"> =D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D9=88=D9=82=D8=B1=
=D8=A7=D8=A1=D8=A9 =D8=A7=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=
=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D8=A8=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81.<=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;Segoe UI Symbol&quot;,sans-=
serif;color:rgb(64,64,64);background-image:initial;background-position:init=
ial;background-size:initial;background-repeat:initial;background-origin:ini=
tial;background-clip:initial">=E2=9C=85</span><span lang=3D"AR-SA" style=3D=
"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;=
,sans-serif;color:rgb(64,64,64);background-image:initial;background-positio=
n:initial;background-size:initial;background-repeat:initial;background-orig=
in:initial;background-clip:initial"> =D8=AA=D8=B7=D8=A8=D9=8A=D9=82 =D8=A3=
=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=
=D9=84=D9=85=D8=A7=D9=84=D9=8A =D8=B9=D9=84=D9=89 =D8=AD=D8=A7=D9=84=D8=A7=
=D8=AA =D8=B9=D9=85=D9=84=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;Segoe UI Symbol&quot;,sans-=
serif;color:rgb(64,64,64);background-image:initial;background-position:init=
ial;background-size:initial;background-repeat:initial;background-origin:ini=
tial;background-clip:initial">=E2=9C=85</span><span lang=3D"AR-SA" style=3D=
"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;=
,sans-serif;color:rgb(64,64,64);background-image:initial;background-positio=
n:initial;background-size:initial;background-repeat:initial;background-orig=
in:initial;background-clip:initial"> =D8=AA=D9=82=D9=8A=D9=8A=D9=85 =D8=A7=
=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D9=84=
=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D8=A8=D9=85=D8=A4=D8=B4=D8=B1=
=D8=A7=D8=AA =D8=AF=D9=82=D9=8A=D9=82=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 0.25in 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<b><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=
=A8<span style=3D"font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;fo=
nt-feature-settings:normal;font-weight:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;Segoe UI Symbol&quot;,sans-=
serif;color:rgb(64,64,64);background-image:initial;background-position:init=
ial;background-size:initial;background-repeat:initial;background-origin:ini=
tial;background-clip:initial">=E2=9C=85</span><span lang=3D"AR-SA" style=3D=
"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;=
,sans-serif;color:rgb(64,64,64);background-image:initial;background-positio=
n:initial;background-size:initial;background-repeat:initial;background-orig=
in:initial;background-clip:initial"> =D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=AA=
=D9=82=D8=A7=D8=B1=D9=8A=D8=B1 =D8=AA=D8=AD=D9=84=D9=8A=D9=84=D9=8A=D8=A9 =
=D8=AA=D8=A8=D8=B1=D8=B2 =D9=86=D9=82=D8=A7=D8=B7 =D8=A7=D9=84=D9=82=D9=88=
=D8=A9 =D9=88=D8=A7=D9=84=D8=B6=D8=B9=D9=81.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 0.25in 8pt 0in;text-align:center;line-height:107%;directi=
on:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><b=
><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<=
span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-f=
eature-settings:normal;font-weight:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=
=C2=A0=C2=A0
</span></span></b><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;Segoe UI Symbol&quot;,sans-=
serif;color:rgb(64,64,64);background-image:initial;background-position:init=
ial;background-size:initial;background-repeat:initial;background-origin:ini=
tial;background-clip:initial">=E2=9C=85</span><span lang=3D"AR-SA" style=3D=
"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;=
,sans-serif;color:rgb(64,64,64);background-image:initial;background-positio=
n:initial;background-size:initial;background-repeat:initial;background-orig=
in:initial;background-clip:initial"> =D8=AA=D9=82=D8=AF=D9=8A=D9=85 =D8=AA=
=D9=88=D8=B5=D9=8A=D8=A7=D8=AA =D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=85=D8=AF=
=D8=B1=D9=88=D8=B3=D8=A9 =D8=AA=D8=AF=D8=B9=D9=85 =D8=A7=D8=AA=D8=AE=D8=A7=
=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D9=8A
=D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AB=D9=85=D8=A7=D8=B1=D9=8A</span><s=
pan dir=3D"LTR" style=3D"font-size:20pt;line-height:107%;font-family:AMoshr=
ef-Thulth;color:rgb(83,129,53);background-image:initial;background-position=
:initial;background-size:initial;background-repeat:initial;background-origi=
n:initial;background-clip:initial"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=3D"=
font-size:24pt;line-height:107%;font-family:&quot;Tholoth Rounded&quot;;col=
or:rgb(56,86,35)">=D8=B7=D8=B1=D9=82
=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8</span><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:107%;font-family:AMoshref-Thulth;color:rgb(8=
3,129,53);background-image:initial;background-position:initial;background-s=
ize:initial;background-repeat:initial;background-origin:initial;background-=
clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 21.25pt 0in 0in;text-align:center;line-height:107%;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<s=
pan style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fon=
t-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-fe=
ature-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;=
font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-s=
erif;color:rgb(64,64,64);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">=D9=85=D8=AD=D8=A7=D8=B6=D8=B1=D8=A7=D8=AA =D8=
=AA=D9=81=D8=A7=D8=B9=D9=84=D9=8A=D8=A9=D8=8C =D8=AF=D8=B1=D8=A7=D8=B3=D8=
=A7=D8=AA =D8=AD=D8=A7=D9=84=D8=A9 =D9=85=D8=AD=D9=84=D9=8A=D8=A9.</span></=
p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 21.25pt 0in 0in;text-align:center;line-height:107%;dire=
ction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"=
><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<=
span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-f=
eature-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal=
;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-s=
erif;color:rgb(64,64,64);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">=D9=88=D8=B1=D8=B4 =D8=B9=D9=85=D9=84 =D8=AA=
=D8=B7=D8=A8=D9=8A=D9=82=D9=8A=D8=A9=D8=8C =D9=85=D8=AD=D8=A7=D9=83=D8=A7=
=D8=A9 =D8=AA=D8=AF=D9=82=D9=8A=D9=82=D8=8C =D8=AA=D9=85=D8=A7=D8=B1=D9=8A=
=D9=86 =D8=AC=D9=85=D8=A7=D8=B9=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 21.25pt 0in 0in;text-align:center;line-height:107%;dire=
ction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"=
><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<=
span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-f=
eature-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal=
;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-s=
erif;color:rgb(64,64,64);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">=D9=82=D9=88=D8=A7=D9=84=D8=A8 =D8=B9=D9=85=D9=
=84=D9=8A=D8=A9 =D9=88=D9=86=D9=85=D8=A7=D8=B0=D8=AC =D9=82=D8=A7=D8=A8=D9=
=84=D8=A9 =D9=84=D9=84=D8=AA=D8=B9=D8=AF=D9=8A=D9=84 (</span><span dir=3D"L=
TR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle=
 Black&quot;,sans-serif;color:rgb(64,64,64);background-image:initial;backgr=
ound-position:initial;background-size:initial;background-repeat:initial;bac=
kground-origin:initial;background-clip:initial">SOPs, Checklists, Forms</sp=
an><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" s=
tyle=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Blac=
k&quot;,sans-serif;color:rgb(64,64,64);background-image:initial;background-=
position:initial;background-size:initial;background-repeat:initial;backgrou=
nd-origin:initial;background-clip:initial"><span dir=3D"RTL"></span><span d=
ir=3D"RTL"></span>).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 21.25pt 0in 0in;text-align:center;line-height:107%;dire=
ction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"=
><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<=
span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-f=
eature-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal=
;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-s=
erif;color:rgb(64,64,64);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">=D8=B4=D8=B1=D8=A7=D8=A6=D8=AD =D8=AA=D9=82=D8=
=AF=D9=8A=D9=85=D9=8A=D8=A9 (</span><span dir=3D"LTR" style=3D"font-size:14=
pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;c=
olor:rgb(64,64,64);background-image:initial;background-position:initial;bac=
kground-size:initial;background-repeat:initial;background-origin:initial;ba=
ckground-clip:initial">PowerPoint</span><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:10=
7%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:rgb(64,64,64=
);background-image:initial;background-position:initial;background-size:init=
ial;background-repeat:initial;background-origin:initial;background-clip:ini=
tial"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>) =D9=84=D9=83=D9=
=84 =D8=AC=D9=84=D8=B3=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 21.25pt 8pt 0in;text-align:center;line-height:107%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"><=
span style=3D"font-size:14pt;line-height:107%;font-family:Symbol">=C2=A8<sp=
an style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-fea=
ture-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;f=
ont-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-s=
erif;color:rgb(64,64,64);background-image:initial;background-position:initi=
al;background-size:initial;background-repeat:initial;background-origin:init=
ial;background-clip:initial">=D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=AF=D8=B1=D8=
=A7=D8=B3=D9=8A=D8=A9 =D9=88=D8=A7=D9=82=D8=B9=D9=8A=D8=A9 =D9=88=D8=AA=D9=
=85=D8=A7=D8=B1=D9=8A=D9=86 =D9=85=D9=8A=D8=AF=D8=A7=D9=86=D9=8A=D8=A9 =D9=
=82=D8=B5=D9=8A=D8=B1=D8=A9.</span><span dir=3D"LTR" style=3D"font-size:14p=
t;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif;co=
lor:rgb(64,64,64);background-image:initial;background-position:initial;back=
ground-size:initial;background-repeat:initial;background-origin:initial;bac=
kground-clip:initial"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=3D"=
font-size:24pt;line-height:107%;font-family:&quot;Tholoth Rounded&quot;;col=
or:rgb(56,86,35)">=D8=AA=D9=86=D9=88=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 21.25pt 0in 0in;text-align:center;line-height:normal;dir=
ection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif=
"><span style=3D"font-size:14pt;font-family:Symbol">=C2=A8<span style=3D"fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=AC=D9=
=85=D9=8A=D8=B9
=D8=A7=D9=84=D8=B4=D9=87=D8=A7=D8=AF=D8=A7=D8=AA =D8=AA=D8=B4=D9=85=D9=84 =
=D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9=D8=8C =
=D8=AD=D9=82=D9=8A=D8=A8=D8=A9 =D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9.<=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 21.25pt 0in 0in;text-align:center;line-height:normal;di=
rection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-seri=
f"><span style=3D"font-size:14pt;font-family:Symbol">=C2=A8<span style=3D"f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings=
:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&q=
uot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D9=8A=D9=
=85=D9=83=D9=86 =D8=AA=D9=86=D9=81=D9=8A=D8=B0
=D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=AD=D8=B6=D9=88=D8=B1=D9=8A=
=D9=8B=D8=A7 =D8=A3=D9=88 =D8=A3=D9=88=D9=86=D9=84=D8=A7=D9=8A=D9=86 =D8=B9=
=D8=A8=D8=B1 </span><span dir=3D"LTR" style=3D"font-size:14pt;font-family:&=
quot;AlSharkTitle Black&quot;,sans-serif">Zoom</span><span dir=3D"RTL"></sp=
an><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;fo=
nt-family:&quot;AlSharkTitle Black&quot;,sans-serif"><span dir=3D"RTL"></sp=
an><span dir=3D"RTL"></span>.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 21.25pt 0in 0in;text-align:center;line-height:normal;di=
rection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-seri=
f"><span style=3D"font-size:14pt;font-family:Symbol">=C2=A8<span style=3D"f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings=
:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&q=
uot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=A5=D9=
=85=D9=83=D8=A7=D9=86=D9=8A=D8=A9
=D8=AA=D8=AE=D8=B5=D9=8A=D8=B5 =D8=A3=D9=8A =D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =
=D9=84=D8=AA=D9=83=D9=88=D9=86 =D8=AF=D8=A7=D8=AE=D9=84 =D8=A7=D9=84=D8=B4=
=D8=B1=D9=83=D8=A9 (</span><span dir=3D"LTR" style=3D"font-size:14pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,sans-serif">In-House</span><span dir=
=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif"><span dir=
=3D"RTL"></span><span dir=3D"RTL"></span>).</span><span dir=3D"LTR" style=
=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif"><=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 21.25pt 8pt 0in;text-align:center;line-height:normal;dire=
ction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"=
><span style=3D"font-size:14pt;font-family:Symbol">=C2=A8<span style=3D"fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;font-size-adjust:none;font-kerning:auto;font-feature-settings:n=
ormal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quo=
t;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=AE=D8=
=B5=D9=85 20% =D9=84=D9=84=D9=85=D8=AC=D9=85=D9=88=D8=B9=D8=A7=D8=AA
(3 =D8=A3=D8=B4=D8=AE=D8=A7=D8=B5 =D8=A3=D9=88 =D8=A3=D9=83=D8=AB=D8=B1).</=
span><span dir=3D"LTR" style=3D"font-size:14pt;font-family:&quot;AlSharkTit=
le Black&quot;,sans-serif"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;margin:0in 0in 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=
=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=
=D9=8A=D9=8F=D8=B9=D8=AF =D9=87=D8=B0=D8=A7 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=
=D8=A7=D9=85=D8=AC =D8=B1=D9=83=D9=8A=D8=B2=D8=A9 =D8=A3=D8=B3=D8=A7=D8=B3=
=D9=8A=D8=A9 =D9=84=D9=83=D9=84 =D9=85=D9=86 =D9=8A=D8=B3=D8=B9=D9=89 =D8=
=A5=D9=84=D9=89 =D8=A7=D9=84=D8=AA=D9=85=D9=8A=D8=B2
=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D9=88=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D9=8A=D8=8C =D9=81=D9=87=D9=88 =D9=84=D8=A7 =D9=8A=D9=83=D8=AA=D9=81=
=D9=8A =D8=A8=D8=A7=D9=84=D8=AC=D8=A7=D9=86=D8=A8 =D8=A7=D9=84=D9=86=D8=B8=
=D8=B1=D9=8A=D8=8C =D8=A8=D9=84 =D9=8A=D8=AF=D9=85=D8=AC =D8=A7=D9=84=D8=AA=
=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D9=8A =
=D9=88=D8=A7=D9=84=D8=AA=D9=81=D9=83=D9=8A=D8=B1
=D8=A7=D9=84=D9=86=D9=82=D8=AF=D9=8A =D9=81=D9=8A =D8=A8=D9=8A=D8=A6=D8=A9 =
=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=85=D8=AA=D8=BA=D9=8A=D8=B1=D8=A9.</span>=
</p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;margin:0in 0in 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=
=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=
=D9=88=D8=A8=D9=81=D8=B6=D9=84 =D8=AF=D9=85=D8=AC =D8=A7=D9=84=D9=85=D8=B9=
=D8=B1=D9=81=D8=A9 =D8=A7=D9=84=D9=85=D8=AD=D8=A7=D8=B3=D8=A8=D9=8A=D8=A9 =
=D8=A8=D8=A7=D9=84=D8=AA=D9=82=D9=86=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=
=D8=AF=D9=8A=D8=AB=D8=A9=D8=8C =D9=8A=D8=B5=D8=A8=D8=AD
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=88=D9=86 =D9=85=D8=A4=D9=87=
=D9=84=D9=8A=D9=86 =D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=AA=
=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A =D9=81=D9=8A =
=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA=D9=87=D9=85 =D8=A8=D9=83=D9=81=D8=A7=
=D8=A1=D8=A9 =D9=88=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9 =D8=B9=
=D8=A7=D9=84=D9=8A=D8=A9.</span><span lang=3D"AR-EG" style=3D"font-size:12p=
t;font-family:&quot;AlSharkTitle Black&quot;,sans-serif"> </span><span lang=
=3D"AR-EG" style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quo=
t;,sans-serif">=D8=A7=D9=86=D8=B6=D9=85 =D8=A5=D9=84=D9=89
=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=
=D9=84=D9=82=D9=88=D8=A7=D8=A6=D9=85 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=
=D8=A9 =D9=84=D8=AA=D9=83=D8=AA=D8=B4=D9=81 =D9=85=D8=A7 =D9=88=D8=B1=D8=A7=
=D8=A1 =D8=A7=D9=84=D8=A3=D8=B1=D9=82=D8=A7=D9=85=D8=8C =D9=88=D8=AA=D8=AD=
=D9=88=D9=91=D9=84 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D8=A5=
=D9=84=D9=89
=D9=82=D8=B1=D8=A7=D8=B1=D8=A7=D8=AA.</span><span lang=3D"AR-EG" style=3D"f=
ont-size:12pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif"></span=
></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;margin:0in 0in 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=
=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=
=D8=AE=D8=B7=D9=88=D8=A9 =D9=86=D8=AD=D9=88 =D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=
=D9=81 =D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D9=85=D8=A7=
=D9=84=D9=8A =D9=88=D8=B5=D9=86=D8=A7=D8=B9=D8=A9 =D8=A7=D9=84=D9=82=D8=B1=
=D8=A7=D8=B1 =D8=A8=D8=AB=D9=82=D8=A9.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font=
-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:16pt;fo=
nt-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D9=84=D9=84=D8=AA=D8=
=B3=D8=AC=D9=8A=D9=84 =D8=A3=D9=88 =D9=84=D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=
=B9=D8=B1=D8=B6 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A =D8=A7=D9=
=84=D9=83=D8=A7=D9=85=D9=84=D8=8C =D9=8A=D8=B1=D8=AC=D9=89
=D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=85=D8=B9=D9=86=D8=A7:</span>=
<span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;AlSharkTitle Bl=
ack&quot;,sans-serif"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font=
-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:20pt;fo=
nt-family:&quot;AlSharkTitle Black&quot;,sans-serif;color:rgb(196,89,17)">=
=D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=
=88=D8=A7=D8=AF =E2=80=93=D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=
=D8=B1=D9=8A=D8=A8</span><span lang=3D"AR-SA" style=3D"font-size:16pt;font-=
family:&quot;AlSharkTitle Black&quot;,sans-serif;color:rgb(196,89,17)"></sp=
an></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 25.1pt 0in 0in;text-align:center;line-height:normal;dire=
ction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif"=
><span style=3D"font-size:16pt;font-family:Symbol;color:white">=C2=A8<span =
style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;font-size-adjust:none;font-kerning:auto;font-featur=
e-settings:normal;font-stretch:normal;font-size:7pt;line-height:normal;font=
-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0 </span></span><span=
 dir=3D"RTL"></span><span dir=3D"LTR" style=3D"font-size:16pt;font-family:&=
quot;AlSharkTitle Black&quot;,sans-serif">=C2=A0</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 25.1pt 8pt 0in;text-align:center;line-height:normal;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,sans-serif">=
<span dir=3D"RTL"></span><span style=3D"font-size:16pt;font-family:Symbol;c=
olor:white">=C2=A8<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;font-size-adjust:none;font-=
kerning:auto;font-feature-settings:normal;font-stretch:normal;font-size:7pt=
;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=
=C2=A0
</span></span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:&q=
uot;AlSharkTitle Black&quot;,sans-serif"><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span>[=D8=B1=D9=82=D9=85 =D8=A7=D9=84=D9=87=D8=A7=D8=AA=D9=81 / =
=D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=A8]</span><span dir=3D"LTR"></span><span=
 dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:16pt;font-family:&=
quot;AlSharkTitle Black&quot;,sans-serif"><span dir=3D"LTR"></span><span di=
r=3D"LTR"></span>=C2=A0=C2=A0 </span><span dir=3D"RTL"></span><span dir=3D"=
RTL"></span><span style=3D"font-size:16pt;font-family:&quot;AlSharkTitle Bl=
ack&quot;,sans-serif"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=
=A0</span><span lang=3D"AR-SA" style=3D"font-size:14pt;font-family:&quot;Ti=
mes New Roman&quot;,serif">00201069994399 -00201062992510 -
00201096841626</span><span dir=3D"LTR" style=3D"font-size:16pt;font-family:=
&quot;AlSharkTitle Black&quot;,sans-serif"></span></p>

</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKm8QtenmN0jnLYfOkb1Frgqyfw%3DgK_E%3DSO9UHBZLbnUcg%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CADj1ZKm8QtenmN0jnLYfOkb1Frgqyfw%3DgK_E%3DSO9UHBZLbnUcg%40=
mail.gmail.com</a>.<br />

--000000000000acc31d064185f718--
