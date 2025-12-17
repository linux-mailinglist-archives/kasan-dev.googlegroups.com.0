Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBAWPRHFAMGQEDTQQQQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 12CA4CC684F
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 09:19:16 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-477c49f273fsf68425135e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 00:19:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765959555; cv=pass;
        d=google.com; s=arc-20240605;
        b=D4kPSjm/Zty9wgUyii2dwdZtWsXyssOf5IPD27PtSOAYRYmx/dfprHFbxmiuKzQ4eL
         +oJYW4es2x5abN39H/crELBwNrVDZev1IPve+lr42NNMLLapsKFZxBQPFoIolBr0f4wR
         u51DHZ3hRvXZ0S8FcYhZ6MtlqUipm7e1EXZPWH6FLuxYXt1KJSR5JqxmL/T9QcYABrFJ
         S3zd7f8/kzV43UJWlHRMJHSaeMLwTTqC3T8pjXz7SxnD43mASQ3Ys4bGNXNpgml7pKy9
         OvVXfkelS6lXIUWEjgYdz9/n5sQ94C6OX/2Ude3jhEZVMJy6FjH53RbfCndU6W8/5c0F
         SxZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=9p++URcmiOFghWfaqAGYeUY3Vre+mz9T/xqRyeg7zfE=;
        fh=dQTF36cYC+bo7BSNs96F+eT/V29JbHsSbxg8WZdTnLM=;
        b=Td7tg4qJ1lImhwcKUiSnF64oIhIKRKX4eBYSwPX3ItPeuxyRnTmSUlb2tSwgyqy2en
         ySw4wvc6ydsBd6bkQp955o3sp1QtuTr14+MJulJrLnNB7xYjgpcyAkIAIEzHmYa9pNgs
         ZWc3SY3GzAwK76NkOKWb7du1w46hEKRw+OgeoZ1KCZR1jTbnjh5mAaSxImi6UVNOjAJk
         sZvYk0bOKZW4vGsdrWEbts0/t7kP8ycoZ1soB8xLhvQy52jawPySH72qydAZP5HT0A++
         kWlwTRHTUQ5UwfcQqGhBDdFmqf4zz7X8QRTW+aeIF8rXmoizjnTgN+k6BePyvbQdWsq4
         K3Hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ZT31Ax7/";
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765959555; x=1766564355; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9p++URcmiOFghWfaqAGYeUY3Vre+mz9T/xqRyeg7zfE=;
        b=fFx57BjYS2Vc7fWkRLs9kOFoGYpVkQ2VBKUu/xyAaqd+qhLcT23ICLfkpueTdv5Bgn
         vWOp1ZnTZdlyRLv3xaFAFIg5s6T91OMBDtrEPZ7dFWOHA21QozxWxP4MNKsArLR0tlRP
         7K64twKDjCUiTKAGsCb5VuvZo585WAVOT4Mk547hVziIaWIjqv853jV9gxy+Rm6GUGu5
         5br6kfX849QFx6LUIzwNnELvydvs6w0sG+pcF0Be5Fi+1cx9zTWewLerKU269u7t8fRD
         P29zQSWK2jCgSkkg1S9R1NPiWkyrpzmy8u/dyEKF0XGyCSvbd7sSCIlY1zj20oMVSj02
         0tPg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1765959555; x=1766564355; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=9p++URcmiOFghWfaqAGYeUY3Vre+mz9T/xqRyeg7zfE=;
        b=IrhUIbVvzahu/6Ig+lu3o17BV7VBsq5opiQqEFFJ+8hBdPr5jHDXuNR3MHImZeSSHY
         ergzQkLsLthUwyt7hOqH+LhdNZ17Ys9vavbpuOtHeypAvTdiEucxUREqigqBp/bksr4z
         uZnMNTkToBPam5TWry+/yZE3zg6FBQ/5Ti8LWKB08exEEdZ4nTOcuTBcZg3GJbMXKrvW
         ctraBV/zxXAXlm59j/KOoD2agO0lKbd8stricAnAqfZ9Vm7dlrFal4fb3K7zTwQA1R6e
         jfvXbrL0vuOMCH2TGsIPr1l+UQ87DeV6K47yX92GzB2+8JP4OdsdKuqeUlBJNMbNs5AX
         DRYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765959555; x=1766564355;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9p++URcmiOFghWfaqAGYeUY3Vre+mz9T/xqRyeg7zfE=;
        b=hbqkNzV6t4yfue3FFptCYqbYVtSC86DssB5HYUVykFhOeOAQTcSsIJZ+MGlPF8PKXP
         J/bqdmQuI2VkbbRhU549fV8TUt9sbI68Pq2mPQTkqCXKMvWChkONSh89lCA5mMPDByNG
         MJO/jHtQom0lJ0hEg/GO6m0llS0fzdEplX9yrNNsnpzB9iP3lvMAKUYEcU/qK5Uuf7w/
         sQdEFRB66oId8XS6PcIWg7+WlPxOjs69hD288YvZxfBko0Gh232gBlnJ5LFOfENTBOqp
         N+WTsNgVU1uJA/LOZjmdmIIVRrdus3XPom26Wsbz76kr5FlK5CtoaD+rhJ5dT/L8KcD2
         M0OA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUN412YUEH4ZV/7xDXfICVMneKjdWkmfsy2cQNlKdpLHi5C/0mPMV6PBPzdHuiDjLRLTX/iQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz9k2IWpldCsCzMx7rttWEGTobEmoz2KtoR/Lzy+CeBkOQLggdi
	79S/dv1cWY7tao8oVkmHvGjC9gcZ8IpNRfrD6dgoQgnQMCBSWyWSvyO9
X-Google-Smtp-Source: AGHT+IEuxTHtCTmdHTQd85Xh8gtxXct+MBATEaK5Vp4XNA8yg2I+aAr2XzAf33GqbzVy6TVfve7qyw==
X-Received: by 2002:a05:600c:8b62:b0:477:abea:901c with SMTP id 5b1f17b1804b1-47a953da53fmr138615795e9.11.1765959555232;
        Wed, 17 Dec 2025 00:19:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYRusiL5YMzRLKv4RpPklcKotd3rSoFTSVkTagUpWqB7Q=="
Received: by 2002:a05:600c:5487:b0:479:10b7:a7cb with SMTP id
 5b1f17b1804b1-47a8ec77875ls35981465e9.2.-pod-prod-02-eu; Wed, 17 Dec 2025
 00:19:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW/InpSJSUT1WqwNu+6wNxofdS1g5X0FTnRVEGY9y184WNxH/72/fvUqqjm9Ca80yfVFL6iiVJRqb4=@googlegroups.com
X-Received: by 2002:a05:600c:4448:b0:477:df3:1453 with SMTP id 5b1f17b1804b1-47a8f90cd73mr180215455e9.28.1765959551477;
        Wed, 17 Dec 2025 00:19:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765959551; cv=none;
        d=google.com; s=arc-20240605;
        b=aM7xfTNR2v7TzcGvhE8ZZbpiIGXfMVIKK2wCPNoWhx6J6w3jbqKavHPYKdmXBpqLVY
         3xNNMH5/elt+/acTcjSAHmwxoDYfQuZtjImcMhpkXVErqsQBKQyqVgwArEFjZRWClDnq
         LuCaHLLxTCBVuNaGTnX/9rco2QczExRoCMrRYbIu+dYWaSPSp4eOJzOGQ+YL2hSclsq4
         GWOcBiuCevUx+UoydbhTLGDelEsfPUlOn0V4JFJpVDYdfBfumFVMdCJabK+S5upqhpqt
         63wCtQY9M8RGnBndSES3WzBl3rtWAIvpE5WD779lMY9USTfVW5YNaR4YpJ0r281laJ1h
         IkPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=hsWiv7QpL5ojIeI8esmKLrgZJ0+sXR8jWNFCVk0jWag=;
        fh=eliHOyXEkVvbvOf+gml71/vnOrPp97Tx42x7a/O57iM=;
        b=Gxcm2znlBGtYIUeE0A44zXBtCfh8UtNOcuNYHZuKO6PrlVqo4HM8edYo1IHFObfPDI
         6nKurH+Nd9kSsnAilo3FZH81Uk1tf1DdrZ5ITIkA5obRHgrXM3CnH8ar+25haDv05S4A
         Nn+1D8CWe6GQxGzZtMmm8TIFMA+NtxxpJ3HRkEFuQWF6nScCqUFZh60m5NZHTR48DUhg
         TXsz6YdtuXBL7PvsEz2Pt2bkQyVG9T1FNmTlzIkXbfSAV8xCo8YLtBadihWd3dsKzmWY
         Dj18/ja6kB+PnoqMnd0bM18DmpNvRMjs00Wav6XH625sk6bUKFUiS6z5bkUBnIRS9EkQ
         2Z4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ZT31Ax7/";
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4310ad4ec8dsi37336f8f.0.2025.12.17.00.19.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Dec 2025 00:19:11 -0800 (PST)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id 4fb4d7f45d1cf-6418b55f86dso7471969a12.1
        for <kasan-dev@googlegroups.com>; Wed, 17 Dec 2025 00:19:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVFjNLUQ4BDjCBhxw5VpDYoPngZfK25CUgDrhoWtt4i3t+ETVeXUqQwZTZiNqDW99qU7+zitifuKzk=@googlegroups.com
X-Gm-Gg: AY/fxX4sb6j/V58R91UlSl44ALGxP11kRb8uyaf9SBWOBPVFkwkditpbtcSy2t4yDtJ
	ismhSX7r4bOzZnP28hF7X6TQHsSDAAcm5otdTmrrBowQLDVtC7uOXaqzkHvtO63WpjetBsmFbBt
	xsreTEE6b7nAL3RP9KficjaDyBQWcIbczSq39KFJWCSdKiAUtqJf9lzPYFxs5vQjR5S06jTzwWL
	mGLOz/BDm2MZ1XLNCqJ55orRCH3GXjUiAAXW1g+JlP5pJpWzrO2NxppwPkgr4TnSzQkwJdcNUN+
	d9qCG9Lca4CWBQ==
X-Received: by 2002:a05:6402:146d:b0:640:abd5:864d with SMTP id
 4fb4d7f45d1cf-6499b1f1bacmr13993155a12.21.1765959550049; Wed, 17 Dec 2025
 00:19:10 -0800 (PST)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Wed, 17 Dec 2025 10:18:57 +0200
X-Gm-Features: AQt7F2rqI-3-3q-fstUZTfOW37C2BJweJpsAZctGSx58wBWZ-jWZ831iqH5VbIg
Message-ID: <CADj1ZKmtUDeWCbofWiNr1uiKN1wuy3S9ytbFckh9uytQfdy=bQ@mail.gmail.com>
Subject: =?UTF-8?B?2KfZhNmI2LHYtNmA2YDZgNmA2YDYqSDYqtmA2YDZgNmA2K/YsdmK2YDZgNio2YrYqSA6?=
	=?UTF-8?B?2KfYs9iq2LHYp9iq2YrYrNmK2KfYqiDYp9mE2YLZitin2K/YqSDYp9mE2LDZg9mK2KkgU21hcnQgTGVh?=
	=?UTF-8?B?ZGVyc2hpcCBTdHJhdGVnaWVz2YXZiNi52K8g2YjZhdmD2KfZhiDYp9mE2KfZhti52YLYp9ivOtiq2Lk=?=
	=?UTF-8?B?2YLYryDYqNin2YTZgtin2YfYsdipIOKAkyDYrNmF2YfZiNix2YrYqSDZhdi12LEg2KfZhNi52LHYqNmK?=
	=?UTF-8?B?2Kkg2K7ZgNmA2YDZgNmA2YTYp9mEINin2YTZgdiq2LHYqdmF2YYgMTEg4oCTIDE1INmK2YbZgNmA2YA=?=
	=?UTF-8?B?2YDZgNmA2YDYp9mK2LEyMDI22YUg2YTZhdiv2KkgNSDYo9mK2KfZhdiq2K/YsdmK2KjZitip?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000ab22690646217f65"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="ZT31Ax7/";       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::52d
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

--000000000000ab22690646217f65
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YrYs9ix2ZEg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE2KXY
r9in2LHZitipINin2YTYpdi52YTYp9mGINi52YYg2LnZgtivINmI2LHYtNipINin2YTYudmF2YQg
2KfZhNmF2KrYrti12LXYqQ0K2YHZiiAq2KfYs9iq2LHYp9iq2YrYrNmK2KfYqg0K2KfZhNmC2YrY
p9iv2Kkg2KfZhNiw2YPZitipKtiMDQoNCiDZiNin2YTYqtmKINiq2YfYr9mBINil2YTZiSDYqtmF
2YPZitmGINin2YTZgtmK2KfYr9in2Kog2YXZhiDYqti32YjZitixINij2LPYp9mE2YrYqCDYp9mE
2YLZitin2K/YqSDYp9mE2K3Yr9mK2KvYqdiMINmI2KrYudiy2YrYsg0K2KfZhNmC2K/YsdipINi5
2YTZiSDYp9iq2K7Yp9iwINin2YTZgtix2KfYsdiMDQoNCtmI2YLZitin2K/YqSDYp9mE2YHYsdmC
INio2YHYudin2YTZitipINmB2Yog2KjZitim2KfYqiDYudmF2YQg2YXYqti62YrYsdipLg0KDQoN
Cg0K2KfZhNmI2LHYtNmA2YDZgNmA2YDYqSDYqtmA2YDZgNmA2K/YsdmK2YDZgNio2YrYqSA6DQoN
Ctin2LPYqtix2KfYqtmK2KzZitin2Kog2KfZhNmC2YrYp9iv2Kkg2KfZhNiw2YPZitipDQoqU21h
cnQgTGVhZGVyc2hpcCBTdHJhdGVnaWVzKg0KDQoq2YXZiNi52K8g2YjZhdmD2KfZhiDYp9mE2KfZ
hti52YLYp9ivKio6Kg0KDQrYqti52YLYryDYqNin2YTZgtin2YfYsdipIOKAkyDYrNmF2YfZiNix
2YrYqSDZhdi12LEg2KfZhNi52LHYqNmK2KkNCtiu2YDZgNmA2YDZgNmE2KfZhCDYp9mE2YHYqtix
2Kkg2YXZhiAxMSDigJMgMTUg2YrZhtmA2YDZgNmA2YDZgNmA2KfZitixMjAyNtmFDQrZhNmF2K/Y
qSA1INij2YrYp9mFINiq2K/YsdmK2KjZitipDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0NCg0KKtij2YfYr9in2YEg2KfZhNmI2LHYtNipKio6Kg0KDQrCpyAgICAgICDYqtmG2YXZitip
INmF2YfYp9ix2KfYqiDYp9mE2YLZitin2K/YqSDYp9mE2LDZg9mK2Kkg2YjYp9mE2KrZgdmD2YrY
sSDYp9mE2KfYs9iq2LHYp9iq2YrYrNmKDQoNCsKnICAgICAgINiq2LnYstmK2LIg2YPZgdin2KHY
qSDYp9iq2K7Yp9iwINin2YTZgtix2KfYsSDZgdmKINin2YTYuNix2YjZgSDYp9mE2YXYudmC2K/Y
qQ0KDQrCpyAgICAgICDZgtmK2KfYr9ipINin2YTYqti62YrZitixINmI2KfZhNiq2K3ZiNmEINin
2YTZhdik2LPYs9mKINio2YHYudin2YTZitipDQoNCsKnICAgICAgINio2YbYp9ihINmB2LHZgiDY
udmF2YQg2LnYp9mE2YrYqSDYp9mE2KPYr9in2KENCg0KwqcgICAgICAg2KrZiNi42YrZgSDYp9mE
2KPYr9mI2KfYqiDYp9mE2LHZgtmF2YrYqSDZiNin2YTYsNmD2YrYqSDZgdmKINin2YTZgtmK2KfY
r9ipDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCg0KDQoNCirYo9mH2YUg2YXYrdin
2YjYsSDYp9mE2YjYsdi02KkqKjoqDQoNCsKnICAgICAgINmF2YHYp9mH2YrZhSDYp9mE2YLZitin
2K/YqSDYp9mE2LDZg9mK2Kkg2YjYo9io2LnYp9iv2YfYpyDYp9mE2K3Yr9mK2KvYqQ0KDQrCpyAg
ICAgICDYo9mG2YXYp9i3INin2YTZgtmK2KfYr9ipINmB2Yog2KfZhNi52LXYsSDYp9mE2LHZgtmF
2YoNCg0KwqcgICAgICAg2KfZhNiw2YPYp9ihINin2YTYudin2LfZgdmKINmI2K/ZiNix2Ycg2YHZ
iiDYp9mE2YLZitin2K/YqQ0KDQrCpyAgICAgICDYp9mE2YLZitin2K/YqSDYp9mE2YXYqNmG2YrY
qSDYudmE2Ykg2KfZhNio2YrYp9mG2KfYqiDZiNin2YTYqtit2YTZitmEDQoNCsKnICAgICAgINil
2K/Yp9ix2Kkg2KfZhNiq2LrZitmK2LEg2YjYp9mE2KfYqNiq2YPYp9ixINin2YTZhdik2LPYs9mK
DQoNCsKnICAgICAgINiq2K3ZgdmK2LIg2KfZhNmB2LHZgiDZiNio2YbYp9ihINir2YLYp9mB2Kkg
2KfZhNij2K/Yp9ihDQoNCsKnICAgICAgINiv2LHYp9iz2KfYqiDYrdin2YTYqSDZiNiq2LfYqNmK
2YLYp9iqINi52YXZhNmK2KkNCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQoNCg0K
Ktin2YTZgdim2Kkg2KfZhNmF2LPYqtmH2K/ZgdipKio6Kg0KDQrCpyAgICAgICDYp9mE2YLZitin
2K/Yp9iqINin2YTYqtmG2YHZitiw2YrYqQ0KDQrCpyAgICAgICDZhdiv2LHYp9ihINin2YTYpdiv
2KfYsdin2KoNCg0KwqcgICAgICAg2LHYpNiz2KfYoSDYp9mE2KPZgtiz2KfZhQ0KDQrCpyAgICAg
ICDZhdiv2LHYp9ihINin2YTZhdi02LHZiNi52KfYqg0KDQrCpyAgICAgICDYp9mE2YXYsdi02K3Z
iNmGINmE2YTZhdmG2KfYtdioINin2YTZgtmK2KfYr9mK2KkNCi0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLQ0KDQoNCg0KKtmF2LLYp9mK2Kcg2KfZhNmF2LTYp9ix2YPYqSoqOioNCg0Kwqcg
ICAgICAg2K3ZgtmK2KjYqSDYqtiv2LHZitio2YrYqSDZhdiq2YPYp9mF2YTYqQ0KDQrCpyAgICAg
ICDYtNmH2KfYr9ipINmF2LnYqtmF2K/YqSDZhdmGINin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg
2YTZhNiq2YbZhdmK2Kkg2KfZhNil2K/Yp9ix2YrYqQ0KDQrCpyAgICAgICDYqti32KjZitmC2KfY
qiDYudmF2YTZitipINmI2YbZhdin2LDYrCDZgtmK2KfYr9mK2Kkg2K3Yr9mK2KvYqQ0KDQrCpyAg
ICAgICDYr9i52YUg2KfYs9iq2LTYp9ix2Yog2KjYudivINin2YTZiNix2LTYqQ0KDQoNCg0KKtio
2YrYp9mG2KfYqiDYp9mE2KrZiNin2LXZhCDZhNmE2KrYs9is2YrZhCDZiNin2YTYp9iz2KrZgdiz
2KfYsSoqOioNCg0KKtijLyDYs9in2LHYqSDYudio2K8g2KfZhNis2YjYp9ivIOKAkyDZhdiv2YrY
sSDYp9mE2KrYr9ix2YrYqCoNCtin2YTZh9in2KrZgToNCg0KDQoqMDAyMDEwNjk5OTQzOTkgMDAy
MDEwNjI5OTI1MTAgMDAyMDEwOTY4NDE2MjYqDQoq2KzZh9ipKiog2KfZhNiq2YbZgdmK2LAqKiAg
ICA6Ktin2YTYr9in2LEg2KfZhNi52LHYqNmK2Kkg2YTZhNiq2YbZhdmK2Kkg2KfZhNil2K/Yp9ix
2YrYqQ0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tDQoNCi0tIApZb3UgcmVjZWl2ZWQg
dGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3Jv
dXBzICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5k
IHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRl
dit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiB2
aXNpdCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L0NBRGoxWktt
dFVEZVdDYm9mV2lOcjF1aUtOMXd1eTNTOXl0YkZja2g5dXl0UWZkeSUzRGJRJTQwbWFpbC5nbWFp
bC5jb20uCg==
--000000000000ab22690646217f65
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:jus=
tify;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;f=
ont-size:12pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D=
"font-size:18pt;line-height:115%;font-family:Arial,sans-serif">=D9=8A=D8=B3=
=D8=B1=D9=91 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=
=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=
=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=B9=D9=84=D8=A7=D9=86 =
=D8=B9=D9=86 =D8=B9=D9=82=D8=AF =D9=88=D8=B1=D8=B4=D8=A9 =D8=A7=D9=84=D8=B9=
=D9=85=D9=84
=D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=81=D9=8A <b>=D8=A7=D8=
=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D9=
=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=B0=D9=83=D9=8A=D8=A9</b>=D8=8C<=
/span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;direction:rt=
l;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;fon=
t-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:18pt;l=
ine-height:115%;font-family:Arial,sans-serif">=C2=A0=D9=88=D8=A7=D9=84=D8=
=AA=D9=8A =D8=AA=D9=87=D8=AF=D9=81 =D8=A5=D9=84=D9=89 =D8=AA=D9=85=D9=83=D9=
=8A=D9=86
=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA =D9=85=D9=86 =D8=AA=D8=B7=
=D9=88=D9=8A=D8=B1 =D8=A3=D8=B3=D8=A7=D9=84=D9=8A=D8=A8 =D8=A7=D9=84=D9=82=
=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9=D8=8C =
=D9=88=D8=AA=D8=B9=D8=B2=D9=8A=D8=B2 =D8=A7=D9=84=D9=82=D8=AF=D8=B1=D8=A9 =
=D8=B9=D9=84=D9=89 =D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=
=D8=A7=D8=B1=D8=8C </span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;direction:rt=
l;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;fon=
t-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"font-size:18pt;l=
ine-height:115%;font-family:Arial,sans-serif">=D9=88=D9=82=D9=8A=D8=A7=D8=
=AF=D8=A9 =D8=A7=D9=84=D9=81=D8=B1=D9=82 =D8=A8=D9=81=D8=B9=D8=A7=D9=84=D9=
=8A=D8=A9 =D9=81=D9=8A =D8=A8=D9=8A=D8=A6=D8=A7=D8=AA =D8=B9=D9=85=D9=84 =
=D9=85=D8=AA=D8=BA=D9=8A=D8=B1=D8=A9</span><span dir=3D"LTR"></span><span d=
ir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-size:18pt;line-height:115=
%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>.</span><span lang=3D"=
AR-EG" style=3D"font-size:18pt;line-height:115%;font-family:Arial,sans-seri=
f"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;direction:rt=
l;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;fon=
t-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=3D"font-size:18pt;l=
ine-height:115%;font-family:Arial,sans-serif">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;fon=
t-family:Arial,sans-serif">=D8=A7=D9=84=D9=88=D8=B1=D8=B4=D9=80=D9=80=D9=80=
=D9=80=D9=80=D8=A9 =D8=AA=D9=80=D9=80=D9=80=D9=80=D8=AF=D8=B1=D9=8A=D9=80=
=D9=80=D8=A8=D9=8A=D8=A9 </span><span dir=3D"LTR"></span><span dir=3D"LTR">=
</span><span dir=3D"LTR" style=3D"font-size:20pt;line-height:115%"><span di=
r=3D"LTR"></span><span dir=3D"LTR"></span>:</span><span lang=3D"AR-EG" styl=
e=3D"font-size:20pt;line-height:115%;font-family:Arial,sans-serif"></span><=
/p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><span lang=3D"AR-SA" style=3D"=
font-size:48pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,=
sans-serif">=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=
=AA =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=B0=D9=83=D9=
=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:24pt;line-height:115%"=
><br>
</span><i><span dir=3D"LTR" style=3D"font-size:24pt;line-height:115%;font-f=
amily:&quot;Times New Roman&quot;,serif">Smart Leadership Strategies</span>=
</i><span dir=3D"LTR" style=3D"font-size:24pt;line-height:115%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:20pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">=D9=85=D9=88=D8=B9=D8=AF =D9=88=D9=85=D9=83=D8=A7=D9=86 =D8=
=A7=D9=84=D8=A7=D9=86=D8=B9=D9=82=D8=A7=D8=AF</span></b><span dir=3D"LTR"><=
/span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:20pt=
;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif"><s=
pan dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><span lang=3D"AR-EG" style=3D"=
font-size:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=AA=D8=B9=
=D9=82=D8=AF =D8=A8=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9 =E2=80=93 =D8=
=AC=D9=85=D9=87=D9=88=D8=B1=D9=8A=D8=A9 =D9=85=D8=B5=D8=B1 =D8=A7=D9=84=D8=
=B9=D8=B1=D8=A8=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:18pt=
;line-height:115%"><br>
</span><span lang=3D"AR-EG" style=3D"font-size:18pt;line-height:115%;font-f=
amily:Arial,sans-serif">=D8=AE=D9=80=D9=80=D9=80=D9=80=D9=80=D9=84=D8=A7=D9=
=84 =D8=A7=D9=84=D9=81=D8=AA=D8=B1=D8=A9
=D9=85=D9=86 </span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span=
 dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"><span dir=3D"LTR"></=
span><span dir=3D"LTR"></span>11</span><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><span style=3D"font-size:18pt;line-height:115%;font-family:=
Arial,sans-serif"><span dir=3D"RTL"></span><span dir=3D"RTL"></span> <span =
lang=3D"AR-EG">=E2=80=93 15 =D9=8A=D9=86=D9=80=D9=80=D9=80=D9=80=D9=80=D9=
=80=D9=80=D8=A7=D9=8A=D8=B12026=D9=85</span></span><span dir=3D"LTR" style=
=3D"font-size:18pt;line-height:115%"><br>
</span><span lang=3D"AR-EG" style=3D"font-size:18pt;line-height:115%;font-f=
amily:Arial,sans-serif">=D9=84=D9=85=D8=AF=D8=A9 5 =D8=A3=D9=8A=D8=A7=D9=85
=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D=
"font-size:18pt;line-height:115%"></span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;=
font-size:12pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"0" width=3D"69%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;=
font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=A3=D9=87=D8=AF=
=D8=A7=D9=81 =D8=A7=D9=84=D9=88=D8=B1=D8=B4=D8=A9</span></b><span dir=3D"LT=
R"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:=
20pt;line-height:115%;font-family:&quot;AlSharkTitle Black&quot;,sans-serif=
"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 106.5pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-si=
ze:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-=
height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font=
-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stret=
ch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roma=
n&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fon=
t-family:Arial,sans-serif">=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D9=85=D9=87=D8=
=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9
=D8=A7=D9=84=D8=B0=D9=83=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D9=81=D9=83=
=D9=8A=D8=B1 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=
=D9=8A</span><span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 106.5pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D8=AA=D8=B9=D8=B2=D9=8A=D8=B2 =D9=83=D9=81=D8=
=A7=D8=A1=D8=A9 =D8=A7=D8=AA=D8=AE=D8=A7=D8=B0
=D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1 =D9=81=D9=8A =D8=A7=D9=84=D8=B8=D8=B1=
=D9=88=D9=81 =D8=A7=D9=84=D9=85=D8=B9=D9=82=D8=AF=D8=A9</span><span dir=3D"=
LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 106.5pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=
=AA=D8=BA=D9=8A=D9=8A=D8=B1
=D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=
=D8=B3=D9=8A =D8=A8=D9=81=D8=B9=D8=A7=D9=84=D9=8A=D8=A9</span><span dir=3D"=
LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 106.5pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D8=A8=D9=86=D8=A7=D8=A1 =D9=81=D8=B1=D9=82 =D8=
=B9=D9=85=D9=84 =D8=B9=D8=A7=D9=84=D9=8A=D8=A9
=D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1</span><span dir=3D"LTR" style=3D"font-=
size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 106.5pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-siz=
e:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-h=
eight:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font-=
size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stretc=
h:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman=
&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RTL=
"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;font=
-family:Arial,sans-serif">=D8=AA=D9=88=D8=B8=D9=8A=D9=81 =D8=A7=D9=84=D8=A3=
=D8=AF=D9=88=D8=A7=D8=AA
=D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=B0=D9=83=
=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9</span>=
<span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;=
font-size:12pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"0" width=3D"69%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;=
font-family:Arial,sans-serif">=C2=A0</span></b></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;=
font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=A3=D9=87=D9=85 =
=D9=85=D8=AD=D8=A7=D9=88=D8=B1 =D8=A7=D9=84=D9=88=D8=B1=D8=B4=D8=A9</span><=
/b><span dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" s=
tyle=3D"font-size:20pt;line-height:115%;font-family:&quot;AlSharkTitle Blac=
k&quot;,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</sp=
an></b></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 109.8pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-si=
ze:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-=
height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font=
-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stret=
ch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roma=
n&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fon=
t-family:Arial,sans-serif">=D9=85=D9=81=D8=A7=D9=87=D9=8A=D9=85 =D8=A7=D9=
=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9
=D8=A7=D9=84=D8=B0=D9=83=D9=8A=D8=A9 =D9=88=D8=A3=D8=A8=D8=B9=D8=A7=D8=AF=
=D9=87=D8=A7 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9</span><span dir=3D"=
LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 109.8pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D8=A3=D9=86=D9=85=D8=A7=D8=B7 =D8=A7=D9=84=D9=
=82=D9=8A=D8=A7=D8=AF=D8=A9 =D9=81=D9=8A
=D8=A7=D9=84=D8=B9=D8=B5=D8=B1 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A</span><=
span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 109.8pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=
=84=D8=B9=D8=A7=D8=B7=D9=81=D9=8A =D9=88=D8=AF=D9=88=D8=B1=D9=87
=D9=81=D9=8A =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9</span><span dir=3D"=
LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 109.8pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=
=A7=D9=84=D9=85=D8=A8=D9=86=D9=8A=D8=A9 =D8=B9=D9=84=D9=89
=D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=AA=
=D8=AD=D9=84=D9=8A=D9=84</span><span dir=3D"LTR" style=3D"font-size:18pt;li=
ne-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 109.8pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=
=AA=D8=BA=D9=8A=D9=8A=D8=B1
=D9=88=D8=A7=D9=84=D8=A7=D8=A8=D8=AA=D9=83=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=
=D8=A4=D8=B3=D8=B3=D9=8A</span><span dir=3D"LTR" style=3D"font-size:18pt;li=
ne-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 109.8pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"R=
TL"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;fo=
nt-family:Arial,sans-serif">=D8=AA=D8=AD=D9=81=D9=8A=D8=B2 =D8=A7=D9=84=D9=
=81=D8=B1=D9=82 =D9=88=D8=A8=D9=86=D8=A7=D8=A1
=D8=AB=D9=82=D8=A7=D9=81=D8=A9 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1</span><=
span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 109.8pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-siz=
e:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-h=
eight:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font-=
size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stretc=
h:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman=
&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RTL=
"></span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;font=
-family:Arial,sans-serif">=D8=AF=D8=B1=D8=A7=D8=B3=D8=A7=D8=AA =D8=AD=D8=A7=
=D9=84=D8=A9 =D9=88=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA
=D8=B9=D9=85=D9=84=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:1=
8pt;line-height:115%"></span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;=
font-size:12pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"0" width=3D"69%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;=
font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=C2=A0</span></b></p=
>

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
m 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=82=
=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=
=D9=8A=D8=A9</span><span dir=3D"LTR" style=3D"font-size:18pt;line-height:11=
5%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D9=85=D8=AF=D8=B1=
=D8=A7=D8=A1 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A7=D8=AA</span><span d=
ir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=B1=D8=A4=D8=B3=
=D8=A7=D8=A1 =D8=A7=D9=84=D8=A3=D9=82=D8=B3=D8=A7=D9=85</span><span dir=3D"=
LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D9=85=D8=AF=D8=B1=
=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=B4=D8=B1=D9=88=D8=B9=D8=A7=D8=AA</span><=
span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 113.05pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-si=
ze:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-=
height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font=
-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stret=
ch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roma=
n&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=A7=D9=84=D9=85=
=D8=B1=D8=B4=D8=AD=D9=88=D9=86 =D9=84=D9=84=D9=85=D9=86=D8=A7=D8=B5=D8=A8 =
=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D9=8A=D8=A9</span><span dir=3D"LTR" st=
yle=3D"font-size:18pt;line-height:115%"></span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;=
font-size:12pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"0" width=3D"69%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;=
font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=C2=A0</span></b></p=
>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"direction:rtl;unicode-bidi:embe=
d;margin:0cm 0cm 8pt;line-height:115%;font-size:12pt;font-family:Calibri,sa=
ns-serif"><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;=
font-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D9=85=D8=B2=D8=A7=
=D9=8A=D8=A7 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9</span></b><sp=
an dir=3D"LTR"></span><span dir=3D"LTR"></span><b><span dir=3D"LTR" style=
=3D"font-size:20pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span><=
/b></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0c=
m 105.95pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-s=
ize:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line=
-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fon=
t-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stre=
tch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Rom=
an&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=AD=D9=82=D9=8A=
=D8=A8=D8=A9 =D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9 =D9=85=D8=AA=D9=83=
=D8=A7=D9=85=D9=84=D8=A9</span><span dir=3D"LTR" style=3D"font-size:18pt;li=
ne-height:115%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 105.95pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=B4=D9=87=D8=A7=
=D8=AF=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=
=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=
=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=
=D8=A9</span><span dir=3D"LTR" style=3D"font-size:18pt;line-height:115%"></=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
cm 105.95pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-=
size:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;lin=
e-height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;fo=
nt-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-str=
etch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Ro=
man&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=AA=D8=B7=D8=A8=
=D9=8A=D9=82=D8=A7=D8=AA =D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=88=D9=86=D9=85=
=D8=A7=D8=B0=D8=AC =D9=82=D9=8A=D8=A7=D8=AF=D9=8A=D8=A9 =D8=AD=D8=AF=D9=8A=
=D8=AB=D8=A9</span><span dir=3D"LTR" style=3D"font-size:18pt;line-height:11=
5%"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0cm=
 105.95pt 8pt 0cm;direction:rtl;unicode-bidi:embed;line-height:115%;font-si=
ze:12pt;font-family:Calibri,sans-serif"><span style=3D"font-size:18pt;line-=
height:115%;font-family:Wingdings">=C2=A7<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;font=
-size-adjust:none;font-kerning:auto;font-feature-settings:normal;font-stret=
ch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New Roma=
n&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=AF=D8=B9=D9=85 =
=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D9=8A =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=
=D9=88=D8=B1=D8=B4=D8=A9</span><span dir=3D"LTR" style=3D"font-size:18pt;li=
ne-height:115%"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"fon=
t-size:18pt;line-height:115%">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:18pt;line-height:115%;font-family:Arial,sans-serif">=D8=A8=D9=
=8A=D8=A7=D9=86=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84
=D9=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=
=D8=AA=D9=81=D8=B3=D8=A7=D8=B1</span></b><span dir=3D"LTR"></span><span dir=
=3D"LTR"></span><b><span dir=3D"LTR" style=3D"font-size:18pt;line-height:11=
5%"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>:</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;fo=
nt-size:12pt;font-family:Calibri,sans-serif"><b><span lang=3D"AR-SA" style=
=3D"font-size:22pt;line-height:115%;font-family:&quot;AlSharkTitle Black&qu=
ot;,sans-serif">=D8=A3/ =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=
=D9=84=D8=AC=D9=88=D8=A7=D8=AF =E2=80=93 =D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=
=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8</span></b><span dir=3D"LTR" style=3D"font=
-size:18pt;line-height:115%"><br>
</span><span lang=3D"AR-SA" style=3D"font-size:18pt;line-height:115%;font-f=
amily:Arial,sans-serif">=D8=A7=D9=84=D9=87=D8=A7=D8=AA=D9=81</span><span di=
r=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"LTR" style=3D"font-s=
ize:18pt;line-height:115%"><span dir=3D"LTR"></span><span dir=3D"LTR"></spa=
n>:<br>
</span><i><span dir=3D"LTR" style=3D"font-size:22pt;line-height:115%;font-f=
amily:&quot;Times New Roman&quot;,serif">00201069994399<br>
00201062992510<br>
00201096841626</span></i><span dir=3D"LTR" style=3D"font-size:18pt;line-hei=
ght:115%"><br>
</span><b><span lang=3D"AR-SA" style=3D"font-size:20pt;line-height:115%;fon=
t-family:&quot;AlSharkTitle Black&quot;,sans-serif">=D8=AC=D9=87=D8=A9</spa=
n></b><b><span lang=3D"AR-EG" style=3D"font-size:20pt;line-height:115%;font=
-family:&quot;AlSharkTitle Black&quot;,sans-serif"> =D8=A7=D9=84=D8=AA=D9=
=86=D9=81=D9=8A=D8=B0</span></b><span dir=3D"LTR"></span><span dir=3D"LTR">=
</span><b><span dir=3D"LTR" style=3D"font-size:20pt;line-height:115%;font-f=
amily:&quot;AlSharkTitle Black&quot;,sans-serif"><span dir=3D"LTR"></span><=
span dir=3D"LTR"></span>=C2=A0=C2=A0 =C2=A0:</span></b><span lang=3D"AR-SA"=
 style=3D"font-size:20pt;line-height:115%;font-family:&quot;AlSharkTitle Bl=
ack&quot;,sans-serif">=D8=A7=D9=84=D8=AF=D8=A7=D8=B1
=D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=
=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span><span d=
ir=3D"LTR" style=3D"font-size:20pt;line-height:115%;font-family:&quot;AlSha=
rkTitle Black&quot;,sans-serif"></span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:c=
enter;direction:rtl;unicode-bidi:embed;margin:0cm 0cm 8pt;line-height:115%;=
font-size:12pt;font-family:Calibri,sans-serif"><span dir=3D"LTR" style=3D"f=
ont-size:18pt;line-height:115%">

<hr size=3D"0" width=3D"69%" align=3D"center">

</span></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKmtUDeWCbofWiNr1uiKN1wuy3S9ytbFckh9uytQfdy%3DbQ%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CADj1ZKmtUDeWCbofWiNr1uiKN1wuy3S9ytbFckh9uytQfdy%3DbQ%40mail=
.gmail.com</a>.<br />

--000000000000ab22690646217f65--
