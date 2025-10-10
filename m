Return-Path: <kasan-dev+bncBDM2ZIVFZQPBB4WBULDQMGQE52FEDIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E8BF5BCBC02
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 08:00:19 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-40fd1b17d2bsf867692f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 23:00:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760076019; cv=pass;
        d=google.com; s=arc-20240605;
        b=TZmx7rJgDxi8SOaTMYLyVO1af0C8cXw2ZP71r1tG0UbFVeEnvej6So5X+vYatrv2j5
         vK+7bBcEKwc/kVFwmRK7+g8UUhn8bFz/vQRKWFnz9kMqym8VtmNcQm99O/SCVqthjizj
         IZVDYblRu0mHqrKwrjpcx3P9rRk/45KZt9y6OdoXMnytabtVITqdznYYQJB1S4fFJGtN
         lBBMFHTGz/oXaJ8vyloA2E2djBVfz1FHFDt0suqRV/sM0zeS1Q+o7eX0p2pcq++6DLFi
         2/XohelEKuHLt0xOCUK3duTvUVuVrvwes5q1WvQJAETEMHvr33Zh7mS5uBzj4/FnyzEA
         MDbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=FuDI+z42Kq8TJuurBKwzb0qdxdZ/QOftfOX9zrsGTms=;
        fh=Lx2jnWu4IcrAQXOI8eQNzqKcH+9Y0o0yDbzjSf4mlTw=;
        b=aRi3HdNjpcXP2fdocZfGiCY6/eIpSehYwfOrU0f7Hn7Zn6S4ZdlqlWT578pnjSdNU5
         /Amo9oUfFzWQtFTp4PWCuEiROlqYg8Pfqni+LjS0DRD7aqnJo2zLTb9G+UzyTYhjuANq
         qpHlmA0Z8CBKE4+KyP9mWinaLI6hN2cY7pxw3FIrQ0uYm6K52qpvYsmuwCPzW5WfsNKe
         SPxkGa3m2INT1RADezJccko9w4di1FZkGoKQjcUQBOl9R3Ba8wLYei9vv0xmnC2xnI4J
         R2m2+HNqlPBZdMyPW5RfkpWqnf3LlPxU+dGdBSZxUW61BkkWpcyMLEdFUAUuDRKVqSti
         jnpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=I+tYaWr8;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760076019; x=1760680819; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FuDI+z42Kq8TJuurBKwzb0qdxdZ/QOftfOX9zrsGTms=;
        b=HwIz7WPAws3Eb9i88d9pC5salla3OsweJ2CZyzNKtlQz5aHMDtdLhXFat9snHX4a7Q
         whf8D5WH1+tL8MkXgdtfds2abv9XYM5gR5pWdwYcdykKYQJyGY+gdzQYgBVgkDBXo+cf
         W0OzO4VRcnbCcoGab/sWjy2P91GR60T12G/55BldpN5QSeEmCcVLBYRliAgUJkpiMxv3
         t/ZDnEihw2VHX+JwMlECKfCWnAyQJi9zEKYKa0MNH16hSgYPqos49HnQaLUjd+DRYf9Q
         DnSXBjpZlOtxWtwMVym9PpwnonZJd2O1+9GmyLhYAtd9mrb3xcAKQ7uWV5g8Ff3b0mzW
         nYUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760076019; x=1760680819; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=FuDI+z42Kq8TJuurBKwzb0qdxdZ/QOftfOX9zrsGTms=;
        b=WuJ0fRvvYraXyw5axTdVyqhrgpEdyxmplTiZJC8dDcDgS2za9lEgDoHEYGNtMxqFoY
         kWNpWmxqNbKuJByxFsnnU/LuWvXe5ri08EcRen2vry4jsgaSITimzzSJy3m3iMVqPyto
         sUBzxFOLXeuj/uCC7EYTVeEfYGKoRXsdDOsY3rex+rYIBvjWiUcaI1qxug7n8nOxTkEo
         jI0Me7KQmfaATJdquEcMa7QIGMK6c5i5TkLsHmfpWZk5/LIX5lWZNTd5Q9N6cr3qTGCa
         BvqE3xOyjIXyVS0JI69I3jvRr90ikrOC58xCZnhg45rseraT4SQUmoxKyvgBsQSKyzMw
         xMZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760076019; x=1760680819;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FuDI+z42Kq8TJuurBKwzb0qdxdZ/QOftfOX9zrsGTms=;
        b=kn3gVHcErH2NBeWwsc6yNITmv8yR3Ibiuf7pM/sQINZzKEz0n0f0PL3XAaWzWuR+ko
         z7kW5vb5qORtv4GuJpcFVN36BMiiPSSVicoDICN5eaFT4zumFI7k+qE+ArNW55p5bHef
         M0LwxTJBlpgKrPszD7kZrdSml2CVBaS8hb9FEf63if4kzuZQZ8KCQNTlSRLy6q3SEJRA
         3yTbstJ39MhOZZFhzbB+9ZY2b0e53/bNpl8i9veDtBfLhMU8xiHP/LP+m7QO9p80PQno
         Mr1UTQcYgfSSOl1Jpi6NAEzmEsOZbEPkQXOBwg3zExHVVpHYSuEAk9sltGQIJSdj7f6M
         FaEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEt2nEZuxcz5Ri+l1xho2A1fc9nM3qd4ThSxXuBoIzqJ5tF+TUvvHdpf8QqdNsidcdLn/dtg==@lfdr.de
X-Gm-Message-State: AOJu0YwRHA7vWnQrYhnpA6rkMMYxRAsElebD6PlHrnpGMRQi7XpcP4SH
	rEYFHV6cnRtc4GKm8T3QrTYM69kfnPGESawrIOS/Yx5sy5bLnQMepuGs
X-Google-Smtp-Source: AGHT+IHSwj4RUespqEKDN0rc7jpuJWSsvXj41zqgyCxvzOWcj1kmoHtAlcd1J0eoqaTwAEKdKdrJlA==
X-Received: by 2002:a05:6000:2c11:b0:3ec:dd16:fc16 with SMTP id ffacd0b85a97d-4266e7df779mr6492635f8f.43.1760076018734;
        Thu, 09 Oct 2025 23:00:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6jqDEs1ocevUsgRiaWqw7WsnV2fTG1NX3kuejoXHQ23Q=="
Received: by 2002:adf:ce0e:0:b0:3fd:4c4f:96d2 with SMTP id ffacd0b85a97d-426c7dcd77bls871467f8f.1.-pod-prod-03-eu;
 Thu, 09 Oct 2025 23:00:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFsI+fudP/v7BuG8yv08d5OqKtSemZopRrGDf2I5WqykRdYJeSdINhVzy+/Ov5UD0PcsGEItGcXZ8=@googlegroups.com
X-Received: by 2002:a05:6000:1862:b0:3e7:492f:72b4 with SMTP id ffacd0b85a97d-4266e7df7f7mr6623379f8f.42.1760076015828;
        Thu, 09 Oct 2025 23:00:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760076015; cv=none;
        d=google.com; s=arc-20240605;
        b=AoHFv7nKvPdN8dp/t6/+PfoOd2V9FE/HisXdZyeEyWAlL4IQc0W/gUMmitnUms/FSw
         FKwnuKW/4nKly4/bS0VPdFB0/pRUuo+EIbYQTqM3CnMZ3BnaUGg8HES3lL8hxDJ8VugR
         RSMmA0LeX3fCq7ahZIFMF0X83hvTaMG15wB3IGrvTe7GB6FaCFS06tK5XOR3M7rcPWM7
         Dtpoe8IvWz1MFaSPMZOljKKvIRXTC01fP/8j3vz3pt4Qsy9KMp5dz213eCdCNfIzFGXM
         aqqErt0giN1BerUPdlvuqTSdf3Dar96R5EY8DWpWfjeitOpDjR+vTcke60wP65jdOMfw
         K86w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=ZddV6NiZ3KRlbZZrsg0ttOu0rN/CNgLbyFNJ/C/ZOqI=;
        fh=vK1vRK6ehBVBaFxXjtdrvkdR6TXmNo4HLfVj4QIJw9Q=;
        b=P26ev4bfk1z4aPcw//yGoQ5jd2apXOWTI7JK8JTtY1trZ6XhZOL5MSK8uhfkj1+sZf
         +OUUeWSZuCvUCA15BTAGGcK/yEtTeUVh3mY/tGYAyFY3FRImBldD9vdnUE3cZpmH2If8
         WxKe1EGwJSRY5f5tphOgAwu3aTO8Nb6XOdoFFk2yY4LqMi/A1a1Rkhkb767iyTURUin1
         wtDrmx3WEwJm+qoJEvLUkWPvT5GJRp5dd6TrKhneRhpmplDEXlqLtvNISHSZjWEL4jhP
         TbiK/E4Sm7VKncDkf6WU+RvW3nPYsVzlrRTsMWdo+96V+M5zru0bO9jiT39gPgZxeCbw
         xCdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=I+tYaWr8;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-426ce5e78ecsi25742f8f.8.2025.10.09.23.00.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 23:00:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id 4fb4d7f45d1cf-6364eb29e74so3082216a12.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 23:00:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW0ZmZv7w70UmlaG153V3sTeNAsxupaOxHejx1u2MO6Zj5DevdfbiZ43TvIhfZSmlFE0jGn0xNLAqc=@googlegroups.com
X-Gm-Gg: ASbGncvTY/wWux/LpnHr7WYUwRxHhNSIQx0ysIFI8Wge4Sjl791Pah9flX5DAz2nl6R
	Kh7wyodzrWiBQiw1m1fKgtSRa55XYAOe0326xI0mOFhCDimXmTtZasaNnoPiPrynknj+XvEUGOo
	ZYK27o1r0iacdER3BdnR9/Gv/GjQShtZ/DVsHfUbNHoZgW0iUKScat8eNCSpqKZZ63UF3Z7NHgD
	kvQoVFxJGE69w0VEjEuUqgDskyiHCk=
X-Received: by 2002:a17:907:9628:b0:b46:abad:430f with SMTP id
 a640c23a62f3a-b50ac5d0873mr866899466b.52.1760076014711; Thu, 09 Oct 2025
 23:00:14 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Fri, 10 Oct 2025 08:00:00 +0200
X-Gm-Features: AS18NWB70cOb-jKjqx696d2H7Oo4Cq70xPfqXJ5aw0NYweitbAGbpg0YBV7GU78
Message-ID: <CADj1ZKkQ8g17dowUwqXzJ-1REbtkKxuc0p8hRK=+5vzjJOoKUA@mail.gmail.com>
Subject: =?UTF-8?B?2KfZhNmF2LPYp9ixINin2YTZiNi42YrZgdmKINmE2KrYo9mH2YrZhCDYp9mE2YLZitin?=
	=?UTF-8?B?2K/Yp9iqINin2YTYpdiv2KfYsdmK2Kk=?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000a28c850640c7a1f8"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=I+tYaWr8;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::535
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

--000000000000a28c850640c7a1f8
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YXZhiDZhdmI2LjZgSDZitik2K/ZiuKApiDYpdmE2Ykg2YLYp9im2K8g2YrZj9mE2YfZhSAgINin
2YTZiNi12YjZhCDZhNmE2YLZitin2K/YqSDZhNmK2LMg2K3YuNmL2KfigKYg2KjZhCDZgtix2KfY
sdmL2Kcg2YrYqNiv2KMg2YXZhg0K2YfZhtinLg0KDQrZg9mEINmC2KfYptivINi52LjZitmFINmD
2KfZhiDZitmI2YXZi9inINmF2YjYuNmB2YvYpyDYudin2K/ZitmL2KfYjCDZhNmD2YbZhyDZgtix
2LEg2KPZhiDZiti12YbYuSDZhdiz2KfYsdmHINio2YbZgdiz2YcuINmI2YXZhiDZh9mG2KcNCtiq
2YbYt9mE2YIg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE2KXY
r9in2LHZitipICAgICAgICAgICAgICAgICDYqNio2LHZhtin2YXYrCDYp9mE2YXYs9in2LEg2KfZ
hNmI2LjZitmB2YoNCtmE2KrYo9mH2YrZhCDYp9mE2YLZitin2K/Yp9iqINin2YTYpdiv2KfYsdmK
2Kkg2YTYqtmF2YbYrdmDINin2YTYo9iv2YjYp9iqINin2YTYqtmKINiq2K3ZiNmR2YQg2LfZhdmI
2K3Yp9iq2YMg2KXZhNmJINmI2KfZgti5INmC2YrYp9iv2YoNCtmF2YTZhdmI2LMuDQoNCirYrtmE
2KfZhCDYtNmH2LEg2KfZg9iq2YjYqNixKg0KDQoNCirYp9mE2YXYs9in2LEg2KfZhNmI2LjZitmB
2Yog2YTYqtij2YfZitmEINin2YTZgtmK2KfYr9in2Kog2KfZhNil2K/Yp9ix2YrYqSoNCg0KDQoN
CtmF2Kcg2YfZiCDYp9mE2YXYs9in2LEg2KfZhNmI2LjZitmB2YrYnw0KDQrYp9mE2YXYs9in2LEg
2KfZhNmI2LjZitmB2Yog2YfZiCDYs9mE2LPZhNipINmF2KrYudin2YLYqNipINmF2YYg2KfZhNiq
2LrZitix2KfYqiDYp9mE2YjYuNmK2YHZitipINin2YTYqtmKINmK2YXYsSDYqNmH2Kcg2KfZhNmF
2YjYuNmBDQrYrtmE2KfZhCDYrdmK2KfYqtmHINin2YTYudmF2YTZitipINiv2KfYrtmEINin2YTZ
hdik2LPYs9ipLiAgICAgICAgICAgICAgICAg2YfYsNmHINin2YTYqti62YrYsdin2Kog2YLYryDY
qtmD2YjZhjoNCg0KwrcgICAgICAgINin2YTZhdiz2KfYsSDYp9mE2LHYo9iz2YogKFZlcnRpY2Fs
IENhcmVlciBQYXRoKToNCg0K2YjZiti52KjYsSDYudmGINin2YTYqtix2YLZitipINil2YTZiSDZ
iNi42YrZgdipINij2LnZhNmJINi22YXZhiDYp9mE2YfZitmD2YQg2KfZhNiq2YbYuNmK2YXZitiM
INit2YrYqyDZitit2YLZgiDYp9mE2YXZiNi42YENCtiq2YLYr9mR2YXZi9inINmI2LjZitmB2YrZ
i9inINij2YPYqNix2Iwg2YrYrdi12YQg2LnZhNmJINij2KzYsSDYo9i52YTZidiMINmI2YrZg9iq
2LPYqCDZhdmD2KfZhtipINmI2LjZitmB2YrYqSDZiNmF2LPYpNmI2YTZitin2Kog2KPZiNiz2Lku
DQoNCsK3ICAgICAgICDYp9mE2YXYs9in2LEg2KfZhNij2YHZgtmKIChIb3Jpem9udGFsIENhcmVl
ciBQYXRoKToNCg0K2YjZiti02YrYsSDYpdmE2Ykg2KfZhtiq2YLYp9mEINin2YTZhdmI2LjZgSDY
qNmK2YYg2YjYuNin2KbZgSDYo9mIINmF2YfYp9mFINmF2K7YqtmE2YHYqSDYudmE2Ykg2YbZgdiz
INin2YTZhdiz2KrZiNmJINin2YTYqtmG2LjZitmF2YrYjA0K2K/ZiNmGINij2YYg2YrYsdiq2KjY
tyDYsNmE2YMg2KjYp9mE2LbYsdmI2LHYqSDYqNmF2YPYp9mG2Kkg2KXYtNix2KfZgdmK2Kkg2KPY
udmE2YnYjCDZhNmD2YbZhyDZitiq2YrYrSDZhNmHINin2YPYqtiz2KfYqCDYrtio2LHYp9iqDQrY
rNiv2YrYr9ipINmI2KrZiNiz2YrYuSDZgtin2LnYr9ipINmF2LnYp9ix2YHZhyDZiNmF2YfYp9ix
2KfYqtmHLg0KDQrZiNmF2YYg2YfZhtinINmK2YXZg9mGINin2YTZgtmI2YQg2KXZhiDYp9mE2YXY
s9in2LEg2KfZhNmI2LjZitmB2Yog2YfZiCDYp9mE2KXYt9in2LEg2KfZhNiw2Yog2YrZhdmD2ZHZ
hiDYp9mE2YXZiNi42YEg2YXZhiDYsdiz2YUNCti32YXZiNit2KfYqtmHINin2YTZhdmH2YbZitip
INio2YXYpyDZitiq2YbYp9iz2Kgg2YXYuSDZhdmH2KfYsdin2KrZhyDZiNmC2K/Ysdin2KrZh9iM
ICAgICAgICAgICAgICAgICAg2YHZiiDYttmI2KEg2YXYpw0K2KrYrdiv2K/ZhyDYpdiv2KfYsdip
INin2YTZhdmI2KfYsdivINin2YTYqNi02LHZitipINmF2YYg2YHYsdi1INmI2YXYs9in2LHYp9iq
INiv2KfYrtmEINin2YTZh9mK2YPZhCDYp9mE2KrZhti42YrZhdmKINmE2YTZhdik2LPYs9ipLg0K
DQog4pymIOKcptin2YTYo9mH2K/Yp9mBINin2YTYudin2YXYqToNCg0KMS4gICAg2KrYudix2YrZ
gSDYp9mE2YXYtNin2LHZg9mK2YYg2KjZhdmB2YfZiNmFINin2YTZhdiz2KfYsSDYp9mE2YjYuNmK
2YHZiiDZiNij2KjYudin2K/ZhyDZiNiv2YjYsdmHINmB2Yog2KfZhNiq2LfZiNmK2LENCtin2YTY
pdiv2KfYsdmKINmI2KjZhtin2KEg2KfZhNmC2YrYp9iv2KfYqi4NCg0KMi4gICAg2KrZhtmF2YrY
qSDYp9mE2YjYudmKINin2YTYqtiu2LfZiti32Yog2YjYp9mE2KXYs9iq2LHYp9iq2YrYrNmKINmE
2K/ZiSDYp9mE2YXYtNin2LHZg9mK2YYg2YTYsdio2Lcg2LfZhdmI2K3Yp9iq2YfZhSDYp9mE2YXZ
h9mG2YrYqQ0K2KjYp9it2KrZitin2KzYp9iqINin2YTZhdik2LPYs9ipLg0KDQozLiAgICDYpdmD
2LPYp9ioINin2YTZhdi02LHZgdmK2YYg2YjYsdik2LPYp9ihINin2YTYo9mC2LPYp9mFINmF2YfY
p9ix2KfYqiDYp9mE2KXYr9in2LHYqSDYp9mE2KXYtNix2KfZgdmK2Kkg2KfZhNmB2LnZkdin2YTY
qSDZhdmGDQoo2KrYrti32YrYtyDigJMg2KrZhti42YrZhSDigJMg2YXYqtin2KjYudipIOKAkyDY
qtmC2YrZitmFKS4NCg0KNC4gICAg2KrYudiy2YrYsiDZhdmH2KfYsdin2Kog2KfZhNmC2YrYp9iv
2Kkg2KfZhNi52YXZhNmK2Kkg2YXYq9mEINin2YTYqtmB2YjZiti22Iwg2KfZhNiq2YHYp9mI2LbY
jCDYp9iq2K7Yp9iwINin2YTZgtix2KfYsdiMINmI2K3ZhA0K2KfZhNmF2LTZg9mE2KfYqiDYqNij
2LPYp9mE2YrYqCDYrdiv2YrYq9ipINmI2KXYqNiv2KfYudmK2KkuDQoNCjUuICAgINiq2LfZiNmK
2LEg2YXZh9in2LHYp9iqINin2YTYqtmI2KfYtdmEINmI2KfZhNil2YLZhtin2Lkg2YTYpdiv2KfY
sdipINin2YTZgdix2YIg2YjYqNmG2KfYoSDYudmE2KfZgtin2Kog2LnZhdmEINil2YrYrNin2KjZ
itipDQrZiNmB2LnZkdin2YTYqS4NCg0KNi4gICAg2KrZhdmD2YrZhiDYp9mE2YXYtNin2LHZg9mK
2YYg2YXZhiDYsdiz2YUg2K7Yt9i32YfZhSDYp9mE2YjYuNmK2YHZitipINmI2LXZitin2LrYqSDY
o9mH2K/Yp9mBINmI2KfYttit2Kkg2KrYs9in2LnYr9mH2YUg2YHZig0K2KrYrdmC2YrZgiDZhdiz
2KfYsSDZhdmH2YbZiiDZhdiq2YjYp9iy2YYg2YjZhdiq2K/YsdisLg0KDQo3LiAgICDYpdi52K/Y
p9ivINin2YTZg9mI2KfYr9ixINin2YTZiNin2LnYr9ipINmE2KrZiNmE2Yog2YXZhtin2LXYqCDZ
gtmK2KfYr9mK2Kkg2YXYs9iq2YLYqNmE2YrYqdiMINio2YXYpyDZiti22YXZhiDYp9iz2KrZhdix
2KfYsdmK2KkNCtmI2KfYs9iq2YLYsdin2LEg2KfZhNij2K/Yp9ihINin2YTZhdik2LPYs9mKLg0K
DQoNCg0KDQoNCiDinKYg4pym2KfZhNmB2KbYp9iqINin2YTZhdiz2KrZh9iv2YHYqToNCg0Kwqcg
ICAgICAgINin2YTZg9mB2KfYodin2Kog2KfZhNmI2LjZitmB2YrYqSDYp9mE2YXYsdi02K3YqSDZ
hNi02LrZhCDZhdmI2KfZgti5INmC2YrYp9iv2YrYqSDZhdiz2KrZgtio2YTZitipLg0KDQrCpyAg
ICAgICAg2KfZhNmF2K/Zitix2YjZhiDYp9mE2KzYr9ivINin2YTYsNmK2YYg2KjYr9ij2YjYpyDY
o9mI2YTZiSDYrti32YjYp9iq2YfZhSDZgdmKINmF2LPYp9ixINin2YTZgtmK2KfYr9ipINin2YTY
pdiv2KfYsdmK2KkuDQoNCsKnICAgICAgICDYsdik2LPYp9ihINin2YTYo9mC2LPYp9mFINmI2YHY
sdmCINin2YTYudmF2YQg2KjYp9mE2KXYr9in2LHYqSDYp9mE2KrYtNi62YrZhNmK2Kkg2KXZhNmJ
INin2YTZgtmK2KfYr9ipDQrYp9mE2KXYs9iq2LHYp9iq2YrYrNmK2KkuDQoNCsKnICAgICAgICDY
p9mE2YLZitin2K/Yp9iqINin2YTZiNiz2LfZiSDYp9mE2KrZiiDYqti02YPZhCDYrdmE2YLYqSDZ
iNi12YQg2KPYs9in2LPZitipINio2YrZhiDYp9mE2KXYr9in2LHYqSDYp9mE2LnZhNmK2KcNCtmI
2KfZhNi12YHZiNmBINin2YTYqtmG2YHZitiw2YrYqS4NCg0KwqcgICAgICAgINin2YTZhdmI2LjZ
gdmI2YYg2LDZiNmIINin2YTYo9iv2KfYoSDYp9mE2YXYqtmF2YrYsiDYp9mE2LDZitmGINiq2LnY
qtmF2K8g2LnZhNmK2YfZhSDYp9mE2YXYpNiz2LPYp9iqINmB2Yog2K7Yt9i3DQrYpdi52K/Yp9iv
INin2YTZgtin2K/YqSDZiNi12YbYp9i52Kkg2KfZhNi12YEg2KfZhNir2KfZhtmKLg0KDQrCpyAg
ICAgICAg2KfZhNmF2KTYs9iz2KfYqiDYp9mE2LPYp9i52YrYqSDYpdmE2Ykg2KjZhtin2KEg2YLY
p9i52K/YqSDZgtmK2KfYr9mK2Kkg2YXYpNmH2YTYqSDYqti22YXZhiDYp9iz2KrYr9in2YXYqSDY
p9mE2YbZhdmIDQrZiNin2YTYqtmB2YjZgiDYp9mE2KrZhtin2YHYs9mKLg0KDQrinKYg4pym2KfZ
hNmF2K3Yp9mI2LEg2KfZhNix2KbZitiz2YrYqSDZiNmF2YbZh9mK2KzYqSDYp9mE2KjYsdmG2KfZ
hdisDQoNCtin2YTZhdit2YjYsSDYp9mE2KPZiNmEOiDZhdiv2K7ZhCDYpdmE2Ykg2KfZhNmF2LPY
p9ixINin2YTZiNi42YrZgdmKDQoNCsKnICAgICAgICDYp9mE2YXZgdmH2YjZhSDZiNin2YTYo9iz
2LMg2KfZhNmG2LjYsdmK2Kkg2YTZhNmF2LPYp9ixINin2YTZiNi42YrZgdmKLg0KDQrCpyAgICAg
ICAg2K7Ytdin2KbYtSDYp9mE2YXYs9in2LEg2KfZhNmI2LjZitmB2Yog2YjYo9io2LnYp9iv2Ycu
DQoNCsKnICAgICAgICDYp9mE2LnZhNin2YLYqSDYqNmK2YYg2KrYrti32YrYtyDYp9mE2YXZiNin
2LHYryDYp9mE2KjYtNix2YrYqSDZiNiq2K7Yt9mK2Lcg2KfZhNmF2LPYp9ixINin2YTZiNi42YrZ
gdmKLg0KDQoNCg0K2KfZhNmF2K3ZiNixINin2YTYq9in2YbZijog2KPZh9mF2YrYqSDYp9mE2YXY
s9in2LEg2KfZhNmI2LjZitmB2YoNCg0KwqcgICAgICAgINij2YfZhdmK2Kkg2KfZhNmF2LPYp9ix
INin2YTZiNi42YrZgdmKINmE2YTZgdix2K8gKNin2YTYt9mF2YjYrdin2KrYjCDYp9mE2LHYttin
2Iwg2KfZhNiq2YjYp9iy2YYg2KjZitmGINin2YTYrdmK2KfYqQ0K2YjYp9mE2LnZhdmE2Iwg2KjZ
htin2KEg2KfZhNmF2YfYp9ix2KfYqikuDQoNCsKnICAgICAgICDYo9mH2YXZitipINin2YTZhdiz
2KfYsSDYp9mE2YjYuNmK2YHZiiDZhNmE2YXYpNiz2LPYqSAo2KfZhNin2LPYqtmC2LfYp9io2Iwg
2KfZhNiq2YbZhdmK2KnYjCDYqtiu2LfZiti3INin2YTYpdit2YTYp9mE2IwNCtiq2LnYstmK2LIg
2KfZhNi12YjYsdipINin2YTZhdik2LPYs9mK2KkpLg0KDQrCpyAgICAgICAg2KfZhNmF2YbZgdi5
2Kkg2KfZhNmF2KrYqNin2K/ZhNipINio2YrZhiDYp9mE2YHYsdivINmI2KfZhNmF2KTYs9iz2Kkg
2YHZiiDYqti32YjZitixINin2YTZhdiz2KfYsdin2Kog2KfZhNmF2YfZhtmK2KkuDQoNCg0KDQrY
p9mE2YXYrdmI2LEg2KfZhNir2KfZhNirOiDZhdix2KfYrdmEINiq2LfZiNixINin2YTZhdiz2KfY
sSDYp9mE2YjYuNmK2YHZig0KDQrCpyAgICAgICAg2YXYsdit2YTYqSDYp9mE2KfYs9iq2YPYtNin
2YEuDQoNCsKnICAgICAgICDZhdix2K3ZhNipINin2YTYqtij2LPZitizLg0KDQrCpyAgICAgICAg
2YXYsdit2YTYqSDYp9mE2K3Zgdin2Lgg2KPZiCDYp9mE2LXZitin2YbYqS4NCg0KwqcgICAgICAg
INmF2LHYrdmE2Kkg2KfZhNin2YbZgdi12KfZhCDYo9mIINin2YTYqtmC2KfYudivLg0KDQrCpyAg
ICAgICAg2KfZhNiq2K3Yr9mK2KfYqiDYp9mE2KrZiiDYqtmI2KfYrNmHINin2YTYo9mB2LHYp9iv
INmI2KfZhNmF2KTYs9iz2KfYqiDZgdmKINmD2YQg2YXYsdit2YTYqS4NCg0KDQoNCtin2YTZhdit
2YjYsSDYp9mE2LHYp9io2Lk6INin2LPYqtiu2K/Yp9mF2KfYqiDYqtiu2LfZiti3INmI2KrYt9mI
2YrYsSDYp9mE2YXYs9in2LEg2KfZhNmI2LjZitmB2YoNCg0KwqcgICAgICAgINil2LnYr9in2K8g
2KfZhNmC2YrYp9iv2KfYqiDYp9mE2KXYr9in2LHZitipINmI2KfZhNi12YEg2KfZhNir2KfZhtmK
INmF2YYg2KfZhNmC2KfYr9ipLg0KDQrCpyAgICAgICAg2KfZhNiq2LHZgtmK2Kkg2YjYp9mE2YbZ
gtmEINmI2KfZhNil2K3ZhNin2YQg2KfZhNmI2LjZitmB2YouDQoNCsKnICAgICAgICDYp9mE2KrY
r9ix2YrYqCDZiNin2YTYqti32YjZitixINin2YTZhdiz2KrZhdixLg0KDQrCpyAgICAgICAg2KrZ
gtiv2YrYsSDYp9mE2KrZg9in2YTZitmBINin2YTZhdiz2KrZgtio2YTZitipINmE2YTZhdmI2KfY
sdivINin2YTYqNi02LHZitipLg0KDQrCpyAgICAgICAg2KfZhNiq2YPZitmBINmF2Lkg2KfZhNiq
2LrZitix2KfYqiDYp9mE2KfZgtiq2LXYp9iv2YrYqSDZiNin2YTYqtmD2YbZiNmE2YjYrNmK2Kkg
2YjYp9mE2KrZhti42YrZhdmK2KkuDQoNCtin2YTZhdit2YjYsSDYp9mE2K7Yp9mF2LM6INin2LPY
qtix2KfYqtmK2KzZitin2Kog2KrYt9mI2YrYsSDYp9mE2YXYs9in2LEg2KfZhNmI2LjZitmB2YoN
Cg0KwqcgICAgICAgINin2YTZhdmF2KfYsdiz2KfYqiDYp9mE2KXYr9in2LHZitipINmI2KfZhNiq
2YbYuNmK2YXZitipINin2YTYr9in2LnZhdipICjYp9mE2KfYrtiq2YrYp9ix2Iwg2KfZhNiq2LnZ
itmK2YbYjCDYp9mE2KrYr9ix2YrYqNiMDQrYp9mE2KrYsdmC2YrYqdiMINin2YTZhtmC2YQpLg0K
DQrCpyAgICAgICAg2KfZhNmG2LjZhSDZiNin2YTYs9mK2KfYs9in2Kog2KfZhNiq2Yog2KrYttmF
2YYg2KfYs9iq2YXYsdin2LHZitipINmI2KrZg9in2YXZhCDYp9mE2YXYs9in2LEg2KfZhNmI2LjZ
itmB2YouDQoNCsKnICAgICAgICDYqNmG2KfYoSDYqNmK2KbYqSDYudmF2YQg2YXYrdmB2LLYqSDZ
hNmE2YbZhdmIINmI2KrYt9mI2YrYsSDYp9mE2YLYr9ix2KfYqi4NCg0KwqcgICAgICAgINil2K/Y
p9ix2Kkg2KfZhNis2YXZiNivINmI2KfZhNix2LPZiNioINin2YTZiNi42YrZgdmKLg0KDQoNCg0K
2KfZhNmF2K3ZiNixINin2YTYs9in2K/Yszog2YXYrNin2YTYp9iqINix2LPZhSDYp9mE2YXYs9in
2LHYp9iqINin2YTZiNi42YrZgdmK2KkNCg0KwqcgICAgICAg2KfZhNmF2LPYp9ixINin2YTYpdiv
2KfYsdmKINmI2KfZhNmC2YrYp9iv2YouDQoNCsKnICAgICAgINin2YTZhdiz2KfYsSDYp9mE2YHZ
htmKINin2YTYqtiu2LXYtdmKLg0KDQrCpyAgICAgICDYp9mE2K/ZhdisINio2YrZhiDYp9mE2YXY
s9in2LHZitmGINmE2KrYrdmC2YrZgiDYp9mE2KrZiNin2LLZhiDYp9mE2YXYpNiz2LPZii4NCg0K
DQoNCtin2YTZhdit2YjYsSDYp9mE2LPYp9io2Lk6INin2YTYo9mG2LTYt9ipINin2YTYqti32KjZ
itmC2YrYqSDZiNin2YTZiNix2LQg2KfZhNi52YXZhNmK2KkNCg0KwqcgICAgICAgINiq2LTYrtmK
2LUg2KfZhNmF2LPYp9ix2KfYqiDYp9mE2YjYuNmK2YHZitipINin2YTYrdin2YTZitipINmB2Yog
2KjZitim2Kkg2KfZhNi52YXZhC4NCg0KwqcgICAgICAgINiq2LXZhdmK2YUg2K7Yp9ix2LfYqSDZ
hdiz2KfYsSDZiNi42YrZgdmKINmE2YTZgdix2K8v2KfZhNmB2LHZitmCLg0KDQrCpyAgICAgICAg
2YXYrdin2YPYp9ipINi52YXZhNmK2Kkg2YTYqtiu2LfZiti3INin2YTYpdit2YTYp9mEINin2YTZ
iNi42YrZgdmKINmI2KXYudiv2KfYryDYp9mE2YLYp9iv2KkuDQoNCsKnICAgICAgICDYrdin2YTY
p9iqINi52YXZhNmK2KkgKENhc2UgU3R1ZGllcykg2YXZhiDZhdik2LPYs9in2Kog2YXYrdmE2YrY
qSDZiNi52KfZhNmF2YrYqS4NCg0K8J+boO+4jyDYp9mE2KPZhti02LfYqSDYp9mE2KrYr9ix2YrY
qNmK2Kkg2YjYp9mE2KrYt9io2YrZgtin2Kog2KfZhNi52YXZhNmK2KkNCg0KwqcgICAgICAgINiq
2LTYrtmK2LUg2KfZhNmI2KfZgti5INin2YTZiNi42YrZgdmKOiDYqtmF2KfYsdmK2YYg2KrZgtmK
2YrZhSDYsNin2KrZiiDZiNiq2K3ZhNmK2YQg2KfZhNmF2LPYp9ix2KfYqiDYp9mE2K3Yp9mE2YrY
qS4NCg0KwqcgICAgICAgINiq2LXZhdmK2YUg2K7YsdmK2LfYqSDYp9mE2YXYs9in2LEg2KfZhNmI
2LjZitmB2Yo6INmI2LHYtCDYudmF2YQg2KrZgdin2LnZhNmK2Kkg2YTYsdiz2YUg2KfZhNmF2LPY
p9ixINin2YTZhdmH2YbZig0K2KfZhNi02K7YtdmKINmI2KfZhNmC2YrYp9iv2YouDQoNCsKnICAg
ICAgICDZhdit2KfZg9in2Kkg2YLYsdin2LHYp9iqINin2YTZgtmK2KfYr9ipOiDZhNi52Kgg2KPY
r9mI2KfYsSDZhNin2KrYrtin2LAg2YLYsdin2LHYp9iqINin2YTYqtix2YLZitipINmI2KfZhNil
2K3ZhNin2YQNCtmI2KrYrti32YrYtyDYp9mE2LXZgSDYp9mE2KvYp9mG2YouDQoNCsKnICAgICAg
ICDYrdin2YTYp9iqINi52YXZhNmK2KkgKENhc2UgU3R1ZGllcyk6INmF2YbYp9mC2LTYqSDYo9mF
2KvZhNipINmF2K3ZhNmK2Kkg2YjYudin2YTZhdmK2Kkg2YbYp9is2K3YqSDZgdmKDQrYqti32YjZ
itixINin2YTZhdiz2KfYsdin2KouDQoNCsKnICAgICAgICDZiNix2LQg2KXYqNiv2KfYudmK2Kk6
INit2YTZiNmEINmF2KjYqtmD2LHYqSDZhNmE2KrYudin2YXZhCDZhdi5INiq2K3Yr9mK2KfYqiDY
p9mE2KzZhdmI2K8g2YjYp9mE2KrYrdmB2YrYsi4NCg0KwqcgICAgICAgINio2YbYp9ihINiu2LfY
qSDYtNiu2LXZitipOiDYpdi52K/Yp9ivINiu2LfYqSDYqti32YjZitixINmB2LHYr9mK2Kkg2YTY
qtit2YLZitmCINin2YTYt9mF2YjYrdin2Kog2KfZhNmC2YrYp9iv2YrYqS4NCg0K4pymIOKcptmF
2K7Ysdis2KfYqiDYp9mE2KrYudmE2YUg2KfZhNmF2KrZiNmC2LnYqQ0KDQrCpyAgICAgICAg2YHZ
h9mFINi52YXZitmCINmE2YXZgdmH2YjZhSDYp9mE2YXYs9in2LEg2KfZhNmI2LjZitmB2Yog2YjY
r9mI2LHZhyDZgdmKINin2YTYqtmG2YXZitipINin2YTZgtmK2KfYr9mK2KkuDQoNCsKnICAgICAg
ICDYsdiz2YUg2YjYqti12YXZitmFINmF2LPYp9ix2KfYqiDZiNi42YrZgdmK2Kkg2LnZhdmE2YrY
qSDYqtiq2YbYp9iz2Kgg2YXYuSDYt9mF2YjYrdin2KrZh9mFINmI2KPZh9iv2KfZgSDZhdik2LPY
s9in2KrZh9mFLg0KDQrCpyAgICAgICAg2KfZhdiq2YTYp9mDINij2K/ZiNin2Kog2LnZhdmE2YrY
qSDZhNin2KrYrtin2LAg2YLYsdin2LHYp9iqINin2YTYqtix2YLZitipINmI2KfZhNil2K3ZhNin
2YQg2KfZhNmI2LjZitmB2Yog2KjZgdi52KfZhNmK2KkuDQoNCsKnICAgICAgICDYqti52LLZitiy
INmC2K/Ysdin2KrZh9mFINi52YTZiSDZhdmI2KfYrNmH2Kkg2KrYrdiv2YrYp9iqINin2YTZhtmF
2Ygg2YjYp9mE2KzZhdmI2K8g2KfZhNmI2LjZitmB2Yog2KjYt9ix2YIg2YXYqNiq2YPYsdipLg0K
DQrCpyAgICAgICAg2KfZhNiu2LHZiNisINio2K7Yt9ipINiq2LfZiNmK2LEg2YLZitin2K/Zitip
INmI2KfYttit2Kkg2YjZhdiq2YPYp9mF2YTYqSDZgtin2KjZhNipINmE2YTYqti32KjZitmCLg0K
DQrCpyAgICAgICAg2KfZhNmF2LPYp9mH2YXYqSDZgdmKINil2LnYr9in2K8g2LXZgSDYq9in2YbZ
jSDZhdmGINin2YTZgtin2K/YqSDZiti22YXZhiDYp9iz2KrZhdix2KfYsdmK2Kkg2YjZhtis2KfY
rSDYp9mE2YXYpNiz2LMNCg0K4pymIOKcptmF2YTYp9it2LjYp9iqINi52KfZhdipOg0KDQrCpyAg
ICAgICDYtNix2KfYptitINiq2YLYr9mK2YXZitipIChQb3dlclBvaW50KSDZhNmD2YQg2KzZhNiz
2KkuDQoNCsKnICAgICAgINmG2YXYp9iw2Kw6INiz2YrYp9iz2Kkg2KfZhNis2YjYr9ipINmI2KfZ
hNio2YrYptip2Iwg2KzYr9mI2YQg2KrYrdmE2YrZhCDYp9mE2YHYrNmI2KfYqtiMINiz2KzZhNin
2Kog2KfZhNiq2K/ZgtmK2YINCtin2YTYr9in2K7ZhNmK2Iwg2YLZiNin2KbZhSDZhdix2KfYrNi5
2KkuDQoNCsKnICAgICAgINit2KfZhNin2Kog2K/Ysdin2LPZitipINmI2KfZgti52YrYqSDZiNiq
2YXYp9ix2YrZhiDZhdmK2K/Yp9mG2YrYqSDZgti12YrYsdipLg0KDQrCpyAgICAgICDYrNmF2YrY
uSDYp9mE2LTZh9in2K/Yp9iqINiq2LTZhdmEINi02YfYp9iv2Kkg2YXYudiq2YXYr9ip2Iwg2K3Z
gtmK2KjYqSDYqtiv2LHZitio2YrYqdiMINmI2YjYsdi0INi52YXZhCDYqtmB2KfYudmE2YrYqS4N
Cg0KwqcgICAgICAg2YrZhdmD2YYg2KrZhtmB2YrYsCDYp9mE2KjYsdin2YXYrCDYrdi22YjYsdmK
2YvYpyDYo9mIINij2YjZhtmE2KfZitmGINi52KjYsSBab29tLg0KDQrCpyAgICAgICDYpdmF2YPY
p9mG2YrYqSDYqtiu2LXZiti1INij2Yog2LTZh9in2K/YqSDZhNiq2YPZiNmGINiv2KfYrtmEINin
2YTYtNix2YPYqSAoSW4tSG91c2UpLg0KDQoNCg0KItmB2Yog2KfZhNiv2KfYsSDYp9mE2LnYsdio
2YrYqSDZhNmE2KrZhtmF2YrYqSDYp9mE2KXYr9in2LHZitip2Iwg2YbZhNiq2LLZhSDYqNiq2YXZ
g9mK2YYg2KfZhNij2YHYsdin2K8g2YjYp9mE2YXYpNiz2LPYp9iqINmF2YYg2K7ZhNin2YQNCtio
2LHYp9mF2Kwg2KrYr9ix2YrYqNmK2Kkg2YjYr9mI2LHYp9iqINmI2YjYsdi0INi52YXZhCAg2YXY
qtmD2KfZhdmE2Kkg2YjYrtio2LHYp9iqINin2K3Yqtix2KfZgdmK2KnYjCDZhNmG2LXZhti5INmF
2LnZi9inINmC2K/Ysdin2KoNCtmF2LPYqtiv2KfZhdipINiq2K3ZgtmCINin2YTYqtmF2YrYsiDZ
iNin2YTYsdmK2KfYr9ipLiLZiNio2YfYsNmHINin2YTZhdmG2KfYs9io2Kkg2YrYs9i52K/Zhtin
INiv2LnZiNiq2YPZhSDZhNmE2YXYtNin2LHZg9ipINmI2KrYudmF2YrZhQ0K2K7Yt9in2KjZhtin
INi52YTZiSDYp9mE2YXZh9iq2YXZitmGINio2YXZgNmA2YjYttmA2YjYuSDYp9mE2LTZh9in2K/Y
qSDYp9mE2KfYrdiq2LHYp9mB2YrYqSDZiNil2YHYp9iv2KrZhtinINio2YXZhiDYqtmC2KrYsdit
2YjZhiDYqtmI2KzZitmHDQrYp9mE2K/YudmI2Kkg2YTZh9mFDQoNCtmE2YTYqtiz2KzZitmEINij
2Ygg2YTYt9mE2Kgg2KfZhNi52LHYtiDYp9mE2KrYr9ix2YrYqNmKINin2YTZg9in2YXZhNiMINmK
2LHYrNmJINin2YTYqtmI2KfYtdmEINmF2LnZhtinOg0KDQogINijIC8g2LPYp9ix2Kkg2LnYqNiv
INin2YTYrNmI2KfYryDigJPZhdiv2YrYsSDYp9mE2KrYr9ix2YrYqA0KDQrCqA0KDQrCqCAgICBb
2LHZgtmFINin2YTZh9in2KrZgSAvINmI2KfYqtizINin2KhdICAgIDAwMjAxMDY5OTk0Mzk5IC0w
MDIwMTA2Mjk5MjUxMCAtDQowMDIwMTA5Njg0MTYyNg0KDQotLSAKWW91IHJlY2VpdmVkIHRoaXMg
bWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAi
a2FzYW4tZGV2IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFuZCBzdG9w
IHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byBrYXNhbi1kZXYrdW5z
dWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24gdmlzaXQg
aHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9DQURqMVpLa1E4ZzE3
ZG93VXdxWHpKLTFSRWJ0a0t4dWMwcDhoUkslM0QlMkI1dnpqSk9vS1VBJTQwbWFpbC5nbWFpbC5j
b20uCg==
--000000000000a28c850640c7a1f8
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:jus=
tify;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-=
family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:black;background-image:initial;background-position:i=
nitial;background-size:initial;background-repeat:initial;background-origin:=
initial;background-clip:initial">=D9=85=D9=86 =D9=85=D9=88=D8=B8=D9=81 =D9=
=8A=D8=A4=D8=AF=D9=8A=E2=80=A6 =D8=A5=D9=84=D9=89 =D9=82=D8=A7=D8=A6=D8=AF =
=D9=8A=D9=8F=D9=84=D9=87=D9=85=C2=A0=C2=A0 =D8=A7=D9=84=D9=88=D8=B5=D9=88=
=D9=84 =D9=84=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D9=84=D9=8A=D8=B3 =D8=AD=
=D8=B8=D9=8B=D8=A7=E2=80=A6 =D8=A8=D9=84 =D9=82=D8=B1=D8=A7=D8=B1=D9=8B=D8=
=A7 =D9=8A=D8=A8=D8=AF=D8=A3 =D9=85=D9=86
=D9=87=D9=86=D8=A7.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D9=83=D9=84 =D9=82=D8=A7=D8=A6=D8=AF =D8=B9=D8=B8=
=D9=8A=D9=85 =D9=83=D8=A7=D9=86 =D9=8A=D9=88=D9=85=D9=8B=D8=A7 =D9=85=D9=88=
=D8=B8=D9=81=D9=8B=D8=A7 =D8=B9=D8=A7=D8=AF=D9=8A=D9=8B=D8=A7=D8=8C =D9=84=
=D9=83=D9=86=D9=87 =D9=82=D8=B1=D8=B1 =D8=A3=D9=86 =D9=8A=D8=B5=D9=86=D8=B9=
 =D9=85=D8=B3=D8=A7=D8=B1=D9=87
=D8=A8=D9=86=D9=81=D8=B3=D9=87. =D9=88=D9=85=D9=86 =D9=87=D9=86=D8=A7 =D8=
=AA=D9=86=D8=B7=D9=84=D9=82 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=
=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=
=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=D8=A8=
=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =
=D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=84=D8=AA=D8=A3=D9=87=D9=8A=
=D9=84 =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA
=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D9=84=D8=AA=D9=85=D9=86=
=D8=AD=D9=83 =D8=A7=D9=84=D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=
=D9=8A =D8=AA=D8=AD=D9=88=D9=91=D9=84 =D8=B7=D9=85=D9=88=D8=AD=D8=A7=D8=AA=
=D9=83 =D8=A5=D9=84=D9=89 =D9=88=D8=A7=D9=82=D8=B9 =D9=82=D9=8A=D8=A7=D8=AF=
=D9=8A =D9=85=D9=84=D9=85=D9=88=D8=B3.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;margin:0in 0in 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:36pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=AE=D9=84=D8=A7=D9=84 =D8=B4=D9=87=D8=B1 =D8=A7=D9=83=D8=
=AA=D9=88=D8=A8=D8=B1</span></b></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=C2=A0</span></p>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;margin:0.25in 0=
in 4pt;line-height:107%;break-after:avoid;direction:rtl;unicode-bidi:embed;=
font-size:20pt;font-family:&quot;Calibri Light&quot;,&quot;sans-serif&quot;=
;color:rgb(46,116,181);font-weight:normal"><b><span lang=3D"AR-SA" style=3D=
"font-family:&quot;Times New Roman&quot;,&quot;serif&quot;;color:windowtext=
">=D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=
=D9=8A =D9=84=D8=AA=D8=A3=D9=87=D9=8A=D9=84 =D8=A7=D9=84=D9=82=D9=8A=D8=A7=
=D8=AF=D8=A7=D8=AA
=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></b></h1>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-family:Arial,&quot=
;sans-serif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-EG" style=3D"font-size:24pt;line-hei=
ght:107%;font-family:&quot;Tholoth Rounded&quot;;color:rgb(192,0,0)">=D9=85=
=D8=A7
=D9=87=D9=88 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D9=88=D8=B8=
=D9=8A=D9=81=D9=8A=D8=9F</span><span lang=3D"AR-SA" style=3D"font-size:18pt=
;line-height:107%;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;=
;color:rgb(192,0,0);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;margin:0in 0=
in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:11pt;fon=
t-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-=
position:initial;background-size:initial;background-repeat:initial;backgrou=
nd-origin:initial;background-clip:initial">=D8=A7=D9=84=D9=85=D8=B3=D8=A7=
=D8=B1
=D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=87=D9=88 =D8=B3=D9=84=D8=B3=
=D9=84=D8=A9 =D9=85=D8=AA=D8=B9=D8=A7=D9=82=D8=A8=D8=A9 =D9=85=D9=86 =D8=A7=
=D9=84=D8=AA=D8=BA=D9=8A=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=88=D8=B8=D9=8A=
=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D9=8A =D9=8A=D9=85=D8=B1 =D8=A8=D9=87=
=D8=A7 =D8=A7=D9=84=D9=85=D9=88=D8=B8=D9=81 =D8=AE=D9=84=D8=A7=D9=84 =D8=AD=
=D9=8A=D8=A7=D8=AA=D9=87
=D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D8=AF=D8=A7=D8=AE=D9=84 =D8=A7=
=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A9. =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=D9=87=D8=B0=D9=
=87
=D8=A7=D9=84=D8=AA=D8=BA=D9=8A=D8=B1=D8=A7=D8=AA =D9=82=D8=AF =D8=AA=D9=83=
=D9=88=D9=86:</span></p>

<p class=3D"gmail-MsoListParagraph" dir=3D"RTL" style=3D"margin:0in 0.5in 8=
pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:11pt;fon=
t-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:14pt;line=
-height:107%;font-family:Symbol;color:rgb(64,64,64)">=C2=B7<span style=3D"f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-stretch:norm=
al;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;=
">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=
=B1 =D8=A7=D9=84=D8=B1=D8=A3=D8=B3=D9=8A (</span><span dir=3D"LTR" style=3D=
"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;=
,&quot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;backgr=
ound-position:initial;background-size:initial;background-repeat:initial;bac=
kground-origin:initial;background-clip:initial">Vertical Career Path</span>=
<span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" styl=
e=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&q=
uot;,&quot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;ba=
ckground-position:initial;background-size:initial;background-repeat:initial=
;background-origin:initial;background-clip:initial"><span dir=3D"RTL"></spa=
n><span dir=3D"RTL"></span>):</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D9=88=D9=8A=D8=B9=D8=A8=D8=B1 =D8=B9=D9=86 =D8=A7=
=D9=84=D8=AA=D8=B1=D9=82=D9=8A=D8=A9 =D8=A5=D9=84=D9=89 =D9=88=D8=B8=D9=8A=
=D9=81=D8=A9 =D8=A3=D8=B9=D9=84=D9=89 =D8=B6=D9=85=D9=86 =D8=A7=D9=84=D9=87=
=D9=8A=D9=83=D9=84 =D8=A7=D9=84=D8=AA=D9=86=D8=B8=D9=8A=D9=85=D9=8A=D8=8C =
=D8=AD=D9=8A=D8=AB =D9=8A=D8=AD=D9=82=D9=82 =D8=A7=D9=84=D9=85=D9=88=D8=B8=
=D9=81 =D8=AA=D9=82=D8=AF=D9=91=D9=85=D9=8B=D8=A7
=D9=88=D8=B8=D9=8A=D9=81=D9=8A=D9=8B=D8=A7 =D8=A3=D9=83=D8=A8=D8=B1=D8=8C =
=D9=8A=D8=AD=D8=B5=D9=84 =D8=B9=D9=84=D9=89 =D8=A3=D8=AC=D8=B1 =D8=A3=D8=B9=
=D9=84=D9=89=D8=8C =D9=88=D9=8A=D9=83=D8=AA=D8=B3=D8=A8 =D9=85=D9=83=D8=A7=
=D9=86=D8=A9 =D9=88=D8=B8=D9=8A=D9=81=D9=8A=D8=A9 =D9=88=D9=85=D8=B3=D8=A4=
=D9=88=D9=84=D9=8A=D8=A7=D8=AA =D8=A3=D9=88=D8=B3=D8=B9.</span></p>

<p class=3D"gmail-MsoListParagraph" dir=3D"RTL" style=3D"margin:0in 0.5in 8=
pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:11pt;fon=
t-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:14pt;line=
-height:107%;font-family:Symbol;color:rgb(64,64,64)">=C2=B7<span style=3D"f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-stretch:norm=
al;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;=
">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=
=B1 =D8=A7=D9=84=D8=A3=D9=81=D9=82=D9=8A (</span><span dir=3D"LTR" style=3D=
"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;=
,&quot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;backgr=
ound-position:initial;background-size:initial;background-repeat:initial;bac=
kground-origin:initial;background-clip:initial">Horizontal Career Path</spa=
n><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" st=
yle=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black=
&quot;,&quot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;=
background-position:initial;background-size:initial;background-repeat:initi=
al;background-origin:initial;background-clip:initial"><span dir=3D"RTL"></s=
pan><span dir=3D"RTL"></span>):</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D9=88=D9=8A=D8=B4=D9=8A=D8=B1 =D8=A5=D9=84=D9=89 =
=D8=A7=D9=86=D8=AA=D9=82=D8=A7=D9=84 =D8=A7=D9=84=D9=85=D9=88=D8=B8=D9=81 =
=D8=A8=D9=8A=D9=86 =D9=88=D8=B8=D8=A7=D8=A6=D9=81 =D8=A3=D9=88 =D9=85=D9=87=
=D8=A7=D9=85 =D9=85=D8=AE=D8=AA=D9=84=D9=81=D8=A9 =D8=B9=D9=84=D9=89 =D9=86=
=D9=81=D8=B3 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=88=D9=89
=D8=A7=D9=84=D8=AA=D9=86=D8=B8=D9=8A=D9=85=D9=8A=D8=8C =D8=AF=D9=88=D9=86 =
=D8=A3=D9=86 =D9=8A=D8=B1=D8=AA=D8=A8=D8=B7 =D8=B0=D9=84=D9=83 =D8=A8=D8=A7=
=D9=84=D8=B6=D8=B1=D9=88=D8=B1=D8=A9 =D8=A8=D9=85=D9=83=D8=A7=D9=86=D8=A9 =
=D8=A5=D8=B4=D8=B1=D8=A7=D9=81=D9=8A=D8=A9 =D8=A3=D8=B9=D9=84=D9=89=D8=8C =
=D9=84=D9=83=D9=86=D9=87 =D9=8A=D8=AA=D9=8A=D8=AD =D9=84=D9=87 =D8=A7=D9=83=
=D8=AA=D8=B3=D8=A7=D8=A8
=D8=AE=D8=A8=D8=B1=D8=A7=D8=AA =D8=AC=D8=AF=D9=8A=D8=AF=D8=A9 =D9=88=D8=AA=
=D9=88=D8=B3=D9=8A=D8=B9 =D9=82=D8=A7=D8=B9=D8=AF=D8=A9 =D9=85=D8=B9=D8=A7=
=D8=B1=D9=81=D9=87 =D9=88=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA=D9=87.</span>=
</p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D9=88=D9=85=D9=86 =D9=87=D9=86=D8=A7 =D9=8A=D9=85=
=D9=83=D9=86 =D8=A7=D9=84=D9=82=D9=88=D9=84 =D8=A5=D9=86 =D8=A7=D9=84=D9=85=
=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=87=D9=88 =
=D8=A7=D9=84=D8=A5=D8=B7=D8=A7=D8=B1 =D8=A7=D9=84=D8=B0=D9=8A =D9=8A=D9=85=
=D9=83=D9=91=D9=86 =D8=A7=D9=84=D9=85=D9=88=D8=B8=D9=81 =D9=85=D9=86 =D8=B1=
=D8=B3=D9=85 =D8=B7=D9=85=D9=88=D8=AD=D8=A7=D8=AA=D9=87
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9 =D8=A8=D9=85=D8=A7 =D9=8A=D8=AA=
=D9=86=D8=A7=D8=B3=D8=A8 =D9=85=D8=B9 =D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA=
=D9=87 =D9=88=D9=82=D8=AF=D8=B1=D8=A7=D8=AA=D9=87=D8=8C =C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=D9=81=D9=8A =D8=B6=D9=88=D8=A1 =D9=85=D8=A7 =D8=AA=D8=AD=D8=AF=D8=
=AF=D9=87 =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=
=B1=D8=AF
=D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9 =D9=85=D9=86 =D9=81=D8=B1=D8=B5 =
=D9=88=D9=85=D8=B3=D8=A7=D8=B1=D8=A7=D8=AA =D8=AF=D8=A7=D8=AE=D9=84 =D8=A7=
=D9=84=D9=87=D9=8A=D9=83=D9=84 =D8=A7=D9=84=D8=AA=D9=86=D8=B8=D9=8A=D9=85=
=D9=8A =D9=84=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A9.</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%;font-family:&quot;Segoe UI Symbol&=
quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span dir=3D"LTR" style=3D"font-size:14pt;line-height=
:107%;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;color:=
rgb(255,192,0)">=C2=A0=E2=9C=A6</span><span dir=3D"LTR" style=3D"font-size:=
14pt;line-height:107%;font-family:AMoshref-Thulth;color:rgb(255,192,0)"> </=
span><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family=
:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)">=
=E2=9C=A6</span><span lang=3D"AR-EG" style=3D"font-size:24pt;line-height:10=
7%;font-family:&quot;Tholoth Rounded&quot;;color:rgb(56,86,35)">=D8=A7=D9=
=84=D8=A3=D9=87=D8=AF=D8=A7=D9=81
=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D8=A9</span><span lang=3D"AR-SA" style=3D"fo=
nt-size:20pt;line-height:107%;font-family:AMoshref-Thulth;color:rgb(83,129,=
53);background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial">:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font=
-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-=
size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot=
;sans-serif&quot;;color:rgb(64,64,64)">1.<span style=3D"font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-stretch:normal;font-size:7pt;l=
ine-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&q=
uot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;backgroun=
d-position:initial;background-size:initial;background-repeat:initial;backgr=
ound-origin:initial;background-clip:initial">=D8=AA=D8=B9=D8=B1=D9=8A=D9=81
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D8=A8=D9=85=D9=81=
=D9=87=D9=88=D9=85 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D9=88=
=D8=B8=D9=8A=D9=81=D9=8A =D9=88=D8=A3=D8=A8=D8=B9=D8=A7=D8=AF=D9=87 =D9=88=
=D8=AF=D9=88=D8=B1=D9=87 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=
=D8=B1 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A =D9=88=D8=A8=D9=86=D8=A7=
=D8=A1
=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;;color:rgb(64,64,64)">2.<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-stretch:normal;font-size:7pt;=
line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&q=
uot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;backgroun=
d-position:initial;background-size:initial;background-repeat:initial;backgr=
ound-origin:initial;background-clip:initial">=D8=AA=D9=86=D9=85=D9=8A=D8=A9
=D8=A7=D9=84=D9=88=D8=B9=D9=8A =D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7=
=D9=8A =D9=88=D8=A7=D9=84=D8=A5=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=
=D9=8A =D9=84=D8=AF=D9=89 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=
=D9=86 =D9=84=D8=B1=D8=A8=D8=B7 =D8=B7=D9=85=D9=88=D8=AD=D8=A7=D8=AA=D9=87=
=D9=85 =D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9 =D8=A8=D8=A7=D8=AD=D8=AA=
=D9=8A=D8=A7=D8=AC=D8=A7=D8=AA
=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;;color:rgb(64,64,64)">3.<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-stretch:normal;font-size:7pt;=
line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&q=
uot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;backgroun=
d-position:initial;background-size:initial;background-repeat:initial;backgr=
ound-origin:initial;background-clip:initial">=D8=A5=D9=83=D8=B3=D8=A7=D8=A8
=D8=A7=D9=84=D9=85=D8=B4=D8=B1=D9=81=D9=8A=D9=86 =D9=88=D8=B1=D8=A4=D8=B3=
=D8=A7=D8=A1 =D8=A7=D9=84=D8=A3=D9=82=D8=B3=D8=A7=D9=85 =D9=85=D9=87=D8=A7=
=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=
=D8=A5=D8=B4=D8=B1=D8=A7=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D9=81=D8=B9=D9=91=
=D8=A7=D9=84=D8=A9 =D9=85=D9=86 (=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =E2=80=93 =
=D8=AA=D9=86=D8=B8=D9=8A=D9=85 =E2=80=93
=D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =E2=80=93 =D8=AA=D9=82=D9=8A=D9=8A=D9=
=85).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;;color:rgb(64,64,64)">4.<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-stretch:normal;font-size:7pt;=
line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&q=
uot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;backgroun=
d-position:initial;background-size:initial;background-repeat:initial;backgr=
ound-origin:initial;background-clip:initial">=D8=AA=D8=B9=D8=B2=D9=8A=D8=B2
=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=
=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=85=D8=AB=D9=84 =D8=A7=
=D9=84=D8=AA=D9=81=D9=88=D9=8A=D8=B6=D8=8C =D8=A7=D9=84=D8=AA=D9=81=D8=A7=
=D9=88=D8=B6=D8=8C =D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=
=D8=A7=D8=B1=D8=8C =D9=88=D8=AD=D9=84 =D8=A7=D9=84=D9=85=D8=B4=D9=83=D9=84=
=D8=A7=D8=AA =D8=A8=D8=A3=D8=B3=D8=A7=D9=84=D9=8A=D8=A8
=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9 =D9=88=D8=A5=D8=A8=D8=AF=D8=A7=D8=B9=D9=8A=
=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;;color:rgb(64,64,64)">5.<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-stretch:normal;font-size:7pt;=
line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&q=
uot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;backgroun=
d-position:initial;background-size:initial;background-repeat:initial;backgr=
ound-origin:initial;background-clip:initial">=D8=AA=D8=B7=D9=88=D9=8A=D8=B1
=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=
=D9=84 =D9=88=D8=A7=D9=84=D8=A5=D9=82=D9=86=D8=A7=D8=B9 =D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=81=D8=B1=D9=82 =D9=88=D8=A8=D9=86=D8=A7=
=D8=A1 =D8=B9=D9=84=D8=A7=D9=82=D8=A7=D8=AA =D8=B9=D9=85=D9=84 =D8=A5=D9=8A=
=D8=AC=D8=A7=D8=A8=D9=8A=D8=A9 =D9=88=D9=81=D8=B9=D9=91=D8=A7=D9=84=D8=A9.<=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 0.5in 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;;color:rgb(64,64,64)">6.<span style=3D"font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-stretch:normal;font-size:7pt;=
line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=
=A0 </span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&q=
uot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;backgroun=
d-position:initial;background-size:initial;background-repeat:initial;backgr=
ound-origin:initial;background-clip:initial">=D8=AA=D9=85=D9=83=D9=8A=D9=86
=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=8A=D9=86 =D9=85=D9=86 =D8=B1=
=D8=B3=D9=85 =D8=AE=D8=B7=D8=B7=D9=87=D9=85 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=
=D9=81=D9=8A=D8=A9 =D9=88=D8=B5=D9=8A=D8=A7=D8=BA=D8=A9 =D8=A3=D9=87=D8=AF=
=D8=A7=D9=81 =D9=88=D8=A7=D8=B6=D8=AD=D8=A9 =D8=AA=D8=B3=D8=A7=D8=B9=D8=AF=
=D9=87=D9=85 =D9=81=D9=8A =D8=AA=D8=AD=D9=82=D9=8A=D9=82 =D9=85=D8=B3=D8=A7=
=D8=B1 =D9=85=D9=87=D9=86=D9=8A
=D9=85=D8=AA=D9=88=D8=A7=D8=B2=D9=86 =D9=88=D9=85=D8=AA=D8=AF=D8=B1=D8=AC.<=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 0.5in 8pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;font-size:=
11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:1=
4pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-=
serif&quot;;color:rgb(64,64,64)">7.<span style=3D"font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-stretch:normal;font-size:7pt;line-he=
ight:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0 </s=
pan></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size=
:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;san=
s-serif&quot;;color:rgb(64,64,64);background-image:initial;background-posit=
ion:initial;background-size:initial;background-repeat:initial;background-or=
igin:initial;background-clip:initial">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
=D8=A7=D9=84=D9=83=D9=88=D8=A7=D8=AF=D8=B1 =D8=A7=D9=84=D9=88=D8=A7=D8=B9=
=D8=AF=D8=A9 =D9=84=D8=AA=D9=88=D9=84=D9=8A =D9=85=D9=86=D8=A7=D8=B5=D8=A8 =
=D9=82=D9=8A=D8=A7=D8=AF=D9=8A=D8=A9 =D9=85=D8=B3=D8=AA=D9=82=D8=A8=D9=84=
=D9=8A=D8=A9=D8=8C =D8=A8=D9=85=D8=A7 =D9=8A=D8=B6=D9=85=D9=86 =D8=A7=D8=B3=
=D8=AA=D9=85=D8=B1=D8=A7=D8=B1=D9=8A=D8=A9 =D9=88=D8=A7=D8=B3=D8=AA=D9=82=
=D8=B1=D8=A7=D8=B1 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1
=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-EG" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span lang=3D"AR-EG" style=3D"font-size:14pt;line-hei=
ght:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an lang=3D"AR-EG" dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font=
-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,19=
2,0)"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=A0</span><span =
dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;Sego=
e UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)">=E2=9C=A6</s=
pan><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:=
AMoshref-Thulth;color:rgb(255,192,0)"> </span><span dir=3D"LTR" style=3D"fo=
nt-size:14pt;line-height:107%;font-family:&quot;Segoe UI Symbol&quot;,&quot=
;sans-serif&quot;;color:rgb(255,192,0)">=E2=9C=A6</span><span lang=3D"AR-EG=
" style=3D"font-size:24pt;line-height:107%;font-family:&quot;Tholoth Rounde=
d&quot;;color:rgb(56,86,35)">=D8=A7=D9=84=D9=81=D8=A6=D8=A7=D8=AA
=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9:</span><span lang=3D=
"AR-SA" style=3D"font-size:20pt;line-height:107%;font-family:AMoshref-Thult=
h;color:rgb(83,129,53);background-image:initial;background-position:initial=
;background-size:initial;background-repeat:initial;background-origin:initia=
l;background-clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:black;background-image:initial;background-position:initial;background=
-size:initial;background-repeat:initial;background-origin:initial;backgroun=
d-clip:initial">=D8=A7=D9=84=D9=83=D9=81=D8=A7=D8=A1=D8=A7=D8=AA =D8=A7=D9=
=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=B4=D8=
=AD=D8=A9
=D9=84=D8=B4=D8=BA=D9=84 =D9=85=D9=88=D8=A7=D9=82=D8=B9 =D9=82=D9=8A=D8=A7=
=D8=AF=D9=8A=D8=A9 =D9=85=D8=B3=D8=AA=D9=82=D8=A8=D9=84=D9=8A=D8=A9.</span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:black;background-image:initial;background-position:initial;background=
-size:initial;background-repeat:initial;background-origin:initial;backgroun=
d-clip:initial">=D8=A7=D9=84=D9=85=D8=AF=D9=8A=D8=B1=D9=88=D9=86 =D8=A7=D9=
=84=D8=AC=D8=AF=D8=AF =D8=A7=D9=84=D8=B0=D9=8A=D9=86 =D8=A8=D8=AF=D8=A3=D9=
=88=D8=A7
=D8=A3=D9=88=D9=84=D9=89 =D8=AE=D8=B7=D9=88=D8=A7=D8=AA=D9=87=D9=85 =D9=81=
=D9=8A =D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =
=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:black;background-image:initial;background-position:initial;background=
-size:initial;background-repeat:initial;background-origin:initial;backgroun=
d-clip:initial">=D8=B1=D8=A4=D8=B3=D8=A7=D8=A1 =D8=A7=D9=84=D8=A3=D9=82=D8=
=B3=D8=A7=D9=85 =D9=88=D9=81=D8=B1=D9=82 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=
=A8=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9
=D8=A7=D9=84=D8=AA=D8=B4=D8=BA=D9=8A=D9=84=D9=8A=D8=A9 =D8=A5=D9=84=D9=89 =
=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=A5=D8=B3=D8=AA=
=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:black;background-image:initial;background-position:initial;background=
-size:initial;background-repeat:initial;background-origin:initial;backgroun=
d-clip:initial">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D9=
=84=D9=88=D8=B3=D8=B7=D9=89 =D8=A7=D9=84=D8=AA=D9=8A =D8=AA=D8=B4=D9=83=D9=
=84
=D8=AD=D9=84=D9=82=D8=A9 =D9=88=D8=B5=D9=84 =D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=
=D8=A9 =D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=B9=D9=84=D9=8A=D8=A7 =D9=88=D8=A7=D9=84=D8=B5=D9=81=D9=88=D9=81 =
=D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:black;background-image:initial;background-position:initial;background=
-size:initial;background-repeat:initial;background-origin:initial;backgroun=
d-clip:initial">=D8=A7=D9=84=D9=85=D9=88=D8=B8=D9=81=D9=88=D9=86 =D8=B0=D9=
=88=D9=88 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=AA=D9=
=85=D9=8A=D8=B2
=D8=A7=D9=84=D8=B0=D9=8A=D9=86 =D8=AA=D8=B9=D8=AA=D9=85=D8=AF =D8=B9=D9=84=
=D9=8A=D9=87=D9=85 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D9=81=
=D9=8A =D8=AE=D8=B7=D8=B7 =D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=A7=D9=84=D9=82=
=D8=A7=D8=AF=D8=A9 =D9=88=D8=B5=D9=86=D8=A7=D8=B9=D8=A9 =D8=A7=D9=84=D8=B5=
=D9=81 =D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"line-heigh=
t:normal;margin:0in 0.5in 8pt 0in;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size=
:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-variant-=
numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:black;background-image:initial;background-position:initial;background=
-size:initial;background-repeat:initial;background-origin:initial;backgroun=
d-clip:initial">=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D8=A7=D9=
=84=D8=B3=D8=A7=D8=B9=D9=8A=D8=A9 =D8=A5=D9=84=D9=89 =D8=A8=D9=86=D8=A7=D8=
=A1
=D9=82=D8=A7=D8=B9=D8=AF=D8=A9 =D9=82=D9=8A=D8=A7=D8=AF=D9=8A=D8=A9 =D9=85=
=D8=A4=D9=87=D9=84=D8=A9 =D8=AA=D8=B6=D9=85=D9=86 =D8=A7=D8=B3=D8=AA=D8=AF=
=D8=A7=D9=85=D8=A9 =D8=A7=D9=84=D9=86=D9=85=D9=88 =D9=88=D8=A7=D9=84=D8=AA=
=D9=81=D9=88=D9=82 =D8=A7=D9=84=D8=AA=D9=86=D8=A7=D9=81=D8=B3=D9=8A.</span>=
<span dir=3D"LTR" style=3D"font-size:14pt;font-family:&quot;Segoe UI Symbol=
&quot;,&quot;sans-serif&quot;;color:black"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span dir=3D"LTR" style=3D"font-size:14pt;font-fami=
ly:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)"=
>=E2=9C=A6</span><span dir=3D"LTR" style=3D"font-size:14pt;font-family:AMos=
href-Thulth;color:rgb(255,192,0)"> </span><span dir=3D"LTR" style=3D"font-s=
ize:14pt;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;col=
or:rgb(255,192,0)">=E2=9C=A6</span><span lang=3D"AR-EG" style=3D"font-size:=
24pt;font-family:&quot;Tholoth Rounded&quot;;color:rgb(56,86,35)">=D8=A7=D9=
=84=D9=85=D8=AD=D8=A7=D9=88=D8=B1 =D8=A7=D9=84=D8=B1=D8=A6=D9=8A=D8=B3=D9=
=8A=D8=A9 =D9=88=D9=85=D9=86=D9=87=D9=8A=D8=AC=D8=A9
=D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC </span><span lang=3D"AR-SA=
" style=3D"font-size:20pt;font-family:AMoshref-Thulth;color:rgb(83,129,53);=
background-image:initial;background-position:initial;background-size:initia=
l;background-repeat:initial;background-origin:initial;background-clip:initi=
al"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=A3=D9=88=D9=84: =D9=85=D8=AF=D8=AE=
=D9=84 =D8=A5=D9=84=D9=89 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=
=D9=88=D8=B8=D9=8A=D9=81=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D9=85=D9=81=D9=87=D9=88=D9=85 =D9=88=D8=A7=D9=84=D8=A3=D8=B3=
=D8=B3 =D8=A7=D9=84=D9=86=D8=B8=D8=B1=D9=8A=D8=A9 =D9=84=D9=84=D9=85=D8=B3=
=D8=A7=D8=B1 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AE=D8=B5=D8=A7=D8=A6=D8=B5 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=
=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=88=D8=A3=D8=A8=D8=B9=D8=A7=D8=AF=
=D9=87.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"line-heigh=
t:normal;margin:0in 0.5in 8pt 0in;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size=
:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-variant-=
numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D8=B9=D9=84=D8=A7=D9=82=D8=A9 =D8=A8=D9=8A=D9=86 =D8=AA=D8=AE=
=D8=B7=D9=8A=D8=B7 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=
=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9 =D9=88=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D8=A7=
=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A.<=
/span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:5pt;font-fa=
mily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</span></=
p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A: =D8=A3=D9=87=
=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D9=88=
=D8=B8=D9=8A=D9=81=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A3=D9=87=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=
=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=84=D9=84=D9=81=D8=B1=D8=AF (=D8=A7=
=D9=84=D8=B7=D9=85=D9=88=D8=AD=D8=A7=D8=AA=D8=8C =D8=A7=D9=84=D8=B1=D8=B6=
=D8=A7=D8=8C =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B2=D9=86 =D8=A8=D9=8A=D9=86
=D8=A7=D9=84=D8=AD=D9=8A=D8=A7=D8=A9 =D9=88=D8=A7=D9=84=D8=B9=D9=85=D9=84=
=D8=8C =D8=A8=D9=86=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=
=D8=AA).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A3=D9=87=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=
=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=84=D9=84=D9=85=D8=A4=D8=B3=D8=B3=
=D8=A9 (=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=82=D8=B7=D8=A7=D8=A8=D8=8C =D8=A7=
=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9=D8=8C =D8=AA=D8=AE=D8=B7=D9=8A=D8=B7
=D8=A7=D9=84=D8=A5=D8=AD=D9=84=D8=A7=D9=84=D8=8C =D8=AA=D8=B9=D8=B2=D9=8A=
=D8=B2 =D8=A7=D9=84=D8=B5=D9=88=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=
=D8=B3=D9=8A=D8=A9).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"line-heigh=
t:normal;margin:0in 0.5in 8pt 0in;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size=
:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-variant-=
numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D9=85=D9=86=D9=81=D8=B9=D8=A9 =D8=A7=D9=84=D9=85=D8=AA=D8=A8=
=D8=A7=D8=AF=D9=84=D8=A9 =D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D9=81=D8=B1=D8=AF =
=D9=88=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A9 =D9=81=D9=8A =D8=AA=D8=B7=
=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1=D8=A7=D8=AA
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A=D8=A9.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:5pt;font-fa=
mily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</span></=
p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=AB=D8=A7=D9=84=D8=AB: =D9=85=D8=B1=
=D8=A7=D8=AD=D9=84 =D8=AA=D8=B7=D9=88=D8=B1 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=
=D8=B1 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=85=D8=B1=D8=AD=D9=84=D8=A9 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=83=D8=B4=
=D8=A7=D9=81.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=85=D8=B1=D8=AD=D9=84=D8=A9 =D8=A7=D9=84=D8=AA=D8=A3=D8=B3=D9=8A=D8=B3.=
</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=85=D8=B1=D8=AD=D9=84=D8=A9 =D8=A7=D9=84=D8=AD=D9=81=D8=A7=D8=B8 =D8=A3=
=D9=88 =D8=A7=D9=84=D8=B5=D9=8A=D8=A7=D9=86=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=85=D8=B1=D8=AD=D9=84=D8=A9 =D8=A7=D9=84=D8=A7=D9=86=D9=81=D8=B5=D8=A7=
=D9=84 =D8=A3=D9=88 =D8=A7=D9=84=D8=AA=D9=82=D8=A7=D8=B9=D8=AF.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"line-heigh=
t:normal;margin:0in 0.5in 8pt 0in;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size=
:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-variant-=
numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D8=AA=D8=AD=D8=AF=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=8A =
=D8=AA=D9=88=D8=A7=D8=AC=D9=87 =D8=A7=D9=84=D8=A3=D9=81=D8=B1=D8=A7=D8=AF =
=D9=88=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D9=81=D9=8A =D9=83=
=D9=84 =D9=85=D8=B1=D8=AD=D9=84=D8=A9.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:5pt;font-fa=
mily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</span></=
p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=B1=D8=A7=D8=A8=D8=B9: =D8=A7=D8=B3=
=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=D8=A7=D8=AA =D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =
=D9=88=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =
=D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A7=
=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=
=D8=B5=D9=81 =D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A =D9=85=D9=86 =D8=A7=D9=84=
=D9=82=D8=A7=D8=AF=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D8=AA=D8=B1=D9=82=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=86=D9=82=
=D9=84 =D9=88=D8=A7=D9=84=D8=A5=D8=AD=D9=84=D8=A7=D9=84 =D8=A7=D9=84=D9=88=
=D8=B8=D9=8A=D9=81=D9=8A.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=
=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=85=D8=B1.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AA=D9=82=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D9=83=D8=A7=D9=84=D9=8A=
=D9=81 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=82=D8=A8=D9=84=D9=8A=D8=A9 =D9=84=
=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=
=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"line-heigh=
t:normal;margin:0in 0.5in 8pt 0in;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size=
:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-variant-=
numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D8=AA=D9=83=D9=8A=D9=81 =D9=85=D8=B9 =D8=A7=D9=84=D8=AA=D8=BA=
=D9=8A=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A7=D9=82=D8=AA=D8=B5=D8=A7=D8=AF=
=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=
=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D9=86=D8=B8=D9=8A=D9=85=D9=8A=D8=A9.<=
/span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=AE=D8=A7=D9=85=D8=B3: =D8=A7=D8=B3=
=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA =D8=AA=D8=B7=D9=88=
=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D9=88=D8=B8=
=D9=8A=D9=81=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D9=85=D9=85=D8=A7=D8=B1=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=
=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D9=86=D8=B8=D9=8A=
=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=AF=D8=A7=D8=B9=D9=85=D8=A9 (=D8=A7=D9=84=
=D8=A7=D8=AE=D8=AA=D9=8A=D8=A7=D8=B1=D8=8C =D8=A7=D9=84=D8=AA=D8=B9=D9=8A=
=D9=8A=D9=86=D8=8C
=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D8=8C =D8=A7=D9=84=D8=AA=D8=B1=
=D9=82=D9=8A=D8=A9=D8=8C =D8=A7=D9=84=D9=86=D9=82=D9=84).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D9=86=D8=B8=D9=85 =D9=88=D8=A7=D9=84=D8=B3=D9=8A=D8=A7=D8=B3=
=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=8A =D8=AA=D8=B6=D9=85=D9=86 =D8=A7=D8=B3=
=D8=AA=D9=85=D8=B1=D8=A7=D8=B1=D9=8A=D8=A9 =D9=88=D8=AA=D9=83=D8=A7=D9=85=
=D9=84 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=
=D9=81=D9=8A.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A8=D9=86=D8=A7=D8=A1 =D8=A8=D9=8A=D8=A6=D8=A9 =D8=B9=D9=85=D9=84 =D9=
=85=D8=AD=D9=81=D8=B2=D8=A9 =D9=84=D9=84=D9=86=D9=85=D9=88 =D9=88=D8=AA=D8=
=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=82=D8=AF=D8=B1=D8=A7=D8=AA.</span></p=
>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"line-heigh=
t:normal;margin:0in 0.5in 8pt 0in;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size=
:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-variant-=
numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AC=D9=85=D9=88=D8=AF =D9=88=
=D8=A7=D9=84=D8=B1=D8=B3=D9=88=D8=A8 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=
=D9=8A.</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:5pt;font-fa=
mily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</span></=
p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=B3=D8=A7=D8=AF=D8=B3: =D9=85=D8=AC=
=D8=A7=D9=84=D8=A7=D8=AA =D8=B1=D8=B3=D9=85 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=
=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A=D8=A9</span><=
/p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:16pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=
=D9=8A =D9=88=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D9=8A.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:16pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D9=81=D9=86=D9=8A =D8=A7=
=D9=84=D8=AA=D8=AE=D8=B5=D8=B5=D9=8A.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"line-heigh=
t:normal;margin:0in 0.5in 8pt 0in;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size=
:16pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-variant-=
numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A7=D9=84=D8=AF=D9=85=D8=AC =D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D9=85=D8=B3=
=D8=A7=D8=B1=D9=8A=D9=86 =D9=84=D8=AA=D8=AD=D9=82=D9=8A=D9=82 =D8=A7=D9=84=
=D8=AA=D9=88=D8=A7=D8=B2=D9=86 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A.<=
/span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:5pt;font-fa=
mily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=C2=A0</span></=
p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=D8=A7=D9=84=
=D9=85=D8=AD=D9=88=D8=B1 =D8=A7=D9=84=D8=B3=D8=A7=D8=A8=D8=B9: =D8=A7=D9=84=
=D8=A3=D9=86=D8=B4=D8=B7=D8=A9 =D8=A7=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=
=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D9=88=D8=B1=D8=B4 =D8=A7=D9=84=D8=B9=D9=85=
=D9=84=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AA=D8=B4=D8=AE=D9=8A=D8=B5 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1=D8=A7=
=D8=AA =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D8=AD=
=D8=A7=D9=84=D9=8A=D8=A9 =D9=81=D9=8A =D8=A8=D9=8A=D8=A6=D8=A9 =D8=A7=D9=84=
=D8=B9=D9=85=D9=84.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AA=D8=B5=D9=85=D9=8A=D9=85 =D8=AE=D8=A7=D8=B1=D8=B7=D8=A9 =D9=85=D8=B3=
=D8=A7=D8=B1 =D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=84=D9=84=D9=81=D8=B1=D8=AF/=
=D8=A7=D9=84=D9=81=D8=B1=D9=8A=D9=82.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=85=D8=AD=D8=A7=D9=83=D8=A7=D8=A9 =D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=84=
=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D8=A7=D9=84=D8=A5=D8=AD=D9=84=D8=A7=D9=84 =
=D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=88=D8=A5=D8=B9=D8=AF=D8=A7=
=D8=AF =D8=A7=D9=84=D9=82=D8=A7=D8=AF=D8=A9.</span><span dir=3D"LTR" style=
=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-se=
rif&quot;"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"line-heigh=
t:normal;margin:0in 0.5in 8pt 0in;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size=
:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-variant-=
numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=B9=D9=85=D9=84=D9=8A=D8=A9 (</span><spa=
n dir=3D"LTR" style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&=
quot;,&quot;sans-serif&quot;">Case Studies</span><span dir=3D"RTL"></span><=
span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"><span dir=3D"R=
TL"></span><span dir=3D"RTL"></span>) =D9=85=D9=86 =D9=85=D8=A4=D8=B3=D8=B3=
=D8=A7=D8=AA =D9=85=D8=AD=D9=84=D9=8A=D8=A9 =D9=88=D8=B9=D8=A7=D9=84=D9=85=
=D9=8A=D8=A9.</span><span dir=3D"LTR" style=3D"font-size:14pt;font-family:&=
quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span lang=3D"AR-EG" style=3D"font-size:24pt;font-f=
amily:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(56,86,35=
)">=F0=9F=9B=A0=EF=B8=8F</span><span lang=3D"AR-EG" style=3D"font-size:24pt=
;font-family:&quot;Tholoth Rounded&quot;;color:rgb(56,86,35)"> =D8=A7=D9=84=
=D8=A3=D9=86=D8=B4=D8=B7=D8=A9 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=
=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA =
=D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AA=D8=B4=D8=AE=D9=8A=D8=B5 =D8=A7=D9=84=D9=88=D8=A7=D9=82=D8=B9 =D8=A7=
=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A: =D8=AA=D9=85=D8=A7=D8=B1=D9=8A=D9=86 =
=D8=AA=D9=82=D9=8A=D9=8A=D9=85 =D8=B0=D8=A7=D8=AA=D9=8A =D9=88=D8=AA=D8=AD=
=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1=D8=A7=D8=AA
=D8=A7=D9=84=D8=AD=D8=A7=D9=84=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AA=D8=B5=D9=85=D9=8A=D9=85 =D8=AE=D8=B1=D9=8A=D8=B7=D8=A9 =D8=A7=D9=84=
=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A: =D9=88=
=D8=B1=D8=B4 =D8=B9=D9=85=D9=84 =D8=AA=D9=81=D8=A7=D8=B9=D9=84=D9=8A=D8=A9 =
=D9=84=D8=B1=D8=B3=D9=85 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1
=D8=A7=D9=84=D9=85=D9=87=D9=86=D9=8A =D8=A7=D9=84=D8=B4=D8=AE=D8=B5=D9=8A =
=D9=88=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D9=8A.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=85=D8=AD=D8=A7=D9=83=D8=A7=D8=A9 =D9=82=D8=B1=D8=A7=D8=B1=D8=A7=D8=AA =
=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9: =D9=84=D8=B9=D8=A8 =D8=A3=D8=AF=
=D9=88=D8=A7=D8=B1 =D9=84=D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D9=82=D8=B1=D8=A7=
=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=B1=D9=82=D9=8A=D8=A9
=D9=88=D8=A7=D9=84=D8=A5=D8=AD=D9=84=D8=A7=D9=84 =D9=88=D8=AA=D8=AE=D8=B7=
=D9=8A=D8=B7 =D8=A7=D9=84=D8=B5=D9=81 =D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A.=
</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=B9=D9=85=D9=84=D9=8A=D8=A9 (</span><spa=
n dir=3D"LTR" style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&=
quot;,&quot;sans-serif&quot;">Case Studies</span><span dir=3D"RTL"></span><=
span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;font-f=
amily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"><span dir=3D"R=
TL"></span><span dir=3D"RTL"></span>): =D9=85=D9=86=D8=A7=D9=82=D8=B4=D8=A9=
 =D8=A3=D9=85=D8=AB=D9=84=D8=A9 =D9=85=D8=AD=D9=84=D9=8A=D8=A9 =D9=88=D8=B9=
=D8=A7=D9=84=D9=85=D9=8A=D8=A9 =D9=86=D8=A7=D8=AC=D8=AD=D8=A9 =D9=81=D9=8A =
=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1=D8=A7=
=D8=AA.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D9=88=D8=B1=D8=B4 =D8=A5=D8=A8=D8=AF=D8=A7=D8=B9=D9=8A=D8=A9: =D8=AD=D9=
=84=D9=88=D9=84 =D9=85=D8=A8=D8=AA=D9=83=D8=B1=D8=A9 =D9=84=D9=84=D8=AA=D8=
=B9=D8=A7=D9=85=D9=84 =D9=85=D8=B9 =D8=AA=D8=AD=D8=AF=D9=8A=D8=A7=D8=AA =D8=
=A7=D9=84=D8=AC=D9=85=D9=88=D8=AF =D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=81=D9=
=8A=D8=B2.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"line-heigh=
t:normal;margin:0in 0.5in 8pt 0in;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size=
:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-variant-=
numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=A8=D9=86=D8=A7=D8=A1 =D8=AE=D8=B7=D8=A9 =D8=B4=D8=AE=D8=B5=D9=8A=D8=A9=
: =D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=AE=D8=B7=D8=A9 =D8=AA=D8=B7=D9=88=D9=
=8A=D8=B1 =D9=81=D8=B1=D8=AF=D9=8A=D8=A9 =D9=84=D8=AA=D8=AD=D9=82=D9=8A=D9=
=82 =D8=A7=D9=84=D8=B7=D9=85=D9=88=D8=AD=D8=A7=D8=AA
=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D9=8A=D8=A9.</span><span dir=3D"LTR" s=
tyle=3D"font-size:14pt;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-s=
erif&quot;;color:rgb(255,192,0)"></span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"line-height:normal;margin:0in 0=
in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,=
&quot;sans-serif&quot;"><span dir=3D"LTR" style=3D"font-size:14pt;font-fami=
ly:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)"=
>=E2=9C=A6</span><span dir=3D"LTR" style=3D"font-size:14pt;font-family:AMos=
href-Thulth;color:rgb(255,192,0)"> </span><span dir=3D"LTR" style=3D"font-s=
ize:14pt;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;col=
or:rgb(255,192,0)">=E2=9C=A6</span><span lang=3D"AR-EG" style=3D"font-size:=
24pt;font-family:&quot;Tholoth Rounded&quot;;color:rgb(56,86,35)">=D9=85=D8=
=AE=D8=B1=D8=AC=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=B9=D9=84=D9=85 =D8=A7=D9=
=84=D9=85=D8=AA=D9=88=D9=82=D8=B9=D8=A9</span><span lang=3D"AR-SA" style=3D=
"font-size:20pt;font-family:AMoshref-Thulth;color:rgb(83,129,53);background=
-image:initial;background-position:initial;background-size:initial;backgrou=
nd-repeat:initial;background-origin:initial;background-clip:initial"></span=
></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"line-heig=
ht:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fon=
t-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D9=81=D9=87=D9=85 =D8=B9=D9=85=D9=8A=D9=82 =D9=84=
=D9=85=D9=81=D9=87=D9=88=D9=85 =D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=B1 =D8=A7=
=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D9=88=D8=AF=D9=88=D8=B1=D9=87 =D9=81=
=D9=8A =D8=A7=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9
=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D8=B1=D8=B3=D9=85 =D9=88=D8=AA=D8=B5=D9=85=D9=8A=
=D9=85 =D9=85=D8=B3=D8=A7=D8=B1=D8=A7=D8=AA =D9=88=D8=B8=D9=8A=D9=81=D9=8A=
=D8=A9 =D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D8=AA=D8=AA=D9=86=D8=A7=D8=B3=D8=A8 =
=D9=85=D8=B9
=D8=B7=D9=85=D9=88=D8=AD=D8=A7=D8=AA=D9=87=D9=85 =D9=88=D8=A3=D9=87=D8=AF=
=D8=A7=D9=81 =D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA=D9=87=D9=85.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D8=A7=D9=85=D8=AA=D9=84=D8=A7=D9=83 =D8=A3=D8=AF=
=D9=88=D8=A7=D8=AA =D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=84=D8=A7=D8=AA=D8=AE=
=D8=A7=D8=B0 =D9=82=D8=B1=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=B1=
=D9=82=D9=8A=D8=A9
=D9=88=D8=A7=D9=84=D8=A5=D8=AD=D9=84=D8=A7=D9=84 =D8=A7=D9=84=D9=88=D8=B8=
=D9=8A=D9=81=D9=8A =D8=A8=D9=81=D8=B9=D8=A7=D9=84=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D8=AA=D8=B9=D8=B2=D9=8A=D8=B2 =D9=82=D8=AF=D8=B1=
=D8=A7=D8=AA=D9=87=D9=85 =D8=B9=D9=84=D9=89 =D9=85=D9=88=D8=A7=D8=AC=D9=87=
=D8=A9 =D8=AA=D8=AD=D8=AF=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D9=86=D9=85=D9=88 =
=D9=88=D8=A7=D9=84=D8=AC=D9=85=D9=88=D8=AF
=D8=A7=D9=84=D9=88=D8=B8=D9=8A=D9=81=D9=8A =D8=A8=D8=B7=D8=B1=D9=82 =D9=85=
=D8=A8=D8=AA=D9=83=D8=B1=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"line-hei=
ght:normal;margin:0in 0.5in 0.0001pt 0in;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;fo=
nt-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D8=A7=D9=84=D8=AE=D8=B1=D9=88=D8=AC =D8=A8=D8=AE=
=D8=B7=D8=A9 =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D9=82=D9=8A=D8=A7=D8=AF=D9=8A=
=D8=A9 =D9=88=D8=A7=D8=B6=D8=AD=D8=A9 =D9=88=D9=85=D8=AA=D9=83=D8=A7=D9=85=
=D9=84=D8=A9 =D9=82=D8=A7=D8=A8=D9=84=D8=A9
=D9=84=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=D9=82.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"line-heigh=
t:normal;margin:0in 0.5in 8pt 0in;direction:rtl;unicode-bidi:embed;font-siz=
e:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size=
:14pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-variant-=
numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font-size=
:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D8=A7=D9=84=D9=85=D8=B3=D8=A7=D9=87=D9=85=D8=A9 =
=D9=81=D9=8A =D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=B5=D9=81 =D8=AB=D8=A7=D9=86=
=D9=8D =D9=85=D9=86 =D8=A7=D9=84=D9=82=D8=A7=D8=AF=D8=A9 =D9=8A=D8=B6=D9=85=
=D9=86
=D8=A7=D8=B3=D8=AA=D9=85=D8=B1=D8=A7=D8=B1=D9=8A=D8=A9 =D9=88=D9=86=D8=AC=
=D8=A7=D8=AD =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0in 8pt;line-height:=
107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&q=
uot;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span><sp=
an dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&quot;S=
egoe UI Symbol&quot;,&quot;sans-serif&quot;;color:rgb(255,192,0)"><span dir=
=3D"LTR"></span><span dir=3D"LTR"></span>=E2=9C=A6</span><span dir=3D"LTR" =
style=3D"font-size:14pt;line-height:107%;font-family:AMoshref-Thulth;color:=
rgb(255,192,0)"> </span><span dir=3D"LTR" style=3D"font-size:14pt;line-heig=
ht:107%;font-family:&quot;Segoe UI Symbol&quot;,&quot;sans-serif&quot;;colo=
r:rgb(255,192,0)">=E2=9C=A6</span><span lang=3D"AR-EG" style=3D"font-size:2=
4pt;line-height:107%;font-family:&quot;Tholoth Rounded&quot;;color:rgb(56,8=
6,35)">=D9=85=D9=84=D8=A7=D8=AD=D8=B8=D8=A7=D8=AA
=D8=B9=D8=A7=D9=85=D8=A9:</span><span lang=3D"AR-SA" style=3D"font-size:20p=
t;line-height:107%;font-family:AMoshref-Thulth;color:rgb(83,129,53);backgro=
und-image:initial;background-position:initial;background-size:initial;backg=
round-repeat:initial;background-origin:initial;background-clip:initial"></s=
pan></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 35.4pt 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fon=
t-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"font=
-size:16pt;line-height:107%;font-family:Wingdings;color:black">=C2=A7<span =
style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-st=
retch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New R=
oman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D8=B4=D8=B1=D8=A7=D8=A6=D8=AD =D8=
=AA=D9=82=D8=AF=D9=8A=D9=85=D9=8A=D8=A9 (</span><span dir=3D"LTR" style=3D"=
font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,=
&quot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;backgro=
und-position:initial;background-size:initial;background-repeat:initial;back=
ground-origin:initial;background-clip:initial">PowerPoint</span><span dir=
=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-=
position:initial;background-size:initial;background-repeat:initial;backgrou=
nd-origin:initial;background-clip:initial"><span dir=3D"RTL"></span><span d=
ir=3D"RTL"></span>) =D9=84=D9=83=D9=84 =D8=AC=D9=84=D8=B3=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 35.4pt 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:16pt;line-height:107%;font-family:Wingdings;color:black">=C2=A7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-s=
tretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New =
Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D9=86=D9=85=D8=A7=D8=B0=D8=AC: =
=D8=B3=D9=8A=D8=A7=D8=B3=D8=A9 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D9=88=
=D8=A7=D9=84=D8=A8=D9=8A=D8=A6=D8=A9=D8=8C =D8=AC=D8=AF=D9=88=D9=84 =D8=AA=
=D8=AD=D9=84=D9=8A=D9=84
=D8=A7=D9=84=D9=81=D8=AC=D9=88=D8=A7=D8=AA=D8=8C =D8=B3=D8=AC=D9=84=D8=A7=
=D8=AA =D8=A7=D9=84=D8=AA=D8=AF=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=AF=D8=A7=
=D8=AE=D9=84=D9=8A=D8=8C =D9=82=D9=88=D8=A7=D8=A6=D9=85 =D9=85=D8=B1=D8=A7=
=D8=AC=D8=B9=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 35.4pt 0.0001pt 0in;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fon=
t-size:16pt;line-height:107%;font-family:Wingdings;color:black">=C2=A7<span=
 style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-s=
tretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New =
Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;;color:rgb(64,64,64);background-image:initial;background-po=
sition:initial;background-size:initial;background-repeat:initial;background=
-origin:initial;background-clip:initial">=D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=
=AF=D8=B1=D8=A7=D8=B3=D9=8A=D8=A9 =D9=88=D8=A7=D9=82=D8=B9=D9=8A=D8=A9 =D9=
=88=D8=AA=D9=85=D8=A7=D8=B1=D9=8A=D9=86 =D9=85=D9=8A=D8=AF=D8=A7=D9=86=D9=
=8A=D8=A9 =D9=82=D8=B5=D9=8A=D8=B1=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 35.4pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:16pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-=
variant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;f=
ont-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D8=AC=D9=85=D9=8A=D8=B9 =D8=A7=D9=84=D8=B4=D9=87=
=D8=A7=D8=AF=D8=A7=D8=AA =D8=AA=D8=B4=D9=85=D9=84 =D8=B4=D9=87=D8=A7=D8=AF=
=D8=A9 =D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=A9=D8=8C =D8=AD=D9=82=D9=8A=D8=A8=
=D8=A9 =D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9=D8=8C
=D9=88=D9=88=D8=B1=D8=B4 =D8=B9=D9=85=D9=84 =D8=AA=D9=81=D8=A7=D8=B9=D9=84=
=D9=8A=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 35.4pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:16pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-=
variant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;f=
ont-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D9=8A=D9=85=D9=83=D9=86 =D8=AA=D9=86=D9=81=D9=8A=
=D8=B0 =D8=A7=D9=84=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=AD=D8=B6=D9=88=D8=B1=
=D9=8A=D9=8B=D8=A7 =D8=A3=D9=88 =D8=A3=D9=88=D9=86=D9=84=D8=A7=D9=8A=D9=86 =
=D8=B9=D8=A8=D8=B1 </span><span dir=3D"LTR" style=3D"font-size:14pt;font-fa=
mily:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64,64,=
64);background-image:initial;background-position:initial;background-size:in=
itial;background-repeat:initial;background-origin:initial;background-clip:i=
nitial">Zoom</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span =
lang=3D"AR-SA" style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black=
&quot;,&quot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;=
background-position:initial;background-size:initial;background-repeat:initi=
al;background-origin:initial;background-clip:initial"><span dir=3D"RTL"></s=
pan><span dir=3D"RTL"></span>.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 35.4pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:16pt;font-family:Wingdings;color:black">=C2=A7<span style=3D"font-=
variant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;f=
ont-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;=
color:rgb(64,64,64);background-image:initial;background-position:initial;ba=
ckground-size:initial;background-repeat:initial;background-origin:initial;b=
ackground-clip:initial">=D8=A5=D9=85=D9=83=D8=A7=D9=86=D9=8A=D8=A9 =D8=AA=
=D8=AE=D8=B5=D9=8A=D8=B5 =D8=A3=D9=8A =D8=B4=D9=87=D8=A7=D8=AF=D8=A9 =D9=84=
=D8=AA=D9=83=D9=88=D9=86 =D8=AF=D8=A7=D8=AE=D9=84 =D8=A7=D9=84=D8=B4=D8=B1=
=D9=83=D8=A9 (</span><span dir=3D"LTR" style=3D"font-size:14pt;font-family:=
&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(64,64,64);b=
ackground-image:initial;background-position:initial;background-size:initial=
;background-repeat:initial;background-origin:initial;background-clip:initia=
l">In-House</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&=
quot;,&quot;sans-serif&quot;;color:rgb(64,64,64);background-image:initial;b=
ackground-position:initial;background-size:initial;background-repeat:initia=
l;background-origin:initial;background-clip:initial"><span dir=3D"RTL"></sp=
an><span dir=3D"RTL"></span>).</span><span dir=3D"LTR" style=3D"font-size:1=
4pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color=
:rgb(64,64,64);background-image:initial;background-position:initial;backgro=
und-size:initial;background-repeat:initial;background-origin:initial;backgr=
ound-clip:initial"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" dir=3D"RTL" style=3D"margin:0in=
 35.4pt 8pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;font-si=
ze:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" style=
=3D"font-size:14pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-se=
rif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" dir=3D"RTL" style=3D"text-align:justify;line-height:=
normal;margin:0in 0in 8pt;direction:rtl;unicode-bidi:embed;font-size:11pt;f=
ont-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"RTL"></span><span d=
ir=3D"RTL"></span><span lang=3D"AR-EG" style=3D"font-size:14pt;font-family:=
&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:black"><span di=
r=3D"RTL"></span><span dir=3D"RTL"></span>&quot;=D9=81=D9=8A =D8=A7=D9=84=
=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=
=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=
=D8=A9=D8=8C =D9=86=D9=84=D8=AA=D8=B2=D9=85 =D8=A8=D8=AA=D9=85=D9=83=D9=8A=
=D9=86 =D8=A7=D9=84=D8=A3=D9=81=D8=B1=D8=A7=D8=AF
=D9=88=D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D9=85=D9=86 =D8=AE=
=D9=84=D8=A7=D9=84 =D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=AA=D8=AF=D8=B1=D9=8A=
=D8=A8=D9=8A=D8=A9 =D9=88=D8=AF=D9=88=D8=B1=D8=A7=D8=AA =D9=88=D9=88=D8=B1=
=D8=B4 =D8=B9=D9=85=D9=84=C2=A0
=D9=85=D8=AA=D9=83=D8=A7=D9=85=D9=84=D8=A9 =D9=88=D8=AE=D8=A8=D8=B1=D8=A7=
=D8=AA =D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=D9=8A=D8=A9=D8=8C =D9=84=D9=86=
=D8=B5=D9=86=D8=B9 =D9=85=D8=B9=D9=8B=D8=A7 =D9=82=D8=AF=D8=B1=D8=A7=D8=AA =
=D9=85=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D8=AA=D8=AD=D9=82=D9=82 =D8=A7=
=D9=84=D8=AA=D9=85=D9=8A=D8=B2
=D9=88=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=AF=D8=A9.&quot;=D9=88=D8=A8=D9=87=
=D8=B0=D9=87 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=A9 =D9=8A=D8=B3=
=D8=B9=D8=AF=D9=86=D8=A7 =D8=AF=D8=B9=D9=88=D8=AA=D9=83=D9=85 =D9=84=D9=84=
=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=88=D8=AA=D8=B9=D9=85=D9=8A=D9=85 =
=D8=AE=D8=B7=D8=A7=D8=A8=D9=86=D8=A7 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=
=D9=87=D8=AA=D9=85=D9=8A=D9=86
=D8=A8=D9=85=D9=80=D9=80=D9=88=D8=B6=D9=80=D9=88=D8=B9 =D8=A7=D9=84=D8=B4=
=D9=87=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=A7=D8=AD=D8=AA=D8=B1=D8=A7=D9=81=
=D9=8A=D8=A9 =D9=88=D8=A5=D9=81=D8=A7=D8=AF=D8=AA=D9=86=D8=A7 =D8=A8=D9=85=
=D9=86 =D8=AA=D9=82=D8=AA=D8=B1=D8=AD=D9=88=D9=86 =D8=AA=D9=88=D8=AC=D9=8A=
=D9=87 =D8=A7=D9=84=D8=AF=D8=B9=D9=88=D8=A9 =D9=84=D9=87=D9=85</span><span =
lang=3D"AR-EG" style=3D"font-size:12pt;font-family:&quot;AlSharkTitle Black=
&quot;,&quot;sans-serif&quot;;color:black"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font=
-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-=
size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;=
">=D9=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D8=A3=D9=88 =D9=84=D8=B7=D9=
=84=D8=A8 =D8=A7=D9=84=D8=B9=D8=B1=D8=B6 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=
=8A=D8=A8=D9=8A =D8=A7=D9=84=D9=83=D8=A7=D9=85=D9=84=D8=8C =D9=8A=D8=B1=D8=
=AC=D9=89
=D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=85=D8=B9=D9=86=D8=A7:</span>=
<span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;AlSharkTitle Bl=
ack&quot;,&quot;sans-serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font=
-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:&q=
uot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(196,89,17)"><=
span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0 </span><span lang=
=3D"AR-SA" style=3D"font-size:20pt;font-family:&quot;AlSharkTitle Black&quo=
t;,&quot;sans-serif&quot;;color:rgb(196,89,17)">=D8=A3 / =D8=B3=D8=A7=D8=B1=
=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=A7=D8=AF
=E2=80=93=D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=
=A8</span><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:&quot;Al=
SharkTitle Black&quot;,&quot;sans-serif&quot;;color:rgb(196,89,17)"></span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" dir=3D"RTL" style=3D"margin:0i=
n 25.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;f=
ont-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"fo=
nt-size:16pt;font-family:Symbol;color:white">=C2=A8<span style=3D"font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font-=
size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=
=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=C2=A0</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" dir=3D"RTL" style=3D"margin:0=
in 25.1pt 0.0001pt 0in;line-height:normal;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span style=3D"f=
ont-size:16pt;font-family:Symbol;color:white">=C2=A8<span style=3D"font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font=
-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>[=D8=B1=D9=82=D9=85
=D8=A7=D9=84=D9=87=D8=A7=D8=AA=D9=81 / =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=
=A8]</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"L=
TR" style=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=A0=C2=A0 </span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span st=
yle=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans=
-serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0</spa=
n><span lang=3D"AR-SA" style=3D"font-size:14pt;font-family:&quot;Times New =
Roman&quot;,&quot;serif&quot;">00201069994399
-00201062992510 - 00201096841626</span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
></span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 25.1pt 8pt 0in;text-align:center;line-height:normal;direc=
tion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-s=
erif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16pt;font-family:&quot;=
AlQalam Alvi Nastaleeq&quot;;color:rgb(196,89,17)">=C2=A0</span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKkQ8g17dowUwqXzJ-1REbtkKxuc0p8hRK%3D%2B5vzjJOoKUA%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CADj1ZKkQ8g17dowUwqXzJ-1REbtkKxuc0p8hRK%3D%2B5vzjJOoKUA%40=
mail.gmail.com</a>.<br />

--000000000000a28c850640c7a1f8--
