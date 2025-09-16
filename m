Return-Path: <kasan-dev+bncBDP53XW3ZQCBB36OUTDAMGQEB2YRQSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 86ADFB59186
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:01:36 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5607bdd7739sf2686865e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:01:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758013296; cv=pass;
        d=google.com; s=arc-20240605;
        b=aKPba+fGZ5N1NHg5/MKEnhdQowPPZQRbzqb2iv46yHk8bnAET+0YdCDEbmsqbRi5Fq
         in6y3WzEcjVuLDDzUIrf/kl8ex38BM4lPMmzlZjrrvIlBtf0GNQ/teHLiLxdat8N0ov+
         ItN10xL6sfHJfQUJ6xFJe4cEewd6lyutGWbCsXcIqU+9NIAm6ye5g1UBMqUAtkDNIvJP
         UaWdX878Fszw2+GeN8fzbyJ2p2DMRzbp5vfh9qrzL7v9fGApnjjr4m6FosFDKFAo5ZpL
         vfDKfGW5eXSJEcIx8idBb2g5954avBU6vCWjxPr4puKhB4OqCXYIABnkyXDD7jvp3J92
         YQPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=d796aabB21RLDgP5uN5bHhwWOlfD67YBWo9Sl98/J5w=;
        fh=6fmaPQb3EOkpSMdFu3AGg37f1Zf5cFOlqIwuCpUy1wA=;
        b=hT0I5EoUZqjzJ5vWFkWKFGtt0B45urBirRwTS48XxyoorF1DDR9bfVwyN85Y6UkheO
         Ja+F+azYEC2PfGhcdUwP10KCR8aEqevoAVRGwf7DTq+wLWMhBhSb4UQ16xfKEekb+JA/
         Q4Zg8TmZv/9lJJH5pDylwG4Wz5QjvZopPSK3dsic6xJpBxCbkRC0sbaejURgs4nQ59zT
         o1LloAXelQ3yA5ueC3QIZZLg6GXhuXIR05QGnaameGRVTF5peAg9PPkjd9YykLk98Myb
         lK/CKorWCfWtjppe1Q79hPOT71YSIumldYMWd/+EYHzYIHWOsJb/d6yGRxxUkIhM4R03
         G30g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cRgBrzY6;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758013296; x=1758618096; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=d796aabB21RLDgP5uN5bHhwWOlfD67YBWo9Sl98/J5w=;
        b=hgtJU2dssoXUCNMRnkaM0ksUd8TtH7YKfXTRpk5u1oqRi+PoH7BY0dxZCbgxrKmEmm
         37BgMQv7E3RC8j1WM/h3d2TatnykKO383DkAJDYqOmnCMXJ1XQsBTtR2bPs8MgNcf4Wr
         cjysV+4WvKWNYXCfCwoo4BemlS44mRAXZJ98rQf6k5CqSgsnpQWvPHOok3Wl4quuAPi/
         6NL6EC5atUk5L6qKkSnmSVv5/4Y1wv29617F60zLYUz3pu2BAAwhhd+me3kpwUURiiiq
         iiUyf8PMTaM7fXBxiVWob2To3ubKYsGGIBAsrZ3HS7Xo4Hl+CbBrEMWypRChmPbeW82H
         Pysw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758013296; x=1758618096; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=d796aabB21RLDgP5uN5bHhwWOlfD67YBWo9Sl98/J5w=;
        b=YoGmJcWVM2o9T5I1/FpqPKHPerirYKCDrEnjFnvEK8H40oau4kAk85phkPzaQ0WROR
         SfnH375HV2wYBuyS6Qtc9YgxW3nT5uZP1hds3QrK+aSXgoDl/7xu5UGX4mG2Wyr34y6G
         TuI+UWvFIWDloQvC3RVgfcsZxxgB+EKlNagx4MYYg0YDFSnbF/J0uTOTNLg6KvKXDj+F
         LvRbAzthjY7khfAP/A/R55o1o2kTMJRlLWj8BUHYoYF8BA9f3m6U61FhoKneYaC96WDF
         zIHnCU9Ul9uL0xGD1jn8MFmsvZiItJ4fmIfBqXD/5135v/TMy2QAA8Wc0L6s75rbxbTp
         Ssbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758013296; x=1758618096;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d796aabB21RLDgP5uN5bHhwWOlfD67YBWo9Sl98/J5w=;
        b=fTPM+ADxoL67KljbdYAph/f2unWbVKsW7gno6unkJZvrCa/KiUyK6241hjd9/9UONw
         lmP0taacKgezvcCiJ1BGp2CuEvSzFy6hvZsIL4FOubpxlaoJO8zf9nRs97+r0XGNRVRi
         ARQz7x3FphqT5W9trCwWkiXM+lXhKK/lvXhn6SACV/eHLQ6Dfc72RxpUgQeTVGaSHmvA
         //4fkaf7i1U7dh++hbHb5h8oSxd1P+t8TBujxdsC0uypWXhbiGBUN2f2VGRazhVQOuvh
         O33je97rSe9VUe7TMrBBHWPGs3tGNlJlbEQlrjY2smWEWOxViTSzhRTrdPp4gHrcPiUE
         HSJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdb2w//AcrLrUVFFV6rHsNPVLcqZmp/XVpRiKrWFdlY7MUb3OAAEb2G1fWLyjWdvJAIyCWOg==@lfdr.de
X-Gm-Message-State: AOJu0YyH+kIrCAP+x6MrgRfqdh2pasU4+vpJwsWylByGqh3J8rPgTWUD
	M8pSj6XV5Fa9gQdzHU9BTGIH6GKnG5ogMyg/UvnkJCa6kg1D360ZB64t
X-Google-Smtp-Source: AGHT+IFR6Kxk+OfGFxWJfs7M3OzpFZD5C9y3HZvHEcQUKKQLlsm6hMoN78KoZ263xbDreslcc4swnQ==
X-Received: by 2002:a05:6512:361a:b0:55f:5cad:28d5 with SMTP id 2adb3069b0e04-5704f1cecc8mr3772941e87.48.1758013295725;
        Tue, 16 Sep 2025 02:01:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5ptQ8SwwUUJ+L72kvaXCw3KoJKqIjewO6h7zns9aykPQ==
Received: by 2002:a2e:b5b2:0:b0:336:684f:84be with SMTP id 38308e7fff4ca-34eb1af07a3ls6207331fa.1.-pod-prod-06-eu;
 Tue, 16 Sep 2025 02:01:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVplRa+7PyJ/A0PaJfKxzZIUB31UgVwCAgpDmnVyR0O2h3FAmIDGmw0oIx0V/o4FvxJ/QLz1pD8GNk=@googlegroups.com
X-Received: by 2002:a05:651c:54c:b0:336:b47b:d145 with SMTP id 38308e7fff4ca-35139e55629mr42328201fa.2.1758013291605;
        Tue, 16 Sep 2025 02:01:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758013291; cv=none;
        d=google.com; s=arc-20240605;
        b=UACtL0VXDVhFRxP/10j4TNkDKTnV/GbHLBv4bbN5N/G3LUk2cHU37ePq3NtGoOltXT
         6ZKa6+8ho9dcivcASZFXZ5XDIN5m8msRXfKZAEYZ1hUpTszhtPTscactwuK+8YS1MEwx
         mTD2r8fRyR2wscTLFG1d1Xjt2UCoLd5AMhBv7tUzg/IPQbmYa0M1ER+8HppFxHHEk7bh
         luYsx2L59yADTmWUWuUbMYvklmSoVMxTav9jxMqRhWim3pzxdW3XGxcUniO0k/MY4E1V
         65KcB3FGEby8gHMqerb/Mklx0w08ldO1gY5WFZymnpVQ5uulrUgR0hzW4SDVWPcxYXlk
         IxPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Dn/O6EVQArdDsuUvojtCYkGjh1nRaP/fdtC5qzIrIQ0=;
        fh=eaQuS1CF7ov3KpjvKwkWGqhJAO7ImJEjV82AcyIM8Gs=;
        b=C7grvnw81UuwYEYBp808d7Rl1XLKSHZi8HDTEBSggWfDoXMqOOOyfRATQxZQFmTVTS
         wuNmubl5pHNN3oCLtQc2cNocqX8pWTuS8bKXgt7tVhczJ13GQDE8J4NMo92CyQggsxEs
         sTifrvslpPJeJBVszbuyfMMiVEnW6iIW6/SBdhDaYDTUrBCfla3+Z8hNilyv9R333ZeY
         TL9tH072f+i94iFmKTakDUOSfhrrSiO9ttZsQBSIreDosRkMkUU+EgWDxOqhxxYRAl9u
         IHHn9j4fCq1DclIH6GlPm67uVJ1gK8lcHpUOt0jYYNWwJjz/6HMHYHjPJfKSu5a1tk9P
         xbTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cRgBrzY6;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3512a98ca2bsi1938891fa.5.2025.09.16.02.01.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:01:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-45de56a042dso34126365e9.3
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:01:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXo45ogMHNumsENgaJFVQy3H+jPmfeKRYCtIEaoGBdgh2Wpks8mrBQtkNANRDCuDAsbEfuhT2p+W9c=@googlegroups.com
X-Gm-Gg: ASbGnculkJGRmRFjKA38zSiihBKxi254QGJLCAa1KRZUjnwMb45zwG+NG8tbPG3gKCb
	vT+zrfCjHOTDgTib3qkVt9fDhahmnFTMJklLAyXgAONSKw9jMLMXQ5YDVF6xleQLWvpyGhtfYjX
	16QXChR0zyO6blj84/iNa1deAm5GUhJ/kM45dWls0P2yGaB22xT32HwSkIDoNDJJJXqpPI3xRmm
	4OMUwYXaOsWavfObAv6UuD1r/M4PVLzCWsvFe+xxYR9sqdJS1EwMw1lbNBFGoxPJ0w8c048EuU2
	55neede41Txunn5qUGQIprDm2Z2iz0eHrgZiGysE6YgWapMyCPxxPempn1qXSqbR/Fz/K0laIeU
	h9t8w8fm8BhAL1ve124E0rg7x1+g5/Q6loGEPd67rdY5hTEpqEaFd079JU56T1mDVAE/Z4DhHyp
	lyZdHUtX4RIKOv
X-Received: by 2002:a05:600c:a0b:b0:45b:74fc:d6ec with SMTP id 5b1f17b1804b1-45f211ca9dbmr161791435e9.8.1758013290736;
        Tue, 16 Sep 2025 02:01:30 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (42.16.79.34.bc.googleusercontent.com. [34.79.16.42])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45e037186e5sm212975035e9.5.2025.09.16.02.01.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 02:01:29 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	tarasmadan@google.com
Subject: [PATCH v1 10/10] MAINTAINERS: add maintainer information for KFuzzTest
Date: Tue, 16 Sep 2025 09:01:09 +0000
Message-ID: <20250916090109.91132-11-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
In-Reply-To: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cRgBrzY6;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
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

From: Ethan Graham <ethangraham@google.com>

Add myself as maintainer and Alexander Potapenko as reviewer for
KFuzzTest.
---
 MAINTAINERS | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 6dcfbd11efef..14972e3e9d6a 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13641,6 +13641,14 @@ F:	include/linux/kfifo.h
 F:	lib/kfifo.c
 F:	samples/kfifo/
 
+KFUZZTEST
+M:  Ethan Graham <ethan.w.s.graham@gmail.com>
+R:  Alexander Potapenko <glider@google.com>
+F:  include/linux/kfuzztest.h
+F:  lib/kfuzztest/
+F:  Documentation/dev-tools/kfuzztest.rst
+F:  tools/kfuzztest-bridge/
+
 KGDB / KDB /debug_core
 M:	Jason Wessel <jason.wessel@windriver.com>
 M:	Daniel Thompson <danielt@kernel.org>
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916090109.91132-11-ethan.w.s.graham%40gmail.com.
