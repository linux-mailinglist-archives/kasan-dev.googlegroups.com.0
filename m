Return-Path: <kasan-dev+bncBDP53XW3ZQCBB5EWSXFQMGQEFKNCEEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9299BD1501B
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 20:28:53 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-4325cc15176sf3459447f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 11:28:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768246133; cv=pass;
        d=google.com; s=arc-20240605;
        b=J4IK1jEC43MClKitt91OgiIf9GlflF+2+TNzuSa0HE6Z9DC/OQUsBXa7F8auVo++dC
         BPqUTMP2CQHMIH8YsaDlXMMKELRbsWOqcLlr/STWzVqIpmLXJFWo08bM0LtqDZwE6T54
         PXTe5Gt7To4V0hD6cG6I2nvaAFtgbHKp/OW+kMqzBxJL1vgtG8UbjmWqz/tSkyklwtxr
         kaWg5riUX22NYasHNOYqikYlT2Ff5OoLH99zvQ7EzVDV4avI/+4m/JHZTO9DFBmGK/k4
         I4iyty218/xtdh3VaCrrnEn7mAgNLKvxHmactqG3FLA+R+FNKtYV8uEOXdvt7fhY3C0B
         Ahqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=BUvoUAF6badPPysECSFvgezykAZ2qDWypqvgRtQn4mo=;
        fh=ihXW9yv8oUIjV1mZxSFWkcw9aSuxeTCxJYNnKijkRc8=;
        b=IPjpaQJxBjrbkc2hb/qRjwUiofoR7GnV6tfL3Whre5UgcCy091hyl9V66AlhTV7WpF
         x/rLnWub98xEd6crdJRHeUGJ0pWdDu/bWWeRx6k4+pI9r5mgwrN8CpTbgu5gpr1eE7S8
         Y8IhvqKGE8nDhBqVaXAletDih3HosBySAF6Gcm4b0fS52cBt37EMYbcx7y0NgZ/03nJT
         ARmK3HpIU4tBghL1LxIvJbPp+EGEg+Gx/o6R2PNoGQ6/ZxTd6bXr8yQD4Vs/Usd0O1ji
         K1bTUVHOjYLIfAl8KNH5yoM0EBnr5JFLh3H6gAIb1cVcjrQxW/CLHan8MU9BW3qWe4XW
         dbRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SfHJMLpe;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768246133; x=1768850933; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BUvoUAF6badPPysECSFvgezykAZ2qDWypqvgRtQn4mo=;
        b=Mw3bAii36sB9FXRMEfVfFrL5AcLLh+xaMpQUgokiQZIGmRTHO0qjGESUPT58F4NGL1
         FRGEIaOQ46zr7jQrQHd0XpUM2wc0wSyVHpEZI0L1jeOdL32kgA59eXViY1GZUNg5MrMk
         3R27a67YH7N5fM1h+qzq6JODgFozX+NNL8TD3heOEUDl4d89KQNAh2/9ZV02ExKHgetF
         b2a6pDK//jYCLI2wFi9cZf5n2vG8U0O6LPptPL4lx1QWkWJTl3eFUZI7wgLZX4e66+Wt
         p5KsdqHZqWMgZkfHAleCK4whR16f30h58U5sbCd/aM+O0X2TUqulXBx/4CJybf4SmK+9
         fCpw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768246133; x=1768850933; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=BUvoUAF6badPPysECSFvgezykAZ2qDWypqvgRtQn4mo=;
        b=RCcOGGh4WMU1zCkwU0PSP7biiMGJ52gPcRzK6ZA9kq+KUZMOZmnjPmZKEk6hrgxjVr
         9nimPIwP4HO0v72qpgyMMSDYpo6NtgaG1bR7PsKoOLMeklrUIN+HJx9fGaMqxXjX2bJb
         xFeQE+EK7yJgJu7F76eJMyPbVgORX1d2eEkSTLTL8GACF78N3t+I/X5L+ps2wvNufx1V
         aN7uCEFcR5ae8GNkzfSXjNG2q8YT5gSmHzIh7wskrYdHXdIUQUzONBVeF5RI7dL1AkK+
         F4V3COX9vzfjY+drHtUMtalRbYKKBfcbFPA+A6GVT9pmctgn7w1A8qZ71flsP538Li0/
         t1hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768246133; x=1768850933;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BUvoUAF6badPPysECSFvgezykAZ2qDWypqvgRtQn4mo=;
        b=vh4QYUUcK8W4MniV2U4s4Pi9kknrcMrZkFvNZYIpIEUaCNKE7sICVqmvbwqtLlqSdY
         6Wc/Qhh0mHcmFU0G5eZUoP0qzDSWs1JyOcRNrSuExgZ5K1d4jidioqzD9xLfg0fqoVWa
         8ub1eCOww4f8UlXVCDFVKVcsynRq7nMrc9fFWdDEM+XJ6jWoHmAbf/MqjWmFcOCRvPQP
         PoawfdmTlnpt3L0M1xmSE8XGErbfHk5VzGKpDHM0C30BvpJ8i0RTzmCvIkdxxfxhhvi+
         qRfsSTB+a3RT7UqqgDpJE2kbJrTMVp1iaruB223vj/yFWLPvv8yNPplgA8cIWyIVrHza
         OalA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXXCYhRvlcegLMrHfcakUbJoFMAgm1EW8VsLDYQ+ltWcBDZn0F7EawUoIhP3fuZHBmuHwvW1g==@lfdr.de
X-Gm-Message-State: AOJu0YzGwb08XxWcdkeHRFyuxUKyVLKahs6/klNHmfSwxyMweP4cWNYF
	ARy4lZSqqnYKAcesOZQM4q6H2BE6Deg/0ln08LoTBd6voW+aeuBjOE/Z
X-Google-Smtp-Source: AGHT+IE+uVSNnQ5q/Kmm0iMQ+vmzvxT1PNKnw0/dDPC3g6cHfii4FxeJssBamcyUhFFDnIH2nCgHWw==
X-Received: by 2002:a05:6000:2003:b0:42f:bbc6:edaf with SMTP id ffacd0b85a97d-432c379dc56mr24193387f8f.37.1768246132862;
        Mon, 12 Jan 2026 11:28:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fm4WkhTup4kv7hThxk4SXnfUjQZ1GoMx/Voyia/FJfvg=="
Received: by 2002:a05:6000:2dc8:b0:432:dbd4:cace with SMTP id
 ffacd0b85a97d-432dbd4cdc3ls2267628f8f.1.-pod-prod-08-eu; Mon, 12 Jan 2026
 11:28:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVbOAwxa3a8iFr0fX7NHEB7ZhJ2CRbwXi0AqBdqM/FWbXXUprHZ86aqSCMmxsCkbPkNjA28DGdC4c=@googlegroups.com
X-Received: by 2002:a05:6000:2882:b0:42b:55a1:214c with SMTP id ffacd0b85a97d-432c37c1462mr19495621f8f.55.1768246130167;
        Mon, 12 Jan 2026 11:28:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768246130; cv=none;
        d=google.com; s=arc-20240605;
        b=idhbDsh4fVqi8JOD9VkBZKwpcDzG9XhbdW4k+3IqTKOyrDzaWRkETcbM5lE8kCR2oQ
         Sa1ieFylaI65J3/fJIo1Q3fGBzdfk3qRokr3+p9NY/WNH1bvFqnVK9kIfYOO314oqAtn
         TzuwTQ3EJbUsm10VqX8YFaxY8eYIq7qz4bsLHqVDpqCGpcYVGqByscdJ8eAi3TTcVJSz
         LEY9nxOamHjUQiw5K8UNwcKmX9cpek3Bxpb9mKDHA7Jx6jpCj4dcxYUti1dAQB0d5Ygi
         EDgthZi3Tr48mcyANEKFeNG1oXfMwzEgp2tNZvlVmwXAICwqx4CAcCiEfSHq7nbtPdof
         obPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sQS0SzXkMyBsX0r/DMnRoitwZR/NjZ11xjjJpvDZxFQ=;
        fh=lhoUYz4lM4aNcTjZWhWWdgLY69Qa0E34NVG1IhuKLDM=;
        b=L+ZaifI7GbAQ34hq7bHciC5vddkkOtbHKUp8xRZkz/LZKsQtx4NJOZabBrIFgcxwPx
         dz71VvwNzWharOKo+scKeTCXP6N6pWjPUHqF7ES+Ys/oU1x6JmiJ3BZx7hicgdI9JkBS
         jYJsYJj/BQLAbmx948KQD5FQJT2uRo9V56r7KzDf+E4tsp0lvpuHE1SJe6fB6TTl7SJC
         AxZCoZEAlrlXDD08qQECh839wp7ZLjHFXbNi1GiRDNOPCaNoAHvk+g4Rs+Yuq37GsToW
         9CHkiZnC00P8IhV+B+U81djI4s92LPXT2WKndu6lwarq5O+ws5nfD4XCMcBET78cns1u
         Xphg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SfHJMLpe;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432be509c5dsi305476f8f.7.2026.01.12.11.28.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 11:28:50 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-64b83949fdaso11207027a12.2
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 11:28:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUhtYip1Rt7YWxO0731u5Sor3E4s3v0+cfeBLluWKR7uuwdCso6L2HtBBFwtFZ/zqaoxH2GfQ7/rrE=@googlegroups.com
X-Gm-Gg: AY/fxX5584GI9ItPb6sb11012QPucNUGalpmpvYEPR382hv0a6siqrYAj9tA2WoVV/o
	jCDKtbYba4NKVQ+JwlpsMakiDM2fVaN0NI7bkHePWDR+TPLh0QuOtKAI/AAQp1a4vfQTnRaI4be
	aKzachydK9jcfwK5GlSIAAgMp7dXGOBnG7AuXTNLOEKXhpxTbI8QRrJIXlF6Gl3kjW/x19LahMW
	siGihCq0fwuTStA6VaO2MNicCRB3Tsf7RXSLXVGz7nuWSVolY3rI4+hYnCJWUVA2pOA3RpZwhBa
	DWqtZZsjMkKeBPDlln4W+9xDh/wqZh1Ofet+s2WUwP5Cm5yAKare1MT2Zfty5i5ZYdXYqZpgfAH
	NhkzMKlV8ZGxiBEwwdf2vpKGV/FrfBm/LFHEwq0J9+vw+azG+s0jchRSPskDbOnq4qKKkQBFi5W
	6t36KUKGnzkby39vEFZi0w7i0Epv/sqHQBHacgxcuLzRZMobnOTw==
X-Received: by 2002:a05:6402:280f:b0:64b:3e03:63b with SMTP id 4fb4d7f45d1cf-65097e8c00fmr14927123a12.31.1768246129525;
        Mon, 12 Jan 2026 11:28:49 -0800 (PST)
Received: from ethan-tp (xdsl-31-164-106-179.adslplus.ch. [31.164.106.179])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-6507bf667fcsm18108959a12.29.2026.01.12.11.28.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 11:28:49 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	ebiggers@kernel.org,
	elver@google.com,
	gregkh@linuxfoundation.org,
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
	mcgrof@kernel.org,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	skhan@linuxfoundation.org,
	tarasmadan@google.com,
	wentaoz5@illinois.edu
Subject: [PATCH v4 6/6] MAINTAINERS: add maintainer information for KFuzzTest
Date: Mon, 12 Jan 2026 20:28:27 +0100
Message-ID: <20260112192827.25989-7-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SfHJMLpe;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add myself as maintainer and Alexander Potapenko as reviewer for
KFuzzTest.

Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
Acked-by: Alexander Potapenko <glider@google.com>

---
PR v4:
- Remove reference to the kfuzztest-bridge tool that has been removed
PR v3:
- Update MAINTAINERS to reflect the correct location of kfuzztest-bridge
  under tools/testing as pointed out by SeongJae Park.
---
---
 MAINTAINERS | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 6dcfbd11efef..0119816d038d 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13641,6 +13641,13 @@ F:	include/linux/kfifo.h
 F:	lib/kfifo.c
 F:	samples/kfifo/
 
+KFUZZTEST
+M:  Ethan Graham <ethan.w.s.graham@gmail.com>
+R:  Alexander Potapenko <glider@google.com>
+F:  include/linux/kfuzztest.h
+F:  lib/kfuzztest/
+F:  Documentation/dev-tools/kfuzztest.rst
+
 KGDB / KDB /debug_core
 M:	Jason Wessel <jason.wessel@windriver.com>
 M:	Daniel Thompson <danielt@kernel.org>
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112192827.25989-7-ethan.w.s.graham%40gmail.com.
