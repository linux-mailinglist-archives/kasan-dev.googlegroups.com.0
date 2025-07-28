Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBXVMT3CAMGQEFQJL76Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C29EB13E2E
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:25:20 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-553bb73e055sf2696681e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:25:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716319; cv=pass;
        d=google.com; s=arc-20240605;
        b=VZpZz26fiB6zz1+OcxoJ6eD/MQvxu/3qScEezA2yLn4chE3j7FuStkZ0TKCJ8MKxez
         Fn7hM0DpY57p6so/0DNLIIKq+o3t3p1LA/wv0Il2zdZKoYjISL/TXwWDI6u2CgTsbsrD
         g/P0SFok7A1FGWEWMc2ihEMrHgCbcsr3RUBam4RpQYgckqgWaok+GVwp5uuI0gCUCgG1
         rY64uiQdwvWubA9W+rJqZPGf8hBw9YDBeNZ+dffNAOdDIcQSRhkEhMUQimJfBHXiORkg
         xqRO1xERihAyMrMM2m1/UQixNN+vbWhu24WmlecPhIdfT8ez5PrPzLuzO6I/cs0Jwt6A
         rycQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=CXaZFTYtC6Jym64W9edrJUyuBCm8u/E0Vh9bAHf/0KQ=;
        fh=MU99y0MixWblZYP27geG4r0OiO2xEKHhqmWFwhz9nZY=;
        b=jJbPvoiCo+p0Di30ISf0zRxwGiP6i/9cuQWlUSfe/wO07cieFC95gpQxwSDu7nI+7G
         cYvRGQ15YfJhZmB4E64VIMuQmoxxbOiR57q8j2L5ac9v78njN25XbJw1Q0fgUtSMEx9o
         zsSfdszO5quQFmVNUT7lh7DqrD59pP6lSCLfMOQ59OKAx+EWpU04NU/q8v9c17D4JcGi
         Zpuyc3RDBHnroNOEfHAv2F0sN3IDEFvQfA3PSO8RwFTv7mN8kK4kzJKWNmTEHYVlxjH7
         StXf31i7UhHuD3a7xISELiktpjX3Q24BuiUTRq836O2cPLRFAP5s0nYK++MT1aHXwGy2
         Hn/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="ULU/Vlof";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716319; x=1754321119; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CXaZFTYtC6Jym64W9edrJUyuBCm8u/E0Vh9bAHf/0KQ=;
        b=MsQFh9DTaTE1yASWj0pmVk95o7GXVyH3ozuMI5s9GD+uAcgHELdCCd8Mb/p39M44SY
         fGnEmgiFOQ7SSR6nEuuN6AumCb6RhOnTBKuxRayhBiCZilhH1mfRABa6sv1qoRoGwPAs
         FyfNDm9/EAyPiKwXqCAhZYbXEXPhB9Uq1awrP49r6eg4+n//Wpb1vmYO0S4qW8i2xc2I
         BuyQbkxbUTb/bJ1M5FtYnDbuX6z4JAq9LeitVsX/mss1ElwZOODHTe7cCSgoAHV64ErG
         yi2Mk/RTdjy+TAdpnSTD++qNMambTvlK/uG1KQ1DE2cUsiSdc9gwxEt2nlAOgxcG/uYf
         UMFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716319; x=1754321119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=CXaZFTYtC6Jym64W9edrJUyuBCm8u/E0Vh9bAHf/0KQ=;
        b=sRPGemS/UELK2OmhtiweTMAbnbCk8Bfd7bB28TxxN12B1PWM3jqv6D3b/1WhZRNBWb
         fsM9rkkxm9U9y2pQbfRWkAxYsH6t6ZpRci1cLuoPx+E/hk1vsbfrabtsMbaDyAfdotCT
         4YgobE2O74/bmi6kzjnHmQshbbQHDSY2DoaHLXNVdSs+qHVBK0pSQxxiGz71pdkHfRQj
         NAqSxFCDS5uub9Q7Tnwi3mXxXaXuwzVgBC7o++Yh+xhH++e3UDl8qCnkZtExMsS0gFzo
         ApvjA6FkfUU9FJBiMi33Vz8/lkEBCMs4I6U6z3N+mjkcQqYtPe/9uz7vXZma6D4UJ9E/
         DRhA==
X-Forwarded-Encrypted: i=2; AJvYcCWe3BS+5ysY4jGoDGgEQLyKSVZrqPJ9s4FZg2jANP2egxFeRf3NNF6Oql5pRKZVSqUhtQxrfg==@lfdr.de
X-Gm-Message-State: AOJu0YzbmuVYTbsGKEXIz0gGgLj14MRGI/d/rhWgJsP6/IaDlKaaF1n/
	Loo6H5MV7kTk/wBlUWfRgsbeJeYhqf7HpBjY2VdzjYRzQWK1lp4gfSiQ
X-Google-Smtp-Source: AGHT+IHLRfjQDDR0+Yb39r2jkkaXOLBeDZFaOXLDWZpqcc7WK7SpwHEp96zvEt56NPuArh4vjjGn7w==
X-Received: by 2002:a05:6512:23a2:b0:553:3916:4e1c with SMTP id 2adb3069b0e04-55b5f41e8c5mr2447691e87.2.1753716318800;
        Mon, 28 Jul 2025 08:25:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf6X2nazE9QVHQQmzlULkeOcG+eH2sqzersftdbpT8blA==
Received: by 2002:a05:6512:1349:b0:549:91ca:8970 with SMTP id
 2adb3069b0e04-55b51f308fcls1504315e87.1.-pod-prod-05-eu; Mon, 28 Jul 2025
 08:25:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYr/aMquaXRMXuaQaIMo383A8j3+0SXvGLcHnc8QNZH231gD18Mc6RP+WHjQZu3q0cfGqZ5rRkJ2c=@googlegroups.com
X-Received: by 2002:a05:6512:2248:b0:552:2257:93dd with SMTP id 2adb3069b0e04-55b5f485f3cmr2823206e87.25.1753716315705;
        Mon, 28 Jul 2025 08:25:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716315; cv=none;
        d=google.com; s=arc-20240605;
        b=B68ef+R2iIxk7fobsmP+UdeeQHTQ6tF0jldmsvg/h/UljeHzuDNzQXwg6acuhavGld
         Dp2FmObTUg67Xw75qRiKolSNB8n2hgFkbFec/99lQx1tnT1i8MPDh+PffVKtQTD6qmT8
         X++3lH2heXuRePV4zGM8/ebi0ZdogeYzBhXVC3qpUgZPcOgW/LTQb6pb4MGWrR/1937W
         WMjaYRro8YRZSOpWD5xifh565n1wqCRMvCIgI3rSUJksdC3XbCc+LppVNcBKnsUZcnAR
         K0kyl0CKRJlSP6SZMomyLWsn2gnHZNPBGmQ8Aw4an6HulSEx3+sYNRi6X0WBBrlgWvBE
         P/Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=FmtiBSyLbULt1UA1JWlLsO3uP2X4WloH9sMbWEu3NzA=;
        fh=ExkgyisYyxNvZ6RVlhL9dWHUV6qVna5rEkvNdac9xW4=;
        b=jYRHKP3jK3IeyIEPWWAl5NvfX515GLoQYqHYoDb6sQVl5DZ4KJnb22OYFVEtYZstSC
         h7resxgfl1vdpZCHMqpMfvgArJ4S/VdobPB5yYH3S5iyitA4v23o72GxQIz+qW/XmjPU
         hPg534pyiSrMsZX35XAycbnH/X+Rxy/H3jalP3oEkXE0NAksHglwnZCIlywJufRLW0rJ
         jPFWrbjuGhCYzqyi8vLPw1nD0zsh8iMTp1VqUFnpRw8NxOeklvGJKVB9S3eW7Ut58Xpg
         aR/doun0Gxs03h/sdVMzd6eSDw9jeKXZ9bNkVcA7ESUaPVsOHMLL8KFJBsCo8U+23PO4
         K5eA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="ULU/Vlof";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b63170588si198801e87.3.2025.07.28.08.25.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:25:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-456007cfcd7so145575e9.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:25:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUYhzHMtDe4aLkpxkS8nKDvvRksg7LsLw3Wpbhhkp9mI3vLBnu9oCk44IJjh6AOpYok3LajaLv7XbA=@googlegroups.com
X-Gm-Gg: ASbGncvFGGbi5XO608pdOA01ohZoBK76y3aCzQ5PXzLD+RnP+Zk1HsabbHDzXfx6BFV
	NRem5Su+0d67ye7zsQhl16ziVp0Ad4Hy3IXiXWe1tHeqgRR+DOBcT0vxGpJlgi9G6a4HtKWQRkm
	iYpcoCwFnmauMmqte1L91EOXoRWVkd6vFPBCNABuxyk9rYvOTdqhUXNNwiN423UwdjLGtPALC6e
	oLYaU6HLJa02LGAIQ9vP7VfAuFVVLmI+fHhFOmQ3/lFc8Hjwh4ulje4PH6IkI1oCnyBQoYjY3cT
	Mw0Y3jar+XUMFzNihvr7hQ5up28dOXTb2M6V1R688JgkbqgyRL0vwjYGpG1jxw4tT6e30cqNd51
	oAsk88khzYQ==
X-Received: by 2002:a05:600d:11:b0:455:fd3e:4e12 with SMTP id 5b1f17b1804b1-4587c203b63mr3367205e9.4.1753716314556;
        Mon, 28 Jul 2025 08:25:14 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:ec3e:2435:f96c:43d])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-458705c4fdasm166070335e9.28.2025.07.28.08.25.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Jul 2025 08:25:14 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Jul 2025 17:25:07 +0200
Subject: [PATCH] kasan: add test for SLAB_TYPESAFE_BY_RCU quarantine
 skipping
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250728-kasan-tsbrcu-noquarantine-test-v1-1-fa24d9ab7f41@google.com>
X-B4-Tracking: v=1; b=H4sIAFKWh2gC/33NSwrCMBSF4a2EOzaQJqax2Yp0kMSrBuHW5lGE0
 r0brODM4X8G51shY4qYwbIVEi4xx4ladAcG4e7ohjxeWoMUUgsjT/zhsiNesk+hcprm6pKjEgl
 5wVy4DkYq1RsUuod28kx4ja8PcB73TjjX5pR9/DGWfRH1B0EpjPfDIFAe7dLBuG1vXjjTucQAA
 AA=
X-Change-ID: 20250728-kasan-tsbrcu-noquarantine-test-5c723367e056
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1753716310; l=2679;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=Kptubjw33lIYXvj73r+Ak5WjJnBxiCJjjkNyZ62pUp4=;
 b=63awq6A643TMQphYSCgAxn8VRGNZqIMqOct7AU3rsaLfhYPVM3wE6iOhb9oBMDvAWudz6meau
 daIFkzIVpRXBf+8r00bPgCO+mafWmDLqF24NHkkqsPzSiRM+jBHA/Z8
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="ULU/Vlof";       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Verify that KASAN does not quarantine objects in SLAB_TYPESAFE_BY_RCU slabs
if CONFIG_SLUB_RCU_DEBUG is off.

Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Jann Horn <jannh@google.com>
---
Feel free to either take this as a separate commit or squash it into the
preceding "[PATCH] kasan: skip quarantine if object is still accessible
under RCU".

I tested this by running KASAN kunit tests for x86-64 with KASAN
and tracing manually enabled; there are two failing tests but those
seem unrelated (kasan_memchr is unexpectedly not detecting some
accesses, and kasan_strings is also failing).
---
 mm/kasan/kasan_test_c.c | 36 ++++++++++++++++++++++++++++++++++++
 1 file changed, 36 insertions(+)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 5f922dd38ffa..15d3d82041bf 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1073,6 +1073,41 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+/*
+ * Check that SLAB_TYPESAFE_BY_RCU objects are immediately reused when
+ * CONFIG_SLUB_RCU_DEBUG is off, and stay at the same address.
+ */
+static void kmem_cache_rcu_reuse(struct kunit *test)
+{
+	char *p, *p2;
+	struct kmem_cache *cache;
+
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_SLUB_RCU_DEBUG);
+
+	cache = kmem_cache_create("test_cache", 16, 0, SLAB_TYPESAFE_BY_RCU,
+				  NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	p = kmem_cache_alloc(cache, GFP_KERNEL);
+	if (!p) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+
+	kmem_cache_free(cache, p);
+	p2 = kmem_cache_alloc(cache, GFP_KERNEL);
+	if (!p2) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+	KUNIT_ASSERT_PTR_EQ(test, p, p2);
+
+	kmem_cache_free(cache, p2);
+	kmem_cache_destroy(cache);
+}
+
 static void kmem_cache_double_destroy(struct kunit *test)
 {
 	struct kmem_cache *cache;
@@ -2098,6 +2133,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmem_cache_double_free),
 	KUNIT_CASE(kmem_cache_invalid_free),
 	KUNIT_CASE(kmem_cache_rcu_uaf),
+	KUNIT_CASE(kmem_cache_rcu_reuse),
 	KUNIT_CASE(kmem_cache_double_destroy),
 	KUNIT_CASE(kmem_cache_accounted),
 	KUNIT_CASE(kmem_cache_bulk),

---
base-commit: 0df7d6c9705b283d5b71ee0ae86ead05bd3a55a9
change-id: 20250728-kasan-tsbrcu-noquarantine-test-5c723367e056
prerequisite-change-id: 20250723-kasan-tsbrcu-noquarantine-e207bb990e24:v1
prerequisite-patch-id: 4fab9d3a121bfcaacc32a40f606b7c04e0c6fdd0

-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728-kasan-tsbrcu-noquarantine-test-v1-1-fa24d9ab7f41%40google.com.
