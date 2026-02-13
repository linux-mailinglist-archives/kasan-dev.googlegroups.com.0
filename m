Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSXJXPGAMGQEKL4UXVQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id aP0dMcz0jmnDGAEAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRBSXJXPGAMGQEKL4UXVQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Feb 2026 10:54:20 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 67808134B88
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Feb 2026 10:54:20 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-385b73b864esf3389241fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Feb 2026 01:54:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770976459; cv=pass;
        d=google.com; s=arc-20240605;
        b=N/ayyoglKBvIAvG+eaxHy4HxU6+cuIb8mZXbE7hHP5iI+dXnHKngijJ+5O/zis9C+Y
         jf7xS2KAsmvQeAXqBOejlxyi5XlAlzSXy70FoM8Cx2zedKZijJ5oCpb+DzsPDJauXepK
         cdMemMHF5yAoFKU7ZHV1SICPdRKQySWnRDavcHMTBuMvxdDNWi41uhIhFTL0z0F9TUm1
         b6WWA07MAGi/e14A5Nt9y2mfLxAFXdWtdpk3If1JN8ifeBanuLfji9e5wJ7yA9cX1GTm
         t0llOPEjeQvXLyHtNWaPUOPQSRXRWhNBDoS0QTdtCbPMnXybP+JEDRdweWW4Hqgx0GmW
         Nvfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=1PALfgLRdgEH1hVtEPGhzxuR7g4kjQ+PtatPL44ay0c=;
        fh=F6r+p3gxDD9MyJQEYjZmVbltUn9OTQA8P8Hfek1p+FM=;
        b=bT1PtfT0JUSkjeC7nmP/Yi/Kl+ow5VdCWiMt8EoQTm+t3dl1BoN0yG4rn57jv/EIZj
         g3wUgyCI6N38zndW4QoKnBqgprKrxFkCPZUFGq6TOq/C1MCb6bEO6AJrxc3NmaH/iTfQ
         SIl8dZ3SPvKktk30H8q81nauSOnjbcL5YnyOYDGciRb8PxdLQtmLMRmBwfZVHPzLF7eV
         NkQHSNWlfyHebTvR++QGcg7q1UEpmbJHzt33qgQ8xQhlLJrUAbFf4AD1vWwm+o1+Sc/w
         55mGXom5ZRLnEexfuIVD29qmE4XvWdChodRcanofIRE55Rq8/XM1Ixdn/Y1dTMIh95Ok
         JaZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vNjej+E+;
       spf=pass (google.com: domain of 3x_soaqykcuainkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3x_SOaQYKCUAinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770976459; x=1771581259; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1PALfgLRdgEH1hVtEPGhzxuR7g4kjQ+PtatPL44ay0c=;
        b=klSkfFCjcOZBFTns+Sc2UNZ+x5R2YyxbG7LmFO48QxziioGrbSeEYJI9r3KJ+rxZv4
         IgI+wi826fpNs9VQ0fOOryrjQYwy/MBkT1bpjtAtAk0NHtW03y0pMFtP/h+1nynWwwm2
         yZAjV4HLylataYITCruzYl75ngCQBBKou4NtvGtBvD/F/lkPtCNOFxrjaL3XHZN+DrE1
         UL8Zh5FA0/nhk/5nV4zRf/YjNEuX/YGT3yPsLcw/TVhJHHuwpufTa07GJF0szYY5joD4
         M3fxPRnI6eXSH9IlITdvPqJsC57mL1ta44DkLGcBvAYLy+b7P0tAAfSk6bIcgiDHHc4q
         RWDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770976459; x=1771581259;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1PALfgLRdgEH1hVtEPGhzxuR7g4kjQ+PtatPL44ay0c=;
        b=rLngnYvrKFowCG2x2LMgpGurkJWgbLEYzOPbhbIX+4D0v9KQw73xln92Ml7AVp2q87
         mFkEy1r1qslFD+Z6Cqq8wtjg7FuXghnTKJxm0rtT4EZ1PSUpfLcWnvzUgt/43IpIvchu
         RMd5m+oJ/Woyvc2S0HCqIv7sOn8s1IJ5ctRE047DXEZ3lt+1sKvDqIhvIz1di3ALvmHI
         GT8BJ4RJVE75z9y69FIeaMjELOT0ii1xDpa4vWA1oQtn8ZeqQRpisdvbX8iMmQk0kvIJ
         UeFQcNanvG9SX43TkGJwBanFpdRrV/cP0f0sYVfePFo6lfidlIOMGD6bzns32BqM8nGa
         yrDw==
X-Forwarded-Encrypted: i=2; AJvYcCUWPbYFNRqZdowDfNbsFqLxmxPe4yqybGrVB1zKuBTVJMXXozHqdlZEg5EA5dHmVfFPAA8LgQ==@lfdr.de
X-Gm-Message-State: AOJu0YyKVBhbob88ZSWT6djZNizPfb3qfeUFOcO9L2D9dj2WdWCZfrIz
	OZkhDUcjMVk/3ThMv/0XSAJRiiJfWUsoKv52tijRRkdU6sKi7QqgO8nR
X-Received: by 2002:a2e:bd07:0:b0:385:f547:184b with SMTP id 38308e7fff4ca-3881056399amr3538021fa.24.1770976459219;
        Fri, 13 Feb 2026 01:54:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Ek3WMkwqBh0AJnF1PcD5jdj/WtO6VKimDQwHk4gLOuwQ=="
Received: by 2002:a2e:380a:0:b0:383:1a5f:713e with SMTP id 38308e7fff4ca-387127db5e3ls2018321fa.0.-pod-prod-09-eu;
 Fri, 13 Feb 2026 01:54:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXRUcdAplN9LtuVvHoDg6mPkuRz2tl2VU4Dv6j6ZkUExoqj7juy4EEtqjOXXcf1Ob5plUJR9ciEBos=@googlegroups.com
X-Received: by 2002:a05:651c:e0a:b0:387:197d:2073 with SMTP id 38308e7fff4ca-3881057ae4fmr4384711fa.40.1770976456536;
        Fri, 13 Feb 2026 01:54:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770976456; cv=none;
        d=google.com; s=arc-20240605;
        b=kKKR7N2p/5J3QQerPMAZHwBLZJN+jvjMlt7yDhI2gFgjJ50lGgWQQPrJt9zsEkUK1W
         dDSL9NWkLDk6+f7szv6nC4X7QAbTbdHM7L+UeRpKFGEU8rq83eavIAeOA1yI968/TwC1
         HLfKV38xOlvBj9d3eCzJZIUqz9iAaJPaa2WIcgz3pUDwaPdO3CigwZceUzV0s1YMpSfh
         Px8uO+s3nomW+YmTnE8eM/788fqT2KsrYj1NGtKlqs4BbZQWk8ld1gFGg8myobvgb5/M
         M9L8DA4zJCDoXksNatGbbY3DKCCd/9X/FKHB7Ef/6v47+DZkE4j+3s2KXiN95T7KVpW3
         aUyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=LFs1D2cDtd6f/aAyQgYmfXZj2j/U+wImXIancDSX5wo=;
        fh=PtkD5XDhT3955OVxribWhCP7/D2gfGe9vlDJtWn0SIs=;
        b=DepGRjiJJ8HxACAZKj3lg+L2IKeDy4iJrx2CM3FjtAm+9cMcIlZveH3y7zZfQUku5k
         eJMXvsP7nOITfxpUVVdnKxB5PrasTxwl7f577qX7ktOG59qLYjmJXDeEY+4l8H+qbfgu
         aF0rwbQLNjqmd5oXD/YHONiBm8pXXlqfHwXJi36ENW2hSgV5eV1EW/JNPeeoYQDftlSk
         qCcgaadxm8z7IrnFzuSqQy1bJ5j1Bdh2w8SBLz8SAnFSGPdWQShfZe/XRgz142nuvg3O
         /NWg+UmBEV8KPF8cQmq4hLr9S3HZGIidV5s7fgY+2B2CmrxGceRZNtrAj0dWiiPBpF6F
         NpWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vNjej+E+;
       spf=pass (google.com: domain of 3x_soaqykcuainkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3x_SOaQYKCUAinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3870690c4b6si2030981fa.8.2026.02.13.01.54.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Feb 2026 01:54:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 3x_soaqykcuainkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-47ee432070aso5230565e9.1
        for <kasan-dev@googlegroups.com>; Fri, 13 Feb 2026 01:54:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUpSM/r42FjPlbGw5MTbZXcSIO+q8jGnge6d3g6sZjs1ZneLcjPX1iUukSYLgZswdnoIkTEa7osiUs=@googlegroups.com
X-Received: from wmoo19.prod.google.com ([2002:a05:600d:113:b0:483:6a60:3501])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4fc8:b0:47a:814c:ee95
 with SMTP id 5b1f17b1804b1-48373a234fdmr19866675e9.12.1770976455591; Fri, 13
 Feb 2026 01:54:15 -0800 (PST)
Date: Fri, 13 Feb 2026 10:54:10 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.53.0.273.g2a3d683680-goog
Message-ID: <20260213095410.1862978-1-glider@google.com>
Subject: [PATCH v1] mm/kfence: disable KFENCE upon KASAN HW tags enablement
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: akpm@linux-foundation.org, mark.rutland@arm.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, pimyn@google.com, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, 
	Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>, Greg KH <gregkh@linuxfoundation.org>, 
	Kees Cook <kees@kernel.org>, stable@vger.kernel.org, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vNjej+E+;       spf=pass
 (google.com: domain of 3x_soaqykcuainkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3x_SOaQYKCUAinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.79 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_CONTAINS_TO(1.00)[];
	MV_CASE(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[15];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRBSXJXPGAMGQEKL4UXVQ];
	FREEMAIL_CC(0.00)[linux-foundation.org,arm.com,kvack.org,vger.kernel.org,googlegroups.com,google.com,gmail.com,tugraz.at,linuxfoundation.org,kernel.org];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[glider@google.com]
X-Rspamd-Queue-Id: 67808134B88
X-Rspamd-Action: no action

KFENCE does not currently support KASAN hardware tags. As a result, the
two features are incompatible when enabled simultaneously.

Given that MTE provides deterministic protection and KFENCE is a
sampling-based debugging tool, prioritize the stronger hardware
protections. Disable KFENCE initialization and free the pre-allocated
pool if KASAN hardware tags are detected to ensure the system maintains
the security guarantees provided by MTE.

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>
Cc: Greg KH <gregkh@linuxfoundation.org>
Cc: Kees Cook <kees@kernel.org>
Cc: <stable@vger.kernel.org>
Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kfence/core.c | 15 +++++++++++++++
 1 file changed, 15 insertions(+)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 4f79ec7207525..71f87072baf9b 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -13,6 +13,7 @@
 #include <linux/hash.h>
 #include <linux/irq_work.h>
 #include <linux/jhash.h>
+#include <linux/kasan-enabled.h>
 #include <linux/kcsan-checks.h>
 #include <linux/kfence.h>
 #include <linux/kmemleak.h>
@@ -911,6 +912,20 @@ void __init kfence_alloc_pool_and_metadata(void)
 	if (!kfence_sample_interval)
 		return;
 
+	/*
+	 * If KASAN hardware tags are enabled, disable KFENCE, because it
+	 * does not support MTE yet.
+	 */
+	if (kasan_hw_tags_enabled()) {
+		pr_info("disabled as KASAN HW tags are enabled\n");
+		if (__kfence_pool) {
+			memblock_free(__kfence_pool, KFENCE_POOL_SIZE);
+			__kfence_pool = NULL;
+		}
+		kfence_sample_interval = 0;
+		return;
+	}
+
 	/*
 	 * If the pool has already been initialized by arch, there is no need to
 	 * re-allocate the memory pool.
-- 
2.53.0.273.g2a3d683680-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260213095410.1862978-1-glider%40google.com.
