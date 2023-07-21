Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBK665KSQMGQESTW3QPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E42CD75CDE4
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jul 2023 18:15:40 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-565d6b6c1c7sf4026283eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jul 2023 09:15:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689956139; cv=pass;
        d=google.com; s=arc-20160816;
        b=UAWQKzsMajFsXY4FrEuzjdTidditW12Tq5feYuilU4Io+q32Bd7BGkjbL5ZQk4y3N/
         jBz+Aw8GHiRst87jiuFLZbGkEpn4SdSUKhaVTswXJq7LYKGmvrRoubwga2tTL556f5ng
         HVloM3e1LJh2Y3kRhMQb1mo1ah/YzgARq36wIgkGL+ODr40IsMnJMaP1U11Aa2VkueDq
         2zfHghyVDgLI87Fv0gIf5JId4bt78OqhOPP9sf81F0WUkVouOn1S3Tv2+fuV7gt35W+W
         DjEQrN8xtYeyYm1SO3AjmR3gZtYs29baYyhP0uZyYnCKNJeR7jyHi5hBErSF03jMGdAm
         pOfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=vosdUY7qX55FP6yOzb4cM4wxwNXQAexsmI2JMMeR2wE=;
        fh=ZPGZKrQ+qxkFVLpEVH0HywtKANkkNHp0EtQFg2ItNoc=;
        b=K36/Rh21DsGywCJ8g5/x8hDbdzUGMdlQfuS0yaWo273vxiD0zLDMm2t5Nh50yqXvSy
         AWFy+gFfnpKOM7JTZeDhh313zOu8do/PONo+IA0tMeItTL00Ntnm9GJKG/bY9UK/cA1/
         p3jYYsMCFLfPutRw1V/HHqD5NmkhQDkhf0JICWrYuQN6dHEWfvEfFlQY7Lc2wFJcsnlk
         D4tomugRh3y6YuHECWBscB3kVdi1LZ/DOnTuu2mJfHJ1hROOI68x81XDFldHYCh27aFr
         lsBksLXS+dwE/TgvIbT3/hnsZE92UKYbYjCzI2H2LLOuoufGAUeB49DSW/cmHi46Uj9l
         ESRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=GwOX9Zx8;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689956139; x=1690560939;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vosdUY7qX55FP6yOzb4cM4wxwNXQAexsmI2JMMeR2wE=;
        b=gqxHwPvXPPvcWdDgTYzmRI6Bf2TmhAFROG+QAqgjdt0uAevpE2SLN3Zgzf8TFSTThk
         9XqoWTdz/8+GUwcr/MdiUW3z3tb7wIxem4ijv2mdLsTCeWFWRmHzjJYnKF2GmB9KdhH2
         7t2RBCrAacDVGFs7Yuc9hubvjHB55u7u3ot/p2vurvdx7EMH1GEmvnI7X6i3TSeuPtpa
         LK2en4p1W6NgnRH9D3DfU1iu2LFMsLQaHs9tGAd3qwejQFSgDG1DNMZM9gKTtXkhFSNu
         GZKucpMq+ZhKUddB9bxwNnZIVioIz65DQSwpOKYc+CJbNReZ/XUYFH6+tTUogNoX/Kub
         +i7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689956139; x=1690560939;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vosdUY7qX55FP6yOzb4cM4wxwNXQAexsmI2JMMeR2wE=;
        b=NgAMbIotnnZFdVsDWv7GM4f3UaB2u7iYlluIh/3An8hbtNcx05Dw2ISoxg5tu58MTF
         TR48y7naML8WANvOYu8FTWAs3NzZ3eGg0PrVPAuJD+WCOt4hZz05eWswCmeGOLI9ZEFt
         gGA0BIpaO62c2GEYdxtTm4sS3ezJ0s4331PHKemx1VL4uj7afglRBLB3WMzgfxR1wf5C
         I1BfTN576MSjYSN5Xabz2tNXhT0aN3usQn85VXB3Yfvau+NnDo2caBhV3MzU0+hNOz0R
         ahbK7TI1jPgddupVVToeoJVbS4MkUiHMk+HKTWjRpdyYdZSaINaWJW/b1Cz4v8gTgtqA
         MtGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbwgjEzoHs/szX6dGw1nUVMH7B5gQksFYAa8Gu8aCJWSFcnyKd5
	sOWeQVGInWPNLWICXU70fBk=
X-Google-Smtp-Source: APBJJlFehU2x2SPZWT0/kHQ0K8zPuXUGLPfFOuVZUFX8FKrQl8vBPZmpXGwe9HecL3aVjhvRUnpQAA==
X-Received: by 2002:a05:6870:f69e:b0:1b0:43b6:e13b with SMTP id el30-20020a056870f69e00b001b043b6e13bmr2589423oab.54.1689956139458;
        Fri, 21 Jul 2023 09:15:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:49d1:0:b0:564:377f:9511 with SMTP id z200-20020a4a49d1000000b00564377f9511ls2154227ooa.1.-pod-prod-04-us;
 Fri, 21 Jul 2023 09:15:39 -0700 (PDT)
X-Received: by 2002:a4a:6f03:0:b0:566:f7c7:93bb with SMTP id h3-20020a4a6f03000000b00566f7c793bbmr1922734ooc.4.1689956138938;
        Fri, 21 Jul 2023 09:15:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689956138; cv=none;
        d=google.com; s=arc-20160816;
        b=QTNjS9xEShGbGU9Favzh6tCBHLNWdcQMhnTLRLsIXxuzetinC/dk6FwOkMLxNBQhF5
         3PA65R8umIXmjEtWV//bCCmeuIHSbiju/WVVaALQw4OOBM5Trx+88qfrmfbevY8Kzi5A
         VftasRzifl8GVgVbkg0y40QxwZ+kjfJx/hMs1hb3xQdkkSAleWLa7Jv8weIvymPCXul1
         Iq6lUcUu2tjwqTYc8CBOc44l2iTdj8t5hOG9KBZ1Y20FL0TR8ayle9/YnQJQeaGgeClD
         tG9+/I5f4LLkG70if6ipVpQaw8a/LpYlfE1Kg864swDw9sloRvlAxVOnqOSc0siXB1hb
         4UIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4qWjtJMAM1r6qoAwdo21XlULlJBYYcbKba/hk/vjxx8=;
        fh=ZPGZKrQ+qxkFVLpEVH0HywtKANkkNHp0EtQFg2ItNoc=;
        b=z9Ks1ibuIJjAoaVrpCzGNDP2EZKYQKv85kxirK3reMsoY0xImhAt6510Ayz2XXHZ3A
         BU7LXjl4VxxLbcB7mvYz7s1S9ir8TyOgF38XmcaMJITOXMoFX8Ew7FL1OBupk24xOnjv
         qzM68nsKRNp3q+TyVhr/x49B4qVgf7bYSQllBe3kwxZvqc3C6kbH5HbzHuOmT3T+udHP
         oxfbVRnjUTeoKf+LEtuAIrIswtWcvDIGH1T6yqZ0s7Wlv/njL5SJUht+RvVqs/zgy3dl
         SiXGKkpvrCAFsVTBg/i68RES1xhWDyWkvSrIhXHTErZxsYevUcQe6t3MDok0PxQy/t/S
         GkMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=GwOX9Zx8;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id i21-20020a056820013500b00566fd59ede2si173066ood.2.2023.07.21.09.15.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Jul 2023 09:15:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A71AF61D2B;
	Fri, 21 Jul 2023 16:15:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 90304C433C8;
	Fri, 21 Jul 2023 16:15:37 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: stable@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	patches@lists.linux.dev,
	Andrey Konovalov <andreyknvl@google.com>,
	Will Deacon <will@kernel.org>,
	Marco Elver <elver@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Feng Tang <feng.tang@intel.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	kasan-dev@googlegroups.com,
	Pekka Enberg <penberg@kernel.org>,
	Peter Collingbourne <pcc@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH 6.4 138/292] kasan, slub: fix HW_TAGS zeroing with slub_debug
Date: Fri, 21 Jul 2023 18:04:07 +0200
Message-ID: <20230721160534.776366260@linuxfoundation.org>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20230721160528.800311148@linuxfoundation.org>
References: <20230721160528.800311148@linuxfoundation.org>
User-Agent: quilt/0.67
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=GwOX9Zx8;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

From: Andrey Konovalov <andreyknvl@google.com>

commit fdb54d96600aafe45951f549866cd6fc1af59954 upstream.

Commit 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated
kmalloc space than requested") added precise kmalloc redzone poisoning to
the slub_debug functionality.

However, this commit didn't account for HW_TAGS KASAN fully initializing
the object via its built-in memory initialization feature.  Even though
HW_TAGS KASAN memory initialization contains special memory initialization
handling for when slub_debug is enabled, it does not account for in-object
slub_debug redzones.  As a result, HW_TAGS KASAN can overwrite these
redzones and cause false-positive slub_debug reports.

To fix the issue, avoid HW_TAGS KASAN memory initialization when
slub_debug is enabled altogether.  Implement this by moving the
__slub_debug_enabled check to slab_post_alloc_hook.  Common slab code
seems like a more appropriate place for a slub_debug check anyway.

Link: https://lkml.kernel.org/r/678ac92ab790dba9198f9ca14f405651b97c8502.1688561016.git.andreyknvl@google.com
Fixes: 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated kmalloc space than requested")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reported-by: Will Deacon <will@kernel.org>
Acked-by: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Feng Tang <feng.tang@intel.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: kasan-dev@googlegroups.com
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Peter Collingbourne <pcc@google.com>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
---
 mm/kasan/kasan.h |   12 ------------
 mm/slab.h        |   16 ++++++++++++++--
 2 files changed, 14 insertions(+), 14 deletions(-)

--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -466,18 +466,6 @@ static inline void kasan_unpoison(const
 
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
-	/*
-	 * Explicitly initialize the memory with the precise object size to
-	 * avoid overwriting the slab redzone. This disables initialization in
-	 * the arch code and may thus lead to performance penalty. This penalty
-	 * does not affect production builds, as slab redzones are not enabled
-	 * there.
-	 */
-	if (__slub_debug_enabled() &&
-	    init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
-		init = false;
-		memzero_explicit((void *)addr, size);
-	}
 	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	hw_set_mem_tag_range((void *)addr, size, tag, init);
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -684,6 +684,7 @@ static inline void slab_post_alloc_hook(
 					unsigned int orig_size)
 {
 	unsigned int zero_size = s->object_size;
+	bool kasan_init = init;
 	size_t i;
 
 	flags &= gfp_allowed_mask;
@@ -701,6 +702,17 @@ static inline void slab_post_alloc_hook(
 		zero_size = orig_size;
 
 	/*
+	 * When slub_debug is enabled, avoid memory initialization integrated
+	 * into KASAN and instead zero out the memory via the memset below with
+	 * the proper size. Otherwise, KASAN might overwrite SLUB redzones and
+	 * cause false-positive reports. This does not lead to a performance
+	 * penalty on production builds, as slub_debug is not intended to be
+	 * enabled there.
+	 */
+	if (__slub_debug_enabled())
+		kasan_init = false;
+
+	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_alloc and initialization memset must be
 	 * kept together to avoid discrepancies in behavior.
@@ -708,8 +720,8 @@ static inline void slab_post_alloc_hook(
 	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
 	 */
 	for (i = 0; i < size; i++) {
-		p[i] = kasan_slab_alloc(s, p[i], flags, init);
-		if (p[i] && init && !kasan_has_integrated_init())
+		p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
+		if (p[i] && init && (!kasan_init || !kasan_has_integrated_init()))
 			memset(p[i], 0, zero_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230721160534.776366260%40linuxfoundation.org.
