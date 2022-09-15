Return-Path: <kasan-dev+bncBCT4XGV33UIBBM5HR2MQMGQEUUI2XVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 717085BA22A
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 23:05:56 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id v128-20020a1cac86000000b003b33fab37e8sf10118659wme.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 14:05:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663275956; cv=pass;
        d=google.com; s=arc-20160816;
        b=arVxehb+P5youdlHRa7J+53pE8SX0TwGdIh+JRaYyY2HaKcshKoSuEWuWobOMAYl7A
         MBlXOBU1kHFdK/r5KvSC7g3v++uhk69ydo3tV5vF4nvgifda6+Q/IUr91uKxf0OCb4oL
         aK8cR52SqIdlYA8j6CKJrc3gd8BjaHNHToW2LDl0zfS9OHMoKOUK9yt4IhFCWzcJDHu2
         aMqSsl6WF7upCavxGjlAby9+0ceDHkSVbmmtOTbrPFQDs+XlFZmNbl5CTEj+y+64dfv1
         VAQ/oo7ZDrP1oln5CvZ9TEc8+Jqh2QHnca266NV0gon+izZLL9lC1KqUkvAh/4EAnhrW
         5fqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=XhJRdXQSuR/qtGTgFuem5yWrmkk9veg1FYG+O/zv4os=;
        b=sr7+/p7eH/1m9GZ09MDYZnQUfSeeVD6KrXS1z8rufsoL+iDTOohyPINzsxBtQYH6oM
         iMkwzy6Wy5av321D2kF9NS1wf3CiFPd72q8Eo5dKgc9dUcZuIunO2ZM6qY3mjJ060JiY
         wgwK0TbxjWW1kFA1iGKabILaKYhupZI/O1BX9mZGaW82QxOq+cbXp+0UMW2CxKUw9Z4p
         IN+ayimkP02tXKVqrwG5z8zPAm+7yEFBR9qFh3CfSzUxELziBFX4k3nUzK/U0+ylxLF/
         2d7VwAoOsgglvdqzyr+vXS5ZMpRDQkB+fSzqDmn5vEZJrT6SJFurXtjhs1z3VoUIJXAx
         8k1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=jNTI5WaC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=XhJRdXQSuR/qtGTgFuem5yWrmkk9veg1FYG+O/zv4os=;
        b=XpZf15+MGJf7ewUK4Naj3u+x9N49udVPPrq1JSPx+rQZOfRcjeozTqm1n6UJfEpV7w
         t7ypFXDM959tbTjblVhf3hnkuZJCWoYHzKZlSiYZNr/wL7H8ETWPJFpAXhj8jrw4ntOb
         Qc02GnIL56S9Zx+FDFF1TS3ny36RiPp/RcN+NotM4h1X1dsfLveepXzIMh9+vxlp5q0Z
         WDz6Qi7vHQEK6GndXTOjlLZWFh62pPl6cPpFniDYqfcqIzisLm84Kku/mT6+EnFsMRkU
         +GLGqU197t/OA7obwI2mFoXutzb3TnWw+PxyjsIKRZO71saB84xvW+2zVMQTG/gl/gDn
         piSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=XhJRdXQSuR/qtGTgFuem5yWrmkk9veg1FYG+O/zv4os=;
        b=7Uo8Rbbc6fBEj/PnqCWeOav/fAwUJa0D9Eufg325wceHKVVliyHE4iexHwkD4fIW6o
         jMc08wlklCfYqFQjfN1/mMbymbp75gAXmuf6sfY2c1D8W7DLLP8i3JEVanoojtSyZDOe
         ErmxpWu4NocLu4ddlYVrh0jy37441a0XdM7T056tp7ZccrPgbcUkWg+n/fJgdayyoPst
         gFvKaPHwzdCvD1KAzr7Ydn8pf8cjOZO1WwiVZ50cR33vtwzZNgWYxrG0rx6V0JiG5Wqd
         oK62JSBZOlLbfbTiIsZWOo6q0PckLsjqwmLcNdagDsgU3bHs3/7/M9BrdFTJLsh7RsDY
         Jixg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3l48fo6/niox4UeSs2oNwpbxQQyI2PgDamahp3nX64hJX9sxdJ
	DoAEo9Ss3cD4C8zCTjdhpLk=
X-Google-Smtp-Source: AMsMyM4GnxFcKAcp0ycwMDacz9SaT+jXXBH/JWyAD+D8jeuLvHb77SwCqOVdyw1DDGDD4CJtITH/Lg==
X-Received: by 2002:a5d:6545:0:b0:228:dab8:af03 with SMTP id z5-20020a5d6545000000b00228dab8af03mr957441wrv.29.1663275956079;
        Thu, 15 Sep 2022 14:05:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6187:0:b0:228:c8fc:9de8 with SMTP id j7-20020a5d6187000000b00228c8fc9de8ls524266wru.1.-pod-prod-gmail;
 Thu, 15 Sep 2022 14:05:54 -0700 (PDT)
X-Received: by 2002:a5d:6985:0:b0:22a:d169:6fce with SMTP id g5-20020a5d6985000000b0022ad1696fcemr918346wru.717.1663275954804;
        Thu, 15 Sep 2022 14:05:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663275954; cv=none;
        d=google.com; s=arc-20160816;
        b=oDTqTvT/uJXOFfDV+alpu3gDhjNMMxN7vIfMGuK0EazKE/8kDg3RC1RbWS+t3/hro7
         ItP3VfsEI3eh3Xe7m5C8+3btFio5Dn8HQzhHPD7377FLBhUgl+B6TviIfnj66pE/vfSJ
         RgE0tRKNM0ylxmiQRc1qi+Bpg0tze0Zd4HGnMzyaVuB8cWcVeaRBh1HgpAJgVQr9f2rK
         fkmVHN0i+6q1lIfNola7jboe/5hCDkvPVODIwOa07yN16upjYr86fdl7A8MiLSg80g2S
         1Dn9vc1Yq8UdHQVGOrlAMmPUHoLgxDXWq+E2OVW+5eX/ivxiFAIFz3QhKLg7OuP9rb16
         GSBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=vlWj2NYLyRUOXAJrHk6h7mpFMyF26yljvB7x4WHUu08=;
        b=WCFh7cm0rt+W8FS0G0aPsWGroDPUdvW5AuYWIQAQt4cArjC/CC3pZMHFcN2RniL4Vr
         GTnALCtgVW8kHJfPcfT7JEskw2M78ZjSVj6oF4R81ewE/1prg/P4ZJtdFSFZKFOmKuBc
         /fLB0JQcZXs3v/B/QIVk5qdcsryNjHM2z0B9aJ3PojKrL8n8Hg98vlabZX4wc5ITPCPX
         Y9yVgLfG+4NTlLkp8+6aJaxQRVyDd5yyPgMUyG+u979dzlPQfUNn4+Emd1sa8lAvAHAh
         ujnbbgD27B6lMAvhHZnc2b9YUkxwvZdBmZ2RBJJAacvpvfLkBNs2WXKEI1ohlR+S/Te9
         c3tA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=jNTI5WaC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si106913wma.1.2022.09.15.14.05.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Sep 2022 14:05:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 48D86B82134;
	Thu, 15 Sep 2022 21:05:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DBB10C433C1;
	Thu, 15 Sep 2022 21:05:51 +0000 (UTC)
Date: Thu, 15 Sep 2022 14:05:51 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov
 <ast@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski
 <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov
 <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, Eric Dumazet
 <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich
 <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe
 <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook
 <keescook@chromium.org>, Marco Elver <elver@google.com>, Mark Rutland
 <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>,
 "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>,
 Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>,
 Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt
 <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik
 <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil
 Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v7 00/43] Add KernelMemorySanitizer infrastructure
Message-Id: <20220915140551.2558e64c6a3d3a57d7588f5d@linux-foundation.org>
In-Reply-To: <20220915150417.722975-1-glider@google.com>
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=jNTI5WaC;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 15 Sep 2022 17:03:34 +0200 Alexander Potapenko <glider@google.com> wrote:

> Patchset v7 includes only minor changes to origin tracking that allowed
> us to drop "kmsan: unpoison @tlb in arch_tlb_gather_mmu()" from the
> series.
> 
> For the following patches diff from v6 is non-trivial:
>  - kmsan: add KMSAN runtime core
>  - kmsan: add tests for KMSAN

I'm not sure this really merits a whole new patchbombing, but I'll do
it that way anyway.

For the curious, the major changes are:

For "kmsan: add KMSAN runtime core":

 mm/kmsan/core.c   |   28 ++++++++++------------------
 mm/kmsan/kmsan.h  |    1 +
 mm/kmsan/report.c |    8 ++++++++
 3 files changed, 19 insertions(+), 18 deletions(-)

--- a/mm/kmsan/core.c~kmsan-add-kmsan-runtime-core-v7
+++ a/mm/kmsan/core.c
@@ -29,13 +29,6 @@
 #include "../slab.h"
 #include "kmsan.h"
 
-/*
- * Avoid creating too long origin chains, these are unlikely to participate in
- * real reports.
- */
-#define MAX_CHAIN_DEPTH 7
-#define NUM_SKIPPED_TO_WARN 10000
-
 bool kmsan_enabled __read_mostly;
 
 /*
@@ -219,23 +212,22 @@ depot_stack_handle_t kmsan_internal_chai
 	 * Make sure we have enough spare bits in @id to hold the UAF bit and
 	 * the chain depth.
 	 */
-	BUILD_BUG_ON((1 << STACK_DEPOT_EXTRA_BITS) <= (MAX_CHAIN_DEPTH << 1));
+	BUILD_BUG_ON(
+		(1 << STACK_DEPOT_EXTRA_BITS) <= (KMSAN_MAX_ORIGIN_DEPTH << 1));
 
 	extra_bits = stack_depot_get_extra_bits(id);
 	depth = kmsan_depth_from_eb(extra_bits);
 	uaf = kmsan_uaf_from_eb(extra_bits);
 
-	if (depth >= MAX_CHAIN_DEPTH) {
-		static atomic_long_t kmsan_skipped_origins;
-		long skipped = atomic_long_inc_return(&kmsan_skipped_origins);
-
-		if (skipped % NUM_SKIPPED_TO_WARN == 0) {
-			pr_warn("not chained %ld origins\n", skipped);
-			dump_stack();
-			kmsan_print_origin(id);
-		}
+	/*
+	 * Stop chaining origins once the depth reached KMSAN_MAX_ORIGIN_DEPTH.
+	 * This mostly happens in the case structures with uninitialized padding
+	 * are copied around many times. Origin chains for such structures are
+	 * usually periodic, and it does not make sense to fully store them.
+	 */
+	if (depth == KMSAN_MAX_ORIGIN_DEPTH)
 		return id;
-	}
+
 	depth++;
 	extra_bits = kmsan_extra_bits(depth, uaf);
 
--- a/mm/kmsan/kmsan.h~kmsan-add-kmsan-runtime-core-v7
+++ a/mm/kmsan/kmsan.h
@@ -27,6 +27,7 @@
 #define KMSAN_POISON_FREE 0x2
 
 #define KMSAN_ORIGIN_SIZE 4
+#define KMSAN_MAX_ORIGIN_DEPTH 7
 
 #define KMSAN_STACK_DEPTH 64
 
--- a/mm/kmsan/report.c~kmsan-add-kmsan-runtime-core-v7
+++ a/mm/kmsan/report.c
@@ -89,12 +89,14 @@ void kmsan_print_origin(depot_stack_hand
 	depot_stack_handle_t head;
 	unsigned long magic;
 	char *descr = NULL;
+	unsigned int depth;
 
 	if (!origin)
 		return;
 
 	while (true) {
 		nr_entries = stack_depot_fetch(origin, &entries);
+		depth = kmsan_depth_from_eb(stack_depot_get_extra_bits(origin));
 		magic = nr_entries ? entries[0] : 0;
 		if ((nr_entries == 4) && (magic == KMSAN_ALLOCA_MAGIC_ORIGIN)) {
 			descr = (char *)entries[1];
@@ -109,6 +111,12 @@ void kmsan_print_origin(depot_stack_hand
 			break;
 		}
 		if ((nr_entries == 3) && (magic == KMSAN_CHAIN_MAGIC_ORIGIN)) {
+			/*
+			 * Origin chains deeper than KMSAN_MAX_ORIGIN_DEPTH are
+			 * not stored, so the output may be incomplete.
+			 */
+			if (depth == KMSAN_MAX_ORIGIN_DEPTH)
+				pr_err("<Zero or more stacks not recorded to save memory>\n\n");
 			head = entries[1];
 			origin = entries[2];
 			pr_err("Uninit was stored to memory at:\n");
_

and for "kmsan: add tests for KMSAN":

--- a/mm/kmsan/kmsan_test.c~kmsan-add-tests-for-kmsan-v7
+++ a/mm/kmsan/kmsan_test.c
@@ -469,6 +469,34 @@ static void test_memcpy_aligned_to_unali
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+static noinline void fibonacci(int *array, int size, int start) {
+	if (start < 2 || (start == size))
+		return;
+	array[start] = array[start - 1] + array[start - 2];
+	fibonacci(array, size, start + 1);
+}
+
+static void test_long_origin_chain(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE_FN(expect,
+				    "test_long_origin_chain");
+	/* (KMSAN_MAX_ORIGIN_DEPTH * 2) recursive calls to fibonacci(). */
+	volatile int accum[KMSAN_MAX_ORIGIN_DEPTH * 2 + 2];
+	int last = ARRAY_SIZE(accum) - 1;
+
+	kunit_info(
+		test,
+		"origin chain exceeding KMSAN_MAX_ORIGIN_DEPTH (UMR report)\n");
+	/*
+	 * We do not set accum[1] to 0, so the uninitializedness will be carried
+	 * over to accum[2..last].
+	 */
+	accum[0] = 1;
+	fibonacci((int *)accum, ARRAY_SIZE(accum), 2);
+	kmsan_check_memory((void *)&accum[last], sizeof(int));
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_uninit_kmalloc),
 	KUNIT_CASE(test_init_kmalloc),
@@ -486,6 +514,7 @@ static struct kunit_case kmsan_test_case
 	KUNIT_CASE(test_memcpy_aligned_to_aligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
+	KUNIT_CASE(test_long_origin_chain),
 	{},
 };
 
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915140551.2558e64c6a3d3a57d7588f5d%40linux-foundation.org.
