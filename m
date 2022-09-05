Return-Path: <kasan-dev+bncBAABBOWL3GMAMGQE35QV4SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D6A275ADABD
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:10:18 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id j22-20020a05600c485600b003a5e4420552sf7917359wmo.8
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:10:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412218; cv=pass;
        d=google.com; s=arc-20160816;
        b=03SmrkhVFyhuOjGrdIqdDvHCg4FGhWNpTru5p1QjRrgwAoJeMOiWYatEGT7o++d9Zq
         b1DJ9LuCq/ne35bSxnF1Cmf6VnJuhYs30rWLlvMxH+f8L5NDVONha/VdOoUgR4mwJzea
         8aFqWFzJ194IVoWGjVsaOkRH2DhPERFOSe4v2Xr7lHCtpzdoAYxedaTpngcsjZOz1zSd
         nSijkXWM7SN4tSPGDIaCt6noGV8Xie8PzaCncE8tKe60aMoK/+T3D68Jv+QMRN4MJSBK
         kxDKKljdWg3YIZllSJnpsb2f8+TiLULiv5F1NKifJfB7EftpURwEReZRjPHSJNHCzTtf
         VdXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VhF9uPZT6XcH+m6a0g+dpwkzaKFDEOGo5LFZmhlpNC4=;
        b=Jsl6wJI2srnf19adRBex5GGHlheoWg1OO4OENcpPNiLJ+byp+mFVnfvAaGRayi27XH
         71+E3U/lwufNgYeCeRO0lTvD8LAmugoeSbicnB8djge6qP3WP8MC2YY3KoUq5RjJzsv1
         Lg3oPseXMY5VU85ywT8nzXobLtui1Ypae0OqKvgo7Nszt77EXRIBegTF1tmgesQfICqQ
         A+4benBmDPleItFxSXyET3qOS1VVzwAYV+adAmDI7RyVSyFl5FL9c7y69RmSxbXjcDjl
         X1yL8r4XTpqlKJE09w2xBQTO30VoKNJG4ARuF+73yvfDGdzcYeGdZZqoGlZKxbbijk4+
         zkuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eclOyiHs;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=VhF9uPZT6XcH+m6a0g+dpwkzaKFDEOGo5LFZmhlpNC4=;
        b=P7Ca9q2O4u1yY2EoRWw5TiZ3OqNG5JgXFdnAcMLSGLX+U5+JFyNHtZDrpPlV8R7mEV
         /JZS9/ObBOcdCHZbTYEK70fJfPLmzwAtDAwPeYT9EAwWMYhT5B8Xm7CHVMpf/+BQLB52
         XBZG70LIdyvjV/gwxSWcuQLAimJOK3QOy7PRKyT+I3uFtxFFuUeigZhDaabF5/3+ZTPI
         T5fxSIlaKmBok5FIRbLUSlBw6+tfuf7nDXrqViXyru90Xn2yAoDJ3WsPg0evf84BfWjw
         jOlef55OEwAKFBd7TzJwvPlVS+rsZ7WaTD7hXw/+S0KNbaFtU43Sr9PgBx7GDJXGz+Ph
         Zr4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=VhF9uPZT6XcH+m6a0g+dpwkzaKFDEOGo5LFZmhlpNC4=;
        b=Uw2UU0EVUUKrqnbirGEHfQH/9txDNY9fXceVAftS/y4fbjLw6JEEljaraWCJF2qnU3
         XQ+YnT8jmuLRppA1HHNOutLu/fqZ/sZHbkcdLfjMCYnTVx1F9IXYcpuGNHzkBGCfx06Y
         X/QmfyNCSiY+0356psECxh/9HosXtDerx5gVRTkk037gXFkgHBjYSY3dFZHynCNenHgi
         xmznSZz+ZdC3HH0rBXsAG1f46Z7Uqc8CDKt6OxxoebMAVT/useac3chSQFh9koTIMS7+
         HA5qSJhL1/i+B6kJ+ocCt8UANFKWJsaH2UICnrj1PPdfIwsS32JR0Y5jzk1GThfExwLo
         M9Tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1NPgN6zTBL+We9AkItqk2qmhzNKmzG5HMHRjEls+hZ1eYzI6UR
	7JQTXYefeEnM41S3lrSHO9Q=
X-Google-Smtp-Source: AA6agR5yGJc8GGxl1u+58r2Fq7gWfzhJRvfv4oGQa8Lxm/+3+rfrVHCpS/TlevlMNllkYt9uYq2azA==
X-Received: by 2002:adf:f8c9:0:b0:225:50da:d43 with SMTP id f9-20020adff8c9000000b0022550da0d43mr24971097wrq.28.1662412218611;
        Mon, 05 Sep 2022 14:10:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7407:0:b0:3a5:abc9:1b3b with SMTP id p7-20020a1c7407000000b003a5abc91b3bls4142962wmc.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 14:10:18 -0700 (PDT)
X-Received: by 2002:a05:600c:190b:b0:3a5:f8a3:7abe with SMTP id j11-20020a05600c190b00b003a5f8a37abemr11911434wmq.81.1662412218064;
        Mon, 05 Sep 2022 14:10:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412218; cv=none;
        d=google.com; s=arc-20160816;
        b=C2/EdvGR3tSC+6q550tJLbo5txcBJIrMyJ8jlx3aIW5JcneQxsS7Q91siSR4Aae5N7
         WvMlCM12X9YwqhuaNH8G2M+m4k/QFo7R1lgm+iMvE5G78qDWrXze2MxgFCT3AAjjdY76
         HXYtuBiaWrIB0zkyLJ270k+yQDmIUqa4JhLcHH0w4nnFBSFgfUE/h4o4Xdc0pMLy9sCX
         EW0sGsQLgUROcz8VpquaYBQjLKLI/8MNMiKDYds5qaUJBf2e2WO3xwRQTqtGlvW1BMru
         SEPR4hmfFklhV8bygVoS6K4zUOK8WQBHlNQ1K0wpojBd+z9qU4j9PE7iJ0QVA7iDwk5E
         elnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kPlnTXt8NQm9Ac19H9NvNTSg2CSZklYQnAaLBGVcJ14=;
        b=VflGPhDFmyp9dfc0OSY0hl4L9WFRsamqsQK6EaAWQPgMxON4gDJnXuYw4gK0YR00gt
         VmDQW1y0h0T0GHoXB6+Caot4m9TyatxRpPmnmYFoLO7CYkN4sx5zrv1NreCie+Nbo2Ji
         w0rm0mZwR/NoP8b0K5eRoYM6qdcGJMnuWoqtmKixMOOlKTBpRyac8Hi2nUsewKwoEavK
         vvkposeNGR1lDb/VLoWYfAaOm4+8Acbwfl+qmRySzoXn0pK1buxvnNSCiVcaPyrPqr2h
         sKXKltuaLqRq4pHqPp8ps7Y6jkFO+6HUsMPJLiyqEany0d0y124dcWprQPBrqJZajRbV
         Ay7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eclOyiHs;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id ck14-20020a5d5e8e000000b00228d6a43531si62622wrb.1.2022.09.05.14.10.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:10:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 28/34] kasan: rework function arguments in report.c
Date: Mon,  5 Sep 2022 23:05:43 +0200
Message-Id: <2e0cdb91524ab528a3c2b12b6d8bcb69512fc4af.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=eclOyiHs;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Pass a pointer to kasan_report_info to describe_object() and
describe_object_stacks(), instead of passing the structure's fields.

The untagged pointer and the tag are still passed as separate arguments
to some of the functions to avoid duplicating the untagging logic.

This is preparatory change for the next patch.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 23 +++++++++++------------
 1 file changed, 11 insertions(+), 12 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 763de8e68887..ec018f849992 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -213,8 +213,8 @@ static inline struct page *addr_to_page(const void *addr)
 	return NULL;
 }
 
-static void describe_object_addr(struct kmem_cache *cache, void *object,
-				const void *addr)
+static void describe_object_addr(const void *addr, struct kmem_cache *cache,
+				 void *object)
 {
 	unsigned long access_addr = (unsigned long)addr;
 	unsigned long object_addr = (unsigned long)object;
@@ -242,33 +242,32 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 		(void *)(object_addr + cache->object_size));
 }
 
-static void describe_object_stacks(struct kmem_cache *cache, void *object,
-					const void *addr, u8 tag)
+static void describe_object_stacks(u8 tag, struct kasan_report_info *info)
 {
 	struct kasan_track *alloc_track;
 	struct kasan_track *free_track;
 
-	alloc_track = kasan_get_alloc_track(cache, object);
+	alloc_track = kasan_get_alloc_track(info->cache, info->object);
 	if (alloc_track) {
 		print_track(alloc_track, "Allocated");
 		pr_err("\n");
 	}
 
-	free_track = kasan_get_free_track(cache, object, tag);
+	free_track = kasan_get_free_track(info->cache, info->object, tag);
 	if (free_track) {
 		print_track(free_track, "Freed");
 		pr_err("\n");
 	}
 
-	kasan_print_aux_stacks(cache, object);
+	kasan_print_aux_stacks(info->cache, info->object);
 }
 
-static void describe_object(struct kmem_cache *cache, void *object,
-				const void *addr, u8 tag)
+static void describe_object(const void *addr, u8 tag,
+			    struct kasan_report_info *info)
 {
 	if (kasan_stack_collection_enabled())
-		describe_object_stacks(cache, object, addr, tag);
-	describe_object_addr(cache, object, addr);
+		describe_object_stacks(tag, info);
+	describe_object_addr(addr, info->cache, info->object);
 }
 
 static inline bool kernel_or_module_addr(const void *addr)
@@ -296,7 +295,7 @@ static void print_address_description(void *addr, u8 tag,
 	pr_err("\n");
 
 	if (info->cache && info->object) {
-		describe_object(info->cache, info->object, addr, tag);
+		describe_object(addr, tag, info);
 		pr_err("\n");
 	}
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2e0cdb91524ab528a3c2b12b6d8bcb69512fc4af.1662411799.git.andreyknvl%40google.com.
