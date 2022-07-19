Return-Path: <kasan-dev+bncBAABB3XM26LAMGQEQ5IGCDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id BA915578EC2
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:10:23 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 3-20020a05651c00c300b0025d8fcbd063sf2310307ljr.16
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:10:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189423; cv=pass;
        d=google.com; s=arc-20160816;
        b=xaibE8h9tIh16UmSFGd4Oj6Nil9CWWSO6zQgU+GH1uOGOVGrlTHI3gJ2QlYoCSBgEt
         3KCs6LLCsg5TQXGcLLj0FtAGpYkgNHw4pjKeRp4d0S+oMUL8Rm0/EQhVTd+vUKOKgZqE
         Ge3/ADaBwF9ynTvGdbmtOOVl5U5ILTHqAfHcrG2FAbxzitDfa82S6KrTWcOnewu5UWIt
         xpylfXLfhAvb2TronXYdgXLTVEyq73cLwz2k+M8hBNbYFvoCNeEQGnC68fmxxepH31K3
         0UYsIYmEEgNKhhkoE2DwODZ+7b+SAsu0uwB7IkxUGZDFigIfiGVMOO7iO+TL22oovFL0
         h/Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=B2xa/J55tC/FZWUvjcDOgh5GTFgmt4mM3soU5JuYsCg=;
        b=0xa3xsXhyyvcMJBrC4gr1gihbpljQ4tc4U3LHSiEqVOQV9S6dIXbNbJ7tCWxJCfybQ
         7HOkHi9jxa+rU3B8FEDpqdGaru9ctaOZ/9Ls2rf74D2iNahy3IXrarayBgnsRAglmGE4
         cQeA30ccoYmUJqvXxl1ny44gihnBX7Zm20k3pP6tGmpqTBxTsRE9c8utRKcN6vfmtOWs
         yBP+/KV1PNQeBKynedix7XLQWbdTwh5320llDScnjQTX2xzSuZrVt0lyJXlG6EpfMFGm
         6T6SV6hzs+Wfkp7ciMNeicTn8DtahkoPZkgCLcILaTfIwsvTLoNShd32otIOPBlg5Qr3
         vA+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="vN5sLA/6";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B2xa/J55tC/FZWUvjcDOgh5GTFgmt4mM3soU5JuYsCg=;
        b=uAWaz+lHMqxx/fEI59FE5bvkW54HBmi0pteXX9zoXXZ65OqoftZ9VPeliiROKIgRrP
         HpXpuqpK9XUJ0VdSt1nqjYVfD027B+wv40lKc3j8nyM/2HV3xFqTj7Fq1oIZoGJ4C01g
         P3kq0aX89cinbHLWG64EmlhBvBF5pv+iB2R1g6Xzw557jAftK9YxgKgdRRQ4JTPMf9mM
         rRDxkZjY/Ecgi1XzhZOlHCmat/njJMMNStqMOyV/BqH97zPBqkTtBIVsyk1r1gAf9MQg
         Ae2qxQ2KePP1IB9qfReO0uDM3p36CxAhS9I9rpG4cw8zUbgx4Euwcr3N1SkmWNsrS1dR
         IMFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B2xa/J55tC/FZWUvjcDOgh5GTFgmt4mM3soU5JuYsCg=;
        b=H5BfBzZ3xasLL2LFZ7HE77vETpXrYLiGFkCIRszIPVcvNVbQvwA75y/RSEyokupstp
         LcNPAZ6AUlEIIGF8YfVrpHGMI0eGlXedOBuiNqXyA8cni7NG1Ns3kdypOLJUrUHB43ZF
         ebK92cINdBWKfwAGB61nnRMLVQoajXVDKsx9jbzKcbMzEBQvwwwid+sxvdsB+YT8hYQl
         DVyFmQhGXk21gtAv7jtU28eQWkPhI8iDz2LDNfCI+yLABbYZ7Ru0RMjsxgrQpnWKgBAM
         FX0jxDK3epVYuBIyzvXY1ZRII8qyCWNXLTgwwIlyaM2KbtA0AJOV0HxF4coFe3aq8xi6
         s1Bw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8e9svr2grIAdWMiumjGFtNDZCu5E5UIlb6HZ+PUhfyQWCpcVEF
	AVVFCC/zMNODrxjinkF7dCE=
X-Google-Smtp-Source: AGRyM1t6p0Jfh+EvMRtTBzsWOKyqQBPfP3/WgdciOPQ9NvOMRHNrw4uw43atRvon+ll/Mtw9MVt4dw==
X-Received: by 2002:a05:6512:2285:b0:487:2538:f0e0 with SMTP id f5-20020a056512228500b004872538f0e0mr17328360lfu.614.1658189423128;
        Mon, 18 Jul 2022 17:10:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a405:0:b0:25a:6ed4:32a3 with SMTP id p5-20020a2ea405000000b0025a6ed432a3ls115571ljn.1.-pod-prod-gmail;
 Mon, 18 Jul 2022 17:10:22 -0700 (PDT)
X-Received: by 2002:a2e:86c6:0:b0:25d:6eee:127e with SMTP id n6-20020a2e86c6000000b0025d6eee127emr14198106ljj.328.1658189422302;
        Mon, 18 Jul 2022 17:10:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189422; cv=none;
        d=google.com; s=arc-20160816;
        b=e/0OrouJFlGHcDQ9UHkU2/qoJONMBZ7lMv3ioapzldcHiFQTAY70RIqxmb01n4sPTv
         M+KOKInywa5EauADTNN1RvqZzDYoy7XFJVzn/5Iwph0OY0b+1QJk7g9WfyxBfj6JAkFy
         kCJxY/GKuv+UlLSpAVHVgj9MEmsZXZ658H2I5ON3rPzH7G1bvQEooE6IoMKr0Bn0M27C
         V1wQMchA178gjqgBlLePpVuMHoINqKqqTxc4kVZenJolw2dU8zS2deIB/Xiy3f0x2j9W
         miTXN0LMh7MKg8Y/vSBHWUZPYnPZUYV7jjBJUjgPfpcKf5IlGAo484hEDJ4fc2GqHIO0
         vSHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BHknbGRO3VLc1Ld9zukA6zQR173/1lpbGzpiOKO/Yio=;
        b=ei9W8kCUTvPsB3WqXek10ThIooSn/aW4KaoGH6m2a9/9OdcqG09a3gZatM+FAIqfG3
         jSu5ksJy/okP5vJBJaJEw/Hdv/9Ev77UgmyKYbSI0rjW09p5w9xAdFrtV5s8bqjsYpoz
         NXujKuG3Pdufp/RMndQz5pefou5ZujrVHZ9RgUCp69UlkEp5P88anXTERGj0sOwf2uVM
         AHoBgt47+er3J84jqdYm6fxfyM3pvk7hFkrZr0nsgo60bD4c2in0YrMlwCEM7OAtgOsG
         0PxqG4V1A1B8trv60dHEeAbig82ZgLcsXydXpHJ44xhc39tlYJT8zE6A+EFbMruPgqbx
         ilLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="vN5sLA/6";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id w8-20020a05651234c800b004830f9faad9si380662lfr.1.2022.07.18.17.10.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:10:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 04/33] kasan: split save_alloc_info implementations
Date: Tue, 19 Jul 2022 02:09:44 +0200
Message-Id: <891eb09a249af9bc79939b5be0a5076d65a34220.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="vN5sLA/6";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Provide standalone implementations of save_alloc_info() for the Generic
and tag-based modes.

For now, the implementations are the same, but they will diverge later
in the series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 13 ++-----------
 mm/kasan/generic.c |  9 +++++++++
 mm/kasan/kasan.h   |  1 +
 mm/kasan/tags.c    |  9 +++++++++
 4 files changed, 21 insertions(+), 11 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a6fd597f73f5..6156c6f0e303 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -423,15 +423,6 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	}
 }
 
-static void save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
-{
-	struct kasan_alloc_meta *alloc_meta;
-
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta)
-		kasan_set_track(&alloc_meta->alloc_track, flags);
-}
-
 void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 					void *object, gfp_t flags, bool init)
 {
@@ -462,7 +453,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
 	if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
-		save_alloc_info(cache, (void *)object, flags);
+		kasan_save_alloc_info(cache, (void *)object, flags);
 
 	return tagged_object;
 }
@@ -508,7 +499,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
 	 * This also rewrites the alloc info when called from kasan_krealloc().
 	 */
 	if (kasan_stack_collection_enabled() && cache->kasan_info.is_kmalloc)
-		save_alloc_info(cache, (void *)object, flags);
+		kasan_save_alloc_info(cache, (void *)object, flags);
 
 	/* Keep the tag that was set by kasan_slab_alloc(). */
 	return (void *)object;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 03a3770cfeae..98c451a3b01f 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -358,6 +358,15 @@ void kasan_record_aux_stack_noalloc(void *addr)
 	return __kasan_record_aux_stack(addr, false);
 }
 
+void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		kasan_set_track(&alloc_meta->alloc_track, flags);
+}
+
 void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index bf16a74dc027..d401fb770f67 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -285,6 +285,7 @@ struct slab *kasan_addr_to_slab(const void *addr);
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
+void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
 void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 				void *object, u8 tag);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index b453a353bc86..1ba3c8399f72 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -17,6 +17,15 @@
 
 #include "kasan.h"
 
+void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		kasan_set_track(&alloc_meta->alloc_track, flags);
+}
+
 void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/891eb09a249af9bc79939b5be0a5076d65a34220.1658189199.git.andreyknvl%40google.com.
