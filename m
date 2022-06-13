Return-Path: <kasan-dev+bncBAABBX5VT2KQMGQELO4YGOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 56044549EB2
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:15:28 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id c21-20020a056512105500b00479762353a4sf3508087lfb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:15:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151328; cv=pass;
        d=google.com; s=arc-20160816;
        b=R+303bv2t+CFBnL7R1FakGGW2CGgt02mLAO1nfZctjClCOL/T3+LcwmmjrdlaQo0as
         +sJB6Co7rzCFw19K8qndckEQLwZGXCmKCEiQCsq617wgev3rHuhJ0g/qzcUHO3qwJbb6
         l6t6wIt/bp1U/GuhR+m7hIYgPyJDi680Zvsj+qucUFW2BNbFwzSLB8i/5oh4WIeXnxwO
         hCX/cWcfYivwuXzT1zp2I1ztlTCI20VEusT63WgbnrdIYDsKIUun5Hadoq96DBLpWeAi
         4Nql7zNAMt7VfG/HFVFt1gVlTnLzeBHZOXfjSHX6u70CReOGUn8lpWu5GEwTKYDSVUxb
         /SiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oEXYKE/uTzBXTJWlUoCA1Gb1UyhfEV8GsY1sqm5esf0=;
        b=vzT5cRs7PD6ByvDaY+A6FfUTG6dEe21I/Z2cALYKTipPVackTL04VYBm/3aovZ5Bsf
         UavhW3KvqiHPa6uqZSW3udtXCxNiWI4qJrjkSZsaIt8Ezb1btqoc7FJvxJ1gla6zKpoO
         m/OmXy53I5e5m8YM9TDod06wHmm/v+eyf9i0ejytGqwqTImPYjjo/g7qVYuAwVHYZBMJ
         sUHv+BK1Z68+6OiPLbt5NttzlBQqCy6bESudw8Q34+6T7I9aN/XKp3b2LaW/RjqfrV9c
         uBJHXeZ9m61PSOHyZXuW/cvuDPhQ5xVKwtUCXPTInRD343PybURU8mduFcJK/nbL3OWy
         OuCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=McdlmQai;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oEXYKE/uTzBXTJWlUoCA1Gb1UyhfEV8GsY1sqm5esf0=;
        b=UyCP2Lnr2bnT/HsyE/CRtOQic9R6YLdksn3m84zn1ywRIWO0QNL+H3dj3WOE0xPunb
         /eqTntjEF6gnPivD6TM3pxKNDp2vWZQY8aPBXkgkrWc4zzsBFYRR7u2elumHhzlqSR8/
         4kyi06eiiWMjmdEQv0r6VrK1aoI+MzLvj/d/6sTjGGqI5cpzU3CMxGv4vpbZ2bXiMM4j
         xKnB8oV7N9fIVouAbKwadY4p7p66c//5P4B6CxV0uePVyOtgwHMcFP+lI3upiLOE5piV
         rrQwUaqHl/U7cshIvFWLrxmh0rXXqj48ycLOr9znAVOdmGj1l3+KuhdefQFf6U63BRh9
         66vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oEXYKE/uTzBXTJWlUoCA1Gb1UyhfEV8GsY1sqm5esf0=;
        b=v6G9SOf5pMyHUSvdS/ZBhOLQrXTCf80cGdjkTYfD90Fo+yI/AwSGHdHrHckuENjIa6
         OmSv/2TuxqFr2jHHSmrYriPcFz8h7yDNrl/F0UD+LOfrEh2doM5q9q49atHf05aFO10i
         0q/ju3USo0Uzlp5L7SvrWzlawGDL3PLFGFDkdnZPFINHnMHpI0XNOUqHRVFg/V5tBoUD
         JqkvpFi7WaW7TIr+Zo4tpK6xG3DpSi+2Od/KrgcqiIo7QlUpanFaSFX71eNgUWGvzLqX
         fXhYJXuYThRra+QJimNiQK52xRlAxiabqkhxxKmLtdc3f8013vlVXqIrjz8i0bSrTWhZ
         SjeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9TUMBoXh4bBFpyeKrgJIphyXUHqHdngImQYpP1etKns8LYZHvd
	4aTxsQ1VcRUjzBumZPjpWE8=
X-Google-Smtp-Source: AGRyM1vR4wvPPabAl3Vals8hCHYcCCxmeNpMgG/HeC35hjTD8GkBzsbSgDBJvBQvEe7kGGYEUyd0yA==
X-Received: by 2002:a05:6512:158c:b0:479:307c:e73e with SMTP id bp12-20020a056512158c00b00479307ce73emr863481lfb.576.1655151327729;
        Mon, 13 Jun 2022 13:15:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als182897lfa.2.gmail; Mon, 13 Jun 2022
 13:15:27 -0700 (PDT)
X-Received: by 2002:a05:6512:4004:b0:479:1d77:4e43 with SMTP id br4-20020a056512400400b004791d774e43mr878304lfb.537.1655151326916;
        Mon, 13 Jun 2022 13:15:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151326; cv=none;
        d=google.com; s=arc-20160816;
        b=SYT7u7hC4wglQorMetD4I7z4R7H+XYUchD8acKLD1RdCOKrDQFqj45eUAaycHg8G9N
         936kbBEX18Ggilo8EN7YT79I7DJ47K5MXWOuHVig5wiXAJRbNVecDU2mLn5BwG9IQbmn
         8xNmvv3P7yh2pPONZczPWaD0h8f0Ey99ac3cM4+ulUQHnRIU31nizDXvWNnHguovs3A8
         sjIiLtQbusji6TtG+BgNRTD+VxaEkDsfWDJHuA+M3cjWInEnzllS/AFkxCRKg3eLPHd8
         AkuGz9YW1OK9QIqxi47pUL3dPleMoRBMQN7/wxSIzVmlC6QxSs0Eta7a6lOBLhO882Oz
         tbIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CulRI3DSt2ZPgq4QmoSCGGdERJCYU8brnjMdmOnBudE=;
        b=VJnr0YXwsErPh6EnuDs3TH3nFY4y1limy3GYSzgJjaAcUpf/ePgELM0iPewc2+wo7a
         VOiE3EKq2b9XSjmE20L7JdtXEegYa2OwRgLehw9+FbFp/rYPobj9eY0foh4wDQT4WggO
         ldgQmyPNniNL3MGeRrwRkDJL/yF7M3LysqQzvFaIsVgHvpFs5AWd+Gs2p6WPWEQ/6cEH
         xEvgIPy1jeA6fQ+dL/OZHbYnOin71QVHsu6WHnzt0GsMsT3kVAcUI3aX8xcnMcy3Qd9c
         HrkYohza0HHnYwpw9en5auM5DXF+MvN86viB9KKalM0OC2VU7/bU/JS5bOcOgUd9vgfe
         V8LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=McdlmQai;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id i27-20020a0565123e1b00b004786caccd4esi301357lfv.4.2022.06.13.13.15.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:15:26 -0700 (PDT)
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
Subject: [PATCH 04/32] kasan: split save_alloc_info implementations
Date: Mon, 13 Jun 2022 22:13:55 +0200
Message-Id: <ae1389c0717d1875077ee3f6cd4beb5b7e046ae0.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=McdlmQai;       spf=pass
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 13 ++-----------
 mm/kasan/generic.c |  9 +++++++++
 mm/kasan/kasan.h   |  1 +
 mm/kasan/tags.c    |  9 +++++++++
 4 files changed, 21 insertions(+), 11 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a6107e8375e0..2848c7a2402a 100644
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
index 6df8d7b01073..610057e651d2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -284,6 +284,7 @@ struct slab *kasan_addr_to_slab(const void *addr);
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ae1389c0717d1875077ee3f6cd4beb5b7e046ae0.1655150842.git.andreyknvl%40google.com.
