Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBE5BZ2HAMGQEW6V77UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id EEB3B483966
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jan 2022 01:10:59 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id bq6-20020a056512150600b0041bf41f5437sf7107037lfb.17
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jan 2022 16:10:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641255059; cv=pass;
        d=google.com; s=arc-20160816;
        b=JzJG5FL4rXJ1pqIl8IBAMbGV8ag4VUmR0conV6+WBfGNfyFbo+frpNLTtxYD299Hnc
         OME70TvC4B6o0D1bM/M1CnsCX2xrp3OC4yfrdQ0RIJ6XSUTciHh51QQoZCW80TFT0dkQ
         e1LihNSOKVvFCBnRHmPK6TEtpyN8I4HisOiK9u3dAo09iB3Z8liNPjwxbwXm0bHnwS0s
         0bYSI119Ryd/4f8uHoqxzQnYt3KpHEL3fBXzBOd56i7fNjNKy/wA3VDeqhhokzVJGW4o
         BceYQI+eKzTuuQEI0kRb1VdoAWm5OYFBugZnMoDO/ulX70Jzq5A6DYYu3oTWeBIREnYQ
         eYyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uoHxe2A+N8oCvXJ6n1n5p63Juw/SOGsa99oOACLLjo8=;
        b=AQ5Wxu1HqtUhzdwXbz1mGiinSD75JP+8v4TG1vO0lugnXTxRUfPpPhT7HIISFx56Ey
         JbhWslP84kL4LUUj2nwRA3UkAPf3W4dfogFGdUEBTVjddbRQUPR8Kz6Hus1nYvV0ATwU
         Yyl7Bx7xZCHG049b+Xua9Cdtq3PmonR/KMwhrXVIgRbcm+fnTrsf71JNrLgYm+KW9xlt
         WQ1eANRSNeeLCYKpiOI38FsiHPhI3csP/p9otGFlBR4gms/+/kJ704vRI1RxyTxxLdNT
         OWQiwQyEV3buhuGH0VMb+qQ/5SXevABLIYBUysWwtw9UKQU62k9Mob7I1sx0RU3VS2U8
         gSFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ykEUHH7D;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=SrSBjdlQ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uoHxe2A+N8oCvXJ6n1n5p63Juw/SOGsa99oOACLLjo8=;
        b=MUkelr/CpBQAGpeEsIPcEjxRIgpqGpSzVH0xs2gcWZMQAt9Nw8Fsetk7YvMNUU5uBx
         hrSe6nmfkBQmZ2n7pHB3k8v0KFONemMUYiaY+AD3ng8ZrRh97QyWQzdgZxW4iIVluZgT
         c2+gVkY4kkKxXWp70VIQqOpP4wi/VJI1izrrHKYRa58EEBjtVRN04vzvLFCMecSfbxMr
         A63qLWOfgFDvLaKbQnaDXlTec2HueVvZsuprdwwRrwTsgNJGq327k/LsLOq4PmLtlzQc
         FVwgHeBGF3fGyJGer1khI2t2QQXrU3/bmZsf2mqPsL7oKzZoJS/voV4y7zC0zANgupXr
         5iow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uoHxe2A+N8oCvXJ6n1n5p63Juw/SOGsa99oOACLLjo8=;
        b=U5Kg7iI55Q915T8arfFen7+ixeBS1wVwoZ87Ektjdf/rOwZfsnOko2iKn3AepNeC2P
         o17FW5iezJPMwnmrqjgLA+zSXaFdXdpo2MTnKgMe59cASn1YYwfwBivTbAA60ZxHiN/0
         yxegFSk7wkhk2MvQT/Kr+zGzArpulmPFyTVksjorleEkVXTvNVXay9fWmCBYLphOjqfi
         6MuhklKniIDrpHUeKqmrVLMaA9NkncnTbHLMcEf9SINBTX2yKUa86oy4wHooilWcyH/Y
         T1k7uftMzdQiN6nbZmtTuq+wfpYqzcCo07SW/maIiNLrLglDiaH7qlhWEkZoY1KDrFSw
         dTJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531LFPvXO9aVf6RtMrpQ5axUnrCwj2LBQFugaOmWmlKQR/qqaRy8
	in9zrJhi0oLBvdoBQoW0gfE=
X-Google-Smtp-Source: ABdhPJw3AqfxDNj8fplkP7Je2pcFCHFMzVyC0FS/zVdY/LXY8IMfY6d07Ybvag0l2pZU1q615OkPVg==
X-Received: by 2002:a05:6512:39cf:: with SMTP id k15mr39920801lfu.664.1641255059585;
        Mon, 03 Jan 2022 16:10:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5304:: with SMTP id c4ls3754499lfh.3.gmail; Mon, 03 Jan
 2022 16:10:58 -0800 (PST)
X-Received: by 2002:a05:6512:2347:: with SMTP id p7mr38788071lfu.341.1641255058690;
        Mon, 03 Jan 2022 16:10:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641255058; cv=none;
        d=google.com; s=arc-20160816;
        b=cR3En0Z87ninLbQBdYQfxBJ9pPwQ1vrfnbYrAPe6DzyzjMJemCxPDzf90HO5epjbNJ
         mjmgm64DcP0sPW4/rPAP454pocol3HkJjiWx/kllH/O9xaMt4htUMVZ50PwMD5o0MzNS
         PTUk7b94GDye/+yQjenFi01nksrTuRADGkvqMvcJD4/ud2ghxaY+Ayl3kjaM1787YJcz
         fd8Pl41SP7VK54eO5PJJGKJfdcoG3l4Spw0hh52uHXmHZ4dCYLaphNFwD3aahgNBkT4f
         ct1xk/bH6ZpYNZs538/Z+pX4oeOS/dryy1toyKgCiCAsvdSwW3XwDEesgODZpt3m4FBh
         V2pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=r/9GRM1wKTGUJP0nx+VBbfm6M5Dh8MHDWKxDDmjiXMQ=;
        b=RGSm06eTYGTcPx3GxbpooUp9wELFnU6cil+S3VnhKwe3BClSS/Dm+xz090vsawSZbB
         yE4cARdxoYX0Qxx+ndMR5sFW1NshiQjbznMjRL1VTnFXyHgqTVHrOtPmZOzNxHMTJGDT
         l/zg378SId3W5kc9hVGcfhT6SUponi68BwXnXuulZuxlPxzud7A8BP+JcC97APHvNAct
         5m4q49k+bXgFpB489JDAMHwGSC0ZQGUOP3DQqbA3nuAEIcbHaMRpnnPcLTGq7CTtpjwH
         qeyEtLxEqPU5OaVCkuSfnTNkPBrlDUs50VpyVomzrAIQ8U1D42B0PhyAQo+8CPFSnMhs
         lUGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ykEUHH7D;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=SrSBjdlQ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id c2si1108962ljb.7.2022.01.03.16.10.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 Jan 2022 16:10:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 230EF1F398;
	Tue,  4 Jan 2022 00:10:58 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id E3CBF139D1;
	Tue,  4 Jan 2022 00:10:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id oBYXN5GQ02FEQwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 04 Jan 2022 00:10:57 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <guro@fb.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	patches@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH v4 26/32] mm/kfence: Convert kfence_guarded_alloc() to struct slab
Date: Tue,  4 Jan 2022 01:10:40 +0100
Message-Id: <20220104001046.12263-27-vbabka@suse.cz>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220104001046.12263-1-vbabka@suse.cz>
References: <20220104001046.12263-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2616; h=from:subject; bh=ebf99JA0JUFS8hR5i+Q9WIOfxROG6KOiIr2oSEnpdfU=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBh05CAxKL+8XpPG+tHXG/rEDsSOazvUDmcH4h06cbA LlP5mQiJATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYdOQgAAKCRDgIcpz8YmpEH/hCA CU3QxDuJ2g1z5AZ8lVEst2UoUjtcd/fiDDNkjeyQSmkB74sNw+ZLSlLyzTM5qr0yeXV5PGOFHg/WjY rsZso9vUG3xnqeGqrQG9bKWmXcFFcK0OWV3d7RzkgxvJTmHM/cg2xmt8lBgibkdKlXbXirDXvnWHmm 52XEaqrENbNra2dBuT0Xzm7odYeA57SihSx9oKO1ti0Qdcp3b2FswJizgCdEJd1ig9E2QD0hM1Ugj6 v/2pWa9ANC6gywhOicfwhKpEdAdbLLKrTYo2Jl+4Tz8RgLujq2bu9xyNrzpdye7TBo8qOtB5UWCQt9 P+dr2FO9ODl4GfrIYxiyNMB2iWXkKl
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ykEUHH7D;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=SrSBjdlQ;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The function sets some fields that are being moved from struct page to
struct slab so it needs to be converted.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
Tested-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: <kasan-dev@googlegroups.com>
---
 mm/kfence/core.c        | 12 ++++++------
 mm/kfence/kfence_test.c |  6 +++---
 2 files changed, 9 insertions(+), 9 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 09945784df9e..4eb60cf5ff8b 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -360,7 +360,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 {
 	struct kfence_metadata *meta = NULL;
 	unsigned long flags;
-	struct page *page;
+	struct slab *slab;
 	void *addr;
 
 	/* Try to obtain a free object. */
@@ -424,13 +424,13 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 
 	alloc_covered_add(alloc_stack_hash, 1);
 
-	/* Set required struct page fields. */
-	page = virt_to_page(meta->addr);
-	page->slab_cache = cache;
+	/* Set required slab fields. */
+	slab = virt_to_slab((void *)meta->addr);
+	slab->slab_cache = cache;
 	if (IS_ENABLED(CONFIG_SLUB))
-		page->objects = 1;
+		slab->objects = 1;
 	if (IS_ENABLED(CONFIG_SLAB))
-		page->s_mem = addr;
+		slab->s_mem = addr;
 
 	/* Memory initialization. */
 	for_each_canary(meta, set_canary_byte);
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index f7276711d7b9..a22b1af85577 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -282,7 +282,7 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
 			alloc = kmalloc(size, gfp);
 
 		if (is_kfence_address(alloc)) {
-			struct page *page = virt_to_head_page(alloc);
+			struct slab *slab = virt_to_slab(alloc);
 			struct kmem_cache *s = test_cache ?:
 					kmalloc_caches[kmalloc_type(GFP_KERNEL)][__kmalloc_index(size, false)];
 
@@ -291,8 +291,8 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
 			 * even for KFENCE objects; these are required so that
 			 * memcg accounting works correctly.
 			 */
-			KUNIT_EXPECT_EQ(test, obj_to_index(s, page_slab(page), alloc), 0U);
-			KUNIT_EXPECT_EQ(test, objs_per_slab(s, page_slab(page)), 1);
+			KUNIT_EXPECT_EQ(test, obj_to_index(s, slab, alloc), 0U);
+			KUNIT_EXPECT_EQ(test, objs_per_slab(s, slab), 1);
 
 			if (policy == ALLOCATE_ANY)
 				return alloc;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220104001046.12263-27-vbabka%40suse.cz.
