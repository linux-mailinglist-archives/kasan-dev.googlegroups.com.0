Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB2XQZOGAMGQESHKUKWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 80E44451C88
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 01:16:42 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id j193-20020a1c23ca000000b003306ae8bfb7sf6579180wmj.7
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 16:16:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637021802; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y0j3MDY5LWlqyn6vIA3zjnqfBScRYb3rn9zksLoNaVnbHNIqVI2B7RSRZKiKKhmmtE
         QnUvPvEoOKXK+fI7WC/2KVnOv4tFI+d4kkP9pg9WtMWcChpMTZJDAYoK1lvouVksIXwH
         qw+D/C+eYzX1CQu2jy7dtY+45fIYpt8TZ3FedGZbHLYJ0U6OS7N6P+LUEIZ/lYfMZQ1b
         D5E4idF7LFV6zcEhDj+kBj7KbOMK80UA7Lf/4VqL/ydLUzyG6cxtIW2ffrcgseWZ7ChD
         s0kJ9RBNtzbdp/0wV5ZCo5LfeTVxtMfMNBC2gcLd5WUfGoO/aILES4jKCPj7CDOdGsNA
         LC/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/ePCoceuSPRehaRk4ZpZoblRqKfxZxBHyj/UFSJaZkU=;
        b=xq0iJ6huQpNHi/fRObAmfUB3rg2fW+tSEXVKXIXNqmyjHD9QkTKIobOn4K2mFdRBgW
         8zMx+THMCVl9WQ/EbIuNzD2Au9GpvjWyD9P+Vw9xP6vOsmJcOksWF2OHWcg7sTBUEO8b
         s5grVRDQV9pmDUBcuBjsu9nQJdF+44ImJNnYYeOkvCvMFLG7/GgYaxV+aVOoSoZrC/Cf
         USfgoTohRdODs/MUqJCe4aTuO4NMbjo2f2KmpTlSoTQIi42Spxo0N3oMRijLZa4xSGC6
         LfkWkaWrKOgAeq5nGjhWkH/VDuJVjBLcCyH3ZGfxyPuZPxKzk/NG+36Yv6vtR97ORTBl
         qHyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ljDnu3I5;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/ePCoceuSPRehaRk4ZpZoblRqKfxZxBHyj/UFSJaZkU=;
        b=O1amD/yq8NuQ3s8mAuKjJJu4DBRhbexFQBYOnmOA6WuBZ2xvkmML/H44tez5zBKBv4
         1CCvBaJOiAzlQsEUQuAIoDJ09x1YnUuUtX65snkF8LiFXybg6XqvBjEdIqRhFWVqgL3K
         v9EOuuOY57M0qc1VN+GxJzrC4+anxrCCNtLZ0V3H6YlMhqQFfLe+OifDiZuKGGrJcivj
         Es5LO0c5h1PvpWcuT51eZhrc3HNQZDG69C0p0N/aEIhd3MTZEUsNW5Ixiw6/Ev1zECrm
         sK1s/hEogNHBTLfrhOQSlloyNLYjeAeo/cDBtV5XIHvyBiYqKAQHm9SaiUxDMnC2ICwP
         bHHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/ePCoceuSPRehaRk4ZpZoblRqKfxZxBHyj/UFSJaZkU=;
        b=0CVyRTqS82vG26AlfNCU0IAbVpkFsXX9ODRiDqb/DBcG2CKbVxm57jluPa8bJtIKue
         fUhOUqOXPsMcKP7hgXwgptzOFR18AUbSL2XO9t7/nE7ZTxuzfgM5WNozLu8nZQLaSqXt
         LaboT3cxxrQ20TMfHOrbR4ltMvc8GYBPQ2a6JqTDHirWI2RxGj+XIj+6ox2dqjmCc0AO
         OsQcG3hft9A5MyoctTJPbOQ/Q5VQtk/m5qcw5rdaFyfRV+094ocRVD4ViNTh2NhHe3zq
         Jvo40Qvu0bswx0G+bZupBotUH1aYyYEmwRCDc4gTfOqwoKRX3CRmiEHRw6HWys3BX44+
         Y4fQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532sxUffMQXOHK3mH6JRliL4euUJCL7sQl6eUC7gK2deaSb44ThC
	oUJgp6WqEMJSfp+gtKQEFTs=
X-Google-Smtp-Source: ABdhPJxDQwA4LiS+fkSqAGp+5koFH4J3Y+0io5rB1yKtB+Bjx3lhIOYA8Sl0bhbgFJD7X77QvyGl4w==
X-Received: by 2002:a5d:624f:: with SMTP id m15mr3980156wrv.13.1637021802263;
        Mon, 15 Nov 2021 16:16:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls12455816wrp.1.gmail; Mon, 15
 Nov 2021 16:16:41 -0800 (PST)
X-Received: by 2002:a05:6000:1862:: with SMTP id d2mr3921069wri.203.1637021801339;
        Mon, 15 Nov 2021 16:16:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637021801; cv=none;
        d=google.com; s=arc-20160816;
        b=LwVuP2nAS22g77swJbLbbXvrebipzz7Jyg0y7e9VZZaX3Tpyecd0bk1RpuWj837WDj
         gXmSlXMs5ncmx9W679wh9MLErym3a6WB/0Mmg54FbMvuNAohY0ZlsanWIYwqmuDsIOyI
         GtEOPdn3RnaZty6k3UGJdYPAvs2iUXGFNBfGkBIkejmOm25W07FKSA5T0tx0ChHqsuKF
         2gd33HKUtJEbVKDOhy547tP2tAjmCIU+pCJ1li8A3SWjcxUxFovfzclWd2eg2yKSxfi+
         dAIc5vllYm/TOV0d+zaqaSs5zi0GzeeiVznkMsH/VtYW5DW9Y0XjYcN7txaKktOp5AHU
         YmbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=jlcyhF2LLUE3bvmbDw8O0jIb6Enb6GP8zJd72Sp+Bx4=;
        b=En2hCFrTR9Fy3Vpok09edEl0ZK/69epQZGAcq0Sanisy21oyOVPcWQ8PEpTO0Wu/CN
         1H9RN2B2y5qekGSP1nQcoOtBclOCGoQbluEuKmY/JELFDECnxc8qH2QaJuIg11JpK6I+
         WE5c6HppASSBduue1t8bDTKi6R2/Q9Tmc9/A2QTLl8pjTvozKDItSGvXpStd/vlXfdw4
         c8SpostBmV4EEoYFmqUdk8ul4IPI2RP6eSznjpl8N9o5NwE1+Bx2mlSRibeP7c3fSOpc
         0gmFPiQhT2k1dXSWXzcq9H5lVkRLMOTzUG5it4zXOUBRAiLt9IWyrNApa2a6avW6HxOA
         +Gww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ljDnu3I5;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id g130si63044wmg.0.2021.11.15.16.16.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Nov 2021 16:16:41 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 2440E21985;
	Tue, 16 Nov 2021 00:16:41 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id ED9DF139DB;
	Tue, 16 Nov 2021 00:16:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id CMxgOWj4kmFjXAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 16 Nov 2021 00:16:40 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	linux-mm@kvack.org,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [RFC PATCH 25/32] mm/kfence: Convert kfence_guarded_alloc() to struct slab
Date: Tue, 16 Nov 2021 01:16:21 +0100
Message-Id: <20211116001628.24216-26-vbabka@suse.cz>
X-Mailer: git-send-email 2.33.1
In-Reply-To: <20211116001628.24216-1-vbabka@suse.cz>
References: <20211116001628.24216-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2573; h=from:subject; bh=cWCuHox2hs9ihwBAo3Akoy8nEbvO0ofNE6iZX9Rgt+o=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBhkvhOwJgpWqypMqjNDyHsLI3sXHr7P80qS6s2ts/L 3rJka4uJATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYZL4TgAKCRDgIcpz8YmpEAdMCA Ctmcd0hMpy5IvRPb/Zr2eu47QEcHeQOG9jh6KIq86yXC2L5XLTwL71NEz25yxP2Vl6EfzszsDxcTJ0 UOIfIy+r+d+hTADzHqDGs2501lh8/vM07kTBJc5CUF/PVWAPfarkXC31YdAYCGCR2cL+Oc4vtItczY QL9BJZLcGq4vdiGbaLvUZJtxir+AY4jOGi/xRknxupkmzBA7HzvVkwfZ4ze5bIXCR09O1C8l1LJ1hu 4AphWha3BoWLtAOVZL1wayRYAX/0QMQS+kXOEsdUu1bGEU/eXu7lr2vLrs0uQQmMOY/lFaqx10y8ow QqErRy755K3r21yXsQGQYXKe+J+a42
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ljDnu3I5;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The function sets some fields that are being moved from struct page to struct
slab so it needs to be converted.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
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
2.33.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116001628.24216-26-vbabka%40suse.cz.
