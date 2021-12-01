Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOPXT2GQMGQEHWTMLEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DAD84654ED
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 19:15:21 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id l15-20020a056402124f00b003e57269ab87sf21025210edw.6
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 10:15:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638382521; cv=pass;
        d=google.com; s=arc-20160816;
        b=IZI5B/n5HNQsy0e+b5Utq3xmCHq6q2EU5Z231I5g5tpa75+OhHQ17sMV18GN63zgoQ
         wVqSsoS9zkRojbMz2IH72gAg07m2lxa87iXswVBc8ioa03BAF2tSKp5kQCIARsgkXWuD
         dwuDCYwjFK5hpErtvd7xwftKpLmTO+6pFHcfoP8mpQu0Nio4cT6R1q17Z1BFMCf5l0qV
         OuvBO8HWDzOCwwAx6SS+WzZOOG5G4ZXVNc7w+YyJWUm+NYQhjSR5VxjUFqDECTUUGpCB
         47weytbjXTJfj795nKelX4E0b9lzYEZlsE0wi7AT2I5AlWRwCqJcZyuT6VU+6vSJLD9x
         ti2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vETDZdWXgbKxYSX5jlmn4YVVYO1Bcf3pHB+HUhaSMMg=;
        b=czF3Zg3EqslCkJAaTmsvRn0KtmU4DgWlPVO35G6X4i98LDX8IxvzD7GQymJET8hENA
         FuVBXLrlIMHF7HUdXv28hDvM6JQ1Xq/OC5IVPSeVSVF/dsk88BiKA9r7Jeeyhn+cOEQp
         3TfnASoY41euB261DJrrECQxQBIrU4ssNK8ND6lQHMjiTn4I4Y8ph+I+B2jhTAImNTzd
         Vb/VNeNfaYXvPFO9AG1bKGITSWEacu9X1n+/ModKH6qpKYYRcGlsIh4A4NI4nuLu46Ec
         xiBA8bx5wccuf4z0dlgLYV+zRSlNcmAcD6H8db+5xFDZJzJGZv7x2rvdOxh4dxhn790E
         gWCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="ELzro/zI";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=kmr6F2+S;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vETDZdWXgbKxYSX5jlmn4YVVYO1Bcf3pHB+HUhaSMMg=;
        b=r9GJFAsKxCjBMq16PwydOM109IyF4NIdqzBC3lGGMkC9wnAMvD7zuEM7+RiV+xaF8o
         C0qKk3AJvqfe3N+8uOl1aibPoVT2dOKZ8EipsWNU3oB+0k7/7jKAm4kHXz0T2EFLjqG4
         im00IAZA1DPxVjMVp8RTdcat5vSVech2cjjzvO1diQMbpChuP5EI5neeWKxwGFwe02ey
         ZEPM4LqkHSH9oMRrrOXiGkUXB9zpxGLKusqqAKSt03wqB63fdS3tWgwyPFLfcsmi2zGA
         v7T3g01+OJbOAPEzjQDneBkLK068Q5Qg/2NsHIlN9tiUrrOtYj1S2q4T7GQ3mWZq1kHn
         bxzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vETDZdWXgbKxYSX5jlmn4YVVYO1Bcf3pHB+HUhaSMMg=;
        b=FcteUtKfyFzUzbftJC6PLhFJXnldiVlZnAxZq1XbxMcWu6Vw+rdnkoL5ayS2gfCZzS
         7MTdQth9e/XjSjt+CFhSwPMt8LfOSEoVz21Wx3U0S3+Q+VuUZx3n3SCL7RSE8aSOs12K
         1UEjxX3PB56smUtmy3vkIcpX8DgxpaM59QTGdNCoBkVHv1pVegwBAUe5heXhPGiloTb3
         YAzYYW/vinDikrdRzJViWCSVpV4O8Cgoykw9B35WAme1tp4qEZ2L5Dzv+Uy8fFiZvyvO
         8EDK4WFxSUhRDzYVYVwOhC1v09FKvM/yCFenPXswLVVaGXvqtYNpvYCoDYGl9eVDGEUy
         AICw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530rPWgQAMCp//PtJYt1EvWKu8NfjbRmwssQv064K0S0sGt1kar8
	G4DQFMNYjcmL/sPVncjq/TQ=
X-Google-Smtp-Source: ABdhPJyhFAKj9Y/1T38r6VYVNzbZnPcxqhmNfQb8bfEGO9eu5b8n9ukCd/SP5RJtF5hQQiFqOB1oiA==
X-Received: by 2002:a17:906:974c:: with SMTP id o12mr9167914ejy.229.1638382521189;
        Wed, 01 Dec 2021 10:15:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c944:: with SMTP id h4ls3693023edt.1.gmail; Wed, 01 Dec
 2021 10:15:20 -0800 (PST)
X-Received: by 2002:a05:6402:5cb:: with SMTP id n11mr10812596edx.279.1638382520260;
        Wed, 01 Dec 2021 10:15:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638382520; cv=none;
        d=google.com; s=arc-20160816;
        b=ZslHEKQb2VcNW9SxFqJ+NHzq/VIGoP9UmHgyWIvchD58SDdFdHucIiwufqqN/W09Uu
         T08YCXg+fgnHuLACIs+mNFlH1d/AlfhUt4V7lwuh3d0BvofmY9wHPCNtB1vp2KZkW/Gn
         GMLSU+T8vIeNfTAQW5Nb9+ASGnxe1tzDN+iFoYOtxlMs8lg0ugzEVpojHjngyZRP0qSr
         aqZIvGqpud1uE0mrw7KmTyMZ3VNnub5wR4/kDmJRym7n4hblOrlbEE96RkDG+N92PP7Z
         JAntZutggxNLgi3lgyVPSzqAGPjg+J5UyCSN1uTVZYQuENxGuuvQzTvvrKLrDB+xNKgz
         jK0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=pRNn3FUWmIkB+AIBt8k4Hc3p8VqTdjyb4KkYPCXkybg=;
        b=bZdSnKjzlrqP4ij4urX9yO7dFGz0n22zfJ5cgPnZyuX1rasqRvjrbwOALmCMQpTBvx
         bSws1GF+voQt7ewDzILLCTFC2AHB9takB7wzsDEPw/syCzIVu3KdfnMYWm4l7GhAt6J/
         uF6WVpm5e83FOoIECSgMz/lTv7rV6M1dCoBzpxEQP60lbXjfQ4XTfNlEG3T1EpuQJ+DQ
         CEuP+tA9U7B97TCT7Vj1xGRJlJ+yQOo1aknUnJ5PzIeJGrtXBLP2l1c4MHLtJWRWi7wj
         ch3W8NR3ZVlWbSXwDRTRmHpYlDKecd+FTT/mtSfTuDskb1rsUHZddC61AkA2+bKckuIF
         HBYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="ELzro/zI";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=kmr6F2+S;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id eb8si52623edb.0.2021.12.01.10.15.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Dec 2021 10:15:20 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0A010218E0;
	Wed,  1 Dec 2021 18:15:20 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id D33C213D9D;
	Wed,  1 Dec 2021 18:15:19 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id yAUOM7e7p2HPSAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 01 Dec 2021 18:15:19 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>
Cc: linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>,
	patches@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH v2 26/33] mm/kfence: Convert kfence_guarded_alloc() to struct slab
Date: Wed,  1 Dec 2021 19:15:03 +0100
Message-Id: <20211201181510.18784-27-vbabka@suse.cz>
X-Mailer: git-send-email 2.33.1
In-Reply-To: <20211201181510.18784-1-vbabka@suse.cz>
References: <20211201181510.18784-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2616; h=from:subject; bh=+CNHtzGum/tOmd/kW8GAUx888uquumIQ2d0wfPG8TF4=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBhp7ubr9qa0wQH93+qc0CSNF9NLizxF8+su0OTZzLH lGacLvSJATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYae7mwAKCRDgIcpz8YmpEJDXCA CpJyrm/iqqE/v6T1tHy7bIGV5jHGrybBMM/EmUqQSj86aWhtP8Oi8CPAIFBtOu+CTFldmPk4Nh/0nq uw93aFHn4LHexWfSTIp53E0vyNSuHBYqtokdvrdbJN848c4mu37p5Ip8eLzmFavLDfrBdCoQYkGvpL IEcYpRa+yB8sVCIywEoZSrPi6OQwzslxQspXoZb7yM7Pm6AHdV/uPNfOui/2aRHVfFh0nYWuvz6ER2 WK77d7PonT7Mpg5p4Hwd82vtUvdGkz/R4PMOTbU3gIYV5zFvZ+2VOTvua7gTWrKL/iQG+0yxHKrhZf QchjOVxsNvaOcxzNOGhcIz4RzdVBRz
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="ELzro/zI";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=kmr6F2+S;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
2.33.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211201181510.18784-27-vbabka%40suse.cz.
