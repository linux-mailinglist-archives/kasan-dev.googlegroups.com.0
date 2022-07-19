Return-Path: <kasan-dev+bncBAABBLPN26LAMGQEXU7TEJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 17409578ECC
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:11:26 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id n21-20020a7bc5d5000000b003a2ff4d7a9bsf4837145wmk.9
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:11:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189485; cv=pass;
        d=google.com; s=arc-20160816;
        b=RoDB5D/ta3hVbuos9G3GYaNM9ujTfiLuKGE/QV+91xqNjtBqK2XwvGOpb4OAoT8uHL
         Zxqv59wRGqt3uLGMH9o8zsKwkO2xoYBBOVpIwZcPVBaWjQFrPFYk23MnGh3m2NIkfmUB
         xk/sXbd/bD+pf21vJZiDnEyKzByuB6H22O0baFNjCgP6mNgYlFeARlGzw7pFp/gY9zR4
         U97umwlmunnkE03+YNNcTilYBTOW4TE7AzBWC/Mb7M1FZ69BaKRvdpOwHRyXWKtk77v5
         0ESM6Zz2gHY4wIq1PYVjPo0SjmrC3lEbL7fukGPiRNnc0BIOiXRygJC194SG9MEqRREZ
         EZig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fsX+SwQaijRj76/fzQWAvW0HnDEr939Z9ipEvGIWjtk=;
        b=ZlHLaUkBudeUDx10iMVNuEXbpLHQpcax6IoVQ91ozo8m+OoZebO7B6HXxXJP8NO8DM
         Is/eONJP09FxY78WaFZJ1/a9EbkWlEs0/X/dlR1ioFOospwVllhHqIXTtybKXLFcFP6f
         rUWAEM+V+SsN1hYy9FZXAkp4UzkAeFaf7/kxE+7yQhPR8ssD5w2f8iDLD8OduMj58nEU
         Q1uNWHbKCFLd3AN4ni0Vs+3Gv3iZKiA7JUDaDSAccAoqzWQZNQnq8sLMYOYq6LLt4YAg
         z7wBU6Fs/8P3lY1konFyvW0FBjqSnHyZv0Ws55pWJpXT0YN6EXfMD+fnx2zwYR5tn0uj
         eUxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fT298j9m;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fsX+SwQaijRj76/fzQWAvW0HnDEr939Z9ipEvGIWjtk=;
        b=QM81hUnmTHo+8LyU+4Zy+4/wNBVEiSwZJEglTC5e8K9vtULrzJJ7DAxjHOqliRzKKb
         7MBcdk92Pgupb96/JMz8bkqOs7AC6quSZLMpDQM7VDvxNUaLgQe+kRPZfChxHoLuxHh0
         lvCNoSEFc87+xSGAy5Qhi6OYHg/selB0hAU7/f8CcerqOUDfcmVNKgjo/04cE1xOk1Jf
         IOZ7zxW/uxAh/I84SK6yeY3NVD2nLyEqP8g9xkE/Poa4TF4EJBbK9KQj0VUPsOHmHmm2
         LL+Qk/tUJgTX6Qqk8Za7qEPQJbnvPnal7vPzm5mgVwpeSr6+m3Iy54POHzBpCmWNJlB0
         qjlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fsX+SwQaijRj76/fzQWAvW0HnDEr939Z9ipEvGIWjtk=;
        b=R8EO+xsUkgrU6zXZUeu13cwzCaec/w5ulw+10utFxUpemFbNh/ADAzVzY7/0duUDsZ
         4a7nz8HuruLILdSqQtA6Pt93GhaJTguStFePbcM1rh3f/IeGNN17grdMCoay51Z1qUuV
         2T68CjxBKj1UyMGkbQ4j+Vg8rrgDoEYt0NzDJNs6T+XIwSdIx2pQApNtsncyy3QvyxTB
         gYcRLPnfYJP5t7QLTrBvfcB7Ooc3XLFrMRcm+b45bjptreF8ih6gdXe+pCPG8GCpXl2a
         MEYDuy2OReuRpL3YyfragcQYFiHprCOlPNx9lJxTdk03W+BUOHinSkdP5GSmSKr8oOLM
         6B5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9q44XYXfDrnWBpyH/vvMwYqJHp9qrLBoPGzmLYKCQZJX3dkFYl
	ADtO4LNpjTjdUeT/+TKNWZQ=
X-Google-Smtp-Source: AGRyM1ssookgN9jDej8/6Pq2oL314FaAeU1kaTUBsy7Eb+GH7U5Lz7ZS9zblz1vQRjJsl7drr7u5NA==
X-Received: by 2002:a05:600c:4f48:b0:3a0:45dd:8bd5 with SMTP id m8-20020a05600c4f4800b003a045dd8bd5mr35269477wmq.80.1658189485700;
        Mon, 18 Jul 2022 17:11:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbc7:0:b0:3a3:19d9:6190 with SMTP id n7-20020a7bcbc7000000b003a319d96190ls41052wmi.3.-pod-prod-gmail;
 Mon, 18 Jul 2022 17:11:25 -0700 (PDT)
X-Received: by 2002:a7b:ce8f:0:b0:3a3:150c:d8ff with SMTP id q15-20020a7bce8f000000b003a3150cd8ffmr11258680wmj.152.1658189485042;
        Mon, 18 Jul 2022 17:11:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189485; cv=none;
        d=google.com; s=arc-20160816;
        b=WdXrdf2UDYBCRlZAq1PmS758GaIw1m5G+Eyb6cEHOhJcWSKSenM2wmpd5fj0BxZWJ3
         qFuJlZMk77mktWaAAHLa6n0Da9IIjzwo5hpEJnc5XZS80KTYucBTdq9l9qUQVj96C8aJ
         WiR9Awc3ko3MfLcNlOSLEq9J+2+yeCrW3e2E3ShScy9adcsTp8IXUS6Fz9FOPEAqz+j1
         F+4c9/UdVYORPa9QodvgxUixX6a7afBHKYOV2p+xR3JG8Z3XpuFqd8EF9qIOyqctHpTv
         HJsleFXecLtF79/cVMnV91MfyRrxOfCGuY1iVsNzgIQqcZKDHEreZnmdYqa7R5y1CHNY
         VD1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7hpsrcZa6raPAkQKqOapEqD/IGxCajqUwWoTNw3lCzg=;
        b=mabTKdvaIOgQGFcqNBQjuoBBFjANtUAUh+2rO7P+fguUgrqrzyaNNDiFBKZu7MT/Oi
         DSCmU0iiVeFXhuNAGuVnh6iCAeJ4/K0buLImEgkjDuVTXsTY+mhpriUqOwzca9nfceN4
         PsAuSQ3C65rak6CSGSm/3emncUpC2BeU5DT6PhgE2TFQwrtYopWLcgiQEgAb1zvvPnHg
         sJkN5vtIPRejvywbkpuDn0hSIwrxheFmyxoF8ggRj1B15Hap1wAAmN/spzg6943cveOk
         N2WT3LUlchHbizJNoDSdYr7BQkcgCIjRgpv9UaLC/M2XGG52hrO9DnpNTGUL2ds+TQWW
         MG4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fT298j9m;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id k23-20020a5d5257000000b0021d2e06d2absi366374wrc.3.2022.07.18.17.11.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:11:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH mm v2 08/33] kasan: introduce kasan_init_object_meta
Date: Tue, 19 Jul 2022 02:09:48 +0200
Message-Id: <fab6a675e736c1ef21563a216b09b92383487ff9.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fT298j9m;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Add a kasan_init_object_meta() helper that initializes metadata for a slab
object and use it in the common code.

For now, the implementations of this helper are the same for the Generic
and tag-based modes, but they will diverge later in the series.

This change hides references to alloc_meta from the common code. This is
desired as only the Generic mode will be using per-object metadata after
this series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 10 +++-------
 mm/kasan/generic.c |  9 +++++++++
 mm/kasan/kasan.h   |  2 ++
 mm/kasan/tags.c    |  9 +++++++++
 4 files changed, 23 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6156c6f0e303..f57469b6b346 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -312,13 +312,9 @@ static inline u8 assign_tag(struct kmem_cache *cache,
 void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
-	struct kasan_alloc_meta *alloc_meta;
-
-	if (kasan_stack_collection_enabled()) {
-		alloc_meta = kasan_get_alloc_meta(cache, object);
-		if (alloc_meta)
-			__memset(alloc_meta, 0, sizeof(*alloc_meta));
-	}
+	/* Initialize per-object metadata if it is present. */
+	if (kasan_stack_collection_enabled())
+		kasan_init_object_meta(cache, object);
 
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
 	object = set_tag(object, assign_tag(cache, object, true));
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index f212b9ae57b5..5462ddbc21e6 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -328,6 +328,15 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+}
+
 static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 {
 	struct slab *slab = kasan_addr_to_slab(addr);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b65a51349c51..2c8c3cce7bc6 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -279,6 +279,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report
 struct page *kasan_addr_to_page(const void *addr);
 struct slab *kasan_addr_to_slab(const void *addr);
 
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object);
+
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 7b1fc8e7c99c..2e200969a4b8 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -17,6 +17,15 @@
 
 #include "kasan.h"
 
+void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (alloc_meta)
+		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+}
+
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 	struct kasan_alloc_meta *alloc_meta;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fab6a675e736c1ef21563a216b09b92383487ff9.1658189199.git.andreyknvl%40google.com.
