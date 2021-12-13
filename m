Return-Path: <kasan-dev+bncBAABBBEB36GQMGQE4MNL6VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id E4DF94736C0
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:52:04 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id g81-20020a1c9d54000000b003330e488323sf6727308wme.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:52:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432324; cv=pass;
        d=google.com; s=arc-20160816;
        b=LEsThwIP6fl6SM/GXbdO/jjHWr2nYGWXqxo9CM7Qp4qmIxAA8atUprEhYb/Ve6JOzS
         DQYNvES66hE4Uz/HAx5XYRPLFhWruSlfGBB4tc90d7iRjJyHnOqMq0A2FlPNeRtJ/qnj
         pMsAmhWDpkdHK6JpaXRt9gB3858JmhoaqcyP+rcEw7YjCisotmACrOnGqPukdD4A+Kx0
         7Pzewy7RCrxCPH855K67hxPbKBRISEIRwK41ZxMqNZkn6nmpy5JNN/qEc58RthbdXr7K
         xZ+HwIzdiMrUD6bhDYBFHgezBplMxqENwwp5NY3BXrdkZ33enwv0SGz1CwNRKxz45KW/
         7gcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XbgBXhgOQ0wbHQoiAQ4uITqGLKiw5w1OMsYk2Vmh9f4=;
        b=g118V100SanwWzK6iihrvkzCwh/4RHwh7u3fULPa+eBt5V/N9TP9SsNzqP9UaBtbIY
         Zo+hGfXuMJyDUxCakLnxQivwUddMKe8GX1VNz5kN7qR9jeY8WKfp+5+BEdFfJ7ZUjeFV
         zRIByKu6d+9MYQ+UwvqxLeKkHryovk5Tg1SiSv7JQkFGe76MDp5DVUIu/EZViDEYwCQW
         TIWIDAeUNqVzU0dmrpuQsdTaLykcgk6tXs6STQGGLdOPzJAz6bQr2ul9YTTi2bkP4I1q
         OTkvLfodIWyda1tjbMbjOKPpdKbeRTt6Moh5tnLX/rzoZfxt1RNAXKeXSsM9Xvz5itrc
         bX9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pO2y9wB9;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XbgBXhgOQ0wbHQoiAQ4uITqGLKiw5w1OMsYk2Vmh9f4=;
        b=EmDWmURQsizuSUqguWHKUDLCpAzcgo3wJawrsHHzu3LKa1Buqq6KAleIeituR73kSx
         p4FcDGEifhscfpvMEbJ9jSLsoyLpO6/1oVC+J9XtzFkoRCyW+AHR+XMvf59FouyEPvPI
         e+DLxashtB7sK7eAnTitTcOn3KG3FJzAYdXxezfRGCaCBRjCOtcsqHzS3qWqkyV3WRs9
         Y2283SAwHBWNhgMacE0C0pJKkBpDoH0Yg+++8OPIg+sFiT/5BqM6viXkX2GwF2yzUZFH
         0vgLOki5cNnKaOoI9SGM+ZXpA4HAji2FGyiTxQHPG8rKxdwFrdCVdfUkp+tzj5Ap/AqZ
         8Sxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XbgBXhgOQ0wbHQoiAQ4uITqGLKiw5w1OMsYk2Vmh9f4=;
        b=sy/47CAHrs4RIjdEzkkqTXxpVHV+kHqveCnYr1iWXS8lQhV8FRgtXL7BDyO78gHCTl
         RH9xScZxwA/+HIV0KP24uxx7OtfJB3Hf5sImFdvSfcGrnt8RCQqVieki9nDnmRbLk/6j
         3Jpcn19eM3+ubQDTl/Oz0JsF/Qnu/I9f1bKJy8qXTp1O/zPN3+REWCczYXNsgj39eOro
         s6zJoQUroLReVm+yl5y7dQLVlWohK7JP9DrAtRw5mx+XmhydQO2pSJkvF5G0hwaRY5/Z
         l5y2EaKarXvpgdFqxPPsa8jljdaoveZ54X0yNBYqojHcE3GaX+wVC7pW+YhtAQi4sLVK
         KPUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qFEETrE57BbVpS2rHwqQ7OnAWU30htMYc3zgcMpJGhy8taAVi
	movCxBCT1RkWB7UOPcpep1A=
X-Google-Smtp-Source: ABdhPJyY8TWFfxSO6pk9yGku+eWZfZfpuJTBSWlNvxj9xM8rwE8BXoLnYhqBRlx9gR5GAQKQjHP5oA==
X-Received: by 2002:adf:e482:: with SMTP id i2mr1339544wrm.284.1639432324481;
        Mon, 13 Dec 2021 13:52:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls496175wrr.0.gmail; Mon, 13 Dec
 2021 13:52:03 -0800 (PST)
X-Received: by 2002:a05:6000:1885:: with SMTP id a5mr1255311wri.258.1639432323717;
        Mon, 13 Dec 2021 13:52:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432323; cv=none;
        d=google.com; s=arc-20160816;
        b=WjZvkmJ5KpHVo4XZtlOTDTzZVwvu8nYE1NzcrTpJXiz70vxsnqkj3svyecO7BnkPrn
         KaqXWrRF6v5kWLl1/OelI+ZjIXxVHP9Wal2t55cG3iw8Rr2RwGdFATrqYaKsWnz8Eg93
         Tg8luWWWzSCAJYmxnrkTJys2DkuqE0jdnGiMRvcVRb/BxifQSK9SGgPIJQ/WUVNMWSVg
         w6tt8GwIVypVZ2gAt6LVo8IT1/GrcVrRiw2R/KVR9Dn9JrjBzuW+jIQXmDurnprBmqsR
         4WYG7ZNL7U4zhfFkx5II1UvUVjaNsPhckQyRO8C4L2x6VkHXZ2WrgHc1GAJPTVWDgZNS
         q86A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HTPWk4VEgIiC15H1k53BSSNevm2/MKWkVZ7PL0Pz+og=;
        b=IJwrq+3MJkzrQkEY4uYSd1hI3ZyA2AfzHReBQxs9kBFaeLzD4UufwvLBrpk/s2IarC
         bFUzZaqC6mFwBUtwre3JWVOJQ5xynnTFMAjW9R5p5HdPfSr2FscBqbW49qecQy2SNRB2
         95BO8/DG7Aq41PN1xP/vHeS44sa79A5R8ezCFA/nzpyb3hX4QuAgu/dwTH9pKdn/GUE/
         vhRyj5NFMUx28A3H+PIUPzIrtdITkUyFixqkTzRvs0kY+6prEDFiYOcn8LBYzXiZ/0Vy
         CzlIzD2WSbKDFBRoDnd2UBHH5skxzLaNLAn1SdsilDYp7822haALiIJUQFneWQFcuHPd
         Suuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pO2y9wB9;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id o19si14809wme.2.2021.12.13.13.52.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:52:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 01/38] kasan, page_alloc: deduplicate should_skip_kasan_poison
Date: Mon, 13 Dec 2021 22:51:20 +0100
Message-Id: <3423b7a9e4ba814fc77df37267a3f7911490b1db.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pO2y9wB9;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Currently, should_skip_kasan_poison() has two definitions: one for when
CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled, one for when it's not.

Instead of duplicating the checks, add a deferred_pages_enabled()
helper and use it in a single should_skip_kasan_poison() definition.

Also move should_skip_kasan_poison() closer to its caller and clarify
all conditions in the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 55 +++++++++++++++++++++++++++++--------------------
 1 file changed, 33 insertions(+), 22 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index edfd6c81af82..f0bcecac19cd 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -377,25 +377,9 @@ int page_group_by_mobility_disabled __read_mostly;
  */
 static DEFINE_STATIC_KEY_TRUE(deferred_pages);
 
-/*
- * Calling kasan_poison_pages() only after deferred memory initialization
- * has completed. Poisoning pages during deferred memory init will greatly
- * lengthen the process and cause problem in large memory systems as the
- * deferred pages initialization is done with interrupt disabled.
- *
- * Assuming that there will be no reference to those newly initialized
- * pages before they are ever allocated, this should have no effect on
- * KASAN memory tracking as the poison will be properly inserted at page
- * allocation time. The only corner case is when pages are allocated by
- * on-demand allocation and then freed again before the deferred pages
- * initialization is done, but this is not likely to happen.
- */
-static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
+static inline bool deferred_pages_enabled(void)
 {
-	return static_branch_unlikely(&deferred_pages) ||
-	       (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-		(fpi_flags & FPI_SKIP_KASAN_POISON)) ||
-	       PageSkipKASanPoison(page);
+	return static_branch_unlikely(&deferred_pages);
 }
 
 /* Returns true if the struct page for the pfn is uninitialised */
@@ -446,11 +430,9 @@ defer_init(int nid, unsigned long pfn, unsigned long end_pfn)
 	return false;
 }
 #else
-static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
+static inline bool deferred_pages_enabled(void)
 {
-	return (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-		(fpi_flags & FPI_SKIP_KASAN_POISON)) ||
-	       PageSkipKASanPoison(page);
+	return false;
 }
 
 static inline bool early_page_uninitialised(unsigned long pfn)
@@ -1270,6 +1252,35 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
 	return ret;
 }
 
+/*
+ * Skip KASAN memory poisoning when either:
+ *
+ * 1. Deferred memory initialization has not yet completed,
+ *    see the explanation below.
+ * 2. Skipping poisoning is requested via FPI_SKIP_KASAN_POISON,
+ *    see the comment next to it.
+ * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
+ *    see the comment next to it.
+ *
+ * Poisoning pages during deferred memory init will greatly lengthen the
+ * process and cause problem in large memory systems as the deferred pages
+ * initialization is done with interrupt disabled.
+ *
+ * Assuming that there will be no reference to those newly initialized
+ * pages before they are ever allocated, this should have no effect on
+ * KASAN memory tracking as the poison will be properly inserted at page
+ * allocation time. The only corner case is when pages are allocated by
+ * on-demand allocation and then freed again before the deferred pages
+ * initialization is done, but this is not likely to happen.
+ */
+static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
+{
+	return deferred_pages_enabled() ||
+	       (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+		(fpi_flags & FPI_SKIP_KASAN_POISON)) ||
+	       PageSkipKASanPoison(page);
+}
+
 static void kernel_init_free_pages(struct page *page, int numpages, bool zero_tags)
 {
 	int i;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3423b7a9e4ba814fc77df37267a3f7911490b1db.1639432170.git.andreyknvl%40google.com.
