Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYUNY36AKGQE4FVFCBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DE13295FA7
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:31 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id x71sf294578lfa.14
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372771; cv=pass;
        d=google.com; s=arc-20160816;
        b=NuozDbz0JvzmCt1JWWczvjwcAa59tVzOYB+8BVuHx1YLudJ6j/OwlqXXTx3dIsSXFD
         M10X5oH8axnGJwwuwbhBJY5S2jX7ewBvDxtNy1iPYsU1aPtjTL50JuIgfuQKjVUXzlqb
         UJPPullDFWctDbsuD3oafcmOkp4mi3+csyXcJLJYZRVDvS6IeLkDQjjgrPwoKv8fkP5u
         rkoGuTs/+bEeoueS7h1M6sHEVQ05kcsxYAMk1XiZ2z8aOfsYxQubPrD3Lw0S5PThFfR6
         opven4V3ezkQJkzZnEaVbhGIXywl6hq/LQv8RgfuCnuvIXA7v7DFRyjx/mx4yc3NLD5n
         6Z4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=66LrKFY7iqoDLfXNTPD8AVMpy9H0iRgSa8JcB0QIVWk=;
        b=ne0YW4ev80WJHHPW/sjzjo5rAbjDtr6Jd4fqlBN6Kj/q0pq2TBqB9UbVcoYzRFQL4S
         nOQ2Qs6dX3o+DHiwZakIBodfkyjzO3bvq+PeZcxvOZZ0sk3dgNaaWyFd0ncXOIdfoPlU
         YSqViyPPyl+lyNJ3grQYQ5kaJpbVODvrveH3qu6BGGdC+wuC3ZSZz91Q9ZO+guWmfkBw
         7VoYDehZEnSvg6dleexTjIiz7ttP+EM15tVMtGETpYY44lkM2vWzS9/Aov+V9z9QA0kI
         oh4vrfMbp/EI1oDvMwVpG2j2cKXkKbnINyDGycgfcfKMKeGScnZR7vjGGv90mXfgyXOF
         tpZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ShgR8nQg;
       spf=pass (google.com: domain of 34yarxwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=34YaRXwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=66LrKFY7iqoDLfXNTPD8AVMpy9H0iRgSa8JcB0QIVWk=;
        b=nXnG5jWFHo7vVAJVnggrvHgEJKfp/nI+GdqljvlBPPBhntn6lJA2mtvvxQbIY3UnYr
         Z31u3Uwo0cEUUP/z5fUnEKbHtkKvmNCjZEorJIMsRrGbCtuIVQ8b1I/Th4swlpRqR0CM
         EPI9WoDMM8Y3/Bbr0vKwIp6aG1ISCa5IIIlTGwB40JOm9SBruIbRlZrt4s6lI7wBYjHp
         q4qs4PoPTiBWA3+c79IOD28iCDoVWEBME4s1rfZgWoHWYUV4g085l4AjTR+xbOEY+39z
         zTuUWaDdmWpS7RrkiMQqK56vXWbpvj5BlEg13v/HP7o/N/AxO7+hziWiVV2yEDttgzHa
         HsHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=66LrKFY7iqoDLfXNTPD8AVMpy9H0iRgSa8JcB0QIVWk=;
        b=nGes2DfKG6Fw7yC4oXfy9mV937rDxNaEMzHwEejUDV3tHUlQkjbej2W0mijw/4AQ14
         5W0jzaW7vZuu/prtWqJ4zme4Y5h3Ez17tNn2z4njHl62krR38QZrltJxzf11Q49nuZ+9
         9oSSuoRTv8tknDu/9TMdJ2SOxzsrVDvgOrNaVaWcPxV2vFa/m60qMXAYYITd1nRANZXB
         0O8P6eqMBoIsQz7SuBMAOGTgW2xFszCqPIkcz9DiYxMT7dhXg8fvnO3KWczH1t1e0SGN
         pySKCLk6sFf6KXlYZItRwXI7QkKqTvs4qtju+W/T8pD6rWsnrFGnygrMz2+sWw+6AtTj
         iheA==
X-Gm-Message-State: AOAM531s/afHuPU6ZXP5j9Bg6ppuA5Y1KsLwfM+/Q+gughlLLXOirtbU
	Mt+d1DnQjCvyCgWp9Umtk78=
X-Google-Smtp-Source: ABdhPJz5TOCQQgsqVfUa5zyoPiWH5Ak1V0iuhPYmjt7nMOyuvIAIfcDOOpVqgYzddVmDMCCUL72WcA==
X-Received: by 2002:a05:651c:294:: with SMTP id b20mr1062780ljo.288.1603372771121;
        Thu, 22 Oct 2020 06:19:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b016:: with SMTP id y22ls334487ljk.3.gmail; Thu, 22 Oct
 2020 06:19:30 -0700 (PDT)
X-Received: by 2002:a2e:b4d0:: with SMTP id r16mr1087210ljm.470.1603372770093;
        Thu, 22 Oct 2020 06:19:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372770; cv=none;
        d=google.com; s=arc-20160816;
        b=0h52ta566HWgraynzB419F47xoQRj13EDibbX0+vOcm9O98XHrkeqrlMkywb44FECT
         4woUIawcdL/Xna9BEZVKWqm1gq2brkr4c9d5pilWWT40zlbmLbOHFANlTBPpXuwAIv9v
         EzOTS11DZY3so4A+jG4Z2kiojhsEbvZ1JLZICRHO9jX18PVjbo1cKD/YdJTKyx4GWvOH
         iZdjB5GnnAfsbGbXJbB7QGcf1lhuaZSpQxIsFIpG9l+BaEPj+VdIcqIKlaPvVUUqLeqd
         pNbK1imZlnjEHgTaNSBNBS9JxlNJjeecAUCmCPaD7Dl+zTtW2fwmVML0cAUgg9yxxSYN
         +LSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=3WRI9oDu6hZ+XySeeDEAjitD0U0NMNqgPQUgQO92Hds=;
        b=pCBK++E7fU37lY9xgmTapsCSqN5fK7Fs7TPzOoFTbcPxdFsQg00qL7HCXqyfJaPPp0
         80+4rxCqHt96sgkbzx+zJYAadoUep/K0NoBxHk2uRc8bQPokqo217hOHtF0Gi78oKrig
         VUXVA9wbqfSX+FBdR/jnCa+MhGI/NHkdmGF3BUUoJ++b4j37dEOMypAjTjPc+bVYxoZ1
         QvF00cY+IuTiLJI7AH1LHgpbWe1A5Y0zDcuKYHuHPIjV5ICFUl1jKnqMOx9KoctGpIQu
         LrRcSsuX04+VZAarWNO222oPxai3VNk/kAp8bNjrDPnoTA5uOV3EUR/eQZn9Z5c1YxI0
         Owzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ShgR8nQg;
       spf=pass (google.com: domain of 34yarxwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=34YaRXwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id i17si67392ljn.4.2020.10.22.06.19.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34yarxwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id t11so618200wrv.10
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:30 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:fe48:: with SMTP id
 m8mr2645540wrs.127.1603372769376; Thu, 22 Oct 2020 06:19:29 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:18:54 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <b205406ea24f189da7fa94f0fc78de8d856858d9.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 02/21] kasan: rename get_alloc/free_info
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ShgR8nQg;       spf=pass
 (google.com: domain of 34yarxwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=34YaRXwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Rename get_alloc_info() and get_free_info() to kasan_get_alloc_meta()
and kasan_get_free_meta() to better reflect what those do and avoid
confusion with kasan_set_free_info().

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ib6e4ba61c8b12112b403d3479a9799ac8fff8de1
---
 mm/kasan/common.c         | 16 ++++++++--------
 mm/kasan/generic.c        | 12 ++++++------
 mm/kasan/hw_tags.c        |  4 ++--
 mm/kasan/kasan.h          |  8 ++++----
 mm/kasan/quarantine.c     |  4 ++--
 mm/kasan/report.c         | 12 ++++++------
 mm/kasan/report_sw_tags.c |  2 +-
 mm/kasan/sw_tags.c        |  4 ++--
 8 files changed, 31 insertions(+), 31 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 5712c66c11c1..8fd04415d8f4 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -175,14 +175,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
 		sizeof(struct kasan_free_meta) : 0);
 }
 
-struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
-					const void *object)
+struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
+					      const void *object)
 {
 	return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
 }
 
-struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
-				      const void *object)
+struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
+					    const void *object)
 {
 	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
 	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
@@ -259,13 +259,13 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
 void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
-	struct kasan_alloc_meta *alloc_info;
+	struct kasan_alloc_meta *alloc_meta;
 
 	if (!(cache->flags & SLAB_KASAN))
 		return (void *)object;
 
-	alloc_info = get_alloc_info(cache, object);
-	__memset(alloc_info, 0, sizeof(*alloc_info));
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	__memset(alloc_meta, 0, sizeof(*alloc_meta));
 
 	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		object = set_tag(object, assign_tag(cache, object, true, false));
@@ -345,7 +345,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
-		kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
+		kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
 
 	return set_tag(object, tag);
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index e1af3b6c53b8..de6b3f03a023 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -331,7 +331,7 @@ void kasan_record_aux_stack(void *addr)
 {
 	struct page *page = kasan_addr_to_page(addr);
 	struct kmem_cache *cache;
-	struct kasan_alloc_meta *alloc_info;
+	struct kasan_alloc_meta *alloc_meta;
 	void *object;
 
 	if (!(page && PageSlab(page)))
@@ -339,13 +339,13 @@ void kasan_record_aux_stack(void *addr)
 
 	cache = page->slab_cache;
 	object = nearest_obj(cache, page, addr);
-	alloc_info = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 
 	/*
 	 * record the last two call_rcu() call stacks.
 	 */
-	alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
-	alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
+	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
+	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
 }
 
 void kasan_set_free_info(struct kmem_cache *cache,
@@ -353,7 +353,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 {
 	struct kasan_free_meta *free_meta;
 
-	free_meta = get_free_info(cache, object);
+	free_meta = kasan_get_free_meta(cache, object);
 	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
 
 	/*
@@ -367,5 +367,5 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 {
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_KMALLOC_FREETRACK)
 		return NULL;
-	return &get_free_info(cache, object)->free_track;
+	return &kasan_get_free_meta(cache, object)->free_track;
 }
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 7f0568df2a93..2a38885014e3 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -56,7 +56,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
 }
 
@@ -65,6 +65,6 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 	return &alloc_meta->free_track[0];
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 5c0116c70579..456b264e5124 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -148,10 +148,10 @@ struct kasan_free_meta {
 #endif
 };
 
-struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
-					const void *object);
-struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
-					const void *object);
+struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
+						const void *object);
+struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
+						const void *object);
 
 void kasan_poison_memory(const void *address, size_t size, u8 value);
 
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index a0792f0d6d0f..0da3d37e1589 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -166,7 +166,7 @@ void quarantine_put(struct kmem_cache *cache, void *object)
 	unsigned long flags;
 	struct qlist_head *q;
 	struct qlist_head temp = QLIST_INIT;
-	struct kasan_free_meta *info = get_free_info(cache, object);
+	struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
 
 	/*
 	 * Note: irq must be disabled until after we move the batch to the
@@ -179,7 +179,7 @@ void quarantine_put(struct kmem_cache *cache, void *object)
 	local_irq_save(flags);
 
 	q = this_cpu_ptr(&cpu_quarantine);
-	qlist_put(q, &info->quarantine_link, cache->size);
+	qlist_put(q, &meta->quarantine_link, cache->size);
 	if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
 		qlist_move_all(q, &temp);
 
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index f8817d5685a7..dee5350b459c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -162,12 +162,12 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 static void describe_object(struct kmem_cache *cache, void *object,
 				const void *addr, u8 tag)
 {
-	struct kasan_alloc_meta *alloc_info = get_alloc_info(cache, object);
+	struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
 
 	if (cache->flags & SLAB_KASAN) {
 		struct kasan_track *free_track;
 
-		print_track(&alloc_info->alloc_track, "Allocated");
+		print_track(&alloc_meta->alloc_track, "Allocated");
 		pr_err("\n");
 		free_track = kasan_get_free_track(cache, object, tag);
 		if (free_track) {
@@ -176,14 +176,14 @@ static void describe_object(struct kmem_cache *cache, void *object,
 		}
 
 #ifdef CONFIG_KASAN_GENERIC
-		if (alloc_info->aux_stack[0]) {
+		if (alloc_meta->aux_stack[0]) {
 			pr_err("Last call_rcu():\n");
-			print_stack(alloc_info->aux_stack[0]);
+			print_stack(alloc_meta->aux_stack[0]);
 			pr_err("\n");
 		}
-		if (alloc_info->aux_stack[1]) {
+		if (alloc_meta->aux_stack[1]) {
 			pr_err("Second to last call_rcu():\n");
-			print_stack(alloc_info->aux_stack[1]);
+			print_stack(alloc_meta->aux_stack[1]);
 			pr_err("\n");
 		}
 #endif
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index aebc44a29e83..317100fd95b9 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -46,7 +46,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (page && PageSlab(page)) {
 		cache = page->slab_cache;
 		object = nearest_obj(cache, page, (void *)addr);
-		alloc_meta = get_alloc_info(cache, object);
+		alloc_meta = kasan_get_alloc_meta(cache, object);
 
 		for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
 			if (alloc_meta->free_pointer_tag[i] == tag)
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index ccc35a311179..c10863a45775 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -172,7 +172,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 	struct kasan_alloc_meta *alloc_meta;
 	u8 idx = 0;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	idx = alloc_meta->free_track_idx;
@@ -189,7 +189,7 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 	struct kasan_alloc_meta *alloc_meta;
 	int i = 0;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b205406ea24f189da7fa94f0fc78de8d856858d9.1603372719.git.andreyknvl%40google.com.
