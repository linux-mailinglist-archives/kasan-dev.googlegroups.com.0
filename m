Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEWE3H5QKGQERJIF5VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 50EEF280AFE
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:15 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id b2sf125523wrs.7
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593875; cv=pass;
        d=google.com; s=arc-20160816;
        b=nlIIMwcJBKK8BEjninKcXwvEWhmRkloVM4CuWnJRpbWZajTOD55WPP9qq1Y5VqoiOJ
         EQQQ8UzqwlNlbapMm9rc3I8Lwt7ABqvb7LyLje806u1s8+ePnASf1YikgGnIsu9gZhdn
         7UX+lZi+yxOzbqZ0RJpOtV1JMQiFDhCJvlo1gapraPhvZDFPcB8w8OyuygLUGJkPktfP
         GdZE6jLEuweqPI6vNdB8j46OBPp+PD9oAioYDemWjGKR7Ik8RDL69ZM6qGbvPpLqr8t1
         dNoZajE+LmLKrXD67AC1dKDt/BAcs9mEG4DzRf8RjXFmDxquboQxWvUJWHKa4B06GX4J
         Gw9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=WXScPBtPW2aLiZOtD/bpIDvMaHNSFyJF93/VcscRSDs=;
        b=Zm+IAjd9d6jPz4H9xzl8rwANwE4nloYDVvVGZ3vnJ06d6Vog5f+uOcoQlZaSjV9tk+
         zuRQN/clIcYYGuJA2JgPmnhHOby1uRTD+O7ma0v+k7NV92cvcwJ+ivFzz5zY1A6mux48
         7Ynz2iftReeQ1xaalKI7RfB4l38ceCh4XiEFysA60LxCYsxdpK43dqHPN2fBZlGCPdHv
         doEaWf4nDSvaaQ1mWAJa4KodxZNJotUqHNI2SaEgPM7tRD+BnwenpDtPNvFzsJGBFXyW
         Rf6EPBuN80412NrMGCBX0TDoPgVwHxTUvTSOmvkhn0DdsqDG/VOQJA9Qu/5D5Og/pohj
         VPGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iBnDmdG2;
       spf=pass (google.com: domain of 3ewj2xwokcbaqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3EWJ2XwoKCbAQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WXScPBtPW2aLiZOtD/bpIDvMaHNSFyJF93/VcscRSDs=;
        b=QyXGbruZk5dGu+2OYCFLFBWKgRx7SvggVzB1YY8JyzzwOw5bdbo+Gp/a6CtYIm826R
         4CCGCzq0tXAxjm3u5AnI+RjfYxGP0EkS+U2iCuIX/BXBV+tGxp8aiOWApFt5zQ8IwGwK
         n/wp6y4TUcVorLIo8YbAfZY8KXs7bvREwgplEPwtouMI2DF/ouuXdQWEzO/TMYiK1zJd
         w20dT2yDY7C/M5ywH1UEM/py5c174pfKE+tsgoYCeZQ+9Vzl/GGJRRm2hbR9VxxP8Tqt
         KzfI/lkuD4MB2ymsi2X+bwhksNT3dvezUH0t2lltvZstmWXYJJ8W21FVjlsyXFyGb0ZM
         FEKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WXScPBtPW2aLiZOtD/bpIDvMaHNSFyJF93/VcscRSDs=;
        b=ExrM43+9SAHo5s1XQM9g4QhTGsdu+gUobr/w4+nUzfXtYpGl/i70FzIKoQcnXyoFJM
         ngDb1nKZrYpRP5FNZ7mvAc26u5NQet2EDFx+AeJQz3T4MmZBu2UELYxLX7x0zMeagjyo
         y0MIPc0EqvUHjZkMKblj4HdRDsb3+uVXirq/BGZugoSPbEtoUpKJldrKGW0+SY5vMKqI
         hOBI6WFoXTwzJb+0yV8UFExG/uCAyla4w9Bq+Wq0CEIchVc6MqK1BDcLxUXuWihAi7cK
         MVfU/g6gE88ahMKaQafRsz+EYXl11riXpWuuW2y3AXZ32fdlmSVuhZ5uWkOABQwMKeIY
         cTPQ==
X-Gm-Message-State: AOAM530wcDBzfSCbqsAQQX4mJ1uhHnE+28qC0NRoCCHlw4rDIpcqDI5A
	Z6a2i+dIvKIEr444gnsy9cU=
X-Google-Smtp-Source: ABdhPJwfnjVQiSvEYp/Vs4vsDUeGIT/J/ZhJnzeMzdCunqaCD6id5JJIFGlkZq5K8cAJ9f+LEq6HTw==
X-Received: by 2002:a5d:5106:: with SMTP id s6mr12321580wrt.166.1601593874958;
        Thu, 01 Oct 2020 16:11:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c3:: with SMTP id k3ls8624997wrm.1.gmail; Thu, 01 Oct
 2020 16:11:14 -0700 (PDT)
X-Received: by 2002:adf:e449:: with SMTP id t9mr11710132wrm.154.1601593874071;
        Thu, 01 Oct 2020 16:11:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593874; cv=none;
        d=google.com; s=arc-20160816;
        b=Zoe8QvG4prYLJVIMRYfFgFHsjYdKZjbGaLmiCgm9vzpSFj6YKORFtpKlyqqkF27TvR
         u2GvzIcfm3brchgmvLWUo7VcS1iUgRv2nWDG15Ai+vmOPBczs46DglUomhRPG5gooUQj
         vX1mTx0uWtYTm8hsKqitDGnJ8dJVVxlcQV7Ogf4y711lhyHsfAWyuq9aLCnbIYnuJ0eq
         XEhb3kzbFKwPnga/m+cd9UhoXGyY2hMrxQ+jpZ2kbVFeAOWGza9XfQpN+oRCK4EoSrVD
         PgXHS9JKRTCW47Nji1XmVQif31S+8aw6kyN69PKqRhG+mvCh1ZfxIJgGmPzIgVdVNZJL
         uRHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=zWR1cCG1rjrYp9C+AfwbmJjQNsNISZ2LulzQ9QrW8Jg=;
        b=ZMZy2Ft+NU+qTDRQQNAjm5PMaY6/0fkcDtPHsvqLYcls2wZr3QdZjUc+j4NMST3gh8
         Vq9Dz7VFjdkN2E4DNoDjmb0po+2EJ+h0gyFdwXhPO0wfJb+tQk9vAUF6ssVXCi9AKfuz
         p6OxkNIbcPSiiB57dj4Ltp/W8zIVjhgoyD4UiYLgyg2VCWYOJxe6+MyP8AQPH8RNaAG6
         kodyVJjJakXRJKZ+uLTyqaf5LnEbEZQ31pDsq+Uuxra+zJZchb/cqvmvRAcr6jnjB60J
         /LDVjhQvV8jVzwBlFGWrka1R26qgFCOZ0BhUCyQWrajEBTYFkep7eHyKVfBZ4+FONLvR
         d/3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iBnDmdG2;
       spf=pass (google.com: domain of 3ewj2xwokcbaqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3EWJ2XwoKCbAQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id w2si151714wrr.5.2020.10.01.16.11.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ewj2xwokcbaqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id y3so113310wrl.21
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:14 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:f802:: with SMTP id
 s2mr10978766wrp.328.1601593873339; Thu, 01 Oct 2020 16:11:13 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:13 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <823cf1ad36d0a93ed0ecdd81fab8c5b77437c418.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 12/39] kasan: hide invalid free check implementation
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iBnDmdG2;       spf=pass
 (google.com: domain of 3ewj2xwokcbaqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3EWJ2XwoKCbAQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

For software KASAN modes the check is based on the value in the shadow
memory. Hardware tag-based KASAN won't be using shadow, so hide the
implementation of the check in check_invalid_free().

Also simplify the code for software tag-based mode.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I5fae9531c9fc948eb4d4e0c589744032fc5a0789
---
 mm/kasan/common.c  | 19 +------------------
 mm/kasan/generic.c |  7 +++++++
 mm/kasan/kasan.h   |  2 ++
 mm/kasan/sw_tags.c |  9 +++++++++
 4 files changed, 19 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 123abfb760d4..543e6bf2168f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -272,25 +272,9 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
-{
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
-		return shadow_byte < 0 ||
-			shadow_byte >= KASAN_GRANULE_SIZE;
-
-	/* else CONFIG_KASAN_SW_TAGS: */
-	if ((u8)shadow_byte == KASAN_TAG_INVALID)
-		return true;
-	if ((tag != KASAN_TAG_KERNEL) && (tag != (u8)shadow_byte))
-		return true;
-
-	return false;
-}
-
 static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 			      unsigned long ip, bool quarantine)
 {
-	s8 shadow_byte;
 	u8 tag;
 	void *tagged_object;
 	unsigned long rounded_up_size;
@@ -309,8 +293,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
-	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
-	if (shadow_invalid(tag, shadow_byte)) {
+	if (check_invalid_free(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
 	}
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index ec4417156943..e1af3b6c53b8 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -187,6 +187,13 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	return check_memory_region_inline(addr, size, write, ret_ip);
 }
 
+bool check_invalid_free(void *addr)
+{
+	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
+
+	return shadow_byte < 0 || shadow_byte >= KASAN_GRANULE_SIZE;
+}
+
 void kasan_cache_shrink(struct kmem_cache *cache)
 {
 	quarantine_remove_cache(cache);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 1865bb92d47a..3eff57e71ff5 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -164,6 +164,8 @@ void kasan_poison_memory(const void *address, size_t size, u8 value);
 bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip);
 
+bool check_invalid_free(void *addr);
+
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 4bdd7dbd6647..b2638c2cd58a 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -121,6 +121,15 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	return true;
 }
 
+bool check_invalid_free(void *addr)
+{
+	u8 tag = get_tag(addr);
+	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(reset_tag(addr)));
+
+	return (shadow_byte == KASAN_TAG_INVALID) ||
+		(tag != KASAN_TAG_KERNEL && tag != shadow_byte);
+}
+
 #define DEFINE_HWASAN_LOAD_STORE(size)					\
 	void __hwasan_load##size##_noabort(unsigned long addr)		\
 	{								\
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/823cf1ad36d0a93ed0ecdd81fab8c5b77437c418.1601593784.git.andreyknvl%40google.com.
