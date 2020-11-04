Return-Path: <kasan-dev+bncBDX4HWEMTEBRBC7ORT6QKGQESJH2OHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 81FBE2A7122
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:39 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id t21sf6815wmt.8
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531979; cv=pass;
        d=google.com; s=arc-20160816;
        b=WW06BP00YhG29zMp3R/1Fk7weDkyMakhBSbHWsKESXSjt5t1IeBacItU5khThDHsEk
         g4+2bH2YDxdWwFmfWWn7+RBkzCVv8VcTKC+Zc+MfTKzU1Igj+3fiyrw63EJettIzvQwB
         Y6fE6ugfGqMibN/qmPTPo3qSAVghTDTQYikr+U+KzWDV4o60v6/NRcoThvDkwxtnsZfa
         MNKG9N0wu8ZknuySDTho+LyIXDLZEZqpKbYwPMvZWroDv047I8KLViCvahFF+X3v0ydo
         sWNQTFHaM7oCs2kQvCSAjFBumQv1wegyGzjyiplc1x+0Jcl7SOmW6eapB0aGCpuUagkr
         5Ufg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=GH8tMrwfx/Hzqp8x2PUb3HwyJTmw5SEg+D4D3KvVDnM=;
        b=XC3nUaV7hL9HMA/Pbm0QUnrV0V7kBFcCDLqBSZQpNpXShtQVN4JRe58jppi7locQWe
         Lmjv3vzbH8PTOZAJQyQm8EIxUGlW+Hty2ykHTj6evURGK1NNgo7gQ8ChTer6qnGcYyPv
         APAeNYDexXM9rTNCaB2AzyDN36tPrwWXrUHhZMPIDSaL0Kt7rkpbWSAWo7hHz4Jjc7v0
         40VfaXJwqts2Glxq3Yv1BhQ7IwkxZR6ZQI6VWuQXAbYKMM4LpvNZ6HkAUL860A6hwlrp
         UKIF8YNWPY1DnZ6LFz92dxsQt/SMk/nAqbP1RdQ5SlOj6fHJW99C1P5zIlYIy4FezBSy
         3cwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kkZxgHLi;
       spf=pass (google.com: domain of 3ctejxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3CTejXwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GH8tMrwfx/Hzqp8x2PUb3HwyJTmw5SEg+D4D3KvVDnM=;
        b=Op7kKQ5ipJtBnqPkiAe+hlBWvGgsvaRhPFxrNhBHNiU29ZMvUFFdGReNCwGi9AvO7Y
         Vk5ruy5QrmtW4udq9Oxu2iIeR52VrnKZiPZma5ow9VM50cSgVtPhHn8s+bjplSeWrzb2
         lhPaaF0whUG9tKvVepFgTMLWN0aHWNXqRfueep18NE8GxkAc0c+/SeqnVWWnJCg2B1rg
         9aREnJ8ibKm7iHKnKiH7wT32ESdgr+wLmi0uhLmxv1dftQi96DruVEYSeX9cufcbcbR+
         QBbWtn19/KnCXeApTNVm4RhQAdyI32RgntUN55P1OrIgeLD+dyDPmdmDscG5fkIG1Opr
         Rc8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GH8tMrwfx/Hzqp8x2PUb3HwyJTmw5SEg+D4D3KvVDnM=;
        b=t5fh7WyOte44SQX9JAojbD24F9ZFD4fUEQ5+nIUtBBrbAKYKXijbLm+qs/95obSHLE
         sWVlPvxKQN1ulbwFJKAU4iFgZlX4bxN8ueawYGsLUJXbKgT3+aZhZKfCRodnMytIbXCP
         lgDkZAh6XMKImuqVhz+7GoXIA8Y7nnwQEfEEmEOgqKwF1hDOsEM2uK9FVyqK+ChQ3d6g
         EZPHBPoRNz3RiMnlY+gLTRqLoQhxcCDb8H2gcD5Lwq2Yqny2+PleZL24kKh8VvIR8EFM
         ijMFOu5gjcvkkzKcaAXhwngXPPQZHMdq3vzEvVUN534F1nqqLNfSj2oK4zE6Omc2YFeK
         OyJA==
X-Gm-Message-State: AOAM532QkCCHYa+XNwlq+49bAF3MCnXZzknu78GobxakW1ft0cZXqINm
	RyF/ofP271tbSP/Pjozu//M=
X-Google-Smtp-Source: ABdhPJy7f9jcOTQMgTjfAtVbyNixMjO9K909qtuVvhp8KarVRy7gpIU9kI/fr7ZucJwbOn6SePdKJA==
X-Received: by 2002:adf:ce91:: with SMTP id r17mr385144wrn.326.1604531979295;
        Wed, 04 Nov 2020 15:19:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e4e:: with SMTP id z75ls1894948wmc.0.canary-gmail; Wed,
 04 Nov 2020 15:19:38 -0800 (PST)
X-Received: by 2002:a1c:bd0b:: with SMTP id n11mr58921wmf.111.1604531978504;
        Wed, 04 Nov 2020 15:19:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531978; cv=none;
        d=google.com; s=arc-20160816;
        b=y4kPu9WyKXM1d0SbyGa0In5g+ZtFGNiqoElJiyT9//JzIvFT369RUq3J8Q2aoa0dwL
         UBBzr1EnQ0JRCEi5pTmj82wMFWAxYcvCefxrBFhDfGZJDzmQ3OHQIudS6CF3WoKwf76u
         kU1671Z0rRAtVoBWnAK0W5CCbO/hxBF4C/ehcHJMPqwSr+DWnr3292h/ayDXruCJhl0w
         dkKwP8GtjQlyecc1aSlfo3Q97iFcCgvo39ok96+JGKLkUm4nZU/4DWMZU4wjN8kTCnrN
         QfZcMwHcFrgDQX3CgTME2XIeFlDTs1LZ9Q+wsfw2qPVLVUDqAX2mb0ZqTdZhB3ta0U/X
         4q7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=KbFeAZ0fCuPi+p3+zRj17HQjRaGn7T9HM7M+MvodvIE=;
        b=vwLi5Zpkn7gQ76kUrKVB9HxFHTeEnxXKt9ne1Vws+LzM4kDAgruCrYzXh+WPwQTr2x
         yVc4PK7D1jpREOFaqLkMaObDd222Qu2dLFHZuZXCQoMitwXuVlFjUrdPhqq2UGhq7xHd
         9/jQ5TOlLG76uu3YOTQAMC7H/yK8IxCEGabpjf4ns5mA0t5H38MmCb+IEkIBSxN1E0Hm
         4ToV3bZBcWOpA5ZWWBwsheGZruDvSu76PBeIpft+6hx+MP/7CJoMqYutygIQ1XmJIziC
         NcON3HOII2q1Q/BeERuTj31mdQUTj+l/poWoMdjLzJmw161qC2Ul8C7S7x557uhTcZmc
         OfrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kkZxgHLi;
       spf=pass (google.com: domain of 3ctejxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3CTejXwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id z83si331834wmc.3.2020.11.04.15.19.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ctejxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id o2so45074edw.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:38 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6402:759:: with SMTP id
 p25mr215552edy.22.1604531977800; Wed, 04 Nov 2020 15:19:37 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:28 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <7366c8102820448b082445924a7a014976e1f252.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 13/43] kasan: hide invalid free check implementation
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kkZxgHLi;       spf=pass
 (google.com: domain of 3ctejxwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3CTejXwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7366c8102820448b082445924a7a014976e1f252.1604531793.git.andreyknvl%40google.com.
