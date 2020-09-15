Return-Path: <kasan-dev+bncBDX4HWEMTEBRBP66QT5QKGQEBZAGZCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id D25D826AF54
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:48 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id b54sf3973005qtk.17
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204608; cv=pass;
        d=google.com; s=arc-20160816;
        b=xlDIwcqEOz4BIZIOsr0iDuRjzXa5nQn/dO7YYLZaVNk5vasncoICqfau2CdHRXjTq2
         2yim0Eansh6I1nzfYbzZo6tFnR2GLjo/KcGIDNvRguEJjJYrNsr+j/eGfwT3zhhNUfyH
         SBReMppSZdpnf2u5z63MqRAu0jq8l/SsdfaVW3zsBgl1ZRCkhH8JFiJfa0DyvjOtqE3L
         44qzsKxD0StgV4reV8M9oL6S47xzqWrCF9bdrpdFmXWZW3iTmmAaWF/SIjc+PDb9heV8
         IMP9rIzV9P83x2n7/pcfSpiuRd7myFDPfT0tVRRzZIbS/J0c/wLHDnsYNtUrpxCp1dAK
         ulrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=VEMn7iKWyi67S7MggQyODQ1S5qRlVWX9ROfcCfopE+g=;
        b=exhiowpqcoJJtBz3FgeAk9w/XoPJclbSFB9buv+7ejMImLarEMcwP+Oi2Zgwh1X53+
         rGM0mM29Jvl/lbzwgIPM9xmxgDlmvIm2q+f50JtoNen5IlUlwFnae5R2Aw+i44G28sP+
         E9oX0RydJdh5ySQpU3zzWtM0e9CLwzx8X7QIMNuIKN/myFg/jUtycNtyigLnMx+uVA8k
         AaXQN6CcCkUV7JDm+qjrGCLL3g2t/eBMnIv+KmAPRvnCWt1tnLQk0M9PrHOhUpo9BLA/
         LrSyyGaXmjnWknb/Taysnt+X1E689Ix2HV6qb0ZLl1b49KqRsDtg0pNE0zWBBy6eC6H7
         bEsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pyez5vKz;
       spf=pass (google.com: domain of 3py9hxwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Py9hXwoKCSQANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VEMn7iKWyi67S7MggQyODQ1S5qRlVWX9ROfcCfopE+g=;
        b=Yhof8UIe1sQUn+dkg3BcBvAKVDHRlquxRy1bOwtlM7CsSMOuiYeRSSnOISfpD3B9Qs
         NdZRHLRHS3LmEL1U0POFF7et3MMpwRYO9neSiWyTCsrN0Bv8WNNNwlII7K68zWzLYHlr
         dCz+RGJQ+qSvDSThbqF6HPvK17sSLVilyKmfQyB0huTf3oISGcknZfAysVKYWS9dzh9K
         GIPULAIIzOzyxzTB72+XPR3SXUr/R02DucSt88AJTASdwWUq75M1EpxeB0Out+IvAEGU
         CE2hvkpwvIJXExsyXo5takdgtt3SVhZOAQkxd2aXqxW5ufj1KkLR3lj89QYecup2rIyC
         /dbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VEMn7iKWyi67S7MggQyODQ1S5qRlVWX9ROfcCfopE+g=;
        b=Qb0gSLFN9uwEpfdcmY/ROcV7csCttgvDp1lXFCs6HhWWFYzcyz1vsIB0X6nsd/6LCI
         GnWQT13xfRqjiLR587ttJA2oMPF+Kh7N+PY/n/7FunzHiL1xvT/WY+V1aYuPxIfVybYK
         ysGNVs7D3R0eS9cGHEEBpsPcKsTU0j9YxRqwDTIL4HFcyE2jgZ44hwtKFIplFU5262zy
         2ceoUGodMOETG4tAnxAosaOKUjPZVcJacKt3gGin2fn7742imollHkvUDm7fsKY/PaaI
         +5A3i0zhShBve55zT0J998dU5LI2HB809cNvwKNuH6wZhvA43YFtcYwSGqeIjMHHZ1FJ
         PzUg==
X-Gm-Message-State: AOAM532kHSfVOnjU4rQqyGAhq3R056VhCxbZk43XC8x6/6oOgqU/uUEL
	eXxYoA7mTZhNnVNpZSQwQU8=
X-Google-Smtp-Source: ABdhPJwv5BPI9rgf697UpLvBauZ7wX7NwoI2Fq4Jt2XaMtaF5ULRruVKKwf+g7dTH+Mjk2e7sc7GaQ==
X-Received: by 2002:a05:6214:292:: with SMTP id l18mr19884721qvv.3.1600204607799;
        Tue, 15 Sep 2020 14:16:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b64c:: with SMTP id q12ls130888qvf.7.gmail; Tue, 15 Sep
 2020 14:16:47 -0700 (PDT)
X-Received: by 2002:a0c:cb11:: with SMTP id o17mr3676181qvk.44.1600204607369;
        Tue, 15 Sep 2020 14:16:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204607; cv=none;
        d=google.com; s=arc-20160816;
        b=ESbD2dMpUcLzoSXDL7LC25oJ166/RkkB4QH6VJFBkCqc8Uy3TsftgUGmd3tLaihYcc
         SNyiyMFvmhBQi9YPgyM3nDSfaFNUis/dP4k3HzWOorvlAetq9O3tfedoRQjtJ7uJnnq4
         tzgwXlsq/J2u7zNn0zuiMp2peDjFPLpuVIFyV6in/0s6olh0cq9I+kJii09CJ6EGUSip
         Bdc2+5qFrnHz9nbHXhQOybhDIgeNe76jWTPPcSiw1EKioaAKIMhkAQRsDPmcu8doZ0HW
         KeUbBZK6z5ogbKu+4kr8B9QwDAMIiHMFUzVNSy7AQ/zL2MvZi+1JNxCFtzPYivWXtqHX
         KHQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=PJMOcA8gqYHqxhIXShAJ08j6C1UfzhHyZzvegxBV4p8=;
        b=WBu5q+5tIvA2E6PXgldnhHJPDwVNZYTcI6jt4gEwiWUYJgUaAnueqljY+9jqjeSkKH
         C+dy8X6/+j8f2dFoKchnK/+NKVi+OucpM/5Q7EDkkxwjY1e/ZPxA/B011MHF4AUPLtBC
         iEz4d6s5546VT0z2SUVgOW9sN/nVJKKS0FheB5/gL+ZNb1OoNrANTiEQKIUxY7JQDZjq
         NjaJQO6IlFK2ldf2VBnF0JIByF4oExXBRfSNIAd41GZHahpqxpMF+aGOBJRwiFpgkvW3
         KT/VYX5E7eRQdCUoelS1sFZBDrlkKqmmKP4MyaN+XQ3hmGrzEkPPPqk0orLvQCdbtmv+
         Wk3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pyez5vKz;
       spf=pass (google.com: domain of 3py9hxwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Py9hXwoKCSQANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id x13si876482qtp.0.2020.09.15.14.16.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3py9hxwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id b18so4026243qto.4
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:47 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5743:: with SMTP id
 q3mr19874682qvx.6.1600204607062; Tue, 15 Sep 2020 14:16:47 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:52 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <29aaa1e9ab63d03891f8fae268a5f71582db5778.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 10/37] kasan: hide invalid free check implementation
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
 header.i=@google.com header.s=20161025 header.b=Pyez5vKz;       spf=pass
 (google.com: domain of 3py9hxwokcsqandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Py9hXwoKCSQANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
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

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I5fae9531c9fc948eb4d4e0c589744032fc5a0789
---
 mm/kasan/common.c  | 19 +------------------
 mm/kasan/generic.c |  7 +++++++
 mm/kasan/kasan.h   |  2 ++
 mm/kasan/tags.c    | 12 ++++++++++++
 4 files changed, 22 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 43a927e70067..a2321d35390e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -277,25 +277,9 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
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
@@ -314,8 +298,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
-	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
-	if (shadow_invalid(tag, shadow_byte)) {
+	if (check_invalid_free(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
 	}
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index f6d68aa9872f..73f4d786ad5d 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -192,6 +192,13 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
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
index c31e2c739301..cf6a135860f2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -163,6 +163,8 @@ void kasan_poison_memory(const void *address, size_t size, u8 value);
 bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip);
 
+bool check_invalid_free(void *addr);
+
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 4d5a1fe8251f..feb42c1763b8 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -126,6 +126,18 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	return true;
 }
 
+bool check_invalid_free(void *addr)
+{
+	u8 tag = get_tag(addr);
+	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(reset_tag(addr)));
+
+	if (shadow_byte == KASAN_TAG_INVALID)
+		return true;
+	if (tag != KASAN_TAG_KERNEL && tag != shadow_byte)
+		return true;
+	return false;
+}
+
 #define DEFINE_HWASAN_LOAD_STORE(size)					\
 	void __hwasan_load##size##_noabort(unsigned long addr)		\
 	{								\
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/29aaa1e9ab63d03891f8fae268a5f71582db5778.1600204505.git.andreyknvl%40google.com.
