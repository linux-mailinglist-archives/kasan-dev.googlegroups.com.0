Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6UBZ3UAKGQEJULQPSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AD8256BE0
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 16:28:11 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id p14sf1549100plq.1
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 07:28:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561559290; cv=pass;
        d=google.com; s=arc-20160816;
        b=CJ/LZDu6xnEf7jHqWHdyhVGKDmnEbuayZfKYUA6+yLYiL4LaWFMD5m5zuYRz0HF3c8
         wfLYUzMxv0C1SrwDkWr5f+8Nbv2UFHN/C2PU9KJJ1MXHZPITpJp+Cw0WUl+GWM61Oczs
         CHVraj1qpdckl7k1Nl+q+yxVNXQrSS9HYJL68cf0VAK3I6+gJYffXjLtukErk+/miUlH
         ACqtka27zVjn5IHdOPyXPgC4cVriXb3y83RAPjHfLhI5/tOJhUU4rTbYTMsEpgFlycBQ
         /bkz2Osx5LwGS+A7jgPi799wYtDj45pOitmMV4c48hJQIJNpDZTEHF+DbOMiuZGWovik
         jTfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=XZJ8tn6LaE2EPwYZLgBxmJkngLxutzQv98z+usveFm0=;
        b=e4H3ug2Qynzu+AN8jCONKakn2BtsEgpslviUcJYCSB93rbJo2ao5DGjYIA1aHF9Cec
         rP6YkUc6e1i8pmJcoKnZd/oZKPdiruyrkvlitO2baa4KupcdvhfSWW5G/EeqZ4rFSthe
         AuJ3c2OFXKk/IGn/6P16j76C/7EdOdJ5ydzFJEOBHI49VDCt+yCjGpm8vrCsyt0BFj4H
         OguP2iiihXXDov31B8muuZQ2RA87dN8xOplApl0JJe7nvo6hc8hNGRTJtQ2R/oQ3vSBI
         ArFYmwIG2RLLm+D0QYejxB3fjw0+LzFRVQWoH5Il3H8SbOToatLWLm40ibcUk4cqThGx
         tVtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Rpe/+hhA";
       spf=pass (google.com: domain of 3-yatxqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3-YATXQUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XZJ8tn6LaE2EPwYZLgBxmJkngLxutzQv98z+usveFm0=;
        b=SfaVHSc44+/ugrhPW0kYJPr3bqIUiBQoBBPyoWwkoJVvtOCg7YVsw9UZevMmOz9PKC
         qh2AFdj+hlul7dmOfTbe69LlroP95LMM8Dhy4pfFsO2X3iy7krQOoEo7F90plDQ29Srd
         D2HclEmWOvAqb60ZXFp3aPYtZJAG7ZSV3ijj7rlBr1uEPMzDzZktUyzbhmXI36plPGOA
         vKalPkn5sco0XnsxZl4SQnnuv2phzukmYGA64q+e8P468IEzIjUvaGn2oKhB+oYCmx/P
         UGbZ5WgS6a9Yanc/3lzsGqW3vR/PTd1jRTuRJXM55Rx/wDtnyT1G8DLH3e1KEybRp4rE
         Mksw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XZJ8tn6LaE2EPwYZLgBxmJkngLxutzQv98z+usveFm0=;
        b=kd21zC8t/6Vfy0IXHWKNWGdmCMFqyUicQixiPwC7Jn8AHVvxHzZl7Ye0K2wynbRM8m
         Ij5wCRH48VHVvmXA6T8YgBnqgTy1nr9LYM684xlCwa3qxtaBgSWUb3OBXnSDMVNFUYUD
         AjDIxLkZL4zomypEMXubweqtlhElP3ewkisfoducvCXbAJDyltf6ugNA+6QHalMSS/V6
         13gzaIOz7+hC5k0vp8xdKSluzr7bvLLd84QtMjQEf5CWn6OqJNWjSYwBlr6xzIipieFo
         kRh4Wl+B1Q6BSA9RVbHOT14L2+3atIcWBYgcRz1nqxJU2m1XoUj11kJ3m+Dpe+KUHn14
         aWfA==
X-Gm-Message-State: APjAAAW8GKfAPm3aAbwgo4EbS3I1F4QFJZdVzsCimframt4cziBsOiOv
	CQcXtdi9yTXOvIxBx80Tqts=
X-Google-Smtp-Source: APXvYqx9H1oPgZ3xbUDVwN5UzZfeE2Zfekp1pj3Fbgm6zAap1NdrzjrxPKQGJ7aATfY46O9vgeB1PA==
X-Received: by 2002:a63:4c46:: with SMTP id m6mr2540993pgl.59.1561559290253;
        Wed, 26 Jun 2019 07:28:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2ec7:: with SMTP id h7ls2085664pjs.3.canary-gmail;
 Wed, 26 Jun 2019 07:28:09 -0700 (PDT)
X-Received: by 2002:a17:902:aa8a:: with SMTP id d10mr5942397plr.154.1561559289926;
        Wed, 26 Jun 2019 07:28:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561559289; cv=none;
        d=google.com; s=arc-20160816;
        b=i2BByNCFjA5NXLAcNOBf+c5b+e5LxPyi7WRZGyrO73pHdK5PKbL4dSROxBuianMZJe
         x9+4R7fcMiv1H4UwkyeIpVh4v4f5cajE1kjPLgLy3oAZZqTGsznJjfB4HhHHRM2j84rT
         oPpS7/0cZvROjYlb1rMOl9dK5vzIplk3aob+BvuFIqBww5+VDYzZQq6w7UCGFXNFl/bT
         HgtmBKDsXy0PaaCAcG55xnww2Cvrc0s9TzEVTpEuOTTnbFc2meKRJY+QdE9QA5umS1YD
         xOaNZm1HamRMjLaa9yj+WlkLAONK4trOB/9ga0ZwVUkrzmcGoz+zzf24FkVLeAFKVkAj
         blsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=faSJHauNDZMNHqAQEQyENlJrk267vkTV0fUxMXAvovc=;
        b=yn564ySOLH7CmRxDF3Mtv0JliRXUYXbUZUs+CoVWQwJmtwrWJlVflLrCQf0fsRhadP
         hZdr7Ra4GYK36c7F77+G62rUqJucwdHV1G7SjDDUNmRzzYpYZtzhwyNI9TPrwenEJQSU
         0eA89y4MjK5LRi/beQCU9Isp0MLJeLPCMX8L/COKwbwXtGWeIqn3I6sGiN/SqtL5vyiw
         n6vt9TyQ/0+FWzP5j6TKgnE+GUki1Qq7pFjoQU4rBSpxlu/0o8f53t2aG5Co9VeOmcfC
         3Hb0fwIvcbWVBRmYJQw1WC4bUja/EGuc2vnQJ5IOJskZNDAKuj5Nb3NCDqnvVGY0x2oQ
         5/wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Rpe/+hhA";
       spf=pass (google.com: domain of 3-yatxqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3-YATXQUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id j2si836478pff.1.2019.06.26.07.28.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 07:28:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-yatxqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id v83so6045126ybv.17
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2019 07:28:09 -0700 (PDT)
X-Received: by 2002:a25:4d55:: with SMTP id a82mr2984762ybb.383.1561559289029;
 Wed, 26 Jun 2019 07:28:09 -0700 (PDT)
Date: Wed, 26 Jun 2019 16:20:14 +0200
In-Reply-To: <20190626142014.141844-1-elver@google.com>
Message-Id: <20190626142014.141844-6-elver@google.com>
Mime-Version: 1.0
References: <20190626142014.141844-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v3 5/5] mm/kasan: Add object validation in ksize()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Rpe/+hhA";       spf=pass
 (google.com: domain of 3-yatxqukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3-YATXQUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

ksize() has been unconditionally unpoisoning the whole shadow memory region
associated with an allocation. This can lead to various undetected bugs,
for example, double-kzfree().

Specifically, kzfree() uses ksize() to determine the actual allocation
size, and subsequently zeroes the memory. Since ksize() used to just
unpoison the whole shadow memory region, no invalid free was detected.

This patch addresses this as follows:

1. Add a check in ksize(), and only then unpoison the memory region.

2. Preserve kasan_unpoison_slab() semantics by explicitly unpoisoning
   the shadow memory region using the size obtained from __ksize().

Tested:
1. With SLAB allocator: a) normal boot without warnings; b) verified the
   added double-kzfree() is detected.
2. With SLUB allocator: a) normal boot without warnings; b) verified the
   added double-kzfree() is detected.

Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=199359
Signed-off-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
 include/linux/kasan.h |  7 +++++--
 mm/slab_common.c      | 21 ++++++++++++++++++++-
 2 files changed, 25 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b40ea104dd36..cc8a03cc9674 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -76,8 +76,11 @@ void kasan_free_shadow(const struct vm_struct *vm);
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
 
-size_t ksize(const void *);
-static inline void kasan_unpoison_slab(const void *ptr) { ksize(ptr); }
+size_t __ksize(const void *);
+static inline void kasan_unpoison_slab(const void *ptr)
+{
+	kasan_unpoison_shadow(ptr, __ksize(ptr));
+}
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
 bool kasan_save_enable_multi_shot(void);
diff --git a/mm/slab_common.c b/mm/slab_common.c
index b7c6a40e436a..ba4a859261d5 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1613,7 +1613,26 @@ EXPORT_SYMBOL(kzfree);
  */
 size_t ksize(const void *objp)
 {
-	size_t size = __ksize(objp);
+	size_t size;
+
+	BUG_ON(!objp);
+	/*
+	 * We need to check that the pointed to object is valid, and only then
+	 * unpoison the shadow memory below. We use __kasan_check_read(), to
+	 * generate a more useful report at the time ksize() is called (rather
+	 * than later where behaviour is undefined due to potential
+	 * use-after-free or double-free).
+	 *
+	 * If the pointed to memory is invalid we return 0, to avoid users of
+	 * ksize() writing to and potentially corrupting the memory region.
+	 *
+	 * We want to perform the check before __ksize(), to avoid potentially
+	 * crashing in __ksize() due to accessing invalid metadata.
+	 */
+	if (unlikely(objp == ZERO_SIZE_PTR) || !__kasan_check_read(objp, 1))
+		return 0;
+
+	size = __ksize(objp);
 	/*
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626142014.141844-6-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
