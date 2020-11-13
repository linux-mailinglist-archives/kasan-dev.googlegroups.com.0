Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOENXT6QKGQEZZQFT3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id AA1592B2841
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:41 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id o128sf4731048ooo.11
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306040; cv=pass;
        d=google.com; s=arc-20160816;
        b=hnNwOHxn2HJCTHqM/TdbBPFXHgWSBGdBrHwzkIXJhHIP2WRgz1gUHxAHRajOOyUA6/
         nSu3X93IclCIwCe8DSUlj5cY9SlMiLMu1o1sMF3jcsG/moO4DQQGTqWrz4SdaaMEoRlk
         QoOgLeUh9TdZ/Knd8aFE2BY7KS5bAAdOqhX43gIVFKx4bkwmkSbIab98J0x4qVceJ5YU
         j4W0Z0nOnvyXxzGri+vbv4hJ0lBlSPtazbEnRqt6IECEhMrjAYT+3uLOF6g4NZdz1Loa
         OfuxFOFWXlKcxwewVL9O5Nk9mzuo8h0ZtgxiWLGCFFqwwoYOtJk8x9W49a50sl6CjSvX
         mbSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=zn0PQm0zkPT5HQTqLhMA83O5vLCFZtGMZJzmS7+FiUk=;
        b=cfYRus+ympDNMUUbHCFGHhju46IzJ9nIB+QrKVB3DPmcGVvm3mQuDVlMoLIYLunyTQ
         20yBkRybrcfIqO2RX5CX6C+6vK3qlLHONGEcc67FQrHS1hxPHS7uOFo2rlFs34K/Cfmo
         XKygRFpiO/8aCf1TiUuAnPiqZq/GknX91gGFgn0VT7KIpm3HTqScjr549cPo/qDnJ0xd
         F/aSSpHtlrsPP1Pk6VkgSTWw4lxKk8DERX5xmx5a/wLgrDAulY/bPQ1cFAsHLvpAKJqe
         pG/Gk+ABtr1uAKnG+eow52RbAiao4lwfOWUgmaEVdMdPdYxOzOLwQtp9v0K7AzGo0mdQ
         V3mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a7iYcqhi;
       spf=pass (google.com: domain of 3twavxwokcyqivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3twavXwoKCYQivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zn0PQm0zkPT5HQTqLhMA83O5vLCFZtGMZJzmS7+FiUk=;
        b=fYab7BxB+6LxpS2/dbdNN3wK9f4qZwnGzJZC8eZv6K95BOcA1f/HgYSR1pNyuhXpFl
         fAPMDecCcuOuIgdqMxLFVHs47F5M9ilFDp5u7DZiU5CcdtAnhdF3m35D27qteg+/CU0j
         w4N80IaWJTJIfcTJz/1ZbVl9MaSuTb5HnJanrHwAewWgGkb1vXqDnBuwahLTmbXP82wX
         K5sOx+STNoywLZVFTEt+g/+6AlY14sM6aclsOmRfZeCEKD8Mm7gIhj/b/pXqJGdEHd+q
         1p8o/fNl3uB/cOVaHI5BHclbMZL2jDGCuAmgVZRKh7q8hl7eWELJSb9mnu/7Vym/gdK8
         ci2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zn0PQm0zkPT5HQTqLhMA83O5vLCFZtGMZJzmS7+FiUk=;
        b=SKV1qn8hH454pKBYSA8C+/2DiHKtwSmgUaLyGqe4zdXWlxIRspvqGQpSti/KsMONXl
         Ltx+ganXBkvqGt4CKFJcApruyJOjJTX7//sc4jt31FQU0WlzC5WwhDp0ZJHg8cZzsPyE
         lgsFGU6fINFiYAYJEaqX8LJ3uXhS6K4HS+ZKZhwDv0iVf4aQmZacnLO1cytidp1jkIwt
         wQXe05lK+1GRWHxawHJUowfWTWWaFWKF9U5Ek6WqQc5vcOJA3GGznpB0v+9yAOvabwAw
         lAwRP/s8iSXeHW0H6nrE+bBrBsY0m7ew8UoFhvTHjSJjOAjN1zH6tNv2YWgKQRM2xMvF
         aMmg==
X-Gm-Message-State: AOAM532JLGOE47+1siZIM3Iy4WEV4ehrrhCHvibpCcP+L7GgzM0Fb0BE
	EHbPCzmjMZZ/inVhqUFc030=
X-Google-Smtp-Source: ABdhPJyQ6smwLUkt97dicgIjyBRTjfVAi0WnxLFRlhAd1lxh20IxrbIeLUZ4F4rLXWPeUB3gHvjrXw==
X-Received: by 2002:aca:b854:: with SMTP id i81mr3062731oif.6.1605306040702;
        Fri, 13 Nov 2020 14:20:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f59:: with SMTP id u25ls1922491oth.1.gmail; Fri,
 13 Nov 2020 14:20:39 -0800 (PST)
X-Received: by 2002:a05:6830:1e95:: with SMTP id n21mr3207143otr.49.1605306039687;
        Fri, 13 Nov 2020 14:20:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306039; cv=none;
        d=google.com; s=arc-20160816;
        b=LARRNg6exUGU2FBDVBBK34tmrhYG2dRQ5BMl/5RLan/c7qpL0xnt13nSmAR0UL4LKx
         t6puoynHzJ+7kQF+Slzuvk+GPZ0f+MBfi4nPM9FPdUDMert0LG1d4bEBE+JqmCsSXOsF
         ch7cdMFN2Z0cwc7FiUepZQyyoHHo8p7IXlOKyfobsao0Ep+mGFXOoKizs8rTyaNLbKvy
         AQwc0Q7VUL6p5Dl6dpV3p1WsCl8y/YiS7w5ZjU7yCKTPrh83Mp1dIUZy7UN5HyvRi9Iy
         EkxezXbeMG5QdbQivJmo2tEMGzRDyFF2XI7h5M48tyWGwzq6sb2d57JnPIwwkiuGnRTG
         wJVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=MeFL8PhZCdNKf3Y6a938/A3o+3e79v6OLkm/7y5InEs=;
        b=ncG8YwccuEE+AujfT/1bUl6n+wi62yn19Bx5c5rzHFWYaViB46UhGxpj/axh0FrnCv
         2WfUckHTOloTlIuxzUUZ6787MtzZuRcCtHEfUEYb/CP9Dr6Sy3LA7Ga5JtVOamw4HIWr
         2JT53qiFuLxHYSLvGz8mjTpaMpg9xxmEEXdmt+n1TfdFMgr+FNzrvpHqspuJtUq4+uEq
         82zdZn/Yg/kmJyXwgUm0Nt3NyhohKgr2TRtkJhkQXe0sgMHEQ9/6nltXrbz+cSdc6NaD
         GDDvoivpnvw2z5tFMoOesQOaM/BNqKi6tqNDcshjTW3cihQLKJ0BtT60NONv0dGf9x2x
         y1JA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a7iYcqhi;
       spf=pass (google.com: domain of 3twavxwokcyqivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3twavXwoKCYQivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id e13si894636oth.3.2020.11.13.14.20.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3twavxwokcyqivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id t64so7625847qkd.5
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:39 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b6c4:: with SMTP id
 h4mr4429589qve.35.1605306039132; Fri, 13 Nov 2020 14:20:39 -0800 (PST)
Date: Fri, 13 Nov 2020 23:20:00 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <cc8bea6e21d1cba10f4718fb58458f54fce0dab3.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 10/19] kasan: inline (un)poison_range and check_invalid_free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=a7iYcqhi;       spf=pass
 (google.com: domain of 3twavxwokcyqivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3twavXwoKCYQivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
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

Using (un)poison_range() or check_invalid_free() currently results in
function calls. Move their definitions to mm/kasan/kasan.h and turn them
into static inline functions for hardware tag-based mode to avoid
unneeded function calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ia9d8191024a12d1374675b3d27197f10193f50bb
---
 mm/kasan/hw_tags.c | 30 ------------------------------
 mm/kasan/kasan.h   | 45 ++++++++++++++++++++++++++++++++++++++++-----
 2 files changed, 40 insertions(+), 35 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 3cdd87d189f6..863fed4edd3f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -10,7 +10,6 @@
 
 #include <linux/kasan.h>
 #include <linux/kernel.h>
-#include <linux/kfence.h>
 #include <linux/memory.h>
 #include <linux/mm.h>
 #include <linux/string.h>
@@ -31,35 +30,6 @@ void __init kasan_init_hw_tags(void)
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void poison_range(const void *address, size_t size, u8 value)
-{
-	/* Skip KFENCE memory if called explicitly outside of sl*b. */
-	if (is_kfence_address(address))
-		return;
-
-	hw_set_mem_tag_range(kasan_reset_tag(address),
-			round_up(size, KASAN_GRANULE_SIZE), value);
-}
-
-void unpoison_range(const void *address, size_t size)
-{
-	/* Skip KFENCE memory if called explicitly outside of sl*b. */
-	if (is_kfence_address(address))
-		return;
-
-	hw_set_mem_tag_range(kasan_reset_tag(address),
-			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
-}
-
-bool check_invalid_free(void *addr)
-{
-	u8 ptr_tag = get_tag(addr);
-	u8 mem_tag = hw_get_mem_tag(addr);
-
-	return (mem_tag == KASAN_TAG_INVALID) ||
-		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
-}
-
 void kasan_set_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 7876a2547b7d..8aa83b7ad79e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -3,6 +3,7 @@
 #define __MM_KASAN_KASAN_H
 
 #include <linux/kasan.h>
+#include <linux/kfence.h>
 #include <linux/stackdepot.h>
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
@@ -154,9 +155,6 @@ struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
 
-void poison_range(const void *address, size_t size, u8 value);
-void unpoison_range(const void *address, size_t size);
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
@@ -196,8 +194,6 @@ void print_tags(u8 addr_tag, const void *addr);
 static inline void print_tags(u8 addr_tag, const void *addr) { }
 #endif
 
-bool check_invalid_free(void *addr);
-
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 void metadata_fetch_row(char *buffer, void *row);
@@ -278,6 +274,45 @@ static inline u8 random_tag(void) { return hw_get_random_tag(); }
 static inline u8 random_tag(void) { return 0; }
 #endif
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+static inline void poison_range(const void *address, size_t size, u8 value)
+{
+	/* Skip KFENCE memory if called explicitly outside of sl*b. */
+	if (is_kfence_address(address))
+		return;
+
+	hw_set_mem_tag_range(kasan_reset_tag(address),
+			round_up(size, KASAN_GRANULE_SIZE), value);
+}
+
+static inline void unpoison_range(const void *address, size_t size)
+{
+	/* Skip KFENCE memory if called explicitly outside of sl*b. */
+	if (is_kfence_address(address))
+		return;
+
+	hw_set_mem_tag_range(kasan_reset_tag(address),
+			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
+}
+
+static inline bool check_invalid_free(void *addr)
+{
+	u8 ptr_tag = get_tag(addr);
+	u8 mem_tag = hw_get_mem_tag(addr);
+
+	return (mem_tag == KASAN_TAG_INVALID) ||
+		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
+}
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
+void poison_range(const void *address, size_t size, u8 value);
+void unpoison_range(const void *address, size_t size);
+bool check_invalid_free(void *addr);
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cc8bea6e21d1cba10f4718fb58458f54fce0dab3.1605305978.git.andreyknvl%40google.com.
