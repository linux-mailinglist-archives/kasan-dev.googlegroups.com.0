Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBTMMVOQQMGQEW7IYK2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 75D746D4462
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Apr 2023 14:27:58 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id h6-20020ac85846000000b003e3c23d562asf19707800qth.1
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Apr 2023 05:27:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680524877; cv=pass;
        d=google.com; s=arc-20160816;
        b=WLiAz6W5YA+mkG91+d7w4y1HrUPV9AWSL9JKJs7BMQysjGO9xnEw3zkLH8xwYYsUte
         ASIcBnUaNS0BnjhYQoGZAnTMfxzs6iIurTqLk9A6X9FjN1QDSxAULDagsZgsTRKcn3Mt
         KaapN+PArk4D92CQwZ2+Bz1zq75pz3NO2hwxy+65A6gvmFDZ5PlOLTNfwOyyRBQ7L1T6
         O6sU17lJKILQZh3zMQDRS2ZWiYpSERLwaAzlWqAV8Is2C8V7RJPqRKi5x0wljXMBLR9z
         c8aGIcDBbBOEXDCLmV5rwwxdJB8rdebVRPWFMZrU4aBsX9YEvEbhd17XIcwYdy9aWuuL
         GYxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=813kFNREAflewYPIzQ27X91zSzCU/+O4rbn3B0dO/IM=;
        b=idowpLu9SzghRvTaoqPziNhIYV2wHSjFlfCsyVr9pTTqUy77vc7KC5xBUcqCqFOk28
         cpXxGQpkCeJAeCD8dr8bZQ2f4so5VLTT+6JB1WuRs3olVVJu0GncuSRVNEhi9CpHpur4
         0E4zAlNrZ/kR+J704hUzc4nwkRAuPM3i36CiFXsGzl9Z3f0OOEk69lSu5KhdWn7FcaVg
         wc2qVWQwp/Jvy7iVf/raMLd+LsJiBHhku1+XEoRZh6CxTnPQHRKrC6iYCxDfEAEps20a
         LIWjFlRczZG9T71WmTbLPnTYdNbiZ3G+ZQ6RXHjwZ2tk9LwP4HGe6PwOwRXAGvHYiyOA
         f1YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=cQF1RNTr;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680524877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=813kFNREAflewYPIzQ27X91zSzCU/+O4rbn3B0dO/IM=;
        b=ZTKy8Y2YHAJEFJ9X/+xNtgoqYBNvXqtE75/YLu99ITRGgjbCmWbmUwXwgSZssCr40v
         3TBJoS1VgqtLNtMm8SozXqZQ8Hc6r/O+HyEkg0M6lp5yFHzNgrPHhbTu5qgCKyMgCLr8
         aTUCrdt880NcTRILlV9A3rfc7JQCwoHSwCUHEJ7YsF5UBQIgrUfFEoKCf8ffckQz/kfG
         AX3xUmnfvPe42M1kbgjlPQS2O7v9Xg/ysPqbfwi8hIYWv85DmoiaIsI3gV4dpkdJHPtz
         PbJbFBSERh13C6WlUQ3/3wR0YNnj1Eo/mx3+cUGn7Sn8gkCPYEFGoYt72wDaq4ZfbM4i
         14tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680524877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=813kFNREAflewYPIzQ27X91zSzCU/+O4rbn3B0dO/IM=;
        b=3i4/oso3ieMVCa1YomnxA4riTpyMtFORvDu7lVLpMSj0WsrZRGvazzVZ4I5TvB1M7p
         PDAf7+XPsksx33KYPQs/JOMsQvKf9zc0BZGz6QpZX/o40HKo6pSNh7WsLzJXxBrLOgqt
         9UAe+j3V9jbfrLPEMa/OCtbA2IQK7nbbqZH6aeMF3ODBU5jmm5m/k8h2OJ4Sl3Yt6Hv9
         LJ6t39LGklHWFqoLhgVj5PH9qGh2XNOX4lc9YZ+k4gZDsRbBT/Xin7eedoSSnGfhaS1u
         i/YcXqpdN87j5Rqm55nLkwi6pVVP6Mb8I0/OGe5oyWJedgUfJacnnAEpUypPBSiAsUgY
         PWeA==
X-Gm-Message-State: AO0yUKUbKmake0W1XaiqJz8zJMZ+V2uDbmoHWrDYUYyASqgeLLiG32ZU
	NgqATA47rf4cpZGVQJOP8dvK+w==
X-Google-Smtp-Source: AK7set8UgzFg/FXqEIriAo2UK3T5yEiwefa13BDPzcVfiOdcSFwlMRFaTWlmm9sdi8M+ZdsQPvFyOQ==
X-Received: by 2002:a05:622a:88:b0:3bf:b826:a5e3 with SMTP id o8-20020a05622a008800b003bfb826a5e3mr12783136qtw.1.1680524877364;
        Mon, 03 Apr 2023 05:27:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:438f:b0:3c0:184b:29e9 with SMTP id
 em15-20020a05622a438f00b003c0184b29e9ls12173149qtb.4.-pod-prod-gmail; Mon, 03
 Apr 2023 05:27:56 -0700 (PDT)
X-Received: by 2002:ac8:57c8:0:b0:3d5:477:f42b with SMTP id w8-20020ac857c8000000b003d50477f42bmr66855717qta.56.1680524876832;
        Mon, 03 Apr 2023 05:27:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680524876; cv=none;
        d=google.com; s=arc-20160816;
        b=ElCnEwaW37N1qpejWTzJ/IQ6oLmC2FkPYTAoY7wAVqBoaxB1YsSs+J27W0nqTbXy/s
         AxzbL+qTqLf93ChWyb+ArxHv/UyQ21rYbU6FOK8ZZbCdStKkQqLTNdy6h09l+0JJW7Ba
         iAQ6VZ6KWXOGdhA5T1xODsXlUxaDLb2mXOD0kL6Cm2iAKn82xiZLsnar6SeW5n++qHMd
         KtPnmTS7JTLn83w5AkaRELQ1PeoKOIVBnwc+6l1Xe6UfZ7ICp/R/R+JBMAUhi7Ap7cOQ
         2VYnGy4GRExP7Qh5yOmSD6whgwx8wwXeRoIgGDtxn6u7DO2VRXyqXaDYThioWZoE3HgG
         mS7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5olhRivIG/hHd0cpc7oUvrJOToDW8+BEcztjjWShXR4=;
        b=r5dNPf0RbqJ9K/kh/uDPrr8SsUa6BS5YV1NeI8MnGSLdOAHYqW/73+1BEtI8MeN6zz
         svvZ9HzdO/B9TvwYnqs0VyCPxK6Q3KQPwrw62d/6tnhlyAWYJ1fzDkukmz9ZafwF59TK
         H0Qz0v92Xvj43YRDGxGLOEU0ZY2MaPHraa5Ejf89SR+zZeIZBr2cMf5hq4UhheCVH6XK
         VdT8G0Xn4XcCbQmzncmQC5k//oTE2lWmCGcQ5BUaAsoM6a7DxZrzBjDuHjGVpOvKxz2f
         5vhCVR0F0TtrVD92tgmsFlazDu5Z9Y63/gOZ5BJv8qwJSF6OBBpslztZdXUsDwJmKKEm
         /SUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=cQF1RNTr;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id ey17-20020a05622a4c1100b003e267f85a30si563368qtb.1.2023.04.03.05.27.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Apr 2023 05:27:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id j13so27058502pjd.1
        for <kasan-dev@googlegroups.com>; Mon, 03 Apr 2023 05:27:56 -0700 (PDT)
X-Received: by 2002:a17:90a:b397:b0:23d:1b82:7236 with SMTP id e23-20020a17090ab39700b0023d1b827236mr42253971pjr.16.1680524876113;
        Mon, 03 Apr 2023 05:27:56 -0700 (PDT)
Received: from GL4FX4PXWL.bytedance.net ([139.177.225.248])
        by smtp.gmail.com with ESMTPSA id x5-20020a17090a1f8500b00240ab3c5f66sm6107802pja.29.2023.04.03.05.27.52
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Mon, 03 Apr 2023 05:27:55 -0700 (PDT)
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Peng Zhang <zhangpeng.00@bytedance.com>
Subject: [PATCH v2] mm: kfence: Improve the performance of __kfence_alloc() and __kfence_free()
Date: Mon,  3 Apr 2023 20:27:38 +0800
Message-Id: <20230403122738.6006-1-zhangpeng.00@bytedance.com>
X-Mailer: git-send-email 2.37.0 (Apple Git-136)
MIME-Version: 1.0
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=cQF1RNTr;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Peng Zhang <zhangpeng.00@bytedance.com>
Reply-To: Peng Zhang <zhangpeng.00@bytedance.com>
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

In __kfence_alloc() and __kfence_free(), we will set and check canary.
Assuming that the size of the object is close to 0, nearly 4k memory
accesses are required because setting and checking canary is executed
byte by byte.

canary is now defined like this:
KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)(addr) & 0x7))

Observe that canary is only related to the lower three bits of the
address, so every 8 bytes of canary are the same. We can access 8-byte
canary each time instead of byte-by-byte, thereby optimizing nearly 4k
memory accesses to 4k/8 times.

Use the bcc tool funclatency to measure the latency of __kfence_alloc()
and __kfence_free(), the numbers (deleted the distribution of latency)
is posted below. Though different object sizes will have an impact on the
measurement, we ignore it for now and assume the average object size is
roughly equal.

Before patching:
__kfence_alloc:
avg = 5055 nsecs, total: 5515252 nsecs, count: 1091
__kfence_free:
avg = 5319 nsecs, total: 9735130 nsecs, count: 1830

After patching:
__kfence_alloc:
avg = 3597 nsecs, total: 6428491 nsecs, count: 1787
__kfence_free:
avg = 3046 nsecs, total: 3415390 nsecs, count: 1121

The numbers indicate that there is ~30% - ~40% performance improvement.

Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>
---
 mm/kfence/core.c   | 70 ++++++++++++++++++++++++++++++++--------------
 mm/kfence/kfence.h | 10 ++++++-
 mm/kfence/report.c |  2 +-
 3 files changed, 59 insertions(+), 23 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 79c94ee55f97..b7fe2a2493a0 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -297,20 +297,13 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 	WRITE_ONCE(meta->state, next);
 }
 
-/* Write canary byte to @addr. */
-static inline bool set_canary_byte(u8 *addr)
-{
-	*addr = KFENCE_CANARY_PATTERN(addr);
-	return true;
-}
-
 /* Check canary byte at @addr. */
 static inline bool check_canary_byte(u8 *addr)
 {
 	struct kfence_metadata *meta;
 	unsigned long flags;
 
-	if (likely(*addr == KFENCE_CANARY_PATTERN(addr)))
+	if (likely(*addr == KFENCE_CANARY_PATTERN_U8(addr)))
 		return true;
 
 	atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
@@ -323,15 +316,31 @@ static inline bool check_canary_byte(u8 *addr)
 	return false;
 }
 
-/* __always_inline this to ensure we won't do an indirect call to fn. */
-static __always_inline void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))
+static inline void set_canary(const struct kfence_metadata *meta)
 {
 	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
-	unsigned long addr;
+	unsigned long addr = pageaddr;
+
+	/*
+	 * The canary may be written to part of the object memory, but it does
+	 * not affect it. The user should initialize the object before using it.
+	 */
+	for (; addr < meta->addr; addr += sizeof(u64))
+		*((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
+
+	addr = ALIGN_DOWN(meta->addr + meta->size, sizeof(u64));
+	for (; addr - pageaddr < PAGE_SIZE; addr += sizeof(u64))
+		*((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
+}
+
+static inline void check_canary(const struct kfence_metadata *meta)
+{
+	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
+	unsigned long addr = pageaddr;
 
 	/*
-	 * We'll iterate over each canary byte per-side until fn() returns
-	 * false. However, we'll still iterate over the canary bytes to the
+	 * We'll iterate over each canary byte per-side until a corrupted byte
+	 * is found. However, we'll still iterate over the canary bytes to the
 	 * right of the object even if there was an error in the canary bytes to
 	 * the left of the object. Specifically, if check_canary_byte()
 	 * generates an error, showing both sides might give more clues as to
@@ -339,16 +348,35 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
 	 */
 
 	/* Apply to left of object. */
-	for (addr = pageaddr; addr < meta->addr; addr++) {
-		if (!fn((u8 *)addr))
+	for (; meta->addr - addr >= sizeof(u64); addr += sizeof(u64)) {
+		if (unlikely(*((u64 *)addr) != KFENCE_CANARY_PATTERN_U64))
 			break;
 	}
 
-	/* Apply to right of object. */
-	for (addr = meta->addr + meta->size; addr < pageaddr + PAGE_SIZE; addr++) {
-		if (!fn((u8 *)addr))
+	/*
+	 * If the canary is corrupted in a certain 64 bytes, or the canary
+	 * memory cannot be completely covered by multiple consecutive 64 bytes,
+	 * it needs to be checked one by one.
+	 */
+	for (; addr < meta->addr; addr++) {
+		if (unlikely(!check_canary_byte((u8 *)addr)))
 			break;
 	}
+
+	/* Apply to right of object. */
+	for (addr = meta->addr + meta->size; addr % sizeof(u64) != 0; addr++) {
+		if (unlikely(!check_canary_byte((u8 *)addr)))
+			return;
+	}
+	for (; addr - pageaddr < PAGE_SIZE; addr += sizeof(u64)) {
+		if (unlikely(*((u64 *)addr) != KFENCE_CANARY_PATTERN_U64)) {
+
+			for (; addr - pageaddr < PAGE_SIZE; addr++) {
+				if (!check_canary_byte((u8 *)addr))
+					return;
+			}
+		}
+	}
 }
 
 static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp,
@@ -434,7 +462,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 #endif
 
 	/* Memory initialization. */
-	for_each_canary(meta, set_canary_byte);
+	set_canary(meta);
 
 	/*
 	 * We check slab_want_init_on_alloc() ourselves, rather than letting
@@ -495,7 +523,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 	alloc_covered_add(meta->alloc_stack_hash, -1);
 
 	/* Check canary bytes for memory corruption. */
-	for_each_canary(meta, check_canary_byte);
+	check_canary(meta);
 
 	/*
 	 * Clear memory if init-on-free is set. While we protect the page, the
@@ -751,7 +779,7 @@ static void kfence_check_all_canary(void)
 		struct kfence_metadata *meta = &kfence_metadata[i];
 
 		if (meta->state == KFENCE_OBJECT_ALLOCATED)
-			for_each_canary(meta, check_canary_byte);
+			check_canary(meta);
 	}
 }
 
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 600f2e2431d6..2aafc46a4aaf 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -21,7 +21,15 @@
  * lower 3 bits of the address, to detect memory corruptions with higher
  * probability, where similar constants are used.
  */
-#define KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)(addr) & 0x7))
+#define KFENCE_CANARY_PATTERN_U8(addr) ((u8)0xaa ^ (u8)((unsigned long)(addr) & 0x7))
+
+/*
+ * Define a continuous 8-byte canary starting from a multiple of 8. The canary
+ * of each byte is only related to the lowest three bits of its address, so the
+ * canary of every 8 bytes is the same. 64-bit memory can be filled and checked
+ * at a time instead of byte by byte to improve performance.
+ */
+#define KFENCE_CANARY_PATTERN_U64 ((u64)0xaaaaaaaaaaaaaaaa ^ (u64)(0x0706050403020100))
 
 /* Maximum stack depth for reports. */
 #define KFENCE_STACK_DEPTH 64
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 60205f1257ef..197430a5be4a 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -168,7 +168,7 @@ static void print_diff_canary(unsigned long address, size_t bytes_to_show,
 
 	pr_cont("[");
 	for (cur = (const u8 *)address; cur < end; cur++) {
-		if (*cur == KFENCE_CANARY_PATTERN(cur))
+		if (*cur == KFENCE_CANARY_PATTERN_U8(cur))
 			pr_cont(" .");
 		else if (no_hash_pointers)
 			pr_cont(" 0x%02x", *cur);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230403122738.6006-1-zhangpeng.00%40bytedance.com.
