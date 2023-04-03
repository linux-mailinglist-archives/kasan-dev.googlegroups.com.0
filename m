Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBDPEVGQQMGQEBXU4CMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id B2F196D3D54
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Apr 2023 08:28:31 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id q1-20020a656841000000b0050be5e5bb24sf8007371pgt.3
        for <lists+kasan-dev@lfdr.de>; Sun, 02 Apr 2023 23:28:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680503310; cv=pass;
        d=google.com; s=arc-20160816;
        b=IIbAftCS1gWQDoWJf5nh87NwNhVl0E/FvbomIKulSYXsr/VqVPaN5D3Dqn3YcDvX8i
         hFjUfX/+EKJLtCTgyZ2EJ9mDq3B9+Ry+/584XqWtgYdrdeWZsYCWbwESg6FgmmXnxg4k
         d7ZzyEI//t/GGVfcVzk0HynsSu2TVmwCYzLqK3k99UXtM30N5XtCIDO63XbLNb+9DxPA
         EQLkynbd1IGmkc1DQjhUMgwFwHxYysezAcsNEhspDR55EeF5o6iXzigJKCUwv8LGm6ET
         NIF7ulxsEKsyBHKUsYKb6T3W/K2UZgAthIjHgcCVsLZcJ+LoT0Pofmm5WnnCdWWJuhc+
         MD6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=TDjlsXJ8Q67+pf8fNbtIezk015NwG2ejDnnB/VIiXKc=;
        b=kvRGMKA3eshhXBWUjldc9llUjtCsN6lzZXvZosELkxx4p63zaeB389tsANkaYBX3q3
         n1GZx5ZxNOHsl6RopLvWAui3qYhHgEjpJfLNZbbETYcQ6I9KFummfddBB6UO8tf7VruS
         JzwNNnQWOq3SSkdWQcQflV0hmmh6QugK2MP1bzzfOKhW69EL8ED/ClVWwMW0qRFyVbnw
         BgeOI+2V+2YobaoyVoZ/yriinoqWTYh/QloB3jEssXSDWicWO+xSCsfmxiO/MlbGauVZ
         j7p/7YYo/tN/QQu9WTxhGOZ5x0n9Wgp7VmRFL7PyhQn4l94z9vKWKJm9vpfu+Z1+O5XV
         9gEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=fIWatEyL;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680503310;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TDjlsXJ8Q67+pf8fNbtIezk015NwG2ejDnnB/VIiXKc=;
        b=rd5zq1KLajV81gL2GLDeQEoXwdVBeNP3jrt3aZEUDwB33FLwi+xH0nYW2n4dDXmyxy
         cDZvRgDI8nfLiy0M6bIY5aWS0wgq08WLVFpbBmkdZJoXMop0mhC+EwyaQYGDAwagG0jZ
         U3m9JhCKaYbESjqx4WFSspxx8BrSheE5eX3Cvj7OGHs5GgUm+z6LQoz8oc364kR6mP6p
         5u+B20bcflAUJYvayDJL9B8XYVJEEoRhhw7rLXu29HIUC5xpfW83ZIYdSQgRQ8WAWL+a
         /4juTb5y84/jPJ+61aKAQrvgrXqfsIA6fsybsEkyH35oiHMwiudf8/hXOFrocZX4tPi6
         iP0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680503310;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TDjlsXJ8Q67+pf8fNbtIezk015NwG2ejDnnB/VIiXKc=;
        b=fqyglCDVg1aD3miLI5Vto06J0M5NBXzyQhjzM8Vi5TsxMAzl9qpmsg+uRgaSArBFKA
         l1fdPpdF1jbnijNUNzLS6E9OCeTT0w8EbLYGjyPOUMvccoeHWVugaH5KZnrUmT7G/End
         G+zVB+9hotySa2jKJyMPw0cOgCx4AmAQX3k7FFIQKz6B94+MkSoch3KbOlv+U5rMZ72p
         jI7cHppG35D4sNrHeHZWmu2mKinZP7gvAU2cs1gU9ZX6UR9AGeq/5Y7qQCdX/b/N/ZPk
         p6Lwte6a7T/KY1KPaOqW4GEc3Km1oVvVMSnp63NOtYy5n7Fi4pmLhkyh7Xh6PrJZyDsA
         HBGw==
X-Gm-Message-State: AAQBX9dObKpNRP5MGLJdPPhvnw23otVBBZU40tR+g2s2oxjW82eVANnr
	E2VEXW/YO3l1ln1SFd/g7ec=
X-Google-Smtp-Source: AKy350YadrveaMkbUUuO6N+2FI263Yd9ARe5z/h2Y878jKD3Z1ooInoawelkOv+u1Eh1DfE7ZVVCIw==
X-Received: by 2002:a17:903:454:b0:1a0:5057:1b77 with SMTP id iw20-20020a170903045400b001a050571b77mr11780485plb.10.1680503309810;
        Sun, 02 Apr 2023 23:28:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2843:b0:194:d87a:ffa6 with SMTP id
 kq3-20020a170903284300b00194d87affa6ls10325078plb.1.-pod-prod-gmail; Sun, 02
 Apr 2023 23:28:29 -0700 (PDT)
X-Received: by 2002:a17:903:11cf:b0:1a3:c8c2:c322 with SMTP id q15-20020a17090311cf00b001a3c8c2c322mr615579plh.29.1680503309011;
        Sun, 02 Apr 2023 23:28:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680503309; cv=none;
        d=google.com; s=arc-20160816;
        b=U/294/JpWZ04RCZCvzomjdwIkGxeA1o9idkx2DqlWjaFIqIgOchOllynMn/Dq69NpX
         mc93VKWlK/hcBP4bD9f14meytEe2KPTAF5zRZWZrl4IwMHxpCDGMzJXmajNv2e6iY0j6
         afslSTMReJHZ9dxl/7+Ti/TCmyLQc4daYzeH0CfeuDCAl/FP93rLixEmF+xeWM7qoxh0
         XMA7y3twX/mj5z1Ic1tMAL2RQZlFeH8QsVqI9VF4/IqkeTcHJJzG+cemBqgjGkz0T5GN
         2P72cSLeEcBf72k1n4jmucPebylNEAq6d/rcnQEeIVhBso7AwlHf5bWWqQ5ArIDKP/EE
         DCpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=8EZusFPyKlVLlAuor8AkBQgzEgMdx910d6xeQgDfz4M=;
        b=iGlTVL5PN4f3bif3Rp64WaNt0Tsq0mNSZxuEJv0Tz2jid4j7T+hCLntudQr3vYwFQ9
         sLWrBwra8y/bnb4oWyr/hhZUYTBQNXKt+xUGmsxMRJK1f75Poa720N5JLeg4kJYrxdL4
         8zkBB7JRRy+m4njx6xVV9TQPd57vX/oQAQ0y4cuhiMAeZLfeLhad3oTWKAbiHqsNJsat
         7RsQfsYVJe8pGstfAvqQa13v8DSshPXDfeaI6HAPB+ou4Bb+8VJ7btIug/kgLq6nLpIj
         SGHMJmKyJZOXG+wbGnGroyboJLcNd5rKgcR1YU1tUci7pFGuX6aB/HTRYxxN9CRiFj9O
         8Orw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=fIWatEyL;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id z10-20020a170902ccca00b0019cb7349e64si433486ple.8.2023.04.02.23.28.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 02 Apr 2023 23:28:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id cv11so5592044pfb.8
        for <kasan-dev@googlegroups.com>; Sun, 02 Apr 2023 23:28:28 -0700 (PDT)
X-Received: by 2002:a62:6346:0:b0:626:cc72:51a7 with SMTP id x67-20020a626346000000b00626cc7251a7mr34281634pfb.9.1680503308511;
        Sun, 02 Apr 2023 23:28:28 -0700 (PDT)
Received: from GL4FX4PXWL.bytedance.net ([139.177.225.248])
        by smtp.gmail.com with ESMTPSA id k14-20020aa7820e000000b00625ee4c50eesm6013919pfi.77.2023.04.02.23.28.24
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Sun, 02 Apr 2023 23:28:28 -0700 (PDT)
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Peng Zhang <zhangpeng.00@bytedance.com>
Subject: [PATCH] mm: kfence: Improve the performance of __kfence_alloc() and __kfence_free()
Date: Mon,  3 Apr 2023 14:27:57 +0800
Message-Id: <20230403062757.74057-1-zhangpeng.00@bytedance.com>
X-Mailer: git-send-email 2.37.0 (Apple Git-136)
MIME-Version: 1.0
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=fIWatEyL;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
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

Before playing patch:
__kfence_alloc:
avg = 5055 nsecs, total: 5515252 nsecs, count: 1091
__kfence_free:
avg = 5319 nsecs, total: 9735130 nsecs, count: 1830

After playing patch:
__kfence_alloc:
avg = 3597 nsecs, total: 6428491 nsecs, count: 1787
__kfence_free:
avg = 3046 nsecs, total: 3415390 nsecs, count: 1121

The numbers indicate that there is ~30% - ~40% performance improvement.

Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>
---
 mm/kfence/core.c   | 71 +++++++++++++++++++++++++++++++++-------------
 mm/kfence/kfence.h | 10 ++++++-
 mm/kfence/report.c |  2 +-
 3 files changed, 62 insertions(+), 21 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 79c94ee55f97..0b1b1298c738 100644
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
@@ -323,11 +316,27 @@ static inline bool check_canary_byte(u8 *addr)
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
 	 * We'll iterate over each canary byte per-side until fn() returns
@@ -339,14 +348,38 @@ static __always_inline void for_each_canary(const struct kfence_metadata *meta,
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
+	 * If the canary is damaged in a certain 64 bytes, or the canay memory
+	 * cannot be completely covered by multiple consecutive 64 bytes, it
+	 * needs to be checked one by one.
+	 */
+	for (; addr < meta->addr; addr++) {
+		if (unlikely(!check_canary_byte((u8 *)addr)))
+			break;
+	}
+
+	/*
+	 * Apply to right of object.
+	 * For easier implementation, check from high address to low address.
+	 */
+	addr = pageaddr + PAGE_SIZE - sizeof(u64);
+	for (; addr >= meta->addr + meta->size ; addr -= sizeof(u64)) {
+		if (unlikely(*((u64 *)addr) != KFENCE_CANARY_PATTERN_U64))
+			break;
+	}
+
+	/*
+	 * Same as above, checking byte by byte, but here is the reverse of
+	 * the above.
+	 */
+	addr = addr + sizeof(u64) - 1;
+	for (; addr >= meta->addr + meta->size; addr--) {
+		if (unlikely(!check_canary_byte((u8 *)addr)))
 			break;
 	}
 }
@@ -434,7 +467,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 #endif
 
 	/* Memory initialization. */
-	for_each_canary(meta, set_canary_byte);
+	set_canary(meta);
 
 	/*
 	 * We check slab_want_init_on_alloc() ourselves, rather than letting
@@ -495,7 +528,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
 	alloc_covered_add(meta->alloc_stack_hash, -1);
 
 	/* Check canary bytes for memory corruption. */
-	for_each_canary(meta, check_canary_byte);
+	check_canary(meta);
 
 	/*
 	 * Clear memory if init-on-free is set. While we protect the page, the
@@ -751,7 +784,7 @@ static void kfence_check_all_canary(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230403062757.74057-1-zhangpeng.00%40bytedance.com.
