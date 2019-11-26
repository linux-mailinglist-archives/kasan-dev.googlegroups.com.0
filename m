Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDHC6TXAKGQE7FNZRRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A5CF5109FD6
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 15:05:00 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id s25sf435663wmj.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 06:05:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574777100; cv=pass;
        d=google.com; s=arc-20160816;
        b=iQmAFhOoG8AdG9O/EfJpYlqu65FmyI5T9nW9Gi+aqFOaTsUWz++FVnC3FFY4b2T+Lu
         BEYbZoYm3FbaOqv0GNmO5DyKtkCNyAivYYOt59iaR9om4h+CMMO0jX2xRYcVHJo87TY9
         ByREJDZMVIavLPpTtaZ/VJ5S8/RSiLVWhCcKI3J5Z71AFZuRLuqal792DjswbFViv/4d
         mmgzGXNfYOeGYkj3ujlMMB3GDmNuPAvEjh39rB3a6mavgRWipiWtKLbc82DHTOIu+I8n
         rELK+vwrTc4LVbyXaexD1drX93UWNQgDK95SB9fXRWQpVp/n0+qFo+U4YmfPglLuBY2D
         3UQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=6XE8IL1SoVFdfzILGh/82KPpGi8JFt7lry7c9Z+vUjk=;
        b=ICUc5lehEerMb0FXNZfUvmVsX0IWpzw4JtlNhoJPgW8ajY4DXR8uyr+M/Ifw4xeO5Q
         QuKalqBcIuaxfnY45n208K+fG8hY76KzZt8ofyvBHy041DwCrX/zmgWHXQEWSNsonh47
         nPEms9IwHkeyjz2Z6FKR2c2oXQsWukYK2TI5ooxXYlya/4tKdWTM5v24Y933PkOQOd57
         Jm48aZDbKfxzsfcwfWStCXpQyRga913OkJ+xVIKrvilYQ8iGNOrCgl7BY3gFgX5uhYdc
         8SSHOYhgrO0buc99Rs6sHYrZQVbnnEbfqwYh5alCYKN7+TXWSFd6P76xViMFR/+HVphE
         LR9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EymjOpB0;
       spf=pass (google.com: domain of 3cjhdxqukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CjHdXQUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6XE8IL1SoVFdfzILGh/82KPpGi8JFt7lry7c9Z+vUjk=;
        b=qsrYZ/6n7wGw+POKBdSHutZdKn8/vJ1Td5hgnaxAUo1188leM/to79jrHz4ZrQlYcv
         Jf0ni8f5omWMqw2ry0vRjxNUM2JBGy0XVzKEpjZ/81clS39dBQXUoZPvMaP8Qay8Z/sq
         G3EW0U3J1BElYbAcgmLdokKit1F4R4eVFp+L3ShmIg5BRHPXlIM7CIB3wTB6amcgodVr
         pnXckKHEro5sglU/Jamu3u9BVNMjaup+tabdH63JL4CNtR2kdIdIdXIvUXl+4ojV7Jzz
         AF5o8hBqtwRYpRnuA4vXMuTvfVx/y6tRTufd7aEn1w7degeOmzTV720AEYblv2pD3XV1
         xu/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6XE8IL1SoVFdfzILGh/82KPpGi8JFt7lry7c9Z+vUjk=;
        b=W/1NBl3HOYTOQ7+fbdW2vMZ9r9PSF4ol+k4qk37LrM3E2gIHpXlXUYouqyljWvFEkK
         Vg+y6Wm6esC5DmG+/bod2L7SAyf/H5ZvXfk2DQw/hwUI1IDbJqIF11fjKQnD7/aE0xop
         9ALpnJwo76w01/311j+a0DOQ/2zJBAAGWl8UOVkdEeP9ranG1+ZdIVq8N9eX5+5lC2AE
         pqzp4EVghynT3ejLD+IG2qRWxB275GlEe9BhRf4qUR7Xg+3mvqzYYLGW218QND21eHy1
         i8rmlygeKsd6ambtCM5ZExOAEWYuboES/UgkYFtCl9PDgTywBhUsAe/OcBd4k2AQuFhV
         OAxA==
X-Gm-Message-State: APjAAAW4pMxFNq/LKvAiax+bmdQ3YXCSSGtiR42huoohQR78KGfQG3dz
	8DWEUbe3A1iCiDnf9wS3VhQ=
X-Google-Smtp-Source: APXvYqyVy2fvdzYs7D6GNsulZ/NJbNok3N0zeRMcNi4Ty5V0S9fUjjxQoVa7oxUw5RDoVjtBdKZnCw==
X-Received: by 2002:a5d:4589:: with SMTP id p9mr21565185wrq.61.1574777100313;
        Tue, 26 Nov 2019 06:05:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f305:: with SMTP id q5ls155265wmq.3.canary-gmail; Tue,
 26 Nov 2019 06:04:59 -0800 (PST)
X-Received: by 2002:a7b:c7d3:: with SMTP id z19mr4588905wmk.98.1574777099652;
        Tue, 26 Nov 2019 06:04:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574777099; cv=none;
        d=google.com; s=arc-20160816;
        b=CCkyuyCgSbm1gpv75HDRaLazzdLnMpuolYrlyaP/QPrGA0A2StT4lqlZxLNGXoNZMd
         OTxO7qIVcKmoIwUciHcCsMzavKA63pjUJFKXa4OzQ7iXn22d3omPeusPHGVO54DsfoCG
         qVTSVo9zIB0ikxh3gWh4HSifoaf+rLPmrgPjIfVYsAiQuDVMLkYj9aAefdfErbe7/ZI+
         R1hDS5fJR5CpBgEqnyjS3fTSSFJ1X1RaeG7FkUTpMNSakHSKknrVfuLHzUO+L3uuzNrG
         BdI/S0i040WzwF98WJs1XTJ86r15UFJtaK4Aj0XqkdYW0Cz0rS0Ya6vI6RQ3/eRrGIBR
         01oA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=UhG4TbrFQmzzMiP4BKNG5iQmKmV3aCdN4xUR1YDfRPM=;
        b=tTL7Luou2VG7RCSeWrzXgWfOcCZ1eyyIU7fyyWEgV2vgXlmd2JszJjE5/9r6gGsLjY
         8p2iVp2vxTrTtuaimEVWjx09g6D9hX6xKNiEUyQWiZbVCWEXycyBKQb/D5CbrE5oYnqS
         2BEWQscKNmy0/4CnlueQEqy0F90XHekW1aX47ECkogzMEIK73flnwjuVS86gGtM1CEWb
         QmmZsmhpY5i1v4bhBmVnIdEf1BDDwAXSIn/cCPar3uEQ/eOksDrqnc2l5k4P08HMm260
         zun719YLXhQ4VAx4Y77y6rshd3y9CA6nNC9RHNcNuauUq+5oNRN7U7KnObO/iuEGIE8X
         QeJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EymjOpB0;
       spf=pass (google.com: domain of 3cjhdxqukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CjHdXQUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id l23si176112wmg.0.2019.11.26.06.04.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Nov 2019 06:04:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cjhdxqukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id t9so6523378wru.10
        for <kasan-dev@googlegroups.com>; Tue, 26 Nov 2019 06:04:59 -0800 (PST)
X-Received: by 2002:a5d:694d:: with SMTP id r13mr27765421wrw.395.1574777098959;
 Tue, 26 Nov 2019 06:04:58 -0800 (PST)
Date: Tue, 26 Nov 2019 15:04:06 +0100
In-Reply-To: <20191126140406.164870-1-elver@google.com>
Message-Id: <20191126140406.164870-3-elver@google.com>
Mime-Version: 1.0
References: <20191126140406.164870-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v3 3/3] kcsan: Prefer __always_inline for fast-path
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: mark.rutland@arm.com, paulmck@kernel.org, linux-kernel@vger.kernel.org, 
	will@kernel.org, peterz@infradead.org, boqun.feng@gmail.com, arnd@arndb.de, 
	dvyukov@google.com, linux-arch@vger.kernel.org, kasan-dev@googlegroups.com, 
	Randy Dunlap <rdunlap@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EymjOpB0;       spf=pass
 (google.com: domain of 3cjhdxqukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3CjHdXQUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
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

Prefer __always_inline for fast-path functions that are called outside
of user_access_save, to avoid generating UACCESS warnings when
optimizing for size (CC_OPTIMIZE_FOR_SIZE). It will also avoid future
surprises with compiler versions that change the inlining heuristic even
when optimizing for performance.

Report: http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
Reported-by: Randy Dunlap <rdunlap@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
Rebased on: locking/kcsan branch of tip tree.
---
 kernel/kcsan/atomic.h   |  2 +-
 kernel/kcsan/core.c     | 16 +++++++---------
 kernel/kcsan/encoding.h | 14 +++++++-------
 3 files changed, 15 insertions(+), 17 deletions(-)

diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
index 576e03ddd6a3..a9c193053491 100644
--- a/kernel/kcsan/atomic.h
+++ b/kernel/kcsan/atomic.h
@@ -18,7 +18,7 @@
  * than cast to volatile. Eventually, we hope to be able to remove this
  * function.
  */
-static inline bool kcsan_is_atomic(const volatile void *ptr)
+static __always_inline bool kcsan_is_atomic(const volatile void *ptr)
 {
 	/* only jiffies for now */
 	return ptr == &jiffies;
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 3314fc29e236..c616fec639cd 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -78,10 +78,8 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
  */
 static DEFINE_PER_CPU(long, kcsan_skip);
 
-static inline atomic_long_t *find_watchpoint(unsigned long addr,
-					     size_t size,
-					     bool expect_write,
-					     long *encoded_watchpoint)
+static __always_inline atomic_long_t *
+find_watchpoint(unsigned long addr, size_t size, bool expect_write, long *encoded_watchpoint)
 {
 	const int slot = watchpoint_slot(addr);
 	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
@@ -146,7 +144,7 @@ insert_watchpoint(unsigned long addr, size_t size, bool is_write)
  *	2. the thread that set up the watchpoint already removed it;
  *	3. the watchpoint was removed and then re-used.
  */
-static inline bool
+static __always_inline bool
 try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
 {
 	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
@@ -160,7 +158,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
 	return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) != CONSUMED_WATCHPOINT;
 }
 
-static inline struct kcsan_ctx *get_ctx(void)
+static __always_inline struct kcsan_ctx *get_ctx(void)
 {
 	/*
 	 * In interrupts, use raw_cpu_ptr to avoid unnecessary checks, that would
@@ -169,7 +167,7 @@ static inline struct kcsan_ctx *get_ctx(void)
 	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
 }
 
-static inline bool is_atomic(const volatile void *ptr)
+static __always_inline bool is_atomic(const volatile void *ptr)
 {
 	struct kcsan_ctx *ctx = get_ctx();
 
@@ -193,7 +191,7 @@ static inline bool is_atomic(const volatile void *ptr)
 	return kcsan_is_atomic(ptr);
 }
 
-static inline bool should_watch(const volatile void *ptr, int type)
+static __always_inline bool should_watch(const volatile void *ptr, int type)
 {
 	/*
 	 * Never set up watchpoints when memory operations are atomic.
@@ -226,7 +224,7 @@ static inline void reset_kcsan_skip(void)
 	this_cpu_write(kcsan_skip, skip_count);
 }
 
-static inline bool kcsan_is_enabled(void)
+static __always_inline bool kcsan_is_enabled(void)
 {
 	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
 }
diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index b63890e86449..f03562aaf2eb 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -59,10 +59,10 @@ encode_watchpoint(unsigned long addr, size_t size, bool is_write)
 		      (addr & WATCHPOINT_ADDR_MASK));
 }
 
-static inline bool decode_watchpoint(long watchpoint,
-				     unsigned long *addr_masked,
-				     size_t *size,
-				     bool *is_write)
+static __always_inline bool decode_watchpoint(long watchpoint,
+					      unsigned long *addr_masked,
+					      size_t *size,
+					      bool *is_write)
 {
 	if (watchpoint == INVALID_WATCHPOINT ||
 	    watchpoint == CONSUMED_WATCHPOINT)
@@ -78,13 +78,13 @@ static inline bool decode_watchpoint(long watchpoint,
 /*
  * Return watchpoint slot for an address.
  */
-static inline int watchpoint_slot(unsigned long addr)
+static __always_inline int watchpoint_slot(unsigned long addr)
 {
 	return (addr / PAGE_SIZE) % CONFIG_KCSAN_NUM_WATCHPOINTS;
 }
 
-static inline bool matching_access(unsigned long addr1, size_t size1,
-				   unsigned long addr2, size_t size2)
+static __always_inline bool matching_access(unsigned long addr1, size_t size1,
+					    unsigned long addr2, size_t size2)
 {
 	unsigned long end_range1 = addr1 + size1 - 1;
 	unsigned long end_range2 = addr2 + size2 - 1;
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191126140406.164870-3-elver%40google.com.
