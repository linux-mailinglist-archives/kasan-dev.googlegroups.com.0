Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD476TXAKGQEPE44U4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E7EF109D1D
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 12:42:08 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id h16sf3659819ljk.20
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 03:42:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574768527; cv=pass;
        d=google.com; s=arc-20160816;
        b=C4gBbEHGlfC7bWFSQT0Xar8Amowkv2kuRb3+ke4q71bJhpzT04GvBRrgNUazRaWhrV
         hAz/HZgoszhd/muf/8SyP7evwkgtJqEoEuArJg8D0SV6mr9fIxmRjWO1m8NJ5qtMOv/v
         slGHzBZLwjVO1im3uXRvrD8zy4s1FBEKhVL6dBG05xj5O11Iw8DC/Tj6eM4ZA11X5gDw
         7kDnNe5E/86PM9nQhzgrEgtaMha7J5+OdI+WbiH067AvG1f2vgnMDf432z1fRYiFvvnk
         tQq1qLIY2Wfu4aqdPhrIZ8hS4owYC5epm4q/UN8kYni7YRnKfGLIuF97B0pGmFTHthq/
         /DPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=w3RqBDcWuBV6NLDXp2/bATwqAH9YT5EwJNljXzTeaTo=;
        b=k1p5TiZcvAzbH3EoSVu4GKuudCFVdgodPQlGZoubz0C1HHKxGaxW4op8SotTNvEY47
         StB1LiQBfPTMacXw8W16sGInqsD+R+MUIJpnMgrYUZ+EHQ1nZECeQpMf0rRJY9Cy/3t1
         zhYj3TUQn0FW9RQiaoJk+wYL/r3CHAQfh2skAwNPlT8AtH46C/Y4NGY/qBhfU9RRcOAO
         /R2ULhHxBsqkBg7tfQFZ/6rw+f1Xv/yHxdkpRBHAbJtl2v1sl3q6UbdlZn+r4a9wuFnm
         +8ffM3KSWY0BDMhhP4h3x3iZb2jCsnV6kVogc6rZwHFPUrMYXkm9mKDAcfYOUc6iPgnS
         iigw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pfMouhbR;
       spf=pass (google.com: domain of 3jg_dxqukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3jg_dXQUKCRc18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w3RqBDcWuBV6NLDXp2/bATwqAH9YT5EwJNljXzTeaTo=;
        b=GOkPUBogngV98c+v4Tim0bFeSt5XbQTiVVxjs8cD+v//7z2dhd4GYCk9+Bw5bx/YSP
         GTCtpslHArj8LgJcoSaLidFQ4a1YId0kQ2lk/DyNn6u7/SuZLGPMY1frkglywn+H9XFv
         jmZCvIRmVKYn0k3mzMBOaZNksmuM23iqqIpmA1sp3NdR7W8fOF8pxLWCcEBAeAZgzF1l
         gMx5kqv8ar3oeH7g+9AdzQmMJlDESYnieV5wNY2/I6Qkoqkx/YIJpsaPvn8pcWUl8Cgw
         EtXQnt9YzmDPqokgEQgcXQxyxfk6LttFP9caidGppNkdr5sqKRDW/o41IqfyGYOk5GHt
         ehtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w3RqBDcWuBV6NLDXp2/bATwqAH9YT5EwJNljXzTeaTo=;
        b=sDcGikf+Pa45IG3iX8j3gjwNPT8Q7+bF3Qtq++zZaXpKZs19tITRFm6iZzffm3nOFe
         Ia/QQAAl06TOSVkFbPQYc0kE6YaYY/UFP+dyaEPIiewidoLjK8/wYNp0fV4aOr1BC4ef
         T0W/Aofuxj5DI4zb6J+Q0ehnM8nbCOCpDDzfG4vCDH2m7w2fx/k5pbPHhUe8ABRZEXNH
         /+xLy8vx0/+RcAgZN7Ei/MAMDD4u3ir6yi9bu25bcduDcsRRXf1IZRYSH8kztiIIgnun
         Xu9t1Cua6iFCYSYBd6y7wEhwT9BbomX3WCSEtd5SbwyWPQe4Wx65hGzzMl/FG8nVR/TT
         s7pQ==
X-Gm-Message-State: APjAAAVQTYQPa7QktqJJrbIXbnFymF/AFxxWK98MQ7eO9pY5aHECH2NR
	xHhZkN8hIZUCBaMFbdOQriw=
X-Google-Smtp-Source: APXvYqz4SNVFu5nDYwZDkJJ89dDwoBIHKO4iLdS71taadSKN0HKh/8VjLORSG2UZ39bEOkJdPGkblA==
X-Received: by 2002:a19:22c4:: with SMTP id i187mr22852578lfi.152.1574768527733;
        Tue, 26 Nov 2019 03:42:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2e01:: with SMTP id u1ls2824632lju.12.gmail; Tue, 26 Nov
 2019 03:42:06 -0800 (PST)
X-Received: by 2002:a2e:3311:: with SMTP id d17mr26918617ljc.237.1574768526914;
        Tue, 26 Nov 2019 03:42:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574768526; cv=none;
        d=google.com; s=arc-20160816;
        b=TMbsqgIL2wpYXbNmziUZDiVq0lR4F6RpC8Vp8EwSuFzfjklrkV+0tWki5TSysaQI3h
         3PgvfuNpH8HkcbwYhrrUL7ywWYsZZOoOl7nHOjkPOzgSkqi4rTYMeSevxi1dZR38MXQD
         vqp2nV5K3kqj9gfkk0+frM0rbez55+N7ldFhOJiaWZ8qodRX08FjmJV5wGH+Am1u514R
         HKuRcgLH20mfouDgOtkQb9Qr5vM2iQwd1zjGsgi/goSNbNU8bO5m+oZWb7Czr9WupZV/
         AuoOmfiRQP7/u0jkAKkf8omoz6WdTMFkNlRt+2kCLZNpvjoXLn7XQZtBBbV5/9J9ttqF
         PuqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=UhG4TbrFQmzzMiP4BKNG5iQmKmV3aCdN4xUR1YDfRPM=;
        b=geDGbawKs8GeTuilz+OC94k1dZGeV6dvzgU33X9w1SpoiUal/0QafFOJemn9M3pTU2
         MW0hfeEZEvFP2s/8mRL1S1nj4/MRJLaerbYlf6muZp01QdMTiastalgTHl4UvUgLhV59
         pci5PdIjSxdG6yFWS7Pv71YujJbqR200h0wO4JJwzvGV4OY56YL5G/JGjoeye4QDdQ9Q
         aTEnSk7pdsSBQ8LRO7/kkUVJy+b6dH9iUGcc9Ef4SQEAtLSONjpLGYFCGzBXE/eoEqEk
         0ZExBeB3DHTvgn/RcdGx3xBncQbTWoKPVS0/J9pZkHScJTE9DdiACsFBHinPsQRjuUA5
         X7kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pfMouhbR;
       spf=pass (google.com: domain of 3jg_dxqukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3jg_dXQUKCRc18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f11si661972lfm.2.2019.11.26.03.42.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Nov 2019 03:42:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jg_dxqukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id q12so10444315wrr.3
        for <kasan-dev@googlegroups.com>; Tue, 26 Nov 2019 03:42:06 -0800 (PST)
X-Received: by 2002:a5d:46c1:: with SMTP id g1mr15855542wrs.200.1574768526170;
 Tue, 26 Nov 2019 03:42:06 -0800 (PST)
Date: Tue, 26 Nov 2019 12:41:21 +0100
In-Reply-To: <20191126114121.85552-1-elver@google.com>
Message-Id: <20191126114121.85552-3-elver@google.com>
Mime-Version: 1.0
References: <20191126114121.85552-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v2 3/3] kcsan: Prefer __always_inline for fast-path
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: will@kernel.org, peterz@infradead.org, boqun.feng@gmail.com, arnd@arndb.de, 
	dvyukov@google.com, linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, 
	kasan-dev@googlegroups.com, mark.rutland@arm.com, paulmck@kernel.org, 
	Randy Dunlap <rdunlap@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pfMouhbR;       spf=pass
 (google.com: domain of 3jg_dxqukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3jg_dXQUKCRc18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191126114121.85552-3-elver%40google.com.
