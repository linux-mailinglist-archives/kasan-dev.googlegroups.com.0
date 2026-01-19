Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMHYW7FQMGQE3UBBWFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 33085D3A354
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 10:41:06 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-64d0f9057b3sf312960a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 01:41:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768815665; cv=pass;
        d=google.com; s=arc-20240605;
        b=KVxIHyYhZrKjEaes9yAxA55FJQQntkXKVXRyrtk9dRoRadzvw7HSDPD+1aqci8XHxW
         raEtgsYPE+2c1BQTM/j9P8RRYlpQZgDTKJqaRPudm86yi3fm9BYEYoDTEjdWI3+XFrfP
         2tc/u2Ih0rV7uU0bn9bp36+/p8911ZcoPHGX9eTIy1iB4jWWK/NQVvbEPBpoDqkjksO5
         aQTDrStHGSc1LtpwKhsd2jlBkCEgMWOvlLktdd/zGkpWzL4i8rWJQ9pyvpmi2RLpUhBT
         8KYElrBWqwFFCn7y0AOLxCncr0IRXNrk2Ut/wjdfxt/eFPMC8VxlaZBK7ejc5PvtyPOG
         cEmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=b2Eqi4adAk9beFNdXLT8PwJ2/rPGn/OmRccZwN9B8I8=;
        fh=iut9rRXO4of/hPy6j545wWCNoysKhUnmtq+nzffkcBo=;
        b=F6sQz/TCCn5DKlKm1n5WUtlWbiSfh/AROZV3TcdgTxujVP8KbpHEUBPj97cz3qy3zI
         EcKY5owmGpQz2NeJaU04CH0NJaBkqc7BuQOzxoJ9fgNaG5YncpAr6/G/tiYYgdpDNe9G
         UC/kKXZsfC9I3XTf4yPn0qFYfbHC91nIUoz6l/WZffKm1TnmU0Fx8nEpapthhHKhlqY+
         8XcS9a8L8g9gvZ3zJ7ZqZN09GhPsWVWpxWAdQLnr2t+T6TRimoQQf9ElhST3vc3c6cBe
         K73/3RCiySGReIg+DvAxACuM5WHEiUfw4t713xtekt8LJYuIvtDrtg+Va9akY4qjt06B
         HvFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zoNvdDIt;
       spf=pass (google.com: domain of 3lvxtaqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3LvxtaQUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768815665; x=1769420465; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=b2Eqi4adAk9beFNdXLT8PwJ2/rPGn/OmRccZwN9B8I8=;
        b=Mcl/HxPoW4NsSvun7gAwfWWWEt6z32K8APYQEUcU7X7WUy+Lt4cn9HAXKpM1nO3sKq
         hblO1xaM+Vx0jq7e1zWZ7gsmRRIk1qTnhRr4YAoN9mpcFItIeGCIWno4ifGUFZ1neXJT
         QGX3sUBk7hwmojFB011Wcz9dUjEy+pme0q/QdtVNFekKoiGEswcen9rU7UH9YvsUMsHp
         Z3F6yf5bNN8jb61SJdG9rK7bRGdCNhg4VdyrDIBeVUhXXjc4lx6/cR6MlSnPns6vAcMP
         8uByIZ2Ker6xhaPyN38w70P2UimPMafdoiPx0MkO31eBws8cUKzkh3Zl2j+ceVS+mpwi
         tMYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768815665; x=1769420465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b2Eqi4adAk9beFNdXLT8PwJ2/rPGn/OmRccZwN9B8I8=;
        b=hwU0XjSVoxH6/FmsFnhOgQR/4H3DDTiuUJ1oJ6juFLIVRxFujWbwDsKbMKQvXnGvt9
         ErYXClJcUc+w+u9DJnXRKpJf+h0/6eTnV3hljQIcwVMszsKRHAzAXjD5jkxpx1xLT7w9
         QGxNghxyQa/YQvrucRN4LpJ3BPpYAnjNijBrWJdW6MsOC8POMS/u3FvqocCZVt7Q3PYz
         HGqW0D74TwUydLN7+R/QSPd9jvIZTPfYH9soQvr1JoffdLh9jDwms+YJSqKT1nx0vaiJ
         CkOfIZ4M6pZILY7RDRR2U3s0bRPu0AIgkzz4IakUG/GuIakniLgdNkVfvqGOrTq3Vgdq
         7DyA==
X-Forwarded-Encrypted: i=2; AJvYcCWl6RoEEeY9+4gclaNWr3kiAD17cUWFCsjclIMMlNrvkZk0S+ViNVj4ofG+/nxik0wDtdf4vw==@lfdr.de
X-Gm-Message-State: AOJu0YxSU4/YnJHF+UoMTNonqdk5TSUf8PeEQfuTvSsEhoxz5ivdj3mY
	sXifZyEeKHXQVSrk/gS5MWD0W0Mb9ylxrKRSJ4P4ZpS/u5ng2l9quPbK
X-Received: by 2002:a05:6402:3487:b0:64d:1bbf:9548 with SMTP id 4fb4d7f45d1cf-65452cd78f9mr4651663a12.6.1768815665402;
        Mon, 19 Jan 2026 01:41:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HaIvcxTtjmZmcpUYkcJGv5Sy1zRO3GIZlpOdveCd5lGg=="
Received: by 2002:a05:6402:a247:20b0:64d:faf4:f73e with SMTP id
 4fb4d7f45d1cf-6541bd8aa4els2725470a12.0.-pod-prod-05-eu; Mon, 19 Jan 2026
 01:41:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVKT/a/wf0sxJuGaIuDRBm0q+eZ22f5e6JrvEo6QQa3qpNIYOT8qfB5T0EVjC+Znm0jLI3a6JrhjoE=@googlegroups.com
X-Received: by 2002:a17:907:3da8:b0:b77:1a42:d5c0 with SMTP id a640c23a62f3a-b8796b3ed8cmr818973066b.43.1768815662776;
        Mon, 19 Jan 2026 01:41:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768815662; cv=none;
        d=google.com; s=arc-20240605;
        b=h+p0FOkThAF+QhAgA/2Nk9odny4sL5BcBN5iiTVhanZ3312nV4M6i7Hl2RPXo6GaPL
         0KTrkHuVAQKp5NvW9Vd5UvUJDdSbPxcM4GS5ikWNFHrOnvOEOXyRxArBXkGc7BM+SnjX
         QGVGPeNQKtszS0TsDy9SXe1L0bf14hl3jX6nNU/UwtMt5rG5fDYrdtKq3l/sLVA2E6dG
         mDdI5NjSSMdOycaDN7aA9N3CKKQ8YTFPiOPOX2QUnrR+Qvb3A2awTO0vkkTGS7un0gMn
         RpWNCVYWxdUeTghuIFFzpEnC2tKpIv6GX7taCfVjqUCtAwemsPk1VzBq6RoW8BHwwJjN
         dA7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hOlRW9xg19eCgYwriGsA0YBy8PVXki3QHZit/P09OME=;
        fh=oY0qX85VU2Y8wxUH0V19cCdugacOCAloSXAXZnKYSak=;
        b=VevDF4xp2iDhaoIngpoTWRyeQ7VpIrSU/1xA/HsnQ0KBa3onArmZZRWaHu/K+fCseh
         Vo/atAhx3CIRM6eYrPEX8kwLrlWZRTZvAwg2iPugBz53/f24GWtdfKTkiwe0obQbXsoX
         mLc/bJwq1ZGYJQceOly2+Da5C2YZk6sogBFydR2HIbrROcqP3N8Na5rxoCSB+2ukuLdp
         wG0tanw4erHm0CRmFDCDMFcK2dTfzlf4XzoLpKHFtTXfGBXDJ1hF3anzPkqsua0l3nxf
         2l7NnfYGgCAVAuxsGGTPbMJiDFne7/B9go5GrHBX/XL5i9Wfdnzb2XraB0UCtZLk3UZz
         QiWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zoNvdDIt;
       spf=pass (google.com: domain of 3lvxtaqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3LvxtaQUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b87959e0a04si11956866b.4.2026.01.19.01.41.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 01:41:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lvxtaqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-b86fd61e3b4so459327866b.0
        for <kasan-dev@googlegroups.com>; Mon, 19 Jan 2026 01:41:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUSXl0x7k3t0VamJhgOAvIgFmFv18fiWWQXLGyFde8iHLlTKIhzFlJHAWyOL/SLYVrd3TYcHsfY9lE=@googlegroups.com
X-Received: from ejek27.prod.google.com ([2002:a17:906:2a5b:b0:b7a:21aa:899e])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:3f21:b0:b87:25a7:3ea0
 with SMTP id a640c23a62f3a-b87968f6e82mr875438166b.25.1768815662390; Mon, 19
 Jan 2026 01:41:02 -0800 (PST)
Date: Mon, 19 Jan 2026 10:05:56 +0100
In-Reply-To: <20260119094029.1344361-1-elver@google.com>
Mime-Version: 1.0
References: <20260119094029.1344361-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.457.g6b5491de43-goog
Message-ID: <20260119094029.1344361-7-elver@google.com>
Subject: [PATCH tip/locking/core 6/6] compiler-context-analysis: Remove
 __assume_ctx_lock from initializers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Waiman Long <longman@redhat.com>, 
	Christoph Hellwig <hch@lst.de>, Steven Rostedt <rostedt@goodmis.org>, Bart Van Assche <bvanassche@acm.org>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-security-module@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zoNvdDIt;       spf=pass
 (google.com: domain of 3lvxtaqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3LvxtaQUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Remove __assume_ctx_lock() from lock initializers.

Implicitly asserting an active context during initialization caused
false-positive double-lock errors when acquiring a lock immediately after its
initialization. Moving forward, guarded member initialization must either:

	1. Use guard(type_init)(&lock) or scoped_guard(type_init, ...).
	2. Use context_unsafe() for simple initialization.

Link: https://lore.kernel.org/all/57062131-e79e-42c2-aa0b-8f931cb8cac2@acm.org/
Reported-by: Bart Van Assche <bvanassche@acm.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/local_lock_internal.h | 3 ---
 include/linux/mutex.h               | 1 -
 include/linux/rwlock.h              | 3 +--
 include/linux/rwlock_rt.h           | 1 -
 include/linux/rwsem.h               | 2 --
 include/linux/seqlock.h             | 1 -
 include/linux/spinlock.h            | 5 +----
 include/linux/spinlock_rt.h         | 1 -
 include/linux/ww_mutex.h            | 1 -
 lib/test_context-analysis.c         | 6 ------
 10 files changed, 2 insertions(+), 22 deletions(-)

diff --git a/include/linux/local_lock_internal.h b/include/linux/local_lock_internal.h
index 4521c40895f8..ebfcdf517224 100644
--- a/include/linux/local_lock_internal.h
+++ b/include/linux/local_lock_internal.h
@@ -87,13 +87,11 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_PERCPU);			\
 	local_lock_debug_init(lock);				\
-	__assume_ctx_lock(lock);				\
 } while (0)
 
 #define __local_trylock_init(lock)				\
 do {								\
 	__local_lock_init((local_lock_t *)lock);		\
-	__assume_ctx_lock(lock);				\
 } while (0)
 
 #define __spinlock_nested_bh_init(lock)				\
@@ -105,7 +103,6 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_NORMAL);			\
 	local_lock_debug_init(lock);				\
-	__assume_ctx_lock(lock);				\
 } while (0)
 
 #define __local_lock_acquire(lock)					\
diff --git a/include/linux/mutex.h b/include/linux/mutex.h
index 6b12009351d2..ecaa0440f6ec 100644
--- a/include/linux/mutex.h
+++ b/include/linux/mutex.h
@@ -62,7 +62,6 @@ do {									\
 	static struct lock_class_key __key;				\
 									\
 	__mutex_init((mutex), #mutex, &__key);				\
-	__assume_ctx_lock(mutex);					\
 } while (0)
 
 /**
diff --git a/include/linux/rwlock.h b/include/linux/rwlock.h
index 65a5b55e1bcd..3390d21c95dd 100644
--- a/include/linux/rwlock.h
+++ b/include/linux/rwlock.h
@@ -22,11 +22,10 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__rwlock_init((lock), #lock, &__key);			\
-	__assume_ctx_lock(lock);				\
 } while (0)
 #else
 # define rwlock_init(lock)					\
-	do { *(lock) = __RW_LOCK_UNLOCKED(lock); __assume_ctx_lock(lock); } while (0)
+	do { *(lock) = __RW_LOCK_UNLOCKED(lock); } while (0)
 #endif
 
 #ifdef CONFIG_DEBUG_SPINLOCK
diff --git a/include/linux/rwlock_rt.h b/include/linux/rwlock_rt.h
index 37b387dcab21..5353abbfdc0b 100644
--- a/include/linux/rwlock_rt.h
+++ b/include/linux/rwlock_rt.h
@@ -22,7 +22,6 @@ do {							\
 							\
 	init_rwbase_rt(&(rwl)->rwbase);			\
 	__rt_rwlock_init(rwl, #rwl, &__key);		\
-	__assume_ctx_lock(rwl);				\
 } while (0)
 
 extern void rt_read_lock(rwlock_t *rwlock)	__acquires_shared(rwlock);
diff --git a/include/linux/rwsem.h b/include/linux/rwsem.h
index ea1bbdb57a47..9bf1d93d3d7b 100644
--- a/include/linux/rwsem.h
+++ b/include/linux/rwsem.h
@@ -121,7 +121,6 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
-	__assume_ctx_lock(sem);					\
 } while (0)
 
 /*
@@ -175,7 +174,6 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
-	__assume_ctx_lock(sem);					\
 } while (0)
 
 static __always_inline int rwsem_is_locked(const struct rw_semaphore *sem)
diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 22216df47b0f..c0c6235dff59 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -817,7 +817,6 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
 	do {								\
 		spin_lock_init(&(sl)->lock);				\
 		seqcount_spinlock_init(&(sl)->seqcount, &(sl)->lock);	\
-		__assume_ctx_lock(sl);					\
 	} while (0)
 
 /**
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index 7b11991c742a..e1e2f144af9b 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -106,12 +106,11 @@ do {									\
 	static struct lock_class_key __key;				\
 									\
 	__raw_spin_lock_init((lock), #lock, &__key, LD_WAIT_SPIN);	\
-	__assume_ctx_lock(lock);					\
 } while (0)
 
 #else
 # define raw_spin_lock_init(lock)				\
-	do { *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock); __assume_ctx_lock(lock); } while (0)
+	do { *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock); } while (0)
 #endif
 
 #define raw_spin_is_locked(lock)	arch_spin_is_locked(&(lock)->raw_lock)
@@ -324,7 +323,6 @@ do {								\
 								\
 	__raw_spin_lock_init(spinlock_check(lock),		\
 			     #lock, &__key, LD_WAIT_CONFIG);	\
-	__assume_ctx_lock(lock);				\
 } while (0)
 
 #else
@@ -333,7 +331,6 @@ do {								\
 do {						\
 	spinlock_check(_lock);			\
 	*(_lock) = __SPIN_LOCK_UNLOCKED(_lock);	\
-	__assume_ctx_lock(_lock);		\
 } while (0)
 
 #endif
diff --git a/include/linux/spinlock_rt.h b/include/linux/spinlock_rt.h
index 0a585768358f..373618a4243c 100644
--- a/include/linux/spinlock_rt.h
+++ b/include/linux/spinlock_rt.h
@@ -20,7 +20,6 @@ static inline void __rt_spin_lock_init(spinlock_t *lock, const char *name,
 do {								\
 	rt_mutex_base_init(&(slock)->lock);			\
 	__rt_spin_lock_init(slock, name, key, percpu);		\
-	__assume_ctx_lock(slock);				\
 } while (0)
 
 #define _spin_lock_init(slock, percpu)				\
diff --git a/include/linux/ww_mutex.h b/include/linux/ww_mutex.h
index 58e959ee10e9..c47d4b9b88b3 100644
--- a/include/linux/ww_mutex.h
+++ b/include/linux/ww_mutex.h
@@ -107,7 +107,6 @@ context_lock_struct(ww_acquire_ctx) {
  */
 static inline void ww_mutex_init(struct ww_mutex *lock,
 				 struct ww_class *ww_class)
-	__assumes_ctx_lock(lock)
 {
 	ww_mutex_base_init(&lock->base, ww_class->mutex_name, &ww_class->mutex_key);
 	lock->ctx = NULL;
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 0f05943d957f..140efa8a9763 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -542,12 +542,6 @@ struct test_ww_mutex_data {
 	int counter __guarded_by(&mtx);
 };
 
-static void __used test_ww_mutex_init(struct test_ww_mutex_data *d)
-{
-	ww_mutex_init(&d->mtx, &ww_class);
-	d->counter = 0;
-}
-
 static void __used test_ww_mutex_lock_noctx(struct test_ww_mutex_data *d)
 {
 	if (!ww_mutex_lock(&d->mtx, NULL)) {
-- 
2.52.0.457.g6b5491de43-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260119094029.1344361-7-elver%40google.com.
