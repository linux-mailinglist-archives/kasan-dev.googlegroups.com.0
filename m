Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZXZSO6QMGQESE5UE2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 17980A2B055
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:16 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-38dae2ab056sf670788f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865895; cv=pass;
        d=google.com; s=arc-20240605;
        b=UQaHuzriGIfK8MkWhz+bndplqSL6TW+NbWLrXBMAzVF9KTOxf7+Dj4uc/Et4ZmQt0K
         dyuEUf6rOGjISJMx4EQOBRFTi1CiDxkQfg9qKRSseM5wHGhxM7OSZcdnenlOyP1o+/ah
         1ZRP5gKnezOB0KA/Xs9G6fzmhIfWHlBcwADyaupsc7SFg27eq0qpvHRgbPOYdKu82knZ
         itStGr0jzEbsHcS8Do661QbAy6JwCZ+lxq2A0cLQUczGWSvzWBjkt2rHQWXot+0VfQ1M
         crX+12Inb/nQNRQfeLwIVJ2tvNJq+HiWuY1u3VRE9wriTf5wLJO9KEe4Q3+EfiCoA+sN
         8dIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=5RwzOHd3Nct/65lj7pv44QJA6klzk9dwMYEAKx0Afz0=;
        fh=OKNT6jykk4ujyG+4yzo0z439JlaP03j5Zbk4+KqNcHI=;
        b=IZug8IdZ18/ShtH+L4ZD7/tvGBvCWPrbBSWUfoCWe5YxufmPTNJy0DsPRaNW239uvJ
         oZ9kzHadLn9pUqRwUeTt4HczQNCi/5CdQJbgpgrs21ur9jCnp/1DE1C0fQ241kQ2HdGh
         juL3cvsiUBcaHROXO8/IQP8DXBwIza81L80veaB1W9psh88cEtdMlxSpDT9JmzzG+Zoc
         R9HYGdIJrLqEuREhkNnXMzZzHmVMk4r3mJNjd77PuNX3Sd+pZL86ZM7p/33EjqbxydSL
         /loaqYU7J15wJSUXYf3AvzmexO5iLljQNpC+T2V05wrydftZvIEK/6ib0SryFUcTK4b3
         ubcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=H+ddS3Hg;
       spf=pass (google.com: domain of 34vykzwukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=34vykZwUKCbMXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865895; x=1739470695; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5RwzOHd3Nct/65lj7pv44QJA6klzk9dwMYEAKx0Afz0=;
        b=YVoqgPlUdd5+8CDIwFNYG+7S+eIGlUfoskSaa3+EPtI+8fc733cBhezXnUUEWsOFYp
         DBD6ZVYXZ+EG+UyMDldG0MVlC/pH3CW//2fHDJO8yXjyxyxvP8SEgOUBFvkOc+LI8yNh
         Y/KPSUmsKnPlpO/vUVGJKrN3PgMDjyl50EghHDwZsxnJFTLMcc2Q+fPO/mNgY8fjsfu+
         r+3RFa7LmuT6Yve5dOq4Bwg54vJxOi5gq9tTnLGIzukHzwx6j7+/KQ/e+y5egOfxGoDZ
         OLzpYNWFrPMXCHfF0tXltDmHEeavwdmdejoCY5kG5owhjE4RIUS2Rt3QSBdPPTbyMxIU
         QFVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865895; x=1739470695;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5RwzOHd3Nct/65lj7pv44QJA6klzk9dwMYEAKx0Afz0=;
        b=rDVvjb28qAGIFHuPnMFyneM4zIxe6NQGJZ9ywd7pkCsF+/qfk7cW4hgiBnJZGTMjym
         7UKXB/h0WIcEoKWqQh0NY06QD87764Y0tdJ0vzM9vBdkQPORqtEoAxMirxXHlw/XEI9H
         bpXsuZfJfOVOrXNa4nWi0UvK/QQ9Fn3wfwVAZkdnD8RFZRLHEnOWWSSHsa6xcMQNOQb7
         tnQRltU3tfOpygO6+BdSugrg3sYxoXGXBHf/Pw66k9w+oJNQg5QJ7/Tou2Ol2CXgVko3
         FlbYapKBCR3AU2mr2W6KatHmcTB9T+h09KHViOr5KKdJ2spoOrLrh7ZYboaobWAPKzkE
         98Tg==
X-Forwarded-Encrypted: i=2; AJvYcCUo+rmsY2nZFDRDPeC93jy5YB+b3X+PME2zhP1rpRzyAX4v/xlo/L+xH7m5T8ar3sGCXoHuCQ==@lfdr.de
X-Gm-Message-State: AOJu0YzRwkSTV9hZ/NkKdl36iifq/KruKbyi3h59P6A4+pyq49YlCy1W
	UO9ZrtEsfCd4j0B0+H3Lcy2xMaqEtszYuAcAXWyVXiYfAMtleiwc
X-Google-Smtp-Source: AGHT+IE8u4Hrh24xkDTXqMyP6rwTu2KaL4iocqSsaGRdOFKKTXxZch/DVq2laAbsA980KUsjZM4M8g==
X-Received: by 2002:a5d:47c5:0:b0:38d:be7b:6051 with SMTP id ffacd0b85a97d-38dc8d98a42mr48264f8f.11.1738865894433;
        Thu, 06 Feb 2025 10:18:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a30d:0:b0:38d:c1e5:15bf with SMTP id ffacd0b85a97d-38dc70dbed6ls161680f8f.2.-pod-prod-09-eu;
 Thu, 06 Feb 2025 10:18:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUmjLaSrYXltJLkZoEEGRKSGbdXHbAf0pOaGxFaXxljQK5FlCnQIaz+kcUD03tQhpluvQTgNvgN+zc=@googlegroups.com
X-Received: by 2002:a5d:5885:0:b0:38d:b125:3783 with SMTP id ffacd0b85a97d-38dc8db06b7mr35314f8f.18.1738865891542;
        Thu, 06 Feb 2025 10:18:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865891; cv=none;
        d=google.com; s=arc-20240605;
        b=KhBMe0/S0Xx+8HKXGrmi+rp4vTlKmqfRTxRS996cSq36ssrDT59HiCw8cEQrGXebyh
         B/ToA2mnxtlnx70jGN6olsAU6ppIflDdlhA3zUXijIU2aoXkm8+pNpr1qCSL2jBKASlO
         dkDrZBcTjiRdcF0ZmbPsUUa9NfIfGmcFovW1y+mBqy1uvFhE8RsHKrMJIyhj1lms0GHv
         mjwS3He2b2Thu6ztxCxnQXZwPpUwgy35SvGIJ53/ZSR16fmh3xs2BFD6jg7yM1aTS3xy
         hzP8fdiPKaOeaFVZVkxPpApGxt4i8cCkwn77/xtD39I5Bei75JZp1U4OQelf/3ayqSiv
         CWag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Y0plDjCJ1B0qZbMeycYJk7FAuIdA1LrCIxvHWeEdHoU=;
        fh=u/lPB4xUI4ZlZ168x5U7wky09wLdf//j8Mafx6rVZq8=;
        b=GXOKfsIkKZHKXx3Gu+8VT27gCRQ2IOd85kMfA5Bm7MVzbdXigmbC+h1YtUuyhnpz3y
         cRYNHt1nNeB/L9HBt6Q230dpVxOpyaKp+A5g7lL/iExLcXfrjevroJMa8f/yQTmRQ76Z
         HlAjVkRti2U1g6LLIi3RriQFO1ZKSehNpvBnUwTTpw+vnNBOSOr2+a/EkucpbF++1b9T
         yAzklCwG2iSxiUr4z53OrBDE2AsQl5c9yyWWS5rc8jam2txdEhl1ZHc+OTavwnutbi3X
         z3K0qiZKnuh/53uY7qrVLWWXDdhj6sPrAMuhxmxs1+voVbmwTlrqBQpDxf5jbedp+cMh
         C4zA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=H+ddS3Hg;
       spf=pass (google.com: domain of 34vykzwukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=34vykZwUKCbMXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38dbde0e6d0si45446f8f.3.2025.02.06.10.18.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 34vykzwukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-38dc88ed7e6so16855f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUUvmlW2ax4hSJ114sndXjC4ubwVUrlAaviHZQv1u3MpBmJyjeNKnbNjnM7biYE5G3sXTPb92H6JhY=@googlegroups.com
X-Received: from ejcvs8.prod.google.com ([2002:a17:907:a588:b0:aa6:8676:3b2b])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a5d:64af:0:b0:386:605:77e
 with SMTP id ffacd0b85a97d-38dc933bd7amr24f8f.49.1738865890985; Thu, 06 Feb
 2025 10:18:10 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:04 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-11-elver@google.com>
Subject: [PATCH RFC 10/24] compiler-capability-analysis: Change
 __cond_acquires to take return value
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=H+ddS3Hg;       spf=pass
 (google.com: domain of 34vykzwukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=34vykZwUKCbMXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
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

While Sparse is oblivious to the return value of conditional acquire
functions, Clang's capability analysis needs to know the return value
which indicates successful acquisition.

Add the additional argument, and convert existing uses.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 fs/dlm/lock.c                                |  2 +-
 include/linux/compiler-capability-analysis.h | 14 +++++++++-----
 include/linux/refcount.h                     |  6 +++---
 include/linux/spinlock.h                     |  6 +++---
 include/linux/spinlock_api_smp.h             |  8 ++++----
 net/ipv4/tcp_sigpool.c                       |  2 +-
 6 files changed, 21 insertions(+), 17 deletions(-)

diff --git a/fs/dlm/lock.c b/fs/dlm/lock.c
index c8ff88f1cdcf..e39ca02b793e 100644
--- a/fs/dlm/lock.c
+++ b/fs/dlm/lock.c
@@ -343,7 +343,7 @@ void dlm_hold_rsb(struct dlm_rsb *r)
 /* TODO move this to lib/refcount.c */
 static __must_check bool
 dlm_refcount_dec_and_write_lock_bh(refcount_t *r, rwlock_t *lock)
-__cond_acquires(lock)
+      __cond_acquires(1, lock)
 {
 	if (refcount_dec_not_one(r))
 		return false;
diff --git a/include/linux/compiler-capability-analysis.h b/include/linux/compiler-capability-analysis.h
index ca63b6513dc3..10c03133ac4d 100644
--- a/include/linux/compiler-capability-analysis.h
+++ b/include/linux/compiler-capability-analysis.h
@@ -231,7 +231,7 @@
 # define __must_hold(x)		__attribute__((context(x,1,1)))
 # define __must_not_hold(x)
 # define __acquires(x)		__attribute__((context(x,0,1)))
-# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
+# define __cond_acquires(ret, x) __attribute__((context(x,0,-1)))
 # define __releases(x)		__attribute__((context(x,1,0)))
 # define __acquire(x)		__context__(x,1)
 # define __release(x)		__context__(x,-1)
@@ -277,12 +277,14 @@
 /**
  * __cond_acquires() - function attribute, function conditionally
  *                     acquires a capability exclusively
+ * @ret: value returned by function if capability acquired
  * @x: capability instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
- * given capability instance @x exclusively, but does not release it.
+ * given capability instance @x exclusively, but does not release it. The
+ * function return value @ret denotes when the capability is acquired.
  */
-# define __cond_acquires(x)	__try_acquires_cap(1, x)
+# define __cond_acquires(ret, x) __try_acquires_cap(ret, x)
 
 /**
  * __releases() - function attribute, function releases a capability exclusively
@@ -349,12 +351,14 @@
 /**
  * __cond_acquires_shared() - function attribute, function conditionally
  *                            acquires a capability shared
+ * @ret: value returned by function if capability acquired
  * @x: capability instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
- * given capability instance @x with shared access, but does not release it.
+ * given capability instance @x with shared access, but does not release it. The
+ * function return value @ret denotes when the capability is acquired.
  */
-# define __cond_acquires_shared(x) __try_acquires_shared_cap(1, x)
+# define __cond_acquires_shared(ret, x) __try_acquires_shared_cap(ret, x)
 
 /**
  * __releases_shared() - function attribute, function releases a
diff --git a/include/linux/refcount.h b/include/linux/refcount.h
index 35f039ecb272..f63ce3fadfa3 100644
--- a/include/linux/refcount.h
+++ b/include/linux/refcount.h
@@ -353,9 +353,9 @@ static inline void refcount_dec(refcount_t *r)
 
 extern __must_check bool refcount_dec_if_one(refcount_t *r);
 extern __must_check bool refcount_dec_not_one(refcount_t *r);
-extern __must_check bool refcount_dec_and_mutex_lock(refcount_t *r, struct mutex *lock) __cond_acquires(lock);
-extern __must_check bool refcount_dec_and_lock(refcount_t *r, spinlock_t *lock) __cond_acquires(lock);
+extern __must_check bool refcount_dec_and_mutex_lock(refcount_t *r, struct mutex *lock) __cond_acquires(1, lock);
+extern __must_check bool refcount_dec_and_lock(refcount_t *r, spinlock_t *lock) __cond_acquires(1, lock);
 extern __must_check bool refcount_dec_and_lock_irqsave(refcount_t *r,
 						       spinlock_t *lock,
-						       unsigned long *flags) __cond_acquires(lock);
+						       unsigned long *flags) __cond_acquires(1, lock);
 #endif /* _LINUX_REFCOUNT_H */
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index 1646a9920fd7..de5118d0e718 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -362,7 +362,7 @@ static __always_inline void spin_lock_bh(spinlock_t *lock)
 }
 
 static __always_inline int spin_trylock(spinlock_t *lock)
-	__cond_acquires(lock) __no_capability_analysis
+	__cond_acquires(1, lock) __no_capability_analysis
 {
 	return raw_spin_trylock(&lock->rlock);
 }
@@ -420,13 +420,13 @@ static __always_inline void spin_unlock_irqrestore(spinlock_t *lock, unsigned lo
 }
 
 static __always_inline int spin_trylock_bh(spinlock_t *lock)
-	__cond_acquires(lock) __no_capability_analysis
+	__cond_acquires(1, lock) __no_capability_analysis
 {
 	return raw_spin_trylock_bh(&lock->rlock);
 }
 
 static __always_inline int spin_trylock_irq(spinlock_t *lock)
-	__cond_acquires(lock) __no_capability_analysis
+	__cond_acquires(1, lock) __no_capability_analysis
 {
 	return raw_spin_trylock_irq(&lock->rlock);
 }
diff --git a/include/linux/spinlock_api_smp.h b/include/linux/spinlock_api_smp.h
index fab02d8bf0c9..9b6f7a5a0705 100644
--- a/include/linux/spinlock_api_smp.h
+++ b/include/linux/spinlock_api_smp.h
@@ -34,8 +34,8 @@ unsigned long __lockfunc _raw_spin_lock_irqsave(raw_spinlock_t *lock)
 unsigned long __lockfunc
 _raw_spin_lock_irqsave_nested(raw_spinlock_t *lock, int subclass)
 								__acquires(lock);
-int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock)		__cond_acquires(lock);
-int __lockfunc _raw_spin_trylock_bh(raw_spinlock_t *lock)	__cond_acquires(lock);
+int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock)		__cond_acquires(1, lock);
+int __lockfunc _raw_spin_trylock_bh(raw_spinlock_t *lock)	__cond_acquires(1, lock);
 void __lockfunc _raw_spin_unlock(raw_spinlock_t *lock)		__releases(lock);
 void __lockfunc _raw_spin_unlock_bh(raw_spinlock_t *lock)	__releases(lock);
 void __lockfunc _raw_spin_unlock_irq(raw_spinlock_t *lock)	__releases(lock);
@@ -84,7 +84,7 @@ _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
 #endif
 
 static inline int __raw_spin_trylock(raw_spinlock_t *lock)
-	__cond_acquires(lock)
+	__cond_acquires(1, lock)
 {
 	preempt_disable();
 	if (do_raw_spin_trylock(lock)) {
@@ -177,7 +177,7 @@ static inline void __raw_spin_unlock_bh(raw_spinlock_t *lock)
 }
 
 static inline int __raw_spin_trylock_bh(raw_spinlock_t *lock)
-	__cond_acquires(lock)
+	__cond_acquires(1, lock)
 {
 	__local_bh_disable_ip(_RET_IP_, SOFTIRQ_LOCK_OFFSET);
 	if (do_raw_spin_trylock(lock)) {
diff --git a/net/ipv4/tcp_sigpool.c b/net/ipv4/tcp_sigpool.c
index d8a4f192873a..10b2e5970c40 100644
--- a/net/ipv4/tcp_sigpool.c
+++ b/net/ipv4/tcp_sigpool.c
@@ -257,7 +257,7 @@ void tcp_sigpool_get(unsigned int id)
 }
 EXPORT_SYMBOL_GPL(tcp_sigpool_get);
 
-int tcp_sigpool_start(unsigned int id, struct tcp_sigpool *c) __cond_acquires(RCU_BH)
+int tcp_sigpool_start(unsigned int id, struct tcp_sigpool *c) __cond_acquires(0, RCU_BH)
 {
 	struct crypto_ahash *hash;
 
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-11-elver%40google.com.
