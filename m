Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFEOTO7AMGQEXUZOH5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 15CA5A4D802
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:42 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-3072f9103d7sf49853961fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080341; cv=pass;
        d=google.com; s=arc-20240605;
        b=PlUdsw9cbYbJvBPOglV250yqgZBQJ7nTdGW4TTcYbBYMQKpw+5Kp3G2ur030HQHnW+
         CN+5fC3d7hO/w0B27L7gcKzA31TfTaqjaCd3/mmVKmzql7pNZ97FFCCEZ7aXpOyTEMyx
         CtWElk6k6lR0RUEutCh37cPr9dKG6eZ7ZYERr5YNMvBc6Gadoo6JQOhnhgdxZ+151nMx
         WT8zt477a6MrEZFifpPcIGkH3gQF/S8XyL+gEF0iCz+lOh1T1HVhy2/DUKNavKRk6LYi
         jzTxS74kkJVoXbg7n5UxT8BLiZxCyXWtZYuXSliCrtJcn5YeXm5EZuG/39vhP6S5o/u0
         ZjPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ASBC/wu6tkbrrrqzy94Xnt0Q4Za3jchuDND5rqxFJuA=;
        fh=goLqF9L1afiU8r9gA49FAdJ7u3N2a7xwagsMqoHpjkk=;
        b=H296VcEhDTTG4Zchyrwcc2xjkmxA2ho55uMc/PM+wE0SRGqodds61BYW/So3/FfBsI
         P2K+tSq5UMLGaSg4fDfciq/J9ww8qJZhYhByApGZWnLDOq4B58lGqYiLRRULVUaY0ytA
         7vv4V9G5IbearbRSnosxeQSRPK+lhTElacAR10yhouPbjR0DLI7/heMgReMNii7YWuJ2
         P3IgT/OfCbvwVC4mmDPlwe52ktrZv9dmHqGX1O3Aa/C0V7Ea7yUck2lXh7ufW3EoLYjo
         mAAKuvIS/Q1WEMQx9yqN6LrETOe9hC+4XxtuYVxoG5Hv2ihsaBJgBS1/S6IV4j7jJDWw
         6bGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pKGWxQnQ;
       spf=pass (google.com: domain of 3d8fgzwukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3D8fGZwUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080341; x=1741685141; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ASBC/wu6tkbrrrqzy94Xnt0Q4Za3jchuDND5rqxFJuA=;
        b=nzKHI42YZ7yHlT9LuUOkMKktElS1UZNfA+yohJW+rEy2MxJHJIomjec+1SJhuM4BqL
         RkmeBHAeRD2hzACYpVeGDDZuBK6BCYVt8TmG7GyMOxr6Bob4hzxRVz7NYtgikcEgxAYY
         Cmi4OAsL9XbMxiAkZhSJASNKo1BKceuegGiwcmc+6TUn77qmBPJ5uPaHniQ81ws32A84
         NKTa9gxFrxi84+EqKLlhILaKR7Qmah4KW0neawCRH+kbpl2l0gxPB8lDz/XbbPDgA7QS
         p8Xi3gRg6Lzanf7T456UweJB41sIWfiWR4VZ0TVauE/GiMINKvw5+E+clMifHrvH0xgx
         n6EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080341; x=1741685141;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ASBC/wu6tkbrrrqzy94Xnt0Q4Za3jchuDND5rqxFJuA=;
        b=SA1I3A+u3XTzsE1fQBW95eVXsUdfFDWymhCSsRsi56fl2au9rP0/L9LtaSmyCUwNvK
         ucRb5O04P4hSnYr7fNWushXf7Fu6Cuh0tzfUbjq83SE+3PjByINc88zaw8rgUlj5TqJx
         oQuaGqTMiKQ9qY7/5f9kfnOVIaAmLgMRU93d1FfXONHOGlmUcSvXz44V34gaO3WKZR91
         Ovt3mKDRGGdhrekIOCa1xdPPoQn/Y3eKW0iquGF0cNrD/lRxx38ds5wXEUHFR1+JnEbl
         Qdpubau1TPy4vGsEALe9CjUrssiJafVFKUgXs/EcReR13NO/oLpDNg3G8J7l8IFjJg4M
         qKWA==
X-Forwarded-Encrypted: i=2; AJvYcCVLU80pCMJ9zXvVyoDxWxaPhW3Qp7r6XPT63BHvhLZEt04NVCwDExVAt7yA18mnN2IMtWx11Q==@lfdr.de
X-Gm-Message-State: AOJu0YwLjsOVytyamccQRB1OQtMWT95RqQCWu03eD42x56DEyl8Kz5Go
	HZGyqR3gtUjCd0fwTEPMmrkLEYC7yLZ4TkSCC0e3Ug8LKeeUkA7t
X-Google-Smtp-Source: AGHT+IEdvJXkQCXSYmyw+c5XIR//6jrdgnX7boKnnZa8G7hRGx6AidSk1NRlyjMmVzvDib5eMFFFCg==
X-Received: by 2002:a05:651c:1507:b0:30b:c637:fcc3 with SMTP id 38308e7fff4ca-30bc6380221mr15578901fa.6.1741080340766;
        Tue, 04 Mar 2025 01:25:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHuem2SRqSeiaWpGAFojMS1HzaekxDNXIKwqnCVYZKhFg==
Received: by 2002:a05:651c:50e:b0:30b:78cd:df63 with SMTP id
 38308e7fff4ca-30b846e1bf8ls2401451fa.0.-pod-prod-09-eu; Tue, 04 Mar 2025
 01:25:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWNwFX63V6UgKcqCdd9Ha5G2ze2V62WhQcRpbm/zbPwiCEwBHZGiDGffIHVQ2/eLFxKY/e/MkKUIb4=@googlegroups.com
X-Received: by 2002:a05:651c:b0c:b0:30b:b8e6:86d7 with SMTP id 38308e7fff4ca-30bb8e6885dmr33019661fa.22.1741080336805;
        Tue, 04 Mar 2025 01:25:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080336; cv=none;
        d=google.com; s=arc-20240605;
        b=eIP+uCLaWP0NBjeZ11j+OeFC9cNMMPhCMuAz7MuggIRCoLsFsgitj7uGMHCTlaUpxa
         t8QoJ1t2j4z4DZ85IGHGMMAn950NeNT0bfRAdfDQX2fM/UwyOGGxTbYXgoxZ8b2DOPfv
         qXQuuchCmdIZPa9xy69xTttFCwC3BUb1VSJqaq68k9wyJ8y/lzYCRMDfbZPuir3+Jyoc
         /Aar8SLsUumyTd0W2EHSyPrv1jg4VhXGFvFLawiEASuBCM63Yor9yu3mGPElKGiHF6yj
         JtquvULTduWKQy3YZ9u4zsUXOhLqip9uaRaBTS/yrqzFYkVQiBjl89SCY5/WnV7DyN2n
         jUSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=istr0KCQ5s77c/egqf7KkvIi9CTO4kygD0ofOymfkU8=;
        fh=BSvLydZhKNiKD9FRQxHvFsDHnzDxsps2O5UnpjG45Do=;
        b=itFMpXqAZAkaCAFQ89qi1AYlN6CkcspWuifgnLZrN2KTj+pMbjaipyuSeAv5BehqCR
         bTay+P43D+9f4XjwhT/g00aL7pYGg25a1a06hjs9XZHVLXSbMcu0oo9l0sNQeE5ik1nW
         2knNSs/en0/qhcy06Ix8L20BCb0wECXscfU+cY2ZqPeOI45JQ/VVca27ew7nEKXL14wL
         F73lw7V9WesK1QZBuR/8zug6sbsdvVrSkCDahTv9DZyRxBE5ql+tW/PkDWpgLKID2XPg
         7kKWqt0doofMPbk+RXNW0pABzubx6MRKY1WjO6kNwcyr/0SnRQFeOFJ4sskfGQ9Hw57b
         zaLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pKGWxQnQ;
       spf=pass (google.com: domain of 3d8fgzwukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3D8fGZwUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30bb38c77dfsi1093281fa.6.2025.03.04.01.25.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3d8fgzwukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-39101511442so1076003f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUTUg8mxG2/V94N8EElBOTgb5HnLkVckpAX20KxLVdE/TxCuxlpDKvPBNJZ4pFTJqGMEgXLBBNj1c8=@googlegroups.com
X-Received: from wrbei4.prod.google.com ([2002:a05:6000:4184:b0:390:f69f:8c34])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:1fa4:b0:390:f9e0:f0d0
 with SMTP id ffacd0b85a97d-391155feb2emr1821321f8f.6.1741080335989; Tue, 04
 Mar 2025 01:25:35 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:09 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-11-elver@google.com>
Subject: [PATCH v2 10/34] locking/mutex: Support Clang's capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pKGWxQnQ;       spf=pass
 (google.com: domain of 3d8fgzwukcfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3D8fGZwUKCfwipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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

Add support for Clang's capability analysis for mutex.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/mutex.h                         | 29 +++++----
 include/linux/mutex_types.h                   |  4 +-
 lib/test_capability-analysis.c                | 64 +++++++++++++++++++
 4 files changed, 82 insertions(+), 17 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index ddda3dc0d8d3..0000214056c2 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -79,7 +79,7 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/mutex.h b/include/linux/mutex.h
index 2bf91b57591b..f71ad9ec96d0 100644
--- a/include/linux/mutex.h
+++ b/include/linux/mutex.h
@@ -62,6 +62,7 @@ do {									\
 	static struct lock_class_key __key;				\
 									\
 	__mutex_init((mutex), #mutex, &__key);				\
+	__assert_cap(mutex);						\
 } while (0)
 
 /**
@@ -154,14 +155,14 @@ static inline int __devm_mutex_init(struct device *dev, struct mutex *lock)
  * Also see Documentation/locking/mutex-design.rst.
  */
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
-extern void mutex_lock_nested(struct mutex *lock, unsigned int subclass);
+extern void mutex_lock_nested(struct mutex *lock, unsigned int subclass) __acquires(lock);
 extern void _mutex_lock_nest_lock(struct mutex *lock, struct lockdep_map *nest_lock);
 
 extern int __must_check mutex_lock_interruptible_nested(struct mutex *lock,
-					unsigned int subclass);
+					unsigned int subclass) __cond_acquires(0, lock);
 extern int __must_check mutex_lock_killable_nested(struct mutex *lock,
-					unsigned int subclass);
-extern void mutex_lock_io_nested(struct mutex *lock, unsigned int subclass);
+					unsigned int subclass) __cond_acquires(0, lock);
+extern void mutex_lock_io_nested(struct mutex *lock, unsigned int subclass) __acquires(lock);
 
 #define mutex_lock(lock) mutex_lock_nested(lock, 0)
 #define mutex_lock_interruptible(lock) mutex_lock_interruptible_nested(lock, 0)
@@ -175,10 +176,10 @@ do {									\
 } while (0)
 
 #else
-extern void mutex_lock(struct mutex *lock);
-extern int __must_check mutex_lock_interruptible(struct mutex *lock);
-extern int __must_check mutex_lock_killable(struct mutex *lock);
-extern void mutex_lock_io(struct mutex *lock);
+extern void mutex_lock(struct mutex *lock) __acquires(lock);
+extern int __must_check mutex_lock_interruptible(struct mutex *lock) __cond_acquires(0, lock);
+extern int __must_check mutex_lock_killable(struct mutex *lock) __cond_acquires(0, lock);
+extern void mutex_lock_io(struct mutex *lock) __acquires(lock);
 
 # define mutex_lock_nested(lock, subclass) mutex_lock(lock)
 # define mutex_lock_interruptible_nested(lock, subclass) mutex_lock_interruptible(lock)
@@ -193,13 +194,13 @@ extern void mutex_lock_io(struct mutex *lock);
  *
  * Returns 1 if the mutex has been acquired successfully, and 0 on contention.
  */
-extern int mutex_trylock(struct mutex *lock);
-extern void mutex_unlock(struct mutex *lock);
+extern int mutex_trylock(struct mutex *lock) __cond_acquires(true, lock);
+extern void mutex_unlock(struct mutex *lock) __releases(lock);
 
-extern int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock);
+extern int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock) __cond_acquires(true, lock);
 
-DEFINE_GUARD(mutex, struct mutex *, mutex_lock(_T), mutex_unlock(_T))
-DEFINE_GUARD_COND(mutex, _try, mutex_trylock(_T))
-DEFINE_GUARD_COND(mutex, _intr, mutex_lock_interruptible(_T) == 0)
+DEFINE_LOCK_GUARD_1(mutex, struct mutex, mutex_lock(_T->lock), mutex_unlock(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(mutex, _try, mutex_trylock(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(mutex, _intr, mutex_lock_interruptible(_T->lock) == 0)
 
 #endif /* __LINUX_MUTEX_H */
diff --git a/include/linux/mutex_types.h b/include/linux/mutex_types.h
index fdf7f515fde8..e1a5ea12d53c 100644
--- a/include/linux/mutex_types.h
+++ b/include/linux/mutex_types.h
@@ -38,7 +38,7 @@
  * - detects multi-task circular deadlocks and prints out all affected
  *   locks and tasks (and only those tasks)
  */
-struct mutex {
+struct_with_capability(mutex) {
 	atomic_long_t		owner;
 	raw_spinlock_t		wait_lock;
 #ifdef CONFIG_MUTEX_SPIN_ON_OWNER
@@ -59,7 +59,7 @@ struct mutex {
  */
 #include <linux/rtmutex.h>
 
-struct mutex {
+struct_with_capability(mutex) {
 	struct rt_mutex_base	rtmutex;
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 84060bace61d..286723b47328 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -5,6 +5,7 @@
  */
 
 #include <linux/build_bug.h>
+#include <linux/mutex.h>
 #include <linux/spinlock.h>
 
 /*
@@ -144,3 +145,66 @@ TEST_SPINLOCK_COMMON(read_lock,
 		     read_unlock,
 		     read_trylock,
 		     TEST_OP_RO);
+
+struct test_mutex_data {
+	struct mutex mtx;
+	int counter __guarded_by(&mtx);
+};
+
+static void __used test_mutex_init(struct test_mutex_data *d)
+{
+	mutex_init(&d->mtx);
+	d->counter = 0;
+}
+
+static void __used test_mutex_lock(struct test_mutex_data *d)
+{
+	mutex_lock(&d->mtx);
+	d->counter++;
+	mutex_unlock(&d->mtx);
+	mutex_lock_io(&d->mtx);
+	d->counter++;
+	mutex_unlock(&d->mtx);
+}
+
+static void __used test_mutex_trylock(struct test_mutex_data *d, atomic_t *a)
+{
+	if (!mutex_lock_interruptible(&d->mtx)) {
+		d->counter++;
+		mutex_unlock(&d->mtx);
+	}
+	if (!mutex_lock_killable(&d->mtx)) {
+		d->counter++;
+		mutex_unlock(&d->mtx);
+	}
+	if (mutex_trylock(&d->mtx)) {
+		d->counter++;
+		mutex_unlock(&d->mtx);
+	}
+	if (atomic_dec_and_mutex_lock(a, &d->mtx)) {
+		d->counter++;
+		mutex_unlock(&d->mtx);
+	}
+}
+
+static void __used test_mutex_assert(struct test_mutex_data *d)
+{
+	lockdep_assert_held(&d->mtx);
+	d->counter++;
+}
+
+static void __used test_mutex_guard(struct test_mutex_data *d)
+{
+	guard(mutex)(&d->mtx);
+	d->counter++;
+}
+
+static void __used test_mutex_cond_guard(struct test_mutex_data *d)
+{
+	scoped_cond_guard(mutex_try, return, &d->mtx) {
+		d->counter++;
+	}
+	scoped_cond_guard(mutex_intr, return, &d->mtx) {
+		d->counter++;
+	}
+}
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-11-elver%40google.com.
