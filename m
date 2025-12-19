Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQHGSXFAMGQEAYKPMZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 90456CD0953
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:09 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-599cdb859c9sf1590137e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159169; cv=pass;
        d=google.com; s=arc-20240605;
        b=TDqsjAoTG9/6tH63lfHl5rinHIwSTXuIYSZ7OIUuPR9tnDyaK0uy1PW4EgrtiVIEMx
         JX4icMKMvKfuq4CIcb0pLiu9+x/Q7Q/HsWVNISUMX8SzEKhCEdb5K0+bHTujnvDyxdip
         4LTUEGpP7srqudNQAaJ2RU+ufVSsXatzu+es3TuZZXwvpHrWj26fMUX3XGltx5fno2G3
         MQ0kBvbgepOmaUPDioe9FVgSGBEgk84FwL25//OzRSz1w/AaK+Mvi79P4rPnL7HQ1AzR
         ISEGXhP445xHxrhX7bFHQsnH8f0bF/3KWhTmaMqHo3qsdaHQ+J7fjZCC5FOKWtK9uCKV
         C77Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=rVrWhxXT3m1oS1/9KDvyVKcY9OMZZ2bvyBz2QJ7/LQE=;
        fh=OdeUyRf6w7fKboBSex5HBbCqLOR+ueYWrEgwfKQIsGU=;
        b=VKppmdrfTR5ebiImdgw5A0iApmT2EWcltQ5FUPCjxeKX7stS0hGYGuoSsGml3VyNtp
         KPcOegdfeNGs80x0+F5zpxTXjLTogALsDz5mREiUIKPVqO4nmKJ8PgRzghzw5j39iK1Y
         FcZmno78skBoBxhbAEZireY+OGRFy4/nqUdapkC8TnWELxfMybaWN8GRu2Pc0pU9R3oE
         vz4JDHtnmSRKdKapxHaCjX3rk3N6L+XnL15T+JkjG5JzBhND7G7BEZwFdFpo+XR4H+Vr
         9N5c2erXjTwyLHxMvWmLtbqlM+mKEn66tgQtkObFHtrLGzR1bxBVQ7QHzJu6ivOYdC89
         vK0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2nj8umuX;
       spf=pass (google.com: domain of 3pxnfaqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3PXNFaQUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159169; x=1766763969; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rVrWhxXT3m1oS1/9KDvyVKcY9OMZZ2bvyBz2QJ7/LQE=;
        b=YZovZ7D/7cnNaWMha97qL9McLUj90J0iYJZ2klsynV5MCh+T7Ks5julIxcgoonJLGz
         ELkBsOpPkX0yT2FzVNE1Khix8QDLI7kHy/8SnuDeXAx0KeStrxk5ekBCWatJe2sL53w7
         DzqyQsobr583uErQtR2eUgFjQMBqecJ8kldmoEsoRDXQsXQRjBmPq8NVnkDILjjIuPut
         3UOFNnUyxRmHqz2q1eUYp7bstYErZ4aNFKNtiMpoxdYllML/HD80jApFggrmVX/eWcOm
         GIY+T/SGYCnrXTJUtkOMdnHJpuLbgPR4MMRPPr5ZFQ+D3I/P96kC5WEwnFy8c8h8zKWI
         TSGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159169; x=1766763969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rVrWhxXT3m1oS1/9KDvyVKcY9OMZZ2bvyBz2QJ7/LQE=;
        b=dTgJUS7U9hsACv6cKjRi80ewjmhH4qWCFg9gxE4Dxh5d1evN4Malo12WkyEebVdMfH
         XNe8R6Ri7YKseFctPNNq6cMMcyk6K33u4TeJ+L4L1ZIjufRoy+LTSMMwpGoC0XUqCZIt
         B1yKWrk3Mtu9WWxTNTmXk9ajPPAPt2qdZmIAhD6YeUyadiEw2HZP3UoEiC6aOcBfmaCh
         kAgt81bOkXriPCFgdKbyTSnQrMpJDHzjRwpBCFhFBjemdFXKMhczFHQWWlb1en1hHIKu
         bKYX6aMeUiB9K4HH5S/50TJ/BnZYv5bqEojS2e3aqw1WDJE7IzjJMW++Rj5FXXx4Hg+P
         DJ6A==
X-Forwarded-Encrypted: i=2; AJvYcCXRe+vV7FihIyCkY80VsjIohoSGbCm1WvOdWnQ0w2dd9F1KFZQ8nhYfWo0BqUs8SseMFjqToA==@lfdr.de
X-Gm-Message-State: AOJu0Yy/UNDb7uFh5fu9U0AliffwAEsUXz4IEtxNsG2k+9MaqEUbHlxQ
	frMQw1Vi48fm94YbyKfZHaikeXdnTiyCwBxB/Vuh9F/ZSec0rfHWbaQ6
X-Google-Smtp-Source: AGHT+IET2U9NoePxXmUeuDkRX7AsEvK1gpKzPT6nXTlbLr4U/wixm7t2+K+o1l76nQXC/A4+7IwcJw==
X-Received: by 2002:a05:6512:1113:b0:598:eed5:a218 with SMTP id 2adb3069b0e04-59a17d74470mr1163409e87.10.1766159168832;
        Fri, 19 Dec 2025 07:46:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa4rFmeYHQ+Wq8QyBC3BWivp5PG9kJgkUqt0/S3tJu4iw=="
Received: by 2002:a05:6512:159e:b0:598:f0c5:381e with SMTP id
 2adb3069b0e04-598fa40e77als2986956e87.2.-pod-prod-08-eu; Fri, 19 Dec 2025
 07:46:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVXDV9LdovvfKUyQh4tPyVg4nYYhCuv/XLttMPFBwdbC54HwuohXP5cEQUaXqUrn5tk8xjtfH5RYG4=@googlegroups.com
X-Received: by 2002:a05:6512:3f09:b0:595:81c1:c55 with SMTP id 2adb3069b0e04-59a17d74426mr1394345e87.8.1766159165962;
        Fri, 19 Dec 2025 07:46:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159165; cv=none;
        d=google.com; s=arc-20240605;
        b=VdkJaZ+zftBCRsbOtu4JrJmoOGEUaNASvWf9aumiPXqZefKH+Rytp0iVUsVuGRCQN4
         UVgVnAlr7xVjDv8bR02ScWI5K+RgOLxlrgrxlY/U1RfcDR5ogKA22q1nBOT2JpSt3xCd
         lWEw7Jd2dgsEJpOqznogut+f526AnhdIChCNXjd4x1DGSbwn/NMt4KeDpUPQoTDxY/hS
         CRHKSI217cJSynnVHFLYFK/OZnKf4lDOiD/E/+U8MPSbeX2VZM9zKkgcsuOnmCD9syDX
         AgbdSVBlAAi0wtQZnfZ3NRUixWGr3zp8sGVfxyu4DX5uRJo5bNlwwHo6pqvAY1wH7R72
         tRug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=2nto1KcJJjiv3QrSNF53pqHLj6j420z7Hf2YMAu356w=;
        fh=arVOht5y4N7DepTy/2DA6AAdEvBOL0HoB1zyEKizrhc=;
        b=iVrSWkXx1RKrN/6tOVZBqzJvVH5Y8mjeKWq1nktOkqzQ2PHFTO3naMEESI+++JExbf
         bjK6CuEjFQvJfpjHIpbo8idC/iri1n8sEojXZ6oQVL8FFkGAMVoYP4/ir+Q4j9/XSfFw
         QwDqOtV2/sQG5ZKCQ6pI2px+BHcvUcs+IFdMqqmYfWuKLHpGLaGOw3672Ibwjf5wtfjd
         7RjYSH01eD3L5V0HSuUHExpsKYyEWCXyRKT1yqwv9pSHv77gIrfMbGzJp3Bbqs2ddIUy
         QR7tQ7sK3179syPWB3Q4u/TdiQLVfpLj4fdNnhynP1xp1sQ9S6SK5z1HBHj3iurC/CaT
         Rdsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2nj8umuX;
       spf=pass (google.com: domain of 3pxnfaqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3PXNFaQUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a185d65d5si67040e87.1.2025.12.19.07.46.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pxnfaqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-477563e531cso12944285e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUpEmzWExiusr4bUIT0l/OKX5KeuqMFMpBoWKPUXN4sub15A6IAsWdDjMQEE9eP5CQ8cg1dqbFXleg=@googlegroups.com
X-Received: from wmby2.prod.google.com ([2002:a05:600c:c042:b0:477:165e:7e2a])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4ecd:b0:477:1bb6:17e5
 with SMTP id 5b1f17b1804b1-47d19593e32mr28466615e9.30.1766159165093; Fri, 19
 Dec 2025 07:46:05 -0800 (PST)
Date: Fri, 19 Dec 2025 16:39:59 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-11-elver@google.com>
Subject: [PATCH v5 10/36] locking/mutex: Support Clang's context analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2nj8umuX;       spf=pass
 (google.com: domain of 3pxnfaqukcyosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3PXNFaQUKCYosz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
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

Add support for Clang's context analysis for mutex.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rename "context guard" -> "context lock".

v4:
* Rename capability -> context analysis.

v3:
* Switch to DECLARE_LOCK_GUARD_1_ATTRS() (suggested by Peter)
* __assert -> __assume rename
---
 Documentation/dev-tools/context-analysis.rst |  2 +-
 include/linux/mutex.h                        | 38 +++++++-----
 include/linux/mutex_types.h                  |  4 +-
 lib/test_context-analysis.c                  | 64 ++++++++++++++++++++
 4 files changed, 90 insertions(+), 18 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index 746a2d275fb2..1864b6cba4d1 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -79,7 +79,7 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`.
 
 For context locks with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/mutex.h b/include/linux/mutex.h
index bf535f0118bb..89977c215cbd 100644
--- a/include/linux/mutex.h
+++ b/include/linux/mutex.h
@@ -62,6 +62,7 @@ do {									\
 	static struct lock_class_key __key;				\
 									\
 	__mutex_init((mutex), #mutex, &__key);				\
+	__assume_ctx_lock(mutex);					\
 } while (0)
 
 /**
@@ -182,13 +183,13 @@ static inline int __must_check __devm_mutex_init(struct device *dev, struct mute
  * Also see Documentation/locking/mutex-design.rst.
  */
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
-extern void mutex_lock_nested(struct mutex *lock, unsigned int subclass);
+extern void mutex_lock_nested(struct mutex *lock, unsigned int subclass) __acquires(lock);
 extern void _mutex_lock_nest_lock(struct mutex *lock, struct lockdep_map *nest_lock);
 extern int __must_check mutex_lock_interruptible_nested(struct mutex *lock,
-					unsigned int subclass);
+					unsigned int subclass) __cond_acquires(0, lock);
 extern int __must_check _mutex_lock_killable(struct mutex *lock,
-		unsigned int subclass, struct lockdep_map *nest_lock);
-extern void mutex_lock_io_nested(struct mutex *lock, unsigned int subclass);
+		unsigned int subclass, struct lockdep_map *nest_lock) __cond_acquires(0, lock);
+extern void mutex_lock_io_nested(struct mutex *lock, unsigned int subclass) __acquires(lock);
 
 #define mutex_lock(lock) mutex_lock_nested(lock, 0)
 #define mutex_lock_interruptible(lock) mutex_lock_interruptible_nested(lock, 0)
@@ -211,10 +212,10 @@ do {									\
 	_mutex_lock_killable(lock, subclass, NULL)
 
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
@@ -232,7 +233,7 @@ extern void mutex_lock_io(struct mutex *lock);
  */
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
-extern int _mutex_trylock_nest_lock(struct mutex *lock, struct lockdep_map *nest_lock);
+extern int _mutex_trylock_nest_lock(struct mutex *lock, struct lockdep_map *nest_lock) __cond_acquires(true, lock);
 
 #define mutex_trylock_nest_lock(lock, nest_lock)		\
 (								\
@@ -242,17 +243,24 @@ extern int _mutex_trylock_nest_lock(struct mutex *lock, struct lockdep_map *nest
 
 #define mutex_trylock(lock) _mutex_trylock_nest_lock(lock, NULL)
 #else
-extern int mutex_trylock(struct mutex *lock);
+extern int mutex_trylock(struct mutex *lock) __cond_acquires(true, lock);
 #define mutex_trylock_nest_lock(lock, nest_lock) mutex_trylock(lock)
 #endif
 
-extern void mutex_unlock(struct mutex *lock);
+extern void mutex_unlock(struct mutex *lock) __releases(lock);
 
-extern int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock);
+extern int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock) __cond_acquires(true, lock);
 
-DEFINE_GUARD(mutex, struct mutex *, mutex_lock(_T), mutex_unlock(_T))
-DEFINE_GUARD_COND(mutex, _try, mutex_trylock(_T))
-DEFINE_GUARD_COND(mutex, _intr, mutex_lock_interruptible(_T), _RET == 0)
+DEFINE_LOCK_GUARD_1(mutex, struct mutex, mutex_lock(_T->lock), mutex_unlock(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(mutex, _try, mutex_trylock(_T->lock))
+DEFINE_LOCK_GUARD_1_COND(mutex, _intr, mutex_lock_interruptible(_T->lock), _RET == 0)
+
+DECLARE_LOCK_GUARD_1_ATTRS(mutex,	__acquires(_T), __releases(*(struct mutex **)_T))
+#define class_mutex_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(mutex, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(mutex_try,	__acquires(_T), __releases(*(struct mutex **)_T))
+#define class_mutex_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(mutex_try, _T)
+DECLARE_LOCK_GUARD_1_ATTRS(mutex_intr,	__acquires(_T), __releases(*(struct mutex **)_T))
+#define class_mutex_intr_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(mutex_intr, _T)
 
 extern unsigned long mutex_get_owner(struct mutex *lock);
 
diff --git a/include/linux/mutex_types.h b/include/linux/mutex_types.h
index fdf7f515fde8..80975935ec48 100644
--- a/include/linux/mutex_types.h
+++ b/include/linux/mutex_types.h
@@ -38,7 +38,7 @@
  * - detects multi-task circular deadlocks and prints out all affected
  *   locks and tasks (and only those tasks)
  */
-struct mutex {
+context_lock_struct(mutex) {
 	atomic_long_t		owner;
 	raw_spinlock_t		wait_lock;
 #ifdef CONFIG_MUTEX_SPIN_ON_OWNER
@@ -59,7 +59,7 @@ struct mutex {
  */
 #include <linux/rtmutex.h>
 
-struct mutex {
+context_lock_struct(mutex) {
 	struct rt_mutex_base	rtmutex;
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 	struct lockdep_map	dep_map;
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 273fa9d34657..2b28d20c5f51 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
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
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-11-elver%40google.com.
