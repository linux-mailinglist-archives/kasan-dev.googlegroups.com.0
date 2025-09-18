Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRNDWDDAMGQEIAUMQ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id BD3B7B84F90
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:05:58 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-45de13167aasf9993785e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:05:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204358; cv=pass;
        d=google.com; s=arc-20240605;
        b=NIF/0BvrQwE/Y3Oz95eMI/PwJ5Jw5yAvD9qUm3ezp/bGSIXBKoNIwxOd+rFXSS5+Xj
         oaVbRyCGsxnEIp2tWKzvRwTM6UaZWToiG6cKSDGIQvAp4uKueXBAOdHIX6P1nCC0jWOq
         OSOJq2hQOqVLClnQxHiwgd4j11woBa2PdoaGmtFv3702Fb4m1c0aJ7uZvXsLK3scPX1o
         HmBfph7CP5u8yFIrXN9oFZ7ksGF89Q+XOlwt//xv2FyWY6BJLlNCsw+/d0yXj2BN9pDD
         v7z+midlBMDsslI9+6c386F8baVAooAyiiedydDJrawoX6XWPoUZRU3KQCbs8mzno3Ss
         Tz1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=nbMkg7t7LspiqV6w3qS9rn2xLUXD3+x0AZTZVcTciHk=;
        fh=nwdxCNRoMSfAi+PB1SscCofmAqdNixwHRXXgQipJl6Y=;
        b=CMeQV/RqGUuuiBDFAfHlqwggqR5aHbo7TnDouxKcM7vRQBsGPfEt+L3kDo7BzBA3PH
         LIaP2lrsokqqp9816LefK6aiGHQFhmN1UsuQdVSMfBVDBXcI4jXhEs3XE55e6mLYLAcf
         ovjlzOTqRBzstMgjES76dCT4y3WDaXKJMD8yKm6jJ/quWZyw90HpTg1htNU+s7Xw4F4/
         OT9fX0U5OHsjiJnd7WsGbDrQTWyQ5mGAJk2tCvqSyHKLlJ5toZm+G63Vb1spsi2K8dkW
         Qs/XgL1eqFSCqta8In7D9HogINeIg8rI46tbbPu11eRKNO3soFH/dlFTkFjNpxyb6NtN
         qb8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LoWCAITu;
       spf=pass (google.com: domain of 3whhmaaukcwmfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3whHMaAUKCWMFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204358; x=1758809158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nbMkg7t7LspiqV6w3qS9rn2xLUXD3+x0AZTZVcTciHk=;
        b=UdpEPVrkNgt6uEz8c/g4n1SFoj4ew43m1VejQdVeDDeWd65U03riJCOeNIXVFBhYRr
         l5ciU3up+BEogeB33jNW6VXAk1+IsnH0ueyYwselMSY/bKcxRwqjpRDTayddyV6irKz0
         mLhuJjqp2HMMgIz1KhS0CamWRjTWX4DjwD+HRRvChw7RV6iVO6kislWRWUpPQPhBRCkS
         tQPDoCMLajf1T4eJHDsT1hpqbbKZ77K7NgliUKWP9v/U65ackPCkTgW1XzXvLHmV+46U
         0Is+p4WUUQU8C0nYgXzj/HH6j4UFr4L0/UMA7fKHEDC4AUuzAXZXyDruJFfPD+e7vVJp
         bD6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204358; x=1758809158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nbMkg7t7LspiqV6w3qS9rn2xLUXD3+x0AZTZVcTciHk=;
        b=qIHpsMM4LHn0Pe3JdvR4xtkVa68a3D62xFRDVB+5KwlPkjbB7eTi+AF4dx7HL30lIW
         +rc++/q9AX9FETvuJCqqofL2vrUiFBE00jrKWKnykTnq/T1Ly9YQJjoVmvGjcoWvw0zD
         Xt4aaWygZC7fef7Mc7iul06Igr8v4XiDG+cLftT/QCGMqtsc1s4vizoiQ/0CIfR5MZ3S
         9WKdlwrc0n9Rw87TRllZxZR0XIkgHikmeM//15WjwxbP8i8VXKPuYWs3lXJZ/5BlhWs4
         KJiK4wMB0w5cwiIevCYEOw9LqukeOjsW4EaPyv3SHeepjWQSu4o45uwb8VZoXnXWnUW4
         xdnQ==
X-Forwarded-Encrypted: i=2; AJvYcCXLdG7rwaTs/SywD1d5yjx3GNBSTP2uP/PhE4GUcbtqHozsDwugswxTGEgyJbqP2T/+JSKrHw==@lfdr.de
X-Gm-Message-State: AOJu0Yyo+OeZSwmpY6zwmOTedEpmAn+1srLO3N1eI+WzhMa479GCM3ZG
	VpQIbRDuqvlVl5jc3Jfp+yry2sZSFUNX3VQhI/Wv7Cb6uZnNIPPl28kA
X-Google-Smtp-Source: AGHT+IFOXWUybL8iZ7JAt8dWaSBlEKq6VqHUYcUix5TbdW5Eu9Sfp5AgxBxaeetmcLoJcZmof3iHLg==
X-Received: by 2002:a05:600c:b86:b0:455:f59e:fd9b with SMTP id 5b1f17b1804b1-46205eb1674mr64725315e9.24.1758204357985;
        Thu, 18 Sep 2025 07:05:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4viLfsI3IjfDToI9OX2ZUkRr0foGrbvc1mYaWFeSYJhg==
Received: by 2002:a05:600c:181b:b0:45b:990e:8515 with SMTP id
 5b1f17b1804b1-465454cdef0ls5472235e9.1.-pod-prod-05-eu; Thu, 18 Sep 2025
 07:05:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvDi8xS0xDxe4MlbrLwGJ7OXF/oCL/xJlCegQUyEyjpPS2o9Nf4g/oeeUQJ2sXTyFKcRvWGr+KE4U=@googlegroups.com
X-Received: by 2002:a05:6000:1863:b0:3e9:d9bd:5043 with SMTP id ffacd0b85a97d-3ecdf94504amr5206861f8f.0.1758204355058;
        Thu, 18 Sep 2025 07:05:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204355; cv=none;
        d=google.com; s=arc-20240605;
        b=COTNS0U+3FBLJd02WgZOZOhysY7v0eP5DgrVwjeJXHS6AO5G0mF+ZLH45oL9TdUG9q
         Q8+OVTkWLM1eJi9FxN65ZF3jupkJ/uK9ok9hQa+VgwxfYFdyOIUAeCZHwhke57TFtdme
         BASYDx4zVZTP7UP1yoLo9o8XQ9wgDH4ebB+Dz+h48DRPiYy0qTaryAESV+rzGnSdATPM
         lqEBWz4g2O4xFge2VgeYJZQT9mTOpOJ6uHbaAwZkGbCusz8xSxc/JvVuu8THuKhWpHXi
         h1GMSIfvLEuxaEhD6gpsGgzkXCfI92vdjXOaTEFUHoS2l5i9lGLcwoGN/BSD1/ngLrrc
         ZQmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=P08xa+RVj+NYVod6vjIgPrZ1iS5A/lHieiP5dR8CwWY=;
        fh=88Nc0bGuHvf84OwA5FrT1+WzaolrltRSITcaHAG0ETI=;
        b=EHlJXvwKGmY7LV4Q+Ci8hb1d4FUeUc8f0TnniHAMLjgdk4z4CSO7vjIROO/1b3zEIt
         TKeH1fHCAnxgJ0mXIkgSSEqmUb7hGMvZsQqHxbfOj6jAiJmzQOou9CJAVbWwdzUCD68p
         9wKlXcS0TtV/xvqilisvyUfNsrhnLvQNnovfAF4j2DaB0DqxyrCfhyVVZNf3ayukNr74
         sFXzNdzmSFyugRcXsd4XpN9Uq5l+vpzSQHTFExKh3vEomJskayDqk7GxU+TBvRjv8uRA
         BC5uHxXXjf+VjeBZ2TyxbAw7OBAh1RbUp7V0sGFVV7s7S7WICeoqLdyvUzFZ1mF9i3HU
         MHxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LoWCAITu;
       spf=pass (google.com: domain of 3whhmaaukcwmfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3whHMaAUKCWMFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f32088d94si559865e9.0.2025.09.18.07.05.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:05:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3whhmaaukcwmfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-b044a42959dso158180966b.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:05:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXS3JkYEA+yVgkC/8D4cdM61TBJHZHIB+8VMzqI3Qpdl9tXXn0oLWw6LLNMJX431uiSsBv8WAW3a3g=@googlegroups.com
X-Received: from ejctp26.prod.google.com ([2002:a17:907:c49a:b0:b0d:2e46:f67])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:6e8d:b0:b0d:5e0d:eaa4
 with SMTP id a640c23a62f3a-b1bba003769mr678528666b.16.1758204354138; Thu, 18
 Sep 2025 07:05:54 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:21 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-11-elver@google.com>
Subject: [PATCH v3 10/35] locking/mutex: Support Clang's capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=LoWCAITu;       spf=pass
 (google.com: domain of 3whhmaaukcwmfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3whHMaAUKCWMFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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
v3:
* Switch to DECLARE_LOCK_GUARD_1_ATTRS() (suggested by Peter)
* __assert -> __assume rename
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/mutex.h                         | 35 +++++-----
 include/linux/mutex_types.h                   |  4 +-
 lib/test_capability-analysis.c                | 64 +++++++++++++++++++
 4 files changed, 87 insertions(+), 18 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 9abd7f62cf4e..89f9c991f7cf 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -81,7 +81,7 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/mutex.h b/include/linux/mutex.h
index 847b81ca6436..7e4eb778d269 100644
--- a/include/linux/mutex.h
+++ b/include/linux/mutex.h
@@ -62,6 +62,7 @@ do {									\
 	static struct lock_class_key __key;				\
 									\
 	__mutex_init((mutex), #mutex, &__key);				\
+	__assume_cap(mutex);						\
 } while (0)
 
 /**
@@ -157,13 +158,13 @@ static inline int __must_check __devm_mutex_init(struct device *dev, struct mute
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
@@ -186,10 +187,10 @@ do {									\
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
@@ -207,7 +208,7 @@ extern void mutex_lock_io(struct mutex *lock);
  */
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
-extern int _mutex_trylock_nest_lock(struct mutex *lock, struct lockdep_map *nest_lock);
+extern int _mutex_trylock_nest_lock(struct mutex *lock, struct lockdep_map *nest_lock) __cond_acquires(true, lock);
 
 #define mutex_trylock_nest_lock(lock, nest_lock)		\
 (								\
@@ -217,17 +218,21 @@ extern int _mutex_trylock_nest_lock(struct mutex *lock, struct lockdep_map *nest
 
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
+DECLARE_LOCK_GUARD_1_ATTRS(mutex, __assumes_cap(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(mutex_try, __assumes_cap(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(mutex_intr, __assumes_cap(_T), /* */)
 
 extern unsigned long mutex_get_owner(struct mutex *lock);
 
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-11-elver%40google.com.
