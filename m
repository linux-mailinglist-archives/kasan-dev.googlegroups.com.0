Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUO77TEAMGQEL4LBRQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 98DA2C74C24
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:12:18 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-594285c6850sf456339e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:12:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651538; cv=pass;
        d=google.com; s=arc-20240605;
        b=b1M4yrt43De3vp8wiSyEroS64+eNVVUS06SCCSB5C5nBVx3AZ9CCKfdNX1LGL94tS9
         4thEcPJN0ZlvI43XnbYGHRq3zaJYZ8LsfE+0rgblBzWcp5XziijnMMkhtp04j34cDqF7
         0nMun7mPL8pqag3net/8rPDVPzLiVyoxtxrAJoBXSMJ2t6nwK5SuqANWLRhTHec8berN
         IreCSfufbQmuNalE1QZOViSeJKYLJDDAiPm5WtAn3kWJAUMCvn8U9dZMqSCyBd/BBguB
         Ou0PW9xW2EmxCBSuQDzR7Em7OkzTIMBDqgwHsLqKuQimzEqCx9JhDV5ksUaUmpRlS8+h
         KDKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=o3awSWCP5xuGZXo9pRVDu2uWzynCKnOSWQf8Fgs/N5o=;
        fh=76Wi8WfUXlyErRoX1rLb2ab5q8bun6NiP3XudtHtth0=;
        b=Us0BgOa4qHrqiMN+Rsh++CKzVcTUFnnzf+XnvDY/Gs+3r1v04h7XwMW8kkYaM2+EEq
         ug9QowO5f32bzuO8LPCggcq2Fb/W/ToBqAiMFD/vwsKHtyH/EweN6GA0E0woj+5nt2aN
         DbhBgZhKDOqlTkrSk84geQcjZFhPozqRJzHPL3euqH/YhogT/5D8N/OIo28lKntlMnAP
         wHhNAwA5yYylC7BAlVr+fgkFVuiKLauhKSf3nFIjNS9H2p2vsN8pz94LgElaxRaKBgLm
         myJf5RhZwY0iZvQPswRffMpxiIJyFViKzeFf/x9eQT7IJcGzkWJV+Zp6m+pacz6dNht6
         kH2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=u0Qgv0vC;
       spf=pass (google.com: domain of 3zs8faqukcfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3zS8faQUKCfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651538; x=1764256338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=o3awSWCP5xuGZXo9pRVDu2uWzynCKnOSWQf8Fgs/N5o=;
        b=gElW7kGsBpa6jrsQRY968+qd82TzwIMFNbktEAIBJVnKdoMNm3fcdXM+lcOq4DgkFk
         RDWi9kp1m5oAYwSBRuUCwi3QghlXavQ1nQdfUQ6yv70yt6tmGhZmrrG8luoilDsiE3VC
         fBZGCSsEh47FjrKZlb1pxbDn53H4I6EqkSmRHVhSSd9LxjFSIyICgGduDIWhBGZbdKT2
         6YZGG2lFIz4jnvRIuCNC46Go5ORZdGymjid2OwXLInChgMdItML2rVCFgKpuZWvpiFLt
         ZlS80g1hS5jM//X74O8inkBjs/hgoaRe0W8DO6xtGPU3T9L5bpwxM+be+RJFC3+nAVaA
         +cZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651538; x=1764256338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=o3awSWCP5xuGZXo9pRVDu2uWzynCKnOSWQf8Fgs/N5o=;
        b=XplYelx7LU5JMEAPoAEAm4bxb4mqynC0gtG+I/c3T/jPzyJNqLETdLQja9ju1zypIe
         zk+2hWKR4w3sRvRfaUC1gojGLdo8Dy5TVk7xIprUTzU0np2DaR49ftk3ICYEfTJb2JQl
         94cG2Fx6YMpjXL7N9+c0PGopKjmH6x4V2Ebk9lGAMZJSsacSr9PBhHgfDQeaxKnr/G2B
         VGxVNn91kw3DjijLWCV8b1NFzlC23FnahKzbH95y3CNADB3kZRumCrsZw3w0NwocyQjJ
         DNBzOgzbGV0pAGyA+n11m2ZyNFgJRZcP6fHWwg6wUMad8ZVSXK2SWGpgQrnqIbgXaFX/
         ZTKw==
X-Forwarded-Encrypted: i=2; AJvYcCWOaMj2A73A5ANZELdMyduLcgR+4dviWq7Ff6Bg7KfqMK+UVXeY0TYJz69m1+1T1CCf0KeXGg==@lfdr.de
X-Gm-Message-State: AOJu0YyvmuAzXEArDA/Hz67C6jUGrD+zQO4rKbA4IM3VQHT9eLhBYhX9
	JlxFs9wEmOJRBUJ+g0ygvQOnCZ2qiK4W+DbQhu1qBCP5u7DQVRhTYHTz
X-Google-Smtp-Source: AGHT+IF7rfV3YEkD7xKc7Be+Q0qe9lun3oSkj7rYS/10s6/tpevw0XjLALpWt5SElSm4JHkrPJL6jQ==
X-Received: by 2002:a05:6512:10cb:b0:595:7df4:5a73 with SMTP id 2adb3069b0e04-5969e2fcbc7mr1317090e87.24.1763651537762;
        Thu, 20 Nov 2025 07:12:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YGCIBhXfqI56+aiBVNu/bHysuT3W0xGo4jAdUhgyp0Hg=="
Received: by 2002:a05:6512:252a:b0:595:85d5:d930 with SMTP id
 2adb3069b0e04-5969dc10975ls343010e87.0.-pod-prod-02-eu; Thu, 20 Nov 2025
 07:12:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU6ZSVJINnQYBKdRXnuUQOFgBzpu89Mt8+wAxh7dn2yxNzTxw3CMn62RBFSZrXISJ4s6rQPu4ZTnRk=@googlegroups.com
X-Received: by 2002:a05:6512:238d:b0:594:2a33:ac04 with SMTP id 2adb3069b0e04-5969e30ac67mr1273140e87.37.1763651534608;
        Thu, 20 Nov 2025 07:12:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651534; cv=none;
        d=google.com; s=arc-20240605;
        b=kSFDIKCtREZK1pY/gal3KGHQBlIyLNcPnc0KOdcmRlRh1riVmyP0RVZ0PuY8QVvEyz
         c5QqOW8wwWhswHEx0W8jTnwJwEfLRuM+CvAp7GShUpF14r+y5X5CaGxvr2ZjmuZHhaep
         EQsT+kyCZ0rgIIqoAlwNV5FNbdv3lsXwzZv9W9QieCFEQk7dvOS2od8EXbVyD9BGyKwW
         DmhTZb0a/oV/WSpP+Eia2Rl24FQe8R4DP7f2u9984DzRZV/o0ZbTpgXPxvJ9QgG5QiSj
         dGuz/cIxfWhWGqJ09yI/5xu3uf2FyXJQuXAyiNlJ+GCfXBp+NKcKs0ph9PM7/3Eh+gjz
         naGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TcdgfkZVjo+28iDEn5YG970J38eiF4zhn7KHxHB91wc=;
        fh=qDnu3OBMwptZIgsuzuKIP3VyrpN9ebXlAtfvbtK8XNg=;
        b=FyaWSTPSLdmgOXY5RKneCgREL1ytGKrA0klj1KpgkDE9PXE56jTVs/A9reBxV5wNfG
         dVLCKKYF9ci4JBXpUqFGhhaUSoO88K87t5iiAu7tkiYLvlrlQzI5M910zpoOgXRjppIv
         hRIQcnVRBRbchKG81bHJIeJefsIzl0DYZfRFKFurPokEa5w/dvtI/oHyIpY7h7nZNGcw
         eOkDn6fQUIto/yOvcs5AaNKmcN2VP+E/2OttAGhlPbiAR6bm8SkQUNKSO+qVZRj7khp1
         3FvxmtZFRRLIQMDKqdfuCgl0UAAnlmXB4SW2blJL9olwfeab6huidkW1oKqx86PPyEMW
         yQ9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=u0Qgv0vC;
       spf=pass (google.com: domain of 3zs8faqukcfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3zS8faQUKCfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dba0852si45587e87.4.2025.11.20.07.12.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:12:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zs8faqukcfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4775d110fabso9552545e9.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:12:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVDmYnIbauHsfSFSw6gbuqfeKaohuqgCcorjorxsXiohsF5U0AJ8HeAgZoqU0f1NduV7iwjMyT2A18=@googlegroups.com
X-Received: from wmco18.prod.google.com ([2002:a05:600c:a312:b0:477:d21:4a92])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:450f:b0:477:557b:6917
 with SMTP id 5b1f17b1804b1-477b8a98d9dmr32529805e9.18.1763651533655; Thu, 20
 Nov 2025 07:12:13 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:35 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-11-elver@google.com>
Subject: [PATCH v4 10/35] locking/mutex: Support Clang's context analysis
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
 header.i=@google.com header.s=20230601 header.b=u0Qgv0vC;       spf=pass
 (google.com: domain of 3zs8faqukcfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3zS8faQUKCfgjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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
v4:
* Rename capability -> context analysis.

v3:
* Switch to DECLARE_LOCK_GUARD_1_ATTRS() (suggested by Peter)
* __assert -> __assume rename
---
 Documentation/dev-tools/context-analysis.rst |  2 +-
 include/linux/mutex.h                        | 35 ++++++-----
 include/linux/mutex_types.h                  |  4 +-
 lib/test_context-analysis.c                  | 64 ++++++++++++++++++++
 4 files changed, 87 insertions(+), 18 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index 50b57a1228ea..1f5d7c758219 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -80,7 +80,7 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`.
 
 For context guards with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/mutex.h b/include/linux/mutex.h
index 847b81ca6436..be91f991a846 100644
--- a/include/linux/mutex.h
+++ b/include/linux/mutex.h
@@ -62,6 +62,7 @@ do {									\
 	static struct lock_class_key __key;				\
 									\
 	__mutex_init((mutex), #mutex, &__key);				\
+	__assume_ctx_guard(mutex);					\
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
+DECLARE_LOCK_GUARD_1_ATTRS(mutex, __assumes_ctx_guard(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(mutex_try, __assumes_ctx_guard(_T), /* */)
+DECLARE_LOCK_GUARD_1_ATTRS(mutex_intr, __assumes_ctx_guard(_T), /* */)
 
 extern unsigned long mutex_get_owner(struct mutex *lock);
 
diff --git a/include/linux/mutex_types.h b/include/linux/mutex_types.h
index fdf7f515fde8..3a5efaa2da2d 100644
--- a/include/linux/mutex_types.h
+++ b/include/linux/mutex_types.h
@@ -38,7 +38,7 @@
  * - detects multi-task circular deadlocks and prints out all affected
  *   locks and tasks (and only those tasks)
  */
-struct mutex {
+context_guard_struct(mutex) {
 	atomic_long_t		owner;
 	raw_spinlock_t		wait_lock;
 #ifdef CONFIG_MUTEX_SPIN_ON_OWNER
@@ -59,7 +59,7 @@ struct mutex {
  */
 #include <linux/rtmutex.h>
 
-struct mutex {
+context_guard_struct(mutex) {
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-11-elver%40google.com.
