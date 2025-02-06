Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2PZSO6QMGQEBJJZXCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id DBAF0A2B057
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:19 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-5440ef9a3b2sf580349e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865899; cv=pass;
        d=google.com; s=arc-20240605;
        b=SCFM5RFuMjngRmMgw20T9rOHpCTS7nDVoqjrr/2Shypsp0sRXEln/A+I0pjG5mDA2g
         46fbItfMyUKCtZ+cqIjEAg8TeD5NDEDMo0owwrbhreZXQoN6iWB4u3rOUiLuI2y9EPaB
         FoLj8BPcd4tFLGVYzpwh84ScLexsr8TyiaVHL8c7WZWyQxvmGqexTswH12fjxEzTZzo+
         12L07JIY5tm/vYCiR05OgJbA0ZmzRyPFi/G1LcikgogvVN2h+1TfpsldsR1gLsD/MJ8Q
         xM/skaY39xz4yZ/m2Mt5PeccrysStzMu7EShPOpD3QXX1E+CXRFbkCvJxr/7FqFbmP7S
         AqyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gOQ1PNCTeamJsacyi/XvqJ4XLF286W/GuFUYd7JLxSQ=;
        fh=l7I/dy+wXXyqwN0M+pwXU/ZGVHPVtiaIjxO04k/lUYc=;
        b=ZzGQdu+/T9fUisZPDnFZuttHnbkAc0COV+DBphRN7gjrLMiQiTDCU90/OVBFmY/LlE
         9qnHyKYnAgZVyQJN6NIZ5kmB61xelQKHMVrJw5JbAEox4BFSivIlC6JJXbczb8GF9vRm
         PmT2kq+hHEIV1rLXH8Y6oQSUxzRxFRPQjWZ6i2oRC2ARGNwpCGqWPcejOC3sc7rpU1oj
         UP71hYNXURuzJpsfpizKhIBqA1qqJwEv/KR5V/EHYR1lYh0+7uAiWxXDN30x5K8h76O7
         0Fl3LCEKbxz/MLO6wRz82bPrnrsZoS2qCFnqiykXefjtnFo+D4KlVvAmSn5+eRnGX1vy
         ayjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QeFOhkdJ;
       spf=pass (google.com: domain of 35fykzwukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=35fykZwUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865899; x=1739470699; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gOQ1PNCTeamJsacyi/XvqJ4XLF286W/GuFUYd7JLxSQ=;
        b=t1mUz2tA/9E12rI5Rm/mwz8ICg3jXYhdj9yP86YM/u9Ua3oKZtUDAQxwwCru/BRSdn
         HFG9I4VdCe92/mYaUkJ5YiuHreaQHVz8EggCeJ3JxfbceVpFv4DCiSz6lM/BKcwypYwD
         VraDhPPFti88EcdvIzrD8FG9I1xfzzN9EoJKj3TG5jZVPQn3tUCXQZ5p/91XugMUmNd0
         UWQCrGyuhTIQ7tq4zs2lCVH2Q6HLAAZ7MW4fkSQOprNtCyrKwMsdCClA9SrNDUbqvlmf
         M5zGM5VGdA8ETAi2oSzlBp/cyuN5m4MUTWvAeAXAdIPk7VFWoTkF/oXwUHCx3lM56kFE
         Gr3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865899; x=1739470699;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gOQ1PNCTeamJsacyi/XvqJ4XLF286W/GuFUYd7JLxSQ=;
        b=mrP+DyQj3pIsiS2umbpfTagWR+B63jRcVId/y8LjEFLme0ao5JB1PiNK7UDroV1bHV
         YvTXqNRuX1wEsMvI8yu3qbfSHy0kGre5N0k09WBgeE8DlIHe1PGZ16BE9lCu0Ob3o/bi
         SvpzH1kLNdBJiQ9+UDc+iZHGAEno+OeQ0WqojF+zknuooQnkN92ddqVaL9c6i4HjmQ21
         XDd7IHKoa5lNwUpkXLgboxybg8fgzpPlwk6IbL5+99W6RGntMj/IZzKHNpbHKJPBJerr
         2vZr+3ZiVkpfyh2Hf6uiCRjq7ePRwXZJOTC8qwufKLRUrFnoHSns2y5bvlHdNFUQu46g
         c3ew==
X-Forwarded-Encrypted: i=2; AJvYcCVtA+23Zn5jLdu8GdD/axkEc1HrkRgsAavRE1Udp+5TQjCaJyR6ShMhaEkt6BEThJjrsJYQog==@lfdr.de
X-Gm-Message-State: AOJu0YzFnzHnAuIWewhg7FyhxGV504MuAr0lf6ZZ3wLF7z0mkXXXA9BE
	XX+cvY0hCZpSm/Hgvzaf9D5ibxQR3XR/Rl0WvednyhJXTJHa4JJV
X-Google-Smtp-Source: AGHT+IGddqzpMtJP7ZzoWCLSulihAl5ien5Pb1jj67llZ235B3+nfhm32KMp7HiZKSR/Ob6lvGXVXg==
X-Received: by 2002:a05:6512:70e:b0:542:223c:30f5 with SMTP id 2adb3069b0e04-5440e6b19f6mr1451270e87.24.1738865897574;
        Thu, 06 Feb 2025 10:18:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5491:0:b0:540:1786:f554 with SMTP id 2adb3069b0e04-5440da9e239ls300649e87.1.-pod-prod-00-eu;
 Thu, 06 Feb 2025 10:18:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXnjiClUTKuo+BAnOLUPVL4ajvPlJ12/Fw+Mh/I/xt5gUR+7E/QQG79nzRNU2ZKf1dZm6uFE0IqRao=@googlegroups.com
X-Received: by 2002:a05:6512:3696:b0:542:8c7f:cfc1 with SMTP id 2adb3069b0e04-5440e62e47fmr1394933e87.3.1738865894385;
        Thu, 06 Feb 2025 10:18:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865894; cv=none;
        d=google.com; s=arc-20240605;
        b=ky7mbx76cClhIFYurY5Mp773Z1mZiq4QBlp4V081Nc7fJlhluR4fcBBvIIFWkTD2z+
         lX8e9sDttjve1z/xGX8KpnvLUueBUSgHcZ+SUbJWaJM75qJ9HxjwM4+8+BoPUWSzYev1
         Br+28S3nWRZh8me2OnMQJOrEFAu4JQ6bicfmJEhexKW5tQa9LdAKyEtSHtns3PmYgHUw
         nAHBPAp519qGXV6NlWqI33JpI55efHUTGzSHZ6ZptJoShAst8dTJliljOQoNzaBM5Tn5
         rHEy0sUwhjwwOxSukatN401YnlYO9tP2uFAhxp4Af1rdjl5YN/m7/N7jECc6Ry1Dxs9n
         wCCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=745NDxNXHBzGRxy9OOyVrOwCOzE5UpzdpD8KZdhsNVE=;
        fh=U8TUPT7wVk9HgdkIl4j0J2uiOcCSgydM0FQ/Ko8uayU=;
        b=NfHl9KoKXiN/BaR59KhbZll/TcOnhyB2hHXI59djHksAQFIu41TiFDnOj8Xjo7vqTX
         hDo4iuyUcaCZHGBroi+m7W0mARAPeOOQEkFq5dzt1w0p3IwLyGNM+tydkDBqaIa1sUD2
         gv/hHkQsJE4UkmhuzfWDV6yHwyF1wBV8x9N2hWhESMK45HgvayIn38oLhJN6rdWMlOKS
         FqokqqDgO44azujazrtL+ZAUUfw3+XJWtxitqw9KYLUrqbY5FYYXgmtdZfGuHCf4A2NR
         Zhg1aMujgLTBWnYwHPL3uKFmIpiv0t2xngUToZ7kCJwWy5p6APnYo0oWuWDoKTLyC1L8
         WJSA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QeFOhkdJ;
       spf=pass (google.com: domain of 35fykzwukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=35fykZwUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54410612783si29081e87.8.2025.02.06.10.18.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 35fykzwukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ab68fbe53a4so173137866b.2
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWKki4ATT8KQaQFRNoCsJqq/h1zpmkpU55Mnf4WW2/6q5Isa6B68avgH8XHpK+s/vWpj9gcghdrFr8=@googlegroups.com
X-Received: from ejchx5.prod.google.com ([2002:a17:906:8465:b0:ab7:8024:1fb3])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:906:c147:b0:aaf:117c:e929
 with SMTP id a640c23a62f3a-ab75e358d20mr804115566b.57.1738865893605; Thu, 06
 Feb 2025 10:18:13 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:05 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-12-elver@google.com>
Subject: [PATCH RFC 11/24] locking/mutex: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=QeFOhkdJ;       spf=pass
 (google.com: domain of 35fykzwukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=35fykZwUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
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
index 904448605a77..31f76e877be5 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -85,7 +85,7 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/mutex.h b/include/linux/mutex.h
index 2bf91b57591b..09ee3b89d342 100644
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
+extern int mutex_trylock(struct mutex *lock) __cond_acquires(1, lock);
+extern void mutex_unlock(struct mutex *lock) __releases(lock);
 
-extern int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock);
+extern int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock) __cond_acquires(1, lock);
 
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
index f63980e134cf..3410c04c2b76 100644
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
+	int counter __var_guarded_by(&mtx);
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
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-12-elver%40google.com.
