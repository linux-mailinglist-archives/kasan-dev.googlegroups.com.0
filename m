Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIEOTO7AMGQEWDWBNZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 608FBA4D80A
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:54 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-30ba3ad7cbbsf14609901fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080354; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tcrcn2/dH9kmnW1CHZIW17wIk+FH8V+s1CF/kl6q2mC+TtW/mmnM65c+RNqa6awct6
         xwBe6hswlO1qqcq24NikHIASvxgINzEbn7o8UiyMZhhqZsb7SaeOWzKOWk+n5ZdH7qjH
         W9+4GwUjpNvNmPPODqihQPrBTqQjxn/WCvTB47wpZEj2tEpe8xoq9y881JOzOMcMoriU
         ATvyuRcS2zhjSKjWsHwQ47YJzFvsGjaTk6zNVAEWdR9ZsomuT4lADIyPmdyNMl/tLkXy
         lyztQh9KyK//Nat8QQA6ycBjQz2ZI+zSelV1hnlobjn+4J4F7mWOIWZeii6ihgob2yWb
         PLhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SaSD5d0f67GW4AhSerYT+wad8THN3e68++V/VxX/aNQ=;
        fh=wfPSLF1TElsmfGEc7mwflkStLYmg9Q0bBOJg+j2h6ow=;
        b=D7/ROwQbeAGDj5kv3wN5ewxsdaxt4/dCNfS1vDdiPvn2vOuLHLMEv8XQT5SFP33XRQ
         4plopyiW9mY+B474OBEZdb4HV/ulp0huZoRK4OK21mC3cujkRR3tltBLAo0QFidLYpmV
         xI7bqHAOAbYlxS78yUlw6xIUZk/3vAxQUgrfmZA9XHtn/Tof8gsMCNVgnk6yFbfqi2aj
         sAMazwmYHJ6TJeSM2Ol3ej/17XeMVzcgHyE0R5ZX31lbEYbVoTf537pMDeBlaCF3634F
         n+4TfQt/0O5gUeZnbqUCu5aW6Yx/rTAwVTL4VKdVGdrwPRDJfmqSjpSfTkSNrp6iE3R3
         i8kA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=g3aAWd8k;
       spf=pass (google.com: domain of 3hcfgzwukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HcfGZwUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080354; x=1741685154; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SaSD5d0f67GW4AhSerYT+wad8THN3e68++V/VxX/aNQ=;
        b=F9knI5JoMYXFuKdEzrJAsNmx1XZk/dqK1w1BU1haci580v5MHebSAAifAM11wXPjQk
         8WA9loJBqpq4rv0oGPRUwJSuUFdkTDP+OVaKAXS2CdksAT3oYXa/KOFqLkP1QwS5YsQg
         f3Tvni7ZfZJxvAwdkpLJT8iVWv27H3I7VJ5Fz6oPTzOWT0KZjLvBCl9ul59e863yaePu
         QHw+WuEWyyfIO4NbMVkkw11uCbBwpjQWOaRq70pTmNdP0Pcnu0QvJhO+JN2gIhUk7dVL
         DEkQFzDSVRB+1JDfP4TrRR3qH/Yr1GhhpgHLe3wkm99XLXlq5LCCOXT/wG6QEtW9iv//
         ZKmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080354; x=1741685154;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SaSD5d0f67GW4AhSerYT+wad8THN3e68++V/VxX/aNQ=;
        b=lCccwGt+yazKdPSwaaBgar3yFDH/L4v44PawWzBPzReoBNOj7anW8Y5vtDjmrBtW7q
         +QMTAN9CrZR8lTvG7ilhAi8ywxs9QME2WM2+6Eq3pDSz1NiEBB0jKmjLmBEohB2a3V22
         gpfrcPN2L+HuVkBvDWVJ+/yCUgEfr3ix+Isxtm/VNumIk1VWEw/3wL4vmymfV/g/SLZY
         MiCN2D2jWk0Jg24C9V/Yut8GwYTuV86FD9jIMrjsrSaKq01EM4gLYNaQYdx29zlbrK8T
         kb0uoI2P0ORoAZfLZGJz7xRst8LtBwI48/G+ZKJPBo5WbXwgZsffR7zufLi6wDtxyN61
         PdaA==
X-Forwarded-Encrypted: i=2; AJvYcCWscQQe0gED93zB3Q9YiYD5XYxGO+OFSm8pigHKvYG48thZ0mQ9sM8hUhUmx2GzANFAotEPJg==@lfdr.de
X-Gm-Message-State: AOJu0YyzgmEBVK1WeKk5GynomheKttFfkLP99cG3LSIX5YgsyLphCMwP
	DhpvEBnNySq1EiZDAFgeKvbYFv2CRmwfU5ZLNmatx7gIBmvYKVzw
X-Google-Smtp-Source: AGHT+IHwejbGSgkyNvIX5aiv7kxZGiSLdi0LguInbIzLI9tZAeE6w+n84vN672iAGbNqplrjcFU6ng==
X-Received: by 2002:a05:6512:4885:b0:549:5a14:96d with SMTP id 2adb3069b0e04-549756e2591mr679761e87.19.1741080353270;
        Tue, 04 Mar 2025 01:25:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHhORCtuyflssOHnRKvogqvxTLW09zPCadQ065NjNyaog==
Received: by 2002:ac2:4c4f:0:b0:549:7658:b947 with SMTP id 2adb3069b0e04-5497658c35cls51474e87.1.-pod-prod-00-eu;
 Tue, 04 Mar 2025 01:25:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUa3mSu9zesYnruLCpRuHwtWmnH8Xz/utDzwDIyy2b3EgPDxzR3/sjfVoGkjRHFYaR1XENN9zo+fvU=@googlegroups.com
X-Received: by 2002:a05:6512:239b:b0:545:3035:f0bb with SMTP id 2adb3069b0e04-549756e4d98mr909606e87.22.1741080350357;
        Tue, 04 Mar 2025 01:25:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080350; cv=none;
        d=google.com; s=arc-20240605;
        b=a7dfeaUyC8Tiw8ZvJ2Ou1ZyuhWVO1CteLN0Rnx+VdByvPE52dVVzL/SxhlMxd0yxsw
         ISc2xFQC8ykiHkKzTdkpin+YgUn9tbZ2JmS1eMh6kIznJahxGC6+QSG1Vn0pi4y/S7uc
         mfCoQmTbAzKeOYfBkkpxOCTKsr0dgZ+xMr96D8Qv7qqvNh2QGqVXaaD4UaDtqSjg5gCv
         wSsBYvCCAQrXXGXV7Tr+bEZTj+3/kx6Ym6CBqs+oyAS6urvy8N3IG2vS5kgQ8PAOrnMG
         3x1RNjU5l+yZhAu29Xon4runZEBosZpjgIdgdQ8yon8PC2QhrhQTeMsGBhC7zjCaMcnb
         SCMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=IjZvxS6CXb9r/jfHcsWB9NCl/hhxYyJhywIjI+5O6TY=;
        fh=3OdtHMfZwe+2uWNRruxCRJD15HCxSJXkc+C2WVGqxQM=;
        b=I/W3N/pE9qeALT9OurUNEzsNlIEL5fFy9V2LMBs9qGajW/piJQBzivgpLPhTa7GaV+
         lksXrtwG5wZVMYHsaaGaH8FCZu51Z+nf7GUBqRgpuS+pmi7RLoh9RrjpB2wCgT+ca36i
         HVB45LhThKnuvCvBVk0oYf8b8q/3pYh0XKrxVEs48qulwvYAaH90XZ4ixrQ754QAYYHa
         Q3kQ+7ZHewK4J35tVCunzm52uwhhSMUcEYZ5t7X9m6TeJYX7Qct4oNFfAq+jJGQRTTpl
         qOrb0EL+9FsOUlkbspBe7kOAwb2aeflu+P5uBhnlmsG/QmWePfl6x7t9uz3iqFAcZkz5
         +Sow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=g3aAWd8k;
       spf=pass (google.com: domain of 3hcfgzwukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HcfGZwUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5494416c543si232046e87.1.2025.03.04.01.25.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hcfgzwukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-439a0e28cfaso29744105e9.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWl1oMvVevCLVrkoXDHbLmnHGen2ovOFp97IioJeIakDpYTSMLggDg3FCz5Hrueu0n011dZqIr14EI=@googlegroups.com
X-Received: from wmbg14.prod.google.com ([2002:a05:600c:a40e:b0:43b:cebe:8011])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:3c9c:b0:439:89e9:4eff
 with SMTP id 5b1f17b1804b1-43ba66e6b5dmr142151345e9.10.1741080349701; Tue, 04
 Mar 2025 01:25:49 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:14 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-16-elver@google.com>
Subject: [PATCH v2 15/34] srcu: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=g3aAWd8k;       spf=pass
 (google.com: domain of 3hcfgzwukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HcfGZwUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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

Add support for Clang's capability analysis for SRCU.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/srcu.h                          | 61 +++++++++++++------
 lib/test_capability-analysis.c                | 24 ++++++++
 3 files changed, 66 insertions(+), 21 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index a14d796bcd0e..918e35d110df 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -80,7 +80,7 @@ Supported Kernel Primitives
 
 Currently the following synchronization primitives are supported:
 `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
-`bit_spinlock`, RCU.
+`bit_spinlock`, RCU, SRCU (`srcu_struct`).
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/srcu.h b/include/linux/srcu.h
index d7ba46e74f58..fde8bba191a5 100644
--- a/include/linux/srcu.h
+++ b/include/linux/srcu.h
@@ -21,7 +21,7 @@
 #include <linux/workqueue.h>
 #include <linux/rcu_segcblist.h>
 
-struct srcu_struct;
+struct_with_capability(srcu_struct);
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 
@@ -60,14 +60,14 @@ int init_srcu_struct(struct srcu_struct *ssp);
 void call_srcu(struct srcu_struct *ssp, struct rcu_head *head,
 		void (*func)(struct rcu_head *head));
 void cleanup_srcu_struct(struct srcu_struct *ssp);
-int __srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp);
-void __srcu_read_unlock(struct srcu_struct *ssp, int idx) __releases(ssp);
+int __srcu_read_lock(struct srcu_struct *ssp) __acquires_shared(ssp);
+void __srcu_read_unlock(struct srcu_struct *ssp, int idx) __releases_shared(ssp);
 #ifdef CONFIG_TINY_SRCU
 #define __srcu_read_lock_lite __srcu_read_lock
 #define __srcu_read_unlock_lite __srcu_read_unlock
 #else // #ifdef CONFIG_TINY_SRCU
-int __srcu_read_lock_lite(struct srcu_struct *ssp) __acquires(ssp);
-void __srcu_read_unlock_lite(struct srcu_struct *ssp, int idx) __releases(ssp);
+int __srcu_read_lock_lite(struct srcu_struct *ssp) __acquires_shared(ssp);
+void __srcu_read_unlock_lite(struct srcu_struct *ssp, int idx) __releases_shared(ssp);
 #endif // #else // #ifdef CONFIG_TINY_SRCU
 void synchronize_srcu(struct srcu_struct *ssp);
 
@@ -110,14 +110,16 @@ static inline bool same_state_synchronize_srcu(unsigned long oldstate1, unsigned
 }
 
 #ifdef CONFIG_NEED_SRCU_NMI_SAFE
-int __srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires(ssp);
-void __srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx) __releases(ssp);
+int __srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires_shared(ssp);
+void __srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx) __releases_shared(ssp);
 #else
 static inline int __srcu_read_lock_nmisafe(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	return __srcu_read_lock(ssp);
 }
 static inline void __srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx)
+	__releases_shared(ssp)
 {
 	__srcu_read_unlock(ssp, idx);
 }
@@ -189,6 +191,14 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
 
 #endif /* #else #ifdef CONFIG_DEBUG_LOCK_ALLOC */
 
+/*
+ * No-op helper to denote that ssp must be held. Because SRCU-protected pointers
+ * should still be marked with __rcu_guarded, and we do not want to mark them
+ * with __guarded_by(ssp) as it would complicate annotations for writers, we
+ * choose the following strategy: srcu_dereference_check() calls this helper
+ * that checks that the passed ssp is held, and then fake-acquires 'RCU'.
+ */
+static inline void __srcu_read_lock_must_hold(const struct srcu_struct *ssp) __must_hold_shared(ssp) { }
 
 /**
  * srcu_dereference_check - fetch SRCU-protected pointer for later dereferencing
@@ -202,9 +212,15 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
  * to 1.  The @c argument will normally be a logical expression containing
  * lockdep_is_held() calls.
  */
-#define srcu_dereference_check(p, ssp, c) \
-	__rcu_dereference_check((p), __UNIQUE_ID(rcu), \
-				(c) || srcu_read_lock_held(ssp), __rcu)
+#define srcu_dereference_check(p, ssp, c)					\
+({										\
+	__srcu_read_lock_must_hold(ssp);					\
+	__acquire_shared_cap(RCU);						\
+	__auto_type __v = __rcu_dereference_check((p), __UNIQUE_ID(rcu),	\
+				(c) || srcu_read_lock_held(ssp), __rcu);	\
+	__release_shared_cap(RCU);						\
+	__v;									\
+})
 
 /**
  * srcu_dereference - fetch SRCU-protected pointer for later dereferencing
@@ -247,7 +263,8 @@ static inline int srcu_read_lock_held(const struct srcu_struct *ssp)
  * invoke srcu_read_unlock() from one task and the matching srcu_read_lock()
  * from another.
  */
-static inline int srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_read_lock(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -274,7 +291,8 @@ static inline int srcu_read_lock(struct srcu_struct *ssp) __acquires(ssp)
  * where RCU is watching, that is, from contexts where it would be legal
  * to invoke rcu_read_lock().  Otherwise, lockdep will complain.
  */
-static inline int srcu_read_lock_lite(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_read_lock_lite(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -295,7 +313,8 @@ static inline int srcu_read_lock_lite(struct srcu_struct *ssp) __acquires(ssp)
  * then none of the other flavors may be used, whether before, during,
  * or after.
  */
-static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -307,7 +326,8 @@ static inline int srcu_read_lock_nmisafe(struct srcu_struct *ssp) __acquires(ssp
 
 /* Used by tracing, cannot be traced and cannot invoke lockdep. */
 static inline notrace int
-srcu_read_lock_notrace(struct srcu_struct *ssp) __acquires(ssp)
+srcu_read_lock_notrace(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	int retval;
 
@@ -337,7 +357,8 @@ srcu_read_lock_notrace(struct srcu_struct *ssp) __acquires(ssp)
  * Calls to srcu_down_read() may be nested, similar to the manner in
  * which calls to down_read() may be nested.
  */
-static inline int srcu_down_read(struct srcu_struct *ssp) __acquires(ssp)
+static inline int srcu_down_read(struct srcu_struct *ssp)
+	__acquires_shared(ssp)
 {
 	WARN_ON_ONCE(in_nmi());
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
@@ -352,7 +373,7 @@ static inline int srcu_down_read(struct srcu_struct *ssp) __acquires(ssp)
  * Exit an SRCU read-side critical section.
  */
 static inline void srcu_read_unlock(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
@@ -368,7 +389,7 @@ static inline void srcu_read_unlock(struct srcu_struct *ssp, int idx)
  * Exit a light-weight SRCU read-side critical section.
  */
 static inline void srcu_read_unlock_lite(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_LITE);
@@ -384,7 +405,7 @@ static inline void srcu_read_unlock_lite(struct srcu_struct *ssp, int idx)
  * Exit an SRCU read-side critical section, but in an NMI-safe manner.
  */
 static inline void srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NMI);
@@ -394,7 +415,7 @@ static inline void srcu_read_unlock_nmisafe(struct srcu_struct *ssp, int idx)
 
 /* Used by tracing, cannot be traced and cannot call lockdep. */
 static inline notrace void
-srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases(ssp)
+srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases_shared(ssp)
 {
 	srcu_check_read_flavor(ssp, SRCU_READ_FLAVOR_NORMAL);
 	__srcu_read_unlock(ssp, idx);
@@ -409,7 +430,7 @@ srcu_read_unlock_notrace(struct srcu_struct *ssp, int idx) __releases(ssp)
  * the same context as the maching srcu_down_read().
  */
 static inline void srcu_up_read(struct srcu_struct *ssp, int idx)
-	__releases(ssp)
+	__releases_shared(ssp)
 {
 	WARN_ON_ONCE(idx & ~0x1);
 	WARN_ON_ONCE(in_nmi());
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 050fa7c9fcba..63d81ad1562f 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -10,6 +10,7 @@
 #include <linux/rcupdate.h>
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
+#include <linux/srcu.h>
 
 /*
  * Test that helper macros work as expected.
@@ -345,3 +346,26 @@ static void __used test_rcu_assert_variants(void)
 	lockdep_assert_in_rcu_read_lock_sched();
 	wants_rcu_held_sched();
 }
+
+struct test_srcu_data {
+	struct srcu_struct srcu;
+	long __rcu_guarded *data;
+};
+
+static void __used test_srcu(struct test_srcu_data *d)
+{
+	init_srcu_struct(&d->srcu);
+
+	int idx = srcu_read_lock(&d->srcu);
+	long *data = srcu_dereference(d->data, &d->srcu);
+	(void)data;
+	srcu_read_unlock(&d->srcu, idx);
+
+	rcu_assign_pointer(d->data, NULL);
+}
+
+static void __used test_srcu_guard(struct test_srcu_data *d)
+{
+	guard(srcu)(&d->srcu);
+	(void)srcu_dereference(d->data, &d->srcu);
+}
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-16-elver%40google.com.
