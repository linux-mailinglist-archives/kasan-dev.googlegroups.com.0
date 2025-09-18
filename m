Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTNDWDDAMGQE536IRII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id DC85EB84FA8
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:07 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-36396f4f31dsf1007351fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204367; cv=pass;
        d=google.com; s=arc-20240605;
        b=XRxXlFG1kOcTUwpfNXVKngeaorY8qFTY9rQpC4wB7LjrCUvg6+HtfUICl8mMNOIMbg
         5GZuaHWMTe9c0MEcm/1pFiVzh0ZK9Km2O5qd9CQNU9y7uktgfM/wEwPqJ+Ui696PTFCg
         RKdpnm05MV34FzrKOW0pQSHAmYvUB549TjAUAg9gpdsGvqwjAZkezNNQ05JGdCcg3n5V
         KuQXiZD6PlkMBRiDmaElidVslP4RXKbDlMtHa0nn1h8k0wNvhcL6twH5QxXoKgNixIAn
         l8yFoAn22LJDpT/JObjcesUbXdlqlVVxs3xQTnuLZDFiHrbguuMLJaMdnt9E1StD2x2D
         Vq7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=maYUI1OUByEj5eZxRLvv1Kj+EYEBLckTilG1Z6QIWnU=;
        fh=K3VKUJQI9NAXPBK6NYmD6wy3NMvrhpCADyoMj4mvZ0c=;
        b=OznUPu7iKS9wcEXfzbwclay1KMLqb+amkF+ksqra2E4Vl29H50dnXY8BiGLFNSUJ4M
         2gqt3tk0Hajykc+mAXrC6OTSMpNYe+McQCJrja2tvdmKBs06ii1eh6Lz6nmEeQvNentp
         PamePM/z3xUI0aWh+nj1gO7/T/VN8JZfcwzL7aLLGUoAZCWy09VhykZl3Qw9X7idoY/d
         bh057kCW/Bajp/br1NY8+tBKitA4yB/Yk7j0fFyxGVqOHpko2l1vhZt57E6Q0gPZ7SGi
         EQJwT6IH7C5F2CYrsLZobwqYLe11fQB++ENv/Q3mWMos9R4ooqTKv/pK5UnNS4GMPsT6
         pcLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gLf1iXL6;
       spf=pass (google.com: domain of 3yhhmaaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yhHMaAUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204367; x=1758809167; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=maYUI1OUByEj5eZxRLvv1Kj+EYEBLckTilG1Z6QIWnU=;
        b=cD+pYmeoiDpGj/tBuR81l9hiJD0fJlu9k3xhAAa74e2ygJOCOrAdHOyRfDw2CNNkRH
         zYxPPPNkqb4RqqS7jMgqsPm9XLAW0sBMreDUlbbK6iXz5iBBn9M0wZ6+wxfgQqwG5wmd
         fb/ZmbXv1g3Vakzy+0JsVSGGPAMSk21UxMNlMkwibq/GgoyGsM+bldzIi1n/R75rqt9W
         C1PSOhGfivOSOGFjVY3PXwCFysyFjhRR0qZjuP39TMXBZ85NeQXFjZiaT+Nki+pIJ+xs
         gfFmGHLpUeibwtmeupXoLBBaRL9JCwE3ycyeINfIcOhoevYXWE2u7DkuP36olP8Uua8w
         6TxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204367; x=1758809167;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=maYUI1OUByEj5eZxRLvv1Kj+EYEBLckTilG1Z6QIWnU=;
        b=lusZ/dXbGyGTLJ2iZZmzX68/6FCuxrUSkzJwhmbo9bXVygTxQ5WuRZKI3PSq66X4Kq
         cu37NZdI2EIcBlgXRAIJEE3jKMk0ojUfqGNBIgPgjn8IPuRJeMS6cLxt1SUZ+42jcEVv
         n+T6g0TaNZbsUyJAN5Vw7cZb2d+kl8VnhuaXxfwU1eR/L0SUEFNjen+s0FBrdzef2nIf
         UBX7x0Q+U7hJC4u2Yj+wkCwhb1gdVZVr4Wsyno1U3cIhsW2UXc8RMPtnpr2818LMxW3K
         Qh6RFMdQAygWuYkgF8rTVn78DYypQrCxawJ535ZB1NcL2P7e0RyIKFnKXfD5ojw0yw3u
         veFw==
X-Forwarded-Encrypted: i=2; AJvYcCVY1rnhcSs/noBERcuUQEBFp/z6HybMWO8m/w5UVZo/FLdXF710iNPDar6djcGc4gshK7bc5w==@lfdr.de
X-Gm-Message-State: AOJu0YzBjfufGPrr4SYfdn5A6STE60l+pLn8QVOMvqCTgABnz/a9L2O8
	DXdDr/HBupiwfjx5j0cnG2m4YXQHfnHpz8Ows+nGJFvy0T1axmblwlr3
X-Google-Smtp-Source: AGHT+IHsuRwO8sYIme9ethbqo5OZib6qLKSx6d2/+xI5CYJsd9aZaxUqBYtKj9Py/tpH/81N4Thsxw==
X-Received: by 2002:a2e:9c56:0:b0:336:8be2:a6ee with SMTP id 38308e7fff4ca-35f64ff289fmr14567911fa.23.1758204366622;
        Thu, 18 Sep 2025 07:06:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7wRoVvvBeWmfzyt64QXFLPkTKC+m6nMef8AOHq7XSxaw==
Received: by 2002:a05:651c:4391:10b0:338:97c:7be4 with SMTP id
 38308e7fff4ca-361c985b295ls2749021fa.1.-pod-prod-04-eu; Thu, 18 Sep 2025
 07:06:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWLK+Z2RExyDnSRgIjgh0mtDabljsjEpOReSv73tB3+cnAefqJi1HHmdsubAEMn/RgQcj+sOFTZYBw=@googlegroups.com
X-Received: by 2002:a05:651c:220f:b0:338:11e1:c7d3 with SMTP id 38308e7fff4ca-35f65b86674mr17085331fa.30.1758204362988;
        Thu, 18 Sep 2025 07:06:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204362; cv=none;
        d=google.com; s=arc-20240605;
        b=T8krTp/iktOwkYE0z3UKVzAkYZrmI6dTAtaZVGAm+e0OIaCqqD89wfJCgD9hgduj9X
         UtYca4Wjf7ePuupck0Ow73OHM1NtffWEqofn6rfRdROQ3S/qUY1TaHH9psS+ggEO8ilt
         SbkmKao8JIZpzqaGIxZ9JCcy/VNXT+z5Vp54orggmLfrOnafkI/eTnA7rGc/Z4mIaa3g
         ITnopmObYVOEld5YMheVjOZFHxlKlR2nDj40avyPRjoRAaBH2G+c9EFsVRDN/0LWUQKJ
         RhHX/a8QWXi3Q0/PwWwq107mXuC7jraNPB2iLFEaGT0EyJ0Z7rYIsQP9flMLYQCMu55P
         Wa0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DCWUNblN4U9kpWEcSaN4JvbXJbXAoJAUqhw7MiIdu4A=;
        fh=RpHVkfYUqCEOuZpNPIwV0JzU+Jv1sab2t3YAjJIzgLw=;
        b=ZtyAku8lqzhy545sI5ETI3XQ039DIRVtGUUmsiYevAaEX8DsaE+fAV+hvtIg238ifz
         UA+cx1j/fk024xzsKIhk2MuoTJaAP+AKkNYQ0OfdDicHUeJG8c1tcsQ0XernMnaNgfmX
         uPoPF6opam87uOCFt5+utStKQ3XIwU2Hq4xLLfd34KG4b9EwMTVT6aE3qqdXO+xYkJqr
         nR6KTgjB7GFkiwXr/bM6eqMHd4r1bfcXJXcQx9fK9U25+DhA3OokbY9SgbZ2sC5rseMA
         4rG7HUmbpoql7BwKDxDlL4Dr4yNXD6etYAgPMRu1zrq0SbkDPXZRfqI40lgY7ljUYMXP
         a/Tg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gLf1iXL6;
       spf=pass (google.com: domain of 3yhhmaaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yhHMaAUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-361a62c8ff4si424031fa.3.2025.09.18.07.06.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yhhmaaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3eb8215978aso1025099f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWOrkhr37OSQ1Y4OjcVI9ilVQXmlHbrv9ERi86tyljJJ8GFNehSP07UIWTSm2VsKG9JXMbMcHxBAhM=@googlegroups.com
X-Received: from wrbbs1.prod.google.com ([2002:a05:6000:701:b0:3ec:d97e:c0bb])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:adf:fac7:0:b0:3ec:e285:546b
 with SMTP id ffacd0b85a97d-3ece285566fmr3233104f8f.50.1758204362163; Thu, 18
 Sep 2025 07:06:02 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:24 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-14-elver@google.com>
Subject: [PATCH v3 13/35] bit_spinlock: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=gLf1iXL6;       spf=pass
 (google.com: domain of 3yhhmaaukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yhHMaAUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
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

The annotations for bit_spinlock.h have simply been using "bitlock" as
the token. For Sparse, that was likely sufficient in most cases. But
Clang's capability analysis is more precise, and we need to ensure we
can distinguish different bitlocks.

To do so, add a token capability, and a macro __bitlock(bitnum, addr)
that is used to construct unique per-bitlock tokens.

Add the appropriate test.

<linux/list_bl.h> is implicitly included through other includes, and
requires 2 annotations to indicate that acquisition (without release)
and release (without prior acquisition) of its bitlock is intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../dev-tools/capability-analysis.rst         |  3 ++-
 include/linux/bit_spinlock.h                  | 22 +++++++++++++---
 include/linux/list_bl.h                       |  2 ++
 lib/test_capability-analysis.c                | 26 +++++++++++++++++++
 4 files changed, 48 insertions(+), 5 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 4789de7b019a..56c6ba7205aa 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -81,7 +81,8 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
+`bit_spinlock`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/bit_spinlock.h b/include/linux/bit_spinlock.h
index 59e345f74b0e..ba3a67f39f0c 100644
--- a/include/linux/bit_spinlock.h
+++ b/include/linux/bit_spinlock.h
@@ -9,6 +9,16 @@
 
 #include <asm/processor.h>  /* for cpu_relax() */
 
+/*
+ * For static capability analysis, we need a unique token for each possible bit
+ * that can be used as a bit_spinlock. The easiest way to do that is to create a
+ * fake capability that we can cast to with the __bitlock(bitnum, addr) macro
+ * below, which will give us unique instances for each (bit, addr) pair that the
+ * static analysis can use.
+ */
+struct_with_capability(__capability_bitlock) { };
+#define __bitlock(bitnum, addr) (struct __capability_bitlock *)(bitnum + (addr))
+
 /*
  *  bit-based spin_lock()
  *
@@ -16,6 +26,7 @@
  * are significantly faster.
  */
 static __always_inline void bit_spin_lock(int bitnum, unsigned long *addr)
+	__acquires(__bitlock(bitnum, addr))
 {
 	/*
 	 * Assuming the lock is uncontended, this never enters
@@ -34,13 +45,14 @@ static __always_inline void bit_spin_lock(int bitnum, unsigned long *addr)
 		preempt_disable();
 	}
 #endif
-	__acquire(bitlock);
+	__acquire(__bitlock(bitnum, addr));
 }
 
 /*
  * Return true if it was acquired
  */
 static __always_inline int bit_spin_trylock(int bitnum, unsigned long *addr)
+	__cond_acquires(true, __bitlock(bitnum, addr))
 {
 	preempt_disable();
 #if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
@@ -49,7 +61,7 @@ static __always_inline int bit_spin_trylock(int bitnum, unsigned long *addr)
 		return 0;
 	}
 #endif
-	__acquire(bitlock);
+	__acquire(__bitlock(bitnum, addr));
 	return 1;
 }
 
@@ -57,6 +69,7 @@ static __always_inline int bit_spin_trylock(int bitnum, unsigned long *addr)
  *  bit-based spin_unlock()
  */
 static __always_inline void bit_spin_unlock(int bitnum, unsigned long *addr)
+	__releases(__bitlock(bitnum, addr))
 {
 #ifdef CONFIG_DEBUG_SPINLOCK
 	BUG_ON(!test_bit(bitnum, addr));
@@ -65,7 +78,7 @@ static __always_inline void bit_spin_unlock(int bitnum, unsigned long *addr)
 	clear_bit_unlock(bitnum, addr);
 #endif
 	preempt_enable();
-	__release(bitlock);
+	__release(__bitlock(bitnum, addr));
 }
 
 /*
@@ -74,6 +87,7 @@ static __always_inline void bit_spin_unlock(int bitnum, unsigned long *addr)
  *  protecting the rest of the flags in the word.
  */
 static __always_inline void __bit_spin_unlock(int bitnum, unsigned long *addr)
+	__releases(__bitlock(bitnum, addr))
 {
 #ifdef CONFIG_DEBUG_SPINLOCK
 	BUG_ON(!test_bit(bitnum, addr));
@@ -82,7 +96,7 @@ static __always_inline void __bit_spin_unlock(int bitnum, unsigned long *addr)
 	__clear_bit_unlock(bitnum, addr);
 #endif
 	preempt_enable();
-	__release(bitlock);
+	__release(__bitlock(bitnum, addr));
 }
 
 /*
diff --git a/include/linux/list_bl.h b/include/linux/list_bl.h
index ae1b541446c9..df9eebe6afca 100644
--- a/include/linux/list_bl.h
+++ b/include/linux/list_bl.h
@@ -144,11 +144,13 @@ static inline void hlist_bl_del_init(struct hlist_bl_node *n)
 }
 
 static inline void hlist_bl_lock(struct hlist_bl_head *b)
+	__acquires(__bitlock(0, b))
 {
 	bit_spin_lock(0, (unsigned long *)b);
 }
 
 static inline void hlist_bl_unlock(struct hlist_bl_head *b)
+	__releases(__bitlock(0, b))
 {
 	__bit_spin_unlock(0, (unsigned long *)b);
 }
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 74d287740bb8..ad362d5a7916 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -4,6 +4,7 @@
  * positive errors when compiled with Clang's capability analysis.
  */
 
+#include <linux/bit_spinlock.h>
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
 #include <linux/seqlock.h>
@@ -251,3 +252,28 @@ static void __used test_seqlock_writer(struct test_seqlock_data *d)
 	d->counter++;
 	write_sequnlock_irqrestore(&d->sl, flags);
 }
+
+struct test_bit_spinlock_data {
+	unsigned long bits;
+	int counter __guarded_by(__bitlock(3, &bits));
+};
+
+static void __used test_bit_spin_lock(struct test_bit_spinlock_data *d)
+{
+	/*
+	 * Note, the analysis seems to have false negatives, because it won't
+	 * precisely recognize the bit of the fake __bitlock() token.
+	 */
+	bit_spin_lock(3, &d->bits);
+	d->counter++;
+	bit_spin_unlock(3, &d->bits);
+
+	bit_spin_lock(3, &d->bits);
+	d->counter++;
+	__bit_spin_unlock(3, &d->bits);
+
+	if (bit_spin_trylock(3, &d->bits)) {
+		d->counter++;
+		bit_spin_unlock(3, &d->bits);
+	}
+}
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-14-elver%40google.com.
