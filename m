Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTG77TEAMGQEK76JCQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EF32C74C21
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:12:14 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-596a25b32edsf37857e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:12:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651534; cv=pass;
        d=google.com; s=arc-20240605;
        b=IB4KSa8Lu0GKrysBoYBDXmjKF0oi0CRYPcO/R48avz/Oq72P49+Xg2+j9rk9MOBjJl
         ZsAKhVKlIE/fe7QvuGRrFvSdnf7Lz/DaJHs0dLchz26jncmWxnL9LBxOTY4Caoh8+GQn
         TExNkKRgsd0p1uUCnbFgcHsbpa0gupjpDR/6zEram+n95TPZrmRWoMDjdpNOMndwWCoG
         3l8G2V3ALW9ca1W4JBmk1/3HDD3eIjme39gl1DxYBghopbEOUh2C+g34cyd4p7XCbwRd
         y30zFm9EGew1ovnfs2FZFsvTwgzlyPAhPNSShAosLg3kpcNSReB38ZDrsFoxyMEY0Ent
         pxfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=DJc8s8IlALsRAkwUXbOg/KdCPrHqaTRYjBTJg2N1STM=;
        fh=DGtfM8zWms3fwAZK5DBaM55pfaQclIWqpn7DJT1+SnM=;
        b=TTJaYG56yCz10PkXF9licBipI1PK2Qa2KymRsWOsa1kbdO4VyuTpCabCqoUPzY3O0R
         dRQOWkIniGcsKiQyVJ8Ry/gCHd82gzAnFSxUw08x4o3Fq9PMM4MrCmRcqJv6hUc7+IgZ
         qzDy1Li95AH/6lRrWlrfnkE1yo/gf2zGnl2/u6fBqJZk+3bgfSfaMzjzwYvs/+s7DsZo
         5malC7zHgCUfC8gwps37MmDHcPWvR9pY3lw0yvbVIV/BqKWBNEQq4gGbU0vUNzPpz7M0
         T+fa3HJDHwnZSfN3FR0xRx474ylNJQt3/l9rXcQ7P1PbRq8GCAwH/6RKYyydh877Jc6B
         CiQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2SaCmyPu;
       spf=pass (google.com: domain of 3ys8faqukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3yS8faQUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651534; x=1764256334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DJc8s8IlALsRAkwUXbOg/KdCPrHqaTRYjBTJg2N1STM=;
        b=d3MvoTsOH6zxjGmn5hsxrdpQfLnm19+Fx76rnlI3UOx0RJGOwhmngYvmyml5FSrdX6
         pBI+Sz+hAO1nmcN+l4unuo9MgVHj7R4pPKb1m/V39A/u5g+y2tUKDvSGiTFRvndJ1mN6
         r/JaMe7z6raxeHrPWvKkMHRCHKnrSohkWHdQbY2bgLHsUVvlJJ1p1b/P2DmdnCq2GnHe
         jbkaKfC2SmJ43EXdlcIJV4rVPBesl1LxQv4KyObo7n51qp1o8p+2GCApnMUU0D6DtmRF
         POa5t5uTFtOQ8rpfw+a19ne9GqXjtoB/BJ9TjtS2XPEd/Uy6UecMckoF7WQ90atLrm/H
         etjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651534; x=1764256334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DJc8s8IlALsRAkwUXbOg/KdCPrHqaTRYjBTJg2N1STM=;
        b=E3g4+KsbV3On2NYm9rzrADexppLUaI/RilrcCu+T+AqkrWoJciT7vdFAWx78yHb8J6
         sGaGq5ocdvjEd2nUe4nlQriyvMqiB+bmkuonozSpilNgBiHhKEfQE1G6rCMZCd4jCVPI
         VIxZ1fuoNXhYcrPhAA7D14fM40grZppZesZcC42DetLN3Y0Tfdi2q8D5b+PUMamHzLCt
         kzTqoHxZOudbuFTDGPV0X9twLslb2ERxKIMytEvKOP7P4PJxRnjGQ7bJ61XasjBSRfOP
         +qFq3kAoinog8doQL0dz6L/8NRPQjZV0JT8vqBxARJFt1xAwI5EZTjhVGLctvk7mnvSy
         8CwA==
X-Forwarded-Encrypted: i=2; AJvYcCXnQYhxTAPEtV5+zZ+c6PRG5z1XP0oVdrSXWX4SO+9g1mtQwCdJztL1h7Utm45pY4UlEbXH8A==@lfdr.de
X-Gm-Message-State: AOJu0YzdbaDtrQEvNQlVRuvSj1yzAmKA2Y7HTwnhIrbhup7Z3inP9Tc3
	/tPg2Ct9xm3jiF7ctjc38VLijT/ZRIoPj1Z2BTgsVixCPSVcIDj10nO8
X-Google-Smtp-Source: AGHT+IEAu6OX/A3Ham3OQJdE5gG1Dgwp1SAO1ta0a+2ECJH+3GicFhyBb/PXi6B0Xu7sgQktS7lmqg==
X-Received: by 2002:a05:6512:acf:b0:595:9d54:93e2 with SMTP id 2adb3069b0e04-5969ea3af86mr1060174e87.24.1763651533531;
        Thu, 20 Nov 2025 07:12:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z/kTrGCwOBiz6Wg5zRiTOseZR4+8HL90Oy9EtrWzoFwQ=="
Received: by 2002:a2e:a1cb:0:b0:37a:3ee8:f671 with SMTP id 38308e7fff4ca-37bcfe4a010ls1390421fa.0.-pod-prod-00-eu-canary;
 Thu, 20 Nov 2025 07:12:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVawfyccheEaq6hMkTd04VWnam1kzixtUhHS2DeACkrG3h6YVr1S0ne2iurqWjbwMGVwJjgsinOn2U=@googlegroups.com
X-Received: by 2002:a05:651c:f14:b0:37b:926d:5c16 with SMTP id 38308e7fff4ca-37cc82b4c72mr9298791fa.5.1763651530246;
        Thu, 20 Nov 2025 07:12:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651530; cv=none;
        d=google.com; s=arc-20240605;
        b=gO6kbKzsEMLDITFawrbYH0o8uOiraR8W8F6S+juJHD0+l3Y6wB7b5/xT4UF8sWVy0C
         k01pDskLhjOmwwOkJ2QLVMqk0asbM4utp1FVJWZWqww/f+oH18vGrx4uZkNlEajq/aR4
         UfaydeBT2Ht2PCVmJslwZxfD89bVFufZrCRPe9lfrreq+5v2avvMJ21QUQrcz3GwlJTQ
         qeWXDQG/5f1kehzGsh2wdVzB/9CWBuQNlA78jRtKmmde/QtIcpOyu/Eyx1q9pJHE6OHu
         DbGrRZWd60zEeEPFXcscG/kN856c3/Y9EIY4gWePq2vdzvMcNtZJdYkRI74Df9BKVQwt
         iA+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=2auqzFTNru84Mc/h4FPy5CTt8CBssizo13Uye4GopmU=;
        fh=JIE1Q2HMfSBncoPDqNKd2h5LVxD43DmeilpoMTsVWNk=;
        b=dvs3Yq0Hhu9GlTX3R8NMaVdWvUZGChARNDqHOkN/nUFJe8x7qaGdU25bZWjTA6wobQ
         wsPjpRZNAhRmpZ0/hzfUhFkLd5rFtpGGCfbtYj7+Fs7nKMuNgGadb2An2ShT81uNSQ0s
         q8K62Z9j5Kdb6rFa4SH0W9mgTqvg/E0E7XwORXyrjHZYFt910gjrrK1vZFxYBhFNYwpY
         mj3gANY/g0lrSwj3B4o2zZEr1HvR9aKWeeBFo2Ap0DEuaDa0Ayws/J5saFi2rAvHB7BX
         4SiG4wIVvV75GP5vBA6qIxBjfNkqaQtcMkqwUNS2YtCsqAq1RoEfSocsdABScvVZrqNi
         fxbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2SaCmyPu;
       spf=pass (google.com: domain of 3ys8faqukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3yS8faQUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37cc6b2b7a1si366911fa.2.2025.11.20.07.12.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:12:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ys8faqukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-47754e6bddbso6983505e9.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:12:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXsXBreWusgl38bQA2NlwRd349Eams/2wwIWyWmU+oL3juWXXLKxDx1h3v4lO9tP7BFosKrrIFXl2o=@googlegroups.com
X-Received: from wmoy21.prod.google.com ([2002:a05:600c:17d5:b0:477:a7d1:fd12])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1f0f:b0:46e:53cb:9e7f
 with SMTP id 5b1f17b1804b1-477b8a8bd4fmr35618325e9.18.1763651529324; Thu, 20
 Nov 2025 07:12:09 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:34 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-10-elver@google.com>
Subject: [PATCH v4 09/35] compiler-context-analysis: Change __cond_acquires to
 take return value
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
 header.i=@google.com header.s=20230601 header.b=2SaCmyPu;       spf=pass
 (google.com: domain of 3ys8faqukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3yS8faQUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
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
functions, Clang's context analysis needs to know the return value
which indicates successful acquisition.

Add the additional argument, and convert existing uses.

Notably, Clang's interpretation of the value merely relates to the use
in a later conditional branch, i.e. 1 ==> context guard acquired in
branch taken if condition non-zero, and 0 ==> context guard acquired in
branch taken if condition is zero. Given the precise value does not
matter, introduce symbolic variants to use instead of either 0 or 1,
which should be more intuitive.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v2:
* Use symbolic values for __cond_acquires() and __cond_acquires_shared()
  (suggested by Bart).
---
 fs/dlm/lock.c                             |  2 +-
 include/linux/compiler-context-analysis.h | 31 +++++++++++++++++++----
 include/linux/refcount.h                  |  6 ++---
 include/linux/spinlock.h                  |  6 ++---
 include/linux/spinlock_api_smp.h          |  8 +++---
 net/ipv4/tcp_sigpool.c                    |  2 +-
 6 files changed, 38 insertions(+), 17 deletions(-)

diff --git a/fs/dlm/lock.c b/fs/dlm/lock.c
index be938fdf17d9..0ce04be0d3de 100644
--- a/fs/dlm/lock.c
+++ b/fs/dlm/lock.c
@@ -343,7 +343,7 @@ void dlm_hold_rsb(struct dlm_rsb *r)
 /* TODO move this to lib/refcount.c */
 static __must_check bool
 dlm_refcount_dec_and_write_lock_bh(refcount_t *r, rwlock_t *lock)
-__cond_acquires(lock)
+      __cond_acquires(true, lock)
 {
 	if (refcount_dec_not_one(r))
 		return false;
diff --git a/include/linux/compiler-context-analysis.h b/include/linux/compiler-context-analysis.h
index 8c75e1d0034a..935e59089d75 100644
--- a/include/linux/compiler-context-analysis.h
+++ b/include/linux/compiler-context-analysis.h
@@ -259,7 +259,7 @@ static inline void _context_unsafe_alias(void **p) { }
 # define __must_hold(x)		__attribute__((context(x,1,1)))
 # define __must_not_hold(x)
 # define __acquires(x)		__attribute__((context(x,0,1)))
-# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
+# define __cond_acquires(ret, x) __attribute__((context(x,0,-1)))
 # define __releases(x)		__attribute__((context(x,1,0)))
 # define __acquire(x)		__context__(x,1)
 # define __release(x)		__context__(x,-1)
@@ -302,15 +302,32 @@ static inline void _context_unsafe_alias(void **p) { }
  */
 # define __acquires(x)		__acquires_ctx_guard(x)
 
+/*
+ * Clang's analysis does not care precisely about the value, only that it is
+ * either zero or non-zero. So the __cond_acquires() interface might be
+ * misleading if we say that @ret is the value returned if acquired. Instead,
+ * provide symbolic variants which we translate.
+ */
+#define __cond_acquires_impl_true(x, ...)     __try_acquires##__VA_ARGS__##_ctx_guard(1, x)
+#define __cond_acquires_impl_false(x, ...)    __try_acquires##__VA_ARGS__##_ctx_guard(0, x)
+#define __cond_acquires_impl_nonzero(x, ...)  __try_acquires##__VA_ARGS__##_ctx_guard(1, x)
+#define __cond_acquires_impl_0(x, ...)        __try_acquires##__VA_ARGS__##_ctx_guard(0, x)
+#define __cond_acquires_impl_nonnull(x, ...)  __try_acquires##__VA_ARGS__##_ctx_guard(1, x)
+#define __cond_acquires_impl_NULL(x, ...)     __try_acquires##__VA_ARGS__##_ctx_guard(0, x)
+
 /**
  * __cond_acquires() - function attribute, function conditionally
  *                     acquires a context guard exclusively
+ * @ret: abstract value returned by function if context guard acquired
  * @x: context guard instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
- * given context guard instance @x exclusively, but does not release it.
+ * given context guard instance @x exclusively, but does not release it. The
+ * function return value @ret denotes when the context guard is acquired.
+ *
+ * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires(x)	__try_acquires_ctx_guard(1, x)
+# define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
 
 /**
  * __releases() - function attribute, function releases a context guard exclusively
@@ -377,12 +394,16 @@ static inline void _context_unsafe_alias(void **p) { }
 /**
  * __cond_acquires_shared() - function attribute, function conditionally
  *                            acquires a context guard shared
+ * @ret: abstract value returned by function if context guard acquired
  * @x: context guard instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
- * given context guard instance @x with shared access, but does not release it.
+ * given context guard instance @x with shared access, but does not release it. The
+ * function return value @ret denotes when the context guard is acquired.
+ *
+ * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires_shared(x) __try_acquires_shared_ctx_guard(1, x)
+# define __cond_acquires_shared(ret, x) __cond_acquires_impl_##ret(x, _shared)
 
 /**
  * __releases_shared() - function attribute, function releases a
diff --git a/include/linux/refcount.h b/include/linux/refcount.h
index 80dc023ac2bf..3da377ffb0c2 100644
--- a/include/linux/refcount.h
+++ b/include/linux/refcount.h
@@ -478,9 +478,9 @@ static inline void refcount_dec(refcount_t *r)
 
 extern __must_check bool refcount_dec_if_one(refcount_t *r);
 extern __must_check bool refcount_dec_not_one(refcount_t *r);
-extern __must_check bool refcount_dec_and_mutex_lock(refcount_t *r, struct mutex *lock) __cond_acquires(lock);
-extern __must_check bool refcount_dec_and_lock(refcount_t *r, spinlock_t *lock) __cond_acquires(lock);
+extern __must_check bool refcount_dec_and_mutex_lock(refcount_t *r, struct mutex *lock) __cond_acquires(true, lock);
+extern __must_check bool refcount_dec_and_lock(refcount_t *r, spinlock_t *lock) __cond_acquires(true, lock);
 extern __must_check bool refcount_dec_and_lock_irqsave(refcount_t *r,
 						       spinlock_t *lock,
-						       unsigned long *flags) __cond_acquires(lock);
+						       unsigned long *flags) __cond_acquires(true, lock);
 #endif /* _LINUX_REFCOUNT_H */
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index 2bcb3f0bf00e..274d866a0be3 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -362,7 +362,7 @@ static __always_inline void spin_lock_bh(spinlock_t *lock)
 }
 
 static __always_inline int spin_trylock(spinlock_t *lock)
-	__cond_acquires(lock) __no_context_analysis
+	__cond_acquires(true, lock) __no_context_analysis
 {
 	return raw_spin_trylock(&lock->rlock);
 }
@@ -422,13 +422,13 @@ static __always_inline void spin_unlock_irqrestore(spinlock_t *lock, unsigned lo
 }
 
 static __always_inline int spin_trylock_bh(spinlock_t *lock)
-	__cond_acquires(lock) __no_context_analysis
+	__cond_acquires(true, lock) __no_context_analysis
 {
 	return raw_spin_trylock_bh(&lock->rlock);
 }
 
 static __always_inline int spin_trylock_irq(spinlock_t *lock)
-	__cond_acquires(lock) __no_context_analysis
+	__cond_acquires(true, lock) __no_context_analysis
 {
 	return raw_spin_trylock_irq(&lock->rlock);
 }
diff --git a/include/linux/spinlock_api_smp.h b/include/linux/spinlock_api_smp.h
index d19327e04df9..7e7d7d373213 100644
--- a/include/linux/spinlock_api_smp.h
+++ b/include/linux/spinlock_api_smp.h
@@ -34,8 +34,8 @@ unsigned long __lockfunc _raw_spin_lock_irqsave(raw_spinlock_t *lock)
 unsigned long __lockfunc
 _raw_spin_lock_irqsave_nested(raw_spinlock_t *lock, int subclass)
 								__acquires(lock);
-int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock)		__cond_acquires(lock);
-int __lockfunc _raw_spin_trylock_bh(raw_spinlock_t *lock)	__cond_acquires(lock);
+int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock)		__cond_acquires(true, lock);
+int __lockfunc _raw_spin_trylock_bh(raw_spinlock_t *lock)	__cond_acquires(true, lock);
 void __lockfunc _raw_spin_unlock(raw_spinlock_t *lock)		__releases(lock);
 void __lockfunc _raw_spin_unlock_bh(raw_spinlock_t *lock)	__releases(lock);
 void __lockfunc _raw_spin_unlock_irq(raw_spinlock_t *lock)	__releases(lock);
@@ -84,7 +84,7 @@ _raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
 #endif
 
 static inline int __raw_spin_trylock(raw_spinlock_t *lock)
-	__cond_acquires(lock)
+	__cond_acquires(true, lock)
 {
 	preempt_disable();
 	if (do_raw_spin_trylock(lock)) {
@@ -177,7 +177,7 @@ static inline void __raw_spin_unlock_bh(raw_spinlock_t *lock)
 }
 
 static inline int __raw_spin_trylock_bh(raw_spinlock_t *lock)
-	__cond_acquires(lock)
+	__cond_acquires(true, lock)
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-10-elver%40google.com.
