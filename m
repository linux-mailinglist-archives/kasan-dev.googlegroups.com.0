Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZVDWDDAMGQE5HJZ2HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 77F00B84FD8
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:31 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3eb67c4aae5sf473522f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204391; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZB/AF/u4D+87N+XjbJ8lc98trVK3r4QhSuVrJ5Vkm4ejeHULuDsdQ3erGGCeiQwvMH
         l8EoNkA7B9to6ZFhyf9evYEiIJ9Us0fCvlXQhAX3vPviG6WapACByhEC/EVXQsgqefre
         JHw9dp95EOToeivdw7fMkcA6Wp/sHgBgXwYNqX9C+FHl+wDI/Q2nlVVD3+d2nX6jgpF3
         84HvLoSuNurrgQ/wn++zmoiFGPBLibFlJ8j4Jl+GATyL9vSXaw4fT+wA2vlJh77Fo+/A
         v66dUVYH5D0rMNBH99gPiEVJ1O/NQhsn2s1XByY6ImEkVKtjE6GOHbd/cOG/21y8I7tN
         KNZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=25iwYjTkSGuL15dba2YU7KV+dEz09dN9xcIdqItQYU8=;
        fh=+UG3ijYcnfB2FWkqZJDQTbTZL6dgilGanrVm4a92Vbo=;
        b=isw6cxvuLxR/zveF5mKMhDIbmpEdtDBYgCU00FpM1aE1oUu40Ko8GU+NpOA7SnY0vI
         ff2pWstOk6aWeugvPcOcgrPjk9d2Go2snxYoN5exa1kgPP13u0BnZpySYKY47crwN8NA
         Qq0jG+bGjfcbrQ2HSdRvFiG5NvayWp5R2hpaszYy53W/r8nip7aQAIputLS3ZgUWS97D
         TeXPGRcNflCuAWZWc2zlFmx1YXStJYKQSTRkGEm1MPveDhIJC4S44upSKLKYmfUVoNX7
         /WyaZVHW5yXZwsivtpcmAh8nDITONjH1NJqMAkmTG0ZE3w/rf+QZy9Zizb8nT3C96IlP
         lQIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NmIAEQm5;
       spf=pass (google.com: domain of 34hhmaaukcymls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=34hHMaAUKCYMls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204391; x=1758809191; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=25iwYjTkSGuL15dba2YU7KV+dEz09dN9xcIdqItQYU8=;
        b=CC8wfWlDfAOD0Q/DXA/7cV+sh+pnKynFuQPiHE9bghzW7ISCjs8KQS/wor3nzgZKSC
         e6kjKUR3dj+1IZO98/E3QhsAi4JzA95TLDd9qtmEPnOCr7txvEFjnJWPF+cRPWACUzLr
         OlrxhxxSym/mTpvvfQVsvPAgW7rcCjWyVQqDTi+Gn2X++S9ean7N0KDsCpTGcYAkI5G/
         cMUMS4V7f/5EvM2hjNMKlJEw54VVJhuhvtmM8rLvo8CqPyBkAy/whNchtbZaazgzACL2
         +9Fg4bEnlCsCY8M3o6mj+i4u2KXqFx1AX/ZYHEnNTKA+BCHFU8E9SP5VD7bjpgNKRxqK
         YSnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204391; x=1758809191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=25iwYjTkSGuL15dba2YU7KV+dEz09dN9xcIdqItQYU8=;
        b=jYU1dXLfSncTLwhvfai5Z+CRua+6+a2+Csnvp3V12/13XGo7TaGdpfqfOrT8+Yd0Nk
         7quXYJgtMMvvPmSOrppvooUrT+TQltXhT8NqcWp4HmpP0jG5ny5ipB/Wc3Xmpob0PrM/
         ljNkNQ2wpWP6tngEnBAG2vAmzkQC1vjGdcAnr0GzmoXfJNtxEAedF2zarTH8PRZ0FDFm
         DPkF46dqtA89Hkyu7RlQAQToXhO9uaUap90G04SsSTbsnO8ZLe0PK0HtQ7j6H0RbTPxm
         Fv18CZnYmhx72m6JIoMJlNOW9BUU2JyGcsD/azTbT3/sFL2si/KUDAdlgaE4KZ4gNwu3
         cVfA==
X-Forwarded-Encrypted: i=2; AJvYcCWexeelkUxft7j/s0GDiW8qY16dz116VJz9nh07REixwDP04goAHiADJ5jTN3mNSnUFFGJqdA==@lfdr.de
X-Gm-Message-State: AOJu0YzVpnqCFUEeu5Xrf4c1PtlKuj6cnkOktJ2XlCGpIJluwfbnjOZX
	AaNufCxiXR8drnShQ5p44C0ciwsU3JFprmshXpsl2kW9p+koEqgSjGjh
X-Google-Smtp-Source: AGHT+IEWrjTftvwMHNrS4PwKTUA3c8egW7qQhCZ/rMfl2dG1oci89O6yb41KblnOZtsfsQz8DbdlJw==
X-Received: by 2002:a05:6000:4383:b0:3ec:c50c:7164 with SMTP id ffacd0b85a97d-3ecdf9ffa15mr5750916f8f.15.1758204390720;
        Thu, 18 Sep 2025 07:06:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7Z80WQj4wtX19Va5Gni5nvxHzqABrtVuF6IPwAAojVVA==
Received: by 2002:a05:6000:40ca:b0:3ed:8e48:5e0d with SMTP id
 ffacd0b85a97d-3ee106bfb24ls558998f8f.1.-pod-prod-04-eu; Thu, 18 Sep 2025
 07:06:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0aY8fg6Sw+ABQIODLhlSXcZFHxfLPh6gHTSy8CXv04pJKlTXUkEB50WaDY2BJmwtsUZ/abf5zxqo=@googlegroups.com
X-Received: by 2002:a05:6000:1861:b0:3ee:13ba:e13b with SMTP id ffacd0b85a97d-3ee13bae501mr1511509f8f.33.1758204387245;
        Thu, 18 Sep 2025 07:06:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204387; cv=none;
        d=google.com; s=arc-20240605;
        b=dIw+IOn0q+Ec47uV7gxupvo8kHaooR+v0OS9Wk5Qguy079JEWz77I6FkY6ghn132R4
         MqPahPtWN/kC2RdtBNyunjnKnhZhxnzHeLjmSho1zt4k/PbAIAYT6YAVZZO3yhBGCPdo
         7Jn0ie+4YvWdag/m7DmmMt7vwJZC2fyQJzWB5IyYiupuf1Sts9urANtso8fc4R4e1vR4
         9ToHFdlTrvtYevl31w+iNkVdkf1cMoemDF1asp12efeKpnnIj7tq4ZNnxH8gqe/y9Eqp
         dID+vp3S/GTF0aLcMqvDEHCaU9C2KUr6G7Q0cNSJTCbTnADDmQ1ipyNTTv7IKzqUK0ow
         b3Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=3E29rPCnN3EjGw7BZaVdq2KLgeK/DgzeRknIagImVk4=;
        fh=sKFvpb2nCzn+EniAyiIFCZgu/CZNfZw+3zWIlaKtUb0=;
        b=RXmAvypmB/T/YlAKqropDTmJ0XX3chmtzPGfKPEqsAz4CQLhOIfOjaAhBppQKZNZ6T
         mkETmnI9zN1/U1dFZIovJ7CCARnz+oNWbJdfiBompDoa66mO0QIiss3xMXoSFCtA533u
         TeUm5N1MkCBmO48MjK6SIRJBSJ50hTYX4BtFmetcQK84ahNNoCwerL+8kRwGZkFbcsh5
         sAeJ+ZfJtp3EN9zWUwJsOt8HTfOB6F2MGTL1w91iAyg6a21nAQcCF90lFnj6/IwiyZgs
         PuqrhhSZTG7h9pcKwJABING+f5jsqPDKSZ78cIg2sOs4BxK+sHrDAaiohQOeoI1NXc6j
         7WZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NmIAEQm5;
       spf=pass (google.com: domain of 34hhmaaukcymls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=34hHMaAUKCYMls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ee0fbb7c0esi41811f8f.6.2025.09.18.07.06.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34hhmaaukcymls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-3ee13e43dd9so307452f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUttxCKIRThQ5E2UwwY281V3iv1rKPMncXHtpdiwpHJ4xdTaOZBLXDPk1zy+lb+0eZvCVKeEQMqz8A=@googlegroups.com
X-Received: from wmben15.prod.google.com ([2002:a05:600c:828f:b0:45c:b62f:ca0d])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:1887:b0:3e7:615a:17f6
 with SMTP id ffacd0b85a97d-3ecdf9ec859mr5220873f8f.28.1758204386463; Thu, 18
 Sep 2025 07:06:26 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:33 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-23-elver@google.com>
Subject: [PATCH v3 22/35] compiler-capability-analysis: Remove Sparse support
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
 header.i=@google.com header.s=20230601 header.b=NmIAEQm5;       spf=pass
 (google.com: domain of 34hhmaaukcymls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=34hHMaAUKCYMls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
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

Remove Sparse support as discussed at [1].

The kernel codebase is still scattered with numerous places that try to
appease Sparse's context tracking ("annotation for sparse", "fake out
sparse", "work around sparse", etc.). Eventually, as more subsystems
enable Clang's capability analysis, these places will show up and need
adjustment or removal of the workarounds altogether.

Link: https://lore.kernel.org/all/20250207083335.GW7145@noisy.programming.kicks-ass.net/ [1]
Link: https://lore.kernel.org/all/Z6XTKTo_LMj9KmbY@elver.google.com/ [2]
Cc: "Luc Van Oostenryck" <luc.vanoostenryck@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 Documentation/dev-tools/sparse.rst           | 19 -----
 include/linux/compiler-capability-analysis.h | 80 ++++++--------------
 include/linux/rcupdate.h                     | 15 +---
 3 files changed, 25 insertions(+), 89 deletions(-)

diff --git a/Documentation/dev-tools/sparse.rst b/Documentation/dev-tools/sparse.rst
index dc791c8d84d1..37b20170835d 100644
--- a/Documentation/dev-tools/sparse.rst
+++ b/Documentation/dev-tools/sparse.rst
@@ -53,25 +53,6 @@ sure that bitwise types don't get mixed up (little-endian vs big-endian
 vs cpu-endian vs whatever), and there the constant "0" really _is_
 special.
 
-Using sparse for lock checking
-------------------------------
-
-The following macros are undefined for gcc and defined during a sparse
-run to use the "context" tracking feature of sparse, applied to
-locking.  These annotations tell sparse when a lock is held, with
-regard to the annotated function's entry and exit.
-
-__must_hold - The specified lock is held on function entry and exit.
-
-__acquires - The specified lock is held on function exit, but not entry.
-
-__releases - The specified lock is held on function entry, but not exit.
-
-If the function enters and exits without the lock held, acquiring and
-releasing the lock inside the function in a balanced way, no
-annotation is needed.  The three annotations above are for cases where
-sparse would otherwise report a context imbalance.
-
 Getting sparse
 --------------
 
diff --git a/include/linux/compiler-capability-analysis.h b/include/linux/compiler-capability-analysis.h
index ccd312dbbf06..6046fca44f17 100644
--- a/include/linux/compiler-capability-analysis.h
+++ b/include/linux/compiler-capability-analysis.h
@@ -248,57 +248,32 @@ static inline void _capability_unsafe_alias(void **p) { }
 	extern const struct __capability_##cap *name
 
 /*
- * Common keywords for static capability analysis. Both Clang's capability
- * analysis and Sparse's context tracking are currently supported.
- */
-#ifdef __CHECKER__
-
-/* Sparse context/lock checking support. */
-# define __must_hold(x)		__attribute__((context(x,1,1)))
-# define __must_not_hold(x)
-# define __acquires(x)		__attribute__((context(x,0,1)))
-# define __cond_acquires(ret, x) __attribute__((context(x,0,-1)))
-# define __releases(x)		__attribute__((context(x,1,0)))
-# define __acquire(x)		__context__(x,1)
-# define __release(x)		__context__(x,-1)
-# define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
-/* For Sparse, there's no distinction between exclusive and shared locks. */
-# define __must_hold_shared	__must_hold
-# define __acquires_shared	__acquires
-# define __cond_acquires_shared __cond_acquires
-# define __releases_shared	__releases
-# define __acquire_shared	__acquire
-# define __release_shared	__release
-# define __cond_lock_shared	__cond_acquire
-
-#else /* !__CHECKER__ */
+ * Common keywords for static capability analysis.
+ */
 
 /**
  * __must_hold() - function attribute, caller must hold exclusive capability
- * @x: capability instance pointer
  *
  * Function attribute declaring that the caller must hold the given capability
- * instance @x exclusively.
+ * instance(s) exclusively.
  */
-# define __must_hold(x)		__requires_cap(x)
+#define __must_hold(...)	__requires_cap(__VA_ARGS__)
 
 /**
  * __must_not_hold() - function attribute, caller must not hold capability
- * @x: capability instance pointer
  *
  * Function attribute declaring that the caller must not hold the given
- * capability instance @x.
+ * capability instance(s).
  */
-# define __must_not_hold(x)	__excludes_cap(x)
+#define __must_not_hold(...)	__excludes_cap(__VA_ARGS__)
 
 /**
  * __acquires() - function attribute, function acquires capability exclusively
- * @x: capability instance pointer
  *
  * Function attribute declaring that the function acquires the given
- * capability instance @x exclusively, but does not release it.
+ * capability instance(s) exclusively, but does not release them.
  */
-# define __acquires(x)		__acquires_cap(x)
+#define __acquires(...)		__acquires_cap(__VA_ARGS__)
 
 /*
  * Clang's analysis does not care precisely about the value, only that it is
@@ -325,16 +300,15 @@ static inline void _capability_unsafe_alias(void **p) { }
  *
  * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
+#define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
 
 /**
  * __releases() - function attribute, function releases a capability exclusively
- * @x: capability instance pointer
  *
  * Function attribute declaring that the function releases the given capability
- * instance @x exclusively. The capability must be held on entry.
+ * instance(s) exclusively. The capability must be held on entry.
  */
-# define __releases(x)		__releases_cap(x)
+#define __releases(...)		__releases_cap(__VA_ARGS__)
 
 /**
  * __acquire() - function to acquire capability exclusively
@@ -342,7 +316,7 @@ static inline void _capability_unsafe_alias(void **p) { }
  *
  * No-op function that acquires the given capability instance @x exclusively.
  */
-# define __acquire(x)		__acquire_cap(x)
+#define __acquire(x)		__acquire_cap(x)
 
 /**
  * __release() - function to release capability exclusively
@@ -350,7 +324,7 @@ static inline void _capability_unsafe_alias(void **p) { }
  *
  * No-op function that releases the given capability instance @x.
  */
-# define __release(x)		__release_cap(x)
+#define __release(x)		__release_cap(x)
 
 /**
  * __cond_lock() - function that conditionally acquires a capability
@@ -369,31 +343,28 @@ static inline void _capability_unsafe_alias(void **p) { }
  *
  *	#define spin_trylock(l) __cond_lock(&lock, _spin_trylock(&lock))
  */
-# define __cond_lock(x, c)	__try_acquire_cap(x, c)
+#define __cond_lock(x, c)	__try_acquire_cap(x, c)
 
 /**
  * __must_hold_shared() - function attribute, caller must hold shared capability
- * @x: capability instance pointer
  *
  * Function attribute declaring that the caller must hold the given capability
- * instance @x with shared access.
+ * instance(s) with shared access.
  */
-# define __must_hold_shared(x)	__requires_shared_cap(x)
+#define __must_hold_shared(...)	__requires_shared_cap(__VA_ARGS__)
 
 /**
  * __acquires_shared() - function attribute, function acquires capability shared
- * @x: capability instance pointer
  *
  * Function attribute declaring that the function acquires the given
- * capability instance @x with shared access, but does not release it.
+ * capability instance(s) with shared access, but does not release them.
  */
-# define __acquires_shared(x)	__acquires_shared_cap(x)
+#define __acquires_shared(...)	__acquires_shared_cap(__VA_ARGS__)
 
 /**
  * __cond_acquires_shared() - function attribute, function conditionally
  *                            acquires a capability shared
  * @ret: abstract value returned by function if capability acquired
- * @x: capability instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
  * given capability instance @x with shared access, but does not release it. The
@@ -401,17 +372,16 @@ static inline void _capability_unsafe_alias(void **p) { }
  *
  * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
-# define __cond_acquires_shared(ret, x) __cond_acquires_impl_##ret(x, _shared)
+#define __cond_acquires_shared(ret, x) __cond_acquires_impl_##ret(x, _shared)
 
 /**
  * __releases_shared() - function attribute, function releases a
  *                       capability shared
- * @x: capability instance pointer
  *
  * Function attribute declaring that the function releases the given capability
- * instance @x with shared access. The capability must be held on entry.
+ * instance(s) with shared access. The capability must be held on entry.
  */
-# define __releases_shared(x)	__releases_shared_cap(x)
+#define __releases_shared(...)	__releases_shared_cap(__VA_ARGS__)
 
 /**
  * __acquire_shared() - function to acquire capability shared
@@ -420,7 +390,7 @@ static inline void _capability_unsafe_alias(void **p) { }
  * No-op function that acquires the given capability instance @x with shared
  * access.
  */
-# define __acquire_shared(x)	__acquire_shared_cap(x)
+#define __acquire_shared(x)	__acquire_shared_cap(x)
 
 /**
  * __release_shared() - function to release capability shared
@@ -429,7 +399,7 @@ static inline void _capability_unsafe_alias(void **p) { }
  * No-op function that releases the given capability instance @x with shared
  * access.
  */
-# define __release_shared(x)	__release_shared_cap(x)
+#define __release_shared(x)	__release_shared_cap(x)
 
 /**
  * __cond_lock_shared() - function that conditionally acquires a capability
@@ -443,9 +413,7 @@ static inline void _capability_unsafe_alias(void **p) { }
  * access, if the boolean expression @c is true. The result of @c is the return
  * value, to be able to create a capability-enabled interface.
  */
-# define __cond_lock_shared(x, c) __try_acquire_shared_cap(x, c)
-
-#endif /* __CHECKER__ */
+#define __cond_lock_shared(x, c) __try_acquire_shared_cap(x, c)
 
 /**
  * __acquire_ret() - helper to acquire capability of return value
diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
index 8eeece72492c..aec28e98d3f2 100644
--- a/include/linux/rcupdate.h
+++ b/include/linux/rcupdate.h
@@ -1177,20 +1177,7 @@ rcu_head_after_call_rcu(struct rcu_head *rhp, rcu_callback_t f)
 extern int rcu_expedited;
 extern int rcu_normal;
 
-DEFINE_LOCK_GUARD_0(rcu,
-	do {
-		rcu_read_lock();
-		/*
-		 * sparse doesn't call the cleanup function,
-		 * so just release immediately and don't track
-		 * the context. We don't need to anyway, since
-		 * the whole point of the guard is to not need
-		 * the explicit unlock.
-		 */
-		__release(RCU);
-	} while (0),
-	rcu_read_unlock())
-
+DEFINE_LOCK_GUARD_0(rcu, rcu_read_lock(), rcu_read_unlock())
 DECLARE_LOCK_GUARD_0_ATTRS(rcu, __acquires_shared(RCU), __releases_shared(RCU))
 
 #endif /* __LINUX_RCUPDATE_H */
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-23-elver%40google.com.
