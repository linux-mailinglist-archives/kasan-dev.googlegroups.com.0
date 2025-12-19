Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD7GSXFAMGQEVCEJW6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id C9037CD0923
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:45:20 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-b7fca7b5966sf16941566b.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:45:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159120; cv=pass;
        d=google.com; s=arc-20240605;
        b=I+bgqHVWcV/EyAbrxznMC5b3mmKj/8BeQlj+Ow1vVdwt99VtvZck8oM4GxaCVPvcqm
         E4fyi0CCfpzAvzVpu4JQBTn6wlu0xi/ZBO1L1Mgclnay4oNoM8uwdDlbAu3/RbVasxux
         2NDFWOH8fMhebBSMl/rBeMlWIg81FVmSvJnKCYfF4zHAuOklN2U8C9pDGwLnzpsuWoNR
         XskEj72Bq0fb/eiK6zgDWm97uwFUO7S4DeX9/IwGgkIHwmxhX93wBA7hZNyKm9fVEMuH
         A9Yhhn+eYyMDdmFsLO1ahjzUEh6hr839eaLrXCR8XX/jvgajS/gASRSors59GLGk9SaU
         jHkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=h5DJuYIJhXwZ6ejkOYP6R07HMybnZ/FPlR7So8v0iZo=;
        fh=+73HUwGRzeqcV0IsHfNokHTS6QZ/cN7B4VtNw6ETzYQ=;
        b=kbjqgmyU9EGckVE5eO7AxuGM02Z3nEYNuPcGsipO/3s9zjl9BZ0iEim1UVcD2GA/4t
         WrWNnTwlOfkqXBr6cpfswoaEvQb8qXdP1j95lNLmLirw1Pjjdk1H4YCJnOgsZjo3fZai
         /VdUw6/k+TCm+HZDNiWI+2hY2+9ZgcOi/ofqFtL9ec/Yl9sJHYWLPRdCdCm6hqxqHOEQ
         HWLHMNPrcOx0CltYrFZnRsguMAA3ux6qRKHsT0fedg4LD0PmyfCC/myBw/kA+zxnwxa5
         pADeJdbLTwLF0HArENQ8BHMJt79arWK9g7T/Buz3aM/Zl73RUJImivQr2vwPvAU06Wtg
         WXkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MFGVPJDx;
       spf=pass (google.com: domain of 3dhnfaqukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3DHNFaQUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159120; x=1766763920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=h5DJuYIJhXwZ6ejkOYP6R07HMybnZ/FPlR7So8v0iZo=;
        b=Y8sc1sgBJPvvkHPc+1miXDdf+JLQkEk9OgBFdcImyM7i8HJWDNWYFlNvOj3KgLOVWO
         4JI32NmhTfzGaNvrz0QozzcdpPFd+G8+hOkfaN6BsxBLiqvDNET8NWdGFgAuqgWyGFqc
         0F+OCIVIjNxniUTcv1DQRLvhDm7wHPT2Jojpp91bH9xbu1G7KvG+bXTqkJTvD0RQHUeP
         nyInswWVEr3yZ/88Lz1tU+yZnKSKTHnmx9y+7Sajy4EvGVvbYCgzfDw8y+Rdt+0/sJvc
         lGe+ccwvrOx6kwWF4mpjdXAvtAqYozq04ngYvSEU1Zpyzmc3mYcw4r2KTabmhaZc/pPa
         CcUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159120; x=1766763920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=h5DJuYIJhXwZ6ejkOYP6R07HMybnZ/FPlR7So8v0iZo=;
        b=OQf0wSId4SFFXAHpLolYIak6tIKInpXPbf5Q/O1j8ZixrgG0K0kiniMp6d/pcrWjoO
         VoNaZltV2kxyrI/WfQjafXmWtE9utAthUWYgwmBlFOdYNs4am2cVRRbfwFrC6I4+3S3I
         O3UOnX0Zid/0dK6/Shcs4OBxCWmDqlvUHqTqzXktN0ApfEefcs/WI+VIdUQ6Y4/CdU5D
         8H+tpFWyeid58mbn/1mz/BaGzyCZqXgd9eGToLcINhWZtt/H1QHi1fUkZF7AKuK9WUGW
         HF7qg1cKHyNEwbjOogLXk6JhMUVZrKsmyvVLon4/jqMVFj8Zr2rr8mcoU5SkEq2AkGyo
         +ugQ==
X-Forwarded-Encrypted: i=2; AJvYcCXkJaAXL3C9DlcS320mx/4F7pfMEp0UvtspLoY3+le2N9vKkSXo7We3VQqh0qyAkInmLpelzA==@lfdr.de
X-Gm-Message-State: AOJu0YwEluMXsWxAfgIPik0G0X/wj+nxEuOMLPdDQlR8SA5r1ofLH9+h
	vxf8Xd+Fo/m4CYCfyDG2fFmBfPezf2Fs6OxuW79ZHzlu3NU9txkyiKKx
X-Google-Smtp-Source: AGHT+IEZ6p7XIDZ3YN2yNb0O3peUXg5gPJmU2wNMRannyClZfTrP0Au9EfZ0zlsVXIXzbrmLLv4B1Q==
X-Received: by 2002:a05:6402:440a:b0:64b:4037:6f6a with SMTP id 4fb4d7f45d1cf-64b8ecafa98mr1865677a12.4.1766159120009;
        Fri, 19 Dec 2025 07:45:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbrxZHjLjQtjOpk7/Dq7BJN+DIMCNdTh4xmkvd0TMr8hg=="
Received: by 2002:a05:6402:5686:b0:64b:7641:af54 with SMTP id
 4fb4d7f45d1cf-64b7641aff6ls1774797a12.2.-pod-prod-02-eu; Fri, 19 Dec 2025
 07:45:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXid31TAOtmCRO7PktupWNC+RjDSQManwY7EizFvs8hO6SiijH7gEkVV8Zq+vp+HLxxdu2tcQwyAqU=@googlegroups.com
X-Received: by 2002:a05:6402:5170:b0:640:96fe:c7bb with SMTP id 4fb4d7f45d1cf-64b8eddfe35mr2204776a12.28.1766159117369;
        Fri, 19 Dec 2025 07:45:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159117; cv=none;
        d=google.com; s=arc-20240605;
        b=ROfjtb84N0WpGNzZNaj0us4kXbH33kVNBQlLTbBLQ++e6obGdnBThVyfOFHhyWiemx
         GDRJd3BW5mKRXtVgrxZS/FeGLWch2H4waw/bqzazhPCxxsFovCWIrRbJ+ErCuos6fMqU
         xZafT36BJPyx8iDLTy2bx56r7YEDGgnWQ4nOYquYIYJdy9mDAFExNS5ELBm+XlpkNaL9
         opHTClb+3G9VGGmpNGmeJECGhfuwDfLUe0B1W1pjcIeBovbrkGQSuoC6G9z4Mw4z1apJ
         MnnIKjBUBrw13eAoWNO6iBFCYhK/nW2sNJyv24cYXaMWq9c/kBZ0DXt2hLw90uGoFfs/
         wtrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uTTrpDgY6boLD/2fqquzR5fZiR/OECGrXMTsYaAZTdg=;
        fh=ZrtxfFziOIJyM9XD0MoHVRigvF7kWMTWlRo7fsRPLc4=;
        b=ZI7g+KqgvAHtHkkUJFK6ixpWVkd8+xTVJkwAePJbuPHNto54jzk3Xczj+V4Ts4Y6Pz
         BXQbh3bvL8zO6uxg45Ykw5mO84eXJQGausnHxVOqnXbfhfxbOL1nrBZzy64n9rh6bgUR
         qFb6W5BNLAtGVmRLLCcMflo0Knz2wdydDeY2R2Kjimz5KTT14HWtaK06BD94cXwXRgas
         g0TKQrn4ibNYimC9ej6ehM6LvKqaC6lCz7BXurATUrMtuQ5VDzpCEqE6MtLdnzHi/pz9
         J5013F909v9llUIhMJzfN/3O86MeM8jYwKSrv7BxZu/+VD6MUu/YkKnkHV35hrq3JkBb
         POaw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MFGVPJDx;
       spf=pass (google.com: domain of 3dhnfaqukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3DHNFaQUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64b9158a9f2si61640a12.7.2025.12.19.07.45.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:45:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dhnfaqukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-6409f6d6800so2067653a12.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:45:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVV3P42g3l5ZAPJla4Y70mG/s5JazXDKOhfY/casVUGUSF0/CXPHc+CPQy5iuFyq6NWZT3JKc6q6Ew=@googlegroups.com
X-Received: from edvd12.prod.google.com ([2002:aa7:ce0c:0:b0:64b:5a31:444e])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:3582:b0:64c:584c:556c
 with SMTP id 4fb4d7f45d1cf-64c584c586dmr960916a12.30.1766159116689; Fri, 19
 Dec 2025 07:45:16 -0800 (PST)
Date: Fri, 19 Dec 2025 16:39:50 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-2-elver@google.com>
Subject: [PATCH v5 01/36] compiler_types: Move lock checking attributes to compiler-context-analysis.h
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
 header.i=@google.com header.s=20230601 header.b=MFGVPJDx;       spf=pass
 (google.com: domain of 3dhnfaqukcvk5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3DHNFaQUKCVk5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
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

The conditional definition of lock checking macros and attributes is
about to become more complex. Factor them out into their own header for
better readability, and to make it obvious which features are supported
by which mode (currently only Sparse). This is the first step towards
generalizing towards "context analysis".

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Bart Van Assche <bvanassche@acm.org>
---
v4:
* Rename capability -> context analysis.
---
 include/linux/compiler-context-analysis.h | 32 +++++++++++++++++++++++
 include/linux/compiler_types.h            | 18 ++-----------
 2 files changed, 34 insertions(+), 16 deletions(-)
 create mode 100644 include/linux/compiler-context-analysis.h

diff --git a/include/linux/compiler-context-analysis.h b/include/linux/compiler-context-analysis.h
new file mode 100644
index 000000000000..f8af63045281
--- /dev/null
+++ b/include/linux/compiler-context-analysis.h
@@ -0,0 +1,32 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Macros and attributes for compiler-based static context analysis.
+ */
+
+#ifndef _LINUX_COMPILER_CONTEXT_ANALYSIS_H
+#define _LINUX_COMPILER_CONTEXT_ANALYSIS_H
+
+#ifdef __CHECKER__
+
+/* Sparse context/lock checking support. */
+# define __must_hold(x)		__attribute__((context(x,1,1)))
+# define __acquires(x)		__attribute__((context(x,0,1)))
+# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
+# define __releases(x)		__attribute__((context(x,1,0)))
+# define __acquire(x)		__context__(x,1)
+# define __release(x)		__context__(x,-1)
+# define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
+
+#else /* !__CHECKER__ */
+
+# define __must_hold(x)
+# define __acquires(x)
+# define __cond_acquires(x)
+# define __releases(x)
+# define __acquire(x)		(void)0
+# define __release(x)		(void)0
+# define __cond_lock(x, c)	(c)
+
+#endif /* __CHECKER__ */
+
+#endif /* _LINUX_COMPILER_CONTEXT_ANALYSIS_H */
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 1280693766b9..ddada1ed88ea 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -41,6 +41,8 @@
 # define BTF_TYPE_TAG(value) /* nothing */
 #endif
 
+#include <linux/compiler-context-analysis.h>
+
 /* sparse defines __CHECKER__; see Documentation/dev-tools/sparse.rst */
 #ifdef __CHECKER__
 /* address spaces */
@@ -51,14 +53,6 @@
 # define __rcu		__attribute__((noderef, address_space(__rcu)))
 static inline void __chk_user_ptr(const volatile void __user *ptr) { }
 static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
-/* context/locking */
-# define __must_hold(x)	__attribute__((context(x,1,1)))
-# define __acquires(x)	__attribute__((context(x,0,1)))
-# define __cond_acquires(x) __attribute__((context(x,0,-1)))
-# define __releases(x)	__attribute__((context(x,1,0)))
-# define __acquire(x)	__context__(x,1)
-# define __release(x)	__context__(x,-1)
-# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)
 /* other */
 # define __force	__attribute__((force))
 # define __nocast	__attribute__((nocast))
@@ -79,14 +73,6 @@ static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
 
 # define __chk_user_ptr(x)	(void)0
 # define __chk_io_ptr(x)	(void)0
-/* context/locking */
-# define __must_hold(x)
-# define __acquires(x)
-# define __cond_acquires(x)
-# define __releases(x)
-# define __acquire(x)	(void)0
-# define __release(x)	(void)0
-# define __cond_lock(x,c) (c)
 /* other */
 # define __force
 # define __nocast
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-2-elver%40google.com.
