Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6UNTO7AMGQEDTBSGOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 534D5A4D7F0
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:16 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-30badd1f368sf12942301fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080315; cv=pass;
        d=google.com; s=arc-20240605;
        b=f8bMImXS9Gcy5lIcEKUgX9+SiOtkorHcSeYjI9VSR+tMY1NySmTR3TT5TmEYbGAibK
         r76RbZYHt8OThaA1stM+YQ3Cc1jn1gLagi7bnsVrThfhBtK8UcemxQl+AwbuWdmKkr5i
         5lGHAl6ioEPlqlQFkJgGleBIOL/n22XR85eBD5NFNjQCx28emZrbIpP4n/SNAeQ1iOqj
         7MazBnv0ttkXxFBEWgpHlHUlzQqF0Be9UuQqjSBI7LmAObCr/O/3VxolCHSuVb/c64Jw
         YfYaSmQFVRICO0fuYkzCZ6GB0eCsvsfbdIplXeFcLMeHgHc5H5P5fV1EZOt786EY3NAA
         soNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=0w7vyhLazEjJIJHwTEoyRmhhK1tXg6pGukPkyrB9BGE=;
        fh=isWmpD72n3MPnJ69NQyrZ5/dy9ESwlA2CE2HVvJhg70=;
        b=dYxq/S2E3IMtpilCBAKpkSDpc21S/ZUOyCfhT/oLyj+xJU4aUbweq7WkhHmZOaRxVp
         y8O18y+u38DsNAoJCxaPZ+/YKeZaxPlXgBBbVaM3q5leggFjxE7dBVticH+4LBBDoZfP
         o7uFcJRD1OfDs656ZeQO73vPSX/CPkZQ/APqUSoq9vaKkvmR7KcyFDU3Ep8BMvSaQ5ML
         3EGFsy0HcWlbOIWWjOicoR5A/YDmFrPcfAR4R3kBMev8WSy3omrKEZ9zwwRACyh1BCuc
         ymV/dYlaJhkBLeM9i1OjwvAqjb7wjtZCHbVMY6ANt8RYu+WQ1pyfyQDFel/AJu+QvsG3
         ejxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eUCzvy5R;
       spf=pass (google.com: domain of 398bgzwukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=398bGZwUKCeQKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080315; x=1741685115; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0w7vyhLazEjJIJHwTEoyRmhhK1tXg6pGukPkyrB9BGE=;
        b=M+2XVAlEcU7eiJOKtRU8o1WiouBznitpIfgsRhoVnkxIxmXeBsXLEUR0DAKT9vIVXZ
         wgQS7ZdkUcM78GPlnoxK7DU9Awls9XBZCEOV/UO4ep+P236qRp+/dMylDmTA3Br7HY6g
         RKQljyTupLfWqt4X8GBdprKztpfrN+MG1RfSGJxZpe5vqCcjzqVNbnQD5GWspsb2TzeB
         z3ENBzLwnk690XEmepIHsBlDDHEW2iiN7IPM9C4vSXhpUODsWTOsJGE0CXk8cuixZ0jr
         0wct51oZTYUygGXRxFO+2mbrg5YVYJyRrK/QPSPJAJh3gw9FIlEBwurZ6xLov85ldrbK
         1TsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080315; x=1741685115;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0w7vyhLazEjJIJHwTEoyRmhhK1tXg6pGukPkyrB9BGE=;
        b=Exu+9DhG0ZCT/zX7uDRB0YimHOYXyq5RBglUDlR84MRMoErGYF0bBKYyilz/nnPE1Y
         tK/KXDIRFJ48EhibaljRnGNO9Cqro5npp1vqOMWP9Tj0f3W6zgKp6f9/CGRUAIB92xuj
         d1LieZbFQ/GIkeElg4UnIwVSLU8CKrpqWR40tfZ9FVf4I1h13QcyGIxL1EG7OIS5jJQ3
         1QPqCwC1KB3lz67aILmSHIeVEhei5kP3KKExQK4R1wBOodFzavoaXLiDpqVK0U2IKqD3
         sJgp/jY7IKncv8s082g9tGCOuB877mQAF0iD2b92SPlwpI5owRX4f/CQMMA0OnNpt7mH
         jIIg==
X-Forwarded-Encrypted: i=2; AJvYcCWdoi+45wx2tigbnE0CJOBAs3NJ4Ql0eRyYTaDPCtWsK+4EcHBARp8jl5SbarLY7nb4ASSBEw==@lfdr.de
X-Gm-Message-State: AOJu0Yy5m7ud9mDIUDHxY0spOrH4MAZLicg2xyaCsaOdBDajYrKXXSiT
	yHi9pp2DF8ak+Y/f8rF8q+Jk38ydhgc972f5vdHcLNC3I6NrTTQ6
X-Google-Smtp-Source: AGHT+IGRFhqaProWEK+qCmIaGV61R2BBnIC7OzYwHzDXb5YM9DJ+s8MPG8J/3q/TwSQesqcyMa71eA==
X-Received: by 2002:a05:651c:b23:b0:30b:c91d:3600 with SMTP id 38308e7fff4ca-30bc91d3c15mr9440231fa.8.1741080314867;
        Tue, 04 Mar 2025 01:25:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFekBbJmdXWclpOkQ0jrVCo+rlLkr3Lq6yBRPDjeAlShw==
Received: by 2002:a05:651c:50d:b0:30a:355a:214a with SMTP id
 38308e7fff4ca-30b847ab637ls2712911fa.1.-pod-prod-03-eu; Tue, 04 Mar 2025
 01:25:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWzUzYTtEWvHVwNWADhvKik7PBpXzbyjAQEEpT6UDuhfR827qjanC/7Ek/DPg/8qLGIF13+xaLOa9Q=@googlegroups.com
X-Received: by 2002:a2e:bc12:0:b0:30b:cd68:b6a9 with SMTP id 38308e7fff4ca-30bcd68b99amr5492611fa.11.1741080312064;
        Tue, 04 Mar 2025 01:25:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080312; cv=none;
        d=google.com; s=arc-20240605;
        b=MNJOpmklYTG2w22MZGbvRZxQOeHwzAwfmlY7bqGGLtbRdVBnQ8LNNs2gBXl8pQ6WuY
         ehGvsUdm/3R894T05UhSjZVlDHLzve40ciY8MbPNu9z04lAhEO2++xFdVJxEqDxcT6K6
         7QxHV5W+NwhcQCUPi9nxmdNFXQyPxrAkCddNnpVODu7YqgMwtwFMfsWL0N4IjVbv5pId
         1tNvBZiT1hmH/OTezAT+XTvRzROe8sRc5OfVznB8OuO+r2FliXK5+oFVgYbsL2t8EDcc
         iHH/ouLBJ5RHGvVNlX5luzOX9LOynQayQarcuiWCLkUGnLAKNt2BWmYcv714Bz+XDY+s
         GLoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=NQzJ/uCYeuflL88Y+3MrtFVv4DOW+ANfKOTFJKL+x3k=;
        fh=zPo/w/gebHhavRLrk/ieUzqEgUtqVjx99EGOaCgh4x0=;
        b=iKQvHEQLNCAcg7gE8cj98YIP1uljVsNJdzoMZVqFuNOune/cj/rnHakaUpykLAUqc/
         lI+VrATV//Cyu8hXODQwEj6J2kk3VodL7uiu37qI7fZJ2+AwDAL8vrzTAK1yRTF02yxl
         kpr1lZdV5lFABb/8x89XCdUBQ2UvV6Y16hwexm9o2zNd2LTHZg99r9Uqg9kTuxD7D1no
         k9YodHYtnRKuJW20VvamkQum30GkS/6+7bsd8MZM83sIMTCsoWZwylSvbofTp+vO41q6
         KVXO+Af8BI6zszs0TAtLveBTnOjT+yY07vam6cdUPTEE2xu2SLMKe6CkLx+IuXE9WTHR
         AcWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eUCzvy5R;
       spf=pass (google.com: domain of 398bgzwukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=398bGZwUKCeQKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30ba2e9c829si1448181fa.1.2025.03.04.01.25.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 398bgzwukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-abf78df3bbcso209545766b.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWI4F3tnblaoPtylKzYXBTk5CwvWMi0IM5idigbseBtlNRMqkm9yEqOfbf4UQQVd1Uk6ugS8kpm2LY=@googlegroups.com
X-Received: from edbfd23.prod.google.com ([2002:a05:6402:3897:b0:5e4:d495:16dd])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:268f:b0:5e0:3f83:92ab
 with SMTP id 4fb4d7f45d1cf-5e4d6b87d70mr17084911a12.30.1741080311449; Tue, 04
 Mar 2025 01:25:11 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:00 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-2-elver@google.com>
Subject: [PATCH v2 01/34] compiler_types: Move lock checking attributes to compiler-capability-analysis.h
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
 header.i=@google.com header.s=20230601 header.b=eUCzvy5R;       spf=pass
 (google.com: domain of 398bgzwukceqkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=398bGZwUKCeQKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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
generalizing towards "capability analysis".

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler-capability-analysis.h | 32 ++++++++++++++++++++
 include/linux/compiler_types.h               | 18 ++---------
 2 files changed, 34 insertions(+), 16 deletions(-)
 create mode 100644 include/linux/compiler-capability-analysis.h

diff --git a/include/linux/compiler-capability-analysis.h b/include/linux/compiler-capability-analysis.h
new file mode 100644
index 000000000000..7546ddb83f86
--- /dev/null
+++ b/include/linux/compiler-capability-analysis.h
@@ -0,0 +1,32 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Macros and attributes for compiler-based static capability analysis.
+ */
+
+#ifndef _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
+#define _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
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
+#endif /* _LINUX_COMPILER_CAPABILITY_ANALYSIS_H */
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 981cc3d7e3aa..4a458e41293c 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -24,6 +24,8 @@
 # define BTF_TYPE_TAG(value) /* nothing */
 #endif
 
+#include <linux/compiler-capability-analysis.h>
+
 /* sparse defines __CHECKER__; see Documentation/dev-tools/sparse.rst */
 #ifdef __CHECKER__
 /* address spaces */
@@ -34,14 +36,6 @@
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
@@ -62,14 +56,6 @@ static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
 
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
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-2-elver%40google.com.
