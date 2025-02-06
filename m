Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVHZSO6QMGQER5C6YRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 23035A2B04D
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:01 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-3062b3bcdf6sf6617261fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865878; cv=pass;
        d=google.com; s=arc-20240605;
        b=DiOrMsBjdk957ZcRI5RgAE/Mk+NURrjjvahqkLmOInr+GMnqVtWzcM+ag8/JEwXPoX
         lf4brqljoBbN7nLrHlWEGSIjgKoNmv6xl5/HD8IjLnIlvOF6AbnWzwLjJK57A90AxcfI
         8zEu62Y+rbFq3LW1hlSi6wgzg4p1YaPtQux/QE/M407/wp9lnGYBvUlZdnYLMsWEzV2u
         R0AZCihJ6CPogA03NUhvBSmxTc1OjWCBScPq56cY0qlvkJiF1UEpvJvBclUzJWhDgGZk
         1W68wIRHOEHqbN9NIPxgY+y+iG3Aj9ocKWXJr1yusrOBzVp8ZzvTh0gR/9V3vEHBc7uP
         5+lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=bv42cUUm6qg80UwtsCh4RANYpRxzMk4vTGfcdXrrEHA=;
        fh=Nz1XENZ0iWGVyhl8irKFCBfg254HxJ+ySD3i1KPgV8M=;
        b=KxkI13mrXgEBenQxzH0FjShJ1S4TBLY+xVWkWOohIw4rsrU+iE7uwCNHK4YzxHjwYj
         0/82qzqkbsrK5jrdvhU3yeJa9S7HoxFDRckmArBoZBAlfeH7Q1sdiqpf/Jdi4nPxFGv+
         ewYDkiVHVze6KnVTSb4/xPTlRMl9cQpOBxUbxmMRVjHSprSgm89zVszudqYJRaPVAcXr
         hkAOD8Pqi2GABPlnEqcRc7ctfJeshA6WK9mmWLZiVzDHraA04XULwOLX5ZGa2obVxZ12
         37VK6OoWApr/6GP+dVYrFRN91byWbWw01oRA3bft2DhWqlgauL2EyJDrjBms/rRe3zQg
         qNaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pRIpfMiX;
       spf=pass (google.com: domain of 30fykzwukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30fykZwUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865878; x=1739470678; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bv42cUUm6qg80UwtsCh4RANYpRxzMk4vTGfcdXrrEHA=;
        b=bH7QCmTHLxFPl9ygXdEFClDmoIyKCf3J6nmPF0+ZBk4C+2x7YfH0cV0Ejfcx5wPGFF
         5Tdl0f+shXkVAJXNXNllIsSCYlX35mDpBa8Ui56ZS3p6ydg0e+6RtQ5fewVSs8v+xpBm
         F6H+m3X6CLTMDD3FQOy/F7uWvRJqba70stgOk4opa0ZJqMyqTj2L/d4I5Gba5U3IS7Lc
         24gfjM1wJOygtc4YdGUNISjISjC23q6RZT0Qq8VRjW321ALh0XMSv7w/nXtnoSi3/L26
         HQ5QRY9goRw1ir04dfYP2kDkVMDgL1qD6hjAtXj7kujUMOn8rWwkimPp3Bjkr4+B88VQ
         /w1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865878; x=1739470678;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bv42cUUm6qg80UwtsCh4RANYpRxzMk4vTGfcdXrrEHA=;
        b=tlFAZOpJtRa8RTxlgy9KT7Ul/aRedPsZTtyqenIzQc4szkfo6yNv02kd62jy3u8xig
         1mnLOqEMd9alUgigDpMqSyJ2VpFh6p75eeER4nt6kToX3FPMPvwF6jPAO+3pVXCyV5wv
         lpjriqkJxUbUVGzhijFr1ovYQb+2TcCGtjBdwp8Iy4sBkcIIz028g9KbdDpuWuEcKzBK
         IsU8ezP7QzlN6VpeTUK9E2QpkxBrdwQEvjV8IohKxfpi0lHeGgcTP+iZ4IGeSm8FFmp6
         ORT6BV5ESg1qjIkqJgLCGFi4IFcOEkVmedoo1Kaw45JTnQ4Ksk7LpdQIKAz3FmbuIMAL
         ac0Q==
X-Forwarded-Encrypted: i=2; AJvYcCUK0WnU0p1sVu/3p7lLpMhuOcqCIz2V54GjeS71ay5D2jEecgdAs49e+FoLqKQc69qYUboirg==@lfdr.de
X-Gm-Message-State: AOJu0Yw4XDLHRaZpWEOTgvAu4/ZuzcBMkn87B/jQ6RTm+ZAZgixNa3SB
	iiwCccYpm0ibBBcHgA1Q/1I9sLT1OtYLx57uSGd+1CErZukah3HF
X-Google-Smtp-Source: AGHT+IFkFctML+inA5M8qONzTltgyQjVVLYkKifJnpPUYIWzQEDL5bFU/3pKLcQlaEG2zisTDzvPhA==
X-Received: by 2002:a2e:bea0:0:b0:300:4d77:6b7e with SMTP id 38308e7fff4ca-307e57ca98fmr14011fa.10.1738865876796;
        Thu, 06 Feb 2025 10:17:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1986:b0:300:151b:db37 with SMTP id
 38308e7fff4ca-307e4a08ce1ls455211fa.1.-pod-prod-08-eu; Thu, 06 Feb 2025
 10:17:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXfqTZhtsMJILltqnwvEfKcZpt/o7Q+ZJyQAF1Wtao7jbKvKcUC59Go+maCTX4wUnyzFUA0sZGHDUA=@googlegroups.com
X-Received: by 2002:ac2:5696:0:b0:540:2122:faee with SMTP id 2adb3069b0e04-54405a1d0e0mr3230078e87.26.1738865873943;
        Thu, 06 Feb 2025 10:17:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865873; cv=none;
        d=google.com; s=arc-20240605;
        b=cfrUUsUTVgQeQXXaYGBNrS75UG0KPAi7YqlZq4ioawF+cp0z5ngOBXE8QKdLQDJ18Y
         ikSFEIVYBFWwhbUKCqPHW9krmrPec5JGf3/P0PgPSXWpLZMFZqejsAivVlMTyS5bliCD
         sXwxH9ZOYB4KqdN/l2Cm9St6Js8r0mJXgFqCrUYiKhVkxK9PCgikxice/FIYmO/tP8SR
         LjCj9fbBcDb0ZddGnA4ehK3BPUpHiqmOgTn72WVPcKYt+mow3onWV2funa8t1prQcPBM
         9FoQG2HWVvPrqheJIHRm1XA5J5FO7KatVz46ifiKy8OmrauTb6pSLT7CykXNxe/+RDBy
         zqwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=i/6NHOCJ0j6Hx0AS5oQYzqhaSxqaXPhlyrR7hNMYhdY=;
        fh=xuCmzx09rLL7iWLrEqsduuk2gCKkQq3RHo4njR8iL6k=;
        b=dowsXImBd9iRrZ35hRiug3pwmM307u4avWt3ysZefmPL7NKLo28H3lMJ/fBHZPYUpt
         c39IKtzaFMW0y2pfbEERygqHCHTk+x658QTOR/x9tNUmZUOJDZXsaSxP32lEu8NexQ7i
         U3npMEkEJjWHTFcZ+9WBljwg/2eS5e4VVB9oKAZXc5qm4C7QKIvydEIC14sNQAUC072n
         lyPMZE4enHUJSwe25dzKStnQpcNzHee9wqSzjLwhn2LsDomgh3pPZUyZSVoSIUzieW63
         iidZVhpe1dlgH97Tmvq768zfO+ndAS6ZO8r6b7w5ZYBO2gtBX2Xybeqpy9QSw3pWlUMh
         VPEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pRIpfMiX;
       spf=pass (google.com: domain of 30fykzwukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30fykZwUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-544106096e1si31583e87.6.2025.02.06.10.17.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:17:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 30fykzwukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ab2e44dc9b8so242507966b.1
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:17:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVwIXQC95XClOnx2cAAkGwLX7v8z3UmBHtkobvAz7X35c11VyEAPGv8Ay0F469LY9STP63Fe8/4YrY=@googlegroups.com
X-Received: from ejcvo15.prod.google.com ([2002:a17:907:a80f:b0:aab:9ce1:20df])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:6d21:b0:ab6:8bb8:af2e
 with SMTP id a640c23a62f3a-ab76e913b7amr490828066b.26.1738865873264; Thu, 06
 Feb 2025 10:17:53 -0800 (PST)
Date: Thu,  6 Feb 2025 19:09:57 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-4-elver@google.com>
Subject: [PATCH RFC 03/24] compiler-capability-analysis: Add infrastructure
 for Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=pRIpfMiX;       spf=pass
 (google.com: domain of 30fykzwukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=30fykZwUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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

Capability analysis is a C language extension, which enables statically
checking that user-definable "capabilities" are acquired and released where
required. An obvious application is lock-safety checking for the kernel's
various synchronization primitives (each of which represents a "capability"),
and checking that locking rules are not violated.

Clang originally called the feature "Thread Safety Analysis" [1], with
some terminology still using the thread-safety-analysis-only names. This
was later changed and the feature became more flexible, gaining the
ability to define custom "capabilities". Its foundations can be found in
"capability systems", used to specify the permissibility of operations
to depend on some capability being held (or not held).

[1] https://clang.llvm.org/docs/ThreadSafetyAnalysis.html
[2] https://www.cs.cornell.edu/talc/papers/capabilities.pdf

Because the feature is not just able to express capabilities related to
synchronization primitives, the naming chosen for the kernel departs
from Clang's initial "Thread Safety" nomenclature and refers to the
feature as "Capability Analysis" to avoid confusion. The implementation
still makes references to the older terminology in some places, such as
`-Wthread-safety` being the warning enabled option that also still
appears in diagnostic messages.

See more details in the kernel-doc documentation added in this and the
subsequent changes.

[ RFC Note: A Clang version that supports -Wthread-safety-addressof is
  recommended, but not required:
  	https://github.com/llvm/llvm-project/pull/123063
  Should this patch series reach non-RFC stage, it is planned to be
  committed to Clang before. ]

Signed-off-by: Marco Elver <elver@google.com>
---
 Makefile                                     |   1 +
 include/linux/compiler-capability-analysis.h | 385 ++++++++++++++++++-
 lib/Kconfig.debug                            |  29 ++
 scripts/Makefile.capability-analysis         |   5 +
 scripts/Makefile.lib                         |  10 +
 5 files changed, 423 insertions(+), 7 deletions(-)
 create mode 100644 scripts/Makefile.capability-analysis

diff --git a/Makefile b/Makefile
index 9e0d63d9d94b..e89b9f7d4a08 100644
--- a/Makefile
+++ b/Makefile
@@ -1082,6 +1082,7 @@ include-$(CONFIG_KCOV)		+= scripts/Makefile.kcov
 include-$(CONFIG_RANDSTRUCT)	+= scripts/Makefile.randstruct
 include-$(CONFIG_AUTOFDO_CLANG)	+= scripts/Makefile.autofdo
 include-$(CONFIG_PROPELLER_CLANG)	+= scripts/Makefile.propeller
+include-$(CONFIG_WARN_CAPABILITY_ANALYSIS) += scripts/Makefile.capability-analysis
 include-$(CONFIG_GCC_PLUGINS)	+= scripts/Makefile.gcc-plugins
 
 include $(addprefix $(srctree)/, $(include-y))
diff --git a/include/linux/compiler-capability-analysis.h b/include/linux/compiler-capability-analysis.h
index dfed4e7e6ab8..ca63b6513dc3 100644
--- a/include/linux/compiler-capability-analysis.h
+++ b/include/linux/compiler-capability-analysis.h
@@ -6,26 +6,397 @@
 #ifndef _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
 #define _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
 
+#if defined(WARN_CAPABILITY_ANALYSIS)
+
+/*
+ * The below attributes are used to define new capability types. Internal only.
+ */
+# define __cap_type(name)			__attribute__((capability(#name)))
+# define __acquires_cap(var)			__attribute__((acquire_capability(var)))
+# define __acquires_shared_cap(var)		__attribute__((acquire_shared_capability(var)))
+# define __try_acquires_cap(ret, var)		__attribute__((try_acquire_capability(ret, var)))
+# define __try_acquires_shared_cap(ret, var)	__attribute__((try_acquire_shared_capability(ret, var)))
+# define __releases_cap(var)			__attribute__((release_capability(var)))
+# define __releases_shared_cap(var)		__attribute__((release_shared_capability(var)))
+# define __asserts_cap(var)			__attribute__((assert_capability(var)))
+# define __asserts_shared_cap(var)		__attribute__((assert_shared_capability(var)))
+# define __returns_cap(var)			__attribute__((lock_returned(var)))
+
+/*
+ * The below are used to annotate code being checked. Internal only.
+ */
+# define __excludes_cap(var)		__attribute__((locks_excluded(var)))
+# define __requires_cap(var)		__attribute__((requires_capability(var)))
+# define __requires_shared_cap(var)	__attribute__((requires_shared_capability(var)))
+
+/**
+ * __var_guarded_by - struct member and globals attribute, declares variable
+ *                    protected by capability
+ * @var: the capability instance that guards the member or global
+ *
+ * Declares that the struct member or global variable must be guarded by the
+ * given capability @var. Read operations on the data require shared access,
+ * while write operations require exclusive access.
+ *
+ * .. code-block:: c
+ *
+ *	struct some_state {
+ *		spinlock_t lock;
+ *		long counter __var_guarded_by(&lock);
+ *	};
+ */
+# define __var_guarded_by(var)		__attribute__((guarded_by(var)))
+
+/**
+ * __ref_guarded_by - struct member and globals attribute, declares pointed-to
+ *                    data is protected by capability
+ * @var: the capability instance that guards the member or global
+ *
+ * Declares that the data pointed to by the struct member pointer or global
+ * pointer must be guarded by the given capability @var. Read operations on the
+ * data require shared access, while write operations require exclusive access.
+ *
+ * .. code-block:: c
+ *
+ *	struct some_state {
+ *		spinlock_t lock;
+ *		long *counter __ref_guarded_by(&lock);
+ *	};
+ */
+# define __ref_guarded_by(var)		__attribute__((pt_guarded_by(var)))
+
+/**
+ * struct_with_capability() - declare or define a capability struct
+ * @name: struct name
+ *
+ * Helper to declare or define a struct type with capability of the same name.
+ *
+ * .. code-block:: c
+ *
+ *	struct_with_capability(my_handle) {
+ *		int foo;
+ *		long bar;
+ *	};
+ *
+ *	struct some_state {
+ *		...
+ *	};
+ *	// ... declared elsewhere ...
+ *	struct_with_capability(some_state);
+ *
+ * Note: The implementation defines several helper functions that can acquire,
+ * release, and assert the capability.
+ */
+# define struct_with_capability(name)									\
+	struct __cap_type(name) name;									\
+	static __always_inline void __acquire_cap(const struct name *var)				\
+		__attribute__((overloadable)) __no_capability_analysis __acquires_cap(var) { }		\
+	static __always_inline void __acquire_shared_cap(const struct name *var)			\
+		__attribute__((overloadable)) __no_capability_analysis __acquires_shared_cap(var) { }	\
+	static __always_inline bool __try_acquire_cap(const struct name *var, bool ret)			\
+		__attribute__((overloadable)) __no_capability_analysis __try_acquires_cap(1, var)	\
+	{ return ret; }											\
+	static __always_inline bool __try_acquire_shared_cap(const struct name *var, bool ret)		\
+		__attribute__((overloadable)) __no_capability_analysis __try_acquires_shared_cap(1, var) \
+	{ return ret; }											\
+	static __always_inline void __release_cap(const struct name *var)				\
+		__attribute__((overloadable)) __no_capability_analysis __releases_cap(var) { }		\
+	static __always_inline void __release_shared_cap(const struct name *var)			\
+		__attribute__((overloadable)) __no_capability_analysis __releases_shared_cap(var) { }	\
+	static __always_inline void __assert_cap(const struct name *var)				\
+		__attribute__((overloadable)) __asserts_cap(var) { }					\
+	static __always_inline void __assert_shared_cap(const struct name *var)				\
+		__attribute__((overloadable)) __asserts_shared_cap(var) { }				\
+	struct name
+
+/**
+ * disable_capability_analysis() - disables capability analysis
+ *
+ * Disables capability analysis. Must be paired with a later
+ * enable_capability_analysis().
+ */
+# define disable_capability_analysis()				\
+	__diag_push();						\
+	__diag_ignore_all("-Wunknown-warning-option", "")	\
+	__diag_ignore_all("-Wthread-safety", "")		\
+	__diag_ignore_all("-Wthread-safety-addressof", "")
+
+/**
+ * enable_capability_analysis() - re-enables capability analysis
+ *
+ * Re-enables capability analysis. Must be paired with a prior
+ * disable_capability_analysis().
+ */
+# define enable_capability_analysis() __diag_pop()
+
+/**
+ * __no_capability_analysis - function attribute, disables capability analysis
+ *
+ * Function attribute denoting that capability analysis is disabled for the
+ * whole function. Prefer use of `capability_unsafe()` where possible.
+ */
+# define __no_capability_analysis	__attribute__((no_thread_safety_analysis))
+
+#else /* !WARN_CAPABILITY_ANALYSIS */
+
+# define __cap_type(name)
+# define __acquires_cap(var)
+# define __acquires_shared_cap(var)
+# define __try_acquires_cap(ret, var)
+# define __try_acquires_shared_cap(ret, var)
+# define __releases_cap(var)
+# define __releases_shared_cap(var)
+# define __asserts_cap(var)
+# define __asserts_shared_cap(var)
+# define __returns_cap(var)
+# define __var_guarded_by(var)
+# define __ref_guarded_by(var)
+# define __excludes_cap(var)
+# define __requires_cap(var)
+# define __requires_shared_cap(var)
+# define __acquire_cap(var)			do { } while (0)
+# define __acquire_shared_cap(var)		do { } while (0)
+# define __try_acquire_cap(var, ret)		(ret)
+# define __try_acquire_shared_cap(var, ret)	(ret)
+# define __release_cap(var)			do { } while (0)
+# define __release_shared_cap(var)		do { } while (0)
+# define __assert_cap(var)			do { (void)(var); } while (0)
+# define __assert_shared_cap(var)		do { (void)(var); } while (0)
+# define struct_with_capability(name)		struct name
+# define disable_capability_analysis()
+# define enable_capability_analysis()
+# define __no_capability_analysis
+
+#endif /* WARN_CAPABILITY_ANALYSIS */
+
+/**
+ * capability_unsafe() - disable capability checking for contained code
+ *
+ * Disables capability checking for contained statements or expression.
+ *
+ * .. code-block:: c
+ *
+ *	struct some_data {
+ *		spinlock_t lock;
+ *		int counter __var_guarded_by(&lock);
+ *	};
+ *
+ *	int foo(struct some_data *d)
+ *	{
+ *		// ...
+ *		// other code that is still checked ...
+ *		// ...
+ *		return capability_unsafe(d->counter);
+ *	}
+ */
+#define capability_unsafe(...)		\
+({					\
+	disable_capability_analysis();	\
+	__VA_ARGS__;			\
+	enable_capability_analysis()	\
+})
+
+/**
+ * token_capability() - declare an abstract global capability instance
+ * @name: token capability name
+ *
+ * Helper that declares an abstract global capability instance @name that can be
+ * used as a token capability, but not backed by a real data structure (linker
+ * error if accidentally referenced). The type name is `__capability_@name`.
+ */
+#define token_capability(name)				\
+	struct_with_capability(__capability_##name) {};	\
+	extern const struct __capability_##name *name
+
+/**
+ * token_capability_instance() - declare another instance of a global capability
+ * @cap: token capability previously declared with token_capability()
+ * @name: name of additional global capability instance
+ *
+ * Helper that declares an additional instance @name of the same token
+ * capability class @name. This is helpful where multiple related token
+ * capabilities are declared, as it also allows using the same underlying type
+ * (`__capability_@cap`) as function arguments.
+ */
+#define token_capability_instance(cap, name)		\
+	extern const struct __capability_##cap *name
+
+/*
+ * Common keywords for static capability analysis. Both Clang's capability
+ * analysis and Sparse's context tracking are currently supported.
+ */
 #ifdef __CHECKER__
 
 /* Sparse context/lock checking support. */
 # define __must_hold(x)		__attribute__((context(x,1,1)))
+# define __must_not_hold(x)
 # define __acquires(x)		__attribute__((context(x,0,1)))
 # define __cond_acquires(x)	__attribute__((context(x,0,-1)))
 # define __releases(x)		__attribute__((context(x,1,0)))
 # define __acquire(x)		__context__(x,1)
 # define __release(x)		__context__(x,-1)
 # define __cond_acquire(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
+/* For Sparse, there's no distinction between exclusive and shared locks. */
+# define __must_hold_shared	__must_hold
+# define __acquires_shared	__acquires
+# define __cond_acquires_shared __cond_acquires
+# define __releases_shared	__releases
+# define __acquire_shared	__acquire
+# define __release_shared	__release
+# define __cond_acquire_shared	__cond_acquire
 
 #else /* !__CHECKER__ */
 
-# define __must_hold(x)
-# define __acquires(x)
-# define __cond_acquires(x)
-# define __releases(x)
-# define __acquire(x)		(void)0
-# define __release(x)		(void)0
-# define __cond_acquire(x, c)	(c)
+/**
+ * __must_hold() - function attribute, caller must hold exclusive capability
+ * @x: capability instance pointer
+ *
+ * Function attribute declaring that the caller must hold the given capability
+ * instance @x exclusively.
+ */
+# define __must_hold(x)		__requires_cap(x)
+
+/**
+ * __must_not_hold() - function attribute, caller must not hold capability
+ * @x: capability instance pointer
+ *
+ * Function attribute declaring that the caller must not hold the given
+ * capability instance @x.
+ */
+# define __must_not_hold(x)	__excludes_cap(x)
+
+/**
+ * __acquires() - function attribute, function acquires capability exclusively
+ * @x: capability instance pointer
+ *
+ * Function attribute declaring that the function acquires the the given
+ * capability instance @x exclusively, but does not release it.
+ */
+# define __acquires(x)		__acquires_cap(x)
+
+/**
+ * __cond_acquires() - function attribute, function conditionally
+ *                     acquires a capability exclusively
+ * @x: capability instance pointer
+ *
+ * Function attribute declaring that the function conditionally acquires the
+ * given capability instance @x exclusively, but does not release it.
+ */
+# define __cond_acquires(x)	__try_acquires_cap(1, x)
+
+/**
+ * __releases() - function attribute, function releases a capability exclusively
+ * @x: capability instance pointer
+ *
+ * Function attribute declaring that the function releases the given capability
+ * instance @x exclusively. The capability must be held on entry.
+ */
+# define __releases(x)		__releases_cap(x)
+
+/**
+ * __acquire() - function to acquire capability exclusively
+ * @x: capability instance pinter
+ *
+ * No-op function that acquires the given capability instance @x exclusively.
+ */
+# define __acquire(x)		__acquire_cap(x)
+
+/**
+ * __release() - function to release capability exclusively
+ * @x: capability instance pinter
+ *
+ * No-op function that releases the given capability instance @x.
+ */
+# define __release(x)		__release_cap(x)
+
+/**
+ * __cond_acquire() - function that conditionally acquires a capability
+ *                    exclusively
+ * @x: capability instance pinter
+ * @c: boolean expression
+ *
+ * Return: result of @c
+ *
+ * No-op function that conditionally acquires capability instance @x
+ * exclusively, if the boolean expression @c is true. The result of @c is the
+ * return value, to be able to create a capability-enabled interface; for
+ * example:
+ *
+ * .. code-block:: c
+ *
+ *	#define spin_trylock(l) __cond_acquire(&lock, _spin_trylock(&lock))
+ */
+# define __cond_acquire(x, c)	__try_acquire_cap(x, c)
+
+/**
+ * __must_hold_shared() - function attribute, caller must hold shared capability
+ * @x: capability instance pointer
+ *
+ * Function attribute declaring that the caller must hold the given capability
+ * instance @x with shared access.
+ */
+# define __must_hold_shared(x)	__requires_shared_cap(x)
+
+/**
+ * __acquires_shared() - function attribute, function acquires capability shared
+ * @x: capability instance pointer
+ *
+ * Function attribute declaring that the function acquires the the given
+ * capability instance @x with shared access, but does not release it.
+ */
+# define __acquires_shared(x)	__acquires_shared_cap(x)
+
+/**
+ * __cond_acquires_shared() - function attribute, function conditionally
+ *                            acquires a capability shared
+ * @x: capability instance pointer
+ *
+ * Function attribute declaring that the function conditionally acquires the
+ * given capability instance @x with shared access, but does not release it.
+ */
+# define __cond_acquires_shared(x) __try_acquires_shared_cap(1, x)
+
+/**
+ * __releases_shared() - function attribute, function releases a
+ *                       capability shared
+ * @x: capability instance pointer
+ *
+ * Function attribute declaring that the function releases the given capability
+ * instance @x with shared access. The capability must be held on entry.
+ */
+# define __releases_shared(x)	__releases_shared_cap(x)
+
+/**
+ * __acquire_shared() - function to acquire capability shared
+ * @x: capability instance pinter
+ *
+ * No-op function that acquires the given capability instance @x with shared
+ * access.
+ */
+# define __acquire_shared(x)	__acquire_shared_cap(x)
+
+/**
+ * __release_shared() - function to release capability shared
+ * @x: capability instance pinter
+ *
+ * No-op function that releases the given capability instance @x with shared
+ * access.
+ */
+# define __release_shared(x)	__release_shared_cap(x)
+
+/**
+ * __cond_acquire_shared() - function that conditionally acquires a capability
+ *                           shared
+ * @x: capability instance pinter
+ * @c: boolean expression
+ *
+ * Return: result of @c
+ *
+ * No-op function that conditionally acquires capability instance @x with shared
+ * access, if the boolean expression @c is true. The result of @c is the return
+ * value, to be able to create a capability-enabled interface.
+ */
+# define __cond_acquire_shared(x, c) __try_acquire_shared_cap(x, c)
 
 #endif /* __CHECKER__ */
 
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 1af972a92d06..801ad28fe6d7 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -603,6 +603,35 @@ config DEBUG_FORCE_WEAK_PER_CPU
 	  To ensure that generic code follows the above rules, this
 	  option forces all percpu variables to be defined as weak.
 
+config WARN_CAPABILITY_ANALYSIS
+	bool "Compiler capability-analysis warnings"
+	depends on CC_IS_CLANG && $(cc-option,-Wthread-safety -fexperimental-late-parse-attributes)
+	# Branch profiling re-defines "if", which messes with the compiler's
+	# ability to analyze __cond_acquire(..), resulting in false positives.
+	depends on !TRACE_BRANCH_PROFILING
+	default y
+	help
+	  Capability analysis is a C language extension, which enables
+	  statically checking that user-definable "capabilities" are acquired
+	  and released where required.
+
+	  Clang's name of the feature ("Thread Safety Analysis") refers to
+	  the original name of the feature; it was later expanded to be a
+	  generic "Capability Analysis" framework.
+
+	  Produces warnings by default. Select CONFIG_WERROR if you wish to
+	  turn these warnings into errors.
+
+config WARN_CAPABILITY_ANALYSIS_ALL
+	bool "Enable capability analysis for all source files"
+	depends on WARN_CAPABILITY_ANALYSIS
+	depends on EXPERT && !COMPILE_TEST
+	help
+	  Enable tree-wide capability analysis. This is likely to produce a
+	  large number of false positives - enable at your own risk.
+
+	  If unsure, say N.
+
 endmenu # "Compiler options"
 
 menu "Generic Kernel Debugging Instruments"
diff --git a/scripts/Makefile.capability-analysis b/scripts/Makefile.capability-analysis
new file mode 100644
index 000000000000..71383812201c
--- /dev/null
+++ b/scripts/Makefile.capability-analysis
@@ -0,0 +1,5 @@
+# SPDX-License-Identifier: GPL-2.0
+
+export CFLAGS_CAPABILITY_ANALYSIS := -DWARN_CAPABILITY_ANALYSIS \
+	-fexperimental-late-parse-attributes -Wthread-safety	\
+	$(call cc-option,-Wthread-safety-addressof)
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index ad55ef201aac..5bf37af96cdf 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -191,6 +191,16 @@ _c_flags += $(if $(patsubst n%,, \
 	-D__KCSAN_INSTRUMENT_BARRIERS__)
 endif
 
+#
+# Enable capability analysis flags only where explicitly opted in.
+# (depends on variables CAPABILITY_ANALYSIS_obj.o, CAPABILITY_ANALYSIS)
+#
+ifeq ($(CONFIG_WARN_CAPABILITY_ANALYSIS),y)
+_c_flags += $(if $(patsubst n%,, \
+		$(CAPABILITY_ANALYSIS_$(target-stem).o)$(CAPABILITY_ANALYSIS)$(if $(is-kernel-object),$(CONFIG_WARN_CAPABILITY_ANALYSIS_ALL))), \
+		$(CFLAGS_CAPABILITY_ANALYSIS))
+endif
+
 #
 # Enable AutoFDO build flags except some files or directories we don't want to
 # enable (depends on variables AUTOFDO_PROFILE_obj.o and AUTOFDO_PROFILE).
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-4-elver%40google.com.
