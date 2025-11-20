Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI637TEAMGQEYIPAZAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id B91F9C74BA2
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:03:00 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-42b3086a055sf905217f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:03:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763650980; cv=pass;
        d=google.com; s=arc-20240605;
        b=HPKJDyMsnERicG9kuoS5h/oaOCAFkWBZ2u/RgbUosWFVd5KwjrVBZEtSBTFJ7W0kaE
         AJkmXwZjz/T+Gcs2/me4OMp5gt3jJFNmDGbGtNSMaZUHa2YhDAJ8T6J5C77MghOIEmgC
         HIgylLKi6xVzmbQ2hyTucnnjFM85vIsdJAx/LGe8h3mrA//uDc4d/gZvwBMxDCKfrUm9
         NNY7hznGO9kflhtLvR51CboCsOmbM1IXRZgg7/RCipXKOdfL1pGDXkWRsqdIwe9aJHT3
         lnPEi0VN4+7NLYzDrKRzcfIX66zXf/6up1RVzJf2B6XNYyLuAJhX95XQTES76ZVk99bY
         7u0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=3ATkRluvzTxkDN12pG1qFFgCDjHM9phkwGdCVvx+9Sg=;
        fh=GLbpkM2LMJiZseO8+2Q5Ws+Cqzi2jTNw3EWCALOxXmY=;
        b=Z+VrEH4d4wyrTjzO/hibGE/HdTDK9aYfzSyn5ErTPMK7JbS/q7iz3LRwptMu7iLRfZ
         /tkZRFNKkcIkQ1iL3zrpfK9m0EdZ1Hk1dkjJCuWRjTNSHQ4prVdDl7GRfl9sYGBl8R9F
         ViAwFsUBxzj8bHObTztJxvjJ4bkZYnSMVqy0QtfDCz6Ej3oUO5RHNVnwimDLX2aH4gox
         3dLl7JLspn1AVeO6i8PBOkF1KV7v6KyzO+7UwptUhytRRfXXYWntEW7TFWPnSq+KMGMb
         I2sVtn9ovc4TyNLxKSNkdZhxfBJTh7BPOq5vqypsniNZE7pj9t2Czri9p5ChYOppDSM1
         hreg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bgot0owZ;
       spf=pass (google.com: domain of 3oc0faqukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oC0faQUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763650980; x=1764255780; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3ATkRluvzTxkDN12pG1qFFgCDjHM9phkwGdCVvx+9Sg=;
        b=qAaaJ6GvHJGcJ03B7lTT06tFKArDlSKSZanKMC2DNxZGA3GfCtL5xX42aXkId026Xd
         WTvNuQxIs+9+qVP5CAbpgqgqBCbTtS0Chavs93iU4s/IctarBsMkxNipzZ0MiIRLgOl7
         uyrxA+zu0giPa/BzmOdd68BYgRvqGUcVB4lyyQsIxpynobXlBMKPF+IiSB9U0unU/6LU
         vtNp0ceCLQsRekKfKqYSC5j04iK9kobtdtvD4M0YDbTLsKwznHgpRAac5bR8AjipIzVm
         gh+0od7NwDr3QiYQLe8oJ1hrCyLXKXCeY0J9gTXRlNU0Z66OvR6yJJe2KBQHH3RFtq9L
         w1pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763650980; x=1764255780;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3ATkRluvzTxkDN12pG1qFFgCDjHM9phkwGdCVvx+9Sg=;
        b=COt7GK5MhILpN71UeH+Diii3uTPZcVlRmSyCPh0X8HrO1yA0g2F7bW75bhLk/aGU0i
         A4yR9sLvyZXMgruumozbzkurzqXBLwpIVFJGqcU8VDKjynE3iyHWsGa8RZTXvJDGiLF5
         p6SLsS63YcB+1BEwnqI/mOOt1UJZDR5Fkqmp3NhZEnbvLZU78YdbH8iufa2qL+Iy1rHh
         t2BHgV+7nnU+QKgcxe2LJ8J+2QIP48Qs+1FpgnNrFAJyGOnRv24zreQfosg467H+u3KH
         +2EEJY8AN6Tch3pnvAew3DfySuUc9iPHF7tY7rVup56Hq3anfMJkKmMATGau5REvrCsF
         dviw==
X-Forwarded-Encrypted: i=2; AJvYcCVDrvo11yvdiG0NCfGKv9N/edzuXLKX1Y7azfjMoDlXbtiv2APQSWLpL+tifmSBnT0y/UkCiw==@lfdr.de
X-Gm-Message-State: AOJu0Yw0eAZLH/yIaS3+NClhUljMyjRWGseXWbfM6gx54+zRKCT3rrOj
	aJj6UP5S86+DgkyvnrlOS+q0DBZndJnOrqWdVWw3CpqX4ro7lM46ohoG
X-Google-Smtp-Source: AGHT+IGIZYpZwiXwWBllWLhva8GgAbGm5oOlkFRqo4kVpVvfUWLet02HfnPsHauKhhiAAFauuTtptQ==
X-Received: by 2002:a05:6000:2003:b0:42b:32a0:3490 with SMTP id ffacd0b85a97d-42cb9a6aaf2mr2797350f8f.49.1763650979864;
        Thu, 20 Nov 2025 07:02:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZJXUSNp5ncyQbFxTTOUYAhoEmpHLv11FVLY7vStob4PA=="
Received: by 2002:a5d:5f93:0:b0:3b3:9ca4:d6f3 with SMTP id ffacd0b85a97d-42cb8239897ls642274f8f.2.-pod-prod-09-eu;
 Thu, 20 Nov 2025 07:02:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVLjW4wJ3UCWDGBtIEtqTs7ab5k9ak0dGq/h7TrvkVLyoM6N6mFoIItSy1IoQH3m7WsU7HckKEohOI=@googlegroups.com
X-Received: by 2002:a05:600c:4449:b0:477:98f7:2aec with SMTP id 5b1f17b1804b1-477b89548b6mr33171795e9.3.1763650977187;
        Thu, 20 Nov 2025 07:02:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763650977; cv=none;
        d=google.com; s=arc-20240605;
        b=aAwzNyjy0GCSKEY6/BulT7/OPhaOe3vsulBtzbbPzFZv/X9688drjWAOuRc+9EfwrG
         zDIslMtgqDpiBzGTSC2xDQtuB4oWlcZUzONOmPX3r5VZE2cxTLNu9VNaXwmqaWcYDDNA
         x1Q32B3jojV4m8KWZsfp12uXQrMhvIAp68UzsEtXjlvO2AIF6Ia0ofjIVsNKM3f2Vwt1
         Fsefo+t2IMN8nvQsXLxroRuptG2mqy1eOdG4M2xcfPq0Tm5tU6nX9wqbzAn991uy5fNp
         /GdnoBRShic7NbHoWzo/bsjw+YMOzXXv4Fzqf3G68ajYtmBUQD387q2CXsQZieWcqq8A
         RRZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=zAJGdoX03+Z7kHA10F2BJAYl/c1vU7j8o14tItuzLUc=;
        fh=e2qiXvVRwGhFiyxmAiH9Nlxsg2Vr2XDqE0qWXoGQnNY=;
        b=L12VlvMDKsN4ELwqrgWKDPZLskg8+hcRsfOIyZP+B7hUQYnVKqkkIITcwsT8xCP12Z
         qFZ6YNoZ3HNCQ7U/XsrBi98spuPgqxAMsiiFJ9zxaaRU0gwQk0lPpWbLjQSuspivpErK
         zdGNRwV3IWPgXLZoEV72FBoAd2d394ElK448+o8i4cmKyj4JymDPAhYw7HTevBWzMGmF
         O2dCPFPLUMKFfU3CKvjqgx+BToiS9pGzerNC4hKzJXodAVwLEvXZraW0/IEApO8/tTvf
         X6BUohfKE8kkp6N50aA8cwjBRcb3McNtH0lip9jw7Z3CDErY/qI3Lkn1EUiZojbl0l/x
         7LnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bgot0owZ;
       spf=pass (google.com: domain of 3oc0faqukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oC0faQUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-477a9da5ae2si631005e9.3.2025.11.20.07.02.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:02:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oc0faqukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477563e531cso9731005e9.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:02:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUTxlOdjdYsv+9Nhet6ho7jLswcOEnz8YsSpW8+aDqpgOthoJ9194G4ux9CROMeyN12xpfQrKcyubo=@googlegroups.com
X-Received: from wmot8.prod.google.com ([2002:a05:600c:4508:b0:477:a4d4:607a])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1d05:b0:477:54cd:200a
 with SMTP id 5b1f17b1804b1-477b8a518f4mr26264575e9.6.1763650976118; Thu, 20
 Nov 2025 07:02:56 -0800 (PST)
Date: Thu, 20 Nov 2025 15:49:06 +0100
In-Reply-To: <20251120145835.3833031-2-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120145835.3833031-6-elver@google.com>
Subject: [PATCH v4 04/35] Documentation: Add documentation for Compiler-Based
 Context Analysis
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
 header.i=@google.com header.s=20230601 header.b=bgot0owZ;       spf=pass
 (google.com: domain of 3oc0faqukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oC0faQUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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

Adds documentation in Documentation/dev-tools/context-analysis.rst, and
adds it to the index.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v2:
* Remove cross-reference to Sparse, since we plan to remove Sparse
  support anyway.
* Mention __no_context_analysis should be avoided.
---
 Documentation/dev-tools/context-analysis.rst | 145 +++++++++++++++++++
 Documentation/dev-tools/index.rst            |   1 +
 2 files changed, 146 insertions(+)
 create mode 100644 Documentation/dev-tools/context-analysis.rst

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
new file mode 100644
index 000000000000..a15436e288fd
--- /dev/null
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -0,0 +1,145 @@
+.. SPDX-License-Identifier: GPL-2.0
+.. Copyright (C) 2025, Google LLC.
+
+.. _context-analysis:
+
+Compiler-Based Context Analysis
+===============================
+
+Context Analysis is a language extension, which enables statically checking
+that required contexts are active (or inactive) by acquiring and releasing
+user-definable "context guards". An obvious application is lock-safety checking
+for the kernel's various synchronization primitives (each of which represents a
+"context guard"), and checking that locking rules are not violated.
+
+The Clang compiler currently supports the full set of context analysis
+features. To enable for Clang, configure the kernel with::
+
+    CONFIG_WARN_CONTEXT_ANALYSIS=y
+
+The feature requires Clang 22 or later.
+
+The analysis is *opt-in by default*, and requires declaring which modules and
+subsystems should be analyzed in the respective `Makefile`::
+
+    CONTEXT_ANALYSIS_mymodule.o := y
+
+Or for all translation units in the directory::
+
+    CONTEXT_ANALYSIS := y
+
+It is possible to enable the analysis tree-wide, however, which will result in
+numerous false positive warnings currently and is *not* generally recommended::
+
+    CONFIG_WARN_CONTEXT_ANALYSIS_ALL=y
+
+Programming Model
+-----------------
+
+The below describes the programming model around using context guard types.
+
+.. note::
+   Enabling context analysis can be seen as enabling a dialect of Linux C with
+   a Context System. Some valid patterns involving complex control-flow are
+   constrained (such as conditional acquisition and later conditional release
+   in the same function).
+
+Context analysis is a way to specify permissibility of operations to depend on
+context guards being held (or not held). Typically we are interested in
+protecting data and code in a critical section by requiring a specific context
+to be active, for example by holding a specific lock. The analysis ensures that
+callers cannot perform an operation without the required context being active.
+
+Context guards are associated with named structs, along with functions that
+operate on struct instances to acquire and release the associated context
+guard.
+
+Context guards can be held either exclusively or shared. This mechanism allows
+assigning more precise privileges when a context is active, typically to
+distinguish where a thread may only read (shared) or also write (exclusive) to
+data guarded within a context.
+
+The set of contexts that are actually active in a given thread at a given point
+in program execution is a run-time concept. The static analysis works by
+calculating an approximation of that set, called the context environment. The
+context environment is calculated for every program point, and describes the
+set of contexts that are statically known to be active, or inactive, at that
+particular point. This environment is a conservative approximation of the full
+set of contexts that will actually be active in a thread at run-time.
+
+More details are also documented `here
+<https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_.
+
+.. note::
+   Clang's analysis explicitly does not infer context guards acquired or
+   released by inline functions. It requires explicit annotations to (a) assert
+   that it's not a bug if a context guard is released or acquired, and (b) to
+   retain consistency between inline and non-inline function declarations.
+
+Supported Kernel Primitives
+~~~~~~~~~~~~~~~~~~~~~~~~~~~
+
+.. Currently the following synchronization primitives are supported:
+
+For context guards with an initialization function (e.g., `spin_lock_init()`),
+calling this function before initializing any guarded members or globals
+prevents the compiler from issuing warnings about unguarded initialization.
+
+Lockdep assertions, such as `lockdep_assert_held()`, inform the compiler's
+context analysis that the associated synchronization primitive is held after
+the assertion. This avoids false positives in complex control-flow scenarios
+and encourages the use of Lockdep where static analysis is limited. For
+example, this is useful when a function doesn't *always* require a lock, making
+`__must_hold()` inappropriate.
+
+Keywords
+~~~~~~~~
+
+.. kernel-doc:: include/linux/compiler-context-analysis.h
+   :identifiers: context_guard_struct
+                 token_context_guard token_context_guard_instance
+                 __guarded_by __pt_guarded_by
+                 __must_hold
+                 __must_not_hold
+                 __acquires
+                 __cond_acquires
+                 __releases
+                 __must_hold_shared
+                 __acquires_shared
+                 __cond_acquires_shared
+                 __releases_shared
+                 __acquire
+                 __release
+                 __cond_lock
+                 __acquire_shared
+                 __release_shared
+                 __cond_lock_shared
+                 __acquire_ret
+                 __acquire_shared_ret
+                 context_unsafe
+                 __context_unsafe
+                 disable_context_analysis enable_context_analysis
+
+.. note::
+   The function attribute `__no_context_analysis` is reserved for internal
+   implementation of context guard types, and should be avoided in normal code.
+
+Background
+----------
+
+Clang originally called the feature `Thread Safety Analysis
+<https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_, with some keywords
+and documentation still using the thread-safety-analysis-only terminology. This
+was later changed and the feature became more flexible, gaining the ability to
+define custom "capabilities". Its foundations can be found in `Capability
+Systems <https://www.cs.cornell.edu/talc/papers/capabilities.pdf>`_, used to
+specify the permissibility of operations to depend on some "capability" being
+held (or not held).
+
+Because the feature is not just able to express capabilities related to
+synchronization primitives, and "capability" is already overloaded in the
+kernel, the naming chosen for the kernel departs from Clang's initial "Thread
+Safety" and "capability" nomenclature; we refer to the feature as "Context
+Analysis" to avoid confusion. The internal implementation still makes
+references to Clang's terminology in a few places, such as `-Wthread-safety`
+being the warning option that also still appears in diagnostic messages.
diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
index 4b8425e348ab..d864b3da4cc7 100644
--- a/Documentation/dev-tools/index.rst
+++ b/Documentation/dev-tools/index.rst
@@ -21,6 +21,7 @@ Documentation/process/debugging/index.rst
    checkpatch
    clang-format
    coccinelle
+   context-analysis
    sparse
    kcov
    gcov
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120145835.3833031-6-elver%40google.com.
