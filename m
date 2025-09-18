Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPVDWDDAMGQESOHUTWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D8B6B84F81
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:05:52 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-45f2a1660fcsf9388275e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:05:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204351; cv=pass;
        d=google.com; s=arc-20240605;
        b=QqWO/aJhVUbYBQtMvz68XLGZyu1WVc2c3Ql4dJtUKUub8t+XQcB47x/LZbdvRY95Lh
         QxY1CetlfkBjG8CIq/yidQiM5oI2xWI1Av1acmHR3tDzmFJOj6i/Yv/fDl4E4DpuccAM
         ZJcDNGhoY4Nj2wC1oPltxknvaeO671PdM58nTUPkRU8KM2UdxtDLrpMzZumhL/W7tyVF
         Z2cBSRHTA0cIYbjm6UfkykTGTBCfjQIBm800L8JQBGNN8mZbnYTUqhhH9hnGqYYCjhxn
         Fgt5bsCJndo1q4dwwEb7gD7VFK6EsGk8cLhWj92yixSDC9fTMugPL7GGNCe0fh1LnrlC
         pqsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=PX2fk3kNQZWrbnojlO3ibeQHwKoaViHHQE4H0y2gS38=;
        fh=/aMR0UKCq1MOTttVwu5hrm/qDSHvZKOYN0gtV5ij6KI=;
        b=UXrT33v0wfAArrJN4DxkfJNjQu6YYPMgrA0p2TEITzaDhpUSO8DH4WS/ef11nc1e9h
         YPu+b4/Yf0rUtmGu3BQwjOEpuVRlBbRDNgYDTJOnQrfdEGweIEkCICTHfuP1c5/v33ux
         MWme+kmrDuMgXwKqwr+LyELkEBK33y9V52abo6WQIFolVbW+dxjnIMm3Yi3bn3w1BC27
         apzjP+SGqJjHfzI14D+7J84ejpXjEVtNnSmuFNj50jl6j28iedR3SWE1D41flk2ZuglW
         HNuMrZWCU6rxIIgju+jRGxKbDWbXAEI4gGIbxh9dm+rOYlQ7PRh7Fx0nU1cuvmJnK/Wn
         UJKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=clAAMd00;
       spf=pass (google.com: domain of 3srhmaaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3sRHMaAUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204351; x=1758809151; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PX2fk3kNQZWrbnojlO3ibeQHwKoaViHHQE4H0y2gS38=;
        b=Fv+NRlZs/6EvB+CfKnyvK440dxc8H3Pd/asA1umLhpuf+3D+o4nT+lKsXRus+LyAZn
         rNX9g17M96PTtCJKnHDTy97dYqYKUIsLUcLiBU6TpgUcyA+3u77mNech9BECxd5DhwmW
         RI1qDdeYxjthoPnQaDhfK7LNVS/Oun01GAMDxehO0xD/8/7NGALbuzhEYX7HEDIPGxXC
         Ql65kpozh7zAd2jtTZtvF21TTlTynIjPmjPLpo4veRKW66NsXhz+xXRx8bofIvlfE3T3
         KlO+KsGT0vFjUQfuBG/ljAGI650dnb8XpBNLpv3dSLv8OnDJbn6PVpnMye3Hjjfs4Sgt
         V+/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204351; x=1758809151;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PX2fk3kNQZWrbnojlO3ibeQHwKoaViHHQE4H0y2gS38=;
        b=mUMjuc0Z9bSZsSt69BHWsaCE163WkSUqEhsT8oZdhnxjT3y1FkDbNhPM2Z2NRhJg+5
         9JJsMjrFpInQmNLJEYR/YDzKrbjrzUontiVihk4W+CFVDshPkSfl0RlgNws1EQCcaVOO
         w4zKMZWlYGyt06d4xeKhcPafUcerm+iwHUfbNh5/dZaqDqFgb9oYgFdGfI6ZnGlN6tX+
         35deCbmL6n3mSouU9yyFvyo4aeoKvoEDRncT4Fzg1GB2S4BQ8BWQGd8KjRm87dxdxQ64
         ICAiJAPPUIMG6E9HqZ0XicfaTN355VZzeW7owUMyNcBjGYpwl36w5jjNlZlAy/W0ZqmO
         usFw==
X-Forwarded-Encrypted: i=2; AJvYcCUuDnH+HVyKTWT5jE1Dqb88gcC9KuDDbkyh4A2cEXdEm5iuUqz+30wcn0j/Sw4SMgcOI9flTQ==@lfdr.de
X-Gm-Message-State: AOJu0YyVHkRyCeQU/urAtNqiCR5ODrDe9hQT/V6t2u/lv8VRGDvbX8KA
	PG2x3ZUTQFO1NWxhAI7qhRFH6gu/VGLqjcSHpHzUAuwaogw6wQWx0cLC
X-Google-Smtp-Source: AGHT+IHfC1wH6yhM21t5zskLihjtnEtjXFtwzsSK3uj8+maxraT8MjSknYPxnnSfb6qYBQhUUYK9SQ==
X-Received: by 2002:a05:600c:450f:b0:45d:d8d6:7fcc with SMTP id 5b1f17b1804b1-46206a2b929mr54675535e9.27.1758204351434;
        Thu, 18 Sep 2025 07:05:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4mBNONBmmTGN7KNKkEiFIDTbH8aYsUNm+Pq55smyGgEA==
Received: by 2002:a05:600c:8b76:b0:459:d42f:7dd5 with SMTP id
 5b1f17b1804b1-4653cefee11ls6338855e9.0.-pod-prod-09-eu; Thu, 18 Sep 2025
 07:05:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVc9SJUq2UfdFwzUY9Odeb9MhjhkTO1o2+QBjFU05iOyZw+cNrQ+QWvBxxEiT5rwI1OATk03A0Fdic=@googlegroups.com
X-Received: by 2002:a05:600c:1d1a:b0:45d:e326:96e7 with SMTP id 5b1f17b1804b1-46206b20d8bmr53724415e9.29.1758204347317;
        Thu, 18 Sep 2025 07:05:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204338; cv=none;
        d=google.com; s=arc-20240605;
        b=MqGyB2NubY/evfzYp36oWy6bjShrJg8eT+bJI5rAbrr/52Yo8iHhHwGfESgHBWVyZC
         5GNhqaPm0FNa9L5tU5UY+BWvTuMxxmblZRLGG5nUKApROiRIdAdWVhQNddNVySaEMASj
         3XoW8yQpQ0XJ73y74CkRt09fj4ZmsMqns+nERddBMGF1Z2KYqgzdHw0hggINbEgdncpO
         niWivE1dI7xdWK1LYTKEpmPqJ0zT7LhgsYjIQttv1+DusP4OuMswQcgZMmzI5qrPvhfp
         sgaTmbb3kpuyAz/B3gEIVjh5KQdbU+ow4gmTNDn+PRbDB5z/8Nc7G3du+qC/LHWQQNKH
         kghQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=bj3A6JwSdDEEkQDBIc6+7Le1EULqvByaO8E+vTXCoDc=;
        fh=2Gnpn2aXwryNUAUnJXJX0VCR+y6f5bG8NtdlXlAu8dg=;
        b=Ep+pXoNJzy+QBZcyCE98813yKYLndquLWo53hSFeqBkkvfSCD9J2p1OHP3BZ94Kd6T
         P3pbQzO0JLBibwcmDNOB8eA2frVwFMrFta6NrcRno9DRWj7b1WT3zkJBYRoDVkUz48n1
         vL/3EA92im92MBuDHC+qIVTOc+5jjf7G1voMLrI2PqTvFpmFnYTAmtj1BRXhpXJC6q3a
         s82N7ldjc24R+RSkwG8DkSKayV9gmSBz7AyRU4PzVQD/m961fYZOqtNMiBYZzW4QOeow
         yUSNrKtTKPBnA7zW44Ssd6REJ1RBo2NDDpCdcmP751HF448Z5AIuPilEsFkPgeTqmqFJ
         zyeg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=clAAMd00;
       spf=pass (google.com: domain of 3srhmaaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3sRHMaAUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3edff885cf2si49992f8f.0.2025.09.18.07.05.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:05:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3srhmaaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-45f2a1660fcso9386515e9.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:05:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWNppq0E1zIMKvKXlFFu6U/nyyh+GbRo8QWPDHVKix1DfMlQaHZWwHqQm4tz0AKV3Rgcm95WqQ/eDw=@googlegroups.com
X-Received: from wrum18.prod.google.com ([2002:a5d:6a12:0:b0:3ee:15bb:3d66])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:adf:b19a:0:b0:3ec:dfe5:17d0
 with SMTP id ffacd0b85a97d-3ecdfe51b3emr3102866f8f.9.1758204337306; Thu, 18
 Sep 2025 07:05:37 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:15 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-5-elver@google.com>
Subject: [PATCH v3 04/35] Documentation: Add documentation for Compiler-Based
 Capability Analysis
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
 header.i=@google.com header.s=20230601 header.b=clAAMd00;       spf=pass
 (google.com: domain of 3srhmaaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3sRHMaAUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
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

Adds documentation in Documentation/dev-tools/capability-analysis.rst,
and adds it to the index and cross-references from Sparse's document.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Remove cross-reference to Sparse, since we plan to remove Sparse
  support anyway.
* Mention __no_capability_analysis should be avoided.
---
 .../dev-tools/capability-analysis.rst         | 147 ++++++++++++++++++
 Documentation/dev-tools/index.rst             |   1 +
 2 files changed, 148 insertions(+)
 create mode 100644 Documentation/dev-tools/capability-analysis.rst

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
new file mode 100644
index 000000000000..1287f792f6cd
--- /dev/null
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -0,0 +1,147 @@
+.. SPDX-License-Identifier: GPL-2.0
+.. Copyright (C) 2025, Google LLC.
+
+.. _capability-analysis:
+
+Compiler-Based Capability Analysis
+==================================
+
+Capability analysis is a C language extension, which enables statically
+checking that user-definable "capabilities" are acquired and released where
+required. An obvious application is lock-safety checking for the kernel's
+various synchronization primitives (each of which represents a "capability"),
+and checking that locking rules are not violated.
+
+The Clang compiler currently supports the full set of capability analysis
+features. To enable for Clang, configure the kernel with::
+
+    CONFIG_WARN_CAPABILITY_ANALYSIS=y
+
+The feature requires Clang 22 or later.
+
+The analysis is *opt-in by default*, and requires declaring which modules and
+subsystems should be analyzed in the respective `Makefile`::
+
+    CAPABILITY_ANALYSIS_mymodule.o := y
+
+Or for all translation units in the directory::
+
+    CAPABILITY_ANALYSIS := y
+
+It is possible to enable the analysis tree-wide, however, which will result in
+numerous false positive warnings currently and is *not* generally recommended::
+
+    CONFIG_WARN_CAPABILITY_ANALYSIS_ALL=y
+
+Programming Model
+-----------------
+
+The below describes the programming model around using capability-enabled
+types.
+
+.. note::
+   Enabling capability analysis can be seen as enabling a dialect of Linux C with
+   a Capability System. Some valid patterns involving complex control-flow are
+   constrained (such as conditional acquisition and later conditional release
+   in the same function, or returning pointers to capabilities from functions.
+
+Capability analysis is a way to specify permissibility of operations to depend
+on capabilities being held (or not held). Typically we are interested in
+protecting data and code by requiring some capability to be held, for example a
+specific lock. The analysis ensures that the caller cannot perform the
+operation without holding the appropriate capability.
+
+Capabilities are associated with named structs, along with functions that
+operate on capability-enabled struct instances to acquire and release the
+associated capability.
+
+Capabilities can be held either exclusively or shared. This mechanism allows
+assign more precise privileges when holding a capability, typically to
+distinguish where a thread may only read (shared) or also write (exclusive) to
+guarded data.
+
+The set of capabilities that are actually held by a given thread at a given
+point in program execution is a run-time concept. The static analysis works by
+calculating an approximation of that set, called the capability environment.
+The capability environment is calculated for every program point, and describes
+the set of capabilities that are statically known to be held, or not held, at
+that particular point. This environment is a conservative approximation of the
+full set of capabilities that will actually held by a thread at run-time.
+
+More details are also documented `here
+<https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_.
+
+.. note::
+   Clang's analysis explicitly does not infer capabilities acquired or released
+   by inline functions. It requires explicit annotations to (a) assert that
+   it's not a bug if a capability is released or acquired, and (b) to retain
+   consistency between inline and non-inline function declarations.
+
+Supported Kernel Primitives
+~~~~~~~~~~~~~~~~~~~~~~~~~~~
+
+.. Currently the following synchronization primitives are supported:
+
+For capabilities with an initialization function (e.g., `spin_lock_init()`),
+calling this function on the capability instance before initializing any
+guarded members or globals prevents the compiler from issuing warnings about
+unguarded initialization.
+
+Lockdep assertions, such as `lockdep_assert_held()`, inform the compiler's
+capability analysis that the associated synchronization primitive is held after
+the assertion. This avoids false positives in complex control-flow scenarios
+and encourages the use of Lockdep where static analysis is limited. For
+example, this is useful when a function doesn't *always* require a lock, making
+`__must_hold()` inappropriate.
+
+Keywords
+~~~~~~~~
+
+.. kernel-doc:: include/linux/compiler-capability-analysis.h
+   :identifiers: struct_with_capability
+                 token_capability token_capability_instance
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
+                 capability_unsafe
+                 __capability_unsafe
+                 disable_capability_analysis enable_capability_analysis
+
+.. note::
+   The function attribute `__no_capability_analysis` is reserved for internal
+   implementation of capability-enabled primitives, and should be avoided in
+   normal code.
+
+Background
+----------
+
+Clang originally called the feature `Thread Safety Analysis
+<https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_, with some
+terminology still using the thread-safety-analysis-only names. This was later
+changed and the feature became more flexible, gaining the ability to define
+custom "capabilities".
+
+Indeed, its foundations can be found in `capability systems
+<https://www.cs.cornell.edu/talc/papers/capabilities.pdf>`_, used to specify
+the permissibility of operations to depend on some capability being held (or
+not held).
+
+Because the feature is not just able to express capabilities related to
+synchronization primitives, the naming chosen for the kernel departs from
+Clang's initial "Thread Safety" nomenclature and refers to the feature as
+"Capability Analysis" to avoid confusion. The implementation still makes
+references to the older terminology in some places, such as `-Wthread-safety`
+being the warning option that also still appears in diagnostic messages.
diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
index 65c54b27a60b..62ac23f797cd 100644
--- a/Documentation/dev-tools/index.rst
+++ b/Documentation/dev-tools/index.rst
@@ -18,6 +18,7 @@ Documentation/process/debugging/index.rst
    :maxdepth: 2
 
    testing-overview
+   capability-analysis
    checkpatch
    clang-format
    coccinelle
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-5-elver%40google.com.
