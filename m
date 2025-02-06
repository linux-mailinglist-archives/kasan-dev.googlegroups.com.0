Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWPZSO6QMGQEAPH3ZRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id E5676A2B04F
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:02 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-4359206e1e4sf10493565e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865882; cv=pass;
        d=google.com; s=arc-20240605;
        b=DxbpogArDEd4E0wp8ftYB5wrP0DtFfY7I2kNU4ih4beKSVTPQpsEGM+KjNoZwm8W/j
         v4co68okX97DA60L72hgePOZ5nHyWjL4nJ4hCMer26po5uug98iJStw4z25fho4YREu9
         NTL9RS9Qyxu3xKPEv8QnIsAEWUMfJJxay4LypqXCOoQZptpt95+jg8/eK6bBa8XfWmwo
         N8PaO0xFhj7B3Or0ospL4d698Z8bPtMqDnx6jwpCPl7c6cggheJNIVmCg2g5Zi3eB81B
         iw+94PWe75MCAUaEezzlUSD+CPjpBigECUWb2a3YdaR/0RIyJR7O/AnjI7k6axWYmmPr
         44vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=U/w4LSZS0Frd6lIiyxDJjyhW6vZTLa1vCeL1fSB0ksI=;
        fh=urC0/mIPixzlLpqJQp/VRhgPc2HJuLM0IZ0hT2vnT+Q=;
        b=AEjXbhYTPNnFUMnj5laUIAUJBHo7uZTlAMgCkD8IsENgf0sFNcJztLeg+4Bs8BWuZh
         b6EBKs7R1nKo1ycgEUCXI7QDTp1ofDxPED5qFo5woNfnUMLqIG/HHcYo7k5xOHicqGdF
         4gXftra8KhpB4YLMvieRxyM3eK1B3C8g+cVh2NiTphikpBtamNZpNplKyeHe8mhJbmv0
         K/D2I/xsI+k0HezGSFfADhz3nA7eO1YEci3p4drN13kxv5Zy67gHir1AA6ePDQpSQUOb
         UfVGGA5vw6OCfYIu6U55iFp4NVczAeBb5AlTRkbjlxUaWzASutfU9FW3Gq+sIBxEzQpY
         lItQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Nj3dzUCO;
       spf=pass (google.com: domain of 31vykzwukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=31vykZwUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865882; x=1739470682; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=U/w4LSZS0Frd6lIiyxDJjyhW6vZTLa1vCeL1fSB0ksI=;
        b=JUifTyfce+0D4LHxtd8km/GBAC4Mc8CzWiShs0K4VMp2kJiH78w/mB1jM0ZYa5Hkjq
         1BieSizo/bEtLHzR4In9pZf/J/yA9GLKTws7iA96jntseASJDAO5PuvLcRWi2pEVdbzL
         /1p9Zsk3g81pT+7nSH9lVLKM/UuOJ41JfSsdbGMPumrrIy8dUfotCikbfoQlMBHM/7iy
         sPGhA6h6OyMaGRZuphn4QbB82P8aVb7ABREWjcneh+hpxoGlHJBxBCe84SXqGdTeg+z6
         2FWNKdLUhxkHevDxE+agp0TQSEmbu8QqRWjzaeQw0K716JQISW3w/lfmkzyjkQnElfg6
         YdFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865882; x=1739470682;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=U/w4LSZS0Frd6lIiyxDJjyhW6vZTLa1vCeL1fSB0ksI=;
        b=D7IAvZpoF9Ff9Y6JO42pfPt1sXwi5i/XVlEkvXkvgp68WbayI2G81lGhFR7f4LhD+A
         k+Uid5o9GWANWgL5igUMGEVm4+Z3WAnl0NcS3gufEd7qWGqbtsSaZvYp40cCsnlhXAK9
         J8mbtBnmtaEFzymv4jo+8WCFoGGPxtS1aOcIz5asX7y6Ex7afpSNlU9UbrCdI9eGsmC/
         LHgOHSDtrnAwh3XeKspvrUGOUwPKUOFz+piZg0KtiZmpxEoVle7iIkBOSmC0CcNPP/8G
         oRd3b8/dfB2tWa+4yHGCkBXRfHjV8YNZu5om+W0zLVS61d9ZjBVPl1v6BDvnvUNscJ/x
         Eo5g==
X-Forwarded-Encrypted: i=2; AJvYcCUyrcwogc4aIUJtyV1MsrduDjslCdUsmVaXPs5liU3EGAVQVbgAaSLvR2HQCiOJxoqx9SR18w==@lfdr.de
X-Gm-Message-State: AOJu0YwPUi5nOBugKW+bvR8feuB66qPM5cUaoE53a9v43u7PaQDLa4zl
	Pm8Wzgp42zI9o6OI6sNwT0mGXumH9ytSz2p89N3pVGcjdZpTNefh
X-Google-Smtp-Source: AGHT+IEmruBEqJABhTrarKC8LJJacd2OHkDgjFCrAMfKpIvoOJLNXemcgGjy0U3vCTft7Xr+Qwg84g==
X-Received: by 2002:a05:600c:1da8:b0:431:5c3d:1700 with SMTP id 5b1f17b1804b1-439249a7534mr4250445e9.21.1738865881963;
        Thu, 06 Feb 2025 10:18:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cd85:0:b0:436:9336:a5f9 with SMTP id 5b1f17b1804b1-43924c3fa80ls355735e9.0.-pod-prod-05-eu;
 Thu, 06 Feb 2025 10:17:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXtkbsnveo29iGpm2LorKGxtNstUqkEcwappVphjqfWHI/UIqWYOwKLDQ3KnlnIGmCqt9A1BM1/t5Y=@googlegroups.com
X-Received: by 2002:a05:600c:138f:b0:434:a734:d279 with SMTP id 5b1f17b1804b1-4392499189fmr6139605e9.16.1738865879145;
        Thu, 06 Feb 2025 10:17:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865879; cv=none;
        d=google.com; s=arc-20240605;
        b=F4prqq8QoK2xOjc08a6R//ZrNXwFAKR6SL62v4RWzrcuvOpWzqIGI8m07rmOStccB8
         atEnzA0gAxBXgyPMDVe8mXmygcRxoUtz6IpxxhTrMzSjU9b4W5/aJ6g5jKgY9re7/EsM
         7rAD7fJr/7hoUhGFxI2qevZv1wLzuFWDXS8YpVmsUesr5LfazmsFjvCMPNk8+sBP7LGB
         US3OpNSuePiIF/+wBaIRGU9MGUpn/8BcH7GMZgnVejGKWH6TAwSUmrA7AfoJM0PvIKIp
         yHn5/JQt52rwyjcDDIMKWZMrnB31iLE6zPjokUJmjppr0NGufqwvEc3jKgdOmak+7f5i
         elqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=3zCXzYYWNA/v8qcQtOcKIh5TmuX7E6oXR0H5ZAQV+vQ=;
        fh=kf/1B3pS5A/MIS5m780WhZ3LwugndMhDLYUQWp4SANc=;
        b=dkm6oC0+IY29xZu6PJ78MjdNyZ8op/Jq2BoSNbi5Xm33kduXir73CX5V31jfWP04dJ
         wBsYwgrPE66NUdTrB8x5hgpcezhplO1AngJYyIXhsloRL2AXB5zv2MUdiHQphr1Wt9k1
         7QT/FuOMHp0rv5QASbKpM0ovn/TbE62Cn+OfUx2hrCR9Mr2RgHi+y2lh4IIays/rAz3V
         oTmzN+Ad8D6zxTKAVBeR0Pl8QW8OP7JNLcpIKc5yYQ0jeXHjXM+LqvOxJM0DBaXv19Dk
         PZKw0CdA4ujM7aLVflkrhb1Gg8duOnyZn9LB7iR4+vMENeluaTsa0j8zFPiF6orjVTTY
         0LIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Nj3dzUCO;
       spf=pass (google.com: domain of 31vykzwukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=31vykZwUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38dbde0e507si51298f8f.4.2025.02.06.10.17.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:17:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 31vykzwukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5dc0de54194so2596216a12.0
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:17:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWr91v3ReMioFr7Vk5o9p++2R8LAr8Nsej4XMJYoRGiIlceob3OUPLEjX2zlK+GBlrWf7hv8XAgnJc=@googlegroups.com
X-Received: from edap10.prod.google.com ([2002:a05:6402:500a:b0:5d8:ab23:4682])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:4404:b0:5dc:abe4:9d8d
 with SMTP id 4fb4d7f45d1cf-5dcecca9427mr4164056a12.9.1738865878495; Thu, 06
 Feb 2025 10:17:58 -0800 (PST)
Date: Thu,  6 Feb 2025 19:09:59 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-6-elver@google.com>
Subject: [PATCH RFC 05/24] Documentation: Add documentation for Compiler-Based
 Capability Analysis
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
 header.i=@google.com header.s=20230601 header.b=Nj3dzUCO;       spf=pass
 (google.com: domain of 31vykzwukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=31vykZwUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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
 .../dev-tools/capability-analysis.rst         | 147 ++++++++++++++++++
 Documentation/dev-tools/index.rst             |   1 +
 Documentation/dev-tools/sparse.rst            |   4 +
 3 files changed, 152 insertions(+)
 create mode 100644 Documentation/dev-tools/capability-analysis.rst

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
new file mode 100644
index 000000000000..2211af90e01b
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
+Independent of the above Clang support, a subset of the analysis is supported
+by :ref:`Sparse <sparse>`, with weaker guarantees (fewer false positives with
+tree-wide analysis, more more false negatives). Compared to Sparse, Clang's
+analysis is more complete.
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
+   Unlike Sparse's context tracking analysis, Clang's analysis explicitly does
+   not infer capabilities acquired or released by inline functions. It requires
+   explicit annotations to (a) assert that it's not a bug if a capability is
+   released or acquired, and (b) to retain consistency between inline and
+   non-inline function declarations.
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
+                 __var_guarded_by __ref_guarded_by
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
+                 __cond_acquire
+                 __acquire_shared
+                 __release_shared
+                 __cond_acquire_shared
+                 capability_unsafe
+                 __no_capability_analysis
+                 disable_capability_analysis enable_capability_analysis
+
+Background
+----------
+
+Clang originally called the feature `Thread Safety Analysis
+<https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_, with some
+terminology still using the thread-safety-analysis-only names. This was later
+changed and the feature become more flexible, gaining the ability to define
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
+being the warning enabled option that also still appears in diagnostic
+messages.
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
diff --git a/Documentation/dev-tools/sparse.rst b/Documentation/dev-tools/sparse.rst
index dc791c8d84d1..8c2077834b6f 100644
--- a/Documentation/dev-tools/sparse.rst
+++ b/Documentation/dev-tools/sparse.rst
@@ -2,6 +2,8 @@
 .. Copyright 2004 Pavel Machek <pavel@ucw.cz>
 .. Copyright 2006 Bob Copeland <me@bobcopeland.com>
 
+.. _sparse:
+
 Sparse
 ======
 
@@ -72,6 +74,8 @@ releasing the lock inside the function in a balanced way, no
 annotation is needed.  The three annotations above are for cases where
 sparse would otherwise report a context imbalance.
 
+Also see :ref:`Compiler-Based Capability Analysis <capability-analysis>`.
+
 Getting sparse
 --------------
 
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-6-elver%40google.com.
