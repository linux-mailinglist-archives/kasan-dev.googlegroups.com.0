Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTHZSO6QMGQEX2VX7WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 56D1CA2B047
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:17:50 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-38dc88ed7casf13004f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:17:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865870; cv=pass;
        d=google.com; s=arc-20240605;
        b=We/2NFQLY7nnK8H+0kiIWX5Qf0MmKdgFvy7AsDCecfzSB3OItn6PI8QQsVC/+Muc2y
         +vRyb4hNPRpJlxgVXuLHZ+/XfRK57oF/FdpQHUAZf3GVM4KvLrzld7tZIXjeMa5BkfVl
         zftfAdKhZHBR5m+b03ZWKq3J5v/HTxPRSCVICiq73AcKkCf4QZgZ0I0qZBY0rxcGlDt/
         OE3Hl7/IS7gGupZTVU/sDY/h96G28Wnop30GOq4VVv3Zy8iLeUCkGWI4UrwgwoYHRlkY
         NramKa7NY58amWhQP8fgWN/J21W/LEi8mUSzBqgSPx6mz9FV7pLPvno8JdHvCb3tqN+K
         k/tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=CpnrKseW5Z9GCYhZLfE4LXcPyKvsMEvq+RTQ6COz9dc=;
        fh=ceZoc8lGz0J/fjH79/bibs7JjWo3pve3l6sBXTyNgdQ=;
        b=ju882UDDJIMXrUgFSNn+Yc1CMfwiokt3mlPpXIgcAArwpmTkE5bCXEsP5Q6BHOb7TS
         6NxsEHoMrbclwEDqnV4WwRo6OfM3aAF2uKWwloPNg8XDkYid3BjpB1fXVyU11l+QkIlT
         meaYbFjV4Mm//7vxqnHmPhJqBNazM6kUlfQxD+0s4v/BLlVEPpXJzysCWeqWBCWYMoj9
         pZJhOxAg2AkrqTOvY/ouSHQw6Ev5PcPQc12KFibEIqoH9gJpgrfwctAJ84OpgbyIq6rs
         US4bOYHxFtZ60KHpNEeEg/UmrHHQk55aawUXVBLZXAcf4CvKLAMpyr4yKZ+0E04cpwTk
         LgCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aU7+j2JU;
       spf=pass (google.com: domain of 3yfykzwukczo8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yfykZwUKCZo8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865870; x=1739470670; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CpnrKseW5Z9GCYhZLfE4LXcPyKvsMEvq+RTQ6COz9dc=;
        b=rz1wiNOX5+xcpGLgED64KtITO+ku9Rv37Cdf3dA92yM8dXjjvMqIzia06z+n/xshUp
         n24zwgRPdf/l1MHdi1NCE+EODkW9IOEvPEDN3D9BMF0IPoiPR3e/WYLSS9lXy7gOfuhK
         kzNBkWE++wbP1QgRSdoNqh6SdaGFKTWlF1+gKviEp6Y332IVRyEvewApo13n0a2PIFtN
         dFtuRCiRGajIgUI7C4+kN2kJ35hGLZtVFCnH9/vJkmGaqkpX0lpmcvD9hJYtlCOa1P3i
         kjCNGUPbl49K/PL9I5Meua7caQAmYrrBhNpFJUyBj6VyHKTr1Lr1S9ZxG/kP0IOESoRh
         vIPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865870; x=1739470670;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CpnrKseW5Z9GCYhZLfE4LXcPyKvsMEvq+RTQ6COz9dc=;
        b=maYkx1Z5LG9uA/XtCvUY1Qs35WRc2wJmVmWwGfAUK9Ez7PjbFrcOaHFer63cs7Kzti
         n6Rt36pGjWIDPz2Up6WIKQv2NA5DscYwfYbPdc6Z6SpnBXJXh06t9BFaPO/yebHATwHP
         Yxekj/bTesc8nrU3uPXj4+8uO4aRheBjdajLBdHJM9sHNcXTl79oXzzLA1RSrHBdyb0Y
         k2Wm78OLMlRP//kRCII6Oi4fnmOU4mG+ys849O1ORQLKmj+RKsdQffm4+Sq/aSCs8SeS
         YBBEu6J2K1+mW/FY0nxOIDS6gVwFcht9/OjxfIkGQ3BoEGmP3MSiMADV8QMkVNu5dWoP
         U52Q==
X-Forwarded-Encrypted: i=2; AJvYcCVD0i697vi4HwzNjr0KoTLars78aFI3CIor87NsLCOwrg5Cb8eIt3eLx3tuqZoLbwaoCLgvTA==@lfdr.de
X-Gm-Message-State: AOJu0Yw9qIzB+6wzz/ZwI+GXQK8dAE6t9KdPebanKAFQspr9DErQhvaB
	iCNReyylKCnowZEnrut7EBB1CN7lJjjF5rfzKwaYrWK+quvHGfr1
X-Google-Smtp-Source: AGHT+IFJk+pYzlUiVvbf8pu5wOLk932tN8WaB7txCjK9/PV/bcpra5qDFCCelEE1hEx2NYuOmCURnw==
X-Received: by 2002:a5d:5f55:0:b0:38d:b2e4:6d97 with SMTP id ffacd0b85a97d-38db493efb2mr6960101f8f.41.1738865868519;
        Thu, 06 Feb 2025 10:17:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4e0d:b0:434:a968:899c with SMTP id
 5b1f17b1804b1-439246aadffls1079815e9.2.-pod-prod-07-eu; Thu, 06 Feb 2025
 10:17:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVP8/QinA4Jxx2qRemJxtjFlszSsajht1vj8V8LfJKyUchFVaoTh2W8Ge4lk3/LEx6Afcjf/vJ35eU=@googlegroups.com
X-Received: by 2002:a05:600c:4e44:b0:436:9227:915 with SMTP id 5b1f17b1804b1-4392498796dmr3771295e9.9.1738865865989;
        Thu, 06 Feb 2025 10:17:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865865; cv=none;
        d=google.com; s=arc-20240605;
        b=fXSJtWpqWAoh0MziyidpokHAhYFeskeenLb0HZt25I6VFN+xLQhR4wIbEn0VvLjXft
         h7g932e8dyZL5v6PPafJ04jMhyB4DsOQG4jvGUBcYV6klcreAWVUEUYs9/i9RpLNV9d3
         6iYodz1V3OXuXVX25GWwb4MF0dRenDp14o65dGiP4AcWfTz0IwAj5bQtuMcx9SRs7yg/
         L4TxG5TR7jT8Zi/QtYnrA08j0hKhyD8kJLFwzk1Na54NoSILXMp3r7kv4cy2JE7NEapY
         qjDfBPwEUuNuQRPQBuZFOxkiK6+Y3Cv9GLNLzoTG5pxAThHBhh7FFvsyuZuK4OpJ6Dci
         iIdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=wjF/wnCzuGEvgHEer/kAKPbsva6fhifSjqXPblr3+7Y=;
        fh=5t091UjdxkMsMVFtW+OFrb2EleLkJ+llLpYFhj+oroI=;
        b=F8xuryG0Zwoo8q3LyH9EWKQdvEx0+8ESe8Jv3Iy5j3/nugEQSZJwwSgq2YWISV2imH
         OwHoo2tJUec5KfP0USQOF4nKBKOFXGoqkIy1BgEt67kU1Izu4wZf802RLmLoIBocBqeJ
         U1Ghz/NDzshOSacQ4+e+2ZY5Iwb3hLIAWeYKCnmVkvtnNI0y0ozvN5LiFTn+oeues0bp
         U+QbHCR2ERnaQWEKxUI89bLt/MtPuk9DibnWZRg7hs18b/eWkBOvK4J3PjrXM5LgswDb
         VLtrh3Q0KNNrIOP5mnd7sU6gNOH7EI7hpI8J3o5ywHOUJjU8JIZy83dTIoPGrs1Re6N1
         2N1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aU7+j2JU;
       spf=pass (google.com: domain of 3yfykzwukczo8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yfykZwUKCZo8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43907f224a1si5584405e9.1.2025.02.06.10.17.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:17:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yfykzwukczo8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-38dbd36c021so528679f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:17:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWy73bmCjZq56ae/vJdmQfU06m25B82nz4ZxZAk7Isd8fJC8klwBEC7ZC+mIlyY6Bbwx9vE0qERty4=@googlegroups.com
X-Received: from wrpc10.prod.google.com ([2002:adf:ef4a:0:b0:38b:ed0c:b648])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a5d:5849:0:b0:38d:b0fe:8c99
 with SMTP id ffacd0b85a97d-38db49101c1mr7178227f8f.48.1738865865616; Thu, 06
 Feb 2025 10:17:45 -0800 (PST)
Date: Thu,  6 Feb 2025 19:09:54 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-1-elver@google.com>
Subject: [PATCH RFC 00/24] Compiler-Based Capability- and Locking-Analysis
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
 header.i=@google.com header.s=20230601 header.b=aU7+j2JU;       spf=pass
 (google.com: domain of 3yfykzwukczo8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yfykZwUKCZo8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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

[ Note: Bart and I had concurrently been working on bringing Clang's
  -Wthread-safety to the kernel:
    https://lore.kernel.org/all/20250206175114.1974171-1-bvanassche@acm.org/
  Having both RFCs out should hopefully provide a good picture on these
  design points and trade-offs - the approaches differ significantly. ]

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

Enabling capability analysis can be seen as enabling a dialect of Linux
C with a Capability System.

Additional details can be found in the added kernel-doc documentation.

=== Development Approach ===

Prior art exists in the form of Sparse's context tracking. Locking
annotations on functions exist, so the concept of analyzing locking rules
is not foreign to the kernel's codebase.

However, Clang's analysis is more complete vs. Sparse's, with the
typical trade-offs in static analysis: improved completeness is
sacrificed for more possible false positives or additional annotations
required by the programmer. Numerous options exist to disable or opt out
certain code from analysis.

This series aims to retain compatibility with Sparse, which can provide
tree-wide analysis of a subset of the capability analysis introduced.
For the most part, the new (and old) keywords used for annotations are
shared between Sparse and Clang.

One big question is how to enable this feature, given we end up with a
new dialect of C - 2 approaches have been considered:


	A. Tree-wide all-or-nothing approach. This approach requires
	   tree-wide changes, adding annotations or selective opt-outs.
	   Making additional primitives capability-enabled increases
	   churn, esp. where maintainers are unaware of the feature's
	   existence and how to use it.

Because we can't change the programming language (even if from one C
dialect to another) of the kernel overnight, a different approach might
cause less friction.

	B. A selective, incremental, and much less intrusive approach.
	   Maintainers of subsystems opt in their modules or directories
	   into "capability analysis" (via Makefile):

	     CAPABILITY_ANALYSIS_foo.o := y	# foo.o only
	     CAPABILITY_ANALYSIS := y  		# all TUs

	   Most (eventually all) synchronization primitives and more
	   capabilities (including ones that could track "irq disabled",
	   "preemption" disabled, etc.) could be supported.

The approach taken by this series if B. This ensures that only
subsystems where maintainers are willing to deal with any warnings one
way or another. Introducing the feature can be done incrementally,
without large tree-wide changes and adding numerous opt-outs and
annotations to the majority of code.

=== Initial Uses ===

With this initial series, the following synchronization primitives are
supported: `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`,
`seqlock_t`, `bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`,
`local_lock_t`.

As an initial proof-of-concept, this series also enables capability
analysis for the following subsystems: kfence, kcov, stackdepot,
rhashtable. (Those subsystems were chosen because I am familiar with
their locking rules; rhashtable was chosen semi-randomly as a test
because it combines a bunch of things: RCU, mutex, bit_spinlock.)

The initial benefits are static detection of violations of locking
rules. As more capabilities are added, we would see more static checking
beyond what regular C can provide, all while remaining easy (read quick)
to use via the Clang compiler.

=== Appendix ===

The following pending Clang patch is recommended, but not a strong
dependency:

	https://github.com/llvm/llvm-project/pull/123063

This series is also available at this Git tree:

	https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=cap-analysis

Marco Elver (24):
  compiler_types: Move lock checking attributes to
    compiler-capability-analysis.h
  compiler-capability-analysis: Rename __cond_lock() to __cond_acquire()
  compiler-capability-analysis: Add infrastructure for Clang's
    capability analysis
  compiler-capability-analysis: Add test stub
  Documentation: Add documentation for Compiler-Based Capability
    Analysis
  checkpatch: Warn about capability_unsafe() without comment
  cleanup: Basic compatibility with capability analysis
  lockdep: Annotate lockdep assertions for capability analysis
  locking/rwlock, spinlock: Support Clang's capability analysis
  compiler-capability-analysis: Change __cond_acquires to take return
    value
  locking/mutex: Support Clang's capability analysis
  locking/seqlock: Support Clang's capability analysis
  bit_spinlock: Include missing <asm/processor.h>
  bit_spinlock: Support Clang's capability analysis
  rcu: Support Clang's capability analysis
  srcu: Support Clang's capability analysis
  kref: Add capability-analysis annotations
  locking/rwsem: Support Clang's capability analysis
  locking/local_lock: Support Clang's capability analysis
  debugfs: Make debugfs_cancellation a capability struct
  kfence: Enable capability analysis
  kcov: Enable capability analysis
  stackdepot: Enable capability analysis
  rhashtable: Enable capability analysis

 .../dev-tools/capability-analysis.rst         | 149 ++++++
 Documentation/dev-tools/index.rst             |   1 +
 Documentation/dev-tools/sparse.rst            |   4 +
 Makefile                                      |   1 +
 .../net/wireless/intel/iwlwifi/iwl-trans.h    |   2 +-
 .../wireless/intel/iwlwifi/pcie/internal.h    |   2 +-
 fs/dlm/lock.c                                 |   2 +-
 include/linux/bit_spinlock.h                  |  24 +-
 include/linux/cleanup.h                       |  18 +-
 include/linux/compiler-capability-analysis.h  | 407 +++++++++++++++
 include/linux/compiler_types.h                |  18 +-
 include/linux/debugfs.h                       |  12 +-
 include/linux/kref.h                          |   2 +
 include/linux/list_bl.h                       |   2 +
 include/linux/local_lock.h                    |  18 +-
 include/linux/local_lock_internal.h           |  41 +-
 include/linux/lockdep.h                       |  12 +-
 include/linux/mm.h                            |   6 +-
 include/linux/mutex.h                         |  29 +-
 include/linux/mutex_types.h                   |   4 +-
 include/linux/rcupdate.h                      |  73 ++-
 include/linux/refcount.h                      |   6 +-
 include/linux/rhashtable.h                    |  14 +-
 include/linux/rwlock.h                        |  27 +-
 include/linux/rwlock_api_smp.h                |  29 +-
 include/linux/rwlock_rt.h                     |  37 +-
 include/linux/rwlock_types.h                  |  10 +-
 include/linux/rwsem.h                         |  56 +-
 include/linux/sched/signal.h                  |   2 +-
 include/linux/seqlock.h                       |  24 +
 include/linux/seqlock_types.h                 |   5 +-
 include/linux/spinlock.h                      |  61 ++-
 include/linux/spinlock_api_smp.h              |  14 +-
 include/linux/spinlock_api_up.h               |  71 +--
 include/linux/spinlock_rt.h                   |  27 +-
 include/linux/spinlock_types.h                |  10 +-
 include/linux/spinlock_types_raw.h            |   5 +-
 include/linux/srcu.h                          |  61 ++-
 kernel/Makefile                               |   2 +
 kernel/kcov.c                                 |  40 +-
 kernel/time/posix-timers.c                    |   2 +-
 lib/Kconfig.debug                             |  43 ++
 lib/Makefile                                  |   6 +
 lib/rhashtable.c                              |  12 +-
 lib/stackdepot.c                              |  24 +-
 lib/test_capability-analysis.c                | 481 ++++++++++++++++++
 mm/kfence/Makefile                            |   2 +
 mm/kfence/core.c                              |  24 +-
 mm/kfence/kfence.h                            |  18 +-
 mm/kfence/kfence_test.c                       |   4 +
 mm/kfence/report.c                            |   8 +-
 net/ipv4/tcp_sigpool.c                        |   2 +-
 scripts/Makefile.capability-analysis          |   5 +
 scripts/Makefile.lib                          |  10 +
 scripts/checkpatch.pl                         |   8 +
 tools/include/linux/compiler_types.h          |   4 +-
 56 files changed, 1682 insertions(+), 299 deletions(-)
 create mode 100644 Documentation/dev-tools/capability-analysis.rst
 create mode 100644 include/linux/compiler-capability-analysis.h
 create mode 100644 lib/test_capability-analysis.c
 create mode 100644 scripts/Makefile.capability-analysis

-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-1-elver%40google.com.
