Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKNDWDDAMGQEXGZHL2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 75227B84F5A
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:05:31 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-45cb612d362sf5694235e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:05:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204331; cv=pass;
        d=google.com; s=arc-20240605;
        b=TM0r//ntRYy9Dy4k4QNG42LcMj+ehgNo4EqcWXYTdnM6M7h+V9LSof3GqugrWp4ykp
         /q+4Z0xv1JdIG5fxqi1HKYC7Jn6R74yp7OMctGmFNLz9p33IRpJAPyCOroLljI6e93Ed
         ObuX3b6PC3FvCpLLWjAZGGLptpXnrgaHyego+pZ4nRzSvNI4TrqZVpELtCVV24cNmNmU
         qk/vu+K5CAkqEsbjAQm+qidOMqdhWd6vEhojsUVLyPMt2ssS00MpcRA6/455KXuhm34I
         gHS8KIzRygP7xHAbvXTEbcsNiPMQrrE44+qXCx9lqLIJFy+69H5MSsWte9jdH8fd9MI0
         5qCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=iF7gvMn6pEcdEOfGZ5NSZvrS4V0ApwlOyM/ZqEUbMWI=;
        fh=TbLHt4xtOgEpuyg84uOrX5bV1jxVVoHGchnG35zdtF8=;
        b=OFNXVZojGskkFETEBSsICEqFGo60EKm009UzHF/pSnE9HWaAIdWA1wfAGCJb6osw2U
         NhADAFvQzJyL5b8a59sQ+1nbVEovMLA7IqzKojYj+ho4RrjaHPAKMfzbEdh27qU7h6VY
         B/gmfZ+6nd8WF2dzzpekNbDYaNCdVq86l1yKrn9pg/4Wg/ER7rwAJJFm6cedUu6AarBz
         AtGmjJoaxEpX//pQqH+nujkoMWdTQ2Vu/QVMw1zgzCUeu0Is3xazFD01ozY52Zc0Pf1G
         cpRSy4pNWISk0nTUgVRrjrhqiOerVmRNteiCzRlCP4Jj76E0QHu1DcOht6gA7mRxs4zC
         hNZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ee0aem4i;
       spf=pass (google.com: domain of 3phhmaaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3phHMaAUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204331; x=1758809131; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iF7gvMn6pEcdEOfGZ5NSZvrS4V0ApwlOyM/ZqEUbMWI=;
        b=wJGuA3uGdW86oirteaj9ieB6HYsnE+6ygila209fgUK19PaVcRqeKm1bp465/Hzp0G
         IqCYY/Pysyn+7bEwQ7GK6s8kDP69zN/od2zX9rPtI1oK9T8Y20kmL+wtoKwx/qmxJDQz
         H19PCFrs1tXaNgPrl2VDcLvJr1vsbSdAeUSoAZGl5mfNvOShoGAijOLkUen9+TrBy2mG
         5nj9UAtLUa/w+w7stPOfuxHyCGpaRQ8cM/GCz23o9JewQzJJpxAiDzQ4TEsyAyS5QuxK
         zHF5KnOSEGVrS6gvTD+5wWAnMrdF47UlTnbe9jXwpicdsbz9CsRWiI9QrljdmN6a03tm
         ABww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204331; x=1758809131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iF7gvMn6pEcdEOfGZ5NSZvrS4V0ApwlOyM/ZqEUbMWI=;
        b=ZsuNlY6fsGPI2UyQ5+jSIov4Ds2MSwhUqKSeX7+EJjiGMzZMnGpmrJt4s2RS9y1ib3
         jG7LMNNDfy188isgtHOSlkVg4OXLopNmDqBH9SrAxNq+0G3e79N5SsXmsru3Pld54PEb
         pLTUeeHWkRJRNdoOxPKoFDfAv5XZjfcsI0Ra9yEoTR/H2fH2priuDKlwK3iX/1MyUK1q
         8rZPyilDSZPxZvz8eIRPHikGiSm9cz8vuf+kKEH8Pzfv/fLr7Zn4Q3nGn9drNAQXZFel
         uUZK/NtSbbsSB9uxGosZoM3RSEE8cdjIhLyTbJvTjFD1vSH6iKCjfpXC2ndl4E6hhxRQ
         LWlA==
X-Forwarded-Encrypted: i=2; AJvYcCWfFLaqPcMcO2NQg8UfYERZBYHw+9ocffeURIBcj45etzprrya0+d2y4x1gKJNjeBqPfDLCOQ==@lfdr.de
X-Gm-Message-State: AOJu0YwiNf62irUt1IIFD05sJeo1/wUzTRwqfk5ux+gMdOUqYsJEVer/
	4biwR3lWXXwWFnU2s+cNVZKIO8pZjfv5mZG5PuH40UWKxtIuQA5ZjOiN
X-Google-Smtp-Source: AGHT+IF8TyPA3cppMZwLyxpo4w3J8Jxv89W6h1H7thTU1FblXY0td96e18mco40Ob+lpHq+1Twj6cA==
X-Received: by 2002:a05:600c:468f:b0:45f:28c9:4261 with SMTP id 5b1f17b1804b1-46205adf781mr56380535e9.20.1758204330291;
        Thu, 18 Sep 2025 07:05:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4V24aP3qK3LW9ovIO+91VQMvN4baSfh0bpof59Kajqaw==
Received: by 2002:a5d:5d0f:0:b0:3da:cb77:e987 with SMTP id ffacd0b85a97d-3ee10310db2ls389013f8f.0.-pod-prod-06-eu;
 Thu, 18 Sep 2025 07:05:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWXj5ulpH79Q1kubMpG4TRf6EpSHzfG8w80H71Oiu/wnbo2IvBLzoiWMYAZtm6+8i2aE0hGYfyDvig=@googlegroups.com
X-Received: by 2002:a05:6000:178e:b0:3ea:124c:8fb7 with SMTP id ffacd0b85a97d-3ecdfa4e102mr5894934f8f.48.1758204327390;
        Thu, 18 Sep 2025 07:05:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204327; cv=none;
        d=google.com; s=arc-20240605;
        b=T9mDVpxBr2opjXDALL/z+eyweEooEObW1Ig8ylGnS7mAYCPyYKQ1FnkGJtB7LRxYVw
         /LhDTopwGmH4W2UpjtQVDeL1gyyQ/M+ip9489I/oLU0+Gzqo4ZdRFOUpwmelfQnDioEo
         nwdHWROTGCzlm7VF5uA+x03C4B5KOjdih3nv2a9ti4FN9uOS2Qy7KOwI3k7oAOAh/ss/
         SOGLNyc7oe1ieB1f/ME05eRQ7XOmWn8a4F2zMix9ztr1rEw+5faRbnMMpXk8q40X6K2u
         y0LQL5B7oev2k58zQleoASKQoTHFqqwV+7AbSzevb1FXLu2awJFPWGOyUTf4Zhm0JN3t
         6WwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=wxDWT9Jhe5/U9R8flrhyT53CUNqFwMWNSIwpcA9ZCHg=;
        fh=BDXSlpXWg+IjA+GmZ7wVo1OaA/mhTIEqYuDaRZc/LBI=;
        b=djRK+N8E89f+ze+9esObhj1FzcAPiBMdlv8d9sqwsytwBU59tmtEbNiqsaHVtLGNXf
         vmtnyLU3oWRo6CvH8Bmu7ijyjkjPP5bWIn6jw4fA/vaJZZB3SrbQiJuSsRURtdMTutgB
         pw0bDIMqzpMqTf+NqyDF2pHvCktfKghdeLLpQKR/xQOWg+fqxY7NV6BN/MofdSH0zVBr
         H3HmqxxKmAeuGDX1gu0q8dl2P+G2rQlkkzhblnY8RP9/y5/Fj33bBm7A2j4UVAkVSiXs
         j+yXzHPi2zliTC4fCAgcCjb69ELdfCREb3RD8y/gCJfKXxiN4bW883hEziiMTap4rzKO
         cmoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ee0aem4i;
       spf=pass (google.com: domain of 3phhmaaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3phHMaAUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ee073f5527si56263f8f.2.2025.09.18.07.05.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:05:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3phhmaaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-45b467f5173so8896955e9.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:05:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUL9YmODdhn/gPffLaV7i9ETPiaOD6e6YTFrKD15k/qIH5QDPDFLt5hHtRJE3bbKP3QhOz21EkDxMY=@googlegroups.com
X-Received: from wrbcc12.prod.google.com ([2002:a5d:5c0c:0:b0:3ec:e0b7:7699])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2483:b0:3cd:ef83:a9a1
 with SMTP id ffacd0b85a97d-3ecdf9c2666mr5663097f8f.20.1758204326802; Thu, 18
 Sep 2025 07:05:26 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:11 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-1-elver@google.com>
Subject: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
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
 header.i=@google.com header.s=20230601 header.b=Ee0aem4i;       spf=pass
 (google.com: domain of 3phhmaaukcucnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3phHMaAUKCUcnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
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
"capability systems" [2], used to specify the permissibility of
operations to depend on some capability being held (or not held).

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
An LWN article covered v2 of the series: https://lwn.net/Articles/1012990/

 [1] https://clang.llvm.org/docs/ThreadSafetyAnalysis.html
 [2] https://www.cs.cornell.edu/talc/papers/capabilities.pdf

=== Development Approach ===

Prior art exists in the form of Sparse's context tracking. Locking
annotations on functions exist, so the concept of analyzing locking rules
is not foreign to the kernel's codebase.

However, Clang's analysis is more complete vs. Sparse's, with the
typical trade-offs in static analysis: improved completeness is
sacrificed for more possible false positives or additional annotations
required by the programmer. Numerous options exist to disable or opt out
certain code from analysis.

This series initially aimed to retain compatibility with Sparse, which
can provide tree-wide analysis of a subset of the capability analysis
introduced, but it was later decided to drop Sparse compatibility. For
the most part, the new (and old) keywords used for annotations remain
the same, and many of the pre-existing annotations remain valid.

One big question is how to enable this feature, given we end up with a
new dialect of C -- 2 approaches have been considered:

  A. Tree-wide all-or-nothing approach. This approach requires tree-wide
     changes, adding annotations or selective opt-outs. Making additional
     primitives capability-enabled increases churn, esp. where maintainers
     are unaware of the feature's existence and how to use it.

Because we can't change the programming language (even if from one C
dialect to another) of the kernel overnight, a different approach might
cause less friction.

  B. A selective, incremental, and much less intrusive approach.
     Maintainers of subsystems opt in their modules or directories into
     "capability analysis" (via Makefile):
  
       CAPABILITY_ANALYSIS_foo.o := y	# foo.o only
       CAPABILITY_ANALYSIS := y  	# all TUs
  
     Most (eventually all) synchronization primitives and more
     capabilities (including ones that could track "irq disabled",
     "preemption" disabled, etc.) could be supported.

The approach taken by this series is B. This ensures that only
subsystems where maintainers are willing to deal with any warnings are
opted-in. Introducing the feature can be done incrementally, without
large tree-wide changes and adding numerous opt-outs and annotations to
the majority of code.

  Note: Bart Van Assche concurrently worked on enabling -Wthread-safety:
  https://lore.kernel.org/all/20250206175114.1974171-1-bvanassche@acm.org/
  Bart's work has shown what it might take to go with approach A
  (tree-wide, restricted to 'mutex' usage). This has shown that the
  analysis finds real issues when applied to enough subsystems!  We hope
  this serves as motivation to eventually enable the analysis in as many
  subsystems as possible, particularly subsystems that are not as easily
  tested by CI systems and test robots.

=== Initial Uses ===

With this initial series, the following synchronization primitives are
supported: `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`,
`seqlock_t`, `bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`,
`local_lock_t`, `ww_mutex`.

To demonstrate use of the feature on real kernel code, the series also
enables capability analysis for the following subsystems:

	* kernel/kcov
	* kernel/kcsan
	* kernel/sched/
	* lib/rhashtable
	* lib/stackdepot
	* mm/kfence
	* security/tomoyo
    	* crypto/

The initial benefits are static detection of violations of locking
rules. As more capabilities are added, we would see more static checking
beyond what regular C can provide, all while remaining easy (read quick)
to use via the Clang compiler.

  Note: The kernel already provides dynamic analysis tools Lockdep and
  KCSAN for lock-safety checking and data-race detection respectively.
  Unlike those, Clang's capability analysis is a compile-time static
  analysis with no runtime impact. The static analysis complements
  existing dynamic analysis tools, as it may catch some issues before
  even getting into a running kernel, but is *not* a replacement for
  whole-kernel testing with the dynamic analysis tools enabled!

=== Appendix ===

A Clang version that supports `-Wthread-safety-pointer` and the new
alias-analysis of capability pointers is required (from this version
onwards):

	https://github.com/llvm/llvm-project/commit/b4c98fcbe1504841203e610c351a3227f36c92a4 [3]

This series is also available at this Git tree:

	https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=cap-analysis/dev

=== Changelog ===

v3:

  - Bump min. Clang version to 22+ (unreleased), which now supports:

	* re-entrancy via __attribute__((reentrant_capability));
	* basic form of capability alias analysis [3] - which is the
	  biggest improvement since v2.

    This was the result of conclusions from this discussion:
    https://lore.kernel.org/all/CANpmjNPquO=W1JAh1FNQb8pMQjgeZAKCPQUAd7qUg=5pjJ6x=Q@mail.gmail.com/

  - Rename __asserts_cap/__assert_cap to __assumes_cap/__assume_cap.

  - Switch to DECLARE_LOCK_GUARD_1_ATTRS().

  - Add __acquire_ret and __acquire_shared_ret helper macros - can be
    used to define function-like macros that return objects which
    contains a held capabilities. Works now because of capability alias
    analysis.

  - Add capability_unsafe_alias() helper, where the analysis rightfully
    points out we're doing strange things with aliases but we don't
    care.

  - Support multi-argument attributes.

  - Enable for kernel/sched/{core,fair}.c, kernel/kcsan.
  - Drop drivers/tty changes (revisit later).

v2: https://lore.kernel.org/all/20250304092417.2873893-1-elver@google.com/

  - Remove Sparse context tracking support - after the introduction of
    Clang support, so that backports can skip removal of Sparse support.

  - Remove __cond_lock() function-like helper.

  - ww_mutex support.

  - -Wthread-safety-addressof was reworked and committed in upstream
    Clang as -Wthread-safety-pointer.

  - Make __cond_acquires() and __cond_acquires_shared() take abstract
    value, since compiler only cares about zero and non-zero.

  - Rename __var_guarded_by to simply __guarded_by. Initially the idea
    was to be explicit about if the variable itself or the pointed-to
    data is guarded, but in the long-term, making this shorter might be
    better.

  - Likewise rename __ref_guarded_by to __pt_guarded_by.

  - Introduce common header warning suppressions - this is a better
    solution than guarding header inclusions with disable_ +
    enable_capability_analysis(). Header suppressions are disabled when
    selecting CONFIG_WARN_CAPABILITY_ANALYSIS_ALL=y. This bumps the
    minimum Clang version required to 20+.

  - Make the data_race() macro imply disabled capability analysis.
    Writing capability_unsafe(data_race(..)) is unnecessarily verbose
    and data_race() on its own already indicates something subtly unsafe
    is happening.  This change was made after analysis of a finding in
    security/tomoyo.

  - Enable analysis in the following subsystems as additional examples
    of larger subsystem. Where it was obvious, the __guarded_by
    attribute was added to lock-guarded variables to improve coverage.

    	* drivers/tty
	* security/tomoyo
    	* crypto/

RFC v1: https://lore.kernel.org/lkml/20250206181711.1902989-1-elver@google.com

Marco Elver (35):
  compiler_types: Move lock checking attributes to
    compiler-capability-analysis.h
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
  locking/local_lock: Include missing headers
  locking/local_lock: Support Clang's capability analysis
  locking/ww_mutex: Support Clang's capability analysis
  debugfs: Make debugfs_cancellation a capability struct
  compiler-capability-analysis: Remove Sparse support
  compiler-capability-analysis: Remove __cond_lock() function-like
    helper
  compiler-capability-analysis: Introduce header suppressions
  compiler: Let data_race() imply disabled capability analysis
  MAINTAINERS: Add entry for Capability Analysis
  kfence: Enable capability analysis
  kcov: Enable capability analysis
  kcsan: Enable capability analysis
  stackdepot: Enable capability analysis
  rhashtable: Enable capability analysis
  printk: Move locking annotation to printk.c
  security/tomoyo: Enable capability analysis
  crypto: Enable capability analysis
  sched: Enable capability analysis for core.c and fair.c

 .../dev-tools/capability-analysis.rst         | 148 +++++
 Documentation/dev-tools/index.rst             |   1 +
 Documentation/dev-tools/sparse.rst            |  19 -
 Documentation/mm/process_addrs.rst            |   6 +-
 MAINTAINERS                                   |  11 +
 Makefile                                      |   1 +
 crypto/Makefile                               |   2 +
 crypto/acompress.c                            |   6 +-
 crypto/algapi.c                               |   2 +
 crypto/api.c                                  |   1 +
 crypto/crypto_engine.c                        |   2 +-
 crypto/drbg.c                                 |   5 +
 crypto/internal.h                             |   2 +-
 crypto/proc.c                                 |   3 +
 crypto/scompress.c                            |  24 +-
 .../net/wireless/intel/iwlwifi/iwl-trans.c    |   4 +-
 .../net/wireless/intel/iwlwifi/iwl-trans.h    |   6 +-
 .../intel/iwlwifi/pcie/gen1_2/internal.h      |   5 +-
 .../intel/iwlwifi/pcie/gen1_2/trans.c         |   4 +-
 fs/dlm/lock.c                                 |   2 +-
 include/crypto/internal/acompress.h           |   7 +-
 include/crypto/internal/engine.h              |   2 +-
 include/linux/bit_spinlock.h                  |  24 +-
 include/linux/cleanup.h                       |  17 +
 include/linux/compiler-capability-analysis.h  | 423 +++++++++++++
 include/linux/compiler.h                      |   2 +
 include/linux/compiler_types.h                |  18 +-
 include/linux/console.h                       |   4 +-
 include/linux/debugfs.h                       |  12 +-
 include/linux/kref.h                          |   2 +
 include/linux/list_bl.h                       |   2 +
 include/linux/local_lock.h                    |  45 +-
 include/linux/local_lock_internal.h           |  73 ++-
 include/linux/lockdep.h                       |  12 +-
 include/linux/mm.h                            |  33 +-
 include/linux/mutex.h                         |  35 +-
 include/linux/mutex_types.h                   |   4 +-
 include/linux/rcupdate.h                      |  86 +--
 include/linux/refcount.h                      |   6 +-
 include/linux/rhashtable.h                    |  14 +-
 include/linux/rwlock.h                        |  22 +-
 include/linux/rwlock_api_smp.h                |  43 +-
 include/linux/rwlock_rt.h                     |  44 +-
 include/linux/rwlock_types.h                  |  10 +-
 include/linux/rwsem.h                         |  66 +-
 include/linux/sched.h                         |   6 +-
 include/linux/sched/signal.h                  |  16 +-
 include/linux/sched/task.h                    |   5 +-
 include/linux/sched/wake_q.h                  |   3 +
 include/linux/seqlock.h                       |  24 +
 include/linux/seqlock_types.h                 |   5 +-
 include/linux/spinlock.h                      |  89 ++-
 include/linux/spinlock_api_smp.h              |  34 +-
 include/linux/spinlock_api_up.h               | 112 +++-
 include/linux/spinlock_rt.h                   |  37 +-
 include/linux/spinlock_types.h                |  10 +-
 include/linux/spinlock_types_raw.h            |   5 +-
 include/linux/srcu.h                          |  60 +-
 include/linux/srcutiny.h                      |   4 +
 include/linux/srcutree.h                      |   6 +-
 include/linux/ww_mutex.h                      |  22 +-
 kernel/Makefile                               |   2 +
 kernel/kcov.c                                 |  36 +-
 kernel/kcsan/Makefile                         |   2 +
 kernel/kcsan/report.c                         |  11 +-
 kernel/printk/printk.c                        |   2 +
 kernel/sched/Makefile                         |   3 +
 kernel/sched/core.c                           |  89 ++-
 kernel/sched/fair.c                           |   9 +-
 kernel/sched/sched.h                          | 110 +++-
 kernel/signal.c                               |   4 +-
 kernel/time/posix-timers.c                    |  13 +-
 lib/Kconfig.debug                             |  45 ++
 lib/Makefile                                  |   6 +
 lib/dec_and_lock.c                            |   8 +-
 lib/rhashtable.c                              |   5 +-
 lib/stackdepot.c                              |  20 +-
 lib/test_capability-analysis.c                | 596 ++++++++++++++++++
 mm/kfence/Makefile                            |   2 +
 mm/kfence/core.c                              |  20 +-
 mm/kfence/kfence.h                            |  14 +-
 mm/kfence/report.c                            |   4 +-
 mm/memory.c                                   |   4 +-
 mm/pgtable-generic.c                          |  19 +-
 net/ipv4/tcp_sigpool.c                        |   2 +-
 scripts/Makefile.capability-analysis          |  11 +
 scripts/Makefile.lib                          |  10 +
 scripts/capability-analysis-suppression.txt   |  33 +
 scripts/checkpatch.pl                         |   8 +
 security/tomoyo/Makefile                      |   2 +
 security/tomoyo/common.c                      |  52 +-
 security/tomoyo/common.h                      |  77 +--
 security/tomoyo/domain.c                      |   1 +
 security/tomoyo/environ.c                     |   1 +
 security/tomoyo/file.c                        |   5 +
 security/tomoyo/gc.c                          |  28 +-
 security/tomoyo/mount.c                       |   2 +
 security/tomoyo/network.c                     |   3 +
 tools/include/linux/compiler_types.h          |   2 -
 99 files changed, 2370 insertions(+), 589 deletions(-)
 create mode 100644 Documentation/dev-tools/capability-analysis.rst
 create mode 100644 include/linux/compiler-capability-analysis.h
 create mode 100644 lib/test_capability-analysis.c
 create mode 100644 scripts/Makefile.capability-analysis
 create mode 100644 scripts/capability-analysis-suppression.txt

-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-1-elver%40google.com.
