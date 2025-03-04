Return-Path: <kasan-dev+bncBC7OBJGL2MHBB54NTO7AMGQE3IU6MSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 85FE9A4D7EE
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:13 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5e067bbd3bcsf8155105a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080313; cv=pass;
        d=google.com; s=arc-20240605;
        b=P4cR82im3ACD03lbQApKkJzSn4pByrivF2mgjMGVNjfgcNZHg2X/xh5NxnwIo5kEW2
         Q72DilWN4p7XHBeYN/TSDLetfDY/Jp8mwgKY9q+KHQUxC6f+BeZZgTqGO8yCsb54vG/+
         YCy58GyH2t0ZYf4qz5dD3ABuDrubFw9Y3EANlFezw3X+bmKmXGRSwhDEUZSfZsw5LNjW
         1TR4cS0k942hdBBEg6oyPDyWuzwe92cSXSfxe9swS4+ofsrf75wcVthOkBWkFYgLwrY+
         7/WMYL2Xh3e6yfss0lSb/EnKXrl+GdFWZuOvvYLJBWqqenJQHMGb7qOHrdiFgWbkhQxc
         fHPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=YhPYE0yuoAwdi/KOAFDQamOe0KYtUBFi79MRQ9xnTvw=;
        fh=FIDXNHQ85LllpXwjrmW+DRtRU2SHdv2cVIy0qTsRXzM=;
        b=MPgmxu2C5XoXESXT3eVBW2rQJeF1h9UZcOl2cMoPV1QXQy3kBsgLadiIiyqOtELNe+
         l7Rh+Xa33kc/V1IeErNMIRoA0DXpomAiqc9r79yVjIa1Jojvw5GgJHvl0VtXhna8TH9D
         weRH8hPZ4/1HfwonPVojOT3g7UEcMCCLVb7Id2YRqKIBdnLzrFwOUeFnEeClVZndxAi3
         /gv4ZCU/oTfdSiy3aRQZDwXFXFvCxuKahmjcRYOIy8lzoQov/kgmOEAa+66RGgm6CS5g
         3ZaHYr6kxJNIk3EiPlNG+Vt0Glv+qXlwrYZP+uM1u8BTW/wm8ryioFmF+FOxkcoLwzwt
         wTFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=R+FZSreQ;
       spf=pass (google.com: domain of 39mbgzwukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=39MbGZwUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080313; x=1741685113; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YhPYE0yuoAwdi/KOAFDQamOe0KYtUBFi79MRQ9xnTvw=;
        b=V9CLIuzljD2mXv58i0XYt7Enkn38fxYYzUmtlixRzAKSZUlt8L1xp+OLrd6GTMpNlo
         s6MNxt1z0c+DGIFcIU3LLum0pm7Uruqmo9TS8zauJHP3gUa5dXcrYRc3mjFGQTc4E3F4
         wjdRnKwResrnecDIDv+CtIhc3acEldruJp9MVfrdBpDFcUyNVspZ9hZt2iGvm8KMORZX
         LIvbT2s//ZW/iGcle1GaV1Vz5n5ra93BNDhp2ZrEnMLODRNlgwAmHdZETNqiYbBtjWkC
         /OVIWg6oGqCbnkhWOChUxROBDeyOjUqgwcQ7x1kYbwTfRiu4KxGhGYVW5joLnGi0rb6P
         mLHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080313; x=1741685113;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YhPYE0yuoAwdi/KOAFDQamOe0KYtUBFi79MRQ9xnTvw=;
        b=p+A1aclAd4a6hdsieZdTk64+SunZo5Tx0+yW1+ZozhxTIETDMGmfNuvFoRzYMlTMnA
         /WKAwt/uy/s9jV3wyP++wF4BZW3hNkQoOIs8xtJj7GMBiy4P2ZpONAUXkGELWPZ7pyMc
         +IlfKnLhuomtYNB45Lm5CA6T6ZngrMzHOHzgiMcIOpn2qFjQQgymERECCRx67b5YPfPB
         tHLr+WWOkxl/+P1knv6QRTCOsgI4wDD3mM9YjN7tGD9Myd+1mXWmHDRyc2LvD5/7DRia
         BJ+XkssNh987Lw4eKk52B5JNChmTxYsiI7Tb6v1rpY7V5uTXqWTnplYpezwXkE4EHxSK
         xdUw==
X-Forwarded-Encrypted: i=2; AJvYcCWan9Kr7K12mYhjqM225T5recuf2m7xQdJRmygRZY+moeVV2EYGv1hwkA7G22W/KQ1VwlFtUw==@lfdr.de
X-Gm-Message-State: AOJu0Yw0baKdRltUUxJJqLBj7alnVrmxVe758oDVjzXlYecoC9LFlzQo
	Q/wsLADlkJLICrhDanOnIDB2cdIVo7OCBs2uUl4zgzUWrfgJfBIV
X-Google-Smtp-Source: AGHT+IEv6M3LmhZDa2SHWQ7W80C+KnacFEu3YhZqvWskNM0zqVeKfYpcRdRIwQjkAxsDrYZggGSvFw==
X-Received: by 2002:a05:6402:26d5:b0:5e0:9f31:a27a with SMTP id 4fb4d7f45d1cf-5e4d6ac9e31mr19855621a12.5.1741080312050;
        Tue, 04 Mar 2025 01:25:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHZLseEI4w6haFD9naW8sjrk4PHHr9CauQdyx26JtRbiQ==
Received: by 2002:a50:9e69:0:b0:5e5:60d2:a01f with SMTP id 4fb4d7f45d1cf-5e560d2a486ls934287a12.1.-pod-prod-06-eu;
 Tue, 04 Mar 2025 01:25:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVBsEvVB5r/2NCcX5VLK0NsVWPXSgOlbDx7qVDuvdG8NVIBL5+I9UzLWqkdvaUnApW9JBngKM2jrjI=@googlegroups.com
X-Received: by 2002:a17:907:3e88:b0:abc:c34:4130 with SMTP id a640c23a62f3a-abf25fdc124mr2079893166b.18.1741080309202;
        Tue, 04 Mar 2025 01:25:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080309; cv=none;
        d=google.com; s=arc-20240605;
        b=de4tLhGCYDm0XEm/lfdzEux5SUCgVmq8ZOq5vsIUCluKbG4P3fnvIs2DHT0xLrr0ph
         XkcX1Ew2fPokyuQptfdy9Dfg/6u4Jx5LnOckekCEEuINH38DcH7vO5arFKMUHf0w2/E7
         jm7Ap+iqvp+cYG5npJcz/dkTUizsJfLF+vKVM6+hhrT32WNmGhxYzPn0h70+5sM0kQqP
         xC+ts2LHqR204tctbjeHRvSrb9HTySkEHobhAZ8bqSIC3I6tQpYjxUeoJOtW5H5mLWd2
         o3V47CtV5EoLn/AWCewT2QmSQSqGRhFwPhJY2ieOyzMqczWoYFQvbNBS74m8lNHOWy3R
         pxmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=QdCpZ4aObsNxM+hepokqGHyX6wVByWNLfhfuOJ8rUU0=;
        fh=/QbslfFNjw5lov3Nd8VPiGRrW7TW9mb7Srnw0NTaJfo=;
        b=kZzR3asDCZ0iNJOX/IFJOubBBVMtl9u2mHGjtyJs/QHpQCadyFaiCHTkqbvWEoyRvS
         BehB3vKQoIXbrlrdcgGOQwTvfSBvfeKh7yCZ63YW0xN8jQAeSaEio8G2pAmbbS7/kr0k
         Wo0hdcN3KqexxbCWmryOSKH0u+q9Y03fvKOcas4W03jO7iCIIkv+afNyJK4XtuVuwpZ6
         iWnXngUug7W0iyN2ascpwUPOU++xjsrTI9xI/8iltdc9yH6JHZgSYkVtVzZ8J/+PfjyO
         L369/HVDRp+rfJtsYwgbO2LFRhv/MTSnx8ftHBUZUBxp1GO1xwteIL4S8PrMiAWorS3u
         jLWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=R+FZSreQ;
       spf=pass (google.com: domain of 39mbgzwukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=39MbGZwUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-abf0c0dd5a8si46875666b.1.2025.03.04.01.25.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 39mbgzwukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-abf48e1e70eso288283266b.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:09 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUg56IhOxMSpsiEWaySd4Nao1nh5kGtm/eucYSOrmM04QsaOX6266+GG3X0nTcYG/SE2/hvRBy7aRs=@googlegroups.com
X-Received: from edbij6.prod.google.com ([2002:a05:6402:1586:b0:5de:45f9:8813])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:3faa:b0:abf:71b9:4e38
 with SMTP id a640c23a62f3a-abf71b9511emr887914766b.45.1741080308740; Tue, 04
 Mar 2025 01:25:08 -0800 (PST)
Date: Tue,  4 Mar 2025 10:20:59 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-1-elver@google.com>
Subject: [PATCH v2 00/34] Compiler-Based Capability- and Locking-Analysis
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
 header.i=@google.com header.s=20230601 header.b=R+FZSreQ;       spf=pass
 (google.com: domain of 39mbgzwukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=39MbGZwUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
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

	* mm/kfence
	* kernel/kcov
	* lib/stackdepot
	* lib/rhashtable
    	* drivers/tty
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

A Clang version that supports `-Wthread-safety-pointer` is recommended,
but not a strong dependency:

	https://github.com/llvm/llvm-project/commit/de10e44b6fe7f3d3cfde3afd8e1222d251172ade

This series is also available at this Git tree:

	https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=cap-analysis/dev

=== Changelog ===

v2:

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

Marco Elver (34):
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
  kfence: Enable capability analysis
  kcov: Enable capability analysis
  stackdepot: Enable capability analysis
  rhashtable: Enable capability analysis
  printk: Move locking annotation to printk.c
  drivers/tty: Enable capability analysis for core files
  security/tomoyo: Enable capability analysis
  crypto: Enable capability analysis
  MAINTAINERS: Add entry for Capability Analysis

 .../dev-tools/capability-analysis.rst         | 148 +++++
 Documentation/dev-tools/index.rst             |   1 +
 Documentation/dev-tools/sparse.rst            |  19 -
 Documentation/mm/process_addrs.rst            |   6 +-
 MAINTAINERS                                   |  11 +
 Makefile                                      |   1 +
 crypto/Makefile                               |   2 +
 crypto/algapi.c                               |   2 +
 crypto/api.c                                  |   1 +
 crypto/crypto_engine.c                        |   2 +-
 crypto/drbg.c                                 |   5 +
 crypto/internal.h                             |   2 +-
 crypto/proc.c                                 |   3 +
 crypto/scompress.c                            |   8 +-
 .../net/wireless/intel/iwlwifi/iwl-trans.c    |   4 +-
 .../net/wireless/intel/iwlwifi/iwl-trans.h    |   6 +-
 .../wireless/intel/iwlwifi/pcie/internal.h    |   5 +-
 .../net/wireless/intel/iwlwifi/pcie/trans.c   |   4 +-
 drivers/tty/Makefile                          |   3 +
 drivers/tty/n_tty.c                           |  16 +
 drivers/tty/pty.c                             |   1 +
 drivers/tty/sysrq.c                           |   1 +
 drivers/tty/tty.h                             |   8 +-
 drivers/tty/tty_buffer.c                      |   8 +-
 drivers/tty/tty_io.c                          |  12 +-
 drivers/tty/tty_ioctl.c                       |   2 +-
 drivers/tty/tty_ldisc.c                       |  35 +-
 drivers/tty/tty_ldsem.c                       |   2 +
 drivers/tty/tty_mutex.c                       |   4 +
 drivers/tty/tty_port.c                        |   2 +
 fs/dlm/lock.c                                 |   2 +-
 include/crypto/internal/engine.h              |   2 +-
 include/linux/bit_spinlock.h                  |  24 +-
 include/linux/cleanup.h                       |  18 +-
 include/linux/compiler-capability-analysis.h  | 368 ++++++++++++
 include/linux/compiler.h                      |   2 +
 include/linux/compiler_types.h                |  18 +-
 include/linux/console.h                       |   4 +-
 include/linux/debugfs.h                       |  12 +-
 include/linux/kref.h                          |   2 +
 include/linux/list_bl.h                       |   2 +
 include/linux/local_lock.h                    |  18 +-
 include/linux/local_lock_internal.h           |  43 +-
 include/linux/lockdep.h                       |  12 +-
 include/linux/mm.h                            |  33 +-
 include/linux/mutex.h                         |  29 +-
 include/linux/mutex_types.h                   |   4 +-
 include/linux/rcupdate.h                      |  86 +--
 include/linux/refcount.h                      |   6 +-
 include/linux/rhashtable.h                    |  14 +-
 include/linux/rwlock.h                        |  22 +-
 include/linux/rwlock_api_smp.h                |  43 +-
 include/linux/rwlock_rt.h                     |  44 +-
 include/linux/rwlock_types.h                  |  10 +-
 include/linux/rwsem.h                         |  56 +-
 include/linux/sched/signal.h                  |  14 +-
 include/linux/seqlock.h                       |  24 +
 include/linux/seqlock_types.h                 |   5 +-
 include/linux/spinlock.h                      |  64 +-
 include/linux/spinlock_api_smp.h              |  34 +-
 include/linux/spinlock_api_up.h               | 112 +++-
 include/linux/spinlock_rt.h                   |  37 +-
 include/linux/spinlock_types.h                |  10 +-
 include/linux/spinlock_types_raw.h            |   5 +-
 include/linux/srcu.h                          |  61 +-
 include/linux/tty.h                           |  14 +-
 include/linux/tty_flip.h                      |   4 +-
 include/linux/tty_ldisc.h                     |  19 +-
 include/linux/ww_mutex.h                      |  21 +-
 kernel/Makefile                               |   2 +
 kernel/kcov.c                                 |  36 +-
 kernel/printk/printk.c                        |   2 +
 kernel/signal.c                               |   4 +-
 kernel/time/posix-timers.c                    |  10 +-
 lib/Kconfig.debug                             |  45 ++
 lib/Makefile                                  |   6 +
 lib/dec_and_lock.c                            |   8 +-
 lib/rhashtable.c                              |   5 +-
 lib/stackdepot.c                              |  20 +-
 lib/test_capability-analysis.c                | 548 ++++++++++++++++++
 mm/kfence/Makefile                            |   2 +
 mm/kfence/core.c                              |  20 +-
 mm/kfence/kfence.h                            |  14 +-
 mm/kfence/report.c                            |   4 +-
 mm/memory.c                                   |   4 +-
 mm/pgtable-generic.c                          |  19 +-
 net/ipv4/tcp_sigpool.c                        |   2 +-
 scripts/Makefile.capability-analysis          |  11 +
 scripts/Makefile.lib                          |  10 +
 scripts/capability-analysis-suppression.txt   |  32 +
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
 101 files changed, 2086 insertions(+), 521 deletions(-)
 create mode 100644 Documentation/dev-tools/capability-analysis.rst
 create mode 100644 include/linux/compiler-capability-analysis.h
 create mode 100644 lib/test_capability-analysis.c
 create mode 100644 scripts/Makefile.capability-analysis
 create mode 100644 scripts/capability-analysis-suppression.txt

-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-1-elver%40google.com.
