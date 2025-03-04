Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOEOTO7AMGQEJ7RH7SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E546A4D81A
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:19 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-43bcddbe698sf1248725e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080378; cv=pass;
        d=google.com; s=arc-20240605;
        b=XZNB539g45W6HF7jYTI+RgIqHDktnbbBsXeCwdcPKgrCPZU8rV5FeEGn9cdSRdgERP
         WdL7QFNkEqNoZ8HpjcI7xigg/qB2k6oCIdBC3CCTKApT1aqfOYLJrKL4toXK/7gEYqRL
         GpPOkuRcrkeAH3mt/3vYTN4f7nsg615SfWqzk5shynd0jMmfwCnKw/SgKs/3R3bDbFsO
         9T76ZxReVbmzih3yF0qSwLRGigCx7inPaJwdScpLGpCe2guMuYX2l93gxy7hNxzspeQ9
         gOkX9oNJaV0yHlk4W07aVyMKb3uxn4cgKSNtfCBj/Swog3DiteXFBiW9caO3VDtjpB/L
         IXLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=g400RcqqyPASf9p8bI5NdatcjwCZULKJMhpMP6BcMcY=;
        fh=NIoV5R9Cns91DBBkN3AvmhZOc9QjG83/qfdH20WYvdY=;
        b=JHLUcF1AuPSiFheze7bO7s+ZAnO1IWjN3YLkR0/6buKDMYWz4rFh5LQi93Gs7c8O09
         jcc8ZXNHr0b4QsCafIBPlQuoTKtup4hB4TjjVuvOlIopqO/adtqt1E6G1nPAfQVZugii
         JMzatuj+IxHbfujz6SE0Xd3ed8jhBG5Lc9dJJq27taGVa4toXZojZdUdLS5xfqWmw+q/
         IDHBARHIKyxPUxG1EA4rkbCRR/Z9g8YqvM+i2JRXGt/7rIERoKy/VEyKry2/T9Q+GOzz
         /Qn9HfGUm8TzaFdiquYBPkSTrXG/XABAoLedhS12QLE4fMrDTuYxjvvdZgOkxOIVR9gN
         cZFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QkUAtDxy;
       spf=pass (google.com: domain of 3nsfgzwukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3NsfGZwUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080378; x=1741685178; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=g400RcqqyPASf9p8bI5NdatcjwCZULKJMhpMP6BcMcY=;
        b=WxolKa95g0FGS72MuYdNcMoX2H/m7FOhKpCfzWxT0/f7zZ9M3X+p0+nGaM0dBoLC6U
         cUiPe5RTswkolb9s8HgmSSf/ierQTe8BRt71g51EsgNfEXbagQfDYGvNDFRMz64qnlgH
         Za1mKFGl0k2cNO7QoucabD+nLRzPp88NCxXgUnKlhW+7aOTvzpMLsJg++7/kppjGloam
         OoFZPJ3a3ClCP2s+PxNvdebXS9dkB/nQ7i6xziucJp7u6Vx5bvQBHfjSlSTiu93DOaB4
         ZzY7gnX8OwaUfMY/Cn6qxFq5UwPJApUm9GTHSTNe+gR2uodbNV4PJA43xPUQZm+Ihmyk
         Lwug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080378; x=1741685178;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g400RcqqyPASf9p8bI5NdatcjwCZULKJMhpMP6BcMcY=;
        b=teS+VcUO3/GUxxubowoIWjhv11pLwGXyc4khu18kDMSHfkzp9g9BkCYyF8h4vOxXXC
         gJRoEyrxod1f2Kau8tDpdmmS9lPVpoAxvh5PC5dLOTANMwcjD4pPFzmP8nAvb6Byq4ah
         M3uSRwucIFvY/WmYPFitMW2tOxFoFjmc6q9EKzL5WydKpgTTXIIP/zHhf7+/6e/AQD+p
         Lz4rc3J+BUoI8WXloqHiGeDklVNikcqRYk/Oe1zRoNwMGNwKrWOVEVDBDeaO6QgY0oEV
         QLaNf3/BfrSPdC67eYsO0aw8fwE7lOcSdOQuCl/YKgdvmpj0GnIGJEtrtgzpzv3FI7pz
         AVeA==
X-Forwarded-Encrypted: i=2; AJvYcCV+/DMUqeSL3pqYAr9p/2HtrRB5u89TrfoSaqSosHt81eFMVcJ6YtCtPXdoK5z2UQWLSXj5pQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy75NT/PaM9pu37s7uA4sob7wGPtskTE+Vo96pKQBWgXG6qUQZ1
	ylaMeweDPpWpKV3nLZMLuI2CymXV61F41W3hNyxZBo9K6rTMPiOp
X-Google-Smtp-Source: AGHT+IHd2Oju8zlOKBxjAL6qPvv+fk1BJYSqUj0FgLX2rshKZf5TpCIxPLMSCxfwxIpYy7PvfZJS3g==
X-Received: by 2002:a05:600c:1384:b0:439:9192:f088 with SMTP id 5b1f17b1804b1-43ba66e6f80mr136430685e9.8.1741080377186;
        Tue, 04 Mar 2025 01:26:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG90/2BfO9qgfOpyNowbHECae+gFp/r1RL5BhRXLmuRDw==
Received: by 2002:a05:600c:1c2a:b0:43b:c82b:4337 with SMTP id
 5b1f17b1804b1-43bc82b4435ls7021365e9.0.-pod-prod-01-eu; Tue, 04 Mar 2025
 01:26:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWirKpjNu/tCRUNYedeDd6Qj+9SvDSCiwXMRQSUngAxUiO0es4Fuq1EpinWstz0GGFrdKGXens9cUw=@googlegroups.com
X-Received: by 2002:a05:600c:4f86:b0:43b:ca39:6c75 with SMTP id 5b1f17b1804b1-43bca3972d7mr31402285e9.16.1741080374783;
        Tue, 04 Mar 2025 01:26:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080374; cv=none;
        d=google.com; s=arc-20240605;
        b=SUC5nLnupp6RxgIP/ktqGhlsptMsxLzZJRP0zM9REXtmB00c4XIqD1s1woE5bCrj4h
         A/Dw1EdHMtyraKl+g4I5rg/OSsTDiXzoExGJTYRctx9sFPLWMKw+Bh6VglhVHb4r7viu
         2sMBZRzxgJOI+xhxBlIevUlPwnnqyW2JTucJyJuhbqgA+cMehNYIKbkAG9/7e5sC9Qa0
         W3P5UdfXPnI2XbHPCXyAh5AsWaRfY5FST74eF4Vb9xk+yOP/VThjeE7FH8ywTHEuz1TV
         jri4sc5+cDcENdkBCXgWcJ6A54OLECARAyugRowvUy+c1J81j2vPZWU2mh/7+7zukRtL
         7cuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=lSVagzG7gv+v/g8zzR4ILNSARzsQANzMJVGDI4EywE8=;
        fh=0ZCm+pClwqn4F1ua8vio3ArsaI4xGhZ7+BlhiXoCCeE=;
        b=TBapm0Uy6Jd8djDVWHPSDJxckdC+hC60r9QcKue7naji8P8B00P5EPi/C2yoeji6uL
         5A1Jflx8Rja0RHVgRMNO4h4tEN56PGm/bVJWOlXTSgre+XNfi8MX48FgQmw2qR0WDCCI
         h8dpNLsmXyesP6qIUNzi0SApM5h1ryiAr/vsCIsJjSpF7cz6hGuK5jk46I3JgKVBED6n
         xwVxRaevt0uwWTGLripnJZLdo3S51WgoPWZYsx7RHztQskuOE2PHEr9wBZEb4KsX0TqH
         ZfzEgxE7zTP8MNBaCfuhMNv3hJQZ2gwdh/9DtttZiZ71ecHBeOe8MZfD4f2JG/e7xVAq
         gdOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QkUAtDxy;
       spf=pass (google.com: domain of 3nsfgzwukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3NsfGZwUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bcc139b49si809165e9.1.2025.03.04.01.26.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nsfgzwukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ac0f1651227so126952366b.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWFFGpGXMhYPhlitiFdtrDijzoLTpvDqJ0D3+n+5mPVOCQmkf0AS+6t+wjmB/IdwtCKIDIiEuIbKXs=@googlegroups.com
X-Received: from ejcvb9.prod.google.com ([2002:a17:907:d049:b0:ac1:f9fe:d27b])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:906:880e:b0:abf:4521:eb2a
 with SMTP id a640c23a62f3a-abf4521edabmr1374674266b.49.1741080374222; Tue, 04
 Mar 2025 01:26:14 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:23 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-25-elver@google.com>
Subject: [PATCH v2 24/34] compiler-capability-analysis: Introduce header suppressions
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
 header.i=@google.com header.s=20230601 header.b=QkUAtDxy;       spf=pass
 (google.com: domain of 3nsfgzwukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3NsfGZwUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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

While we can opt in individual subsystems which add the required
annotations, such subsystems inevitably include headers from other
subsystems which may not yet have the right annotations, which then
result in false positive warnings.

Making compatible by adding annotations across all common headers
currently requires an excessive number of __no_capability_analysis
annotations, or carefully analyzing non-trivial cases to add the correct
annotations. While this is desirable long-term, providing an incremental
path causes less churn and headaches for maintainers not yet interested
in dealing with such warnings.

Rather than clutter headers unnecessary and mandate all subsystem
maintainers to keep their headers working with capability analysis,
suppress all -Wthread-safety warnings in headers. Explicitly opt in
headers with capability-enabled primitives.

This bumps the required Clang version to version 20+.

With this in place, we can start enabling the analysis on more complex
subsystems in subsequent changes.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../dev-tools/capability-analysis.rst         |  2 ++
 lib/Kconfig.debug                             |  4 ++-
 scripts/Makefile.capability-analysis          |  4 +++
 scripts/capability-analysis-suppression.txt   | 32 +++++++++++++++++++
 4 files changed, 41 insertions(+), 1 deletion(-)
 create mode 100644 scripts/capability-analysis-suppression.txt

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index d11e88ab9882..5c87d7659995 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -17,6 +17,8 @@ features. To enable for Clang, configure the kernel with::
 
     CONFIG_WARN_CAPABILITY_ANALYSIS=y
 
+The feature requires Clang 20 or later.
+
 The analysis is *opt-in by default*, and requires declaring which modules and
 subsystems should be analyzed in the respective `Makefile`::
 
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 8abaf7dab3f8..8b13353517a9 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -605,7 +605,7 @@ config DEBUG_FORCE_WEAK_PER_CPU
 
 config WARN_CAPABILITY_ANALYSIS
 	bool "Compiler capability-analysis warnings"
-	depends on CC_IS_CLANG && $(cc-option,-Wthread-safety -fexperimental-late-parse-attributes)
+	depends on CC_IS_CLANG && $(cc-option,-Wthread-safety -fexperimental-late-parse-attributes --warning-suppression-mappings=/dev/null)
 	# Branch profiling re-defines "if", which messes with the compiler's
 	# ability to analyze __cond_acquires(..), resulting in false positives.
 	depends on !TRACE_BRANCH_PROFILING
@@ -619,6 +619,8 @@ config WARN_CAPABILITY_ANALYSIS
 	  the original name of the feature; it was later expanded to be a
 	  generic "Capability Analysis" framework.
 
+	  Requires Clang 20 or later.
+
 	  Produces warnings by default. Select CONFIG_WERROR if you wish to
 	  turn these warnings into errors.
 
diff --git a/scripts/Makefile.capability-analysis b/scripts/Makefile.capability-analysis
index b7b36cca47f4..2a3e493a9d06 100644
--- a/scripts/Makefile.capability-analysis
+++ b/scripts/Makefile.capability-analysis
@@ -4,4 +4,8 @@ capability-analysis-cflags := -DWARN_CAPABILITY_ANALYSIS	\
 	-fexperimental-late-parse-attributes -Wthread-safety	\
 	$(call cc-option,-Wthread-safety-pointer)
 
+ifndef CONFIG_WARN_CAPABILITY_ANALYSIS_ALL
+capability-analysis-cflags += --warning-suppression-mappings=$(srctree)/scripts/capability-analysis-suppression.txt
+endif
+
 export CFLAGS_CAPABILITY_ANALYSIS := $(capability-analysis-cflags)
diff --git a/scripts/capability-analysis-suppression.txt b/scripts/capability-analysis-suppression.txt
new file mode 100644
index 000000000000..0a5392fee710
--- /dev/null
+++ b/scripts/capability-analysis-suppression.txt
@@ -0,0 +1,32 @@
+# SPDX-License-Identifier: GPL-2.0
+#
+# The suppressions file should only match common paths such as header files.
+# For individual subsytems use Makefile directive CAPABILITY_ANALYSIS := [yn].
+#
+# The suppressions are ignored when CONFIG_WARN_CAPABILITY_ANALYSIS_ALL is
+# selected.
+
+[thread-safety]
+src:*arch/*/include/*
+src:*include/acpi/*
+src:*include/asm-generic/*
+src:*include/linux/*
+src:*include/net/*
+
+# Opt-in headers:
+src:*include/linux/bit_spinlock.h=emit
+src:*include/linux/cleanup.h=emit
+src:*include/linux/kref.h=emit
+src:*include/linux/list*.h=emit
+src:*include/linux/local_lock*.h=emit
+src:*include/linux/lockdep.h=emit
+src:*include/linux/mutex*.h=emit
+src:*include/linux/rcupdate.h=emit
+src:*include/linux/refcount.h=emit
+src:*include/linux/rhashtable.h=emit
+src:*include/linux/rwlock*.h=emit
+src:*include/linux/rwsem.h=emit
+src:*include/linux/seqlock*.h=emit
+src:*include/linux/spinlock*.h=emit
+src:*include/linux/srcu.h=emit
+src:*include/linux/ww_mutex.h=emit
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-25-elver%40google.com.
