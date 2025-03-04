Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAUOTO7AMGQEWNAANZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id CA22DA4D7F6
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:23 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4399d2a1331sf26553365e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080323; cv=pass;
        d=google.com; s=arc-20240605;
        b=XfRy7OBg0kGHJN+Da30vPwDbOiKIZVVRQl3o+oORCIOVUHWhQC8UJF3o4tUA1HyuJR
         wLAkAzs2ohiK6sn8RJX8+VYHUACG9fd2YoccVVXRjmHUAYfRn12AWkP92X9hTK3MOZmF
         zTZ6IT/8iSv59FAYQROplffJtf3vAXU8DEyHR/yYZr3NyDGUe9OkbTRuoaGkw+ET9iDj
         /YUpxcGcl9mbPe8whv68ZnSYk+lx1HEfX1NRlZ1iktc27g+7FxYbsZH9/h8cE5xmrPyj
         6BlsSsSU/jnC0x2Oisf0KlvRJgkzuHwnUQntLMwkRMKRyUiXTXKEvnyf5fv9Ze2/hul6
         2BZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=S6Q53y19BuJg8BAYMV44EVKyUeMmtJRNb9hJbsXSUhM=;
        fh=bGV7fve0SLI62N0mzU6OjZ/Ie6v3XIjOUnZWI8sIgW0=;
        b=e/o+NCCS3ZwHMDQNnCXP2nrL5DVYmu5YO12lqfjrOXWCdFAhjhHHaStlh6sDlSlLX4
         OHJvdcsci349Elo0ae0mWYGJAmrIEE52VScyfyXS6bH9daqqOzMV5bjO429Bea0V8Xyl
         twYu9C6UVo7nrVdEmIHB/FufWgG6xAsWhRdjzV3RNVWwqdYS+eiH/wLlLEtzN+iwkyNa
         7O8+l2UYFFzMZj0qYBtqAavlrGCqSaZofo0OWOLYxKFnxBToHnd5GcjJxxrMbWYMTyv1
         fE4RQ1gzfu0wigeTBOmEPNGuTbshQsXGx07XzhMsVjm2pbzByVS6zmltJQHDm3abLiFU
         WsmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="kN+/8ei7";
       spf=pass (google.com: domain of 3_8bgzwukcewszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3_8bGZwUKCewSZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080323; x=1741685123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=S6Q53y19BuJg8BAYMV44EVKyUeMmtJRNb9hJbsXSUhM=;
        b=oKZgd/AZlNumWMSD7XaqThKgpckttpSYT/bV/caNceWWJCbhrgy8YkUwwzNYBQ4cQ4
         QoXCPD5Fe59JNtee2J3h/tDpCgO7z4yIgflTqaVTDf05xNd5ikf13KTzWvKjNkLEHwq1
         jBeX/MwBWajbLK1Ybm/X+MvC/x1H49EH4XxEX/QXx/fsySLeRVQ2O25AbHZ2Ff5kcQYJ
         x6W9b007cB9r1/EYek+xfSvFEdDPrXSMJsSrt7aqXxChyxqCQyW66V58EIxY1ItBTjPK
         nTErtU9/qgCC/Zz+iLfDJVQ3lD7bXt7bBW5DvTcEnTbLhFxeIv7FnUyJ4sSby5BXsHYu
         gXsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080323; x=1741685123;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S6Q53y19BuJg8BAYMV44EVKyUeMmtJRNb9hJbsXSUhM=;
        b=cRp4qicGuy9wrzVA1g1+K6VFdwZBdMZV0kHvucbndBnA5dqecaLryE8gqX3aAEf1FF
         jz16fMLCPUcsfur43GbZCRAHuuHQyvNZejiJyoolaRn/JmyrKUcBC4R/5ZvX+olCDdgm
         3wWHieRCn2EOV+AinviGEHtEjmvORZO+ywD6DxzGQimm8zGIPSISGvZs5Gmj91JLu6U2
         T/aMvayYGEBFmHPJNy1UHgloAJ8UqOGGNUHenY2k7ZVGU2OKTVx1FpS3ZEMDw4mTo3dH
         nci4FCkkP7XBRfO2jOtFWkIVyYO1XcLCX8KMLGHT9ttk74esp/w69nvnK415iuPq/pFx
         idnQ==
X-Forwarded-Encrypted: i=2; AJvYcCXcUhE/wflUX7JK/rEjPFpfXosPlGIpzi5mCoJrRe3+2V9XP2oRiYJrKU2YnmLSYuEbEe76gw==@lfdr.de
X-Gm-Message-State: AOJu0Yz4s0wIab0pKUEfpcVl9EKhyveRaBpU3+dMrp5t3GSkjkO4NbO/
	/VnciO8zUYolVn8tCywjjYLgUEtdGQeG0QuG1fAYXCw+tYZGVY17
X-Google-Smtp-Source: AGHT+IGkbPmrJC607yOUVDOJ/qfLeY2g9G13K2DLk5kdh1pUYklhmIf8oEzEgcmAeOPijcj74Izqng==
X-Received: by 2002:a05:600c:4793:b0:43b:baf7:76e4 with SMTP id 5b1f17b1804b1-43bcae04e19mr19797765e9.1.1741080322609;
        Tue, 04 Mar 2025 01:25:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG8jmsJ+ln8KVBFzKvHxp63rTaWTarkUy32OY76rS5esw==
Received: by 2002:a05:600c:1d98:b0:439:9891:79ee with SMTP id
 5b1f17b1804b1-43aed4d7aaals6854905e9.0.-pod-prod-00-eu; Tue, 04 Mar 2025
 01:25:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVjIXrE1YwIqzpmqnPR0UJJXb05Vhmti2XR7vsu9bZ+W3BmKG9wZWiNLVt825VR/PJmNcF5yK3U+Wo=@googlegroups.com
X-Received: by 2002:a05:6000:186b:b0:390:f5c8:1079 with SMTP id ffacd0b85a97d-39115627ea8mr1899877f8f.24.1741080320061;
        Tue, 04 Mar 2025 01:25:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080320; cv=none;
        d=google.com; s=arc-20240605;
        b=JKLhn7AlzFw/1P8vyVEOAmOzPW2ZrxQ7k9zj2fNOEwdj/oM7v88rlu7ljjtMXWS2im
         reQZKEvk5H3jM632ssdpjw83d6aE9bUxNe9Kvm/fVuii/GXTCklkfI1j/JQL/X2Y/Zpn
         Baa8Vqbxlta4x3d8nZJFdGeoFKxbhGBdsQxLrNE47agbZtTnpG6HfusNh0qSQfTmxG4g
         OELTmao/d0WIVl3xZGftaF1aE+htArnLJJw5Us7WzrWDgP8EpzIbbZjqYbACipR8Z5Wk
         NgyuC9IWI9T9NDnMMi94fr02CXexNDp7DiIOnp/DJwrOU6jLfbw/0W3MHKj34cJ2gurr
         XwCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=dE96AlLyXfE4zcTJ3mSZ7GpwRWlrYm2AzYTGYdTipys=;
        fh=oeHuK0hnGe5PpJZwf5lH0soi7UnS/UF/Kat/FmZMjpo=;
        b=kmHbwUiuPF+5mA3SfOKJ+c02PtPqBCbP8EsQItuI8IhYAvtVAfSw6S1dtYwW6TKCl7
         EgtNB7NTdGIRMNJE8Q1psD9scfXSS9chWRxjvd+M9cwUnRn9NQn0VpRgrkx936JzqniD
         ZDhGCCqvvRcEFJjXIXv5cV9Eoh+PinrdWoVGnuwKR7AJRDpHalxPq4vNXe9zBtvxozil
         ZzFHN+d/87cKAUOWcx+7hyWWLa0E9xOqP3FToezAhZeY6D9BFQJuE6If8Xt0C/pHbqfD
         abbyYgLwlPQRW72vw3X+N1nf0ADR5j8qqzSEio3IvB37+95KUXoEmtyPLucAYMHbabbU
         n7TA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="kN+/8ei7";
       spf=pass (google.com: domain of 3_8bgzwukcewszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3_8bGZwUKCewSZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bce05d49bsi355555e9.0.2025.03.04.01.25.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_8bgzwukcewszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5e4cc705909so1862553a12.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWPsdr81hPCQDXjzOckkqHDCqE9I16+OoRYX+6vstk8QH4vl8iuf1nDqGdNr9eM5IruEPfOkXYtkMA=@googlegroups.com
X-Received: from ejcti14.prod.google.com ([2002:a17:907:c20e:b0:abf:6ebf:550f])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:6d0f:b0:abf:7a26:c47c
 with SMTP id a640c23a62f3a-abf7a26c669mr613682066b.47.1741080319651; Tue, 04
 Mar 2025 01:25:19 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:03 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-5-elver@google.com>
Subject: [PATCH v2 04/34] Documentation: Add documentation for Compiler-Based
 Capability Analysis
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
 header.i=@google.com header.s=20230601 header.b="kN+/8ei7";       spf=pass
 (google.com: domain of 3_8bgzwukcewszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3_8bGZwUKCewSZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
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
 .../dev-tools/capability-analysis.rst         | 145 ++++++++++++++++++
 Documentation/dev-tools/index.rst             |   1 +
 2 files changed, 146 insertions(+)
 create mode 100644 Documentation/dev-tools/capability-analysis.rst

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
new file mode 100644
index 000000000000..4b9c93cc8fcd
--- /dev/null
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -0,0 +1,145 @@
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
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-5-elver%40google.com.
