Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZEVQTZQKGQEG7DS4XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 58A8317A743
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 15:21:25 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id d15sf1998553lfn.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 06:21:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583418085; cv=pass;
        d=google.com; s=arc-20160816;
        b=heWTdjoPFMG6a8s6laqyEHvgK3SfFB0d0is51xUcjP8ErUPUlOvfdUhrJFGl7U9vEG
         GxJZ/qQdHkynjSS/reiiCTTwYCxsUEHJb+wJwq+IQaMBXbp3vXwl6i4ycwbKJmWj0m98
         VW0HydjmmA1o7GHDjQeguMwSJgd4Tvis8Oqz+N1LdV47H6r4xLNNyAr++o9QOw/aTdvV
         9i5+ZQu+bB5il/MqLL1/bKYc07p+CDK3HjtaYDPL6MRoULFjSMgoIrwSxnQuqvcU5+Uj
         dWCaYKZPVG802rQpQV9gS0ldUYizYD16jD0AOdcCAtVc25pysZbRPt1IxfRcev8PRHex
         QqzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ql0CGLw6lRvfGME+lCTwamY8Gf3vXTDUmxmYwRc6pyY=;
        b=axg0Q5qXho7pqYPjaiZvfPUKdTqNqudAgIabAw7Cx8N4esiEZSeSXYkHnkaMdtc8rv
         amDI4G/8mhXP215OCW/Y1L5x3CxbQnJI375+H2eUMsg9CKWyXtHzObu+NNCygt8jOJdU
         bh0pcd+ngtbNAsLCT3OIxS6GvmbOjpsCuJwjRYInqw8ikwkkZA18Lr27bppo2O1GUJQJ
         gkMzUgSzPS3J1XGnCqPL+SLLPsvoCqXVbCYIE80HN3WKq5zM7jWd1S0Jim4BWOzGfW29
         Bcf9D0T01Uzp+Tp54361tAoUNq2CDvz4Hum6LNC1eNMH1iQgYX/V0gbO2vsZZtOieLj2
         Vj8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WN0hLRUl;
       spf=pass (google.com: domain of 34wphxgukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=34wphXgUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ql0CGLw6lRvfGME+lCTwamY8Gf3vXTDUmxmYwRc6pyY=;
        b=kliJIAuveeiphHCQZhqv/XtSfkEy7mHa76VBzgt34qhO9M62WoqJgpxdm+vcKe74dd
         d3XRnmviGt1pz6GOphZGNbvCr6L2JukeMI17fRTb1V5q9TbuPyp0leIcaZQkIE0zbdJJ
         aHsicHzF3j4PBu+igB5FiYWYycZe1n65qzAizzkpUqSbaGB24u47PHbJQj1tkngURpvW
         HzzAlaHmCAmRH5e87Kah2hkTHFcaoqa5Psqwx7oJf4HftU95Og5OPGKHRVsechFDF0DF
         27YPR7G8pux9MQoZne7kRr/LVSil9lvQonzFWYT7/6x28+gL7/Wr1d7Z2DjDajc9wyM2
         HEig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ql0CGLw6lRvfGME+lCTwamY8Gf3vXTDUmxmYwRc6pyY=;
        b=Qxd/jfHGzZkm0FaHkG6k/6ekUMx13pk+U4kFkfE+ldcuXDcER7RyBIYBNUXwzllPVK
         0DPVQCT3MJjbmNlh1pV3AvdG4PUPuSAQKuWlsOf21ZuhQvfMtyBWGQWPuisn1Dx3Ydqk
         Ig7raWqF/dKgXup8/bVUnCe3+gb1gC/ch4ZTpfZdQCNOsWjLJWuiCbraw/VoDvZn+xyu
         OEyFKzoV3ieuy+zunyGOdpHyI8+k8BquAHu10f+s5FWpFVr1FUob2Rgd3hpnhPCAOL/k
         uFzlVGpT4cbhMrKb6BuKhAPtMoSud7ESO9mJtXwsdJd512bU528vyy/RPYUC/nRyPfqD
         jhRA==
X-Gm-Message-State: ANhLgQ1OIHk/fy9eAVnKCLE873geGSdIMVw/+f1UknaqhvFnZvKP5n58
	YXW3rqMveuh1nWTZ3yGiThY=
X-Google-Smtp-Source: ADFU+vtfr4ucF3PvXGJkc8s2AoMyEum3yhZEN2LF8ocdyOMzVFzu500TJx5ZYt3vzsiegP+fzfKTtg==
X-Received: by 2002:a2e:b6c6:: with SMTP id m6mr5513775ljo.3.1583418084802;
        Thu, 05 Mar 2020 06:21:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b59:: with SMTP id o25ls77374ljj.2.gmail; Thu, 05 Mar
 2020 06:21:23 -0800 (PST)
X-Received: by 2002:a05:651c:1078:: with SMTP id y24mr2917619ljm.102.1583418083880;
        Thu, 05 Mar 2020 06:21:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583418083; cv=none;
        d=google.com; s=arc-20160816;
        b=L0Cw9axqG3qiiufhbYBioRSt7aQixUmk9aVcUXBTnogW4PaOZC9busUUiBAX03vQ4v
         iDjFZLmAsCWpsq90seOFK+DBBUh7MCOEr8AxvK49ZCwkatgfqjtQjJDyGgjr0N7zop6I
         eUTSZgjKUOwmZADO9m77aXnpRI3cOIX4RkiQ88ulz9z2vLiRUk+QsXVIeVlt32ejsQ2W
         2P/fyMn9XQY5zQfgqpuxG8FnTxqsmyr2GM4H+LL2Eq+E6kxqVQbWjYAMMfY1RRFqm+nW
         8u1pMv7kz0GfSYsvzKKcMZ6qcnvKmveYvSxAsoRqTQrRUKty1XevqVnNv1W3o0VZE8FF
         ti7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=vQSYhtj+Fs/1Q0PpL2zU0OA2iyyqEHPsZ9keElViPa4=;
        b=En4hS3GrUhYpaMehmJxz+smbC2XHSyutzJsPURKJ4lv7KM3c1no0+PxUBJts2r8ke0
         mOCiv2S8qfiDPlRsEeSLK+lWsyKEzQ4REr70STR93MaB2HVRHDS8nkhT+r3/l0d7z3oc
         PmS15Q8TXgY0T5DMQ4DPPCjHQem7yOtR/1Qc3jAEe3/WIMUUqqHzszKNZu+noTTx0cO6
         wjhbibOmFftd63eZEr7ftrnOyhFd8ybkk2WrKigi30WzGh//tW1vTGEC+Kpx5vwWzybU
         tDP2eXuJC6tXE/b4ev2lg6+1XGb9AuEeAozgxW+rJXHe8QsAQ6O+6GX0Brl3denM9p8N
         ZB0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WN0hLRUl;
       spf=pass (google.com: domain of 34wphxgukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=34wphXgUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id y1si313832lfy.2.2020.03.05.06.21.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 06:21:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 34wphxgukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id y18so2933999wmi.1
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 06:21:23 -0800 (PST)
X-Received: by 2002:adf:d4c7:: with SMTP id w7mr1329413wrk.20.1583418083060;
 Thu, 05 Mar 2020 06:21:23 -0800 (PST)
Date: Thu,  5 Mar 2020 15:21:08 +0100
In-Reply-To: <20200305142109.50945-1-elver@google.com>
Message-Id: <20200305142109.50945-2-elver@google.com>
Mime-Version: 1.0
References: <20200305142109.50945-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH v2 2/3] kcsan: Update Documentation/dev-tools/kcsan.rst
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	corbet@lwn.net, linux-doc@vger.kernel.org, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WN0hLRUl;       spf=pass
 (google.com: domain of 34wphxgukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=34wphXgUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Extend and improve based on recent changes, and summarize important
bits that have been missing. Tested with "make htmldocs".

Signed-off-by: Marco Elver <elver@google.com>
Cc: Qian Cai <cai@lca.pw>
---
v2:
* Note on __no_kcsan with regular inline functions and old compilers,
  and suggestion to use __no_kcsan_or_inline in those cases. [Suggested by
  Qian Cai]

Preview of generated documentation (with the next patch):
https://htmlpreview.github.io/?https://github.com/google/ktsan/blob/kcsan-kerneldoc/output/dev-tools/kcsan.html
---
 Documentation/dev-tools/kcsan.rst | 227 +++++++++++++++++++-----------
 1 file changed, 144 insertions(+), 83 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 65a0be513b7de..52a5d6fb9701f 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -1,27 +1,22 @@
 The Kernel Concurrency Sanitizer (KCSAN)
 ========================================
 
-Overview
---------
-
-*Kernel Concurrency Sanitizer (KCSAN)* is a dynamic data race detector for
-kernel space. KCSAN is a sampling watchpoint-based data race detector. Key
-priorities in KCSAN's design are lack of false positives, scalability, and
-simplicity. More details can be found in `Implementation Details`_.
-
-KCSAN uses compile-time instrumentation to instrument memory accesses. KCSAN is
-supported in both GCC and Clang. With GCC it requires version 7.3.0 or later.
-With Clang it requires version 7.0.0 or later.
+The Kernel Concurrency Sanitizer (KCSAN) is a dynamic race detector, which
+relies on compile-time instrumentation, and uses a watchpoint-based sampling
+approach to detect races. KCSAN's primary purpose is to detect `data races`_.
 
 Usage
 -----
 
-To enable KCSAN configure kernel with::
+KCSAN is supported in both GCC and Clang. With GCC it requires version 7.3.0 or
+later. With Clang it requires version 7.0.0 or later.
+
+To enable KCSAN configure the kernel with::
 
     CONFIG_KCSAN = y
 
 KCSAN provides several other configuration options to customize behaviour (see
-their respective help text for more info).
+the respective help text in ``lib/Kconfig.kcsan`` for more info).
 
 Error reports
 ~~~~~~~~~~~~~
@@ -96,7 +91,8 @@ The other less common type of data race report looks like this::
 This report is generated where it was not possible to determine the other
 racing thread, but a race was inferred due to the data value of the watched
 memory location having changed. These can occur either due to missing
-instrumentation or e.g. DMA accesses.
+instrumentation or e.g. DMA accesses. These reports will only be generated if
+``CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=y`` (selected by default).
 
 Selective analysis
 ~~~~~~~~~~~~~~~~~~
@@ -110,9 +106,26 @@ the below options are available:
   behaviour when encountering a data race is deemed safe.
 
 * Disabling data race detection for entire functions can be accomplished by
-  using the function attribute ``__no_kcsan`` (or ``__no_kcsan_or_inline`` for
-  ``__always_inline`` functions). To dynamically control for which functions
-  data races are reported, see the `debugfs`_ blacklist/whitelist feature.
+  using the function attribute ``__no_kcsan``::
+
+    __no_kcsan
+    void foo(void) {
+        ...
+
+  To dynamically limit for which functions to generate reports, see the
+  `DebugFS interface`_ blacklist/whitelist feature.
+
+  For ``__always_inline`` functions, replace ``__always_inline`` with
+  ``__no_kcsan_or_inline`` (which implies ``__always_inline``)::
+
+    static __no_kcsan_or_inline void foo(void) {
+        ...
+
+  Note: Older compiler versions (GCC < 9) also do not always honor the
+  ``__no_kcsan`` attribute on regular ``inline`` functions. If false positives
+  with these compilers cannot be tolerated, for small functions where
+  ``__always_inline`` would be appropriate, ``__no_kcsan_or_inline`` should be
+  preferred instead.
 
 * To disable data race detection for a particular compilation unit, add to the
   ``Makefile``::
@@ -124,13 +137,29 @@ the below options are available:
 
     KCSAN_SANITIZE := n
 
-debugfs
-~~~~~~~
+Furthermore, it is possible to tell KCSAN to show or hide entire classes of
+data races, depending on preferences. These can be changed via the following
+Kconfig options:
+
+* ``CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY``: If enabled and a conflicting write
+  is observed via a watchpoint, but the data value of the memory location was
+  observed to remain unchanged, do not report the data race.
+
+* ``CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC``: Assume that plain aligned writes
+  up to word size are atomic by default. Assumes that such writes are not
+  subject to unsafe compiler optimizations resulting in data races. The option
+  causes KCSAN to not report data races due to conflicts where the only plain
+  accesses are aligned writes up to word size.
+
+DebugFS interface
+~~~~~~~~~~~~~~~~~
+
+The file ``/sys/kernel/debug/kcsan`` provides the following interface:
 
-* The file ``/sys/kernel/debug/kcsan`` can be read to get stats.
+* Reading ``/sys/kernel/debug/kcsan`` returns various runtime statistics.
 
-* KCSAN can be turned on or off by writing ``on`` or ``off`` to
-  ``/sys/kernel/debug/kcsan``.
+* Writing ``on`` or ``off`` to ``/sys/kernel/debug/kcsan`` allows turning KCSAN
+  on or off, respectively.
 
 * Writing ``!some_func_name`` to ``/sys/kernel/debug/kcsan`` adds
   ``some_func_name`` to the report filter list, which (by default) blacklists
@@ -142,91 +171,120 @@ debugfs
   can be used to silence frequently occurring data races; the whitelist feature
   can help with reproduction and testing of fixes.
 
+Tuning performance
+~~~~~~~~~~~~~~~~~~
+
+Core parameters that affect KCSAN's overall performance and bug detection
+ability are exposed as kernel command-line arguments whose defaults can also be
+changed via the corresponding Kconfig options.
+
+* ``kcsan.skip_watch`` (``CONFIG_KCSAN_SKIP_WATCH``): Number of per-CPU memory
+  operations to skip, before another watchpoint is set up. Setting up
+  watchpoints more frequently will result in the likelihood of races to be
+  observed to increase. This parameter has the most significant impact on
+  overall system performance and race detection ability.
+
+* ``kcsan.udelay_task`` (``CONFIG_KCSAN_UDELAY_TASK``): For tasks, the
+  microsecond delay to stall execution after a watchpoint has been set up.
+  Larger values result in the window in which we may observe a race to
+  increase.
+
+* ``kcsan.udelay_interrupt`` (``CONFIG_KCSAN_UDELAY_INTERRUPT``): For
+  interrupts, the microsecond delay to stall execution after a watchpoint has
+  been set up. Interrupts have tighter latency requirements, and their delay
+  should generally be smaller than the one chosen for tasks.
+
+They may be tweaked at runtime via ``/sys/module/kcsan/parameters/``.
+
 Data Races
 ----------
 
-Informally, two operations *conflict* if they access the same memory location,
-and at least one of them is a write operation. In an execution, two memory
-operations from different threads form a **data race** if they *conflict*, at
-least one of them is a *plain access* (non-atomic), and they are *unordered* in
-the "happens-before" order according to the `LKMM
-<../../tools/memory-model/Documentation/explanation.txt>`_.
+In an execution, two memory accesses form a *data race* if they *conflict*,
+they happen concurrently in different threads, and at least one of them is a
+*plain access*; they *conflict* if both access the same memory location, and at
+least one is a write. For a more thorough discussion and definition, see `"Plain
+Accesses and Data Races" in the LKMM`_.
+
+.. _"Plain Accesses and Data Races" in the LKMM: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/explanation.txt#n1922
 
-Relationship with the Linux Kernel Memory Model (LKMM)
-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+Relationship with the Linux-Kernel Memory Consistency Model (LKMM)
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 The LKMM defines the propagation and ordering rules of various memory
 operations, which gives developers the ability to reason about concurrent code.
 Ultimately this allows to determine the possible executions of concurrent code,
 and if that code is free from data races.
 
-KCSAN is aware of *atomic* accesses (``READ_ONCE``, ``WRITE_ONCE``,
-``atomic_*``, etc.), but is oblivious of any ordering guarantees. In other
-words, KCSAN assumes that as long as a plain access is not observed to race
-with another conflicting access, memory operations are correctly ordered.
+KCSAN is aware of *marked atomic operations* (``READ_ONCE``, ``WRITE_ONCE``,
+``atomic_*``, etc.), but is oblivious of any ordering guarantees and simply
+assumes that memory barriers are placed correctly. In other words, KCSAN
+assumes that as long as a plain access is not observed to race with another
+conflicting access, memory operations are correctly ordered.
 
 This means that KCSAN will not report *potential* data races due to missing
-memory ordering. If, however, missing memory ordering (that is observable with
-a particular compiler and architecture) leads to an observable data race (e.g.
-entering a critical section erroneously), KCSAN would report the resulting
-data race.
-
-Race conditions vs. data races
-~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
-
-Race conditions are logic bugs, where unexpected interleaving of racing
-concurrent operations result in an erroneous state.
-
-Data races on the other hand are defined at the *memory model/language level*.
-Many data races are also harmful race conditions, which a tool like KCSAN
-reports!  However, not all data races are race conditions and vice-versa.
-KCSAN's intent is to report data races according to the LKMM. A data race
-detector can only work at the memory model/language level.
-
-Deeper analysis, to find high-level race conditions only, requires conveying
-the intended kernel logic to a tool. This requires (1) the developer writing a
-specification or model of their code, and then (2) the tool verifying that the
-implementation matches. This has been done for small bits of code using model
-checkers and other formal methods, but does not scale to the level of what can
-be covered with a dynamic analysis based data race detector such as KCSAN.
-
-For reasons outlined in this `article <https://lwn.net/Articles/793253/>`_,
-data races can be much more subtle, but can cause no less harm than high-level
-race conditions.
+memory ordering. Developers should therefore carefully consider the required
+memory ordering requirements that remain unchecked. If, however, missing
+memory ordering (that is observable with a particular compiler and
+architecture) leads to an observable data race (e.g. entering a critical
+section erroneously), KCSAN would report the resulting data race.
+
+Race Detection Beyond Data Races
+--------------------------------
+
+For code with complex concurrency design, race-condition bugs may not always
+manifest as data races. Race conditions occur if concurrently executing
+operations result in unexpected system behaviour. On the other hand, data races
+are defined at the C-language level. The following macros can be used to check
+properties of concurrent code where bugs would not manifest as data races.
+
+.. kernel-doc:: include/linux/kcsan-checks.h
+    :functions: ASSERT_EXCLUSIVE_WRITER ASSERT_EXCLUSIVE_ACCESS
+                ASSERT_EXCLUSIVE_BITS
 
 Implementation Details
 ----------------------
 
-The general approach is inspired by `DataCollider
+KCSAN relies on observing that two accesses happen concurrently. Crucially, we
+want to (a) increase the chances of observing races (especially for races that
+manifest rarely), and (b) be able to actually observe them. We can accomplish
+(a) by injecting various delays, and (b) by using address watchpoints (or
+breakpoints).
+
+If we deliberately stall a memory access, while we have a watchpoint for its
+address set up, and then observe the watchpoint to fire, two accesses to the
+same address just raced. Using hardware watchpoints, this is the approach taken
+in `DataCollider
 <http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf>`_.
 Unlike DataCollider, KCSAN does not use hardware watchpoints, but instead
-relies on compiler instrumentation. Watchpoints are implemented using an
-efficient encoding that stores access type, size, and address in a long; the
-benefits of using "soft watchpoints" are portability and greater flexibility in
-limiting which accesses trigger a watchpoint.
+relies on compiler instrumentation and "soft watchpoints".
 
-More specifically, KCSAN requires instrumenting plain (unmarked, non-atomic)
-memory operations; for each instrumented plain access:
+In KCSAN, watchpoints are implemented using an efficient encoding that stores
+access type, size, and address in a long; the benefits of using "soft
+watchpoints" are portability and greater flexibility. KCSAN then relies on the
+compiler instrumenting plain accesses. For each instrumented plain access:
 
 1. Check if a matching watchpoint exists; if yes, and at least one access is a
    write, then we encountered a racing access.
 
 2. Periodically, if no matching watchpoint exists, set up a watchpoint and
-   stall for a small delay.
+   stall for a small randomized delay.
 
 3. Also check the data value before the delay, and re-check the data value
    after delay; if the values mismatch, we infer a race of unknown origin.
 
-To detect data races between plain and atomic memory operations, KCSAN also
-annotates atomic accesses, but only to check if a watchpoint exists
-(``kcsan_check_atomic_*``); i.e.  KCSAN never sets up a watchpoint on atomic
-accesses.
+To detect data races between plain and marked accesses, KCSAN also annotates
+marked accesses, but only to check if a watchpoint exists; i.e. KCSAN never
+sets up a watchpoint on marked accesses. By never setting up watchpoints for
+marked operations, if all accesses to a variable that is accessed concurrently
+are properly marked, KCSAN will never trigger a watchpoint and therefore never
+report the accesses.
 
 Key Properties
 ~~~~~~~~~~~~~~
 
-1. **Memory Overhead:**  The current implementation uses a small array of longs
-   to encode watchpoint information, which is negligible.
+1. **Memory Overhead:**  The overall memory overhead is only a few MiB
+   depending on configuration. The current implementation uses a small array of
+   longs to encode watchpoint information, which is negligible.
 
 2. **Performance Overhead:** KCSAN's runtime aims to be minimal, using an
    efficient watchpoint encoding that does not require acquiring any shared
@@ -253,14 +311,17 @@ Key Properties
 Alternatives Considered
 -----------------------
 
-An alternative data race detection approach for the kernel can be found in
+An alternative data race detection approach for the kernel can be found in the
 `Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/wiki>`_.
 KTSAN is a happens-before data race detector, which explicitly establishes the
 happens-before order between memory operations, which can then be used to
-determine data races as defined in `Data Races`_. To build a correct
-happens-before relation, KTSAN must be aware of all ordering rules of the LKMM
-and synchronization primitives. Unfortunately, any omission leads to false
-positives, which is especially important in the context of the kernel which
-includes numerous custom synchronization mechanisms. Furthermore, KTSAN's
-implementation requires metadata for each memory location (shadow memory);
-currently, for each page, KTSAN requires 4 pages of shadow memory.
+determine data races as defined in `Data Races`_.
+
+To build a correct happens-before relation, KTSAN must be aware of all ordering
+rules of the LKMM and synchronization primitives. Unfortunately, any omission
+leads to large numbers of false positives, which is especially detrimental in
+the context of the kernel which includes numerous custom synchronization
+mechanisms. To track the happens-before relation, KTSAN's implementation
+requires metadata for each memory location (shadow memory), which for each page
+corresponds to 4 pages of shadow memory, and can translate into overhead of
+tens of GiB on a large system.
-- 
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200305142109.50945-2-elver%40google.com.
