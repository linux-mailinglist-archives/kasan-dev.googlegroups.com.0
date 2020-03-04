Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTNN77ZAKGQEUPU5XWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E412179510
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 17:26:54 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id b67sf742871wmb.8
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 08:26:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583339214; cv=pass;
        d=google.com; s=arc-20160816;
        b=cDejX9U+tgqySTqx7eYUAbYyRStAgxnFvcI/9RB+DDxOvHZJ5eOp7TDDcZA88iXNJ7
         g98lBPNj/fNc/eu9iQQS3dByHzKCTYAAWTu6hNtt/FnWSJl2SUvr9iezPAzKltHbQs+m
         ppRNid+55hrRx/Aq85gEKm2M7zlfNv8KewTj760aQOuVXS/BefsU2ZrPgm/mlQdrTpKb
         UvQk3E2D3Cztnu7M/TadEoPYpFIq7KB+Y7jLEmqpkOxzf9SGj0ymn/u26iMPEe81MBgo
         bTu9vmrNPk0vZokDSyN0Laz+j5BDeRO8X0aq31LJgKGw1eN0D8mo1A94iMQvwAKM9wDJ
         p4Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=abdD4LQflcj94F2GJaD8EZ4UBNQKvGLFl8JORnWYSWI=;
        b=v7JFLtvsnpsUOJ78BoorzdfAaS1X53bz/AkggLOuNZ5RnZfOO9WYx8HerR9kjDSuAP
         6OGALvbZwlHY/v7ytUHwb6uQ1pVCcCHmwE56Fslg6SLwZ9JIpfcXYpFr94CpHl0DVa79
         zcFQEHII+ntfBdioyBGrLRuodm1wwMT63Qc2E82V+50/ZpuZA8jnnOBzoEdiIOeuFGB5
         3NrrRgJOeG9B337/RCQcyVYRzEc/y+yn8Mv5zm3agGkqpUEjHOXmwhhTfpKD3/JZRE7N
         utxtrzC9voRhAVpFA1Yd2anvHBvjRodZrUG2cGBbtj1ntr/jcg0XS4drezfV/TlFfqGX
         VKfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eJu+CLk6;
       spf=pass (google.com: domain of 3znzfxgukcfexeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zNZfXgUKCfEXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=abdD4LQflcj94F2GJaD8EZ4UBNQKvGLFl8JORnWYSWI=;
        b=NIz7E6KS4ZOYYp3ylmv6FXxHGTCYRUYWbrorGz6iMnVKgc0CFiyrTQst5QVNBFdqzk
         uizlMUGiZBjZbIFoHufPzJtAX0eUJNMFdwm6HMQ59DeRFagV9IPyARR097xutKIEzZPA
         fjtO6m5zRe7qzg/OUXr5Zyf9PHICL14xxCSvf16/6swLUyUBjIyrWUYficNboXJcWbfQ
         ijloVK37cuIkmk4hz2lcGIxQZera7SsZ+JUnCKcc/qkL0RoRVZmkVFGo2EkTMllRWWEW
         4mFX/KZ701V87FGBm9b4IrIuZx+R/UaL+wJB3c/JdNqxnv8OLsv7EQ9F1RPTj2MFK9Bc
         D/jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=abdD4LQflcj94F2GJaD8EZ4UBNQKvGLFl8JORnWYSWI=;
        b=kWUFAfhe8sHhGPIhOGVNavDW04+1vyKLSc/WU21/CB/3AgHeEpfhvVU9OL+Bqitb9V
         9sYRgGpmffVuEviHvt8K4cuPO5reWEbw8Nf78OG5anY9xRY50x/tvUZAEsNncc+qXpuJ
         AQol1bBglNU6qVb293/fHn4PnOO1dLta/DG3PyzVs+pnqm36928FTfWLnRenBS2wRJlk
         W4ZXA9kiRrqn3TdYf+BFCFkTo2bth8InSls7VdkVZLKzKfXg1rLykGRrzctzDiqlKW8Z
         I2sb1TP/1T5gw8hHp5d/gM2pCxz5o20eT0VnTk//w4mmVYSTna9eKAd2IWtMo+1xjlh5
         +ujg==
X-Gm-Message-State: ANhLgQ01GC9WUsPYh9ChRxuI94jkHc5zYpu4VjHCiD1na+1G96SylPPA
	ikMnglUmfi3gNyRfB6OdFRk=
X-Google-Smtp-Source: ADFU+vvgeZK3kiFi5ngfHOd22Wwwfkk6AzDwCpUq4Rh3aVY8iVYdu2TFvxdNpUp3OC4gCF3bN88DQw==
X-Received: by 2002:a5d:4ecb:: with SMTP id s11mr4879547wrv.83.1583339213909;
        Wed, 04 Mar 2020 08:26:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5710:: with SMTP id a16ls1318558wrv.5.gmail; Wed, 04 Mar
 2020 08:26:53 -0800 (PST)
X-Received: by 2002:a05:6000:18f:: with SMTP id p15mr5230707wrx.149.1583339213209;
        Wed, 04 Mar 2020 08:26:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583339213; cv=none;
        d=google.com; s=arc-20160816;
        b=iHmTVsqW2nr5HFyO1h/w7IbrXpCjEMRSl9NwN5zTUafpPM0OMuj5ixgGW661ZosA9o
         BkFinnbPO8o/kgK0PWwIcuDOz5q9QoRmCHgghvy9qQloOzBpyDopA3EYorp6jZ8JuyFo
         yz8wbv+VGV8m6o8OZcrsTDYh1BCGMCQrQrSZQFAQwvTxFtyklTPiIeidJ0B3G8bbI7BE
         TOF8KwK0phrod/hnmC6fNU2WlcrrJCi+i808SiXZaDlCzepz8FE6+bTfs+RrzbVoyKrT
         UPMDNs+xtNpyRzwZ5pmvApVyWlSeIXH7utVkZrd2iR8TasBgxzXSmhzczUwAb2sS8nUE
         ZIOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=gWOrBh3oN76+CKwSk0doDLVP37A7Mfhwrga+6Wn1PRM=;
        b=lpPBMuV/OpqWTmVGnIguC6lasKB1h7R9Gx5GSC9ElkFnFIQAO8XHfY+Sl0xlQpZizU
         nzpQAOQI4eUFHWF3dRq0TObNSwhTOqfkNhPs4AFV04GdnAm6NcgmCG8GYHYZdU4Z28AC
         JWb5cyvsICa7xknb5FdxC+ThZt6EptAuH4i7AdWDWo/5DlbGA8I4OqScV0u/0ROBdizn
         Il/ZLhSsQBLSW9e/BVEv64YPdS5o8bkymnptD3YtVpjr5qEuyvTlLdmvb03K56f1f1bs
         R9wG3Kh901XicppNlbOtOyK8CbXwwgSGSlICsKtV0Zb9sB6jWz4ZQXhN7EoEFxLnFlae
         fRZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eJu+CLk6;
       spf=pass (google.com: domain of 3znzfxgukcfexeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zNZfXgUKCfEXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id w11si165336wmk.0.2020.03.04.08.26.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Mar 2020 08:26:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3znzfxgukcfexeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id f207so1055440wme.6
        for <kasan-dev@googlegroups.com>; Wed, 04 Mar 2020 08:26:53 -0800 (PST)
X-Received: by 2002:adf:f087:: with SMTP id n7mr4641157wro.328.1583339212658;
 Wed, 04 Mar 2020 08:26:52 -0800 (PST)
Date: Wed,  4 Mar 2020 17:25:40 +0100
In-Reply-To: <20200304162541.46663-1-elver@google.com>
Message-Id: <20200304162541.46663-2-elver@google.com>
Mime-Version: 1.0
References: <20200304162541.46663-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH 2/3] kcsan: Update Documentation/dev-tools/kcsan.rst
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	corbet@lwn.net, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eJu+CLk6;       spf=pass
 (google.com: domain of 3znzfxgukcfexeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3zNZfXgUKCfEXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
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
---
Preview of generated documentation (with the next patch):
https://htmlpreview.github.io/?https://github.com/google/ktsan/blob/kcsan-kerneldoc/output/dev-tools/kcsan.html#race-detection-beyond-data-races
---
 Documentation/dev-tools/kcsan.rst | 206 ++++++++++++++++++------------
 1 file changed, 124 insertions(+), 82 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 65a0be513b7de..323ddc1547751 100644
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
@@ -111,8 +107,8 @@ the below options are available:
 
 * Disabling data race detection for entire functions can be accomplished by
   using the function attribute ``__no_kcsan`` (or ``__no_kcsan_or_inline`` for
-  ``__always_inline`` functions). To dynamically control for which functions
-  data races are reported, see the `debugfs`_ blacklist/whitelist feature.
+  ``__always_inline`` functions). To dynamically limit for which functions to
+  generate reports, see the `DebugFS interface`_ blacklist/whitelist feature.
 
 * To disable data race detection for a particular compilation unit, add to the
   ``Makefile``::
@@ -124,13 +120,27 @@ the below options are available:
 
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
 
-* The file ``/sys/kernel/debug/kcsan`` can be read to get stats.
+DebugFS interface
+~~~~~~~~~~~~~~~~~
 
-* KCSAN can be turned on or off by writing ``on`` or ``off`` to
-  ``/sys/kernel/debug/kcsan``.
+* Reading ``/sys/kernel/debug/kcsan`` returns various runtime statistics.
+
+* Writing ``on`` or ``off`` to ``/sys/kernel/debug/kcsan`` allows turning KCSAN
+  on or off, respectively.
 
 * Writing ``!some_func_name`` to ``/sys/kernel/debug/kcsan`` adds
   ``some_func_name`` to the report filter list, which (by default) blacklists
@@ -142,91 +152,120 @@ debugfs
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
@@ -253,14 +292,17 @@ Key Properties
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200304162541.46663-2-elver%40google.com.
