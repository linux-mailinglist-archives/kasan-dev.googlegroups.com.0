Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGFOW3XAKGQELMTWC7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id EADB5FCC7D
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:04:08 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id b4sf4889429wrn.8
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:04:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754648; cv=pass;
        d=google.com; s=arc-20160816;
        b=vBdk1yIWwrnhgKX2bn9T6YHHq1vb6ZvgnYEb5NccWCAvRT9XHvVSTDOxFUdehrTBfW
         MCO8iJgKz1wsc7RtWUu/59kiThv522R6mo/+AlZfALwp1RSI7PWpaoHjt7m3Z2n8eWKa
         jd8OXxExlurury2XuidB+QIyCnRn/pcD/4lXI5U2QvkBkBjQwL2yFbgBy6bhyv5bFsmZ
         +0K50UL2i6Y+JcaDjZaoRQQyTyG6SOxdRUs61Aj2qoEZf5vx8pSc/Q3EwsjMVGIDUmEv
         EkXKjWmUXX25W5+TV0n4aMcM4nNltyv9YQfQ1ZQP2DIxqy2YOzfUXpnJe/HpolH2mVcd
         wvGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=9hC87VJoAfz2nmNHXX0bR9arZszQD6YXY8B3ofDB6Ow=;
        b=os0k58Gsc3f4zHK1lQJPTBXa1ILmIPJFzCzLyPyo9WNleBw31WFuBMG+GtawC+CTQY
         N9YaziVv5PgWvsTnPB/fm9HFIDzlaoZo2ufGAokBZ7/qhA9cTQJBUMieTsjx/ahwLHiM
         AvCVPlLmfgm/7IIU4PQb04LOt72xPqd207mNnetR7p1oWOc4z9Rq8H/YRSvg5Of7D0v4
         P/8cPF/cbaoy4HeJKGUX23QYJrho4A+i4pNVvEa3z3c4LXiZnLyOhcnQSUPBH7TUevhC
         eZavHAVXlM99zbICgq6W4ei/HBgPXJUIucUSg19uD6jsAmm8S1biY8IEAlCUePAhXq5r
         K+yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l4L1IbG6;
       spf=pass (google.com: domain of 3f5fnxqukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3F5fNXQUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9hC87VJoAfz2nmNHXX0bR9arZszQD6YXY8B3ofDB6Ow=;
        b=kvR0/1d9P19K2CwX8KETMGZVQWDBEXgf9O5PfMqis6XIMuzC33kAIcHxv5bbga0WCR
         B0FMgg7GurMBtoqg7NHlkwczXHs/OzfES9vvFQvb3XVw+TRcGf7e4tYRZDVzR5ORU9AB
         Cx1Phe5qvbZXVvl+q0Kj+ho2AwEyyjxvtugZD9C5cZ4ePs7hlLEfjBvmLVS7cHkiYEIG
         FGoEdacEOdaC8jMNoqfut9dN/Lm9UG1AR9YWZgag/ht99l2KDyYylCQScEjUVhDv9EQ8
         ay1rXW8AwZWxMjywQg999w7bF1E0HjUhpbiL7p5kWZudqesukl8T2DKMRkvMbglRPAMK
         E/1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9hC87VJoAfz2nmNHXX0bR9arZszQD6YXY8B3ofDB6Ow=;
        b=PEHbft2lm0JEFQfIkuBapKKXn7bSukfOqhQ+cG7izdNDuC4RGxv9iRCqfOibILy3Qz
         SFeBpIRmHwQTfPD8ubfFcmkJblN0qNsrZ/aoMpdE5sYWXguywzaesXN83Zz5wdC0z5Iq
         wiPkWZVU8nKrjo7JOwgzHkNHGtVM8/7+6pSD2Xq4uuupb/A95fS3D1YvDbmXOA5BMK5n
         BOTh7YhjcPLMROl7NDLAe+KUU4KbFOORUYkTmp1lDqeTULNn+KypFA9hSdMwvFo9VDtP
         9EW7CcAtyjacz6B0w5ixwDrpDRrgo9r/Amw4hEwiYRa78N4/fZQWHd+jBpAwz6o5sETR
         INKA==
X-Gm-Message-State: APjAAAX7daep96uKq/58vvqmdfSYcAODx0ZiiuXBAMO5EYw8/KLU+qH4
	MGegLZgg0H7axDr8VS5QbuQ=
X-Google-Smtp-Source: APXvYqysL3u4VUB3YS/jGfe5MNBYLVKVccVV3lkMd7v3vdP5CGrshzoB2LLSAQEpbmd9eXotbm2npg==
X-Received: by 2002:adf:fe81:: with SMTP id l1mr6431161wrr.207.1573754648577;
        Thu, 14 Nov 2019 10:04:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4b43:: with SMTP id w3ls8786029wrs.5.gmail; Thu, 14 Nov
 2019 10:04:07 -0800 (PST)
X-Received: by 2002:adf:c649:: with SMTP id u9mr1321790wrg.20.1573754647908;
        Thu, 14 Nov 2019 10:04:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754647; cv=none;
        d=google.com; s=arc-20160816;
        b=KXDq/bzW3CfTsJgpDkIvc4+U5LyA4aeM9wHYOgV47Z1V74WBnEROwLJFpIBMBSg9u1
         qNxYPVbGUSwRizSfq0MdDKZiBkPqgo6QAFDpig3jCZX6O65vVgrXVzTj8Abwpv8OxpiI
         QUgg/mi7RZMu4B3aSHmb2M5qt/Zeud1DJMM6RbhCFd+dWhvhvfSDF0Fv2XIT9r4Pm/WU
         MBnGMToWEtSbtXQ1HgwByVXZRyeiLcCE60iuJ6VFlX3bS3GbsmXlkPRc4QAcsgogglhs
         CBHwMjIi7094VFf2jhpaWTE3o0rMyOIvDLJlgFl0v51H7Snce+pPnHTBI1h5A58Tu6YC
         tD0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LzuhNW3X/u6HJLSspB2zZFCbexO+TanhD/k0bWBpy/o=;
        b=v5WAE3QCR4KZBPALqIJAODJ0y5bOV2PCF4EkE+Y8FMF9rTaxLEy+QocHaPUn91QavR
         OrYtbj7KlXrUqTJIWK3Uq4Nc3WTSJR1ZzfL9TJdsTjDFVDlUBcGaeq9BxYgOvUQopcIx
         HYDtZGe9WeN4A7pIzoiNB1NTbVi1NfNiCKO8lP6rVovhq0+pwmRXb6IPLopd/tiIJTDm
         vLAuFtsLvITl1uTEOIhvwvMHvAgeoaHS+Ba5RZXXv/GOd1udn09VfiSjZ/gd7WK2fFb0
         rIAqtWgeqIx/0RSLjZA5mSeOrl+YRzsAgTLdZ/vxECRLuRaHBhH/N4b6MhDNg6uNz/6h
         2hhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l4L1IbG6;
       spf=pass (google.com: domain of 3f5fnxqukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3F5fNXQUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id y188si473644wmc.0.2019.11.14.10.04.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:04:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3f5fnxqukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id y133so3730274wmd.8
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:04:07 -0800 (PST)
X-Received: by 2002:a05:6000:1181:: with SMTP id g1mr7045286wrx.131.1573754647053;
 Thu, 14 Nov 2019 10:04:07 -0800 (PST)
Date: Thu, 14 Nov 2019 19:02:56 +0100
In-Reply-To: <20191114180303.66955-1-elver@google.com>
Message-Id: <20191114180303.66955-4-elver@google.com>
Mime-Version: 1.0
References: <20191114180303.66955-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v4 03/10] kcsan: Add Documentation entry in dev-tools
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, edumazet@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-efi@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=l4L1IbG6;       spf=pass
 (google.com: domain of 3f5fnxqukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3F5fNXQUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
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

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Paul E. McKenney <paulmck@kernel.org>
---
v4:
* Update to performance numbers after optimizations: no measurable
  change with default, and minor improvement when no watchpoints are set
  up.
* Add section on race conditions vs. data races.
* Add section on selective analysis.

v3:
* Split Documentation into separate patch.
* Fix typos.
* Accuracy: refer to unsoundness/completeness.
* Update with new slow-down after optimizations.
* Add Alternatives Considered section and move KTSAN mentions there.
---
 Documentation/dev-tools/index.rst |   1 +
 Documentation/dev-tools/kcsan.rst | 256 ++++++++++++++++++++++++++++++
 2 files changed, 257 insertions(+)
 create mode 100644 Documentation/dev-tools/kcsan.rst

diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
index b0522a4dd107..1b756a7014e0 100644
--- a/Documentation/dev-tools/index.rst
+++ b/Documentation/dev-tools/index.rst
@@ -21,6 +21,7 @@ whole; patches welcome!
    kasan
    ubsan
    kmemleak
+   kcsan
    gdb-kernel-debugging
    kgdb
    kselftest
diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
new file mode 100644
index 000000000000..a6f4f92df2fa
--- /dev/null
+++ b/Documentation/dev-tools/kcsan.rst
@@ -0,0 +1,256 @@
+The Kernel Concurrency Sanitizer (KCSAN)
+========================================
+
+Overview
+--------
+
+*Kernel Concurrency Sanitizer (KCSAN)* is a dynamic data race detector for
+kernel space. KCSAN is a sampling watchpoint-based data race detector. Key
+priorities in KCSAN's design are lack of false positives, scalability, and
+simplicity. More details can be found in `Implementation Details`_.
+
+KCSAN uses compile-time instrumentation to instrument memory accesses. KCSAN is
+supported in both GCC and Clang. With GCC it requires version 7.3.0 or later.
+With Clang it requires version 7.0.0 or later.
+
+Usage
+-----
+
+To enable KCSAN configure kernel with::
+
+    CONFIG_KCSAN = y
+
+KCSAN provides several other configuration options to customize behaviour (see
+their respective help text for more info).
+
+Error reports
+~~~~~~~~~~~~~
+
+A typical data race report looks like this::
+
+    ==================================================================
+    BUG: KCSAN: data-race in generic_permission / kernfs_refresh_inode
+
+    write to 0xffff8fee4c40700c of 4 bytes by task 175 on cpu 4:
+     kernfs_refresh_inode+0x70/0x170
+     kernfs_iop_permission+0x4f/0x90
+     inode_permission+0x190/0x200
+     link_path_walk.part.0+0x503/0x8e0
+     path_lookupat.isra.0+0x69/0x4d0
+     filename_lookup+0x136/0x280
+     user_path_at_empty+0x47/0x60
+     vfs_statx+0x9b/0x130
+     __do_sys_newlstat+0x50/0xb0
+     __x64_sys_newlstat+0x37/0x50
+     do_syscall_64+0x85/0x260
+     entry_SYSCALL_64_after_hwframe+0x44/0xa9
+
+    read to 0xffff8fee4c40700c of 4 bytes by task 166 on cpu 6:
+     generic_permission+0x5b/0x2a0
+     kernfs_iop_permission+0x66/0x90
+     inode_permission+0x190/0x200
+     link_path_walk.part.0+0x503/0x8e0
+     path_lookupat.isra.0+0x69/0x4d0
+     filename_lookup+0x136/0x280
+     user_path_at_empty+0x47/0x60
+     do_faccessat+0x11a/0x390
+     __x64_sys_access+0x3c/0x50
+     do_syscall_64+0x85/0x260
+     entry_SYSCALL_64_after_hwframe+0x44/0xa9
+
+    Reported by Kernel Concurrency Sanitizer on:
+    CPU: 6 PID: 166 Comm: systemd-journal Not tainted 5.3.0-rc7+ #1
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
+    ==================================================================
+
+The header of the report provides a short summary of the functions involved in
+the race. It is followed by the access types and stack traces of the 2 threads
+involved in the data race.
+
+The other less common type of data race report looks like this::
+
+    ==================================================================
+    BUG: KCSAN: data-race in e1000_clean_rx_irq+0x551/0xb10
+
+    race at unknown origin, with read to 0xffff933db8a2ae6c of 1 bytes by interrupt on cpu 0:
+     e1000_clean_rx_irq+0x551/0xb10
+     e1000_clean+0x533/0xda0
+     net_rx_action+0x329/0x900
+     __do_softirq+0xdb/0x2db
+     irq_exit+0x9b/0xa0
+     do_IRQ+0x9c/0xf0
+     ret_from_intr+0x0/0x18
+     default_idle+0x3f/0x220
+     arch_cpu_idle+0x21/0x30
+     do_idle+0x1df/0x230
+     cpu_startup_entry+0x14/0x20
+     rest_init+0xc5/0xcb
+     arch_call_rest_init+0x13/0x2b
+     start_kernel+0x6db/0x700
+
+    Reported by Kernel Concurrency Sanitizer on:
+    CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.3.0-rc7+ #2
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
+    ==================================================================
+
+This report is generated where it was not possible to determine the other
+racing thread, but a race was inferred due to the data value of the watched
+memory location having changed. These can occur either due to missing
+instrumentation or e.g. DMA accesses.
+
+Selective analysis
+~~~~~~~~~~~~~~~~~~
+
+To disable KCSAN data race detection for an entire subsystem, add to the
+respective ``Makefile``::
+
+    KCSAN_SANITIZE := n
+
+To disable KCSAN on a per-file basis, add to the ``Makefile``::
+
+    KCSAN_SANITIZE_file.o := n
+
+KCSAN also understands the ``data_race(expr)`` annotation, which tells KCSAN
+that any data races due to accesses in ``expr`` should be ignored and resulting
+behaviour when encountering a data race is deemed safe.
+
+debugfs
+~~~~~~~
+
+* The file ``/sys/kernel/debug/kcsan`` can be read to get stats.
+
+* KCSAN can be turned on or off by writing ``on`` or ``off`` to
+  ``/sys/kernel/debug/kcsan``.
+
+* Writing ``!some_func_name`` to ``/sys/kernel/debug/kcsan`` adds
+  ``some_func_name`` to the report filter list, which (by default) blacklists
+  reporting data races where either one of the top stackframes are a function
+  in the list.
+
+* Writing either ``blacklist`` or ``whitelist`` to ``/sys/kernel/debug/kcsan``
+  changes the report filtering behaviour. For example, the blacklist feature
+  can be used to silence frequently occurring data races; the whitelist feature
+  can help with reproduction and testing of fixes.
+
+Data Races
+----------
+
+Informally, two operations *conflict* if they access the same memory location,
+and at least one of them is a write operation. In an execution, two memory
+operations from different threads form a **data race** if they *conflict*, at
+least one of them is a *plain access* (non-atomic), and they are *unordered* in
+the "happens-before" order according to the `LKMM
+<../../tools/memory-model/Documentation/explanation.txt>`_.
+
+Relationship with the Linux Kernel Memory Model (LKMM)
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+
+The LKMM defines the propagation and ordering rules of various memory
+operations, which gives developers the ability to reason about concurrent code.
+Ultimately this allows to determine the possible executions of concurrent code,
+and if that code is free from data races.
+
+KCSAN is aware of *atomic* accesses (``READ_ONCE``, ``WRITE_ONCE``,
+``atomic_*``, etc.), but is oblivious of any ordering guarantees. In other
+words, KCSAN assumes that as long as a plain access is not observed to race
+with another conflicting access, memory operations are correctly ordered.
+
+This means that KCSAN will not report *potential* data races due to missing
+memory ordering. If, however, missing memory ordering (that is observable with
+a particular compiler and architecture) leads to an observable data race (e.g.
+entering a critical section erroneously), KCSAN would report the resulting
+data race.
+
+Race conditions vs. data races
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+
+Race conditions are logic bugs, where unexpected interleaving of racing
+concurrent operations result in an erroneous state.
+
+Data races on the other hand are defined at the *memory model/language level*.
+Many data races are also harmful race conditions, which a tool like KCSAN
+reports!  However, not all data races are race conditions and vice-versa.
+KCSAN's intent is to report data races according to the LKMM. A data race
+detector can only work at the memory model/language level.
+
+Deeper analysis, to find high-level race conditions only, requires conveying
+the intended kernel logic to a tool. This requires (1) the developer writing a
+specification or model of their code, and then (2) the tool verifying that the
+implementation matches. This has been done for small bits of code using model
+checkers and other formal methods, but does not scale to the level of what can
+be covered with a dynamic analysis based data race detector such as KCSAN.
+
+For reasons outlined in this `article <https://lwn.net/Articles/793253/>`_,
+data races can be much more subtle, but can cause no less harm than high-level
+race conditions.
+
+Implementation Details
+----------------------
+
+The general approach is inspired by `DataCollider
+<http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf>`_.
+Unlike DataCollider, KCSAN does not use hardware watchpoints, but instead
+relies on compiler instrumentation. Watchpoints are implemented using an
+efficient encoding that stores access type, size, and address in a long; the
+benefits of using "soft watchpoints" are portability and greater flexibility in
+limiting which accesses trigger a watchpoint.
+
+More specifically, KCSAN requires instrumenting plain (unmarked, non-atomic)
+memory operations; for each instrumented plain access:
+
+1. Check if a matching watchpoint exists; if yes, and at least one access is a
+   write, then we encountered a racing access.
+
+2. Periodically, if no matching watchpoint exists, set up a watchpoint and
+   stall for a small delay.
+
+3. Also check the data value before the delay, and re-check the data value
+   after delay; if the values mismatch, we infer a race of unknown origin.
+
+To detect data races between plain and atomic memory operations, KCSAN also
+annotates atomic accesses, but only to check if a watchpoint exists
+(``kcsan_check_atomic_*``); i.e.  KCSAN never sets up a watchpoint on atomic
+accesses.
+
+Key Properties
+~~~~~~~~~~~~~~
+
+1. **Memory Overhead:**  The current implementation uses a small array of longs
+   to encode watchpoint information, which is negligible.
+
+2. **Performance Overhead:** KCSAN's runtime aims to be minimal, using an
+   efficient watchpoint encoding that does not require acquiring any shared
+   locks in the fast-path. For kernel boot on a system with 8 CPUs:
+
+   - 5.0x slow-down with the default KCSAN config;
+   - 2.8x slow-down from runtime fast-path overhead only (set very large
+     ``KCSAN_SKIP_WATCH`` and unset ``KCSAN_SKIP_WATCH_RANDOMIZE``).
+
+3. **Annotation Overheads:** Minimal annotations are required outside the KCSAN
+   runtime. As a result, maintenance overheads are minimal as the kernel
+   evolves.
+
+4. **Detects Racy Writes from Devices:** Due to checking data values upon
+   setting up watchpoints, racy writes from devices can also be detected.
+
+5. **Memory Ordering:** KCSAN is *not* explicitly aware of the LKMM's ordering
+   rules; this may result in missed data races (false negatives).
+
+6. **Analysis Accuracy:** For observed executions, due to using a sampling
+   strategy, the analysis is *unsound* (false negatives possible), but aims to
+   be complete (no false positives).
+
+Alternatives Considered
+-----------------------
+
+An alternative data race detection approach for the kernel can be found in
+`Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/wiki>`_.
+KTSAN is a happens-before data race detector, which explicitly establishes the
+happens-before order between memory operations, which can then be used to
+determine data races as defined in `Data Races`_. To build a correct
+happens-before relation, KTSAN must be aware of all ordering rules of the LKMM
+and synchronization primitives. Unfortunately, any omission leads to false
+positives, which is especially important in the context of the kernel which
+includes numerous custom synchronization mechanisms. Furthermore, KTSAN's
+implementation requires metadata for each memory location (shadow memory);
+currently, for each page, KTSAN requires 4 pages of shadow memory.
-- 
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114180303.66955-4-elver%40google.com.
