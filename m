Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4GDUOMAMGQEMPYOW7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 43BB75A2A5F
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:33 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id z11-20020a2eb52b000000b00261d940ce36sf654050ljm.9
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526512; cv=pass;
        d=google.com; s=arc-20160816;
        b=WMYlqYnK58pt2yKvwUG3rOyZ2zSjBNNe+xiIMnXFiXQayMwC7V707+E6/TlwIkEN/U
         WEj+9cbFy1DwmuJ83QMmIuyxhyMTyGKkY3bablHMBTx2viTfb56qhKfBfaZlfR5Q9CxT
         758cim8AN0qgZjQlm+uRoV77GjTd391Ck5v+L19BmMnmS0NZs3eFun+mvHh51TKlc1eD
         9ce/qsPkfSt4BGmHrN0qOgpo7LcbOb6FPLOzqP/7p2Mt+G44nbN3bzsFEtWxCDYl0AYp
         HYr52/YY/m27Dsl0QzujLjbC2K6gefe89gLjQ7qu0f/zxHC6RxgIoc0UyBMgjOo2Ok6p
         4hJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=WGS9tmnCgbucbDpaL49mzrlvGNOjr66rTHCls2G7WVE=;
        b=gaivGGYjmksI+8oGA+2mf6WECc3yyP7S1q897L9UuAXCdTsgzUoqm40NzVcBmzlR8Q
         hSC/BKR1UiPWV8j2pZu2ksFVEr8sh8ppl0jtON9cxr58ascTR3NOI/lE0cb6qqjDWlR0
         Kn3vMr1W914v5ub3deYwkS4z6fNIWxZqyts2zqMZsc9I5Z/hXqZQZUkheuHNmSPpMdTM
         AyTrhAtc2i6z1Ax6+sk9JNxHwKLVaIDMLyskHJesJ0mvXn2PAhkmufHX8TSFadVryJfx
         w0oblwYk/gJ7HII99eh2Q1bCCY8z9rpLsvKgmsCQCfahHdP1t887j3/LkjUmtIjM4o5H
         n2bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="EKDv/PKg";
       spf=pass (google.com: domain of 37eeiywykcfiafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37eEIYwYKCfIafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=WGS9tmnCgbucbDpaL49mzrlvGNOjr66rTHCls2G7WVE=;
        b=ajOZPlFQ5hBIBayVmot7WY/gpd8WGnKwrVqKT+iSoxwaTqdKgt7Jq3LfyawieoOz72
         1J7Q2Ja/9EvDAbW9DCgJHXXJhKDca04Cm4Vjlw9lAoTwRkrFprezEuuxokoelUDNxVxu
         0Xs6QPWDQsYLW99wPSHW5U/xMFukulAINpcn/kB2Su18bpM981mWOn9KOMpNfxQvOZW8
         a40mT4qy1BUYJBwMZfzprM534c4eKhpifO+WCCkcdjsNLVHVtsPqTngn19g000GXtHTi
         rJgnR56eUeMTR5hWeSa/IvzLM40oXoezkZgJELaDT+2AUCdDDQJgGrrIzkhkRRrlLl+h
         zduw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=WGS9tmnCgbucbDpaL49mzrlvGNOjr66rTHCls2G7WVE=;
        b=JBzboqa/HdRsyFQfDJfYfFEGEykiSINWx2p0JCEICWU7HNL8jUIdIKjjh0p3kFM+S1
         O4gY7aDyarxE1twrPQvEKcceX5Ex+PnTD6h/jP1G94xeJ5Nc/Rw0BFnQCboyuuOC04dG
         H78lcYNpe614pdMX2MFX6hyx4OLpwW9uEjXBXj8Oc/Uh8tl0GJIZ+GmfvWLIMr1x7rZu
         3le3Y6gNlX2NwiSWDM7llRNlYRn1eMjMpAGMtOw3/KuoYCAJA3pzvLgrVWVCHbRSkcTc
         1AXtld/pfixhXW/wtMzvbKxERCIobkyRASrDadlkw6xHKGDO8hO2gMD0UtVXZek4IHn7
         YMeA==
X-Gm-Message-State: ACgBeo2SuSe4bQhR7eHfYwaAIOadqoMBKdFK+yHcGFfe+j6q0On1sKBh
	VYWkd0ODDaAVxN5Sb/56In8=
X-Google-Smtp-Source: AA6agR7hiSntarVPprZicNQ6PAJlXSW6K5Rl1KxQZr/VMJYRFCHQBA5oxg4+aRoeBHK6AfGlltS97w==
X-Received: by 2002:a2e:b910:0:b0:261:c243:b230 with SMTP id b16-20020a2eb910000000b00261c243b230mr2382317ljb.382.1661526512574;
        Fri, 26 Aug 2022 08:08:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f53:0:b0:48a:f49f:61c4 with SMTP id 19-20020ac25f53000000b0048af49f61c4ls1122999lfz.2.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:08:30 -0700 (PDT)
X-Received: by 2002:a05:6512:1581:b0:492:8c61:5bef with SMTP id bp1-20020a056512158100b004928c615befmr2731856lfb.518.1661526510693;
        Fri, 26 Aug 2022 08:08:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526510; cv=none;
        d=google.com; s=arc-20160816;
        b=UsQxtMAIMbwfQbcTW8zIFt+Lh0iGh3ZvnIYg1A5kkwNWka1x7Ag7b9NvDNmix+dijS
         n/uW+D4ypWNvz5wz5zqoXyxLUFtmzFl2WhqsZyAsj3BVwMDdUfyDp6/rrtSE9SAEMcS8
         1sOsxKrtld8Cl1yETwWu4cXkyHWipMHjkt9PqLQKD90tvdL8QFfvogwPGjZhobwMxsP1
         UVyYiC7RdBGT2KvSpsKaEKR2V0+Nq4aweo6CMaCFHIWMRX2h3eR+W9pbhGORv5rxo4gz
         KUJ7ATY6gZcXVR3JCnhF4U0yyMdnuQtD90GLzoYfnU8P2TcepYn+Or+BlYKDuFOy6dui
         JrVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hggbZ+cOdGgnZCdhDJpRznFT1vHDu/CChFRNqftxg0A=;
        b=DUsrkWN+US9zSv9RddbIRFGkBmC/aOOPwrLxV+KqETnGmdPn0ejs64YsCpFZBxJlTo
         7Xb6Vb7qYH21aPBYgGmjCVGnc9EcMA3KzeyBuVArGxiptifudJmlB8kgMdR8DSghg1OP
         MvfWFX2K3XPCJxAiimmkViO9fwyqalYi/qjb63KUkFOFtpWpukzsIEnq8Dtez8rhuMQB
         wo9k2r0uTgaicgE+PhSD4FW1Ic7eF8n0O5tUTU7r+1pq3Nr6MEb7qnbifp8WKaOkZcBf
         zMhRfIcYQ0AWDsLvwyAhqRpIxVsyOsfG8eLCH/9Mk/w22Ni49PV3zbCiMGiMWjkIZWDQ
         /Jgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="EKDv/PKg";
       spf=pass (google.com: domain of 37eeiywykcfiafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37eEIYwYKCfIafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id t12-20020a056512068c00b0048b12871da5si59445lfe.4.2022.08.26.08.08.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37eeiywykcfiafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id f18-20020a056402355200b00446c8d2ed50so1220059edd.18
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:30 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:360d:b0:445:bd16:803b with SMTP id
 el13-20020a056402360d00b00445bd16803bmr6959224edb.318.1661526509859; Fri, 26
 Aug 2022 08:08:29 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:29 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-7-glider@google.com>
Subject: [PATCH v5 06/44] kmsan: add ReST documentation
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="EKDv/PKg";       spf=pass
 (google.com: domain of 37eeiywykcfiafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37eEIYwYKCfIafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Add Documentation/dev-tools/kmsan.rst and reference it in the dev-tools
index.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- added a note that KMSAN is not intended for production use

v5:
 -- mention CONFIG_KMSAN_CHECK_PARAM_RETVAL, drop mentions of cpu_entry_area
 -- add SPDX license
 -- address Marco Elver's comments: reorganize doc structure, fix minor
    nits

Link: https://linux-review.googlesource.com/id/I751586f79418b95550a83c6035c650b5b01567cc
---
 Documentation/dev-tools/index.rst |   1 +
 Documentation/dev-tools/kmsan.rst | 427 ++++++++++++++++++++++++++++++
 2 files changed, 428 insertions(+)
 create mode 100644 Documentation/dev-tools/kmsan.rst

diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
index 4621eac290f46..6b0663075dc04 100644
--- a/Documentation/dev-tools/index.rst
+++ b/Documentation/dev-tools/index.rst
@@ -24,6 +24,7 @@ Documentation/dev-tools/testing-overview.rst
    kcov
    gcov
    kasan
+   kmsan
    ubsan
    kmemleak
    kcsan
diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tools/kmsan.rst
new file mode 100644
index 0000000000000..2a53a801198cb
--- /dev/null
+++ b/Documentation/dev-tools/kmsan.rst
@@ -0,0 +1,427 @@
+.. SPDX-License-Identifier: GPL-2.0
+.. Copyright (C) 2022, Google LLC.
+
+===================================
+The Kernel Memory Sanitizer (KMSAN)
+===================================
+
+KMSAN is a dynamic error detector aimed at finding uses of uninitialized
+values. It is based on compiler instrumentation, and is quite similar to the
+userspace `MemorySanitizer tool`_.
+
+An important note is that KMSAN is not intended for production use, because it
+drastically increases kernel memory footprint and slows the whole system down.
+
+Usage
+=====
+
+Building the kernel
+-------------------
+
+In order to build a kernel with KMSAN you will need a fresh Clang (14.0.6+).
+Please refer to `LLVM documentation`_ for the instructions on how to build Clang.
+
+Now configure and build the kernel with CONFIG_KMSAN enabled.
+
+Example report
+--------------
+
+Here is an example of a KMSAN report::
+
+  =====================================================
+  BUG: KMSAN: uninit-value in test_uninit_kmsan_check_memory+0x1be/0x380 [kmsan_test]
+   test_uninit_kmsan_check_memory+0x1be/0x380 mm/kmsan/kmsan_test.c:273
+   kunit_run_case_internal lib/kunit/test.c:333
+   kunit_try_run_case+0x206/0x420 lib/kunit/test.c:374
+   kunit_generic_run_threadfn_adapter+0x6d/0xc0 lib/kunit/try-catch.c:28
+   kthread+0x721/0x850 kernel/kthread.c:327
+   ret_from_fork+0x1f/0x30 ??:?
+
+  Uninit was stored to memory at:
+   do_uninit_local_array+0xfa/0x110 mm/kmsan/kmsan_test.c:260
+   test_uninit_kmsan_check_memory+0x1a2/0x380 mm/kmsan/kmsan_test.c:271
+   kunit_run_case_internal lib/kunit/test.c:333
+   kunit_try_run_case+0x206/0x420 lib/kunit/test.c:374
+   kunit_generic_run_threadfn_adapter+0x6d/0xc0 lib/kunit/try-catch.c:28
+   kthread+0x721/0x850 kernel/kthread.c:327
+   ret_from_fork+0x1f/0x30 ??:?
+
+  Local variable uninit created at:
+   do_uninit_local_array+0x4a/0x110 mm/kmsan/kmsan_test.c:256
+   test_uninit_kmsan_check_memory+0x1a2/0x380 mm/kmsan/kmsan_test.c:271
+
+  Bytes 4-7 of 8 are uninitialized
+  Memory access of size 8 starts at ffff888083fe3da0
+
+  CPU: 0 PID: 6731 Comm: kunit_try_catch Tainted: G    B       E     5.16.0-rc3+ #104
+  Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
+  =====================================================
+
+The report says that the local variable ``uninit`` was created uninitialized in
+``do_uninit_local_array()``. The third stack trace corresponds to the place
+where this variable was created.
+
+The first stack trace shows where the uninit value was used (in
+``test_uninit_kmsan_check_memory()``). The tool shows the bytes which were left
+uninitialized in the local variable, as well as the stack where the value was
+copied to another memory location before use.
+
+A use of uninitialized value ``v`` is reported by KMSAN in the following cases:
+ - in a condition, e.g. ``if (v) { ... }``;
+ - in an indexing or pointer dereferencing, e.g. ``array[v]`` or ``*v``;
+ - when it is copied to userspace or hardware, e.g. ``copy_to_user(..., &v, ...)``;
+ - when it is passed as an argument to a function, and
+   ``CONFIG_KMSAN_CHECK_PARAM_RETVAL`` is enabled (see below).
+
+The mentioned cases (apart from copying data to userspace or hardware, which is
+a security issue) are considered undefined behavior from the C11 Standard point
+of view.
+
+Disabling the instrumentation
+-----------------------------
+
+A function can be marked with ``__no_kmsan_checks``. Doing so makes KMSAN
+ignore uninitialized values in that function and mark its output as initialized.
+As a result, the user will not get KMSAN reports related to that function.
+
+Another function attribute supported by KMSAN is ``__no_sanitize_memory``.
+Applying this attribute to a function will result in KMSAN not instrumenting
+it, which can be helpful if we do not want the compiler to interfere with some
+low-level code (e.g. that marked with ``noinstr`` which implicitly adds
+``__no_sanitize_memory``).
+
+This however comes at a cost: stack allocations from such functions will have
+incorrect shadow/origin values, likely leading to false positives. Functions
+called from non-instrumented code may also receive incorrect metadata for their
+parameters.
+
+As a rule of thumb, avoid using ``__no_sanitize_memory`` explicitly.
+
+It is also possible to disable KMSAN for a single file (e.g. main.o)::
+
+  KMSAN_SANITIZE_main.o := n
+
+or for the whole directory::
+
+  KMSAN_SANITIZE := n
+
+in the Makefile. Think of this as applying ``__no_sanitize_memory`` to every
+function in the file or directory. Most users won't need KMSAN_SANITIZE, unless
+their code gets broken by KMSAN (e.g. runs at early boot time).
+
+Support
+=======
+
+In order for KMSAN to work the kernel must be built with Clang, which so far is
+the only compiler that has KMSAN support. The kernel instrumentation pass is
+based on the userspace `MemorySanitizer tool`_.
+
+The runtime library only supports x86_64 at the moment.
+
+How KMSAN works
+===============
+
+KMSAN shadow memory
+-------------------
+
+KMSAN associates a metadata byte (also called shadow byte) with every byte of
+kernel memory. A bit in the shadow byte is set iff the corresponding bit of the
+kernel memory byte is uninitialized. Marking the memory uninitialized (i.e.
+setting its shadow bytes to ``0xff``) is called poisoning, marking it
+initialized (setting the shadow bytes to ``0x00``) is called unpoisoning.
+
+When a new variable is allocated on the stack, it is poisoned by default by
+instrumentation code inserted by the compiler (unless it is a stack variable
+that is immediately initialized). Any new heap allocation done without
+``__GFP_ZERO`` is also poisoned.
+
+Compiler instrumentation also tracks the shadow values as they are used along
+the code. When needed, instrumentation code invokes the runtime library in
+``mm/kmsan/`` to persist shadow values.
+
+The shadow value of a basic or compound type is an array of bytes of the same
+length. When a constant value is written into memory, that memory is unpoisoned.
+When a value is read from memory, its shadow memory is also obtained and
+propagated into all the operations which use that value. For every instruction
+that takes one or more values the compiler generates code that calculates the
+shadow of the result depending on those values and their shadows.
+
+Example::
+
+  int a = 0xff;  // i.e. 0x000000ff
+  int b;
+  int c = a | b;
+
+In this case the shadow of ``a`` is ``0``, shadow of ``b`` is ``0xffffffff``,
+shadow of ``c`` is ``0xffffff00``. This means that the upper three bytes of
+``c`` are uninitialized, while the lower byte is initialized.
+
+Origin tracking
+---------------
+
+Every four bytes of kernel memory also have a so-called origin mapped to them.
+This origin describes the point in program execution at which the uninitialized
+value was created. Every origin is associated with either the full allocation
+stack (for heap-allocated memory), or the function containing the uninitialized
+variable (for locals).
+
+When an uninitialized variable is allocated on stack or heap, a new origin
+value is created, and that variable's origin is filled with that value. When a
+value is read from memory, its origin is also read and kept together with the
+shadow. For every instruction that takes one or more values, the origin of the
+result is one of the origins corresponding to any of the uninitialized inputs.
+If a poisoned value is written into memory, its origin is written to the
+corresponding storage as well.
+
+Example 1::
+
+  int a = 42;
+  int b;
+  int c = a + b;
+
+In this case the origin of ``b`` is generated upon function entry, and is
+stored to the origin of ``c`` right before the addition result is written into
+memory.
+
+Several variables may share the same origin address, if they are stored in the
+same four-byte chunk. In this case every write to either variable updates the
+origin for all of them. We have to sacrifice precision in this case, because
+storing origins for individual bits (and even bytes) would be too costly.
+
+Example 2::
+
+  int combine(short a, short b) {
+    union ret_t {
+      int i;
+      short s[2];
+    } ret;
+    ret.s[0] = a;
+    ret.s[1] = b;
+    return ret.i;
+  }
+
+If ``a`` is initialized and ``b`` is not, the shadow of the result would be
+0xffff0000, and the origin of the result would be the origin of ``b``.
+``ret.s[0]`` would have the same origin, but it will never be used, because
+that variable is initialized.
+
+If both function arguments are uninitialized, only the origin of the second
+argument is preserved.
+
+Origin chaining
+~~~~~~~~~~~~~~~
+
+To ease debugging, KMSAN creates a new origin for every store of an
+uninitialized value to memory. The new origin references both its creation stack
+and the previous origin the value had. This may cause increased memory
+consumption, so we limit the length of origin chains in the runtime.
+
+Clang instrumentation API
+-------------------------
+
+Clang instrumentation pass inserts calls to functions defined in
+``mm/kmsan/nstrumentation.c`` into the kernel code.
+
+Shadow manipulation
+~~~~~~~~~~~~~~~~~~~
+
+For every memory access the compiler emits a call to a function that returns a
+pair of pointers to the shadow and origin addresses of the given memory::
+
+  typedef struct {
+    void *shadow, *origin;
+  } shadow_origin_ptr_t
+
+  shadow_origin_ptr_t __msan_metadata_ptr_for_load_{1,2,4,8}(void *addr)
+  shadow_origin_ptr_t __msan_metadata_ptr_for_store_{1,2,4,8}(void *addr)
+  shadow_origin_ptr_t __msan_metadata_ptr_for_load_n(void *addr, uintptr_t size)
+  shadow_origin_ptr_t __msan_metadata_ptr_for_store_n(void *addr, uintptr_t size)
+
+The function name depends on the memory access size.
+
+The compiler makes sure that for every loaded value its shadow and origin
+values are read from memory. When a value is stored to memory, its shadow and
+origin are also stored using the metadata pointers.
+
+Handling locals
+~~~~~~~~~~~~~~~
+
+A special function is used to create a new origin value for a local variable and
+set the origin of that variable to that value::
+
+  void __msan_poison_alloca(void *addr, uintptr_t size, char *descr)
+
+Access to per-task data
+~~~~~~~~~~~~~~~~~~~~~~~
+
+At the beginning of every instrumented function KMSAN inserts a call to
+``__msan_get_context_state()``::
+
+  kmsan_context_state *__msan_get_context_state(void)
+
+``kmsan_context_state`` is declared in ``include/linux/kmsan.h``::
+
+  struct kmsan_context_state {
+    char param_tls[KMSAN_PARAM_SIZE];
+    char retval_tls[KMSAN_RETVAL_SIZE];
+    char va_arg_tls[KMSAN_PARAM_SIZE];
+    char va_arg_origin_tls[KMSAN_PARAM_SIZE];
+    u64 va_arg_overflow_size_tls;
+    char param_origin_tls[KMSAN_PARAM_SIZE];
+    depot_stack_handle_t retval_origin_tls;
+  };
+
+This structure is used by KMSAN to pass parameter shadows and origins between
+instrumented functions (unless the parameters are checked immediately by
+``CONFIG_KMSAN_CHECK_PARAM_RETVAL``).
+
+Passing uninitialized values to functions
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+
+Clang's MemorySanitizer instrumentation has an option,
+``-fsanitize-memory-param-retval``, which makes the compiler check function
+parameters passed by value, as well as function return values.
+
+The option is controlled by ``CONFIG_KMSAN_CHECK_PARAM_RETVAL``, which is
+enabled by default to let KMSAN report uninitialized values earlier.
+Please refer to the `LKML discussion`_ for more details.
+
+Because of the way the checks are implemented in LLVM (they are only applied to
+parameters marked as ``noundef``), not all parameters are guaranteed to be
+checked, so we cannot give up the metadata storage in ``kmsan_context_state``.
+
+String functions
+~~~~~~~~~~~~~~~~
+
+The compiler replaces calls to ``memcpy()``/``memmove()``/``memset()`` with the
+following functions. These functions are also called when data structures are
+initialized or copied, making sure shadow and origin values are copied alongside
+with the data::
+
+  void *__msan_memcpy(void *dst, void *src, uintptr_t n)
+  void *__msan_memmove(void *dst, void *src, uintptr_t n)
+  void *__msan_memset(void *dst, int c, uintptr_t n)
+
+Error reporting
+~~~~~~~~~~~~~~~
+
+For each use of a value the compiler emits a shadow check that calls
+``__msan_warning()`` in the case that value is poisoned::
+
+  void __msan_warning(u32 origin)
+
+``__msan_warning()`` causes KMSAN runtime to print an error report.
+
+Inline assembly instrumentation
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+
+KMSAN instruments every inline assembly output with a call to::
+
+  void __msan_instrument_asm_store(void *addr, uintptr_t size)
+
+, which unpoisons the memory region.
+
+This approach may mask certain errors, but it also helps to avoid a lot of
+false positives in bitwise operations, atomics etc.
+
+Sometimes the pointers passed into inline assembly do not point to valid memory.
+In such cases they are ignored at runtime.
+
+
+Runtime library
+---------------
+
+The code is located in ``mm/kmsan/``.
+
+Per-task KMSAN state
+~~~~~~~~~~~~~~~~~~~~
+
+Every task_struct has an associated KMSAN task state that holds the KMSAN
+context (see above) and a per-task flag disallowing KMSAN reports::
+
+  struct kmsan_context {
+    ...
+    bool allow_reporting;
+    struct kmsan_context_state cstate;
+    ...
+  }
+
+  struct task_struct {
+    ...
+    struct kmsan_context kmsan;
+    ...
+  }
+
+KMSAN contexts
+~~~~~~~~~~~~~~
+
+When running in a kernel task context, KMSAN uses ``current->kmsan.cstate`` to
+hold the metadata for function parameters and return values.
+
+But in the case the kernel is running in the interrupt, softirq or NMI context,
+where ``current`` is unavailable, KMSAN switches to per-cpu interrupt state::
+
+  DEFINE_PER_CPU(struct kmsan_ctx, kmsan_percpu_ctx);
+
+Metadata allocation
+~~~~~~~~~~~~~~~~~~~
+
+There are several places in the kernel for which the metadata is stored.
+
+1. Each ``struct page`` instance contains two pointers to its shadow and
+origin pages::
+
+  struct page {
+    ...
+    struct page *shadow, *origin;
+    ...
+  };
+
+At boot-time, the kernel allocates shadow and origin pages for every available
+kernel page. This is done quite late, when the kernel address space is already
+fragmented, so normal data pages may arbitrarily interleave with the metadata
+pages.
+
+This means that in general for two contiguous memory pages their shadow/origin
+pages may not be contiguous. Consequently, if a memory access crosses the
+boundary of a memory block, accesses to shadow/origin memory may potentially
+corrupt other pages or read incorrect values from them.
+
+In practice, contiguous memory pages returned by the same ``alloc_pages()``
+call will have contiguous metadata, whereas if these pages belong to two
+different allocations their metadata pages can be fragmented.
+
+For the kernel data (``.data``, ``.bss`` etc.) and percpu memory regions
+there also are no guarantees on metadata contiguity.
+
+In the case ``__msan_metadata_ptr_for_XXX_YYY()`` hits the border between two
+pages with non-contiguous metadata, it returns pointers to fake shadow/origin regions::
+
+  char dummy_load_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
+  char dummy_store_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
+
+``dummy_load_page`` is zero-initialized, so reads from it always yield zeroes.
+All stores to ``dummy_store_page`` are ignored.
+
+2. For vmalloc memory and modules, there is a direct mapping between the memory
+range, its shadow and origin. KMSAN reduces the vmalloc area by 3/4, making only
+the first quarter available to ``vmalloc()``. The second quarter of the vmalloc
+area contains shadow memory for the first quarter, the third one holds the
+origins. A small part of the fourth quarter contains shadow and origins for the
+kernel modules. Please refer to ``arch/x86/include/asm/pgtable_64_types.h`` for
+more details.
+
+When an array of pages is mapped into a contiguous virtual memory space, their
+shadow and origin pages are similarly mapped into contiguous regions.
+
+References
+==========
+
+E. Stepanov, K. Serebryany. `MemorySanitizer: fast detector of uninitialized
+memory use in C++
+<https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/43308.pdf>`_.
+In Proceedings of CGO 2015.
+
+.. _MemorySanitizer tool: https://clang.llvm.org/docs/MemorySanitizer.html
+.. _LLVM documentation: https://llvm.org/docs/GettingStarted.html
+.. _LKML discussion: https://lore.kernel.org/all/20220614144853.3693273-1-glider@google.com/
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-7-glider%40google.com.
