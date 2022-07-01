Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZUG7SKQMGQEDDGL6WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B75956350C
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:35 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id g3-20020a2e9cc3000000b00253cc2b5ab5sf503308ljj.19
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685415; cv=pass;
        d=google.com; s=arc-20160816;
        b=CW1zgve8f5aIE3zNxWi6LbhoB8p6MBzSVMNAWabVmFhOixYol6COOBn4ToMpJCPm+b
         uFhJ/ZtABBSH2GA4Hhaf/zXj0xORDWMG6z2TksbmgAVEZdzrFrXHeUz8pwJOONhlZcE4
         aTQNluPsNQN54XBg5+G7y9pTypRFnS00RRzxtml3sZY+5jxEfuNfT6hSgoN/JuDiHBA6
         U89lFa+N/Q7X+tuEmMc3+RAyht8qt326RxnsojvmY+odjcPJbzX3bYcF8RXgbokU/L92
         lJXxQg55AxtgmAK1fbosOoJc2uAxdzhXHDVI+io9ivHj4xhDwdL0UdGkqF9at/KDyIMX
         eMMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=7P+ydqZosWFWnySP85c64QQr36QP4HvrnznI0fsXc/s=;
        b=ghXECh2xqC5iZ1n5Kflbg4sO+qmbPPWmD/mUf1wiEy/wPnoMu0wNTK2YaNRi2KIYVY
         MEWoxVRa/QWUL7tpRuS54Ink8W4MxKblgJE5rbl8DZ0shyC6eu+dTjF3W3VqjbFii0Zf
         Rd7G3m4f8BsFQvy074Kc4K4EOZAnylzEUN5bYJgFAwr9u/FeTAc+uWzcfrpCxpb5vQMk
         vIJGzmBkAZ4mzDxAYXCBRxdK2gi7bHxSojbHwP25hlEAofvjRsSvAf2ivyPeJ1ksXcKb
         7ocdBb00owWos6TLXbqIQ7FZwB9FGsVRU/CeXkyLi3/vrsHgL+HP04QKlYrdyNt4HNd3
         xNPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KQ8tvNca;
       spf=pass (google.com: domain of 3zao_ygykcymnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ZAO_YgYKCYMnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7P+ydqZosWFWnySP85c64QQr36QP4HvrnznI0fsXc/s=;
        b=LpOa8ldqtAhO4d+4LlPjZDP+98dDMKEVVrZcolQsiazPE+9wC+POah95dovhCuEnqH
         uP4z0j+f0tzVrj+G1/s+CTvXWUNwj0EMwNdUnpB+0seYniLOau8CiUI4F6shwdHbtlcr
         cgSxm81U2lAcZMnv96DFmbq5YTbOTAPNLdO4jFQsLmSfqSl536lCFWPQJcjQhPHfRH+3
         j/BuSNxKD9MKIXkkaNm0LXmZgT0cbzJHNXYWTXMPnO+rP4I+JCRc1ocmvVgz7yGh3/C9
         h00ukXRl9LFSJaZRMVb/Is9S+eTWPEZ9Lt1dYF8LPLO2ig+E1uKruZ1jaQRJUo94RZ8+
         UALQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7P+ydqZosWFWnySP85c64QQr36QP4HvrnznI0fsXc/s=;
        b=aJ94v3rt1QpLEKT+rcDrVy47pG/L5fIKhdRERFp3PnxaJcyI7YOcE1zQnqPFgkN1i1
         T04O7UF0dw8439Q3jiScasMquUBKHu334tJ2or2mU4QT0EFTu7I2WdIn47Uw2SPVivzg
         bsqwrD9xz44s9XIWf5vMqv/iLcIq3EcZ883tiNYLL+pLypy3iFcwOcDi6rwyRY9+IIi9
         6PgzrOsovVImua3sMp1tnMFfgmhtZLWaH6q1GnqgtUFI51ds9152DUgTMTviXSpnp3bb
         62uuYUC+tHes0wJpaq0/+ENKIdIXRSTqny/ZY8ugiJp51y59dctFIPXkteo87WvJYaaG
         n6sw==
X-Gm-Message-State: AJIora9YiILezW7rzJqfMLod9JeT+1ZBlvA5VyzF/uTXiw0u/5ngaCTR
	eVyuteFCYEzgaMef9abX4i8=
X-Google-Smtp-Source: AGRyM1uRkv5qy7xnQA9+YgA3iKsxQ5C2VUh6bXviR+2lRFUx19+MslsN1tJRsN6DeqPHWpXXX6ysyw==
X-Received: by 2002:a05:6512:1149:b0:480:77ae:cdbe with SMTP id m9-20020a056512114900b0048077aecdbemr9261667lfg.604.1656685414958;
        Fri, 01 Jul 2022 07:23:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf11:0:b0:24a:fdc1:7af4 with SMTP id c17-20020a2ebf11000000b0024afdc17af4ls7175982ljr.1.gmail;
 Fri, 01 Jul 2022 07:23:33 -0700 (PDT)
X-Received: by 2002:a2e:bd0e:0:b0:25a:88b3:9af6 with SMTP id n14-20020a2ebd0e000000b0025a88b39af6mr8644208ljq.363.1656685412925;
        Fri, 01 Jul 2022 07:23:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685412; cv=none;
        d=google.com; s=arc-20160816;
        b=sbMU+s3juODHI+7vhl1uxVVyLqJR7/M+qqypnvH6gApi4r/cZ1Y/7FlmDPJ+GQhQpb
         OUxykmtkSCad78voGJg8XslIMssUjByeQEKEwTVtTiqaRSlHossVSY6vxiRt8LBpPN85
         cEj921nHbi7o55rADtayuTteBOWcMco1ILmtDenMAVDZ6O8eRgOAfQpmLAvs6leAIzX1
         PXoxfJ1tNYIwjwjN67cziRBNdlS6H7lOgL7HMZFNZhFRb3syPB7OlSaRtvhSfkDDjsa6
         4GQbILeyAwmuyc1Z95/rVcGXCCEp6wICJeBckxLuAEBnf0nziDXw3rOs5ivCi+Hh0Fqr
         XOmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Pcx/5TatZO+PLwZ5TV1XrBLvINh7By4hSIuvqXTbyqY=;
        b=CDodB1t+G4jxT+zOX5bEsN8Tjmv7yd00aEATl+63TrEwZOE8lUelsxMlGR/R0GVmRQ
         rkZ8QMMl85o8hhKf3yAfMBOMwJC6L1LDmJXJecvumH7QM+/izrBYKUOrc3fNJ04S+CUx
         h8Roz2gQgNAk1Zv7FhlaL6Sh/y5Pi0dCPB9eA+qRQreuR5n/DRS1708MA005H2rUMN0y
         O5oZyud5Ex0LlOP44CdQzsxQr2Kim0L1Ed1f5tGPdvIiDy0MjF5IJZ8GxZ4p68sH0cNm
         lzo0bW+254+mIbDpTKXs7hNZSnBnKJ9kpJd6zojjhknG7U/pxbWWauy/W5tq8NmXvrQY
         p1Kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KQ8tvNca;
       spf=pass (google.com: domain of 3zao_ygykcymnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ZAO_YgYKCYMnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id h6-20020a05651c124600b0025a45f568e9si830921ljh.0.2022.07.01.07.23.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zao_ygykcymnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hs18-20020a1709073e9200b0072a3e7eb0beso842668ejc.10
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:32 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:42d5:b0:433:1727:b31c with SMTP id
 i21-20020a05640242d500b004331727b31cmr11243413edc.9.1656685412341; Fri, 01
 Jul 2022 07:23:32 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:31 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-7-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 06/45] kmsan: add ReST documentation
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
 header.i=@google.com header.s=20210112 header.b=KQ8tvNca;       spf=pass
 (google.com: domain of 3zao_ygykcymnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3ZAO_YgYKCYMnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
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

v4:
 -- describe CONFIG_KMSAN_CHECK_PARAM_RETVAL
 -- drop mentions of cpu_entry_area
 -- add SPDX license

Link: https://linux-review.googlesource.com/id/I751586f79418b95550a83c6035c650b5b01567cc
---
 Documentation/dev-tools/index.rst |   1 +
 Documentation/dev-tools/kmsan.rst | 422 ++++++++++++++++++++++++++++++
 2 files changed, 423 insertions(+)
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
index 0000000000000..3fa5d7fb222c9
--- /dev/null
+++ b/Documentation/dev-tools/kmsan.rst
@@ -0,0 +1,422 @@
+.. SPDX-License-Identifier: GPL-2.0
+.. Copyright (C) 2022, Google LLC.
+
+=============================
+KernelMemorySanitizer (KMSAN)
+=============================
+
+KMSAN is a dynamic error detector aimed at finding uses of uninitialized
+values. It is based on compiler instrumentation, and is quite similar to the
+userspace `MemorySanitizer tool`_.
+
+An important note is that KMSAN is not intended for production use, because it
+drastically increases kernel memory footprint and slows the whole system down.
+
+Example report
+==============
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
+
+The report says that the local variable ``uninit`` was created uninitialized in
+``do_uninit_local_array()``. The lower stack trace corresponds to the place
+where this variable was created.
+
+The upper stack shows where the uninit value was used - in
+``test_uninit_kmsan_check_memory()``. The tool shows the bytes which were left
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
+KMSAN and Clang
+===============
+
+In order for KMSAN to work the kernel must be built with Clang, which so far is
+the only compiler that has KMSAN support. The kernel instrumentation pass is
+based on the userspace `MemorySanitizer tool`_.
+
+How to build
+============
+
+In order to build a kernel with KMSAN you will need a fresh Clang (14.0.0+).
+Please refer to `LLVM documentation`_ for the instructions on how to build Clang.
+
+Now configure and build the kernel with CONFIG_KMSAN enabled.
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
+Compiler instrumentation also tracks the shadow values with the help from the
+runtime library in ``mm/kmsan/``.
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
+
+Origin tracking
+---------------
+
+Every four bytes of kernel memory also have a so-called origin assigned to
+them. This origin describes the point in program execution at which the
+uninitialized value was created. Every origin is associated with either the
+full allocation stack (for heap-allocated memory), or the function containing
+the uninitialized variable (for locals).
+
+When an uninitialized variable is allocated on stack or heap, a new origin
+value is created, and that variable's origin is filled with that value.
+When a value is read from memory, its origin is also read and kept together
+with the shadow. For every instruction that takes one or more values the origin
+of the result is one of the origins corresponding to any of the uninitialized
+inputs. If a poisoned value is written into memory, its origin is written to the
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
+``ret.s[0]`` would have the same origin, but it will be never used, because
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
+``mm/kmsan/instrumentation.c`` into the kernel code.
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
+~~~~~~~~~~~~~~~~~~~~~~~~~
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
+KMSAN instrumentation pass has an option, ``-fsanitize-memory-param-retval``,
+which makes the compiler check function parameters passed by value, as well as
+function return values.
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
+Disabling the instrumentation
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+
+A function can be marked with ``__no_kmsan_checks``. Doing so makes KMSAN
+ignore uninitialized values in that function and mark its output as initialized.
+As a result, the user will not get KMSAN reports related to that function.
+
+Another function attribute supported by KMSAN is ``__no_sanitize_memory``.
+Applying this attribute to a function will result in KMSAN not instrumenting it,
+which can be helpful if we do not want the compiler to mess up some low-level
+code (e.g. that marked with ``noinstr``).
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
+pages may not be contiguous. So, if a memory access crosses the boundary
+of a memory block, accesses to shadow/origin memory may potentially corrupt
+other pages or read incorrect values from them.
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-7-glider%40google.com.
