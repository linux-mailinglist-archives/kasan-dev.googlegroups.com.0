Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVMG7SKQMGQEHECHVMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DB20563504
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:18 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id i23-20020a2e9417000000b0025a739223d1sf503925ljh.4
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685398; cv=pass;
        d=google.com; s=arc-20160816;
        b=J3B+khDvjJfqDdVEKgM5ZL4F5VXLSuaXvQ+LLrxegSIsFdoL0vsYdp83g23XUopcZa
         HVHox4iN0vZkGAqX34Cb27qQv8TqxoS3FszjKOCBmmtqcCztbXeDDsAO1m3oJD8aLt8J
         1XaMxb9xsMYyW57qYkei2G0Nanw8Ulvn4GSMDZGbfF1lKmLm5wUNT9RoQnU17DswAL1a
         gSoRPb0znkN1PnI8WbK1MgrOAAG80UPhE38sHWPoKN5ZhPHajzd+pyuvneJWgGF1gZ5r
         L8FcVYEKQ/OKHf/ZOHMmhyCnfXx1n3ahykmzuAvMZQK1B6MEuPoPi+tIswjcII6fGasM
         ECCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=hmM9Zt8M7EnFfDaRtWTvHKhC/6BrHEp1A6RXCYSOuaA=;
        b=d4RkFJjOjeSY9ERsAbSKYNKUgGk1JMRgUalvqDEmVmsYa49ktpNO7VyBHlzktvAReh
         Xse4+H207f6nVr1JCsatY9u8tBN7aeOKwhOPZ75VSq4QhGlMQzvwhWbGDR2X8HIq2+kb
         ER/Luc99WrXFFKdFmzO85ACs6AYBOy5Qqj/6mL/ALq1g4SazCW+vFIR5Bnmp3GEAGDEV
         MFqkOSIPVSoZlPos//do4+jZZpz6uOJJ/AfAQ3Vty8Xtiov6QpTFzWw3EJv/J1UXaOpA
         anFcm7iD0m22jMLtaybqdcNFHwMLyvmsSrsZJ/sBZ/gjRlYCGbkGH2qtEWRc+T0Sl4MV
         X/+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="rRH/DJ0i";
       spf=pass (google.com: domain of 3vao_ygykcxmxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3VAO_YgYKCXMXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=hmM9Zt8M7EnFfDaRtWTvHKhC/6BrHEp1A6RXCYSOuaA=;
        b=o76XCTRsMcAuRuyNrMNlYE0olZBC587VjdKLZDz5J8p9rtuYvVWEC31UxSVauSqXBh
         9EjPWJz3c06rDRRVbJJ0J9f6kNBL6yd0iXVJRWITttfXy5wy/PAJtYnUXn9xtHjOrWer
         zMGwd9bFZwWQL9X/m0xmfeN8ZobZQ1kGgma1OFu4zEOxHJCt+Z6xcC1gC6hM61GiyM50
         KVaYG5yua4J3UsdtW6UdM1H2VJs33CIC4d7n+as3IlsHyayuTEZTDnpsUn73N+MoFoyM
         /U15XuiUYXTl9US9/hQP92Wrm1IeekV19FXpVhKeIITcL54YwDPIHNdjCVOGL6PdPIXK
         bPIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hmM9Zt8M7EnFfDaRtWTvHKhC/6BrHEp1A6RXCYSOuaA=;
        b=vzkMr1xkHZCo7eXnkovpSQ0o25CaNoDqxUZ63W96md9YEADoMZOUTD324ptBReRCVt
         rray6z3cs/dpc9N1VdWK18pOU8QJkyl0QhPAdTz7WrIS+WfGgFRvXBKamxNOoc2r7SaK
         c2CmGA0LHOwgfJD9uCLCFWgk5Gk1ZgZ5Cm3LCwCCmi8NjlHwsSOkmL4uuPz8Xv/Z1GV7
         +IwKzFjnkD4nNOshR4+DGqZjc1bspyQBoQ7+sG2oIh8C5b71msr8WlvR2TRBbQjYGKMU
         HynQAnDCZqlU0iM44nXsjjayH5OW1Du3ahKrrlhhHqWnz/ZAMBtjs57FUbl6W1f8sqpc
         U61A==
X-Gm-Message-State: AJIora+XTu1fj/6TgaanlBvr4x03i4YUUV/wW4NKeQC5z9CekIY6L/1e
	2XjPLju50N/SD8Zd8K3GW30=
X-Google-Smtp-Source: AGRyM1tcTnRPxUzokAgbOgP6hW5klCn1MWip1C2dQBO1x3PBCV7H5BeVWVpuj6JG6OI5cnk03Cbjlg==
X-Received: by 2002:a05:6512:3d1a:b0:47f:79df:2ea8 with SMTP id d26-20020a0565123d1a00b0047f79df2ea8mr10356628lfv.610.1656685397897;
        Fri, 01 Jul 2022 07:23:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls85766lfb.1.gmail; Fri, 01 Jul 2022
 07:23:16 -0700 (PDT)
X-Received: by 2002:ac2:4906:0:b0:47f:6c71:6de5 with SMTP id n6-20020ac24906000000b0047f6c716de5mr10028089lfi.137.1656685396647;
        Fri, 01 Jul 2022 07:23:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685396; cv=none;
        d=google.com; s=arc-20160816;
        b=Pe3OTvRsaFvsibMUTdqnQdvFg9Fpi3PvOeFZK40vh86L/O90Suk2opZkOiqI/OtjiY
         pYd3fXpOZ+AibBxTjASXEmEWShSvOhjBOftNLwCKX8dFVagh6c/ctvMQwMwFXtThrnzQ
         gEznoxx1vtKOlbUayoY8mOEdAK6vDK3L0om+2sU16ZQXuXx8s+MXi2+lwByBVoARkyl1
         GdWgYoKa1P5JRx/Yiev9dolKylhOcOtpeqIWKqx1Is9qenCTiwzaJcEpvI3Ezzpj7RUF
         9wk63fjX3Nn0oBtejsQNj/AUjzO5IU3n3Q7ZuTf3jJ1ATwMYWEhmczzYRSSIRFoSuRDF
         UzlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=hq/yXGoN0Uko6++mgqy4oyVuT+D1D64+d8ukuTyOF7Y=;
        b=nKs0sOZQDLuOOiP6sTujkpND9T6mzKTkv2kz2eP5O1pxIyEUZM4t7tYhFc3fRyM6Jb
         Qd15MaB/UZeVO7DO6sz2kFKK9e1rTI9C4DL8xAqPZkFvVSxa/qdxuXO74zPV+bM/w+HM
         xvFxLPRcdn9sgUG8eNHT8mRgqPezQo8GKLVQb6zVCmuU4SwSiW0Ii98wnXifiQ2y+tKp
         mg23qsk7xNuWCE9dSenadCYIJGgIHPtAtcfGGwVOKROEC/POxh/v8LX9FeucKdf27Fdy
         cxEwOkgZrRPQH11Wvn6z47d1nM05viZGdjJQzhn6vUZsV8nUKj3wjnsovANOXAJs4/zX
         t8OA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="rRH/DJ0i";
       spf=pass (google.com: domain of 3vao_ygykcxmxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3VAO_YgYKCXMXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id c38-20020a05651223a600b004811cb1ed75si648446lfv.13.2022.07.01.07.23.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vao_ygykcxmxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id r12-20020a05640251cc00b00435afb01d7fso1869426edd.18
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:16 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:906:5343:b0:722:ea54:fe67 with SMTP id
 j3-20020a170906534300b00722ea54fe67mr14451273ejo.181.1656685396004; Fri, 01
 Jul 2022 07:23:16 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:25 +0200
Message-Id: <20220701142310.2188015-1-glider@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 00/45] Add KernelMemorySanitizer infrastructure
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
 header.i=@google.com header.s=20210112 header.b="rRH/DJ0i";       spf=pass
 (google.com: domain of 3vao_ygykcxmxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3VAO_YgYKCXMXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
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

KernelMemorySanitizer (KMSAN) is a detector of errors related to uses of
uninitialized memory. It relies on compile-time Clang instrumentation
(similar to MSan in the userspace [1]) and tracks the state of every bit
of kernel memory, being able to report an error if uninitialized value
is used in a condition, dereferenced, or escapes to userspace, USB or
DMA.

KMSAN has reported more than 300 bugs in the past few years (recently
fixed bugs: [2]), most of them with the help of syzkaller. Such bugs
keep getting introduced into the kernel despite new compiler warnings
and other analyses (the 5.16 cycle already resulted in several
KMSAN-reported bugs, e.g. [3]). Mitigations like total stack and heap
initialization are unfortunately very far from being deployable.

The proposed patchset contains KMSAN runtime implementation together
with small changes to other subsystems needed to make KMSAN work.

The latter changes fall into several categories:

1. Changes and refactorings of existing code required to add KMSAN:
 - [01/45] x86: add missing include to sparsemem.h
 - [02/45] stackdepot: reserve 5 extra bits in depot_stack_handle_t
 - [03/45] instrumented.h: allow instrumenting both sides of copy_from_user()
 - [04/45] x86: asm: instrument usercopy in get_user() and __put_user_size()
 - [05/45] asm-generic: instrument usercopy in cacheflush.h
 - [10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE

2. KMSAN-related declarations in generic code, KMSAN runtime library,
   docs and configs:
 - [06/45] kmsan: add ReST documentation
 - [07/45] kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
 - [09/45] x86: kmsan: pgtable: reduce vmalloc space
 - [11/45] kmsan: add KMSAN runtime core
 - [13/45] MAINTAINERS: add entry for KMSAN
 - [25/45] kmsan: add tests for KMSAN
 - [32/45] objtool: kmsan: list KMSAN API functions as uaccess-safe
 - [36/45] x86: kmsan: use __msan_ string functions where possible
 - [45/45] x86: kmsan: enable KMSAN builds for x86

3. Adding hooks from different subsystems to notify KMSAN about memory
   state changes:
 - [14/45] mm: kmsan: maintain KMSAN metadata for page
 - [15/45] mm: kmsan: call KMSAN hooks from SLUB code
 - [16/45] kmsan: handle task creation and exiting
 - [17/45] init: kmsan: call KMSAN initialization routines
 - [18/45] instrumented.h: add KMSAN support
 - [20/45] kmsan: add iomap support
 - [21/45] Input: libps2: mark data received in __ps2_command() as initialized
 - [22/45] dma: kmsan: unpoison DMA mappings
 - [35/45] x86: kmsan: handle open-coded assembly in lib/iomem.c
 - [37/45] x86: kmsan: sync metadata pages on page fault

4. Changes that prevent false reports by explicitly initializing memory,
   disabling optimized code that may trick KMSAN, selectively skipping
   instrumentation:
 - [08/45] kmsan: mark noinstr as __no_sanitize_memory
 - [12/45] kmsan: disable instrumentation of unsupported common kernel code
 - [19/45] kmsan: unpoison @tlb in arch_tlb_gather_mmu()
 - [23/45] virtio: kmsan: check/unpoison scatterlist in vring_map_one_sg()
 - [24/45] kmsan: handle memory sent to/from USB
 - [26/45] kmsan: disable strscpy() optimization under KMSAN
 - [27/45] crypto: kmsan: disable accelerated configs under KMSAN
 - [28/45] kmsan: disable physical page merging in biovec
 - [29/45] block: kmsan: skip bio block merging logic for KMSAN
 - [30/45] kcov: kmsan: unpoison area->list in kcov_remote_area_put()
 - [31/45] security: kmsan: fix interoperability with auto-initialization
 - [33/45] x86: kmsan: disable instrumentation of unsupported code
 - [34/45] x86: kmsan: skip shadow checks in __switch_to()
 - [38/45] x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on x86, enable it for KASAN/KMSAN
 - [39/45] x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS
 - [40/45] x86: kmsan: don't instrument stack walking functions
 - [41/45] entry: kmsan: introduce kmsan_unpoison_entry_regs()

5. Fixes for bugs detected with CONFIG_KMSAN_CHECK_PARAM_RETVAL:
 - [42/45] bpf: kmsan: initialize BPF registers with zeroes
 - [43/45] namei: initialize parameters passed to step_into()
 - [44/45] mm: fs: initialize fsdata passed to write_begin/write_end interface


This patchset allows one to boot and run a defconfig+KMSAN kernel on a
QEMU without known false positives. It however doesn't guarantee there
are no false positives in drivers of certain devices or less tested
subsystems, although KMSAN is actively tested on syzbot with a large
config.

The biggest difference between this patch series and v3 is the
introduction of CONFIG_KMSAN_CHECK_PARAM_RETVAL, which maps to the
-fsanitize-memory-param-retval compiler flag and enforces conservative
checks of most kernel function parameters passed by value. As discussed
in [4], passing uninitialized values as function parameters is
considered undefined behavior, therefore KMSAN now reports such cases as
errors. Several newly added patches fix known manifestations of these
errors.

The patchset was generated relative to Linux v5.19-rc4. The most
up-to-date KMSAN tree currently resides at
https://github.com/google/kmsan/. One may find it handy to review these
patches in Gerrit [5].

A huge thanks goes to the reviewers of the RFC patch series sent to LKML
in 2020 ([6]).

[1] https://clang.llvm.org/docs/MemorySanitizer.html
[2] https://syzkaller.appspot.com/upstream/fixed?manager=ci-upstream-kmsan-gce
[3] https://lore.kernel.org/all/20211126124746.761278-1-glider@google.com/
[4] https://lore.kernel.org/all/20220614144853.3693273-1-glider@google.com/ 
[5] https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/12604/ 
[6] https://lore.kernel.org/all/20200325161249.55095-1-glider@google.com/

Alexander Potapenko (44):
  stackdepot: reserve 5 extra bits in depot_stack_handle_t
  instrumented.h: allow instrumenting both sides of copy_from_user()
  x86: asm: instrument usercopy in get_user() and __put_user_size()
  asm-generic: instrument usercopy in cacheflush.h
  kmsan: add ReST documentation
  kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
  kmsan: mark noinstr as __no_sanitize_memory
  x86: kmsan: pgtable: reduce vmalloc space
  libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
  kmsan: add KMSAN runtime core
  kmsan: disable instrumentation of unsupported common kernel code
  MAINTAINERS: add entry for KMSAN
  mm: kmsan: maintain KMSAN metadata for page operations
  mm: kmsan: call KMSAN hooks from SLUB code
  kmsan: handle task creation and exiting
  init: kmsan: call KMSAN initialization routines
  instrumented.h: add KMSAN support
  kmsan: unpoison @tlb in arch_tlb_gather_mmu()
  kmsan: add iomap support
  Input: libps2: mark data received in __ps2_command() as initialized
  dma: kmsan: unpoison DMA mappings
  virtio: kmsan: check/unpoison scatterlist in vring_map_one_sg()
  kmsan: handle memory sent to/from USB
  kmsan: add tests for KMSAN
  kmsan: disable strscpy() optimization under KMSAN
  crypto: kmsan: disable accelerated configs under KMSAN
  kmsan: disable physical page merging in biovec
  block: kmsan: skip bio block merging logic for KMSAN
  kcov: kmsan: unpoison area->list in kcov_remote_area_put()
  security: kmsan: fix interoperability with auto-initialization
  objtool: kmsan: list KMSAN API functions as uaccess-safe
  x86: kmsan: disable instrumentation of unsupported code
  x86: kmsan: skip shadow checks in __switch_to()
  x86: kmsan: handle open-coded assembly in lib/iomem.c
  x86: kmsan: use __msan_ string functions where possible
  x86: kmsan: sync metadata pages on page fault
  x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on x86, enable it for
    KASAN/KMSAN
  x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS
  x86: kmsan: don't instrument stack walking functions
  entry: kmsan: introduce kmsan_unpoison_entry_regs()
  bpf: kmsan: initialize BPF registers with zeroes
  namei: initialize parameters passed to step_into()
  mm: fs: initialize fsdata passed to write_begin/write_end interface
  x86: kmsan: enable KMSAN builds for x86

Dmitry Vyukov (1):
  x86: add missing include to sparsemem.h

 Documentation/dev-tools/index.rst       |   1 +
 Documentation/dev-tools/kmsan.rst       | 422 ++++++++++++++++++
 MAINTAINERS                             |  12 +
 Makefile                                |   1 +
 arch/s390/lib/uaccess.c                 |   3 +-
 arch/x86/Kconfig                        |   9 +-
 arch/x86/boot/Makefile                  |   1 +
 arch/x86/boot/compressed/Makefile       |   1 +
 arch/x86/entry/vdso/Makefile            |   3 +
 arch/x86/include/asm/checksum.h         |  16 +-
 arch/x86/include/asm/kmsan.h            |  55 +++
 arch/x86/include/asm/page_64.h          |  12 +
 arch/x86/include/asm/pgtable_64_types.h |  41 +-
 arch/x86/include/asm/sparsemem.h        |   2 +
 arch/x86/include/asm/string_64.h        |  23 +-
 arch/x86/include/asm/uaccess.h          |   7 +
 arch/x86/kernel/Makefile                |   2 +
 arch/x86/kernel/cpu/Makefile            |   1 +
 arch/x86/kernel/dumpstack.c             |   6 +
 arch/x86/kernel/process_64.c            |   1 +
 arch/x86/kernel/unwind_frame.c          |  11 +
 arch/x86/lib/Makefile                   |   2 +
 arch/x86/lib/iomem.c                    |   5 +
 arch/x86/mm/Makefile                    |   2 +
 arch/x86/mm/fault.c                     |  23 +-
 arch/x86/mm/init_64.c                   |   2 +-
 arch/x86/mm/ioremap.c                   |   3 +
 arch/x86/realmode/rm/Makefile           |   1 +
 block/bio.c                             |   2 +
 block/blk.h                             |   7 +
 crypto/Kconfig                          |  30 ++
 drivers/firmware/efi/libstub/Makefile   |   1 +
 drivers/input/serio/libps2.c            |   5 +-
 drivers/net/Kconfig                     |   1 +
 drivers/nvdimm/nd.h                     |   2 +-
 drivers/nvdimm/pfn_devs.c               |   2 +-
 drivers/usb/core/urb.c                  |   2 +
 drivers/virtio/virtio_ring.c            |  10 +-
 fs/buffer.c                             |   4 +-
 fs/namei.c                              |  10 +-
 include/asm-generic/cacheflush.h        |   9 +-
 include/linux/compiler-clang.h          |  23 +
 include/linux/compiler-gcc.h            |   6 +
 include/linux/compiler_types.h          |   3 +-
 include/linux/fortify-string.h          |   2 +
 include/linux/highmem.h                 |   3 +
 include/linux/instrumented.h            |  26 +-
 include/linux/kmsan-checks.h            |  83 ++++
 include/linux/kmsan.h                   | 362 ++++++++++++++++
 include/linux/mm_types.h                |  12 +
 include/linux/sched.h                   |   5 +
 include/linux/stackdepot.h              |   8 +
 include/linux/uaccess.h                 |  19 +-
 init/main.c                             |   3 +
 kernel/Makefile                         |   1 +
 kernel/bpf/core.c                       |   2 +-
 kernel/dma/mapping.c                    |   9 +-
 kernel/entry/common.c                   |   5 +
 kernel/exit.c                           |   2 +
 kernel/fork.c                           |   2 +
 kernel/kcov.c                           |   7 +
 kernel/locking/Makefile                 |   3 +-
 lib/Kconfig.debug                       |   1 +
 lib/Kconfig.kmsan                       |  62 +++
 lib/Makefile                            |   3 +
 lib/iomap.c                             |  44 ++
 lib/iov_iter.c                          |   9 +-
 lib/stackdepot.c                        |  29 +-
 lib/string.c                            |   8 +
 lib/usercopy.c                          |   3 +-
 mm/Makefile                             |   1 +
 mm/filemap.c                            |   2 +-
 mm/internal.h                           |   6 +
 mm/kasan/common.c                       |   2 +-
 mm/kmsan/Makefile                       |  28 ++
 mm/kmsan/core.c                         | 468 ++++++++++++++++++++
 mm/kmsan/hooks.c                        | 395 +++++++++++++++++
 mm/kmsan/init.c                         | 238 ++++++++++
 mm/kmsan/instrumentation.c              | 271 ++++++++++++
 mm/kmsan/kmsan.h                        | 195 +++++++++
 mm/kmsan/kmsan_test.c                   | 552 ++++++++++++++++++++++++
 mm/kmsan/report.c                       | 211 +++++++++
 mm/kmsan/shadow.c                       | 297 +++++++++++++
 mm/memory.c                             |   2 +
 mm/mmu_gather.c                         |  10 +
 mm/page_alloc.c                         |  18 +
 mm/slab.h                               |   1 +
 mm/slub.c                               |  18 +
 mm/vmalloc.c                            |  20 +-
 scripts/Makefile.kmsan                  |   8 +
 scripts/Makefile.lib                    |   9 +
 security/Kconfig.hardening              |   4 +
 tools/objtool/check.c                   |  20 +
 93 files changed, 4222 insertions(+), 52 deletions(-)
 create mode 100644 Documentation/dev-tools/kmsan.rst
 create mode 100644 arch/x86/include/asm/kmsan.h
 create mode 100644 include/linux/kmsan-checks.h
 create mode 100644 include/linux/kmsan.h
 create mode 100644 lib/Kconfig.kmsan
 create mode 100644 mm/kmsan/Makefile
 create mode 100644 mm/kmsan/core.c
 create mode 100644 mm/kmsan/hooks.c
 create mode 100644 mm/kmsan/init.c
 create mode 100644 mm/kmsan/instrumentation.c
 create mode 100644 mm/kmsan/kmsan.h
 create mode 100644 mm/kmsan/kmsan_test.c
 create mode 100644 mm/kmsan/report.c
 create mode 100644 mm/kmsan/shadow.c
 create mode 100644 scripts/Makefile.kmsan

-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-1-glider%40google.com.
