Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGWV26MAMGQEFXTPEJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 164335AD24B
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:24:59 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id hp14-20020a1709073e0e00b00741a2093c4asf2310699ejc.20
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:24:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380698; cv=pass;
        d=google.com; s=arc-20160816;
        b=kpueWq7oNHC9HHW8klCeMA/YUNUZsU0CBBipxffWRSkpmIPJxW94Lmhn9m/w9Kjs9G
         jAO6oliTX77qNHgDPZ2MVuYjyarKIC9rye5RJDzdGFQGX4nz0nnNSrc6QIiArAikp6pg
         WMQRWonWSPRgmBc4NzeAmm2AdUdw7slpoxrK64pqm1kKu/b1uVXa2f7GsZ+sNo3jnZMx
         6IEE5aVb4oehm9r0Gfja3jV5TuYHCIhh4praSlGweaIdluHJTc1vjyauAHip50X3u5Ij
         Dt/8yQNw1oLpEoj/ABMwHHKdcI9B7xvkTkIelyJ13/A0DyHwTXexXsgzBdsyzjFDUth2
         6LuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=sn0dWUSq825n16lLq2xtZmw0cJd90xQdzViEZs5NRIc=;
        b=d767n+abDQVTHUH495r8g8UhSMTqEGUUfJiEB4qDSBZMTs3RWDsZQx5UFJDNgtHR5W
         6V1O4ZegEJLLB3wk4jvl8CQafrppK1qi9cfLEMYzZzdIX8+5pa16NkxfcB0+cB8VuHpA
         xx78uuustuzev/Ym4H1aPBw8iZLrV6WSaC3fTW7my/ZgZz1growOfzaitO6SNjzg29oQ
         J5oGLxDYvN9e//TCwMFH1X3XPDfi7N8Hq4yZJQwyB7M2q3vqeyyb2Dq2itRXu2B56pAe
         RmPwLVrhIiAGcvCcLCVx/hSbGRMMAhkvgdbBZ1TqV1OvZjRY59c+0vNmTWe7jgjHc8rt
         tyMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qIFPN9Ok;
       spf=pass (google.com: domain of 3moovywykcemlqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3mOoVYwYKCeMLQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date;
        bh=sn0dWUSq825n16lLq2xtZmw0cJd90xQdzViEZs5NRIc=;
        b=rn/5ps4G7GeXbCOjVhSjWhMJdL20W/O4S8ZTBz5XQM145cAjjOybCV8L9W+CLh1ZK6
         ZhE7EzW9j4LYUgq/XAJQGv2YU7ezhQs5ajWfqKCAObrlXo7p8NUYw6lQ/1odNLove95G
         cHu6WjKtkxfeK97nNGTf8fpbkpBHEfPH6uH8j0TXToGDoGI97NwUyN5U0viaSoOSKp3/
         zpLMzf5X07iRjk+YNhBqqUmI/+LN5UZFUxQfXriavfiKUljJiEOdUDXA1OZeA4HQ13XS
         Anfdsswha9VWcAC0TchfgMD61hHjUEkRndPXJ5q6/5nnESVOjce+9EOw44KvZ/XVpRYu
         FwXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date;
        bh=sn0dWUSq825n16lLq2xtZmw0cJd90xQdzViEZs5NRIc=;
        b=s/8nIQL0Tc+sCwG7D2s/BOsVMvujKts9iPkqweyvuPLXn7nBwTr0q8gjOrJ+Aq9YjU
         zliKaxJcLTGcogbxJhI6qF55BYHueoN4DH2ylGv2pGmM8rvkJM1l2NdBSOX7pH6Lyc6D
         6UJ7ip3sDKCJx2texFruiifTUMuFxNUett++bhOKhaeTLlg2IWIzr0oGeE9wyST5Sl2u
         c72tQ7dzs3skbWcYYrG3UdV9gYl1bF1MJDHbzgCJT29ExwMgqYJmz7K0DVwN2QNPB2QQ
         799reTZB6xy4X9OHAS7U4F1Kizar+xCsONwd30sT+vTZvN1Uadw+negR43ckYaRbLpEb
         B6EA==
X-Gm-Message-State: ACgBeo397nH72LxTTnrLaAV6bjIF74JmagVls9J+JxdvUtXfxFIbuei1
	nMZ7OWP10DWwllOYhYZRp3k=
X-Google-Smtp-Source: AA6agR5VVsgEeLGjREejM2dDf45GKRkvHVBm8xqIio9Gt5nkBn6BQeD1sEXR6Zz79ltovkViF5Llug==
X-Received: by 2002:a05:6402:274e:b0:447:4e9d:69e8 with SMTP id z14-20020a056402274e00b004474e9d69e8mr43219449edd.295.1662380698411;
        Mon, 05 Sep 2022 05:24:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:880f:b0:73d:afe3:ffd9 with SMTP id
 zh15-20020a170906880f00b0073dafe3ffd9ls3420713ejb.10.-pod-prod-gmail; Mon, 05
 Sep 2022 05:24:57 -0700 (PDT)
X-Received: by 2002:a17:907:86a9:b0:741:79ed:63c5 with SMTP id qa41-20020a17090786a900b0074179ed63c5mr26707703ejc.672.1662380697264;
        Mon, 05 Sep 2022 05:24:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380697; cv=none;
        d=google.com; s=arc-20160816;
        b=dHuFuaatNpGm3tX4ZFUpSZdLerg6lmjtbC2FogJjK0A8J2A8yD3AFbPOUlAo6llVde
         Xw5CdQnNXGv9VL0IW93s3PGRjmm0duj2Mz8jyFYfs9DIvoyDl4z4phRQlre8vt7olUNo
         hbXB9wn5R/BkXaD6NTzhQ6H4yiMxdp+D5wLeck1jcYj2yEoOo8gpSwGsSgP0Did75BwW
         lFGFC3tSVQesSjcEiqHC8+EL5o084ZVIslvqEksbD0mM2QWgdmsW1VeYyM4GJBSzJoZ+
         Mex9p21aOes6Jxl32iSz74cKpKuHi4jJPjSjjaUrnEWEJGKzhcCSRlNZg6LdSxslOQFd
         6nfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=RhEZT1SNq0NPBQzxON055CwG2z9S9v0DBpHgk5coq2c=;
        b=MoJCwpMeYWKyaz4gYQsPUqoSHht7aigII1ARtn9VmuxC4FenWzQwhswIoOuASxve2A
         lvs4HkAkGLsNiAqu6HPBoyr5x07NyxKWVoZ8qEyDkJ0bi3XBJLHR/PNT+struaAYFHOl
         NunisvS6BdrzeB7CfUdUM+drICIrjG0n0EkMurnV8OlWEQ/iUTVgstuPETTotPj8H2ju
         x5CHJFhmJ+ve3NUDYkK3ICMXoi0DQEiapLKGsnl7kgpIj2ZEFn79VhKDcpl4EKL0QNoV
         zis2LqjHgtSpnyG1Ay3CgyWaR2mXoki2Nju+WrJi6g3qWrKN7UdMRI23bqHyYXtFTOhj
         qe9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qIFPN9Ok;
       spf=pass (google.com: domain of 3moovywykcemlqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3mOoVYwYKCeMLQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id s17-20020aa7c551000000b0044609bb9ed0si171134edr.1.2022.09.05.05.24.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:24:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3moovywykcemlqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id he38-20020a1709073da600b0073d98728570so2283222ejc.11
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:24:57 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:3dab:b0:741:9a23:eb01 with SMTP id
 he43-20020a1709073dab00b007419a23eb01mr25839379ejc.26.1662380696610; Mon, 05
 Sep 2022 05:24:56 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:08 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-1-glider@google.com>
Subject: [PATCH v6 00/44] Add KernelMemorySanitizer infrastructure
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
 header.i=@google.com header.s=20210112 header.b=qIFPN9Ok;       spf=pass
 (google.com: domain of 3moovywykcemlqnijwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3mOoVYwYKCeMLQNIJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--glider.bounces.google.com;
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
and other analyses (the 6.0 cycle already resulted in several
KMSAN-reported bugs, e.g. [3]). Mitigations like total stack and heap
initialization are unfortunately very far from being deployable.

The proposed patchset contains KMSAN runtime implementation together
with small changes to other subsystems needed to make KMSAN work.

The latter changes fall into several categories:

1. Changes and refactorings of existing code required to add KMSAN:
 - [01/44] x86: add missing include to sparsemem.h
 - [02/44] stackdepot: reserve 5 extra bits in depot_stack_handle_t
 - [03/44] instrumented.h: allow instrumenting both sides of copy_from_user()
 - [04/44] x86: asm: instrument usercopy in get_user() and __put_user_size()
 - [05/44] asm-generic: instrument usercopy in cacheflush.h
 - [10/44] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE

2. KMSAN-related declarations in generic code, KMSAN runtime library,
   docs and configs:
 - [06/44] kmsan: add ReST documentation
 - [07/44] kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
 - [09/44] x86: kmsan: pgtable: reduce vmalloc space
 - [11/44] kmsan: add KMSAN runtime core
 - [13/44] MAINTAINERS: add entry for KMSAN
 - [25/44] kmsan: add tests for KMSAN
 - [32/44] objtool: kmsan: list KMSAN API functions as uaccess-safe
 - [36/44] x86: kmsan: use __msan_ string functions where possible
 - [44/44] x86: kmsan: enable KMSAN builds for x86

3. Adding hooks from different subsystems to notify KMSAN about memory
   state changes:
 - [14/44] mm: kmsan: maintain KMSAN metadata for page
 - [15/44] mm: kmsan: call KMSAN hooks from SLUB code
 - [16/44] kmsan: handle task creation and exiting
 - [17/44] init: kmsan: call KMSAN initialization routines
 - [18/44] instrumented.h: add KMSAN support
 - [20/44] kmsan: add iomap support
 - [21/44] Input: libps2: mark data received in __ps2_command() as initialized
 - [22/44] dma: kmsan: unpoison DMA mappings
 - [35/44] x86: kmsan: handle open-coded assembly in lib/iomem.c
 - [37/43] x86: kmsan: sync metadata pages on page fault

4. Changes that prevent false reports by explicitly initializing memory,
   disabling optimized code that may trick KMSAN, selectively skipping
   instrumentation:
 - [08/44] kmsan: mark noinstr as __no_sanitize_memory
 - [12/44] kmsan: disable instrumentation of unsupported common kernel code
 - [19/44] kmsan: unpoison @tlb in arch_tlb_gather_mmu()
 - [23/44] virtio: kmsan: check/unpoison scatterlist in vring_map_one_sg()
 - [24/44] kmsan: handle memory sent to/from USB
 - [26/44] kmsan: disable strscpy() optimization under KMSAN
 - [27/44] crypto: kmsan: disable accelerated configs under KMSAN
 - [28/44] kmsan: disable physical page merging in biovec
 - [29/44] block: kmsan: skip bio block merging logic for KMSAN
 - [30/44] kcov: kmsan: unpoison area->list in kcov_remote_area_put()
 - [31/44] security: kmsan: fix interoperability with auto-initialization
 - [33/44] x86: kmsan: disable instrumentation of unsupported code
 - [34/44] x86: kmsan: skip shadow checks in __switch_to()
 - [38/44] x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on x86, enable it for KASAN/KMSAN
 - [39/44] x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS
 - [40/44] x86: kmsan: don't instrument stack walking functions
 - [41/44] entry: kmsan: introduce kmsan_unpoison_entry_regs()

5. Fixes for bugs detected with CONFIG_KMSAN_CHECK_PARAM_RETVAL:
 - [42/44] bpf: kmsan: initialize BPF registers with zeroes
 - [43/44] mm: fs: initialize fsdata passed to write_begin/write_end interface


This patchset allows one to boot and run a defconfig+KMSAN kernel on a
QEMU without known false positives. It however doesn't guarantee there
are no false positives in drivers of certain devices or less tested
subsystems, although KMSAN is actively tested on syzbot with a large
config.

By default, KMSAN enforces conservative checks of most kernel function
parameters passed by value (via CONFIG_KMSAN_CHECK_PARAM_RETVAL, which
maps to the -fsanitize-memory-param-retval compiler flag). As discussed
in [4] and [5], passing uninitialized values as function parameters is
considered undefined behavior, therefore KMSAN now reports such cases as
errors. Several newly added patches fix known manifestations of these
errors.

The patchset was generated relative to Linux v6.0-rc4. The most
up-to-date KMSAN tree currently resides at
https://github.com/google/kmsan/. One may find it handy to review these
patches in Gerrit [6].

A huge thanks goes to the reviewers of the RFC patch series sent to LKML
in 2020 ([7]).

[1] https://clang.llvm.org/docs/MemorySanitizer.html
[2] https://syzkaller.appspot.com/upstream/fixed?manager=ci-upstream-kmsan-gce
[3] https://lore.kernel.org/all/0000000000002c7abf05e721698d@google.com/
[4] https://lore.kernel.org/all/20220614144853.3693273-1-glider@google.com/ 
[5] https://lore.kernel.org/linux-mm/20220701142310.2188015-45-glider@google.com/
[6] https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/12604/ 
[7] https://lore.kernel.org/all/20200325161249.55095-1-glider@google.com/

Alexander Potapenko (43):
  stackdepot: reserve 5 extra bits in depot_stack_handle_t
  instrumented.h: allow instrumenting both sides of copy_from_user()
  x86: asm: instrument usercopy in get_user() and put_user()
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
  x86: kmsan: use __msan_ string functions where possible.
  x86: kmsan: sync metadata pages on page fault
  x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on x86, enable it for
    KASAN/KMSAN
  x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS
  x86: kmsan: don't instrument stack walking functions
  entry: kmsan: introduce kmsan_unpoison_entry_regs()
  bpf: kmsan: initialize BPF registers with zeroes
  mm: fs: initialize fsdata passed to write_begin/write_end interface
  x86: kmsan: enable KMSAN builds for x86

Dmitry Vyukov (1):
  x86: add missing include to sparsemem.h

 Documentation/dev-tools/index.rst       |   1 +
 Documentation/dev-tools/kmsan.rst       | 427 ++++++++++++++++++
 MAINTAINERS                             |  13 +
 Makefile                                |   1 +
 arch/s390/lib/uaccess.c                 |   3 +-
 arch/x86/Kconfig                        |   9 +-
 arch/x86/boot/Makefile                  |   1 +
 arch/x86/boot/compressed/Makefile       |   1 +
 arch/x86/entry/vdso/Makefile            |   3 +
 arch/x86/include/asm/checksum.h         |  16 +-
 arch/x86/include/asm/kmsan.h            |  55 +++
 arch/x86/include/asm/page_64.h          |   7 +
 arch/x86/include/asm/pgtable_64_types.h |  47 +-
 arch/x86/include/asm/sparsemem.h        |   2 +
 arch/x86/include/asm/string_64.h        |  23 +-
 arch/x86/include/asm/uaccess.h          |  22 +-
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
 fs/namei.c                              |   2 +-
 include/asm-generic/cacheflush.h        |  14 +-
 include/linux/compiler-clang.h          |  23 +
 include/linux/compiler-gcc.h            |   6 +
 include/linux/compiler_types.h          |   3 +-
 include/linux/fortify-string.h          |   2 +
 include/linux/highmem.h                 |   3 +
 include/linux/instrumented.h            |  59 ++-
 include/linux/kmsan-checks.h            |  83 ++++
 include/linux/kmsan.h                   | 330 ++++++++++++++
 include/linux/kmsan_types.h             |  35 ++
 include/linux/mm_types.h                |  12 +
 include/linux/sched.h                   |   5 +
 include/linux/stackdepot.h              |   8 +
 include/linux/uaccess.h                 |  19 +-
 init/main.c                             |   3 +
 kernel/Makefile                         |   1 +
 kernel/bpf/core.c                       |   2 +-
 kernel/dma/mapping.c                    |  10 +-
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
 mm/kmsan/core.c                         | 458 ++++++++++++++++++++
 mm/kmsan/hooks.c                        | 384 +++++++++++++++++
 mm/kmsan/init.c                         | 235 ++++++++++
 mm/kmsan/instrumentation.c              | 307 +++++++++++++
 mm/kmsan/kmsan.h                        | 208 +++++++++
 mm/kmsan/kmsan_test.c                   | 552 ++++++++++++++++++++++++
 mm/kmsan/report.c                       | 211 +++++++++
 mm/kmsan/shadow.c                       | 294 +++++++++++++
 mm/memory.c                             |   2 +
 mm/mmu_gather.c                         |  10 +
 mm/page_alloc.c                         |  19 +
 mm/slab.h                               |   1 +
 mm/slub.c                               |  17 +
 mm/vmalloc.c                            |  20 +-
 scripts/Makefile.kmsan                  |   8 +
 scripts/Makefile.lib                    |   9 +
 security/Kconfig.hardening              |   4 +
 tools/objtool/check.c                   |  20 +
 94 files changed, 4296 insertions(+), 56 deletions(-)
 create mode 100644 Documentation/dev-tools/kmsan.rst
 create mode 100644 arch/x86/include/asm/kmsan.h
 create mode 100644 include/linux/kmsan-checks.h
 create mode 100644 include/linux/kmsan.h
 create mode 100644 include/linux/kmsan_types.h
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-1-glider%40google.com.
