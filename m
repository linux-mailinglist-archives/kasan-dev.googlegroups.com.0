Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZOCUCJQMGQE6WNAKDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C500E5103D6
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:22 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id c11-20020a056512104b00b00471f86be758sf4028016lfb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991462; cv=pass;
        d=google.com; s=arc-20160816;
        b=H9Nkk1ZPGQmkgR3S1GYmK4ZBZLAC6VDKwI/HbzLRgmF4vqUXFAGFfPDGsikpsMdXjH
         K+qh370eTH/D/1omJ/nB4NBfQBcCcaJKppMXvFTDiCH6XLCYdmRAVCHURmlYMKjEO9MY
         OsN2JQNjoPPjLclmWoau6uLr/hAHQWFj63JgXjjkdJC/ZFGkpH4w0vG+LxTdASh6Hl+j
         EOhDTQJch24ouHbMKBHaAJRnEIQCeOJICilFzIfk8Rdw/YIfOpVyTK3T1FU6ynoTSd1k
         1TI1YShtNEbuK5VycBoF/PQMUjYBLRDANwTXDlCYPlQcOt8ab463C/gnf/s0iZV8CO1Z
         BsbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=J4XJOqRcsZiWbje69Fpt6fkxV8Qg2eKW2MxPnXe3ZM8=;
        b=VIk5wTRrunrAfYpkP1w2zhAN5qSmUpjLut8qhSZgUVGmV0rV26EcdunMvc8k5EGf7F
         W+9mpDIBcSSAV098XLVvQ6xRuoOGqZG9xvgDjngaqhnbFsIDFwqezADhn/Vz6c3bu8xi
         WAlsTP751NXL/UJaQhQrbKWzh2UHb/ZhEvqPaxUwFfWmcWEswPBcIsz3FyjXDYGJqq9O
         NAmJmodCKPFFNmYOgNvCBoPfB5fMHEW018cRS6bvwNdbjZPpUL710csGdX7WKSKfazj/
         vqCDsw4bApY2gBR3YucCyw+HFG3zv/kj+iXdTmnT3aAyxXli2joAwgT28SUd+4JAp/iz
         +iwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=H02YMRXj;
       spf=pass (google.com: domain of 3zcfoygykcwefkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ZCFoYgYKCWEFKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=J4XJOqRcsZiWbje69Fpt6fkxV8Qg2eKW2MxPnXe3ZM8=;
        b=mR0rauNVuRHfAy+jLwSX6dZDjj59z0BpASqb3jJuzh5LveBdjSuxNFVSD/LUlSJx8e
         TzZHAu/JEvIf4Psu6MQbxY7QbrnbOJyI0xy9T2pfpo3vApbr7qDv2nSV+2KXkl3DGDwJ
         DYvpJt0NO0TLefzZdYi9MTaX4WY5VWod64XFkkdEQMWmwAMZnxUJZ83fwLS0s7kkIcyj
         gXNO9RqVtc7Bo9Z8diXInQc7tlDzR2+XToHNpJmT+LlyRpW5dZdtB5VTCkEwPV+1mUMc
         mPMoU9ZU4WcFMUKz2CRsxcMs4S+eZh+/QQ64dr3uTnRz9Lkmg6E3sa+iHes1miAy/fps
         Aniw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J4XJOqRcsZiWbje69Fpt6fkxV8Qg2eKW2MxPnXe3ZM8=;
        b=AoDAXvgQ79y8C2/JOUQOSIXxC4POVvQtYqjhZRAKoxY6VI5KOt69/EKzgMlhAVHZiY
         KUEKgzxyl9JtqpYwlq3c/90fzy7Bqa2WqWQ1P5pJneSdEXpyRqrNa0FwWvZvyYH8ZQ2b
         o5J2G6kHPztLYrN73VU6CJq2yIFE/egWUjfkGCh0H7aLWfohOYgp5GPkTOAF2ZmXfOsj
         Ojf3HIEaw7IevIUkQZL9yGPVNNJLX/qWzRK9eYKcmSuftB23q9rXcovtbKBFxHmPhC80
         z1F+v5D4TPGNA3Pk2ZTbo/O0sUlG1g/Xmc4KBJ5hSjZjPEL9CUJTPYe9aenWofC89bja
         KniA==
X-Gm-Message-State: AOAM530h1q79f3xOorr7lTPh8WCpLJVyzWiv/TClIHqgZInG4KSZpw7w
	50TrD4AoxnzR+CJVJ+9VJ+o=
X-Google-Smtp-Source: ABdhPJyDsr1LnzPPw5lTirJ8eE1D+8xjQg3D3Esq4d1ILBjnlcBLLHe//BkDHqidmWMxC2hX4V5Xsw==
X-Received: by 2002:a05:6512:1108:b0:471:a7b3:829c with SMTP id l8-20020a056512110800b00471a7b3829cmr17020349lfg.107.1650991462239;
        Tue, 26 Apr 2022 09:44:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc0c:0:b0:24f:1432:3be with SMTP id b12-20020a2ebc0c000000b0024f143203bels1213665ljf.8.gmail;
 Tue, 26 Apr 2022 09:44:20 -0700 (PDT)
X-Received: by 2002:a2e:b888:0:b0:24e:f119:8fce with SMTP id r8-20020a2eb888000000b0024ef1198fcemr14654357ljp.48.1650991460731;
        Tue, 26 Apr 2022 09:44:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991460; cv=none;
        d=google.com; s=arc-20160816;
        b=eHWqKPoOp99kpY/yB2E2zq9jRKQaHbfc9WgO4/VJgpJ1UvIAXObhZFqpZCrOE8Zgy4
         hrR/naMPsqJlhivizX2Ts+6Qf5m4DLAWwggoOSKThBjMHnBScG5tPtKdbj+WLi84xK8r
         mt2X6uDQP8WFqCjUotSFV1YLclwx0KfrDqx1Y1Za+VCkKYbhJ2ncJFE8SnM+ogzNx995
         87bGbE96AC565lD7m+/WsssVVlR47dfRW0eQm6OBKNsoH5TXor5HY+Do9ojjmr0OHURO
         T3NmdxXO3Dr5itZA3bZHzNuYlosf65UD/LuXQtVfZ9E7QciFQ8K2qLP6EU0AFDRcIdyi
         T3ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=1G8xzyhN/6cC/oSos2efdoQedsBkWbUJY6WrTftKsiQ=;
        b=y235vOX1P6GpYY0q6ZfhCQ9LWJQU4BdCF2I3NRl2nh0jWfW/mALdCSfJhUgMuYmsLP
         kcO9q32DN9VNr7+LAF+1CxTBMqZs08UNzRKxtvxw0WsFSSQJDEhyI3HNbJPihCCfR15b
         nlJLy9VylFRyPLGeGok4kKAjerFIouQQaFTlxJM9o/BcCPTyGQDf1Fz0R8aZ9jaBwYwK
         WIzxUUFVLHr1p+Rbg1kLziSDyC2IMeK1PVX/PWofT57ArqRcIrDNtrWliRnyScsnylcu
         2i9V5l/XKrh05rKjWrugP1MQBWQP8Y/REuhvlfCe+9pFDW0Ux2jyci0ZlmQpHUu3iw1D
         E9cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=H02YMRXj;
       spf=pass (google.com: domain of 3zcfoygykcwefkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ZCFoYgYKCWEFKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id t8-20020a19dc08000000b004719503b360si829890lfg.13.2022.04.26.09.44.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zcfoygykcwefkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id co27-20020a0564020c1b00b00425ab566200so8062934edb.6
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:20 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:aa7:cb93:0:b0:415:d57a:4603 with SMTP id
 r19-20020aa7cb93000000b00415d57a4603mr25274990edt.62.1650991460014; Tue, 26
 Apr 2022 09:44:20 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:29 +0200
Message-Id: <20220426164315.625149-1-glider@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 00/46] Add KernelMemorySanitizer infrastructure
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=H02YMRXj;       spf=pass
 (google.com: domain of 3zcfoygykcwefkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ZCFoYgYKCWEFKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
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
of kernel memory, being able to report an error if uninitialized value is
used in a condition, dereferenced, or escapes to userspace, USB or DMA.

KMSAN has reported more than 300 bugs in the past few years (recently
fixed bugs: [2]), most of them with the help of syzkaller. Such bugs
keep getting introduced into the kernel despite new compiler warnings and
other analyses (the 5.16 cycle already resulted in several KMSAN-reported
bugs, e.g. [3]). Mitigations like total stack and heap initialization are
unfortunately very far from being deployable.

The proposed patchset contains KMSAN runtime implementation together with
small changes to other subsystems needed to make KMSAN work.

The latter changes fall into several categories:

1. Changes and refactorings of existing code required to add KMSAN:
 - [1/46] x86: add missing include to sparsemem.h
 - [2/46] stackdepot: reserve 5 extra bits in depot_stack_handle_t
 - [3/46] kasan: common: adapt to the new prototype of __stack_depot_save()
 - [4/46] instrumented.h: allow instrumenting both sides of copy_from_user()
 - [5/46] x86: asm: instrument usercopy in get_user() and __put_user_size()
 - [6/46] asm-generic: instrument usercopy in cacheflush.h
 - [11/46] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE

2. KMSAN-related declarations in generic code, KMSAN runtime library,
   docs and configs:
 - [7/46] kmsan: add ReST documentation
 - [8/46] kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
 - [10/46] x86: kmsan: pgtable: reduce vmalloc space
 - [12/46] kmsan: add KMSAN runtime core
 - [15/46] MAINTAINERS: add entry for KMSAN
 - [29/46] kmsan: add tests for KMSAN
 - [36/46] objtool: kmsan: list KMSAN API functions as uaccess-safe
 - [41/46] x86: kmsan: use __msan_ string functions where possible.
 - [46/46] x86: kmsan: enable KMSAN builds for x86

3. Adding hooks from different subsystems to notify KMSAN about memory
   state changes:
 - [16/46] kmsan: mm: maintain KMSAN metadata for page operations
 - [17/46] kmsan: mm: call KMSAN hooks from SLUB code
 - [18/46] kmsan: handle task creation and exiting
 - [19/46] kmsan: init: call KMSAN initialization routines
 - [20/46] instrumented.h: add KMSAN support
 - [22/46] kmsan: add iomap support
 - [23/46] Input: libps2: mark data received in __ps2_command() as initialized
 - [24/46] kmsan: dma: unpoison DMA mappings
 - [40/46] x86: kmsan: handle open-coded assembly in lib/iomem.c
 - [42/46] x86: kmsan: sync metadata pages on page fault

4. Changes that prevent false reports by explicitly initializing memory,
   disabling optimized code that may trick KMSAN, selectively skipping
   instrumentation:
 - [13/46] kmsan: implement kmsan_init(), initialize READ_ONCE_NOCHECK()
 - [14/46] kmsan: disable instrumentation of unsupported common kernel code
 - [21/46] kmsan: unpoison @tlb in arch_tlb_gather_mmu()
 - [25/46] kmsan: virtio: check/unpoison scatterlist in vring_map_one_sg()
 - [26/46] kmsan: handle memory sent to/from USB
 - [30/46] kmsan: disable strscpy() optimization under KMSAN
 - [31/46] crypto: kmsan: disable accelerated configs under KMSAN
 - [32/46] kmsan: disable physical page merging in biovec
 - [33/46] kmsan: block: skip bio block merging logic for KMSAN
 - [34/46] kmsan: kcov: unpoison area->list in kcov_remote_area_put()
 - [35/46] security: kmsan: fix interoperability with auto-initialization
 - [37/46] x86: kmsan: make READ_ONCE_TASK_STACK() return initialized values
 - [38/46] x86: kmsan: disable instrumentation of unsupported code
 - [39/46] x86: kmsan: skip shadow checks in __switch_to()
 - [43/46] x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on x86, enable it for KASAN/KMSAN
 - [44/46] x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS

5. Noinstr handling:
 - [9/46] kmsan: mark noinstr as __no_sanitize_memory
 - [27/46] kmsan: instrumentation.h: add instrumentation_begin_with_regs()
 - [28/46] kmsan: entry: handle register passing from uninstrumented code
 - [45/46] x86: kmsan: handle register passing from uninstrumented code

This patchset allows one to boot and run a defconfig+KMSAN kernel on a
QEMU without known false positives. It however doesn't guarantee there
are no false positives in drivers of certain devices or less tested
subsystems, although KMSAN is actively tested on syzbot with a large
config.

The patchset was generated relative to Linux v5.18-rc4. The most
up-to-date KMSAN tree currently resides at
https://github.com/google/kmsan/.
One may find it handy to review these patches in Gerrit:
https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/12604/25

A huge thanks goes to the reviewers of the RFC patch series sent to LKML
in 2020
(https://lore.kernel.org/all/20200325161249.55095-1-glider@google.com/).

[1] https://clang.llvm.org/docs/MemorySanitizer.html
[2] https://syzkaller.appspot.com/upstream/fixed?manager=ci-upstream-kmsan-gce
[3] https://lore.kernel.org/all/20211126124746.761278-1-glider@google.com/


Alexander Potapenko (45):
  stackdepot: reserve 5 extra bits in depot_stack_handle_t
  kasan: common: adapt to the new prototype of __stack_depot_save()
  instrumented.h: allow instrumenting both sides of copy_from_user()
  x86: asm: instrument usercopy in get_user() and __put_user_size()
  asm-generic: instrument usercopy in cacheflush.h
  kmsan: add ReST documentation
  kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
  kmsan: mark noinstr as __no_sanitize_memory
  x86: kmsan: pgtable: reduce vmalloc space
  libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
  kmsan: add KMSAN runtime core
  kmsan: implement kmsan_init(), initialize READ_ONCE_NOCHECK()
  kmsan: disable instrumentation of unsupported common kernel code
  MAINTAINERS: add entry for KMSAN
  kmsan: mm: maintain KMSAN metadata for page operations
  kmsan: mm: call KMSAN hooks from SLUB code
  kmsan: handle task creation and exiting
  kmsan: init: call KMSAN initialization routines
  instrumented.h: add KMSAN support
  kmsan: unpoison @tlb in arch_tlb_gather_mmu()
  kmsan: add iomap support
  Input: libps2: mark data received in __ps2_command() as initialized
  kmsan: dma: unpoison DMA mappings
  kmsan: virtio: check/unpoison scatterlist in vring_map_one_sg()
  kmsan: handle memory sent to/from USB
  kmsan: instrumentation.h: add instrumentation_begin_with_regs()
  kmsan: entry: handle register passing from uninstrumented code
  kmsan: add tests for KMSAN
  kmsan: disable strscpy() optimization under KMSAN
  crypto: kmsan: disable accelerated configs under KMSAN
  kmsan: disable physical page merging in biovec
  kmsan: block: skip bio block merging logic for KMSAN
  kmsan: kcov: unpoison area->list in kcov_remote_area_put()
  security: kmsan: fix interoperability with auto-initialization
  objtool: kmsan: list KMSAN API functions as uaccess-safe
  x86: kmsan: make READ_ONCE_TASK_STACK() return initialized values
  x86: kmsan: disable instrumentation of unsupported code
  x86: kmsan: skip shadow checks in __switch_to()
  x86: kmsan: handle open-coded assembly in lib/iomem.c
  x86: kmsan: use __msan_ string functions where possible.
  x86: kmsan: sync metadata pages on page fault
  x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on x86, enable it for
    KASAN/KMSAN
  x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS
  x86: kmsan: handle register passing from uninstrumented code
  x86: kmsan: enable KMSAN builds for x86

Dmitry Vyukov (1):
  x86: add missing include to sparsemem.h

 Documentation/dev-tools/index.rst       |   1 +
 Documentation/dev-tools/kmsan.rst       | 414 ++++++++++++++++++
 MAINTAINERS                             |  12 +
 Makefile                                |   1 +
 arch/x86/Kconfig                        |   9 +-
 arch/x86/boot/Makefile                  |   1 +
 arch/x86/boot/compressed/Makefile       |   1 +
 arch/x86/entry/common.c                 |   3 +-
 arch/x86/entry/vdso/Makefile            |   3 +
 arch/x86/include/asm/checksum.h         |  16 +-
 arch/x86/include/asm/idtentry.h         |  10 +-
 arch/x86/include/asm/page_64.h          |  13 +
 arch/x86/include/asm/pgtable_64_types.h |  41 +-
 arch/x86/include/asm/sparsemem.h        |   2 +
 arch/x86/include/asm/string_64.h        |  23 +-
 arch/x86/include/asm/uaccess.h          |   7 +
 arch/x86/include/asm/unwind.h           |  23 +-
 arch/x86/kernel/Makefile                |   2 +
 arch/x86/kernel/cpu/Makefile            |   1 +
 arch/x86/kernel/cpu/mce/core.c          |   2 +-
 arch/x86/kernel/kvm.c                   |   2 +-
 arch/x86/kernel/nmi.c                   |   2 +-
 arch/x86/kernel/process_64.c            |   1 +
 arch/x86/kernel/sev.c                   |   4 +-
 arch/x86/kernel/traps.c                 |  14 +-
 arch/x86/lib/Makefile                   |   2 +
 arch/x86/lib/iomem.c                    |   5 +
 arch/x86/mm/Makefile                    |   2 +
 arch/x86/mm/fault.c                     |  25 +-
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
 include/asm-generic/cacheflush.h        |   9 +-
 include/asm-generic/rwonce.h            |   5 +-
 include/linux/compiler-clang.h          |  23 +
 include/linux/compiler-gcc.h            |   6 +
 include/linux/compiler_types.h          |   3 +-
 include/linux/fortify-string.h          |   2 +
 include/linux/highmem.h                 |   3 +
 include/linux/instrumentation.h         |   6 +
 include/linux/instrumented.h            |  26 +-
 include/linux/kmsan-checks.h            | 123 ++++++
 include/linux/kmsan.h                   | 359 ++++++++++++++++
 include/linux/mm_types.h                |  12 +
 include/linux/sched.h                   |   5 +
 include/linux/stackdepot.h              |   8 +
 include/linux/uaccess.h                 |  19 +-
 init/main.c                             |   3 +
 kernel/Makefile                         |   1 +
 kernel/dma/mapping.c                    |   9 +-
 kernel/entry/common.c                   |  22 +-
 kernel/exit.c                           |   2 +
 kernel/fork.c                           |   2 +
 kernel/kcov.c                           |   7 +
 kernel/locking/Makefile                 |   3 +-
 lib/Kconfig.debug                       |   1 +
 lib/Kconfig.kmsan                       |  39 ++
 lib/Makefile                            |   3 +
 lib/iomap.c                             |  40 ++
 lib/iov_iter.c                          |   9 +-
 lib/stackdepot.c                        |  29 +-
 lib/string.c                            |   8 +
 lib/usercopy.c                          |   3 +-
 mm/Makefile                             |   1 +
 mm/internal.h                           |   6 +
 mm/kasan/common.c                       |   2 +-
 mm/kmsan/Makefile                       |  26 ++
 mm/kmsan/annotations.c                  |  28 ++
 mm/kmsan/core.c                         | 468 +++++++++++++++++++++
 mm/kmsan/hooks.c                        | 384 +++++++++++++++++
 mm/kmsan/init.c                         | 240 +++++++++++
 mm/kmsan/instrumentation.c              | 267 ++++++++++++
 mm/kmsan/kmsan.h                        | 188 +++++++++
 mm/kmsan/kmsan_test.c                   | 536 ++++++++++++++++++++++++
 mm/kmsan/report.c                       | 211 ++++++++++
 mm/kmsan/shadow.c                       | 336 +++++++++++++++
 mm/memory.c                             |   2 +
 mm/mmu_gather.c                         |  10 +
 mm/page_alloc.c                         |  18 +
 mm/slab.h                               |   1 +
 mm/slub.c                               |  21 +-
 mm/vmalloc.c                            |  20 +-
 scripts/Makefile.kmsan                  |   1 +
 scripts/Makefile.lib                    |   9 +
 security/Kconfig.hardening              |   4 +
 tools/objtool/check.c                   |  19 +
 96 files changed, 4211 insertions(+), 87 deletions(-)
 create mode 100644 Documentation/dev-tools/kmsan.rst
 create mode 100644 include/linux/kmsan-checks.h
 create mode 100644 include/linux/kmsan.h
 create mode 100644 lib/Kconfig.kmsan
 create mode 100644 mm/kmsan/Makefile
 create mode 100644 mm/kmsan/annotations.c
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-1-glider%40google.com.
