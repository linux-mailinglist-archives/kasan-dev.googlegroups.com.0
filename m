Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBX6RSMQMGQEBJD5CCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C17575B9DF7
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:04:39 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id v128-20020a1cac86000000b003b33fab37e8sf9724461wme.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:04:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254279; cv=pass;
        d=google.com; s=arc-20160816;
        b=tKFPnZBcoxGtR+VcKrbrPfq2D2Vs/W1OD9AADAwB2uvtFtUh1U4HAVS4ry6bKicKdo
         zEiAlWH8+mGPzMw8CFGGfbAketsnUjGeLY++elReIM6X7rMI/GfQ0kcsigk3bQZ8tRiK
         xHV3EetrpG3MJghvnnZXJUzJyAWg/EK59VVuKJB/XekmOzwWYajtHrF8Res0YdupKHXy
         So2PEdEFCDoXjHgPuGtzeWE/dgXXvAzTwmsJNjWlXX4AVjHsCa30k7ltfGGFCEpGp7s1
         JVXBU5Drfx1B0NSMEp5nLTMGIXSfyrDjeJpinvhH3MFC3WxEnUFwInQ9fjb1mqBLcI/P
         sZgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=+kl1Hs+8BakMqVEjTYceDkWMcnU2elLU6ngVb0mlr4E=;
        b=mqqatIe9bpjPCyXtyY1W1ET/9kMB5htqsTMEv4L2l+EW5ELd69CKOvo9MqwNHQOIdk
         kDYHJNefqOk1lORmr8Ff5/qUAmPm0ZgjDA0vthawBxUQCWCgV2wItP8kbjTQwMWJGXmF
         dPM0qRB6aTgKRxyWP7BsE7e/RUbRwDIGyCBHi4CrZApjhpE/cnoNnyGFM4ii+l5L9w44
         XKdSm/g+Y0Qew/lg6PHEQ+Q7I7lkoS2tvY0XBGx1zjGhGvY3oP9frQbMUX3Sz4ABrYcv
         dycdQ2J6TfthKoX1eXSi3hIlL8yknuL7P7qi7Y5RlKF9n4dyva58B2eh1Ug96+gCw1bS
         MRKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JkTkROgP;
       spf=pass (google.com: domain of 3bt8jywykctasxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3BT8jYwYKCTASXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date;
        bh=+kl1Hs+8BakMqVEjTYceDkWMcnU2elLU6ngVb0mlr4E=;
        b=WUEp1PzXTc5++gQ3Y/b46bjOygZ2XBJvb10/OulVjOTBqwF7dR+sRCL/g+EjFxYo5+
         U7xwxw6DRL82PUe6izk7tUtt1bQC7HtpKr+0mBJfrwn9t9AzWfL26B4IoTN54kdVV65g
         ogvKKhLNTSdoOBBcwVqy1lrmIVdI5ATsjKqANyCE4D9dMeFoCuKH3EOXboKRkYXHAa6N
         BT7iDCMv9J+M2Xf+OR7CJ9W1rpgmKsNYM8S0i3ctN2Y491LQ2egrvj6ddHinEmFcae6n
         H+I4MbHtpeBUXEgL07440Ug6twMuG8KMqfCmf44lURsEQ6RV0D4hm6PUwLaRYAm43bQI
         Kp/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date;
        bh=+kl1Hs+8BakMqVEjTYceDkWMcnU2elLU6ngVb0mlr4E=;
        b=UEJLRXirHssUGTYRJqW5O2JmUjWsqUZx/ThQATcdbBTiGAnuv6Rivlf+xPgYu8mkDy
         d5Es94dKxh6W6UQE35v5R0ZRLQau0u+E572BRVuT93RY5k8N3UzhmZr0lmQ4B79Tsmcq
         qX15/LsFpwWuDt4dXy34vIPZvAqekpj7TF4XVkBgErby3bkZ8ziX0AUB8J66PMFI/LB8
         8vz4EEcXCA7mtRwghbcVjkpN7iR7GIZiZiYu/UUYdsOnPRNhTlOHMzcPWWniXDrmp1dp
         Lvsja0PWtKjadOoiqVXLvuknJNh0wVRx0wqfv52db+616IF39EqL+6Ry1qCPz491W9mB
         NIBA==
X-Gm-Message-State: ACrzQf3Rqskjn1zbNBS1P4XRHD4LmvpYZGrFRC1tO+7Wf4tzO0boZoat
	fzdBQh56SINuZOhA6WHg4xo=
X-Google-Smtp-Source: AMsMyM5QmEaD7Rur3NDbP7d3F9m1R0ynztNBiE3wMAHJVQaw3CIMS14DHt6HVKfgrzsrvD+RRHf2Sw==
X-Received: by 2002:a05:600c:1c22:b0:3b4:b2bc:15e4 with SMTP id j34-20020a05600c1c2200b003b4b2bc15e4mr165078wms.69.1663254279077;
        Thu, 15 Sep 2022 08:04:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7510:0:b0:3a6:6268:8eae with SMTP id o16-20020a1c7510000000b003a662688eaels7264317wmc.0.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:04:38 -0700 (PDT)
X-Received: by 2002:a05:600c:3b12:b0:3b4:a6ea:1399 with SMTP id m18-20020a05600c3b1200b003b4a6ea1399mr4360721wms.49.1663254277866;
        Thu, 15 Sep 2022 08:04:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254277; cv=none;
        d=google.com; s=arc-20160816;
        b=GjxV5CqArZDBmV010ON1lfge1wWNF61gN4OvxzgvbAKsUjVaywvl6j0aQklKFd5jRd
         Qa87OePwPS3lu0QkpL2elEuQIHtvcYNX1TVf+1QpcMVROxulOAUTuCjP7h4MNyLRf41f
         ccB9Iowfo8444kN5vhaVVmVCA40Vxv9kUbTvxvI+GUzkDj7uB2UwA5dqIC5eWX/FU/RO
         UkMEJ5pHBpMtL6++OQvcLVUNI2ypAzjbfzCwNpSoj/1WS9rdhd15BG95keCmqWXLzyIz
         Kf3G5YXUUIhyidxXyYDQ4/zLsaTqE62SMRn2K04SLKJeIAkroBXZHJX6PwCtDnbBCLtG
         BJhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=XeyuklZw0NLQJbMOzL/M4tk3073tRNanGD8d61oNPrA=;
        b=uhdET1uHq14sIj0LopFiLiretpSiIFkd3HivViiHnOieSByJNHPC0Ico99xDgOUYKq
         bkFECxO1DowfjmzAhwY9iYWq0aH41SCnxseK6JheJj2glGp6hxEToulTT6UwY+zGaI7t
         v9ihUK/XZkiL/m3hMMtmO+bNnGBEeYKhT0bOmhDTx6kpPPlarv4HKJfSw358G6dM2mFb
         4tPeRVL4REtgQ0xBXbafOCDSGrs9FzkvR/7eGA+UDsn+DfjSPiLrd5DOUyEnUNjfAeFk
         YeWOncofQmb/5S/OCIuGhyEHWFfLSLcufYyrI4NlyTGfi2wSAWRw9RyS1xvfnk0EXSqs
         R2cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JkTkROgP;
       spf=pass (google.com: domain of 3bt8jywykctasxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3BT8jYwYKCTASXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id c2-20020a05600c0a4200b003a49e4e7e14si77548wmq.0.2022.09.15.08.04.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:04:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bt8jywykctasxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id qb30-20020a1709077e9e00b0077d1271283eso5521494ejc.2
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:04:37 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:3587:b0:451:30ca:c067 with SMTP id
 y7-20020a056402358700b0045130cac067mr248075edc.195.1663254277332; Thu, 15 Sep
 2022 08:04:37 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:34 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-1-glider@google.com>
Subject: [PATCH v7 00/43] Add KernelMemorySanitizer infrastructure
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JkTkROgP;       spf=pass
 (google.com: domain of 3bt8jywykctasxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3BT8jYwYKCTASXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
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
 - [01/43] x86: add missing include to sparsemem.h
 - [02/43] stackdepot: reserve 5 extra bits in depot_stack_handle_t
 - [03/43] instrumented.h: allow instrumenting both sides of copy_from_user()
 - [04/43] x86: asm: instrument usercopy in get_user() and __put_user_size()
 - [05/43] asm-generic: instrument usercopy in cacheflush.h
 - [10/43] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE

2. KMSAN-related declarations in generic code, KMSAN runtime library,
   docs and configs:
 - [06/43] kmsan: add ReST documentation
 - [07/43] kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
 - [09/43] x86: kmsan: pgtable: reduce vmalloc space
 - [11/43] kmsan: add KMSAN runtime core
 - [13/43] MAINTAINERS: add entry for KMSAN
 - [24/43] kmsan: add tests for KMSAN
 - [31/43] objtool: kmsan: list KMSAN API functions as uaccess-safe
 - [35/43] x86: kmsan: use __msan_ string functions where possible
 - [43/43] x86: kmsan: enable KMSAN builds for x86

3. Adding hooks from different subsystems to notify KMSAN about memory
   state changes:
 - [14/43] mm: kmsan: maintain KMSAN metadata for page
 - [15/43] mm: kmsan: call KMSAN hooks from SLUB code
 - [16/43] kmsan: handle task creation and exiting
 - [17/43] init: kmsan: call KMSAN initialization routines
 - [18/43] instrumented.h: add KMSAN support
 - [19/43] kmsan: add iomap support
 - [20/43] Input: libps2: mark data received in __ps2_command() as initialized
 - [21/43] dma: kmsan: unpoison DMA mappings
 - [34/43] x86: kmsan: handle open-coded assembly in lib/iomem.c
 - [36/43] x86: kmsan: sync metadata pages on page fault

4. Changes that prevent false reports by explicitly initializing memory,
   disabling optimized code that may trick KMSAN, selectively skipping
   instrumentation:
 - [08/43] kmsan: mark noinstr as __no_sanitize_memory
 - [12/43] kmsan: disable instrumentation of unsupported common kernel code
 - [22/43] virtio: kmsan: check/unpoison scatterlist in vring_map_one_sg()
 - [23/43] kmsan: handle memory sent to/from USB
 - [25/43] kmsan: disable strscpy() optimization under KMSAN
 - [26/43] crypto: kmsan: disable accelerated configs under KMSAN
 - [27/43] kmsan: disable physical page merging in biovec
 - [28/43] block: kmsan: skip bio block merging logic for KMSAN
 - [29/43] kcov: kmsan: unpoison area->list in kcov_remote_area_put()
 - [30/43] security: kmsan: fix interoperability with auto-initialization
 - [32/43] x86: kmsan: disable instrumentation of unsupported code
 - [33/43] x86: kmsan: skip shadow checks in __switch_to()
 - [37/43] x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on x86, enable it for KASAN/KMSAN
 - [38/43] x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS
 - [39/43] x86: kmsan: don't instrument stack walking functions
 - [40/43] entry: kmsan: introduce kmsan_unpoison_entry_regs()

5. Fixes for bugs detected with CONFIG_KMSAN_CHECK_PARAM_RETVAL:
 - [41/43] bpf: kmsan: initialize BPF registers with zeroes
 - [42/43] mm: fs: initialize fsdata passed to write_begin/write_end interface

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

The patchset was generated relative to Linux v6.0-rc5. The most
up-to-date KMSAN tree currently resides at
https://github.com/google/kmsan/. One may find it handy to review these
patches in Gerrit [6].

Patchset v7 includes only minor changes to origin tracking that allowed
us to drop "kmsan: unpoison @tlb in arch_tlb_gather_mmu()" from the
series.

For the following patches diff from v6 is non-trivial:
 - kmsan: add KMSAN runtime core
 - kmsan: add tests for KMSAN

A huge thanks goes to the reviewers of the RFC patch series sent to LKML
in 2020 ([7]).

[1] https://clang.llvm.org/docs/MemorySanitizer.html
[2] https://syzkaller.appspot.com/upstream/fixed?manager=ci-upstream-kmsan-gce
[3] https://lore.kernel.org/all/0000000000002c7abf05e721698d@google.com/
[4] https://lore.kernel.org/all/20220614144853.3693273-1-glider@google.com/ 
[5] https://lore.kernel.org/linux-mm/20220701142310.2188015-45-glider@google.com/
[6] https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/12604/ 
[7] https://lore.kernel.org/all/20200325161249.55095-1-glider@google.com/


Alexander Potapenko (42):
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
 Documentation/dev-tools/kmsan.rst       | 427 +++++++++++++++++
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
 mm/kmsan/core.c                         | 450 ++++++++++++++++++
 mm/kmsan/hooks.c                        | 384 ++++++++++++++++
 mm/kmsan/init.c                         | 235 ++++++++++
 mm/kmsan/instrumentation.c              | 307 +++++++++++++
 mm/kmsan/kmsan.h                        | 209 +++++++++
 mm/kmsan/kmsan_test.c                   | 581 ++++++++++++++++++++++++
 mm/kmsan/report.c                       | 219 +++++++++
 mm/kmsan/shadow.c                       | 294 ++++++++++++
 mm/memory.c                             |   2 +
 mm/page_alloc.c                         |  19 +
 mm/slab.h                               |   1 +
 mm/slub.c                               |  17 +
 mm/vmalloc.c                            |  20 +-
 scripts/Makefile.kmsan                  |   8 +
 scripts/Makefile.lib                    |   9 +
 security/Kconfig.hardening              |   4 +
 tools/objtool/check.c                   |  20 +
 93 files changed, 4316 insertions(+), 56 deletions(-)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-1-glider%40google.com.
