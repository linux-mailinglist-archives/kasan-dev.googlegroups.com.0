Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBH444OIAMGQENJADI7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E0624C44B5
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 13:40:00 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id j11-20020a19f50b000000b00443304eab91sf981246lfb.13
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 04:40:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645792800; cv=pass;
        d=google.com; s=arc-20160816;
        b=iGLCxabxzCdyhP4HzCDCXOOdtHM2a73JJsZDjrn7lDL3kADqHJ004InWlzOzv+1ETR
         hQ7W2yhP6h/+E8QTq3ELbPtd3GKsX7tCMmnhtYrTm83kX61/SjZM/24lpO7tx7z6nSR+
         5NKT0j7+5e3F9AfmClYx4yFw4BHhyHjcrQLaZwBlzYxHrW38qDMCaWYCCCmRKy34QzgW
         AFa+MrMBlqbY7KUosNlPB07f6bARR4bkeC2bHSr9mPn+KaB9+5oOxJU/GmFcoG2eNUmg
         H0pjCwhr90fIMa+5wxedo6x8859KH3+pvHWy7fgN0BTLlK23EqHmc7MAL0SM26nL4Io1
         NV1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=IgbwSECI3q4yWUHdH3FNQamFMk5VRtyD1nrw/Ugbxmo=;
        b=i3cXKQfpQjFPM4BFYP4QSyBHg1wT+16uNpHcoNmXSboHa4/ypSfqF0x60llOZJup3h
         h8gjRSgQFcVxz8s+8+/4UfspwkoVYutXg1OY7MFQz0KbsYEjByjTSu42nM12BJGSyOLZ
         Yg8IQh+FW60i8jXkK70bAMV/zNqiNTIUMSHZ2W9EZ679ApjLpSKMfo3BwUc9ZF8epzTg
         SQLqFOqoxXNwIq6YUoaXK4hXATk1PrWi9cGLxl4outM/4jmJXaw8GZ6wifw/dPI0eHrc
         /t/hFcw9RVgAXKVOrUFBklaJW3348rZUv9j7FD9+H/y+QNO9jQlE2rS2luQf3bpuhFM3
         EfiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=bjt6hy1G;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IgbwSECI3q4yWUHdH3FNQamFMk5VRtyD1nrw/Ugbxmo=;
        b=ZeHHkeaMYNj6JojzzkX+I70ciVYAbzHLOy26QMaSjLbAoqa9zZdNRDLLpNY0qd8/XR
         yz/FuxRjiukt0Phw5Ui+pzX0PkkLw/KEe5Fc68KNag8JjlEcSvmdyYSGTphcjYxq9fKP
         XWfdbZObvMIMSINcDmfADEocxXpirx90h+pEBUkeYPWtmkpB2k/vcZp7PONWlRXJ0NuJ
         2EImARJpgJyEla6OdpzKncHeUyIUgF5vc+zENYXntHvm70sfU5Xzfkb4ijB9NQ+OetoR
         itGPBZPv1bmQqgK7UshA1OyeLGI+zra0dB3LVQ1hgXnNU7YGCwCBrfXSyfZbdldnaVQD
         lwww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IgbwSECI3q4yWUHdH3FNQamFMk5VRtyD1nrw/Ugbxmo=;
        b=nkFBBvtRfoGux+lCUfyFMEOqohfNNP7oOYMcBwaR8SZlzX+5uhQB3KqToMhbPvxx/0
         X1PTUwOr7/ZQbD0llYZsD9wtGkyiIZ0I8ELGBpcMVdjyOVEBhZy1r8t/nUkqE8iGT+px
         OlGGv4ej1M6F+siW8zjsPRkAL/ONSLxB0j9aPNRi3Wvkayt+facDiHCj2ob170oVdKWr
         OfZlUoSC+J9lot9agrnNSaQ0tu1KyrCk53xgw7bKeenLky2Sn0B63jO+6njOBmAn0jLY
         2eKuO0IHRpWjw0kIt/Gm3dYhCemgKhVSzY/cvDUnqlUHhJLGoeqUFUzVfC3GX6BuKzrb
         2NKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Ixhr+wF6A5GSiYgYq5+xHaloij3KCTLiJgnhXzyrp6oMxLXpI
	WfcGjksZgUVNQseY/e3bflQ=
X-Google-Smtp-Source: ABdhPJzy0t3T5rsQ6hy0CGLOhIAnLMaCHR8t4aGkwovsbDdGe1mYGUUX2PG+95fxc5zxgQtYRHhYog==
X-Received: by 2002:a2e:bc0f:0:b0:246:2af2:bf44 with SMTP id b15-20020a2ebc0f000000b002462af2bf44mr5291728ljf.485.1645792799891;
        Fri, 25 Feb 2022 04:39:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:19a7:b0:246:4772:53ba with SMTP id
 bx39-20020a05651c19a700b00246477253bals1132477ljb.11.gmail; Fri, 25 Feb 2022
 04:39:58 -0800 (PST)
X-Received: by 2002:a05:651c:888:b0:241:695:c9ef with SMTP id d8-20020a05651c088800b002410695c9efmr5149334ljq.523.1645792798857;
        Fri, 25 Feb 2022 04:39:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645792798; cv=none;
        d=google.com; s=arc-20160816;
        b=Cipy7rGrz8N2N3QpV/0LiKyATrZhvrCe6gtlNI0ARLnpQYuTOK/B2I9qk9chHFl7Fc
         QxRL3FcRj/Ph38IckJJt71BdaHnv7XlMVCYGmpZ29PyUrhZ68OU5cjE1a5z03N2cIPvt
         A2TZWnqyoYnntEyHHDIhTH8JRHwU1aemu5uUYoYYhJ7xXqowYqOfRZNmLmd6MzqwKtGy
         1/MRWcd22mlYo/kuRkXu9sfA1xYBeX6PLs1+I++Tl2F2r/UtwilCywflSGVu6FNQ1CYN
         YyTiL1As3KjiBgETUvem5EoILXz/ZguWjDtJf1hwhJusHrIJD3NQwLD1WsJDIvvBYftN
         PjGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=HCBpo4PsqJUx1yHp1r7/10LuebIPFGAh3ml+5ybdqeU=;
        b=QckoiimMogpr/VFGJva+W6Wqlxst32Mj48WUAvxL61/Fkysm9/SA39X0My2aDHGbql
         /4b8sphsBqV03PhD9n57g1hThH6W2vDK137NNpW1lM6WJIoP17rqSud8batdVm54HdBF
         rPxExCzKTZk4ovdK+rch/VwV85yILLcXg02sYD32y7G49atIez5hDCspkz7OyeihuJ2c
         +RxJvvZoakEjM+StrPS5wd7MN8Xg2LldKVNeIPt5xy1QMJFAzfFPHj7qEKnsDPPXIa7U
         TY9WBEqID4HoD7VYVIsmYHmr/6FydBvZtXMnm5iFNw6OIVa/43Qy5W6pwoI24qVnRCIb
         f/iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=bjt6hy1G;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id w10-20020a05651234ca00b004435a161cd2si117821lfr.12.2022.02.25.04.39.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:39:58 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com [209.85.221.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 16ECF3F1D9
	for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 12:39:57 +0000 (UTC)
Received: by mail-wr1-f72.google.com with SMTP id u9-20020adfae49000000b001e89793bcb0so846120wrd.17
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 04:39:57 -0800 (PST)
X-Received: by 2002:a05:600c:4e8d:b0:37c:4e20:baa6 with SMTP id f13-20020a05600c4e8d00b0037c4e20baa6mr2571094wmq.19.1645792796220;
        Fri, 25 Feb 2022 04:39:56 -0800 (PST)
X-Received: by 2002:a05:600c:4e8d:b0:37c:4e20:baa6 with SMTP id f13-20020a05600c4e8d00b0037c4e20baa6mr2571082wmq.19.1645792796034;
        Fri, 25 Feb 2022 04:39:56 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id m1-20020adfdc41000000b001edb7520438sm2216981wrj.115.2022.02.25.04.39.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:39:55 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
Date: Fri, 25 Feb 2022 13:39:47 +0100
Message-Id: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=bjt6hy1G;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Content-Type: text/plain; charset="UTF-8"
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

As reported by Aleksandr, syzbot riscv is broken since commit
54c5639d8f50 ("riscv: Fix asan-stack clang build"). This commit actually
breaks KASAN_INLINE which is not fixed in this series, that will come later
when found.

Nevertheless, this series fixes small things that made the syzbot
configuration + KASAN_OUTLINE fail to boot.

Note that even though the config at [1] boots fine with this series, I
was not able to boot the small config at [2] which fails because
kasan_poison receives a really weird address 0x4075706301000000 (maybe a
kasan person could provide some hint about what happens below in
do_ctors -> __asan_register_globals):

Thread 2 hit Breakpoint 1, kasan_poison (addr=<optimized out>, size=<optimized out>, value=<optimized out>, init=<optimized out>) at /home/alex/work/linux/mm/kasan/shadow.c:90
90		if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
1: x/i $pc
=> 0xffffffff80261712 <kasan_poison>:	andi	a4,a0,7
5: /x $a0 = 0x4075706301000000

Thread 2 hit Breakpoint 2, handle_exception () at /home/alex/work/linux/arch/riscv/kernel/entry.S:27
27		csrrw tp, CSR_SCRATCH, tp
1: x/i $pc
=> 0xffffffff80004098 <handle_exception>:	csrrw	tp,sscratch,tp
5: /x $a0 = 0xe80eae0b60200000
(gdb) bt
#0  handle_exception () at /home/alex/work/linux/arch/riscv/kernel/entry.S:27
#1  0xffffffff80261746 in kasan_poison (addr=<optimized out>, size=<optimized out>, value=<optimized out>, init=<optimized out>)
    at /home/alex/work/linux/mm/kasan/shadow.c:98
#2  0xffffffff802618b4 in kasan_unpoison (addr=<optimized out>, size=<optimized out>, init=<optimized out>)
    at /home/alex/work/linux/mm/kasan/shadow.c:138
#3  0xffffffff80260876 in register_global (global=<optimized out>) at /home/alex/work/linux/mm/kasan/generic.c:214
#4  __asan_register_globals (globals=<optimized out>, size=<optimized out>) at /home/alex/work/linux/mm/kasan/generic.c:226
#5  0xffffffff8125efac in _sub_I_65535_1 ()
#6  0xffffffff81201b32 in do_ctors () at /home/alex/work/linux/init/main.c:1156
#7  do_basic_setup () at /home/alex/work/linux/init/main.c:1407
#8  kernel_init_freeable () at /home/alex/work/linux/init/main.c:1613
#9  0xffffffff81153ddc in kernel_init (unused=<optimized out>) at /home/alex/work/linux/init/main.c:1502
#10 0xffffffff800041c0 in handle_exception () at /home/alex/work/linux/arch/riscv/kernel/entry.S:231


Thanks again to Aleksandr for narrowing down the issues fixed here.


[1] https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
[2] https://gist.github.com/AlexGhiti/a5a0cab0227e2bf38f9d12232591c0e4

Changes in v3:
- Add PATCH 5/6 and PATCH 6/6

Changes in v2:
- Fix kernel test robot failure regarding KERN_VIRT_SIZE that is
  undefined for nommu config

Alexandre Ghiti (6):
  riscv: Fix is_linear_mapping with recent move of KASAN region
  riscv: Fix config KASAN && SPARSEMEM && !SPARSE_VMEMMAP
  riscv: Fix DEBUG_VIRTUAL false warnings
  riscv: Fix config KASAN && DEBUG_VIRTUAL
  riscv: Move high_memory initialization to setup_bootmem
  riscv: Fix kasan pud population

 arch/riscv/include/asm/page.h    | 2 +-
 arch/riscv/include/asm/pgtable.h | 1 +
 arch/riscv/mm/Makefile           | 3 +++
 arch/riscv/mm/init.c             | 2 +-
 arch/riscv/mm/kasan_init.c       | 8 +++++---
 arch/riscv/mm/physaddr.c         | 4 +---
 6 files changed, 12 insertions(+), 8 deletions(-)

-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220225123953.3251327-1-alexandre.ghiti%40canonical.com.
