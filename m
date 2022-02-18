Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBNOBX2IAMGQEWETVFZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D17054BBA27
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 14:35:49 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id u14-20020a05600c210e00b0037bddd0562esf2859575wml.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 05:35:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645191349; cv=pass;
        d=google.com; s=arc-20160816;
        b=V9B93VpFErdKZoEKWeZpwTQv2jsodsDdwKMAt/C/Hy0BdbYOzrcjV8vSA+mB5J5ifw
         T8dCC5SLoUBxkwc+EIPONkBH1R4anuxerXe/K5joPr19/CwF2MpCwJeLAqiEcVE/cuVe
         vbDKZLSkAaxyacS5UDidsQDpTuo04Mr7GPmHAJv2XjMVNvWLGapcJEsj016NhhIUov2V
         UwIjfBZMR1dMPdpZIjrndvJCAl4FCMgAAHlmnLQKY1O+ofre+ZdAi/UmdwKVrNa9SzgW
         be050DQEyxL/ysWyZtvO0KIoYkWxPfejXmoo2MmqKW1Lss8aeS6RH6wKlzYPzcJoXwTo
         BfNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=PFy5xPQK+VF2tsYxum30YkaV1Bs9RvR4g7EtdKnzt6k=;
        b=r6xEL+SnISapxsi1g8Q6JOZ31CUBL1BlVlP9QHLT+tN5ue8SbYTTArsQKlU7rv4U3y
         3cN9yVsaVkf4IUz7RqrNwre16Xnokj3F+Yp+IrgCVXJ2ZO5CtOo0oNpAo9v63LUTyo6o
         YzwbwIWI6j+ZDJ0jkkNQUM0dlbHe9sdMXC0QQwrBdXaotNU0bho0V4+NxoKgYFW5Yth5
         1Df7Ts+aO8LrlJ6lLlNyhHUN7zuDw6Ul50OXutUwyNQOXkrymYzE98jYvE1AH9R3oOLX
         C6xxD2xv4j2yzfJMyWNBhmIXAKdvDUBHG/CmEn1/b69SDgTwSgJxTGZGymqE2JLUSzSM
         Gqaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=iBOYM1O4;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PFy5xPQK+VF2tsYxum30YkaV1Bs9RvR4g7EtdKnzt6k=;
        b=SbUAUqDt2GblQVv4NM+yfkVSxOvrCC0+EgFp2NW2Q78oxTN7gWzny0bayXiv0aSKDC
         AH8hx6tdwZpLjRJxBlWZQFjNCxq2RuJfimMLdq4ZY9/8KAfP/plgVfdYwI82Juie07ha
         vBfQpghr4heOPGOckxyOejYsrkkwh74w6dH7iG94AZxQE4aPhottbzZtjdGHkjsrWvDR
         qVLFcNlWtMQJdXZQUNfCtedkOqAHPqWC+RwJOeNrOuZ0bmG9PLVNs56kYlQSXzXtJlkg
         2SHLtrzqxGZUZk73/1PPim+V+P27iph1UaPHWhRey178u69HhVVVTJRrFKFMCDbcmfc8
         Y0Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PFy5xPQK+VF2tsYxum30YkaV1Bs9RvR4g7EtdKnzt6k=;
        b=VKImEPyBlv12amdOVrSXy/SBy5dYga/S67xjtWMhbJ8ghJ26pGykppR8F4SNaSxQgj
         yigwAhrOt1fUwOQ1JF6pnJsY/gfEulRuBKYRVv+SgnBbMXS3Fyq2DkWIrlcoQNK4I+01
         QktRPC3KNMJbz3j68y61eWZXfnhzfHZYukmFhGUvbYN/pNl7XRMeXeWJBtqryhrFAKwB
         Hf8K4hnrm6uBqQigenSprlIRcfocjdrlW2GLtvxCfHxwSIBMXBPXywg4b+M7rMgGXxf0
         efR+lfR/UgtGuqDgbCqNdGxUiijvTvwHC6ANs53iowH0PubcaA+LT35Fkbpt7lCuBx4X
         Qjyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532v7WvLbBqFsy/kbv68T7eKPc6cerVMgFIovI4h7ecjy6k5uDuE
	rsVwXw1DRsqmvqy0KM0rLRM=
X-Google-Smtp-Source: ABdhPJw56qMEcHcsaREMFqY0YKmsoiFfdS1+epxIbdGmJIHjrWwhqg08fUMZntLEycdF/wXOTp2pVA==
X-Received: by 2002:a05:6000:1ac6:b0:1e9:3a52:4c86 with SMTP id i6-20020a0560001ac600b001e93a524c86mr2357236wry.389.1645191349430;
        Fri, 18 Feb 2022 05:35:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:35d1:b0:37c:dec7:dbc0 with SMTP id
 r17-20020a05600c35d100b0037cdec7dbc0ls3314524wmq.3.gmail; Fri, 18 Feb 2022
 05:35:48 -0800 (PST)
X-Received: by 2002:a7b:cbd2:0:b0:37b:f880:a34c with SMTP id n18-20020a7bcbd2000000b0037bf880a34cmr7728731wmi.57.1645191348605;
        Fri, 18 Feb 2022 05:35:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645191348; cv=none;
        d=google.com; s=arc-20160816;
        b=HRg2BDP3+hoheHz15KbhYhL66kwqmOvjT4jg40u+q89z2sQCpWi3MmDIpdSlejxI9j
         +zc6Zgw9jEU3KdOTwHWuc3RBxR2rA/u1tMbP1nN5lqFOPLWYNT894FPDn45NIcqePX7f
         jDJYQTFUzZZom8YyRGbJ/ObpN3RD9ElwHxMVD3zHRfEPgLZfVUZjv5W7915QnZ+BsG7p
         a+DTdkEHgK3i4wTn2ID3p9ZqctpFRdbzpvGYhfyY1vLeZ9fR6WDSenBf7zImx1+vCKRA
         RwtOi0KnXpLeZC1Iycgnu7YEclpXZDGPaEAhb3z2fpScVy2uyz3OEe2mFXs60zvLtWBa
         XX3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=2yMxZwtr/8gF+DdEs5PumNe+/8vsdXtXdAp73EogBDY=;
        b=P/yE18ZBMTBR3blEuMyKc0Q7IcdBxTsvml628xgbc9zTIrsAyz+dvzIsvhQYCq5IY7
         eOMvORXLDrzazKtvnCQzpGcfevylrekpPzZHVBr7rvs7RQV/c5VxTz+TX9rIib8m599U
         I++1TL+JJ9iVMFLz1XKND5Or4KJ4dk4xwgUwbYSaLszZDHMwEn8SURv8SVsmC3qSaQkk
         HR4hF92D+7mMD7DEm3q7UEhU2umCxZD6bfC0yk5kiO5VupGiWbGgaWdxXt0I5FeP864a
         gAhMDr8+6iOYwjT2BIlsmtOH4WLXgkI0SYDLtNRiOM9mK3jz/0vpVnn5O4+XC6qZ0SPs
         rzrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=iBOYM1O4;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id j13si1416283wrp.6.2022.02.18.05.35.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 05:35:48 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com [209.85.128.71])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id BE82440306
	for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 13:35:44 +0000 (UTC)
Received: by mail-wm1-f71.google.com with SMTP id r16-20020a05600c2c5000b0037bb20c50b8so2855797wmg.3
        for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 05:35:44 -0800 (PST)
X-Received: by 2002:a05:600c:1e8e:b0:37b:b9ab:e35d with SMTP id be14-20020a05600c1e8e00b0037bb9abe35dmr10720476wmb.109.1645191340873;
        Fri, 18 Feb 2022 05:35:40 -0800 (PST)
X-Received: by 2002:a05:600c:1e8e:b0:37b:b9ab:e35d with SMTP id be14-20020a05600c1e8e00b0037bb9abe35dmr10720462wmb.109.1645191340715;
        Fri, 18 Feb 2022 05:35:40 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id c4sm21258318wri.22.2022.02.18.05.35.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 05:35:40 -0800 (PST)
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
Subject: [PATCH -fixes 0/4] Fixes KASAN and other along the way
Date: Fri, 18 Feb 2022 14:35:09 +0100
Message-Id: <20220218133513.1762929-1-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=iBOYM1O4;       spf=pass
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

Alexandre Ghiti (4):
  riscv: Fix is_linear_mapping with recent move of KASAN region
  riscv: Fix config KASAN && SPARSEMEM && !SPARSE_VMEMMAP
  riscv: Fix DEBUG_VIRTUAL false warnings
  riscv: Fix config KASAN && DEBUG_VIRTUAL

 arch/riscv/include/asm/page.h | 2 +-
 arch/riscv/mm/Makefile        | 3 +++
 arch/riscv/mm/kasan_init.c    | 3 +--
 arch/riscv/mm/physaddr.c      | 4 +---
 4 files changed, 6 insertions(+), 6 deletions(-)

-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220218133513.1762929-1-alexandre.ghiti%40canonical.com.
