Return-Path: <kasan-dev+bncBCJMBM5G5UCRBBNX6CNQMGQEBF7Z7IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 269AB633184
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 01:44:55 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id s187-20020a1ff4c4000000b003b8128789cfsf4591504vkh.1
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 16:44:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669077893; cv=pass;
        d=google.com; s=arc-20160816;
        b=djXFzbrP3T/6WZf+ij7ynHxJZgvoga1kbdDn3cAUgO7qhxxIOkUyRqxz3PcYfvvY39
         U3YDeQDg079x5I30Oq1AqfV//ekC1Bw/Vk9chdvO0KQkzCglJT6VtpoCcB0YQgzgT3SM
         daFGWgNyADf8GQlJnkhrrlzuFGSHLOwpmtfANdWcFCiF/sBeXPQmXiD2dmO8UxyedLeg
         VgpUlRIS1RLg79LcVw+D7BIpLHOkI6QGBqYiXKf9pbUQQgx2mfg679hn5bKdTMs3pWk7
         JCWsRdfiXLOYmNCxUoxwc3N3IsKtKvZOKWE0lg8Rm9i6xxqcy3UXkcb/P6jldOOJc/+e
         ygvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=mX1KeKIaxpnv3ynWnj/BXXsf2tFKP6bdPo4g8ID1EXY=;
        b=zDsUt7sLnbZygtWJbwGnQ07J/Ke0xh3g+HBwqZsIZK4L8gqQKZOKdz1XhvvTVeTrRC
         9zfbkTrpDaPNixKomnnaZzQRQ9LylUnUxbBNt/XGBEsCMS4T/m+tEMFafOX7gdY8QLUB
         Zdi4L+BT/URrfELbjdgk2kUJ9yDxaG+NcLZ/RAAzRE+VtRF0MEpbdu2lkhnzgIWOzB++
         wvduRJY6pfh9e2izPw+5I0IGwoZqe1vQWvYuLJWX/g3Pk/tdWc87iP8wlh3sG0m5eT8H
         u5YVMR8pbrFMvFEe5zVb7rohKcypBLjjRfEiMH9/rbdL/Es/9am4Iv76k84sxAHOHpCN
         q3zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=JF4RjqIQ;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=dplqPyIC;
       spf=pass (google.com: domain of 010101849ccb788e-2602375c-6365-4f50-a5ce-c37ad3c833a6-000000@us-west-2.amazonses.com designates 54.240.27.18 as permitted sender) smtp.mailfrom=010101849ccb788e-2602375c-6365-4f50-a5ce-c37ad3c833a6-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mX1KeKIaxpnv3ynWnj/BXXsf2tFKP6bdPo4g8ID1EXY=;
        b=Lrf4arGzhUAMm2Cpas45Ddv49Z3cMTZaJL/jXaJ/gDOiQaE37L1RxJQPEjVFxsxE2W
         V8bvfNpAZBPllU2o297suhQjuuHxJIQr00zdjepqNX5APm+TXhFfg7EmuFFAIx0ck0zp
         /ybQEnHoJY1Lc5MGr2bErhfO9Yff0EBOz4NYoFo2o9eHwfV2HgGTlBnljGyDjRub/BZh
         3FLf6+otLqWmqoKEosqRCrPwsUY2EfdVTpHg60fnRIPdwaRYLG+DY6hIve5zIERMmaHr
         9pYMC44swviJujri20vkv6/w3wWiFkArT8oed8ZVTLUXv4yE7ePqvLaJDEbAWBJs+/Rc
         l3fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mX1KeKIaxpnv3ynWnj/BXXsf2tFKP6bdPo4g8ID1EXY=;
        b=ODfMblj7gYXpsWkJCALPqkL1f02QcDBjScYsN5BvbczdEF+GAICwNJqtnNJDqzfrf6
         kc+dFK3lfagjoRgPtYgGoyMqHSeywRlA9lAz1CHMuQUySLaDew734hrY300iehhuKfoE
         tS3DzKvtvi9p2dx1IYm8JqaYtLE1kImYAJ+nKFZCytSqj9JQBUF74QpNYJk0/8IPkyUL
         Jwq3K4lM7w37xlcATxpXjp3GvEk50HB5HeG6JeLTZprEmqgBExqapA0qLLLOCF1nWbuk
         gzl7YAA92v7hh4l21TCPz9C8/NrSiuKwyb/keCG+GRLpqv6ZaH/7VQ06mxmJB6ZOWs0p
         Wr/g==
X-Gm-Message-State: ANoB5pkKwpLMzKiEd3QM6R6xrAB1gPkU77hXw/4xjcRsc48uA7bXgPdD
	NCJWELvdXc2nPrWXSVocfe4=
X-Google-Smtp-Source: AA0mqf5odubRbw8MwrvoAWd7N90flp98HFVXQSd/u7Wm9DOYFiy0IZyLZ1GxsDYdXVxzFovIrbSJLQ==
X-Received: by 2002:ab0:2617:0:b0:411:6a11:dc46 with SMTP id c23-20020ab02617000000b004116a11dc46mr11663230uao.88.1669077893649;
        Mon, 21 Nov 2022 16:44:53 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6907:0:b0:418:d23c:2e13 with SMTP id b7-20020ab06907000000b00418d23c2e13ls275265uas.6.-pod-prod-gmail;
 Mon, 21 Nov 2022 16:44:53 -0800 (PST)
X-Received: by 2002:ab0:77c1:0:b0:418:620e:6794 with SMTP id y1-20020ab077c1000000b00418620e6794mr11354254uar.59.1669077892988;
        Mon, 21 Nov 2022 16:44:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669077892; cv=none;
        d=google.com; s=arc-20160816;
        b=nFPCIVtl9orbjyqbjUrPf5hpbZ9oP0AeJSysdb0KyGcPf0rM+IhYKY7oX7baFNdCue
         LAd/sK6He7snGudtYLIQ9x/SvWybs0pga46YhPY3ub/BMSbUJ+vN7ZClJk7G8mWdB+f9
         rHvK2yEIvKO7psDja2pdcWRssLRK48Y9yXVSHye2JC+//a/Oj7M8h1a3tuvmkKFQSIKo
         Xw+E8m+mvqWSCqswBTk8kf0y8U+0M5ZEgltYGBYpId2KJLmNFxrR3SdnH5cPJqM+0OtP
         h+wgn/bXTHDCwhh340wFepEGxnhE+bkEzhl9HD0ONV+XArwYtNONo9cfQWvK1qS9HW7I
         BZqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=cBu5DhW0Wdx4VsjP+nNwUd5v8JCWg839by5WeklAH/I=;
        b=BcBbF5UGvWDZlMP6NqbPEEEK0DvOw+uw7tIHMj26JfSf4LJtRh9JxiF7ftVZkhc89e
         hi494LHJOMX40T5xp0Gb+HwzIMXnKpboEg7vXybo2kKzuWUz81fuLPUCcIf3xKSXG1jQ
         K5cXmvGv+Jn+nNZ3USpO25PfsSz7/K3yxSWc/hhkcKhjYC48dypBQBVrvzgyxI+mEG+r
         l6d2YhQHxODFBmqJyJpqrG+KZ+I5TyZE6TKIJa98G1CK/86Fes4vsrGN2JynhHUeKbsp
         Rjzo1xXJOQgOEzKjZQz94clo8sfrQZqVosnn6LQ/ApsbwEYbThj70r5Yhtk0o54F/0hD
         89wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=JF4RjqIQ;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=dplqPyIC;
       spf=pass (google.com: domain of 010101849ccb788e-2602375c-6365-4f50-a5ce-c37ad3c833a6-000000@us-west-2.amazonses.com designates 54.240.27.18 as permitted sender) smtp.mailfrom=010101849ccb788e-2602375c-6365-4f50-a5ce-c37ad3c833a6-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-18.smtp-out.us-west-2.amazonses.com (a27-18.smtp-out.us-west-2.amazonses.com. [54.240.27.18])
        by gmr-mx.google.com with ESMTPS id q11-20020a67de0b000000b003a96db77ebbsi571533vsk.0.2022.11.21.16.44.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 16:44:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101849ccb788e-2602375c-6365-4f50-a5ce-c37ad3c833a6-000000@us-west-2.amazonses.com designates 54.240.27.18 as permitted sender) client-ip=54.240.27.18;
Date: Tue, 22 Nov 2022 00:44:51 +0000
Message-ID: <010101849ccb788e-2602375c-6365-4f50-a5ce-c37ad3c833a6-000000@us-west-2.amazonses.com>
To: bscattergood@roku.com, dmendenhall@roku.com, kcooper@roku.com,
        ksandvik@roku.com, mizhang@roku.com, najain@roku.com, pzhang@roku.com,
        sabellera@roku.com, snahibin@roku.com, tparker@roku.com
Cc: Andrey@localhost, Ryabinin@localhost, aryabinin@virtuozzo.com,
        Alexander@localhost, Potapenko@localhost, glider@google.com,
        Dmitry@localhost, Vyukov@localhost, dvyukov@google.com,
        kasan-dev@googlegroups.com, Mike@localhost, Rapoport@localhost,
        rppt@linux.ibm.com
From: no-reply via kasan-dev <kasan-dev@googlegroups.com>
Reply-To: no-reply@roku.com ((Automation Account))
Subject: PERFORCE change 3224911: commit a8d6c6ed2922ec1930bb0b227f73eb0aad4c408c
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.22-54.240.27.18
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=JF4RjqIQ;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=dplqPyIC;       spf=pass
 (google.com: domain of 010101849ccb788e-2602375c-6365-4f50-a5ce-c37ad3c833a6-000000@us-west-2.amazonses.com
 designates 54.240.27.18 as permitted sender) smtp.mailfrom=010101849ccb788e-2602375c-6365-4f50-a5ce-c37ad3c833a6-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
X-Original-From: no-reply@roku.com (Automation Account)
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

Change 3224911 by automation@vsergiienko-flipday-internal-rtd1395-nemo on 2022/11/22 00:40:08

	commit a8d6c6ed2922ec1930bb0b227f73eb0aad4c408c
	Author: Linus Walleij <linus.walleij@linaro.org>
	Date:   Sun Oct 25 23:53:46 2020 +0100
	
	    ARM: 9015/2: Define the virtual space of KASan's shadow region
	    
	    Define KASAN_SHADOW_OFFSET,KASAN_SHADOW_START and KASAN_SHADOW_END for
	    the Arm kernel address sanitizer. We are "stealing" lowmem (the 4GB
	    addressable by a 32bit architecture) out of the virtual address
	    space to use as shadow memory for KASan as follows:
	    
	     +----+ 0xffffffff
	     |    |
	     |    | |-> Static kernel image (vmlinux) BSS and page table
	     |    |/
	     +----+ PAGE_OFFSET
	     |    |
	     |    | |->  Loadable kernel modules virtual address space area
	     |    |/
	     +----+ MODULES_VADDR = KASAN_SHADOW_END
	     |    |
	     |    | |-> The shadow area of kernel virtual address.
	     |    |/
	     +----+->  TASK_SIZE (start of kernel space) = KASAN_SHADOW_START the
	     |    |   shadow address of MODULES_VADDR
	     |    | |
	     |    | |
	     |    | |-> The user space area in lowmem. The kernel address
	     |    | |   sanitizer do not use this space, nor does it map it.
	     |    | |
	     |    | |
	     |    | |
	     |    | |
	     |    |/
	     ------ 0
	    
	    0 .. TASK_SIZE is the memory that can be used by shared
	    userspace/kernelspace. It us used for userspace processes and for
	    passing parameters and memory buffers in system calls etc. We do not
	    need to shadow this area.
	    
	    KASAN_SHADOW_START:
	     This value begins with the MODULE_VADDR's shadow address. It is the
	     start of kernel virtual space. Since we have modules to load, we need
	     to cover also that area with shadow memory so we can find memory
	     bugs in modules.
	    
	    KASAN_SHADOW_END
	     This value is the 0x100000000's shadow address: the mapping that would
	     be after the end of the kernel memory at 0xffffffff. It is the end of
	     kernel address sanitizer shadow area. It is also the start of the
	     module area.
	    
	    KASAN_SHADOW_OFFSET:
	     This value is used to map an address to the corresponding shadow
	     address by the following formula:
	    
	       shadow_addr = (address >> 3) + KASAN_SHADOW_OFFSET;
	    
	     As you would expect, >> 3 is equal to dividing by 8, meaning each
	     byte in the shadow memory covers 8 bytes of kernel memory, so one
	     bit shadow memory per byte of kernel memory is used.
	    
	     The KASAN_SHADOW_OFFSET is provided in a Kconfig option depending
	     on the VMSPLIT layout of the system: the kernel and userspace can
	     split up lowmem in different ways according to needs, so we calculate
	     the shadow offset depending on this.
	    
	    When kasan is enabled, the definition of TASK_SIZE is not an 8-bit
	    rotated constant, so we need to modify the TASK_SIZE access code in the
	    *.s file.
	    
	    The kernel and modules may use different amounts of memory,
	    according to the VMSPLIT configuration, which in turn
	    determines the PAGE_OFFSET.
	    
	    We use the following KASAN_SHADOW_OFFSETs depending on how the
	    virtual memory is split up:
	    
	    - 0x1f000000 if we have 1G userspace / 3G kernelspace split:
	      - The kernel address space is 3G (0xc0000000)
	      - PAGE_OFFSET is then set to 0x40000000 so the kernel static
	        image (vmlinux) uses addresses 0x40000000 .. 0xffffffff
	      - On top of that we have the MODULES_VADDR which under
	        the worst case (using ARM instructions) is
	        PAGE_OFFSET - 16M (0x01000000) = 0x3f000000
	        so the modules use addresses 0x3f000000 .. 0x3fffffff
	      - So the addresses 0x3f000000 .. 0xffffffff need to be
	        covered with shadow memory. That is 0xc1000000 bytes
	        of memory.
	      - 1/8 of that is needed for its shadow memory, so
	        0x18200000 bytes of shadow memory is needed. We
	        "steal" that from the remaining lowmem.
	      - The KASAN_SHADOW_START becomes 0x26e00000, to
	        KASAN_SHADOW_END at 0x3effffff.
	      - Now we can calculate the KASAN_SHADOW_OFFSET for any
	        kernel address as 0x3f000000 needs to map to the first
	        byte of shadow memory and 0xffffffff needs to map to
	        the last byte of shadow memory. Since:
	        SHADOW_ADDR = (address >> 3) + KASAN_SHADOW_OFFSET
	        0x26e00000 = (0x3f000000 >> 3) + KASAN_SHADOW_OFFSET
	        KASAN_SHADOW_OFFSET = 0x26e00000 - (0x3f000000 >> 3)
	        KASAN_SHADOW_OFFSET = 0x26e00000 - 0x07e00000
	        KASAN_SHADOW_OFFSET = 0x1f000000
	    
	    - 0x5f000000 if we have 2G userspace / 2G kernelspace split:
	      - The kernel space is 2G (0x80000000)
	      - PAGE_OFFSET is set to 0x80000000 so the kernel static
	        image uses 0x80000000 .. 0xffffffff.
	      - On top of that we have the MODULES_VADDR which under
	        the worst case (using ARM instructions) is
	        PAGE_OFFSET - 16M (0x01000000) = 0x7f000000
	        so the modules use addresses 0x7f000000 .. 0x7fffffff
	      - So the addresses 0x7f000000 .. 0xffffffff need to be
	        covered with shadow memory. That is 0x81000000 bytes
	        of memory.
	      - 1/8 of that is needed for its shadow memory, so
	        0x10200000 bytes of shadow memory is needed. We
	        "steal" that from the remaining lowmem.
	      - The KASAN_SHADOW_START becomes 0x6ee00000, to
	        KASAN_SHADOW_END at 0x7effffff.
	      - Now we can calculate the KASAN_SHADOW_OFFSET for any
	        kernel address as 0x7f000000 needs to map to the first
	        byte of shadow memory and 0xffffffff needs to map to
	        the last byte of shadow memory. Since:
	        SHADOW_ADDR = (address >> 3) + KASAN_SHADOW_OFFSET
	        0x6ee00000 = (0x7f000000 >> 3) + KASAN_SHADOW_OFFSET
	        KASAN_SHADOW_OFFSET = 0x6ee00000 - (0x7f000000 >> 3)
	        KASAN_SHADOW_OFFSET = 0x6ee00000 - 0x0fe00000
	        KASAN_SHADOW_OFFSET = 0x5f000000
	    
	    - 0x9f000000 if we have 3G userspace / 1G kernelspace split,
	      and this is the default split for ARM:
	      - The kernel address space is 1GB (0x40000000)
	      - PAGE_OFFSET is set to 0xc0000000 so the kernel static
	        image uses 0xc0000000 .. 0xffffffff.
	      - On top of that we have the MODULES_VADDR which under
	        the worst case (using ARM instructions) is
	        PAGE_OFFSET - 16M (0x01000000) = 0xbf000000
	        so the modules use addresses 0xbf000000 .. 0xbfffffff
	      - So the addresses 0xbf000000 .. 0xffffffff need to be
	        covered with shadow memory. That is 0x41000000 bytes
	        of memory.
	      - 1/8 of that is needed for its shadow memory, so
	        0x08200000 bytes of shadow memory is needed. We
	        "steal" that from the remaining lowmem.
	      - The KASAN_SHADOW_START becomes 0xb6e00000, to
	        KASAN_SHADOW_END at 0xbfffffff.
	      - Now we can calculate the KASAN_SHADOW_OFFSET for any
	        kernel address as 0xbf000000 needs to map to the first
	        byte of shadow memory and 0xffffffff needs to map to
	        the last byte of shadow memory. Since:
	        SHADOW_ADDR = (address >> 3) + KASAN_SHADOW_OFFSET
	        0xb6e00000 = (0xbf000000 >> 3) + KASAN_SHADOW_OFFSET
	        KASAN_SHADOW_OFFSET = 0xb6e00000 - (0xbf000000 >> 3)
	        KASAN_SHADOW_OFFSET = 0xb6e00000 - 0x17e00000
	        KASAN_SHADOW_OFFSET = 0x9f000000
	    
	    - 0x8f000000 if we have 3G userspace / 1G kernelspace with
	      full 1 GB low memory (VMSPLIT_3G_OPT):
	      - The kernel address space is 1GB (0x40000000)
	      - PAGE_OFFSET is set to 0xb0000000 so the kernel static
	        image uses 0xb0000000 .. 0xffffffff.
	      - On top of that we have the MODULES_VADDR which under
	        the worst case (using ARM instructions) is
	        PAGE_OFFSET - 16M (0x01000000) = 0xaf000000
	        so the modules use addresses 0xaf000000 .. 0xaffffff
	      - So the addresses 0xaf000000 .. 0xffffffff need to be
	        covered with shadow memory. That is 0x51000000 bytes
	        of memory.
	      - 1/8 of that is needed for its shadow memory, so
	        0x0a200000 bytes of shadow memory is needed. We
	        "steal" that from the remaining lowmem.
	      - The KASAN_SHADOW_START becomes 0xa4e00000, to
	        KASAN_SHADOW_END at 0xaeffffff.
	      - Now we can calculate the KASAN_SHADOW_OFFSET for any
	        kernel address as 0xaf000000 needs to map to the first
	        byte of shadow memory and 0xffffffff needs to map to
	        the last byte of shadow memory. Since:
	        SHADOW_ADDR = (address >> 3) + KASAN_SHADOW_OFFSET
	        0xa4e00000 = (0xaf000000 >> 3) + KASAN_SHADOW_OFFSET
	        KASAN_SHADOW_OFFSET = 0xa4e00000 - (0xaf000000 >> 3)
	        KASAN_SHADOW_OFFSET = 0xa4e00000 - 0x15e00000
	        KASAN_SHADOW_OFFSET = 0x8f000000
	    
	    - The default value of 0xffffffff for KASAN_SHADOW_OFFSET
	      is an error value. We should always match one of the
	      above shadow offsets.
	    
	    When we do this, TASK_SIZE will sometimes get a bit odd values
	    that will not fit into immediate mov assembly instructions.
	    To account for this, we need to rewrite some assembly using
	    TASK_SIZE like this:
	    
	    -       mov     r1, #TASK_SIZE
	    +       ldr     r1, =TASK_SIZE
	    
	    or
	    
	    -       cmp     r4, #TASK_SIZE
	    +       ldr     r0, =TASK_SIZE
	    +       cmp     r4, r0
	    
	    this is done to avoid the immediate #TASK_SIZE that need to
	    fit into a limited number of bits.
	    
	    Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
	    Cc: Alexander Potapenko <glider@google.com>
	    Cc: Dmitry Vyukov <dvyukov@google.com>
	    Cc: kasan-dev@googlegroups.com
	    Cc: Mike Rapoport <rppt@linux.ibm.com>
	    Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
	    Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
	    Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
	    Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
	    Reported-by: Ard Biesheuvel <ardb@kernel.org>
	    Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
	    Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
	    Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
	    Signed-off-by: Russell King <rmk+kernel@armlinux.org.uk>

Affected files ...

.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/Documentation/arm/memory.txt#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/Kconfig#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/include/asm/kasan_def.h#1 add
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/include/asm/memory.h#2 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/kernel/entry-armv.S#3 edit
.. //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/mm/mmu.c#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/Documentation/arm/memory.txt#2 (text) ====

@@ -68,6 +68,11 @@
 				Kernel modules inserted via insmod are
 				placed here using dynamic mappings.
 
+TASK_SIZE	MODULES_VADDR-1	KASAn shadow memory when KASan is in use.
+				The range from MODULES_VADDR to the top
+				of the memory is shadowed here with 1 bit
+				per byte of memory.
+
 00001000	TASK_SIZE-1	User space mappings
 				Per-thread mappings are placed here via
 				the mmap() system call.

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/Kconfig#2 (text) ====

@@ -1462,6 +1462,15 @@
 	default 0xB0000000 if VMSPLIT_3G_OPT
 	default 0xC0000000
 
+config KASAN_SHADOW_OFFSET
+	hex
+	depends on KASAN
+	default 0x1f000000 if PAGE_OFFSET=0x40000000
+	default 0x5f000000 if PAGE_OFFSET=0x80000000
+	default 0x9f000000 if PAGE_OFFSET=0xC0000000
+	default 0x8f000000 if PAGE_OFFSET=0xB0000000
+	default 0xffffffff
+
 config NR_CPUS
 	int "Maximum number of CPUs (2-32)"
 	range 2 32

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/include/asm/memory.h#2 (text) ====

@@ -21,6 +21,7 @@
 #ifdef CONFIG_NEED_MACH_MEMORY_H
 #include <mach/memory.h>
 #endif
+#include <asm/kasan_def.h>
 
 /*
  * Allow for constants defined here to be used from assembly code
@@ -37,7 +38,11 @@
  * TASK_SIZE - the maximum size of a user space task.
  * TASK_UNMAPPED_BASE - the lower boundary of the mmap VM area
  */
+#ifndef CONFIG_KASAN
 #define TASK_SIZE		(UL(CONFIG_PAGE_OFFSET) - UL(SZ_16M))
+#else
+#define TASK_SIZE		(KASAN_SHADOW_START)
+#endif
 #define TASK_UNMAPPED_BASE	ALIGN(TASK_SIZE / 3, SZ_16M)
 
 /*

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/kernel/entry-armv.S#3 (text) ====

@@ -280,7 +280,7 @@
 
 	get_thread_info tsk
 	ldr	r0, [tsk, #TI_ADDR_LIMIT]
-	mov	r1, #TASK_SIZE
+	ldr	r1, =TASK_SIZE
 	str	r1, [tsk, #TI_ADDR_LIMIT]
 	str	r0, [sp, #SVC_ADDR_LIMIT]
 
@@ -537,7 +537,8 @@
 	@ if it was interrupted in a critical region.  Here we
 	@ perform a quick test inline since it should be false
 	@ 99.9999% of the time.  The rest is done out of line.
-	cmp	r4, #TASK_SIZE
+	ldr	r0, =TASK_SIZE
+	cmp	r4, r0
 	blhs	kuser_cmpxchg64_fixup
 #endif
 #endif

==== //depot/firmware/release/main/port/realtek/rtd1395/platform/software_phoenix/linux-kernel/arch/arm/mm/mmu.c#2 (text) ====

@@ -32,6 +32,7 @@
 #include <asm/traps.h>
 #include <asm/procinfo.h>
 #include <asm/memory.h>
+#include <asm/kasan_def.h>
 
 #include <asm/mach/arch.h>
 #include <asm/mach/map.h>
@@ -1289,8 +1290,25 @@
 	/*
 	 * Clear out all the mappings below the kernel image.
 	 */
+#ifdef CONFIG_KASAN
+	/*
+	 * KASan's shadow memory inserts itself between the TASK_SIZE
+	 * and MODULES_VADDR. Do not clear the KASan shadow memory mappings.
+	 */
+	for (addr = 0; addr < KASAN_SHADOW_START; addr += PMD_SIZE)
+		pmd_clear(pmd_off_k(addr));
+	/*
+	 * Skip over the KASan shadow area. KASAN_SHADOW_END is sometimes
+	 * equal to MODULES_VADDR and then we exit the pmd clearing. If we
+	 * are using a thumb-compiled kernel, there there will be 8MB more
+	 * to clear as KASan always offset to 16 MB below MODULES_VADDR.
+	 */
+	for (addr = KASAN_SHADOW_END; addr < MODULES_VADDR; addr += PMD_SIZE)
+		pmd_clear(pmd_off_k(addr));
+#else
 	for (addr = 0; addr < MODULES_VADDR; addr += PMD_SIZE)
 		pmd_clear(pmd_off_k(addr));
+#endif
 
 #ifdef CONFIG_XIP_KERNEL
 	/* The XIP kernel is mapped in the module area -- skip over it */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101849ccb788e-2602375c-6365-4f50-a5ce-c37ad3c833a6-000000%40us-west-2.amazonses.com.
