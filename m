Return-Path: <kasan-dev+bncBCJMBM5G5UCRBOG3SWOAMGQE463DQHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B31163B7CB
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Nov 2022 03:26:02 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id u3-20020a056a00124300b0056d4ab0c7cbsf9831334pfi.7
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 18:26:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669688760; cv=pass;
        d=google.com; s=arc-20160816;
        b=iThKoY/q+TIMH1cGUPDIBigGeljKMzM+WrJ0mCyRVhWhEPK0t6JcMP5O4Nd6/Jhl54
         JuStnpuekrTRW5G4OYvlZ1saERCtH8VVBl6/kqcaRX4RX7oskm/DeZwKOYkgbjh24gsb
         ErsVC3X1wl/Hwk/Y1r/VNfS4zd8RdlzPbsfQQMMG5hs/qHSIMswWj/0VrRGr3vVio5je
         piUZGoAYG4OK+P5W0Ft4PVu08SGJfWf+QPKYotFqJwgYf9PeiJ9GspLm4gcYE5Z/LaZE
         94q/qfd3zA05TUPCcs2YFHAc4OOJNaTyOt5d3lD1N3649VRK4OZjsPwrUiHpKoTTLgER
         yHxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=NN58VFfJPk8LpgQiTXQ4iY4QGBquDXptLQZIqilJ6Bs=;
        b=Pn0JDWvz8KgsY+MiT4utJgATi3X7r7BqFQN3m2Af4Wo7+5sAqT2FhpLdnOrznUkWas
         LY5IUJdL4IEKy5t9ZZi3ALdHhxmtpTTea52B8ML2HMiAcFebSANLvh6M9GsuaBHHuqE6
         X/ALNb9WkFm7sX8xxdghjW6+bgjj0o2Mml/ZffB+zGfNKUbluluvAc6FXbJ/ErCbLfSv
         09GFEJZI36xIXvgXiKb59BDFVCK3qnIQwEaNthFBOxE+AeCDQ6W3Nz2mf0azvkURO8uJ
         2Ke21mp+0rLeEY5mpABLMn2Bv9D2WRuZqULAQDgPqXDMOMwC9lXORoQMNPCEdrWY+uSz
         6zcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=SUe4MDyy;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=YRT0kL4h;
       spf=pass (google.com: domain of 01010184c134919e-d7d79ac9-bd22-47a8-b46b-96f5e90c268a-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) smtp.mailfrom=01010184c134919e-d7d79ac9-bd22-47a8-b46b-96f5e90c268a-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NN58VFfJPk8LpgQiTXQ4iY4QGBquDXptLQZIqilJ6Bs=;
        b=d2uCAAuEUoE9gHrLwyZZmxydMQYKGilodepWN+FeMYQvXPFmHXCyfm3uR3hiqXr8gb
         oAw9YI9e77pW+LWHT+/RX1Do/U3pMFC6MkkoU59YxWEEtfMD5mY5PYJZfADiQemZ9CqV
         N9rvjDSxoesZoz2HmX6rmmT9JaZrZXYk7D3FkObvtkWjM52CJSQ0Prb6u/rruFyfFNOI
         n/7rdZOT1XDI9INLMY4X6crnaBA7SLFqNwbnrWn6GNqoFROt8MtMOC5I7gc9JbJjq1KO
         5kDVwks09c7ZQvmGyqta7eDMqvOkUOmUv1d7QsVZcThrbAGVfoNAKoWjg0j5/+oLWzIH
         dlKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=NN58VFfJPk8LpgQiTXQ4iY4QGBquDXptLQZIqilJ6Bs=;
        b=FIukCUpbg13IoPpyGXx/pOdNx0TBD43GOpvYajPVTxiUef0UcYxXKTqhGdWPTMaLuS
         w6p6tLCqaRgLnH9pIJneIQMUOTDgyR8gjtFXPM4dO9tJzDYv4/2ZBVoLxoDjcmu+Kt7Y
         bKpkxKsN88bIN5c8utlIq0oELIj4K+cHjLe+i4C+uR/+abEM3qsKdfpSfbIRleuWaVTn
         r58KNjQR9f3ocTUQL0PsEmk7eGMo2iBcaqIGkXpmyZEBaI9FfeyQi+MrTlnpenLj2led
         RRApD+R9+Ex4i7+Sp7L6k963kuOiBTx3187McO1osEqEu8nWUJ3dMUpMRjU+FGH613oB
         VCng==
X-Gm-Message-State: ANoB5pmGUQw1bkTncmuNIyaPHzsnrpt7vnikD+/syYnHeIqC/DSD1mmH
	az0uba8PBqc2FHtN5dNjf8E=
X-Google-Smtp-Source: AA0mqf7HNBC87X23N5zMtCZer7bKOJ9a0FaO4Kdy82XjajxSg1iMGqNeysCFevVahD8+Zml0hwSqAA==
X-Received: by 2002:a05:6a00:1c8d:b0:56c:f87e:c662 with SMTP id y13-20020a056a001c8d00b0056cf87ec662mr35883576pfw.65.1669688760182;
        Mon, 28 Nov 2022 18:26:00 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a93:b0:210:6f33:e22d with SMTP id
 x19-20020a17090a8a9300b002106f33e22dls10387127pjn.2.-pod-control-gmail; Mon,
 28 Nov 2022 18:25:59 -0800 (PST)
X-Received: by 2002:a17:902:8c97:b0:189:13df:9dac with SMTP id t23-20020a1709028c9700b0018913df9dacmr34124484plo.34.1669688759430;
        Mon, 28 Nov 2022 18:25:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669688759; cv=none;
        d=google.com; s=arc-20160816;
        b=oWv24IU+If7CZhh7g5+gRvgz2HM8vI5loc3ZNXLtwxuJ16gnG9Oubqd3rQoQXhkDJF
         EgyYyUOcoEzVysGw3SsngxX/zPEsvi+L6XwTYxnvqYMXT1n/by9yaZMCuFxVWli8dGnI
         9qF2mTp3+2LAGOWpNLYKrB+8iBkrd/prLaQwvwiUJo/N/b7ucaxxKkOZqTRaOY+QvF03
         NZuzjbqnK/azRDzuOYa4A8bUghBzYZ+4ckdD/uHsG3mnLORH/guFhGhCGW/a1F1XDkh4
         WZqZJT+jrgjw9MaXOQ9j/bBmz/qI52h55un5wEDqvCTviWpIJcRRbNsEMvKoy1k0qIxP
         rnQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=QAeB7Vd5qU+ZP/QJ3z97GyaXug/x+K+O+tqqzF71qEE=;
        b=cIFGrbeVT13H209xFSvFSGOZq87jPK7s61M/izzqBct1OPi19E8lzSTqlQZzZuJwkj
         3K5h13PDIIgbmB28bhCGF47OPopPWWMPeqxwW6WY37TQXaRe/Jn+/RRF+RR2DTJrjkEz
         w/Mp7/FA5yLqTHe+PdEOZUL5zSbVoA1QYkNHpUxFoGZKPgILzJX3uE1s+saqKRyScMFu
         1/Ni1E89aP0Z8ye5BJ3zxc7/owTcm8LTzr5V2tUdS1rycLNvVKQLKxqv4L02B+8Ak2/8
         DdTAX8ex+zhFg0NWjLXUqxc+in0SiGAE6+7c7opWe4TrQI1J2QJMkODwDytbfCFSL8Sc
         HLoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=SUe4MDyy;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=YRT0kL4h;
       spf=pass (google.com: domain of 01010184c134919e-d7d79ac9-bd22-47a8-b46b-96f5e90c268a-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) smtp.mailfrom=01010184c134919e-d7d79ac9-bd22-47a8-b46b-96f5e90c268a-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-185.smtp-out.us-west-2.amazonses.com (a27-185.smtp-out.us-west-2.amazonses.com. [54.240.27.185])
        by gmr-mx.google.com with ESMTPS id l195-20020a633ecc000000b004772bae20ebsi713023pga.5.2022.11.28.18.25.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 28 Nov 2022 18:25:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 01010184c134919e-d7d79ac9-bd22-47a8-b46b-96f5e90c268a-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) client-ip=54.240.27.185;
Date: Tue, 29 Nov 2022 02:25:58 +0000
Message-ID: <01010184c134919e-d7d79ac9-bd22-47a8-b46b-96f5e90c268a-000000@us-west-2.amazonses.com>
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
Subject: PERFORCE change 3225582: commit da3f85646b027d05b70610993a1bb0e29705518c
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.29-54.240.27.185
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=SUe4MDyy;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=YRT0kL4h;       spf=pass
 (google.com: domain of 01010184c134919e-d7d79ac9-bd22-47a8-b46b-96f5e90c268a-000000@us-west-2.amazonses.com
 designates 54.240.27.185 as permitted sender) smtp.mailfrom=01010184c134919e-d7d79ac9-bd22-47a8-b46b-96f5e90c268a-000000@us-west-2.amazonses.com;
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

Change 3225582 by automation@source_control_dishonor on 2022/11/29 02:20:26

	commit da3f85646b027d05b70610993a1bb0e29705518c
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

.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/Documentation/arm/memory.txt#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/Kconfig#3 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/include/asm/kasan_def.h#1 add
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/include/asm/memory.h#2 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/kernel/entry-armv.S#3 edit
.. //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/mm/mmu.c#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/Documentation/arm/memory.txt#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/Kconfig#3 (text) ====

@@ -1472,6 +1472,15 @@
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

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/include/asm/memory.h#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/kernel/entry-armv.S#3 (text) ====

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

==== //depot/firmware/release/main/port/realtek/stark/platform/linux_kernel/arch/arm/mm/mmu.c#2 (text) ====

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01010184c134919e-d7d79ac9-bd22-47a8-b46b-96f5e90c268a-000000%40us-west-2.amazonses.com.
