Return-Path: <kasan-dev+bncBCJMBM5G5UCRBYWB6CNQMGQECQG47NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BFB526331DD
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 02:07:47 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id d130-20020a1f9b88000000b003b87d0db0d9sf4606496vke.15
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 17:07:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669079266; cv=pass;
        d=google.com; s=arc-20160816;
        b=z0b7+6tLMeCnRoz4DXdWj9Pu1J6gSiJ9GL3pPsx7uQLV244LafXMBK3fzjWsD7qkNq
         eagR0kalzETZ9keEBCRxoMWAn1memxTNv7VROyIAUwr1dcriVvtoKYn3M4lNYY6d1SVf
         CZQXgrPH0XOPDds8qFYRCxVaPClYZjX0laM86ARVzmgJLvFAsiUnycTuUwv2Lgo/lKpS
         6K2VZ75uJbZ/c3uscEe3qh4Ff5XDRdrTMkRtNP1vvYbf7j9lTM/FJnIvzmQfj+HfBK6u
         VF82cc11NMfnt/fBSxm1mO6pS0Vr93cGdQL4HV3xk9cAdZCrfoIVex7NVHH1JI/pG/83
         gHHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:subject:reply-to:from
         :cc:to:message-id:date:mime-version:dkim-signature;
        bh=b3aeZm7HkFvLGYi62U/UsQZHgUIzvYcD68cfDG6WWvk=;
        b=1BFk63hiQpV4QYINd38MZSI2cVv9A0lM1JDVRG9y7hb0dt29hudZs74HMTOsksz4MD
         yada8trV2P4tUKxH73NEOghkXMZczUBgkIqVy/SPBppad3xaZxuI0TVKT+7jw/ZfGJ8I
         wK36D2BR4o7ZGW68BihQFUYC6/4g2UbTyBQq9QxfOQ0nExEcCvn6jEHptoWhPlPnHtWR
         CjRDMJGCfjh3tr/Nte6jHu6299D4wqrnXkxYrNLKeuFYOxpBRl0HlmHEUR455tRgPM3c
         ll0RyEgboVAixFpvCPC9sBrlaI3MIHM3oGVzC7u1s33XUmp4ONTeLJbbPl1+KKVZjRaN
         E4Hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=S5N5R8ch;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BO314SfE;
       spf=pass (google.com: domain of 010101849ce06c5c-f72a9abc-84c8-497c-a2a3-33a0f50271ff-000000@us-west-2.amazonses.com designates 54.240.27.10 as permitted sender) smtp.mailfrom=010101849ce06c5c-f72a9abc-84c8-497c-a2a3-33a0f50271ff-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:subject:reply-to:from:cc:to
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b3aeZm7HkFvLGYi62U/UsQZHgUIzvYcD68cfDG6WWvk=;
        b=l3bznvfbl5dLKJooP8UJSao1AB2gVCoidONO49j9Wrw/HnNN4NwT0s4/llZ+uJLfv6
         Mvyjky+ZUR3u5PX9aeAZyi6M0DdZT1zq9q+dvxdJUvdpmiWNNmgesXK1p5Gbgock5PYG
         JfeDRCnGKO6NpBu2pwDEfE7zlDpOJwImweZHZSCnjQu7Nz2nfAXwqJ2lJxU0R+rgG7OX
         b3ITTpJNCWOxmTvW5sqOgT+0spKcUP8hS6ZcTxlm9bYhFstR69+vPEeQQoke2zzvp4To
         /yelDlKn0sPh+S0qB6P+IyhL4J0Ar0qshr4SZIrSAT6C8qCVEFkUlY5iwXNQUTqw1JM0
         Wu9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :subject:reply-to:from:cc:to:message-id:date:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=b3aeZm7HkFvLGYi62U/UsQZHgUIzvYcD68cfDG6WWvk=;
        b=EkIDrlafL/CI83MtNz9+sHVlF0ZL4JsFB6tF/CrkPlvvA0NVJWtVwWHlID4u5Vj/Wy
         QQSvTWhC6QUw5TNcv6egPCjfUZEmyP/w9GCuGJY4b6kqAUdJW3+/GHtGlpRJ7sPNNw9t
         x935Xxl8yBgI9A5aI+T53utPbz7oBnQ9il3q13mwbIaud3V/PCN1wrTuouzkU1cE3q8L
         KdsAPW+Tspo8IlTTK8CTXEsiVElfFgUQOcG5oje7b4x7BBugmKeLuYQUuPg8mC814xtc
         rWCnVGOi5tLE8Q+/0iaGsyR/68mO8LhkK3RFU4WIuXy+stHCq5akaPZjEBQf1+sM+GTl
         oeCQ==
X-Gm-Message-State: ANoB5pnboqjunqfOKNcvE1Byqxvo4ujwJDpe+xGzaSnRx8CJ4qANtHfL
	bPJBmaVyWKvaDMS5bItWyT8=
X-Google-Smtp-Source: AA0mqf7UORPfEXJf8NK013F1Oc3b6aZusfG8YQhoXIPHUllnneQwshiVQtYw/m1OBPlgqsHhLz9tpA==
X-Received: by 2002:a9f:3181:0:b0:408:c198:a734 with SMTP id v1-20020a9f3181000000b00408c198a734mr4388332uad.94.1669079266490;
        Mon, 21 Nov 2022 17:07:46 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a0d5:0:b0:3bc:2cac:f10e with SMTP id j204-20020a1fa0d5000000b003bc2cacf10els1394726vke.0.-pod-prod-gmail;
 Mon, 21 Nov 2022 17:07:45 -0800 (PST)
X-Received: by 2002:a1f:9dcd:0:b0:3b8:a3f9:be82 with SMTP id g196-20020a1f9dcd000000b003b8a3f9be82mr1668336vke.18.1669079265795;
        Mon, 21 Nov 2022 17:07:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669079265; cv=none;
        d=google.com; s=arc-20160816;
        b=JX0AsL20swsi+oJhF6rKZcKnIc07EYz1OqpIhrOCDbldnuT0EyAiWPnlzmzryoOeim
         4QAuntbvHOV0Vwz6pfkIdMVZ+TW7oOXg9eDqzIBAfUS/GDgQqqpZWw9Hb207q85R43vL
         xh/mP1ZzxV3iwtjlfntCSvRQ9rHag4dH+b8GPxbKvL9Gy61gLc8eGNssdyMaLBpdepqy
         XupJHlchDsxXpFP6hJRXSwah64bg0HCyBcbVHLr5OuG38r09rykzszrR2cCw8/bi1xKf
         1EsZBuoltYVJgyL44ph1cMuMRYUwOfPFh4aH3/jnXh+fFx2BqOxiDPXayS4ZT8a9DlB/
         mrlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:subject:reply-to:from:cc:to:message-id:date
         :dkim-signature:dkim-signature;
        bh=gOTAxaRZemegd9Oh4Kc2kh87cjSv+1aZ/k0Gt+fb3H0=;
        b=wYdneoeiNIUnYHacj4FF6OlKgRLhPsxvrpDXiVXb09vnBWZaIj6mKsnndUP4x7/Lbo
         t9xpMpln1kbzhdSNaudwSBFZgMyFizyF5XVrbcOZCwMdgpBu4ZPZ0Jxc4IRCATy9lKzv
         mZ4jIwH2gAaj7VFise4tNvjbpTZsIKqrK8uDfH61JvR+1FVXlUuZGtayF3AdRjhfHhyy
         IXz/kAuon+4Gfm7yoQYuuVjGFV3mDkHfXvbmr4f5wjoyxfvdt7BwoUXOZYXsW+0RySAN
         D9nJJH9eXc2k0fEJRGsW/NIJUXOXUayRSjqNwU3dCQBfZzt9cKvD04cdhbWhH042x8eC
         mWLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7 header.b=S5N5R8ch;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BO314SfE;
       spf=pass (google.com: domain of 010101849ce06c5c-f72a9abc-84c8-497c-a2a3-33a0f50271ff-000000@us-west-2.amazonses.com designates 54.240.27.10 as permitted sender) smtp.mailfrom=010101849ce06c5c-f72a9abc-84c8-497c-a2a3-33a0f50271ff-000000@us-west-2.amazonses.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=roku.com
Received: from a27-10.smtp-out.us-west-2.amazonses.com (a27-10.smtp-out.us-west-2.amazonses.com. [54.240.27.10])
        by gmr-mx.google.com with ESMTPS id t77-20020a1f9150000000b003b758af3b49si727813vkd.5.2022.11.21.17.07.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 17:07:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 010101849ce06c5c-f72a9abc-84c8-497c-a2a3-33a0f50271ff-000000@us-west-2.amazonses.com designates 54.240.27.10 as permitted sender) client-ip=54.240.27.10;
Date: Tue, 22 Nov 2022 01:07:44 +0000
Message-ID: <010101849ce06c5c-f72a9abc-84c8-497c-a2a3-33a0f50271ff-000000@us-west-2.amazonses.com>
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
Subject: PERFORCE change 3224927: commit ea528d8026798673349b7c7b5e80d5d9560c4f8b
Feedback-ID: 1.us-west-2.J7/CQbUSlVIlOn4fv32wqSnUATrm78Y7YaTj1nfQ4pI=:AmazonSES
X-SES-Outgoing: 2022.11.22-54.240.27.10
X-Original-Sender: no-reply@roku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@roku.com header.s=xgw4ulqzvzh432p4hgzcsfjqyyekywc7
 header.b=S5N5R8ch;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=BO314SfE;       spf=pass
 (google.com: domain of 010101849ce06c5c-f72a9abc-84c8-497c-a2a3-33a0f50271ff-000000@us-west-2.amazonses.com
 designates 54.240.27.10 as permitted sender) smtp.mailfrom=010101849ce06c5c-f72a9abc-84c8-497c-a2a3-33a0f50271ff-000000@us-west-2.amazonses.com;
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

Change 3224927 by automation@source_control_dishonor on 2022/11/22 01:02:35

	commit ea528d8026798673349b7c7b5e80d5d9560c4f8b
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

.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/Documentation/arm/memory.txt#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/Kconfig#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/include/asm/kasan_def.h#1 add
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/include/asm/memory.h#2 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/kernel/entry-armv.S#3 edit
.. //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/mm/mmu.c#2 edit

Differences ...

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/Documentation/arm/memory.txt#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/Kconfig#2 (text) ====

@@ -1473,6 +1473,15 @@
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

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/include/asm/memory.h#2 (text) ====

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

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/kernel/entry-armv.S#3 (text) ====

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

==== //depot/firmware/release/main/port/realtek/hank/platform/linux_kernel/arch/arm/mm/mmu.c#2 (text) ====

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/010101849ce06c5c-f72a9abc-84c8-497c-a2a3-33a0f50271ff-000000%40us-west-2.amazonses.com.
