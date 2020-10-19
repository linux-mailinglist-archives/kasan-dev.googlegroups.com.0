Return-Path: <kasan-dev+bncBDE6RCFOWIARBVFCWX6AKGQEBTF3F7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7845F2923CF
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 10:41:57 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id q15sf7123846wrw.8
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 01:41:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603096917; cv=pass;
        d=google.com; s=arc-20160816;
        b=mB6SZ4NF3sre6Sp+ktai/mOIoZ206mP2V4Sm5sp+3S+LgnyDup2G37yXTPrSTITFM2
         B2F3ki7wvpUeplAteUqGZOxntGkSNQqArZhxej6qCpccr+IygI97e0bklliOV1H0NiL3
         EZgZL45bsdtlweOwsBkFh0IJC9ZQ5FiI1PQmGX0OFeShVl1ozgf+RVDovTwVLI8ha8ok
         APZA6Cwu9+Tf0u9ku2pflSDqXh5Yd6K8XzGzKZtwnd3QKfUImyZzjgDJwaunDWFfQugX
         reriA7l1GCEf9MhFTbUcDnuD/CYkn3ZCsT/+3iOg+ELMkw9x3BmERYE11gaX8bq8OV6J
         tRFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aiLaqMSkIniB/nKNBkSxSgboxkTNGo0wuzaE/iz9YH0=;
        b=R7E0RH9qFfsWtlQ5okdaY7ULrkljzs7omeQgr6ICyT+ra7ESdQUakqMXpAl6329X0M
         iALg2JThdAsYLilKk8pvOJH5KDZ7hjV4znVW6yMt4N+gOGz3E2iglxb0w9CmqL53uG9D
         bV1a8bWsdIDHp8Pf9PhLA8+DLDdS5JsK8Ylc0/v7ZL+lEGkO5PRmgU8bDhZyiNLsywpg
         /pzfHfAQYbADl9bxfmaO9l7QBTINxMpGAhnWWdmkWpw3ecNbQohsXDxXuF2QINQRtXOT
         vPjteUgODSlm8d+HAbC9D2cBmdBw6QvguIt10ZG41mnR+DlGMuAp+saiKgv1aVSxeSxa
         pOCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ob1jnoZB;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aiLaqMSkIniB/nKNBkSxSgboxkTNGo0wuzaE/iz9YH0=;
        b=MIvGT5GE5mSM0msBvCNLnEmugf19+bnvBGRIVKFONCoFASLFhtF+3h1PT6KRZ87ZC2
         VitFuDR2YfTUo/PIP5q/ry68EX5ucr9/ovrhPBTj51GKBwlrFEc1jeyjUTB2SONlCbR5
         Eq5a/E5kD1wGUYb+sBHUb1/y64/Y8rLn5NBB7AAU3fIKa9mKjSiqfPLqaC50EJRR/6qg
         KIQPiyKVdiXskUxXYUD6Za64VXj+W7zIUY4ylbsSAIJnOoYBe0mdzrah3TxsGjCNc5gw
         cUTW1Yv8hgY/Vw/VgWfL2W2cUuXvWwRexervh96oq5rL2iGBDZxw2uZiZUZi51eZkWGS
         H7kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aiLaqMSkIniB/nKNBkSxSgboxkTNGo0wuzaE/iz9YH0=;
        b=J+nKOStFhuAT0TFQNp9ozuW8EBUU9ilJAwLUgVau0zqYFj8Mth3UszvWO8G/Omq/PZ
         Jt1pXGohEcQdr4i8D19wD9pa8vWILsD6FGMY7kYX+UBL14sZOkUqruwY5ruvVc+COui5
         pC6FJF5l7YzmKMQG7yAv8UkvqV0JI0/Ecpo7wGPPuW3FW3ihYCoB4orLi/prD4NNBKPP
         7JOyF6GpAGMrWg/4njkU5JV6x3wv4JbFITY+8RTCip+YZL+QmqNqw9wevz1e3J7n8/9+
         /J/ZqkPG0adexbKH/qQxag30fU87Xqk8hNbaGNwrfxUFdxufFlE91dT/c9PpvdSslhJi
         T8cQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531F4f0zIFlFOJfCIcfCRfGkKLx0gRAijgHvJX3m438GaPr1Urtw
	5hVDy/OuTZYeUUYRSewkHtY=
X-Google-Smtp-Source: ABdhPJz/UadeubyyxrKJmAFduUyCLu0xkK45Sz27X113RoJ8AVHdlpAMBszs9pgfyrcMJAEcm2WBww==
X-Received: by 2002:a5d:46c1:: with SMTP id g1mr19036185wrs.101.1603096917143;
        Mon, 19 Oct 2020 01:41:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a544:: with SMTP id j4ls9344534wrb.3.gmail; Mon, 19 Oct
 2020 01:41:56 -0700 (PDT)
X-Received: by 2002:adf:c5c3:: with SMTP id v3mr19008316wrg.205.1603096916265;
        Mon, 19 Oct 2020 01:41:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603096916; cv=none;
        d=google.com; s=arc-20160816;
        b=L7ocZQ2+Rc1+uxKdCBJDpEj2g/Qgc+BXAcfXWVu2VnACC0L1V25iTmTlk4+qovBnYX
         epK8wOjXfzdcTtn7uLFFAgwkWVHhcXjPSUOY3PmXZ3ltk1xuvqrxjHiaICyUWxT/ahm7
         ZYkdjQ5HcYhP+qwnVTgcbFKmXokT3YE1MV1kadTEIwqJvfU+dEEx6Wo+u55AhmvTxfD9
         nZo9LgPniv8+VizdYFGLVuEy0KwtVyvM6aLYf8tc1+keJv4Idm6jDbJbymajpfY0kDZ3
         26YJA0EtWPcZX+9HIH25ZmRSrsUNZAGaRP2MAIULFFJvsd/68/SipJdNqmIos7kyye5C
         rO2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=c21Ufxn7ZHMvuPZiRxw/BGOAehHCv3VLva/ICXX2zLs=;
        b=KtjHTX/SYILA6fkMZSd6KPtv/uWpiHFrQcgYt44y82cMPvsLO6Wsg3iCXzAoysiy+O
         Z7TU5jxJJzMnM5kQALWAFBPmdCXOJRakSJDsid3qaaZdz3a2+T4HL6h+37eFQvssl9K2
         YLMwE9Ru1KBo9lb9ELAhp9zv8XCTbDGvm1L/dAPF7yefcG1lIbODmmyNIRdl+eQO9ZnM
         /NUhSvnusS37NWCYFou+EJNuYZOfBdpY2JK8RxmNojfKgnpxrziY8Ui3BnPvsC4sH5mo
         MvLWgCCPa1G0Mv7SHqZ7yk3D71aYIfxYtiTbIL25qTTNwShtlCWAUxASBuk8pAxhLvI4
         TN1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ob1jnoZB;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id o4si143661wrx.4.2020.10.19.01.41.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 01:41:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id a9so13157642lfc.7
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 01:41:56 -0700 (PDT)
X-Received: by 2002:a19:ca4b:: with SMTP id h11mr6025390lfj.6.1603096915588;
        Mon, 19 Oct 2020 01:41:55 -0700 (PDT)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id b18sm3174795lfp.89.2020.10.19.01.41.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Oct 2020 01:41:55 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Mike Rapoport <rppt@linux.ibm.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Ahmad Fatoum <a.fatoum@pengutronix.de>,
	Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH 3/5 v16] ARM: Define the virtual space of KASan's shadow region
Date: Mon, 19 Oct 2020 10:41:38 +0200
Message-Id: <20201019084140.4532-4-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20201019084140.4532-1-linus.walleij@linaro.org>
References: <20201019084140.4532-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=ob1jnoZB;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

From: Abbott Liu <liuwenliang@huawei.com>

Define KASAN_SHADOW_OFFSET,KASAN_SHADOW_START and KASAN_SHADOW_END for
the Arm kernel address sanitizer. We are "stealing" lowmem (the 4GB
addressable by a 32bit architecture) out of the virtual address
space to use as shadow memory for KASan as follows:

 +----+ 0xffffffff
 |    |\
 |    | |-> Static kernel image (vmlinux) BSS and page table
 |    |/
 +----+ PAGE_OFFSET
 |    |\
 |    | |->  Loadable kernel modules virtual address space area
 |    |/
 +----+ MODULES_VADDR = KASAN_SHADOW_END
 |    |\
 |    | |-> The shadow area of kernel virtual address.
 |    |/
 +----+->  TASK_SIZE (start of kernel space) = KASAN_SHADOW_START the
 |    |\   shadow address of MODULES_VADDR
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
---
ChangeLog v15->v16:
- Collect Florian's Tested-by
- Resend with the other patches
ChangeLog v14->v15:
- Resend with the other patches
ChangeLog v13->v14:
- Resend with the other patches
ChangeLog v12->v13:
- Rebase on kernel v5.9-rc1
ChangeLog v11->v12:
- Resend with the other changes.
ChangeLog v10->v11:
- Resend with the other changes.
ChangeLog v9->v10:
- Rebase on v5.8-rc1
ChangeLog v8->v9:
- Collect Ard's tags.
ChangeLog v7->v8:
- Rewrote the PMD clearing code to take into account that
  KASan may not always be adjacent to MODULES_VADDR: if we
  compile for thumb, then there will be an 8 MB hole between
  the shadow memory and MODULES_VADDR. Make this explicit and
  use the KASAN defines with an explicit ifdef so it is clear
  what is going on in the prepare_page_table().
- Patch memory.rst to reflect the location of KASan shadow
  memory.
ChangeLog v6->v7:
- Use the SPDX license identifier.
- Rewrote the commit message and updates the illustration.
- Move KASAN_OFFSET Kconfig set-up into this patch and put it
  right after PAGE_OFFSET so it is clear how this works, and
  we have all defines in one patch.
- Added KASAN_SHADOW_OFFSET of 0x8f000000 for 3G_OPT.
  See the calculation in the commit message.
- Updated the commit message with detailed information on
  how KASAN_SHADOW_OFFSET is obtained for the different
  VMSPLIT/PAGE_OFFSET options.
---
 Documentation/arm/memory.rst       |  5 ++
 arch/arm/Kconfig                   |  9 ++++
 arch/arm/include/asm/kasan_def.h   | 81 ++++++++++++++++++++++++++++++
 arch/arm/include/asm/memory.h      |  5 ++
 arch/arm/include/asm/uaccess-asm.h |  2 +-
 arch/arm/kernel/entry-armv.S       |  3 +-
 arch/arm/kernel/entry-common.S     |  9 ++--
 arch/arm/mm/mmu.c                  | 18 +++++++
 8 files changed, 127 insertions(+), 5 deletions(-)
 create mode 100644 arch/arm/include/asm/kasan_def.h

diff --git a/Documentation/arm/memory.rst b/Documentation/arm/memory.rst
index 34bb23c44a71..0cb1e2938823 100644
--- a/Documentation/arm/memory.rst
+++ b/Documentation/arm/memory.rst
@@ -77,6 +77,11 @@ MODULES_VADDR	MODULES_END-1	Kernel module space
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
diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index e00d94b16658..0489b8d07172 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -1324,6 +1324,15 @@ config PAGE_OFFSET
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
diff --git a/arch/arm/include/asm/kasan_def.h b/arch/arm/include/asm/kasan_def.h
new file mode 100644
index 000000000000..5739605aa7cf
--- /dev/null
+++ b/arch/arm/include/asm/kasan_def.h
@@ -0,0 +1,81 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ *  arch/arm/include/asm/kasan_def.h
+ *
+ *  Copyright (c) 2018 Huawei Technologies Co., Ltd.
+ *
+ *  Author: Abbott Liu <liuwenliang@huawei.com>
+ */
+
+#ifndef __ASM_KASAN_DEF_H
+#define __ASM_KASAN_DEF_H
+
+#ifdef CONFIG_KASAN
+
+/*
+ * Define KASAN_SHADOW_OFFSET,KASAN_SHADOW_START and KASAN_SHADOW_END for
+ * the Arm kernel address sanitizer. We are "stealing" lowmem (the 4GB
+ * addressable by a 32bit architecture) out of the virtual address
+ * space to use as shadow memory for KASan as follows:
+ *
+ * +----+ 0xffffffff
+ * |    |							\
+ * |    | |-> Static kernel image (vmlinux) BSS and page table
+ * |    |/
+ * +----+ PAGE_OFFSET
+ * |    |							\
+ * |    | |->  Loadable kernel modules virtual address space area
+ * |    |/
+ * +----+ MODULES_VADDR = KASAN_SHADOW_END
+ * |    |						\
+ * |    | |-> The shadow area of kernel virtual address.
+ * |    |/
+ * +----+->  TASK_SIZE (start of kernel space) = KASAN_SHADOW_START the
+ * |    |\   shadow address of MODULES_VADDR
+ * |    | |
+ * |    | |
+ * |    | |-> The user space area in lowmem. The kernel address
+ * |    | |   sanitizer do not use this space, nor does it map it.
+ * |    | |
+ * |    | |
+ * |    | |
+ * |    | |
+ * |    |/
+ * ------ 0
+ *
+ * 1) KASAN_SHADOW_START
+ *   This value begins with the MODULE_VADDR's shadow address. It is the
+ *   start of kernel virtual space. Since we have modules to load, we need
+ *   to cover also that area with shadow memory so we can find memory
+ *   bugs in modules.
+ *
+ * 2) KASAN_SHADOW_END
+ *   This value is the 0x100000000's shadow address: the mapping that would
+ *   be after the end of the kernel memory at 0xffffffff. It is the end of
+ *   kernel address sanitizer shadow area. It is also the start of the
+ *   module area.
+ *
+ * 3) KASAN_SHADOW_OFFSET:
+ *   This value is used to map an address to the corresponding shadow
+ *   address by the following formula:
+ *
+ *	shadow_addr = (address >> 3) + KASAN_SHADOW_OFFSET;
+ *
+ *  As you would expect, >> 3 is equal to dividing by 8, meaning each
+ *  byte in the shadow memory covers 8 bytes of kernel memory, so one
+ *  bit shadow memory per byte of kernel memory is used.
+ *
+ *  The KASAN_SHADOW_OFFSET is provided in a Kconfig option depending
+ *  on the VMSPLIT layout of the system: the kernel and userspace can
+ *  split up lowmem in different ways according to needs, so we calculate
+ *  the shadow offset depending on this.
+ */
+
+#define KASAN_SHADOW_SCALE_SHIFT	3
+#define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+#define KASAN_SHADOW_END	((UL(1) << (32 - KASAN_SHADOW_SCALE_SHIFT)) \
+				 + KASAN_SHADOW_OFFSET)
+#define KASAN_SHADOW_START      ((KASAN_SHADOW_END >> 3) + KASAN_SHADOW_OFFSET)
+
+#endif
+#endif
diff --git a/arch/arm/include/asm/memory.h b/arch/arm/include/asm/memory.h
index bb79e52aeb90..598dbdca2017 100644
--- a/arch/arm/include/asm/memory.h
+++ b/arch/arm/include/asm/memory.h
@@ -18,6 +18,7 @@
 #ifdef CONFIG_NEED_MACH_MEMORY_H
 #include <mach/memory.h>
 #endif
+#include <asm/kasan_def.h>
 
 /* PAGE_OFFSET - the virtual address of the start of the kernel image */
 #define PAGE_OFFSET		UL(CONFIG_PAGE_OFFSET)
@@ -28,7 +29,11 @@
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
diff --git a/arch/arm/include/asm/uaccess-asm.h b/arch/arm/include/asm/uaccess-asm.h
index 907571fd05c6..e6eb7a2aaf1e 100644
--- a/arch/arm/include/asm/uaccess-asm.h
+++ b/arch/arm/include/asm/uaccess-asm.h
@@ -85,7 +85,7 @@
 	 */
 	.macro	uaccess_entry, tsk, tmp0, tmp1, tmp2, disable
 	ldr	\tmp1, [\tsk, #TI_ADDR_LIMIT]
-	mov	\tmp2, #TASK_SIZE
+	ldr	\tmp2, =TASK_SIZE
 	str	\tmp2, [\tsk, #TI_ADDR_LIMIT]
  DACR(	mrc	p15, 0, \tmp0, c3, c0, 0)
  DACR(	str	\tmp0, [sp, #SVC_DACR])
diff --git a/arch/arm/kernel/entry-armv.S b/arch/arm/kernel/entry-armv.S
index 55a47df04773..c4220f51fcf3 100644
--- a/arch/arm/kernel/entry-armv.S
+++ b/arch/arm/kernel/entry-armv.S
@@ -427,7 +427,8 @@ ENDPROC(__fiq_abt)
 	@ if it was interrupted in a critical region.  Here we
 	@ perform a quick test inline since it should be false
 	@ 99.9999% of the time.  The rest is done out of line.
-	cmp	r4, #TASK_SIZE
+	ldr	r0, =TASK_SIZE
+	cmp	r4, r0
 	blhs	kuser_cmpxchg64_fixup
 #endif
 #endif
diff --git a/arch/arm/kernel/entry-common.S b/arch/arm/kernel/entry-common.S
index 271cb8a1eba1..fee279e28a72 100644
--- a/arch/arm/kernel/entry-common.S
+++ b/arch/arm/kernel/entry-common.S
@@ -50,7 +50,8 @@ __ret_fast_syscall:
  UNWIND(.cantunwind	)
 	disable_irq_notrace			@ disable interrupts
 	ldr	r2, [tsk, #TI_ADDR_LIMIT]
-	cmp	r2, #TASK_SIZE
+	ldr	r1, =TASK_SIZE
+	cmp	r2, r1
 	blne	addr_limit_check_failed
 	ldr	r1, [tsk, #TI_FLAGS]		@ re-check for syscall tracing
 	tst	r1, #_TIF_SYSCALL_WORK | _TIF_WORK_MASK
@@ -87,7 +88,8 @@ __ret_fast_syscall:
 #endif
 	disable_irq_notrace			@ disable interrupts
 	ldr	r2, [tsk, #TI_ADDR_LIMIT]
-	cmp	r2, #TASK_SIZE
+	ldr     r1, =TASK_SIZE
+	cmp     r2, r1
 	blne	addr_limit_check_failed
 	ldr	r1, [tsk, #TI_FLAGS]		@ re-check for syscall tracing
 	tst	r1, #_TIF_SYSCALL_WORK | _TIF_WORK_MASK
@@ -128,7 +130,8 @@ ret_slow_syscall:
 	disable_irq_notrace			@ disable interrupts
 ENTRY(ret_to_user_from_irq)
 	ldr	r2, [tsk, #TI_ADDR_LIMIT]
-	cmp	r2, #TASK_SIZE
+	ldr     r1, =TASK_SIZE
+	cmp	r2, r1
 	blne	addr_limit_check_failed
 	ldr	r1, [tsk, #TI_FLAGS]
 	tst	r1, #_TIF_WORK_MASK
diff --git a/arch/arm/mm/mmu.c b/arch/arm/mm/mmu.c
index a7231d151c63..50ae506a39e1 100644
--- a/arch/arm/mm/mmu.c
+++ b/arch/arm/mm/mmu.c
@@ -30,6 +30,7 @@
 #include <asm/procinfo.h>
 #include <asm/memory.h>
 #include <asm/pgalloc.h>
+#include <asm/kasan_def.h>
 
 #include <asm/mach/arch.h>
 #include <asm/mach/map.h>
@@ -1265,8 +1266,25 @@ static inline void prepare_page_table(void)
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
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201019084140.4532-4-linus.walleij%40linaro.org.
