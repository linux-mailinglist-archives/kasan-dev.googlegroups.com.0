Return-Path: <kasan-dev+bncBC447XVYUEMRBXOVW6GQMGQENNIJH3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 78D7446943D
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:50:06 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id t9-20020a056512068900b00417ba105469sf3699764lfe.4
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:50:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638787806; cv=pass;
        d=google.com; s=arc-20160816;
        b=rRsxg4cNJ2F8Qda47gP0ER0O/RgR+at6v9tXNGHCSOOmR+viUN3btxdwB6YVoaqwC0
         td8hqJlZ3PEPsZv2nVWJa0Jn9Qaz7sHk7unTMikjq+33I5voJ6xVc2vjTrgsmaf1566j
         qmc3XzWHEGA3sYSNKsXYl3CfaEn7IM/6X+Fn+N3ggCsVMG6d6noKv28CADo6KeMAj1Gw
         gaj+uDiG89kM8tnIqFEVZnWaO4J/qDF8ChWh8zJaANv97xPsb9/skixkbQgyuKvmp1yw
         3gYvhl3xFfjVwHy6rgqPGq1+B2mNN7c34w/bCyfLEnxlnl+UM7AHQ+viUDaov29qdTBu
         noYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=RuewOUaaCS7kGndqfr0raKf7mZy/szrZtJs7nx0ormY=;
        b=Qu3RAo6/vPAZJ3SbnjIm/XWkim2uyDFKuY81rdwFBzERzkQi/FSb2mOvSULekpU9Sq
         UMOEu+fZJTgj6kmIEYCkTF3Ou8mb7DCX3WiwBcIWsJhoUJMtsw6YDKfOJkqCKnmaeoF3
         ROeqxR00vozYxAXi/WwlTw9YujOk847mRLAitd8QqVtL4GnTzjYQHxfI6nhLnNzUbeT1
         J3MCU4FUzzbhhp9HtCd0JCVIk4HsOKPUE9yf6Ms37lkzYOoQyghE/zUHcVLcDdTZ0PCb
         bsNaRGve/Hw9LwcgU0mymzt/3Vwqaf1/CHPPXt8K8KjSc7CscF5alWSjsNshXqOvee3X
         ervg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RuewOUaaCS7kGndqfr0raKf7mZy/szrZtJs7nx0ormY=;
        b=Im5PAraLRx3dAJntQFjqw7qDa13AceLi06epHI9wLVRylnrpjebrv5YxRGhD4NVUc/
         Lpo7MWyeevDYNABijSbGEyPzQrTRk7oYvkBqwIKeYKNIoRTcwiCPWWSSxoEUNUKXwA2R
         wW1qMEHERJ4ExOrPlh+MevuPEbjfauCQ3a6PHqBXrvke8Jg8GP9qqDMyz87d0zCVwNue
         GxU1Wr1E5gyJ8ezbzUWy2owCIs+mDbwPu0O4n1lAG1P0K/JSfgCXzSXpLtJAvUjkRMGF
         V2il6UmKgkAnMvjYAB+/1W3JA5fjnsqX4wTm3qUM2iE1HReDwEChxpJQKQNK8e3TIP4D
         fqGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RuewOUaaCS7kGndqfr0raKf7mZy/szrZtJs7nx0ormY=;
        b=wzAsv/RclS2RZSbDRxx99lFPxJBmpzpslLVgFSByW+A+llIJHk9RNxmkiJM9H7QvUb
         0IgWFxwtxUsoplhhxo9tlRnWAvJ0r5tv/HF91nb6FH2EI+97EhC6yma0jE7peBFgf+Mz
         9m/Q96+R7ah0ilX5oQ/VOQd6BRFysD3hF1yuNkMYchyIK61JGGzt/sBwKWejBM1uYZQo
         0fPaPQB9Q6zFPy6JnvBwefmQDBO7jA05cjWH6M/b2if5i1knBIU+fAbCFWYm0WktpM9i
         XbQVCRO1fbrXnVsIfIpo9WuOl2PAa3wE8DXaH6+6R/r27e6/aPQXj89ndh9suYQiS69u
         deww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531d1aVDLVqhWSMu6y25mN8sne243jsIt6SI7dv07PtwbwEatdPH
	XdJs7dMo+yfes8ZtjMSohD4=
X-Google-Smtp-Source: ABdhPJy0ZjpgPNktuxKz/FP9mv/NdhghdUhElygXb28wqN/SRHjl4P+MGoD2besW6tZ6S797uIIxeg==
X-Received: by 2002:a19:ee01:: with SMTP id g1mr36005447lfb.44.1638787806068;
        Mon, 06 Dec 2021 02:50:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e10:: with SMTP id i16ls694588lfv.3.gmail; Mon, 06
 Dec 2021 02:50:05 -0800 (PST)
X-Received: by 2002:a05:6512:1115:: with SMTP id l21mr33203057lfg.201.1638787805242;
        Mon, 06 Dec 2021 02:50:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638787805; cv=none;
        d=google.com; s=arc-20160816;
        b=dfY4c2XGrXonnRuWX+wzgyUOuOw9iZUYj9mahNC1P/SFtaK5nIC/Zx4MIIs86NEAb2
         wfjjQbysoMKlXL57UT7ZpplbICH7IW15mmQX8IbvB2TqewS+4hp52i6fufRrOAlCaIKS
         OR1wb1KGQRE7AXShNfn9kqBEjruHdFRNevf++PAK586duO3kE7WYeOk/H/kHjyfUDsIq
         06ljYxcb8jvKei3tPrEAGAt2RRrFbDTS4NhgRqQvO6Y710Xffp2E1vJuKfgm31bIDs7/
         YCyIRXy3O4UTXTP+QLpWjzwI0zAl4VUzis9W2U1EQLBRauzaEbsU7WYyvQNTPIUXccfa
         EHwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=Uq7Gnu2dokVPS8bxmGq7O67GOMdU6Avy0AVm7c3w5fY=;
        b=n7N8ftgAIqHQPjgP7HeYnNBZBEsHzb7vuD4KfVdKJCdKD+jT3AVfLB5VJ88XR+NLKD
         JqgWUw5nMdjh4Y3CBNbtY7yknX06uGkp7wWFwgoVC3XT68nUIP1dmrhkGRRwF1T2eRbD
         G4AHvdr1tueCcmfV8jbTUMpbqgcUzd7UfdGSyF+u05MPxJ2xfZMNnBdLqCMWS8iNhm1t
         v7uohKU0iACykhbUp1W1pepMmrgON0It7WV7/w602z8wOiD+kzaqkYayzPoGK7dd36f9
         pMNT4Kx9jfvQMRpMZOh84OxA+F0nfbmxfNGCv++GZ/Wl//fNhRGOlFvu8fUm5CmXe2LH
         2n5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay3-d.mail.gandi.net (relay3-d.mail.gandi.net. [217.70.183.195])
        by gmr-mx.google.com with ESMTPS id e15si892797ljg.0.2021.12.06.02.50.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 02:50:05 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.195 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.195;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay3-d.mail.gandi.net (Postfix) with ESMTPSA id B1A846000F;
	Mon,  6 Dec 2021 10:49:55 +0000 (UTC)
Message-ID: <3283761f-0506-464b-d351-af8ddecafa9b@ghiti.fr>
Date: Mon, 6 Dec 2021 11:49:55 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.1
Subject: Re: [PATCH v2 00/10] Introduce sv48 support without relocatable
 kernel
Content-Language: en-US
To: =?UTF-8?Q?Heiko_St=c3=bcbner?= <heiko@sntech.de>,
 Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Zong Li <zong.li@sifive.com>, Anup Patel <anup@brainfault.org>,
 Atish Patra <Atish.Patra@wdc.com>, Christoph Hellwig <hch@lst.de>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 Kees Cook <keescook@chromium.org>, Guo Ren <guoren@linux.alibaba.com>,
 Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
 Mayuresh Chitale <mchitale@ventanamicro.com>, linux-doc@vger.kernel.org,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-efi@vger.kernel.org,
 linux-arch@vger.kernel.org, Alexandre Ghiti <alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
 <2700575.YIZvDWadBg@diego>
From: Alexandre ghiti <alex@ghiti.fr>
In-Reply-To: <2700575.YIZvDWadBg@diego>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.195 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

On 11/25/21 00:29, Heiko St=C3=BCbner wrote:
> Am Mittwoch, 29. September 2021, 16:51:03 CET schrieb Alexandre Ghiti:
>> This patchset allows to have a single kernel for sv39 and sv48 without
>> being relocatable.
>>                                                                         =
         =20
>> The idea comes from Arnd Bergmann who suggested to do the same as x86,
>> that is mapping the kernel to the end of the address space, which allows
>> the kernel to be linked at the same address for both sv39 and sv48 and
>> then does not require to be relocated at runtime.
>>                                                                         =
         =20
>> This implements sv48 support at runtime. The kernel will try to
>> boot with 4-level page table and will fallback to 3-level if the HW does=
 not
>> support it. Folding the 4th level into a 3-level page table has almost n=
o
>> cost at runtime.
>>                                                                         =
         =20
>> Tested on:
>>    - qemu rv64 sv39: OK
>>    - qemu rv64 sv48: OK
>>    - qemu rv64 sv39 + kasan: OK
>>    - qemu rv64 sv48 + kasan: OK
>>    - qemu rv32: OK
>>    - Unmatched: OK
> On a beagleV (which supports only sv39) I've tested both the limit via
> the mmu-type in the devicetree and also that the fallback works when
> I disable the mmu-type in the dt, so
>
> Tested-by: Heiko Stuebner <heiko@sntech.de>
>

Thanks Heiko for testing this, unfortunately I could not add this tag to=20
the latest version as significant changes came up.

Thanks again for taking the time to test this,

Alex


>>   =20
>>                                                                         =
         =20
>> Changes in v2:
>>    - Rebase onto for-next
>>    - Fix KASAN
>>    - Fix stack canary
>>    - Get completely rid of MAXPHYSMEM configs
>>    - Add documentation
>>
>> Alexandre Ghiti (10):
>>    riscv: Allow to dynamically define VA_BITS
>>    riscv: Get rid of MAXPHYSMEM configs
>>    asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
>>    riscv: Implement sv48 support
>>    riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
>>    riscv: Explicit comment about user virtual address space size
>>    riscv: Improve virtual kernel memory layout dump
>>    Documentation: riscv: Add sv48 description to VM layout
>>    riscv: Initialize thread pointer before calling C functions
>>    riscv: Allow user to downgrade to sv39 when hw supports sv48
>>
>>   Documentation/riscv/vm-layout.rst             |  36 ++
>>   arch/riscv/Kconfig                            |  35 +-
>>   arch/riscv/configs/nommu_k210_defconfig       |   1 -
>>   .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
>>   arch/riscv/configs/nommu_virt_defconfig       |   1 -
>>   arch/riscv/include/asm/csr.h                  |   3 +-
>>   arch/riscv/include/asm/fixmap.h               |   1 +
>>   arch/riscv/include/asm/kasan.h                |   2 +-
>>   arch/riscv/include/asm/page.h                 |  10 +
>>   arch/riscv/include/asm/pgalloc.h              |  40 +++
>>   arch/riscv/include/asm/pgtable-64.h           | 108 +++++-
>>   arch/riscv/include/asm/pgtable.h              |  30 +-
>>   arch/riscv/include/asm/sparsemem.h            |   6 +-
>>   arch/riscv/kernel/cpu.c                       |  23 +-
>>   arch/riscv/kernel/head.S                      |   4 +-
>>   arch/riscv/mm/context.c                       |   4 +-
>>   arch/riscv/mm/init.c                          | 323 +++++++++++++++---
>>   arch/riscv/mm/kasan_init.c                    |  91 +++--
>>   drivers/firmware/efi/libstub/efi-stub.c       |   2 +
>>   include/asm-generic/pgalloc.h                 |  24 +-
>>   include/linux/sizes.h                         |   1 +
>>   21 files changed, 615 insertions(+), 131 deletions(-)
>>
>>
>
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3283761f-0506-464b-d351-af8ddecafa9b%40ghiti.fr.
