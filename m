Return-Path: <kasan-dev+bncBC447XVYUEMRBA5UQOAQMGQEXIXRW3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 86D28312AAB
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 07:28:20 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id p19sf3254lji.10
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Feb 2021 22:28:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612765700; cv=pass;
        d=google.com; s=arc-20160816;
        b=yonxOLVl63yOKPDlJizXz0dcjrd9QWVUZa7Y5ci4SAhNGN6sHBVIwW9hsQBgvgnOay
         k//DcrCSE1autOphhQKECkeiin83g1kS1UP995PqwPcDHWqXCFsCr95LRBiDLh8g80O8
         VFVnppRQernGul4CX2IlGyhlQADz+8Iq8MXuVHVfW7M05vebl67XLw3QJ4UXYmcgGh4v
         lJpi8YcFtR7wdFjqUt4KRBGRez2YB0ArkUOZE/D8MkcUSq7AWWw7ByXXHCK9XmIpwQNv
         yGVBAkZOCaKG92DuFNMXOvVdGMRZKHVo3PIMkusEDDYLJVqYOQTBpdxgMjqeNIXqURRY
         lz6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:subject:from:sender:dkim-signature;
        bh=1+qldbjaDYjHvlZZ7WtgLVM2mjHaGxuavBVzXZov3aI=;
        b=a2S9eCHMcWoONnSADSfn7frXNC9JCWDXnIcNuhgwHeUlBaBsMi/uJ8mDJUgcsHoF/L
         FgXMu9eOK8n7Pb0NkT4kkZZVp8Bm4IVWyIuQMl2c3pUGBS+mrx8TXhDGOKvOl43DhhDF
         bBNfUcu6y0ZOaRXvMbptb+huW+jqP/FsLhOW4t9ggt8RvN5srce1/KJInqRzFg4i4ueI
         DaOtjgXGx4lHOZg0ZrU7w+4phu5tZDBriaJPOgEeNgqXqNxN5FsuH07ODZztwXiGgFzs
         l4IyPLlHf5wjjm9sjOnWA7bZ8XSpYUifCkNDJIeo2IBPCmdER7lSiTkyX1zpC0+D5KR7
         sDcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1+qldbjaDYjHvlZZ7WtgLVM2mjHaGxuavBVzXZov3aI=;
        b=LUhcRtE8HbcsgFYUlRva+ALgOIXVSWFhiVb0n0YFEeuHrozJ7uo2MqISbhLRS51gU4
         U3D4tmU8aQ+q5wyu93QDtB978k7TGBV9otiiLyc2MeUsMhE39pEo1b2Ja6GUkEp8h3MW
         +gv+YEkAK1QX1UZtdWK2gLhRAOHsynY2VDTL7KHldnYFoLT+1bw4lfIkZ65TJ1Z9MJhs
         eWeLFuOyiGMsAd+YhVmlRloFfYQ66E+db6drtMY9ZZePvowzDsvMxdAL3klVaV6Ayu7z
         Hz28GFMPf67g69wfUP9qXnDEZOYZBzB3XziZkkhdUTATj6Fty3xT6mjRcXkraCBteHLk
         6OAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1+qldbjaDYjHvlZZ7WtgLVM2mjHaGxuavBVzXZov3aI=;
        b=Y6+dEV2QpqRiCcM/K4Q6SSYc+bJ+WJtSKZn3hwGCVRsF8z3/C0Eu/3KM9rK4TQhdZG
         LktAIKWMnJhEE9ThJzGt50S3+FfppMm6uaf8kmh0AN4dgp3PnMpfCLvyN6yXnC+1KBfq
         GvSSTYyUz5rjNq4otY1Gynap2Hcn2GhHpVvVFQuhGJcO4yxTayooPGFbYBUGSOFi12XP
         nTDa2qqgF22RjfTJpTRvygVv70Lelm5RmL+H6EHckJ1W9unbFFX6JZ62SgZqgErqPlYR
         BHXhst1s32ZRvIkqAZEWC67UYSgEQUsIkSxeoA6wDP9fIza/l/Xr03j4VYNOQwxqYHI3
         6RUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KdquwKx9ATgQbogrCmkG7kJiBq410dVLrckv/yZiIKaY331fp
	3s4N5+RseysGkzuhjS4a+PI=
X-Google-Smtp-Source: ABdhPJxafNp/jmtAHxFhy0At6gXjye9gbOwFHjGj6oMVn07mjVdkr6ZO9nmf1RpCM3oP47ld9S6Htg==
X-Received: by 2002:a2e:9c88:: with SMTP id x8mr10314021lji.409.1612765700031;
        Sun, 07 Feb 2021 22:28:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls3085084lff.1.gmail; Sun, 07
 Feb 2021 22:28:19 -0800 (PST)
X-Received: by 2002:ac2:4c26:: with SMTP id u6mr9289048lfq.347.1612765699005;
        Sun, 07 Feb 2021 22:28:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612765699; cv=none;
        d=google.com; s=arc-20160816;
        b=Xx7gN2hZMIIwODhC/FSN4ttDK2TXd9DPPkMkVyHWPr1ef5kPHYmetpbHfEK9E9v1dW
         zUGQJp2VBh48N8fSEWRrqF+Zxgqak6WOW3HrDIOeedXK2RoXTxNPBaBaKR+LZhFRH6cP
         hspCEC8glbmqnRvXMS25ak47Lljo+v3OpCTinawpQ4tOBZNto4KCWzqr3/ePj5iTPeWi
         HOK/zJCANIlhApsbonyE/ByHN+ZFY8OV5WQXnN2cyyd7IpZrSp4nvA88BpqJTMAttTTL
         dzw7c0PLCpf+TQm2tekwjnx5W5H69ybXufLQL1YURFL+vFRw77jTsRYa1baiR/RvrLsD
         ofxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:subject:from;
        bh=Z8uS0inXTkM3VYag9Eo5KF9pIJxppyvChDaKXZo5uz4=;
        b=q1xdmSh2/pGwPUTHMLz/oaDI0tiiI5IBfoLfh5qev0gU1Cs5Ihzkfrb4F61sAsWFDn
         VdAabiwdVPmMskaXbxL64xeEorg1QVCsj3Kq63PJgKPA0TLMjZWgaTEhPiNfDnka/qAw
         /fK8xh7b4NCbfP91nq1KTIzpWsSx1Bqwkv8NIvLO7HE5SvDNFWXnSBEJv0reB92rsLCc
         goYcTr5OWqIMKGe5WgwA+pkUMp448nwF6gpDsnr53N4i8QXSh5QYo4woce6ZPJRlA6AS
         ASa/9v7SMMqna1dAcGRsYScT9Qr4jkQz2lefxRmorVhhioGUdLTYAJmuHipIUYmVbyVJ
         TFjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [217.70.183.196])
        by gmr-mx.google.com with ESMTPS id k21si194240lji.3.2021.02.07.22.28.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 07 Feb 2021 22:28:18 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.196;
X-Originating-IP: 82.65.183.113
Received: from [172.16.5.113] (82-65-183-113.subs.proxad.net [82.65.183.113])
	(Authenticated sender: alex@ghiti.fr)
	by relay4-d.mail.gandi.net (Postfix) with ESMTPSA id CCB10E0007;
	Mon,  8 Feb 2021 06:28:13 +0000 (UTC)
From: Alex Ghiti <alex@ghiti.fr>
Subject: Re: [PATCH v2 1/1] riscv/kasan: add KASAN_VMALLOC support
To: Palmer Dabbelt <palmer@dabbelt.com>, nylon7@andestech.com
Cc: aou@eecs.berkeley.edu, nickhu@andestech.com, alankao@andestech.com,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 nylon7717@gmail.com, glider@google.com,
 Paul Walmsley <paul.walmsley@sifive.com>, aryabinin@virtuozzo.com,
 linux-riscv@lists.infradead.org, dvyukov@google.com
References: <mhng-443fd141-b9a3-4be6-a056-416877f99ea4@palmerdabbelt-glaptop>
Message-ID: <2b2f3038-3e27-8763-cf78-3fbbfd2100a0@ghiti.fr>
Date: Mon, 8 Feb 2021 01:28:13 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <mhng-443fd141-b9a3-4be6-a056-416877f99ea4@palmerdabbelt-glaptop>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.196 is neither permitted nor denied by best guess
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

Hi Nylon,

Le 1/22/21 =C3=A0 10:56 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
> On Fri, 15 Jan 2021 21:58:35 PST (-0800), nylon7@andestech.com wrote:
>> It references to x86/s390 architecture.
>> >> So, it doesn't map the early shadow page to cover VMALLOC space.
>>
>> Prepopulate top level page table for the range that would otherwise be
>> empty.
>>
>> lower levels are filled dynamically upon memory allocation while
>> booting.

I think we can improve the changelog a bit here with something like that:

"KASAN vmalloc space used to be mapped using kasan early shadow page.=20
KASAN_VMALLOC requires the top-level of the kernel page table to be=20
properly populated, lower levels being filled dynamically upon memory=20
allocation at runtime."

>>
>> Signed-off-by: Nylon Chen <nylon7@andestech.com>
>> Signed-off-by: Nick Hu <nickhu@andestech.com>
>> ---
>> =C2=A0arch/riscv/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 |=C2=A0 1 +
>> =C2=A0arch/riscv/mm/kasan_init.c | 57 ++++++++++++++++++++++++++++++++++=
+++-
>> =C2=A02 files changed, 57 insertions(+), 1 deletion(-)
>>
>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>> index 81b76d44725d..15a2c8088bbe 100644
>> --- a/arch/riscv/Kconfig
>> +++ b/arch/riscv/Kconfig
>> @@ -57,6 +57,7 @@ config RISCV
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL_RELATIVE
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN if MMU && 64BIT
>> +=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB_QXFER_PKT
>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_MMAP_RND_BITS if MMU
>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>> index 12ddd1f6bf70..4b9149f963d3 100644
>> --- a/arch/riscv/mm/kasan_init.c
>> +++ b/arch/riscv/mm/kasan_init.c
>> @@ -9,6 +9,19 @@
>> =C2=A0#include <linux/pgtable.h>
>> =C2=A0#include <asm/tlbflush.h>
>> =C2=A0#include <asm/fixmap.h>
>> +#include <asm/pgalloc.h>
>> +
>> +static __init void *early_alloc(size_t size, int node)
>> +{
>> +=C2=A0=C2=A0=C2=A0 void *ptr =3D memblock_alloc_try_nid(size, size,
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __pa(MAX_DMA_ADDRESS), MEMBL=
OCK_ALLOC_ACCESSIBLE, node);
>> +
>> +=C2=A0=C2=A0=C2=A0 if (!ptr)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 panic("%pS: Failed to alloca=
te %zu bytes align=3D%zx nid=3D%d=20
>> from=3D%llx\n",
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __fu=
nc__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
>> +
>> +=C2=A0=C2=A0=C2=A0 return ptr;
>> +}
>>
>> =C2=A0extern pgd_t early_pg_dir[PTRS_PER_PGD];
>> =C2=A0asmlinkage void __init kasan_early_init(void)
>> @@ -83,6 +96,40 @@ static void __init populate(void *start, void *end)
>> =C2=A0=C2=A0=C2=A0=C2=A0 memset(start, 0, end - start);
>> =C2=A0}
>>
>> +void __init kasan_shallow_populate(void *start, void *end)
>> +{
>> +=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned long)start & PAGE_=
MASK;
>> +=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN((unsigned long)end=
);
>> +=C2=A0=C2=A0=C2=A0 unsigned long pfn;
>> +=C2=A0=C2=A0=C2=A0 int index;
>> +=C2=A0=C2=A0=C2=A0 void *p;
>> +=C2=A0=C2=A0=C2=A0 pud_t *pud_dir, *pud_k;
>> +=C2=A0=C2=A0=C2=A0 pgd_t *pgd_dir, *pgd_k;
>> +=C2=A0=C2=A0=C2=A0 p4d_t *p4d_dir, *p4d_k;
>> +
>> +=C2=A0=C2=A0=C2=A0 while (vaddr < vend) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 index =3D pgd_index(vaddr);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D csr_read(CSR_SATP) &=
 SATP_PPN;

At this point in the boot process, we know that we use swapper_pg_dir so=20
no need to read SATP.

>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D (pgd_t *)pfn_to_=
virt(pfn) + index;

Here, this pgd_dir assignment is overwritten 2 lines below, so no need=20
for it.

>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_k =3D init_mm.pgd + inde=
x;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D pgd_offset_k(vad=
dr);

pgd_offset_k(vaddr) =3D init_mm.pgd + pgd_index(vaddr) so pgd_k =3D=3D pgd_=
dir.

>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd_dir, *pgd_k);
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_dir =3D p4d_offset(pgd_d=
ir, vaddr);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_k=C2=A0 =3D p4d_offset(p=
gd_k, vaddr);
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr =3D (vaddr + PUD_SIZE)=
 & PUD_MASK;

Why do you increase vaddr *before* populating the first one ? And=20
pud_addr_end does that properly: it returns the next pud address if it=20
does not go beyond end address to map.

>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_dir =3D pud_offset(p4d_d=
ir, vaddr);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_k =3D pud_offset(p4d_k, =
vaddr);
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pud_present(*pud_dir)) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p =
=3D early_alloc(PAGE_SIZE, NUMA_NO_NODE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_=
populate(&init_mm, pud_dir, p);

init_mm is not needed here.

>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr +=3D PAGE_SIZE;

Why do you need to add PAGE_SIZE ? vaddr already points to the next pud.

It seems like this patch tries to populate userspace page table whereas=20
at this point in the boot process, only swapper_pg_dir is used or am I=20
missing something ?

Thanks,

Alex

>> +=C2=A0=C2=A0=C2=A0 }
>> +}
>> +
>> =C2=A0void __init kasan_init(void)
>> =C2=A0{
>> =C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t _start, _end;
>> @@ -90,7 +137,15 @@ void __init kasan_init(void)
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow((void *)KASAN_SHADO=
W_START,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kasan_mem_to_shado=
w((void *)
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 VMALLOC_END));
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 VMEMMAP_END));
>> +=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_shallow_populate(
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (voi=
d *)kasan_mem_to_shadow((void *)VMALLOC_START),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (voi=
d *)kasan_mem_to_shadow((void *)VMALLOC_END));
>> +=C2=A0=C2=A0=C2=A0 else
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow(
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (voi=
d *)kasan_mem_to_shadow((void *)VMALLOC_START),
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (voi=
d *)kasan_mem_to_shadow((void *)VMALLOC_END));
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &_start, &_end) {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *start =3D (void *=
)_start; >
> Thanks, this is on for-next.
>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2b2f3038-3e27-8763-cf78-3fbbfd2100a0%40ghiti.fr.
