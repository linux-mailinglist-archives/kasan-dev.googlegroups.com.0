Return-Path: <kasan-dev+bncBC447XVYUEMRB6W6T2AQMGQEQ3IRUNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C24031AAED
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Feb 2021 11:52:48 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id q13sf1238172ljp.23
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Feb 2021 02:52:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613213563; cv=pass;
        d=google.com; s=arc-20160816;
        b=IsR4il+0K+LzAHNt/rKSiTOZn6wy8ipuxgnlVpPOkm1DnnchexsCsQVRNx9joto6rx
         d91jGWgUBfMP0cTeacWU4JwrE3lkdqrTH+67tB+lrC5RTnBWdNfHO5scKR0kJNPUG/wB
         TepEb/8MC6UmgL8CS/sszFOUzp+kREPrEDA7UYhxZaK+DFaSQpTY5worIpCG5pEeegxP
         MwLvdzuWspam1UIbtM55T5lX3TeX8nxj/2XCjGwv48eOjzfbsDEQPVkA60YDmpHv5h8v
         vp+hj4kkdp1XvGD6ga6D23bhOfTJdiUzMBU1RPwoynWf/QyKi+CZmSavYUhaCQiEPJig
         Vtdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=jttLadorskJIvB/7aELWT5UP9yU0FKzEeLa634iuyK0=;
        b=DjL1BrMo0C/Zs8gY8OQ96ne7ME7DOzlBuGc3TgiF28QiMpYq89b1cxArhyRUCLWcwr
         KUBaWhgcIROweYPjLa7xCGeIYHh6m9Ge2TknQYQ+pkPGQ9gKTy+UOJzXQcwKOyQIPGli
         uFMXVqTapV1jCMKF5aAMYoHsxronz6x3mXuEPDu6V0Fof9YL3S0oEK1BVLsJMuXuRs/w
         Z5amOKI10/Ve0Ra05yN3WLSCK5289gXshewfBIJu5uaLb67slECAjKF01xThmLZglUxV
         OSk/WTNrb9cyMf7jlMDWmrkYYYu9LZM68Gqfe6cgZFG91fGcC28Gt/gSTnguV/I7/VPA
         KvXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jttLadorskJIvB/7aELWT5UP9yU0FKzEeLa634iuyK0=;
        b=FgEJDYlhzu7F6EekSsYKFEvHjYGYNOEFA1UtadBZRIHjQmQUEEWRIeTOIQRIyzbRKo
         gnLGucJcYgJc9HkOGLBVNgS8IwoypywRz85gFzhdOcjjO25Wx7b10O2yYNzXQXqeSHXz
         MGRQsmD3Yd7C7qGi9I5bK9gx6cmn2Hp2cQC/sRdOPoNo50MBse/cCmaxUL5xiWBUCs6Q
         19Didu7uj9GbSY/e5uLwEXLAjfIY77fJ4DpWlvFhpYWyDYr9eK2gvwXzydxnwswlAPb7
         KfK8kUrno+aNE2QQcpozUvpnbvsuzJCmiOnTIaHXbsLu04G8Pov5LnB4vtYQryscR7bK
         rYVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jttLadorskJIvB/7aELWT5UP9yU0FKzEeLa634iuyK0=;
        b=GXevrdTCZ02LGjVVzdTd/uDNjDYFKBcE0je5SuwCJ/cH/cPnWaNKt7MIMNYSMxliyd
         WnVhd3iWxk+77rcBPUEfh2CjWmA6APb9p6rpAj/I4REX9eON+lGNbsz00mXoI/tmSSi7
         Otv1s+DfSKkrsRUHFGFLSgzRTjKUfQoT36Gsnd5oKwfdFqAwt3bcSTXPLzGPFKiFnviG
         3QSmUja9n42Dh7rlS3QmyzC03n4VnrI4xOw+valhOHqhYfI0gxh0ivDZmooS0VAO2UAM
         9XNljZNGbJBbxA6Ep5nDhV/pfp46Iunzy1cIWpjFYb8sHt9sm6GznFL5ZuGwr07Fvbml
         lY5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532jsDYpxBmWE9mO5DMfPtFyKiZIKcNgIpMyhUs2dWUObsPx6IQX
	3MfX5xRf94AKjPFjrKarxQs=
X-Google-Smtp-Source: ABdhPJz7aV238aXoCK5lYg3c6hlVkDi3FK6py8Rnjvha1s0NcKtJ4SQVb16vunDkZBzFD54meUQ0Gw==
X-Received: by 2002:a19:4918:: with SMTP id w24mr3813785lfa.369.1613213563030;
        Sat, 13 Feb 2021 02:52:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:32b:: with SMTP id b11ls2199713ljp.11.gmail; Sat,
 13 Feb 2021 02:52:42 -0800 (PST)
X-Received: by 2002:a2e:8594:: with SMTP id b20mr4082930lji.120.1613213562082;
        Sat, 13 Feb 2021 02:52:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613213562; cv=none;
        d=google.com; s=arc-20160816;
        b=f+O5+7yYc4Ef4Ta9+u97mdiMyr64Vreyv6LHba6LxfEpQI8gBoEbBOnRfq+X5CbBMz
         270c2ZH626oq729VtKX0fkcqxzL9A69Euus1xmYNCiesh7heKWmnaMz2l9iGi4MEskrO
         3tkj5X/hb2UjLdkthfgbSsYbPZtuNz+YZWnamsEra3GnWhltmzz2wgd7U1x0g8X5qXSj
         Q04J/3qbpyGVbuG8UQ3uJ3JJUZ2CFs2iaybKJgW0ybYdaQ4HBghurZ60a5jeYpxTQOyk
         0J6PtRfnO5e2T/ELoeBUk23ww/yyCBXFs0gdeiPfAI45gQTA9nCjh6qxFTJ1yKHM05Ql
         QMwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=dZlwKnsGnZ2/ft8gA8mBM3DOoZCEZtQUzGQVt9rkbNg=;
        b=OrPlA/rSZpcyXiBNc8avBgS1KJsHbSOr/8Sd26HhSQ9Mt5QO+Fru2ig+tWjMCTusaj
         awdBM0moP7cwS4/Gw9aIG9FmPRBD67SrMpUBrZsT5ia5pA5XUPQ09P4IivmVYZmdod34
         yBk03Etzd0tLedUlABXacW/a6Fl5KVXbr1ut2j1OXgL7ODoACGL2bpFzmTz59or+0aVF
         ySttWvw0i4xwnYANZ08hub2gUY6lMpCcIN+GROI3uX5/Xmb/Z58iQu+TOjEi8/Wpj0k8
         5xCFiBbJpGHSLXZ/PcNp63rbiVlNId/PsBzAaScOyD0/GoZZ9x97ukkvIpCfTvLkW6YF
         xLvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id z15si231200lfr.7.2021.02.13.02.52.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 13 Feb 2021 02:52:41 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
X-Originating-IP: 2.7.49.219
Received: from [192.168.1.12] (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id CC2B9240007;
	Sat, 13 Feb 2021 10:52:36 +0000 (UTC)
Subject: Re: [PATCH v2 1/1] riscv/kasan: add KASAN_VMALLOC support
From: Alex Ghiti <alex@ghiti.fr>
To: Palmer Dabbelt <palmer@dabbelt.com>, nylon7@andestech.com
Cc: aou@eecs.berkeley.edu, nickhu@andestech.com, alankao@andestech.com,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 nylon7717@gmail.com, glider@google.com,
 Paul Walmsley <paul.walmsley@sifive.com>, aryabinin@virtuozzo.com,
 linux-riscv@lists.infradead.org, dvyukov@google.com
References: <mhng-443fd141-b9a3-4be6-a056-416877f99ea4@palmerdabbelt-glaptop>
 <2b2f3038-3e27-8763-cf78-3fbbfd2100a0@ghiti.fr>
Message-ID: <4fa97788-157c-4059-ae3f-28ab074c5836@ghiti.fr>
Date: Sat, 13 Feb 2021 05:52:36 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <2b2f3038-3e27-8763-cf78-3fbbfd2100a0@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
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

Hi Nylon, Palmer,

Le 2/8/21 =C3=A0 1:28 AM, Alex Ghiti a =C3=A9crit=C2=A0:
> Hi Nylon,
>=20
> Le 1/22/21 =C3=A0 10:56 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
>> On Fri, 15 Jan 2021 21:58:35 PST (-0800), nylon7@andestech.com wrote:
>>> It references to x86/s390 architecture.
>>> >> So, it doesn't map the early shadow page to cover VMALLOC space.
>>>
>>> Prepopulate top level page table for the range that would otherwise be
>>> empty.
>>>
>>> lower levels are filled dynamically upon memory allocation while
>>> booting.
>=20
> I think we can improve the changelog a bit here with something like that:
>=20
> "KASAN vmalloc space used to be mapped using kasan early shadow page.=20
> KASAN_VMALLOC requires the top-level of the kernel page table to be=20
> properly populated, lower levels being filled dynamically upon memory=20
> allocation at runtime."
>=20
>>>
>>> Signed-off-by: Nylon Chen <nylon7@andestech.com>
>>> Signed-off-by: Nick Hu <nickhu@andestech.com>
>>> ---
>>> =C2=A0arch/riscv/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 |=C2=A0 1 +
>>> =C2=A0arch/riscv/mm/kasan_init.c | 57 +++++++++++++++++++++++++++++++++=
++++-
>>> =C2=A02 files changed, 57 insertions(+), 1 deletion(-)
>>>
>>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>>> index 81b76d44725d..15a2c8088bbe 100644
>>> --- a/arch/riscv/Kconfig
>>> +++ b/arch/riscv/Kconfig
>>> @@ -57,6 +57,7 @@ config RISCV
>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL
>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN if MMU && 64BIT
>>> +=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB
>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_KGDB_QXFER_PKT
>>> =C2=A0=C2=A0=C2=A0=C2=A0 select HAVE_ARCH_MMAP_RND_BITS if MMU
>>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>>> index 12ddd1f6bf70..4b9149f963d3 100644
>>> --- a/arch/riscv/mm/kasan_init.c
>>> +++ b/arch/riscv/mm/kasan_init.c
>>> @@ -9,6 +9,19 @@
>>> =C2=A0#include <linux/pgtable.h>
>>> =C2=A0#include <asm/tlbflush.h>
>>> =C2=A0#include <asm/fixmap.h>
>>> +#include <asm/pgalloc.h>
>>> +
>>> +static __init void *early_alloc(size_t size, int node)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 void *ptr =3D memblock_alloc_try_nid(size, size,
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __pa(MAX_DMA_ADDRESS), MEMB=
LOCK_ALLOC_ACCESSIBLE, node);
>>> +
>>> +=C2=A0=C2=A0=C2=A0 if (!ptr)
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 panic("%pS: Failed to alloc=
ate %zu bytes align=3D%zx nid=3D%d=20
>>> from=3D%llx\n",
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __f=
unc__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
>>> +
>>> +=C2=A0=C2=A0=C2=A0 return ptr;
>>> +}
>>>
>>> =C2=A0extern pgd_t early_pg_dir[PTRS_PER_PGD];
>>> =C2=A0asmlinkage void __init kasan_early_init(void)
>>> @@ -83,6 +96,40 @@ static void __init populate(void *start, void *end)
>>> =C2=A0=C2=A0=C2=A0=C2=A0 memset(start, 0, end - start);
>>> =C2=A0}
>>>
>>> +void __init kasan_shallow_populate(void *start, void *end)
>>> +{
>>> +=C2=A0=C2=A0=C2=A0 unsigned long vaddr =3D (unsigned long)start & PAGE=
_MASK;
>>> +=C2=A0=C2=A0=C2=A0 unsigned long vend =3D PAGE_ALIGN((unsigned long)en=
d);
>>> +=C2=A0=C2=A0=C2=A0 unsigned long pfn;
>>> +=C2=A0=C2=A0=C2=A0 int index;
>>> +=C2=A0=C2=A0=C2=A0 void *p;
>>> +=C2=A0=C2=A0=C2=A0 pud_t *pud_dir, *pud_k;
>>> +=C2=A0=C2=A0=C2=A0 pgd_t *pgd_dir, *pgd_k;
>>> +=C2=A0=C2=A0=C2=A0 p4d_t *p4d_dir, *p4d_k;
>>> +
>>> +=C2=A0=C2=A0=C2=A0 while (vaddr < vend) {
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 index =3D pgd_index(vaddr);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D csr_read(CSR_SATP) =
& SATP_PPN;
>=20
> At this point in the boot process, we know that we use swapper_pg_dir so=
=20
> no need to read SATP.
>=20
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D (pgd_t *)pfn_to=
_virt(pfn) + index;
>=20
> Here, this pgd_dir assignment is overwritten 2 lines below, so no need=20
> for it.
>=20
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_k =3D init_mm.pgd + ind=
ex;
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pgd_dir =3D pgd_offset_k(va=
ddr);
>=20
> pgd_offset_k(vaddr) =3D init_mm.pgd + pgd_index(vaddr) so pgd_k =3D=3D pg=
d_dir.
>=20
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pgd(pgd_dir, *pgd_k);
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_dir =3D p4d_offset(pgd_=
dir, vaddr);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p4d_k=C2=A0 =3D p4d_offset(=
pgd_k, vaddr);
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr =3D (vaddr + PUD_SIZE=
) & PUD_MASK;
>=20
> Why do you increase vaddr *before* populating the first one ? And=20
> pud_addr_end does that properly: it returns the next pud address if it=20
> does not go beyond end address to map.
>=20
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_dir =3D pud_offset(p4d_=
dir, vaddr);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud_k =3D pud_offset(p4d_k,=
 vaddr);
>>> +
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (pud_present(*pud_dir)) =
{
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 p =
=3D early_alloc(PAGE_SIZE, NUMA_NO_NODE);
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pud=
_populate(&init_mm, pud_dir, p);
>=20
> init_mm is not needed here.
>=20
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 vaddr +=3D PAGE_SIZE;
>=20
> Why do you need to add PAGE_SIZE ? vaddr already points to the next pud.
>=20
> It seems like this patch tries to populate userspace page table whereas=
=20
> at this point in the boot process, only swapper_pg_dir is used or am I=20
> missing something ?
>=20
> Thanks,
>=20
> Alex

I implemented this morning a version that fixes all the comments I made=20
earlier. I was able to insert test_kasan_module on both sv39 and sv48=20
without any modification: set_pgd "goes through" all the unused page=20
table levels, whereas p*d_populate are noop for unused levels.

If you have any comment, do not hesitate.

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c=20

index adbf94b7e68a..d643b222167c 100644=20

--- a/arch/riscv/mm/kasan_init.c=20

+++ b/arch/riscv/mm/kasan_init.c=20

@@ -195,6 +195,31 @@ static void __init kasan_populate(void *start, void=20
*end)
         memset(start, KASAN_SHADOW_INIT, end - start);=20

  }=20

=20

+void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned=20
long end)
+{=20

+       unsigned long next;=20

+       void *p;=20

+       pgd_t *pgd_k =3D pgd_offset_k(vaddr);=20

+=20

+       do {=20

+               next =3D pgd_addr_end(vaddr, end);=20

+               if (pgd_page_vaddr(*pgd_k) =3D=3D (unsigned=20
long)lm_alias(kasan_early_shadow_pgd_next)) {
+                       p =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);=20

+                       set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)),=20
PAGE_TABLE));
+               }=20

+       } while (pgd_k++, vaddr =3D next, vaddr !=3D end);=20

+}=20

+=20

+void __init kasan_shallow_populate(void *start, void *end)=20

+{=20

+       unsigned long vaddr =3D (unsigned long)start & PAGE_MASK;=20

+       unsigned long vend =3D PAGE_ALIGN((unsigned long)end);=20

+=20

+       kasan_shallow_populate_pgd(vaddr, vend);=20

+=20

+       local_flush_tlb_all();=20

+}=20

+=20

  void __init kasan_init(void)=20

  {=20

         phys_addr_t _start, _end;=20

@@ -206,7 +231,15 @@ void __init kasan_init(void)=20

          */=20

         kasan_populate_early_shadow((void *)KASAN_SHADOW_START,=20

                                     (void *)kasan_mem_to_shadow((void=20
*)
-=20
VMALLOC_END));
+=20
VMEMMAP_END));
+       if (IS_ENABLED(CONFIG_KASAN_VMALLOC))=20

+               kasan_shallow_populate(=20

+                       (void *)kasan_mem_to_shadow((void=20
*)VMALLOC_START),
+                       (void *)kasan_mem_to_shadow((void=20
*)VMALLOC_END));
+       else=20

+               kasan_populate_early_shadow(=20

+                       (void *)kasan_mem_to_shadow((void=20
*)VMALLOC_START),
+                       (void *)kasan_mem_to_shadow((void=20
*)VMALLOC_END));
=20

         /* Populate the linear mapping */=20

         for_each_mem_range(i, &_start, &_end) {=20

--=20

2.20.1

Thanks,

Alex

>=20
>>> +=C2=A0=C2=A0=C2=A0 }
>>> +}
>>> +
>>> =C2=A0void __init kasan_init(void)
>>> =C2=A0{
>>> =C2=A0=C2=A0=C2=A0=C2=A0 phys_addr_t _start, _end;
>>> @@ -90,7 +137,15 @@ void __init kasan_init(void)
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow((void *)KASAN_SHAD=
OW_START,
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (void *)kasan_mem_to_sh=
adow((void *)
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 VMALLOC_END));
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 VMEMMAP_END));
>>> +=C2=A0=C2=A0=C2=A0 if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_shallow_populate(
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (vo=
id *)kasan_mem_to_shadow((void *)VMALLOC_START),
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (vo=
id *)kasan_mem_to_shadow((void *)VMALLOC_END));
>>> +=C2=A0=C2=A0=C2=A0 else
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate_early_shadow=
(
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (vo=
id *)kasan_mem_to_shadow((void *)VMALLOC_START),
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (vo=
id *)kasan_mem_to_shadow((void *)VMALLOC_END));
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0 for_each_mem_range(i, &_start, &_end) {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 void *start =3D (void =
*)_start; >
>> Thanks, this is on for-next.
>>
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv
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
kasan-dev/4fa97788-157c-4059-ae3f-28ab074c5836%40ghiti.fr.
