Return-Path: <kasan-dev+bncBAABBQ74ZKFAMGQEDI2TQJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7092541A93E
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Sep 2021 09:03:32 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id m3-20020aca1e03000000b00268ff33ea91sf18698986oic.5
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Sep 2021 00:03:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632812611; cv=pass;
        d=google.com; s=arc-20160816;
        b=aLrH2YxxTJx3Kjpjv+QGH7MePYMCWKeBO9tjyGUB8kk+4bhEzt9iQM0lnjDozu2/wr
         MMSqyI1wHv7+EPKD1fBvSlL9AzlEFfipqLiPKkhRRCOsFMg+FoSV5o6e3PzwRCsN2Wje
         3kis965RLMeTow/z/Rkacq2nYasApdR3AlReW8Q/51sWt6Ol2MwU/y+YoFJtYCYuuiaz
         hkmXLDTzSZqucRcbVr4Ek43XpYj6v/ZRFf4Unkf9f7DPFF6NgzoUv/toEGAn+lGeForr
         fiNBvEw9NALKS3hh2bnmFts2twUuNd1f4QIpMljl/dzP02BvJxVeUgDpCmQ7hcuN6Bgu
         +Q9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=OOELrgiRXn1EEL7N4i8aoInTwu70F86xzbUPcn7Zcqo=;
        b=cd0zblR2d3wFX/QWSEDsqmQDK2Supn7tMHtr0ohCn+Uk5KWtQrQbD6I0xcJLxX/yoO
         p1DNuCoTaCSGsFh0MsZ9jUI0h5vYSCCnOCgKYLxvIGGEBvFptDK4qZjj4srzKvEi9Buc
         4sBlfaFV9pjgASgP3pW3NFzNGPN8lAPoYOOFzLDVHW9mU6qIcmZI94R6ctaVBPcBKC6f
         UQns+SA3J7yzqWvO7n2Bpt1Uhq/rwXwynPsZPtRRNmIUNJBF6Mis34+xDpBIBWB96LSs
         fsbLoWsBBmWa4bzYKr1PcwZWyd2/n/cLoDl8kCmDWnzOVqtriAuPe+/ygVuGFuSQ695j
         gwQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:references:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OOELrgiRXn1EEL7N4i8aoInTwu70F86xzbUPcn7Zcqo=;
        b=DiNNjujuGzjyQaHOPyzJ5KZqimGZOgojxOAFmGYBf5HrjPsLFYqPniBQkVAAC/soz2
         v+sagXZBZmj1wYO02+1D3XP8AwLX1zkrnP8QUqtxPtqhBPfjvDE6iNzJLgyz2PqOIYlf
         C6HojyL4PuMl4yVs1j/myJXGXf0vz5ZIiAK6mKCeNw064BnpgT6BXWWArS/fO5yDk/L4
         iwFYqTvUgaV3DfGwHVjLS/NrI/BYkSykF87BS4JWGGldJlnOp58io0Oc1T7nSJdnvohy
         yJUkiR+4J9N2PftzZykzLEXVmL7vtUP3qCSRW1z2sQQ+JkwdCMCiwYILtHEEMGsg5ZxH
         YRPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:references:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OOELrgiRXn1EEL7N4i8aoInTwu70F86xzbUPcn7Zcqo=;
        b=MJkXzdsnO6rLVqvdv56EzXp7o883UJuVUQ6IXkYyILY7Z7ovHhYzfx7KobRsmGazcq
         mGlQkBCtEYKAGttsaHhnDckdSZXqirM6w8dQIMR3n9GL/IDZ/bCn7aRjvlHKwqu9qRAN
         4+dud/TL72qc87TT0U8z9E7GVa1wst2LczA38z7gfGVfWMfPuBcxXpRBOXMPlnzuibiF
         CN1EERgAphyb9mvnCDVZZpxVQv6V5WNa6RLQEhT7Tgxu4M5DsTAX6PWW2TbgL6wnb/x1
         BWRQHsfD+OGT8edIjHt92rYgyKI10OmzQSt94DkIWIOcDVCpDQbhl/9JQUJ3w4vkF/Wq
         GeTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Z8scZB7ud0YEhIYeMvk+2JYvDy3BroNjMohdaC+hngBTC3E04
	Exkc+nzmYfVW31auipRwcyI=
X-Google-Smtp-Source: ABdhPJwslh0LSuR936cw+akA3oAqQmI2w6Biz91L8SMjvdSU5lQHRasc9YxxLvfoI4Q+jikn0jhaGA==
X-Received: by 2002:a05:6830:9c9:: with SMTP id y9mr3742750ott.6.1632812611213;
        Tue, 28 Sep 2021 00:03:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4bd8:: with SMTP id y207ls4633787oia.1.gmail; Tue, 28
 Sep 2021 00:03:30 -0700 (PDT)
X-Received: by 2002:a05:6808:14d6:: with SMTP id f22mr2525574oiw.132.1632812610819;
        Tue, 28 Sep 2021 00:03:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632812610; cv=none;
        d=google.com; s=arc-20160816;
        b=zsdYbmqASPPBzGsy5039e1mP+B3mbsa+Iy+FvgHNcK6Agm/eVXySeZv8mb3MjmaNo0
         WH8FpMRuK/L3gLVYlj0/JoZ1mbGbTvvebFShjzFhJlLrk9Qq6sBXRi+YwK1kwa8jaaXn
         XW/4ltQYXUHNP9FKPD0lsHFoXNwl4Gs4/yv0DizwzYJHm9rpgcjxwqp7fyw2n+Xxjguj
         vMdwDguPdlZcnanBNhJMiopwgWTkd4PsGmWjcn+8Jwce4v4u3D+SP9h/iuMGhKY4/ZSa
         fJckfraHo77jmbxcyknxqVBSnq/DrXXU/NWD8Ud7nCzlOLJhNwFJPctk7P4dr4tcOmqr
         DT3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject;
        bh=hHSWNcp/SHYwmOEtkHIQRbNmL7chsDyvLvvl45Waq/A=;
        b=CaNzkUOIpHqt+Ao/WEYkKossXyd7SBT7jAub8RHzigejJq5eT3X/Rb+QdQ2YedkH3t
         4ZBGYaboEQ1AjZAlnv3Zic6fnNIkYhuwT3I2iPT1AzEE4bimhxpsTtRaCEOCP3os2g+H
         ECPfMBrOwZdeUlSmnMWdBQkFq58dj9cPAH4RfKwfgWSYUd5HqJo5OTjDpA7izzsNXVXc
         u9D//sU4jidfhvVtswkIzZFT+ivpn5V3ZruK21rzij3KH/ErAIw0Qu/S7uI/n28m75Ze
         jIEhfrYYpWINsGLR2G/p+60PL07xZtmSbOr42lY1P9QTASZPyPVLwupv/RtkuqZ0FOhc
         iIsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id bi42si668305oib.4.2021.09.28.00.03.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Sep 2021 00:03:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.53])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4HJVjX06xqzbmtP;
	Tue, 28 Sep 2021 14:59:12 +0800 (CST)
Received: from dggpemm500009.china.huawei.com (7.185.36.225) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Tue, 28 Sep 2021 15:03:22 +0800
Received: from [10.174.179.24] (10.174.179.24) by
 dggpemm500009.china.huawei.com (7.185.36.225) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Tue, 28 Sep 2021 15:03:21 +0800
Subject: Re: [PATCH] arm64: remove page granularity limitation from KFENCE
To: Alexander Potapenko <glider@google.com>
References: <20210918083849.2696287-1-liushixin2@huawei.com>
 <CAG_fn=X=k3w-jr3iCevB_t7Hh0r=qZ=nOxwk5ujsO+LZ7hA4Aw@mail.gmail.com>
CC: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>,
	<Jisheng.Zhang@synaptics.com>, Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Mark Rutland <mark.rutland@arm.com>
From: Liu Shixin <liushixin2@huawei.com>
Message-ID: <0676448f-08f9-f498-5fb3-b88fd3810c58@huawei.com>
Date: Tue, 28 Sep 2021 15:03:21 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101
 Thunderbird/45.7.1
MIME-Version: 1.0
In-Reply-To: <CAG_fn=X=k3w-jr3iCevB_t7Hh0r=qZ=nOxwk5ujsO+LZ7hA4Aw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.174.179.24]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 dggpemm500009.china.huawei.com (7.185.36.225)
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=liushixin2@huawei.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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



On 2021/9/18 19:50, Alexander Potapenko wrote:
> On Sat, Sep 18, 2021 at 10:10 AM Liu Shixin <liushixin2@huawei.com> wrote:
>> Currently if KFENCE is enabled in arm64, the entire linear map will be
>> mapped at page granularity which seems overkilled. Actually only the
>> kfence pool requires to be mapped at page granularity. We can remove the
>> restriction from KFENCE and force the linear mapping of the kfence pool
>> at page granularity later in arch_kfence_init_pool().
> There was a previous patch by Jisheng Zhang intended to remove this
> requirement: https://lore.kernel.org/linux-arm-kernel/20210524180656.395e45f6@xhacker.debian/
> Which of the two is more preferable?
The previous patch by Jisheng Zhang guarantees kfence pool to be mapped at
page granularity by allocating kfence pool before paging_init(), and then map it
at page granularity during map_mem().

The previous patch has a problem: Even if kfence is disabled in cmdline, kfence pool
is still allocated, which is a waste of memory.

I'm sorry for sending it repeatly, and I have no idea how to limit the email format
to TEXT/PLAIN.

thanks.

>> Signed-off-by: Liu Shixin <liushixin2@huawei.com>
>> ---
>>  arch/arm64/include/asm/kfence.h | 69 ++++++++++++++++++++++++++++++++-
>>  arch/arm64/mm/mmu.c             |  4 +-
>>  2 files changed, 70 insertions(+), 3 deletions(-)
>>
>> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
>> index aa855c6a0ae6..bee101eced0b 100644
>> --- a/arch/arm64/include/asm/kfence.h
>> +++ b/arch/arm64/include/asm/kfence.h
>> @@ -8,9 +8,76 @@
>>  #ifndef __ASM_KFENCE_H
>>  #define __ASM_KFENCE_H
>>
>> +#include <linux/kfence.h>
>>  #include <asm/set_memory.h>
>> +#include <asm/pgalloc.h>
>>
>> -static inline bool arch_kfence_init_pool(void) { return true; }
>> +static inline int split_pud_page(pud_t *pud, unsigned long addr)
>> +{
>> +       int i;
>> +       pmd_t *pmd = pmd_alloc_one(&init_mm, addr);
>> +       unsigned long pfn = PFN_DOWN(__pa(addr));
>> +
>> +       if (!pmd)
>> +               return -ENOMEM;
>> +
>> +       for (i = 0; i < PTRS_PER_PMD; i++)
>> +               set_pmd(pmd + i, pmd_mkhuge(pfn_pmd(pfn + i * PTRS_PER_PTE, PAGE_KERNEL)));
>> +
>> +       smp_wmb(); /* See comment in __pte_alloc */
>> +       pud_populate(&init_mm, pud, pmd);
>> +       flush_tlb_kernel_range(addr, addr + PUD_SIZE);
>> +       return 0;
>> +}
>> +
>> +static inline int split_pmd_page(pmd_t *pmd, unsigned long addr)
>> +{
>> +       int i;
>> +       pte_t *pte = pte_alloc_one_kernel(&init_mm);
>> +       unsigned long pfn = PFN_DOWN(__pa(addr));
>> +
>> +       if (!pte)
>> +               return -ENOMEM;
>> +
>> +       for (i = 0; i < PTRS_PER_PTE; i++)
>> +               set_pte(pte + i, pfn_pte(pfn + i, PAGE_KERNEL));
>> +
>> +       smp_wmb(); /* See comment in __pte_alloc */
>> +       pmd_populate_kernel(&init_mm, pmd, pte);
>> +
>> +       flush_tlb_kernel_range(addr, addr + PMD_SIZE);
>> +       return 0;
>> +}
>> +
>> +static inline bool arch_kfence_init_pool(void)
>> +{
>> +       unsigned long addr;
>> +       pgd_t *pgd;
>> +       p4d_t *p4d;
>> +       pud_t *pud;
>> +       pmd_t *pmd;
>> +
>> +       for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
>> +            addr += PAGE_SIZE) {
>> +               pgd = pgd_offset(&init_mm, addr);
>> +               if (pgd_leaf(*pgd))
>> +                       return false;
>> +               p4d = p4d_offset(pgd, addr);
>> +               if (p4d_leaf(*p4d))
>> +                       return false;
>> +               pud = pud_offset(p4d, addr);
>> +               if (pud_leaf(*pud)) {
>> +                       if (split_pud_page(pud, addr & PUD_MASK))
>> +                               return false;
>> +               }
>> +               pmd = pmd_offset(pud, addr);
>> +               if (pmd_leaf(*pmd)) {
>> +                       if (split_pmd_page(pmd, addr & PMD_MASK))
>> +                               return false;
>> +               }
>> +       }
>> +       return true;
>> +}
>>
>>  static inline bool kfence_protect_page(unsigned long addr, bool protect)
>>  {
>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>> index cfd9deb347c3..b2c79ccfb1c5 100644
>> --- a/arch/arm64/mm/mmu.c
>> +++ b/arch/arm64/mm/mmu.c
>> @@ -516,7 +516,7 @@ static void __init map_mem(pgd_t *pgdp)
>>          */
>>         BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
>>
>> -       if (can_set_direct_map() || crash_mem_map || IS_ENABLED(CONFIG_KFENCE))
>> +       if (can_set_direct_map() || crash_mem_map)
>>                 flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>>
>>         /*
>> @@ -1485,7 +1485,7 @@ int arch_add_memory(int nid, u64 start, u64 size,
>>          * KFENCE requires linear map to be mapped at page granularity, so that
>>          * it is possible to protect/unprotect single pages in the KFENCE pool.
>>          */
>> -       if (can_set_direct_map() || IS_ENABLED(CONFIG_KFENCE))
>> +       if (can_set_direct_map())
>>                 flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>>
>>         __create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start),
>> --
>> 2.18.0.huawei.25
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210918083849.2696287-1-liushixin2%40huawei.com.
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0676448f-08f9-f498-5fb3-b88fd3810c58%40huawei.com.
