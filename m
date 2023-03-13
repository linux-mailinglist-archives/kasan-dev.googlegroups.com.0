Return-Path: <kasan-dev+bncBCRKFI7J2AJRB47MXSQAMGQENRRVFDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C8766B7AAC
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 15:43:02 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-172ace24d4dsf7337013fac.18
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 07:43:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678718581; cv=pass;
        d=google.com; s=arc-20160816;
        b=HVhlA90NfnXtHpmCXAGBx/9FdnfYyrv8IiHy5B9BT4skqUNwbgL9pg6F5AONcPectY
         sx7YROuplpzMZXRWGAwhpUBgT6OBc0maJVsSmWrk5JN93fWBsV/nkSgiTSAaQlwcZA56
         FfTtS4Oi03s05GT0WovgwhhZorNYvSbT/yXZu/0dz5EAHnbBRZf9Y9Da5V0gKUapnrXE
         Y4aAajuDmhukAGxo+4SY8eJcs/0QyuG3MSoZkZtVLDjsINVqktDIvBpxJceoK6kxUevA
         +DQym7egJ5V+bApVuldGzz9YqiZ4tJv/hfToSuCf4AL0geTjWNGB6GqyvsYQtkShaC9q
         QaQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=uKmNMeD++mcTwkx2XSQZ+rgpzu3z2x3LhaCsbM6oTaY=;
        b=E9bZXathaXg6T8N5JCbtEbshChxgwxCJYcOW/BOSa3SyLJ5j44mNMWfYup79tEA2Lo
         s2+M0CU62acGsqM6uOBKg5sv+jqWwHYO3mAlF5U8NjrVaKf9+z8+F+09/+ab/Mg1IMzr
         0gxJRsWPNtcaoTL8LxH3bfvwXGcQhOLUJxKpl+T9670xL8Bh282A7T4lZUtjo1Owdu33
         +rEpdst9V4/Zhtvc22NirFPPXOBqid519fb906q6u64PwNydxXkVKnWR5+DYkklzQqax
         f4KTkKjU3Bma+cEs1YmkITFznLPEeG4vyTzeuT1+fhOzETlCNLWNc81KNKay5i/7YS4n
         o3Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678718581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uKmNMeD++mcTwkx2XSQZ+rgpzu3z2x3LhaCsbM6oTaY=;
        b=Fr/5a70uzXXIJQUfqyJuHg8x4aI3osTejhpJbwVDPLsrmyYsbjypBMhLubunfewi9Q
         JyyQqA79iNn/irP0QoWMRQUYqRrFGF3dSTbFmq+2Hqp0zvLkk/iQ6eKRkeSWe5Jj2Nm3
         XNHRGGFEa12WvoVbr3SRxGauc4ugdpuhnKOXsOGsG/1/rgaWQXslDyb1N9wXOAvqRio7
         m9P6HuL7FFwRNQ64/zRllIWgJj2+XZpsOECCQ5UHHWzk8FGufkV4GA2lLGi08ogU0h6i
         oyTrh6TnHU9LLTviqJ6iV1mYcOlGmn7aJfD3H7oHtMBIJGCrIsXuWKKgHszuyd1tWi1S
         1/fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678718581;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=uKmNMeD++mcTwkx2XSQZ+rgpzu3z2x3LhaCsbM6oTaY=;
        b=ThWJNnI+C3NgWsr6oBcVts/QALdfvj2M6m2hNXCioxnt8x/6s5ao/ZIe9nekLUXoz5
         JAi+UR+jiaCpBQCk9LjYx29d4lG7LCoL04Y/tkuY0TkQg/rb7ho7ct1LdUogGEsqFKrq
         yH2Ci3rFYPN6Y0Y56Yf3yNPxbck/U2WI3AbyHf8bXWIa79q3YO4hVW/YFivrszZRkAGC
         j7sAWzfHpSG/PluN+XkqBzMewjYshxBAGJscR9K2rDq515LRdcpBZKmhNVUigtsg/TnN
         wtgISCT+mjM5TC1KoYd4Ye962r/hNuTsi0MwyGpvBp9TTDQURHIqbt+nbtNLb76cOUe3
         n97Q==
X-Gm-Message-State: AO0yUKWgdagfuzpn0LuVkXK+MtujLAGpJOWhqPNh2ZhDS4kikz+Z3uFq
	jhojKoJqPXHDne4jdjTnDi8=
X-Google-Smtp-Source: AK7set/3qWRYVFD2yOJyEKHL5jF3SgCT8YJbJ0rwrx+2YKCSkzWiAZEimIzCf6hGFD/kVzcrvDclRQ==
X-Received: by 2002:a05:6870:4395:b0:177:bf3e:5d4f with SMTP id r21-20020a056870439500b00177bf3e5d4fmr1145913oah.8.1678718579554;
        Mon, 13 Mar 2023 07:42:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1404:b0:378:5e56:83f3 with SMTP id
 w4-20020a056808140400b003785e5683f3ls4229607oiv.4.-pod-prod-gmail; Mon, 13
 Mar 2023 07:42:59 -0700 (PDT)
X-Received: by 2002:aca:2803:0:b0:384:264:9ca1 with SMTP id 3-20020aca2803000000b0038402649ca1mr15196508oix.37.1678718579067;
        Mon, 13 Mar 2023 07:42:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678718579; cv=none;
        d=google.com; s=arc-20160816;
        b=EP7U1IXIeLKD+w+vJ0OYOkgdEqqfgcUkZ3f1sbQvZKJDa42OgZPWw5L3vyt44b+ZdC
         U8Q0iuz/PoT1/k9ue0g3qMfqwWzQDg9t6UZM0B/90a2oK7tzlWd4c9W7m6gVqSsxGP8x
         CBq7Adz29I6jV+ntOb/TtoihpS0i5u7jTSqQHOAIs/rSY9yZkSa0R/D2mww5f7iTzguV
         1cqKFlq94Szqzz4oLvgrbLyzlM91doTatBzU4V2Jhx4OPmHmpgbBSbSyd0tYNksPHuUA
         4RvoGWPWgsJHhWFORj2qi4ckWCStStJTQX5Zia4Ztz3QGl9t16PA2lt+bP84hF3iUIzC
         EaNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=Jq1BUbWKG13gdJQBFg8xdyThIvd23+F5BgCkeMF5Zk8=;
        b=bWcc/RF6sc+h9ACCwIDg3v9e3ep6d+fAIF+YIhalQNY45PsU1kU5D//PeoANP5JQ3t
         /oxeGweuxOvtkldPSlOh/qxbECx8gJyr6pfl3BhG76hMP584XJGBueTyO8YcOXBUTJ67
         BdU+MFfAAwlh9Q4aI1j/FMFUNhuLob/SL063uZjEFSJ3S/Wbk4oeXMZm1LvNakE1eZzg
         mLjwZmzqdwTO0IKgrjytiok2PpBnZr/lYpCxnzpNy/11DRubYxnDUaYECKlLnvEC6JUd
         tJUyjrs6fgMAcCGx6ThhmNcTFiGIikH78BDIaCLZrC7lf8/ol9n0KbzelEx0+6W1x26O
         TTTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id z2-20020aca3302000000b00384e4da7e50si407944oiz.0.2023.03.13.07.42.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Mar 2023 07:42:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpemm500001.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4PZzrX16pGzrSqQ;
	Mon, 13 Mar 2023 22:42:04 +0800 (CST)
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.21; Mon, 13 Mar 2023 22:42:55 +0800
Message-ID: <41a98759-1626-5e8f-3b1b-d038ef1925a7@huawei.com>
Date: Mon, 13 Mar 2023 22:42:54 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: [PATCH v6] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: Marco Elver <elver@google.com>, Zhenhua Huang <quic_zhenhuah@quicinc.com>
CC: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>, <robin.murphy@arm.com>,
	<mark.rutland@arm.com>, <jianyong.wu@arm.com>, <james.morse@arm.com>,
	<linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>, <quic_guptap@quicinc.com>,
	<quic_tingweiz@quicinc.com>
References: <1678708637-8669-1-git-send-email-quic_zhenhuah@quicinc.com>
 <CANpmjNNBhfdshGhiycY5S-sMnubQx=qGCBcKL5Hm=WL2HXQ2uw@mail.gmail.com>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNNBhfdshGhiycY5S-sMnubQx=qGCBcKL5Hm=WL2HXQ2uw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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



On 2023/3/13 21:00, Marco Elver wrote:
> On Mon, 13 Mar 2023 at 12:57, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>>
>> Kfence only needs its pool to be mapped as page granularity, if it is
>> inited early. Previous judgement was a bit over protected. From [1], Mark
>> suggested to "just map the KFENCE region a page granularity". So I
>> decouple it from judgement and do page granularity mapping for kfence
>> pool only. Need to be noticed that late init of kfence pool still requires
>> page granularity mapping.
>>
>> Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
>> platform. Like what I've tested on QEMU(emulated 1GB RAM) with
>> gki_defconfig, also turning off rodata protection:
>> Before:
>> [root@liebao ]# cat /proc/meminfo
>> MemTotal:         999484 kB
>> After:
>> [root@liebao ]# cat /proc/meminfo
>> MemTotal:        1001480 kB
>>
>> To implement this, also relocate the kfence pool allocation before the
>> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
>> addr, __kfence_pool is to be set after linear mapping set up.
>>
>> LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
>> Suggested-by: Mark Rutland <mark.rutland@arm.com>
>> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
>> ---
>>   arch/arm64/mm/mmu.c      | 42 ++++++++++++++++++++++++++++++++++++++++++
>>   arch/arm64/mm/pageattr.c |  8 ++++++--
>>   include/linux/kfence.h   | 10 ++++++++++
>>   mm/kfence/core.c         |  9 +++++++++
>>   4 files changed, 67 insertions(+), 2 deletions(-)
>>
>> diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
>> index 6f9d889..ca5c932 100644
>> --- a/arch/arm64/mm/mmu.c
>> +++ b/arch/arm64/mm/mmu.c
>> @@ -24,6 +24,7 @@
>>   #include <linux/mm.h>
>>   #include <linux/vmalloc.h>
>>   #include <linux/set_memory.h>
>> +#include <linux/kfence.h>
>>
>>   #include <asm/barrier.h>
>>   #include <asm/cputype.h>
>> @@ -525,6 +526,31 @@ static int __init enable_crash_mem_map(char *arg)
>>   }
>>   early_param("crashkernel", enable_crash_mem_map);
>>
>> +#ifdef CONFIG_KFENCE
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>> +{
>> +       phys_addr_t kfence_pool;
>> +
>> +       if (!kfence_sample_interval)
>> +               return 0;
>> +
>> +       kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
>> +       if (!kfence_pool)
>> +               pr_err("failed to allocate kfence pool\n");
>> +
>> +       return kfence_pool;
>> +}
>> +
>> +#else
>> +
>> +static phys_addr_t arm64_kfence_alloc_pool(void)
>> +{
>> +       return 0;
>> +}
>> +
>> +#endif
>> +
>>   static void __init map_mem(pgd_t *pgdp)
>>   {
>>          static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
>> @@ -532,6 +558,7 @@ static void __init map_mem(pgd_t *pgdp)
>>          phys_addr_t kernel_end = __pa_symbol(__init_begin);
>>          phys_addr_t start, end;
>>          int flags = NO_EXEC_MAPPINGS;
>> +       phys_addr_t kfence_pool;
>>          u64 i;
>>
>>          /*
>> @@ -564,6 +591,10 @@ static void __init map_mem(pgd_t *pgdp)
>>          }
>>   #endif
>>
>> +       kfence_pool = arm64_kfence_alloc_pool();
>> +       if (kfence_pool)
>> +               memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
>> +
>>          /* map all the memory banks */
>>          for_each_mem_range(i, &start, &end) {
>>                  if (start >= end)
>> @@ -608,6 +639,17 @@ static void __init map_mem(pgd_t *pgdp)
>>                  }
>>          }
>>   #endif
>> +
>> +       /* Kfence pool needs page-level mapping */
>> +       if (kfence_pool) {
>> +               __map_memblock(pgdp, kfence_pool,
>> +                       kfence_pool + KFENCE_POOL_SIZE,
>> +                       pgprot_tagged(PAGE_KERNEL),
>> +                       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
>> +               memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
>> +               /* kfence_pool really mapped now */
>> +               kfence_set_pool(kfence_pool);
>> +       }
>>   }
>>
>>   void mark_rodata_ro(void)
>> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
>> index 79dd201..25e4a983 100644
>> --- a/arch/arm64/mm/pageattr.c
>> +++ b/arch/arm64/mm/pageattr.c
>> @@ -7,6 +7,7 @@
>>   #include <linux/module.h>
>>   #include <linux/sched.h>
>>   #include <linux/vmalloc.h>
>> +#include <linux/kfence.h>
>>
>>   #include <asm/cacheflush.h>
>>   #include <asm/set_memory.h>
>> @@ -22,12 +23,15 @@ bool rodata_full __ro_after_init = IS_ENABLED(CONFIG_RODATA_FULL_DEFAULT_ENABLED
>>   bool can_set_direct_map(void)
>>   {
>>          /*
>> -        * rodata_full, DEBUG_PAGEALLOC and KFENCE require linear map to be
>> +        * rodata_full and DEBUG_PAGEALLOC require linear map to be
>>           * mapped at page granularity, so that it is possible to
>>           * protect/unprotect single pages.
>> +        *
>> +        * Kfence pool requires page granularity mapping also if we init it
>> +        * late.
>>           */
>>          return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
>> -               IS_ENABLED(CONFIG_KFENCE);
>> +           (IS_ENABLED(CONFIG_KFENCE) && !kfence_sample_interval);
> 
> If you're struggling with kfence_sample_interval not existing if
> !CONFIG_KFENCE, this is one of the occasions where it'd be perfectly
> fine to write:
> 
> bool can_set_direct_map(void) {
> #ifdef CONFIG_KFENCE
>      /* ... your comment here ...*/
>      if (!kfence_sample_interval)
>          return true;
> }
> #endif
>       return .........
> }
> 
>>   }
>>
The can_set_direct_map() could be called anytime, eg, memory add,
vmalloc, and this will make different state of can_set_direct_map()
if kfence is re-enabled, I think that we need a new value to check 
whether or not the early kfence_pool is initialized.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/41a98759-1626-5e8f-3b1b-d038ef1925a7%40huawei.com.
