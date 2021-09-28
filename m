Return-Path: <kasan-dev+bncBAABBME4ZKFAMGQE4QDY2HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 336E241A618
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Sep 2021 05:38:26 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id k1-20020a17090a590100b001971da53970sf1626853pji.4
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Sep 2021 20:38:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632800304; cv=pass;
        d=google.com; s=arc-20160816;
        b=qCXfnsnsFCzEewJW3GGEZ7ZKTVUuojljrdfxHiWf+V7BOV42ysKBn/WIg6kv+KdeLk
         43l6BA685SxyNwHME4Fy1HYl7yQLUMOnS4gAjTqqoDfTkoraGrsvX9DGRxZxgqG66mQj
         7o0DGVqThayzz6eGH4bvetbGzl7Zhgz+Fee6ZU4J3OghRfcChHmlRpMJA4DFXUQA53gq
         vJkwUdJGw+hdve3EE53QfSIRC0WhBnK7u4YW4311ICltLouq5R4PajKNwbTrIQU7Klzj
         VPny6UaJH6cxGjFZbNQGv3wHZ0Hogm+JCySxcgG+ABlF2oI14SKAV6UgY7lIKlYum7uc
         ab9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=xD/ZDqnrdF8fCVPJtjbmlGIa567XNXJj2FEmk5pyAd4=;
        b=i6Pvstlot76MzLqwnHCCDvOO+WvedJ8T54DRkXFr3Z3bAfndrDaaLfxZs7bYnC97W/
         g1TunXpOJrCTDes7YtspH9B6zsXYvFXM9gLFN2y4Q9NXyRN8gzOgxC+WEYRvmWan5nYF
         AJNAdd6lJqW8kMWU++7fmermu5BryRhPWgaG7kcl2jnX2mqKd7YlZRBH7BR35Mofb8Zh
         EQ8u2r7Wk24yT+UJJzbiPp6hWFjK0FP9RIAcZv2f8fH1oleToFCwdByopbCT3ltIQj1Z
         xU6leSAwicND5NVy8wrm7eSZ/qHyBdAd/WB8Nd+80bf1xW+Wl720/PJj381WooW53tt/
         1i7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:references:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xD/ZDqnrdF8fCVPJtjbmlGIa567XNXJj2FEmk5pyAd4=;
        b=YvLWhq/Cm86bTaykCM/nBV307wkvOwjEKTFKyzezra+6Te16VoTE6qCNf1GZx0CnX3
         civCE5sofbC+qk25KiTl588LUrcwNJPwLwv26CvoUyyqiVt2yYb44h0vY7ztwxK3TxQs
         76w60BpHxeGH8GnAbNzds+H3xG4vm+xJqx+kPOzCffKBAeOD4N80xB5O0y9cnHxc3aB8
         pofmC4VCvzYbg1sQW+hC2I5g0uX6tma30VVXKL/wo4NxVCGUA9oJvdAM3TuZPNJJxd2F
         WneyU8CVHQrQScH/Piwx5DMsxp3ywe1Fv8VkQlhP2HgI7jWwYPQDniFakLAKHnKGQ6kc
         cwtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:references:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xD/ZDqnrdF8fCVPJtjbmlGIa567XNXJj2FEmk5pyAd4=;
        b=s+QzDsb7g0PpHUXGz542IDNfODRR7JuSZm/YmE9BB3xiANbySlHO+0CeE0CUlU6eqs
         EhEVe7PPq70R8Wt1Iw9p573MQoNLT9Lp9kTzNakvI85rH9YPEG9IU5NmTYlp64IwNLxB
         ZZTVNX09HZhYlh+P21bAKkdCNaxVEkaDEtf5iXvPyqKOBzPhn2XZkROkvoFBU72q1noU
         E2yVpcwsoooHYQyzko21oE1GdYX2jrPnCL2S80AN1CWKNyv5BCNTxy19wsZwpI1xEaHY
         zAvGuAOY5A80nlMYof+MX8c7vgXzxv6WlXyGMmflE3OFpIY6mGb+tgW1NwERioqNWOXt
         0Tew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531lSS7aLjkKr1zJ6mhvvHU2UdoFeOug1AAyLtlnC1gb9ovJdl4Z
	m/x05N6hcCUciTkmz7Pp2hE=
X-Google-Smtp-Source: ABdhPJwhx4X/4jtrFMEhtskpFbx3GYnWHiRX08dD6xOB4O3Oc3bSwq4MVO3/o+nklLpznSMbNwYnrg==
X-Received: by 2002:a17:90a:86:: with SMTP id a6mr2838583pja.190.1632800304441;
        Mon, 27 Sep 2021 20:38:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e57:: with SMTP id p23ls864705pja.2.canary-gmail;
 Mon, 27 Sep 2021 20:38:24 -0700 (PDT)
X-Received: by 2002:a17:90a:c90a:: with SMTP id v10mr737441pjt.1.1632800303897;
        Mon, 27 Sep 2021 20:38:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632800303; cv=none;
        d=google.com; s=arc-20160816;
        b=HnZgYloaGtXfpVTOLVQzHL/vpMfZG/DUjsuTxvBB6i8g+STbNblZagY0F30yQbqnJR
         juZncDG0KgTZl2rCFDt8JK7EzflHjiEQG6y97qBYgyx98Ui37RwjLLrhpSZEGQ65J8Uk
         pQJY7pCckAiLR3FRAZj4XKNkiK2WbKMe29au9H/MIArfoTU+VEwfy7h/6kVtW7zQSbdw
         wj5GiQG/k0Zq+tdPYnupkAda7hoXAxg2lVfbH/LHY4Tnd4rT7GtluRRe+V8jftZSsDbA
         gWxl+Lovik+WmOi1FkMySxHWpPT20xaNkCZ6BVRCzNXc6mk+Hwo96AKOAnoJeUZOiu0f
         J1RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:mime-version:user-agent:date:message-id:from:cc
         :references:to:subject;
        bh=Z7vWGsUjnCiDBB36u/xSD+RM+ZRAx/SfEkifpH/vZq4=;
        b=buBGom0w9PXhGW39MvJpIUbg4au4s3Egp0ztfJKRv14xdcqRBCuCfH+TCvhdVScnct
         u4Z1Qxf4krmCWNyWowdp7RCUqaBZcRCARorxi9z4a04DXEmYlecOQziVNDgKz4dscuRq
         6yXyPECWrDKgGxptIrcv8Dt0HBpmuksHHZd6thBqamGiDdqkMwmT0P/S++vXaN9/oPjH
         jCb68Ko+mnpoIZqLhJQf1sQK95friCJ+aTasAtkmzYdyU822Xuvl8s21LGXhmgpXWxFw
         1g7S9kJM6ISIfFDqfB5zEBNdcmumlcDqQhef8XmJ/TJAD4rMC9iZTbDtoMGh2VS0+aDf
         tBPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id r7si242997pjp.0.2021.09.27.20.38.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Sep 2021 20:38:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4HJQ8s1G5zzRS6g;
	Tue, 28 Sep 2021 11:34:05 +0800 (CST)
Received: from dggpemm500009.china.huawei.com (7.185.36.225) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Tue, 28 Sep 2021 11:38:21 +0800
Received: from [10.174.179.24] (10.174.179.24) by
 dggpemm500009.china.huawei.com (7.185.36.225) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Tue, 28 Sep 2021 11:38:20 +0800
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
Message-ID: <9006e94d-ce2b-4019-6be7-6111513165cd@huawei.com>
Date: Tue, 28 Sep 2021 11:38:20 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101
 Thunderbird/45.7.1
MIME-Version: 1.0
In-Reply-To: <CAG_fn=X=k3w-jr3iCevB_t7Hh0r=qZ=nOxwk5ujsO+LZ7hA4Aw@mail.gmail.com>
Content-Type: multipart/alternative;
	boundary="------------67D944B06E273A272E877EF7"
X-Originating-IP: [10.174.179.24]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 dggpemm500009.china.huawei.com (7.185.36.225)
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as
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

--------------67D944B06E273A272E877EF7
Content-Type: text/plain; charset="UTF-8"

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
The previous patch by Jisheng Zhang guaranteeskfence pool to be mapped at
page granularity by allocating KFENCE pool before paging_init(), and then map it
at page granularity during map_mem().

The previous patch has a problem: Even If kfence is disabled in cmdline, kfence_pool
is still allocated, which is a waste.

thanks,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9006e94d-ce2b-4019-6be7-6111513165cd%40huawei.com.

--------------67D944B06E273A272E877EF7
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <head>
    <meta content=3D"text/html; charset=3Dutf-8" http-equiv=3D"Content-Type=
">
  </head>
  <body bgcolor=3D"#FFFFFF" text=3D"#000000">
    <div class=3D"moz-cite-prefix">On 2021/9/18 19:50, Alexander Potapenko
      wrote:<br>
    </div>
    <blockquote
cite=3D"mid:CAG_fn=3DX=3Dk3w-jr3iCevB_t7Hh0r=3DqZ=3DnOxwk5ujsO+LZ7hA4Aw@mai=
l.gmail.com"
      type=3D"cite">
      <pre wrap=3D"">On Sat, Sep 18, 2021 at 10:10 AM Liu Shixin <a class=
=3D"moz-txt-link-rfc2396E" href=3D"mailto:liushixin2@huawei.com">&lt;liushi=
xin2@huawei.com&gt;</a> wrote:
</pre>
      <blockquote type=3D"cite">
        <pre wrap=3D"">
Currently if KFENCE is enabled in arm64, the entire linear map will be
mapped at page granularity which seems overkilled. Actually only the
kfence pool requires to be mapped at page granularity. We can remove the
restriction from KFENCE and force the linear mapping of the kfence pool
at page granularity later in arch_kfence_init_pool().
</pre>
      </blockquote>
      <pre wrap=3D"">
There was a previous patch by Jisheng Zhang intended to remove this
requirement: <a class=3D"moz-txt-link-freetext" href=3D"https://lore.kernel=
.org/linux-arm-kernel/20210524180656.395e45f6@xhacker.debian/">https://lore=
.kernel.org/linux-arm-kernel/20210524180656.395e45f6@xhacker.debian/</a>
Which of the two is more preferable?
</pre>
    </blockquote>
    The previous patch by Jisheng Zhang guarantees<span style=3D"color:
      rgb(32, 33, 36); font-family: arial, sans-serif; font-size: 16px;
      font-style: normal; font-variant-ligatures: normal;
      font-variant-caps: normal; font-weight: 400; letter-spacing:
      normal; orphans: 2; text-align: left; text-indent: 0px;
      text-transform: none; white-space: normal; widows: 2;
      word-spacing: 0px; -webkit-text-stroke-width: 0px;
      background-color: rgb(255, 255, 255); text-decoration-thickness:
      initial; text-decoration-style: initial; text-decoration-color:
      initial; display: inline !important; float: none;"> </span>kfence
    pool to be mapped at<br>
    page granularity by allocating KFENCE pool before paging_init(), and
    then map it <br>
    at page granularity during map_mem().<br>
    <br>
    The previous patch has a problem: Even If kfence is disabled in
    cmdline, kfence_pool<br>
    is still allocated, which is a waste.<br>
    <br>
    thanks,<br>
    <blockquote
cite=3D"mid:CAG_fn=3DX=3Dk3w-jr3iCevB_t7Hh0r=3DqZ=3DnOxwk5ujsO+LZ7hA4Aw@mai=
l.gmail.com"
      type=3D"cite">
      <pre wrap=3D"">
</pre>
      <blockquote type=3D"cite">
        <pre wrap=3D"">Signed-off-by: Liu Shixin <a class=3D"moz-txt-link-r=
fc2396E" href=3D"mailto:liushixin2@huawei.com">&lt;liushixin2@huawei.com&gt=
;</a>
---
 arch/arm64/include/asm/kfence.h | 69 ++++++++++++++++++++++++++++++++-
 arch/arm64/mm/mmu.c             |  4 +-
 2 files changed, 70 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfenc=
e.h
index aa855c6a0ae6..bee101eced0b 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -8,9 +8,76 @@
 #ifndef __ASM_KFENCE_H
 #define __ASM_KFENCE_H

+#include &lt;linux/kfence.h&gt;
 #include &lt;asm/set_memory.h&gt;
+#include &lt;asm/pgalloc.h&gt;

-static inline bool arch_kfence_init_pool(void) { return true; }
+static inline int split_pud_page(pud_t *pud, unsigned long addr)
+{
+       int i;
+       pmd_t *pmd =3D pmd_alloc_one(&amp;init_mm, addr);
+       unsigned long pfn =3D PFN_DOWN(__pa(addr));
+
+       if (!pmd)
+               return -ENOMEM;
+
+       for (i =3D 0; i &lt; PTRS_PER_PMD; i++)
+               set_pmd(pmd + i, pmd_mkhuge(pfn_pmd(pfn + i * PTRS_PER_PTE,=
 PAGE_KERNEL)));
+
+       smp_wmb(); /* See comment in __pte_alloc */
+       pud_populate(&amp;init_mm, pud, pmd);
+       flush_tlb_kernel_range(addr, addr + PUD_SIZE);
+       return 0;
+}
+
+static inline int split_pmd_page(pmd_t *pmd, unsigned long addr)
+{
+       int i;
+       pte_t *pte =3D pte_alloc_one_kernel(&amp;init_mm);
+       unsigned long pfn =3D PFN_DOWN(__pa(addr));
+
+       if (!pte)
+               return -ENOMEM;
+
+       for (i =3D 0; i &lt; PTRS_PER_PTE; i++)
+               set_pte(pte + i, pfn_pte(pfn + i, PAGE_KERNEL));
+
+       smp_wmb(); /* See comment in __pte_alloc */
+       pmd_populate_kernel(&amp;init_mm, pmd, pte);
+
+       flush_tlb_kernel_range(addr, addr + PMD_SIZE);
+       return 0;
+}
+
+static inline bool arch_kfence_init_pool(void)
+{
+       unsigned long addr;
+       pgd_t *pgd;
+       p4d_t *p4d;
+       pud_t *pud;
+       pmd_t *pmd;
+
+       for (addr =3D (unsigned long)__kfence_pool; is_kfence_address((void=
 *)addr);
+            addr +=3D PAGE_SIZE) {
+               pgd =3D pgd_offset(&amp;init_mm, addr);
+               if (pgd_leaf(*pgd))
+                       return false;
+               p4d =3D p4d_offset(pgd, addr);
+               if (p4d_leaf(*p4d))
+                       return false;
+               pud =3D pud_offset(p4d, addr);
+               if (pud_leaf(*pud)) {
+                       if (split_pud_page(pud, addr &amp; PUD_MASK))
+                               return false;
+               }
+               pmd =3D pmd_offset(pud, addr);
+               if (pmd_leaf(*pmd)) {
+                       if (split_pmd_page(pmd, addr &amp; PMD_MASK))
+                               return false;
+               }
+       }
+       return true;
+}

 static inline bool kfence_protect_page(unsigned long addr, bool protect)
 {
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index cfd9deb347c3..b2c79ccfb1c5 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -516,7 +516,7 @@ static void __init map_mem(pgd_t *pgdp)
         */
        BUILD_BUG_ON(pgd_index(direct_map_end - 1) =3D=3D pgd_index(direct_=
map_end));

-       if (can_set_direct_map() || crash_mem_map || IS_ENABLED(CONFIG_KFEN=
CE))
+       if (can_set_direct_map() || crash_mem_map)
                flags |=3D NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;

        /*
@@ -1485,7 +1485,7 @@ int arch_add_memory(int nid, u64 start, u64 size,
         * KFENCE requires linear map to be mapped at page granularity, so =
that
         * it is possible to protect/unprotect single pages in the KFENCE p=
ool.
         */
-       if (can_set_direct_map() || IS_ENABLED(CONFIG_KFENCE))
+       if (can_set_direct_map())
                flags |=3D NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;

        __create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start),
--
2.18.0.huawei.25

--
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a class=3D"moz-txt-link-abbreviated" href=3D"mailto:kasan-dev+unsu=
bscribe@googlegroups.com">kasan-dev+unsubscribe@googlegroups.com</a>.
To view this discussion on the web visit <a class=3D"moz-txt-link-freetext"=
 href=3D"https://groups.google.com/d/msgid/kasan-dev/20210918083849.2696287=
-1-liushixin2%40huawei.com">https://groups.google.com/d/msgid/kasan-dev/202=
10918083849.2696287-1-liushixin2%40huawei.com</a>.
</pre>
      </blockquote>
      <pre wrap=3D"">


</pre>
    </blockquote>
    <br>
  </body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/9006e94d-ce2b-4019-6be7-6111513165cd%40huawei.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/9006e94d-ce2b-4019-6be7-6111513165cd%40huawei.com</a>.<br />

--------------67D944B06E273A272E877EF7--
