Return-Path: <kasan-dev+bncBCRKFI7J2AJRBWXXSCFAMGQE2AVZP4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id E0C9A40F2A3
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 08:55:23 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id l23-20020a17090aec1700b0019aefe0a92fsf6854650pjy.5
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 23:55:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631861722; cv=pass;
        d=google.com; s=arc-20160816;
        b=imIWzSFBUXTEYL22AuyekOatXIr6h5TvdC+ekMtN3xpj4mlIf/UlG2sSVjLrKPej2w
         uFWKFZ0/xLjeDEucgrAEKl+roplpw7AG8ZtVcmdC0G6u2zoVEkKVfL+zVfgJRLLcfTaa
         8fA6jSF6QxdVs7Z33wQMCqM9ION3K4eY8TN+q8Ld1ICk1VbRuIwtPQvXk/kjGSlPFEQu
         EbVFajKtD28PM1zUfAKviiJUhmM4qxz5QpiqlE+B8Yuxqfo/nGqS89JCB9GJBmKD/PSo
         8ZsCejmJutR9hvzasiycxvXgCrTmKlfDYwjG1MvCmr+rAsKxEgEVMYOf27de7NyBm7J0
         La6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=VTj2qRZw5XK847iLYggaEXAEwTKB6N3b4sC71oQfsRw=;
        b=RqbEZXmXu2hjXWsy6iajOwnLAt1mF8dKME038nOQI+pTv/CSS3uJ314LPAIcIeWmWB
         zVz6RVEdZ0bLmkOL5TNENyEaK17HjfbxAWeksFX8kmn5cT7SrCfWL3ENPyLA6tYnvg33
         Pr6j4xyLqpmaj4GVFgyWixkaRMjC1Burg8ab7g8HrmZBLF4tBdRHkidL1bvluIUKh4KD
         vAU846rK9g6BFvSTx8qxLp/hqbdhgdVgPLgZOWb8PuOn6dtEb3v51WKGWHx894yVTUxr
         JNOvTczMadGff8NI/pZe0MsFcmQUQ3iJMzHVpsira0VTMRA4JZW38yq1pJFhARUsa2B4
         /RaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VTj2qRZw5XK847iLYggaEXAEwTKB6N3b4sC71oQfsRw=;
        b=Eto9mBVy4nTZqApY13KiHDxdziQWZo3Qf0/XFaMHUWQU24FDKcvMaWKs6INBxIZCSf
         2qqvT4FdO1bgDxto60JSnxaL9b4qdYDKDhli/QEXI2fBUDMZR5QvyyLfeZsgcWTCZov2
         DCZA0RuMdiUwppi6HecWg9N40IBJ3d4Wn22X2kFt1SWXEljm8Pzv7+QZwSXfKoU+zqEU
         Oqx7HBXvvuBmXvahJ6XVE+D1sa40Xz5eV8tMVmR7WXAspq2d/qn4/IR4StDgdAl1u2BQ
         B/r9I55oJddv9tbeEsoUY1YtAxUlXUS9DzXK37JEOnPt5MM5yfyhFP+jTWZdnyYv/G5+
         BklQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VTj2qRZw5XK847iLYggaEXAEwTKB6N3b4sC71oQfsRw=;
        b=PApcI6tvQ0D1ORADXTs0QDHSQBSLGr23lWIGuxsxoY1SEmmt9NQK6JHXm+4oUwHwrX
         9pqGVkjDW8euAXKExjPRrJLOWyRUMV7BBtl9BM6CYJe0GmtN6cnW3VfUP0qjW89mFSf3
         LRqxIMabPa112NrXQ1S0Q/lvz5zljIhgGQlgTF7r685iFLK1VXxwPXMPAIWsg9DwGL9A
         FPJlJkoTys6y595FrxdKCW/Q5BXcGwecckJs2IBhsRRm3Rl/llHNdAtL8qwVtk2HTNta
         tQD8KGW/PPgeTEk6rxFzbCYqNPBywXMgN3uZxg/Gi5geh5ljZOzjRtSbOAZTinpVeOIE
         h/vA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fzzWEiJm/pjIy43wQksPUWaw1Rg6uWHO08BrzuieY+yfr048O
	SNr5CpXBTG3W2m6u3f261mI=
X-Google-Smtp-Source: ABdhPJz2nj5Kwpz7DHhP2Vl0JrsvvKY20F5X21rDHX5cXJceUN2VoZTbjDExtjx3UO11f0Xwa4tLzQ==
X-Received: by 2002:a63:5b08:: with SMTP id p8mr8576679pgb.28.1631861722601;
        Thu, 16 Sep 2021 23:55:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:848e:: with SMTP id c14ls3400390plo.1.gmail; Thu, 16
 Sep 2021 23:55:22 -0700 (PDT)
X-Received: by 2002:a17:902:c406:b0:13b:7b40:9c51 with SMTP id k6-20020a170902c40600b0013b7b409c51mr8326354plk.89.1631861722036;
        Thu, 16 Sep 2021 23:55:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631861722; cv=none;
        d=google.com; s=arc-20160816;
        b=c7RwdFITd7RaSMPOpLLpVBWsTWq3xe3MvaXH5qGJudRCPsxYXU52RQzyDAVJV+LbEg
         ofjYBTbCM8a2cPGqlLi4a4ch4GZrPHSBggwyTXraqOPOLzSv9O1m24S6QmIi77ifc2Tx
         OqZmg/moeRHWgGhBWSDAXpGrQnu85sfk91AlVpoUmszHyZtv6Z7XOYxNAgCOszYToPve
         9M0BJtVjUNUUHo35dsiT5Ogj1w2wu3N6n0VdIW031zeKiuXLDQQQ6SEl9YIeftwWGHl9
         /pUrQnjgxDCrDjo2/eeETtkIajq16uF3aESkiIdsc0MWIsBJ03jaWdtEGJIr5asD+Pzg
         QEwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=OR9GPLLQdFB12ge4GICfw98hVlwciAUysHIjzgxV2nI=;
        b=NGyHS9mbYGegd+6WNZLGDZgUsyBmgmjtyoQIVMT/rrv6gxmUydPYgqtRWKLQRr76y1
         F1wBlSVw8cAZdhsp557dHuIcJK0RuxfGcpGNvAseGKFp17SIHz7H5okWZldxfXUtXbSR
         sGWjuQk6yH3Rn2mubqF3CEfLwsiaJQoILBDc04AdarUMj2EmqQ+KiWDjiIXAW2OBHEDx
         G2rz9Y/+hO2gR3vW+lm2jMNT92H+CVtxLnNL/RvkLnDccBuEPd+mLLhdwxa3ULMTk6C5
         2iWr4HUf46tlozN6lTx+nauLFAGKrPz1WQjeVrdxeX30GUm90h2USJiNwk3ns5am2SCC
         YQ5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id u5si877967pji.0.2021.09.16.23.55.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Sep 2021 23:55:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4H9l3N2yCXzbmb8;
	Fri, 17 Sep 2021 14:51:12 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 17 Sep 2021 14:55:20 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 17 Sep 2021 14:55:19 +0800
Subject: Re: [PATCH v4 2/3] arm64: Support page mapping percpu first chunk
 allocator
To: Greg KH <gregkh@linuxfoundation.org>
CC: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <elver@google.com>, <akpm@linux-foundation.org>,
	<kasan-dev@googlegroups.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <20210910053354.26721-3-wangkefeng.wang@huawei.com>
 <YUQ0lvldA+wGpr0G@kroah.com>
From: Kefeng Wang <wangkefeng.wang@huawei.com>
Message-ID: <9b2e89c4-a821-8657-0ffb-d822aa51936c@huawei.com>
Date: Fri, 17 Sep 2021 14:55:18 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <YUQ0lvldA+wGpr0G@kroah.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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


On 2021/9/17 14:24, Greg KH wrote:
> On Fri, Sep 10, 2021 at 01:33:53PM +0800, Kefeng Wang wrote:
>> Percpu embedded first chunk allocator is the firstly option, but it
>> could fails on ARM64, eg,
>>    "percpu: max_distance=3D0x5fcfdc640000 too large for vmalloc space 0x=
781fefff0000"
>>    "percpu: max_distance=3D0x600000540000 too large for vmalloc space 0x=
7dffb7ff0000"
>>    "percpu: max_distance=3D0x5fff9adb0000 too large for vmalloc space 0x=
5dffb7ff0000"
>>  =20
>> then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get=
_vm_areas+0x488/0x838",
>> even the system could not boot successfully.
>>
>> Let's implement page mapping percpu first chunk allocator as a fallback
>> to the embedding allocator to increase the robustness of the system.
>>
>> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
>> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
>> ---
>>   arch/arm64/Kconfig       |  4 ++
>>   drivers/base/arch_numa.c | 82 +++++++++++++++++++++++++++++++++++-----
>>   2 files changed, 76 insertions(+), 10 deletions(-)
>>
>> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
>> index 077f2ec4eeb2..04cfe1b4e98b 100644
>> --- a/arch/arm64/Kconfig
>> +++ b/arch/arm64/Kconfig
>> @@ -1042,6 +1042,10 @@ config NEED_PER_CPU_EMBED_FIRST_CHUNK
>>   	def_bool y
>>   	depends on NUMA
>>  =20
>> +config NEED_PER_CPU_PAGE_FIRST_CHUNK
>> +	def_bool y
>> +	depends on NUMA
> Why is this a config option at all?

The config is introduced from

commit 08fc45806103e59a37418e84719b878f9bb32540
Author: Tejun Heo <tj@kernel.org>
Date:=C2=A0=C2=A0 Fri Aug 14 15:00:49 2009 +0900

 =C2=A0=C2=A0=C2=A0 percpu: build first chunk allocators selectively

 =C2=A0=C2=A0=C2=A0 There's no need to build unused first chunk allocators =
in. Define
 =C2=A0=C2=A0=C2=A0 CONFIG_NEED_PER_CPU_*_FIRST_CHUNK and let archs enable =
them
 =C2=A0=C2=A0=C2=A0 selectively.

For now, there are three ARCHs support both PER_CPU_EMBED_FIRST_CHUNK

and PER_CPU_PAGE_FIRST_CHUNK.

 =C2=A0 arch/powerpc/Kconfig:config NEED_PER_CPU_PAGE_FIRST_CHUNK
 =C2=A0 arch/sparc/Kconfig:config NEED_PER_CPU_PAGE_FIRST_CHUNK
 =C2=A0 arch/x86/Kconfig:config NEED_PER_CPU_PAGE_FIRST_CHUNK

and we have a cmdline to choose a alloctor.

 =C2=A0=C2=A0 percpu_alloc=3D=C2=A0=C2=A0 Select which percpu first chunk a=
llocator to use.
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Currently supported values are "embed"=
 and "page".
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Archs may support subset or none of th=
e selections.
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 See comments in mm/percpu.c for detail=
s on each
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 allocator.=C2=A0 This parameter is pri=
marily for debugging
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 and performance comparison.

embed percpu first chunk allocator is the first choice, but it could=20
fails due to some

memory layout(it does occurs on ARM64 too.), so page mapping percpu=20
first chunk

allocator is as a fallback, that is what this patch does.

>
>> +
>>   source "kernel/Kconfig.hz"
>>  =20
>>   config ARCH_SPARSEMEM_ENABLE
>> diff --git a/drivers/base/arch_numa.c b/drivers/base/arch_numa.c
>> index 46c503486e96..995dca9f3254 100644
>> --- a/drivers/base/arch_numa.c
>> +++ b/drivers/base/arch_numa.c
>> @@ -14,6 +14,7 @@
>>   #include <linux/of.h>
>>  =20
>>   #include <asm/sections.h>
>> +#include <asm/pgalloc.h>
>>  =20
>>   struct pglist_data *node_data[MAX_NUMNODES] __read_mostly;
>>   EXPORT_SYMBOL(node_data);
>> @@ -168,22 +169,83 @@ static void __init pcpu_fc_free(void *ptr, size_t =
size)
>>   	memblock_free_early(__pa(ptr), size);
>>   }
>>  =20
>> +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
> Ick, no #ifdef in .c files if at all possible please.

The drivers/base/arch_numa.c is shared by RISCV/ARM64, so I add this=20
config to

no need to build this part on RISCV.

>
>> +static void __init pcpu_populate_pte(unsigned long addr)
>> +{
>> +	pgd_t *pgd =3D pgd_offset_k(addr);
>> +	p4d_t *p4d;
>> +	pud_t *pud;
>> +	pmd_t *pmd;
>> +
>> +	p4d =3D p4d_offset(pgd, addr);
>> +	if (p4d_none(*p4d)) {
>> +		pud_t *new;
>> +
>> +		new =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>> +		if (!new)
>> +			goto err_alloc;
>> +		p4d_populate(&init_mm, p4d, new);
>> +	}
>> +
>> +	pud =3D pud_offset(p4d, addr);
>> +	if (pud_none(*pud)) {
>> +		pmd_t *new;
>> +
>> +		new =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>> +		if (!new)
>> +			goto err_alloc;
>> +		pud_populate(&init_mm, pud, new);
>> +	}
>> +
>> +	pmd =3D pmd_offset(pud, addr);
>> +	if (!pmd_present(*pmd)) {
>> +		pte_t *new;
>> +
>> +		new =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>> +		if (!new)
>> +			goto err_alloc;
>> +		pmd_populate_kernel(&init_mm, pmd, new);
>> +	}
>> +
>> +	return;
>> +
>> +err_alloc:
>> +	panic("%s: Failed to allocate %lu bytes align=3D%lx from=3D%lx\n",
>> +	      __func__, PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);
> That feels harsh, are you sure you want to crash?  There's no way to
> recover from this?  If not, how can this fail in real life?
Yes,=C2=A0 if no memory, the system won't work, panic is the only choose.
>
>> +}
>> +#endif
>> +
>>   void __init setup_per_cpu_areas(void)
>>   {
>>   	unsigned long delta;
>>   	unsigned int cpu;
>> -	int rc;
>> +	int rc =3D -EINVAL;
>> +
>> +	if (pcpu_chosen_fc !=3D PCPU_FC_PAGE) {
>> +		/*
>> +		 * Always reserve area for module percpu variables.  That's
>> +		 * what the legacy allocator did.
>> +		 */
>> +		rc =3D pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
>> +					    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE,
>> +					    pcpu_cpu_distance,
>> +					    pcpu_fc_alloc, pcpu_fc_free);
>> +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
>> +		if (rc < 0)
>> +			pr_warn("PERCPU: %s allocator failed (%d), falling back to page size=
\n",
>> +				   pcpu_fc_names[pcpu_chosen_fc], rc);
>> +#endif
> Why only print out a message for a config option?  Again, no #ifdef in
> .c files if at all possible.

Same reason as above.

Thanks for your review.

>
> thanks,
>
> greg k-h
> .
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9b2e89c4-a821-8657-0ffb-d822aa51936c%40huawei.com.
