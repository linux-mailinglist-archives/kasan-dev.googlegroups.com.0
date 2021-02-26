Return-Path: <kasan-dev+bncBCRKNY4WZECBBXEP4KAQMGQERE7P3RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F14C325D31
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 06:32:13 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id o4sf5626087pjp.3
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 21:32:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614317532; cv=pass;
        d=google.com; s=arc-20160816;
        b=0OYt6PVtHLmG8qJj62cuobJpCe+6Y/3bXjCpLw2Cs9u9Bzx3WDD6b3gcuKEdTAcmiJ
         Ogn00f4IPKSZzEDg6h1PjRV6yKMxAElw8PVr7vsXTZ47JABBAJhLXWjAZGeNP6xSIgMF
         QHxJSUQD6hjrqXMhkEhSQvscTKkKKqCCQrNBzAcszDQGrAIX1i4T1LcQiOOzT1zXKRaL
         0y2t8C5j4PdF3gOdiQsenEC4lsgoQDvSDUG2hdX+0xQCwEYIzJ4SuQP2ZaVLTgNy78rg
         E0i+IljOJWYBT27PSJpAWYFeJi5bSr53plxeS3NiSA9+FEnrNCNA9M1+1gnVRvzjIGHR
         ywyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:to:from:cc:in-reply-to:subject:date:sender
         :dkim-signature;
        bh=/vgPyzXRaCw1xtDzctfcn2NHQmScu7Z03U0/GK3BNG8=;
        b=Q497UgZn+AlBwRv8xe9ZuDk/QY/1msbIsxtR5GDQQJjjhE+EsLS60wZciWJsxOqY0l
         x6wyf4ooSaVZ/gkLsc41fSXOfVLz4708KWD4d8Z/6Ojty9bt/GraSqo3raEkPtPq7eYj
         pS+JTty4Dhzg9CCWZOaJQ0rttap5OVqbBJgmkHlNTy5TnTY3NCXpM3s7mwjR8iLKT/jW
         6QGCx2umsS3wpQ4H9xtoCp9LdY0bN8l6orNuiEM57/CcmbPLmnhiyL0+tqinnRGLURZP
         9RSztTHR8k3bhhtBqGXE5RMLMGNXFXE33BLmvqw3Gq0rw1m6MO6+OVp0Ov5WRoDdATgh
         g+uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b="JioBCib/";
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/vgPyzXRaCw1xtDzctfcn2NHQmScu7Z03U0/GK3BNG8=;
        b=PFFXOLdFGfIfgP5UDAZw5esPjQDdp7bWe7Q8cViVI8400+zy0gFaKWeyuzTzdF0rDG
         Z2vRYQ4NrV31GEdE4CrP33TSEgVDQ3aph6v+bcDwxj5JPMUTIcz11yhVhmY/fAnoXJHa
         LxcEPCQiLY3Gifv3Z+3Y5rVHi9NAPp4muhdbR9BiKiAD052LaNLRxrGdtUA+juhziY+I
         kDN9HtZmLk14PH7rKmTYAE8z6KDGFxsruwd82az6FL0LDhEbRXbhldkveiTy4LkiNs77
         rSJSXiujuI0UY6cG3uWQGlRJvKaueRDz4Q9l9VS/teWjkp5aFLJoRQ+jmAUoFmVaH8VB
         a9ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/vgPyzXRaCw1xtDzctfcn2NHQmScu7Z03U0/GK3BNG8=;
        b=FLgpIe/JiHhYjnJ0TRWBqRodufzH73ljflSLdDeaH4UTPvS5Lss0jJuXVNWcCsC3z9
         SMhxV+OX1c7IVHbEdW9NcE8nLq2qBkHGCVAsJ5/aNbWqkP9wg3tEk3uxIe/13FQD5H54
         w9ohe+xR7RuPzTnbGyXkdwCB22WMoNklE36BMbH0EcutlR0+GpsXFJmWwp4s2CjG8C7R
         hi8TZT7Y+1ViUAe+0Q0TON4v9l8VEJTcSbzWtdT0gUEmY1Hk3F93RtEXoLQbFK6X5rhi
         FDi/Ohf51JKy0ykOpFCjGeWQyi62JK0W04ekFtrp3zzW6mNQ0EWwyeC2rI0+SW2JOsgV
         qcrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531KeWjJzrODRNlZ6IseXj/8aeRxwlsPuFFgoN72ff+AlKkrIicI
	onsFClMh+muHBAVnLYZTSCk=
X-Google-Smtp-Source: ABdhPJwIh4UI2vE43yDr5+Elao9tbNgDwW5Pj5y63aIt4XOZRO/yETJU90g6Jxu97atYMlbHKeISRA==
X-Received: by 2002:a17:90a:ba16:: with SMTP id s22mr1755475pjr.88.1614317532257;
        Thu, 25 Feb 2021 21:32:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1790:: with SMTP id 138ls3233971pfx.5.gmail; Thu, 25 Feb
 2021 21:32:11 -0800 (PST)
X-Received: by 2002:a63:581f:: with SMTP id m31mr1457542pgb.142.1614317531711;
        Thu, 25 Feb 2021 21:32:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614317531; cv=none;
        d=google.com; s=arc-20160816;
        b=M2z4Y5YSrifYvXG+e5HVpTQusgTVzqudX3pO6WbleGi+Dx18nn3XDFZVYgOJncVKQy
         tLzmgYUjG14caed/zYeu30GGEJ7gPvQUBqxYP7RxE3GuGHZKOxM+g/5q0L7CxwLUcsb3
         LPlnQvEm0mBnNpDCNjqueZGvsLVykpOpOxx1+r+Z9Z3WCd+CDMnh/zVXjcMSXutPpv0q
         NX+S7TRQdS/MGlPV9D6lTt5TjrA3vbwACnLrIOYcSoZ5ErbYuQV/8b2bMH3/gLkrHNoA
         M3SbHeBSoUVa7H0lzK5Lv1HS0zP5m26sF9soWR8afrdNbbKuZO1Vlf3BC3RIO1XeI3I5
         cN2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=nFi/Tly9ElESGJN8oskhUGGfZDgsnBKdYL375bNbXVw=;
        b=KVK2jX25Tmdu47d8U9eDVcrqAyrXnmbKwUkhNd0wkwrb0egDI0Ex+OyluDwQacphCf
         wB3PwKJ2KMidZwBtMvmO29Ewe9eDcBs+D39ArlD1hFnqPO37lJjSaTv3ddq50N6J0fie
         cxkemNPWyZfEW/6dh3Z9AXcSecbVEKfLbvQm/lnDA8WEW8fOHImAFBZCo8WzvE9fQYtP
         J9QSN9hZtSvjHCWDLsiF6E7L4EKRDChI8brYtlE73GGzSbySceYcEXmdvnuE4ekB6uKX
         gxBbADar+qfUauDEZYDcScB3L68nOWhPaPkhb/F40vlIwbxRYc5risNLKIMVZjkkacj+
         a1UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b="JioBCib/";
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id lt14si821020pjb.2.2021.02.25.21.32.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Feb 2021 21:32:11 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id j12so5478311pfj.12
        for <kasan-dev@googlegroups.com>; Thu, 25 Feb 2021 21:32:11 -0800 (PST)
X-Received: by 2002:aa7:85cf:0:b029:1ee:8ae:533a with SMTP id z15-20020aa785cf0000b02901ee08ae533amr1486354pfn.30.1614317531108;
        Thu, 25 Feb 2021 21:32:11 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id v185sm7960624pfb.125.2021.02.25.21.32.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Feb 2021 21:32:10 -0800 (PST)
Date: Thu, 25 Feb 2021 21:32:10 -0800 (PST)
Subject: Re: [PATCH] riscv: Add KASAN_VMALLOC support
In-Reply-To: <bdef5309-03dd-6c0b-7d0c-9dd036ceae95@ghiti.fr>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  nylon7@andestech.com, nickhu@andestech.com, aryabinin@virtuozzo.com, glider@google.com,
  dvyukov@google.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-ea9a6037-0f18-41d5-8c01-6c16b14b6a63@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b="JioBCib/";       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Wed, 24 Feb 2021 23:48:13 PST (-0800), alex@ghiti.fr wrote:
> Le 2/25/21 =C3=A0 2:42 AM, Alexandre Ghiti a =C3=A9crit=C2=A0:
>> Populate the top-level of the kernel page table to implement KASAN_VMALL=
OC,
>> lower levels are filled dynamically upon memory allocation at runtime.
>>
>> Co-developed-by: Nylon Chen <nylon7@andestech.com>
>> Signed-off-by: Nylon Chen <nylon7@andestech.com>
>> Co-developed-by: Nick Hu <nickhu@andestech.com>
>> Signed-off-by: Nick Hu <nickhu@andestech.com>
>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>> ---
>>   arch/riscv/Kconfig         |  1 +
>>   arch/riscv/mm/kasan_init.c | 35 ++++++++++++++++++++++++++++++++++-
>>   2 files changed, 35 insertions(+), 1 deletion(-)
>>
>> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
>> index 8eadd1cbd524..3832a537c5d6 100644
>> --- a/arch/riscv/Kconfig
>> +++ b/arch/riscv/Kconfig
>> @@ -57,6 +57,7 @@ config RISCV
>>   	select HAVE_ARCH_JUMP_LABEL
>>   	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>   	select HAVE_ARCH_KASAN if MMU && 64BIT
>> +	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>>   	select HAVE_ARCH_KGDB
>>   	select HAVE_ARCH_KGDB_QXFER_PKT
>>   	select HAVE_ARCH_MMAP_RND_BITS if MMU
>> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
>> index 719b6e4d6075..171569df4334 100644
>> --- a/arch/riscv/mm/kasan_init.c
>> +++ b/arch/riscv/mm/kasan_init.c
>> @@ -142,6 +142,31 @@ static void __init kasan_populate(void *start, void=
 *end)
>>   	memset(start, KASAN_SHADOW_INIT, end - start);
>>   }
>>
>> +void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned lo=
ng end)
>> +{
>> +	unsigned long next;
>> +	void *p;
>> +	pgd_t *pgd_k =3D pgd_offset_k(vaddr);
>> +
>> +	do {
>> +		next =3D pgd_addr_end(vaddr, end);
>> +		if (pgd_page_vaddr(*pgd_k) =3D=3D (unsigned long)lm_alias(kasan_early=
_shadow_pmd)) {
>> +			p =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>> +			set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
>> +		}
>> +	} while (pgd_k++, vaddr =3D next, vaddr !=3D end);
>> +}
>> +
>> +void __init kasan_shallow_populate(void *start, void *end)
>> +{
>> +	unsigned long vaddr =3D (unsigned long)start & PAGE_MASK;
>> +	unsigned long vend =3D PAGE_ALIGN((unsigned long)end);
>> +
>> +	kasan_shallow_populate_pgd(vaddr, vend);
>> +
>> +	local_flush_tlb_all();
>> +}
>> +
>>   void __init kasan_init(void)
>>   {
>>   	phys_addr_t _start, _end;
>> @@ -149,7 +174,15 @@ void __init kasan_init(void)
>>
>>   	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
>>   				    (void *)kasan_mem_to_shadow((void *)
>> -								VMALLOC_END));
>> +								VMEMMAP_END));
>> +	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
>> +		kasan_shallow_populate(
>> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
>> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
>> +	else
>> +		kasan_populate_early_shadow(
>> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
>> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
>>
>>   	for_each_mem_range(i, &_start, &_end) {
>>   		void *start =3D (void *)_start;
>>
>
> Palmer, this commit should replace (if everyone agrees) Nylon and Nick's
> Commit e178d670f251 ("riscv/kasan: add KASAN_VMALLOC support") that is
> already in for-next.

Sorry, but it's way too late to be rebasing things.  I can get trying to ha=
ve
the history clean, but in this case we're better off having this as an expl=
icit
fix patch -- changing hashes this late in the process messes with all the
testing.

I'm not sure what the issue actually is, so it'd be great if you could send=
 the
fix patch.  If not then LMK and I'll try to figure out what's going on.  Ei=
ther
way, having the fix will make sure this gets tested properly as whatever's
going on isn't failing for me.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-ea9a6037-0f18-41d5-8c01-6c16b14b6a63%40palmerdabbelt-glaptop=
.
