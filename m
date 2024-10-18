Return-Path: <kasan-dev+bncBAABBKOCY64AMGQE4PSFE3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id BECA39A33B2
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 06:16:45 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-288c2f6697bsf1117077fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 21:16:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729225001; cv=pass;
        d=google.com; s=arc-20240605;
        b=LTSqTAeAi/UEzEGfomh8WHV+Ltgne8tYYZ75d3+GQGGNQ1BqBbilXTpcxILFjVbJ5T
         VjdAy9VhSm653EgbuIZJ4e+hiR7umG4xjW+NN0M8kRFcqEQYLTxmjUFhcEQCZiMwTde3
         s0XcRnxvGMsr7NWi2fX+gOBgs1H6uo5dX2MChmLyJjy7T6Uh0PN5Ibxi6pTWqnBx1A5Q
         AZ+vUh+ioGa0N0c9vnvS04ByVu8C7rdSnpiWNziMuE9qq84CEYmjLjRkKB8SZohmPbas
         BCU2aTQCpgBGalw6RGB9ZHdpoQXkXuw1iQCZx0b2mnWlYi+Z2ux+eXfRVFtESt06z7bh
         /zGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=d2R011gUlxVWO07jKqvrVsdL4TW1xANY9NWKYfwOfkI=;
        fh=mpuZwSn5ht3LhnMeYze5V3wLLBbgTJTwKuEJPYc7nes=;
        b=PYshRqbbWOuB1k1IBBG67Ce4cNgYFap7G/uvEjKRq/uhWaA8ZJ34zkUl88hJH8NhqH
         Iw/HXOmlX0W5mugh9hA4XHuAECIOZNUcuA03w7rnlhTo7TavuXdEG8FbDwWo8RPCcqfK
         9tDUT6WUzAtnKSgY9g/gfxblVyOnb0dMGqnp8iuh21q3pJeA8/RMTSY+Q/2S3OsKIBoj
         beqA8BqVC9mZt855AsMdJKwuUuxZDXOF5qB62q5LQjQz20BmTm8W/46cJYnmh9bd+77Y
         4mbiBceodsPDJFZOxeIis0pg5W+QWHksGZdyCHfDUW1qhlBoXK4XXSOvPfRrOlmxKerk
         MHzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729225001; x=1729829801; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=d2R011gUlxVWO07jKqvrVsdL4TW1xANY9NWKYfwOfkI=;
        b=nc/A6uvJMxa/9XXScp4f6CdAeWQlyMOMahNrpxFiQskn6wekQ/QAVBIwDD1iAEa10K
         jJLD0qC4ANMYb/jdh5vahlINrC2zAzlwQK9HMb7yPFmjTbJ7pqyOcp0rrle5xxlsgkgj
         prrlB8E7xeLqY2fduD4yaP5a4ZWaizvUx03whFXeMjubWnVQfRVttGLg+OLJeyv5+qdf
         xVouRi83s0xBmowhw90+9Gz48Ju1vAE8wo5T7eKLNXDNVoinzXwHylWJkTlVNhJh4HyZ
         LIWUxmKQiDhvKrClm/fls3Dq+7nKdnVzWM6nWmOhRygzcNY1ZYFkFAkwqNPuj8/JsI3D
         s/QQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729225001; x=1729829801;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d2R011gUlxVWO07jKqvrVsdL4TW1xANY9NWKYfwOfkI=;
        b=UKaDB3XOiS3GEB/jDcOgGrU8sZPaPpTLjLJ17TlK16EFQKJvxcTZmJHVXAE0gpsGmb
         3uhh1WvgihhZt3LgD6UtPS8msNzSNF4rR4fEOnyy2+/Zl6ztYgyJbFs+2eSKABplfGWu
         qzO8lE22v3w2kZOn1YCkNjATtqqNshbQAXiUa06py7J9NR9XW2hoq1YEmKcv8wMilGG0
         EWW1SZL6UytAQXOPL/HMwb/rxJH1eZT8FCThFH4DE6AmR5WdPLH+gXl+v9xZWKjyEyrD
         JAzTQOfgUodnT/wJJq+Sg7pDSQ0oQk23YC1180xtJvfysaJOhcxvWMFahGFtw/ZKHF4m
         0zgg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1NwaN11DJ2+KbJEUGTaU9x/EP352tR8ba0Yog01FsJa+5p+5IsnZK49eK1Li0fe1V/lQLzg==@lfdr.de
X-Gm-Message-State: AOJu0Yz11dW3rGwZ4FqBQaaQwXmCTOySAY/xFo/H2Woq7qaFjFWvza8Z
	A0bGIdr1HidXyEjDgSjUmrq5wMMOdnwQLCPRNa9h75Rn5SSgqahY
X-Google-Smtp-Source: AGHT+IGZMauoSAObrMKz9J7cwnre3DkErX4kRP764m2wvHBV/FTFg8DrCVhrWHpCO5eCZClvH1WGcg==
X-Received: by 2002:a05:6870:9126:b0:268:9f88:18ef with SMTP id 586e51a60fabf-2892c2cb210mr1040894fac.13.1729225001622;
        Thu, 17 Oct 2024 21:16:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:b81:b0:71e:5962:e291 with SMTP id
 d2e1a72fcca58-71e8fd5df34ls1638935b3a.2.-pod-prod-08-us; Thu, 17 Oct 2024
 21:16:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVU7ZwHVhedjmlsyWhQp3dV0YIDuhaUpg+WJuov5w/HNAfROQLUuWB1k79gZ4USB9n6QQfF7BbGAAE=@googlegroups.com
X-Received: by 2002:a05:6a21:3a94:b0:1d8:b11e:19b9 with SMTP id adf61e73a8af0-1d92c57df1dmr1986560637.47.1729225000403;
        Thu, 17 Oct 2024 21:16:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729225000; cv=none;
        d=google.com; s=arc-20240605;
        b=Nlf6QuRuFvYdb88GjdDjWj156Y4fjmxRMiNVHPwp6qnCvdXmXOfO1eG4SHmTlJAmCA
         3BVdKkSmmRqWyR98pSHes4cVy3LU10tWyW2NLFHpE0Pe+1kxKREtRnOrEKu7/DHK+mvU
         9karwG9qLDkY0tKpzl2UsCinrAjnsrPilf+IkdwvdAUQUlsZzYGVNxUMPSgZSRPT4PF3
         7poGJU61Moa2DK+jVbVVWgyaIaVLRd6xAwZHLzXMnn1rw5QO4PHrvSVXZST6AAbAr+s0
         eiG+Cf9NxB1/FTp6vVDYzbzfCJj26zUnFoCEZxbkHgPFRr4w0pFjzjSdyuSGgfezELh6
         UMtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=WP6P+IuTJcpjgkSRKRPTSezlMceIv/n3G8809khThsY=;
        fh=ocVjpFH1JzmNVfR49Byi2MWYGiGWER7Q25i+GX3k5Kg=;
        b=Rn1awRC+u3fYNNHrCdWCZWm55TglU6ufcf0hSyuFrLiAyFdTI+KX08IBhIXshKoqmS
         7eELu0CPWkbkxIBkF7D8YMp/NnGe423cJqlWI0Xd1F+IPiirb+jgYQ5BVZoCYFI1hwtL
         ltllH9WXM+YdIPZeBLO6QEkievU6sSQoZm00a7ubRikz7VFQ0etGGlwqPt05UMUgFlF7
         BMg9sO74A8F27X20yNFDQof5yCgOFMAnmD/8fuV2w0aujr/FIaywFQZr6yUsgLR+yW0U
         PdaQN1sWmgRv2PTaNxg9EwrAwILm18yv6M0qUq6PWkp8SqkRJKmom5MP856dJLAt/Xor
         cSVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-20e5a7524easi287015ad.1.2024.10.17.21.16.39
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Oct 2024 21:16:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.20.42.62])
	by gateway (Coremail) with SMTP id _____8AxDOsX4RFnwFEjAA--.52658S3;
	Fri, 18 Oct 2024 12:16:23 +0800 (CST)
Received: from [10.20.42.62] (unknown [10.20.42.62])
	by front1 (Coremail) with SMTP id qMiowMAxQNYU4RFnDmcvAA--.23651S3;
	Fri, 18 Oct 2024 12:16:20 +0800 (CST)
Subject: Re: [PATCH v2 1/3] LoongArch: Set initial pte entry with PAGE_GLOBAL
 for kernel space
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20241014035855.1119220-1-maobibo@loongson.cn>
 <20241014035855.1119220-2-maobibo@loongson.cn>
 <CAAhV-H5QkULWp6fciR1Lnds0r00fUdrmj86K_wBuxd0D=RkaXQ@mail.gmail.com>
 <f3089991-fd49-8d55-9ede-62ab1555c9fa@loongson.cn>
 <CAAhV-H7yX6qinPL5E5tmNVpJk_xdKqFaSicUYy2k8NGM1owucw@mail.gmail.com>
From: maobibo <maobibo@loongson.cn>
Message-ID: <a4c6b89e-4ffe-4486-4ccd-7ebc28734f6f@loongson.cn>
Date: Fri, 18 Oct 2024 12:16:01 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAAhV-H7yX6qinPL5E5tmNVpJk_xdKqFaSicUYy2k8NGM1owucw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qMiowMAxQNYU4RFnDmcvAA--.23651S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBj93XoW3try5ZFWrur17Jr4UuF4DGFX_yoWDWr47pr
	9rCF1kuF4UXrnrJwsFqwn0vrnFqwn7KF42gFnrKF1rAF9FgFnrXr1UJry3uFy8A3y8Ga40
	vr4rKa4agF1Ut3cCm3ZEXasCq-sJn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUU9Sb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r106r15M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Jr0_JF4l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Jr0_Gr1l84ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVCY1x0267AK
	xVW8Jr0_Cr1UM2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx
	1l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv
	67AKxVW8JVWxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lc7I2V7IY0VAS07
	AlzVAYIcxG8wCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwCFI7km07C2
	67AKxVWUAVWUtwC20s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI
	8E67AF67kF1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWU
	CwCI42IY6xIIjxv20xvEc7CjxVAFwI0_Jr0_Gr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r
	1xMIIF0xvEx4A2jsIE14v26r4j6F4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBI
	daVFxhVjvjDU0xZFpf9x07jOF4_UUUUU=
X-Original-Sender: maobibo@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=maobibo@loongson.cn
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



On 2024/10/18 =E4=B8=8B=E5=8D=8812:11, Huacai Chen wrote:
> On Fri, Oct 18, 2024 at 11:44=E2=80=AFAM maobibo <maobibo@loongson.cn> wr=
ote:
>>
>>
>>
>> On 2024/10/18 =E4=B8=8A=E5=8D=8811:14, Huacai Chen wrote:
>>> Hi, Bibo,
>>>
>>> I applied this patch but drop the part of arch/loongarch/mm/kasan_init.=
c:
>>> https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-loongs=
on.git/commit/?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70ced50afc40=
3067
>>>
>>> Because kernel_pte_init() should operate on page-table pages, not on
>>> data pages. You have already handle page-table page in
>>> mm/kasan/init.c, and if we don't drop the modification on data pages
>>> in arch/loongarch/mm/kasan_init.c, the kernel fail to boot if KASAN is
>>> enabled.
>>>
>> static inline void set_pte(pte_t *ptep, pte_t pteval)
>>    {
>>          WRITE_ONCE(*ptep, pteval);
>> -
>> -       if (pte_val(pteval) & _PAGE_GLOBAL) {
>> -               pte_t *buddy =3D ptep_buddy(ptep);
>> -               /*
>> -                * Make sure the buddy is global too (if it's !none,
>> -                * it better already be global)
>> -                */
>> -               if (pte_none(ptep_get(buddy))) {
>> -#ifdef CONFIG_SMP
>> -                       /*
>> -                        * For SMP, multiple CPUs can race, so we need
>> -                        * to do this atomically.
>> -                        */
>> -                       __asm__ __volatile__(
>> -                       __AMOR "$zero, %[global], %[buddy] \n"
>> -                       : [buddy] "+ZB" (buddy->pte)
>> -                       : [global] "r" (_PAGE_GLOBAL)
>> -                       : "memory");
>> -
>> -                       DBAR(0b11000); /* o_wrw =3D 0b11000 */
>> -#else /* !CONFIG_SMP */
>> -                       WRITE_ONCE(*buddy, __pte(pte_val(ptep_get(buddy)=
) | _PAGE_GLOBAL));
>> -#endif /* CONFIG_SMP */
>> -               }
>> -       }
>> +       DBAR(0b11000); /* o_wrw =3D 0b11000 */
>>    }
>>
>> No, please hold on. This issue exists about twenty years, Do we need be
>> in such a hurry now?
>>
>> why is DBAR(0b11000) added in set_pte()?
> It exists before, not added by this patch. The reason is explained in
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit=
/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
why speculative accesses may cause spurious page fault in kernel space=20
with PTE enabled?  speculative accesses exists anywhere, it does not=20
cause spurious page fault.

Obvious you do not it and you write wrong patch.

>=20
> Huacai
>=20
>>
>> Regards
>> Bibo Mao
>>> Huacai
>>>
>>> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.cn>=
 wrote:
>>>>
>>>> Unlike general architectures, there are two pages in one TLB entry
>>>> on LoongArch system. For kernel space, it requires both two pte
>>>> entries with PAGE_GLOBAL bit set, else HW treats it as non-global
>>>> tlb, there will be potential problems if tlb entry for kernel space
>>>> is not global. Such as fail to flush kernel tlb with function
>>>> local_flush_tlb_kernel_range() which only flush tlb with global bit.
>>>>
>>>> With function kernel_pte_init() added, it can be used to init pte
>>>> table when it is created for kernel address space, and the default
>>>> initial pte value is PAGE_GLOBAL rather than zero at beginning.
>>>>
>>>> Kernel address space areas includes fixmap, percpu, vmalloc, kasan
>>>> and vmemmap areas set default pte entry with PAGE_GLOBAL set.
>>>>
>>>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
>>>> ---
>>>>    arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
>>>>    arch/loongarch/include/asm/pgtable.h |  1 +
>>>>    arch/loongarch/mm/init.c             |  4 +++-
>>>>    arch/loongarch/mm/kasan_init.c       |  4 +++-
>>>>    arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++++++++
>>>>    include/linux/mm.h                   |  1 +
>>>>    mm/kasan/init.c                      |  8 +++++++-
>>>>    mm/sparse-vmemmap.c                  |  5 +++++
>>>>    8 files changed, 55 insertions(+), 3 deletions(-)
>>>>
>>>> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongarch/inc=
lude/asm/pgalloc.h
>>>> index 4e2d6b7ca2ee..b2698c03dc2c 100644
>>>> --- a/arch/loongarch/include/asm/pgalloc.h
>>>> +++ b/arch/loongarch/include/asm/pgalloc.h
>>>> @@ -10,8 +10,21 @@
>>>>
>>>>    #define __HAVE_ARCH_PMD_ALLOC_ONE
>>>>    #define __HAVE_ARCH_PUD_ALLOC_ONE
>>>> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
>>>>    #include <asm-generic/pgalloc.h>
>>>>
>>>> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
>>>> +{
>>>> +       pte_t *pte;
>>>> +
>>>> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
>>>> +       if (!pte)
>>>> +               return NULL;
>>>> +
>>>> +       kernel_pte_init(pte);
>>>> +       return pte;
>>>> +}
>>>> +
>>>>    static inline void pmd_populate_kernel(struct mm_struct *mm,
>>>>                                          pmd_t *pmd, pte_t *pte)
>>>>    {
>>>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/inc=
lude/asm/pgtable.h
>>>> index 9965f52ef65b..22e3a8f96213 100644
>>>> --- a/arch/loongarch/include/asm/pgtable.h
>>>> +++ b/arch/loongarch/include/asm/pgtable.h
>>>> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm, unsig=
ned long addr, pmd_t *pmdp, pm
>>>>    extern void pgd_init(void *addr);
>>>>    extern void pud_init(void *addr);
>>>>    extern void pmd_init(void *addr);
>>>> +extern void kernel_pte_init(void *addr);
>>>>
>>>>    /*
>>>>     * Encode/decode swap entries and swap PTEs. Swap PTEs are all PTEs=
 that
>>>> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
>>>> index 8a87a482c8f4..9f26e933a8a3 100644
>>>> --- a/arch/loongarch/mm/init.c
>>>> +++ b/arch/loongarch/mm/init.c
>>>> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned long =
addr)
>>>>           if (!pmd_present(pmdp_get(pmd))) {
>>>>                   pte_t *pte;
>>>>
>>>> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>>>> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE);
>>>>                   if (!pte)
>>>>                           panic("%s: Failed to allocate memory\n", __f=
unc__);
>>>> +
>>>> +               kernel_pte_init(pte);
>>>>                   pmd_populate_kernel(&init_mm, pmd, pte);
>>>>           }
>>>>
>>>> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_=
init.c
>>>> index 427d6b1aec09..34988573b0d5 100644
>>>> --- a/arch/loongarch/mm/kasan_init.c
>>>> +++ b/arch/loongarch/mm/kasan_init.c
>>>> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t *pmdp,=
 unsigned long addr,
>>>>                   phys_addr_t page_phys =3D early ?
>>>>                                           __pa_symbol(kasan_early_shad=
ow_page)
>>>>                                                 : kasan_alloc_zeroed_p=
age(node);
>>>> +               if (!early)
>>>> +                       kernel_pte_init(__va(page_phys));
>>>>                   next =3D addr + PAGE_SIZE;
>>>>                   set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), PAGE=
_KERNEL));
>>>>           } while (ptep++, addr =3D next, addr !=3D end && __pte_none(=
early, ptep_get(ptep)));
>>>> @@ -287,7 +289,7 @@ void __init kasan_init(void)
>>>>                   set_pte(&kasan_early_shadow_pte[i],
>>>>                           pfn_pte(__phys_to_pfn(__pa_symbol(kasan_earl=
y_shadow_page)), PAGE_KERNEL_RO));
>>>>
>>>> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>>>> +       kernel_pte_init(kasan_early_shadow_page);
>>>>           csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH)=
;
>>>>           local_flush_tlb_all();
>>>>
>>>> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
>>>> index eb6a29b491a7..228ffc1db0a3 100644
>>>> --- a/arch/loongarch/mm/pgtable.c
>>>> +++ b/arch/loongarch/mm/pgtable.c
>>>> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
>>>>    }
>>>>    EXPORT_SYMBOL_GPL(pgd_alloc);
>>>>
>>>> +void kernel_pte_init(void *addr)
>>>> +{
>>>> +       unsigned long *p, *end;
>>>> +       unsigned long entry;
>>>> +
>>>> +       entry =3D (unsigned long)_PAGE_GLOBAL;
>>>> +       p =3D (unsigned long *)addr;
>>>> +       end =3D p + PTRS_PER_PTE;
>>>> +
>>>> +       do {
>>>> +               p[0] =3D entry;
>>>> +               p[1] =3D entry;
>>>> +               p[2] =3D entry;
>>>> +               p[3] =3D entry;
>>>> +               p[4] =3D entry;
>>>> +               p +=3D 8;
>>>> +               p[-3] =3D entry;
>>>> +               p[-2] =3D entry;
>>>> +               p[-1] =3D entry;
>>>> +       } while (p !=3D end);
>>>> +}
>>>> +
>>>>    void pgd_init(void *addr)
>>>>    {
>>>>           unsigned long *p, *end;
>>>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>>>> index ecf63d2b0582..6909fe059a2c 100644
>>>> --- a/include/linux/mm.h
>>>> +++ b/include/linux/mm.h
>>>> @@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long size);
>>>>    struct page * __populate_section_memmap(unsigned long pfn,
>>>>                   unsigned long nr_pages, int nid, struct vmem_altmap =
*altmap,
>>>>                   struct dev_pagemap *pgmap);
>>>> +void kernel_pte_init(void *addr);
>>>>    void pmd_init(void *addr);
>>>>    void pud_init(void *addr);
>>>>    pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>>> index 89895f38f722..ac607c306292 100644
>>>> --- a/mm/kasan/init.c
>>>> +++ b/mm/kasan/init.c
>>>> @@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t *pmd, u=
nsigned long addr,
>>>>           }
>>>>    }
>>>>
>>>> +void __weak __meminit kernel_pte_init(void *addr)
>>>> +{
>>>> +}
>>>> +
>>>>    static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
>>>>                                   unsigned long end)
>>>>    {
>>>> @@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t *pud, un=
signed long addr,
>>>>
>>>>                           if (slab_is_available())
>>>>                                   p =3D pte_alloc_one_kernel(&init_mm)=
;
>>>> -                       else
>>>> +                       else {
>>>>                                   p =3D early_alloc(PAGE_SIZE, NUMA_NO=
_NODE);
>>>> +                               kernel_pte_init(p);
>>>> +                       }
>>>>                           if (!p)
>>>>                                   return -ENOMEM;
>>>>
>>>> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
>>>> index edcc7a6b0f6f..c0388b2e959d 100644
>>>> --- a/mm/sparse-vmemmap.c
>>>> +++ b/mm/sparse-vmemmap.c
>>>> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block_zero(=
unsigned long size, int node)
>>>>           return p;
>>>>    }
>>>>
>>>> +void __weak __meminit kernel_pte_init(void *addr)
>>>> +{
>>>> +}
>>>> +
>>>>    pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long ad=
dr, int node)
>>>>    {
>>>>           pmd_t *pmd =3D pmd_offset(pud, addr);
>>>> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud,=
 unsigned long addr, int node)
>>>>                   void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE, node=
);
>>>>                   if (!p)
>>>>                           return NULL;
>>>> +               kernel_pte_init(p);
>>>>                   pmd_populate_kernel(&init_mm, pmd, p);
>>>>           }
>>>>           return pmd;
>>>> --
>>>> 2.39.3
>>>>
>>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a4c6b89e-4ffe-4486-4ccd-7ebc28734f6f%40loongson.cn.
