Return-Path: <kasan-dev+bncBAABBHGDU64AMGQE7IHPKXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id F10CA99B02A
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 04:40:31 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-71e01bfe040sf3053658b3a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 19:40:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728700829; cv=pass;
        d=google.com; s=arc-20240605;
        b=SKiEgWBSb1iZI/5TDWd7UJBggWVGVY9fW/hmnuBhPd2o2JKN4LGBg67g+UKz9gd+qR
         YjJJ9ZWhwSasiJWGppYjfSmI7kggvUH5Ma2jiZVdrdXr2QoxQEdn1Pyy7moqR3fm8hqw
         i1W1vOTN6rI6mL9OvX791+XjIqW4D0xRZZk2RSgLSitQgST5InLEVRWdYFh5AuLtylL9
         Ulok973b0KqEm/og2EbnHYBxKR2ppG5x2BiHva00Ch75epsxRNsCcPRpUxi9DZrbRDr9
         stsZeAFAJZ80vAaB8MZuCiHQWJRvTphSroaq3D2eeENus9GA6CbNu1o8F24+thF255EM
         kRXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=z29ZQHFsVr4nvhLMidkDhiDG7Ki/5ofljztftQMSoms=;
        fh=8oIMDQvn0IPSqMCoAOeyNmGsM+p2pJ6vlHxkTm9zXKI=;
        b=kc7eOUWoIGv1RXrrOwWBdqrJoUiU4vwAYJzYl1bQwfitMeVhdp5wku1oFCclyQCum1
         eT/otL8kz7d57GONznq/qyFHFFK893bctotsZvSDT1CKtyMIgWID7LVJIoyEC+4xVT3M
         ShAyWDg/AI0d5Rs86M/JdM2VAgXVI/44FNIucNDz4bJtjeJ32hRzD9f/p9K7Uxu9oZXz
         tettQXxkb2busdFQ9TtXEWdWuw9s7sazVjYxT+FRcDnRoARSpORV82GJiI0jzHuUDAeN
         oTnrSin0C4ZbYxydvj+3h+UbuXFkGX6PZP3wE4MFDLf+NAX3Xl3ZxyNFDhK4OzZ47sfc
         gWig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728700829; x=1729305629; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=z29ZQHFsVr4nvhLMidkDhiDG7Ki/5ofljztftQMSoms=;
        b=gUUj+/JN2bcz83XYgP0imeozwDioybc3eym9rBr08h1ujbbYYwrR+vK5Ful9FAQHFm
         DTOKJfDo4ZCVipVNnGOcDNkX7tXODJkwU/f+NCkBveKrmSPTGIn2IcjJ0l9OaciZ3B4x
         8/q3sYTnbMATU7tMjrjWs5CCi0dzBuf0U5ADHzYI+eYXMw/Gf2ficF6ETxxbX8/VCnyH
         PYfO4ra44c/GAQDV15KJ/A9Vg3r6LOIBXBMR9cGI9Hd9krqFfAq0xuYd/749hBe3Pos0
         2rpO4Vw/xTGPcIQqSfoFOaTbGjJkX0Ip+oQVfJkUsa5SunNWosdBSzW6+tFaM4/qpwmM
         UzKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728700829; x=1729305629;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z29ZQHFsVr4nvhLMidkDhiDG7Ki/5ofljztftQMSoms=;
        b=JsMnjRCFmrz7CAU8iEkRc9PkOjyJmCdXr5cKsXDpbieIac6/IzefVmrGMgZRCq4uKp
         sCfLGGPYVvOnl1ziDCqB/1A5y1/cUJTPF9iVt43pfUCYTESChjwvQpAtaM3Pz9H2iSag
         7bXLHQiwyrJewzx6NFl+UMshfcBedBNy6Wt95ruZCAyw4YLmwX65Ex5uVmkMb2+xZaka
         0Pi1Wtuf28EbJZ7OwUavOer2+W4vU0yqtgSnfN7oI4qmG30/I2sE1szUxhjLH6gRTYf3
         SK7lBx9XCj8H2WS3gW5JgHVKf8QESJpAh4rLeUVjw9J0Sy/2p8v0yQrXpgYPPvYf+0hu
         bSMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX4ltDc7+1CoWjahh8nb1wln3Wkb3iO9eyGqpmpUTVIyJvLK/1mYubPyCaln1bFQFXS2dOKGw==@lfdr.de
X-Gm-Message-State: AOJu0YyckHZoYCcmk+uN4tHEsx9QAiESqEw5A+41lUYmmXHMGREuM5j8
	x7MSK3+aVTiGf4kAAG90EjwSi03NFailrfJS/j/gb/2YO3DPn3uo
X-Google-Smtp-Source: AGHT+IGHxDvBt0CEyJCu+VHFhV1T++bW7uzh9E78wahI+REmBPBIOYKC64UbEBfLFbtPSwc+D2ojgw==
X-Received: by 2002:a05:6a00:4b12:b0:71d:fe64:e3fe with SMTP id d2e1a72fcca58-71e38098a52mr7203572b3a.19.1728700828805;
        Fri, 11 Oct 2024 19:40:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:138a:b0:71e:1fb8:5f36 with SMTP id
 d2e1a72fcca58-71e270ae6cfls2373217b3a.2.-pod-prod-03-us; Fri, 11 Oct 2024
 19:40:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWP3kkCkIbMJ8J/IX6X4v9T61k1Gpy7zfqTR6SXdbhY6+HrIusQ4DZyGkc28jWOjiMELm/0nsQY484=@googlegroups.com
X-Received: by 2002:a05:6a21:4a4c:b0:1d5:a29:3173 with SMTP id adf61e73a8af0-1d8bcf41208mr6048827637.24.1728700827815;
        Fri, 11 Oct 2024 19:40:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728700827; cv=none;
        d=google.com; s=arc-20240605;
        b=A+BsBRsLXtpnVV4wonReDV3SmvNQB1KKDDcglla0s3IrYsdGqPiMnxil0tlZj8hmQJ
         XzMYA6ByWnsgGEbKc0fEp9woRh+vwPh6SZlpsShxuRZGRnrBYtHWfq0XtEKvlIPLL2sS
         S7j5vHn5qes7USGwjVe/L66cnn6tsfbtHCrhsixfPu8aJyx7FjJrp0XAlHWPkCML5LKe
         UaIerz4v83GA7+T7Qcg7R51P9er50TWvUqN9Iq9uPNSuC5OTBCwUtjuZ2rhNWwSFo0Du
         5Nb7XJwCSrtuerD3Yiu4HloKVYUxKs+acCheBwmrNoZ7if4PWLjlbh/dObjwEDUvvF2S
         esSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=H7mMbSfNJgTzy1idiofQAFjU5REtPnuTZBXvPYcneog=;
        fh=ocVjpFH1JzmNVfR49Byi2MWYGiGWER7Q25i+GX3k5Kg=;
        b=BIqjZJxskEVJ8yi8FK0dOMDysnYi5Riazhyo/6JFuP0bGdP/hFPj5Zm7Dn11Y+qM6A
         GLYELY0N0vizDtOx049KO2GmF5UxgiCat578t5dE5Ux+/V2oGdlu8mGIfCZBGaBSMHh7
         6lMGxOIv1Lwd6USa18r+qr5QgPI+XafmceEwG0piNLHucgI6nbc9sXe1Q8sgjJXZVySl
         UtqmlVORMVyKkBiqRMsWLR1VK70qxKsbe3k25XnA+wG6pHwi572CHa0Buc56XFH/zyeQ
         CJl0RmRV6KdGMWDEZm8rLp69PDTw5gprSRwD4ERK6OEAiyFfCam0HUd4KmRHxMJTwh7C
         o+Nw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id d2e1a72fcca58-71e2ab7ffa7si215344b3a.3.2024.10.11.19.40.26
        for <kasan-dev@googlegroups.com>;
        Fri, 11 Oct 2024 19:40:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.20.42.62])
	by gateway (Coremail) with SMTP id _____8DxNOmY4QlnPWgUAA--.29899S3;
	Sat, 12 Oct 2024 10:40:24 +0800 (CST)
Received: from [10.20.42.62] (unknown [10.20.42.62])
	by front1 (Coremail) with SMTP id qMiowMBxXuSV4QlnS54kAA--.51895S3;
	Sat, 12 Oct 2024 10:40:23 +0800 (CST)
Subject: Re: [PATCH 1/4] LoongArch: Set pte entry with PAGE_GLOBAL for kernel
 space
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20241010035048.3422527-1-maobibo@loongson.cn>
 <20241010035048.3422527-2-maobibo@loongson.cn>
 <CAAhV-H4q_P1HL74k5k+er9QEvZjMaa2kTYz8N+7aJ1vDii=GKQ@mail.gmail.com>
From: maobibo <maobibo@loongson.cn>
Message-ID: <56c7ae02-1426-b503-9afa-5a87a2b4bd21@loongson.cn>
Date: Sat, 12 Oct 2024 10:40:03 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAAhV-H4q_P1HL74k5k+er9QEvZjMaa2kTYz8N+7aJ1vDii=GKQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qMiowMBxXuSV4QlnS54kAA--.51895S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBj93XoW3XryDZrW3Cr4kCr48Kw1UCFX_yoW7ZrWDpr
	9rAFn5WF48Wr97Aa97tF1qgr15Xws3KF42gF1akFWrAFnF9r1kWr1kG3sxuFy8XayUCayF
	9r1rKa43XF4UtagCm3ZEXasCq-sJn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUUv0b4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Jr0_JF4l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Jr0_Gr1l84ACjcxK6I8E87Iv67AKxVW8JVWxJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_
	Gr0_Gr1UM2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx1l5I
	8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv67AK
	xVWUJVW8JwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lc7I2V7IY0VAS07AlzV
	AYIcxG8wCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E
	14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw0_GFylIx
	kGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv20xvEc7CjxVAF
	wI0_Jr0_Gr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r1j6r
	4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Jr0_GrUvcSsGvfC2KfnxnUUI43ZEXa7IU1CPfJUU
	UUU==
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

Huacai,

On 2024/10/12 =E4=B8=8A=E5=8D=8810:15, Huacai Chen wrote:
> Hi, Bibo,
>=20
> On Thu, Oct 10, 2024 at 11:50=E2=80=AFAM Bibo Mao <maobibo@loongson.cn> w=
rote:
>>
>> Unlike general architectures, there are two pages for one TLB entry
>> on LoongArch system. For kernel space, it requires both two pte
>> entries with PAGE_GLOBAL set, else HW treats it as non-global tlb,
>> there will be potential problems if tlb entry for kernel space is
>> not global. Such as fail to flush kernel tlb with function
>> local_flush_tlb_kernel_range() which only flush tlb with global bit.
>>
>> Here function kernel_pte_init() is added, it can be used to init
>> pte table when it is created, so the default inital pte is
>> PAGE_GLOBAL rather than zero at beginning.
> I think kernel_pte_init() is also needed in zero_pmd_populate() in
> mm/kasan/init.c. And moreover, the second patch should be squashed in
yes, it is needed in zero_pmd_populate() in mm/kasan/init.c, will add it
in next version.

> this one because they should be as a whole. Though the second one
> touches the common code, I can merge it with mm maintainer's acked-by.
Sure, will merge it with the second one into one patch.

Regards
Bibo Mao
>=20
>=20
> Huacai
>=20
>>
>> Kernel space areas includes fixmap, percpu, vmalloc and kasan areas
>> set default pte entry with PAGE_GLOBAL set.
>>
>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
>> ---
>>   arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
>>   arch/loongarch/include/asm/pgtable.h |  1 +
>>   arch/loongarch/mm/init.c             |  4 +++-
>>   arch/loongarch/mm/kasan_init.c       |  4 +++-
>>   arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++++++++
>>   5 files changed, 42 insertions(+), 2 deletions(-)
>>
>> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongarch/inclu=
de/asm/pgalloc.h
>> index 4e2d6b7ca2ee..b2698c03dc2c 100644
>> --- a/arch/loongarch/include/asm/pgalloc.h
>> +++ b/arch/loongarch/include/asm/pgalloc.h
>> @@ -10,8 +10,21 @@
>>
>>   #define __HAVE_ARCH_PMD_ALLOC_ONE
>>   #define __HAVE_ARCH_PUD_ALLOC_ONE
>> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
>>   #include <asm-generic/pgalloc.h>
>>
>> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
>> +{
>> +       pte_t *pte;
>> +
>> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
>> +       if (!pte)
>> +               return NULL;
>> +
>> +       kernel_pte_init(pte);
>> +       return pte;
>> +}
>> +
>>   static inline void pmd_populate_kernel(struct mm_struct *mm,
>>                                         pmd_t *pmd, pte_t *pte)
>>   {
>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/inclu=
de/asm/pgtable.h
>> index 9965f52ef65b..22e3a8f96213 100644
>> --- a/arch/loongarch/include/asm/pgtable.h
>> +++ b/arch/loongarch/include/asm/pgtable.h
>> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm, unsigne=
d long addr, pmd_t *pmdp, pm
>>   extern void pgd_init(void *addr);
>>   extern void pud_init(void *addr);
>>   extern void pmd_init(void *addr);
>> +extern void kernel_pte_init(void *addr);
>>
>>   /*
>>    * Encode/decode swap entries and swap PTEs. Swap PTEs are all PTEs th=
at
>> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
>> index 8a87a482c8f4..9f26e933a8a3 100644
>> --- a/arch/loongarch/mm/init.c
>> +++ b/arch/loongarch/mm/init.c
>> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned long ad=
dr)
>>          if (!pmd_present(pmdp_get(pmd))) {
>>                  pte_t *pte;
>>
>> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE);
>>                  if (!pte)
>>                          panic("%s: Failed to allocate memory\n", __func=
__);
>> +
>> +               kernel_pte_init(pte);
>>                  pmd_populate_kernel(&init_mm, pmd, pte);
>>          }
>>
>> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_in=
it.c
>> index 427d6b1aec09..34988573b0d5 100644
>> --- a/arch/loongarch/mm/kasan_init.c
>> +++ b/arch/loongarch/mm/kasan_init.c
>> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t *pmdp, u=
nsigned long addr,
>>                  phys_addr_t page_phys =3D early ?
>>                                          __pa_symbol(kasan_early_shadow_=
page)
>>                                                : kasan_alloc_zeroed_page=
(node);
>> +               if (!early)
>> +                       kernel_pte_init(__va(page_phys));
>>                  next =3D addr + PAGE_SIZE;
>>                  set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), PAGE_KE=
RNEL));
>>          } while (ptep++, addr =3D next, addr !=3D end && __pte_none(ear=
ly, ptep_get(ptep)));
>> @@ -287,7 +289,7 @@ void __init kasan_init(void)
>>                  set_pte(&kasan_early_shadow_pte[i],
>>                          pfn_pte(__phys_to_pfn(__pa_symbol(kasan_early_s=
hadow_page)), PAGE_KERNEL_RO));
>>
>> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>> +       kernel_pte_init(kasan_early_shadow_page);
>>          csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH);
>>          local_flush_tlb_all();
>>
>> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
>> index eb6a29b491a7..228ffc1db0a3 100644
>> --- a/arch/loongarch/mm/pgtable.c
>> +++ b/arch/loongarch/mm/pgtable.c
>> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
>>   }
>>   EXPORT_SYMBOL_GPL(pgd_alloc);
>>
>> +void kernel_pte_init(void *addr)
>> +{
>> +       unsigned long *p, *end;
>> +       unsigned long entry;
>> +
>> +       entry =3D (unsigned long)_PAGE_GLOBAL;
>> +       p =3D (unsigned long *)addr;
>> +       end =3D p + PTRS_PER_PTE;
>> +
>> +       do {
>> +               p[0] =3D entry;
>> +               p[1] =3D entry;
>> +               p[2] =3D entry;
>> +               p[3] =3D entry;
>> +               p[4] =3D entry;
>> +               p +=3D 8;
>> +               p[-3] =3D entry;
>> +               p[-2] =3D entry;
>> +               p[-1] =3D entry;
>> +       } while (p !=3D end);
>> +}
>> +
>>   void pgd_init(void *addr)
>>   {
>>          unsigned long *p, *end;
>> --
>> 2.39.3
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/56c7ae02-1426-b503-9afa-5a87a2b4bd21%40loongson.cn.
