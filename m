Return-Path: <kasan-dev+bncBAABBQ5TY64AMGQELCXY54Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 611919A337B
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 05:45:09 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3a3c5b90293sf16389005ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 20:45:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729223108; cv=pass;
        d=google.com; s=arc-20240605;
        b=CihSo7+HhzPZ98qcDxiXNvY/gyx/wsaqjBkmnIWu4IxKA9vQ/ADM+SlXEIK/SARxFK
         RKrVaih2W+cDenIJz+yo+zU9iO6lPuNcXP7S6GbwxuOV+vygQXxoqtUzpSjfpI3Pj5xf
         8RvOiSJRnpxLR3QzPUEFJhF6LFuuCooE1TahfmBGrcl7Bt0pE4VLGQ/WNzlSfVgBL+wN
         JkjAyiBolQQ/MI4xa3XHrkIYqE3ykyoUg75+fHfsGbCy/IzTL6TpSGEZ37cHjbDGDSxC
         jVm4h2CrCXZSF67X99xR9Xw9yANLDyOE2/d3re7FaOYyWjTcKUHryILy0NBhPaZB24bz
         UsEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=P0RAwZNrZfNeJomi9gDpDIqq4MLhM0dqvX48dY/o988=;
        fh=FRN/BxVEnZfxsEG+PQFRyEXWr3pKZQtv1hwFe280etc=;
        b=KHnHh1qDq/aerfKmuUfIq6V0q2eiiDEsiPDBkhqYy10LxNQk4gDqQeImh7e8ccy6OH
         DD3SjzP2tz+FXbf1AdEyVfRK+k6gchsveWVxXtY3ac7G/X31ZHPCRqUr97AiVl8ggfdw
         M8ICStPoNM89TOkRPF8DgEbgBjWEZbyEGSkiZVY3K1FkovfBRNVI48veisErsLiBbxw/
         Utu2fQHKboLlR4AJgxy0rFrMbeBtTpKyk9sjtRfir+4P9zzot3Q6FP2Qe57uIl+IIiTp
         jfULZoI6kFgoJeSuxTPf7yChsjsCxBUZPta1lxfE0Sei7ALA2u9DmycxbqpsY9pIGF1t
         MLEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729223108; x=1729827908; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=P0RAwZNrZfNeJomi9gDpDIqq4MLhM0dqvX48dY/o988=;
        b=rJ1v+qOR7gkRncJgRfymb2DOixOyUtKivx701OE1l/l3VnMi6sFnHNFq+aJhLH2JvL
         LqAb2NOKp2nzuaPw9JxslsFgGv/jI/QURm74xQW/F1BTwqSWf536Jrw1D4gVUJuYEQet
         w1mN4h55K1Tpal9UHJmmt0IGJK7uVjix8HphDTMU2W5uuSfcq6Jl9Or48eggApXp7Pwf
         Q4jPxPaIcCcjqOnUYJFKX5gLVap9OThvbz3thrDuJaCqN4h3G8F9fihGn0+XjXPXD+u2
         E9hrc+7Rcc4tDy+Zinj9N745+QGmLfUFiC2aHp0/kn92Uv6b0ZesRda9zFv1A3VnrXBL
         IojA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729223108; x=1729827908;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=P0RAwZNrZfNeJomi9gDpDIqq4MLhM0dqvX48dY/o988=;
        b=Y1WfS/QKb8r5aFqtWMa1s5P5sDVX3M8ggd6/RsUI5WKNXiFe8f9X6I79VNLfBVgxwW
         Hf1zWJwUDLTwI3z7rxIip3laTb3fKMayxULlDA0STjQ49z1UlPATZLBwFhBH5/uYNRPI
         Bj+UVxiNxa5NTyUy0Duxugqoy1MQ/vjfefRZMovx7GDxiRQEXVEFdkXmyms4tNNjYepG
         clBa8uSuFhhqcVnCyJH17L/JfHwhGbfE2LmRbcIYC6yNL6dd+yQRNJdYZfroXzF91+Ic
         HII4CD/aMw2ewEn1PgBtTQ0ywFHXwFmwbQkw0pU+aiNSmLQiEPLN3qs2Sa5nQadn/59o
         m67g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3DJ0E1nnq0Klax+4uy34ElszJSRAckaInUZMZYyt3qTLsf53inFzjnGuxafHMwuzfBwg25w==@lfdr.de
X-Gm-Message-State: AOJu0YyUDGf3POZ3mwL9OUEnRIvFdJiIt0Tmsz9BCsQsIiyDeXb5+Ne3
	WxzjmWH/YZhJGVdorkkwcc5x5wzPkiHaA3d6cNyEmP5JX7sN/74W
X-Google-Smtp-Source: AGHT+IH6N5lccIw09QNjs29SBMAEkx/i1Tt6iIUclPfKjasid5+BcILwb+qQaGsgJqeNsz2yUmfGsw==
X-Received: by 2002:a05:6e02:1c29:b0:3a2:aed1:12a6 with SMTP id e9e14a558f8ab-3a3f4059d87mr9726705ab.6.1729223107872;
        Thu, 17 Oct 2024 20:45:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1e03:b0:3a2:7592:2bf with SMTP id
 e9e14a558f8ab-3a3e5061c61ls12205715ab.2.-pod-prod-03-us; Thu, 17 Oct 2024
 20:45:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUTXsN42q6/V3P3Rj/uLQIk98UGZzuE6UmAFCyJHgipQsh+kDODoYk1IEq9doG+R38/iYOkf+2cBEo=@googlegroups.com
X-Received: by 2002:a05:6e02:1caf:b0:3a3:778e:45cd with SMTP id e9e14a558f8ab-3a3f40b719fmr12095395ab.21.1729223107005;
        Thu, 17 Oct 2024 20:45:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729223106; cv=none;
        d=google.com; s=arc-20240605;
        b=KPz8Lk6GONHyu1iB2owfGafP1zpX105buieiQPf6GzSmF43hAA2WNtbGidp1L2CcTm
         j5ThpF1iBhFxD20opIy+rBREPrqynHs6fbLYYghkDkvP0ctJCJZiP0vesRZLiy69EeU7
         aERXaVPOpLK7R7kWyI8TVkAt1s3+apUcvTF8ioz0v9njfMO2cdp9gDHsZNAomMxZuvcg
         QlWCmkdIqsUHl5DjrGfL0FSMn+XCkqzLWAIObIsLgud4wMSYhaZg4nxvSWZ2Uih//P/J
         vt5QS7LQX+eWiaVkUWFOovkmXeZDv5NYvVGxoFpYBx7rDZBX+UJmvwFO9FsiWAL0EIg1
         MRFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=lTAxJwkGGKWR2096DeYAbEpsIZo7osRC19vJGemQ3W8=;
        fh=ocVjpFH1JzmNVfR49Byi2MWYGiGWER7Q25i+GX3k5Kg=;
        b=G3QsalCEAEGPWSlANNmei4LkxeQ2ENCEuiDiTDsKL2VJwic7lLlkChUPTdRkv4cnuw
         1x5DmWKAz1ZvlQVJoYGSIKX8fbdeOMINJZsBv8PGWztxDiMymCtILkmypPOCeds5QjmE
         pa/LTxOl3Q7ZAAmsc43CwZHG3h+nBID+zyTOfnpSIriGHei8BA3k5Fk9+RUx/clAnwQt
         eeNdbchdA/DfY9YI9UA3UUrJjGyPlw9hnf32jtkxtZ2io8uVAPjUl8oFLrQj75kD0l6b
         UtUfXVL8ZrNkRqxRUZt92M9DA5WoBwhJP/3quVBWEqeU7mVUkqXmNoDsHOMBFETzcfwX
         Qh/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 41be03b00d2f7-7eacc1efdb0si36056a12.2.2024.10.17.20.45.06
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Oct 2024 20:45:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.20.42.62])
	by gateway (Coremail) with SMTP id _____8Bx22qv2RFnZEwjAA--.51294S3;
	Fri, 18 Oct 2024 11:44:47 +0800 (CST)
Received: from [10.20.42.62] (unknown [10.20.42.62])
	by front1 (Coremail) with SMTP id qMiowMBxHeSn2RFnpmAvAA--.29241S3;
	Fri, 18 Oct 2024 11:44:41 +0800 (CST)
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
From: maobibo <maobibo@loongson.cn>
Message-ID: <f3089991-fd49-8d55-9ede-62ab1555c9fa@loongson.cn>
Date: Fri, 18 Oct 2024 11:44:20 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAAhV-H5QkULWp6fciR1Lnds0r00fUdrmj86K_wBuxd0D=RkaXQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qMiowMBxHeSn2RFnpmAvAA--.29241S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBj93XoW3ArWxtrWfKrWkZr1Utw4fJFc_yoWfWr4rpF
	9rCFn5WF4UXr97Ja92qr1Uur1UXwsagF4xKFnFkFyrAasFgr1kWr18Gr9xuF1kA3yUCa4F
	vr4fKa4a9a1jqagCm3ZEXasCq-sJn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUUvFb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Jr0_JF4l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Jr0_Gr1l84ACjcxK6I8E87Iv67AKxVWxJVW8Jr1l84ACjcxK6I8E87Iv6xkF7I0E14v2
	6r4UJVWxJr1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44I27w
	Aqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_JrI_JrylYx0Ex4A2jsIE
	14v26r1j6r4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvEwIxGrwCYjI0SjxkI62AI1c
	AE67vIY487MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8C
	rVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8Zw
	CIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x02
	67AKxVWUJVW8JwCI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr
	0_Gr1lIxAIcVC2z280aVCY1x0267AKxVWUJVW8JbIYCTnIWIevJa73UjIFyTuYvjxUrNtx
	DUUUU
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



On 2024/10/18 =E4=B8=8A=E5=8D=8811:14, Huacai Chen wrote:
> Hi, Bibo,
>=20
> I applied this patch but drop the part of arch/loongarch/mm/kasan_init.c:
> https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-loongson=
.git/commit/?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70ced50afc4030=
67
>=20
> Because kernel_pte_init() should operate on page-table pages, not on
> data pages. You have already handle page-table page in
> mm/kasan/init.c, and if we don't drop the modification on data pages
> in arch/loongarch/mm/kasan_init.c, the kernel fail to boot if KASAN is
> enabled.
>=20
static inline void set_pte(pte_t *ptep, pte_t pteval)
  {
  	WRITE_ONCE(*ptep, pteval);
-
-	if (pte_val(pteval) & _PAGE_GLOBAL) {
-		pte_t *buddy =3D ptep_buddy(ptep);
-		/*
-		 * Make sure the buddy is global too (if it's !none,
-		 * it better already be global)
-		 */
-		if (pte_none(ptep_get(buddy))) {
-#ifdef CONFIG_SMP
-			/*
-			 * For SMP, multiple CPUs can race, so we need
-			 * to do this atomically.
-			 */
-			__asm__ __volatile__(
-			__AMOR "$zero, %[global], %[buddy] \n"
-			: [buddy] "+ZB" (buddy->pte)
-			: [global] "r" (_PAGE_GLOBAL)
-			: "memory");
-
-			DBAR(0b11000); /* o_wrw =3D 0b11000 */
-#else /* !CONFIG_SMP */
-			WRITE_ONCE(*buddy, __pte(pte_val(ptep_get(buddy)) | _PAGE_GLOBAL));
-#endif /* CONFIG_SMP */
-		}
-	}
+	DBAR(0b11000); /* o_wrw =3D 0b11000 */
  }

No, please hold on. This issue exists about twenty years, Do we need be=20
in such a hurry now?

why is DBAR(0b11000) added in set_pte()?

Regards
Bibo Mao
> Huacai
>=20
> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.cn> w=
rote:
>>
>> Unlike general architectures, there are two pages in one TLB entry
>> on LoongArch system. For kernel space, it requires both two pte
>> entries with PAGE_GLOBAL bit set, else HW treats it as non-global
>> tlb, there will be potential problems if tlb entry for kernel space
>> is not global. Such as fail to flush kernel tlb with function
>> local_flush_tlb_kernel_range() which only flush tlb with global bit.
>>
>> With function kernel_pte_init() added, it can be used to init pte
>> table when it is created for kernel address space, and the default
>> initial pte value is PAGE_GLOBAL rather than zero at beginning.
>>
>> Kernel address space areas includes fixmap, percpu, vmalloc, kasan
>> and vmemmap areas set default pte entry with PAGE_GLOBAL set.
>>
>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
>> ---
>>   arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
>>   arch/loongarch/include/asm/pgtable.h |  1 +
>>   arch/loongarch/mm/init.c             |  4 +++-
>>   arch/loongarch/mm/kasan_init.c       |  4 +++-
>>   arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++++++++
>>   include/linux/mm.h                   |  1 +
>>   mm/kasan/init.c                      |  8 +++++++-
>>   mm/sparse-vmemmap.c                  |  5 +++++
>>   8 files changed, 55 insertions(+), 3 deletions(-)
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
>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>> index ecf63d2b0582..6909fe059a2c 100644
>> --- a/include/linux/mm.h
>> +++ b/include/linux/mm.h
>> @@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long size);
>>   struct page * __populate_section_memmap(unsigned long pfn,
>>                  unsigned long nr_pages, int nid, struct vmem_altmap *al=
tmap,
>>                  struct dev_pagemap *pgmap);
>> +void kernel_pte_init(void *addr);
>>   void pmd_init(void *addr);
>>   void pud_init(void *addr);
>>   pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>> index 89895f38f722..ac607c306292 100644
>> --- a/mm/kasan/init.c
>> +++ b/mm/kasan/init.c
>> @@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t *pmd, uns=
igned long addr,
>>          }
>>   }
>>
>> +void __weak __meminit kernel_pte_init(void *addr)
>> +{
>> +}
>> +
>>   static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
>>                                  unsigned long end)
>>   {
>> @@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t *pud, unsi=
gned long addr,
>>
>>                          if (slab_is_available())
>>                                  p =3D pte_alloc_one_kernel(&init_mm);
>> -                       else
>> +                       else {
>>                                  p =3D early_alloc(PAGE_SIZE, NUMA_NO_NO=
DE);
>> +                               kernel_pte_init(p);
>> +                       }
>>                          if (!p)
>>                                  return -ENOMEM;
>>
>> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
>> index edcc7a6b0f6f..c0388b2e959d 100644
>> --- a/mm/sparse-vmemmap.c
>> +++ b/mm/sparse-vmemmap.c
>> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block_zero(un=
signed long size, int node)
>>          return p;
>>   }
>>
>> +void __weak __meminit kernel_pte_init(void *addr)
>> +{
>> +}
>> +
>>   pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr,=
 int node)
>>   {
>>          pmd_t *pmd =3D pmd_offset(pud, addr);
>> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, u=
nsigned long addr, int node)
>>                  void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE, node);
>>                  if (!p)
>>                          return NULL;
>> +               kernel_pte_init(p);
>>                  pmd_populate_kernel(&init_mm, pmd, p);
>>          }
>>          return pmd;
>> --
>> 2.39.3
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f3089991-fd49-8d55-9ede-62ab1555c9fa%40loongson.cn.
