Return-Path: <kasan-dev+bncBAABBQGIU64AMGQEP5VD3LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C2CE599B03E
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 04:51:46 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-71e1ed58e9bsf3054392b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 19:51:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728701505; cv=pass;
        d=google.com; s=arc-20240605;
        b=QQ/9S7s/lACe0ivvX4fQwpdUamcBQHcSLUCCc3tSBK6rhEzU/aIZ2U5FiObO/fM6bu
         kGew5q2k1lfEnM1BiI2v8iJ3zRJBEoubIM4lN5N17yafQh2ipOpXMSZ7A8B4p/gUFrty
         dnmuTzzoo1AwNzoZ7pm6Ei4OHOLy78iwZIWSd/7rurg8nQlVdHKj6xPeDpMcMbueVyFr
         FzM4HMy5cIUeI12qh8rSxLsT8NEaKvcdw6PC8CIXCuK9MM2INq3xyFa26vp1OZmS4hWd
         hsrm39H1Qzl6bMmnBx1bta79iIwSjG+XAyqwRdqGkPsPls9iyJ+MSgCuNlUmjsYm8Ir1
         UN3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=bab3uHk1tu0mn1ADByeWZOjBf4yzNCiavzVy348LVBg=;
        fh=Mv7bQcFXlzyAWgSdb9Ac4jOz4x1ZhG6xHa/i5U1PVAo=;
        b=Egh4dmNVjKwzjmGZqa6GInPwnse3061vlNFcSQi0iIFW3B6FSFx4n8Z6qfWm3at1wp
         vpnuUkm4sNiPkEB+c3v/iWCFNFeSzfcKK6HxvzeWKFF1q0c+JY4LipBnDzK8RYagpyWa
         /+TGU5vhQ+aKSMMRzpvYYiRCxatDdG0GkpgtK+cLL3BHpnGPxcYTUOfvojgJWA7AjAJs
         ivPLzmkLJh3xh+8CKKyXUF37pJ8c67Pb0pDksWwflZTugUiEFOs9J8jQDH1UxgCHJ/ad
         AyV72/cDW6GvI6qdtV+JzcvKkhWD6S0a8rHRVsroqshrRJhxxd6BruNWuQ/cw5+8YB1U
         MPRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728701505; x=1729306305; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bab3uHk1tu0mn1ADByeWZOjBf4yzNCiavzVy348LVBg=;
        b=nVmvjZu3XXClkhD78vgezmOYAG+mlAyr9+oFWFHxaN60PnTU3KVc5krKQ3nHm39RPX
         VwUtMdtBj9Ynwvx+EJTEy4Hqd8M08uVLoPbNvKCY13XpGgPdRP67SZ/SQ2cqFjkJyHEW
         AdhCmDQjBh6gilewFl6fz6RafbjsX6teknCNTZI5Ha5cL86GcTYeDJY0ioCaAbyMsEwh
         CliQ3pk2uH5y96ZWs9XEkexSpFCI/UlgsM1iV0HXVG3sX0otwSLzy9WUlPooZafM1dmg
         Hq0AYJeoh4pBCbhBxKMGSgOnEHK/Qz1sMKemMi450f1/oWGXW+dmRo9IbXLuk9NHC9GK
         +HeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728701505; x=1729306305;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bab3uHk1tu0mn1ADByeWZOjBf4yzNCiavzVy348LVBg=;
        b=sC0XpxcrK72/Mt7yeci0K7js5w/7NZ23eaoehPzNSmpTQZB0+Oln20OrRwvw8VrvNV
         j2RUmHxQxUxtQ7UjURVi0F54LP++Kru6G5pNVEZsjtkXTcSNOpL3uOuRzOIgX476acCd
         2b16Rxus8vARI18COltZ7XEqAgWuHbTMNBxREn8uF5Oet+0nM0KtQHmeyQfsx+tkBSmu
         Dsq2DzoOQx6D/0Qi+YjFYkvZPcukXjwpB8FtyJxkk/iOxR+z3MXP0Mh2BfrfRH15wTEU
         gTlGVRrxsCDBZLVfKScwPstq5F0i1yFvyT5U0OI2DHcb7peZ8ZZVpkMhJ3JymwHl6uOr
         B8vw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX3lPPAEMRg3LXtM+bimgmS8NISkYeYfgEiwLdTdY6RfOryVKXMhIisCOWIEUeXlHc4PX2dzA==@lfdr.de
X-Gm-Message-State: AOJu0YwjJ7SbXi4a0LWLpArdgZu3BoUiv5D+pNFpJAR8ku+WKXfKlRXv
	7NQ4pW5E1axkfwZfeAJqYz0NmvqtmY6l05hcbAfxHAGVnOI21Ber
X-Google-Smtp-Source: AGHT+IFZfifaulIJVk2x9PY9YuJorcRoSkUHM0b6Kq73RputwYLme4BkE+l6mxXhmUJ+y0AGdzcsLg==
X-Received: by 2002:a05:6a20:e188:b0:1d8:a3ab:7212 with SMTP id adf61e73a8af0-1d8c9577310mr2236961637.2.1728701505151;
        Fri, 11 Oct 2024 19:51:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8c04:0:b0:71e:4de3:36df with SMTP id d2e1a72fcca58-71e4de33c19ls201826b3a.1.-pod-prod-04-us;
 Fri, 11 Oct 2024 19:51:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWSCW4dQ4o0tNh6Sgiwxac5seOe9vvWod9jiq5JQilFAfvt9rCv/+Mpk7nULeBKKhHqIvWwaOku2Uk=@googlegroups.com
X-Received: by 2002:a05:6a00:22d4:b0:71e:104d:62fe with SMTP id d2e1a72fcca58-71e4c1bfbcbmr2528735b3a.20.1728701503623;
        Fri, 11 Oct 2024 19:51:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728701503; cv=none;
        d=google.com; s=arc-20240605;
        b=K/hiVZSxv/AzTOI26KorGU8Q8UX3gZfBWepyYNwNnorXOimORGw3PWP4FVFiIWHDJ1
         LCuACAHOtqgeiJJTvu4kI3FXPpKrjg0YgDwFb25wjrEIRi0OH2aDOEB1y18g4lTQWp4I
         xN/EmyGCD2M3Ueq5HCheIRsu3S0QmvHOfw/raJrLADpYWZ8qh5QRhwljLbdpFY6E3tcv
         1s5afinGI4vG6kTQebvlNuGpnXSoetgO1bfPqNRGsWkQanmuc/gtIqkkzR6Ym1A5mDFR
         FCaH3KRUce4HUB3FWMQJk6CAc4rEOkHH27ZsT1moCtQeVqtogQfbU//3o9y5sYhNdqEn
         U63w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=j//Qp/2cQmu1nXrbzNxviuEmwhTe22q+aYbVOnDIM7s=;
        fh=ocVjpFH1JzmNVfR49Byi2MWYGiGWER7Q25i+GX3k5Kg=;
        b=gANa3HdZqPaNwizaUlEFeoauC8h1D1xH9e0OCSX/kc5xEXaJXibLTmsbgDly9lH4Kq
         dyb7KgAlbyfH7Y0P1eQiyF5os8GYPGboVkb28J4GaR5KU0deVc0850FJiwy1Yh9TUm0p
         bLkRYK/NkLmhbOhDRgRL0IF7JD2AhRkvSEffn0jHpIb47ajarMwwtoCJiO4/TbW2M4KC
         QAhknttzbuCGGb1vyqZL6jFHswDqLG6ZClEQnK92IKAuYcf7w7oV9brCKFYdGz0s3iZI
         +XPcsaSEcsvj+KamjxTWWvvFyjwnOZ4pBE/GDEVHIiJ//i3s/JV5iJ7qnQWfGz8Flksq
         3vDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id d2e1a72fcca58-71e4c35aea9si38359b3a.2.2024.10.11.19.51.42
        for <kasan-dev@googlegroups.com>;
        Fri, 11 Oct 2024 19:51:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.20.42.62])
	by gateway (Coremail) with SMTP id _____8CxrrM95Aln_GoUAA--.31421S3;
	Sat, 12 Oct 2024 10:51:41 +0800 (CST)
Received: from [10.20.42.62] (unknown [10.20.42.62])
	by front1 (Coremail) with SMTP id qMiowMBxXuQ85AlnuqAkAA--.51936S3;
	Sat, 12 Oct 2024 10:51:40 +0800 (CST)
Subject: Re: [PATCH 4/4] LoongArch: Use atomic operation with set_pte and
 pte_clear function
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20241010035048.3422527-1-maobibo@loongson.cn>
 <20241010035048.3422527-5-maobibo@loongson.cn>
 <CAAhV-H5DvHcS+apFthMWNNqvvq+VMu--6bcuyGzdMz66K8Bd=g@mail.gmail.com>
From: maobibo <maobibo@loongson.cn>
Message-ID: <4917e6ac-2874-218c-a3be-f2a1462f11c5@loongson.cn>
Date: Sat, 12 Oct 2024 10:51:22 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAAhV-H5DvHcS+apFthMWNNqvvq+VMu--6bcuyGzdMz66K8Bd=g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qMiowMBxXuQ85AlnuqAkAA--.51936S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBj93XoWxCF1fKr13Aw47Xw45WrWUJrc_yoW5Zw1Upr
	ZxCF95ZFs7GryIkwsFqFn8tryYv34ava4ktr9IkFy8AFnav3sFqFy0grWayFy5t3yfWw48
	Ja1UKwnxWFsFyacCm3ZEXasCq-sJn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUUvFb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVWxJVW8Jr1l84ACjcxK6I8E87Iv6xkF7I0E14v2
	6r4j6r4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zVCFFI0UMc
	02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUtVWrXwAv7VC2z280aVAF
	wI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JMxk0xIA0c2IEe2xFo4
	CEbIxvr21l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG
	67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r1q6r43MI
	IYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Gr0_Xr1lIxAIcVC0I7IYx2IY6xkF7I0E
	14v26r4j6F4UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87Iv67AKxVW8JV
	WxJwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnIWIevJa73UjIFyTuYvjxU2F4i
	UUUUU
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

On 2024/10/12 =E4=B8=8A=E5=8D=8810:16, Huacai Chen wrote:
> Hi, Bibo,
>=20
> On Thu, Oct 10, 2024 at 11:50=E2=80=AFAM Bibo Mao <maobibo@loongson.cn> w=
rote:
>>
>> For kernel space area on LoongArch system, both two consecutive page
>> table entries should be enabled with PAGE_GLOBAL bit. So with function
>> set_pte() and pte_clear(), pte buddy entry is checked and set besides
>> its own pte entry. However it is not atomic operation to set both two
>> pte entries, there is problem with test_vmalloc test case.
>>
>> With previous patch, all page table entries are set with PAGE_GLOBAL
>> bit at beginning. Only its own pte entry need update with function
>> set_pte() and pte_clear(), nothing to do with buddy pte entry.
>>
>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
>> ---
>>   arch/loongarch/include/asm/pgtable.h | 44 ++++++++++------------------
>>   1 file changed, 15 insertions(+), 29 deletions(-)
>>
>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/inclu=
de/asm/pgtable.h
>> index 22e3a8f96213..4be3f0dbecda 100644
>> --- a/arch/loongarch/include/asm/pgtable.h
>> +++ b/arch/loongarch/include/asm/pgtable.h
>> @@ -325,40 +325,26 @@ extern void paging_init(void);
>>   static inline void set_pte(pte_t *ptep, pte_t pteval)
>>   {
>>          WRITE_ONCE(*ptep, pteval);
>> +}
>>
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
>> +static inline unsigned long __ptep_get_and_clear(pte_t *ptep)
>> +{
>> +       return atomic64_fetch_and(_PAGE_GLOBAL, (atomic64_t *)&pte_val(*=
ptep));
>>   }
>>
>>   static inline void pte_clear(struct mm_struct *mm, unsigned long addr,=
 pte_t *ptep)
>>   {
>> -       /* Preserve global status for the pair */
>> -       if (pte_val(ptep_get(ptep_buddy(ptep))) & _PAGE_GLOBAL)
>> -               set_pte(ptep, __pte(_PAGE_GLOBAL));
>> -       else
>> -               set_pte(ptep, __pte(0));
>> +       __ptep_get_and_clear(ptep);
> With the first patch, a kernel pte always take _PAGE_GLOBAL, so we
> don't need an expensive atomic operation, just
> "set_pte(pte_val(ptep_get(ptep)) & _PAGE_GLOBAL)" is OK here. And then
> we don't need a custom ptep_get_and_clear().
Will use non-atomic method and test again, also will remove customed=20
function ptep_get_and_clear().

Regards
Bibo Mao
>=20
>=20
> Huacai
>=20
>> +}
>> +
>> +#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
>> +static inline pte_t ptep_get_and_clear(struct mm_struct *mm,
>> +                                       unsigned long addr, pte_t *ptep)
>> +{
>> +       unsigned long val;
>> +
>> +       val =3D __ptep_get_and_clear(ptep);
>> +       return __pte(val);
>>   }
>>
>>   #define PGD_T_LOG2     (__builtin_ffs(sizeof(pgd_t)) - 1)
>> --
>> 2.39.3
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4917e6ac-2874-218c-a3be-f2a1462f11c5%40loongson.cn.
