Return-Path: <kasan-dev+bncBAABB475Y64AMGQE3ARHFNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 77AE49A3545
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 08:23:48 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-e28fc60660dsf2545224276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 23:23:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729232627; cv=pass;
        d=google.com; s=arc-20240605;
        b=J3JckL64VxS/ZBOlzS/aQx5/tDCcYjnr+RN0Z5GAl0ST6KDUrl3QdQCWZXIb9NeeQ1
         E0QUhCLV+oWrlkzo+PJ9OBsWfMjEIQoHlflnR+Z6Tl4y1KTrJtYqgnzpm7gOVCx0DyLm
         dGqztlTb/egOiGyzf+zwW8m9u7pIa59uPMNFcojY2PhNLVINPlXC/5Yb8vzlYRiaIj6X
         xw4aLjl4jLlDhAR7F8qRcObsMkC9YpMZY+1GRXR7tJIjQXEDpGrCNqZpi0QQ3Ah6S5lU
         4tJaIxhkGAvjtf4SD+K7blBeyqFcQeiZjO49XNW8FgcF4D/TS4s9uBGgfxCmgflcKcCQ
         mrZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=BeRzVq/QHVHxgqydYlpXW4iUzn/bEYi4RwhgogDRBn8=;
        fh=wkbfkZ2Pt50kKBoxSsLDDITSEEporEwEboQnQEh1Fbo=;
        b=JQ3E0N6zYl5caII9BvEbK1LKbVK7NO4gKvBqOrazeT87oM9y2i8H4g+XB/CoupsRAl
         RPHHL5Vuuec8Y+e9l25QKjSGfvMSvPDqzHw+i7UNqNVmFgNAzRMJjhTKuZRYyGOL1zp1
         1A2/y5JwWV+dFxcIDGfXUJ49Kn3Yg4LRsRA4SIF8Yqw+rTgg7y700NADDlxYLte8WWUS
         YfZ4DvQ6UCVKCzN8CmMrMebkdb3H2kED3aSAhnnANPJhJM6bwi/DOvcfkPaLRiT3KTIH
         BYqUVPVhVvQUKp4lDLppxuCBPmOV4kMFQfJymaw2b3OnGxZmKxhlBa7xDT/Qg4NMyABT
         074w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729232627; x=1729837427; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BeRzVq/QHVHxgqydYlpXW4iUzn/bEYi4RwhgogDRBn8=;
        b=N/SxkeSky3GmTJ/3TIkA8mSv26pSMjZ8QHtddFvvp2an2A4w9XkjK6ILm2gBMos5q/
         vkj06202lzOF35PZBMR4Tl3Cbce0WNdv6mF+/WzfwNOXSiaGJcOQu5aH9U9uV0rmBswX
         XdRY2sDeg3inXQCzDFqIZtBOWU0Avez+OBAa8XNMSkj4zrwLgxkQ8uBbOeCqWp2EHt+n
         dOlQyovY9wM+bnGkkeStnNNKC43hKF4Td8FPeEc0T6X/f+QdPRKzPLqn0QpkmWnwmlqL
         5oFJ92pwTMVHvXsaa1B0PBahqJfzpcfa4br4AyzXFCQM9UUzxh3SvsKxJCHxGnU02yz2
         vfqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729232627; x=1729837427;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BeRzVq/QHVHxgqydYlpXW4iUzn/bEYi4RwhgogDRBn8=;
        b=teuLxIqyAotlDL1WXipbMUyuChhbuiFPaFt9cmiV0i+eGPCWc1qseE5nZdJC6T1NPC
         AJwAEyWPf+qC+m+93WT52+qHayrFJ6Mzu++XjJLi6mjLUBw2/LouLAm0lmldheBnqIHU
         FChQ0hI9pfJKeA2FWmXYKw2QiKu6Z+/eAkKVSuuLAp9EVKF7C1Y8u8NqTkiRUVFQ6IxN
         PoigD6K2dXOaAq/suHoy3FI6UIhdTgKwhp1sj/UMcU5YJR+OtQq4Ix10jTPwxdKe9ycX
         sQEfAzjJMcG+8wEbZnrNe1T3gn+vfOqXSaeLY7wPq4ATDdZ0BWJcklOjN5WJmeYmNwyg
         fQNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVd1TXR8+XUt2U0dzHsDodK/UIuBN14iXxeDS31ec8dyeFqquwvkcJAD/G57/A30WGLP8Kp3Q==@lfdr.de
X-Gm-Message-State: AOJu0YwYChTq6hFL4RJ/Q/wB5FUbCo65mphBBMfq4NeKBn34K2jEryui
	HkA7KXI39KuLw0vfpujcPigpfSS02LadVF5tfnr4aRLZLGPolG++
X-Google-Smtp-Source: AGHT+IHoZiwzEAhhF4v6LjcfF7uJ6LL+B68h4e9YuZIUj/7/9sVaGsaI2h9v6cpJM0eZxz3swk4mNg==
X-Received: by 2002:a05:6902:260a:b0:e29:5540:7f85 with SMTP id 3f1490d57ef6-e2bb11e55b0mr1070769276.1.1729232627230;
        Thu, 17 Oct 2024 23:23:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1887:b0:e29:2d4a:f757 with SMTP id
 3f1490d57ef6-e2b9cdece50ls1728648276.1.-pod-prod-09-us; Thu, 17 Oct 2024
 23:23:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZaFyrLOeO659KkRMD4bKvrObmSA7vFafhwGCLIKYB1jJExlm9pHACUrYwVzEVl46nH+/Uhp/xHwI=@googlegroups.com
X-Received: by 2002:a05:6902:124a:b0:e29:1def:1032 with SMTP id 3f1490d57ef6-e2bb16ac49emr1107977276.41.1729232626371;
        Thu, 17 Oct 2024 23:23:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729232626; cv=none;
        d=google.com; s=arc-20240605;
        b=bwmlit9iVMnSYGZw2XYIZ5Jkf7iY8J5BmIfjyYqrFPB4j2dlK79ge7v1Iw0Dl2AeNq
         Y6oMWKc2q8OUeGRcvH45Bw80dMNElNh6tBE4EPGFCFmOAWCHrTe0kmZj7aeNHoTeo0m7
         dW7P6KOdbrL/mTcQ/Usg3/2C+oY0aSNGH1vddwYsCYlWLbbIoR2o9TSJWZivc+isbG7J
         zMI0hK4FlznHr7F1erPz1u0QVvbKHbJTqau52q2otjQcLBXC8+uQMExwI3f3uxmwX7IT
         Qa7iPuSEvPBEv4UqWLYwE/dOj4vqqPaB7VwkGk7o/fOvRihCVhSOeF68w/cdAdwj85f9
         jf5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=IS+NMHaCLJDhf0HKE2ebm54p21Ok6Av5jM3ADqBkHRQ=;
        fh=9ZQsqNuoVdQ7BX1qRjo+A/vfeXmiVHNy+Ra0CfN5Jfg=;
        b=IVbf35CMZLT1pwXJTqilDLlDSdDPBajFzsf2TH1n4YmwI8R8lJ5VNnCk0+/IQYj5i1
         5WJB45oHm8W7hrjyuTQbfruqYuBd0+bvlHhYcMmSgQO/nA44ky+f9j5169ubE9s4MWEE
         G6OfzR8RzGRo+ZSVmd8FmyI+RvK6yfmwp7XUQMxX5IncEjZCWtx8d46nW+giCIWCvyCR
         obKH8yCS52O/NQhew9c7upCfM5Q21/f7xM4ddSvLL7cPE1O6h1XG405ZW2VwhXGkoewt
         22txVCXeHWbQDIJGeEPCzzI5SIqncwmmwFpOhBO5Q5nkoW5qFwyMohS+yOvtRhXHUggH
         b3TQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 3f1490d57ef6-e2bb03c241esi52645276.2.2024.10.17.23.23.45
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Oct 2024 23:23:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.20.42.62])
	by gateway (Coremail) with SMTP id _____8Axhons_hFnx2sjAA--.51292S3;
	Fri, 18 Oct 2024 14:23:40 +0800 (CST)
Received: from [10.20.42.62] (unknown [10.20.42.62])
	by front1 (Coremail) with SMTP id qMiowMAxSebi_hFn8IEvAA--.29158S3;
	Fri, 18 Oct 2024 14:23:33 +0800 (CST)
Subject: Re: [PATCH v2 1/3] LoongArch: Set initial pte entry with PAGE_GLOBAL
 for kernel space
To: Huacai Chen <chenhuacai@kernel.org>, wuruiyang@loongson.cn
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
 <a4c6b89e-4ffe-4486-4ccd-7ebc28734f6f@loongson.cn>
 <CAAhV-H6FkJZwa-pALUhucrU5OXxsHg+ByM+4NN0wPQgOJTqOXA@mail.gmail.com>
From: maobibo <maobibo@loongson.cn>
Message-ID: <5f76ede6-e8be-c7a9-f957-479afa2fb828@loongson.cn>
Date: Fri, 18 Oct 2024 14:23:11 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAAhV-H6FkJZwa-pALUhucrU5OXxsHg+ByM+4NN0wPQgOJTqOXA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qMiowMAxSebi_hFn8IEvAA--.29158S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBj93XoW3try8Xr4fAF45Wr1DZFWUAwc_yoWkAw1Upr
	yDCF1kAF4UXr1UJwsFqw1jqrnrtwn7KF4IgF17Gr15AFnFqFnrJr1UJry5uF18J3yUG3W0
	vr1rKw13WF1UJ3cCm3ZEXasCq-sJn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUUvIb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Jr0_JF4l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Jr0_Gr1l84ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVCY1x0267AK
	xVW8Jr0_Cr1UM2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx
	1l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv
	67AKxVW8JVWxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lc7I2V7IY0VAS07
	AlzVAYIcxG8wCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02
	F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw0_GF
	ylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv20xvEc7Cj
	xVAFwI0_Jr0_Gr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r
	4j6F4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07j8
	sqAUUUUU=
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



On 2024/10/18 =E4=B8=8B=E5=8D=8812:23, Huacai Chen wrote:
> On Fri, Oct 18, 2024 at 12:16=E2=80=AFPM maobibo <maobibo@loongson.cn> wr=
ote:
>>
>>
>>
>> On 2024/10/18 =E4=B8=8B=E5=8D=8812:11, Huacai Chen wrote:
>>> On Fri, Oct 18, 2024 at 11:44=E2=80=AFAM maobibo <maobibo@loongson.cn> =
wrote:
>>>>
>>>>
>>>>
>>>> On 2024/10/18 =E4=B8=8A=E5=8D=8811:14, Huacai Chen wrote:
>>>>> Hi, Bibo,
>>>>>
>>>>> I applied this patch but drop the part of arch/loongarch/mm/kasan_ini=
t.c:
>>>>> https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-loon=
gson.git/commit/?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70ced50afc=
403067
>>>>>
>>>>> Because kernel_pte_init() should operate on page-table pages, not on
>>>>> data pages. You have already handle page-table page in
>>>>> mm/kasan/init.c, and if we don't drop the modification on data pages
>>>>> in arch/loongarch/mm/kasan_init.c, the kernel fail to boot if KASAN i=
s
>>>>> enabled.
>>>>>
>>>> static inline void set_pte(pte_t *ptep, pte_t pteval)
>>>>     {
>>>>           WRITE_ONCE(*ptep, pteval);
>>>> -
>>>> -       if (pte_val(pteval) & _PAGE_GLOBAL) {
>>>> -               pte_t *buddy =3D ptep_buddy(ptep);
>>>> -               /*
>>>> -                * Make sure the buddy is global too (if it's !none,
>>>> -                * it better already be global)
>>>> -                */
>>>> -               if (pte_none(ptep_get(buddy))) {
>>>> -#ifdef CONFIG_SMP
>>>> -                       /*
>>>> -                        * For SMP, multiple CPUs can race, so we need
>>>> -                        * to do this atomically.
>>>> -                        */
>>>> -                       __asm__ __volatile__(
>>>> -                       __AMOR "$zero, %[global], %[buddy] \n"
>>>> -                       : [buddy] "+ZB" (buddy->pte)
>>>> -                       : [global] "r" (_PAGE_GLOBAL)
>>>> -                       : "memory");
>>>> -
>>>> -                       DBAR(0b11000); /* o_wrw =3D 0b11000 */
>>>> -#else /* !CONFIG_SMP */
>>>> -                       WRITE_ONCE(*buddy, __pte(pte_val(ptep_get(budd=
y)) | _PAGE_GLOBAL));
>>>> -#endif /* CONFIG_SMP */
>>>> -               }
>>>> -       }
>>>> +       DBAR(0b11000); /* o_wrw =3D 0b11000 */
>>>>     }
>>>>
>>>> No, please hold on. This issue exists about twenty years, Do we need b=
e
>>>> in such a hurry now?
>>>>
>>>> why is DBAR(0b11000) added in set_pte()?
>>> It exists before, not added by this patch. The reason is explained in
>>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/comm=
it/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
>> why speculative accesses may cause spurious page fault in kernel space
>> with PTE enabled?  speculative accesses exists anywhere, it does not
>> cause spurious page fault.
> Confirmed by Ruiyang Wu, and even if DBAR(0b11000) is wrong, that
> means another patch's mistake, not this one. This one just keeps the
> old behavior.
> +CC Ruiyang Wu here.
Also from Ruiyang Wu, the information is that speculative accesses may=20
insert stale TLB, however no page fault exception.

So adding barrier in set_pte() does not prevent speculative accesses.=20
And you write patch here, however do not know the actual reason?

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?=
h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030

Bibo Mao
>=20
> Huacai
>=20
>>
>> Obvious you do not it and you write wrong patch.
>>
>>>
>>> Huacai
>>>
>>>>
>>>> Regards
>>>> Bibo Mao
>>>>> Huacai
>>>>>
>>>>> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.c=
n> wrote:
>>>>>>
>>>>>> Unlike general architectures, there are two pages in one TLB entry
>>>>>> on LoongArch system. For kernel space, it requires both two pte
>>>>>> entries with PAGE_GLOBAL bit set, else HW treats it as non-global
>>>>>> tlb, there will be potential problems if tlb entry for kernel space
>>>>>> is not global. Such as fail to flush kernel tlb with function
>>>>>> local_flush_tlb_kernel_range() which only flush tlb with global bit.
>>>>>>
>>>>>> With function kernel_pte_init() added, it can be used to init pte
>>>>>> table when it is created for kernel address space, and the default
>>>>>> initial pte value is PAGE_GLOBAL rather than zero at beginning.
>>>>>>
>>>>>> Kernel address space areas includes fixmap, percpu, vmalloc, kasan
>>>>>> and vmemmap areas set default pte entry with PAGE_GLOBAL set.
>>>>>>
>>>>>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
>>>>>> ---
>>>>>>     arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
>>>>>>     arch/loongarch/include/asm/pgtable.h |  1 +
>>>>>>     arch/loongarch/mm/init.c             |  4 +++-
>>>>>>     arch/loongarch/mm/kasan_init.c       |  4 +++-
>>>>>>     arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++++++++
>>>>>>     include/linux/mm.h                   |  1 +
>>>>>>     mm/kasan/init.c                      |  8 +++++++-
>>>>>>     mm/sparse-vmemmap.c                  |  5 +++++
>>>>>>     8 files changed, 55 insertions(+), 3 deletions(-)
>>>>>>
>>>>>> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongarch/i=
nclude/asm/pgalloc.h
>>>>>> index 4e2d6b7ca2ee..b2698c03dc2c 100644
>>>>>> --- a/arch/loongarch/include/asm/pgalloc.h
>>>>>> +++ b/arch/loongarch/include/asm/pgalloc.h
>>>>>> @@ -10,8 +10,21 @@
>>>>>>
>>>>>>     #define __HAVE_ARCH_PMD_ALLOC_ONE
>>>>>>     #define __HAVE_ARCH_PUD_ALLOC_ONE
>>>>>> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
>>>>>>     #include <asm-generic/pgalloc.h>
>>>>>>
>>>>>> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
>>>>>> +{
>>>>>> +       pte_t *pte;
>>>>>> +
>>>>>> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
>>>>>> +       if (!pte)
>>>>>> +               return NULL;
>>>>>> +
>>>>>> +       kernel_pte_init(pte);
>>>>>> +       return pte;
>>>>>> +}
>>>>>> +
>>>>>>     static inline void pmd_populate_kernel(struct mm_struct *mm,
>>>>>>                                           pmd_t *pmd, pte_t *pte)
>>>>>>     {
>>>>>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/i=
nclude/asm/pgtable.h
>>>>>> index 9965f52ef65b..22e3a8f96213 100644
>>>>>> --- a/arch/loongarch/include/asm/pgtable.h
>>>>>> +++ b/arch/loongarch/include/asm/pgtable.h
>>>>>> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm, uns=
igned long addr, pmd_t *pmdp, pm
>>>>>>     extern void pgd_init(void *addr);
>>>>>>     extern void pud_init(void *addr);
>>>>>>     extern void pmd_init(void *addr);
>>>>>> +extern void kernel_pte_init(void *addr);
>>>>>>
>>>>>>     /*
>>>>>>      * Encode/decode swap entries and swap PTEs. Swap PTEs are all P=
TEs that
>>>>>> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
>>>>>> index 8a87a482c8f4..9f26e933a8a3 100644
>>>>>> --- a/arch/loongarch/mm/init.c
>>>>>> +++ b/arch/loongarch/mm/init.c
>>>>>> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned lon=
g addr)
>>>>>>            if (!pmd_present(pmdp_get(pmd))) {
>>>>>>                    pte_t *pte;
>>>>>>
>>>>>> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>>>>>> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE);
>>>>>>                    if (!pte)
>>>>>>                            panic("%s: Failed to allocate memory\n", =
__func__);
>>>>>> +
>>>>>> +               kernel_pte_init(pte);
>>>>>>                    pmd_populate_kernel(&init_mm, pmd, pte);
>>>>>>            }
>>>>>>
>>>>>> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasa=
n_init.c
>>>>>> index 427d6b1aec09..34988573b0d5 100644
>>>>>> --- a/arch/loongarch/mm/kasan_init.c
>>>>>> +++ b/arch/loongarch/mm/kasan_init.c
>>>>>> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t *pmd=
p, unsigned long addr,
>>>>>>                    phys_addr_t page_phys =3D early ?
>>>>>>                                            __pa_symbol(kasan_early_s=
hadow_page)
>>>>>>                                                  : kasan_alloc_zeroe=
d_page(node);
>>>>>> +               if (!early)
>>>>>> +                       kernel_pte_init(__va(page_phys));
>>>>>>                    next =3D addr + PAGE_SIZE;
>>>>>>                    set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), P=
AGE_KERNEL));
>>>>>>            } while (ptep++, addr =3D next, addr !=3D end && __pte_no=
ne(early, ptep_get(ptep)));
>>>>>> @@ -287,7 +289,7 @@ void __init kasan_init(void)
>>>>>>                    set_pte(&kasan_early_shadow_pte[i],
>>>>>>                            pfn_pte(__phys_to_pfn(__pa_symbol(kasan_e=
arly_shadow_page)), PAGE_KERNEL_RO));
>>>>>>
>>>>>> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>>>>>> +       kernel_pte_init(kasan_early_shadow_page);
>>>>>>            csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PG=
DH);
>>>>>>            local_flush_tlb_all();
>>>>>>
>>>>>> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable=
.c
>>>>>> index eb6a29b491a7..228ffc1db0a3 100644
>>>>>> --- a/arch/loongarch/mm/pgtable.c
>>>>>> +++ b/arch/loongarch/mm/pgtable.c
>>>>>> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
>>>>>>     }
>>>>>>     EXPORT_SYMBOL_GPL(pgd_alloc);
>>>>>>
>>>>>> +void kernel_pte_init(void *addr)
>>>>>> +{
>>>>>> +       unsigned long *p, *end;
>>>>>> +       unsigned long entry;
>>>>>> +
>>>>>> +       entry =3D (unsigned long)_PAGE_GLOBAL;
>>>>>> +       p =3D (unsigned long *)addr;
>>>>>> +       end =3D p + PTRS_PER_PTE;
>>>>>> +
>>>>>> +       do {
>>>>>> +               p[0] =3D entry;
>>>>>> +               p[1] =3D entry;
>>>>>> +               p[2] =3D entry;
>>>>>> +               p[3] =3D entry;
>>>>>> +               p[4] =3D entry;
>>>>>> +               p +=3D 8;
>>>>>> +               p[-3] =3D entry;
>>>>>> +               p[-2] =3D entry;
>>>>>> +               p[-1] =3D entry;
>>>>>> +       } while (p !=3D end);
>>>>>> +}
>>>>>> +
>>>>>>     void pgd_init(void *addr)
>>>>>>     {
>>>>>>            unsigned long *p, *end;
>>>>>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>>>>>> index ecf63d2b0582..6909fe059a2c 100644
>>>>>> --- a/include/linux/mm.h
>>>>>> +++ b/include/linux/mm.h
>>>>>> @@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long size);
>>>>>>     struct page * __populate_section_memmap(unsigned long pfn,
>>>>>>                    unsigned long nr_pages, int nid, struct vmem_altm=
ap *altmap,
>>>>>>                    struct dev_pagemap *pgmap);
>>>>>> +void kernel_pte_init(void *addr);
>>>>>>     void pmd_init(void *addr);
>>>>>>     void pud_init(void *addr);
>>>>>>     pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
>>>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>>>>> index 89895f38f722..ac607c306292 100644
>>>>>> --- a/mm/kasan/init.c
>>>>>> +++ b/mm/kasan/init.c
>>>>>> @@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t *pmd,=
 unsigned long addr,
>>>>>>            }
>>>>>>     }
>>>>>>
>>>>>> +void __weak __meminit kernel_pte_init(void *addr)
>>>>>> +{
>>>>>> +}
>>>>>> +
>>>>>>     static int __ref zero_pmd_populate(pud_t *pud, unsigned long add=
r,
>>>>>>                                    unsigned long end)
>>>>>>     {
>>>>>> @@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t *pud, =
unsigned long addr,
>>>>>>
>>>>>>                            if (slab_is_available())
>>>>>>                                    p =3D pte_alloc_one_kernel(&init_=
mm);
>>>>>> -                       else
>>>>>> +                       else {
>>>>>>                                    p =3D early_alloc(PAGE_SIZE, NUMA=
_NO_NODE);
>>>>>> +                               kernel_pte_init(p);
>>>>>> +                       }
>>>>>>                            if (!p)
>>>>>>                                    return -ENOMEM;
>>>>>>
>>>>>> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
>>>>>> index edcc7a6b0f6f..c0388b2e959d 100644
>>>>>> --- a/mm/sparse-vmemmap.c
>>>>>> +++ b/mm/sparse-vmemmap.c
>>>>>> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block_zer=
o(unsigned long size, int node)
>>>>>>            return p;
>>>>>>     }
>>>>>>
>>>>>> +void __weak __meminit kernel_pte_init(void *addr)
>>>>>> +{
>>>>>> +}
>>>>>> +
>>>>>>     pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long=
 addr, int node)
>>>>>>     {
>>>>>>            pmd_t *pmd =3D pmd_offset(pud, addr);
>>>>>> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pu=
d, unsigned long addr, int node)
>>>>>>                    void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE, n=
ode);
>>>>>>                    if (!p)
>>>>>>                            return NULL;
>>>>>> +               kernel_pte_init(p);
>>>>>>                    pmd_populate_kernel(&init_mm, pmd, p);
>>>>>>            }
>>>>>>            return pmd;
>>>>>> --
>>>>>> 2.39.3
>>>>>>
>>>>
>>>>
>>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5f76ede6-e8be-c7a9-f957-479afa2fb828%40loongson.cn.
