Return-Path: <kasan-dev+bncBAABBLO5SOQQMGQESQQY4NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DA976CF903
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 04:06:39 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id s12-20020a67c38c000000b00426234007dbsf5380773vsj.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 19:06:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680141998; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pl5yRFaXURPRe3ObiyWUXoL59kbxYxKsYuxWC7JqxRyPaaAQDbyaXOuvcEbXVdu0+4
         jqtdES++AvkURAqrmWTd3frZdgvQiLJBxLi8MPlwNomBjy5/aPkrsbY22scmtjHxANDO
         izQ5OAsSVDPwQHFyBaxtP24Z7iYJBZM86Y+Ehd0RYu3GnLkREHif5FM8byvb9Vf94pdu
         QrAe9FgWgXAQJkjI15DSnUngWEO0bRQk5XT6vdL5vXg8TZ7WlgIHwcYQwb+hkY0diw1Q
         pBqmno3KakNezCDVzsdMG3PvwDu8Y4v6S+MrfIACyiOsHYy6uPgLBdfBhD+5o4TuR1r2
         gBqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=ru20bznnXZ8WUyTk2cMzqYsZ4fpATT59sk5LDRnJn3w=;
        b=nRVneZiZ8qsuNtgX6v2R/I9AGQV1Z73iXSvvpQIdlXMyU37IBIWEZVSw486LdQzlVl
         zfhuPnGwu1ebHLKpXKWyA/5gY1R7KnKlP5mRfQqKWqqqVXQZr3CS+DjIFt6rUZ/4nzdq
         GGJoee5p9zo8RYWbWBcCPL7ibpuEeaczyfAsTRpOUQ/9t1L423ij33NpB4xei8NtMiO4
         dQsjr+NtlPQsqTj1SyoYehd2swD+53BqXwXwy6vmzdVjhVhC2BxPBGoM814pcItjE8bj
         wq+wo2HGn3dho7jgMxOHxfEEk+4ghFX5rulIQx3uaOPhr1QOn97/hffGBGjjY+yMfjFB
         b94A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680141998;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ru20bznnXZ8WUyTk2cMzqYsZ4fpATT59sk5LDRnJn3w=;
        b=O98LFxtVW/64k/PY1WUQAmlVIBz8Asp38rOt+ZlFjOHdqc6e7GvbtsMjItk98oOnao
         sdV9d7ycE4H0VJl+yLQtqEt80wkhpZSPJXZp7sRh1c9gDYO7f0WEaxAXQcF2+jW9qzXe
         x7SIlliYOFlkGH3HITdfRLq8Iurx+g/1ybcRtjKCQ2JEFZfh+GXpBAb3BkbI1c/t/SUe
         X50nbB2r7Qauhd5mP8cjeMdKy7wUIlPR5JxA862ehY7f5se+KyxtjNQWqisjy67vZSlV
         Bu/QyiqEk0ZwyREQ9XdnFOpKoriejUbnzR3rVU29F/89nvke3PYvorM7g19zJc798IfU
         q4eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680141998;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ru20bznnXZ8WUyTk2cMzqYsZ4fpATT59sk5LDRnJn3w=;
        b=RJu3ssJgsbjkng8xkO/McF58yDBoN7NR6UnJKcOv5AOqhcQivtOQ308/iDkT14wS8f
         Gk9IvpVJj3Flj1u7F5xEeiXC46q+wZd7GS+ZEU6DO+FxBzQ4yzKaCAgZPPYKJHEAyTFI
         xUIcCxxt1gYG7EgbLt9AWndu+SfbCmY+nsh8L1qsbvH4sIvyHKqPFLJ++c9YItLWr9wa
         qgpW/y2DtaYV9B3Yj4FaO6xmd2bTVnA35hnSQb5cIlIGWqumLPMlbvFbXabG2yLlIYwR
         XAGyTry+SLDTam6SbGc3sNyLQVhr4TFCx30J7/O23vPIClhLEj0vqzcdtrlz/c6pCEAm
         VYKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9eMrFHPNIn+GerTTemqpJxrDEwHJx4GU6KrTe/4Wf8JAYWQqByn
	+XKhzXGu84z5FVTpouSuN70=
X-Google-Smtp-Source: AKy350aO7i6UMTAMYvl0PuFcXz5/YdQ/F4zEtOkOql4oEKSeMGNZmXXOGuODNOeEBpv5ueXWHXs7gg==
X-Received: by 2002:a67:e053:0:b0:425:b978:efb7 with SMTP id n19-20020a67e053000000b00425b978efb7mr11970903vsl.2.1680141998026;
        Wed, 29 Mar 2023 19:06:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:abcc:0:b0:435:e934:1e29 with SMTP id u195-20020a1fabcc000000b00435e9341e29ls45150vke.7.-pod-prod-gmail;
 Wed, 29 Mar 2023 19:06:37 -0700 (PDT)
X-Received: by 2002:a05:6122:2094:b0:436:29ce:7ef5 with SMTP id i20-20020a056122209400b0043629ce7ef5mr9321354vkd.0.1680141997429;
        Wed, 29 Mar 2023 19:06:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680141997; cv=none;
        d=google.com; s=arc-20160816;
        b=tHsbjDZChk+doiGsy4elNbG0l+M7U+lrfs3O85egzrHugm4Q+a9QG0odQPmnpUrPso
         WGENWnbAgsewT4/CkZEGyRbm9AbGLgSbuqe1F8ENdDrKC/djAqrSOOh3HqfBAgUXbfuE
         XoLy2zHJRzPfsQRqtZ9kZTpRO5p4v5ZPb8U0n9iR5OndUxul5WuRO61awlTcGhAwqwo7
         TIpat9noDQAjTQpIpgkpw/EU1OiKH6Cxf2sO/OveEdR+Oqq+qrTXmEg64E85Aubf/U50
         0fOnXapfCc6q1Nw90EBwMiBfxVr5TqSwpxPG+h0MS7+PpzgcfJIYI1526bMDQUM26XO/
         0MHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=U+g6Y5JzvLGP0jhGpnxPSHffGBY07LEpQ+2IPlDG9nA=;
        b=CzNq9e2AggMI2XAITCCiNzmcV/zhKNLar9ekdFxILOV++Ms8CJFR46qGNvDCESJ3Wj
         2t2h8Do4lsN2nfyKMOCCal55uP4nHvAnTalUJzBxuLqlbYBUxnXKVbVpAWJkxuAgZu4d
         4P6cLpYshHj/GPo6ya+k7pIDzNc15uu6suZ7FdfPsm+71oiVmJa5hiWDR0+UCLj4qzH+
         MA/iH0Fxx/5Z2gRJws5ZD7YUP1VQkixywIrhjQOCDLMnFpWHc33vHmiva6Y+UJ1/SoGS
         NJA0a5/7ALgzkqMBtG+bmY/7CxUJf6+/KNf9xg2WuaIVeHFOaXEIqJQ2K8ZRI7NEnRbf
         nfzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id f37-20020ab014e8000000b00690829432ebsi3525071uae.2.2023.03.29.19.06.35
        for <kasan-dev@googlegroups.com>;
        Wed, 29 Mar 2023 19:06:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8AxJISL7iRkSSkUAA--.31101S3;
	Thu, 30 Mar 2023 10:06:03 +0800 (CST)
Received: from [10.130.0.102] (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8AxHL6I7iRkjugQAA--.13156S3;
	Thu, 30 Mar 2023 10:06:03 +0800 (CST)
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Huacai Chen <chenhuacai@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>
References: <20230328111714.2056-1-zhangqing@loongson.cn>
 <CA+fCnZevgYh7CzJ9gOWJ80SwY4Y9w8UO2ZiFAXEnAhQhFgrffA@mail.gmail.com>
From: Qing Zhang <zhangqing@loongson.cn>
Message-ID: <dccfbff3-7bad-de33-4d96-248bdff44a8b@loongson.cn>
Date: Thu, 30 Mar 2023 10:06:00 +0800
User-Agent: Mozilla/5.0 (X11; Linux mips64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CA+fCnZevgYh7CzJ9gOWJ80SwY4Y9w8UO2ZiFAXEnAhQhFgrffA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: AQAAf8AxHL6I7iRkjugQAA--.13156S3
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoW3Gw4rZr1UJF48tw1rtF1UJrb_yoW7WF4fpF
	yDGFy8AF4IqF1qga9rAr1Uur1UJwnak3WxKFs09r4rCa4UWrykJFyDWF9Iyrn3urW7AFya
	yws3Wa9xAw4jq3DanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	bxAYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_JrI_Jryl8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVWUCVW8JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVWUJVW8JwA2z4
	x0Y4vEx4A2jsIE14v26F4j6r4UJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS
	0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zVCFFI0UMc02F40EFcxC0V
	AKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUGVWUXwAv7VC2z280aVAFwI0_Jr0_Gr1l
	Ox8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JMxk0xIA0c2IEe2xFo4CEbIxvr21l42
	xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxVWUJVWU
	GwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r4a6rW5MIIYrxkI7VAKI4
	8JMIIF0xvE2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26r1j6r4U
	MIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I
	8E87Iv6xkF7I0E14v26r1j6r4UYxBIdaVFxhVjvjDU0xZFpf9x07URa0PUUUUU=
X-Original-Sender: zhangqing@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=zhangqing@loongson.cn
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

Hi, Andrey
On 2023/3/30 =E4=B8=8A=E5=8D=883:02, Andrey Konovalov wrote:
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index f7ef70661ce2..3b91b941873d 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -54,11 +54,13 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D=
];
>>   int kasan_populate_early_shadow(const void *shadow_start,
>>                                  const void *shadow_end);
>>
>> +#ifndef __HAVE_ARCH_SHADOW_MAP
>>   static inline void *kasan_mem_to_shadow(const void *addr)
>>   {
>>          return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT=
)
>>                  + KASAN_SHADOW_OFFSET;
>>   }
>> +#endif
>>
>>   int kasan_add_zero_shadow(void *start, unsigned long size);
>>   void kasan_remove_zero_shadow(void *start, unsigned long size);
>> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
>> index e5eef670735e..f86194750df5 100644
>> --- a/mm/kasan/generic.c
>> +++ b/mm/kasan/generic.c
>> @@ -175,6 +175,11 @@ static __always_inline bool check_region_inline(uns=
igned long addr,
>>          if (unlikely(!addr_has_metadata((void *)addr)))
>>                  return !kasan_report(addr, size, write, ret_ip);
>>
>> +#ifndef __HAVE_ARCH_SHADOW_MAP
>> +       if (unlikely(kasan_mem_to_shadow((unsigned long *)addr) =3D=3D N=
ULL))
>> +               return !kasan_report(addr, size, write, ret_ip);
>> +#endif
>=20
> This should have been ifdef, right?
>=20
Sorry, it was a clerical error,
Here it is
#ifndef __HAVE_ARCH_SHADOW_MAP
if (unlikely(! addr_has_metadata((void *)addr)))
return ! kasan_report(addr, size, write, ret_ip);
#else
if (unlikely(kasan_mem_to_shadow((void *)addr) =3D=3D NULL)) {
kasan_report(addr, size, write, ret_ip);
return;
}
#endif
> But I don't think you need this check here at all: addr_has_metadata
> already checks that shadow exists.
>=20
On LongArch, there's a lot of holes between different segments, so kasan
shadow area is some different type of memory that we concatenate, we
can't use if (unlikely((void *)addr <
kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) to determine the
validity, and in arch/loongarch/include/asm/kasan.h I construct invalid
NULL.
>> +
>>          if (likely(!memory_is_poisoned(addr, size)))
>>                  return true;
>>
>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>> index cc64ed6858c6..860061a22ca9 100644
>> --- a/mm/kasan/init.c
>> +++ b/mm/kasan/init.c
>> @@ -166,8 +166,9 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsig=
ned long addr,
>>                                  if (!p)
>>                                          return -ENOMEM;
>>                          } else {
>> -                               pud_populate(&init_mm, pud,
>> -                                       early_alloc(PAGE_SIZE, NUMA_NO_N=
ODE));
>> +                               p =3D early_alloc(PAGE_SIZE, NUMA_NO_NOD=
E);
>> +                               pmd_init(p);
>> +                               pud_populate(&init_mm, pud, p);
>>                          }
>>                  }
>>                  zero_pmd_populate(pud, addr, next);
>> @@ -207,8 +208,9 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsig=
ned long addr,
>>                                  if (!p)
>>                                          return -ENOMEM;
>>                          } else {
>> -                               p4d_populate(&init_mm, p4d,
>> -                                       early_alloc(PAGE_SIZE, NUMA_NO_N=
ODE));
>> +                               p =3D early_alloc(PAGE_SIZE, NUMA_NO_NOD=
E);
>> +                               pud_init(p);
>> +                               p4d_populate(&init_mm, p4d, p);
>=20
> Please explain why these changes are needed in the patch description.

This is because in pagetable_init on loongarch/mips, we populate pmd/pud
with invalid_pmd_table/invalid_pud_table,
So pmd_init/pud_init(p) is required, perhaps we define them as __weak in
mm/kasan/init.c, like mm/sparse-vmemmap.c.

diff --git a/include/linux/mm.h  b/include/linux/mm.h
...
+void pmd_init(void *addr);
+void pud_init(void *addr);
...
diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
...
+void __weak __meminit pmd_init(void *addr)
+ {
+}
+
@@-203,11 +207,16 @@pud_t * __meminit vmemmap_pud_populate(p4d_t *p4d,=20
unsigned long addr, int node)
void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE, node);
if (! p)
return NULL;
+               pmd_init(p);
pud_populate(&init_mm, pud, p);
}
return pud;
}
+void __weak __meminit pud_init(void *addr)
+ {
+}
+
p4d_t * __meminit vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr,=20
int node)
{
p4d_t *p4d =3D p4d_offset(pgd, addr);
@@-215,6 +224,7 @@p4d_t * __meminit vmemmap_p4d_populate(pgd_t *pgd,=20
unsigned long addr, int node)
void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE, node);
if (! p)
return NULL;
+               pud_init(p);
p4d_populate(&init_mm, p4d, p);
}
return p4d;

Thanks,
- Qing
>=20
>>                          }
>>                  }
>>                  zero_pud_populate(p4d, addr, next);
>> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
>> index a61eeee3095a..033335c13b25 100644
>> --- a/mm/kasan/kasan.h
>> +++ b/mm/kasan/kasan.h
>> @@ -291,16 +291,22 @@ struct kasan_stack_ring {
>>
>>   #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>>
>> +#ifndef __HAVE_ARCH_SHADOW_MAP
>>   static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>>   {
>>          return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFS=
ET)
>>                  << KASAN_SHADOW_SCALE_SHIFT);
>>   }
>> +#endif
>>
>>   static __always_inline bool addr_has_metadata(const void *addr)
>>   {
>> +#ifdef __HAVE_ARCH_SHADOW_MAP
>> +       return (kasan_mem_to_shadow((void *)addr) !=3D NULL);
>> +#else
>>          return (kasan_reset_tag(addr) >=3D
>>                  kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
>> +#endif
>>   }
>>
>>   /**
>> --
>> 2.20.1
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/dccfbff3-7bad-de33-4d96-248bdff44a8b%40loongson.cn.
