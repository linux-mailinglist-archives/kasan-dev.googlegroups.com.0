Return-Path: <kasan-dev+bncBAABBFVRXW4AMGQEZBPQQRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 472D99A0118
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 08:09:28 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-e29bcb5591csf397745276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 23:09:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729058967; cv=pass;
        d=google.com; s=arc-20240605;
        b=jYqrweTuw45saXPaI/DI0obMegxOLdmCOC8N88gSfqPYQtTJuPUF/tIRn2F9lyNMxa
         HNmVWcEK3+hw0oeSPBJdzCdWVLkzvRecrkGC89tB3yX/t6d3uLMpG3GK+6TsfFbLPEjc
         OckIPOPZe7BnUim3o2xr6b6Gf4TiKXk9i7Ds3CU1kk9B2OYJWz+gqE+h4xIKcwc3i+C6
         fRJAmuacYYkpU+nFCjKHwGZNWvMA7ZMIPBAv9tReMjFZeAme6J+VYw5Pg7vUic0fY+RZ
         jtP7EjprqAyQb4JwW/LxxYw4jHjfy/3AbLZ3zKxSmHrfohdqfob2bESsQpFchbLNZSfF
         MvPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=eQzzT2qtHT14Wh/BX0U/vaxEKWxMH9pxlL0M2B7FYyI=;
        fh=cLxda15xFLLlaU0eEavr9q+I8bKh+VJIDisw9Y5D8UA=;
        b=TjApUnSMb8CsnFKE3ISIS4b9j0DURKaL6M5fE1znGsRSj2QrqiYe3Dbg1CHP+ImVcO
         v7+dAps2XM8e9s6ReiZ67vqGqsyH0fG6xKf+amd3DPWzWtmDNqldNmC/NIy5Q/+/v2i3
         xyUwDvVf1Qu0hoSRKa+cpuxWrGSnbKcEeaCxPOexUYm7UHKYtp3LFBMXIpuQ8tpt928u
         ccLI5bThqy/aecflR671X6n4Nw+waqN8/qoUEh5/aUybW2y4N18KYp13QcBwPfD23X4S
         3gNfol63RmjD0zGuy7iSnfT3U/trP3U6SrCflu/J0cZ9t8aHxrs7J7sWhlrKJewk5I53
         aMpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729058967; x=1729663767; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eQzzT2qtHT14Wh/BX0U/vaxEKWxMH9pxlL0M2B7FYyI=;
        b=LlJaRmY1IPzZTS/wXrwkeFMkPrfYI4QbcwCxBnD41BYk2AlEJ+qGHFJFs9HM/UM2eF
         tGNayGVU1ke+IpTq/EB+lPnd719/hbBldlt7CDEPsyTJAIaGCNiNty9i+NTqGA7GNMeb
         M7JoE+2j/bjhy4MYZZnATizxYH20RJF327DaVt4XAhymNT02XbJFsft7I8WH3hhxqPXo
         tRG4zJzJa8btFfopitEIavYJcMdz02i4ptMh1S/HKlsA4vt/rVCbhISa9NNYDlfWnVZ0
         mFsmhAHczUa0kES7xpvXE9jaBB/WLN3IEu0Fx3lJV7ypRsjGRmcYL8SdvQJmslNgaMjq
         Kx/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729058967; x=1729663767;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eQzzT2qtHT14Wh/BX0U/vaxEKWxMH9pxlL0M2B7FYyI=;
        b=hYm9ZwLHxNDqVo0/7Ebb08Ahs+i6WnmYmzMWpwMH1TQ4poEo6ekAsyPmgJdtYVwOZ9
         IbOpS2I2HD+VEo5P79o/pl/hFN1H9kTPn5Yyq00Q4+FT/JJ55v5vrEjnwBY61qiAjaCl
         w9yJy4YdXEvvdEspgmshKcfTgrENeZ76NF3+ByKTpvGu4Qz7Lm7jVgyGoanP3WqgJtuj
         J1Rx5hh7PKFRj+3dxHV9idJ1z5yq3XDkyzfJtNOVxJYbUoRHPGP1T3TFi5zcAp3CYbJp
         nTJ51J5UYKtfKMdnh4wLk+HK5knPPVdefyNbMFf8eVbRtkPksfy2rv25YmLy44y4zsHf
         VxYQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUvn7LTw53Qxuy9WGGfO9rEUIJ6P81M0aEsZoo0hzKFfrTVB1jJnNcBgBz0lIf4YdsUFgTQtA==@lfdr.de
X-Gm-Message-State: AOJu0YwGsFsjSjvUN3le44BM48bPQmJpVrDZynkZjZo/UsrRzFVSq7PU
	L6Qy+Cut9aQIgd7tZ/qTSTcgrf/s6m7ks8PU1bYWkejhWKSCJyNF
X-Google-Smtp-Source: AGHT+IFjJgPNxrdhlZ8PClcD4A1O7EF5o8jaaeKv757oVU9Z/8YjTw3xOWI46ULrvx4dTBxU0DI7bA==
X-Received: by 2002:a05:6902:1507:b0:e29:24c:1d82 with SMTP id 3f1490d57ef6-e2919df82d5mr14814730276.38.1729058966749;
        Tue, 15 Oct 2024 23:09:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:725:b0:e26:bea:956d with SMTP id
 3f1490d57ef6-e290bb7c45als346858276.2.-pod-prod-03-us; Tue, 15 Oct 2024
 23:09:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFpG56bgWYWVwb70SrOz3iXsbK0lbjq2cV8JnwRMorOTXapWNXGzlolrpSqf66MOYxH02ecA1JbKI=@googlegroups.com
X-Received: by 2002:a05:690c:670e:b0:647:7782:421a with SMTP id 00721157ae682-6e347c8df8cmr127800767b3.45.1729058965742;
        Tue, 15 Oct 2024 23:09:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729058965; cv=none;
        d=google.com; s=arc-20240605;
        b=NMoi1sHKk1oy+lJMEHtkcbEdGlmLOWj39G4cKMh62aMcvCqzzkR01mRi78iRYNxzpX
         WtYgkFRWdmuWPLYI0uT071ZaY7du9z2HHkWsQYyeA8VTGkWrb4p37VoVDryQiKIkC2PO
         sdXaP79wjx6m4bfaFV/eDa5eRycgNABd6/Q3b1n8E5iGa5Qus4DIgusETHZqRhrZtkB3
         Jx8TuNBMdFaaDxkJ0Y99qH8N0g4PPgSm9cdvAakxOrpDsnACpaEsYMXNcwzVQ/jIfPmr
         Vek9cuHAtg9veNmlszqpbhOWdlpQY1+guiqBVIA6OCFi4QajaVNNgbdeNKFIzr/GPqEU
         l/iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=s5GauQ51CQYdbsZdOQ6plFGnwMuUiYdffpMo6dLdCS8=;
        fh=ocVjpFH1JzmNVfR49Byi2MWYGiGWER7Q25i+GX3k5Kg=;
        b=LrGfJ5RljsHUzLdgNm5AkwkBkutZFUk0vauXZ1+pDfbnotHxiWx1RWKT6F4xW0xI3f
         XS1h3YWK14XVLmVu3WAOtxqAL8cD4Eo1CAJmSBMF/xOfqx7003BA3EnZBb9317r8sn3B
         4i5ByQ5QJkhRhOXS5ywe1cXf3vXV6PXDdOTwpvMHfHT967CQWPNV/VJKDyPhRqrZgEJe
         7np55hEG0KbaMdBWHcoe8iUwwkA0kGa+KDdk9CR725VwOYPcDCq31NW+b49xvVwb4Dn3
         ZrvPRLZRTDmMTXfdQ8ZzUNIphkb7evjUkYPHjh6V1HoF8o+PZIwks9uEs8Quskdn2iT5
         Ha3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 00721157ae682-6e3c5cce0bbsi1386237b3.2.2024.10.15.23.09.24
        for <kasan-dev@googlegroups.com>;
        Tue, 15 Oct 2024 23:09:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.20.42.62])
	by gateway (Coremail) with SMTP id _____8Dxn_GSWA9nToYfAA--.49988S3;
	Wed, 16 Oct 2024 14:09:22 +0800 (CST)
Received: from [10.20.42.62] (unknown [10.20.42.62])
	by front1 (Coremail) with SMTP id qMiowMDx_9ePWA9nMj8sAA--.15772S3;
	Wed, 16 Oct 2024 14:09:21 +0800 (CST)
Subject: Re: [PATCH v2 2/3] LoongArch: Add barrier between set_pte and memory
 access
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20241014035855.1119220-1-maobibo@loongson.cn>
 <20241014035855.1119220-3-maobibo@loongson.cn>
 <CAAhV-H6nkiw_eOS3jFdojJsCJOA2yiprQmaT5c=SnPhJTOyKkQ@mail.gmail.com>
 <e7c06bf4-897a-7060-61f9-97435d2af16e@loongson.cn>
 <CAAhV-H6H=Q=1KN5q8kR3j55Ky--FRNifCT93axhqE=vNMArDaQ@mail.gmail.com>
From: maobibo <maobibo@loongson.cn>
Message-ID: <1b4070c9-921e-65e3-c2a7-dab486d4f17f@loongson.cn>
Date: Wed, 16 Oct 2024 14:09:01 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAAhV-H6H=Q=1KN5q8kR3j55Ky--FRNifCT93axhqE=vNMArDaQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qMiowMDx_9ePWA9nMj8sAA--.15772S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBj93XoWxtr18CF4xtw18JF45Ww48AFc_yoW7AFW5pr
	W2k3Z8Kr4kXF1Fvw12vw1fWr1ft39rWFy8Xw1FqryDCw1qqFy29ry8WrW8uryxXa4rJa1x
	uw4Utr13WFWUJagCm3ZEXasCq-sJn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUUv2b4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVWxJVW8Jr1l84ACjcxK6I8E87Iv6xkF7I0E14v2
	6r4UJVWxJr1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44I27w
	Aqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_Jw0_WrylYx0Ex4A2jsIE
	14v26r4j6F4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvEwIxGrwCYjI0SjxkI62AI1c
	AE67vIY487MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8C
	rVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8Zw
	CIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r4j6ryUMIIF0xvE2Ix0cI8IcVCY1x02
	67AKxVW8JVWxJwCI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Gr
	0_Cr1lIxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7IU84x
	RDUUUUU==
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



On 2024/10/15 =E4=B8=8B=E5=8D=888:27, Huacai Chen wrote:
> On Tue, Oct 15, 2024 at 10:54=E2=80=AFAM maobibo <maobibo@loongson.cn> wr=
ote:
>>
>>
>>
>> On 2024/10/14 =E4=B8=8B=E5=8D=882:31, Huacai Chen wrote:
>>> Hi, Bibo,
>>>
>>> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.cn>=
 wrote:
>>>>
>>>> It is possible to return a spurious fault if memory is accessed
>>>> right after the pte is set. For user address space, pte is set
>>>> in kernel space and memory is accessed in user space, there is
>>>> long time for synchronization, no barrier needed. However for
>>>> kernel address space, it is possible that memory is accessed
>>>> right after the pte is set.
>>>>
>>>> Here flush_cache_vmap/flush_cache_vmap_early is used for
>>>> synchronization.
>>>>
>>>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
>>>> ---
>>>>    arch/loongarch/include/asm/cacheflush.h | 14 +++++++++++++-
>>>>    1 file changed, 13 insertions(+), 1 deletion(-)
>>>>
>>>> diff --git a/arch/loongarch/include/asm/cacheflush.h b/arch/loongarch/=
include/asm/cacheflush.h
>>>> index f8754d08a31a..53be231319ef 100644
>>>> --- a/arch/loongarch/include/asm/cacheflush.h
>>>> +++ b/arch/loongarch/include/asm/cacheflush.h
>>>> @@ -42,12 +42,24 @@ void local_flush_icache_range(unsigned long start,=
 unsigned long end);
>>>>    #define flush_cache_dup_mm(mm)                         do { } while=
 (0)
>>>>    #define flush_cache_range(vma, start, end)             do { } while=
 (0)
>>>>    #define flush_cache_page(vma, vmaddr, pfn)             do { } while=
 (0)
>>>> -#define flush_cache_vmap(start, end)                   do { } while (=
0)
>>>>    #define flush_cache_vunmap(start, end)                 do { } while=
 (0)
>>>>    #define flush_icache_user_page(vma, page, addr, len)   do { } while=
 (0)
>>>>    #define flush_dcache_mmap_lock(mapping)                        do {=
 } while (0)
>>>>    #define flush_dcache_mmap_unlock(mapping)              do { } while=
 (0)
>>>>
>>>> +/*
>>>> + * It is possible for a kernel virtual mapping access to return a spu=
rious
>>>> + * fault if it's accessed right after the pte is set. The page fault =
handler
>>>> + * does not expect this type of fault. flush_cache_vmap is not exactl=
y the
>>>> + * right place to put this, but it seems to work well enough.
>>>> + */
>>>> +static inline void flush_cache_vmap(unsigned long start, unsigned lon=
g end)
>>>> +{
>>>> +       smp_mb();
>>>> +}
>>>> +#define flush_cache_vmap flush_cache_vmap
>>>> +#define flush_cache_vmap_early flush_cache_vmap
>>>   From the history of flush_cache_vmap_early(), It seems only archs wit=
h
>>> "virtual cache" (VIVT or VIPT) need this API, so LoongArch can be a
>>> no-op here.
> OK,  flush_cache_vmap_early() also needs smp_mb().
>=20
>>
>> Here is usage about flush_cache_vmap_early in file linux/mm/percpu.c,
>> map the page and access it immediately. Do you think it should be noop
>> on LoongArch.
>>
>> rc =3D __pcpu_map_pages(unit_addr, &pages[unit * unit_pages],
>>                                        unit_pages);
>> if (rc < 0)
>>       panic("failed to map percpu area, err=3D%d\n", rc);
>>       flush_cache_vmap_early(unit_addr, unit_addr + ai->unit_size);
>>       /* copy static data */
>>       memcpy((void *)unit_addr, __per_cpu_load, ai->static_size);
>> }
>>
>>
>>>
>>> And I still think flush_cache_vunmap() should be a smp_mb(). A
>>> smp_mb() in flush_cache_vmap() prevents subsequent accesses be
>>> reordered before pte_set(), and a smp_mb() in flush_cache_vunmap()
>> smp_mb() in flush_cache_vmap() does not prevent reorder. It is to flush
>> pipeline and let page table walker HW sync with data cache.
>>
>> For the following example.
>>     rb =3D vmap(pages, nr_meta_pages + 2 * nr_data_pages,
>>                     VM_MAP | VM_USERMAP, PAGE_KERNEL);
>>     if (rb) {
>> <<<<<<<<<<< * the sentence if (rb) can prevent reorder. Otherwise with
>> any API kmalloc/vmap/vmalloc and subsequent memory access, there will be
>> reorder issu. *
>>         kmemleak_not_leak(pages);
>>         rb->pages =3D pages;
>>         rb->nr_pages =3D nr_pages;
>>         return rb;
>>     }
>>
>>> prevents preceding accesses be reordered after pte_clear(). This
>> Can you give an example about such usage about flush_cache_vunmap()? and
>> we can continue to talk about it, else it is just guessing.
> Since we cannot reach a consensus, and the flush_cache_* API look very
> strange for this purpose (Yes, I know PowerPC does it like this, but
> ARM64 doesn't). I prefer to still use the ARM64 method which means add
> a dbar in set_pte(). Of course the performance will be a little worse,
> but still better than the old version, and it is more robust.
>=20
> I know you are very busy, so if you have no time you don't need to
> send V3, I can just do a small modification on the 3rd patch.
No, I will send V3 by myself. And I will drop the this patch in this=20
patchset since by actual test vmalloc_test works well even without this
patch on 3C5000 Dual-way, also weak function kernel_pte_init will be=20
replaced with inline function rebased on
=20
https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patche=
s/mm-define-general-function-pxd_init.patch

I dislike the copy-paste method without further understanding :(,=20
although I also copy and paste code, but as least I try best to=20
understand it.

Regards
Bibo Mao
>=20
>=20
> Huacai
>=20
>>
>> Regards
>> Bibo Mao
>>> potential problem may not be seen from experiment, but it is needed in
>>> theory.
>>>
>>> Huacai
>>>
>>>> +
>>>>    #define cache_op(op, addr)                                         =
    \
>>>>           __asm__ __volatile__(                                       =
    \
>>>>           "       cacop   %0, %1                                  \n" =
    \
>>>> --
>>>> 2.39.3
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
kasan-dev/1b4070c9-921e-65e3-c2a7-dab486d4f17f%40loongson.cn.
