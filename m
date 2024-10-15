Return-Path: <kasan-dev+bncBAABBSVSW64AMGQE74YXZLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EBD499DC74
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 04:54:04 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-6e31e5d1739sf75244987b3.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 19:54:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728960843; cv=pass;
        d=google.com; s=arc-20240605;
        b=eyVEsaiW7A2+ew4vqGb1navPHfIVbEiu85VUDPCUeghuVxqX0bnNIzqsSQ/k/yS8dY
         V7bShfyx+bn12xevNe7lAGH0+FLvbY18KSy7OAW10E5NhNHA3BpZoyz3pIvn3zW2oALW
         8t/mvp2cVOkPHOoJSEC8PE+wk69j0ohMR1tjTyC9iOmznjUHvtEgl1HrjaOd8QfGZY+U
         xttnIOwFrYA6yaIqhS4EXrAt4OnJTXMzGDkiuv8hBth8uARCQpQ8R4oe+MLLVlYpfsO/
         Ik4Oh81vt2a8qgjppyZ5L52esh7+oEqfHCS3m1DY06mYwiOVQbAH7QUOOcQAkkr+40Fg
         atIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=6pk/C9/IfTr4qaPxB5RjgV2FifZCPnhDbnxbfu98wbE=;
        fh=eG7TQzIKUS8/W4WXbi0xkEh2rMuB/rvx+6eQKHccY/k=;
        b=DITp/CIhGALLGxjHT7IGWSQEHBWCScz8zq6+kG1G6mbBj9JnSkZYWgdUgYuXfFShke
         qIfmzbudn5qFYZ17VQZZ4PQx8BxxjDOxJa8OFVIavyHFatZK3T60RZf+ujj7LEFFzB09
         a3bWc94T51JUFOMLFOEmQBq4yjpO/T1M+Zr4BtCE4rY8S3Yz0ySDHXuRS+B6c3+JtBSy
         kx8H2YCOfFJTJnSkJzpizFi4HSqmRJ10gIjXJ21ekfzTzDscvLJAZgEbs2H+M191VtEf
         EqI5TimvpLBd5vQ64+BlGM6SCFcJGt0GkYLIf+i7q4quKcUoY1dX6oQ2+siyqpcKR92i
         SJlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728960843; x=1729565643; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6pk/C9/IfTr4qaPxB5RjgV2FifZCPnhDbnxbfu98wbE=;
        b=al+XZZecmpsorlBz531zgNzxrKklld5Vhux6l/T8HhQBZbZevF7ZHsb++mHY3FKhSA
         8W6e+9gJpR00VEpp2wSo7wZmF0+rHiBjCD0XcmxV8uIONLglJKPcfgwqywslYPV8qrAt
         sJCElUq+gKlqM1F2udXrY/eH6eTtFs+HoJd09Ga6GhTIQTv3DJ+m1clW541JOuD1cxQv
         JxM+fbU2KXTRbpX+3tYtm2//L6DboRnlY5+AbOQaEhedd+uPmGWcjdP8QfAcyQn4FT5f
         8vQ7qhdcWTWC72GBlBa6WvTe6KJ4NllB0XAupzVYbgE7LW6TSqWqruEG0jqn4vaJbbmB
         a/DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728960843; x=1729565643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6pk/C9/IfTr4qaPxB5RjgV2FifZCPnhDbnxbfu98wbE=;
        b=j5kUtyaPburLW5Fymk60Rm04vK4XyG33FxcYae3Aj6UAhASkZvS5rdnkS2RIbGTprI
         6TAYaVZt/ZAfduzuw4WRsCtX9JfhQHhE6ffumCkNkPpEtPPYXM4mujxDlazVX57k06n0
         uBSFdrmkCEhQC97iZduPYb1NwvqrT+Xm1nEhMsLExqmbp4aLSu6FpL66ARkal7iiZF6P
         jIyBGuxLLbgVhipY8fD+7t0D7JQQPRytKX4GBxDvhiQrEodt7GJUizl/xFDm4syosdSp
         V/ng+XzgkaxwqxrsnAOA3uTA+geK1zduvcUjqKjlwPYHwiVo5ZzplVf2v9BnHLPI66gm
         a8MQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6kfhRoN49yXdNSVTYWQevGWjoofBabgWemYRIQQPWZ3YHxWkvgcyoe9wW9CF0Y4N0kzzLHQ==@lfdr.de
X-Gm-Message-State: AOJu0YxOwceE0bgJVUDta313EXa9ldVkYXeQn1kb2NlPhKg2Lz/eM52K
	bYWGKvoFq9gkdQJqVCW399/qBdEUh3aHHVCMfTt8uFx9Em5xSYAf
X-Google-Smtp-Source: AGHT+IHaVMJ9KZ7zqwRCuCjh6Kg+07La+GuhxabZRsw1wGdQ/Xlmeb3gsRhPCdtyggkFvpIaKlbAuA==
X-Received: by 2002:a05:6902:1b01:b0:e28:f0e5:380b with SMTP id 3f1490d57ef6-e2931b00e80mr6921371276.4.1728960842877;
        Mon, 14 Oct 2024 19:54:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:704:b0:e1c:e3aa:57d1 with SMTP id
 3f1490d57ef6-e290bb9ea1fls278564276.2.-pod-prod-05-us; Mon, 14 Oct 2024
 19:54:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXUabUxF5V9JWJKIGi4rya9C/Kc8rAyfIn4WjGt43lo4TPn8K8j7MmHKABOIhz4lszqfhwUzaT7ELA=@googlegroups.com
X-Received: by 2002:a05:6902:70c:b0:e29:2fa2:fe92 with SMTP id 3f1490d57ef6-e2931b01110mr9417132276.5.1728960842159;
        Mon, 14 Oct 2024 19:54:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728960842; cv=none;
        d=google.com; s=arc-20240605;
        b=Dmp5ZxTMPJkNMVclmt09CDdhgdbNJjmBVwQjGsfQxi5LtqCpXTtNFf8Ip9g9Zna73t
         GT02COqmmBFdY/7YJE0YvYl+T4JVxCHQVotbz7Hn7Y+C6ECbOJZJdrVojGm+QucwY16J
         DX2Y12ekpTrNQE4hwORbN13S1n4ZMLFDjNUfVIhUtUeOOGKixggm9Cu4PDmDnK2UZNvL
         Glv2EdRpBmKyDs+NiRy3uOuAgV6/vDMFXgpeqAjnWkphJZ8NC1qtfpnRZJg3Q9ItRfuj
         lYxSdeRgdnzHeC/DGWphUg87gGZd2rsLZ4SpF4Rl1KLIiqHwqlJw3rwY6aSLD4dwrNci
         NR5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=antQz67lcCNued2pq+xEdHFbmajHIbSvTPFsRsj2B6Y=;
        fh=ocVjpFH1JzmNVfR49Byi2MWYGiGWER7Q25i+GX3k5Kg=;
        b=S2/1GQj7r5WwTvu2yjZWxHGmdQnDLh36kDlHadcqPTjIaWGyit0Vvft7dXEL3A1w/U
         n29cRtpcso96Bc/2IOW62mz5PoKjKVWosTwIN9st39/Np3j7jFDYeSUz5QdOQtkR7zkc
         LhlkqnayRmF2Y90sC6aHGaeUVZsppnKrQhVTlSKVF+Osuul854lq+VMPo54hKz/1/WQi
         49rFSytGiObNlfSy4yzpCQlRhOf13bkj6gYNTpW7R9r0pIWuUBidMyGPoBnm8Kj4tLav
         mx/D5RdCvCGmQrOATeGQQukaS/Ejoxz5wbo7guMuV/5UJmZ5rp3y6JdyYbwFYYHw82rD
         nK8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 3f1490d57ef6-e296d1894f0si22530276.4.2024.10.14.19.53.59
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2024 19:54:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.20.42.62])
	by gateway (Coremail) with SMTP id _____8BxTPBE2Q1niYkcAA--.45531S3;
	Tue, 15 Oct 2024 10:53:57 +0800 (CST)
Received: from [10.20.42.62] (unknown [10.20.42.62])
	by front1 (Coremail) with SMTP id qMiowMAxSeZB2Q1nClAqAA--.8242S3;
	Tue, 15 Oct 2024 10:53:56 +0800 (CST)
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
From: maobibo <maobibo@loongson.cn>
Message-ID: <e7c06bf4-897a-7060-61f9-97435d2af16e@loongson.cn>
Date: Tue, 15 Oct 2024 10:53:35 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAAhV-H6nkiw_eOS3jFdojJsCJOA2yiprQmaT5c=SnPhJTOyKkQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qMiowMAxSeZB2Q1nClAqAA--.8242S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBj93XoWxXw1ktw1kAFykJrWfWw15GFX_yoWrXF1Dpr
	W2kas8Krs7WF4fXw1jvr13Wr1kX3srWF18Jw1FvryDCwsrXFy29ryxWrW8Wry3Xa4rJa1x
	Cw4UKw15WFWUXFXCm3ZEXasCq-sJn29KB7ZKAUJUUUUf529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUUPIb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r106r15M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVWxJVW8Jr1l84ACjcxK6I8E87Iv6xkF7I0E14v2
	6r4UJVWxJr1ln4kS14v26r126r1DM2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12
	xvs2x26I8E6xACxx1l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r12
	6r1DMcIj6I8E87Iv67AKxVW8JVWxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr4
	1lc7I2V7IY0VAS07AlzVAYIcxG8wCY1x0262kKe7AKxVWUAVWUtwCF04k20xvY0x0EwIxG
	rwCFx2IqxVCFs4IE7xkEbVWUJVW8JwCFI7km07C267AKxVWUAVWUtwC20s026c02F40E14
	v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw0_GFylIxkG
	c2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUCVW8JwCI42IY6xIIjxv20xvEc7CjxVAFwI
	0_Jr0_Gr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r4j6F4U
	MIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07jFOJ5UUU
	UU=
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



On 2024/10/14 =E4=B8=8B=E5=8D=882:31, Huacai Chen wrote:
> Hi, Bibo,
>=20
> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.cn> w=
rote:
>>
>> It is possible to return a spurious fault if memory is accessed
>> right after the pte is set. For user address space, pte is set
>> in kernel space and memory is accessed in user space, there is
>> long time for synchronization, no barrier needed. However for
>> kernel address space, it is possible that memory is accessed
>> right after the pte is set.
>>
>> Here flush_cache_vmap/flush_cache_vmap_early is used for
>> synchronization.
>>
>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
>> ---
>>   arch/loongarch/include/asm/cacheflush.h | 14 +++++++++++++-
>>   1 file changed, 13 insertions(+), 1 deletion(-)
>>
>> diff --git a/arch/loongarch/include/asm/cacheflush.h b/arch/loongarch/in=
clude/asm/cacheflush.h
>> index f8754d08a31a..53be231319ef 100644
>> --- a/arch/loongarch/include/asm/cacheflush.h
>> +++ b/arch/loongarch/include/asm/cacheflush.h
>> @@ -42,12 +42,24 @@ void local_flush_icache_range(unsigned long start, u=
nsigned long end);
>>   #define flush_cache_dup_mm(mm)                         do { } while (0=
)
>>   #define flush_cache_range(vma, start, end)             do { } while (0=
)
>>   #define flush_cache_page(vma, vmaddr, pfn)             do { } while (0=
)
>> -#define flush_cache_vmap(start, end)                   do { } while (0)
>>   #define flush_cache_vunmap(start, end)                 do { } while (0=
)
>>   #define flush_icache_user_page(vma, page, addr, len)   do { } while (0=
)
>>   #define flush_dcache_mmap_lock(mapping)                        do { } =
while (0)
>>   #define flush_dcache_mmap_unlock(mapping)              do { } while (0=
)
>>
>> +/*
>> + * It is possible for a kernel virtual mapping access to return a spuri=
ous
>> + * fault if it's accessed right after the pte is set. The page fault ha=
ndler
>> + * does not expect this type of fault. flush_cache_vmap is not exactly =
the
>> + * right place to put this, but it seems to work well enough.
>> + */
>> +static inline void flush_cache_vmap(unsigned long start, unsigned long =
end)
>> +{
>> +       smp_mb();
>> +}
>> +#define flush_cache_vmap flush_cache_vmap
>> +#define flush_cache_vmap_early flush_cache_vmap
>  From the history of flush_cache_vmap_early(), It seems only archs with
> "virtual cache" (VIVT or VIPT) need this API, so LoongArch can be a
> no-op here.

Here is usage about flush_cache_vmap_early in file linux/mm/percpu.c,
map the page and access it immediately. Do you think it should be noop=20
on LoongArch.

rc =3D __pcpu_map_pages(unit_addr, &pages[unit * unit_pages],
                                      unit_pages);
if (rc < 0)
     panic("failed to map percpu area, err=3D%d\n", rc);
     flush_cache_vmap_early(unit_addr, unit_addr + ai->unit_size);
     /* copy static data */
     memcpy((void *)unit_addr, __per_cpu_load, ai->static_size);
}


>=20
> And I still think flush_cache_vunmap() should be a smp_mb(). A
> smp_mb() in flush_cache_vmap() prevents subsequent accesses be
> reordered before pte_set(), and a smp_mb() in flush_cache_vunmap()
smp_mb() in flush_cache_vmap() does not prevent reorder. It is to flush=20
pipeline and let page table walker HW sync with data cache.

For the following example.
   rb =3D vmap(pages, nr_meta_pages + 2 * nr_data_pages,
                   VM_MAP | VM_USERMAP, PAGE_KERNEL);
   if (rb) {
<<<<<<<<<<< * the sentence if (rb) can prevent reorder. Otherwise with=20
any API kmalloc/vmap/vmalloc and subsequent memory access, there will be=20
reorder issu. *
       kmemleak_not_leak(pages);
       rb->pages =3D pages;
       rb->nr_pages =3D nr_pages;
       return rb;
   }

> prevents preceding accesses be reordered after pte_clear(). This
Can you give an example about such usage about flush_cache_vunmap()? and=20
we can continue to talk about it, else it is just guessing.

Regards
Bibo Mao
> potential problem may not be seen from experiment, but it is needed in
> theory.
>=20
> Huacai
>=20
>> +
>>   #define cache_op(op, addr)                                            =
 \
>>          __asm__ __volatile__(                                          =
 \
>>          "       cacop   %0, %1                                  \n"    =
 \
>> --
>> 2.39.3
>>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e7c06bf4-897a-7060-61f9-97435d2af16e%40loongson.cn.
