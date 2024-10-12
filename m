Return-Path: <kasan-dev+bncBAABBK6HU64AMGQEDETVEII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E35B99B03B
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 04:49:17 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3a3b4395dedsf16800315ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 19:49:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728701356; cv=pass;
        d=google.com; s=arc-20240605;
        b=f4r+TL+7xv2jyLkLziuzhsNyvEW87UFBCEi+pPoOdHLcEkwniBeOwONF4Kz1S0NWb/
         N3p4lUj8jQ4RG5Rql53U3UP2yj8Xr80Has5IgarKCGNNwvaThPffN5JZiJrlcSR5YhF8
         eeySZXvb//vcWGMsAKG093gI0HBNnrhHoOeEGhQInV2wdJVzDdo9CmSFsBNmvpLGXWc1
         WWSCn/NWAi3rWknSbUUdvWjBuzb3mHE8yVaSKW9In1eDP7hqbUsfcNN5TPG5c7GTuQil
         1oPEAvo5Zur8v86AqcNGqljuOFAg6EfKvMWXK6cAiIC/McKcxkoToH7N3hXZnQuWcOMy
         wvHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=MwpwSalHyIo9g+cAJ7+f4Qdmo8uJykGeJ06k7uJYeXQ=;
        fh=dWDVqJN+MYLipkdqv525yd7+z0UDSoI+cNF2DZwLULQ=;
        b=fc6VOovDAvMCHrEqXc3g0IX6Cm4ZTT0FS4wFALDnDlbuznz89/N1E+1BQscvuE0ft0
         uQ1GpSPeyfSMT+eqHSaCV2jnjC8FbXIneglxL19c4Zgq1J2MBDhkH3vkgCJEJLVAqmmy
         o13nSKjqeI503WFQjSOoINRk+1EA2oClej35eI74KW50qie2ZocPDujQatk9bIeS/Lgc
         BflfEvD/8+Kym3byjKJvgaVG1QeL60A5mkrxLF976o8qUoLWMltNRF6ZerW4xfuijErC
         STGJahwi33Im+P1pc0UOC2tOkHn9qcKz+15sB5gjYjOmiCoV3F2ThUGCsUW5rjA7EhMK
         xkXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728701356; x=1729306156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MwpwSalHyIo9g+cAJ7+f4Qdmo8uJykGeJ06k7uJYeXQ=;
        b=vsVesbMj48xZeoTMT5htiJNaD2oHo2JW2zljMk8VL4Qd/Vt1tpB3wAZyNMFHAw0Ysc
         JJshd+F9QZllRrfsk96EapSGDrg8cMJYxFUrvX3BzWKfoMCWIeMrQlvQlQ0MpQQLeGL2
         Uq3JsnwsvddzRxXgSUPXTAWPARGheug3iLI6D91dH31R36gFc892YrFjV9ZUgHpkWLYV
         GlMtMR0qfjj4+rAUzn7LrWqzdHmQo5pmuN7GXrzAkZPFbrz5qE5Fc3c9xQGiEuhjlUC2
         xXtZj3/uKcFN6CYbh5O8JUDhrjCG4Z8t/1ADkuAm6Mo75ckJPWLzyDbw6hA1P/EI5Qq7
         FhKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728701356; x=1729306156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MwpwSalHyIo9g+cAJ7+f4Qdmo8uJykGeJ06k7uJYeXQ=;
        b=IzviTE7+T/SPuEnOW0yBxxMck5ThzgG+wWYJQosL8AHNvzg9NDJMJOcoubIHPwg5Zs
         5kleToZZFz3C6TtyTfAZfz3dc2fnHxb2hBOf4GwuNy3rBiQsq0gk3DbMmOdCjPTGWDOD
         C5jtU7BXOnRt8Wlr7k2J1ZgraqabSCJ6DrGRa7o42VC5GEumgwaZgXXTbWJd8uFI5yjC
         F7iF2GTNcLTdSP3fYVn49LrRLgU5sqPamwMiTIac9b+bemL1xzynuBWXVqu6E0w2/sfY
         yyTc2eUrpYtsGgfTNR2wcQmutKxtHbtEi7CeGdpTL1HHNkYe9XPbga72R0dQndyhcutD
         6brg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXqVzwj+R+m2gD84KAMrlW7dajFlCXVsST8tILm4TY1OyGMOtpEQxPHkqdZu0t1lX2fJdka6g==@lfdr.de
X-Gm-Message-State: AOJu0Yxk6h1tMQ9Fu25JyMRtu4pGOHV+fWLj0Zx6PdgpwmIf2tAzintt
	Rfg4oi8fEzDQMCOcgQoc+mDBJeAxRAoVusIbqyjio8hxnFj5rT0I
X-Google-Smtp-Source: AGHT+IFZfBB9lZQ/6dnmiSWZANeLsiVtAesAFlZJL9ebbHX3vd3Xt4hdVQVMXzxA1DVP1ikz7Ud3vg==
X-Received: by 2002:a92:c241:0:b0:3a2:91f:497b with SMTP id e9e14a558f8ab-3a3b5fa76f0mr43335335ab.13.1728701356075;
        Fri, 11 Oct 2024 19:49:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1805:b0:3a1:96f6:f0f2 with SMTP id
 e9e14a558f8ab-3a3a7428207ls18153665ab.1.-pod-prod-02-us; Fri, 11 Oct 2024
 19:49:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUkrQ1H5o/7UXvqNf9NgV10tAlG2esK/AYD2O6ERB64+6dUgk+L7/mSm1K51XHMnNnmF3+k3t+7YO4=@googlegroups.com
X-Received: by 2002:a05:6e02:180e:b0:3a3:b3f4:af42 with SMTP id e9e14a558f8ab-3a3b5f86635mr39716405ab.7.1728701355297;
        Fri, 11 Oct 2024 19:49:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728701355; cv=none;
        d=google.com; s=arc-20240605;
        b=ii15/Y/pgMQHplC71RK4fo6WQI46kh0izHoAim/RtoI10GJv9R3IwfgTUhPYDXzyoC
         Mekc/sG/LLSz9tsmeCjIZ8k1OcolWBrXljEf5NCIDXTnQ0WPLN52dLzlcZfjpOpVA+rA
         BaWR4IQ7G8Ne3xCqzHmb1L9dzw8bC6XxRtLVdneeIaAGjo2WGSh8+ERSiK0rA9OEc0/D
         92pz7Ovj393oWjO+DQtde8W0Qmxymwa8rQ7lOSrjA8A5bRlkFcPiZpCEwo/CRU6scCea
         98nV5XPiWp6xikc06emJXhmW6PREwkXJJlYuBXH2AcUIucmPnAja4dDfxdCHVVM77gDj
         +dkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=EgfVMQ505JhtZRIyJWfm34fHt7zMejpm4MBtyVmSdqo=;
        fh=ocVjpFH1JzmNVfR49Byi2MWYGiGWER7Q25i+GX3k5Kg=;
        b=HW5XpzU/2qifKzVTQ++wa0Isj1KSQkQQNek+NeOCMAu5fV4k0TTP2bB5Rn17PdXHdk
         YAdY1qFj8q7X2il9/ABZ/HIxKf0DQ3gN2OcEaqeXWbJyvp8HyZysEgQvJaPHvq+bWO8c
         5NRY0Z0OvIVi42MERKR/rQoAp+9UK5BBD5JhUpG4ZC7iN8EWgdqiMXKA6Gb+diSFliCn
         2PiANHyZs0l9TbiLTJg9xu9b/kuMWfdnZtg+UNv2tdNk7h03SFJSMc4bNSZ0mjj8QEVm
         8nIG/mvw1R4m5nlmSME21uG5J7TLiH+vBIPKIlIJzDKqiDsC3i2kGjjHmElumpoAF/jb
         Fpzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id e9e14a558f8ab-3a3afdec443si2064805ab.4.2024.10.11.19.49.14
        for <kasan-dev@googlegroups.com>;
        Fri, 11 Oct 2024 19:49:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.20.42.62])
	by gateway (Coremail) with SMTP id _____8Bxkuin4wlnL2oUAA--.30137S3;
	Sat, 12 Oct 2024 10:49:11 +0800 (CST)
Received: from [10.20.42.62] (unknown [10.20.42.62])
	by front1 (Coremail) with SMTP id qMiowMDx_9en4wlnIaAkAA--.51933S3;
	Sat, 12 Oct 2024 10:49:11 +0800 (CST)
Subject: Re: [PATCH 3/4] LoongArch: Add barrier between set_pte and memory
 access
To: Huacai Chen <chenhuacai@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20241010035048.3422527-1-maobibo@loongson.cn>
 <20241010035048.3422527-4-maobibo@loongson.cn>
 <CAAhV-H6OR_HYSF451vSk_qSt1a6froSPZKY-=YSRBQgww5a+0A@mail.gmail.com>
From: maobibo <maobibo@loongson.cn>
Message-ID: <1141ad15-26ae-71a9-9f6f-26671d01a30e@loongson.cn>
Date: Sat, 12 Oct 2024 10:48:53 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAAhV-H6OR_HYSF451vSk_qSt1a6froSPZKY-=YSRBQgww5a+0A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qMiowMDx_9en4wlnIaAkAA--.51933S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBj93XoWxCr13WF4fZry7Kr43Wry7twc_yoW5Aw48pr
	y2k3Z8Krs7WF4fJw1jvr1rWr18X39rWF1xK3ySvryUCw1DXF12gryrWws5ury7Xa4rJa1x
	u3yUK345WFWUAagCm3ZEXasCq-sJn29KB7ZKAUJUUUU8529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUUvYb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r1Y6r17M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVWxJVW8Jr1l84ACjcxK6I8E87Iv6xkF7I0E14v2
	6r4j6r4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zVCFFI0UMc
	02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUtVWrXwAv7VC2z280aVAF
	wI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JMxk0xIA0c2IEe2xFo4
	CEbIxvr21l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG
	67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r1q6r43MI
	IYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_JFI_Gr1lIxAIcVC0I7IYx2IY6xkF7I0E
	14v26r1j6r4UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87Iv67AKxVWUJV
	W8JwCI42IY6I8E87Iv6xkF7I0E14v26r1j6r4UYxBIdaVFxhVjvjDU0xZFpf9x07josjUU
	UUUU=
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
> I don't know whether this is the best API to do this, and I think
> flush_cache_vunmap() also should be a smp_mb().
I do not know neither -:(, it seems that flush_cache_vmap() is better=20
than arch_sync_kernel_mappings(), since function flush_cache_vmap() is=20
used in vmalloc/kasan/percpu module, however arch_sync_kernel_mappings
is only used in vmalloc.

For flush_cache_vunmap(), it is used before pte_clear(), here is usage=20
example.
void vunmap_range(unsigned long addr, unsigned long end)
{
         flush_cache_vunmap(addr, end);
         vunmap_range_noflush(addr, end);
         flush_tlb_kernel_range(addr, end);
}

So I think it is not necessary to add smp_mb() in flush_cache_vunmap().

Regards
Bibo Mao
>=20
>=20
> Huacai
>=20
>> +#define flush_cache_vmap flush_cache_vmap
>> +#define flush_cache_vmap_early flush_cache_vmap
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

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1141ad15-26ae-71a9-9f6f-26671d01a30e%40loongson.cn.
