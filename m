Return-Path: <kasan-dev+bncBC447XVYUEMRBY7QVODAMGQE2CGKCCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id AF1573AAD69
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 09:23:16 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id y5-20020a2e9d450000b02900f6299549d1sf2288815ljj.22
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 00:23:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623914596; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vqdnu41hzm2MMuhggcPmlqWsmZ7MvRix0BpPrryCH0ZMKXqtm2JCo/NuXhVqndxL0m
         v5JS+xfIotSoCmg8v4UH8LTnQhjrsjHai8CCjeH1BIDiD0E7HR3Nu695DAQo4fMtarpO
         4nIg5+XjHG+Tvw5xVrSRgpG+pwG8F3mP9uxUV63jPQrWp95QfQy99TdsaTn5W2EJIquY
         sMR/Q6PaptGp0veD+sMu+CyzFM3FYqQjf6AXgr1c5AU7D9fLc0G57FI1KihwD6e61PBB
         qfaejFgOxVIfyUuTKflZa6oOUx7PItXObKPTveq/ENJ3uMv1t6I8JhClF34TRQzQmLCc
         qW6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=Swv8LtMTnm6VXO1hD4uTVjuWjPovgDvmPzDqmhioRnI=;
        b=SdXddu82LOYjJBwLwkKBbat0QlDYPASj58GPErUOc/+kwjRi9JvGdj8i+DSvOzTfF2
         a/nfXjpzuBd4XK9inXcYmIKGpi78Us83MEhPpdS5nJNK9uz22qd+dx9zIVtwAFlktNAo
         TRvtgUCkd6ZZ/Cy/wSWPwn6EKWeyvmnNwGPNRtnz0M8WhmNaY610jq8hXRVK0mIQzcmh
         j6npt82gUlI4m9Ub1qYdAj8hFdz/dSuciEavNmXBer+3/MX3bbn9YO7SDdFOSIjrh63/
         8XrADF/n3MXfAG0xWp68u5p3Rm7mA4PZQ6GTun8M2LiVAe6fz2NNEdkPp3l8AIleCNwq
         wH/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Swv8LtMTnm6VXO1hD4uTVjuWjPovgDvmPzDqmhioRnI=;
        b=BFLN1u7285iUrYaqgZDKMQGuYszKEEEDqf64Vt/turnaDPVvgL91m64SYs4q4o1rQV
         fCUYqMGvvOCI5T3bB6fx+5rRCt4ZCDHL7tOt2VagbUQ+s91HA9bV8S/p5fN5TV41La5W
         1naeLJtBxndNBxC+SnyxJcFTZr4QJtJC0OCuZrHaTZxne+NR9ZTacn2EmoA7ZAgzDF67
         E4IdE14BG1NeZfqLCRaKXkjVVxDO3btfUYUEVi9VKz441JSGLSmNxYw+Jhj8uBBdJS2J
         rVEHqVszJVwFpBAYe77x3f12Q0TFK8j7FeEtCF34Gu6vv9Kz9XcvVNQ7tVV/RfYy8xXx
         EfWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Swv8LtMTnm6VXO1hD4uTVjuWjPovgDvmPzDqmhioRnI=;
        b=lgEUAVJiggNeEj2qrnx1ov910SsGUeyiIC+YERYRGelchh8Y1qr+OO0LQ7cmeELgqy
         b/pM89yGtQcTwcNxu2x5YephtdShUm1x4mw3RcqlfR5HcQ6erW7OVS6qGZDa3TlWfn/R
         GMJGJE9dQiCQCBjV1AmcZKqMDPGAPmmrT/qkaihqakvyxWbcnIyez8Wdob/1qo4cVyzF
         6HgkzjJWl4iBbGK/2edEGIMlOVYjwabIZ09m59M1RdX5CC6bmPvM9+MZ5O1NFaNr3H21
         vRm+QbUb7dcrq0eTa17z1mJSceN+n9ec1qGYroE359QQK1vp5CfHZW5BJEEcDshjw+fS
         ZIAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gqvxFt2+LTeVULMNYZijA0PjV0jk8PwbPI0RVeNql5AfE0q8h
	TBdxGh1dQGz3CD+Ch09qJW4=
X-Google-Smtp-Source: ABdhPJxy6ijhDj8BydV+OAn0Ci9MPTFs/YLknxNJ1+4NUEcne/7zoFisdqRKHGUn07uebW1ckRONrg==
X-Received: by 2002:a19:a406:: with SMTP id q6mr2906431lfc.616.1623914596217;
        Thu, 17 Jun 2021 00:23:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b54c:: with SMTP id a12ls1134627ljn.5.gmail; Thu, 17 Jun
 2021 00:23:15 -0700 (PDT)
X-Received: by 2002:a2e:8ec2:: with SMTP id e2mr3227360ljl.446.1623914595143;
        Thu, 17 Jun 2021 00:23:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623914595; cv=none;
        d=google.com; s=arc-20160816;
        b=rEAPyxi0pu3huJBMbL74el0yn5JnRDPVkq4afSRF8mmjLxgkfA/TPk5Tvb+g30nicA
         r0xsmmkI1RJ3mYjFK3/8IM/2FurEC30R7lcYAB9JSy3QFsVO9wkMVQ/d6UtZKTsdhAxR
         ka1ksuCOd4/A2Ca5X2hjsMN6vj+5gEwIjBUh65U+7d47bmHLU1tQ+QZBaAnVIjZ7lPnm
         5SRmS3E8U6UcINSA91p7F1BHhkDV6zcCS4uBwrp/LAi36ILxxeGdQZijC6ToVOTjF/dM
         HeGuZbMXxbmXj+GTNyJTUbLVaqsx97CP3V7EMRPjjfbfLfs0C7O5sA3L2Qvz6QOUFcTD
         LBog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=WIlxqyimA2aPzYPvZDvzsXn05AcmKkMfn5Mwe4pp7jE=;
        b=jzO+8CoptKCJGdbIeHp0+8OiveIXH/iYoYktq4pSsjWvbZUvkSDXxIrcEBJuoU491+
         qaz2cEI89aLXumw9fvtOx206nmAD46MTsYEMe2oKcWQMSJaiIpEzSvIEl7LMI4ecwk2V
         +B2lUjyOT9KWS7PCJxLekKCGyXeJT7T0EZnLLAuLyMSrfY2buUiinc7NrQ7B1oGoAnZi
         Rnv+J2skVUIJHTktvxIN9hg7GElowS8+HoADBM1sIANGuIqkWq8CEq2Y0R1ZepCbDVC2
         hvNvaQeeS9K+0CcQJBJXeb8e0iu52JaPohrDVMLwynUhHn0hbkTQy1ui4j9zVtrKHqes
         1y3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id q10si189942lfo.11.2021.06.17.00.23.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 17 Jun 2021 00:23:14 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id E10C7240008;
	Thu, 17 Jun 2021 07:23:04 +0000 (UTC)
Subject: Re: [PATCH] riscv: Ensure BPF_JIT_REGION_START aligned with PMD size
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Cc: Andreas Schwab <schwab@linux-m68k.org>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>,
 Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>,
 Andrii Nakryiko <andrii@kernel.org>, Martin KaFai Lau <kafai@fb.com>,
 Song Liu <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>,
 John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>,
 Luke Nelson <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
References: <20210330022144.150edc6e@xhacker>
 <20210330022521.2a904a8c@xhacker> <87o8ccqypw.fsf@igel.home>
 <20210612002334.6af72545@xhacker> <87bl8cqrpv.fsf@igel.home>
 <20210614010546.7a0d5584@xhacker> <87im2hsfvm.fsf@igel.home>
 <20210615004928.2d27d2ac@xhacker>
 <ab536c78-ba1c-c65c-325a-8f9fba6e9d46@ghiti.fr>
 <20210616080328.6548e762@xhacker>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <4cdb1261-6474-8ae6-7a92-a3be81ce8cb5@ghiti.fr>
Date: Thu, 17 Jun 2021 09:23:04 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <20210616080328.6548e762@xhacker>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Le 16/06/2021 =C3=A0 02:03, Jisheng Zhang a =C3=A9crit=C2=A0:
> On Tue, 15 Jun 2021 20:54:19 +0200
> Alex Ghiti <alex@ghiti.fr> wrote:
>=20
>> Hi Jisheng,
>=20
> Hi Alex,
>=20
>>
>> Le 14/06/2021 =C3=A0 18:49, Jisheng Zhang a =C3=A9crit=C2=A0:
>>> From: Jisheng Zhang <jszhang@kernel.org>
>>>
>>> Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid breaking W^X")
>>> breaks booting with one kind of config file, I reproduced a kernel pani=
c
>>> with the config:
>>>
>>> [    0.138553] Unable to handle kernel paging request at virtual addres=
s ffffffff81201220
>>> [    0.139159] Oops [#1]
>>> [    0.139303] Modules linked in:
>>> [    0.139601] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.13.0-rc5-def=
ault+ #1
>>> [    0.139934] Hardware name: riscv-virtio,qemu (DT)
>>> [    0.140193] epc : __memset+0xc4/0xfc
>>> [    0.140416]  ra : skb_flow_dissector_init+0x1e/0x82
>>> [    0.140609] epc : ffffffff8029806c ra : ffffffff8033be78 sp : ffffff=
e001647da0
>>> [    0.140878]  gp : ffffffff81134b08 tp : ffffffe001654380 t0 : ffffff=
ff81201158
>>> [    0.141156]  t1 : 0000000000000002 t2 : 0000000000000154 s0 : ffffff=
e001647dd0
>>> [    0.141424]  s1 : ffffffff80a43250 a0 : ffffffff81201220 a1 : 000000=
0000000000
>>> [    0.141654]  a2 : 000000000000003c a3 : ffffffff81201258 a4 : 000000=
0000000064
>>> [    0.141893]  a5 : ffffffff8029806c a6 : 0000000000000040 a7 : ffffff=
ffffffffff
>>> [    0.142126]  s2 : ffffffff81201220 s3 : 0000000000000009 s4 : ffffff=
ff81135088
>>> [    0.142353]  s5 : ffffffff81135038 s6 : ffffffff8080ce80 s7 : ffffff=
ff80800438
>>> [    0.142584]  s8 : ffffffff80bc6578 s9 : 0000000000000008 s10: ffffff=
ff806000ac
>>> [    0.142810]  s11: 0000000000000000 t3 : fffffffffffffffc t4 : 000000=
0000000000
>>> [    0.143042]  t5 : 0000000000000155 t6 : 00000000000003ff
>>> [    0.143220] status: 0000000000000120 badaddr: ffffffff81201220 cause=
: 000000000000000f
>>> [    0.143560] [<ffffffff8029806c>] __memset+0xc4/0xfc
>>> [    0.143859] [<ffffffff8061e984>] init_default_flow_dissectors+0x22/0=
x60
>>> [    0.144092] [<ffffffff800010fc>] do_one_initcall+0x3e/0x168
>>> [    0.144278] [<ffffffff80600df0>] kernel_init_freeable+0x1c8/0x224
>>> [    0.144479] [<ffffffff804868a8>] kernel_init+0x12/0x110
>>> [    0.144658] [<ffffffff800022de>] ret_from_exception+0x0/0xc
>>> [    0.145124] ---[ end trace f1e9643daa46d591 ]---
>>>
>>> After some investigation, I think I found the root cause: commit
>>> 2bfc6cd81bd ("move kernel mapping outside of linear mapping") moves
>>> BPF JIT region after the kernel:
>>>
>>> The &_end is unlikely aligned with PMD size, so the front bpf jit
>>> region sits with part of kernel .data section in one PMD size mapping.
>>> But kernel is mapped in PMD SIZE, when bpf_jit_binary_lock_ro() is
>>> called to make the first bpf jit prog ROX, we will make part of kernel
>>> .data section RO too, so when we write to, for example memset the
>>> .data section, MMU will trigger a store page fault.
>>
>> Good catch, we make sure no physical allocation happens between _end and
>> the next PMD aligned address, but I missed this one.
>>
>>>
>>> To fix the issue, we need to ensure the BPF JIT region is PMD size
>>> aligned. This patch acchieve this goal by restoring the BPF JIT region
>>> to original position, I.E the 128MB before kernel .text section.
>>
>> But I disagree with your solution: I made sure modules and BPF programs
>> get their own virtual regions to avoid worst case scenario where one
>> could allocate all the space and leave nothing to the other (we are
>> limited to +- 2GB offset). Why don't just align BPF_JIT_REGION_START to
>> the next PMD aligned address?
>=20
> Originally, I planed to fix the issue by aligning BPF_JIT_REGION_START, b=
ut
> IIRC, BPF experts are adding (or have added) "Calling kernel functions fr=
om BPF"
> feature, there's a risk that BPF JIT region is beyond the 2GB of module r=
egion:
>=20
> ------
> module
> ------
> kernel
> ------
> BPF_JIT
>=20
> So I made this patch finally. In this patch, we let BPF JIT region sit
> between module and kernel.
>=20

 From what I read in the lwn article, I'm not sure BPF programs can call=20
module functions, can someone tell us if it is possible? Or planned?

> To address "make sure modules and BPF programs get their own virtual regi=
ons",
> what about something as below (applied against this patch)?
>=20
> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pg=
table.h
> index 380cd3a7e548..da1158f10b09 100644
> --- a/arch/riscv/include/asm/pgtable.h
> +++ b/arch/riscv/include/asm/pgtable.h
> @@ -31,7 +31,7 @@
>   #define BPF_JIT_REGION_SIZE	(SZ_128M)
>   #ifdef CONFIG_64BIT
>   #define BPF_JIT_REGION_START	(BPF_JIT_REGION_END - BPF_JIT_REGION_SIZE)
> -#define BPF_JIT_REGION_END	(MODULES_END)
> +#define BPF_JIT_REGION_END	(PFN_ALIGN((unsigned long)&_start))
>   #else
>   #define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
>   #define BPF_JIT_REGION_END	(VMALLOC_END)
> @@ -40,7 +40,7 @@
>   /* Modules always live before the kernel */
>   #ifdef CONFIG_64BIT
>   #define MODULES_VADDR	(PFN_ALIGN((unsigned long)&_end) - SZ_2G)
> -#define MODULES_END	(PFN_ALIGN((unsigned long)&_start))
> +#define MODULES_END	(BPF_JIT_REGION_END)
>   #endif
>  =20
>=20

In case it is possible, I would let the vmalloc allocator handle the=20
case where modules steal room from BPF: I would then not implement the=20
above but rather your first patch.

And do not forget to modify Documentation/riscv/vm-layout.rst=20
accordingly and remove the comment "/* KASLR should leave at least 128MB=20
for BPF after the kernel */"

Thanks,

Alex

>=20
>>
>> Again, good catch, thanks,
>>
>> Alex
>>
>>>
>>> Reported-by: Andreas Schwab <schwab@linux-m68k.org>
>>> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
>>> ---
>>>    arch/riscv/include/asm/pgtable.h | 5 ++---
>>>    1 file changed, 2 insertions(+), 3 deletions(-)
>>>
>>> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/=
pgtable.h
>>> index 9469f464e71a..380cd3a7e548 100644
>>> --- a/arch/riscv/include/asm/pgtable.h
>>> +++ b/arch/riscv/include/asm/pgtable.h
>>> @@ -30,9 +30,8 @@
>>>   =20
>>>    #define BPF_JIT_REGION_SIZE	(SZ_128M)
>>>    #ifdef CONFIG_64BIT
>>> -/* KASLR should leave at least 128MB for BPF after the kernel */
>>> -#define BPF_JIT_REGION_START	PFN_ALIGN((unsigned long)&_end)
>>> -#define BPF_JIT_REGION_END	(BPF_JIT_REGION_START + BPF_JIT_REGION_SIZE=
)
>>> +#define BPF_JIT_REGION_START	(BPF_JIT_REGION_END - BPF_JIT_REGION_SIZE=
)
>>> +#define BPF_JIT_REGION_END	(MODULES_END)
>>>    #else
>>>    #define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
>>>    #define BPF_JIT_REGION_END	(VMALLOC_END)
>>>   =20
>=20
>=20
>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4cdb1261-6474-8ae6-7a92-a3be81ce8cb5%40ghiti.fr.
