Return-Path: <kasan-dev+bncBC447XVYUEMRBRMDWGDAMGQEV7C5M4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4296F3AC442
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 08:48:38 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id h104-20020adf90710000b029010de8455a3asf3952943wrh.12
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 23:48:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623998918; cv=pass;
        d=google.com; s=arc-20160816;
        b=oso9LulAIuhMp9o3cHG0cyBOY3cmkf3+ICzn4WptI31ndOLbHUQjja3NUSyvBekqV3
         9xgRF+e1H0SRJBeKIPYX3AgDTzkbceZqJ4pZ03QsY3JXYHc7oURjh2itnR4cuKYP9/+e
         u70/L2ZINjDYEVp7lX7CAK0L1EAEojVAkCwBqlf3POr9TPdW+lZGT2GTcoRKKriR5+k5
         L86F5nXyrTrs13Gx7zkRb3cRku6T3TbAFbBV9JPtwT+N+Wizi3wLl5mahaOe2uPWNG1X
         Uo8IxTTkdG3v4z8DQqH6IgbV3A140zlK0CsQi39PY3wlwCa5iZFfcH9PoJA+psT6cINA
         jZog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=g2rluZuLGG/cvlpVY5yqCiELJ7r/ReulwWqOSSC4HY4=;
        b=nOWX77zqiccvsMsOG1tC8mhcYG5SRHiv7yAnlJbQfB6+0WzRQqhnLnRzqmtBlkwfCs
         wukcFjyOtxMST64Ze6gWXAhUu42P7+s9UtiepNIJnGrc06Qh14JBO8wGk8AWCPI8q8c3
         Xie7i0Aqxgtk8/0yXStJBbA00CpY6tqfpzjwsPqZ3pof1pEB6crNevgBEVqC7O552RgN
         9wu7iRuDign/W39zJHXvfpKeFos7bD23c2V9NwnXIrNBcSAwqVSh4eFYmCgcrGxjr/Df
         weA8HwX8UmbfYymRP3ivkLniicPrU4/uaQmCjVQRU3Oa89xUNwL9QG/KIDiyrKl0MFhG
         m3Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g2rluZuLGG/cvlpVY5yqCiELJ7r/ReulwWqOSSC4HY4=;
        b=KzGVSnEqBFTSAMONlgaenqpSdafiv3QvEcj73st8blHOP7Rzv7+MPmA/86KUdLvEIY
         Uf9uDHudQkUn9085hFSaF6aE8K5+rSg5/FuIYyCRRbCxllBSXN/sI7XFbckvIXbw7Ti/
         /Ze7z7Xwk0Yf+st8Ef+SbDa+nXmPiCw+TKbWa2F0FbRxvC3ckgG+zPBwXGG+rNb7YoFz
         K4YaFTz821uIlDZdNF2vXubwb1zaI4bKISCgVn6iay8hYO1DfZyMEo/ZPByJ7YIPsHKG
         V9XXhipna4LqQ4KU3yPP6t5V3Sz9T1z9e5omXgg+kIf4g70Yj5A9M1IwJBoRXRrH1u92
         iclg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g2rluZuLGG/cvlpVY5yqCiELJ7r/ReulwWqOSSC4HY4=;
        b=OzI8sgtDvLbZbdqkjDwcU+spozPC7it++HnFz+n4sBqSbfFMEdSNl6ugyaOEtGdQ6a
         Kfr+CFThzkQ8nri4LXgJF8pm2/gYLEsfppC8nAEP0uWNUNby5ujSMax8/Tt0D3XNau44
         ltJ9P6PHYDFloUB3v4zc1pDLcH79+haICBsUR/pQeCTpYICuOsVFjuJAhCVty4Xy9+uU
         bUdqmXEQGic8YSyHHeSGcHYw3pkGmvglVMYLDDrNcg081UYBhXZtnmVCq5zvIdy9ChR4
         /FK0f7DYbV0Doux+MH91e8qaUjvaXIgy4JckLS6znkz5np8N/QTrC5Bl9TPhfH+LyqmM
         mxyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5329m58keKP4WJ5hXtsREkXF6Ob+c01R9m550kG7Dxx0eGXM3xZ4
	KdZWqZafNUfRxrFt5VhWoxg=
X-Google-Smtp-Source: ABdhPJyujQ7903Vk6LFW1MAB0Pjww6Eov+e4NWH5IY3QAZ2qkdDI3au+ClShTEL9jCS2VG/me+lFOA==
X-Received: by 2002:a5d:5182:: with SMTP id k2mr10654613wrv.262.1623998917941;
        Thu, 17 Jun 2021 23:48:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6945:: with SMTP id r5ls1772081wrw.2.gmail; Thu, 17 Jun
 2021 23:48:37 -0700 (PDT)
X-Received: by 2002:a05:6000:1367:: with SMTP id q7mr10583856wrz.306.1623998917072;
        Thu, 17 Jun 2021 23:48:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623998917; cv=none;
        d=google.com; s=arc-20160816;
        b=r9vochPmIIQhwSL3rQbGGxPOjy6BTSNXt/O+oD9txbiS1DkUEQeAaKrGvdo4eoI9sc
         llYiuWIgayUz7cL6ZH1fPolG5w62k3V4nbcKD+rETAAlbYDY21TUYhjc7N4sQTHaH7bL
         ol4CVIzinvcfHqg33rWS2tYYaVxYcF4qp8x6CT2SMNQrcQEM4lHRA+x+xGjyQ95oM6GL
         HHlnOO1SBcNz9xGHxdr99Cr+O+yTkqwr9ULzptNhlWT7j5qxaAelsfh5445ZzhaLQBJ/
         PLJLhTHXhIyZBza/WIzOB+D1exgNw+7PDBkTebGjp3MTo6ZEeA/aT1Ynw+9P6z89mOZr
         Ty7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=TZ9zEq0cSJ4Ch/JAFShJ169r/R+HVyfkmecPCN7dcsM=;
        b=hF2Q/xmnoaLw3FH4/gwQK1NiOEeR12njhgg8NVL83i7wJ79XDdYr7pdDg3lufDJALt
         V72xjgK7ShuW3xFcRD9VNj53Vuqj9u+6FIsBxb33PJ+hOCaNlb3yaCa2VRtkPouNxWHa
         lJoxWUko5seO48AzaZmZy0x5CbSZRLX+XriSk1WDFQi75mzJ3qQuMit82cSdwji02rRI
         +xNqvCx4uQSdKL+MqY9/TxW+WIseJLUZzaD8riFezvr0c/ysm3PqPtpJp+eKGazBaluP
         Bx/xrLVCKcCfa0fS2N0CesMb5C2WXy9XtuaSxFyFG2mUad/YXBqvqnmCmSRMbM+Uo194
         X6Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id c26si477045wmr.1.2021.06.17.23.48.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 17 Jun 2021 23:48:36 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id 8F2072000D;
	Fri, 18 Jun 2021 06:48:28 +0000 (UTC)
Subject: Re: [PATCH v2] riscv: Ensure BPF_JIT_REGION_START aligned with PMD
 size
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>,
 Palmer Dabbelt <palmer@dabbelt.com>, schwab@linux-m68k.org,
 Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
 ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, bjorn@kernel.org, ast@kernel.org, andrii@kernel.org,
 kafai@fb.com, songliubraving@fb.com, yhs@fb.com, john.fastabend@gmail.com,
 kpsingh@kernel.org, luke.r.nels@gmail.com, xi.wang@gmail.com
Cc: daniel@iogearbox.net, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 netdev@vger.kernel.org, bpf@vger.kernel.org
References: <mhng-042979fe-75f0-4873-8afd-f8c07942f792@palmerdabbelt-glaptop>
 <ae256a5d-70ac-3a5f-ca55-5e4210a0624c@ghiti.fr>
 <50ebc99c-f0a2-b4ea-fc9b-cd93a8324697@ghiti.fr>
 <20210618012731.345657bf@xhacker> <20210618014648.1857a62a@xhacker>
 <20210618021038.52c2f558@xhacker> <20210618021535.29099c75@xhacker>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <058cfd88-07f0-8079-51dc-928fe9ee4fdb@ghiti.fr>
Date: Fri, 18 Jun 2021 08:48:27 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <20210618021535.29099c75@xhacker>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.200 is neither permitted nor denied by best guess
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

Le 17/06/2021 =C3=A0 20:15, Jisheng Zhang a =C3=A9crit=C2=A0:
> Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid breaking W^X")
> breaks booting with one kind of defconfig, I reproduced a kernel panic
> with the defconfig:
>=20
> [    0.138553] Unable to handle kernel paging request at virtual address =
ffffffff81201220
> [    0.139159] Oops [#1]
> [    0.139303] Modules linked in:
> [    0.139601] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.13.0-rc5-defau=
lt+ #1
> [    0.139934] Hardware name: riscv-virtio,qemu (DT)
> [    0.140193] epc : __memset+0xc4/0xfc
> [    0.140416]  ra : skb_flow_dissector_init+0x1e/0x82
> [    0.140609] epc : ffffffff8029806c ra : ffffffff8033be78 sp : ffffffe0=
01647da0
> [    0.140878]  gp : ffffffff81134b08 tp : ffffffe001654380 t0 : ffffffff=
81201158
> [    0.141156]  t1 : 0000000000000002 t2 : 0000000000000154 s0 : ffffffe0=
01647dd0
> [    0.141424]  s1 : ffffffff80a43250 a0 : ffffffff81201220 a1 : 00000000=
00000000
> [    0.141654]  a2 : 000000000000003c a3 : ffffffff81201258 a4 : 00000000=
00000064
> [    0.141893]  a5 : ffffffff8029806c a6 : 0000000000000040 a7 : ffffffff=
ffffffff
> [    0.142126]  s2 : ffffffff81201220 s3 : 0000000000000009 s4 : ffffffff=
81135088
> [    0.142353]  s5 : ffffffff81135038 s6 : ffffffff8080ce80 s7 : ffffffff=
80800438
> [    0.142584]  s8 : ffffffff80bc6578 s9 : 0000000000000008 s10: ffffffff=
806000ac
> [    0.142810]  s11: 0000000000000000 t3 : fffffffffffffffc t4 : 00000000=
00000000
> [    0.143042]  t5 : 0000000000000155 t6 : 00000000000003ff
> [    0.143220] status: 0000000000000120 badaddr: ffffffff81201220 cause: =
000000000000000f
> [    0.143560] [<ffffffff8029806c>] __memset+0xc4/0xfc
> [    0.143859] [<ffffffff8061e984>] init_default_flow_dissectors+0x22/0x6=
0
> [    0.144092] [<ffffffff800010fc>] do_one_initcall+0x3e/0x168
> [    0.144278] [<ffffffff80600df0>] kernel_init_freeable+0x1c8/0x224
> [    0.144479] [<ffffffff804868a8>] kernel_init+0x12/0x110
> [    0.144658] [<ffffffff800022de>] ret_from_exception+0x0/0xc
> [    0.145124] ---[ end trace f1e9643daa46d591 ]---
>=20
> After some investigation, I think I found the root cause: commit
> 2bfc6cd81bd ("move kernel mapping outside of linear mapping") moves
> BPF JIT region after the kernel:
>=20
> The &_end is unlikely aligned with PMD size, so the front bpf jit
> region sits with part of kernel .data section in one PMD size mapping.
> But kernel is mapped in PMD SIZE, when bpf_jit_binary_lock_ro() is
> called to make the first bpf jit prog ROX, we will make part of kernel
> .data section RO too, so when we write to, for example memset the
> .data section, MMU will trigger a store page fault.
>=20
> To fix the issue, we need to ensure the BPF JIT region is PMD size
> aligned. This patch acchieve this goal by restoring the BPF JIT region
> to original position, I.E the 128MB before kernel .text section. The
> modification to kasan_init.c is inspired by Alexandre.
>=20
> Reported-by: Andreas Schwab <schwab@linux-m68k.org>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> ---
>=20
> Since v1:
>   - Fix early boot hang when kasan is enabled
>   - Update Documentation/riscv/vm-layout.rst
>=20
>   Documentation/riscv/vm-layout.rst |  4 ++--
>   arch/riscv/include/asm/pgtable.h  |  5 ++---
>   arch/riscv/mm/kasan_init.c        | 10 +++++-----
>   3 files changed, 9 insertions(+), 10 deletions(-)
>=20
> diff --git a/Documentation/riscv/vm-layout.rst b/Documentation/riscv/vm-l=
ayout.rst
> index 329d32098af4..b7f98930d38d 100644
> --- a/Documentation/riscv/vm-layout.rst
> +++ b/Documentation/riscv/vm-layout.rst
> @@ -58,6 +58,6 @@ RISC-V Linux Kernel SV39
>                                                                 |
>     ____________________________________________________________|________=
____________________________________________________
>                       |            |                  |         |
> -   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules
> -   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel, =
BPF
> +   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules,=
 BPF
> +   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel
>     __________________|____________|__________________|_________|________=
____________________________________________________
> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pg=
table.h
> index 9469f464e71a..380cd3a7e548 100644
> --- a/arch/riscv/include/asm/pgtable.h
> +++ b/arch/riscv/include/asm/pgtable.h
> @@ -30,9 +30,8 @@
>  =20
>   #define BPF_JIT_REGION_SIZE	(SZ_128M)
>   #ifdef CONFIG_64BIT
> -/* KASLR should leave at least 128MB for BPF after the kernel */
> -#define BPF_JIT_REGION_START	PFN_ALIGN((unsigned long)&_end)
> -#define BPF_JIT_REGION_END	(BPF_JIT_REGION_START + BPF_JIT_REGION_SIZE)
> +#define BPF_JIT_REGION_START	(BPF_JIT_REGION_END - BPF_JIT_REGION_SIZE)
> +#define BPF_JIT_REGION_END	(MODULES_END)
>   #else
>   #define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
>   #define BPF_JIT_REGION_END	(VMALLOC_END)
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 9daacae93e33..d7189c8714a9 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -169,7 +169,7 @@ static void __init kasan_shallow_populate(void *start=
, void *end)
>  =20
>   void __init kasan_init(void)
>   {
> -	phys_addr_t _start, _end;
> +	phys_addr_t p_start, p_end;


IMHO this fix deserves its own patch, it is not related to the issue you=20
describe in the changelog and has been around for some time.

That's too bad BPF people did not answer my question regarding BPF <->=20
modules calls: I'll ask the question directly in kasan-dev mailing list=20
and add you in cc.


>   	u64 i;
>  =20
>   	/*
> @@ -189,9 +189,9 @@ void __init kasan_init(void)
>   			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
>  =20
>   	/* Populate the linear mapping */
> -	for_each_mem_range(i, &_start, &_end) {
> -		void *start =3D (void *)__va(_start);
> -		void *end =3D (void *)__va(_end);
> +	for_each_mem_range(i, &p_start, &p_end) {
> +		void *start =3D (void *)__va(p_start);
> +		void *end =3D (void *)__va(p_end);
>  =20
>   		if (start >=3D end)
>   			break;
> @@ -201,7 +201,7 @@ void __init kasan_init(void)
>  =20
>   	/* Populate kernel, BPF, modules mapping */
>   	kasan_populate(kasan_mem_to_shadow((const void *)MODULES_VADDR),
> -		       kasan_mem_to_shadow((const void *)BPF_JIT_REGION_END));
> +		       kasan_mem_to_shadow((const void *)MODULES_VADDR + SZ_2G));
>  =20
>   	for (i =3D 0; i < PTRS_PER_PTE; i++)
>   		set_pte(&kasan_early_shadow_pte[i],
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/058cfd88-07f0-8079-51dc-928fe9ee4fdb%40ghiti.fr.
