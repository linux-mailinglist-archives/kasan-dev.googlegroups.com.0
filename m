Return-Path: <kasan-dev+bncBCTJ7DM3WQOBBUV2UKDAMGQEU73XZ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 754143A7E34
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 14:30:10 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id b8-20020a170906d108b02903fa10388224sf4480496ejz.18
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 05:30:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623760210; cv=pass;
        d=google.com; s=arc-20160816;
        b=SdqSx9/Cm26NbMgWSPUQ/Wdz8pw50MNiGIhmwfPIsBuyjlltPe3gLiAfQdB4GogF1+
         pVvxMzjXlwcSF1QuXeB7qhR25abNwpd1CZbIEJDD9PMgHTcgTDtp0/Y+CIWjo9HWkZmQ
         A45ATIjlK9ohkSv3wgFhUScAsdL1ibQ/1hXzeV018kxZHV8WG+lX5yLa0f5xDOeGy0tx
         qAIhv9niwwvB9J7LpOXuT1T4joCnsc0yyH2HWryLq16IBn61UDAm5m8NqU1AStjx4gyG
         IrXXm7cqxwaZIGX/auTlJvZeAOM9WdrqJUesZBL/XUmxJRXElfLSd+OnyElJLsUd3eCy
         +WAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=xTC4Tj7xvozIDVSEjEQ97AmaFIQlHCmb4Dw9A2916A8=;
        b=uxNSNBw02Opuwdc+lvEqw0/5CHDDlJgQrJS1S/0yYhAGNiCXiH5hjXp/hjHrI2S9lR
         B2IxbvKbhWfHMl1yVWG/Lnc2AQAR2XUsz1A1DWqb3bWK4SMKLL8+HanVg4F8aXHgwV5x
         W4VSAax+m2nt3w8I6oJT+Qm7iKgLCm4qz50fAwdvUIKsIJaOGyRgT5dV1YZyPJ8n6Zc1
         aORXWlPmEvQ00Ajadkfwtm1h3GfY6SXzqlPD2aVBRf2Vc6k2XGGu6V+w6Vg49EUKmzhB
         3wuuP5oa8B1VKW45Y2PzhDwvr3ogsZkcaBxcl7FEWtWUWYZgXqr8NO9pOuFHR+hxNoaF
         ALZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xTC4Tj7xvozIDVSEjEQ97AmaFIQlHCmb4Dw9A2916A8=;
        b=WEGUE67uIVPGKGL9rF+F9PKxAjOWkFQMPugQtZZgmdUosAJhU2CR3I80XBGk2HCk6+
         MokpnUefrYPOftOhYIkNk6YKCwXJUWBdVlBQQ/dvmlR2s2siA2a5Ur5gIV3+Mlt694iM
         5c/QM3QA86tKHowOEWGyGCBFbPKF9Hr3GfUv+H3cBV37CPWdZaZrc6f+u0Gkl+7w4MgE
         luri1c+Z82fjd+6RA0OtyhK/fgrb1k9HFdqbJj2XSZrpGKSZe6/t+9/hw3YLNXSDpfmU
         W0dzikdY+fur1oxx+aW6U2n3R9q3OxHkEnQiSHdljUzqw41o0NnCput4UesYZFC2YgMZ
         56sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xTC4Tj7xvozIDVSEjEQ97AmaFIQlHCmb4Dw9A2916A8=;
        b=Domc1/zhIXftV382WNOnTbml1aOqBOemBFL3z0VYGMljBldH/y2P/XzZGp0sTf2vY1
         81kRfA1QD0IiJ13HJyvSaCgn7LCm7GHzBF/Ehshuat9pSbNH4/RG8eO0QXSzyIik0XVl
         kmNy1H37izvBzBpozfwGKUY1ZBwb5CxnCEnEW90OZR7OPh57kztbq9fRwlq6KxVN5qmW
         Ox127vV8rkNvECITt8in1RFoS0PXsgQXhagvr2/q1zUIyPBOywgsDILGx187sVJ4i3/f
         ZUM+ni960aiPfkN3STb+SHx5AoubnAgV6AdrRnM4x5lXbZIxm0KVHfe7mcvrmSy6Zbe9
         F7Dw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y3mPFIZV17eOUsr2nyJEyV/QekulnSavq53pCoYbjRt+IOe8u
	L2UxqIkEfYAFRgiE5AO8i2U=
X-Google-Smtp-Source: ABdhPJyD7F3QMU29GnHN5TsDpNZc/SarE2xQLhLex4q8Mi9SjRHUyO+lbqsrdgjwZZgvttVjtOrE7Q==
X-Received: by 2002:a17:907:e90:: with SMTP id ho16mr2392146ejc.410.1623760210275;
        Tue, 15 Jun 2021 05:30:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1c97:: with SMTP id cy23ls10044522edb.0.gmail; Tue,
 15 Jun 2021 05:30:09 -0700 (PDT)
X-Received: by 2002:aa7:d898:: with SMTP id u24mr22479326edq.172.1623760209415;
        Tue, 15 Jun 2021 05:30:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623760209; cv=none;
        d=google.com; s=arc-20160816;
        b=c2/sJHBPlw96bxOV0Favl+QbHMx5BPhzg5VlzhxYuOUFvehIsCvM29rDbtpG1xBLRx
         egEwGYvvFcr6QsTZwCnUQx7hl5LYvL0XlEJeOquBXztSJzHOQZYHDM0CGTCz7wjuBkv/
         aed8lE05cU50XGvBXmAskcUeqeq+A788vSogWps7NzW34ekdFMfEPXVTpyaB8VLZFnWm
         aaIEj/30NJnWpgcgDYNONGRPhWwjodYrtSTjRsPmD+AlvXGo4156AFWtWYnQJaqTgEYY
         FuCFya3dsFWQWWcTkHcsHcd4QLG211fzA/w7HZXKexlza0cD97SRMEAXMwONbcOl65OL
         ebdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=GPaGSXHMa1l9c8olABaqUqDl8cs4eNfRWtkkwPkhABg=;
        b=uPdgDvWJ4CIKiGVBGoujp04YkP+svtXzypaF+ioeDpiLNe/mRAhePduKypVfda246g
         ZzNRzdDCFdHzVYsTogiHCuj+ZHDHIFhS/G41sFYCZijTZMqyg5bb/teZs1pwSxoWTIEx
         2F6lam1qRiUzIZaFffqdLJ1Dv9MNwNmitUDESayBNccEfVKHS/J/RjfQztEDfjtGNsgL
         ItRy1VZQcU5kh8+RLFWSbipn7I+BpZXLs4hBmbyJkq4TyLm9gKLR3fFRfAz3WgnLpbIM
         HRncvYB/aMcd2rCDa5L3Fe/oLQTHCxxH+Cocxm4TillLf0puG/m70dcD8hYSpRg4VNXX
         f35w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
Received: from www62.your-server.de (www62.your-server.de. [213.133.104.62])
        by gmr-mx.google.com with ESMTPS id s9si124343edw.4.2021.06.15.05.30.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jun 2021 05:30:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) client-ip=213.133.104.62;
Received: from sslproxy02.your-server.de ([78.47.166.47])
	by www62.your-server.de with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)
	(Exim 4.92.3)
	(envelope-from <daniel@iogearbox.net>)
	id 1lt8CZ-000G4r-Ko; Tue, 15 Jun 2021 14:29:55 +0200
Received: from [85.7.101.30] (helo=linux-3.home)
	by sslproxy02.your-server.de with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <daniel@iogearbox.net>)
	id 1lt8CZ-0005iV-78; Tue, 15 Jun 2021 14:29:55 +0200
Subject: Re: [PATCH] riscv: Ensure BPF_JIT_REGION_START aligned with PMD size
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>,
 Andreas Schwab <schwab@linux-m68k.org>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>,
 Alexei Starovoitov <ast@kernel.org>, Andrii Nakryiko <andrii@kernel.org>,
 Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>,
 Yonghong Song <yhs@fb.com>, John Fastabend <john.fastabend@gmail.com>,
 KP Singh <kpsingh@kernel.org>, Luke Nelson <luke.r.nels@gmail.com>,
 Xi Wang <xi.wang@gmail.com>, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 netdev@vger.kernel.org, bpf@vger.kernel.org
References: <20210330022144.150edc6e@xhacker>
 <20210330022521.2a904a8c@xhacker> <87o8ccqypw.fsf@igel.home>
 <20210612002334.6af72545@xhacker> <87bl8cqrpv.fsf@igel.home>
 <20210614010546.7a0d5584@xhacker> <87im2hsfvm.fsf@igel.home>
 <20210615004928.2d27d2ac@xhacker>
From: Daniel Borkmann <daniel@iogearbox.net>
Message-ID: <3c7ec52d-7fa3-dfac-239c-989ea1cc37ee@iogearbox.net>
Date: Tue, 15 Jun 2021 14:29:54 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <20210615004928.2d27d2ac@xhacker>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Authenticated-Sender: daniel@iogearbox.net
X-Virus-Scanned: Clear (ClamAV 0.103.2/26202/Tue Jun 15 13:21:24 2021)
X-Original-Sender: daniel@iogearbox.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as
 permitted sender) smtp.mailfrom=daniel@iogearbox.net
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

On 6/14/21 6:49 PM, Jisheng Zhang wrote:
> From: Jisheng Zhang <jszhang@kernel.org>
> 
> Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid breaking W^X")
> breaks booting with one kind of config file, I reproduced a kernel panic
> with the config:
> 
> [    0.138553] Unable to handle kernel paging request at virtual address ffffffff81201220
> [    0.139159] Oops [#1]
> [    0.139303] Modules linked in:
> [    0.139601] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.13.0-rc5-default+ #1
> [    0.139934] Hardware name: riscv-virtio,qemu (DT)
> [    0.140193] epc : __memset+0xc4/0xfc
> [    0.140416]  ra : skb_flow_dissector_init+0x1e/0x82
> [    0.140609] epc : ffffffff8029806c ra : ffffffff8033be78 sp : ffffffe001647da0
> [    0.140878]  gp : ffffffff81134b08 tp : ffffffe001654380 t0 : ffffffff81201158
> [    0.141156]  t1 : 0000000000000002 t2 : 0000000000000154 s0 : ffffffe001647dd0
> [    0.141424]  s1 : ffffffff80a43250 a0 : ffffffff81201220 a1 : 0000000000000000
> [    0.141654]  a2 : 000000000000003c a3 : ffffffff81201258 a4 : 0000000000000064
> [    0.141893]  a5 : ffffffff8029806c a6 : 0000000000000040 a7 : ffffffffffffffff
> [    0.142126]  s2 : ffffffff81201220 s3 : 0000000000000009 s4 : ffffffff81135088
> [    0.142353]  s5 : ffffffff81135038 s6 : ffffffff8080ce80 s7 : ffffffff80800438
> [    0.142584]  s8 : ffffffff80bc6578 s9 : 0000000000000008 s10: ffffffff806000ac
> [    0.142810]  s11: 0000000000000000 t3 : fffffffffffffffc t4 : 0000000000000000
> [    0.143042]  t5 : 0000000000000155 t6 : 00000000000003ff
> [    0.143220] status: 0000000000000120 badaddr: ffffffff81201220 cause: 000000000000000f
> [    0.143560] [<ffffffff8029806c>] __memset+0xc4/0xfc
> [    0.143859] [<ffffffff8061e984>] init_default_flow_dissectors+0x22/0x60
> [    0.144092] [<ffffffff800010fc>] do_one_initcall+0x3e/0x168
> [    0.144278] [<ffffffff80600df0>] kernel_init_freeable+0x1c8/0x224
> [    0.144479] [<ffffffff804868a8>] kernel_init+0x12/0x110
> [    0.144658] [<ffffffff800022de>] ret_from_exception+0x0/0xc
> [    0.145124] ---[ end trace f1e9643daa46d591 ]---
> 
> After some investigation, I think I found the root cause: commit
> 2bfc6cd81bd ("move kernel mapping outside of linear mapping") moves
> BPF JIT region after the kernel:
> 
> The &_end is unlikely aligned with PMD size, so the front bpf jit
> region sits with part of kernel .data section in one PMD size mapping.
> But kernel is mapped in PMD SIZE, when bpf_jit_binary_lock_ro() is
> called to make the first bpf jit prog ROX, we will make part of kernel
> .data section RO too, so when we write to, for example memset the
> .data section, MMU will trigger a store page fault.
> 
> To fix the issue, we need to ensure the BPF JIT region is PMD size
> aligned. This patch acchieve this goal by restoring the BPF JIT region
> to original position, I.E the 128MB before kernel .text section.
> 
> Reported-by: Andreas Schwab <schwab@linux-m68k.org>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> ---
>   arch/riscv/include/asm/pgtable.h | 5 ++---
>   1 file changed, 2 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
> index 9469f464e71a..380cd3a7e548 100644
> --- a/arch/riscv/include/asm/pgtable.h
> +++ b/arch/riscv/include/asm/pgtable.h
> @@ -30,9 +30,8 @@
>   
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

I presume this fix will be routed via riscv tree?

Thanks,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3c7ec52d-7fa3-dfac-239c-989ea1cc37ee%40iogearbox.net.
