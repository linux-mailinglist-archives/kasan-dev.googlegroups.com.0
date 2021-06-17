Return-Path: <kasan-dev+bncBCRKNY4WZECBBHPUVODAMGQE6IJZQYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id C96803AAD93
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 09:30:38 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id p190-20020a625bc70000b02902fb3dbe05a2sf3194249pfb.21
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 00:30:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623915037; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fjc8dQdJ80/JE/HXwlLLv/eumBjp/TlBqeGC90Cskh8dvgDt2so6LU2RS24Z4whB/V
         vK166ny7ykvRMyG34BmnEbSM2Hnmxui9Gh68mDgp5xzwso1jA7OIMReygerWWBrcN8Ly
         Yr+WLo9BuyNE9YyDeNlC6M7+BwRA9JINnnPLBHEN0BT423nBJbe/ea4Pv4NN0b99VpXx
         kOqpe1gKCT48qqZCe2E50WSspcuWnSx5OXAjH6Ymy+EdB/Wb4muZhWh5KIOvIZKDDvkx
         4yC10uIfhaXjvkSh22T93sn0HInkJkfcTXID8HjaBtJ5qnCT8MS15dusl7++XlwrGrfZ
         Mp0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:to:from:cc:in-reply-to:subject:date:sender
         :dkim-signature;
        bh=WMqMMqxmvaRohe7Q00IOxflYg3slhR2XpcfyEf6V3ZM=;
        b=KeVDZwMr/GAVP2Brf9iUCVP8r7GWSyQE+ePcQ0+i1ibUA+KrnpJtF93nCXWGM42k7D
         zJXIok3u8obM9kUqXJmOlodyBE204Zl05HajLgqkYWQmpCAzUHLVXCp6jeuT+GDIraLD
         8EIDXRSNOKWrnqct08dhStWrhS3czUw6IaEPJuskEAdV0zLw7pCcLF/k+K5OGkslDgwp
         ubsJe+zDK1lQacWvYxD0qNo6VyIEcYqeyFuaBl7E4m4O7QnC8+eyp3c0qsFmjmu3XMM/
         CwIzhTSvkhFvrEm9xOmOG8WnVHnFKO09tE8ati2PP3+PS4GJFI0IgN6GQMP5V8jE0zXH
         J5xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b="GibhX/x+";
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WMqMMqxmvaRohe7Q00IOxflYg3slhR2XpcfyEf6V3ZM=;
        b=Mwksu7ljU7o8VGGzqAZn9hT3PZZMzr5JwymcKfqC2UVDrDcKQu4DLa+KNXF546Mchz
         gw9F6kfeHgcsZkYVozD8trneNLjPUiWbnj6liSgbr9AWwEyUszVIsFXId9z0qTJeOo43
         CXfrDgqRJYGg/C7y1zayTEIg4J/QTmd9LXjclTGxjKpHQwNRSGeQex+mFxATP4ofdB+n
         mG84pe/a5Uu5xs9jQoniZMs+Y8pEcL0wIkkMs5RLGFEpy+AvZ48Cbvt39w+ARZm7XMEE
         MnZxdhgwrkfJGrOyKSz51vdlCEm42gveKHLyPdSsHTntjsFVOZpMLwFliwoB3UQ0U3E1
         tFYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WMqMMqxmvaRohe7Q00IOxflYg3slhR2XpcfyEf6V3ZM=;
        b=eN7MUKQArn09Ws7L8fXPS8kYzbowawRmCyFC2kfqQF0iO4oH7VAdlx7OagIjbvk3QU
         zlzn1ysbLiGVGmhZgcMDy4nc7B2voK5YAu/TLufBh96igftz4rl+YGuWAhFr7Zkrn6pq
         OeUd4k04wu4FO88Dm+7g96mc+zkIcrGj6lxwAHt+EEkPh/y/4O2QGKfwBXf4upBD9mEs
         M61oSgqIrDMBwKx8Kx4xX/RWpcg3VPLXrg1/aS10F6GkxC5R3u3p4hMzHDGPriac5KvS
         HUg4u0jqs4KLRqs/SUrVcLpI24I+dC5WNwJSYTW3pTJIsGhmeURBFtVnrUMuiT3ecIou
         ugZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530g0cDI9Fyzmhhz4m27KH+t53Dmc86tkVy9PLeFb3Hopg7a67QA
	JiCGH6dqQeoLgSwR13zhm0s=
X-Google-Smtp-Source: ABdhPJz24zd+o58aB4e3SEVQaX/BrpaTpJbRWvwkb5HPl2soDYFp00E/fczsoCFo07p89fFYd75a5w==
X-Received: by 2002:a17:902:548:b029:10f:30af:7d5f with SMTP id 66-20020a1709020548b029010f30af7d5fmr3318390plf.22.1623915037151;
        Thu, 17 Jun 2021 00:30:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:b256:: with SMTP id t22ls2445924pgo.8.gmail; Thu, 17 Jun
 2021 00:30:36 -0700 (PDT)
X-Received: by 2002:a17:90a:66cc:: with SMTP id z12mr15247535pjl.93.1623915036538;
        Thu, 17 Jun 2021 00:30:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623915036; cv=none;
        d=google.com; s=arc-20160816;
        b=garymFWmp/asu/LLH3T178pzSYP3f24BqsrhNiLsV9OlJrc/qKOaw5QDl4SaQ/PBKI
         ZcEkBR8NoddH/1W11eQ5PxEhJ0KMnx0iIsHmF4PLHyjZlDbjWYKKeTagLcf3rWJDkYa2
         xqkDXm9DIsjmOUaDCRfN2r5tN5eyeMRZ6qTokvdf2XSx3Nqmg5TgJJlX0wEKzXAUiiWL
         4pjsn8cN+ADMEF20mwj89YhpRBFS9zL9hnJfLWOGvEIOmKtLOco3aoELzC8fHyuqeS+6
         nyym407331rYUDuGvRt4a4IXDxG8jme+kJ+WORYmnKXGm4j4h+BTjziiXThNtPAb6Zsy
         EQpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=mvyhzqW+Hc4oQ0f08FKYwzVyWbIXfaK4t1+vDnDUCOk=;
        b=FQKnvHIqGtvENTIxYlTzpyO9L0KObsW59O5kZt9+eiWEzIdrzIrLDTWlQpUKzTxYI4
         MStXixChVUKvyj2Dk6LFcRAiFj7gbnKkERMWcO/Ca+khhTdsG8t0qVZPkTekySVIo7JP
         K1dgkeRsdMIsdU/+UyMaDVM7FgGatxNm/wXA6dAI2bI4pwCtRQG/EJAD//kj2KYmb1fF
         UibYMyH61cCHTCt2IpKwfKG260Znj9dPtAX9jDiIJgNQDHFOdKCeNJU3vMLSpvEnM9ij
         +PwA8Tu7WTJzfsy+6BhKo30fVNBRhRcg0rd2u053dPYfJNcwkwxOhR0pp0Kl6/EutgeK
         xvkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b="GibhX/x+";
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id d15si2401pll.3.2021.06.17.00.30.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 00:30:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id f10so334270plg.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 00:30:36 -0700 (PDT)
X-Received: by 2002:a17:903:2482:b029:fd:696c:1d2b with SMTP id p2-20020a1709032482b02900fd696c1d2bmr3383750plw.24.1623915036012;
        Thu, 17 Jun 2021 00:30:36 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id v7sm4259002pfi.187.2021.06.17.00.30.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 00:30:35 -0700 (PDT)
Date: Thu, 17 Jun 2021 00:30:35 -0700 (PDT)
Subject: Re: [PATCH] riscv: Ensure BPF_JIT_REGION_START aligned with PMD size
In-Reply-To: <20210616080328.6548e762@xhacker>
CC: alex@ghiti.fr, schwab@linux-m68k.org, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
  dvyukov@google.com, bjorn@kernel.org, ast@kernel.org, daniel@iogearbox.net, andrii@kernel.org,
  kafai@fb.com, songliubraving@fb.com, yhs@fb.com, john.fastabend@gmail.com,
  kpsingh@kernel.org, luke.r.nels@gmail.com, xi.wang@gmail.com, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: jszhang3@mail.ustc.edu.cn
Message-ID: <mhng-042979fe-75f0-4873-8afd-f8c07942f792@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b="GibhX/x+";       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Tue, 15 Jun 2021 17:03:28 PDT (-0700), jszhang3@mail.ustc.edu.cn wrote:
> On Tue, 15 Jun 2021 20:54:19 +0200
> Alex Ghiti <alex@ghiti.fr> wrote:
>
>> Hi Jisheng,
>
> Hi Alex,
>
>>=20
>> Le 14/06/2021 =C3=A0 18:49, Jisheng Zhang a =C3=A9crit=C2=A0:
>> > From: Jisheng Zhang <jszhang@kernel.org>
>> >=20
>> > Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid breaking W^X"=
)
>> > breaks booting with one kind of config file, I reproduced a kernel pan=
ic
>> > with the config:
>> >=20
>> > [    0.138553] Unable to handle kernel paging request at virtual addre=
ss ffffffff81201220
>> > [    0.139159] Oops [#1]
>> > [    0.139303] Modules linked in:
>> > [    0.139601] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.13.0-rc5-de=
fault+ #1
>> > [    0.139934] Hardware name: riscv-virtio,qemu (DT)
>> > [    0.140193] epc : __memset+0xc4/0xfc
>> > [    0.140416]  ra : skb_flow_dissector_init+0x1e/0x82
>> > [    0.140609] epc : ffffffff8029806c ra : ffffffff8033be78 sp : fffff=
fe001647da0
>> > [    0.140878]  gp : ffffffff81134b08 tp : ffffffe001654380 t0 : fffff=
fff81201158
>> > [    0.141156]  t1 : 0000000000000002 t2 : 0000000000000154 s0 : fffff=
fe001647dd0
>> > [    0.141424]  s1 : ffffffff80a43250 a0 : ffffffff81201220 a1 : 00000=
00000000000
>> > [    0.141654]  a2 : 000000000000003c a3 : ffffffff81201258 a4 : 00000=
00000000064
>> > [    0.141893]  a5 : ffffffff8029806c a6 : 0000000000000040 a7 : fffff=
fffffffffff
>> > [    0.142126]  s2 : ffffffff81201220 s3 : 0000000000000009 s4 : fffff=
fff81135088
>> > [    0.142353]  s5 : ffffffff81135038 s6 : ffffffff8080ce80 s7 : fffff=
fff80800438
>> > [    0.142584]  s8 : ffffffff80bc6578 s9 : 0000000000000008 s10: fffff=
fff806000ac
>> > [    0.142810]  s11: 0000000000000000 t3 : fffffffffffffffc t4 : 00000=
00000000000
>> > [    0.143042]  t5 : 0000000000000155 t6 : 00000000000003ff
>> > [    0.143220] status: 0000000000000120 badaddr: ffffffff81201220 caus=
e: 000000000000000f
>> > [    0.143560] [<ffffffff8029806c>] __memset+0xc4/0xfc
>> > [    0.143859] [<ffffffff8061e984>] init_default_flow_dissectors+0x22/=
0x60
>> > [    0.144092] [<ffffffff800010fc>] do_one_initcall+0x3e/0x168
>> > [    0.144278] [<ffffffff80600df0>] kernel_init_freeable+0x1c8/0x224
>> > [    0.144479] [<ffffffff804868a8>] kernel_init+0x12/0x110
>> > [    0.144658] [<ffffffff800022de>] ret_from_exception+0x0/0xc
>> > [    0.145124] ---[ end trace f1e9643daa46d591 ]---
>> >=20
>> > After some investigation, I think I found the root cause: commit
>> > 2bfc6cd81bd ("move kernel mapping outside of linear mapping") moves
>> > BPF JIT region after the kernel:
>> >=20
>> > The &_end is unlikely aligned with PMD size, so the front bpf jit
>> > region sits with part of kernel .data section in one PMD size mapping.
>> > But kernel is mapped in PMD SIZE, when bpf_jit_binary_lock_ro() is
>> > called to make the first bpf jit prog ROX, we will make part of kernel
>> > .data section RO too, so when we write to, for example memset the
>> > .data section, MMU will trigger a store page fault. =20
>>=20
>> Good catch, we make sure no physical allocation happens between _end and=
=20
>> the next PMD aligned address, but I missed this one.
>>=20
>> >=20
>> > To fix the issue, we need to ensure the BPF JIT region is PMD size
>> > aligned. This patch acchieve this goal by restoring the BPF JIT region
>> > to original position, I.E the 128MB before kernel .text section. =20
>>=20
>> But I disagree with your solution: I made sure modules and BPF programs=
=20
>> get their own virtual regions to avoid worst case scenario where one=20
>> could allocate all the space and leave nothing to the other (we are=20
>> limited to +- 2GB offset). Why don't just align BPF_JIT_REGION_START to=
=20
>> the next PMD aligned address?
>
> Originally, I planed to fix the issue by aligning BPF_JIT_REGION_START, b=
ut
> IIRC, BPF experts are adding (or have added) "Calling kernel functions fr=
om BPF"
> feature, there's a risk that BPF JIT region is beyond the 2GB of module r=
egion:
>
> ------
> module
> ------
> kernel
> ------
> BPF_JIT
>
> So I made this patch finally. In this patch, we let BPF JIT region sit
> between module and kernel.
>
> To address "make sure modules and BPF programs get their own virtual regi=
ons",
> what about something as below (applied against this patch)?
>
> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pg=
table.h
> index 380cd3a7e548..da1158f10b09 100644
> --- a/arch/riscv/include/asm/pgtable.h
> +++ b/arch/riscv/include/asm/pgtable.h
> @@ -31,7 +31,7 @@
>  #define BPF_JIT_REGION_SIZE	(SZ_128M)
>  #ifdef CONFIG_64BIT
>  #define BPF_JIT_REGION_START	(BPF_JIT_REGION_END - BPF_JIT_REGION_SIZE)
> -#define BPF_JIT_REGION_END	(MODULES_END)
> +#define BPF_JIT_REGION_END	(PFN_ALIGN((unsigned long)&_start))
>  #else
>  #define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
>  #define BPF_JIT_REGION_END	(VMALLOC_END)
> @@ -40,7 +40,7 @@
>  /* Modules always live before the kernel */
>  #ifdef CONFIG_64BIT
>  #define MODULES_VADDR	(PFN_ALIGN((unsigned long)&_end) - SZ_2G)
> -#define MODULES_END	(PFN_ALIGN((unsigned long)&_start))
> +#define MODULES_END	(BPF_JIT_REGION_END)
>  #endif
> =20
>
>
>>=20
>> Again, good catch, thanks,
>>=20
>> Alex
>>=20
>> >=20
>> > Reported-by: Andreas Schwab <schwab@linux-m68k.org>
>> > Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
>> > ---
>> >   arch/riscv/include/asm/pgtable.h | 5 ++---
>> >   1 file changed, 2 insertions(+), 3 deletions(-)
>> >=20
>> > diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm=
/pgtable.h
>> > index 9469f464e71a..380cd3a7e548 100644
>> > --- a/arch/riscv/include/asm/pgtable.h
>> > +++ b/arch/riscv/include/asm/pgtable.h
>> > @@ -30,9 +30,8 @@
>> >  =20
>> >   #define BPF_JIT_REGION_SIZE	(SZ_128M)
>> >   #ifdef CONFIG_64BIT
>> > -/* KASLR should leave at least 128MB for BPF after the kernel */
>> > -#define BPF_JIT_REGION_START	PFN_ALIGN((unsigned long)&_end)
>> > -#define BPF_JIT_REGION_END	(BPF_JIT_REGION_START + BPF_JIT_REGION_SIZ=
E)
>> > +#define BPF_JIT_REGION_START	(BPF_JIT_REGION_END - BPF_JIT_REGION_SIZ=
E)
>> > +#define BPF_JIT_REGION_END	(MODULES_END)
>> >   #else
>> >   #define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
>> >   #define BPF_JIT_REGION_END	(VMALLOC_END)
>> >  =20

This, when applied onto fixes, is breaking early boot on KASAN=20
configurations for me.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-042979fe-75f0-4873-8afd-f8c07942f792%40palmerdabbelt-glaptop=
.
