Return-Path: <kasan-dev+bncBC447XVYUEMRBWNTVWDAMGQE4LCMXEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 29B223AB5B4
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 16:19:06 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id h6-20020a2e85c60000b029014fcff4ccdcsf2996351ljj.11
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 07:19:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623939545; cv=pass;
        d=google.com; s=arc-20160816;
        b=zWqBbnL4+VVCu3th60NvWekqSJquKKV9ILF8OA4e5IcBOHtK/8ZIYwgQ17qxc5/bo5
         PSjVFq/oBqXSpnwiSSvmdvoXuiLcLTNWFpNHltUPlPsHBm/wzAinDy+0NyMwkrgfNzUM
         fLEzjqaL5yGNSkGWSCZYBsgDg6XX1TtyAXGMqCQ321XmcJ7dSMo9y75DOb8O7HNYCu5J
         izwae6nk9MoSQEyfIXZDP2RPWFsjlaHqQnx/oXgmgJMn/USwyv9WKUViSQw0pJrYk+NK
         o/ON/ip8DumuGNngh6Ks/uhlPMUq9CU109zT+rcyvlA9ie1zuzcM7WyGK28D0PqnKqGw
         UHmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=e3JgZwu9CIzq+kinIAClQtn+lgI2Zyp60C/xqeb65r4=;
        b=SkqNknlakdhRl0+VSHqR52ACSUQguhCfeAGxrZDFCqwOu9pvfgl2057MnDbSuPH+Dt
         hdc0Ae4c0fmtN8Zjq9Ha65p9WXG+d/qprqGCmELs2ygeAlclREkA9y47MfJb+BJTIFFS
         qRQq8swhxvDTQ5hyqQtJTypZCVMUFc0q/f4tvMMSQ2QZFfSLfTSAesvfjvF0gGQ7wMFs
         cst6AaPebseh48Ue2jxInpdBmAjka+5NA73Ql6f4619F3KbOcj4FVgHAVOkym2lJqCq/
         VLrQPUqoVj6I5l+LE1h0ZJ2eFuZdDX0vXYyWIM+McfpQZ9MUGqBsXApRve15hnZDZWHp
         qXDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e3JgZwu9CIzq+kinIAClQtn+lgI2Zyp60C/xqeb65r4=;
        b=FxuY3KxnKIvz1aFnraldsRyjwsVhPnGtrbtfzPYyvmdAQVDfn8hlgQyt7K0kaPEUqy
         GaDW+mK/YrDTytczoNqHUXcP1aotqlrKtT2dIKjw6nroU3V8e2vamMAFXapjie9JFsZX
         7AeCOI9Dsm+nUFViG3zo9+9W7yR0AlOoPKxxUTOWZOzjM/POYSBtRezzejuTIjexuN0S
         +ha8KBfNXpz61/CFkwgphLAx3Qbrb6Nv8NfuZhuZbUnXv5npoWtvNWrrRxgW05iSPZgh
         5/pmA8vyaRVTSk9HyPJgs/sVBflSyjf2V4PzZqbwi5fMPF1c8P11HgHTWX/S2pN8myUF
         94IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e3JgZwu9CIzq+kinIAClQtn+lgI2Zyp60C/xqeb65r4=;
        b=PKscoSLgT9khoZ+62H1Hy0GbrlRtq+pS9UpZ2BZ5o1gbpCyQKt1MyuC3hbOXe11H7e
         iaQ258M/S7Blw2hQIUIeG+HpC85ga8R4PwPLmpQ93wsk15qez1I96FUmKVr3UoppSVqv
         gZprS8vqE6PSkFENyphbf0cll25xWXma4jBSkmOjNnA2cE+5KQQ2QQJnBM6Ub2vQP1Hm
         PWtQcqBm1w4XYDBpHtXcBRQsCasDMjUoNIYM14A619lHixog9SV/WjOzO7DyvoFFy8D8
         yFRgTdgXZob9svHoPPhIUbN6bgCirbTIveqcuS3ShXP4hy4+GIgFPGNZ6I/h0T53CAGe
         PabA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310EC7DTn25KMatUNxKk27joc9utULezkkqBoTBRKhJ5KfKSeLL
	i2r+GE1JhXEFZLDBGV9cPPA=
X-Google-Smtp-Source: ABdhPJzGgEr4fyLf7PNr7KsD5+vsh1s6ylfI/IFI6/aOquGGO0FfspbpbL9IgYkMGB6arnNCM0pwwg==
X-Received: by 2002:a19:488b:: with SMTP id v133mr3164930lfa.519.1623939545629;
        Thu, 17 Jun 2021 07:19:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8790:: with SMTP id n16ls1543246lji.11.gmail; Thu, 17
 Jun 2021 07:19:04 -0700 (PDT)
X-Received: by 2002:a2e:844a:: with SMTP id u10mr4955610ljh.443.1623939544523;
        Thu, 17 Jun 2021 07:19:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623939544; cv=none;
        d=google.com; s=arc-20160816;
        b=je8kCd8ZBseEyvAfUIgdiEVA3BH7epXAiwRrYlVGuuUakG8vIj3Stdl5fXzpHa5PXg
         Nq73i811NwFoHIjG2sUUJuOOpfDnoMolc9AxiSe/wuUkDehzhfBUxNuHbhIhPl09aSwu
         ktjoq1LP9d0FFXmENhwnsUqETg1pn8pkEuTQGJSPNZ00pxZb1P7VmUAcUkZ6Vs586QDb
         ZG4e3WqIlsQHQ4qOyGaFf8c0xzQ0l/SFmTNxbwTlLBQJpAnCgZYVfy8Sy19gEq3JU3eM
         I6FeN0tEXeyO48/yHOyUDqPIs3TBpdraKSkM1hbnzKsMTpzKaQ0JBPFlC2wNqkFQNHex
         tnCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject;
        bh=lqrO2KGVjs+jz3JICRhUKwhl02bzxHC4WQGMTLd2EqM=;
        b=KJISXD4OMWrHp0t55davy9uUWc2Z7BFtbR5XdM4yNSPwhOr7Nr18F5TJTSf77U9BEu
         r9z4cylvydCn7YGkd7opSLzdCTqn8LQBYbhpsYropWbnMzEqVZGv0upFMy90jF/gzVh6
         L4WBKd/A6iz9BzMfu/EtSOxVmrmw0/WTW3K+2pbi5eerrcp1tvVNyOWy3EjxyzZDZuU+
         5sFIthibtrvUq0tPLpgyTu3VcNi7OFj1IQS5iY75MXVvrqJKooWj09EC4v273n95ms/o
         5+H0fCtLNmYDeaS9Yz0VaIiLgB9pqfGAoa6cSZaC/FR7cxtKSsyQGgCMqaRHdgdmmfna
         Sm1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay6-d.mail.gandi.net (relay6-d.mail.gandi.net. [217.70.183.198])
        by gmr-mx.google.com with ESMTPS id bn2si170634ljb.7.2021.06.17.07.19.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 17 Jun 2021 07:19:04 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.198 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.198;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay6-d.mail.gandi.net (Postfix) with ESMTPSA id 09F16C0007;
	Thu, 17 Jun 2021 14:18:54 +0000 (UTC)
Subject: Re: [PATCH] riscv: Ensure BPF_JIT_REGION_START aligned with PMD size
From: Alex Ghiti <alex@ghiti.fr>
To: Palmer Dabbelt <palmer@dabbelt.com>, jszhang3@mail.ustc.edu.cn
Cc: schwab@linux-m68k.org, Paul Walmsley <paul.walmsley@sifive.com>,
 aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, glider@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, bjorn@kernel.org, ast@kernel.org,
 daniel@iogearbox.net, andrii@kernel.org, kafai@fb.com,
 songliubraving@fb.com, yhs@fb.com, john.fastabend@gmail.com,
 kpsingh@kernel.org, luke.r.nels@gmail.com, xi.wang@gmail.com,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
References: <mhng-042979fe-75f0-4873-8afd-f8c07942f792@palmerdabbelt-glaptop>
 <ae256a5d-70ac-3a5f-ca55-5e4210a0624c@ghiti.fr>
Message-ID: <50ebc99c-f0a2-b4ea-fc9b-cd93a8324697@ghiti.fr>
Date: Thu, 17 Jun 2021 16:18:54 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <ae256a5d-70ac-3a5f-ca55-5e4210a0624c@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.198 is neither permitted nor denied by best guess
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

Le 17/06/2021 =C3=A0 10:09, Alex Ghiti a =C3=A9crit=C2=A0:
> Le 17/06/2021 =C3=A0 09:30, Palmer Dabbelt a =C3=A9crit=C2=A0:
>> On Tue, 15 Jun 2021 17:03:28 PDT (-0700), jszhang3@mail.ustc.edu.cn=20
>> wrote:
>>> On Tue, 15 Jun 2021 20:54:19 +0200
>>> Alex Ghiti <alex@ghiti.fr> wrote:
>>>
>>>> Hi Jisheng,
>>>
>>> Hi Alex,
>>>
>>>>
>>>> Le 14/06/2021 =C3=A0 18:49, Jisheng Zhang a =C3=A9crit=C2=A0:
>>>> > From: Jisheng Zhang <jszhang@kernel.org>
>>>> > > Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid=20
>>>> breaking W^X")
>>>> > breaks booting with one kind of config file, I reproduced a kernel=
=20
>>>> panic
>>>> > with the config:
>>>> > > [=C2=A0=C2=A0=C2=A0 0.138553] Unable to handle kernel paging reque=
st at virtual=20
>>>> address ffffffff81201220
>>>> > [=C2=A0=C2=A0=C2=A0 0.139159] Oops [#1]
>>>> > [=C2=A0=C2=A0=C2=A0 0.139303] Modules linked in:
>>>> > [=C2=A0=C2=A0=C2=A0 0.139601] CPU: 0 PID: 1 Comm: swapper/0 Not tain=
ted=20
>>>> 5.13.0-rc5-default+ #1
>>>> > [=C2=A0=C2=A0=C2=A0 0.139934] Hardware name: riscv-virtio,qemu (DT)
>>>> > [=C2=A0=C2=A0=C2=A0 0.140193] epc : __memset+0xc4/0xfc
>>>> > [=C2=A0=C2=A0=C2=A0 0.140416]=C2=A0 ra : skb_flow_dissector_init+0x1=
e/0x82
>>>> > [=C2=A0=C2=A0=C2=A0 0.140609] epc : ffffffff8029806c ra : ffffffff80=
33be78 sp :=20
>>>> ffffffe001647da0
>>>> > [=C2=A0=C2=A0=C2=A0 0.140878]=C2=A0 gp : ffffffff81134b08 tp : fffff=
fe001654380 t0 :=20
>>>> ffffffff81201158
>>>> > [=C2=A0=C2=A0=C2=A0 0.141156]=C2=A0 t1 : 0000000000000002 t2 : 00000=
00000000154 s0 :=20
>>>> ffffffe001647dd0
>>>> > [=C2=A0=C2=A0=C2=A0 0.141424]=C2=A0 s1 : ffffffff80a43250 a0 : fffff=
fff81201220 a1 :=20
>>>> 0000000000000000
>>>> > [=C2=A0=C2=A0=C2=A0 0.141654]=C2=A0 a2 : 000000000000003c a3 : fffff=
fff81201258 a4 :=20
>>>> 0000000000000064
>>>> > [=C2=A0=C2=A0=C2=A0 0.141893]=C2=A0 a5 : ffffffff8029806c a6 : 00000=
00000000040 a7 :=20
>>>> ffffffffffffffff
>>>> > [=C2=A0=C2=A0=C2=A0 0.142126]=C2=A0 s2 : ffffffff81201220 s3 : 00000=
00000000009 s4 :=20
>>>> ffffffff81135088
>>>> > [=C2=A0=C2=A0=C2=A0 0.142353]=C2=A0 s5 : ffffffff81135038 s6 : fffff=
fff8080ce80 s7 :=20
>>>> ffffffff80800438
>>>> > [=C2=A0=C2=A0=C2=A0 0.142584]=C2=A0 s8 : ffffffff80bc6578 s9 : 00000=
00000000008 s10:=20
>>>> ffffffff806000ac
>>>> > [=C2=A0=C2=A0=C2=A0 0.142810]=C2=A0 s11: 0000000000000000 t3 : fffff=
ffffffffffc t4 :=20
>>>> 0000000000000000
>>>> > [=C2=A0=C2=A0=C2=A0 0.143042]=C2=A0 t5 : 0000000000000155 t6 : 00000=
000000003ff
>>>> > [=C2=A0=C2=A0=C2=A0 0.143220] status: 0000000000000120 badaddr: ffff=
ffff81201220=20
>>>> cause: 000000000000000f
>>>> > [=C2=A0=C2=A0=C2=A0 0.143560] [<ffffffff8029806c>] __memset+0xc4/0xf=
c
>>>> > [=C2=A0=C2=A0=C2=A0 0.143859] [<ffffffff8061e984>]=20
>>>> init_default_flow_dissectors+0x22/0x60
>>>> > [=C2=A0=C2=A0=C2=A0 0.144092] [<ffffffff800010fc>] do_one_initcall+0=
x3e/0x168
>>>> > [=C2=A0=C2=A0=C2=A0 0.144278] [<ffffffff80600df0>] kernel_init_freea=
ble+0x1c8/0x224
>>>> > [=C2=A0=C2=A0=C2=A0 0.144479] [<ffffffff804868a8>] kernel_init+0x12/=
0x110
>>>> > [=C2=A0=C2=A0=C2=A0 0.144658] [<ffffffff800022de>] ret_from_exceptio=
n+0x0/0xc
>>>> > [=C2=A0=C2=A0=C2=A0 0.145124] ---[ end trace f1e9643daa46d591 ]---
>>>> > > After some investigation, I think I found the root cause: commit
>>>> > 2bfc6cd81bd ("move kernel mapping outside of linear mapping") moves
>>>> > BPF JIT region after the kernel:
>>>> > > The &_end is unlikely aligned with PMD size, so the front bpf jit
>>>> > region sits with part of kernel .data section in one PMD size=20
>>>> mapping.
>>>> > But kernel is mapped in PMD SIZE, when bpf_jit_binary_lock_ro() is
>>>> > called to make the first bpf jit prog ROX, we will make part of=20
>>>> kernel
>>>> > .data section RO too, so when we write to, for example memset the
>>>> > .data section, MMU will trigger a store page fault.
>>>> Good catch, we make sure no physical allocation happens between _end=
=20
>>>> and the next PMD aligned address, but I missed this one.
>>>>
>>>> > > To fix the issue, we need to ensure the BPF JIT region is PMD size
>>>> > aligned. This patch acchieve this goal by restoring the BPF JIT=20
>>>> region
>>>> > to original position, I.E the 128MB before kernel .text section.
>>>> But I disagree with your solution: I made sure modules and BPF=20
>>>> programs get their own virtual regions to avoid worst case scenario=20
>>>> where one could allocate all the space and leave nothing to the=20
>>>> other (we are limited to +- 2GB offset). Why don't just align=20
>>>> BPF_JIT_REGION_START to the next PMD aligned address?
>>>
>>> Originally, I planed to fix the issue by aligning=20
>>> BPF_JIT_REGION_START, but
>>> IIRC, BPF experts are adding (or have added) "Calling kernel=20
>>> functions from BPF"
>>> feature, there's a risk that BPF JIT region is beyond the 2GB of=20
>>> module region:
>>>
>>> ------
>>> module
>>> ------
>>> kernel
>>> ------
>>> BPF_JIT
>>>
>>> So I made this patch finally. In this patch, we let BPF JIT region sit
>>> between module and kernel.
>>>
>>> To address "make sure modules and BPF programs get their own virtual=20
>>> regions",
>>> what about something as below (applied against this patch)?
>>>
>>> diff --git a/arch/riscv/include/asm/pgtable.h=20
>>> b/arch/riscv/include/asm/pgtable.h
>>> index 380cd3a7e548..da1158f10b09 100644
>>> --- a/arch/riscv/include/asm/pgtable.h
>>> +++ b/arch/riscv/include/asm/pgtable.h
>>> @@ -31,7 +31,7 @@
>>> =C2=A0#define BPF_JIT_REGION_SIZE=C2=A0=C2=A0=C2=A0 (SZ_128M)
>>> =C2=A0#ifdef CONFIG_64BIT
>>> =C2=A0#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_EN=
D -=20
>>> BPF_JIT_REGION_SIZE)
>>> -#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (MODULES_END)
>>> +#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigned long=
)&_start))
>>> =C2=A0#else
>>> =C2=A0#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET - BPF=
_JIT_REGION_SIZE)
>>> =C2=A0#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (VMALLOC_END)
>>> @@ -40,7 +40,7 @@
>>> =C2=A0/* Modules always live before the kernel */
>>> =C2=A0#ifdef CONFIG_64BIT
>>> =C2=A0#define MODULES_VADDR=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigned long=
)&_end) - SZ_2G)
>>> -#define MODULES_END=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigned long)&_star=
t))
>>> +#define MODULES_END=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_END)
>>> =C2=A0#endif
>>>
>>>
>>>
>>>>
>>>> Again, good catch, thanks,
>>>>
>>>> Alex
>>>>
>>>> > > Reported-by: Andreas Schwab <schwab@linux-m68k.org>
>>>> > Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
>>>> > ---
>>>> >=C2=A0=C2=A0 arch/riscv/include/asm/pgtable.h | 5 ++---
>>>> >=C2=A0=C2=A0 1 file changed, 2 insertions(+), 3 deletions(-)
>>>> > > diff --git a/arch/riscv/include/asm/pgtable.h=20
>>>> b/arch/riscv/include/asm/pgtable.h
>>>> > index 9469f464e71a..380cd3a7e548 100644
>>>> > --- a/arch/riscv/include/asm/pgtable.h
>>>> > +++ b/arch/riscv/include/asm/pgtable.h
>>>> > @@ -30,9 +30,8 @@
>>>> > >=C2=A0=C2=A0 #define BPF_JIT_REGION_SIZE=C2=A0=C2=A0=C2=A0 (SZ_128M=
)
>>>> >=C2=A0=C2=A0 #ifdef CONFIG_64BIT
>>>> > -/* KASLR should leave at least 128MB for BPF after the kernel */
>>>> > -#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 PFN_ALIGN((unsigned =
long)&_end)
>>>> > -#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_START =
+=20
>>>> BPF_JIT_REGION_SIZE)
>>>> > +#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_END =
-=20
>>>> BPF_JIT_REGION_SIZE)
>>>> > +#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (MODULES_END)
>>>> >=C2=A0=C2=A0 #else
>>>> >=C2=A0=C2=A0 #define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (PAGE_OFF=
SET - BPF_JIT_REGION_SIZE)
>>>> >=C2=A0=C2=A0 #define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (VMALLOC_EN=
D)
>>>> >=20
>>
>> This, when applied onto fixes, is breaking early boot on KASAN=20
>> configurations for me.
>=20
> Not surprising, I took a shortcut when initializing KASAN for modules,=20
> kernel and BPF:
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate(kasan_mem_to_s=
hadow((const void *)MODULES_VADDR),
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_mem_to_s=
hadow((const void=20
> *)BPF_JIT_REGION_END));
>=20
> The kernel is then not covered, I'm taking a look at how to fix that=20
> properly.
>

The following based on "riscv: Introduce structure that group all=20
variables regarding kernel mapping" fixes the issue:

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 9daacae93e33..2a45ea909e7f 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -199,9 +199,12 @@ void __init kasan_init(void)
                 kasan_populate(kasan_mem_to_shadow(start),=20
kasan_mem_to_shadow(end));
         }

-       /* Populate kernel, BPF, modules mapping */
+       /* Populate BPF and modules mapping: modules mapping encompasses=20
BPF mapping */
         kasan_populate(kasan_mem_to_shadow((const void *)MODULES_VADDR),
-                      kasan_mem_to_shadow((const void=20
*)BPF_JIT_REGION_END));
+                      kasan_mem_to_shadow((const void *)MODULES_END));
+       /* Populate kernel mapping */
+       kasan_populate(kasan_mem_to_shadow((const void=20
*)kernel_map.virt_addr),
+                      kasan_mem_to_shadow((const void=20
*)kernel_map.virt_addr + kernel_map.size));


Without the mentioned patch, replace kernel_map.virt_addr with=20
kernel_virt_addr and kernel_map.size with load_sz. Note that load_sz was=20
re-exposed in v6 of the patchset "Map the kernel with correct=20
permissions the first time".

Alex

>>
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/50ebc99c-f0a2-b4ea-fc9b-cd93a8324697%40ghiti.fr.
