Return-Path: <kasan-dev+bncBC447XVYUEMRBZPOUODAMGQEBJMC5LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 87E363A88EF
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 20:54:30 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id t8-20020a05651c2048b029012eb794d268sf34077ljo.14
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 11:54:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623783270; cv=pass;
        d=google.com; s=arc-20160816;
        b=JmH4H1LrxrGXkSHk+vEpkwLqZ/5Uos+3Av1GAQ2Vc8u/Pcw39/CMCuLOBD7xROpF88
         KhdHlb+gxmmqInVdv2w+z7xygSzYfnTIlYgghbhVX+xCFpZJsQ2cI+r/1Z+YbbAzpDaG
         tWsCx6r1vfk9O2V1Vujq1M6Lf3vI+8qimCaKpcGh6LmXrrYUKxuPneIkBokol/Xwxjg0
         7/NOR+QJx+FjDyswm+0uMvh2k3DNZFIU9O4TsXysaIQIm8xfsKPkDxxmqYIYUExl+8Zi
         4wIeJ4q4W2TXlnw2xlQA5tewyyRXalcXe5Dsi37BGDtaKH0SmPUIUR8hZNox77tHTkyj
         llGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=0uLB4qT5kKWHgnRfqUgzyvjuIrtA3qMvtnJeDvJQbpM=;
        b=vX6/2qKYETJr9IcO3OzFnsshjoiYS3Fo8wQY445nNts6kIBHQbLkWh4VdOmlxh+KHn
         cC4cWwns6fmwYHN8WJC1vufgxvWRMj4cFHaayYkor83rCI7qbAPVlRXd8mVgQDbCNbKM
         6zEgQIKAzYaZ1yTbbjtVFno06TusBqAyhYDjWuj353G9W2UCozpMUoW+n7vtCpp3BVKU
         mgwJmmz6cJ6HI8xeSFNVKpDR49lOE3PUY/gN3o7VuODYHBpLZlOI4f2njzNd0pyZodnz
         YBXTE8xH3DYp/82Yu2bwIGzLRXiN7jMqi2EKqjkFc5TxJymWFOLzGRox/2Qry2+Gs/xH
         twMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0uLB4qT5kKWHgnRfqUgzyvjuIrtA3qMvtnJeDvJQbpM=;
        b=In+HmdretGkiz3K/APY8J4dFXSU29XJtTMl2xdZE3qmMzXjD1trgzPv9/zy5p3yuhN
         njgLfebb6vatL5jULTiiQ1hFst+m9z0Gg5LDLwAT9YsoySc7LDpD2n3PHD8C3wCqOUu0
         tq4oXxnK6LQfBtKntycxS6X1pSVE+DK8NgXxvvP5x5RPHgzx6b+szKupgr32QOzSoHca
         YOPwWC/kqthtdmPmqNc32Q4aKAXNVVNK5ROBoIi5tbahR5nQAaWqH/zKpz6f72yVelti
         w3/WXo0YjYnbrUnMCP/QhNNddbP6oj7UCqWb7ZcZ82I7NkiVg4OV/07Zu93/7fJGNuKY
         LorA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0uLB4qT5kKWHgnRfqUgzyvjuIrtA3qMvtnJeDvJQbpM=;
        b=nlaZ1PPat+AKiglzVvGrBPm4+ouGsIdcK/zGgai1CbMVFZDzEhXIdUoWoh7Li36/uy
         A9hUaDWii+wJkiE7a7IX+uM7Qysv+32Y8yj+TWubkfp+RzKdHAeslyOVeqW/Rbgrc+F2
         EyUuDhGEy2U5K5JZo67pK07xP+6xmcasKgdNRBOVyc8FHjLOA1KkhmNaXKvUttXqfH9c
         yBWuXk3DIky6rvysWUFNdxY0eLdlS3vaCB+lopiz4zBQ9LCAwTQ8dige6NC7AfQtZ+l+
         5SBo3qvWkT8nPasJ9vS8JdzttvRZn7ohB3WQtNZ9untBkB+5SKlxZ2i93fuRKvVF/gBA
         5Mbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530VmetB1cy/vbMehIVqwnCCAttUYub8vptEqhBHn2Z/76m2aAUK
	R1OvKAnfRLapNnn1RxQH//w=
X-Google-Smtp-Source: ABdhPJw/C3Bgczd4d2eHmlt5FCu0MORYkhyxRUcwzOpGaziwIZLdCOENPDK7Bk8sjn7NjtZtjFmYeQ==
X-Received: by 2002:a2e:999a:: with SMTP id w26mr933604lji.191.1623783270134;
        Tue, 15 Jun 2021 11:54:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a86:: with SMTP id q6ls1465664lfu.3.gmail; Tue, 15
 Jun 2021 11:54:29 -0700 (PDT)
X-Received: by 2002:ac2:58e3:: with SMTP id v3mr576871lfo.339.1623783269064;
        Tue, 15 Jun 2021 11:54:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623783269; cv=none;
        d=google.com; s=arc-20160816;
        b=IRlRAHcA9CVJZbUbLBSKaFz3/wJYdUG6OeOPYRIaqlJLPski6Q5Mg8ZLEpqO1dbVMU
         jp/SMApukw5Qcroh87cVRJQX4CfndUaf7E2/xeor3WBUftlUfO8Dp7HPm5Fiy4mLYsn7
         kiGDFJoU/6nRWAKMLgvoMeVvDUc6XWQOLiw0CJGYZGTlRVgAXPlNnRy7u0M45NVlfaDH
         MQk7MC/2jMSn3r/K/6K01ZG2u5eHHVikKROqSa9A72CyKbjweYLQ57ivsP5fX+FIwulo
         vz3KLxYKjaG8QwQtBK9qNGrmlaPAeSGAslfNN1HJOI+7QHYlGLaRNqmcY5CO22azcoc1
         Qm3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=X1+JzE58pzgK2+3hAVJ1O8CVksYO0uskpADRQzVjRC8=;
        b=Rh8lfRloUAmTqQ7eW3cUMFB++z4jJpZ8a7rxSN+PHNwT8UzQJ+tfvzeuOaeUM4624o
         UEuSWEMsbm2F7Ox291CxdJf+mRNca3dyqrwOkaSIfmNU6qtGjYWoC61uBYIgTS+r2yhM
         M+sgBtam8QTLTPzkncEenfNE4K2hTZ2qAqbsYRUYSah4LW1//+YwFWNs5uW9bOhbIg7N
         FigdXaZ2aER5XdJSa0mr3oWMyXXKrBxKyOoyeHgchV8U6Kb4GgxH70e76ZPQYIR4qWgQ
         C3h1RZE96KzrWILLsIUOMSOohdzNNJ1bKSpvwi5hzKEjfAySBUDmZik8L11JBWbgwmpx
         bz7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay11.mail.gandi.net (relay11.mail.gandi.net. [217.70.178.231])
        by gmr-mx.google.com with ESMTPS id a21si133347lfl.10.2021.06.15.11.54.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 15 Jun 2021 11:54:28 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.231;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay11.mail.gandi.net (Postfix) with ESMTPSA id 6C97B100006;
	Tue, 15 Jun 2021 18:54:21 +0000 (UTC)
Subject: Re: [PATCH] riscv: Ensure BPF_JIT_REGION_START aligned with PMD size
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>,
 Andreas Schwab <schwab@linux-m68k.org>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
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
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <ab536c78-ba1c-c65c-325a-8f9fba6e9d46@ghiti.fr>
Date: Tue, 15 Jun 2021 20:54:19 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <20210615004928.2d27d2ac@xhacker>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.231 is neither permitted nor denied by best guess
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

Hi Jisheng,

Le 14/06/2021 =C3=A0 18:49, Jisheng Zhang a =C3=A9crit=C2=A0:
> From: Jisheng Zhang <jszhang@kernel.org>
>=20
> Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid breaking W^X")
> breaks booting with one kind of config file, I reproduced a kernel panic
> with the config:
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

Good catch, we make sure no physical allocation happens between _end and=20
the next PMD aligned address, but I missed this one.

>=20
> To fix the issue, we need to ensure the BPF JIT region is PMD size
> aligned. This patch acchieve this goal by restoring the BPF JIT region
> to original position, I.E the 128MB before kernel .text section.

But I disagree with your solution: I made sure modules and BPF programs=20
get their own virtual regions to avoid worst case scenario where one=20
could allocate all the space and leave nothing to the other (we are=20
limited to +- 2GB offset). Why don't just align BPF_JIT_REGION_START to=20
the next PMD aligned address?

Again, good catch, thanks,

Alex

>=20
> Reported-by: Andreas Schwab <schwab@linux-m68k.org>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> ---
>   arch/riscv/include/asm/pgtable.h | 5 ++---
>   1 file changed, 2 insertions(+), 3 deletions(-)
>=20
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
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ab536c78-ba1c-c65c-325a-8f9fba6e9d46%40ghiti.fr.
