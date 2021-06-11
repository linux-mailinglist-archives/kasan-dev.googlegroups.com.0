Return-Path: <kasan-dev+bncBAABBGU7R2DAMGQEJVG3CTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id EE2113A467E
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 18:30:19 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id j23-20020ab01d170000b029023ea6f67624sf2759463uak.14
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 09:30:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623429019; cv=pass;
        d=google.com; s=arc-20160816;
        b=UzmRdk4zV4OalI6Mt+8Hpviethm6lTpNsmQitAwBD7HiXWK8Z71JvUvzESItHM9sMU
         fXromTiPAXmgsECSzlwZioWFf3+yaxuIwsYcA23hbY5aeFdPRfu8N6N/ATS55rhsTvYX
         m2Kolno7YcbRyq2VzJJv0jReX6OBzsfe+KqtBHnIDaqY6YZUkFi6QfdtZuIaYzgqa31T
         9pbOYG5eK6KZSoyjw+OEPlezs4XOD2m6LOfrL6F9Ef3WowOH5a1hMxlwbw3EaTDE0Abm
         bieOmlHiix3JmkGeMVAYhiQkp0ocqkc9a0nqv9T8eM8I6ojB/ox8HkGEu0bTb0//Pfve
         ltLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=Dwc6z4FH9+u2b0UxhZ3O1d9c4yxKOFrOXu7mMhcHQto=;
        b=zVrFBGQtFWdnbgTeqJyrDd95ZrO0KEWPFJP/+F5zV5glJCN0Ir8aPpwA46OUC+wE+q
         WDW4xfYZmByeuwxo4OFHfTqZH/KBA/RWs0o9QbnQe7uT3n1ZbwR1sj6T2N4ta9DVtZRh
         RElTqS6ASCE9w25RW7anibcAHK8ILPQPi6MGALzKgvufzbSQF6+204i7mdAp4yrFETyF
         LxMurvyHhDM9cVHQTNepMo1QYa8nfgLyYDNfU8uxbdSbBUYxmeuq87IP/5+1FfMnarkW
         kcal/HQa1q92VmrjaUvU7zzioUEqls992HgdaQG8b7zotOmlqSprBrYffGLtloCUr4N8
         gTsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=NhVTjKTk;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Dwc6z4FH9+u2b0UxhZ3O1d9c4yxKOFrOXu7mMhcHQto=;
        b=dM5OQ8iqCUndOV2X22fgDuAbeKARPwSDomAEplTFgC2rjhw3som9zkolXN5XiBt37R
         /UlQ0RHh7eAqbxpCFKKup+/e55X/p+0FRnsLljXkxIObqsi6FqQgEF6CJieFaACVJiai
         +sp4g+Y9UFtt31rFu3aUF7DUTmjlWQ8bpxd0e0BujaQdBdm49rDJLOaWNO7dAnU3M/lm
         /POrauyrHY7SdHgZvo5lnZJx0DoM/iKAOYtAf/i8VwMHFvDET/C8q+IsDFjTNIY3peCk
         A62VMLW2AdVhnVeFgFaiWF2nowi8GyycO7NB/36G95JJYhI1LQcDiCjoJhVYIwANIuk6
         xUxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dwc6z4FH9+u2b0UxhZ3O1d9c4yxKOFrOXu7mMhcHQto=;
        b=QvGYaiCBLr3nHwomv/+FXW6LxzFrBC+CbvSz0Gyxs1AC47MoFjf8EHN4duDoA6GjaN
         5ZpVBZVh6Q5Xe9HF5nrir1fH/X9ZPr3Pq7Sx5go6oHTq361e++IDsUSpT9h6Q/ntTa2S
         v583lAKX7KAFKmoWpU2Z+4Nw7Cyl2T9MBa0BMzf6iRvOFwsiwZo6hOfI2BFbG0XyfFOw
         fVMI+JVlxwblLBO6fG6padxdAI0dk8ZtttBCrKlnzqqWOY6a1GhBwyocP2FLWuiB1+rk
         o/2hniXSLib9SGYCKfHyQMdA7/76wVKXMD7BxQy9gwYBSm5pZPfL0aVh/S62EYt4Lj/C
         i8pQ==
X-Gm-Message-State: AOAM533kNow27zR+Z41JkKptJg7yr0zBoiksvWR+lKHyPEWCQlNKw41F
	ndE99n3Ra9UQUMxWLya8OHc=
X-Google-Smtp-Source: ABdhPJxY2V3zHwBRHZxowi6pS116lyI1SoNmZQ1aA1LdZQC82PSUbweUgmje912oUYg+06F/YO8veg==
X-Received: by 2002:a67:f6d0:: with SMTP id v16mr7759459vso.11.1623429019067;
        Fri, 11 Jun 2021 09:30:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:b705:: with SMTP id h5ls2498370vsf.11.gmail; Fri, 11 Jun
 2021 09:30:18 -0700 (PDT)
X-Received: by 2002:a67:fc46:: with SMTP id p6mr9807525vsq.48.1623429018630;
        Fri, 11 Jun 2021 09:30:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623429018; cv=none;
        d=google.com; s=arc-20160816;
        b=Sz6o4r0eckz7vCH070dCsWe2SqJZh8b/DJ6EuQtHzO6ekw01eWIHySG0c/yDo8Blps
         bSFbl77rlKhwfUWNVWDRh6C91n196mkTf/ZmuFaH6tJ2G1yz194UR+OD33fNVgpgk8vx
         mVzM2E/VMEb2Az+EPDN0yMvYCToaPVrgD6WAWOPAmiJ4QMRfxf7SVtXYgPYb5aWANzhu
         APusQr5CS6RS7Epp9mje2TqcISZ7890bf2E098B8sf0c9sB2eA64/GMzjAdljLH9y6/b
         8kx2hGEVKs96UPNzRoeXfp4HUWRhALwgbI+KhZxzqtwxz6PzzxljElXL2C1y3Kj1NOfN
         g68g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=loSuEwYH2/ErgrOv9smUX/ZtX7NHKWXh5VA17UsKWAU=;
        b=m2BrsghDO2fAqImDhJxgdGE/Gn5CmhbeI1EMSR17Mj4FaXuIPu1n+wooohCCosWDiW
         GJJyfKPIC+HXnIw5YoFfjxufF5RfIN5hUapfdYfQf5VPPpfO7QRpcyduWwy3IBZd/p8O
         nAN6nf5ln7NmNOEXnD/Zd05D5/y8o6E5g79gZR7NvV8cT39WAToDA1HJUCBLa7MSdV36
         Wshz6IWQq3THsfyYyxqfiUq0lYcGKkctmu17ypqysCxhBjny771qkQVJrFFnb0Du8H8r
         z4FEe4L1fTfk27H7ZDuHNoL8YvjAIBQQQMDFHXlRNNOYb89mr/zAgqDiKDq/BzIqTsAB
         1CqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=NhVTjKTk;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id d18si648067vsf.0.2021.06.11.09.30.16
        for <kasan-dev@googlegroups.com>;
        Fri, 11 Jun 2021 09:30:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.20.15])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygCHj1tUj8NgA0LIAA--.30112S2;
	Sat, 12 Jun 2021 00:29:09 +0800 (CST)
Date: Sat, 12 Jun 2021 00:23:34 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andreas Schwab <schwab@linux-m68k.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>, Alexei Starovoitov
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko
 <andrii@kernel.org>, Martin KaFai Lau <kafai@fb.com>, Song Liu
 <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, John Fastabend
 <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, Luke Nelson
 <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: Re: [PATCH 7/9] riscv: bpf: Avoid breaking W^X
Message-ID: <20210612002334.6af72545@xhacker>
In-Reply-To: <87o8ccqypw.fsf@igel.home>
References: <20210330022144.150edc6e@xhacker>
	<20210330022521.2a904a8c@xhacker>
	<87o8ccqypw.fsf@igel.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: LkAmygCHj1tUj8NgA0LIAA--.30112S2
X-Coremail-Antispam: 1UD129KBjvJXoW3AFy3KryxZr4UJr1rCw13CFg_yoW7Wr47pr
	4UAr1UGr48tr1UJr18Cr15AF1UAr1UAa13JFnrJrZ5J3WUWw1DJr18JrW7CF1DGr1rJF17
	tr1DXr48tr1DGaUanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkCb7Iv0xC_Kw4lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Ar0_tr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26F4j6r4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Jr
	0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	W8JVWxJwCI42IY6xAIw20EY4v20xvaj40_WFyUJVCq3wCI42IY6I8E87Iv67AKxVWUJVW8
	JwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnIWIevJa73UjIFyTuYvjxUg0D7DU
	UUU
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=NhVTjKTk;       spf=pass
 (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as
 permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
X-Original-From: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Reply-To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
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

Hi Andreas,

On Fri, 11 Jun 2021 16:10:03 +0200
Andreas Schwab <schwab@linux-m68k.org> wrote:

> On M=C3=A4r 30 2021, Jisheng Zhang wrote:
>=20
> > From: Jisheng Zhang <jszhang@kernel.org>
> >
> > We allocate Non-executable pages, then call bpf_jit_binary_lock_ro()
> > to enable executable permission after mapping them read-only. This is
> > to prepare for STRICT_MODULE_RWX in following patch. =20
>=20
> That breaks booting with
> <https://github.com/openSUSE/kernel-source/blob/master/config/riscv64/def=
ault>.
>=20

Thanks for the bug report.
I reproduced an kernel panic with the defconfig on qemu, but I'm not sure w=
hether
this is the issue you saw, I will check.

    0.161959] futex hash table entries: 512 (order: 3, 32768 bytes, linear)
[    0.167028] pinctrl core: initialized pinctrl subsystem
[    0.190727] Unable to handle kernel paging request at virtual address ff=
ffffff81651bd8
[    0.191361] Oops [#1]
[    0.191509] Modules linked in:
[    0.191814] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.13.0-rc5-default=
+ #3
[    0.192179] Hardware name: riscv-virtio,qemu (DT)
[    0.192492] epc : __memset+0xc4/0xfc
[    0.192712]  ra : skb_flow_dissector_init+0x22/0x86
[    0.192915] epc : ffffffff803e2700 ra : ffffffff8058f90c sp : ffffffe001=
a4fda0
[    0.193221]  gp : ffffffff8156d120 tp : ffffffe001a5b700 t0 : ffffffff81=
651b10
[    0.193631]  t1 : 0000000000000100 t2 : 00000000000003a8 s0 : ffffffe001=
a4fdd0
[    0.194034]  s1 : ffffffff80c9e250 a0 : ffffffff81651bd8 a1 : 0000000000=
000000
[    0.194502]  a2 : 000000000000003c a3 : ffffffff81651c10 a4 : 0000000000=
000064
[    0.195053]  a5 : ffffffff803e2700 a6 : 0000000000000040 a7 : 0000000000=
000002
[    0.195436]  s2 : ffffffff81651bd8 s3 : 0000000000000009 s4 : ffffffff81=
56e0c8
[    0.195723]  s5 : ffffffff8156e050 s6 : ffffffff80a105e0 s7 : ffffffff80=
a00738
[    0.195992]  s8 : ffffffff80f07be0 s9 : 0000000000000008 s10: ffffffff80=
8000ac
[    0.196257]  s11: 0000000000000000 t3 : fffffffffffffffc t4 : 0000000000=
000000
[    0.196511]  t5 : 00000000000003a9 t6 : 00000000000003ff
[    0.196714] status: 0000000000000120 badaddr: ffffffff81651bd8 cause: 00=
0000000000000f
[    0.197103] [<ffffffff803e2700>] __memset+0xc4/0xfc
[    0.197408] [<ffffffff80831f58>] init_default_flow_dissectors+0x22/0x60
[    0.197693] [<ffffffff800020fc>] do_one_initcall+0x3e/0x168
[    0.197907] [<ffffffff80801438>] kernel_init_freeable+0x25a/0x2c6
[    0.198157] [<ffffffff8070a8a8>] kernel_init+0x12/0x110
[    0.198351] [<ffffffff8000333a>] ret_from_exception+0x0/0xc
[    0.198973] Unable to handle kernel paging request at virtual address ff=
ffffff8164d860
[    0.199242] Oops [#2]
[    0.199336] Modules linked in:
[    0.199514] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G      D           5.=
13.0-rc5-default+ #3
[    0.199785] Hardware name: riscv-virtio,qemu (DT)
[    0.199940] epc : _raw_spin_lock_irqsave+0x14/0x4e
[    0.200113]  ra : _extract_crng+0x58/0xac
[    0.200264] epc : ffffffff807117ae ra : ffffffff80490774 sp : ffffffe001=
a4fa70
[    0.200489]  gp : ffffffff8156d120 tp : ffffffe001a5b700 t0 : ffffffff81=
57c0d7
[    0.200715]  t1 : ffffffff8157c0c8 t2 : 0000000000000000 s0 : ffffffe001=
a4fa80
[    0.200938]  s1 : ffffffff8164d818 a0 : 0000000000000022 a1 : ffffffe001=
a4fac8
[    0.201166]  a2 : 0000000000000010 a3 : 0000000000000001 a4 : ffffffff81=
64d860
[    0.201389]  a5 : 0000000000000000 a6 : c0000000ffffdfff a7 : ffffffffff=
ffffff
[    0.201612]  s2 : ffffffff8156e1c0 s3 : ffffffe001a4fac8 s4 : ffffffff81=
64d860
[    0.201836]  s5 : ffffffff8156e0c8 s6 : ffffffff80a105e0 s7 : ffffffff80=
a00738
[    0.202060]  s8 : ffffffff80f07be0 s9 : 0000000000000008 s10: ffffffff80=
8000ac
[    0.202295]  s11: 0000000000000000 t3 : 000000000000005b t4 : ffffffffff=
ffffff
[    0.202519]  t5 : 00000000000003a9 t6 : ffffffe001a4f9b8
[    0.202691] status: 0000000000000100 badaddr: ffffffff8164d860 cause: 00=
0000000000000f
[    0.202940] [<ffffffff807117ae>] _raw_spin_lock_irqsave+0x14/0x4e
[    0.203326] Unable to handle kernel paging request at virtual address ff=
ffffff8164d860
[    0.203574] Oops [#3]
[    0.203664] Modules linked in:
[    0.203784] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G      D           5.=
13.0-rc5-default+ #3
[    0.204046] Hardware name: riscv-virtio,qemu (DT)
[    0.204201] epc : _raw_spin_lock_irqsave+0x14/0x4e
[    0.204371]  ra : _extract_crng+0x58/0xac
[    0.204519] epc : ffffffff807117ae ra : ffffffff80490774 sp : ffffffe001=
a4f740
[    0.204819]  gp : ffffffff8156d120 tp : ffffffe001a5b700 t0 : ffffffff81=
57c0d7
[    0.205089]  t1 : ffffffff8157c0c8 t2 : 0000000000000000 s0 : ffffffe001=
a4f750
[    0.205330]  s1 : ffffffff8164d818 a0 : 0000000000000102 a1 : ffffffe001=
a4f798
[    0.205553]  a2 : 0000000000000010 a3 : 0000000000000001 a4 : ffffffff81=
64d860
[    0.205768]  a5 : 0000000000000000 a6 : c0000000ffffdfff a7 : ffffffff81=
408a40
[    0.205981]  s2 : ffffffff8156e1c0 s3 : ffffffe001a4f798 s4 : ffffffff81=
64d860
[    0.206197]  s5 : ffffffff8156e0c8 s6 : ffffffff80a105e0 s7 : ffffffff80=
a00738
[    0.206411]  s8 : ffffffff80f07be0 s9 : 0000000000000008 s10: ffffffff80=
8000ac
[    0.206633]  s11: 0000000000000000 t3 : 000000000000005b t4 : ffffffffff=
ffffff
[    0.206849]  t5 : 00000000000003a9 t6 : ffffffe001a4f688



--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210612002334.6af72545%40xhacker.
