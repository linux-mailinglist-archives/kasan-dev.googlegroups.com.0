Return-Path: <kasan-dev+bncBAABBL4KV2DAMGQEGNVPIFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D6193ABA95
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 19:24:00 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id e17-20020aa798110000b02902f12fffef4esf4142201pfl.7
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 10:24:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623950639; cv=pass;
        d=google.com; s=arc-20160816;
        b=TZe2PzC0oAI5njKc76o5iaLYo34y/fvCS7G4RKK+tvFLjH+D3by+KE7W90txgqySdv
         PN5IpdAZXUfCkgx3eipYf17X5D9BxAJXM8Niy+SqY466PhbLNxDKUsowoIouAXiGxQ+S
         CBztcLQVMzIy4kAy9wMKmi+YiQgq1gV04qLiwMFxt1azCifRhs8mFQZ1gWM2DV5vZYMf
         7dvHuXPkumkZj5R3Gvm1EGNCiHGwUTDU6D8qFOibkuIIRfjZgeSQ5eu0WJpAuTo5XpIB
         9+DS+oqqUvxwnuvKJjYNTscjjT9kEYpLaOR3xMsV6y2ijezoajoD76dCWxCX8TnAVMrP
         lt8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=6DVraiSvzqt7XuW8an+Ysq/Z2M6qe+to4dZM3q06aR8=;
        b=lZvqZhZFidHmJRxolQGJqx12t+SM/XrWODjCKRGKu6oMzEUZaSPUQFZIP5TNaPWd5z
         Avbzm1p1YZdpUock7/+Mx6WjmJRew3x2V6kJUa7bw+SkUsQceNScpUbl+Z/++Gyam0wg
         uPj3PxjSbnoehwzgquMe6+NnQFcI22e101bDLJ6zBQo6gX8e5Nc9Xoj5k1dnjq1KHx94
         kNc/HM9QLHE5unY5UxAJnaouUQi/NznLC2FIMBYEDT6DR8CwzxBwWCqSZijNP2c7wRPd
         c/aE9TK5/2W2pq9EjzTwkzvPNhnf+lLUBrCy4WTA+uD45YK4RHLjrQb6Ba+SwzhtXy1w
         8zjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=LC9c56KA;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6DVraiSvzqt7XuW8an+Ysq/Z2M6qe+to4dZM3q06aR8=;
        b=QPp4dMCoIkTUSDiHNQSlfKaonIQ+uD9qYVdkckI2p7rcAQXpMNqOgo8rPfmR1h0moc
         sqwK5DAjmcHnw6zyjzNrp1KICnuUxNP1ykkAHZtqBo7vQ5a/N7kZlDJt83uKVyPLdKWV
         VIQAIa8R2Q6hKY3bvuU4BIIoGey2+Lb5gonWqhPuvd7ht9MdFa+h0zFZ+dlm7AL7rgmh
         riYXDmH5ND0vyX08Jn3dXn34exV346KjX/TtIH3Hz4UpArNJxmi8unNNvnFhmZdSPr0B
         Z3Oz/Sb8P3l+sSvSzCGGV8BlReE0eQ35X+frzCiQfO7gDW8/HBOsnQOSht3Rg8WX4UPB
         k+PA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6DVraiSvzqt7XuW8an+Ysq/Z2M6qe+to4dZM3q06aR8=;
        b=UJ/GdtScE/aubq0tjD9Cb63p58bwFhSew1aHmtLzZl1qmIvva/vMlnYcmvruHJtqhO
         GrHb784pdX3z5QbEHjzWNwXPCW4Q9zNUJdRwdZYnvCHSjkv8LiX4J8kystAba4hmahIn
         HKZhLit8oFUaXJys6Rxw49ATFCF5CSCyVrGgoL0dDVWMYMEO3DlLjXazJnhh4ZcD+451
         HTjeat7Sc8/4V+eYCvcPKIkTm6fbMwPGtZVMpTi5iUq9R9CsS1wZIdveoBZ7cK/z8vfF
         JluJd/k7ziPCv+1Z9i/LCb/TViguOamd0CpAkolrnu9BX/tjeeRXWtvSIUsaq7pgaX57
         i5AA==
X-Gm-Message-State: AOAM532nzMJkaL+4HSY8BjIxMgSBdguAYipMDR+uLBPtj/vm4nwpO+Xj
	Lq/+fpbrZOxIxtAqJzVMCWw=
X-Google-Smtp-Source: ABdhPJw4NOGA6AZrtMGwQn5Xz/ijdsmW281aFBYoCJXIOpWp2LDdrMJeRuksoWFIq273aKFlPrb52A==
X-Received: by 2002:a63:1a5b:: with SMTP id a27mr5892159pgm.427.1623950639186;
        Thu, 17 Jun 2021 10:23:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:e23:: with SMTP id d35ls1596508pgl.5.gmail; Thu, 17 Jun
 2021 10:23:58 -0700 (PDT)
X-Received: by 2002:a63:e253:: with SMTP id y19mr5960127pgj.137.1623950638737;
        Thu, 17 Jun 2021 10:23:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623950638; cv=none;
        d=google.com; s=arc-20160816;
        b=l9uuj62zns6z6/I6ZkBHNRmpT3SXr4AwJxOZQRNKl9AYYCQX7dg13sWUza4meOyL07
         IApUjreT8x6bw+4fG2/5IInM2XF2LnUxj1rgp3jmJQXTRzQYyijMFdnh8DzPioDoyoKQ
         dxD3aLGfAn/LOv5Wr991ta3WXddi73qUvpC4DFWJhj0wJO4/3dHHakaXaTqwUGgJD9Tz
         EBD6i2CKGjZIYX9FWp/j/eOo8hcOOJNc9/BtLh9lF4Yz1PayyigfU/Fc+z6QgE0oIr3M
         BPO40rceUTaqMgSJP9uwvuUL0b5e/CW0HpLWuUDVt4hTixntCHkjMJD/S8RoRQpBQDkm
         3JBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=zuggjvpts9K1MPrpdIvHo11IpZU+3fBBgNvj3uKB8go=;
        b=KEMmQOcWIGPUv06mRDLWh6qER+FJ74PWakxiVoCgggU0ct0556vepbv8vw4aqTucFQ
         +e+2wJSN0DoLmLQq3kdDLuEh9QlDand1SaFOtJcQN6l+1UrOxkSM7Os2fKDp5X9OyRoj
         Aij4DpY6kv11sPzkn6Y/KpEymZ/2GRARLwsaGH5bqWy1OKcXr/z/IOX1yjaxqFid6kD/
         7Wav5ZzHz/eFAkBij1MhTg+0+nP8o46/PCOztnthlLCunUKwwunw0IDcDPIKT/sjIt08
         cbR08yjgp+sbdXJdBxs9K/wgJTQx2PY8q9whcl+7u4Qc3hupT9PwAmw7dgR0kPrC+qGQ
         b2Hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=LC9c56KA;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id d123si579202pfa.2.2021.06.17.10.23.57
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Jun 2021 10:23:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.20.15])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygBn1JTphMtgHwD3AA--.17025S2;
	Fri, 18 Jun 2021 01:22:50 +0800 (CST)
Date: Fri, 18 Jun 2021 01:17:12 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alex Ghiti <alex@ghiti.fr>
Cc: Andreas Schwab <schwab@linux-m68k.org>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou
 <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>, Alexei Starovoitov
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko
 <andrii@kernel.org>, Martin KaFai Lau <kafai@fb.com>, Song Liu
 <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, John Fastabend
 <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, Luke Nelson
 <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: Re: [PATCH] riscv: Ensure BPF_JIT_REGION_START aligned with PMD
 size
Message-ID: <20210618011712.2bbacb27@xhacker>
In-Reply-To: <4cdb1261-6474-8ae6-7a92-a3be81ce8cb5@ghiti.fr>
References: <20210330022144.150edc6e@xhacker>
	<20210330022521.2a904a8c@xhacker>
	<87o8ccqypw.fsf@igel.home>
	<20210612002334.6af72545@xhacker>
	<87bl8cqrpv.fsf@igel.home>
	<20210614010546.7a0d5584@xhacker>
	<87im2hsfvm.fsf@igel.home>
	<20210615004928.2d27d2ac@xhacker>
	<ab536c78-ba1c-c65c-325a-8f9fba6e9d46@ghiti.fr>
	<20210616080328.6548e762@xhacker>
	<4cdb1261-6474-8ae6-7a92-a3be81ce8cb5@ghiti.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: LkAmygBn1JTphMtgHwD3AA--.17025S2
X-Coremail-Antispam: 1UD129KBjvJXoWxtFW7Wr4xXrWkKFW3XFy3XFb_yoW7tFy8pF
	15JF43KrW8Jr1UAryIv34Yvr1Utw1UAa47WrnrJr95AF15Kr1UZr10qrW7ur1qqry8C3Wx
	Krs0yrs2yFWUCaDanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkGb7Iv0xC_Kw4lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Xr0_Ar1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwV
	C2z280aVCY1x0267AKxVW8Jr0_Cr1UM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVAC
	Y4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv67AKxVWUJV
	W8JwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkI
	wI1l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxV
	WUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r4a6rW5MIIYrxkI
	7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26r
	4j6F4UMIIF0xvE42xK8VAvwI8IcIk0rVWrZr1j6s0DMIIF0xvEx4A2jsIE14v26r1j6r4U
	MIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07b5sjbUUU
	UU=
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=LC9c56KA;       spf=pass
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

On Thu, 17 Jun 2021 09:23:04 +0200
Alex Ghiti <alex@ghiti.fr> wrote:

> Le 16/06/2021 =C3=A0 02:03, Jisheng Zhang a =C3=A9crit=C2=A0:
> > On Tue, 15 Jun 2021 20:54:19 +0200
> > Alex Ghiti <alex@ghiti.fr> wrote:
> >  =20
> >> Hi Jisheng, =20
> >=20
> > Hi Alex,
> >  =20
> >>
> >> Le 14/06/2021 =C3=A0 18:49, Jisheng Zhang a =C3=A9crit=C2=A0: =20
> >>> From: Jisheng Zhang <jszhang@kernel.org>
> >>>
> >>> Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid breaking W^X=
")
> >>> breaks booting with one kind of config file, I reproduced a kernel pa=
nic
> >>> with the config:
> >>>
> >>> [    0.138553] Unable to handle kernel paging request at virtual addr=
ess ffffffff81201220
> >>> [    0.139159] Oops [#1]
> >>> [    0.139303] Modules linked in:
> >>> [    0.139601] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.13.0-rc5-d=
efault+ #1
> >>> [    0.139934] Hardware name: riscv-virtio,qemu (DT)
> >>> [    0.140193] epc : __memset+0xc4/0xfc
> >>> [    0.140416]  ra : skb_flow_dissector_init+0x1e/0x82
> >>> [    0.140609] epc : ffffffff8029806c ra : ffffffff8033be78 sp : ffff=
ffe001647da0
> >>> [    0.140878]  gp : ffffffff81134b08 tp : ffffffe001654380 t0 : ffff=
ffff81201158
> >>> [    0.141156]  t1 : 0000000000000002 t2 : 0000000000000154 s0 : ffff=
ffe001647dd0
> >>> [    0.141424]  s1 : ffffffff80a43250 a0 : ffffffff81201220 a1 : 0000=
000000000000
> >>> [    0.141654]  a2 : 000000000000003c a3 : ffffffff81201258 a4 : 0000=
000000000064
> >>> [    0.141893]  a5 : ffffffff8029806c a6 : 0000000000000040 a7 : ffff=
ffffffffffff
> >>> [    0.142126]  s2 : ffffffff81201220 s3 : 0000000000000009 s4 : ffff=
ffff81135088
> >>> [    0.142353]  s5 : ffffffff81135038 s6 : ffffffff8080ce80 s7 : ffff=
ffff80800438
> >>> [    0.142584]  s8 : ffffffff80bc6578 s9 : 0000000000000008 s10: ffff=
ffff806000ac
> >>> [    0.142810]  s11: 0000000000000000 t3 : fffffffffffffffc t4 : 0000=
000000000000
> >>> [    0.143042]  t5 : 0000000000000155 t6 : 00000000000003ff
> >>> [    0.143220] status: 0000000000000120 badaddr: ffffffff81201220 cau=
se: 000000000000000f
> >>> [    0.143560] [<ffffffff8029806c>] __memset+0xc4/0xfc
> >>> [    0.143859] [<ffffffff8061e984>] init_default_flow_dissectors+0x22=
/0x60
> >>> [    0.144092] [<ffffffff800010fc>] do_one_initcall+0x3e/0x168
> >>> [    0.144278] [<ffffffff80600df0>] kernel_init_freeable+0x1c8/0x224
> >>> [    0.144479] [<ffffffff804868a8>] kernel_init+0x12/0x110
> >>> [    0.144658] [<ffffffff800022de>] ret_from_exception+0x0/0xc
> >>> [    0.145124] ---[ end trace f1e9643daa46d591 ]---
> >>>
> >>> After some investigation, I think I found the root cause: commit
> >>> 2bfc6cd81bd ("move kernel mapping outside of linear mapping") moves
> >>> BPF JIT region after the kernel:
> >>>
> >>> The &_end is unlikely aligned with PMD size, so the front bpf jit
> >>> region sits with part of kernel .data section in one PMD size mapping=
.
> >>> But kernel is mapped in PMD SIZE, when bpf_jit_binary_lock_ro() is
> >>> called to make the first bpf jit prog ROX, we will make part of kerne=
l
> >>> .data section RO too, so when we write to, for example memset the
> >>> .data section, MMU will trigger a store page fault. =20
> >>
> >> Good catch, we make sure no physical allocation happens between _end a=
nd
> >> the next PMD aligned address, but I missed this one.
> >> =20
> >>>
> >>> To fix the issue, we need to ensure the BPF JIT region is PMD size
> >>> aligned. This patch acchieve this goal by restoring the BPF JIT regio=
n
> >>> to original position, I.E the 128MB before kernel .text section. =20
> >>
> >> But I disagree with your solution: I made sure modules and BPF program=
s
> >> get their own virtual regions to avoid worst case scenario where one
> >> could allocate all the space and leave nothing to the other (we are
> >> limited to +- 2GB offset). Why don't just align BPF_JIT_REGION_START t=
o
> >> the next PMD aligned address? =20
> >=20
> > Originally, I planed to fix the issue by aligning BPF_JIT_REGION_START,=
 but
> > IIRC, BPF experts are adding (or have added) "Calling kernel functions =
from BPF"
> > feature, there's a risk that BPF JIT region is beyond the 2GB of module=
 region:
> >=20
> > ------
> > module
> > ------
> > kernel
> > ------
> > BPF_JIT
> >=20
> > So I made this patch finally. In this patch, we let BPF JIT region sit
> > between module and kernel.
> >  =20
>=20
>  From what I read in the lwn article, I'm not sure BPF programs can call=
=20
> module functions, can someone tell us if it is possible? Or planned?

What about module call BPF program? this case also wants the 2GB address li=
mit.

>=20
> > To address "make sure modules and BPF programs get their own virtual re=
gions",
> > what about something as below (applied against this patch)?
> >=20
> > diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/=
pgtable.h
> > index 380cd3a7e548..da1158f10b09 100644
> > --- a/arch/riscv/include/asm/pgtable.h
> > +++ b/arch/riscv/include/asm/pgtable.h
> > @@ -31,7 +31,7 @@
> >   #define BPF_JIT_REGION_SIZE	(SZ_128M)
> >   #ifdef CONFIG_64BIT
> >   #define BPF_JIT_REGION_START	(BPF_JIT_REGION_END - BPF_JIT_REGION_SIZ=
E)
> > -#define BPF_JIT_REGION_END	(MODULES_END)
> > +#define BPF_JIT_REGION_END	(PFN_ALIGN((unsigned long)&_start))
> >   #else
> >   #define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
> >   #define BPF_JIT_REGION_END	(VMALLOC_END)
> > @@ -40,7 +40,7 @@
> >   /* Modules always live before the kernel */
> >   #ifdef CONFIG_64BIT
> >   #define MODULES_VADDR	(PFN_ALIGN((unsigned long)&_end) - SZ_2G)
> > -#define MODULES_END	(PFN_ALIGN((unsigned long)&_start))
> > +#define MODULES_END	(BPF_JIT_REGION_END)
> >   #endif
> >  =20
> >  =20
>=20
> In case it is possible, I would let the vmalloc allocator handle the=20
> case where modules steal room from BPF: I would then not implement the=20
> above but rather your first patch.
>=20
> And do not forget to modify Documentation/riscv/vm-layout.rst=20
> accordingly and remove the comment "/* KASLR should leave at least 128MB=
=20
> for BPF after the kernel */"

Thanks for the comments

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210618011712.2bbacb27%40xhacker.
