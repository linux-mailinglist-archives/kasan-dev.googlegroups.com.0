Return-Path: <kasan-dev+bncBAABBNFDV2DAMGQEYSIM5KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E4EE3ABB45
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 20:17:25 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id v19-20020a4a31530000b029024944222912sf4440202oog.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 11:17:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623953844; cv=pass;
        d=google.com; s=arc-20160816;
        b=a7fTq+GZGdUWqaY10p9mInyj0nhJFhPHouQ41o1bHmUiGaYPOlmCV7ziigXyfpj8bN
         PtBMmjog5sdet+gveh8ohHGl/+vOyiH0ckutmHcNk7FV2dzRBDHlme30op22zDW6mOaL
         p5m7VGapdbvhkm4JxP/yJdr+IOUi3tRIMToTbojpLX2mnnAugIho60qsbh76XlCHxR8V
         y1yEnEOz6dDmqeEd4BiH8pzhoyw0ZFx0ZV4I7rfeoksCfwas7q3rjw4w+mdQ4UezeDen
         GC/aRfTytDb3L5XMpe+Cj+iAA9/AZbcDVRiFV99xq8GsJoYNlqpnuOnZLi7gFq859grr
         3YjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=8Hc03/su6RrxLvtsEOw+ZEMKL/3lfiQGBcKeUp8KhjU=;
        b=u+Fo7VyTPcfecCnoHr9lt/sbd65jtKOgIANqlhr6ymlz64amI7AwVOg0Ghz8HNztzV
         eSPt9juDuW9y/v18jV4FL9D0D5gyddSQ4SjouhpqDLBA+WMVmf0X/4yZnT6gEVdGDY+u
         YOLlOJk23P1jX84nfDPEAtP7yUF6yUH3zDhMGkxufYxP7iAvjTcc706THfk17NDHxvwt
         l31yCiZGpmx6WzBxqTbgfu85MzuuViBoVZAHJjXOdmWF90/l6w52sby34f8aX7EQPcvn
         pj+jInndHahWkjQTATgF3PiElF+h20mjJh6HBLK02MLyv6K96U76/kFTpu7M+ygawr4J
         KArg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=pwmNuilL;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=8Hc03/su6RrxLvtsEOw+ZEMKL/3lfiQGBcKeUp8KhjU=;
        b=NIb26a4fOg1W7H36A8WYVq/XzKm58hjyN+AarO086xD7C0DBi5aWhJMoziAho/XUKn
         qFTD1soAdpW9x1TL5orvMXUqAXyR1i0qBiZNERQjF5jeoekEhWWTyHFTysdIWgyx/BJ+
         +BR7i8Fb0PaD251zZ/VZh0TsvB4dUw3ElqV7hnf6r3tV4VsfjlLgyMa/Xm2sWKVtGrkz
         +T96Xi6NV7ucvh7XN38noh93kNsHvfJwBq3l/Lc/jqqN7U6FxgGxpCa7IBCJUGpf320k
         ZSfKn5RIMg9yqe416ThzR1/2fWibha2rdFgJcNWGEq1d71PKPoSkZTV6y+LypXXkRZ1d
         ld+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Hc03/su6RrxLvtsEOw+ZEMKL/3lfiQGBcKeUp8KhjU=;
        b=mjeY06HQDFUICvnjxKw52SlyXMjb+aeNUcv8ciUV0Ktzv3BEo5qhTjrMUShIE/z081
         uUpwFiQbMvbaKqImS6ENZhofqTtbqGY5jahuKvjtcOBEUl4q2h0/eCtqd7OzvyU+rtXD
         DtpSMr3R8Bym4gR1ACYb9E2EyMY9Oi6d90a/G7Qza4l6MSMvBP4bivSJii8DpLRChJHY
         IcNOyKOBR3hcph7dJOJ99WYwPUFITBbhi+PRdks8CWxERwRTZCWs6HvvZIeggthjnUay
         +cKE83iaVolK0F3SGrl3h+ayS3xvqF70uuj3uBk1Ny/xZqnUBS2eXo2Y3GvV+z+MKDWC
         Xsbg==
X-Gm-Message-State: AOAM533DFbQ4/7L0Mff8L+A00fujUT4j5JngkLCS8w2VhCS+JMAFzkYI
	93lOOigDWIJhM1bTlNtdelA=
X-Google-Smtp-Source: ABdhPJwP+Gbx9qiIOLrSh5rQI91VYtN3D0HQHB8cL435/4rGdNtIrDyy9fHccRWZfFe4vYy70Ro86Q==
X-Received: by 2002:a9d:6508:: with SMTP id i8mr5482527otl.368.1623953844266;
        Thu, 17 Jun 2021 11:17:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5754:: with SMTP id l81ls2157522oib.9.gmail; Thu, 17 Jun
 2021 11:17:23 -0700 (PDT)
X-Received: by 2002:a05:6808:14c8:: with SMTP id f8mr4427707oiw.7.1623953843917;
        Thu, 17 Jun 2021 11:17:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623953843; cv=none;
        d=google.com; s=arc-20160816;
        b=LZP/+gXYavg1k1C02mLlJFUlEXr+UFfRSDcTUHAMx06+PuOQyMABYWUPI/Zq69t8VL
         mzUPFu+wnuvdWlLFUBas+j2M4gsp6VnzC2CX/vAXyq3kejP44PUzFTX+WAemMU85dLXP
         /84YU3vamuqpezJxzktzElHoicBZ/SyNkrVKFWT27b+/Wp+jqEpKnD1vND88CNkZ8+F5
         754YDUTscWRLghr+ENpG2dSrybXj1A3J1sPCc1CYHiQb/1UTJEfY45Yfkr2F4UP67znq
         YdD4FhPG6M+XIqKmsXI+SIrJQKsRLu69jwpEnEzzBW5oeiErHisBg5rlPTSuiAeqQY89
         T5+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Z7XdKee+EQziVNAT70nU6H2kFcBGtBk/IkTlYkN+608=;
        b=v1rsF8rvDope32qImXdsKSGNFub1sosvHuKP6gi/R11b9f+7Et9QVp5Mlv66pQP5hR
         lKlqwjkU0Hmf9YoyAxnumgFto+mjcE24Z3qU6OHzpi+K3jW9Uh9POATiZrdgyNPkyS/V
         xTdmUguoB9XymRS3sCtdzPPBDk4TL63Mb4c/oqWC+iH2Lje00K8ablZ+XLZ3Jw8lzcpZ
         u4PDduEu+raj2cPoZgzJyydAKV/DcUCjFDShOet312Bd+ZTn/r4Vy3uok5xHcgWgOOUK
         LShSmUqU4C7/WuVSJgYD8LZUIEoYtBaE6lN38rXXyDIfMH6KifGekUlL/UIyGlUOsz64
         AA2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=pwmNuilL;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id w16si666868oov.0.2021.06.17.11.17.21
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Jun 2021 11:17:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.20.15])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygAnKYFskctgSkT3AA--.4906S2;
	Fri, 18 Jun 2021 02:16:13 +0800 (CST)
Date: Fri, 18 Jun 2021 02:10:38 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alex Ghiti <alex@ghiti.fr>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, schwab@linux-m68k.org, Paul
 Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
 ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, bjorn@kernel.org, ast@kernel.org, daniel@iogearbox.net,
 andrii@kernel.org, kafai@fb.com, songliubraving@fb.com, yhs@fb.com,
 john.fastabend@gmail.com, kpsingh@kernel.org, luke.r.nels@gmail.com,
 xi.wang@gmail.com, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: Re: [PATCH] riscv: Ensure BPF_JIT_REGION_START aligned with PMD
 size
Message-ID: <20210618021038.52c2f558@xhacker>
In-Reply-To: <20210618014648.1857a62a@xhacker>
References: <mhng-042979fe-75f0-4873-8afd-f8c07942f792@palmerdabbelt-glaptop>
	<ae256a5d-70ac-3a5f-ca55-5e4210a0624c@ghiti.fr>
	<50ebc99c-f0a2-b4ea-fc9b-cd93a8324697@ghiti.fr>
	<20210618012731.345657bf@xhacker>
	<20210618014648.1857a62a@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: LkAmygAnKYFskctgSkT3AA--.4906S2
X-Coremail-Antispam: 1UD129KBjvJXoW3Zw1ftF1xGr13XF1kXF48tFb_yoWkXF1kpr
	1DJF43GrW8Jr18X342qry5GryUtw1UA3ZFqr1DJa4rJF9rKF1jqr1UXFy7urnFqF4xJ3W2
	yr4DJrsIv345Aw7anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUvEb7Iv0xC_Kw4lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwV
	C2z280aVCY1x0267AKxVW8Jr0_Cr1UM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVAC
	Y4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv67AKxVWUJV
	W8JwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkI
	wI1l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1l4IxYO2xFxVAFwI0_Jr
	v_JF1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY
	17CE14v26r4a6rW5MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcV
	C0I7IYx2IY6xkF7I0E14v26r4j6F4UMIIF0xvE42xK8VAvwI8IcIk0rVWrJr0_WFyUJwCI
	42IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnIWI
	evJa73UjIFyTuYvjxUg0D7DUUUU
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=pwmNuilL;       spf=pass
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

On Fri, 18 Jun 2021 01:46:48 +0800
Jisheng Zhang <jszhang3@mail.ustc.edu.cn> wrote:

> On Fri, 18 Jun 2021 01:27:31 +0800
> Jisheng Zhang <jszhang3@mail.ustc.edu.cn> wrote:
>=20
> > On Thu, 17 Jun 2021 16:18:54 +0200
> > Alex Ghiti <alex@ghiti.fr> wrote:
> >  =20
> > > Le 17/06/2021 =C3=A0 10:09, Alex Ghiti a =C3=A9crit=C2=A0:   =20
> > > > Le 17/06/2021 =C3=A0 09:30, Palmer Dabbelt a =C3=A9crit=C2=A0:     =
=20
> > > >> On Tue, 15 Jun 2021 17:03:28 PDT (-0700), jszhang3@mail.ustc.edu.c=
n=20
> > > >> wrote:     =20
> > > >>> On Tue, 15 Jun 2021 20:54:19 +0200
> > > >>> Alex Ghiti <alex@ghiti.fr> wrote:
> > > >>>     =20
> > > >>>> Hi Jisheng,     =20
> > > >>>
> > > >>> Hi Alex,
> > > >>>     =20
> > > >>>>
> > > >>>> Le 14/06/2021 =C3=A0 18:49, Jisheng Zhang a =C3=A9crit=C2=A0:   =
  =20
> > > >>>> > From: Jisheng Zhang <jszhang@kernel.org>     =20
> > > >>>> > > Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid    =
  =20
> > > >>>> breaking W^X")     =20
> > > >>>> > breaks booting with one kind of config file, I reproduced a ke=
rnel      =20
> > > >>>> panic     =20
> > > >>>> > with the config:     =20
> > > >>>> > > [=C2=A0=C2=A0=C2=A0 0.138553] Unable to handle kernel paging=
 request at virtual      =20
> > > >>>> address ffffffff81201220     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.139159] Oops [#1]
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.139303] Modules linked in:
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.139601] CPU: 0 PID: 1 Comm: swapper/0 No=
t tainted      =20
> > > >>>> 5.13.0-rc5-default+ #1     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.139934] Hardware name: riscv-virtio,qemu=
 (DT)
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.140193] epc : __memset+0xc4/0xfc
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.140416]=C2=A0 ra : skb_flow_dissector_in=
it+0x1e/0x82
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.140609] epc : ffffffff8029806c ra : ffff=
ffff8033be78 sp :      =20
> > > >>>> ffffffe001647da0     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.140878]=C2=A0 gp : ffffffff81134b08 tp :=
 ffffffe001654380 t0 :      =20
> > > >>>> ffffffff81201158     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.141156]=C2=A0 t1 : 0000000000000002 t2 :=
 0000000000000154 s0 :      =20
> > > >>>> ffffffe001647dd0     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.141424]=C2=A0 s1 : ffffffff80a43250 a0 :=
 ffffffff81201220 a1 :      =20
> > > >>>> 0000000000000000     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.141654]=C2=A0 a2 : 000000000000003c a3 :=
 ffffffff81201258 a4 :      =20
> > > >>>> 0000000000000064     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.141893]=C2=A0 a5 : ffffffff8029806c a6 :=
 0000000000000040 a7 :      =20
> > > >>>> ffffffffffffffff     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.142126]=C2=A0 s2 : ffffffff81201220 s3 :=
 0000000000000009 s4 :      =20
> > > >>>> ffffffff81135088     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.142353]=C2=A0 s5 : ffffffff81135038 s6 :=
 ffffffff8080ce80 s7 :      =20
> > > >>>> ffffffff80800438     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.142584]=C2=A0 s8 : ffffffff80bc6578 s9 :=
 0000000000000008 s10:      =20
> > > >>>> ffffffff806000ac     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.142810]=C2=A0 s11: 0000000000000000 t3 :=
 fffffffffffffffc t4 :      =20
> > > >>>> 0000000000000000     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.143042]=C2=A0 t5 : 0000000000000155 t6 :=
 00000000000003ff
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.143220] status: 0000000000000120 badaddr=
: ffffffff81201220      =20
> > > >>>> cause: 000000000000000f     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.143560] [<ffffffff8029806c>] __memset+0x=
c4/0xfc
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.143859] [<ffffffff8061e984>]      =20
> > > >>>> init_default_flow_dissectors+0x22/0x60     =20
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.144092] [<ffffffff800010fc>] do_one_init=
call+0x3e/0x168
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.144278] [<ffffffff80600df0>] kernel_init=
_freeable+0x1c8/0x224
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.144479] [<ffffffff804868a8>] kernel_init=
+0x12/0x110
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.144658] [<ffffffff800022de>] ret_from_ex=
ception+0x0/0xc
> > > >>>> > [=C2=A0=C2=A0=C2=A0 0.145124] ---[ end trace f1e9643daa46d591 =
]---     =20
> > > >>>> > > After some investigation, I think I found the root cause: co=
mmit     =20
> > > >>>> > 2bfc6cd81bd ("move kernel mapping outside of linear mapping") =
moves
> > > >>>> > BPF JIT region after the kernel:     =20
> > > >>>> > > The &_end is unlikely aligned with PMD size, so the front bp=
f jit     =20
> > > >>>> > region sits with part of kernel .data section in one PMD size =
     =20
> > > >>>> mapping.     =20
> > > >>>> > But kernel is mapped in PMD SIZE, when bpf_jit_binary_lock_ro(=
) is
> > > >>>> > called to make the first bpf jit prog ROX, we will make part o=
f      =20
> > > >>>> kernel     =20
> > > >>>> > .data section RO too, so when we write to, for example memset =
the
> > > >>>> > .data section, MMU will trigger a store page fault.     =20
> > > >>>> Good catch, we make sure no physical allocation happens between =
_end=20
> > > >>>> and the next PMD aligned address, but I missed this one.
> > > >>>>     =20
> > > >>>> > > To fix the issue, we need to ensure the BPF JIT region is PM=
D size     =20
> > > >>>> > aligned. This patch acchieve this goal by restoring the BPF JI=
T      =20
> > > >>>> region     =20
> > > >>>> > to original position, I.E the 128MB before kernel .text sectio=
n.     =20
> > > >>>> But I disagree with your solution: I made sure modules and BPF=
=20
> > > >>>> programs get their own virtual regions to avoid worst case scena=
rio=20
> > > >>>> where one could allocate all the space and leave nothing to the=
=20
> > > >>>> other (we are limited to +- 2GB offset). Why don't just align=20
> > > >>>> BPF_JIT_REGION_START to the next PMD aligned address?     =20
> > > >>>
> > > >>> Originally, I planed to fix the issue by aligning=20
> > > >>> BPF_JIT_REGION_START, but
> > > >>> IIRC, BPF experts are adding (or have added) "Calling kernel=20
> > > >>> functions from BPF"
> > > >>> feature, there's a risk that BPF JIT region is beyond the 2GB of=
=20
> > > >>> module region:
> > > >>>
> > > >>> ------
> > > >>> module
> > > >>> ------
> > > >>> kernel
> > > >>> ------
> > > >>> BPF_JIT
> > > >>>
> > > >>> So I made this patch finally. In this patch, we let BPF JIT regio=
n sit
> > > >>> between module and kernel.
> > > >>>
> > > >>> To address "make sure modules and BPF programs get their own virt=
ual=20
> > > >>> regions",
> > > >>> what about something as below (applied against this patch)?
> > > >>>
> > > >>> diff --git a/arch/riscv/include/asm/pgtable.h=20
> > > >>> b/arch/riscv/include/asm/pgtable.h
> > > >>> index 380cd3a7e548..da1158f10b09 100644
> > > >>> --- a/arch/riscv/include/asm/pgtable.h
> > > >>> +++ b/arch/riscv/include/asm/pgtable.h
> > > >>> @@ -31,7 +31,7 @@
> > > >>> =C2=A0#define BPF_JIT_REGION_SIZE=C2=A0=C2=A0=C2=A0 (SZ_128M)
> > > >>> =C2=A0#ifdef CONFIG_64BIT
> > > >>> =C2=A0#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (BPF_JIT_REG=
ION_END -=20
> > > >>> BPF_JIT_REGION_SIZE)
> > > >>> -#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (MODULES_END)
> > > >>> +#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigne=
d long)&_start))
> > > >>> =C2=A0#else
> > > >>> =C2=A0#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET=
 - BPF_JIT_REGION_SIZE)
> > > >>> =C2=A0#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (VMALLOC_END)
> > > >>> @@ -40,7 +40,7 @@
> > > >>> =C2=A0/* Modules always live before the kernel */
> > > >>> =C2=A0#ifdef CONFIG_64BIT
> > > >>> =C2=A0#define MODULES_VADDR=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigne=
d long)&_end) - SZ_2G)
> > > >>> -#define MODULES_END=C2=A0=C2=A0=C2=A0 (PFN_ALIGN((unsigned long)=
&_start))
> > > >>> +#define MODULES_END=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_END)
> > > >>> =C2=A0#endif
> > > >>>
> > > >>>
> > > >>>     =20
> > > >>>>
> > > >>>> Again, good catch, thanks,
> > > >>>>
> > > >>>> Alex
> > > >>>>     =20
> > > >>>> > > Reported-by: Andreas Schwab <schwab@linux-m68k.org>     =20
> > > >>>> > Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> > > >>>> > ---
> > > >>>> >=C2=A0=C2=A0 arch/riscv/include/asm/pgtable.h | 5 ++---
> > > >>>> >=C2=A0=C2=A0 1 file changed, 2 insertions(+), 3 deletions(-)   =
  =20
> > > >>>> > > diff --git a/arch/riscv/include/asm/pgtable.h      =20
> > > >>>> b/arch/riscv/include/asm/pgtable.h     =20
> > > >>>> > index 9469f464e71a..380cd3a7e548 100644
> > > >>>> > --- a/arch/riscv/include/asm/pgtable.h
> > > >>>> > +++ b/arch/riscv/include/asm/pgtable.h
> > > >>>> > @@ -30,9 +30,8 @@     =20
> > > >>>> > >=C2=A0=C2=A0 #define BPF_JIT_REGION_SIZE=C2=A0=C2=A0=C2=A0 (S=
Z_128M)     =20
> > > >>>> >=C2=A0=C2=A0 #ifdef CONFIG_64BIT
> > > >>>> > -/* KASLR should leave at least 128MB for BPF after the kernel=
 */
> > > >>>> > -#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 PFN_ALIGN((uns=
igned long)&_end)
> > > >>>> > -#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGION_=
START +      =20
> > > >>>> BPF_JIT_REGION_SIZE)     =20
> > > >>>> > +#define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (BPF_JIT_REGIO=
N_END -      =20
> > > >>>> BPF_JIT_REGION_SIZE)     =20
> > > >>>> > +#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (MODULES_END)
> > > >>>> >=C2=A0=C2=A0 #else
> > > >>>> >=C2=A0=C2=A0 #define BPF_JIT_REGION_START=C2=A0=C2=A0=C2=A0 (PA=
GE_OFFSET - BPF_JIT_REGION_SIZE)
> > > >>>> >=C2=A0=C2=A0 #define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0 (VMAL=
LOC_END)
> > > >>>> >      =20
> > > >>
> > > >> This, when applied onto fixes, is breaking early boot on KASAN=20
> > > >> configurations for me.     =20
> >=20
> > I can reproduce this issue.
> >  =20
> > > >=20
> > > > Not surprising, I took a shortcut when initializing KASAN for modul=
es,=20
> > > > kernel and BPF:
> > > >=20
> > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_populate(kasan_me=
m_to_shadow((const void *)MODULES_VADDR),
> > > >  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kasan_me=
m_to_shadow((const void=20
> > > > *)BPF_JIT_REGION_END));
> > > >=20
> > > > The kernel is then not covered, I'm taking a look at how to fix tha=
t=20
> > > > properly.
> > > >     =20
> > >=20
> > > The following based on "riscv: Introduce structure that group all=20
> > > variables regarding kernel mapping" fixes the issue:
> > >=20
> > > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> > > index 9daacae93e33..2a45ea909e7f 100644
> > > --- a/arch/riscv/mm/kasan_init.c
> > > +++ b/arch/riscv/mm/kasan_init.c
> > > @@ -199,9 +199,12 @@ void __init kasan_init(void)
> > >                  kasan_populate(kasan_mem_to_shadow(start),=20
> > > kasan_mem_to_shadow(end));
> > >          }
> > >=20
> > > -       /* Populate kernel, BPF, modules mapping */
> > > +       /* Populate BPF and modules mapping: modules mapping encompas=
ses=20
> > > BPF mapping */
> > >          kasan_populate(kasan_mem_to_shadow((const void *)MODULES_VAD=
DR),
> > > -                      kasan_mem_to_shadow((const void=20
> > > *)BPF_JIT_REGION_END));
> > > +                      kasan_mem_to_shadow((const void *)MODULES_END)=
);
> > > +       /* Populate kernel mapping */
> > > +       kasan_populate(kasan_mem_to_shadow((const void=20
> > > *)kernel_map.virt_addr),
> > > +                      kasan_mem_to_shadow((const void=20
> > > *)kernel_map.virt_addr + kernel_map.size));
> > >   =20
> > If this patch works, maybe we can still use one kasan_populate() to cov=
er
> > kernel, bpf, and module:
> >=20
> >         kasan_populate(kasan_mem_to_shadow((const void *)MODULES_VADDR)=
,
> > -                      kasan_mem_to_shadow((const void *)BPF_JIT_REGION=
_END));
> > +                      kasan_mem_to_shadow((const void *)MODULES_VADDR =
+ SZ_2G));
> >  =20
>=20
> I made a mistake. Below patch works:
>=20
>         kasan_populate(kasan_mem_to_shadow((const void *)MODULES_VADDR),
> -                      kasan_mem_to_shadow((const void *)BPF_JIT_REGION_E=
ND));
> +                      kasan_mem_to_shadow((const void *)(MODULES_VADDR +=
 SZ_2G)));

This isn't the key. I knew the reason now. kasan_init() has local vars name=
d
as _start and _end, then MODULES_VADDR is defined as:
#define MODULES_VADDR   (PFN_ALIGN((unsigned long)&_end) - SZ_2G)

So MODULES_VADDR isn't what we expected. To fix it, we must rename the loca=
l
vars

>=20
> > However, both can't solve the early boot hang issue. I'm not sure what'=
s missing.
> >=20
> > I applied your patch on rc6 + solution below "replace kernel_map.virt_a=
ddr with kernel_virt_addr and
> > kernel_map.size with load_sz"
> >=20
> >=20
> > Thanks
> >   =20
> > >=20
> > > Without the mentioned patch, replace kernel_map.virt_addr with=20
> > > kernel_virt_addr and kernel_map.size with load_sz. Note that load_sz =
was=20
> > > re-exposed in v6 of the patchset "Map the kernel with correct=20
> > > permissions the first time".
> > >    =20
> >=20
> >=20
> > _______________________________________________
> > linux-riscv mailing list
> > linux-riscv@lists.infradead.org
> > http://lists.infradead.org/mailman/listinfo/linux-riscv =20
>=20


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210618021038.52c2f558%40xhacker.
