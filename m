Return-Path: <kasan-dev+bncBCMIZB7QWENRBPESQ2QAMGQEW367V4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CF386A908B
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 06:44:29 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id l14-20020a5d526e000000b002cd851d79b2sf178675wrc.5
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 21:44:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677822268; cv=pass;
        d=google.com; s=arc-20160816;
        b=i+YgeTCeybFc7plu/GLqiaxheSj07nZumRA3OJ07fhWqQD+YNwwPoEljggWGjNFVXM
         tyHeudMCJkzlb4MHhgcD9jICyot91BiOEyaoP0UBmj7MmLEwZAXyo9Kx2RQtefOwmpB9
         CFrCav23R+rDjszV2IZ70FI8vpsXdQ4QpNmKlZKb3WsxBnhiSDLTuhsinv87c6tMQGjm
         t4TyL6CqUM1oyuQkh7NP5XcFeUZU4r+R2J1noGpaWhR8fLpHBINuMNI/SkNnhE6f5MKC
         R7w74ICWx7tzJ7JouZfm5BlN7bhSq0HaS3bcONthzAcCdywIR+jUWk2TFf6mrxINgoP3
         5jUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YfBpOgHEGf0tlsxi4PrYkxFLrxL9Y5pCOWaG26EyHKE=;
        b=iy2+VRLKhbrvJGpO48IL7dd2pv6G3G7ZcPpFMbnRz8at925NuoSozt6F2qSZOXmxFF
         FJYObhMv51YrrYm4xsmNs7FDa/Jqs6mM3UgbtE+5FGr2GQ7sxSYy13SFlkCCczWSdD4i
         zYjmSpqRUp3Ex5o/V6nN72PrGjDD6B/eK9jROYerek3YPjf+iFxiqyS+NNkWU3aY1jmA
         fN7e7OHvEBIOqt834kMj2fmOy9cKuZZ6Et7MOlux7yHn8xLbsvIeKRQ8jTewMOU8+Ner
         EEa3gMZQRtMbkU0o8ZsIEuKOq1GFt1QSPJvPFdvObc+EkCgau7GRoSOEKNdnIQ8LPNRu
         PaKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=slrJxt7m;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677822268;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YfBpOgHEGf0tlsxi4PrYkxFLrxL9Y5pCOWaG26EyHKE=;
        b=CM0Gm0wCKLSfQWaj8/KTCWA5p5tQi8EdHPkNCmINuEHOy+DvI150JcG8GAsfc8xapX
         vjun8yTVfQyTLkCp+1r4IQvBpVe8sswpi/+6xEpvBhrEcA8XXmidVkyHkO7m6Y7w2Sin
         DORpUHpv3pPuOjfdFJukZ6PTU2inVorTuMdI0FuVt9u1MowqB+iv11zOmPUc51Gyx2C0
         Pgna7zytcb5CRZ6Zcyqan3QJ5Z56/z9ZfpSab2ZB51pdz1kNKEVpG0U68AYtZp0piRzj
         LxdxFAbCh8FUvjnhWqPxy+Jj/FgS67HFcBRHGXlXXo4Bs+X8KyEVlF2OqiZ6iFkdkOBJ
         qaWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677822268;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YfBpOgHEGf0tlsxi4PrYkxFLrxL9Y5pCOWaG26EyHKE=;
        b=r3UZ9mPGTCXdqiFMAAQbQtR/+Cj2uc+6grbTW/j3alN6ZY8jcz855q6PAHspYoAETh
         /NKo7r5eDjgP1rKwwfWlW2DCPdDOCZzYV90KxUZSYFNKhtGipopm0kpiQ3SMXw80emNR
         z+PED19mUOhCVaKidYGEWygBqy7cLtcDLcZuWuoRIf/CZyDV7x4y3Bdkgh1xpv2deI7b
         wGnCeIoG6xBY9DKvc/eWK6cBiIyMCPnlkmwNd+dAe1KNl/PIdBCL640rnmrPnXHGDIKU
         odmKHXX1L/dTZwSBNXIXG3brPM/opqPQ0A13R5hj3HaKexG3ih6aRjCA4100WPwLb8AW
         xRUw==
X-Gm-Message-State: AO0yUKWQ7Ob7RisKZcwI/yyDVXtlafdI7G3IrYyzGLqY7hauRWNE4yyG
	cFSxvHH8g873nwKti5vA7BY=
X-Google-Smtp-Source: AK7set9s6AsIbpwf175jjLbM91ZxFCs/sJd8IwjUnvLzefCDoYB4umE8qEnRtlwEjSxTrN5P5I6fhQ==
X-Received: by 2002:a05:600c:a3a1:b0:3eb:2e68:5c76 with SMTP id hn33-20020a05600ca3a100b003eb2e685c76mr117334wmb.3.1677822268468;
        Thu, 02 Mar 2023 21:44:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c01:b0:3dc:5300:3d83 with SMTP id
 j1-20020a05600c1c0100b003dc53003d83ls897859wms.0.-pod-control-gmail; Thu, 02
 Mar 2023 21:44:26 -0800 (PST)
X-Received: by 2002:a05:600c:45d2:b0:3df:e6bb:768 with SMTP id s18-20020a05600c45d200b003dfe6bb0768mr411184wmo.24.1677822266830;
        Thu, 02 Mar 2023 21:44:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677822266; cv=none;
        d=google.com; s=arc-20160816;
        b=gaTjXfaDJF7FqvYPTdy2R29U3h/pP6zKhfQi2aOcueTgOnB+KtJ2TXul9Ank+ut571
         M9vLXBFF02lGkF7BaBvBxYk7TA03+AmKO6zCi02Y4Ipb7asDI69jalsjDWIEJGWoQFq7
         BkSzN2rmZlefk8qZt7IUunSX65KT95smMCLBybiHxNsx8vVLzF8/uANN2dx0Z7m9y7m3
         8Ja0dw9jggIOwTGcYy39z8Zx/4C4qyvE0LsM3S95TUBI+znz+odbYqmxqKAP9444Rq22
         vsE/eUP6JShk0Ez1VpXEsDJWm1P8ufjC6RkSvsf56wFzK2g5m1fG3H64kR8jVFxRLZRo
         065Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qWOckUXkp6qY/RaSFL4tFSFedCAxs9RCvjBq2qAr3Sk=;
        b=wJ/f1vHU7MFsoXP8zQCLk/ZuKUmMpiONwLlH6JGxAzwayAU3J+qKsvn99Bv2ZQHZAB
         gxW30VK9jGMbJEdiWktGcwg03GAZrs5aGzEifJOly4ZKMxBwG3p6g26zPgguVku3TrpQ
         /L0mepuUz/a8a0mxKktKGpHchp43xRzvbjWvYPicow5QfwIoLEeGRq7slPTfSZglpY4+
         Voq9xNUQyKW2/LOAilLqv4v5lLDkwtaCfHc5WqNk5rfi8Loj4sBgb/7cx9N9tICZuLvZ
         5PgpEgC3Ide/MPn8/ekilLeJY1rwJICVnVJ2Gx4CdQ2xN+8QqdkTwLmK660StLOZzVZ8
         EKbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=slrJxt7m;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id h10-20020a05600c314a00b003db110e1928si194187wmo.1.2023.03.02.21.44.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Mar 2023 21:44:26 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id n2so2150827lfb.12
        for <kasan-dev@googlegroups.com>; Thu, 02 Mar 2023 21:44:26 -0800 (PST)
X-Received: by 2002:a05:6512:68:b0:4d5:ca32:9bd7 with SMTP id
 i8-20020a056512006800b004d5ca329bd7mr248513lfo.3.1677822265864; Thu, 02 Mar
 2023 21:44:25 -0800 (PST)
MIME-Version: 1.0
References: <CAD7mqryyz0PGHotBxvME7Ff4V0zLS+OcL8=9z4TakaKagPBdLw@mail.gmail.com>
 <789371c4-47fd-3de5-d6c0-bb36b2864796@ghiti.fr> <CAD7mqrzv-jr_o2U3Kz7vTgcsOYPKgwHW-L=ARAucAPPJgs4HCw@mail.gmail.com>
 <CAD7mqryDQCYyJ1gAmtMm8SASMWAQ4i103ptTb0f6Oda=tPY2=A@mail.gmail.com> <067b7dda-8d3d-a26c-a0b1-bd6472a4b04d@ghiti.fr>
In-Reply-To: <067b7dda-8d3d-a26c-a0b1-bd6472a4b04d@ghiti.fr>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 3 Mar 2023 06:44:13 +0100
Message-ID: <CACT4Y+avaVT4sBOioxm8N+iH26udKwAogRhjMwGWcp4zzC8JdA@mail.gmail.com>
Subject: Re: RISC-V Linux kernel not booting up with KASAN enabled
To: alex@ghiti.fr
Cc: Chathura Rajapaksha <chathura.abeyrathne.lk@gmail.com>, linux-riscv@lists.infradead.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=slrJxt7m;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, 2 Mar 2023 at 21:11, Alexandre Ghiti <alex@ghiti.fr> wrote:
>
> +cc Dmitry and kasan-dev, in case they know about this but I did not
> find anything related

Hard to say anything w/o commit/symbolized report.
If it's stack unwinder and it's supposed to be precise, then it may be
a bug in the unwinder where it reads a wrong location and is imprecise
(not the frame pointer).
If it's supposed to be imprecise, then it should use READ_ONCE_NOCHECK
to read random stack locations.

> On 3/2/23 19:01, Chathura Rajapaksha wrote:
> > Hi Alex/All,
> >
> > Kernel is booting now but I get the following KASAN failure in the
> > bootup itself.
> > I didn't see this bug was reported before anywhere.
> >
> > [    0.000000] Memory: 63436K/129024K available (20385K kernel code,
> > 7120K rwdata, 4096K rodata, 2138K init, 476K bss, 65588K reserved, 0K
> > cma-reserved)
> > [    0.000000] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > [    0.000000] BUG: KASAN: stack-out-of-bounds in walk_stackframe+0x1b2=
/0x1e2
> > [    0.000000] Read of size 8 at addr ffffffff81e07c40 by task swapper/=
0
> > [    0.000000]
> > [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted
> > 6.2.0-gae3419fbac84-dirty #7
> > [    0.000000] Hardware name: riscv-virtio,qemu (DT)
> > [    0.000000] Call Trace:
> > [    0.000000] [<ffffffff8000ab9e>] walk_stackframe+0x0/0x1e2
> > [    0.000000] [<ffffffff80108508>] init_param_lock+0x26/0x2a
> > [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
> > [    0.000000] [<ffffffff813d86e0>] dump_stack_lvl+0x22/0x36
> > [    0.000000] [<ffffffff813bd17a>] print_report+0x198/0x4a8
> > [    0.000000] [<ffffffff80108508>] init_param_lock+0x26/0x2a
> > [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
> > [    0.000000] [<ffffffff8023bd52>] kasan_report+0x9a/0xc8
> > [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
> > [    0.000000] [<ffffffff8000ad4c>] walk_stackframe+0x1ae/0x1e2
> > [    0.000000] [<ffffffff80108748>] stack_trace_save+0x88/0xa6
> > [    0.000000] [<ffffffff801086bc>] filter_irq_stacks+0x8a/0x8e
> > [    0.000000] [<ffffffff800b65e2>] devkmsg_read+0x3f8/0x3fc
> > [    0.000000] [<ffffffff8023b2de>] kasan_save_stack+0x2c/0x56
> > [    0.000000] [<ffffffff80108744>] stack_trace_save+0x84/0xa6
> > [    0.000000] [<ffffffff8023b31a>] kasan_set_track+0x12/0x20
> > [    0.000000] [<ffffffff8023b8f6>] __kasan_slab_alloc+0x58/0x5e
> > [    0.000000] [<ffffffff8023aeae>] __kmem_cache_create+0x21e/0x39a
> > [    0.000000] [<ffffffff8141623e>] create_boot_cache+0x70/0x9c
> > [    0.000000] [<ffffffff8141b5f6>] kmem_cache_init+0x6c/0x11e
> > [    0.000000] [<ffffffff8140125a>] mm_init+0xd8/0xfe
> > [    0.000000] [<ffffffff8140145c>] start_kernel+0x190/0x3ca
> > [    0.000000]
> > [    0.000000] The buggy address belongs to stack of task swapper/0
> > [    0.000000]  and is located at offset 0 in frame:
> > [    0.000000]  stack_trace_save+0x0/0xa6
> > [    0.000000]
> > [    0.000000] This frame has 1 object:
> > [    0.000000]  [32, 56) 'c'
> > [    0.000000]
> > [    0.000000] The buggy address belongs to the physical page:
> > [    0.000000] page:(____ptrval____) refcount:1 mapcount:0
> > mapping:0000000000000000 index:0x0 pfn:0x82007
> > [    0.000000] flags: 0x1000(reserved|zone=3D0)
> > [    0.000000] raw: 0000000000001000 ff60000007ca5090 ff60000007ca5090
> > 0000000000000000
> > [    0.000000] raw: 0000000000000000 0000000000000000 00000001ffffffff
> > [    0.000000] page dumped because: kasan: bad access detected
> > [    0.000000]
> > [    0.000000] Memory state around the buggy address:
> > [    0.000000]  ffffffff81e07b00: 00 00 00 00 00 00 00 00 00 00 00 00
> > 00 00 00 00
> > [    0.000000]  ffffffff81e07b80: 00 00 00 00 00 00 00 00 00 00 00 00
> > 00 00 00 00
> > [    0.000000] >ffffffff81e07c00: 00 00 00 00 00 00 00 00 f1 f1 f1 f1
> > 00 00 00 f3
> > [    0.000000]                                            ^
> > [    0.000000]  ffffffff81e07c80: f3 f3 f3 f3 00 00 00 00 00 00 00 00
> > 00 00 00 00
> > [    0.000000]  ffffffff81e07d00: 00 00 00 00 00 00 00 00 00 00 00 00
> > 00 00 00 00
> > [    0.000000] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
>
> I was able to reproduce the exact same trace, I'll debug that tomorrow,
> I hope it is a real bug :)
>
> Thanks for the report Chatura,
>
> Alex
>
>
> >
> > Best,
> > Chath
> >
> > On Thu, Mar 2, 2023 at 11:25=E2=80=AFAM Chathura Rajapaksha
> > <chathura.abeyrathne.lk@gmail.com> wrote:
> >> Hi Alex,
> >>
> >> Thank you very much, kernel booted up with the patches you mentioned.
> >> Bootup was pretty slow compared to before though (on a dev board).
> >> I guess that is kind of expected with KASAN enabled.
> >> Thanks again.
> >>
> >> Regards,
> >> Chath
> >>
> >> On Thu, Mar 2, 2023 at 2:50=E2=80=AFAM Alexandre Ghiti <alex@ghiti.fr>=
 wrote:
> >>> Hi Chatura,
> >>>
> >>> On 3/2/23 04:13, Chathura Rajapaksha wrote:
> >>>> Hi All,
> >>>>
> >>>> I observed that RISC-V Linux hangs when I enable KASAN.
> >>>> Without KASAN it works fine with QEMU.
> >>>> I am using the commit ae3419fbac845b4d3f3a9fae4cc80c68d82cdf6e
> >>>>
> >>>> When KASAN is enabled, QEMU hangs after OpenSBI prints.
> >>>>
> >>>> I noticed a similar issue was reported before in
> >>>> https://lore.kernel.org/lkml/CACT4Y+ZmuOpyf_0vHTT4t3wkmJuW8Ezvcg7v6y=
DVd8YOViS=3DGA@mail.gmail.com/t/
> >>>> But I believe I have the patch mentioned in that thread.
> >>>
> >>> I proposed a series that will be included in 6.3 regarding KASAN issu=
es
> >>> here: https://patchwork.kernel.org/project/linux-riscv/list/?series=
=3D718458
> >>>
> >>> Can you give it a try and tell me if it works better?
> >>>
> >>> Thanks,
> >>>
> >>> Alex
> >>>
> >>>
> >>>> My kernel config:
> >>>> https://drive.google.com/file/d/1j9nU7f9MxCc_i-UHUCTvo7o6nDrcUz0w/vi=
ew?usp=3Dsharing
> >>>>
> >>>> Best regards,
> >>>> Chath
> >>>>
> >>>> _______________________________________________
> >>>> linux-riscv mailing list
> >>>> linux-riscv@lists.infradead.org
> >>>> http://lists.infradead.org/mailman/listinfo/linux-riscv
> >
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BavaVT4sBOioxm8N%2BiH26udKwAogRhjMwGWcp4zzC8JdA%40mail.gm=
ail.com.
