Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU6O7WAQMGQEXKT2TRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2553532B6BB
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 11:39:16 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id g17sf26297236ybh.4
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 02:39:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614767955; cv=pass;
        d=google.com; s=arc-20160816;
        b=H/MTlX34IJ7GNYh7utqFC3FNbWf39YffSQGxEa5/sxXOBF+gBnPtI8Uh68GRgqKvMx
         kvdl87DSwgPYft2XcYYffGFI3k+mGWWCZnrNuNy93EdiWd+lVXVNctGVt7iazv6qFuLS
         a8GRTkHAQfMjsPpJQxsBzHu3M2umftEPJ70fFKR9NH1GmAu+qnXEueCtPnwxccSbBPr6
         aghN+vrjqHFS34oaWodcyaNBgqxh0EogPwDsQa+AsBMjyQENlc9x4z1fdEIpDfcFgvc7
         urTjMDdyqA9abBD0oZ+tqp9OCNFV94M3zuWCmP71JOyh4/uaRVX016At39yTjnTbiFEk
         AO6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+5le2IXVIkofErjBRgyJ7EC8vrJQjov2J13QAUDr544=;
        b=pZHLyVas/2hyJVeDa+YMAciwXTwzRgdrzJ32uJVyLgkXMxcXkkNIC1TI9nK629S+Hy
         yeMuGf8aQtwk2FjOldsaBaCwMD5di4cpP/eqpyIqT2e0ADjesqsgGD5zXp8fqOotbg/Y
         nrgxaND1loyve0gLs7JQGxNdh8/DFt4ZFV4H/PhWAv/sfQqEtpWdaZJmSvUXBDpXjJdu
         YcNzSUWpuLH7XI4reVGGjQ8mPBKWiDX/4l2tOCKmDS9pyBvkjijLxiXhsI8Rn2fXRcYj
         GwXe7Sb/b3G5+vYXjFJkslc0rxHq4qXPBCnlFKGsPZwjsWzucZ1+hAvPhmX2TICNfE0t
         0UNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YAoB3Pva;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=+5le2IXVIkofErjBRgyJ7EC8vrJQjov2J13QAUDr544=;
        b=e4/wtoHSEFXehvBJQoZgGQySnNz/gHE9V30eNiISFYw3DDlIwHPiJKj2y5Xl/kLF4K
         OM0Id8Q8XxSL2b9CKngUMMCLbXaZ7xZ9UaB3pf/7nf4VE0T8PYVeSMklWNj4EzGUWkhT
         +CYxWb8UDse6R/nzEmf9ZM+W2Nak/0z9I7mdWzS/srX1Tgt+apBZVDSX0TXTHnHuKp74
         74qeympDpdNhEJBBRMSQV++8UDY1v6G86RGPDZSSDOXoiI11e3mJhFh06zfq8Rw2r3Ov
         5SmvVb2tuSfdZICzRdKcM7BGUgU0oECOyEG5wu7xAW6auAHfniWyeu5QNaDU7GdFdsXw
         VBrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+5le2IXVIkofErjBRgyJ7EC8vrJQjov2J13QAUDr544=;
        b=Lz1VvCCBFhp2UW57E5KLrnYWiAcBIXSC8gj5AuatcBj62Q8Rv9PGpUWijJmE4oxRAo
         Hv1rUEhnNBxgJa2O1b3+HBJjpYGdbpAoSqcNMbO03Vx+mnN1ZMXCo8IVPI+VS83XJIJ/
         iw+QGAPXSQ0PZEk8t58FHjW9gkAlSse0Lt0OwsDHVDz+q7nZTlJg/BpmNUzAlUv+q47x
         OqAm+GET0qBAuS4bFkNFdToDdOlBltRbT3vCy3OPaDgiQrR0eWVGyam6Rn7VU3f1lplX
         hJYGDflW3ElAE5FGjT8BvpuWbHuYLNaJt/yym52im1dEajSEyNfxoIveFKlvHFC6efaw
         RXSA==
X-Gm-Message-State: AOAM531lJELqg6yIiTviuxSjXVmmgjgjxIpODITecpwHURqEhkF8eK+G
	L+Oi6d8eo5CXrhLWkRmtFms=
X-Google-Smtp-Source: ABdhPJy9RAzzgK/2959pslGHxlGKrCyNmWKweOlhGJt0/Mm9oM2EjCqQLY/WYahougwjaYEZxfTT6w==
X-Received: by 2002:a25:7d84:: with SMTP id y126mr36726157ybc.179.1614767955225;
        Wed, 03 Mar 2021 02:39:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d907:: with SMTP id q7ls908845ybg.3.gmail; Wed, 03 Mar
 2021 02:39:14 -0800 (PST)
X-Received: by 2002:a25:1008:: with SMTP id 8mr3187022ybq.21.1614767954671;
        Wed, 03 Mar 2021 02:39:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614767954; cv=none;
        d=google.com; s=arc-20160816;
        b=ohWQP85/CrSd3/D5duXEvQz/oL64PCUfyPFRPNoXFfJOd+BxVV/CN/r0choNKmsbEb
         DowBFuyI/nQfFCuOMAakABrqwOFuttxRRpggHDLHTDaJou1/dW517WmZfy27NAJVKOPb
         BKeY7YQJphEkI135yYDJ5TcnlVCTc+6juMqkgIJ/2G6rh0QAmp1maub27dEWSp4XFuiR
         wHqKPdLciPi6c4OAR2/9qk6a7kCNtH3ZlQU4rZXGblbFJ7QzhxsW8AO0Rw/7O7jY6xlB
         jlVS3xeWoUxfdgFiMixyDSQCbcEX0kHGUzrGMX3463FPBavGTtp6Lk9OA46t6Jjd6Sn/
         YZBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oa11Uxo3wLTqZSkd+I1gIQsAxvPirjDmAcK7uIr/Uf0=;
        b=UG22Q2plb0jLEYz02A8KRQRQ3GeELt+fuCJqP3l1eQTXK+AcCBOiCTSuzGNc+wlPuC
         AvIgpLpa2RQOPl9nEW6J2QBAMoOrVWOKioFvtV0SX0x1qVB3GLlrNjf0B3wEXOS7FsWs
         3eIFramCbphn+6UAP7Q3wfSB7E+uDSUN3ONBooaaHMRtOM1qpau16PR7ual672TO4evZ
         qUhYITjxgV0Kwg/vAidG8vI6lU3f3s/yrHdIOZvpm6kJV9gNt1X5r+gpxh8S0NbCHmOE
         xlV2g+CTl+6mLZIqhs+pWVWU5h8ZhRzY6MeVC/F548I4Kn2mp3J0kGC6K/uk2vs5ObCj
         FcZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YAoB3Pva;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id s44si1834585ybi.3.2021.03.03.02.39.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Mar 2021 02:39:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id q203so2399331oih.5
        for <kasan-dev@googlegroups.com>; Wed, 03 Mar 2021 02:39:14 -0800 (PST)
X-Received: by 2002:a05:6808:10d3:: with SMTP id s19mr6860226ois.70.1614767954014;
 Wed, 03 Mar 2021 02:39:14 -0800 (PST)
MIME-Version: 1.0
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
 <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu> <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu> <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <3abbe4c9-16ad-c168-a90f-087978ccd8f7@csgroup.eu>
In-Reply-To: <3abbe4c9-16ad-c168-a90f-087978ccd8f7@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Mar 2021 11:39:02 +0100
Message-ID: <CANpmjNMKEObjf=WyfDQB5vPmR5RuyUMBJyfr6P2ykCd67wyMbA@mail.gmail.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Alexander Potapenko <glider@google.com>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YAoB3Pva;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 3 Mar 2021 at 11:32, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
>
>
> Le 02/03/2021 =C3=A0 10:53, Marco Elver a =C3=A9crit :
> > On Tue, 2 Mar 2021 at 10:27, Christophe Leroy
> > <christophe.leroy@csgroup.eu> wrote:
> >> Le 02/03/2021 =C3=A0 10:21, Alexander Potapenko a =C3=A9crit :
> >>>> [   14.998426] BUG: KFENCE: invalid read in finish_task_switch.isra.=
0+0x54/0x23c
> >>>> [   14.998426]
> >>>> [   15.007061] Invalid read at 0x(ptrval):
> >>>> [   15.010906]  finish_task_switch.isra.0+0x54/0x23c
> >>>> [   15.015633]  kunit_try_run_case+0x5c/0xd0
> >>>> [   15.019682]  kunit_generic_run_threadfn_adapter+0x24/0x30
> >>>> [   15.025099]  kthread+0x15c/0x174
> >>>> [   15.028359]  ret_from_kernel_thread+0x14/0x1c
> >>>> [   15.032747]
> >>>> [   15.034251] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
> >>>> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
> >>>> [   15.045811] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >>>> [   15.053324]     # test_invalid_access: EXPECTATION FAILED at mm/k=
fence/kfence_test.c:636
> >>>> [   15.053324]     Expected report_matches(&expect) to be true, but =
is false
> >>>> [   15.068359]     not ok 21 - test_invalid_access
> >>>
> >>> The test expects the function name to be test_invalid_access, i. e.
> >>> the first line should be "BUG: KFENCE: invalid read in
> >>> test_invalid_access".
> >>> The error reporting function unwinds the stack, skips a couple of
> >>> "uninteresting" frames
> >>> (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c=
#L43)
> >>> and uses the first "interesting" one frame to print the report header
> >>> (https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c=
#L226).
> >>>
> >>> It's strange that test_invalid_access is missing altogether from the
> >>> stack trace - is that expected?
> >>> Can you try printing the whole stacktrace without skipping any frames
> >>> to see if that function is there?
> >>>
> >>
> >> Booting with 'no_hash_pointers" I get the following. Does it helps ?
> >>
> >> [   16.837198] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> [   16.848521] BUG: KFENCE: invalid read in finish_task_switch.isra.0+=
0x54/0x23c
> >> [   16.848521]
> >> [   16.857158] Invalid read at 0xdf98800a:
> >> [   16.861004]  finish_task_switch.isra.0+0x54/0x23c
> >> [   16.865731]  kunit_try_run_case+0x5c/0xd0
> >> [   16.869780]  kunit_generic_run_threadfn_adapter+0x24/0x30
> >> [   16.875199]  kthread+0x15c/0x174
> >> [   16.878460]  ret_from_kernel_thread+0x14/0x1c
> >> [   16.882847]
> >> [   16.884351] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
> >> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
> >> [   16.895908] NIP:  c016eb8c LR: c02f50dc CTR: c016eb38
> >> [   16.900963] REGS: e2449d90 TRAP: 0301   Tainted: G    B
> >> (5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty)
> >> [   16.911386] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: 000=
00000
> >> [   16.918153] DAR: df98800a DSISR: 20000000
> >> [   16.918153] GPR00: c02f50dc e2449e50 c1140d00 e100dd24 c084b13c 000=
00008 c084b32b c016eb38
> >> [   16.918153] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
> >> [   16.936695] NIP [c016eb8c] test_invalid_access+0x54/0x108
> >> [   16.942125] LR [c02f50dc] kunit_try_run_case+0x5c/0xd0
> >> [   16.947292] Call Trace:
> >> [   16.949746] [e2449e50] [c005a5ec] finish_task_switch.isra.0+0x54/0x=
23c (unreliable)
> >
> > The "(unreliable)" might be a clue that it's related to ppc32 stack
> > unwinding. Any ppc expert know what this is about?
> >
> >> [   16.957443] [e2449eb0] [c02f50dc] kunit_try_run_case+0x5c/0xd0
> >> [   16.963319] [e2449ed0] [c02f63ec] kunit_generic_run_threadfn_adapte=
r+0x24/0x30
> >> [   16.970574] [e2449ef0] [c004e710] kthread+0x15c/0x174
> >> [   16.975670] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x1c
> >> [   16.981896] Instruction dump:
> >> [   16.984879] 8129d608 38e7eb38 81020280 911f004c 39000000 995f0024 9=
07f0028 90ff001c
> >> [   16.992710] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908adb0=
 812a4b98 3d40c02f
> >> [   17.000711] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> [   17.008223]     # test_invalid_access: EXPECTATION FAILED at mm/kfe=
nce/kfence_test.c:636
> >> [   17.008223]     Expected report_matches(&expect) to be true, but is=
 false
> >> [   17.023243]     not ok 21 - test_invalid_access
> >
> > On a fault in test_invalid_access, KFENCE prints the stack trace based
> > on the information in pt_regs. So we do not think there's anything we
> > can do to improve stack printing pe-se.
> >
> > What's confusing is that it's only this test, and none of the others.
> > Given that, it might be code-gen related, which results in some subtle
> > issue with stack unwinding. There are a few things to try, if you feel
> > like it:
> >
> > -- Change the unwinder, if it's possible for ppc32.
> >
> > -- Add code to test_invalid_access(), to get the compiler to emit
> > different code. E.g. add a bunch (unnecessary) function calls, or add
> > barriers, etc.
> >
> > -- Play with compiler options. We already pass
> > -fno-optimize-sibling-calls for kfence_test.o to avoid tail-call
> > optimizations that'd hide stack trace entries. But perhaps there's
> > something ppc-specific we missed?
> >
> > Well, the good thing is that KFENCE detects the bad access just fine.
> > Since, according to the test, everything works from KFENCE's side, I'd
> > be happy to give my Ack:
> >
> >    Acked-by: Marco Elver <elver@google.com>
> >
>
> Thanks.
>
> For you information, I've got a pile of warnings from mm/kfence/report.o =
. Is that expected ?
>
>    CC      mm/kfence/report.o
> In file included from ./include/linux/printk.h:7,
>                   from ./include/linux/kernel.h:16,
>                   from mm/kfence/report.c:10:
> mm/kfence/report.c: In function 'kfence_report_error':
> ./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argumen=
t of type 'signed size_t',
> but argument 6 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
>      5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
>        |                  ^~~~~~
> ./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_SO=
H'
>     11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
>        |                  ^~~~~~~~
> ./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
>    343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
>        |         ^~~~~~~~
> mm/kfence/report.c:207:3: note: in expansion of macro 'pr_err'
>    207 |   pr_err("Out-of-bounds %s at 0x%p (%luB %s of kfence-#%zd):\n",
>        |   ^~~~~~
> ./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argumen=
t of type 'signed size_t',
> but argument 4 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
>      5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
>        |                  ^~~~~~
> ./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_SO=
H'
>     11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
>        |                  ^~~~~~~~
> ./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
>    343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
>        |         ^~~~~~~~
> mm/kfence/report.c:216:3: note: in expansion of macro 'pr_err'
>    216 |   pr_err("Use-after-free %s at 0x%p (in kfence-#%zd):\n",
>        |   ^~~~~~
> ./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argumen=
t of type 'signed size_t',
> but argument 2 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
>      5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
>        |                  ^~~~~~
> ./include/linux/kern_levels.h:24:19: note: in expansion of macro 'KERN_SO=
H'
>     24 | #define KERN_CONT KERN_SOH "c"
>        |                   ^~~~~~~~
> ./include/linux/printk.h:385:9: note: in expansion of macro 'KERN_CONT'
>    385 |  printk(KERN_CONT fmt, ##__VA_ARGS__)
>        |         ^~~~~~~~~
> mm/kfence/report.c:223:3: note: in expansion of macro 'pr_cont'
>    223 |   pr_cont(" (in kfence-#%zd):\n", object_index);
>        |   ^~~~~~~
> ./include/linux/kern_levels.h:5:18: warning: format '%zd' expects argumen=
t of type 'signed size_t',
> but argument 3 has type 'ptrdiff_t' {aka 'const long int'} [-Wformat=3D]
>      5 | #define KERN_SOH "\001"  /* ASCII Start Of Header */
>        |                  ^~~~~~
> ./include/linux/kern_levels.h:11:18: note: in expansion of macro 'KERN_SO=
H'
>     11 | #define KERN_ERR KERN_SOH "3" /* error conditions */
>        |                  ^~~~~~~~
> ./include/linux/printk.h:343:9: note: in expansion of macro 'KERN_ERR'
>    343 |  printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
>        |         ^~~~~~~~
> mm/kfence/report.c:233:3: note: in expansion of macro 'pr_err'
>    233 |   pr_err("Invalid free of 0x%p (in kfence-#%zd):\n", (void *)add=
ress,
>        |   ^~~~~~
>
> Christophe

No this is not expected. Is 'signed size_t' !=3D 'long int' on ppc32?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMKEObjf%3DWyfDQB5vPmR5RuyUMBJyfr6P2ykCd67wyMbA%40mail.gmai=
l.com.
