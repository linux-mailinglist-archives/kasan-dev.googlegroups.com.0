Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJX2QOBAMGQE5TWC6PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id B62D132D6A9
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 16:30:47 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id s197sf2091913oie.12
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 07:30:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614871846; cv=pass;
        d=google.com; s=arc-20160816;
        b=MO/kK8Ar0Zk0NIFdWBrRfli7QU9f+m6TIEn36tbFjXt5FImHSTj0N9z0BUoZvngiNd
         jc31A4rUWO493G1Nq1yLaNa/1RnKVadGLE7jS36UgnAqKaQ4T8aWRkop2NWZjqBmMBdr
         hZ1lPp3iBg5kwFfOfN1kxnPi2Q8PjVfKDunQmcDmoKi8+Qt4WPmfaDb8VINlPZe+8yMr
         meKTCFfxMDWjCyOIlsX4tk60xfkMvnHbFyzzJlEP4tw8yHsLIXF6/5Ls7jG40vaoUKHI
         kD2y+5yEmU5Y3OiitpJd3mID8yfgIpeDTRoSCrYb3213OWm0zIRwSUwqSEANAvAG1U6G
         cf1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YFN6Isdxh5lMVd3+Vf3opyBCeFqQvMhexGzw/Z3pORI=;
        b=oEpMgeCHoQpVDqA0yueDIKdYL+rgyUHxnOBBXIrY9f754UQr7R5h4ERF2TBMLn3z9G
         lZrt2Fo88CrlVGl8mwGjIKwZGKpA+t0OE2oQxRmuxbK7d6DzmKfDwAu8omAwMKO62IVY
         HWw4D3cgIMtFA3QE3dXUT/5Y/Q8sOukPiE0BNZg8MdGCHXADhoqut7Cn02MeG1hi5SNk
         Z/HwpoE4sEVw+oXUXm652qZQYsHxUqUu3qDgQ8YWRl8kCSlWuPESuVtnGkcB6iRhWyCB
         Bj3NuqnvBUf6FhhhG0iUhJZqnUVHELeLDGg5nApVfUQC3FHpWXwQmPVuBt1Is9VMRaFG
         2HKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZbSTgcxF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=YFN6Isdxh5lMVd3+Vf3opyBCeFqQvMhexGzw/Z3pORI=;
        b=VBTSLtFIaJj4Orq8sX7XHMKij+AFcZO96mEkOSVL3ilRjKnVT9qw0Tv2SBhoQEaOBq
         1VXFm+aO1jaiJ3hYVoCRVr53i/plG6zFVN7lnkRy78xtb7ZqWHqXrCxgbcDRuLV4ld4+
         KO0NYT6WmzSSyUu00VIhJfoomc+j1NS244G4nDGwQ8bPFrCIs2fDqcRbEVCXXkAflf6z
         Szv7sIpbljfSp7u0FzeAyByb3LWUkk/3KFP2fpF83dJ7BrqiowqeceTQ3VG+az0XQ/GQ
         t+CGOVM9WnleYi0o+ZNRlkFUrY5j4Xz2Da2SFDMYILK4DDqG+27Fv09SmXb2504dygX5
         7npA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YFN6Isdxh5lMVd3+Vf3opyBCeFqQvMhexGzw/Z3pORI=;
        b=mQy3wvKL6Lo2PLp5KXY4cWmqenCy0Yclw/OxR4G2F6LYZIf25GrdbAMYyZbsn3oD/Q
         vZzwmvht9zFc32axg79eCumH+rn7YZfhLRK6PXQDxldEoSvGLnLT1sPxCjLEuvzRTwP0
         WaQ2geJ1KOkL7emiG03RzDOQ0r6N2qdycnzlz9IiyFCEl5hIaD6gnJHlAVO/9DNE07kJ
         Z8DHQ0X3eejgpYHg/dBiwaNh8C6f7UnUgp28Ku8nZQoxbHOhnNAtY2YjsAcDahjwK7Lh
         wEn7OwNDCfXzfBIJKfX46RyPpSMkn+JLPp5jYzOx/xwjlth4VmCxF8TOag5rE7AnueSq
         75ng==
X-Gm-Message-State: AOAM531iuOAVhUas18u9COCTKQAdEdriCj7TvHeZRtokhAHwbIiqJPNV
	Diqu5jYQcXYssuUTTMSzqB8=
X-Google-Smtp-Source: ABdhPJyjS8wn4UwcQrJsjePSUbfQafOnDxDMTc/FoYTqiZmVLqH9iL/TnUYUJBQ/SOqUt8uLtkIAvg==
X-Received: by 2002:a4a:ea94:: with SMTP id r20mr3730990ooh.43.1614871846725;
        Thu, 04 Mar 2021 07:30:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:39b5:: with SMTP id y50ls1646342otb.6.gmail; Thu, 04 Mar
 2021 07:30:46 -0800 (PST)
X-Received: by 2002:a05:6830:4121:: with SMTP id w33mr3702448ott.361.1614871846308;
        Thu, 04 Mar 2021 07:30:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614871846; cv=none;
        d=google.com; s=arc-20160816;
        b=xxCY4AZ/ZrKyYf24gsAs2IoEDsseVKYVUOoL0HKYQ4eZSv2p78I0nKFrKHa8ZZFM4G
         uNGXMYHpjd7yD8E0mlps/HUQ+/7GMv/WT3QamHz0JqXonfD8pAE3zPeO+joraXsn0ot+
         aC5Z7E3Nj0TZowHWINJUyittsa/N3YukPrOyb6B14nDo+TMnvwIGnJsRlT5pkIwgaIFn
         jtiNiNdRidMcqlajBSkvujA95/+cg1wyY8SDEIWlbXpGA+TbN/ZwzyrICLXdYOu0iy+O
         8q0m7qp4CfML7Xruwa8UW/urWNGg2USh3xn3nk/tOa4oHAcCKYC0X/MAYlY2dE5aw/w2
         IRSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YsbrBjQ4ejiQFiBXd0K2I2t5lmeYk0KLBpHXPT2nL3g=;
        b=vD0Szq2WBvHQd3cGpxwDpeHEHtQlHWK3XE3GFPb4Y7zCNgRbwi4+bojXTyIYprZ+bZ
         AGbbQgUwXs8X8l8/SZw+k5A6wU9OgbYt6EH+sXNqnj629cGMe/TJMaNFqqsuQC3gOtWh
         zGTdqgefxfz3Ca42EnQ1UNKEe4ODTErLoXA/JP+aJ6F7dphsIsY2oYkhRWnMNsVlqTIn
         Et0kEkMd+sOqd4lcdlsppH1psZU3vpjwO52i2b+X8MRKxZ+MWapPkiHrl+CzWYGvjezL
         mp7daDmNxwhZh/B5ACJBv5RJFGW5vueZ5UWnTd34nofsyF+hMJJ+5Ds9J0egIlG0ke3w
         y1lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZbSTgcxF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id p23si1760053otf.2.2021.03.04.07.30.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 07:30:46 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id x10so6679827oor.3
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 07:30:46 -0800 (PST)
X-Received: by 2002:a4a:a105:: with SMTP id i5mr3765483ool.54.1614871845744;
 Thu, 04 Mar 2021 07:30:45 -0800 (PST)
MIME-Version: 1.0
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu> <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local>
In-Reply-To: <20210304145730.GC54534@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Mar 2021 16:30:34 +0100
Message-ID: <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com>
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
To: Mark Rutland <mark.rutland@arm.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>, 
	Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, broonie@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZbSTgcxF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as
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

On Thu, 4 Mar 2021 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> [adding Mark Brown]
>
> On Wed, Mar 03, 2021 at 04:20:43PM +0100, Marco Elver wrote:
> > On Wed, Mar 03, 2021 at 03:52PM +0100, Christophe Leroy wrote:
> > > Le 03/03/2021 =C3=AF=C2=BF=C2=BD 15:38, Marco Elver a =C3=AF=C2=BF=C2=
=BDcrit=C3=AF=C2=BF=C2=BD:
> > > > On Wed, 3 Mar 2021 at 15:09, Christophe Leroy
> > > > <christophe.leroy@csgroup.eu> wrote:
> > > > >
> > > > > It seems like all other sane architectures, namely x86 and arm64
> > > > > at least, include the running function as top entry when saving
> > > > > stack trace.
> > > > >
> > > > > Functionnalities like KFENCE expect it.
> > > > >
> > > > > Do the same on powerpc, it allows KFENCE to properly identify the=
 faulting
> > > > > function as depicted below. Before the patch KFENCE was identifyi=
ng
> > > > > finish_task_switch.isra as the faulting function.
> > > > >
> > > > > [   14.937370] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > [   14.948692] BUG: KFENCE: invalid read in test_invalid_access+0=
x54/0x108
> > > > > [   14.948692]
> > > > > [   14.956814] Invalid read at 0xdf98800a:
> > > > > [   14.960664]  test_invalid_access+0x54/0x108
> > > > > [   14.964876]  finish_task_switch.isra.0+0x54/0x23c
> > > > > [   14.969606]  kunit_try_run_case+0x5c/0xd0
> > > > > [   14.973658]  kunit_generic_run_threadfn_adapter+0x24/0x30
> > > > > [   14.979079]  kthread+0x15c/0x174
> > > > > [   14.982342]  ret_from_kernel_thread+0x14/0x1c
> > > > > [   14.986731]
> > > > > [   14.988236] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G  =
  B             5.12.0-rc1-01537-g95f6e2088d7e-dirty #4682
> > > > > [   14.999795] NIP:  c016ec2c LR: c02f517c CTR: c016ebd8
> > > > > [   15.004851] REGS: e2449d90 TRAP: 0301   Tainted: G    B       =
       (5.12.0-rc1-01537-g95f6e2088d7e-dirty)
> > > > > [   15.015274] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER=
: 00000000
> > > > > [   15.022043] DAR: df98800a DSISR: 20000000
> > > > > [   15.022043] GPR00: c02f517c e2449e50 c1142080 e100dd24 c084b13=
c 00000008 c084b32b c016ebd8
> > > > > [   15.022043] GPR08: c0850000 df988000 c0d10000 e2449eb0 2200028=
8
> > > > > [   15.040581] NIP [c016ec2c] test_invalid_access+0x54/0x108
> > > > > [   15.046010] LR [c02f517c] kunit_try_run_case+0x5c/0xd0
> > > > > [   15.051181] Call Trace:
> > > > > [   15.053637] [e2449e50] [c005a68c] finish_task_switch.isra.0+0x=
54/0x23c (unreliable)
> > > > > [   15.061338] [e2449eb0] [c02f517c] kunit_try_run_case+0x5c/0xd0
> > > > > [   15.067215] [e2449ed0] [c02f648c] kunit_generic_run_threadfn_a=
dapter+0x24/0x30
> > > > > [   15.074472] [e2449ef0] [c004e7b0] kthread+0x15c/0x174
> > > > > [   15.079571] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/=
0x1c
> > > > > [   15.085798] Instruction dump:
> > > > > [   15.088784] 8129d608 38e7ebd8 81020280 911f004c 39000000 995f0=
024 907f0028 90ff001c
> > > > > [   15.096613] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 390=
8adb0 812a4b98 3d40c02f
> > > > > [   15.104612] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > >
> > > > > Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> > > >
> > > > Acked-by: Marco Elver <elver@google.com>
> > > >
> > > > Thank you, I think this looks like the right solution. Just a quest=
ion below:
> > > >
> > > ...
> > >
> > > > > @@ -59,23 +70,26 @@ void save_stack_trace(struct stack_trace *tra=
ce)
> > > > >
> > > > >          sp =3D current_stack_frame();
> > > > >
> > > > > -       save_context_stack(trace, sp, current, 1);
> > > > > +       save_context_stack(trace, sp, (unsigned long)save_stack_t=
race, current, 1);
> > > >
> > > > This causes ip =3D=3D save_stack_trace and also below for
> > > > save_stack_trace_tsk. Does this mean save_stack_trace() is included=
 in
> > > > the trace? Looking at kernel/stacktrace.c, I think the library want=
s
> > > > to exclude itself from the trace, as it does '.skip =3D skipnr + 1'=
 (and
> > > > '.skip   =3D skipnr + (current =3D=3D tsk)' for the _tsk variant).
> > > >
> > > > If the arch-helper here is included, should this use _RET_IP_ inste=
ad?
> > > >
> > >
> > > Don't really know, I was inspired by arm64 which has:
> > >
> > > void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cook=
ie,
> > >                  struct task_struct *task, struct pt_regs *regs)
> > > {
> > >     struct stackframe frame;
> > >
> > >     if (regs)
> > >             start_backtrace(&frame, regs->regs[29], regs->pc);
> > >     else if (task =3D=3D current)
> > >             start_backtrace(&frame,
> > >                             (unsigned long)__builtin_frame_address(0)=
,
> > >                             (unsigned long)arch_stack_walk);
> > >     else
> > >             start_backtrace(&frame, thread_saved_fp(task),
> > >                             thread_saved_pc(task));
> > >
> > >     walk_stackframe(task, &frame, consume_entry, cookie);
> > > }
> > >
> > > But looking at x86 you may be right, so what should be done really ?
> >
> > x86:
> >
> > [    2.843292] calling stack_trace_save:
> > [    2.843705]  test_func+0x6c/0x118
> > [    2.844184]  do_one_initcall+0x58/0x270
> > [    2.844618]  kernel_init_freeable+0x1da/0x23a
> > [    2.845110]  kernel_init+0xc/0x166
> > [    2.845494]  ret_from_fork+0x22/0x30
> >
> > [    2.867525] calling stack_trace_save_tsk:
> > [    2.868017]  test_func+0xa9/0x118
> > [    2.868530]  do_one_initcall+0x58/0x270
> > [    2.869003]  kernel_init_freeable+0x1da/0x23a
> > [    2.869535]  kernel_init+0xc/0x166
> > [    2.869957]  ret_from_fork+0x22/0x30
> >
> > arm64:
> >
> > [    3.786911] calling stack_trace_save:
> > [    3.787147]  stack_trace_save+0x50/0x78
> > [    3.787443]  test_func+0x84/0x13c
> > [    3.787738]  do_one_initcall+0x5c/0x310
> > [    3.788099]  kernel_init_freeable+0x214/0x294
> > [    3.788363]  kernel_init+0x18/0x164
> > [    3.788585]  ret_from_fork+0x10/0x30
> >
> > [    3.803615] calling stack_trace_save_tsk:
> > [    3.804266]  stack_trace_save_tsk+0x9c/0x100
> > [    3.804541]  test_func+0xc4/0x13c
> > [    3.804803]  do_one_initcall+0x5c/0x310
> > [    3.805031]  kernel_init_freeable+0x214/0x294
> > [    3.805284]  kernel_init+0x18/0x164
> > [    3.805505]  ret_from_fork+0x10/0x30
> >
> > +Cc arm64 folks.
> >
> > So I think the arm64 version also has a bug, because I think a user of
> > <linux/stacktrace.h> really doesn't care about the library function
> > itself. And from reading kernel/stacktrace.c I think it wants to exclud=
e
> > itself entirely.
> >
> > It's a shame that <linux/stacktrace.h> isn't better documented, but I'm
> > pretty sure that including the library functions in the trace is not
> > useful.
>
> I agree this behaviour isn't desireable, and that the lack of
> documentation is unfortunate.
>
> It looks like GCC is happy to give us the function-entry-time FP if we us=
e
> __builtin_frame_address(1), and assuming clang is similarly happy we can =
do:
>
> | diff --git a/arch/arm64/kernel/stacktrace.c b/arch/arm64/kernel/stacktr=
ace.c
> | index ad20981dfda4..5dfbf915eb7f 100644
> | --- a/arch/arm64/kernel/stacktrace.c
> | +++ b/arch/arm64/kernel/stacktrace.c
> | @@ -203,8 +203,8 @@ void arch_stack_walk(stack_trace_consume_fn consume=
_entry, void *cookie,
> |                 start_backtrace(&frame, regs->regs[29], regs->pc);
> |         else if (task =3D=3D current)
> |                 start_backtrace(&frame,
> | -                               (unsigned long)__builtin_frame_address(=
0),
> | -                               (unsigned long)arch_stack_walk);
> | +                               (unsigned long)__builtin_frame_address(=
1),
> | +                               (unsigned long)__builtin_return_address=
(0));
> |         else
> |                 start_backtrace(&frame, thread_saved_fp(task),
> |                                 thread_saved_pc(task));
>
> ... such that arch_stack_walk() will try to avoid including itself in a
> trace, and so the existing skipping should (w/ caveats below) skip
> stack_trace_save() or stack_trace_save_tsk().

Thank you! Yes, that works.

> If that works for you, I can spin that as a patch, though we'll need to
> check that doesn't introduce a new fencepost error elsewhere.
>
> The bigger problem here is that skipping is dodgy to begin with, and
> this is still liable to break in some cases. One big concern is that
> (especially with LTO) we cannot guarantee the compiler will not inline
> or outline functions, causing the skipp value to be too large or too
> small. That's liable to happen to callers, and in theory (though
> unlikely in practice), portions of arch_stack_walk() or
> stack_trace_save() could get outlined too.
>
> Unless we can get some strong guarantees from compiler folk such that we
> can guarantee a specific function acts boundary for unwinding (and
> doesn't itself get split, etc), the only reliable way I can think to
> solve this requires an assembly trampoline. Whatever we do is liable to
> need some invasive rework.

Will LTO and friends respect 'noinline'? One thing I also noticed is
that tail calls would also cause the stack trace to appear somewhat
incomplete (for some of my tests I've disabled tail call
optimizations). Is there a way to also mark a function
non-tail-callable? But I'm also not sure if with all that we'd be
guaranteed the code we want, even though in practice it might.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOSpFbbDaH9hNucXrpzG%3DHpsoQpk5w-24x8sU_G-6cz0Q%40mail.gmai=
l.com.
