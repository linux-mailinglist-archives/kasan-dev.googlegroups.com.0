Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUWS72AQMGQEIS7EUEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E43132B8E4
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 16:20:51 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id c7sf1410655wml.8
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 07:20:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614784851; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zd65vQPXVfXHz+2Vg6FAeQpXDb+nRRdYp+n5b1/MYd3gYS7c/556jfTyHx4W3ixfz1
         d4iVIh7PT0IIzmN94Kt4e/rWHppFGGWA4GLHRYsyE78vyx53HwMCeOrBiay8BRwMyo5f
         W6Iq3vUIrbSPDfhSJbXiwhr8/QeicXOo2CeHJlMqIQREQkh+/UaV9Qfyi04qFavRZsl4
         KbIabqvSvvXhGnytJ7KXJk1usRSriCpI7YKtVNocifbXavuH1mSDjcd8Ma5sSVsZ3hWq
         Zi+8IdWRLlg5mXXNqp/QhW3FA/8exHtrvJfF6lHtU7+H7ey/9DZV61VuKksY8UiYOw7q
         Xiyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=WUoGHp2j2LtYYx+SMWAVvSzJC6IrCPx0fXnQjPivmNU=;
        b=BY1NN60NRgCsKzv+I/RPAvY/iNub/mZwoCG7F4lsX1VpIaIbYYzw3+C2+hHsmhHvPQ
         hcIU932N+4lPJpclBjAihxrRqVWN+pvG/b5GgiMi5QXcwUAbS1xlAfZgI6MGGAXU1YQQ
         QO0eGfjaJClrNszjpfIkcmenl7cV5IGBLle18ilTLTEL18Lv7FxroeU3Sm+6C4DOh+0W
         IUX4zRcyuSLbKTGZ0k52Wd6LhZbJshs61AVcx1LFIAPGQXDmeUJxCZtu9wGTg7gWznJQ
         kD0bFDsayqsu4JOGD6YJCbuln3F62WqdSLGat8puDBnwp5KRF1In2XzcGCoOnL+xuztF
         BTyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ki76JYgQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WUoGHp2j2LtYYx+SMWAVvSzJC6IrCPx0fXnQjPivmNU=;
        b=KHpD5x2bkdS9o+pCX7mE2m4fCP5Jx4hwwVZ535xu9L6Qyv0SIn2sG6Re5Mq1S8PPPh
         xqvW9PULBcodKBdpgIBx+gcOjIivSVshKhNUk0QBSLQ/6w4tWnnekpSK7QtdoZHOeAXQ
         WbtKP2IR4PJuNN1uCQqsvUKLBAdvRvAg2vc/EkW4YNHagpjoN5c+jkFW1E+AsreKT5X4
         4Fm3ts9EQFvCbJJvcgVN/haAtrcQm94xQdNgg8fqsJZcGzGEXT9Up5z2CxNuDpGU6QxF
         1fKhkWub2sWk9zsza5+RnqAf81gVTdl5Ck9wI17ddiZRuyHSBJ7KZEfYABilvQVhrJSa
         iR0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WUoGHp2j2LtYYx+SMWAVvSzJC6IrCPx0fXnQjPivmNU=;
        b=YAmo7t1dhFB4apWt9mRH2uc78maH9zNfey1upPhjumhi9iXZSKjL3r6aM5auiXjGSj
         xPcQbrS7DwRBGEb3poBxriXT7eKTSVqOXRurBxshn9PLK45rA4phc4WGaxBeZToSQNuB
         IGoV7bNEDgJpZ6FLoXDw5C+jlAPZAouNt1soAKOS5n8oFMLqxAMfYbYbMZKpmVZHXXcS
         N0oWzyrpm9TjUfLdQe1cbXxhaLCJBiO3b8oHha48e8O7mxoAF0h4nfXbBTZESCir3ft7
         psc4BfpjqjHUGbqkpKr+zg2MUigpiwMdobEcTaMXc9a1fuWwtFtsrD5XtPQJAW+37IuE
         eolw==
X-Gm-Message-State: AOAM533FGJufit5OpyF+FKNuY45vpQ590MSfGpDwkeAvbRskfkKdTQws
	YcfpjQOb7lhDPOmkQltDYQU=
X-Google-Smtp-Source: ABdhPJxw91QQbIGL8N9mG3bnowTdwLoXxBinmBY2x55cuzyGuXcgtqUnapVcpq1yJpDSey6Cv8ruJQ==
X-Received: by 2002:adf:a1d8:: with SMTP id v24mr27038585wrv.378.1614784851096;
        Wed, 03 Mar 2021 07:20:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:60c2:: with SMTP id u185ls1358960wmb.2.gmail; Wed, 03
 Mar 2021 07:20:50 -0800 (PST)
X-Received: by 2002:a1c:8041:: with SMTP id b62mr9973017wmd.0.1614784850176;
        Wed, 03 Mar 2021 07:20:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614784850; cv=none;
        d=google.com; s=arc-20160816;
        b=St+NBzYRc+BuJuAQc48qdM9QQtQdFdET9/qLq6oivA52WVm4vBgcOeF+vcTGE4iH7b
         9zzXz3TjOTKhj7ad/vZpg6teeBtdKmdSyk9gt4j3i8uLi4vTcCfYrfCjweBrQR0XxoLK
         JPyLNF9myMKRrymRiRVnkN6k4tIUPdqLpsxBz5Mj0PNAp5Ag00kImxvdjSLuUhv3AdX9
         kaN/GTs/8g20K8kllPBMsXkzJrG5vkqwp9YpkDcqgxgShoOhDlDC10fcl6UdoM5qV4Mf
         Vn4LF6mOVLW9a1Tpwqncn1bGykFuNrzLBY+ZD9M6OCuyJZpO3Rar/oEW5BWrVGjzCRHR
         VumA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=kayPbw8A7iB7X1IwkMYnahJ/vHZk8i/lpZLyVsXqadA=;
        b=m0iQBB5i++C2VK/M7VXf2UX/9JokC2hlAFQyIgZVOkIt5zGeoijJsn+9Yw0uVLpZ2u
         a9PKmpuYnQgr1psYk742D+pedVpRVGIG0hSDcMqwLsfPnn+2cgeFDLgm3ZR6Z7gqPrLx
         lDmaERxeasnfKkdlqLfva7BEvDfgT7Ms+8P2FrmIXz6a2oRgZA/dJP5MsPTi19hKufYB
         nT8ZHHDbaOLqlo3M8/P6vCZft7ShejW/uGnm23s3g7+1zKtikALsOIFtxHrxFMIq6Gix
         1o2/4dHaMT0f1rSA0q4uuzv8VQ8f8tc6M5dVKzmUksO+uNCHvFkk3Kz/L9esAC68R3E2
         7fDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ki76JYgQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id g132si314515wma.1.2021.03.03.07.20.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Mar 2021 07:20:50 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id f12so20296313wrx.8
        for <kasan-dev@googlegroups.com>; Wed, 03 Mar 2021 07:20:50 -0800 (PST)
X-Received: by 2002:adf:fecc:: with SMTP id q12mr27405465wrs.317.1614784849639;
        Wed, 03 Mar 2021 07:20:49 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:811:228c:e84:3381])
        by smtp.gmail.com with ESMTPSA id m6sm32306902wrv.73.2021.03.03.07.20.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Mar 2021 07:20:49 -0800 (PST)
Date: Wed, 3 Mar 2021 16:20:43 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
Message-ID: <YD+o5QkCZN97mH8/@elver.google.com>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ki76JYgQ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as
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

On Wed, Mar 03, 2021 at 03:52PM +0100, Christophe Leroy wrote:
> Le 03/03/2021 =C3=A0 15:38, Marco Elver a =C3=A9crit=C2=A0:
> > On Wed, 3 Mar 2021 at 15:09, Christophe Leroy
> > <christophe.leroy@csgroup.eu> wrote:
> > >=20
> > > It seems like all other sane architectures, namely x86 and arm64
> > > at least, include the running function as top entry when saving
> > > stack trace.
> > >=20
> > > Functionnalities like KFENCE expect it.
> > >=20
> > > Do the same on powerpc, it allows KFENCE to properly identify the fau=
lting
> > > function as depicted below. Before the patch KFENCE was identifying
> > > finish_task_switch.isra as the faulting function.
> > >=20
> > > [   14.937370] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > [   14.948692] BUG: KFENCE: invalid read in test_invalid_access+0x54/=
0x108
> > > [   14.948692]
> > > [   14.956814] Invalid read at 0xdf98800a:
> > > [   14.960664]  test_invalid_access+0x54/0x108
> > > [   14.964876]  finish_task_switch.isra.0+0x54/0x23c
> > > [   14.969606]  kunit_try_run_case+0x5c/0xd0
> > > [   14.973658]  kunit_generic_run_threadfn_adapter+0x24/0x30
> > > [   14.979079]  kthread+0x15c/0x174
> > > [   14.982342]  ret_from_kernel_thread+0x14/0x1c
> > > [   14.986731]
> > > [   14.988236] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B =
            5.12.0-rc1-01537-g95f6e2088d7e-dirty #4682
> > > [   14.999795] NIP:  c016ec2c LR: c02f517c CTR: c016ebd8
> > > [   15.004851] REGS: e2449d90 TRAP: 0301   Tainted: G    B           =
   (5.12.0-rc1-01537-g95f6e2088d7e-dirty)
> > > [   15.015274] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: 00=
000000
> > > [   15.022043] DAR: df98800a DSISR: 20000000
> > > [   15.022043] GPR00: c02f517c e2449e50 c1142080 e100dd24 c084b13c 00=
000008 c084b32b c016ebd8
> > > [   15.022043] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
> > > [   15.040581] NIP [c016ec2c] test_invalid_access+0x54/0x108
> > > [   15.046010] LR [c02f517c] kunit_try_run_case+0x5c/0xd0
> > > [   15.051181] Call Trace:
> > > [   15.053637] [e2449e50] [c005a68c] finish_task_switch.isra.0+0x54/0=
x23c (unreliable)
> > > [   15.061338] [e2449eb0] [c02f517c] kunit_try_run_case+0x5c/0xd0
> > > [   15.067215] [e2449ed0] [c02f648c] kunit_generic_run_threadfn_adapt=
er+0x24/0x30
> > > [   15.074472] [e2449ef0] [c004e7b0] kthread+0x15c/0x174
> > > [   15.079571] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x1c
> > > [   15.085798] Instruction dump:
> > > [   15.088784] 8129d608 38e7ebd8 81020280 911f004c 39000000 995f0024 =
907f0028 90ff001c
> > > [   15.096613] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908adb=
0 812a4b98 3d40c02f
> > > [   15.104612] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > >=20
> > > Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> >=20
> > Acked-by: Marco Elver <elver@google.com>
> >=20
> > Thank you, I think this looks like the right solution. Just a question =
below:
> >=20
> ...
>=20
> > > @@ -59,23 +70,26 @@ void save_stack_trace(struct stack_trace *trace)
> > >=20
> > >          sp =3D current_stack_frame();
> > >=20
> > > -       save_context_stack(trace, sp, current, 1);
> > > +       save_context_stack(trace, sp, (unsigned long)save_stack_trace=
, current, 1);
> >=20
> > This causes ip =3D=3D save_stack_trace and also below for
> > save_stack_trace_tsk. Does this mean save_stack_trace() is included in
> > the trace? Looking at kernel/stacktrace.c, I think the library wants
> > to exclude itself from the trace, as it does '.skip =3D skipnr + 1' (an=
d
> > '.skip   =3D skipnr + (current =3D=3D tsk)' for the _tsk variant).
> >=20
> > If the arch-helper here is included, should this use _RET_IP_ instead?
> >=20
>=20
> Don't really know, I was inspired by arm64 which has:
>=20
> void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
> 		     struct task_struct *task, struct pt_regs *regs)
> {
> 	struct stackframe frame;
>=20
> 	if (regs)
> 		start_backtrace(&frame, regs->regs[29], regs->pc);
> 	else if (task =3D=3D current)
> 		start_backtrace(&frame,
> 				(unsigned long)__builtin_frame_address(0),
> 				(unsigned long)arch_stack_walk);
> 	else
> 		start_backtrace(&frame, thread_saved_fp(task),
> 				thread_saved_pc(task));
>=20
> 	walk_stackframe(task, &frame, consume_entry, cookie);
> }
>=20
> But looking at x86 you may be right, so what should be done really ?

x86:

[    2.843292] calling stack_trace_save:
[    2.843705]  test_func+0x6c/0x118
[    2.844184]  do_one_initcall+0x58/0x270
[    2.844618]  kernel_init_freeable+0x1da/0x23a
[    2.845110]  kernel_init+0xc/0x166
[    2.845494]  ret_from_fork+0x22/0x30

[    2.867525] calling stack_trace_save_tsk:
[    2.868017]  test_func+0xa9/0x118
[    2.868530]  do_one_initcall+0x58/0x270
[    2.869003]  kernel_init_freeable+0x1da/0x23a
[    2.869535]  kernel_init+0xc/0x166
[    2.869957]  ret_from_fork+0x22/0x30

arm64:

[    3.786911] calling stack_trace_save:
[    3.787147]  stack_trace_save+0x50/0x78
[    3.787443]  test_func+0x84/0x13c
[    3.787738]  do_one_initcall+0x5c/0x310
[    3.788099]  kernel_init_freeable+0x214/0x294
[    3.788363]  kernel_init+0x18/0x164
[    3.788585]  ret_from_fork+0x10/0x30

[    3.803615] calling stack_trace_save_tsk:
[    3.804266]  stack_trace_save_tsk+0x9c/0x100
[    3.804541]  test_func+0xc4/0x13c
[    3.804803]  do_one_initcall+0x5c/0x310
[    3.805031]  kernel_init_freeable+0x214/0x294
[    3.805284]  kernel_init+0x18/0x164
[    3.805505]  ret_from_fork+0x10/0x30

+Cc arm64 folks.

So I think the arm64 version also has a bug, because I think a user of
<linux/stacktrace.h> really doesn't care about the library function
itself. And from reading kernel/stacktrace.c I think it wants to exclude
itself entirely.

It's a shame that <linux/stacktrace.h> isn't better documented, but I'm
pretty sure that including the library functions in the trace is not
useful.

For the ppc version, let's do what x86 does and start with the caller.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YD%2Bo5QkCZN97mH8/%40elver.google.com.
