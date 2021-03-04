Return-Path: <kasan-dev+bncBDV37XP3XYDRBYXKQOBAMGQEM56QOTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id CDD8332D5B7
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 15:57:39 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id m1sf15516030pll.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 06:57:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614869858; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qhgti0c+biWYxDEkPXvmzWG83w0b4PDDHQaHLYHcx3Y/Qrmk5rVzSUBldw8jfgWWyE
         4MJPwZnOOBUnM/JJ0+QixEAdV0OOeEnQm0tM+PrH5H9UdysFXMQn/vy7dFg3XdCE8yk7
         1iCwefPf2egPsRJkgB1fvXeRmIbE97j4CfBrCBzScJfDiq4R5H61qH2zxINwkiQuuN0b
         ea56Wb1q/xA5/ifWkbbVxNsvWpCs78RfijNIdjAxAWTPPdRZsK5IplIc+0ti7Nq+2+RU
         nCc9P8Xt8/gD9Oy1WwDkJ8gnKXAR0iW9oTEfWVX9xKkEXN+qQKX7E57KPCxmNpnuQghs
         T1Tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=OTzwbJPT4e/qZbMQpM1nv3UkY4R7f2CPjfYsOUb6wp8=;
        b=hc4bRQx68hLKdbujH9mO8z8rxjs7mekgpXPzdT7+05UY8ZW6ayd5qPmUDgCwXy7VwF
         n/JC7GMKgI6xq7fBdQ9ASvi/o/RYAS4kb6win7ujxtNVtNUg+pfP13pHkteVJv0xy0A7
         z/lLKQ1iHT8WSFNExRiB1awc+JQwGDTj7Alv0gqoLkn5MgWXFTRfeeIjK593sJk4NMNg
         DMMDvDfoLbTX60oOGfcNVUHzah35TYeFSgGX8kVa1LbMA/OqKK9E/xsPyHARLxIzuAPW
         +KZMG4KfD2xUK1iOaurP+DcwSrIzQQotgauhdgGwQp7H9SP1HQN5wWNC1ub536w0cS4Y
         bRDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OTzwbJPT4e/qZbMQpM1nv3UkY4R7f2CPjfYsOUb6wp8=;
        b=bIkG7Vkc0oIdjtkkc9ZV6zZt6r1+kd4o1/qsAiUJcibt8FX2MdNicANLAyT+B2SDUC
         aXwkvLdrCywdxWyz+2UEYl9QNjJPhoj2HUYUl0bUX+18nYoG1QWQt40ZhOIe45Sgurwz
         lh/d6k/74vh7yNQEc7MchV/1pZKvW/4YfqmNkPJzSKAU+TWp/AnNCalsZBE/HfJ3VYZJ
         t+zxvSipxR3BjED9UDh3zg+cYKXLfqv9wD3q8TRLf/pFaDSORDRF8808MwON8PQ+NMM/
         zgx2uyjpHAA2QGNaLeyqkpEOYNIIThhu0f+epKdJxvB92kKk+wCxVVIfquhZ6U6smpKW
         mA/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OTzwbJPT4e/qZbMQpM1nv3UkY4R7f2CPjfYsOUb6wp8=;
        b=KbOsOHLmElIg0SPR5UnrL+XxZjPjW+Kcp6ivBR7ViVHJ/pIDeAtQlgd+WNvVHKWhOl
         KwR76Dwe2mEh0SdFmg3ED1amd9wgBk8xkRtpx8q3bA811ToTyB5lF5rCGP7blo9so7D7
         ar5MjA/tohljFrzzcKVQBMYgV4a9vmIom+7gYASyI7NaDYF7mg23q8B32vq9YWWowCTt
         3S2XqWb0lsJ2SMYYgFwM3obzVjKkRcAh1ljeOMPUma6hu8kb29Ms1hwHnJeC2p29Oknh
         /MolSdKvvPSdOMBLFQ5M8Jm96sTmffs57RC7Vyv8O1CTH4AyWmsh967PlZfEUTZpXQOf
         Jzvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YPF84JFsnGNzn/hIJwSqAWO3iZlqA79u8GyQgjgjiIzmM5z90
	wvOnJB88E0aK0Z8HRNzkNWs=
X-Google-Smtp-Source: ABdhPJx7u93suik+SZaOHfnRJ82dtnQwB/AcmVcqvR3SjmKtXe1eRdOR9CZv7mMGtuZsNDILGgw4BQ==
X-Received: by 2002:a17:902:8690:b029:e3:91f9:eaeb with SMTP id g16-20020a1709028690b02900e391f9eaebmr4320278plo.34.1614869858393;
        Thu, 04 Mar 2021 06:57:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:511a:: with SMTP id f26ls2516232pgb.9.gmail; Thu, 04 Mar
 2021 06:57:37 -0800 (PST)
X-Received: by 2002:a63:4442:: with SMTP id t2mr3835244pgk.23.1614869857733;
        Thu, 04 Mar 2021 06:57:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614869857; cv=none;
        d=google.com; s=arc-20160816;
        b=Vqk+RTxE/K1e0KWvA1aA2vCs6fzCAAWPRBKMUJRie675NJyrcSbZjDlulWSkSEfC5E
         LsdpM9vWQmWiRDDcPYomtQZUWRpDckpoRY5zeZSs8gD/yFJRmtmL7rDrNNUp0E5D9qQ3
         QKl7T9UagY5VZvCFWFSeUn93QmN63BCrd2CgSjK0pFv64RMN31Za+YAeIXZKTNBn7pRW
         30/QHNCbKvfD1Rvr+MXRjbveRlokZYhSTE6QSeSFm0pXn53e+Vtm2OtF1CxMqlpa3GvW
         CGMDdgj0TOGulhezELyGlED7sbzQTduZcSbBYPGgz/jRLOE38kKqwLlMxQz89h8dcNoa
         2GxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=zxxSvr+0Qvu8W49w5usmTYuq6qFHgPXDoxA55ieNp7I=;
        b=olID9wvy8NdDeaa0cEA3osdaaEiwBDXbJTAYEf8YXmaY9zieLjrTnNwICBSW4dKKh+
         tAMITQ32wdiS48EuY3vvQr4KxH7sdvowZdFWzge4OfccHeuR6gp2C52fmZZC8YCg3Qpt
         ek2d9FMoAuBvhaDUznIQxSyUa6YXZqSwpHGfIkoEYlKJ1LCOQaGMbUnlcouGMvBOR6fR
         Mq5RglCL+US0/Rt3HjD/eMoRy5I7vI3Vmj6I3vFzxOcQOtxoLY1YuN7qQQafVZs3UiWe
         2VpGs2flCiM8TpvUpDOt3otssIQAkb42Qn3FCqnbdoLFnL/kwlmHOSY0fjoVL51EBOzb
         /Nsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h7si1415809plr.3.2021.03.04.06.57.37
        for <kasan-dev@googlegroups.com>;
        Thu, 04 Mar 2021 06:57:37 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B40671FB;
	Thu,  4 Mar 2021 06:57:36 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.53.210])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E80F43F766;
	Thu,  4 Mar 2021 06:57:33 -0800 (PST)
Date: Thu, 4 Mar 2021 14:57:30 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org,
	broonie@kernel.org
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
Message-ID: <20210304145730.GC54534@C02TD0UTHF1T.local>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
 <YD+o5QkCZN97mH8/@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <YD+o5QkCZN97mH8/@elver.google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

[adding Mark Brown]

On Wed, Mar 03, 2021 at 04:20:43PM +0100, Marco Elver wrote:
> On Wed, Mar 03, 2021 at 03:52PM +0100, Christophe Leroy wrote:
> > Le 03/03/2021 =C3=AF=C2=BF=C2=BD 15:38, Marco Elver a =C3=AF=C2=BF=C2=
=BDcrit=C3=AF=C2=BF=C2=BD:
> > > On Wed, 3 Mar 2021 at 15:09, Christophe Leroy
> > > <christophe.leroy@csgroup.eu> wrote:
> > > >=20
> > > > It seems like all other sane architectures, namely x86 and arm64
> > > > at least, include the running function as top entry when saving
> > > > stack trace.
> > > >=20
> > > > Functionnalities like KFENCE expect it.
> > > >=20
> > > > Do the same on powerpc, it allows KFENCE to properly identify the f=
aulting
> > > > function as depicted below. Before the patch KFENCE was identifying
> > > > finish_task_switch.isra as the faulting function.
> > > >=20
> > > > [   14.937370] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > [   14.948692] BUG: KFENCE: invalid read in test_invalid_access+0x5=
4/0x108
> > > > [   14.948692]
> > > > [   14.956814] Invalid read at 0xdf98800a:
> > > > [   14.960664]  test_invalid_access+0x54/0x108
> > > > [   14.964876]  finish_task_switch.isra.0+0x54/0x23c
> > > > [   14.969606]  kunit_try_run_case+0x5c/0xd0
> > > > [   14.973658]  kunit_generic_run_threadfn_adapter+0x24/0x30
> > > > [   14.979079]  kthread+0x15c/0x174
> > > > [   14.982342]  ret_from_kernel_thread+0x14/0x1c
> > > > [   14.986731]
> > > > [   14.988236] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    =
B             5.12.0-rc1-01537-g95f6e2088d7e-dirty #4682
> > > > [   14.999795] NIP:  c016ec2c LR: c02f517c CTR: c016ebd8
> > > > [   15.004851] REGS: e2449d90 TRAP: 0301   Tainted: G    B         =
     (5.12.0-rc1-01537-g95f6e2088d7e-dirty)
> > > > [   15.015274] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: =
00000000
> > > > [   15.022043] DAR: df98800a DSISR: 20000000
> > > > [   15.022043] GPR00: c02f517c e2449e50 c1142080 e100dd24 c084b13c =
00000008 c084b32b c016ebd8
> > > > [   15.022043] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
> > > > [   15.040581] NIP [c016ec2c] test_invalid_access+0x54/0x108
> > > > [   15.046010] LR [c02f517c] kunit_try_run_case+0x5c/0xd0
> > > > [   15.051181] Call Trace:
> > > > [   15.053637] [e2449e50] [c005a68c] finish_task_switch.isra.0+0x54=
/0x23c (unreliable)
> > > > [   15.061338] [e2449eb0] [c02f517c] kunit_try_run_case+0x5c/0xd0
> > > > [   15.067215] [e2449ed0] [c02f648c] kunit_generic_run_threadfn_ada=
pter+0x24/0x30
> > > > [   15.074472] [e2449ef0] [c004e7b0] kthread+0x15c/0x174
> > > > [   15.079571] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x=
1c
> > > > [   15.085798] Instruction dump:
> > > > [   15.088784] 8129d608 38e7ebd8 81020280 911f004c 39000000 995f002=
4 907f0028 90ff001c
> > > > [   15.096613] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908a=
db0 812a4b98 3d40c02f
> > > > [   15.104612] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > >=20
> > > > Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> > >=20
> > > Acked-by: Marco Elver <elver@google.com>
> > >=20
> > > Thank you, I think this looks like the right solution. Just a questio=
n below:
> > >=20
> > ...
> >=20
> > > > @@ -59,23 +70,26 @@ void save_stack_trace(struct stack_trace *trace=
)
> > > >=20
> > > >          sp =3D current_stack_frame();
> > > >=20
> > > > -       save_context_stack(trace, sp, current, 1);
> > > > +       save_context_stack(trace, sp, (unsigned long)save_stack_tra=
ce, current, 1);
> > >=20
> > > This causes ip =3D=3D save_stack_trace and also below for
> > > save_stack_trace_tsk. Does this mean save_stack_trace() is included i=
n
> > > the trace? Looking at kernel/stacktrace.c, I think the library wants
> > > to exclude itself from the trace, as it does '.skip =3D skipnr + 1' (=
and
> > > '.skip   =3D skipnr + (current =3D=3D tsk)' for the _tsk variant).
> > >=20
> > > If the arch-helper here is included, should this use _RET_IP_ instead=
?
> > >=20
> >=20
> > Don't really know, I was inspired by arm64 which has:
> >=20
> > void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie=
,
> > 		     struct task_struct *task, struct pt_regs *regs)
> > {
> > 	struct stackframe frame;
> >=20
> > 	if (regs)
> > 		start_backtrace(&frame, regs->regs[29], regs->pc);
> > 	else if (task =3D=3D current)
> > 		start_backtrace(&frame,
> > 				(unsigned long)__builtin_frame_address(0),
> > 				(unsigned long)arch_stack_walk);
> > 	else
> > 		start_backtrace(&frame, thread_saved_fp(task),
> > 				thread_saved_pc(task));
> >=20
> > 	walk_stackframe(task, &frame, consume_entry, cookie);
> > }
> >=20
> > But looking at x86 you may be right, so what should be done really ?
>=20
> x86:
>=20
> [    2.843292] calling stack_trace_save:
> [    2.843705]  test_func+0x6c/0x118
> [    2.844184]  do_one_initcall+0x58/0x270
> [    2.844618]  kernel_init_freeable+0x1da/0x23a
> [    2.845110]  kernel_init+0xc/0x166
> [    2.845494]  ret_from_fork+0x22/0x30
>=20
> [    2.867525] calling stack_trace_save_tsk:
> [    2.868017]  test_func+0xa9/0x118
> [    2.868530]  do_one_initcall+0x58/0x270
> [    2.869003]  kernel_init_freeable+0x1da/0x23a
> [    2.869535]  kernel_init+0xc/0x166
> [    2.869957]  ret_from_fork+0x22/0x30
>=20
> arm64:
>=20
> [    3.786911] calling stack_trace_save:
> [    3.787147]  stack_trace_save+0x50/0x78
> [    3.787443]  test_func+0x84/0x13c
> [    3.787738]  do_one_initcall+0x5c/0x310
> [    3.788099]  kernel_init_freeable+0x214/0x294
> [    3.788363]  kernel_init+0x18/0x164
> [    3.788585]  ret_from_fork+0x10/0x30
>=20
> [    3.803615] calling stack_trace_save_tsk:
> [    3.804266]  stack_trace_save_tsk+0x9c/0x100
> [    3.804541]  test_func+0xc4/0x13c
> [    3.804803]  do_one_initcall+0x5c/0x310
> [    3.805031]  kernel_init_freeable+0x214/0x294
> [    3.805284]  kernel_init+0x18/0x164
> [    3.805505]  ret_from_fork+0x10/0x30
>=20
> +Cc arm64 folks.
>=20
> So I think the arm64 version also has a bug, because I think a user of
> <linux/stacktrace.h> really doesn't care about the library function
> itself. And from reading kernel/stacktrace.c I think it wants to exclude
> itself entirely.
>
> It's a shame that <linux/stacktrace.h> isn't better documented, but I'm
> pretty sure that including the library functions in the trace is not
> useful.

I agree this behaviour isn't desireable, and that the lack of
documentation is unfortunate.

It looks like GCC is happy to give us the function-entry-time FP if we use
__builtin_frame_address(1), and assuming clang is similarly happy we can do=
:

| diff --git a/arch/arm64/kernel/stacktrace.c b/arch/arm64/kernel/stacktrac=
e.c
| index ad20981dfda4..5dfbf915eb7f 100644
| --- a/arch/arm64/kernel/stacktrace.c
| +++ b/arch/arm64/kernel/stacktrace.c
| @@ -203,8 +203,8 @@ void arch_stack_walk(stack_trace_consume_fn consume_e=
ntry, void *cookie,
|                 start_backtrace(&frame, regs->regs[29], regs->pc);
|         else if (task =3D=3D current)
|                 start_backtrace(&frame,
| -                               (unsigned long)__builtin_frame_address(0)=
,
| -                               (unsigned long)arch_stack_walk);
| +                               (unsigned long)__builtin_frame_address(1)=
,
| +                               (unsigned long)__builtin_return_address(0=
));
|         else
|                 start_backtrace(&frame, thread_saved_fp(task),
|                                 thread_saved_pc(task));

... such that arch_stack_walk() will try to avoid including itself in a
trace, and so the existing skipping should (w/ caveats below) skip
stack_trace_save() or stack_trace_save_tsk().

If that works for you, I can spin that as a patch, though we'll need to
check that doesn't introduce a new fencepost error elsewhere.

The bigger problem here is that skipping is dodgy to begin with, and
this is still liable to break in some cases. One big concern is that
(especially with LTO) we cannot guarantee the compiler will not inline
or outline functions, causing the skipp value to be too large or too
small. That's liable to happen to callers, and in theory (though
unlikely in practice), portions of arch_stack_walk() or
stack_trace_save() could get outlined too.

Unless we can get some strong guarantees from compiler folk such that we
can guarantee a specific function acts boundary for unwinding (and
doesn't itself get split, etc), the only reliable way I can think to
solve this requires an assembly trampoline. Whatever we do is liable to
need some invasive rework.

Thanks,
Mark.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210304145730.GC54534%40C02TD0UTHF1T.local.
