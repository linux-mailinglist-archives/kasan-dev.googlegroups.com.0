Return-Path: <kasan-dev+bncBAABBW6A6T6QKGQETILTHMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 203642C2A99
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 16:01:49 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id s201sf15922314pfs.1
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 07:01:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606230107; cv=pass;
        d=google.com; s=arc-20160816;
        b=gMXYNrNO79Eoc4gt3YEBPr92+u/8dBZehVQgXihE99/vZ2X5xh1ubdvV3khM25U8Xp
         YUEZ1hhq8SEIbZq3OAfDETR9CilRwSfyIJ8A2YphyF1tvacVu+g2A3pRnTnTBDnj5Vmv
         N7I8ATmEbtSfKS38x4MxeWdKMjYGDinucW4ZS35zn2m9Lxznq+i6WMID/1MFCKqOTB1B
         uwAPwCThOynrik9wusdrc8bzH8sM/imWosxgBH6yLoDOydLk8yijE1VoOS/19II8UzFo
         CA/EjD5wWPFhFH8GguXCv6Kk9sIALdKX3tzoaQFA0i/IbkDB146YiEcU2GTpLE+PCz2y
         s8tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+Wgd0QkRfEiDD9Bqly5vT4Hc/09JALlRnkROrQ+FNEE=;
        b=A2sUhwlXPARjGeg1PCuNRFwlvtpHygO6b/u9cwA5K5d3xIua31d9vlje0XF6ep2kif
         QBxcQebf0Nl9kFAoShKL9eRLAZT8P/H+b0D5Y2GHfV558KFp9lKt2HLGa2/kTk2TLXa/
         6If0H3RjY76EmeeuW6W3NlfdRPB5wK3meveNzaLece8yxqpVQrgm4XndvkBP53Qu/WXc
         kCJz/ma6sKofMwhRQLoj1s9uqLso59TZTlm4Tnurt4UynafVnzVYXHOCyBxrb0g/Qh/D
         kJfYYpt4W9C1WTuUsismO/f/Qdu69ftoCB8zg33Lg+AQlPwgf4aHwkY+3CqmYYk4Z42l
         8wyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=xnLGfNCO;
       spf=pass (google.com: domain of srs0=j79q=e6=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=j79Q=E6=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+Wgd0QkRfEiDD9Bqly5vT4Hc/09JALlRnkROrQ+FNEE=;
        b=C2uLK+xIcZCcjBNSZ0pMii8LqmkC8nhhGGuoS5STR0U3E39GbxJ/QuVBnSamsIoP1z
         i5o4JETF6luqRtMIB/jOHcAf2l+yoqxP/eZSHvld5cOIqSTF2Hx25DphjwdZKdpVoaBs
         D2FtBNxqDAJ75LTViJOloXpR2WAf1V1eATZyw0RwnP9HLv4rmL0g0p16DpsqR52XTW2J
         unrtK+jAwM9hRlhzFyOHf4wO1GLedmZSeEZai7Z2PQoECbXyKrmTxLnMjnH7Ki9IAOXE
         n3mY9Q8Y3JqRiN0sbm9y1+3LXfaysi/1QFRH8yf3cHGayHRSooXsqNaDwrXvvll+iAUC
         afOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Wgd0QkRfEiDD9Bqly5vT4Hc/09JALlRnkROrQ+FNEE=;
        b=aNmPyTf51svR/LFWBjt6jOAz4lRtuERNSw9W/J4ZqpQOHQymqjibXayWb8UO8GnZdm
         nvrr6JmbjlPiBU0jxmglGM+kcEDJHac+RvgfNgynnT8L6zvL8CPyFH4anosSlpZ7Ro2p
         Arumao7Vc003YfJg+9/+taty9cNUmWGE3lrnTUD2GrGSfRNEix9rKUgbmFY6w+ISCuqm
         VEd56DikH3t7masnEBd3ZMTBZbrjffUvDttRocjIc8a18OQpAalfCdXBWkqdUgYsGVuY
         cQ3Thy1vmMvRCbC66MbuASA0qxXw1qbcEA7tZXIKdRoyCgyrcqm/yvIb1buLsbdosmeD
         GhOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5317Z6buj5gIQ8trcXj3YIn4ktwHVJU+aYm20RRk84SDanK9qCcr
	VPW9bqH7/SpCQZYz6lb0nkY=
X-Google-Smtp-Source: ABdhPJwsD9cvaeovHEtyd8SpA6xwYv4WfUnMmFuzhexiK5HwkfB+nqthJyY0WbQ+HzFrVsseOqQRTg==
X-Received: by 2002:a63:131a:: with SMTP id i26mr4114253pgl.232.1606230107755;
        Tue, 24 Nov 2020 07:01:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:485d:: with SMTP id x29ls5797889pgk.3.gmail; Tue, 24 Nov
 2020 07:01:47 -0800 (PST)
X-Received: by 2002:a62:ce47:0:b029:198:1512:16e0 with SMTP id y68-20020a62ce470000b0290198151216e0mr4380007pfg.65.1606230107193;
        Tue, 24 Nov 2020 07:01:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606230107; cv=none;
        d=google.com; s=arc-20160816;
        b=POyDlJS0bKVJD0xdAIzOr+HMaU1obrD+OlK6zEL95dL37EH6jJ/bDUcKepZe2teFl/
         TzDkh4i2GEe9+GxLvD3t90Y6S1lGjz7u+mLHIS8m25pEu6GOTM2+nv5Gq7FQD25jg2sA
         1LYGbpEhPSU9uQyzVIM5qPkBsEO+bMbDoBajO/LpBcZ0K4/K1sPollRP88j42p8gokUh
         cTM1SFMoIPKyYmYc8t8TbOCImFhXgs8c7hyoayAq3bWilHiDQp6iFx3/4D4I1Tiwh9Cx
         hj7da/RHTvO/VCLm5uHUqCuBMufGYnLZM1ZsTh9y4H+0BTR/BYK7zXaDTz4v47ZD3Xsx
         IedQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KieeQOmX2HHw7CUrIC9hZXIuZw+h4NVy54/vo59yoJw=;
        b=eBv2cbCDBM2Qx7c5a8BbDZIMiF96nZnBfGQfRhdH4gpRsMQiocmCO1oDnhG1Zawpbz
         UHEiyv1MNVyhTiNPBgt2WhsX5O5DeilMMxMv+nn/UUIjz6VY77Xt0bUiq3iBCo0aNH4p
         /5+wlj6pcWvBBRvBnKQozp2Tp1Hh5wEuVAPOWQqAXuZNSI35w3l3j+ZB05lNYYwso7H5
         wAWW+akE3qOQX9V/5Ra0oNVrXvmA5enKsATdWiDt5bmRUjsHpqC5OmZ/wQdk7AuSgpn/
         2eflfwPlKLRNFHrVhUBmhV5R7ONiCAcyZvsbNHXgWQFHc92hLEAu6bxdJrveLTsZ8V2l
         JJ5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=xnLGfNCO;
       spf=pass (google.com: domain of srs0=j79q=e6=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=j79Q=E6=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id mp11si323890pjb.1.2020.11.24.07.01.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Nov 2020 07:01:47 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=j79q=e6=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9FC3720757;
	Tue, 24 Nov 2020 15:01:46 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 3A5293520FE6; Tue, 24 Nov 2020 07:01:46 -0800 (PST)
Date: Tue, 24 Nov 2020 07:01:46 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Will Deacon <will@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org, boqun.feng@gmail.com,
	tglx@linutronix.de
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201124150146.GH1437@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201119225352.GA5251@willie-the-truck>
 <20201120103031.GB2328@C02TD0UTHF1T.local>
 <20201120140332.GA3120165@elver.google.com>
 <20201123193241.GA45639@C02TD0UTHF1T.local>
 <20201124140310.GA811510@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20201124140310.GA811510@elver.google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=xnLGfNCO;       spf=pass
 (google.com: domain of srs0=j79q=e6=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=j79Q=E6=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Nov 24, 2020 at 03:03:10PM +0100, Marco Elver wrote:
> On Mon, Nov 23, 2020 at 07:32PM +0000, Mark Rutland wrote:
> > On Fri, Nov 20, 2020 at 03:03:32PM +0100, Marco Elver wrote:
> > > On Fri, Nov 20, 2020 at 10:30AM +0000, Mark Rutland wrote:
> > > > On Thu, Nov 19, 2020 at 10:53:53PM +0000, Will Deacon wrote:
> > > > > FWIW, arm64 is known broken wrt lockdep and irq tracing atm. Mark=
 has been
> > > > > looking at that and I think he is close to having something worka=
ble.
> > > > >=20
> > > > > Mark -- is there anything Marco and Paul can try out?
> > > >=20
> > > > I initially traced some issues back to commit:
> > > >=20
> > > >   044d0d6de9f50192 ("lockdep: Only trace IRQ edges")
> > > >=20
> > > > ... and that change of semantic could cause us to miss edges in som=
e
> > > > cases, but IIUC mostly where we haven't done the right thing in
> > > > exception entry/return.
> > > >=20
> > > > I don't think my patches address this case yet, but my WIP (current=
ly
> > > > just fixing user<->kernel transitions) is at:
> > > >=20
> > > > https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/=
?h=3Darm64/irq-fixes
> > > >=20
> > > > I'm looking into the kernel<->kernel transitions now, and I know th=
at we
> > > > mess up RCU management for a small window around arch_cpu_idle, but=
 it's
> > > > not immediately clear to me if either of those cases could cause th=
is
> > > > report.
> > >=20
> > > Thank you -- I tried your irq-fixes, however that didn't seem to fix =
the
> > > problem (still get warnings and then a panic). :-/
> >=20
> > I've just updated that branch with a new version which I hope covers
> > kernel<->kernel transitions too. If you get a chance, would you mind
> > giving that a spin?
> >=20
> > The HEAD commit should be:
> >=20
> >   a51334f033f8ee88 ("HACK: check IRQ tracing has RCU watching")
>=20
> Thank you! Your series appears to work and fixes the stalls and
> deadlocks (3 trials)! I noticed there are a bunch of warnings in the log
> that might be relevant (see attached).
>=20
> Note, I also reverted
>=20
> =C2=A0 sched/core: Allow try_invoke_on_locked_down_task() with irqs disab=
led
>=20
> and that still works.

This is expected behavior given that there were no RCU CPU stall
warnings.  As to the warnings...

[ . . . ]

> [   91.184432] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   91.188301] WARNING: suspicious RCU usage
> [   91.192316] 5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25 Tainted: =
G        W       =20
> [   91.197536] -----------------------------
> [   91.201431] kernel/trace/trace_preemptirq.c:78 RCU not watching trace_=
hardirqs_off()!
> [   91.206546]=20
> [   91.206546] other info that might help us debug this:
> [   91.206546]=20
> [   91.211790]=20
> [   91.211790] rcu_scheduler_active =3D 2, debug_locks =3D 0
> [   91.216454] RCU used illegally from extended quiescent state!
> [   91.220890] no locks held by swapper/0/0.
> [   91.224712]=20
> [   91.224712] stack backtrace:
> [   91.228794] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G        W         =
5.10.0-rc4-next-20201119-00002-g51c2bf0ac853 #25
> [   91.234877] Hardware name: linux,dummy-virt (DT)
> [   91.239032] Call trace:
> [   91.242587]  dump_backtrace+0x0/0x240
> [   91.246500]  show_stack+0x34/0x88
> [   91.250295]  dump_stack+0x140/0x1bc
> [   91.254159]  lockdep_rcu_suspicious+0xe4/0xf8
> [   91.258332]  trace_hardirqs_off+0x214/0x330
> [   91.262462]  trace_graph_return+0x1ac/0x1d8
> [   91.266564]  ftrace_return_to_handler+0xa4/0x170
> [   91.270809]  return_to_handler+0x1c/0x38
> [   91.274826]  default_idle_call+0x94/0x38c
> [   91.278869]  do_idle+0x240/0x290
> [   91.282633]  rest_init+0x1e8/0x2dc
> [   91.286529]  arch_call_rest_init+0x1c/0x28
> [   91.290585]  start_kernel+0x638/0x670
> [   91.295524] WARNING: CPU: 0 PID: 0 at kernel/locking/lockdep.c:5279 ch=
eck_flags.part.0+0x1d4/0x1f8
> [   91.296302] Modules linked in:
> [   91.297644] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.10.0-rc4-next-=
20201119-00002-g51c2bf0ac853 #25
> [   91.298317] Hardware name: linux,dummy-virt (DT)
> [   91.298975] pstate: 80000085 (Nzcv daIf -PAN -UAO -TCO BTYPE=3D--)
> [   91.299648] pc : check_flags.part.0+0x1d4/0x1f8
> [   91.300303] lr : check_flags.part.0+0x1d4/0x1f8
> [   91.300960] sp : ffffdb60f8d73a50
> [   91.301628] x29: ffffdb60f8d73a50 x28: ffffdb60f8d84000=20
> [   91.303527] x27: ffffdb60f869cbb8 x26: ffffdb60f6835930=20
> [   91.305431] x25: 0000000000000000 x24: 0000000000000000=20
> [   91.307343] x23: ffffdb60f8daf360 x22: 0000000000000001=20
> [   91.309242] x21: 0000000000000000 x20: 0000000000000001=20
> [   91.311145] x19: ffffdb60f9bcf000 x18: 00000000749f6e65=20
> [   91.313044] x17: 00000000dcd3f761 x16: 0000000000000005=20
> [   91.314954] x15: 0000000000000000 x14: 0000000000000028=20
> [   91.316854] x13: 000000000000067a x12: 0000000000000028=20
> [   91.318753] x11: 0101010101010101 x10: ffffdb60f8d73820=20
> [   91.320657] x9 : ffffdb60f6960ff8 x8 : 4e5241575f534b43=20
> [   91.322582] x7 : 4f4c5f4755424544 x6 : ffff4454fdbd3667=20
> [   91.324486] x5 : 00000000ffffffc8 x4 : ffff4454fdbd2c60=20
> [   91.326413] x3 : ffffdb60f6800000 x2 : ffffdb60f7c60000=20
> [   91.328308] x1 : 1c0af7741e0f0c00 x0 : 0000000000000000=20
> [   91.330227] Call trace:
> [   91.330880]  check_flags.part.0+0x1d4/0x1f8
> [   91.331547]  lock_acquire+0x208/0x508
> [   91.332200]  _raw_spin_lock+0x5c/0x80
> [   91.332849]  vprintk_emit+0xb4/0x380
> [   91.333528]  vprintk_default+0x4c/0x60
> [   91.334189]  vprintk_func+0x120/0x330
> [   91.334863]  printk+0x78/0x9c
> [   91.335523]  lockdep_rcu_suspicious+0x2c/0xf8
> [   91.336195]  trace_hardirqs_off+0x214/0x330
> [   91.336854]  trace_graph_return+0x1ac/0x1d8
> [   91.337518]  ftrace_return_to_handler+0xa4/0x170
> [   91.338190]  return_to_handler+0x1c/0x38

This looks like tracing in the idle loop in a place where RCU is not
watching.  Historically, this has been addressed by using _rcuidle()
trace events, but the portion of the idle loop that RCU is watching has
recently increased.  Last I checked, there were still a few holdouts (that
would splat like this) in x86, though perhaps those have since been fixed.

> [   91.338841]  default_idle_call+0x94/0x38c
> [   91.339512]  do_idle+0x240/0x290
> [   91.340166]  rest_init+0x1e8/0x2dc
> [   91.340840]  arch_call_rest_init+0x1c/0x28
> [   91.341499]  start_kernel+0x638/0x670
> [   91.342147] irq event stamp: 1727
> [   91.342832] hardirqs last  enabled at (1727): [<ffffdb60f7c33094>] exi=
t_el1_irq_or_nmi+0x24/0x50
> [   91.343502] hardirqs last disabled at (1724): [<ffffdb60f7c33060>] ent=
er_el1_irq_or_nmi+0x20/0x30
> [   91.344193] softirqs last  enabled at (1726): [<ffffdb60f6835930>] ret=
urn_to_handler+0x0/0x38
> [   91.344866] softirqs last disabled at (1725): [<ffffdb60f68c6880>] irq=
_enter_rcu+0x88/0xa8
> [   91.345546] ---[ end trace e131d25144579308 ]---

The other warning looked similar.

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201124150146.GH1437%40paulmck-ThinkPad-P72.
