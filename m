Return-Path: <kasan-dev+bncBCS4VDMYRUNBBCX5WKLAMGQEJUJUY3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1005D570EE3
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 02:21:32 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id li2-20020a0562145e0200b0047350bbed70sf1063987qvb.19
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jul 2022 17:21:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657585290; cv=pass;
        d=google.com; s=arc-20160816;
        b=osrJ/xR+1TReUxp96izp2R3pG1mfnXH7JK7ofnabTV0nhFE02CiJo6YLim/+JoW3jb
         qyt3szA6hc0tlcP0CLWaK4SOAeHj+GAsxZy7qKp2KngRibZWlzo9+0UDvga4G3hefOCo
         MzyY3IyeUo37lmfbfJahy1RI0Y1zoLcy0pjq88KW0ujm2+gYcpT58eskt+xGMvuO/47B
         fsh5KhLG3MOigQAS9iP3GaY1Jn0ClR8WmGlbKGB68OC8UsiS4+V2s4W2EqsMBTA1j3jh
         RtsQG+fZlQFUOr9HQG0RkyTZO5Mr0ygY677GXyjnrRf2nHRcmIeLn9YSiuZoGMSAuoIN
         5tGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=8qlSaampeur+7ersCN+MY8tWex0jv22E+HpebnlrsWk=;
        b=L8oLyNKwV7NPH1gI9vQYz90O19U5vbpMcP4DJxf9lX7Xt5pUKzMWmpu7VnS/RoT7dt
         bo5FLS9iPHTVRXxWwMPRwk4lNsz5T/oCfznDSUwrhmzR0Fj6kfCNdrCoUrMm91+FoGbg
         OH7Utt1G5frlEdeM4nMWkci1kH3OUjF2xKZ3boS210IH4BkrOnfhe2a9v9b14pGGot33
         FZQepZU5pAZsiyobM2UoyKvS/Rt++8iPhR3TvYffVCle/OZL4XiFy0Nn1JCU09GXW/i5
         45qAlYV5FPujn7FfCesX7ckfpXolKKCUVDyDAcx5IqzHwYhzPk+bA9jl3PiQwgDPaQ/X
         Xv0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fjwtWoah;
       spf=pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8qlSaampeur+7ersCN+MY8tWex0jv22E+HpebnlrsWk=;
        b=qd8Iqc6dJb0i/B4SsGwFxmhztaol6iLfnjkVQyilPjpZoGFu+EJo/VrJ1GMq01YYMB
         SYcOPTYJBb6qWJXXchj1DBNYrm6noYtADvW39lK/RRzsfvt6EQSI4w552B8+aZv9kz+m
         vUwaTfBrse+/kygbgieQEd3wypw3k2qA3/xxq1VAk4afO3JmtVFAN7838Bn/xIGsEgB8
         FXyAS+2VpflsSxF860Y3QQfxnfA3/tqRm9GBZS0jdsMybxA27xQlVfhMSPuMiF4V3gCX
         w8O4GggxfX5j+MlnltomTAYD+UgdzNy8M903KIpvFgmLj7yjtnszGe9mQlGdGO1c+ywr
         RVZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8qlSaampeur+7ersCN+MY8tWex0jv22E+HpebnlrsWk=;
        b=6rQcOTyd6L8HtvpEtfJ46oXdPbAvxeE+Hy5K//uG0UlbEBahuHCpflL3BIvyB68FvN
         cf65m8jRXQuiSS7SM9QhoKULKDKdJVMo6lFLERnSb0EEmViXvTmTd9kmOZLFioCotail
         wtXO+QfZ81EdaMudU4aIOFnztuwd458Mm7R924+Atk/Ln9Cdbn4ZP1p6+fqIS5L/h8al
         cuuiqQ6Jb1UDFgGZRHa4z9+AseJXwPqUsEVpWxKvuA24HOdPFrnPJbNFrYtK9pOSUoTI
         /RUlp3j7zDBu5rSXpM7huU8/n+8y/eW9vgHCnttabfZdTpz587CPwayffRcNx11ADd37
         VWIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8y5NaxNIn7cNhjJVkeOcFuMMW7BQpfvA1C9iLzVTnBX2qtYmlu
	FY4axujM3rgCg3DLp3MtteE=
X-Google-Smtp-Source: AGRyM1vPvMqwtKYJUAQuLiNX+YHDkcz/Gi97GlTwLgIS2UObrfC9kIcmsEsyj3w6DwTf3SnXMQQZxQ==
X-Received: by 2002:a05:620a:1728:b0:6af:59d0:d87f with SMTP id az40-20020a05620a172800b006af59d0d87fmr13353121qkb.149.1657585290787;
        Mon, 11 Jul 2022 17:21:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4312:b0:699:fda3:7819 with SMTP id
 u18-20020a05620a431200b00699fda37819ls884891qko.1.gmail; Mon, 11 Jul 2022
 17:21:30 -0700 (PDT)
X-Received: by 2002:a05:620a:5:b0:6b5:7c8e:78a4 with SMTP id j5-20020a05620a000500b006b57c8e78a4mr6595165qki.554.1657585290284;
        Mon, 11 Jul 2022 17:21:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657585290; cv=none;
        d=google.com; s=arc-20160816;
        b=iBwN5YzyrD2P5WA7SYUfth3wICaYPbqasPkAhGiJTcKnJuIcnjUxdhaFC6h5MVJ2Ti
         GxPeNx7LRHjE9RYLL/wOGU0/EXFw8xe1VBf7qnhC3MV+D3304VuvHih35vzjrsYQ0W8K
         TD7S7tlY1Cllq+BBFgjd18DxVtlptThBkoatk/42lI2boem9JVG+vSQ+Os9aepVeHeh0
         KV8YuSoyHHJZlBEFiVecEtjVZgISC5QyM42j4rfRZt66KLxtFjzKqO8BdDjB8VDQXyWx
         nlxUXs7Lgszbwi/IxEfKkOPptY4tRSMqA16DRB5I3RABTIaNnCA48friQISfCmHudEuQ
         kEyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=JR9Z0DevueO6a1sNoUr1ma5k2qBsn43YrKGV6lCVwP4=;
        b=LBC5Qb2h/A3oEprbFD5lni8xMjIYmRR3Ryf0sWMdmDTmM36HcBbfwayFLs4hUYQNfi
         xZvo+rpENpmfiSfScfVKqKKMStfviNuD2n2g6bLCtNkcMK4mu2H6zr46zlN5x27pdbfB
         z8go2aQv8hJEwrmTW4hmNlIuOdksHVQmw9M45UpwPR3uwIVPcbRRSafCixh/Uy1PvDPs
         J9AObOMCgElkXDxVx/qdh9bFf4+TnTmXw+F43vfW/u8+aB2RoEN/Ir+btvm2SHiHXr7s
         vYWvjOB4tXKc9NxE03oISMwSXhbo3T7uJZzejtsqSkUqBDQZeB03rQn6CaDPUMu+cXXY
         NqnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fjwtWoah;
       spf=pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id k6-20020ae9f106000000b006af462badf3si291525qkg.6.2022.07.11.17.21.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Jul 2022 17:21:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D3D47615D1;
	Tue, 12 Jul 2022 00:21:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C02A1C34115;
	Tue, 12 Jul 2022 00:21:28 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 4B6485C03B9; Mon, 11 Jul 2022 17:21:28 -0700 (PDT)
Date: Mon, 11 Jul 2022 17:21:28 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Marco Elver <elver@google.com>, John Ogness <john.ogness@linutronix.de>,
	Petr Mladek <pmladek@suse.com>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20220503073844.4148944-1-elver@google.com>
 <20220711182918.338f000f@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220711182918.338f000f@gandalf.local.home>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fjwtWoah;       spf=pass
 (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, Jul 11, 2022 at 06:29:18PM -0400, Steven Rostedt wrote:
> 
> I know I acked this, but I finally got a tree where it is included in my
> testing, and I hit this:
> 
> INFO: NMI handler (perf_event_nmi_handler) took too long to run: 9.860 msecs
> ------------[ cut here ]------------
> WARNING: CPU: 1 PID: 16462 at include/trace/events/printk.h:10 printk_sprint+0x81/0xda
> Modules linked in: ppdev parport_pc parport
> CPU: 1 PID: 16462 Comm: event_benchmark Not tainted 5.19.0-rc5-test+ #5
> Hardware name: MSI MS-7823/CSM-H87M-G43 (MS-7823), BIOS V1.6 02/22/2014
> EIP: printk_sprint+0x81/0xda
> Code: 89 d8 e8 88 fc 33 00 e9 02 00 00 00 eb 6b 64 a1 a4 b8 91 c1 e8 fd d6 ff ff 84 c0 74 5c 64 a1 14 08 92 c1 a9 00 00 f0 00 74 02 <0f> 0b 64 ff 05 14 08 92 c1 b8 e0 c4 6b c1 e8 a5 dc 00 00 89 c7 e8
> EAX: 80110001 EBX: c20a52f8 ECX: 0000000c EDX: 6d203036
> ESI: 3df6004c EDI: 00000000 EBP: c61fbd7c ESP: c61fbd70
> DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 00010006
> CR0: 80050033 CR2: b7efc000 CR3: 05b80000 CR4: 001506f0
> Call Trace:
>  vprintk_store+0x24b/0x2ff
> perf: interrupt took too long (7980 > 7977), lowering kernel.perf_event_max_sample_rate to 25000
>  vprintk+0x37/0x4d
>  _printk+0x14/0x16
>  nmi_handle+0x1ef/0x24e
>  ? find_next_bit.part.0+0x13/0x13
>  ? find_next_bit.part.0+0x13/0x13
>  ? function_trace_call+0xd8/0xd9
>  default_do_nmi+0x57/0x1af
>  ? trace_hardirqs_off_finish+0x2a/0xd9
>  ? to_kthread+0xf/0xf
>  exc_nmi+0x9b/0xf4
>  asm_exc_nmi+0xae/0x29c
> 
> 
> On Tue,  3 May 2022 09:38:44 +0200
> Marco Elver <elver@google.com> wrote:
> 
> > Petr points out [1] that calling trace_console_rcuidle() in
> > call_console_driver() had been the wrong thing for a while, because
> > "printk() always used console_trylock() and the message was flushed to
> > the console only when the trylock succeeded. And it was always deferred
> > in NMI or when printed via printk_deferred()."
> 
> The issue is that we use "trace_console_rcuidle()" where the "_rcuidle()"
> version uses srcu, which the last I knew is not safe in NMI context.
> 
> Paul, has that changed?

On x86, both srcu_read_lock() and srcu_read_unlock() should be OK from
NMI context, give or take their use of lockdep.  Which is why we have
srcu_read_lock_notrace() and srcu_read_unlock_notrace(), which do not
use lockdep.  Which __DO_TRACE() does in fact invoke.  Ah, but you have
this: "WARN_ON_ONCE(rcuidle && in_nmi())".

Because all the world is not an x86.

For srcu_read_lock() and srcu_read_unlock() to be NMI-safe more generally,
this_cpu_inc() would need to be NMI-safe on all platforms.  This requires
it be implemented with read-modify-write atomic instructions, which
appears to be the case on arm64, s390 (for at least some configs,
maybe all depending on what the "laa" instruction does), and again x86.
The generic code relies on disabling interrrupts, which does nothing
against NMIs.

So srcu_read_lock_notrace() and srcu_read_unlock_notrace() are NMI-safe
only on arm64, s390, and x86.  So that WARN_ON_ONCE() is necessary.

> Thus, we need to make sure that printk() is always called when "rcu is
> watching" and remove the _rcuidle() part, or we do not call it from nmi
> context. Or make srcu nmi safe.

Which means making this_cpu_inc() NMI-safe.  Which could be done
by making the generic this_cpu_inc() implementation use something
like arch_atomic_fetch_add().  Or a cmpxchg() loop.  Or making
__srcu_read_lock() and srcu_read_unlock() check the architecture and Do
The Right Thing.  Maybe a CONFIG_THIS_CPU_NMI_SAFE that is set by
x86, s390, and arm64?

Is either approach something that those other architectures would be
willing to countenance?  For me, it might be worth it just to not have
to dig through many layers of this_cpu macro definitions from time
to time...  :-/

							Thanx, Paul

> For now, I'm reverting this in my local tree.
> 
> -- Steve
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220712002128.GQ1790663%40paulmck-ThinkPad-P17-Gen-1.
