Return-Path: <kasan-dev+bncBCS4VDMYRUNBBZN7WWLAMGQENAWNW2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B5E75718DE
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 13:49:59 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id b23-20020a2e8497000000b0025d4590922csf1369242ljh.7
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 04:49:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657626598; cv=pass;
        d=google.com; s=arc-20160816;
        b=0GtWPFIFnLuNG9vQCxZfg7YNapQe2TEARqBHkFRguY3EuIemsutfuKGJSDRynPkn+y
         unfwgChAncD4WRpQQ/97uZwAh5urylCNgGzTB3nkF5oJUcVPo47mK7BNc+BniGWXMye4
         zrgrEBEXvdCs06H9REEv9D7kfXBlue1wSgPwk8iytoyZo5t18AaCF/zsO3RBDhdbbpmG
         CIbQiU7n+1jC5KnpUzryiat7IobTzYcU1fZGc+zJftIlWpOquXCwzHGurS8FjVsfohn5
         /Hhk1OAHu9ZTCLEGqcbFZQmug2aDS10wY69NI1eIsloPOXSRCSfyj6CKeMXZuYbsZxte
         5gSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=xaXb2aVUIIN4Ja68eiI/CbGa8qATnTKniUVv8Whu39k=;
        b=hVylhnvnlCC3EnfQYWs4k/6twNVmzIGDgoOEDCbn4s9Tath+gb6O5iHWNWw6R4bAsj
         iH9MzdyIPolLVbz/62+KzUgCM62uUjFnPjgulAlhv9qUYsO4dd8peM6YxH5PziZJURoQ
         m0zcQoNb+PT7siBB4xGx1kexBfckmncNycgQe+ROM0v5MxLDKc6ZY2QGSOsA8NRWMNw4
         qyIZuBFU3m4m+/4u/3JG1u04yO10kIzSDdrdRFoBqULSMkQhilyEApIU0C7xiFsvqZ5+
         rcv8UiyTuG9x3tOx+4/h5rQ7X2qpY6gVnFAH1XAGlr/GOtqxl0CSZbChDp/DMcUV0zHL
         g38Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BeSmurLa;
       spf=pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xaXb2aVUIIN4Ja68eiI/CbGa8qATnTKniUVv8Whu39k=;
        b=G7x1FhaORZ4OpkRoV0qQ84xrEmRr+SPuzyc6J25mBjBq4VBrx0K6AB6JHiIUeZL9xp
         Px/JzgfsemjmjoNVpcXp1XpM6HK/869+hAwhFJlDYUnfcLHghBA8OUIA1gn9+PHzAXCr
         +b4a3stj04uCuEoOubkoWWLq/U89H2dcE5+W6ASAFMJGd8/6RHUWzo4QKhTXFsKcYeHQ
         HnanZqDhYITZTret+CV1FUIyBx2Sg7WxFjxAZlODugNeuOpV71YpM5UWJ+d+EpivokIf
         T2KKPufGaqfGUwOU51jNfDpq1hsEDgIn5EvvwJ8m+EWEIRDbRRBxPkgCsUyj30X2YZW9
         l/5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xaXb2aVUIIN4Ja68eiI/CbGa8qATnTKniUVv8Whu39k=;
        b=5MvnwsltmsKytqnshuAbMX7w8635akB1v77//35meGiiFqtVetcEQovGWumH6toq3v
         6CI/IjPE3Nog+SNo7JM6ZhUsSIzEWY3Rs7sxg0p4uSMoVJftQJ6s9mgo//hsw58wgae3
         FLguLulRB/+PQ+a/51fewXnBurETw+iLwwJqzDwaoKgC8YbCGjRLJ2XvaY+QZNrYbSjo
         l2FaW4oRcueNlQea5wmkUTM6O2wdyeFVl1P/DYTLDZ2zSHG1A8XE6NWb2ZzG+23G4LeR
         aZb08SpbZLeMD4FO/Bbg58FtFf0jjEYyn03ThF9hUbHPdzZK3rzf1hzMDdd4gO/ph7/5
         1bYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8Wf7f4ta03kp2e3XwrK9v6mo/+nqgQw80egKAMzPO6H+kg44i6
	45CZW87hLeJVDwvf4CScw9s=
X-Google-Smtp-Source: AGRyM1sv99OZQt6QPBFs+4ALndAOfqBOJ1NvhF8SLnY7TxY1PV5IKRbS9VmEyFHbQDb8X2HseGd4sg==
X-Received: by 2002:a05:6512:13a6:b0:482:b947:77f7 with SMTP id p38-20020a05651213a600b00482b94777f7mr14114382lfa.687.1657626598211;
        Tue, 12 Jul 2022 04:49:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:a8a:b0:489:e73d:dffb with SMTP id
 m10-20020a0565120a8a00b00489e73ddffbls57415lfu.3.gmail; Tue, 12 Jul 2022
 04:49:56 -0700 (PDT)
X-Received: by 2002:a05:6512:1043:b0:481:31f:5505 with SMTP id c3-20020a056512104300b00481031f5505mr15318156lfb.112.1657626596789;
        Tue, 12 Jul 2022 04:49:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657626596; cv=none;
        d=google.com; s=arc-20160816;
        b=SzJolf/Lj9/NisssF3Of42BXw6wLO29Z0qKGpyXTPi7M3Iz8I7dAqZahQiZv4pOmBf
         lpMjS77Gi3S0PAz06pTyXGzx5QC5lsjG1d1I2ZU2vpZvZ41rCUdFJdpY6tGJxJgx+WQw
         t6vume7SBvXgV8ySsEyPEp0e7bnUgCXJlUbOAZ81w7gDoS+/jh/6/tEyR3rrL2dsPvOb
         npuadhLadAzWT4XSoIpNNuh3MDVNuON8DWDXEXJL/Gh3qtYI7owg6TR5j/OmreFjVKIG
         AeMlp8UDCbow4ExumxnF+NxLoat3L3u6MhHxZbiT8zq3NAxte98caR42yMaPFULR+5iS
         ZkEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ToHx549QaViTfc7xBfsFkeHptY+YjRFggkvlgR3B45U=;
        b=UPoMFnPxx8TXobZvFoClpYTqdgR9a7fLokkamWCMvuksm7sM46fMeCbAUwgDHq8J56
         OtIbhdsFNtGrGgEdxBduzfzp4k/sET8oBfDNFtQyHeFv5FRSs6SuXS3XccHeQ1ldpLmD
         NwTY5+yVRXmmbcQ7qEg8Tr9nT/tYD3QnXzp/gxu9xK83D8GN1QD2FJu0/ii/nrzpW1yI
         T7E5mpmG03mPHr3mx7vaORA/YT67gE8tFTmBaXGO3onlTeLQKyddwxid1yCn02X/4+XY
         AXiWWJ9/jCgIJrBHRuMxuvWBGiCdPSmEtCYg8U+sTHyK+cr7VyOnuLBBslqoVrXG2KSu
         uHRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BeSmurLa;
       spf=pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id m7-20020a056512114700b00489d438ad8bsi294105lfg.3.2022.07.12.04.49.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Jul 2022 04:49:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 39FFDB817DE;
	Tue, 12 Jul 2022 11:49:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F2802C3411C;
	Tue, 12 Jul 2022 11:49:54 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 8C3DC5C0516; Tue, 12 Jul 2022 04:49:54 -0700 (PDT)
Date: Tue, 12 Jul 2022 04:49:54 -0700
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
Message-ID: <20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20220503073844.4148944-1-elver@google.com>
 <20220711182918.338f000f@gandalf.local.home>
 <20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220711205319.1aa0d875@gandalf.local.home>
 <20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BeSmurLa;       spf=pass
 (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, Jul 11, 2022 at 07:57:01PM -0700, Paul E. McKenney wrote:
> On Mon, Jul 11, 2022 at 08:53:19PM -0400, Steven Rostedt wrote:
> > On Mon, 11 Jul 2022 17:21:28 -0700
> > "Paul E. McKenney" <paulmck@kernel.org> wrote:
> > 
> > > On x86, both srcu_read_lock() and srcu_read_unlock() should be OK from
> > > NMI context, give or take their use of lockdep.  Which is why we have
> > > srcu_read_lock_notrace() and srcu_read_unlock_notrace(), which do not
> > > use lockdep.  Which __DO_TRACE() does in fact invoke.  Ah, but you have
> > > this: "WARN_ON_ONCE(rcuidle && in_nmi())".
> > > 
> > > Because all the world is not an x86.
> > 
> > But since NMIs are architecture specific, we could change that to:
> > 
> > 	WARN_ON_ONCE(!srcu_nmi_safe && rcuidle && in_nmi());
> > 
> > and add a srcu_nmi_safe constant or macro that is 1 on architectures that
> > srcu is safe in NMI and 0 otherwise.
> > 
> > Or do we care if a tracepoint happens in those architectures where it is
> > not safe. We could then just do:
> > 
> > 	if (!srcu_nmi_safe && rcuidle && in_nmi())
> > 		return;
> > 
> > and just skip tracepoints that are marked rcu_idle and happen within NMI.
> 
> More generally, this is this_cpu_nmi_safe rather than just SRCU.  Or could
> be, depending on what the architecture guys would like to guarantee.
> SRCU is just passing through the this_cpu*() NMI-safety property.
> 
> And in addition to in_nmi(), there is the HAVE_NMI Kconfig option:
> 
> 	$ git grep -w HAVE_NMI
> 	arch/Kconfig:config HAVE_NMI
> 	arch/Kconfig:	depends on HAVE_NMI
> 	arch/arm/Kconfig:	select HAVE_NMI
> 	arch/arm64/Kconfig:	select HAVE_NMI
> 	arch/loongarch/Kconfig:	select HAVE_NMI
> 	arch/mips/Kconfig:	select HAVE_NMI
> 	arch/powerpc/Kconfig:	select HAVE_NMI				if PERF_EVENTS || (PPC64 && PPC_BOOK3S)
> 	arch/s390/Kconfig:	select HAVE_NMI
> 	arch/sh/Kconfig:	select HAVE_NMI
> 	arch/sparc/Kconfig:	select HAVE_NMI
> 	arch/x86/Kconfig:	select HAVE_NMI
> 
> So if I understand correctly, arm, loongarch, mips, powerpc, sh, and
> sparc are the ones that have NMIs but don't have NMI-safe this_cpu*()
> operations.  These are the ones that would need !srcu_nmi_safe.
> 
> Or, longer term, I could make HAVE_NMI && !srcu_safe_nmi cause SRCU to use
> explicit atomics for srcu_read_lock_trace() and srcu_read_unlock_trace().
> I am assuming that any NMI handler executing srcu_read_lock_trace()
> also executes the matching srcu_read_unlock_trace().  (Silly me, I know!)
> This assumption means that srcu_read_lock() and srcu_read_unlock() can
> continue with their non-atomic this_cpu_inc() ways.
> 
> But a quick fix that stopped the bleeding and allowed printk() to
> progress would be useful in the short term, regardless of whether or
> not in the longer term it makes sense to make srcu_read_lock_trace()
> and srcu_read_unlock_trace() NMI-safe.

Except that doesn't rcuidle && in_nmi() imply a misplaced trace event?

Isn't it still the case that you are not supposed to have trace events
in NMI handlers before RCU is watching or after it is no longer watching,
just as for entry/exit code in general?  Once in the body of the handler,
rcuidle should be false and all should be well.

Or am I missing something here?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220712114954.GA3870114%40paulmck-ThinkPad-P17-Gen-1.
