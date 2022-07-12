Return-Path: <kasan-dev+bncBCS4VDMYRUNBB76FWOLAMGQEB3GMGJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2883F571080
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 04:57:05 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-31c8a5d51adsf58956207b3.14
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jul 2022 19:57:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657594624; cv=pass;
        d=google.com; s=arc-20160816;
        b=VH4Ts7DRlh1ZLb9N2umGl1el/JMGu+M97ftyyJkunpMkZHNS23en55UGoEkbRoOrCT
         1XeDKgPoQg6M7fCIfRI99FX/ZHNRQZZSU7aX9slA6muhmveNrguwQ0ZbkxbWAtnhhNs6
         1+JH1CYgiS3N2JKE6e4sKL5Mo1xznV/pa5D/pKxk3URSKe7z4MhWIisN9cgVTBzYLVnG
         cFfkhz7a1w4R8fQT1h/XkukhT3ZzZjSgBdtKUinHQZ5WffsveMZ8sQC3wXuit/JVpDoe
         2K8Y7GsKAMlcPgqnUbr18NADdGKMUtihmx1DnnvtcqmW7Z8Yrpz8yVDcUKgueH/SdDkU
         TOgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=ZzeGeT4Cms7bJ0/NPl4p2U0r0TTrvrjeCazwjYVWusQ=;
        b=dnivKr0T4l4pQiuisy/xxNk2myxC04zCpVkUyyADRIc4FdHrIydK98mArBICuIiPiV
         gZVlEceAo2gtJIMiP/p0m8Wyzx/piSoGAzOaqrNlh+5iN7EbK07Nb+kGZIPFdmpAqBCM
         Px8+h23lKZ6EjangjodLPZz3V75jIUFtxrp3DVNS39k0/g/0Or05JoI7fL8vbcPtdjCB
         k7JxT+JnU6NAtiMA9eqZppo5HvZCwM2tycoB2huE3NDm1Gdc/n7oTNoH66WGJfSKzqoD
         hFHluz//34fGoEuT2k1/5sYukSUYG5dUKujM5kh11DWyzGi7W17TbnmOBAPDZbVksB3B
         /JPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TYwrnnIn;
       spf=pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZzeGeT4Cms7bJ0/NPl4p2U0r0TTrvrjeCazwjYVWusQ=;
        b=U7GU8kzSRJDA/lmujrFQjBHJqw7DBtTGtjfpgB0s/g0sF2lufrA4O4UkL3SIGxMEHS
         Z1zHtGE+EqEbEXzoz0esxInfZvy5CtqoZ4gu9xV3TgKMfCqMWCeG6Lm58ER99HkEvZWB
         hBlD44aMW4llsu3OClii/hWVeoq7ut+lxMvnkB7F1LFN8TAjdq/d4KIkpgH0G8nodq/F
         pcumK2tgcxQLR7wT1qWIoZ8uoGj9wQkfo50PRUCRot6mfCnogxq1r5ImIXVKilHMAnWh
         QBTgve8rkOMKxYCO+iLuLdVsPn+g180Bd0cV4U+sb6fnGt5YtxW+E+7WW5LfVDlfvLP5
         SHXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZzeGeT4Cms7bJ0/NPl4p2U0r0TTrvrjeCazwjYVWusQ=;
        b=EFvhj2bvOKUT+uUh97qoi8ygC34usJM/Qz1DrL8cJhzD8TqnDDJ6y/p6tYRfVGlU6Q
         KYdXiApoJmFG/A7fHdofueF/Frkmho9ch86qkJ7aE5JG+efOGCyVdFiV90YmN3TwNcUY
         3ems7/MJSZL5r2sARqlwLO7b2wIRy+jMI3Bt9+ZL8TsgYrCD/rJnnhCdAzdeKjA3+bk6
         81Vfdnt/J/in/giuOX3BdCYnsKC8EzfqJfzNsR3uAVMsH1EoLUDzfA1suZe5WkVXpxL/
         IAjuqlXeeSgZ+cQXG++pUdP7Z0TV5JHQx6YW77pyIPH8pZG6/0wDJ0CvpHMdfFPf+vB5
         h1kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9ujIbHdOCw8qmkpY/6uiQ68EVkPzsb4uD5unxrRh/d78IpDU75
	pxcYLVgw/R2VO0nbM9CRFGc=
X-Google-Smtp-Source: AGRyM1u9JuWCfHRZ6Qi6KwZjq49uHneNlyW44WHyia6tfWwK+FzTB5MIyn75pDgFFBfxssQoeqvYNw==
X-Received: by 2002:a0d:f342:0:b0:313:62f5:292c with SMTP id c63-20020a0df342000000b0031362f5292cmr23276960ywf.226.1657594623997;
        Mon, 11 Jul 2022 19:57:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a488:0:b0:66d:24b5:fd75 with SMTP id g8-20020a25a488000000b0066d24b5fd75ls22566951ybi.10.gmail;
 Mon, 11 Jul 2022 19:57:03 -0700 (PDT)
X-Received: by 2002:a25:b6cc:0:b0:66e:68a9:a006 with SMTP id f12-20020a25b6cc000000b0066e68a9a006mr20388673ybm.249.1657594623462;
        Mon, 11 Jul 2022 19:57:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657594623; cv=none;
        d=google.com; s=arc-20160816;
        b=oVJfYwewgnPlv5jS+TOr3XZx6I0LdDi8ApWZNJu83r2gSZU9zQ1pL5MCAQZR8VH2tb
         MdQzh/VoMbhQA9exOvZVf3b1C/MidgONasruqctfJJ5Ad6087lERjNQPUBGkTbjSwdra
         1mn/8if4yVdClZGO6MUjDX5qzi+Kgwul1gPiShNYZPELHOtDHduuq69NkhuX2bzz4OuG
         3ocnB89P4FDKA1Nz8ZEBOqLFL4YCh1cuYugbATGucDrNW0o/nMdPO5k5UCMi9f9Nyt6H
         qOkNooWmXCTGinGynXdtUVikgETeauEbv0FtgBuoO1nmO9dzu/INoUU8VH50uzOgzY/8
         JCJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=elXhnDHf5FTiWyLaSlNOh3WhuxkhpUE1KvIHEcUEopY=;
        b=cIyFylCvCbDTW3k9ogmIiRgcAOCMYmDMCoIWMld7qI5qCriY9c0q1rh4rBV+l/wSqT
         FEb41wswwapqAOqaorI9dxXEbASkxqfeXP0Y6KzGs9d6rA2lGTA67lfl/GVRJWK9ExpI
         1OD8nf5KboAMghgGM2y5j5F24glbROmJwp8w7F3NV8vyVk5GgnleU23UyEAa7lSkOMKB
         Lg4g6TWh0YdJY99Ps6ABUh2nHRrTKQq8z+NensmqRaqDhwhMff2P/tXpeDqZGXGtJVVB
         /ZrmXxoC4bO3WqYk7vXa8JdkhykUyAIm0E5FJtvxKBJCxU/QXBOQPBZmAoXVkrELyP/P
         iZlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TYwrnnIn;
       spf=pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bg17-20020a05690c031100b0031cad635b99si335725ywb.0.2022.07.11.19.57.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Jul 2022 19:57:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 114D561684;
	Tue, 12 Jul 2022 02:57:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6EF84C341C8;
	Tue, 12 Jul 2022 02:57:02 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id E86245C0741; Mon, 11 Jul 2022 19:57:01 -0700 (PDT)
Date: Mon, 11 Jul 2022 19:57:01 -0700
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
Message-ID: <20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20220503073844.4148944-1-elver@google.com>
 <20220711182918.338f000f@gandalf.local.home>
 <20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220711205319.1aa0d875@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220711205319.1aa0d875@gandalf.local.home>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TYwrnnIn;       spf=pass
 (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, Jul 11, 2022 at 08:53:19PM -0400, Steven Rostedt wrote:
> On Mon, 11 Jul 2022 17:21:28 -0700
> "Paul E. McKenney" <paulmck@kernel.org> wrote:
> 
> > On x86, both srcu_read_lock() and srcu_read_unlock() should be OK from
> > NMI context, give or take their use of lockdep.  Which is why we have
> > srcu_read_lock_notrace() and srcu_read_unlock_notrace(), which do not
> > use lockdep.  Which __DO_TRACE() does in fact invoke.  Ah, but you have
> > this: "WARN_ON_ONCE(rcuidle && in_nmi())".
> > 
> > Because all the world is not an x86.
> 
> But since NMIs are architecture specific, we could change that to:
> 
> 	WARN_ON_ONCE(!srcu_nmi_safe && rcuidle && in_nmi());
> 
> and add a srcu_nmi_safe constant or macro that is 1 on architectures that
> srcu is safe in NMI and 0 otherwise.
> 
> Or do we care if a tracepoint happens in those architectures where it is
> not safe. We could then just do:
> 
> 	if (!srcu_nmi_safe && rcuidle && in_nmi())
> 		return;
> 
> and just skip tracepoints that are marked rcu_idle and happen within NMI.

More generally, this is this_cpu_nmi_safe rather than just SRCU.  Or could
be, depending on what the architecture guys would like to guarantee.
SRCU is just passing through the this_cpu*() NMI-safety property.

And in addition to in_nmi(), there is the HAVE_NMI Kconfig option:

	$ git grep -w HAVE_NMI
	arch/Kconfig:config HAVE_NMI
	arch/Kconfig:	depends on HAVE_NMI
	arch/arm/Kconfig:	select HAVE_NMI
	arch/arm64/Kconfig:	select HAVE_NMI
	arch/loongarch/Kconfig:	select HAVE_NMI
	arch/mips/Kconfig:	select HAVE_NMI
	arch/powerpc/Kconfig:	select HAVE_NMI				if PERF_EVENTS || (PPC64 && PPC_BOOK3S)
	arch/s390/Kconfig:	select HAVE_NMI
	arch/sh/Kconfig:	select HAVE_NMI
	arch/sparc/Kconfig:	select HAVE_NMI
	arch/x86/Kconfig:	select HAVE_NMI

So if I understand correctly, arm, loongarch, mips, powerpc, sh, and
sparc are the ones that have NMIs but don't have NMI-safe this_cpu*()
operations.  These are the ones that would need !srcu_nmi_safe.

Or, longer term, I could make HAVE_NMI && !srcu_safe_nmi cause SRCU to use
explicit atomics for srcu_read_lock_trace() and srcu_read_unlock_trace().
I am assuming that any NMI handler executing srcu_read_lock_trace()
also executes the matching srcu_read_unlock_trace().  (Silly me, I know!)
This assumption means that srcu_read_lock() and srcu_read_unlock() can
continue with their non-atomic this_cpu_inc() ways.

But a quick fix that stopped the bleeding and allowed printk() to
progress would be useful in the short term, regardless of whether or
not in the longer term it makes sense to make srcu_read_lock_trace()
and srcu_read_unlock_trace() NMI-safe.

Thoughts?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220712025701.GS1790663%40paulmck-ThinkPad-P17-Gen-1.
