Return-Path: <kasan-dev+bncBCS4VDMYRUNBBQFCXOLAMGQE2UQ7XIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 07619573851
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jul 2022 16:05:55 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id r7-20020aa79627000000b00528beaf82c3sf4023847pfg.8
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jul 2022 07:05:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657721153; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZY4824GKqxGdnKvfA44nJ16rRuDurnpjw/ZgPir7CMtj+loQTFOEh9dpSfQ5T9/k0f
         PqnL8Fv38ZgY7TDyNBEjxLKDOBZHQcYDv21Kxmz7RR6TSeSpE16EchKPlbf3QqcQuUlH
         O+kAYlUZrpA/t57ecTtIUY/lX3/I6cKxvYhcQJYx4rxF62D7IGd20UuHACvS2hH+U8ea
         1vv6r0FtfU4NKMvdsJ0hoJuEw0LRGcsIOAszGx4ybiYr2vjNPccm/jdJFgGUsXJfSXTc
         E8Q2RijbkgMg9Lk2qGLY63VzIiPhg8kDFj/QYgBmKzLspfGXklgs5I6yxhVsC/V0TPVK
         aXFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=IvD0SknYSX2wKSYCImUJm9HT3iwJpj1QhYQHy8nsF4Y=;
        b=ZfuVhEMGwkuL7gLWIfTQEU+mwJSJGIu6psFHvbSTNoxR7AZz9ksHvaHHcS6BMfQI4i
         ndpZncsreWpTn+dw/fnijjhA/O9D5X3slPj55RhV2hyEdnAzo2KQaFUeKaKp+FpGf/27
         FvKXsXEcQUL3OsyfW4Z+scDNaDzW2ba2mnwRLmWMWG277lg32uF+VQpv12WFxrHH8vDl
         rNGnOOf9prhCfn54j+eJqR+gak2sxGOlNLV6WuvBZvqnpVTLG5qufKRxa5UScioSJz1f
         9Vtsnx8kbysD0k23xdeaa4ITJLLznP6FYbuaz9EsodouU4r23HX514c/T5wYJfWgB1ZN
         mwfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="SBr4/onX";
       spf=pass (google.com: domain of srs0=uvzi=xs=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Uvzi=XS=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IvD0SknYSX2wKSYCImUJm9HT3iwJpj1QhYQHy8nsF4Y=;
        b=DuIjWerojIMsmztkHXOsiQJgssoa9C3uD17NinkWNUaUWgzZ2GetyyszQ9bTAIy2mb
         /qoTpm5ALyyC8Ttsxw+P2UjiigUApVEY8v60jmfTw73HbwFE9nJ+A2IboTbea4RcTTFv
         Ofwv47QPXCTF0Rn+A7Y6D0HGD1L5mpHrLYU27TTwSUoDC5Ae7eTJZAEngYrHc7yy37+z
         QwshwVvT1VGZiYiH1yNnmWRoL4s6pTlMGvOKkifGx6ub19Cp15uB+SI5tGsz/xDibzQG
         O64KI97B04+cSX0k3wrn/iH2evciDhYVhlixAklwCsKnH+kX/yFTInrcxJJ5nADGMdbk
         ACGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IvD0SknYSX2wKSYCImUJm9HT3iwJpj1QhYQHy8nsF4Y=;
        b=felZqx5NUVG5FWpA89pgM/4HCNX1Yo2Dm+FnbIo6k15np65FuCP5VjasQ6gLYYAWY7
         n4rSVeP5Yvs3Bz8fpbSN6cMnJh1WR9gpGCXi5Zsp6EU1FJPctKTTFCOAER3p/DOMhVDd
         fBPpmYCHN3xeFwQriA66RYS0aJFTLE0Hrnd9ddURXLUnRtX0roAsLR+gsYahx3oPlzt/
         fTNiJ8zQwOsmrM32de782hubsqaTq/8+gEZ/ERCIZfoLcPc8vj1IMeKc5mVWHoSpUBCS
         CrSbFWlIMdsp/bDgvKd4/jy3GNQDV/fRKD9gnvrEamo3wvpx1/qZsPGLwgqscww10Dys
         fZfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/j13b2xWJi59E/R5KKyEm8KmC0CmRiAzTpGg0u1nvmIlk9qRNs
	3RzRuIfxUj8390pvR6ZmPAk=
X-Google-Smtp-Source: AGRyM1s7zMs4Yu26YDY67adCSfjZ63o5i9ZHJt7YU7/T986LCOqbHpZG1DynOkBPxeVf85Bd3C1Www==
X-Received: by 2002:a17:902:d4c5:b0:16c:44b7:c8fd with SMTP id o5-20020a170902d4c500b0016c44b7c8fdmr3384774plg.36.1657721152866;
        Wed, 13 Jul 2022 07:05:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:a1a:b0:528:9fad:1baf with SMTP id
 p26-20020a056a000a1a00b005289fad1bafls2843325pfh.3.gmail; Wed, 13 Jul 2022
 07:05:52 -0700 (PDT)
X-Received: by 2002:a63:87c7:0:b0:415:e33d:ee9e with SMTP id i190-20020a6387c7000000b00415e33dee9emr3204268pge.612.1657721152046;
        Wed, 13 Jul 2022 07:05:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657721152; cv=none;
        d=google.com; s=arc-20160816;
        b=tLEIQk9dk1QnQbComfd/G2DHjX4iJbDI9CIMn2CA0sOBq37ofDf3r4kn7uzmtvSpvW
         ZHS8OyXSi3AUXmeVHtHAKbSRlqT58XdMKgvCTpHwrQXSuT6nnrp5cj8Ca7WxH7uGBchQ
         A6fRAPhCfMpJkBsoKx7VqJaIl09u1l3GnDFqxo0/9AIHMK7No+8zqOhr8bYdc8UHOtab
         lPL+nP3CbPAJL03/QK+LamxCpGBc/M1HZ/wYowK1f5zz4v/h4bjCzEsmp3KPnz+v5Q5I
         KmL4a+NH1DVa8r0FZclZZPjmwsP8z/Gy0yeQTyA/0uvHFwrG1rGJSZXsZoz+HcEt4SmL
         97LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UG0OaKdP50GJetUiiPAuy493p+udkQdXG3XMAn2fyiM=;
        b=CYAhTjQ15z2EZyHWaw6fMLl5ARC6kSOVp04gl9FNq9riASO2MojrtBFfJzHJ27iisX
         N9wjAF/JdhfqeZmEZ0+ROoKdFkBoxQpfVLu9KpPIzskkYt3Gkz53OmyPraN1Qgubh2Z+
         Y2+MDwc4uOy/qYmyxApLWpSS8PPJEW0RS3fCrwqMqUYd7E22mOY8IOfkV79dS9JBTOxm
         jU4FjLk5Qp9sacAHjJiGNRjxY2AkAHvpbkXhRNLG08BhkixZs3bXfJj3X2FmYgJkfhkL
         aPuW4iKjegFuCg1TOXx5UnTWnKgPUvAXMORqhFqM3ZXP7DQ1nZaaFhvkMn/zaDNTrElb
         6mRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="SBr4/onX";
       spf=pass (google.com: domain of srs0=uvzi=xs=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Uvzi=XS=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id lp3-20020a17090b4a8300b001e8520a65e7si72319pjb.1.2022.07.13.07.05.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Jul 2022 07:05:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=uvzi=xs=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7B64361DA0;
	Wed, 13 Jul 2022 14:05:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D2D36C34114;
	Wed, 13 Jul 2022 14:05:50 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 6AFC05C0134; Wed, 13 Jul 2022 07:05:50 -0700 (PDT)
Date: Wed, 13 Jul 2022 07:05:50 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Petr Mladek <pmladek@suse.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Marco Elver <elver@google.com>,
	John Ogness <john.ogness@linutronix.de>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220713140550.GK1790663@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20220711182918.338f000f@gandalf.local.home>
 <20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220711205319.1aa0d875@gandalf.local.home>
 <20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
 <20220712093940.45012e47@gandalf.local.home>
 <20220712134916.GT1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712105353.08358450@gandalf.local.home>
 <20220712151655.GU1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220713112541.GB2737@pathway.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220713112541.GB2737@pathway.suse.cz>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="SBr4/onX";       spf=pass
 (google.com: domain of srs0=uvzi=xs=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Uvzi=XS=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, Jul 13, 2022 at 01:25:41PM +0200, Petr Mladek wrote:
> On Tue 2022-07-12 08:16:55, Paul E. McKenney wrote:
> > On Tue, Jul 12, 2022 at 10:53:53AM -0400, Steven Rostedt wrote:
> > > On Tue, 12 Jul 2022 06:49:16 -0700
> > > "Paul E. McKenney" <paulmck@kernel.org> wrote:
> > > 
> > > > > I guess the question is, can we have printk() in such a place? Because this
> > > > > tracepoint is attached to printk and where ever printk is done so is this
> > > > > tracepoint.  
> > > > 
> > > > As I understand it, code in such a place should be labeled noinstr.
> > > > Then the call to printk() would be complained about as an illegal
> > > > noinstr-to-non-noinstr call.
> > > > 
> > > > But where exactly is that printk()?
> > > 
> > > Perhaps the fix is to remove the _rcuidle() from trace_console_rcuidle().
> > > If printk() can never be called from noinstr (aka RCU not watching).
> > 
> > Maybe printk() is supposed to be invoked from noinstr.  It might be a
> > special case in the tooling.  I have no idea.  ;-)
> 
> I think that it is ok to do _not_ support printk() in noinstr parts.
> 
> > However, the current SRCU read-side algorithm will tolerate being invoked
> > from noinstr as long as it is not also an NMI handler.  Much though
> > debugging tools might (or might not) complain.
> > 
> > Don't get me wrong, I can make SRCU tolerate being called while RCU is
> > not watching.  It is not even all that complicated.  The cost is that
> > architectures that have NMIs but do not have NMI-safe this_cpu*()
> > operations have an SRCU reader switch from explicit smp_mb() and
> > interrupt disabling to a cmpxchg() loop relying on the implicit barriers
> > in cmpxchg().
> > 
> > For arm64, this was reportedly a win.
> 
> IMHO, the tracepoint in printk() is not worth slowing down other
> important fast paths.
> 
> The tracepoint was moved into vprintk_store() in 5.19-rc1. It used
> to be in console_unlock() before. The previous location was not
> reliable by definition. Old messages might be overridden by new
> ones before they reach console. Also messages in NMI context
> used to be stored in per-CPU buffers. There was even bigger
> risk that they would not reach the console.

Fair enough, works for me!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220713140550.GK1790663%40paulmck-ThinkPad-P17-Gen-1.
