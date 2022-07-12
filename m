Return-Path: <kasan-dev+bncBCS4VDMYRUNBB2VAW2LAMGQETI4SFFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 51A0D571EB3
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 17:16:59 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id i24-20020a056808031800b00339e6eda448sf5524640oie.21
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 08:16:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657639018; cv=pass;
        d=google.com; s=arc-20160816;
        b=QQyucFmN+LHJ8uALQ1CO7SPP04BWnj2yAl0ZSqnJxV+9xI7Z3H0x2fI4eLaiJNnJgh
         ZpdsvEiIcpZAKBkidJ6VJEkwzWYrJvxtL2tET4wlwEPqBKkkzu5PYYaV9JaTl6N58/MN
         /kbZkS+ycegqQdS6yUeY8mJy5Hd9VyCuplFY2XXIzCGB+bRHG9uvYZ02TFllD9HUe9GX
         bgcRuo/xz2f+I4IthXHdQuPv2xq4xxBMUeSC4Bl9bqt7XXxVARPV4emaUXx4EKjYAJx4
         it916f06TytkI7rVevDsm1SX5cJMVG6ktqc6pufV54HWnIdEyU7QR5MyBYgAQ2VVO1qT
         7ITg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=mENS0dYAuLfTvoSYbC/TnaOP+OPpe+iq4tWUpJVY0eM=;
        b=Y3RhBnKX3hpprt97YuqdQB8533zkxPoelMtGHr4B+0cYeRXSCOoAtl6nVfDeF2Sj82
         0XrKLf2YNf4PmxmySxH6GikkAGBgQwsWXeR1U2R42hMmMBnLy9eqlBaCED4CEvIfwi6P
         nqonVHm6xHWxLknzxedE2O5ZOIFZY4xPGQ0UTAdN1GgORX0YjI1NhRMgvOWVa9r7gl+a
         v/QZfNysXRkD7p/9dUB44IDCElEVM82oae1C7ptyq34gB7VrRPtawzwYIS5zGdEjG192
         zf1zRzPOuZP+KVPN8PKjbKvRKZOg8xOgqIIn67hSRa6Yx0Cke5C6qMIFd9L5gKOLjmmJ
         kTmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WTFrV4Er;
       spf=pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mENS0dYAuLfTvoSYbC/TnaOP+OPpe+iq4tWUpJVY0eM=;
        b=ZBJQCVQot4AR+XCyUe7sbn7FhIC3uuByzoyyGPbthRspDk2RUAVogWJ+8QN/3WwhM5
         Jg2eohJLr4ADe9DOpjiTf+nXMdAlwcXmz0DvzBQiNZYLqXOlG7hFrxZs5l1fTEI5dwEj
         3Bc4y5IhRo9folvQ8ryoZ8nUF5jJWJpxDG2vd10Zv7WmXxdwGbo/PhpRo+xlgzdvIstK
         455Y7nl0f3rY1LRYb3lzt0O3/hnaq/vmrNXoeg6ueJpxJwpMrmotjPJ/C/D6dG+VhWz7
         I2nzN9X0csjCpk0bPFgCyx640XSkyYDEbyQhlbrXZOniQKyJm2Ke9JHtramYs7QBW2sj
         l1Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mENS0dYAuLfTvoSYbC/TnaOP+OPpe+iq4tWUpJVY0eM=;
        b=sfEmCRJR4+UrCtqnYQlOBtUaUyZu6xcoeM+Vfb4HCHJ6uT8h9/n8+POf6klMQtLFU/
         U8jSz5zjfRi9nDSHLok/ykLTUMO2esL07sO7a1bEA9Gy9EGQIASYLZyXpoHWRwXX2Zj5
         Ib3WkbO74L0kCiBFs6opCRD/paqjXhUnjb9y5QUdHcr77MVs4430k/+FM27SRsYni2Vh
         Dsc5Ry7T0n66smj1liQslMRlA8BYgUVNLQHRM9glWi/tvKrNv88uTUvX5MCv6/dtklxh
         8uHJy/5sgAzmuF8h6sLeYMu78YBGA6fqSMoKt873NUWjP9/kPQlimeTlwgp5irSTsT7X
         EFcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/qiBOO5DHmZX0uAoa41a6tFO0iz+4HP4hGhrdCu3CjWWYiPAZX
	pgpC1umPmRhQmGG8wg0N76Y=
X-Google-Smtp-Source: AGRyM1v0fIfd2GPc7sPttUyRgxDyOGwAglBnsQzKjT4Jq+Do7kH07bnWe/TdEfNJN823piUj6EdSJQ==
X-Received: by 2002:a05:6870:b613:b0:10b:db5f:6026 with SMTP id cm19-20020a056870b61300b0010bdb5f6026mr2105907oab.159.1657639018153;
        Tue, 12 Jul 2022 08:16:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:408e:b0:10c:ce56:fa50 with SMTP id
 kz14-20020a056871408e00b0010cce56fa50ls517799oab.5.gmail; Tue, 12 Jul 2022
 08:16:57 -0700 (PDT)
X-Received: by 2002:a05:6870:c087:b0:10b:f146:69bb with SMTP id c7-20020a056870c08700b0010bf14669bbmr2082994oad.48.1657639017621;
        Tue, 12 Jul 2022 08:16:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657639017; cv=none;
        d=google.com; s=arc-20160816;
        b=cP4Dg5alBOhIqHqJdHKy7vt4FEqJrO1vt5XRIFUOQ41hiZu9ofMwiUTUlSrQtNgVeT
         YZ8CRTrdB63UOH1GYVo5Hu51kRmO3XQXbt2S0VNF6TASncDbjIwpFzkjjYBVqt7mcOta
         r0K85mEQ0RtPeDI10Vr2b/nmeQvE7firZO/DvNjeoFSbVeSICFAtrYXnjCpgQ90z8Jqh
         ISgf8XVzIkHAZOvUdCjPtY/vrjeMaFi2fjvIExsZzvKVKQWtna5LmLe8Ptn44BPpgdGW
         dAiJTkZAWn2SAthHwgPYlBXKkRQ2sM636Az1F+nV4FeeN+U6qB4nAYZ1cBKsWOBd4AwH
         IJWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Znmue3EeeLb0r3vQHgPRF6vlpK7sqNyZ+O5F91xt5/A=;
        b=lrZGRpHyijAZFb39j1JRPUmAOWzR4NomKnmsqPKAUtNwrffqnlyVYeQJuOpcy5Jgd4
         5LtIsnQniIiL7XcsNH4LcONe5riJED4pCiXEunwVbLljhMPTBTMVUDMuhP7UPfrCLADv
         ZCvIFSknb4tKiu0FsrCq5NvMeoVvWjGDysNLr9zplzBSpHWgS/RWMF5+AGuZPDIqaXNo
         fM9VQlVJxSk2klhWwihejhcVd8lwmZKd/z45FY62ot2bMg0KH/5ztxvdkuSFJXx7NgAU
         nXEtGrG5Q06zsWxfuaeQs7DQVbrpUe18f13nr/vMk181M8UBgp555zXQnqIR7GkuRgSX
         xe0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WTFrV4Er;
       spf=pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id l6-20020a056871068600b000ddac42441esi566800oao.0.2022.07.12.08.16.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Jul 2022 08:16:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B1D89615C8;
	Tue, 12 Jul 2022 15:16:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 22461C3411C;
	Tue, 12 Jul 2022 15:16:56 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A917D5C0516; Tue, 12 Jul 2022 08:16:55 -0700 (PDT)
Date: Tue, 12 Jul 2022 08:16:55 -0700
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
Message-ID: <20220712151655.GU1790663@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20220503073844.4148944-1-elver@google.com>
 <20220711182918.338f000f@gandalf.local.home>
 <20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220711205319.1aa0d875@gandalf.local.home>
 <20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
 <20220712093940.45012e47@gandalf.local.home>
 <20220712134916.GT1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712105353.08358450@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220712105353.08358450@gandalf.local.home>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WTFrV4Er;       spf=pass
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

On Tue, Jul 12, 2022 at 10:53:53AM -0400, Steven Rostedt wrote:
> On Tue, 12 Jul 2022 06:49:16 -0700
> "Paul E. McKenney" <paulmck@kernel.org> wrote:
> 
> > > I guess the question is, can we have printk() in such a place? Because this
> > > tracepoint is attached to printk and where ever printk is done so is this
> > > tracepoint.  
> > 
> > As I understand it, code in such a place should be labeled noinstr.
> > Then the call to printk() would be complained about as an illegal
> > noinstr-to-non-noinstr call.
> > 
> > But where exactly is that printk()?
> 
> Perhaps the fix is to remove the _rcuidle() from trace_console_rcuidle().
> If printk() can never be called from noinstr (aka RCU not watching).

Maybe printk() is supposed to be invoked from noinstr.  It might be a
special case in the tooling.  I have no idea.  ;-)

However, the current SRCU read-side algorithm will tolerate being invoked
from noinstr as long as it is not also an NMI handler.  Much though
debugging tools might (or might not) complain.

Don't get me wrong, I can make SRCU tolerate being called while RCU is
not watching.  It is not even all that complicated.  The cost is that
architectures that have NMIs but do not have NMI-safe this_cpu*()
operations have an SRCU reader switch from explicit smp_mb() and
interrupt disabling to a cmpxchg() loop relying on the implicit barriers
in cmpxchg().

For arm64, this was reportedly a win.

If it turns out that we need SRCU readers to be invoked from NMI handlers
in locations where RCU is not watching, are there people who would be
willing to play with a modified SRCU on the systems in question?

-ENOHARDWARE at this end.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220712151655.GU1790663%40paulmck-ThinkPad-P17-Gen-1.
