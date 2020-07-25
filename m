Return-Path: <kasan-dev+bncBAABBN626L4AKGQECVMJPUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 100E322DA25
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Jul 2020 00:07:53 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id v125sf644253vkg.9
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 15:07:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595714872; cv=pass;
        d=google.com; s=arc-20160816;
        b=WNX6q3PPMtWX2IdMeVZs3KcthXKUkHWuyhEXS1VFIR9hnP8ITWcNvVHZJyb/bojM8S
         Gikdp9kMJGc/u6dwzGOq497rNg79r/50hqiYSTB3AIiobnLQBUTusQD3jDxb91O5bmpe
         dVwajyVBbcULpjBV73rQ+HgX18XF+fpKr7lPSbJtjEHP2VIF+iREqpD4uAsliQszWUNW
         i98wp5PyFicnJOTMVxy18ODpWPrkWXgMqVe84YbjmcIa8Ldckuoeenaja51lr9wF9eU6
         vSe5TmdF0WjYuvK6OR00gqXa9z1DyhPHc8/VTZiP3lkaFJxYE7HuoXHzv/dfDVXmBJ9u
         PFKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=w/aUsEQQbmoY8OFcfnT3cgtLcc+Ytja7zlqkygA5588=;
        b=zyOZrjmTZMRRcs65j34EI0y/v/6DVaPuRVYuo8Ua9GkHMO9KdPbek6QNvY9jAvX6le
         xmW202X4cJWjyRoA1pvoAzGeTbGAdDj05RuRgwJ7E4bW63woDICsIVRcjh/UW2gRExdy
         a7ad1X9W5mnuYFMBDb7CJFfclrHZDvB1+OK0iY+CIfSgZZTa/7dd5ndYOh9fJqhRbUAQ
         41Vtg8DSfaw0IqvV9wHi6W90NjJ4VufSe9eiTXABV/xcMV5pwy+cUN0Z7ycqjQq76kFu
         zzCVhkLSzjPtL17kmhOE4avBrUJMcRmhcb+ie6YcWnSJ17Wj5zv/n9fASfTYmB/EpLig
         3nHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=efq8CSlT;
       spf=pass (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=eJ9M=BE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w/aUsEQQbmoY8OFcfnT3cgtLcc+Ytja7zlqkygA5588=;
        b=da5qzPdVuZIGbG2RHxWPDvSNGN+BHDVYkiC5R725Od3rSYNPQDENdJgYR5qiPs5NfH
         B7mYdwkaRouXLQIjPrlFyvqdQPbk+hvIgAXXrgNYzbwZfgwH+b/Tqpd2nT6/IKhhvL2j
         fsbpRE83zS/eLysTyrkSY57EIA8bc7Jahq6lciY5n5Ms8X8CpfzBWU3smCKNrv5oD94l
         l28t2rxdCvzl197I3acX8ViUB+i1KrwW3XZE9iJguM/yGLbzZ00jelyiFIObQZaV0kws
         Jn0qcOhFFYqs+zC7T8wDheIdRzpMhYmJbLXXNHSeDmPwsmunT0J8xbIPtgCxCk0hVhmI
         Z7sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=w/aUsEQQbmoY8OFcfnT3cgtLcc+Ytja7zlqkygA5588=;
        b=FtJPAd5zn7LNK/kJOsI5qzIMRVp0xqugnsi+irELFuzJwex7zwZbF6huFT3/tFOqYb
         RUvOHMNmDpVTjRIpvBjEwTw07rcPCUQSGJXqsW3GfZAoMzvzp19B1ZA9QtIDMHOhLHxa
         ajz8sqtfMJJGnc/UXNa6mgOOUvJPec+Oz0NuJv0dSN9nL0eizXOGAtUlVLXvV2DGkExu
         3WRORbaq2oNHiLrzNDigroa+RVSp/C/6BSSJJYWZmiy/CeColERw/mbH/ieDpLuyvRZR
         r/7gUvzbB4l3N/yxy8gvB0PfYXGyZcqzaWfvH7X6+HDZ3PmXeXOxMqzBmUS5bQQgqkxY
         PtGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531k6hO/bR+IL2s+f4SSENqx1Bsn/O6spa62ld+vjGp5yO1cm+aF
	VlAZQWQrqYAnf0+SbMQQc7w=
X-Google-Smtp-Source: ABdhPJwKU2TZPoWv/VGIzLm3WNmad41VQTa+zLP+0YKFTf5npHVtDxMrh3G5hj/reoG4IDIokJj9rw==
X-Received: by 2002:a1f:9a85:: with SMTP id c127mr12488251vke.8.1595714871833;
        Sat, 25 Jul 2020 15:07:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4d6c:: with SMTP id k44ls883348uag.2.gmail; Sat, 25 Jul
 2020 15:07:51 -0700 (PDT)
X-Received: by 2002:ab0:6353:: with SMTP id f19mr12512971uap.69.1595714871567;
        Sat, 25 Jul 2020 15:07:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595714871; cv=none;
        d=google.com; s=arc-20160816;
        b=ANWUnT1Z/60iHUBJeraI/phnit/nc1KIvdW41O8/KSOwfvBBAZibUnZBFxZL/fh0+H
         7QxuXp1ZfW/q/9bykoDfsT/3ydHpXB37G7pZ+YhnppUmQYRQcAsj6ZX0G4fKWqjFbDmu
         OkFgUUEfCYQeO1WhWy9TUlz1HozPV1SN9GUL23jlQiX2dtfkIhBSo6oljqhiM6D3Svx0
         2pYKzaDvp7crGlgEvp3PDIcmih0C6sc4KkDU06N7e9LXaeGYweloH7eXDke5Pnf3H5xw
         M9Pv7VV1GO6Xo4q0lRUJAWlsGbjk7Bs69z8SsHw3FfiSKb7L3jQ3b/qguzCcTZ09itZK
         C1dQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=6C0F6wmLKV8+bswy9QMLQsjcbgQUJc1tcHq4/eNHgVs=;
        b=c/YHXILEW/mEt2o5Uia8s0mLvPibC4jVrziczxgvWMS3ZrJ700n5An2C/rTRY1Wzld
         RyeCCJnKP4xlKYujwAoqDdIyJsJqKNiH/Af5GYYNJPRRJ0PWccZosPY0pE1vu4j0VTNt
         TWmPSbSKhCjAjEC1A8gpQJzzcR+Q+0YcEil9MsO1H+Ru5vtSp8bRl9eaA8YLYjJGSM4+
         qn+stUfo3mTKb+aStBZAzm7Amd1YzyGOgXP+xs+vIXwy1xghCMgDpE34d/inw87agbL7
         zO2VHNV+fccPzWqFUkR3jb/1ZqGnZGVA+OlPCWKNzU6NfNZ9kTOS8uxlJAhzhukZ43Mk
         5OVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=efq8CSlT;
       spf=pass (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=eJ9M=BE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j1si358572vkl.1.2020.07.25.15.07.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 25 Jul 2020 15:07:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-111-31.bvtn.or.frontiernet.net [50.39.111.31])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 758AC20663;
	Sat, 25 Jul 2020 22:07:50 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 427EE3522767; Sat, 25 Jul 2020 15:07:50 -0700 (PDT)
Date: Sat, 25 Jul 2020 15:07:50 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: peterz@infradead.org
Cc: Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
Message-ID: <20200725220750.GC9247@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200220141551.166537-1-elver@google.com>
 <20200220185855.GY2935@paulmck-ThinkPad-P72>
 <20200220213317.GA35033@google.com>
 <20200725145623.GZ9247@paulmck-ThinkPad-P72>
 <CANpmjNPhuvrhRHAiuv2Zju1VNSe7dO0aaYn+1TB99OF2Hv0S_A@mail.gmail.com>
 <20200725174430.GH10769@hirez.programming.kicks-ass.net>
 <20200725193909.GB9247@paulmck-ThinkPad-P72>
 <20200725201013.GZ119549@hirez.programming.kicks-ass.net>
 <20200725202131.GM43129@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200725202131.GM43129@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=efq8CSlT;       spf=pass
 (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=eJ9M=BE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Sat, Jul 25, 2020 at 10:21:31PM +0200, peterz@infradead.org wrote:
> On Sat, Jul 25, 2020 at 10:10:13PM +0200, peterz@infradead.org wrote:
> > On Sat, Jul 25, 2020 at 12:39:09PM -0700, Paul E. McKenney wrote:
> 
> > > This gets me the following for __rcu_read_lock():
> > > 
> > > 00000000000000e0 <__rcu_read_lock>:
> > >       e0:	48 8b 14 25 00 00 00 	mov    0x0,%rdx
> > >       e7:	00 
> > >       e8:	8b 82 e0 02 00 00    	mov    0x2e0(%rdx),%eax
> > >       ee:	83 c0 01             	add    $0x1,%eax
> > >       f1:	89 82 e0 02 00 00    	mov    %eax,0x2e0(%rdx)
> > >       f7:	c3                   	retq   
> > >       f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
> > >       ff:	00 
> > > 
> > > One might hope for a dec instruction, but this isn't bad.  We do lose
> > > a few instructions compared to the C-language case due to differences
> > > in address calculation:
> > > 
> > > 00000000000000e0 <__rcu_read_lock>:
> > >       e0:	48 8b 04 25 00 00 00 	mov    0x0,%rax
> > >       e7:	00 
> > >       e8:	83 80 e0 02 00 00 01 	addl   $0x1,0x2e0(%rax)
> > >       ef:	c3                   	retq   
> > 
> > Shees, that's daft... I think this is one of the cases where GCC is
> > perhaps overly cautious when presented with 'volatile'.
> > 
> > It has a history of generating excessively crap code around volatile,
> > and while it has improved somewhat, this seems to show there's still
> > room for improvement...
> > 
> > I suppose this is the point where we go bug a friendly compiler person.

Sounds very good!  Do you have someone specific in mind?

> Having had a play with godbolt.org, it seems clang isn't affected by
> this particular flavour of crazy, but GCC does indeed refuse to fuse the
> address calculation and the addition.

So there is hope, then!

And even GCC's current state is an improvement.  Last I messed with this,
the ACCESS_ONCE()++ approach generated a load, a register increment,
and a store.

Do you still have the godbolt.org URLs?  I would be happy to file
a bugzilla.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200725220750.GC9247%40paulmck-ThinkPad-P72.
