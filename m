Return-Path: <kasan-dev+bncBCV5TUXXRUIBBEO56X4AKGQEEPD7VKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id B54E622DEC8
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Jul 2020 13:52:50 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id g24sf1837491ljl.19
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Jul 2020 04:52:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595764370; cv=pass;
        d=google.com; s=arc-20160816;
        b=jNYgpgpl/uWEJeepwYTLiYE6KlOkabJt7RMGLERCqQH2anebVOdaRHnistLhQqh00y
         y4CZN8gVMlDzqc0VejmlR485olurNhxmmBYM6hTpXnUT+mDMiSIZ3j+egBDKy9PunrAh
         E4CJmN7L/DqIsxxI8GbcgzashTjUMWPF1ewD+PW+m6zNUCRKFfkcDwE1/MDIsHCkY8PP
         Wa9oTp0zfM3UyiOgb+T4WxKDPxBvzVJZp/gF2KSmZHLIcHW9JR6bHeDHnA6azXm1W8Lo
         cMScu8rePIXqu5LyOVTeqn5th+2OU9MnjocvaS3pxChcCWp5zSWVdkK19SeediXve9Na
         PCww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yjb9UQ2d4TUqxQzfOQm1xsixdTJ/xbW2Jvipkxjy738=;
        b=LD7DuM43p3LHatVEj0o+rlYs/MIO7hPkFwVgDK4Za3r8+38YZej8surc9JunMKwG7A
         1h6+hD1yWeH0UpgJh29WhcgnuHZAr2jjkMNeXxYgwim1JDGGcSED566QuhtLF4b9jvRb
         K4YOggGHDPhcydClRldvCNgzgAB6t/PdA2lPOd4tJ8ODERy0wr2VUoJmCMMk00tT8PXU
         OBV/aB8OSkF1u3VHd1I6DldAwoPp5bw/ypSB+xQyKEOmAmmbAe1gSy1p8N9jgdZsO2m6
         BrpRUOkgdGNdefhvCxDsxkw9xmifjSW4XtMoVinSn/kq6uWQOX2tmE8UM0awIEW8fdrq
         DjVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=2TtrIcN2;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yjb9UQ2d4TUqxQzfOQm1xsixdTJ/xbW2Jvipkxjy738=;
        b=h02eJFsC5naY9Q9MbNqQArkxMfFd9QNvxPyl+PhRoii/BF2G4xUuU6UHi+hs0JMl2S
         eB9RVKiYYBFdQ6lP6hS+5Hlwtp9A7kyD3KOeiGtubs4Xc37SXPdq2XWQN08YAI/8HwLq
         y3elU79gmyS+CI2pqaVdjuDw+A6oyzD8WeBYluNO7EUnnRFutMOl0ketwtD8zASzFdKy
         G8W+Y1//rlEtnFnobW6SnfsMZlN8mdyf0PIdect7kGK65E9mdbvv2gvnTuLWFBE+9oi1
         3Igw76g+IN7Oe1MBi7i1gueNZpuBSknvkQB8i+uVHOKQuYcP42Z/P2CD8xvLq9Vc8Fs2
         snew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yjb9UQ2d4TUqxQzfOQm1xsixdTJ/xbW2Jvipkxjy738=;
        b=Rovb2ATU+mMDWBHfwWZ/uY+U0n8UutZlVK0MXt/iFKCOWgvjvO+/fSMDUGdO8+vVK+
         fzuRNmvttcQ2jvrW6Z3xj25sLC8bWzcxKFlut0IG7+CSUFDEYWmYLPLV6dk3k0u9osQo
         rcy/Wpfz9AWCZB1rQfHNBiklItOwzvib2PjbWrvywgpSXtJzO5/+Jez40cNStCLzu7CN
         HgLzUkQmrckoCiOi/gpck+HaSShhskWTul00mKgyYk0tdMdj44cDIDYN8VImcHKCj5eJ
         0uLsTq21UD6hWYwlXF/8uk0xUFJ1zwxVmEV3YmjrL6ssyJ7Z2yJrsKUElJyuFIqCkFO6
         ldcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331f/6aT5rpZ1470ur8EMZ3tY/pFJ92ZeZVfWd2w9V21YWpSDdj
	y/38nEX6NkrA6urEUWFXzlU=
X-Google-Smtp-Source: ABdhPJz2dQJHmZ0eQDcZ9R64vMSywgVq8xC2TORl29ys8u+306Dm+so0YjX+aDGgWvkfJsvWBchpiw==
X-Received: by 2002:a05:651c:1134:: with SMTP id e20mr3225580ljo.40.1595764370164;
        Sun, 26 Jul 2020 04:52:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e33:: with SMTP id o19ls1365391lfg.1.gmail; Sun, 26 Jul
 2020 04:52:49 -0700 (PDT)
X-Received: by 2002:a05:6512:523:: with SMTP id o3mr9384226lfc.212.1595764369482;
        Sun, 26 Jul 2020 04:52:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595764369; cv=none;
        d=google.com; s=arc-20160816;
        b=lY6JQNfLPUkbVob1b/fivDomSS02HDYgEVAoqSPePTECYxSRvUWUY8qDu92xOOR0DR
         qvYMOo501zMPzs/d9KVZmdmSzyd7JZC0hNwjd4ZHnv7lypV3OWWlKE1q2MQHIRKBtXNQ
         uBdPlgE7dIlwN7xN/jsnttXjx3kdI5gy+Ln+0EwIj7BNzoULP0C5PyyjCIb8fAX9S35O
         KIFAwOSx40ornQTxt9Jk6CxZ1u9sP16freKInOVCUEUq3K0yQUVUDo26ODWJev925Ndy
         mSxZlXoRuYMKieA9p8Y0l+WtF03XpqU7atyYZe0z9MWG3P6oDd8Zkao8ho+u3z8ffhrL
         B2MQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KjnRKLEHDr8Ifsf9arCUZI0KOq8oLtgssys0oHriYEo=;
        b=lEqC/f9AEyKu+Xcb71/JvbD/ytfjQzJfy4EKMmsx3GwIlAmbbQdywyaCBGRwY+wrxZ
         DZu+z0QJHM10GxC5Qacb7XnNBCaCrgltQqo8UacyJTbrytzqtwA6bAJtIHFBTGHqd+BW
         kyBVUV1w/dnU0FS2f8Zzb93ASKVHN0c1ecoj+1ZIihekPfJi/7hU6H6XqXbSq2DurjBt
         kRvG6ZFxSSNytZls5/TczltblEcYQbFL8aJq33Bbx/IfW+P3svrAYPbkmFCaSEdaMX2L
         +TtEZMM7AOTitlYyt7myEoy7bL1eZLhBfZbAhdFoFQzSpyNe2FaTqueaAgxxg3EmuooU
         84nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=2TtrIcN2;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id b13si315246lji.7.2020.07.26.04.52.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 26 Jul 2020 04:52:49 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jzfCv-00086M-D6; Sun, 26 Jul 2020 11:52:45 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D0C1A301AC6;
	Sun, 26 Jul 2020 13:52:42 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 279DC2141FBAD; Sun, 26 Jul 2020 13:52:42 +0200 (CEST)
Date: Sun, 26 Jul 2020 13:52:42 +0200
From: peterz@infradead.org
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, jakub@redhat.com,
	hjl.tools@gmail.com
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
Message-ID: <20200726115242.GA119549@hirez.programming.kicks-ass.net>
References: <20200220141551.166537-1-elver@google.com>
 <20200220185855.GY2935@paulmck-ThinkPad-P72>
 <20200220213317.GA35033@google.com>
 <20200725145623.GZ9247@paulmck-ThinkPad-P72>
 <CANpmjNPhuvrhRHAiuv2Zju1VNSe7dO0aaYn+1TB99OF2Hv0S_A@mail.gmail.com>
 <20200725174430.GH10769@hirez.programming.kicks-ass.net>
 <20200725193909.GB9247@paulmck-ThinkPad-P72>
 <20200725201013.GZ119549@hirez.programming.kicks-ass.net>
 <20200725202131.GM43129@hirez.programming.kicks-ass.net>
 <20200725220750.GC9247@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200725220750.GC9247@paulmck-ThinkPad-P72>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=2TtrIcN2;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Sat, Jul 25, 2020 at 03:07:50PM -0700, Paul E. McKenney wrote:
> On Sat, Jul 25, 2020 at 10:21:31PM +0200, peterz@infradead.org wrote:
> > On Sat, Jul 25, 2020 at 10:10:13PM +0200, peterz@infradead.org wrote:
> > > On Sat, Jul 25, 2020 at 12:39:09PM -0700, Paul E. McKenney wrote:
> > 
> > > > This gets me the following for __rcu_read_lock():
> > > > 
> > > > 00000000000000e0 <__rcu_read_lock>:
> > > >       e0:	48 8b 14 25 00 00 00 	mov    0x0,%rdx
> > > >       e7:	00 
> > > >       e8:	8b 82 e0 02 00 00    	mov    0x2e0(%rdx),%eax
> > > >       ee:	83 c0 01             	add    $0x1,%eax
> > > >       f1:	89 82 e0 02 00 00    	mov    %eax,0x2e0(%rdx)
> > > >       f7:	c3                   	retq   
> > > >       f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
> > > >       ff:	00 
> > > > 
> > > > One might hope for a dec instruction, but this isn't bad.  We do lose
> > > > a few instructions compared to the C-language case due to differences
> > > > in address calculation:
> > > > 
> > > > 00000000000000e0 <__rcu_read_lock>:
> > > >       e0:	48 8b 04 25 00 00 00 	mov    0x0,%rax
> > > >       e7:	00 
> > > >       e8:	83 80 e0 02 00 00 01 	addl   $0x1,0x2e0(%rax)
> > > >       ef:	c3                   	retq   
> > > 
> > > Shees, that's daft... I think this is one of the cases where GCC is
> > > perhaps overly cautious when presented with 'volatile'.
> > > 
> > > It has a history of generating excessively crap code around volatile,
> > > and while it has improved somewhat, this seems to show there's still
> > > room for improvement...
> > > 
> > > I suppose this is the point where we go bug a friendly compiler person.
> 
> Sounds very good!  Do you have someone specific in mind?

Jakub perhaps?, Cc'ed

> > Having had a play with godbolt.org, it seems clang isn't affected by
> > this particular flavour of crazy, but GCC does indeed refuse to fuse the
> > address calculation and the addition.
> 
> So there is hope, then!
> 
> And even GCC's current state is an improvement.  Last I messed with this,
> the ACCESS_ONCE()++ approach generated a load, a register increment,
> and a store.
> 
> Do you still have the godbolt.org URLs?  I would be happy to file
> a bugzilla.

https://godbolt.org/z/rP8rYM

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200726115242.GA119549%40hirez.programming.kicks-ass.net.
