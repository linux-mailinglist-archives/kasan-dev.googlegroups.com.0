Return-Path: <kasan-dev+bncBCV5TUXXRUIBBMF6XD7AKGQEX2ZY6NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 7395D2D108B
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 13:25:21 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id u2sf7301231pje.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 04:25:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607343920; cv=pass;
        d=google.com; s=arc-20160816;
        b=iy2d7hV1NbPVC9EPVLXMtMW3HZfQZGxgnXahtWQylrsIC+4HqQ1HRgwIpHIX/pneP2
         Pl5iq6jQZSyZLSkbCsZw1g15A/5WeJi7ETP0PrPLhogjGMDDn6HfGo4TKNnBCakxEYcD
         unuXilf+phKLroWpf9nSoESfa5KCRjz/s1M86hENkWCjlPhf4i9sFhGaE14BCYUby3V2
         at1O0qRT/CSRxHAkBgwtLkVYHfAqu/tJUEZN5tdrGSQL/jPBYb5nYbZML5vNPcKhzYRr
         HEU5gqP9AxHipTSYift4tmkkV2KMyeWDaieWdiM0TMSxvn2pUOxBXnJtjFuwo7z06FQh
         v/LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=a4K1IpKVLF4WAtyJVS2L0lDCOIaOkxGj9ykUaNOET8o=;
        b=n2UPku2hFPnUzYIs3d/KnUwmRsFigVT03gaMDIoEh3E2X0tilUIa4cIJqCOUFlbAYv
         JVdsZeMEWhxJVRhWLuTRXmJSS98hQ+x7/JjqPP4B5/NHRRcG2uHkI8U/9KXdz08K9IhI
         QPlnPwAAtwIZ1ONEsCK/soykSBWBgAUuIx0XIIr2U4PvPdLE5ucGysdKEdu72JOhPwVa
         CQayZMlSl0SimDgcH3z4bQokbN+w2/gnNWEmPjAUx7WRSJLdA9G5hJbFbDAX+OqVV6Cg
         IFjI262DoAkp6D36Mtp27NRo91u+kPT7FddqJevbxKGpY/+x4eyfUqJccub+0hBAv96R
         q04w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=k5IwLzqp;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=a4K1IpKVLF4WAtyJVS2L0lDCOIaOkxGj9ykUaNOET8o=;
        b=I33r3xZeB7ky0GOso6uNZT9FisZSMX+FvNl3h9imG9g5YeVD1IPXl0ldNAT1ooQMXd
         jDD3dJdjXcmmYLNUFPiIQpnGOVwxFbPnh4MIysqALsjvL8/X0TfC23xlCCcwW0KTCbG+
         Amn4EZaX5rG/a0M3iIPPjY9fa+h3x1UlschGaY3Rdb4FE10T2Uizb0nzPLJ24WNcjb70
         5XYSGZbDJcSlgA2RmGR6gWnYiWF1WSV9auC8vM2P+HiyHkFghCBmxJMBuMH2XE9Zhu1e
         I6h8/pU7elbNCh+j+Vwl1nJ3VKu3oLt0dVMtnsQnmunUVR4EUbGggYpO6xKXYfZMVctw
         QnMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=a4K1IpKVLF4WAtyJVS2L0lDCOIaOkxGj9ykUaNOET8o=;
        b=bsKRhy1Ij3SwCT2aSuWClGigqDkumcXr8WgtpS9gi3QoIvPDBcdl/zsoIRy9KftzEi
         06S1hiSF3hFWN66F7vPaB2ObWQjP3KuYw15lbSjC6wlKNr1rmr5O2wpGzLjdGX6UNZ41
         w/wslJgoup5YKtY/S54zwy3fzsLj27CAv3d5G6zI/Cf09EKgFmjoI9oeW0/nEWag7KY5
         Jx0r49fh47efX6qzpHu4xxwMxzq0Y0ySyFnOAVs849nFWWvh4ujAPErR7VUNO+iCJIkG
         B/bOwKFvvcxAUdxltJTJOOP31Oa4c3QR/wXQq+vS+VbrE8jLr/N5sfiTdE9DmDbGQdeB
         lhoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533x8c/Jgsod33AsMQvq44gVkPXHfTUMo6afdk4VzARgxFZIy+uj
	i8HKCDd/kTsCoQbPt3HoV8Y=
X-Google-Smtp-Source: ABdhPJxwJ0/nhvAQKnkRXie7f5lFYolwW3uKhs3FUlmLGvsaHjjnV/bs521uSDHYhjLY7I2c/IfYxg==
X-Received: by 2002:a17:90a:a485:: with SMTP id z5mr16283152pjp.160.1607343920141;
        Mon, 07 Dec 2020 04:25:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7583:: with SMTP id j3ls5104824pll.0.gmail; Mon, 07
 Dec 2020 04:25:19 -0800 (PST)
X-Received: by 2002:a17:902:6803:b029:d6:cf9d:2cfb with SMTP id h3-20020a1709026803b02900d6cf9d2cfbmr15762950plk.55.1607343919652;
        Mon, 07 Dec 2020 04:25:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607343919; cv=none;
        d=google.com; s=arc-20160816;
        b=N5MWQ3eNq0uRyZW/kFNNbpw66zby2W65+2vjBXfCYx5vQIXhkfgo7P6sxyBQAkpMCP
         DaZnpyYbB/dap3j90i+SpTRKFs2Z1O3ceSQEPzNQiODoUVhfMSEzHtLW+Bz7MnEUUKat
         Xq7542BwNrEwT9D/e9+ti+GiylQmCu5yWzLxu/QuFGcBgKc2CAWPCC1l2ici9Qz7vwhd
         l3N8JuyJqqsoFQlq8UDU9/4u6mLOw6WWuKk2YGGHX58QFDLIyRoh5XVrg0y+rtFtbPHv
         Kvge7JL6ESd2T4o8BVVPdmuoNBi3+upnB2Cn2yMIReexA2+sd1ztroUWEGHHc7VPjpme
         M1HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KMHvh9xDEViq9Wttdh76WcHcHftlsk/1mfEYbi1JYyE=;
        b=uXbU+Q9gIPomZKuxVx3CE1TgGpr03nB30huwnHWpDXCnYHmXX3mUgbzaNTXjqN/nQ7
         ep5ooNHe8P4JBBcEurp+A5phzxX/scgoxg2pu7T0Br3PT/+NxWTDnAPExByXY1CFHAKJ
         osgXrsZ0je3i4QodLfh653dF5vgkoB/d53Xy7Mqiw2yYsKAHH+77DhUP9H+MoUBY+fcv
         l9I0WVV4DS4jp20Vr6/XXsOoGDrkiE6e+KzDWBFbcvbPokaizlT9Jza1DfR3+/0+WSpF
         l2hQGMRIM0b0HFyNY6x4XCu9+osPgE52clSqP3X2+GEP4zyG9aGBp6orimknhhGXnrxG
         DwiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=k5IwLzqp;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id z14si717269pjr.3.2020.12.07.04.25.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 04:25:19 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kmFZt-0001Im-0n; Mon, 07 Dec 2020 12:25:17 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 01349305C1C;
	Mon,  7 Dec 2020 13:25:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id E3EFE20299B5F; Mon,  7 Dec 2020 13:25:13 +0100 (CET)
Date: Mon, 7 Dec 2020 13:25:13 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Frederic Weisbecker <frederic@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: Re: timers: Move clearing of base::timer_running under base::lock
Message-ID: <20201207122513.GT3021@hirez.programming.kicks-ass.net>
References: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
 <20201207011013.GB113660@lothringen>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201207011013.GB113660@lothringen>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=k5IwLzqp;
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

On Mon, Dec 07, 2020 at 02:10:13AM +0100, Frederic Weisbecker wrote:
> On Sun, Dec 06, 2020 at 10:40:07PM +0100, Thomas Gleixner wrote:
> > syzbot reported KCSAN data races vs. timer_base::timer_running being set to
> > NULL without holding base::lock in expire_timers().
> > 
> > This looks innocent and most reads are clearly not problematic but for a
> > non-RT kernel it's completely irrelevant whether the store happens before
> > or after taking the lock. For an RT kernel moving the store under the lock
> > requires an extra unlock/lock pair in the case that there is a waiter for
> > the timer. But that's not the end of the world and definitely not worth the
> > trouble of adding boatloads of comments and annotations to the code. Famous
> > last words...
> 
> There is another thing I noticed lately wrt. del_timer_sync() VS timer execution:

> Here if the timer has previously executed on CPU 1 and then CPU 0 sees base->running_timer == NULL,
> it will return, assuming the timer has completed. But there is nothing to enforce the fact that x
> will be equal to 1. Enforcing that is a behaviour I would expect in this case since this is a kind
> of "wait for completion" function. But perhaps it doesn't apply here, in fact I have no idea...
> 
> But if we recognize that as an issue, we would need a mirroring load_acquire()/store_release() on
> base->running_timer.

Yeah, I think you're right. del_timer_sync() explicitly states it waits
for completion of the handler, so it isn't weird to then also expect to
be able to observe the results of the handler.

Thomas' patch fixes this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207122513.GT3021%40hirez.programming.kicks-ass.net.
