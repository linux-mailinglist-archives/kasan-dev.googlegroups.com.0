Return-Path: <kasan-dev+bncBC65ZG75XIPRB35RUC7AMGQE765TBKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D5A5EA4F9F0
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Mar 2025 10:27:13 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-43947979ce8sf25893155e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Mar 2025 01:27:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741166833; cv=pass;
        d=google.com; s=arc-20240605;
        b=DrYCk3DSx+V0yMZf5hVPdWF8Tg1ohXktp//6SJIIbidue8IO6yj9T0T2hDMvLyPMPH
         fmpeqob2ubMJdDt8YXGvNG2Bsv1FpYhJy9ob4ga2BQR9gCtYPbBsGFIhox7l4KPO1tu8
         cj1MRRDZJBQHTPvKCDemvdT6dX3bL+4yd98w+h108VLoZBcV8lI/9bOlQPnMLnfYFY1t
         aTNCh7R71bhHXDNvj2GP8D/BVG5x1nRutsTFeQXoV0ydu2m0EpF14zN8aoGV2oczlGS0
         kGZ1d4elnUczEJF0KaafhVsIVK6VvHeOR40x1dWaZLMyqNKTudIIJbouhBsipy/sSYsC
         Q0/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=AGhdHDX6pW59mX1zOICpLWGnyGQwmL5i27p0SMwV06Q=;
        fh=1Lxl7yy4F0+7B7SPdc6d8+5dm7p50hUKE6yza2oTFvQ=;
        b=Fd9PG7wlYqYPxiIaIILfn2FuT0OuhsgweQoLoRWqNQalX9ZR1dZuxABlsCrHN4dLMz
         Fr2XK9gUrcMNkZPrVXJwMSRqrjP8xcc0eQP9S2UPrPQlGsaVPaWD3Qm9KgzqxKRPiXjm
         zLCulyy9298B63vYWUMC2HnA5Z8c4SllS4+Zdj/7KLRZ2I/bTUBj9WKSt+Nu0egZUns2
         cydhnHQ123llDaHEPcauumV015zg6ux7TLVBk4dR5WRJ+gI8YMXWdU6q4mel7PMZRqeR
         MPvevFQBAQs0isp2VqTdQLfwid0d5+i9Xd8JQ+TFQWMFETRA27o34r5aV09yHRjRqgTg
         jXBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=uspUaXJG;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741166833; x=1741771633; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AGhdHDX6pW59mX1zOICpLWGnyGQwmL5i27p0SMwV06Q=;
        b=KvXP4hO+X/wOqTMaNAmvJtr28QbyQiQRp4M+HqChDG/EBdjsP5oQOL4fTq0z9d/IGf
         jq0jaq+WyN6x31EmaOwFPZ7WcgkYSiN1BToTcy8CslRKPkLyXEpzvyIhoW/Edi4qsWkS
         PL/9MKU+sVmejtiRS1gBdFELS1qcHOuV5WHOO6Qvoba7c7Rvjvxt6vxKxjg+Hwj/ZPta
         TAYxDv6G9xXQ0QBkAncNPUTyZSsFhGNo/AbkTAeaVCu1o/9C6F2/JzOawQV6/oVrvdqV
         JBSmqMl1alMjIrB71SgJZ95uMSTRBXZEVNkDSC0KPqUqglZ9CA13BXtENtnfWVMNfalF
         GBrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741166833; x=1741771633;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AGhdHDX6pW59mX1zOICpLWGnyGQwmL5i27p0SMwV06Q=;
        b=oGnyemndlPwtim2eSeltHaXCbH64ew04A/AJbXVXWKHT+ScpQ8qdjYygFwnYHhgZ24
         UqWMkHe4TBSTnuU65zwfSC9/U9hbXREneXuoUMXnnBUmgHc9bTStBO2/dTNSNdvzdudM
         p3JRcChBpHmd6CCaZFts0FRQgc4Jtp8joawBLyJqC0Slg0FBsD4s4TvOAU6WqUOPteBc
         CX8b88c3H80JXOdlXXuQJw4h0J8seQxQrY/mCa438pQK4ocbwoz5+EzZo43NmBjcWq5W
         wuh0aPZNX+hOkTz5Fzgh7VPocHUL2imNM7VRABO0gpBXEIXOgb/cf3bAoFa6hNOgC90j
         WlZg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnaHhVEs8uthaiLxtu66y2e/axVNOv3M9JQ4/nwtzKXgFay7Bw/a7XbuQaQZTI0CQSTXuXtQ==@lfdr.de
X-Gm-Message-State: AOJu0YxYtkkZ3imIxqIvWk+j1aNDOqOxW8ANdkVMwZSITKvQS1KAo9BB
	2mUkWuFmufn1x1Ch7Cu/nnCXadm197u+lRnkpqLIG6dovTC7AA6W
X-Google-Smtp-Source: AGHT+IEbv+DzqFkxbKhPqcX/xu9GuRL7nE08k3gLfjXPatfxYcszagT7Bc6ZuujMPHT8XThXK/zjhg==
X-Received: by 2002:a05:600c:1c9d:b0:439:955d:7adb with SMTP id 5b1f17b1804b1-43bd29daf14mr17276815e9.30.1741166831976;
        Wed, 05 Mar 2025 01:27:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEwfF9fOP4sq6O3QXUDLDsxVZleys+HEkxEex1e1t2G5g==
Received: by 2002:a05:600c:3d0a:b0:43b:c596:e809 with SMTP id
 5b1f17b1804b1-43bc596ec8dls12055405e9.1.-pod-prod-01-eu; Wed, 05 Mar 2025
 01:27:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVKzJJEb4YED738NsJp0qjNf++BfVibGIELz+wFCIqekylBqzXaF2SZX04aJQGAReaM73Bf57thwUE=@googlegroups.com
X-Received: by 2002:a05:600c:4f87:b0:439:9d75:9e7d with SMTP id 5b1f17b1804b1-43bd29c4593mr12514765e9.22.1741166829632;
        Wed, 05 Mar 2025 01:27:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741166829; cv=none;
        d=google.com; s=arc-20240605;
        b=C1m4nK28PC0bkj798CJxSU9NuK/+YKngdeAVYipry1g7ljk8oP4lfexG9f7G7rBxtW
         XlhOHhcl/JdJ7mW4x4c/JmPTaB8B8bUkdMVQlwXQk+w3n388ysjRP8ThzN4BcDR3Tutu
         5hd+6Cvbq5PryIgklcCR3JDqCPRXYlkUzNdXne5vpEIcMkJgKaXC00Qg5cJnSbAEvMk7
         HkPOlcqHbCXeI63J2TuyfLrL8N2rMuyQLYThEkCowNGbPQh2JFQdErZnrTb/T5AKAis1
         WSgTu1GJQy1vas8q11idxlMGoJ7gFTGpH4fBuIuSSdCvQklzpmbzrBaCbxFMQiCq+Vo9
         DJFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=VaMa3tOr/8WS8V6AnlLw/eUNgZqrJVmxSDme9KtSQnA=;
        fh=vEp/8wYNzCLq3NuaCwzDTIKuDEf+OphgBVNplS773dA=;
        b=SCD9JyD9ts5zWvbH2G50hIwcNBFIv0FXTxB5VdToTDnyXu93apZk87ycvy/ZsXgOtY
         iR11bFQcVUUyCDq4hwm5XvfSUO74t1iS23/8Q1wp/S7uwsVS1/V0F1uTM5tSfcb6bwdB
         V/lLjmuy/CtkFOSjoGh8jXdZwzJLbprEeSqm3LHgDPUqcok8nUk7NN0GT7gw8/sxuAEF
         yRvmXnB5t82HUmZMdjr2naO02Kel2KVo7GTNcDMVNxPCOvEtdMPkg55mw8VhqeBRMjkx
         5a46+T1LgkXk4OmrhHNwtJnH7PgwAAsgEyNC+xGSr73R8EIzT3O2o8swTKQJ3DR7T4HM
         27Gw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=uspUaXJG;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e4798e1csi468833f8f.2.2025.03.05.01.27.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Mar 2025 01:27:09 -0800 (PST)
Received-SPF: pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-4393dc02b78so42535275e9.3
        for <kasan-dev@googlegroups.com>; Wed, 05 Mar 2025 01:27:09 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXSZTLFmTBcel1+wmF/f52+7Og87tuAySqRZC/okNIE4K/tw3jyby5iOEvsuNRmKa9eb5fADOzLbis=@googlegroups.com
X-Gm-Gg: ASbGncvX0h9OJRCZ1TLJFlTQNLxoXm5ipKXdXxGoUEjcVBQrRF/NsYx+76TJ3avvYH1
	eihkBHIztMHKMBlkSYCYFpy/lVybq27xlqMsUc4rEshdgJKpSHfWxvKxkI/Two6+8IBF6A8fW+T
	8OHcOmAGxMqJ/W2bky5LTCBAiyloPULrySw/gXucUaVwdTFnGwuQr7cxYkbqCDGjhMLvG+ZmeI+
	RDQCHlrq+iXRz48qn1m/3jARdVa1AoZPsJ5UHyCCX/NIFaBs+4ymqUWWas7PYwkLzo+NAZ2CkQi
	NE/EwMtU65Imtg+xSiQyC4Jzo5pk5AubL8+n8AcA1Vn8ZEgEdw==
X-Received: by 2002:a05:600c:4750:b0:439:9e8b:228e with SMTP id 5b1f17b1804b1-43bd29c42c8mr13412085e9.20.1741166829098;
        Wed, 05 Mar 2025 01:27:09 -0800 (PST)
Received: from localhost ([196.207.164.177])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-43bd426d069sm11942015e9.3.2025.03.05.01.27.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Mar 2025 01:27:08 -0800 (PST)
Date: Wed, 5 Mar 2025 12:27:04 +0300
From: Dan Carpenter <dan.carpenter@linaro.org>
To: Marco Elver <elver@google.com>
Cc: "David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Jiri Slaby <jirislaby@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-serial@vger.kernel.org
Subject: Re: [PATCH v2 01/34] compiler_types: Move lock checking attributes
 to compiler-capability-analysis.h
Message-ID: <b6af185f-0109-4f98-a2d7-ab8f716e21a5@stanley.mountain>
References: <20250304092417.2873893-1-elver@google.com>
 <20250304092417.2873893-2-elver@google.com>
 <f76a48fe-09da-41e0-be2e-e7f1b939b7e3@stanley.mountain>
 <Z8gVyLIU71Fg1QWK@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Z8gVyLIU71Fg1QWK@elver.google.com>
X-Original-Sender: dan.carpenter@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=uspUaXJG;       spf=pass
 (google.com: domain of dan.carpenter@linaro.org designates
 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
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

On Wed, Mar 05, 2025 at 10:13:44AM +0100, Marco Elver wrote:
> On Wed, Mar 05, 2025 at 11:36AM +0300, Dan Carpenter wrote:
> > On Tue, Mar 04, 2025 at 10:21:00AM +0100, Marco Elver wrote:
> > > +#ifndef _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
> > > +#define _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
> > > +
> > > +#ifdef __CHECKER__
> > > +
> > > +/* Sparse context/lock checking support. */
> > > +# define __must_hold(x)		__attribute__((context(x,1,1)))
> > > +# define __acquires(x)		__attribute__((context(x,0,1)))
> > > +# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
> > > +# define __releases(x)		__attribute__((context(x,1,0)))
> > > +# define __acquire(x)		__context__(x,1)
> > > +# define __release(x)		__context__(x,-1)
> > > +# define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
> > > +
> > 
> > The other thing you might want to annotate is ww_mutex_destroy().
> 
> We can add an annotation to check the lock is not held:
> 

Sorry, my email was bad.

I haven't actually tried your patch at all.  I have locking check in
Smatch so I'm just basing this on the things that I did...
https://github.com/error27/smatch/blob/master/smatch_locking.c
This isn't a mandatory thing.  Whatever happens we're going to end up
doing dozens of patches all over the kernel later.

I thought you could destroy a mutex regardless or whether it was held
or not.  I was getting false positives which said that we should drop
the lock on error but actually the mutex is destroyed on that path so it
doesn't matter.

regards,
dan carpenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b6af185f-0109-4f98-a2d7-ab8f716e21a5%40stanley.mountain.
