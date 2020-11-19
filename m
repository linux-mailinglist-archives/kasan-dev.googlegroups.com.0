Return-Path: <kasan-dev+bncBDAZZCVNSYPBBCPP3P6QKGQENIHTLPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1089F2B9DD8
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 23:54:02 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id r192sf3247073vkf.21
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 14:54:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605826441; cv=pass;
        d=google.com; s=arc-20160816;
        b=R8mWT6/D2F6n0DOmE6hiAPqPnzjzWrR6OAPGYvzbIHSESXuCaHLcRBFPRxvY7z1l+6
         0zXGGR5na9HEzXq0NLrJkKvMDXpULvOOoyLmDopwl5aMwgBEr88e2UfU3PY6pfd8RbZs
         Gh4sjla6SV2mxn+cewfmf2CtbrdVeih/XQqUUzKDrUYnNz5uIZ4AlA8Z0pxqzTd7W4SV
         ExpjNpFJnJJA+VMFw+gjbut0Cao9YaXtHqvtnvhhHmhtpGaAtQ2JmhyHiqFF5l9vX6jk
         UX/qbS2uVPvsxAEJHb5rXP/44nUol5OD+UkLirqcEa0aMN/OJGXRVjzWeQAtI7t28GGE
         8+og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gOQ+damjP2HdRxZutnmZYKWNB/vHcUKY+HfwsMffcX8=;
        b=lW/pqPE3Wqgul5X5txWg8cKhoWDFZnI52wx7ircdybS5pIPxSvksOyEoWj2ft6uzgW
         usVmAmos8cBxtgYBb8857ANrUtbRh1eWoGStjGHDAEXMRjjg+w455tlEiB7liscwHoAj
         4YsP2WXYt7fPNqiQ8lcv0yjp+d1vCZhZwyYLzKtX88dlH+cTYpuWHOQlPmxB5F0NQd5h
         CpyX6SCXeRoGUk1xvjD+ll1xnLusFslK/3LKuoi3DInR6yV8gTbG3C5G0l2bixf4QsyK
         ItWDxxjW1mUa63WzXpP6UZXch3gH3pdc1Iyd17SOWJRNEBVHyNaExd5KWLqffr1R14kx
         oZLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=kL3PAxbG;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gOQ+damjP2HdRxZutnmZYKWNB/vHcUKY+HfwsMffcX8=;
        b=Cl76RPAAjZhaK7W7A3BoHFk9MjU2xg/+ZkVwy8omfK5v2sFwrubC7ZYs24vRi3PefG
         G1G3Jik9aYvolprteLGCKrObYHNcHi0ec55Y/W8x8cPQwvbS/XnFegZra/miJ3cF5VKx
         +L5kZIulVbYyIGD9b4ZsX1fTIWPjqvvBL5WMdHKhVbRdTOMIceRMF54WDpSE1eCQ7qUf
         iJ3Mv58lYyYllVgSpUuBPMcMZ0qptFDpuP3q9eEWd8LhMe1StwWqvX/48K53cf4FPwAr
         u6D7FqvM7krGJnFICUiEi/dBfK5jkw8gDKIIqSxi8lDVxz8nC6cOYPFkjiNZ6xszw7VS
         kn3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gOQ+damjP2HdRxZutnmZYKWNB/vHcUKY+HfwsMffcX8=;
        b=QMfZL+Vu2g3bGJm0heMMhtQJGIKawB/7cDpF/DUX+HOmq7O4q7Jz92vG0z1RudEJ3N
         9atbQhIrUuRKFl6b5yw1snme80AWRx/WQjnIGWDTxRrjc69WOI9Hm4HgTaF3HglU3K1o
         OIxcp0CEDDlWSPYGSt00vR/QzCXJoeKAJrEM1Uwd/TQaVM6V3qWQLtJaeKqA2RvrtPw9
         0RTQZnankq+HxTMmrnm7juRG8qj8kJc6/vboFAbeHPMFZ9kAkslGMxpLxYthHlvocfyo
         NSJky1pckOVXDZHyoBcBe4dIHEstmaslrqogFg3SJKLYeFPqm2XFrpsZ+Kg9grQDgItR
         sZvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532UYhmUc+/mgYFYLNoOkHB3cr2RcdcF8MiF2peB7v/UuS76KVUs
	MFjVroVw9Q0XL5yQlqsnjx0=
X-Google-Smtp-Source: ABdhPJxbU6BcSxH4XxDE2YTtcZWNySqt98YAFfkWqRHp/fQWNRkaLI5A5Kk9/I+HSPwZtZIUl2OKUg==
X-Received: by 2002:a67:3251:: with SMTP id y78mr10231353vsy.36.1605826441104;
        Thu, 19 Nov 2020 14:54:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:3113:: with SMTP id e19ls434553ual.6.gmail; Thu, 19 Nov
 2020 14:54:00 -0800 (PST)
X-Received: by 2002:ab0:4145:: with SMTP id j63mr8927120uad.50.1605826440644;
        Thu, 19 Nov 2020 14:54:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605826440; cv=none;
        d=google.com; s=arc-20160816;
        b=MJXmYGaNbNMkF6/KCuGdQah/hTO/uOezBlK0hn55bgmAQQu7fedFGxanVzYAY+POWa
         CvYXB0iCGiVhX1VURmOsqV+laHGmWuGcpmfpyp7Sp0D6SKjSKhLTnWQ+Pl9tLE+LUASd
         5ElU2jTgLBvNPKfwJApfR1lSc2s8hZAcs5KOnGEUnTXVBKwrjgcQuOE/lL9IKWlZqR3h
         TFJvj/VfscSEFEkWE1BFzF9BUJpIU4lAQjN5GSkkJ8neYGVMURr4Op9Gzo7VneEgsMwc
         p1oUwHZBTeLzwqvWjjnmFPbjO9zFN7FpyV8M5svA8gujgUWBq7Cb+DsyN4fULmDXYONU
         cY2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xnJSpUmF1F6JqTF9douWsY8DshAOf+QcFr6Uvc58igE=;
        b=ab4wPcPLmab61W78QjyuM6xO7fO6PQraP2zheCZ5M6hqH4lWBj0JG+qYGsJsqO0te8
         +7DvoGycYN9QtsB1TXsQbE/ZMb5rAel9SzcNpq6RSP7F1f2fJWAFqUmn8j7pySbYPs5Y
         HjpSdMzc5nyM1GNDdNac7rAh7Yj2Cx3bVLHI1aSTd8kpHBzduq4+gHaXFJXSFBveEo4y
         jMFvR4HlVMZ5zTK1YS9wJF0cuWyKA6vvquz+tdgqHFPgiH7dcbqoFPeOeXoqVaPOQByo
         3ns+DsN0YBm+q5kGl4t3Sa0CNTILMic9NhqWAmWztlSftEVbmVPRH+Sk72npgV+PABeq
         hjHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=kL3PAxbG;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v18si69860uat.0.2020.11.19.14.54.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Nov 2020 14:54:00 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7B8022078D;
	Thu, 19 Nov 2020 22:53:56 +0000 (UTC)
Date: Thu, 19 Nov 2020 22:53:53 +0000
From: Will Deacon <will@kernel.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201119225352.GA5251@willie-the-truck>
References: <20201117105236.GA1964407@elver.google.com>
 <20201117182915.GM1437@paulmck-ThinkPad-P72>
 <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201119213512.GB1437@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=kL3PAxbG;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Nov 19, 2020 at 01:35:12PM -0800, Paul E. McKenney wrote:
> On Thu, Nov 19, 2020 at 08:38:19PM +0100, Marco Elver wrote:
> > On Thu, Nov 19, 2020 at 10:48AM -0800, Paul E. McKenney wrote:
> > > On Thu, Nov 19, 2020 at 06:02:59PM +0100, Marco Elver wrote:
> 
> [ . . . ]
> 
> > > > I can try bisection again, or reverting some commits that might be
> > > > suspicious? But we'd need some selection of suspicious commits.
> > > 
> > > The report claims that one of the rcu_node ->lock fields is held
> > > with interrupts enabled, which would indeed be bad.  Except that all
> > > of the stack traces that it shows have these locks held within the
> > > scheduling-clock interrupt handler.  Now with the "rcu: Don't invoke
> > > try_invoke_on_locked_down_task() with irqs disabled" but without the
> > > "sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled"
> > > commit, I understand why.  With both, I don't see how this happens.
> > 
> > I'm at a loss, but happy to keep bisecting and trying patches. I'm also
> > considering:
> > 
> > 	Is it the compiler? Probably not, I tried 2 versions of GCC.
> > 
> > 	Can we trust lockdep to precisely know IRQ state? I know there's
> > 	been some recent work around this, but hopefully we're not
> > 	affected here?
> > 
> > 	Is QEMU buggy?
> > 
> > > At this point, I am reduced to adding lockdep_assert_irqs_disabled()
> > > calls at various points in that code, as shown in the patch below.
> > > 
> > > At this point, I would guess that your first priority would be the
> > > initial bug rather than this following issue, but you never know, this
> > > might well help diagnose the initial bug.
> > 
> > I don't mind either way. I'm worried deadlocking the whole system might
> > be worse.
> 
> Here is another set of lockdep_assert_irqs_disabled() calls on the
> off-chance that they actually find something.

FWIW, arm64 is known broken wrt lockdep and irq tracing atm. Mark has been
looking at that and I think he is close to having something workable.

Mark -- is there anything Marco and Paul can try out?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201119225352.GA5251%40willie-the-truck.
