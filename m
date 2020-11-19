Return-Path: <kasan-dev+bncBAABBEWK3P6QKGQEQPQAPBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id E0F042B9CFE
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 22:35:15 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id v50sf1932802otb.15
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 13:35:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605821714; cv=pass;
        d=google.com; s=arc-20160816;
        b=PpeADJRmksidy3GGY49q7liW8+s1E4aM1+C9tUzZiWwaVS2L4kWCEVqBEDzXwOhl6w
         TVtZNk6H7VkYQmoI3esrMrmXMjejtw5NRVI1b7NJxE8LKvr3H2cAYhTL4qnQTRqO2ZJm
         IX9bwJSWa1+aKf1kwEFMEVLkubvVhdgIA5enVisZwXengKIyZK7erQz/TZY47mlejWve
         oZPeb1SydyYC+ys0SirrtyBkT/WFURFNaY7cj51mk0p+dsn3ZlkQOmiPPQDm/JTsyPwZ
         bIUG5dle2d7KwI46/XTI0pQFIbn0Lp7raHtDg7NQq90rfnJzqeFgyQIJoIB0U/oVM1vy
         xlCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=+9MHpb/btRk6Bg53hPiXhy6Gdz8WVUzWzFkODBiiqik=;
        b=E1YBKYybHlABvmDX361TBPcZRg4/+hrpgaA7aWfl3/3/jukU5hTcTlGB7JlPjaKtrZ
         QGEkQi8N9ZC1cu0J/84/PvYQX4LrGcwCpSvLErjKxO1htwPVBNkmt5Ne5SKaMitpXMV2
         IQURcdiMKjqPtQWWHv1joPF35cZmK0SHdeLoqWxhDl2Uw5XBKk9/PFtI4bIg0t/KxvDz
         hvkvyz4yOb1xJwsxXjV9Api4wcejSRG1Th/igc+s6WoF58DxABgR4j0VHLQYGUcwApxG
         p1IqIAenYcws1Z+D15G1ZUcRbV9bOyXf4T5K3HUWkaqiB5jUFRHK5McRIvBWVDAy553v
         48Sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="FjzSuS/v";
       spf=pass (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8Ov6=EZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+9MHpb/btRk6Bg53hPiXhy6Gdz8WVUzWzFkODBiiqik=;
        b=bZjmmIshlDwh5/iS1Z6W/8RwR8I4NyC15hZ3gr8BhypGlfOvJKWlOaaqh5vJZlAUQs
         5Fzj3+9JfRR09nxFKc1wijTvxIGBLXrsLfjjDGcNUaM3CRfDQ1nG7CR0pwYc36DERRo6
         H/K0OZlQX9yIMbZQvp4zlQik/IADvaHIYrwq4tEMxC3oLhAgfmftA9T3RF12qoSsD7FH
         b9KWc2Idzq852ysa8sqmWeAJyX5LdQ8JtQMy9B/Y6nIyyzK/lzYEVcBDgYZz0zA8FaLd
         dFB4Qt4vzrSmTNUdKBvz+1YqDiujBpPXWfXVEWMnq+gM6jkUr14pFK6wghNmRZY05E38
         RNMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+9MHpb/btRk6Bg53hPiXhy6Gdz8WVUzWzFkODBiiqik=;
        b=gFPGmc7K/0PmxGWKBA5pNgd8IvIcLkuKESmNrqqWlEKUkXQRiK88oWplTkc+paN2ug
         wDm0bpcLP0+FYZ9N1aow7YDSYCfU3Lqx5H9WsD1uxC7Y2hIPQ9EztjeWy4GCyn8ScFun
         CkK2aP4KIpGSojZjQvNIAhgEgHttCZgx81sDf23tvYqaJ95xEumrbGlC4AUuo9WWpxzj
         her1P8nsPWDL2crwtkSKcqbISJJvXSJF9mC1byUtT/wF6zuv4kE0TYY18WaH1eONbVpR
         UuLzB3NOBRHB57pDzV3yHhZrzG6FryFJPfsabo5YHitkSyCz9HE3k3z3GtCOxyZ1r0ii
         N+QQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533aMhHTFD3mL76oWQRAMqNQtH1Zp0+pJNl+ev+qgVvxJ9rYURYt
	Sp0flQQc0IUDVo5uFlDciBA=
X-Google-Smtp-Source: ABdhPJzRyY8CFMTQH0Qzd6OFfF4zi+KeJ9XIEtcvCOtM3mfKEn+AnUYu1vCaGKWCg4v1tlp+aRCDUQ==
X-Received: by 2002:a9d:6b98:: with SMTP id b24mr11632023otq.46.1605821714566;
        Thu, 19 Nov 2020 13:35:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4fd0:: with SMTP id d199ls1064164oib.5.gmail; Thu, 19
 Nov 2020 13:35:14 -0800 (PST)
X-Received: by 2002:aca:52d5:: with SMTP id g204mr4439685oib.91.1605821713969;
        Thu, 19 Nov 2020 13:35:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605821713; cv=none;
        d=google.com; s=arc-20160816;
        b=p8iZMZSOgVTWpnpL1QxBGeZjx81xJAZrL84KrvqZHIl9WdrdhA9Lmk0OStqSrg9gjF
         k6Xrqrzg7vygVfQ2bTpDwFPzui3agFg/ra+DuRym4wgbOrGIxuQEkXzbVmF/T7nmU7G0
         KHkThyLDXpT0Q+AAYG0ybYG7wBAyoD32sVKdito6bt8my0qEYaZROlCQHXPrtUxuCn8c
         insKKHxQQHolZFSFGyPwAptgUVJSWKgbLSs6RN3+T+++Rzdk6XSdC36yA6oLMFPA+al5
         yZqnYtGLqxImXNr9c/r5uqiuSHpnDtCHLxHVXHo0MpnXHeIKKK+G2Q7WoySmoDPMfRt8
         //tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Lts6D61qcD81EoXKyIuB/di8I9f+6BnxhHNlIezApr4=;
        b=bbkG+nI3oOcQLU1hRh0VjrblLiGggTPODyGNNY6oz2hYW1vwu0O8dl2MNIc+m/CEtH
         QOmsc+ONkfScozrmRDIwnBZDTyyea89vudR1ENetA76bXg3ghgyVbvLGnBpQHs+KEzBX
         H6BnGN/6UMmgOQYeeVZlUskVJModHy7c4xT+8ItBxw6F6BoWztLLVvo6bzQImLQtb26D
         TI4Mv637j63cXBxbkl920+STzXakrN1KPfkZlYC5/1Qg1Ltc0uPmem2Jj8dZh2YNGw9k
         YHDVQg6YKaQ9L254roODC8WUz2/xfUXSe2eCY6QwLp/Oa4OrkfxwUTTgtmebNJUkvbcD
         mqNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="FjzSuS/v";
       spf=pass (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8Ov6=EZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i23si100374oto.5.2020.11.19.13.35.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Nov 2020 13:35:13 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CC7352222A;
	Thu, 19 Nov 2020 21:35:12 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 75FDB35225D3; Thu, 19 Nov 2020 13:35:12 -0800 (PST)
Date: Thu, 19 Nov 2020 13:35:12 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>,
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
Message-ID: <20201119213512.GB1437@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201113175754.GA6273@paulmck-ThinkPad-P72>
 <20201117105236.GA1964407@elver.google.com>
 <20201117182915.GM1437@paulmck-ThinkPad-P72>
 <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201119193819.GA2601289@elver.google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="FjzSuS/v";       spf=pass
 (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8Ov6=EZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Nov 19, 2020 at 08:38:19PM +0100, Marco Elver wrote:
> On Thu, Nov 19, 2020 at 10:48AM -0800, Paul E. McKenney wrote:
> > On Thu, Nov 19, 2020 at 06:02:59PM +0100, Marco Elver wrote:

[ . . . ]

> > > I can try bisection again, or reverting some commits that might be
> > > suspicious? But we'd need some selection of suspicious commits.
> > 
> > The report claims that one of the rcu_node ->lock fields is held
> > with interrupts enabled, which would indeed be bad.  Except that all
> > of the stack traces that it shows have these locks held within the
> > scheduling-clock interrupt handler.  Now with the "rcu: Don't invoke
> > try_invoke_on_locked_down_task() with irqs disabled" but without the
> > "sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled"
> > commit, I understand why.  With both, I don't see how this happens.
> 
> I'm at a loss, but happy to keep bisecting and trying patches. I'm also
> considering:
> 
> 	Is it the compiler? Probably not, I tried 2 versions of GCC.
> 
> 	Can we trust lockdep to precisely know IRQ state? I know there's
> 	been some recent work around this, but hopefully we're not
> 	affected here?
> 
> 	Is QEMU buggy?
> 
> > At this point, I am reduced to adding lockdep_assert_irqs_disabled()
> > calls at various points in that code, as shown in the patch below.
> > 
> > At this point, I would guess that your first priority would be the
> > initial bug rather than this following issue, but you never know, this
> > might well help diagnose the initial bug.
> 
> I don't mind either way. I'm worried deadlocking the whole system might
> be worse.

Here is another set of lockdep_assert_irqs_disabled() calls on the
off-chance that they actually find something.

							Thanx, Paul

------------------------------------------------------------------------

commit bcca5277df3f24db15e15ccc8b05ecf346d05169
Author: Paul E. McKenney <paulmck@kernel.org>
Date:   Thu Nov 19 13:30:33 2020 -0800

    rcu: Add lockdep_assert_irqs_disabled() to raw_spin_unlock_rcu_node() macros
    
    This commit adds a lockdep_assert_irqs_disabled() call to the
    helper macros that release the rcu_node structure's ->lock, namely
    to raw_spin_unlock_rcu_node(), raw_spin_unlock_irq_rcu_node() and
    raw_spin_unlock_irqrestore_rcu_node().  The point of this is to help track
    down a situation where lockdep appears to be insisting that interrupts
    are enabled while holding an rcu_node structure's ->lock.
    
    Link: https://lore.kernel.org/lkml/20201111133813.GA81547@elver.google.com/
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

diff --git a/kernel/rcu/rcu.h b/kernel/rcu/rcu.h
index 59ef1ae..bf0827d 100644
--- a/kernel/rcu/rcu.h
+++ b/kernel/rcu/rcu.h
@@ -378,7 +378,11 @@ do {									\
 	smp_mb__after_unlock_lock();					\
 } while (0)
 
-#define raw_spin_unlock_rcu_node(p) raw_spin_unlock(&ACCESS_PRIVATE(p, lock))
+#define raw_spin_unlock_rcu_node(p)					\
+do {									\
+	lockdep_assert_irqs_disabled();					\
+	raw_spin_unlock(&ACCESS_PRIVATE(p, lock));			\
+} while (0)
 
 #define raw_spin_lock_irq_rcu_node(p)					\
 do {									\
@@ -387,7 +391,10 @@ do {									\
 } while (0)
 
 #define raw_spin_unlock_irq_rcu_node(p)					\
-	raw_spin_unlock_irq(&ACCESS_PRIVATE(p, lock))
+do {									\
+	lockdep_assert_irqs_disabled();					\
+	raw_spin_unlock_irq(&ACCESS_PRIVATE(p, lock));			\
+} while (0)
 
 #define raw_spin_lock_irqsave_rcu_node(p, flags)			\
 do {									\
@@ -396,7 +403,10 @@ do {									\
 } while (0)
 
 #define raw_spin_unlock_irqrestore_rcu_node(p, flags)			\
-	raw_spin_unlock_irqrestore(&ACCESS_PRIVATE(p, lock), flags)
+do {									\
+	lockdep_assert_irqs_disabled();					\
+	raw_spin_unlock_irqrestore(&ACCESS_PRIVATE(p, lock), flags);	\
+} while (0)
 
 #define raw_spin_trylock_rcu_node(p)					\
 ({									\

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201119213512.GB1437%40paulmck-ThinkPad-P72.
