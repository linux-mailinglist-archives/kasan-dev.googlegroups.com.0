Return-Path: <kasan-dev+bncBCU73AEHRQBBBYUNY2LAMGQEOWO7QKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C5AB576465
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 17:25:23 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id b38-20020a2ebc26000000b0025d9fce1f19sf924639ljf.22
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 08:25:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657898722; cv=pass;
        d=google.com; s=arc-20160816;
        b=S6x15cvAbiAuXZb3C77QV/cK5Zj2pm2emarL7VJ7spk8iOwvJC21Ep+CL+r0z4rxGy
         47XyvQEiF5VvnKAezeVnR9vEQ7HZ3CyOdOJm+JjIHnJBgF4ArR7HXpRp/CPQRQKM7uJJ
         2ChwNBquvB/UkOGJlROPM/bXg/iCujDK9XPjqMOPuH63fMiY8sgq+284JzU0smVcgzq0
         ajYIQYHh1wCSLNnw7E8FWSLvX+rjLOpmRyfzuSwjnwm4KVgYOEFiXkIB2HAs+jrJffOT
         /6sm9S8m/gqmEvRBxfXj4oXxUCZps8bJlqk5ypOjEOfvoK+GcrJj59zv1XUwRf8uQAXa
         giDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=XwNmYjRRhNGNi+F9fIOBNCSTFFyJEtT0TtFGvbgIMAM=;
        b=kIjU4AFd1IRKRqK4JDuusDH0w9o4yk7rH37ieV38/2NsWHrfx675uKyu0+p5LgNk43
         bT5BYePGSAD7D1i7R5DFBczTIUHKeuHf0JYzLOG3cMCv2T/QZMwoCWTEpcdgCbJVor+l
         bPxG7urnJhe+wg5V1KhW139HqN4HCYWj94z5FPGsvoSBbGic94K8pXhuYapFhc87yYue
         5h5g+buI2PI6voSEfts4ds69oOHuV4XeIuyai0sjT7rosFyFZbdCi5cMnCe44Ugzv/I5
         Q36vXJZomn7TU/z82c1Ctn9mCIBnKPjgx1ZWphDHwcJQ9A3xQuO1S1OYNneLiu6R1A8p
         WyOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=n1ry=xu=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=n1Ry=XU=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XwNmYjRRhNGNi+F9fIOBNCSTFFyJEtT0TtFGvbgIMAM=;
        b=Akjdo6CmWnfDpL0yqK4JVnPbZSohDr5hJ6C8HG69YkBsxSMXh9Sz/lTZgW8fJLAmwo
         xywpD6h1yEztxZQodDoewImZVH6SWsTaMkf+Y6QqQwOwYl9mg3Dm5g+DiJiASuZk+sSW
         VkUlzo313Xo5fTDJe0YKrtJwv15a0TqrQruFYS8vg8iaB+fuvP7FhA3+rNWr9e+z8Zsy
         kCJnZZN6u3gH8RDHd7tgT9LOE9aeln2HdN14RmP3ulkok8ikaY79u7bBVqDS/hyahVW6
         5dMdJtHFZgE7DINc1j1EBQQueD1m/D4ax5v+dyiUsqvYMNjg4FoFp+2W8D/VegbeJfKE
         wUMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XwNmYjRRhNGNi+F9fIOBNCSTFFyJEtT0TtFGvbgIMAM=;
        b=KE35RWvqFXKVU1BA+gvh8BiWlRUZ7omsAFldhLumAXfhijl7LWNys23AR1GE9R3KWY
         /mVXa53MOpHqprGhgdNJ0qb/MMYqcyET8zLpbZmv6t+eESgaN1KveRK2lMHiwe4VZKMj
         uf5lxJArcPsKCyLSE4ArxhLzyJVlm+Hxg3o6Dyy6tOdCkNwll1luSp/zUXnHhYhOPgow
         EppxtWXntUXZAQa2Wh0eSQy3Hy835DNx726wBmJnCrBkYYw5+XfyydZR6+UTBhL/4GYy
         EG/4UmYaMqh9a/vdcGhqoEUjy97azEarY11ZbEUbRnKFlCBpB6Yaag6LXsEeE5hjNNXv
         xMWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+iTB9xU1IGesMPJ+SbUwt+NUjGdBnNx8HH5ea2fmE2pGWizkvj
	M/bbtZQiOYRobrUO+BqmA8o=
X-Google-Smtp-Source: AGRyM1u6xUokYwxhkqI8kLlgioxE8587vaJLsEQpGXL0xtYdXhqMG4aRIlqQxqvC3n1rAjsB1O10ug==
X-Received: by 2002:a2e:bd13:0:b0:246:1ff8:6da1 with SMTP id n19-20020a2ebd13000000b002461ff86da1mr7237871ljq.219.1657898722382;
        Fri, 15 Jul 2022 08:25:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ac:b0:488:e12b:17e9 with SMTP id
 v12-20020a05651203ac00b00488e12b17e9ls1396378lfp.2.gmail; Fri, 15 Jul 2022
 08:25:21 -0700 (PDT)
X-Received: by 2002:ac2:4d5c:0:b0:48a:4ac:d0e4 with SMTP id 28-20020ac24d5c000000b0048a04acd0e4mr8663286lfp.519.1657898721146;
        Fri, 15 Jul 2022 08:25:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657898721; cv=none;
        d=google.com; s=arc-20160816;
        b=ypRJtJONJ5pKmWgr9rqkA51Rny5M7enDb3F48kjwh6ov00druUMjIjLqjBL87AQWJQ
         Hb2siYd3Zw2YpZDQuUaeh3e33TflibmR2rKXKl9UczbwJ8bhmqL8QvoUFQBnWkd8Iu4F
         UhYxy+j+WNgsUdjmuYfnFlc/cK7O9NnSWxRAK2UzrKHjrYJzOEI8xJiARlSJHv7l1yfv
         A20LKnR8w3gSQYn5uLXUeDoLMdjhs9s6mC9SCnX8wS+0VZmuOwMKrxUsNVqcE2mEToDE
         MI2mICyQD5D3CdgvuztqJ0bXy1JKT8RuhfXnwGtyohcItDddF4D1JAwBI8rJdtdXUwPA
         LYcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=SgCDOtz+9DrHrspwF07fqUW0yuIDh3KynaPo2QKvgPs=;
        b=HWONcs7H+1k7UzFvZr4U8ZF3KImHZqsIOz0s/O5qxfcCUgzixuXOSypJxPNOt/pnIQ
         RqnC8uUw7OZfhJbE4GUb1aNm87LtTyU1eCGYmbSUox/soARJVhIX2fsJ4/FjyEaoZIVj
         nzB5kT9ChUYdSww3iYyXOtW5299Zy+xVeJnDmdkAzqAinFuSHSBK+SN7zZUjTkTs+JKT
         fu8k7yfH27QP0GpWukk/IfaRjfdcQQKIBaTILk/B2RmxdQ/NSMYTrQgrH0/XvJggE2mL
         ggxhx6D0xFxvhGV72rqwiDmYZG4UEspxUIGoDcRzH7eM4wjJ5+upjecSYMHG72Elb6wZ
         ul4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=n1ry=xu=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=n1Ry=XU=goodmis.org=rostedt@kernel.org"
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id w8-20020a05651234c800b004830f9faad9si142982lfr.1.2022.07.15.08.25.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jul 2022 08:25:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=n1ry=xu=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 6618BB82B41;
	Fri, 15 Jul 2022 15:25:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A6BF6C34115;
	Fri, 15 Jul 2022 15:25:17 +0000 (UTC)
Date: Fri, 15 Jul 2022 11:25:16 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, Petr Mladek <pmladek@suse.com>, John
 Ogness <john.ogness@linutronix.de>, Sergey Senozhatsky
 <senozhatsky@chromium.org>, kasan-dev@googlegroups.com, Thomas Gleixner
 <tglx@linutronix.de>, Johannes Berg <johannes.berg@intel.com>, Alexander
 Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Naresh
 Kamboju <naresh.kamboju@linaro.org>, Peter Zijlstra <peterz@infradead.org>,
 Linux Kernel Functional Testing <lkft@linaro.org>,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH] printk: Make console tracepoint safe in NMI() context
Message-ID: <20220715112516.58e9e5f8@gandalf.local.home>
In-Reply-To: <20220715151000.GY1790663@paulmck-ThinkPad-P17-Gen-1>
References: <20220715120152.17760-1-pmladek@suse.com>
	<CANpmjNOHY1GC_Fab4T6J06vqW0vRf=4jQR0dG0MJoFOPpKzcUA@mail.gmail.com>
	<20220715095156.12a3a0e3@gandalf.local.home>
	<20220715151000.GY1790663@paulmck-ThinkPad-P17-Gen-1>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=n1ry=xu=goodmis.org=rostedt@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=n1Ry=XU=goodmis.org=rostedt@kernel.org"
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

On Fri, 15 Jul 2022 08:10:00 -0700
"Paul E. McKenney" <paulmck@kernel.org> wrote:

> So if preemption is enabled at that point in tracing, you really want
> to be using rcu_is_watching().

And yes, at that point in tracing, preemption is still enabled if the
tracepoint was called with preemption enabled.

Thus, we really need to convert that to rcu_is_watching().

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220715112516.58e9e5f8%40gandalf.local.home.
