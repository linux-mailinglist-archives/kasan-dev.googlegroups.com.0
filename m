Return-Path: <kasan-dev+bncBAABBZH77TYAKGQEQPUZZ4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D50F13C9AA
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:37:57 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id n24sf1442932vsr.12
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 08:37:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579106276; cv=pass;
        d=google.com; s=arc-20160816;
        b=keLZ7v6tkkx7jGVW4meEp+/2+j/7aDRsB0bz+uNeIilI7vZjKJhmtpk7+0fscOhMWV
         amDWOn4HRYxtfOYDI9n5idPk7rZx+r4ggvKOVOIMur+qBXzCXlAz2ndDZL22MuFvcFAn
         /JfqAtWpWF3H0PYkFrudNpdysQYGoReso4yr7g4WtpHwVWNWw4I8557kgV+ZJ6Nqw9j0
         VMvDTm9edpWDT9ghfaydyhq44Wr+2Xsl5W2koDkm0lw8NDJp3apLVRz2vffR2x/bTjnJ
         OvlbhcTtt7koqXmZlOLovaRX8qW3xanJsFVku/8d6m4KA5II6k+ZucLLdpLfXjl/UU5j
         3EfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=VklteaeOKOL2xfP2fosNWO8xyrDM1mFJhulwslYyHck=;
        b=viUhBkiN028lQDywlhJuIvGhmoKSn8afR+VSY8e4cO68t1iNQ9rVtt1RWcqNnziKiD
         8KHdG6hj/phMxEYd5bOJpBcUIYM16wRL4Pc7ttQXROlwAJ8jQr6au/6MrmMleg/CgPTE
         J9sSE8mHPKVbJkNlwd7XRaYDVsHc73e8gndjbanHntsjJHosbVTKxGLp6itPo/f2VUrM
         2wP0nqftzYaCx4ILLZBN62Fd39KfN7xOdDUx0tRp9oRKPURuXnP0KnIlslBU+ehwfNsD
         6djKJGRLpHbOXsUsUgOqhtVKMVhSicEl/qc6/XwaDzkVLdPkKk7Y1ZoR64Kc+NGVcbSw
         uAuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=otOeJmqz;
       spf=pass (google.com: domain of srs0=xt/d=3e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xT/D=3E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VklteaeOKOL2xfP2fosNWO8xyrDM1mFJhulwslYyHck=;
        b=nvuxEHyCTaJ8AK/bmET5uLvMOIFB1PHbOACej77p3uwmwBsIMkYgzbshWUaW+zbaUc
         znE7BN9UQE+jvv9ikamDQrLcEKU5AZcTOKxn2cUmNI2GIoGASyhZ2CilSHT4qzwhn1Ck
         k86LEaL127Mig1/ICgtekA8TgM6WTdxhOQmFzmmqhj3prET/xle4PeWmjo+j5PEj81JO
         f9DXh33y6zQvcFVq04AA+KkF3KOgeA8J+iwlOqQ+H2ykSs5NhoR081JZJvijlnIWWOim
         xICIGf9pGLHyJ9y1/oicVkcP/VCEhjnXNLnQva4F5gdv+qS1Jy4HC4VaZs5Ap/x8q+m1
         gIhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VklteaeOKOL2xfP2fosNWO8xyrDM1mFJhulwslYyHck=;
        b=LQGb+v1BmBnYknYySogvZdweEa5vJgrA/qRhJ3ZEW2eiKdHqhmelEVhpT6LF+IMEMv
         FUK69ei0JKkbksoxE81fUK3LZbkRjTkQKGEJzvVK/UOaJ1sSrvVx+mvfXUhX81dw1PpL
         wsFU3qmm4+Hj08eT6cLHxiMjJ4SdnqRhc43KJHj7uhxsAsQGW15peSLiIogmkAQZ4Yr1
         aqrbU9koSCOeFEMtquZ2Le3ntWcb+JXL0RH2HhFmD8CErtA2Z7tbWytvEtWlR6vXOzzB
         3Gf7PrAKh3xSTS17susbQEnwmN+kpEPQhbPu/cWinuLkhSQ3PJGnFYbEJu3DNC8O+Otp
         uXFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUPXfG+eQiqoEvG5u4JziWwIhc7Rkz09Ax5qcmc10NCmYbP2WxV
	PFlBkeFuu1CsJhl3C+BUl1M=
X-Google-Smtp-Source: APXvYqz+Utxoz6lGlba2L57plTPzvHAbSMmY5yEACpzM41b03A5p2wQl0t01kuMRB9v+vpoPeyaQGA==
X-Received: by 2002:a67:af15:: with SMTP id v21mr4723178vsl.161.1579106276052;
        Wed, 15 Jan 2020 08:37:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2885:: with SMTP id s5ls1106589uap.10.gmail; Wed, 15 Jan
 2020 08:37:55 -0800 (PST)
X-Received: by 2002:ab0:902:: with SMTP id w2mr5085382uag.41.1579106275771;
        Wed, 15 Jan 2020 08:37:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579106275; cv=none;
        d=google.com; s=arc-20160816;
        b=gmrvAhDDD6LuqfONAGYi2CmHD3tGW8UNBMJxQHHQ/3mti8WNBGdVlzIhnbZgTkmgJt
         49DDqjfMNmMdEuzPRG6bnKQ9MDTzibDneTGM4qCYmkCkV1vxAaI9Hr2MOcrPCJmEXYnn
         JH83DkXWTQi2cYLsHJ/PYTRDv4ZQBjZmPiaZmze1ysljX2Ootgex3rieLPTctpENysFJ
         4AF+ID2acv7HBGtyc9mB15A1BXemmNvyPVnKNk8nheJS9hzvk/sNSioIaGq9b5EIVTRt
         17XvZDVQZchKM2KWvn3CV4gJtahZnZ1fbUxTqGcC/cCF1uuAGokQgqwm4MdiTLX+l3z0
         pu7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=iOeW0VLWmYFM7+YoNDx59EM4+RrbBVjjruJl+xkGwLw=;
        b=uvVDPD7o+efaHlp8JLz9ojH5GtunB7qjGaqZ/KE0ccv1oNlztB9YPYobGfaK2bWbRV
         hpM9FpV6MTyeNnv94D6SiTMoCQXo+VqgmQVo7CiDBkJHl9VEBIhWMuSg/3PDmL63p6s1
         Q5XupW+WQUnamxSTFvKan1qmBA30lcX3l5qEg2UYnaHhv/vtu6esjMUgdF1EJqS2xrR1
         bJuGm1ECgSFvbJBAUx4D9/AVI9rYe47UxjVz8WBfk0rDamv3aqA0AEikbJee2KixT7fa
         jI0SPUbUnZ7QhjdCAeFlasG+UAK77qf/1SUdcfu/aturvPUhHjg4LD8Dp35XGAjqkzUj
         Y61Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=otOeJmqz;
       spf=pass (google.com: domain of srs0=xt/d=3e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xT/D=3E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i27si755362uat.1.2020.01.15.08.37.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jan 2020 08:37:55 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=xt/d=3e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8D6FF214AF;
	Wed, 15 Jan 2020 16:37:54 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 239A73520BAE; Wed, 15 Jan 2020 08:37:54 -0800 (PST)
Date: Wed, 15 Jan 2020 08:37:54 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Dmitriy Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Qian Cai <cai@lca.pw>
Subject: Re: [PATCH -rcu] kcsan: Make KCSAN compatible with lockdep
Message-ID: <20200115163754.GA2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200114124919.11891-1-elver@google.com>
 <CAG_fn=X1rFGd1gfML3D5=uiLKTmMbPUm0UD6D0+bg+_hJtQMqA@mail.gmail.com>
 <CANpmjNP6+NTr7_rkNPVDbczst5vutW2K6FXXqkqFg6GGbQC31Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP6+NTr7_rkNPVDbczst5vutW2K6FXXqkqFg6GGbQC31Q@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=otOeJmqz;       spf=pass
 (google.com: domain of srs0=xt/d=3e=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xT/D=3E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Jan 15, 2020 at 05:26:55PM +0100, Marco Elver wrote:
> On Tue, 14 Jan 2020 at 18:24, Alexander Potapenko <glider@google.com> wrote:
> >
> > > --- a/kernel/kcsan/core.c
> > > +++ b/kernel/kcsan/core.c
> > > @@ -337,7 +337,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> > >          *      detection point of view) to simply disable preemptions to ensure
> > >          *      as many tasks as possible run on other CPUs.
> > >          */
> > > -       local_irq_save(irq_flags);
> > > +       raw_local_irq_save(irq_flags);
> >
> > Please reflect the need to use raw_local_irq_save() in the comment.
> >
> > >
> > >         watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
> > >         if (watchpoint == NULL) {
> > > @@ -429,7 +429,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> > >
> > >         kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
> > >  out_unlock:
> > > -       local_irq_restore(irq_flags);
> > > +       raw_local_irq_restore(irq_flags);
> >
> > Ditto
> 
> Done. v2: http://lkml.kernel.org/r/20200115162512.70807-1-elver@google.com

Alexander and Qian, could you please let me know if this fixes things
up for you?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200115163754.GA2935%40paulmck-ThinkPad-P72.
