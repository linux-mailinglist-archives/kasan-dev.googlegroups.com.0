Return-Path: <kasan-dev+bncBAABBANI376QKGQEPDJOJKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id B91842BABE8
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 15:34:42 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id p15sf6617489plr.2
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 06:34:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605882881; cv=pass;
        d=google.com; s=arc-20160816;
        b=hCz3jPOC67DhsImHN1yILwPShy/CMfcqbuvy2alo3Vel+TiyDTBirgPokV42+/yI1Z
         lquxAawrdQbnnIe7V1ojedEY2qQPZXLKUZ7fK5KeHq+WHPnLV3DMZeoZfpAmEehfE5so
         hVclWYMJGiOrzFLFCZr1ZGyBA60yPqp38i2M+EAw7mDLWlopOD8SjcMqNFoSb6HODF8F
         FTzZZnyCy5uxXNWa5yILmrzPfQLjivvbvRQSLnl7g03KD/+vzjs0oXuAH6+9bSFGOPQT
         sL74xzuoQwqDPpjisdmQphZIadyqq3FcjKZ1DxuroEGnKvjb0L/6B2pA8d1CIIZ4SqNz
         2LXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=nDlUa6KmFPUytelvIoKD7rHLoI5z1FgmDEXMb267O2I=;
        b=kFjRsUz0XZoNx+Jvjm/Z5mTuM/jLG8fP7Jk/GTYXNkAQpNM64cny8/br5lw0UiW2uX
         OsmMjKY553zcFnzonbWMeiH6NfY/ixSpULzDYPXEEn33RZrN/NI7xqqLsU7Qe/GuYeHn
         wrMjRvx6mSksPmyJJkysxsnEqouOlW7vsz24ZbEcZe7MOGIp8h8Pjlxi9FLSNbx3BTOb
         cKWvP4IOEbIJm2fkCuQa3tVKAWBu9LNka5sZUJhPyVLyDm0CUq+Y6pIjoxRuNqA49UYP
         iglWJ0axJbazVUz1D6Hza3P0zdONslfrU1pT0sRRiLnRqd8dt965UA1HhmQJYl5MwRIH
         48YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=pWXHsH0z;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nDlUa6KmFPUytelvIoKD7rHLoI5z1FgmDEXMb267O2I=;
        b=j5WXCGUDkOKB6o1EMnTNaxAOfGUTQi8r56nZqhbGg434i1N04bbdyVj2D0NrcjqOA2
         LeSPj2Yv2bNw5vU9hn4VtHtlXydbNx/nbXrUCjcDGZA5ECmldbrv8nMZ+S6y095Y4hw0
         jMlmOi7OjB7XdqPu5g5ov0egJY4cXTcEb2tqZDBdx0sBa+nTTXBUhg1VhNXz7xl7a+LI
         ZWO+7CTX6V1oLMJ1SY2rdSIZxX68auzKBxASAMom3+RYPkcbNHVmHtI6pwjL0b4FP81u
         KRZkL4tOaEjLLXsAzl1ToEFaxP7f4HUB7JwAscSXe5Dc9cYNRm0nmPU2hxl2tqmVQNi9
         Eshw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nDlUa6KmFPUytelvIoKD7rHLoI5z1FgmDEXMb267O2I=;
        b=ChibGNMgW+su1BglhKSkQFtQ5gkgLvR+InlJVg/iVOf81sfgmFN6g7lZwYqNVLG/YN
         kB+cDMPoWwMDEYdq86eX6Fidyq0K4DnoE3OhdUM+1MwWQLhrnqkZ5cNuvTB2xrHdigO0
         ogFZpBU5H1o13zCcqBZEGEbvf4+XkdEiBsN+PpigbaqoVAK0jLVSmsuUpYKjEkleuzSI
         pzJs+tQOqW+/rkq5ZXn+sKbGdTT8pn8bW/2g75Cu6x/VdyEoyZzbqhS1h0qjW2fXlu5I
         r2nmr/KZH5b/8Gp5vZDp6eG559V0nXd09vRdBfJwzivFYGY5ZAZaZu6vmdZm1HtoEisg
         LggA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328OnIohZZPyrpVcwYxcXHdWwe10w/8LPPyskzD4ODc99B9POq5
	dCipeO4r26cvZPwOgPDiI+U=
X-Google-Smtp-Source: ABdhPJy5jOQs/fvIxdHjoSrZbdimwRkz6rncCb7u/ihtuvbibvVg1cydzefceTsy8NYxxVkyNJiiBw==
X-Received: by 2002:a62:f211:0:b029:18c:28cf:89ff with SMTP id m17-20020a62f2110000b029018c28cf89ffmr14028935pfh.71.1605882881442;
        Fri, 20 Nov 2020 06:34:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7745:: with SMTP id s66ls2531744pfc.0.gmail; Fri, 20 Nov
 2020 06:34:41 -0800 (PST)
X-Received: by 2002:a63:cc05:: with SMTP id x5mr17586701pgf.85.1605882880956;
        Fri, 20 Nov 2020 06:34:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605882880; cv=none;
        d=google.com; s=arc-20160816;
        b=bhu9l8hiwthNnQ2NhzgcfA3S0DYUfkB6nyu7uAEyhtmjZEsBIM3AkPXFlzHVmcirOr
         yZp7aPjDgcgiXnNO3Ey7YWkKXUZpgPbMq0wfhnWuFUUVPxWtCdVPlI2wtLBVy56IXFv6
         7BjycEbMqO67uaT0amEotjH6AI9tiLVyP9bK438ndrpyzwFF+PwilmBHPIjsQ0CnkwAH
         qQq2MB5LyeFSF6fy9s98HfZfqeU6CX2QitawVTqduCAjvAnAtrEshE8MMaRTM4j8bJJh
         J3V+vBygV/5h4JA/ypCyj0tjFtCPhLd/nQHkslYD0FzblTLA+oNPcsPF1bcAzcLdX8cD
         Pfow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=GMw1FvxC+16cIhD5brQOh1Z7JVio7YF7jZ7dLFdPU7M=;
        b=NnoI7B498/NwNvTDewrYajb4K5B59HIaVggEqnACqGtrAKryAzRDeYkBqk+jUquUB6
         bdOXiSbG4YNfeZ/i9P0H61S9nRPBAbHrUoUkJsrkiKoNSr7PsMtbBwHlXMoofLUF4pNq
         p+l3r6WrEuVNatDtJ4fM99uPtR2Wc9mC1DFR9zYxoUimLN74rnRkTv39e1lf/hGYvOkJ
         rS/5YaaJmdBYTCeyMIqngSpCmhJ7V9lMDoNIGndDOVFJlVp9cjO0kNCDDeT5e9rDWHDp
         Je+9dZz/VmlQUHN6W5KaWblPf+1d1pDdKuEMpljZUH5dIVYDD1mzvvut7DHYDwOgU9js
         q+IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=pWXHsH0z;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g4si338786pju.0.2020.11.20.06.34.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Nov 2020 06:34:40 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 70B8322272;
	Fri, 20 Nov 2020 14:34:40 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 11AC83522A6E; Fri, 20 Nov 2020 06:34:40 -0800 (PST)
Date: Fri, 20 Nov 2020 06:34:40 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Zhang, Qiang" <qiang.zhang@windriver.com>,
	Josh Triplett <josh@joshtriplett.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Joel Fernandes <joel@joelfernandes.org>, rcu@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Uladzislau Rezki <urezki@gmail.com>
Subject: Re: [PATCH] rcu: kasan: record and print kvfree_call_rcu call stack
Message-ID: <20201120143440.GF1437@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201118035309.19144-1-qiang.zhang@windriver.com>
 <20201119214934.GC1437@paulmck-ThinkPad-P72>
 <CACT4Y+bas5xfc-+W+wkpbx6Lw=9dsKv=ha83=hs1pytjfK+drg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bas5xfc-+W+wkpbx6Lw=9dsKv=ha83=hs1pytjfK+drg@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=pWXHsH0z;       spf=pass
 (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Nov 20, 2020 at 09:51:15AM +0100, Dmitry Vyukov wrote:
> On Thu, Nov 19, 2020 at 10:49 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Wed, Nov 18, 2020 at 11:53:09AM +0800, qiang.zhang@windriver.com wrote:
> > > From: Zqiang <qiang.zhang@windriver.com>
> > >
> > > Add kasan_record_aux_stack function for kvfree_call_rcu function to
> > > record call stacks.
> > >
> > > Signed-off-by: Zqiang <qiang.zhang@windriver.com>
> >
> > Thank you, but this does not apply on the "dev" branch of the -rcu tree.
> > See file:///home/git/kernel.org/rcutodo.html for more info.
> >
> > Adding others on CC who might have feedback on the general approach.
> >
> >                                                         Thanx, Paul
> >
> > > ---
> > >  kernel/rcu/tree.c | 2 +-
> > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > >
> > > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > > index da3414522285..a252b2f0208d 100644
> > > --- a/kernel/rcu/tree.c
> > > +++ b/kernel/rcu/tree.c
> > > @@ -3506,7 +3506,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > >               success = true;
> > >               goto unlock_return;
> > >       }
> > > -
> > > +     kasan_record_aux_stack(ptr);
> > >       success = kvfree_call_rcu_add_ptr_to_bulk(krcp, ptr);
> > >       if (!success) {
> > >               run_page_cache_worker(krcp);
> 
> kvfree_call_rcu is intended to free objects, right? If so this is:

True, but mightn't there still be RCU readers referencing this object for
some time, as in up to the point that the RCU grace period ends?  If so,
won't adding this cause KASAN to incorrectly complain about those readers?

Or am I missing something here?

						Thanx, Paul

> Acked-by: Dmitry Vyukov <dvyukov@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120143440.GF1437%40paulmck-ThinkPad-P72.
