Return-Path: <kasan-dev+bncBAABBH5N376QKGQEDY6AFSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 734722BAC1F
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 15:45:53 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id u3sf7019506pfm.22
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 06:45:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605883552; cv=pass;
        d=google.com; s=arc-20160816;
        b=EigKpxtLILBgN4LRrD6/nq96RJS/a2JDw78x53xtsDOrGYxrKI6jd66hCLr2+GUTAj
         1Na7eHlZChUJw7mk5c3axdJt1L8c+MOyFR4uspL/d5u1IydxM1Xn1Y9IzKpN8SNWdvNb
         eGV+OuzNX9uzGquNuCtmhJqU1kxCKVOZADWgyK0OSkZqQw8Fa/0g3eFBJcWqKuhSl5Ow
         kUkrQNEzad25+vc2hhrQxzc14v/oJGVTUkckVFp19fhyB5tP+jgNOmgKkbPN9BsDkHNW
         rovu1qTIWK/rqKgkSKZptXdtDdNg24PyN7f8XpUIygmIFmbCvjrR9FnMT3wZsm4G8OZF
         upgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=3Ux91myOQpR72AqeZDnzwROhST34rZJAxTJVa8nOeG4=;
        b=LLp/DQtXF4ZAWZOLrs2Zp1X0gFNatEQN4jBm200vbp7OXyQZjNvlbehZLA2nQWuuY1
         sd4zRvxjZTdjROXl1IHYzeQT2trcaxh2I4msjCSpkzHm0h4j8bpXRh13U8BEsFma+jn6
         ITMdr4Fx0lIBZJTRrL1GzmpJ+gkYmDKB23HQlx6NJS14k0FHSHi2ul/0qE3u31tE+tTU
         NfOMQi9JJlP7KsfDfi5ZaCd9R6MrZD2iLs8gHXDEVkriVFlqj368wfKbOYlBvPi1F4JU
         cwS+SWva+cej2y/nmjdfKYc1Ov9E/yH4pV0S9rJS6LhK6ZoymDtUHbmkAmnZ5WVUzEjZ
         bUjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=EsniAHv5;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Ux91myOQpR72AqeZDnzwROhST34rZJAxTJVa8nOeG4=;
        b=HMWh+KdqqWr+QW7JJunxTIVRQd2DJnviJqtkqCPD2raJMZ/6udZ/DIwdoBxWpaNzWE
         mDRH4OTffmVTQpzpgDvLn+AUyANVUqIrvlbNb8RH+Uz0hBkyVLeC+/mudn8APo/qKqGN
         5jLtQtGkbatzGy6dAytc1sWp6KV/F2Jr9ELYYr/Ou8LmlfjJsAg2PBRVmdDVdZNaH0dr
         /bTTHygkwTiFxW8yOaOz7zci3zzhs9o6k9PyE2mYShYI/XylkI8PiqdjjdiwMOxk7EDg
         lZkA/V2W+slrxGbORfW2IcXhhljv88RnAjsPQ/8gZpz+Px40MpoCyge8lBMHlnCFgCnz
         9SdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3Ux91myOQpR72AqeZDnzwROhST34rZJAxTJVa8nOeG4=;
        b=M5ECIsC766NNY/BkncoeAaq6Q15iirxd75633WbmqM8qR/IMYGtSfYNKY0xZJLgxhO
         Ld7sAreQ1xoAwOurBTxB+jPMpoafloUhKBAbPgNVGnl0SgX1ue+SztuWv5+N6khA6hlf
         yWzgHf43VEKNc2/ouNgLFZVggFKpJxX/I+rjarguYyxtulYDrD27aOmi5IA+wPxZgXFa
         SAmQRnXaRv+Wv0+57TvB3QZ3r8iI4ea1y3FDPVsP+miXYQ+6yTzugZnEcshnvZSdR4w2
         7LyPLM8fJdJoZAbBYG30h1o6rZ4J/ZceUGGPmmVNi/Rrirj8S1ep6ZO9rEBY/weyupBy
         /wEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Lfhp7RdDN4/qZTbCe3W0aeXY2z4qSmTE+jioSZRDFzSCN2oLk
	4c/qGAxyRRmyiPPq8J7WBeM=
X-Google-Smtp-Source: ABdhPJxeNTw/HPitTiM5KmYpikW4j3CnYtx4pgRspi1t1HmoAobmGpGMDwVY/rez0Qitey7m397Iew==
X-Received: by 2002:a62:7f95:0:b029:197:dab1:6f70 with SMTP id a143-20020a627f950000b0290197dab16f70mr2246489pfd.69.1605883552034;
        Fri, 20 Nov 2020 06:45:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f994:: with SMTP id cq20ls2177710pjb.0.gmail; Fri,
 20 Nov 2020 06:45:51 -0800 (PST)
X-Received: by 2002:a17:90a:4687:: with SMTP id z7mr9960806pjf.168.1605883551529;
        Fri, 20 Nov 2020 06:45:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605883551; cv=none;
        d=google.com; s=arc-20160816;
        b=xzVvYYF+m2H06ATotRuszsI8kekVEVEP9JPagKXRSxo252+ffblMsVwczm3sAYI9M9
         3FiaMiyU+lTfgnOByAriNcOq8Rh6cAgTZEMtJQjR0i581YbwrXTcLhGasupe7B2q5p80
         L9UGlLed+P4s9CI6LCHO1OCyXUAWtNknQCvdS5a+J5diB+MPMuOq5Xs8fEDgFxv7Bt4r
         U/ZXwKii268ByZ41PLI77SBdaTZTcLqrE6rGi+hQWvheOWadzojRWLPQ4wQPg/xt30Jv
         0Cpo1t6IQnzmTly+PGMRD/ZbwHO1moEmJT4c9A2Z6oyrZ5y6pAbRFNjuJ2d/6OEhMViS
         pJxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=oSh0PUMLC5d+kwbtErJ66aYpPlvRTBYZaqxMk3zCS7I=;
        b=lD0ifKNXdv4zs32T2BSAh+jEFsSjOOnUG5EJHb4fZVV4rHE+V/otk+bNQl1nPbqQ2H
         qy+RUF+r64aM+Be3nleJgKXYOx4Vrt6cnP0lIauzpdDpNE7Po54ik7Vm3ZYOXjqfoX02
         ZBVB/NIvzLOWNHXLtDMmfB6G+Fe+2WRoaekNeNSZzT5QvJOC2EDFqxrohrgumngLHy0k
         grZ7N2r+GLEBp9ILUazWlZGlqvLQW9KMFMO8U3zAe6vi/Wzi1Dx/duFEq+PuPsmQQDuo
         5VTCI9CaKqhd/LCB7fgmOlIQkNTET9KRiXR2QgJmbLgawUGWBq0J67ce0TpFPh7YHA0O
         V1YQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=EsniAHv5;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id gg20si313652pjb.3.2020.11.20.06.45.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Nov 2020 06:45:51 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1B2B22224C;
	Fri, 20 Nov 2020 14:45:51 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id C57CC3522A6E; Fri, 20 Nov 2020 06:45:50 -0800 (PST)
Date: Fri, 20 Nov 2020 06:45:50 -0800
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
Message-ID: <20201120144550.GA8216@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201118035309.19144-1-qiang.zhang@windriver.com>
 <20201119214934.GC1437@paulmck-ThinkPad-P72>
 <CACT4Y+bas5xfc-+W+wkpbx6Lw=9dsKv=ha83=hs1pytjfK+drg@mail.gmail.com>
 <20201120143440.GF1437@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201120143440.GF1437@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=EsniAHv5;       spf=pass
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

On Fri, Nov 20, 2020 at 06:34:40AM -0800, Paul E. McKenney wrote:
> On Fri, Nov 20, 2020 at 09:51:15AM +0100, Dmitry Vyukov wrote:
> > On Thu, Nov 19, 2020 at 10:49 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Wed, Nov 18, 2020 at 11:53:09AM +0800, qiang.zhang@windriver.com wrote:
> > > > From: Zqiang <qiang.zhang@windriver.com>
> > > >
> > > > Add kasan_record_aux_stack function for kvfree_call_rcu function to
> > > > record call stacks.
> > > >
> > > > Signed-off-by: Zqiang <qiang.zhang@windriver.com>
> > >
> > > Thank you, but this does not apply on the "dev" branch of the -rcu tree.
> > > See file:///home/git/kernel.org/rcutodo.html for more info.
> > >
> > > Adding others on CC who might have feedback on the general approach.
> > >
> > >                                                         Thanx, Paul
> > >
> > > > ---
> > > >  kernel/rcu/tree.c | 2 +-
> > > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > > >
> > > > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > > > index da3414522285..a252b2f0208d 100644
> > > > --- a/kernel/rcu/tree.c
> > > > +++ b/kernel/rcu/tree.c
> > > > @@ -3506,7 +3506,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > > >               success = true;
> > > >               goto unlock_return;
> > > >       }
> > > > -
> > > > +     kasan_record_aux_stack(ptr);
> > > >       success = kvfree_call_rcu_add_ptr_to_bulk(krcp, ptr);
> > > >       if (!success) {
> > > >               run_page_cache_worker(krcp);
> > 
> > kvfree_call_rcu is intended to free objects, right? If so this is:
> 
> True, but mightn't there still be RCU readers referencing this object for
> some time, as in up to the point that the RCU grace period ends?  If so,
> won't adding this cause KASAN to incorrectly complain about those readers?
> 
> Or am I missing something here?

For example, is kasan_record_aux_stack() -only- recording the stack and
not at all updating the allocated/freed state?

						Thanx, Paul

> > Acked-by: Dmitry Vyukov <dvyukov@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120144550.GA8216%40paulmck-ThinkPad-P72.
