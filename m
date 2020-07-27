Return-Path: <kasan-dev+bncBAABBVXE7D4AKGQEK46CN3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DCF122E3B5
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jul 2020 03:48:07 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id x4sf4741951iov.8
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Jul 2020 18:48:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595814486; cv=pass;
        d=google.com; s=arc-20160816;
        b=h15vh2SfQl/D9NvZgApmuomK5Vs/8pyzjzzhiNU0T2dG8AkvfRweekHfPrxlcIu+kz
         BAp/lWoc690LT5dZOCd39ytSRXO37EiYFlHFuBVty+hpiJ6+TCdi8NmROVKUcojr3tbY
         Adwkbpjgn4DtEXC4fBxngBMm918IAPZRSI5fEL8EIcdsDIMsXeBltCJx3osv6njQvkTG
         TK0UIuYNRIA4Bwy3fwZg9ULl9Wh7s5WNg0XqGeofl0mD4swciR/+EMEBunYBRgxpk2rV
         GTeuBr5ewoOF7rM2p5Sv7VM6N2cNqZTL0Lh1LJbKOqxdraoV/JFkAoEmubq8SeEgxGde
         b8og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=3qbcmoq+k2Upjw2Mo+nlSice81Vms/XVJHsGovXLFik=;
        b=XXLf3YgCjUfP5fn1gyuJIFopmoV0QQEykRKbchztqxtV012eGDgi7CK8gfpQbUdsfe
         Bnha+axULeqnRAMaJcYD+8kCgnsuqn/BJ/jI1RrOSq3SLPVz4qkm2Y9+sM27bCLdiVea
         FLNwMjw6CtBjS1LoTee0CITpizdyh7mdgDOtFPHV10tou3WW+ER2Ej4DA08HpEbGbUbl
         uMvMiUuEVgMztpMkhn1MLCvAWlJXrRyWBQTvFUc1EmDMX246iw0Us7KqQqIaXYXESNh1
         15PdDuWDSQ2+lxy6AV/1wyuOl/7i83DXvnHx0wCK2XXYqQhfVBTiXuEkrfTXeKcPcCbQ
         nteA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=J0PNf3he;
       spf=pass (google.com: domain of srs0=kgnp=bg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=KgNP=BG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3qbcmoq+k2Upjw2Mo+nlSice81Vms/XVJHsGovXLFik=;
        b=LYpOYuZb+UBjRhv3X+3l2KIUgILk6LRpoUnm2aLcclgkrOT55qEoF4hHroOIbUqQMS
         NYQ7UiQ89qXHtCSeq4pSbr3s+A1pGJoHFwWK/AJ3HHswE+fhpWRedR+BHLPGuN4oxHLq
         TDzqC04GvW+WGtp3vbV/63vlFlEHACwXT0xJSw5ASz9ow6i6hC8AScXRi8YB9iUP+rbL
         eiMgXhMHU+P1TGvMQcyRVxK2uWpip9mWpo+HcEbXlM4lIKdkvkgcPJy/HSuv9zF7tvzg
         o29sU5WZBF749ZuA4iteQbf7+f5lSPICVzGr1iMZxnEd28kv+04HD0odH3XhgW1YQFWi
         2Ymw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3qbcmoq+k2Upjw2Mo+nlSice81Vms/XVJHsGovXLFik=;
        b=C+sxf45nxF7NaJJANjlfOqlwcGl0a3wWAcPoydasjkEDUGYPTtbAEFZiclmjwrk8aW
         jqn5GwQqLw7UbPquIopmKxr+BnlyHXCjQNo8PayHyx4hh6qa3TfKaEkXfeVZOO2nGGiL
         svktCxNX9/RlQwrlNrbsQHAVXpvxBhdgVUTCx8TJooaO1aAymN9h70eKJLItXI3CyjqU
         gRdehX05SFVXgbAmpUgIt4QjlvaND8rVbuW7NCaXJtwVcAPiMs37Bog6B0K0AcaRDF/4
         7ROCEze9RYhRUm5PJpPNYw2R5griQSzRnfGztXGWPu2c9OlO5Dbnx8WhTnQx85pm5ITc
         F7Dw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532FCsRrWWUOk2AHE3EbdRjB1g7nmrq1gWyLy4AijtoDRA4W0Dot
	r34bTC3xOswdInXtTubVToc=
X-Google-Smtp-Source: ABdhPJygKPdu7+/o3LOi9W7kDdgpCG7EVnqD9oMCdQp+gPqYwJ1X07IeqHJsUckM+oqE1+Uhb0jkug==
X-Received: by 2002:a92:6a07:: with SMTP id f7mr9711181ilc.271.1595814486193;
        Sun, 26 Jul 2020 18:48:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:e54:: with SMTP id l20ls3778255ilk.0.gmail; Sun, 26
 Jul 2020 18:48:05 -0700 (PDT)
X-Received: by 2002:a92:494e:: with SMTP id w75mr21783751ila.115.1595814485926;
        Sun, 26 Jul 2020 18:48:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595814485; cv=none;
        d=google.com; s=arc-20160816;
        b=tb29JaVf4MWbZXUSvT9HNQYRFUThFDuG7IUH03celMFsytu64Bns++yscMcLtR8WIJ
         M7fxQ69OVKUNkg9NlBZXofSFNd6tqap9QhcMeyL26C/KeRpNrj3gzDuVUEjNbx+gGF2j
         xrqtoctVnFGMWB8Wo7K6olEH2NAxz/SggvOrTZ5QNF9u1Ezjk6pXRyp/0bdJYe0nlBc8
         sfRIbkx/etSnXFAmCoab9jQ/G+t+/My81dVqXii7g6RLRT1L2pMmaQ7v0mS1g5UN8taj
         Q3FrEpoGmqfG63ArrS4pWSVf6XJd/0ErtvY5INnnG0c0Jhg1EaSkGXrLIwVjaep84wLv
         yg3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=vtByp67xVuhf6FVeZ+rsKNur17gNljJn/qXRSwMkrNw=;
        b=ZO6U0dIaqvu1ynMQqe0P5fRk54uwqrpVvSRfZ+K4l4yBiiIvofjWQtCxxJr3UQFXRE
         Tf+M3OjHbuwLz5GkS6hGN8xtwsEmsuk2yy3uwcah5WAhemqdaXJkpPWgtw9gD+ohjwPq
         WcAtgRw6MnnB8y45dDtYAw2djVtyZaYwtl26ipLN7dD6zW0zZNJ6lO0VryDFTTLZ0by5
         h6llGkQ05UgnH8coeNw5RzfBYAc0pVlebg6Km7iRb3IKHXfGmHG96FQammWn9Oefmt+0
         18O32krrqCzUfYTnI2qfOFTz5FWTj7YdhKT8jCYUKpUd0zwgNxkPZf2FpHebP21HuwDf
         bVow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=J0PNf3he;
       spf=pass (google.com: domain of srs0=kgnp=bg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=KgNP=BG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a15si678119ilq.4.2020.07.26.18.48.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 26 Jul 2020 18:48:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=kgnp=bg=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-111-31.bvtn.or.frontiernet.net [50.39.111.31])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2D2C320663;
	Mon, 27 Jul 2020 01:48:05 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 16361352276B; Sun, 26 Jul 2020 18:48:05 -0700 (PDT)
Date: Sun, 26 Jul 2020 18:48:05 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: peterz@infradead.org
Cc: Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, jakub@redhat.com,
	hjl.tools@gmail.com
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
Message-ID: <20200727014805.GF9247@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200220185855.GY2935@paulmck-ThinkPad-P72>
 <20200220213317.GA35033@google.com>
 <20200725145623.GZ9247@paulmck-ThinkPad-P72>
 <CANpmjNPhuvrhRHAiuv2Zju1VNSe7dO0aaYn+1TB99OF2Hv0S_A@mail.gmail.com>
 <20200725174430.GH10769@hirez.programming.kicks-ass.net>
 <20200725193909.GB9247@paulmck-ThinkPad-P72>
 <20200725201013.GZ119549@hirez.programming.kicks-ass.net>
 <20200725202131.GM43129@hirez.programming.kicks-ass.net>
 <20200725220750.GC9247@paulmck-ThinkPad-P72>
 <20200726115242.GA119549@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200726115242.GA119549@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=J0PNf3he;       spf=pass
 (google.com: domain of srs0=kgnp=bg=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=KgNP=BG=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Sun, Jul 26, 2020 at 01:52:42PM +0200, peterz@infradead.org wrote:
> On Sat, Jul 25, 2020 at 03:07:50PM -0700, Paul E. McKenney wrote:
> > On Sat, Jul 25, 2020 at 10:21:31PM +0200, peterz@infradead.org wrote:
> > > On Sat, Jul 25, 2020 at 10:10:13PM +0200, peterz@infradead.org wrote:
> > > > On Sat, Jul 25, 2020 at 12:39:09PM -0700, Paul E. McKenney wrote:
> > > 
> > > > > This gets me the following for __rcu_read_lock():
> > > > > 
> > > > > 00000000000000e0 <__rcu_read_lock>:
> > > > >       e0:	48 8b 14 25 00 00 00 	mov    0x0,%rdx
> > > > >       e7:	00 
> > > > >       e8:	8b 82 e0 02 00 00    	mov    0x2e0(%rdx),%eax
> > > > >       ee:	83 c0 01             	add    $0x1,%eax
> > > > >       f1:	89 82 e0 02 00 00    	mov    %eax,0x2e0(%rdx)
> > > > >       f7:	c3                   	retq   
> > > > >       f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
> > > > >       ff:	00 
> > > > > 
> > > > > One might hope for a dec instruction, but this isn't bad.  We do lose
> > > > > a few instructions compared to the C-language case due to differences
> > > > > in address calculation:
> > > > > 
> > > > > 00000000000000e0 <__rcu_read_lock>:
> > > > >       e0:	48 8b 04 25 00 00 00 	mov    0x0,%rax
> > > > >       e7:	00 
> > > > >       e8:	83 80 e0 02 00 00 01 	addl   $0x1,0x2e0(%rax)
> > > > >       ef:	c3                   	retq   
> > > > 
> > > > Shees, that's daft... I think this is one of the cases where GCC is
> > > > perhaps overly cautious when presented with 'volatile'.
> > > > 
> > > > It has a history of generating excessively crap code around volatile,
> > > > and while it has improved somewhat, this seems to show there's still
> > > > room for improvement...
> > > > 
> > > > I suppose this is the point where we go bug a friendly compiler person.
> > 
> > Sounds very good!  Do you have someone specific in mind?
> 
> Jakub perhaps?, Cc'ed
> 
> > > Having had a play with godbolt.org, it seems clang isn't affected by
> > > this particular flavour of crazy, but GCC does indeed refuse to fuse the
> > > address calculation and the addition.
> > 
> > So there is hope, then!
> > 
> > And even GCC's current state is an improvement.  Last I messed with this,
> > the ACCESS_ONCE()++ approach generated a load, a register increment,
> > and a store.
> > 
> > Do you still have the godbolt.org URLs?  I would be happy to file
> > a bugzilla.
> 
> https://godbolt.org/z/rP8rYM

Here you go!  https://gcc.gnu.org/bugzilla/show_bug.cgi?id=96327

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200727014805.GF9247%40paulmck-ThinkPad-P72.
