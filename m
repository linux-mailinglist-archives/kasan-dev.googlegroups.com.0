Return-Path: <kasan-dev+bncBCV5TUXXRUIBBUFI6L4AKGQEXJUJCHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 971A122D9D1
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 22:21:36 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id h205sf5770588wmf.0
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 13:21:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595708496; cv=pass;
        d=google.com; s=arc-20160816;
        b=RAh4cCbKb0dZ3SuM2C3q8PvTPpCNIc1kHfr65FmIxWD+d4GyfI/ii9owiE+T6tIMoh
         a4DbKebYe/tN8tLw5zL0qKN6jVrAlecgaczDMnY+6o4++My7o9T0zL77B3tpwmjyNNz9
         DXuDtUbSMGwabZbipb3liJc0oXJWLAsGVRXMicfjlVkWep7SADEHf+OWiDEWGknlfwGX
         qwoLeLLtUBsGVnL5Caq9IL66IBEWMbBSifJ9GTWLDcWusMIM77kHsFCYnOumFkznCbbt
         vHTJbA92vyoWDb3lNqqambgzSApitK09Qs90aqPPCjhYKLhp7bnGe58uYUi8tZeYktEO
         h18w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=e+B/YmfAlYALv0VFyjJb2cEvCb+PCVUINxz+6eqBcnI=;
        b=bj9DTgfNq0qKUlWurmtPTDlYNld8Q/LkTUivLAFaGoNyRyqjZou8+AYYsnz2R5fk0G
         HeI5PM3KeRpt65Idkz07SFdTOrd5E2iK8PnYogOyIkVHwhFyKWcAE3aM3N2Xs9+2fzAH
         XlpehrI5E/VzxSfr4Fx6u1ehXEVI2gfzbGT7aBv49Z5Jbfnsa+KjQ36BE8UmZAicunr4
         +GP7GvDnvOMYkbvH9TvYMeVnPa8S7dlOo8E2LHxkcn3113+keXLpoVByv4dYRUNJWpQ/
         KBElf8kT0MhT1zS+wS+dQGb8ovGjBHfGaEF0NaFyRh6ee1MMlTncfscMOIAugopFQwU/
         gYqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=M82R7Oo1;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e+B/YmfAlYALv0VFyjJb2cEvCb+PCVUINxz+6eqBcnI=;
        b=pSh4E0aL6vXj/PT/M54imLH9AulYwfoNi9TF4q7IBm3SrH4Wd/rqN4iN16B1DTXsUn
         e9AixX5QcFiwlvLTYqFq8N9HW6w/H+kgFoks/M6Dc/mwttbZ2GL2VPROS/GOgWDhDMM0
         uaOcbQXwVaTlOHTf9rpKAkrTDpEraLvH3khGe8W5Kj6qASFRaobqg7nrCuiSYpVXSkKN
         i3aWNIS2hKYhe6WxQK7Jbc/mnPrrclntecrmOcJ3MCgdkj2yHnKgl8IOppYldT9M2Vfo
         fLSidf5uWnQRrQ+/BkZcEVNjBTkIQpOs6a8huQfYwHw/aE0eUMzMiYOdItGTjcV6oIO1
         QOag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=e+B/YmfAlYALv0VFyjJb2cEvCb+PCVUINxz+6eqBcnI=;
        b=IHNIXw40PUO0vrfdOBCli7N1MK/IQiFpkNPFyECyFlJyBwM3x58FiSwdaFky3ety6m
         F93W/v/Pu7bLnWx8bXSB7B8ZCHa4APXBUvCnBsJWGICgzVOGPlMjbrNwg8OzZ7Z/v+So
         6wBQDAaqbvkwUs3jwKLHNdKxuFdP6JC8I9XHN7swljMX8ZA1ZJnWsISorJwO6qPPFJGG
         MDQFwgr301cxRLlfaa3Sv3PAD/C14lzygvnMO2sN0hGRmOslsMG2tTapvsD7MwaYoFep
         QBJCzeRa8vSOXYgF+vEVRTkx3ISWR41hYpY5kXYlIY3/QzE4g5jZQ1HEDl3YEfUBCI6Q
         T6ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mmNyGEqEhfLZa8MzyjiaaYOZetdSzGJgi9OO28pp+VSDNdGEg
	ahZSQYlvHiAvVei+4a3y6YU=
X-Google-Smtp-Source: ABdhPJzbZho/gGE+2jQl52TrZ/GW339RJbrDFX1FKNzo7IsbCxqURlMHpEsFHlF7NONpKtUNuNJJNw==
X-Received: by 2002:a1c:3102:: with SMTP id x2mr14785933wmx.171.1595708496246;
        Sat, 25 Jul 2020 13:21:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7311:: with SMTP id d17ls6014034wmb.0.canary-gmail; Sat,
 25 Jul 2020 13:21:35 -0700 (PDT)
X-Received: by 2002:a1c:790b:: with SMTP id l11mr1653072wme.127.1595708495754;
        Sat, 25 Jul 2020 13:21:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595708495; cv=none;
        d=google.com; s=arc-20160816;
        b=X+SKxc5Afva/dUeG03AQgL3OeWdbHhFC5xLXq+SDgCxA5vFU4eauRySN71Ara3TKIA
         BjZkjTaQeBj/2sXFAbAeNKw2hhaztkXTniNKmAYA/b3uo4jRUjHKzyrGNeq6HEP2aCU4
         ILltKnZFUGNkRXXgdHqZl8yzAlWOcB5dc7jRIZuCby7ad+k0OyMNAtNeWGziEPniw/e5
         N8jYP8MNYAUyTi0obdK/5WQjCCvOnlvv/92CAcovP8lOOtpUC9AaXqjTgtrHwao6onUi
         dOD8oyTxz6TjQG4LaY/ZjUZht4V+6Os7yENrXBOoy/DyKBMWuMC5k45zdjgT8Xrnva//
         4+Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nEVDy9qer+ckQqB0/s8J9oIrB0Y28OWoQKAT4jlVuho=;
        b=Z3yyXM/0rjaT+K0x8jJBujUVjriqXzDKSp7qQEDnUYvVysS9aATC+35URld6fBmz5b
         zbijXn+fCgk318RfjK3GBTHWez5GZVGRrryEUlBZzg0DuOwtGICcm/HcxeIedodFTxvP
         VJfpxqj0R4H0sRmVzT1un575xq7kCJEfkc7FbvnWFIL0oe4CbiuF8LMjs0sLU7wZCYG3
         tnTu20kXwJRIL9Cohu3W3W6YrJxZWbmh62jjYfxrmTkpFo09TV/aJs+SyH6Th3etbNNu
         XWuVBS/hSmQx9Fb8vrj3iz5mlwlLovRwXNwKeSXMvNda4P1yJmDQ1zhybibqr5NyVELj
         BFOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=M82R7Oo1;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id g14si755036wmh.3.2020.07.25.13.21.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 25 Jul 2020 13:21:35 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jzQfl-0000FO-VL; Sat, 25 Jul 2020 20:21:34 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 8A970301179;
	Sat, 25 Jul 2020 22:21:31 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 6E7582141FBB0; Sat, 25 Jul 2020 22:21:31 +0200 (CEST)
Date: Sat, 25 Jul 2020 22:21:31 +0200
From: peterz@infradead.org
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
Message-ID: <20200725202131.GM43129@hirez.programming.kicks-ass.net>
References: <20200220141551.166537-1-elver@google.com>
 <20200220185855.GY2935@paulmck-ThinkPad-P72>
 <20200220213317.GA35033@google.com>
 <20200725145623.GZ9247@paulmck-ThinkPad-P72>
 <CANpmjNPhuvrhRHAiuv2Zju1VNSe7dO0aaYn+1TB99OF2Hv0S_A@mail.gmail.com>
 <20200725174430.GH10769@hirez.programming.kicks-ass.net>
 <20200725193909.GB9247@paulmck-ThinkPad-P72>
 <20200725201013.GZ119549@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200725201013.GZ119549@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=M82R7Oo1;
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

On Sat, Jul 25, 2020 at 10:10:13PM +0200, peterz@infradead.org wrote:
> On Sat, Jul 25, 2020 at 12:39:09PM -0700, Paul E. McKenney wrote:

> > This gets me the following for __rcu_read_lock():
> > 
> > 00000000000000e0 <__rcu_read_lock>:
> >       e0:	48 8b 14 25 00 00 00 	mov    0x0,%rdx
> >       e7:	00 
> >       e8:	8b 82 e0 02 00 00    	mov    0x2e0(%rdx),%eax
> >       ee:	83 c0 01             	add    $0x1,%eax
> >       f1:	89 82 e0 02 00 00    	mov    %eax,0x2e0(%rdx)
> >       f7:	c3                   	retq   
> >       f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
> >       ff:	00 
> > 
> > One might hope for a dec instruction, but this isn't bad.  We do lose
> > a few instructions compared to the C-language case due to differences
> > in address calculation:
> > 
> > 00000000000000e0 <__rcu_read_lock>:
> >       e0:	48 8b 04 25 00 00 00 	mov    0x0,%rax
> >       e7:	00 
> >       e8:	83 80 e0 02 00 00 01 	addl   $0x1,0x2e0(%rax)
> >       ef:	c3                   	retq   
> 
> Shees, that's daft... I think this is one of the cases where GCC is
> perhaps overly cautious when presented with 'volatile'.
> 
> It has a history of generating excessively crap code around volatile,
> and while it has improved somewhat, this seems to show there's still
> room for improvement...
> 
> I suppose this is the point where we go bug a friendly compiler person.

Having had a play with godbolt.org, it seems clang isn't affected by
this particular flavour of crazy, but GCC does indeed refuse to fuse the
address calculation and the addition.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200725202131.GM43129%40hirez.programming.kicks-ass.net.
