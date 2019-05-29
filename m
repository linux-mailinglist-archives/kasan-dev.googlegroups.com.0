Return-Path: <kasan-dev+bncBCV5TUXXRUIBBG7JXHTQKGQEKT3LDKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D7C012DC4C
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 14:01:32 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id c13sf356390vso.12
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 05:01:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559131291; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mcid46U6Ucp25HF4hF/fiqhKKfmccImC61KlCxwC+MA+OHiUQhGNY5nDxQWUZAm40r
         biW4qfqsBY41QqmxnHhwQ2yo8PDUK8c8fLDGr5mJ3RzLqtmZjoiQHXuH3qEUe+qItrNX
         /ypLxY8artkAJHy0modkIkW875D8nDr2cp0BfilM1r4s0M/S6IiTdxt69hTrXN8Ua23s
         o0OQFPDuuKaE8pAANRS89YLzW2hgoXGs4AjBvtaCESIEpkPPyyDnS3+jYZusO6fs3ona
         apVpFE1mlTDk7L3Op5WqAGEpof6thDweNL4fW2eVJaimrq8Xt/ki0WTwra0ZXqjL0Ug/
         oPyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Su8bwbW9GO2R4BRFCQqHWlgftfbWN+H7P3oSimVQhtA=;
        b=bTUKlwFKgPMoPUc7Id92Mu+FcqMaAjnxtAHSFPszUyQDc0tv9bdelP5zAXBC3FS5Wu
         A1G5fjyQYvCbaLAzcCEGEWftYZk8QsMDHiNjoxc0Xa/xeG06+fG3/OADuXNiARDXCWUO
         po9mdUhD8fCNbeYgjPVh/OzZzrFtL25kxe76EYBo9K4TgsqAD7wJLgHuBLSNW5Qu4Is9
         BfsCaXCwX/Zy7WtHrWNuIQ2lify9iaoeq8cIyY5xiJ2H0o+oO7TpJTcXeY06sbK3oqR1
         V17+lpRFWq4OSWsqNBY6jDE1fLUveQ3xhPjDKGhQbGxhZ/lMol2fWXE3wdI6DpWqEoSM
         +dyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Nzz9NhjF;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Su8bwbW9GO2R4BRFCQqHWlgftfbWN+H7P3oSimVQhtA=;
        b=Fr97uYKt+jnnFMP+enjy4MhwlDssuG5+AMK5SXWNsWacuOJr0F1mxvczrU21r9I4Zx
         MVDQFFh8103FO44kKc/9LwCmMsuJABT6umkhDUSMg4aEZF3v3QZ+pWv61lypQwzdfxZN
         6hsbX09wcYko3zF/2tAndaV/z8LqqZsYqixhz/yJGAgG1kFl1+8EJaNZ0JZWNadTgCbW
         +c58NvxxFs/7T1xFJGQMdtejkSyr8OEsnee/7Mnwe0cAIFWjuU7VKj1hcaSXBY5JcYsO
         E7hXke6coFDHhZ0cebSjfxqDQfCb6oHbdBFWltOWYi7MZfc4a2SdPpTYWmiuUFJo2oTr
         iGBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Su8bwbW9GO2R4BRFCQqHWlgftfbWN+H7P3oSimVQhtA=;
        b=DBKnTvEH1jGEItigvGHyxH4ixMZfgiomHO2z0m622MTbI11kaj4uI5ckrJUCkA10MW
         I6I+AntW9GBGovH7Zb2lVc6pTf8FOhFMGQFOm9etfhTYDzwLP8QAJEckyqfXj3Y3tey+
         Ua28aSeTbh0A40sAjIfB6wpjOP6Tgd5LmOiboiEZAN0BfDixZyQCA9dUPjeDbzFjO4/G
         qNjL05d71oO/YOMOP/p8Lea7wqQTE25CAyhE4I1woBelUqh7j1rMU0utvZDGHfLi5Q83
         Q2AQtVFdipuJYIfMA9gW7fRhRf5l7dCrKLxewBv9ZAJ1ngSRALCaGMcrWsQlEGXlAOIx
         xTYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWy9/4HAae60x3Cu/h81G3ooZ3zc1CxSGJd8sPVpzu5N/GhPKrn
	1+ig0ixlWb+iRDb904kRynA=
X-Google-Smtp-Source: APXvYqy7WPkiyFW4LGe1DH6gTJAXwY0jvaYy2jqLxYjLKo4dYWkX2LvoZLkAuQPdn0iqvTZS43lWzQ==
X-Received: by 2002:a67:63c2:: with SMTP id x185mr1706351vsb.166.1559131291809;
        Wed, 29 May 2019 05:01:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e318:: with SMTP id j24ls27809vsf.15.gmail; Wed, 29 May
 2019 05:01:31 -0700 (PDT)
X-Received: by 2002:a67:dd98:: with SMTP id i24mr27404809vsk.4.1559131291527;
        Wed, 29 May 2019 05:01:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559131291; cv=none;
        d=google.com; s=arc-20160816;
        b=pw9U7dL4rMmsF0iMvc/SXfURyxsNpjGv3ncDbyXCUoddJOGe9aeArs1N0Yp2rmAtSa
         sAf1v7SG5xtwcbNmJ58vWRl2v/ANw6PSY1qXfsrH5C78QonbdUGxn2Gvunl2VUCsgxN/
         QN2mwcJ0erLvXT24uiGvMd/FhT0NYC/ig2Fxa0xMoNt1R4XUpvnc0/ixDSbcpxw5fNu3
         5ScfbVqRah1JHeIrURQcEoyoZl+zzlesPPYe1PAxypaIkRLqaTntyUBYt8g4F7St9EJY
         wAVDTTJ6aQHnrIWBcEwaZ3CX1RibRe4oYsMZh/2iZwu6I9y73UXFF+UCEbEA2On7ra+o
         HGdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=YPtPUNuDX71Si0dZ9/GsA4yGWJlCJusvLAiyqICMNXY=;
        b=y+tA1qvylj8Y3OV2ZDgQXek29fLvxtKthWFoAfiYm8sW982rRmCOtoh+EC14IN0pJr
         dQJ2jiBT08Rhpv753/2Eob3QlJnky6FDRFTdBke+6asxUfw2RthoEEIz0u2rMvAxJWPP
         Ji+1RXxyues5psVLib3JC02uUtPNsnHEdhNE86OhbG6OYevptVKesEt8/lsweAuiLr+0
         vQFYVHv1DwACqrVHaHA1qBPbUkM5RmH3KlFwLZ2q+HI8YUziRDjlOUUTVQoAXYTb3QdY
         fxUGRH8GnSxOSTQea5eWITwxtzu87BysmYmzPVmMNoCsFKGjaSypoGkvD6xZsDU7ooN0
         2GIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Nzz9NhjF;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id b63si877158vka.2.2019.05.29.05.01.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 29 May 2019 05:01:31 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=hirez.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.90_1 #2 (Red Hat Linux))
	id 1hVxGi-0003lQ-Tc; Wed, 29 May 2019 12:01:21 +0000
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 45DDD201DA657; Wed, 29 May 2019 14:01:18 +0200 (CEST)
Date: Wed, 29 May 2019 14:01:18 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: David Laight <David.Laight@ACULAB.COM>
Cc: 'Dmitry Vyukov' <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for
 KASAN
Message-ID: <20190529120118.GQ2623@hirez.programming.kicks-ass.net>
References: <20190528163258.260144-1-elver@google.com>
 <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com>
 <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
 <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com>
 <20190529100116.GM2623@hirez.programming.kicks-ass.net>
 <CANpmjNMvwAny54udYCHfBw1+aphrQmiiTJxqDq7q=h+6fvpO4w@mail.gmail.com>
 <20190529103010.GP2623@hirez.programming.kicks-ass.net>
 <CACT4Y+aVB3jK_M0-2D_QTq=nncVXTsNp77kjSwBwjqn-3hAJmA@mail.gmail.com>
 <a0157a8d778a48b7ba3935f3e6840d30@AcuMS.aculab.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a0157a8d778a48b7ba3935f3e6840d30@AcuMS.aculab.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=Nzz9NhjF;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, May 29, 2019 at 11:20:56AM +0000, David Laight wrote:
> From: Dmitry Vyukov
> > Sent: 29 May 2019 11:57

> > Interesting. Does an address passed to bitops also should be aligned,
> > or alignment is supposed to be handled by bitops themselves?
> 
> The bitops are defined on 'long []' and it is expected to be aligned.
> Any code that casts the argument is likely to be broken on big-endian.
> I did a quick grep a few weeks ago and found some very dubious code.
> Not all the casts seemed to be on code that was LE only (although
> I didn't try to find out what the casts were from).
> 
> The alignment trap on x86 could be avoided by only ever requesting 32bit
> cycles - and assuming the buffer is always 32bit aligned (eg int []).
> But on BE passing an 'int []' is just so wrong ....

Right, but as argued elsewhere, I feel we should clean up the dubious
code instead of enabling it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529120118.GQ2623%40hirez.programming.kicks-ass.net.
For more options, visit https://groups.google.com/d/optout.
