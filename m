Return-Path: <kasan-dev+bncBCV5TUXXRUIBBAU5T33QKGQEIPYEDTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 150FD1F9B74
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 17:06:44 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id a20sf13490278pfa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 08:06:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592233602; cv=pass;
        d=google.com; s=arc-20160816;
        b=nyn5RElxSc5OUDu9BjHuSkiMRGU2S7MtKKNFD+mjLaQLSjJRVIst5SQ/fINtVNWptO
         HOvRf566U7IiflPLcrv+3Xdr0VnLLkxoOCTJ26l+ElJVUwW6v8CLLjWo6/hltJ0lrO0G
         QmW2TMVkjTGHgSuu17ocvA0N/ldbHGDDv/mVFuRCQlo++vrhwheQ+VN3rdCbdol78GfV
         PjORMV4GUZb8e5HUsEypmAt3a90ujqx3kLQOLs4ht1VHnnoVpTw1aBQl7BiMuFgTJMbW
         eCiqoGwlbqzwoGQvO1ieWDUM74Ei3kmUrrdb8vnAgVkpGNQfJw1OOgScbadcrSF0e2dJ
         VwRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2sV5C/n+h+vmcQNWzVc99o3PdKgYBjTcOd3d0z8VZGg=;
        b=vncQEgaD1w4+vHPJa9HJC30qWkRtdNSc2lMQKzZe1FJ7YeJl0o8iCHLluwoe2vemv1
         3IvpN/SGucMVP6tNkGO1Eom2qDsmL7ynRJnz40CSuZdpDiNfQmA6yjFiIDWpQmgitZwP
         Neph/eB0HF5BwcIv9WhHC7f6lpAvoWiuqP8ZnyWm7N5Kr4z4XIADHEuNMoe8gBSdQ3wc
         UaZncIepupx3a+Wae97JifNfbfugd2NtLz48TLwRGHzVlX3+ZnY1uQjHYzy9yhOVvjGp
         +9GL1y4L1RGMNfW7dUHZYjLWsacXmtQR6elvqwswQCXc0Qi6Yno+cj//VdxoXpjfUc9g
         jD6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=emIMXaZp;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2sV5C/n+h+vmcQNWzVc99o3PdKgYBjTcOd3d0z8VZGg=;
        b=lH0+KD2uuzw+4zmpGVtVFazjbiiMID4J7m4XsDueyvmQfFxu5wkwr3mr28d+6XOR0c
         QZ0lFez7hDEBsM6sonfrmW3nq1G6TaBRcGtZm5GPlWvfWn4/PZ8Y2Y/VTy5Xtqj3Ga9D
         fNw0SVT1btHDLDI2gaIdGodqYAvMJoByEocZIFVQR7AfQ8QLWU194lI6I7L/0w40e9Tc
         9bKpKxiTrRyjSbLFigDw20iRgiDPApEljTytzXqYvwKSIzIIoWux3uWrHBSYCDyfvcsl
         2fubRg/4N951/xhbI4DJRIFaVrpoFlh8dycw41fybV/0dGombU9KLezHy+HgyHAD+wtG
         nF/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2sV5C/n+h+vmcQNWzVc99o3PdKgYBjTcOd3d0z8VZGg=;
        b=s4tChTfSMKHQJJxu9QzEzZTO1D9RSrTdy9qHmvgjyUmzV+Qr9l75YkbPvAXUI6SnPh
         d5fzRAdhN6lQKh6g23WNz7GcsMUo3tAWTt17YcPGFwq6rlkVzlkkAXnUUF2a233Dqlu6
         bwBeIgiS2uJP2v0lS2Qr6F4r9yMzv1nXy/w9GLi6PW+M+TakzCUTEPn8FY7d71utuWTH
         sRqfPXBz2YhxNwdg27CQbhgTStmejXS1tyysGoG4hg4mvpwMpoQ16bMg7vapnKUeowSp
         6NpTjQ8IBCCzx6LsSElzg1VCDJC3hqNQzr1ZfEIUATwDsSJ11+MexNQyYB1AWmKY063U
         EtEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VBxCbVVgiIagOXWNrBcyPpq5DYjhqQhYoVPHTDM4KAI++sJxi
	DzUgVAdkzZ+kOayPx/eWpv8=
X-Google-Smtp-Source: ABdhPJwf3CfzguyVv4Ps1JQh7wTy0eJf8sRq0VmGp4VRwCdedFjeRFNCETRk5K5Qgx4zTM0DV4qU3g==
X-Received: by 2002:a63:1641:: with SMTP id 1mr18417374pgw.370.1592233602709;
        Mon, 15 Jun 2020 08:06:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:63d0:: with SMTP id n16ls3486584pgv.6.gmail; Mon, 15 Jun
 2020 08:06:42 -0700 (PDT)
X-Received: by 2002:a63:546:: with SMTP id 67mr22749467pgf.364.1592233602176;
        Mon, 15 Jun 2020 08:06:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592233602; cv=none;
        d=google.com; s=arc-20160816;
        b=iJ7zg5+8+XS/1BcJklN03kQkvqdJq0Oi1vynnTiU1DSSJ2fCR1d5DhZ0tqdMxwHWIz
         pET0KNIK/3EZnI275fV4zzdoAhkHI4Qmdbp8OcVNOCxIMxSoTp+XCq91LwAPqm3c2alb
         5F+tTCs+3QkW+xL3Y9rF8TXe/SgN8lqaqjXZq5eqj0PK9HAK1W8z+gVN9xfOOeLzAS1W
         caVwo3CIbKlV6cY1mC56adDuTlZ8mWuC8j7uqLdzSC9+eX6yL7eilJtdKBHo6ygXRL0T
         l1ypfkEQPzEkSB/e0SMW9befhMUPxvWeBd5TGxDWsCBY02rPMPSCQ5MvNJWoHOJCaxRM
         nRMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pdG9YeyyHFpa+KDZLF5PuhAEcav4b8GAmq2VKm/tnYI=;
        b=eqnoMWoqL9Y1sVMhMnyT4FM1oZq6AigJMAFQh9zSNuqJGyu5cz++i+2y0sPxg4Ot0e
         ToLrFgDaG52IC+ecu16d9B1SrB61/ggaWcx9yYNhvAmULy2nYj9zzVVbKyJZt5KSuQM/
         +DmEPVmDPMGqxEvAWkfui3Hc0w6x4bBUs5dK3vwjaVdLrL+fbVTtcCNdWDJRIgpOMvz9
         h0kxQUqeLXX/oAWIaYh5mRH3eokQIoMflUkkhNkKIDjBK58PNIgBs5mFscaKKTuDjnUz
         0nvwjLdRMHut2YWRMHBQcTV+WX/4jUEQnoYwln7mf0PLVTNzylLZsq8U0VlP3OavRlXG
         H9kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=emIMXaZp;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id w15si711955pjn.0.2020.06.15.08.06.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 08:06:42 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jkqh7-00034R-BW; Mon, 15 Jun 2020 15:06:41 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 51A5E30604B;
	Mon, 15 Jun 2020 17:06:39 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3723B203C3761; Mon, 15 Jun 2020 17:06:39 +0200 (CEST)
Date: Mon, 15 Jun 2020 17:06:39 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Qian Cai <cai@lca.pw>
Cc: Marco Elver <elver@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	the arch/x86 maintainers <x86@kernel.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 0/8] x86/entry: KCSAN/KASAN/UBSAN vs noinstr
Message-ID: <20200615150639.GX2531@hirez.programming.kicks-ass.net>
References: <20200604102241.466509982@infradead.org>
 <CANpmjNPEXdGV-ZRYrVieJJsA01QATH+1vUixirocwKGDMsuEWQ@mail.gmail.com>
 <CANpmjNP2ayM6Oehw08yFM4+5xTjXWcCT7P3u7FL=cCMxFJNkXw@mail.gmail.com>
 <20200615145718.GA1091@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615145718.GA1091@lca.pw>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=emIMXaZp;
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

On Mon, Jun 15, 2020 at 10:57:18AM -0400, Qian Cai wrote:
> On Mon, Jun 15, 2020 at 12:07:34PM +0200, 'Marco Elver' via kasan-dev wrote:
> > On Thu, 4 Jun 2020 at 13:01, Marco Elver <elver@google.com> wrote:
> > >
> > > On Thu, 4 Jun 2020 at 12:25, Peter Zijlstra <peterz@infradead.org> wrote:
> > > >
> > > > Hai,
> > > >
> > > > Here's the remaining few patches to make KCSAN/KASAN and UBSAN work with noinstr.
> > >
> > > Thanks for assembling the series!
> > >
> > > For where it's missing (1,2,3 and last one):
> > >
> > > Acked-by: Marco Elver <elver@google.com>
> > 
> > Where was this series supposed to go? I can't find it on any tree yet.
> > 
> > How urgent is this? Boot-test seems fine without this, but likely
> > doesn't hit the corner cases. Syzbot will likely find them, and if we
> > noticeably end up breaking various sanitizers without this, I'd
> > consider this urgent.
> 
> Today's linux-next had a lot of those with this .config,
> 
> https://raw.githubusercontent.com/cailca/linux-mm/master/x86.config
> 
> Wondering if this patchset will cure them all?

Many, not all, you also need:

  https://lkml.kernel.org/r/20200603114051.896465666@infradead.org

and then I think you're down to only 1 kasan thing. But also read this
thread:

  https://lkml.kernel.org/r/20200611215812.GF4496@worktop.programming.kicks-ass.net

latest version of that actual patch here:

  https://lkml.kernel.org/r/20200612143034.933422660@infradead.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615150639.GX2531%40hirez.programming.kicks-ass.net.
