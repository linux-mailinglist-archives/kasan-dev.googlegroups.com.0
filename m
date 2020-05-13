Return-Path: <kasan-dev+bncBDGPTM5BQUDRB4NL5X2QKGQEJOIPP4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 96DFB1D0498
	for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 04:05:38 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id m15sf8596730qka.20
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 19:05:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589335537; cv=pass;
        d=google.com; s=arc-20160816;
        b=w17SKL44INY7l69ukndkJo5lMgASYzOC6JEsaTyRddRwb80jTsutdh7g4Lfw+94DDf
         cZyLX4jPivF/woDXHzTWjFzcADHYDPpRwkCyyG3pTm3p72T9OF34naW7GzPNWmrc9arZ
         SVJbErPKOwD14yCpTze/xdy5PryIT9YsN3vMlfbkyi33uOtOKD62DcTh7+Q602UDRwnB
         V9aGKDWMCxehra952IigE1eJNCnl8/59zrL/rDqrq373HRAmQaKR+NNu/bQW/QcuU+6n
         U9+sZ2dsNliXj3xUwgp+Ee+nG5/R05igUK9ABU9q/+rZ/NgkKxKhv43nzYCuheWY6IQC
         xoBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=jwVu1t5NTCn4apC0ZuQvqX9pjTm421T69/3tDSwctVo=;
        b=ijT9ALwcB4kiMP8DxhgsEVBzxmTtYA9x+wv+aDXzaFlfAPm/5BHY02+vquy4cQpZnm
         A/DR3p3CCwNDbg0MJ95+rm3qEy9BcWLXXNZYCFvek7kG5wv16sPYk63tn+r/uRtmh10Y
         ufQGP7GZP2GLZ2WH7Oe6pg/1jewpK9HtbIGqvfaAqBakeOXhG5UC/+vyaGoRb4CrTfnO
         RchijlWECJtK5cDU9RA0Lq9kLsrWdB7YHoPQ2HldZCQ39PR0icuadMklFb2UZ5BudZi/
         4UFuCD3sOG6UPNI0q6KXOJqCqGIcZlmxdG7l0ZeiqJJ/SrdwOzx02GHeWvuyjdKBAEqv
         fRTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=JpFd5ST+;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jwVu1t5NTCn4apC0ZuQvqX9pjTm421T69/3tDSwctVo=;
        b=Fa8WCK+seK9BA7EalW+FiR6iLTFOlv8Fp2QhIsM54cwpa+2oojDJLfuKvFGpjCEiAE
         R56aKwq2HHKYGFKtkr18pIYf1iu3RJ3VkqgM5lZdhNSDPG8Dx792vCR2w4FG6L+pxAxF
         vZFFpEPqc07licvzA9yB3JXS9joqg+E/Vda/pHVacVJJSi2jrHmyWvPX9sWEa2t694SF
         1sro9IOsJ+CiQiHEihhAnk7BWniEp0vi02YKNuDwzZGNj9TsYi8ZNUJ/+D4acbv0YEa9
         AoG0Lx6vetyEjQ5MHwSw84amBCD7At7KmRp/3tYGvKFjbZ98PO9mY8odrec17Xj7Vdnr
         PgZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jwVu1t5NTCn4apC0ZuQvqX9pjTm421T69/3tDSwctVo=;
        b=EyqN75bXSCZxgPtx170xf6/mGoj08gVFM8+I8rNmQxN2Gcpfh/WE+bqFlnNJH9IGfy
         fXmsEpWLor4t6pYOxgLgGJGOVEywDwwZZTc2AVxH8nAcqY8kw4MsZpCY813EIm+ZzgpQ
         PFuJQnXaPxD2PoWTtCnrEYMNj4f9Z5j7Dx8q+8JLfTJgIcV9Fwf7zlfMyS9dPb8rpfx0
         BArAouPYI3WyoIiOYmffskgX3BlRjpcOKZxDp6CLj3DJYhvShdeScbH+waUYinsjgdol
         u+L+tydtyt6Ue7QAaLWuET54kVASyKGH90I/YsSQf7g1cmIAdfJhw0OjN3ZIkXHElDRg
         O4wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYj3GnxPOhG320/tNeP8lHUYYaD9x52ubCAnSw5hD70ECch8kNo
	DTqeQjOyKD5HWzxTdjFzqC8=
X-Google-Smtp-Source: APiQypIJ0vQQLRmE/s3grAgbYXzYNXNk33MZD5MWfH7kv6/YtB+PVv6ixWqgEb5h6GJ34Wue2G9eOw==
X-Received: by 2002:aed:3009:: with SMTP id 9mr25221401qte.191.1589335537447;
        Tue, 12 May 2020 19:05:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4182:: with SMTP id e2ls124428qvp.8.gmail; Tue, 12 May
 2020 19:05:37 -0700 (PDT)
X-Received: by 2002:a0c:b259:: with SMTP id k25mr1405490qve.178.1589335537160;
        Tue, 12 May 2020 19:05:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589335537; cv=none;
        d=google.com; s=arc-20160816;
        b=ew9iaD+PLMlC3lTzNdwWcWqTyD5xWYR6OTRaxzJQYPTny+lVnUA3UyD/YrSQXwkpKx
         Iw3zMRYm90V+2qOXnlwjlgiN7U83JI1MqpjY4LzXFLfzikOnzAc8Ub0ix1CRQxSorYsK
         QsttnbBFB43yikBOrCs9JWqPI7qRoVhEyCnvl02fcUG4MuMjvPeyu+T1/XzvbMrzM4+X
         Q+1PHLgVFfIeVzNDOqOKJZe739kqcZYISkmGpB0XVxqG5O9N+YIDKbN4Oz/W5kvTpSgF
         4ePqozo3MMM8pMVg5a7dutZhr6jMSWjQ5WQ8W00Xty+YRvM5wbyOnkzjF/5BCtvY9bmL
         PQNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=096wrzVA6wz4JNcGHZfNakkofpMPOvUZEm4oZoXOkWA=;
        b=SoHM07UXzbmsq87CsZyUSuXSGS7OQARhzdwYBVys41MO+q3DohqBs569UXGMSesd4k
         j/QEGILryPEdDiPH3d0+u6xN4UXCc4a2pcWhM+H6VrCHT+9UHKpOr547FMQdnYa95bh1
         /HyKyCDLmeVzrsul9ceQD/wh02v8wX+gdndsT2tRmd8wOjEXCyMjtU62eRZoCkINeoap
         Lua+bIAPuCAwmpW3eGhptN0X095QKKs3p3IAfNhP8C2fjwTcCqY4E4XahNdIsjpwBSsF
         ++7DiCNIarlsVtGFUjIPqu3rSvbAy4YxbQhIwHGxYaAjVg1N5/PbzG9vhXWmoxgB1jhY
         1W3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=JpFd5ST+;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id f16si1047920qte.3.2020.05.12.19.05.36
        for <kasan-dev@googlegroups.com>;
        Tue, 12 May 2020 19:05:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: e4d4ff2ba2164878b27d683e16db2781-20200513
X-UUID: e4d4ff2ba2164878b27d683e16db2781-20200513
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1593172682; Wed, 13 May 2020 10:05:32 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 13 May 2020 10:05:30 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 13 May 2020 10:05:30 +0800
Message-ID: <1589335531.19238.52.camel@mtksdccf07>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Matthias
 Brugger <matthias.bgg@gmail.com>, Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, Andrew
 Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, "Linux
 ARM" <linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 13 May 2020 10:05:31 +0800
In-Reply-To: <CACT4Y+aWNDntO6+Rhn0a-4N1gLOTe5UzYB9m5TnkFxG_L15cXA@mail.gmail.com>
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
	 <20200511180527.GZ2869@paulmck-ThinkPad-P72>
	 <1589250993.19238.22.camel@mtksdccf07>
	 <CACT4Y+b6ZfmZG3YYC_TkoeGaAQjSEKvF4dZ9vHzTx5iokD4zTQ@mail.gmail.com>
	 <20200512142541.GD2869@paulmck-ThinkPad-P72>
	 <CACT4Y+ZfzLhcG2Wy_iEMB=hJ5k=ib+X-m29jDG2Jcs7S-TPX=w@mail.gmail.com>
	 <20200512161422.GG2869@paulmck-ThinkPad-P72>
	 <CACT4Y+aWNDntO6+Rhn0a-4N1gLOTe5UzYB9m5TnkFxG_L15cXA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=JpFd5ST+;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2020-05-12 at 18:22 +0200, Dmitry Vyukov wrote:
> On Tue, May 12, 2020 at 6:14 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > > > > This feature will record first and last call_rcu() call stack and
> > > > > > > > print two call_rcu() call stack in KASAN report.
> > > > > > >
> > > > > > > Suppose that a given rcu_head structure is passed to call_rcu(), then
> > > > > > > the grace period elapses, the callback is invoked, and the enclosing
> > > > > > > data structure is freed.  But then that same region of memory is
> > > > > > > immediately reallocated as the same type of structure and again
> > > > > > > passed to call_rcu(), and that this cycle repeats several times.
> > > > > > >
> > > > > > > Would the first call stack forever be associated with the first
> > > > > > > call_rcu() in this series?  If so, wouldn't the last two usually
> > > > > > > be the most useful?  Or am I unclear on the use case?
> > > > >
> > > > > 2 points here:
> > > > >
> > > > > 1. With KASAN the object won't be immediately reallocated. KASAN has
> > > > > 'quarantine' to delay reuse of heap objects. It is assumed that the
> > > > > object is still in quarantine when we detect a use-after-free. In such
> > > > > a case we will have proper call_rcu stacks as well.
> > > > > It is possible that the object is not in quarantine already and was
> > > > > reused several times (quarantine is not infinite), but then KASAN will
> > > > > report non-sense stacks for allocation/free as well. So wrong call_rcu
> > > > > stacks are less of a problem in such cases.
> > > > >
> > > > > 2. We would like to memorize 2 last call_rcu stacks regardless, but we
> > > > > just don't have a good place for the index (bit which of the 2 is the
> > > > > one to overwrite). Probably could shove it into some existing field,
> > > > > but then will require atomic operations, etc.
> > > > >
> > > > > Nobody knows how well/bad it will work. I think we need to get the
> > > > > first version in, deploy on syzbot, accumulate some base of example
> > > > > reports and iterate from there.
> > > >
> > > > If I understood the stack-index point below, why not just move the
> > > > previous stackm index to clobber the previous-to-previous stack index,
> > > > then put the current stack index into the spot thus opened up?
> > >
> > > We don't have any index in this change (don't have memory for such index).
> > > The pseudo code is"
> > >
> > > u32 aux_stacks[2]; // = {0,0}
> > >
> > > if (aux_stacks[0] != 0)
> > >     aux_stacks[0] = stack;
> > > else
> > >    aux_stacks[1] = stack;
> >
> > I was thinking in terms of something like this:
> >
> > u32 aux_stacks[2]; // = {0,0}
> >
> > if (aux_stacks[0] != 0) {
> >     aux_stacks[0] = stack;
> > } else {
> >    if (aux_stacks[1])
> >         aux_stacks[0] = aux_stacks[1];
> >    aux_stacks[1] = stack;
> > }
> >
> > Whether this actually makes sense in real life, I have no idea.
> > The theory is that you want the last two stacks.  However, if these
> > elements get cleared at kfree() time, then I could easily believe that
> > the approach you already have (first and last) is the way to go.
> >
> > Just asking the question, not arguing for a change!
> 
> Oh, this is so obvious... in hindsight! :)
> 
> Walter, what do you think?
> 

u32 aux_stacks[2]; // = {0,0}

if (aux_stacks[0] != 0) {
     aux_stacks[0] = stack;
} else {
    if (aux_stacks[1])
         aux_stacks[0] = aux_stacks[1];
    aux_stacks[1] = stack;
}

Hmm...why I think it will always cover aux_stacks[0] after aux_stacks[0]
has stack, it should not record last two stacks?

How about this:

u32 aux_stacks[2]; // = {0,0}

if (aux_stacks[1])
    aux_stacks[0] = aux_stacks[1];
aux_stacks[1] = stack;

> I would do this. I think latter stacks are generally more interesting
> wrt shedding light on a bug. The first stack may even be "statically
> known" (e.g. if object is always queued into a workqueue for some lazy
> initialization during construction).

I think it make more sense to record latter stack, too.

Thanks for your and Paul's suggestion.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1589335531.19238.52.camel%40mtksdccf07.
