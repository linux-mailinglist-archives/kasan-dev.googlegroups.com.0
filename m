Return-Path: <kasan-dev+bncBCMIZB7QWENRBOM25P2QKGQEPUKXPLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id DAAB31CFA78
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 18:22:18 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id l15sf13546628ilj.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 09:22:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589300537; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z36WLBLgQisQySllPZYQQybq0L+FJdwd07pIybW3Jx5miDP8IR7H4Yz30GZWYZWtfV
         PcwQgwjN0PUuDxfV4w9gHL909eZyPf4hYSu4JBoJ1W18+BLIO06saiytQXhL3FgJ74db
         C4FsjcMiiUmli1kMZlplLhtDWJF8spYB5eWQMUBUMiSCXsJmUJExjq/X9i7hqI5DhAjZ
         5kCKJZuGyN0LZKL7H0cU+fKpaFtzGRoP5pZOBW4/1EkJyZEupQL3cHDoG5G4YCjFPQL9
         oqrSxotITGqUR9A7Lk6j0JqZSa+UC3kfjqDmmMnLyBUoQ08InOg0vMDt2pmv+B61+mwM
         ecHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iQmuLzsF8EJYlH5+XoZVVwb41KZq8cFPfCw57152sOI=;
        b=HFn3DLlC+HjvHZfeYal4fhzpBzJ2m57zn6A/P/9n6LvjBbDzAgaue/fSoHm/rf94iV
         TiCgN4RBkz4Ir6pOft8rb/rCVxzB7JjmIFjcfd1FCR83pYgXpuCxkomfTNEqyNRnUoBo
         +Hu6P55GZwhkzrSikCB+AlRQ8Q8tSvoPd/efGWEkYJhBpkTonI1FFyyjMN3U/ToyfAsk
         T7Og9LyPJh/Vs54UQwaFcX4smKqqKLC/TNemSz/R5lPYbIdjN4UGwHyCraxOg/SsgmnB
         FFbQ5xaHfpY2xTxnf2t28irjSLXQe9+xbzDOoXi3hZ4CGAlFyMVbfllzo3JGmxIK8xOT
         eTig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="qpJ2/f9j";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iQmuLzsF8EJYlH5+XoZVVwb41KZq8cFPfCw57152sOI=;
        b=p8YMFT/00fOyN5+QGGRp2zo4ffqUw6XmDlNYFK44eIbG1LtQuNyFmF9M8hbAQl3tGI
         CrvYEu9kML2RW1xFa5qNmmnMDRM2vN1SN5KDOw9bVsB//AKG6syW7NYptwpCaDWhpzH0
         h7saClGgTvtoycOJZheOnvv4z4eNkGOC3YD/u6QlEVZN21/ipnM3gJcfOZfUQnZjFRbv
         52AngIayDBvBhTm+0DYyOw69IaqlyTTSgfxaOB5oGtVVGaWNqZB6nWzkRP0sXRDREeQg
         iQ+7XFGPTEXjMBBKxqe4QNxPWh/R98LopyjFkRiqaLybTUo8r9frEgsZEGJMfSfuoe1l
         Yjdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iQmuLzsF8EJYlH5+XoZVVwb41KZq8cFPfCw57152sOI=;
        b=AZIgp+zZ3VE1cnNjB462xihxbFR6ibaocAjM8V8be14nm7mHuFAE93gHcSwTn98AUP
         NM5acEXWVufYcFD0Z4DHjrhj2+YEUUI5eWqfVTwqys+EWQae3A2oJfn3DtvXISxcESN4
         sIPZhhc83wCNZSRX0lJD3iT5PTVbwWXPXFxZLL4me+4GCEF13roZkXC+MCe3bOCJ67sh
         Z4Hv0za+RlNhlSMxcS5LarzFQQGKjKU2gcI8uzthHIv7bLGhi9tp7qe+liIdf8Jjh1MA
         /+ugHT4OrNbaAJNbhOnvPdMJUjc0qezWEfM35vB8U0fERRFKMmuDKtEOaHcslyTka4IY
         d+Sg==
X-Gm-Message-State: AGi0PuZ/1+KKm1urDvGRSpTFhDmpvrm5A1GJxfTD1qb2nso1FY1rTRzH
	3LzstoiTGHqCFiopgAdTITs=
X-Google-Smtp-Source: APiQypIBOXrwiZ14OcH3XIn7m+NZTM3Ifc4P9IKdEwMOpAwHfL0dVg732X6pQZMXMpEAG8c6l4xG4A==
X-Received: by 2002:a6b:f812:: with SMTP id o18mr20738123ioh.87.1589300537458;
        Tue, 12 May 2020 09:22:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3a9:: with SMTP id z9ls2073778jap.11.gmail; Tue, 12
 May 2020 09:22:16 -0700 (PDT)
X-Received: by 2002:a02:77c7:: with SMTP id g190mr4368560jac.14.1589300536506;
        Tue, 12 May 2020 09:22:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589300536; cv=none;
        d=google.com; s=arc-20160816;
        b=BpJaWlLxBpZ/9wP7kmeteAYHUgSPD2C9VSyOIysgbJBGePu6/QFRRWHzDDWHXa+WsC
         xuTaAl+xGQM/LyuioO0i65mo6rUwI4q4CaphohmZFPH6GHp7njCeoSDcM1f2H7ZotDPx
         O7AOk3W5E4o1cSh4BH91LWR7JTBr+z3lAYndysLEEyQXnDdv6ea6ZAXTiyFo04859hEV
         l7NiKuo2fwAOx+nNRdUhAhoOsN3eN7Zwz5bi2f2uMSUxDSWgQaE5162OlVpbLxA4bvBk
         5zc9EL3dvM73QELqtM/nEwRKZwg3atHPkdK0VyvSNaKs+kJPWC0EiHpyaBi7zwKo/QpZ
         ncbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UEnxThmKo9eCKn9Sp5S//SCIqt2NuliFRLICXjN1F8w=;
        b=tHptnOBQnXy/MaUJ8mLy7XQYovm5UknY1/fuHHoEwsrIl0wb7iZZt6hZODV6PglT3Q
         lLSD1KImSTzPDqHtQrIGT/5zskO7vNTJsrAmG7AiKXjJ04DnGQRQlxIZQ1K4RAxpnyLx
         siLEn14jcs5Z3ncpolwte/MkMZntK3nOdwMLdvBugIIOtv1Xo7BlfUYcVNcm+aULPcpJ
         VDGRI0pAXGC1p0pIY8fRVNgP/Z+rN0lmgzf9FYiILjQTPVXkm8ss2uRRrcZODnz22YHk
         c+ydoB/f+Av6bkZX275jY4L5L4qBjfv1kdPcM7In3q491ci2OF6VnKN+qVVnOXhCv7a0
         XtWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="qpJ2/f9j";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id x4si383319iof.0.2020.05.12.09.22.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 May 2020 09:22:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id a136so5242088qkg.6
        for <kasan-dev@googlegroups.com>; Tue, 12 May 2020 09:22:16 -0700 (PDT)
X-Received: by 2002:a37:9d55:: with SMTP id g82mr18935803qke.407.1589300535553;
 Tue, 12 May 2020 09:22:15 -0700 (PDT)
MIME-Version: 1.0
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
 <20200511180527.GZ2869@paulmck-ThinkPad-P72> <1589250993.19238.22.camel@mtksdccf07>
 <CACT4Y+b6ZfmZG3YYC_TkoeGaAQjSEKvF4dZ9vHzTx5iokD4zTQ@mail.gmail.com>
 <20200512142541.GD2869@paulmck-ThinkPad-P72> <CACT4Y+ZfzLhcG2Wy_iEMB=hJ5k=ib+X-m29jDG2Jcs7S-TPX=w@mail.gmail.com>
 <20200512161422.GG2869@paulmck-ThinkPad-P72>
In-Reply-To: <20200512161422.GG2869@paulmck-ThinkPad-P72>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 May 2020 18:22:04 +0200
Message-ID: <CACT4Y+aWNDntO6+Rhn0a-4N1gLOTe5UzYB9m5TnkFxG_L15cXA@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Josh Triplett <josh@joshtriplett.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="qpJ2/f9j";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, May 12, 2020 at 6:14 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > > > This feature will record first and last call_rcu() call stack and
> > > > > > > print two call_rcu() call stack in KASAN report.
> > > > > >
> > > > > > Suppose that a given rcu_head structure is passed to call_rcu(), then
> > > > > > the grace period elapses, the callback is invoked, and the enclosing
> > > > > > data structure is freed.  But then that same region of memory is
> > > > > > immediately reallocated as the same type of structure and again
> > > > > > passed to call_rcu(), and that this cycle repeats several times.
> > > > > >
> > > > > > Would the first call stack forever be associated with the first
> > > > > > call_rcu() in this series?  If so, wouldn't the last two usually
> > > > > > be the most useful?  Or am I unclear on the use case?
> > > >
> > > > 2 points here:
> > > >
> > > > 1. With KASAN the object won't be immediately reallocated. KASAN has
> > > > 'quarantine' to delay reuse of heap objects. It is assumed that the
> > > > object is still in quarantine when we detect a use-after-free. In such
> > > > a case we will have proper call_rcu stacks as well.
> > > > It is possible that the object is not in quarantine already and was
> > > > reused several times (quarantine is not infinite), but then KASAN will
> > > > report non-sense stacks for allocation/free as well. So wrong call_rcu
> > > > stacks are less of a problem in such cases.
> > > >
> > > > 2. We would like to memorize 2 last call_rcu stacks regardless, but we
> > > > just don't have a good place for the index (bit which of the 2 is the
> > > > one to overwrite). Probably could shove it into some existing field,
> > > > but then will require atomic operations, etc.
> > > >
> > > > Nobody knows how well/bad it will work. I think we need to get the
> > > > first version in, deploy on syzbot, accumulate some base of example
> > > > reports and iterate from there.
> > >
> > > If I understood the stack-index point below, why not just move the
> > > previous stackm index to clobber the previous-to-previous stack index,
> > > then put the current stack index into the spot thus opened up?
> >
> > We don't have any index in this change (don't have memory for such index).
> > The pseudo code is"
> >
> > u32 aux_stacks[2]; // = {0,0}
> >
> > if (aux_stacks[0] != 0)
> >     aux_stacks[0] = stack;
> > else
> >    aux_stacks[1] = stack;
>
> I was thinking in terms of something like this:
>
> u32 aux_stacks[2]; // = {0,0}
>
> if (aux_stacks[0] != 0) {
>     aux_stacks[0] = stack;
> } else {
>    if (aux_stacks[1])
>         aux_stacks[0] = aux_stacks[1];
>    aux_stacks[1] = stack;
> }
>
> Whether this actually makes sense in real life, I have no idea.
> The theory is that you want the last two stacks.  However, if these
> elements get cleared at kfree() time, then I could easily believe that
> the approach you already have (first and last) is the way to go.
>
> Just asking the question, not arguing for a change!

Oh, this is so obvious... in hindsight! :)

Walter, what do you think?

I would do this. I think latter stacks are generally more interesting
wrt shedding light on a bug. The first stack may even be "statically
known" (e.g. if object is always queued into a workqueue for some lazy
initialization during construction).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaWNDntO6%2BRhn0a-4N1gLOTe5UzYB9m5TnkFxG_L15cXA%40mail.gmail.com.
