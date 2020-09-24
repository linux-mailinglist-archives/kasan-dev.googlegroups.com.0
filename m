Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTM6WL5QKGQELUNULCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C9622770CB
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 14:21:34 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id c19sf1773405qkk.20
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 05:21:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600950093; cv=pass;
        d=google.com; s=arc-20160816;
        b=gRTInKL8TZWPmbeenhcPlrlAR5laHWhMYnq32s/bgCtAXMundzfYh7ypk2+k6DQke4
         S/QFLZ+w5hkyMRi0f8wZBG2xFgB8bhcEQBoOxC4isXp/ItKGqzEqViRqZaABdir9FGQp
         xtm9b5s9WZcRYD6x8hfolAI/HnRY5p+JhSMDcwtLtPt7LNym8u/kZfbSxDgh2M5KnoO1
         bAc36XrNKZt4yMvsrbBy8yH/qfWLgUt/kKTNJdRBFiC5fLINR6eHt1tONzyIzxWK9td/
         7e+Q9bRzt/1hBPJ5SCjEDvz/h/6JXZRQp+EirqZiOpv+NRSj+S5hzpcLKILWwIOqPk+0
         QxRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vrGW2zwnWw6Mv3cD3nc1KK6xn8ouGpOee/m/0PV5U4E=;
        b=c2IQnhXhVLy9RihTZDFA2DAyqH2Wu3unzmWy27NBnVtfagBnx1Y3BlvS/GneHwnZWA
         7Kz1Zu9eZhFXQPNnJL5rCcJliSKtJcUzFKykvwpzwHRZFE+PMNtMAveC+ocgLmU6CnAT
         H3DS2H1TE5xD8i/2AL/XwLLhBgNL30I6M0I6N+ZU8PAm8npbZDR/odXRItNzAABXJh6l
         5tFBPp/M07FZt/pcdrPVXqksGNl4znEClcvJ8J1sNeFbA7BScTjCAvta47Nbb7wWxl62
         onnOTtukWW8QL2/UH4Ugu6T9gEjBYB14Q7K/jB46iG95RPQFmr3+ag7eztdJMKv8e3HN
         5zkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wh7FyLoZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vrGW2zwnWw6Mv3cD3nc1KK6xn8ouGpOee/m/0PV5U4E=;
        b=I7ypO+afJvHw400TxQbbIaRtvCMW85A7R29PcJA6uywoh72bNoamJbUOBcdhT5LmKv
         n413k8dEw8SiTCuAeYdbKQPs8WaQjFnAQH551hD9RrQDd1KkrO3dWAC22YXpQKnAqjmy
         HJizR7GwlKbyMd8SZeRjKrGX+MDfcBcTqDp4g309dVAIaBqYQ9SIn4o49r4mFWdSBRKl
         V15SWSy0JCD63VupZttwaiyfmoaVdijy09qdydRjB2qoZGQrhpiYefwNT/u0GBc2AN2T
         kEBP6pFC/zafwdK5kuOQTG0yXvG1h1n3PZBYBLH86dJrkJkDWGr1fYH3d5iKvxUPAj6y
         Sjeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vrGW2zwnWw6Mv3cD3nc1KK6xn8ouGpOee/m/0PV5U4E=;
        b=POX4l009cImxKNUlxWDlzGKC7RJt5dfsjyzY+Q/IXQy+iD2liSKQmzkVgaMY/RZgfe
         cOcIQ9FGERDtHbiLxGFN28dQks8JzWRt0OmwdOF+OJX5Nblmc9T6uwdZhvypHm0D0BbY
         ZZE7koCJauQW8ApUpBJBPKLZtEBHq+5sg1v2UYrxEWuW9AhiuhM6uMgwq2WfT2xG7icc
         De/+IfxtMjOY4e+3i6mzdMoLq8wiza/+F7n1ZyP0R67yw5Pv9Ua0yhv47OkGul8wAY8Q
         DV66bYUCEE2P2Yd0Nh/TCnqIDnaQJVizvMgc3QUHc6zsxtVysxgYvueXf+kHu6G01NFW
         xMyA==
X-Gm-Message-State: AOAM533b7q4e1z4A2MCZehXFOUQr99W+kxKeEaMMdNaCXK8CJ5+6gPSr
	mXk4H5dH5UWamd6elKLByFs=
X-Google-Smtp-Source: ABdhPJyzM8Q9WynXmS7nvoiBl6F5Vs41cZm4Moe2juwdTo9mS2ZFYUtrm3kGqQiQpzV72AEqFjb9FA==
X-Received: by 2002:ac8:12c4:: with SMTP id b4mr5306979qtj.224.1600950093263;
        Thu, 24 Sep 2020 05:21:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:f50b:: with SMTP id l11ls1342911qkk.6.gmail; Thu, 24 Sep
 2020 05:21:32 -0700 (PDT)
X-Received: by 2002:a37:62c4:: with SMTP id w187mr4469673qkb.102.1600950092579;
        Thu, 24 Sep 2020 05:21:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600950092; cv=none;
        d=google.com; s=arc-20160816;
        b=I7zFp4/Fl/BgGAQ87goneXcoGYnfGTNAeB/XCbknJhVQ0VvIBOVqm2SOjpog9RS3oI
         reJAa5gUmzow8MjgrsLPEzPS+aChKtK6LB73DcUM0A0LJEXpahb56E+LkV7KKUKoj/UV
         nh6LNKMNg4qeIudxVlKN4/VjaZVB+F94T12aS8k9uvC9I1KPj28vQfvBbT1vf21KTDJD
         u6XTXDkV6O3arnfCAdtt2uZGfuwofP8sr2ARlu8K6dzP9XZzMV31DZPps1iPbMBecEBh
         5jeYT05IsfbsOJWIwTEKs3oZ7wl1XYz0uMNRoH/ierY+Zu5YCvFWR7CmZ29XZNnV1gTU
         cbhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SMi05EnEOfVdGhWpH6feACxpwD+9PbH32BgxYxZVzjg=;
        b=EFPUO3OhP5/+Q+ctXkb/a+ZSOqjEPQtTHh9DsH3iQvW+9bkgEHzDH4wvFKrgLsRfQP
         1ZkCOkV5OuEa/m+CGSLk2tIalxLZXtsXuMVqrgtGmqt+suJ9DJLDLQdusMGr/Ub5JFAq
         C889ENnsw0TKuCtod4ReOvJgT3ranWB8YJ85kOrOH1VIFeBLgrNNOHouftFpDmDEEy3h
         2Gq9PxfGeSHzO+z6/pSFtd0pAdfSNEnN4KtdoVQucZ0LO6K67zVIk9JDmPMgW7ifVIYw
         cLCFeHmw3gtSg2+TAk/Zhw3hZybbngTBLMo9YpudPusj47sQMyivEQyqRn1oayB9VH3W
         VNDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wh7FyLoZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id h17si155772qtu.2.2020.09.24.05.21.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 05:21:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id x14so3394154oic.9
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 05:21:32 -0700 (PDT)
X-Received: by 2002:aca:5158:: with SMTP id f85mr2388516oib.121.1600950091824;
 Thu, 24 Sep 2020 05:21:31 -0700 (PDT)
MIME-Version: 1.0
References: <20200924040513.31051-1-walter-zh.wu@mediatek.com>
 <CAG_fn=W2dcGKFKHpDXzNvbPUp3USYyWi2DEpEewboqYBodnSsQ@mail.gmail.com>
 <CANpmjNNmeqfMLZ0aFC49fHTYS5k7BqTZHP4FmDc=sfZe+j6bOg@mail.gmail.com> <CAG_fn=UFnju7qBw2FC8nGxTKQ5VB2QeG-DKik_t=eWzu6p+H6A@mail.gmail.com>
In-Reply-To: <CAG_fn=UFnju7qBw2FC8nGxTKQ5VB2QeG-DKik_t=eWzu6p+H6A@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Sep 2020 14:21:20 +0200
Message-ID: <CANpmjNP6gKToqT-EZM88ZoedWfyHr86EB2s9sKEtzTxBVQe_Lg@mail.gmail.com>
Subject: Re: [PATCH v4 3/6] kasan: print timer and workqueue stack
To: Alexander Potapenko <glider@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Wh7FyLoZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 24 Sep 2020 at 14:11, Alexander Potapenko <glider@google.com> wrote:
>
> On Thu, Sep 24, 2020 at 1:55 PM Marco Elver <elver@google.com> wrote:
> >
> > On Thu, 24 Sep 2020 at 13:47, Alexander Potapenko <glider@google.com> wrote:
> > >
> > > On Thu, Sep 24, 2020 at 6:05 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > >
> > > > The aux_stack[2] is reused to record the call_rcu() call stack,
> > > > timer init call stack, and enqueuing work call stacks. So that
> > > > we need to change the auxiliary stack title for common title,
> > > > print them in KASAN report.
> > > >
> > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > Suggested-by: Marco Elver <elver@google.com>
> > > > Acked-by: Marco Elver <elver@google.com>
> > > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > > > Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> > > > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > > > Cc: Alexander Potapenko <glider@google.com>
> > > > ---
> > > >
> > > > v2:
> > > > - Thanks for Marco suggestion.
> > > > - We modify aux stack title name in KASAN report
> > > >   in order to print call_rcu()/timer/workqueue stack.
> > > >
> > > > ---
> > > >  mm/kasan/report.c | 4 ++--
> > > >  1 file changed, 2 insertions(+), 2 deletions(-)
> > > >
> > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > index 4f49fa6cd1aa..886809d0a8dd 100644
> > > > --- a/mm/kasan/report.c
> > > > +++ b/mm/kasan/report.c
> > > > @@ -183,12 +183,12 @@ static void describe_object(struct kmem_cache *cache, void *object,
> > > >
> > > >  #ifdef CONFIG_KASAN_GENERIC
> > > >                 if (alloc_info->aux_stack[0]) {
> > > > -                       pr_err("Last call_rcu():\n");
> > > > +                       pr_err("Last potentially related work creation:\n");
> > >
> > > This doesn't have to be a work creation (expect more callers of
> > > kasan_record_aux_stack() in the future), so maybe change the wording
> > > here to "Last potentially related auxiliary stack"?
> >
> > I suggested "work creation" as it's the most precise for what it is
> > used for now.
>
> I see, then maybe my suggestion is premature.
>
> > What other users do you have in mind in future that are not work creation?
>
> I think saving stacks may help in any case where an object is reused
> for a different purpose without reallocation.
> SKBs, maybe?

I currently don't know, it's hard to say without having a report that
we can't debug without it.

The litmus test for if it's useful would probably be "do we need this
stacktrace to debug a use-after-free/double-free?". If the answer is
maybe (and not yes!), I'd err on the side of not going overboard with
these, because we only have limited storage anyway. "Work creation" is
a clear case of "we loose information to the original caller" and need
it to debug. But of course, if there are similar issues elsewhere, we
need to identify them and then decide if we need it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP6gKToqT-EZM88ZoedWfyHr86EB2s9sKEtzTxBVQe_Lg%40mail.gmail.com.
