Return-Path: <kasan-dev+bncBCMIZB7QWENRB7FR532QKGQEJAEPTJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 98C7D1D0906
	for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 08:51:41 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id l9sf6931168uao.12
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 23:51:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589352700; cv=pass;
        d=google.com; s=arc-20160816;
        b=ik8wHW8kchB08qYj9MT3xpP4zMcG0lGqZ16YloCdqx2nnIn75AEM9rtg8BLOagh3ja
         Or1OLbeAZlAu8K8fvPdQgN/THATMxCaS8tHGCX/+w3qlFI+TF+KnKNfDNH06GhRW2PQB
         ZlWMC7QsEHX5xSN3z8VWEoebGtnEtUzJKtxx6WVgVGJ2V6LHvmpeaQGX7UqDTQ6LPpOt
         ljn3F50VcrEJhhyIRPfCG1UJL/Zh752w5s1MnEE27IP6BNGUy+Bv5p2fPbIGFlwNbGJU
         qYMh6SABnG+NFgJEkH1s2zNfmU9/nxXsLxuiDi4ReNhSD1Bbj+5cw3UEYWdRWQnGf9jL
         6zWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1DR9eHEhS0OESK+XGbyGDagsM8wiojtagCgd3i1AXJA=;
        b=xWXVDhziIH7gDyvRLie2IgXmsjIpAtM8aCoSUepzoT2qzy3ORubhtRjIcxUVm5TFn0
         C60KFBqSb1kl0C+E6iSnONHTfQtqLkRQsqR3GtsXcHfnfBS0791hXzwim8RxWiK5ANoy
         RfLY8AFV7bPJJ3hs27JUHovkixvx1lvYN9yF92RN/mX0N9+VDIbtU6uePvgG6dNVzRm5
         YnEuYAm/tOEzdaRu7Brf8HIscux09ZqySZiK1Z6ronl65dB+LYPU1fzODldQ24BGCrjP
         4BjElrbcuGh9zl2Ncgfkeah91MoCQyLFcBBAmuyjeBnzEqDWBCXG8oao8dl3AYHTSAWI
         7z0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MVQ6mRj0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1DR9eHEhS0OESK+XGbyGDagsM8wiojtagCgd3i1AXJA=;
        b=gXWvuoeXYd2gcB14gjLAyflkKWIK3v8KSS+GC0gpE6thfEyss/pQywhFAuvnY4mr0e
         b64DOrrVtNl06e3ly+QSiCXURJVT8IHw8cZ/zIGyHwWXJzQK9BvUnbolOdPcDqDIXINO
         2GOtizsUZTQkQP7mblu3HiszykFnmlROzO6p+8sUWnKzsljL5RJk8z/RMrzhbuuub7hT
         SpIXz3Eu+qFHcPOdFm3d9/74QQjgsy9gvo5z9azFKhfA3JQQteHaZLke8Bl5qKyzlMDx
         4Gm05XTQm17xsQuaJCXH5SbZvrAWnPDFGTi3gFtmEx+tX9GL5NgGaWdCcEMxvAJ2Kb4M
         N99g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1DR9eHEhS0OESK+XGbyGDagsM8wiojtagCgd3i1AXJA=;
        b=d8RyevgbJyPwGPpEaYgXtcHj3FzSAhCqCE0bpZSl7CHlhYsPI+NK7JoDj6sBjR1HBn
         AHxjd5etUwOAcsnio7vrJEueHyZtPoSK1U+mNRSvewb3s8k+n5xQF4MCmK050XOmLZKp
         gF4r++DAIdcgJ7W3ANeeIsH7niHEjoKCeswTThTPH92tuxWitf8qHni/eUPrq1jT/1iH
         /FhWNSSxvmURyAl7Qg0BXE6rtmmrvckMT9JkANa7sRX3l7fraaTyyzykhouWc4S1lLXp
         JDfDCwouNOXmyn/nhdAqR1oIRwwPobIhtkXPLURdM00Zb0XioWkMdtY59z7HBAKrJt7Z
         9r0A==
X-Gm-Message-State: AGi0PuZqX5nec40yG3kK6A5E6gGfzMyq7LsOreZgyUjC+7USj8mvKjN4
	83valcpNJ8gqQLgNAZFTtUM=
X-Google-Smtp-Source: APiQypIwiluGr2zqZNOl/OkSQ8hxxtp4GGideVhO8A/1ps7hDdYeUksZpv4uP1pqIMnT8sGJPWkitg==
X-Received: by 2002:a67:6e07:: with SMTP id j7mr18231599vsc.181.1589352700435;
        Tue, 12 May 2020 23:51:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:3346:: with SMTP id z67ls102076vsz.6.gmail; Tue, 12 May
 2020 23:51:40 -0700 (PDT)
X-Received: by 2002:a67:e3b9:: with SMTP id j25mr17423044vsm.110.1589352700081;
        Tue, 12 May 2020 23:51:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589352700; cv=none;
        d=google.com; s=arc-20160816;
        b=Q4VOT8TWrW3vBT7kkwTwFLYeLoLvF0jVzf+rvPz+NDmrVhqAlZMzgA2USIZNfkLd3W
         0sUo1KRfy57tV3xWmhl98qqK7a8w+KU/4KI//X6ptrmzFrOsezSVjbOGdBFSuHb1b+kc
         2ZY9NXs0cipONHyqGZ3xbGntI6sLGeVDtdzXmfCy02BBd2YZHQWmXMCEefgXoj9uhJkd
         phWQdRcGX1U1xo810aAMRw8U8jzD/k0LbvIs5J/vfvPtfs7pBNpkfB4KL3OFM59DGFcu
         TuKxK5cisivMmeIlNr8y2iTXqUAOSUK603oYDHDkLeNHDXr+8vev1eXUKv9LSoQKl+j5
         DDGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e6QbSlNOUjKcG/ZMZ3XtXHK+IfmeCzylC8Xkh73q0Aw=;
        b=i9wHdWJ7xNbICDVOi65gXYH1Jawt7ML1b3OOFsBHs/etZD272DoVLLf28siPIe9h48
         tpKpHrrPDb4g3IErNchAnNrNu8PLhIlT7d8Au4/LqefD+NMiArypS/KxMAQbY96LqTU6
         RnRAAS1EDFKEmROdSdYgsirwcJR7sNtjzhWxvCbLH4KNQ4lqTtAAn+d3l0aRRqHYvHZ9
         kRlVmA8VMRFyXCnz04C1V+UDsDZA1DE/qP99j+AedNqwuageYTj/tMqBl/vIBNnrjJEB
         8nTY9oYefkTPPwyewXz4SL4+gu5StpWL2eKAUOd29UhrGMeBxNNcdAFPPABoKgxbFkds
         5jjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MVQ6mRj0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id e22si1066960vkn.4.2020.05.12.23.51.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 May 2020 23:51:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id di6so7617507qvb.10
        for <kasan-dev@googlegroups.com>; Tue, 12 May 2020 23:51:40 -0700 (PDT)
X-Received: by 2002:a0c:f153:: with SMTP id y19mr909681qvl.22.1589352699379;
 Tue, 12 May 2020 23:51:39 -0700 (PDT)
MIME-Version: 1.0
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
 <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
 <CACT4Y+bO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7=oyOt4Gg@mail.gmail.com>
 <1589203771.21284.22.camel@mtksdccf07> <CACT4Y+aOkuH6Dn+L+wv1qVOLgXyCY_Ck4hecAMw3DgyBgC9qHw@mail.gmail.com>
 <1589254720.19238.36.camel@mtksdccf07> <CACT4Y+aibZEBR-3bos3ox5Tuu48TnHC20mDDN0AkWeRUKrT0aw@mail.gmail.com>
 <1589334472.19238.44.camel@mtksdccf07>
In-Reply-To: <1589334472.19238.44.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 May 2020 08:51:27 +0200
Message-ID: <CACT4Y+Zv3rCZs8z56NHM0hHWMwQr_2AT8nx0vUigzMG2v3Rt8Q@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Josh Triplett <josh@joshtriplett.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MVQ6mRj0;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Wed, May 13, 2020 at 3:48 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > Are you sure it will increase object size?
> > > > I think we overlap kasan_free_meta with the object as well. The only
> > > > case we don't overlap kasan_free_meta with the object are
> > > > SLAB_TYPESAFE_BY_RCU || cache->ctor. But these are rare and it should
> > > > only affect small objects with small redzones.
> > > > And I think now we simply have a bug for these objects, we check
> > > > KASAN_KMALLOC_FREE and then assume object contains free stack, but for
> > > > objects with ctor, they still contain live object data, we don't store
> > > > free stack in them.
> > > > Such objects can be both free and still contain user data.
> > > >
> > >
> > > Overlay kasan_free_meta. I see. but overlay it only when the object was
> > > freed. kasan_free_meta will be used until free object.
> > > 1). When put object into quarantine, it need kasan_free_meta.
> > > 2). When the object exit from quarantine, it need kasan_free_meta
> > >
> > > If we choose to overlay kasan_free_meta, then the free stack will be
> > > stored very late. It may has no free stack in report.
> >
> > Sorry, I don't understand what you mean.
> >
> > Why will it be stored too late?
> > In __kasan_slab_free() putting into quarantine and recording free
> > stack are literally adjacent lines of code:
> >
> > static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> >       unsigned long ip, bool quarantine)
> > {
> >     ...
> >     kasan_set_free_info(cache, object, tag);
> >     quarantine_put(get_free_info(cache, object), cache);
> >
> >
> > Just to make sure, what I meant is that we add free_track to kasan_free_meta:
> >
> > struct kasan_free_meta {
> >     struct qlist_node quarantine_link;
> > +  struct kasan_track free_track;
> > };
> >
>
> When I see above struct kasan_free_meta, I know why you don't understand
> my meaning, because I thought you were going to overlay the
> quarantine_link by free_track, but it seems like to add free_track to
> kasan_free_meta. Does it enlarge meta-data size?

I would assume it should not increase meta-data size. In both cases we
store exactly the same information inside of the object: quarantine
link and free track.
I see it more as a question of code organization. We already have a
concept of "this data is placed inside of the freed object", we
already have a name for it (kasan_free_meta), we already have code to
choose where to place it, we already have helper functions to access
it. And your change effectively duplicates all of this to place the
free track.

> > And I think its life-time and everything should be exactly what we need.
> >
> > Also it should help to fix the problem with ctors: kasan_free_meta is
> > already allocated on the side for such objects, and that's exactly
> > what we need for objects with ctor's.
>
> I see.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZv3rCZs8z56NHM0hHWMwQr_2AT8nx0vUigzMG2v3Rt8Q%40mail.gmail.com.
