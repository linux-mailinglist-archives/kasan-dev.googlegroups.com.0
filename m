Return-Path: <kasan-dev+bncBCMIZB7QWENRBNFIXHTQKGQE7PQ24NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id C7F332D94A
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 11:43:17 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id e69sf1344288pgc.7
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 02:43:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559122996; cv=pass;
        d=google.com; s=arc-20160816;
        b=EbRPzrINxi7otBDA69txV6nCDsi723wjZsH4uC3IGwGVjX3CPoEnSfu17diP43VT5D
         rgCMivQmQbH0XA8cdpOYLmI0Z/c35ifKOm2+y4wKrvjPlSP5GJeCHnUA0ZCeKiwFhHpw
         oSQn4dPJQ9ZsTrgOAasSe9qop/bRHOgYrpSolhZNMqD0VRa5RGtpoEUYc6MjWFLKJDDA
         2JdQpofomGL0rR5Gkkxb4tukvI1nP1JhW+qZVFl0UNCiNnWreDYqrrw+6VY4B1mZZodd
         lGcK9Avd45HRlzhgUiPosyHb8z1Gjc7c53hLTOcQ4Kf9fhUCsZ9BDYUl8LBnCV7wjqlp
         Z6pQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1mJrs7tlnfpd+dx5q0uzD8qBLR1ZYDNbZaa76jyh08Q=;
        b=LCWsZHn+bySq486V4E8jX1keIw+9G0A9e93yv3M++XhSR3P1mjCan3VKvU+QwecxXK
         r7dzk44ohf1E2fMP26kv7RQUxP2r8C2kMsL1wq02t2kUcL1SB8f117aNyj730cuiwEE7
         6ebOPTvrgR1gtn3fJ/a0Qp2kJ1fUdZhMi8x4AtXekTnSq0CsLohibzzdDbbavWH68x9Y
         NnJcYdaU2deSUsuZ1HNEw9P1XOgVwX+E9uUn0/EsfQbrVU1lFyuxXpjSMCf1QEF/5RKc
         5I0+gzUfXmH7iKafGhJ5iWSXFG6dJ4+pI8bO9zPZGOlWBXT8ybyC5vnkeRQuK/k5ZPHq
         SFnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=chAc1nMB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::141 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1mJrs7tlnfpd+dx5q0uzD8qBLR1ZYDNbZaa76jyh08Q=;
        b=WdB1zKGzbEnGfCWggzJbG6xI3txhKCh/fH8il+muG+Aivn2UyGQ3/qfEqUm3/muZiC
         PQ/g0utKxqv4Nd0x+5yNl8rcbaDg/tOvfyAuAftRdtYexvyPrccf9mKVmTUBn9dxK4to
         1fdUhzKLBUA10d0IVoav1kTIMcwmSAuvOT8SyYYVR4HSTwO7YmGtEQPyJuMMFE7Aymg/
         k9VsjFaTP8ha4s7Dg0e5Tv5E/RB6Jv925o46EMEb1oBBnwmdIwe60Z9XCpjXEGHZ0giX
         TO3hQkmQaviH5mmdmtkCu0IJyrafHSju7ymtKbdADlV/+ZkBUun3SWkfR1Hw/LFPrpnV
         RylQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1mJrs7tlnfpd+dx5q0uzD8qBLR1ZYDNbZaa76jyh08Q=;
        b=HLDcz/X11V6TDIL8fLMrATfz1fLm44pCgJ8gYe1TdsERBdTGBVEh8afdEjeJViCRSG
         0l2ddOfe5Md5rExT8B9VMJ9q3JUWSNKi3y158257q6eiZ+7TtaqaD+f+DgozYurGNyGG
         CdtUK7KUIk1ssvG/mhQF7HcXxWW/Na+XW9ho8u93rCQC75x9XEijYJDPMR5OH7ITaVZi
         YLC1hZhV75escOVAgoYc5Yx+llPB8vFLc838slXXp3AsHinkGQSmcNMVbSKqYlmu54sN
         hqItvUMA8az6gb9/XLqT55MHyWuWQXNlGmrqUrrOwYLb8mSoDLFHOVLm0k9rxwFuXOfc
         +pWQ==
X-Gm-Message-State: APjAAAXLpU3EOv5/XwyBvWa7peqjD+yRd/gTP41jD5yMcfktoaCFTwth
	HutMuu+LSePJg34rbK8nFmU=
X-Google-Smtp-Source: APXvYqz107N5roM8WTGiDGtDY5lcLW2nxZ156TSaoRPzBDo4u31RK/Cf4dtJW5mlGUVjVV6fjFF+6A==
X-Received: by 2002:a17:90a:f98d:: with SMTP id cq13mr11039028pjb.41.1559122996089;
        Wed, 29 May 2019 02:43:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:985b:: with SMTP id n27ls528260pfq.7.gmail; Wed, 29 May
 2019 02:43:15 -0700 (PDT)
X-Received: by 2002:a63:cc4b:: with SMTP id q11mr138285617pgi.43.1559122995722;
        Wed, 29 May 2019 02:43:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559122995; cv=none;
        d=google.com; s=arc-20160816;
        b=gp65gmge1dvtFObW/fTmPZ4rX8fnAfBaxyA7PSSBhWmFo0afH/I79uTQmn9lKHjjyH
         Wy9nAhezMT1pZL4hpcMtYfs0HiB/UyUccB/3sVnXr/qHulvJpL+xTA/JDmEOveelswpm
         SK9VX/3oxiMilLobNPHHMDXvDybrBCoB4bM46sTX3iBgC2XWs0ev9vkfHcGjNSBpc07y
         lmaaHS5LOIwisNFbIz9O9jMSDMME4ziVIuDHheZffoVkyEfzfkY+IAjM329O1QiJw8i1
         e6OhW+VAHm1p4S39YnaKyNL6YQsf0LlzfQqPF/SjaK2j16H9dFIfBFUfje2BL745DTIA
         1NqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1vwG6ed0prywy+z8KiREagdtZuNI9VOig8toshOVg54=;
        b=uiM1gUcJ+cA31HXWGuuNk8FiWNjlAvMqnQ1ebzt4T7CyGFVJsQB0pTbvxGu9oUJVEq
         zU5vNoGd9Y8HN2bioSqjkC8jUWi8Ilu2OroSOWjOJG2XPHW+71iqaRCnq0d27FAq+JVf
         jKXpyQTcSDPLxyF9P2NLDjDfKB/EPtXcmnXBTduWDQaVclSMDNrXkDF7F+HRmGbc+Ru2
         nrvu5uaBTtM7Yh2tkR7iTTxdI+lmy7D/P28XJzWytT04GmUYAoWfbfHY7hhRBaAKNat7
         b8v1gm6KLTIulxp2xjvYISRNaNtY9bzvjS+99Fw0zaKzc7N/hDlqI8YJgtT3KlLycDXN
         hjXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=chAc1nMB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::141 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-it1-x141.google.com (mail-it1-x141.google.com. [2607:f8b0:4864:20::141])
        by gmr-mx.google.com with ESMTPS id e8si617522plk.4.2019.05.29.02.43.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 02:43:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::141 as permitted sender) client-ip=2607:f8b0:4864:20::141;
Received: by mail-it1-x141.google.com with SMTP id m141so2640960ita.3
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 02:43:15 -0700 (PDT)
X-Received: by 2002:a02:1384:: with SMTP id 126mr13105640jaz.72.1559122994696;
 Wed, 29 May 2019 02:43:14 -0700 (PDT)
MIME-Version: 1.0
References: <1559027797-30303-1-git-send-email-walter-zh.wu@mediatek.com>
 <CACT4Y+aCnODuffR7PafyYispp_U+ZdY1Dr0XQYvmghkogLJzSw@mail.gmail.com> <1559122529.17186.24.camel@mtksdccf07>
In-Reply-To: <1559122529.17186.24.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 May 2019 11:43:02 +0200
Message-ID: <CACT4Y+a__7FQxqbzowLq5KOZGyBys90S8=HP_Gqu_KoNm7W39w@mail.gmail.com>
Subject: Re: [PATCH] kasan: add memory corruption identification for software
 tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Miles Chen <miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream@mediatek.com, Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=chAc1nMB;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::141
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

On Wed, May 29, 2019 at 11:35 AM Walter Wu <walter-zh.wu@mediatek.com> wrot=
e:
>
> > Hi Walter,
> >
> > Please describe your use case.
> > For testing context the generic KASAN works better and it does have
> > quarantine already. For prod/canary environment the quarantine may be
> > unacceptable in most cases.
> > I think we also want to use tag-based KASAN as a base for ARM MTE
> > support in near future and quarantine will be most likely unacceptable
> > for main MTE use cases. So at the very least I think this should be
> > configurable. +Catalin for this.
> >
> My patch hope the tag-based KASAN bug report make it easier for
> programmers to see memory corruption problem.
> Because now tag-based KASAN bug report always shows =E2=80=9Cinvalid-acce=
ss=E2=80=9D
> error, my patch can identify it whether it is use-after-free or
> out-of-bound.
>
> We can try to make our patch is feature option. Thanks your suggestion.
> Would you explain why the quarantine is unacceptable for main MTE?
> Thanks.

MTE is supposed to be used on actual production devices.
Consider that by submitting this patch you are actually reducing
amount of available memory on your next phone ;)


> > You don't change total quarantine size and charge only sizeof(struct
> > qlist_object). If I am reading this correctly, this means that
> > quarantine will have the same large overhead as with generic KASAN. We
> > will just cache much more objects there. The boot benchmarks may be
> > unrepresentative for this. Don't we need to reduce quarantine size or
> > something?
> >
> Yes, we will try to choose 2. My original idea is belong to it. So we
> will reduce quarantine size.
>
> 1). If quarantine size is the same with generic KASAN and tag-based
> KASAN, then the miss rate of use-after-free case in generic KASAN is
> larger than tag-based KASAN.
> 2). If tag-based KASAN quarantine size is smaller generic KASAN, then
> the miss rate of use-after-free case may be the same, but tag-based
> KASAN can save slab memory usage.
>
>
> >
> > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > ---
> > >  include/linux/kasan.h  |  20 +++++---
> > >  mm/kasan/Makefile      |   4 +-
> > >  mm/kasan/common.c      |  15 +++++-
> > >  mm/kasan/generic.c     |  11 -----
> > >  mm/kasan/kasan.h       |  45 ++++++++++++++++-
> > >  mm/kasan/quarantine.c  | 107 ++++++++++++++++++++++++++++++++++++++-=
--
> > >  mm/kasan/report.c      |  36 +++++++++-----
> > >  mm/kasan/tags.c        |  64 ++++++++++++++++++++++++
> > >  mm/kasan/tags_report.c |   5 +-
> > >  mm/slub.c              |   2 -
> > >  10 files changed, 262 insertions(+), 47 deletions(-)
> > >
> > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > index b40ea104dd36..bbb52a8bf4a9 100644
> > > --- a/include/linux/kasan.h
> > > +++ b/include/linux/kasan.h
> > > @@ -83,6 +83,9 @@ size_t kasan_metadata_size(struct kmem_cache *cache=
);
> > >  bool kasan_save_enable_multi_shot(void);
> > >  void kasan_restore_multi_shot(bool enabled);
> > >
> > > +void kasan_cache_shrink(struct kmem_cache *cache);
> > > +void kasan_cache_shutdown(struct kmem_cache *cache);
> > > +
> > >  #else /* CONFIG_KASAN */
> > >
> > >  static inline void kasan_unpoison_shadow(const void *address, size_t=
 size) {}
> > > @@ -153,20 +156,14 @@ static inline void kasan_remove_zero_shadow(voi=
d *start,
> > >  static inline void kasan_unpoison_slab(const void *ptr) { }
> > >  static inline size_t kasan_metadata_size(struct kmem_cache *cache) {=
 return 0; }
> > >
> > > +static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > > +static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> > >  #endif /* CONFIG_KASAN */
> > >
> > >  #ifdef CONFIG_KASAN_GENERIC
> > >
> > >  #define KASAN_SHADOW_INIT 0
> > >
> > > -void kasan_cache_shrink(struct kmem_cache *cache);
> > > -void kasan_cache_shutdown(struct kmem_cache *cache);
> > > -
> > > -#else /* CONFIG_KASAN_GENERIC */
> > > -
> > > -static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > > -static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> >
> > Why do we need to move these functions?
> > For generic KASAN that's required because we store the objects
> > themselves in the quarantine, but it's not the case for tag-based mode
> > with your patch...
> >
> The quarantine in tag-based KASAN includes new objects which we create.
> Those objects are the freed information. They can be shrunk by calling
> them. So we move these function into CONFIG_KASAN.

Ok, kasan_cache_shrink is to release memory during memory pressure.
But why do we need kasan_cache_shutdown? It seems that we could leave
qobjects in quarantine when the corresponding cache is destroyed. And
in fact it's useful because we still can get use-after-frees on these
objects.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Ba__7FQxqbzowLq5KOZGyBys90S8%3DHP_Gqu_KoNm7W39w%40mail.gm=
ail.com.
For more options, visit https://groups.google.com/d/optout.
