Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXXIRKEAMGQEYZ5WI3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8ECA73DA53D
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 15:59:59 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id u2-20020a056e021a42b0290221b4e6b2c8sf3296791ilv.23
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 06:59:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627567198; cv=pass;
        d=google.com; s=arc-20160816;
        b=kFKUyStGOrdGcdYKe+3q/KENrfTJPPBFHH0ePS+fzONuNxTTpmKbARP7vofOR9XFmP
         lJuaO9j4RCcgP0SJ+H8+jplOakJsJOmST3KtD2EtDqk1DbS6d7/fYBvXnAlKq656D9f9
         4rr6dVxty6crVsQzFoCkic84Hp3irs/NMIbfSYhvLDYEZsDrzHNIskLFVO7Wr3MT+x+M
         l7UbntUepEDAR/fjs2SsXmbMfWVs/8iz6ZTOmw3gXOdeSPaypxZ//xtAVUMkTgts5FUH
         baNsEH+kWzm0+ta8i2/hKOH7UWyOIDlbjNLUFv9YXWP9enV4KmWd6rZk4sbrQQhfmcvk
         U1Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AvQ48YmuxyJ8ZLWbZaJwJEYIrtWDxg3Ijm5GGxFfk0g=;
        b=aoAFVjX1e8FHKIzDIlSzjcf03lpmXj6co2cz5sALU4llp9epxCODd0Pn+0tKxL3+AC
         hFOVoIU7+xlmSPM381Iu1wL5KI2ebf5NWuIHh3SEa/ttHOeIVmVm7AcJRZplArytR0o7
         uSr7M2MOuTVdG4m+yTn/Nsx+36NdoabrPcUY+h4NOiF38DHugVj14GGD4XYdgTFiwEw6
         OCg8DTRUXHgsX1qsVgZZAdLrfZbuT6ie0i47HLXVGqX1+rOdc8YDOyQbXyhiq0cmkAxV
         PaCq5yFMM0N8g9yXhX2+a5NJKJSAwGJdYOyvAmfaWcyXOCuktkartw5xGAOWSQHdijFT
         5j0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iOwiVk+5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AvQ48YmuxyJ8ZLWbZaJwJEYIrtWDxg3Ijm5GGxFfk0g=;
        b=Yea9067yGBokaixv9bZme/FLk2tlCaiYiu30/P5T8eNPIVUusZwJ4Wk60T/TneAjkR
         FywvPtFqfIFWYDGkQrebElBjWB83Caxr6aue4LoBPON7rgzJRw/xKx6boto12dGj4Ftx
         NfH35LxA6RxdOJPa2ve2oiShk+CutPhpM21Ro7MEvfCJz1P3bjjsYvLiCXg9BF2lmckw
         imE3vwbbrbz9Y3i2VQtGhn+HruxgGKRK5CWd8Il8zZ5eEwA3mKDxCtTesAfkWWrodplN
         pNc8fy4C/qehmD/GWUnOeryHZfg3m0+pvAHztrNF7hvq7bxMAtF1PJK83vd3grjchExv
         zbYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AvQ48YmuxyJ8ZLWbZaJwJEYIrtWDxg3Ijm5GGxFfk0g=;
        b=XJSxFMpvppURtEtvcS4c5qOxfSIbVY0+5BgRQjs8Oh/eBYzZaYBAKjt8UeK09aIKRY
         K7aT9/6M7RmP815pyC9zlQmv9AKnVuE124L4VeP5/djgleAxhVGGVvqJYcEhctIgBIf5
         Z1TUO9Rp80rPJYAg2p9DEk/rIFW+7QVGVUuIb0JNRSQM+Pe7MPnHQwEILVV7wWdWrEyI
         5eohSdQBySLI50e5/vvgr1Prb57tl8ZgsOJJ9MPGw31BbmB2BTkeSkHoYr+ayBsK3sCS
         57DCwHIcrPClf+ONbyoy3LYaFDAQpujkdCip8Mg6vpoXtG0GIuWL3KuPQXDPh1j/UTzM
         4izQ==
X-Gm-Message-State: AOAM532qL2sNN52gVRH88kok7BWwU8hh/Ix8VgZ3cYZCP8wjzQhYCcKa
	IgsYroLlXgoVlRkg6t6H7F0=
X-Google-Smtp-Source: ABdhPJw9Xc3/dIf6fyfw9OXrvPlHZojldDtyPXsF57iE4pBBrrgiYW+iHxAaaAGbEjbdka79qNz/7A==
X-Received: by 2002:a05:6e02:1a67:: with SMTP id w7mr3738788ilv.175.1627567198453;
        Thu, 29 Jul 2021 06:59:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b511:: with SMTP id e17ls1049755iof.1.gmail; Thu, 29 Jul
 2021 06:59:58 -0700 (PDT)
X-Received: by 2002:a6b:dd02:: with SMTP id f2mr4255522ioc.11.1627567198115;
        Thu, 29 Jul 2021 06:59:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627567198; cv=none;
        d=google.com; s=arc-20160816;
        b=Y8H9F7cHUDesj+XVL8AsL4ndcmXBBGcjBW27AU8Wq/64kj5jiopWRkB48U43+3cgty
         fZZBZxCPoj4VJs2P0/efW7w7e21PtuR3mwXtPpYEGUO97KnYdzjZAbt7LAZ+w/OscIzc
         8PlHtUNyOh2OALNWMAUoUgJrTyBxZFRe7TH7Z2yazUwpezUapltx+vc7KehBbqcUTxVt
         y63YZlF9OnzLWXnsUbJXLvPf3DcTHU5iQ0Vdq0pidZl9RdoacpWbj9MdQTZZ9plxY7il
         prYTHfvo5MN0X9NWzVGrY2KcgjQeRV9M0Z2JcUwcnJ2/SF9k9vBUFJaXHmADtVXbd31b
         jE7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KUvzSeTHiMYYDqDJxB7rJ4PNsknIyxmHg+DiEVHfwLI=;
        b=mjhttf5t3q6lpN2o2oOk/LxYSDLeAZ4M53GhKMcXgHcXV5RZRrt+f2qNhxV3iDMU6/
         cXYsLTolvQj69Un5AyA2td3rIbgpIUxA7lcHA+ZF7hxfjj0tpMuNCD9Xn3gwsClVxfo9
         uJ+nkbA9FeZnBoLnReJILqSW7nf1cV9iuTzc6HWFMWlEht8wptQJ38Eazabi8AX3as71
         +b74/ROmG53n1lXTC4/4vqPx2/FluPQnU1EGY1F3VIVCErK8hdikhTwxN6Z6Sb9zEnZV
         Fg8gcS8dKf1o31Jr4yE1ZxIl1EtxaOEcqtwOdOI/+kNqVl0IvlJzVprta5kdFogK/NVV
         kjyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iOwiVk+5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id q14si223317ior.1.2021.07.29.06.59.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Jul 2021 06:59:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id b20so6025956qkj.3
        for <kasan-dev@googlegroups.com>; Thu, 29 Jul 2021 06:59:58 -0700 (PDT)
X-Received: by 2002:a37:a5ca:: with SMTP id o193mr5414456qke.352.1627567197517;
 Thu, 29 Jul 2021 06:59:57 -0700 (PDT)
MIME-Version: 1.0
References: <20210728190254.3921642-1-hca@linux.ibm.com> <20210728190254.3921642-3-hca@linux.ibm.com>
 <CAG_fn=VS_WFjL+qjm79Jvq5M0KaNScvX2vCw=aNxPx14Hffa0A@mail.gmail.com> <yt9dtukdteoj.fsf@linux.ibm.com>
In-Reply-To: <yt9dtukdteoj.fsf@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 29 Jul 2021 15:59:21 +0200
Message-ID: <CAG_fn=XHr2j+xVaxjxqSUKU7ddDoekvxVoac9sSJ+Yk3voRUnA@mail.gmail.com>
Subject: Re: [PATCH 2/4] kfence: add function to mask address bits
To: Sven Schnelle <svens@linux.ibm.com>
Cc: Heiko Carstens <hca@linux.ibm.com>, Marco Elver <elver@google.com>, 
	Vasily Gorbik <gor@linux.ibm.com>, Christian Borntraeger <borntraeger@de.ibm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-s390 <linux-s390@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iOwiVk+5;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jul 29, 2021 at 3:47 PM Sven Schnelle <svens@linux.ibm.com> wrote:
>
> Alexander Potapenko <glider@google.com> writes:
>
> > On Wed, Jul 28, 2021 at 9:03 PM Heiko Carstens <hca@linux.ibm.com> wrote:
> >>
> >> From: Sven Schnelle <svens@linux.ibm.com>
> >>
> >> s390 only reports the page address during a translation fault.
> >> To make the kfence unit tests pass, add a function that might
> >> be implemented by architectures to mask out address bits.
> >>
> >> Signed-off-by: Sven Schnelle <svens@linux.ibm.com>
> >> Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
> >> ---
> >>  mm/kfence/kfence_test.c | 13 ++++++++++++-
> >>  1 file changed, 12 insertions(+), 1 deletion(-)
> >>
> >> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> >> index 942cbc16ad26..eb6307c199ea 100644
> >> --- a/mm/kfence/kfence_test.c
> >> +++ b/mm/kfence/kfence_test.c
> >> @@ -23,8 +23,15 @@
> >>  #include <linux/tracepoint.h>
> >>  #include <trace/events/printk.h>
> >>
> >> +#include <asm/kfence.h>
> >> +
> >>  #include "kfence.h"
> >>
> >> +/* May be overridden by <asm/kfence.h>. */
> >> +#ifndef arch_kfence_test_address
> >> +#define arch_kfence_test_address(addr) (addr)
> >> +#endif
> >> +
> >>  /* Report as observed from console. */
> >>  static struct {
> >>         spinlock_t lock;
> >> @@ -82,6 +89,7 @@ static const char *get_access_type(const struct expect_report *r)
> >>  /* Check observed report matches information in @r. */
> >>  static bool report_matches(const struct expect_report *r)
> >>  {
> >> +       unsigned long addr = (unsigned long)r->addr;
> >>         bool ret = false;
> >>         unsigned long flags;
> >>         typeof(observed.lines) expect;
> >> @@ -131,22 +139,25 @@ static bool report_matches(const struct expect_report *r)
> >>         switch (r->type) {
> >>         case KFENCE_ERROR_OOB:
> >>                 cur += scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_type(r));
> >> +               addr = arch_kfence_test_address(addr);
> >
> > Can we normalize addr once before (or after) this switch?
> >
>

> I don't think so. When reporing corrupted memory or an invalid free the
> address is not generated by hardware but kfence itself, and therefore we
> would strip valid bits.

Ah, sorry, I missed that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXHr2j%2BxVaxjxqSUKU7ddDoekvxVoac9sSJ%2BYk3voRUnA%40mail.gmail.com.
