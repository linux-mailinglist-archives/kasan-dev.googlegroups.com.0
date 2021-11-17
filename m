Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXP32OGAMGQEPRYFOBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id EE8454546D6
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 14:04:31 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id w7-20020aa78587000000b004a28bb92381sf1620246pfn.22
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 05:04:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637154270; cv=pass;
        d=google.com; s=arc-20160816;
        b=IDSnsDuNOcLUgyxOc68RW1vZpOIagnV1adBCRHlsXiOUtWFbVsQrDeeMEimLLO5RY9
         KyERgkZoXLx/ltF7GZaxNfabE9d24iMLMz+kpYH6j+lPKcbo/hcwX5nGhB6duecKnKOb
         zHvXygiFYClMUSQiii6rtpKq/K7gViO9edDB1GM/fhMkkFHlZk2hIj3dZgyMZ7UrxH5z
         do+GHhB4SAIauk/eXwh/mNX2te+6py480T2hj1mrMf5glhxKcdWOs4gb5Y0aCGl6dW5l
         tooF+88/YJu/4DRx34IByJuLJVjewl4fLMAuzlmpgHbmRKIpsLjahNqAydQ0jA8yyHv/
         HCeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lRZkxk9Gml9cSNjEC3vyOAtzZ214zUM2a5kFo7Tpu5s=;
        b=GFefItTSR11ExZSghsCcdmtbpauiUAP4Oqm24HCg9gSTVjaEFG1S7LNMRWTMCi/73S
         hJccVZuv2wYZX3Y0G+4220Xg1w5Go4ytoi9DUouo9oboKhQ+MPdjlPt8zRThY2KSPXnK
         WlPrJeloG3hog0A/OhdAWLGTWEiaM14A4hts0OkbI0LXQgfYiQgyp+76HS/8WNmpTYDO
         c9oAGeXOZXLXLc9+B6j1ClNa9laETXOVvLwP4e20qEi3J9zSBFRshCf/t1Y6+3o0A78a
         AbZDwskXVuSelCkh/cQFbJX5nWJRhzcH+vEImou3sFC7clTw+3dynMsotGX6Y3swIp92
         rw7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=liGg1iEP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lRZkxk9Gml9cSNjEC3vyOAtzZ214zUM2a5kFo7Tpu5s=;
        b=r0vNRabIKTaRM/UhjnAymwqp5+QrqYlkW2IRyfnT2Y6W6kQMS+DBcPlZqRAis+MYbd
         4cMiQjPC6dK1PhhgFESM58nahkJvav7OFfLF5niFrVrapUa68WTIn5a/wNS569T8no7d
         ZEt9r6OFeyoCfnP7YxS+v8ivcJ7B1hDsJ3VEEvAkmSDobZmXNzxD1hAXaI6t+Lw7w22Y
         /0vHOzpnq7OlnTaVQ7r8YUlcALAGnQZWmsyWXNxTnFMwBa0Y5hj/3l3cQIUEpF6UwPZ9
         qZrtErr5baKpbn62Lz7p1pJAzc2ZrCRrs4xWjplyX5wOo09HtPud4u5vCwpg2AF1cR2g
         a+mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lRZkxk9Gml9cSNjEC3vyOAtzZ214zUM2a5kFo7Tpu5s=;
        b=JYxXfG/lrkJ+HNF+qPjzMAVuyvTXpEB2Nus6MmWamAO9RKXwq/RG18D3ISm4/NdEiC
         cGjcURt6oYVSFApyPTcyJRdOeyOyk58U2BB63uxA2L4mvcbq1wSOvtq71GfTueMXBozj
         tmzI4zrRr/GOjx/NY2u2xBKwraMjnZU84REQhGKL/qHPxlnD26f1eiX4NGE8EGpgh+h0
         MZGJEQgzRnoQVHZ/IxT9l1dlC24Xw4fcCn1UohGLMYNjbq3ZiPBAuld672QcFteCjUFb
         AvnUJXjFc4cyfB1SYQvZw1sZ6dh8KjGqDwvktGdXhPOfDXpDdF5SPw6ucDN3IrE6K+s9
         8+lQ==
X-Gm-Message-State: AOAM533CL9nSJCl7EgwghVngxAgTZp2UrYhxHCQP98HA2X8OhyscN+yd
	m+uiC1s+yLm1hqHN/S2j1T0=
X-Google-Smtp-Source: ABdhPJzTyQcmbzKxkLYACWiNm6Jn15Cje7IyA1OVUQXL/9pN+6jRzgIauKYKlICkQzlXd+jtjknAsA==
X-Received: by 2002:a17:90a:430f:: with SMTP id q15mr9364217pjg.170.1637154270147;
        Wed, 17 Nov 2021 05:04:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:24cc:: with SMTP id d12ls7354115pfv.1.gmail; Wed,
 17 Nov 2021 05:04:29 -0800 (PST)
X-Received: by 2002:a63:501d:: with SMTP id e29mr4911051pgb.313.1637154269343;
        Wed, 17 Nov 2021 05:04:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637154269; cv=none;
        d=google.com; s=arc-20160816;
        b=QmlgRocC2eP28eLNA4wtYbGKpsEtq1nJYjkVUz2yNghjGyqlEuDmKFY1Ag/gF5y3XM
         R1Sv6q8VciZJqqG4YtIVRttDVtUb6Y+CfoZDv91iiwMC14k7cKKHC5MvLdgDKzqR5vvJ
         y/5wBb20ZjTI6FmRxx1ZXZIqrfmcmOFAGpeHzPPX8KDDxkz7QBh6V3mkGFvQimqEdHm/
         Z2KBG4KSMTnQE7Bomcfi2WbDPvKsMUpj0riD8MGSJTXkdKSmvnn7PaW/c6C3D3YBcErK
         iLCq0VNVbOxs3j9Tb9quN8n7iIQfDL7RnmAH2myxaSsK6+ZBNudU6yD+t5OCsX5r3tyO
         Y8Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GQVwuxwEF7Twnep+EJ7g8xvuzr4jtUj3SWg3Cfbdhis=;
        b=jix05gUoG3LGdneCixfVmkp7c4k/lFY94rK3988Q4qRUAQLWgeBfAvxio/S9k3OCu+
         MKH35DZ5mSz/ltj3PEem4tfxCpQ0ZPVcY/oJrpBLZmRsjyND3HwdOkP+MGJTEJB8BjVm
         rfbsVIIxbxa9OBT5cZhA2IQRTxyf73gn7UfG48fimLL4imt6jKBtI3O7MUybosSVF1tu
         +wfiXXUiAy5T/SVOf8gO4seiDuMEp6UwVYzo9jVL6qGj/xMu7X+qPxY5zoanpihstx7q
         OEYWV36f/RHjhPq4KX5mveXDx7qun/4Y3itofD9TBA+k9k5QaxT6z4rENV8NUMXxmvrC
         sQGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=liGg1iEP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id ls15si202893pjb.1.2021.11.17.05.04.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Nov 2021 05:04:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id s139so6154558oie.13
        for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 05:04:29 -0800 (PST)
X-Received: by 2002:a05:6808:1903:: with SMTP id bf3mr49706426oib.7.1637154268831;
 Wed, 17 Nov 2021 05:04:28 -0800 (PST)
MIME-Version: 1.0
References: <20211117110916.97944-1-elver@google.com> <CA+fCnZcp3dFd3rwpLx6VUi2Yv9uqsWQyQNB6d3X-A7VgTjXUpw@mail.gmail.com>
In-Reply-To: <CA+fCnZcp3dFd3rwpLx6VUi2Yv9uqsWQyQNB6d3X-A7VgTjXUpw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 17 Nov 2021 14:04:17 +0100
Message-ID: <CANpmjNO3DMUmQGkSggibRYY_XmWzW9fDyVOSRC8AoPzmv+jE2A@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: add globals left-out-of-bounds test
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=liGg1iEP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

On Wed, 17 Nov 2021 at 13:59, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Wed, Nov 17, 2021 at 12:09 PM Marco Elver <elver@google.com> wrote:
> >
> > Add a test checking that KASAN generic can also detect out-of-bounds
> > accesses to the left of globals.
> >
> > Unfortunately it seems that GCC doesn't catch this (tested GCC 10, 11).
> > The main difference between GCC's globals redzoning and Clang's is that
> > GCC relies on using increased alignment to producing padding, where
> > Clang's redzoning implementation actually adds real data after the
> > global and doesn't rely on alignment to produce padding. I believe this
> > is the main reason why GCC can't reliably catch globals out-of-bounds in
> > this case.
> >
> > Given this is now a known issue, to avoid failing the whole test suite,
> > skip this test case with GCC.
> >
> > Reported-by: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Hi Marco,
>
> > ---
> >  lib/test_kasan.c | 18 ++++++++++++++++--
> >  1 file changed, 16 insertions(+), 2 deletions(-)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 67ed689a0b1b..69c32c91420b 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *test)
> >
> >  static char global_array[10];
> >
> > -static void kasan_global_oob(struct kunit *test)
> > +static void kasan_global_oob_right(struct kunit *test)
> >  {
> >         /*
> >          * Deliberate out-of-bounds access. To prevent CONFIG_UBSAN_LOCAL_BOUNDS
> > @@ -723,6 +723,19 @@ static void kasan_global_oob(struct kunit *test)
> >         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
> >  }
> >
> > +static void kasan_global_oob_left(struct kunit *test)
> > +{
> > +       char *volatile array = global_array;
> > +       char *p = array - 3;
> > +
> > +       /*
> > +        * GCC is known to fail this test, skip it.
> > +        */
>
> Please link the KASAN bugzilla issue here.

I was wondering how to solve the cyclic dependency, because I wanted
to link this patch from the bugzilla.

Now that the bugzilla entry exists, I guess I can add it and then
update bugzilla with link to this patch closing the cycle. :-)

> > +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_CC_IS_CLANG);
> > +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
> > +       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
> > +}
> > +
> >  /* Check that ksize() makes the whole object accessible. */
> >  static void ksize_unpoisons_memory(struct kunit *test)
> >  {
> > @@ -1160,7 +1173,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
> >         KUNIT_CASE(kmem_cache_oob),
> >         KUNIT_CASE(kmem_cache_accounted),
> >         KUNIT_CASE(kmem_cache_bulk),
> > -       KUNIT_CASE(kasan_global_oob),
> > +       KUNIT_CASE(kasan_global_oob_right),
> > +       KUNIT_CASE(kasan_global_oob_left),
> >         KUNIT_CASE(kasan_stack_oob),
> >         KUNIT_CASE(kasan_alloca_oob_left),
> >         KUNIT_CASE(kasan_alloca_oob_right),
> > --
> > 2.34.0.rc2.393.gf8c9666880-goog
> >
>
> Otherwise:
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> Thanks!
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcp3dFd3rwpLx6VUi2Yv9uqsWQyQNB6d3X-A7VgTjXUpw%40mail.gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO3DMUmQGkSggibRYY_XmWzW9fDyVOSRC8AoPzmv%2BjE2A%40mail.gmail.com.
