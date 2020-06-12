Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSPPRX3QKGQERHUY6NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F4411F7804
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 14:40:42 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id n51sf4208211ota.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 05:40:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591965641; cv=pass;
        d=google.com; s=arc-20160816;
        b=daVWUg6CNz+St6PRUpiFwFyA/D9a6jvsORpKCZ7BZNVnqVP4bN5Rgrt+c8CVyz83bM
         htuUKqzkYuh7VqudkLHXSZy9SNCCqIEWiDhCMUzXemx1oQihNGYrjosSJ4ly/j8lELtY
         JyvRPthX06j8j/OkZb/Vn5V/lDr1ooX2PXz65F45+cOKPiaiXgFCkr+y9GBct23IeOiI
         ygvG/fVWyZVhvxQSrdQoEhQuYYOJU8wyAi6R9Z60P7LUHUDbajnWFK8+xOS/XmUmTN8c
         54OBy/3PRqVOXsVG8akCk63Z5xHMXaaGi7I73nGx03O0pxzPur9suvoPWT7sKgRIog4B
         o3uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6RYp1c6OH8LFeSEJcc6kmlBTcW5SjLjDmMaj4jaObRw=;
        b=p4NFkneIukXwx9RwnWoZE8rkQDzNaPG07Hyi/1t4oIDnX2OEYBAbUj30Vwgqn2ViWe
         bh2CReAnaOsscSxZcDOj9sXX1exGcMsrqnIF4o9BgtXj5yrk7WA7g1RJojRGXNrB89Ff
         Lv0Cl7FxQmL72g3DMMYCFDHWFFW72zChHjBJ8gTsqLHxMx0MpAUL5Ak7NuF6iIhneY1+
         5q1Rpo2LgFU82qPmazKf2/zGTM4mHbCqT7aRDk8TECrij5uYOCBIJoty6jt7hRxIUQm4
         O6Oa/TFhclGTiULEUs4SQbGN8Tk244mBYh9dR+M2VQlmSsBuq/xJ942hs3mBG96JVsKW
         6zpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C02vUSxS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6RYp1c6OH8LFeSEJcc6kmlBTcW5SjLjDmMaj4jaObRw=;
        b=gylV5lIegAt2urCY/MppSf2ihFE/TlkQUdp3udi+2kQzGkZ4tPUiEvjwpMM7WIZi8y
         4CrZHo9K2rXTVANfn5UGrSdLC0xuRLh+KL8Y6HriaWIWvUfBr0vxJ9tfgmgf5MJcXs36
         7QNngWjOWYH9FwYY0imx99/RyVaRB7NrwAImkpJwScbaUgzNjrxArNUxtT0T1uklpXA3
         X/zxpCau/ZMMO5r+wFv0GrvLf18NmRQCM3cJEilYjRwZZFgkdiLqxoZqFEc6EdKfANJ9
         GKlfrRRQ2vOJ7a1LSJQ50wSIzeKUxDkLaIr2oieM0KOcbrTyRhIjeOJQArv25b8+IUbD
         AoSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6RYp1c6OH8LFeSEJcc6kmlBTcW5SjLjDmMaj4jaObRw=;
        b=JGFEx0UHJvf12ddzEreKx6GY4bkOYzGS8n0E7r9PEtSEdfn+RA8ZXAK25nk+C1mN6r
         PT5tjweN1QHDw1KNizBJOPVy61Zf/Cr4R6CHiPbMYToBJzW6yCc32n7AN/sxesNnRjy8
         DVyJwSg3At694sTRujjsGK89J/ii/AL1zgnIMss0RcGlaZ38w3GMnJpaG7qQuxta4Le2
         qXJ/IyLu0wLlOAMpymJAAggXB2iQhyJ64oH92gkgiY8Z6WTkVEpZC6uNPOqofkmp+F2C
         LVdcmHJXzzVPVk5hYW1h1FvTF/YASmyrjoiVuMwK5+lrcBkU0CV3r/4MAmhIZQ61wOE0
         sT7Q==
X-Gm-Message-State: AOAM531kA0I9PiLcnMvNpUGPEgpWdhl2buJWVFjTr/Q6ibvtDiwlQhvv
	ReAj8NNwEPNnMxNF+Bk74S0=
X-Google-Smtp-Source: ABdhPJxzVKbFG60wtPLrPYJplJ1mD1Xu64BAV0YOnOe9eC32LexIES9wOVNcHUIlBij9Jai/J2NZ/Q==
X-Received: by 2002:a05:6830:1bca:: with SMTP id v10mr10116421ota.109.1591965641084;
        Fri, 12 Jun 2020 05:40:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:460f:: with SMTP id p15ls1079025oip.7.gmail; Fri, 12 Jun
 2020 05:40:40 -0700 (PDT)
X-Received: by 2002:a05:6808:20c:: with SMTP id l12mr2000079oie.32.1591965640800;
        Fri, 12 Jun 2020 05:40:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591965640; cv=none;
        d=google.com; s=arc-20160816;
        b=af79RTxJ+J83wk3xtvWyXHxYY6fZmqo8i253yaZdpV+j68Dfs/b/PfuQMf+rDyayj8
         5YsuZ01baJ7qd0Weeviz9r5QBtiS+9ICXlDaJqnhmE6kW5JoNoyipgyIkJ3gMNLqgGYq
         a5eqI0YrHFJgQMVwpeVH1/O9YE7YsA85a2dQS/KDopgtHcP3FfSS7eRTZIowrsobLWT/
         lfzfVJoqVzoUdc27yEqoQ/Xw0qF4/fiQrx7eHLgdkCoqLKaFG64AU+2v/ouLHhMVm3ja
         OojUxle6kIyE+eD3P1XMl9/uGW6S1dYD5X1X+zR/5dD9U1JXdn1dqZUGUeQsvsRGqMoI
         gLWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JpHLlXAN7G427r35f2r7Du9MUfcHBFZBrWIKOETEink=;
        b=r7WELworguq4Jou7T2PLHIDGj0307F6ItDRWKqsrJia08/TI3XNOKDqIaRxy41N5GF
         nUH6LpEhDnoiKMKWRmoXx9ladPah5+2Dixi0njTsVouK5lCI5s91m+62JwB+y437KpkW
         N1BvWETgdrnMRvx6zniRkoQTF/xJ7GEAZjJKXemiYcNQ1d1vg1oa6CN8dp68VJOrLPxs
         IvAqM1Ad4+mQwcaH40XOjMerhGvi1DD8ZpbY7cKW2iXuKRIrXy7DjtdVz13fPICm8+uQ
         NXWlPM557FnsmYM1PWJfPoWtZ7CS2AY6GM70UBoNJ8jUKx/yBOL2uaBgaWnTua+sxgsW
         rjRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C02vUSxS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id c26si289898otn.4.2020.06.12.05.40.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Jun 2020 05:40:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id a3so8537462oid.4
        for <kasan-dev@googlegroups.com>; Fri, 12 Jun 2020 05:40:40 -0700 (PDT)
X-Received: by 2002:aca:530e:: with SMTP id h14mr1965259oib.172.1591965640253;
 Fri, 12 Jun 2020 05:40:40 -0700 (PDT)
MIME-Version: 1.0
References: <20200612072159.187505-1-elver@google.com> <20200612102912.GJ8462@tucnak>
In-Reply-To: <20200612102912.GJ8462@tucnak>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Jun 2020 14:40:28 +0200
Message-ID: <CANpmjNOnWREWz21NR=gVf7OGDskzNYYJdsoZ_B=DPCB4=6TVrg@mail.gmail.com>
Subject: Re: [PATCH] tsan: Add param to disable func-entry-exit instrumentation
To: Jakub Jelinek <jakub@redhat.com>
Cc: GCC Patches <gcc-patches@gcc.gnu.org>, =?UTF-8?Q?Martin_Li=C5=A1ka?= <mliska@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C02vUSxS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Fri, 12 Jun 2020 at 12:29, Jakub Jelinek <jakub@redhat.com> wrote:
>
> On Fri, Jun 12, 2020 at 09:21:59AM +0200, Marco Elver wrote:
> > Adds param tsan-instrument-func-entry-exit, which controls if
> > __tsan_func_{entry,exit} calls should be emitted or not. The default
> > behaviour is to emit the calls.
>
> If you want that, I wonder if the spots you've chosen are the best ones.
> E.g. shouldn't
>   if (sanitize_flags_p (SANITIZE_THREAD))
>     {
>       gcall *call = gimple_build_call_internal (IFN_TSAN_FUNC_EXIT, 0);
> ...
> in gimplify.c have this && param_tsan_instrument_func_entry_exit, so that
> we don't waste a call or several in every function when we are going to dump
> them all?

Yes, makes sense. Thanks for pointing it out! Done in v2.

> And in tsan.c, perhaps instead of changing instrument_gimple twice change:
>             fentry_exit_instrument |= instrument_gimple (&gsi);
> to:
>             fentry_exit_instrument
>               |= (instrument_gimple (&gsi)
>                   && param_tsan_instrument_func_entry_exit);
> ?

Yeah, I was wondering where the best place is. I chose
instrument_gimple() because it's the inner-most function controlling
if func-entry-exit instrumentation is emitted. But I suppose that
function won't be used elsewhere, so your suggestion is simpler. Done
in v2.

> > gcc/ChangeLog:
> >
> >       * params.opt: Add --param=tsan-instrument-func-entry-exit=.
> >       * tsan.c (instrument_gimple): Make return value if
> >         func entry and exit  should be instrumented dependent on
> >         param.
>
> No tab + 2 spaces please, the further lines should be just tab indented.
> And s/  / /.

Done for v2.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOnWREWz21NR%3DgVf7OGDskzNYYJdsoZ_B%3DDPCB4%3D6TVrg%40mail.gmail.com.
