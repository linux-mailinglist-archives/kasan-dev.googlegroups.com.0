Return-Path: <kasan-dev+bncBCIO53XE7YHBBB5A375AKGQEZM2EJEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 43D9C261AC2
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 20:40:08 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id c187sf19491oia.20
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 11:40:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599590407; cv=pass;
        d=google.com; s=arc-20160816;
        b=DN2o7oZtslQCvvE7ZoBhc+/2OOn7XoYHevv1YHNxgLpiDVHSVvyevLdhehpiHZBCGo
         7+rhgoLWPm/HdiKnm0CYIJ1NX8Pw1q3GIFMNmNhDrJVu2KZKoEFkXnzbmXsrOaa+0YYF
         z4zECEV2yMINMuFRbCCxAHyIwFucSwY32b+g8iGMjRdX3KKnh5DnyHZ8Z98w4k6yJEtj
         6eBP+Lo53ocvdvFNlVgwruPHqrkpxt3L1YQLWYIQWQqI38TpYl6iwNAxfIp1VLL2Qgi3
         UmwSSP3QI1PZ9v+SRwo5A1KMvu1lemKcQHdDqa4I6QIf/4rxu6gtcoI/qvwAvjWIkJ+J
         dUvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature;
        bh=ED3JRbbHBn/pGM1d6KHZEEosG0XFjE4i7K70RP8LStc=;
        b=AZwOAmS2jOHdXa/AGgrtRZQnD8vz85aCQiryjkqXBkoo4CXvdhzRxRxMXz2WL0AkWJ
         nGJPpd0XhzuciEYFXTf06pAUexSBbgnkLaDlKjKvTevuok9QVrvz+q7FeyxiQFGfd+nU
         lKVpppslU8BBwwyhRVxfktPEJonSrMTLh85uvp83/FFoNBSZAZ+AERIuV4wCMeO1Q2TO
         kihtKRYrymijlszzkSJnWT9bLERL5lzR55Z1gHK5SDQBwOUOO1OHbmRrWJEQ14W+1h/Z
         bx0GW1yJAPKMteSFhMxKk/wYlb7APRLDNbanK7I8rqg+ilgQxOaMJkJGNRqgHIicSkhM
         2hMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=bhGN0zBc;
       spf=pass (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ED3JRbbHBn/pGM1d6KHZEEosG0XFjE4i7K70RP8LStc=;
        b=DvoCA11G8t5+A9tZOxJrcCJd/oxP2GK99cvbtT51V8mU8rmXuz4YrBKtQVwp9p4lZg
         j28BEtD93ZW2jbOK/k7Q3n8vzpml0A5e3NQh7a8X6OV6R5/Ao+vyRvHcX8XiqRWEwO/Z
         Vb/rCZCHO7UDXmJpbtn4d+FqJ3WkZ97+NakAtPqOrUBFUsUc5d5uG73shRLZoKfExzUO
         mOPPKbvrR+4gppK/5rlMTrqWwMfS8YSqrnVn7vUInhhffAtKU61tDLzm/jveEeRqi1++
         z7W5g+d2qpFfW9PlLDc/r5ZX8XQ3PU0cRJQ9Tb+i4cPeYxUDRWRuLBK6IJgAqGshGg3x
         KkHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ED3JRbbHBn/pGM1d6KHZEEosG0XFjE4i7K70RP8LStc=;
        b=hY8CFY1N8ZbaRy73iX2dR8iV5cldFvRdsrIPRv+2SR2Fphbm0lOIsoU+R9pynVzVEv
         aYogab6qL1LDvZkHUnnCO5Jyr1K2Fqifk4X8+Qp5M0bWrxM7UOb/s3CXME7BUHLNXMtZ
         cyEkqA8DNO1eqY9/WlB7HbCJrZUWHiks4BW0s5COzMojC1HnjAuldwegmmOt1RxGw/le
         6pi62NELTsytxBkioZWSYunTF/odfff0piUdQA4Iz2jUV/pZPQaNFVbhvpE/VdKbs+Ia
         akl12Cz2JPkP7sKjGiVms5M/fcqP/fbkSNIqu5+JtKWoYMPKhyPnD/vfQ1e7H4OkSoX9
         OTPw==
X-Gm-Message-State: AOAM5325Umxiv0QuBsXo1zSWaCumQgcxP7q8iCOxp3jp0LbPwBgTeCsV
	DL11f4pd2AIGecXREUAF6Pw=
X-Google-Smtp-Source: ABdhPJxXRVWtXexiFnl+kQ8dyJ4vXXLE357x1T9ppvBJr+mTJehGZWUuHRRqS+9DygnTiTalvzlqTA==
X-Received: by 2002:aca:1118:: with SMTP id 24mr207453oir.59.1599590407256;
        Tue, 08 Sep 2020 11:40:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:84c:: with SMTP id 70ls84663oty.5.gmail; Tue, 08 Sep
 2020 11:40:06 -0700 (PDT)
X-Received: by 2002:a9d:6287:: with SMTP id x7mr335903otk.14.1599590406696;
        Tue, 08 Sep 2020 11:40:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599590406; cv=none;
        d=google.com; s=arc-20160816;
        b=0+GMeOwDUKv7w0svl++fsOjiIxW6BQF/KAZ9DkvSi13xt8PHm/H5X34puk+fbncMZK
         itYTSjzK7c8RAkAjWCodP+6Zg98PO8VnfS1W4PN/9+DbDOdk/j5DaGDEiCgbO1ywQlc5
         Ovny3ge3xtZH+OWQINpelAGt4n08FllUCoDx67zXVpzw5MT3PuIJ6vdEYB1H3IKXImEr
         p0Iiu3qQQXUF1qRXz+V+7cwwE/3/Ji7olohI+wUgZwyEf/a0PkPLAoOfUtnowJ1jZzxJ
         txd4i5bMfQk2m6Sr36Fc5j1L63kALAsOT+XgkvIeo4pplx08iHASX2cw6rMOJD82PWd4
         H9qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:sender:dkim-signature;
        bh=TQ1kE8zjkXsEOKgpDnRJ81WMBnwwGE+DuFfJR40oSM0=;
        b=Fv3BYLQ/0Bzc/oqAExrvxpL/VryNuKW7xnO4ARKwaGgI+Dt0xX3A94W+Vf8T56asng
         S3hfOfAjopz78ggafd6xaQsARKzybl8gmBd4JEhF2jvTwEfAaAAGlwd5Zs37PFcQU4iO
         nrQtOdgIOq5v/geECkfmAlFeQFXHt4VCNOS4qdNqfh0/8peQQuJJxM2L1cBK+pD8iEXK
         Dm5046G7Ga8L1mbHS2XaB2Uy9qT4KFdMwUJhBTkOWsb/tuzbQd3CzNdZi+40CJ/xJnZy
         2cTlgCFTaXcBG+lepP87/9edhmLq3e3Jxf1itMcJynEiJcrjdey25MS+XwXj98F80XES
         lh9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=bhGN0zBc;
       spf=pass (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id l15si20160otb.0.2020.09.08.11.40.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 11:40:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id p4so93697qkf.0
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 11:40:06 -0700 (PDT)
X-Received: by 2002:a37:d41:: with SMTP id 62mr1323744qkn.444.1599590405983;
        Tue, 08 Sep 2020 11:40:05 -0700 (PDT)
Received: from rani.riverdale.lan ([2001:470:1f07:5f3::b55f])
        by smtp.gmail.com with ESMTPSA id k72sm45511qke.121.2020.09.08.11.40.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Sep 2020 11:40:05 -0700 (PDT)
Sender: Arvind Sankar <niveditas98@gmail.com>
From: Arvind Sankar <nivedita@alum.mit.edu>
Date: Tue, 8 Sep 2020 14:40:03 -0400
To: Kees Cook <keescook@chromium.org>
Cc: Marco Elver <elver@google.com>, Arvind Sankar <nivedita@alum.mit.edu>,
	the arch/x86 maintainers <x86@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: [RFC PATCH 1/2] lib/string: Disable instrumentation
Message-ID: <20200908184003.GA4164124@rani.riverdale.lan>
References: <20200905222323.1408968-1-nivedita@alum.mit.edu>
 <20200905222323.1408968-2-nivedita@alum.mit.edu>
 <CANpmjNMnU03M0UJiLaHPkRipDuOZht0c9S3d40ZupQVNZLR+RA@mail.gmail.com>
 <202009081021.8E5957A1F@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202009081021.8E5957A1F@keescook>
X-Original-Sender: nivedita@alum.mit.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=bhGN0zBc;       spf=pass
 (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
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

On Tue, Sep 08, 2020 at 10:21:32AM -0700, Kees Cook wrote:
> On Tue, Sep 08, 2020 at 11:39:11AM +0200, Marco Elver wrote:
> > On Sun, 6 Sep 2020 at 00:23, Arvind Sankar <nivedita@alum.mit.edu> wrote:
> > >
> > > String functions can be useful in early boot, but using instrumented
> > > versions can be problematic: eg on x86, some of the early boot code is
> > > executing out of an identity mapping rather than the kernel virtual
> > > addresses. Accessing any global variables at this point will lead to a
> > > crash.
> > >
> > 
> > Ouch.
> > 
> > We have found manifestations of bugs in lib/string.c functions, e.g.:
> >   https://groups.google.com/forum/#!msg/syzkaller-bugs/atbKWcFqE9s/x7AtoVoBAgAJ
> >   https://groups.google.com/forum/#!msg/syzkaller-bugs/iGBUm-FDhkM/chl05uEgBAAJ
> > 
> > Is there any way this can be avoided?
> 
> Agreed: I would like to keep this instrumentation; it's a common place
> to find bugs, security issues, etc.
> 
> -- 
> Kees Cook

Ok, understood. I'll revise to open-code the strscpy instead.

Is instrumentation supported on x86-32? load_ucode_bsp() on 32-bit is
called before paging is enabled, and load_ucode_bsp() itself, along with
eg lib/earlycpio and lib/string that it uses, don't have anything to
disable instrumentation. kcov, kasan, kcsan are unsupported already on
32-bit, but the others like gcov and PROFILE_ALL_BRANCHES look like they
would just cause a crash if microcode loading is enabled.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908184003.GA4164124%40rani.riverdale.lan.
