Return-Path: <kasan-dev+bncBC7OBJGL2MHBB25377ZAKGQEKC3XQDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E25F1795D0
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 17:57:17 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id j8sf1284984plk.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 08:57:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583341035; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gkynu5re9xXJqXplHhzy8dB4eMHmdAm8Sp4uc8CcgKIEvbG0aPyU+nKNNRJj7+HsTM
         CTE7f7Lg6zUXgSOaPs+NyL/5IYLWVaNRc/hEDXImazr9fFcIgZaX54Xic3vnPtQDjMIf
         tIaTz/kDPB7y9v4emz5FrzeAR1iO8XDaMvof/Y9cju/DhqweBbiJzU+WAQ+gyeqvHWH+
         BwvEqjfSCu7CwOE4RduBiwP+6dx9Y74obMAHns4BaAgPAR4qvfNdfbGmI+9IM19xq2as
         rhwwP4SXGMT7CQ35atc2v/eYjqAITC1/a6FukophhrENAH7doi3uGNMaXX6SINHiwyg0
         058Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=a4y7L9kjNgoNHyc31skibS1Mo6yyomlctxPiT0C9YfQ=;
        b=GZBSQJ4Fbv9A4F5ii4Gil/LtwpHJR0dAzKwc7IkJW+Du3Bx7lEqLoeb1fTgLN3x31b
         U2RfkV7fmEqhvEk9EDYzlx6kQbHc+1L49AayIlzVnWF9vr5IGbGmK0MaGCMv/+URoRj1
         eXmNI2BypZPldEM1zh5hERPguLLp8x3owvgaalxL4ajksfRVlg9sy409mjp9tlP2WPWf
         Pg4Bno0WDlX0dcOGpMljhvp+Ewyo7+hYCPRAUGxbkCZwBB7M/buPOk9ndNstNj/nG1qx
         0QhKjZXtcwbkvN5SfSugWIIoFDNf0w0/kZ4Wse5fWPV3ZBrOGW+QaWfXDbM5ccQOha5m
         Cs9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=h8fJVp2S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a4y7L9kjNgoNHyc31skibS1Mo6yyomlctxPiT0C9YfQ=;
        b=JlZ59vMEFlGsB6WDGPj15FJpRfzMWJSuFT3gxqjrdB9nM3uxrvUTcUtshGwtArC1H0
         PKCFzRrZgQzFMPeMf1A1nIGpE2gg+NQ47/nJENX6l+W6WWN4pXKsBf64lFqCYdYd7iIC
         ckReyXoghq9yuGNbkPwVOjmB4m9tjHevPmG5TfYGqE5na2dt83Fxpo6oNI0ZCnuE7bkx
         8LCeUnEMl8CPLrhh/K76aLBPnsrO4bTN90jBAH/B4sgNSZ3NJyxSzQ4K6aNUvGnnQvqB
         tNU9Pycuj00Sb047M+z/qvMW6Xx6duEIQJkD5vKBp9bytGGvxAnTKucISSdQNNp22lHA
         H/2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a4y7L9kjNgoNHyc31skibS1Mo6yyomlctxPiT0C9YfQ=;
        b=f7UYHgxTTg4OFTLv4c8WyN9UAwSw6vPeLP5YiUC+F15EeHgVtCuSOay+Vu/GhgPue4
         GH8qU0nTNfBMwbjLO4USfpY+cPQyYnvmaVR6vkJB49IRvZrrYVSJJzw+JelOGOzlChp+
         9zLZdkyB+mN3RUk0ktyQNCKALbF2psRED8Q5qe3GPXhFxaDgKv+xosHYOvkWAnsDeSEf
         wWN7hxO5yGwml0s7MgaW+mFcqYdsEsQx/MYsqvPfP59/tRovOGSBlq86La/Y8hHWIHNv
         nlVhBBbBJFp+mdq1wWqEmjM+hkPLqOyXUo11BdrMiZ+pzVAi3Z3RAfYKButtAYBxSdt6
         DRKA==
X-Gm-Message-State: ANhLgQ1iAuo3Uzc/QPNN9yyZ4MkhQ4JGgBUhq2qO6klV+M+KOyXeCmIb
	1aoUGmM/10nKCZ2ee3erxdI=
X-Google-Smtp-Source: ADFU+vueU3Ez15aCy5obcYMhmR5Mw2nn5d1amWLbbCN8846kPWZQikt3RFeFK/GkpX/Di/Qn9nP0lQ==
X-Received: by 2002:a63:1246:: with SMTP id 6mr3341247pgs.4.1583341035471;
        Wed, 04 Mar 2020 08:57:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:e118:: with SMTP id z24ls758109pgh.9.gmail; Wed, 04 Mar
 2020 08:57:15 -0800 (PST)
X-Received: by 2002:a63:1f58:: with SMTP id q24mr3556454pgm.334.1583341034948;
        Wed, 04 Mar 2020 08:57:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583341034; cv=none;
        d=google.com; s=arc-20160816;
        b=iYMd9S9TdR63DD+4Cbu+q1PTAEXUnKVq8cUHbK01P3wsu+eNr0OQjD56TQgYN0fpor
         Rz0NpUYV8nUGhMgCniO5LKBjmy9ihZFexmR7TWd5pKzNM9m43CNLMKoqSnFbOdgnMCAH
         8fM5Fy5IaZBgvPInFtDdaN7McXFrOp4Iv9FOt42ihT3XnIoYEUmQqexz7o/A31vxDYJS
         z8zseNI80jNtTdsoJfLaB5GLhD1crLkqe0r2sVwflCaahumvXMwhzAR9CDchlM14WIpl
         dJkXf39JjhaEKtpjNNSjcWmLY/FsdgqD9Hbhh+lYPNi0Q4Y9e/mTOpdLWy2JQsGAB6iO
         iW7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yur0Lyv+QJRNaR7D40FqUvoblidYiD7uzVtpeJGfpoE=;
        b=W3vstG/AqJ3n5vyq4ToH4LMbo6uEm3ffp87CtoaPS9W+RBxClgjS9628rc9mVCscHi
         BApnQWWxoQAhyzt5m2E8FStg9cswraVtFtEfUoDxzMJzAlL/wN9J2NMci3HqZFvupGL/
         d6/ZVNvtcN7EJZipPbYslEsPup/sXaVoYwySOx/yyWtPD4APTTtV0VSu7pnhb/KZcLWK
         QvWpKMxohtXy3VHdFslXp7vmdKUYnQ4zJTRo81EFCw6yh9zEoZRDG1dT3XOYYEBSlObS
         19heTS97CnjcsNeMKmx4VDw6Fncf92G8PXOmkSx04mwgb+aEUa05bA0NilEE5GpeBkUh
         j6Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=h8fJVp2S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id s92si93003pjb.0.2020.03.04.08.57.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Mar 2020 08:57:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id j14so2713462otq.3
        for <kasan-dev@googlegroups.com>; Wed, 04 Mar 2020 08:57:14 -0800 (PST)
X-Received: by 2002:a9d:68ce:: with SMTP id i14mr3218726oto.233.1583341034238;
 Wed, 04 Mar 2020 08:57:14 -0800 (PST)
MIME-Version: 1.0
References: <20200304162541.46663-1-elver@google.com> <20200304162541.46663-2-elver@google.com>
 <1583340277.7365.153.camel@lca.pw>
In-Reply-To: <1583340277.7365.153.camel@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Mar 2020 17:57:03 +0100
Message-ID: <CANpmjNPKjbCi=m+3Cqyhh9o5xrmLOzB6O48vtAP9KMsEsgzNrA@mail.gmail.com>
Subject: Re: [PATCH 2/3] kcsan: Update Documentation/dev-tools/kcsan.rst
To: Qian Cai <cai@lca.pw>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Jonathan Corbet <corbet@lwn.net>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=h8fJVp2S;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Wed, 4 Mar 2020 at 17:44, Qian Cai <cai@lca.pw> wrote:
>
> On Wed, 2020-03-04 at 17:25 +0100, 'Marco Elver' via kasan-dev wrote:
> >  Selective analysis
> >  ~~~~~~~~~~~~~~~~~~
> > @@ -111,8 +107,8 @@ the below options are available:
> >
> >  * Disabling data race detection for entire functions can be accomplished by
> >    using the function attribute ``__no_kcsan`` (or ``__no_kcsan_or_inline`` for
> > -  ``__always_inline`` functions). To dynamically control for which functions
> > -  data races are reported, see the `debugfs`_ blacklist/whitelist feature.
> > +  ``__always_inline`` functions). To dynamically limit for which functions to
> > +  generate reports, see the `DebugFS interface`_ blacklist/whitelist feature.
>
> As mentioned in [1], do it worth mentioning "using __no_kcsan_or_inline for
> inline functions as well when CONFIG_OPTIMIZE_INLINING=y" ?
>
> [1] https://lore.kernel.org/lkml/E9162CDC-BBC5-4D69-87FB-C93AB8B3D581@lca.pw/

Strictly speaking it shouldn't be necessary. Only __always_inline is
incompatible with __no_kcsan.

AFAIK what you noticed is a bug with some versions of GCC. I think
with GCC >=9 and Clang there is no problem.

The bigger problem is turning a bunch of 'inline' functions into
'__always_inline' accidentally, that's why the text only mentions
'__no_kcsan_or_inline' for '__always_inline'. For extremely small
functions, that's probably ok, but it's not general advice we should
give for that reason.

I will try to write something about this here, but sadly there is no
clear rule for this until the misbehaving compilers are no longer
supported.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPKjbCi%3Dm%2B3Cqyhh9o5xrmLOzB6O48vtAP9KMsEsgzNrA%40mail.gmail.com.
