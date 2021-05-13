Return-Path: <kasan-dev+bncBC7OBJGL2MHBBREK6SCAMGQEHIXVU7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B9CE37F5FE
	for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 12:54:03 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id u14-20020a056830248eb02902a5e3432ae9sf16750999ots.12
        for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 03:54:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620903237; cv=pass;
        d=google.com; s=arc-20160816;
        b=o3JdTyRoTZDMAHCPxT3jGO6u0+6u9w8j7YolUf4M1dLE7Uh7BDLrbAbt8c11k2sfx4
         zzTlArcydqLeWKe1qafYahUcLv1TGtJo+aO6BeH0JCx3+1Geqc0fOVZLSqQfkEP+WM8c
         M6KddTCoifKpSje7nl9J5vi489fnYL1tNUIy8Ne7R3xQ5who5VHqMDEeSiaF17HnlA7V
         qPHnLXQTVGch34H0kmB0JORzN5+H9dsUqzxyJEhDhOW1jvMd+d39aGoiYGhWcEyAyUfi
         dgdlVyzwuVCpODSLCZKEUZt99sAz476Dhx4k9UK8PB+O0Gb5eU2gU9lxKXbRHMSmc00j
         Ambw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=C9SwxbKrL6ICSDY6WOPj+BncuC/iaAmvnFX+VCQtX6g=;
        b=QsmiWba9KIQ54AFz6Mmtw20aNGWTgh4moEyHvX4AY7HBaZ+vPO11lii+eXmcJbIs5N
         TcMojlaG0W6yx2Zaefnt8PQ2K65d4kSgnaMLzeuirnheZSkzvn4rmOAV4J7gve109TwR
         BUP0pwLwTxycDFC51TUAqcU5lheukg7Il+XWTzciIA2X8joK+kRz0vwjn8Uoaki0U0ws
         egMIlvPBXZer8LEO7mmDCmEmiTsXjFgNDTzR+Pqd/jOIG7uOHWYx9UfQM+3pDWqHFA/V
         FmGxgnvL5iKcsD2i4/0um0vwNLTYBaX9Jvo545xmLR2NOwzbAv7ceUXx0/Qsg9KtQPfP
         yv9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Nwnt9aKW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C9SwxbKrL6ICSDY6WOPj+BncuC/iaAmvnFX+VCQtX6g=;
        b=RTTsN6RQdQhW906ES4gPw+YVZvpXvvMK3rE6WR5SDn7wOBGJ/Z9+ZrGiKGqS3E2LHi
         gijjsu+5TgsrnT+5oVQbtW9YuTmE8TWoE/SDEOkGXAtcbTcMoHlluqAZxl/NL8AQWyXj
         biaFVxLRDBFvVFkDkjNOo65/dpxLH1WwbOBE803evJX359Oi6CvFondU5ooM+nJXIfvc
         v89Fh2TwTI3a7RMxUqkJ5GrRFr8t3aFExyHUUcPGeeFBWnjXrHRLgN2mvKZTSnz1cAde
         pdpzL7VV4PRSqC4SJMYhl8zl5RuhPphxvGuKt5b24D1KA6tVqK+j61TUOwh1SIw64YLf
         vxRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C9SwxbKrL6ICSDY6WOPj+BncuC/iaAmvnFX+VCQtX6g=;
        b=FGVfYwh/xVddl1glrhC+3pL76uxXxfjpU7moMmydd6yT0qHesvZS2bhjElhy43uHZL
         xITDj049TczbeYt4TQihV09RcDKqXgFZRCP9f+c6H2FtpYhXFBIr89ac2on1G/I2mx79
         fsaJT6GlBYsZzeNiD8TxgmZam6yIYymq8Zqz/kgLLH67CiCx+o2gzN27w1LMjY2uOD7T
         21bKRNW0GDIL52IGk1DYxf5iDC3Rj/KKFmf7zHe+/RYOlWfKGVy07Uv13+UyeBnX4yYd
         ouo2mNUxZbHkPShWjIai5htV1aIooLgsh76E7vKYMVZILT8RJEvhHVMFkr+oM5Ks79d2
         SOrg==
X-Gm-Message-State: AOAM530eKmXqxoe1zlZzIE6sezln2WGLcoMVwZetOUVfsC6ZNdR7m/07
	WovVb9DALw014GzeXXhIp24=
X-Google-Smtp-Source: ABdhPJyjWQ/FQQtWirSMkploI9qAfoDOv2w8K9XKkNT3MaaXBKpy/r5AtYTUs72pTy+/jBgj1AYwXA==
X-Received: by 2002:a4a:eb97:: with SMTP id d23mr16274202ooj.70.1620903236979;
        Thu, 13 May 2021 03:53:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:1711:: with SMTP id i17ls1573967ota.11.gmail; Thu, 13
 May 2021 03:53:56 -0700 (PDT)
X-Received: by 2002:a9d:d0e:: with SMTP id 14mr35537941oti.12.1620903236629;
        Thu, 13 May 2021 03:53:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620903236; cv=none;
        d=google.com; s=arc-20160816;
        b=CSAVKUudmBJurmlTePS6qCeasx8qYGhorHhJfEryCOOHyF2XVOAgngSvI3HQYCB92Q
         lHxqcE3FojgD6nKO5LI+S1h8K9bJGKlPTk4rP9X8HcDA0HstxYHhd8wTgp7xbvW5Z6B7
         m75C3aAizzJyvPT+IrQViAVW2YE3dQUgpWhgGHuxZ8gwJ8NOKXmx2EZbLN1X0ndA173G
         EPUpH7AbrjJuvgFkWdTcWi8oOECVRgUxX4DzNtpyxMvehQ7yj9VDshpxHu+0AX0Qz1I8
         3vW9gtqXQJy3+7dGJww/tR02Ap8MbwJPyl8oTxYT9YDEjZG/tNGh6PWMr/vJ6DTfEvsL
         /8qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lYLCvpNZX5w1upIsGWaUJr6yD2kIWAzqUdyxsIrTylA=;
        b=vkQj/Fsf9+8xGDvMfsZvHjaaOsH3HeFFm7dfYlk6yr205bP6/gKCRcrUDr5KBwdaCh
         efU+ibBL0RKlxmms+VvwJmiOTU11NphPIMgifmjtIc4IzOpzPMK3FrRGXNDqLKinXg2a
         ynp8N6g9wH7ki0OueYW1+9dXFlLIlpI4bAcUnQxp0L07EX9fOaLZ6X5NPEAhZU3/+0mt
         RD/MoVOjlcoO9VdVQz6YudjYZKdd6ksm6hckj0bGu1Fpy5GOQXG18ezYIL9MrbxQIXoA
         3NaSnNtQ+UZlS9aDE9Jnj/aFJ5rT/aFDTlfhDDLNbtgt9yZTiLFTxD/PNFsZ26h1/PJE
         mO2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Nwnt9aKW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x332.google.com (mail-ot1-x332.google.com. [2607:f8b0:4864:20::332])
        by gmr-mx.google.com with ESMTPS id x16si154981otr.5.2021.05.13.03.53.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 May 2021 03:53:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) client-ip=2607:f8b0:4864:20::332;
Received: by mail-ot1-x332.google.com with SMTP id t4-20020a05683014c4b02902ed26dd7a60so13095497otq.7
        for <kasan-dev@googlegroups.com>; Thu, 13 May 2021 03:53:56 -0700 (PDT)
X-Received: by 2002:a05:6830:349b:: with SMTP id c27mr17419866otu.251.1620903236141;
 Thu, 13 May 2021 03:53:56 -0700 (PDT)
MIME-Version: 1.0
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
 <20210511232401.2896217-1-paulmck@kernel.org> <a1675b9f-5727-e767-f835-6ab9ff711ef3@gmail.com>
In-Reply-To: <a1675b9f-5727-e767-f835-6ab9ff711ef3@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 May 2021 12:53:44 +0200
Message-ID: <CANpmjNM48id0b+H=PqFkCBDSyK76RFTB3Uk0mNeE2htu3v8qfw@mail.gmail.com>
Subject: Re: [PATCH tip/core/rcu 01/10] kcsan: Add pointer to
 access-marking.txt to data_race() bullet
To: Akira Yokosawa <akiyks@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com, 
	Ingo Molnar <mingo@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>, 
	Boqun Feng <boqun.feng@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Nwnt9aKW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as
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

On Thu, 13 May 2021 at 12:47, Akira Yokosawa <akiyks@gmail.com> wrote:
>
> Hi Paul,
>
> On Tue, 11 May 2021 16:23:52 -0700, Paul E. McKenney wrote:
> > This commit references tools/memory-model/Documentation/access-marking.txt
> > in the bullet introducing data_race().  The access-marking.txt file
> > gives advice on when data_race() should and should not be used.
> >
> > Suggested-by: Akira Yokosawa <akiyks@gmail.com>
> > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > ---
> >  Documentation/dev-tools/kcsan.rst | 4 +++-
> >  1 file changed, 3 insertions(+), 1 deletion(-)
> >
> > diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> > index d85ce238ace7..80894664a44c 100644
> > --- a/Documentation/dev-tools/kcsan.rst
> > +++ b/Documentation/dev-tools/kcsan.rst
> > @@ -106,7 +106,9 @@ the below options are available:
> >
> >  * KCSAN understands the ``data_race(expr)`` annotation, which tells KCSAN that
> >    any data races due to accesses in ``expr`` should be ignored and resulting
> > -  behaviour when encountering a data race is deemed safe.
> > +  behaviour when encountering a data race is deemed safe.  Please see
> > +  ``tools/memory-model/Documentation/access-marking.txt`` in the kernel source
> > +  tree for more information.
> >
> >  * Disabling data race detection for entire functions can be accomplished by
> >    using the function attribute ``__no_kcsan``::
> >
>
> I think this needs some adjustment for overall consistency.
> A possible follow-up patch (relative to the change above) would look
> like the following.
>
> Thoughts?
>
>         Thanks, Akira
>
> -------8<--------
> From: Akira Yokosawa <akiyks@gmail.com>
> Subject: [PATCH] kcsan: Use URL link for pointing access-marking.txt
>
> For consistency within kcsan.rst, use a URL link as the same as in
> section "Data Races".
>
> Signed-off-by: Akira Yokosawa <akiyks@gmail.com>
> Cc: Paul E. McKenney <paulmck@kernel.org>

Good catch. I'd be in favour of this change, as it makes it simpler to
just follow the link. Because in most cases I usually just point folks
at the rendered version of this:
https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html

Acked-by: Marco Elver <elver@google.com>

> ---
>  Documentation/dev-tools/kcsan.rst | 5 +++--
>  1 file changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> index 80894664a44c..151f96b7fef0 100644
> --- a/Documentation/dev-tools/kcsan.rst
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -107,8 +107,7 @@ the below options are available:
>  * KCSAN understands the ``data_race(expr)`` annotation, which tells KCSAN that
>    any data races due to accesses in ``expr`` should be ignored and resulting
>    behaviour when encountering a data race is deemed safe.  Please see
> -  ``tools/memory-model/Documentation/access-marking.txt`` in the kernel source
> -  tree for more information.
> +  `"Marking Shared-Memory Accesses" in the LKMM`_ for more information.
>
>  * Disabling data race detection for entire functions can be accomplished by
>    using the function attribute ``__no_kcsan``::
> @@ -130,6 +129,8 @@ the below options are available:
>
>      KCSAN_SANITIZE := n
>
> +.. _"Marking Shared-Memory Accesses" in the LKMM: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt
> +
>  Furthermore, it is possible to tell KCSAN to show or hide entire classes of
>  data races, depending on preferences. These can be changed via the following
>  Kconfig options:
> --
> 2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM48id0b%2BH%3DPqFkCBDSyK76RFTB3Uk0mNeE2htu3v8qfw%40mail.gmail.com.
