Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBR4CQ2IAMGQEAMINJYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 989834ACA73
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 21:29:59 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id r18-20020a17090609d200b006a6e943d09esf4785836eje.20
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 12:29:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644265799; cv=pass;
        d=google.com; s=arc-20160816;
        b=FnmZr7U+GhQZptuJOvmdlCgO8AgmcucDG/8DX2kVw7ns74Q+o2iepbKSiwGfQdferE
         6mJ0str0SuEMDycBS20h3OxUwJ3DzmIRsW/mKxhxjcubaCtfRxFWoHedPPy0EoJolWrG
         D/8icrXDNAriyN93B+O/0/LUoFkbeTQJzumFc4UskVsWx9PgEti4eR0e8frmYYTEBgwP
         wOMUDmu9IxsO9BwHhpPGLWMujnuZ70uiOTKVn+MJMmebIq1ZWjIE1Bc7j4B8oWOkPvPm
         NdR6V6dpaxSiVpUqoOqL7/8KikYlI8UZuO699wFhrqkoRigoYZw9vwNOmegOQOoBICFt
         yrbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/AkwSrRzlIe9tch0gQsxC0ZfKIOJZwAYy08IAbxe8No=;
        b=sQO5e8YijlM414WPil4JXohOLAZipInP0XC1mjaNY4NG4cdSAt34m///Wc/n/R4qnV
         oynjFCmAd83gzChZrr4vqs1HGhze2TOCYQwWRlStyYf9h+5JZUsIaQRRHQVcPeBZioxn
         rUAt//9+SshfNm0lvcFphygghsPb3sSeN0w91uvMRlvh6Vks132qTOZk37xjn3m/6cWa
         H7B32me4cYvTuZ8ZrByQ6kxVlBfw7PpwCC+ETovxPbJmjf6PU5fag4vJlHW7OMFNgbw3
         aYRkGnyO9twEsrfOyrfeSebV4umMSlBH0wTeozHCFyYALuvhdsX7KedXSwkP3iAgnZkx
         pCuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="h/r8mcsD";
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/AkwSrRzlIe9tch0gQsxC0ZfKIOJZwAYy08IAbxe8No=;
        b=aT1LaHVuV1ab5ApqUDroPQHGJQccE/MV9pnhrR1IQLsYrnepVfRYkib41C89ODq+ji
         nr4VCzGGlmfDQ0IWAsK80cbGqV6vwefq1drwyMSF/eti8Z//lkE1gzMlnXMbGC4tW5XH
         xiZtjC28NRgYfAcNbp+yIYfTufKQMYsIcQhoic+4cqcK8t+kMdQrx6F9vVDDJgleR+an
         kXFYo5fN9af7JddfkigSpz/zOU25KyC+tgKLh0soqsnV6EPwp5zM6NL+dPcAPul6u7Rg
         3zZtXhG6GnhhnYQtFC/WKgEkaNwFw23d6Q3zF7NHw5a9GWo49ulTEvzch1ynDdqdc+bU
         oiyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/AkwSrRzlIe9tch0gQsxC0ZfKIOJZwAYy08IAbxe8No=;
        b=B5CPzyxkC2H3NNrmnCt2w8nigaDnNV4YN8fAqxG/TruNiftUJuWwjiMD2s+Yui66e7
         UBZx4XXx5szeJe1Mw6C5Xrx0oW5+gTVGUbg/X6xFH8ZBbY7PIfIz7jeHILdHnOTA7YhN
         mKYtnI+xDovXQal0Qa+bxBUeelB4/XtLdmUURvdIQDj1IGDWzNmFc25PrfrhvRrh0osr
         RYavf0HmZ92oGtVPiIxJ90jHan2KZ5iE49pqw1Dr5BOCaMp0q5pb+oFAqpJ/18pDlnP2
         dt0ysOEFhtmBhE0TYm6YeOexXQNMCBx7Qx+gUyYGE0DREZfJMdNUvbyITJhPXHs4h7MM
         Vb/Q==
X-Gm-Message-State: AOAM531NKbp8tardhLe6I9kuMtGyd0K8wWWD2yK6R+YMEJwPnozKv/zZ
	xYdvpJAZKhD1388rX/WbMp8=
X-Google-Smtp-Source: ABdhPJwksxg0nyeP44d0gTfkPJp6G4Cz+TSAyEg5OOY1qgRWhnD9O3G/dPY/78gS7TadRQ1v8tLauA==
X-Received: by 2002:a17:907:6e16:: with SMTP id sd22mr1128997ejc.172.1644265799272;
        Mon, 07 Feb 2022 12:29:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:8a20:: with SMTP id sc32ls4102442ejc.3.gmail; Mon,
 07 Feb 2022 12:29:58 -0800 (PST)
X-Received: by 2002:a17:906:8451:: with SMTP id e17mr1073648ejy.99.1644265798377;
        Mon, 07 Feb 2022 12:29:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644265798; cv=none;
        d=google.com; s=arc-20160816;
        b=aej1lP0RB3EyhADAmlVov1cxQ9Ij81zolA1ho2o3zcIXiK7bepJqbBpRavYvELdX7X
         gCNWZeFMCP1KKKdNn94KiYNoCQLExZnWp28Z8i9VDhJEpcbC5u3fosQNaZrKBWYk6D3X
         5L5ZPO3VAEjgME6cqrPBgp5AWn5LJW+Wtgauzdfpo0UNsCAZf7ImW/7Kl+TBBAsIRpSF
         X3eEoOyk6kg2GF3Mb+MKn0Ofh5QOc45vlcUSTQg1SEQZvGkLUXXx+2uE+dga7//OzvCe
         +l9Gp17okMnOYMPWIKKB40o7J5xSPq0uAEsVmtZPKhcJzK9VCcDcb6g5rza9jbInmJKa
         DohA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=l7+lDRwMEEhHx0jHQ997hOwLnkm6ZLU/VDRQObDrGjg=;
        b=N4b5llfP+sL+wdPbidkN7bnIjZLHBkEtMFSSkphDrwR9lHhuTB0NNorRbeoMYu4zCH
         TuBqGYiQyfNseV6M0ONq6Ds9WAr95jnvELKURi3M0Jy4XuAX7+R9CYBREGJ/bUSkUnOF
         ajx4/TWn0Ijbtp0ZtYhh/d8z4Tt3I+da5+VRGXmzYiVgyUfHMkfMf8LC+z1RULQixf+i
         zDu6kMJlMEB0Utyd2WJ/d/bhT9mZdL206rXVrWCmtyOGR9+fEdbS1qy9le7cZ8aPxb4V
         MVUwKTfA2SrndX0DTMokza9YE5I6Ercmk6s77CarUeGQZwULuu0SLz4W0gCktrQ8HGa3
         Ee1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="h/r8mcsD";
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id s15si430857eji.1.2022.02.07.12.29.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 12:29:58 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id og43so21551926ejc.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 12:29:58 -0800 (PST)
X-Received: by 2002:a17:907:3f0d:: with SMTP id hq13mr1129891ejc.358.1644265797925;
 Mon, 07 Feb 2022 12:29:57 -0800 (PST)
MIME-Version: 1.0
References: <20220207183308.1829495-1-ribalda@chromium.org> <CAGS_qxoTLwvVjDGbfeOjMrGvh7sck7TDmiVeDXS2S5oyDWiKzA@mail.gmail.com>
In-Reply-To: <CAGS_qxoTLwvVjDGbfeOjMrGvh7sck7TDmiVeDXS2S5oyDWiKzA@mail.gmail.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 12:29:46 -0800
Message-ID: <CAGS_qxrkswforSv4XKGChwOZ0MbTGzCqYKsZq=0Sx6ThMOrheQ@mail.gmail.com>
Subject: Re: [PATCH 1/6] kunit: Introduce _NULL and _NOT_NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="h/r8mcsD";       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62d
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Mon, Feb 7, 2022 at 11:09 AM Daniel Latypov <dlatypov@google.com> wrote:
>
> On Mon, Feb 7, 2022 at 10:33 AM Ricardo Ribalda <ribalda@chromium.org> wrote:
> >
> > Today, when we want to check if a pointer is NULL and not ERR we have
> > two options:
> >
> > EXPECT_TRUE(test, ptr == NULL);
> >
> > or
> >
> > EXPECT_PTR_NE(test, ptr, (struct mystruct *)NULL);
> >
> > Create a new set of macros that take care of NULL checks.
>
> I think we've usually had people do
>   KUNIT_EXPECT_FALSE(test, nullptr);
>
> I'm not personally against having an explicit NULL check, however.
>
> But if we want to continue with this, we'll want to rebase on top of
> https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git/?h=kunit
> since a lot of this code has been deleted or refactored.
> E.g. see https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git/tree/include/kunit/test.h?h=kunit

I forgot to mention, it'd also be a good idea to update the new
example test case:
https://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git/tree/lib/kunit/kunit-example-test.c?h=kunit#n76

e.g. just adding
  KUNIT_EXPECT_NULL(test, NULL);
with the rest of the pointer assertions

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxrkswforSv4XKGChwOZ0MbTGzCqYKsZq%3D0Sx6ThMOrheQ%40mail.gmail.com.
