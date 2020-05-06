Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOUVZP2QKGQE7NOLKCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F4801C72E5
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 16:33:31 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id p126sf1880127qke.8
        for <lists+kasan-dev@lfdr.de>; Wed, 06 May 2020 07:33:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588775610; cv=pass;
        d=google.com; s=arc-20160816;
        b=PPEJ6g/t1IL/2RZK2EftRTzz9v4Jp1mZvwdySrlI/v79jDeu7L7LAWqH+21mIu5yqZ
         WP/9NA6hyIN2sjT86yPA+O6D1Yfkkok8q3YMyQXTxtbE2fhUI0ZE0JRZY0YaJxzIOSCw
         Xfttt0H0CY3sVyGol9n96/C42gv0jnkCS1Y405+SYcRITPnMWcOEcEhBPew7a+1rng8w
         JduBxtAOxsRO/yCD4R6UArni5En92fsFP7iVVIKSIS9NTDXeE2RDzJNGFLBKCF7FGjBo
         yLLREhE+9773T/Jhve/O43gWl22LtWWy5okNw3N/1C/H6pStuJpPRHeeC1xzlsWq9YIo
         a65g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=g7YyG+hXkCrEAMJQHkOOgKNVsIkDm1e7cD2Mthb5yw8=;
        b=efgPs7rpF8wsJEiGhO8ldxlcuI6MbCwy2cFDhkiNvDPxbuOamZPtzvTNrwyk5Cj1cK
         yosSDvJD3acSnOI2hIj1+y05dg8zQlPgX2pTJn5a9JvyB8VLDeTUHBDystJWiL05/KPu
         QI17gM+ZUBxttqxBFhZ0bM6WI4/jq1ln+aGTNeGrtUbL92SQoEdS5+Io1byb/C95nzbc
         C6RAgnmXVqhh0LYBq/wV8NR1RWhb0yX8IzF9HhgUNGI31oicNbNKZuDqjraeRbMLE7PT
         HOs8I5Opiqoj2Y2C+EL+QAS8YKcBeluOhwWrI4aNYiP1bIq3x2jZY3oA25Kctz3kVsVM
         /JIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FZnr5yyR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g7YyG+hXkCrEAMJQHkOOgKNVsIkDm1e7cD2Mthb5yw8=;
        b=YBn/lGUfFwQ10U1ggl1l5fFflIUpZvmfEGFtGmJ2y8Ndgl5WQUKE872mVdDevJd/k6
         nfYTH1NPExbRKLNoci8ePqwMgaTpYQPkajEWTsL2f/qeeBqcJ9X4fqM44nwMSMAGCRcF
         3xWI3qTf0e2dwlqB+LFsRofKgV7BqaCMoz/lZzdvnEWbHsrK2m/TtDFP6s2fsTV9SBJM
         n6c+srSXgGZFAzuZXahybXxUVfcfXk+DnVTYThxoUVbFd5ZNADr/h55Sqfu2u1JNehUW
         R74u02bXrWsw6zeDoTxwL/3hThZGxh6ucY2ya4OtWvFGRF1IZiY/Hn7Z2ilo1TczJMlr
         n6+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g7YyG+hXkCrEAMJQHkOOgKNVsIkDm1e7cD2Mthb5yw8=;
        b=WkykiPdqo60AggZ5C6rkUaRDEDJT45f6KLSE43Px0a00Z1t5hYU5Y7S4K9RyLaDheW
         KMzAvxuzchk6o2bIShOCyEUfvoknp5g0PjKspLiKtb+ZFzKz+NcP5YQo+317ZHlA0B5Y
         NSMDBC3FoDDxnVgyoQLdNctZ5feLGbnHPJxX3WlwdIxIC3jW1+18gJpiUQTwuIui3ov0
         MvpBex7TvY8xSPEHlGyG9ErsFSbq35jipJezR5gok8iO/Ca+Zy3+v6aSBplDs9sStAPB
         1xi8sjahD/mep8l7fKxYa7d/vMtMXR7UmLyIVIJSbn7wNMa1NluMWd3DmFXO59eJREBV
         ePaQ==
X-Gm-Message-State: AGi0PuaxfvMw8O3Y0iEK9Z1KEyle/4YEyBSzgSrpJIsqPFWV2CVcWvWl
	V1rel7TsDkul0xAjijvCg5I=
X-Google-Smtp-Source: APiQypIGUL6qS0cgJPgfnCYbswg3vWxGHpeCYM2KgbjA58Ul+zaMs3z2JkMiuMNH0wM1tmQzACstsw==
X-Received: by 2002:ac8:3581:: with SMTP id k1mr8717612qtb.50.1588775610072;
        Wed, 06 May 2020 07:33:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ec06:: with SMTP id h6ls1980290qkg.9.gmail; Wed, 06 May
 2020 07:33:29 -0700 (PDT)
X-Received: by 2002:ae9:de83:: with SMTP id s125mr9542309qkf.33.1588775609162;
        Wed, 06 May 2020 07:33:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588775609; cv=none;
        d=google.com; s=arc-20160816;
        b=HJVBbTRl9cD2XoW+r1CBdRfU2XHMdWCNsCLHr7IQ+asq2vQO6gPcerLVewcYSmPuye
         qz3ISQouZaj/+luHhDcrbEnl1kQ8JkPi+G2TSc58vdvnHM1+TmEDmyVTEISdXXxqWDgP
         PxVJMfbyumIhXItWD0dOg9piw1IFgoFPM7HHsk6xn4wO3QMzUGjrhxorC3Wp1t8Y/qaI
         XXVecfeV12whCvjoMQtXaEcm5bImRDLWiBu5qGlBLM/APpnqJ03XfkngSE98ZdEs6YA0
         fWDAhrzzxW3AI9a/aLbGZsmYyc5M9p4EGZp27UEA5K92EVdtGFL48k02EaMS9K/gNVYS
         0mIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CKaG65pfWBIrxWgKL/V3GCu1CzEQCO5YtFQd2K9q/Hg=;
        b=yBRimI1bdksAVMh9KbH2ZP1B+RTutOU/dah3bJPvYOtI53wUWCHlgNIqTKtpgeQ6yh
         RBuU7EJq172YfmHttYukwnh9zOC3OJz+9QhxuAJ3Hs+hyJ+JcFVtC7acJtOOKeZWzykl
         5mDtkPziO+Vv8ZppC6WSaGai2ZuoZmQGZ9/32OzYngdHjCq9lQRmZYLCKlniCFUexcnF
         BxvpON1UQ52g+XItnXxCA+FJ9UyiIDE77uQoFktwO1bblWhxJyAjTVIXHiRFHR8ihmy9
         F+KOuHSXUACsOdBNc1zbxEbJPxbijfOeMtKFSBL7/O4RdHkftU9uqEZvh3vtMl3VbTRe
         AQEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FZnr5yyR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id f3si151997qkh.5.2020.05.06.07.33.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 May 2020 07:33:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id j26so1525196ots.0
        for <kasan-dev@googlegroups.com>; Wed, 06 May 2020 07:33:29 -0700 (PDT)
X-Received: by 2002:a9d:412:: with SMTP id 18mr6834810otc.233.1588775608353;
 Wed, 06 May 2020 07:33:28 -0700 (PDT)
MIME-Version: 1.0
References: <20200423154250.10973-1-elver@google.com> <CACT4Y+arbSpBSwNoH4ySU__J4nBiEbE0f7PffWZFdcJVbFmXAA@mail.gmail.com>
 <20200428145532.GR2424@tucnak> <CACT4Y+YpO-VWt5-JH6aLBc3EeTy4VHc4uBc33_iQNAEkw0XAXw@mail.gmail.com>
In-Reply-To: <CACT4Y+YpO-VWt5-JH6aLBc3EeTy4VHc4uBc33_iQNAEkw0XAXw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 May 2020 16:33:16 +0200
Message-ID: <CANpmjNOYx7s9EJ56mdwyGyTzED-yq3B0UvkiZ11KmCe+QMt47w@mail.gmail.com>
Subject: Re: [PATCH] tsan: Add optional support for distinguishing volatiles
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Jakub Jelinek <jakub@redhat.com>, GCC Patches <gcc-patches@gcc.gnu.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FZnr5yyR;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

Hello, Jakub,

On Tue, 28 Apr 2020 at 16:58, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Apr 28, 2020 at 4:55 PM Jakub Jelinek <jakub@redhat.com> wrote:
> >
> > On Tue, Apr 28, 2020 at 04:48:31PM +0200, Dmitry Vyukov wrote:
> > > FWIW this is:
> > >
> > > Acked-by: Dmitry Vyukov <dvuykov@google.com>
> > >
> > > We just landed a similar change to llvm:
> > > https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be361137efd705e05814
> > >
> > > Do you have any objections?
> >
> > I don't have objections or anything right now, we are just trying to
> > finalize GCC 10 and once it branches, patches like this can be
> > reviewed/committed for GCC11.
>
> Thanks for clarification!
> Then we will just wait.

Just saw the announcement that GCC11 is in development stage 1 [1]. In
case it is still too early, do let us know what time window we shall
follow up.

Would it be useful to rebase and resend the patch?

Many thanks,
-- Marco

[1] https://gcc.gnu.org/pipermail/gcc/2020-April/000505.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOYx7s9EJ56mdwyGyTzED-yq3B0UvkiZ11KmCe%2BQMt47w%40mail.gmail.com.
