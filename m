Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4NA572QKGQENI47NPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 731201D102E
	for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 12:48:18 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id o187sf11861213oig.9
        for <lists+kasan-dev@lfdr.de>; Wed, 13 May 2020 03:48:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589366897; cv=pass;
        d=google.com; s=arc-20160816;
        b=0KwGnmjKXvlnBMTISESg3z5yjZ8NRp4aUbMtu+KLmzsE0ipL/i+cli3GwlRSVKPc5M
         ftXlfn3I35j7QDLGTMMiVPNj7Y3AoAOylOs7acyKrAzVAftvkrPcNRJVJiaUXyWFE7xG
         6xPRuj34QWU/tGHBR4nwfd+LDpoO6FtNwHA3f/4PSpSqdCQUEbqeI7bd0Dkz+kwuQjA4
         p2W2OwYxtXq2JXaIbW8VtehdPCZ0F7uYK9RJptAXfmR3CQsyOML/hIpPvWGEWEE4TyQF
         bIT2z9UQ5Q0hh9D54js/jI37WUpgfjMc/YSJkVbR9XEuTDBgZ2lC844LhMFxdupzbP0A
         pOVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=njofn4edXAcoOFlem0ad6RF/gJ+RMnxov+VZNbOmZaY=;
        b=uuRAdhkNglMSEIXUXDkDBHrrzIB1lE+6Vhf6W0+HSMICul86zrh0Jf701Db4Hy6AT4
         HGyoc0PM289lgXYZl6AmdrGiAEW384slFLalgwBXEblaOKXyoV6+TJIJigm+w1xO/mIY
         /LfWIEGaIgbsOedjEnXflkoWzg4ocFNurvxuMljsBUCb8XJb2LaTsfcH0EWsTlsVILpy
         3FIKYmek6o7cg68XQYqgLAeiO7N+PgVkwFn4cekZsK3XKssI7Q7NLmM/nGe5fuKa3y9X
         hewBFSG4Z2v1hTZkxo19Z/+FEPG5S9R87ocavEfVMd7IPZK5F1+bC24vojwhi0t8bmHC
         1+rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WSDuLbgU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=njofn4edXAcoOFlem0ad6RF/gJ+RMnxov+VZNbOmZaY=;
        b=g/5XTfZPbj2S9Taro1PDw/+4aui2fyodCWOAs46aN7VeC/BodPr4TlO65OyOX/VaSQ
         626uJ12YhFdOjG5053JfVvCRz52Pm+zNx2KgGo8aMsVkWjMeZrNykJH8i8yZN5LHYmsb
         +FZfT0oEH86LkneKbagqgVV/+cLNSDxrnfZFaBmBThdlOpv/bCDA8o3L7Oie4pdRKOtj
         lY2XTE0vRPlhc5/ogOZY8KVx1pXsQmZGrjL6usmGQ+Nu6RHgpH2gV2OzsoG7hRZJ4vQ6
         J2ycdJqYpuBh4E6AUY+xbSk5f4JEXMz2a4QECfiUhnmlkf/+AznZLBSbkFsFzcCD4OVt
         7jqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=njofn4edXAcoOFlem0ad6RF/gJ+RMnxov+VZNbOmZaY=;
        b=V2NoDbQ5mngq8eMsf3z7zXVj2RZsOVlDhEyPeqij5hcPH+7gxo52P4tGyD2D8CwU4g
         PLO5YgA5ZbQkRS6n35Kd7HlloIrkfN7DZIr2v/BoNesfiZHSkMzoitn+5+FMqKkhsAU9
         ZGmgb0LzN3NNI7E7BI2Q7c+zc5xp12EvlPFhx0no9SvHivsBYG6jyhJJ7GAi3AmYQCMq
         pcUgzo+stTKNGBmoa4etmlsFGN8SrfYZioDH9YF5cshYZGU3EmChLOq/r94lpg9kk6bT
         u1M5mtqNfLptWPpMYyNadmZ0Hep7y+c494oXCSbPW39x8HK5fLyFYh0k7U02LFTxsuzM
         sMLA==
X-Gm-Message-State: AGi0PuYNvHngTyyO160MUoOsWu9Ph58jcSXsW55VNYjLT15edA5EvuIO
	9sJeyrEV6Yq4TtMG7SuJqcs=
X-Google-Smtp-Source: APiQypJMM2kkViZz0cELP0p644TuA7zmgOCuIE7rQNL/c0oeySVy1lOaIyEqLMoyfaJBorpkdbhRWg==
X-Received: by 2002:a05:6830:1e7c:: with SMTP id m28mr21394246otr.151.1589366897209;
        Wed, 13 May 2020 03:48:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:1eb:: with SMTP id e98ls371143ote.3.gmail; Wed, 13 May
 2020 03:48:16 -0700 (PDT)
X-Received: by 2002:a05:6830:1da4:: with SMTP id z4mr21839042oti.244.1589366896852;
        Wed, 13 May 2020 03:48:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589366896; cv=none;
        d=google.com; s=arc-20160816;
        b=W785CAfE+rQq8oel19QxloRT9Yq6+qlKI+acUiNSnIxEFtCd7iRh6we0gfHEj0SDdy
         xL8Lv+MEMl0lUYhmhBL3OV8PZpN2XfsZKxuYYt/Okh3e3OVHuMyG6QHjFB18ly42/EUO
         trrAxrFY7P73WKhILh7laqBuvzXtBl3e64xVwA9BIvRVlNevxPw4EvviYf2OR3aATY41
         KtpW+sG486WjQrUITbUbCxUoxOudr5jUYfUcGKF1LZHOmYUU5CdSSexhGMA5qZm328WW
         Vx51GZdBxUvQphBtdU8q6S46auAQz4tMdVcfPHmLWJinVzaJhxYXKujw4xiPKWRuvvll
         xgag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0c6MlTKXUYuHlbC+2G/ALEP/TjZi6GA+V2waX/rc6VU=;
        b=FISZpP8TubsF8UNBmjloV4Sd/oJr6ufKjSpSyWFro81qAGCcFiAmg130lqWfSS7fmW
         hpFYmM0vt7tFLuXdGyDPdTBp4gXtZbuZZ7xV/YziCe12CpCHnAWK3RTr6VTPfGhltFZy
         v5Y0x074VtE9Qt74FkiYGaKr5dfGejY63bm034sxYD2HQHTlKVoAcK+TeCUPf/Jv1zuZ
         QtZ5caFjSG94osLBaISM9CU2h4snWBlKYVHK8bTvjoqhwte7F4FVGL8nMs9zSi4Sq03F
         SiJZnASVOc9L3rl6dLdfX9/XYi/dZ9wOZuvVqR/KR/k5rbQLhlUDAaiJXImzZPrYdBb5
         oeRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WSDuLbgU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id l22si737900oos.2.2020.05.13.03.48.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 May 2020 03:48:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id i22so4413409oik.10
        for <kasan-dev@googlegroups.com>; Wed, 13 May 2020 03:48:16 -0700 (PDT)
X-Received: by 2002:a05:6808:b36:: with SMTP id t22mr27348779oij.121.1589366896224;
 Wed, 13 May 2020 03:48:16 -0700 (PDT)
MIME-Version: 1.0
References: <20200423154250.10973-1-elver@google.com> <CACT4Y+arbSpBSwNoH4ySU__J4nBiEbE0f7PffWZFdcJVbFmXAA@mail.gmail.com>
 <20200428145532.GR2424@tucnak> <CACT4Y+YpO-VWt5-JH6aLBc3EeTy4VHc4uBc33_iQNAEkw0XAXw@mail.gmail.com>
 <CANpmjNOYx7s9EJ56mdwyGyTzED-yq3B0UvkiZ11KmCe+QMt47w@mail.gmail.com>
In-Reply-To: <CANpmjNOYx7s9EJ56mdwyGyTzED-yq3B0UvkiZ11KmCe+QMt47w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 May 2020 12:48:04 +0200
Message-ID: <CANpmjNNzkcddHMMucH9CxpUeHoee9g5ViMLUuRPBvepo7TBHXA@mail.gmail.com>
Subject: Re: [PATCH] tsan: Add optional support for distinguishing volatiles
To: Jakub Jelinek <jakub@redhat.com>
Cc: GCC Patches <gcc-patches@gcc.gnu.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WSDuLbgU;       spf=pass
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

On Wed, 6 May 2020 at 16:33, Marco Elver <elver@google.com> wrote:
>
> Hello, Jakub,
>
> On Tue, 28 Apr 2020 at 16:58, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Tue, Apr 28, 2020 at 4:55 PM Jakub Jelinek <jakub@redhat.com> wrote:
> > >
> > > On Tue, Apr 28, 2020 at 04:48:31PM +0200, Dmitry Vyukov wrote:
> > > > FWIW this is:
> > > >
> > > > Acked-by: Dmitry Vyukov <dvuykov@google.com>
> > > >
> > > > We just landed a similar change to llvm:
> > > > https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be361137efd705e05814
> > > >
> > > > Do you have any objections?
> > >
> > > I don't have objections or anything right now, we are just trying to
> > > finalize GCC 10 and once it branches, patches like this can be
> > > reviewed/committed for GCC11.
> >
> > Thanks for clarification!
> > Then we will just wait.
>
> Just saw the announcement that GCC11 is in development stage 1 [1]. In
> case it is still too early, do let us know what time window we shall
> follow up.
>
> Would it be useful to rebase and resend the patch?

So, it's starting to look like we're really going to need this sooner
than later. Given the feature is guarded behind a flag, and otherwise
does not affect anything else, would it be possible to take this for
GCC11? What do we need to do to make this happen?

Thanks,
-- Marco

> [1] https://gcc.gnu.org/pipermail/gcc/2020-April/000505.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNzkcddHMMucH9CxpUeHoee9g5ViMLUuRPBvepo7TBHXA%40mail.gmail.com.
