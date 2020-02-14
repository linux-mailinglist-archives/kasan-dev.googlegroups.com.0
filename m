Return-Path: <kasan-dev+bncBDK3TPOVRULBBXW7S7ZAKGQE45YVB5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F02A15CF3F
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 01:54:54 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id y8sf6136017edv.4
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 16:54:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581641694; cv=pass;
        d=google.com; s=arc-20160816;
        b=P3JJ2j7K/dWiBne/lkicCNOMiSo7Rp8nMgo//P7XzIeZGhsHInDUVBWabB2L+RZQ+J
         xPxg52/gQGhty5lNkfZ17D2cWxPuo6MBLhXuYIO4N/XY856NORM0c/6Uofnb93Ig9PYa
         AvESfGforKlOIPtn6FctyfAp/p2NOgOAixER21w74b2FZBLf2Z5BGOau1gddKpT6DGK+
         5N2q2uJGa/0AQcotLqgAGg/NfowHUnrZoyQy5H26A+0SC4TMCYnC439mdaF87ARbOs8F
         ROcLv5hC1BaGfe8vjALC0I9RSUDWWtdwwY0fdybH3S8Uo2t2XO9U56W1W9exLvPz13rO
         4weQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2L61A3D87Sjgm0C6fJL9s5s3QH8JvH00UVDm5BEH5cI=;
        b=ybgip3wxWWDCEkILjzWvW8bDzGPmudFIcLka6ZIIrlFhjTh5dqMTUkDiDOksIPyDNE
         HFj/KF6JM8iX0jz8iJH7FD+urmbsO3hlm1Cacc/wFmoZLkiun7f+ey/Zm1P4BHt5SDFh
         rvhzcKSKMVrh2fMFt2P+sCIv78oGslW1ezlkhkJqaAwVWlE6GA1vTVWZCKKJO6D62LZR
         zUbax5qpnt/6G07aLJhU8/W6bv4p/5kI1jm2LRaWrxvGu9z+aGwSHR+ITPoA2wbK3yoM
         Tl2sts9xVNk2RBS1KCZaUSSpTGFtFEGcKkYrw9Gy2pYw+Kx9FLpyz0K3Tx5AwA5HwYIg
         J8lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cGa0u271;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2L61A3D87Sjgm0C6fJL9s5s3QH8JvH00UVDm5BEH5cI=;
        b=qiEtMGqZ0pbe0cqN3bzyXzYM8+NIUjVPN4x+PS7CfD+e9B/gvgbWfx6PH2nRoIHFJm
         Qs3D91XY3HyhHlwDlU+DiOOWBC17K17Sls8sv+X5sHzfPqPwO5Wv4cXHK5ER7V6HJ6Lr
         vPsSl/iBBg5gThOwaH1f4rR8Ajab/aoh9cWb0DdPXawwYoCcQI126r1l0r6dLAerXEz8
         vZafkaNFZ/D92Fps01Cz7jljGMpdAzlsCaFDlbVxf8b1SR+YjTa2APUdhmMWd+l+gF8S
         pDioDNt/Msyoh5fSq26JXbqARZcB9o3Svnv91PnhMBSPI7ptThNmfgl+ERg15gFwzIrO
         1QOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2L61A3D87Sjgm0C6fJL9s5s3QH8JvH00UVDm5BEH5cI=;
        b=NI2NII/aJgrSK58diuSqkf2NJ4Z8nUBs/IJpP/QJiJI28s+y8MnZLtRpUORuN8nAX0
         Y2pVhn8G4nIYrkVyS4506oYl+jvFu2UK076ybgG6Wqp6XLPUf9o4GPLklpl8bwsRsXJU
         VBdnZx55Y/Lxb5LGFlGwjvSGlYIh0ofmR7KZaFDXYCcJdZDTZ7pHr2gcQtTXiHmrsfem
         c5gagSBwND5+wR143P0iWHBMarCbl6ABaRH9Dvtf19RsEd/FXvG8WGFdipbUn3OmjZjR
         U6TvyjqyjTDmq/PP1JOsgqxmBYYeiGzV5z/jaGbc3RIWE78fncflK60ydeCNdLiyNDhH
         HvjA==
X-Gm-Message-State: APjAAAWTQhxrZWk3pTEgjufTqH+mJ3KVh8ru5h9xyWy61RmCI2rVxYK8
	YmKu2P6a8X6OChGv8zyr26Q=
X-Google-Smtp-Source: APXvYqxOZTASZlPLSN7sgJuFr1f4wdt9jW0ODZtsahrhJr191Mb5mOoTyXXoGtiV0gDJjXADMqRgmA==
X-Received: by 2002:aa7:d9c6:: with SMTP id v6mr298160eds.107.1581641694155;
        Thu, 13 Feb 2020 16:54:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c0d1:: with SMTP id j17ls215330edp.4.gmail; Thu, 13 Feb
 2020 16:54:53 -0800 (PST)
X-Received: by 2002:a05:6402:1ac4:: with SMTP id ba4mr305298edb.201.1581641693657;
        Thu, 13 Feb 2020 16:54:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581641693; cv=none;
        d=google.com; s=arc-20160816;
        b=Egu/dD5u9o713Q1lmkyxtqiCc+i8uYTjybKUQ0TKgx9V0ZRavppDJmNk9INJA3FDsP
         gSQndAgm/y5vtCelIX9pGiZItxqB4JigjNL54aH2XraHnpCnL4mzCSSW1qLgfeocn0X2
         7XgQ7DdwFbr4TuY++83bUEnVkgMNJjDUiDoBrLRCKsIwpIksrUQQU8vmtHQipXpnsTWo
         Ic6GDPxqHFa00+LlzLR4vKw0dYDFn6rO1inKehvVBcmzxHPtw2YNyPRSKqzabGR1ZJ0D
         KiIEOTypmHq+iKL/T3L/gYRD4yjnHmkR/LYlgTdhDTyB6MPKmr5ULDFLIyM/fVSCkEAs
         +9Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ik5Lp9/74mcaPuHZovIpPmbd4aGXGDxcFYnSBT9/TXw=;
        b=DIlaDGt/hetiK+Gv3lvvTeSYOZkHfsKC6V2iiMDyK4Du9QTuCN3pZj+q6V+Ee/msU7
         ZsLKA57X3yhOMouy72vd+K75u/jGHmJgsAkU9guuPRdv0qJtBe+m636+w68yGEqXNJZc
         pO4lJzB4dBFBG60+DOlkzBm3HZtWbJmns7NJO+4JDyB1l11+aG/RsaonQlvvpF0sEKbA
         vqioQn+19oFkHqjPGes5yyDFkB6R0T22MybdaWeMtsGyKmzweO498M510fCkTc5jlopF
         DSbU8BmaDv5Lg1j18O8U7vmx+8K/rDKDid3JX9YFebfAkpWztcp4Wjxdtj3bTvyA9jAr
         3zMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cGa0u271;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id cw13si52999edb.2.2020.02.13.16.54.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Feb 2020 16:54:53 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id a6so8857473wme.2
        for <kasan-dev@googlegroups.com>; Thu, 13 Feb 2020 16:54:53 -0800 (PST)
X-Received: by 2002:a1c:16:: with SMTP id 22mr878442wma.8.1581641693059; Thu,
 13 Feb 2020 16:54:53 -0800 (PST)
MIME-Version: 1.0
References: <20200210225806.249297-1-trishalfonso@google.com>
 <13b0ea0caff576e7944e4f9b91560bf46ac9caf0.camel@sipsolutions.net>
 <CAKFsvUKaixKXbUqvVvjzjkty26GS+Ckshg2t7-+erqiN2LVS-g@mail.gmail.com> <e8a45358b273f0d62c42f83d99c1b50a1608929d.camel@sipsolutions.net>
In-Reply-To: <e8a45358b273f0d62c42f83d99c1b50a1608929d.camel@sipsolutions.net>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Feb 2020 16:54:41 -0800
Message-ID: <CAKFsvULfrFC_t4CJN5evwu3EnbzbVF1UGs30uHc1Jad-Sd=s9Q@mail.gmail.com>
Subject: Re: [RFC PATCH v2] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cGa0u271;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::341
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

> Well I had two patches:
>  (1) the module constructors one - I guess we need to test it, but you
>      can include it here if you like. I'm kinda swamped with other
>      things right now, no promises I can actually test it soon, though I
>      really do want to because that's the case I need :)
>  (2) the [DEMO] patch - you should just take the few lines you need from
>      that (in the linker script) and stick it into this patch. Don't
>      even credit me for that, I only wrote it as a patch instead of a
>      normal text email reply because I couldn't figure out how to word
>      things in an understandable way...
>
> Then we end up with 2 patches again, the (1) and your KASAN one. There's
> no point in keeping the [DEMO] separate, and
>
Okay, so I'll rebase onto (1) and just add the lines I need from the
[DEMO]. Are you sure you don't want to be named as a co-developed-by
at least?

>
> > > > +     if (mmap(start,
> > > > +              len,
> > > > +              PROT_READ|PROT_WRITE,
> > > > +              MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE,
> > > > +              -1,
> > > > +              0) == MAP_FAILED)
> > > > +             os_info("Couldn't allocate shadow memory %s", strerror(errno));
> > >
> > > If that fails, can we even continue?
> > >
> > Probably not, but with this executing before main(), what is the best
> > way to have an error occur? Or maybe there's a way we can just
> > continue without KASAN enabled and print to the console that KASAN
> > failed to initialize?
>
> You can always "exit(17)" or something.
>
> I'm not sure you can continue without KASAN?
>
> Arguably it's better to fail loudly anyway if something as simple as the
> mmap() here fails - after all, that probably means the KASAN offset in
> Kconfig needs to be adjusted?
>
> johannes
>
Yeah, failing loudly does seem to be the best option here.

-- 
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvULfrFC_t4CJN5evwu3EnbzbVF1UGs30uHc1Jad-Sd%3Ds9Q%40mail.gmail.com.
