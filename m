Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCMC7D7QKGQELGAZSQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EEAD2F3B5C
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 21:05:31 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id t206sf1639139oib.5
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 12:05:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610481930; cv=pass;
        d=google.com; s=arc-20160816;
        b=eB7yJ+wGuap2DYHY2pMhq7L83OtuhgqPV4j9dshRfktRFlc4dkXy4XQ6kN68PuL8tY
         bW2ixpykWiyumCcqYutGcusAqKBA++0+Vehcz9gvzkrUAEiTshhDOMOFDnHkRdenzL82
         nEm1kfCIjYKT2s0KfmIfXWyqthc7an9pgxSMTjePwpBg8pxWOyc4NQAO/aau2IeEuMIs
         t5SZ/FtWnChjFji9CSpQWWUimIxXDtXyfPvuSZUZEJXQSsRJD/Cih6c22LeMjgiQiwPh
         i5NDtctlY4IsUaIATEbCv8gkbfglPXJ2x3cPMlczV6mIxPJslej7+CHzwuunIirI0paL
         mK6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vUlHz89JahGjyqjuTungZOcPT1B4bhajNttJfuQiqJA=;
        b=zTocsiFREJRI2hlglS5cUxKImqFr7DFWQlDu1OoxIZGKjsaFYFndgYeFV1bPnrTBkn
         w7foCXM0ghygYsSt8+6zY3bkfSeBLfEO9nbcFXVrH2ft3RSvOSOTSa2WkTSefJbf0H8g
         fHxyxw/YSoxz52DhYA+wFmfjH/GhPwpW7UzwlJlzvkMVPr5MSwk8NfW0DElKpAzpk0d9
         DRuaeif0sByYU8fxJhnFANsx1S7VsNpk93gLMLsBxBo1V2bDJG+oqd/9sBOBkA7mtdoz
         VZZo1NXIm7K2g79tno8/HsJhEbywJ+wNdVjVvypc9VvZgtm+ZdG2yO+XH3Oj4uqxR6C1
         WOUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wPsXp3Ms;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vUlHz89JahGjyqjuTungZOcPT1B4bhajNttJfuQiqJA=;
        b=Wha7TcEc/SPd9Ji5eFXdcrZuVkBgZ7pd8/h2L/xLYOLjd24My+R9P+lY+cmwN4IL41
         Yb6UNyOt0mnM19HoO5m6Q+nJzZFBQc1+e5FL/eKeMacFP5rJzePUGMjPjuTrbY4itqkR
         x1plwgDIquZnGaOgCDAN1LiMPoLwH13Q/zny7Ko8LwhuUlh6nE9K4yJxTgYbiiLe9MnA
         mXYF2nbIZw2RHsCQRfMtEiFj3SsJDDTMXyr4+BJURaTcT/RnI1DGV8nzZ2YS3bGxg9qo
         P/BQV1NnCozhwTGHkaOk1WHqsFxRwzjhrvMJ8quYLp3N8c01MxFTHxI0TtwqBeQicJQP
         G0jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vUlHz89JahGjyqjuTungZOcPT1B4bhajNttJfuQiqJA=;
        b=aWwMoT9eaITWvIf+XCSrftx1Hva6hj2+02J8yPLN/dVO2MkrSEwy03gEi20swRn20A
         JN4M9yonB1QxeUgZSZ4DNj7KcFaklguk1rXng3Zs3TznKZmB6AL2kp0Dr7kvziHb8Wu4
         MB/Hqic1wFabg6772FGTQnRRXHbTL/XXhZaJy3/QLaXn5S6N8bAUHs7+fCQgxrwOsZZx
         g44kwoCYy1xTKoW3/As3nD8kmJkCWGonHRsGbXulJLqDyRhpcdcdJncuVeQaxBQOBzCU
         nxl+6n13qvPCOfD+6GT969Hna6Pc2xrvhW+Uw6l7WeZ2EWhY2Fg9OC4psX2rMNwIIGzp
         9Cig==
X-Gm-Message-State: AOAM531IL1wqstHiHstZPqzv8Y24j3+si36eBpHv/2rrMGvC8ZmJrttg
	D9xzg1GMhnBurkkn9epyqA4=
X-Google-Smtp-Source: ABdhPJyCezviDIjSavFhSyNNPzlUnNMNAfVPplaEwMo13Rn6YUnZbTgAcxBlHPYvTgT8Ga+zdSlUuQ==
X-Received: by 2002:aca:2418:: with SMTP id n24mr529825oic.62.1610481929988;
        Tue, 12 Jan 2021 12:05:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4a83:: with SMTP id k125ls234986oob.9.gmail; Tue, 12 Jan
 2021 12:05:29 -0800 (PST)
X-Received: by 2002:a4a:e687:: with SMTP id u7mr514891oot.20.1610481929695;
        Tue, 12 Jan 2021 12:05:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610481929; cv=none;
        d=google.com; s=arc-20160816;
        b=Mb0E/Kz59HWxLvslA8AcdOnMXckACUXcUSj6foVroi8du3Df1gjwPdbrgO9TZ+Z0iA
         Xze8XxDb+u6QePJwNjHHc2GN13PhnUzbPTH2pKpdoGJyL70+iyqL5DW7F7p+SNyQqtVQ
         Xwy2MH0U0BqWWF38uLgYSYvMsQ76d5bcDFldMclZs3hPkQyzYI5cufFdf2XKL0S+XPiu
         UUhxNFOOqIjchJ+2ueHtruW9T1bkU6Q6/TjOuMmBDXwiAN+fLaIM6cyAQeVUTzzE7nmk
         Hege9jfLujKPkUBN5ZhmkGD44QOmihanW+m8u36pdhMXDbR7fQ0Y51y+hxYS/zVAKCyQ
         qOVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zL6WgU5Xs4gBKlOeTyyYJxfsUDm2s7KXGqsTMwbacGQ=;
        b=MCrBjTuGgCfzrHEw+xxwJY6l9KJrz8ectWPGoTIabLpwx6lNYn4SKqZEMh1MLthWYF
         K/nm72LUSsWj3Wg5OzfkadEYorBBDZZrsogIehU4TczlY59MKjNjS/PQ37aA50RH1hjN
         sESZNU7+K/Ap37HmoR33PXIugI/0xCgqPwLNgSz+n0mgk3sM0UgkRO2jTe8f4LvsXeX8
         1NOh+9L0qYL2j45pQK8iXDuLz8kjrAvTPPi9uSMDnrMte/jDrerd/yJhC/+uijiiWlHI
         WXmm4mGgMuoURO3qVDf0ynKroWETKfPVmfrfftitqE3XtVzMtvdjjmY+c5YxowhjqNdT
         VK0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wPsXp3Ms;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id a33si231322ooj.2.2021.01.12.12.05.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 12:05:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id md11so484482pjb.0
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 12:05:29 -0800 (PST)
X-Received: by 2002:a17:90b:1087:: with SMTP id gj7mr814111pjb.41.1610481928938;
 Tue, 12 Jan 2021 12:05:28 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <9a4f47fe8717b4b249591b307cdd1f26c46dcb82.1609871239.git.andreyknvl@google.com>
 <X/2md4h0Nki8RNW0@elver.google.com>
In-Reply-To: <X/2md4h0Nki8RNW0@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 21:05:18 +0100
Message-ID: <CAAeHK+w0_WmVZ9kh1QM4vmn3-0oBeWWV3BaLj2+-uh0xj8_BnA@mail.gmail.com>
Subject: Re: [PATCH 08/11] kasan: adopt kmalloc_uaf2 test to HW_TAGS mode
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wPsXp3Ms;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jan 12, 2021 at 2:39 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Jan 05, 2021 at 07:27PM +0100, Andrey Konovalov wrote:
> > In the kmalloc_uaf2() test, the pointers to the two allocated memory
> > blocks might be the same, and the test will fail. With the software
> > tag-based mode, the probability of the that happening is 1/254, so it's
> > hard to observe the failure. For the hardware tag-based mode though,
> > the probablity is 1/14, which is quite noticable.
> >
> > Allow up to 4 attempts at generating different tags for the tag-based
> > modes.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/Ibfa458ef2804ff465d8eb07434a300bf36388d55
> > ---
> >  lib/test_kasan.c | 9 +++++++++
> >  1 file changed, 9 insertions(+)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index b5077a47b95a..b67da7f6e17f 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -375,7 +375,9 @@ static void kmalloc_uaf2(struct kunit *test)
> >  {
> >       char *ptr1, *ptr2;
> >       size_t size = 43;
> > +     int counter = 0;
> >
> > +again:
> >       ptr1 = kmalloc(size, GFP_KERNEL);
> >       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> >
> > @@ -384,6 +386,13 @@ static void kmalloc_uaf2(struct kunit *test)
> >       ptr2 = kmalloc(size, GFP_KERNEL);
> >       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> >
> > +     /*
> > +      * For tag-based KASAN ptr1 and ptr2 tags might happen to be the same.
> > +      * Allow up to 4 attempts at generating different tags.
> > +      */
> > +     if (!IS_ENABLED(CONFIG_KASAN_GENERIC) && ptr1 == ptr2 && counter++ < 4)
> > +             goto again;
> > +
>
> Why do we even need a limit? Why not retry until ptr1 != ptr2?

Then the test will hang if it's failing. Let's do up to 16 attempts,
it should be more than enough in practice. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw0_WmVZ9kh1QM4vmn3-0oBeWWV3BaLj2%2B-uh0xj8_BnA%40mail.gmail.com.
