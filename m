Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKX3677QKGQEGSZNMBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FBEC2F3B1D
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 20:51:07 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id m15sf1608546oig.20
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 11:51:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610481066; cv=pass;
        d=google.com; s=arc-20160816;
        b=YNpn/ObX6IB9P5c79MzaTzmDrtLeNsvb5Wip1TVGS2yJx6F3KmQ1lj+evrWZuDX98F
         CXSbmrWUDR+WzJPiSUKpKNJ3iYeNFCOMPI3QuqgWShhtEEiJ1kajkHWCHSOMTjagcPCd
         WI9FkNKSH0sx8652GArAgCmT5wWUsq2CSfIY72xWAuuJvFpXo/QdS8BfYjDAaZMVQOye
         JuQ9JbeWav2MQt8bLDHsZvcjY3Mz24yjYgf8k0UEYlvDECvdNTnGNFv30BRPF5XiPT1s
         1y04j20xK4DuAOpoboY8QYh1+S09g9xHMc8G6S4Ck+o1XyqbE+tpFctTqW7VlOAiZSaS
         EZPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=equDDUGBNmo2pfe+S/bA/cPyM59fI8JsOsJ5eBB2V6c=;
        b=y7hSbMgAvhebrSNgeA0PqQ+tKfhikgp+aMlwrW/+U3Xk5gOoPRcXy/7sTfHka4lF4x
         WdQOWXe/ifDTcN2AIA6biPBSR61r6tlync98KFMcE6+lBAiopaRxLpeSxuYJ4bfOQbKP
         QV4h1DEIpyFGAbDB0/noGzU45IajcLXO3Oke0rbypMA1KIn0ijD132TkQM/fPllcqVhx
         8T69f/dFzcB3b6+fhK9vV4SxEZkuU3psY38BFqcD+/2/Zo06ahRHLXeA5uJpp5mkEH5J
         cnZ9USmbo1zQbfnyM3cfLcWsiuBiiWFx5bVZZXLxdveZObGL2ILFyNJnIF45zLe+zJZ6
         AzMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dl6ZgRi9;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=equDDUGBNmo2pfe+S/bA/cPyM59fI8JsOsJ5eBB2V6c=;
        b=bnso8S7mmgDSxwWErc3WVIYDAWq/K9I6hnKfS2in+nwwwonI/OBOEbhteFEM/jZHSm
         zowBWsOanGhM+s+p4SsU6vScyd5FYSpqW2ymRFxwbtMxAtH9iqiYzHqGsOoUh/uB4vus
         e9lklf5jd6DfXb/UmGxE/hpoVRfsGRC4yjmSPSffZ+pIWX2xBmPy9azfCX0bi6J9LE5E
         x65cJal+YOzoQqlqJsgXOcXQwX9rmb/ghsvDVFZRgPwmqPNffa7oNVCGT3PnHl89rBsz
         XctCily2yZ+NA3zHU3lhX3k14IAWpWdx9Px9+g5ykNBNE6cuvKx7L/OhfKjZwqAQ2Qzd
         QLBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=equDDUGBNmo2pfe+S/bA/cPyM59fI8JsOsJ5eBB2V6c=;
        b=UGopwfZQM34dd9cKhP5hXFkuPLgb4AbPJr3kXv/8kY/8I/2Ub6b6zB8xbzz61gKOmZ
         WyZc3GX8FZNVxSoLtiSeZkhpuBdvZQT9/piQDNbxh0agxsHULn+jGtwFsCCDzd0jHgYo
         fb1VeE00Lbiv9hZb+Q3I1usbpqEehu6nb2PkpJItf8PU/BKQrZkRi3gGidKfTfpBhmjL
         HfKoc2VWJphrKe31SxHGd6ItQ9D4EX7i+Z7WPvBb336mPceIA6a3YU3T2CKijMR8O4v7
         nhtYTi/qe0ruZBSUP8f3Rd/UgBc+HZdvy0VW3DxCHg7AtY/3rkMwLFgwcVfQKySFBk+R
         mDMA==
X-Gm-Message-State: AOAM530MtkV/SFsoJXiBbBbP87UTSfYbbIQFFNpqxitHYlSvhY/cX0jb
	Ree0PJdCm4KxiYA2+OsgyTs=
X-Google-Smtp-Source: ABdhPJyY+SIy5UtBlBIUE3SIYTyX6hqvriFtyfAgWpQQ+gsdd7lZr6uOUrgekhu1Svab9mlHN74qeA==
X-Received: by 2002:a4a:c692:: with SMTP id m18mr437740ooq.59.1610481066415;
        Tue, 12 Jan 2021 11:51:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:a97:: with SMTP id q23ls809509oij.1.gmail; Tue, 12
 Jan 2021 11:51:06 -0800 (PST)
X-Received: by 2002:aca:d406:: with SMTP id l6mr515198oig.26.1610481066035;
        Tue, 12 Jan 2021 11:51:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610481066; cv=none;
        d=google.com; s=arc-20160816;
        b=uKY2wV/DMFepKcixE1b7oF+2KZXuJZqujU4OAXVawGlfb0Pw+e8mgfvrKdj/93twaK
         TW/LpeJgkeP4zRwpf9VJvBMgSgfVanMWAsoNFzqp5EovIPUXKDN8ByLWKqs97bR5chbX
         TPvPKH6XeGILvYqAEQlEReKfkS/SD5juxUUannRr47mq5zhB9OnpShwqw4yvM2gQa0un
         7f/4JJ3k36AjbFEsKtDvjqVfs1S8VBmftVL2X8WwPafkLmy0tvGU/9XHBXAqIb3jlGKQ
         Z5WBqb7pc6msX9y1aFaN0+SaL+DjzqvNaUyPuCxey9Gm4Vq0lzklKEqLg83VPAm9pFsD
         j8Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DCxpZYyPI/Y3trjmBrRTDlsX92cIUAx7GVVWW0wsbxI=;
        b=fLtjbQbXd6yFzppKcIgdPdPTJLGtItuYVEE1LTkTywHQibsTikh5oEP5O49hIJqvTG
         M72lOnAby5Pf9rem6a5Su2jYE3k8qsXXt8AwXPTM1RFHb6gn4fBUaxCvuPRrcFoUqqhX
         zx7ilLZtHv5quk4O1eDoRxeYwu1fX+oQVibe/kOiUJwu7QJaeUaBYT8AZF9SiafYbOtI
         gFw2aGu4YrkfvJPh820Oqi83J7EA+rSIueBWHL19fsJdBI7YD37PT8GSrU6odYrFug6+
         ar/sIJ0tIzBJuA98xHbPgTpNES8GlktLs7dwEUIO4+0bhvJ4mC4Ma63zK/u7cQikN+/3
         eELQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dl6ZgRi9;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id 7si283286otq.5.2021.01.12.11.51.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 11:51:06 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id my11so1217134pjb.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 11:51:05 -0800 (PST)
X-Received: by 2002:a17:90a:f683:: with SMTP id cl3mr792157pjb.136.1610481065204;
 Tue, 12 Jan 2021 11:51:05 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <a37dab02f89ad93cc986a87866da74fb8be1850d.1609871239.git.andreyknvl@google.com>
 <CAG_fn=Uqp6dt5VGF8Dt6FeQzDgcEbVY8fs+5+wyMp2d1Z98sEw@mail.gmail.com>
In-Reply-To: <CAG_fn=Uqp6dt5VGF8Dt6FeQzDgcEbVY8fs+5+wyMp2d1Z98sEw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 20:50:54 +0100
Message-ID: <CAAeHK+yFw5YcR1jAYbE+PSLc0NowCv88mS8kJLspe_RkSjX37w@mail.gmail.com>
Subject: Re: [PATCH 07/11] kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dl6ZgRi9;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030
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

On Tue, Jan 12, 2021 at 9:18 AM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > It might not be obvious to the compiler that the expression must be
> > executed between writing and reading to fail_data. In this case, the
> > compiler might reorder or optimize away some of the accesses, and
> > the tests will fail.
>
> Have you seen this happen in practice?

Yes.

> Are these accesses to fail_data that are optimized (in which case we
> could make it volatile)?

Yes. AFAIU compiler doesn't expect expression to change fail_data
fields, no those accesses and checks are optimized away.

> Note that compiler barriers won't probably help against removing
> memory accesses, they only prevent reordering.
>
> > +       barrier();                                              \
> >         expression;                                             \
> > +       barrier();                                              \
>
> The need for barriers is not obvious to the reader, so a comment in
> the code clarifying that would be nice.

Will add a comment in v2, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByFw5YcR1jAYbE%2BPSLc0NowCv88mS8kJLspe_RkSjX37w%40mail.gmail.com.
