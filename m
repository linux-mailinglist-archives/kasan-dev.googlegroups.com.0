Return-Path: <kasan-dev+bncBDX4HWEMTEBRB74D5P2QKGQE2OOJX7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id C60FE1CF949
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 17:34:24 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id r124sf13985350qkf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 08:34:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589297664; cv=pass;
        d=google.com; s=arc-20160816;
        b=wMM9/gH4B9yRQb2ughTO/qXOqZ4A6ad0kdRvbLMW62K9LUpSbqPwaPaMCxFopo+kW2
         BrUma70K3qK3E95w+Fxk/DzTrjqfUm4kLnmoQISnFm0jR3uG/fZfNe6alP5xJaH0T3kH
         SwmDV1Y0L2KaecNhsT8jzBMPmRVXVDJgPmgYIvyMbg99UvJzn/nbpzCsTT6mkvN0mUM+
         GQo8lsBd7DIGawkZ+cQlELAQ+yzU0GjzxbrsT7o5vPoozPTwmnm76bKKPZ6+5Cpt3r3J
         1LW4y8OgZ3Vug65+miCuxZS7xTAv0wSyHYy4OT7YZ/ZIiQeQYUG9TvjY6c87ahTqIg1k
         I9Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=n6bS2bDsISDv1GIK0R7fPlXqbvodOM2WI5OHlOARmZo=;
        b=cEyKvygIAExoRVlSIpEy8XIO9QLT+KyxiFruQJNymURKAN+ScGBkp6wPgdPEBZa/B1
         eNcqO6dhW1S/MU/cbOLplJxY/Zlq0jFs87pISUcKaeoW7M3KiLERaaDdHaQkdgGiiJJ3
         Ng6+8cLyPao4u/9IYHw4jDMl6ZNECP6LTGL5xwYDGHh0M+PUovXmHXMJeCKT8knvh3EB
         Nj2xttkYDgJqqHbnf3wLFKC9Q4WNExsdWNpmDszVEL7XlAGigJa7yOkzFpa1LjOAMoYG
         qn1Ur+jz0PvuVuZFZxQ0cErZk0CXSD70JhgSI8B8k2oe+VHDeDTTgdD/QjAL3DYbi7Ei
         0uUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JhRgWIyG;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n6bS2bDsISDv1GIK0R7fPlXqbvodOM2WI5OHlOARmZo=;
        b=Ew5PqG5Jk63jl/vdDNLgzTqBH6GaB9lsNQoWDOwfLpW9amLUn8wJEscrM42wW4Iwqh
         og8TqnC0IONqq77GlPu889d040Ep63syf2IvauQzO6qhsjt5GCxMKTGUoKGR2Sy/PH5/
         pvSziN81ujyx4xS/JOKhprZrrrsxZLS7rCmgVKf++sMxYeGjSUTbb5f5FVkJkZpx+3H2
         smTNHJDNEO6maHyKXP6js0VaJKpy+J0olr9hjc+pGa1cf6aQIgxO57/OgoVQmkFAAEVP
         rQWF4gN2ca7sMiCkShrkt5RoBcNn7rCJOCGeBko6jJUMGissBqUUQgs9z2625zkgy2lK
         HgPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n6bS2bDsISDv1GIK0R7fPlXqbvodOM2WI5OHlOARmZo=;
        b=ohuacVjCXNDxl8A2EWY8cf0YWaeewoqBlyN3bFpvQ59m8Bc3sGEivB68zVtL2UopDU
         voNNnn3DScq+Zak2W0WIkSBdVYga92y9dvY+0sw1w9e2IHHw4uHabMYnhFaALEfswQXK
         mcIrWKEw/YV6j7UijLEf7016wBibdCREYF5quTPq67fQ3pnmnhzRpTX+Zj4K/IYCQLOf
         vyXy+u0VXDBecVf/TctgL6F8UL4pZs84hXI2/g+ZzihbVwze5Ps0sBMGjhPARFQb/tle
         eqEyV6SSvGmacFxgE2mPLpBYISwfIYthy+PK4fX0hmjQTkdMDGN/nnLE/6xwvcvxXKOK
         8BnA==
X-Gm-Message-State: AGi0PuZnmwT5CMK6lOJDOz/M+jhqOav8PaoiTyEcy58P7VzAUKDMbYD4
	MJrj1qNHYklHk42UPoTRmbk=
X-Google-Smtp-Source: APiQypJKTnu4M2dhv2tf+ZCh57UUmQrA5oTjpfiOdtDLwLJkvgfwa+IVM4s1VjwZ11zIg1inX4D3kA==
X-Received: by 2002:a37:ad02:: with SMTP id f2mr20446038qkm.486.1589297663892;
        Tue, 12 May 2020 08:34:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:15d9:: with SMTP id o25ls7291781qkm.6.gmail; Tue,
 12 May 2020 08:34:23 -0700 (PDT)
X-Received: by 2002:a05:620a:2290:: with SMTP id o16mr8294132qkh.410.1589297662828;
        Tue, 12 May 2020 08:34:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589297662; cv=none;
        d=google.com; s=arc-20160816;
        b=sW7MhLpopETNpbCuPGq7IBhlUuGOvfyOu/hfVSJD322NISNFVtuDyUbclW0pf2hPX9
         2sX1W8ifQYH5ub5oOc5QtyFo90c6AL12qGB0B7I40SvL7teQ+5jSzvisnu3ljjBujQeK
         or+TNwy2ZpU59FJoRfukEU5FwUEr9UdiZ8WnZXNh6rRtvKeCnlwTjNGM8WZr6DyjDsXk
         ytm+hNR3rck96CO6fHeSL2G8ycC4HNQ34LnHFAyQgMNDogVExH9DwpN0mbruW2tZl7HT
         K/5ZchbEk4FcUarFiBKaySXy4vKYP2qLHGZzQreJHvVmFO6BFZF7YGLxMGee8zJnrHgv
         NMjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S1nGYbQQUmvuJU/OQ0QH/3SmFbvxo3s8FBGQi1+ShN0=;
        b=hnluGaDB8ZWpGoOvAPrHSYgcyLMclI2QRGiRKSdJaHsD+HQqXniV1MVZxV4GtTbT9P
         YtkqJYI7t8UvSzus0YeTe76MoSmhk3RfW+st2qAXHtNML3B04ogzr30Fa3eg+8YzzQjV
         H+VJyMakfUVKx/p/aq8apBzpCu/dIAh4cFgk49HV0BbHMyFPFU6JDHa2Sxi5BbE8tPIk
         /qB7A8ZBLZ6SuLX3Ug5El92GMomvme//9jqC3jTfqXCUwzZbDr+/WAHxqAzOYcBMR9WT
         c40dbeQPNqt9NZHbelIYkYepel0xwDT0qbCBj6lqHqepB2u0udnGKhkQKZcen6bw3L1k
         4AmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JhRgWIyG;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id 2si569706qtp.1.2020.05.12.08.34.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 May 2020 08:34:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id t40so9556468pjb.3
        for <kasan-dev@googlegroups.com>; Tue, 12 May 2020 08:34:22 -0700 (PDT)
X-Received: by 2002:a17:90a:dc01:: with SMTP id i1mr27443683pjv.166.1589297661687;
 Tue, 12 May 2020 08:34:21 -0700 (PDT)
MIME-Version: 1.0
References: <20200512063728.17785-1-leon@kernel.org>
In-Reply-To: <20200512063728.17785-1-leon@kernel.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 May 2020 17:34:10 +0200
Message-ID: <CAAeHK+zFDoykmS3KD88hD3S8R09n064c7n1gLDurMr0KOhte5A@mail.gmail.com>
Subject: Re: [PATCH rdma-next 0/2] Fix kasan compilation warnings
To: Leon Romanovsky <leon@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <adech.fo@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Leon Romanovsky <leonro@mellanox.com>, 
	Ingo Molnar <mingo@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Michal Marek <mmarek@suse.cz>, 
	Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JhRgWIyG;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042
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

On Tue, May 12, 2020 at 8:37 AM Leon Romanovsky <leon@kernel.org> wrote:
>
> From: Leon Romanovsky <leonro@mellanox.com>
>
> Hi,
>
> The following two fixes are adding missing function prototypes
> declarations to internal kasan header in order to eliminate compilation
> warnings.
>
> Thanks
>
> Leon Romanovsky (2):
>   kasan: fix compilation warnings due to missing function prototypes
>   kasan: add missing prototypes to fix compilation warnings

Hi Leon,

I've mailed a series with slightly different/fuller fixes for these issues.

Thanks for the report!

>
>  mm/kasan/common.c |  3 ---
>  mm/kasan/kasan.h  | 15 +++++++++++++++
>  2 files changed, 15 insertions(+), 3 deletions(-)
>
> --
> 2.26.2
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200512063728.17785-1-leon%40kernel.org.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzFDoykmS3KD88hD3S8R09n064c7n1gLDurMr0KOhte5A%40mail.gmail.com.
