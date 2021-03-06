Return-Path: <kasan-dev+bncBCT4XGV33UIBB3VUROBAMGQEK7GVYFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B769B32F779
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 02:27:11 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id 129sf1313622vsv.9
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 17:27:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614994030; cv=pass;
        d=google.com; s=arc-20160816;
        b=CYbSc8OGuygu8b3jH7bMyOBG1wR5VvI3Br6u8cUsNEnrNu/H7zVlMNQ26fQIFsY3js
         bKseEn7MJvh43CXi0FzFd3CZ03MbhQ3kYGQUdxPi95wY7RXIP+GNOWp3fRlePFm7yxcq
         QTcz9j97razworibNIQzdETTEopiTFCtvVs71oYupBCRGA0l8bgCO5/ce3SchXpJlsFw
         PjtD8sVFL4VUsxlEjNFkpe4mUqWulMkLcMa9NKnpgoknyF94sGKZL7XrRz2hP2gnAtsb
         Twc9/WzQmxahukTLnTeHckTqlZ5a+c3zn1wpd7GCjUFFn9IZ7QSgNFyQMJaNPldWDMl1
         +m3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Grix08JlNSiP4N0UeU6DaoBFFx5S3FFLTSYYTJCn/1A=;
        b=zI/2yOkvav5IjNZo/96cV1OUzse2NVI3QJYxI8Zydj9kJExfLI/LjrasirAtwRAS2+
         HkEjUHYVREfi0OJaXHjq9CgPPUlX8T0w2CyrZD69XnqxNWkOc3EURuEqmw9W75I/c5d1
         CSLc7SIf9/u0458S/mrqoY2T0/1ahT4TjBfXwGOI0XqbPo1uFkBzcZVifIsX+5S+0qqs
         s+cTRSCRFhdN7D29iUcibBEqJwUnMNBuwXpkCfBhSUanRReqiIPjYrkypolH7DTAJmmO
         404RwxopyfBeNBxn4K3dKvjk+A2ITfc7Co4WXAaOa31LcVVEVoojx2NPYT9HExQX5MkS
         7j8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fHQ7TGXN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Grix08JlNSiP4N0UeU6DaoBFFx5S3FFLTSYYTJCn/1A=;
        b=sQ1e0qc46xHXKfg4wc7yI+3TcArB8qGf74/5hsxjFQTQ/3/iUEuZZN4V9JDzpLoG00
         8I52P6s8deA0GBv6L5slu4gr5rbibWhOe1v3RkW3F94ZIPhFn0cIx5FfGQgRWeHgW1yB
         /fVUE7acUJRPJk6qLAn12t0WKPDRnfDy9WGVkrKs12LIJmankwm57hwIyLnMnxBjBoAL
         5yjpPSY4DdRVubRF3A9DhcYMxqlCuZJnOnCY8QkADFDVoWlh0sr0lMRgkxNLiKqpzHzJ
         c3nZ0wU0dPKO51YyqTa3GS5+YdRcfLXvhBess4s6Ra3o4ThDhSN49a25I3Cu/Jg1c6lz
         eREg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Grix08JlNSiP4N0UeU6DaoBFFx5S3FFLTSYYTJCn/1A=;
        b=JEst4XtVGBjmsdJ2iSLwK0JiXshhuheaIReP2dfYYlG3waZtvyxq8udpza2+yaatpa
         cK7jLTu/PMBQLuTREr2ExP6hKVLcFyhp06QLEyeTyBoOZUNpjfi7Aobqc9QAPHld2XGK
         gCMgRkyrj6lyXa+Ei9tNC+PFjlW9VkSYDCZMzgOJEVog4POu03drEGVb+PIrBFksxH6I
         7fECoXDMUBDzoO+mC1uz5GmaW2G4738lTSh+IR1xZQIIlSa5HC4RAPHW5dnxeJoD/ySZ
         p53qbRG4pdyfPm/eOHbFZ3epYG4v1zvS3KbrpAlatWL2azovtEiniQKvfPb7iK6BmNGv
         QT3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uISpqsmZl4eaEwcn03QlkwqezSkigDmH0tHAyeCOEjGdBpFY9
	OXMl8gah4jCTbZ/pBaJEBQA=
X-Google-Smtp-Source: ABdhPJxUAdemYjKtV3BI9Nbx0og4POiDgVbuyw+BTGoW1p0ONlwjU0aFj6PQRFG55GvyHt2eCaxVBA==
X-Received: by 2002:a67:fa86:: with SMTP id f6mr8847413vsq.36.1614994030810;
        Fri, 05 Mar 2021 17:27:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2645:: with SMTP id m66ls1477347vsm.3.gmail; Fri, 05 Mar
 2021 17:27:10 -0800 (PST)
X-Received: by 2002:a67:8c83:: with SMTP id o125mr8713034vsd.42.1614994030234;
        Fri, 05 Mar 2021 17:27:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614994030; cv=none;
        d=google.com; s=arc-20160816;
        b=BcosdQcLxeuqLQvYFMzklDEJV5Jl3VgQco4nbqI+rJ3jwm2oziIJPFGdYY2dhvObtD
         D+IXqNNO+PKN1uouL5e5rMczWd91voMcUFalP+uSVsKzn8y1bA1yOXlBPq1HTW/I2KAR
         2M+NlNki3NwJNXTSodVXsbb4+gs42sNJmNWs68f++H/5GR/cnqjFuwt3XcAHhypHs2e8
         74wiWoghcKcDkc/bcnQE7foH5AGbA6sWOz3PI/cDoYVrFfT/j3Oq4v4feLOvEaJUG+px
         cQr89jW0Uu8BWjXJ84EF2VYdp7E6YuxYmHB/YutATfhd0kECMZKM8MraFYy6cfVQRttF
         6q+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=kJH4kws+Uj5SyaeFPflzYPen/w5a7Z00uQ2gaSwjVAY=;
        b=tfdhhpINoF66jRc9994D2xQpu36h0K1QYvOW0a0kpuP7Yl3n8pKm5iqG99BAqZ8YZ8
         V3sTfe38imSf04K7Zr36WYuQVJYDMCyZpyEZMlhEo1+a0f6HhkvHbISHTzl6CKLGvptn
         naz9EQ5oOSSEG+Z2HwQ3Pa0kGyZQ7ttPtVZBOjMoH+bBXJStBNKsby7ldQkJmtfWht2k
         IqlrmppWQeWr+n90InmIJtJDNXDJCAj/lAbL+4GRv0/vRvxyN9BSiqoqiqBs559S04A/
         ojR+J7vZ+hQtAhINdPDj81bqSvOV8VJWU3/96ESb8VWxNKXNMN6Aues/JxKmo5DUALNt
         K8aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=fHQ7TGXN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e11si282434vkp.4.2021.03.05.17.27.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Mar 2021 17:27:09 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4A5B865093;
	Sat,  6 Mar 2021 01:27:08 +0000 (UTC)
Date: Fri, 5 Mar 2021 17:27:07 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>, Catalin Marinas
 <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov
 <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, Kevin
 Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux Memory Management
 List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, stable
 <stable@vger.kernel.org>
Subject: Re: [PATCH v2] kasan, mm: fix crash with HW_TAGS and
 DEBUG_PAGEALLOC
Message-Id: <20210305172707.0d16383226ce5bfa87939702@linux-foundation.org>
In-Reply-To: <CAAeHK+yHf7p9H_EiPVfA9qadGU_6x0RrKwX-WjKrHEFz+xFEbg@mail.gmail.com>
References: <24cd7db274090f0e5bc3adcdc7399243668e3171.1614987311.git.andreyknvl@google.com>
	<20210305154956.3bbfcedab3f549b708d5e2fa@linux-foundation.org>
	<CAAeHK+yHf7p9H_EiPVfA9qadGU_6x0RrKwX-WjKrHEFz+xFEbg@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=fHQ7TGXN;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat, 6 Mar 2021 00:54:32 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:

> On Sat, Mar 6, 2021 at 12:50 AM Andrew Morton <akpm@linux-foundation.org> wrote:
> >
> > On Sat,  6 Mar 2021 00:36:33 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > > Currently, kasan_free_nondeferred_pages()->kasan_free_pages() is called
> > > after debug_pagealloc_unmap_pages(). This causes a crash when
> > > debug_pagealloc is enabled, as HW_TAGS KASAN can't set tags on an
> > > unmapped page.
> > >
> > > This patch puts kasan_free_nondeferred_pages() before
> > > debug_pagealloc_unmap_pages() and arch_free_page(), which can also make
> > > the page unavailable.
> > >
> > > ...
> > >
> > > --- a/mm/page_alloc.c
> > > +++ b/mm/page_alloc.c
> > > @@ -1304,6 +1304,12 @@ static __always_inline bool free_pages_prepare(struct page *page,
> > >
> > >       kernel_poison_pages(page, 1 << order);
> > >
> > > +     /*
> > > +      * With hardware tag-based KASAN, memory tags must be set before the
> > > +      * page becomes unavailable via debug_pagealloc or arch_free_page.
> > > +      */
> > > +     kasan_free_nondeferred_pages(page, order, fpi_flags);
> > > +
> > >       /*
> > >        * arch_free_page() can make the page's contents inaccessible.  s390
> > >        * does this.  So nothing which can access the page's contents should
> > > @@ -1313,8 +1319,6 @@ static __always_inline bool free_pages_prepare(struct page *page,
> > >
> > >       debug_pagealloc_unmap_pages(page, 1 << order);
> > >
> > > -     kasan_free_nondeferred_pages(page, order, fpi_flags);
> > > -
> > >       return true;
> > >  }
> >
> > kasan_free_nondeferred_pages() has only two args in current mainline.
> 
> Ah, yes, forgot to mention: this goes on top of:
> 
> kasan: initialize shadow to TAG_INVALID for SW_TAGS
> mm, kasan: don't poison boot memory with tag-based modes

This patch (kasan, mm: fix crash with HW_TAGS and DEBUG_PAGEALLOC) is
cc:stable, so it should come head of the other two lower priority
patches.

> >
> > I fixed that in the obvious manner...
> 
> Thanks!
> 
> If you changed this patch, you'll also need to change the other one though.


Yup.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210305172707.0d16383226ce5bfa87939702%40linux-foundation.org.
