Return-Path: <kasan-dev+bncBDW2JDUY5AORBMXXXGGQMGQENF5SAHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id D7A3C46A91A
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:08:03 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id y28-20020ab05e9c000000b002c9e6c618c9sf6750837uag.14
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:08:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638824882; cv=pass;
        d=google.com; s=arc-20160816;
        b=gP5QJsDl7m/Ujs8QMSc8K/yt+vQ1Mj6cxppNTJTJu/8CN0mWZL49g6hCtr5kevKvo0
         rbLNkdnpJIRxy/z2kPaKbEj6WZ8umQL3DBhHjT9GJAl2lHWl5QiAFI8CWLh79ev727rs
         TQn8Szm4U+84kqIqWBLN3dTByvG/GuOh5lc+gHx3Msorg14DrjKbfER/Yuv2C7x9GTJr
         nS/F8B1aNYy+H6tXdguHq/SdJyV1SgxnNUUylVPRVyXxXyvb+8W5/zOBOjpFROsIlOuO
         tk667S/cN8/51GLHYO0lRUtYu1nvxnZ1JYCg41WSI9OCislaQUcfYs+8zHbeC3NdQGgr
         hLeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=onkrNqwUOWPnPdGWPxdxRKAPBgyzXkaVP4wpOHt/Y9Y=;
        b=TaugIUcuRrFkA3HYqpLH2Z+H5uQbxwE7vH+SvAPA3cxEDXwr1088RNfhblk7b3aWIh
         Z01CQFptbAsemEr+Y3v3dO51drqRwslvbOsWUfKSLx0yt66HCJyn5HmMoNto7PrqqXr1
         tkjV1Rqw9nUv+RpSs2Lh89nhTINURODgXC/BVJVsUiV5ptrFnKsXGKWgTVx3AW88QIt1
         1tfU+HmP3G+Bk8ZoifTfIUpIm5Z8v2sNcIxovwLg+v5JeLCipO6PeWiSOXRhp0uqnoW9
         +7AkwHATzN1XCTT/jvn5f/ShkYxmcUb6Bo3AURgVN41aCezH0Q/KitX9OgLZKIvrQ8kq
         1CbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WC6vPd2g;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=onkrNqwUOWPnPdGWPxdxRKAPBgyzXkaVP4wpOHt/Y9Y=;
        b=f58HV0W1lb+p7r6h22rnA/jY7pg84Bkk5TbKdS5R59C8DssmvCXRMkDybKC6H/eCOA
         7J3PONrTlO4q+qA/rky1z+R0f8pbjXMkBz66nyJXxed3OExhoLSn7bcvIGQyqvmf0RqO
         9yDtzb1IEDP3b/bWn77DkxSc3TgB4RJzkJxGtwmjHyn5Sif60YFLT287qq8e8ncFPnkW
         TSzGctzXXLXpu9c/dLdvTpsNvWdFT1gyGTnXwhkMPFW5RuPvxyMBkDM5erzi+AQs1ijB
         Nl3BnPqlZcYmUmT6f45zRfGvyzEsOCw3SSwIbtOZTU2QDeUjJAiAVheI4WNEHrsNeKQb
         JAUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=onkrNqwUOWPnPdGWPxdxRKAPBgyzXkaVP4wpOHt/Y9Y=;
        b=lCY9G24S3OjgIuL9bL648NWUyuGTaejWpOue0zoLZmg/wSS9kTqEubAMiNYy916uAe
         hYUHUrzXA14WqEF/qAnesqeu1peKzjB1psS3rkhpXCHYjtNgQ8J+X02AXy9vDNoWSpAZ
         hdotHx/xMa174Sxykz/wFMg2QD92BQ9CHfAgL0MfJur7SUtrotlBs7EHA2SAPdOXyDIj
         teEWrFtPtUmcWiVYBmdNElmyRJo47wfG7fQmO6InigvvNAHktUEPxIZIHVwQQgzs7ENo
         5+AAFNQBCagLuIDFOpf2tHYAhnJNX9/e9B37uCm3bk0pvWsBf05Jb+O0xYa0hYsXflGK
         VgVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=onkrNqwUOWPnPdGWPxdxRKAPBgyzXkaVP4wpOHt/Y9Y=;
        b=IrDsdhyAKKBbmS+VCK/eqAOJknYEZedrPnX517FVxSLsonH8V2oKV93bylwvyOy3cz
         PlMquu3WsKxwpZvhTJjzlpbXv8lFAH4Kd/d+OgNbNnNZH17K11p3ijJm9aSrmt2UqNMq
         vIwgPix1Th+2OlcX63g8qqL7QeDYam3+lNaHyuhtSCFC8qpThxPPOWyu49cdiMoIjktE
         2vaUzAWOPbinAEmjLDZANuYhyNPfSRrGsDbNdGQJo7S3IjxvMhKU1dfzcp9wjTlFRrWq
         /vjfnmdLH5/i/7GbhLqfNZWn+d1LadDrXGZS8arwufcxSXYzHOS31ZJAj5vxJTimZBFE
         aHFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+oij9DO1Y2snoK91LrxWxFILnyEDEwKx3d+cs9DL0Rf+f0UuR
	R6EmuVSh56i9iRAgFPJQ9bo=
X-Google-Smtp-Source: ABdhPJxnm0cFxS+HS38ADLJlSCQbZa4AihemTr10YN6Uj2CuashzR43b8EEczj/duDoXnKkABufO3Q==
X-Received: by 2002:a67:3054:: with SMTP id w81mr36990043vsw.0.1638824882280;
        Mon, 06 Dec 2021 13:08:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6130:41e:: with SMTP id ba30ls2476614uab.9.gmail; Mon,
 06 Dec 2021 13:08:01 -0800 (PST)
X-Received: by 2002:ab0:35cd:: with SMTP id x13mr44064518uat.46.1638824881824;
        Mon, 06 Dec 2021 13:08:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638824881; cv=none;
        d=google.com; s=arc-20160816;
        b=h4yGom9MOU+xRMRKhwHuddlLueVaGZF/ZU+HpEDwGoTukNi3URo+7mC1cHd3aCwJ4v
         b6Az1l8ghtFJlNa0iGlPmsrjCrB+s58ghUtOrWlc+gKEo02LHyU8kjlSIYpXl2iQpiBb
         rynZaWHDhgNQokPLRSCvUY3IBJLl9oANoJ+ZLab9Y+YgZCI5zEM45rZg6D2tVNlX7gca
         tPFx7dUrPdi5fYKGQLyKYUMQ3QnT7HNdLT1OZGuoav8BrLgoV87DvvogQBsGNDpWxT+Q
         NvzsH5xaD25kgkPxopglBHtZPkNOHI88J+905pVFNtGhR6ZulZ7defLQekMAv5kY+bVL
         NQcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IH41mDAtzUD8A+tMjDFc178hVvqONneJF0Z3g7u2BhU=;
        b=ZK6rGvnA3f5ztqj966Ag/cLUUIYPhY1JwghnpVg9H1Lv2359SmeDkFU+lH5K8TQxMi
         8/SMV5zVDh0rpAJQRHFGTQEe1xUgjrtryldBesSLKB4R6BLiOx9D0YKlfCXLUKhykU+X
         ksYZmxCyeCqgVxmydb1NK46mnnZ0JeumqDpUTFMl9+77lxkz3JrXFz8sjFyzMz5ZUZgA
         YvKcnyZazT90Qs0aDAECubzC1BgdSDVOK5OZdGOHBzHa5H1l6ku8pFAu7Q9HnfAiuXpX
         7jHFAUsBRE5g8Pw0hFMBKBsGQQWAyhJQMxTcrQM3ZxF5iB7GbgNKoBQsApioLyY1fNHj
         2TBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WC6vPd2g;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id w8si673458vkd.4.2021.12.06.13.08.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:08:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id p65so14601228iof.3
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:08:01 -0800 (PST)
X-Received: by 2002:a05:6602:45d:: with SMTP id e29mr37027391iov.202.1638824881589;
 Mon, 06 Dec 2021 13:08:01 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <b28f30ed5d662439fd2354b7a05e4d58a2889e5f.1638308023.git.andreyknvl@google.com>
 <YaeCNIyblUAk5mmI@elver.google.com>
In-Reply-To: <YaeCNIyblUAk5mmI@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:07:50 +0100
Message-ID: <CA+fCnZfBNuDYf7A5EiBLrFjYKQNp_fydBrmjW5-wS7Sttk4wrg@mail.gmail.com>
Subject: Re: [PATCH 04/31] kasan, page_alloc: simplify kasan_poison_pages call site
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=WC6vPd2g;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Dec 1, 2021 at 3:10 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 30, 2021 at 10:39PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Simplify the code around calling kasan_poison_pages() in
> > free_pages_prepare().
> >
> > Reording kasan_poison_pages() and kernel_init_free_pages() is OK,
> > since kernel_init_free_pages() can handle poisoned memory.
>
> Why did they have to be reordered?

It's for the next patch, I'll move the reordering there in v2.

> > This patch does no functional changes besides reordering the calls.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  mm/page_alloc.c | 18 +++++-------------
> >  1 file changed, 5 insertions(+), 13 deletions(-)
> >
> > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > index 3f3ea41f8c64..0673db27dd12 100644
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -1289,6 +1289,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
> >  {
> >       int bad = 0;
> >       bool skip_kasan_poison = should_skip_kasan_poison(page, fpi_flags);
>
> skip_kasan_poison is only used once now, so you could remove the
> variable -- unless later code will use it in more than once place again.

Will do in v2.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfBNuDYf7A5EiBLrFjYKQNp_fydBrmjW5-wS7Sttk4wrg%40mail.gmail.com.
