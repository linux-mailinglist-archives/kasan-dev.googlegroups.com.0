Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBXHXKJAMGQEO3NNHYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E9D94F7C2A
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Apr 2022 11:48:55 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id g7-20020a92c7c7000000b002ca31b0b53csf3508111ilk.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Apr 2022 02:48:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649324934; cv=pass;
        d=google.com; s=arc-20160816;
        b=1GOXtCUiSUAWtMkQ3VoNAgJvSLMLGZch9FtKhn5esVgHr1c8Gavc1YCRla0iv0a+LD
         K3LM9a17Swa3eaBagQxpOqXwocYO7qG4C4nQjfpdNHtP2GMsmnJULKl0ewkdcN2GJwV9
         9Gj7E4GRLt4BMnuVgcyfqjJhDN/8HWfwgflgVb+DQ9CiqwNE6lX/JQ9siLGlMCDQXzGV
         pLZtUrbYM1kMSXOdXmAPBTDhvZD7drztnGHdVJel2thWRtX/czXSaVz1DkYuBQ9+qRVT
         4wOcEGAcp4El1tqtjtNJGCb6AiaH7JYd2VzUaIswCshD8XLPyfWCwyJ/6gfzpb2J4JSq
         ePPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fydwc+BE40B1UCte2KRQR6JIqb8f/sEaINJkdAPC91A=;
        b=PWxpMmFFDWHPjNDphQbygzLJpdQQWzp7Z1t3230llVQZm4GaFUkuIiv9ndGK90Oz9u
         bN4GRR45ZiR4Hjay7luMZQlQ8MMUX8UmMnuwnZzBVYIXSkYza0A+/74pHrhQ2oMHY4kl
         3CSYkXRuXCRJRIoI6HSCLz7vB4DpNjrX0HGcM+nbMy410uqcyYzlFIAKDX3Lbch9pTru
         sOw78vWUFIDHoABS0tCqoERrAUy0tOMQ/UVP7TcFCNngxUPEWS6luduweTpFv79C78JP
         RBKMhnU6Rz/QdvKXVBP1sFou4mcrud3rgQYCdhY5Ag5khR31p4/Zdhq8pKre7nwGWTJt
         X2VA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fJfbpG72;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fydwc+BE40B1UCte2KRQR6JIqb8f/sEaINJkdAPC91A=;
        b=ar9tNrHgj/xoL/gcrR+0W2OhqgWFRCNjXOmeFI+IQD16izAOHcvGk3Yrdx0wurN7wh
         L3PS1DtlNzth4ZUthbeHJDNVuikJLDK6pDRR9t0G1f8JEt/u6Qh8h+HSBzS5YcYn5TPj
         9Jo4YrliEGvkf+TYX4Wliqx8axox4VecHpM5C1I86m2a4JSKaJN1yQX66sALX16EhFAX
         ZPOWKnNOWY69rsnOtsIbG0bhnfLPcyW7mZc0gxdLJuyLlpWYzS0o7AJiCeLWBecABIU6
         iFNEP1LeEMnhmPR/Ulniq+OtKxe6ZVgIJAicc4ltbZ0wus6WaBCfLyUFNhZd2bz6rb3w
         gMqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fydwc+BE40B1UCte2KRQR6JIqb8f/sEaINJkdAPC91A=;
        b=R08nE11D8K+aUOzD7vO75ZJw5vPKckheMX3ZQo1Gi9e0Wgvv2Xel+n7HVzUBKZp6/i
         wBOqIIUdhlz/Q0UiClgM5k7aK/zqj1BCeCR2IjC3kuIDceBVqqIsjI5s1HgAsvuI+SFz
         5MfP75hdp7FA1d1WdULCu2VDpUQjOVzW6m5ur8TQX92Gg/t+HaPRH+epZJahMOrX+sxr
         glYOHXv+10jef2uGvfC3dHSSGsR9puPqmLPm3cANI19ru+KYK5YlpR/CTRVsE0fIE5bD
         5UKVZnkfCgY259HGNvFBbwAZKRCPmyW/e/jNriNmbkefmhoZ/Zac/D/W6AmhjP0vvvqZ
         3buQ==
X-Gm-Message-State: AOAM5324SFIIVeGwXMyWTKR3CNtTS/bN6xbXzcUTrFPSfm43OpWzr9Jr
	i3wF5/mlqXNy0LKPTkxEmeo=
X-Google-Smtp-Source: ABdhPJxMtHLSbrWjPSJbmp+sEm+lIIJ+Smzy/Q8nU9wLpa/ZMkRelTNXsALNFETIHW6WWrU0NucA3g==
X-Received: by 2002:a05:6602:2ace:b0:648:d9f0:da00 with SMTP id m14-20020a0566022ace00b00648d9f0da00mr6035333iov.115.1649324934161;
        Thu, 07 Apr 2022 02:48:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2402:b0:648:af12:ecaf with SMTP id
 s2-20020a056602240200b00648af12ecafls332586ioa.0.gmail; Thu, 07 Apr 2022
 02:48:53 -0700 (PDT)
X-Received: by 2002:a05:6602:2a47:b0:649:ee6f:c5e1 with SMTP id k7-20020a0566022a4700b00649ee6fc5e1mr5873776iov.91.1649324933673;
        Thu, 07 Apr 2022 02:48:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649324933; cv=none;
        d=google.com; s=arc-20160816;
        b=xvgWNDWRUkdN7GYN2L0pYZcDc+xCkvZcpXs1F4Y0ApGti7/PlqFuGBZQFWqXkjEmS4
         f8bF628JyByGN3D0+JezKNKcfYc0CeBIJ2JQ1d1DNsqVdjidtkcKR/fO5RiaSeznG+8c
         U1lZDRJ2EIe7YMfB9Elc52zE+Ypam95a6ow23fIEbXvNpwao/GNVZHizpBewBQ3Tiqj4
         wrQVyGFyaT6jIi9LuUmX9S/giJoNqmUNjMw4m8HvJBfO7dvYdy5ybgkdwLimba/NUIpu
         sI8Q9RC20tg5fBJ39D8Y8UPImjZSSpgiu8bT9u5hVG9JjOyusrWJ1SRfxQJDBOuUxaP8
         WQ2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RZbNz+SpGjPMORTCOnUHEEDjbgkpN3TzZ8t3nm7Vc+A=;
        b=Wy2FxGovN1+OIMy+Z4mD+4jVN9dCuYby5iYtCBoZtOJsilE8FDhAyTr8bKehQR+t2n
         zJ+XjnJojID7+YsvSFmiRdtSKbkHA19oU8/mKSEAb0AeahycCWHJ3qtLnWLYdSbHj3zV
         HPIewoS9jMK1/UUSUZR8hBVCcbhEBFB+4jCxFn+XB48ixCNr+N9jWSZ16FK2uPHJ8bk/
         Un+VaA5nDZkq7ixwfNl5ynHt2wzDdgOiOYoLtQU/Ne+RXN4vECE8E+KBx8ruydM7NH9z
         5ncgrXLF9TkBE1gg0cTpM0XBp+BU+eyWoI3JTQoxurYCbYZ4mnxUZosbqd5YE8dOO682
         oCdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fJfbpG72;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id t17-20020a5e9911000000b00641b4797049si1366271ioj.2.2022.04.07.02.48.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Apr 2022 02:48:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-2e5e9025c20so55353287b3.7
        for <kasan-dev@googlegroups.com>; Thu, 07 Apr 2022 02:48:53 -0700 (PDT)
X-Received: by 2002:a0d:c306:0:b0:2e5:96ab:592e with SMTP id
 f6-20020a0dc306000000b002e596ab592emr10782019ywd.316.1649324933050; Thu, 07
 Apr 2022 02:48:53 -0700 (PDT)
MIME-Version: 1.0
References: <20220406131558.3558585-1-elver@google.com> <4b592848-ef06-ea8a-180a-3efc22b1bb0e@suse.cz>
In-Reply-To: <4b592848-ef06-ea8a-180a-3efc22b1bb0e@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Apr 2022 11:48:16 +0200
Message-ID: <CANpmjNP-XtRB3zTOymH_PCKbDMHoJVYx6UQd_xoM-s33bXJk2w@mail.gmail.com>
Subject: Re: [PATCH] mm, kfence: support kmem_dump_obj() for KFENCE objects
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kernel test robot <oliver.sang@intel.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fJfbpG72;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as
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

On Thu, 7 Apr 2022 at 11:43, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 4/6/22 15:15, Marco Elver wrote:
> > Calling kmem_obj_info() via kmem_dump_obj() on KFENCE objects has been
> > producing garbage data due to the object not actually being maintained
> > by SLAB or SLUB.
> >
> > Fix this by implementing __kfence_obj_info() that copies relevant
> > information to struct kmem_obj_info when the object was allocated by
> > KFENCE; this is called by a common kmem_obj_info(), which also calls the
> > slab/slub/slob specific variant now called __kmem_obj_info().
> >
> > For completeness, kmem_dump_obj() now displays if the object was
> > allocated by KFENCE.
> >
> > Link: https://lore.kernel.org/all/20220323090520.GG16885@xsang-OptiPlex-9020/
> > Fixes: b89fb5ef0ce6 ("mm, kfence: insert KFENCE hooks for SLUB")
> > Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
> > Reported-by: kernel test robot <oliver.sang@intel.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>
> Thanks.
> Given the impact on slab, and my series exposing the bug, I will add this to
> slab tree.

It's already in Andrew's tree:
https://lore.kernel.org/all/20220406192351.2E115C385A5@smtp.kernel.org/T/#u

Does your series and this patch merge cleanly? If so, maybe leaving in
-mm is fine. Of course I don't mind either way and it's up to you and
Andrew.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP-XtRB3zTOymH_PCKbDMHoJVYx6UQd_xoM-s33bXJk2w%40mail.gmail.com.
