Return-Path: <kasan-dev+bncBDKPDS4R5ECRBD5KQSJAMGQE5VUPFKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id D423B4E8BC5
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 03:53:20 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id r11-20020a63440b000000b0038068f34b0csf6147761pga.0
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 18:53:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648432399; cv=pass;
        d=google.com; s=arc-20160816;
        b=ky9u0BE5PTY1QYNWpllVFiOkqMdSYNCZBS6O7fHWsruB5RlEHCmV/PzIK/ocRApmw5
         2/vWXcYfgjBFfM4avzW9Ddd4OvU1c3PJvmBuvpqccksvS6XprkMiitjftdgUSauWKCx4
         +gjQOZqMs5f1krchG/lW75yW0cKRltnY9mqQ3TpYE2d5qlQiync0783h1WFjNBdjW5P4
         KCSiGoz/a1acOJBwr6uXJhh4fS3hN2XDcg+WRyoawBv7GM5plZ1QOqkiZtvqEXylSaGH
         Ah0r4OrIWPk5Kd3crFriZykKYnFq9WwMsoKoLi7s3pqRhCBZiVpg/hOhBLXKxxZUtIEk
         pJcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=hHxD48JvGVHMCOABLXBNhVYtVGWIRq7XorYX1XHGqE8=;
        b=ZXpTvtCvwvGyQpTyD5V/eVeMvZnTbXWoG647kl5AGWySYmqWlL1SjDyb1HZ+EoeIkF
         QCuLO8NGIK8xUFBMvRYzF1cxID/VX4mtjyhXR/FkNSr57diRTGCzI2ecRzNNUxUk09w1
         47EJTOLk2nXgZrkIew2v3YxXs90JYRFPUxZg2XeWE2aTtaPfuh6/lXUM4Hj5xIox/28d
         fbavZhzb/5qvE8pi8AZ6z8hUzfJ+aN/QRHa72/PCsNoZQoVTdXkYf6HMQDR31JwJblbn
         mdh5Y25WvmcaBybRUxobOBIyhqRl/3qeh3ugVof1KnItI6wqEHd6W4B/oKp1RZiuqS+O
         qeRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=5h4Rr7Cx;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hHxD48JvGVHMCOABLXBNhVYtVGWIRq7XorYX1XHGqE8=;
        b=WtzSpm3mUu/n8xRtpBdG4MzegX9IOElRobY49JIA+fnpSDE+EeBdV0w3QZjUBFG8SR
         67bPZNv2LMAB+iZv1RbvZ49DtjRnSgklUDGcLVX3gt+qO4/BUriLyUJoNUkZrIWQ22O3
         ULWpQJDrAAZKn2uGZ+gOx9LT8ZGoWFVugbtW7SG8RGK5kglTY2o0ZYXI1C7rrRd+Ujjj
         6y/aQsXZvG5oa4DSDAKf0Xi5MRqnYDYpFsGAkU/xVSBvXze2CiwuhsTQpfJzy7JJAwit
         jpI2oKcnH3s9v1iILXHr6hvBTABVXSKOtq7LE9OTb9fDQOSMuA9Wbq0yHRY5H8oPs0rZ
         A3Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hHxD48JvGVHMCOABLXBNhVYtVGWIRq7XorYX1XHGqE8=;
        b=bCOdNBxclSfsZPIejBzT21uwPaP5y88mLLvO+6HBdXCcaT54y/WOSYeXW0K7MZ9DFG
         sB/rOu0UeAGoS+0ArFbCZshbLudUJUeZswBhXNkD4TYPnLs7MrDp0zbIZwfZDrR+U+3F
         6k/JsE1NnDqUZacnRLh4biTdw1OrwCcZnpn9Wa0AgOrgFLRXcJwOZtakPFscRkJnvPwj
         PoNZSRqLmBhk3AMWIpFVsE0U+fZfz2K1nIVYF+wOTfwqwNglom9z64z8Lj6V74FFLCuz
         VQgdh8jaF1zhIIDr5SJvQuP6UEEUw/0Ij+6d3TA0ePel4uBsKWRAfwX9O88s8I7M7uZv
         EFbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530iN5d7bXg2luOS/07LhAPoyNGoPWRJGwcYDna1xcxpAbPoQSUm
	QDMMZN+57cmxkP8C1GENRGA=
X-Google-Smtp-Source: ABdhPJx1QZtTzw1jhxYpRy7xK4Y9m4OQ3YNsZZgsednV95O3aDB0n1QD/5L0G3TjDtJYSWEqnU650w==
X-Received: by 2002:a05:6a00:1494:b0:4fb:34a7:dcc9 with SMTP id v20-20020a056a00149400b004fb34a7dcc9mr8317202pfu.43.1648432399387;
        Sun, 27 Mar 2022 18:53:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6e8c:0:b0:381:309f:14a0 with SMTP id bm12-20020a656e8c000000b00381309f14a0ls4048044pgb.2.gmail;
 Sun, 27 Mar 2022 18:53:18 -0700 (PDT)
X-Received: by 2002:a05:6a00:1252:b0:4fa:afcc:7d24 with SMTP id u18-20020a056a00125200b004faafcc7d24mr21060582pfi.85.1648432398787;
        Sun, 27 Mar 2022 18:53:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648432398; cv=none;
        d=google.com; s=arc-20160816;
        b=WcZdwNPjs1R7Me7F+zyuQx8vj3aRpTBe3buQmoXepDMkD8ZCL8ys8mnL4j3wA6FXZJ
         60IpQV9MxVS2lVq1h2QOLLLLu8c4hVfWq0u6V/GuJRroKqZgK66CRi3P+FAW0lKonWcq
         OSh9RupXJLHTXsiJpwQbTdBN/pmKfTtrbzSu4gT4RuQc34er9K4xH+M7iqxpdZBjOD3H
         MRPECUox0PZ/PbhzuRb6k9ze1hDsdemZvF+lzoaZTuqFwa/YmJKyFWEx6P51yHFWD+tZ
         2JDrreG1eX9Mc+/sDkPVjC9qYuZEZr12AA6NcWp2eRB0ogc0TPVOAI9wUcQkiOBaEma2
         n9pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ld6gg90UxBewd5EuGKuXKzT3kPcWyc890roNOgvWpfk=;
        b=U3EiCSz+dtCl99UIsOkM4/p59V7K7AYn4d7OvdV0qnPPh/waudjt5gmhCOaAQj+mIL
         24MJ8V1ZkG2kOW2Ykn3P7QIPE1k8wPnbL8TP+b1NUbp/cWwV0P3Gd2L7SJAzOfk2NlrO
         WyVW4FcnYrYsc3S8W1vp71DvT0H/ZEZAT95qxH+lUX8svWy5D9jlX3no+qW+98RYl3+C
         jlQUUhnqrHkYUPILoUh0GnzFdwFkwoZKByd7QhQLORXguBIbEBwyWUOiKy5EdXdDV3ju
         cQ12Sa7vTaWO9HZP3KVO+2C53brma2eDxsMduD3afKDqlFOfZGuALTvcjNispJ445bHq
         yr8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=5h4Rr7Cx;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id m12-20020a170902bb8c00b0015016b90616si937348pls.11.2022.03.27.18.53.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 27 Mar 2022 18:53:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-2e68c95e0f9so133883547b3.0
        for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 18:53:18 -0700 (PDT)
X-Received: by 2002:a81:897:0:b0:2e5:f3b2:f6de with SMTP id
 145-20020a810897000000b002e5f3b2f6demr23165273ywi.141.1648432398131; Sun, 27
 Mar 2022 18:53:18 -0700 (PDT)
MIME-Version: 1.0
References: <20220327051853.57647-1-songmuchun@bytedance.com>
 <20220327051853.57647-2-songmuchun@bytedance.com> <CANpmjNPA71CyZefox1rb_f8HqEM_R70EgZCX8fHeeAnDyujO8w@mail.gmail.com>
In-Reply-To: <CANpmjNPA71CyZefox1rb_f8HqEM_R70EgZCX8fHeeAnDyujO8w@mail.gmail.com>
From: Muchun Song <songmuchun@bytedance.com>
Date: Mon, 28 Mar 2022 09:52:40 +0800
Message-ID: <CAMZfGtXt9xWnVv8hav+zWHYRmOqBGu3WPaasYwGxCb1-MDDwgQ@mail.gmail.com>
Subject: Re: [PATCH 2/2] mm: kfence: fix objcgs vector allocation
To: Marco Elver <elver@google.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=5h4Rr7Cx;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

On Mon, Mar 28, 2022 at 1:31 AM Marco Elver <elver@google.com> wrote:
>
> On Sun, 27 Mar 2022 at 07:19, Muchun Song <songmuchun@bytedance.com> wrote:
> >
> > If the kfence object is allocated to be used for objects vector, then
> > this slot of the pool eventually being occupied permanently since
> > the vector is never freed.  The solutions could be 1) freeing vector
> > when the kfence object is freed or 2) allocating all vectors statically.
> > Since the memory consumption of object vectors is low, it is better to
> > chose 2) to fix the issue and it is also can reduce overhead of vectors
> > allocating in the future.
> >
> > Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
> > Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> > ---
> >  mm/kfence/core.c   | 3 +++
> >  mm/kfence/kfence.h | 1 +
> >  2 files changed, 4 insertions(+)
>
> Thanks for this -- mostly looks good. Minor comments below + also
> please fix what the test robot reported.

Will do.

>
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index 13128fa13062..9976b3f0d097 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -579,9 +579,11 @@ static bool __init kfence_init_pool(void)
> >         }
> >
> >         for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> > +               struct slab *slab = virt_to_slab(addr);
> >                 struct kfence_metadata *meta = &kfence_metadata[i];
> >
> >                 /* Initialize metadata. */
> > +               slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
>
> Maybe just move it to kfence_guarded_alloc(), see "/* Set required
> slab fields */", where similar initialization on slab is done.

But slab->memcg_data is special since it is only needed to be
initialized once.  I think it is better move it to the place where
__SetPageSlab(&pages[i]) is.  What do you think?

>
> >                 INIT_LIST_HEAD(&meta->list);
> >                 raw_spin_lock_init(&meta->lock);
> >                 meta->state = KFENCE_OBJECT_UNUSED;
> > @@ -938,6 +940,7 @@ void __kfence_free(void *addr)
> >  {
> >         struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
> >
> > +       KFENCE_WARN_ON(meta->objcg);
>
> This holds true for both SLAB and SLUB, right? (I think it does, but
> just double-checking.)

Right.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMZfGtXt9xWnVv8hav%2BzWHYRmOqBGu3WPaasYwGxCb1-MDDwgQ%40mail.gmail.com.
