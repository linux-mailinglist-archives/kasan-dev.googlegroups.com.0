Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTPIZWIAMGQEJQLXCTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id F09DA4BD958
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 12:15:26 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id bh9-20020a056a02020900b0036c0d29eb3esf9273748pgb.9
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 03:15:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645442125; cv=pass;
        d=google.com; s=arc-20160816;
        b=QZLXZGJ2/e/KPAFuvrf6MJrCKsggk+TWoQtc9OXo/3qPXt1nzF/+gk4htWD4eZp2y2
         hQ92Zp7MLbhjmihVq+k4JTGX3x7qOxXJyAqdEic8Le3K6PxjtBx7VQzjGSjxvHZUTsjA
         5DPKJ/+5gqyljP3Mcl+NxUtoB2Wp+b+KT2Hd6VQJV4ODB+WMd2qZ/iHWu8m+LwoQitze
         2u/ClLIQo+Z7xDW2gJxTtw4UmMPThH3zgfY+hjtlWVI3kjc2V8yKz+j7gCx5Ya9egfke
         xRWAopn/Qxr/Rx6Q43H5pW0jZLwLMtDljWNddwEoJPIzQ4h/SE5bfLRtVx8xaGalNTCj
         htag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dngKWEmneqv5B/OcArEhgQ6J3mhdB7K5Ng3wzDL/Cn0=;
        b=zZVtL7qd+rZrgKG6sgM1KK42wk/umPrx0n7cnAEd4YLFQn+crMZDpJrwP5014Cw81I
         NWLRRNy42P24PXipHgBpedMUbFJsHZgZwp/xQiX9nqPUyezpIogguyheLO6idMHa5SG4
         cTMTAjWSFDlxNXyWeBWs/6UrR8jTbrpjZWozLKqqJEYtNqZvpGlIa2gpiHut1PnSQD9z
         EWdOGMICo6SZbhgvQivfZcyKdzqdzmVcoy+Yuj4sIMDixjmUvJnQwrb3BWGYXhWjHqhI
         JKJIgbG+zCp+ZE7XP1aPlJzhJj7MuHJCpir6MqwcVQsOvK4RVU/uSD2Udu58P5HxioRd
         w4dQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ouaPUyc5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dngKWEmneqv5B/OcArEhgQ6J3mhdB7K5Ng3wzDL/Cn0=;
        b=kYOaKFePMAcmlGsmXZBIGEkYRu/8EdMeGz+7iQX8D/Gd9DN/yf4h91AqsuZ5bTBYOs
         6Fh+JKHblCp+7muxe+tT/YFgnw1zAK0TH/WFR74JxGPl/kv9+yHcPQc3Yr03SSBm753i
         gNaPVR7zVWdut9+gXlkObKTJB23u0ASO4+OAkFSelnZrpojcGEHzUr7gwhAWbj11jw9p
         WGBVaFVpWUT1/aQ0U786h/gKUa9ndniMCggkmbuFZ/iIRPx1tkvfycNN7hJag9QyWDRv
         W6g2egTAoN+C7YUM95b68mJWDPiz1F0JjtXNEvKv7F7Nq2XxdWqLxaFdFHthRi/owhSt
         pRGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dngKWEmneqv5B/OcArEhgQ6J3mhdB7K5Ng3wzDL/Cn0=;
        b=lxJ4GuvOC2pYwcIs7onbz9I2JzUMH2C4whheOIm6wXMEkTD7EOZmaSU90aq+v3N1rV
         SRMHJBK8c/IYUrWSN5N8QDXMIQckR/VJW78NvzF0LwhbqMaUjkSPtOlmSsKOKpyHyXdg
         YEUbs9fO5yHMV97Dfb6lc10Jh0DelLTxmXA1sHYlP9ID9WZwlqG+6F4nK2BkYxc9Z2KB
         3s/XWRaw8Kocmy+f3c+BimIholREmTcwHa/ZjudmzUmJT3i7kZK5KX2piLgooev2/hZS
         Ah9JhDmXUv6JujYozyOoJ6PDtezSmAVhr6mMUN8rBu2M38TNOtv2c1IKWBZghrUyDOaa
         8SDQ==
X-Gm-Message-State: AOAM530UOF27CRfbVoWBPfdki5SaTdx/L15jF8X5Q688NP07Y2xAxNyl
	iByeB3WUYCmvKBbLbK6ETNE=
X-Google-Smtp-Source: ABdhPJxrf31nz1kckRrNNd07MR0U6dVADQ5Gt/vJtJf1D/VFQhbq5ZJszw1c0j9LH7acwmDMJiBWHQ==
X-Received: by 2002:a17:902:758f:b0:14f:b5ee:cc5a with SMTP id j15-20020a170902758f00b0014fb5eecc5amr5117234pll.43.1645442125311;
        Mon, 21 Feb 2022 03:15:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d4d2:b0:14f:af3f:5dca with SMTP id
 o18-20020a170902d4d200b0014faf3f5dcals2461121plg.4.gmail; Mon, 21 Feb 2022
 03:15:24 -0800 (PST)
X-Received: by 2002:a17:90a:578f:b0:1b9:b03f:c33c with SMTP id g15-20020a17090a578f00b001b9b03fc33cmr21192628pji.114.1645442124692;
        Mon, 21 Feb 2022 03:15:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645442124; cv=none;
        d=google.com; s=arc-20160816;
        b=B+LK2UXFI5BFGcRgn5jcPVlSyLNbBoSHGh3w5P34nPUJ9smJzX0X8VYdEMBIO7GGKp
         XQO1DIOIXTG/yaW711LmbfOE1ej1NcMUVvuDMzQi/In2+zAfWKko/Prgi03tcbijGkNv
         J8lj0+fTzBolWnDJ1y4hs6JfzcRi26XTrRRBXWK3EfN3WVT3vyTW3J/DFqFO37x0pcDf
         CBKVDy+bwWt+uq92S6QOZBIwjcis0VkHiYzPfJRPlwIMsbkiIAJ/FklaJ6Wwrcrp7TiZ
         Hec0iRzJkLZoWsa2T6H+zR0eCS44x6UmwuH/iHLHC3WN48l81FTmc52KHLU77Jy6otb4
         3CIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aW+puJnFP6GDgHHGWDtmoEv/OAIRXfNxeTuS1KHKS4k=;
        b=oZHU4gvqZ93KF2if1eueNHhyq+RnihmvvKPxrddhY9Vq1+iaqoWe047WW2R3Gc0c75
         tqI5/7NdcZIRCd7i+BwVwRVJd5FI7rRr3VHdVp8GZPtiAYfVgFtIFvMCkP74xdJmHQlO
         lKHwwDZcirgOyOdDKT+sc5nKM70BsBPPsKQXrjRS0RG1L3lwFmKSw3qiK5sGIl10+N4r
         zLtW+RcUeExmrRWAu331VVYrrlVkQds/50Fc+9INboOHXXgKJ8djR338g2s70rMm964t
         PCHQ00+RUbDGSAz8AYuX+lsqq3BjVF+dZnmZUriT+oRgYUBbS/B6xWMUsl6hdGoa+Vjq
         5MUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ouaPUyc5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id p11-20020a17090a930b00b001b97a1bfec2si498865pjo.3.2022.02.21.03.15.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Feb 2022 03:15:24 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-2d6d0cb5da4so79041617b3.10
        for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 03:15:24 -0800 (PST)
X-Received: by 2002:a0d:fb07:0:b0:2ca:287c:6c97 with SMTP id
 l7-20020a0dfb07000000b002ca287c6c97mr18617337ywf.316.1645442123922; Mon, 21
 Feb 2022 03:15:23 -0800 (PST)
MIME-Version: 1.0
References: <20220219012433.890941-1-pcc@google.com> <7a6afd53-a5c8-1be3-83cc-832596702401@huawei.com>
In-Reply-To: <7a6afd53-a5c8-1be3-83cc-832596702401@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Feb 2022 12:15:12 +0100
Message-ID: <CANpmjNO=1utdh_52sVWb1rNCDme+hbMJzP9GMfF1xWigmy2WsA@mail.gmail.com>
Subject: Re: [PATCH] kasan: update function name in comments
To: Miaohe Lin <linmiaohe@huawei.com>
Cc: Peter Collingbourne <pcc@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ouaPUyc5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1133 as
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

On Sat, 19 Feb 2022 at 03:00, Miaohe Lin <linmiaohe@huawei.com> wrote:
>
> On 2022/2/19 9:24, Peter Collingbourne wrote:
> > The function kasan_global_oob was renamed to kasan_global_oob_right,
> > but the comments referring to it were not updated. Do so.
> >
> > Link: https://linux-review.googlesource.com/id/I20faa90126937bbee77d9d44709556c3dd4b40be
> > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > Fixes: e5f4728767d2 ("kasan: test: add globals left-out-of-bounds test")
>
> This Fixes tag is unneeded.
>
> Except the above nit, this patch looks good to me. Thanks.
>
> Reviewed-by: Miaohe Lin <linmiaohe@huawei.com>

Reviewed-by: Marco Elver <elver@google.com>

And yes, the Fixes tag should be removed to not have stable teams do
unnecessary work.

+Cc'ing missing mailing lists (use get_maintainers.pl - in particular,
LKML is missing, which should always be Cc'd for archival purposes so
that things like b4 can work properly).

> > ---
> >  lib/test_kasan.c | 6 +++---
> >  1 file changed, 3 insertions(+), 3 deletions(-)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 26a5c9007653..a8dfda9b9630 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -780,7 +780,7 @@ static void ksize_uaf(struct kunit *test)
> >  static void kasan_stack_oob(struct kunit *test)
> >  {
> >       char stack_array[10];
> > -     /* See comment in kasan_global_oob. */
> > +     /* See comment in kasan_global_oob_right. */
> >       char *volatile array = stack_array;
> >       char *p = &array[ARRAY_SIZE(stack_array) + OOB_TAG_OFF];
> >
> > @@ -793,7 +793,7 @@ static void kasan_alloca_oob_left(struct kunit *test)
> >  {
> >       volatile int i = 10;
> >       char alloca_array[i];
> > -     /* See comment in kasan_global_oob. */
> > +     /* See comment in kasan_global_oob_right. */
> >       char *volatile array = alloca_array;
> >       char *p = array - 1;
> >
> > @@ -808,7 +808,7 @@ static void kasan_alloca_oob_right(struct kunit *test)
> >  {
> >       volatile int i = 10;
> >       char alloca_array[i];
> > -     /* See comment in kasan_global_oob. */
> > +     /* See comment in kasan_global_oob_right. */
> >       char *volatile array = alloca_array;
> >       char *p = array + i;
> >
> >
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO%3D1utdh_52sVWb1rNCDme%2BhbMJzP9GMfF1xWigmy2WsA%40mail.gmail.com.
