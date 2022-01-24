Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWNCXKHQMGQE7ASRZJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 42D07497E33
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 12:45:31 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id v5-20020a17090a960500b001b4da78d668sf13415857pjo.4
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 03:45:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643024729; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZaNuecPIyQIhetVuVlv1VM6GGkJoIrqOTLEH1OXmpp4R9uBSIRKNmwk44+5TcKOfdb
         2txZunkN0LQC3n56iObH4mjXNyQZmtCT45YQ14eKg/6fvWOQYBHhUjRl2b+pBWP73eOw
         iMEHMVRNewsZKcNGhjm9Ho7b1eeh9sfCa4FRZKNu1QKVBHdxYstJaSAq50e1T9s04yz6
         3hw6MyI2j90qAZm269Fg4y42Gm6X4cmLpt8bqMsWJBlyUBZQj8kCkdWRQjOHOJE2mPyy
         R6jqLfaI4DbXGs75aA7VwbXvO8HDIFuFtlxr3H0Q7v3zZ1xw/q+3N41U47HHYru5BBPZ
         nIDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j+HIJlDEFv0VeiZ45ca8sJEbOAKf5o8fOqYHKH28zGI=;
        b=NFNLBpvp8Md6XDWhD6E0BdDrIlgJ75uwERweX/8vU5pAUmZWZqb8z5U91j0Xt8TWeF
         hzBhi7tNVRjLNFoJi4IseN6vd6shcFeRmgY+31vHIp2jRB6Qph26uMZ0gvy12KxFizub
         jgfsHeviUoclhAfXfeXkHPl7Jd5B3/qAXiZAjx6rKl+isS2tu6BfGxcnxPNz6M0QMj8s
         3yH6LWFgPIJ6UaZZ9Jz+eZ9ENgAyYQ4CGvaM4dhDuXOZx8hYumtsiW/3sW3K9//jG24R
         NSbJUXqzx5a4nsiLlBE3OS7dtI3RMEx5nxBLbGUdBjXEDQHSPMCy8FMQvaSLbE0fcCPz
         vZtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="HvPmu/lB";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j+HIJlDEFv0VeiZ45ca8sJEbOAKf5o8fOqYHKH28zGI=;
        b=F132E0dFAYhWrES/BnwgeWl10mLo/iiDbo74psuyioVDfh0jSfiOPh8ZL2wS/EY4rE
         oqC/pjIi2Pipcjr5UzzRJf8oixOFfWfZ57jhMzax9+GdV0poDlwiLbWNyvLKTfQ5hQow
         yPc0eD55oYRHObdUwRNbPZywR3+WMvC+cgbIpTvKxFKOX9gZqINIq73W3UzWzaYLs+7Q
         esNy0wpO/5a7J+djBe1YgB254kGMMPBtLDqvalxMEFZdxU9gNkWapfRia1Gz5+02k6tq
         gE/kjuQ1ZIY0FFzjVi2kRw6Bhd+ooLfd23SVtlbaMCikoZgnnN4NaYCwxJJvnXPb0ncC
         /BEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j+HIJlDEFv0VeiZ45ca8sJEbOAKf5o8fOqYHKH28zGI=;
        b=TB860hOuUWPmLtQj70/4Idoxv0UbAq2sj9g9u65w40NpXLaDW2Y2rZJt/CuV29/1O9
         6Owmp7vBXw/CAkGxKrx2ggzmekNfJuF2h2nNTV4aB3bGG6DtLlPXeYFUAM8V6sFUE11F
         OAbzjHG/mc5qWqzhQicco6LlhZVqZ3A80QneHanikyWEyXMUjq4QElNx72XbsELhsVkG
         llsKOzApEEUor3v9JkNq9oIQ/Z+BisSjJMsNcK2QtQiHHDWANekiOb3bZ9rx6yDQyNST
         dUwSB6xEz3lvuzCOa260V8ZnRnLxzBKCyMkWTPPIALopz/9N30YfRunrfTv7yP8aa/fD
         xBqw==
X-Gm-Message-State: AOAM53297B0SmKNJBCdDU/R23SxoZoRvZegEdBRQmaKxk2OLILE0pCqn
	ad3QMgcp+qC8I3FT7LVfIgw=
X-Google-Smtp-Source: ABdhPJxe9C14FDHpbTDJn/sfAmLtW/inz4QlApI92o5BctMcDcuWH8ZerjGSRBe35bE832Oilx9X7Q==
X-Received: by 2002:a17:90b:1803:: with SMTP id lw3mr1526970pjb.124.1643024729782;
        Mon, 24 Jan 2022 03:45:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5b64:: with SMTP id l36ls4584535pgm.0.gmail; Mon, 24 Jan
 2022 03:45:29 -0800 (PST)
X-Received: by 2002:a05:6a00:24c9:b0:4bb:ffe2:17c2 with SMTP id d9-20020a056a0024c900b004bbffe217c2mr11331695pfv.31.1643024729101;
        Mon, 24 Jan 2022 03:45:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643024729; cv=none;
        d=google.com; s=arc-20160816;
        b=TRYt7WWt4DYAfFD/IZqYCuJxi/uxHUIUMiIH82OhgDRTXlw8QJ+0Z9Pg0rx24Pd/xe
         3/+bHqthzZT0DnVgJp3/w2y/rX97q06JWntz9lWPOfBBQHrYO3heirlJigzEYhJ8Ru2p
         2/lczl8JHR9SCreE5ZKrClf59wt+bc6BuCpwhj/rnYcjxa1yRblb2du2fbPswvgUiRfn
         gCHcu86r+1FQaWHjtj05YUDy+uzXNzL8UpkxfR6PG/Q+VA7Ya0H4la5ZLPte663r68WA
         8vQnGzpdOYb87RShSgDkFBAkV2A93thwkqGD4UxyD5OZ3Yg6pxZiKjNNWj+TkUW48zSr
         HvAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HDkM4IiHfUKgbkZ+J9zwOceHsfDsj5OClEazZRmTBPg=;
        b=GIorUO24nQILsG7eIT5CL6EN1HSCVRCleaGCgAD0EjGJICi1amsCzJ91BJmOo03+32
         qfAM1haJ2oJnqj18phgpqRn1klLWqhFxzXECEFxQFZYfFbk7G2axvZGnTRpr699fOtgc
         +zGcQqvPaWHTErUtcPWQdwhDDPEML+iNakNPFZUU1J4HmDMMfIYu7HT0Vh9an21phOHD
         f9qLPb21LIdHN4oW2kGuvZ0aVdXCctaRPl6Wg69O5lJQQrvysbpeha9LpRwn4ZDWog6v
         D6I3sUHmS4ApBSGcnzLqtuRZclWXOd9tHp+Vb7310MgJKhlpD3pvWYF1sJtoy+xqOUdY
         UV8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="HvPmu/lB";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id c6si45182plg.9.2022.01.24.03.45.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 03:45:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id q186so25043182oih.8
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 03:45:29 -0800 (PST)
X-Received: by 2002:a05:6808:15a6:: with SMTP id t38mr1044668oiw.154.1643024728284;
 Mon, 24 Jan 2022 03:45:28 -0800 (PST)
MIME-Version: 1.0
References: <20220124025205.329752-1-liupeng256@huawei.com>
 <20220124025205.329752-2-liupeng256@huawei.com> <Ye5hKItk3j7arjaI@elver.google.com>
 <6eb16a68-9a56-7aea-3dd6-bd719a9ce700@huawei.com>
In-Reply-To: <6eb16a68-9a56-7aea-3dd6-bd719a9ce700@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jan 2022 12:45:16 +0100
Message-ID: <CANpmjNM_bp03RvWYr+PaOxx0DS3LryChweG90QXci3iBgzW4wQ@mail.gmail.com>
Subject: Re: [PATCH RFC 1/3] kfence: Add a module parameter to adjust kfence objects
To: "liupeng (DM)" <liupeng256@huawei.com>
Cc: glider@google.com, dvyukov@google.com, corbet@lwn.net, 
	sumit.semwal@linaro.org, christian.koenig@amd.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linaro-mm-sig@lists.linaro.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="HvPmu/lB";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

[ FYI, your reply was not plain text, so LKML may have rejected it. I
advise that you switch your email client for LKML emails to plain
text. ]

On Mon, 24 Jan 2022 at 12:24, liupeng (DM) <liupeng256@huawei.com> wrote:
[...]
> > I think the only reasonable way forward is if you add immediate patching
> > support to the kernel as the "Note" suggests.
>
> May you give us more details about "immediate patching"?
[...]
> Thank you for your patient suggestions, it's actually helpful and inspired.
> We have integrated your latest work "skipping already covered allocations",
> and will do more experiments about KFENCE. Finally, we really hope you can
> give us more introductions about "immediate patching".

"Immediate patching" would, similar to "static branches" or
"alternatives" be based on code hot patching.

https://www.kernel.org/doc/html/latest/staging/static-keys.html

"Patching immediates" would essentially patch the immediate operands
of certain (limited) instructions. I think designing this properly to
work across various architectures (like static_keys/jump_label) is
very complex. So it may not be a viable near-term option.

What Dmitry suggests using a constant virtual address carveout is more
realistic. But this means having to discuss with arch maintainers
which virtual address ranges can be reserved. The nice thing about
just relying on memblock and nothing else is that it is very portable
and simple. You can have a look at how KASAN deals with organizing its
shadow memory if you are interested.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM_bp03RvWYr%2BPaOxx0DS3LryChweG90QXci3iBgzW4wQ%40mail.gmail.com.
