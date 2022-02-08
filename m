Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBOXMQ2IAMGQES5S3Q7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A6434ACCB6
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 01:15:55 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id y10-20020adfc7ca000000b001e30ed3a496sf1893024wrg.15
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 16:15:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644279355; cv=pass;
        d=google.com; s=arc-20160816;
        b=Knwu1AMivYPZyWxI14J0aoKDWK39Qnzb/tU5afJ5lf5kdyU3XzuThANjPto44jZh1F
         uwmckH76ZFWNEoaGo9XO8YiV1XqkhEfDvcNessMvklAZ3SiAlolTU4wSqcOX+IkhMj9j
         0LR94+bOn14ipkiKQy6r0V7QW7UvsHsO6NRU7lF7hsXsGeiAYFx5dt93H1pANp356FHF
         4J+U07/FJEv8xq1djh+ExpTVoZJsXCsibSj0HogZTMsZB/iilRWPWj9whxNVJc3fdmI8
         HxxAlvJtOCBOCQOQ6mJUPmnZHRhfkq8u5YSGPNosYpX6TRAza5cAlbb5Sr6VH1bnuxLt
         THRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=11XyMsmg0QL6mr5/lVzDG9L/B+O+THHIQuXNhRVoLpI=;
        b=A5s7SCNgeYOitGDZwKcWhWdCR6L3+dJE4tnvYZKfCxZhN08GaF6ytCxauzsltdn9TV
         p6cL8Y+jUXAnvLG5LNMX3K2NvKYF0mhlYJjHbgny9HsiAMfhImqgsTQ4cxhyriXvoRpH
         yZjOaRYNiRlWLU1wA31H5U/jm3kXSVzrDamStQHyUzoz1oIGxEgd+Rqg27GKnuPAYKJa
         BCdnsRRAdj5Eu3+BmJcu+jRsllHAndYplPiJ1F/jmZhU0+LAduhK1c2U3Ys7AB/03cBX
         K55L6r0k2xUcoskbU0+ozoJMepsfkk5sztAnABjtZQ30QWprOKOaY6W1F+XrYOHh4rQu
         wNaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rbqKbdD3;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=11XyMsmg0QL6mr5/lVzDG9L/B+O+THHIQuXNhRVoLpI=;
        b=TEkRCAk/2n6OEJ62z4tO8JwD7rtJwHbBpt9Tt3NDJaYjpk8L4sY7Ym8F3OGAAhEjnE
         o82EW1DIvXP3A1hml5+TUBA5KZDruufJmFaPOB05Kzwk++wZLMExh/wi9uQ2vnUcZmEK
         UYCM6sES2GwRQCpYdlMlj2lb/aaZlRYVekxf2OCwpEU5VXEhJLJMnT0/C8eSOctrEXZR
         BSiixAKODKIa9fnuM1Y302VyriPFvysEQYJb4TUpODuYROMzv2ufczVfIhZUjCPJonHp
         nLz/Rw4DK62U6Mn4dYnwteYahNJ8jURbcq7ao3Mt6nGCEfhnhBlRul8a6V6E6GCj8Ryu
         ET3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=11XyMsmg0QL6mr5/lVzDG9L/B+O+THHIQuXNhRVoLpI=;
        b=ZxK4VlJc/hzVUr5ysJ4qN1FeRVaL065Rzq10HP3PwvP66KVHD707NM+mEDuV5b8p5J
         8vIASVO7H3668hl3EL3ZnUMsAnB2XmcLovd40jejh2nBxTEex2tOXvf2BbbD8fXwBEVI
         FYhjsOXAAO7+QnGHcog8GgmUHXddyZKs5NEyLJ6Hu2QRSkvDxPzObbIahPFWej1KH0+t
         yRdqc4sVwPgKmSYqGw5afu4U0GQ9+J8OKLtN/OCkq1LRQVLaDp6idBWl6M2YFy3+Eh/b
         6g2CE29lF6wO7uiZMitfQGmKbNs3mD/SXWrY3Bmae+KxfvHlgaU0+08iCPPklrOAfnr1
         ki+w==
X-Gm-Message-State: AOAM531dgOdIWH0vIVgR4qhYUD/rB9wUtZbuZO186XHnTsZDtVjCmTdq
	G0a0EY3uQns3n71qd8IZco0=
X-Google-Smtp-Source: ABdhPJwdXUw/DEjcWEBrwzMDjXfNcevULwhaGy+ViIwl53J93z/RETuIaarcmhbnUlNziqdbnNZNyg==
X-Received: by 2002:adf:ffce:: with SMTP id x14mr1395182wrs.552.1644279354892;
        Mon, 07 Feb 2022 16:15:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3487:: with SMTP id a7ls328087wmq.2.canary-gmail;
 Mon, 07 Feb 2022 16:15:54 -0800 (PST)
X-Received: by 2002:a05:600c:4ed0:: with SMTP id g16mr1009862wmq.19.1644279354039;
        Mon, 07 Feb 2022 16:15:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644279354; cv=none;
        d=google.com; s=arc-20160816;
        b=JEB7e6Nf1qw/eR7BDbo07SEH0SQYrfaqUUgvzxY43pViJqlHyY/FfBG2hM1YnfTH0r
         cUQweqYLmx1CE0pZR6MrBB5FChjulDkSAKnpip6mmVIEaBw94TbGl6NRSs7rp5/lnjc+
         s2QA58K49x561qXLmjKF4QO2vbG8O7WvsHuQICVhZvPp3cHhwLEREeLNrLUhE4hYEo1Z
         xA3djimN9cWsfn5MP5z/ADGCfZ6lEILGOU/zKDV+QTV8lPCWGDIeSxmu6imMlQmNX894
         MlD0DwXZRcH/RclvIjJOd05U6eMKZElGhuIQ3kBO0prhEBpYmM6klWGVEn4AFcDR35oG
         ao1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KAhtgPEL1/b/o+qskfhoxIg0uA7IhIyD/T0+zZPOZiM=;
        b=m4tzd++JlOjo7YYD1eQ1eB9vazo1lLx2dtaoC/Y0aHF9dI6hUqGRX1+Xehns8EQnSL
         tHCiTBNXu8+x4nhj41bpm4jzyf/zNbW020tAgfrVoissxlRLae1dJ2RN/hMrYfNFNVbO
         YSLuSFGE6rjizwNxKBo6RL1D76x6vltkesjPcYltFT5rQFsoJmI7ud86oYPATKqnFT6G
         3U3mOCJ4RTC6bJG1Klgb5On+aDz3j5RCGXZOs2UHlKeANX1bKN2GNd0z9rMaApsfy07H
         QrajuBM9XgPUgX2un4J+PgPj4xAkakBBcjVGiEjk84axu9yqJX2Bh2LuT8U3hc5oI3Nn
         OXmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rbqKbdD3;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id ay37si39226wmb.2.2022.02.07.16.15.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 16:15:54 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id p24so9317700ejo.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 16:15:54 -0800 (PST)
X-Received: by 2002:a17:906:782:: with SMTP id l2mr1602822ejc.631.1644279353562;
 Mon, 07 Feb 2022 16:15:53 -0800 (PST)
MIME-Version: 1.0
References: <20220207211144.1948690-1-ribalda@chromium.org> <20220207211144.1948690-4-ribalda@chromium.org>
In-Reply-To: <20220207211144.1948690-4-ribalda@chromium.org>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 16:15:42 -0800
Message-ID: <CAGS_qxpjTf=PLxh2ucE23_hW4f2ub10fJ5bbw2Qy_10vWUXrCA@mail.gmail.com>
Subject: Re: [PATCH v3 4/6] kasan: test: Use NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rbqKbdD3;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::62b
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Mon, Feb 7, 2022 at 1:11 PM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Replace PTR_EQ checks with the more idiomatic and specific NULL macros.
>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>

Acked-by: Daniel Latypov <dlatypov@google.com>

> ---
>  lib/test_kasan.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 847cdbefab46..d680f46740b8 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -385,7 +385,7 @@ static void krealloc_uaf(struct kunit *test)
>         kfree(ptr1);
>
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr2 = krealloc(ptr1, size2, GFP_KERNEL));
> -       KUNIT_ASSERT_PTR_EQ(test, (void *)ptr2, NULL);
> +       KUNIT_ASSERT_NULL(test, ptr2);
>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
>  }
>
> --
> 2.35.0.263.gb82422642f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxpjTf%3DPLxh2ucE23_hW4f2ub10fJ5bbw2Qy_10vWUXrCA%40mail.gmail.com.
