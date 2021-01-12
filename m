Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAFL6X7QKGQE2CMQ6CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id E92632F293D
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 08:53:37 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id m7sf1041299pjr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 23:53:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610438016; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z19rCUDdyfiAPLfZrRwtqGZkEttDyoNGBsK+1IicUGiahqkj8/JLyEp019vQqi2wy5
         PtiivwtNfh9KMLPif+RQ5o0cyoMV0g9FqcroIDwPMpues1tXCheIGS19CG/eKAtIRQGM
         GR36jzlm0fdbOj7+zwTM2kPc1mDhR78S1eMH0f7ADYV5t/66gXrU6ICqN8I48cLmUb5A
         hgNJ45aNJsnjAa1eI9fghDnYiaqdTZMm9Q+o4oxOaH8lCKdv1gnyP69KR4AWGwF48lY4
         2a48f+pD7L4jbuw2gTMabv0x0LSxGL9cwlE3+4qogTHrvxe/d/Ls4TpkvpHVgUzjn9hL
         yLdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Xp73G8KFS2cytXMcraS5f7ug/Y+DpcV6zzBQ0f9TfCk=;
        b=nSOYUj76L6h90PsnyjyPA/V7McLu0w1sWQH1MwLsDVbp6nKbu9iZE3U75hjLuTyfIn
         FbM5mvPgoQGTpWOErmyL/uSFfvCAxoPaC9LuYuoBZU8SWGj1pzDu4LWvn7UnJ9cSLTqX
         zdamM4+Q2RnZv6OSNQqDAl3TP8cWkJBNUp5M4CQW31OnGSEu3LJRMmb4S8vXJy4zpNqh
         Tn0fgyzoxJ9XYAGEkDU1fGx/3PBeUjkWAOD7oAJX8FPYJSZWwog5JAijnYtyXPxugQa3
         fe9egzJLcgBQSNA8xTgRka8VqcjhU2Ul5gdocWvwIi+2ntuOwt5oOwBt6f6z2+RXM7aU
         zlrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VcB+5Bvj;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xp73G8KFS2cytXMcraS5f7ug/Y+DpcV6zzBQ0f9TfCk=;
        b=HFWsU13kFa1bQ5Hz9slcOpLRDC79WsUg+666HIdde5xT88Ga35Ce0vuYrpZDdkWYGZ
         mnQUQ2hC04Dfap/sr1o3glk0tKg0xFeWkzAAIvLis0LhmQuIty+CjjdanxsBuU/rfabv
         rJ9ZE+1CVXoftOIC+yIFUKxhHTsNOse6iguWI079MC4IwcS3TxThjLQVWCIRD6j8EfIZ
         qecNjKhSwDL/HW1XV1OCk5rZ+KlbwcI/qVBoJDqMuOd1M6ASUsNuqqxse5AdUC44S+Mf
         UaVqPGLOLASFA8JnPpR7fOPVe9NxH/iNYy+Y99146pvHrfz7cH7R1C/6QwEcWnjltuqY
         17Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xp73G8KFS2cytXMcraS5f7ug/Y+DpcV6zzBQ0f9TfCk=;
        b=L2mFiqWgbEKHbe1/ziv6aSYv2y8EPDzmXZ9G7h/xEZpamhZ5eByrznUYUVatGWJHRL
         Y8m3pbVjV8adpDCRiZNZ/MRjDkTchpksfAF3EJVSOjHj9D32TukZdVsyHDuN+4qtpQXg
         BK0a4KTUBcRlt9wGCNCw1j45iJ9bZ7+eAmsSmSqp7iUtW4R1H9TXtg6TY+mYxlCI7Mp1
         hkdHn3XqcMNrswTOXvlG7uBI9JCg7uHUCjK9XQljsrBbY4aMPZ+Z5XgY1T8NcOW/qXaH
         TghWtgrDSzKgS2X2SHPDYWBlL17EQ3FaGuc6VSy8qRAVIA0YuXHAouWDoLWAQEm8XdgA
         4PTg==
X-Gm-Message-State: AOAM531aeyhpdpI3EwuczjGe17fa0IdpgGp0c5jGdaEk/4nzVhoTBJKG
	DyOxOvaTzkiTP1GW4UfYuXQ=
X-Google-Smtp-Source: ABdhPJyZnGbrKYnYJhPgiNGMO1QkKqghoWho66UKfbRPkKDVzg1FyFbrtt8QsGTH5NfPKpuqyP0vng==
X-Received: by 2002:a17:90b:50e:: with SMTP id r14mr3268345pjz.90.1610438016411;
        Mon, 11 Jan 2021 23:53:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7d97:: with SMTP id y145ls894621pfc.10.gmail; Mon, 11
 Jan 2021 23:53:35 -0800 (PST)
X-Received: by 2002:a62:774e:0:b029:1ae:8101:6360 with SMTP id s75-20020a62774e0000b02901ae81016360mr3435427pfc.31.1610438015842;
        Mon, 11 Jan 2021 23:53:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610438015; cv=none;
        d=google.com; s=arc-20160816;
        b=mVos3PxfKF3EnePLxdJtvSTsuG7GISXRfO2eSp46HsJGpM54+uHSYPo9JmMKb1ddoi
         Pi5mZBgDE3ikVoGvuCrfeRaKUzxMpdn6WiugfcKtjcPNG3U5FSo9NjO+cg3sNjNKy6IO
         aie3n46VTWy4gqdtNRjqlVJGADA60SIhSLT01shDNjuXLLG0EWnId8MLztGRsaS8MnbA
         h8vmonZGQqlKmqbNYw6RG9hp7P42IP9oihmJCpr2Di/Y1qnRIf3VXh31LNkvN2EluXxv
         +Nfq2qrKJuo0Y+IOsP+IjtIMb2I7OF1uhy7TdLvOQiXxIK0cwDarNUJEVyaTkc7Jswe4
         4hvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mGCAtyq15j5iLbAyhIjgwA3t0EKUEm8gTtrvCf4O7jE=;
        b=kQ0hXFasiWGcaNDuexJaRURwkYjIOMIX+wRZkFaAF2wSUKfaHGZR12+Lqw55X4n6cf
         IQXk70n2dKUqbguclWJ77B6FLaoTPKXTC5QRq725naSu+MAPce8JiN6BUjlUErOkKyII
         Fr4O2NaZQT8PUUTBEPEkT+v09rZZ4Q+Lm9qglo+QZJhmz75f+U7ahS354K/CcWXBI5Os
         9zgGP6NbuMZBIwAw88xB6C/c6C1yUpiSsdZzJAuEmgMIXXW+wapo7ahdgTbwnbiPFKbs
         ZzhYmzQNuLlnZs1j3t7d9evVjNJ9giZbv2yx6X3g8TQD2zkGudrlroxI5Cwu1C4yGSaC
         dxXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VcB+5Bvj;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id b18si154622pls.1.2021.01.11.23.53.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 23:53:35 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id 143so1118445qke.10
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 23:53:35 -0800 (PST)
X-Received: by 2002:a37:a747:: with SMTP id q68mr3233844qke.352.1610438014849;
 Mon, 11 Jan 2021 23:53:34 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <cb4e610c6584251aa2397b56c46e278da0050a25.1609871239.git.andreyknvl@google.com>
In-Reply-To: <cb4e610c6584251aa2397b56c46e278da0050a25.1609871239.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 08:53:22 +0100
Message-ID: <CAG_fn=VDPR2bkHA_CeDP-m8vwr3rTH+3-qwMNHNUQA2g6VghKA@mail.gmail.com>
Subject: Re: [PATCH 03/11] kasan: clean up comments in tests
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VcB+5Bvj;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Clarify and update comments and info messages in KASAN tests.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I6c816c51fa1e0eb7aa3dead6bda1f339d2af46c8


>  void *kasan_ptr_result;
>  int kasan_int_result;
Shouldn't these two variables be static, by the way?
>
> @@ -39,14 +38,13 @@ static struct kunit_resource resource;
>  static struct kunit_kasan_expectation fail_data;
>  static bool multishot;
>
> +/*
> + * Temporarily enable multi-shot mode. Otherwise, KASAN would only report the
> + * first detected bug and panic the kernel if panic_on_warn is enabled.
> + */

YMMV, but I think this comment was at its place already.

>  static int kasan_test_init(struct kunit *test)
>  {
> -       /*
> -        * Temporarily enable multi-shot mode and set panic_on_warn=0.
> -        * Otherwise, we'd only get a report for the first case.
> -        */
>         multishot = kasan_save_enable_multi_shot();

Unrelated to this change, but have you considered storing
test-specific data in test->priv instead of globals?

>         if (!IS_ENABLED(CONFIG_SLUB)) {
> -               kunit_info(test, "CONFIG_SLUB is not enabled.");
> +               kunit_info(test, "skipping, CONFIG_SLUB required");
>                 return;
>         }

You may want to introduce a macro that takes a config name and prints
the warning/returns if it's not enabled.

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVDPR2bkHA_CeDP-m8vwr3rTH%2B3-qwMNHNUQA2g6VghKA%40mail.gmail.com.
