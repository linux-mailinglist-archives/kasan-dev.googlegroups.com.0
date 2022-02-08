Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJHTRKIAMGQEMBQNSTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 493804AE109
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 19:42:46 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id 2-20020a251302000000b006118f867dadsf37259211ybt.12
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 10:42:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644345765; cv=pass;
        d=google.com; s=arc-20160816;
        b=CciIyHmTkWOJ/ApTYhCUTAhM3qnlrjmiuzpr5duyXHntxsj80cws1Ldr4Vf475VT5Q
         cOQV5cX2Sfv4cYzvGGDIRCa8ZQ2FD59/4usNCE/IRijU/EhE1mvPY4j99l1dizt/5WN8
         jkjbntt8Gdx1LIOtmZHBz4Z5tkku4vWg4TuMCCM+zv6B3pwldwc+a1rQ9o/Y21QRkwhE
         SJ7wq9NKYTGlqoz3NHpOB9wq1I/gm53TG85UrIb+jJkSvzrbWYbx1Nj2+io/E6GcUGmx
         vSREFosUsODC9g9uwH8qalwppL4n7IQCFt1a4H23540E6aR1KUhnZnKhpbzWitvb+YoJ
         IEgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+gukRB2SGqzW25lbajdLHXmFYJr9EswttflaIJgcqcs=;
        b=aZ19LsXyLn68i/l/CiMpJSbhc5iSAIjVp9Ih2FifxcfHkBdwZPzKDw0CEE3nfR9ckO
         MrHq1qJQSx9J9rl352uxRoaVfN83x8jWZEOhB4J8izDdg4Tdh9IiA4bStroYhGyG0a9z
         fQulm4t7TfWvSAFZOl7q7xgfLCrtvvseAPol6FIOCfx4d6pGrjijkg+iKytgtrSROkxe
         c1Vmui3wzeu97qXJUSpqPPVbz3TNVUNmvEsA4DQAurLHXK7YwKOvkmLB0hyuU/KMtTlz
         5PRmHr3bUPjkZdLqfkYi4thpqXBnxZwkGrUwGJ8QELSDOdoA7KfZBK0/DXLazWsHznf6
         t1Zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gaYYFlmO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+gukRB2SGqzW25lbajdLHXmFYJr9EswttflaIJgcqcs=;
        b=b9XLbTXhMkJBNhMQdqFhJEhtqx9TIwjD/4FQamt25CUslvImMZaqYOVmKk5x6y2oJe
         cZWXcETblvo50FuIKI0g2iNXnrLkFK2ICt3q/b7epIlKW4V7pDS9lNA8nlj8OdlAM+/n
         cfAbQ7pbHH2UjEq59/Ij6k5HBiU30Nnr6GJoiQLCK05+gWm3OZw5xUIJjc1xOWFROn2/
         ZAEnTi9ufKPc/BmyBSGJdbGGl7iaFlrTgWIFx20Pld8Mp+Ulr3MAuJZ+tVUGEk3nOhE9
         /aCf39KcDQRfeQSQW+1w+qZ+TreRWCrdsmJDjr7oT2g4+HN1tJYcyV/osWE4aLymbWQo
         9vPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+gukRB2SGqzW25lbajdLHXmFYJr9EswttflaIJgcqcs=;
        b=z4gkyVeE4ghSJgeDMfq2qns+xfMzDbwJ4UtIwMkhtN0n3uz5GxLAFwgLmBEXM8R8tQ
         WuXVGbc6cCPcQfngXE4ym+CZb6mQ0/dnuqx1KoAfk6aFZOMG6lu9saMK2o3wacMvLzIO
         +qrA2gVHxQQxbUpF2o3o2rY1j0ZCt+61Jirk3cn6Uz5B8NSxWsgMilmvXl699WtKPMQs
         /hrxgKmn620zUZ2bHLRzPvYbJ8+jymCTqpK+DJWDNZAYgKGNp1V+WqfkvbgHPfW4Cn3b
         V9cIn2FHq04CKzBNTx9vHVnVGowPjAV9mgcHhSArVg1M7jh+3bThO9mCdkgxk3cpXY3L
         9cyQ==
X-Gm-Message-State: AOAM531MWJmmDMA3bZnvYxag036xjBuvRUjJWzTi2K7u7L3YbtAUtpyW
	WtCj8WAfFomwaK42pPVmwZs=
X-Google-Smtp-Source: ABdhPJyOVSaBu1Jucjf8WBcOH3aJyLCPSbc/7+Cz+BkaxEXZ5JPsUzLp2C809sza+nDtdtnEvcGvqg==
X-Received: by 2002:a0d:f903:: with SMTP id j3mr6074597ywf.118.1644345765113;
        Tue, 08 Feb 2022 10:42:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:2e46:: with SMTP id u67ls4702512ywu.10.gmail; Tue, 08
 Feb 2022 10:42:44 -0800 (PST)
X-Received: by 2002:a81:e50e:: with SMTP id s14mr6070571ywl.177.1644345764616;
        Tue, 08 Feb 2022 10:42:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644345764; cv=none;
        d=google.com; s=arc-20160816;
        b=qXJ4ParHO58mJe4CzzF3xDvenkN+5v2mpsPM5kmtlkFzhvSbO38XUdGIbayJyD/wtb
         x6nuGXZjn5U6JJorhqL7vDGL+r2JHsDpzudqy1rHOpBPUpUdTtZD3r9dFtO6KZAv4HFF
         wfkP5XTtBTqxqqt89Otqk1dI+Reh9jN/QP2qsmllCZrhTSTAUFGvCv1XiSsx+wX0Ryqb
         gpdJ7NJWcXFfsUiRlY01iYjXxnzcc9bxbXswYKDik/4f/L+LVwU7z3UkjtngQR23hDLe
         Zl1AgnCopr22VLHRmHyUUfzP37erWqfwJWwfU9oRdHYk5r88ofk34Sc5e3pA5Kx8xTN7
         oAxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/wpZic7Pvz+TsDyuU6lHPsRfMMkUmLxvHW1ooX7tgs4=;
        b=bM8HbZrTCy6YtE+IaHStBgMg2i1OVrvBhyAHpSQZy3u9LzwtHthCy8cupyfhgTRej+
         6AQy2z4uSvCSZsmJUuLWZ3LEoCK4HDQhHlYYR9HYiRihz+uKIYb5H2NxIjRtwMScGn+c
         DV1gX5yHLjclXNY5exWxREbP7ODsbOXhD82HkqMjme7SZIkaUJoQ+x1NYPBE2TvNeLD+
         hJU5eWg5oX9z9TPWzrVAWhU+l+P7Wt+ueSVGGHGHkqLtqZwSgsFIr+YrtmNgWuSmi2QP
         V5a8xgnzHvi3jTt8WRGhKYcvUsmyVxlCSH0NNfuRpxZiMxZaMfKlxLXbLQBoEhDjNfYJ
         X+Hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gaYYFlmO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id bc25si156744ywb.3.2022.02.08.10.42.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 10:42:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id m6so52445425ybc.9
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 10:42:44 -0800 (PST)
X-Received: by 2002:a81:4741:: with SMTP id u62mr6495415ywa.512.1644345764183;
 Tue, 08 Feb 2022 10:42:44 -0800 (PST)
MIME-Version: 1.0
References: <748bd5e0bad5266a4cac52ff25232bbc314b24f5.1644345308.git.andreyknvl@google.com>
In-Reply-To: <748bd5e0bad5266a4cac52ff25232bbc314b24f5.1644345308.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Feb 2022 19:42:31 +0100
Message-ID: <CANpmjNOhrPie9aWGdBeTke6yz-o+MV+G5moKB=eb9EN8Ky+f1Q@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: prevent cache merging in kmem_cache_double_destroy
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gaYYFlmO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as
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

On Tue, 8 Feb 2022 at 19:37, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> With HW_TAGS KASAN and kasan.stacktrace=off, the cache created in the
> kmem_cache_double_destroy() test might get merged with an existing one.
> Thus, the first kmem_cache_destroy() call won't actually destroy it
> but will only descrease the refcount. This causes the test to fail.

s/descrease/decrease/

> Provide an empty contructor for the created cache to prevent the cache

s/contructor/constructor/

> from getting merged.
>
> Fixes: f98f966cd750 ("kasan: test: add test case for double-kmem_cache_destroy()")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  lib/test_kasan.c | 5 ++++-
>  1 file changed, 4 insertions(+), 1 deletion(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 26a5c9007653..3b413f8c8a71 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -869,11 +869,14 @@ static void kmem_cache_invalid_free(struct kunit *test)
>         kmem_cache_destroy(cache);
>  }
>
> +static void empty_cache_ctor(void *object) { }
> +
>  static void kmem_cache_double_destroy(struct kunit *test)
>  {
>         struct kmem_cache *cache;
>
> -       cache = kmem_cache_create("test_cache", 200, 0, 0, NULL);
> +       /* Provide a constructor to prevent cache merging. */
> +       cache = kmem_cache_create("test_cache", 200, 0, 0, empty_cache_ctor);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
>         kmem_cache_destroy(cache);
>         KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_destroy(cache));
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOhrPie9aWGdBeTke6yz-o%2BMV%2BG5moKB%3Deb9EN8Ky%2Bf1Q%40mail.gmail.com.
