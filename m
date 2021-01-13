Return-Path: <kasan-dev+bncBC7OBJGL2MHBB46D7T7QKGQERV4LFCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7516E2F5022
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:38:12 +0100 (CET)
Received: by mail-vs1-xe3f.google.com with SMTP id a11sf427879vsr.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:38:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610555891; cv=pass;
        d=google.com; s=arc-20160816;
        b=PRcfCI7eEJ2U/RCvSKq2gvaGcBwZOPgv5nlctXCENFrMxDgE1APkJLyFCRI7iQIghZ
         Ry197dYzRfdb3tM2c42LTGyA7gcWmTvGdSHPdSMVZMSovQPtUK6v+yOtKhdAq65GRzlc
         aQnibyY6tNN0Q3VHxQbV9zIy/1236hzB2YIVKJ7CDWAXzO0mRPWH2O8sMtvhTRyW9fF1
         ZAF+QtIoy3xJIUM1b8nuyTPjZDg7fcSB/LsxOiJy1aKuOTs5aJnP6kNREfBG/J2SVo3C
         sWaKWSyosD1207B3oDecDDqZImlWtSq4jc9URcNJQUGQNoUPVszhCaOpS51e1Ikeb+bb
         3aEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8+f38tvOm90pDlX4GYk3S1OHRwz1oZ4+k2iF//G3hFE=;
        b=bAuDhB5DuTJrHFWUvC4xYyFiAWkDE5MQsMDrS92tsc27y0eDg1gqYgpRRz/D6a3NhK
         oDa3T4OmEFOCeMIQ10WPv8RJx7Y1Kna1/pd35MibN435BqchVyeLsjiii+H8qMI+SjUL
         0WhNzeLGDuaJ45JBlOk1lPFVFPfMycW81+Xv6LpbnjlKehishif23/eJ7hBXN3b3lQX7
         UgI/wjCDkM6a6z5R9XXWoRmG7NIPAG02e6cTxqTY9pA3Fm1jSKeim1wxDKDdzPdMZg+a
         EG3jm8JIjq2v9WZGS1/mcERjfdXdPQAszbXtSh/sc87cC7KkMcrYhKJUXkycq0QlCv46
         QS6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ezx3nAz4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8+f38tvOm90pDlX4GYk3S1OHRwz1oZ4+k2iF//G3hFE=;
        b=Ug1l9NEY9VHMJJZ6lkDUXq8VR3Sz4t1DJtA3Vr29kT5QclzAwhRDfzZf2SLHW+VRla
         REEMIegRhew4DnrZYc1ndo2f3VwFL3Sr5wYU8caxKrOSo8amJ9EJqc6D/DXtrV8RB9+4
         5PXLNYfXmRSd8slWE2aCCfi77DCTJljHayGhbWGqGyPZLiJipF0Nroy3/KSY2/rEci5b
         VjabCgpiKOIXOHgjRznvGEj9evDFaQEE6YIU3ygfQV+fFXlYpJzldq8YBkR4bbM8dPn1
         yG/FPdHYFb1rudgKaArBvl6Z63wjIKBxP2WMudys+Sts0cr5nuWZdHsxiTHw4LvuQZ8L
         ufLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8+f38tvOm90pDlX4GYk3S1OHRwz1oZ4+k2iF//G3hFE=;
        b=XqMsJSa2Vi03i6frtrdfHaLO8XFG4qc88Ey0Kt0yr52DnXT6/Waj7F+kInaGImo3hH
         1WTF9/bXO8MGsfbkPuCL9sLmXfaJ5poZIScxQwQuUVhdqgxMlQPK7xari/MTIEDQWfD9
         gUoIx8CKaZcAv6GAV59u289uqti+71+ab0sqH99nh2WWC3OxzUNgUt0IaKN1pAma6lG4
         Mat/Z4PnRDbRmeudgqHeWoM6oSMLpevwcI/PsnR6iClhRvsXOhH0GMO0nnb9lMwQZ0QL
         APHIOivgSPdC/DRad7W6xgg4h3UtLyht12RGplJaEaBAKGs1eaMbOCsSR0TnYqlK8GBt
         uwCw==
X-Gm-Message-State: AOAM530z0ElCSYKzbTDK6x9/dWeVMXsjOu2h2b/sfqzSOlWcTAjUdFVH
	BoBTRCPxqjqttjEXLpw59PQ=
X-Google-Smtp-Source: ABdhPJwXSFRlAzLM04bvkZEORPrg7/ZR+lpn+OwxseD0cPwuIZRYmcoWR+jMuwDc26CgWpirhBQw3Q==
X-Received: by 2002:ab0:3b59:: with SMTP id o25mr2890897uaw.62.1610555891566;
        Wed, 13 Jan 2021 08:38:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f9cb:: with SMTP id c11ls323816vsq.1.gmail; Wed, 13 Jan
 2021 08:38:11 -0800 (PST)
X-Received: by 2002:a05:6102:2334:: with SMTP id b20mr2916419vsa.51.1610555890950;
        Wed, 13 Jan 2021 08:38:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610555890; cv=none;
        d=google.com; s=arc-20160816;
        b=j747GZjXhdTi7ZiQ7emWqk+uwnr1rEZ44JNSHO9bGgolBll/C/bRsAznZUKCWfdmcz
         eOhJv7tZpzK+LXeLcUdgz1Lic390qJvHnNw+lcuYow/VVgBwZocpE72mj2ulV3+D3ILL
         4JuW1ciTCzblr4k07ojlBXGYjMYVweSLdwOlAiiRJAYmpcBWEjSSyJaOcpew64VfCYpc
         OD0fTv1Ru2Q4uBMYeDidV/CMsF8Npvps6odL3tBU602Wvkos57Lmk4V83p03M1Ykozib
         KQJwKh/KsvzG7IqY1TnSn+0UHhIGOJhocIqAcsnfEKkEwaTEvqUxOfDl47L+WrdskGhW
         64pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oHd/Kicf/hoH6eKoo5AC7GFnFGH61vMiUslEm8Z70PU=;
        b=VYn5E1SHB/nDbjNjH1SAZOAY33vsFhrcD85V8kz8y15ZabohA2Ra/Mav+6tQqGBw8Y
         QBL3dVg69Dny216dc+9eNo67ln83VyY6AfuFwrMPeu6lYYD8dkreuRc54FoURUX1xidx
         z8pRL2kbTDNLS3U2sIoZI8vrjCNt7/epII3ChWACq2h9VaXzF0+GkR5aSohNtZ+a7B+F
         anrhDXPMpVm2xS0XVK0AQFGze8sW4kwHLtTuyvTku8mzjOtK7eSB8eZp+UqOKH6olZZJ
         19vQMmLOh7XNUyGKYNBUg3oesgPmxf8mL1ZhubhzPfkMkgY+GtQXkiGy5+D9uG/zVzRH
         NFWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ezx3nAz4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id g3si164293vkl.1.2021.01.13.08.38.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:38:10 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id b24so2495231otj.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:38:10 -0800 (PST)
X-Received: by 2002:a05:6830:2413:: with SMTP id j19mr1858158ots.251.1610555890417;
 Wed, 13 Jan 2021 08:38:10 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <0e994d67a05cbf23b3c6186a862b5d22cad2ca7b.1610554432.git.andreyknvl@google.com>
In-Reply-To: <0e994d67a05cbf23b3c6186a862b5d22cad2ca7b.1610554432.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 17:37:58 +0100
Message-ID: <CANpmjNN5t0-dEHJUqKbT8eRQcj2epdiR5xbUkp=JR-Ka7jLM4A@mail.gmail.com>
Subject: Re: [PATCH v2 13/14] kasan: add a test for kmem_cache_alloc/free_bulk
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ezx3nAz4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Wed, 13 Jan 2021 at 17:22, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Add a test for kmem_cache_alloc/free_bulk to make sure there are now
> false-positives when these functions are used.

s/now/no/ (but by itself doesn't necessarily demand a v3)

> Link: https://linux-review.googlesource.com/id/I2a8bf797aecf81baeac61380c567308f319e263d
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/test_kasan.c | 39 ++++++++++++++++++++++++++++++++++-----
>  1 file changed, 34 insertions(+), 5 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 5e3d054e5b8c..d9f9a93922d5 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -479,10 +479,11 @@ static void kmem_cache_oob(struct kunit *test)
>  {
>         char *p;
>         size_t size = 200;
> -       struct kmem_cache *cache = kmem_cache_create("test_cache",
> -                                               size, 0,
> -                                               0, NULL);
> +       struct kmem_cache *cache;
> +
> +       cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> +
>         p = kmem_cache_alloc(cache, GFP_KERNEL);
>         if (!p) {
>                 kunit_err(test, "Allocation failed: %s\n", __func__);
> @@ -491,11 +492,12 @@ static void kmem_cache_oob(struct kunit *test)
>         }
>
>         KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
> +
>         kmem_cache_free(cache, p);
>         kmem_cache_destroy(cache);
>  }
>
> -static void memcg_accounted_kmem_cache(struct kunit *test)
> +static void kmem_cache_accounted(struct kunit *test)
>  {
>         int i;
>         char *p;
> @@ -522,6 +524,32 @@ static void memcg_accounted_kmem_cache(struct kunit *test)
>         kmem_cache_destroy(cache);
>  }
>
> +static void kmem_cache_bulk(struct kunit *test)
> +{
> +       struct kmem_cache *cache;
> +       size_t size = 200;
> +       size_t p_size = 10;

s/p_size/ARRAY_SIZE(p)/
?

> +       char *p[10];
> +       bool ret;
> +       int i;
> +
> +       cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> +
> +       ret = kmem_cache_alloc_bulk(cache, GFP_KERNEL, p_size, (void **)&p);
> +       if (!ret) {
> +               kunit_err(test, "Allocation failed: %s\n", __func__);
> +               kmem_cache_destroy(cache);
> +               return;
> +       }
> +
> +       for (i = 0; i < p_size; i++)
> +               p[i][0] = p[i][size - 1] = 42;
> +
> +       kmem_cache_free_bulk(cache, p_size, (void **)&p);
> +       kmem_cache_destroy(cache);
> +}
> +
>  static char global_array[10];
>
>  static void kasan_global_oob(struct kunit *test)
> @@ -961,7 +989,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(kfree_via_page),
>         KUNIT_CASE(kfree_via_phys),
>         KUNIT_CASE(kmem_cache_oob),
> -       KUNIT_CASE(memcg_accounted_kmem_cache),
> +       KUNIT_CASE(kmem_cache_accounted),
> +       KUNIT_CASE(kmem_cache_bulk),
>         KUNIT_CASE(kasan_global_oob),
>         KUNIT_CASE(kasan_stack_oob),
>         KUNIT_CASE(kasan_alloca_oob_left),
> --
> 2.30.0.284.gd98b1dd5eaa7-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN5t0-dEHJUqKbT8eRQcj2epdiR5xbUkp%3DJR-Ka7jLM4A%40mail.gmail.com.
