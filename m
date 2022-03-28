Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4G5Q2JAMGQE4PB7GFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E4984E96FB
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 14:49:53 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id x6-20020a923006000000b002bea39c3974sf7689931ile.12
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 05:49:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648471792; cv=pass;
        d=google.com; s=arc-20160816;
        b=WKMsp62TsWgWsRlmSfNX+arWGU7hR/X/b0AjcI9UAgL6ovAUFN/sjBnQldFmVmGJ2/
         n2vxhnItdsS4wtE96sJXUA/1fGnz3Zzrrv6OFhZRwTsTyqmXirdQEm8MGxW5jzqjl7KG
         Ck4qOBOjMC8s2X8x9O/DQMX9gFjJ1fsdGMGx4TVYIY+u7PButPlUdeBBv3h1oZ9Yx5/M
         4VSNW901NJuqn30GlEp+z0cpI+A2KptWyd1V9R+60hAnlM+BmhRHqddu+Ps7tnpZNYPU
         5881T1BOnorJ9aRzjI4RL0Bv0m7+CsbT/Vaq1pdJKjY9mbaXDV6xj1HPGVTJC216zG0M
         qK+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=24ECY6NnarUDnotHbpBxxwM4/rsyCm0qZHtOafZqUiY=;
        b=aFeIDp+EakbrJiBCb2NgxecCU7xeDL6IpVro3x755dbyOLtcOa+6B9ZIBeTP48pTbX
         yNyA81WM59V5v20DuxQO/9js/53NNjuoET2pBxx03joAwJxZQZSGBkWu5rWg5NlBgSJ5
         PNIZQAu1FgUVDQ1HilDFNisaNu4udIZ1M7DiaQqooKEE+izGl+lJtmR4omArrHQEEcX4
         Zf5cpLrdvnWqhQ045Pk/aVPg6Jo1S7GAUa4EoAHKMzZYYc0VTd5nE4QtitbCcqu66flZ
         JC/MiWjM5IuAGYKADL1hfgULnZNnW/NpFMc/fqzhf8LtI6UwhnPeaMvTcFHT4o3HeZbA
         bkFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=maVnbV2w;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=24ECY6NnarUDnotHbpBxxwM4/rsyCm0qZHtOafZqUiY=;
        b=lmww1NnFOUZn+zALb/udglmNh9Mcwhm0dW+x5HEwb4HsuhcSOppJKT+xk46vl5bgXF
         M51mwLM71FfXqWBxsjieTueNzSzbQHujWjJEXMffBlxrKKTcXXJgq76fhI1SWONvQIPv
         vL6Koo+cjAsj6dozGZtjC3GaPqqU4vZg8JRbSvinRp5Z2u72KpFp6u3wiVzQGjgpCiaz
         u6hfmYjEyHxuBdECCKA1JgFVNWQYjFSQqJk/r5CQ3bayZQPjYAiNxkzdZwGMm2i5QNqI
         vRlW+EbQ44F7GYW4tNZ/G4pAukJI60W8nL1/9vT5mk64SoSg9peqGbYDlTYYkgW5oiSV
         F09Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=24ECY6NnarUDnotHbpBxxwM4/rsyCm0qZHtOafZqUiY=;
        b=ZQ0iA2iANwEOVgyRi0IuroSBzDnDCcs5mnbBVrsDDyj0YM7A0tnt9RgH7NZQD5Em47
         KTxHq8OVsKQ4t4Mzb91/U8zCCPjq00lSyWPOKgaJNEgxshvYbEwHIXl6TNu+QQyjVT+n
         IIeXFRMCP4w0cNTqX60mvhGNkpJHGFnOfZMzBR68EPYs9+B2Cta0ltR9WFDXm4qP7OGg
         doUavDWJQiRFbrLCri+2aekUKcfpw63eR/Xhrqj3/YsKa8iYrydf/oyPCbnhfoe16HzI
         tZ1tGUr+6moR5CoYUSXuUkpQ0QioLtFFJsMyV4sj92QzcajdGgv3oHZcaM8oAXEWpyzU
         jYxA==
X-Gm-Message-State: AOAM531+pgYRVjrEYjOJpfL3dH2OdVkoqfEE7QsqFtZcyTdtl9dePyky
	VEud66/LJRWoC+TLkqtrcro=
X-Google-Smtp-Source: ABdhPJyQdcBrr32DZQf06nviVs0HCgbioKQIM1h8JZhr0C07W6e8oWoZbogKGhWR/fQfaeU4vjo5MA==
X-Received: by 2002:a6b:f60d:0:b0:645:b224:8d45 with SMTP id n13-20020a6bf60d000000b00645b2248d45mr6265853ioh.131.1648471792448;
        Mon, 28 Mar 2022 05:49:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2647:b0:31a:888d:3294 with SMTP id
 n7-20020a056638264700b0031a888d3294ls2590214jat.11.gmail; Mon, 28 Mar 2022
 05:49:52 -0700 (PDT)
X-Received: by 2002:a05:6638:3e88:b0:321:34f4:8e32 with SMTP id ch8-20020a0566383e8800b0032134f48e32mr12903254jab.56.1648471792027;
        Mon, 28 Mar 2022 05:49:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648471792; cv=none;
        d=google.com; s=arc-20160816;
        b=Ji57xYyecx8QCOUobqjHTyHfpFqLVJlWjTCuKOg/7A0yiPOKwqGTbXtkmQQfSdcUrD
         iieQ2rNF8eBO9P7kEtAnF6VF5+BHYYkS+qrJLKzUvMmfE08r6nZMcxmihApJjGiWZw05
         BDizcTmbVr9f6s7mywAU6Na5c22of4la4/O7ixaLBA60Fw+zQXXNm7neyQvsCPtsYiZZ
         Sd3lnYnA/KNdJN5uFwTZDnv4Wd5lvcQT3KcVM99uckXmO2kbS3n0L86EiAIvnp8nAlW1
         DfWYvy8ymKyeyxR7a9e2tXp627Aluk8qQmxPasn4A/rrZ6XxQl+aTQJlxMHHnOxcxBgD
         quVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KUChceqjpLh79J1JQFAPdmmRt16+9BpF6Er6lqRNHnM=;
        b=kVhbi4TkuwkNYIyGb1QoYePVvR71dK5P2OgaiU01li7uFXcxvkj99F17414ZlVUyRS
         7wckVuUvnw0SAVFv8ENiQ49Ph3uAREqEPp6NZCcoemEa1bOb0BHkIFvwGrbBjK4OUBCU
         Xa1eKU/q8Xmy+bH8/lX1mi2gUE0f864S5NyTzagtXtxeTtYuon+9H5rSqOLBHwg9wvTM
         WyrI55Ids2ej1hiyEaKR39vf3f31SSu3jJvD1b9NA3nMElVZQ8dsZsRxD1nZQYG1rfEt
         9E1rWDxXRELCPa98bvTzbf2G/tKT2em3+UUJB70peYPI6ZBCXZYhCWXz5W1Ieu/Oc8eh
         PiUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=maVnbV2w;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id az20-20020a056638419400b00317af1adf67si898526jab.5.2022.03.28.05.49.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Mar 2022 05:49:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id f38so25815877ybi.3
        for <kasan-dev@googlegroups.com>; Mon, 28 Mar 2022 05:49:51 -0700 (PDT)
X-Received: by 2002:a05:6902:24f:b0:62d:69d:c9fc with SMTP id
 k15-20020a056902024f00b0062d069dc9fcmr21590325ybs.87.1648471791406; Mon, 28
 Mar 2022 05:49:51 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1648049113.git.andreyknvl@google.com> <7027b9b6b0cae2921ff65739582ae499bf61470c.1648049113.git.andreyknvl@google.com>
In-Reply-To: <7027b9b6b0cae2921ff65739582ae499bf61470c.1648049113.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Mar 2022 14:49:15 +0200
Message-ID: <CANpmjNPJkFOMn1pL-=gx+x_YHgg72QH5iqe561+Geiy3JoOg1w@mail.gmail.com>
Subject: Re: [PATCH v2 4/4] kasan: use stack_trace_save_shadow
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Mark Rutland <mark.rutland@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=maVnbV2w;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as
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

On Wed, 23 Mar 2022 at 16:33, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Now that stack_trace_save_shadow() is implemented by arm64, use it
> whenever CONFIG_HAVE_SHADOW_STACKTRACE is enabled. This improves the
> boot time of a defconfig build by ~30% for all KASAN modes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/common.c | 9 ++++++---
>  1 file changed, 6 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index d9079ec11f31..8d9d35c6562b 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -33,10 +33,13 @@
>  depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
>  {
>         unsigned long entries[KASAN_STACK_DEPTH];
> -       unsigned int nr_entries;
> +       unsigned int size;

Why did this variable name change?

> -       nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> -       return __stack_depot_save(entries, nr_entries, flags, can_alloc);
> +       if (IS_ENABLED(CONFIG_HAVE_SHADOW_STACKTRACE))

Would it be more reliable to check the return-code? I.e. do:

  int size;

  size = stack_trace_save_shadow(...)
  if (size < 0)
    size = stack_trace_save(...);

> +               size = stack_trace_save_shadow(entries, ARRAY_SIZE(entries), 0);
> +       else
> +               size = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> +       return __stack_depot_save(entries, size, flags, can_alloc);
>  }
>
>  void kasan_set_track(struct kasan_track *track, gfp_t flags)
> --
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPJkFOMn1pL-%3Dgx%2Bx_YHgg72QH5iqe561%2BGeiy3JoOg1w%40mail.gmail.com.
