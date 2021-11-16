Return-Path: <kasan-dev+bncBDW2JDUY5AORBYHXZ2GAMGQE4WRZ5SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id B56454533BA
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 15:10:41 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id x14-20020a627c0e000000b0049473df362dsf11839760pfc.12
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 06:10:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637071840; cv=pass;
        d=google.com; s=arc-20160816;
        b=KoeZGEYS47CnjvlRCcD83jWqnSeXAxq2noXRRTSh9n4nrx+ld8f6UmP8XFx7P5yxgM
         nJ8rFp3RsFuUIL8+fpTX6uM7jtKlJppSMYRkDvZOs2/DKXZpEjt3zb1rfXKqOma17Bp2
         i86/s8M0r5vIgCN7rUqQhkZ9LhntX2/obKDeMLjG4kpahpFt9qHJE1RhNjFLzK+HNJ30
         ROFTKoDLAuyzEebFlVfKXRzuoVgOmZa0AQY43E6GCX3JmW0d/rUZh4iR4bjB7t/IF72E
         npUy9qpYcUgQL2A25J06j+NlXjxGM/UM2PMR2m0UQY7MU8mJyaJy96xJ5ZkmsZM9oKXr
         MhOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=pC9CvFwiuekBJhClsAdYYbkJDjYRtV7GLS1i0UbfpXo=;
        b=hS3XIH3RHP9wRKLklLGWKV3VClTbMTJ4CGuMN9/i1Qd8httUCjg2RdMNGO8Ie+DM06
         m568KDdupxE1viTCU7+y4c23wR86bpm30EJAV9jG3AweSZBeOsg+PBfS0pBpiXuC/+7c
         S/zZrvwyQ5QXIrRsegHnM7pU4tmkfnMBQILW/fkgK65R8VL0L5r2tyX+d9aETrYqgS/j
         IoL0X1keEkfP0A2x2fJMW5TndYuTI1kNUEwPYsQv9FAjb1IW2OVfNVoL3bUkbCSCtvYU
         x0o5MR527n66UMgLop3A7YvwjWXfuyaKiySFpQzYWojaCGk7Gv0BpUMRHisms1HouMgB
         E7kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=o5UmTOXK;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pC9CvFwiuekBJhClsAdYYbkJDjYRtV7GLS1i0UbfpXo=;
        b=cJRrJul5uJAVRpcrmyELUK7CmvigdH1jaR8hw0BX5Ply6pM7sIlIs9uDVrHOVuFQUz
         F/tYkxm98wHGzsThaZZqWMHMlwR+veS+oIoQVHDT/xGSuFgs4voiNCnrS6NpdsmFB9GR
         hE6UNQBDggVqYcTt7Ot3j+sob5ePoJZEVK8r0p9prThc4cbekGeTTv3iC7+5a+oK8rHu
         ZIbPPSK3I62E8yp6UbQdFo/nLLF7uZ0pcp+W0tNSAAdTGeHSt4Xqj9cgk+dZbLuW3ubm
         T9gVomnpzlAKnV87qdzyP1QeXpHgal6/aTZoHiICwZrpxfuN9Qx0ByvlEnf2/3krdncc
         fRog==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pC9CvFwiuekBJhClsAdYYbkJDjYRtV7GLS1i0UbfpXo=;
        b=T/6pFU+dtZvYOfLsntvUVqG3wbOwfHVGpPvIaasGaF6pTFZG5krri0VXfKQX2qvRWc
         Y0Plw0gmJaFasDqdFIY8qUV7oygArtTGldhzNmtvvxR3HrgAH84G/pRsmDy+6XBTM3Pc
         zhUwiaTUIZjXGpgTl1wOL5UIk941YqechqWzo32lcwUfjrB1d9zntOvkH+kvdcuTUf7/
         AXiZ5cU1dYwbOAk4rLUdJitjd0e9qFI1ls9mbkugJMEQ2FCiSDwoxxArwCXHIRAzTVvP
         ksQhivF+I1PZuRxKKfOwvLM4eJJXKyiS1hj5DD0DPae/1/FVPth1GLNnSVhZCCG42HJj
         Pj2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pC9CvFwiuekBJhClsAdYYbkJDjYRtV7GLS1i0UbfpXo=;
        b=Uvg0CW2SMY3ww2llzoTCg5MBgbJaH9x7U0ZxWU0pgnSlSgiXGFBgktuxu+obb04eoT
         AUvpjGHl5MPpGbVZbUSRJFXl43nlM5/C0OZlX5ZJ8ooG8wmfKKdZfi+nKjW0jaY5UwNo
         tcjEBwvBFJdhLecZT8xD1BxcauH1Wx8iujikC2CwbaODe0QAo+7eRruSI+ea1CpxN0Rq
         8hx6roMvyRdC3WNjY/9EFKsM2PMy6BRWzb6TaUAelmaqQgXJ3o4d7jqrcWx8/HqIe3JW
         esV9fYL5wnl2BRvFTRQAvx1xvRbQ0IzTFcks6Mj0hM3YFXKxmA2/YkZWS4/ZgKfsfAum
         o3jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531abjmUAbV3tJCOI0cFyjoc8mhNpL4SvPjJhIHnBPQzu2OrN4aP
	MsthkWeaLjTAunUzBu3qS6w=
X-Google-Smtp-Source: ABdhPJzdaxcp2McvgNC04HhKhTgao6yo69JhX03496DYPM8rYkwDUzxrC7WUT4PWHQqiXgyQnoagJw==
X-Received: by 2002:a63:725e:: with SMTP id c30mr1057733pgn.240.1637071840396;
        Tue, 16 Nov 2021 06:10:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:da8c:: with SMTP id j12ls11374230plx.4.gmail; Tue,
 16 Nov 2021 06:10:39 -0800 (PST)
X-Received: by 2002:a17:90b:1bca:: with SMTP id oa10mr9451181pjb.20.1637071839565;
        Tue, 16 Nov 2021 06:10:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637071839; cv=none;
        d=google.com; s=arc-20160816;
        b=atbdgS6wKfz8GLEbaVVeUYyuiCPUthzuJehydyPPTQvtDdxTVknl/8DsUsWSjMbm/c
         YVV/bNKq/SFLLJjfAYDEm/TA3jduyOi1jlxeg3lvCiefF+Wa1eBV7IQ6jz3vz6zK4C3z
         ae9E/crlWgIFwyRapCvbTK15Yn8xB3DxDpQ1WY/zcMNJnPfXNRtAnZrFbHvTvzRxQcE6
         ZRgDTxD4USIfgKSNYtmpSFGK1yhG/bCCUIVAhA7afbNUbvRD0BrdGxb2qIdyqFIq/j55
         0UJbp8N67TmMOpt0dkkp2tB2Nyy3etEnbTqeh6TFSveVlLWxC7DTJyhfzOrYW+Qd8J2N
         8X8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M/UEt3LXFYRGol9LnZjoBsvjbD91zGyozW9PiMcjgf0=;
        b=WI+Y9FKaGF+eVeii1nu9UewD5WPa018d6TMSSPUlUE9tOzs6pB/skZ6X89l7YLcTBs
         GJFbLy1lI9UCJBNaHAVsKAo39woyaKVauvZw821sE0sxQMY1xpZ+KTFAgDlNFuinObif
         BC1sA9/nKxrEkWfqjqFLB9GhXbKd+Lp1G3S4OjDPBwdwewbsYQ7ybg9dc7tiJPQeoKnk
         N+DR9KshwPcKgGEJU3555S67W50dHQpQLWpNkL4OJzz/+HJatlOGY6f3CVGrA/+xtT57
         c5binBkDAMPPw+SIiP7xqX3ol2RdvDpbO0YGtLM8wBWXnkPhNtRPUb4KkdVo9byQKPVU
         vMVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=o5UmTOXK;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12f.google.com (mail-il1-x12f.google.com. [2607:f8b0:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id ls15si765491pjb.1.2021.11.16.06.10.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 06:10:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) client-ip=2607:f8b0:4864:20::12f;
Received: by mail-il1-x12f.google.com with SMTP id x9so20471336ilu.6
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 06:10:39 -0800 (PST)
X-Received: by 2002:a05:6e02:15c9:: with SMTP id q9mr4825161ilu.28.1637071839309;
 Tue, 16 Nov 2021 06:10:39 -0800 (PST)
MIME-Version: 1.0
References: <20211116004111.3171781-1-keescook@chromium.org>
In-Reply-To: <20211116004111.3171781-1-keescook@chromium.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 16 Nov 2021 15:10:28 +0100
Message-ID: <CA+fCnZcZ0eCPEjaLoQWc5a7pVHDKzYLL9ZbOQXv4wE5qA1NwoQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: Silence intentional read overflow warnings
To: Kees Cook <keescook@chromium.org>
Cc: Marco Elver <elver@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=o5UmTOXK;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f
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

On Tue, Nov 16, 2021 at 1:41 AM Kees Cook <keescook@chromium.org> wrote:
>
> As done in commit d73dad4eb5ad ("kasan: test: bypass __alloc_size checks")
> for __write_overflow warnings, also silence some more cases that trip
> the __read_overflow warnings seen in 5.16-rc1[1]:
>
> In file included from /kisskb/src/include/linux/string.h:253,
>                  from /kisskb/src/include/linux/bitmap.h:10,
>                  from /kisskb/src/include/linux/cpumask.h:12,
>                  from /kisskb/src/include/linux/mm_types_task.h:14,
>                  from /kisskb/src/include/linux/mm_types.h:5,
>                  from /kisskb/src/include/linux/page-flags.h:13,
>                  from /kisskb/src/arch/arm64/include/asm/mte.h:14,
>                  from /kisskb/src/arch/arm64/include/asm/pgtable.h:12,
>                  from /kisskb/src/include/linux/pgtable.h:6,
>                  from /kisskb/src/include/linux/kasan.h:29,
>                  from /kisskb/src/lib/test_kasan.c:10:
> In function 'memcmp',
>     inlined from 'kasan_memcmp' at /kisskb/src/lib/test_kasan.c:897:2:
> /kisskb/src/include/linux/fortify-string.h:263:25: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
>   263 |                         __read_overflow();
>       |                         ^~~~~~~~~~~~~~~~~
> In function 'memchr',
>     inlined from 'kasan_memchr' at /kisskb/src/lib/test_kasan.c:872:2:
> /kisskb/src/include/linux/fortify-string.h:277:17: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
>   277 |                 __read_overflow();
>       |                 ^~~~~~~~~~~~~~~~~
>
> [1] http://kisskb.ellerman.id.au/kisskb/buildresult/14660585/log/
>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Fixes: d73dad4eb5ad ("kasan: test: bypass __alloc_size checks")
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  lib/test_kasan.c | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 67ed689a0b1b..0643573f8686 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -869,6 +869,7 @@ static void kasan_memchr(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(size);
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 kasan_ptr_result = memchr(ptr, '1', size + 1));
>
> @@ -894,6 +895,7 @@ static void kasan_memcmp(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         memset(arr, 0, sizeof(arr));
>
> +       OPTIMIZER_HIDE_VAR(size);
>         KUNIT_EXPECT_KASAN_FAIL(test,
>                 kasan_int_result = memcmp(ptr, arr, size+1));
>         kfree(ptr);
> --
> 2.30.2
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcZ0eCPEjaLoQWc5a7pVHDKzYLL9ZbOQXv4wE5qA1NwoQ%40mail.gmail.com.
