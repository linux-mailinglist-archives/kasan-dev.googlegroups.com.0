Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKPRTGRAMGQENJZCHRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id B38E66ECC2D
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 14:40:11 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-517bfcfe83fsf2738365a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 05:40:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682340010; cv=pass;
        d=google.com; s=arc-20160816;
        b=CQEN04FPzm5Eo1JT7hnt4ohySasNHSd9bTysooz662e6xYqLBgAQ5ZRO3Sg+MByaNB
         ErhEed45tntEgb6biZKGgapDwvbmb2z0GZLlaRb3F44gEvJP56Lp2o5+8ph15TExDP5V
         DP+voNdoYICmEJWyacXgDHDedWH2eOZBY2EfLpvjGhr5uZ1UKRaNwfEU+i7IJKIMOYLS
         gquHLo9PRrJYLEt1joheCDbwH4eBrWoHCOr/ixO+wAUbtCRqYlKqHrYtE17qvl0wnvWA
         GAEt2Zu1oxZZHATm91Uie3FIPJDaelC1lAI+CODOdpZp1nBku31qs5Zp688UUQeHP931
         T3Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DK90974e45767dFqChta55f6V5yCRmd46VfNTMcmenY=;
        b=KGDt1kbdmCYTBCxkLDd08RxYguEX7dgnrkJk/HkB1MblZhkcHHG2QZkTb/d3a3GDXy
         YXbggfB/ExvNrQs/bdWy/xlzkcukKp6doU6zaOKy57hCl1W7PvjHI/w9ePdtY78hs6aT
         aoNRPW1UfyuUYivttXFGhIfG/5FP7zoKMSXg1SRIV0U7NirLRTlNX5kehNRxIudG2HUX
         +rzZu43yFAscJwguKLWxlg0mqTci0eprJ3KYc/pXnpXovsQ0F4t/UBDOLyH/QX9qqC88
         3nhbhN2KRjjYgegl/rVXPfu7k+aW6pBMPBqCcaIwohYqghTeJubDyOoTqG8a8lP0iOSG
         eE9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=EvhSjrdg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682340010; x=1684932010;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DK90974e45767dFqChta55f6V5yCRmd46VfNTMcmenY=;
        b=mNm/eo6Nf7nbOBWL6tkVRZoDan1V3+dc6hzQ1+zJ/zWT25w1JuN5d2evr3GzA/jmae
         py4Jo7FMYNfnoAxIBWg6iD41VZUYgJNed46Zh6pHJe3ZQBa0nKIu+JxKo6iBA4h1xZTf
         kRtsRMRMWKXpXK2qKKNGQSw3CMMwEPBz65kUG0oh+stgQ6gLzIQpmbR02bqqaxph6ABX
         yTSch0lqghMr+ERUprm3QxzYYPJFvxwdmXrYu/UoJT+G7DDZi3JtgZOhE9yTqYVpF3+L
         KQ/wXxMg80LyoNAkF3dpjA/bOCngUMGR4u/RY0qj4PGzE1EKKx0+jXeopo3VW/4IcCyW
         n8ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682340010; x=1684932010;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DK90974e45767dFqChta55f6V5yCRmd46VfNTMcmenY=;
        b=FLmtvoBNI/ueZ9BBhioySRnRSyY34UEWQTXyih+bOkUbiK1oiH2ui5OKFpWyy525Zv
         k3b8xdk659YRhkuFiWsr6KVPPeTI+w0WjcSJof5UA66eNlZS4l28E8Ts4KL4VL5Mmr5a
         b60ICD8po60qv++MqpDiELR3FwqkqCcAwvPAXJoZPxJr8Q95x1SzGYhMcvfIv6fwla0O
         n4EBgGJKEmOP4Yl1hAnJ5DVY0D2ozS5zIfWcmhBneU84j0l4ucqAer+Pmpk31QYXF5Ji
         TMSZwR+mXYpwTwXyVJRnexDqOUH3U0cv7tz1/P2UORtR7g+lsPQBVlq7up5PClt+zEvV
         eLyw==
X-Gm-Message-State: AAQBX9dSQ1mPV2s19U4v035fvqDVnsquvC4YoEH0Mg8Unei+/GrSqWIx
	gAlBt41LEm3daZMt7/0HBlw=
X-Google-Smtp-Source: AKy350agRdpmLAeA6nyDKbIn4zmKM1z4SFZDFu0pDI7QhrK4W+yFGMEgcYChNw3uuxgV7qgyzBUSkg==
X-Received: by 2002:a65:6390:0:b0:520:4dfb:530a with SMTP id h16-20020a656390000000b005204dfb530amr2982724pgv.8.1682340010038;
        Mon, 24 Apr 2023 05:40:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8542:b0:199:50f5:6729 with SMTP id
 d2-20020a170902854200b0019950f56729ls10484577plo.11.-pod-prod-gmail; Mon, 24
 Apr 2023 05:40:09 -0700 (PDT)
X-Received: by 2002:a17:90b:889:b0:24b:7618:2d16 with SMTP id bj9-20020a17090b088900b0024b76182d16mr9728448pjb.31.1682340009132;
        Mon, 24 Apr 2023 05:40:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682340009; cv=none;
        d=google.com; s=arc-20160816;
        b=fjNOQlGEPDPZT0ucllzxJoylPUvzXm3N5yHVjke2fIdB8bkctXkhlwwhBhKTRlcrxc
         YTrqNVojhXk9ZeCRIomM0eUZe6XwfQaoyX/kNig7fOLYjzBmiUwRHSO3mNr1KPDrqxK3
         Ri+cAd9mDyf32dQ3JXLlE42LWpM5f9P16gS2JwORve1UY3uuwGcji/nraodWuCldWq0U
         k11PlJoOksFFUMdEeZk37PT8/AB1wNkqwQrSJ/+ABim2bglerfNpcWceOg1Li5xD4paW
         eaWyOAyZU/qHSwfZWPa4I9Wjgqzb8vq+tdpughcDAPDmWgL+v3DisXkyZQVyN5KdPcR2
         7eug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pm5YgAO5GczZ8cxOJAygGAJ/cd9lfTw7GnmC+q/KoRk=;
        b=MeApYkiVbuAWAWynhKc0xPu9V4ww+EmHLyJBJTPHUuL7JDOuH3pWzaYQvZatz/r5bL
         YBD+e8dHgCdvkIUd+Fcslhv8HXh7uQWdZEhXdoW8eHtFDzNn08j847pnDMQWI5aBxVl3
         gu8/m2EFAQP0liChcMFNJkMOovW40uLxiRM/6jW9F4lU+xHioLgpc4rVCZpcZJcbOhn4
         VbOaJW5RpHGkLKzbS8CE+uvMmfCxltjfvpR2kI7bbPTz4g4r8JRGAsaJTa6kWgTrRrBX
         sOL4RPgokddZNa7KYcbt3wyfxFyQtnBnvF6tC4yKOy5pVPERrod4cqJRsW6qpFg1ZUcy
         HtaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=EvhSjrdg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa30.google.com (mail-vk1-xa30.google.com. [2607:f8b0:4864:20::a30])
        by gmr-mx.google.com with ESMTPS id s11-20020a170902c64b00b001a80e7783fdsi561237pls.13.2023.04.24.05.40.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Apr 2023 05:40:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) client-ip=2607:f8b0:4864:20::a30;
Received: by mail-vk1-xa30.google.com with SMTP id 71dfb90a1353d-4404923f303so1509518e0c.3
        for <kasan-dev@googlegroups.com>; Mon, 24 Apr 2023 05:40:09 -0700 (PDT)
X-Received: by 2002:a1f:cb02:0:b0:43f:c225:129c with SMTP id
 b2-20020a1fcb02000000b0043fc225129cmr2806380vkg.14.1682340008166; Mon, 24 Apr
 2023 05:40:08 -0700 (PDT)
MIME-Version: 1.0
References: <20230424112313.3408363-1-glider@google.com>
In-Reply-To: <20230424112313.3408363-1-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Apr 2023 14:39:32 +0200
Message-ID: <CANpmjNNwzup9o+XNcjQcXEjFrU5QUQEc4qMP1yA07e74eyk6Dw@mail.gmail.com>
Subject: Re: [PATCH] string: use __builtin_memcpy() in strlcpy/strlcat
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	akpm@linux-foundation.org, dvyukov@google.com, kasan-dev@googlegroups.com, 
	andy@kernel.org, ndesaulniers@google.com, nathan@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=EvhSjrdg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as
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

On Mon, 24 Apr 2023 at 13:23, Alexander Potapenko <glider@google.com> wrote:
>
> lib/string.c is built with -ffreestanding, which prevents the compiler
> from replacing certain functions with calls to their library versions.
>
> On the other hand, this also prevents Clang and GCC from instrumenting
> calls to memcpy() when building with KASAN, KCSAN or KMSAN:
>  - KASAN normally replaces memcpy() with __asan_memcpy() with the
>    additional cc-param,asan-kernel-mem-intrinsic-prefix=1;
>  - KCSAN and KMSAN replace memcpy() with __tsan_memcpy() and
>    __msan_memcpy() by default.
>
> To let the tools catch memory accesses from strlcpy/strlcat, replace
> the calls to memcpy() with __builtin_memcpy(), which KASAN, KCSAN and
> KMSAN are able to replace even in -ffreestanding mode.
>
> This preserves the behavior in normal builds (__builtin_memcpy() ends up
> being replaced with memcpy()), and does not introduce new instrumentation
> in unwanted places, as strlcpy/strlcat are already instrumented.
>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Link: https://lore.kernel.org/all/20230224085942.1791837-1-elver@google.com/

Reviewed-by: Marco Elver <elver@google.com>

Looks reasonable.

> ---
>  lib/string.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/lib/string.c b/lib/string.c
> index 3d55ef8901068..be26623953d2e 100644
> --- a/lib/string.c
> +++ b/lib/string.c
> @@ -110,7 +110,7 @@ size_t strlcpy(char *dest, const char *src, size_t size)
>
>         if (size) {
>                 size_t len = (ret >= size) ? size - 1 : ret;
> -               memcpy(dest, src, len);
> +               __builtin_memcpy(dest, src, len);
>                 dest[len] = '\0';
>         }
>         return ret;
> @@ -260,7 +260,7 @@ size_t strlcat(char *dest, const char *src, size_t count)
>         count -= dsize;
>         if (len >= count)
>                 len = count-1;
> -       memcpy(dest, src, len);
> +       __builtin_memcpy(dest, src, len);
>         dest[len] = 0;
>         return res;
>  }
> --
> 2.40.0.634.g4ca3ef3211-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNwzup9o%2BXNcjQcXEjFrU5QUQEc4qMP1yA07e74eyk6Dw%40mail.gmail.com.
