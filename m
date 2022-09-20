Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHFAVCMQMGQEG2FIQUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 73D975BED5B
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 21:10:21 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id sd4-20020a1709076e0400b00781e6ba94e1sf829328ejc.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 12:10:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663701021; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q3F1al8wjTuA8iUNpKt4OzGxlKqnp6itT6LiZtEZliw5dzgcJkyCfk2pdvAp6ifm1i
         jmDkbwiSnuQP1czAzabejUOxotBKoIYenf4+dPSS0ly0uMbTMfwqouBnQmU0C4a+OlgI
         RxroA8OdvErQMV56DvMSlucdOfSIs98lDkLoOcNRZhrhrI7jvHLsd5y6sibR6sBXfVmg
         ucqvEN1F0PspstoPlwj2c3/YxVymg46gCKzEGPaoahn+I6nKUBeRwz8upFNF5dfpJU3K
         xHwJTk8TOw5PpOHu2ZMlS+JM7ffpCUbknbtGftDQgjUYom7JIxrIZ2npCI872j4pHz2L
         ac4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c44oUKyQWgqyhrc7tE9yX3Lz433cuUoitlGD6zPZTFA=;
        b=Rids3b9JrUBF50/UqiZlJm3mJu7KPG57j0HWwsG4blSXarwVB66vN+A5pWgyhEWSHl
         +W/bdrDFDWb12iCfFH6xFHrkQnEetgUbsxNUvfttTBsXou3VGiLsbrfOpiro7eCgABzf
         TWOEgtszWL3CVeTIveu2+3D9vGGYMB0BWUX/PGs7n7b4XlIeLYhLC9uhlSurrFwP/4+/
         NZ8qY+CU9DAtQiz36MnKbg9g5cnuuBCrtz9U+bpCrtMVSMYIuVfLlabjxejUKceUOTuH
         nmyH5lmGyo9kCIr3GuHQ3xH1AgSWudFrVhVYhFDdRF1D2XXDeuY6UEWWDGRlqLJ0U3nQ
         MPaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rY1HK3uJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=c44oUKyQWgqyhrc7tE9yX3Lz433cuUoitlGD6zPZTFA=;
        b=aJZLgSmMDvwRLzKnmcJb+xwf5hhdN1MruoSHimX5V4L2IYasJw46MyF3eK7shbXeTJ
         +2wC1maDvwg2DTRliWOqxVUKCfoHjWhkBAcT2gdJaXZDHf+KB4sC2UfeS2r20AoIsK5I
         J+WuYillBzA6K2zZcMScjxfc1kBEMJBjp8FmCauQBxgS9Q1j0mhQez91J9pQv+n8QyQV
         E9zVTJe9snsRZj7qFgioQ0V1mkpIbwOPi/WZyb2rlYpVssVQ8tZxf6vzOTpI67TelnCm
         VNcrzZR6YxBmtnNuS8wsw49c/wYcVVqopZMXReIg0FS3umk1OeNHw2DaWXebLxfu3bf+
         kNbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=c44oUKyQWgqyhrc7tE9yX3Lz433cuUoitlGD6zPZTFA=;
        b=5b0zs3gkeVtSs8RflLXMQtZ3v8EcOp/qoAdIv1UMsAJb3tZlGCuyq7bNzhD3SnpXQE
         38RrsQcysB9RI80cvJ4R1lk22wLoBkGHYyfGXE8UDc+mKX4P9rx4aVfrl65HzSpI0z14
         nqYtF0eXIoXNbxSeiaE2xcmwR2BtfWLWBUvD6uDbbYLQ615S9kDktltkYmwlIktQGNDJ
         YQxAMt/NHodksuV1feMGRjSKOVnkpUDT4LVqVQ2SHkiyhqWwN4MwcJDVDDo74qbNhG0H
         0LLws/abNfrrEm5OZEWlbyx+nsXZVBqPUv7sG9rpes2pHHzevTerI4NoDjCJLKW1mob1
         af8w==
X-Gm-Message-State: ACrzQf0hCmJEgifRqAKYDzWuV4y6l1E9RgpTm3HO8hT6v9hsD8zV2QIo
	jv/gR6nrxTEpDxLYq8m62x0=
X-Google-Smtp-Source: AMsMyM5ICjidEpQ1EQUfgSvdnQffly+w75TlfzjM9+NZ6UYfrIhTqEjVJMKHlUnc21vfZZ6zTC/S5w==
X-Received: by 2002:a05:6402:914:b0:451:22c5:2e28 with SMTP id g20-20020a056402091400b0045122c52e28mr21343836edz.294.1663701021007;
        Tue, 20 Sep 2022 12:10:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34cc:b0:44e:93b9:21c8 with SMTP id
 w12-20020a05640234cc00b0044e93b921c8ls8796054edc.1.-pod-prod-gmail; Tue, 20
 Sep 2022 12:10:19 -0700 (PDT)
X-Received: by 2002:aa7:d150:0:b0:44e:3c06:d719 with SMTP id r16-20020aa7d150000000b0044e3c06d719mr21930598edo.265.1663701019651;
        Tue, 20 Sep 2022 12:10:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663701019; cv=none;
        d=google.com; s=arc-20160816;
        b=f3OGNWDoEcemUu/xhlmZMjhAjeRNWGZWlCksa+a6oAUTfP7bq2Miz+hCiXpZomD05+
         TmNxib7JiwYICXASjF9xHGIWKSfAkA3JpW9sQlCZdoxt1fl73HusqKqlOgR92fZ5+m6Q
         DhzkO4swxFDd0AMC4KlXE/6cC82aUmzjtryEyVa0dtdYEd1dRrdYgVOm/KKdHPJVj3AV
         PN5kQz5XRlN2u3nG3InMsMs/W5zCVrWaGXbr/hPjNzy1qyDrwAybxK4M3hhCNhPax+N5
         BPYbGpgxEgB/UL9DSZyRpE3t8xBtfYq1fLKgrBf1MfjYzKlluVe1G5k1sTpYJgZ5CaEj
         WY5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vhcZzgEgF161dV3JAs/7wiPgpLh5ucK8PQ1AhMND7Wk=;
        b=oVydzH531wwLqNW5Cl2HOPfC1XAPeh+FoEj91fr+3DL13pvOkeV8EK1vaNbwhFwqKe
         K4UO643MWyJhUqQfaTl9xpz/pKIbs6Vw4vpvy4d+fFpbaFi6W1iFYM7N02OnnurcFTah
         PJ5cknKXGQ72cllLAUUO4dOU+h4EqWG/uR1KMaOzxQ3uDXpX2/PbrocO5d98U5WZWTGD
         p+Y5rbrT6TEnJu8mKtasf1FtCFVnIwGLcvitm20LebJBQAOOz9PMGypUQLrlneQAuwiJ
         4cBbJUWj2WZ3WiFaI5b38rLr7YCnR4P+6IuA1kiJcHxHrtwYjr+nV8Nfue2Y6lPyvOl+
         JsmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rY1HK3uJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id o21-20020a50fd95000000b00454412dc7c5si34334edt.1.2022.09.20.12.10.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Sep 2022 12:10:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id i203-20020a1c3bd4000000b003b3df9a5ecbso7584778wma.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Sep 2022 12:10:19 -0700 (PDT)
X-Received: by 2002:a05:600c:1d11:b0:3b4:7644:b788 with SMTP id
 l17-20020a05600c1d1100b003b47644b788mr3742800wms.114.1663701019260; Tue, 20
 Sep 2022 12:10:19 -0700 (PDT)
MIME-Version: 1.0
References: <576182d194e27531e8090bad809e4136953895f4.1663700262.git.andreyknvl@google.com>
In-Reply-To: <576182d194e27531e8090bad809e4136953895f4.1663700262.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Sep 2022 21:09:42 +0200
Message-ID: <CANpmjNN0jyK0svOOHSFPAfFV9CAEUVUb+y_748Fww-sgf=3pdg@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: initialize read-write lock in stack ring
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Yu Zhao <yuzhao@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rY1HK3uJ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as
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

On Tue, 20 Sept 2022 at 20:58, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Use __RW_LOCK_UNLOCKED to initialize stack_ring.lock.
>
> Reported-by: Yu Zhao <yuzhao@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Andrew, could you please fold this patch into:
> "kasan: implement stack ring for tag-based modes".
> ---
>  mm/kasan/tags.c | 4 +++-
>  1 file changed, 3 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 9d867cae1b7b..67a222586846 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -36,7 +36,9 @@ DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
>  /* Non-zero, as initial pointer values are 0. */
>  #define STACK_RING_BUSY_PTR ((void *)1)
>
> -struct kasan_stack_ring stack_ring;
> +struct kasan_stack_ring stack_ring = {
> +       .lock = __RW_LOCK_UNLOCKED(stack_ring.lock)
> +};

Reviewed-by: Marco Elver <elver@google.com>

>  /* kasan.stacktrace=off/on */
>  static int __init early_kasan_flag_stacktrace(char *arg)
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN0jyK0svOOHSFPAfFV9CAEUVUb%2By_748Fww-sgf%3D3pdg%40mail.gmail.com.
