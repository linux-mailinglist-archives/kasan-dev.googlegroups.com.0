Return-Path: <kasan-dev+bncBCMIZB7QWENRB7VAS6QAMGQEO6MBBQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A0B96ABE53
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Mar 2023 12:37:35 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id m10-20020adfe94a000000b002cdc5eac0d0sf1405217wrn.2
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Mar 2023 03:37:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678102654; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dv74UT+vnQ4JuPQjQF3xp13U9WYGybGwfNTrRzXSy95cD6dLDoYhLewHuFPm1oDESD
         7CNEJA9OlDCxRP9qfFMnBmjKdPE4UhNfZ35UG0PSODvUAkmQ4azmYIlNow9clfrD5L0x
         QFwgW/eEZdlzDzfKAFVtcbqMFx7KoXpbnTraeoZRaZj4S5PdqAzcQqH0RB8JlRPKzBEn
         zaehMjoFxBc2FGauJPs0geqUF2Wb74XN7+dHkLadC3t7FjDzKDMDJWfW3HF58ZzbKLr5
         U98z2g27yB5pmV3FYy/fzRVYg+ZV5XGh+ldeMjEE2t7e/y6Yk1BLP96fuYtjyq2R0siG
         BYQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6kS96VLUvXX+Fskjc02RmiXXQyqN6sgrToLzv3we558=;
        b=Zg735CF0HGcq3PYRZKBJtiuKXqUSmnCwUsS2Ej5qUZjGe4mOlGNngBGrK4LHMAEGK1
         4z10ZaaoavxDfcXOeyr5oWQyBDZw/Z745ol+F592oiykA4y9+ptGAr728d+vc6OsOXaL
         q+pEHnDPs7zUTeoaFODYc69z/k1ZY/1KTC9zJe9OwSG3gm+6kBNqf85IHwjqtFa7kr74
         Wd97mlAsd1lOdeFOqXLUts5/qVh7OWy9/Ik8tY7Nbf7J8UTCOVB4PDzJHAx4dAR11PaY
         YwQcTVS6qWdXT+bLEHk9xnd6EciuZ6MjcgM5YyGnb82SvoZwTd7QPhNKH5eOTFnySbZi
         5rhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U5ElntDz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678102654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6kS96VLUvXX+Fskjc02RmiXXQyqN6sgrToLzv3we558=;
        b=t0ERfAIU9DS0W/TXzcmEbdHe7Mj3LqEiRNiycfa/58klebwewEZGwPd9pZrrZqBNIk
         sZEOrFkzOXZl/AJxZJbwUzqwGt0N41vl97jURg5OeDjM08WLagHCstltGZI7MtpfsqZ5
         BK0dOZc4nF5fTPndIVxBw2NX6AzmEs7xMoRoxwCQWN/824Yu0UnspmTXByctVuNyE1N2
         qMboCcvtmqz5b0t2dvMl2j44ILu16X1H3wjyce2/MDnDPhFGGER71lFMtTBLip/O++Qw
         8M6SM5lZ3eAPLkDrKyopQMR3YRmzoaa8h/YfQg5o7bLk6P8lJTJRqi8uRRQgkOo8MuoA
         a/cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678102654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=6kS96VLUvXX+Fskjc02RmiXXQyqN6sgrToLzv3we558=;
        b=ja856j8ByBpyQqnRc6jH0FvLB3sYsN0WCbkETNLHvVKtGGVeyaNfUxqDBSAzerhvDJ
         WY3f3ThHytiV+W0Y+GmtaVvV4fbVSg/vGUjFtCesz/6y4EzFqQs85piZ0e/M3iV3/njP
         ce7w/wDlqCoiWIhsIjJ2fTByeIg3NiKSFaWatUVgAhUxnbrrF0aAUVq4FyFWGS+0MkEV
         KE5L4NtmKUy3YJpFxc0sim7ejsvutzK5RHW7xiLxzLdD0Gyobs0h/puXd+PzgrwTBBJE
         E/rJ/3FTAy4ygQ2KWU/sWQelUSi7sn8gyai8JVJm64kZ2Vt3Riir1k9eozO0b9jhP489
         Ow2A==
X-Gm-Message-State: AO0yUKUxNICEI9gn8ubgxAdxQRwTB03G6NFU3+lijRImMEkpLh4+f10w
	ZB38p6fAl4cNZaG9Vx+oE6c=
X-Google-Smtp-Source: AK7set/8gk+tSri/MYZmiO7Stk3+Qx3o9Z3WwRr6yKkDg+LDhCE5r1H0NGK2tXneqmfFkgCHZKPC8g==
X-Received: by 2002:adf:f241:0:b0:2c5:557a:59b2 with SMTP id b1-20020adff241000000b002c5557a59b2mr1849859wrp.12.1678102654434;
        Mon, 06 Mar 2023 03:37:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c01:b0:3dc:5300:3d83 with SMTP id
 j1-20020a05600c1c0100b003dc53003d83ls5111507wms.0.-pod-control-gmail; Mon, 06
 Mar 2023 03:37:33 -0800 (PST)
X-Received: by 2002:a05:600c:4f4e:b0:3db:15b1:fb28 with SMTP id m14-20020a05600c4f4e00b003db15b1fb28mr9745824wmq.19.1678102653214;
        Mon, 06 Mar 2023 03:37:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678102653; cv=none;
        d=google.com; s=arc-20160816;
        b=I6K2rh2KQPzbpKJRyGGJ9gJzlPkcAgiPdUEw+XxYCrUm4sqx4MNrZ3nYDEytfcoZqf
         LwKs1hzwD8dGY85NzjDpCSvXYr8T4Fb81yC3pHGQhy6lWRDxlFfzEZewJElm6R4tvanp
         8TeBmch11nZZbsSTpD+HrdZ99CSgjwATeiBurdL5EVxndKxVHK9hxOg9nRz07Z3e/+oV
         Ha1A68RSw228tbtiUJ8CxZiiU4spscPuLh3LlTGY6UCFzyXAjRhC+WZAEdkPrXrohofl
         iwxQB05KkTXJZFYvALrNGTHkrx8TPXVs6DE4C8Zx24X+veels3CVNpQXSU55wMH+dm8F
         Fq+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/EG0K6pekvZn1QIAwUQIbgo3cKkJaQ89TXn04u6/9Ng=;
        b=eoK1WrybRxEA63RS6E34CLSSFgtpV/upj7YAxX11FlOC1OzzQZ4WIi9e60yKV3GTh2
         UYPfDMZHC9kpvaIPEze9JjwulKsXurcMOqw74eKO5TlB5lbWkiw2BsROd1RW5K/DmGep
         R0u3mmagbvNrGj+tqK3vY3zcR+xj9LgPJlNDk47su4dne79G6RbmkUWNDWTFiTADI9nU
         Nizg7DVk5spJqYptybJKIGFpU/YkzMX9bJzLrFjaYXmal6ZTLeINVqjwMhnp7vSsbyZ4
         CYNEkfPLtAvTS6o+v4a5o42j18QF11ItKMqcXWJqBHAP0yqslp4DJOrM32ZuzRCjQfwa
         buFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U5ElntDz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id b3-20020a05600c4e0300b003e21b96f27asi622687wmq.2.2023.03.06.03.37.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Mar 2023 03:37:33 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id k14so12284295lfj.7
        for <kasan-dev@googlegroups.com>; Mon, 06 Mar 2023 03:37:33 -0800 (PST)
X-Received: by 2002:a19:8c4e:0:b0:4dc:7e56:9839 with SMTP id
 i14-20020a198c4e000000b004dc7e569839mr6502919lfj.5.1678102652464; Mon, 06 Mar
 2023 03:37:32 -0800 (PST)
MIME-Version: 1.0
References: <20230306111322.205724-1-glider@google.com>
In-Reply-To: <20230306111322.205724-1-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 6 Mar 2023 12:37:20 +0100
Message-ID: <CACT4Y+Yzm90bzM5CDyjCCY9Dveysp6h-nh3F2DhhesRLLxhWDQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] lib/stackdepot: kmsan: mark API outputs as initialized
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	akpm@linux-foundation.org, elver@google.com, kasan-dev@googlegroups.com, 
	Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=U5ElntDz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 6 Mar 2023 at 12:13, Alexander Potapenko <glider@google.com> wrote:
>
> KMSAN does not instrument stackdepot and may treat memory allocated by
> it as uninitialized. This is not a problem for KMSAN itself, because its
> functions calling stackdepot API are also not instrumented.
> But other kernel features (e.g. netdev tracker) may access stack depot
> from instrumented code, which will lead to false positives, unless we
> explicitly mark stackdepot outputs as initialized.
>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Marco Elver <elver@google.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Add:
Reported-by: syzbot <syzkaller@googlegroups.com>

Otherwise:
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>


> ---
>  lib/stackdepot.c | 12 ++++++++++++
>  1 file changed, 12 insertions(+)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 036da8e295d19..2f5aa851834eb 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -17,6 +17,7 @@
>  #include <linux/gfp.h>
>  #include <linux/jhash.h>
>  #include <linux/kernel.h>
> +#include <linux/kmsan.h>
>  #include <linux/mm.h>
>  #include <linux/mutex.h>
>  #include <linux/percpu.h>
> @@ -306,6 +307,11 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>         stack->handle.extra = 0;
>         memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
>         pool_offset += required_size;
> +       /*
> +        * Let KMSAN know the stored stack record is initialized. This shall
> +        * prevent false positive reports if instrumented code accesses it.
> +        */
> +       kmsan_unpoison_memory(stack, required_size);
>
>         return stack;
>  }
> @@ -465,6 +471,12 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>         struct stack_record *stack;
>
>         *entries = NULL;
> +       /*
> +        * Let KMSAN know *entries is initialized. This shall prevent false
> +        * positive reports if instrumented code accesses it.
> +        */
> +       kmsan_unpoison_memory(entries, sizeof(*entries));
> +
>         if (!handle)
>                 return 0;
>
> --
> 2.40.0.rc0.216.gc4246ad0f0-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYzm90bzM5CDyjCCY9Dveysp6h-nh3F2DhhesRLLxhWDQ%40mail.gmail.com.
