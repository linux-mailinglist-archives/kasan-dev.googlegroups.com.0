Return-Path: <kasan-dev+bncBCMIZB7QWENRBAUFRP4AKGQECCWVPZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 69E46215288
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 08:19:47 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id f11sf1669402vso.22
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Jul 2020 23:19:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594016386; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZlcyqTj5+1MXsfce6QM9WEiwRKTRzik9cle9tmvrZAQ/V3x0lQmirFDrLru9uu1zHK
         0wXC1S6el/+EQFq35z0pxUVvA+CGsyTOTDopmixbfk8nq7QQwuaFtvAw8oFnMLoBJaEY
         r/LisDPKsjijkENyyGSUB1JjpK/DIKX0snxG1O7EgwwJBcmtCmVEty/Q4TTOm/DfW3r7
         OIrZFHoJRVdenwDZIebjCe24B3KTWwWXzAr7colN94ev3oCJArADZMnhG+7Vyx6B37I4
         4lyq4kxijbjQIZvuDF2u7yVkgKZSFd625MamwEDme85ealEB9aGbVGozjtXyPZf8TM/g
         mbTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qHyJSjDci4J9oXZAs1HnhoFt2++4UhdLt22Fbd2rhpg=;
        b=Fl//TvrAc1PTwr8Ky4MOPvQCf44UyQmboTD8BU64uvHzbcIfE5R5wVlWTNIGCmFjNz
         DnQ0wPmEf6Zh0d8L/S+arC9o0qX2h6i4pcwatzrHSGctnz69QYLJl4Y5/mXaCTuyV5TQ
         LVl2u42frVHOqp+trq5oe2FCIzGRm2PBj4wt4ppqpXvGDGf2gSeMTzTgfJ7Ww4Z1xQWB
         aycJDU3iS1nvN5//pzC2FPRJN4LlwBVPbqp/KfRugG39R49dmsSuTQQFENBFk1E/KNDe
         +qfARpZ2yB4Cnky1RjybO7mjw62iEQUdPCil07kvB39exI9U/OsSRfu7+kZ1TWy6VDQJ
         1Ylw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kb5GyZA+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qHyJSjDci4J9oXZAs1HnhoFt2++4UhdLt22Fbd2rhpg=;
        b=ZCIwc70ik4XXJycUnMtwY91bZvJZZv9CVKt/udTC1avcI/XeMUGRz2JyeR6Gucpcdd
         t9SzUqP55N4KkvFi6ASSXEM1R1mF2Huc+ekR4jTX/92YhLt//O7Qy/k3nAoZ2uPBExTW
         9vsFWlT5q5FJWfLdjyblAcCoQJYYBsGpTNkyBmYZ5ADzQvfKejBt5oDMsCu4fCn/iBgE
         jokAC84/vTlGPHAx4TKsGfF9PGIFOFova5TlWJItCCG7QqMG31bR2TyACq87W7yWOhiH
         5jM2fLqDIGnmiTHqv/vJlCerAHdum8HS6DZj/qqbDIwtP0El34dtJB7Fyw7bv7qaAyHy
         WaMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qHyJSjDci4J9oXZAs1HnhoFt2++4UhdLt22Fbd2rhpg=;
        b=TO6douFeAd4crDQIFNEQnK6TtpovqGNGzEvzvIOgaYIFn1JdqXcTtHmMjZI4kjV9hH
         XozzIajMwQSPWE0CPtqFM4tQY2yXw6qieHSmfmjM8RL8BqmYK92Ous5iXTfanFx8lA9B
         I+/H+fbOdWL89ZxM3piVaq862cQ396TueILkCM9N2S7WjzJdBemen08HhlUyUcYqb1Gq
         SxdRxNveZTvbnj56lz0iGAutxJzfrH1m18PThKVud/yLc5ei6hBMEfQ3T1ua8YdL3gvl
         yp1AyLc22qrZC/qDIt+AcsgEd9OIC4heec6ZlrgR6+/07Cyiu5VdTewGx9q0csxyTrUL
         CUkQ==
X-Gm-Message-State: AOAM530mzXjO4sHEqyU8UBxhIW/DTKQcmEqITN92211e+U5Pbr4Hsaoj
	AFjO1BJMpUGbD0Bj/uuQdVI=
X-Google-Smtp-Source: ABdhPJzY0Ep6UuvtgAVFw1xh0RPBrvSFg9M9oz2t0HA5Q1LZhaKe1X2LVQryc2qNmoheBcTBur8Tmg==
X-Received: by 2002:a67:ee94:: with SMTP id n20mr28511940vsp.239.1594016386329;
        Sun, 05 Jul 2020 23:19:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a04a:: with SMTP id j71ls746983vke.3.gmail; Sun, 05 Jul
 2020 23:19:46 -0700 (PDT)
X-Received: by 2002:a1f:61c2:: with SMTP id v185mr3146048vkb.42.1594016385915;
        Sun, 05 Jul 2020 23:19:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594016385; cv=none;
        d=google.com; s=arc-20160816;
        b=ntDmWlR/XevDCoSrSZX8+T3MbyuKoSvpxQMzXGuoOPZorMeOT05mnHBWs9RXaLq0Oz
         RoBpfuzmqFuL3/JLZ3y8XjoriKufe92IyZ/iv9kHwmMfiDU1nona5cYCFDe1OIMPVeOs
         s0s6NZJiem3nxstUXy0mn0Wa9z8JiwOR5tNkkoj8BWl+ndC7WEvl7eGpXY5MP3HtQ9wZ
         zEXqpQVaP0Obc4QbeVKkIyfwEndG1eW5ybcALNhUtrpqptXUVuEQ8vB4vZ8Tmm2MxK+s
         36B7pSnYyX4IINZiOGR81ay5btW1Gft51vidvLrOdT5x+VGjxgGLKy3p6agtXpV5UJqr
         KGIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=p8GSicWISxuLf8SI+byIF+xMxTNvfdYQixlttIglDVo=;
        b=QOLaKkjxXHw27RcXyBLwsSjybVyzkUk0SHJUNCdEwyvDOmwcyb/r6vTRiyYVrB08/a
         XGpAqy6/9zNau73ZQ6jwRFh8J3/5ImUe/Bcpav3JU6ZBQRTaXLje3/KfwuGVTkcJe0Sr
         St7Dh1Y2h75cvQW3ngswezvT2HAeBNYGNMinhshDBWhNDpKnarUULD/fEP+NCFlGdHMw
         QXtKNin+UzLG3+HzfcRtTK5EVjdah4F4AhVMwmrVkVYrNUaqD28O7sArZ3mhcs5gZwYW
         lX0zk8ioMW62cI3fADCQWdCtsBpE2YfRFFtkA1bF8FqjofXvvgDSEPEpGlwOO1wBT6jV
         1rsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kb5GyZA+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id a68si1158907vke.1.2020.07.05.23.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 05 Jul 2020 23:19:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id z63so33793232qkb.8
        for <kasan-dev@googlegroups.com>; Sun, 05 Jul 2020 23:19:45 -0700 (PDT)
X-Received: by 2002:a37:67d4:: with SMTP id b203mr19900712qkc.407.1594016385214;
 Sun, 05 Jul 2020 23:19:45 -0700 (PDT)
MIME-Version: 1.0
References: <20200706022150.20848-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200706022150.20848-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 6 Jul 2020 08:19:33 +0200
Message-ID: <CACT4Y+akZ5iu2ohQhRqiUd8zkew-NmrUPrA=xYtS1xxHWZ60Og@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix KASAN unit tests for tag-based KASAN
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org, 
	Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Kb5GyZA+;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Mon, Jul 6, 2020 at 4:21 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> We use tag-based KASAN, then KASAN unit tests don't detect out-of-bounds
> memory access. They need to be fixed.
>
> With tag-based KASAN, the state of each 16 aligned bytes of memory is
> encoded in one shadow byte and the shadow value is tag of pointer, so
> we need to read next shadow byte, the shadow value is not equal to tag
> value of pointer, so that tag-based KASAN will detect out-of-bounds
> memory access.
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Matthias Brugger <matthias.bgg@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> ---
>
> changes since v1:
> - Reduce amount of non-compiled code.
> - KUnit-KASAN Integration patchset are not merged yet. My patch should
>   have conflict with it, if needed, we can continue to wait it.
>
> ---
>
>  lib/test_kasan.c | 81 ++++++++++++++++++++++++++++++++++++++----------
>  1 file changed, 64 insertions(+), 17 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index e3087d90e00d..660664439d52 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -40,7 +40,11 @@ static noinline void __init kmalloc_oob_right(void)
>                 return;
>         }
>
> -       ptr[size] = 'x';
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               ptr[size] = 'x';
> +       else
> +               ptr[size + 5] = 'x';
> +

Hi Walter,

Would if be possible to introduce something like:

#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : 8)

and then add it throughout as

        ptr[size + OOB_TAG_OFF] = 'x';

?
The current version results in quite some amount of additional code
that needs to be read, extended  and maintained in the future. So I am
thinking if it's possible to minimize it somehow...

>         kfree(ptr);
>  }
>
> @@ -92,7 +96,11 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
>                 return;
>         }
>
> -       ptr[size] = 0;
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               ptr[size] = 0;
> +       else
> +               ptr[size + 6] = 0;
> +
>         kfree(ptr);
>  }
>
> @@ -162,7 +170,11 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
>                 return;
>         }
>
> -       ptr2[size2] = 'x';
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               ptr2[size2] = 'x';
> +       else
> +               ptr2[size2 + 13] = 'x';
> +
>         kfree(ptr2);
>  }
>
> @@ -180,7 +192,12 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
>                 kfree(ptr1);
>                 return;
>         }
> -       ptr2[size2] = 'x';
> +
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               ptr2[size2] = 'x';
> +       else
> +               ptr2[size2 + 2] = 'x';
> +
>         kfree(ptr2);
>  }
>
> @@ -216,7 +233,11 @@ static noinline void __init kmalloc_oob_memset_2(void)
>                 return;
>         }
>
> -       memset(ptr+7, 0, 2);
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               memset(ptr+7, 0, 2);
> +       else
> +               memset(ptr+15, 0, 2);
> +
>         kfree(ptr);
>  }
>
> @@ -232,7 +253,11 @@ static noinline void __init kmalloc_oob_memset_4(void)
>                 return;
>         }
>
> -       memset(ptr+5, 0, 4);
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               memset(ptr+5, 0, 4);
> +       else
> +               memset(ptr+15, 0, 4);
> +
>         kfree(ptr);
>  }
>
> @@ -249,7 +274,11 @@ static noinline void __init kmalloc_oob_memset_8(void)
>                 return;
>         }
>
> -       memset(ptr+1, 0, 8);
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               memset(ptr+1, 0, 8);
> +       else
> +               memset(ptr+15, 0, 8);
> +
>         kfree(ptr);
>  }
>
> @@ -265,7 +294,11 @@ static noinline void __init kmalloc_oob_memset_16(void)
>                 return;
>         }
>
> -       memset(ptr+1, 0, 16);
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               memset(ptr+1, 0, 16);
> +       else
> +               memset(ptr+15, 0, 16);
> +
>         kfree(ptr);
>  }
>
> @@ -281,7 +314,11 @@ static noinline void __init kmalloc_oob_in_memset(void)
>                 return;
>         }
>
> -       memset(ptr, 0, size+5);
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               memset(ptr, 0, size+5);
> +       else
> +               memset(ptr, 0, size+7);
> +
>         kfree(ptr);
>  }
>
> @@ -415,7 +452,11 @@ static noinline void __init kmem_cache_oob(void)
>                 return;
>         }
>
> -       *p = p[size];
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               *p = p[size];
> +       else
> +               *p = p[size + 8];
> +
>         kmem_cache_free(cache, p);
>         kmem_cache_destroy(cache);
>  }
> @@ -497,6 +538,7 @@ static noinline void __init copy_user_test(void)
>         char __user *usermem;
>         size_t size = 10;
>         int unused;
> +       size_t oob_size;
>
>         kmem = kmalloc(size, GFP_KERNEL);
>         if (!kmem)
> @@ -511,26 +553,31 @@ static noinline void __init copy_user_test(void)
>                 return;
>         }
>
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               oob_size = 1;
> +       else
> +               oob_size = 7;
> +
>         pr_info("out-of-bounds in copy_from_user()\n");
> -       unused = copy_from_user(kmem, usermem, size + 1);
> +       unused = copy_from_user(kmem, usermem, size + oob_size);
>
>         pr_info("out-of-bounds in copy_to_user()\n");
> -       unused = copy_to_user(usermem, kmem, size + 1);
> +       unused = copy_to_user(usermem, kmem, size + oob_size);
>
>         pr_info("out-of-bounds in __copy_from_user()\n");
> -       unused = __copy_from_user(kmem, usermem, size + 1);
> +       unused = __copy_from_user(kmem, usermem, size + oob_size);
>
>         pr_info("out-of-bounds in __copy_to_user()\n");
> -       unused = __copy_to_user(usermem, kmem, size + 1);
> +       unused = __copy_to_user(usermem, kmem, size + oob_size);
>
>         pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> -       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> +       unused = __copy_from_user_inatomic(kmem, usermem, size + oob_size);
>
>         pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> -       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> +       unused = __copy_to_user_inatomic(usermem, kmem, size + oob_size);
>
>         pr_info("out-of-bounds in strncpy_from_user()\n");
> -       unused = strncpy_from_user(kmem, usermem, size + 1);
> +       unused = strncpy_from_user(kmem, usermem, size + oob_size);
>
>         vm_munmap((unsigned long)usermem, PAGE_SIZE);
>         kfree(kmem);
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706022150.20848-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BakZ5iu2ohQhRqiUd8zkew-NmrUPrA%3DxYtS1xxHWZ60Og%40mail.gmail.com.
