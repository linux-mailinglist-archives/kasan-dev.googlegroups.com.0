Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKP4S34AKGQE2QR5FVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id A7DE62187BE
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jul 2020 14:38:03 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id 75sf4397111pfb.21
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jul 2020 05:38:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594211882; cv=pass;
        d=google.com; s=arc-20160816;
        b=k/1PFfAWLgJga9z4043Y2Dk3UHTQvSefjWRN3va+k1RhK/Gvb17GWgJIOTxNDQkS7A
         UzP4shYs3WAYouqDJZb8fRsrN53caTyvAn3bQ2/qbDJoqiFxIr5/PaAsvCcKM+r1d8aC
         J6u4QZi+nA2eyd9gBwGME2SvWoYluwZFkwdoEAt8nlv3qGmdiqE/fxPxSjGtVhycsOVL
         fklAMeRnrIC6KOeRTX6HCX5mgqxzboHun7QsDGVCvbjJSkMQYUhowiKuiCyeg7iuVz+L
         2jLq3RFxw6YUXWP/TRSfaEi0C6wBt/pJ9AXzJsZBz9PKhDkzkcVLl9lcom4OKlOLuSYb
         WCwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oqzXyk6zP8C/6lOSTXpmxYjiSu30lHb++ouyvKR2/b8=;
        b=JZNkpZEIYK2+OOO/laJNOAhBSsss3wzY9GtUK02b+erXKZrKmk6EtbG2XLgOt17YTd
         pV1YoYOkeGq3Ot87j3pB60LEtKF50XLpwIKwREwirZ0NVxC1QKUyWqLxDU+vbFzzF/ka
         sEIDQsU1SiInSXkGHN5Gw0qvBIuTgJl/6toZfOxALwx/qGRXDruo4ORdM9XNHNGHmS18
         9Y9TInyad1RdZoW971MVeluOkV+oQVD25ps4XItIMbh4Md7RRifO3FloZYI+bpkynidq
         w62scWyDmF+5FUZHiZo3I7KzSmjxwVOQgm673pE6ib0S0xrp/IKxb7ukMAW2u2CkaDrV
         DDhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BUVoyvYm;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oqzXyk6zP8C/6lOSTXpmxYjiSu30lHb++ouyvKR2/b8=;
        b=cOcRjGv5Qi2PQTNvg6y+PoZ89chFxN7MgZRv8pjEzwmiD1wrzPh0yksNVBbWc5oY5Z
         I2Bo8shCRyDZsaQy7hCtFBoMcKC2ZG8y2XBUXc6s+Y6G6oRhWtR8qZ5ZqS/qIDm3BkhF
         MISLFeYERGWaSdatb7c391V36xUgU6Ze1hpM3leAj3MPpNwqaJ0sy4IYmwNRokufKK2m
         aCItsK8RFNvvY3vrc3qS30q95YUO8w5QMeS1BeembNuEUV8D9ff5sOqSnHLTKNYX8kJf
         L0/UJwl152/3mWd4l2HowJXvmPW1wh4iTqS0gOJFxGsMyH9b8FO7iGSZ0tIaeo1aitPF
         cIBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oqzXyk6zP8C/6lOSTXpmxYjiSu30lHb++ouyvKR2/b8=;
        b=mdxyjSg1Rm5LYH5l+HORyHA+jhHoK0IT67NuMfB0HZGhTYAxT87Yy+Z+NTmfBS/RQ0
         5jIQLySY0MhqWZX2mBelI8YTdHTVg/AqaMi6aQJZLccQmhmuAWZA8VuGrqh6kwPQ+Jy6
         AGW/+8k/qxg70H5usUuF47NLPo7/6KngAERuMlgdKh5UiUOS7HstMt7FR3glYaQVUjeK
         E/75V4m/Ud6J88DYve+T3H2aRPY3qCQTQ98Jd6mOsgu+c2pdQLn6TRNiYbtf3bZu1+RI
         HS4glLyEFQAwOBR6VY2mg6hyBthOiu4pSVRcPFRoTXkLczgzJdBPCMZa53YBzESV8Gn7
         PpxQ==
X-Gm-Message-State: AOAM532N9zyh+X0qe1naF7X+7qtwUNwkULSh9Yxz/nrlJyxQkt38S1PJ
	/GFgJAQfK/HyNUsGra7xMY4=
X-Google-Smtp-Source: ABdhPJzWcBO3XvV48XjYSWtcUBk9jEb4a7Z5j31jn+s33oGfzZxwknlqowgB2IiEw/AylbZN3hjj1g==
X-Received: by 2002:a17:90a:db8a:: with SMTP id h10mr9544490pjv.197.1594211881824;
        Wed, 08 Jul 2020 05:38:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:46cd:: with SMTP id n13ls697455pgr.2.gmail; Wed, 08 Jul
 2020 05:38:01 -0700 (PDT)
X-Received: by 2002:a63:1a44:: with SMTP id a4mr35828217pgm.281.1594211881354;
        Wed, 08 Jul 2020 05:38:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594211881; cv=none;
        d=google.com; s=arc-20160816;
        b=euKBwDDWdwPDGwQLC1njnrtCXQUp5HR0BZD2uyISv4/VVbVa1rBKzrRKelsEITrojV
         9+ZkDzuWBvp7LXkclKrl8gBT6z9qW4hd+KWv6f+0SXcJvFJ1mY2ZftjUcNdWqMbj/SEM
         wWirCiAJwIotQkgnrKSTak783THkLF1NJAJCxgSoJt0DgLYg9u89Z3QnMW29bIK+3XxY
         +v9koQKuFKd0bOl8iTdvPlsI5XkAL+wqfq+VWuXZEEESG5Q3OUCCkmoXFtK2HvmOFmR2
         BknjOoQPmTJooAYlqzV6iK1Cl6hKFgVqgr/8hwIjyinjLGQu5GfnPXoBICBHwRcTKfIi
         qPcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kee2YtmMHgv7A7dyVw1lKxR+tADNMGpw4FHY05ErWKs=;
        b=HB2V3xLE6dzz2rx9R56XyIht7f4kgS6JBTX3RDx7mB3nIcAfx+TObvpDApvfiN4/NF
         HSGZtpFFv5k8iTkVgAinknZCaVYtpx8P8AAjBR0RuFJ0EeE1N9ThxB/XiM7J/8juN5H8
         qZNxbFwEx9uehrEXY25Gby4/EC2EvxeKW3p+NDV0A4K/4cD+aYLDfSqmohnFCL3T87of
         JhFU263vguEsDk1fS/2rtWOlHmU1ZMWTQXY0U7Acjw24ujA2e+ZdVHHOPq0qUnYEIlIX
         6nMZQ+pis8zdN2xr78TJjTjP48eI92tT8LTjUr9TWMmTokkw0Q9qQrYhtRxOTOv1U5P+
         tu5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BUVoyvYm;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id 10si710926pfp.0.2020.07.08.05.38.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Jul 2020 05:38:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id 1so2211997pfn.9
        for <kasan-dev@googlegroups.com>; Wed, 08 Jul 2020 05:38:01 -0700 (PDT)
X-Received: by 2002:a62:52cd:: with SMTP id g196mr53579108pfb.178.1594211880888;
 Wed, 08 Jul 2020 05:38:00 -0700 (PDT)
MIME-Version: 1.0
References: <20200706115039.16750-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200706115039.16750-1-walter-zh.wu@mediatek.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 8 Jul 2020 14:37:49 +0200
Message-ID: <CAAeHK+zQDeo5K8D9QTQvdkp4H36s_wPPcGDizJ-ZDD0YAtLeRw@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: fix KASAN unit tests for tag-based KASAN
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BUVoyvYm;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Jul 6, 2020 at 1:50 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
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
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
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
> - KUnit-KASAN Integration patchset is not merged yet. My patch should
>   have conflict with it, if needed, we can continue to wait it.
>
> changes since v2:
> - Add one marco to make unit tests more readability.
>
> ---
>  lib/test_kasan.c | 47 ++++++++++++++++++++++++++++++-----------------
>  1 file changed, 30 insertions(+), 17 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index e3087d90e00d..b5049a807e25 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -23,6 +23,8 @@
>
>  #include <asm/page.h>
>
> +#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : 13)

Let's use KASAN_SHADOW_SCALE_SIZE instead of 13 to make sure the
access always lands in the next memory granule.

With that:

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

> +
>  /*
>   * Note: test functions are marked noinline so that their names appear in
>   * reports.
> @@ -40,7 +42,8 @@ static noinline void __init kmalloc_oob_right(void)
>                 return;
>         }
>
> -       ptr[size] = 'x';
> +       ptr[size + OOB_TAG_OFF] = 'x';
> +
>         kfree(ptr);
>  }
>
> @@ -92,7 +95,8 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
>                 return;
>         }
>
> -       ptr[size] = 0;
> +       ptr[size + OOB_TAG_OFF] = 0;
> +
>         kfree(ptr);
>  }
>
> @@ -162,7 +166,8 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
>                 return;
>         }
>
> -       ptr2[size2] = 'x';
> +       ptr2[size2 + OOB_TAG_OFF] = 'x';
> +
>         kfree(ptr2);
>  }
>
> @@ -180,7 +185,9 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
>                 kfree(ptr1);
>                 return;
>         }
> -       ptr2[size2] = 'x';
> +
> +       ptr2[size2 + OOB_TAG_OFF] = 'x';
> +
>         kfree(ptr2);
>  }
>
> @@ -216,7 +223,8 @@ static noinline void __init kmalloc_oob_memset_2(void)
>                 return;
>         }
>
> -       memset(ptr+7, 0, 2);
> +       memset(ptr + 7 + OOB_TAG_OFF, 0, 2);
> +
>         kfree(ptr);
>  }
>
> @@ -232,7 +240,8 @@ static noinline void __init kmalloc_oob_memset_4(void)
>                 return;
>         }
>
> -       memset(ptr+5, 0, 4);
> +       memset(ptr + 5 + OOB_TAG_OFF, 0, 4);
> +
>         kfree(ptr);
>  }
>
> @@ -249,7 +258,8 @@ static noinline void __init kmalloc_oob_memset_8(void)
>                 return;
>         }
>
> -       memset(ptr+1, 0, 8);
> +       memset(ptr + 1 + OOB_TAG_OFF, 0, 8);
> +
>         kfree(ptr);
>  }
>
> @@ -265,7 +275,8 @@ static noinline void __init kmalloc_oob_memset_16(void)
>                 return;
>         }
>
> -       memset(ptr+1, 0, 16);
> +       memset(ptr + 1 + OOB_TAG_OFF, 0, 16);
> +
>         kfree(ptr);
>  }
>
> @@ -281,7 +292,8 @@ static noinline void __init kmalloc_oob_in_memset(void)
>                 return;
>         }
>
> -       memset(ptr, 0, size+5);
> +       memset(ptr, 0, size + 5 + OOB_TAG_OFF);
> +
>         kfree(ptr);
>  }
>
> @@ -415,7 +427,8 @@ static noinline void __init kmem_cache_oob(void)
>                 return;
>         }
>
> -       *p = p[size];
> +       *p = p[size + OOB_TAG_OFF];
> +
>         kmem_cache_free(cache, p);
>         kmem_cache_destroy(cache);
>  }
> @@ -512,25 +525,25 @@ static noinline void __init copy_user_test(void)
>         }
>
>         pr_info("out-of-bounds in copy_from_user()\n");
> -       unused = copy_from_user(kmem, usermem, size + 1);
> +       unused = copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in copy_to_user()\n");
> -       unused = copy_to_user(usermem, kmem, size + 1);
> +       unused = copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in __copy_from_user()\n");
> -       unused = __copy_from_user(kmem, usermem, size + 1);
> +       unused = __copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in __copy_to_user()\n");
> -       unused = __copy_to_user(usermem, kmem, size + 1);
> +       unused = __copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
> -       unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
> +       unused = __copy_from_user_inatomic(kmem, usermem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
> -       unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
> +       unused = __copy_to_user_inatomic(usermem, kmem, size + 1 + OOB_TAG_OFF);
>
>         pr_info("out-of-bounds in strncpy_from_user()\n");
> -       unused = strncpy_from_user(kmem, usermem, size + 1);
> +       unused = strncpy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
>
>         vm_munmap((unsigned long)usermem, PAGE_SIZE);
>         kfree(kmem);
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706115039.16750-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzQDeo5K8D9QTQvdkp4H36s_wPPcGDizJ-ZDD0YAtLeRw%40mail.gmail.com.
