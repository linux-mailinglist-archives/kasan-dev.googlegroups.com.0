Return-Path: <kasan-dev+bncBCMIZB7QWENRB2F67P2AKGQERUIBBZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 24A111B2563
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 13:56:26 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id e3sf9385734qvs.16
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 04:56:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587470185; cv=pass;
        d=google.com; s=arc-20160816;
        b=xIuoUUpIrJ3kgOq2EGQXGPc0ogo0+8MvtHFPM6J6a89b7xHfY7lZJapOqDCCBNyLYp
         dxDht41tePQsEvIfAtUlmJgSUdlx70EEvwIdYwCCO36dmM13j0o7ofvf1hU+mAOccuDY
         wFl2CS13NrpB4aDwJdHspVQzM1uY5zBd0xyOIzEbHjXWyhDCceVZ/W4Ny8G0WHDgF4gq
         Wz3BGiidZ/HXAc+T4dZYAV5fbLp7I1N0IRfmPG5GToIluitxoytXfHf2isDyG4qjGUzz
         QpVmbpOal/JN18W4vAFULuYRDRUxrMDwFOfrpsTHTBvEn3y+m6YvG20c8dBVQwaTGlwq
         biOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=J4yAilDj1J+PMGBISbp60l9A2tE5FTUQ8hcTeSVnikU=;
        b=J0bqAYfQAMtH4CsGtQrt7ra31Z9v0mJF9TSRfPdgUK63ei7f94tCayl+wHF9a5EdUn
         QjtulQhVK0i2wrwDpk5LnuKV2aojp0eQkZ7La4EsOTwQI7g6vE3GlkVoZh+K25RrSd/4
         x24hAn+l+dA8BfLRnfCaB9f07HQ1Es5VQf/9i4r3yhGN5iDzExTGGM0/u2TIIdEQMg/d
         xSVA5PBES/QNNmAyzE8rmvfcDXOQo+ePduJg436Pb8yX4jLGa7IQyWBLshJRqI11+Vxl
         FDhA59viAPIYC00o/FlLW0BWBITa/ixSp7opDr+KYM+71O6UIspNwx7iux0NPqXGa9lx
         7m2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aCc5+8+A;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J4yAilDj1J+PMGBISbp60l9A2tE5FTUQ8hcTeSVnikU=;
        b=tctZ8MChkRpuN/QJIKhK56xzhoxAoi2RO+YcBqabVbCRqSkost6z3gu9d2fO6q53lM
         P5numToHBrCDQuK7MwO6fdZL5LwlZ5CFk6UnShOU5ODHqiTcT3AUJ91PBLCp0beMXfJh
         8YejuAeWBVmsscpNcH3Ae0vDd9q/WwMFZ2dTclCrEczBaZhoI8T4vRH/kPe7mVr8DIGI
         9dvm4bUV8gyx+2jyPe2WhK/EsOLWa/coWGx5YXjJsBc3zkysJGKSJ8UO3uJ3JqjX0bIH
         YhqFRpwm9rmWeGzgRGLZHgEDnj9wkL1WGGpksY4EUvIgw06bI3p1D2nRMY41/YtJv5ez
         954Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J4yAilDj1J+PMGBISbp60l9A2tE5FTUQ8hcTeSVnikU=;
        b=oL5BxFAvhBt+1Ga9nDJU21lIiGFLWUly8d4i0p8TRN7LC66UOtGxMqzFy7Ylhvbbp1
         JSKwQLNdIsNYKsEjfBSg6bvWYFiPIhQlprF1Y2AvScQfBTlAddhr93xso2IdLbVmpjbh
         L+lAzxPNRCtKbiCaIur8WXLh98x2Xpc+UcNKKxCEjl9B9UKHCBByudGcQIKEIc1gFFSQ
         YUSoQrhN5qkRA7UOKMEoPhJLbH99rTwBLmvUsNqaxhY4jN/BkN7GY/6nB5gl7TT7ozuR
         hME3Y9o51EbK4cx5GJXXIPPyc5IpvQfdXrgxkTdLzvbCp+c1FZdVFF1ThBGvSNNroPXV
         CBdA==
X-Gm-Message-State: AGi0PubjJrcvOD0KwI1ugUcjYKf/vBlH9uKDI5qpovgDA6jpe2P+jrQu
	ywdGH4uQ9+SAJVtvlBoBg2M=
X-Google-Smtp-Source: APiQypKrBUS/sDYE7ndmp5KckqdzgJdSmmkV8JHHU6B7rwf5OAbI8I9VOJtAN1u+zlS1uIHzBMgHcA==
X-Received: by 2002:ac8:39a2:: with SMTP id v31mr20563282qte.373.1587470184980;
        Tue, 21 Apr 2020 04:56:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:232:: with SMTP id u18ls206434qkm.9.gmail; Tue, 21
 Apr 2020 04:56:24 -0700 (PDT)
X-Received: by 2002:a37:63d1:: with SMTP id x200mr21633391qkb.144.1587470184630;
        Tue, 21 Apr 2020 04:56:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587470184; cv=none;
        d=google.com; s=arc-20160816;
        b=I6KU5KhyrHVfFtsPiOpfS3PdlTa+sjf66jlO/TULU07M3WCtn4ae4NktPn7CUXLnfz
         GPigSxi9dPNeRBtusvb/pYBn95KXPRdyHbXrm1AIEhtYB94+ydDGkonPIpxOeppcBlR1
         f77bigu1XaZYk6wPDBck6uNP2abDpcxdL9c2bnFU5YAeVoxeftp9mU3udfVxQobj5yY4
         JC4cDqErxxOuqKWcS0pu8+WAcJwdV/Lqr/8We4Sp4DUcuFBzepVleXFvqyeN9xXxz1lK
         ZEXe6jHMTiaRQvD7YW27a9Uc7S69JLYQfdmvjuSgz386cya/VJO2cOrlI2E//YaWSFuv
         rkgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Gy/qiieN90UJKr/c+cYCi+ub2I5kQwPARkN3XL1JRak=;
        b=IpX9YKUP4JzYlyZWix2Ys6Mxml7344tH8Td8uJGejrONO9chDFQTisIkNcTMAltOeX
         e/z0jI3RmkPU9582aEkUN2pOPIo7b9gpUxEv+0gJ0XOVKizAjDbeynXf4CyhZoSrmmbh
         36yJoOuahDlRthsWKYsfpHEdA7RbT0E+dW0RDs+LZeZ8qrghP1dWeDpK+UdHVySxPNw4
         qXbncZ3j/vCLq6izppstim3XxZ3Fu7eJps6i17nE/qTOlEChNUZorlYgMBqtDKUQcffV
         Lvvs4dpKVLQIUV2ruxZnd0tH1BGkocYcCN0a/ozbK+06udR94HtH9BROqJUMSxaaSi94
         G1Qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aCc5+8+A;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id p9si275841qtn.1.2020.04.21.04.56.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Apr 2020 04:56:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id t3so14170135qkg.1
        for <kasan-dev@googlegroups.com>; Tue, 21 Apr 2020 04:56:24 -0700 (PDT)
X-Received: by 2002:a37:bc47:: with SMTP id m68mr21780368qkf.8.1587470184030;
 Tue, 21 Apr 2020 04:56:24 -0700 (PDT)
MIME-Version: 1.0
References: <20200421014007.6012-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200421014007.6012-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Apr 2020 13:56:12 +0200
Message-ID: <CACT4Y+af5fegnN9XOUSkf_B62J5sf2ZZbUwYk=GxtSmAhF3ryQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix KASAN unit tests for tag-based KASAN
To: Walter Wu <walter-zh.wu@mediatek.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, Patricia Alfonso <trishalfonso@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aCc5+8+A;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Tue, Apr 21, 2020 at 3:40 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> When we use tag-based KASAN, then KASAN unit tests don't detect
> out-of-bounds memory access. Because with tag-based KASAN the state
> of each 16 aligned bytes of memory is encoded in one shadow byte
> and the shadow value is tag of pointer, so we need to read next
> shadow byte, the shadow value is not equal to tag of pointer,
> then tag-based KASAN will detect out-of-bounds memory access.
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Matthias Brugger <matthias.bgg@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> ---
>  lib/test_kasan.c | 62 ++++++++++++++++++++++++++++++++++++++++++------
>  1 file changed, 55 insertions(+), 7 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index e3087d90e00d..a164f6b47fe5 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -40,7 +40,12 @@ static noinline void __init kmalloc_oob_right(void)
>                 return;
>         }

Hi Walter,

This would be great to have!
But I am concerned about these series that port KASAN tests to KUNIT:
https://lkml.org/lkml/2020/4/17/1144
I suspect it will be one large merge conflict. Not sure what is the
proper way to resovle this. I've added authors to CC.


> +#ifdef CONFIG_KASAN_GENERIC
>         ptr[size] = 'x';
> +#else
> +       ptr[size + 5] = 'x';
> +#endif
> +

For this particular snippet I think we can reduce amount of idef'ery
and amount of non-compiled code in each configuration with something
like:

  ptr[size + 5] = 'x';
  if (ENABLED(CONFIG_KASAN_GENERIC))
      ptr[size] = 'x';

One check runs always (it should pass in both configs, right?). The
only only in GENERIC, but it's C-level if rather than preprocessor.
KUNIT should make 2 bugs per test easily expressable (and testable).




>         kfree(ptr);
>  }
>
> @@ -92,7 +97,12 @@ static noinline void __init kmalloc_pagealloc_oob_right(void)
>                 return;
>         }
>
> +#ifdef CONFIG_KASAN_GENERIC
>         ptr[size] = 0;
> +#else
> +       ptr[size + 6] = 0;
> +#endif
> +
>         kfree(ptr);
>  }
>
> @@ -162,7 +172,11 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
>                 return;
>         }
>
> +#ifdef CONFIG_KASAN_GENERIC
>         ptr2[size2] = 'x';
> +#else
> +       ptr2[size2 + 13] = 'x';
> +#endif
>         kfree(ptr2);
>  }
>
> @@ -180,7 +194,12 @@ static noinline void __init kmalloc_oob_krealloc_less(void)
>                 kfree(ptr1);
>                 return;
>         }
> +
> +#ifdef CONFIG_KASAN_GENERIC
>         ptr2[size2] = 'x';
> +#else
> +       ptr2[size2 + 2] = 'x';
> +#endif
>         kfree(ptr2);
>  }
>
> @@ -216,7 +235,11 @@ static noinline void __init kmalloc_oob_memset_2(void)
>                 return;
>         }
>
> +#ifdef CONFIG_KASAN_GENERIC
>         memset(ptr+7, 0, 2);
> +#else
> +       memset(ptr+15, 0, 2);
> +#endif
>         kfree(ptr);
>  }
>
> @@ -232,7 +255,11 @@ static noinline void __init kmalloc_oob_memset_4(void)
>                 return;
>         }
>
> +#ifdef CONFIG_KASAN_GENERIC
>         memset(ptr+5, 0, 4);
> +#else
> +       memset(ptr+15, 0, 4);
> +#endif
>         kfree(ptr);
>  }
>
> @@ -249,7 +276,11 @@ static noinline void __init kmalloc_oob_memset_8(void)
>                 return;
>         }
>
> +#ifdef CONFIG_KASAN_GENERIC
>         memset(ptr+1, 0, 8);
> +#else
> +       memset(ptr+15, 0, 8);
> +#endif
>         kfree(ptr);
>  }
>
> @@ -265,7 +296,11 @@ static noinline void __init kmalloc_oob_memset_16(void)
>                 return;
>         }
>
> +#ifdef CONFIG_KASAN_GENERIC
>         memset(ptr+1, 0, 16);
> +#else
> +       memset(ptr+15, 0, 16);
> +#endif
>         kfree(ptr);
>  }
>
> @@ -281,7 +316,11 @@ static noinline void __init kmalloc_oob_in_memset(void)
>                 return;
>         }
>
> +#ifdef CONFIG_KASAN_GENERIC
>         memset(ptr, 0, size+5);
> +#else
> +       memset(ptr, 0, size+7);
> +#endif
>         kfree(ptr);
>  }
>
> @@ -415,7 +454,11 @@ static noinline void __init kmem_cache_oob(void)
>                 return;
>         }
>
> +#ifdef CONFIG_KASAN_GENERIC
>         *p = p[size];
> +#else
> +       *p = p[size + 8];
> +#endif
>         kmem_cache_free(cache, p);
>         kmem_cache_destroy(cache);
>  }
> @@ -497,6 +540,11 @@ static noinline void __init copy_user_test(void)
>         char __user *usermem;
>         size_t size = 10;
>         int unused;
> +#ifdef CONFIG_KASAN_GENERIC
> +       size_t oob_size = 1;
> +#else
> +       size_t oob_size = 7;
> +#endif
>
>         kmem = kmalloc(size, GFP_KERNEL);
>         if (!kmem)
> @@ -512,25 +560,25 @@ static noinline void __init copy_user_test(void)
>         }
>
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
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200421014007.6012-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Baf5fegnN9XOUSkf_B62J5sf2ZZbUwYk%3DGxtSmAhF3ryQ%40mail.gmail.com.
