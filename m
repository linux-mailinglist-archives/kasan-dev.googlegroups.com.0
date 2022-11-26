Return-Path: <kasan-dev+bncBDW2JDUY5AORBNEORGOAMGQE7RNYRRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C4E03639752
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 18:04:53 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id m62-20020a25d441000000b006f1ccc0feffsf5782282ybf.9
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 09:04:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669482292; cv=pass;
        d=google.com; s=arc-20160816;
        b=N1gcZex/xMIuq8io6tRJlRHeARXV/85uKLOUTjLsCJPowwXQhZ3HrlLu+CiiGfO3bL
         etgSc9NCSLKsYiiHPTZlJOSRl6D2R6Rj3kr9yhBzqu43/L3s5/QXk76DjCA7dIb9NVPn
         K547QCQEwPVgt9Y1EhihTntuSPqo5xPsTGI7CS6raeBrXjlYWfdDvo8hGAKMeqSV9+mW
         yfdJN+q815rqPDt9X+Alf9nbSaFV9wZm2sSa5DMjdinSil90wM7jbFRU3V0qBwIgGxnG
         jgwkrO0KRxb0f6529UOVV8WNKlaKoRhLR8oc7P9r4by149Hv39HQI4cqxOMxtuFkkTTY
         rmDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=xbydFk8xV686d8ZXeHoNesAfDXnyTCLBs/oXDzF3tMI=;
        b=lPs1yNFRPghGdzrkKtkzj4acUUQxi2g4Bh+mUGIrk5zR1dAJYVmUrzRRk4MyWSnG+p
         THrFfdTlmFyHxd3/mNMt2sRBobgzJohvcQ968ejqcXb6aALQx+/EORV/k2WYJ2kuhbkG
         F2nF+0sobkqSI3+H5FKHfBooPKwOH2sAkQL2fCpmQ318j3mhwIEgDNXnM67HO8krIKXX
         n2VMqG+9l8h2LFa5p0SEFDWAaN/HK7N6yHlkuKHLak5dO3371cLxJKcxk+jzVnFxC2b5
         ZZr+7bXt1pK6Z4OUlAvEbk5WS8YHY16025vpRq9yh8EKkF/pw1869BwtDPphEFaCWd6/
         zX6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=cUl3qd8u;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xbydFk8xV686d8ZXeHoNesAfDXnyTCLBs/oXDzF3tMI=;
        b=Xbq+tZQ3JsmhAOkhRiGcUfva0Kthtbb34YQGbFn4H2mcKQ0y/BGoRbKVzNFU6Udk69
         QN7K5uyM/ZFTJX0XPIVB1EI6byHT4115PEbTI31mPDPO7b4KWPaAO9etaXIP1Fa6ynqC
         3EJrLHKRirhYs0dD+XnIcFSDj0bkjoesd/1WMRe/pqeAT0it+E09X8xdEjaRL7Z18NoK
         4X7M2kRZCuc8VXx0KLqxV17zHnSmrdo4xXNI/7Ygl4U6kTAmoEptL8Qehd45B3eFCX5z
         TSHaYTBAneoku+ISSVCJ4ru1FybACUp4I2GKRSCrJ3T41FaKq9/5h3UcwUBTYT3fX0vo
         F4nA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=xbydFk8xV686d8ZXeHoNesAfDXnyTCLBs/oXDzF3tMI=;
        b=CbcUcyfNk8DsPgSTSakEq3BoB8sjOMy63AoTx5nsAtgFL1+M4z9oybwJjdhD0A80x7
         /jZ8OHo6cu7hInOyUed5mLFjONAKHqK9wE6e/V6WEU8Y6YWzEc8fqip5MmH6AOg/1yAW
         qXwoaGFlDVmHAiE8aApqkTfOOnfL9NB0Ln1qXJtfivSneWTvOD1/m/1ucyjpbUdictKg
         NihHTq3K5W7TGC8vEejAV80KGsEnLUZtcY0IS6Y/D+ay6P2cpz3xx2SRfwWjR6yZkBhY
         U3WD2bbfbtLjOAnT3WnY7MUPHTVXVOTp1qAe+myBVkmGP8h4OCiXkSvtUnknhp/0PzDZ
         DFtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xbydFk8xV686d8ZXeHoNesAfDXnyTCLBs/oXDzF3tMI=;
        b=eRR35z7XUvu3eRzB++RhGr50C5ItZkpve6WH+qsC+jFCOJ+VDnn3d04HICyWTxlsjS
         xTxHL/JX7kM8vaRr8axX47LQepzRHoKVkX26qG/Ayd8eW+WKBnCxbyN6m6XBEeLalRZL
         X8vw1I/UzITu2wpuLVRxwYC2Ttc078tPNoXOoH2ZKN3HpC7r+/kyqx3xvD4oEKX58iX7
         sEt/AQ5PsyjE/i1E4j+aR0LXWWXPjsHbDdaVQF76hbmQLhnlwk9p3OSInZBHuCudP5S5
         4r/ZhdtSHym46ZkEn18Glk7pFBvW+G1AXLoyv/4v46ypc/DO6fZSzYb95HuKlx7rfY8p
         iJnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmcXEeBYnKf+QWRtEg+G0ZTq47dfY7KcPQPyFayzlWoHIzPjbbI
	phWuIG/NyvEcR9ZB69tqJkw=
X-Google-Smtp-Source: AA0mqf4MTAjEP0GMpDfkjP2vygLfp8FgT8n29MzvZpKHaEkftClKrfzOS43zaF1WQtc7ztrti6F+zg==
X-Received: by 2002:a25:76c7:0:b0:6f4:9bf0:b5db with SMTP id r190-20020a2576c7000000b006f49bf0b5dbmr2947007ybc.435.1669482292404;
        Sat, 26 Nov 2022 09:04:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:f61f:0:b0:6e8:6123:5a3f with SMTP id t31-20020a25f61f000000b006e861235a3fls3621177ybd.8.-pod-prod-gmail;
 Sat, 26 Nov 2022 09:04:51 -0800 (PST)
X-Received: by 2002:a25:8743:0:b0:6f0:c999:8115 with SMTP id e3-20020a258743000000b006f0c9998115mr15102667ybn.546.1669482291675;
        Sat, 26 Nov 2022 09:04:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669482291; cv=none;
        d=google.com; s=arc-20160816;
        b=VT4Ng2sbWYMDzCpSx8FNtZ4hskjuWCopBXrTS8YEsNfLHxckoY/HOJc62O2KbjLCYn
         nctFfGg0p5a6R+LZk2Zul4Xf/fye2pGmBCNv4Bs5Hvyzb9gHZoYYAgGCSa3wMDyQB7j2
         DnUSsk+mqexDXc81GBcFGtC7cLz1hjS1g7rhvQwtaDYhhFyO8vaZEBlum6s5dbPGGbO2
         dK96hBYKbi18BkbNZP33pZT/7i6Kt/eh9a5u8NX5axAXLkEys4oCinhNB9oE0SAL/FYe
         Uh94R4edRBz+NdU465pvo19rQhZmlxCjK29tU8qYhrD7vEdWn3L5MBff7ngcZuF+8xDy
         zu4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uKmnIaloULHriFcopQa51nxjENCmgGQKjpIIPfSTFtA=;
        b=ua8SBi76iKQpQbA5zxcRLwm0iKzG0wPlRkABBZwZFjTizOHS/byiaUoR45iK0R+6cj
         5jz3s4agi8oWfoJ/iL+ZTd2fSZSTzpzQUOwZlGV9wy8wJvBlyb7RSfCNsdhzS9xHPo6p
         7ZJSqTz/N9W/7eepEp2YGoCMsc2KoEqUfdSJwozsoNEikRzkCF27rSU5SKDJqjN5u9id
         FPsXJlDRRWunbrSj+TWL4VKFoklj2k9MiKCu+hSGS27u1lVzfzPtR/IGl1t3J65DMIc3
         TI97ZCozkMcUxqCzNlT/MiqPzMXr/A3jHt3/CaOYnzSYDoQgAu+IjN/gdN2ufHxhaua5
         5LVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=cUl3qd8u;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id h22-20020a25d016000000b006ea2fed115bsi438167ybg.4.2022.11.26.09.04.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Nov 2022 09:04:51 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id b4so6699700pfb.9
        for <kasan-dev@googlegroups.com>; Sat, 26 Nov 2022 09:04:51 -0800 (PST)
X-Received: by 2002:a63:1659:0:b0:477:98cc:3cfe with SMTP id
 25-20020a631659000000b0047798cc3cfemr20169345pgw.508.1669482290899; Sat, 26
 Nov 2022 09:04:50 -0800 (PST)
MIME-Version: 1.0
References: <20221118035656.gonna.698-kees@kernel.org>
In-Reply-To: <20221118035656.gonna.698-kees@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 26 Nov 2022 18:04:39 +0100
Message-ID: <CA+fCnZfVZLLmipRBBMn1ju=U6wZL+zqf7S2jpUURPJmH3vPLNw@mail.gmail.com>
Subject: Re: [PATCH v2] mm: Make ksize() a reporting-only function
To: Kees Cook <keescook@chromium.org>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=cUl3qd8u;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::429
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

On Fri, Nov 18, 2022 at 4:57 AM Kees Cook <keescook@chromium.org> wrote:
>
> With all "silently resizing" callers of ksize() refactored, remove the
> logic in ksize() that would allow it to be used to effectively change
> the size of an allocation (bypassing __alloc_size hints, etc). Users
> wanting this feature need to either use kmalloc_size_roundup() before an
> allocation, or use krealloc() directly.
>
> For kfree_sensitive(), move the unpoisoning logic inline. Replace the
> some of the partially open-coded ksize() in __do_krealloc with ksize()
> now that it doesn't perform unpoisoning.
>
> Adjust the KUnit tests to match the new ksize() behavior.
>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Christoph Lameter <cl@linux.com>
> Cc: Pekka Enberg <penberg@kernel.org>
> Cc: David Rientjes <rientjes@google.com>
> Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Roman Gushchin <roman.gushchin@linux.dev>
> Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: linux-mm@kvack.org
> Cc: kasan-dev@googlegroups.com
> Acked-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
> v2:
> - improve kunit test precision (andreyknvl)
> - add Ack (vbabka)
> v1: https://lore.kernel.org/all/20221022180455.never.023-kees@kernel.org
> ---
>  mm/kasan/kasan_test.c | 14 +++++++++-----
>  mm/slab_common.c      | 26 ++++++++++----------------
>  2 files changed, 19 insertions(+), 21 deletions(-)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 7502f03c807c..fc4b22916587 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -821,7 +821,7 @@ static void kasan_global_oob_left(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
>
> -/* Check that ksize() makes the whole object accessible. */
> +/* Check that ksize() does NOT unpoison whole object. */
>  static void ksize_unpoisons_memory(struct kunit *test)
>  {
>         char *ptr;
> @@ -829,15 +829,19 @@ static void ksize_unpoisons_memory(struct kunit *test)
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
>         real_size = ksize(ptr);
> +       KUNIT_EXPECT_GT(test, real_size, size);
>
>         OPTIMIZER_HIDE_VAR(ptr);
>
> -       /* This access shouldn't trigger a KASAN report. */
> -       ptr[size] = 'x';
> +       /* These accesses shouldn't trigger a KASAN report. */
> +       ptr[0] = 'x';
> +       ptr[size - 1] = 'x';
>
> -       /* This one must. */
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
> +       /* These must trigger a KASAN report. */
> +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);

Hi Kees,

I just realized there's an issue here with the tag-based modes, as
they align the unpoisoned area to 16 bytes.

One solution would be to change the allocation size to 128 -
KASAN_GRANULE_SIZE - 5, the same way kmalloc_oob_right test does it,
so that the last 16-byte granule won't get unpoisoned for the
tag-based modes. And then check that the ptr[size] access fails only
for the Generic mode.

Thanks!

>
>         kfree(ptr);
>  }
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 8276022f0da4..27caa57af070 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1335,11 +1335,11 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
>         void *ret;
>         size_t ks;
>
> -       /* Don't use instrumented ksize to allow precise KASAN poisoning. */
> +       /* Check for double-free before calling ksize. */
>         if (likely(!ZERO_OR_NULL_PTR(p))) {
>                 if (!kasan_check_byte(p))
>                         return NULL;
> -               ks = kfence_ksize(p) ?: __ksize(p);
> +               ks = ksize(p);
>         } else
>                 ks = 0;
>
> @@ -1407,21 +1407,21 @@ void kfree_sensitive(const void *p)
>         void *mem = (void *)p;
>
>         ks = ksize(mem);
> -       if (ks)
> +       if (ks) {
> +               kasan_unpoison_range(mem, ks);
>                 memzero_explicit(mem, ks);
> +       }
>         kfree(mem);
>  }
>  EXPORT_SYMBOL(kfree_sensitive);
>
>  size_t ksize(const void *objp)
>  {
> -       size_t size;
> -
>         /*
> -        * We need to first check that the pointer to the object is valid, and
> -        * only then unpoison the memory. The report printed from ksize() is
> -        * more useful, then when it's printed later when the behaviour could
> -        * be undefined due to a potential use-after-free or double-free.
> +        * We need to first check that the pointer to the object is valid.
> +        * The KASAN report printed from ksize() is more useful, then when
> +        * it's printed later when the behaviour could be undefined due to
> +        * a potential use-after-free or double-free.
>          *
>          * We use kasan_check_byte(), which is supported for the hardware
>          * tag-based KASAN mode, unlike kasan_check_read/write().
> @@ -1435,13 +1435,7 @@ size_t ksize(const void *objp)
>         if (unlikely(ZERO_OR_NULL_PTR(objp)) || !kasan_check_byte(objp))
>                 return 0;
>
> -       size = kfence_ksize(objp) ?: __ksize(objp);
> -       /*
> -        * We assume that ksize callers could use whole allocated area,
> -        * so we need to unpoison this area.
> -        */
> -       kasan_unpoison_range(objp, size);
> -       return size;
> +       return kfence_ksize(objp) ?: __ksize(objp);
>  }
>  EXPORT_SYMBOL(ksize);
>
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfVZLLmipRBBMn1ju%3DU6wZL%2Bzqf7S2jpUURPJmH3vPLNw%40mail.gmail.com.
