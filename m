Return-Path: <kasan-dev+bncBCMIZB7QWENRBIWD5T5AKGQESZP2AXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 34E262659F5
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 09:05:08 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id v67sf2529177vsb.12
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 00:05:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599807907; cv=pass;
        d=google.com; s=arc-20160816;
        b=WcOR4kLr8Zyb5m1tyFMFi+BeAEF0LadoZpHeinEWw+q/bCB4qmtkf1C8bkm6gxm93f
         son+zUCfpyByEoJtINtJflxVy0HjDQXWV88hsVpCdvP06etzToikzxV6IiH1NLCGUljj
         kSrOvuNzUDB63xOaD0I4rW0hLU6vAgufEX1ivavbtBAoCxi+wtlZki1+lf1Gfs/oaXGP
         pzp0+l5QgDoBnH2LeUImg4GS8jFu+uWfPR3s7aZel+Hkh6kwu4MNWIVeA+ZrueAYiI8w
         dZqqG4Cf7JQILwWpNK1+G+XiY5a1rOZ684c8BX4YIRqVOJvuwOSP4StUrW7qosMKme4L
         hQxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kfSETKVPQhqDbmospqe5tdym7cvvHYynGogj/3kJ22I=;
        b=eviZGHMH/FrqylgXATEEJ3F8Sdc5wMUmSTr0NxtzfV0Ct/5V9C89KtJ9swyro9SoFK
         FYnNu4iiSsVKuBL2EEFoLeXs28+N+hZA1Lr2RrOKim2toOqSUWJSdLPsA+0lh3VFW4uh
         9659t+i+2Kt1EKcDzgvbkKsPSPsojv5AiBQjEGG0QUzwy01OrRytxrRzQucWganjKYZI
         1XhpLWZUaTCxc1DMQuUw/ngKOImuyaiE6RugRwj/M3Q7HIDDTPx+8qHHoUIhaxiCk0e+
         FQnTvdEG+edxFCr/PDVucp6o0eC8omzLGljwKWY+8Rj7+yx1CEpFzsX04CDYVAL0Q+wT
         2K7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l6I1g9C1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kfSETKVPQhqDbmospqe5tdym7cvvHYynGogj/3kJ22I=;
        b=Pz6jCoVWFYsLpSYlNPvLmcnuU9emVov3WkkkMLKVvDupFCoNpxJsRyBRDsiFHN1VVu
         bth4VXprTQwqtKdlpF9z6MC+wjfHdWDx3HayEGnBfvklyAqi+mya8l+lpHJUhChFKf3G
         aTftFEUjiyIvWqd/CJnIj9YQ/lgOgUpkf3QqZ2JD2nGhfbRKRAgIAg3hXahzKZiPJGVD
         tm2QjGbH3RRML9Rm4YMQNymU2zK2EPZAzYH2N7v2asYLaalhbQBcLLaoObleM5quaLeG
         QJZZkKOP9r3RtIxYeEqw+DUQ1UzofzeSpe2cjtRulWjYtpSKBFSPLNWBVAqYLey4vG2k
         x/GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kfSETKVPQhqDbmospqe5tdym7cvvHYynGogj/3kJ22I=;
        b=a96t94Xb4ON2lOp9fyF6MLOi1doYrTwtbs0nEETYhGn4V9G/1wCb60IMO9rCWFkE6N
         ijNybqsTrbziaH51C0tMxW4NQDQyOwnAiBRqg20XUR7cPwKUWBLLvx9rLt0JPOArwsat
         /elrzRqemDWByRGlObAoB+Zg5P7vilmwYtsrCW9KB3KRaHqB4CHz7nzZ1gncHdBooufp
         bGM/tGjgG4XfFVKMuB91gsxBOK6pm25S/XSZxjknd+feJ5CeYcxawTTz+g1hXtnyz9um
         RWd5pWKdRw+5vTB7SnHz7E/btVzAcLPFPKIliJJqblxZrCgcSQwyhNrNxpTk53V6cO+S
         2Sdw==
X-Gm-Message-State: AOAM532dvpajhT9mlj3uEh5oe9VFr00proqu48EJN0IkaUUj1kNE6O5F
	uNAcRuKPKQaY4guW4dobQ3Q=
X-Google-Smtp-Source: ABdhPJyU/WS/1Q8zkToJfPKvBvUaDLo+PKrtDkaofpBkUcWlR4dhPz12/37ybQQ1wpsWp7g5ZMyXJQ==
X-Received: by 2002:a1f:141:: with SMTP id 62mr227641vkb.2.1599807906880;
        Fri, 11 Sep 2020 00:05:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2e6:: with SMTP id j6ls184497vsj.1.gmail; Fri, 11
 Sep 2020 00:05:06 -0700 (PDT)
X-Received: by 2002:a05:6102:2132:: with SMTP id f18mr304111vsg.61.1599807906347;
        Fri, 11 Sep 2020 00:05:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599807906; cv=none;
        d=google.com; s=arc-20160816;
        b=F7PfI0Up17mTSY4tPnRM+cFtFu3R5EOvC1rfhWGWI3mbGDydLdzjIwnSN+kMJ179Y9
         3D3wXCP+lC3N8eUU8VumD/mJmBwPzlH6JQg5dYISHG28m2UEPRqgDDfECKtvpI6OPgy8
         vNw5Gp+ISAQOjE+sPFP7I+EE5eLqRTbPS2WmnYZtAkNdZ62y6uFJv+LapQ4R5+1H2TQI
         W2+TjwwN0QSyNlMAzKiF/cHjuXyVoahgi7Gjk16hZjVLJzOt15QNNXRo+G9hcsiOniFk
         jzAVP8+BVDJPZDwQAl+QBPa5WjmuC4e4a1BtvxHLro5t8yUGdYLNsXVXeT4iIs0qSWJi
         6q7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8qYTA7a/mDb0x7v76SumPW6fQ7bLMrnrWY5ltUv9JNU=;
        b=zByCiIU7HWfoPdCK5ci7rHPSWIb687xxHYAN4LHNrivFc3XTUdMMdhXeyq7As4uGsr
         Ub9CpSiBQqXWrTj0qvSKucI62Kj6uGNeDL+WD1G97gtE/sTRMxt6A5LtiLM0I6lw6e/4
         aNEFL70dpvXNv6WB5K/fMq93K72AlVh/PsWQcDPl2BwwbUg9IBiYeS8Ffc4X3Eue4uIy
         kB+rFI7QkivPuAMxkh66Ng1y/gFqtMJDQ0b/hCMlZr2oPhsJ+RWO9TwZo5BslnYU0Tlb
         KbDIghJgse3T8chE7xM2qUp3y+KwVa/neQ7GqlRZoFE7DxWnAu6flq4HtK0p9QHMaJwN
         hUuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l6I1g9C1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id 134si109370vkx.0.2020.09.11.00.05.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 00:05:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id z18so4702086qvp.6
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 00:05:06 -0700 (PDT)
X-Received: by 2002:a0c:c24a:: with SMTP id w10mr609462qvh.99.1599807905731;
 Fri, 11 Sep 2020 00:05:05 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-7-elver@google.com>
In-Reply-To: <20200907134055.2878499-7-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 09:04:54 +0200
Message-ID: <CACT4Y+b=Ph-fD_K5F_TNMp_dTNjD7GXGT=OXogrKc_HwH+HHwQ@mail.gmail.com>
Subject: Re: [PATCH RFC 06/10] kfence, kasan: make KFENCE compatible with KASAN
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=l6I1g9C1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Mon, Sep 7, 2020 at 3:41 PM Marco Elver <elver@google.com> wrote:
>
> From: Alexander Potapenko <glider@google.com>
>
> We make KFENCE compatible with KASAN for testing KFENCE itself. In
> particular, KASAN helps to catch any potential corruptions to KFENCE
> state, or other corruptions that may be a result of freepointer
> corruptions in the main allocators.
>
> To indicate that the combination of the two is generally discouraged,
> CONFIG_EXPERT=y should be set. It also gives us the nice property that
> KFENCE will be build-tested by allyesconfig builds.
>
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  lib/Kconfig.kfence | 2 +-
>  mm/kasan/common.c  | 7 +++++++
>  2 files changed, 8 insertions(+), 1 deletion(-)
>
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> index 7ac91162edb0..b080e49e15d4 100644
> --- a/lib/Kconfig.kfence
> +++ b/lib/Kconfig.kfence
> @@ -10,7 +10,7 @@ config HAVE_ARCH_KFENCE_STATIC_POOL
>
>  menuconfig KFENCE
>         bool "KFENCE: low-overhead sampling-based memory safety error detector"
> -       depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
> +       depends on HAVE_ARCH_KFENCE && (!KASAN || EXPERT) && (SLAB || SLUB)
>         depends on JUMP_LABEL # To ensure performance, require jump labels
>         select STACKTRACE
>         help
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 950fd372a07e..f5c49f0fdeff 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -18,6 +18,7 @@
>  #include <linux/init.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
> +#include <linux/kfence.h>
>  #include <linux/kmemleak.h>
>  #include <linux/linkage.h>
>  #include <linux/memblock.h>
> @@ -396,6 +397,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>         tagged_object = object;
>         object = reset_tag(object);
>
> +       if (is_kfence_address(object))
> +               return false;

Is this needed?
At least in the slab patch I see that we do :

if (kfence_free(objp)) {
  kmemleak_free_recursive(objp, cachep->flags);
  return;
}

before:

/* Put the object into the quarantine, don't touch it for now. */ /*
Put the object into the quarantine, don't touch it for now. */
if (kasan_slab_free(cachep, objp, _RET_IP_)) if
(kasan_slab_free(cachep, objp, _RET_IP_))
  return; return;


If it's not supposed to be triggered, it can make sense to replace
with BUG/WARN.


>         if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
>             object)) {
>                 kasan_report_invalid_free(tagged_object, ip);
> @@ -444,6 +448,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>         if (unlikely(object == NULL))
>                 return NULL;
>
> +       if (is_kfence_address(object))
> +               return (void *)object;
> +
>         redzone_start = round_up((unsigned long)(object + size),
>                                 KASAN_SHADOW_SCALE_SIZE);
>         redzone_end = round_up((unsigned long)object + cache->object_size,
> --
> 2.28.0.526.ge36021eeef-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb%3DPh-fD_K5F_TNMp_dTNjD7GXGT%3DOXogrKc_HwH%2BHHwQ%40mail.gmail.com.
