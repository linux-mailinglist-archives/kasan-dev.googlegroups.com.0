Return-Path: <kasan-dev+bncBCCMH5WKTMGRBO6MV76QKGQEKMOE5FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 028F82AF207
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 14:25:17 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id p67sf1379042iod.9
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 05:25:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605101115; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ae5Xkh7wtP7xOg1UshG4kHITwbflghB/2NtrCz2Rcv+0hcalVLMZPlNUF36FvlStcf
         Qhy549BxnArHUVxc98glQhWt8BFdPwtR54VwHm3BmPnv8JNVa1w4fAg/sK6btLITYaCu
         kQCUplnDrnHzq5ZjBUMKa1q1WvsmBwB4vsw2Dvttwb0TzSDfhuVQmgia32XVocs5ztTz
         RR8c77FXZCzjxan0NO9f4ZGSCNwHQG7h0whM8qGrII8peONpwXlXdCeFFVCZkAMTZemV
         VjAYL62l7WUk7+UYbY/mZZRKpJTvJdNDL3+JSBvNfZHFfRhOyN0U9FoX9jHIVdP20J3p
         tVxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uOLkWPHpiz94Cs9afpetDoHvyBDZYriuGVOcdBf/+u8=;
        b=Jh+cpJ7upc1YJlkSB3+GEO7JonTJeuBqIh53uO1PUrcKJCoRjBk3aLbse03WVYBKTa
         fB0Lhi8nIhrxGX7/pQQr7RtbJMy5Qmyt4x9hEPESrU9SfjonYzRXsBBDF/ZlCLLnmycu
         3rW/gvq5+E/4Xt3JYdDeTNuTjuXNNYnAtG5I/TacAQ1qHQo25R+w/wrDdcPMB+taDPzG
         xIshSYotltTvauDRANNFEkRS4aaddAxXeLqECpo4wpkad/DDsyR9T4emjh8giDXbbDw3
         OiFGIsNYeXa7THw1KOM64zGGUc9nI1yoggMKKMxRpnUqvdsQGH60dukVg4ePqMIISE+H
         +OIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W2VqwyDs;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=uOLkWPHpiz94Cs9afpetDoHvyBDZYriuGVOcdBf/+u8=;
        b=SyHcDyPKylbMJNhYiC5MhZYIgK548mg+A6aA4C2OCyp649Y7bJLCIk/nFTM2RW1hy2
         QeCbBDYelemP5E6gYuVVuggPHObWe0abunUaL+oVBBQ1O1HkGo0yg5M/b5dVwTZbXRPD
         1YJDQaK9N5s7F3kEHYn7rL7G6mUfI+L9LwDwLCHK9lOlhBW4rljTTKMUnMmo+cd9iCP7
         2LWPwDnnyToVAxRFwgkyZzCvzeYyQr+Gu7EKe5mlxyNlWJwFoolI0kafaR/+zA0Lj7Zo
         T9pmmuWz77IYPmGx7LVGMA9VVh8fOQW+j/WjyDtQXNJgAvlVsb0NjwNF/LiPU2YkQEqB
         9Qag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uOLkWPHpiz94Cs9afpetDoHvyBDZYriuGVOcdBf/+u8=;
        b=E9EmpP2jiMMYrwvArVo+2yU773RlryAYkwM0a1VhUzenM82SIdi49amrtscB0huPK6
         Jtae4ccBpYpng5RYW2qjvl6m8p79WzaCg4hmgyXTyzWyecdf3ejWxEp+qBSNoZ3ihwNX
         ylrV1CNT1p5VTOvmNHeBi2GvpjIwOLuVyuBHkOaflDb2PjROPAEbx280DyDrj+0iYYPh
         eQMcPkq/76Amj2nUml8JW3UOs1kqbdUR86rehZ/U6YHkS+UEmD2FmlrRic9gTuomBrPN
         z4EaXRU86bBju1HggkINVxFuNiY1sMLQXWvVa8dW9Y0SMGVQOFHrykxgBDzi4RSOl2bp
         nJBQ==
X-Gm-Message-State: AOAM5335mpItrqHSAgjW2GlaunaMHBzNex38hjTfDsnqypWMqCBa2ESN
	O8ieJ8rE4DBdu1asY4xAz3I=
X-Google-Smtp-Source: ABdhPJwLFjW5bZtl8FXTsfSEg+J7/M0N+dOfFz6/ko5ZjNfP+3WtlU6cU2r3Lgue+aLncluKLXBBpQ==
X-Received: by 2002:a05:6638:bc4:: with SMTP id g4mr20823562jad.21.1605101115561;
        Wed, 11 Nov 2020 05:25:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5b47:: with SMTP id p68ls3380108ilb.5.gmail; Wed, 11 Nov
 2020 05:25:15 -0800 (PST)
X-Received: by 2002:a05:6e02:111:: with SMTP id t17mr19537955ilm.79.1605101115246;
        Wed, 11 Nov 2020 05:25:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605101115; cv=none;
        d=google.com; s=arc-20160816;
        b=ZBqLATmtz/QvCSp7zS4eV46ti/SVoMMgIt3FjuraXGgbvMAgDlOJ4SSaETHh+Tbk+v
         c05wpVkLbSz2hIAOozN90hoFSu31rw8q/ONRf3NqBSgiSkEKT3Iy5NLgB6HRU2xOaQ6S
         TPPAplVqgjzfwVpZ2KDOq9bEcsGUhaXPPUb30OGgWB8vkwDi41HaUBCFEsikM95+LaCv
         7ykaUVuNJ9gc80BiRA1vWNrBiHmupBChYs+6eZ8whEPsqdcAwjA+6NaAFgEwiFBJhtMJ
         5dfwRZILy6XhwZm/pvmQRVp8xbtodHM5kdDSYDcUmn8MEcpsn3gfBKfXJDPSyTLUFfyy
         1w4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lxMzMj/D4VM40jBrYMiztVpoEGAQUw5RwBN1Z96sbhM=;
        b=uHhtwrdDD8jMpuexgYH2F0lulhjWuh7GpAO+aD5aQib2achPYX3wtaXVoNu0CxAMQL
         zC2bHhLsITkezw2BFbfOhNathzVTV5QIjrT5ByN5OBuT8/7aRq2QsBM6MT6TMpGveUvE
         V5+X/A+f56qFaCmIErQmp6yZ08789IU+YJEm9IezoLbe+9shaOsJsp9T7PmGZY0ahg7o
         a2NNejYEY5oFKEIiNmllgoPwEktNV+KqnwpJ4GYQtYW7sRLl2Y6+Dd/n0v7a0JNuXY2c
         2UEj5s4SjbddFNCTP2o1NcvwvvqLfBsS/aUV1e4PRMzzaawrVpC8JN0s68Z93hzBv6/7
         seDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W2VqwyDs;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id k16si117501ilr.2.2020.11.11.05.25.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 05:25:15 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id 3so1226704qtx.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 05:25:15 -0800 (PST)
X-Received: by 2002:ac8:454d:: with SMTP id z13mr20929301qtn.175.1605101114470;
 Wed, 11 Nov 2020 05:25:14 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <81fbf12c3455448b2bb4162dd9888d405ee0c00a.1605046192.git.andreyknvl@google.com>
In-Reply-To: <81fbf12c3455448b2bb4162dd9888d405ee0c00a.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 14:25:03 +0100
Message-ID: <CAG_fn=W0abFzRDhm1ArqqntZt5OLOLv_EjC1Z1j9KQnswH7cgA@mail.gmail.com>
Subject: Re: [PATCH v9 05/44] kasan: shadow declarations only for software modes
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W2VqwyDs;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::842 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> Group shadow-related KASAN function declarations and only define them
> for the two existing software modes.
>
> No functional changes for software modes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I864be75a88b91b443c55e9c2042865e15703e164
> ---
>  include/linux/kasan.h | 47 ++++++++++++++++++++++++++++---------------
>  1 file changed, 31 insertions(+), 16 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 59538e795df4..26f2ab92e7ca 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -11,7 +11,6 @@ struct task_struct;
>
>  #ifdef CONFIG_KASAN
>
> -#include <linux/pgtable.h>
>  #include <asm/kasan.h>
>
>  /* kasan_data struct is used in KUnit tests for KASAN expected failures =
*/
> @@ -20,6 +19,20 @@ struct kunit_kasan_expectation {
>         bool report_found;
>  };
>
> +#endif
> +
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> +
> +#include <linux/pgtable.h>
> +
> +/* Software KASAN implementations use shadow memory. */
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +#define KASAN_SHADOW_INIT 0xFF
> +#else
> +#define KASAN_SHADOW_INIT 0
> +#endif
> +
>  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>  extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
>  extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> @@ -35,6 +48,23 @@ static inline void *kasan_mem_to_shadow(const void *ad=
dr)
>                 + KASAN_SHADOW_OFFSET;
>  }
>
> +int kasan_add_zero_shadow(void *start, unsigned long size);
> +void kasan_remove_zero_shadow(void *start, unsigned long size);
> +
> +#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
> +static inline int kasan_add_zero_shadow(void *start, unsigned long size)
> +{
> +       return 0;
> +}
> +static inline void kasan_remove_zero_shadow(void *start,
> +                                       unsigned long size)
> +{}
> +
> +#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
> +#ifdef CONFIG_KASAN
> +
>  /* Enable reporting bugs after kasan_disable_current() */
>  extern void kasan_enable_current(void);
>
> @@ -75,9 +105,6 @@ struct kasan_cache {
>         int free_meta_offset;
>  };
>
> -int kasan_add_zero_shadow(void *start, unsigned long size);
> -void kasan_remove_zero_shadow(void *start, unsigned long size);
> -
>  size_t __ksize(const void *);
>  static inline void kasan_unpoison_slab(const void *ptr)
>  {
> @@ -143,14 +170,6 @@ static inline bool kasan_slab_free(struct kmem_cache=
 *s, void *object,
>         return false;
>  }
>
> -static inline int kasan_add_zero_shadow(void *start, unsigned long size)
> -{
> -       return 0;
> -}
> -static inline void kasan_remove_zero_shadow(void *start,
> -                                       unsigned long size)
> -{}
> -
>  static inline void kasan_unpoison_slab(const void *ptr) { }
>  static inline size_t kasan_metadata_size(struct kmem_cache *cache) { ret=
urn 0; }
>
> @@ -158,8 +177,6 @@ static inline size_t kasan_metadata_size(struct kmem_=
cache *cache) { return 0; }
>
>  #ifdef CONFIG_KASAN_GENERIC
>
> -#define KASAN_SHADOW_INIT 0
> -
>  void kasan_cache_shrink(struct kmem_cache *cache);
>  void kasan_cache_shutdown(struct kmem_cache *cache);
>  void kasan_record_aux_stack(void *ptr);
> @@ -174,8 +191,6 @@ static inline void kasan_record_aux_stack(void *ptr) =
{}
>
>  #ifdef CONFIG_KASAN_SW_TAGS
>
> -#define KASAN_SHADOW_INIT 0xFF
> -
>  void kasan_init_tags(void);
>
>  void *kasan_reset_tag(const void *addr);
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW0abFzRDhm1ArqqntZt5OLOLv_EjC1Z1j9KQnswH7cgA%40mail.gmai=
l.com.
