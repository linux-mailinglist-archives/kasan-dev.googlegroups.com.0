Return-Path: <kasan-dev+bncBDW2JDUY5AORBYGEZOWQMGQEXLR6H7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 31ABC83CF7B
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jan 2024 23:36:17 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-50e7ddf4dacsf5745360e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jan 2024 14:36:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706222176; cv=pass;
        d=google.com; s=arc-20160816;
        b=CpdZF+wRvhR72SAF26soIF2vtG0hGPejAJKgutufoKUvOJOvxsiJ/eeXWxuJeaL9dT
         aRy5RLoYr3+dfF5zcC8/o5fvxvurfePpJxH4rZuxFYOabdiP9pV5L0ArW9WE3ff+YQ8q
         GnVfUrpXT6pJ0YVxlQrciTwiwsCNN4gxCcyyUV0SMKax7vM6yRrqSukxL9xzvvsrqleF
         56ZigKfPHWZGJAOjxutD49I43iF+AOkF186Qo5HT1aMaQA/IKVd+i0JVhL31OjCklzKu
         dxA9a8Rj9rU6FxqxkOQJlKy1TDbTBR7gU+iRbi0wfc2SB+nBg6EZgrRFx69IKuhT5GAD
         ux0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=oVhjgRXMOCxxncLMcudz6GPIwPYFSSxrHarkeD6DOng=;
        fh=1LkwsyefFK4QXJxf+UaR9FwDzUqg8mdFhAXARJLExsY=;
        b=tZUqPfjb4sHgPineVKK6ImHM//OoIf7XgyXoE52012xgvh0o1MhyKvU6EAAUWK0IG8
         MrrxIs/vc+W7rrbYqRo+1bybVEg490SCDOV5738SQoiAad0TV0RkOxCjZ0e+KyzCqtFa
         cFFIXZX4doxtnu8zR0PyzHRu0/wqq2RwrrK5tz2DRT0oWPcoB6Dzc5UXL7pmLPuqM7UN
         5CFdc84EJqLqjySKwaTZmBm+RIRuziODH+P/r+MMtFaHyWxwWOIXLUWub30Ydr+YA8BS
         1QMtXWMat7rGQ252NhhplKOSlHkPHLZZuLL6faZ+sJSF77WomV5kZuDvZgFZgaw+bZUo
         8vJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hrc66Q8j;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706222176; x=1706826976; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oVhjgRXMOCxxncLMcudz6GPIwPYFSSxrHarkeD6DOng=;
        b=OgjmKueWUyvqXWp6912usCh4s7bnHdiCr8RXPmPg4OTLytnT00qNbrQBSYLH9YdwLZ
         0JVHYGzxbxHajLlTRCIYlL1XhT2IKf633CXXlqEzsoOh4pe8XBQjsGjrmabVEWo9DRKS
         rRSC1Aa4f4J184JXUauVIwb6aQ1fW/X0TMHDlGuSN3pj6ix31jhzu2g5R8XpKEj0kcNc
         AD/3EfJwO1tbP8xpELgMizeb71pR7FvtgCty93qizFN4D20SEgdE38g7SPSM20mmV0n6
         9ZuPPeaTvYI5wYF/ee05PW1/elwSXbJNVFx6oRD/Yv1r711YLeyvw2Z+qEX7vpDcYVw4
         QV4A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1706222176; x=1706826976; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oVhjgRXMOCxxncLMcudz6GPIwPYFSSxrHarkeD6DOng=;
        b=jdVx+gmpunUF0NJOFQCjw90gSfzILdowIdVDjG9+ino+2w2W8V2wpOLVGcd+IJRtTF
         vmot/gpsSdyh8gpjegbOO5PpIa+GT27SnhIiEC65gNE8RlfrYpiSbSbPfLkQzuR45MqW
         4irbFI4jT2EbqYM7wCLiqrwljZAor0NUegPr1lC7DkgXhYnRYw4SJ0QRODeqM39GkqY9
         cNCfXSKqY1gA0XK52XWaYUG04ZOv46UkNlJ0HFeFmAMaQIhFJgWiBr0j5DdY7EMPWI+z
         DPEPYcXOCuSBclKve+nm5FU/tCiyAQtJsPOOl9tpyhNDgdRMJ+QRacyQh1gIN8peyJr+
         oP5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706222176; x=1706826976;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oVhjgRXMOCxxncLMcudz6GPIwPYFSSxrHarkeD6DOng=;
        b=KSPH1A4s9hMOVNJgHmAH4lLIH1u2QGrlpkFpd6mszef8aiNqbDz5M3dxLUtYZzObD8
         2LyL59UsKCOObwR25ySkwWbGWs1BxVbH3B8wK5XqB2jkiLFEZabrJnHYdd+GBGWjJT9j
         9FN1PfCD+hXq+tp2z2FlZNZ+GZUkVIaeOly8riv+VLt5iQUdQ9nGR17YjQK6tLO0UDFX
         Cdxv/lHdMssbFXtiAyTyvnL7haVuf0jAIVKz17zJzhaDPiOswVj856Db3D20Fe5tLGkJ
         pFiFaFdmmPn6frXtNkyRrkQchGEY4RnbIwJlNgcXF+PZ579yKd4VnLi0bdV/aZD1WLfi
         rp3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzSvNItRRqzITbQ80etstI3dqpDGeb22WFj4ZEFjzbDyp7LlEDP
	hDZa1Jz3jy0N4CtVBMsSAQ3OJwMAgtB9jUC2opZO0ljf3WktuRqq
X-Google-Smtp-Source: AGHT+IHRdMnTEm+8ZVPf+FYtkB9jVoqvLEYSarc8ABbCLJuRUFdSlQry5i5cFNBfdmk2XFQx61fULA==
X-Received: by 2002:a05:651c:4c8:b0:2cf:348c:776e with SMTP id e8-20020a05651c04c800b002cf348c776emr214645lji.22.1706222176193;
        Thu, 25 Jan 2024 14:36:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:918c:0:b0:2cf:2f21:fe84 with SMTP id f12-20020a2e918c000000b002cf2f21fe84ls57870ljg.2.-pod-prod-03-eu;
 Thu, 25 Jan 2024 14:36:14 -0800 (PST)
X-Received: by 2002:a2e:2ac5:0:b0:2cd:494b:b4aa with SMTP id q188-20020a2e2ac5000000b002cd494bb4aamr194569ljq.30.1706222174352;
        Thu, 25 Jan 2024 14:36:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706222174; cv=none;
        d=google.com; s=arc-20160816;
        b=hkVfe2SQEKmGqhK+DuaWx/SnLXUW7obmJPScMjTJJ2Om/YrztHxE0wIo3Cw71No9cq
         9x25dt9Up8JdndjpDZUXoIMbXHaSUBH2xPHI5xgyuovc7AQgfGB3RfG2XeWQoSUbOF6U
         62iyx0ckTcethuoY+0mxfK3A7JoPfcfJmww/42mVhlhyyre7k9opW9wEjkJpOe2udFTQ
         uw64hABbUcRff0jUoutjsHn9Kr35QsRtoNOyPvvAal+PlGhHQ/7z/Bjfni9mJfmJEITr
         InkW5i0Z4xgUHvsjmJDBf9ceRriVc9qA4q8pSETJk8/v2wfboB3Hn/U9wVVn0+jP14zZ
         nv6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=abiH/PhhRDGXkyL1IB+beHQOnSwz7Jg04l0sv5fMRUk=;
        fh=1LkwsyefFK4QXJxf+UaR9FwDzUqg8mdFhAXARJLExsY=;
        b=NIpbmQhjkFwo9wkEWHVUu7g2dSibDfqMUvNH31oNJERYKyzOM0H3sHJ2JXiQ9mcUhM
         aiLGsMn5yn6UtVHFPZoF4ivuK709bFg/68crDgZM5yiAxn6jKubf5ciGa9DAZSSGfT3u
         PadjKsO8jVJyAlBZgr/mpTVEBDmfsyG0+VZcLY3xDHKZul4iyeyKcf26GyrNaVnhtPcA
         5Sl5bixUlffMb9r2ZY1LaeS7WAPJ0ZV5f8vy3z5FAcS3Gf1nbf/r0H+8Fu3p93qstEol
         2SUQL9d6NkWLt9V5JUV/F+pIngpvqJbYlaJKtJNM+69UGyzUmcEScV9L+bfSfLgfz3oC
         U4Dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hrc66Q8j;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id m23-20020a2e97d7000000b002cf2d9ccc7fsi104384ljj.5.2024.01.25.14.36.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jan 2024 14:36:14 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-337d32cd9c1so6204701f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 25 Jan 2024 14:36:14 -0800 (PST)
X-Received: by 2002:a5d:66c7:0:b0:33a:eb3:d8e9 with SMTP id
 k7-20020a5d66c7000000b0033a0eb3d8e9mr297880wrw.83.1706222173438; Thu, 25 Jan
 2024 14:36:13 -0800 (PST)
MIME-Version: 1.0
References: <20240125094815.2041933-1-elver@google.com> <20240125094815.2041933-2-elver@google.com>
In-Reply-To: <20240125094815.2041933-2-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 25 Jan 2024 23:36:02 +0100
Message-ID: <CA+fCnZc6L3t3AdQS1rjFCT0s6RpT+q4Z4GmctOveeaDJW0tBow@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: revert eviction of stack traces in generic mode
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hrc66Q8j;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430
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

On Thu, Jan 25, 2024 at 10:48=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> This partially reverts commits cc478e0b6bdf, 63b85ac56a64, 08d7c94d9635,
> a414d4286f34, and 773688a6cb24 to make use of variable-sized stack depot
> records, since eviction of stack entries from stack depot forces fixed-
> sized stack records. Care was taken to retain the code cleanups by the
> above commits.
>
> Eviction was added to generic KASAN as a response to alleviating the
> additional memory usage from fixed-sized stack records, but this still
> uses more memory than previously.
>
> With the re-introduction of variable-sized records for stack depot, we
> can just switch back to non-evictable stack records again, and return
> back to the previous performance and memory usage baseline.
>
> Before (observed after a KASAN kernel boot):
>
>   pools: 597
>   allocations: 29657
>   frees: 6425
>   in_use: 23232
>   freelist_size: 3493
>
> After:
>
>   pools: 315
>   allocations: 28964
>   frees: 0
>   in_use: 28964
>   freelist_size: 0
>
> As can be seen from the number of "frees", with a generic KASAN config,
> evictions are no longer used but due to using variable-sized records, I
> observe a reduction of 282 stack depot pools (saving 4512 KiB) with my
> test setup.
>
> Fixes: cc478e0b6bdf ("kasan: avoid resetting aux_lock")
> Fixes: 63b85ac56a64 ("kasan: stop leaking stack trace handles")
> Fixes: 08d7c94d9635 ("kasan: memset free track in qlink_free")
> Fixes: a414d4286f34 ("kasan: handle concurrent kasan_record_aux_stack cal=
ls")
> Fixes: 773688a6cb24 ("kasan: use stack_depot_put for Generic mode")
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> ---
>  mm/kasan/common.c  |  3 +--
>  mm/kasan/generic.c | 54 ++++++----------------------------------------
>  mm/kasan/kasan.h   |  8 -------
>  3 files changed, 8 insertions(+), 57 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 610efae91220..ad32803e34e9 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -65,8 +65,7 @@ void kasan_save_track(struct kasan_track *track, gfp_t =
flags)
>  {
>         depot_stack_handle_t stack;
>
> -       stack =3D kasan_save_stack(flags,
> -                       STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET=
);
> +       stack =3D kasan_save_stack(flags, STACK_DEPOT_FLAG_CAN_ALLOC);
>         kasan_set_track(track, stack);
>  }
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index df6627f62402..8bfb52b28c22 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -485,16 +485,6 @@ void kasan_init_object_meta(struct kmem_cache *cache=
, const void *object)
>         if (alloc_meta) {
>                 /* Zero out alloc meta to mark it as invalid. */
>                 __memset(alloc_meta, 0, sizeof(*alloc_meta));
> -
> -               /*
> -                * Prepare the lock for saving auxiliary stack traces.
> -                * Temporarily disable KASAN bug reporting to allow instr=
umented
> -                * raw_spin_lock_init to access aux_lock, which resides i=
nside
> -                * of a redzone.
> -                */
> -               kasan_disable_current();
> -               raw_spin_lock_init(&alloc_meta->aux_lock);
> -               kasan_enable_current();
>         }
>
>         /*
> @@ -506,18 +496,8 @@ void kasan_init_object_meta(struct kmem_cache *cache=
, const void *object)
>
>  static void release_alloc_meta(struct kasan_alloc_meta *meta)
>  {
> -       /* Evict the stack traces from stack depot. */
> -       stack_depot_put(meta->alloc_track.stack);
> -       stack_depot_put(meta->aux_stack[0]);
> -       stack_depot_put(meta->aux_stack[1]);
> -
> -       /*
> -        * Zero out alloc meta to mark it as invalid but keep aux_lock
> -        * initialized to avoid having to reinitialize it when another ob=
ject
> -        * is allocated in the same slot.
> -        */
> -       __memset(&meta->alloc_track, 0, sizeof(meta->alloc_track));
> -       __memset(meta->aux_stack, 0, sizeof(meta->aux_stack));
> +       /* Zero out alloc meta to mark it as invalid. */
> +       __memset(meta, 0, sizeof(*meta));
>  }
>
>  static void release_free_meta(const void *object, struct kasan_free_meta=
 *meta)
> @@ -526,9 +506,6 @@ static void release_free_meta(const void *object, str=
uct kasan_free_meta *meta)
>         if (*(u8 *)kasan_mem_to_shadow(object) !=3D KASAN_SLAB_FREE_META)
>                 return;
>
> -       /* Evict the stack trace from the stack depot. */
> -       stack_depot_put(meta->free_track.stack);
> -
>         /* Mark free meta as invalid. */
>         *(u8 *)kasan_mem_to_shadow(object) =3D KASAN_SLAB_FREE;
>  }
> @@ -571,8 +548,6 @@ static void __kasan_record_aux_stack(void *addr, depo=
t_flags_t depot_flags)
>         struct kmem_cache *cache;
>         struct kasan_alloc_meta *alloc_meta;
>         void *object;
> -       depot_stack_handle_t new_handle, old_handle;
> -       unsigned long flags;
>
>         if (is_kfence_address(addr) || !slab)
>                 return;
> @@ -583,33 +558,18 @@ static void __kasan_record_aux_stack(void *addr, de=
pot_flags_t depot_flags)
>         if (!alloc_meta)
>                 return;
>
> -       new_handle =3D kasan_save_stack(0, depot_flags);
> -
> -       /*
> -        * Temporarily disable KASAN bug reporting to allow instrumented
> -        * spinlock functions to access aux_lock, which resides inside of=
 a
> -        * redzone.
> -        */
> -       kasan_disable_current();
> -       raw_spin_lock_irqsave(&alloc_meta->aux_lock, flags);
> -       old_handle =3D alloc_meta->aux_stack[1];
>         alloc_meta->aux_stack[1] =3D alloc_meta->aux_stack[0];
> -       alloc_meta->aux_stack[0] =3D new_handle;
> -       raw_spin_unlock_irqrestore(&alloc_meta->aux_lock, flags);
> -       kasan_enable_current();
> -
> -       stack_depot_put(old_handle);
> +       alloc_meta->aux_stack[0] =3D kasan_save_stack(0, depot_flags);
>  }
>
>  void kasan_record_aux_stack(void *addr)
>  {
> -       return __kasan_record_aux_stack(addr,
> -                       STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET=
);
> +       return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC)=
;
>  }
>
>  void kasan_record_aux_stack_noalloc(void *addr)
>  {
> -       return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_GET);
> +       return __kasan_record_aux_stack(addr, 0);
>  }
>
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t=
 flags)
> @@ -620,7 +580,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, =
void *object, gfp_t flags)
>         if (!alloc_meta)
>                 return;
>
> -       /* Evict previous stack traces (might exist for krealloc or mempo=
ol). */
> +       /* Invalidate previous stack traces (might exist for krealloc or =
mempool). */
>         release_alloc_meta(alloc_meta);
>
>         kasan_save_track(&alloc_meta->alloc_track, flags);
> @@ -634,7 +594,7 @@ void kasan_save_free_info(struct kmem_cache *cache, v=
oid *object)
>         if (!free_meta)
>                 return;
>
> -       /* Evict previous stack trace (might exist for mempool). */
> +       /* Invalidate previous stack trace (might exist for mempool). */
>         release_free_meta(object, free_meta);
>
>         kasan_save_track(&free_meta->free_track, 0);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index d0f172f2b978..216ae0ef1e4b 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -6,7 +6,6 @@
>  #include <linux/kasan.h>
>  #include <linux/kasan-tags.h>
>  #include <linux/kfence.h>
> -#include <linux/spinlock.h>
>  #include <linux/stackdepot.h>
>
>  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> @@ -265,13 +264,6 @@ struct kasan_global {
>  struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
>         /* Free track is stored in kasan_free_meta. */
> -       /*
> -        * aux_lock protects aux_stack from accesses from concurrent
> -        * kasan_record_aux_stack calls. It is a raw spinlock to avoid sl=
eeping
> -        * on RT kernels, as kasan_record_aux_stack_noalloc can be called=
 from
> -        * non-sleepable contexts.
> -        */
> -       raw_spinlock_t aux_lock;
>         depot_stack_handle_t aux_stack[2];
>  };
>
> --
> 2.43.0.429.g432eaa2c6b-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

But I'm wondering if we should also stop resetting metadata when the
object is fully freed (from quarantine or bypassing quarantine).

With stack_depot_put, I had to put the stack handles on free, as
otherwise we would leak the stack depot references. And I also chose
to memset meta at that point, as its gets invalid anyway. But without
stack_depot_put, this is not required.

Before the stack depot-related changes, the code was inconsistent in
this regard AFAICS: for quarantine, free meta was marked as invalid
via KASAN_SLAB_FREE but alloc meta was kept; for no quarantine, both
alloc and free meta were kept.

So perhaps we can just keep both metas on full free. I.e. drop both
kasan_release_object_meta calls. This will go back to the old behavior
+ keeping free meta for the quarantine case (I think there's no harm
in that). This will give better reporting for uaf-before-realloc bugs.

WDYT?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZc6L3t3AdQS1rjFCT0s6RpT%2Bq4Z4GmctOveeaDJW0tBow%40mail.gm=
ail.com.
