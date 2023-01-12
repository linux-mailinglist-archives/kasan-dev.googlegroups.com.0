Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4XA76OQMGQEEOV52II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 602B9667103
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 12:35:16 +0100 (CET)
Received: by mail-vs1-xe37.google.com with SMTP id l189-20020a6770c6000000b003d0cbd94bc0sf2018662vsc.7
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 03:35:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673523315; cv=pass;
        d=google.com; s=arc-20160816;
        b=PuIGPneouvvKWOrzuzbBm03IENVdw4tPnEDXXGeIZ/L01aFZVmmeOpbXkgFYMpR0Ir
         dfyeCy009uBtDQDpDdIyz53HqA9pWE+NAdUZSSNkh8pZk8EA/StjMQ2TtU5huz5BqYmZ
         lmZR6e955JAisL26xK3mDbIeTztgK+dFL+m5Ugj66NQUocv3wn4L/Z8hi2xGKZFlgG0c
         7QjKOhf+vPC1pI60o7hWSnxGmQYqVpSpXF8KhO+NFb8enc+VMR4n4weVFVp8Qnq3c7g7
         POom56FvnxFFLJMKX47I4NnXkrbpKpw7OUm+qIxjSmMPeijohBoC3yFbRNfD08K9Lpw/
         u6ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5eL9dOVa7oYUg5RZx/Ifky8XIsQigP97HdIiVbBMcwk=;
        b=cdogsuvsxO2TzqMiwtLbBCcDrxlpsUz/weRKD4MFltrAYGONw+PloCIxY4UrcSGFX8
         Ibah/OMRjk/Q6S0xr/zbriDLwUxrnqBDmIW2ChOw77Qvke+9MoEXZxId6rCT6lsplrFg
         BT25GS4ID3M9wyZxrpviXhIDdzoM7caTTmjvcjMA8CYjDuErCg941EJ5Y5BbwIhY1VqI
         kevATPQhBEXMKZlHUZmeUEwZgM+nIjpIXepPOpRuLQZBP3yPY+y9kS702SL51mNw5lpt
         A/faovIk4/7f+fo/lYvDr2m7IwPUw4prhK/DNHbVwIst5nmz8T5MNhsca/3HUrB8a016
         DZ4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SmA+oCE6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5eL9dOVa7oYUg5RZx/Ifky8XIsQigP97HdIiVbBMcwk=;
        b=ljNMds7MHXA5QMdW5jq+4GxadfciX6JmbKm3t0cmXvZvQCpDLtTv4lmURFuXQg2IdA
         1CVSi4vh08jW91+hHxBQB6mtUKonFgepdU3hPfVQbigTvMN3vHAkwrEx6o9Ms3JpSTdP
         QuX7LD6z1dKswXaNH6TYYRbN7erN+twLtujwS5IKDwvAocvXO9d53WpbrGRAVShIgMkD
         1f6Op2dkpYDfeYZCrv15E5UXy5+Jh5c7SE8redchx/Nrry3IonyW/DdwddUzWTH2oyLh
         ewp66IrqaqoZE3wZkRLzrjoYQhncVJOMgU4oC9vxiyH4255HJg7l03iA1Ju2Yx3CV7qq
         Ckyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=5eL9dOVa7oYUg5RZx/Ifky8XIsQigP97HdIiVbBMcwk=;
        b=fzauBfqUIhQ+qJBkrB0JbVBV3DQqOl0GhOM3eeRmGv6sFSrULYaPhJPbunY9uRA2oL
         dqyEToLXXXX3r8imoH7g7DsNMjv0jdssbdQZ/UTEdUfJU2kgnV6cYMmNeHmb20YIYW/0
         68a5ytY/KUmwLTdqlyAdr1OV4h54PrFPcdhihMkRa3jq4T5S3+SxYThGi6OUlTjthj06
         tgq7SqzeLslM99WSzD2HZcur8B74IrCYqOEdrv9cgRkEp17ReqpGbOEUMnGOXzGAu9IO
         mfR1bq3qWr2bRhsFLbLEnuHprP71Sp4FMYEnofNoIW6916NjRFuUZ5KkfcK8Izpg/Wfc
         GgOQ==
X-Gm-Message-State: AFqh2kr6FY+TC8VTWCGOER+sv8eO/ZPeOq+GjWviHggkK1CB4gL7mwjG
	60VuVBkiPtMOJnaOVQDAt+0=
X-Google-Smtp-Source: AMrXdXvvpSPTAbCWao08VbwZSVW1ZYCsiLKRnNFhQOLwWm6B485u1yUPuwfaE7MndLicfthn5OzfeQ==
X-Received: by 2002:ab0:3b57:0:b0:5ed:f692:ee6b with SMTP id o23-20020ab03b57000000b005edf692ee6bmr132939uaw.49.1673523315040;
        Thu, 12 Jan 2023 03:35:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:aa10:0:b0:3d8:d251:63a5 with SMTP id t16-20020a1faa10000000b003d8d25163a5ls289474vke.4.-pod-prod-gmail;
 Thu, 12 Jan 2023 03:35:14 -0800 (PST)
X-Received: by 2002:a1f:3081:0:b0:3d5:5366:dc6c with SMTP id w123-20020a1f3081000000b003d55366dc6cmr34207483vkw.4.1673523314272;
        Thu, 12 Jan 2023 03:35:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673523314; cv=none;
        d=google.com; s=arc-20160816;
        b=nwLOW32DKOgfN1lYZY0a0fkSX80agkM11ctiN2bR2xAxylGj5cvGS8ttuBaLYQXTVF
         Qs1sULfdsxkHF/E6iLQoD0F+uFpRHjrZGE14ztKKNd33Eeb9DsgeT+LdP0sNK9ZofrD0
         EumP7jn33WTy+DzucdrUi1LwgSywDqSeZ5FkOS9oXgzkcOu/19Q77LnMXeRJ3USiiOSc
         8H/ArCaUaHzHf0kM4OVURdAO4t3SiMurso1ErGdUR1sZAaaRZtmka9Kr7cRFrNO66xd+
         U5ueuGP5UcUh+biqtuWcFr06DvVaW2n9HFkoxZW9zQsXaHLFKpNp9LFjEM/0pUtB4yV2
         sISA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sZdRy8QTItnLRyny4d2jEHrecgEcHxwrD4J8NtmTL7Y=;
        b=EhS3oCCCMqkitfSn2RpnSGqWeJyjpjefyTo/EqPNn+RQ1hmBor4yJ46K8+//MvHzI9
         k6X2Rcvd3jcWoDA0xTz/S4NGlZCR6mIBgMjg0XEDE/VzdAEfX8deE5E+xfzb/WXYhOJ4
         G1P1ozTMWR2F6H/2gyfiesWAItu+KUjrW5sCOnisiyHqzO7EbNhcrKmy9Hbc5kQ1Ft1C
         bCr9wda8snIxYgP5U/zDk9I+wQ/5F0G+oCogAMuDW2qhxjtM7NVkLdFwA9cRF0BJ9lI4
         L9+s/TZgTq+HBdPC7+1bEqYdu8LJN8P2gXcK1P5BF1pbyghLbMsTlEXjN05hb7x0PW8H
         Tv7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SmA+oCE6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id w83-20020a1f9456000000b003d995c67be1si1227039vkd.4.2023.01.12.03.35.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Jan 2023 03:35:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id t15so18321279ybq.4
        for <kasan-dev@googlegroups.com>; Thu, 12 Jan 2023 03:35:14 -0800 (PST)
X-Received: by 2002:a5b:a90:0:b0:70b:87d5:4a73 with SMTP id
 h16-20020a5b0a90000000b0070b87d54a73mr5919340ybq.584.1673523313774; Thu, 12
 Jan 2023 03:35:13 -0800 (PST)
MIME-Version: 1.0
References: <20230112103147.382416-1-glider@google.com>
In-Reply-To: <20230112103147.382416-1-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Jan 2023 12:34:37 +0100
Message-ID: <CANpmjNMznQsC6ftzy7MCa7uQVCFv=MFg6JW28QdnGPyzFEZn5A@mail.gmail.com>
Subject: Re: [PATCH] kmsan: silence -Wmissing-prototypes warnings
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, akpm@linux-foundation.org, 
	peterz@infradead.org, mingo@redhat.com, dvyukov@google.com, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	kernel test robot <lkp@intel.com>, Vlastimil Babka <vbabka@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=SmA+oCE6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as
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

On Thu, 12 Jan 2023 at 11:31, Alexander Potapenko <glider@google.com> wrote:
>
> When building the kernel with W=1, the compiler reports numerous
> warnings about the missing prototypes for KMSAN instrumentation hooks.
>
> Because these functions are not supposed to be called explicitly by the
> kernel code (calls to them are emitted by the compiler), they do not
> have to be declared in the headers. Instead, we add forward declarations
> right before the definitions to silence the warnings produced by
> -Wmissing-prototypes.
>
> Reported-by: kernel test robot <lkp@intel.com>
> Link: https://lore.kernel.org/lkml/202301020356.dFruA4I5-lkp@intel.com/T/
> Reported-by: Vlastimil Babka <vbabka@suse.cz>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kmsan/instrumentation.c | 23 +++++++++++++++++++++++
>  1 file changed, 23 insertions(+)
>
> diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
> index 770fe02904f36..cf12e9616b243 100644
> --- a/mm/kmsan/instrumentation.c
> +++ b/mm/kmsan/instrumentation.c
> @@ -38,7 +38,15 @@ get_shadow_origin_ptr(void *addr, u64 size, bool store)
>         return ret;
>  }
>
> +/*
> + * KMSAN instrumentation functions follow. They are not declared elsewhere in
> + * the kernel code, so they are preceded by prototypes, to silence
> + * -Wmissing-prototypes warnings.
> + */
> +
>  /* Get shadow and origin pointers for a memory load with non-standard size. */
> +struct shadow_origin_ptr __msan_metadata_ptr_for_load_n(void *addr,
> +                                                       uintptr_t size);
>  struct shadow_origin_ptr __msan_metadata_ptr_for_load_n(void *addr,
>                                                         uintptr_t size)
>  {
> @@ -47,6 +55,8 @@ struct shadow_origin_ptr __msan_metadata_ptr_for_load_n(void *addr,
>  EXPORT_SYMBOL(__msan_metadata_ptr_for_load_n);
>
>  /* Get shadow and origin pointers for a memory store with non-standard size. */
> +struct shadow_origin_ptr __msan_metadata_ptr_for_store_n(void *addr,
> +                                                        uintptr_t size);
>  struct shadow_origin_ptr __msan_metadata_ptr_for_store_n(void *addr,
>                                                          uintptr_t size)
>  {
> @@ -59,12 +69,16 @@ EXPORT_SYMBOL(__msan_metadata_ptr_for_store_n);
>   * with fixed size.
>   */
>  #define DECLARE_METADATA_PTR_GETTER(size)                                  \
> +       struct shadow_origin_ptr __msan_metadata_ptr_for_load_##size(      \
> +               void *addr);                                               \
>         struct shadow_origin_ptr __msan_metadata_ptr_for_load_##size(      \
>                 void *addr)                                                \
>         {                                                                  \
>                 return get_shadow_origin_ptr(addr, size, /*store*/ false); \
>         }                                                                  \
>         EXPORT_SYMBOL(__msan_metadata_ptr_for_load_##size);                \
> +       struct shadow_origin_ptr __msan_metadata_ptr_for_store_##size(     \
> +               void *addr);                                               \
>         struct shadow_origin_ptr __msan_metadata_ptr_for_store_##size(     \
>                 void *addr)                                                \
>         {                                                                  \
> @@ -86,6 +100,7 @@ DECLARE_METADATA_PTR_GETTER(8);
>   * entering or leaving IRQ. We omit the check for kmsan_in_runtime() to ensure
>   * the memory written to in these cases is also marked as initialized.
>   */
> +void __msan_instrument_asm_store(void *addr, uintptr_t size);
>  void __msan_instrument_asm_store(void *addr, uintptr_t size)
>  {
>         unsigned long ua_flags;
> @@ -138,6 +153,7 @@ static inline void set_retval_metadata(u64 shadow, depot_stack_handle_t origin)
>  }
>
>  /* Handle llvm.memmove intrinsic. */
> +void *__msan_memmove(void *dst, const void *src, uintptr_t n);
>  void *__msan_memmove(void *dst, const void *src, uintptr_t n)
>  {
>         depot_stack_handle_t origin;
> @@ -162,6 +178,7 @@ void *__msan_memmove(void *dst, const void *src, uintptr_t n)
>  EXPORT_SYMBOL(__msan_memmove);
>
>  /* Handle llvm.memcpy intrinsic. */
> +void *__msan_memcpy(void *dst, const void *src, uintptr_t n);
>  void *__msan_memcpy(void *dst, const void *src, uintptr_t n)
>  {
>         depot_stack_handle_t origin;
> @@ -188,6 +205,7 @@ void *__msan_memcpy(void *dst, const void *src, uintptr_t n)
>  EXPORT_SYMBOL(__msan_memcpy);
>
>  /* Handle llvm.memset intrinsic. */
> +void *__msan_memset(void *dst, int c, uintptr_t n);
>  void *__msan_memset(void *dst, int c, uintptr_t n)
>  {
>         depot_stack_handle_t origin;
> @@ -217,6 +235,7 @@ EXPORT_SYMBOL(__msan_memset);
>   * uninitialized value to memory. When reporting an error, KMSAN unrolls and
>   * prints the whole chain of stores that preceded the use of this value.
>   */
> +depot_stack_handle_t __msan_chain_origin(depot_stack_handle_t origin);
>  depot_stack_handle_t __msan_chain_origin(depot_stack_handle_t origin)
>  {
>         depot_stack_handle_t ret = 0;
> @@ -237,6 +256,7 @@ depot_stack_handle_t __msan_chain_origin(depot_stack_handle_t origin)
>  EXPORT_SYMBOL(__msan_chain_origin);
>
>  /* Poison a local variable when entering a function. */
> +void __msan_poison_alloca(void *address, uintptr_t size, char *descr);
>  void __msan_poison_alloca(void *address, uintptr_t size, char *descr)
>  {
>         depot_stack_handle_t handle;
> @@ -272,6 +292,7 @@ void __msan_poison_alloca(void *address, uintptr_t size, char *descr)
>  EXPORT_SYMBOL(__msan_poison_alloca);
>
>  /* Unpoison a local variable. */
> +void __msan_unpoison_alloca(void *address, uintptr_t size);
>  void __msan_unpoison_alloca(void *address, uintptr_t size)
>  {
>         if (!kmsan_enabled || kmsan_in_runtime())
> @@ -287,6 +308,7 @@ EXPORT_SYMBOL(__msan_unpoison_alloca);
>   * Report that an uninitialized value with the given origin was used in a way
>   * that constituted undefined behavior.
>   */
> +void __msan_warning(u32 origin);
>  void __msan_warning(u32 origin)
>  {
>         if (!kmsan_enabled || kmsan_in_runtime())
> @@ -303,6 +325,7 @@ EXPORT_SYMBOL(__msan_warning);
>   * At the beginning of an instrumented function, obtain the pointer to
>   * `struct kmsan_context_state` holding the metadata for function parameters.
>   */
> +struct kmsan_context_state *__msan_get_context_state(void);
>  struct kmsan_context_state *__msan_get_context_state(void)
>  {
>         return &kmsan_get_context()->cstate;
> --
> 2.39.0.314.g84b9a713c41-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMznQsC6ftzy7MCa7uQVCFv%3DMFg6JW28QdnGPyzFEZn5A%40mail.gmail.com.
