Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOPZU2DAMGQETROGQKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EBCC3A9570
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 10:56:27 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id w10-20020aa7954a0000b02902eac51f8aa5sf1172460pfq.20
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 01:56:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623833786; cv=pass;
        d=google.com; s=arc-20160816;
        b=ogeYwP+yOmuyaNgm/AHeJ6iq+o7c0NrybpOopW5PIgGcOj6ztq2+pKV+lpMicMvxyZ
         yMzNrJLxdqVvVMowcrlxHW4PsK1hWL7NVu2W/JL7nFGI9wp3Nryz8j9Lal0xLvVLUS1H
         O6fgf6axkwgcSFJVHUzQBnXQ+7+qEOu/EMj4BgVhBM0FA9/9ABstOMICD08wIZ+x9kHq
         9tmosV+585D5ANjVDkJSgqhc+ORS3fDi2VarPKsT8usXurL4DbfHl+HEd+Exr9hAwoDz
         vKPIVZ60g+qwkBdLKgb5SVjZpmp17emhGGGNUzLY5SO6fR3Rcs1MNjOPmwusDHahf6Tx
         RfRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vFiP1tUIBg8z89Ci8wus5e/9RwmVqncXv8YjYksPMGU=;
        b=lfCSxYOsjwbj2rycsRk1/3+HoV9mRjHtmLUkckmcvGIHxdx9Yz2D1ryNEs1WrarQiY
         qe+Ad87MFGO135kbJoQtnJHCLb6l7F6h91u7/llMTai5oTXNSRGKd15yQtSL4VSlN3qi
         mqhlDKjH3qz7M88eSRMp11Y4k/5/UDzsNeJaoUzRpTgYLlrexDACQ/GH+DJ47V6Dl1gd
         5QkPgr5pBJ6F/IZ48eQvTqQUnXfZ+YBFt2u72P3ZYsR/8tkIWwijy0ABBH0Y+ItEEdfi
         EiIEU3/axeRdxkuGTZYK45hKC++Ebt+B/a2TjYHrClT+ovrHtuDLN718wlF/VdMDtk3V
         YO3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NWG0M7wK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vFiP1tUIBg8z89Ci8wus5e/9RwmVqncXv8YjYksPMGU=;
        b=Y0NSF8KdcyrjVGEjy8fQJrY8X/7bDOGOHioowzzCUWsdGpOTSuEzeI5+DbV8GYvkbl
         azmd4MLuwy9+RnhQr9T/gY+AywPQd/FC4d1/qQSitJ4T3EEX+Hf1RPdhd0VrbLF/J2Ji
         ZCfZgFuqFsyD5gma1Nhej92sMAWpvWGJISbKZlAFFWBRxmKQYRRlHBxoaDJ95oxT0GIJ
         NbRpDqXGn6U1R0F0l5p5d4LhasTb7CbBsqjtvdW9rpj1CZG7irw+zIqjtgxH/B6MV/00
         BsFG9ir2lA+s4I6SZoNj9CtlTBQzN+nggB8busZKoUnszmZV25mCZXSSXy4l0VHIJwE+
         DdGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vFiP1tUIBg8z89Ci8wus5e/9RwmVqncXv8YjYksPMGU=;
        b=panW7b907Y0sq1kvIEJDCaMDORbDxa/YEZ/YVsBOf1ki4cHtbRQVcJpPQ1ZIA1pGqL
         cMk1rNGOWxufgtCT4Z9HwlM8VDsr9vmDnJlUWA28AC/o/PECzAmYpvTOSbZaBzOikOtM
         sgauEyoRzv5JYhN1d053ey6LkSnxiA7k6f+kudhec41ModBd52o3j9k1crmp+Qbwnh0d
         nOWYbKCl3GQTBpFHzLrglsUlzuiDzFfh/pGVkQICsQvZye846+rytFJCIS1UW6elFETi
         bXc5R4Vaft9LQlKplLU+7c5plxyAWLc5lQmtCJN8g7lyZaBMg9+hYN0ekoPZAwgbizQW
         pDEg==
X-Gm-Message-State: AOAM531I1pLttQ/fRHIHxFi1H136S+XNdIREvUOr3cuNrvEtcEGkWZfI
	hgTqqIlUi6K5NVc75pOdHLw=
X-Google-Smtp-Source: ABdhPJwBBqRaCxou8tvZJ1/VfcC0ROKb3DKedqpnJnff5LPyjf0c9aLWrprLHPnkfBWARCvVyWTGYg==
X-Received: by 2002:a65:52c8:: with SMTP id z8mr4013379pgp.50.1623833785937;
        Wed, 16 Jun 2021 01:56:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5992:: with SMTP id l18ls3777272pji.1.canary-gmail;
 Wed, 16 Jun 2021 01:56:25 -0700 (PDT)
X-Received: by 2002:a17:90b:3581:: with SMTP id mm1mr9434673pjb.98.1623833785328;
        Wed, 16 Jun 2021 01:56:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623833785; cv=none;
        d=google.com; s=arc-20160816;
        b=0xal64/1AmjpDEM3qGB6IZ3bs8RJlcmTrMmmK72B04ZAqkptlKdDRSRd9AzYoqPAhS
         eT6g7B35sT48xlIjqoJwuOmTtr19X4iSYvD5k1OA7piOWFrL2fyUnAKlRj7x9yEqymMm
         21icjfZ2pF8L6ti2s95xOTQDBI51voj7QiGq6zTt4jaHTaBqQ2w8Z8W8Vr2gj/QZcqt3
         l8zV+8WQSUFKD9HxgWtxnHSkkglQh2MUM9eoBz8fJ2Zc/5P9rIkc0y4suZsUoIAlCMbk
         8aNkujd1T7TR6aagnj5JxmtvpriG3PviI8IFwN3oxu9E7DZI50K8YU5C7XB4AZlVMz+g
         seOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PJLq/uYB/Lpm2G2R7d6L11/gd8MJ7X0dg2M/HcvVqks=;
        b=s5ESpGIbTIt6RAneFyRBRXA17j69ElBPLX3SXjbBDSdKR1Z7od9T2+5D7C77On/PTF
         DKaDJppxpJa6xbH7a/dzSZXOtwQ4Tx/mfMSEjbGTBYpoambrC4KfQTPyABnQxG6EzDcD
         Lza5D1SAEuT7J+WwntlDSNIYOaT/JKqhC/Pql436FN5V2FkD7AP+m/YjEGTKnqhumwhX
         q7S4EUkmaQm+UT6PtaqnmNHx3E7t6+QXYCdQg1xofLbbWg5yQpxoBuFY/MWd1YvSYqbB
         dD9r+w3MONyEt6bdLulcRiBUJEctpQs+2nq+LS9hA+1haO11HKczJk5fIs/RxOocHqF+
         sYwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NWG0M7wK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id ob7si88091pjb.1.2021.06.16.01.56.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 01:56:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id j11-20020a9d738b0000b02903ea3c02ded8so1788411otk.5
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 01:56:25 -0700 (PDT)
X-Received: by 2002:a05:6830:1bcb:: with SMTP id v11mr3196923ota.251.1623833784490;
 Wed, 16 Jun 2021 01:56:24 -0700 (PDT)
MIME-Version: 1.0
References: <20210616080244.51236-1-dja@axtens.net> <20210616080244.51236-3-dja@axtens.net>
In-Reply-To: <20210616080244.51236-3-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Jun 2021 10:56:11 +0200
Message-ID: <CANpmjNP8U_Mg05F0qOKsC3g58e9+hsuYkTQg0ZqsY==B5uLNqw@mail.gmail.com>
Subject: Re: [PATCH v13 2/3] kasan: allow architectures to provide an outline
 readiness check
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	linuxppc-dev@lists.ozlabs.org, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>, 
	"Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NWG0M7wK;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

On Wed, 16 Jun 2021 at 10:02, Daniel Axtens <dja@axtens.net> wrote:
> Allow architectures to define a kasan_arch_is_ready() hook that bails
> out of any function that's about to touch the shadow unless the arch
> says that it is ready for the memory to be accessed. This is fairly
> uninvasive and should have a negligible performance penalty.
>
> This will only work in outline mode, so an arch must specify
> ARCH_DISABLE_KASAN_INLINE if it requires this.
>
> Cc: Balbir Singh <bsingharora@gmail.com>
> Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
> Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Marco Elver <elver@google.com>

but also check if an assertion that this is only used with
KASAN_GENERIC might make sense (below). Depends on how much we want to
make sure kasan_arch_is_ready() could be useful for other modes (which
I don't think it makes sense).

> --
>
> I discuss the justfication for this later in the series. Also,
> both previous RFCs for ppc64 - by 2 different people - have
> needed this trick! See:
>  - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
>  - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
> ---
>  mm/kasan/common.c  | 4 ++++
>  mm/kasan/generic.c | 3 +++
>  mm/kasan/kasan.h   | 4 ++++
>  mm/kasan/shadow.c  | 8 ++++++++
>  4 files changed, 19 insertions(+)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 10177cc26d06..0ad615f3801d 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -331,6 +331,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>         u8 tag;
>         void *tagged_object;
>
> +       /* Bail if the arch isn't ready */
> +       if (!kasan_arch_is_ready())
> +               return false;
> +
>         tag = get_tag(object);
>         tagged_object = object;
>         object = kasan_reset_tag(object);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 53cbf28859b5..c3f5ba7a294a 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -163,6 +163,9 @@ static __always_inline bool check_region_inline(unsigned long addr,
>                                                 size_t size, bool write,
>                                                 unsigned long ret_ip)
>  {
> +       if (!kasan_arch_is_ready())
> +               return true;
> +
>         if (unlikely(size == 0))
>                 return true;
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8f450bc28045..19323a3d5975 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -449,6 +449,10 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> +#ifndef kasan_arch_is_ready
> +static inline bool kasan_arch_is_ready(void)   { return true; }
> +#endif
> +

I've been trying to think of a way to make it clear this is only for
KASAN_GENERIC mode, and not the others. An arch can always define this
function, but of course it might not be used. One way would be to add
an '#ifndef CONFIG_KASAN_GENERIC' in the #else case and #error if it's
not generic mode.

I think trying to make this do anything useful for SW_TAGS or HW_TAGS
modes does not make sense (at least right now).

>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 082ee5b6d9a1..3c7f7efe6f68 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -73,6 +73,10 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
>  {
>         void *shadow_start, *shadow_end;
>
> +       /* Don't touch the shadow memory if arch isn't ready */
> +       if (!kasan_arch_is_ready())
> +               return;
> +
>         /*
>          * Perform shadow offset calculation based on untagged address, as
>          * some of the callers (e.g. kasan_poison_object_data) pass tagged
> @@ -99,6 +103,10 @@ EXPORT_SYMBOL(kasan_poison);
>  #ifdef CONFIG_KASAN_GENERIC
>  void kasan_poison_last_granule(const void *addr, size_t size)
>  {
> +       /* Don't touch the shadow memory if arch isn't ready */
> +       if (!kasan_arch_is_ready())
> +               return;
> +
>         if (size & KASAN_GRANULE_MASK) {
>                 u8 *shadow = (u8 *)kasan_mem_to_shadow(addr + size);
>                 *shadow = size & KASAN_GRANULE_MASK;
> --
> 2.30.2
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210616080244.51236-3-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP8U_Mg05F0qOKsC3g58e9%2BhsuYkTQg0ZqsY%3D%3DB5uLNqw%40mail.gmail.com.
