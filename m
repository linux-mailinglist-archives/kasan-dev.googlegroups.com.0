Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2HIVODAMGQEUXEFXAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AA543AACF6
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 09:06:17 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id z6-20020a92cd060000b02901eb52fdfd60sf3251537iln.14
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 00:06:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623913576; cv=pass;
        d=google.com; s=arc-20160816;
        b=HHuRqQkOf3gA01j+0C/wNDRPvd5uatDDM5KIfMTjJbSbOi/8+tLc0bmYgQAuAqZyot
         Hx7LzC1VnSgs+WEqLYWrJ/DHub1VS/MMI0RBFYVNEYQEr7AwHLN25wxeijbV0YYGqddu
         HqYyN3XU+8adADNow7nsCbLTDtW6h4+o+CXNFzxuiqxuMr/4LeyeuO+2yQOVzDp4cN2E
         MCLZ+Qcu3v3MpqufRA63I1h7Nkmk9ZerMLKEPyLLJKYFgbCfe/5pVBa5fg/XX9xj12g0
         t3+dKBzfnbak7DS2mPsxoO0ccshx8oUxsWEtZxAec3l8LJe6mj1bJFbUY5xg/ZENKz1e
         zgZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BDpF0Z2IrYG9rHtzP/QxpY52WEdUIh0Gu9FYFiLv7Mk=;
        b=wI79nRw1RiazzQgnO0sYG51eu4OxrDwvmQuBT4KJp86w9k6PVakoMGq4MdupEiXmbr
         gCUjD5fS29h5RbkyGR8EgkQx/Z0IMeDgvfpA4O/R5NWkHPpSauvy96pGVXeUySB5U4zr
         EimEnWofZlS/a/hQy0YBtpRYPPhvsXZEEcGhPf+m+ARoh8Ml2AkTA1ipyfytXSY7eHU3
         L0omQxwW/0Gf7MzI7L5URG7aJ3tju6mc7Kk0g47z7Si3Jscb7cFnH3bEij6lclsLggoM
         CWKL8jw2y+oCYpJceBvNYXbFmSPCOlGCLkiaZJNiA7FpuTUsNQHEDdZCKKRvW634ZQXS
         yGcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eGrVtvwA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BDpF0Z2IrYG9rHtzP/QxpY52WEdUIh0Gu9FYFiLv7Mk=;
        b=FC+2DPoIO0Bh7nV95Llgp+1hoobWOCTwturXcDaDCfJbvQVPyez/Ifxb3Au3dBkEBg
         0eOG4MK0ZKYF+VBBOjEorUQErnodqwmHlJ8i+cIyz/ZcmKnTMTnk6KEUAtqobU+QE+8U
         Wjay37ql+G/h1Q/qPej0yMm+STZwi409ZZ9vhG4fwmErglrOzsjk+nwmUlXCMHxTQmcg
         yCMxDXvkd2fnujXDyMrpGStMD1CrmU48tCGZCVnJjW9EmiNQ/mISZLtUZNTaA+jo0uEl
         tsP2ovvJdufBSkv5YQ8x/FV+qUN28U/XPHDao+FwpyYqaSkNhByUWt9SPXKCRV2TSsRu
         WNfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BDpF0Z2IrYG9rHtzP/QxpY52WEdUIh0Gu9FYFiLv7Mk=;
        b=oJ08cYhnSDHkfVifCtTrAdzZFZzTwhJpcqNDKXWoy0TM/j1P/9R1U9cTLAf8MWDpuf
         +TazEDRFK6k3OGSTgCjMZcice5mn5HvSaOaDHnr4K5jzv6QwLa93pmVpJDFb5WUROxL2
         Eo5ObsVvrdUOq2Lkeeif5Z17wWzqJASJmZPmYF3TT2Z1si6dE22IdO/Cjh7gnOjtglcJ
         5Tki5sjvSkrINeN64xttG0h6i8rsY8RTE7D7kwTbiDhXJIbHYpiGwWaKPtp+U8NmSj5X
         3+1IinMt2pnU7W7yaOeZmnrtwUxR+IDHj40KphPBqsEvutlhqSACW/c6AumJ+QMOBK8h
         vPEg==
X-Gm-Message-State: AOAM530Y5a0X0NC25L7LHK0SO8Qx5xTNU8dq9/OtJcl5HMs5DIB2Zyzr
	lVCAj6HV9eQi+BcEXckQfCI=
X-Google-Smtp-Source: ABdhPJy7anO2zS6LxBD2B4w1Jhk5gJ65ZbananZbbCgMDWZBLnqpyZZ7EA/oJbmzqj16YnsXjihf4Q==
X-Received: by 2002:a02:647:: with SMTP id 68mr3149589jav.29.1623913576549;
        Thu, 17 Jun 2021 00:06:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:860d:: with SMTP id z13ls788837ioj.8.gmail; Thu, 17 Jun
 2021 00:06:16 -0700 (PDT)
X-Received: by 2002:a05:6602:12:: with SMTP id b18mr2518098ioa.115.1623913576209;
        Thu, 17 Jun 2021 00:06:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623913576; cv=none;
        d=google.com; s=arc-20160816;
        b=l5zdVhARzJ8sp7FdkdQncdVsHeq+uNwXuM/POM5HR3dYCsfR/UVDZeDcLFLLrajj4n
         00pQVw5jFkmJYxzMwZxNCCIstaU1oElF8pPXqB1eRi+2UwP33NaGwc6e9BMEA4btXyvf
         A6hO6PyDuKK31C08ssg98z+aUisL/kFxcByhXydA14ll7i7CcZV8dqCkp9F3PEs2dJ9W
         IDA68Op3zcOgn5MzRH2/zqkdMYMJKOivgnFnYHVN5N5KV7r65CP5WX3kAyJX1fTmEFG6
         xW2UZ7DdqgtxxdfEv0auU7KMdOWE/hK+m6Yo13mGZWQflo5NXW40P3O20fIUS1u6XDVm
         AdBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nhqmE1vBTbQZlPad3fKuDW4Qef6o+8lKl4ONa0J/G/8=;
        b=07/8veNPLW9ZNBEigK1JewpCzh9C6+Ctjx3Y6oFVy34lsKAnz9vz8FIG9Cj8gukwRJ
         dXOoYiNOlj9SBMv7zTVvV6WMzAtjelYZ9gxoiTXvLmg6CpIYbvoNzoYpmi4PcSlxuCQP
         5QdHLQSK43hlxkkGeyZDmYzKbGDko+HW4dwsqMP/unex1Pg5ddqFEJUJUmde+bUhvq0n
         u36o8V43TvdAHj3vSyURioZ/l5+SPAehSUVVBuVO1hxLvgO4Xklpor7S1M/I8X235pDd
         /fg2d5zup5cWAwihEYYfMP5Y57C0zQU905Q6Y2KW0qTpEB0BDG9Y97pptCciGZXUlTO/
         rjbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eGrVtvwA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id x5si389020ilu.0.2021.06.17.00.06.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 00:06:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id w23-20020a9d5a970000b02903d0ef989477so5132431oth.9
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 00:06:16 -0700 (PDT)
X-Received: by 2002:a9d:4e7:: with SMTP id 94mr3260598otm.233.1623913575674;
 Thu, 17 Jun 2021 00:06:15 -0700 (PDT)
MIME-Version: 1.0
References: <20210617063956.94061-1-dja@axtens.net> <20210617063956.94061-3-dja@axtens.net>
In-Reply-To: <20210617063956.94061-3-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Jun 2021 09:06:02 +0200
Message-ID: <CANpmjNPvCprs4+aToP4GXC1upii2sVYbHPRcDoVr=qL3psMUSw@mail.gmail.com>
Subject: Re: [PATCH v14 2/4] kasan: allow architectures to provide an outline
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
 header.i=@google.com header.s=20161025 header.b=eGrVtvwA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

On Thu, 17 Jun 2021 at 08:40, Daniel Axtens <dja@axtens.net> wrote:
>
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

With Christophe's suggestion:

Reviewed-by: Marco Elver <elver@google.com>


> --
>
> Both previous RFCs for ppc64 - by 2 different people - have
> needed this trick! See:
>  - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
>  - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
>
> I haven't been able to exercise the arch hook error for !GENERIC as I
> don't have a particularly modern aarch64 toolchain or a lot of experience
> cross-compiling with clang. But it does fire for GENERIC + INLINE on x86.
> ---
>  mm/kasan/common.c  | 4 ++++
>  mm/kasan/generic.c | 3 +++
>  mm/kasan/kasan.h   | 8 ++++++++
>  mm/kasan/shadow.c  | 8 ++++++++
>  4 files changed, 23 insertions(+)
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
> index 8f450bc28045..b18abaf8c78e 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -449,6 +449,14 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> +#ifndef kasan_arch_is_ready
> +static inline bool kasan_arch_is_ready(void)   { return true; }
> +#else
> +#if !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
> +#error kasan_arch_is_ready only works in KASAN generic outline mode!
> +#endif
> +#endif
> +
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPvCprs4%2BaToP4GXC1upii2sVYbHPRcDoVr%3DqL3psMUSw%40mail.gmail.com.
