Return-Path: <kasan-dev+bncBDW2JDUY5AORBB5426DAMGQEEC3QHTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id B356E3B44B6
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 15:45:43 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id l6-20020a0560000226b029011a80413b4fsf3495924wrz.23
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 06:45:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624628743; cv=pass;
        d=google.com; s=arc-20160816;
        b=T00wacBeBNzviAJM7lz4Drnsc/ew1Q7tIujWMqvIRjqHqwkynXtPdrfueV2U0tUSnl
         yEJUlBEdi8IiPhzHm7+hC616yGwLMsakcvPr36w5z0m5qINrXFUBnK/6+/HdvlhrPMQg
         ufh5r6o90X4aCP24AL/kgakWra4xJht5zc6PaJYVDczjuU6hafBk5Njy+81EcRUNMJx3
         nnMSzydY5UwZWkLTQ309+JQmo9p34YUDqq5yuYR9W3InComp1d53qVnt6HN2wQ71PCjN
         GCcCToHzjb5puevc5CbZM+gr55w6IL6Fiky5Uxh324RmKGYPgIWIU+dyQVPwoQ0DBKTJ
         qoYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=VJOCtYnypz8hBJc7RuDospsCVeDb/ld5JnbZq22qoQs=;
        b=wgvR2SYZaubCIGoEYu32TrjWUxpzC4zIAB1lhIeCJKfSwhrejTfjogFsfn/dJbmsbq
         bHpyKZUWtRsuyyEwTxqTzbsRbN/lUdaLl3aeeE1SZJSdFbaxY7zm5LlN3VtAZxMQw4dj
         9Vn6LNn2yC+ZI5w8v4vuLoCVJ9kIG8aaXlkMzSfjLGVCKj1DpzafVAwahaXlNDaPxEyS
         tCJ0TGSGMXkvwRDgO/TV53FbffZN5BTHK84xBcslEtbLSUZrWhbEaL4ct9YXw0T/iRH5
         /am8EVVkO9VgEfU3hKw7PMxe/+E1pPBcf4Sa1qzYto/xF2hL9xFea+2l12kz+Icnks9a
         hTCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=HP6Z00KL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VJOCtYnypz8hBJc7RuDospsCVeDb/ld5JnbZq22qoQs=;
        b=taHsnqMQL0szcEOTJR4IQFtQriV6CQ2dKwQ8a+4bVdLZgZWm6aaAwYFDqD8hvvgzjD
         /aaUSsc3okfwnnMsckwrMFOWgKqfZHJa8rXcKGmr/df7GkfRPBAD7wOUDzStB5XxRPyE
         3DMYb+UsnrYZEks1kCCJXmnhdeDM7W3uW0rQq7H4Jq1YEuHjdBzz3bgGUt6/Txv8VeLk
         aM74I3AESwJeaNBj6GtcstGV22I23bPOLJobDMqZgtDDdI5W1R1v0mOT3QDg9CnABOZz
         X31CVsGV1ZgiCizJ0YBMGlSon56WuI3IXLEop+TB3buDT+LC3+bCqp1Dhhzl9Td3r/7J
         pUpg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VJOCtYnypz8hBJc7RuDospsCVeDb/ld5JnbZq22qoQs=;
        b=avNX3dXpjcQ+h7h3wSX0JNFP17wqm9AxdzLdlmV2+gpnmEeqmPP6O7Ry6uBtAC+qCx
         Gmqpxtw1pmB6lfQQMrE/K3Hyltai+Lgdwr/8SZaMk0/YhJSKXCRwHQcD+g4ADi6E8yU2
         4mN0onemgQMft5AedFhNzrwViD2HSdlK+ItoxqKYj9xqiGIhhdyXk5HDgMK3u9hg09SI
         8ims7zQcg4AyNYEdJLajykghNABdAbgy3NQhxRGDZXyV2hQnF602tIITf0lZ44f63k/X
         egANbftp79zsEcuO3YPSFqTvgvIPi7TSElYOyXmWMTKGB/+t37MRxVctwK0j6ds9AJSL
         /XEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VJOCtYnypz8hBJc7RuDospsCVeDb/ld5JnbZq22qoQs=;
        b=eEjdTnVmWlO/D5a5Ejr3ST9y5FOnKfI0krwKFRbEl9T9fbMZKam5QPhdQG5OQMPv6r
         DR5rk+kAzOtV3jBlbQGiXLQXwq1FQpBqoYJrpk2kUrUyYDQ0VpjaRalt06jn3QI8DvNo
         4RelGVzEQ6lDXQgVHdIWBZ5xwPEW5aSIEPUDUZGtz61ljjJdpvA4CrGzokizVKe1C0Va
         2PTw//T2+6i/djUbluyQfqqoxYQHRTIlYIa9XFQHuA/lIedJ/qMN24LKsfszpZ5PLHoj
         J/iXrMWieyutt2mSV2oCiGis/ywZ0n3Qqhhi8ZEC+7B9vvWpplZ6YH3jvk/Ca2k0PrBh
         0wRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533M7xDFQCP55QUYdcWeRTxvin4bVM5qpbggS4L7931c49RJNyji
	lR2nJprui9IX+RtYtftVHcw=
X-Google-Smtp-Source: ABdhPJw9AA3JDkE6E+mDWIFpCFyP/URosU17pZKSAxoaroo8pMy9PzCZI8z32lFXJTnPdyVcchDwyQ==
X-Received: by 2002:a1c:ac87:: with SMTP id v129mr11223003wme.45.1624628743451;
        Fri, 25 Jun 2021 06:45:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5106:: with SMTP id o6ls6242399wms.2.canary-gmail;
 Fri, 25 Jun 2021 06:45:42 -0700 (PDT)
X-Received: by 2002:a05:600c:b57:: with SMTP id k23mr10946045wmr.133.1624628742573;
        Fri, 25 Jun 2021 06:45:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624628742; cv=none;
        d=google.com; s=arc-20160816;
        b=EVmHmHfha0vb7Nsd3h7PDpG3kvB8hz681tSwK2scaNNe/6I29/kKR4LUEshbJbtaYw
         ceB2glB1SlNju50E08DbNPp31lZYfZuAnN1o3gwShFOY7RfIV4Ih/kBPuIo1LqCo4S9G
         y60LNYLQY2HIA6goYRcypbX2sG22zboTKsI3/6EI7lwZlY8q8uS/RhteUWJ/W1O44ZMu
         M8G+Vu7dsp5ucq4pTUnDZ1hpL94U3QCpfKx/VGEIDofDbY5BpVcd2KMPRoMgiVEyWVQ1
         rZSXSYB44qbb5JzqKBPQ5u/ST5xWt3vK4JqqKQ2a13Id6Vr+i1SdLYJ+tvd6/0wshw64
         3NnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0CpnvSJnCFtaGuYOVBatHS50FEMI3wJ5bkwuLzl1+lo=;
        b=jryVm2Kz66VBmtpTG0tlNVmXES8NAz0ofsYMtfVw5bWw91RMJCgGL3WpB9CRvJZjVj
         OLvNAUnYNuSb6W05gfF+rcT423c3UpOVsewqKuukY5hTnW9ptJb8fWimUS8fiwtpQKYl
         HdOVXHzeH58rcFos9fHxV5Tc35RBPU/8Kgo5BgojWZT6bgGi0Ih5txPJaJEyUBbtgTSm
         rqJgI9DjpZ6Z7jgZpelBgv8DOYUqqOpGzrtmYLKuvEE0GckZbn4p9ddlF2wrLx7LsJaW
         t90BUe26Kj3v6MXI2W0bQfAq6CYmUx8kPbDkyyUXyn9DtOXAtNkQiegk++zsK9/cZyvj
         xU8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=HP6Z00KL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id o17si301229wrp.4.2021.06.25.06.45.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Jun 2021 06:45:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id r7so13421745edv.12
        for <kasan-dev@googlegroups.com>; Fri, 25 Jun 2021 06:45:42 -0700 (PDT)
X-Received: by 2002:a05:6402:1d11:: with SMTP id dg17mr15087371edb.30.1624628742089;
 Fri, 25 Jun 2021 06:45:42 -0700 (PDT)
MIME-Version: 1.0
References: <20210624034050.511391-1-dja@axtens.net> <20210624034050.511391-3-dja@axtens.net>
In-Reply-To: <20210624034050.511391-3-dja@axtens.net>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 25 Jun 2021 16:45:19 +0300
Message-ID: <CA+fCnZe14NZMbD8wPJQr=jj_0Mik8ZN1-Q3H6iM2tPp8qY1X4w@mail.gmail.com>
Subject: Re: [PATCH v16 2/4] kasan: allow architectures to provide an outline
 readiness check
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linuxppc-dev@lists.ozlabs.org, christophe.leroy@csgroup.eu, 
	aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=HP6Z00KL;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536
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

On Thu, Jun 24, 2021 at 6:41 AM Daniel Axtens <dja@axtens.net> wrote:
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
> Cc: Aneesh Kumar K.V <aneesh.kumar@linux.ibm.com>
> Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>
> --
>
> Both previous RFCs for ppc64 - by 2 different people - have
> needed this trick! See:
>  - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
>  - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
>
> Build tested on arm64 with SW_TAGS and x86 with INLINE: the error fires
> if I add a kasan_arch_is_ready define.
> ---
>  mm/kasan/common.c  | 3 +++
>  mm/kasan/generic.c | 3 +++
>  mm/kasan/kasan.h   | 6 ++++++
>  mm/kasan/shadow.c  | 6 ++++++
>  4 files changed, 18 insertions(+)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 10177cc26d06..2baf121fb8c5 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -331,6 +331,9 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>         u8 tag;
>         void *tagged_object;
>
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
> index 8f450bc28045..4dbc8def64f4 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -449,6 +449,12 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> +#ifndef kasan_arch_is_ready
> +static inline bool kasan_arch_is_ready(void)   { return true; }
> +#elif !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
> +#error kasan_arch_is_ready only works in KASAN generic outline mode!
> +#endif
> +
>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 082ee5b6d9a1..8d95ee52d019 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -73,6 +73,9 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
>  {
>         void *shadow_start, *shadow_end;
>
> +       if (!kasan_arch_is_ready())
> +               return;
> +
>         /*
>          * Perform shadow offset calculation based on untagged address, as
>          * some of the callers (e.g. kasan_poison_object_data) pass tagged
> @@ -99,6 +102,9 @@ EXPORT_SYMBOL(kasan_poison);
>  #ifdef CONFIG_KASAN_GENERIC
>  void kasan_poison_last_granule(const void *addr, size_t size)
>  {
> +       if (!kasan_arch_is_ready())
> +               return;
> +
>         if (size & KASAN_GRANULE_MASK) {
>                 u8 *shadow = (u8 *)kasan_mem_to_shadow(addr + size);
>                 *shadow = size & KASAN_GRANULE_MASK;
> --
> 2.30.2
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe14NZMbD8wPJQr%3Djj_0Mik8ZN1-Q3H6iM2tPp8qY1X4w%40mail.gmail.com.
