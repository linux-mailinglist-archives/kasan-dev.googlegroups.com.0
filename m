Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJHJVCBAMGQEXHL7CSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id BADD53376BB
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 16:17:57 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id h75sf6269627vka.9
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 07:17:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615475876; cv=pass;
        d=google.com; s=arc-20160816;
        b=cwzFXccZx4DcBDdWTKsti673Yg8XB1l+S1w+0V1N5KW6Sh7Cg144WpLMCJHbw/iAL+
         G9YhbHbr2ARhzJ4W7d1hH7MfTtuTq+yNRUEug+ISiuOg3sjVfL9KoMKkTOLNenYuVwDz
         6qX7v0jHxSD8l4jGjtolMRSEfXx2DWzk6Jr/Qmz/6HdNl8VMx2pz4+5DE4EF6HDr8+7n
         eawkj6RIXHhKYIxkXhz6HTIcenVwJQZrqoONU0xNgwZj9jHS/z2cwPffj6Ff+XxafTmo
         E7laPlMijfuRpsLI6LTa/PaopqqSZ/n02JirbCcUW4Gb3mCuwTnMa9dxAYz3xiti7zWE
         BjDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=58ygG3bGhMR+kXh9FKOpHIZb6vBarq0TKUi0eqQBY6g=;
        b=GXQbk4PhIL5GADGsIRLo5BOp7JgDx+8Q+lPZadENCAkyrhItT7f2iDyFp8W8EG29cP
         YXZb8S0Y2hdR7m6bRcziJ31ZSOuF5T2de0+EOnsof2HNr7t7RfOGmpSs3vEkDqdabGzl
         f+tmn34uXyKKImWpE3brDhMfEStkcRpvG34IyyTwQORHDw0KgSbGzzUQqTGj4ZpFKVLd
         QLVkmyou+b73lepypX7VGyi/jS/I8vRiWgtXKchpzYCZb5Ana9z7zxKz75w+/IDvB4oX
         NaNjH9Qz0ZHEqhy+xjhgA88nLtvXaj451g7msH1S8dLpkcWAnamYteOTFhDVfabGaQJV
         ogMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aSWbR3Pv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=58ygG3bGhMR+kXh9FKOpHIZb6vBarq0TKUi0eqQBY6g=;
        b=fuREKGNqcTr6tK6p7WgA4lx552Gp3vaomcmR8Xj3fNwuzKxyn/YONLTWsLSctKlzOH
         cZ1uZy5BD5uGwprwU3N0QqRZOVi8ALPz5v72XPXlhGaDanuEu3rPLxS6R8FMPywEuZbV
         LakDWghuuH3lXUGsnNPoHNzoQVD8PNfPxsBD2LRcCWEJ4Y9xk9gnOl/hSB0lzJqYxWH9
         OXRqA92yP4T6WrcK64U3CTS/ldz0/NvxXrpgMlj9fJbMyQcDKeyv6OcM3dD0OIXmkdBG
         HdUi/QSbklv/kbDfSV2vGV/ysWYghrUaInF7WoqYjnPr3F4byxfMbaYoEHzdFG1Pqt98
         BYqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=58ygG3bGhMR+kXh9FKOpHIZb6vBarq0TKUi0eqQBY6g=;
        b=MffC//l5okI4AM9w+pMr1x31SqIagGLY/OlkY+Z6bV9237+2YVou1hW5VAPrCrCVAI
         sQCCeWuaiJmuREz2IGlfkEkK3fh8CTflpykIFOxUmqzuwpiWiH5IH4KkAFM3SqwjmsAm
         1/LOU4ypVoG5DWqXxCN6348MGX8a8+q9XoJI2LDgUsjksKQ/1y8bkkUtLjWMfW7x+eoI
         8KJBDyTTvPCWpkiOBgaTnqoNuBKoXDVeq6Pwkr31WyJSqNEUq8ULWn1JdbZ1e/tv6yBA
         P7LhhVACgIINuGlnjhMOIZDd2do1Uj4bQfRvHzeBjkBPUyCyUxJBU49q+/PxipbGB7fU
         QCDQ==
X-Gm-Message-State: AOAM531ujWBrpNh3bD0CQ13mJX0j+B6RkfD01TncHvQ+/vyDmIsoBEu/
	RFZ50bwPX/Ysut7RQrtAhkE=
X-Google-Smtp-Source: ABdhPJzl7NcpuhwN1a1ojmlV037XxFxvB1XqH9oHyVZPEbDT45X/l9e9Oz6YD+Oicc/QTFbtG1rRLQ==
X-Received: by 2002:ab0:217:: with SMTP id 23mr5265952uas.140.1615475876837;
        Thu, 11 Mar 2021 07:17:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6f87:: with SMTP id f7ls474063uav.1.gmail; Thu, 11 Mar
 2021 07:17:56 -0800 (PST)
X-Received: by 2002:ab0:20c4:: with SMTP id z4mr5321791ual.77.1615475876227;
        Thu, 11 Mar 2021 07:17:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615475876; cv=none;
        d=google.com; s=arc-20160816;
        b=IzsylLqW/OX1RnTNK+f+hpf4dYB7fhGuoioxF16MekgaKxvFCtW2GrXHwKzHrt4R2J
         ytEbWOxdYsaIZ4bwUfciJoEsnc2CaAj2nlN7WZWc4d9/CXuH2RCAHYGtYr+/6qA3+zAT
         0oSVN7nktQDBOlEieNnHK67u+bclhF1ioB9Ubrh1DR5mNbZ0ACrc2iCwRvM8LrlujWJk
         mDrj998SkEMwAVN1HP8NjgoLtcg+jk5cI9q5hX11Btgu8SLReJwdwoV6EQn5PfY2XDOi
         IrwkWmY/gUiFX/j8GaCLKkoST+i6crZfS1rFUGWrqlnsIKf4UYaJ4YZ6PzsXH49WJqVD
         aYZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=F5wgH+AYh/WyBJYoU8SW+a64FMCETkhDvGXcF7UG8O0=;
        b=BIa1k1dFs4gyF7AXzqzVrnGuCOHIKGp1v+zZ3tKvzxh7ukUt07QpjXD0SlPoYJ/Jel
         S8VVogQZ3EseBPbef8UU7dxna/JM/QazSdhhkI49mxpDKBDzRy2cnPslLlHITotwkyEh
         79FSzwg5RJcHCntuMooUsyxheGZeS4frPxNFKyNVwi7fKlrQcrpyaU6+iB3ES7cCcL2K
         kywFqo26mSxDahNnySrazR9gO9F4VK9j5k/gB45veHZvcI8/sDbqkgWNW5+ZiDks5hCf
         UE+EC+LH44KZXXsfDf/n+4Uto6RXyR27et0/Nzd0l2u17FQpuc5WAe7Hkzh+pLN/tlnA
         ZagQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aSWbR3Pv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id r5si148046vka.3.2021.03.11.07.17.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 07:17:56 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id p24so1757893ota.11
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 07:17:56 -0800 (PST)
X-Received: by 2002:a9d:644a:: with SMTP id m10mr7491620otl.233.1615475875698;
 Thu, 11 Mar 2021 07:17:55 -0800 (PST)
MIME-Version: 1.0
References: <1a41abb11c51b264511d9e71c303bb16d5cb367b.1615475452.git.andreyknvl@google.com>
In-Reply-To: <1a41abb11c51b264511d9e71c303bb16d5cb367b.1615475452.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Mar 2021 16:17:43 +0100
Message-ID: <CANpmjNP4Uz4Kmr+8KE_reyjRLCTj9q0s3ncQ26Xay+1Xwxvgiw@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix per-page tags for non-page_alloc pages
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	stable <stable@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aSWbR3Pv;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as
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

On Thu, 11 Mar 2021 at 16:11, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> To allow performing tag checks on page_alloc addresses obtained via
> page_address(), tag-based KASAN modes store tags for page_alloc
> allocations in page->flags.
>
> Currently, the default tag value stored in page->flags is 0x00.
> Therefore, page_address() returns a 0x00ffff... address for pages
> that were not allocated via page_alloc.
>
> This might cause problems. A particular case we encountered is a conflict
> with KFENCE. If a KFENCE-allocated slab object is being freed via
> kfree(page_address(page) + offset), the address passed to kfree() will
> get tagged with 0x00 (as slab pages keep the default per-page tags).
> This leads to is_kfence_address() check failing, and a KFENCE object
> ending up in normal slab freelist, which causes memory corruptions.
>
> This patch changes the way KASAN stores tag in page-flags: they are now
> stored xor'ed with 0xff. This way, KASAN doesn't need to initialize
> per-page flags for every created page, which might be slow.
>
> With this change, page_address() returns natively-tagged (with 0xff)
> pointers for pages that didn't have tags set explicitly.
>
> This patch fixes the encountered conflict with KFENCE and prevents more
> similar issues that can occur in the future.
>
> Fixes: 2813b9c02962 ("kasan, mm, arm64: tag non slab memory allocated via pagealloc")
> Cc: stable@vger.kernel.org
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Thank you!

> ---
>  include/linux/mm.h | 18 +++++++++++++++---
>  1 file changed, 15 insertions(+), 3 deletions(-)
>
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 77e64e3eac80..c45c28f094a7 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -1440,16 +1440,28 @@ static inline bool cpupid_match_pid(struct task_struct *task, int cpupid)
>
>  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>
> +/*
> + * KASAN per-page tags are stored xor'ed with 0xff. This allows to avoid
> + * setting tags for all pages to native kernel tag value 0xff, as the default
> + * value 0x00 maps to 0xff.
> + */
> +
>  static inline u8 page_kasan_tag(const struct page *page)
>  {
> -       if (kasan_enabled())
> -               return (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> -       return 0xff;
> +       u8 tag = 0xff;
> +
> +       if (kasan_enabled()) {
> +               tag = (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> +               tag ^= 0xff;
> +       }
> +
> +       return tag;
>  }
>
>  static inline void page_kasan_tag_set(struct page *page, u8 tag)
>  {
>         if (kasan_enabled()) {
> +               tag ^= 0xff;
>                 page->flags &= ~(KASAN_TAG_MASK << KASAN_TAG_PGSHIFT);
>                 page->flags |= (tag & KASAN_TAG_MASK) << KASAN_TAG_PGSHIFT;
>         }
> --
> 2.31.0.rc2.261.g7f71774620-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP4Uz4Kmr%2B8KE_reyjRLCTj9q0s3ncQ26Xay%2B1Xwxvgiw%40mail.gmail.com.
