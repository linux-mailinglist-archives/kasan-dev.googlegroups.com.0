Return-Path: <kasan-dev+bncBDW2JDUY5AORBKO7SOKQMGQEQOBQFUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F959547754
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Jun 2022 21:40:27 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id l23-20020a056830239700b0060c2c71255dsf986389ots.1
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Jun 2022 12:40:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654976426; cv=pass;
        d=google.com; s=arc-20160816;
        b=BRLFEP7U/So3U7ipoNuga1+4Jdp6gJi/BltuRU7dXKsCDDS3Fc9koAgBvl/L6W2YEr
         kVT4ZmneX9+NHuEyeS/YedWmblhvrUrXN3tm79fNeFgLTBpyzxBRMkexj1Gp1TIW3Fgm
         K81/iwgIyjoNqkkyxvz2RnJ+UXXQcy2ABJR8Dg2BBcYqDRg6L1gCW6U0TsFGehtk/OGp
         vZV1tyZkL6QxY2Ql3hKGOOElSILtlqruhRiaQ17cB+CznvbndurbRbgk2kgq5BDMVimT
         +J59y+0TF0/nySbL6CEUmww/lXCPBHacKVmnlny2+smDjF2vnH7yoRXfGX+NnXDlt6Fx
         wGkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=0iyKNOzoc9ZibcD6yYVxgltw3gMeKxxXhhoSACVByvg=;
        b=0VR8B8GgEBteRPu8YqvGBH9f70XiiNCy2Uucqkh5U8JsdJ42mzopIVzreYsB8wRtT4
         B9d3Xt47GmRe3aPrnx1iyjEGWzAiToMSh1uUAB4uyfRZLviaiq5lhKZwzS1dzSainQy/
         Nwrpe8fA7q5j7h5NpG+CmtSsHbJW7JbHPyIEdaTsK1R92YmBiY2Id5KAzXWaodTTWuro
         pzJzgnwDKqjiB1rOfSMtK8KulfVEo8Y69+nvvUKrNwiK5UfJpRsZ5sposWCdRRrj09AM
         B4LVsbE/h497oT4ZEdZaNLR63Rizrm3vgILZaF0ED8NP8t0UxvNUhCj3iaLtGp8gR77A
         VtPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=BXJRsYZ8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0iyKNOzoc9ZibcD6yYVxgltw3gMeKxxXhhoSACVByvg=;
        b=JVJOvJXWJxcwynHjab5zkyjUsR00bpNb4bP4PquATJSieGWq5PjlGtPw8i2getBclp
         WId5hxAZadgzbFp0+BRZ+//xUKQCJSJ/YwgRbP+Hjv+YT6DWv/vXbFDK4xpd9XwLlTt5
         DyWlntfk4mGC0289gV/lCnBnohH87Ua8S0YyU2IcBJs5apQ0KpTU50a75YvFYsEyinRa
         4tzz06w2Y+5p9GGnmHn1IPdMkqOnGkFdJzJVhWKu6M7dCsXEHazT2oCWYGmN7ftc7bOE
         epj+aR3S6ZnawbYtNNNXbADvMp9+QqYRtaDht6AQsF8Lk0FTksQFvMl7PqW1GrRwi60O
         v0Tw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0iyKNOzoc9ZibcD6yYVxgltw3gMeKxxXhhoSACVByvg=;
        b=nA0ro21IrfHP0lg6HqGmtFvv5+945RcPsDFXk+LRsI5GdsES8CkuTk8b/S9sO7e9IX
         HPfOlEPBK4xGg6AZhEP36xaUolNrE3yQ2wT9MAzUYs+TaLPY6N+bdrs0mslxccTrhSAa
         QcrUKXKgO9KEBC21DdMA2rNHflLQRkvrB/1cOP+Dg9OzP+6xmsQfJZTL0nFougVXv7Rn
         vvTu90LCdPJed2FhPr0zkjVCTmg3PxkS6DK1rPINYUyg/btFwFznsR3hzBzqF0STH77C
         Axsa6mcq5PnpirV3/EyPTPjdeyPYdKzg6letPm/AFr7JuQi9KdPB3uk1Sql4gFvX7rUZ
         1hyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0iyKNOzoc9ZibcD6yYVxgltw3gMeKxxXhhoSACVByvg=;
        b=uuGWgXdan3f0H4u0BRAHv+NdykWrn7HivcRdFkSgEHosbfXrsUTQDe/b/Ou3tDKBIC
         YgtiNWEdhzsbIrlGvZ9yxIcdutcR/K0TEorS5eSJqwB5x8LK8XKwkEIN5R8S8gDz/Ne6
         BUiwRoTRV4iXch8GeX1vGMv6NUnF0acVWSrTqA7PrbI/7VZO7Pl1CEKepXs9Nei2Gk9O
         FbqXR81zkGOxDsiReG62JIVw4sAijnGMfpODaClsmh1CxJSlfTmC4DvRct8YGTsyYhQf
         9pylx3ALRbdX0vNoy1LC52iGv0oxz2UMwZM3+UWkwuzlszQTfSouw4eXukmBWqpeW27k
         Br/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bTljpnxxEwsKfXrpny/urQk1zdUSCS0Kqd1XGckTVVRqpgppA
	TEbIHYVx9bBNGHhLTgss7iE=
X-Google-Smtp-Source: ABdhPJwbpEZn1IibJQ5f9IupDMuvJuo9O9YnPZXeWG/sd1ce7Sm9pdvYgEq2co8eYN/XLFDNUSPjrQ==
X-Received: by 2002:a05:6870:3320:b0:fd:fa2c:a35a with SMTP id x32-20020a056870332000b000fdfa2ca35amr3534464oae.30.1654976426011;
        Sat, 11 Jun 2022 12:40:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e156:0:b0:35e:a621:2001 with SMTP id p22-20020a4ae156000000b0035ea6212001ls120385oot.5.gmail;
 Sat, 11 Jun 2022 12:40:25 -0700 (PDT)
X-Received: by 2002:a4a:a54e:0:b0:41b:9f80:50d4 with SMTP id s14-20020a4aa54e000000b0041b9f8050d4mr9921184oom.88.1654976425543;
        Sat, 11 Jun 2022 12:40:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654976425; cv=none;
        d=google.com; s=arc-20160816;
        b=kzDq6rImBPlJpZ/HzA/ZGbaelBJL+DSie9+q7AOtAgjLg5KlbzkUUWZrYHU4EAw0wm
         WkkTWcWJqjO+h7sxmBpUiNjdsujYjagfw6jpWxDP8QbCiKgmA7a4TlXrc6gAq0QIdycR
         uHMRPcPCYJoc9AJLoGAOVbKTK6/BybmHmKRo9/U2V6Yh/M8ufffVSP0WwHsPgti2pDHo
         ZHfDX69Tnwt5Lk003eGQAwACzhO1hKStzI1cQDRScxhV0WrcL0V3Fdqta07DeD4xTDn8
         0RcJ/pl6UAq9DVR5j4sqNKrENtNSHGvMjWz+4aD1tw7t+zfVthMzwuV955Bn5Ylu7FiO
         0A0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=R25EekwyNOEiwlYnKcmMYUuLmBwG/+0RRzVWEW/5EYg=;
        b=ZJHla7YCJlYvCROjxFo9HnPp4zHG+x/Sw7bHaTBASKYoN28ZnOUlhU4AT10q3SDErb
         lAYHWWiy5tcOJohDrijPFTTnihPe+MH2IPe7iGLzjOoDUEVxyNjlvo5esiYU44q8Deoi
         OajBVPW27vSTGku93I+HNbooD+lX+dwhbhQk10gadBcBfaiWxu4Vm4ZTzOmaaAH0NMMb
         YkAdTjSCu5x68IL4VQRJROB1VbPUVPDhPQqFxaZEBBghah/Zg9uZxds9CCbupIqkEJ5r
         KZ2fiRtFsXRNzyoVCNEpL/+7ZbY0WDaQWpdrCqypDsW+0NHq3UyiJX7GphxBIGQfGc9I
         8Rvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=BXJRsYZ8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id bk13-20020a056820190d00b0035e8a81e5fcsi137661oob.2.2022.06.11.12.40.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 11 Jun 2022 12:40:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id i16so2299256ioa.6
        for <kasan-dev@googlegroups.com>; Sat, 11 Jun 2022 12:40:25 -0700 (PDT)
X-Received: by 2002:a05:6638:381b:b0:331:b4c2:1f3a with SMTP id
 i27-20020a056638381b00b00331b4c21f3amr17960818jav.71.1654976425228; Sat, 11
 Jun 2022 12:40:25 -0700 (PDT)
MIME-Version: 1.0
References: <20220610152141.2148929-1-catalin.marinas@arm.com> <20220610152141.2148929-3-catalin.marinas@arm.com>
In-Reply-To: <20220610152141.2148929-3-catalin.marinas@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 11 Jun 2022 21:40:14 +0200
Message-ID: <CA+fCnZeR2ZqHxH4__joq1jtED6rohCk7L9KJSRGbsePdOfksxA@mail.gmail.com>
Subject: Re: [PATCH v2 2/4] mm: kasan: Skip unpoisoning of user pages
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=BXJRsYZ8;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a
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

On Fri, Jun 10, 2022 at 5:21 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> Commit c275c5c6d50a ("kasan: disable freed user page poisoning with HW
> tags") added __GFP_SKIP_KASAN_POISON to GFP_HIGHUSER_MOVABLE. A similar
> argument can be made about unpoisoning, so also add
> __GFP_SKIP_KASAN_UNPOISON to user pages. To ensure the user page is
> still accessible via page_address() without a kasan fault, reset the
> page->flags tag.
>
> With the above changes, there is no need for the arm64
> tag_clear_highpage() to reset the page->flags tag.
>
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Peter Collingbourne <pcc@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/mm/fault.c | 1 -
>  include/linux/gfp.h   | 2 +-
>  mm/page_alloc.c       | 7 +++++--
>  3 files changed, 6 insertions(+), 4 deletions(-)
>
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index c5e11768e5c1..cdf3ffa0c223 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -927,6 +927,5 @@ struct page *alloc_zeroed_user_highpage_movable(struct vm_area_struct *vma,
>  void tag_clear_highpage(struct page *page)
>  {
>         mte_zero_clear_page_tags(page_address(page));
> -       page_kasan_tag_reset(page);
>         set_bit(PG_mte_tagged, &page->flags);
>  }
> diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> index 2d2ccae933c2..0ace7759acd2 100644
> --- a/include/linux/gfp.h
> +++ b/include/linux/gfp.h
> @@ -348,7 +348,7 @@ struct vm_area_struct;
>  #define GFP_DMA32      __GFP_DMA32
>  #define GFP_HIGHUSER   (GFP_USER | __GFP_HIGHMEM)
>  #define GFP_HIGHUSER_MOVABLE   (GFP_HIGHUSER | __GFP_MOVABLE | \
> -                        __GFP_SKIP_KASAN_POISON)
> +                        __GFP_SKIP_KASAN_POISON | __GFP_SKIP_KASAN_UNPOISON)
>  #define GFP_TRANSHUGE_LIGHT    ((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
>                          __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
>  #define GFP_TRANSHUGE  (GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index e008a3df0485..f6ed240870bc 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2397,6 +2397,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>         bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
>                         !should_skip_init(gfp_flags);
>         bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
> +       int i;
>
>         set_page_private(page, 0);
>         set_page_refcounted(page);
> @@ -2422,8 +2423,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>          * should be initialized as well).
>          */
>         if (init_tags) {
> -               int i;
> -
>                 /* Initialize both memory and tags. */
>                 for (i = 0; i != 1 << order; ++i)
>                         tag_clear_highpage(page + i);
> @@ -2438,6 +2437,10 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>                 /* Note that memory is already initialized by KASAN. */
>                 if (kasan_has_integrated_init())
>                         init = false;
> +       } else {
> +               /* Ensure page_address() dereferencing does not fault. */
> +               for (i = 0; i != 1 << order; ++i)
> +                       page_kasan_tag_reset(page + i);
>         }
>         /* If memory is still not initialized, do it now. */
>         if (init)

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeR2ZqHxH4__joq1jtED6rohCk7L9KJSRGbsePdOfksxA%40mail.gmail.com.
