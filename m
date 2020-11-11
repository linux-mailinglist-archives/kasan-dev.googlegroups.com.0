Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHNSWD6QKGQEK3IYCZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 61EF52AF717
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 18:02:22 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id b206sf1000962wmd.3
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 09:02:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605114142; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z6p+ICnABYtBB6ZjG3oKqnIM7s4nCXar1LJXNCiFsrCUbPzeP75do/lLdQa4yr9+fY
         JDMgYGKOTGRzaMeQhowdgK+YbPE1PLrjEQYc0+070gx/2htSdaE9Yr3r4q/II5iprRHW
         6G5fu6NBfm4JhdwiJqZTyJYAV/5cuCBDBisT+c9sNG2fmMqBGAt1jTlmALZkihRjfHNp
         sU+FG3q5pvfb1gF/6iPVZRxkUmx16KuJa7MMK+JpfSLJXgVpnqGEnq7NiM4pS/jMibNo
         xMv3KcsBtxCHJjeFeGEGbD7IcUHJgbp9MOgd251LpmXOUQqcjVIO/de6odm7UFe46xYf
         NFlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=XcEzH4C3VZRxa2ru4AWuIJwIa8NCFW/NgXq+G8I44Ok=;
        b=FWWURcHQpfmgaCbM0pUCcMpBz6CNyXPgdEkykYlvg4wRQ86P1uqfb3Er4pGWgyfBd1
         /jUYkyDmtgq1wd6xz5mPkbcypqb6VFhcE4Qd/8eRsn/TVWhi5BULHdbomnNkHaZO9YDA
         7N9c+hBUZuzCB5czCbyWQvVxpoL7mVoegNJhKI4pFdR7ozOGXb9KsC3bIqlhSAOIm23z
         F2PkAG2c3C4amO+ZJKinVkEu0S2E0ndAmoiu2OTx2+2FomAazlawfCrhQUVbzPqwsgEK
         w4P6ixkd3qZC1lptASiQUuth+IIm3IYTnLuUMcPXs7Zv2680qkuI/pQkq+M5tN7j7W/d
         ESaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C0lPrtGZ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=XcEzH4C3VZRxa2ru4AWuIJwIa8NCFW/NgXq+G8I44Ok=;
        b=ngfC9AiHYPRfG51RTVUwssdV6YKx7UgxDemBI2LE3SRFJYag396w+Q5+7Dp3IXVyOq
         7f9I5p0wUtsG2NGzPEz2sMKY+nXDsFmWS1fvjV/k7QbRPQUUuvdHKDcM8SysIR/njkUN
         Hz8RNprfaALz7FJnulHqI/Sq1cYpvc6h+p3v+1NhzD/LvPNoyoVQ5mqCJo2s5e/wh5bT
         jmUvECCAlCqv+Hj7BchoQzAqAGBasesJgY0TE84se+XAuDQO0Xvq6OAnwPHsRxmonwCq
         25NoGyDkpHw0AtKudY9JTRFv5lV2CDko5QF+gLFFfLGAhgUgF9fIqCDR5p2KIcRww0qW
         TvWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XcEzH4C3VZRxa2ru4AWuIJwIa8NCFW/NgXq+G8I44Ok=;
        b=EQ9NS2HKWHIbDtXa2pxJbSae+eKccbLejisPvHqrgYkKdnsn8R+c1CW7vVXP5um/Qz
         p1TgxT63/7QWtt4aJqBoV7nQfY0MoOjCEmm3PIQ4d2MCFM5t1D2b9XgfaHUPwvPcU+0q
         KJocOMkukW1VGYR00zxlJtKnqtM80Hn8XaqLXXC9Z1snzBYvyPG7WfEXiDrkbCFY8QZi
         rnuq/jU6mnXXdLMKx1X7F2NtoFPuNkIRNZtG+Zucw5mkVNxNA8DIh/VTxlcFSQqFVb19
         8h/vhjrGdjhFhDjuAEmmq0yjuf/6MIhR4W80DVHSokI4qjtKUrv9Z4mDE4TUsyZHta05
         NoCA==
X-Gm-Message-State: AOAM530C8T9+Y9/Cabm5fyn8vS/Fic/I+5xjhazMl0dKwwRImwisG/Tn
	CzVNwE+0MPY9dTRk49KcQOE=
X-Google-Smtp-Source: ABdhPJxwhYr8Kk6GyG0F5auKnzQlipMupcxmb69xTLprZiBo7Dh7bVmgpBaK8kikAzqSYG+RK1FjtA==
X-Received: by 2002:a1c:21c1:: with SMTP id h184mr5465691wmh.106.1605114142134;
        Wed, 11 Nov 2020 09:02:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls358219wrp.1.gmail; Wed, 11 Nov
 2020 09:02:21 -0800 (PST)
X-Received: by 2002:adf:e551:: with SMTP id z17mr31805438wrm.374.1605114140976;
        Wed, 11 Nov 2020 09:02:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605114140; cv=none;
        d=google.com; s=arc-20160816;
        b=orASNvvKzMSuiU4fFv7OsfooIj+5Ky2tkcxBSTFHz+j8GdH+jmW+kmhRO1vzvl/sbN
         1cEsRlWqTh3qhL5RPZVWGh6eJI3B3m92X98N1uR2C1H+3YBn8b0+V3vWl/N148iepADd
         FSOxWwYkogccqLnjUIKlg49I56Kv4WzK1jAe09CIZ7L9wQa3PHIYyVxfrShAt/NAteG0
         /rscoVSt5oKXS9pLNEtdddzfk0BrtB14mRrRuTFwOLDtlZgIKZNH4iZtXk0nhhf/6SI5
         vmBMdLX+kOZQ4vAsk7VvkUQVIYxT0S3yYesgeDLFi7g72T3qHaZRe9WTnkrJdBYt6Nqy
         ySsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=X24sjVNgpxyUWyZmmGXSuDW61sfZW/dMlYXC795Q6f4=;
        b=s5/tkqtxZsE37VeIndhcMh+NJMzN2uIMno2EZkiu1c5+CrsQoSbQ3T55w3tsxSWfCl
         1uTirEtN9Y4uFWre13dcib0EqkDcu7gMGt6w6RMBHY+arby9ffRLzjKnZRQFz/Um/wgB
         zR5/4Y/Hiw2yyivaXTptVZd4RylrLyfwxndkDCORc2w27ggJ7evnkwYUeBFDlBmr+BgK
         uz4TJsZ0iULuzSy0H+/+jP4+LxLgxmMcKAmpW6fqRh9caLP6DDlbIAv0X2q8nJ8iCyaa
         Fmtnrc6dQanwSBRWLNmYc65DlEfJ0SFSq6nFYdkeO6LJS1QQL0aSLie4ocPV+eqDBBkB
         Is9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C0lPrtGZ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id i1si97367wml.2.2020.11.11.09.02.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 09:02:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id b8so3241036wrn.0
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 09:02:20 -0800 (PST)
X-Received: by 2002:adf:e484:: with SMTP id i4mr18558640wrm.398.1605114140431;
        Wed, 11 Nov 2020 09:02:20 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id i11sm3321276wro.85.2020.11.11.09.02.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 09:02:19 -0800 (PST)
Date: Wed, 11 Nov 2020 18:02:13 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 08/20] kasan: inline random_tag for HW_TAGS
Message-ID: <20201111170213.GJ517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <73399d4c0644266d61ad81eb391f5ee10c09e098.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <73399d4c0644266d61ad81eb391f5ee10c09e098.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C0lPrtGZ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> Using random_tag() currently results in a function call. Move its
> definition to mm/kasan/kasan.h and turn it into a static inline function
> for hardware tag-based mode to avoid uneeded function calls.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Iac5b2faf9a912900e16cca6834d621f5d4abf427
> ---
>  mm/kasan/hw_tags.c |  5 -----
>  mm/kasan/kasan.h   | 34 +++++++++++++++++-----------------
>  2 files changed, 17 insertions(+), 22 deletions(-)

Reviewed-by: Marco Elver <elver@google.com>

But see style comments below.

> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 49ea5f5c5643..1476ac07666e 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -42,11 +42,6 @@ void kasan_unpoison_memory(const void *address, size_t size)
>  			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
>  }
>  
> -u8 random_tag(void)
> -{
> -	return hw_get_random_tag();
> -}
> -
>  bool check_invalid_free(void *addr)
>  {
>  	u8 ptr_tag = get_tag(addr);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8a5501ef2339..7498839a15d3 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -188,6 +188,12 @@ static inline bool addr_has_metadata(const void *addr)
>  
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>  
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> +void print_tags(u8 addr_tag, const void *addr);
> +#else
> +static inline void print_tags(u8 addr_tag, const void *addr) { }
> +#endif
> +
>  bool check_invalid_free(void *addr);
>  
>  void *find_first_bad_addr(void *addr, size_t size);
> @@ -223,23 +229,6 @@ static inline void quarantine_reduce(void) { }
>  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
>  #endif
>  
> -#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> -
> -void print_tags(u8 addr_tag, const void *addr);
> -
> -u8 random_tag(void);
> -
> -#else
> -
> -static inline void print_tags(u8 addr_tag, const void *addr) { }
> -
> -static inline u8 random_tag(void)
> -{
> -	return 0;
> -}
> -
> -#endif
> -
>  #ifndef arch_kasan_set_tag
>  static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  {
> @@ -279,6 +268,17 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  
>  #endif /* CONFIG_KASAN_HW_TAGS */
>  
> +#ifdef CONFIG_KASAN_SW_TAGS
> +u8 random_tag(void);
> +#elif defined(CONFIG_KASAN_HW_TAGS)
> +#define random_tag() hw_get_random_tag()

Shouldn't this also be a function?

+static inline u8 random_tag(void) { return hw_get_random_tag(); }

Or is there a reason why this was made a macro?

> +#else
> +static inline u8 random_tag(void)
> +{
> +	return 0;
> +}

Could just be on 1 line:

+static inline u8 random_tag(void) { return 0; }

> +#endif
> +
>  /*
>   * Exported functions for interfaces called from assembly or from generated
>   * code. Declarations here to avoid warning about missing declarations.
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111170213.GJ517454%40elver.google.com.
