Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLNL3D5QKGQEZCYWV3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id B30162805C0
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:45:17 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id ga21sf2564636ejb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:45:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601574317; cv=pass;
        d=google.com; s=arc-20160816;
        b=XaokpyXaTpwljaXNt0NYifiCsHxGnerfUecmq41afP4+Y7Bh998CejPXAXSCSQ0Tcl
         NqtzlC4CBwlkKjFcya3T8kktqt+hFs1fLSimSHNiVQXT9NHUEv4jgwJ0ho7lGRoWBevG
         zL6vgckLVSe2uEZtSydxfIvhKjF0sDD0gRlgeywx5dRREYC4LKklTNbhx0FT7IlfPGJT
         E7LncNLSFvoi7ncc6rD1hdeRbeu2VMQ+y5raXnsSQvSXg4L7I6N3Hop59HC5w9hUP4e3
         4qZecun2nQRYwyuh2rUJEDRYG7VLbdwDjduIvjZXpMTCoVFJ480n+FOAx7fHuxmEZc8/
         Y8HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=6yKYpaGVFwCcB56h/0+WaPpHWEaY+Sj8vaQ4YCmNVdk=;
        b=KEI9SBXPwBk0whS6EQtTjlyT7U5Ku2a22bFncHpo1xSzccW01hEnKe/VruYk6/aALB
         +Cf79AmGfWkAaLMA2taoHdVEDw3oOi2mwpBxdKuhqDRv0cqJA4VpICvUUt+Xlp86iafj
         28gRgcvsq/YlDmQvGHrTG8XE+r3fowgtZAD4ZEC3F8jJzjxA7vfilzK1qBR+TH38uPnr
         lw5PNUgx5dNyVZqN3EiWqzzxZdivFEzPtTtR3FiEmAfjqfbzqXcfZUbtemta6T5UDwsH
         c7RFgWN9XxTj3SGELiuvFePJittp2XItYCaARteLGQwtd6n6GMBWsqC+mI0Nutd4QDVb
         L1Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HIqQhj0r;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6yKYpaGVFwCcB56h/0+WaPpHWEaY+Sj8vaQ4YCmNVdk=;
        b=tpAXpimE4uZPh65/zbsHAPXa7u4I/+oQPDPfOWhPXKl7gaRlm+XWN3LBdp9fOTqTLH
         BExAIGkleyclkvk8vYyArJ8BuW6QfMl8tGCDesLPuml9xALSUztHr3Gr6HcHIEG6QlA+
         oFXua8KVhg1lfObeaL1B3Q0TD//8hKeDMlgBTFGKVOtWcbGOfLBjPs8YiYYHhhCstITW
         zcgJF3LaoIHBn7+JJLzuRmTmq/HZtzTmYQkisrQwZjLl1B1A5s48D9JxmbKhEv1WswTK
         qt2n5Ht7hc1lSwULX7nHjVNJng6gnr+BREFRwvl+8Q6tbm0DqWn6+4bOcJKqg1L1/FDz
         vEnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6yKYpaGVFwCcB56h/0+WaPpHWEaY+Sj8vaQ4YCmNVdk=;
        b=d2YHwRmZuq9RMFn9MOQWQ4dxTvLc/wB7N3w/BTLYTX0YJXgydpDUZjoA8R9t6Av2Xr
         trszMfU/0MYaJzjMxzW3AcmIoGRjGUhVN/uJUYZsAyUy7XOJKPk6DE0+r5Gr3fP/B4AI
         9DRJyK7ZGLXdNxSrh9mUl505DRXI2Xdzua+eVLWuW7VlTDAh//6YvFVXsJ/oShQ4PHH6
         6dagF80RK3QqvEppxOA2RVF2N/yw+juCgFKgQ7ib7cMOOydlpWSRbn/rHVUIy3C6RlxZ
         YcGGXMRKa1pSyvMbleQdK9ORLdJTtYWRVxFqTHsj+dY1W+/MGwQOwPMe5n0Y1E8qIgdY
         DUig==
X-Gm-Message-State: AOAM530NOvA4bren4XbVF06PPQ2+yGioAFtZY1IBYU1hs7bbJFUKvcb/
	RoDqKmiG816ENPV+oitFPT0=
X-Google-Smtp-Source: ABdhPJyFHBHB+rRdzd9imXf0+5GNeKTbf7VP31fhqxAzM7JyLu18yWQrI5hCDHPcK4BfwfnnUHoKuA==
X-Received: by 2002:a50:eb92:: with SMTP id y18mr9227553edr.373.1601574317492;
        Thu, 01 Oct 2020 10:45:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:39d8:: with SMTP id i24ls1026938eje.11.gmail; Thu,
 01 Oct 2020 10:45:16 -0700 (PDT)
X-Received: by 2002:a17:906:1955:: with SMTP id b21mr3754345eje.42.1601574316462;
        Thu, 01 Oct 2020 10:45:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601574316; cv=none;
        d=google.com; s=arc-20160816;
        b=hypDQpzsUJS4CXOXXLsmq26/46/RPHwcq7JS3cxuQ7GmeGclChLMqrAZo9btSW2RH2
         PxhqBEJ/KnB583py9F7YGPTdLio2Vt6afgC+aVQg0ZuN9tbvwHF2vCwbo5wcD4uZ/PpB
         uds+9WfW1xbGlG87bSsfLDvKHrOrMSEWM/uaRDF6N22Nxu/AoKTVXsN3YBJvILqZpV8Q
         rnK/oJBKzA8zmoLMjFhGfX3MeNCK5dHHeEqx4aHyzqRByDj7rXEfCe/srcRkkkyhlWDl
         gYN+DYWubTkqPwinvNzFCET1Y1toAmt9zEOjUM551r4N0VlmWUNvNkeExCAB4dxDd7ta
         MPwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=SdTU4gQ/GSNzMeDvk9Yhuq+mmVJCx1AqWYuvXYSPp6E=;
        b=ArTO6L1wKXNTQ0IfWonUwjgIPrMuKGJC+uRJQZn1YkW5qLcdlAOcWMCknok28mZ/vq
         RTItWA6Lc5Cj/0eZS5H3BuI6z8EmPc1TwrO+AyRuvKqYtt94T9yaZVZOusIIWuSLq1lj
         WTdxuYXB8soGtB4AqtbnqFZnB2XixJBL1qsXNeAouRdaUshsTGXRXOp13Sr6WJ5GsdkK
         T9woyi1K7Z/rYaX/9HFLMKziGJFEkkuQVNStaKprkp8kTGOWm+w/98/hnMfflHwvIUfp
         bs6HAXvCwmA/UWXTBaPPrt0/0fgPnm15USPaPvYdtZF0z0BErEsRnhpBCVB21wXfqviO
         bGfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HIqQhj0r;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id a16si268263ejk.1.2020.10.01.10.45.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:45:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id c18so6777676wrm.9
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:45:16 -0700 (PDT)
X-Received: by 2002:adf:f6c8:: with SMTP id y8mr10971682wrp.217.1601574315975;
        Thu, 01 Oct 2020 10:45:15 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id w7sm9695314wrm.92.2020.10.01.10.45.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:45:15 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:45:09 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 16/39] kasan: rename addr_has_shadow to
 addr_has_metadata
Message-ID: <20201001174509.GL4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <fd0103571c825317241bfdc43ef19766fd370e4f.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fd0103571c825317241bfdc43ef19766fd370e4f.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HIqQhj0r;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, 'Andrey Konovalov' via kasan-dev wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> Hardware tag-based KASAN won't be using shadow memory, but will reuse
> this function. Rename "shadow" to implementation-neutral "metadata".
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I03706fe34b38da7860c39aa0968e00001a7d1873
> ---
>  mm/kasan/kasan.h          | 2 +-
>  mm/kasan/report.c         | 6 +++---
>  mm/kasan/report_generic.c | 2 +-
>  3 files changed, 5 insertions(+), 5 deletions(-)
> 
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8dfacc0f73ea..0bf669fad345 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -146,7 +146,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>  		<< KASAN_SHADOW_SCALE_SHIFT);
>  }
>  
> -static inline bool addr_has_shadow(const void *addr)
> +static inline bool addr_has_metadata(const void *addr)
>  {
>  	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
>  }
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 91b869673148..145b966f8f4d 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -329,7 +329,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>  	untagged_addr = reset_tag(tagged_addr);
>  
>  	info.access_addr = tagged_addr;
> -	if (addr_has_shadow(untagged_addr))
> +	if (addr_has_metadata(untagged_addr))
>  		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
>  	else
>  		info.first_bad_addr = untagged_addr;
> @@ -340,11 +340,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>  	start_report(&flags);
>  
>  	print_error_description(&info);
> -	if (addr_has_shadow(untagged_addr))
> +	if (addr_has_metadata(untagged_addr))
>  		print_tags(get_tag(tagged_addr), info.first_bad_addr);
>  	pr_err("\n");
>  
> -	if (addr_has_shadow(untagged_addr)) {
> +	if (addr_has_metadata(untagged_addr)) {
>  		print_address_description(untagged_addr, get_tag(tagged_addr));
>  		pr_err("\n");
>  		print_shadow_for_address(info.first_bad_addr);
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 42b2b5791733..ff067071cd28 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -117,7 +117,7 @@ const char *get_bug_type(struct kasan_access_info *info)
>  	if (info->access_addr + info->access_size < info->access_addr)
>  		return "out-of-bounds";
>  
> -	if (addr_has_shadow(info->access_addr))
> +	if (addr_has_metadata(info->access_addr))
>  		return get_shadow_bug_type(info);
>  	return get_wild_bug_type(info);
>  }
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 
> -- 
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fd0103571c825317241bfdc43ef19766fd370e4f.1600987622.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001174509.GL4162920%40elver.google.com.
