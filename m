Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC5N3D5QKGQEP33EWJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 788BC2805D2
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:48:59 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id d9sf2350625wrv.16
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:48:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601574539; cv=pass;
        d=google.com; s=arc-20160816;
        b=bwpwsLytW/lXkO09GOHB1f3QaEZ9GVPDM33ssAOIwSjnCyJ9AjIa2iadABTqPPX4Z6
         nNuRUY+exzEqkWIdwOLdRvIdF6cyBZirOv5MwwvkGVdOzix6OJ5sTle09Z+ZkaE7TQBJ
         wnVfXrRPIf7SiGxeoU+15j4DoilOGX4NwX8uBTq1ae2A8XD2pISrw5yF3v0F/kLp4oS8
         I22wk6eTi2ozU5i+hVcDASTLqcKF+V9tp7e/AEcUulNOBFSQojGTZsW0q3XAgev3c7ub
         YWpMFPy32Jw4hr+E1UoFSlgpB+N8TGAJ9eg42QEZYBnRVwfbanLBjmF035e/vP6boCS7
         zYfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yuZnbp7GIu+qH5A0UyH91aCk3rFxjevRbepQ85STMTI=;
        b=wPuvhrwLfT4JlSST6BWHyUmpYtWiZ69mkBtPycqiaTafkwgwcU9IRdm5e5Ls7AefS3
         mBXAuUKqhsWBWTTUFzJc6r9Z7RwVy33ubV7DEc1oQBr/GrB/7VcSplDI92ksJMxmSOE8
         ORZaM8KKzje4+heU8mcW6pwjM8mJK7RWRH/dORWqX/vtbVsN5ZLQN0Qnb1x6gUOwQqZO
         HKIN7+Ei0N0UgjkwuT6jMajeWMSRgApHmoKI2mVhXs5W7maWyqnt80mEWA38xlS037aj
         W4UiCKRZ4KbBaDSDUIixuhvvMSHOGqBKBh0lxICT64108WHgXxuOxGpJT+H0PRpEnMrO
         IwUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GQIN6Bic;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yuZnbp7GIu+qH5A0UyH91aCk3rFxjevRbepQ85STMTI=;
        b=g5JGcLnRJK3KVv7QonVNLbSoYdXXxqilTUzxsDObv5fXXPo0jOOmlF4+ka+QZ+f4mE
         foPDj+ebzyqMpECkMsm6SYsAUXZm53Ky9p/Gs+NSanP20rvJtZ2ou6gFdNQf0RMuzOuC
         FDcJpBSPgtDr2asKLLR4370ulrXOPlxPQCBxjRFBPgNyjkj7ALkiizCeEAUIuTb1wII5
         a5/jtvnwuJdKnccoCUduwQvMttUc6dei/6w9a/J3ejgLn74+nTOAOob5kbFAgPmKZ3i0
         Sz1rP80Z3QKtO0p0ScnAKbz+Q5BdAF6ggMWjVpQ+0wv9/FbaRiuX/LPE/xhZwQRL4ocv
         5rsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yuZnbp7GIu+qH5A0UyH91aCk3rFxjevRbepQ85STMTI=;
        b=Ew/SiFzYZ36mOZLb4EeFffdILJWp5ptlDC5QTEfN9xXCGWWSXx/k81wcIhgNUrHHC2
         TmFYzA/ncX9XjiXSW31oQWg5E1E2XMaRCU5hv94fvjolTAE8Pldl7wnDuymRCQ1PZLzL
         GVbNEBpBAxzQQRa/mqasHrJZEoCDm33E5mByjpgfy2+L80XtvkglWlgzUKXpq867IaIZ
         p3hg7BVe0ZnnVVRQkpwbKTZDPLwFHHa7aBQFaxFRhcZWXJlBaKZnv6PF3A52PV8UNX5v
         xStkI89RyjEObBkYGhq+kBC6GKDRT8MuovBsi8YEwNxTv1TKg86/aY8VwO6TgCbjfK89
         2f4A==
X-Gm-Message-State: AOAM533rSwnxmFlKvomjnOozVo6r5OOhqlEvsxyzmqOB6t2bxS9IKxl+
	SHYw4OR7FiCHYiakqSzeSXo=
X-Google-Smtp-Source: ABdhPJySAGSRQwlL/Co9JJ8LddsqRi15g8zS5hxWn6KqjvxYTjwoFHvASs9/PdDL9rosBcXR5yAhOw==
X-Received: by 2002:adf:df81:: with SMTP id z1mr10748136wrl.9.1601574539246;
        Thu, 01 Oct 2020 10:48:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbc4:: with SMTP id n4ls3303933wmi.3.gmail; Thu, 01 Oct
 2020 10:48:58 -0700 (PDT)
X-Received: by 2002:a7b:c151:: with SMTP id z17mr1214183wmi.53.1601574538368;
        Thu, 01 Oct 2020 10:48:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601574538; cv=none;
        d=google.com; s=arc-20160816;
        b=uCrBQ5XQ79t/zRKLsW1DEYPfb+Q7QG5LNB8WfdBuZGe8eOk9MKx5EbH++jMdliSRwH
         kKM1QDOY7FqggghGaigouEm10DnZ/epVRXKo1/ehWeTXF1WEr/WGROhdqxxj3G6z1+jX
         AGHg2sBCAa5HkAey19FG4Kx9E6vdyz5pHtywrozydFNHTgWsv2VEDXNqrxPj4rsvK8K/
         TjnoTXMd/VKzI7l+O3+XV2nlwMFxm/dOKQGlZXxNlGgSKAj6lHORjZ2X1XTa8MrQpBbt
         y3bIo+T80FApYuSgoiBZFkvpuGzdTZhds4oaYNNdhYoyTCQUc947yoZs9LhMfPwQYQ1B
         FJmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jxWceFBJemERUVJXLpe5M4H3KWrtmYrogpYMra7Mtm0=;
        b=xQem65py214axhHjD0JFHn0AAEDyRazCvLHCKonbYfL4wXtKMnMk82EevQzdkktPNW
         vHNbbaJaHEOqbc0IxtU1UIxTWnEde3l0UIhVSSZFJPxWVD3SJm1Q0MaxDOlKzEv4aS5I
         iJf/QTJ1IAkQK16Zc1x0YGWguQBup8bRgUmcEECwOgW5JXN/6tKuSpeXmRpcsynOkmRu
         cQ5D9BDNyNAJMU+pwiKKBjXpLD8Eb1qIw2nB3Vww2NnKqM7hL7vHXvJtTGhWqXaBog1z
         Pes9fM8ZvAgcLDaiPSCegaAqDsJie/5sq0KWouvr08BRjf+ARdqNaw8MwBIrm5nGTY3W
         ySrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GQIN6Bic;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id 24si27069wmg.1.2020.10.01.10.48.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:48:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id x14so6794987wrl.12
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:48:58 -0700 (PDT)
X-Received: by 2002:adf:9b8b:: with SMTP id d11mr11001000wrc.71.1601574537863;
        Thu, 01 Oct 2020 10:48:57 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id u66sm6396017wme.1.2020.10.01.10.48.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:48:56 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:48:51 +0200
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
Subject: Re: [PATCH v3 19/39] kasan: rename SHADOW layout macros to META
Message-ID: <20201001174851.GO4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <cac8b9713e5d3ac1ab767a9cc42c61b04c46bdfc.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cac8b9713e5d3ac1ab767a9cc42c61b04c46bdfc.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GQIN6Bic;       spf=pass
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> Hardware tag-based KASAN won't be using shadow memory, but will reuse
> these macros. Rename "SHADOW" to implementation-neutral "META".
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: Id2d836bf43b401bce1221cc06e745185f17b1cc
> ---
>  mm/kasan/report.c | 30 +++++++++++++++---------------
>  1 file changed, 15 insertions(+), 15 deletions(-)
> 
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 67aa30b45805..13b27675a696 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -31,11 +31,11 @@
>  #include "kasan.h"
>  #include "../slab.h"
>  
> -/* Shadow layout customization. */
> -#define SHADOW_BYTES_PER_BLOCK 1
> -#define SHADOW_BLOCKS_PER_ROW 16
> -#define SHADOW_BYTES_PER_ROW (SHADOW_BLOCKS_PER_ROW * SHADOW_BYTES_PER_BLOCK)
> -#define SHADOW_ROWS_AROUND_ADDR 2
> +/* Metadata layout customization. */
> +#define META_BYTES_PER_BLOCK 1
> +#define META_BLOCKS_PER_ROW 16
> +#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
> +#define META_ROWS_AROUND_ADDR 2
>  
>  static unsigned long kasan_flags;
>  
> @@ -238,7 +238,7 @@ static void print_address_description(void *addr, u8 tag)
>  
>  static bool row_is_guilty(const void *row, const void *guilty)
>  {
> -	return (row <= guilty) && (guilty < row + SHADOW_BYTES_PER_ROW);
> +	return (row <= guilty) && (guilty < row + META_BYTES_PER_ROW);
>  }
>  
>  static int shadow_pointer_offset(const void *row, const void *shadow)
> @@ -247,7 +247,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
>  	 *    3 + (BITS_PER_LONG/8)*2 chars.
>  	 */
>  	return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
> -		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
> +		(shadow - row) / META_BYTES_PER_BLOCK + 1;
>  }
>  
>  static void print_memory_metadata(const void *addr)
> @@ -257,15 +257,15 @@ static void print_memory_metadata(const void *addr)
>  	const void *shadow_row;
>  
>  	shadow_row = (void *)round_down((unsigned long)shadow,
> -					SHADOW_BYTES_PER_ROW)
> -		- SHADOW_ROWS_AROUND_ADDR * SHADOW_BYTES_PER_ROW;
> +					META_BYTES_PER_ROW)
> +		- META_ROWS_AROUND_ADDR * META_BYTES_PER_ROW;
>  
>  	pr_err("Memory state around the buggy address:\n");
>  
> -	for (i = -SHADOW_ROWS_AROUND_ADDR; i <= SHADOW_ROWS_AROUND_ADDR; i++) {
> +	for (i = -META_ROWS_AROUND_ADDR; i <= META_ROWS_AROUND_ADDR; i++) {
>  		const void *kaddr = kasan_shadow_to_mem(shadow_row);
>  		char buffer[4 + (BITS_PER_LONG/8)*2];
> -		char shadow_buf[SHADOW_BYTES_PER_ROW];
> +		char shadow_buf[META_BYTES_PER_ROW];
>  
>  		snprintf(buffer, sizeof(buffer),
>  			(i == 0) ? ">%px: " : " %px: ", kaddr);
> @@ -274,17 +274,17 @@ static void print_memory_metadata(const void *addr)
>  		 * function, because generic functions may try to
>  		 * access kasan mapping for the passed address.
>  		 */
> -		memcpy(shadow_buf, shadow_row, SHADOW_BYTES_PER_ROW);
> +		memcpy(shadow_buf, shadow_row, META_BYTES_PER_ROW);
>  		print_hex_dump(KERN_ERR, buffer,
> -			DUMP_PREFIX_NONE, SHADOW_BYTES_PER_ROW, 1,
> -			shadow_buf, SHADOW_BYTES_PER_ROW, 0);
> +			DUMP_PREFIX_NONE, META_BYTES_PER_ROW, 1,
> +			shadow_buf, META_BYTES_PER_ROW, 0);
>  
>  		if (row_is_guilty(shadow_row, shadow))
>  			pr_err("%*c\n",
>  				shadow_pointer_offset(shadow_row, shadow),
>  				'^');
>  
> -		shadow_row += SHADOW_BYTES_PER_ROW;
> +		shadow_row += META_BYTES_PER_ROW;
>  	}
>  }
>  
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001174851.GO4162920%40elver.google.com.
