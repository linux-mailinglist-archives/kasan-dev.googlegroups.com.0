Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQVP3D5QKGQEGME6UUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 94EA32805F5
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:54:10 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id f2sf562887wml.6
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:54:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601574850; cv=pass;
        d=google.com; s=arc-20160816;
        b=RE4laOBb6QTT13xe60H2EQ0pVsP2GkRmsRMjGqMPN1TKTXT9SDg+A9pdX/IES4Qk4S
         GNNeo0AdABwzPynYSW42AYp9v4pfFZBsgO4Wy6iRloEG0Vq6m+LSzfRsnFH1LkcQIIng
         q7YaG8kNvJEEOilyFkm8QuxXh8UHVfnGg5npu7Kv5qDp4IiMnmeJQSDvgk6YdUzVQA5R
         nUXiujLCuM0WGCreROlXWShFllEr7MMW60BMOcREn8U0gcE5TGUH3ukVwQ0wqUb2pa4O
         uT1N2t9fd2nsCSINrD4Rll6XZR1SDgMTbiaucqVhAf1P8YmEc88KabhjZDEbP7XlNhBM
         V48w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=VQctIeBqwAu9y07xl+pp5fuJ7kInIx9dzqtXXDFFF5k=;
        b=HmFCHPNHFQQ49EOzLjUPL+CK3lp/JhW0BI1c6u0mUwC1mDzZgXFlPlcHJMC0kiFs/A
         nojldIETP1pxTBS1tDoeX7JdBV72LU2UAMZ0debf4X0O0gMn00NKCTvK+9VCfxUoDNUS
         1Yj2sZ1diyjWhdaZgqkPV1D7z0963YbIJEFEAFHo+1fMjirbE5PFYmdNOIEs+t5+sw7B
         XVdsqJg/pbJH6U9lLXKospoGvS3hnXq9I0xnjTjVG22iBfq3Hu9OKqR8O2CsxGfxO6i7
         v7i7VSBGT8JTfqmhjPnoPPs1okWXMU+bwfok/NDza+fzVFrUJlIKbN9u/PjCUhvMpNFo
         F+HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vJCzAYSD;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=VQctIeBqwAu9y07xl+pp5fuJ7kInIx9dzqtXXDFFF5k=;
        b=j2vQolQuUjhWkitSRWt3npgVlT8/mDShZlM1L7YHpeWFk5rf2pJSVRRzizWBbHr0Wb
         5EMIZ33o9CWAlv97Pbq1sYAYimzQgUWc6W9c72Qt+db5mdZA8LihOlEk9vpZGjq40PBL
         iHmX8DbKI+JO6ze0HUAy32W5WuLoW/i+oRIO45G7QqZo+4lKoGxDjw35Tg3Md3jyJv4g
         EA5Vou0NHvoo1EHdIhWXgy0uvnWXmXDnPIgk39xm6hoiewj//Gm/kFOzaYiVVuk11Nac
         Hrw69TLapK2s99JyDf31z8MafuQuNqNl4SzW6SKlvHMlrEVlVlHLEsAF4X3nRQkrSeDJ
         jt6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VQctIeBqwAu9y07xl+pp5fuJ7kInIx9dzqtXXDFFF5k=;
        b=R0dvMQ92IGiruQnCHMqeMkL4loE7JLkY34c9RhRWmGIv725oOW7uNyWWIcq+v3tal5
         idp/7CtoXmnBsq3/nUg7mFG+PxrS9MdWdsNAAELw9c71qsGWJepptIki3t3RS+THMZyp
         IyH1QXpp7E7SvxbJ1jSsMqW0i+HscVSk2EYVijDidoa04ZKVXlYDeDQhKU5BWC6/vEYZ
         FtWS7KIXIrs+ugec5sTLekGcbenhKwlHIYvwyh2A27m0RuqHPOzYybWKXuxDVGA2svRY
         V2eexnW091jmcm6Ex2ADfzzlP50BuQauS+ko9jxJR+qx/SjXlkJNHxCyjmktyVY5bvYP
         4d5w==
X-Gm-Message-State: AOAM532IncbZ7Fj98YsB/wtTuCi6GMiBrbWeUM0IDqv+zl53apbKGEdb
	hONzad96tKT+37rBSYSvr4s=
X-Google-Smtp-Source: ABdhPJwE+hGvP+pEMphnLNRw3Ps6lBXAfAyvDEBeyp/CB8N20yaBW3mpsVL3nJjZtounWL75kuTVAA==
X-Received: by 2002:a1c:20ce:: with SMTP id g197mr1256509wmg.72.1601574850259;
        Thu, 01 Oct 2020 10:54:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:c2c1:: with SMTP id s184ls3291986wmf.2.canary-gmail;
 Thu, 01 Oct 2020 10:54:09 -0700 (PDT)
X-Received: by 2002:a7b:c0c1:: with SMTP id s1mr1248595wmh.73.1601574849250;
        Thu, 01 Oct 2020 10:54:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601574849; cv=none;
        d=google.com; s=arc-20160816;
        b=j234uNmewG9NPmpwdFbUonu9KAjYSYkEHojTArAsN71UDSiEF4VvMxBpidaq2n1qWb
         SKpT01eAwyqkXqWGE0IUFuOKvki+4BSKGBLyL9aI/fR1ZFIfLbMux1Y8xApA7Crl8Td8
         i8GX1in761F3ZoZtM5ioaLnHp/0yEiLCXlZ/ZzXUz2OG9GMXka0VnTQyVsTR8e+ccLMu
         yYUEgodIXEGoiOBQQnEQoVDj19S/Vro2k4aXR4ivBc2vrkHQc2JlawtiRhZnhYiMcVpM
         RlBTS9Q4CAkP5Ij+sVMZeiIO3KuYffSuS/b4BHUlZwE6agvw9jZxyhqKg0ruOVEQFgtX
         0kQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=MD/fcatPT9QjaIWjzyQ070sd24blgVyHZ+oxa+kxMTk=;
        b=u6KC/DpbQbSqnxJy0TfD2V0rjTgLqAbLpuINAdc/DfbwKtEFhsrXqh6+93V5rUPp7R
         tXfZVMTQZylaeLAk5jKZW6pew5BY8RZ5zfSN5DB1g04HYNn699W9vV0ZDAQ9npYCS86a
         u9qcJKPYAQLmPT6w6zzp8EXF/EkXmf8jA3HsgOqcLUkPhZguJD6r+BbsuH78pDQwPQm2
         BJSSN9RqLhxpFCRcK61WrHvCUS5ncdOOY4a891YHMITppamf61iOEYrYx+pMK6ve7Vqt
         AOha1zh9erEIRUGhPuQt+5Y8OPhqkyCzVQMLYojcoeQaGbjrue814bo3pTmhfkZfC99B
         WI6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vJCzAYSD;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id z17si159971wrm.2.2020.10.01.10.54.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:54:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id e2so4086622wme.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:54:09 -0700 (PDT)
X-Received: by 2002:a1c:4b04:: with SMTP id y4mr1143592wma.111.1601574848674;
        Thu, 01 Oct 2020 10:54:08 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id q20sm1008470wmj.5.2020.10.01.10.54.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:54:07 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:54:02 +0200
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
Subject: Re: [PATCH v3 20/39] kasan: separate metadata_fetch_row for each mode
Message-ID: <20201001175402.GP4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <494045645c31b7f9298851118cb0b7f8964ac0f4.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <494045645c31b7f9298851118cb0b7f8964ac0f4.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vJCzAYSD;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
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

Not sure why I've only noticed this now, but all these patches seem to
say "This is a preparatory commit" -- I don't think "commit" is
applicable, and "This .. patch" is discouraged.

Maybe just change it to say "This is to prepare for the upcoming ..."
after the below paragraph?

> Rework print_memory_metadata() to make it agnostic with regard to the
> way metadata is stored. Allow providing a separate metadata_fetch_row()
> implementation for each KASAN mode. Hardware tag-based KASAN will provide
> its own implementation that doesn't use shadow memory.

(i.e. move it here)

> No functional changes for software modes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Other than that,

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I5b0ed1d079ea776e620beca6a529a861e7dced95
> ---
>  mm/kasan/kasan.h          |  8 ++++++
>  mm/kasan/report.c         | 56 +++++++++++++++++++--------------------
>  mm/kasan/report_generic.c |  5 ++++
>  mm/kasan/report_sw_tags.c |  5 ++++
>  4 files changed, 45 insertions(+), 29 deletions(-)
> 
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 0bf669fad345..50b59c8f8be2 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -57,6 +57,13 @@
>  #define KASAN_ABI_VERSION 1
>  #endif
>  
> +/* Metadata layout customization. */
> +#define META_BYTES_PER_BLOCK 1
> +#define META_BLOCKS_PER_ROW 16
> +#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
> +#define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
> +#define META_ROWS_AROUND_ADDR 2
> +
>  struct kasan_access_info {
>  	const void *access_addr;
>  	const void *first_bad_addr;
> @@ -168,6 +175,7 @@ bool check_invalid_free(void *addr);
>  
>  void *find_first_bad_addr(void *addr, size_t size);
>  const char *get_bug_type(struct kasan_access_info *info);
> +void metadata_fetch_row(char *buffer, void *row);
>  
>  #ifdef CONFIG_KASAN_STACK_ENABLE
>  void print_address_stack_frame(const void *addr);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 13b27675a696..3924127b4786 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -31,12 +31,6 @@
>  #include "kasan.h"
>  #include "../slab.h"
>  
> -/* Metadata layout customization. */
> -#define META_BYTES_PER_BLOCK 1
> -#define META_BLOCKS_PER_ROW 16
> -#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
> -#define META_ROWS_AROUND_ADDR 2
> -
>  static unsigned long kasan_flags;
>  
>  #define KASAN_BIT_REPORTED	0
> @@ -236,55 +230,59 @@ static void print_address_description(void *addr, u8 tag)
>  	print_address_stack_frame(addr);
>  }
>  
> -static bool row_is_guilty(const void *row, const void *guilty)
> +static bool meta_row_is_guilty(const void *row, const void *addr)
>  {
> -	return (row <= guilty) && (guilty < row + META_BYTES_PER_ROW);
> +	return (row <= addr) && (addr < row + META_MEM_BYTES_PER_ROW);
>  }
>  
> -static int shadow_pointer_offset(const void *row, const void *shadow)
> +static int meta_pointer_offset(const void *row, const void *addr)
>  {
> -	/* The length of ">ff00ff00ff00ff00: " is
> -	 *    3 + (BITS_PER_LONG/8)*2 chars.
> +	/*
> +	 * Memory state around the buggy address:
> +	 *  ff00ff00ff00ff00: 00 00 00 05 fe fe fe fe fe fe fe fe fe fe fe fe
> +	 *  ...
> +	 *
> +	 * The length of ">ff00ff00ff00ff00: " is
> +	 *    3 + (BITS_PER_LONG / 8) * 2 chars.
> +	 * The length of each granule metadata is 2 bytes
> +	 *    plus 1 byte for space.
>  	 */
> -	return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
> -		(shadow - row) / META_BYTES_PER_BLOCK + 1;
> +	return 3 + (BITS_PER_LONG / 8) * 2 +
> +		(addr - row) / KASAN_GRANULE_SIZE * 3 + 1;
>  }
>  
>  static void print_memory_metadata(const void *addr)
>  {
>  	int i;
> -	const void *shadow = kasan_mem_to_shadow(addr);
> -	const void *shadow_row;
> +	void *row;
>  
> -	shadow_row = (void *)round_down((unsigned long)shadow,
> -					META_BYTES_PER_ROW)
> -		- META_ROWS_AROUND_ADDR * META_BYTES_PER_ROW;
> +	row = (void *)round_down((unsigned long)addr, META_MEM_BYTES_PER_ROW)
> +			- META_ROWS_AROUND_ADDR * META_MEM_BYTES_PER_ROW;
>  
>  	pr_err("Memory state around the buggy address:\n");
>  
>  	for (i = -META_ROWS_AROUND_ADDR; i <= META_ROWS_AROUND_ADDR; i++) {
> -		const void *kaddr = kasan_shadow_to_mem(shadow_row);
> -		char buffer[4 + (BITS_PER_LONG/8)*2];
> -		char shadow_buf[META_BYTES_PER_ROW];
> +		char buffer[4 + (BITS_PER_LONG / 8) * 2];
> +		char metadata[META_BYTES_PER_ROW];
>  
>  		snprintf(buffer, sizeof(buffer),
> -			(i == 0) ? ">%px: " : " %px: ", kaddr);
> +				(i == 0) ? ">%px: " : " %px: ", row);
> +
>  		/*
>  		 * We should not pass a shadow pointer to generic
>  		 * function, because generic functions may try to
>  		 * access kasan mapping for the passed address.
>  		 */
> -		memcpy(shadow_buf, shadow_row, META_BYTES_PER_ROW);
> +		metadata_fetch_row(&metadata[0], row);
> +
>  		print_hex_dump(KERN_ERR, buffer,
>  			DUMP_PREFIX_NONE, META_BYTES_PER_ROW, 1,
> -			shadow_buf, META_BYTES_PER_ROW, 0);
> +			metadata, META_BYTES_PER_ROW, 0);
>  
> -		if (row_is_guilty(shadow_row, shadow))
> -			pr_err("%*c\n",
> -				shadow_pointer_offset(shadow_row, shadow),
> -				'^');
> +		if (meta_row_is_guilty(row, addr))
> +			pr_err("%*c\n", meta_pointer_offset(row, addr), '^');
>  
> -		shadow_row += META_BYTES_PER_ROW;
> +		row += META_MEM_BYTES_PER_ROW;
>  	}
>  }
>  
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index ff067071cd28..de7a85c83106 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -122,6 +122,11 @@ const char *get_bug_type(struct kasan_access_info *info)
>  	return get_wild_bug_type(info);
>  }
>  
> +void metadata_fetch_row(char *buffer, void *row)
> +{
> +	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
> +}
> +
>  #ifdef CONFIG_KASAN_STACK_ENABLE
>  static bool __must_check tokenize_frame_descr(const char **frame_descr,
>  					      char *token, size_t max_tok_len,
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index c87d5a343b4e..add2dfe6169c 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -80,6 +80,11 @@ void *find_first_bad_addr(void *addr, size_t size)
>  	return p;
>  }
>  
> +void metadata_fetch_row(char *buffer, void *row)
> +{
> +	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
> +}
> +
>  void print_tags(u8 addr_tag, const void *addr)
>  {
>  	u8 *shadow = (u8 *)kasan_mem_to_shadow(addr);
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001175402.GP4162920%40elver.google.com.
