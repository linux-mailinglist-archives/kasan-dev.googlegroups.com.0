Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2FK3D5QKGQE6FI2H4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id B35912805B2
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:44:08 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id s22sf1350255ljp.15
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:44:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601574248; cv=pass;
        d=google.com; s=arc-20160816;
        b=AHONjG7IOhvZATzq/Y+RHoTbhXrZjBYwPlqqpaPuztmpDqU3Qp51iTGHVbUOCo74p3
         LdzVWBAata/whXdlbaXc9SqMnCozlkLWRySJnAsfvFJkGlBKRCkO03iu7XCYIcKyfZOX
         sdROg11UG3PukFk5M++Jeu6Q3RqbIWZweQJlYbSJiUXIawAcHB5u+2djbABnFQy52FfH
         x6bNgAkixgSPsUv7tOkgdeduDm2OvQBoe6NdeY6NoFg/GfsXwKTvSNKPGQOTiZ/Rgly8
         9tZa7ko2SCz1+VtgbYW/dO5bljQ5Y2d2IgfEAwnxCxnDSW5mxpd2a1f0EFOM5sh9pWqw
         r4Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=T5J1tppdFZwFie1KCVzPAD6BOT6K8CKujC6JWpCMAMA=;
        b=EbJZo4yQ+z5x9kCp4a2IhtsP6K56rZ8NI0hDZ6q6KPChHBQqeNed/fQ8rng9MdQj77
         JampAMWmv/90PobrQ8qu/7qbhGOhv1DBJvbETKnXT7KClNYY2YKL2UjN6xYrR2jA+GIv
         QmdeNpp+2B/eP05+F8uq2WqA0D1BM2fdSojCidaFDzGfLitSY572a6yXVvcPMzTWzsqu
         0dv6e8JcRez0nQ6PMr1oh5uGnD8/nXUgZkgBmWPNgpyDkmEnMhdiVbSTPEWmcFOZYU+j
         Swwydr6rziWM9CE2pP+y40yiE+dw74ZDInDrkekqBlZ3dQlId+5gcNNnW7bkOcpK+wH9
         u/OA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z+hew0WZ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=T5J1tppdFZwFie1KCVzPAD6BOT6K8CKujC6JWpCMAMA=;
        b=k/hC8LidpqmR23uCW5TkzLrbpR6gmb7yWAVqILjyUym8/IdTVX1UorQgAs3jTxblAw
         DhR3BD5AS1uyg+/6PzN7dISv7IDgzIEG0O+9pWmPs9+Ho0no+RZKU81SngYLWPbhHtVx
         /W9IEWnos/sqTAMJ3SF2AhEsvfa/rzU3qjP0reK8Q/E7Ffxtdw5R9xWfKdo8xSYrvCCI
         EibLluokDyofLypnb1GZ8pCIZlrpx9/AEGnknxzWAfOm/7cMNMUJiXJvAgecgQ++s3J8
         LWUxPFV5D8YLmNzHS6BAK3LoIVyIxHA150ZiE9+P/TWDgEW6j5uWaOlVcAk2tIADMNrA
         Rsjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=T5J1tppdFZwFie1KCVzPAD6BOT6K8CKujC6JWpCMAMA=;
        b=ZaNKwSG2vr51dz4L04uAv7Roz/c/kmJHczAyG67e3C4cH3iGEST7UY7ZaH6gbSTJ4O
         sMu0+d5QT8wOn2OWI3is6waZ76xKAQPyV2tGpGS/nquFnQU3ubGXe+onGuSKtmCwEj9S
         uZakbKLD43LuBGsckzGhiiAIS0yMhCgpn2mBI0WIqa79uzobAz3aTKIls2+xx8clrnzY
         BKg/MR6jln+KbmotDcD4LtlkF8f6NQ2qphATXm5lPI8/i3TdJ5Z+ldf6maR6eYlDx0VQ
         wRsCJf+HJ8Yt/kfsSsWjUldHGvt6cvexgxCpeerrFPhwpvBYKqvjdw4TCtIu4is0Q8E/
         FGkQ==
X-Gm-Message-State: AOAM530f/yQGdIWdAm2tRL3xc+k7Dg4jvLKvwfZ3uiVESv23yOD0yjTD
	UuyJGMT1siKD7JCQcduekrg=
X-Google-Smtp-Source: ABdhPJxLwZdC/frJFMVs52md7mEp8eQuY9wU7AEtCVP6aPPsP0W0LUx17HoARd4DAh8qwZ/SnI0SeA==
X-Received: by 2002:a2e:8e81:: with SMTP id z1mr2868220ljk.379.1601574248214;
        Thu, 01 Oct 2020 10:44:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls1708113lff.0.gmail; Thu, 01
 Oct 2020 10:44:07 -0700 (PDT)
X-Received: by 2002:ac2:48a2:: with SMTP id u2mr3347788lfg.391.1601574247040;
        Thu, 01 Oct 2020 10:44:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601574247; cv=none;
        d=google.com; s=arc-20160816;
        b=qz36iWmSEVbLMGgJTJsBfkV1H/BbQ0QOc+CXP3YNBMD0E4f/gb7R4L7MNOQFCLaEKw
         SWT1Ltri54JED6grWRuJRjeMNVnfqiS3+23O8dLxXeYPqiTXrpzqjXLVDklSE3D+Autn
         U9PpNWl9dpM68WSW/jXrbtCXaGKxp9w/Uc8NYhaSWA3+CMZWBZLA+OdoTbVxG2f2KNtn
         IR3cm+8URKkd3YsdaKFHKWwESSAoeTI/YF2fMakZxaSU2ia+e4TuWThQ/5zoE4OnmU9j
         BHQQAMnOfTp1Htd9j/ttHDMOPcs3A0DKYWBfvJsq7s4HlTbiqW436ZkJH3CKhP9Lqy3j
         NOlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4KTP5PPBXPQCQ9o0Du3pwA+7Doqcit+qoPcV04ur9Bc=;
        b=LIQETSUVFlVjxP1MHKMJ2P6ZafvWZhD9jDzOldVi5uVxGZBCbgBcyIQul0PQB50kty
         VDbomqS1ERMAYK54lM8wtmGpuzPWzvhiDi0q2I8hmGR1JwsTuIrY3iG6vsXmicxQMFF/
         /VGjDIAm9bz1z99aXcERxIAgktHh3XLOTo+8KvJieiFpt93atYN8ENt7l/q9P0gnFev1
         vgtaEVnL7/1tl2R8SQCSi1xYs7nCmqwRUjFYBXoF8ano1JCfbGZkf5DCaygyvO7PGIiS
         h14Ek+WwU1LJK2/hMZt11tP2vGFWdfzoZ3BOsv+q21/RUnP7m4H5aYYJuvTv2ggOqkJc
         gPFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z+hew0WZ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id q20si135029lji.2.2020.10.01.10.44.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:44:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id j136so2745462wmj.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:44:07 -0700 (PDT)
X-Received: by 2002:a1c:7d4d:: with SMTP id y74mr1141258wmc.73.1601574246171;
        Thu, 01 Oct 2020 10:44:06 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id e13sm10909107wre.60.2020.10.01.10.44.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:44:05 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:43:59 +0200
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
Subject: Re: [PATCH v3 13/39] kasan: decode stack frame only with
 KASAN_STACK_ENABLE
Message-ID: <20201001174359.GK4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <4f2a790cc95d2ab6400e5f75fa78ff0a0fdd9593.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4f2a790cc95d2ab6400e5f75fa78ff0a0fdd9593.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Z+hew0WZ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as
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
> Decoding routines aren't needed when CONFIG_KASAN_STACK_ENABLE is not
> enabled. Currently only generic KASAN mode implements stack error
> reporting.
> 
> No functional changes for software modes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I084e3214f2b40dc0bef7c5a9fafdc6f5c42b06a2
> ---
>  mm/kasan/kasan.h          |   6 ++
>  mm/kasan/report.c         | 162 --------------------------------------
>  mm/kasan/report_generic.c | 161 +++++++++++++++++++++++++++++++++++++
>  3 files changed, 167 insertions(+), 162 deletions(-)
> 
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3eff57e71ff5..8dfacc0f73ea 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -169,6 +169,12 @@ bool check_invalid_free(void *addr);
>  void *find_first_bad_addr(void *addr, size_t size);
>  const char *get_bug_type(struct kasan_access_info *info);
>  
> +#ifdef CONFIG_KASAN_STACK_ENABLE
> +void print_address_stack_frame(const void *addr);
> +#else
> +static inline void print_address_stack_frame(const void *addr) { }
> +#endif
> +
>  bool kasan_report(unsigned long addr, size_t size,
>  		bool is_write, unsigned long ip);
>  void kasan_report_invalid_free(void *object, unsigned long ip);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 5961dbfba080..f28eec5acdf6 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -209,168 +209,6 @@ static inline bool init_task_stack_addr(const void *addr)
>  			sizeof(init_thread_union.stack));
>  }
>  
> -static bool __must_check tokenize_frame_descr(const char **frame_descr,
> -					      char *token, size_t max_tok_len,
> -					      unsigned long *value)
> -{
> -	const char *sep = strchr(*frame_descr, ' ');
> -
> -	if (sep == NULL)
> -		sep = *frame_descr + strlen(*frame_descr);
> -
> -	if (token != NULL) {
> -		const size_t tok_len = sep - *frame_descr;
> -
> -		if (tok_len + 1 > max_tok_len) {
> -			pr_err("KASAN internal error: frame description too long: %s\n",
> -			       *frame_descr);
> -			return false;
> -		}
> -
> -		/* Copy token (+ 1 byte for '\0'). */
> -		strlcpy(token, *frame_descr, tok_len + 1);
> -	}
> -
> -	/* Advance frame_descr past separator. */
> -	*frame_descr = sep + 1;
> -
> -	if (value != NULL && kstrtoul(token, 10, value)) {
> -		pr_err("KASAN internal error: not a valid number: %s\n", token);
> -		return false;
> -	}
> -
> -	return true;
> -}
> -
> -static void print_decoded_frame_descr(const char *frame_descr)
> -{
> -	/*
> -	 * We need to parse the following string:
> -	 *    "n alloc_1 alloc_2 ... alloc_n"
> -	 * where alloc_i looks like
> -	 *    "offset size len name"
> -	 * or "offset size len name:line".
> -	 */
> -
> -	char token[64];
> -	unsigned long num_objects;
> -
> -	if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> -				  &num_objects))
> -		return;
> -
> -	pr_err("\n");
> -	pr_err("this frame has %lu %s:\n", num_objects,
> -	       num_objects == 1 ? "object" : "objects");
> -
> -	while (num_objects--) {
> -		unsigned long offset;
> -		unsigned long size;
> -
> -		/* access offset */
> -		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> -					  &offset))
> -			return;
> -		/* access size */
> -		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> -					  &size))
> -			return;
> -		/* name length (unused) */
> -		if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
> -			return;
> -		/* object name */
> -		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> -					  NULL))
> -			return;
> -
> -		/* Strip line number; without filename it's not very helpful. */
> -		strreplace(token, ':', '\0');
> -
> -		/* Finally, print object information. */
> -		pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
> -	}
> -}
> -
> -static bool __must_check get_address_stack_frame_info(const void *addr,
> -						      unsigned long *offset,
> -						      const char **frame_descr,
> -						      const void **frame_pc)
> -{
> -	unsigned long aligned_addr;
> -	unsigned long mem_ptr;
> -	const u8 *shadow_bottom;
> -	const u8 *shadow_ptr;
> -	const unsigned long *frame;
> -
> -	BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
> -
> -	/*
> -	 * NOTE: We currently only support printing frame information for
> -	 * accesses to the task's own stack.
> -	 */
> -	if (!object_is_on_stack(addr))
> -		return false;
> -
> -	aligned_addr = round_down((unsigned long)addr, sizeof(long));
> -	mem_ptr = round_down(aligned_addr, KASAN_GRANULE_SIZE);
> -	shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
> -	shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
> -
> -	while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
> -		shadow_ptr--;
> -		mem_ptr -= KASAN_GRANULE_SIZE;
> -	}
> -
> -	while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
> -		shadow_ptr--;
> -		mem_ptr -= KASAN_GRANULE_SIZE;
> -	}
> -
> -	if (shadow_ptr < shadow_bottom)
> -		return false;
> -
> -	frame = (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
> -	if (frame[0] != KASAN_CURRENT_STACK_FRAME_MAGIC) {
> -		pr_err("KASAN internal error: frame info validation failed; invalid marker: %lu\n",
> -		       frame[0]);
> -		return false;
> -	}
> -
> -	*offset = (unsigned long)addr - (unsigned long)frame;
> -	*frame_descr = (const char *)frame[1];
> -	*frame_pc = (void *)frame[2];
> -
> -	return true;
> -}
> -
> -static void print_address_stack_frame(const void *addr)
> -{
> -	unsigned long offset;
> -	const char *frame_descr;
> -	const void *frame_pc;
> -
> -	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> -		return;
> -
> -	if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
> -					  &frame_pc))
> -		return;
> -
> -	/*
> -	 * get_address_stack_frame_info only returns true if the given addr is
> -	 * on the current task's stack.
> -	 */
> -	pr_err("\n");
> -	pr_err("addr %px is located in stack of task %s/%d at offset %lu in frame:\n",
> -	       addr, current->comm, task_pid_nr(current), offset);
> -	pr_err(" %pS\n", frame_pc);
> -
> -	if (!frame_descr)
> -		return;
> -
> -	print_decoded_frame_descr(frame_descr);
> -}
> -
>  static void print_address_description(void *addr, u8 tag)
>  {
>  	struct page *page = kasan_addr_to_page(addr);
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 7d5b9e5c7cfe..42b2b5791733 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -122,6 +122,167 @@ const char *get_bug_type(struct kasan_access_info *info)
>  	return get_wild_bug_type(info);
>  }
>  
> +#ifdef CONFIG_KASAN_STACK_ENABLE
> +static bool __must_check tokenize_frame_descr(const char **frame_descr,
> +					      char *token, size_t max_tok_len,
> +					      unsigned long *value)
> +{
> +	const char *sep = strchr(*frame_descr, ' ');
> +
> +	if (sep == NULL)
> +		sep = *frame_descr + strlen(*frame_descr);
> +
> +	if (token != NULL) {
> +		const size_t tok_len = sep - *frame_descr;
> +
> +		if (tok_len + 1 > max_tok_len) {
> +			pr_err("KASAN internal error: frame description too long: %s\n",
> +			       *frame_descr);
> +			return false;
> +		}
> +
> +		/* Copy token (+ 1 byte for '\0'). */
> +		strlcpy(token, *frame_descr, tok_len + 1);
> +	}
> +
> +	/* Advance frame_descr past separator. */
> +	*frame_descr = sep + 1;
> +
> +	if (value != NULL && kstrtoul(token, 10, value)) {
> +		pr_err("KASAN internal error: not a valid number: %s\n", token);
> +		return false;
> +	}
> +
> +	return true;
> +}
> +
> +static void print_decoded_frame_descr(const char *frame_descr)
> +{
> +	/*
> +	 * We need to parse the following string:
> +	 *    "n alloc_1 alloc_2 ... alloc_n"
> +	 * where alloc_i looks like
> +	 *    "offset size len name"
> +	 * or "offset size len name:line".
> +	 */
> +
> +	char token[64];
> +	unsigned long num_objects;
> +
> +	if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> +				  &num_objects))
> +		return;
> +
> +	pr_err("\n");
> +	pr_err("this frame has %lu %s:\n", num_objects,
> +	       num_objects == 1 ? "object" : "objects");
> +
> +	while (num_objects--) {
> +		unsigned long offset;
> +		unsigned long size;
> +
> +		/* access offset */
> +		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> +					  &offset))
> +			return;
> +		/* access size */
> +		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> +					  &size))
> +			return;
> +		/* name length (unused) */
> +		if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
> +			return;
> +		/* object name */
> +		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> +					  NULL))
> +			return;
> +
> +		/* Strip line number; without filename it's not very helpful. */
> +		strreplace(token, ':', '\0');
> +
> +		/* Finally, print object information. */
> +		pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
> +	}
> +}
> +
> +static bool __must_check get_address_stack_frame_info(const void *addr,
> +						      unsigned long *offset,
> +						      const char **frame_descr,
> +						      const void **frame_pc)
> +{
> +	unsigned long aligned_addr;
> +	unsigned long mem_ptr;
> +	const u8 *shadow_bottom;
> +	const u8 *shadow_ptr;
> +	const unsigned long *frame;
> +
> +	BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
> +
> +	/*
> +	 * NOTE: We currently only support printing frame information for
> +	 * accesses to the task's own stack.
> +	 */
> +	if (!object_is_on_stack(addr))
> +		return false;
> +
> +	aligned_addr = round_down((unsigned long)addr, sizeof(long));
> +	mem_ptr = round_down(aligned_addr, KASAN_GRANULE_SIZE);
> +	shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
> +	shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
> +
> +	while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
> +		shadow_ptr--;
> +		mem_ptr -= KASAN_GRANULE_SIZE;
> +	}
> +
> +	while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
> +		shadow_ptr--;
> +		mem_ptr -= KASAN_GRANULE_SIZE;
> +	}
> +
> +	if (shadow_ptr < shadow_bottom)
> +		return false;
> +
> +	frame = (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
> +	if (frame[0] != KASAN_CURRENT_STACK_FRAME_MAGIC) {
> +		pr_err("KASAN internal error: frame info validation failed; invalid marker: %lu\n",
> +		       frame[0]);
> +		return false;
> +	}
> +
> +	*offset = (unsigned long)addr - (unsigned long)frame;
> +	*frame_descr = (const char *)frame[1];
> +	*frame_pc = (void *)frame[2];
> +
> +	return true;
> +}
> +
> +void print_address_stack_frame(const void *addr)
> +{
> +	unsigned long offset;
> +	const char *frame_descr;
> +	const void *frame_pc;
> +
> +	if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
> +					  &frame_pc))
> +		return;
> +
> +	/*
> +	 * get_address_stack_frame_info only returns true if the given addr is
> +	 * on the current task's stack.
> +	 */
> +	pr_err("\n");
> +	pr_err("addr %px is located in stack of task %s/%d at offset %lu in frame:\n",
> +	       addr, current->comm, task_pid_nr(current), offset);
> +	pr_err(" %pS\n", frame_pc);
> +
> +	if (!frame_descr)
> +		return;
> +
> +	print_decoded_frame_descr(frame_descr);
> +}
> +#endif /* CONFIG_KASAN_STACK_ENABLE */
> +
>  #define DEFINE_ASAN_REPORT_LOAD(size)                     \
>  void __asan_report_load##size##_noabort(unsigned long addr) \
>  {                                                         \
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001174359.GK4162920%40elver.google.com.
