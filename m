Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBB5BR6PQMGQEJZGQPKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C753E68F376
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 17:40:40 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id k25-20020a2e2419000000b00291830c756esf4816909ljk.19
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 08:40:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675874440; cv=pass;
        d=google.com; s=arc-20160816;
        b=aXPvgO9FDglmNcZNDQjrlKvrG76r9KhrkAYCIw7z7PLZXzBPmJlXjgdU88VsXcgQoS
         fDFTH8jpQ8/0GGfhOeLA+8G9pGCuwFNcVz+83zHTUxoVC2T9/+ATmtMcjZS9DwIZi0uf
         wu/3C5tt3rHJi7LhjvXEYDwOTEr5QQG6Ofq7IwHLDHRfXbYLv9pwKAxQs9nXAyCTKMBB
         wrLf+vB4GOoJE/BcpiZo1mWptsbBKz64eKuOKKgBI040zBhZEli/TDlUSvaOzGpy6fac
         rf8N+mMcNOpCilaBVIPElgSX7e8s0ys7nZEICHnbXUFGAAvAdOFdyLdP6+hp5gEdSU8Z
         ec5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=ieAOSF8VR7dgehsOugd+TdNbmgnC0y40L8vU+1Wz3U4=;
        b=DPc1UjBy8IKap003PbyucC/klPnpY0wnXU+Cks2xQK/6wxeNtiEiuZFphivfNwr9ab
         xB/HQpdNr9EpO/3yzjuL5Ja4pTo5rawZKEzcj9kYAUfYvEgkeLCR0i/nF4t5ST1vRUfS
         BFG6qlng1LOROYjgsLHW4tsbuYf9UBxrhqrPFF4RL921aWm6grHJE9tSHOqfGsuVy6nc
         btNSt22nf2zXEKp53mFxLF1WJ/TFX/PeDBxFJiRgykKf7s1KB3c4CZFWBy0S2stXR8DE
         LuiyUp6j583TR9nfoDcdiH6rV5/KH0FB/1A404f7tkXTefiG3SNWW6cyR5KWd92AA4q+
         jncw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=vfT1tSdJ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ieAOSF8VR7dgehsOugd+TdNbmgnC0y40L8vU+1Wz3U4=;
        b=F6OfiHD6tfUECyto5xLQGMWNc8vYr+1doBPAAA2p2pW7tmaRkB96meEBpMdeGfbU+p
         zM/k5LAyUGyUB3XsdoI0COTFQOX2ZqqA9cFvQZ2ASmL3NoDyCEA5obK23+2q6Dfoof1I
         xTucDEuV1gEG3vbbhOOmTd71PYc6aI7Nmf+uSgBZS3Y+NqE1arY9DiYk5k/+QOtBqQlf
         6lu3C3kLbjWdJ2g+BJuUOQxI8YMZrgmwY/CA+x3cehwtWfySKIAbNyYBa9wGe9h7jXLh
         9sbIDUOlMnTDvtBmzQkYxwjObAp6mlQHDDuX8DwrMT8w+HlF+KA2AwBSuBGpj8133GXi
         Colg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ieAOSF8VR7dgehsOugd+TdNbmgnC0y40L8vU+1Wz3U4=;
        b=1NILq2WkvCOglqJLwqYyV8VB8+FAbvP/7/XrEJ/QCTTP0oIeM6FhTKuneojvD3wAA9
         9ZtOT/3fp7qQleefUofrwfJBAsQTbX81jTnNArI+a3Jdx/AdyGke/2GczbC+c9CR95Ub
         LJgiD06iSK6c9NrSb5hIiTxifTdKkWAHv+X2lAnvAycEOMb9t4QBtTqh7YU/Z0bCU53O
         OCCOh6htsPH6FDCtwugR90GcWgWvtlkmtXAUrl8fk4ubVCE93z4Sm2cewiTbWMTVX8O1
         izKhLd5/jFRoJf9ZuGDpnRvddsMHIP6EqAcNQcVIrP/gQCigLEIzd3/keND/yibG+r/O
         Tz8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUNZM/1T8Iw8/cO1NmHZTaehiNZFT7bS++AEYrehjp+HjM2kyJ2
	BH0WKfIm3C4n6zuTYYTOK0c=
X-Google-Smtp-Source: AK7set+G+VCc9PX3tuZwHaxdrlMwx7GFu0m9D9V6QK3MEwil62CvxOWH1nTKnUv32tQf/BkFuRHivg==
X-Received: by 2002:ac2:5fb1:0:b0:4db:a5:31b9 with SMTP id s17-20020ac25fb1000000b004db00a531b9mr1399693lfe.139.1675874439801;
        Wed, 08 Feb 2023 08:40:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d1f:b0:4d1:8575:2d31 with SMTP id
 d31-20020a0565123d1f00b004d185752d31ls3135725lfv.0.-pod-prod-gmail; Wed, 08
 Feb 2023 08:40:38 -0800 (PST)
X-Received: by 2002:ac2:54a6:0:b0:4cc:597b:583e with SMTP id w6-20020ac254a6000000b004cc597b583emr2393862lfk.55.1675874438026;
        Wed, 08 Feb 2023 08:40:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675874438; cv=none;
        d=google.com; s=arc-20160816;
        b=uaHviL44VIyIDwgTfnSac0cRPHT4wt4rIkmKqiUpigWKiKMVo1b43dCrGuNlFEBQx1
         MaW9I0c0h5/75iypoCTnoWlbwIhV6nvFyT4q+j/OQm35fLshxpuhnO4ozD1nmVc4SK+E
         03olzYdRERWrCxgFrDmb8Gj4oWM9GEnD7QyfA/Cy1TH4B1E9UvNv7+ot+WQESqPOL3wP
         +kPd7Ky7lpKtDEK/dQLQq1wEQl6o2+UMBjOYmmZqAh6naKpH/u4iFAD45nxl8KjOpJDu
         OnQ6xUXHePw8H+AEKZqe/sTT8QLAg08oGvGHMpQcN/zNYBb6mpHXEBRpilAnP79GRp55
         mm7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=F1KlVZ9F3aIxHpgD6Jwxy+qwJV6X/hM6MXtY37o4YVE=;
        b=jTpTdXGKzg/A7zNVnYuVtGPbe5/8i6FN6FYvVsTfoYWw/PjsYjzaZ8KYAIBtTQbGjn
         S+/HH0WzjSHzVD8m+23U9fd/zF6lvLyhFikfzmLa6Kx5PiIipuD2losDwzBQxKUhg4QR
         K/oGo6d64jgAqwTK4AcU2tyOk447YCm0LU/KFPRL8suT7wwZCcJsz132E1n7NM2fQl9c
         h3rIDXxYbKoa29Yaho8FhhshL8PTHUxylQFYncGKiQf6eYtLv5nJORf35xcgC9ZBmvYG
         hgQdPvNNPpJhQJ8rZpcGl4zWPLx3ZvVYUyypx8iBmlvaMUN/WpdOGsKI2+DCJUp6yPBP
         vPwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=vfT1tSdJ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id c19-20020a056512075300b004ce3ceb0e80si975833lfs.5.2023.02.08.08.40.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Feb 2023 08:40:37 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 42E3334280;
	Wed,  8 Feb 2023 16:40:37 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 1D6211358A;
	Wed,  8 Feb 2023 16:40:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id Jc2CBoXQ42OvXwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 08 Feb 2023 16:40:37 +0000
Message-ID: <e5a264d8-0e5a-176d-13d4-7d411a0d169f@suse.cz>
Date: Wed, 8 Feb 2023 17:40:36 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.7.1
Subject: Re: [PATCH 04/18] lib/stackdepot, mm: rename
 stack_depot_want_early_init
Content-Language: en-US
To: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
 Evgenii Stepanov <eugenis@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
 <cb34925852c81be2ec6aac75766292e4e590523e.1675111415.git.andreyknvl@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <cb34925852c81be2ec6aac75766292e4e590523e.1675111415.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=vfT1tSdJ;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/30/23 21:49, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Rename stack_depot_want_early_init to stack_depot_request_early_init.
> 
> The old name is confusing, as it hints at returning some kind of intention
> of stack depot. The new name reflects that this function requests an action
> from stack depot instead.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  include/linux/stackdepot.h | 14 +++++++-------
>  lib/stackdepot.c           | 10 +++++-----
>  mm/page_owner.c            |  2 +-
>  mm/slub.c                  |  4 ++--
>  4 files changed, 15 insertions(+), 15 deletions(-)
> 
> diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
> index 1296a6eeaec0..c4e3abc16b16 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -31,26 +31,26 @@ typedef u32 depot_stack_handle_t;
>   * enabled as part of mm_init(), for subsystems where it's known at compile time
>   * that stack depot will be used.
>   *
> - * Another alternative is to call stack_depot_want_early_init(), when the
> + * Another alternative is to call stack_depot_request_early_init(), when the
>   * decision to use stack depot is taken e.g. when evaluating kernel boot
>   * parameters, which precedes the enablement point in mm_init().
>   *
> - * stack_depot_init() and stack_depot_want_early_init() can be called regardless
> - * of CONFIG_STACKDEPOT and are no-op when disabled. The actual save/fetch/print
> - * functions should only be called from code that makes sure CONFIG_STACKDEPOT
> - * is enabled.
> + * stack_depot_init() and stack_depot_request_early_init() can be called
> + * regardless of CONFIG_STACKDEPOT and are no-op when disabled. The actual
> + * save/fetch/print functions should only be called from code that makes sure
> + * CONFIG_STACKDEPOT is enabled.
>   */
>  #ifdef CONFIG_STACKDEPOT
>  int stack_depot_init(void);
>  
> -void __init stack_depot_want_early_init(void);
> +void __init stack_depot_request_early_init(void);
>  
>  /* This is supposed to be called only from mm_init() */
>  int __init stack_depot_early_init(void);
>  #else
>  static inline int stack_depot_init(void) { return 0; }
>  
> -static inline void stack_depot_want_early_init(void) { }
> +static inline void stack_depot_request_early_init(void) { }
>  
>  static inline int stack_depot_early_init(void)	{ return 0; }
>  #endif
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 90c4dd48d75e..8743fad1485f 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -71,7 +71,7 @@ struct stack_record {
>  	unsigned long entries[];	/* Variable-sized array of entries. */
>  };
>  
> -static bool __stack_depot_want_early_init __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
> +static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
>  static bool __stack_depot_early_init_passed __initdata;
>  
>  static void *stack_slabs[STACK_ALLOC_MAX_SLABS];
> @@ -107,12 +107,12 @@ static int __init is_stack_depot_disabled(char *str)
>  }
>  early_param("stack_depot_disable", is_stack_depot_disabled);
>  
> -void __init stack_depot_want_early_init(void)
> +void __init stack_depot_request_early_init(void)
>  {
> -	/* Too late to request early init now */
> +	/* Too late to request early init now. */
>  	WARN_ON(__stack_depot_early_init_passed);
>  
> -	__stack_depot_want_early_init = true;
> +	__stack_depot_early_init_requested = true;
>  }
>  
>  int __init stack_depot_early_init(void)
> @@ -128,7 +128,7 @@ int __init stack_depot_early_init(void)
>  	if (kasan_enabled() && !stack_hash_order)
>  		stack_hash_order = STACK_HASH_ORDER_MAX;
>  
> -	if (!__stack_depot_want_early_init || stack_depot_disable)
> +	if (!__stack_depot_early_init_requested || stack_depot_disable)
>  		return 0;
>  
>  	if (stack_hash_order)
> diff --git a/mm/page_owner.c b/mm/page_owner.c
> index 2d27f532df4c..90a4a087e6c7 100644
> --- a/mm/page_owner.c
> +++ b/mm/page_owner.c
> @@ -48,7 +48,7 @@ static int __init early_page_owner_param(char *buf)
>  	int ret = kstrtobool(buf, &page_owner_enabled);
>  
>  	if (page_owner_enabled)
> -		stack_depot_want_early_init();
> +		stack_depot_request_early_init();
>  
>  	return ret;
>  }
> diff --git a/mm/slub.c b/mm/slub.c
> index 13459c69095a..f2c6c356bc36 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1592,7 +1592,7 @@ static int __init setup_slub_debug(char *str)
>  		} else {
>  			slab_list_specified = true;
>  			if (flags & SLAB_STORE_USER)
> -				stack_depot_want_early_init();
> +				stack_depot_request_early_init();
>  		}
>  	}
>  
> @@ -1611,7 +1611,7 @@ static int __init setup_slub_debug(char *str)
>  out:
>  	slub_debug = global_flags;
>  	if (slub_debug & SLAB_STORE_USER)
> -		stack_depot_want_early_init();
> +		stack_depot_request_early_init();
>  	if (slub_debug != 0 || slub_debug_string)
>  		static_branch_enable(&slub_debug_enabled);
>  	else

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e5a264d8-0e5a-176d-13d4-7d411a0d169f%40suse.cz.
