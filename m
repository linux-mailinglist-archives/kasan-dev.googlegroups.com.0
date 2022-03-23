Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBEES5SIQMGQENINDDAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C8AE4E5193
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 12:48:33 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id q5-20020a2e9145000000b002497bf0eaa1sf483557ljg.5
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 04:48:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648036112; cv=pass;
        d=google.com; s=arc-20160816;
        b=lU5b8ohVH1y2ECAtdOugbnFrxIOFcpa8oYfrv4uePwNLjjzZhtyGDChDTaslINrW5K
         +R2C4OqzbIKpDCeFpvJ5bREXrZLlefZ57i9JZzA87/G3VjkchHjvGIRkYL5Jjii/CqDE
         PbmzzFneBP6s3kASr7trb+Yyu/4XxbOD+5Cb/5kn3LdL5z5JYrFnkI5TqUfBSNZF50lz
         iuyvhlv7MDx3+ANXQ5wNyEgyyVLeylINJ/SvpnhWThYtgc/MKJWMoGQbwdI5ficOohXW
         iN0XUyjsSjQFsWnWcpxqFynDxFaFFZhpfcumxiGCZi1BFNZDoDo4fZsmesSY1uTToZKt
         N8cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=2h2figklWFhBVfeiWkVUzH9Ju2u4rIXVyJfcGi9odMM=;
        b=aOkthgP5wA0T6Qf/YK7LHVsa/GB6I9yFqZVoy7iyVzS2mKPKkxc0BVMCgl2Xqzw9z2
         scEwM50KzEqbYtYkIndtPI3YQS46rua/adpE6ROAeuJyaQd8Hew9n33uYyNQ8jBqYfBb
         +JWA2HJH+tor1brVRcPLv5vIghivegpIp+gOUCq4IufpUoirjGWlFR7RKYIwWDUS+75E
         BeJvxHmcYbm0Q3MPFjobl5+gXVIt0LIvqGZggAKJcX8EncqVWJycbDPkcCm089ocL118
         6ABTpHEWbN145XPSv5STaemwMpv4nxeyBJV+ljUu7qwPzTGi7GUghtM24H/JzknjozgF
         nFrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=due7XOdw;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=DNkYmWTO;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2h2figklWFhBVfeiWkVUzH9Ju2u4rIXVyJfcGi9odMM=;
        b=Xb19QfGzrvvtjPiWqGvmNNScJ2Y04JI4+8N5Mqb/s0deYzkraTZhyICQXfVlj6U8rc
         yAnvp2hYOeOlGfm5Xl8a9oi9NcvfEV92dvPYMZhFWGFaoZvPLj3XrbcffrT9hkjbMHxZ
         xBnjylLrkGD2A47Tv4gLPVm8q5ppaWbwkyGfXOem5CBAmlcweJwoKnmcdfcjRqInwMMO
         re0YodsthD4PBfZW+RAlDAenn5HRb+tNEuRvTgLJBEsPGjS5Kgt/DE1kMVtw5PJ41wJc
         XlEbTVuAOvcTdZwMnlbHA52eGod7/VkEzpxY3AxPtj99L7F3knt/fE6Hj1t5rw0Rt2lR
         4z3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2h2figklWFhBVfeiWkVUzH9Ju2u4rIXVyJfcGi9odMM=;
        b=hYnPhyF7fodDT8hU/jAV6xNVMggTz6nYdJpvfkumw35HP7W5Rkeg4+GBkjs+J1TjmE
         VZxef09d4kyOyev5E4Fe8LSCs0ngyiAY66u/RxkvhF3RJzsnzF4RYeFDYDvE2QcXnQlx
         1QE/NHMrXNmNzsdD636BlJUjpZYHC7zNeL+rLldXTrkmuEjRfiR4aeAVHfjRQNN3RFjZ
         RVKKIF6VhmFliC0UzSZF1As6IXnptIRjRr4eE98r36h+3gAj0hXy+5gu1SdavBRfw9h8
         7ER7JcSxcWxsPbs/WE1Ao71geQPbgNSPMPS4v4VAcpUXCSZQTqkrEYqsfFS+ef3v+/J3
         vyAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532o+satvGuQ0xQmEQ60MJTo7Ua6r8KxQtuYFF9s3NuV+8mM1pNC
	dWO8+nRmpICiocIBBdaC1AQ=
X-Google-Smtp-Source: ABdhPJxWwmaH6I/ljpXkPeIYLCZovwf7GRBq+GlsC1khZ9FK+cbHk0vVC2QWk5otDqFwx4uw5qEavw==
X-Received: by 2002:a05:6512:3f0a:b0:44a:e3f:2862 with SMTP id y10-20020a0565123f0a00b0044a0e3f2862mr17023775lfa.397.1648036112622;
        Wed, 23 Mar 2022 04:48:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b951:0:b0:249:181d:ceeb with SMTP id 17-20020a2eb951000000b00249181dceebls3944648ljs.2.gmail;
 Wed, 23 Mar 2022 04:48:31 -0700 (PDT)
X-Received: by 2002:a2e:2d11:0:b0:246:3c3e:d544 with SMTP id t17-20020a2e2d11000000b002463c3ed544mr22150847ljt.518.1648036111401;
        Wed, 23 Mar 2022 04:48:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648036111; cv=none;
        d=google.com; s=arc-20160816;
        b=tTENAGiG4aYd/RFoPgQWQJr5mVJ0KxwxoXvBNIo/LEEqqEPdWbYsh6i9sh9YK5m+V6
         UEwdwtNWPh0ldqmlcG6cPG3EOV1qqJxyoJx4nVRtXw+9LZtlbr/1iu+PoX56oRncHehv
         mfyZPqcinNa7lktN1LDQRGvneUQoIu5XsMbaHXTYS1cXHvnKguS4oEXlrH6+/BZdXk+O
         krcj8rjDKneeeoGm/XRzh7D5Mix1/q4p3ee/GjMbAwaRHRjNAQJhobvpzaFTKPJ2VnoG
         KmLge0JRXdzQNgRoEfRPbDxlRu0RWCmSoNWpqRd39BiOaqdGupkkFRM/At/jLzkx4/WH
         mCtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=8PjZDyXTMEaHn2duElkoOX449JsJoEUnBONEtu7w2ec=;
        b=tYTVxN3zDV5/mPAR4m+NMCWYVwL9/7Uv4TGUam1butmkrtOrl56rZBx2NAKpSKLdSe
         hmqid81T9Bl2D6dO2IHrXhgWv5Nnz1eNLpF35zdgzKIh3lhKfFLFotuAvrMrBBsRf524
         FpkEECbxaU+SBXtpgQFHEOabQwn0Vu9N29KlSirfLCQ4B9/c8NoE+7tzGsajAk/aoCXF
         MGkhokY/DE2gS1AGLwW0Kvtx1sYeZo2tk/fbpgKvFg7JC45zP7/rsT0lkCuhKPat5bK3
         9IUDsJEJtYAzZNDqaDsj8jqS3PwbyxdrikylxxavQV3pNcMttEu4/zxoeGLZx1DmLzMD
         ucDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=due7XOdw;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=DNkYmWTO;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id e23-20020a2e8197000000b00249674b39dcsi1071536ljg.3.2022.03.23.04.48.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Mar 2022 04:48:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id AFF561F37F;
	Wed, 23 Mar 2022 11:48:30 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 38B4413A78;
	Wed, 23 Mar 2022 11:48:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id CqUDDA4JO2IdcgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 23 Mar 2022 11:48:30 +0000
Message-ID: <63704e10-18cf-9a82-cffb-052c6046ba7d@suse.cz>
Date: Wed, 23 Mar 2022 12:48:29 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.7.0
Subject: Re: [PATCH v6 27/39] kasan, mm: only define ___GFP_SKIP_KASAN_POISON
 with HW_TAGS
Content-Language: en-US
To: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>, linux-arm-kernel@lists.infradead.org,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
 <44e5738a584c11801b2b8f1231898918efc8634a.1643047180.git.andreyknvl@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <44e5738a584c11801b2b8f1231898918efc8634a.1643047180.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=due7XOdw;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=DNkYmWTO;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/24/22 19:05, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Only define the ___GFP_SKIP_KASAN_POISON flag when CONFIG_KASAN_HW_TAGS
> is enabled.
> 
> This patch it not useful by itself, but it prepares the code for
> additions of new KASAN-specific GFP patches.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> ---
> 
> Changes v3->v4:
> - This is a new patch.
> ---
>  include/linux/gfp.h            |  8 +++++++-
>  include/trace/events/mmflags.h | 12 +++++++++---
>  2 files changed, 16 insertions(+), 4 deletions(-)
> 
> diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> index 581a1f47b8a2..96f707931770 100644
> --- a/include/linux/gfp.h
> +++ b/include/linux/gfp.h
> @@ -54,7 +54,11 @@ struct vm_area_struct;
>  #define ___GFP_THISNODE		0x200000u
>  #define ___GFP_ACCOUNT		0x400000u
>  #define ___GFP_ZEROTAGS		0x800000u
> +#ifdef CONFIG_KASAN_HW_TAGS
>  #define ___GFP_SKIP_KASAN_POISON	0x1000000u
> +#else
> +#define ___GFP_SKIP_KASAN_POISON	0
> +#endif
>  #ifdef CONFIG_LOCKDEP
>  #define ___GFP_NOLOCKDEP	0x2000000u
>  #else
> @@ -251,7 +255,9 @@ struct vm_area_struct;
>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
>  
>  /* Room for N __GFP_FOO bits */
> -#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
> +#define __GFP_BITS_SHIFT (24 +					\
> +			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
> +			  IS_ENABLED(CONFIG_LOCKDEP))

This breaks __GFP_NOLOCKDEP, see:
https://lore.kernel.org/all/YjoJ4CzB3yfWSV1F@linutronix.de/

>  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
>  
>  /**
> diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
> index 116ed4d5d0f8..cb4520374e2c 100644
> --- a/include/trace/events/mmflags.h
> +++ b/include/trace/events/mmflags.h
> @@ -49,12 +49,18 @@
>  	{(unsigned long)__GFP_RECLAIM,		"__GFP_RECLAIM"},	\
>  	{(unsigned long)__GFP_DIRECT_RECLAIM,	"__GFP_DIRECT_RECLAIM"},\
>  	{(unsigned long)__GFP_KSWAPD_RECLAIM,	"__GFP_KSWAPD_RECLAIM"},\
> -	{(unsigned long)__GFP_ZEROTAGS,		"__GFP_ZEROTAGS"},	\
> -	{(unsigned long)__GFP_SKIP_KASAN_POISON,"__GFP_SKIP_KASAN_POISON"}\
> +	{(unsigned long)__GFP_ZEROTAGS,		"__GFP_ZEROTAGS"}	\
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define __def_gfpflag_names_kasan					      \
> +	, {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"}
> +#else
> +#define __def_gfpflag_names_kasan
> +#endif
>  
>  #define show_gfp_flags(flags)						\
>  	(flags) ? __print_flags(flags, "|",				\
> -	__def_gfpflag_names						\
> +	__def_gfpflag_names __def_gfpflag_names_kasan			\
>  	) : "none"
>  
>  #ifdef CONFIG_MMU

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/63704e10-18cf-9a82-cffb-052c6046ba7d%40suse.cz.
