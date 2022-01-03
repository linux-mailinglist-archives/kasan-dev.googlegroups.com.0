Return-Path: <kasan-dev+bncBDY7XDHKR4OBBXGAZGHAMGQEYSKKWOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id B53E0482D8E
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jan 2022 03:33:01 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id p1-20020a17090a680100b001b1ea621b81sf21634384pjj.2
        for <lists+kasan-dev@lfdr.de>; Sun, 02 Jan 2022 18:33:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641177180; cv=pass;
        d=google.com; s=arc-20160816;
        b=B7EV1ikVNeM5Sv3eUeDeYAEURlMXGFkVaxiNpq+Ou7OowX+3j7+n6kkCZVJ2GPE7SJ
         7N2zxsI+gg0rrjZHPlpJgOhhLSNQcQgmMEN9h/ye6x9ehL+EsLMz6pg8md7KTkLeHdTa
         peQvjX+sMhZpdgsGlAkS81l8WDGF+Rm20Wl610asA2lBWG9jdR8Jgyqim0fbkZSvdTNi
         xdAu6y2ff20AXiL2VL9/xd/5m6SgwFT/VIJOrmRRU+toAMwpZCmB59xXIoStpTTWD46W
         1f2DUeHNO2NEnyVzEYJmHuzOgG3HmqORHhX5/PpayY1GEtIbNSTcVBs4/cY1tfCJ51ZZ
         uAjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=XZ44ZYoOURIS/XaDp86A/e5lEMbIZyWI0JprPKyjdks=;
        b=AajPI1LfUTCKa30sLtYHhMVBNY9cWabs5wCbfn0Qa1Ym4Jljr6cxzD60F1wM5feMjY
         F1hgqZw0MWxbsXMzDecQt3iG5vVdza/PQZwRL/vWfV65zm/AAbc+fpA+AEynRQu8tBzA
         52HNfXMOIUpSDEVJ8dOGLVO2tqVYUbu5fXjVHgzxkHLTVojoPBfg4qEqFwzN9bBEeFDe
         6C9/7juAuN01UhPqYGxKGuunWc+SrE+3qdDd/HTP8T/EZwBPmtx5lVTcJ6iFbnrPb5/G
         dIAf9gGJtyjnN042GhTdioV7TThvA2KwZJBS1UAgz3s/IuIBwpkO3IQT9mf24xS0qfr9
         vylw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XZ44ZYoOURIS/XaDp86A/e5lEMbIZyWI0JprPKyjdks=;
        b=JQWOP820JYf8FP85W1vtTDzPd9wtZTMsjeW9HYJtVsQETnrBf0311DoYsPb0tIfr36
         ZdpUPEcBBHqjDDxNCninFhv8S8empXrApUNvdKkHJpX+N2NSPcCjkMxTVQXlFzgWbDZZ
         H1kPAVqWR9R/j7U6EUOk6bBHsDJ9KuEY+VWziGB5lOO067rXI85z1zdK+LzpU8Dg9Uu1
         mWxBCNxMQCT3Z861dbSoj1+a1Ajh4dA3Iv3KEhzjmFv/oRtjzSJHYt2W9GyjE7ktMjpI
         AHr7aMjGTIvwB/w0VFk4TBsgFXXxwBHES9qRJHSR/RI06pFuAZJl+1+UF80trO6UZbzQ
         yWow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XZ44ZYoOURIS/XaDp86A/e5lEMbIZyWI0JprPKyjdks=;
        b=BoMT9v7O6UyYO4Luk4wsy0UN70aoptbN9SLa2rT1in9ngMMSQGNa84Os2mcJYeGdn7
         qO1X/rh3f2gYxZ75Za2T85Ek838QEbj+K4p8vDcvMfhLteDN63DhFYlcVd9Sht8zLn6s
         CbtPAcXxFqniDjXCVyohcoBf4YZ4KIPOq2ewSLgTyzR/h8h5mYLMZ7+ZJvB1o46GUAmn
         Bgh2B+B9OLzdxJI5yvYDBh7YoQBR3DHyXVfEwxK/fDSBN+DJ/bSzvHYUAFPCvqt85uGM
         M7HcGO0E7NV+hayUNlIHCtKDi/qoy3iJT2rAmZlhF8ACZg3Pkl1ORqAOzYoqhuc0MJPg
         YR0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VXm4Httegb6oyYVYYcRGefpkTrm8E3C8N9CzFJaZezzxTGB/4
	+f68BdQpb91skllkoOvZwis=
X-Google-Smtp-Source: ABdhPJwRi5w8rAX+3GygYnQhuO5HplwAGRIWhgXt+hhTKUH4TXg7hVKmn7/TIRwX4RVlhj4GMEl5XA==
X-Received: by 2002:a17:902:e54c:b0:149:a59c:145b with SMTP id n12-20020a170902e54c00b00149a59c145bmr15433910plf.138.1641177180197;
        Sun, 02 Jan 2022 18:33:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1902:: with SMTP id mp2ls19359308pjb.2.gmail; Sun,
 02 Jan 2022 18:32:59 -0800 (PST)
X-Received: by 2002:a17:90b:4b0d:: with SMTP id lx13mr53050837pjb.89.1641177179714;
        Sun, 02 Jan 2022 18:32:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641177179; cv=none;
        d=google.com; s=arc-20160816;
        b=ciEmOJn49UD1CSsvbkmTRPcit7q8oIUdB3ozalXPHyhbgV9UMk9ZaSQR6f/yBvSy/u
         0mL5f6VYA6w9+HxYgHjHREwjfy3CorlG87Z3ahezRJgec6YHwUi/hzfMeSOqoNuciabO
         DYlLh8Et1KlYtI7Z+8Ifv4Gm9NIi5rgCiXNA6HiV0Yn+zgJw/gn2Kg//wzkKbvnlL6R6
         DXf9pbfwaN7Dcox6qREmGbeofePfgwJgl6/kOudEr/RxbaM7jZkieSFlJg2+iFT+mZRs
         RZcay4nRmfcvwnDnDsQ0eMC5jRdwwU3yblR2KBuvKFK4l1MZlPeIlatqCNEypQ6X6uR4
         626Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=0h4K3vuS2U1zzK3xF6m9eVw+MOv1uZntgRfmgW6NtXg=;
        b=lkOqAVWOaLhx+NRQNdlxoJZvBy7jQuhrmOCPSom5aqd/Zgu7PmN4OiH8FC/Gh9E37k
         IT6i202JKFf9CqwA383tkMPdlipWfrDgOSYZcUXMy1HMayr2MKtpXkxoea8QXX87f/ci
         Pcy7rbKXMx0H/a4VuJbI0keSmQxWRf02L1hPgC3GqZT3r6zyG98NDGu9dgoa8oGQ5oLb
         iuE5ev/htT8Amob1UgGerKJ9E7UNsVdBVjRgT3LuzDCwZWSDI315NUcwVVZpDDhYevef
         Ki6UxEurh5d1XveQUAEwdYRVzmNMMdhy4AQIbdPvxmm8PflzGYxAHzTGtr6MNCn28Qil
         ow/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id v3si1066360ply.6.2022.01.02.18.32.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 02 Jan 2022 18:32:59 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 18dc1dbfd22c420398ecef977ad9a2e2-20220103
X-UUID: 18dc1dbfd22c420398ecef977ad9a2e2-20220103
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1170971578; Mon, 03 Jan 2022 10:32:57 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Mon, 3 Jan 2022 10:32:56 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 3 Jan 2022 10:32:56 +0800
Message-ID: <b968e485f4d7f201fdb4e39f64ca757180e7374a.camel@mediatek.com>
Subject: Re: [PATCH mm v5 29/39] kasan, page_alloc: allow skipping memory
 init for HW_TAGS
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: "andrey.konovalov@linux.dev" <andrey.konovalov@linux.dev>, Andrew Morton
	<akpm@linux-foundation.org>
CC: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas
	<catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Mark Rutland
	<mark.rutland@arm.com>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>,
	<Kuan-Ying.Lee@mediatek.com>
Date: Mon, 3 Jan 2022 10:32:55 +0800
In-Reply-To: <88f2964f4063aa6fd935ef8c8302d02d8d67005b.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
	 <88f2964f4063aa6fd935ef8c8302d02d8d67005b.1640891329.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Fri, 2021-12-31 at 03:14 +0800, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add a new GFP flag __GFP_SKIP_ZERO that allows to skip memory
> initialization. The flag is only effective with HW_TAGS KASAN.
> 
> This flag will be used by vmalloc code for page_alloc allocations
> backing vmalloc() mappings in a following patch. The reason to skip
> memory initialization for these pages in page_alloc is because
> vmalloc
> code will be initializing them instead.
> 
> With the current implementation, when __GFP_SKIP_ZERO is provided,
> __GFP_ZEROTAGS is ignored. This doesn't matter, as these two flags
> are
> never provided at the same time. However, if this is changed in the
> future, this particular implementation detail can be changed as well.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> ---
> 
> Changes v4->v5:
> - Cosmetic changes to __def_gfpflag_names_kasan and __GFP_BITS_SHIFT.
> 
> Changes v3->v4:
> - Only define __GFP_SKIP_ZERO when CONFIG_KASAN_HW_TAGS is enabled.
> - Add __GFP_SKIP_ZERO to include/trace/events/mmflags.h.
> - Use proper kasan_hw_tags_enabled() check instead of
>   IS_ENABLED(CONFIG_KASAN_HW_TAGS). Also add explicit checks for
>   software modes.
> 
> Changes v2->v3:
> - Update patch description.
> 
> Changes v1->v2:
> - Add this patch.
> ---
>  include/linux/gfp.h            | 18 +++++++++++-------
>  include/trace/events/mmflags.h |  1 +
>  mm/page_alloc.c                | 18 +++++++++++++++++-
>  3 files changed, 29 insertions(+), 8 deletions(-)
> 
> diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> index 487126f089e1..6eef3e447540 100644
> --- a/include/linux/gfp.h
> +++ b/include/linux/gfp.h
> @@ -55,14 +55,16 @@ struct vm_area_struct;
>  #define ___GFP_ACCOUNT		0x400000u
>  #define ___GFP_ZEROTAGS		0x800000u
>  #ifdef CONFIG_KASAN_HW_TAGS
> -#define ___GFP_SKIP_KASAN_UNPOISON	0x1000000u
> -#define ___GFP_SKIP_KASAN_POISON	0x2000000u
> +#define ___GFP_SKIP_ZERO		0x1000000u
> +#define ___GFP_SKIP_KASAN_UNPOISON	0x2000000u
> +#define ___GFP_SKIP_KASAN_POISON	0x4000000u
>  #else
> +#define ___GFP_SKIP_ZERO		0
>  #define ___GFP_SKIP_KASAN_UNPOISON	0
>  #define ___GFP_SKIP_KASAN_POISON	0
>  #endif
>  #ifdef CONFIG_LOCKDEP
> -#define ___GFP_NOLOCKDEP	0x4000000u
> +#define ___GFP_NOLOCKDEP	0x8000000u
>  #else
>  #define ___GFP_NOLOCKDEP	0
>  #endif
> @@ -235,9 +237,10 @@ struct vm_area_struct;
>   * %__GFP_ZERO returns a zeroed page on success.
>   *
>   * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the
> memory itself
> - * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
> This flag is
> - * intended for optimization: setting memory tags at the same time
> as zeroing
> - * memory has minimal additional performace impact.
> + * is being zeroed (either via __GFP_ZERO or via init_on_alloc,
> provided that
> + * __GFP_SKIP_ZERO is not set). This flag is intended for
> optimization: setting
> + * memory tags at the same time as zeroing memory has minimal
> additional
> + * performace impact.
>   *
>   * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page
> allocation.
>   * Only effective in HW_TAGS mode.
> @@ -249,6 +252,7 @@ struct vm_area_struct;
>  #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
>  #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
>  #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
> +#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
>  #define __GFP_SKIP_KASAN_UNPOISON ((__force
> gfp_t)___GFP_SKIP_KASAN_UNPOISON)
>  #define __GFP_SKIP_KASAN_POISON   ((__force
> gfp_t)___GFP_SKIP_KASAN_POISON)
>  
> @@ -257,7 +261,7 @@ struct vm_area_struct;
>  
>  /* Room for N __GFP_FOO bits */
>  #define __GFP_BITS_SHIFT (24 +					
> 	\
> -			  2 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
> +			  3 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
>  			  IS_ENABLED(CONFIG_LOCKDEP))
>  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) -
> 1))
>  
> diff --git a/include/trace/events/mmflags.h
> b/include/trace/events/mmflags.h
> index 5ffc7bdce91f..0698c5d0f194 100644
> --- a/include/trace/events/mmflags.h
> +++ b/include/trace/events/mmflags.h
> @@ -52,6 +52,7 @@
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
>  #define __def_gfpflag_names_kasan ,					
>        \
> +	{(unsigned long)__GFP_SKIP_ZERO,	   "__GFP_SKIP_ZERO"},	     
>   \
>  	{(unsigned
> long)__GFP_SKIP_KASAN_POISON,   "__GFP_SKIP_KASAN_POISON"}, \
>  	{(unsigned long)__GFP_SKIP_KASAN_UNPOISON,
> "__GFP_SKIP_KASAN_UNPOISON"}
>  #else
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 102f0cd8815e..30da0e1f94f8 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2415,10 +2415,26 @@ static inline bool
> should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
>  	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
>  }
>  
> +static inline bool should_skip_init(gfp_t flags)
> +{
> +	/* Don't skip if a software KASAN mode is enabled. */
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> +	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +		return false;

Forget to drop the above check?

I saw v4 mentioned that this check can be dropped. [1]

Do I miss something?

[1] https://lkml.org/lkml/2021/12/30/450

> +
> +	/* Don't skip, if hardware tag-based KASAN is not enabled. */
> +	if (!kasan_hw_tags_enabled())
> +		return false;
> +
> +	/* For hardware tag-based KASAN, skip if requested. */
> +	return (flags & __GFP_SKIP_ZERO);
> +}
> +
>  inline void post_alloc_hook(struct page *page, unsigned int order,
>  				gfp_t gfp_flags)
>  {
> -	bool init = !want_init_on_free() &&
> want_init_on_alloc(gfp_flags);
> +	bool init = !want_init_on_free() &&
> want_init_on_alloc(gfp_flags) &&
> +			!should_skip_init(gfp_flags);
>  	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
>  
>  	set_page_private(page, 0);
> -- 
> 2.25.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b968e485f4d7f201fdb4e39f64ca757180e7374a.camel%40mediatek.com.
