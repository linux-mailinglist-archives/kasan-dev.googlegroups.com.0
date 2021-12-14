Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSVX4OGQMGQEEC34BPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id E3185474A40
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 19:00:45 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id b14-20020a05651c0b0e00b0021a1a39c481sf5726334ljr.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 10:00:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639504843; cv=pass;
        d=google.com; s=arc-20160816;
        b=izhs2Sca/h0c5nK/Dz5m/oF288ylM29wL9KAbdb474VPFcB78oZw1sxzMyDNSiV4QH
         pXV7HoDM/1aMo/1iidMHu+cUIhBRC+TUKsT1T62ookxZ42PvtiFwSmKhKiXHy7n93CrQ
         9Qrj4RgWdJNtPTs1SV8UeXovzT/6/MM61texBgyBDexzq/03P1UlCfU+64Jhngat00r5
         LcKmc+OZwdKpE+42hZmo1pGolVeOie2cZ4A/E+a2TLOZvai16jyr5f2mLlZpMIpVdH+v
         1awEd986LL1hrN/kVW1yn0V44QaT+7h25EW/YJfKdKeRbDbaeKvHXPYXabm5QjZ79QLy
         nmdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=SwskSGNNyda9HiVlFqJU6LQXMfreZwN/vIDzk2EknTw=;
        b=gyuJYNDUMiVTFNZX9cMazarueeBQ528XK6MJg9N5OF7aMosIQocxWxDAx9OsgujzNc
         51HsLlfFa6IZlxuCc7yQeQ6TdUTZRIyJ+eaI5E9bvGS3yIHdM0EVdi10gh3iIcKkCDea
         ZBDtGfdgCMlWKl8lOVkvkgDqTz6wFV4JMXeQmy9ZZ3mhErdHJTP7j5imKaqga41k56gI
         c5S8Zf87+V3raJJcvDck1P+VhmT/Ui6qqzoPmiinW89xJin9t55PVJaStikhU7SajpUB
         YMTvTMBDYqRfBdQ+D2m8+hMfHNmaif7vrYfG85tQ95wYkmh3/OxxdWPt4FPNZGZJB3dR
         V2EQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=syl17ArW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=SwskSGNNyda9HiVlFqJU6LQXMfreZwN/vIDzk2EknTw=;
        b=CNawluAkojSYkhQt7+AKbQ2VTz7S4g1AJSroBXj7P0KcPIQ2dyi9stU7d57WTZN2v8
         7xX9B58kQzlXo9y2M2yVmJh8m/YxKzMmDTFtsz+EDf2ZhISbFj8UkJxsodMjJzMBqN+B
         o+ck6APnAFh6vC/hz2oOTLuTyfV0IxS7qMOKtExuzNpgbD5vG6FhqDy7FAnk+DR9Ewwp
         tVOFRI8uxVMeUdgBMyF/W1HGnv+Zh/Eyhu6LLKQNidjpj+7g0ENrZOafQQMQutr+cY2M
         oqT2lzDUNnEVwriC2enhAvmtHudL/6ZHTwFzuLwPrh8nQcnzaJ9sEX4tVTgvyZhffctS
         vORw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SwskSGNNyda9HiVlFqJU6LQXMfreZwN/vIDzk2EknTw=;
        b=PruKtPypLTMyyz1mlgO3GoiNV61n4Oz02ZjeK/3uHdR2V8FCPu3oaaXv45vCPeL+SD
         unqm4wmqLDKWuJMlQaZr4VS6IoNB5UDO0DhIrxjArT9lLB2ZP/n3T9qJEpOQlJ+2LfP3
         k7ZJRtd1hHrcDWx9pBEFwnBompgfKC6PHQRGurutQ3AxaMQivIHOV02AuDeQsn//oVFw
         TcWj5Aq/qaXm6toKqnDQPPoJr5OBiGh8O0Qt2nZxisklT62/mYVoYnx+wttLYNq/fUX7
         Pl2jI1zfo+LhfGxQQQXXdwMzFiyJZPHXUjaNmAtXFtkb25e+vTN9OT+rUkZQ9d5pLmfZ
         8niA==
X-Gm-Message-State: AOAM532Mb4WVINLF3SouCR/qBaHDb8lQRs+NbuCTA4+dCSvxhF3+P0nr
	NhF7f5mGT9iYDn6sKeJO8xU=
X-Google-Smtp-Source: ABdhPJzRHY82CkAl9wuhNPQKgZ7hjDSgWll45NTcXqykNJ4vMy62pZcJrybCSrZ+CIvKO5v29QA2EA==
X-Received: by 2002:a2e:5308:: with SMTP id h8mr6215566ljb.352.1639504843325;
        Tue, 14 Dec 2021 10:00:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c4:: with SMTP id x4ls3194515ljp.8.gmail; Tue, 14 Dec
 2021 10:00:42 -0800 (PST)
X-Received: by 2002:a05:651c:1507:: with SMTP id e7mr6547148ljf.300.1639504842084;
        Tue, 14 Dec 2021 10:00:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639504842; cv=none;
        d=google.com; s=arc-20160816;
        b=r6/dwjnEPQscbZdw8VSQqzBGRiULIQtFB5NoHADj2h86dl0JrN1AJPv2d9PolQIbon
         awMiGclf30BgG1JOleIJKpp+0d7BqucaLEik32juFql8zqa/Lnz0942ngVTlJnnl7Qg2
         G54JIgh1h2T7HEnGVfSCYnF2YlbuZpelIFkhcIMLfg8DP5ovkwChcQ4eG998mEDe5UVi
         wG7jMO7j7TMawzlhfCpKl6ek+WVYIzs4mP1flRvcZeJ5T5ZLwXnb1ld23uEJ0HDV3sMF
         5T/ye6RtP6PtsembDKbC3bIBW5VYgoHs3uJQMipCWd+jPNrDu9FyU1c8L9zQL0r6y0cL
         0IFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+IqBfvBvBmcxlYVp+0RytaxVZtHRcBsFFTjJF1k6GHc=;
        b=AMzPzIXU+jqCUeWlbU31cEd7XZkQW1Bpw74DPQQLW4YxJfAXqysIrVN+TioIKH6q3l
         UdnoNhd5wyWwWSVbF1uJYAe9nxHAsVQBM+yzWpGRExxq2jU9+LLGQVykd7i4kocmkwLN
         O8dX0+bKGDne6WSdGEo2RCO2NKb2RDf43Mb1cppBmg2n+RgVGtzR+26+NF+Ib4W7Ls55
         yW9pSYC4XwUEuSUS1ABwA0mvnzNNP0b8Tbwm591dSmiXwYsuuTUU6UdhUSgfkCsbByLN
         PGrf90w9YjBVffjLdseA8vtDX+YqhEwMkXC18ohusTCdQkEgkd/oUDGFWFgh6ryPu1PF
         GgTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=syl17ArW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id d8si23639lfv.13.2021.12.14.10.00.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Dec 2021 10:00:42 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id g191-20020a1c9dc8000000b0032fbf912885so14311304wme.4
        for <kasan-dev@googlegroups.com>; Tue, 14 Dec 2021 10:00:42 -0800 (PST)
X-Received: by 2002:a1c:f217:: with SMTP id s23mr694802wmc.70.1639504841398;
        Tue, 14 Dec 2021 10:00:41 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:b1a9:56e:da78:fa44])
        by smtp.gmail.com with ESMTPSA id n36sm1316753wmr.2.2021.12.14.10.00.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Dec 2021 10:00:40 -0800 (PST)
Date: Tue, 14 Dec 2021 19:00:35 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v3 28/38] kasan, page_alloc: allow skipping memory
 init for HW_TAGS
Message-ID: <Ybjbw5iPg2BWsgqF@elver.google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
 <cd8667450f7a0daf6b4081276e11a5f7bed60128.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cd8667450f7a0daf6b4081276e11a5f7bed60128.1639432170.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=syl17ArW;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as
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

On Mon, Dec 13, 2021 at 10:54PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add a new GFP flag __GFP_SKIP_ZERO that allows to skip memory
> initialization. The flag is only effective with HW_TAGS KASAN.
[...]
> - * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
> + * is being zeroed (either via __GFP_ZERO or via init_on_alloc, provided that
> + * __GFP_SKIP_ZERO is not set).
> + *
> + * %__GFP_SKIP_ZERO makes page_alloc skip zeroing memory.
> + * Only effective when HW_TAGS KASAN is enabled.
>   *
>   * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page allocation.
>   * Only effective in HW_TAGS mode.
> @@ -242,6 +247,7 @@ struct vm_area_struct;
>  #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
>  #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
>  #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
> +#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
>  #define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
>  #define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
>  
> @@ -249,7 +255,7 @@ struct vm_area_struct;
>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
>  
>  /* Room for N __GFP_FOO bits */
> -#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
> +#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))

You're adding several new flags, I think you should also make a
corresponding change to include/trace/events/mmflags.h?

At least __GFP_SKIP_KASAN_POISON is currently in there.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ybjbw5iPg2BWsgqF%40elver.google.com.
