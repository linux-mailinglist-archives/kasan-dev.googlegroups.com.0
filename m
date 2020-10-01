Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWNR3D5QKGQE67SXZFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6315228060F
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:58:49 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id b17sf2570505ejb.20
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:58:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601575129; cv=pass;
        d=google.com; s=arc-20160816;
        b=GdRGFs428i03Vj+thldV5nOlmHPAVlOxDpYtOEKf5hpZVtEKdGzK08C6bW1JTmZ1R1
         CWGM7tk4plGVIQgNCqb5MYIbq9hM5Rk7PTzLyGZk/hIcNwsh7c4P5P0gLlZc0DPnanu/
         b5tYl3uEIgOeqBpSE2rz+Z/+c1rUqLO5fiaAbAWO93B6fR4hy8YC+yQn8J7dK2xWHSWh
         LWLunugaLP60WGtTLf/EPJADHRT3tcHlSHUhe2PeAL9C/mdJvmuM/bSgCCAVfwI5DDYL
         7xz1t6ze/vDnw5Ari725/EFiIbMKVa57+ky/3yEluvi5+cYXUauB6/Eymy/RPFcxRpVn
         CsPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/j9J3IINPunLkuYdjj9LbWL0gA5v1jERVqINV9GnT8A=;
        b=zX07Wrd8MbP+We8F9KEjbF6kWdLtGGJvNLjoMjoJJ62BgR604TBcvXiuW1wMHqZ6Kc
         Y14Pob5jT5XwAQLmMl3HrpaGtGVBRzy1p9/m2utWJmoJhEGpgz+YHLUixvWJBYxig+/6
         PL1uqI1bE8dQtTWK6SN+0muQ0Guftkr+Pc0i046olu3+ZSXn4OOks4ia6bEE/4b0lEp8
         NbgMx7WvVXJmgvN8qK5QMuOVsELFPU+1cRbeviFNq+DlvVWQizN1ZiouqB1exlED521r
         A2mFU7aapkQoLxYRZ+rYRtDbBVtl03vxoNHc91ZlKo9uXT1uxhga7Bh9UylipapKY71M
         ngkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=od955wzc;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/j9J3IINPunLkuYdjj9LbWL0gA5v1jERVqINV9GnT8A=;
        b=qaf364f8wY2dXBQoIuFvmjC3vYARvhatEyHH3OZFG+tgU+Tr00H43E5VgK7yqGhr7f
         AIKWfdAmqc2/WQb7FynqV90pn2nf7lHBTtNOd7A7jPhcDsa8oN2DDmpMmliNSnsmLMVw
         duOm1J7DfIpa3W4BPV4RYf2ht59oO1uPEsB/0K25VzcUlz6EDjV1Z1fUwdoywDZyFar5
         PejdJvsG8baR3cUry2vytHtXBhyLkwfUMXyFoQi68eZnRveWqtEEyWE791ncMCeiHaLr
         j1/rOwLXqRayL7Mgm3dNMVENVLn1s2e/rReGqTVgdXmet9OrH0Ep+/OVb0t2S4yzs0jj
         mUbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/j9J3IINPunLkuYdjj9LbWL0gA5v1jERVqINV9GnT8A=;
        b=WSzGLiYSjsD6wNww6NWqnO0zgDxprOzzWl/leLG1vCV5cvSyfOpQe+HLd3gnXJQ5JJ
         j5yT/Ce4Vr419IjA2ypQ6CgJGE0acrGXvtVWJJUDAkraMBPfdY8joIAGroFeu1SDGLCB
         pvkaAp5VZMoNSoww2ah8ef6sJYnTe5HiFX3eed0iDWG3cq8mCrDUlsDp1dFOW6tn7/J2
         SIn6UA1/SG31N+29Z2lPxbuZKF+p5NKbplExUU2zroaZg52mCncr1JSrboJOLbwIufch
         86ZXJT7iWIa+0wJSTnEyGiwi08DO1+tBop8+tAMVCf/kpGc0cseNf0VvNiRVqMv1Qdd2
         yU3g==
X-Gm-Message-State: AOAM530poVxcPpWNBMcfj9gF9rwlC3HjwLb3j5b4jaUcUZ08IGNNHqMu
	80BdmsbXKOkodVrOaOBWZAI=
X-Google-Smtp-Source: ABdhPJwmqfkqkFsBmw8N+xDOQDVVUyWxC8gasoIDFBPDJVztQG2NR/lIsT4rvR4ahrgeVOwJQhNuxQ==
X-Received: by 2002:a17:906:2e14:: with SMTP id n20mr9615130eji.214.1601575129183;
        Thu, 01 Oct 2020 10:58:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a20b:: with SMTP id r11ls1043660ejy.4.gmail; Thu, 01
 Oct 2020 10:58:48 -0700 (PDT)
X-Received: by 2002:a17:906:3748:: with SMTP id e8mr9545195ejc.71.1601575128183;
        Thu, 01 Oct 2020 10:58:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601575128; cv=none;
        d=google.com; s=arc-20160816;
        b=vEMkSJs4D+cdNT5EelzIBcqaiHW6zPnY8fFXj/GVQ2SQmbjE6GwNRd1bqYI5jIom+Z
         811y6dT0qsEAiX1zstArAk44pvypmy/RUcKCYh8R24dNnNDaQ7bbS3jKVX0JTCElVNRs
         8pTi6Ox9uhQ3AcJq/wcaWddyqK2sUbwtuyhRrD/hUXj+5zIzhRMhgGxoRBSfjAV8MIG3
         0jTB0Je8Wjs4uzv3UKXzagqW6oaQ7/PjeVLQ/s9YtuWFr5yc2P78pCuCW1wAznLw5VL0
         x3CczzvJWuO+xapeUOCL3z+W8drCKcTxj8r+2kXr8Ii0XjFnj2JqYxlermXmWzdQ3ZVJ
         Iq3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Z3LAespRKggBAzZJgRL/XlMKflXl6US5qlulvNZ+CWs=;
        b=ZyTagmpNSheQc7G2Wv7ErIaRkcieOrvGMKtn8cDrHwuPjeFxT35Y73wkAs+zH/jcYZ
         8bhEpFCGMxc2feSloNYHNI+WuxXfepi9449el3P8eM2tEMrYSkn9yvKNvDY+bh8uW3rk
         26U1SZJlJiVV83dmApI2TQdx72ec0OKUTLl8IYxYs7yYDMWI3KqvYmYgARQ+em+5kMv+
         7NjgDAVVtUBynUMXFvcxWtjYG/mlHgWC0RugVobrDkdWJXPcJxJXfvpzD92w/0kAE2d/
         NTW3Xz8DwRXnDkM/2PuS5kUm6x28Cx1jY8ajr+76RW/SF1tYANMowxiP6+6KAwafOXrB
         NCew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=od955wzc;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id r17si58870edc.4.2020.10.01.10.58.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:58:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id k10so6850608wru.6
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:58:48 -0700 (PDT)
X-Received: by 2002:adf:f34a:: with SMTP id e10mr10271328wrp.91.1601575127768;
        Thu, 01 Oct 2020 10:58:47 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id q12sm10203515wrs.48.2020.10.01.10.58.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:58:46 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:58:41 +0200
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
Subject: Re: [PATCH v3 32/39] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
Message-ID: <20201001175841.GS4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <08b7f7fe6b20f6477fa2a447a931b3bbb1ad3121.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <08b7f7fe6b20f6477fa2a447a931b3bbb1ad3121.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=od955wzc;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as
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
> Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
> KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
> ---
>  mm/kasan/kasan.h | 6 ++++++
>  1 file changed, 6 insertions(+)
> 
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 9c73f324e3ce..bd51ab72c002 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -5,7 +5,13 @@
>  #include <linux/kasan.h>
>  #include <linux/stackdepot.h>
>  
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
> +#else
> +#include <asm/mte-kasan.h>
> +#define KASAN_GRANULE_SIZE	(MTE_GRANULE_SIZE)

Why braces? Shouldn't MTE_GRANULE_SIZE already have braces?

> +#endif
> +
>  #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
>  #define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
>  
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001175841.GS4162920%40elver.google.com.
