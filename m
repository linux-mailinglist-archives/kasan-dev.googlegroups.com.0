Return-Path: <kasan-dev+bncBCF5XGNWYQBRBE7LZOVAMGQESL2M7LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id A764D7EA973
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:20:36 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-41e58a33efasf62186461cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:20:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699935635; cv=pass;
        d=google.com; s=arc-20160816;
        b=r9AYAzCHPGeQYYminAjyWugQd9y1CKiTN2J2bnZRUthHnjvD9/CE6WWjt3LB3MCQSR
         Y9C306MCyiclL+zqeW8vzKfCyWk7s2WntMsAsbZj2Kip8HUoql2dKJFqVSK47d84LJ4v
         /Vo1PmVr9+b0slDsgznsduRADXnya+eesDERdb1lgnuWCXI9haNtJXIs1YfogcnT42Xg
         cve3uQ3OFbZC3HHcfL+EWN2LxLXT5nbqgFmBHgsTDpYLhXkJG37n3ol2uEYOTRGIiKUG
         9MChj/+tETenZzQT5GVbGKfeS1KldgaVJR1B5oWUntJjNuHUERbikbFKcTut2C+PH8ls
         Z0HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=T9Oz5dfbR9jNw2uIJ5BbNfgcioP5DA3rmN0SxvDGEoQ=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=QbC7S2leIHWw5dRHDSKwQghaim/+R3caPZp+B3p/+gnl7ZeEo1DSbr91Pw0YLEf45Y
         zEeJd9ltgeHnzxLFn0QyhpoOgmaW2/eQzql1XyoOqXTTBGaVOoD91jt4q9NZkvJjMkvg
         /rxHo4Xxs0yuJvRb37gvX4ADjdIDUMKXmLn2+BAIDsCFfXNNnesjj98IRB6IY/+mFenf
         q88NYCuKE1UluyYPfR7PCzc2ZMBeUlblKby/LwQPxpD/Ss5bH8HEnbhsnc05q8h/CBL5
         5gPvEUs6UqtvJERZiB6W/451bCPJEYJpZedEWMeHbJtA3erAohC8CTtvqJkTwn7FVbe+
         hDbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="N/cwk22V";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699935635; x=1700540435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=T9Oz5dfbR9jNw2uIJ5BbNfgcioP5DA3rmN0SxvDGEoQ=;
        b=gm5svY7wYt/tlZnwIF7e530dVoB9byvEyOMh6LMpYRFsTQMC9kzyKlIyv6CbKCIBzZ
         mWI6uHk4PW/L8p772E7X40Fc+yWseToiyDymm3jvDKooP3Sk884w2iqdELqyUjF9F0g5
         a88DDBy2gbX6OpcZ1DhrD/KyXvvms5SWOt9quIoDWOwQ1YnH9FjwG+5XUsqHBKXVuLSC
         9uGw5IahyN5kzgt+5QS5515uOqKSs3w261JaqzPI3UHH2CEv2E26GxfHGnPJ0sagyU7A
         KCsHQjc7ZN1bb1tlHt62TpmsuRZuuQ9MdtpldbPr4PPeVyOdBrsrXMKE78m94xPg7eEG
         XRSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699935635; x=1700540435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=T9Oz5dfbR9jNw2uIJ5BbNfgcioP5DA3rmN0SxvDGEoQ=;
        b=QUetlzqUusN8aDy5lFnFNsrA2DS6mO4DrGvN6+GE+BS2WKOw5Ff4wCq8V8+Ju7QYXS
         IWp5ZB60TGHVzW5Bs9kQJXl+Yo4gVMwyq0fv+HY6RspuAoY+wuFMkBnt+Hi3aY/XOzJ0
         uSv548MJV+2WvuE2Tr3Z24b1sfK45D6WQYdtk/gkJaq4WtXi1dh7e221tryVf9/CPXpK
         cBoBqdIRv46TiVw9LPImHyb/BI3+45+b/J3B++jlSlgnICYt7yQBKFQ5xZRT66K1aTvd
         dBT0H+KIPkmXysPkuSdrjk0FIBc/8ZlqlodrTBq52deDSYGcDs0OkQAc7yNU9XmY2FzZ
         /4AQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwBgTYwc2Y4IMhymZFXGf9VwhWpb/f8PD+T6xDyUZrn9+00Q73m
	9Hxg6ccbepsH+OTphIXD+ec=
X-Google-Smtp-Source: AGHT+IH4NgctCl2u6QnUqcZph6lWD1G89GdHf/BllNMahJXBl5g2rm3ZIQH5bmlpYjeJhIf9f1Zg6w==
X-Received: by 2002:ac8:7f93:0:b0:417:b45b:84c7 with SMTP id z19-20020ac87f93000000b00417b45b84c7mr1308445qtj.19.1699935635622;
        Mon, 13 Nov 2023 20:20:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:994:b0:421:96cf:753c with SMTP id
 bw20-20020a05622a099400b0042196cf753cls170742qtb.1.-pod-prod-05-us; Mon, 13
 Nov 2023 20:20:34 -0800 (PST)
X-Received: by 2002:ac8:5a13:0:b0:41e:3dbd:cb28 with SMTP id n19-20020ac85a13000000b0041e3dbdcb28mr1229698qta.38.1699935634787;
        Mon, 13 Nov 2023 20:20:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699935634; cv=none;
        d=google.com; s=arc-20160816;
        b=Imw35K1CNOIBtYg0Djv+wH6H5GLNXWzbXcXHq1Y4mjmc20J5aAHoaC16C0sSzXcCpp
         BSdDTZ8Bg1dpGqxAYkJEX7HuKcHUjENLABBFMCSw1ZDPWMku0nlWmdQw+cZEaezI+4+F
         Ho68OvrpfD1Z9L3P1aQ9IcVEOQ6ofZR0zSJbSghmFNTlAVstdH+0nrwhVE6xb1L7E+BX
         z6ILxhFfgAbfwo/6KLycr+SgPtFfiMuO+iOKfKO9ks2SxhmQIXyObfNx4V/kXVH7fU8P
         lCBivUchKiTSskYypJCjJiSr57GQmFSdcSEZ5jrLP6jl/bkMBbBFHP4aI8se1HBT0C+u
         l7XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ew+aEAUFKMT5ddXwYjWs+9wP5nLqtY4565XxaEvPnVw=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=TchuGCYnPz9YKhzgVlsJuEGuB4oBtBPFhKQjswyy/5/3pT8aoSDj3cJ896n1b5cSuq
         gfdke6+dhjt4DJKOmwH0w1DRVdv5e61opa1OarUAVdqUbhusb0nynJA3Cs33AW7Sz3mE
         Qz3wEQ7TR94O4LztATByzh6tiqVa6sUf+FUKS4wgSaq+2ua5HgXWHezKmnG+A/h6XR6R
         bS6X5wg2oBuZbD2zA1boNULJZeVSQ8N7c+kJgWXhfjx8ft/XUQhjV3nVORJk9pyJ1MXA
         McPsxnWVDTRnx9Eah79sI0D0ow77vWpw2oUL6iuZuDCrflXaw8eaeHHzovg2LCGJ5WeO
         8AXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="N/cwk22V";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id ga23-20020a05622a591700b00421e709bf9bsi157581qtb.5.2023.11.13.20.20.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:20:34 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-1cc3bc5df96so37717975ad.2
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:20:34 -0800 (PST)
X-Received: by 2002:a17:903:260b:b0:1ce:171d:2795 with SMTP id jd11-20020a170903260b00b001ce171d2795mr1129493plb.65.1699935633849;
        Mon, 13 Nov 2023 20:20:33 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id c2-20020a170902d90200b001cc3875e658sm4792216plz.303.2023.11.13.20.20.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:20:33 -0800 (PST)
Date: Mon, 13 Nov 2023 20:20:32 -0800
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 05/20] cpu/hotplug: remove CPUHP_SLAB_PREPARE hooks
Message-ID: <202311132020.5A4B63D@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-27-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-27-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="N/cwk22V";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::635
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Nov 13, 2023 at 08:13:46PM +0100, Vlastimil Babka wrote:
> The CPUHP_SLAB_PREPARE hooks are only used by SLAB which is removed.
> SLUB defines them as NULL, so we can remove those altogether.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  include/linux/slab.h | 8 --------
>  kernel/cpu.c         | 5 -----
>  2 files changed, 13 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index d6d6ffeeb9a2..34e43cddc520 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -788,12 +788,4 @@ size_t kmalloc_size_roundup(size_t size);
>  
>  void __init kmem_cache_init_late(void);
>  
> -#if defined(CONFIG_SMP) && defined(CONFIG_SLAB)
> -int slab_prepare_cpu(unsigned int cpu);
> -int slab_dead_cpu(unsigned int cpu);
> -#else
> -#define slab_prepare_cpu	NULL
> -#define slab_dead_cpu		NULL
> -#endif
> -
>  #endif	/* _LINUX_SLAB_H */
> diff --git a/kernel/cpu.c b/kernel/cpu.c
> index 9e4c6780adde..530b026d95a1 100644
> --- a/kernel/cpu.c
> +++ b/kernel/cpu.c
> @@ -2125,11 +2125,6 @@ static struct cpuhp_step cpuhp_hp_states[] = {
>  		.startup.single		= relay_prepare_cpu,
>  		.teardown.single	= NULL,
>  	},
> -	[CPUHP_SLAB_PREPARE] = {
> -		.name			= "slab:prepare",
> -		.startup.single		= slab_prepare_cpu,
> -		.teardown.single	= slab_dead_cpu,
> -	},
>  	[CPUHP_RCUTREE_PREP] = {
>  		.name			= "RCU/tree:prepare",
>  		.startup.single		= rcutree_prepare_cpu,

Should CPUHP_SLAB_PREPARE be removed from the enum too?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132020.5A4B63D%40keescook.
