Return-Path: <kasan-dev+bncBCF5XGNWYQBRB77GZOVAMGQESIF55TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 378647EA95B
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:11:45 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-420f5614aa9sf64294791cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:11:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699935104; cv=pass;
        d=google.com; s=arc-20160816;
        b=zs0wzJ+eVcBMKqpQjfbUVF3hA48ehfJwgbtl5W9muAOHve12kgUI6a2JaOoaKy9t0i
         t9GrUwx5pu6me+bqaWKJPK56rD4qCHVJpQnSeNPzrOkuTsO3F0hu6mdpHtRgJRM8Sx7b
         qrD21JNwC+UG/D1b5tuLKx9Ki+cbpR8XqINyZe+AOMm7j5EmzexoLJXVBDCmIWHQ/I+b
         bIARXTI0DYlnzBmzRPu2WcmA3defqN8X3mLRNaecHlHRgR4Pf7dCWGR2cEpLT5Zsp3oo
         X+4pZn90c9CnoWelH9GQPZJ7kSQoJS8tG2S6Pb0zDvYwAZe9J48SwqrdmKuKOO0H4T3b
         kr4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SBDjA23xnsXZukkSYU5Q167zzkYStzDGyVKpeJovBdw=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=paMLiv+Y4NDTZ4R8HjmG0YreJrbC5ENMoklnaK6Sv0AsdV5Hf6btJ+hwwjKvPsUPlu
         /wf6uJ/mRYWCk+1e1jQHfZkPp51xsem4Np0M3kUGaTjUFCXjqZBWKONio2kCvkI5n4Y9
         XEXt/gYHOywNJ4Y7a+k2vptB/05PE185jAhJXfxhsXSuKZFWgCDJN+1KKpr3oI2wz237
         aMeJlQ9urPrVhnV8QITBtxaIFlI3+0S/MChtiAl+RhIfZQ76fm8O+ZTHT+yU2GJCOn+D
         IcPoka1lg5ACm/1mC7xt5LjMUMKMJ0z5aeZAe6mZCNNwYmw6OY/iAEKpc7icUU42KcM5
         Ut9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=REGDi01Q;
       spf=pass (google.com: domain of keescook@chromium.org designates 2001:4860:4864:20::2d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699935104; x=1700539904; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SBDjA23xnsXZukkSYU5Q167zzkYStzDGyVKpeJovBdw=;
        b=mSyINAEfsGyxpThgfrRXJWa/Q0EZQfYsMe/VTKT+kjJz2L1OTDshwnOErI34HmBn46
         8ZsTPlxT6OnCtaVcuuNDJGN3whyrGVUyth+7ap7knHDNFy8v600JLGs8xOWKkeu4LIRN
         xgrAPNSffhaTFBWF8AKSk4yozcQmnKMHwHE0rZs+KZCPAGhGJDSRzrwR9jaNdMqXJnDD
         MoeDThYUO1gpmTGFZFRNOyynEN/J99Rc8MBDiBNUuWAHYyOW1Hyd3a0zsgwh0jVXOOF8
         25b6q8rwejLRst/9KLqgYGDmNwkhIhEag6NBAaFkfEr7kRT9ebVbbMarJxURJvAZa5y4
         qoGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699935104; x=1700539904;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SBDjA23xnsXZukkSYU5Q167zzkYStzDGyVKpeJovBdw=;
        b=EppsxRJotWVdS5rS0kgy7VWvotmoRWABKprsbq/8HhWrZdK/fTLaTVAa6YH0KSMPIK
         mr+KPBlbu2L6nDukqnscPtQPAyH9OVUjKmZ2DR31felaMzjmhzsh++Kv+Ia82WTFKSHS
         v52zKSnY3dYHuXMCd8w8lPFv7RccvJI0uLZXiblnJ0CpBFBG05EZa3VzO4iU19QKo0Dq
         o3nRs/nJjUk0I7SB0r5d1dwLFjJ88NGXE2L2uqDJIp6/QOf/lUS8NLcCZSFC9rj5PsiT
         p93Nx5Z8iFkQdRI+0aONtdT3s9uf6m1pnKmA+amzNrWpQqYuNrPcjipSfYeiU0dPiJ6f
         xYJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxdHFqjvE1e0XiNSST1lm9XNyRadorgtcy2JSzF1k1DK9qrBZqA
	LL/kZvPH51V9SxbpoaplIY8=
X-Google-Smtp-Source: AGHT+IFPqHTNVkT9HSYwJr+KprTDqEyc0xPkC/niARVz8Ksa1bMs0mg9rJSa6GvvdgzW+AP9qxPAcQ==
X-Received: by 2002:a05:622a:1ca:b0:41c:dbd9:ad3e with SMTP id t10-20020a05622a01ca00b0041cdbd9ad3emr1299765qtw.57.1699935104092;
        Mon, 13 Nov 2023 20:11:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5a84:0:b0:41c:c87e:86cf with SMTP id c4-20020ac85a84000000b0041cc87e86cfls1242274qtc.1.-pod-prod-04-us;
 Mon, 13 Nov 2023 20:11:43 -0800 (PST)
X-Received: by 2002:a05:620a:640e:b0:76c:8d5f:5954 with SMTP id pz14-20020a05620a640e00b0076c8d5f5954mr1428312qkn.70.1699935103321;
        Mon, 13 Nov 2023 20:11:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699935103; cv=none;
        d=google.com; s=arc-20160816;
        b=CL3lvk9S7EYa3Ebqtqhwhl7IZ8/cA998R+E2CEu/1FCe41exghzkKsV1hdUYUu9d7L
         uuPOOHZ/HS6gGunj1METTYbsFEtnA4gE1Boywrhqea6vq/ZMqG+9PYhlVF9wip32lQ5c
         x5cI5On62/phiHmgwO4J17DSjcb78uJqnc1vIfxKkOzRoGzdy5s9K+Xb7AT/JEemqrYG
         sVTsade5BcuQYtPFcx22VyjosDQ25F/PylbqdhtN6fBjNUIEwdbn9Gaqhg1i+ZsTD1q8
         ZfnI/DL4oCzf+DTtWLnFzTeCly+FgFUAz0CrIoQHsExEyR2eKDfNk+c6Rwqd5YXKnf0O
         JJwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=n+4yq4rGlFBGUUVelo6loa8LJ3whEhAhDSYlb9+Og4U=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=ENZP+ockd4VzBqTe7B5ncNsHx/mAuVaU19S30o5r1DmYKC5cgwadegZlEJCZawz1fY
         Vg1a/08SaXGzGS5AalxiIHOKCjMzS9WgEVxx7WLxiXTyf31VmWk9RibOVIrGCSsz5/5R
         DjSYLrzNnWaYxF3KwCHQZzcoQPUozoUcnj5YWmN/MEQzLsHqk8PJ8S60CXMNSVohXfsn
         n49abzyMFx8TI+lC6Rv2AenLnCM8ddCeD3dm4804xUZAxQjxx0EJ/8nhGn+hVWkfOI6L
         63yaXCe3/uF9X0ybwBiER7tEyUMCz+w/XCTL1ez5RletaFe0+eYhCUdsNCd0mUGeoJA1
         St+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=REGDi01Q;
       spf=pass (google.com: domain of keescook@chromium.org designates 2001:4860:4864:20::2d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-oa1-x2d.google.com (mail-oa1-x2d.google.com. [2001:4860:4864:20::2d])
        by gmr-mx.google.com with ESMTPS id f20-20020a05620a15b400b007776e0097cdsi495281qkk.0.2023.11.13.20.11.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:11:43 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2001:4860:4864:20::2d as permitted sender) client-ip=2001:4860:4864:20::2d;
Received: by mail-oa1-x2d.google.com with SMTP id 586e51a60fabf-1ef370c2e12so3141880fac.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:11:43 -0800 (PST)
X-Received: by 2002:a05:6870:b155:b0:1ef:62fc:d51c with SMTP id a21-20020a056870b15500b001ef62fcd51cmr10394447oal.51.1699935102819;
        Mon, 13 Nov 2023 20:11:42 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id fz10-20020a17090b024a00b00268b439a0cbsm4292411pjb.23.2023.11.13.20.11.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:11:42 -0800 (PST)
Date: Mon, 13 Nov 2023 20:11:41 -0800
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
Subject: Re: [PATCH 01/20] mm/slab: remove CONFIG_SLAB from all Kconfig and
 Makefile
Message-ID: <202311132009.8329C2F5D@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-23-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-23-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=REGDi01Q;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2001:4860:4864:20::2d
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

On Mon, Nov 13, 2023 at 08:13:42PM +0100, Vlastimil Babka wrote:
> Remove CONFIG_SLAB, CONFIG_DEBUG_SLAB, CONFIG_SLAB_DEPRECATED and
> everything in Kconfig files and mm/Makefile that depends on those. Since
> SLUB is the only remaining allocator, remove the allocator choice, make
> CONFIG_SLUB a "def_bool y" for now and remove all explicit dependencies
> on SLUB as it's now always enabled.
> 
> Everything under #ifdef CONFIG_SLAB, and mm/slab.c is now dead code, all
> code under #ifdef CONFIG_SLUB is now always compiled.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> [...]
> diff --git a/mm/Kconfig b/mm/Kconfig
> index 89971a894b60..766aa8f8e553 100644
> --- a/mm/Kconfig
> +++ b/mm/Kconfig
> @@ -228,47 +228,12 @@ config ZSMALLOC_CHAIN_SIZE
>  
>  menu "SLAB allocator options"

Should this be "Slab allocator options" ? (I've always understood
"slab" to mean the general idea, and "SLAB" to mean the particular
implementation.

Regardless:

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132009.8329C2F5D%40keescook.
