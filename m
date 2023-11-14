Return-Path: <kasan-dev+bncBCF5XGNWYQBRBOPQZOVAMGQEN4KESJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C862C7EA987
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:31:54 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6716c2696c7sf10862006d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:31:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699936313; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mm1UmEUYhFZl2Vj0eI0zD9H8rZPKFB91ufgmrT36jg7jvvWZablh2AX3TjANKfqWGW
         Jkjr/bco9j8uJ9DjI2Yor8M/MY2aNAE4zy8E6owed+4htAP+ZolLEH36CgyhGPh/sbF+
         CqAuqBuvbTUQIwkujpLJ3uJblUtxDtDROuinbDzoUeFbrR1iCfcOUynDqMW7ggzDDM9s
         fFxh7C4h6igH2sEzYmTPRJ1Voeuleqf+ZRzU9VEFGMycrvN7zNL4TVxBpSWd0weHcGr4
         X/4lJuZ1qP18B0zNkzGMv+uAW3s6yyCg/6ZHxNOBHo6MA8QpLfCLZfY0lIuP9oaa0wVD
         9SAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0w6B902HMAcIqUkSfmmbXmbZeIaYX+sqqpZkCYp/uvI=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=eCLed8hMIk9hytpdd8qEhtJLVRbFjrz0aVYi/bARyt3RJAsJdBl5MHkBcfTe6xA49+
         HyDamOWTdvVJIVSluWoejZRbA8wCHI9be5wzyz7uZBwZ6iQ35szNxjTAPyDtW8Sxw/m0
         FktE8OWmCN3wEIqt5cJ00a2X1nWTfcirnKIIL08T8RqaPXCA/2Got5R+EFYw+UVaB+Ny
         qslsAmIulPnobliN3ssglclUuQwn/BhlQsTqTq9pKwaO4de4/N63Fh2/B8FUwOkHoB81
         zbEbwn5GIW1pLhqW5xWBmflhT6aYMyj324ETXUxlJ7RzVSwR+M46xFUGbNJDpm9ZLHcK
         oxNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=RMHCFMLU;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699936313; x=1700541113; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0w6B902HMAcIqUkSfmmbXmbZeIaYX+sqqpZkCYp/uvI=;
        b=FgUy+q7YMTVYRxqok/RpnguUPGFPnz+ZKi3ClAp80undcIkNVdLCNp8YFg2SlicIJI
         mI0Ln4cYj210CZrEuT+98Tmx+UFiyT+pwbtZpnYc2eSQr1cV48V22IUN8qZZGy/DKgYy
         SHYvaLoYFdFap26+KJl4lhfivPIiOw3DzdvizhGM5Xx75Ub89VLC7Fo4ydkJ8Hu/NIwo
         QlfGH/Yctat4Q/8Ue8z9fG6ijij4xGacC5algDZtc5IR/x5aS5kEqoDGvqns/iWndRCD
         M+d//+zYhfSxENeKL6SJcoWKQh8V5MSVMzr5Yc1mrTSxIHNJZ1CR4L4UCOXE4wmoeI3y
         UaIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699936313; x=1700541113;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0w6B902HMAcIqUkSfmmbXmbZeIaYX+sqqpZkCYp/uvI=;
        b=GEaFerc9wgQYj1vPtivwURehIvRmTDY+oIltyMoUAq9ONYMEMaHWYnuChwLMQeg+he
         m6I76DB/kFo9fjc0dHQ4CqNQASxH6GynqqgmrP29yOHl5qN417ATil0ha5PCCMlF2C3z
         aBaPFJaTq8TwugTpN9usqwEndU7fW08koa7LfdIzm7oesATYJGv0iFV4E59QuGbemQie
         hKQtw9y9httqV5ONoIImssVA0MXv0QV3PpAHvaReiAUcIff0vaFiTundpmrcJPT6Dcts
         lzchHaI5OGf3b74OwY0s3aWC1rA6ysDI25F3UQS/T5M5wFafF+0TWDvZ9/NL6vcTXUXt
         7hwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzHvtG9pscADARkVErulNe94RwRsJQ2CJ3AFbJnUrJyL7DL/DDa
	kBfdh5AQJ0RUzcMYLoKrEEc=
X-Google-Smtp-Source: AGHT+IGRVIB/IrM/YXtnOuTmXx8HYSlMlEnodmPRsZMdudreHhpZBrlGy6HMhT7f6Xirjh/9wYQjpg==
X-Received: by 2002:a05:6214:5ec5:b0:66d:1178:8729 with SMTP id mn5-20020a0562145ec500b0066d11788729mr1336907qvb.0.1699936313390;
        Mon, 13 Nov 2023 20:31:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:14e5:b0:66d:6af7:454e with SMTP id
 k5-20020a05621414e500b0066d6af7454els1799189qvw.1.-pod-prod-06-us; Mon, 13
 Nov 2023 20:31:52 -0800 (PST)
X-Received: by 2002:a67:c196:0:b0:45d:9a4d:dc1b with SMTP id h22-20020a67c196000000b0045d9a4ddc1bmr7870699vsj.3.1699936312630;
        Mon, 13 Nov 2023 20:31:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699936312; cv=none;
        d=google.com; s=arc-20160816;
        b=QFHVCN26QF1Rll+k1ckTotY1FljfHv7g182gre/3ss/a7BYdGyds3pqYuotI9ecNKz
         6iFgRaFiJ3AqBpld4S5TtdSvZj/fkCH1eMWLT3lO2/a4Z7xb/yz3xhaCnT/6FRomN/Ql
         MGkUMnox0QKANfz/ytphlGW0sN3xiS0389k8gnrpeM/uJ1oaxlchwB0E21nkKsYda1gw
         roY9pN88pKzfymRFjMzlg/mEleSgtTj5VOGjzoEYzrVV8W3Ye/iNh5Yqs1ctWfYnyPeX
         o5qFL8rpUKA6dB8GAYkSJfVmNKr0gaGg2ZTUBgBCNZ3sDaqfD3i93ztaPjp9GI/6eSJS
         eQzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=VRGeaFnyf6oFg3w2q7Y0wKf4gObnq/HsTjuQwLGdqK8=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=JhfvKJWIc+R+xqiZvVItHzU+YAjq7Z5N5+x9t09oWvYq77luw5bYKIoPoiF1XS2yny
         f4uBRwU3DBGmupXPJ7QPOZ3/NRiOSSWRFDa1h/+SdCQ2upTrRI0jieBegnLflnZEElO2
         y+HdIRC3fichv3jyX1rvK3s3SPvhuwe/JMn/sB5/QZngZ0sqt6ERBiXj0GvjBfMdb4kb
         kMQ+Sp7RzOwc+e7+6LHk5a2IfBjfHDh/Z97N9vCETxzvo+hgJCiODcQM4ewKONqd3C3A
         BfrBwF3K/kGLtrfGvSeXhG65IbvqtOh9ok6Hbwf4oYIpXUbLPLIyLsIwY+3223FsWhLu
         vPIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=RMHCFMLU;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id y5-20020ab07d05000000b007bfc3296157si578521uaw.1.2023.11.13.20.31.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:31:52 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-1cc5b705769so47246915ad.0
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:31:52 -0800 (PST)
X-Received: by 2002:a17:903:2a8c:b0:1ce:8e4:111 with SMTP id lv12-20020a1709032a8c00b001ce08e40111mr1701477plb.27.1699936312112;
        Mon, 13 Nov 2023 20:31:52 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id u1-20020a170902bf4100b001bb9d6b1baasm4768235pls.198.2023.11.13.20.31.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:31:51 -0800 (PST)
Date: Mon, 13 Nov 2023 20:31:51 -0800
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
Subject: Re: [PATCH 07/20] mm/mempool/dmapool: remove CONFIG_DEBUG_SLAB ifdefs
Message-ID: <202311132030.1B2302BA4@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-29-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-29-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=RMHCFMLU;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636
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

On Mon, Nov 13, 2023 at 08:13:48PM +0100, Vlastimil Babka wrote:
> CONFIG_DEBUG_SLAB is going away with CONFIG_SLAB, so remove dead ifdefs
> in mempool and dmapool code.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/dmapool.c | 2 +-
>  mm/mempool.c | 6 +++---
>  2 files changed, 4 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/dmapool.c b/mm/dmapool.c
> index a151a21e571b..f0bfc6c490f4 100644
> --- a/mm/dmapool.c
> +++ b/mm/dmapool.c
> @@ -36,7 +36,7 @@
>  #include <linux/types.h>
>  #include <linux/wait.h>
>  
> -#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_SLUB_DEBUG_ON)
> +#ifdef CONFIG_SLUB_DEBUG_ON
>  #define DMAPOOL_DEBUG 1
>  #endif
>  
> diff --git a/mm/mempool.c b/mm/mempool.c
> index 734bcf5afbb7..62dcbeb4c2a9 100644
> --- a/mm/mempool.c
> +++ b/mm/mempool.c
> @@ -20,7 +20,7 @@
>  #include <linux/writeback.h>
>  #include "slab.h"
>  
> -#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_SLUB_DEBUG_ON)
> +#ifdef CONFIG_SLUB_DEBUG_ON
>  static void poison_error(mempool_t *pool, void *element, size_t size,
>  			 size_t byte)
>  {
> @@ -95,14 +95,14 @@ static void poison_element(mempool_t *pool, void *element)
>  		kunmap_atomic(addr);
>  	}
>  }
> -#else /* CONFIG_DEBUG_SLAB || CONFIG_SLUB_DEBUG_ON */
> +#else /* CONFIG_SLUB_DEBUG_ON */
>  static inline void check_element(mempool_t *pool, void *element)
>  {
>  }
>  static inline void poison_element(mempool_t *pool, void *element)
>  {
>  }
> -#endif /* CONFIG_DEBUG_SLAB || CONFIG_SLUB_DEBUG_ON */
> +#endif /*CONFIG_SLUB_DEBUG_ON */

nit: space after "*"

With that fixed:

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132030.1B2302BA4%40keescook.
