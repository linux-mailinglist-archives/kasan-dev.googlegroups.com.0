Return-Path: <kasan-dev+bncBCF5XGNWYQBRBV7PZOVAMGQEB3QYOFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 034E17EA982
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:30:16 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-7a9764cbb95sf527390639f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:30:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699936215; cv=pass;
        d=google.com; s=arc-20160816;
        b=wG2ScUFkBBHomtXzRASekboDU+AU0En+SjlZGPxnZn0hasv3t40TkpnNgZiwQDHOsc
         H+OZqLSCzwhp7A3o/r7xCC0x11tuws6TVzXr34I2wjKA/0vJ3cmZZ7cmVYsgmqUc6mYe
         2WxpiLaOS2CDoUd6YOKF/yt4tUy7kCHOXcae3paTT66PRwrcWmzxmVpUXS5XzI7SkkZK
         z6/zedSKP7fQILpCy2X/F+D0VPgpit+wvxYIKpAdr9L43daDv2LTX/MUTRfS1naI6xik
         BjCzo3rEc+/GDoes2vw5IBsvapkM8yUzZK8beQgVa3vQdsQ96WX22I6t2A5JY7ESVhNP
         HanA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=j40S59wIBGpt/IQkLc8uR+dI9tsq4AmcvEx+5HzPYvA=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=H12JGB00MFpsGJaa9wlC4lhLovW3tvux1+tOWifzlPEIKXovexXo3K9uWIjDgE1cE1
         KORwlKM39MP8L81k+q/LWPq85vYp7o+/+iZc0vv38eO4mL/tmh+6Q2nhCfyf+AVTXCIn
         hKSmTshSd9AHLi+rhPMVuvw8ymPSXQ7tiT26KxPBg4awS/tr9Y/sJatKmU5MQiH94b+L
         JYhX1lAJPS6bg/WDKvzdSctntCr+LEC/vbPXyZTDKulwxlN1j9iGqLAPmMASaCJqRrzF
         Kyr0A7FdWgMH9DyhluyJnqAZMRFLtopjG9aXg02Vhhuq9VNlvpOIbIcscmUu8jt739o8
         yFcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=N35IkwxF;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699936215; x=1700541015; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=j40S59wIBGpt/IQkLc8uR+dI9tsq4AmcvEx+5HzPYvA=;
        b=wVI76iJ8ScAxozqVkuk+nvTTJ9rwimX/RxeYWwoXIPml4AjUojwNAv6TtXRGocyArz
         FSYa2g6cSOKur9UbYT6NNO/ppqUBM8+Ntj9aDSu/O8m0+0BbCropptb/MbkeZWsF7kjW
         4czrP/l0WLVqAae6RPUWc6peSCy5KIBGl6zsYhbTNL2Ev9CzNFEfTNd/GqXiM/K/W+S9
         P67t+e7GEzIRBWRz23A2cKuxoxXt23mOicw8hXZUPYHh7MRlFxw1x7DLONS8ZwokJLLL
         Sxc4XBC2xgMhQoQ2wSd0+jUxOvJcgeLlaIYTfKT2M1km/X24BKlk6fziPi9qnMXJt+/g
         LvTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699936215; x=1700541015;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=j40S59wIBGpt/IQkLc8uR+dI9tsq4AmcvEx+5HzPYvA=;
        b=NI1/zHo62HwqMCvEiLOd2tzJrTtdVBoFgsEE+/XgttB4iHuZwLv9JUxd/L3rbifBI9
         Fpm/WkV4rRut1vQSDPZ6rUC7CoUP2IYahkJrynDCIZkPi4EnWjPYK8fr22C7GW3ZwzXC
         1J0ljolLkiqfa57ZnBHFVKt6Vq4OyiOF+zmAM96rS2BIGts+I218yHItqbfx2v1nYpKP
         t/AwHMJusuJpHKcpv0vu1c6nkHTkwff0WG/Zmbbmxwd6zHIBzHf+rgPVlSOt+yiuqbpV
         qnZb9s6JEV6JVVCJySCKYGUUkOTRwdT22aHPHaoiyRtAKIk3icuaofK6JOjl9ImGAfqY
         /KtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyqL2qaSjuVrrbh2joQPVkbJVYQTIaI9Cyqp1pDTUxjR+5rDFKY
	YlUKWxVbK0EkMZ3f7t5gEnM=
X-Google-Smtp-Source: AGHT+IEZ0nwm578BzmppU0kmyfuqnjP3gpnGGPXySpQFZF1lMwEmk8y6Y1SGjF37SX5KEFDvW847Dw==
X-Received: by 2002:a92:c242:0:b0:34f:d1bc:c47c with SMTP id k2-20020a92c242000000b0034fd1bcc47cmr12674995ilo.22.1699936215405;
        Mon, 13 Nov 2023 20:30:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:23c7:b0:348:81c5:d1cf with SMTP id
 br7-20020a056e0223c700b0034881c5d1cfls265979ilb.1.-pod-prod-06-us; Mon, 13
 Nov 2023 20:30:14 -0800 (PST)
X-Received: by 2002:a92:c544:0:b0:359:4223:5731 with SMTP id a4-20020a92c544000000b0035942235731mr10878706ilj.30.1699936214726;
        Mon, 13 Nov 2023 20:30:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699936214; cv=none;
        d=google.com; s=arc-20160816;
        b=g8BCEOJxo0JWlemAPj1LniSci0cvaQ1sRzoEHd4pQyo1JZ4HYxDtL4Atafc4WPDYc3
         eWQS8gj6OJhLMcPY+Sfvm08q2mr2Rehl5eAcz6NXCEg/0d8+oghWhD8y5nc5t+meQiEs
         evqkxu9E6IwhDHulpIa47oTw6u6iV37PxXbOJEy54fx5eiKS0Etjm2CHuN6SJQVj+DSz
         DWOoF8EANPZ6VXvDLeUGLA/J6CsoYAvGW6/ClPLpo5eE+2cHS+NfLnwqbnL1b9/UfNsv
         wfxOpTbtAX5jjy+/6ZsDJKfx39q7haSGe3GLnn/J111qWhOc8sjUY0udstf9QcG10PW9
         hCOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BVR/Ivq5aw+9huCWfoclhyK6Cz1m1uGsfFPrSjVP+os=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=TzwxD51X12Vn0iLULIlwZoVVs7kL7+lLZomGDikx6NPsiqLRNtt4pQANjeCbk5EKcP
         tDO0hrOVGqKs3/5sPCsk/POv8xoW6WhORp1mPRBWUj26Hxu5nV0l6fhg2OtBbk12EN0z
         f+cv1aTwlL4RiaBcIh7kdkSb7eNEzW1wZeoiNdevLfnElu+0VYh/OkUWfplq2s5rMlOq
         NmfudXXiXy5J8kdeE/W/OianqKwkmfgv2b77sTtwwYlEZVzAN33xdaWBpjtqXUu6MXh2
         5i/hjfxy1pVAX7IdekQgwrphcfFFaughiWxZzuny2Jfv0u13c0VI3T8LNPBMYihib0w6
         1fUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=N35IkwxF;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id bp13-20020a056e02348d00b0035ab283d159si632526ilb.1.2023.11.13.20.30.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:30:14 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-27ddc1b1652so4698442a91.2
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:30:14 -0800 (PST)
X-Received: by 2002:a17:90b:1d06:b0:280:2823:6615 with SMTP id on6-20020a17090b1d0600b0028028236615mr8237152pjb.36.1699936214292;
        Mon, 13 Nov 2023 20:30:14 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id l24-20020a17090aec1800b00280fcbbe774sm4405770pjy.10.2023.11.13.20.30.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:30:13 -0800 (PST)
Date: Mon, 13 Nov 2023 20:30:13 -0800
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
Subject: Re: [PATCH 06/20] mm/slab: remove CONFIG_SLAB code from slab common
 code
Message-ID: <202311132024.80A0D5D58@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-28-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-28-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=N35IkwxF;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1034
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

On Mon, Nov 13, 2023 at 08:13:47PM +0100, Vlastimil Babka wrote:
> In slab_common.c and slab.h headers, we can now remove all code behind
> CONFIG_SLAB and CONFIG_DEBUG_SLAB ifdefs, and remove all CONFIG_SLUB
> ifdefs.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  include/linux/slab.h | 13 +--------
>  mm/slab.h            | 69 ++++----------------------------------------
>  mm/slab_common.c     | 22 ++------------
>  3 files changed, 8 insertions(+), 96 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 34e43cddc520..90fb1f0d843a 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -24,7 +24,6 @@
>  
>  /*
>   * Flags to pass to kmem_cache_create().
> - * The ones marked DEBUG are only valid if CONFIG_DEBUG_SLAB is set.

I think this comment was wrong, yes? i.e. the "DEBUG" flags are also
used in SLUB?

Regardless:

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132024.80A0D5D58%40keescook.
