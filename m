Return-Path: <kasan-dev+bncBCF5XGNWYQBRB77UZOVAMGQEDQGOVQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 56D867EA9AD
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 05:41:37 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id 71dfb90a1353d-4ac08359d7asf1630640e0c.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:41:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699936896; cv=pass;
        d=google.com; s=arc-20160816;
        b=sfGMa3xdpzK2VQUQ5NxBdlrT8DW+3EWTe227UgOT7Dj7SrbYx92+icJVR1D3uwjd/i
         xgUUKagtsbQhFVs62Q2Uy27BwrLQUuprYnP1K9iVraDHgbvaiyEXWxc31Qx98EPJSAOs
         r58EsngW7s7+L5beUTJeIp1TmgmSNJxltNGoq17uXzDcjQaJ9fvCljV7WmOC8J5xncbT
         AxzfR+KkkB+4P3NTa2TAmg8602gpl6dCPNNatIaTJHAPr8yW7Md0GQnO73iR5T5kJF4B
         +gILB8yUdR+y2f6g0quaUWQ+Tb0zs4a2myBI4xEOw6qwdBx7PAKr3TnrKFBSGIeGXSEo
         +5mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CEPVClp8G7m8JjXX447CSW/5VchyZ/3BSpjxu/va6fE=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=K5zArCW5KRAVPfkHgfHcPKqhqgRvgK4U+PKRcg7iiir1taa0vFYeyDJHL+YTkGq0dk
         y54tyZCLAC0p9qo5UhapBif5ObLD0ecYpb/3rLXWjpLgtKzNQk8+RHbbbWc1dGf6OVSE
         CqEs40eH5afaXzkx1ooK0za8iLOQEoBM+aD3LkxdhDJgm0j8PL23chKP6yJAfRUGj34c
         HEFPaOMOi0TuN3NaHcIZeUOz5sDlAZ+N+de2yOUm9gmBadpyuX7yrcmEZRu3KpWsxLU+
         Ar666JcleeC6DUdaTQm9frQ6X0Kq18HAF3x09bLePsJX7t+3Q0PVHs/8KQOLp+j80jlE
         f35A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ESu8Ytw1;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699936896; x=1700541696; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CEPVClp8G7m8JjXX447CSW/5VchyZ/3BSpjxu/va6fE=;
        b=xYtzIVe2mgtUJHC6MT/97yWDBdRlA91x2tSEi4C4LC1ZJA27HiDQjuw5QFY6rCt/w3
         vQI0ykjDVO6DBYaVN8Bis+L7QRVuAl/aU6cSLybwZEgdvFtbMcUZ2hxqXAdNNruQOxg2
         6aUR61VmzPKtAFrxew2FhdaJS/wtg+zJBaw7bIjpPDBbH8a8lTInhFxK6bzocD50MA4D
         MJ5yteMiNhuM7czpdQpamUFFGfMpGwOzJhJWTN0pX88/JyqNoImASCdb3lwchtZkL2cw
         QHLt7fJsrwhr4PiMLnT5gplS+CEjtozmmHEKl90FTnS4GE2vlKQGwXjfKmuiORXZE+CC
         vV3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699936896; x=1700541696;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CEPVClp8G7m8JjXX447CSW/5VchyZ/3BSpjxu/va6fE=;
        b=YE1okGmQRIxhpP2SKrRQMw4qqhW2S/NwOlEb4FN4CXoppM/AeyaHve49NRQCdwyNkP
         vpQgrWLtzcsyQSfoGMe/myioY9x9yA1QzM+wZyVHT4784eO+1N+/VFJBGZoNWeT16Tw3
         tofSmQtrn3u9Dr6MTh3i9MIr6ZD4cjsjo4EP7XdMJsECvTg1Fhln+fY99Cz63AasasxZ
         vjtudVei2txRhAwam3UhVfa/YkzhkZAQHfj9NBWAUuybs7D7mffiySzZ6/q1pNNQJXpN
         IQbtGmfKT3qSVesGlEzpG1WGhRB929FiLIe9cEcfn47z4TtZh9UYiX1+EtXw5jwer8cI
         RRxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yztq/Esjj++yUf//qWVMTtLWqzt95ExC8POKTeh0l241YqHpZbY
	J9lA6whfP4fOur+WJbRR0ZM=
X-Google-Smtp-Source: AGHT+IFlEEd5lmLY9/JRtaZjICyW4RkkgbSlljEHg0Fvrn8VzbdgRiT8QMka5UsI37wkX/7U1zBVqg==
X-Received: by 2002:a05:6122:1508:b0:495:bd61:a184 with SMTP id d8-20020a056122150800b00495bd61a184mr4519307vkq.2.1699936895979;
        Mon, 13 Nov 2023 20:41:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:d68d:0:b0:66d:9d16:5a4c with SMTP id k13-20020a0cd68d000000b0066d9d165a4cls1443758qvi.1.-pod-prod-03-us;
 Mon, 13 Nov 2023 20:41:34 -0800 (PST)
X-Received: by 2002:a05:6122:1055:b0:4ac:fd8:e8ae with SMTP id z21-20020a056122105500b004ac0fd8e8aemr4181730vkn.1.1699936894754;
        Mon, 13 Nov 2023 20:41:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699936894; cv=none;
        d=google.com; s=arc-20160816;
        b=ycnjp6ZZzbnGuBLHmTVs0vvensgxisQFwUZLGqz7IAlsTxAnA6JKEnbdSIgcJeQDVQ
         6ZM5RwWtrZBOhUrnTu6Gjji6iUQBu5y3wNH8mhxXiXSUhrfF1AVe6zIL5fwYOEbjVBca
         vcFOmlL58CYIjp/mxNp9ALH0EKPIcEpfZjI9Eh93TdgurPJ8BmQWM0R+mHCR0as4coiH
         +rviKhbZPHwNBAb8x5v0BOQYr/PYDLgSmlzfuRYzCK+pKb8OVxnzgaLF0bnFtpUjcis2
         8gpglndf58aU1G8Vns6sMiyOpR+Xv2gZE/gW9dcIhORJy3D4rasP+QO0sIMS0POOYlaL
         +qqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=eA82Hdspg/bY+CR7CFpsTdFZp4h7gtZ2SoVDA2UEAEM=;
        fh=1kL6YZIf4gCjZD/dUA6xgrhZxlE48Jm84GD32EC2Zms=;
        b=U7chckPmK553dQtWtaz2DD7d/qx+NP3IijAjZa2b2i/EinSGxq//HF9zyS1QjMJdiW
         9KTXIgRVpuxaAtKBqc064O5RYtq+F8Y7FkBZHQ4/1avhsSBoaPp3d/LVMNZhluzgHAKy
         BtmnPB+jNSZMyXx3a5yYa3w9n2IoAiu61Z5g6LrJ/x5Uzqz/44NhC8ZWvrvYp+Cdy6My
         faGnZkP8VZJb/Vj2Stp+6aY6J4P/OenPuAPvHI0xXdCRErsIMbBg+cT+hrhfazjiJxYl
         bjQ1Yzp6QJPoQ5iiDexsRRqRhmUXusDJ5wLteshwH9+lophdSRTcWtB00wwZz/XeHqGg
         7ZQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ESu8Ytw1;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id eg28-20020a056122489c00b004abe61eb6fdsi687449vkb.1.2023.11.13.20.41.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Nov 2023 20:41:34 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-6b1d1099a84so5232507b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 20:41:34 -0800 (PST)
X-Received: by 2002:a05:6a00:10c8:b0:6b8:a6d6:f51a with SMTP id d8-20020a056a0010c800b006b8a6d6f51amr9811289pfu.31.1699936893812;
        Mon, 13 Nov 2023 20:41:33 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id b13-20020a056a00114d00b006baa1cf561dsm395221pfm.0.2023.11.13.20.41.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 20:41:33 -0800 (PST)
Date: Mon, 13 Nov 2023 20:41:32 -0800
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
Subject: Re: [PATCH 11/20] mm/slab: consolidate includes in the internal
 mm/slab.h
Message-ID: <202311132039.7CC758A@keescook>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-33-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231113191340.17482-33-vbabka@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ESu8Ytw1;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e
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

On Mon, Nov 13, 2023 at 08:13:52PM +0100, Vlastimil Babka wrote:
> The #include's are scattered at several places of the file, but it does
> not seem this is needed to prevent any include loops (anymore?) so
> consolidate them at the top. Also move the misplaced kmem_cache_init()
> declaration away from the top.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h | 28 ++++++++++++++--------------
>  1 file changed, 14 insertions(+), 14 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 6e76216ac74e..c278f8b15251 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -1,10 +1,22 @@
>  /* SPDX-License-Identifier: GPL-2.0 */
>  #ifndef MM_SLAB_H
>  #define MM_SLAB_H
> +
> +#include <linux/reciprocal_div.h>
> +#include <linux/list_lru.h>
> +#include <linux/local_lock.h>
> +#include <linux/random.h>
> +#include <linux/kobject.h>
> +#include <linux/sched/mm.h>
> +#include <linux/memcontrol.h>
> +#include <linux/fault-inject.h>
> +#include <linux/kmemleak.h>
> +#include <linux/kfence.h>
> +#include <linux/kasan.h>

I've seen kernel code style in other places ask that includes be
organized alphabetically. Is the order here in this order for some
particular reason?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202311132039.7CC758A%40keescook.
