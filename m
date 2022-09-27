Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7XNZOMQMGQE2OA6C7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id DDC5B5EC3E5
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 15:13:35 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id y1-20020a2e3201000000b0026c3cb4c13bsf2580613ljy.11
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 06:13:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664284415; cv=pass;
        d=google.com; s=arc-20160816;
        b=vm2+chUA0WOgaUfPv6kCqJ0DbrBBwy1dDtRU9LghnA1ODulfunIXrPyz5/BQ8iVGZr
         4eLDeBZil3usaMq4+EtdH6LiMnC7kCYFL22L4W6LEvkSs6PVtgWfpLcNmIn/vL8+0+HG
         LmcuLoJ4Iedo9clJYapXAnUxRojkvgS5dOM+stS/2ejgBmgumkbnbVfdRKm1xncFPCr3
         DbxZLoEkM9hMhEcsyeVAxsizDg9o6dj+RrO5wc6EyCXE9+rQfIDZgiw0sKgmCy4VR8wn
         7wcGQihduKKxON575YrLJekNXEHegSM9VWhQnhSrNnMACeKOTkMbZJbXz9WZGjbeuiua
         9Mng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=SYAXV05bOzWrMGHcD5MWZurdZMs5JBeLycXlqtajYxk=;
        b=N/HBB7kdZCYwrA4mYmgKpxvcNor+mJhleaV1d0G5K/qv8/Ixy+gSXXYz18HMDRrs7R
         Y5+jajw/IwNO7dyPkSxfATJDFt/X5KQOhB+hcpud7aiInbtkXmRT/VLHEArg0s9imX8O
         CyxyWJQC4pYy25ftqGY+30Kx+8qJ7dRQKQdsvUavRpQMITNuL7LAQ33ROSJliOig9i9F
         e6qhNJeqdD64dcp/3Sgsu364f8V64qv5F8kTdStZMhsnPWek6ZJ+8Lq2stNn69P19olA
         +srO1zBAHmPjLYFVmLjgZ52b/+ifd11i2Q+Q8estnTX++qgUyKdMrtta9aaUVfRa2atd
         2Elw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QCzn9+LB;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date;
        bh=SYAXV05bOzWrMGHcD5MWZurdZMs5JBeLycXlqtajYxk=;
        b=TRtJPIAC/jLUTJQjSEPYT8YjSTL7kEJKY8KPCzZD1LPYn5S8eVG7Hges+GqWy48Nu9
         rCwdQTVOp5Q/Z4FPUeWtIcLGdJnCBrwBmAomL8sPe5HViL39MvdsQZY41nNO9iYSub6P
         J4YOFZynzkqhPy9grumq9N1YgUddPUDrRlfNEfX6Ifbxspb5uQp1mijBKJPXwKbssC8z
         SV6cWYeXUeRWPRqtToZxOGlTRGW4FkVaA/xKemrrxbq0at9Eq4UNoHgJmFMRF/vdChPy
         CHTBRFcB0AWE6Cwg7vf7KYZdwAqXSUCgD754oD7cATLg2DLzXXrBiuXj7780iLtm+iQm
         AQaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=SYAXV05bOzWrMGHcD5MWZurdZMs5JBeLycXlqtajYxk=;
        b=l3NqBxBqqFcwWMkt7pXZyVjKIJf7rTpp+UwjAIvPzD1ni8GFRhhHE+c2AI5eF6GJP+
         CKm1bQxlyoH0rSZ7ouFp5JMHmYoNIUYm0h3v2YMEVVnW/6w27zlFQTwkgtDSS9BYVYzd
         y52Ihm/ijVrIBC8NAdhf7DigZHz/2txDjIC8MRaKtuhTf+DUaHdDySJeFdHkwSeGYDLN
         6U77hAlYHEL4uCW7ylHStcPCQ1VjoRAM6LZovgIerIfRLuLrOkgqLp8MEkjUuocrQVdG
         B+oD5rGMBqsaqxonk5ZaIInEcRGIZDuXtw+1tWA1eAu7NSzFKJ7lhlQeqVVfBXhnQn23
         l3Ow==
X-Gm-Message-State: ACrzQf13vEfS+wlixizWisU+njsL2c19ZRyblLm7V38yzR+pcbkIXpAp
	ZHpr2khrgmPSOmjBbM/7dj0=
X-Google-Smtp-Source: AMsMyM7AfeXFVq9n+LqjqmVXa6Usc10yca3fR4WixvCmQDksiboUczHLH/HkDQMqT9VbZyeDHQWX7w==
X-Received: by 2002:a2e:a448:0:b0:262:f7c4:31ad with SMTP id v8-20020a2ea448000000b00262f7c431admr9430105ljn.283.1664284415106;
        Tue, 27 Sep 2022 06:13:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:118e:b0:49a:b814:856d with SMTP id
 g14-20020a056512118e00b0049ab814856dls787804lfr.1.-pod-prod-gmail; Tue, 27
 Sep 2022 06:13:33 -0700 (PDT)
X-Received: by 2002:a19:e050:0:b0:49f:5464:71d3 with SMTP id g16-20020a19e050000000b0049f546471d3mr11959721lfj.558.1664284413676;
        Tue, 27 Sep 2022 06:13:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664284413; cv=none;
        d=google.com; s=arc-20160816;
        b=K76XVf/SegrNqOHCK6g5zoAYJr+Uo3CzUqEdfBIRZOPouaLy3zadTad1Aw895X5nDH
         z4Kpe/Ao/vus1AcurtyuLoWrvawm58zPsmm4PvYQPFfG2/jsxm+IDQ0BVRk4VEkSZgHY
         9CPZkn0d1Y7x23N07NOUCVm4pJYSjKbseSytD4qWV2XjXmntFmfriqNvsydLmDwIax32
         N3fKmw4U1O5N2xFUkas+XQnbta7aw0tY36QzN3EsMmpbGjqsnM04ZaywTw5Zqf8waks+
         AJ6CJzkXv4dvH2pZDRc9n0+I24WfNCsgGy8LkHwdZKB7PT0uslofyaRNIqh47mgtDmTa
         V7Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xKQUJ8crDSiafngxlHWxH3oZauT5Eq9qaoxq/VTtdws=;
        b=iP+qavyfUxjwK4Z5mzptcUmiop77aix+OsFShffLAg2fr7Ae8Nlq2tjrYaeKP5XFRl
         HerI+TMWRbU+825TdQr76v0nJJqGGfuiW5K7QbBdHmkeKG2ChV61uBk6zQOlDVPWGyrO
         Ca5iNY4DC6Xkj8XWL9m2ApZIdGkmLPGfiIJgarjn4EOzavT2DK0Qwu8HPMbvZ/LfX2Bx
         Asss/vGX8fdAXsdqLS1gsxRoU0hOctgPe3jLxgo/y/++BOHDIEmz3hICfw0Jm1LBfNbD
         zmS4vndkml2qZTHK/YfKJzcX4mg8C0IMaLL+QQi4bClOZcX7o3Bb/magaNLT9kijNkF6
         OfTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QCzn9+LB;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62c.google.com (mail-ej1-x62c.google.com. [2a00:1450:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id be41-20020a056512252900b0048b12871da5si61301lfb.4.2022.09.27.06.13.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Sep 2022 06:13:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62c as permitted sender) client-ip=2a00:1450:4864:20::62c;
Received: by mail-ej1-x62c.google.com with SMTP id nb11so20600515ejc.5
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 06:13:33 -0700 (PDT)
X-Received: by 2002:a17:906:8473:b0:77b:efa8:50e4 with SMTP id hx19-20020a170906847300b0077befa850e4mr22495363ejc.250.1664284412975;
        Tue, 27 Sep 2022 06:13:32 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:693c:15a1:a531:bb4e])
        by smtp.gmail.com with ESMTPSA id u24-20020a056402065800b004571907240asm1265720edx.36.2022.09.27.06.13.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Sep 2022 06:13:32 -0700 (PDT)
Date: Tue, 27 Sep 2022 15:13:25 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm 1/3] kasan: switch kunit tests to console tracepoints
Message-ID: <YzL29buAUPzOa9CG@elver.google.com>
References: <653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QCzn9+LB;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62c as
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

On Sat, Sep 24, 2022 at 08:31PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Switch KUnit-compatible KASAN tests from using per-task KUnit resources
> to console tracepoints.
> 
> This allows for two things:
> 
> 1. Migrating tests that trigger a KASAN report in the context of a task
>    other than current to KUnit framework.
>    This is implemented in the patches that follow.
> 
> 2. Parsing and matching the contents of KASAN reports.
>    This is not yet implemented.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/Kconfig.kasan     |  2 +-
>  mm/kasan/kasan_test.c | 85 +++++++++++++++++++++++++++++++------------
>  mm/kasan/report.c     | 31 ----------------
>  3 files changed, 63 insertions(+), 55 deletions(-)
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index ca09b1cf8ee9..ba5b27962c34 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -181,7 +181,7 @@ config KASAN_VMALLOC
>  
>  config KASAN_KUNIT_TEST
>  	tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
> -	depends on KASAN && KUNIT
> +	depends on KASAN && KUNIT && TRACEPOINTS
>  	default KUNIT_ALL_TESTS
>  	help
>  	  A KUnit-based KASAN test suite. Triggers different kinds of
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index f25692def781..3a2886f85e69 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -5,8 +5,12 @@
>   * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
>   */
>  
> +#define pr_fmt(fmt) "kasan_test: " fmt
> +
> +#include <kunit/test.h>
>  #include <linux/bitops.h>
>  #include <linux/delay.h>
> +#include <linux/io.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
>  #include <linux/mm.h>
> @@ -14,21 +18,28 @@
>  #include <linux/module.h>
>  #include <linux/printk.h>
>  #include <linux/random.h>
> +#include <linux/set_memory.h>
>  #include <linux/slab.h>
>  #include <linux/string.h>
> +#include <linux/tracepoint.h>
>  #include <linux/uaccess.h>
> -#include <linux/io.h>
>  #include <linux/vmalloc.h>
> -#include <linux/set_memory.h>
> +#include <trace/events/printk.h>
>  
>  #include <asm/page.h>
>  
> -#include <kunit/test.h>
> -
>  #include "kasan.h"
>  
>  #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
>  
> +static bool multishot;
> +
> +/* Fields set based on lines observed in the console. */
> +static struct {
> +	bool report_found;
> +	bool async_fault;
> +} test_status;
> +
>  /*
>   * Some tests use these global variables to store return values from function
>   * calls that could otherwise be eliminated by the compiler as dead code.
> @@ -36,35 +47,61 @@
>  void *kasan_ptr_result;
>  int kasan_int_result;
>  
> -static struct kunit_resource resource;
> -static struct kunit_kasan_status test_status;

Also remove this struct from kasan.h?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzL29buAUPzOa9CG%40elver.google.com.
