Return-Path: <kasan-dev+bncBDV2D5O34IDRBS7V66PAMGQE5KQBK4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0156B68A896
	for <lists+kasan-dev@lfdr.de>; Sat,  4 Feb 2023 07:27:24 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-16a0fafd9b7sf1154475fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Feb 2023 22:27:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675492043; cv=pass;
        d=google.com; s=arc-20160816;
        b=iVr5h8MxqIbA/doEV55qvzc3iJDBAjheCV2UEuvRjYNILTRPUAxWyj9iHLA6XPLsoy
         H3X4LhWEzc7iaVqaqUEPGMRw2UJcbWIgprmD30uX8QCu8foKs7Zgnlzg/2Idu7ltRbpG
         SHRd3cmVjX6h/IHpCj2myucfec4jAQRszdRtaiTdeGdjstLgwnhTS/VrvIb2piOdbnht
         P0QVkcKUWS26GFhKb4fBtMpoiWLqa/DmIu6mI+9ikZaZ2x5Rcax0xNKyV/pZ6LVrYfx6
         uVFkF2pPL3E+dyTQlvCqOAKpqAoJY1dHap9SY4YQgTn5MKXgCarOHUHyBDK8gklip5O0
         mDxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Lk4tHSq+xpmF0+iK26F9R1piUPPQE8WRxzS4/IRu/f4=;
        b=SWYpQoW6FfD6p03wdTI2CIgGYQi2/6rYor7JLtJRqMFXIwJOrNc8iBQokj9jbaZtsS
         sGiXgSQMoinUS/MJns8GT737Ktn2jFBlcQRoHqGjeoLlqhs/iOgm+XiRRInrXRTwbY0B
         EvSyw6SjKhl+h/vATFdQQcEZhPi4GBX+AjyLN+Gm/Dh7mwZtyEMb/cvZXauCItcvhvKe
         eT9RlUkP+vAM5y27ba8O6aX7sWPQ7lQ36+7bGFQEQsH2UJYLn7R6mpZeX4YviMumA3ar
         qGpiEf0Iwdme0sj6yYuknvkcQsj1uU7JUKtqiIm6afuK3NbEgyMjdEVdq1+8vz9JrMdZ
         GhKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=2YwQZp4m;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Lk4tHSq+xpmF0+iK26F9R1piUPPQE8WRxzS4/IRu/f4=;
        b=PG185qG9UIxxzETQ2Qp2UZS1a0EhUoiairaAmFcjOvCO5LFlVHXds6TQKhZb6BUB7U
         GeZbT8Bkyk+TdmTWQWb+eAc6tPHB52vKnXXqAK9a3ex08iPwQ5/l9rflDDjiXuzrFw+K
         dxUBRg8o2lvSaPMFHEtiLrvaRS48QuhJxee0XhL8sQ8+CUs9nx+8z4aiJO+TB3FSIzsJ
         75L51xNRGhjboMC0MBBuD44bQWYmZ5eyyFiVRn7flJoavcEZgYo4SLtzXRRJ2R/xmErj
         /MFSqrB2r8nmUzM0T2BVZtFi3sT4B8zE7coVoMf9URP7dSXTQ3Jv/HzCwFxxUlhAeGVh
         9+tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Lk4tHSq+xpmF0+iK26F9R1piUPPQE8WRxzS4/IRu/f4=;
        b=35P2pVJaNazFAziO2xPLAmtJx76DwRtrHI5Zrx3wkKPgOhBzKNgOvWEtaUoJCUaXJ3
         7Nuascwc4tZ+nRG3CJ97lPt+jDTAdpHldeSwjSFv6hgSjUWkMSNyIGdgx2eP8wRSlv2j
         g7ZySLGgvN0XSpQ/XHYEz+Gg8k0Tu00g7N9oJKFmdhKLdrPg87rYHt1iZsPjJ3/aiLd4
         O3v2eiQnsYLQNdXwYGvE3/HDqtrVixNIz9jXqwXicNIGIoQmZD2MBOfTpBzNfIwA76r6
         Yu0nGGgTgUgXjaFHWjsse2l6v50wMdXtLg095wDRcclK332CMO1vvhbaOxKyd2zcyZaP
         Np5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUWkwLZ2uD2pHl0Ciu1iTebfGiOZucpzns8Jsr9m++jo25pgqfy
	IehD1EyJkIvf342mlOzeGBE=
X-Google-Smtp-Source: AK7set8OpPVQfK3Uvi70R+LwlJcYrHcXMKlNLAeE0DP5W7zI1OpYhB71jp6l6IKIjATGcZ7bDg3vNw==
X-Received: by 2002:aca:6745:0:b0:35e:1617:6f57 with SMTP id b5-20020aca6745000000b0035e16176f57mr634591oiy.224.1675492043281;
        Fri, 03 Feb 2023 22:27:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4389:0:b0:37a:fb5a:bdce with SMTP id u9-20020a544389000000b0037afb5abdcels265200oiv.3.-pod-prod-gmail;
 Fri, 03 Feb 2023 22:27:22 -0800 (PST)
X-Received: by 2002:aca:c044:0:b0:364:7d13:acf with SMTP id q65-20020acac044000000b003647d130acfmr5298429oif.13.1675492042792;
        Fri, 03 Feb 2023 22:27:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675492042; cv=none;
        d=google.com; s=arc-20160816;
        b=SBkVbKWeVBg+09llLnpdWc37k+jc/wBd37Rkje/aih5apyre1tsIfnumue9xguN9Eq
         as22ms5tiejQQM2mU/pRqAxXahUH6Z3AXqLNjLaG5Ou0ovGtZp6QP/J2QySpLRFlkOAj
         9hFpyULSMmSWmwuG2TMkgpXrktf9Zzee7nv6UVYQfFsQ2s2+g08eROh75/5ThWJrp2WW
         r07QulfJta7+S2Bl8M4e2kWucLd6jqCUbWvSNHeEmS3/LkzPliF55CmDIKcS/jIwO4di
         Ut0swuLei4l9chdU8d4hcj/0hLolPeBfntxbpoCr/i4PG9WXLGopXFGZhGHCJ3QEvff5
         uhfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=7nzow32rldzNRE37/7gZLZ0DJPZ4skYJN8/BZlQpFHk=;
        b=WVzLsI3m7QWWQOqT46+2wAu7x1SpVnVKm9yvd7vryLxF87N+it2MrBFQNdB0Wodzqb
         LyI82B8mUafGDIrakwVLo8aY6yrzehvnSzedraeBzhvuxIr2s06W/mHRXax2ryA4LiPC
         fXwg8xI2Eme1i6fLMYBSVpoiiRbUSX0/J16ExUyd6cbPQlYbs076gc0ctmpblwMqQE2d
         4+DgeCk1yKrOGUvr88N4o4fwEd2u1MEhowjvfkzB0SUkYFUDQn75cttyXwHR+D1c1roN
         A+PLY49PTwEABybfc7h5xOOB+gIV075GCjoJes0BwaLUxnGxJ612ILA5uko8rPIscr4b
         SdYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=2YwQZp4m;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id p83-20020acad856000000b003783a8a36f0si582185oig.1.2023.02.03.22.27.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 03 Feb 2023 22:27:22 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2601:1c2:d00:6a60::9526]
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pOC12-004ZAV-3y; Sat, 04 Feb 2023 06:27:12 +0000
Message-ID: <be4dace1-f546-1b4e-f33f-c757c100d0f2@infradead.org>
Date: Fri, 3 Feb 2023 22:27:09 -0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: [PATCH] kasan: use %zd format for printing size_t
Content-Language: en-US
To: Arnd Bergmann <arnd@kernel.org>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver
 <elver@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20230201071312.2224452-1-arnd@kernel.org>
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <20230201071312.2224452-1-arnd@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=2YwQZp4m;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=rdunlap@infradead.org
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



On 1/31/23 23:13, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> The size_t type depends on the architecture, so %lu does not work
> on most 32-bit ones:
> 
> In file included from include/kunit/assert.h:13,
>                  from include/kunit/test.h:12,
>                  from mm/kasan/report.c:12:
> mm/kasan/report.c: In function 'describe_object_addr':
> include/linux/kern_levels.h:5:25: error: format '%lu' expects argument of type 'long unsigned int', but argument 5 has type 'size_t' {aka 'unsigned int'} [-Werror=format=]
> mm/kasan/report.c:270:9: note: in expansion of macro 'pr_err'
>   270 |         pr_err("The buggy address is located %d bytes %s of\n"
>       |         ^~~~~~
> 
> Fixes: 0e301731f558 ("kasan: infer allocation size by scanning metadata")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Reviewed-by: Randy Dunlap <rdunlap@infradead.org>
Tested-by: Randy Dunlap <rdunlap@infradead.org>

Thanks.

> ---
>  mm/kasan/report.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index e0492124e90a..89078f912827 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -268,7 +268,7 @@ static void describe_object_addr(const void *addr, struct kasan_report_info *inf
>  	}
>  
>  	pr_err("The buggy address is located %d bytes %s of\n"
> -	       " %s%lu-byte region [%px, %px)\n",
> +	       " %s%zu-byte region [%px, %px)\n",
>  	       rel_bytes, rel_type, region_state, info->alloc_size,
>  	       (void *)object_addr, (void *)(object_addr + info->alloc_size));
>  }

-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/be4dace1-f546-1b4e-f33f-c757c100d0f2%40infradead.org.
