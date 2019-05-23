Return-Path: <kasan-dev+bncBC5L5P75YUERBX56THTQKGQEIAXLANA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 97BCB27880
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 10:52:47 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id f15sf840220lfc.10
        for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 01:52:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558601567; cv=pass;
        d=google.com; s=arc-20160816;
        b=d6nMGiAyCEbOKHNtAIRzlYSOrrxY31WK88tb/Q1nl0S6aWETK1dD0zXecPqI7TCtXr
         CJgMeeEODPF+aJZeNlLrwegp37bFq577uIlVSSqwoNkdZas/vwHiDb/iBattrw0l5hzh
         0/gsNOZI3JH8dLJxE99tOk2siUnsnt3dmc9AC+cILJNOznEszBjy3R7gBHnPXRHC4WZ3
         m5l4rAoWFpPY2Z1o4i3gT92HLaO90IlCVFB5OH9jp5hC3nfVAT8W+GgLCNO7GrPir9hj
         338EyitxgQVVZlhf2LaIj3jwzsXR0rRckGL/IGwhkoae/oJEsi73CWqNd9fldzHMgH/+
         cH7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=BrGu9D9YIohvDGpwp497b6e/8+5alVPuF3ApurTNd0o=;
        b=Eq8UiXjC9lkIedPNSElPdDKBQ+JDHB9Hsoxk4JUXOTRKrF0oln/uatgCc6N3nq7t02
         tYT+N2QxkejTiI77UdbXXETOhjA8Bkb2uLQWNOgjsQrsmRjcxKVhcoQoymmfw1K8D/UK
         yUN9ZI4yS5DtWwFwGv5Df2C1tcW3isvpF95bbZq6PaArQr32u/jtigqKzApmeYNMXFqm
         13sBOT1HzVsrDGFD98KWkHFJ5M8sO6JYUvgrPfA+S/OLTHwdHmBZYnwJhR6A6+5hzE9h
         c9EVbFLk1Okpa56CkDQ5G7GFpQA3d6elcnPMY7I8Oxs5dlSoVcAiEJ6cxYFq4pNd/AOX
         WB/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BrGu9D9YIohvDGpwp497b6e/8+5alVPuF3ApurTNd0o=;
        b=aWDkZPKyJy+ergpVya8izQCOXDN2tCbHEwZw9Diax3m4T6zBr9ztS8JQih1gL0LTML
         Cy5Tl/HVEyy56nJ9rkPlliNy4UUrUUYfz+yZmZEmf9ZHzWFwmqIxPENWk2bV68a8P5Fq
         pJt7esmebmMrjP0LUdJwVGrCyJqQVlAvt8XewORtfh8sEwbsxKYLK9dd3D1SG3U7pbrH
         ZXtqZIOzS4HHDZqQlao+OFxt425pUy4iIUz9SJDoaHVW1dUMPvf2P+Zr1R7Zr4nI4E1k
         tNH2ZtuAKC7zsZ2TjqzZAIIB+rUdnTz/qAJhDyz2vqKQuNDkSq5+/5hxiMUTnNe2DeAA
         fPYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BrGu9D9YIohvDGpwp497b6e/8+5alVPuF3ApurTNd0o=;
        b=H42yXVibz58d6ecMbm82ZdcP9SYGYSNn14+lMbl1aeXbscqqOIDKB7yBz+vyXq8wiv
         BqZRGaYO7vZaPSlyG3iXf2oHp6c5pNHOhMdz+PsCaxi+pLBqKRLIUcn0cDu945XgUOWV
         IUO+Q69wlpXY2QM+7EDGYkA2LCDhYKzB+SHsnFJMux4FQzkJ45hnilSnUP8Sukh9JrmA
         QsIuyFyxA4gkBfg/VzkxrIjYD6uMx2skIIShYaLXPgv2bxmWtAt++uyg+W0CqcYBLE4g
         GGJwzRYpaoqMeS4AaeOJr47NgKOwKnyDkxlXIG9lcPf+Q0YVuKjTDypDQrsdTl93hkbV
         e79g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVGqV0+LvQXP3hZkPkVBTRZVOvPm5PxWX6g+6ZYSnwfCJzz09QJ
	P8gxfioHP7/FzNH2ERIE+vs=
X-Google-Smtp-Source: APXvYqxlW7D8DMjuCgI14hWwgafcXHcsRYH4LO3Z5pDfmNn4AOW3o1LCInzSZtZgrfh6FLR4ZRofzQ==
X-Received: by 2002:ac2:47e7:: with SMTP id b7mr545165lfp.53.1558601567195;
        Thu, 23 May 2019 01:52:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4c27:: with SMTP id u7ls495622lfq.5.gmail; Thu, 23 May
 2019 01:52:46 -0700 (PDT)
X-Received: by 2002:ac2:457a:: with SMTP id k26mr10113798lfm.161.1558601566727;
        Thu, 23 May 2019 01:52:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558601566; cv=none;
        d=google.com; s=arc-20160816;
        b=A4VtKl5ancGINoSg++H5VqYjNBGrPDyNJGTShWp/BPewprEFHvQtyZ4LULI7/k4oJa
         PiHYzPfjWKU/Y6KdBmXnyoi9gPc86xc+1nixIuFrQafRObgqpkM43jwQODL2dhUTIldm
         ZndR2NQH11opBI4ZtFgTzC0FSZoVs0c8SwrOvpVeqhOLbwQwZ0duSRHwatwQf5KHr907
         YkzNNCrapohtcCsW8RCjOLw2ijoVY7t8ZcTQsuOnz5Qx3KOdPzbU5Q/Lq+QN6NgkMHYb
         cVWfLoSWLFqs/9czeE1nbtfRS0WPk1MKMoVsTNj6njGcJ5ivuheJD16MoclJvUbFz0GW
         k6dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=sz4UZ+kS7GmFLyBvXVIykzQAS9lKB4VP6bT/MciVzPw=;
        b=AcKUnLBdxZcuKf2X/z9w0jn1e1LA3PEVlr09hTl5ZNdPZNOnA5n7u1RTZw7n0TYDQV
         nQ5kE37oCTCRa9h++14e/orKjSJz32zrtayaVRv5VwNbWTP3sqw32TYw2tv96R+jrXMa
         8I7SFHGwcjfv4yLsyr9/sIuABApWE6Qr/sDkcMRE8fffobaylnSU+RFVhjTCI49Wukc6
         0eVbkXvN6Pt0oN7WJc0ZCrl+8pSF+M0bEft8RAaInWl6NAepMDg2QnGF8mJvz25im4WD
         jNIHLoO14tj6wrb0Rgcaz5dYyNBTt8mWQPApNEM4YNrdLIb0ucSmyhU0qJkxYixNycvA
         RbTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id c9si2512164lff.2.2019.05.23.01.52.46
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 May 2019 01:52:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.91)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hTjSu-0000Q9-Mk; Thu, 23 May 2019 11:52:44 +0300
Subject: Re: [PATCH v2] kasan: Initialize tag to 0xff in __kasan_kmalloc
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Nathan Chancellor <natechancellor@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Nick Desaulniers <ndesaulniers@google.com>,
 clang-built-linux@googlegroups.com
References: <20190502153538.2326-1-natechancellor@gmail.com>
 <20190502163057.6603-1-natechancellor@gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <126d5884-b906-f85b-e893-a6a30ac0082c@virtuozzo.com>
Date: Thu, 23 May 2019 11:53:02 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.0
MIME-Version: 1.0
In-Reply-To: <20190502163057.6603-1-natechancellor@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 5/2/19 7:30 PM, Nathan Chancellor wrote:
> When building with -Wuninitialized and CONFIG_KASAN_SW_TAGS unset, Clang
> warns:
> 
> mm/kasan/common.c:484:40: warning: variable 'tag' is uninitialized when
> used here [-Wuninitialized]
>         kasan_unpoison_shadow(set_tag(object, tag), size);
>                                               ^~~
> 
> set_tag ignores tag in this configuration but clang doesn't realize it
> at this point in its pipeline, as it points to arch_kasan_set_tag as
> being the point where it is used, which will later be expanded to
> (void *)(object) without a use of tag. Initialize tag to 0xff, as it
> removes this warning and doesn't change the meaning of the code.
> 
> Link: https://github.com/ClangBuiltLinux/linux/issues/465
> Signed-off-by: Nathan Chancellor <natechancellor@gmail.com>

Fixes: 7f94ffbc4c6a ("kasan: add hooks implementation for tag-based mode")
Cc: <stable@vger.kernel.org>
Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

> ---
> 
> v1 -> v2:
> 
> * Initialize tag to 0xff at Andrey's request
> 
>  mm/kasan/common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 36afcf64e016..242fdc01aaa9 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -464,7 +464,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  {
>  	unsigned long redzone_start;
>  	unsigned long redzone_end;
> -	u8 tag;
> +	u8 tag = 0xff;
>  
>  	if (gfpflags_allow_blocking(flags))
>  		quarantine_reduce();
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/126d5884-b906-f85b-e893-a6a30ac0082c%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
