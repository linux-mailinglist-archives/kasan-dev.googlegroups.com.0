Return-Path: <kasan-dev+bncBCF5XGNWYQBRBVW2TKRAMGQEYD64UIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C81AF6ED261
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 18:24:56 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-18486cd43d7sf27401114fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 09:24:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682353495; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bdk437l3zKbGiAgGXQjM+ofcD1yPYwhcoAN49So1Q71Hz3iktXnfDlNwwHLWYwT+jz
         CR/07IxuhXJrbiqrRAGcLYzRAqr7iA8Xny5Gsjm2wnn9Vzkp2AImrOJxKEuSB/c+q3Y+
         35LK6EPJlEuaeiobcOjkLcarsUY++9oRZuGG74QIBm2NzPtjvAX+vWybg5fqvQAVr1TN
         UypkBDviN8KnoWah1znR7Cvby9rgMxCUXFZ8I5kTHvoM7pT64YR5NtRQLNkEXczX9FGK
         6tw0HIM+slnoSYBshlOp5VyW6M633kpSyM3pgPprxuPeX022HfcF9GOiA+5OngAbnCT2
         KNiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:subject:cc:to:from:date:message-id:sender
         :dkim-signature;
        bh=3udI53iC8HnRmlZ96I5Ob4xa9Ov40IHVKCIhsDvpcMs=;
        b=vh6FYq24pdyb/5Y526UTCBBj6CipojKQTdKcn5Eo7W++UNq9S55P0i3kU7I47B2V++
         XFHc52Irb8NOLnI4izdf/9eMzDndfEDXLmCHUMOTEFrzeWeeenAJhuqoJ4ueb2j+beVd
         jgI2mVuXbV08CImnIwCudRs4yEyvZxJptco+pV9lrBhczKOmpSNV0bigzPNpheB/1YJm
         TV8NCpsdo0xjiKGof7ML9YrCnCh9jC0E5OCh69WQEEGXDschedzK3uV5ADKLEdw7Oekh
         hFfAQYZQw0szsnBOSZu6urEuR1vPo72YIHVmN5/5aQR4q/0S4qN8N9EwrjoBTR5jD06X
         RJOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=D7tq8Eaw;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682353495; x=1684945495;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:subject:cc:to:from:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3udI53iC8HnRmlZ96I5Ob4xa9Ov40IHVKCIhsDvpcMs=;
        b=Yn3nY5nC1yIJxmaXWQZBJVhdf8Dt6GGX+p4ZUxsdGNwYkJ07I0oWJK9vkDOM+LjQCl
         gRcdygs9L3kLDvG0C4cjAWfw82TKHOnW7FKkuI6La+Bd7ObnqZRN94sVJblwAuurwn8t
         5HN1VyVc7ISi9bKupvoD4VfnyCXTSJp/GyHgVsIzsEy6hTcB8WzjYj74iGj83qUwXLwi
         cGrXbunRkKxGK1dP7toPvJW/hmWAiyEj9R49wDJLOwchzZyKo2o4jbzvkupfF5axkVFG
         d7ZifXxaTm65sX3NiSBl+PtyXECB1kPzx+WyTDLcoppL3a2+qzelzOdPgdPUhLUWsBVX
         HFPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682353495; x=1684945495;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:subject:cc:to:from:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=3udI53iC8HnRmlZ96I5Ob4xa9Ov40IHVKCIhsDvpcMs=;
        b=N1YEB7RM1bc05k3GGNr0zyg/Lr9lXLaRy/aTqzz9RNJIhwTxDOeTP2TG9J/Wq65AT4
         mUdzhtrdsZaBa2cMs+y7bw3EZk/BHQ8ti+ehnz83Mw3xYruPHgIaVC2oS2xzMUKOznPT
         ACx8sJ8sDzz0exQUcmKOiozR+3pW5CD0E1bwVnhx8LNGQyGWU99UHcSNIsXHG/eoYW/k
         qDGM7UZw/xYU0F7Kg9jjJ4r9XmpjwKchhw692J5kd0ATiYKGy980LBIN+7Jpf3R8oBrX
         vhRWIDYs7T9ulhr+vDYKTRMLaAXiqOepThnEkyb/dGHxAAt6NTKnGh62TfgSdNA32ekn
         dCbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dGaOBTczlr83qRHoWUc5ZnuktL2akzcFgII71nijSp/qVbZMBH
	vqVSR4OiTDBq8XknUaOEawI=
X-Google-Smtp-Source: AKy350ZN1J8vggwLEiC1jBHDbm5/+XmFfCEsGFOvoRGuZQz3hWf/Y5I8GzlyYKQhgd5oBeCCOU90gA==
X-Received: by 2002:a4a:6c5e:0:b0:547:4b06:e73e with SMTP id u30-20020a4a6c5e000000b005474b06e73emr3365190oof.0.1682353494830;
        Mon, 24 Apr 2023 09:24:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:368b:b0:6a3:d400:61a1 with SMTP id
 bk11-20020a056830368b00b006a3d40061a1ls1766260otb.8.-pod-prod-gmail; Mon, 24
 Apr 2023 09:24:54 -0700 (PDT)
X-Received: by 2002:a05:6830:39e4:b0:6a5:db64:c9f4 with SMTP id bt36-20020a05683039e400b006a5db64c9f4mr6728093otb.34.1682353494338;
        Mon, 24 Apr 2023 09:24:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682353494; cv=none;
        d=google.com; s=arc-20160816;
        b=kAlTWW7HM6h+V4Eh+xeTU0RfbcyhmJTtdqemOzMg6/Xo5PE0Y41VWmN9WUyz87Z/zs
         0LokWkENY57sBvaeDYCmAvkSx8KHcI1iSFlW/yv3yAYvU3BvXDHlPCDNplIddAvDcI5z
         cxwPa0xS8eER1Xvz2B4gkfdvWC2wx/sIYsqWcDKy+9GuzETv76/ECpjVBU/M/rCb9fsy
         xM26mmaRhKaHypew1eCnoxI/D44ploBJ3sPGA/q7HJ97WShS/uPK7mPDdAaSvZCfqSpI
         M/qMx+m5tOEYVOXK2dgWHxEnbw7KzWYj12e+fhFTOVJVnR9uWtWPexgBcxxD0H+FLirj
         HJPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:subject:cc
         :to:from:date:message-id:dkim-signature;
        bh=3Ec5rnpGl1sXrFHB3DIjsS4ZKrDnQgNacloNoA+YyYQ=;
        b=viVq4eFwMGPmRwQJQWWmpmmGjRdBrklm4f7POo6NLPA/GVWhtjYXSoa4CcEZecl8sj
         g/2Z9VCn8d3g4n3J8CxhQ5AN0pWVQrmnI2oIsfFX7FLhZYqa4i07mpBhL7+oKYCX8qYE
         YGSoPBDziEnzr4T4YOH/xbK8gPWXTOyKs2iOA0IJQCYoWjx5RF36fWOr9bNoGmdHv1sW
         vcouCM1KPNocnwu8z2FwBu4MmkOdP1i/D+4nMBa5aXF9gI2vLsvh+t8nJD5a1k3YzaEQ
         7FeKdGZFcnNp0qZ9Tpn+u7UT95yfLSFXOaCsmmx1teWzdbLI12zw8hzRa3e4UIIDsOyu
         DpvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=D7tq8Eaw;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id br26-20020a056830391a00b006a6203c4bc5si992004otb.5.2023.04.24.09.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Apr 2023 09:24:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-24b29812c42so3431480a91.0
        for <kasan-dev@googlegroups.com>; Mon, 24 Apr 2023 09:24:54 -0700 (PDT)
X-Received: by 2002:a17:90a:4e07:b0:247:19ac:9670 with SMTP id n7-20020a17090a4e0700b0024719ac9670mr13749994pjh.26.1682353493627;
        Mon, 24 Apr 2023 09:24:53 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id g9-20020a17090a67c900b002465ff5d829sm6599949pjm.13.2023.04.24.09.24.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Apr 2023 09:24:53 -0700 (PDT)
Message-ID: <6446ad55.170a0220.c82cd.cedc@mx.google.com>
Date: Mon, 24 Apr 2023 09:24:52 -0700
From: Kees Cook <keescook@chromium.org>
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	akpm@linux-foundation.org, elver@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, andy@kernel.org,
	ndesaulniers@google.com, nathan@kernel.org
Subject: Re: [PATCH] string: use __builtin_memcpy() in strlcpy/strlcat
References: <20230424112313.3408363-1-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230424112313.3408363-1-glider@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=D7tq8Eaw;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102f
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

On Mon, Apr 24, 2023 at 01:23:13PM +0200, Alexander Potapenko wrote:
> lib/string.c is built with -ffreestanding, which prevents the compiler
> from replacing certain functions with calls to their library versions.
> 
> On the other hand, this also prevents Clang and GCC from instrumenting
> calls to memcpy() when building with KASAN, KCSAN or KMSAN:
>  - KASAN normally replaces memcpy() with __asan_memcpy() with the
>    additional cc-param,asan-kernel-mem-intrinsic-prefix=1;
>  - KCSAN and KMSAN replace memcpy() with __tsan_memcpy() and
>    __msan_memcpy() by default.
> 
> To let the tools catch memory accesses from strlcpy/strlcat, replace
> the calls to memcpy() with __builtin_memcpy(), which KASAN, KCSAN and
> KMSAN are able to replace even in -ffreestanding mode.
> 
> This preserves the behavior in normal builds (__builtin_memcpy() ends up
> being replaced with memcpy()), and does not introduce new instrumentation
> in unwanted places, as strlcpy/strlcat are already instrumented.
> 
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Link: https://lore.kernel.org/all/20230224085942.1791837-1-elver@google.com/
> ---
>  lib/string.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/lib/string.c b/lib/string.c
> index 3d55ef8901068..be26623953d2e 100644
> --- a/lib/string.c
> +++ b/lib/string.c
> @@ -110,7 +110,7 @@ size_t strlcpy(char *dest, const char *src, size_t size)
>  
>  	if (size) {
>  		size_t len = (ret >= size) ? size - 1 : ret;
> -		memcpy(dest, src, len);
> +		__builtin_memcpy(dest, src, len);
>  		dest[len] = '\0';
>  	}
>  	return ret;
> @@ -260,7 +260,7 @@ size_t strlcat(char *dest, const char *src, size_t count)
>  	count -= dsize;
>  	if (len >= count)
>  		len = count-1;
> -	memcpy(dest, src, len);
> +	__builtin_memcpy(dest, src, len);
>  	dest[len] = 0;
>  	return res;

I *think* this isn't a problem for CONFIG_FORTIFY, since these will be
replaced and checked separately -- but it still seems strange that you
need to explicitly use __builtin_memcpy.

Does this end up changing fortify coverage?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6446ad55.170a0220.c82cd.cedc%40mx.google.com.
