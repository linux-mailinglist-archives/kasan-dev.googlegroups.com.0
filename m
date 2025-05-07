Return-Path: <kasan-dev+bncBAABBQM55XAAMGQEMK4RQRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id BDE65AADEB8
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 14:14:58 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-43d733063cdsf49987505e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 05:14:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746620098; cv=pass;
        d=google.com; s=arc-20240605;
        b=GTosvQMfo803U6aTbGiF5FWDvfMrlZEjfcdrLMV43q1l/VdMmb0kmrIXQdtQHMQ0lq
         gLcT1bqVXfJLGRxrV7rtkS1GZWJ6Qa6v+WPoZmuLg1q4vbfxz2Mp3jbPB9Y6KHr4Rk86
         VMBP8nIkbR5dG2SukRz2DUrSCvS7wsdqXPrRRCQOkDVfbjicNEwlA1mefRwXgpZpHiFC
         te2HfQAMDn7WwmdYu8SDntp8Dro9YOfH6wPmNdZkG1SWRn8v02+wDQqbd/b7gk4rkdoT
         j4c8Uhzgd1wfxfsp+XluAonN4gcdsxVjCQMkX+xOUeF4ygijtdl92shJqYnVv28aUaYo
         c2UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=rxiO578AmRdthT1DYPx87LUYDbJm6uX9NMPu8H3qmdk=;
        fh=jWFbLyKUngz8bcfvUPanTjwqsPufT0U8pK3A9OaDX7w=;
        b=DFrEJ9CxqovD3lORPuiDEvsF4Zc7Djbph56eylLw6AweWwCXxxWZCrtebDBpDEHDCo
         DJqmIwfJr6a7tEFS7V5fVM8EBMk/2MfPpl4LfCtMTOMnKqwNRIuUdBncIkgkckE3EtqE
         Ec6Ue9N0CK8zGuq9SuQTu8ZYYheWfrEUnTYW2odiSnl/xbH9QNZmsFQ25RW5Swgrk+tS
         qJ1BurerFnzNDZqHJk2Zhui2oq1htO8hESBE2PY3ZY4i8zCCZGfOi944p6ArbyWAO2rP
         vlgCqUWsD7sDxy+VWNwCsI20rm3R3o7gYivv/QFBoJyu4yfqS+SrNF+ffkdZdq7ED/Vo
         fo5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qJMnoz3T;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 91.218.175.180 as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746620098; x=1747224898; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rxiO578AmRdthT1DYPx87LUYDbJm6uX9NMPu8H3qmdk=;
        b=YsSZAYa9LYhcHWXfcOVueFzdQqVmLPyuM15MWtrrSN5h5nG/XJBxliOg/4n+E78cDn
         g7ARwBP9n0UDJQVEUlqkrfLLv9qV3ddWD3Cd8jrdZAvo1LXgvmGvu3oovp+2Tp3Cv7hA
         S1CHtOkKZfYH/XALlN/9yvZMLyulrVbnEfRAKx9y+TIin7LTUH1GM5+sycpsoB327llE
         aYL23tgcpBL3cqQLaFeCkVIxJ5yjuh7UrB7u+K0kG0w0soTsD6/7KGsVkZvlnsNaRzfb
         dU62sWxbhksuQ+TtywgTVWFUFyOMnruBjUWVN3PtxuwYHoJJXvuRfm+xh/QXtk5006ls
         e99g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746620098; x=1747224898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=rxiO578AmRdthT1DYPx87LUYDbJm6uX9NMPu8H3qmdk=;
        b=s89Pwh6DqiYKqTGukriv9qmH/KEdrfKOwGOe0+8TyBNmBu2KD9Spgb+aQZY2ctaWbu
         XTK4jBQ+ndFhz/Kb5rPpKZ64/mvqsRrsMAFxSx83cEptqzsqD/dKRo8pj3v99nfrEKum
         +OSnq2H3ZagkADjzDNWyKrQW8UprlBecexK9zh/xXYbO7XdFqilexQZeNbzeUkkD/hFO
         w/2edFTOdgBNRPW7/bxEr6iG/SvlPMal1pSEQet37ji0vnwmvGZ9R0jNuj6+YhEU7q/U
         6bzFhURs62wYb4CwYq/uKx7OpZkEgzYQmKFHQTSf5rl9gl/AcflGfyLYmFiRYUj6f66f
         Ix4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVtmbubv/8ACF3THFCUr3hWP4/ckaFF1jORU8IBOJ/2u+1WI+PKsFFzFIJV/xvm4rf6EGPpw==@lfdr.de
X-Gm-Message-State: AOJu0YzWkuZxdzOiudYwIW5HpjY+pHiQwZPcZdAyl/VpKP0pKrc888JF
	g5eZx9yA0HSkOhqHJrXIFRYTtwxBg3NEDyBnT681jFVOkyLa0R+f
X-Google-Smtp-Source: AGHT+IF/G/N6WzCGt8PnBOfKrmTprmvsBFxBKOaVFSg6sqzS1yuaG/LKByjHcQF7gCSEpPDnIxYzVg==
X-Received: by 2002:a05:600c:a44:b0:440:6852:5b31 with SMTP id 5b1f17b1804b1-441d44c3395mr26255875e9.10.1746620098030;
        Wed, 07 May 2025 05:14:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEmqKtg5ov3KxTXmQt8eiOptra7hEgNx2j6NFRMSFQzgA==
Received: by 2002:a05:600c:350e:b0:43b:c5a5:513c with SMTP id
 5b1f17b1804b1-441b5c89818ls14975205e9.1.-pod-prod-02-eu; Wed, 07 May 2025
 05:14:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUoJspqszt1IRJdNw0gbfmvYOtRpGfgnduOr0tGauSl/JJYsAMXuX3VrOOpFhC9qP2lcz4ohZdi460=@googlegroups.com
X-Received: by 2002:a05:600c:528c:b0:43d:300f:fa1d with SMTP id 5b1f17b1804b1-441d44e32cfmr28535785e9.31.1746620096363;
        Wed, 07 May 2025 05:14:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746620096; cv=none;
        d=google.com; s=arc-20240605;
        b=gkx9s+4QxE2WjVDlfYaZDG6Rf7hi5lioM+UDl5pJvC9iWHf+9cOER/qta9m57y6F3p
         zX42hlDBJFAqKqAHX6HXZMdEAW2/63/JOClZIETZAsQy45eFiuCGhuZTSqdLLG+qd9ac
         gePEK5GRe/5VM6q837BgfwixP6nmgD8WRkGefwPM2TwqpxVB86qI2ktvLkTsK/WS53O1
         XQOoEnc+wjfJBMT0DsnbYbmn9AM1MggRNy5wavmd1l7BBQLCVX8cj1WW5xbyolOStoAq
         PAIfnH0IMcYHslVmNT8nNA2o9LqDWX0DH1ui6S9/1tzao/kB7UdUfP6GCv+bzcQsIV3O
         Id0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:dkim-signature:date;
        bh=9XqY7YuOdihrc7IqXrXm7afvm5cHVdOv9tTA20piJDQ=;
        fh=7+uFyCeEE8yiW15L2JddkcGmWUEXx9id5qKYm20rCbU=;
        b=KcR/PTQrLwoN+OhkTjZUVltWTvqWgXEzYimUmvbO4n5wSJ4eOEu45DHxO1MYDWNSkd
         6NIoPTvnPOjtOYO8+2/oMIE0C9+4tYUHV7aEtj6hlOp0JU2NovFTt9bIuhMiUEJDaO1h
         V9eS+ZMpU41MOeejbgJsRWXllkzsf/iu+dvsb960Faf1l0HpAB0BWheU5avRrs5TAsO+
         a7iIqq3eigokWbgcu/2ihNiid1tyjecmx2X+owpgrJTzKCqZNl1b4ghr2qVDKq8SVRPa
         q21nxKVkOu9XXEZClSNXjgNssuCvyS4PmSh+sw36/xV5U6RY4LLP3TwZ21BcrTtjEnfq
         oelw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qJMnoz3T;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 91.218.175.180 as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-180.mta0.migadu.com (out-180.mta0.migadu.com. [91.218.175.180])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-441d15df86dsi1762045e9.1.2025.05.07.05.14.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 05:14:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of nicolas.schier@linux.dev designates 91.218.175.180 as permitted sender) client-ip=91.218.175.180;
Date: Wed, 7 May 2025 14:14:51 +0200
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Nicolas Schier <nicolas.schier@linux.dev>
To: Kees Cook <kees@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	linux-kbuild@vger.kernel.org, Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>, linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org, kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: Re: [PATCH v3 2/3] randstruct: Force full rebuild when seed changes
Message-ID: <20250507-righteous-turquoise-bustard-4fca48@l-nschier-aarch64>
References: <20250503184001.make.594-kees@kernel.org>
 <20250503184623.2572355-2-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250503184623.2572355-2-kees@kernel.org>
Organization: AVM GmbH
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: nicolas.schier@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qJMnoz3T;       spf=pass
 (google.com: domain of nicolas.schier@linux.dev designates 91.218.175.180 as
 permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Sat, 03 May 2025, Kees Cook wrote:

> While the randstruct GCC plugin was being rebuilt if the randstruct seed
> changed, Clang builds did not notice the change. This could result in
> differing struct layouts in a target depending on when it was built.
> 
> Include the existing generated header file in compiler-version.h when
> its associated feature name, RANDSTRUCT, is defined. This will be picked
> up by fixdep and force rebuilds where needed.
> 
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nicolas Schier <nicolas.schier@linux.dev>
> Cc: Petr Pavlu <petr.pavlu@suse.com>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Cc: <linux-kbuild@vger.kernel.org>
> ---
>  include/linux/compiler-version.h | 3 +++
>  include/linux/vermagic.h         | 1 -
>  2 files changed, 3 insertions(+), 1 deletion(-)
> 
> diff --git a/include/linux/compiler-version.h b/include/linux/compiler-version.h
> index 74ea11563ce3..69b29b400ce2 100644
> --- a/include/linux/compiler-version.h
> +++ b/include/linux/compiler-version.h
> @@ -16,3 +16,6 @@
>  #ifdef GCC_PLUGINS
>  #include <generated/gcc-plugins.h>
>  #endif
> +#ifdef RANDSTRUCT
> +#include <generated/randstruct_hash.h>
> +#endif
> diff --git a/include/linux/vermagic.h b/include/linux/vermagic.h
> index 939ceabcaf06..335c360d4f9b 100644
> --- a/include/linux/vermagic.h
> +++ b/include/linux/vermagic.h
> @@ -33,7 +33,6 @@
>  #define MODULE_VERMAGIC_MODVERSIONS ""
>  #endif
>  #ifdef RANDSTRUCT
> -#include <generated/randstruct_hash.h>
>  #define MODULE_RANDSTRUCT "RANDSTRUCT_" RANDSTRUCT_HASHED_SEED
>  #else
>  #define MODULE_RANDSTRUCT
> -- 
> 2.34.1
> 

Reviewed-by: Nicolas Schier <n.schier@avm.de>
Tested-by: Nicolas Schier <n.schier@avm.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507-righteous-turquoise-bustard-4fca48%40l-nschier-aarch64.
