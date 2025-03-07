Return-Path: <kasan-dev+bncBCLM76FUZ4IBBMUEV27AMGQEAUXT2MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 97119A5761D
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Mar 2025 00:33:08 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6e8ccb04036sf48038106d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Mar 2025 15:33:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741390387; cv=pass;
        d=google.com; s=arc-20240605;
        b=bOk0WkjAfwZ0XUpwgvvy38P2g4tAFaGpkZlJrWUrZey4PRNnJcNK+p8rB1tjallBlI
         F/nxH83UtovQThhRvmzkaSh6jcPTKaEMW0ZyBJhCx4iW467xF272igacPwVUwS4O4wFl
         znpdBLDX11fHBx8RuyFe8DWyYzh0YO5qUsn3MdLr8xg5NDhqsqzaKrTmURt8NmYfKkph
         xJKLMcagJ/FcvgF/eBUlYid+IHAbdz2rQhOiMKKw4x1khPAGBv4ZDjigtq2w7QMvdO9h
         I+sLhqn7XS6nkJa7FX27/f25KIceEcJVZE3sq4/sq5cUCwKFyhZ9GT4YIcWH1PbFwUT0
         QrCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=aCSCZn3Z2qi6eQHIfhHe8u0rdLIbyfIeiCr1j/qO25Q=;
        fh=nZwjSCS377cKgM3yJRZG59ixdyz2u3e7kfz+0zbrRCY=;
        b=Rrd70+1qq9MGrTNEaGSjWRHdbVfIYAepUFBrxSLyzAETHrVTJPzB/MSLFQnMgWFV4c
         rWQiSPmhNDbcSM+6wHNroq8dZLmUEBjaKFGX/xA96Sr2X1TTwaB8kF17irEqpRBIiFGX
         PN4OUuUakHHuoALCYBYs7nInTMP54UQ3FO1QowiaGkWpzgwjqk7IooBVodbJS5/1oYNW
         1QeJ/GvG1/B01PMjsDgDNN8luHtZcpnfmRjue2nKE98NNGrxFZp3v7hVq+EhzJ7VFEpp
         RVAidrqbPZyep4UGABkfjZMf76eikBaR91FuT5ZRgNlE8J8FiaKqIKGAcaY02kNPQA+9
         ctSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Fgm5xY8G;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741390387; x=1741995187; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=aCSCZn3Z2qi6eQHIfhHe8u0rdLIbyfIeiCr1j/qO25Q=;
        b=E/u46RQqZtTNlpdZAvW1nitiLsrEn9IJjrYek5HWaSyN/qpF9j/3ddvd/NT6aaa5Eh
         ozKYoB6aHYx8Y4vwxgfX/AsdrgzTs6sVDQs8aHJ9YLHBsc/Kv0/1Px9+NqcE36CPqh9Y
         Xjx9RYn8KP9Csqfl5cwdzp4sFN8rX9erJb2HsvkDwDsJ0J+XXfHFv9MopxyEGGYB4BhC
         1nOZBfii+W+2Nu1hy+88o9ucy47ZNT4hcXojxsIcFBu+6AWXCp7RDhKw8AhfSGEgp8oz
         UjekmC72vG8wbwVgfVKVUpwWnzHE0RvayP/spI+0xGvDCoJPl6FwNECUxpRK+vVzMh+M
         08CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741390387; x=1741995187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aCSCZn3Z2qi6eQHIfhHe8u0rdLIbyfIeiCr1j/qO25Q=;
        b=ueJq3BB5kdbqGWoXZiu6M5UFgB0H+3KwQafjPonB/Rw5niV8iJDL0ePlAUwwPresTb
         +hJj3xEf0bmqc11R/7BHp4mr7GjyUSfB8/kxfJGo++FnDiKnS+gJ8tBhxaIE12uzX6h1
         ZSel0zqac8TIRbi/KlBTwNuEz1g8YRtv3wm/mnJWPYtFLque8LTWKTB9k6LsAdptPn+8
         ZwJF31mrqQl/+ej9IclKhH4ws/UVy4ySq2T46cTYSxVQ83YoipcSIQ9mhGkQTQbPKdRJ
         9/yH3G+yQuFMGZB/2phmReb4LQV/OI19rI+A1BDPE7g7/xjlC+sHr5rX0wSiirJc20uN
         oc0w==
X-Forwarded-Encrypted: i=2; AJvYcCUGGeCI5umsU0V18PEiZUxUiniR8Ie91TtlN8LYFCByZhKR85VCv0Y6QLOULYK7YU+K81vGyQ==@lfdr.de
X-Gm-Message-State: AOJu0YzIIug4b6Yd+oy/qlUF6AfSzCu/sVuPdDeBeabuIGSeEEPohcTA
	zvHyqv/CCjH5WAo3dUvZvp7BAWPgrBku4QMVUhhwqOFOpLkmxGu5
X-Google-Smtp-Source: AGHT+IE3pRwmHfsl90OeaNhbL329asR32dRk60EmiRVCeZnDenguSk8Mwxz6NHY2eVklbLTt7sHLLg==
X-Received: by 2002:a05:6214:76c:b0:6e8:fbb7:6762 with SMTP id 6a1803df08f44-6e9005b6667mr57878686d6.6.1741390386719;
        Fri, 07 Mar 2025 15:33:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFd+hOL227EDLq1OZMUtkQUygYso9gQhjjNBMGg4o05mQ==
Received: by 2002:a05:6214:1084:b0:6e8:fa98:8af6 with SMTP id
 6a1803df08f44-6e8fa98970fls20023526d6.1.-pod-prod-03-us; Fri, 07 Mar 2025
 15:33:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnxzcYGxVcHINBFxJCnKvMeXIs1ngNx63pCpbc9CzDGjcWaPoH4mlpXwpGpc7BoewAsQ1JaL41ZJY=@googlegroups.com
X-Received: by 2002:ad4:5cac:0:b0:6e8:98c0:e53d with SMTP id 6a1803df08f44-6e90069c7e1mr62082496d6.45.1741390385747;
        Fri, 07 Mar 2025 15:33:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741390385; cv=none;
        d=google.com; s=arc-20240605;
        b=Os5GTAI4Mj13E8RgzBfk9fOWQCA60/iFyP1ppIN58AugKQllItoJVEIORssaBUvMVD
         NOYKG++p2e+MrFiyDGc46NK6UN4o4SQbDrrisSNTbNEr2XQFdX1EdjgwYle7xeRJ6BaJ
         ybfMKWd47WotXxauK0JY02J3vSDouuIgc30UC+4SolC16CzEPLUVKoxYbpTaSbhLL4OX
         pAcbnqpwpW2LlFtKwXgfeybGbQ/FBKrCcELhesQkVvI8L3oQR1YN8P6Ctr2/77Gtr7oQ
         BQTKbKiL5vgf3+sYti6f27c08qLZvTIVCkSQeEuvxUxoJSSxO96BtA05UMbFSYs6000S
         7Kkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mHFXO9D6YwhROjoFlwWSesjCYFiKET0NT2Feon19Q6U=;
        fh=r03hT2G/Q+2dnOtVawSSieyGb/pdhha+gmC5RZ0KXk8=;
        b=g9hyU6FI6BtP0Aquy59r5lZ1HtLcbmoyftMNoXWj7TYaYAuU7OuQD/yfY8BHRlYAxZ
         ufMAyzM3vVB8WSAMA/leBf8w+a2jqp2BHUaLS2vmcXc1+KAJmBBiRX1jAyuOID0EMbM7
         VruebVhAIGMTswfErSee2zzpN9OhfY89pmMkC4LbANF9eYBuCzsAmbqzSCyJIJRUFi+e
         JtyaaRCpw/Ho0nXPUitbMe0yff1Xu4yBwbpV8WrJvKJJ2RRyD73nHcSboytJgOMd9TjH
         JkPU52TLonZRfabAojpwLQGPx5DNUVMFL4WHESneiWHHoeDGEQMrs9SWKyFWloZm9YIz
         bedQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Fgm5xY8G;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6e8f7123595si2093616d6.3.2025.03.07.15.33.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Mar 2025 15:33:05 -0800 (PST)
Received-SPF: pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id ca18e2360f4ac-855bd88ee2cso58461639f.0
        for <kasan-dev@googlegroups.com>; Fri, 07 Mar 2025 15:33:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWT9KqP2/sYpJJ8kAY06UlZIk2HA+FC85xztfPRQ8qjxMj/tjKjPiCTfR7mNyBUSPtkNCfqNM0Yulc=@googlegroups.com
X-Gm-Gg: ASbGnctws+fG6l6scLC44Vl3HiJaHCDP5BBaeEd5+VYqSTmG7S2mAXXhyIQwEgJJeXk
	6lYaYneosYZO4nYN7aeDP/Pg02GZWZL9H9os/JhAb0Jdfbm67Q6HoLABpPS92zrXBqZx+ExTz6S
	zZm3mIoAIKGfe7RVjhU8W/5uRmTW9aJ3cwk9nOyIxd9QO6dXRopodi3qXwHwWLzcBcNaOnBUGbt
	cRmuuS7fe6rGhW8omCiB3mkArFwdxRY0B+z59gMaczsKCgj31i/wPYLl9jtaOn7CFhfmWBJUbW/
	qXYwiJAHNKdyTSkb9wvZIyR6/VC/w813IQe1QSmspo2sm4vDiEF6YKoqbC47O2IdzcXvAmcqZrn
	ULzmwuSdg
X-Received: by 2002:a05:6602:4006:b0:855:ac69:32a4 with SMTP id ca18e2360f4ac-85b1d053032mr663250139f.1.1741390384993;
        Fri, 07 Mar 2025 15:33:04 -0800 (PST)
Received: from google.com (26.80.59.108.bc.googleusercontent.com. [108.59.80.26])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4f22079b1dfsm382085173.118.2025.03.07.15.33.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Mar 2025 15:33:04 -0800 (PST)
Date: Fri, 7 Mar 2025 15:33:01 -0800
From: "'Justin Stitt' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, Miguel Ojeda <ojeda@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Hao Luo <haoluo@google.com>, 
	Przemek Kitszel <przemyslaw.kitszel@intel.com>, Bill Wendling <morbo@google.com>, 
	Jakub Kicinski <kuba@kernel.org>, Tony Ambardar <tony.ambardar@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Jan Hendrik Farr <kernel@jfarr.cc>, 
	Alexander Lobakin <aleksander.lobakin@intel.com>, linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH 3/3] ubsan/overflow: Enable ignorelist parsing and add
 type filter
Message-ID: <upvdnfozcexlpb2x4auimec347adozkl2al4hu2yp3kfagdeyp@dqs2ft6wdmog>
References: <20250307040948.work.791-kees@kernel.org>
 <20250307041914.937329-3-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250307041914.937329-3-kees@kernel.org>
X-Original-Sender: justinstitt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Fgm5xY8G;       spf=pass
 (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2c
 as permitted sender) smtp.mailfrom=justinstitt@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Justin Stitt <justinstitt@google.com>
Reply-To: Justin Stitt <justinstitt@google.com>
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

Hi,

On Thu, Mar 06, 2025 at 08:19:11PM -0800, Kees Cook wrote:
> Limit integer wrap-around mitigation to only the "size_t" type (for
> now). Notably this covers all special functions/builtins that return
> "size_t", like sizeof(). This remains an experimental feature and is
> likely to be replaced with type annotations.

For future travelers, track the progress of type annotations over at
[1]. There's still discussion on how these will be implemented in Clang.

> 
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Justin Stitt <justinstitt@google.com>
> Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nicolas Schier <nicolas@fjasle.eu>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-hardening@vger.kernel.org
> Cc: linux-kbuild@vger.kernel.org
> ---
>  lib/Kconfig.ubsan               | 1 +
>  scripts/Makefile.ubsan          | 3 ++-
>  scripts/integer-wrap-ignore.scl | 3 +++
>  3 files changed, 6 insertions(+), 1 deletion(-)
>  create mode 100644 scripts/integer-wrap-ignore.scl
> 
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 888c2e72c586..4216b3a4ff21 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -125,6 +125,7 @@ config UBSAN_INTEGER_WRAP
>  	depends on $(cc-option,-fsanitize=unsigned-integer-overflow)
>  	depends on $(cc-option,-fsanitize=implicit-signed-integer-truncation)
>  	depends on $(cc-option,-fsanitize=implicit-unsigned-integer-truncation)
> +	depends on $(cc-option,-fsanitize-ignorelist=/dev/null)
>  	help
>  	  This option enables all of the sanitizers involved in integer overflow
>  	  (wrap-around) mitigation: signed-integer-overflow, unsigned-integer-overflow,
> diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
> index 233379c193a7..9e35198edbf0 100644
> --- a/scripts/Makefile.ubsan
> +++ b/scripts/Makefile.ubsan
> @@ -19,5 +19,6 @@ ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=	\
>  	-fsanitize=signed-integer-overflow			\
>  	-fsanitize=unsigned-integer-overflow			\
>  	-fsanitize=implicit-signed-integer-truncation		\
> -	-fsanitize=implicit-unsigned-integer-truncation
> +	-fsanitize=implicit-unsigned-integer-truncation		\
> +	-fsanitize-ignorelist=$(srctree)/scripts/integer-wrap-ignore.scl
>  export CFLAGS_UBSAN_INTEGER_WRAP := $(ubsan-integer-wrap-cflags-y)
> diff --git a/scripts/integer-wrap-ignore.scl b/scripts/integer-wrap-ignore.scl
> new file mode 100644
> index 000000000000..431c3053a4a2
> --- /dev/null
> +++ b/scripts/integer-wrap-ignore.scl
> @@ -0,0 +1,3 @@
> +[{unsigned-integer-overflow,signed-integer-overflow,implicit-signed-integer-truncation,implicit-unsigned-integer-truncation}]
> +type:*
> +type:size_t=sanitize

Hi again future travelers, sanitizer special case list support for
overflow/truncation sanitizers as well as the "=sanitize" comes from a
new Clang 20 feature allowing SCL's to specify sanitize categories, see [2].

> -- 
> 2.34.1
> 
>

The plumbing looks correct,

Reviewed-by: Justin Stitt <justinstitt@google.com>

[1]: https://discourse.llvm.org/t/rfc-clang-canonical-wrapping-and-non-wrapping-types/84356
[2]: https://github.com/llvm/llvm-project/pull/107332

Thanks
Justin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/upvdnfozcexlpb2x4auimec347adozkl2al4hu2yp3kfagdeyp%40dqs2ft6wdmog.
