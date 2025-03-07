Return-Path: <kasan-dev+bncBCLM76FUZ4IBBUMHV27AMGQEQ4YNSYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 72F25A57646
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Mar 2025 00:40:03 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-6fd52bae39bsf33516097b3.1
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Mar 2025 15:40:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741390802; cv=pass;
        d=google.com; s=arc-20240605;
        b=YD1lyFM+hhHYDjTyoa7yGGXIHaoWmDs1mtvjPLMVC+Nc4wMm6pUMP9M8tgDwfvZAAV
         v7knaO7ODCOKrXA+PzgEfRAxGPLZkP3CakBgw7sRpE4P25HzzJplUbHmRLVm4xYsC4hE
         SLNz4fH0mLJP+kgguLx9DuI8qsRhoG/FzpptokvqS4JByo0fSVmrY7NG8SW+U9LG7V66
         uI1pCq0+2ZrtQnGUrMPU6IIAZFp8RZ7xRdlx10tNgi/QYpisp3emuitUppSpu3kB2Ik6
         5dZJijWMROapBAUqw/iAXZzFypwY3smamc8PvOr35yJ5CtSLnfE21QXoBhVevUfnEefI
         gZUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=2YYVx0PkZXMqKSpiIV4t+I2Y6opCwjZmbVzsiu78cKk=;
        fh=qcs8l+c84aWaq7gt4xnbxW39fcHrsP5CUu4aBY6gqd8=;
        b=jVE4j8rEZa+CZlw33n52Hs/GevrKJfb5O9di5b/t6B0izelv9gy1AIQBzgbBz9xEcE
         hnSp17wTLOwd8IsW9STJPMv3iwIo4sWHNWbb8OoPdjyF2HLrY8wfCWy/KwKtfi9uP4tk
         HDBNaseSAM0cEU9V4HDdCMFvGlLd2JVfHO5gyvBwVOlyFjRxa3FxfwNvQmXzGOgpG8Bx
         T4m8inPlKStemdHq0Y1WbkdQ5nl69nmw0kXWzopCwX0J0/npQcIX4F+6+tS/bYfARCaH
         kXPDNi3xCIlACdb/44ztuZbzO1iMLXpGYiroRwsH/1KhBVOfILcm4VUnlmcaSBKm/wF4
         83sA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0U3sJvD2;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741390802; x=1741995602; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=2YYVx0PkZXMqKSpiIV4t+I2Y6opCwjZmbVzsiu78cKk=;
        b=Zw2oTkiRh5WBCU/0LIQqsTHqDUDm8UV36wreZ3lkXjaevyCaiawXPWGtbeLNJxPIdg
         8XFacH9201Wxbb8LpkFyjIiDnSZjrnPBPuUCScTCqCY6DjEGqux2cF04CkQ8zWRfIDHY
         hv5LXpi8qaBXG1MDA1Bkt7bQIwW2ohT7JJaTDHTIcvgThFYkIod4TwQ5X6wk91CKysLK
         6Nv3G1VlhQKMjeSvLNsq0/pGGQiZWXJS2Ctu7KvjlMzXEDnK4EZW3+BgkrsT0ln71wNd
         iZf5vOe3y34jkE5L0SqQNHTumeEef87vwRGW/XyMJV+/psBS6SplUe4ezvhgsXG5k3ax
         reKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741390802; x=1741995602;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2YYVx0PkZXMqKSpiIV4t+I2Y6opCwjZmbVzsiu78cKk=;
        b=NG0hIx8loyyE5DJvau/oG7HLcUKJ1OzHJE7kzIAzm+XR/yDCH6MqClFj5tlsNdjUMi
         ET8GeUlj8eL4PYJGrrFz3C+sppAadi8ZJXKB/hvt8HNTUvsQt16JuLUkNW9zibM1E5vI
         VWDhL2k/4VeZbuj5EjmRcHAbUiHS4++/0LC+ETNzjFKsLV0+3XTYbl0EMlC3ALvk8Kox
         bWZ8qIt/amOCxEpBX/fyXvQIyr9fr0/PrM5iz1IdGee4Xq2wmJz/e1u9UIor2S8KAm0s
         IPIKZ2NN4RGXdxqCraWN62dDzLcVRgoUVCU+t6g5RpOC1LfbuPIAu/IuwxivQGj2aSiJ
         +yyw==
X-Forwarded-Encrypted: i=2; AJvYcCUcK1Nn9KCRihnzdzTKKaTjOievgTnn+DS+W8rOyuFmw1pEWybJNYeXQoyn419EiELzzlhaDQ==@lfdr.de
X-Gm-Message-State: AOJu0YwXLr1JU8ujFD9S+hrbH6QAyz3uMYC9NB7uJS3hJcXmqxwjB7PX
	of9dHzZqk6ohJ933BTZM5xwpbBXZJZvUkcR7WnxXf0CaB9jZM5jq
X-Google-Smtp-Source: AGHT+IHoF5Adj3uPb0O8sh7Yvh5dOZWW5W8Smh02FdJAjk/83Ciap44DpM68XkCyqdxPivhU6jjv0w==
X-Received: by 2002:a05:690c:6112:b0:6fb:1c5a:80f8 with SMTP id 00721157ae682-6febf2b5f5fmr77512317b3.15.1741390802042;
        Fri, 07 Mar 2025 15:40:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFN4aYkRGLu9hS0UJdYRx6Bgbf2dbJn6O+WfKnU95TEGg==
Received: by 2002:a25:7244:0:b0:e5b:3917:1c48 with SMTP id 3f1490d57ef6-e63483ee838ls376162276.0.-pod-prod-09-us;
 Fri, 07 Mar 2025 15:40:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWXv/2dxkasYvK/N9JQIPasYvsaQw38GzSzfcxZ7QOY2jn7b0Rwv73iMq6EcA4wZBALx6g/StsFgyg=@googlegroups.com
X-Received: by 2002:a05:6902:3307:b0:e58:ef9:25d4 with SMTP id 3f1490d57ef6-e635c1d8298mr6310622276.30.1741390800966;
        Fri, 07 Mar 2025 15:40:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741390800; cv=none;
        d=google.com; s=arc-20240605;
        b=ZYFFKkN827ySSM3WHHfXUHRGhB9XpoXuVRrZ0qORBsmuvBv7AuPwVNT8Ref7wZaaqf
         F/x1sqTxFQylGPkeg9c9ykcbiEKGR3Y+IN7BDC+UBO1tzlA56IZfJ8LxqkWhS+dfQVPa
         RPQLQ4bdWhYe39NYXawRWVZwHGqDXluUTjTTtyWhMVcK7smdU/Ivnl7P3B3Y/JjMxPwi
         d+LotX9PchU3p4tWk4b95LjC/gHAH56nhQPi7iymW8ge6C2B3Mp+37fUhmmiRQ3rZz09
         HeIOjaclqCizI8HvL6VZPTsdBaKEY34zVJ5QhgBdvTIC72JLZgme5/pQqXSgPgWXS1lx
         e2YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jDc72lD8Mhnu3NfUsPcD1oy818yB1nERuThSEkGUHkw=;
        fh=BZ67lPTTREiwW99eqXvRrVX6f1KsSVenwDezvbb/zw8=;
        b=drJT7d2aMfrw6kPGj+41OCNOQHzMDy+wu71rOhBhOejyiyzx884yRSUiPtuoMH+bWS
         /pcz9WBIyueWxidbwKIpW5zgoGrl7NbHjkt4ST4gsdkC1RjZbhG97IaqIkwryzek13CE
         TaU4YBl13oz/7eDYG8Y5FjYmFyg5GMESYem6gqMEE3XBA4Bur55hMikf0gUkd6Uhj4uA
         +VLM+Sd+BFebpwCmUsAGibJ6LxoM/unrsGwBC2QbUJzd7WatJMNDVXZv7WZEvuhE5ze6
         dHCUsnDxLP0JhY1Fm7aJn2E122BV3mYm87StIY7DPGw1PWYg8k7LGoPxGweHtqvWBdOn
         GPdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0U3sJvD2;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e636755a842si72861276.4.2025.03.07.15.40.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Mar 2025 15:40:00 -0800 (PST)
Received-SPF: pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id ca18e2360f4ac-85b0180631fso72149939f.1
        for <kasan-dev@googlegroups.com>; Fri, 07 Mar 2025 15:40:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV4A8PrW3ZWlNIcKs33rXEwYWoQ7bN5bP4wdYZOADHfaEgCZbhMvKghyo5ppCaQ/ZKXPOiVe2M62rs=@googlegroups.com
X-Gm-Gg: ASbGncsL46GPN037AftWdKpL8RMmkCaPfmbzwzqKxQ8ln8XOh2ycpKCJgGUv9AglOLS
	L7TtIp4BIDnQfH/jbOY24BVzk+gfSwqb2SdBKGSW+5bM4O4peXlA/4CAxA/9VLPATMbP9uBeWZG
	/h+Xt6iBWq6G1OyBcbk6znUwCERNy7hhK1V2Lz/4Ox3olBsMMyz5RkRY6Sh+YK2dVLsKq17rQmX
	XNBJ9p9Zm8iPdy0TcOZzMRKaxumMQ7I9vggMhQbTWUe+6PhCTam+kAFSzjVv7iF/VdC6NVy98VW
	dvm9nA+6sZtKpAEe0lNG7zCY8usa6jU1HqQzglfeMhRKgiZMbLCF7OaG+AzPkBDW2rIJ6l+61IP
	NYiWoV5oA
X-Received: by 2002:a05:6602:474b:b0:855:9c88:7894 with SMTP id ca18e2360f4ac-85b1d03fb51mr700353139f.11.1741390800315;
        Fri, 07 Mar 2025 15:40:00 -0800 (PST)
Received: from google.com (26.80.59.108.bc.googleusercontent.com. [108.59.80.26])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4f20a06b059sm1193908173.136.2025.03.07.15.39.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Mar 2025 15:39:59 -0800 (PST)
Date: Fri, 7 Mar 2025 15:39:57 -0800
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
Message-ID: <52samxs253u3t2cmm5xwbmrwzyof36w7xczpuvbkarqwonwl32@2jbmkagpk7za>
References: <20250307040948.work.791-kees@kernel.org>
 <20250307041914.937329-3-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250307041914.937329-3-kees@kernel.org>
X-Original-Sender: justinstitt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=0U3sJvD2;       spf=pass
 (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d32
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

On Thu, Mar 06, 2025 at 08:19:11PM -0800, Kees Cook wrote:
> Limit integer wrap-around mitigation to only the "size_t" type (for
> now). Notably this covers all special functions/builtins that return
> "size_t", like sizeof(). This remains an experimental feature and is
> likely to be replaced with type annotations.
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

Forgot to mention this in my intial reply but we have to be careful
with what types are added here. Kees, I know we're on the same page from
offline chats but for others: using sanitizer case lists to discriminate
against types for the purposes of sanitizer instrumentation may not work
properly through various arithmetic conversions. Mainly, implicit
promotions which tend to break this particular approach.

Now, for size_t we got kind of "lucky" because there are no implicit
promotions with size_t, it doesn't get promoted. This is not the case
for other types. This further necessitates the need for canonical
wrapping types backed by in-source annotations/qualification -- coming
soon in Clang.

> -- 
> 2.34.1
> 

Justin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/52samxs253u3t2cmm5xwbmrwzyof36w7xczpuvbkarqwonwl32%402jbmkagpk7za.
