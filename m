Return-Path: <kasan-dev+bncBAABBANBZ7BAMGQEQZJZWTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id AFDC0AE0089
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Jun 2025 10:55:30 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4a6f2dbdf84sf9342271cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Jun 2025 01:55:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750323329; cv=pass;
        d=google.com; s=arc-20240605;
        b=lIw4L+IlbiSXiE6FboOoTd16YdPHbSSOrvDaMQsikYxMRTerCbc1/Y6YGxtG5qY5+q
         25rznQOO5C9sgjusnejsTMS0lHJufv2iK/L1y8vN/eaQKW8igRSFeKkRsMKN3U/izRsU
         ZOeJa6oEzHh8UaIlwUj7LxhOeMBpRkOlHU/TxTyRdu1nOiey+n493LPGxmdQccVGSlPi
         SX/XJYWoL71oDjSN27RVcPpiZuevnu4TRC8344izE+LoNGylpGcuEgJ/zVM2JMd5RyCU
         kuQYfQ9VyDBwYrlRzmV7v+p+2Z52cbXF2v2cj3Mad3sGpP2yyJ0L4l/ufh2IMxhbbBUb
         xYkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AlZpjy/eyFesJi1RpBOoe4E1yIeF7tXSid8sYxkpmpA=;
        fh=Ejg4oO/Lfd4ZaSHCc3crPj0gL4892wPvdAsxsyIBZic=;
        b=ZPLu3Wv9QHH+OemHatEkWQ1Hvwo05x8+/uhZvXlLvBnxuUwu20vJAwZanyjsnU4Qez
         XZ6FcAnW9ASH60DZU6hHjBJfLZx8Vh0IrcOoW9kjY3d/+KcIjlvU8rLXmAjc8Dycqn8Q
         CGjB/fZhyHsiAZYkfbkLPBxPYVA+ZzU8jgwDU48ciN527GgRN8g+kb6UgRTQHqmQ9Uiz
         oxp6KOwXLFVvujXt5TmQe1lJaKcF5s5IEVvX0C2A6PxxtUn9c5YGr06qlXoZ7d1GyR8j
         6yN5rgpA6tUcC+MSLLdbgJYuWZR4v5RZ1DBt64I8T9LvK7w3ftNbC3Efyl5y6362GwAg
         TsXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=p2FgroRg;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750323329; x=1750928129; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AlZpjy/eyFesJi1RpBOoe4E1yIeF7tXSid8sYxkpmpA=;
        b=fwPw0xVauJnNXgM1kvIVjFuBk4MIBk1HqLF0X80+7KLwnJxbOPwNwrAVkZlCZh8l4s
         B4M+9o2OpK8+GZPdVTZQKHHXRdROVCkq4GLJnwfp8ZlWYcqfcKY93NSta7+PrXPv9G+3
         1BERWa1sa0FJOY8QGw2YFCN1nO1ZXh3f+CEQJyfPGc2NZwOIBefLNMpGGxNIj9eMSvS5
         eNNdi4mdrCVg8b1E9iH7V9EdGUChtY0gyofSWuGHPOJCKJoJ0lDkTpd9661jWcT0LXWt
         hXH1NMN+t01+39hWEwuYAQp2zxSOLpBPDcciSdzvvsCbkrfk/XBgzgbJgIYErjqjx79A
         qIGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750323329; x=1750928129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AlZpjy/eyFesJi1RpBOoe4E1yIeF7tXSid8sYxkpmpA=;
        b=Gh//mt3J6Ey3CHaNgA2sIDPJWdOSOpzUcpR525+WZklwKr7H4qDknbzGFuINpVxZdx
         PfRmer2s/8JGTldkIufNoWo8rMAniq6r3uoYRgqPpl3hV/SC16sjekrQENt6/Z0aoX8r
         B35IOjQRIDNr5eLqYkX1Ih4/xYYffpwpmDeH9qYaYoQFAl8urJqGJGXsJggsERumRqJE
         b3Alcku4l0IMhWKXCLYGb6Spw4ik1lgD6eRGPAzoPc+/UFA4+63Yh08vxtSHw7xUSezS
         g7CUYSyHuoshjSRYFvxSn1JFd7E3RMe+pQsvolS+4UURa0KXfUx2Zj4Yc2lu9AcdNSXj
         vsEQ==
X-Forwarded-Encrypted: i=2; AJvYcCX7SAVpSkqFFdl32BlBMQ5qm501Zy3I4zXNVXX2bgcloXhZIje9HwO+LkIoOkHwHj11iAfEwg==@lfdr.de
X-Gm-Message-State: AOJu0Yz4KP/J0lM+ozkM34g420RZikdog74MqcXb4k4jQ4e2oNNfkkaW
	jowYIWeiHeHFRQ/AzT0IAqzmIwh+Ic9f8fd1/cHzuL+IJKeqjiavpDH0
X-Google-Smtp-Source: AGHT+IFZXR1b4oOmXxpL9ri4550KaG9Asp2zG74n1KUF/l5AyqAO1Pl1gQZdTOnRN3UWwH7V4w1YOg==
X-Received: by 2002:ad4:5e87:0:b0:6fa:ef0b:6b0a with SMTP id 6a1803df08f44-6fb477938bfmr301771376d6.36.1750323329455;
        Thu, 19 Jun 2025 01:55:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdseHfzHqP8f1fWP9IoV3XG51NSHN5hcsNuKk1CQxzT6Q==
Received: by 2002:a05:6214:212e:b0:6fa:c4e4:78b3 with SMTP id
 6a1803df08f44-6fd0080e3bfls7302936d6.1.-pod-prod-03-us; Thu, 19 Jun 2025
 01:55:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1DbgFpbcZGMq070tsS8wgROzywK2LZW2NbkXPZtHAdEzlMUCw2lCXgxMn8vW26ASdYCDtTIL2H+o=@googlegroups.com
X-Received: by 2002:a05:6214:cc4:b0:6e4:2dd7:5c88 with SMTP id 6a1803df08f44-6fb4779f7a5mr287437276d6.38.1750323328684;
        Thu, 19 Jun 2025 01:55:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750323328; cv=none;
        d=google.com; s=arc-20240605;
        b=hZBZZ5NX542d5xMvB8aEGHbMtUggfxP7/2V9WBAx181QbapO/Ee7GO0c2fe4aogl3c
         BesvtFwAtncZMV4M7EY6pPO7X4BULbP1to8/lirgGaWk8r+kACAZ6l2fbvOS+mAyvpOr
         2MtV6MX1HuMim3ZlcOLEjXNe2oGayd2uFc2Ec3p2IXodfGCzgjeFyQuINL5ao/HD5Gin
         9qu50kUYbaAzFtAj+O1pm8UR7ir3o6YQygXSV+85aaLz9FgwD0FoOLqw/j0ib912Tx9y
         RvygvWGWkDBDoP23JfaBwZ1Wj/tfzlBRLski0nGdHp02KfdKyJCVjVvYl1NHrm80ir0U
         WH7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ks/v4Ujqfzvs18wnvXzme1WPE3egbOvN05dsniZSqtg=;
        fh=K5iRiuNDZru0fAUH1KXx8OzpEh0Q7dVj1GbDiKKMOKc=;
        b=JqaxBuk9sAj70kCaQ9wron+zyOBXqeWvhN9a1btRQN2c86qyJ879RAdJXN7OUFArze
         3Ta73n3kVG0CGtDkYuXvn1Ar+3P+UsmSJPK0GCLgCxfWNuhI846a97nFJU8kcAqtEsOl
         uOyc++ky5ZQJuMKORq9p/Q2mZYRFPZrmWyG7nBhWtML9m/lCb7V12L10IyVdrdM7pV9f
         VLWzkdu/78WzSrUm2jxM5555OsmNtmlOrEszu7GUPmjHnL03pD+6C4H2wrH4BO7P4aon
         wTj0rWgM35w36MhfI9ksTLXXWCRigMSbV5Ak3Nnrncvp72r18GMBIWfS9RlWw6dtaePn
         krFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=p2FgroRg;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6fd014fa8a1si477536d6.1.2025.06.19.01.55.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Jun 2025 01:55:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8ACD24AB27
	for <kasan-dev@googlegroups.com>; Thu, 19 Jun 2025 08:55:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 67B32C4CEF2
	for <kasan-dev@googlegroups.com>; Thu, 19 Jun 2025 08:55:27 +0000 (UTC)
Received: by mail-ed1-f50.google.com with SMTP id 4fb4d7f45d1cf-6070293103cso929178a12.0
        for <kasan-dev@googlegroups.com>; Thu, 19 Jun 2025 01:55:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVLNBHJSHfx9IagbyyEVCs7n1f8Oi40BJrw0lmM6iDg+RH5cS4j4mJR5hWvfX1Cpgzv3H5Hw1oTvgU=@googlegroups.com
X-Received: by 2002:a05:6402:50d2:b0:607:6057:9006 with SMTP id
 4fb4d7f45d1cf-608d08f7a70mr18716524a12.8.1750323325929; Thu, 19 Jun 2025
 01:55:25 -0700 (PDT)
MIME-Version: 1.0
References: <20250523043251.it.550-kees@kernel.org> <20250523043935.2009972-9-kees@kernel.org>
In-Reply-To: <20250523043935.2009972-9-kees@kernel.org>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 Jun 2025 16:55:15 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4rFt3J6hD-eiNN5nihNR0cwMxPJQpq8LQWkx4km428og@mail.gmail.com>
X-Gm-Features: AX0GCFtBM3K8OeK1JL3sld-cpEWi3kLQAET9w-cyksCMv2tJ5SCZdduevj4T0cU
Message-ID: <CAAhV-H4rFt3J6hD-eiNN5nihNR0cwMxPJQpq8LQWkx4km428og@mail.gmail.com>
Subject: Re: [PATCH v2 09/14] mips: Handle KCOV __init vs inline mismatches
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, linux-mips@vger.kernel.org, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org, x86@kernel.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-hardening@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-security-module@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=p2FgroRg;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

Hi, Kees,

On Fri, May 23, 2025 at 12:41=E2=80=AFPM Kees Cook <kees@kernel.org> wrote:
>
> When KCOV is enabled all functions get instrumented, unless
> the __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we have to
> handle differences in how GCC's inline optimizations get resolved. For
> mips this requires forcing a function to be inline with __always_inline.
>
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
> Cc: <linux-mips@vger.kernel.org>
> ---
>  arch/mips/include/asm/time.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/mips/include/asm/time.h b/arch/mips/include/asm/time.h
> index e855a3611d92..044cff0e0764 100644
> --- a/arch/mips/include/asm/time.h
> +++ b/arch/mips/include/asm/time.h
> @@ -55,7 +55,7 @@ static inline int mips_clockevent_init(void)
>   */
>  extern int init_r4k_clocksource(void);
>
> -static inline int init_mips_clocksource(void)
> +static __always_inline int init_mips_clocksource(void)
Similar to x86 and arm, I prefer to mark it as __init rather than
__always_inline.

Huacai

>  {
>  #ifdef CONFIG_CSRC_R4K
>         return init_r4k_clocksource();
> --
> 2.34.1
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAhV-H4rFt3J6hD-eiNN5nihNR0cwMxPJQpq8LQWkx4km428og%40mail.gmail.com.
