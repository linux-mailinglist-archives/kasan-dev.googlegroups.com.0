Return-Path: <kasan-dev+bncBCLM76FUZ4IBBV44WCYQMGQE267UTSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E3A1A8B40CE
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Apr 2024 22:28:08 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-dc6b269686asf4266875276.1
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Apr 2024 13:28:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714163288; cv=pass;
        d=google.com; s=arc-20160816;
        b=GLhg7cMo/D1az7sEysk7Zq9P16C7wqHJtETUCJpR9pUPOPbjt1cBgRnZgncfT6S4In
         MBkRMhGK1EJc3ZciDYekdyuCIKnb+PsSyOMmaixZmD+sfIGh0OS6SO8tauLwlZ5i2AjZ
         N2XJxUFTWI7nZK2JTwyW+OYJ8e07mYkxuK1N/oRy3/U3snliDPBD0bS1ayK5nu4/61PB
         Uhom/xdWu4i2HC/COZBKxCxYGYcN2F7nF+KEX8Mys1dHp1XxqRVQ8yCfISwBfXTFw11m
         njtD0zmZNd/lWclnIu6pqSc3A4WpHGY4Zs+FwLilKsoOjTJvRV1t7TTJ5cZZTtNVVFZN
         51/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ZaGee+UilOsZ+6Mswmb3P2D5SfwLHKN7owlQpIJn8P4=;
        fh=OoTT44hAiJgL1TashK7lk5EBYi8vA+iq+LKOqV5qQow=;
        b=p7auuVBe6GGTf8ncO88RFgqbDivsNfllo6c3TFGs/g+kWoMNqcoTUTrZ5pY3ivFVGi
         uR5x5SNul+eQtWy78SR7P3ZDORksBdUy/0D6YzUbgtsNqAmA9+VkoACAo+KmQWH4egHN
         3cUy/MLlonNcpV3m5lmyGtFb/Fu/ZRHUT791eoiiceWEO0mbZq82LreaC6LfSQlP9otI
         Q8n/katPjSU8vBaxNdTNwHSTGihJi3yGEPnF5titoDr1oBJgjOvpmXbmceIpO7AzhPqC
         Xkn4HzHr8Zps0ASRtyrwZFSVFZ1+kOT5aCYgnPeJzrabDQqNECXTEBZx9xl/KIQn0NwR
         xi4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=J+Z3DXSS;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714163288; x=1714768088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ZaGee+UilOsZ+6Mswmb3P2D5SfwLHKN7owlQpIJn8P4=;
        b=uoXZbE1FtPrubx47VSozcPAqJaDdjknunUT6prXfE6ivr28Des7cbfGGZBesiaHrrj
         /+RXw2VQCDi7OAzIkfnhX2hgVc6O8HVfJVJhE/KqJQwZ6oUZl1xkwHwp/AL1krHXedwF
         GzM5g4QNYoZ0CElMLWGQzDqiAoxGK6+0JM55PC2nnwffgdK7EvD1MmHq+CZgHzA3rxwc
         A3JkehnL0mESeROTFOvW96ebbNRUBS6bhRU7jeFYMgd+n3YCWcT0RhIGPbEGBomxpwb5
         jbNu/wzbYP92NebE4s90rNpDuixJa+vZG/4RjWRMOrQS2u8opEX4Bh2lcVX7DcHKGWLq
         42cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714163288; x=1714768088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZaGee+UilOsZ+6Mswmb3P2D5SfwLHKN7owlQpIJn8P4=;
        b=mCzM/IXY2SEKqWAm0QAuiQ6kkF8fXE8M5DaFfSVAadwIFI0sdU7otK237nvJl9ingA
         r9LZt5oJLmOPR9oVJvpkqNlVNAcsvcQvCfuSQS8mIwqd7Dw6Is7oIT+G6g7E4Ha6ZaDh
         TA25i/ioqzAuCauuFzka1N12yZl9pmsHplnxBAxAFTqEOGBVIYMqPdRYtTqFvoTJnK/S
         lU3+bv3WR+XRI5TOEHmJLr5yPev2f9MHhfVWIxDPZGCydrHDXxnNbcLLS/6Lnn47TAti
         r+eaC7ePt70LgZXnP0hPQ++p1CTx48X1pe4qossByJFo3xeJtKPwx5TvgnqvjQQ/dI6Z
         uCbw==
X-Forwarded-Encrypted: i=2; AJvYcCUv5bW1adBSXlwgtnMxI8b/v9u90Uhuifw3FJB4l8idZdOFhzP+1MbvlGKGAs7JQV3xmX1MfgI6XIaUuGnqi/uVBPJOzKAZ1g==
X-Gm-Message-State: AOJu0YzIZe1FYhLNp6bWWWRfsCv928r7IJgoIc3xDmIKLFARdsX8tmHr
	P+5cjQrNmBQ4ZeGJDaado7/x9kzL75S51J/aRv8bqWRv3iCQ6JRy
X-Google-Smtp-Source: AGHT+IESKtTcl2SM9TfQCSSUWLMUSQgM9bQMpvrgb/pfC2ueTsJfHNmD99k1YYD2WhUvOhMDMla7cQ==
X-Received: by 2002:a25:aa90:0:b0:dc6:bbbc:80e4 with SMTP id t16-20020a25aa90000000b00dc6bbbc80e4mr1160644ybi.4.1714163287656;
        Fri, 26 Apr 2024 13:28:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aaaa:0:b0:de5:a3ef:27b9 with SMTP id 3f1490d57ef6-de5a3ef2a15ls350853276.0.-pod-prod-01-us;
 Fri, 26 Apr 2024 13:28:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWZ/BPCsnhCb1QFna+mgZXswjupXxHNSS9r9rj5KMQkPVMw4gX1S6/ikajqSoeZFaMAfyeqiXzkgley6I2X+gDDoh6cyS/5jXxhCw==
X-Received: by 2002:a0d:ebc2:0:b0:609:1252:61e2 with SMTP id u185-20020a0debc2000000b00609125261e2mr757863ywe.45.1714163286347;
        Fri, 26 Apr 2024 13:28:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714163286; cv=none;
        d=google.com; s=arc-20160816;
        b=NnZNvYfiu7EGIz4yfgUFJOSFKKSOQmrzCou5y15FUmXaCwTWWgmPE1nUzGgWv/Y/I4
         lEEUZQg87QrIWfFO6OnKEo91hlUqvSimREZUgs0BuVWrIr0mblqHHP049KvQD0yKO2Vk
         LdjKiWT1VymU7bylnvzwlQtwx8JuTcQ4c2zJ6xPH2F6cdT5RuM8n1GHPq4ntFIcUZuxa
         Ws22soBDhVJ0CWtuVEZL/1zNH40yNxOFzqaB0gYcivI/N1ARl6P4ETupu+BUq4y69REC
         k0KekFOOAUYXZvHJHZ+KjwFiLQasSQ8rXf7XvoMo47sknF9FAs25uKVMLJQstV3RIQah
         RrrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=z0HjfgQeMYeniizrlmmHEmgJt7Z1IePAUwGcoRhvByo=;
        fh=lGY1DWrUhkR2sU1BnnfeXQgc6KqF7sc9wgs+hHqbEO0=;
        b=tkVgo07eq6jtHMp4qekpKJtnl1FyUUKj5ZHcq21Jup1fs+jY5jv2hdUvuGWsNk6WIt
         ap8bFgClNajSHJyqxLL/JAgmXz1KcoXRt1mhg0Whk+NJILioOda1Q/wOCsQC2jP0q4Dq
         EEwFmB1ZDZqkslBAQ5dnlbT2NjOlCTvjxTCaoM8qAG3wPrIbLG3JphfKzl55apkQwHvV
         iA8BKyrAYkoJxvM0wqJmTTa+gJP2kLXMfA9hfRJL3d1OxsKQmSzlqQqPSVZAP7roJcTi
         ehCqCz/CeT9qqO6H7Mj7VjFJzvCukbxGrMjzyOWMDsFxtUqW78N1NPZ6RtNQvwhukiag
         Nbjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=J+Z3DXSS;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x135.google.com (mail-il1-x135.google.com. [2607:f8b0:4864:20::135])
        by gmr-mx.google.com with ESMTPS id i15-20020a0ddf0f000000b006185e0c6aadsi1863011ywe.1.2024.04.26.13.28.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Apr 2024 13:28:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::135 as permitted sender) client-ip=2607:f8b0:4864:20::135;
Received: by mail-il1-x135.google.com with SMTP id e9e14a558f8ab-36a0bca01e2so10623645ab.3
        for <kasan-dev@googlegroups.com>; Fri, 26 Apr 2024 13:28:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVOhhXu/UpZiRnwtRXFY2nHe1rEJNsZCJHeP/VGfC/QDGzRDsXFwuZ/ZG/QU+bEiuHX0LApPbWTNpkrPmmGGpB4UvAGSuqjtpLgrA==
X-Received: by 2002:a05:6e02:13a9:b0:368:80ff:9bc4 with SMTP id h9-20020a056e0213a900b0036880ff9bc4mr1236703ilo.1.1714163285655;
        Fri, 26 Apr 2024 13:28:05 -0700 (PDT)
Received: from google.com (195.121.66.34.bc.googleusercontent.com. [34.66.121.195])
        by smtp.gmail.com with ESMTPSA id x17-20020a920611000000b0036c28ba3ecesm1089777ilg.85.2024.04.26.13.28.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 26 Apr 2024 13:28:05 -0700 (PDT)
Date: Fri, 26 Apr 2024 20:28:01 +0000
From: "'Justin Stitt' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>
Cc: Marco Elver <elver@google.com>, Erhard Furtner <erhard_f@mailbox.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, llvm@lists.linux.dev, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] ubsan: Avoid i386 UBSAN handler crashes with Clang
Message-ID: <kxzozn56f7xknswj4xmss5agncpy7t7apke665swpcvrijt4uw@35rfqgyuyp5v>
References: <20240424224026.it.216-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240424224026.it.216-kees@kernel.org>
X-Original-Sender: justinstitt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=J+Z3DXSS;       spf=pass
 (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::135
 as permitted sender) smtp.mailfrom=justinstitt@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Apr 24, 2024 at 03:40:29PM -0700, Kees Cook wrote:
> When generating Runtime Calls, Clang doesn't respect the -mregparm=3
> option used on i386. Hopefully this will be fixed correctly in Clang 19:
> https://github.com/llvm/llvm-project/pull/89707
> but we need to fix this for earlier Clang versions today. Force the
> calling convention to use non-register arguments.
> 
> Reported-by: Erhard Furtner <erhard_f@mailbox.org>
> Closes: https://github.com/KSPP/linux/issues/350
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nick Desaulniers <ndesaulniers@google.com>
> Cc: Bill Wendling <morbo@google.com>
> Cc: Justin Stitt <justinstitt@google.com>
> Cc: llvm@lists.linux.dev
> Cc: kasan-dev@googlegroups.com
> Cc: linux-hardening@vger.kernel.org
>  v2:
>    - use email address in Reported-by
>    - link to upstream llvm bug in ubsan.h comment
>    - drop needless /**/
>    - explicitly test Clang version
>  v1: https://lore.kernel.org/lkml/20240424162942.work.341-kees@kernel.org/
> ---
>  lib/ubsan.h | 41 +++++++++++++++++++++++++++--------------
>  1 file changed, 27 insertions(+), 14 deletions(-)
> 
> diff --git a/lib/ubsan.h b/lib/ubsan.h
> index 50ef50811b7c..07e37d4429b4 100644
> --- a/lib/ubsan.h
> +++ b/lib/ubsan.h
> @@ -124,19 +124,32 @@ typedef s64 s_max;
>  typedef u64 u_max;
>  #endif
>  
> -void __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
> -void __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
> -void __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
> -void __ubsan_handle_negate_overflow(void *_data, void *old_val);
> -void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
> -void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
> -void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
> -void __ubsan_handle_out_of_bounds(void *_data, void *index);
> -void __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
> -void __ubsan_handle_builtin_unreachable(void *_data);
> -void __ubsan_handle_load_invalid_value(void *_data, void *val);
> -void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
> -					 unsigned long align,
> -					 unsigned long offset);
> +/*
> + * When generating Runtime Calls, Clang doesn't respect the -mregparm=3
> + * option used on i386: https://github.com/llvm/llvm-project/issues/89670
> + * Fix this for earlier Clang versions by forcing the calling convention
> + * to use non-register arguments.
> + */
> +#if defined(CONFIG_X86_32) && \
> +    defined(CONFIG_CC_IS_CLANG) && CONFIG_CLANG_VERSION < 190000
> +# define ubsan_linkage asmlinkage

Clever.

Acked-by: Justin Stitt <justinstitt@google.com>

> +#else
> +# define ubsan_linkage
> +#endif
> +
> +void ubsan_linkage __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
> +void ubsan_linkage __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
> +void ubsan_linkage __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
> +void ubsan_linkage __ubsan_handle_negate_overflow(void *_data, void *old_val);
> +void ubsan_linkage __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
> +void ubsan_linkage __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
> +void ubsan_linkage __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
> +void ubsan_linkage __ubsan_handle_out_of_bounds(void *_data, void *index);
> +void ubsan_linkage __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
> +void ubsan_linkage __ubsan_handle_builtin_unreachable(void *_data);
> +void ubsan_linkage __ubsan_handle_load_invalid_value(void *_data, void *val);
> +void ubsan_linkage __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
> +						       unsigned long align,
> +						       unsigned long offset);
>  
>  #endif
> -- 
> 2.34.1
> 

Thanks
Justin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/kxzozn56f7xknswj4xmss5agncpy7t7apke665swpcvrijt4uw%4035rfqgyuyp5v.
