Return-Path: <kasan-dev+bncBCLM76FUZ4IBBPWBROXAMGQE4IFVQFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id D9B7E84C217
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Feb 2024 02:45:35 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-68ca5f30b20sf1339096d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Feb 2024 17:45:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707270334; cv=pass;
        d=google.com; s=arc-20160816;
        b=M8NZSk1BkRprpVOB4fzsECoralScAezfrzIbnZVs1t4orGFCdnBovfOp3cgGotBAb4
         k6dqaErCQ2G6CeBNiIiUOYIOO1IVKm6g2iCYcYzO3f0ad2FZE8jx1uYPPoP59a670OIO
         dpYzqU/tb8Q/apkOlcbieKUQXasvZdY6g2uXTcT4vEiRupPtlGGwKp37IXGayxi8jhgW
         b1y5n9dxtgLGfGxsAnfjydMXHbUyoxld7i9TsuV4f/0pxvrmmmZSj4hu0GYMpmg5ThyI
         +wBrou32OOiSgDY4KERkkbdmFTpP6WZpU9rVNo3B/YufvSjNeb8/Ln0kb4xYzd/6+d9z
         8TCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=B0z2+30lwkLfGm53OYzGTU9bi+N2j4hJS9WMdSlWbYM=;
        fh=lqzh0YxZ3/mUqJtMQMM61OnrcqupTHF5EIGh4kZFUIQ=;
        b=VHneT7WwfS2HdY2ERvf6LWjHYpigmIoUmVhjL8gO/qCioX848tWWf2GSbfbvcSZRO+
         o4wc+HZViEGIA+RibbhUjKsJ+e34hjZ8/kSiLqK2inID5//e5HnBJNhPZLWC0UdHENEr
         +tm8e4x+Wyb4LhjxxocugxmxY0rgtav5LvqWnQpWw1T9RhZA8Uftm0347AEhlrsYijqj
         9MxilcdgS/B854qbkcNpWSuEppIP82bmdSIE4lt19/iipc9eKZwiMZNdr3SKpKfcho7L
         m5ulI1HsuX9yC9i0z84R9/NyQ4CFp6+EJW//F58Mtzpt0osbwB8vLq8WHDtQ6MAaPMFv
         5uvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Bgazqmz2;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707270334; x=1707875134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=B0z2+30lwkLfGm53OYzGTU9bi+N2j4hJS9WMdSlWbYM=;
        b=ZtbB9UtbovVT/Te/QUVjPWjH7hQdIxByy4eAyIku+zRufLyDdjTzecxMOGvnIl0RRC
         tIMuiJDoSUZGKjTulga6bwi2n58yd8TZETPAIc3zrOkFYdYGPVHvWb+tl4DOXH4xWdUc
         nEv/42aQ4ekBAn/9TjiY8agot9an3rba19bnwabeJyoUH9C991oKrNRtML2mC72UPWMa
         Tq+v5W76UED7y4u5vevPmPalUQGTllqjZimp7WKrnAP7ZalR0NgSAJl3XA2+NeMCL4A0
         NPNYbHq/NvVDq+3pXrMgIzw76BtMBXXARur/PX54oabKDj0h8D0Mvz2tc7dMn4Dde1D/
         h8hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707270334; x=1707875134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=B0z2+30lwkLfGm53OYzGTU9bi+N2j4hJS9WMdSlWbYM=;
        b=IeTbHyHFx4qAcHhwNoopnQGkE9KTCT4sWorAaz+Eq/LpDBsV5QwpMU0ZCTWQIIZWr7
         5nXyizD/UER7m9DDa+mogYK9pBo2s4kJN4amHUdP58f0FWZKEitcRtKToOF1xqvvX5IO
         hGHIipwwtgmIB/meaTs1a5+T3BQssp3NbMV32h5JITGw/Zgj5uJf+BMEbS6+I1Ghw7xh
         ClB9S4RzveFyOSNVfO9dwWiLD0UcFos9TsRMDvCdqNCljsQbh0+vdXiwYL+nBnwJu1x3
         OnkRPv0axJhbihnIqGtSwhn+knZY0LknDz1Q4b4v11xGehJnGDvvD2+sV5BcJkjGCjW+
         LlKg==
X-Gm-Message-State: AOJu0Yz1Cp+bSbBfCvVeakUiDG7fluzK5aSERVIiAWuK0jB41sVg4eyZ
	kyjRaVicQml1p42bauIToADJ+HghFg4a3gwTvWTyXwqvzxlf/zt3
X-Google-Smtp-Source: AGHT+IF79Tm0G8QrcbnwwpuFT2IWhvs9gvutBFjblkE7qflnU2ji9G9X9o55UZ/g1b2npv4etn0DuQ==
X-Received: by 2002:a05:6214:c48:b0:68c:62e2:65bd with SMTP id r8-20020a0562140c4800b0068c62e265bdmr5291047qvj.46.1707270334475;
        Tue, 06 Feb 2024 17:45:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5ced:0:b0:68c:5c2d:cae9 with SMTP id iv13-20020ad45ced000000b0068c5c2dcae9ls243917qvb.2.-pod-prod-05-us;
 Tue, 06 Feb 2024 17:45:33 -0800 (PST)
X-Received: by 2002:a05:6102:cd1:b0:46b:182:99f2 with SMTP id g17-20020a0561020cd100b0046b018299f2mr1454653vst.22.1707270333289;
        Tue, 06 Feb 2024 17:45:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707270333; cv=none;
        d=google.com; s=arc-20160816;
        b=ptq26TL20qkXPuW07PpoUa3YWWY5pQL31GVp4vR2EHfDfWou7a7GK1JW8hMJeuwRL8
         RPr/wMfUvfZLcrRQVkCxx6f/OoXjNw6tEuTxTYKHIB7pnFGDqZ4yCGRDK4LwA9VPlP5j
         G1/xtlg+4eyOAq69+LHpuAdqpLywQwz6kQuN3DBgTNzdJWCjaoMd+cNyBubj7aZYRU+L
         AsMz7IIicyFIlhIrnEcR+yKTpXsTj8vyxLVOEl9KMrgM3LCiNNC6B9G1tymTrKCRqqIN
         +e683uVLuf1bhcSMvg0W+88kvfHUdL81YU2YDAx5srgn5+NEhngUvFsIyuiAgnMUub+Z
         b0LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=i0KokQpsmVwCg2q3ckhuoiEueFde0IBUJuEJrRWd9+k=;
        fh=lqzh0YxZ3/mUqJtMQMM61OnrcqupTHF5EIGh4kZFUIQ=;
        b=da/WhtSHMyIh7Tv7kV6b+5TOYuhLFSENSnsTPeUAnitp8e9z8PnYQ0ZUPkT46mUJ+B
         z/bc1qZwrwZjLmndApwRC6zDdljTKrfSDF8Cyp0kBEFSKtxIFshCngIbfTgF4v2iehc5
         b0pAobi+IkKdziQPvxDW1h9/AQQsmSE4WQvktDGmzAEIuuaJCjRM2jnq1ktOb5eIPpUY
         YJmvKhaRfRfPz+uOr4oI7jxlKGXbengpFtZOzMrC1cRWiG9Yeve3QeeD4hn1QnoBBdBv
         jf7qTeNYWh0Vy31OowYYs+dZrtatOe7sTJONXswt/vpLk+R4a7nCRGIXL5roJFqR7zQZ
         FvwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Bgazqmz2;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCV8djoFadsUAoEmClP+D+GOn6BeOM3fmVcx/0eLxRI/zj0yZMKDpqXSvU/4vRopU9Qf2+zYAp7ghqVRpVWdHMiE9s8b4nD/J0v7jA==
Received: from mail-io1-xd2f.google.com (mail-io1-xd2f.google.com. [2607:f8b0:4864:20::d2f])
        by gmr-mx.google.com with ESMTPS id g11-20020ab0244b000000b007d698d5b1e8si18245uan.2.2024.02.06.17.45.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Feb 2024 17:45:33 -0800 (PST)
Received-SPF: pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2f as permitted sender) client-ip=2607:f8b0:4864:20::d2f;
Received: by mail-io1-xd2f.google.com with SMTP id ca18e2360f4ac-7c029beb8c9so5644639f.0
        for <kasan-dev@googlegroups.com>; Tue, 06 Feb 2024 17:45:33 -0800 (PST)
X-Received: by 2002:a05:6602:1d52:b0:7be:f7e5:44fc with SMTP id hi18-20020a0566021d5200b007bef7e544fcmr5190362iob.21.1707270332593;
        Tue, 06 Feb 2024 17:45:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXgz0Bk3pqC37J5ry8Hitp4ra1NniLz7Y4v4Tphxf7iyTTW6uwWCALufaKvyh/+5X5pf8Ci3B/VwE4erM2dw7wNGsJN3BkWwQlckmsz+kD8rvAdJRrqdbfDHi7qI5NJ4SclpKgfkKskYgAe+Sgt+/8W+gy28AbW1X1tzm4ESG5ATlNDk+jetgjB5tbXMcK7/2YB7Spu6APCEKEq0JmT74M822R/XzG2ZYcvtXX4U3J/DohfzcR+IJ5j72zJ8fw37StRaKCVYftVKCQSzDicQNNK6PgzuE+DTJWrzuFLPDnwFqltv9slz53wterU3tt7jpG3HVknYUaq4+8UqKXEOa4HXUzpN2FuVoRQzByHikOw7ZTsEBeT2loLAmQ7991loj6fFB3yfkAr0YPCR1FjRjTkeMZKGISsAww5F7vouc9oR1sVxgjfAzAxHRi2hXzaemmLtz2BjUeG2owFlfGUo6lTAkZRtDDwwNYQ8PjUWnc1e/it9sD9+cb/dBJ8ADio1ra6HwSznQM=
Received: from google.com (20.10.132.34.bc.googleusercontent.com. [34.132.10.20])
        by smtp.gmail.com with ESMTPSA id ed7-20020a056638290700b004713a02614bsm29995jab.10.2024.02.06.17.45.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Feb 2024 17:45:31 -0800 (PST)
Date: Wed, 7 Feb 2024 01:45:28 +0000
From: "'Justin Stitt' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>
Cc: Marco Elver <elver@google.com>, Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>, Hao Luo <haoluo@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Przemek Kitszel <przemyslaw.kitszel@intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org
Subject: Re: [PATCH v3] ubsan: Reintroduce signed overflow sanitizer
Message-ID: <20240207014528.5byuufi5f33bl6e2@google.com>
References: <20240205093725.make.582-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240205093725.make.582-kees@kernel.org>
X-Original-Sender: justinstitt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Bgazqmz2;       spf=pass
 (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2f
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

On Mon, Feb 05, 2024 at 01:37:29AM -0800, Kees Cook wrote:
> In order to mitigate unexpected signed wrap-around[1], bring back the
> signed integer overflow sanitizer. It was removed in commit 6aaa31aeb9cf
> ("ubsan: remove overflow checks") because it was effectively a no-op
> when combined with -fno-strict-overflow (which correctly changes signed
> overflow from being "undefined" to being explicitly "wrap around").
>
> Compilers are adjusting their sanitizers to trap wrap-around and to
> detecting common code patterns that should not be instrumented
> (e.g. "var + offset < var"). Prepare for this and explicitly rename
> the option from "OVERFLOW" to "WRAP".
>
> To annotate intentional wrap-around arithmetic, the add/sub/mul_wrap()
> helpers can be used for individual statements. At the function level,
> the __signed_wrap attribute can be used to mark an entire function as
> expecting its signed arithmetic to wrap around. For a single object file
> the Makefile can use "UBSAN_WRAP_SIGNED_target.o := n" to mark it as
> wrapping, and for an entire directory, "UBSAN_WRAP_SIGNED := n" can be
> used.
>
> Additionally keep these disabled under CONFIG_COMPILE_TEST for now.
>
> Link: https://github.com/KSPP/linux/issues/26 [1]
> Cc: Justin Stitt <justinstitt@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Miguel Ojeda <ojeda@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Peter Zijlstra <peterz@infradead.org>
> Cc: Hao Luo <haoluo@google.com>
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
> v3:
>  - split out signed overflow sanitizer so we can do each separately
> v2: https://lore.kernel.org/all/20240202101311.it.893-kees@kernel.org/
> v1: https://lore.kernel.org/all/20240129175033.work.813-kees@kernel.org/
> ---
>  include/linux/compiler_types.h |  9 ++++-
>  lib/Kconfig.ubsan              | 14 +++++++
>  lib/test_ubsan.c               | 37 ++++++++++++++++++
>  lib/ubsan.c                    | 68 ++++++++++++++++++++++++++++++++++
>  lib/ubsan.h                    |  4 ++
>  scripts/Makefile.lib           |  3 ++
>  scripts/Makefile.ubsan         |  3 ++
>  7 files changed, 137 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 6f1ca49306d2..ee9d272008a5 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -282,11 +282,18 @@ struct ftrace_likely_data {
>  #define __no_sanitize_or_inline __always_inline
>  #endif
>
> +/* Do not trap wrapping arithmetic within an annotated function. */
> +#ifdef CONFIG_UBSAN_SIGNED_WRAP
> +# define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
> +#else
> +# define __signed_wrap
> +#endif
> +
>  /* Section for code which can't be instrumented at all */
>  #define __noinstr_section(section)					\
>  	noinline notrace __attribute((__section__(section)))		\
>  	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
> -	__no_sanitize_memory
> +	__no_sanitize_memory __signed_wrap
>
>  #define noinstr __noinstr_section(".noinstr.text")
>
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index 56d7653f4941..129e9bc21877 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -116,6 +116,20 @@ config UBSAN_UNREACHABLE
>  	  This option enables -fsanitize=unreachable which checks for control
>  	  flow reaching an expected-to-be-unreachable position.
>
> +config UBSAN_SIGNED_WRAP
> +	bool "Perform checking for signed arithmetic wrap-around"
> +	default UBSAN
> +	depends on !COMPILE_TEST
> +	depends on $(cc-option,-fsanitize=signed-integer-overflow)
> +	help
> +	  This option enables -fsanitize=signed-integer-overflow which checks
> +	  for wrap-around of any arithmetic operations with signed integers.
> +	  This currently performs nearly no instrumentation due to the
> +	  kernel's use of -fno-strict-overflow which converts all would-be
> +	  arithmetic undefined behavior into wrap-around arithmetic. Future
> +	  sanitizer versions will allow for wrap-around checking (rather than
> +	  exclusively undefined behavior).
> +
>  config UBSAN_BOOL
>  	bool "Perform checking for non-boolean values used as boolean"
>  	default UBSAN
> diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
> index f4ee2484d4b5..276c12140ee2 100644
> --- a/lib/test_ubsan.c
> +++ b/lib/test_ubsan.c
> @@ -11,6 +11,39 @@ typedef void(*test_ubsan_fp)(void);
>  			#config, IS_ENABLED(config) ? "y" : "n");	\
>  	} while (0)
>
> +static void test_ubsan_add_overflow(void)
> +{
> +	volatile int val = INT_MAX;
> +
> +	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
> +	val += 2;
> +}
> +
> +static void test_ubsan_sub_overflow(void)
> +{
> +	volatile int val = INT_MIN;
> +	volatile int val2 = 2;
> +
> +	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
> +	val -= val2;
> +}
> +
> +static void test_ubsan_mul_overflow(void)
> +{
> +	volatile int val = INT_MAX / 2;
> +
> +	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
> +	val *= 3;
> +}
> +
> +static void test_ubsan_negate_overflow(void)
> +{
> +	volatile int val = INT_MIN;
> +
> +	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
> +	val = -val;
> +}
> +
>  static void test_ubsan_divrem_overflow(void)
>  {
>  	volatile int val = 16;
> @@ -90,6 +123,10 @@ static void test_ubsan_misaligned_access(void)
>  }
>
>  static const test_ubsan_fp test_ubsan_array[] = {
> +	test_ubsan_add_overflow,
> +	test_ubsan_sub_overflow,
> +	test_ubsan_mul_overflow,
> +	test_ubsan_negate_overflow,

I wouldn't mind also seeing a test_ubsan_div_overflow test case here.

It has some quirky behavior and it'd be nice to test that the sanitizers
properly capture it.

Check out this Godbolt: https://godbolt.org/z/qG5f1j6n1

tl;dr: with -fsanitize=signed-integer-overflow division (/) and
remainder (%) operators still instrument arithmetic even with
-fno-strict-overflow on.

This makes sense as division by 0 and INT_MIN/-1 are UBs that are not
influenced by -fno-strict-overflow.

Really though, the patch is fine and the above test case is optional and
can be shipped later -- as such:

Reviewed-by: Justin Stitt <justinstitt@google.com>

>  	test_ubsan_shift_out_of_bounds,
>  	test_ubsan_out_of_bounds,
>  	test_ubsan_load_invalid_value,
> diff --git a/lib/ubsan.c b/lib/ubsan.c
> index df4f8d1354bb..5fc107f61934 100644
> --- a/lib/ubsan.c
> +++ b/lib/ubsan.c
> @@ -222,6 +222,74 @@ static void ubsan_epilogue(void)
>  	check_panic_on_warn("UBSAN");
>  }
>
> +static void handle_overflow(struct overflow_data *data, void *lhs,
> +			void *rhs, char op)
> +{
> +
> +	struct type_descriptor *type = data->type;
> +	char lhs_val_str[VALUE_LENGTH];
> +	char rhs_val_str[VALUE_LENGTH];
> +
> +	if (suppress_report(&data->location))
> +		return;
> +
> +	ubsan_prologue(&data->location, type_is_signed(type) ?
> +			"signed-integer-overflow" :
> +			"unsigned-integer-overflow");
> +
> +	val_to_string(lhs_val_str, sizeof(lhs_val_str), type, lhs);
> +	val_to_string(rhs_val_str, sizeof(rhs_val_str), type, rhs);
> +	pr_err("%s %c %s cannot be represented in type %s\n",
> +		lhs_val_str,
> +		op,
> +		rhs_val_str,
> +		type->type_name);
> +
> +	ubsan_epilogue();
> +}
> +
> +void __ubsan_handle_add_overflow(void *data,
> +				void *lhs, void *rhs)
> +{
> +
> +	handle_overflow(data, lhs, rhs, '+');
> +}
> +EXPORT_SYMBOL(__ubsan_handle_add_overflow);
> +
> +void __ubsan_handle_sub_overflow(void *data,
> +				void *lhs, void *rhs)
> +{
> +	handle_overflow(data, lhs, rhs, '-');
> +}
> +EXPORT_SYMBOL(__ubsan_handle_sub_overflow);
> +
> +void __ubsan_handle_mul_overflow(void *data,
> +				void *lhs, void *rhs)
> +{
> +	handle_overflow(data, lhs, rhs, '*');
> +}
> +EXPORT_SYMBOL(__ubsan_handle_mul_overflow);
> +
> +void __ubsan_handle_negate_overflow(void *_data, void *old_val)
> +{
> +	struct overflow_data *data = _data;
> +	char old_val_str[VALUE_LENGTH];
> +
> +	if (suppress_report(&data->location))
> +		return;
> +
> +	ubsan_prologue(&data->location, "negation-overflow");
> +
> +	val_to_string(old_val_str, sizeof(old_val_str), data->type, old_val);
> +
> +	pr_err("negation of %s cannot be represented in type %s:\n",
> +		old_val_str, data->type->type_name);
> +
> +	ubsan_epilogue();
> +}
> +EXPORT_SYMBOL(__ubsan_handle_negate_overflow);
> +
> +
>  void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
>  {
>  	struct overflow_data *data = _data;
> diff --git a/lib/ubsan.h b/lib/ubsan.h
> index 5d99ab81913b..0abbbac8700d 100644
> --- a/lib/ubsan.h
> +++ b/lib/ubsan.h
> @@ -124,6 +124,10 @@ typedef s64 s_max;
>  typedef u64 u_max;
>  #endif
>
> +void __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
> +void __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
> +void __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
> +void __ubsan_handle_negate_overflow(void *_data, void *old_val);
>  void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
>  void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
>  void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
> diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
> index 52efc520ae4f..7ce8ecccc65a 100644
> --- a/scripts/Makefile.lib
> +++ b/scripts/Makefile.lib
> @@ -177,6 +177,9 @@ ifeq ($(CONFIG_UBSAN),y)
>  _c_flags += $(if $(patsubst n%,, \
>  		$(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_SANITIZE)y), \
>  		$(CFLAGS_UBSAN))
> +_c_flags += $(if $(patsubst n%,, \
> +		$(UBSAN_WRAP_SIGNED_$(basetarget).o)$(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_WRAP_SIGNED)$(UBSAN_SANITIZE)y), \
> +		$(CFLAGS_UBSAN_WRAP_SIGNED))
>  endif
>
>  ifeq ($(CONFIG_KCOV),y)
> diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
> index 7cf42231042b..bc957add0b4d 100644
> --- a/scripts/Makefile.ubsan
> +++ b/scripts/Makefile.ubsan
> @@ -13,3 +13,6 @@ ubsan-cflags-$(CONFIG_UBSAN_ENUM)		+= -fsanitize=enum
>  ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
>
>  export CFLAGS_UBSAN := $(ubsan-cflags-y)
> +
> +ubsan-wrap-signed-cflags-$(CONFIG_UBSAN_SIGNED_WRAP)     += -fsanitize=signed-integer-overflow
> +export CFLAGS_UBSAN_WRAP_SIGNED := $(ubsan-wrap-signed-cflags-y)
> --
> 2.34.1
>

Thanks
Justin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240207014528.5byuufi5f33bl6e2%40google.com.
