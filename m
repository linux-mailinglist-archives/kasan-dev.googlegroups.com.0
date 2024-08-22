Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBUETW3AMGQETAIJJBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 65DD595B74B
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Aug 2024 15:50:00 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-270183411aasf904201fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Aug 2024 06:50:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724334599; cv=pass;
        d=google.com; s=arc-20160816;
        b=tVddHhIf9ieXgGelPyXMD09FhrLwG1GYxK8KpKC6XPslRz7p23JVw84zpSswLmedVW
         ejt3X+fdGsCK9pC+FffndR4W+mT0C3NnlHy8EsV+94HY+vAFV4i752IiMml9Xzz12nqZ
         Df+Vq7bWOt5ZhLLA/1optc4Y/87vXNVScX//BHYd6wgxEx4g5pHcO5D5xAc85eGjrNfr
         kUOFQ4KhnLz0CgR9ntMUeSVPBVTlCPflveOxG49FYBAm6tjWBqFZLIesCJFSSKA/6nZn
         nDwQbMp3y49hThjPuqSD/FSuYwzZ7mXEjvKzUuUN7FSO0KO8JGlJ3kKZeuaSuEf0NH4Y
         mTyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YvccAddnKURj99eSVay6mOD9zlJ42pIThZw6KMUvnDM=;
        fh=bqp4GWZYu6HRjszWXvdXC8JgHMyoD0pvmG/saFRcqK8=;
        b=BXf1DDSEpLXx77bwtRtWUKHsw1DoUAME8jV1l/vG/rYZVJmbBajlqEXc29YOLwW70A
         V1TulSROyucRRyeBcBsyJf22BLlEmuhag4ob4FOpVwFZmIHarqmUjK1CbvYxUggoqqhX
         rn4+Xo8fS8EH8U1Z2pvvEOGZZLfmnTYEVNhW72uK+JUgi3GopXLs/OrWW26G4cTDM5YM
         Khg+KhmtENoADkiUTZTI2drkg3/YCJ0W1Lw6FXS9dWIMV5++kzwuOvkQU3Rtm6p/JD3T
         zzjmnN4foQAY3Xrx/8C6VNb2MjW5TPIR9HfHEZsCxamty8OzOF0jUBiyQ+xDaJQDbWfi
         vx1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UYuXQZgk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724334599; x=1724939399; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YvccAddnKURj99eSVay6mOD9zlJ42pIThZw6KMUvnDM=;
        b=O19V/1ALIVNusTlBxnyKPJmWb0QVGpmR5+W5MdVQi8TUcS9yClEwWHslr6xhQB6DQa
         zc3EAYJUIUiBP2OMKSQnz73PUKDiwJbFpdtjijPOKq8lTbw07JMeH+ggeJ1Uhts6qWAe
         aIAbg9ChADnRLJnsPUp2FvlpXiuGVgLzXnHmJP6SBo20CoNBJm1FBTOgsjyce/Qn95cC
         T1NyxSi1lySouya8o+tuxeHHxPxW2NFlcksu75ZsC24PtHiS+NmEOY66Ddu75UUrxxRs
         Vzv6K5YxUsUqnFSLjX+rdPCUFdfEZ5uX0MR4jyXIVrDUpRgF81w5pmqZTtaa4KhVi2E0
         2qKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724334599; x=1724939399;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YvccAddnKURj99eSVay6mOD9zlJ42pIThZw6KMUvnDM=;
        b=YxB2Q2kN2lQdgeadPXJ/HFxKmvjRmJ6Gqs2ZB964fzG/KOJRVwAaguzcKK2kXwEMVZ
         Ffu2VDyb+3B8FGXmGmGnyrtbg2rg4miiSVkQ9Pej81cHuJRY607bfGetjVxQxAgYYMHZ
         EpciH8Pf+XlPAF7EEMNtU5VV3phUhB0cdrAK1N1AZTREz9saUhLyAA0lKnO2dSAcLpBE
         2E/dfVL7xLOl8mMc3nyyMaRa2mMiMvyDgLZNO0YDNm8/13+x3exNqGFnL+1ovVorNKsG
         pY72t8/cWic8dmyz18eUK2wsDjl61Zv6NoG2jZ1qah6hON/lS3JDM4QEzcN6MSKvq2n9
         2OqQ==
X-Forwarded-Encrypted: i=2; AJvYcCUFGavnss5gk9jwdw0hVHSyWMDuZOFE3sKjVO7JaM1TImxPVsDaMgEfp2V135jv/z8mX+6+xw==@lfdr.de
X-Gm-Message-State: AOJu0YyRflq8rEloshwHpx+mZfUBSA1BQhl0wUo6Ej1ObtgsEsVgXun0
	KjmMG2Ao6odQNqjhu37XPbOXF7ZFoN7eY3PeD5D6drf4ZA/DWrzJ
X-Google-Smtp-Source: AGHT+IEcSgIFYFITQzlzGJZRhWEnYHUsV99poDkNeGeLxAsxz7AEv8OCTE9Ig9loy4URnDLSgUZv/w==
X-Received: by 2002:a05:6871:829:b0:260:f43e:7d89 with SMTP id 586e51a60fabf-2737eece6b6mr5843582fac.2.1724334599044;
        Thu, 22 Aug 2024 06:49:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1887:b0:714:2859:13fd with SMTP id
 d2e1a72fcca58-7143337d589ls712295b3a.1.-pod-prod-07-us; Thu, 22 Aug 2024
 06:49:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQUFXknxx3Nk5OFE6DHGzuw6J9JF6pjdIrLP8onp/ltV8iwZnyNlC3Mw8WranC1fRfucHllnf6xVo=@googlegroups.com
X-Received: by 2002:a17:90b:104b:b0:2d3:c976:dd80 with SMTP id 98e67ed59e1d1-2d5ea2ca713mr6264123a91.39.1724334597623;
        Thu, 22 Aug 2024 06:49:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724334597; cv=none;
        d=google.com; s=arc-20240605;
        b=flnm7k0quAHa4C23ksDazbA07CasKuFczN/6Sp3rQQH616VUDKM+mC16I+/4yjbhJK
         nED1Z3vLOksAea8mXMsbRcvJ5dXZnlHBJOvCvitiraDQfjwVKL6ikYqj1Gxo9ujYGTii
         1GjL3HzPmvqo9kt4+DrDPXn/Au2Wv1/cy+KZebAu98rcV3lsvSMd2lO7zkB7Cuj+VdWJ
         nGALs6oIQ+bqU33Aom1+3kYbid0897Dc6uXVa3Sn7KLg98NDiqwQ2n+lj3DGMaqXnJOR
         uQDwJfsgWg0n+KBMhf/ZkbEtU+1unfV4MvoPRV6/K4+zuSVqJGqbSiR/uAJFSJJ/lFwx
         Dwlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6ppKkVe0CCoZvohxPx6OHDazO83RnHbxwEsZp1jfSt0=;
        fh=PdRgGB70zkArIsoejMJFXfsIHd9AXw+Ruy2YO9r9rkw=;
        b=Izs9WCSxzMtg2SISGGvN4u/XDMn2fiZYmeDJpp4ozSnVqx7AH9kj28nH/N37GFw1iS
         T+wQpX6jGJt92bkYFgQc7wnLZEPw7ltTZvxTrH/zAfmoeLjIEN+lAWr06obfTYM6sq+p
         8fI8VE8lXfU6rE9oimr+5rEs2n2hs/kFWjKv7Z1+yS2IV93MVTOKdmuyAqWHYRFDNO6s
         UqiDlxpezHT7JBaoItcBiII7uchlnw2cmq4yHmfdbhOLkaMc5RAJnLvlvLRZz+NHQaYo
         Jh6dQO1/NJ+H1accYkdA20LP8ZXQCkhhx8UK118ZjvfQsvUBTkQ1RP1tk1xv0/4rpEx4
         ugTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UYuXQZgk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x936.google.com (mail-ua1-x936.google.com. [2607:f8b0:4864:20::936])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d5c2e164a8si323529a91.1.2024.08.22.06.49.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Aug 2024 06:49:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) client-ip=2607:f8b0:4864:20::936;
Received: by mail-ua1-x936.google.com with SMTP id a1e0cc1a2514c-844bf4b5051so247215241.3
        for <kasan-dev@googlegroups.com>; Thu, 22 Aug 2024 06:49:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWWusF1MEoETpjVNWbKyuI6L/06h35LYneVfFYNRY+0zNJAEwAWeWBSOWB7Eha6LvMLEETUqMk2J/E=@googlegroups.com
X-Received: by 2002:a05:6122:3125:b0:4ed:145:348f with SMTP id
 71dfb90a1353d-4fcf1b64a4fmr8813741e0c.12.1724334596612; Thu, 22 Aug 2024
 06:49:56 -0700 (PDT)
MIME-Version: 1.0
References: <20240814161052.10374-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240814161052.10374-1-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Aug 2024 15:49:18 +0200
Message-ID: <CANpmjNM7p8-U1eh7m4vCh5M7pKODHExzw0EVtOXQRu-udb7qaA@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: simplify and clarify Makefile
To: andrey.konovalov@linux.dev
Cc: Matthew Maurer <mmaurer@google.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UYuXQZgk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 14 Aug 2024 at 18:11, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> When KASAN support was being added to the Linux kernel, GCC did not yet
> support all of the KASAN-related compiler options. Thus, the KASAN
> Makefile had to probe the compiler for supported options.
>
> Nowadays, the Linux kernel GCC version requirement is 5.1+, and thus we
> don't need the probing of the -fasan-shadow-offset parameter: it exists in
> all 5.1+ GCCs.
>
> Simplify the KASAN Makefile to drop CFLAGS_KASAN_MINIMAL.
>
> Also add a few more comments and unify the indentation.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Acked-by: Marco Elver <elver@google.com>

Just in case, did you test SW and HW tags modes as well?

> ---
>
> Changes v1->v2:
> - Comments fixes based on Miguel Ojeda's feedback.
> ---
>  scripts/Makefile.kasan | 45 +++++++++++++++++++++---------------------
>  1 file changed, 23 insertions(+), 22 deletions(-)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 390658a2d5b74..aab4154af00a7 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -22,30 +22,31 @@ endif
>  ifdef CONFIG_KASAN_GENERIC
>
>  ifdef CONFIG_KASAN_INLINE
> +       # When the number of memory accesses in a function is less than this
> +       # call threshold number, the compiler will use inline instrumentation.
> +       # 10000 is chosen offhand as a sufficiently large number to make all
> +       # kernel functions to be instrumented inline.
>         call_threshold := 10000
>  else
>         call_threshold := 0
>  endif
>
> -CFLAGS_KASAN_MINIMAL := -fsanitize=kernel-address
> -
> -# -fasan-shadow-offset fails without -fsanitize
> -CFLAGS_KASAN_SHADOW := $(call cc-option, -fsanitize=kernel-address \
> -                       -fasan-shadow-offset=$(KASAN_SHADOW_OFFSET), \
> -                       $(call cc-option, -fsanitize=kernel-address \
> -                       -mllvm -asan-mapping-offset=$(KASAN_SHADOW_OFFSET)))
> -
> -ifeq ($(strip $(CFLAGS_KASAN_SHADOW)),)
> -       CFLAGS_KASAN := $(CFLAGS_KASAN_MINIMAL)
> -else
> -       # Now add all the compiler specific options that are valid standalone
> -       CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
> -        $(call cc-param,asan-globals=1) \
> -        $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
> -        $(call cc-param,asan-instrument-allocas=1)
> -endif
> -
> -CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
> +# First, enable -fsanitize=kernel-address together with providing the shadow
> +# mapping offset, as for GCC, -fasan-shadow-offset fails without -fsanitize
> +# (GCC accepts the shadow mapping offset via -fasan-shadow-offset instead of
> +# a --param like the other KASAN parameters).
> +# Instead of ifdef-checking the compiler, rely on cc-option.
> +CFLAGS_KASAN := $(call cc-option, -fsanitize=kernel-address \
> +               -fasan-shadow-offset=$(KASAN_SHADOW_OFFSET), \
> +               $(call cc-option, -fsanitize=kernel-address \
> +               -mllvm -asan-mapping-offset=$(KASAN_SHADOW_OFFSET)))
> +
> +# Now, add other parameters enabled similarly in both GCC and Clang.
> +# As some of them are not supported by older compilers, use cc-param.
> +CFLAGS_KASAN += $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
> +               $(call cc-param,asan-stack=$(stack_enable)) \
> +               $(call cc-param,asan-instrument-allocas=1) \
> +               $(call cc-param,asan-globals=1)
>
>  # Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
>  # instead. With compilers that don't support this option, compiler-inserted
> @@ -57,9 +58,9 @@ endif # CONFIG_KASAN_GENERIC
>  ifdef CONFIG_KASAN_SW_TAGS
>
>  ifdef CONFIG_KASAN_INLINE
> -    instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
> +       instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
>  else
> -    instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
> +       instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
>  endif
>
>  CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
> @@ -70,7 +71,7 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
>
>  # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
>  ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
> -CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
> +       CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
>  endif
>
>  endif # CONFIG_KASAN_SW_TAGS
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM7p8-U1eh7m4vCh5M7pKODHExzw0EVtOXQRu-udb7qaA%40mail.gmail.com.
