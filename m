Return-Path: <kasan-dev+bncBC7OBJGL2MHBB25S37CQMGQES5YBGTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 75737B41493
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 08:00:15 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-61e12e5e9bbsf3669700eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 23:00:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756879212; cv=pass;
        d=google.com; s=arc-20240605;
        b=ASR9ihVZAByxTcL6uGphDuUr2FeQu/geO2aC9Z4ryji1/QDO3q4GbWHL4ENq/dMVOM
         oiHjvKlByhr9ZitBuBAiU/CLjFdaLJCWrwp7og7VOEiNjXg03kY7dLprS64URcCpVu0h
         SN1KpZs2a1j5jVnPY7iJtZX5In/KiNe7kpAJEbSrlkhn5msnNY7MaW1MRLPBiVUx7a0l
         Tnic58SHQHMK/WsghCkHR9FpHDA35xFfJyYcYKz1naeI29xQXKYsuRc2QG3dfQHYCIH6
         1lwQ5YpCi76fvKCpQ7eq+sfo9kVP4Dbo9TOwrAZPHTcOvySJIETG5Wc6A3R+F9AwP9rk
         BGyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qxIHpetW3lJQXwdnjAOh+fViCIEzlWU/H2zo/xkoY2w=;
        fh=acKPry6E/azsfbrpFJrMrr19IQBCjGSuP36yk3LZuIc=;
        b=cbumdqK7+XGSwPZfdKT8LmwKHIqwLVxexzaKckLw5oSV7CMXKnTpnJDxglHNgGtEM0
         0d9Fo0wqSWe7AmzdDeiYL6TdFw4Q87y36jTUlWEACg3rrDVcs+NTnUN7bLFysmcsqeit
         Wm/q5YLF/5XWxN+nBsGh1ZZjAXEhXCSSolvZa4Hrlx3ffDZw3ZvqbfRcbACwKMLudomi
         cEcVC0Tn5lPOXGt5H+SntgAfZKvlYV/TF2PdUZIIwGK4+mYTAyzR2uJxwiTC1JsE+7Y6
         q5o/vMI7pKyIBiB5wgr5YsRgGu74tVooQtv9EYHw2YvEPwNx8zcAWMZ2+fZWIICfAt5n
         7OrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vhmTD9Gy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756879212; x=1757484012; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qxIHpetW3lJQXwdnjAOh+fViCIEzlWU/H2zo/xkoY2w=;
        b=Abzj6waf6pHHXOI8YVGLgOXvaTmwNC3AKumHiqO4n2YH7eRVzkAgCh1mpWIzEzViFl
         spX+sLI6ktZKshWyuiKrN7l2oLALD6MLshMHxdWji5YfdgAG4iecJmUyF0/5ek0k3ceA
         dPUzX9eOWntaDz7d+KkKVioPalc578ic17caSN2ra28DdM8R0Vxoo/ygPaAfrOqaBEcP
         N92PAVxKf5QcNW1L5ShKeYdfNVbWWS0qRKdVnQMvgpI2o7IOqlVKtrIwTGcreeuD3COL
         CmHVGOxKmGgIDBIdmEsrhQY05qvhvFUu+GIg+EULduV5BjX0rbgQog2aiewrwajsSzmy
         Lcjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756879212; x=1757484012;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qxIHpetW3lJQXwdnjAOh+fViCIEzlWU/H2zo/xkoY2w=;
        b=WW5xhccEloyg4RRW/27Jxmg0dVl9tZpXY1+tr3vpkj15wvlBQzhTkk3iUmaj6GJWVV
         74W8+oFfgDvWgx/DU0/xD6+Hn4dUEpRuzrz3G+KPFlY0Xe8nTQCBKrnrYI5/viyFlVB/
         6VFaoOLpWl1W97N4KI8jNP/q9cUhLJZMHmSfBAPBPzTAvUEpXpbmZ+CZzPQzAGKykvtn
         O4opdWDjoFod0oAa+kZ96YKIINOMSpeRPZ3dJQQS4Ll6GCAnGjdmuK0eLEIVrfRWyaU9
         lau6UwDHLU7ZA/zeR/pa9Y7MJ6PfEf7xTSineinVITpmdMgr1mLGVXWdoDxn8tLhwlmL
         L+pQ==
X-Forwarded-Encrypted: i=2; AJvYcCXxHj4HeRi+jmlXE1YvcbRIdFdO8fE4LWihh99ar2eNih1NoJ6rAN+tU6PjPcPnthcYuop/cQ==@lfdr.de
X-Gm-Message-State: AOJu0YzuEd1gV6R0j4ZtisLJhBA05XDE8cVHp7xsXSG4wfoxEqcbwg2m
	GVYztt+9XvJXlW5Ltk14s8CmaueIYIg9UbiUXB0o+e4a4eTMKVTvl6FX
X-Google-Smtp-Source: AGHT+IEqf5vH/bJ3sFqpUH+TYvtLdYMvSU0GN2EW34AXnOLSzJMgQZupmq2AiTCvMiEOo/HYfzdTJQ==
X-Received: by 2002:a05:6820:1609:b0:61e:1b97:149b with SMTP id 006d021491bc7-61e3376c50amr7133785eaf.7.1756879211844;
        Tue, 02 Sep 2025 23:00:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeBoaPy2bJi+C+sL2A4bJdpiargCoe38M1o6g0iPiiQ+Q==
Received: by 2002:a05:6820:4614:b0:61d:f8d4:b32a with SMTP id
 006d021491bc7-61e1271c1c3ls1757637eaf.1.-pod-prod-09-us; Tue, 02 Sep 2025
 23:00:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVivmH2953Y715v8TGO7bm70OA3siMKkq2qs+Aqr+XhbKqnPXeCBCaBMZT4gEJYYzhQwcGUzFf4NI0=@googlegroups.com
X-Received: by 2002:a05:6830:65d2:10b0:745:9272:4a42 with SMTP id 46e09a7af769-74592724eefmr1209517a34.24.1756879210717;
        Tue, 02 Sep 2025 23:00:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756879210; cv=none;
        d=google.com; s=arc-20240605;
        b=SRTgt99v3qpFXyLIU05K8XB6hE2YVoj+mcE9Hv3Gh3e2MQMKgbYqAVXOYdmTfLKImh
         qAnrdhyTtdNi289EAZ3rLbJaHLSCWXryGCFKD4pF82a7+oVaia+tBQMb3qU1zNepPsSo
         uBxbSOhYCrbiMK2ne/5wKaDfqmXCEMcAePinOb1eksqLYf/Z8OmoK+56FYycHfrAnCck
         42dVhdvu5cmaGRvjva3E5eRaTz7l41TcUrkyFFyzH0tJ5JL4TAEQ49ug9Km3fk/9wagn
         rdK/bfzi4tLuBhELER422DTSg0D5WlRk+PpY7sBBPN+vqNwcrfYVqaZzQ8zsK04OvIHm
         i4Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FdC3QTxmU3besuQLS5g8tc+09uf1KenOXC1aPNt3jcA=;
        fh=gSI/LVmk3wcHT8LAxbHNaGw0PZw0vnwLXeLvpjQrSj4=;
        b=ixNe9FK6Jm5EnUb30LBYCu1zD/IeHVBkG3G3Qj7/UynMxxWhDQcRtHqyeVJHvWyYe1
         jX4RIlabguL0lVQNmy6JppGkkdO6cry4mdeC6xap79JIhK2G9BPUPdcMZlzv6c45hvW9
         bwSZP91j0NG4HU4LjdZIRBMPQKyZWcsfAX5finyK8cEWJ/jpfJYODjtAtKhRyzQRs9yT
         oV3bhSRighqzZRutkPwyCEW7JCVUzfcj71xy+0DiqmmvFijR2Ujz0/2obGm8hENqsIFs
         +JST0T60ibrD7TyXOjhkn6Bblgj+M2H19W1lATYtB7bCvvBBfBsaK0msRG5Fkfmgy8hY
         3pWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vhmTD9Gy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61e31dbf0fbsi380472eaf.1.2025.09.02.23.00.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Sep 2025 23:00:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-24a9cc916b3so32567935ad.0
        for <kasan-dev@googlegroups.com>; Tue, 02 Sep 2025 23:00:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWaiAQwP7d/uXA4fJSgZJ68ZRJVfxO0iPTloFR5FtbgmvX+u7k9dN4+J6dtrqh7golUbhwxxtiCsxQ=@googlegroups.com
X-Gm-Gg: ASbGnctIV2fbJZKtHSAgnN/P2313t2wJCiiJ1O0/EKOAEOkYuTrGlnOWTHh7ZdQGz8F
	WSplL/4hvVVieiS45D9a4Pi+gXZIMtQWEoWx8KOHsIpeiyneZbD5AqO69rOpDvJTyp10t7UB2nK
	LpL5iEixBLAWd1fxr4aVg1TY4vdhr+OuiXEcSvZpG1Cjhqj0KQyD+ReMq7tjY0CZqpHPe7ZgAWt
	eRwQFni+Dg10/OI/CuUeeZVQOj5JW52fpmAGNhlIIhv6Q==
X-Received: by 2002:a17:902:d543:b0:246:4077:456f with SMTP id
 d9443c01a7336-24944b35030mr172147985ad.58.1756879209794; Tue, 02 Sep 2025
 23:00:09 -0700 (PDT)
MIME-Version: 1.0
References: <20250903000752.GA2403288@ax162>
In-Reply-To: <20250903000752.GA2403288@ax162>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Sep 2025 08:00:00 +0200
X-Gm-Features: Ac12FXy7vOsop2eZcEJ8r-sYpuE381OhvdK3KJiYzgxTh4KO44xvrZCKXVwkZ5E
Message-ID: <CANpmjNNV=ZmjcGWvPwHz+To6qVE4s=SY0CrcXFbizMeBrBaX4g@mail.gmail.com>
Subject: Re: clang-22 -Walloc-size in mm/kfence/kfence_test.c in 6.6 and 6.1
To: Nathan Chancellor <nathan@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vhmTD9Gy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as
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

On Wed, 3 Sept 2025 at 02:07, Nathan Chancellor <nathan@kernel.org> wrote:
>
> Hi kfence folks,
>
> After [1] in clang, I am seeing an instance of this pop up in
> mm/kfence/kfence_test.c on linux-6.6.y and linux-6.1.y:
>
>   mm/kfence/kfence_test.c:723:8: error: allocation of insufficient size '0' for type 'char' with size '1' [-Werror,-Walloc-size]
>     723 |         buf = krealloc(buf, 0, GFP_KERNEL); /* Free. */
>         |               ^
>
> I do not see this in linux-6.12.y or newer but I wonder if that is just
> because the memory allocation profiling adds some indirection that makes
> it harder for clang to perform this analysis?

It shouldn't, there's still a direct call:

  > void * __must_check krealloc_noprof(const void *objp, size_t new_size,
  >                                     gfp_t flags) __realloc_size(2);
  > #define krealloc(...)
alloc_hooks(krealloc_noprof(__VA_ARGS__))

> Should this warning just be silenced for this translation unit or is
> there some other fix that could be done here?

It should be silenced. I'm surprised that they'd e.g. warn about
malloc(0), which is well defined, and in the kernel, we also have
0-sized kmalloc (incl krealloc) allocations being well-defined. As
long as the returned pointer isn't used, there's no UB. I guess doing
an explicit 0-sized alloc is not something anyone should do normally I
guess, so the warning ought to prevent that, but in the test case we
explicitly want that.

> [1]: https://github.com/llvm/llvm-project/commit/6dc188d4eb15cbe9bdece3d940f03d93b926328c
>
> Cheers,
> Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNV%3DZmjcGWvPwHz%2BTo6qVE4s%3DSY0CrcXFbizMeBrBaX4g%40mail.gmail.com.
