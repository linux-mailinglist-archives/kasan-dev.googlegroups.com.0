Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFOO333AKGQEAOSHGZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BA361ED0EE
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 15:35:18 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id y24sf1566816ool.14
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 06:35:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591191317; cv=pass;
        d=google.com; s=arc-20160816;
        b=i6d/Ri/ORr+kbs2dyqA9cEAyTU734I8dpCen5fUYQxA/p6/sdt5iufPno/Ms3fKr/i
         oLmaNljSE3LtTHcWDLRKPBevkzSeOHVcALMV7jwnKz9d02tJA438iz+vCJ9Skm0zVHNu
         dy4+NMoLDBQg7tKw3q1PVaO+9XmbiESekDPImfr7Qkcj6CZecb97rVlV6vnieJkC064i
         NVKXoIvdwF0H3FBsDuD5Lb8u6N4j8orc61fpn7dbK/12LB38fxrQ2znmC4WoGHLDvOqn
         CnMcl5XmaJQO+HsZhlpMSsllYZPO/4WJXiOu7XcrJH3i9oZIhBxOlGeU6Hf39jKYZJuH
         ZMSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RBmKsozPEj1d7XrqZh9L9Hxcm5OXgMQ9lgwcq3dN5BY=;
        b=zZgSYe4siMiFE0DBujepwO9Qj2a1bcjxzxZNsgQrhDiIQrXHG65WNAoJLb4Lp1OBpn
         gYMEZRmJUJooX3Qmmyf18zvgsm3CJa3gXrjcT6ORhClgCV2NmlOLttE5kHWVu1nq1SGf
         +skjWxHH7HDEjiaBloktWz3yPGM2Q2NB1Ef3TrfSK8mP4nbjroAog19g7eJI9gNlMNaM
         XozAYwuoTG5D0ZoUlXUHid8hL35RaG9TS22B4iXF6hOe4Ts1noGBWJ9cHJNkWUF90wHc
         vg81JrdhnV7behZPMO2bFNkXHcIHhwQAmdwh0FF2fZtyumnlwoO/FrMYQ6woXq7RQnUd
         46Nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dHJRR/6w";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RBmKsozPEj1d7XrqZh9L9Hxcm5OXgMQ9lgwcq3dN5BY=;
        b=ZHvvYwy4SsvTqQb6eugvh8kK91CLjLDCkP35wEbhOMsnFs7L1ZJjyef+VJ53rN1OWl
         sKAop5ciCkCsgfqDBKvOrGG3ozAC/eXoMbFcsVRHxj2sGb33U24p2hWctWeddZim6kCB
         20mAEqZAXNccmUwaLwDdB0742SWDQnjMGS9TntRro347ZBKuVgthicrqsGKP8gOGWb7s
         2qxPWeHBLuSzXHnHqqnwuNTUHIwry+lVWiOQVv0tzXorHuAL1s5unZTzVfTxkZXoVMdj
         c4v8+MqZCW8nrp9QIyf8yK+RbnERolnFoytLAoIstWcWUaDIepJpX7wJpcpdyZcKVq+I
         384g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RBmKsozPEj1d7XrqZh9L9Hxcm5OXgMQ9lgwcq3dN5BY=;
        b=FDbPBd8ZCN8sQJ0nvoQX4uZdq3OjC9o8DlRwA3+BgwwB5Z1Uuzg7xtAOHuln7l9cxy
         nlM3TqMXk9EnWHoTphDcr1DEL2u2IG564YKpRXaZYOcLjAfyTp21311zRxzYv6mQqyQF
         1zu4WkPqraTqy8PLtHsoyD8Bpcux44Aj1g+1ckKsvgplUEfRnUO/PHxj2AJPh+uP0lyk
         X5PdpYq0occBb62UZ5A5vn0IMEusaJf1qQrwOlYoa/HfC3fl2EYexmlUDpl5bq2Hy6d+
         DIblj6rCyRaH+B7D5KJ3+wDapOuRKB8WiB8Z0jx570QX7CSlom4CQXs3pENFjcUzT50L
         yl1g==
X-Gm-Message-State: AOAM530+znT25zDG4G28ZA+DS7wZWEJX4DpAkK87T9n5+WIy8ff4wbBa
	2gtg/blfWKM3i5WG8mzAlRc=
X-Google-Smtp-Source: ABdhPJzIcsqpzifta59Dq55RFKjhTGndpQY4HBEaVC142dB0Vg9skZQVdOd2wQxdc5gyk3QVGjTFkw==
X-Received: by 2002:a9d:2ab:: with SMTP id 40mr28925otl.230.1591191317390;
        Wed, 03 Jun 2020 06:35:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:590c:: with SMTP id t12ls434796oth.1.gmail; Wed, 03 Jun
 2020 06:35:17 -0700 (PDT)
X-Received: by 2002:a9d:4917:: with SMTP id e23mr10282otf.29.1591191317084;
        Wed, 03 Jun 2020 06:35:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591191317; cv=none;
        d=google.com; s=arc-20160816;
        b=SamuLqO2j5kmGeZUTqICUyJZEERduFpfc4GNdkJfaOaLxe97jDpJ+9qxnpxScb7tIY
         apz5kcFps4qFhhIPOkrvS/uL3zruJE+tBH+yTEhTu+cyyBXGJytN16O7mFoJJ1frV7sK
         5TMHTDZAWCC84N89UsP8wzDiUUHGFhpnNk50DsgZEJv9U0To3MyDpMP4QkU5htGdatZg
         eVtoqY7L61INoPUi4ExRAf26TxS9rOmO+0vfmQWaCvmDvqF488EKQTN4ItU5WRIaV+kE
         puxIeZRHcgWxis02PdgeitXTLyI/s2CqBvNnOyCd+xpvFFijKwVWFFAGjFHUQA8NuMfz
         o30Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ffoWRsiIdmktI0Aa3BFBPpp+Z+t9ruAh+fRHAhTsS0U=;
        b=dZxs/dRePcKRApcFOxUnHTWYEFsoCLyjIdJK2RrNafIU1v5BFqaB/BUWvyCjUBxVaF
         UHnMVtexneRXxhKvvf9etWnUqN2r7Q3/m3WlmR0hxFdu/jNZVgAQeLhf1qIo0V9OqrYD
         ZIKVJ4eqXoXbwhSGsBkkrsG8UZLIeNcjvoNkgEFYyxO33Mndy+JUTB7zWihH+D/6K2WR
         gYWitqQO9X1OXtrtMLMudmJ7Yl1uWVZe/zxYNutaqRdWwcoJpU/87vKnZVW5KwiwF/6Q
         /+p2mK8ud0D5pZN4R9LMEr5BepHEn6qRAmQfvjwfERlXMIzInGLxakM4+bRUtbxEy09d
         Oo+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dHJRR/6w";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id p28si156769ota.3.2020.06.03.06.35.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 06:35:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id r10so1756217pgv.8
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 06:35:17 -0700 (PDT)
X-Received: by 2002:a17:90b:1244:: with SMTP id gx4mr2285007pjb.136.1591191316071;
 Wed, 03 Jun 2020 06:35:16 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com>
In-Reply-To: <20200602184409.22142-1-elver@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Jun 2020 15:35:05 +0200
Message-ID: <CAAeHK+yNmGB6mEQoogGhUh_F1fXFF_baA14G3=4NyYv=oz8Fdw@mail.gmail.com>
Subject: Re: [PATCH -tip 1/2] Kconfig: Bump required compiler version of KASAN
 and UBSAN
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="dHJRR/6w";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jun 2, 2020 at 8:44 PM Marco Elver <elver@google.com> wrote:
>
> Adds config variable CC_HAS_WORKING_NOSANITIZE, which will be true if we
> have a compiler that does not fail builds due to no_sanitize functions.
> This does not yet mean they work as intended, but for automated
> build-tests, this is the minimum requirement.
>
> For example, we require that __always_inline functions used from
> no_sanitize functions do not generate instrumentation. On GCC <= 7 this
> fails to build entirely, therefore we make the minimum version GCC 8.
>
> For KCSAN this is a non-functional change, however, we should add it in
> case this variable changes in future.
>
> Link: https://lkml.kernel.org/r/20200602175859.GC2604@hirez.programming.kicks-ass.net
> Suggested-by: Peter Zijlstra <peterz@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by:  Andrey Konovalov <andreyknvl@google.com>

> ---
> Apply after:
> https://lkml.kernel.org/r/20200602173103.931412766@infradead.org
> ---
>  init/Kconfig      | 3 +++
>  lib/Kconfig.kasan | 1 +
>  lib/Kconfig.kcsan | 1 +
>  lib/Kconfig.ubsan | 1 +
>  4 files changed, 6 insertions(+)
>
> diff --git a/init/Kconfig b/init/Kconfig
> index 0f72eb4ffc87..3e8565bc8376 100644
> --- a/init/Kconfig
> +++ b/init/Kconfig
> @@ -39,6 +39,9 @@ config TOOLS_SUPPORT_RELR
>  config CC_HAS_ASM_INLINE
>         def_bool $(success,echo 'void foo(void) { asm inline (""); }' | $(CC) -x c - -c -o /dev/null)
>
> +config CC_HAS_WORKING_NOSANITIZE
> +       def_bool !CC_IS_GCC || GCC_VERSION >= 80000
> +
>  config CONSTRUCTORS
>         bool
>         depends on !UML
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..15e6c4b26a40 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -20,6 +20,7 @@ config KASAN
>         depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
>                    (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
>         depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> +       depends on CC_HAS_WORKING_NOSANITIZE
>         help
>           Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
>           designed to find out-of-bounds accesses and use-after-free bugs.
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 5ee88e5119c2..2ab4a7f511c9 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -5,6 +5,7 @@ config HAVE_ARCH_KCSAN
>
>  config HAVE_KCSAN_COMPILER
>         def_bool CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-distinguish-volatile=1)
> +       depends on CC_HAS_WORKING_NOSANITIZE
>         help
>           For the list of compilers that support KCSAN, please see
>           <file:Documentation/dev-tools/kcsan.rst>.
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index a5ba2fd51823..f725d126af7d 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -4,6 +4,7 @@ config ARCH_HAS_UBSAN_SANITIZE_ALL
>
>  menuconfig UBSAN
>         bool "Undefined behaviour sanity checker"
> +       depends on CC_HAS_WORKING_NOSANITIZE
>         help
>           This option enables the Undefined Behaviour sanity checker.
>           Compile-time instrumentation is used to detect various undefined
> --
> 2.27.0.rc2.251.g90737beb825-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByNmGB6mEQoogGhUh_F1fXFF_baA14G3%3D4NyYv%3Doz8Fdw%40mail.gmail.com.
