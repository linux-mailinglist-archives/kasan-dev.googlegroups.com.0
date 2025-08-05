Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE7TY7CAMGQEVRQQLMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id BEC8DB1B375
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 14:31:17 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-7073cd24febsf40190466d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 05:31:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754397076; cv=pass;
        d=google.com; s=arc-20240605;
        b=K7seWqX09Bt/JYCEFLYa+S7XbmgC2qfZO0v8hUkOdZw7K8HASYt0Y991BwvWu1q6uA
         G9PAqGicEwLbytkxbf4JAVnGWS3+drMT4LT/MOUcJoHvRFggKFM37zp7Bc9boZVfaSOB
         QbvuHBIjRA9qi/z0dkgRcmKKJpnMqgDn0R9vM75Ty+IfSEoi84wYrFCnGKjGkiVQ6vV5
         3P0k5+aI45ebKhD91GW1pHUpqdwSf3H3Zcp57RkDwO84IeEhS39CBh7tKZhaPfsIanzv
         zqjmePw+KFooxznVWoMWVxNUkSy2zEfGP1tlEbBf3aIps08zK/2BZucuMhFQYzFE5qzE
         Eozg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TDhipoEB9HZVzZLI8HtN83XRLf45oehMAxgNgfKQSm0=;
        fh=LmUtHNjNts8LfOlzN7wsbVHzmKkj6S0yoSNl2guzJDY=;
        b=lUyBEXoigiNwTRVATATl/CxqdCRdx+JvrGMuIBDo5g12J2GE1LUE4SAZtcY5r/sf29
         U+GlH+X17zeSYYE0ojKvKNqaxnbdMBzXiXGpYa29sd/LFpdQczZp/cFa0isTkyJ46aIZ
         4KtMWio666F7Zqe64zMDItOIFnKu+TCpz5uTcUK//o3mgZ1SQq6apS/O9iPX0e2ZEv1s
         KUjzZ5tEMlar0HYR3/m0Abr6FL5ON87DkX/NrMA/yRO2wlVysu0QO7+pVQum9vNp6L1A
         79aDcnf0ShWgktGO6MYv0FpTwmit3b9EoXpXUPuslrByQVtT9aLQ69cXeBINZeFvfaV5
         fmdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eOvULmzB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754397076; x=1755001876; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TDhipoEB9HZVzZLI8HtN83XRLf45oehMAxgNgfKQSm0=;
        b=N6lBpiatJoOdkrDPC87gdOxS1BG1q2iqBNQ2NbUUN9ynKI2PK4nDUzvFGr9AWJ5zrH
         IVGe8ZAEPZYUGK3fEZ/CrWlD2twrll8Rb+zB8kQOM63yyH4Ft3JTkQPHLOGIifup/MFr
         LEG+V0zoXyoN5b2seEZHeHQEfgPL7oap2V5d/537Au4mZa8QxOe7GVyy6r42LEMKxO5z
         K+KPg5/kh887fV5MRZV4xSlLm7K97Ryyz3UgAdGr9LSNV2nys8MExL39oCMfJFDgoUfG
         KFO4wEA5I8GMIzIBKIJ68bAWJSJWCPHqeQK0rzJO6zYdgTHpZdpkgSPHeUKPMopbN/R2
         1aZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754397076; x=1755001876;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TDhipoEB9HZVzZLI8HtN83XRLf45oehMAxgNgfKQSm0=;
        b=YEQnVGALdNcZI+jVCGUv1d0J4QrRVVLODt7lLYKWYXQRiRpIbYL9PnDWYx8Dbywg/N
         4wb8BG55jyW7NrA741/f7BW8WyQDWM1CrDbCYTk3pvnpgCuMIBway8vQS1e7RJE1IpKs
         60DqdfuXc6MT2c+afDQIVrB/JlbgYQ86aq1ctK67ATDvxVfV9E204u7ZFpzTsP90f9aT
         XqBWy16Eb3rPLOoxnizJG74pxJ6/bnOgrg5uJawDcEJ1UltPi4HNSc615d2JEAtZXrPV
         xYyY1C/Kcge5wcy1tkl3pB4PQqM95jtruOgU4r71az0/YAJPzdym+on2PsVeYPhknTsX
         JcIQ==
X-Forwarded-Encrypted: i=2; AJvYcCW1N4nwUXAM3lu3iKuJbSB08Z/1f/uQ1Cdp15SY+SESAW7jOuqlHlgm7KfBImkOm+/E8fpjSg==@lfdr.de
X-Gm-Message-State: AOJu0YyfKMSLdBClnVcS9ozvfJvCJFXX+Rm3S9osfQ/olmGA8hW+UDB9
	XgC88IHpDa3tZyKi2HYisbtfF3Ofgk4Hf2rPSQZv8u3GBhGq9MuKpya8
X-Google-Smtp-Source: AGHT+IEQ3YNjaTKjN1V40lo+WPvzPPNUuxXXFmJNUaVOc79TjuaByQgEg+5+QblJQ+FP90zbvGKIcA==
X-Received: by 2002:a05:6214:246f:b0:704:f94e:b5d6 with SMTP id 6a1803df08f44-70936338f46mr196874906d6.46.1754397076066;
        Tue, 05 Aug 2025 05:31:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfCzBg4wWzTgFzyUyxeEUzX8pXbg0cQ3e81hjp9Xk1KrA==
Received: by 2002:a05:6214:2687:b0:707:71f2:6be6 with SMTP id
 6a1803df08f44-7077686aba9ls88418936d6.0.-pod-prod-08-us; Tue, 05 Aug 2025
 05:31:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWOwIX3kskJtieeEkv+V+3WPqikKBg5BFTxVyNQIGZ2nguWbpKejdcThqCdiKnQhH9mKnIyiELEKZ4=@googlegroups.com
X-Received: by 2002:a05:6102:6898:b0:4ec:c4f8:c4d3 with SMTP id ada2fe7eead31-4fdc1f38672mr5129222137.5.1754397075210;
        Tue, 05 Aug 2025 05:31:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754397075; cv=none;
        d=google.com; s=arc-20240605;
        b=SQXru3oolpk2J3N6VAqG4WrGbwRnJtFgtFKpAMmuRS95OyW7HuH+1LeshYyletbZAf
         SeFX1x9XKXWtQJjo3TfNXytQArtILa0ug9XaBpq4XDBkqX1q/ftsMXHpNnmHJDTcRvin
         GVawK1dIKS82E0sY39ZNmbmNTeDTxGkLj4NsRUrkWKixO0IO+DdzAaizyHjb163iwox1
         voGgMaVozYKqZlGwM9Mb77WkITvjrlCECplECLJ74lr/kYGdRZHSFbIlupP0iK2cfD2v
         TrC4yb+rVR8kNnV/0hmkNgbhL0wZaavf/FzTg+nmWoAXrmspCuQrExQFqpLL4gOiHpAV
         U8lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yc4gvWW52t1NDKhzxwrmBqGipvg9SoHEPfFiqWrZ+tE=;
        fh=aMZSPda+s28S3s69f+ahXIRaQv2U7akmFX4HbnNo4fs=;
        b=Zm97Nm7jIjaoSiIj9eW3azt/2X6lptoGW3t/XOEpwQAE75QcjsTmB0f2IKO1HIi3Kb
         abjE5AHYr6t6H1SSUm2YMKawqhPCjjqY2vfcZXONgglb6tfSaDKNr8omw+YtEJOM/CKB
         eziWzfkyH7j1y0es8LzG7gtBVTsd8Vvzm1sfP2H2NY8TK3J5+Hk2hidl/dvw3B73FHyP
         xu+uaEw+FH46co9TY557ZTwugmj9O3/XBE3+QXtncdIG5hISvpXI3qI10LG6WjTnZjOS
         VB6d09UMdjJddGwxJemnPGg9PgmrAGs7P3+BSE4KB9MIOsg/wvWTwAFPjsk+7QPxNtgG
         eYrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eOvULmzB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4fc0ce3cdb3si111745137.0.2025.08.05.05.31.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 05:31:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-24014cd385bso51789135ad.0
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 05:31:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXfng8qfeK5eVOfaybB1u4cnPh4Xq3olFzIOjiWxZwGcILuZ5w+bCuF4DApVivuTJuDMnqm53WTLsc=@googlegroups.com
X-Gm-Gg: ASbGncvKLEGe5ZWlYOVZfX1xXpZHbjSLlk5cykAAuYxWd6rw9V/W08BH46q7m7s25U8
	aYut+Q01lzc4OUHs1aR7LvQTiwhwq0ygvntimDzKM7xS/ltDfE7HpRLUef4YFiwljclqRd1pTmU
	naue7yTGV1RZke9esxYqSjcU5Oa7TddtNavYB0Ccqq1r03ucdSebsTo57CxW7ZyW8S8k4ktU85Q
	nyR95mluTjEzw6mbi+ww0SXNI8hnwnKamqV7Q==
X-Received: by 2002:a17:903:245:b0:224:23be:c569 with SMTP id
 d9443c01a7336-24246f6b79bmr191772715ad.22.1754397074101; Tue, 05 Aug 2025
 05:31:14 -0700 (PDT)
MIME-Version: 1.0
References: <20250804-kasan-via-kcsan-v1-0-823a6d5b5f84@google.com> <20250804-kasan-via-kcsan-v1-2-823a6d5b5f84@google.com>
In-Reply-To: <20250804-kasan-via-kcsan-v1-2-823a6d5b5f84@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Aug 2025 14:30:37 +0200
X-Gm-Features: Ac12FXyvqYle1O7urbvJeMSiw9QK6-PDkDpNKV6wtqm4byhvYfbkU7M963dNpMQ
Message-ID: <CANpmjNOJxJ+kM4J7O5J8meSD_V=4uAa6SwFCiG83Vv_8kn56sw@mail.gmail.com>
Subject: Re: [PATCH early RFC 2/4] kbuild: kasan: refactor open coded cflags
 for kasan test
To: Jann Horn <jannh@google.com>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eOvULmzB;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as
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

On Mon, 4 Aug 2025 at 21:18, Jann Horn <jannh@google.com> wrote:
>
> In the Makefile for mm/kasan/, KASAN is broadly disabled to prevent the
> KASAN runtime from recursing into itself; but the KASAN tests must be
> exempt from that.
>
> This is currently implemented by duplicating the same logic that is also
> in scripts/Makefile.lib. In preparation for changing that logic,
> refactor away the duplicate logic - we already have infrastructure for
> opting in specific files inside directories that are opted out.
>
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
>  mm/kasan/Makefile | 12 ++----------
>  1 file changed, 2 insertions(+), 10 deletions(-)
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index dd93ae8a6beb..922b2e6f6d14 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -35,18 +35,10 @@ CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>
> -CFLAGS_KASAN_TEST := $(CFLAGS_KASAN)
> -ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
> -# If compiler instruments memintrinsics by prefixing them with __asan/__hwasan,
> -# we need to treat them normally (as builtins), otherwise the compiler won't
> -# recognize them as instrumentable. If it doesn't instrument them, we need to
> -# pass -fno-builtin, so the compiler doesn't inline them.
> -CFLAGS_KASAN_TEST += -fno-builtin

Has the -fno-builtin passed to test if
!CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX become redundant?


> -endif
> +KASAN_SANITIZE_kasan_test_c.o := y
> +KASAN_SANITIZE_kasan_test_rust.o := y
>
>  CFLAGS_REMOVE_kasan_test_c.o += $(call cc-option, -Wvla-larger-than=1)
> -CFLAGS_kasan_test_c.o := $(CFLAGS_KASAN_TEST)
> -RUSTFLAGS_kasan_test_rust.o := $(RUSTFLAGS_KASAN)
>
>  obj-y := common.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
>
> --
> 2.50.1.565.gc32cd1483b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOJxJ%2BkM4J7O5J8meSD_V%3D4uAa6SwFCiG83Vv_8kn56sw%40mail.gmail.com.
