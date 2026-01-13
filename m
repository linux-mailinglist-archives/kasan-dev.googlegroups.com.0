Return-Path: <kasan-dev+bncBAABBYGKTHFQMGQEIKXYVFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 91F44D19E79
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 16:31:45 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-47d1622509esf49850235e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 07:31:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768318305; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZKNI+xEbwn8eYwGrsiGr8lFiT05zx+5kG34oOF7MQc0ldAAMdPKAivexx/kt5HfCOB
         vtQAKWhcsB7nqNdoZXtLBxZk0ZOeCwRgN8hGZMtyW3DuYH3EejQlRLkrS8Jcj3L9rQ8Y
         FKD9bYHf1O+kENPXdMF7mmuw9muBB/dkuofjLS43C1WOtYvBrIil1UicKteEMDBIgxbH
         rZgRJe+Szgpabbe4x7WtZzcKm542m3EeW6v3n96WxVI1XgUdTaH3/u73A8lhZslyKFYg
         ho7ukVMQSraPsIek6tz6nqdDOxnVk0p7dZDfRD0d8XpehTx/3TuUYL/9Cw2Agq+z+jGO
         ZFcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=ehc++qo9dE2+asv/weYyq/HfYlhZJSZsYmcTl55JQdQ=;
        fh=6Enn8ahq7zMisWtFn+33FqywXbyNaxvIk7X0peOi0zs=;
        b=eGUZjclUdpY3hmudKRmXPLDRTETgiBVgmTC25sool2qcm6T3WcdBUvn97mzeXvfKhw
         ZtoLWJP8IEo2CG5/iTtTmB1eZAI8Gpszk2+d8M08kZ6ZZzBdw6V2fqMDCMFTTgEj+yK6
         hI3LsB31J1R1TcuKZIFxUnXTSyFteTy6dsLDJgOErCeOB7jtK3BrrEI3JB4msasf1eDq
         tvgqGIn0q2dycoGIMoLL03LJGpVSD4j/uVjUPNWyhNXwhEFvRuEXIougrjPZ3pRY7PeK
         ZPTPRzZo+wd1ctacBdSH6AX4d566I6q23jmaYc97F9I8ehU9qvydL8Px8ZbzNUHNeuOK
         Npdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="QwtOFF/E";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768318305; x=1768923105; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ehc++qo9dE2+asv/weYyq/HfYlhZJSZsYmcTl55JQdQ=;
        b=qDuMfU6UotrL//5ti5+tV5oNf7lkUqOulm8UtR+8GxFLVSo6F7pKUut6Wf0SEZAXBC
         Ca5c9iy/s7uS1pU9yBHZAoQxcDLkiZrDxc1OIw57daBBIOHbMGzL9RgQeDwbKNtaYjPe
         sqxFLsTvlY57XUzOj467AUm5HnHaga19w+AlS788XGs/57Y/jeR8TNelGsArnTO5vKNR
         gRDnMFqFwM2wZbpO9KQoPxoFvvarDbuvSfi5NyBK43EXJodBONYYpaILSs2HiSGc0lLT
         RwHQvRPi9vkTjqk/WYUyUJZ04973uI5eVBzFau2bP3mkKjXbRRaqGToGwYMbycUNrfJq
         XQug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768318305; x=1768923105;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ehc++qo9dE2+asv/weYyq/HfYlhZJSZsYmcTl55JQdQ=;
        b=jh64C22H7L8RzqlPSQ0phCte8w0129VnMvcQK4oiFDudIc3ShU1twqnahu1ERm+WVG
         dHjMubS+sqL3p7rzgUra5AGm3e4qrNxOdy5fNqMRcv9urteOz8UhGm/H28ldp7Q/nX13
         fWfA+eijjViSqmXRtskDIjWf6VYosHSzkXnTP5Y7M51yuoE7i9KAYaop0hh7tNRdM5p3
         9SvCl693YaXbZjrOUah8j/fqzBbeMJdTeeeAa4KN/kldvSaYtV5PKqsiH3WIlzGsTdsU
         di4mYCygB1jpilAe9CerLqo+1YQVHlNE4Z85JSmymbrDom9p+aaRHNqY845XqiuHc7vf
         k7CQ==
X-Forwarded-Encrypted: i=2; AJvYcCXzk4NNscvkIoEuY0UiPkgQ2qPEVuqKVG3P0WfYlQGufzMjjB3Jb1TpAo5vW25Q0FGW/DDg/A==@lfdr.de
X-Gm-Message-State: AOJu0Yzhro6U2VgXOMKT3DRyIb9CT7+VxbJ4VyRmUdlac/53FchczGCB
	I7eSMJeGY9U4VQu5vgqIp9qm0B8CrFKRThKW8lZgMhz3I3vzpTnFbrI4
X-Google-Smtp-Source: AGHT+IEA84qzZT/c2TebG/bUXO1DCMLUz16zvB+IeSuQsWqCkJtXpKWwmR1gt627aX1ZRN45LbZCbQ==
X-Received: by 2002:a05:600c:4f53:b0:46e:506b:20c5 with SMTP id 5b1f17b1804b1-47d84b5b496mr224726615e9.26.1768318304641;
        Tue, 13 Jan 2026 07:31:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GhA8mSVvTnMpLTx0EkiZE56442SmH1GfRVG1brVcp4Bw=="
Received: by 2002:a05:600c:a215:b0:47e:ddf0:fd35 with SMTP id
 5b1f17b1804b1-47eddf100e7ls3355565e9.1.-pod-prod-01-eu; Tue, 13 Jan 2026
 07:31:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUyqWLCTYGJjAM8EfV5+7CNyjSMxx8epSShb76wogsyFkgSWLvGpPnonHMe7Hj/MaIWjDpJba8T6a4=@googlegroups.com
X-Received: by 2002:a05:600c:5391:b0:479:3a89:121d with SMTP id 5b1f17b1804b1-47d84b614b8mr250616105e9.36.1768318302948;
        Tue, 13 Jan 2026 07:31:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768318302; cv=none;
        d=google.com; s=arc-20240605;
        b=Tt6Dzb3kcu9TdxxQs283kzWT28adNpjDaYDVWPgWkHpwGHXPEUS9orKEV3W5bdcoSc
         06jkuNk60skSRrQdYQBo2AFrpBw4lFi89vDzh7Mavpuf4HrJ3898r+lj+BvSmtnXfwYx
         EedgLilrFxlkdY3KuA5LJwXkcXVaMMZTJ+6R4W9S02oRRk8bp0JgDktMKgZ4dZAlxTQN
         c6ERTaS4UDK0Zt/4vEeFz5PE9J2hlgPY6tPjBlOnotRQgDvHTJflx5jpjI/K5HA3QGzg
         ro7ZJ/2qPM4ybtswVwN3FGLNPaGKxZDGbclCBCtIcyDNcB8UeaLCSSl3o+StcKvrAv6g
         TGfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=uEP1NgR6HhXin2bbfObweda7q+8+DdU3HNOIdXWHQS8=;
        fh=mps/4ygjB0bJ1g1LC1b65wYHkMs4PBzcFJL0u1GnqFw=;
        b=gkuJvBI8si9rRP5Dbh6yMM4sWS92GrSp2kPWBRU16f7O7SY4aU5Cj/f0L96KJdXQZB
         8lCWwwmJSzJS+xLfnvBCNT2DM9qHqru2CTJKf/mCJ0GGcNFnK3Sbhejw/5GLlpLo/i8w
         hGFaKy0RTZQZEeNHX14GJcwYp0FjtxaVrnvycEjZzHaYW9RxNxwVIxqeaxDVvXLz3Of4
         j2gitr7pkjL+YlUuOUb6c8uaa523dUOb+/1qWr+mERPX1QQX32/qsO7+qalHBrMEsueT
         1OMrN6T5UGBUiSBbfpiebkHJ/YRqHMW/N8TfQr3kiDfSKkxbHks+G4RC8G1FjlYl+fM0
         BuNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="QwtOFF/E";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4322.protonmail.ch (mail-4322.protonmail.ch. [185.70.43.22])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47ee272aed9si10075e9.1.2026.01.13.07.31.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 07:31:42 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) client-ip=185.70.43.22;
Date: Tue, 13 Jan 2026 15:31:38 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v8 14/14] x86/kasan: Make software tag-based kasan available
Message-ID: <aWZh-4FlO5VVvkpQ@wieczorr-mobl1.localdomain>
In-Reply-To: <CA+fCnZeVEDwojqUfT1CC10sLZiY8MVN-7S7R6FP_OHkU3TH+0g@mail.gmail.com>
References: <cover.1768233085.git.m.wieczorretman@pm.me> <5b46822936bf9bf7e5cf5d1b57f936345c45a140.1768233085.git.m.wieczorretman@pm.me> <CA+fCnZeVEDwojqUfT1CC10sLZiY8MVN-7S7R6FP_OHkU3TH+0g@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 21a14cfcc6d9b67126769e450095932cdd296122
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="QwtOFF/E";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

On 2026-01-13 at 02:21:47 +0100, Andrey Konovalov wrote:
>On Mon, Jan 12, 2026 at 6:28=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
...
>> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
>> index 80527299f859..21c71d9e0698 100644
>> --- a/arch/x86/Kconfig
>> +++ b/arch/x86/Kconfig
>> @@ -67,6 +67,7 @@ config X86
>>         select ARCH_CLOCKSOURCE_INIT
>>         select ARCH_CONFIGURES_CPU_MITIGATIONS
>>         select ARCH_CORRECT_STACKTRACE_ON_KRETPROBE
>> +       select ARCH_DISABLE_KASAN_INLINE        if X86_64 && KASAN_SW_TA=
GS
>>         select ARCH_ENABLE_HUGEPAGE_MIGRATION if X86_64 && HUGETLB_PAGE =
&& MIGRATION
>>         select ARCH_ENABLE_MEMORY_HOTPLUG if X86_64
>>         select ARCH_ENABLE_MEMORY_HOTREMOVE if MEMORY_HOTPLUG
>> @@ -196,6 +197,8 @@ config X86
>>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>>         select HAVE_ARCH_KASAN                  if X86_64
>>         select HAVE_ARCH_KASAN_VMALLOC          if X86_64
>> +       select HAVE_ARCH_KASAN_SW_TAGS          if ADDRESS_MASKING
>> +       select ARCH_NEEDS_DEFER_KASAN           if ADDRESS_MASKING
>
>Do we need this?

I added this to solve the problem "what should happen when there is no hard=
ware
support (discovered at runtime) but someone requested/compiled the kernel w=
ith
LAM and KASAN sw_tags?". I think Samuel suggested the static keys approach
during v6 to solve this issue.

As I recall without it the kernel would just freeze since it would try doin=
g a
bunch of LAM+KASAN related things without LAM working. So that'd end with
various faults and violations.

Technically kasan_init_sw_tags() is locked behind:
	if (boot_cpu_has(X86_FEATURE_LAM))
but not running kasan_init_sw_tags() normally doesn't actually disable soft=
ware
KASAN if we don't have LAM available. Without ARCH_NEEDS_DEFER_KASAN it jus=
t
checks whether CONFIG_KASAN is enabled which it would in this scenario.

>
>>         select HAVE_ARCH_KFENCE
>>         select HAVE_ARCH_KMSAN                  if X86_64
>>         select HAVE_ARCH_KGDB
>> @@ -410,6 +413,7 @@ config AUDIT_ARCH
>>  config KASAN_SHADOW_OFFSET
>>         hex
>>         depends on KASAN
>> +       default 0xeffffc0000000000 if KASAN_SW_TAGS
>>         default 0xdffffc0000000000
>>
>>  config HAVE_INTEL_TXT
>> diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/=
misc.h
>> index fd855e32c9b9..ba70036c2abd 100644
>> --- a/arch/x86/boot/compressed/misc.h
>> +++ b/arch/x86/boot/compressed/misc.h
>> @@ -13,6 +13,7 @@
>>  #undef CONFIG_PARAVIRT_SPINLOCKS
>>  #undef CONFIG_KASAN
>>  #undef CONFIG_KASAN_GENERIC
>> +#undef CONFIG_KASAN_SW_TAGS
>>
>>  #define __NO_FORTIFY
>>
>> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
>> index 9b7951a79753..b38a1a83af96 100644
>> --- a/arch/x86/include/asm/kasan.h
>> +++ b/arch/x86/include/asm/kasan.h
>> @@ -6,7 +6,12 @@
>>  #include <linux/kasan-tags.h>
>>  #include <linux/types.h>
>>  #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>> +
>> +#ifdef CONFIG_KASAN_SW_TAGS
>> +#define KASAN_SHADOW_SCALE_SHIFT 4
>> +#else
>>  #define KASAN_SHADOW_SCALE_SHIFT 3
>> +#endif
>>
>>  /*
>>   * Compiler uses shadow offset assuming that addresses start
>> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
>> index 7f5c11328ec1..3a5577341805 100644
>> --- a/arch/x86/mm/kasan_init_64.c
>> +++ b/arch/x86/mm/kasan_init_64.c
>> @@ -465,4 +465,10 @@ void __init kasan_init(void)
>>
>>         init_task.kasan_depth =3D 0;
>>         kasan_init_generic();
>> +       pr_info("KernelAddressSanitizer initialized\n");
>
>This pr_info is not needed, kasan_init_generic already prints the message.

Thanks! I'll get rid of it.

>
>> +
>> +       if (boot_cpu_has(X86_FEATURE_LAM))
>> +               kasan_init_sw_tags();
>> +       else
>> +               pr_info("KernelAddressSanitizer not initialized (sw-tags=
): hardware doesn't support LAM\n");
>>  }
>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>> index a4bb610a7a6f..d13ea8da7bfd 100644
>> --- a/lib/Kconfig.kasan
>> +++ b/lib/Kconfig.kasan
>> @@ -112,7 +112,8 @@ config KASAN_SW_TAGS
>>
>>           Requires GCC 11+ or Clang.
>>
>> -         Supported only on arm64 CPUs and relies on Top Byte Ignore.
>> +         Supported on arm64 CPUs that support Top Byte Ignore and on x8=
6 CPUs
>> +         that support Linear Address Masking.
>>
>>           Consumes about 1/16th of available memory at kernel start and
>>           add an overhead of ~20% for dynamic allocations.
>> --
>> 2.52.0
>>
>>

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
WZh-4FlO5VVvkpQ%40wieczorr-mobl1.localdomain.
