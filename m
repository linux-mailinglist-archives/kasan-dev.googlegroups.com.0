Return-Path: <kasan-dev+bncBDW2JDUY5AORBW7QR66QMGQE3IQQGXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id D1753A29DAD
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 00:46:44 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-5440c445282sf155585e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2025 15:46:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738799198; cv=pass;
        d=google.com; s=arc-20240605;
        b=H6YymKx95dkkJSiZNr3i5aktq1zra1DqkrsAT/MaJDx6aSMJVUboANo2PVG3fR0OFG
         VAotUdLddzhlopgiKWmtM8wvuYikTeeNYwK/36/3x/ywIPopVyzoF6eN9DDPjImYZofS
         xUWI77Gr9WXRVvyR70Gu2bQaopYimA3Y2FsXerSkr8VHF5DQemkrPWwyBOcnXZO5eYPW
         5Z88ali5RqVhOCnFvsgSbcmkkMmytPJdWtSZUOgmRLz/d+0fePqU5QULYbnf6HOng1DC
         TbdX/cjxR6xS9Dw1XNoXQkTWblCpYlfhYBYHhpHGBW6cJOL5lopB8z7dWibQLxGjF4Cj
         JYmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=dm6WDK5AmvRomisgLhOJhMNe6WiT+/MMwtQHNmJIjgY=;
        fh=s5wMoxZMXuTnWumkqgmvi6TfRXNWtP5eFDTUtwZoaeY=;
        b=kkydEkLe/jMgb+UixoepLOAry05uHu4bG4oy13u9FkTSD4m/8sdC8cFDKqJ/pffgGe
         s5LVWYPLdbVcKjkg6kTZAC+gmsGWmgo9clgYAexsw9E5Pa+JIkQsvjQpDZjwbVD9Kk3r
         KqSBaPfZW6tSMKHZP1ftjHXaJIzyADOHHF3mzCAs8Hb3x13nNTWDZ1UA0TrBnYw6Xhq2
         Hn4Np3cVXZrJXZChSq2V/YxUz4OKZojd+3rr+MprGgfW65XaqcpZ99tEwuVAwWKk+3Hq
         gCngvpts+kUyQIphLL+ovUu34+0CqRc7OfRrLWSo75hqA2qL6V0iL6qwZf9E9DKsEsQf
         Z+3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DyboQR5H;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738799198; x=1739403998; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dm6WDK5AmvRomisgLhOJhMNe6WiT+/MMwtQHNmJIjgY=;
        b=h/RSnm7V+7CtObaPh86tGI+2n5hecNkHqKpuAO4ARQWV46bBAagqLYcAuOcrOeFBrF
         3wc2YfSzaES7D47n1SDJCqbGA3o86kVzDN65xHcZxJzK2KK33SxHR4zMEAEnC7fFzp2A
         +1eDLg+ii41DRuE9DT971s+BR3uKc2SBLzMQKpOpXToHxMkl52D2Bu8rHSpkul4YIQuj
         Iy507r5qKD31peE+zoZBX8q8DPFKBioLFFDM6TfpvkgiZNvRh4g0yYIXAVIji6GRhgAt
         dSeeDumE1Eh1FNHnwgJy6G+/HuXnAZQX3Rjsa9uLug26Cjt9qkL3yWpJOPClerVD15TV
         SBTA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1738799198; x=1739403998; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dm6WDK5AmvRomisgLhOJhMNe6WiT+/MMwtQHNmJIjgY=;
        b=fxPbqhQhxFt1hhfxmJzhVFxZVhux9d9q3oV2kDVMNT+X0pZfnhd1nUc33ZRKQa04vE
         A32DpUYjfuIO78GZA44nT1wAQltFFhSzH7PbrP35S858cofHDZUV4oA2qNiE2+63Uev/
         u4cMbVJIL+Wz/vKosO+mG+4loE87RYzUxUGOIt47W59k5KYrOnzxZKY9jD2M25eTJ7E2
         buVAEdWat4W0OXS7ybLeMZ3tySHDjcvyJfhiJQ7T92S5HZq2+F9ChU0gILX/jfHhMdYi
         fL8JPxplNg3nVWfejFbWMmnvBvUfs1QuKe2NwlUeXTbUkf29ArPi5ugTF4dH2+qpT50w
         tFfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738799198; x=1739403998;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dm6WDK5AmvRomisgLhOJhMNe6WiT+/MMwtQHNmJIjgY=;
        b=RLV4U/lb/oli5NR9XubnmqXA3BS7u0ZltbkmUiTobnuoOVITUwZfl4uqkGU2wdMWwh
         zYaPQJ+LWkCaUm+y81ud2VOW0JG3wGCSTPKHUTjrR3NiVaZCHWemrqVUbWuXJdsXCBOp
         A4ga5z13BEE0yuFO8Hz9P5kIu4knDU2pRh/iwGLMg7rAbfA+h2w/PIPoDlm4b43VFzPt
         ZIwmZke+K6c6+lkgYKbIQvio4AH7NSec4xVCtJNCT4pUTqeruKcN6veYuXBT14uGnHKQ
         ZyvV9g0LoxJX4IcNW9Rm7pAv4IaB8SdXnjs/+LEWlIAEUqW+HL3OU+4uaxmjV8vxeocF
         /+8w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUE1FJW98Jb4e+nftrZ8lIGtLdTg+WYFC/xubPoBUa3l7QK8NYRyBaFC1FeIPN3AlbZtYiTYQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz0uG3V+MqUZ4yQ4LZRs6I++6wp6YMgo+VgkBdWzq0NJ25jr/XN
	Q7nMfcXCWXjg97NK3bdBSksdNuLOVguV7mnzgNH5yleyATyvN+cc
X-Google-Smtp-Source: AGHT+IGKyIpv9nPH+V0Rd9ytIFYAjfhMeJOJpP0Syt34APKyJe3WLf/iHn6GaDiCjB9kEAEqcEhzqg==
X-Received: by 2002:a05:6512:1250:b0:541:d287:a53b with SMTP id 2adb3069b0e04-54405a2314emr1709366e87.19.1738799196200;
        Wed, 05 Feb 2025 15:46:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4141:0:b0:540:fb1a:b5f1 with SMTP id 2adb3069b0e04-5440da4e825ls75850e87.0.-pod-prod-03-eu;
 Wed, 05 Feb 2025 15:46:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWbmu+9+72mnO6Gw/dUp6FDUj2gxIZWcJK/kx9NxU5AvMSaRhanuqqKHOWkKMV/G97UAsI9SANEF54=@googlegroups.com
X-Received: by 2002:ac2:4e04:0:b0:542:29e5:731c with SMTP id 2adb3069b0e04-54405a1059cmr1553639e87.11.1738799193181;
        Wed, 05 Feb 2025 15:46:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738799193; cv=none;
        d=google.com; s=arc-20240605;
        b=kR6FsSiwIqkuvAspTPcvQWTmlspQCOqU4zw4kvOuKdJdUjU/rji1tCMWOwI4d0w+dg
         NEsMpcumMi6s1+vgLFYFZratU+5FbV/6tPCcZ/pu2guCb8O/0ZD3z80OsbKuaXJay2D8
         r+rxX2hngcPH6Hqeci5t8M9GxVgvQGB59zFnMiXjcmY/9GIoj0g8xrcAIuPQSP0LzpPV
         J2kPP1SZxo5rmZs1rkNsAEirFAea+LBGzk6V0vxK2P+nrVg811QkhgIOxHQzvIBFH72Y
         JJrhzF6F06xou+HEo/RplSYNnnoHEU9RhtDFzBHuWJWbnOuN0Z8ZWfDNMufYdw7NuHtE
         AV9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=splJksFz56TDIrwwM0xZxaI8hN1W91tSLAlTGFboN5c=;
        fh=hdEd+d0cO52xNHJmSLO84T9EPSpkGgRHDsnnZ7L8agI=;
        b=OocRTr8bAWyEkLQyOcYknJJf2eFdtKjoV3lKyqF2nhl/h4SAMRbnej7cORMigWrgPx
         VpBgRRlHNPhaF7zrHd+1T9RZceVYrKvSGhtLCZU5E9dIdBQTSoicKtmJ5IeYS+POrLkR
         t9envpCubUpeggY/UszAI3hSFWYasyQ6ER5NQqdTTgH05puCTCZaX9g1SWNczkLTUkRR
         J8J8c8oa197FuaMh1V+s8KI9hZJTduaRzwsl8+HpdPIkECMln1sheLSMS+JLRV9RPnQ8
         WnyzwMpdcxxdNHZAMtKtjXuQHnRfu0bN9RfzSD/gZCOmgqjIQULilv2Q/o0zJrTmW2aN
         +svQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DyboQR5H;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-543ebeb535dsi427364e87.7.2025.02.05.15.46.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2025 15:46:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-4361e89b6daso1858035e9.3
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2025 15:46:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVHShL1eN7ptjHuBTW3sCl3H9eBBxh8wEb8z4AtIHc+kXy0mBETLf2rVYoD1sV8H3LDqPVUnVAxQJA=@googlegroups.com
X-Gm-Gg: ASbGncvlEZdPxgf6MvrFaVsY/3CmtKxE+iUbHC2GUqpEocdP7sDazgB4gw99NnkAKXw
	bLVk4qL/HsXGeRBElV9SYkqliCb+qXz/WDyttVQ5WcR9pWTNJhTm/UK9jDEUsYpN96AHBL5Cs7Q
	==
X-Received: by 2002:a5d:64af:0:b0:38a:518d:97b with SMTP id
 ffacd0b85a97d-38db4858781mr3265952f8f.11.1738799192252; Wed, 05 Feb 2025
 15:46:32 -0800 (PST)
MIME-Version: 1.0
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com> <450a1fe078b0e07bf2e4f3098c9110c9959c6524.1738686764.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <450a1fe078b0e07bf2e4f3098c9110c9959c6524.1738686764.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 6 Feb 2025 00:46:21 +0100
X-Gm-Features: AWEUYZmWa4puMe4djsB8DuAJDHlgw8tfTIgkGA6kMcFx6SJvTthEfUEqJBWFe6Q
Message-ID: <CA+fCnZcG0nv1_ezc+yu3Wj_7iS0r_QfK9OcDnK-MRmJ=BF4iJg@mail.gmail.com>
Subject: Re: [PATCH 15/15] kasan: Add mititgation and debug modes
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: luto@kernel.org, xin@zytor.com, kirill.shutemov@linux.intel.com, 
	palmer@dabbelt.com, tj@kernel.org, brgerst@gmail.com, ardb@kernel.org, 
	dave.hansen@linux.intel.com, jgross@suse.com, will@kernel.org, 
	akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net, dvyukov@google.com, 
	richard.weiyang@gmail.com, ytcoode@gmail.com, tglx@linutronix.de, 
	hpa@zytor.com, seanjc@google.com, paul.walmsley@sifive.com, 
	aou@eecs.berkeley.edu, justinstitt@google.com, jason.andryuk@amd.com, 
	glider@google.com, ubizjak@gmail.com, jannh@google.com, bhe@redhat.com, 
	vincenzo.frascino@arm.com, rafael.j.wysocki@intel.com, 
	ndesaulniers@google.com, mingo@redhat.com, catalin.marinas@arm.com, 
	junichi.nomura@nec.com, nathan@kernel.org, ryabinin.a.a@gmail.com, 
	dennis@kernel.org, bp@alien8.de, kevinloughlin@google.com, morbo@google.com, 
	dan.j.williams@intel.com, julian.stecklina@cyberus-technology.de, 
	peterz@infradead.org, cl@linux.com, kees@kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DyboQR5H;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Feb 4, 2025 at 6:37=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> With smaller memory footprint KASAN could be used in production systems.
> One problem is that saving stacktraces slowes memory allocation
> substantially - with KASAN enabled up to 90% of time spent on kmalloc()
> is spent on saving the stacktrace.
>
> Add mitigation mode to allow the option for running KASAN focused on
> performance and security. In mitigation mode disable saving stacktraces
> and set fault mode to always panic on KASAN error as a security
> mechanism.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
>  lib/Kconfig.kasan | 28 ++++++++++++++++++++++++++++
>  mm/kasan/report.c |  4 ++++
>  mm/kasan/tags.c   |  5 +++++
>  3 files changed, 37 insertions(+)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index d08b4e9bf477..6daa62b40dea 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -244,4 +244,32 @@ config KASAN_SW_TAGS_DENSE
>           ARCH_HAS_KASAN_SW_TAGS_DENSE is needed for this option since th=
e
>           special tag macros need to be properly set for 4-bit wide tags.
>
> +choice
> +       prompt "KASAN operation mode"
> +       default KASAN_OPERATION_DEBUG
> +       help
> +         Choose between the mitigation or debug operation modes.
> +
> +         The first one disables stacktrace saving and enables panic on e=
rror.
> +         Faster memory allocation but less information. The second one i=
s the
> +         default where KASAN operates with full functionality.

This is something that I thought about before and I think we should
_not_ add configuration options like these. The distinction between
debug and mitigation modes is something that's specific to a
particular user of the feature. Some might prefer to take the impact
of having stack traces enabled in a production environment to allow
debugging in-the-wild exploitation attempts. Also at some point in the
future, we will hopefully have production-grade stack traces [1], and
this would thus change the desired behavior of
KASAN_OPERATION_MITIGATION.

We already have the kasan.stacktrace command-line parameter for
disabling stack trace collection. On top of that, if you prefer, we
could add a configuration option that changes the default value of
kasan_flag_stacktrace (but can still be overridden via the
kasan.stacktrace command-line parameter). Note though that by default,
stack traces should be turned on.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=3D211785


> +
> +config KASAN_OPERATION_DEBUG
> +       bool "Debug operation mode"
> +       depends on KASAN
> +       help
> +         The default mode. Full functionality and all boot parameters
> +         available.
> +
> +config KASAN_OPERATION_MITIGATION
> +       bool "Mitigation operation mode"
> +       depends on KASAN
> +       help
> +         Operation mode dedicated at faster operation at the cost of les=
s
> +         information collection. Disables stacktrace saving for faster
> +         allocations and forces panic on KASAN error to mitigate malicio=
us
> +         attacks.
> +
> +endchoice
> +
>  endif # KASAN
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index ee9e406b0cdb..ae989d3bd919 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -47,7 +47,11 @@ enum kasan_arg_fault {
>         KASAN_ARG_FAULT_PANIC_ON_WRITE,
>  };
>
> +#ifdef CONFIG_KASAN_OPERATION_MITIGATION
> +static enum kasan_arg_fault kasan_arg_fault __ro_after_init =3D KASAN_AR=
G_FAULT_PANIC;
> +#else
>  static enum kasan_arg_fault kasan_arg_fault __ro_after_init =3D KASAN_AR=
G_FAULT_DEFAULT;
> +#endif
>
>  /* kasan.fault=3Dreport/panic */
>  static int __init early_kasan_fault(char *arg)
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index c111d98961ed..2414cddeaaf3 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -78,6 +78,11 @@ early_param("kasan.stack_ring_size", early_kasan_flag_=
stack_ring_size);
>
>  void __init kasan_init_tags(void)
>  {
> +       if (IS_ENABLED(CONFIG_KASAN_OPERATION_MITIGATION)) {
> +               static_branch_disable(&kasan_flag_stacktrace);
> +               return;
> +       }
> +
>         switch (kasan_arg_stacktrace) {
>         case KASAN_ARG_STACKTRACE_DEFAULT:
>                 /* Default is specified by kasan_flag_stacktrace definiti=
on. */
> --
> 2.47.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcG0nv1_ezc%2Byu3Wj_7iS0r_QfK9OcDnK-MRmJ%3DBF4iJg%40mail.gmail.com.
