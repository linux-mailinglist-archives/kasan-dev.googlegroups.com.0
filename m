Return-Path: <kasan-dev+bncBCRKNY4WZECBB7EPR66QMGQEYSV6XJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 47AACA29B08
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2025 21:20:14 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-2aa17a7d70dsf132181fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2025 12:20:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738786813; cv=pass;
        d=google.com; s=arc-20240605;
        b=IECb+m2IFquiLB085WBTgeQdYLkyKR4PDB5qJR+T0Esk17kvdawBO6Vn6CffHqKt7K
         5XNbmR7rhvp2fn/Gen9nQUKvRzdWs2/Bg2fjIbUtFIIZIXvh5KF3xt5nfg+t25qPh+5K
         Ex7+H/nO2nPX5qnSP0U1VP1C6dXklCCFEBoLPlXw4GQRCzW9joBhChxGh5565OceMG9t
         /ILnQKDAQNStQ8uasgfrhqVbPISd0/Rql9kVp+1Ue9e3H6uO+IWZaPGijyN3p8wOmQ1z
         KtyhzaD96bp/27fFVhln12j3Y8t/LBeGWTpHElTVjLmiHTT+MZzL20m2+DoFz8wYitaD
         OIKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=9ZOjWDdX9BaG1z91I+lm+IFQcVwlCEiUIBfD6fBYic4=;
        fh=oogidv9MYUS9VtRi+C5IpeJqIvDYBtwn+cr8rvKEBHk=;
        b=aOkET6Frktvr40uF9lYwMPvMK9IoQd3SeZSbS5V7F/DPv/nDK+u+JorDOBap5F2L/m
         PisPA9RdH4mzpV+SyzDDpSZRsHIMiKYBQLRuKRwHqcqziATIYHVUP2KdTFMDMg/eaMHh
         nvmg1DtqD8H0G9KI7xjsMn51PYhBXSsZQVvYL8hPPt6I2ChET6jRndu0csqZ/hadDB/C
         V28jtJfweoA7/9Nw1QdXCFyiTLZquX2n0SQQXhbcfVr+Mn+VxvcXwojKRHJHwmiqyOX6
         9E+RoL3qUaaAVym788DAsBGSWqO1R22J+AWpmH8I2XxcrMA6pnByDRGrD7jlf71O3v4+
         7PKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20230601.gappssmtp.com header.s=20230601 header.b="GJ0Gj/AR";
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=palmer@dabbelt.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738786813; x=1739391613; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:to:from:cc:in-reply-to
         :subject:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9ZOjWDdX9BaG1z91I+lm+IFQcVwlCEiUIBfD6fBYic4=;
        b=b2zl8nwswq+rpQZAFwfquoATqYtgLTocsrgOOulQzLEpqKo8qnmeL57dHjIZXepsH8
         4/4vN/dTEZMpk0vutfMahU8QIcY0oLKuV5wec5+RPNatO/5rp5vALcQZymAegpCOsGyw
         fZztYV6Sb7iIG6tsKkhb9RxP+MQ1ESALK3EoXHjOU5wEGjhUUSbiEhv/TzWgf7B3oJUJ
         RA5zUoL3eYcAEKUG4h5ANrEUlQxIXnhwfy1/unQ6xSUNtfkUwlMcdddx9IjcnYPRZPY0
         jjD6+E0GtqwA2qLfJvDZR88ajXEcCDwhgmT5Uv00Y373wBy6divsGv6+ySKSviTenv3O
         U5Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738786813; x=1739391613;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:to:from:cc:in-reply-to:subject:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9ZOjWDdX9BaG1z91I+lm+IFQcVwlCEiUIBfD6fBYic4=;
        b=QJ60nh9opkFyPMBNhCbAfq3d2QCdUC+hrl+9wCetQTLavcQWSeOIkujZd+9nJurJw5
         0YT94QVLwwNxldfycDuY6sMwHHJfumc1MsN1Y82BYA4ZvCPnDT5xLl9atDJSdnKfp77P
         C0TZU/FiwwssdfRFf0GXZyUKRHZ2qEg2980lchcdS+SS0nf9OjIm3bb3gXYeuJUU3lmi
         Zq2PEyg5LrvFQfw9VkxtPiMA+e+dBQGowcr5cbtpK2W60Bh3M1m0/jFQTS3DUP3/Ngb4
         +dmWT4xjI2v5FKUSdvRz9VmldW1UN/44UB/XQ/wa4jYIwUHg+pVd8V/Oa4fp+/vY4zlO
         lI8w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUuRZJsvqQ3hl9xBdljEDwsdBy0tOkhWOTtDv0op5xLZcZtPEmB0ABxqwFDHoDjUe6cCOJ8Aw==@lfdr.de
X-Gm-Message-State: AOJu0YweEo917aivNhMzBZvXfktrtM7ZINzAI0RSUlv3m/Cc5UQwjs36
	nlmCFPVu2jn6o89K/8XlIPR7tE+RR0G31bDVLNJ6LN4AyXFod4Go
X-Google-Smtp-Source: AGHT+IEVeMDfckk6grbW0930iMJfI9rVnJdugaR2o5P4zFLOLZLXTPRNgjullNqBpcuovPNUYj8yjA==
X-Received: by 2002:a05:6870:eca4:b0:29e:7629:1466 with SMTP id 586e51a60fabf-2b81e978595mr531965fac.7.1738786812665;
        Wed, 05 Feb 2025 12:20:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ac21:b0:29e:83d8:6f06 with SMTP id
 586e51a60fabf-2b81cd23f4dls192357fac.0.-pod-prod-00-us; Wed, 05 Feb 2025
 12:20:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVglKues1eRyXW5j1+PR9S5yVgw41utH0s9LMYFbtLTdNseaCRA/hzKDjpdnNUoxEDSYb9kRkdftvk=@googlegroups.com
X-Received: by 2002:a05:6830:6713:b0:718:4fd:bd78 with SMTP id 46e09a7af769-726ad72c35fmr635506a34.13.1738786811885;
        Wed, 05 Feb 2025 12:20:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738786811; cv=none;
        d=google.com; s=arc-20240605;
        b=WS7ch3WXsGEDG+KUQu3xIiJndGbOsmJ17teK+vVGspzntnYw2oUsz4wO2bCyttIMWm
         tyIbtg54kte2RJFAjn4SwAwIMsW4biEuT1K76bAwI45oAmyAf/VfZn/YCLEVFizbDOpO
         zLlbuOJhXN+hI3ZVmOGl1hQQDCTUTdYY/5ustJxDiGRK06+gQj3u876Qzpduu9vSZiKR
         FaM+ZtXrrfRF/pmLpAUHMix+ypxJh0Ixl+fGEb9JTBK2rcqzHjA2GoNvJwUrTrt89Ajf
         TfFlbyksp34JDfOKyU70xAfiDURe2ZruWI4fkEzcw3iP7shZW2fL18scSZvtXJLfbU2J
         6peA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=IX+Sh5T3PaL+QWEnl0hjKKEH7VOJE9BsDETeBZSLsC4=;
        fh=B5zH3RiXsBw3FpOwgeJwj0cGX3bDrNSmsUxevp2sFMo=;
        b=BHvaHQTSBTHcKftRQP903zeMj4Xt7zSmzpySQ3uEFukrnLAH4QGBIjIpkruGfoe27m
         +zK9zubLOLNqInnPCmb1EBQCrVTKeXMixqR6PfM+hJoMIlj1l6wrRyH6jpkrwWawnMEg
         Y2BZRgGV6q56VMFjZtD6R9raYl8G7GlcHvfEuiqL+byg+LF0uedhtTZuzIVcOL7k0zbO
         cavxtWY6TF5fylLb9IQmw8dJ21zB2X0NgmrJ+qxE0W1vuh9MvxEwnEifi9/K+e9ErEzg
         N/71r4UtC2NVZRoeSNtc5oKlvd+Icm0neDtEQNfxNXdsihPbqb5kE6IpzrqNpbha5IyX
         61pg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20230601.gappssmtp.com header.s=20230601 header.b="GJ0Gj/AR";
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=palmer@dabbelt.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-726617d05e1si637386a34.2.2025.02.05.12.20.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2025 12:20:11 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-2f9f5caa37cso1099681a91.0
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2025 12:20:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXn8tJ+kraDLZVhdAaZ1wNHUWNzoKr2Uiqg6oIz6atgE74nPN5ILphgr85KoK5M+GpUy2pJlQqtcnc=@googlegroups.com
X-Gm-Gg: ASbGncvfsr5c7+fi9CcIfA7o3/HiwM6yEprz2+tZS65qvj2wxj3DPAoUIuwlEFkifZW
	dpFjMnA3YvMI4rJIXfOLbXXjmfexryz3WisvxCjto3h6qjENMrff7Ocimn9FPEyJaJRxbZ68iQE
	ltYKbvPGo0GgwqRUQQw0O8A7VoLqXRsAFjZM2rARY/rHWSKDzlQxhp4gWqIEAL//1MsZ0t7UOp6
	EBc7t0UhzWO6ZhOpHb1UpS/3RyDVZBtTuuQ6NujVwGgVdXm+PzxGXwOrxbmI/E0rOKdlK9LBzn6
	V5tDr/e7XGUN
X-Received: by 2002:a17:90a:e7c8:b0:2f7:b149:538f with SMTP id 98e67ed59e1d1-2f9ff787646mr1078810a91.4.1738786810832;
        Wed, 05 Feb 2025 12:20:10 -0800 (PST)
Received: from localhost ([192.184.165.199])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2f9e1d77b73sm2228736a91.12.2025.02.05.12.20.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Feb 2025 12:20:10 -0800 (PST)
Date: Wed, 05 Feb 2025 12:20:10 -0800 (PST)
Subject: Re: [PATCH 04/15] kasan: arm64: x86: risc-v: Make special tags arch specific
In-Reply-To: <cdb119dcade0cea25745c920aba8434c27e4c93b.1738686764.git.maciej.wieczor-retman@intel.com>
CC: luto@kernel.org, xin@zytor.com, kirill.shutemov@linux.intel.com, tj@kernel.org,
  andreyknvl@gmail.com, brgerst@gmail.com, Ard Biesheuvel <ardb@kernel.org>,
  dave.hansen@linux.intel.com, jgross@suse.com, Will Deacon <will@kernel.org>, akpm@linux-foundation.org,
  Arnd Bergmann <arnd@arndb.de>, corbet@lwn.net, maciej.wieczor-retman@intel.com, dvyukov@google.com,
  richard.weiyang@gmail.com, ytcoode@gmail.com, tglx@linutronix.de, hpa@zytor.com, seanjc@google.com,
  Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, justinstitt@google.com, jason.andryuk@amd.com,
  glider@google.com, ubizjak@gmail.com, jannh@google.com, bhe@redhat.com, vincenzo.frascino@arm.com,
  rafael.j.wysocki@intel.com, ndesaulniers@google.com, mingo@redhat.com,
  Catalin Marinas <catalin.marinas@arm.com>, junichi.nomura@nec.com, nathan@kernel.org, ryabinin.a.a@gmail.com,
  dennis@kernel.org, bp@alien8.de, kevinloughlin@google.com, morbo@google.com,
  dan.j.williams@intel.com, julian.stecklina@cyberus-technology.de, peterz@infradead.org, cl@linux.com,
  kees@kernel.org, kasan-dev@googlegroups.com, x86@kernel.org,
  linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: maciej.wieczor-retman@intel.com
Message-ID: <mhng-33ede5ce-7625-431b-a48f-fd6abf7f78ba@palmer-ri-x1c9>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20230601.gappssmtp.com header.s=20230601
 header.b="GJ0Gj/AR";       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=palmer@dabbelt.com;
       dara=pass header.i=@googlegroups.com
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

On Tue, 04 Feb 2025 09:33:45 PST (-0800), maciej.wieczor-retman@intel.com wrote:
> KASAN's tag-based mode defines multiple special tag values. They're
> reserved for:
> - Native kernel value. On arm64 it's 0xFF and it causes an early return
>   in the tag checking function.
> - Invalid value. 0xFE marks an area as freed / unallocated. It's also
>   the value that is used to initialize regions of shadow memory.
> - Max value. 0xFD is the highest value that can be randomly generated
>   for a new tag.
>
> Metadata macro is also defined:
> - Tag width equal to 8.
>
> Tag-based mode on x86 is going to use 4 bit wide tags so all the above
> values need to be changed accordingly.
>
> Make tags arch specific for x86, risc-v and arm64. On x86 the values
> just lose the top 4 bits.
>
> Replace hardcoded kernel tag value and tag width with macros in KASAN's
> non-arch specific code.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
>  MAINTAINERS                         |  2 +-
>  arch/arm64/include/asm/kasan-tags.h |  9 +++++++++
>  arch/riscv/include/asm/kasan-tags.h | 12 ++++++++++++
>  arch/riscv/include/asm/kasan.h      |  4 ----
>  arch/x86/include/asm/kasan-tags.h   |  9 +++++++++
>  include/linux/kasan-tags.h          | 12 +++++++++++-
>  include/linux/kasan.h               |  4 +++-
>  include/linux/mm.h                  |  6 +++---
>  include/linux/page-flags-layout.h   |  7 +------
>  9 files changed, 49 insertions(+), 16 deletions(-)
>  create mode 100644 arch/arm64/include/asm/kasan-tags.h
>  create mode 100644 arch/riscv/include/asm/kasan-tags.h
>  create mode 100644 arch/x86/include/asm/kasan-tags.h
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index b878ddc99f94..45671faa3b6f 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -12227,7 +12227,7 @@ L:	kasan-dev@googlegroups.com
>  S:	Maintained
>  B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
>  F:	Documentation/dev-tools/kasan.rst
> -F:	arch/*/include/asm/*kasan.h
> +F:	arch/*/include/asm/*kasan*.h
>  F:	arch/*/mm/kasan_init*
>  F:	include/linux/kasan*.h
>  F:	lib/Kconfig.kasan
> diff --git a/arch/arm64/include/asm/kasan-tags.h b/arch/arm64/include/asm/kasan-tags.h
> new file mode 100644
> index 000000000000..9e835da95f6b
> --- /dev/null
> +++ b/arch/arm64/include/asm/kasan-tags.h
> @@ -0,0 +1,9 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_KASAN_TAGS_H
> +#define __ASM_KASAN_TAGS_H
> +
> +#define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
> +
> +#define KASAN_TAG_WIDTH 8
> +
> +#endif /* ASM_KASAN_TAGS_H */
> diff --git a/arch/riscv/include/asm/kasan-tags.h b/arch/riscv/include/asm/kasan-tags.h
> new file mode 100644
> index 000000000000..83d7dcc8af74
> --- /dev/null
> +++ b/arch/riscv/include/asm/kasan-tags.h
> @@ -0,0 +1,12 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_KASAN_TAGS_H
> +#define __ASM_KASAN_TAGS_H
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +#define KASAN_TAG_KERNEL	0x7f /* native kernel pointers tag */
> +#endif
> +
> +#define KASAN_TAG_WIDTH 8
> +
> +#endif /* ASM_KASAN_TAGS_H */
> +
> diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> index f6b378ba936d..27938e0d5233 100644
> --- a/arch/riscv/include/asm/kasan.h
> +++ b/arch/riscv/include/asm/kasan.h
> @@ -41,10 +41,6 @@
>
>  #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>
> -#ifdef CONFIG_KASAN_SW_TAGS
> -#define KASAN_TAG_KERNEL	0x7f /* native kernel pointers tag */
> -#endif
> -
>  #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
>  #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
>  #define arch_kasan_get_tag(addr)	__tag_get(addr)
> diff --git a/arch/x86/include/asm/kasan-tags.h b/arch/x86/include/asm/kasan-tags.h
> new file mode 100644
> index 000000000000..68ba385bc75c
> --- /dev/null
> +++ b/arch/x86/include/asm/kasan-tags.h
> @@ -0,0 +1,9 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_KASAN_TAGS_H
> +#define __ASM_KASAN_TAGS_H
> +
> +#define KASAN_TAG_KERNEL	0xF /* native kernel pointers tag */
> +
> +#define KASAN_TAG_WIDTH		4
> +
> +#endif /* ASM_KASAN_TAGS_H */
> diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
> index e07c896f95d3..b4aacfa8709b 100644
> --- a/include/linux/kasan-tags.h
> +++ b/include/linux/kasan-tags.h
> @@ -2,7 +2,17 @@
>  #ifndef _LINUX_KASAN_TAGS_H
>  #define _LINUX_KASAN_TAGS_H
>
> -#include <asm/kasan.h>
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> +#include <asm/kasan-tags.h>
> +#endif
> +
> +#ifdef CONFIG_KASAN_SW_TAGS_DENSE
> +#define KASAN_TAG_WIDTH		4
> +#endif
> +
> +#ifndef KASAN_TAG_WIDTH
> +#define KASAN_TAG_WIDTH		0
> +#endif
>
>  #ifndef KASAN_TAG_KERNEL
>  #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 5a3e9bec21c2..83146367170a 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -88,7 +88,9 @@ static inline u8 kasan_get_shadow_tag(const void *addr)
>
>  #ifdef CONFIG_KASAN_SW_TAGS
>  /* This matches KASAN_TAG_INVALID. */
> -#define KASAN_SHADOW_INIT 0xFE
> +#ifndef KASAN_SHADOW_INIT
> +#define KASAN_SHADOW_INIT KASAN_TAG_INVALID
> +#endif
>  #else
>  #define KASAN_SHADOW_INIT 0
>  #endif
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 61fff5d34ed5..ddca2f63a5f6 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -1813,7 +1813,7 @@ static inline u8 page_kasan_tag(const struct page *page)
>
>  	if (kasan_enabled()) {
>  		tag = (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
> -		tag ^= 0xff;
> +		tag ^= KASAN_TAG_KERNEL;
>  	}
>
>  	return tag;
> @@ -1826,7 +1826,7 @@ static inline void page_kasan_tag_set(struct page *page, u8 tag)
>  	if (!kasan_enabled())
>  		return;
>
> -	tag ^= 0xff;
> +	tag ^= KASAN_TAG_KERNEL;
>  	old_flags = READ_ONCE(page->flags);
>  	do {
>  		flags = old_flags;
> @@ -1845,7 +1845,7 @@ static inline void page_kasan_tag_reset(struct page *page)
>
>  static inline u8 page_kasan_tag(const struct page *page)
>  {
> -	return 0xff;
> +	return KASAN_TAG_KERNEL;
>  }
>
>  static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
> diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags-layout.h
> index 7d79818dc065..ac3576f409ad 100644
> --- a/include/linux/page-flags-layout.h
> +++ b/include/linux/page-flags-layout.h
> @@ -3,6 +3,7 @@
>  #define PAGE_FLAGS_LAYOUT_H
>
>  #include <linux/numa.h>
> +#include <linux/kasan-tags.h>
>  #include <generated/bounds.h>
>
>  /*
> @@ -72,12 +73,6 @@
>  #define NODE_NOT_IN_PAGE_FLAGS	1
>  #endif
>
> -#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> -#define KASAN_TAG_WIDTH 8
> -#else
> -#define KASAN_TAG_WIDTH 0
> -#endif
> -
>  #ifdef CONFIG_NUMA_BALANCING
>  #define LAST__PID_SHIFT 8
>  #define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)

Acked-by: Palmer Dabbelt <palmer@rivosinc.com> # RISC-V

Probably best to keep this along with the rest of the patches, but LMK 
if you want me to point something at the RISC-V tree.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/mhng-33ede5ce-7625-431b-a48f-fd6abf7f78ba%40palmer-ri-x1c9.
