Return-Path: <kasan-dev+bncBAABBCFWV3FAMGQE4B2AQZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 42926CDBA01
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Dec 2025 08:49:30 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-88a2ea47fa5sf154864426d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Dec 2025 23:49:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766562569; cv=pass;
        d=google.com; s=arc-20240605;
        b=gdXVeXxlhZ99hV4ItVCHqXL0koSqWzpFoxsGQ4VU0OfEMPEjB0Ogm5iVGcEypWu3bA
         QL2YyFWwZkeyC38fGDzBxD7ZrnPd46jI9fVfcC1evBmSYZy0foaf6PxL5SuvHC1jQ2rd
         wOSl48jmSvxqYO/HsZaUbxI3uwejL0u2DMGbqE5XbJANUa7/9/6kAapMkQWofeOYPpCl
         f81aHMBQWleCdaZ1519PSWpMxkaEvcxPqE/IazdC1hjdGIOJtBKmU02DVhasdy1/iaZr
         bEVTCoV/pQHXlK/Bb+R4HXYL7nCInkZzsIki4cD5brPEusXG/pSTZaXhL9JmJGZjJ1TI
         /uOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=WOkYf7yQz2qNfFvi/FL8TdrlZjpU+syf5T7bEKMwY/s=;
        fh=9WSpMYwTxFN+zT5vo536xo+MGvXB41hpu0oqRE6Y1Eo=;
        b=DEB7N2fH3SBu9xBC/EwH4uXbfOp/rTICpTQJr2qBPIdwAQhlecr9ohO+xpMR+vGmv5
         dppG0Y76FlG9V2QqaJMtFJh90fr6U2ETHs0hSbSaAa3qBAidpeRxY0fIsLm1d7UHKFjq
         PIuVK4XZDWvL5dqN/ySy19JIheE/LRRZZQvb+AANQTafWDAVD9pcctb/RMYlBO7dL/Oh
         tqf+Z2DiT9xI2dF/MmZ3l12gyUzLjA35DmfuvmNzwdttvTehvFX8kLXUgAMa0AyRTrNT
         o+48KtOX8BGCAwyi5fX8EeD6tmbOLoIa+FRwzgj/hOg+VuGkgII0sIEWPCYAunV4f+3Q
         ntkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b=CGbaVs09;
       spf=pass (google.com: domain of tianruidong@linux.alibaba.com designates 115.124.30.101 as permitted sender) smtp.mailfrom=tianruidong@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766562569; x=1767167369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WOkYf7yQz2qNfFvi/FL8TdrlZjpU+syf5T7bEKMwY/s=;
        b=P/BBrRds2dbHPM8uQEQxKOtuN3ZwXIxfOvK3Pf/k3prQMTOE+WGE3/dNMs7KoBG2Me
         wY0LKubtyLkLUTAYr8oyyvHw00J9MXlkNULFTONM6cQUs1qEwzvy16jOZPgE5EOb52i/
         c4hKLda/BzHa+ebVgDaeksc5PlzuIcwqCWqLo54MkykBG5GczlaisRHZv0022H5IBy2k
         OIB4MqTr6/xumcDgLUNba9FYP4xAfV86kpUbejDpqkuPopdy4Q5Df6mnCTCuJ98T2+x2
         PPcU6XEisXL3ctucwg+UebuNXDmNxnt0cYt2dwATt+M/i0AvkSUOSt9v7f0WtsNvYRfV
         tvkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766562569; x=1767167369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WOkYf7yQz2qNfFvi/FL8TdrlZjpU+syf5T7bEKMwY/s=;
        b=NUQNWdotPBH33IOeeu1mXhoz4JcVG8K1VbNANsMX9MwAgSfWph6+3D61gQUppxoIfm
         TNOAI6ghweRmWOgNseCaMOvlXth1+FSO4fzLhMjMsSmqIp9QTWm7MwHwKkd7p5prRcoM
         /TBxYhBBZoAAq4R9SWH7r1n4MPtcI2oGpdVrD52c88ihY1d8nRXJWanWXczAgr22gexv
         UyujlNXjXK4IX2KC7bEMjchL8k59TmDfarfugRcuaKzTeS94Ne5HIko9bfPD9JAMMgVJ
         eeUd3gbjMGR81meX0o5hU9ZZfsuGMx+LMUZMCpROzoJ1VANNkgPq0plUhl/n7/afnB+S
         HHDg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU0508x8nCwB3vIaGEZVKeTNcNp5zoUEaQ6iFq7Xhoz492CxNNj+AcwfK3tMfohQLGWoZnF2Q==@lfdr.de
X-Gm-Message-State: AOJu0Yxq5EfMSkvN5tDz8ul5Kyje65L7Hy1gmdmgiw6sg+g+InT3qOrz
	tPS3TtyLA/WEcMfYBcjZIQOgzRBMkbrizi9gMftcl7b/Krihh3M8lHDO
X-Google-Smtp-Source: AGHT+IHa5wUMvJXWdvyybZiRqu2HIsd0NuV9UDQefyxfHiRyrv4S8vPIaHB52df8FnFVL/VfhAsLOw==
X-Received: by 2002:a05:6214:19c9:b0:88a:3255:716b with SMTP id 6a1803df08f44-88c5252e7d6mr324293596d6.24.1766562568961;
        Tue, 23 Dec 2025 23:49:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaNRth6rj86vJ9i/6oMfQMriyXUTNq/4C+Nejh9zZ8nqw=="
Received: by 2002:a05:6214:a08:b0:880:21ca:d7b1 with SMTP id
 6a1803df08f44-8887cd5b503ls98452426d6.2.-pod-prod-00-us-canary; Tue, 23 Dec
 2025 23:49:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXYKE9CBws8sOABS5DjqA0XCfWDigVFP7Qv9Q/e5ju3rJXIAJxhE99LtBYVb+7KTXNlCI0BP+JALHs=@googlegroups.com
X-Received: by 2002:a05:6122:d97:b0:54a:8deb:21a7 with SMTP id 71dfb90a1353d-5614f6a578amr7146196e0c.4.1766562568223;
        Tue, 23 Dec 2025 23:49:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766562568; cv=none;
        d=google.com; s=arc-20240605;
        b=O5iK7O+IBFr6Jb3CWaGQn1bB967wNpYXxf/2/DAKqyGZ62sL+UfbR9SWXLNg5tz4iT
         fWdyl329zUJw20ATefje3gRAwHVkqTOo8/iEaNwo4XfqkGetIp+oJ0OTnzTJh8V5QxR3
         cwBRstjymza4hmGEPH0G9BlnFgaLjYPqkIviMbDqcIs07dAVi5AQ/aRltvoAqBugXekX
         n5BJfAdOcPPJX9aeQ0Zzd3dKUCFG/ot6ruLtxnmu2KIzYJ2MOkI6+bTqtP3rrSlCYIA7
         KJYgCOnOqhZWZjVBj+K3eHK6Mngx9bCSjUoMWKCrl3div/199iyuOb1HtEUXb/LOU1XQ
         1hBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=h0/Sg9vEcVPykAL4iwpmTNn0DtmSkFDaeo8PJsZs1/M=;
        fh=/ISY5QufQnTfO4TkdL6fMd5umtr0f1Aq3646za2abyA=;
        b=j1k1qKkSMmkTM8SkSlRExw8l32IDzoG73gSCiDnyACO51/2JEa/tvesmNsHkppW4mZ
         gkfwnJ3hxI6IC3AyaMUDp3gT6hkaF7/66/rW8d8f9FW6C9ubhjXkQeoIGJOaX6SiyveI
         I5zsuewQypqTHI3BR+lm45kCKVzGMqGrGhQW35uCJ42mLGXS5Vk3MQoyJQ3yaFer5U68
         NcRRXZWkJZE+X/bjtNC8ro6wmUZdxpyeWgyg6GKd04LEiHH5Vh63ef/r7bz2qxZG9tnx
         nsCodwVt2TPxXaEMBdPjirC4iDMnlrZXHvebCjCwmyhTNrIZJ3OSQcarulCqVfL1LzFa
         A5Rg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b=CGbaVs09;
       spf=pass (google.com: domain of tianruidong@linux.alibaba.com designates 115.124.30.101 as permitted sender) smtp.mailfrom=tianruidong@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
Received: from out30-101.freemail.mail.aliyun.com (out30-101.freemail.mail.aliyun.com. [115.124.30.101])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5615d225328si409055e0c.5.2025.12.23.23.49.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Dec 2025 23:49:27 -0800 (PST)
Received-SPF: pass (google.com: domain of tianruidong@linux.alibaba.com designates 115.124.30.101 as permitted sender) client-ip=115.124.30.101;
Received: from 30.221.132.102(mailfrom:tianruidong@linux.alibaba.com fp:SMTPD_---0WvaN3qJ_1766562562 cluster:ay36)
          by smtp.aliyun-inc.com;
          Wed, 24 Dec 2025 15:49:23 +0800
Message-ID: <db72933f-cda7-4196-8e54-73cbefbf1a26@linux.alibaba.com>
Date: Wed, 24 Dec 2025 15:49:21 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v13 2/5] arm64: add support for ARCH_HAS_COPY_MC
To: Tong Tiangen <tongtiangen@huawei.com>, Mark Rutland
 <mark.rutland@arm.com>, Jonathan Cameron <Jonathan.Cameron@Huawei.com>,
 Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>, James Morse
 <james.morse@arm.com>, Robin Murphy <robin.murphy@arm.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,
 "Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
 "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
 Madhavan Srinivasan <maddy@linux.ibm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
 Guohanjun <guohanjun@huawei.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-3-tongtiangen@huawei.com>
From: Ruidong Tian <tianruidong@linux.alibaba.com>
In-Reply-To: <20241209024257.3618492-3-tongtiangen@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: tianruidong@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.alibaba.com header.s=default header.b=CGbaVs09;
       spf=pass (google.com: domain of tianruidong@linux.alibaba.com
 designates 115.124.30.101 as permitted sender) smtp.mailfrom=tianruidong@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
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

Hi Tong:

I applied this path on 6.18 and tested on Kunpeng920, system still alive=20
when i inject a error in copy from user context, but I found that user=20
application receive a SIGBUS, this action is different with x86 machine=20
which return -EFAULT rather than send SIGBUS.

I added a patch to fix this behavior[0]. Feel free to incorporate it=20
into your series, or I can send it as a formal follow-up patch,=20
whichever you prefer.

[0]: https://github.com/winterddd/linux/tree/arm-copyin

Best regards,
Ruidong

=E5=9C=A8 2024/12/9 10:42, Tong Tiangen =E5=86=99=E9=81=93:
> For the arm64 kernel, when it processes hardware memory errors for
> synchronize notifications(do_sea()), if the errors is consumed within the
> kernel, the current processing is panic. However, it is not optimal.
>=20
> Take copy_from/to_user for example, If ld* triggers a memory error, even =
in
> kernel mode, only the associated process is affected. Killing the user
> process and isolating the corrupt page is a better choice.
>=20
> Add new fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR to identify insn
> that can recover from memory errors triggered by access to kernel memory,
> and this fixup type is used in __arch_copy_to_user(), This make the regul=
ar
> copy_to_user() will handle kernel memory errors.
>=20
> Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
> ---
>   arch/arm64/Kconfig                   |  1 +
>   arch/arm64/include/asm/asm-extable.h | 31 +++++++++++++++++++++++-----
>   arch/arm64/include/asm/asm-uaccess.h |  4 ++++
>   arch/arm64/include/asm/extable.h     |  1 +
>   arch/arm64/lib/copy_to_user.S        | 10 ++++-----
>   arch/arm64/mm/extable.c              | 19 +++++++++++++++++
>   arch/arm64/mm/fault.c                | 30 ++++++++++++++++++++-------
>   7 files changed, 78 insertions(+), 18 deletions(-)
>=20
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 100570a048c5..5fa54d31162c 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -21,6 +21,7 @@ config ARM64
>   	select ARCH_ENABLE_THP_MIGRATION if TRANSPARENT_HUGEPAGE
>   	select ARCH_HAS_CACHE_LINE_SIZE
>   	select ARCH_HAS_CC_PLATFORM
> +	select ARCH_HAS_COPY_MC if ACPI_APEI_GHES
>   	select ARCH_HAS_CURRENT_STACK_POINTER
>   	select ARCH_HAS_DEBUG_VIRTUAL
>   	select ARCH_HAS_DEBUG_VM_PGTABLE
> diff --git a/arch/arm64/include/asm/asm-extable.h b/arch/arm64/include/as=
m/asm-extable.h
> index b8a5861dc7b7..0f9123efca0a 100644
> --- a/arch/arm64/include/asm/asm-extable.h
> +++ b/arch/arm64/include/asm/asm-extable.h
> @@ -5,11 +5,13 @@
>   #include <linux/bits.h>
>   #include <asm/gpr-num.h>
>  =20
> -#define EX_TYPE_NONE			0
> -#define EX_TYPE_BPF			1
> -#define EX_TYPE_UACCESS_ERR_ZERO	2
> -#define EX_TYPE_KACCESS_ERR_ZERO	3
> -#define EX_TYPE_LOAD_UNALIGNED_ZEROPAD	4
> +#define EX_TYPE_NONE				0
> +#define EX_TYPE_BPF				1
> +#define EX_TYPE_UACCESS_ERR_ZERO		2
> +#define EX_TYPE_KACCESS_ERR_ZERO		3
> +#define EX_TYPE_LOAD_UNALIGNED_ZEROPAD		4
> +/* kernel access memory error safe */
> +#define EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR	5
>  =20
>   /* Data fields for EX_TYPE_UACCESS_ERR_ZERO */
>   #define EX_DATA_REG_ERR_SHIFT	0
> @@ -51,6 +53,17 @@
>   #define _ASM_EXTABLE_UACCESS(insn, fixup)				\
>   	_ASM_EXTABLE_UACCESS_ERR_ZERO(insn, fixup, wzr, wzr)
>  =20
> +#define _ASM_EXTABLE_KACCESS_ERR_ZERO_MEM_ERR(insn, fixup, err, zero)	\
> +	__ASM_EXTABLE_RAW(insn, fixup, 					\
> +			  EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR,		\
> +			  (						\
> +			    EX_DATA_REG(ERR, err) |			\
> +			    EX_DATA_REG(ZERO, zero)			\
> +			  ))
> +
> +#define _ASM_EXTABLE_KACCESS_MEM_ERR(insn, fixup)			\
> +	_ASM_EXTABLE_KACCESS_ERR_ZERO_MEM_ERR(insn, fixup, wzr, wzr)
> +
>   /*
>    * Create an exception table entry for uaccess `insn`, which will branc=
h to `fixup`
>    * when an unhandled fault is taken.
> @@ -69,6 +82,14 @@
>   	.endif
>   	.endm
>  =20
> +/*
> + * Create an exception table entry for kaccess `insn`, which will branch=
 to
> + * `fixup` when an unhandled fault is taken.
> + */
> +	.macro          _asm_extable_kaccess_mem_err, insn, fixup
> +	_ASM_EXTABLE_KACCESS_MEM_ERR(\insn, \fixup)
> +	.endm
> +
>   #else /* __ASSEMBLY__ */
>  =20
>   #include <linux/stringify.h>
> diff --git a/arch/arm64/include/asm/asm-uaccess.h b/arch/arm64/include/as=
m/asm-uaccess.h
> index 5b6efe8abeeb..19aa0180f645 100644
> --- a/arch/arm64/include/asm/asm-uaccess.h
> +++ b/arch/arm64/include/asm/asm-uaccess.h
> @@ -57,6 +57,10 @@ alternative_else_nop_endif
>   	.endm
>   #endif
>  =20
> +#define KERNEL_MEM_ERR(l, x...)			\
> +9999:	x;					\
> +	_asm_extable_kaccess_mem_err	9999b, l
> +
>   #define USER(l, x...)				\
>   9999:	x;					\
>   	_asm_extable_uaccess	9999b, l
> diff --git a/arch/arm64/include/asm/extable.h b/arch/arm64/include/asm/ex=
table.h
> index 72b0e71cc3de..bc49443bc502 100644
> --- a/arch/arm64/include/asm/extable.h
> +++ b/arch/arm64/include/asm/extable.h
> @@ -46,4 +46,5 @@ bool ex_handler_bpf(const struct exception_table_entry =
*ex,
>   #endif /* !CONFIG_BPF_JIT */
>  =20
>   bool fixup_exception(struct pt_regs *regs);
> +bool fixup_exception_me(struct pt_regs *regs);
>   #endif
> diff --git a/arch/arm64/lib/copy_to_user.S b/arch/arm64/lib/copy_to_user.=
S
> index 802231772608..bedab1678431 100644
> --- a/arch/arm64/lib/copy_to_user.S
> +++ b/arch/arm64/lib/copy_to_user.S
> @@ -20,7 +20,7 @@
>    *	x0 - bytes not copied
>    */
>   	.macro ldrb1 reg, ptr, val
> -	ldrb  \reg, [\ptr], \val
> +	KERNEL_MEM_ERR(9998f, ldrb  \reg, [\ptr], \val)
>   	.endm
>  =20
>   	.macro strb1 reg, ptr, val
> @@ -28,7 +28,7 @@
>   	.endm
>  =20
>   	.macro ldrh1 reg, ptr, val
> -	ldrh  \reg, [\ptr], \val
> +	KERNEL_MEM_ERR(9998f, ldrh  \reg, [\ptr], \val)
>   	.endm
>  =20
>   	.macro strh1 reg, ptr, val
> @@ -36,7 +36,7 @@
>   	.endm
>  =20
>   	.macro ldr1 reg, ptr, val
> -	ldr \reg, [\ptr], \val
> +	KERNEL_MEM_ERR(9998f, ldr \reg, [\ptr], \val)
>   	.endm
>  =20
>   	.macro str1 reg, ptr, val
> @@ -44,7 +44,7 @@
>   	.endm
>  =20
>   	.macro ldp1 reg1, reg2, ptr, val
> -	ldp \reg1, \reg2, [\ptr], \val
> +	KERNEL_MEM_ERR(9998f, ldp \reg1, \reg2, [\ptr], \val)
>   	.endm
>  =20
>   	.macro stp1 reg1, reg2, ptr, val
> @@ -64,7 +64,7 @@ SYM_FUNC_START(__arch_copy_to_user)
>   9997:	cmp	dst, dstin
>   	b.ne	9998f
>   	// Before being absolutely sure we couldn't copy anything, try harder
> -	ldrb	tmp1w, [srcin]
> +KERNEL_MEM_ERR(9998f, ldrb	tmp1w, [srcin])
>   USER(9998f, sttrb tmp1w, [dst])
>   	add	dst, dst, #1
>   9998:	sub	x0, end, dst			// bytes not copied
> diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
> index 228d681a8715..9ad2b6473b60 100644
> --- a/arch/arm64/mm/extable.c
> +++ b/arch/arm64/mm/extable.c
> @@ -72,7 +72,26 @@ bool fixup_exception(struct pt_regs *regs)
>   		return ex_handler_uaccess_err_zero(ex, regs);
>   	case EX_TYPE_LOAD_UNALIGNED_ZEROPAD:
>   		return ex_handler_load_unaligned_zeropad(ex, regs);
> +	case EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR:
> +		return false;
>   	}
>  =20
>   	BUG();
>   }
> +
> +bool fixup_exception_me(struct pt_regs *regs)
> +{
> +	const struct exception_table_entry *ex;
> +
> +	ex =3D search_exception_tables(instruction_pointer(regs));
> +	if (!ex)
> +		return false;
> +
> +	switch (ex->type) {
> +	case EX_TYPE_UACCESS_ERR_ZERO:
> +	case EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR:
> +		return ex_handler_uaccess_err_zero(ex, regs);
> +	}
> +
> +	return false;
> +}
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index ef63651099a9..278e67357f49 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -801,21 +801,35 @@ static int do_bad(unsigned long far, unsigned long =
esr, struct pt_regs *regs)
>   	return 1; /* "fault" */
>   }
>  =20
> +/*
> + * APEI claimed this as a firmware-first notification.
> + * Some processing deferred to task_work before ret_to_user().
> + */
> +static int do_apei_claim_sea(struct pt_regs *regs)
> +{
> +	int ret;
> +
> +	ret =3D apei_claim_sea(regs);
> +	if (ret)
> +		return ret;
> +
> +	if (!user_mode(regs) && IS_ENABLED(CONFIG_ARCH_HAS_COPY_MC)) {
> +		if (!fixup_exception_me(regs))
> +			return -ENOENT;
> +	}
> +
> +	return ret;
> +}
> +
>   static int do_sea(unsigned long far, unsigned long esr, struct pt_regs =
*regs)
>   {
>   	const struct fault_info *inf;
>   	unsigned long siaddr;
>  =20
> -	inf =3D esr_to_fault_info(esr);
> -
> -	if (user_mode(regs) && apei_claim_sea(regs) =3D=3D 0) {
> -		/*
> -		 * APEI claimed this as a firmware-first notification.
> -		 * Some processing deferred to task_work before ret_to_user().
> -		 */
> +	if (do_apei_claim_sea(regs) =3D=3D 0)
>   		return 0;
> -	}
>  =20
> +	inf =3D esr_to_fault_info(esr);
>   	if (esr & ESR_ELx_FnV) {
>   		siaddr =3D 0;
>   	} else {

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d=
b72933f-cda7-4196-8e54-73cbefbf1a26%40linux.alibaba.com.
