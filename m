Return-Path: <kasan-dev+bncBDW2JDUY5AORBE626HCQMGQEF2BKRCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B47E2B47581
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 19:19:16 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-6232f49fe2fsf798516a12.0
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 10:19:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757179156; cv=pass;
        d=google.com; s=arc-20240605;
        b=OkQRliWqq7Lz2JlOITJP1RgjjAqmFW8xXG1Yucb55Zs55UGeZ0fbabvw9ILF94QDTb
         91u6HKCkpSnTukBhmVkx3R6k38IDoAUi9QeBDc7F2VBUBoYXFCV00OUnBYEPReig4xvf
         /OOgo24HArh77hz14U854IhJPa92dbjCLHQHjaBiUX+cH2pxe35Lp8tMVu1AYfiNpI7V
         SL30RB92PNSmq3LpJb1aoV0MvzhMrO5QPOzg8A90oefNDr+X4XZcvu9rI5/soswDXZT1
         k2ZyKJpVIl9WaJ+IG+R59n4sT7cOeyuIcddcOgrkghcAoL5tGstAYwOX45sOwz3drp7C
         QcTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=gscrMgsVLvJ+VeupiadmQB0z3xASrIJBCmFJfBhTQyc=;
        fh=bSvNiGM81lJ+oc0SmiBNkA1hr/ZSLXuhmGKV7ukmUeM=;
        b=BdFvxlDH52LOUNtKmF5GgaTwMRue2oXkA1NoPAHHVZIsT3TacAG8m5940x1jZJJRj+
         BruFy6CFK423fK+9DqMz3WKzeahWsKNn8XZuY2E9WO03BM4jO+OPKV+lH/5SM9lTd/Vu
         gZg8SF1TKcaW00SDp0iYQuTxz0ZBF9rJRIR4AE4aLO9zGPapgb7ameBg7O5DWzgG36Lr
         q3TzAdw+yonZXNgpiIn1Eeu1tW76LUd9gir4N8aEmOecTMAn7//Zwcm44mT8VJlCKhWQ
         J31PkgV3RhaDm5P4xS/iEwd7AUpUPOnxHoF8jPo7WNSYD6wz7577ZAt8hwpmojyNNlSF
         RQpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=btDegNOf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757179156; x=1757783956; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gscrMgsVLvJ+VeupiadmQB0z3xASrIJBCmFJfBhTQyc=;
        b=pxkWwb7RkPykl8y+BJPo6Iznfap6sTtF5OVwklRHXZiT9tIAnsPCMlp76H12ubge3U
         iGXWG9Mi+gZwPya7l6rCplUJKG9DTGz5j/AJiKzUpa+R5HyCl8XmEEicBGSxiO1HREAv
         xKbcgDZuUqvKNy+Hol4+PagwT4VK6Gr6Gd42U1FCvFIdsoeC7hsur4YHFwvrGmQY3VZ8
         pLYsUwKM52hGGOcYEID5fNNq/PmmMPPiGON4LzQyveVZ4AGy6RJMSXO9+hkx5e908m6P
         H+sE7xDTqyHk2ItZIOtc0th9LkSucr5+A185/jMYjaMKyb+qkkrsDSF3wDcBV+fK4J4X
         sg8w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757179156; x=1757783956; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gscrMgsVLvJ+VeupiadmQB0z3xASrIJBCmFJfBhTQyc=;
        b=guNFfvOAjs6jA3rMmIjW67kGdMv8AOUpIydDlS2yH9fuprMPXFoos7T6SujbXgns8T
         K9mNwf+6Etz4vkxUP3Bp0nFYV3n1QlQL6zgMKSg25CAQLT7BAVS1uJUYqG7bqdIRwTNn
         W0NsNahyacyyOS9CZy6jREOsKb/JsWfR/XVrsON1jdIXQA9wF6R6oWmtr+vSFZIKTMru
         1j5x5/9kAUGAowJssas9aRSSWLRVxerZMk+8Jl7citcYC2Q157E6hKhrcrCRKEYnIBhN
         3iPrevNP+AQJ7nIN53nARZhSXIY2JxOgw4Hlz0JnU2eew0tzG9jno26iBgrecz4ZINeB
         QXRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757179156; x=1757783956;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gscrMgsVLvJ+VeupiadmQB0z3xASrIJBCmFJfBhTQyc=;
        b=RK/uzaAnSxyzeBUYUitP9A7LauGQW14dT3wfP1ppk9QxGOfuEHm5Z3wGRIjQ1J7do8
         Q1Y804M1xPt+GRzgYQYC1hPLfWL5ihbm0eFunKroQc5b+owJuIB2K/REfVPrsb2xUdJP
         GEmgKbsTHZuUmivbCAMkvm2R5cUk899XnSK8tH+lRWGQJvTOjb+NVXsD1Oji1F+G2Ixr
         MB7c5KSYWBHm7HY8hCoqPoLiudhdpHBFjDJrwyoODf2EK9nvGIZEeeLI4qcxKQH2tR4F
         xA1rtsZb0VWsdgcSfilaojtX0ATlh+0mEp1dHsJ2dfkxEUTeFarYzwwf88EbZvmdVu9U
         491w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXmOdW2ce/R6vgxvEfxbtTUlPdCUfPFaBNwthi7lgPYZ+Sh2B243rZ8owB+0XmHyJwxSsyDrg==@lfdr.de
X-Gm-Message-State: AOJu0YyfQ70e/dNgZxx7ZTK3IQ8Ri8g66/nx3fSKcYuFYjsXx7HIiLT5
	9soLC5M8m0dTr2wmoQv7qd5TuPhqx4vuXj2+UerkJeOaseHuSRX5U8NH
X-Google-Smtp-Source: AGHT+IE8UvdBomwaEYJQbookCO/SCXOiJxi1iM5Vuh7BH/J9sO28x3Wb3cyhVFCVS5YnlseMUTFcjA==
X-Received: by 2002:a05:6402:13cf:b0:626:3540:97d8 with SMTP id 4fb4d7f45d1cf-62635409923mr1211876a12.8.1757179155900;
        Sat, 06 Sep 2025 10:19:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf2N3ovJcvDzXIC0KOMKOJvnFpFPHHQHJQvvI6vsVOCKg==
Received: by 2002:a05:6402:23cf:b0:61c:3fe3:ce7d with SMTP id
 4fb4d7f45d1cf-62146c05117ls1834715a12.1.-pod-prod-07-eu; Sat, 06 Sep 2025
 10:19:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXaKJsTjaIBp99HPMLGi2h5V4FcKN1EcvQ45eu1rVoXExzcxMnq/5u/H6/BFh3qN4BP9p0tUjEcgZw=@googlegroups.com
X-Received: by 2002:a17:907:9408:b0:afe:eb48:2a3a with SMTP id a640c23a62f3a-b04b180a019mr217280266b.65.1757179152967;
        Sat, 06 Sep 2025 10:19:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757179152; cv=none;
        d=google.com; s=arc-20240605;
        b=LZzEGR1K9KLqpbjZ+owDOAfH6uRJGNHqHlv0wJV5RBsacxU+5/r3aT95CKHJiJlGdU
         hhl5LOv1uNFrdr9FNiAuV+nylAiZ3LCk3zOPBpDsoACIs8ZaqEOe2Yt3nbZYzIeIV0Gb
         eh3UQT7qQ7uW442BVrY5FFWg8BYyKG5mhpYyo7XBe4ARilsUBfIFJw9WSa5B6ksfApAC
         LMLa5p5XUDUEk4Aq5sCTaBN7mtSjiJYP3WutPcg2kL/othM4J9f0IOYldfV2OJnmFssa
         KguwAr887XWEFtCdvHnptF8izNvNoR11Pz469IK31OCsq4CBTY2VbfvdMSgbTPHPG17T
         u+xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JcGjqzlEvwGIwrVgChgsqOwM/ch5h0ABA8uHnxnyHmk=;
        fh=6WfSTBgpZNgZuZaR4XBsjuxMeZyvDzbWNnHJl0wWFz4=;
        b=XElAOBBQ4+46C+cS/SIU+obl60CLfZFmkhN5rbIGhpUU2fy+IRK4xnK3GWIxvoF/98
         07F4oaZyLa4iWBenYNZiTdP15za9RS5plMcHpoZ4iXUQtvHJ1/fN6P4k8sOqdJ7CGrSn
         KWC6AiVWm99bjz3/tDhozmBmV1YWPYV4fmhPFGut8MAMFOmKVL2mGqONVP9EGiEgQem4
         nJt5WVWT4BNP3IfXF1+t1KRPN+GzjJC9oc1yBf4Z71KxKmwuR+FZjPQfwKz/sfcv8KSw
         1OReSLa0vC6a91/ErLWEFEW8jCWoWfy7uSQ5ihsT/dgMvmFx3i+mZgw5eG8HVUUI+gsN
         33xA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=btDegNOf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-aff04cdab8csi44054766b.1.2025.09.06.10.19.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Sep 2025 10:19:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-3e537dc30c7so1145509f8f.3
        for <kasan-dev@googlegroups.com>; Sat, 06 Sep 2025 10:19:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWiA2lo3cixmMa8CZrNrc3s3Czutia6F8bfuegMFsw/ddqhHqaFopW7kRDSXpxSe5Xj8jjVLN4hHrM=@googlegroups.com
X-Gm-Gg: ASbGncvj5soR6UkpMkWDFxcbhMwy56aMLmQicPzn66ftpo3Pyr3kHMmIHL3grxDx0+r
	3Jr5TEHqXSOQZ8IxOdSjKJPe2ReygnatzjCHfA6p67hiovI7FfeENufgr2A3pAQLD97tTg6XTH4
	YB6Jeh2e/OuI7+IEw9WbRfWItZOHy075nGJ/4/qXUkkFqj+M058h8uUDILtsuJb+BQ2aE1EP3Hg
	e31GaLi
X-Received: by 2002:a05:6000:420f:b0:3e3:5b4:dc1b with SMTP id
 ffacd0b85a97d-3e642027172mr2499354f8f.19.1757179152239; Sat, 06 Sep 2025
 10:19:12 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com> <36c0e5e9d875addc42a73168b8090144c327ec9f.1756151769.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <36c0e5e9d875addc42a73168b8090144c327ec9f.1756151769.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 6 Sep 2025 19:19:01 +0200
X-Gm-Features: AS18NWCTNCapbXl_JpY4w398NCDrxjlYVkaeLQmKTOYiJH6ZL4Fo44ag69k2Lug
Message-ID: <CA+fCnZcMV0BOJyvx2nciCK2jvht-Hx0HnFtRzcc=zu+pQSOdVw@mail.gmail.com>
Subject: Re: [PATCH v5 13/19] kasan: x86: Handle int3 for inline KASAN reports
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com, 
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com, 
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com, 
	trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com, 
	joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org, 
	graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org, 
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com, 
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com, 
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com, 
	justinstitt@google.com, catalin.marinas@arm.com, 
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com, 
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com, 
	dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com, 
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org, 
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com, 
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org, 
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com, 
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org, 
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com, 
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com, 
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org, 
	pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev, 
	will@kernel.org, jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=btDegNOf;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
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

On Mon, Aug 25, 2025 at 10:30=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> Inline KASAN on x86 does tag mismatch reports by passing the faulty
> address and metadata through the INT3 instruction - scheme that's setup
> in the LLVM's compiler code (specifically HWAddressSanitizer.cpp).
>
> Add a kasan hook to the INT3 handling function.
>
> Disable KASAN in an INT3 core kernel selftest function since it can raise
> a false tag mismatch report and potentially panic the kernel.
>
> Make part of that hook - which decides whether to die or recover from a
> tag mismatch - arch independent to avoid duplicating a long comment on
> both x86 and arm64 architectures.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v5:
> - Add die to argument list of kasan_inline_recover() in
>   arch/arm64/kernel/traps.c.
>
> Changelog v4:
> - Make kasan_handler() a stub in a header file. Remove #ifdef from
>   traps.c.
> - Consolidate the "recover" comment into one place.
> - Make small changes to the patch message.
>
>  MAINTAINERS                   |  2 +-
>  arch/x86/include/asm/kasan.h  | 26 ++++++++++++++++++++++++++
>  arch/x86/kernel/alternative.c |  4 +++-
>  arch/x86/kernel/traps.c       |  4 ++++
>  arch/x86/mm/Makefile          |  2 ++
>  arch/x86/mm/kasan_inline.c    | 23 +++++++++++++++++++++++
>  include/linux/kasan.h         | 24 ++++++++++++++++++++++++
>  7 files changed, 83 insertions(+), 2 deletions(-)
>  create mode 100644 arch/x86/mm/kasan_inline.c
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 788532771832..f5b1ce242002 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -13177,7 +13177,7 @@ S:      Maintained
>  B:     https://bugzilla.kernel.org/buglist.cgi?component=3DSanitizers&pr=
oduct=3DMemory%20Management
>  F:     Documentation/dev-tools/kasan.rst
>  F:     arch/*/include/asm/*kasan*.h
> -F:     arch/*/mm/kasan_init*
> +F:     arch/*/mm/kasan_*
>  F:     include/linux/kasan*.h
>  F:     lib/Kconfig.kasan
>  F:     mm/kasan/
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index 1963eb2fcff3..5bf38bb836e1 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -6,7 +6,28 @@
>  #include <linux/kasan-tags.h>
>  #include <linux/types.h>
>  #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +#ifdef CONFIG_KASAN_SW_TAGS
> +
> +/*
> + * LLVM ABI for reporting tag mismatches in inline KASAN mode.
> + * On x86 the INT3 instruction is used to carry metadata in RAX
> + * to the KASAN report.
> + *
> + * SIZE refers to how many bytes the faulty memory access
> + * requested.
> + * WRITE bit, when set, indicates the access was a write, otherwise
> + * it was a read.
> + * RECOVER bit, when set, should allow the kernel to carry on after
> + * a tag mismatch. Otherwise die() is called.
> + */
> +#define KASAN_RAX_RECOVER      0x20
> +#define KASAN_RAX_WRITE                0x10
> +#define KASAN_RAX_SIZE_MASK    0x0f
> +#define KASAN_RAX_SIZE(rax)    (1 << ((rax) & KASAN_RAX_SIZE_MASK))
> +
> +#else
>  #define KASAN_SHADOW_SCALE_SHIFT 3

Putting this under else in this patch looks odd, we can move this part
to "x86: Make software tag-based kasan available".

> +#endif
>
>  /*
>   * Compiler uses shadow offset assuming that addresses start
> @@ -35,10 +56,15 @@
>  #define __tag_shifted(tag)             FIELD_PREP(GENMASK_ULL(60, 57), t=
ag)
>  #define __tag_reset(addr)              (sign_extend64((u64)(addr), 56))
>  #define __tag_get(addr)                        ((u8)FIELD_GET(GENMASK_UL=
L(60, 57), (u64)addr))
> +bool kasan_inline_handler(struct pt_regs *regs);
>  #else
>  #define __tag_shifted(tag)             0UL
>  #define __tag_reset(addr)              (addr)
>  #define __tag_get(addr)                        0
> +static inline bool kasan_inline_handler(struct pt_regs *regs)
> +{
> +       return false;
> +}
>  #endif /* CONFIG_KASAN_SW_TAGS */
>
>  static inline void *__tag_set(const void *__addr, u8 tag)
> diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.=
c
> index 2a330566e62b..4cb085daad31 100644
> --- a/arch/x86/kernel/alternative.c
> +++ b/arch/x86/kernel/alternative.c
> @@ -2228,7 +2228,7 @@ int3_exception_notify(struct notifier_block *self, =
unsigned long val, void *data
>  }
>
>  /* Must be noinline to ensure uniqueness of int3_selftest_ip. */
> -static noinline void __init int3_selftest(void)
> +static noinline __no_sanitize_address void __init int3_selftest(void)
>  {
>         static __initdata struct notifier_block int3_exception_nb =3D {
>                 .notifier_call  =3D int3_exception_notify,
> @@ -2236,6 +2236,7 @@ static noinline void __init int3_selftest(void)
>         };
>         unsigned int val =3D 0;
>
> +       kasan_disable_current();
>         BUG_ON(register_die_notifier(&int3_exception_nb));
>
>         /*
> @@ -2253,6 +2254,7 @@ static noinline void __init int3_selftest(void)
>
>         BUG_ON(val !=3D 1);
>
> +       kasan_enable_current();
>         unregister_die_notifier(&int3_exception_nb);
>  }
>
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index 0f6f187b1a9e..2a119279980f 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -912,6 +912,10 @@ static bool do_int3(struct pt_regs *regs)
>         if (kprobe_int3_handler(regs))
>                 return true;
>  #endif
> +
> +       if (kasan_inline_handler(regs))
> +               return true;
> +
>         res =3D notify_die(DIE_INT3, "int3", regs, 0, X86_TRAP_BP, SIGTRA=
P);
>
>         return res =3D=3D NOTIFY_STOP;
> diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
> index 5b9908f13dcf..1dc18090cbe7 100644
> --- a/arch/x86/mm/Makefile
> +++ b/arch/x86/mm/Makefile
> @@ -36,7 +36,9 @@ obj-$(CONFIG_PTDUMP)          +=3D dump_pagetables.o
>  obj-$(CONFIG_PTDUMP_DEBUGFS)   +=3D debug_pagetables.o
>
>  KASAN_SANITIZE_kasan_init_$(BITS).o :=3D n
> +KASAN_SANITIZE_kasan_inline.o :=3D n
>  obj-$(CONFIG_KASAN)            +=3D kasan_init_$(BITS).o
> +obj-$(CONFIG_KASAN_SW_TAGS)    +=3D kasan_inline.o
>
>  KMSAN_SANITIZE_kmsan_shadow.o  :=3D n
>  obj-$(CONFIG_KMSAN)            +=3D kmsan_shadow.o
> diff --git a/arch/x86/mm/kasan_inline.c b/arch/x86/mm/kasan_inline.c
> new file mode 100644
> index 000000000000..9f85dfd1c38b
> --- /dev/null
> +++ b/arch/x86/mm/kasan_inline.c
> @@ -0,0 +1,23 @@
> +// SPDX-License-Identifier: GPL-2.0
> +#include <linux/kasan.h>
> +#include <linux/kdebug.h>
> +
> +bool kasan_inline_handler(struct pt_regs *regs)
> +{
> +       int metadata =3D regs->ax;
> +       u64 addr =3D regs->di;
> +       u64 pc =3D regs->ip;
> +       bool recover =3D metadata & KASAN_RAX_RECOVER;
> +       bool write =3D metadata & KASAN_RAX_WRITE;
> +       size_t size =3D KASAN_RAX_SIZE(metadata);
> +
> +       if (user_mode(regs))
> +               return false;
> +
> +       if (!kasan_report((void *)addr, size, write, pc))
> +               return false;

Hm, this part is different than on arm64: there, we don't check the
return value.

Do I understand correctly that the return value from this function
controls whether we skip over the int3 instruction and continue the
execution? If so, we should return the same value regardless of
whether the report is suppressed or not. And then you should not need
to explicitly check for KASAN_BIT_MULTI_SHOT in the latter patch.

> +
> +       kasan_inline_recover(recover, "Oops - KASAN", regs, metadata, die=
);

Maybe name this is as kasan_die_unless_recover()?


> +
> +       return true;
> +}
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 54481f8c30c5..8691ad870f3b 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -663,4 +663,28 @@ void kasan_non_canonical_hook(unsigned long addr);
>  static inline void kasan_non_canonical_hook(unsigned long addr) { }
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
> +#ifdef CONFIG_KASAN_SW_TAGS
> +/*
> + * The instrumentation allows to control whether we can proceed after
> + * a crash was detected. This is done by passing the -recover flag to
> + * the compiler. Disabling recovery allows to generate more compact
> + * code.
> + *
> + * Unfortunately disabling recovery doesn't work for the kernel right
> + * now. KASAN reporting is disabled in some contexts (for example when
> + * the allocator accesses slab object metadata; this is controlled by
> + * current->kasan_depth). All these accesses are detected by the tool,
> + * even though the reports for them are not printed.
> + *
> + * This is something that might be fixed at some point in the future.
> + */
> +static inline void kasan_inline_recover(
> +       bool recover, char *msg, struct pt_regs *regs, unsigned long err,
> +       void die_fn(const char *str, struct pt_regs *regs, long err))
> +{
> +       if (!recover)
> +               die_fn(msg, regs, err);
> +}
> +#endif
> +
>  #endif /* LINUX_KASAN_H */
> --
> 2.50.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcMV0BOJyvx2nciCK2jvht-Hx0HnFtRzcc%3Dzu%2BpQSOdVw%40mail.gmail.com.
