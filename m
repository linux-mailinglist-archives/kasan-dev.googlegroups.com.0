Return-Path: <kasan-dev+bncBDCPL7WX3MKBBA4XR7CQMGQEWCZKSKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DDF6CB2B597
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 02:55:49 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-70a88de16c0sf111308226d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 17:55:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755564931; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vavdm8OsDqHLffkR9wozDQoGak3VGhSTt39nVS7EI9tXkt+X4+x0xLI7rbl2+DMEwv
         rlDqJzXfHeePDG6EfqFas2dKnx7OxN1DomLQ7TTqSlUmwTlDnofWo6dpfr44cu3BDGOY
         9a3pP6pzdyRlv/68+qBNKlTBK+NjIegx1eDkYrtnSr4Y6XQoSr3V6BHyVcwqsNnwWJfy
         BDNV2RTXkdoXdMKjudADosMEGSMcCtG6udtz1Np1wdLj4h285iPIgp13Dusxk02TdmR1
         qgwCtBD5WsejGvMCxJE+7PBV4gFGpELt1PY+nkps6+Tlf5OmG9eQ/+SKmhm4c8i0wx8N
         /x2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=+vcXU+5csjt9CxFeMT8/oXdBcH7TOeN92wQFAcyEjJA=;
        fh=qgMoo9MZtG5AGtHR8NpPmz2+4FFmvIG8pul9X/cAi70=;
        b=KXJGsLB4pW240JPdiXWaMS5qyT5ZhOctZ9m5NJHqgRk/KEHb4LUTkmnQeHfPEfbeej
         MsKeW+2vM/VC+NjhQLXYGv5WYXQxNwkSUvi1UtvSEUkL4ShqJSVdMNAiA4TMmjNR62aJ
         I9kZPcwctzSfdrNSwqIADiX5GGc/GdcRQ8M0lpIO6w9KMTZ0es0vJe0cXdECP/YqQC2m
         KEBO95OVj3ig/UEn22Rfx72jwr187vQIzdnfTTi4ZJIo+EmnV/BgzJR6hC8KqusaL3Wz
         uy6yrF3PK18ac7ZhS/3g5OtEYSBXgqLXQPrKTtzB28ZUKX3naUVcYX34xY8wIstxj2Er
         6Tig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Xf9fcNQg;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755564931; x=1756169731; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=+vcXU+5csjt9CxFeMT8/oXdBcH7TOeN92wQFAcyEjJA=;
        b=wxWKcLZII4FFMGRgrO9gnSSqxy8G1iK6T6WiIjkYbuQeOt86YtPh+0Gpk6800BVKYS
         oFTmDStJ/xUgwP27T1asaNTPmvWufvnNnlDQUQXLrevEHg8M3LW4K6Vam+YS1waCXO7b
         L3kE5DpqbMhAuLCVoiObqOAzohEdGuJdrZBAT7s2f9wv8z8LMjtp8FyxH3rqCM05LJe7
         f/t9W2x9B1iVo7zWHbmffD4N68eqLiEUkEqqWfDaqSG8QTxQAVWO7I6E5xYW7/9VXAUM
         6YDpQgkhr9devSU9iHc5+kIEIHKHPtZ/b8X2ZMY2a/OziCBhALC97Rv/uthn32f2K84Y
         JnsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755564931; x=1756169731;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+vcXU+5csjt9CxFeMT8/oXdBcH7TOeN92wQFAcyEjJA=;
        b=tDkYz9fnVjjoJXOaxQ2Nqi6nU+TDUeWKuSoc+to1XFq9QgYTXqut9rxoJNXhGKkFuW
         8ga/Y0smZbrgdWFkftiI9CJjKLUKiSOD+OV3e9wjFWmnrs58NjDlRiOCg/6BEgx2IBHf
         4yw8ritQ5HRsYOTsAFMhBLOnkQOMAxEO8OYFqcGA5mkeMlSmfxFziaeejk6K2ulMvp+l
         uN0w0gm/X3l5AJU679IReC2DbSv55I0JMP8tu+nvwi/r3+T2ke2IbWDc787EEZbZaVMe
         oI5C5xZLK8BOUv9wBsdllFo43a2dMf3e0fzS1CXbXv8iZgIExeB8IC1b2eK0nXACebKw
         uCEg==
X-Forwarded-Encrypted: i=2; AJvYcCW+kGLi/Rg7KysnqEotKno8GVpPlQlmp+wGcWjQZjHEs4iszWgoZoQqsMdMh7AWGMIDUcz2UQ==@lfdr.de
X-Gm-Message-State: AOJu0YzOoUluiNMueiqzm9pQuq/8QDAeHvyers9FusRpEeEIXmBUrP0D
	bGlVUap+yHnlV2cj/qZNZAbtymUCdOp4UqS7njGlZdACOjveDQCJy4yK
X-Google-Smtp-Source: AGHT+IFwI/rQZ7rrTzSCpESnxqluez8P0ypOwuGKzY8XlgK6An6d2ER2Ln78T6s4l1ewF715vdDsZQ==
X-Received: by 2002:a05:6214:2242:b0:709:e4a2:bf54 with SMTP id 6a1803df08f44-70c35ca293fmr8522236d6.31.1755564931279;
        Mon, 18 Aug 2025 17:55:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcMzM9KfLqX45HnxrkteFRfOaG+nLoILWue4UvZFs8XJw==
Received: by 2002:ad4:5aad:0:b0:707:1972:6f43 with SMTP id 6a1803df08f44-70ab7b5944dls60891766d6.2.-pod-prod-05-us;
 Mon, 18 Aug 2025 17:55:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWAgMY7rfDGc4uyze/6uM6Jnf1303/9gx8/mYz5uwHtkqsUG+BEXfe2zeiWA7OxDxoE+OjVLA0YIpk=@googlegroups.com
X-Received: by 2002:a05:6122:2090:b0:539:3bb5:e4b1 with SMTP id 71dfb90a1353d-53b5cf154abmr353928e0c.0.1755564930301;
        Mon, 18 Aug 2025 17:55:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755564930; cv=none;
        d=google.com; s=arc-20240605;
        b=QEaHszxA0kOkZAADJ9sBp3rzkzfJy09bccdJq4hTNZtT97N1tjNmznSd6pNZMwhu7Q
         hRUKkL4I/Shhq91zJqJRa5dPLySfW8zn2K3fi4u/mgOI5LwFANParfj3S83XYSdpvTdF
         uL5jr4Fo7e6U5RKdKBLh8tzsMCCXyvtvR2Y2WBj8O8EV6lMaxKjjgV5UP2z4hJ1Qz0Y2
         Zlg54kVVOCHXq11TphGNlWOgnCFeV7J7021lruZogk9vF7F3eDogRNc6X01aZ4eUcPVw
         3jlxLC1ArRAbamPZdcuNhJqIRsEn+1w5jytR+MD87uG86FcWXjY5rN2S8p/QeJc/Ss5t
         nLzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JzfTMaSWFx+xn7Q0qfVZdQJA3fiAtavglfDwO1hdcSA=;
        fh=HUiUKQZF34vto+9XyPPQq5Yqr0sNiu4CMblUr/JqRIk=;
        b=TmelZWCl3/R8HLUgN/3VcWUgrI0vsE65/pYHZeL0Rp6HjLryTeQAc075EgxD0o8TVu
         YB1cEnRRp5VwTtpHFqjZwjaj//g1w/K+Z3205eT3umMSrSqFrsnyW/hizwxDXaFA/LHA
         MkGmbq1vGcKqx+8NzjXcMiEcj34uUS76MDCYo1WkmHi1Ao/WkoltwGCYGrfiZwFN0hRz
         yP7HGR4cnOiZjl/RaGp0Jw/EHpvCnpSQTItnhLm43AHeqe0+4J2PwhGSB67GmJCbrGCs
         0Lupm/DFtMLmhIkZ6Qc8dQ7WBAeZEKsnffO6UAYFXZ2UccNdHuZyUmx0lLQq9n+awiwu
         fAcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Xf9fcNQg;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53b2bf52835si397247e0c.4.2025.08.18.17.55.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 17:55:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 896C55C57B0;
	Tue, 19 Aug 2025 00:55:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F0A33C4CEEB;
	Tue, 19 Aug 2025 00:55:28 +0000 (UTC)
Date: Mon, 18 Aug 2025 17:55:28 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, patches@lists.linux.dev,
	linux-kbuild@vger.kernel.org, linux-hardening@vger.kernel.org,
	Russell King <linux@armlinux.org.uk>,
	Ard Biesheuvel <ardb@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	linux-mips@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	linuxppc-dev@lists.ozlabs.org, Palmer Dabbelt <palmer@dabbelt.com>,
	Alexandre Ghiti <alex@ghiti.fr>, linux-riscv@lists.infradead.org,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH 00/10] Bump minimum supported version of LLVM for
 building the kernel to 15.0.0
Message-ID: <202508181753.7204670E@keescook>
References: <20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0@kernel.org>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Xf9fcNQg;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Mon, Aug 18, 2025 at 11:57:16AM -0700, Nathan Chancellor wrote:
> s390 and x86 have required LLVM 15 since
>
>   30d17fac6aae ("scripts/min-tool-version.sh: raise minimum clang version to 15.0.0 for s390")
>   7861640aac52 ("x86/build: Raise the minimum LLVM version to 15.0.0")
>
> respectively. This series bumps the rest of the kernel to 15.0.0 to
> match, which allows for a decent number of clean ups.

Looks good to me!

Reviewed-by: Kees Cook <kees@kernel.org>

> I think it makes sense for either Andrew to carry this via -mm on a
> nonmm branch or me to carry this via the Kbuild tree, with the
> appropriate acks.

I vote you carry it with Kbuild. :)

--
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202508181753.7204670E%40keescook.
