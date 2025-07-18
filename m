Return-Path: <kasan-dev+bncBDAZZCVNSYPBBZW45DBQMGQEOQGWQRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id DFE45B0A1D2
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 13:22:29 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-2e92a214e2esf1118318fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 04:22:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752837735; cv=pass;
        d=google.com; s=arc-20240605;
        b=NJBraDeTAPb8OnFP66fet7nAOIlj25pkBS8tLBuiPpPf7amZNfP3B+gFNPoa3DDU1b
         7UvLj+Wp0/vXKBu9m3OWF11J8bxoKVUvsg0wnpHGPKBdgVoYl2NgQSWSGCbRGPF+PCCT
         QsFXpb+WBk9/zr7YV+PQ1+60Odx4QBObiQmymQzPSxSDrUj3xhqSzvXZxy6RylpJpx40
         pJX7IAIvPqzFS7/s8K7kvEBGm5yLvxVjhI2pJlbaxPPOJwjvfBL6NS81ld71blWXfv2q
         BxSepPs0F9t5jzma2fIqVvihYbrZSV3wC0jUbX+tr5xkj/rX+BKQP5U4IsEL+yCsOyzi
         3oiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=IMQVFACFCFGQ3abHRWdPi08oGll40xCPm2KrheLpWIM=;
        fh=gcfWPMAcTCrSTVK1e/qJCiuOUiGQvtfAA52hnnjZUtk=;
        b=jP7MkyoVUTgQqmFDEOBbDiQ1tlf3vyDmjeS2lsG/tIh8fpwqLBQcQYTpBIKehSqdUN
         p9cUBonYTKvWl5rIOdS0MZI6YjgP+r6AYenPwH0Da0yIiRtAJZewtoxP0uKgkdVfdRm2
         6or3lEX2Me9dRORbrVFagNm1gjrlO1ytziELQKCMrV7FmdS4P1oRdYxl+gshoPvk0R9Q
         00eIc9BGRQ3g2M1S0V95dbRGWQEw6MYcjgzcfOWhKECAOWHzEWHwRR6ZBNX7FO1FxMS5
         qTK1n9tpOTbxUOH4uF9Ow6lk7WS90omIKWlL4QAT1oY2v3bKIaGBb4aln/0vVxROLQp1
         pc0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R8N985kT;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752837735; x=1753442535; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=IMQVFACFCFGQ3abHRWdPi08oGll40xCPm2KrheLpWIM=;
        b=vmGLLlfrrJDjY0C0FLoLtdhA933wyGcUToRfD2lazbO+WILzK03IMihEgsBWvVUO+U
         bedvZmymQciMQNXKtx37hrxlzUwS2nKJNtJZwEKJ9IFcwk/PinnPhuXYoSrcXX8K35rp
         furfocEWpJMEQkg0Xa5rbyv/5GoSBOytltkn+M2LjIjKYHfbRNYGp7nyYbG2w1fOTT9w
         Cjw/GejLuYklWat9InwI7xOnVnS15J0dMQA1WnyyrkOkvHfF+Fa6bLML8jzZEU01VxIn
         DogsVIsg4Ckhb9TmD+fjfBIyU2IOi0sOQGtK+SUTXSZuZ5p5ld1kdqO4vMAc/g+ZWUtn
         CIxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752837735; x=1753442535;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IMQVFACFCFGQ3abHRWdPi08oGll40xCPm2KrheLpWIM=;
        b=B5y4x+tlzNcYrjmz4TpAHtDvtrQ8TCJM040rtTnFoo2imOAnuh5vhlCWOuUZMey7W8
         KS4+hz24ipBgRnjEa3b+Ykdsudr+h+WkRkcQMNFSz2n/QFwVunu9DveKVzthcjRDMXIY
         rJbMXwrPQJta6U974zHiNzrwlg3039IEIbRbke3y3vgHASunPhNpWXke3Yw29hl6+ycz
         2b4iwELR36nkgesGHO/C7rkalrywz0boynNg9Z+DmH3Etan/nnxttODZ4rCgMA4uCwdG
         83nBn2XazFkQG9ysU2b9qUSs9UqHPtHj4DawUz3eZURBawVjNp+1qRPzqdVOt65Elpbo
         41sg==
X-Forwarded-Encrypted: i=2; AJvYcCU7OCgzqUmhdeE+Ti7rpcq+hSazV2HAtOuBrCgxewSGJRWiimFKS+HftqZGpXXCLRAz5HbuFA==@lfdr.de
X-Gm-Message-State: AOJu0Yw/pAItbAsE9sXJnP56D1qwjxZWMI0RK2htdARKFDVuATFM6z7P
	aFsqXLIMqEfM2m/PNr9OhUzgcJmU5Yu3pmeqLWNF8dla1Ts0lmzvfPNE
X-Google-Smtp-Source: AGHT+IFFsTD/UhlsYVg3+8dwJ8O5pViacz1hXyHXTZqfifs3ta5eC1379VMcqCb9EDZ2qUHL/oupgA==
X-Received: by 2002:a05:6870:a10e:b0:2ff:9224:b1ca with SMTP id 586e51a60fabf-300ea120939mr1945848fac.27.1752837735157;
        Fri, 18 Jul 2025 04:22:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeb3jW1bPrRLRI3nhCXtNY/XdRqWbBiGUyOPphMJkuq2g==
Received: by 2002:a05:6870:343:b0:2ef:3864:284c with SMTP id
 586e51a60fabf-2ffca945753ls763607fac.1.-pod-prod-04-us; Fri, 18 Jul 2025
 04:22:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWYXu0urPw9pFGnE9PtJnaepbVU+iEPErO+gp+UBE74Ie5VD29NOiEfOYL6ooBBvt6cIpgjN/RVVXU=@googlegroups.com
X-Received: by 2002:a05:6870:e047:b0:2ff:8fd9:6dcd with SMTP id 586e51a60fabf-300e8c593d7mr1523704fac.3.1752837734075;
        Fri, 18 Jul 2025 04:22:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752837734; cv=none;
        d=google.com; s=arc-20240605;
        b=UTNeB3X70U57noe8tS1Zs1ZYmLLdorX48uJ8jPMI2PDyLsNiIaoZhpXfiGtk5VjKFo
         f5YJRcuAjFsV04ErD2YXz7Db4XgUaPPFC0GRYkqxv3dRd2ehqA4tv/rPBgxcjFurg7dK
         EhHXSA9lYwHu3XfDOj9inQTsPFnWtT6u2IhrvEhsQ0TIFo23y4ST+BbrUnRD+W1M7ZrM
         wYbNSc6ubdif7OhtNuTxQ/yg5fnHlIHD+SEUgJ9C0A3nFC30CU/KIA8EU9lX5g0O7ii2
         h+bsY4geMV8vkatZG5cfYUjK/2pR8063uG256ucKHP3dcvZur/KSeH1csMwp6wZ5LQ13
         wrLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=z3gndaGJcN2hgsC7vt0hd7Xv3Nt3ExEva3jSiEJodDw=;
        fh=U6TcoqwJfm4zaHcjMkQ8MP5xSmjf4AuZaHbuhM4i8u8=;
        b=CVtmlRqaAg947XmAM9TOlJcuML0ngdzAFgqFdIzUL7j8GGPhvBP+aLbXeANGwHdxZ6
         seufeRS/I9Johhf0s8sggCNmlfLrfB1vFHhsa+WCtJ0/dd0JwuJDjjIV4CLksdlkOtmP
         ae73qFsy2+HIYSAxdkT9DChSLMzzbicJg3LfBUUpxEt+s18A2iCu6Lt6Zew6oQroE3An
         le8396JA3vyTliPo70tMN0GpYkCUCCaDmFMev/WyZXWKX6YloW/pEZDDPnLb/3FtV8uk
         G3c76g91FD869bF6jPYBQxLZij1bmNyRgRWmezz2N2zp4EEr1cGF0QhJWbZi4aq0eRVM
         1eXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R8N985kT;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-301037a93b7si74159fac.3.2025.07.18.04.22.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Jul 2025 04:22:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 6F511A56FFF;
	Fri, 18 Jul 2025 11:22:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 833A3C4CEEB;
	Fri, 18 Jul 2025 11:22:07 +0000 (UTC)
Date: Fri, 18 Jul 2025 12:22:04 +0100
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	x86@kernel.org, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v3 06/13] arm64: Handle KCOV __init vs inline mismatches
Message-ID: <aHouXI5-tyQw78Ht@willie-the-truck>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-6-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250717232519.2984886-6-kees@kernel.org>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=R8N985kT;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

Hey Kees,

On Thu, Jul 17, 2025 at 04:25:11PM -0700, Kees Cook wrote:
> When KCOV is enabled all functions get instrumented, unless
> the __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we
> have to handle differences in how GCC's inline optimizations get
> resolved. For arm64 this requires forcing one function to be inline
> with __always_inline.

Please can you spell out the issue a bit more here? From the description
you've given, I can't figure out why acpi_get_enable_method() is the
only function that needs fixing up so I worry that this could be
fragile.

Thanks,

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aHouXI5-tyQw78Ht%40willie-the-truck.
