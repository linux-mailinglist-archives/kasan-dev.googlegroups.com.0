Return-Path: <kasan-dev+bncBDCLJAGETYJBBI5B62ZQMGQECTVWNWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id CF10291AC69
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2024 18:17:40 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-dff189c7e65sf16470332276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2024 09:17:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719505059; cv=pass;
        d=google.com; s=arc-20160816;
        b=sZZHjV7KCVrrtADYoxCkBrvpOkYmCFXfaby0uXWUOrozWfp8LMZQmvRhWZNOWT6+Ak
         NbWXGlsaIn7mVMc4ShausmqEGCLmyj0Whzvii6tcnIVd1lBiTkDT391qz7+qCG/pT8/M
         Qn/F0hnLFXUiwzZJJ7wuss9SRPvf09AAaiDaGUcYWe29KWxv5WIMiJKVyjDH8gyz6CFr
         +ojXKcdC4gJGzXBRkxZz3t2NK7QMqA2LcWt9BDufT5EQK2rxme5tXxmFXwuK3wT2w47g
         +jXzhJSZZ0SpaOXHFF5SBgoIw1kx1oPM9KwjlAZ+uhfRJUQOu3qXF2e3tXRKjo0f9t8z
         D3Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=IU5c8E8eoBALGrk73/pk+reggRt9aI3yyE7juy4j2Mg=;
        fh=WR1gkCRjA6lBvnxL7ePnoS/JTHFHo1s4zWpIJQu6NHE=;
        b=Wg1wvUI7fxVXTq/MB2GysoM0smsFtRlmeCqPuzX4Qok5Fhl5b2ncaHSCAMtuc2uf5u
         QLRnj6hsYXCLaGIfiFq0SXSBukvPdoCQna0EhPp8U/YSrpxxHuF5R3e1bn0dFLKNIRXC
         YSmSrp8njBDO2d9eFNNG2zIyFVOFNpbOHl/jCcqH3PsdWSQQNT0ZWZ0M3e1tg6yuZqnB
         fsRdnqHjOIP7NXbuuR7zZGosnsdyiu+OPli1IKMu6QJ986r1/nIvgEpx0QxmRkG5EGVG
         DoDCRSGI6MVu1f5LPIqlHyDv9FpvSL6KRHazF+jdFCpqjbBwiIGfCA0mLC4NaE97BXy/
         DWnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oiD2w6AE;
       spf=pass (google.com: domain of conor@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719505059; x=1720109859; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IU5c8E8eoBALGrk73/pk+reggRt9aI3yyE7juy4j2Mg=;
        b=OZhlGao/HVLvkLJXoNtmUboHIfTEIvDSsxYrOp7RE/KW88n3554R9+b4Zw5tYdNy52
         Hs+Yoz4ccyeEvt5Prq70kxVfMOThAy6lhR4838+LDy0HEniZUjtyv+SvsRuGzizYT9Bs
         bBA8Z4oYxkTa4MckAEt/zqPgBGnhNQAEO9VYIe1CIPwGgS0FXT1M3Dzl7+3IJAc9U6Cq
         XwG2vwdGK3UFlXzTLB/v05G5WI6Hs/5MMOR40XkShZ6EnLWUSxmeAUuvNye1PSVjpr5b
         7kvwnn7JjIhHD4uhD1YSzrnE/euTviY/8kEM4+nHwYT6j2gJv00Qz/R4bIImfeWsTsZU
         XH5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719505059; x=1720109859;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IU5c8E8eoBALGrk73/pk+reggRt9aI3yyE7juy4j2Mg=;
        b=Fdb0JTKT1TuEF3I7e2uCIhLsghe3iCKCSALdr2Iqbz7BwYBsWbKqcy23E7wlDxA+Q1
         WoxNKnv60pSoKOrnkbmaxLiaJ+EDuwNbXPaGfhFQ9SKvImnA+VbHl7bMzLS90SSJJ+OI
         5sQFwVLGZA5/a78NAi8OpPyKZSdn1FaTFAoHAlgFj6fk/m1W+2fLuvKDzWhhkM30qSEQ
         /ifRvPRvpz00mfrCAfGmse4Y+eJwfOmHlHc5hcv5e+61ZIZB5fzcIe8++4JR69wYrv/J
         QxEOMZIwaMGrBmwkviR65HYqp18R4ubsydLNFY5hw7HbR9ITvZan7ODfpDZeTvu/LqNO
         PfSQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU44wKYOOjoCI9uVylBAihc9vp/AdXmcWa+85CBC5BVcIhwHOEh8jL9jLDNzOnHMtJDpjGrDO4Z72ByiJzwD7WRQ1IoavsHgQ==
X-Gm-Message-State: AOJu0YzFWTuogy6/lZ09taCE4+kthBLo40/bpNJ5ieDMOU9dJGJ+lu3a
	eitGUgAKkqwGRyunDHoKsoCw9qQq+wKLxcFVEpMDuufzhlGl4Vi0
X-Google-Smtp-Source: AGHT+IF2r61wmzn0pqo/EzT3SxXE4PsSSbs8S9glztcqEbKFfnQ4HCntA68+z/DSsxjKQipVgiG9JA==
X-Received: by 2002:a25:c508:0:b0:de5:4cd0:8da4 with SMTP id 3f1490d57ef6-e0303f7efd6mr17427285276.33.1719505059305;
        Thu, 27 Jun 2024 09:17:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:726:b0:e03:22b3:3c00 with SMTP id
 3f1490d57ef6-e0322b33d64ls4637913276.0.-pod-prod-08-us; Thu, 27 Jun 2024
 09:17:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtvkJ1cgFs+4oBtXsk7W1Xzh/AZIGN6xCWOYpQjOwWQgdH29Z0LIvK2T/G2utimAh+gQc363MunhTM8vGbFtFzRrTMxzi17vo+Lw==
X-Received: by 2002:a0d:ea88:0:b0:64a:5493:e0bd with SMTP id 00721157ae682-64a54944210mr8080917b3.40.1719505058386;
        Thu, 27 Jun 2024 09:17:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719505058; cv=none;
        d=google.com; s=arc-20160816;
        b=EOi0bRlq+Kgw88CQbnuI+IJQWXsxrwpzl/P9aIIVdzZ1KZRNj+UtkMGDLk2iDK2OeG
         YpAM618C6Ug+W8Bevfsxvwz1ieSxDPLTfz8ELlyJofKap31rQaXUVMCLv8ZIcg//ch8L
         Tl7SpAycN39oc+kshzuDHqkQredn5PGfJV0yqNzWPnA9uO8RQ9Rc5qMoypTjZgBf2EXA
         kpwcSj0vNqzFwbfP4LFRAIZiLUyqugFev4vvncHOXQnQBFgZfURtE7S9xEKk+H7CNyIA
         nqIOBB7qLngUOOo2Cs2VVLW6AoMm/mRIs8i7kW3Rj5QTk8kxVMwLvuhxhu98emkb8GED
         rgqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JCHawlPhQVtEB/62gpaSxlS8FpdBXAdzyhtV6Q2BFkI=;
        fh=qLil01d4sTutemriPxxDTu5zOoY8VsABgDPxebgwgog=;
        b=rGN4vHIgAGFAFYPscj28UuEC5dc+F8nhTtvDomIN3ujWh5np/Y4wuDk2C3diapLbPb
         LhAImbXkdTni2LCv7+gOjuCQcCUzMtOgzETzRg13X8bCwjQ0M1vvAFuL1ujPCeYFS0PN
         MrVnes4GnGuAlPb1xDKv/MK/oTNg9LixQUPTYM1AagS2VOxCMsifGmceQaSUTRDvO82W
         eerUZIs1990fhwCTwJo3nKG7/v40MaZWSjj9L3p0mNp2z/hiZFnoKjdsivsCGiYkrtuR
         ifiEZ/OvIIaufL/k1+uRQbe8C5WCrKsKMg1vrHus8E2vTSgXn6xN1z+byfaA+vWS5PzX
         EFUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oiD2w6AE;
       spf=pass (google.com: domain of conor@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-64a90fe8d00si1897b3.1.2024.06.27.09.17.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Jun 2024 09:17:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 03ED0CE2FA7;
	Thu, 27 Jun 2024 16:17:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A9F54C2BBFC;
	Thu, 27 Jun 2024 16:17:32 +0000 (UTC)
Date: Thu, 27 Jun 2024 17:17:30 +0100
From: Conor Dooley <conor@kernel.org>
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
	devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
	kasan-dev@googlegroups.com, Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Subject: Re: [PATCH v2 01/10] dt-bindings: riscv: Add pointer masking ISA
 extensions
Message-ID: <20240627-deprive-unclog-2fba7562a8e6@spud>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
 <20240625210933.1620802-2-samuel.holland@sifive.com>
 <20240626-refined-cadmium-d850b9e15230@spud>
 <acd4c562-1f4f-4cd0-8ff8-e24e3e70d25e@sifive.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="68QJ4uKjJCUY75Cn"
Content-Disposition: inline
In-Reply-To: <acd4c562-1f4f-4cd0-8ff8-e24e3e70d25e@sifive.com>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oiD2w6AE;       spf=pass
 (google.com: domain of conor@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=conor@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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


--68QJ4uKjJCUY75Cn
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Wed, Jun 26, 2024 at 11:14:27AM -0500, Samuel Holland wrote:
> Hi Conor,
> 
> On 2024-06-26 11:01 AM, Conor Dooley wrote:
> > On Tue, Jun 25, 2024 at 02:09:12PM -0700, Samuel Holland wrote:
> >> The RISC-V Pointer Masking specification defines three extensions:
> >> Smmpm, Smnpm, and Ssnpm. Document the behavior of these extensions as
> >> following the current draft of the specification, which is 1.0.0-rc2.
> > 
> > You say draft, but the actual extension has already completed public
> > review, right?
> 
> Correct. The spec is frozen, and public review is complete. Here's the tracking
> ticket for details: https://jira.riscv.org/browse/RVS-1111
> 
> I use the word draft because it is still an -rc version, but I can reword this
> if you prefer.

No, it's fine. I just was double checking the state of the extension
before acking the patch. It'd be good, in the future to note what the
status is, given the policy is to not accept things that are at least
frozen.

Acked-by: Conor Dooley <conor.dooley@microchip.com>

Thanks,
Conor.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240627-deprive-unclog-2fba7562a8e6%40spud.

--68QJ4uKjJCUY75Cn
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCZn2QmgAKCRB4tDGHoIJi
0ugrAPwMAkqBdLVsNJYPUHmC+kiwO+gD/VqRmHsUype6Dvv2iQD/aPrrIh/9f5bL
PgBTuvqfvaF2Rp8IVP+TtTDUn9MREw8=
=3K8O
-----END PGP SIGNATURE-----

--68QJ4uKjJCUY75Cn--
