Return-Path: <kasan-dev+bncBDCLJAGETYJBBVPW6CZQMGQEBXIAUNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C34FD91867F
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2024 18:01:26 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6b057a9690bsf99858626d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2024 09:01:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719417685; cv=pass;
        d=google.com; s=arc-20160816;
        b=LwVoeYuTozRdGD6khsMjQf0BKRYoxPK0GNj6inAc5rpSPi4bqPSy2sjv8QcTFsmM68
         YEAsWOoZhuF4M/P7hANTdulmR+ED9KuTsXMPRM45KOFiCNk7czz9a7wTf4+0lwmMJXbj
         9og2NMxI5DwvcdI/U9Eu5lSCW/+xHrWJQlQ6TElN5TQwdmejykLoQ7Shs8sLhElbfjrt
         Yr5+ZpMLLSAdgyegY8sJvk9tPYY0qXOdBeLLOPfUYSsqAC/LxTiNEoL9y6G2jNhrb35T
         iUyjnRVSEgrs8f9MWDDeguKneBmu/QJ1O4sf6hw6ZExEGS2KqCsaqkGMcKrmDdh5/AK9
         bntQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QVP5IDv7qRz6eUJKbq0/NTySxxaGgwg8+yl3ukkGAr4=;
        fh=jKHW1Hgk33Qh/4Hen8JmP5MWnaa+trnUu+DgdIocv8M=;
        b=Qw941CdUp94uuKch8Z6MAplWnzWhyG9SgHhBdQ52vMgM84HCAaQSf5zL5bksrOFX3X
         p7M/o1k82YxMRaU67UyQNObLe2z5RHjg4/uoatpJ2JV7P99i0kNj2B3BteCcUEtf/MD5
         XGrXYBBPGkAcSXVpdMEtmlHP14kkIUrlXm1FvDgbwEB6RuPHNWhdzW4BDSHmdeJNugcP
         5a36qVYdSMqRNwneYfVgWNkNUih1n1gGnpzV7LHl7EZehhKw2u5vpNkjWH/6A08DVvk7
         EMVwVJyboikwRXRRLsT1Hc8O3A+zll2MpNMn13B+0wBQGC/mxGHqgIUIbrcNwvIGnVzQ
         BBEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FJkoJt9v;
       spf=pass (google.com: domain of conor@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719417685; x=1720022485; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QVP5IDv7qRz6eUJKbq0/NTySxxaGgwg8+yl3ukkGAr4=;
        b=aRYCZvK1ehLkBusC5NOglg90sG8CtsDNe+1qyBj1pWx2ykkLdY/PIdyUXFMEg+O5Kg
         RVE7aCbKjn0fmf0PMXNvV7y0UPi/3J0SUddRWGqGJrheE45J5yaa48UXA33kPRAlVuGw
         QfRe4G7d+jTyyma7hb2pT2+ECx2p0EPKanjJ2GfrtnsvvSUtbD1W8LeYFfoNdmWnyDmo
         /eY8/VpRKx8b75iGv8PFHMKn/PXUVoEQr3B222cDTNFaxoUpJ7CaSOIMeKKkxjfGT7E1
         btyU6liv7zOySYdqS/RjyhhSoRfGyfPuLqNQaJROXo5vfHqCqD5I2NkyGgm/wG6l7im0
         242w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719417685; x=1720022485;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QVP5IDv7qRz6eUJKbq0/NTySxxaGgwg8+yl3ukkGAr4=;
        b=q8zHeQ0JrOMPJkq65Yu+fgBIZh0JsrQJ/uYtwvelK38ma5zTRegMtWy+cIZomZ5CiT
         wEdSn+CvKmsWZYwELHo0AmifcpvrDRpT0hiNIvYvceFEcWx1BY/1WAqyc4Ih1HEG0tKJ
         A+7v03Syr416iuM5W6VLv7+J5RGpOFsfxWb3PyCARf8ywPrSSa/2UETkR9GHgS4XU5WC
         JYUHwzoq4PGrcY++gfojdv0os/soiyjfpNXwY9j0EfqEj+X2/kVr+VxGtdcksNDDuDkV
         GjzQA9cuDhJwcFf6OD7U/NTIxsb872+HdKUPPLnZGvVwBpQfvsET338UVYDpjVOz3D+y
         rsqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVeeYKM9eTL1U5s2pmRK2VsQgBekIq4A2q6yfq+adCQI7e2X1VjPQToB4TmZCQRweNVzGhkm5DaroolCOnvARqR0RexxNtg2g==
X-Gm-Message-State: AOJu0Yx0GaXSgD9dGRZLwpZPZ1Rpq+kKyRYUtCahTSzv3xbVAQP2v72G
	h3LNx3QPMcmoZR+NyaFlGVzuBwjj/3eBUIocbYOmVgPcIhtu6mlD
X-Google-Smtp-Source: AGHT+IG3muKDihQkzJbqUrx27Od+DInjlGRo9hGr2lCzJEcjcRwGz34faOiCkkDCqwW3JsGuqnS1Dg==
X-Received: by 2002:a05:6214:27c5:b0:6b5:7f22:d7ca with SMTP id 6a1803df08f44-6b57f22daa7mr25864136d6.5.1719417685575;
        Wed, 26 Jun 2024 09:01:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4411:b0:6b5:268:d754 with SMTP id
 6a1803df08f44-6b51030178dls107786216d6.2.-pod-prod-03-us; Wed, 26 Jun 2024
 09:01:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVe/niXKnEu7IY0BMbHtLBfiAiwcJCP83eX3E9EsEGd3EshpSlxrENnomCU4E0HrQ/7jyvrqdjD5BNYahuynp67Q2Jnpx7sd+h4bA==
X-Received: by 2002:a05:6122:181e:b0:4eb:5e6b:1c29 with SMTP id 71dfb90a1353d-4ef6a7b7cfcmr8194092e0c.16.1719417684727;
        Wed, 26 Jun 2024 09:01:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719417684; cv=none;
        d=google.com; s=arc-20160816;
        b=W9FUa3uhtSliS2SCOH9yVol8cV2BIGJUY5WKJ0KhNb4busBHS6hr5ZiI1iY8MmI/EM
         IkD2nNsEdwYCoVzeqN2cVNRIZXzqaNDniVaHh8jYf9iiI6rv0EpU84IL7QhnDsynkVtH
         L5zCTb3eZ2evNk2ThIYVFra5+NpQb9Qb7rimWyiKhIXMG2vEck/U7zRZ9txnEEAaL7/v
         yAJ1RPzZieQdyehZaHwH1edrAtH997hglQbZyWhwXscX8YE4TEXtCEjTZVkdQOIxla5k
         RhImPCw2Ub1KHsybymelyJhj8kS4zsnVzallj1+fJRGSq0rdc7jJk3kamTLdWyyUYGcw
         HWLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6FJiMldM69eQJLraRah8bEWxjh1VWv8T0Rugw3i3BMw=;
        fh=qLil01d4sTutemriPxxDTu5zOoY8VsABgDPxebgwgog=;
        b=YtAbFI4bbK3O9r+HDv55I0dnfz7IBkNcaoc8DvNeQtaC/HlRD7k7HFxmalntXEOGX2
         BiUfsM5B3MEvXadzbNFPrbjhKDMFxMC6WGqA0Y2LSsC94Un7DnRrYhJFQHY5dXI9F7h+
         VR0gtcf7Rw4HdcuXKy+qvH2wLa1l9qlTuUFT3YiISptmIvBQurRJw+2HeIRUXl0mzHUT
         tXtq0pdDR/UupeADC9r7+JxBWNS89CBNbuXjDIf0VM4mXpVdDbfKP0HAOe4QfmHd75Ko
         oCEF+9K4brUgIkazqsb0ETkKKlRiWOGZq6qD1GB+Fwo0oh+W4cHmgzrDBGFrUSlsvgmY
         z2Mg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FJkoJt9v;
       spf=pass (google.com: domain of conor@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4ef8af67d5asi305139e0c.5.2024.06.26.09.01.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Jun 2024 09:01:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 1151FCE1F39;
	Wed, 26 Jun 2024 16:01:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9D334C116B1;
	Wed, 26 Jun 2024 16:01:18 +0000 (UTC)
Date: Wed, 26 Jun 2024 17:01:16 +0100
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
Message-ID: <20240626-refined-cadmium-d850b9e15230@spud>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
 <20240625210933.1620802-2-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="2g5NVOE5lfng/7+O"
Content-Disposition: inline
In-Reply-To: <20240625210933.1620802-2-samuel.holland@sifive.com>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FJkoJt9v;       spf=pass
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


--2g5NVOE5lfng/7+O
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Tue, Jun 25, 2024 at 02:09:12PM -0700, Samuel Holland wrote:
> The RISC-V Pointer Masking specification defines three extensions:
> Smmpm, Smnpm, and Ssnpm. Document the behavior of these extensions as
> following the current draft of the specification, which is 1.0.0-rc2.

You say draft, but the actual extension has already completed public
review, right?

> 
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
> 
> Changes in v2:
>  - Update pointer masking specification version reference
> 
>  .../devicetree/bindings/riscv/extensions.yaml  | 18 ++++++++++++++++++
>  1 file changed, 18 insertions(+)
> 
> diff --git a/Documentation/devicetree/bindings/riscv/extensions.yaml b/Documentation/devicetree/bindings/riscv/extensions.yaml
> index cfed80ad5540..b6aeedc53676 100644
> --- a/Documentation/devicetree/bindings/riscv/extensions.yaml
> +++ b/Documentation/devicetree/bindings/riscv/extensions.yaml
> @@ -128,6 +128,18 @@ properties:
>              changes to interrupts as frozen at commit ccbddab ("Merge pull
>              request #42 from riscv/jhauser-2023-RC4") of riscv-aia.
>  
> +        - const: smmpm
> +          description: |
> +            The standard Smmpm extension for M-mode pointer masking as defined
> +            at commit 654a5c4a7725 ("Update PDF and version number.") of
> +            riscv-j-extension.
> +
> +        - const: smnpm
> +          description: |
> +            The standard Smnpm extension for next-mode pointer masking as defined
> +            at commit 654a5c4a7725 ("Update PDF and version number.") of
> +            riscv-j-extension.
> +
>          - const: smstateen
>            description: |
>              The standard Smstateen extension for controlling access to CSRs
> @@ -147,6 +159,12 @@ properties:
>              and mode-based filtering as ratified at commit 01d1df0 ("Add ability
>              to manually trigger workflow. (#2)") of riscv-count-overflow.
>  
> +        - const: ssnpm
> +          description: |
> +            The standard Ssnpm extension for next-mode pointer masking as defined
> +            at commit 654a5c4a7725 ("Update PDF and version number.") of
> +            riscv-j-extension.
> +
>          - const: sstc
>            description: |
>              The standard Sstc supervisor-level extension for time compare as
> -- 
> 2.44.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240626-refined-cadmium-d850b9e15230%40spud.

--2g5NVOE5lfng/7+O
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCZnw7TAAKCRB4tDGHoIJi
0lzdAP9FEjY6nhgecyj1qyL7BY1ORdvCG0mlA35ivg61fW7EsgEAwwWyBymmuOic
KbI1oP/Agz7PwvDvQ4h4QigAxWc+jQs=
=tYy9
-----END PGP SIGNATURE-----

--2g5NVOE5lfng/7+O--
