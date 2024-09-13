Return-Path: <kasan-dev+bncBDHJX64K2UNBB5NAR23QMGQE564LZKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3892E97763D
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 03:08:07 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4584cfbee5bsf57199941cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2024 18:08:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726189686; cv=pass;
        d=google.com; s=arc-20240605;
        b=PjMsQnN+9+zUqyTPhyi9dVkNhfrIIqzatY63s5PS/BioZcyUrziuj/5vOiB+RWjQp/
         rzyzpzAYefofIQyLo/FNyL1ZmS299KL7VQBUU/3eLqiqKSdc/iBRQAA99s99xTUqzFru
         gmIluleUA3+3Ij3kTQYKEl2lLy1BX85tyKL0aP+6itDAm9LGzrvxcY5c2q1FlHAqG/6w
         +erGw/VmFKSPnvIyCbTX3JuuRSkRG5U/HEiHVNClYGylpLL0QzetcinypLJt0vm5Hb2V
         Nips6TM8uHJj/F22jpnqr2bIx85Yfej/M23sEcfCF9yLEB5V72EW2VQ5FP0stcMsvH5T
         PcKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Yewqs+1aXIhewGRQCMq2PJDwC61NAtQswF49koJUHa8=;
        fh=/N2FY8nL0//DVMaxbykFKBlWQKnEAiGnzUViFqnQ2Hw=;
        b=Wxy8jGRWA9nhqPplc3JI0idM1TfamxoOxmeZU9A4m4g4tpGvr6B69Ox9uzag4ElUNl
         WPNIIOYLCF9e5+E9bFH0HVaMJoKo3uJWtTVmBCcaVw66sBPBtVyIG6Bbou8RzbaTodo0
         mNohoXadLTPS0JVG7DcqWq0tktmy9TiYeI2mkB/n2mAqrREJc+4kFRGiZ/eea2sjVY1B
         KDlv7QVLFHBgTmhll8GEFAk2TDziDevLouqJEjvYI1mfp/bhnOB7fJJzyqASI2Foegq6
         ops+hnk1P6mYqvTt7kho8Wh4AEEFfgwP7+Ucl2zDXb9xHeJFpQVGmUO0e/65mRSCwub8
         LSQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=ZYQM1135;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726189686; x=1726794486; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Yewqs+1aXIhewGRQCMq2PJDwC61NAtQswF49koJUHa8=;
        b=gJiOYHkEiiviPrggqGkrokLxqbuzy+ekFg9Zw8gk5iINLyDbv/kygJWD7FhkNaREVw
         DtFLpH5/aAEg0nvVuWUpau2UlEGCa+NlpinttERrTAXRy62w1EfAoHaHilNTIRY+ETvD
         2v7Z03PrJaXxkdr58XtHB3L/Q9ghth2EImTbq70eZZALnIMgHrPu8kHlLLrtEHYizmUf
         vkOSLNlVvkmBdJ9uPHLvZRkHtMBybmt2CfPrlAn9o9q0IzbjifbZeYqVnuvip0CHT3XV
         CvzQuMZoVHZ6Cyk1FvSelxVOA6TTxoeuANYcspLxQySMspblfJIguCFVAYihf6kbBR8m
         FeUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726189686; x=1726794486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Yewqs+1aXIhewGRQCMq2PJDwC61NAtQswF49koJUHa8=;
        b=tdnDaNWJgxl/P5aKh1eb+rxoZjNy4wxPBDLwI/LFTRbVKUj1NyqBmMoM1hRVvenbAB
         fQwf+qKik89lztnyBCP8HcCy4ke6G0k+uoQXF18OBgPZxdosXE3KtRv0h7+h8tplx4vh
         JAw8LCPn3VvDAkg889l7K+qMK5bd8XyUXJan4abVib9jYny3bmhbCupvBvEHZqk1PEvV
         wXRDO7lelUyn4FquOicuLbsIuPpn8MO5Rjy5uQJYWEkmyn9GWMxwgF1WSPTJzd2rauMI
         jRPyf7k6xjrKOsLAi2SEnO9YO6agwOlyYu4Wt5xNib3rv1PY5IfPBT7DUMU99Oj1XLTm
         BCnQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDFWPYz4YBwNtrxWgAPttM+VvIgfI71DVALCITA4ZDJOZ9vM2VscLjXs56h57nVzVik1qZPA==@lfdr.de
X-Gm-Message-State: AOJu0Ywhp8u0O4xpd+BJG2cGnjwNagmzIIF/MThlCIkG1IZ1y7u1Vs3x
	+HlwbAJwrEPJwQEEZz3rFsNuRUZpXuuw6SZ/MEZZqxwPSxt8Mqoi
X-Google-Smtp-Source: AGHT+IHxtaprvTyflvJ3/BPAow25d6BBt9nnMJRy3oudXVK0si2rq5HPUhLr7B34v/lv73kMMQZu4Q==
X-Received: by 2002:ac8:5dce:0:b0:458:2e58:46d with SMTP id d75a77b69052e-4583c71d9eamr225649121cf.12.1726189685715;
        Thu, 12 Sep 2024 18:08:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:da6:b0:6bf:550b:6bdd with SMTP id
 6a1803df08f44-6c57b2e54d7ls3722556d6.2.-pod-prod-00-us; Thu, 12 Sep 2024
 18:08:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVe6atWqoPEW2uZNM6YFbA2xjNIVQ5otGQqCT9VFwTsn6Gl5cjVd8FRyLRg2lgv3fZApEYwmCxY/Cg=@googlegroups.com
X-Received: by 2002:a05:6214:5d89:b0:6c3:5454:6e1e with SMTP id 6a1803df08f44-6c573b5910fmr91385626d6.24.1726189684948;
        Thu, 12 Sep 2024 18:08:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726189684; cv=none;
        d=google.com; s=arc-20240605;
        b=k7t/aoJQ1k8GbAm1WEVuCufiREmD4SJTWlkK+EEbg4cBUfUxgaCLCbwD50TbYdrf9g
         ekBKIXbnybxsIJyT+zQ+fwk1O8AYp2aYVVMFJgS41ZoIpkfn9XXa+hO7u3FHWJWO6EAF
         iOiMJYDndE662t4o+vzY9wDCluWshgulTWHkq86RQlMcdePUNOcIq/5GHkPPx1dI23bt
         K2YJoa4Y3Qw1CtZ57IgSXgCgLR2qSQ84uT9yR6PkHL84qI7dIBWlMnwxACl37z2UL7uP
         v4NGMqUPtVkkZlW1yZGE+n6rrCmVf/a3BsbZICL1GRiUFC1Mrvq0m9fgCC6th2yPqN2t
         8nkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8rX91s/6lVMum4h31lglbcRQxW0xWM2VsFWKtsLlsc0=;
        fh=rz6P4lT0VKGYXx9LcGCIEYQKBexVO/1TyR3X9OwKr2w=;
        b=CQmRbYs8lA6yXmgWyKGJ1pqcbTvl+jaOFlqU/xBI5uXJcpCixMSySTwFjITyrbU1FS
         wC03paDSrQGMdg25zFbiq9Pxkhug7/IgekislVQudYWJddSvpFnfliWoHzixItkxdB3M
         iRFRKXTc3g2TsQW72LlQBMLsS3wOtlkAAoIHxlRdsmc0dMmU8lE/loRF3Dr1WVWvbwnv
         FvbGCqQeOdCxKmbk6eIJF01bA8pF9hD6gy8fyP0TNiD29gsoCq3ei5GvXqeZGah7s4fj
         X2ssDLQ6OTbS7m6bGLFsZYWozg2kj1dzABCamRPKHBzgAPOrIH3Eu6hCBDHPXsrz9GA/
         ciKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=ZYQM1135;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6c53477c63bsi5397666d6.6.2024.09.12.18.08.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Sep 2024 18:08:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-2057c6c57b5so9347435ad.1
        for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2024 18:08:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXGdsdnRkduF/aTDMNxtABtRx/wBusASMgSL/ij4nGI+1Enj4iSuMVAdJeEJesXpA5zUdrVVYB1C7Y=@googlegroups.com
X-Received: by 2002:a17:903:22c9:b0:205:6a64:3144 with SMTP id d9443c01a7336-2074c798c92mr160035315ad.27.1726189683676;
        Thu, 12 Sep 2024 18:08:03 -0700 (PDT)
Received: from ghost ([50.145.13.30])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2076afdd268sm19438885ad.172.2024.09.12.18.08.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Sep 2024 18:08:02 -0700 (PDT)
Date: Thu, 12 Sep 2024 18:08:00 -0700
From: Charlie Jenkins <charlie@rivosinc.com>
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
	devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Conor Dooley <conor.dooley@microchip.com>
Subject: Re: [PATCH v4 01/10] dt-bindings: riscv: Add pointer masking ISA
 extensions
Message-ID: <ZuOQcNTVUZ5/LFOP@ghost>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-2-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240829010151.2813377-2-samuel.holland@sifive.com>
X-Original-Sender: charlie@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=ZYQM1135;       spf=pass (google.com: domain of charlie@rivosinc.com
 designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
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

On Wed, Aug 28, 2024 at 06:01:23PM -0700, Samuel Holland wrote:
> The RISC-V Pointer Masking specification defines three extensions:
> Smmpm, Smnpm, and Ssnpm. Document the behavior of these extensions as
> following the current draft of the specification, which is frozen at
> version 1.0.0-rc2.
> 
> Acked-by: Conor Dooley <conor.dooley@microchip.com>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---

Looks like only aesthetic changes were made, but the spec was updated to
1.0-rc3 (interestingly the second 0 was dropped).

Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>

> 
> (no changes since v3)
> 
> Changes in v3:
>  - Note in the commit message that the ISA extension spec is frozen
> 
> Changes in v2:
>  - Update pointer masking specification version reference
> 
>  .../devicetree/bindings/riscv/extensions.yaml  | 18 ++++++++++++++++++
>  1 file changed, 18 insertions(+)
> 
> diff --git a/Documentation/devicetree/bindings/riscv/extensions.yaml b/Documentation/devicetree/bindings/riscv/extensions.yaml
> index a06dbc6b4928..a6d685791221 100644
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
> 2.45.1
> 
> 
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuOQcNTVUZ5/LFOP%40ghost.
