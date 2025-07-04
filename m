Return-Path: <kasan-dev+bncBDAZZCVNSYPBBDNGUDBQMGQENLLHB3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 44B72AF99F7
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jul 2025 19:44:48 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-b31ca4b6a8esf709762a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jul 2025 10:44:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751651086; cv=pass;
        d=google.com; s=arc-20240605;
        b=GauweP1EuMkDCuufZ+z7fhpHZAeye66BpzPzdUvXJKCMRpVwZMwri00fAIA3yiRq5X
         t4h7iXPkjaNfatIdygGV6NNu1TqrCktYIQ/97GHXxDcJenDZFm4XgnNCW6W73uYIfHIz
         F7JhAWwSFZ2AeyoGXZE1gBYjwXS1zPul/wruocaYiJTonFZM2/PFvcZw435widdtw2ew
         6Xx+dZ5/79m82kBjwaQztIQqeRT2UKLe9cdTT8OQJp1VR8VI01oKqFhTsAxSXPAKYQaf
         cfRePTCn+RXnc9QCL10CTZz3brx4Zw5yu0g5qfIzuAecanbltS+9uotJL6/8St29W1FK
         D/oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=K/sS0WLxcFZIqEKjzahtsBUkaP4m5JZXNrLh5d/hFcs=;
        fh=wS7YpOCklPr62qIZ5HfGzV1ZRCUZqAPleoPV/Ncb+o8=;
        b=gffzwX5TGUofCvWh52Kn85FwU1O8SZV6WpM53IPp3TgadpDIUiPxXpBL10EhvYN8yV
         FiuzBqVave9zKnVhuX33PQ2QJGFfuAOJRnV63TEPOrmRBZulaICHGp75xbo+AQLHGf9y
         /wFFfY6ilXq3cF42ck0Craq05SkeLwv1g3kHmNnwCo2AMXKrkysfD7De9luaWEV4rCLP
         6aPZpxQkgvYZ6waq0huFdwgbXCaynom35y933LNSrE7BLRkwn17E/Y8rh+jY6Q8rJ5us
         txva1E6HgbgAccdM+NZPmt+TT1j/lw1dOMpLuDd7G8hWtYONF1s6ufhHbM0emw56SFG7
         YW0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hJ1LHkhl;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751651086; x=1752255886; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=K/sS0WLxcFZIqEKjzahtsBUkaP4m5JZXNrLh5d/hFcs=;
        b=Z+uS+Rg6D6A8d0EZrW323Adc709qpM6BqRdMWHoZZT/itkDmf4H/jt9mN2Jvb3EO97
         1vKGrZN3GKRXGwPrGCJLNuNiWJvPOoQfBNg4lWrQzD/HKNcjCPP5w2pK3WnSE3KqDDtm
         4r2dB1xL6VprHndfhhFOLpWfQCGzU4RNCd72hJwAxMN3sB6kodFFf9erX5oKnKqX8TMT
         WkDbmjoqikDytDvEZ/b7l3o2TJM/AW7pN6PcEt1MOE6MHTKVU5Y6AyjgP5TFbnoqs4Nk
         19NCupKDKdZeRQ3EbkvI2P3kIJsSk//pkDMtAPGF0VDzlhy6QCPPmsRw7iJ05X5R2SXd
         Lh/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751651086; x=1752255886;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K/sS0WLxcFZIqEKjzahtsBUkaP4m5JZXNrLh5d/hFcs=;
        b=Zw15VMOn+ebo0fRAPgWFmbBIaEhXR716wmtK0qYf5ZYG2clg3+vTKVI65yTAeO3Wo8
         jLdU2/k3w30bHoEmyhuFA5ZbYte+zsEcx1FzqVO0iCb78f8Fsm5m0RvC2rRWm4fCFaw9
         E1YNxe0yJEx87muTjL5C12exP/A7a/OUJv7sM6IdAosvZQ/snp3z7AYHje+ZXwNFBIMB
         LvS2auCBH+qdCeBC0XZas2DUsComvIYxJ9K++0syLFYqg1ogrJsea4RDWHhAZxZpf5uR
         UljjHQyvhmmDf6yn5ZBUW2bIlZpUHEANMva5mFn5obkJdfT2WgUKr4xEyZl/IL3AZLLZ
         c6Yg==
X-Forwarded-Encrypted: i=2; AJvYcCWwHeX2ViD5ur8Kp3aZtUIeAZCtD1YfqOL3+rER1CZyuHYBgAb14L6ItDfb431WRyp1ujuYiA==@lfdr.de
X-Gm-Message-State: AOJu0YyspMH6yzTJ408637HW39oLrrtwUNWGD7pS9Xrzd2sTZ1toifsu
	x43doWl63C9uBI8+bTxCbonkv6JUTld1tSsfDK8cT4+Ee2MKfGDKZweX
X-Google-Smtp-Source: AGHT+IHK4pWwonGibOcJX6wAVDaGmJ2hMRHkiazeHm6+sNjAQp3OFzgUNUJdiSeLOB1d4ZcNdCyDBg==
X-Received: by 2002:a17:90b:55c3:b0:31a:ab75:6e45 with SMTP id 98e67ed59e1d1-31aac4f0ebbmr4538156a91.28.1751651086397;
        Fri, 04 Jul 2025 10:44:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeBNe1Xb4RYmnZn4NNZOEgjLZ/CFFWP3IDsny0Wydd9gg==
Received: by 2002:a17:90b:5203:b0:314:21ab:c5d4 with SMTP id
 98e67ed59e1d1-31ab0335e2els647919a91.1.-pod-prod-04-us; Fri, 04 Jul 2025
 10:44:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLXriYXYslP2TyCU+jgsH36MEsq5Em9dn5uTsNsjmln04eDQzrqbGbjm5rKTdXWiXlye2t5umx8nI=@googlegroups.com
X-Received: by 2002:a17:90b:35c3:b0:311:c1ec:7cfd with SMTP id 98e67ed59e1d1-31aac4fd0bcmr3789965a91.26.1751651084793;
        Fri, 04 Jul 2025 10:44:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751651084; cv=none;
        d=google.com; s=arc-20240605;
        b=CANtEyglzMANoPbu3uViyJatbo9HFwYoNUMYNP0nVwcHpftqCQsDJBWFKBndKNlGJ+
         sf+bK5NW1OGIEknAVws/MdaO5UFfKFdWzWiF2f1mX/+jrGTE8WJjv4vJx0W4hbLGXSve
         JxZ7s4rpYegM6Rx1WEmiwg7VCLgnv0f8H7ALCMf0FQB2ENpDyJ0vSOA9f580S/7eoQ4r
         oC0+BONvP0V0Tu28Z79k1lD89d6NhL6DvDCLKHJNzvTCyYheTGI0U7g+4V3hGdcTS2Vo
         O16eR7soVDbykrk0i84OKHMsykbexeQQvekwyYfIu8pqp9roKNKxxUenR6z7H6P6Lf1J
         244w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4JAt74F1miLEzpWqwEs/9FjD5FZn9rXwKEhCUVtjvGQ=;
        fh=Qsj0PgNj19XIQFz1Xb4BcNn+NqlKRtkpxpTi0HHoW8o=;
        b=TalFnkVNWJUCi5v+Xef94Uxn3HDPJNXRRmtlqkuk1SD2DOcbPQYhIfcLMlNnxh63kC
         2dFbfmeBOV9q7eODd5tSCfYaod6XU9ntLDE8AKWsYONMbXhLWst147hJ0gPiRGOC0Qva
         PnYlC+mvNaDwx/NhibPxVEUjb1bqpqfX51KA2i9NsE+co8AXbqCKfCNH1QyuN9gnqvr/
         sYR3wR/AL0rHjsxbTscnA4qNv8953ghlb3X+8Mqr2pl+RE1Y/xxMeWNUxvWmL4wW00c6
         tIyiyMnAsxF5b7YPFgIMlct//tOaOfpcgJQi7HfZKKB+vW2utm3gutVyHGW8l/GV0qsZ
         W/rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hJ1LHkhl;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31a9cc521dfsi254075a91.1.2025.07.04.10.44.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Jul 2025 10:44:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 21A3B5C6A5E;
	Fri,  4 Jul 2025 17:44:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 22BB6C4CEED;
	Fri,  4 Jul 2025 17:44:40 +0000 (UTC)
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>,
	Breno Leitao <leitao@debian.org>
Cc: kernel-team@android.com,
	Will Deacon <will@kernel.org>,
	usamaarif642@gmail.com,
	Ard Biesheuvel <ardb@kernel.org>,
	rmikey@meta.com,
	andreyknvl@gmail.com,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	leo.yan@arm.com,
	kernel-team@meta.com,
	mark.rutland@arm.com
Subject: Re: [PATCH v2] arm64: efi: Fix KASAN false positive for EFI runtime stack
Date: Fri,  4 Jul 2025 18:44:15 +0100
Message-Id: <175163682742.1322301.12219137975972256785.b4-ty@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250704-arm_kasan-v2-1-32ebb4fd7607@debian.org>
References: <20250704-arm_kasan-v2-1-32ebb4fd7607@debian.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hJ1LHkhl;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as
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

On Fri, 04 Jul 2025 05:47:07 -0700, Breno Leitao wrote:
> KASAN reports invalid accesses during arch_stack_walk() for EFI runtime
> services due to vmalloc tagging[1]. The EFI runtime stack must be allocated
> with KASAN tags reset to avoid false positives.
> 
> This patch uses arch_alloc_vmap_stack() instead of __vmalloc_node() for
> EFI stack allocation, which internally calls kasan_reset_tag()
> 
> [...]

Applied to arm64 (for-next/fixes), thanks!

[1/1] arm64: efi: Fix KASAN false positive for EFI runtime stack
      https://git.kernel.org/arm64/c/ef8923e6c051

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/175163682742.1322301.12219137975972256785.b4-ty%40kernel.org.
