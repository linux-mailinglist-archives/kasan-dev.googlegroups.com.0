Return-Path: <kasan-dev+bncBDAZZCVNSYPBB2UE7OFAMGQENML3TMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 3286842504E
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 11:48:28 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id o10-20020a65614a000000b002850cb8c434sf3159451pgv.13
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 02:48:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633600106; cv=pass;
        d=google.com; s=arc-20160816;
        b=q7g1UTynP4ZknEBrCOql5VKZhInsrsdhJdy8x3nY31p6hRDyeCd8AkF1Ku33UDPmlb
         ck2vy9yC0G+7fQ4WqK9bgtAsWd6BP8C8sLF6dQaD6LHGvzYPvl1YhfCRpEgJ+NHualQL
         dII3en5QDaSf8GBeQw7bEG8fE3gkIHYqMq8foTrvxCQA0P2HtCNh3It5sQXulYfyxFM+
         lU+VZs/0O6v5YS9aBlzIO/6I00s2zIq3OM/JkOEEBL9pjLqBussfJzUboJQpRMJ2xmNh
         PZIuVcWW+bU2C9t2ZItvFQRfOpTHWKNKDV8sXpJlzPrm9mqqkV7tXKpFaEbeZ86dqJh3
         IhlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rzhz/9sFasrbeMdGHRKeeL8HqWKYLIlkCTdPlfzmN+c=;
        b=upkfoMjIiEWy24HXkC+ot/JMBgHdAmbso/cG4bXPMNEk/goFOkJ1ECUXOs06pRVIG5
         6GyH0vmFyDBW9YeTAuzO/O7PfH7ouZnBjhxDp3TydFMQLQMhfKwmPbBnMkA3GTQdvtaD
         4ByJDbCrzoMX3p75nZhnJpJ6R9u4zL7TVe0q01E/QwTpQClBNrwaHjZPyAYjHVUMk790
         dSFAsw6ASgeSCIiEGTqapWu5t+HV2ocFqpS/pONjU+K+G7ZIQegVRIyr2EvTQxEkX6V+
         5qbZViO0JlcxPxmLfeaon2XBEPgoHNta7T2YEOciRUOLlsj7hHX3p/2eOY3XHF7qJn8v
         LW3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JBohsxHT;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rzhz/9sFasrbeMdGHRKeeL8HqWKYLIlkCTdPlfzmN+c=;
        b=ZT52+iglUCv3IQPmetiLo1Mt0MjCnwi5AiuQ3JPK/c3/PPtpuQcjZIDBkrQrzuGdFm
         wMsDto9BkrNpFaNY5K23Stpdw96EQ22d9D1y62Y3ornjc8cayZTEhNWz2AR7HUWDxxL3
         l35KDiDASCnD4Kgk441emrhnAun+jY1GNmmTekEYauvcuKGhJfHWUvzakZZB6ufLRKMS
         dMHt+nwYeNhOqEbzcQgbryrmhrgh/srQCM5aSf1vCwTa0Z8JY4ew0NTN9qBIA/nCMFI7
         JLt/dy8Pw5hokV/Ddt4bGvlCoyIEf9qpicsCIcQqjlpSTRZA8P0L1gFtRx2KwYh0WlqG
         umyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rzhz/9sFasrbeMdGHRKeeL8HqWKYLIlkCTdPlfzmN+c=;
        b=fPy9XwhSqqRGd4Qoku0krPo6iwf/i8p5u2ev5BY7FzgG1FAeq9FktQF3lWR6cHrg3S
         ieji0IifKJ/MRh9ISiCPCN/juubxTt3lYAt7PRkDNc3dJN9obXOxGbd3iYE4ZnJfxM4a
         VGlVkfrDF1XFPMdAd+4NTJIXwy9hLW9lR2q5dO+tHiMvav60KQX7c/CZwiBfwPULM697
         /geiU2XRxsVzNdjBISd3ke6tM8Kup37kkKCft5Nzsk8JR62YBQwixSwKCD7yufOD0een
         jkenP4+EIfKsY+aT0NuFU2qB8AW+15XR299x3tahV32uHZoz+SMkq8I/ca/2af5LlAcq
         /0jQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ktbGsU8+NruIWHhpPnPh3S9qjvZwimp/d6lVT4quyJ7U0AczZ
	0Ju0J6IQeDapoxYtzQbS/t8=
X-Google-Smtp-Source: ABdhPJy979eTDYK5b253AuOYwZsDZbFryFNoe25BUNbOrABFqV7ZODcQY20YPaNIHlRlFaTJqakQ4Q==
X-Received: by 2002:a63:e115:: with SMTP id z21mr2613532pgh.306.1633600106628;
        Thu, 07 Oct 2021 02:48:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:848e:: with SMTP id c14ls1614213plo.1.gmail; Thu, 07
 Oct 2021 02:48:26 -0700 (PDT)
X-Received: by 2002:a17:90b:3910:: with SMTP id ob16mr3717165pjb.234.1633600106117;
        Thu, 07 Oct 2021 02:48:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633600106; cv=none;
        d=google.com; s=arc-20160816;
        b=X2wIdTVseZCYqFOJ0dKx5Yp+K6fpkenM+2tOS6ZHUZfpewnogArjlEruZdcZrnZjx9
         A5dPW1Iel3aay8EEntii9+/QXt/+GeuG+K8n8pBuMHe2gOqVppWDg5O42onDrOjoIq96
         8acATzrA7wk+kjAVyX9LML0duHxiVskT9YfBGGmV79ScrKYAHOsDgZCKu4l/5N9Zo89B
         qfB47PNRh92IW3GqjRHJmLCcb9sNLoAYCrynhiEPZ5ZEuvnaJ4QLuDwLronGu5FdY529
         KjwP52qQxO4bNMPMGi9mOE800Jc7rQ+2BKme9brg0BDYIY3ucbFK0GhTJK94dTje6RWd
         XQQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dEFQK8YJdy1nqLvsyh8XMgwqptO+VGb4JzIoIaWZLmU=;
        b=UXOlQjMJmRsSp+AWOS2ftM5KyyPh0lMYHRKk/8rcA53Qf8FkpDlMdApgPZyw5UN9qS
         efjIF4cnnFuCcOno69AV63GrI88X7aRZnPN7TAEELKoCIX7Wn3ilcIyyMxHPK7FNQRn5
         kLpvAkX87iLmQObo039IrSA3D7pY+nvhUR8QOPldsupmKvSsel0jGe5uBg0h2JRLPMBw
         D9v3Zbc1QnL3dsF9Til5yEE+X7GUDdb0G7Kn8zuvtZkay4e2arIA4lzJMRgzYlbh/Caq
         17ZrLXHM8Zs0k0ekzPBP/mu6kuwOsX+v3PV4XM35NUc6f+gbXg8bLCpW4C/w9/wqvY8D
         QUdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JBohsxHT;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m1si826590pjv.1.2021.10.07.02.48.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Oct 2021 02:48:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5343E6117A;
	Thu,  7 Oct 2021 09:48:23 +0000 (UTC)
From: Will Deacon <will@kernel.org>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com
Cc: catalin.marinas@arm.com,
	kernel-team@android.com,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Evgenii Stepanov <eugenis@google.com>
Subject: Re: [PATCH v3 0/5] arm64: ARMv8.7-A: MTE: Add asymm in-kernel support
Date: Thu,  7 Oct 2021 10:48:16 +0100
Message-Id: <163359491823.3122938.443758719431046592.b4-ty@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20211006154751.4463-1-vincenzo.frascino@arm.com>
References: <20211006154751.4463-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JBohsxHT;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

On Wed, 6 Oct 2021 16:47:46 +0100, Vincenzo Frascino wrote:
> This series implements the in-kernel asymmetric mode support for
> ARMv8.7-A Memory Tagging Extension (MTE), which is a debugging feature
> that allows to detect with the help of the architecture the C and C++
> programmatic memory errors like buffer overflow, use-after-free,
> use-after-return, etc.
> 
> MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
> (Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
> subset of its address space that is multiple of a 16 bytes granule. MTE
> is based on a lock-key mechanism where the lock is the tag associated to
> the physical memory and the key is the tag associated to the virtual
> address.
> 
> [...]

Applied to arm64 (for-next/mte), thanks!

[1/5] kasan: Remove duplicate of kasan_flag_async
      https://git.kernel.org/arm64/c/f5627ec1ff2c
[2/5] arm64: mte: Bitfield definitions for Asymm MTE
      https://git.kernel.org/arm64/c/ba1a98e8b172
[3/5] arm64: mte: CPU feature detection for Asymm MTE
      https://git.kernel.org/arm64/c/d73c162e0733
[4/5] arm64: mte: Add asymmetric mode support
      https://git.kernel.org/arm64/c/ec0288369f0c
[5/5] kasan: Extend KASAN mode kernel parameter
      https://git.kernel.org/arm64/c/2d27e5851473

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/163359491823.3122938.443758719431046592.b4-ty%40kernel.org.
