Return-Path: <kasan-dev+bncBDDL3KWR4EBRBJ6MYWAAMGQERINXANA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F212305C8E
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 14:10:01 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id b4sf1192640pji.4
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 05:10:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611752999; cv=pass;
        d=google.com; s=arc-20160816;
        b=bJZGvCnuN6pzhw8A68+TdvYHpp+tabkgQNjF8JttAFy0OWD2ZXuOaQoF4AAClUbkMX
         ZLsgorKjrcoLCtr880HWtsyfF1gJfLLf71hbQYtsC+OQxEjsUsnrPyoUuCU8+HyLl+kA
         hjbxTjCsnuEHDeqfVdAxlJxO8meBd4cGq1LsMFgrQZONE8rM4As0enrvWtNWUN18UxHi
         itzC7/BcZYdo3SoYhK4IKkOL3TdRtjb2oITeKCEKiIiqAPQW0CmyxK07BPUddGip11Wd
         XNLJEkfLgoQV70V5gHRXc2NqRd8BDaemXHffIJ/6j1cjOHOhcpUb5G+0AB+ODTZf97nG
         2y1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Jyj1hWYNF7Z4Yc8uqoNfcoctTynr/MgtJN5r1z3aPWE=;
        b=kNOv7ULsC8nVUsFJHuTHo89T1+qk7VJE9nsXew/njRHY9viuA7NKwH3Kpkq7ii9GOH
         /ETfxKADk5kAkDwhvjdN9ZSUNCFZ3RMFb/GmGXiyVEF5wMvQLnMLbY/mlY1zRVYPSmpi
         SqZqX/oHOLdSVovsDQ8uR8NVa8nmP7eI0X5768g9YgcCbwIPkhHMfLdLmudT3cl4hrWH
         bj4YBK2lYW22z6orc6OSAZwF5rywhPArjc6ylBQlpVWbsplxZ6i9dQ6OEYuxJDgVg4pI
         Q52tCE29bSrZqWpZi1L2QgMySsv7GS5KJTHmGdWfK7hTMN0xLciv/c2kGwPmY4iSWbvH
         1F2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jyj1hWYNF7Z4Yc8uqoNfcoctTynr/MgtJN5r1z3aPWE=;
        b=b2bFNkulMYv0cDqndRNhBcVrbZ+05nkrd/JnHeau/rzrkKpmiKfAIaeSauQAcKN0Q+
         BE2uxhDhMjjhpctoQb37jNcQEI9gRjHtJoTtz2ZLhgOG7nhnrrtDUuD9UeM0crDITd8Q
         EWf3m5ZQS5IKD1u52s4PLbvQIYkg8+spc8kYI9k4DBchLqcVheHF+OiqFZvguZtqCEcc
         lJRnI9KP3jqGzIg8+7k2zXdymrz+T8+3vVTucUGGDHDYipLaHK37sMSSENbiK5qPePgL
         8LG5XBUlmwc/jtOz+nCZCO0UjwDaCiZCDIDLOQEoa9QUb/A2CzIocw3hsWDHcbmvmQfC
         N08g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jyj1hWYNF7Z4Yc8uqoNfcoctTynr/MgtJN5r1z3aPWE=;
        b=OUCAPWj7SxGE6ZpmeGANAfxaFlGsm1nP3x6fLMDe+PdZWnzw3wm1Z8nsvZ8FoJu11C
         AW1M38FeSGnYQMoXLboyVYosFPVGmX6BK53W39PcL18r04IAP1VUeLjDNgonhQPcyXAD
         VYUVgd4xRSCffxcH1Ij2+2J8agXjCGTZ5PswNZWXUiwoepuHEgAGnh5TP0BQ/pa6x1Tj
         oN77v09hTZzXW3voj1Svq2dAZVnykkH+L2C/v6RuzPv7Uj6+uQGdPc5HmN9/GP4yHKsJ
         holN2DxEN82TQZoTMNOMw0G7Eg44Qew4q4MXT9ThpCdDwFApZ7FwOuGHjRvYMU/7NQdB
         JMfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530vYBMjRoABamI5RlcE4aPAKpkyRZwCQed4i30NMF5/zuzWd++R
	QjYAsIsXOMCcxpXfHbvB6hs=
X-Google-Smtp-Source: ABdhPJyeOmYfEicn6vbfAc8H3iTdtYzEqtZ3xrYt87+NhP352vijjimKJQ8D5BmkXcU2ANgqcxn/Kw==
X-Received: by 2002:a63:575e:: with SMTP id h30mr11076864pgm.7.1611752999723;
        Wed, 27 Jan 2021 05:09:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab83:: with SMTP id f3ls1038040plr.9.gmail; Wed, 27
 Jan 2021 05:09:59 -0800 (PST)
X-Received: by 2002:a17:90a:e393:: with SMTP id b19mr5609123pjz.236.1611752998544;
        Wed, 27 Jan 2021 05:09:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611752998; cv=none;
        d=google.com; s=arc-20160816;
        b=PXVT6F+fTzBNBZXM/31X3GPsvHTLLYwlt6f+V7zQZC3/DIqaVdkHLLPZqAOIu41x7W
         1aEj/7MS42h0POF8XorwpGhhVBlrE5TqlXP2DKtNMuj5IpaGpERgtJZkyskZshNMye2w
         liEBNUE+E6IzbmXg7H720e2CYLos88P+RQznPyideDyVy5wpi9ocM7g5F6zLQayOG/vC
         2w/vlTLIefHAyAAmj6y6npy93WQgqyBzVvyN8w2UE1wfSTVrwsmf+/aUuFIbkgF01uR0
         pHzDcvpwXBGllUx/3o0pAlH05Eg9L9cwQtq/q7l01YALZ6IfUXDyWSyjm4F6+MNT5qlX
         wHlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=c6HCNUfWyKeppNea5ntPHKOmN/hcbBz2bo2rxDPycqU=;
        b=kGaoJ3V7b3ypTREeAH0+eajqvfPcPpk9ktXoCB2NdRQtFPiTNrATkQtud3VJU7SlsU
         d8iQ7C7fI/r0p5yQ7HbXbDez6byMVczmfYUcvZaYyiG2r1R97VkLPmcokDg48refvgXy
         fWOxofs9kUHtaV31p/hQdKioFI7oPfgnL7pryy0C4Qi9bH3nwaTxRP4g3sJc79pprs/9
         X+mrHRmMl6iABmEBgKxBsUs8fcccOIMvfQQFzKy+KH/JYrV1hGwzWlVY7DFJ4QGwd8Cy
         ogXx5nepi8CyYMcliHgG7qedQrYBXaNeNRGP0NdvrWywCtr/XDbyTRLe8mjPnXFsKIXV
         YtPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r142si99281pfr.0.2021.01.27.05.09.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Jan 2021 05:09:58 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id AA235207A3;
	Wed, 27 Jan 2021 13:09:56 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: linux-kernel@vger.kernel.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com
Cc: Will Deacon <will@kernel.org>,
	stable@vger.kernel.org,
	Mark Rutland <mark.rutland@arm.com>
Subject: Re: [PATCH] arm64: Fix kernel address detection of __is_lm_address()
Date: Wed, 27 Jan 2021 13:09:54 +0000
Message-Id: <161175296410.16506.3810718723675940477.b4-ty@arm.com>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210126134056.45747-1-vincenzo.frascino@arm.com>
References: <20210126134056.45747-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, 26 Jan 2021 13:40:56 +0000, Vincenzo Frascino wrote:
> Currently, the __is_lm_address() check just masks out the top 12 bits
> of the address, but if they are 0, it still yields a true result.
> This has as a side effect that virt_addr_valid() returns true even for
> invalid virtual addresses (e.g. 0x0).
> 
> Fix the detection checking that it's actually a kernel address starting
> at PAGE_OFFSET.

Applied to arm64 (for-next/fixes), thanks!

[1/1] arm64: Fix kernel address detection of __is_lm_address()
      https://git.kernel.org/arm64/c/519ea6f1c82f

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/161175296410.16506.3810718723675940477.b4-ty%40arm.com.
