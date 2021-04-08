Return-Path: <kasan-dev+bncBDDL3KWR4EBRBOUJXWBQMGQEROJWYJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A210358BD5
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 20:00:28 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id m189sf804085oib.20
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 11:00:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617904827; cv=pass;
        d=google.com; s=arc-20160816;
        b=xEd6n7pZO2Il28++pqh1r9WXbm2iAef286bR1fVhF/KLftDqDxEOtpt6RueBkGzlxO
         xb1+5nDNbRsYq9zZ36Iv3Du6B8PtB5MuFiRjnjb14cqT9I0VAiDtdA9bpE8ksBTBLYxw
         TZ5JAMmQ8OF+lPvrJYkHUmVFDB7wSV17ECjl6v5+8F/TqESw9/wWXSgQ/m2L3FUwQxOq
         RdPtAK6jOV9vNa0xKkA1RTDvqCxlX4by2Bja/oZy3ASVcoetNG9Jv/F+tTp8GSp14QaM
         qxdf49UYeJCx6qozi4oMSN+7ImUB9+OxmYDMbPeofQWJHM1Ly/i+MrdlJ74k0/duRynK
         gFVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qfFWgy8FaozciftgBVGWEDUZsFHGrOlTt/Nnz4EPIYU=;
        b=DTKe6cSj0ClvOI/ZLgeCbOKbF7qRPM7Pr7N8jWAelRLhMrbQiJerBjXLXiUSYrQkeA
         YFMyCzFKguVLK5CEK61jebFVolR3fSHz1Nv8NVztYiYcEdYB8xMViVIyMVUan6Chuiqo
         egGBjgoutBzSwGhuuRi7boqwfzXHU0LQVi5GduqQJnhhAT9uM5N3MTkaB56kvHo7qPPv
         Ha5UufzSEB7EA8CPdTtdImyPOK3K7PD4hoOiHiM0lyyxR/I2Z8Le00/r6ucMy3W2cMAI
         oRxGsKZHNlST53bKlirQf9c0jKwo31370Z7CunLGrCFonnOaLup36xWb2Hz4L3gHFY0d
         clLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qfFWgy8FaozciftgBVGWEDUZsFHGrOlTt/Nnz4EPIYU=;
        b=qddyTySFirNlst/bpnPRS35YFPwsE6Bsmt2uzaT22Rr5KJbIzTrgFDnDtEZzfMh0qs
         gG6PfWNKsJT6GHM+lWEFDNPGJSWETqQiLQDojzYilCTh0+Wshs7sRbwmZYWZUcxL7Cnh
         q0OktMqeMPBlGb7qc679Xfo6b4c7EBJOs7dzddd15s19ZWf58kPu77wtNOob3PYacLLK
         zJoyijlDrRuvYM/9qX1c5R96uVRKYNgDWZbSXxpfsqlaDkm4GGmcymm32jVs6C8zsZ4w
         uVFehGZ+pi4QmRWkF1vufKZCHYlzjnfOOoT7C+rB2ZtJeZNjoQChwXUJH7OpVLkA2uck
         eS/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qfFWgy8FaozciftgBVGWEDUZsFHGrOlTt/Nnz4EPIYU=;
        b=c/tASojHtgzs6jQQIexlCnu4zbI8Vw+uJxk/X6yptdt36FyyNAAIHe/F9I7UnhKN9X
         1TRNNzMoDRHUDOGHNHPjolloWFo2A5ifhFMtRh4o7TJPpnANFP1e1Jy3qohtLZkfDBbr
         jxnXedk8/0LaaRQ0S2wMDVP7bYGBCeQu9ltX+h/k0eaGbcDP1H5UpAyVteO917oUNf3x
         EAsMi8uMoKFOh/yP6/6Njd2G/Lwesd/V22/IP4QnkO7hXTh9KDFTcuXgMR9+tpGiTpTQ
         i3lolFdPDFi7XRniI9tRUpSXd+3o5gNlwvqVXtUnJPamLA2q54ZYR70fMEHQsgIQOgzS
         VPXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533yQWec65qU4DS661irjd/bds6kNELQjzUl2jmNI82eRuj3ida6
	0Fk1tLL0PPvoFtFJaZwxV/4=
X-Google-Smtp-Source: ABdhPJzsWjiCsQlvUvWySpcM0CEbf/hlwoqwQA45GyBhDyfYffnsKx61hfByOpBwiOgpNm/kSbNOew==
X-Received: by 2002:a54:409a:: with SMTP id i26mr7077149oii.41.1617904826930;
        Thu, 08 Apr 2021 11:00:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:95c7:: with SMTP id p7ls388454ooi.0.gmail; Thu, 08 Apr
 2021 11:00:25 -0700 (PDT)
X-Received: by 2002:a4a:304a:: with SMTP id z10mr8638321ooz.26.1617904825201;
        Thu, 08 Apr 2021 11:00:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617904825; cv=none;
        d=google.com; s=arc-20160816;
        b=O8GYuJOiPi5iUgz37rPMfhCw+z07d48hXFSN5RaiOR/HLBEDCUNalT27mFA0jAkqoE
         7oy1cCDj7ULiht9moElwVMNGZen/KZ1GP2iKdIpTNTDljqTVkrnLRjZukwTmICMlCf7N
         sUQVf04EjOPLGH0T0tqdmPAb6LPPkOXpEIsL/nWRlABy8ZN64j7Bo34vP23XIPFzTTjX
         4W7bw2bSmnNRiqoPb+JjGXUXq/q5qqAk4qjoXSekEoWh3mPCgokUdnswDPi8hOygtEcv
         10VyK5dj/p58DR8ybyMCQ55B+hD/C1bi+1tIGxy2PSCoy7YVz7Oeg7TeRJbfMhtqSM7I
         RgXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=q+95Sqr1L9TWZz2QGJV4MwPUlxnHtrFoKqf0U9Q/DTo=;
        b=pyX6tX6ogtD4CUu5OTXY3897ZpG116RWXkLYcoNaXHk3+dR1mqbkCCX3EBG0Rml6YP
         0e+FgXbWsEP/6xaNJP16Zny4guvbAk8L4BwqsO8fDPULvn140uog3k4EREu2nkjNJpEC
         RP4VC4rO7Kj3o4hJzIaboe9owVVEqiQsYG7575nP9og/76ACY7xrxZ90lvXio7rkW45s
         3Kmx9FyU7y1poIsFRT1uwj9wkIpk2t2eWsX+6KFc7VhMdAfv2ffmt6ywpIeNgZMy4sqS
         s73dqXSZq7EQJ8kzLm0uNuuogDmbUXDJjUmdfOvFuYRz547/kTOP3muE4S/UTKeGw5HG
         GOEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a4si4131oiw.5.2021.04.08.11.00.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Apr 2021 11:00:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 25CB3610C8;
	Thu,  8 Apr 2021 18:00:23 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com
Cc: Will Deacon <will@kernel.org>,
	Derrick McKee <derrick.mckee@gmail.com>
Subject: Re: [PATCH] arm64: mte: Remove unused mte_assign_mem_tag_range()
Date: Thu,  8 Apr 2021 19:00:21 +0100
Message-Id: <161790479237.12189.16889750597145288261.b4-ty@arm.com>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210407133817.23053-1-vincenzo.frascino@arm.com>
References: <20210407133817.23053-1-vincenzo.frascino@arm.com>
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

On Wed, 7 Apr 2021 14:38:17 +0100, Vincenzo Frascino wrote:
> mte_assign_mem_tag_range() was added in commit 85f49cae4dfc
> ("arm64: mte: add in-kernel MTE helpers") in 5.11 but moved out of
> mte.S by commit 2cb34276427a ("arm64: kasan: simplify and inline
> MTE functions") in 5.12 and renamed to mte_set_mem_tag_range().
> 2cb34276427a did not delete the old function prototypes in mte.h.
> 
> Remove the unused prototype from mte.h.

Applied to arm64 (for-next/misc), thanks!

[1/1] arm64: mte: Remove unused mte_assign_mem_tag_range()
      https://git.kernel.org/arm64/c/df652a16a657

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/161790479237.12189.16889750597145288261.b4-ty%40arm.com.
