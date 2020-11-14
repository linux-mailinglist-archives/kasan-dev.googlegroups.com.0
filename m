Return-Path: <kasan-dev+bncBDDL3KWR4EBRBANEX76QKGQEOE6LVAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id EE1262B2D33
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Nov 2020 13:48:02 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id z34sf2114969pga.16
        for <lists+kasan-dev@lfdr.de>; Sat, 14 Nov 2020 04:48:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605358081; cv=pass;
        d=google.com; s=arc-20160816;
        b=KCSMVrJf8LsDLZqiaUVb6J/Egp2vg0zuHech9x0HOofyNn4OqJBLrzpNvkQQawtuf2
         n40BMXdAnzp9D2ojEMFTQRqg6lo4J535wtM4fLgZIcIclBZJm9Oy+/tjaZQQsoWDOhUG
         gScfLuJHwkMFLzRMYjkLIePUIY7S3Mc1dCiJsGYB8gQWdw5aQBz15Anhr+sBHxlp93XS
         qNRGEnJknrUrTDLT4Cel363l1PsDByMqW1PyxSpP9q2sEMERPczLvGWuQ4tZ/FD6Xsg9
         S43tz9RZss1b+JdYqlsGfc0uIFRC01tkDz4AtCoGe1pmylY81jalj7PptJ65W9rHwc66
         8KmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=kbGpOecq4PC5r1tmBWTpwthV+Vd0tGPWlqrtw+t4/ys=;
        b=XFwTjUt7jq2QX0oj8iOMOVuEDHL9pS2MtE9GD994k+om9b8FPVG6nguFYpZHGjPEYG
         RkSN0zKgNFwZIC0JkOMWUb5NIVKQSgyHDieJv8fxEvVmewjH3/a8qaGeefe+P+lpxvAZ
         /BT01t5ld/vLr3XOx8Qarx4UANWk9O4s6/k6+pM+Hh/OFAx35yYhg09R7msq60VYndNO
         UI6Vh68d1wKPL2sdFOiNSPV3sFl5tlKk6tszuBMIXdQSV6nLRN4zl+Y4HQOmiREfZXi5
         H/OsxIwRDFwz+Jrpp7M+AVqhcxDIlA6hWpzNZrOcPqhCJL7gZo8s92vO2BJxTsqSs/sD
         GhVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kbGpOecq4PC5r1tmBWTpwthV+Vd0tGPWlqrtw+t4/ys=;
        b=Qnf+pJzok1N5HRJYaZ75j4tlKRmngmIt3tRKivuIrnGKHvIqHRsdWyv83izNE5vcpk
         HsdrpMVWgpyYi8GhleRbWf5zXfqaQzl/IuCcrbYRN3MV88bwEc4WE9J3fRtAo0sWpF08
         +e58t8bDzXd1HtQ/L7naUsW4VTFpNHM4zh6GvZ+k5628CTptxdY+AUX2tkMzPYKD8A/S
         wK3ZL5W9fXI6zYbhl0+VpINenHpDftnibsv4o0o059VZLr0vmLUxsIyiuWlGkK/lQL5K
         ZJEfbwMSmERy5K77VUdYnV2vrRKLpDHP+fjyPldOO2GI0adSVYsEzdJZwW4EUcFY8FKX
         6aCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kbGpOecq4PC5r1tmBWTpwthV+Vd0tGPWlqrtw+t4/ys=;
        b=oWTfJdcJTK3V3FK2jEO6aQuI9bk4sujp/QelyXhNk6y93znHZGbkpX+7qom4R7Hsmt
         H/H3tln2p+BsMA9bjTVp3kiwFYGuYOZ+H0kXSGf0co9+wmkWJC/qOM7Cx0W3oxKs9tVu
         cJ/WbkBVFPAa/kaGWpplb+gX2Hcl5rbmYwRHVshYqmw7aIlvUQdT2pzAuzC58Mxu5dab
         sWEXbelnzspmhAmGY+bivEKDT5NQVkCNA0B1d4tvhFfznD3XeeQ0lTIG0X037jbH2D1l
         1XBEqA3k8URc/mFkTDGqOYJHTnGUFIqMSQgnqNpD9W4c4ASH3WoGGG/pBG6HpI2pgA9a
         ENkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jZNAvd2RZv22BfWijFUEMnw4ZG3YOTgXtq8lFHMrIK6+SRzFZ
	dg0LzGG+ID3aHYEFqkAcv5E=
X-Google-Smtp-Source: ABdhPJyrrhrb6jRiRHYKNKEFqrcCebM+PxPSmv6+gqAXa1za4zNPQsNLl9Pawo2FU6W2tIq+LnwOuQ==
X-Received: by 2002:a65:4483:: with SMTP id l3mr5642515pgq.96.1605358081705;
        Sat, 14 Nov 2020 04:48:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bd8d:: with SMTP id q13ls4264379pls.0.gmail; Sat, 14
 Nov 2020 04:48:01 -0800 (PST)
X-Received: by 2002:a17:90a:5906:: with SMTP id k6mr8143707pji.173.1605358081131;
        Sat, 14 Nov 2020 04:48:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605358081; cv=none;
        d=google.com; s=arc-20160816;
        b=mzWE+qrQJUvhcKIb3Rlpkn3GceyKzauRO/P9ahciIJfKV8Wroludf/9XhYYK3hRW3W
         S7/oV5xI1HBjDJjK2vVbQLOm4dA3ZZYmsAXOfSbMgYG57JKCce9EXBJiWymVvZti2hCK
         O0kmkdTdSEu33+usCOUjWDuJDFFZdJRcJ6PSYGTD6b5RSrMDupNLaLKndWHsDyoPrer6
         fWgVu2WrCTe3K78POw+fAeHrP2qLWdRYFg16PdTmsnPSPxoX66+fYsA42ZK6NIllQ4nC
         iTQjf7ZomwYEi7j84LaHsIOFhiUv/l7/EVRIUHML/2fOcM8DlzhpnrixZG0zdA4I0VwA
         Xiwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=RRZnlUL5iDro+Y08Pj657BeeXVmfKvVP4SXWMzxw9Ck=;
        b=aa1eQ3VzkhEQ9okaIqsgm+7hz09zvmWcBCeze+2L8KalXnuq3Uc6qYu6Q0u8cOlVZ0
         +HLlfSrLnbwW2C+6aMGj9qD5PCdnDvJVoTh9vxuZU4Np2sVRZ9FrQccS4zOj4l/Il48l
         FdI0gRkav3yWDktlalKuI9hcVob6ZaYPoBjuiVATRb5OA7BMas7gnJs9ac0oFnA1Fe/9
         TtPtlM86lQcP2u1Uq8HJqQINB85P1StwBmeSO/O3T2JD51SMXVCxcZFX66Dtgvn+DNg2
         rrr9TSm4k9UySSV13N9wJsrcUxAd+00cA0mNRsH8FECZHxgbEfeN/SuhXk38AAs4m5GV
         4R+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d2si889032pfr.4.2020.11.14.04.48.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 14 Nov 2020 04:48:01 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 804B82222C;
	Sat, 14 Nov 2020 12:47:58 +0000 (UTC)
Date: Sat, 14 Nov 2020 12:47:56 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm v10 28/42] arm64: kasan: Allow enabling in-kernel MTE
Message-ID: <20201114124755.GD2837@gaia>
References: <cover.1605305705.git.andreyknvl@google.com>
 <123c654a82018611d38af8c83d1e90c16558ce52.1605305705.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <123c654a82018611d38af8c83d1e90c16558ce52.1605305705.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
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

On Fri, Nov 13, 2020 at 11:15:56PM +0100, Andrey Konovalov wrote:
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
> feature and requires it to be enabled. MTE supports
> 
> This patch adds a new mte_enable_kernel() helper, that enables MTE in
> Synchronous mode in EL1 and is intended to be called from KASAN runtime
> during initialization.
> 
> The Tag Checking operation causes a synchronous data abort as
> a consequence of a tag check fault when MTE is configured in
> synchronous mode.
> 
> As part of this change enable match-all tag for EL1 to allow the
> kernel to access user pages without faulting. This is required because
> the kernel does not have knowledge of the tags set by the user in a
> page.
> 
> Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
> similar way as TCF0 affects EL0.
> 
> MTE that is built on top of the Top Byte Ignore (TBI) feature hence we
> enable it as part of this patch as well.
> 
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201114124755.GD2837%40gaia.
