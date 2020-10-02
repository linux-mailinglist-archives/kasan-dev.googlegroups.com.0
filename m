Return-Path: <kasan-dev+bncBDDL3KWR4EBRBSXA3T5QKGQEDG5TBBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C3C31281477
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 15:51:07 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d198sf1190739pfd.15
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 06:51:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601646666; cv=pass;
        d=google.com; s=arc-20160816;
        b=EWALc0ZzjPmkOVf+sOayU2L0o2Q7byoqLKGnpuelAv3Cq9Uf4Ahq5MLEVJH9OFb32D
         +UAjU3eo9ZWLjoiByq0YVPodZR3jDMWjFBrCy4iwXi0AzPEwf1/4U2wN+Us1PMDEYl3i
         Ihxt7loDV5UpfjPTN/AOv8p6wHm2dRH4XV8K7rWbQrFqMyNHW8Vw8w8eObMdYCdKEN5+
         IRuuAP5oWg93fEE92ehCbotfVnrSExCZLLXrE2eVxcwfXt6l08cQ6eNhWSxAUZzHYVIc
         82dCCWhya05Q6mBfeDJRs9iuS4Xnkb5MPyxsNi/jXg/Zq3FUwX/o6gBEKWCFyYMUO5Si
         R3jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=XgMcDsjA6wtGftqdVVafCugsXfD06nfFKNl/kmkHajI=;
        b=zw5/7yhBagtVSEHV0GcArWj+5EaifISJxS4Vk0o4E6z96R2kKaiHppBfg+2frBR/XY
         hkyt47LyGQFnkIou8jLZQtCT/mcM181GbdIGKHe15eG0DPM8ikcdCSEwJWaSqsZaWQlD
         CUL5+E7wcG65TSeaobh+bcJB6kcZGQPFbrn3oVRB+yeGcy+BvtTgcAjbVq8VMaJPg/f1
         eQhUs0X6+7N8JZEbpwG7Pa+nTPHRmYCbaO/0J2S+3ygAfygfMQXjrGLTw8JPFlkalsvw
         cpIxmMooficFhR5AgKDRdWIn3hf7hGXBPVwcrdFyrdK4JsGyT4Nwovfyx165sfXvCP8i
         AmzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XgMcDsjA6wtGftqdVVafCugsXfD06nfFKNl/kmkHajI=;
        b=jz46Unanr9wp5KBwrY7k+tqs1mEtutda/PcDxSTlmb4/S6/0CLf9M0/eZiStQoed6X
         uULt+1R3Qk6m1/XhKBbNiawkspaG2QuP73EfMlRXp0B2AGy/KDfx5YTd2cCQVw+TgzbC
         hgH7Wipp4Jw+lm4W8GappsvZWt5TBNbQ1QZftmvHR1iFyLA+5mUtLXq7n1/jhIDkvnlG
         m0J3URoQEv5+UIKeBj3WCXGs50M2/agxHCGpqWr9kWZZvaDeQhOTNqB5TZYXpsKoHHNe
         RpIJVUCEYa/HswuGbgmx9TJgfFVQAjmXf+wWkAaSqFnvlMPFF2ZAWUqlMrRexzTSWgGe
         ccsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XgMcDsjA6wtGftqdVVafCugsXfD06nfFKNl/kmkHajI=;
        b=TeK4qMLLd2vX1+HyraWYtnhzbN3Z5v0EfQvaSZy9RnFJD53CliPZT6Twi5Ba+mzIkf
         1lgfh1N3n2zX48AA9EKHHoGXcpdyOI9h9Z1Jp+V0Slrgww+bNaBJD7njS+bdj1uKZeFV
         F74ky9CseF0bzn+v4QHr0BQTYnUiGq2yNKqJ6WEC9cU8V0pRawT0X94SjA64NXseSEaN
         Pl6a05usJpAceZ2cq3Lz8Ilh1t7V91aCdkTaHzoA/vTnerygfecXIyl8j3GTBJ0iCA8I
         hojkX7k7AXpXIlSoVHjfqLN1qStYriES+/LsV60fx663Y8MSouD6fYLaPpdd1D4E76WE
         Z1AQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530s4+HynwaqX4FtkB4rWLl/O1HGkJooocvBWYSB4QB10aOcA/5/
	n5mxOzNU4HkVPEPfu4dVW9Y=
X-Google-Smtp-Source: ABdhPJyr6+hhL6H60SI2832CvZXpaoUbVhfjKXo1qp+A4cUy9EOd0cJ69l0SJTJNOpczd0Vz56jPBw==
X-Received: by 2002:a17:90a:67cb:: with SMTP id g11mr2930614pjm.56.1601646666535;
        Fri, 02 Oct 2020 06:51:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4006:: with SMTP id f6ls731491pgp.10.gmail; Fri, 02 Oct
 2020 06:51:05 -0700 (PDT)
X-Received: by 2002:aa7:8b4f:0:b029:142:2501:35e9 with SMTP id i15-20020aa78b4f0000b0290142250135e9mr2997790pfd.73.1601646665747;
        Fri, 02 Oct 2020 06:51:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601646665; cv=none;
        d=google.com; s=arc-20160816;
        b=hPCC1AT8NEpnWszlYrHlDKmfp88O65+AYwPbydSJAV18XPBQjWUSJXjGJRtKaZVrOD
         3EgNENxqQZ1m2E/Im213+YBxK4k/McTMmsHoL8pM4EXE0l9F3veXtM0iTShbBEBIIrbY
         4Dzq6XuKSIeGac/F0yY63U9dBj8R6Cx0PspV/tTZCJUS0D9N2rElf6+Va5/34Ffdzvfb
         7kliDcaiqMY+KFEC4Ruttx/VNM3KY39zMeiL9aJszSY5iLnvhrFJDxTY1LnZIvPs5rIG
         bspL3X5EfcH6gMoTS4xI37+lF9q+wc7R3n70/a2TfQSJiAsTcPhfjPgRrxApeSpBVDgO
         L+iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=+VPPez786ApyfSE1CnOIGOApLDzwNevJBNbk7gbPIas=;
        b=ZHDLU0sd9cnkDftKQnzKYQGuS76wZQqO1Y1V8owDLyV4XYFp6yyQNEKjd3Mal98DSZ
         +NNzjv/LeEW85IISKCPWc4tyyudmkSAZDfLGyLQR1QUhi9WYLO/EW42ee6p4z7Fn5kw7
         OIgAqevSc3+Lz0VYUeh2GVs/u+q+LeGp+Ko3xfREeryYzU+pQi1j5yFjJakQmm0mfWjW
         F8I7XfJeDru9ZYzD7ZGY3InB8p/kFrcwOu/JAaOtsYSaczL2XA7RueGJjct+VnkrjXVs
         fIlqbu4LcKeQV38kh/DiIPneWrFV6hszIecikjkFyicwZWbtIVQ9ulj+I5ODeD4kD0eQ
         AR3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s3si110960pjk.3.2020.10.02.06.51.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 02 Oct 2020 06:51:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [95.149.105.49])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1C1D7206DB;
	Fri,  2 Oct 2020 13:51:02 +0000 (UTC)
Date: Fri, 2 Oct 2020 14:51:00 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4 24/39] arm64: mte: Add in-kernel MTE helpers
Message-ID: <20201002135100.GE7034@gaia>
References: <cover.1601593784.git.andreyknvl@google.com>
 <96d3ade8c6e050fefc597531fa2889e67ed75349.1601593784.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <96d3ade8c6e050fefc597531fa2889e67ed75349.1601593784.git.andreyknvl@google.com>
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

On Fri, Oct 02, 2020 at 01:10:25AM +0200, Andrey Konovalov wrote:
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Provide helper functions to manipulate allocation and pointer tags for
> kernel addresses.
> 
> Low-level helper functions (mte_assign_*, written in assembly) operate
> tag values from the [0x0, 0xF] range. High-level helper functions
> (mte_get/set_*) use the [0xF0, 0xFF] range to preserve compatibility
> with normal kernel pointers that have 0xFF in their top byte.
> 
> MTE_GRANULE_SIZE and related definitions are moved to mte-def.h header
> that doesn't have any dependencies and is safe to include into any
> low-level header.
> 
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201002135100.GE7034%40gaia.
