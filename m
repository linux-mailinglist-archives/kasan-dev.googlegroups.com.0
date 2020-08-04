Return-Path: <kasan-dev+bncBDDL3KWR4EBRB46AUX4QKGQEU5TMICI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AC8923BAFF
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 15:19:48 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id f13sf2191457ooo.13
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 06:19:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596547187; cv=pass;
        d=google.com; s=arc-20160816;
        b=Keu41moH+7y3pN5FoSrBSavhneQC0WzZhMMPEmuWS0Q9Ae1TXhhRfXuBGAXR/eQr5j
         yNRzocESvRjl3+E/wfPTKx/PImvChlzoQXVcJzMgr4E2ENu8Yeirg77z8KpKdpRLFNIX
         AvXw7coFsl/P7zzsqTDE9F1yCCXnjzNZ1BBhaoM9bUMmUZL8OxOW4P3tgugenncYMzJt
         NVwaLjAvEJqjcTAgsKSGNDhoSKHomeswVOqEyeJ4LAtdP39S6MP04d3iBL7NXR/OdYDn
         lHR2DZ/2c+8IsS2FNcdb+4YwXLJj0k3mehf60CNDRO5AlF/Sp1EVIji79NQOG0zcnuy3
         BBtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=CPOBxfxoaxNsNBSHqzJfiFPekVwfaVQ9c2cytavyCIY=;
        b=0I7ikF3B0r9bE7mKKfkBsN/Vcx+BSBR8z8vfETgH0zKg9grC4z9SU+MA8IyQRVkHVZ
         LKyTsiwP1fYvN+utpG3R5TH6gxcBdONVIARK6aLsdPh56dxldDbaw2GpLhMZkNvyMRB/
         YEuwKNpCPV1tzPN5h877oARoeCnn5xDxxXyVn4hjcdTb+mcR74jTuNcLW3THnafWLWe0
         9cKJ8TcEIW2HltDCB/QtqzmJdAWfInHaBiTRn8cOkmUG2LunB4l6s+3QOin8XJpcENG9
         YyblHW7xmsxM0VmsugX0whfcM8zRQoGEiCRsMiRMqQC8UhcXgzRTpTG9Cu91n2fEMQUn
         ZiPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CPOBxfxoaxNsNBSHqzJfiFPekVwfaVQ9c2cytavyCIY=;
        b=YblMIwnHfsJ8/gWW7qignUvNsGiHJg/oeQ8bPjCzz9My7RKh9Q+0lIuNfOyvWYc5OY
         AT8gssH5GK/dg96zOvGyVnp+otFcLhKuQrpsGn403ZKXQ8IBdcfzHGm2mAr+tlm1gaBB
         asWli3jpVOnkvBDdHjyKXC30EFj1L4JWTP+N022G9blNY2pob54sH+h4ZoBot2nE35ci
         IzgXINSS7svt4iEoS4F6oAGDedvAWOtTTiB+o/uLGNIkRxYtzwQBaAfJiF2p35KVa0gZ
         WruiShwjSeYQ/KiYU9QU5XwJeKeltY1L5JNmuYhLb7DKaBbGYudhl2ARC3ODs8H68/w7
         UYFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CPOBxfxoaxNsNBSHqzJfiFPekVwfaVQ9c2cytavyCIY=;
        b=pOM6ttk+4sKPLnd4t61tiDmQrOFmhGcAoPhTTNRjgB7O5gfLy0SGVcQ4Eu/g+BwbfN
         +41FNxMBfOGKsC8PDP+FZiQUwCPkQ0ejyS9AAPGJcYzQKTe3hOlnPjeQ6zg8eBT+oPgJ
         3cINLBCu7Cj8zFILWc1NPZGN7D5l2sIeJ4+B+n0S8MpBZgqYO1jPCbZMmdqcxX6liMdK
         wFdRzsktDfUEgWpredxob5T7SXyuRYG7dCzstimgSSVfjiD5dM38mgcx3VDgpC/KjCyl
         nREyD1Gl1bo8vSHRX8Bi7HRCFfawPgbDM57GB6tdNXafn8zd4SXm+blzGc73MdPZSUh9
         FpBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZaryCPDv6zyyigej+HQ942YFtGo4iC+uN5tMj9TGmT1c9h3mo
	uG87+MsdQTSqufJYIpiPupA=
X-Google-Smtp-Source: ABdhPJwSKWssCj/fJiZoeNOqreLEBYTGGkVIpe1Mr6jLcNVsrszuBVwSzZ9fEilZJMJ/glTQJb4kZw==
X-Received: by 2002:aca:eb84:: with SMTP id j126mr3355513oih.30.1596547187209;
        Tue, 04 Aug 2020 06:19:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5911:: with SMTP id t17ls2495639oth.4.gmail; Tue, 04 Aug
 2020 06:19:46 -0700 (PDT)
X-Received: by 2002:a9d:53c1:: with SMTP id i1mr18501038oth.161.1596547186719;
        Tue, 04 Aug 2020 06:19:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596547186; cv=none;
        d=google.com; s=arc-20160816;
        b=QIX2ETyibnl8I35E5aI6pugq3Bf56906SCzxjOcwymqAwGsU3Chld+p9UpMFwfL3jV
         WzI4kAVvCxSrboJKDrwa1hW76J6IIZgR9hweIrqFt0sg/ehTNNQPIxjFbxLwUZ6pZlEi
         wXaBe0eVoeTZs9YtRzLVcIIur9wg+kosUfPUsg6cPhpjh/GOAvTeuEDuAcie53l3UAZH
         aotNKnxpyXC8zv8b7F7SsOQkvCFkW1Lw2MKGRI7IJXs5/Mj7QX5cNIxNu24QBtOJGIaI
         Vv3HnFUf6/qYjsI+28k4552b0M7LSX3n43CYzgcGML/RstkyIZZmgnU4KHPLZxdCqB+I
         CIcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=j8IfHd9kKmzHNx479U3UD7cT6DAoCV1Fc/Ns+egb1pc=;
        b=L9JUzpTFPhnzpeLILvMQ8QnY2QtyW77ROPJ58GiCg5JAtw8ZTLnFAV6W9ngkY1J9aj
         K5vJflZRKhb8IgHEv3lKXo0z1TDf1JNcgPFkPMIvDqjt0e8Mzz5Bx+cDQLkj+w4CkQC4
         Jo5/zJTbmILuBb1l0gF/kX6GghAGPorg8QIzvWaoIbl0hsqb63Kjslb6X4QBJ+0sawmT
         ESSkas+cA8b1Rd+QGAfyhJdxYOINqO9ttt2cmFrExgV8QXkeQ+osnjBKMiguanPauxQM
         GY2kYzJz+VVF+fkBta7iWJI7XUFr/Gk9xN1GJxbiiCq6atdIGZDKMaykrAVftqHi+ohj
         OYKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i19si1118940oie.3.2020.08.04.06.19.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 04 Aug 2020 06:19:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [95.146.230.158])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id AF763207FC;
	Tue,  4 Aug 2020 13:19:43 +0000 (UTC)
Date: Tue, 4 Aug 2020 14:19:41 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arvind Sankar <nivedita@alum.mit.edu>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-efi@vger.kernel.org,
	linux-kernel@vger.kernel.org, Walter Wu <walter-zh.wu@mediatek.com>,
	Elena Petrova <lenaptr@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Subject: Re: [PATCH v2 3/5] kasan, arm64: don't instrument functions that
 enable kasan
Message-ID: <20200804131939.GC31076@gaia>
References: <cover.1596544734.git.andreyknvl@google.com>
 <26fb6165a17abcf61222eda5184c030fb6b133d1.1596544734.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <26fb6165a17abcf61222eda5184c030fb6b133d1.1596544734.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Aug 04, 2020 at 02:41:26PM +0200, Andrey Konovalov wrote:
> This patch prepares Software Tag-Based KASAN for stack tagging support.
> 
> With stack tagging enabled, KASAN tags stack variable in each function
> in its prologue. In start_kernel() stack variables get tagged before KASAN
> is enabled via setup_arch()->kasan_init(). As the result the tags for
> start_kernel()'s stack variables end up in the temporary shadow memory.
> Later when KASAN gets enabled, switched to normal shadow, and starts
> checking tags, this leads to false-positive reports, as proper tags are
> missing in normal shadow.
> 
> Disable KASAN instrumentation for start_kernel(). Also disable it for
> arm64's setup_arch() as a precaution (it doesn't have any stack variables
> right now).
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

I thought I acked this already. Either way:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200804131939.GC31076%40gaia.
