Return-Path: <kasan-dev+bncBDAZZCVNSYPBBUW256AAMGQEENFIOSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id E6A8830F35E
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 13:49:23 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id b20sf1990158pjh.8
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 04:49:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612442962; cv=pass;
        d=google.com; s=arc-20160816;
        b=qyXcLHpHy1Ytb6jRZpWZyWNm+Omx0bLVzGCB9YNnLPmFola9nnXD2+TKQsa8ClrxBu
         PYTfQWOIlLvZ0c84GLjBKsDS91GzV7rKKTKFsBNxoWs1KZyw5s2H8FmFwOgTbVvRKxWC
         nMuLqXW7xibQ687LSbSaW39Cd/xK/e2S0vBHOaY5DSxZeLGyPL3oxIl5GEZNtByUntAF
         ytneUlWUVnkfRhi/cAEWts7SC7gRIntFFUOjeBYipWxfzGdJWUKjQpDr+DdmuiDWjC9X
         1gxf5y0MIYhCWQSX0NBuZcKCVT09suxZmHd1fjFJlrI3+eQOIrcw1BJFKCbMSAxtclU/
         L7og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=kdBm7y+gCEabSWDDY7p9oKVgnq4Vov0cmZLCaM07PAQ=;
        b=Q+mr1mTxYSUk9SFbZEIzRu5xa7fso0lXkuURDB3R8gaKS1UFUyxQPkWnAxhc2tfevw
         Ni5Ep8YMx5Qwtv9O50aqk5zbbXR0ZdX+f66nUj/JQjbnTbScL5bvEJTDjMMYAu9SJjl9
         8MMr2nA+TEJ201fooXdnTAJ/K7YawIDUv/aXFdBe6laSzyo8uq8V92qrxpmo9y/XlKg+
         Nc0DUIxkJPh10o1UuL6jT4Xro0pp+pY0YXyk7Nt8fbbKsOmEKLFUAfVi0kRDMbvlEsTI
         e7UnyrcKONL8/PDpLevPpG20TeggYtcFu0rkuBT4yoI3rXZ3HSJq1qyM6oob8tn6spfv
         H9iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=U5ESek0o;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kdBm7y+gCEabSWDDY7p9oKVgnq4Vov0cmZLCaM07PAQ=;
        b=pHYPAcibhhB2UOEzvNHjtoNVrZ5qiCZtU1W7pR9C4udNF0K3O9FmS4HZwwiKGF++y5
         RDA5Uju1M2PrYMUiEDX5hAn0JXa/2EOVRwRddOFXax+ycNSr/chn7P7NVdCm2PL6//Xl
         fM0ccsZLanT4FbTgyvJZVHtAIb+YIZiVojKlums7Y2NVU0uNR7uDkkY3CYykE2xBgumu
         oyAaaZp28GUkP7RScCIm5JFQA54I1LJ2VvCzJdolUIR9VNvAWrBsnSqw6ZcQta7TW+BO
         mL3sjgBZUnybqV8YZxlKomAu/9C8M/qo8GZ5J2Pgjq6ivVKfHGQPx6qmcIH0NQnM1E+E
         9aUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kdBm7y+gCEabSWDDY7p9oKVgnq4Vov0cmZLCaM07PAQ=;
        b=JN7xiyBl9fc3chswZn96hI0KYTB2A5a38Cs3Yg2IZHA241sGxUQoHsYmfSaah1k7+W
         YVI6G7kv6aB6mlUF6EID06qkbPBs7PmFEr0bnsgCeZR35xHwwtMsfoEWKfnX5OjcOfjS
         Aj8774y5AhOYX/39i8qx+WS7XAoCttxrbKwPcH8gs56/7XyJtaILLLjKnHiPvpNvN8wM
         RabcrqxVchoommh9o0+ZsCWEcYVyR6uy4pjKf9yqrtloKIido7dLdMv2Z3zluav5ELqY
         gxzEEOq0ibdxSFcbuymvstLC2089lTvARSp7nQHXkCRtIyO+vT3fRQ6iLqNSvCQA9xTa
         7WXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530FRCPD0/c2X1Xd/CSJvhwIYufKl85oShKcOMSrn+qhxKU7Q4Km
	I0eGIYSupHb/AflNBvAsykA=
X-Google-Smtp-Source: ABdhPJwt28GbGEFuTy6ljf7/3tJ/sBvfvI8fy5Sx9NoiYIRaFA2uHXdBrDKYGwrRNYREdBWeX7lSdw==
X-Received: by 2002:a63:1f54:: with SMTP id q20mr8780061pgm.135.1612442962540;
        Thu, 04 Feb 2021 04:49:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ce54:: with SMTP id r20ls2334093pgi.2.gmail; Thu, 04 Feb
 2021 04:49:22 -0800 (PST)
X-Received: by 2002:a63:7e10:: with SMTP id z16mr8919727pgc.263.1612442961942;
        Thu, 04 Feb 2021 04:49:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612442961; cv=none;
        d=google.com; s=arc-20160816;
        b=Y/5DgCRRrzBEX3q7qdd/3sQrdYzVLJwe8ZEv34ew0HImWrajSMJkCZ4nbdC+sTZdvz
         SBJmiwEVDZ0UnUhCky/fZs+aS/cmo9JunbHj0GH/tG/HC6QrU5Bv3Jt4ga5mUeeCy5Gg
         haoVhKG4UOWO+fJ8QMIxTV46HOcWt3dhNA0sqvrgNRhOQoMW/L9iV8jUrEUKZNA17LZO
         Gx2ioSN7ICwyQ+zNPqj9xkz3NBcD0WRdBHIOhM0kgxdgQuiNHG/xXZsPyqtDErSvTl4Y
         C8PdkY/vuz8cdTPb/rW+AdByqrksDY7WBQ0eCd6RD6od5YbpKh4cgHnzljjvwzrk8tg4
         gg7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tE2kdj1G7/MnDDuFpGpQtwBZofhJySV/dm+VhfoyuL4=;
        b=kNswIbQPneOBL7wDCNlCzaAInfFBBnSQ9yWsCINXDFPrQKifglWTDw6nDIXGHlmDhy
         oJEtuNlp/PGbgol7GdaWM9NRgqwqU1lsqutpXbglO0u4KJGt0zq8RGcyeY/LUzuHfWsp
         NJf/OjYwJtQei0U2WID8xJfpzmHxYDUvnVnCTV/PlDO/UXBbBVw6Iv9YN+lkvDfInRFx
         /LppBdI/5h5FQJdvMbAO+BWSkaniaUAMu1b8wpz9GuWkg9H63XfGWBQ1RjpyBzA5QtSG
         RLLuvSckhBiGcxIIDOS6aolyFa0dZzYWXmqsDdPtatKIiDaKit09b9SJP+RZKAi8h3IG
         JVXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=U5ESek0o;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o14si326549pgm.3.2021.02.04.04.49.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Feb 2021 04:49:21 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 11F4464DF8;
	Thu,  4 Feb 2021 12:49:17 +0000 (UTC)
Date: Thu, 4 Feb 2021 12:49:14 +0000
From: Will Deacon <will@kernel.org>
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	dan.j.williams@intel.com, aryabinin@virtuozzo.com,
	glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org, yj.chiang@mediatek.com,
	catalin.marinas@arm.com, ardb@kernel.org, andreyknvl@google.com,
	broonie@kernel.org, linux@roeck-us.net, rppt@kernel.org,
	tyhicks@linux.microsoft.com, robin.murphy@arm.com,
	vincenzo.frascino@arm.com, gustavoars@kernel.org,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: Re: [PATCH v2 0/4] arm64: kasan: support CONFIG_KASAN_VMALLOC
Message-ID: <20210204124914.GC20468@willie-the-truck>
References: <20210109103252.812517-1-lecopzer@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210109103252.812517-1-lecopzer@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=U5ESek0o;       spf=pass
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

On Sat, Jan 09, 2021 at 06:32:48PM +0800, Lecopzer Chen wrote:
> Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> ("kasan: support backing vmalloc space with real shadow memory")
> 
> Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> by not to populate the vmalloc area except for kimg address.

The one thing I've failed to grok from your series is how you deal with
vmalloc allocations where the shadow overlaps with the shadow which has
already been allocated for the kernel image. Please can you explain?

Thanks,

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204124914.GC20468%40willie-the-truck.
