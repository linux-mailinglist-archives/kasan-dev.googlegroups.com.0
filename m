Return-Path: <kasan-dev+bncBD4NDKWHQYDRBFUIQGWQMGQEIOV2SOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 2227082B544
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 20:40:08 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1d45ddf3f58sf51543795ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 11:40:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705002006; cv=pass;
        d=google.com; s=arc-20160816;
        b=zJjW7r33QnKQ/FeBs9PpyMELgX8SJ5vDhHMI3nCyHklJDgTNvrt8HxrsQvKLhhVM6H
         zm4KsbX6En/ERUtuqSX0mgkXLI49y2G2NnX72Q9GqqlldzU/LytaRuib87wcWdpzdoDL
         KJgj7kovPrAhPbyMOdXCy9mb4QvUMfx3T9L31RgHLQ6uPC0IXo1t4xmGlSp/PNl5x/rm
         v9e8faz4m58XLIdeSyIuKBZwviFaEPHh4+kjy0A0IIbEM6sFJ8mJ2n2stzxzlo+aiZXt
         VBWdqcs1smUUebp7jAKl8m1Y/XUALa4sugpTk0+FPc2yn3eC5sviYrP/Prfseh8nLrgq
         RUUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=iHXcVl+jj6maXBRkFFLP0t9OA4W78evmwBufN11nnPw=;
        fh=yZJprR9knx02hZVZC51uBBQnXo9wgyDZ8RtR+dxDSwI=;
        b=emwO925gbxhNg18WqjBulZn7NxdJf86AIzFpDLBU2Yu4iGnNuuAdiCzV5n6zrKkCU5
         QWKzMhzV3YN28gxAzDNVWuclYB65/GdUaUYT3sKzzn6gOSaWhTb8e3TMhK1PBuPq90K0
         nkh0X7qIeH2D5GXYDiop64VEHn3rwPJRdti+BjvGCQFd0Bk5D+7KYKRHtMhcNJg1jyDJ
         9cU8tqEoTDX86OEn6WnyMkdxIhoStzg+E6L9v5d04kwNOwzyRgt7lsoch7syqG+H6qlG
         Yh8aNcFq5koyQ8rK1YsDta3rewjbOlR0l9OMTcn6W26tc7Xb6hXI0oWx+BYLMUG3j/aR
         Ya5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SPPtBjPT;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705002006; x=1705606806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iHXcVl+jj6maXBRkFFLP0t9OA4W78evmwBufN11nnPw=;
        b=lS4BVR8ZhQKmB6FGu2ketRWyOShYhwec9c3o2D7HsH022RoAJY6mXWmjRK1GDJFLJX
         ufh8vRGaToQZu0OtcdyYOy0r6PRtbxd8dbQk0iQ0fXoqggUV+SImMcJoakzCSMLuAj6B
         reJjY2NaiGFjoOgPJ2cbWXPZdjDZA+7B3Ae505LqzXGkShfT0JficziV/ZsamklSQinS
         PW44jo/1zdg/lLuMCKLD/gzC/BuMUGE3I84YybIYUmYnp+KqZ/Q0pK1EEyFNOMqVUZDB
         2axwc1a/YCeU36eJTTYwrGW0zY8E8meIrbAi55cLl/G3qIwLI3LMfNxx4MJVAx3KkBAP
         lrHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705002006; x=1705606806;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iHXcVl+jj6maXBRkFFLP0t9OA4W78evmwBufN11nnPw=;
        b=Pz3TnXefulY7PUR67/9AoObBPFbF8z4gfMcyLCiYdi703gSyJEbS7kjd+zhHqemlgx
         lGMggrB0D9j8E4PhNa3Lwpwetx1V4myFegrBO1eaHRNSp62adulP2/3MPOR8hNHlRUEm
         hft+zqFiWCEaSQdmbnalxAZtP16Ybmo+2uhql0U4pXZqPkWeSWbu+IWhRUtcp60k/2pW
         Yzos3P+2D9K4FQGhmnqtcKKmcIq7gg8iDwFmV44fsufv54/kPV280/WZ3X9XQLm+elC7
         eyv7cTST3ofktNt0IsQET8ZHJXIKq6iROc9BumokbjEXabefvOz4dzxNy3vO8HLLs7TW
         Q14w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwmvAbLuJrHFRC+ZR+hU0Lk8PlO/UDPjWyqwegawuAW4/urEmXi
	e5LFaO+9SHV8WOpeszJx1rY=
X-Google-Smtp-Source: AGHT+IGJunuf0b25os5lggghufwJ/eQF+bF5tBKgLp5NoEXnYry7JctNeZdu86au5BURKqUyy1S7GQ==
X-Received: by 2002:a17:902:654e:b0:1d4:bb7a:4b6a with SMTP id d14-20020a170902654e00b001d4bb7a4b6amr209605pln.6.1705002006392;
        Thu, 11 Jan 2024 11:40:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:860b:b0:1d4:bee6:f8d5 with SMTP id
 f11-20020a170902860b00b001d4bee6f8d5ls3156577plo.2.-pod-prod-08-us; Thu, 11
 Jan 2024 11:40:05 -0800 (PST)
X-Received: by 2002:a05:6a20:914c:b0:19a:5adf:9208 with SMTP id x12-20020a056a20914c00b0019a5adf9208mr417052pzc.104.1705002005340;
        Thu, 11 Jan 2024 11:40:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705002005; cv=none;
        d=google.com; s=arc-20160816;
        b=iAYEqWBCguhsmmJNcnGS83TTjb5S2CjpK7j26alz/D39TV/uojQ/5cb74h4vCO47Xx
         NVwKEcgJlfe2HJNmJ9xqVHlhLS52QUbZVu6A6YOYS2KIQnNwLlTjXjukMldK+t9l+v8P
         MaOMpmcxP23vTYf/IlSTmGH3lSmvlAzI5t5GYKjUMoYqxzDl+QJvCaef4vJmtq8sfGpz
         U8M2nmvcnpzkkgmbYQ4IhWalQ1q6FjjoVyzxHYae+LBKYKsGi8U1iOht3vrbWuwXdshf
         C+S/62bKxmrJRFOfN/2rcovQ95cNtbUTn5ohqBUJbKcdoq7tPvT1Saban4IgQDVE9A0l
         sYhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=C3hlMFdn+OQb4M9O1Nzy0ZVGgF9XSI1qalBPvQ9f1+o=;
        fh=yZJprR9knx02hZVZC51uBBQnXo9wgyDZ8RtR+dxDSwI=;
        b=zeBTZm2wpwMssWmCA0KEe+Hszk1wXzuYKdm0M5q08TDMOF3C/5KT5+xuUpvOxkHLeg
         cXdfVhMjD3KI4009FyfRVe24800v7ZbUyEq5t0jRqRS1Kc+UEJbMYHaigiPk++vBQoYS
         QB2oLHzNAgrWPSYdTBZH/742IDDJtH7SUYn8BhHlvvUZqARzUFCjtlIqaZVRAi5ns3IO
         kB7ZpfjZWaBXlvYkd+oMzzI8czfip08d6k5Lw3/Qx79zJOXrMO6Ik4jnt/yfI5v7nKyj
         Lhany1Low+J6ifNyUbawH5de3jCeCTR2wnkLMkv5uNgoxtgo6I1oNVfxzBxYL1hANkYn
         xyhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SPPtBjPT;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id fc14-20020a056a002e0e00b006d9bb8e9de6si76997pfb.1.2024.01.11.11.40.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Jan 2024 11:40:05 -0800 (PST)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A7724617A3;
	Thu, 11 Jan 2024 19:40:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BFE49C433C7;
	Thu, 11 Jan 2024 19:40:02 +0000 (UTC)
Date: Thu, 11 Jan 2024 12:40:01 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Yonghong Song <yonghong.song@linux.dev>, akpm@linux-foundation.org
Cc: llvm@lists.linux.dev, patches@lists.linux.dev,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, kvm@vger.kernel.org,
	linux-riscv@lists.infradead.org, linux-trace-kernel@vger.kernel.org,
	linux-s390@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-efi@vger.kernel.org,
	amd-gfx@lists.freedesktop.org, dri-devel@lists.freedesktop.org,
	linux-media@vger.kernel.org, linux-arch@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	bridge@lists.linux.dev, netdev@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, ast@kernel.org,
	daniel@iogearbox.net, andrii@kernel.org, mykolal@fb.com,
	bpf@vger.kernel.org
Subject: Re: [PATCH 1/3] selftests/bpf: Update LLVM Phabricator links
Message-ID: <20240111194001.GA3805856@dev-arch.thelio-3990X>
References: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
 <20240109-update-llvm-links-v1-1-eb09b59db071@kernel.org>
 <6a655e9f-9878-4292-9d16-f988c4bdfc73@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6a655e9f-9878-4292-9d16-f988c4bdfc73@linux.dev>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SPPtBjPT;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi Yonghong,

On Wed, Jan 10, 2024 at 08:05:36PM -0800, Yonghong Song wrote:
> 
> On 1/9/24 2:16 PM, Nathan Chancellor wrote:
> > reviews.llvm.org was LLVM's Phabricator instances for code review. It
> > has been abandoned in favor of GitHub pull requests. While the majority
> > of links in the kernel sources still work because of the work Fangrui
> > has done turning the dynamic Phabricator instance into a static archive,
> > there are some issues with that work, so preemptively convert all the
> > links in the kernel sources to point to the commit on GitHub.
> > 
> > Most of the commits have the corresponding differential review link in
> > the commit message itself so there should not be any loss of fidelity in
> > the relevant information.
> > 
> > Additionally, fix a typo in the xdpwall.c print ("LLMV" -> "LLVM") while
> > in the area.
> > 
> > Link: https://discourse.llvm.org/t/update-on-github-pull-requests/71540/172
> > Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> 
> Ack with one nit below.
> 
> Acked-by: Yonghong Song <yonghong.song@linux.dev>

<snip>

> > @@ -304,6 +304,6 @@ from running test_progs will look like:
> >   .. code-block:: console
> > -  test_xdpwall:FAIL:Does LLVM have https://reviews.llvm.org/D109073? unexpected error: -4007
> > +  test_xdpwall:FAIL:Does LLVM have https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d5? unexpected error: -4007
> > -__ https://reviews.llvm.org/D109073
> > +__ https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d
> 
> To be consistent with other links, could you add the missing last alnum '5' to the above link?

Thanks a lot for catching this and providing an ack. Andrew, could you
squash this update into selftests-bpf-update-llvm-phabricator-links.patch?

diff --git a/tools/testing/selftests/bpf/README.rst b/tools/testing/selftests/bpf/README.rst
index b9a493f66557..e56034abb3c2 100644
--- a/tools/testing/selftests/bpf/README.rst
+++ b/tools/testing/selftests/bpf/README.rst
@@ -306,4 +306,4 @@ from running test_progs will look like:
 
   test_xdpwall:FAIL:Does LLVM have https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d5? unexpected error: -4007
 
-__ https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d
+__ https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240111194001.GA3805856%40dev-arch.thelio-3990X.
