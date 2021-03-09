Return-Path: <kasan-dev+bncBDAZZCVNSYPBB7NMT2BAMGQEZRTCLMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DFDC3332AAF
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 16:38:38 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id d8sf10474619ion.10
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 07:38:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615304318; cv=pass;
        d=google.com; s=arc-20160816;
        b=1GgRxGQVIcllximKyCOZ3rT8cqiVG1xZ3VaYVqkcIhxO28kqGv8VG7XCx6/Sy8oTVh
         2JzsgYm/6IMJo7l9xGLgX2y3baBjYjTyI4g+N39NXz4mVUebDTMsybDl219XbQvdi7pK
         dn1wBf33xkyfk1ojvX8SU/smoiwsC2BFTcSMpqB0lPeESEOlZsKbUkV8p6MA2d5iWyDn
         EvmnaJGLLcDupydTB/OFMemX+sexrRykeUAvBO/E+MdcwcapBcjOkbqcWNv3Lo20TyeI
         7OHCpkBv+joPBQUU3JFlCoZ0lrXuQq72zTjqD5GnsLHelefKD69eq2vKWHvhFFnerIeu
         yT6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KqKXfsVn30H3+naHj2CP9/+/f4/VQIW7M/YZVcc0QPs=;
        b=dzQPyhnCcfaxTVRykwwOgh+IESKjoJ0HS0fhpvWEIH2fG4crM+lkQYlF2BFgm1fNEC
         a6Xvupo85Umxdm7CgtEVXmHJ3oFU7mZABanS0uNz3ftuj/bj1apj1odK0D4a+Q87FjGW
         5QIT+/qhccdfy0YyMp3rFIdWTFLsC/Sw0Fn28gM5x678LNVjt8rf1nZyRd/vfFNZXJzT
         Fjs4AyPiEv2OvSpPMnO3VU5CIAMg8TuDmnpIZSogA0PKs5A/xTLxmZlBukvREp1xDhf3
         U7IIPCWtki0seZlY3oFQ8MmkJurPbiRGL4TPwB2pMuR6wFGe0BB6mNEwS4Zt3AmavatE
         HdtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UoqUOhWs;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KqKXfsVn30H3+naHj2CP9/+/f4/VQIW7M/YZVcc0QPs=;
        b=Y/7nINXUmMv8EN5vwzdHindDYb1tFgdxoBo+UnADa7LDJyyXaOQz2ZtfQ+W2ymBzqa
         rYkRkiKsw/VzbNgtS3nrRdmTOVlblSuDDg8qnHz981tQZ1eAVj/btf6b8buuXpFGNDn2
         PjsFADVwsgf0h5SAFztFZ6ZduMG0LW/44+gZ6eGS52wT21QeD1opEauomBOzV8xuLjSR
         uEQwrtmmFWTVFHTtzHjlnDTsDu6P7R4U/7+APSLGgNfZo5zpCD7t0bswixdXxGWZTMgS
         417yFEbB8xnwDXDTbM9EL7OiREyLKrKztuvGOV/Gx+S33XQIoZ89l/oLx9jv2HnR60Ny
         c7ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KqKXfsVn30H3+naHj2CP9/+/f4/VQIW7M/YZVcc0QPs=;
        b=sgKg4/cYPfIHaQeQ1qy8gg9bWMZr5vCLXE2bVaBq+Utgs+PNnCEHnrqfxdRfEpTsKS
         mMG8tWVcL2M/t/p2TSAd+bz/wVJ+cWHy2HgZaeaBPboaynjv2wSvovMsg1rUAC1J8NBi
         TYfIVDanRTwOE1mC4MTiQU617wz3J8Fh3Our7iSGwvVNbFHGPoHOTrWzps2moFdf9Iyv
         lOedQZdPK2KCQwTCoETlM9ZDIVBSe6yC2CPej2gl3oK23dYSv2lHMcOXeGcuZKXSmtLP
         Vqmo8Jw1zMjfZ3epeAsQIOIn8TtyVSdUlgaeG24XAdQSTqsgrAwqcXKGgRP5btGufVIU
         drHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZRM3j03H8q7H7LiB9hOkDq4qwwjd76LJYrMvRN7pe71UQw2zo
	wBAX734DSu2tCM0bxHMBCKo=
X-Google-Smtp-Source: ABdhPJzahGk5w0WF24HPJ/mBaOMioGnACm1MVBRfEWceGLXLZu8D/zUbzi3SmkHCcealk4CriNhhew==
X-Received: by 2002:a92:cd8b:: with SMTP id r11mr25074704ilb.161.1615304317949;
        Tue, 09 Mar 2021 07:38:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1032:: with SMTP id o18ls5293497ilj.5.gmail; Tue,
 09 Mar 2021 07:38:37 -0800 (PST)
X-Received: by 2002:a92:c04b:: with SMTP id o11mr23968699ilf.42.1615304317651;
        Tue, 09 Mar 2021 07:38:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615304317; cv=none;
        d=google.com; s=arc-20160816;
        b=eF/xkqnPajKsaexb1PTv/WKioTmZ+wtFChC59P52wv1xPjQsBoIocCvuCcR9/OYSDt
         DSKkCF3JtLAeQsh+Pyz5vnOpfG1uY7dp+iiOCLNJcAgMjBMZpoKBuC9+ADeJikPbCyOy
         61k8AOvL+7iB37jswei7sOvJwqB9xF62OQeVDt3X6TYdC8ey6fq/BTvn6jrg12BoO9rL
         t1Jbz25ktpSRncaTAdQ0DKq8rHRI5Ll9JRpzrzZmcqBDK8lXIm3eBq7IjgLn4yWDKatq
         7D1N7TlXPQQ64+hP/GkpksNeeGhHs1TpDvx62OZDWi7UKD3sy9Bg4/g1g00p/TzfNJ7K
         +6yQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dx/DvZd2TGCg9Zz3DkBqTmmABZsFFRcDIlIu3SslMt0=;
        b=fLcAQ5R6TGgdhsRAs1tLCjw9KD/eiUe9i7CrrxXNUp2IoVowkOBvpmF9Azj+yuGB3R
         +uClyhrYqA9v3ZaYHa4E+rqAVf+0t3BLfIrX1FCEstDyh/wIA3nK7C47McepJZgxfyKG
         MBoeX1tdujSQNiHfIpDisZM6T6weLqiZYLEWiScr2WGYNjFDuQNDXG33dK7XYX04tIzP
         1Hg3bkvj2v8EF2/Isa8sGTdzO2OFPSTWVPTrusufvU0t/YM67XZm3F5PWd7xf5fzb/HY
         P1kqEurE+vQRS94RL2uQ6Tzuv/RgxDaBP8Cb/KcLIgpziR7ExpyDQMtCkrsmWe33QzgC
         LXkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UoqUOhWs;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d2si829459ila.5.2021.03.09.07.38.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 07:38:37 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5EF3265238;
	Tue,  9 Mar 2021 15:38:33 +0000 (UTC)
From: Will Deacon <will@kernel.org>
To: Catalin Marinas <catalin.marinas@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Will Deacon <will.deacon@arm.com>
Cc: kernel-team@android.com,
	Will Deacon <will@kernel.org>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	linux-kernel@vger.kernel.org,
	Marco Elver <elver@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org,
	stable@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Peter Collingbourne <pcc@google.com>
Subject: Re: [PATCH] arm64: kasan: fix page_alloc tagging with DEBUG_VIRTUAL
Date: Tue,  9 Mar 2021 15:38:29 +0000
Message-Id: <161529596129.3814589.13038514678630962150.b4-ty@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <4b55b35202706223d3118230701c6a59749d9b72.1615219501.git.andreyknvl@google.com>
References: <4b55b35202706223d3118230701c6a59749d9b72.1615219501.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UoqUOhWs;       spf=pass
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

On Mon, 8 Mar 2021 17:10:23 +0100, Andrey Konovalov wrote:
> When CONFIG_DEBUG_VIRTUAL is enabled, the default page_to_virt() macro
> implementation from include/linux/mm.h is used. That definition doesn't
> account for KASAN tags, which leads to no tags on page_alloc allocations.
> 
> Provide an arm64-specific definition for page_to_virt() when
> CONFIG_DEBUG_VIRTUAL is enabled that takes care of KASAN tags.

Applied to arm64 (for-next/fixes), thanks!

[1/1] arm64: kasan: fix page_alloc tagging with DEBUG_VIRTUAL
      https://git.kernel.org/arm64/c/86c83365ab76

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/161529596129.3814589.13038514678630962150.b4-ty%40kernel.org.
