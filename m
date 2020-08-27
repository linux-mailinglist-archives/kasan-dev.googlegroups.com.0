Return-Path: <kasan-dev+bncBDDL3KWR4EBRBIOSTX5AKGQEZPVAX6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id BB606254025
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 10:04:50 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id v125sf1971875vkg.9
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 01:04:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598515489; cv=pass;
        d=google.com; s=arc-20160816;
        b=d9ycE3My92TApAldcICg5Q8GPIi943jah3rWXH0NJKzVN3Hw2LjF+YcdtXbKLJrEke
         4KOzMAfKeLvG00e7P870pM13x++61PXLb87vlqrAVIeOWt5tgDNAUwWozqyeSxDwL+7S
         T5IFvpXiZAyjjYANM4Xp2VXKPGYq9Mhy3PTTvYzFC1X/zNVvi+8/1qpSQ6ifmc66ZNhI
         p8cP1zeCOWXwYVJoHkdDHzXNIzO4n9fMIjmpN6gEf+u+Y0PKkjYt2GPV5RXgy1WjsNxi
         ddqIv6snKGDR5Bbmk/k3qE0lTxCRYmtHzadEy0dCXS3CttGsmEuc7rMZTUAoUIy9vJ/A
         E6bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=rVz4QrC6rHM1IdH957NZhNnVHzR39odZQsdC6WgG2q0=;
        b=uIbMwVS3DiAEKnFK8DKZtMpNzbvMEbN2RUMR6ICEIMZSNZll0OYDAB//5GnCw7/cYf
         t0pe03pwwpbwH/QCoXrpvTagObmX8Skr2BWfVBAYQiBEoA1txZkTN0M9Hcd1WX1yafUX
         p6QSOvzPP1lB+Fl41BANQwIIyoS6snpD5jMi2mFgF66XHE0x6SD0otujZXuwcsVZGBPE
         9LKaz8Dwgg6jx2UUFFdzziHP4OdEIlzQkHpA45/J4xw4G6W9i/qtScVkG8V6v3wEREDP
         yvyzzE5i55PXdeS0mGT4JcQtI/stpT5r0S39WN21JUPz+S+y9LEenUs1obeZbmFnlns3
         ZJqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rVz4QrC6rHM1IdH957NZhNnVHzR39odZQsdC6WgG2q0=;
        b=X6i6xw2DBi2EoALCsQFA1ff8BXBH+7Y2puDE4hm9YsUxLzT6or9VFHKU+rD9/CrDtf
         q4a9yy7sw72r1BzPJA8V/ygpTTJcnhOmlQCOCjmHtYWlUah0pUA7zI8l/tpkQYj/G4AW
         PbfVqK7p17p6ISYVas1vva5jnQMXLeKD5bam11NwBhFhWDrlr2R+ps7//hzsDeE/7FO4
         L8Ukhs+1jL4At+tAtX8WgKgZH46vIQkOcPbHlHR6eYYiNxzMBRXFRDrAyJkET3uRSbl+
         jYvgIE30/5nlDd5bjxJaD2mxnb90XI065+QGJXDsm9+MzcOAYkBex0+BCXTT0H79BQpW
         KujA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rVz4QrC6rHM1IdH957NZhNnVHzR39odZQsdC6WgG2q0=;
        b=LCqWYknrF7IWDj1tF9hX3c9uRAqf0JSkCXfSDepXRU04hlsIXeK2X/wFdUc9fbNKjU
         fdaR9GXlPqmH0XbzL1zyVXZ+Y8olmzQOfOm6FVdZ2ltm9qdFvigfdqkdMxR5qsx6rBZY
         Ivui8FHJ/sSz1OfEgVVX7SRiOlY4oe5lDp4Z/M5oZGVABUppQ9gZtvAwQhic/lq/LS0o
         G/J7bVSDMIQbVyJdsk6NtXn8v7ZD+9FzQ3pqLxslzNg16FaqoVHoLpQAVYExEFU36lPm
         vx/LzSphqUskeMxq0/ToPZt5NoK8hmNIhf/mTwMgL8guF6A5+gh3XFRJdk56Yud1qlhs
         EpQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531UuscSyWkAbMWYC8K7MFqmxMJW7ss48K5tOj7ATK4tpIPtR4Kj
	dythaiYmu774kMdApB5UTJY=
X-Google-Smtp-Source: ABdhPJwJ5MF2acwpiR0YpoI4elJnR3kYGvWwkp13wXHNSudXQnirOzgGh+ntVbgK/HRzxQLel5nuXg==
X-Received: by 2002:a67:1446:: with SMTP id 67mr11682938vsu.151.1598515489787;
        Thu, 27 Aug 2020 01:04:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c295:: with SMTP id h21ls87614vkk.5.gmail; Thu, 27 Aug
 2020 01:04:49 -0700 (PDT)
X-Received: by 2002:a1f:9783:: with SMTP id z125mr11792475vkd.36.1598515489400;
        Thu, 27 Aug 2020 01:04:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598515489; cv=none;
        d=google.com; s=arc-20160816;
        b=kgzpmh9keZU+DXZysePpZ6YZpLPEqeNsiAn5UfsUIIpS/sDbiBQ0Quq4GYdDtNA+M4
         w8bVQKxPX/4+EWgfdEGFzHFIyocb1akEtbGWHPKFHarDRUBHQGoMDkswJmdVIlV09gjg
         mAsbN4OdAxZlJMHEsnil/nHiUWDVUX/rqoIPtMLmLP/sKOdi/js8gWj1T5fzl5BuCbV/
         gPXaBA6tgTFlNjz8x64Bi9P56RH//ERfTISschHKZ2TQeUF87yXjJhjKfWiP0O7kwqEf
         e01u4RiZpLZ7mKVAY9jsdenAzv0GnjsxXOQvCGZ9JbxbypvKVoGpuqbKSJ+HeS8Z9CRU
         sTSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=0r1vIbSol5qITpSGhtGA5Rm51UWZ7DReIXOkVuqSZ9A=;
        b=J473onnPK1GUS2UeKdhRMSRkSNX7B5PXvk+9Zpql6IANIhhmLXj5NWQKO+OV7UXnKn
         a4uNX/UwOAUJ1qsO2SW2DOEoYqYbGJfSIT++L48bI4IqjUrE7JiaVhtj0AHkH7q4L4QL
         TNgAXr0h1XetpHeEgvVIPNaDnIET4xiBedutrFOa7jA06UJWWhecIeqNdV5U9Q13eduF
         r1PC7Jf5QZnB1fC7cdeTorwUkwS45qhUA92x6qLi4qailvti4GIpA1DsjTA+gRGzK5yR
         GtEYZ2keoOQS5Xq8W6omtG2JNKi1SvX7FDHCZ8oqQPTDygWBCiFk1L6PIF3vLmjY/v7Y
         MDlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y3si94785vke.2.2020.08.27.01.04.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 01:04:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C5ED122BF3;
	Thu, 27 Aug 2020 08:04:45 +0000 (UTC)
Date: Thu, 27 Aug 2020 09:04:43 +0100
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
Subject: Re: [PATCH 19/35] kasan: don't allow SW_TAGS with ARM64_MTE
Message-ID: <20200827080442.GA29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <5185661d553238884613a432cf1d71b1480a23ba.1597425745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5185661d553238884613a432cf1d71b1480a23ba.1597425745.git.andreyknvl@google.com>
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

On Fri, Aug 14, 2020 at 07:27:01PM +0200, Andrey Konovalov wrote:
> Software tag-based KASAN provides its own tag checking machinery that
> can conflict with MTE. Don't allow enabling software tag-based KASAN
> when MTE is enabled.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/Kconfig.kasan | 1 +
>  1 file changed, 1 insertion(+)
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index b4cf6c519d71..e500c18cbe79 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -69,6 +69,7 @@ config KASAN_GENERIC
>  config KASAN_SW_TAGS
>  	bool "Software tag-based mode"
>  	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
> +	depends on !ARM64_MTE

I think that's better as:

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 10cf81d70657..736c32bd8905 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -131,7 +131,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
-	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN && !ARM64_MTE
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827080442.GA29264%40gaia.
