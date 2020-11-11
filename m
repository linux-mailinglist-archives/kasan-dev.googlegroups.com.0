Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWPGWH6QKGQEMCKUD5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 225F02AFBA8
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 00:27:22 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 201sf564528lfo.12
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 15:27:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605137241; cv=pass;
        d=google.com; s=arc-20160816;
        b=LDPcuozpNQmZCg0veBwsiyS9eYzhfcC8LHo+KXZWC8SijN6VElZOSyJKiM8wIRffXU
         YxFpJyJk5zNoh7zKAQPPBf8hCeOYWEM5nlTKpSBwh3lgQ5CE1iTItlOwVOSS+vfn6Blo
         n6F81tvh1GbTTedZkG5TexgCJAyr3EuNfXtyiLNE1TeD0UY2Kv6DOLW15FG917UOrBjx
         f6R73SG3JiZXuLJKw5tkiX667iKpw4zn+tkNuSkx6x2S4uxkR6LZKRzrWrCw+i1xQTc4
         vQdGo/c8dOBkZ+kykv4Mp2VtyWHFz8uls/DBqGrHXWqapjqHmm2dQpGPrBy+vuvXg6xu
         In9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=avMCkgKgigJHDLleDvpJAIXQ8OrkNfLHj9Ubq/Tstro=;
        b=MJtIZR3pib5o5lAvlqk3LqijCQYvfrDLEuky23h1U4W2m0DwTPnJ75QbCCov9MYH56
         y7c7Kzs8OTPDwnFpUmCaqmRJDzxfsA3MUidL9ybV0LZ8Bo7fwfy6LUZURi73/UQptHqS
         LbbWC7kuUhr8iOCIK+ZAwfrhM7+Aq6YmRfgBV3BDR1xl/6n7kOnceK9wXh2ZpQw4HkAU
         VMUgNc+1ZHPXc0cnl+iLA7cKuwgsrS2QrcqGe+XyoW39EqcoUfd2Ykx+DLhhcXN1hvyy
         NCU56EiQSfFl8ml9/0Go91No2ZIj1LvMGWZi4YpjHWzXMhuEQkMEe9wpZ8ZFQ0nk4rl4
         F02A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="A/0yIMdi";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=avMCkgKgigJHDLleDvpJAIXQ8OrkNfLHj9Ubq/Tstro=;
        b=p2THZqeHNoFcndc4rqx/o2hraqkT/oAYqOQa3H601TO5GRUTjIMRO+WX9F6Td7UiQo
         VRvYjq+AVTHeLeDmJwKvZkCXmW5neXxVaNjE3Vozwrq5a+Nj8dbN52WM/+RwET/PS4oO
         6KMqX0Tmw44QEZeBdEOj4w30IREqNPhzISMcWFE6w1Kif7RGMscVgJTgSPdTcd5D/fU3
         dkqiF3JH7AOLndyDh7e5+8TFolGUVn5SltM6qckbLLHZTjjkpa+YEgj/vTWaTYK7xpQ+
         31U8uJclufLhuQKNxxpttmakGvJTYtE1AjYnxaKu7E9AQ04nmRCvo2n00ajLslGr/Is0
         OBQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=avMCkgKgigJHDLleDvpJAIXQ8OrkNfLHj9Ubq/Tstro=;
        b=VbkMckpPJlT1NspwxTrKDl67534cYPXp+eJx3ARzB3xLY9lK4NlpFsRcGDP2nDwmGo
         rGEnKAAAI2+i/90cZ4M+QNzvsXoQ/jMI20UPpIGb81K9CWvGy59Afp8G71FTOmv2lg7J
         TjtPkRiOpVxiVs4CDuOGqdigrG7FLw/MXU3IxNlUpdYfFEVWqHCvHryInx00h4ICa05K
         TA5Hn2a1EcZvtBld7CFfYIoWVoDLnj5MYCjQ2HuIQDeINZqjoycxc4P2q8bYPF9yXJBG
         P32bsSSKmOVUK0yKmaOxMhCMO092DxFL+AUrU4z554ERnjkBu4/FQzZcM/Nu/8jp3kaB
         nImw==
X-Gm-Message-State: AOAM5329UhVgYk5zFG0Knvg2yO3ousE77vMolOaAQQ/Z1yqFceG/FEEt
	XHqieCZriloI7ZQChynpq3g=
X-Google-Smtp-Source: ABdhPJxnBYPR6oGofdav8ocVPR6bOOefiKFNjKTZU59hljRL4yE8GVnimCzdtx8jMwN7H/tPMV15eg==
X-Received: by 2002:a2e:90cb:: with SMTP id o11mr3487761ljg.465.1605137241651;
        Wed, 11 Nov 2020 15:27:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls768377lfa.2.gmail; Wed, 11 Nov
 2020 15:27:20 -0800 (PST)
X-Received: by 2002:a05:6512:528:: with SMTP id o8mr6559077lfc.374.1605137240426;
        Wed, 11 Nov 2020 15:27:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605137240; cv=none;
        d=google.com; s=arc-20160816;
        b=KwhzX7Gz2wq5d1CmlW1S1ecbZ9nQtM6BJYe41hdzesyuPe1k0MzkS+9sRHMW9N4/VW
         xshSx2zRrY8cSZpz2zCq6mhvZ0gu+JJB14s39RyQqUBeGDgAj8/LoPD+Hnvzg4PEm5F4
         WEopSX6kQqGND3JLUmTcPrY5fQRnGsQtlOZn8QkoNgRy7Ujncwk0F9kNL05MaW2/gsLx
         QASgYctwqnhMbKNzuXr6ZhPmvCYRpjyjDgMCg2C6IppzkfuF52qr43lrjlq+hzlHpg8R
         YHdqWd06YZ+Bci3VsT0l4PDBNyDOQsPE+pf9QQj59rOx/yDNnU6551PkASfmlXNkdJA1
         tZow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=WFixHAIkrgBx9SA97GwMYqSCYai8tNFPN/kssmEk0o0=;
        b=cwgzyljhYY/ens8kCNp/C9BsNw+Zyxdo+AzBoTwl8ux82O9he2wUgpmxABVLEPNAMg
         lyIapin4B/BOyI7kS57yifPyCv7Uka0gl/+3EylvqMsLvgbiWXAvT4yq6kHNeDhPa7hU
         5nKQTO7YZyVN7QRiuwx3rkQb4EeigwdhTFfMtx2/UmltBaAt0AhAUZ9bKwAgW/itTm06
         QYjQt5WPxLlpWjrHZwGb0pbpKQ0eD72shGOq1jo7smC8UOHeTJs2+Vi1CtxRvLDryyJb
         DoZmcV/KiXulRxIhSIMlv0Ne46Jlfik9ESbkL379JdUzeO2KcPWuesawrNWSASd6hqd2
         QfSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="A/0yIMdi";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id i17si122558ljn.4.2020.11.11.15.27.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 15:27:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id r17so4180723wrw.1
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 15:27:20 -0800 (PST)
X-Received: by 2002:adf:ce87:: with SMTP id r7mr1269889wrn.212.1605137239653;
        Wed, 11 Nov 2020 15:27:19 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id n123sm4187814wmn.38.2020.11.11.15.27.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 15:27:18 -0800 (PST)
Date: Thu, 12 Nov 2020 00:27:13 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 19/20] kasan, mm: allow cache merging with no metadata
Message-ID: <20201111232713.GA1244863@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <936c0c198145b663e031527c49a6895bd21ac3a0.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <936c0c198145b663e031527c49a6895bd21ac3a0.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="A/0yIMdi";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> The reason cache merging is disabled with KASAN is because KASAN puts its
> metadata right after the allocated object. When the merged caches have
> slightly different sizes, the metadata ends up in different places, which
> KASAN doesn't support.
>=20
> It might be possible to adjust the metadata allocation algorithm and make
> it friendly to the cache merging code. Instead this change takes a simple=
r
> approach and allows merging caches when no metadata is present. Which is
> the case for hardware tag-based KASAN with kasan.mode=3Dprod.
>=20
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ia114847dfb2244f297d2cb82d=
592bf6a07455dba
> ---
>  include/linux/kasan.h | 26 ++++++++++++++++++++++++--
>  mm/kasan/common.c     | 11 +++++++++++
>  mm/slab_common.c      | 11 ++++++++---
>  3 files changed, 43 insertions(+), 5 deletions(-)
>=20
[...]
> =20
> +/*
> + * Only allow cache merging when stack collection is disabled and no met=
adata
> + * is present.
> + */
> +slab_flags_t __kasan_never_merge(slab_flags_t flags)

I'm getting=20

	mm/kasan/common.c:88:14: warning: no previous prototype for =E2=80=98__kas=
an_never_merge=E2=80=99 [-Wmissing-prototypes]=20

for a KASAN x86 build with W=3D1. Presumably because if !KASAN_HW_TAGS
then this is never needed and defined static inline in the header.

> +{
> +	if (kasan_stack_collection_enabled())
> +		return flags;
> +	return flags & ~SLAB_KASAN;
> +}

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201111232713.GA1244863%40elver.google.com.
