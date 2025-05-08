Return-Path: <kasan-dev+bncBD4NDKWHQYDRB3566PAAMGQEQLVCY2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C02EAB009F
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 18:44:32 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6f53c479adesf39308996d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 09:44:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746722671; cv=pass;
        d=google.com; s=arc-20240605;
        b=fCvu+uuVADh0x71DxZZztfjW+8dyAAa+GFFHd/ACsXe46feW88M1VBciRQuXbM7Y3Z
         r0ICucwiHQIRZpbUf4S9Pr4vju8GgJuU5CX4bOb0ihNWPEJBxTU/9VHZG3u7x9CeKuo2
         5waPTHYco9+Z4pKP0cQ+N4mdF5EIEsqzai1DhzOntjEtlOZ8jLa7otDCJVkYDRHxqJmi
         30FwGU0rprJsZMsirbtYG6rnBRqYTznDpJT/WaQeJP1Ii7iDPalMaRBLutWyEXeoMI0Q
         x1K+SpopLh4ux1KCR3ubmMA3kidMZMKGwC3MfmBXQ65KToPnVK7qtKfLKg+GktrIFtJQ
         Q2oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=26ssRU260sn6EJW0WJNHo3Djjfn5PLObEgdY17nip48=;
        fh=6SYGdgtcgXFj3vkxBIGwCYByZJe9wcdqcH8JMItuKMM=;
        b=K2AtYnigw/s63g1gEYJGTSzZpA3OzwstkDTOzRQpfanUCKH8IlzyMr+CUk0Evc9OAA
         4CRzpyCKw4ItOI3fYyGxociNtLDF+E92kJ6bwYk5zNUvKDA/dcRBq7JghKWlw9+sTsXO
         M70NutNCgLGoVGvGJvNyFQZzjcV+S2zglMh7IpjN5G/o4NkeIVOHKLwIO2IROfJ9GT+V
         OBuXR6cuRSeUB8z7muvmPlrPiE3zvE30APh2S0Gv7Nmq9UZejFdBnOLIiBRwTIGB67YE
         jrDhdqhhQwa9cvbqElSzwPOsNyRIw/ySHGaytGgyysZt28wkFBMcFyGGWUoAjBrI4cQF
         Edaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="CAYzuZT/";
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746722671; x=1747327471; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=26ssRU260sn6EJW0WJNHo3Djjfn5PLObEgdY17nip48=;
        b=FYKhu3ovRiMwBhgXj/maDmIc34pzDTgX181BrN74QsskgklGBqiPeWrsoLj9QqIver
         pSle0MD56VSBLCrWHt9WntRN5SNxUmG6B8K2dXXgHZiEUhzzosv2rKAGUpAUyl+cR4Xv
         oQ5fxSZR/6oavQy7qZm9POkgcLwKbFibp0jMXvL177hoMH9P7jymQU5UHDLC+t/XuSDQ
         tVgr6islX56jyRpQsKLBVhz0QHGv+uOGmxLJ9I6rf8QFeuu4sVN8QAJ9M9/nLpfgLREB
         U9hPQcK3aPTfav0ZB3FEK76/+EzjCXUTRWPbrDyJnO4Z0VfLOmKmnzOcaccq0WQ9vNQ8
         mI4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746722671; x=1747327471;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=26ssRU260sn6EJW0WJNHo3Djjfn5PLObEgdY17nip48=;
        b=rP47hejA3ezVIZ/ep9fCgd/uxtdgrzsd5vE702FIHqMdoWHPPes7Ojw/P3SDGMfSUt
         MVav1gQHeSbYnmdE4RLgSe+61f/PaxqnZKnYUtvEBhuq05kfOtfJpDhqz4wwy/dzB8P6
         9AyhxHXnwVcTOVAG2Qqvm4zI9ZwrRUkH4lGMDaFxSjwxq0yJMwMZ7bBQ1vjQxgQukVAs
         HBevxgAZK0fSuXSCnBXC6Lh2475jSDrDAIHSg4m+OTITWh7qpx3JTeBQ7ikj8SqWwagr
         pZg/CC8u+6EWAy/iHi84ecWTBazLt9kEsz6ZylOn0KD6plTVPRWo0gsKR0N3IWx5qiir
         f3zQ==
X-Forwarded-Encrypted: i=2; AJvYcCUi8eysT/4+MRg2rUfaUsuARB5vk1WNwcDEf9Be/NrcV0+2Vpft/u5ovgh8s07T+eGKn2IXKQ==@lfdr.de
X-Gm-Message-State: AOJu0YwAWhoGnTqM4n9wi58pSxtXlE+ga6PoYRYuelwQpma+ia/T79QP
	kBv7Ck2WY5XF4tU43sbc8PoP5ib22fgoi2ACPUTicf3KQ1TLQQPh
X-Google-Smtp-Source: AGHT+IFSReubbF7raoitzPdEMwStGUkN2lStilubTtkZEsES8KZZtuXhFpMy67hM4fDAR5dJZWPoSw==
X-Received: by 2002:a05:6214:f2f:b0:6e8:f296:5f57 with SMTP id 6a1803df08f44-6f54bb27257mr65248806d6.20.1746722671356;
        Thu, 08 May 2025 09:44:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGgnUb/2P3MzIXXcgogdTliyoYL8744LB4+EB5o+vuN2A==
Received: by 2002:a0c:f096:0:10b0:6f5:47a1:f42e with SMTP id
 6a1803df08f44-6f54b51288dls6014506d6.1.-pod-prod-00-us; Thu, 08 May 2025
 09:44:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU6SFmtbdH3B250Dw7GnhleZzgNCyoIlGeS/hXG2omQz56l45JAvN0Md0PiqPFfp0BaCx7+ESj9bn4=@googlegroups.com
X-Received: by 2002:a05:6102:1177:b0:4bd:379c:4037 with SMTP id ada2fe7eead31-4ddac9287damr2928967137.9.1746722670685;
        Thu, 08 May 2025 09:44:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746722670; cv=none;
        d=google.com; s=arc-20240605;
        b=R9Igk4ipMCpRh523x+eaPg6kbAujp4DC8CHSFwTKzEHH3JHpCpomM1ZSx60719q99A
         4EffTUNu0lcYUz2QoislbIjpcKwziheIiwX6k2n4lzI28J4d2PZ/CclqxXlh9dy5heB1
         iFAo2MFEuw4X912JlgqiuTM/BqOXb4S9FqKBmvPID8B3jTlDVOk6rghydmIqr2MHZSqk
         ftOxfBKpLhTb3usH9SrXgYTV1gX3Fggb31QS3NGZ/rE/AKyWluKsg/zZjXjx/sTuvdL7
         CbvBqEtm1YVdaDi+NqdOzGBDf8LXPcxxL65inYrmjurRV2cLCdxpdnp6azI3dS2/Z89f
         sFvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xZ4FxmMTsd1iwasfziArFSX9cS+YdWzGtvLgLgrVRyo=;
        fh=0LHNwTyU+Lw7xc5R2NYFn6GBkXNFCC1MJwBWwQ6ce2c=;
        b=ffDSHYdp7ZaoJQ8WglETV+o2jj9BIljX2jRWaz/ooHPjOe117WYl0S6xNTzi3g3+y6
         MOc11cRrJ+UoqozYPajjahUnEkMKQNIwWd71PKrW3AdYCVN6myhGORUReEdP1N8ivFmu
         O1Aaq6syTksbNsAdYBPV4jFgrH4KksCOigwmYHckT3IFPHC/QkNcJelQK8LBPYmRAR9G
         37IWjgDHLnT6Db9bEoJfT4jGH6QhG0bXV4JI3xAn8g6i90IHT71BRCADWVPbb5IX9wMw
         D3G0tzV2RW3OCgWhh7cq/bhp8ZM4JrQCgS35o1N3Yxotm4zgSsPYyos+fhzoJF64Lnom
         EP6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="CAYzuZT/";
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-879f62426d6si11276241.2.2025.05.08.09.44.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 May 2025 09:44:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DC55D5C6355;
	Thu,  8 May 2025 16:42:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A3728C4CEE7;
	Thu,  8 May 2025 16:44:27 +0000 (UTC)
Date: Thu, 8 May 2025 17:44:25 +0100
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lukas Bulwahn <lbulwahn@redhat.com>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>, linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Lukas Bulwahn <lukas.bulwahn@redhat.com>
Subject: Re: [PATCH] Makefile.kcov: apply needed compiler option
 unconditionally in CFLAGS_KCOV
Message-ID: <20250508164425.GD834338@ax162>
References: <20250507133043.61905-1-lukas.bulwahn@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250507133043.61905-1-lukas.bulwahn@redhat.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="CAYzuZT/";       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

On Wed, May 07, 2025 at 03:30:43PM +0200, Lukas Bulwahn wrote:
> From: Lukas Bulwahn <lukas.bulwahn@redhat.com>
> 
> Commit 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin") removes the
> config CC_HAS_SANCOV_TRACE_PC, as all supported compilers include the
> compiler option '-fsanitize-coverage=trace-pc' by now.
> 
> The commit however misses the important use of this config option in
> Makefile.kcov to add '-fsanitize-coverage=trace-pc' to CFLAGS_KCOV.
> Include the compiler option '-fsanitize-coverage=trace-pc' unconditionally
> to CFLAGS_KCOV, as all compilers provide that option now.
> 
> Fixes: 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin")
> Signed-off-by: Lukas Bulwahn <lukas.bulwahn@redhat.com>

Good catch.

Reviewed-by: Nathan Chancellor <nathan@kernel.org>

> ---
>  scripts/Makefile.kcov | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> index 67de7942b3e7..01616472f43e 100644
> --- a/scripts/Makefile.kcov
> +++ b/scripts/Makefile.kcov
> @@ -1,5 +1,5 @@
>  # SPDX-License-Identifier: GPL-2.0-only
> -kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)	+= -fsanitize-coverage=trace-pc
> +kcov-flags-y					+= -fsanitize-coverage=trace-pc
>  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -fsanitize-coverage=trace-cmp
>  
>  export CFLAGS_KCOV := $(kcov-flags-y)
> -- 
> 2.49.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250508164425.GD834338%40ax162.
