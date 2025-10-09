Return-Path: <kasan-dev+bncBAABBR4VTTDQMGQEUG5N7JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5856BBC70DC
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:07:21 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-30cce8e3ceasf1005896fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 18:07:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759972040; cv=pass;
        d=google.com; s=arc-20240605;
        b=XHuURDDx9+H8KoM7lYRGVPUkpd7ubCGZjhSIgWbI5/BNIa/MazsRM+aQBtv6JLM1yW
         ezS/HT3yoK+oxjl6RnhPb7B4AeN8UOjnkOpluGXJ1jZdlMrd0A8hMMpPosKfyCV3DQ4t
         eURzQZFgpfuarVUEPRDA0oXn9I6hiwr44nQz+WMDgST4wBcosel9T7Y+12xxjVG/h6xL
         uzMenm3cTlzZHRdSwBwnsfaBaLPLYYwowpbfWy6BVYN9lKc6OoVHk19DIVNcJsCKYUSV
         1H28A9kW3pcjxCH0oKmG3qCyTGC4mzUZ02DOCp+ny1oCzO4C8XkZHa5Pe8+so5GY1WaS
         TO2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:date:message-id:from:subject:mime-version:dkim-signature;
        bh=rj/r0FGZwqjC1xmwCL/I/BVuCWY9uOmc4bBsndcyFkw=;
        fh=XWGenMPoQ9pjTgNacFtUmvjavUyjbtgvMmCKAK4khmk=;
        b=hJpIZg3mkNP5wscGV6i2zBamXWzsi0Nh0Vl98AxnAFN+qS0rWZXSq246cWKYcsNDKZ
         OLhCt9sta/PJqEKK0LzAyQ2Iov5SMf55EEFzE0/EJlsYRYB656iwwdorUkG3d6VOST8V
         mFlt+p5llWG9gFwVc9fL0BbP9BCHRDh2YgyrJd74NYKY0pzG6xxwry6LSrCU149NVQvd
         qZp7jhvI0tKpa2Av8dl58ePCxfnRtdgQLf+PITb7WD2BXuHjTmbrvZ8J31wz4Vt6VIX1
         0GBHUpQcby3cv/LEF8XUv80dFY7rPNxW6sq0IB2+IvwGrn9FN2DBfqm3Nlzmn/jvyimw
         oxFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mgLCEG1p;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759972040; x=1760576840; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rj/r0FGZwqjC1xmwCL/I/BVuCWY9uOmc4bBsndcyFkw=;
        b=xS6JUcFGuMQC1ZCPpLgRf60BmCaGR7GUcmNk4wutBdWQxBMx8gb/QtsVt4kJYFpEK4
         JtAA0ud9cR/uMJL5cgzSy2SZm52vEbXQMGPWfxPIuyaDYTJStF/WqDxMv+NT+6Lnoj/b
         t9omgMUdTRBCjh6DLJbrfAbHSi+3R505ZHvFacm/PiQ8NcynGrcT58ehJ1bIemj6ZSQj
         nw8vZ66FqmBBNGpg9gaEfQnQye/TadB0n4oeyY39zsXUrpAiXaPd/MTqDGuFyVT8iTVa
         CxMollNu9puZm/jHQwmcimuqSGpL3oa476LzOI8l5oQF2urw+qtwMvcOQWS6a2vU3kn3
         3ESw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759972040; x=1760576840;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rj/r0FGZwqjC1xmwCL/I/BVuCWY9uOmc4bBsndcyFkw=;
        b=Zlxu+s4vLGTJRih8lVlH8z7R/2n5RNsUe9TY95+513jz0hVMtNEC/ndJQUaTHbTclV
         MVydfgSZ6odAixN6PrDi+OJAU7tmeEpBYLLAczmb2GjcTSStihhho3Qas08EWzXjEfm1
         JAXLeWyvHw3SJJofq+AxPOeQJkssyhb1n0gHCASxK2qbkOitXuzySJk/76lOcXn1lpfJ
         DL2L23I8e9ZjYuj+Hl102u2JqOI2pSuh7NLUyNrXOyJyvE/gq5tsHs2J+ePEgaApr89A
         7We9FBVJG6C4WFcK7wVmu4rtmLugMF0gA5gGHXF4oC6okV65PkL1ZcUumQvAOQRJEIVT
         WzRQ==
X-Forwarded-Encrypted: i=2; AJvYcCXPFlNBXlO+tZdyuDA9ZYBgKiMMKrvRP4x754sH0SWdoJwWN6WjDZXvbem1yBXIlE+ZElRcgA==@lfdr.de
X-Gm-Message-State: AOJu0YyY8A1bhJ9XOlWyQMJUvpgd3io/WqQGhPiO4n8elo1/ZWXgIa/k
	7eEVvpp7XuVZb0+gnbyL4XA5qhyiESVeK8JgHRtesd23Oi3oK4tRE56u
X-Google-Smtp-Source: AGHT+IEe9d2aJjXwRcSL+hV4T5sIl+oKv7i8fjpGucGpYCIYvBS23aeAJs3qbywnHYN9nY80heEg8A==
X-Received: by 2002:a05:6870:7024:b0:332:dc4f:1e40 with SMTP id 586e51a60fabf-3c0fa2691c1mr3222269fac.27.1759972039732;
        Wed, 08 Oct 2025 18:07:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7pxDtcs6kSOiQJwkxlG+pu+xHvnFB1r1y9Vhj3WtkmoQ=="
Received: by 2002:a05:687c:339a:20b0:319:c62c:c8e0 with SMTP id
 586e51a60fabf-3c720fcd170ls113896fac.0.-pod-prod-07-us; Wed, 08 Oct 2025
 18:07:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV1x0SAtYpizOPh7V72305IgTC7iBiscY2qU+ZIVN7b3Wex+hmBL4qhv/fuuAqGckj819Anue7diEs=@googlegroups.com
X-Received: by 2002:a05:6870:8185:b0:315:2bc7:cb62 with SMTP id 586e51a60fabf-3c0fa07d82amr3313530fac.30.1759972038959;
        Wed, 08 Oct 2025 18:07:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759972038; cv=none;
        d=google.com; s=arc-20240605;
        b=UGPFa4wW7OByTMJNNpzYEzWm0UIO6K4pyhn30oZL6MYdoIaZC1+VywImQ8ZvmXNF9n
         e18cJNkJAoqFgFWvLe5FS753+LE4WYqNb0QDEjNoh96zo6af+RpN8Up075XNOIQNcHYw
         QXri6I0EB4E83D0W8rxLM6KL8+7QhZJfkNg8BFqaBxi2INfwG9mKm6IC8683z43zvEB2
         QMyszFgGAZ28bJ+NU8uT428dg9hK2NCYOgIg1lZt7xBskOy0BP4rWS/4+3ivxIcnmqYX
         wM+wiQohQ6+u3x8XsmS7svcg4J6HKq9z3Iw3w3AWf1e6geFr/6gflOtk/X1GGj5oKQW2
         iwrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=1QmteHczt4IB2OaGgMcuo7lCBy1YKUcT8nLt2LHCF7g=;
        fh=lp1EjcfZp1fTt8wul+rlIq92P5ez/UUTKPX+HQdj2ls=;
        b=bsdGYyEJ0YO/1LCmD/t3xTbZWDI8QFEH+y1hR2QXt1t2lfhVcg5PU6ETsMeanqzFeN
         GbVPUzLw9gwEvSQmMpwDd7FTzZGiHQYDCxw/CVCwND6PDOCt87u1GdIgufKsaU50Q0Vz
         vjYTTHZnBCsj3mV2Ng+zq2E2kfL2rAMY8nMy+GxJ0DEwJuDUFIH0OfIeKx72q4e1Nt/i
         R9X9HzIVmDrrrmrzjmNRhP5jof/bPE+nHUFF+Zb251ZOk/FGguHl2xNBi/PoadmrPCaC
         +a6Hb3C7WYWpAA4MaKCYWdfAHSrN817CgJiv5iJ6f9Yf06DwbAHQJmSYK0HwAgpokjKp
         O6HQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mgLCEG1p;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3be8937ef62si159989fac.1.2025.10.08.18.07.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Oct 2025 18:07:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 32835450E2;
	Thu,  9 Oct 2025 01:07:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1021AC4CEE7;
	Thu,  9 Oct 2025 01:07:18 +0000 (UTC)
Received: from [10.30.226.235] (localhost [IPv6:::1])
	by aws-us-west-2-korg-oddjob-rhel9-1.codeaurora.org (Postfix) with ESMTP id ADF8C3A41017;
	Thu,  9 Oct 2025 01:07:07 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH v6 0/2] kasan: unify kasan_enabled() and remove
 arch-specific
 implementations
From: "patchwork-bot+linux-riscv via kasan-dev" <kasan-dev@googlegroups.com>
Message-Id: <175997202628.3661959.104646439887808862.git-patchwork-notify@kernel.org>
Date: Thu, 09 Oct 2025 01:07:06 +0000
References: <20250810125746.1105476-1-snovitoll@gmail.com>
In-Reply-To: <20250810125746.1105476-1-snovitoll@gmail.com>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: linux-riscv@lists.infradead.org, ryabinin.a.a@gmail.com,
 christophe.leroy@csgroup.eu, bhe@redhat.com, hca@linux.ibm.com,
 andreyknvl@gmail.com, akpm@linux-foundation.org, zhangqing@loongson.cn,
 chenhuacai@loongson.cn, davidgow@google.com, glider@google.com,
 dvyukov@google.com, alexghiti@rivosinc.com, alex@ghiti.fr,
 agordeev@linux.ibm.com, vincenzo.frascino@arm.com, elver@google.com,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org,
 linux-um@lists.infradead.org, linux-mm@kvack.org
X-Original-Sender: patchwork-bot+linux-riscv@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mgLCEG1p;       spf=pass
 (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: patchwork-bot+linux-riscv@kernel.org
Reply-To: patchwork-bot+linux-riscv@kernel.org
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

Hello:

This series was applied to riscv/linux.git (for-next)
by Andrew Morton <akpm@linux-foundation.org>:

On Sun, 10 Aug 2025 17:57:44 +0500 you wrote:
> This patch series addresses the fragmentation in KASAN initialization
> across architectures by introducing a unified approach that eliminates
> duplicate static keys and arch-specific kasan_arch_is_ready()
> implementations.
> 
> The core issue is that different architectures have inconsistent approaches
> to KASAN readiness tracking:
> - PowerPC, LoongArch, and UML arch, each implement own kasan_arch_is_ready()
> - Only HW_TAGS mode had a unified static key (kasan_flag_enabled)
> - Generic and SW_TAGS modes relied on arch-specific solutions
>   or always-on behavior
> 
> [...]

Here is the summary with links:
  - [v6,1/2] kasan: introduce ARCH_DEFER_KASAN and unify static key across modes
    https://git.kernel.org/riscv/c/1e338f4d99e6
  - [v6,2/2] kasan: call kasan_init_generic in kasan_init
    https://git.kernel.org/riscv/c/e45085f2673b

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/175997202628.3661959.104646439887808862.git-patchwork-notify%40kernel.org.
