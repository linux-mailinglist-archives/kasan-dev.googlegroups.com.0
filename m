Return-Path: <kasan-dev+bncBDBK55H2UQKRBSNE7HBAMGQENKC777Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E400AEB0FF
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 10:11:55 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3a4ff581df3sf915203f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 01:11:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751011914; cv=pass;
        d=google.com; s=arc-20240605;
        b=M5hATQazFIB0aua0qlBlMylKdoKahZ8IvTqcCGVh3uQd86qp6kNumofBKfP2fQFMRi
         utaPiKU6Z0q8nZmMu5zsTxo6Y1hnEZjiibXkV4sL05jgt2P6zUntU3Z+7c/4uvMIoDp3
         9a0sxWN3tWcSKWx8A6xOsapRliMEaJTrjT5kBwK/SE9njOpZZZqiSniEksvP/SomIH9e
         6znTJCsidFcmTzUk6v66RJMiHsdT5Uyx9FgwK2wbf7wfyXzgBZgliw7I2iWL+c9mc4af
         GanPzb5brd20Cil4+26NxVZOKfmmwGq8WhkxspcX5d4UifoPLaJ58jx5sHVNtBz1rswt
         Sd7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=G8s6IlAxYnSRw675l1mbGNIMFjyLsJcAaAfO0fXRdIg=;
        fh=C1sVJaSAvRsoXIGV5dO/ReAISOTTDiRuQ5iMtIqzGpA=;
        b=KKQkjQOeEmJpa5iPHopIvOz0fcdya0FBOFT+JljwEJdQcUMDYLF/Njry0bAUjwkPAh
         UeIKNUXhk/8uc90+le1EvAC/aU6Z0xpCMzzoYr0OmbR11JMSTDsoKpHpiD7Z0aGdrBKy
         nX/k9s8nIOUQZT38/cvbF2oyMZM/nXxLg9WUL5WKgHNSbODVGn+poTi84h/HRQf8W+ig
         MdJUnCqonFZqGlwqeTcUYX8TwLNKcm5yqW/xMZ89P4VlZH1O0RxpxJp2k4HZ6HvAB6II
         yZIFYuDiYNVx/pWr37mF0s/cqgLdKKw42C8Fi4n3KuCSOX9dgutHuRc4wVmnLGio0o5g
         2gNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=pkjFDojl;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751011914; x=1751616714; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G8s6IlAxYnSRw675l1mbGNIMFjyLsJcAaAfO0fXRdIg=;
        b=YLyPjMKHomJzOA04fhN8WCpIeIIWkiz4S3uHq+5YlzprCm3vSZ26HBelr4X+nRkqNZ
         FKPz+znPazIQW6npCoR0fsVvnX9ruenQMIhTIcjOdJI+R+bike1curXjvLrlYKljS8k8
         MluQu6QPNRudz8fE5pTZGchRk7JWIfnVao1AKgsAyqjp8+CfQInciiw8zCm64V6lrIKZ
         Rl+xek2X9/uDCMaqevxEqTpBw3ctAAtDPV0Kn68Q3z0ws/dQ+BFJzFWqu6SqyQqtYklD
         R/TzYRLKsOk7URx9/gFTJ5b0rBWluljFt3fzglxlq3kGAxnVzB48Z2Vk8ZkF3ulwltxB
         ijXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751011914; x=1751616714;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G8s6IlAxYnSRw675l1mbGNIMFjyLsJcAaAfO0fXRdIg=;
        b=ABo+gtTUWaEi6EgxZpueN5kX6AzulO0RWUWFnP5m7q+vKFK3lQpJDjGXPKlTgN+nUR
         Avn7Divz6XwXTBSvpztCYcAs8sxigvgjGZYzGM+Nz+baG00n3PEm1Gj/Hog7lV0aQ1E5
         h5oph3xfpNIcl07mE2v7iH0+b8ulwUN9HTAD3jahpdXxEucMuixWfJ+fuWf8oHJBNr2X
         b7FnTZ0e41BT2LvqCo3LRvHaQxF+FUow+xOd+oZUSgDfYYcUQwKC4VKGzahx6rVjE9dl
         pxr33En7VJqjOpFmyRyxhK3BQurbna07wCGfhTyMOLDuNOeSVjaoP08gJ2gVuSCCaiO2
         W0mg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUstTlftL5iCDufLc5BX6wO8RhPCUMtrkLC56mQdm/U8lf+4lNUVDhascGkyWBS9NnkeBbnAw==@lfdr.de
X-Gm-Message-State: AOJu0YxgoVf6movXUyg2lnM3j7XzhfIH6wTIuiS4sR2IXAk7vlQcJyKX
	4tzKleZqJ+eL8VKoeQzTiT199YB8R2d+GHjk5BN32Fu18Sv2H+blmfyV
X-Google-Smtp-Source: AGHT+IGyKprIF+huvUka9O6VJ9ZLSmYUO7hGG8i0n7pg5RTiZAtfxi7tIxWgtEL8Ape8cgK15uSYcw==
X-Received: by 2002:a05:6000:2f82:b0:3a5:1241:afde with SMTP id ffacd0b85a97d-3a9802971a1mr1455934f8f.9.1751011913715;
        Fri, 27 Jun 2025 01:11:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfz+/W8xhmPAS5bd2nZP6/zxGD/7EF0gDMNmbflrReGnw==
Received: by 2002:a5d:5f83:0:b0:3a3:681e:6505 with SMTP id ffacd0b85a97d-3a6f328d773ls644146f8f.2.-pod-prod-00-eu;
 Fri, 27 Jun 2025 01:11:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5qbGUdliNeWfGkQlpzRjT5RNz34oYE8f99QepUjfXxQEyzkj8QB2Hzb4VrAVlF95LDb0yWgokkwI=@googlegroups.com
X-Received: by 2002:a05:6000:25f9:b0:3a3:64b9:773 with SMTP id ffacd0b85a97d-3a9802971b3mr1740790f8f.10.1751011910506;
        Fri, 27 Jun 2025 01:11:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751011910; cv=none;
        d=google.com; s=arc-20240605;
        b=ENPOMhmvdDAIaLmvywxtkcz9S9T7NUY2O84ij87Rzoosl1sfbyHgna0hDII8jIE7Na
         O+pM9TpS68zx13pngfQ3vXpmPgAyTlpR9cBOfADmgJowCZ53APCIpViW//2GoCcOxdOe
         BBsTLPKFUL2XMUDCLmp9maYvwXdfISAlY80UpQJpF5f0D1ZzF+kHuOQ+OmOp4v1Xvmxx
         5f1b23I/pxtLiE9qO5iapr4/r6wM+Ud+r4sf14p5UpRwsaEX8JpsPzC1uGqfsJYV9reT
         ZKdtV54QNCTv7AQg3MxxzbugQ1qmR+YzdUnImuASoWW7YLAp1pf0Mm1aUkGlGPGa8dyO
         QQ1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OZxKizN0JpjR36/RT3EOCTRtfhdellHAaqC3esyhcTg=;
        fh=6TKN9zgLvb/CKgMZeaoGfcJ+4WSlcvu0IVYYdqB+xXE=;
        b=AGf0tFkfCNHD39ku5FQbolphzks2H0k2424sD52fxxT3+1W4pPegXQoyMorDpmynnA
         urKNRkpzHA8D1BxaBS1oNhAZDvu8ABcmFzDBHBh/FaVp//76YmcueC97Jzxj72vmlFSS
         ipWmTD7tvTNyffECVYGjyL+TQ3IaIZXpQVkHOe/wILs0LAT01MvURmMKE2S9oca5G+YH
         r2qnqaULsLlz6a7RQquPWsRVeyp+3qpfAv8CJEDlNb82PGvKh9/X660khvAU5opDfS2Q
         76UXKnbi2WWgTczNARSL+I8GdXCHC60QfMgqu94SBDjwUzZRoeca+NAuicVS3c5UrDbe
         +lIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=pkjFDojl;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a892e5318asi62137f8f.4.2025.06.27.01.11.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 Jun 2025 01:11:50 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uV4BX-00000006H4F-230u;
	Fri, 27 Jun 2025 08:11:47 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 8D644300222; Fri, 27 Jun 2025 10:11:46 +0200 (CEST)
Date: Fri, 27 Jun 2025 10:11:46 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, x86@kernel.org,
	Aleksandr Nogikh <nogikh@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH v2 06/11] kcov: x86: introduce CONFIG_KCOV_UNIQUE
Message-ID: <20250627081146.GR1613200@noisy.programming.kicks-ass.net>
References: <20250626134158.3385080-1-glider@google.com>
 <20250626134158.3385080-7-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250626134158.3385080-7-glider@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=pkjFDojl;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, Jun 26, 2025 at 03:41:53PM +0200, Alexander Potapenko wrote:
> The new config switches coverage instrumentation to using
>   __sanitizer_cov_trace_pc_guard(u32 *guard)
> instead of
>   __sanitizer_cov_trace_pc(void)
> 
> This relies on Clang's -fsanitize-coverage=trace-pc-guard flag [1].
> 
> Each callback receives a unique 32-bit guard variable residing in the
> __sancov_guards section. Those guards can be used by kcov to deduplicate
> the coverage on the fly.

This sounds like a *LOT* of data; how big is this for a typical kernel
build?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250627081146.GR1613200%40noisy.programming.kicks-ass.net.
