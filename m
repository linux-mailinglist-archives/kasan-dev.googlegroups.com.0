Return-Path: <kasan-dev+bncBCT4XGV33UIBBKHF27CQMGQEAP5FSGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id F17BBB3EE6B
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 21:23:21 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-248d9301475sf63454135ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 12:23:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756754600; cv=pass;
        d=google.com; s=arc-20240605;
        b=jGG4VkuYotWioho1bm5/eEQWlFOz8ZkOSR3ud7jcSPwrXp8NG5rrd3pTClHuLDW55g
         806YLuHwbsDODXLxrBqK18s7qOt1JsLHf/tjR9ftnmhp5M/rKkUtnRinVMgub5kRJCWy
         FzdKIBqhHU4h1slXsN2n5UGu2WWabWJC3f9ognc5N8mEgBaOkqs3CrFyXwjXdzoq93iF
         WDDe11odatsr3v8GY8lvAHEVBXFlOlHCDjRTbmeCoBsu6KtV8cTnv6QDQzaaJGrAtJHr
         Eq1oYmV3cxcihOi6SFO1YNWn5gbHL3Jjc1Mce18bZ3L5ZHHkDSr06EPEUykUM3fzJ8R+
         MPKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=2rULfVRkRDIEdsFM7vi1+IiGGAvcSGZg2rn2+4ERORg=;
        fh=eO0xnplarqTQ8kHbKjalI48b0CTnyWI1J+n/Fs3x5j0=;
        b=Fvw+W92+iY2amLGBHYnDos6nZ9cz6zuhyflPiSt3swMp3i7cpjVfti4K/h2tvxyhj9
         j4/oaPPrnQG8DnJgIy37DhpOws6mxhEvpWQb7lwzSSs0C7R8iZYXwFPXA2eOyVfq9Im5
         aMSdvTRa1Z5P7RB/UxKqCUffuOP+D8YbuIXCQ3NZ4p9+zRELwUflvzg7WlKtDuFLpRlf
         0Ke7W+LUrF1hMfYUpbXqjiPe81TiJni32d5LpQsSIygeSTvSkKPe3LrjPmFgF7GhYZQh
         vhOAKqaHIhZrez+/ixuI0WSJLGIDb5gOF2DnVNRbGlAT1gDjLDa+OdybbwYgO8A0Qtdl
         8zyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=waO5M7TU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756754600; x=1757359400; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2rULfVRkRDIEdsFM7vi1+IiGGAvcSGZg2rn2+4ERORg=;
        b=Gsc5gwcv97NGB32R1TwGBAeE48/YsqUD1tneoe4BD3qkixgF4zaCZyPWTTux40p3aV
         ZGLcSH6lhX/jOO4+B7xURb1f56iGHtIBsxVnw+lKZFBqkgCWIeQHqj61yYkuYM/Fnc1E
         V6o4L6mwgonPbeiEHXLxJK0a4+Y5j04C1oZP/CFpIzk/O9o5SrS+x0cZdY2sj7C8Db0P
         weRtnW1L/va1T8Cn+mr3Ha/QcCD8gx9bCbbHLCD5mE3Vs/U5U+dZ+gF5i4JwqGe8w366
         OmBon3AqOJC3EYUDXQLuA70O9mus29oCEQd6NKvU0XYs8S+SqRRnliF8w751a4I5NfQy
         F+9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756754600; x=1757359400;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2rULfVRkRDIEdsFM7vi1+IiGGAvcSGZg2rn2+4ERORg=;
        b=gwb6aao21ynoBbER2lXNRX2GtTGzjA1D/20z8B3eQhFyS40BdY5pforV4x0jC6Adf/
         FHCuoXsyZUs4R6Y7u4tDC4cXDrWwyg5BYWYhXHGL1eeCOCt7sr+zGrej8syiGpOFpToj
         M6sJ2k2CF7wLOKCr5c35069dqGHpRLRBZYTINZPWtEyNZSsmo/S7o6dJGa5d8PoCbzv7
         Z8QmpRW0VGzWz9eMp9R4Q60/Za/zBXW2NCs0wG8iNjUtsm0uOUdeHrHohXy2TLKoqjob
         pn4Z+Npvy1/hUUwG24Nx+6nvqrxrW+NrwsWGO+qBdmXHNhaEL2Hon83nzB9F4s+UJAhv
         FQxA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU5r9ug6I6kbg56vklk3SfKHbK6Aevj3q0ilMx8oij9e7Lj0yDnFRPSX6DsirIX9q+RUCTXgA==@lfdr.de
X-Gm-Message-State: AOJu0Yx23N7DSLmwmX1wRRv2sHe307xBMw93lCXzgJ/kAzNNfPE8tdNm
	/pnT3/sOeEzC5c+BBXYHyJ808jKKb1ukEIlHv7EpAPKMSMLOgOo1aBMq
X-Google-Smtp-Source: AGHT+IE6051cqZtzCG9mjAHxc6k30wR/Y23QKqv6nQkGZ9M4dpPfvmJ9Pp7lOGSzzf7KJQM1BXXLSQ==
X-Received: by 2002:a17:903:19e8:b0:234:d292:be7a with SMTP id d9443c01a7336-249448803e6mr124084825ad.1.1756754600338;
        Mon, 01 Sep 2025 12:23:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZefiihp3Vg99lRCZMS6TOr6iV88h20oOAnHMf263tPhpw==
Received: by 2002:a17:902:e850:b0:24b:63d:52bf with SMTP id
 d9443c01a7336-24b063d575fls3016425ad.0.-pod-prod-03-us; Mon, 01 Sep 2025
 12:23:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWAeqeaC6KP0hse0AuUmJKhfsalQ3ObNTD5g9DirNTuZ/4tNOWV1/6xcM0TGl7GiDGV8y3I1nYBT4U=@googlegroups.com
X-Received: by 2002:a17:902:dad2:b0:248:eb09:3e11 with SMTP id d9443c01a7336-249448dc75cmr102345845ad.14.1756754598116;
        Mon, 01 Sep 2025 12:23:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756754598; cv=none;
        d=google.com; s=arc-20240605;
        b=PxFfOH/97Ys7x8XvZTVWojXlUlTaA5GLumQlmTjnbYxwTPPJPbFxDDXyTfWL1JYoVP
         zobwp4W2krldk7vAJLq6LAcyVMbK+kRToo5wBEaRqzYeuiBUz0QUTBMcyva+aD/fI7rL
         A4BgTJjh9OYUpU+x5KQsT75RvlS8ZRitxxIQ83XoHqGKMoe2+BBilJ4mfm3ZK4TVO9dm
         C0AMCqqrLKnRhFmLfpLhIULPqEdyMnP39opHmroktKHswqjPGTXI1neYb8O4v3qdVc59
         Bia1yPIGMHBfYXMbNmSQGJhukvQZXxkgMYRyF6WaWw4CHpjrXHbbbwqwBjxFTxot65HG
         tlFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pIqgkGlhxszd5dv+EEyL+ssQRqACdJfeCT3IkVeMdqo=;
        fh=ivQIf3v/Xx1BEYDObZETdcd3jhHLF9mbt+dTRdm7tdg=;
        b=DfW8kbgPwo2c/JunDU7hDSkPoDWJF8rEWsvTu5k9OSBI/1CvmOwp2Jke0A5qXxKnTd
         cJySCne17ZblC+14KdQliEdvuCLNQudFVDLX99xTQZ3SZtloO3m8UYUMdBf3g/v+LdTu
         6S7BjcCMymopnKj3KaczqfHCjZsNfGK9v6YD5s7m+0FHOSKv6LFYZnXt7EYmW1BZOoNn
         2SB8xTfU6xRicCXSQJKR3BZivpTFHamZ6kjKR0ROBFHm46Z+A9/EWm2XyJTzlowmL7Y5
         hqgTEfVG5eRu8PVMfXgf/BfSUdD6RzBSdUPkq+sY5dbJGY/4E2Qg1tvIJWAWp26I5frm
         kzIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=waO5M7TU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-249065a5756si4354265ad.8.2025.09.01.12.23.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 12:23:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id BE35140B99;
	Mon,  1 Sep 2025 19:23:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C9BD1C4CEF0;
	Mon,  1 Sep 2025 19:23:16 +0000 (UTC)
Date: Mon, 1 Sep 2025 12:23:16 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
 catalin.marinas@arm.com, will@kernel.org, scott@os.amperecomputing.com,
 jhubbard@nvidia.com, pankaj.gupta@amd.com, leitao@debian.org,
 kaleshsingh@google.com, maz@kernel.org, broonie@kernel.org,
 oliver.upton@linux.dev, james.morse@arm.com, ardb@kernel.org,
 hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
 yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
 workflows@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 linux-mm@kvack.org
Subject: Re: [PATCH v6 1/2] kasan/hw-tags: introduce kasan.write_only option
Message-Id: <20250901122316.6b7d8d7fdcf03bdb2aa4960a@linux-foundation.org>
In-Reply-To: <20250901104623.402172-2-yeoreum.yun@arm.com>
References: <20250901104623.402172-1-yeoreum.yun@arm.com>
	<20250901104623.402172-2-yeoreum.yun@arm.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=waO5M7TU;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon,  1 Sep 2025 11:46:22 +0100 Yeoreum Yun <yeoreum.yun@arm.com> wrote:

> Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> raise of tag check fault on store operation only.
> Introcude KASAN write only mode based on this feature.
> 
> KASAN write only mode restricts KASAN checks operation for write only and
> omits the checks for fetch/read operations when accessing memory.
> So it might be used not only debugging enviroment but also normal
> enviroment to check memory safty.
> 
> This features can be controlled with "kasan.write_only" arguments.
> When "kasan.write_only=on", KASAN checks write operation only otherwise
> KASAN checks all operations.
> 
> This changes the MTE_STORE_ONLY feature as BOOT_CPU_FEATURE like
> ARM64_MTE_ASYMM so that makes it initialise in kasan_init_hw_tags()
> with other function together.
> 
> ...
>
>  
> -	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
> +	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s, write_only=%s\n",
>  		kasan_mode_info(),

This lost the closing ")" in the printk control string.  I fixed that
up while resolving rejects.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901122316.6b7d8d7fdcf03bdb2aa4960a%40linux-foundation.org.
