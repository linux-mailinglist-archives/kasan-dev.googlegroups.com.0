Return-Path: <kasan-dev+bncBDZMFEH3WYFBBWFE2PDAMGQECF7DL2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 200F8B9D727
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 07:25:47 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-32ee157b9c9sf587310a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 22:25:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758777945; cv=pass;
        d=google.com; s=arc-20240605;
        b=NGEi2m3+KVyJM+4oMFnd6l2RJRdiq7GhMo1HLtiJmoJDz4qWS7uIYYmTUmDiloHF1w
         rV+DHWlIMyu+0qFYpU5SGB8nl39BDY+ujVIYX9DWJF0R1IDZ1kGYFRYatDdrm95d6m36
         +OpJYh9JUNigu1okoSmA2MB3d5ZWqjamLjRLaM9p4dr6al1nbIxGLkPQom3V+VwraN9R
         NdRtzAUsnxIfBCZ8kWhe9NZ+W1vyNJ1qgIzPZ3Ox/knZf4ZeBcrH5hB0QAUbBIe0CWAp
         RYJ2DS1DPwryyTZ1BJdmyX3tRhChaEH84No4xCgeFJsfHRBBMU7DySgS+w0yOG4T5og6
         jwbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=g3hckuJmX7BxjsXpsxMubptYn7saCSMtY6Toi4M+6k0=;
        fh=Jo9OLgK8krfnWZTN0J1K2MKcR2zSeSGikvcepYlz+Lc=;
        b=LzJ2JGSaqdNp/0w4xTCxI7226wVSeKkereBzXbimjQcsK1WTwGLuBzEtuVXlmd4iaN
         29GZUkQ/hp7bMF37utNQfQgeRxEdBhINodSsJlkFI6rAMZllro4D4DWpjw36VfjFgzJr
         7NrttzeoBOSuer4EZnkwWOEP3jSveyzTmBGt7fylm98PABeYJbYhX9JykHgfeBoCXT7o
         jUDfH72hlDVtsUWlgvk0aMzWTVYHJnJHe9n7y8YhnCcE6ZzTKVYZzRGo54LiqjZfZ+Ny
         l9EtqayZKUlskPb3zzQqZWgbGqnODAPTi6Wl9WGoHWmxNq242+bSSyFOEUXAxoHhYloJ
         VC6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qcDk9GaZ;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758777945; x=1759382745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=g3hckuJmX7BxjsXpsxMubptYn7saCSMtY6Toi4M+6k0=;
        b=bPwMcYCIO5UpBdfF0f3oxWLk/pvhc6Dotnk8+1UBfuJ9eBAe5IleUaAzVHqiEgenn4
         jlJh/FOX1NPPZsUlRFbtNYzgcXhmmJ+nfISZRLH+0XRQcECp/qeftmVlbwsKffEzf7Gp
         gekzgaOS/vz9j15waKNhoG2UmYInGrOuDUqIU71F2CwK3uX1Furp2XFoi9vKD7AMO6X7
         SSfaGXgMYOP8AFS0aP94LCVOQ48hE/oGGXjph4wR+0nlWAQ0nuhmj54h3hWu8c0evtcA
         foXMHJXEDrh8TrSJUik8a+kdwPwIV/uzOi7A6jRCccEXxBj93j7eO7cG3xNN5zR/t0zO
         VfHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758777945; x=1759382745;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g3hckuJmX7BxjsXpsxMubptYn7saCSMtY6Toi4M+6k0=;
        b=MXNObDSTFKGc+XmTMKFCaItQ5Pi6RQVMWPIqGoHtraj6jolgMe3Gc+q0FyjLNCEq3m
         ufBvMmFsp33aWnDXZmlQPoxCI8OSpFB3MOX6VkCZjg8nZnKgMnJFUKROINg4LcUtcPd5
         ns4hJko71VjqML8qiPqAa+OtRwXQs/pKBl4QShtwVvC4nXBFp+8QYdMLQ5eRM/Ut7L6w
         uvqNjFwjHNvvcP9/jQ5RTWL6sixBBre1mm5yL3KWBdElCIv6k2tFNQNm7mwLXm6g4TE6
         p4erLT4roEiJhqkk52dchqhCbRcVCvpsh+IL8rfot8xWrBLDxIDx1KpYnuDnFIbl7Bul
         ksaw==
X-Forwarded-Encrypted: i=2; AJvYcCUGY93xxTCEmdZFbcCtNDByGmkwbh6iz4Qu9+NC6j3X9opekr89FeVn8dYT5L819co9DRqV0Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw++/ND2Ovvk0K7CRNRjF+2C+ZcN2TR3lmd9Ib2oETqKm13BDJY
	kl0F0DM//b90M0bhGr0/sdoD9a7lsfsPtvexS5Mh7y9TyxFO6425WPqW
X-Google-Smtp-Source: AGHT+IEXbqfhTahq7xmBvumvudwdcaKlzAPkHnJppvVG0NAnNRDaBsXcTH+ma8plDr2ckRPix2nqYQ==
X-Received: by 2002:a17:90b:164a:b0:32e:3552:8c79 with SMTP id 98e67ed59e1d1-3342a2b1065mr2704341a91.29.1758777945366;
        Wed, 24 Sep 2025 22:25:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4LMbdAuwFgcFcoUwOIpKB9uQ02pQ50/d+7st/TATaEKQ=="
Received: by 2002:a17:90a:3f0f:b0:32d:efd9:d13a with SMTP id
 98e67ed59e1d1-3342a60ae00ls389245a91.2.-pod-prod-09-us; Wed, 24 Sep 2025
 22:25:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGu4su8bJ75lh2jnL3OlRUWxPL7RT0KlfEptHpsZGOFO4buBiifowMIQMry5DXVyaK+9DKi80lC1c=@googlegroups.com
X-Received: by 2002:a17:90b:498e:b0:329:e2b1:def3 with SMTP id 98e67ed59e1d1-3342a22bf4cmr2695729a91.10.1758777943913;
        Wed, 24 Sep 2025 22:25:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758777943; cv=none;
        d=google.com; s=arc-20240605;
        b=fGQwVorGH4wyCs1GdCXQ4IMG6OZ6cxlc1+Kej61ItVfGlACSun1srJbFlVeGMvECq3
         80sK7aX2+epa81HjkfurUVfFhvGceyd8A6fygOK1jPodImmk1wy+u2etGtOp/jSp+UOL
         2OukRHSXdeg28XoP0aWAiAKx6RxczId80fPeDihKhgd7qZG3EtzI6bRypUKE+f6Ll/M4
         /MAKeUhlgdvbKJ5fyDlOWPznGdGYvPs4YS7jKdhd3ogy67qpHmbrtGlQKDkcX1uPgrbH
         RDqFEuD/aE/msS99qIrl2C67XALjmvcdNFPng19FvjULUTMeRJ/xGOj/wl15H47KZN8i
         wm/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=bRk0xd5+cQAs2guF5q7YYr9CznbPHFoPg/gQhOcufFw=;
        fh=e+VlNkVPC9pdCP+vNawoNWChtfjiSnoy2FJ1/uLw3ZM=;
        b=DRJAHTLTyCtzD30GCnGo7sIKYu2c72DnrTClV5sCO9xI99B1moFLIRBWnjMMGuGY1d
         WXu+vmSXd4CdnyLa+ArAmTT7kHmRdVCcCdR6dnkxwplDKz3ELXbfWbuzJmmtyXMC7iMl
         AUznQveb8dXFevvPjbnS3c97B+RH6L/vT+SkVWKr6pQio9kRwU92nGgtx6myD6hsvQpU
         ToyvYog7GzWnaVrdDBjYQpymneySKQEEa9181nBo0LLeM/RBEXSqLqWln9ejJCyIQgKU
         XiTEXdrlo14dG6WTTz1vLb0nsVAaXirN9Sp2n9Fzp+/LoRH/arCkwDvkRQT65IHXlZXF
         uaBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qcDk9GaZ;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-33470ceb81fsi47240a91.3.2025.09.24.22.25.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 22:25:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 919EF438EC;
	Thu, 25 Sep 2025 05:25:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8A352C4CEF0;
	Thu, 25 Sep 2025 05:25:39 +0000 (UTC)
Date: Thu, 25 Sep 2025 08:25:35 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, david@redhat.com, vbabka@suse.cz,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, elver@google.com,
	dvyukov@google.com, kasan-dev@googlegroups.com,
	Aleksandr Nogikh <nogikh@google.com>
Subject: Re: [PATCH v2] mm/memblock: Correct totalram_pages accounting with
 KMSAN
Message-ID: <aNTST_OoeUxLQu-6@kernel.org>
References: <20250924100301.1558645-1-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250924100301.1558645-1-glider@google.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qcDk9GaZ;       spf=pass
 (google.com: domain of rppt@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Wed, Sep 24, 2025 at 12:03:01PM +0200, Alexander Potapenko wrote:
> When KMSAN is enabled, `kmsan_memblock_free_pages()` can hold back pages
> for metadata instead of returning them to the early allocator. The callers,
> however, would unconditionally increment `totalram_pages`, assuming the
> pages were always freed. This resulted in an incorrect calculation of the
> total available RAM, causing the kernel to believe it had more memory than
> it actually did.
> 
> This patch refactors `memblock_free_pages()` to return the number of pages
> it successfully frees. If KMSAN stashes the pages, the function now
> returns 0; otherwise, it returns the number of pages in the block.
> 
> The callers in `memblock.c` have been updated to use this return value,
> ensuring that `totalram_pages` is incremented only by the number of pages
> actually returned to the allocator. This corrects the total RAM accounting
> when KMSAN is active.
> 
> Cc: Aleksandr Nogikh <nogikh@google.com>
> Fixes: 3c2065098260 ("init: kmsan: call KMSAN initialization routines")
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Reviewed-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aNTST_OoeUxLQu-6%40kernel.org.
