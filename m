Return-Path: <kasan-dev+bncBCT4XGV33UIBBCV7RLEAMGQEITDKXQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id AD8A4C1DA58
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 00:13:16 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-87c1cc5a75dsf22308586d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 16:13:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761779595; cv=pass;
        d=google.com; s=arc-20240605;
        b=CeztN+f8iYg24S7F3IIkszeXq9mN2I2Y0QG/UIK+hlpFrwZmwMaBd62c6yNas/52D7
         A9VTTlcvWNl+NOaqr04Bfk8uOH1NV2bc0jlpYZcevrJ9tewbI0CGgwta12SvbJGyeMPq
         S/HED9UR95N+dzntdNu4pihzjJsXTO87P5qs4SxYpvuaLKZQ9zC10W4k6iS/c3rXKwQE
         SRZO9aY1OkGplaxdv3t/Acq13Tf4aE+2kGEi3YwHFPVJ1eOHjImsa6irhH8+enySbaO7
         z0fJeucULyQLTe1/0VL9GdL89nnGKsK4vuFPcNLGnpPK84IUE0P7Kd9HpJhfcKasdb/h
         N5jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:to:from:date:sender:dkim-signature;
        bh=UeZD0cH5EGAPM9MhT8TO2DwHMT/Xqw83hI/swTlypG0=;
        fh=tu2WUGkkmn8cw531upQw/ZkzAKWMlhwTaYVkZ+xZT6I=;
        b=h/+jiyXID/+U6b7jBJ6PYiW1lqQEhKEpN7oKN+rh9PStFxlaPl2t2sZfgucSBxKR4q
         BD/nAUD6pbfzSHA+fQ+jIgpbaUNHsWTW/PE+V1G53eK5ELznUlJyDAsidMN0/sRByjZW
         KZlkXuwtrS3fqxB4pIVDK92NwQLiqL2CDXdJxcDRJS/rHZqYmxyJO9puPaBUQtE5Q1ka
         36fufSdsMYB/+aMYhnSvvn4dsMTHQKT4VS0rELmDOXTQIWOINMiY+RNY83Ck6BaiOUUN
         fR1IvOF36AVvuHMTTH8jIZilCtECALvTOO5wiI9yva/BYLOcV+KPzijbUPV+m8tg3Fr+
         5CtA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=im3LP7Wh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761779595; x=1762384395; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UeZD0cH5EGAPM9MhT8TO2DwHMT/Xqw83hI/swTlypG0=;
        b=ngyXH6UmoKn/zGSRkI7eS1L8WjKEAAhAt6XpgWKw6vuVOM742IPOsZ1uk6wCsXpvR0
         qwsrgdsXaVPbTJPSseooSF0lU7V3E9XxxucAg8UhFCCuoLjKj7u/NTqJwKGt+JYgVbSq
         O4hKbkAXYlPAI6FoN6BrHN+04tdDyKZMi6he7g3Z7toPwrFxZ4kQmdVeAgm+m4PG9sbX
         VCF8xTl17dpisEfDocB5CUGLEYqgchB+fTD7FnfhaTmN8DFHDfyidcoJMLE0WUXfreRO
         /XymmLuJo8evfPJmmLYU+6Vy7w1ZnPEsqia8Dt54RjmRonmEDcCqj3Ta9Y/av4YvYD1j
         OtWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761779595; x=1762384395;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UeZD0cH5EGAPM9MhT8TO2DwHMT/Xqw83hI/swTlypG0=;
        b=TPdjUQ1bJhED49vMZPwgtAeQ5yaGBwb+4+OkMRHajnOknNeDeBibKoBVhaj5dsExoR
         znuvnPaqDhVNUqtqTZvlnCHUjUA4zL70+95813FGlyf2k6KUSId5EUuKkqVpq5aZhwQ3
         ovmXaMDQXFtAzPT/fGhOz0F/h6pzrl2aLIKKwB5ILy4VWCuh+Fsx36aoma2pQpsnhO/S
         ORDvBwMwS3ByNLe142ZIDKfwfjWfuzLjG0X4cgZ4m2Mo+riNuR4sEbc2R6SwtyLnFedY
         e8rOca0UQyvAJz4SOt0WPM6V5wXpRYIuUBjJOJ2HANAfrIVvTVSEtxdDZAxq5PukLh0w
         eQvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX58Ek50GsesA5s+OvGMiQUqFfNZIL/d7dYfNeBVQX0C4eRFVhDAW5p+GimovUkzzOnMSlILA==@lfdr.de
X-Gm-Message-State: AOJu0YytQl319UeV1lBY/F5EiyTdztsZ83EZN7YGycezynqM7yoMcRT4
	RdIQ6XuYBi/vJhqBXelreUD7C8i0cmjj8a9RkZRNVUDRVDrO+jDLmuTQ
X-Google-Smtp-Source: AGHT+IENim0LbBJO4/x7AR0TJ7W42phbWeW58a9JrWwomio3mf9KNxN7TRcLiKj4nFZc4oAd5LEgqA==
X-Received: by 2002:a05:6214:1d07:b0:793:e90f:1bf8 with SMTP id 6a1803df08f44-88009be58ffmr70623536d6.34.1761779595136;
        Wed, 29 Oct 2025 16:13:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zbqe8eWqn3e9Fa953/HDqjnToIE/GIsal7mw2h+KOyXA=="
Received: by 2002:ad4:4d12:0:b0:880:1e2a:7674 with SMTP id 6a1803df08f44-8801e2a78e2ls1977816d6.2.-pod-prod-04-us;
 Wed, 29 Oct 2025 16:13:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcHb6rzhZlA8zMoQMXQEgicyN7fyJbF2Ty4Ydz+tkt5Ex+3j0gvhrGeDJf4UWVtYeqFmrwR10glK8=@googlegroups.com
X-Received: by 2002:a05:6214:400b:b0:87f:bb8e:4102 with SMTP id 6a1803df08f44-88009c20bb1mr57182226d6.56.1761779593732;
        Wed, 29 Oct 2025 16:13:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761779593; cv=none;
        d=google.com; s=arc-20240605;
        b=CAj3UxY6U+ZsXj5FnS1ncgovGoB9zDu75zJDebP2GGfzQeJ4MkUoBlOlRVUcR179W7
         wKP116adSW9qbUjxHMmtFpqRKoz3JiIBSHzg5wCOF11NFA6ImSaaCx+P1upOLZFvate2
         4yah31W78GO90XKEr2KU9xoxVX1Awus/2mf14IitmMpCCUt1Djd8WMieTByfkrbUZdZl
         Ov9uI0meGH+WzRSZwqRraSwEmYLTsTwm3X+j/u+ppEDDid3f+2/ZHudXKwMpYXR7tXob
         qIxTjDsT2s9M0oeW4NjcTV/e0w7gMRtAI/S8JsOcexf0lQ1SVI6BYJ1MIeRTT+u31tIz
         BKMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:to:from:date:dkim-signature;
        bh=cbtV0wXCHdPAvLi1c4husxXdxnZcxbVftKgb5veQJHw=;
        fh=dSD6jKu83bWjMJ+kXPc+xxpI1EG8SsOGJrUindZf0eM=;
        b=iNoUOghXUHIMman6fRTkaPlhb47zq9xLZ3RYBvWyMq7aKizn/ifw+pf8NAJnqWErFg
         Br1RHIv0azQvE+4A0PQdwn4WOD6aPHmz1t4PoPTvQfPIjRPIsJSwFtYmcfbIkR3Ko+4t
         OhZYAaf+yiDzRnUFWylcLCFDI73G/P+2gt8CxdE+RB25yn12bEbJOna/lAniaS3bdgz3
         xOvB6RZo8sWiXMtxAOx9YdewZPA897MWvJki3S0vYWAfzKoo5J6TJkMA04x1q5B5uEyO
         DlL+eVE07UP4WKRla/VSHCwJfx7FhGSBLDc9nr1Q0PgRrAQE7+GmIM4+rUaHoB5daIe7
         vS8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=im3LP7Wh;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87fc6779528si6892906d6.5.2025.10.29.16.13.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 16:13:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id BB86E4324C;
	Wed, 29 Oct 2025 23:13:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A1A30C4CEF7;
	Wed, 29 Oct 2025 23:13:10 +0000 (UTC)
Date: Wed, 29 Oct 2025 16:13:10 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, xin@zytor.com,
 peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org,
 nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com,
 bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com,
 kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com,
 wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com,
 fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com,
 ubizjak@gmail.com, ada.coupriediaz@arm.com,
 nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com,
 elver@google.com, pankaj.gupta@amd.com, glider@google.com,
 mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org,
 thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com,
 jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com,
 mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com,
 vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
 ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev,
 ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com,
 broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com,
 maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org,
 rppt@kernel.org, will@kernel.org, luto@kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, x86@kernel.org,
 linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev,
 linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 00/18] kasan: x86: arm64: KASAN tag-based mode for
 x86
Message-Id: <20251029161310.61308a6b61b1423feb655d2a@linux-foundation.org>
In-Reply-To: <20251029150806.e001a669d9dad6ff9167c1f0@linux-foundation.org>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
	<20251029150806.e001a669d9dad6ff9167c1f0@linux-foundation.org>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=im3LP7Wh;
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

On Wed, 29 Oct 2025 15:08:06 -0700 Andrew Morton <akpm@linux-foundation.org> wrote:

> However patches 1&2 are fixes that have cc:stable.  It's best to
> separate these out from the overall add-a-feature series please - their
> path-to-mainline will be quite different.
> 
> I grabbed just those two patches for some testing,

x86_64 allmodconfig:

/opt/crosstool/gcc-13.2.0-nolibc/x86_64-linux/bin/x86_64-linux-ld: vmlinux.o: in function `pcpu_get_vm_areas':
(.text+0x101cc0f): undefined reference to `__kasan_unpoison_vmap_areas'


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251029161310.61308a6b61b1423feb655d2a%40linux-foundation.org.
