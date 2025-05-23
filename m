Return-Path: <kasan-dev+bncBDCPL7WX3MKBBLFCYLAQMGQEOBFH3QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D8A4AC2628
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 17:16:08 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-30e896e116fsf44097a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 08:16:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748013356; cv=pass;
        d=google.com; s=arc-20240605;
        b=AJovj1RcKtuTglvwYjgXr2POR3xH8l90EVB/5exYVHGGSoZ/bImZGTJNPA5+RnCK7b
         IaxECPviUrIyqp8/mqRQ+GUvsCyNSRl6QNtJrFszYGMYYQlmSIuC9ZsUQ8wP90cvq5IJ
         PAsrCcK6yszeapFaS8DFv/x4k98jDfYG3EpDnBU6dKcTEG5by2/23RhJof2Ll+YgSpiZ
         voO2N9fnbTgoFm0myq26RG9XMk6ji1a68rYtnXNMcPboVoOrqvfyqIvQB6mUAHfYtVFC
         a11ssf/Nm1GSOZ+Q4qyJ2AfejII3vg/qom1Xm5vqY/F3f8L8aQF1IbwDEq8EcjEN03BM
         X7Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :references:in-reply-to:user-agent:subject:cc:to:from:date
         :dkim-signature;
        bh=qA5C3jTHUDmuXG2iAMCkE7EGQSqMXw/MbYdb+Z/EEKQ=;
        fh=pGtEkiKpNWaCeim1dE6PlNewSYJCXnpGhvtNkZgrJTU=;
        b=f0zGthmpxcu7MY9CkE+hWHmvRck7JPpGGKOnBfh48dEnu6ILZNNqf8uupNhaJvTQAS
         xCN6rWd4GJENqFMV5Im2pCZU8nMpbk/arduRsmAdxt6JalmiYvJFn1WS0KLrm4i2W987
         Sj6U1B5RIMbFZcmVJWyKd9lM7p8Vrw/BmMba6NiVn2DhiBvx+PdZ0xmJqq+mVRqSq/Er
         aFDJgHVQ5cdI7rBzlty2kHgTuZMwoMZlM47yxPzs7aLxFV+zFDA+x+K2hKwdrNdB7qyu
         6oyorJGlwdXY0VkfJTf9AnuKqkwXl1xlZg06b0Fy12qWvulzvpNktRMjzfDiTIRP1G0V
         rLpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HX8ckC8A;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748013356; x=1748618156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:references:in-reply-to:user-agent:subject:cc:to:from
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=qA5C3jTHUDmuXG2iAMCkE7EGQSqMXw/MbYdb+Z/EEKQ=;
        b=uxZfNVvT2Xd252yTN2S3GDSWqu6CujChPcIjJMa3z8PQX1hiRegKL2axM4/rcnx++U
         nyoyZXGSkR7FZPiExmkJY1Cuezjll3Pi6Tsns8EjDCyU6FupBz32j0kZS4k9NWqZaLEg
         gIIOTwgGY8zp4zBPlyI0ic8oCAE1KNa9HZFB7t11Li7YXsgqUXcU2h2BuMm5vS8wo/PT
         xF8BA45PboLjnxhEcUjOYvqj3Kkz+Xg8lBENj5SdBwxeTE8+TwMFmmxqQyaERWkSj3iH
         mbyY+5lFBNrge6RuG5Gt96BqubbscT/fmoftSmWUcJp/+EvpHhryzBaAcVO9g5dd8jdl
         nUmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748013356; x=1748618156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:references:in-reply-to:user-agent:subject:cc:to:from
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qA5C3jTHUDmuXG2iAMCkE7EGQSqMXw/MbYdb+Z/EEKQ=;
        b=J6mHVNAfxvc1W6kgrPY6Vr5R6MpblP4vOddemlJCT6TMjPyYmyWRLaZENXhgSjWgnq
         CDzfegqqwu534KsgQS8QkUJ0xJOCjziPSYzSR/oABhlt0+0WxOsf4/mK4s7JT9lz/QjI
         nloU4kllIkT2v+rH6qSHi1BPzW5o6SYexyt4y8ktWzCNEEgYB3BrrU/LruENB24fTYKp
         Pt7ZgRcD7TyCMcFOxMBrkQfYMuUDc1U0Qimky9Z7H2GMzAihOa973uDeip0ukpGYMTmL
         ntGG08Rh3P9M2VbKrQ2ycr3jDOJYAyb22s+bZzR/Iv3w0R8PSqoBNK/8Vxp6VCgEc+NG
         VQZQ==
X-Forwarded-Encrypted: i=2; AJvYcCVWkZvG0faBuJb+YLbwgZnP194gsUtE2F1ezlYneLWKc/z6WMTw8xrJjrJVQ8XszuL1B2wH4g==@lfdr.de
X-Gm-Message-State: AOJu0Yz0UVgRLY+UoEIOcpEcMmTY6+XDPaxcEqzzgWLVvIOb99oZmW5B
	e+L7ZOS10e7tgklgAfQLaMqMMH3NWJ3S2RQtvMWfJ2RQKVv5tOIUxze0
X-Google-Smtp-Source: AGHT+IGEEduxse//rv7kSofTKt2HJ1HeYH3PkTsVtqCzI6fAmF1d7e3SkokOtCyiE9n6tHHcy7mMSQ==
X-Received: by 2002:a17:90b:5410:b0:30e:823f:ef22 with SMTP id 98e67ed59e1d1-30e83215898mr43277594a91.24.1748013356488;
        Fri, 23 May 2025 08:15:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEYQtXybV6qB1DUmExJe8++xyrfnalSbKC+T1lODFF/KQ==
Received: by 2002:a17:90a:a681:b0:30e:8102:9f57 with SMTP id
 98e67ed59e1d1-30e8102a2aals219737a91.2.-pod-prod-04-us; Fri, 23 May 2025
 08:15:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+Vavow0gV6IgUYhsKIBwIbqH18g3HATE5mczcmvTxLZ+9UxuXkwPPH5P7O8/7kr/lvq54w9Vsa1w=@googlegroups.com
X-Received: by 2002:a17:90b:5545:b0:2ff:7331:18bc with SMTP id 98e67ed59e1d1-30e832158e1mr37393325a91.26.1748013355130;
        Fri, 23 May 2025 08:15:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748013355; cv=none;
        d=google.com; s=arc-20240605;
        b=V1pC7Na0nDrcLt0tvccRh5TV8JhIW77jMhJdGuWfA601cyLQhgEqddBpA72G9t8byD
         +pusUyjDreDj+frJZSlvDvTfN3RjZArQNNxITp+CCOKTtixpp7YbvrQWZVbFgbiR2M9J
         DNAdg1D58QEMu6h5sMyPnego+3XckWNUinYebady4nZ+e07Fpmp0yRKgXDOR6cNIf+0A
         BcRXoXF5NU0R8vDa5eQFclMr/ItKWdyypfqkDp8WBl5LmyGUbiEw+qDoWEGapQSAHknn
         97VSe1WDDTJmgDh6jC9fONZXe93nsSZh9ZOvD3h/1Vj4O9WswiuzN8uBY5cAtHD0EvOh
         Vx7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:dkim-signature;
        bh=XWCE6jqKFyONnv3rqRo5aIekZYBw6AYzIcZy4RKLG3w=;
        fh=VGgemvk3FYV3sWcLWu3b9nJ/BYwnwO0h85qCLJqBLxs=;
        b=QHAUwFQFZLTwKL5c7gTbEIqCfGg6D+esVOfuAA9PLrQEb40LzNvg8Jg6oNccrbC2ui
         r10esTYRtdCy7bPbu0YQ44JlLlWJLXUOOMIMlwARkUhZVFGiKZHRQL/1qBfngWNwq7Z4
         IOv+fyreMMeR504QIdGd/FpsdnBlnClgShSj/3UfSQC86f3KhTmA41X7nEAZrQJsbRm1
         Em5/wMLKoLqG9HRZk1hccFvmofBOgjzF/0+7z7gGsq5wuepLvNaaIHioKSqrL6AoNNY3
         L59CWd7ZoKzjUckJhX9IKOx7v0Xz7jlcFCyvh+SBJ7iQnzqTgiPEuyt3HGdba+MAOf7+
         28mw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HX8ckC8A;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30f3659ec37si400969a91.2.2025.05.23.08.15.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 May 2025 08:15:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 3B52E5C5DCC;
	Fri, 23 May 2025 15:13:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C994AC4CEE9;
	Fri, 23 May 2025 15:15:53 +0000 (UTC)
Date: Fri, 23 May 2025 08:15:49 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Donnellan <ajd@linux.ibm.com>, Arnd Bergmann <arnd@arndb.de>
CC: Madhavan Srinivasan <maddy@linux.ibm.com>,
 Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,
 Naveen N Rao <naveen@kernel.org>,
 "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>,
 "Aneesh Kumar K.V" <aneesh.kumar@linux.ibm.com>,
 Andrew Morton <akpm@linux-foundation.org>, linuxppc-dev@lists.ozlabs.org,
 "Gustavo A. R. Silva" <gustavoars@kernel.org>,
 Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Ard Biesheuvel <ardb@kernel.org>,
 Masahiro Yamada <masahiroy@kernel.org>,
 Nathan Chancellor <nathan@kernel.org>,
 Nicolas Schier <nicolas.schier@linux.dev>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>,
 linux-kernel@vger.kernel.org, x86@kernel.org, kasan-dev@googlegroups.com,
 linux-doc@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 kvmarm@lists.linux.dev, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-efi@vger.kernel.org,
 linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-security-module@vger.kernel.org, linux-kselftest@vger.kernel.org,
 sparclinux@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v2 08/14] powerpc: Handle KCOV __init vs inline mismatches
User-Agent: K-9 Mail for Android
In-Reply-To: <e50abba6c962772c73342bacf20fb87dc99dd542.camel@linux.ibm.com>
References: <20250523043251.it.550-kees@kernel.org> <20250523043935.2009972-8-kees@kernel.org> <e50abba6c962772c73342bacf20fb87dc99dd542.camel@linux.ibm.com>
Message-ID: <6E407BC0-4D84-4420-AE07-EF85EBA1AB1C@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HX8ckC8A;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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



On May 22, 2025 10:24:30 PM PDT, Andrew Donnellan <ajd@linux.ibm.com> wrote:
>On Thu, 2025-05-22 at 21:39 -0700, Kees Cook wrote:
>> When KCOV is enabled all functions get instrumented, unless
>> the __no_sanitize_coverage attribute is used. To prepare for
>> __no_sanitize_coverage being applied to __init functions, we have to
>> handle differences in how GCC's inline optimizations get resolved.
>> For
>> s390 this requires forcing a couple functions to be inline with
>
>I assume you mean powerpc here, though I'm sure my employer is happy
>that you're at least confusing us with IBM's other architecture :)

Whoops! Yes. Paste-o on my part. The rest of the sentence was updated correctly though. :)

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6E407BC0-4D84-4420-AE07-EF85EBA1AB1C%40kernel.org.
