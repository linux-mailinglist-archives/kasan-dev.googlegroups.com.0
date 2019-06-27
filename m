Return-Path: <kasan-dev+bncBCF5XGNWYQBRBLWT2PUAKGQEFSGKVUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id CEA85586A7
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 18:07:11 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id t196sf2948318qke.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 09:07:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561651631; cv=pass;
        d=google.com; s=arc-20160816;
        b=TBi1axaMORyM5mRGMw30yOSJikFUVvgSN5pJVK6RaeIkv3osNzoMuenJ+4RwVQY6A9
         4ayY9/wGmiVlK90/sUkM2f22zY6IOMtokMoocrjanLQ08RCrYQIFvQqruedBW1rExZvU
         UyVMO9kEiTLLVUbgdhG46H1RUuP49CPuwtkR7ZcskxYEnrzVIxFgegMmUgki7S3o82T4
         GpDYsUZgZu+nNjJKFCDcAmNxY7Q9e7CKA5lIMTcnsEyw1otxXK9+1g5QrsRUtaFkD9h0
         DhgN1wEPZ+wwLWj23gCdQokRtHYCPKir/xrFg5s38tARdMdS28xJbxzTIeoP5ZKx8awN
         UDzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=z+hKuVbXE7HOTJ5K2dUXHXRxQl0MTSkRx6Kq8UGaUrs=;
        b=rEExo6gJfFoNnsHNtCK/cYergXX6bUPoT5A0nE+7aCyg7+xFDpw8P2oEnsvZSISxi3
         /Xfq13LeIQj6Do7MIHvttovyJvbBV3C6SZHYfAma5x0viUgi6aRI3j4uJ0uUkgtDFj4y
         Uop3ZUs166aqsSq/klT0K2hjkFGvbqp0ycnkve5Is1BqcCEfgzto3qpLMnRm6pzzK9zb
         r5D2FdaA1zhC7/E4R8hV64opa7b1byhx59Ww+qOMrtNeU3e46mYLJlBbFeOpKAh4KEtY
         y6WuzxCpf0Z9JiOTn/BKUnwocu2Jm3rcdlONj9jgxnltfYU4gn7NZ4+VzbhDKedszNRP
         ABnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ZM5jrqkf;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z+hKuVbXE7HOTJ5K2dUXHXRxQl0MTSkRx6Kq8UGaUrs=;
        b=NpY3AjT0keHOy4DaicRJIO3TysAJot1xuErFqKohZHmBtgunniBhuEMgY7OvIm/TLB
         LvS2fHQ4NZ9tOH6plGbYGy+MjhvkOojNlai155dOicyN4pbO3uY5PL53mCCLRIpyHHF3
         db/RUg7EG/AW5iPrSicPi1p9yqT5ZgVDglXe8Ri19QnHIi8bOAzDjAn+MAYNeie/LJK8
         PNHchPrpgPh8KmHiDnuYvID37Ba9ZkBteXt11KJF2u0Bhxn2b45E2trk3gQFDoVhvXPq
         oMs3o0c/BNYqtB1tAuhA44wi+UA0uqxihvOGQWU5ANN/FMtUirKHvkZ8+3OeVODvSb4T
         D29w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z+hKuVbXE7HOTJ5K2dUXHXRxQl0MTSkRx6Kq8UGaUrs=;
        b=ZQHU/j9Imv9Lkp9BwvBNmNfd4/ekX2c1LrYOEh0lhPKPEXT6ApcojEfkj/aowQebe1
         mJOlZ1UxT/Oqk4lDe8WmE/KhlgN7PTEzLld41XXSCWITem3nw6+eN0k88MIZDc/CL3RU
         i7bUmACdTkB6BOPWfqnMfcNP8pF3B/bMZrmQvU+igj/EGPTTjZ7YBCP+yRPR8UEZcimV
         qPjqvfST5iqdBuFO3NfXE59jCzDsmMt8g3vEdcfahSpZVwVvdRcatGcSK/qpZpuPpnLz
         2GdYs9Fb2DacEJVomkMtNJIZM+tFQSvOucoU2YZJpHKS52XhXjnkR02i1F5UFlIq/SAf
         RDTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVuwI9lZ2Cu4XvYNWxnlNFLy+BlbXsUjLjtd3zxiYzvtkCzQ5v2
	ZiAiXdhshHb8GneMgbpFkvk=
X-Google-Smtp-Source: APXvYqwnncwVnhMHV6DH5bJk1UdX2yD4MS7RjLq2UmkZO1C/cU9RL/MgeypaeWBS3yahu5mJUXf8pQ==
X-Received: by 2002:a0c:81f0:: with SMTP id 45mr3970579qve.13.1561651630926;
        Thu, 27 Jun 2019 09:07:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:91f5:: with SMTP id r50ls856372qvr.15.gmail; Thu, 27 Jun
 2019 09:07:10 -0700 (PDT)
X-Received: by 2002:a0c:d295:: with SMTP id q21mr3852382qvh.245.1561651630676;
        Thu, 27 Jun 2019 09:07:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561651630; cv=none;
        d=google.com; s=arc-20160816;
        b=uTqa+9+sxE/SN5AHr9jk1P+Jlgq7oi/yXAQ3ft6sQxykkg/Y8oTpvwdVLnqc14uQQy
         9UcOFqbEcnx/wSo4k0CRkxgWN4Cd7UhvyCjxeSge9BTh4/7gDM9CDkMPAXXNzeA8bCQ6
         1/jv3CKYWZjRXadIVnKyos71Q/9kHBgL5UwymzONjdQAy5XHyMbvEXst7LRy2qUAK57J
         oOkybdbQW/KCm5m0gn7NHI2XVFvJ522UFttvKm8Ps9Y978hPdSvSKjkHYFKrfHKcjw9k
         YA75qcsh2P7q4HGwfGxWWpCNyqMdV3KhXaUHUv0MTlOMAxBHRF9VPWM3PYsbDDfTZaSj
         5feQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=YubArmml1h3da19oo14hDKUh4iUk2iId9IFXcb+lgfE=;
        b=uFDNnrdkebgfgqN8Arr72BjgMjo+XIVEovBGTGJEe4eMkDkmUBhmUkJc4ENOGmULfG
         jx10d7ZdSD4FzAREPmYd2fYwr24WR8eGNxFyE59vRp32VYaGH6GrFr8PcAeGE5U6GbU4
         F9v2yDge0xb13EJZ4fOd7+rvuxTzjb1NJ6lrWZVZMWpKpn0sMZDyTsZOL47VJYK8ZKtB
         9GDKcr+OHA7REhXNOdxme3dMTkkLeXsQZEm3OYXzzChJUUXFV/QRcHwF64zecnsJeUmn
         Bov7/0fXh/koh9mAA0eZ1sX3R2aamNFsZA09XjnH4SflLnif1EmP2cv1cT5H5unhRCov
         WnAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ZM5jrqkf;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id r189si96275qkb.0.2019.06.27.09.07.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2019 09:07:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id e5so1527677pls.13
        for <kasan-dev@googlegroups.com>; Thu, 27 Jun 2019 09:07:10 -0700 (PDT)
X-Received: by 2002:a17:902:4222:: with SMTP id g31mr5760668pld.41.1561651629814;
        Thu, 27 Jun 2019 09:07:09 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id f10sm3514357pfd.151.2019.06.27.09.07.08
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 27 Jun 2019 09:07:08 -0700 (PDT)
Date: Thu, 27 Jun 2019 09:07:08 -0700
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Mark Rutland <mark.rutland@arm.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH v4 5/5] mm/kasan: Add object validation in ksize()
Message-ID: <201906270906.9EE619600@keescook>
References: <20190627094445.216365-1-elver@google.com>
 <20190627094445.216365-6-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190627094445.216365-6-elver@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ZM5jrqkf;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Jun 27, 2019 at 11:44:45AM +0200, Marco Elver wrote:
> ksize() has been unconditionally unpoisoning the whole shadow memory region
> associated with an allocation. This can lead to various undetected bugs,
> for example, double-kzfree().
> 
> Specifically, kzfree() uses ksize() to determine the actual allocation
> size, and subsequently zeroes the memory. Since ksize() used to just
> unpoison the whole shadow memory region, no invalid free was detected.
> 
> This patch addresses this as follows:
> 
> 1. Add a check in ksize(), and only then unpoison the memory region.
> 
> 2. Preserve kasan_unpoison_slab() semantics by explicitly unpoisoning
>    the shadow memory region using the size obtained from __ksize().
> 
> Tested:
> 1. With SLAB allocator: a) normal boot without warnings; b) verified the
>    added double-kzfree() is detected.
> 2. With SLUB allocator: a) normal boot without warnings; b) verified the
>    added double-kzfree() is detected.
> 
> Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=199359
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Kees Cook <keescook@chromium.org>

-Kees

> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Christoph Lameter <cl@linux.com>
> Cc: Pekka Enberg <penberg@kernel.org>
> Cc: David Rientjes <rientjes@google.com>
> Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Mark Rutland <mark.rutland@arm.com>
> Cc: Kees Cook <keescook@chromium.org>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-kernel@vger.kernel.org
> Cc: linux-mm@kvack.org
> ---
> v4:
> * Prefer WARN_ON_ONCE() instead of BUG_ON().
> ---
>  include/linux/kasan.h |  7 +++++--
>  mm/slab_common.c      | 22 +++++++++++++++++++++-
>  2 files changed, 26 insertions(+), 3 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b40ea104dd36..cc8a03cc9674 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -76,8 +76,11 @@ void kasan_free_shadow(const struct vm_struct *vm);
>  int kasan_add_zero_shadow(void *start, unsigned long size);
>  void kasan_remove_zero_shadow(void *start, unsigned long size);
>  
> -size_t ksize(const void *);
> -static inline void kasan_unpoison_slab(const void *ptr) { ksize(ptr); }
> +size_t __ksize(const void *);
> +static inline void kasan_unpoison_slab(const void *ptr)
> +{
> +	kasan_unpoison_shadow(ptr, __ksize(ptr));
> +}
>  size_t kasan_metadata_size(struct kmem_cache *cache);
>  
>  bool kasan_save_enable_multi_shot(void);
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index b7c6a40e436a..a09bb10aa026 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1613,7 +1613,27 @@ EXPORT_SYMBOL(kzfree);
>   */
>  size_t ksize(const void *objp)
>  {
> -	size_t size = __ksize(objp);
> +	size_t size;
> +
> +	if (WARN_ON_ONCE(!objp))
> +		return 0;
> +	/*
> +	 * We need to check that the pointed to object is valid, and only then
> +	 * unpoison the shadow memory below. We use __kasan_check_read(), to
> +	 * generate a more useful report at the time ksize() is called (rather
> +	 * than later where behaviour is undefined due to potential
> +	 * use-after-free or double-free).
> +	 *
> +	 * If the pointed to memory is invalid we return 0, to avoid users of
> +	 * ksize() writing to and potentially corrupting the memory region.
> +	 *
> +	 * We want to perform the check before __ksize(), to avoid potentially
> +	 * crashing in __ksize() due to accessing invalid metadata.
> +	 */
> +	if (unlikely(objp == ZERO_SIZE_PTR) || !__kasan_check_read(objp, 1))
> +		return 0;
> +
> +	size = __ksize(objp);
>  	/*
>  	 * We assume that ksize callers could use whole allocated area,
>  	 * so we need to unpoison this area.
> -- 
> 2.22.0.410.gd8fdbe21b5-goog
> 

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201906270906.9EE619600%40keescook.
For more options, visit https://groups.google.com/d/optout.
