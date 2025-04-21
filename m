Return-Path: <kasan-dev+bncBD4NDKWHQYDRBHO7THAAMGQE4QEVD4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id B7D76A953F1
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 18:17:50 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-3032f4eca83sf3675184a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 09:17:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745252253; cv=pass;
        d=google.com; s=arc-20240605;
        b=W9zLFL1UI1T0Y3JJl7KE6uOG3bAFC3ZBWH/hcD5RCTxY+yEw5uJHn48OoBVnbX3pez
         tKnjdyzpLhytuDI0I8cAK7bwx3Ph//mT6DXVvECP6D/BJb34ilv88Vd605v1fwmFrauR
         yZvf1GdJYUQPFhFvHrf/4BN1akRdFT/dHaE6lfzdVycR99b9rOStvnyPO88+KQP/UB9I
         P1beAGWbNb5Ut/rq6FK3K0ly4VjDBLBl5oTKICtE+PrPr+FrYerTgRluVMJJB5qEFLJr
         s/LQlcb/mqaUOHB24cKZWbosZOEYZ4+dD0irTmPj+9jY2cfiqF/S6RN/yxiXjzaLerS4
         Tv7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=RDEF/8dCqNrZgmWU/yVo4TcEFhTWY/beD0XyX2m3pQM=;
        fh=6z5xNLFrhUXtPLdHAiR+sPxuc4PqsTJj/ECHWqKRsrA=;
        b=lMM2XrT0LcxdKTO01Cr7FIxn/tn5DyHW4mX+iMGrlrk/EAH2LoHRPv56V2eAozbJhP
         rHg90yESN4tmnfvG9t/h9Ck2M0VPqeUz6+irX54L77jG3WKuRFVwr374vfhhhtVELGsY
         ZqyH4nf1qzN+oeIuuZVZj9NSg/BxeyY5UxhBBupfV22UoWP5lXfoZJTuMNw1X2XmMC6C
         sUfLsJJQqfHyOGpMZhNJvEGCrMfLWzyw7aAIlt25Dr64gc0AZMT5M4CafWi+EHvjPMw2
         n26RySLn5nmjcYiXjHE7pVTW9MtQkpWEG2LwMxhujjH90AgOFRP7tY501etvdhfOCyto
         s7gA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RkEOPtLM;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745252253; x=1745857053; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=RDEF/8dCqNrZgmWU/yVo4TcEFhTWY/beD0XyX2m3pQM=;
        b=YHnKl+ZW/xkNVlh8Q2uitX+ThWOtNdHPiZkqvfqMMHoFQOFXFnSzV4trLu2PfvkYU2
         xFbCpdQalOunfCUgy25U5KmL4rIFx/XbisEgffR2WjYFqR/ehrXIjCQR7ldY3A2Y1ktN
         tXFsVmx0kZMzwSCz6I7Fcb3holIffvxy4h4R5pAf78OQTkkJXKonpO6OY+EzuBcfbODY
         UyIoLGQKMWyOgtI0wdJapTH/fVNmCNNvxBuOrmqTvDpMRHbcmItBxbdyF8dWI0DWsG04
         oYkJmX66TJbyGYXq/bWUlvat29CHbodZg2XRp8EUZI1yn372k2wIgZhwOHi78sFACdvg
         HHOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745252253; x=1745857053;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RDEF/8dCqNrZgmWU/yVo4TcEFhTWY/beD0XyX2m3pQM=;
        b=nzuSys1Eh9EdHU3SsTpsR04NFuc8nTaaI0kbzT4egTksYYUzPwOcS8thHReYdAcDv8
         gxYwwYm5ST532l0VJrTfLOVEhryLqF4ZazinSipUpKdOAfwdknaglzZ6aKf7CdtvCPB2
         ki2I5C5FYG1kOmG3Ylayu+JEVf4dktuufRUqUFfkEG1s0X6O+rOTmP/1yPr4CJqePfbf
         WJU+sbF34hnp+ZF9dGOJr/eJo6QqKxYh7kKmqxKv8FqIa2xULOJSsN+hAciJgy/ii2Dc
         TWNOewdtkPHmh4qK3l21ucc/iwQyoQe4lGwHCM/GvFGBkPka6mTDT5Cg+r4Av3VG81w4
         RAdQ==
X-Forwarded-Encrypted: i=2; AJvYcCXfyV9lzFqQLqPHd+pc6qv+aRhR5Q2xtWl8Uxlu7pGUcSnbp1nSrriy7pRjeY+gemrtVX7JLQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz8tzocNt3MT4NY2xTQE/VH9xrm6Fqd1TIxdsU7EJyhFRffc+FO
	CqZ3PtZdZKzyNGV51OJ5orBpq1pfhDqXzhOoxFNPWqrT3CCgXQAc
X-Google-Smtp-Source: AGHT+IGGAI53ub7UNaJBpvhs4HF9SIRZPlUE1RzIqEhNKl1KkkqaLxBmeOJFlrKWJyZq2bwNR74KKA==
X-Received: by 2002:a17:90b:3146:b0:2ee:e113:815d with SMTP id 98e67ed59e1d1-3087bb5341amr17600026a91.8.1745252253266;
        Mon, 21 Apr 2025 09:17:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIu6jPEHmWTe77cww6E1f5dR0bq5CbY5F9V85NPBeHS4Q==
Received: by 2002:a17:90b:2643:b0:301:c125:45b0 with SMTP id
 98e67ed59e1d1-3086db1e3f8ls3674599a91.2.-pod-prod-04-us; Mon, 21 Apr 2025
 09:17:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPBfd4fgtenxCiTlyX67angPnDIIYVDCdc/ERaJBJf1P8zmYdZi0DyqWw7MVkX1DI6xKfVBgzsPRQ=@googlegroups.com
X-Received: by 2002:a17:90a:dfc5:b0:2fa:1a23:c01d with SMTP id 98e67ed59e1d1-3087bb6bcaamr17623778a91.21.1745252252060;
        Mon, 21 Apr 2025 09:17:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745252252; cv=none;
        d=google.com; s=arc-20240605;
        b=l24WLGYQm/lbIGQ6HMgxOpoSz02a/CBk5kUy7QHf3rLHvqX+/DI9UyAmRzSBw0l/gP
         QMrKyF9mnEPGlIPe+egvm6pb3I4yMsAKrYxskymvt4bgZ8UT+n62GfA8jifH+ag+8UCm
         H5k3Q4AnhEe4uNgecB1g3cLK2rMppIWLB72HuJY4jVjL2N8AkCM0G2naqE2SQPR+ZGA7
         BtRMZyam9K3MsMGKteuyEUHfNmissLoDOfzngxbH2ofRWTB9k64BooM2vXQGJ/mdYGSb
         J5oo4NiEbHRn81Wf67w+aljiDqbAOlfuBcuv9gmtGLBKG7EiW63K690b5tihY9brY1wf
         YGZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KRZi2zCeNSkZi+s1ZDTsJt8BFsTp3vDCxh9f/3q8nd8=;
        fh=GbiEPuWRJZCEeJEgoypohjr9jba5PMaoni2A1/GAKzg=;
        b=DqpLtRFN7YldxkzvxBI3yEDsKfunDCspOlV31dsRJT6tPlS3awEQ2ZVg48T9MN/HJd
         skLGvdRtlgzQBBS+l8ieOxM/4AZzo2wEhX4O4O/QWnWN2MRjb02CbIwK321++bo71M6R
         RlhlV8uGuItFnwSzQ5QYC+ylA+cHxY1GFvSvZLPZts4gkQBEwf6RetCqggYjlNx9xEwx
         PxSyRrXvujIiiJrbxe8JCVltvLKr4oFv8BFYEL2lHFNzdd/zZWl6E7p2BrwcgwDBZHxu
         hVLN+80nZfm7qMiZaLBpyybaV0cdzjOMLDwC2KRT+VA1aRhKSGYq86elIIHxZxnPvqfW
         6YPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RkEOPtLM;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3087dddd5d8si9587a91.0.2025.04.21.09.17.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Apr 2025 09:17:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 2A8BA44F2C;
	Mon, 21 Apr 2025 16:17:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EE144C4CEE4;
	Mon, 21 Apr 2025 16:17:27 +0000 (UTC)
Date: Mon, 21 Apr 2025 09:17:25 -0700
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Christoph Hellwig <hch@lst.de>, Masahiro Yamada <masahiroy@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev, linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: Re: [PATCH] kbuild: Switch from -Wvla to -Wvla-larger-than=0
Message-ID: <20250421161725.GA3253782@ax162>
References: <20250418213235.work.532-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250418213235.work.532-kees@kernel.org>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RkEOPtLM;       spf=pass
 (google.com: domain of nathan@kernel.org designates 172.234.252.31 as
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

On Fri, Apr 18, 2025 at 02:32:39PM -0700, Kees Cook wrote:
> Variable Length Arrays (VLAs) on the stack must not be used in the kernel.
> Function parameter VLAs[1] should be usable, but -Wvla will warn for
> those. For example, this will produce a warning but it is not using a
> stack VLA:
> 
>     int something(size_t n, int array[n]) { ...
> 
> Clang has no way yet to distinguish between the VLA types[2], so
> depend on GCC for now to keep stack VLAs out of the tree by using GCC's
> -Wvla-larger-than=0 option (though GCC may split -Wvla[3] similarly to
> how Clang is planning to).
> 
> Switch to -Wvla-larger-than=0 and adjust the two VLA-checking selftests
> to disable the updated option name.
> 
> Link: https://en.cppreference.com/w/c/language/array [1]
> Link: https://github.com/llvm/llvm-project/issues/57098 [2]
> Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=98217 [3]
> Signed-off-by: Kees Cook <kees@kernel.org>

Reviewed-by: Nathan Chancellor <nathan@kernel.org>

>  lib/Makefile               | 2 +-
>  mm/kasan/Makefile          | 2 +-
>  scripts/Makefile.extrawarn | 9 +++++++--
>  3 files changed, 9 insertions(+), 4 deletions(-)
> 
> diff --git a/lib/Makefile b/lib/Makefile
> index f07b24ce1b3f..37b6e5782ecb 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -71,7 +71,7 @@ CFLAGS_test_bitops.o += -Werror
>  obj-$(CONFIG_TEST_SYSCTL) += test_sysctl.o
>  obj-$(CONFIG_TEST_IDA) += test_ida.o
>  obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
> -CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
> +CFLAGS_test_ubsan.o += $(call cc-option, -Wno-vla-larger-than)
>  CFLAGS_test_ubsan.o += $(call cc-disable-warning, unused-but-set-variable)
>  UBSAN_SANITIZE_test_ubsan.o := y
>  obj-$(CONFIG_TEST_KSTRTOX) += test-kstrtox.o
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 1a958e7c8a46..0e326116a70b 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -35,7 +35,7 @@ CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  
> -CFLAGS_KASAN_TEST := $(CFLAGS_KASAN) $(call cc-disable-warning, vla)
> +CFLAGS_KASAN_TEST := $(CFLAGS_KASAN) $(call cc-option, -Wno-vla-larger-than)
>  ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
>  # If compiler instruments memintrinsics by prefixing them with __asan/__hwasan,
>  # we need to treat them normally (as builtins), otherwise the compiler won't
> diff --git a/scripts/Makefile.extrawarn b/scripts/Makefile.extrawarn
> index d75897559d18..0229b10c5d81 100644
> --- a/scripts/Makefile.extrawarn
> +++ b/scripts/Makefile.extrawarn
> @@ -45,8 +45,13 @@ endif
>  # These result in bogus false positives
>  KBUILD_CFLAGS += $(call cc-disable-warning, dangling-pointer)
>  
> -# Variable Length Arrays (VLAs) should not be used anywhere in the kernel
> -KBUILD_CFLAGS += -Wvla
> +# Stack Variable Length Arrays (VLAs) must not be used in the kernel.
> +# Function array parameters should, however, be usable, but -Wvla will
> +# warn for those. Clang has no way yet to distinguish between the VLA
> +# types, so depend on GCC for now to keep stack VLAs out of the tree.
> +# https://github.com/llvm/llvm-project/issues/57098
> +# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=98217
> +KBUILD_CFLAGS += $(call cc-option,-Wvla-larger-than=0)
>  
>  # disable pointer signed / unsigned warnings in gcc 4.0
>  KBUILD_CFLAGS += -Wno-pointer-sign
> -- 
> 2.34.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250421161725.GA3253782%40ax162.
