Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBS7LVOAAMGQEXUC2FAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 614643007ED
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 16:57:00 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id s7sf5782797ybj.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 07:57:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611331019; cv=pass;
        d=google.com; s=arc-20160816;
        b=QWY2IZnfryjev1cc4kD6hYLkyv8w2ihCOkVTwAhbDabqgKEpijSEEmT50ooC+pfZll
         Vxf+96yQRpUg6KkyZchwmipCmU+1p6TzgqoAAAVp2Nb/mRxys58Hr43hDYzfE92IkO1d
         FEnlk2P8sYYOQjRU3fr+VgMmMYiZH4lza17QnFO2geXyaIGkg1Cd2eQDaYKbvjtypmtK
         c5zffMncqLc/UvDunVdPHaTWL8FjMYn1L1G3xZ+9OnzfFSGAR1WBDJKDL/LmVtPkfQ1a
         HRilufU553YIWmwuMACI9AjKDC3oxVW313Wv6Zzz0KQIMOONgU988WR1CRdASTs75yqR
         dIRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NDRQBdIOgPFLIakGcZyC7e+u8r0/50wt4k8uLGXqUJQ=;
        b=Ynnj1CEqgARzrWaq2UtbuTVxP7AdqA+KGlwNa/MjsfOh9j7Fkwpz6c6TwKC/eoqb81
         8QIiMpjmA3iVwGLj1x09a71+/LeP0ONwstKAPevGwq73A1LeUtyuP9mT1LMfgsphPqY0
         DSVhLD+Lxdvw9NeE2hEB7obhc/ccsOG0QWHk6CJ+Uv8sL+1GHLnN8Id60d5cU+P3f/gb
         ALGlnVMxT1PoaB5iy8fxTAYtdiR0M9eQvi12SppHovHKTGFyvzyq7WlWgflRIOlb3F5L
         tdlcft1GiUoia5szurwzWgkBfyizJa6GRZmOjMbQjqZUxhGfgmQL54l6dCUkpxudmJvs
         x9Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NDRQBdIOgPFLIakGcZyC7e+u8r0/50wt4k8uLGXqUJQ=;
        b=fk19p3054A9hPlLRf11ulmBfdk2IvK9XHxhkQfXMuDk0sqn7HSwEeCsPZRXF+mi8bW
         7OejWUm4q+ps/fpNZvDVja03eaUZMbVymh5X0E0+zsSgpSO8SLTlLnYsZaMGAVnNo1BF
         eiKJOzQsbQKoM/dyUzhOkGX2jc4L6qsLkDTj5zpJaLd5AjxtgRnuRtNmF906NE8ErRBE
         6/H5NZlqeclg5zrVsFN5JK/G8UQ6LS4YjL9EOLPvIRidqHtttG734pc68QLXwgdtnBx+
         fDznBrsjqpUS44ZNiUPTetMsDr50eqkw+SYN9gSAaZKsUMr5tLWwzDY5gtzgg4+lTYJt
         0IjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NDRQBdIOgPFLIakGcZyC7e+u8r0/50wt4k8uLGXqUJQ=;
        b=ZcNU2nEjrBVCm0JSm1fLpM8eNHiOtGZXBC0d0sED0h/Bi0K0bpvtVyFlC/3PDSWQpy
         WDUb5TeyyCn70RR00ufAmUzYiKy8wFGcE2y5DcWNXl7kqeCBk/h3Ru/nIbnHtQYXLBHO
         zfHLoXzb929P56mr3gx3qTpM5E0X2z0lz5C6H+ifE8I8ipNzWkYoMeHXxundSCRd8qYj
         ESf0oGfSqYxEEXqGQbQGeHLrcbtWkIw9pT9eiSmh80izeesz1jBxV219bdZvAVgaWh4n
         h5QhuKmsr2fDX8NBahUOS/8OFq0ufOEWzMjYNZD/WL+I9ntkyXcbyZF0NEyoBKUOqO71
         yurw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zxzjClQPRO+4rdceK0TE7QMdZ2cqTpvlN76cKd0q8nwNozOGX
	Et0qt/aatRjfpYC+i++s8BU=
X-Google-Smtp-Source: ABdhPJzijsCWZeoa9EfzCP7djk8ps228lMIrk65DMhvjplPUu9Tl2TUiWuBNCvuB8f7W2ZNCCRhzng==
X-Received: by 2002:a25:76d2:: with SMTP id r201mr7392628ybc.107.1611331019474;
        Fri, 22 Jan 2021 07:56:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2f84:: with SMTP id v126ls3162709ybv.11.gmail; Fri, 22
 Jan 2021 07:56:58 -0800 (PST)
X-Received: by 2002:a25:addf:: with SMTP id d31mr7250356ybe.473.1611331018579;
        Fri, 22 Jan 2021 07:56:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611331018; cv=none;
        d=google.com; s=arc-20160816;
        b=Tz6qZw9C8UGzsGYUV51v7p/atMum6d0rMOFxGKf/3/RpttuCRraQ6pedFBGF6eheNs
         jIUogBXQOeb8ynrDNE0M/TFt/VB70bNDVFjllobbFII1QC9i/60JFsJ/1hMcoIlxaLQn
         ZLteby0HkMxfVnCi6uYW4Xc+Bbg5L7cI2fbmZU8zhnTYO7nyGRJXjqyzBRhRdAI51iS3
         f5coKa7blZTsn9qJ5FJdDmSdK03rU55HXBk9sJd+kdlAFT49BZuwBQrW7UKQz4ogMDIi
         4bx2zo7LmuXux+Y+iCvfJ/YxTYUWOTVXb9yHnY0UHiVxM/rzkgDhT+ZB/PvuE3tQY3C7
         6uLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=jU4BI0cXFTwXwBOqzna996YRc3D/cTs+LCMf1HUdhxk=;
        b=bRdNMboYj7jhZ5IMt5p3Y4WWdByudzLEclTTJ15o/noQhiFxM5yg101OT+aMR/Pm0w
         HzYYeqR+Dss7RgflYEB2Lj/Wya4un1RjnSAjt11Hzy1ki1ltDDA3OJA9sPabNN/EQSbE
         v+LiP9rxpD+XSeURiA+fhPxPTJc7fzF8jCI8AowPobkSjUfw7ulxnWpshl+KGgZR30nW
         EkvNknOIBoeg6QLKCZKnilkxaHitiISsWXEmZbvWbB5TDx5GZGOF8NVGSxuMt32q6ZlT
         b0TTipHQSL17asAgFonzFpFYzS80yYInM+GdFRhSUubZRJsfiGTxPOjXRKRFg5o2nM7i
         dKYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x18si643669ybe.0.2021.01.22.07.56.58
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 07:56:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0AF53139F;
	Fri, 22 Jan 2021 07:56:58 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4147E3F719;
	Fri, 22 Jan 2021 07:56:56 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: [PATCH v4 1/3] arm64: Improve kernel address detection of __is_lm_address()
Date: Fri, 22 Jan 2021 15:56:40 +0000
Message-Id: <20210122155642.23187-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122155642.23187-1-vincenzo.frascino@arm.com>
References: <20210122155642.23187-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
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

Currently, the __is_lm_address() check just masks out the top 12 bits
of the address, but if they are 0, it still yields a true result.
This has as a side effect that virt_addr_valid() returns true even for
invalid virtual addresses (e.g. 0x0).

Improve the detection checking that it's actually a kernel address
starting at PAGE_OFFSET.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 18fce223b67b..99d7e1494aaa 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -247,9 +247,11 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 
 
 /*
- * The linear kernel range starts at the bottom of the virtual address space.
+ * Check whether an arbitrary address is within the linear map, which
+ * lives in the [PAGE_OFFSET, PAGE_END) interval at the bottom of the
+ * kernel's TTBR1 address range.
  */
-#define __is_lm_address(addr)	(((u64)(addr) & ~PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
+#define __is_lm_address(addr)	(((u64)(addr) ^ PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
 
 #define __lm_to_phys(addr)	(((addr) & ~PAGE_OFFSET) + PHYS_OFFSET)
 #define __kimg_to_phys(addr)	((addr) - kimage_voffset)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122155642.23187-2-vincenzo.frascino%40arm.com.
