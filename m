Return-Path: <kasan-dev+bncBDV37XP3XYDRBTNTU2AAMGQE2RCB3EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 05A362FEE24
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 16:12:15 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id t10sf1983484pjw.4
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 07:12:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611241933; cv=pass;
        d=google.com; s=arc-20160816;
        b=v6wC3UUzYf/93aCMRPuKVd5Okt+HcXnzFnLdY98Q5j7mL2BexVoKZQw08bI3UIupW7
         eAE2jxAVlgH1Ti3+xQ6J7pto7krAOKbdmJJGy7tYTtCd3NrTr/gAM+0xqB1BUanr5HJD
         aRDMXRBlAaGanK3/D3qKdErgx4g2WyGeYo/zkMcY827Xo+mBPt4fNP/eQgK+9Vvxu3cF
         eXtkMAP4FbOiozx08+SRl2SnXAZ9biZtHoSyHw/t1xxMpEfH35oFAf67jwwYDWKIEg5y
         72I+mFM41bDODKyZJQE+vo9V0qVEjTgrh/5f6Bm79C9MAkH1kH3eXR9F+G4LaueNPXba
         9m1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bmbz2j9dtwH4FFyUjprmM7YbzyJyKFtNFAvgKz28pN0=;
        b=spLQb8NYO21Ttvksv9HNcynvGmbz7nWW4ADwAm0kwzmL6hfL0vKUIkO31cyLnU/uoX
         uxCzQCkJPXW+1iYZdRLtNhwjiy3KehmH/ZC8KfD6CGxvqY8DQYU9QTfzS1hMyqHTcHtJ
         o7UPZPYoof7VNyRtsyBstxnOmvm/Z/Iv/lVSZvF881TKWj0j8gKrRAvtZmSy4hg/udQv
         XxjgWqMQafwuLlTnKbmWtUmYttOaNxbwpE/KUYGT0xVM149UhZQ8956ogPeJIvjWQE7q
         44TSBBlRNadpEhM2aRdSHvNHrhdXjurmuj/geb1QQre5bUHi5aT8Dk38rkGD/u8ywPZI
         Bamg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bmbz2j9dtwH4FFyUjprmM7YbzyJyKFtNFAvgKz28pN0=;
        b=rYTeQLo8jjZUl4zMXbYmE4u6MHBZXMrhFYtbtWJdhUNSwiTbQrPzj/wYAPuWb2bYVf
         UA73sKqlc0X60hEw0GOFPk2Y0MBDc1ewwxFSG0S8ihWc37tAFUQmS/Hy8SLjXRmuguka
         twy1WkE1JwWxK7kKc0vFCe74hLz1Um5ryAHVLcUEYUnMG1ucgxMZjiIDnFX1svRmjp8T
         b9tFDCQ+0xMvGBeRzYVxYUSD49DuSUwkNXYwN/ZtjWDpTIYoREQ1Ad2jvrAcjkyPbDK3
         NukGKaRxKy5bINGiK4aRKHi9wHJIuUnN6C1NSZtRIyRzSEtsSMW9dztUuzd6btxx8t9d
         2OjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bmbz2j9dtwH4FFyUjprmM7YbzyJyKFtNFAvgKz28pN0=;
        b=h25SqZRLAWv7G579REppdqc5bdFW4EF8WJ14S9CwVLUoNeWB8Moj+9kh8L7icYbwTW
         /y/67UsGrn6Fjn/ZK4gb2Ll+0HyplZt3of2+GvClFQis+p9xwcDXDBGppNdND9vSsIh8
         0XNIkhEDA6XPwT/XuF9BLmtx4GTXHWJ8QC+diafxeVVBkl6DzqCNa6WZWDIqTpQvhN0C
         nRbhl8qwS3MK53FGKRDnUmhyc1pPbkA7uihJgTEoOkWOp5bgT/hWwlPHr1mEww0U9DvR
         qUzyF+My7AhWaYV32VQ/Jbb12v+S70VFoEphL0loK/+vAwdyw+f5sLbQ45VwxIp7g4F1
         2NqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qITR2kyndu9/+mgo7/dLtdML1ykLwYptTElgdvpu9YWzBV5cV
	1MHjkNiwosKIuEde33sfD4M=
X-Google-Smtp-Source: ABdhPJwo/JT5JGsZrXbx/q346sifqR5yOmvDNA4HHZTaJh36huGakbD6jvq/5AYmKrX+xMM5ARnXJQ==
X-Received: by 2002:a17:90a:fd0b:: with SMTP id cv11mr12427929pjb.26.1611241933729;
        Thu, 21 Jan 2021 07:12:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ea89:: with SMTP id x9ls1298634plb.2.gmail; Thu, 21
 Jan 2021 07:12:13 -0800 (PST)
X-Received: by 2002:a17:90a:bb0d:: with SMTP id u13mr12569727pjr.106.1611241933084;
        Thu, 21 Jan 2021 07:12:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611241933; cv=none;
        d=google.com; s=arc-20160816;
        b=Q9fovLtnt//qKHQmW24duyIeqq6QfKku/RY1I9gVft5n5UyBDI8XbYI5Vg1gn8oVw5
         q+FbSvghTzsKlqOpjxFWMyPaCCs2C7KUTVimgRZoqPJKGv6p1iEmBkv6sB8yQRgTJfQG
         17wYxHKP6Fi2+ADuFvB114S2n0CdtcYUaUisW5L4m2xf8PMIK4Gl9zv6P5KYVJF6jr6Q
         GIqbpg+IBoQsR0mY3gOk+T/KjZkJXk54HVcmiBCHvHdL7JyASIMu3R6BYVhVcc11WoCw
         Cy9cS1lODL7dzqZI7AC28F85C1HI6XSdVKi8Jtffu8AHNQcibYG0/bTkboP2Q14i8P4B
         yqdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=X0xJ2n4F6uSOmtoR5/a1617ZGRlxG0BBn9ldRtkyGm8=;
        b=zDT+kEcp1P/80UZKjLHJbi76YMqndZpql3ryrypshq1T6gRbTxTa96doSj5MfCszuh
         oxWSKAzt9TgzIzIO3wKVCg8wRAb2Kw3Wn4rvNeeGNNhoZpgJZHj+3L5mugMMG1N8FGS6
         O+9A32Kf2+/MroE+aVAXfvTEqDfOXDYgRiBZoZCoU72sLSPqvp4aFctzyygKPRn3xPZM
         c0FoPmQp221o7P1AvTHy/rp5ikPxAwWi8VzwWdJTP3qztoZ4nR+FqDH/aGV3SWR2l4qz
         pEzH6fv8LIy2t45uk1vlkEfYCRr3gu8il5Ot6pfkozGFczDFwdYnhIphLrVxQMOpTJML
         IxTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b19si320848pgh.3.2021.01.21.07.12.12
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 07:12:12 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F2C9A139F;
	Thu, 21 Jan 2021 07:12:11 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.35.62])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 34E4A3F68F;
	Thu, 21 Jan 2021 07:12:09 -0800 (PST)
Date: Thu, 21 Jan 2021 15:12:06 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrey Konovalov <andreyknvl@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>
Subject: Re: [PATCH v2 1/2] arm64: Fix kernel address detection of
 __is_lm_address()
Message-ID: <20210121151206.GI48431@C02TD0UTHF1T.local>
References: <20210121131956.23246-1-vincenzo.frascino@arm.com>
 <20210121131956.23246-2-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210121131956.23246-2-vincenzo.frascino@arm.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

[adding Ard]

On Thu, Jan 21, 2021 at 01:19:55PM +0000, Vincenzo Frascino wrote:
> Currently, the __is_lm_address() check just masks out the top 12 bits
> of the address, but if they are 0, it still yields a true result.
> This has as a side effect that virt_addr_valid() returns true even for
> invalid virtual addresses (e.g. 0x0).

When it was added, __is_lm_address() was intended to distinguish valid
kernel virtual addresses (i.e. those in the TTBR1 address range), and
wasn't intended to do anything for addresses outside of this range. See
commit:

  ec6d06efb0bac6cd ("arm64: Add support for CONFIG_DEBUG_VIRTUAL")

... where it simply tests a bit.

So I believe that it's working as intended (though this is poorly
documented), but I think you're saying that usage isn't aligned with
that intent. Given that, I'm not sure the fixes tag is right; I think it
has never had the semantic you're after.

I had thought the same was true for virt_addr_valid(), and that wasn't
expected to be called for VAs outside of the kernel VA range. Is it
actually safe to call that with NULL on other architectures?

I wonder if it's worth virt_addr_valid() having an explicit check for
the kernel VA range, instead.

> Fix the detection checking that it's actually a kernel address starting
> at PAGE_OFFSET.
> 
> Fixes: f4693c2716b35 ("arm64: mm: extend linear region for 52-bit VA configurations")
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/memory.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index 18fce223b67b..e04ac898ffe4 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -249,7 +249,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  /*
>   * The linear kernel range starts at the bottom of the virtual address space.
>   */
> -#define __is_lm_address(addr)	(((u64)(addr) & ~PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
> +#define __is_lm_address(addr)	(((u64)(addr) ^ PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))

If we're going to make this stronger, can we please expand the comment
with the intended semantic? Otherwise we're liable to break this in
future.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121151206.GI48431%40C02TD0UTHF1T.local.
