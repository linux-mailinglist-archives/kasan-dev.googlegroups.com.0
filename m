Return-Path: <kasan-dev+bncBDAZZCVNSYPBB2V3QGFAMGQEMDRDRFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CCBD40A93A
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 10:31:39 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id c11-20020a17090a558b00b00199191acca3sf1347084pji.5
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 01:31:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631608298; cv=pass;
        d=google.com; s=arc-20160816;
        b=G9Cl/lRIJYhbRnPKy8mbf76FUlg70o6Xl16StYOAsj4vS3Zsu2eqUEnXHp4D16JkB1
         ieIaeIWil//nI7YmLzQ/JlbtThRArNyD44LOk+x7M7GA/cej0lVBkbmnUCvHjVgQpjoO
         413Sy3CsQCbkgCjlF10f3HtzvgZEzVE/sR2muAEmU/alWbFx5akGWm62/cpaTMCMug/p
         jnsYEDGt3JrPDQ540sA/cMBQk2EP1nRGQok6fYSnypaN4+Mx8hzcQHswQxbGr/xgcUCC
         +kxVtfgTBO2xYqgJ/+BnZN1GoKh4+4tvNL3nH4wrnJY2QPkQmp1aNaxM6WGEfWeOzh/J
         l2Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=8EEvVXizxHuqO+nAt2n4LWYfnzlS2PYZYAPnQhKe8UA=;
        b=TvvDtUDeiUeo5IRammKdTJfBXe8jejMdLKH/hvO7TvQnzg8mBGxzBgeMJK3tU0joz5
         q3cv30JA11tHoXR3N4Pdj/zejyYAprRGAoJNPpDS1Jciupx1EyifuTQjmsiwZ8KKYFo2
         kN/WOspyK6d9FrCW9LmHAhOOzSsAL1utl+IVjoc8IB/CwzkZIC2o06Tv5gKJzOzOKBxb
         etZ3KF3BTximpwvbJA49uip8p6PDfof3VXI5mLzZQu2ig8qbYdqGgwj9FVq3/1wb62xO
         uOw48l1obQ2asx4AH/Su/94VgqINOowX59culaxuuzWlPUKiFwFxdJyEa2XS/NO6Lf+g
         fqXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ie7BWsEU;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8EEvVXizxHuqO+nAt2n4LWYfnzlS2PYZYAPnQhKe8UA=;
        b=YdhpagKo5UFfowdbv2H5VwWKG3x+joEutYj0xn+kG1YG5uKc/OuKrwfPxxQ7m+tIIl
         MySkg/I2T7UOwpK+wSu8o5Q/C3OqbQKwUg6B7a3VxSUJbzxnkc70RaFV3KP02cyGJMK6
         UL7b78fyNV+7TtPWaLBknQ4QoG2kF1t6lahjyjbHrT6lJuYgnlmNnIWKipgKCyGzZc8c
         Ip6BeXKKkYVWflJP+poACNgEGwiD6qWBGYMTa21h7zpTbGHHmFSZKpVylll2p1xrRmpd
         dw2O9iE03s4uK9YjrmgOZwG6Y8J4fbvG281Hfr4vCJDwJ5ZinVOKHZWo3TTEwRQ0gB23
         dz7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8EEvVXizxHuqO+nAt2n4LWYfnzlS2PYZYAPnQhKe8UA=;
        b=3hTPU90wQ4seqselwSRyDqCeTIEcCV6veX/Uez2FWz8ulO9Nx9WxkWjNx3q9SCcdz+
         SHshR5K1xzFjU1Wi7DJ8YL5WArcyDM6ujtKPcenpzV18oFEAHg/5o8MynodghwQExnAW
         h5shxbl5bfE72Dg7QaIOyoOBaY+UKhPsOPsNRK5AF57vcidihm5mcqzj9hLq/WhJVjMi
         c/nmQqUIO4ZP5B0aJ19QnMJz5JchYaNPa3OSTBK5I4+XNpFKZEvIl4OFGIj1MSQxZWyF
         VegwcnQzWkva71DEWKsMOBlEb+y0rLV0HJiCLMCWl8YqrbnWVR2hgGS+aTKm9RKlsY1W
         hxyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KM857tL/jrX1zTRZtWqhCvOFq3Fq9S4Vg0Bhc41UA/VZHWZUO
	EZ0Q6vBCjSvv97fvEzYcu0o=
X-Google-Smtp-Source: ABdhPJxBoWN/upaZu4864XpO/4U5jD8Bfaj5tr6x/sSdg+znPg7GCLE/yD5/iDwtSJftRUPixNVwyw==
X-Received: by 2002:a17:90a:af86:: with SMTP id w6mr807779pjq.8.1631608298371;
        Tue, 14 Sep 2021 01:31:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:830f:: with SMTP id h15ls3696784pfe.6.gmail; Tue, 14 Sep
 2021 01:31:37 -0700 (PDT)
X-Received: by 2002:a63:ef57:: with SMTP id c23mr14437205pgk.60.1631608297876;
        Tue, 14 Sep 2021 01:31:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631608297; cv=none;
        d=google.com; s=arc-20160816;
        b=kFoJuz3Eukcke+oqInM4+J2rxZMb2fPj/Qw5q4BlvAVHoIioPkbVbQfu4cmQjZKZKZ
         I1brI0T+B7nxJQ9p2l6HbS3rujIcN3M7z/mOoxiEz/tS9k1YuGiRnk8NtBs2bltTAQtR
         TKde4hTCtEPk+jR9SWoSVIQvDEGSgguaqGzNEvdT8lh99S0tN/vBfXAB834bAX2On0h0
         HOXM5xJ9PFjJzjGh6nQ5HdLu1nwOSOf44+DuZy9+G5HjP9AYpvW+6fd8bqi1hkffS3Cf
         pc5hjfQJQVjBoEiH6BINNGXoU/WdX/W8Flf+iReQfSgoq9wAlSebEzoteBiMtCK5akju
         N0OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ajpecLO/fvWy8HOiG6LDUwU+h9koVBTZdjAAdids2nU=;
        b=yRSka1z+NTmvXPPY9I3MI7FmsQ5kBM8FN5RDBR0FH5cXiai2EbTJV2r7z9BbYZiEAq
         MrUT7mEZalDTIlRippO0Xfu45p+b2afi4+/gApfwKR3v0K4kF3SL+/J0Z5K5t+hmtP6K
         G85O1xqjSLlgJraY24Mr/saKdL1a3wV0ATf++xF3KtMs9uHWa5lQTYdArpmAYxTz3Q9G
         aK9TMZBCC2P6BHNfOTKAmc7jyjeCe5nkdQJc7yuR8d2p50m0OBiPc9Tm8Ch/4KhlpcyG
         J4v99z3oZh3t4oJGGhkNAvfFM+8HXrIjXmB1d/UmOXStG5/fe/YMcsa1p8nsw87Fp1Oo
         9FYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ie7BWsEU;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c6si22886pjs.3.2021.09.14.01.31.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Sep 2021 01:31:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 59D4860EE0;
	Tue, 14 Sep 2021 08:31:36 +0000 (UTC)
Date: Tue, 14 Sep 2021 09:31:32 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel test robot <oliver.sang@intel.com>
Subject: Re: [PATCH] mm: fix data race in PagePoisoned()
Message-ID: <20210914083132.GA5891@willie-the-truck>
References: <20210913113542.2658064-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210913113542.2658064-1-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ie7BWsEU;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, Sep 13, 2021 at 01:35:43PM +0200, Marco Elver wrote:
> PagePoisoned() accesses page->flags which can be updated concurrently:
> 
>   | BUG: KCSAN: data-race in next_uptodate_page / unlock_page
>   |
>   | write (marked) to 0xffffea00050f37c0 of 8 bytes by task 1872 on cpu 1:
>   |  instrument_atomic_write           include/linux/instrumented.h:87 [inline]
>   |  clear_bit_unlock_is_negative_byte include/asm-generic/bitops/instrumented-lock.h:74 [inline]
>   |  unlock_page+0x102/0x1b0           mm/filemap.c:1465
>   |  filemap_map_pages+0x6c6/0x890     mm/filemap.c:3057
>   |  ...
>   | read to 0xffffea00050f37c0 of 8 bytes by task 1873 on cpu 0:
>   |  PagePoisoned                   include/linux/page-flags.h:204 [inline]
>   |  PageReadahead                  include/linux/page-flags.h:382 [inline]
>   |  next_uptodate_page+0x456/0x830 mm/filemap.c:2975
>   |  ...
>   | CPU: 0 PID: 1873 Comm: systemd-udevd Not tainted 5.11.0-rc4-00001-gf9ce0be71d1f #1
> 
> To avoid the compiler tearing or otherwise optimizing the access, use
> READ_ONCE() to access flags.
> 
> Link: https://lore.kernel.org/all/20210826144157.GA26950@xsang-OptiPlex-9020/
> Reported-by: kernel test robot <oliver.sang@intel.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
> ---
>  include/linux/page-flags.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
> index a558d67ee86f..628ab237665e 100644
> --- a/include/linux/page-flags.h
> +++ b/include/linux/page-flags.h
> @@ -206,7 +206,7 @@ static __always_inline int PageCompound(struct page *page)
>  #define	PAGE_POISON_PATTERN	-1l
>  static inline int PagePoisoned(const struct page *page)
>  {
> -	return page->flags == PAGE_POISON_PATTERN;
> +	return READ_ONCE(page->flags) == PAGE_POISON_PATTERN;
>  }

Acked-by: Will Deacon <will@kernel.org>

Thanks for writing up the patch!

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210914083132.GA5891%40willie-the-truck.
