Return-Path: <kasan-dev+bncBDDL3KWR4EBRBTGCSD6QKGQE2RY3AUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A7D12A82D8
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 16:59:09 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id l142sf869924oig.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 07:59:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604591948; cv=pass;
        d=google.com; s=arc-20160816;
        b=MMk4ZgiWldEVaazzsV4+/5cJTsNBDltGdXmfceBuI3bc8zx9Z4RFmfKbqVH7IxfTs5
         LfednNogpZAtD3C+GMbm1bOJbr8THQhNgnrTidQUONBab8FxLTQEAhNiYz9Nwhbm6wuw
         s/4htwjefsZCA/XJPVhq6iXPy/1fdBIsS7rj6+ThzSFCjWZfV3y1hx6bUWT8FyBfnopN
         GKhpvoa1BV6QRGN6WTx1KF2ZIXgzYGXJhtWFYAGJedfZEX8PbuNXiop5GpttvPTNhz0A
         WgvWCLQj8Wr7IQYXnyMlf4jvnPwbbQ001X7miiUC7aPnzq48N1edbNVzOTFC+4TgVEsk
         mEyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=kQhUtrTxUEokQ/Ply1fQJUzvH/NkAXY7XCHSd2DT+sg=;
        b=aSrnYhRWTSEMoL/JQULRqLMfYLjFQACBn7oeawHtFxmmi8W02ii1lgxtY+d5k5/f06
         ZHI+bYVXnw2nEjZj62iObkgpQICYtWNI5soIz5pGwmLjPe0Dyrv/AHexMYHIekbsgsNT
         Ua2Qk5IEEiJUV/rpro0XRMCgbaro2Ukjy9xQG7KM6sX5ud78rRFTYfZ/Ud0eRQrdSpa2
         xI6+K83AAy30Dsj4/vWJmip8f+petnB62aEV7GXRP+FTZwj307+4SjDTFlhKNHc0tWwS
         u0DY7tuMyZr3rKkviizN/1wZGZE6Xo14BYr4s6F7W30/rb0QFx59QroDRX5v/IlNTOAL
         sflg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kQhUtrTxUEokQ/Ply1fQJUzvH/NkAXY7XCHSd2DT+sg=;
        b=Y3fw+UfN6laRaDEWLVlMVOLiLO9sjg7nZKfd3eGb04Uz2sElrQDxXml49i+h5C2zkI
         L2qxxl4DJIBVy5GIiJcfqvVKafGwYdMmE0UZeCb5PI6u7Hz1lf/kz4vHZgw8QSCGwmx4
         2NLtrgsPb6/QpTF0zSN39dWRGBhKTqGbAp8n2bY1DnJP4LLg5kUyYkMI5SflymoGhPVi
         kTE1ct9k5BR68mjMP/Kx60lKLWbbtgP6syvuwUEcJ42F80x0hnj8NsyXgB8rXVf8kxHu
         yiq/sko9mWqLsdQSe/+lJLeD0z8cfe7KCCmy2St2JEsOJx+1oHBkyh6jJJCz9adrkTKv
         oj7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kQhUtrTxUEokQ/Ply1fQJUzvH/NkAXY7XCHSd2DT+sg=;
        b=YeM2QfjA3aahLaAaDOj0omWTJNye2ybjoiZLv3vhtzDjh9W5/EGlPfJCnTAdX46TCj
         9Y3MyEOUKLzhexc84l6SyXQQwVyH+uBpB8T3rBD8dmgomNqsT0PGh8KIEu5rt/MRUCjs
         wblCgTlaahaLTMkFZZ6De8yli7IOqHL/H+6TO5B0yGPk2asjECdox909HcWE4ux5vOme
         cYFQhaywDoyG+lV+vGSRtnaYWZ2eFqmnNiNCgAfmaQZbzXgrm6mVfpfi9jxulJyHtRqI
         leAdBgKNzP3E/8b2MpAWbVS1vjBLhMLusEgeZE5IL2r1yK2Y1yFxG3yZCf9WMKfLiFHK
         2AOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533A2C86UfEia6zyTxndVJDTIGzj1enY/n9tzuelMWUWWmW8mUqJ
	p5D5/lBfDy4c1aGYtbX34pQ=
X-Google-Smtp-Source: ABdhPJz86cvSL3V6yGDz2GJ4OszjC97nUjhI8beETMEcOqHAuqrR2EaIz9hXHGYIU+m0oTeIEvk5ag==
X-Received: by 2002:aca:c4c9:: with SMTP id u192mr32242oif.7.1604591948500;
        Thu, 05 Nov 2020 07:59:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf15:: with SMTP id f21ls524534oig.8.gmail; Thu, 05 Nov
 2020 07:59:07 -0800 (PST)
X-Received: by 2002:aca:750d:: with SMTP id q13mr25971oic.77.1604591947855;
        Thu, 05 Nov 2020 07:59:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604591947; cv=none;
        d=google.com; s=arc-20160816;
        b=MJxyiiXGjPrXRSE7RtVt290MndfSF5+W6zITcelu2y3vTFBJxvXavMF6gzJ+uURadp
         c402D+SxFfJeEMcI0F/RmnbG+Q4QVl+vtlPF/TdA6G9OALaLftcjm6GZ5S+MRUTtDxa0
         bm92RXfhXlVmnoMkNNvQK6bnpnOJzRbuJkoCvz4QB3bOlU9a7adHsdLWfKzMFSOdDpAo
         SScTcL4r9Yk7PRfx/tIj/KyeIc4K5FLbG660OvqKcPlfU3YJZmoyHFv7k4qD2Gaz3UaK
         NCS2U0U7WFLGGycECF9dAt/eSTBJMuFDSbQCmQOfwmDPxyhO4e0qOwJI+eF6brna6DEP
         ZklA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Cduiy9rDyJJM4EhCwCFojmPGRIdIcec/kZA4QDLB87I=;
        b=yv9Hh7R6F/SMmFXHfwVweWKYCdPqm+n8V+v9jYrWAh8500X3iRtQZ04hG+68/37AV+
         0ROg882qf2ssbqIxrfc98ObuCwD+Ufnf3fmLLpw6n/n0fWymSs1fkP+gGt04w8nTcbMm
         zywF3P81mNLPEAIy6KGnNPJF+oIgPNfJjKKxAxt9uWexHQmPY5GdV/NFHzOZlDKKjfQu
         9VCfFfxWobEU7iKUWjChopHzZ8/fX9VKsM4R0kT/p9bqG575mBbqbee2SotH99wzmdyN
         CVnX5ByUksrXi++HQgdNgRKvfqZsd4TNCY4cWdKw90mW09TMml42Ilg/2HBNJrxWC0HA
         WcKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v11si134069oiv.0.2020.11.05.07.59.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 07:59:07 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 637012087D;
	Thu,  5 Nov 2020 15:59:03 +0000 (UTC)
Date: Thu, 5 Nov 2020 15:59:00 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v8 28/43] arm64: mte: Reset the page tag in page->flags
Message-ID: <20201105155859.GA30030@gaia>
References: <cover.1604531793.git.andreyknvl@google.com>
 <fc9e96c022a147120b67056525362abb43b2a0ce.1604531793.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fc9e96c022a147120b67056525362abb43b2a0ce.1604531793.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Nov 05, 2020 at 12:18:43AM +0100, Andrey Konovalov wrote:
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 8f99c65837fd..06ba6c923ab7 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -34,6 +34,7 @@ static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>  			return;
>  	}
>  
> +	page_kasan_tag_reset(page);
>  	mte_clear_page_tags(page_address(page));

I think we need an smp_wmb() between setting the flags and clearing the
actual tags. If another threads reads page->flags and builds a tagged
address out of it (see page_to_virt) there's an address dependency to
the actual memory access. However, on the current thread, we don't
guarantee that the new page->flags are visible before the tags were
updated.

>  }
>  
> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> index 70a71f38b6a9..348f4627da08 100644
> --- a/arch/arm64/mm/copypage.c
> +++ b/arch/arm64/mm/copypage.c
> @@ -22,6 +22,7 @@ void copy_highpage(struct page *to, struct page *from)
>  	copy_page(kto, kfrom);
>  
>  	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
> +		page_kasan_tag_reset(to);
>  		set_bit(PG_mte_tagged, &to->flags);
>  		mte_copy_page_tags(kto, kfrom);

Nitpick: move page_kasan_tag_reset() just above mte_copy_page_tags() for
consistency with the other places where PG_mte_tagged is set before or
after the actual tag setting.

>  	}
> diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
> index c52c1847079c..0e7eccbe598a 100644
> --- a/arch/arm64/mm/mteswap.c
> +++ b/arch/arm64/mm/mteswap.c
> @@ -53,6 +53,7 @@ bool mte_restore_tags(swp_entry_t entry, struct page *page)
>  	if (!tags)
>  		return false;
>  
> +	page_kasan_tag_reset(page);
>  	mte_restore_page_tags(page_address(page), tags);

There is another mte_restore_page_tags() caller in hibernate.c. That one
doesn't need page_kasan_tag_reset() since the page->flags would have
been already restored but please add a comment in that file why its not
needed.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105155859.GA30030%40gaia.
