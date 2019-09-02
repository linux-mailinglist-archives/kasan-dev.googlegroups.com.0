Return-Path: <kasan-dev+bncBDQ27FVWWUFRBFWQWTVQKGQEUNJYN2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id DB846A596E
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2019 16:32:55 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id k7sf8090611plt.7
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2019 07:32:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567434774; cv=pass;
        d=google.com; s=arc-20160816;
        b=DR6wK7nYQoLdpteu6efWDiiYXW4li2MvGwartui0SrmUDFj7lSSZvykP4RzTVgRJfg
         aRmQ5lh4qFIdT/IXeTm5CC+VNNvcBChqj8zr1aBEzqE/6GDxaSgrxZkBaYSojnugaECr
         FT0VM4pMh7CEpieIlLwHg0KmB4Jry4UJ9AGsqYroohmlSdUDhdqsgAGsp5DGB/C31pPZ
         XVqrlmT0rsTB/hWDeuvUgq5HqL14jvERByanK7PPlosvOt7WPTHnMgg82qTalz/fktAv
         VU0ogar2LsmsGPtjTWYtz+F+8sOaPDhvoK+PzNP2nLb+xqVPxl07rKpzDdnXJIofIZK0
         53ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=P/85LVLrtZFoUACVq8jHiJmrBhWvyu4yZ6RnhVN6VZo=;
        b=TnjmhwNjeHWPA4mM2Z9Nu5ynTHZe2DkeDyERF8OX+4pUvNTs9GDdtLWQqKo7hudzl4
         0nw93SkGk4Gm62TsP9vQuEJOXgkIbN7t0rcsuH+51WXynSA97bDfvhg2yhlzsXBoOr2L
         x+zzjTR1rlWWcRPYsvWiTmC8sMFHHC4sQhv0Q95YgFY0tMQ6tsBQA8mMnbuQ8qVkqb3v
         0qrUpNRt0VIOZ0TXDicB+Bxd0YGFts+L7ltWRNuJFTfAqPF+Aq4NmeKViJ6JOl0YuXV3
         Eg57uWRZ5L6vu/oucIR1RTsbuw348jFJeywadqlF4Ulrv4oxXSK0eNXgAKyyfVvSbn/y
         ZHww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=OwysBwWB;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P/85LVLrtZFoUACVq8jHiJmrBhWvyu4yZ6RnhVN6VZo=;
        b=cawbXTMbEepNn+ttd234GXOK4PmoiRTuEjD0TUgWhrKq1Y1+X91INzC+8Dhx9vCVQ9
         lUHlTQL3SY2GvnaOZf8ByQih6LOW8zap7Gd57uEFveBlLmffNvWpAZGEHm0wLY1V2+vI
         xO31Z1wuRMHljSRaBjq5gU8RmKI3QbgMghd+khxXR5mqysXy1T30J3n4m4mbabbI2854
         BuRSzUHwPvYS5PQlpjpVkyTm1dtZXjObUNIe3gd6U52s32gv6eex2cI91H6AQq2E/HGZ
         vv8sjSUpOhdAFq+PqdmTSCAnJ3dubUB2al7Z4cZpC+8NQIDQmQhaI5JlRDUZNX7Ygin+
         zH5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P/85LVLrtZFoUACVq8jHiJmrBhWvyu4yZ6RnhVN6VZo=;
        b=USfypHpfVFlV9Q3VuQVuHqlyVxR7wdf7zLKCbqLEvS+qKDQMNNAZPWtIZtN3ogWjMG
         cgF67xkOQZm7NeThRj623jS8h84ZnDw79KD8yHIAVEpz0Hh0hUd9n9i6gFUrENq1bZ3u
         J0O62PSPQI/WPyAWoWUXxTXt6hsZ7L6yv5c30OhJuG5pRXu3hVlTX3je2SyEgNRsyHCl
         EuEUyKcJ4SGsnWa/K3ReiRjjFdHfXd4hH7gIGOfoPLRjVo9NldOv4/RoWDsWsvZH2nzx
         PmjaVUU6EK1RpnL52KzE5AHwgySZBp67kBTpI5x6pRBT0bkt27ER8jDhcfYJyHmfvnBi
         qdcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWcQXiqgfn5kxUa6u0aOKKpxMCRYud+GoximCsp0WFPvv5j/gfZ
	6jNqYM/trPo/Re+flCa1DYI=
X-Google-Smtp-Source: APXvYqzqff3LKfJmdJFSidq70n/mXp7VyJBBhJvYGMCN4O5vKgeJqeW6KK2a7Vk4tz1PE3uA2KaHtQ==
X-Received: by 2002:a63:6097:: with SMTP id u145mr23686424pgb.227.1567434774104;
        Mon, 02 Sep 2019 07:32:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6b81:: with SMTP id p1ls4618393plk.6.gmail; Mon, 02
 Sep 2019 07:32:53 -0700 (PDT)
X-Received: by 2002:a17:90a:890c:: with SMTP id u12mr2083663pjn.124.1567434773830;
        Mon, 02 Sep 2019 07:32:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567434773; cv=none;
        d=google.com; s=arc-20160816;
        b=XA8qVNDyKrROLY5jQStTWFUagrYZx+yfYYz+7shGVOZxWfmMbnCGmJdoW7bK/3uwuc
         9/C4miz2P5sMFVwuJ5lOjTTd5/Cz/8anxBh/NAN2SjrA3ZRXrFQrGQKLRm/T0s1bXDuI
         1lE9hTyAPrNf3kY8Mt1WNe6jwtF/dcWqE+Aj96Mus0YtodTlumFY4Jm6YNaafEdpXExt
         gz5zA1E5d1/63mHJlOcsHMqYRIZIpueeVjN30RaVVlw1SCOJEem+b8PowbLWzrEw21Sl
         tsFuKFG3Tw4vYwlkkSVxCIJnvYLCFcBtMQspSyoCkPGfUyGNsej3uXMR4dRVNCqbHvj7
         G+Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=7KTrdItVhsmDUyDggdvNWAkcifUfR9oLU9QTC4MXwVE=;
        b=jq9I2u0RVqSiC8JP0BDmvDNn2YRBq15CSdes2Tq0X30ZCcrO2VYZ486VB7bz8ZnKke
         JLsn3n6YOdpT5yZPfzV/qOGcJh5joBwVzKJXBT/e6ulXLQfjoGNWmVp3ZnaqVFC95c6J
         Uvbch9klMsinufqQ+ltdKnHPE1heQzOI4fxFWJhQNGOcQzLUIj8CdUa7v+IucIddJ8mT
         mNyEynRSm3K18HnrZfCI0WzThbpE2QdiKRhBl/5PhXKCDzfnFxY4sC+j5gWD9PCONea/
         PFI1k5mIvUQ8XTbrQ4Hcxpzs2QpYjPiOEb5mjRZPBlvaHYJVWr9ihq2nuWjSvXX3OVPa
         l8rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=OwysBwWB;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id c6si338645pls.5.2019.09.02.07.32.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Sep 2019 07:32:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id s12so2086477pfe.6
        for <kasan-dev@googlegroups.com>; Mon, 02 Sep 2019 07:32:53 -0700 (PDT)
X-Received: by 2002:a62:37c5:: with SMTP id e188mr35417324pfa.207.1567434773580;
        Mon, 02 Sep 2019 07:32:53 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id s186sm19233794pfb.126.2019.09.02.07.32.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Sep 2019 07:32:52 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com, christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v6 1/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <20190902132220.GA9922@lakrids.cambridge.arm.com>
References: <20190902112028.23773-1-dja@axtens.net> <20190902112028.23773-2-dja@axtens.net> <20190902132220.GA9922@lakrids.cambridge.arm.com>
Date: Tue, 03 Sep 2019 00:32:49 +1000
Message-ID: <87pnkiu5ta.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=OwysBwWB;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Mark,

>> +static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>> +					void *unused)
>> +{
>> +	unsigned long page;
>> +
>> +	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
>> +
>> +	spin_lock(&init_mm.page_table_lock);
>> +
>> +	if (likely(!pte_none(*ptep))) {
>> +		pte_clear(&init_mm, addr, ptep);
>> +		free_page(page);
>> +	}
>> +	spin_unlock(&init_mm.page_table_lock);
>> +
>> +	return 0;
>> +}
>
> There needs to be TLB maintenance after unmapping the page, but I don't
> see that happening below.
>
> We need that to ensure that errant accesses don't hit the page we're
> freeing and that new mappings at the same VA don't cause a TLB conflict
> or TLB amalgamation issue.

Darn it, I knew there was something I forgot to do! I thought of that
over the weekend, didn't write it down, and then forgot it when I went
to respin the patches. You're totally right.

>
>> +/*
>> + * Release the backing for the vmalloc region [start, end), which
>> + * lies within the free region [free_region_start, free_region_end).
>> + *
>> + * This can be run lazily, long after the region was freed. It runs
>> + * under vmap_area_lock, so it's not safe to interact with the vmalloc/vmap
>> + * infrastructure.
>> + */
>
> IIUC we aim to only free non-shared shadow by aligning the start
> upwards, and aligning the end downwards. I think it would be worth
> mentioning that explicitly in the comment since otherwise it's not
> obvious how we handle races between alloc/free.
>

Oh, I will need to think through that more carefully.

I think the vmap_area_lock protects us against alloc/free races. I think
alignment operates at least somewhat as you've described, and while it
is important for correctness, I'm not sure I'd say it prevented races? I
will double check my understanding of vmap_area_lock, and I agree the
comment needs to be much clearer.

Once again, thanks for your patience and thoughtful review.

Regards,
Daniel

> Thanks,
> Mark.
>
>> +void kasan_release_vmalloc(unsigned long start, unsigned long end,
>> +			   unsigned long free_region_start,
>> +			   unsigned long free_region_end)
>> +{
>> +	void *shadow_start, *shadow_end;
>> +	unsigned long region_start, region_end;
>> +
>> +	/* we start with shadow entirely covered by this region */
>> +	region_start = ALIGN(start, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
>> +	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
>> +
>> +	/*
>> +	 * We don't want to extend the region we release to the entire free
>> +	 * region, as the free region might cover huge chunks of vmalloc space
>> +	 * where we never allocated anything. We just want to see if we can
>> +	 * extend the [start, end) range: if start or end fall part way through
>> +	 * a shadow page, we want to check if we can free that entire page.
>> +	 */
>> +
>> +	free_region_start = ALIGN(free_region_start,
>> +				  PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
>> +
>> +	if (start != region_start &&
>> +	    free_region_start < region_start)
>> +		region_start -= PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
>> +
>> +	free_region_end = ALIGN_DOWN(free_region_end,
>> +				     PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE);
>> +
>> +	if (end != region_end &&
>> +	    free_region_end > region_end)
>> +		region_end += PAGE_SIZE * KASAN_SHADOW_SCALE_SIZE;
>> +
>> +	shadow_start = kasan_mem_to_shadow((void *)region_start);
>> +	shadow_end = kasan_mem_to_shadow((void *)region_end);
>> +
>> +	if (shadow_end > shadow_start)
>> +		apply_to_page_range(&init_mm, (unsigned long)shadow_start,
>> +				    (unsigned long)(shadow_end - shadow_start),
>> +				    kasan_depopulate_vmalloc_pte, NULL);
>> +}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87pnkiu5ta.fsf%40dja-thinkpad.axtens.net.
