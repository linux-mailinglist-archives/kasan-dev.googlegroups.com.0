Return-Path: <kasan-dev+bncBDBIVGHA6UJBBQMNY6BAMGQEZN7TUAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id A952F33EC2F
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 10:07:13 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id m23sf13050435wrh.7
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 02:07:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615972033; cv=pass;
        d=google.com; s=arc-20160816;
        b=khxG71bwoJTVKPEMvwVjsKvg548ppv7/X2SsEDxNLUxYaxbGO09M2VKy1wyHvy/2Tm
         DAOHBgNcf5QgKvpRhW5hxnrNddWUJnPW52BEzbbGPFYO4fLhkmp+I7WatZNc+t3t/TgS
         oKp066bv/sD1Bpwh/HCVJMT3wQ81YOAIbn8OrCzoyAAsb1/1d2zRV6eFjp629Jlxm+Xc
         ursp1wTI5dlGv6HFIUpyV2R+1o+EK++XMik0e5fAHBp1R6BBawvrS3S/aRhnD0ZvxSd9
         Dk9KuRd8irjk7F90BA5npGLd0gXW3YZils7jOLQyjOAk11f/bMEwA5zmwAcgYsgqTwb0
         J/Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xia0pt9qRZ9MvTYIXaL+nNsg7VX8oKPiDbONh4ciJCY=;
        b=Xc+ArcuuFVdQZ5lV2RfQgjbpW9llXGLJC88Mz6O8qGm2q2IKOK4smRtEdxanYcjpOb
         SMKLYj49uIh2EBEo4yo4kW2cNpQXINB5f/VFjYBbF8pWafNwN3gKdjGPFFUsLMIGR5fk
         KyT5Iyl9BuKi4WeR43Mec6FM4ZAfgyJN6671ASzvRzfS6KVCCqVusIN4g2t02sCxNjSg
         1DOtjnmeC5ZdmVW7eD9ymtrf4XhlSM7OrWeZhS7h9T6a2IfOGPPLKaqxOQdOLWE4yNGK
         KET0QNm0u9PBI/kN1Nh5TEBu/AXoM0dUI1y9RqZ3ASLvsxBKePxeWIGADPJds/hJgjCE
         IxUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=lhenriques@suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xia0pt9qRZ9MvTYIXaL+nNsg7VX8oKPiDbONh4ciJCY=;
        b=R4NAkn/StOSRj0y2fl7efFqAVIJuZOc/rotlZjjhVCQ6Q7+6isXOduapKG3K8kdRrj
         baq/Wqyryidta3LDB0+2r6365ytrO0VMq/wsrw3gFOe4JmSF9ZN4tcZg+cB2/qMrguLN
         z7QRkGVzEPfANXzqtpv7Nc9I0XStR3Gep02iB6h+Z8oB4vYHJZl2xO3UaKCaua2e9SWe
         Igp9Uaa2LMDs3UYztEx5Ppk9KFl5XN++S9y8ojtD+WFX0qQDzqzcKT5B/Cc3svkKFKFw
         MDlEznIQfbk/tolc2R2noyQtZP0abLNEa5nZCytDE4cgtMMPzDcr5kZ6n1hd3scbct4K
         9grw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xia0pt9qRZ9MvTYIXaL+nNsg7VX8oKPiDbONh4ciJCY=;
        b=IRh1Iug1Zz8UTgV32a4t/1NBjkDzafpNodfcCUdbU5OCnjbPKldkxnmFAZVt1Zs9Fk
         mAykezReu/LafueZrjWI/ywFDMvfBEyDksomp3q4C03rTS0HOxT3RyGeaMKjhthud+EP
         tOebC5IVJkr1ndimiQJ0ksibDe1qATlX7CNpKw9oBVrnFdchKD6e4nXNImj0dZdMPYWd
         N9f3wGRismgeUKF+eobB7WYmEt5V6coqRbc00lUADV71MMryfsQrbKLGOvA0VBMl6M0y
         iCmWRNvuuFpvhTL/Owxd3p8AUPrC94oOlL4kNl63Rdfk5uEXly0bk1NEGgk9sKrkqqfA
         LRwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5318oYlg3AGGAOupH3wbhD6qYYHnaSHR4+jR6NW2rrzI7wc7RPfx
	rw5eG8rg7jYl6iGUuAaMihs=
X-Google-Smtp-Source: ABdhPJzfE/d8H8Jb5qZn65hZPx6rk2qsm9xYBBaw7Fdu1+76yONGROOs3K8VxFJQU/WWQi26SRtY8Q==
X-Received: by 2002:a1c:9817:: with SMTP id a23mr2671487wme.57.1615972033420;
        Wed, 17 Mar 2021 02:07:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1e6:: with SMTP id g6ls3838576wrd.3.gmail; Wed, 17 Mar
 2021 02:07:12 -0700 (PDT)
X-Received: by 2002:adf:cd8c:: with SMTP id q12mr3221847wrj.185.1615972032638;
        Wed, 17 Mar 2021 02:07:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615972032; cv=none;
        d=google.com; s=arc-20160816;
        b=wgZoLystQ26fsRFDcm6zGGHQa7TBL6cgK+daX04gZ6m1LiBCfwHP3K7BG/EC6X+lv+
         tSzS8WOb3vavCW3udnGA+MFxUUXhw6wLje1BDHXTdNAwXu8olATHFt988S2XvtGGEDhb
         gfbWamkGioujAqSbF88ZuY7b0vWBafv4Hxqp7vBEPS7v9mQksMw9Fccgl6QrrjbG+5QQ
         Yi7o706SHGXPxVSDkv7WBd0mo6P7slKXZsMKbCXRZLVjrRjh52gYrIRLEviJDC6n13Nt
         4e16lY8iGkcKE9vsTrzM5nYHwS6WvCkpNs8QuaRuELpFAtcSXk6AQF7LQuBIhUTB2six
         hUng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=7U07xh2zqleGRz70hYQcPUf+qvh2lpP8dVJ/nDnhvmY=;
        b=clbiXgeos42iNp2vudwY40gNyBvdLPe5yKLIGP3ciC0GQifFLYbMSYd2lD8ZL9KVUD
         JuGbQzFlMz7NKzufPOyH13yDSfmV583DPYTgAOsEx1Dr0VQb359zX8HBTpwoJ9TOk/kA
         BdjCzX6OoEG0y/3YtVsCP6qbY+HgXsyok86MSCJPNhdrWcU5zkEkJ0lQpbfn3+NkNHGa
         4f1eRTsmTuK4xEAMDFB9LzL/PE9PX7XJmFAfbGJY7fib/ydV0i2cxT+9QGB/eJ7lEMb5
         ewVtYbB7ddhRV4ZEYBZhSEr6txSJDggqcuaZ+NYjHfFfIhz/WKncYXYJgSMvAx1/sUDG
         BttA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=lhenriques@suse.de
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id q145si73954wme.1.2021.03.17.02.07.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Mar 2021 02:07:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 37607AC1E;
	Wed, 17 Mar 2021 09:07:12 +0000 (UTC)
Received: from localhost (brahms [local])
	by brahms (OpenSMTPD) with ESMTPA id 5b239ed0;
	Wed, 17 Mar 2021 09:08:27 +0000 (UTC)
Date: Wed, 17 Mar 2021 09:08:26 +0000
From: Luis Henriques <lhenriques@suse.de>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, dvyukov@google.com,
	andreyknvl@google.com, jannh@google.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: [PATCH mm] kfence: make compatible with kmemleak
Message-ID: <YFHHCi247iLcykDF@suse.de>
References: <20210317084740.3099921-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210317084740.3099921-1-elver@google.com>
X-Original-Sender: lhenriques@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as
 permitted sender) smtp.mailfrom=lhenriques@suse.de
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

On Wed, Mar 17, 2021 at 09:47:40AM +0100, Marco Elver wrote:
> Because memblock allocations are registered with kmemleak, the KFENCE
> pool was seen by kmemleak as one large object. Later allocations through
> kfence_alloc() that were registered with kmemleak via
> slab_post_alloc_hook() would then overlap and trigger a warning.
> Therefore, once the pool is initialized, we can remove (free) it from
> kmemleak again, since it should be treated as allocator-internal and be
> seen as "free memory".
> 
> The second problem is that kmemleak is passed the rounded size, and not
> the originally requested size, which is also the size of KFENCE objects.
> To avoid kmemleak scanning past the end of an object and trigger a
> KFENCE out-of-bounds error, fix the size if it is a KFENCE object.
> 
> For simplicity, to avoid a call to kfence_ksize() in
> slab_post_alloc_hook() (and avoid new IS_ENABLED(CONFIG_DEBUG_KMEMLEAK)
> guard), just call kfence_ksize() in mm/kmemleak.c:create_object().
> 
> Reported-by: Luis Henriques <lhenriques@suse.de>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Signed-off-by: Marco Elver <elver@google.com>

Tested-by: Luis Henriques <lhenriques@suse.de>

> ---
>  mm/kfence/core.c | 9 +++++++++
>  mm/kmemleak.c    | 3 ++-
>  2 files changed, 11 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index f7106f28443d..768dbd58170d 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -12,6 +12,7 @@
>  #include <linux/debugfs.h>
>  #include <linux/kcsan-checks.h>
>  #include <linux/kfence.h>
> +#include <linux/kmemleak.h>
>  #include <linux/list.h>
>  #include <linux/lockdep.h>
>  #include <linux/memblock.h>
> @@ -481,6 +482,14 @@ static bool __init kfence_init_pool(void)
>  		addr += 2 * PAGE_SIZE;
>  	}
>  
> +	/*
> +	 * The pool is live and will never be deallocated from this point on.
> +	 * Remove the pool object from the kmemleak object tree, as it would
> +	 * otherwise overlap with allocations returned by kfence_alloc(), which
> +	 * are registered with kmemleak through the slab post-alloc hook.
> +	 */
> +	kmemleak_free(__kfence_pool);
> +
>  	return true;
>  
>  err:
> diff --git a/mm/kmemleak.c b/mm/kmemleak.c
> index c0014d3b91c1..fe6e3ae8e8c6 100644
> --- a/mm/kmemleak.c
> +++ b/mm/kmemleak.c
> @@ -97,6 +97,7 @@
>  #include <linux/atomic.h>
>  
>  #include <linux/kasan.h>
> +#include <linux/kfence.h>
>  #include <linux/kmemleak.h>
>  #include <linux/memory_hotplug.h>
>  
> @@ -589,7 +590,7 @@ static struct kmemleak_object *create_object(unsigned long ptr, size_t size,
>  	atomic_set(&object->use_count, 1);
>  	object->flags = OBJECT_ALLOCATED;
>  	object->pointer = ptr;
> -	object->size = size;
> +	object->size = kfence_ksize((void *)ptr) ?: size;
>  	object->excess_ref = 0;
>  	object->min_count = min_count;
>  	object->count = 0;			/* white color initially */
> -- 
> 2.31.0.rc2.261.g7f71774620-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFHHCi247iLcykDF%40suse.de.
