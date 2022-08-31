Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBAWVXWMAMGQEX6JZSEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 542E75A7F86
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 16:04:52 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id z8-20020a17090abd8800b001fd5f11fca7sf9213353pjr.6
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 07:04:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661954691; cv=pass;
        d=google.com; s=arc-20160816;
        b=GZW6QWMXbjZgQtqwgg+vsEEReB+6CXGed+0Kn9S1GN/tixUaN/YXoiF7CoWgkwPf41
         YiOB0Uc84GDZvJB2Zb7JInXm2lpbkOZkpJqcpCKzDRRw6KjA93xrBWg+mH7UqJgWz0Iq
         7PQZGg5+44iF4bW3+CEmzQB2qKyK+IeD3ttvnoYHcH1WfxruKewf11cx5iznavpyv2C8
         ZhYPCsZy+rRq1tgxX+IB/MYziD6Q25GgmPn0/PyF1iiaNZuiu/2xqQODEwvjhztoUQyP
         Sm7p0RxsFCzaDsF1m2I0nasw8drC2hfk/L0ZBq9DjcyHMRZvhao7r11whu9ukjWaNGZC
         Gtfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=rPcFLThM0uBwozC5PrOJdPO0bxR98DV4av3uNUaD8Jk=;
        b=XTQNmJSyYSxZ0/rvewfPhMY9KnzPAZLk9V1Q6dgigGhoKeV/2Ka82hjAnWxxwhH8mF
         BTOEBaT6T9PbR5P1CsMHexoPbXzmRWZ8xv4KTJMWYdTUmVh+i1hkxzbszJXDQSFoLjIO
         wIr8/tEOb41b54PxCkqKJrNaH+eH1PsT0QnrcljgaSZTS0is3FJ0/mtPhL1QJbSn182c
         23JgLFZ8MZlimrY+RI8d+VyyLLYmFyIKh8nR6Xu5Bo0pyPwVLq5MDUR2wr49alT4jaa8
         BNEI9SaZMmDNf0krCEWwKPqqsv1jJViYCbKy5yCqtaWRCbAvDyYtjoEzVrwdDAYMUK2f
         pQ6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=R7AXl+wh;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=rPcFLThM0uBwozC5PrOJdPO0bxR98DV4av3uNUaD8Jk=;
        b=cPj/JwhwI6aqeiNGF8NdVdhfJD1bjsqJXG5bZr55h67PDfg6LIZa9fc1ESQbiwcP0f
         sWsxXoHnpevyUzs4aklgKJY1XWUeP85d2DMGkAjlnAmdXh3jzWLOy39B5rSnJ+Qz2MFv
         TXnIgMTJjn35mtPPP+tVf+twa1uCKbf1FFDjgyw/00gn5c9JZONOo2rUAGPNtDEyOVig
         YsWkVEaaQtwUaGrSz7XegN1BdTGbPDaFpOuBsHtme8BsrC5BigKPb9KThNtQh2kE3bnE
         WfHslQmKEWI1Hw1w/jkURNHfJwaw9eNvo9V3/HnH8dD6+1neWkwSYX840XEXrjQzJj8+
         5sGg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc;
        bh=rPcFLThM0uBwozC5PrOJdPO0bxR98DV4av3uNUaD8Jk=;
        b=OCCa7gzyeYmdM5b0H9xqXbqGsPkVh3w5QLraBS7s4gtNlWMtHKpAp7/UzmNHYqzcOA
         QneMhe452rzr3i9rw7id2wQygp7z8gP/wjjIrzIJ7RJ+531815C/D4wIUt+1dRfM3SdN
         +mTBPAEjJvcPvyLYsmuOLsG9Jiz0EXm1QlTE4kf7qN8pj44aFiXCc0rVqzzbG+p+ipAQ
         VWmc5YK51IGfJwOepHUh2ZRvyobWYMHOV2KsmjFovDb9/5kd+j67B/plDYbBqy4HQOlF
         OoF59KTrav9Kdc55kAS2MT/8oGz3Sh0rpWONTUnPDm+oyKNsombzCfp83ufd5GinLy3I
         QW9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=rPcFLThM0uBwozC5PrOJdPO0bxR98DV4av3uNUaD8Jk=;
        b=fDK2mvTr/azR1IKZtgtUjLslbtGytZdWOty6HKFp/UoecMMvyfGYaYzq2pUc1JhDVZ
         gTO4CH9d//vNimR96BOaQoD235oka3ka0PDCrPtw1diuK3IpHnazizknm4+iqzTsIzUN
         b5+Lhtpomf3xo8Ek2E2w9OVejCJ42HXND4EA4vhtXTTjk1vjHL2CC9Rzi9kUd46xv+He
         6/PTPagQLADgXJPpRIPbAc4L8yytRpZh0ePVvrrKU7T5y7QWPsWvLUtcwQY3QIH80T+M
         Ip6kkY0Ru1/iHsTV/O2wH/UrxrsgYXvN69BMPIXLChmr4tOkWOTS0nJZoCbNnPauwyMi
         pI6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo15FMn2fFidFhRZKCv9OlsXd8gvQ23/IcmyyV2GIrahsBvx9WeX
	nnno7pUF+lQ9Wjzw73Ul8bc=
X-Google-Smtp-Source: AA6agR6UNi8hfx2kjG669aGmGZtM8D7PjX4MhambWMDXO9img8fbWXswyMDifrK8hQicNZBSVt427A==
X-Received: by 2002:a17:902:c407:b0:175:3c7e:70db with SMTP id k7-20020a170902c40700b001753c7e70dbmr4726889plk.99.1661954690564;
        Wed, 31 Aug 2022 07:04:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:88c6:0:b0:419:7b8c:85d with SMTP id l189-20020a6388c6000000b004197b8c085dls7553334pgd.11.-pod-prod-gmail;
 Wed, 31 Aug 2022 07:04:49 -0700 (PDT)
X-Received: by 2002:a05:6a00:22c7:b0:53a:bea5:9abd with SMTP id f7-20020a056a0022c700b0053abea59abdmr3143293pfj.3.1661954689650;
        Wed, 31 Aug 2022 07:04:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661954689; cv=none;
        d=google.com; s=arc-20160816;
        b=tPw5A/fPERkRifHt2TjhZ24ww3v41S3AGM3dEFFFKIxrwoBFz0A1/0rmhdlhBwK6fD
         uZFzLiLGypsaHzSQ3N6BqqdEBCkGpuBUI8zTEuIOdf/JxkugZ6/Y+GhvLIRpPV5M3467
         wUcChQu22i8D2XC+4OCP7FshQBNVZ+WT5Xj6Ys0ro1uDyRSfvLomODVkHYf9Tr+JDzIF
         Ss2dNiqmxujyrXUJAuGsXMZlzbA19rxh5yo8aDvNkJTw94vrSctzg9g4COGvF4bkdKSv
         dBPx0F/F6RjweGq2gbMbUWd0XAEMkNHCD+0RloS25hVJAx4bUrywVLOyqzzo5YVpGY7J
         ykSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JRpljp0WIXjTAmjOkCvSfavCaZCHOKd5qHM7dwF9nGg=;
        b=o+Pt7UOXh+LSb4Yb/08n/Z3ed/e4MSIjmsigT+2iiq5aNc3kxA5ozZQq3F2U0E3Dnv
         A2Wi4N2E/IB3yAHA9qtTDrTEfj6MkWDVTLHGVkjExu9ehCapS8ekXehhgEBdLEUWCwaq
         nH/0LHhowMQlC37OfLDqCqkGWJo0mdp7HJXBp1j/Zk9/5g/lObsmYeFEHAYUznpIpo8h
         eH/eAgpU+h/OSY+IZLptH2oQROKYg3z/nCdqqA2cpgvur9bcuswjMDq3pfdhlEWvk+3O
         Wba5QGwJ53ftUY/coiHi6gYZ2IltkIdUaVyDXuBioliDz1h6mFG32NO6EJppoN4hVjU/
         c7XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=R7AXl+wh;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id n9-20020a170903110900b00174ea015ef2si257769plh.5.2022.08.31.07.04.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 07:04:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id u22so14204836plq.12
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 07:04:49 -0700 (PDT)
X-Received: by 2002:a17:90b:1b12:b0:1fe:b98:2c42 with SMTP id nu18-20020a17090b1b1200b001fe0b982c42mr3481015pjb.184.1661954689297;
        Wed, 31 Aug 2022 07:04:49 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id w18-20020a1709027b9200b001728ac8af94sm11556321pll.248.2022.08.31.07.04.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 07:04:47 -0700 (PDT)
Date: Wed, 31 Aug 2022 23:04:41 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH -next] mm: kence: add __kmem_cache_free to function skip
 list
Message-ID: <Yw9qeSyrdhnLOA8s@hyeyoo>
References: <20220831073051.3032-1-feng.tang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220831073051.3032-1-feng.tang@intel.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=R7AXl+wh;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::630
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Aug 31, 2022 at 03:30:51PM +0800, Feng Tang wrote:
> When testing the linux-next kernel, kfence's kunit test reported some
> errors:
> 
>   [   12.812412]     not ok 7 - test_double_free
>   [   13.011968]     not ok 9 - test_invalid_addr_free
>   [   13.438947]     not ok 11 - test_corruption
>   [   18.635647]     not ok 18 - test_kmalloc_aligned_oob_write
> 
> Further check shows there is the "common kmalloc" patchset from
> Hyeonggon Yoo, which cleanup the kmalloc code and make a better
> sharing of slab/slub. There is some function name change around it,
> which was not recognized by current kfence function name handling
> code, and interpreted as error.
> 
> Add new function name "__kmem_cache_free" to make it known to kfence.
> 
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/kfence/report.c | 1 +
>  1 file changed, 1 insertion(+)
> 
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index f5a6d8ba3e21..7e496856c2eb 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -86,6 +86,7 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
>  		/* Also the *_bulk() variants by only checking prefixes. */
>  		if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfree") ||
>  		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_free") ||
> +		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmem_cache_free") ||
>  		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmalloc") ||
>  		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_alloc"))
>  			goto found;
> -- 
> 2.27.0
> 

Thank you for catching this!

Unfortunately not reproducible on my environment with linux-next (IDK why).

Maybe you can include those functions too?

- __kmem_cache_alloc_node
- kmalloc_[node_]trace, kmalloc_large[_node]

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yw9qeSyrdhnLOA8s%40hyeyoo.
