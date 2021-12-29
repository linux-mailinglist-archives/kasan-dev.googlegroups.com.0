Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBGEKWGHAMGQE4ACWEVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 0888A4811F8
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Dec 2021 12:23:06 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id br9-20020a05620a460900b0046ad784c791sf12683180qkb.4
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Dec 2021 03:23:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640776985; cv=pass;
        d=google.com; s=arc-20160816;
        b=omQJbSaJAquVWMrO9HrbGDi1hXbQDvP1lOV8REYJDQAPXFwZpYZlht9YNk7nTZA7SY
         XB3l4QLBFw1kD4h0iPKF6BTlX4Rhc9nzbGwb99JsvzfQT+Domw87+VTmN9RL4+FTvIMs
         hHz0liqK6GQQiusnq6bHAJijdp/cLQcuPwXQ0cmpHZllzcbbv3ySNADhDzzpz2GvQzJJ
         +V1kCIJuiILuY+gPJZfQOSpAkhew7iWUSUZeBKqFdDBnL/D63FQIV+kD3LJKCXzd4rtA
         BdMJd+9hI7iUvocWZY7kdloxNd64QRdQy8NzbRsl2bTePR4XSohPubYKfI7Xk8BzzwlL
         FCqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=z2ZgQ6P36pmFNjB9PaYdX4mIOjTsv0xzCprKQCXli6w=;
        b=qpwCrCElFdOlwfoS6CzAl2UH1Lmk1gnnkHASrBbj81SdjXmPqQ/Ync1nverJmcE8ty
         kcDHIRoMk7Euyat/DFnv/NGgwH8H4nlabPdb98+7YZ3nBgWay78IYPPmksbV/OrpteEK
         2VMPkjehqwzjQMwIRDF+qnOy2x3HCp3tT5+fEQ6JOajHGAAmEeWGwEHGy47eP8KVUnvG
         qsTQo3vpxUE5Dy6MeBKPF8lnVj6gdmfsuTu//54Jzr5YK1GAfENGxMPcLrtVG/YMf8Pz
         S8oeViccjzvLGxlampcCWjGlSbeq8HGdwozZGhNfY2Rj7Q6Bd32JUz4C1WPR6U8+sG82
         PdjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WGgAxIa7;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z2ZgQ6P36pmFNjB9PaYdX4mIOjTsv0xzCprKQCXli6w=;
        b=djolbXazSG2lzD3iDbEkYBopbFQgNfT58Gu9xYffioZzY4yvjwuCYGsf5TJUVZ+hBy
         hQcuQ8rULD5gCLYUGAIsa6GXMQxvf5kpuSq8JoAeIdLiaI3pMlVPfqnQcDYkoPbM+vUE
         nJ7L5vNR4IEQwLaBC9NlOvpQMqVL0MtV0irkUQg1m8QS4CbpcVvlvuWpc3z1JC1rldBM
         T8OwgqvVxrzF7ZHVfF0ZTFJS0NslGJwE2X6/vP/gvOwgHNcEOnfFA7GAvTQHGRfk+hpl
         y1vWqiJ/1U716fqCZV/SqiYtC9/3vbSvkPTQpS5dO9wddAsRcR54e4P6P3uPx6rRlp07
         yNxQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z2ZgQ6P36pmFNjB9PaYdX4mIOjTsv0xzCprKQCXli6w=;
        b=F3WhAMPVZJigs/EJgFBZPP1jv/U88RJGPn5SA6lTIGMbIwWixsF+gunJ638Vx9wuXc
         PCjeeUjNM6Ii60B+4OrfbK7QY8t2VaJYW1+r6kX+kgdzYx/QtemCcAc6ZpRGGgg6nNCd
         sSiM91pvJiM83n0HbyQeNpv6oFflSdoXZrjT3pS4TTA6mdQL4SJaWAqGqxsatw1ovNbd
         RdukPIPaMlazW7K0VqdpLvVvyyHaeSEZivKn9T+uPf+I6ms2NqFb7ZAbO3SqiNPOdieQ
         68WvMs4ldAkRcAsQsbVqFBt9byJN4uB3PaCnaPoQPlsEutScK8dxYsd0snwlLUduxv+z
         QoVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z2ZgQ6P36pmFNjB9PaYdX4mIOjTsv0xzCprKQCXli6w=;
        b=eWwLAHawCRieH2ktFXc107qUQwYqoQIphxcLhDXczzFhsVSu08GlEns3B5CYjuqHNA
         IRYu13NZ2TwvOCuau4HbIdSSsZnU6K1dUdLNRwST1YwRxFsyvoDQBtnxPiWo5ED1jLkW
         dA8upzwwQoX/oRr5ca9vhVDLJ37eHXiuSGTpe2ROCISrrDM+kUX0p1f8aXvYIELNn6Rf
         Hnq6ILvQKcR/D0V84WA5T152wN4Sso5Avgt8iqacJ0OBslhSJBz87DwI0cl4G7cIfZ2V
         ONZJMRoeOoqkToDaJqgTuPN7OEaS4qigQHCajYMBaCy/UF7EqA80ele2Sm8nGxl6eMpS
         1yXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jBvVsn5zJuacq2atPxMqHLqaOK/bIjM0ylc9R1BTWl82UJq1f
	obLwk47IgU/dbzTFGU8GRPw=
X-Google-Smtp-Source: ABdhPJzpsC0Vy8465p+n8jRBvdkTCxqL5kcdd2VkUwxqsdXzFPpe9MY5p1QFP1AIc0zaZH9iK84K3Q==
X-Received: by 2002:a05:620a:469f:: with SMTP id bq31mr18104558qkb.41.1640776984903;
        Wed, 29 Dec 2021 03:23:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e206:: with SMTP id q6ls9058160qvl.0.gmail; Wed, 29 Dec
 2021 03:23:04 -0800 (PST)
X-Received: by 2002:a05:6214:2484:: with SMTP id gi4mr22606769qvb.67.1640776984515;
        Wed, 29 Dec 2021 03:23:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640776984; cv=none;
        d=google.com; s=arc-20160816;
        b=npDXzS3Eic6AEwcvbLlmqV/r431TCO8sN2U61T/mxdeQyL8gS7mxLlXp3sEM+ojVQm
         haKelAkyrSloHUH9D7EEaXEBKIfiWORVdNzQK/wxLEMQ2iPekwcn3M6ysw8V1ok/9w1/
         DFV4s+yz38T4qpZwAyi+6xqFPpncTBj5KFYtlJlmpmRteVaGwp08VvLs47TwiCIKJIZP
         2oFckGPKcUtiMHQLL8neBFc0dk2332NYoyvB6aDeLjZnBHsUhHc6SuQLruPLAxt08Fjj
         DVPU2FfTy/A6zr9tjaBeb0VYoZcSXPUG4AYzftLrqNYEhgwPBgMkq8UhpjG0+nMHYVGi
         oMDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=B8D9h3oa8OpyqxIH3xe2rIOLYO1p/ntyh/ItEZc2ers=;
        b=gLh6R6687yBonxMr5sn0b9YZPlabdWl3ye8GNXJM/OCeFU1ltuMP5b45uyyi8PA+lG
         h4qaxaRzBOsVTiWL514Zun2kxd03EKl9pX+vfdX2DLTBqFfeNfzi9ciBIZna4/Tc9000
         aljeblVJZQBdTmuIbJCF7WWJWVN0rHWZfwUh8GPoU1Tl1B5kgFdm2CCxktEW3hfVDtaS
         FZcx30ZjFSle9TjEgiGcZkErtEOJ3gmkIsPn0p9WW8dGXpmxJHAAYoQz+3XTuN8xn9wU
         rvJUZxTMw/kRHz+m/KyznwXgL9xUc5+8Vme7eo/IGSXIAm7gEViC45DIYlAePUGdr3gC
         OcJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WGgAxIa7;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id k10si2051086qko.0.2021.12.29.03.23.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Dec 2021 03:23:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id f18-20020a17090aa79200b001ad9cb23022so19638620pjq.4
        for <kasan-dev@googlegroups.com>; Wed, 29 Dec 2021 03:23:04 -0800 (PST)
X-Received: by 2002:a17:902:9343:b0:148:a2e7:fb5f with SMTP id g3-20020a170902934300b00148a2e7fb5fmr27487300plp.160.1640776983676;
        Wed, 29 Dec 2021 03:23:03 -0800 (PST)
Received: from ip-172-31-30-232.ap-northeast-1.compute.internal (ec2-18-181-137-102.ap-northeast-1.compute.amazonaws.com. [18.181.137.102])
        by smtp.gmail.com with ESMTPSA id pf7sm27063114pjb.8.2021.12.29.03.22.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Dec 2021 03:23:03 -0800 (PST)
Date: Wed, 29 Dec 2021 11:22:54 +0000
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	cgroups@vger.kernel.org, Dave Hansen <dave.hansen@linux.intel.com>,
	David Woodhouse <dwmw2@infradead.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Julia Lawall <julia.lawall@inria.fr>, kasan-dev@googlegroups.com,
	Lu Baolu <baolu.lu@linux.intel.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Marco Elver <elver@google.com>, Michal Hocko <mhocko@kernel.org>,
	Minchan Kim <minchan@kernel.org>, Nitin Gupta <ngupta@vflare.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	Will Deacon <will@kernel.org>, x86@kernel.org,
	Roman Gushchin <guro@fb.com>
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Message-ID: <YcxFDuPXlTwrPSPk@ip-172-31-30-232.ap-northeast-1.compute.internal>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <f3a83708-3f3c-a634-7bee-dcfcaaa7f36e@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f3a83708-3f3c-a634-7bee-dcfcaaa7f36e@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=WGgAxIa7;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1034
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

On Wed, Dec 22, 2021 at 05:56:50PM +0100, Vlastimil Babka wrote:
> On 12/14/21 13:57, Vlastimil Babka wrote:
> > On 12/1/21 19:14, Vlastimil Babka wrote:
> >> Folks from non-slab subsystems are Cc'd only to patches affecting them, and
> >> this cover letter.
> >>
> >> Series also available in git, based on 5.16-rc3:
> >> https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
> > 
> > Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
> > and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:
> 
> Hi, I've pushed another update branch slab-struct_slab-v4r1, and also to
> -next. I've shortened git commit log lines to make checkpatch happier,
> so no range-diff as it would be too long. I believe it would be useless
> spam to post the whole series now, shortly before xmas, so I will do it
> at rc8 time, to hopefully collect remaining reviews. But if anyone wants
> a mailed version, I can do that.
>

Hello Matthew and Vlastimil.
it's part 3 of review.

# mm: Convert struct page to struct slab in functions used by other subsystems
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>


# mm/slub: Convert most struct page to struct slab by spatch
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
with a question below.

-static int check_slab(struct kmem_cache *s, struct page *page)
+static int check_slab(struct kmem_cache *s, struct slab *slab)
 {
        int maxobj;
 
-       if (!PageSlab(page)) {
-               slab_err(s, page, "Not a valid slab page");
+       if (!folio_test_slab(slab_folio(slab))) {
+               slab_err(s, slab, "Not a valid slab page");
                return 0;
        }

Can't we guarantee that struct slab * always points to a slab?

for struct page * it can be !PageSlab(page) because struct page *
can be other than slab. but struct slab * can only be slab
unlike struct page. code will be simpler if we guarantee that
struct slab * always points to a slab (or NULL).


# mm/slub: Convert pfmemalloc_match() to take a struct slab
It's confusing to me because the original pfmemalloc_match() is removed
and pfmemalloc_match_unsafe() was renamed to pfmemalloc_match() and
converted to use slab_test_pfmemalloc() helper.

But I agree with the resulting code. so:
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>


# mm/slub: Convert alloc_slab_page() to return a struct slab
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>


# mm/slub: Convert print_page_info() to print_slab_info()
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

I hope to review rest of patches in a week.

Thanks,
Hyeonggon

> Changes in v4:
> - rebase to 5.16-rc6 to avoid a conflict with mainline
> - collect acks/reviews/tested-by from Johannes, Roman, Hyeonggon Yoo -
> thanks!
> - in patch "mm/slub: Convert detached_freelist to use a struct slab"
> renamed free_nonslab_page() to free_large_kmalloc() and use folio there,
> as suggested by Roman
> - in "mm/memcg: Convert slab objcgs from struct page to struct slab"
> change one caller of slab_objcgs_check() to slab_objcgs() as suggested
> by Johannes, realize the other caller should be also changed, and remove
> slab_objcgs_check() completely.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YcxFDuPXlTwrPSPk%40ip-172-31-30-232.ap-northeast-1.compute.internal.
