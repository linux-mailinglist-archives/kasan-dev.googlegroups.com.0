Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBDFLROHAMGQEXMJLUHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 43FA547CD97
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Dec 2021 08:36:45 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id c1-20020a05620a0ce100b00468060d41ecsf1139249qkj.19
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 23:36:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640158604; cv=pass;
        d=google.com; s=arc-20160816;
        b=BjM0t3RoZilMxRqfBI6pBGb7HAieA/pWJgWwFr43svstJoGWKTscta0b6849jKnbNE
         jnw5clR0nqhmfRABYovYlTI2fTz0xxORmUZUZ2rOJRWq0kC03xLE7jDkU18D2KAWr9l1
         Cd8jVk9iCV40d/xWOtHtWLVSbwzlI9fvjvJbCUwalAeoY3pTNU9VxOYgLBEeeAgdhT5F
         hCaTCDXP7lYJo6k25Qn9AcTontkwB9hO/qk4jBgRDt2NIPL+xxRa6s7TnIwMx0l4VYy4
         szV7380XmV643ASflaB0WmkI7No/tXX/Zidq1RZf4KZSqpOr+WR2mU6lapal+gOnGMhe
         nbEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=3EPSftdbQ1QvX6Aleis3c9mdC9xrTOUojKkC3uA9LPE=;
        b=H2B35e5FeLookpGO8NQgVOuKovpF0eDkw42y11gdraUJiVAOKUjdrd82EWg3e1sswD
         3pQD7VPUJ9qWM994G4L8o8P/PwLL+E6xM5izpcDgpzsMutJXl2net0KwSErwkKVfq0jR
         gJlHFLkEV/fVSfnQrhe+j1MLJEHL+253z3EVuDsLgKaAe6LQ0sNcPYxHLT0tQMAe7lf7
         w92Bijp+FBKzlnqsLGbd5t4QmQ4SJlOonC5PMMvGie5xhUX4N/kw/m6ClUqbAT2DZT4U
         dqCpkE60aFTc6LYBa0nmyURkGMCxdEfasYJdB0N0OcIp5E2gaPcAfc81VjlsK+cSFQ+L
         D+jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RKpi5mEK;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3EPSftdbQ1QvX6Aleis3c9mdC9xrTOUojKkC3uA9LPE=;
        b=eBoObH/Hz/P4ddeE9lAYNBd9a59rziWeHerV8EXtyE9NXl5dxqOYWvmILqfpUNHbV3
         ArnMhTsQdKeu0YuOD3VNpiEhgU3tjmNPhdzql5VTsDm40F/9fq2Bb+EagmH/KOPjabP0
         nuYiqeAxe83oncWk2gB/CgV49WsjHytEQiGNcjuLjNswDa3bvyLa80mO23CzoXRYr9q1
         RNDNvFUGACrsVlzzm6b9mMWVQSDI4UlOyE5YRnuMmg3Dt9mDmkhERDQarOfj2eUsGV71
         6dsdz0nJEKA9X1DpOjaoyHyG4h2yS5oj9XxqOLyLGqUNexU3B4sE6gQfzpOrwj2caxse
         L9Ig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3EPSftdbQ1QvX6Aleis3c9mdC9xrTOUojKkC3uA9LPE=;
        b=SvVTEhmeSmxH0Swb7uYVt7HJY0BGJn8uD1jWeahSVjR8LHnnklrYOlgN2YMkQFHtQR
         MWRSfFmNTcCbpoMWlLUuJ5W4ARHAp32EQzcGDm9iGQiWYzsJBsgNFlij0LEVAd0RMoAa
         fJmKQXY5UvAvoUJd66ehzz93emd1bAve/B2VYcwtguida8A7kiDtIH8ItlqE6r6jZva2
         FgeuqbNMNPF+e3op8Ewg2S0OXo3+7ZxQ59nJ6ZJJ2KlTmy+bCXKvqLfpMOY0rsGOxUYL
         fcUDrkjjRglA8ezovfzVdC4UooGfKtDio9zPFt6Lc6FlTDvBsuM5zmDdOWTSwytcTTx+
         3UlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3EPSftdbQ1QvX6Aleis3c9mdC9xrTOUojKkC3uA9LPE=;
        b=4ITz6u2YfwFAsbN85No6Hl/13bI/pZsGC5duygTngXV0jnkAsZyeaXtqRvlFvT2p6K
         RwEzbpLx78vXyPRaAgDleotQ8lJeM2eVQttzQhT1rF0Mi9AInUC8NJxMtVPqJNG/53tR
         Xgo7bAw9iDE+hJT7Oz1H55gj3i+2zDS82DJ9TPbGpM2XQMILbWdVzqVJvCADbrsvOHZh
         5l/OaLTaqky3S7tKnUKGJe1o1S0CHa5+58CqzmmtapP5FHzUqPaQh45AZYwkKw6Kzuvb
         pR9MSFCd3X/q5B8V+zHXj9Otu26WUC7aL0p9sRDRDC6V5JKE2lD8kqZQ/4KrisMz+leH
         x6Tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532kaINgFLqW8scziIrGMBQ3/YU53tK49h6K9fBXTfr0+q5/RXuT
	NYTwHDQqe71TcOT/WNXFOrw=
X-Google-Smtp-Source: ABdhPJwmfxxl3mX++05oIpWGMNlzHPqgFwn9T/Ucw43qbNL5TEB1osyLTo1RVjRG/amKdyOsbElggw==
X-Received: by 2002:a05:620a:141b:: with SMTP id d27mr1142975qkj.233.1640158604204;
        Tue, 21 Dec 2021 23:36:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1789:: with SMTP id s9ls618302qtk.7.gmail; Tue, 21
 Dec 2021 23:36:43 -0800 (PST)
X-Received: by 2002:ac8:5f0a:: with SMTP id x10mr1243686qta.607.1640158603775;
        Tue, 21 Dec 2021 23:36:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640158603; cv=none;
        d=google.com; s=arc-20160816;
        b=j3dbnhFgDSQ15cX0bxto6hqxGke7msLrfd92vyOZ0+t9hl2yIjKi4zaGjw/p8Y7X67
         xtpRBCFtxOMJF9mMQLINuqRquTujrHAs+t4NKRK2RaCZmPHn0MqBs0+25y2suUSyLTAr
         lN8XqxcwTsOhhJ5/4wwAcAnCnv1JfFkE9pCSE+erf59+bdnER5qXSOi6q2cXzTGU4giP
         NRqazszJOLYFrPC6gPNDhREN/tP8CHdZNsBkxPP3qbyKcoH4q3bBWqsojDAIbZmY/0TE
         gevyGdjA293l2+Q9Tm8lnx0GEnaw96d8P9Q5CxUufmNQvHx27NPGKNIhI0n5Dyk2oXP7
         iznQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WrvvWhSLi37P9Hu9a/lN3dt16MiGegPkcEW+eWXvnco=;
        b=yde6F7+MNpbO1F486OU4z7c5b9ReXSDwKOw/+FthuJKgr9wwZ1vgjOQzPn1H0k0hRe
         1wVrWIKN0I60LkMpROMGkVyUa+eViBDTTOQXMaTT8+ChJcK8r0bd/CtmRnOwTjlVDJ3i
         mLslTYkeHIrZCbxMFBsTsLxxnMUqZRZ9UHPU+6TvjMUm/uu0WJotdB4d0OHIgEVWly0G
         OXPW5QS2VCHvsRAU91y3sVAUzXvbc/h1kDADSpq1tWt6qPqB0eVc7eClIpZQTvj/zigv
         GHAEUwfudePFX78O1CoD91Lay/RCI6z0Tc0qsd7v2mMKQ+2Lmn8Rztu1BU/TXg36FdJf
         Ladg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RKpi5mEK;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id l20si276630qtk.2.2021.12.21.23.36.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 23:36:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id v25so1389552pge.2
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 23:36:43 -0800 (PST)
X-Received: by 2002:a63:8f06:: with SMTP id n6mr1787692pgd.95.1640158602956;
        Tue, 21 Dec 2021 23:36:42 -0800 (PST)
Received: from ip-172-31-30-232.ap-northeast-1.compute.internal (ec2-18-181-137-102.ap-northeast-1.compute.amazonaws.com. [18.181.137.102])
        by smtp.gmail.com with ESMTPSA id v4sm884943pjk.38.2021.12.21.23.36.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Dec 2021 23:36:42 -0800 (PST)
Date: Wed, 22 Dec 2021 07:36:33 +0000
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
	Will Deacon <will@kernel.org>, x86@kernel.org
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Message-ID: <YcLVgdpyhZjtAatZ@ip-172-31-30-232.ap-northeast-1.compute.internal>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <YbtUmi5kkhmlXEB1@ip-172-31-30-232.ap-northeast-1.compute.internal>
 <38976607-b9f9-1bce-9db9-60c23da65d2e@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <38976607-b9f9-1bce-9db9-60c23da65d2e@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=RKpi5mEK;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::536
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

On Tue, Dec 21, 2021 at 12:58:14AM +0100, Vlastimil Babka wrote:
> On 12/16/21 16:00, Hyeonggon Yoo wrote:
> > On Tue, Dec 14, 2021 at 01:57:22PM +0100, Vlastimil Babka wrote:
> >> On 12/1/21 19:14, Vlastimil Babka wrote:
> >> > Folks from non-slab subsystems are Cc'd only to patches affecting them, and
> >> > this cover letter.
> >> > 
> >> > Series also available in git, based on 5.16-rc3:
> >> > https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
> >> 
> >> Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
> >> and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:
> > 
> > Reviewing the whole patch series takes longer than I thought.
> > I'll try to review and test rest of patches when I have time.
> > 
> > I added Tested-by if kernel builds okay and kselftests
> > does not break the kernel on my machine.
> > (with CONFIG_SLAB/SLUB/SLOB depending on the patch),
> 
> Thanks!
>

:)

> > Let me know me if you know better way to test a patch.
> 
> Testing on your machine is just fine.
>

Good!

> > # mm/slub: Define struct slab fields for CONFIG_SLUB_CPU_PARTIAL only when enabled
> > 
> > Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > 
> > Comment:
> > Works on both SLUB_CPU_PARTIAL and !SLUB_CPU_PARTIAL.
> > btw, do we need slabs_cpu_partial attribute when we don't use
> > cpu partials? (!SLUB_CPU_PARTIAL)
> 
> The sysfs attribute? Yeah we should be consistent to userspace expecting to
> read it (even with zeroes), regardless of config.
> 

I thought entirely disabling the attribute is simpler,
But okay If it should be exposed even if it's always zero.

> > # mm/slub: Simplify struct slab slabs field definition
> > Comment:
> > 
> > This is how struct page looks on the top of v3r3 branch:
> > struct page {
> > [...]
> >                 struct {        /* slab, slob and slub */
> >                         union {
> >                                 struct list_head slab_list;
> >                                 struct {        /* Partial pages */
> >                                         struct page *next;
> > #ifdef CONFIG_64BIT
> >                                         int pages;      /* Nr of pages left */
> > #else
> >                                         short int pages;
> > #endif
> >                                 };
> >                         };
> > [...]
> > 
> > It's not consistent with struct slab.
> 
> Hm right. But as we don't actually use the struct page version anymore, and
> it's not one of the fields checked by SLAB_MATCH(), we can ignore this.
>

Yeah this is not a big problem. just mentioned this because 
it looked weird and I didn't know when the patch "mm: Remove slab from struct page"
will come back.

> > I think this is because "mm: Remove slab from struct page" was dropped.
>
> That was just postponed until iommu changes are in. Matthew mentioned those
> might be merged too, so that final cleanup will happen too and take care of
> the discrepancy above, so no need for extra churn to address it speficially.
> 

Okay it seems no extra work needed until the iommu changes are in!

BTW, in the patch (that I sent) ("mm/slob: Remove unnecessary page_mapcount_reset()
function call"), it refers commit 4525180926f9  ("mm/sl*b: Differentiate struct slab fields by
sl*b implementations"). But the commit hash 4525180926f9 changed after the
tree has been changed.

It will be nice to write a script to handle situations like this.

> > Would you update some of patches?
> > 
> > # mm/sl*b: Differentiate struct slab fields by sl*b implementations
> > Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > Works SL[AUO]B on my machine and makes code much better.
> > 
> > # mm/slob: Convert SLOB to use struct slab and struct folio
> > Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > It still works fine on SLOB.
> > 
> > # mm/slab: Convert kmem_getpages() and kmem_freepages() to struct slab
> > Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> >
> > # mm/slub: Convert __free_slab() to use struct slab
> > Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > 
> > Thanks,
> > Hyeonggon.
> 
> Thanks again,
> Vlastimil

Have a nice day, thanks!
Hyeonggon.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YcLVgdpyhZjtAatZ%40ip-172-31-30-232.ap-northeast-1.compute.internal.
