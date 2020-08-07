Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6E2W34QKGQEM5GRODY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F63A23F1D9
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 19:20:56 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id e14sf989926wrr.7
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 10:20:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596820856; cv=pass;
        d=google.com; s=arc-20160816;
        b=EJTH20G/kbToR1Pimfqp42BZ3lm1sX0TzvLQKcsLO5DdTlpd3yqdn4ckI3wEBWEdka
         TXvswCSL39iCFBpagpqZaIJXwkQQjaW5mbDJtrf3a9s7v0puaj/ecvAPI2wSn2nhve69
         yJqqiAQu1R3JFewKzrVgbvzJuTKYnsn0WI81EL0lb/wtLm5qfXGefrqns7oIC8B/LROI
         k+6eDsMTpTA17bs8+u4OWIvFWgiEL4xziTifEyHk+tUuVpsmB/U+5YUvWaJ7uHbW8d4d
         OrtRJOGhkt9BjZgodZt+zOVnJ7By7M6CAFwgAlbrBVu0fVcEDqwOV5LT6lbt8ObQWB+8
         kwmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=SP6Cx1dk9FqC3GO2nu9crEclszbNgWggkrLlEi/ln6Y=;
        b=Me1dOOI57PJz45ndtTaQlCF/fUIbXj8HIcV2f2Qr/+lclLYKp5QQmEYAO3StpBiIX9
         vAGV/8p53PAhdvDkGGJBFgbeaXTl8uxIsR2KRvvBHrFNiV0h9dsTlavFsRAmvjfen1Gv
         gF8q5TMq0AKfHPxaCtbCpI3KYIOKQzlIFLd6cZWPivN79sWa0IVk55W+sROZFMoeP54y
         OpZGBSWWlJyN5jXk13z3A44Fq52tRS+ZPS1La4Eh2ghmXZPKXPI8+V+zzeQI4xAnz80O
         Zw3+jhdvTSh9HdWpc73cfZ8J/XwYFJoJ916km1VD/XYIBJ2C32C8a9I2h4bgE866q9d3
         EQEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J7mC8E68;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=SP6Cx1dk9FqC3GO2nu9crEclszbNgWggkrLlEi/ln6Y=;
        b=VBU51PjYKrAbkjGfMnAWkJDizFy1ZI+X47YT37N38HyAXgwLfF0CnjNNVIpJSsBsnT
         Ms9eHWyU3FOM24XsNIgD0YobMkdZt0I/Mxk4YbDQ2HToRskh+aZ/O2cSX/d+GNow6U3B
         0I9SfKZqcCm7Q+QXoQOhx0nKm3aHyWKxa7S+CoTwlbGp31se9SVOkIfc6IuzRvQGt4fH
         kkcJFvJsYxjrq47vkcrP5T6Pc3laPhVRBl5nkPUc7to3YyKrP0IaDjteY+szCrefgu+x
         BbUOq6E1VR+qzQusVepSwkrhlnEfifjXmly6sOZ0s/W/Xb1OgcEat24fD2hK3SYYZQMc
         AbjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SP6Cx1dk9FqC3GO2nu9crEclszbNgWggkrLlEi/ln6Y=;
        b=pkH7ywgM24Uclbr4AFpcGgXCa75MC5dKOrEnDfxZC/115jxJX+ao6kXNEvSsX0h9+A
         fnc9LkrlaZ0uz/nS/0SjKK7xojwUWsCviV9jxQeIw/tqatN9h1pEiil7Jsp/Hdb5otH7
         I79lerivrHTeCiY9lOoMCisSnBMfMm5R0A+RwsSoPec/sS/NptlCrunUJFWJL125ui5t
         GjjJ2OYFLVs8MK+FHcXnaT3WA+nTtWnhHeq6LQQ0E/ujpetiPtmesswYg/uRUtf7WBYb
         Wq5UdotQD82jBUk81gC6dhl+ths56Qx9Hl7RgTOJjtpALPymrjzLaW7mhu+h+Kh334mi
         W76w==
X-Gm-Message-State: AOAM530jqRVj7jp2A9tqYzZ08Fe8PmmgJh2/D7Xv5sEqjkh/4YuvHhFR
	MkD8dpvDzgJCFpChItSzASw=
X-Google-Smtp-Source: ABdhPJydJJnHehRBGjFCbZuDHfuNs395NIDGGem1Fy1E15UgR1utmSCrK2OBv9udqGpj6sYdTp6Btw==
X-Received: by 2002:a05:600c:21d3:: with SMTP id x19mr14123641wmj.174.1596820856314;
        Fri, 07 Aug 2020 10:20:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:b1cf:: with SMTP id r15ls1441378wra.3.gmail; Fri, 07 Aug
 2020 10:20:55 -0700 (PDT)
X-Received: by 2002:adf:ba83:: with SMTP id p3mr13348427wrg.246.1596820855688;
        Fri, 07 Aug 2020 10:20:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596820855; cv=none;
        d=google.com; s=arc-20160816;
        b=WupQHvawG8rk/tbaaq8VTRR+Q96XXset+fJyUt4DiP7pudNfIUkWpHs/jLvXLaXKFw
         7TfctUkPKoYOVHDdwAnEntBXXgv5IZnWHgDmtYoYR0CnhLNyc4GuEkNYv8mOQ/QXHiui
         xYKLc6L5i6brtwMyh/dOuck5qks9ziVuinlyeFdab059B/iKtXbOSs2lAbpqfHpdaJia
         KWPxxk1HPNY5iPOQhFrWDwZIfL4PMpYByfHH7JHovIr3cYl6iNOt8/fmPMWqUQdcROLR
         xrx5JEPLDofJHGl3Duh6DR4sh6OjBGlq6Z6lGr0xbUD5VB4/90z3/NSP/EM+48HjPiDA
         ugcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=s8Gg7Zt8gvjVcJNqZJEesrPztRK/2q4jyigfD0LuxL0=;
        b=LSaIhG7YB6LL/Zn+AWHUe/n0JWVHpWDHFexXf23QXBgLVq+OAQ4DBi1MbHJwLjcUYu
         739l4/gOItSRWbMAr76Yx0FslNW5+GgNSsklQKmhfRsGDDdbnSEaswHv9j5K7RiB2UsF
         9BQTOMCxj2Dvs/Ld14MVUODaugQg8qaYz708rPBELHKXnjtq/A7ze+qFkXZg1+KUxJLL
         BT3/mPxAzHw2P25nEy1r9rvr8FIjxZTZ4uf0fP5iJivZ8/aYhq9/N/tjkqat62jr2j8d
         iw139hriYgsTV268OWOWPivoWwFoq/XUWVFcr63TDMPLhhddfXmJNGZe4JhZwHAaTY1P
         bmwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J7mC8E68;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id j16si440389wrs.5.2020.08.07.10.20.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 10:20:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id c80so2378029wme.0
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 10:20:55 -0700 (PDT)
X-Received: by 2002:a1c:f204:: with SMTP id s4mr14385469wmc.9.1596820855087;
        Fri, 07 Aug 2020 10:20:55 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id j5sm11530953wmb.15.2020.08.07.10.20.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Aug 2020 10:20:54 -0700 (PDT)
Date: Fri, 7 Aug 2020 19:20:48 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, Christoph Lameter <cl@linux.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: Re: Odd-sized kmem_cache_alloc and slub_debug=Z
Message-ID: <20200807172048.GB1467156@elver.google.com>
References: <20200807160627.GA1420741@elver.google.com>
 <202008071010.69B612E@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202008071010.69B612E@keescook>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=J7mC8E68;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, Aug 07, 2020 at 10:16AM -0700, Kees Cook wrote:
> On Fri, Aug 07, 2020 at 06:06:27PM +0200, Marco Elver wrote:
> > I found that the below debug-code using kmem_cache_alloc(), when using
> > slub_debug=Z, results in the following crash:
> > 
> > 	general protection fault, probably for non-canonical address 0xcccccca41caea170: 0000 [#1] PREEMPT SMP PTI
> > 	CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.8.0+ #1
> > 	Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> > 	RIP: 0010:freelist_dereference mm/slub.c:272 [inline]
> > 	RIP: 0010:get_freepointer mm/slub.c:278 [inline]
> 
> That really looks like more fun from my moving the freelist pointer... 
> 
> > 	R13: cccccca41caea160 R14: ffffe7c6a072ba80 R15: ffffa3a41c96d540
> 
> Except that it's all cccc at the start, which doesn't look like "data"
> nor the hardened freelist obfuscation.
> 
> > 	FS:  0000000000000000(0000) GS:ffffa3a41fc00000(0000) knlGS:0000000000000000
> > 	CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> > 	CR2: ffffa3a051c01000 CR3: 000000045140a001 CR4: 0000000000770ef0
> > 	DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> > 	DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> > 	PKRU: 00000000
> > 	Call Trace:
> > 	 ___slab_alloc+0x336/0x340 mm/slub.c:2690
> > 	 __slab_alloc mm/slub.c:2714 [inline]
> > 	 slab_alloc_node mm/slub.c:2788 [inline]
> > 	 slab_alloc mm/slub.c:2832 [inline]
> > 	 kmem_cache_alloc+0x135/0x200 mm/slub.c:2837
> > 	 start_kernel+0x3d6/0x44e init/main.c:1049
> > 	 secondary_startup_64+0xb6/0xc0 arch/x86/kernel/head_64.S:243
> > 
> > Any ideas what might be wrong?
> > 
> > This does not crash when redzones are not enabled.
> > 
> > Thanks,
> > -- Marco
> > 
> > ------ >8 ------
> > 
> > diff --git a/init/main.c b/init/main.c
> > index 15bd0efff3df..f4aa5bb3f2ec 100644
> > --- a/init/main.c
> > +++ b/init/main.c
> > @@ -1041,6 +1041,16 @@ asmlinkage __visible void __init start_kernel(void)
> >  	sfi_init_late();
> >  	kcsan_init();
> >  
> > +	/* DEBUG CODE */
> > +	{
> > +		struct kmem_cache *c = kmem_cache_create("test", 21, 1, 0, NULL);
> > +		char *buf;
> > +		BUG_ON(!c);
> > +		buf = kmem_cache_alloc(c, GFP_KERNEL);
> > +		kmem_cache_free(c, buf);
> > +		kmem_cache_destroy(c);
> > +	}
> > +
> >  	/* Do the rest non-__init'ed, we're now alive */
> >  	arch_call_rest_init();
> >  
> 
> Which kernel version? Can you send your CONFIG too?

Sorry, didn't see this before I replied to the other -- it's here:
https://lkml.kernel.org/r/20200807171849.GA1467156@elver.google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200807172048.GB1467156%40elver.google.com.
