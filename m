Return-Path: <kasan-dev+bncBCF5XGNWYQBRB3MYW34QKGQEWLMAENY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id D7EF423F1C9
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 19:16:30 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id d6sf1961148qkg.6
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 10:16:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596820589; cv=pass;
        d=google.com; s=arc-20160816;
        b=puKIAGn9YhUHcTX13BaFcGauCVmG12cQOZnT4zoytvfFBXSjB1BznGQQyAcuBrAVxk
         qSrc/KiCcwfPVCVwCNtf5vMJEZsChKOkKY2wY8edrDm95NX8cjl9wNgy3M5/vbkVGqHH
         hVl57oQC/Vas4ua9Zm4Vt5MDzWOq6LtrLndrCvyU4ERLLDykwjHwqrtUUBsxsxpFUrc2
         Dkdjf1kEhOiSpvHxCQzb9oOTkFDTMwz1wEua9fSipsEiZE+Sk7m6R2N0vhVtqbqsLZfW
         I7ZS0N4kgGw5Tx8kxhCDQJHhQQjRoyyTT1QY8HX31SHqnC1EPB9ZYHfMFkAHczGVGooJ
         uixA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zrH3CbigITnfveNuS9NUiExdRr9vHsIm+64lR/YTWYQ=;
        b=dgnZ7+4UuX12u3KgcHF7+HlbG3LUDzePxv9F5ATokZxbLZW+OsnbPvDQOluDrSAIqN
         56IVzvzsN9wBdb00WNqNKuO+Wh4yCWXLonbE2BlyeFMXYMeq5o59RzVeGZBLoo87qTMC
         xfrX80xzlhBDDdn9tPIicijtuqrPMjxHvw5guZHdHwxjpJpaPjdFXpxG4AzBH+b3IOvM
         JgwJmonJ0MI3/9lt0h9y74yKRiCLoveWHkW+kRvLLMpkelg45M+xuEWDtXV5+OMDdpe7
         UzwHPONWD80ihUVBUMpp0c6NpRK4RLJYa3pJvext9Wg2ITS147oXCutLBs7MHbFT8983
         40qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Ge+HwPtY;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zrH3CbigITnfveNuS9NUiExdRr9vHsIm+64lR/YTWYQ=;
        b=BEdsm3dkJH0CO5bkMrmuPEu75R6UkcSJpJlvP117fnosjIF5cc3M6r9r8LH5yEJ/YL
         d+Gf2dcagRcRXzTniIpkuZy3DsiiJwyjimv4TeVjlEVHFY5yJ60+iFYshEXkx0uZN/Mr
         RPpFw/rA9rMCa3qAH+NaECDKkrhctYmdZDfIDdo9mmgf3wFAUbOOybGJ9Tzf8bOjpY7U
         nU1zQq1c2Vv4ti3Zj+5iblY3NeQBLQdsdp8AwcRyJvUEM6Yhj9t7qhEMQXu/w0yjE+DY
         FtFGUjuKP61fVOb//f1QruPYgEWI/qze/d1gkxuFfa5cPJ2bdu+VTygom1eErZu6bec/
         9aMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zrH3CbigITnfveNuS9NUiExdRr9vHsIm+64lR/YTWYQ=;
        b=NdAvGloy9kvW55kWu7Gvt+kQ/XBJ6o9hf2fPLovhs9/VOGLMXB2CGE+6j/djmZ8ub2
         LYNer6DNzSeWhGKB4MXAEz53yjAh0UQknew2amJ/RRvqAa+jOSidyzTlClHLDrkRuMnF
         RVekrTmPtDdieZySKlL/TIjV3CoaSTZFeAtlNY9VI49HhMgU9fIGoiKClOI0o67I1lhi
         j2IIn9ApnbB8bEwWjTEFcNj2ol0CKBJ9qaerYsK1r0nvYUA0NSnW+OCSGVqeDME/OAb2
         WClVQhWm/b1Ww4a2OiqlxAIZJosW74NXdjH82t36//3B1yeasdQEHd/IwhHjl9DvdLUq
         AC2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532n5if2oPBBW3FSlXvF3YMpAzqkp0iU65EPVkzXgE9w9dDf9KQd
	2CifE7dAfRhJgCXpSk4sv3s=
X-Google-Smtp-Source: ABdhPJwblAJJoJJJHUwHR2hlUWjGHFemL6U3TZ4tcd0IVsH9sIOtLXUzFhYrvtqK4xgWEpzQ/qqz8A==
X-Received: by 2002:ae9:dc03:: with SMTP id q3mr14768482qkf.276.1596820589700;
        Fri, 07 Aug 2020 10:16:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:334:: with SMTP id j20ls2540973qvu.5.gmail; Fri, 07
 Aug 2020 10:16:29 -0700 (PDT)
X-Received: by 2002:ad4:54d4:: with SMTP id j20mr15649309qvx.6.1596820589215;
        Fri, 07 Aug 2020 10:16:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596820589; cv=none;
        d=google.com; s=arc-20160816;
        b=zCjQi2rSPD090kaETbx72WFVCZ6grYQLcyPFm3x3nSkQXidzwYKb5ynmMRGIRlTFkD
         89nJ0bCNt2diHaXvLJxksxRhaSkMi/M+KQFb8ySyOwV276Y+F6qMXLacJUO6lsXCdU98
         8fXO6UhExsFO16zMDd3Y5Yo1o8KR30YuO6j9LDEvQW76wyvlVAMLJEAfyxDBjrxg+fhF
         O3oi51W4PSBzaNh5g5UXboxDruINk7TZH/Pc4LlESLpSX8qXi995Nh8YGE8UV7Q7coYi
         7HRmiAYx81Q8cTFEY06zjhasDm46Oh/eNCj220qnqqHvwUQ366ANYP7YN7Ae2Yg0DIxt
         2OEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xF5/XqhC95C9KSNipegVoItT8yYvzxsVDvSLIvoWnRA=;
        b=Pz3lZE7orvHO0M3VrDbBR1wDeIDUHjVKSF9s6FPhm9ASrfYjs8z2N3irvOlr5DGge7
         5dU4nv6m9M67A/OQIrwB76i8XNJWwhRTUhYRLLXY6pNUGt3oiU6rEHO4FyzCJZPmrAcG
         ppsBT7SXRaEdelCM8AVz2qjbE197q5YuH1XAAFqe8cct/clH9uEm+VGgKzJNkFiqd7/k
         yg6T5i1JUF8lLsnvTU+Nyf0sAOok4mxoR9ircnsOsY7b2hdS0FucZgF6ZMzlsvrlqtwo
         5vdvb68Z6+q5A9Ajhz7czA0nvrsmcoYI3/75S46UtWiFW9pEXQ0rjA2lE+77a+Bp+cwz
         v16A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Ge+HwPtY;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id n26si610961qkg.5.2020.08.07.10.16.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 10:16:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id f193so1328444pfa.12
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 10:16:29 -0700 (PDT)
X-Received: by 2002:a63:8ec8:: with SMTP id k191mr12472113pge.154.1596820588188;
        Fri, 07 Aug 2020 10:16:28 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id i7sm11565112pgh.58.2020.08.07.10.16.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Aug 2020 10:16:27 -0700 (PDT)
Date: Fri, 7 Aug 2020 10:16:26 -0700
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, Christoph Lameter <cl@linux.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: Re: Odd-sized kmem_cache_alloc and slub_debug=Z
Message-ID: <202008071010.69B612E@keescook>
References: <20200807160627.GA1420741@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200807160627.GA1420741@elver.google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Ge+HwPtY;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Fri, Aug 07, 2020 at 06:06:27PM +0200, Marco Elver wrote:
> I found that the below debug-code using kmem_cache_alloc(), when using
> slub_debug=Z, results in the following crash:
> 
> 	general protection fault, probably for non-canonical address 0xcccccca41caea170: 0000 [#1] PREEMPT SMP PTI
> 	CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.8.0+ #1
> 	Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> 	RIP: 0010:freelist_dereference mm/slub.c:272 [inline]
> 	RIP: 0010:get_freepointer mm/slub.c:278 [inline]

That really looks like more fun from my moving the freelist pointer... 

> 	R13: cccccca41caea160 R14: ffffe7c6a072ba80 R15: ffffa3a41c96d540

Except that it's all cccc at the start, which doesn't look like "data"
nor the hardened freelist obfuscation.

> 	FS:  0000000000000000(0000) GS:ffffa3a41fc00000(0000) knlGS:0000000000000000
> 	CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> 	CR2: ffffa3a051c01000 CR3: 000000045140a001 CR4: 0000000000770ef0
> 	DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> 	DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> 	PKRU: 00000000
> 	Call Trace:
> 	 ___slab_alloc+0x336/0x340 mm/slub.c:2690
> 	 __slab_alloc mm/slub.c:2714 [inline]
> 	 slab_alloc_node mm/slub.c:2788 [inline]
> 	 slab_alloc mm/slub.c:2832 [inline]
> 	 kmem_cache_alloc+0x135/0x200 mm/slub.c:2837
> 	 start_kernel+0x3d6/0x44e init/main.c:1049
> 	 secondary_startup_64+0xb6/0xc0 arch/x86/kernel/head_64.S:243
> 
> Any ideas what might be wrong?
> 
> This does not crash when redzones are not enabled.
> 
> Thanks,
> -- Marco
> 
> ------ >8 ------
> 
> diff --git a/init/main.c b/init/main.c
> index 15bd0efff3df..f4aa5bb3f2ec 100644
> --- a/init/main.c
> +++ b/init/main.c
> @@ -1041,6 +1041,16 @@ asmlinkage __visible void __init start_kernel(void)
>  	sfi_init_late();
>  	kcsan_init();
>  
> +	/* DEBUG CODE */
> +	{
> +		struct kmem_cache *c = kmem_cache_create("test", 21, 1, 0, NULL);
> +		char *buf;
> +		BUG_ON(!c);
> +		buf = kmem_cache_alloc(c, GFP_KERNEL);
> +		kmem_cache_free(c, buf);
> +		kmem_cache_destroy(c);
> +	}
> +
>  	/* Do the rest non-__init'ed, we're now alive */
>  	arch_call_rest_init();
>  

Which kernel version? Can you send your CONFIG too?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202008071010.69B612E%40keescook.
