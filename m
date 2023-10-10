Return-Path: <kasan-dev+bncBDBK55H2UQKRBOWGSSUQMGQEPNTMEBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 205C87BF833
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 12:11:08 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2c0165b5c5csf20038311fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 03:11:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696932667; cv=pass;
        d=google.com; s=arc-20160816;
        b=k29ETcgaJYAsdYEzrTdXv/9n9CypFF273Ck/DRZOjwbI79uEo511rpZMEpvcvs44yB
         uOVGwzICLQso7fSYKUffmn8RhQjRikRwZDexou/QNbUjI2PiW1fRhkZYR8AxrYQkdR8m
         8lAcEHAQJH08R264vGlGfdYHuLDxy6mi4lU0rLfMH/QXkS7s5Beq4u/5tgm7TTYzipX/
         4yIND10CH/+ase8JPiDdwsN5Dhqp1c8AoclG+PPZdAnl/LhN22TdiXw+mqxBuwXe0eD/
         G8AGQNAitDtiWL8hhwaAhdK3Ca1Kj7EYJUXjNxoWfJoq5OzKQlPxqvTWkZurbT3hTi0W
         DIZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8Ar/dZnEoHUgO4A3NGjJHYzHlACnzubKcCwOlAq8/6Y=;
        fh=mUf2ndWDL5c84ldV6DszTy3j42/aMLRyYOLwUcEDGhM=;
        b=vP/+0bDFpCnz7O91uNEAYdaifpC+O+qBHBsQx4xnGPCrMpbI2H3TyPBziQeBtKfNBX
         40+u75F3nSV5G42EsmMeTQEegBEdbEf3h9Iy+6OE8FIrGHhxSi/kFZNq+6PfgQFff9X8
         rEHQ37WhXFviCzxx8Kuvfy7HIpt0TPp6SeSctIXSnuYI5bmgeNlQ6ApxApAytAWWLB8m
         hTh3iZFIlwsKXHHL0GHsYexg1rE31EEkbCySZNiit4LJUgz+xpqC1VEXCL1uzgdWOk37
         /K5p8X4UFF2Du2rH0unOM+3x1pQAB262H4OGBtnI0qqSbhp1o7Zbzsb7z6hHzgbdicAV
         SmKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gYdO8iqa;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696932667; x=1697537467; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8Ar/dZnEoHUgO4A3NGjJHYzHlACnzubKcCwOlAq8/6Y=;
        b=pjnE8KE8c5Vxz9UV8/LgC/w/TqsR+VBSAaWdaoddGCM300pYkLNRPP90oK4VArvX+O
         5/9OFurFOXveIyGGB57dJ19K8Rvsx0dHKslMstEwpoOKKYssOwQGlCixeXPNA90ivtds
         3daj6XGHsXt+Qg+7/GApioBx4AMDsMa+SKyOgXCkRpQTOQ5uX8eLr9V3X6BlZdcXMmMP
         8GgK4pTSeBFAGRey4yNZJbvJ7el3GaoyHUyWScd0mffpZMlT20R8o8PBL0ZflPdDq5Pn
         A3LtnFiKHXNgKzTANVnr8CiT0XyZun8QvYssGJWIuy0leRuwyli8dnMtqBzoh+J+WTEH
         y4Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696932667; x=1697537467;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8Ar/dZnEoHUgO4A3NGjJHYzHlACnzubKcCwOlAq8/6Y=;
        b=Z7sWx/KiId3scId6poSehlkQwtLD15FYqA6vMHjRCGzVLhFI9WM6gtX9F6+i2cR+mO
         Lc+U9gMPXmFwlfUIP5fOSaFlocJLAR6NfY/Y7t/6L3U0aUYbRmDH34USI2d4TOLzV5W+
         1NsENQrWKazDE3ebHJ9VR468A8nh7VhQQHvxHPq9x2EGmOq6ZTU/aGeMLiaR+JoEgI42
         fD9xLK0dmHnYvPx3YBzz+8LKZUIg07VCg6FXqPFaOB8crUv+8AMxwmFHZOTZxUf+lOSz
         xDhOSLmzf5Mw8iZgG3P5XmMX/3JZKjExm6EuhYOntKQ5fYC9c87JgyqzRITx6NSdf6Ir
         Mxbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxpYmi84NyFxX3cyivU268euptvEQL+uK3839crXtV8pVWlILg8
	2HunKa2FGu2ZAlFnbwjMRtc=
X-Google-Smtp-Source: AGHT+IFPnRErJ0HyIUYCF5BKkNJSNMXagSWuGpIrZ5FV8rB4OrZdlQiIguSqd1Z33eGJ609qyrPOdw==
X-Received: by 2002:a2e:81ce:0:b0:2bf:f5d4:6b5a with SMTP id s14-20020a2e81ce000000b002bff5d46b5amr18584514ljg.41.1696932666440;
        Tue, 10 Oct 2023 03:11:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:98c4:0:b0:2c0:d63:6f2 with SMTP id s4-20020a2e98c4000000b002c00d6306f2ls847328ljj.1.-pod-prod-01-eu;
 Tue, 10 Oct 2023 03:11:04 -0700 (PDT)
X-Received: by 2002:a2e:9bd3:0:b0:2c0:2b1b:d14c with SMTP id w19-20020a2e9bd3000000b002c02b1bd14cmr14395319ljj.24.1696932664346;
        Tue, 10 Oct 2023 03:11:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696932664; cv=none;
        d=google.com; s=arc-20160816;
        b=fDhB1KntHfjGXrjSxTqXxSJFwX5aO1CFpp6GfROa5JLr/c5CiPpsT/hDxLRvaIZn8z
         K1LFx7dj3TmoVh0JKIVrEmL6Eznrr+OyAVG++l9fnA1U0mZYnUSZnjnENgQlRHwVAa5+
         t+S6AptjENyyYzlcc//vpWm10CyPSaTsMdSI7ShOlVA4DbTT8uJTyS5tyLqD+Tjfs3dK
         x5kMXFv1XMyk/3RscEUMMkvhHzdYz920EpXNIMo3HjZnLTuM9ymtfH4NJYmG7eC04vPI
         sR5asZm4lkSfqTIbqZdSUSZSaCR910Mxs1bjRLbwzBwTr5BjLV5ZmbMYdGbT1ipwQrNE
         eqIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=oj1axhxOjginGEELIsLjRAtpZ1XYE8QEYtnImm9KFkM=;
        fh=mUf2ndWDL5c84ldV6DszTy3j42/aMLRyYOLwUcEDGhM=;
        b=zNYfcPP3E/v8iC8HK9F/LwMPG6e//hIMT0VLe+lIW7FHyF8wyQGrZcsSxmT17aswYt
         S0h5m80v2IFunbyq/C+7P9Xtpz3bAGjjIdD/Tm/Cl9d3wqe4L/2mJbgCdhYi69MzFcF+
         vr7we2RCfk2byu58wbPG+IRZqCpkxEw6oPAotnpg1lFl2QfIYsPTV3tZHlzbXRzVnc+b
         h82p+pyd8VZEF9fd24q2BQCHuF38hgNV6GWd96Yv0P+Agv5/K831WJuvyYrCnavghhUk
         b3B/dcmUQIvPSkzSGaXdGVTIxrn6vZTsrjwYRw+7E7sPLKwfYPwCWtYMHZKRgL987Iwc
         TEKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gYdO8iqa;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id e3-20020a2e9e03000000b002b9d5a29ef7si560477ljk.4.2023.10.10.03.11.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Oct 2023 03:11:04 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1qq9hY-0040qP-NX; Tue, 10 Oct 2023 10:10:57 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 63DD1300392; Tue, 10 Oct 2023 12:10:56 +0200 (CEST)
Date: Tue, 10 Oct 2023 12:10:56 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Borislav Petkov <bp@alien8.de>
Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Fei Yang <fei.yang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCH] x86/alternatives: Disable KASAN on text_poke_early() in
 apply_alternatives()
Message-ID: <20231010101056.GF377@noisy.programming.kicks-ass.net>
References: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
 <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=gYdO8iqa;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 10, 2023 at 10:19:38AM +0200, Borislav Petkov wrote:
> On Tue, Oct 10, 2023 at 08:37:16AM +0300, Kirill A. Shutemov wrote:
> > On machines with 5-level paging, cpu_feature_enabled(X86_FEATURE_LA57)
> > got patched. It includes KASAN code, where KASAN_SHADOW_START depends on
> > __VIRTUAL_MASK_SHIFT, which is defined with the cpu_feature_enabled().
> 
> So use boot_cpu_has(X86_FEATURE_LA57).
> 
> > It seems that KASAN gets confused when apply_alternatives() patches the
> 
> It seems?
> 
> > KASAN_SHADOW_START users. A test patch that makes KASAN_SHADOW_START
> > static, by replacing __VIRTUAL_MASK_SHIFT with 56, fixes the issue.
> > 
> > During text_poke_early() in apply_alternatives(), KASAN should be
> > disabled. KASAN is already disabled in non-_early() text_poke().
> > 
> > It is unclear why the issue was not reported earlier. Bisecting does not
> > help. Older kernels trigger the issue less frequently, but it still
> > occurs. In the absence of any other clear offenders, the initial dynamic
> > 5-level paging support is to blame.
> 
> This whole thing sounds like it is still not really clear what is
> actually happening...

somewhere along the line __asan_loadN() gets tripped, this then ends up
in kasan_check_range() -> check_region_inline() -> addr_has_metadata().

This latter has: kasan_shadow_to_mem() which is compared against
KASAN_SHADOW_START, which includes, as Kirill says __VIRTUAL_MASK_SHIFT.

Now, obviously you really don't want boot_cpu_has() in
__VIRTUAL_MASK_SHIFT, that would be really bad (Linus recently
complained about how horrible the code-gen is around this already, must
not make it far worse).


Anyway, being half-way through patching X86_FEATURE_LA57 thing *are*
inconsistent and I really can't blame things for going sideways.

That said, I don't particularly like the patch, I think it should, at
the veyr least, cover all of apply_alternatives, not just
text_poke_early().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010101056.GF377%40noisy.programming.kicks-ass.net.
