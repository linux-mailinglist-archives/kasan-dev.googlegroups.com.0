Return-Path: <kasan-dev+bncBDBK55H2UQKRB7GISSUQMGQEMA6USJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id E085A7BF84F
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 12:16:30 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2c135cf124csf46424391fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 03:16:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696932990; cv=pass;
        d=google.com; s=arc-20160816;
        b=PdADBDwwyQjV9rhdAoA4vD5UBi4lvB5GUaT4p8W/0ofFnfxJ4Hju2hr0dwjDfB2bqj
         srag7IBXHXpMHNSMPJOycvSW8HAU13vuygn8e0uLOdA88jDKTxTHKE/RIR4bNNhSkO2t
         rT6eOfye58XtgW8kYyLna8s258zmpXkpitmsimdwNbLaqKld7bujITSDvPaijhYtJdL2
         RLW8crYTsXxYS+FU/q/wcVfXu0tuUjaN1zW/UP3w0rr+kNSLJl/gabZyMhQFnmbmNz+N
         YlXD369JzbrNuGSyDUv5zdeswUjiQeZIZVu61oOA+XlKHRCUelEb0+u+FVg28/XfpkfM
         hLpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VMQn5Jcs3MKzXgBkqCNrWdZla7nflOX7X8fF4Nnp8ow=;
        fh=mUf2ndWDL5c84ldV6DszTy3j42/aMLRyYOLwUcEDGhM=;
        b=06SgCgDpQHA9P8B97Smbz86DKZ3dug4TorvmVAOFZZ3QvNepLEX8NHAhBwiXV+JjnE
         n0KKQ0zVKFuvB6ROU3kuxei0czSTbT3+tjfpNoT02BtQZNfjHB4GePZBDNVj4w8I5MG+
         mFyPmeqAvbiV1JwXaSKsU38KdKY9lfIr3SxJAfrKYvJLCAbla0YVIFjRVEZNwGJQSzry
         KQE3mtYglwHpAwryPgKmFl225we/i4RyZzI83bGRw6lprQHDfLhNGQ6vpwXJI8npOzfx
         aHUjEyceySczPHpofvwJoDlBmWdd325Ouuaz5vPkQ67l578nqwy+3S2+tMWURTc29Gf1
         x/3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ueKzQLcn;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696932990; x=1697537790; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VMQn5Jcs3MKzXgBkqCNrWdZla7nflOX7X8fF4Nnp8ow=;
        b=TJDcgON7diIcgSKoZ4vd6ONpKre7O6vWI5ArCCcwGrpJ71Ho/W23DzuiJnuuWhZOXh
         sB3p//njmHtufkunh6jZOKOyRYJZhb4V4xY0ItNvae3nq09SyHV/cN3vBEJstkt5hybG
         4XFCQnoaD14x1xgxwo+aMVPPWnrJaJb77pVrs/ty/tkrFpoYiJgEEOlBoNQAf1wQOQf6
         5zVsIGxaE/A9lBH1FqVqpPGnMBQ8HgWTjWvOOEEFMWfvOtTrhcQpiMm53a0JytSkKv++
         sNJs+MQs0QoPpJ6Kh0XJXgXo5PZ718ESDfe6Lg+g7JlyJWzrChWDV0yY+y39pG6V5ZPW
         RLtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696932990; x=1697537790;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VMQn5Jcs3MKzXgBkqCNrWdZla7nflOX7X8fF4Nnp8ow=;
        b=XswH0alVD+6NAxNnXRVZCwHDejbo/yEPbO/SoGHimJK81H+EEMvFnOllBy8YedeCKB
         lH93jXFZOGvdvk/lTPcRvWcP5nTXJm2Fl/2Pl1OQMOkxwrC0gakwT66tKZouOo73qFXF
         Dj2klLkTDl2Q8Ysa5Vn3ztlBUq0HTZpp+7qAnbrb0yuQktXK/rsRFemXA2/6UcCf/wxl
         wfXgQkWsTYryewUcuYniqfNN/27FjwhpGIuOdyK3GKg7HzlQZOLjHqNwjaoqghtt3yFt
         wPMbGWPyCryhChBEoD+FtAN2gdEGrreP9BbPHHskZY/ZhDtOBrzld1NkDsUIMstpoGTm
         kgHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzwJ41iBSFrdeoD7L+Zi6xO3fszr8JiiGT1gCz5S4U8ROdIqYah
	LjskO06WB1QOBdxqSKorrgw=
X-Google-Smtp-Source: AGHT+IGy0Hhv5OfZC/xnFXYvB7hodFeqUEllJfd6uL8m5m6/uI20CJCO1ETfF0gC1tN4TdxlE8jr+w==
X-Received: by 2002:a2e:a212:0:b0:2c2:9810:3677 with SMTP id h18-20020a2ea212000000b002c298103677mr15056049ljm.6.1696932989126;
        Tue, 10 Oct 2023 03:16:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc24:0:b0:2be:574a:3b1b with SMTP id b36-20020a2ebc24000000b002be574a3b1bls2064877ljf.0.-pod-prod-05-eu;
 Tue, 10 Oct 2023 03:16:27 -0700 (PDT)
X-Received: by 2002:a2e:94cb:0:b0:2bd:1cd0:6041 with SMTP id r11-20020a2e94cb000000b002bd1cd06041mr13508747ljh.0.1696932987038;
        Tue, 10 Oct 2023 03:16:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696932987; cv=none;
        d=google.com; s=arc-20160816;
        b=bUP/Vlyuv7rE4K4UlThBE/Mrh51kkvA3AfBCaAJ5qkqzO8v/klCW8JLDUibBaJ60H/
         WGv7tbdcYFVTw9k4kRQ0KS5GV9d8bIAUEXkrjn+6nbhxi/VuUAcx1mXvzEFpEsfzu5no
         E/Z7k2uwThAFZ08Bxj28G431oNaAM4ys2PExpVjrOVDoil0IFgEDDn/jmyhrnESecpEe
         3IOfdqfL4tqt2/GcF/Z+/wmtxeFhVnV+TdeHVz+bATAIcqonwtWXCjs4/t6EPWyEhgT+
         65VQgKkmZJhtepn0pHJszobAPY8ZYLVrZcHj4vLYcvfhWA/pN9Q1IisbHnSLgrpTdy8j
         +aCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Zb6A2kfpJa7lPS8yNIr1mX5OvpeUAPwA3IcDR1IaKKc=;
        fh=mUf2ndWDL5c84ldV6DszTy3j42/aMLRyYOLwUcEDGhM=;
        b=eCezPrNH/bgy+M4mNg3mMtGk0zwyQivPdrlBRWxykyo8ll4PMKYcpJvcOYATb7Uoek
         GVPu0dcRE1zW/QnRnROAlSreXrRrRu7MxhLKMlDyldvgyqeRU59RFssE0D4JGIhF72sR
         1z3m38u3XBc68hwE63bcEuHHsjNf9fDnyBca4cFTsrnQtHXDX8JYGoNsa/KcfgV7+R5D
         gdjq+dlkrOOMjvyCFyLwToUBm0IjqyLAvHg09E3yZHRKGckogqs2YS83eE3OeehzSVTB
         A3auK9bTBRKdSd+dZsMaGq/VDMGcyBFgt75hHk4hDmYDWfDcQ8qPqh91C8nWnvaPKKeU
         WsnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=ueKzQLcn;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id j2-20020a05600c1c0200b004051c2a3263si619947wms.0.2023.10.10.03.16.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Oct 2023 03:16:27 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1qq9mn-00417M-OM; Tue, 10 Oct 2023 10:16:21 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 68AF6300392; Tue, 10 Oct 2023 12:16:21 +0200 (CEST)
Date: Tue, 10 Oct 2023 12:16:21 +0200
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
Message-ID: <20231010101621.GG377@noisy.programming.kicks-ass.net>
References: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
 <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
 <20231010101056.GF377@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231010101056.GF377@noisy.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=ueKzQLcn;
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

On Tue, Oct 10, 2023 at 12:10:56PM +0200, Peter Zijlstra wrote:

> That said, I don't particularly like the patch, I think it should, at
> the veyr least, cover all of apply_alternatives, not just
> text_poke_early().

kasan_arch_is_ready() is another option, x86 doesn't currently define
that, but that would allow us to shut kasan down harder around patching.
Not sure if it's worth the trouble though.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010101621.GG377%40noisy.programming.kicks-ass.net.
