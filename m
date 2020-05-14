Return-Path: <kasan-dev+bncBCV5TUXXRUIBBG446X2QKGQEMWQ3LII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 15F131D31ED
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 15:56:44 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id h8sf911518uan.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 06:56:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589464603; cv=pass;
        d=google.com; s=arc-20160816;
        b=vcXKI5woiBnmu4/5GSxnlWtRImv5/9uYFswpnIzYGse6jcXmBfkYia6N2fNNYaXbRy
         hNpSaHlAhFCQk/DIcN28arFVMB9gGwBlGsKWj8qZ4ndLhxma1b5TSYptM8xQqMCsdFnU
         JdD+DH189804N8Sm4YSXhgDr3hSXthwV45huWhvJeFWPPG5w9Co412wsHwHLfYRnsXwa
         FR8hbfymksbFCXOaI9ijsJoJGKY80RMZKcXOWWtwNdGnljhHiRs/wdvcEnA2QajMyUFB
         AiYSLnK6JzpcMqbJY8V1863rg0g+JZ7LFt8BNfBy3/Fn3/J13nf8VwKIgK41W2is7zH9
         t0qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=WbnxrG+g4YEba6zoz13PcLNxeYtxOVr4TZVVmAqNIFs=;
        b=OilIEqQVA8qePhB46G/VJxe4oZnbSAmWFhsnSg8547U+fqF8cD6SIomAj33s1I2fep
         TVnmlI+20JxpEhTF9IcKKhXr5hEvmkdqYRBmfG0ME1KeFFrr4Smm7MJo5jCeAOGklcis
         cyXms8O1haehWQJ97NZYIR2CKI4xC02eLE+fIEN9ZHLdD21HQWjwls+rc8VhLR26qTyN
         oWTB5l3iX7yU9wrwPeFfHeSVLa+qf/krGN9pq840OTYxhOGlDdUtfb4TGs+Sm0ui7cRK
         p51tr2Nrrh1pWF+9SrQAYs3dcf/7sN5sXGK65ynmQ+FEp/yejwbsCeOfSTAEHBK2uv6a
         CONQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=ukgueQqJ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WbnxrG+g4YEba6zoz13PcLNxeYtxOVr4TZVVmAqNIFs=;
        b=MhHVq6tTZY5jeK4L10wmMI7qMGlMir92fdXjvPlOZABHc7h5l9pzUW5i8czbI44+rT
         3u/wyvwsMHlt33TL3zhasRKcc2PLL5GBuMQeqQQD/AlF/ZNZae6JbhhZ6RRO+5wbGTpw
         y1l4fgLn36rGkLe4/nhdv736YSWLMXsTmO0viStDD+ev6TX3QEy61Q/H7OgFbU7jtIL0
         9OxBR+p4FmNT16K9H3MThgEmaySAogaK0NLvazq6+D9MoSbB7B5J8u6f7jWQW/6as3nJ
         yeNwi/9XLX8P1UTTVaPPMDO4t0gPFSkppeOJGYySARHlYYQKA9OvcJDzcEPeu4wrnU9D
         dhfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WbnxrG+g4YEba6zoz13PcLNxeYtxOVr4TZVVmAqNIFs=;
        b=jd76OsJoVZFAFcDkqmNIPGpigDYxtE1u9EtxpJg4h0XSZBR2HOlMEfvjt2SpUD+nBU
         U180BOY0Cm4tn1fC8Po16FGvGt1m7VMXnL1kZTYhYZOtphAUY/dW3kJIDTcem8wEVm6T
         L73pC3cGnqoqiyOunXYpSrcFG5xClorFOgsqx74KY8QWkvCcvgO3d1HiArn6ON08eLaX
         2BFtcAYkqqALgd1CzvnHfOiAP6XrYFoUZOM4Q/Jppey7EZUtGNaJ6Bw8ah3kjMrm+wG6
         Xt56vgvW7TFboRlaQ6QzhkXlF+ps4zoZTddQUczhgSYeCrsLC9wDXvSbZsQwuPYJCCbI
         5WNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DY5Lg037JmSZ8Mu8X5cuLQIS5oPRGg5bjdrUXYw8NQKDMYf/1
	pzolaVBNUI0VtXv/a093ndQ=
X-Google-Smtp-Source: ABdhPJytLG30dQ2Vl0KAdHAfeWB2m6GkXQbNRFmdQNlJ8mj2iCB6jF4OR4WpMNsA1/2zHDEWg2wX5w==
X-Received: by 2002:a9f:3e0d:: with SMTP id o13mr4117195uai.25.1589464603159;
        Thu, 14 May 2020 06:56:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:1d47:: with SMTP id d68ls260054vsd.7.gmail; Thu, 14 May
 2020 06:56:42 -0700 (PDT)
X-Received: by 2002:a67:2cd0:: with SMTP id s199mr3578498vss.10.1589464602818;
        Thu, 14 May 2020 06:56:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589464602; cv=none;
        d=google.com; s=arc-20160816;
        b=kSkt8GcW4Yd7XTM67jBPCdleLzA1O4e5n6HW1f2D1zXRcLRPMcTC18S58CFMNErS5W
         EUa+FcfEHDuxhftOstzq0/EhNFOctp2n/wVj81tv/y7RffsKUExLgkyGc5HdM5mIAZQV
         YZ7ougJrGiC95kf56F9jDYyy1yyGnGv2pV9rIaYjqPueT+TACBQJdYlRAMh6DeiL9v4v
         x95+dieTX3Cf74aePDOTKlGC3pDoqqTpBzWRJMLqf6guf/p+BcsvoStThJ5VukFZ3zQk
         rI0upgRGDv29KIj8ePpncF1hXCW2IJa6HEwbJxVZkL2qQWVodtKCK+1Ar52CLTjfr0OM
         mMVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yuNZv20GvjcB3xZG0jnCz4zo0tfhmHdfTS3Cc7Ab6N8=;
        b=L5ssGGgj6ya9Nm8xTRlQW1C1+t1VYzrQTJ9mlYsxhGI1lGSrt9pk/TdlsBsTfm89bK
         lD0mO5CpsNmG4BOAUDlPTVzgox97Xy3BkTzDu1IQ/yPDLzJPuVUhKFJDlAAtqXtGW+lf
         3Ihdet+V0ksYSneyjhL+mVBtxs2P6p3OclCLjEqKZMHw55FXNc4R9IHKnW1spxRcGLia
         PbFbxswGOoYxawzsBpW6XOXdJwDpodBBm4HRxtU5y/ZgU58jPSZvj/HMjxfWMU3VOQaE
         d8TxxyNiMqkj16DJQAV7Dix67cUHBnuD1D2IvlV0FIHqZZP+PZnmGZUqJLWmsdGqoyLt
         CtfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=ukgueQqJ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id u20si134150uan.1.2020.05.14.06.56.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 May 2020 06:56:42 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jZELp-0004gL-EQ; Thu, 14 May 2020 13:56:41 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id BC2F3302753;
	Thu, 14 May 2020 15:56:39 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id A79DF2B852D67; Thu, 14 May 2020 15:56:39 +0200 (CEST)
Date: Thu, 14 May 2020 15:56:39 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
Message-ID: <20200514135639.GA2978@hirez.programming.kicks-ass.net>
References: <20200513124021.GB20278@willie-the-truck>
 <CANpmjNM5XW+ufJ6Mw2Tn7aShRCZaUPGcH=u=4Sk5kqLKyf3v5A@mail.gmail.com>
 <20200513165008.GA24836@willie-the-truck>
 <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com>
 <20200513174747.GB24836@willie-the-truck>
 <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com>
 <20200513212520.GC28594@willie-the-truck>
 <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com>
 <20200514110537.GC4280@willie-the-truck>
 <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=ukgueQqJ;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, May 14, 2020 at 03:35:58PM +0200, Marco Elver wrote:

>   5. we should not break atomic_{read,set} for KCSAN. [Because of #1,
> we'd need to add data_race() around the arch-calls in
> atomic_{read,set}; or rely on Clang 11's -tsan-distinguish-volatile
> support (GCC 11 might get this as well).]

Putting the data_race() in atomic_{read,set} would 'break' any sanitized
user of arch_atomic_{read,set}(). Now it so happens there aren't any
such just now, but we need to be aware of that.

I'm thinking the volatile thing is the nicest solution, but yes, that'll
make us depend on 11 everything.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200514135639.GA2978%40hirez.programming.kicks-ass.net.
