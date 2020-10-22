Return-Path: <kasan-dev+bncBCV5TUXXRUIBBPXLYT6AKGQEJU2J6EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 59B27295940
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 09:33:19 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id z8sf315043ejw.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 00:33:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603351999; cv=pass;
        d=google.com; s=arc-20160816;
        b=a+2XtXXfDjkx3SFIo5hBf1XdpnoT/O2LLKViZCz5IocixvlaxEtzwuwjRFwYEbvz66
         ChwiNhtxQLU0LZfwgPLZVtc3byqRFYidBHrQsUgFd2uQoyUhPYV+jldLVe+FSQLmgPeM
         WDogFX7GsITZ3TSK9jQKetKgv2S4/2GWYEajLq75difcfKG+mUGKfbuiYHi5wV/DhOlK
         NNJ2QQSjXNw1wbj22FT8JnaTQVI9ALSWR2ZtFwQjQnThc0NzFDDFXA/dkWeNXU4LVGhH
         qmSCrpjLRArbyHSVjfO3/b6oK2rjAhYUH83WI5KPzF8ksL7BvmaEEzqqV6hR7fhActj8
         DQyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gFOzFnb+upaqp5ajxOuuLtBhgIe7SMqSFjciV/bAdPk=;
        b=GJV73l8BUvR8BIIOX2Ct6fnTzHBgJi9nZ8fi/P4ND+X5qzIoso3HwFYWzVI+EhP2aZ
         d6axKpfXSnIhgX8iDOkqyoHS3oaajzlaNZUZ9qyfNMAYFTwI0x3Jmdn0bFjxvKGbIgSJ
         3iOt3hyaQof4RCph6P4OiWhGIxspOUEf2q+rWh3jr1yQzwnyoEmnvbyfm3rLamb9ckZg
         EoNfBUNX64GzfQClpTWulZQ7OmDnRnb+q9RV/YSI2j221Bjt6daGHuTsz1F29oJIR4mC
         fJJ6Jl62Dm98i4RBWBcfy7u9pi2EVv7IMoskGBe194Qdzcmq/5NuQGOloH+xDTh/BtQg
         EcUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=lMsJhYJG;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gFOzFnb+upaqp5ajxOuuLtBhgIe7SMqSFjciV/bAdPk=;
        b=EtsLBKd5BvoF+n3lb5L50N0Y+wRCeb34/aYsFlE3E2oZZpp+94JVSyQ7kc3XAK7lF7
         co3CBs4hQYkLgW0uNTwcYiJGNtir+fXQUmUn/mSKMbUgcH7HxYTlcBhbnsUabRsqx8OT
         JjKTc/Wx7zz1Vh0qdyxG5K1xoWzqnhz6c1hUFDjn0EpRTf8ySkHDVqxK2cLeZIzov3jf
         QXctpQ8CtmpC5B61kZ6UKHDFoZiaXfdSrdCQGPNnImiBmhp+9fg0s5Q5aJFrcK1C/3nU
         kG6ii8+py2IyCC5xKwYJzZSTi6LytLnGQNpF2oTLRDml818UJ8UUcc5019FnWpqB/mal
         PsrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gFOzFnb+upaqp5ajxOuuLtBhgIe7SMqSFjciV/bAdPk=;
        b=NcJuUILl+EG78yWztqkZQq0uTh05ES8Qo7F3RNzLjzJcGRCzTYAKzXcnYBHaxzM3+w
         HRn0FV0bfPY0RFB20oCeHMAyhmFgJ/bzVtaxaE4dGAIOyIfC77A9wJ434M/1+u43uKaS
         6SNHIVX4TPKwMyPU6Uww9QWtDmzLFodytVQEYWq11H9FFOMvXg9R8oryMGniZ15DDg7S
         Ei29KASFOq4YKXLDRoNqJ/XzQzyz+A5Wf3m+CNIvQK00vRRsNt0LBs0oFjXWmNxOPqI/
         rqm+u/1wXF29VedyWOwRp9t2b0BkzfxmtIMXJoRqmtheJtncNmH48ToEP5HAV9qBfjSR
         Ic/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zEoibTNi97WPH5cVHH85Zj+EKtZSRuAMqZM/6hL/SKhqWVKFE
	aVow/Lk/wI+L5IVAIrZm5iM=
X-Google-Smtp-Source: ABdhPJx8FJILzFbbMh3Fo+PQRad5VyiFUjWNAMRp3dc4/T42ijRgnDBuji81d9ZuACNeNvOdvm8Maw==
X-Received: by 2002:a05:6402:1e6:: with SMTP id i6mr1087075edy.152.1603351999084;
        Thu, 22 Oct 2020 00:33:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cc8b:: with SMTP id p11ls997630edt.3.gmail; Thu, 22 Oct
 2020 00:33:18 -0700 (PDT)
X-Received: by 2002:a50:d642:: with SMTP id c2mr1083209edj.342.1603351998224;
        Thu, 22 Oct 2020 00:33:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603351998; cv=none;
        d=google.com; s=arc-20160816;
        b=O5eaNC/xN2PenbFQ12duTs5vluSmeeT/0ba6kcNF1WZBWRZDHAm7fTtZMNkjAXvNBk
         YKs8QxSlH9EgI20iGJZtelpIHqcPVFrVOrDNG2dF1manVZLHAvUpLe0jbJ5Bmw1wkZhg
         nOqC8Is+i/Ou8Y5Xv9gFY+/ns48ShbvnqWNl1S7qZd+GbZkqSAvH2ST/rWq/d93Rddri
         xQnC5ZpdqeDJOorverZYeFkEQ30yhTcefUx3tFPQ8JWm1+o94pUu7a+atTk90qy6bTG5
         is8r4hgfo47gpnD4OXhgpWGmhCJH0EFQQKrzmSO7gU84gRT0EOK/BnLNtEd9rJDsMH3a
         T5FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JbI0bflC8HQp7NYmkplX8khPFM4YNdFK0FBEU2KovRA=;
        b=Cu+TsxDvy7r6QKe6jerDBTMLHSGcP0fBU52wRfQ8CKoL1WgvrG2y8yF0oMKW6SYJd2
         KXWXM5KfXY43mxMAfoD8Jk07dTuGvUSfbv++Sc8P60eHxBzjwvLkyVJV89EjXaBBnJs0
         vjE2Kl+OdBJfErD2NkFLK+O/Hmhk/C1eN8S39YYMP/y5bfgNTOxwqktyu0zKnHRsHFzm
         4JjhgySW9SDXRHySTTgYEKNC5w4YC/O7eIKSINbT7orBvFfamg1QDDzGwnkE6Syu42+L
         J71lp8gkhBKCsXebkWxL+6etvSid6JFFOZNc8MUEtxdCkBwwIorC8uoSqeg+zo/G7c+M
         C/eA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=lMsJhYJG;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id u2si28935edp.5.2020.10.22.00.33.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Oct 2020 00:33:18 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kVV5w-00028b-Mt; Thu, 22 Oct 2020 07:33:08 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id A8B873011C6;
	Thu, 22 Oct 2020 09:33:07 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 94AE72BB9BA76; Thu, 22 Oct 2020 09:33:07 +0200 (CEST)
Date: Thu, 22 Oct 2020 09:33:07 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Joe Perches <joe@perches.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	"David S. Miller" <davem@davemloft.net>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	linux-kernel@vger.kernel.org, linux-efi@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-mm <linux-mm@kvack.org>
Subject: Re: [PATCH -next] treewide: Remove stringification from __alias
 macro definition
Message-ID: <20201022073307.GP2628@hirez.programming.kicks-ass.net>
References: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=lMsJhYJG;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Oct 21, 2020 at 11:58:25AM -0700, Joe Perches wrote:
> Like the __section macro, the __alias macro uses
> macro # stringification to create quotes around
> the section name used in the __attribute__.
> 
> Remove the stringification and add quotes or a
> stringification to the uses instead.

There's a complete lack of rationale for this change.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201022073307.GP2628%40hirez.programming.kicks-ass.net.
