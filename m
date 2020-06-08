Return-Path: <kasan-dev+bncBCV5TUXXRUIBBAVV7D3AKGQEKPZPH5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A21AB1F1724
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jun 2020 13:01:23 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id l20sf11201722ilk.22
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jun 2020 04:01:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591614082; cv=pass;
        d=google.com; s=arc-20160816;
        b=dWOZTRUry1HaJBwYG/EGr/y2wPA2HMys5GlLfKugXH1WSv2Ak8VY6p3erjCmOpHXuK
         ITm2Gva/20ej/iy1EDY/BYXmew8+KNqnw9Ko0BjrQcSXPiVzXfYtUA6YZbrKwB1sQcz9
         zu43+U3OFKCw4Ds4hMwH/66FUl11pHnC6ABtY7aJRhaydZZNxQIUOs5R6ZF48cZSmagM
         NRc5zuJvMDyBXXXw6z8BQC3egr3rvgMjuR93+g7vVQ128bI0izQStPVkzVQcg19i2bOU
         hmVCQBnli8TBhWvy2f1UbleY2B0+l3RxmQAKbqMlubdqfPb9da6WrKcur2Du5GtAAsKU
         Kc9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cLsCL0b4ocC9ZFINEhvrCTzLK/uWkmm1L9AR3bGuuhs=;
        b=uww6dCcCmMZzF0CXzi0USl1NVZh3sCLKpXLBId+F8j2Z49ql9AjFxk87dEZHInFgQc
         mO2dGx06o6n1KZAIw2mLGb8Yo+wYI2B9IYttKYhClKXfhdC+Ieyg0sH83pdQNKRvSBoD
         AcyxRYGqznH7+r6ok6dGWJDeM7eIDUTlzA4NWvDTF8JpwHT38DfKYuGoBAdlYcIGXW1k
         /ldQ5tSNfMVdGC2+skofnwq/HI/4Px0Bssvv3tVPUFNyf9xmuGhq8olCSTlNe7MR63r3
         pEN1U4Us67P7KzfWC/Yi+4JMOK7qY9/fK1Tjwty9FIgVFYhf2e0UqqxR5EgBSBP4gNiU
         VOGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=NV5cY9XI;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cLsCL0b4ocC9ZFINEhvrCTzLK/uWkmm1L9AR3bGuuhs=;
        b=eimZMc5Edj63iI8wNIzDcE3URRvR7spQrX3l+vdefb0pgEkugj/s2+MNebdLaieBMR
         PCBTOKWbR5rCxySuOgEku5y5FcQIBOE3tGe7VaH1FVvNv37GwDVwikW26z2oKHo4wKEP
         q6ruU5JCfoICLa1a6nWIe5UVMK6Ia0pVYk8rmDZJiTjTlI0HELxdNoYeO498pPhsZ49M
         9sEqa0xtfJ0PTR1OiMpuhzegZzVBb8CGKJFLoUUZ5TyGt4qBTIIow/ScC3AdNbRscnzR
         tc/dk97j828is8h9bcRyi9JAKNiGTFDgcWwSPWD3W53mE8yDSrCQdJbNJf5IBL9E5ekv
         EBqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cLsCL0b4ocC9ZFINEhvrCTzLK/uWkmm1L9AR3bGuuhs=;
        b=NxxI6I9eDpUvOb+amJsinaptpkVmGSEtwntLrRZo+fKpmkmbrwl69tZENS9BWDW9uY
         YHPfVDeV2+IXJFTGJsBDDgGXcEg4HU7UJGpczkbWxCwNmL3Ajt9xxvGWeTThoBtYp7YE
         aA4onXlJqVdGHB2b7vcmeJvwYXdL5GWxiOJkr50fa4xOFOO6MbmE7goyY/zd167tN4bk
         bRr3tDMTloepcQEUo7fnvejPe9WmJlY3u54v7hh/7eDC4wEnumEbGVviQP1s5aQB7RSf
         AZjnaXHssJsCHfex51GuVg5CSHJGdlfdmhSxdgNnH+7cME1u0CLFzKa+MnsYbMoNwJWr
         TjuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gizad9Pn5p657zO/sooEQzdJoXSRjZAIHFEoWpfJzo96pM9ME
	K0FasBvsXFryYbTFiDJoPK0=
X-Google-Smtp-Source: ABdhPJzmQCeEro1Gs+2hbyI3GFrnOcw067JVnDHy8ec0jxjpY6Nv1ViqnYoPaiEbpSR3xYRAVtqFqw==
X-Received: by 2002:a05:6e02:ef2:: with SMTP id j18mr6410877ilk.69.1591614082639;
        Mon, 08 Jun 2020 04:01:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c205:: with SMTP id j5ls4290400ilo.11.gmail; Mon, 08 Jun
 2020 04:01:22 -0700 (PDT)
X-Received: by 2002:a92:c650:: with SMTP id 16mr20543726ill.157.1591614082298;
        Mon, 08 Jun 2020 04:01:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591614082; cv=none;
        d=google.com; s=arc-20160816;
        b=BrTOcI7oxe2+yyndXR5+dVtw9ZunuAf7X4Cj5LfItWx0OrEb1kGWcS4Q5mhdle+4Vb
         RU2AftPLzLv5dVTbes8rUSerzClXuwjDxwAYBTe3IXszTFHRPyc6zmwH7kPfAxH3Ea3r
         Qz71fjFBlmAwdhc2ZFFmqUnu5UA+mmRP33eZ4K0Yq2InZ/n5WUZS7JycBrlSJiR7xYPn
         an3qtZUl+o/9lxwgBN1zB4EzV15sjyP9r6irx6n2iKOSaTZaA8B5xnvXQpJut01NRRpg
         PFSxBfsxSvXGjP9+nc5hX24RjVVbgobFRnoQVB3vbNxutMvE2mesklCUlNTH+6fVgDIf
         GdwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=K/s5mZYe0D3JGCoeAasezBJ22Tds6PXDtFml58Tk67I=;
        b=d7CEImbLzcS2LbuRw8u9hZQO+mXcS1p5L6FW6D38jLhw95mf0fDhj6yxW2XSyhtMp8
         JHXJ3bMnCzJb8GK3gc/CZAbRyjjuveNEX6h7IXVRG333HgGXvlT9rwwEYflxDeEPVhOf
         1M58mAN8meIjlmQTvCvLyKXACRaAtNhzhwJmUOGu2LdJr9XV2+SgI6xHqOIjzD9K1Ksr
         shbRNfYuMl5hT1wswRhU2oD7HhBo4CPyi4MaGznIXyhYaBIpgymfDDbu2A1WEy0X+f8E
         xX3uFgbSHgacMNNw5yOthiWKK0uorXvvX2maJh4iEv5D8NbROh/d98BMVqGmLT3+/Cno
         YnlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=NV5cY9XI;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id z11si704420ilq.5.2020.06.08.04.01.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Jun 2020 04:01:22 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jiFWh-0002iJ-Of; Mon, 08 Jun 2020 11:01:13 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 13313301A7A;
	Mon,  8 Jun 2020 13:01:08 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id DB50A21A7523D; Mon,  8 Jun 2020 13:01:08 +0200 (CEST)
Date: Mon, 8 Jun 2020 13:01:08 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200608110108.GB2497@hirez.programming.kicks-ass.net>
References: <20200605082839.226418-1-elver@google.com>
 <CACT4Y+ZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0+pjgYDsx+A@mail.gmail.com>
 <20200605120352.GJ3976@hirez.programming.kicks-ass.net>
 <CAAeHK+zErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ@mail.gmail.com>
 <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com>
 <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
 <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=NV5cY9XI;
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

On Mon, Jun 08, 2020 at 09:57:39AM +0200, Dmitry Vyukov wrote:

> As a crazy idea: is it possible to employ objtool (linker script?) to
> rewrite all coverage calls to nops in the noinstr section? Or relocate
> to nop function?
> What we are trying to do is very static, it _should_ have been done
> during build. We don't have means in existing _compilers_ to do this,
> but maybe we could do it elsewhere during build?...

Let me try and figure out how to make objtool actually rewrite code.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200608110108.GB2497%40hirez.programming.kicks-ass.net.
