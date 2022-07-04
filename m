Return-Path: <kasan-dev+bncBCS5D2F7IUIL5EMNSYDBUBE7SYBLK@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B42E5565E3C
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 22:08:31 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e4-20020a92de44000000b002dab11299d9sf4617636ilr.9
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 13:08:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656965310; cv=pass;
        d=google.com; s=arc-20160816;
        b=kOP7bPOcUo4E7OI4rW6G0SedMneF8YfG/RYxbm5uD5pNzq15h3cBfOXQHHdeS7+zvQ
         rg/JTsenGBJuprhWRzebt5tV1zwKaExY0zQ7isBthf5ysDSL5LXOBe30GCLnO4PFG7Hf
         JxxYs1P9G3O/2TakBtinavdm3GgalGpKWaPfui3LFk73xxLuiUeYG2Fte8DL6JDOLYw/
         sFvT33Kkb7BneMFjFAgYCxAHZiwZBfzkh+s3kEJRJvxpJShCY0/BglhJl1TX6SP5coee
         p6T7pFfwWeqPcA+DDk2TNKvF0lTz8DoJ/WQ8r7UYfJOUOQ31t8E6k5i46diKgbvuIEUN
         g51w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yuqOgFMd0zrhINrqsh2Pt2sp6y8NFEbOU4tyaP2LyPI=;
        b=yRkE9hPYCP9O+hgtx3xkg9fffv5k6VIFJklsbVMEsqXGs+xluUVmFrKx/vinWHhTHm
         /qYfZBbN6s4oToMF/EC0OeAPLdWddZut6m93uq72yRx3b2LdzdIElRF4cNyYpkNk405p
         xDbKz7BVy64LJ1XaOGwGCbFXX3hMNyjY0ND+7zAncM3os8tgSI8FGHJszECi2rDlb4u4
         YLo2JTsXCJRxEbIy7d/nfFAbLLhCPxMnkhmgai0brFmqTxG5iGHa8ACjwv/cyrY88Jbn
         h4KVoytAn8tPF9DZuLU3csWKjneaSJertV8i0XKMCMU5PuTl15uyfaXrFDFyiBiKKU9F
         YNKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=KPzqGIDn;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yuqOgFMd0zrhINrqsh2Pt2sp6y8NFEbOU4tyaP2LyPI=;
        b=RHUtDYckI1ZoPQPuPsu2XV8s94F04Cup/6+TK8Rg5xFmmeYKD9dCMXWCOZaiNzLQhH
         0ae/VhZ1w1fEB21EcLG08Eab0DcsbwWwkKam6u2zl+3k59b4GGAmp0E/Ob+97YJssh6/
         bcFrGkwYe3tQodYojuaSuiRbcFt2719imX/1+PIUVgMu2bD8gsljXK0pLySuX/l0c8O6
         ibEVBTboI3sjnn6MLZHPE8HteATJgirJSb1SRswKc9y9ZoegAUtMqSxd7WNyHhwg+zcO
         nmQ8iDKVunEcp2gnv11zxOfxcMOVujlXVPDeaJ74tVOcmm//NJywWvGvu93WBLrKyKIr
         9zkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yuqOgFMd0zrhINrqsh2Pt2sp6y8NFEbOU4tyaP2LyPI=;
        b=YGqMXdgVvxvjyyRX9QRPftsVI4anRM239JBM5xmr1eP5S0FJP/C/LZ7Y3GqAYbMDQz
         MnEtZwHygs2930ZRe7SFW4KpPJIEVPdCT/da8uUzpzDmNjmnznic0n6cvLji2Mf2hTdU
         CWWvHUgRGXPYW/qUtlno45KGg4iAgi/r0UlRYPHdcyTHbIKUgl9d1zjcLFpbVRK47vQJ
         1N7zjicSnbSUqmoDgmAaiAGAQigqHg9aWStOGdcHvhpiAjB66BeuKK8ubItLwRw+Eqcb
         ETGut+2EHXwpTGUMCtQEb85hq9rwX1dgJOYsqzMglznjMdP6/7wBgcOxcDrOgehnpL17
         OYpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora87C27GV0eep8vh1JhqaYBcXtgIq91RmOHD+lCqpffeAEbQdo03
	DZ5nLyH7AMHxYxx02QkSHDY=
X-Google-Smtp-Source: AGRyM1tn4svZuoTbg8DdzXUs/tI5tVWhJTHfUFT24VmLbvN4DuLsRTs7jmfA0lpxTDCDXRerUKsa9A==
X-Received: by 2002:a05:6e02:1aad:b0:2da:d2a7:f with SMTP id l13-20020a056e021aad00b002dad2a7000fmr15933621ilv.45.1656965310348;
        Mon, 04 Jul 2022 13:08:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:d94:b0:2dc:14b7:c282 with SMTP id
 i20-20020a056e020d9400b002dc14b7c282ls338922ilj.10.gmail; Mon, 04 Jul 2022
 13:08:29 -0700 (PDT)
X-Received: by 2002:a05:6e02:17ca:b0:2d9:6e29:4975 with SMTP id z10-20020a056e0217ca00b002d96e294975mr18500050ilu.202.1656965309843;
        Mon, 04 Jul 2022 13:08:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656965309; cv=none;
        d=google.com; s=arc-20160816;
        b=J8d/ealmtVpdDbfT4AK3BmfPUfeTzgSDzmaa/30y+LLN5OgeIWV6cuyOUb0Qnx3nkA
         tYauB3ec/JCJLRpt3AEjN6cl+VQimTsBUjqa9BMRJL4I/3zNSL3jCMUXR88YRH/uukGJ
         d+3GFhSnVXRd5Vql6NafaFNIZpK1NslrDNIhf4ySDfc2pg78MGNsjW2pZEBKykHWohz7
         W7Mbwe9YLU2RkcJgIMno45d0jWPZYY2JGv3xs4UfSqgtWVJSJadF1qhyJkGkmwUO4H4X
         MGqhD09zd4VVgWVFx/crfDZgJ6Yn4SjztC2txuDnubeQBgNgVmd6dJoi8/qqJ6mfrdMy
         QRyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ox3ejexcnSO2kiSqXPJuX7n+jNsz1cXUFvtntlnSEE0=;
        b=0myWv8GuoCFm/izYCllTmuW3a6R4ZSzK2cmZYhx/Xtp805LhNSOmAt2eQAYqE64W/i
         Ask2WqOENtkQIzXlzTwgKJXWFZjNjCPSaQHrrjxdQMaF69bEPtFnkhQvuVowQgtFMmJA
         zfoVmyfk6c8LP9D2tO5nwfFXxGORAhCcjBvopqyHnD4qPwc+PzT2h2pRliiAy404kLpR
         ErDKIYKc4IYvoCZnS3zd8qza0huWYroYgduNz/LABYFPKCxNP0tzZb2/1g7a91cIXs+t
         xAcxO4Lpu9exsOdmxb6RIBBBPl0qMEwGq87VghkKvle2tAItEAURWe5ms/ZgASlHM5ED
         eoNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=KPzqGIDn;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id x22-20020a6b6a16000000b00675593cc6acsi654366iog.4.2022.07.04.13.08.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 13:08:26 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1o8SMB-00HYnF-MF; Mon, 04 Jul 2022 20:07:43 +0000
Date: Mon, 4 Jul 2022 21:07:43 +0100
From: Matthew Wilcox <willy@infradead.org>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4 44/45] mm: fs: initialize fsdata passed to
 write_begin/write_end interface
Message-ID: <YsNIjwTw41y0Ij0n@casper.infradead.org>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-45-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220701142310.2188015-45-glider@google.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=KPzqGIDn;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Fri, Jul 01, 2022 at 04:23:09PM +0200, Alexander Potapenko wrote:
> Functions implementing the a_ops->write_end() interface accept the
> `void *fsdata` parameter that is supposed to be initialized by the
> corresponding a_ops->write_begin() (which accepts `void **fsdata`).
> 
> However not all a_ops->write_begin() implementations initialize `fsdata`
> unconditionally, so it may get passed uninitialized to a_ops->write_end(),
> resulting in undefined behavior.

... wait, passing an uninitialised variable to a function *which doesn't
actually use it* is now UB?  What genius came up with that rule?  What
purpose does it serve?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsNIjwTw41y0Ij0n%40casper.infradead.org.
