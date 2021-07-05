Return-Path: <kasan-dev+bncBCK2XL5R4APRBNPGRODQMGQEKFM452A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F2CA3BBC79
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 13:55:34 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id n11-20020a05600c3b8bb02901ec5ef98aa0sf3035242wms.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 04:55:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625486134; cv=pass;
        d=google.com; s=arc-20160816;
        b=JFwmiSnFwBnIvbNxtVohHlWyBqFfcFleXJakEaO8DTY2j0q11hyT0/1bbFhQPvqBMH
         26F/d47HjD9UGk9aUbgM5nLVLwrz4WV0MvfJU1KOBNaLb4Vz4RgUcSfh4sCF4TgBbdcu
         KWTSTDU3Bs0vRNQ7IpTTUjbMs8RGdEANHImUx0Ese4oXm9GVinfpAwV5TY1rMcK1nQ7z
         D8gguV8gI6TVc2XKdXwmfkFoD53DcaRFnUX9xFTiTeWWImgDc/nEXnjvSLyL9iScMbkF
         HSjp9J8IUss4vxnCq7bcFW72uw1AQB4lfoN0Kpyf1nqpoTY0/v4LIJzFeNI3G/Du5Krt
         5nEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dJqCBNBJQ/yJp3haclQsF4Uw+98TvlH+Pu7ZymumLkk=;
        b=psYb/NYob/DdJ4w5Bz5XBdEbzcyXoSLgRVyU5uEd9/BIrpXWlOP869ShFEbaOPFogd
         ria5vxHyDeCkW7bLHCGWFBN1GobjDMZoS0P6E617DlSF/TX55xssJFYCg3gC1yeRxHRs
         jB5dLrvyrKBJSRnEjJy1tlblFbD+pjRSFiFBfFiegd+5FaCZanVctPkldqDnOnzDSkag
         P3lr/UTz9vTvoO+u15fjj0rHSIYai7ecSS9ygy++AtGKfC5j8rxlylM2nz3BSTt2CGS7
         w0upxa3GXsYQvrOTx2Gx047Dfv+/Wpg3rfzNy4BtcUOajic5zpnryQ2loOrPmaQ5kixG
         fV4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=a+qDzygS;
       spf=pass (google.com: best guess record for domain of batv+89f591086bfeb560eb93+6525+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+89f591086bfeb560eb93+6525+infradead.org+hch@casper.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dJqCBNBJQ/yJp3haclQsF4Uw+98TvlH+Pu7ZymumLkk=;
        b=So3W+XxZwoCPNhY9GoAULq5adf9hPVzGekXED+xO4IZrZV4TuhNZLGRnKvh0PtqQZC
         ZgrvqHmRObIUSSiRx+Ais+KCGCwb5FKf+rSMsGEyQZAR9EDdA14Ld5oGaQmrwqsGlmc5
         xNwTmFhQAaiTy51Bk2s4Gp2MBd7JxIvqmUGjCgnqAijKfecEmnjxV1BE46Qjaz+Qf3cw
         qFZtKq/fXf28hVnz57uCcbiMqhzBvpF7y9buSrg/GkT16t9WMig5B83qpsiMPpAw+AaE
         xsZGZC+mY4+HWXR75ky19vDe/mPL7XpqsrgUQQhlj6knigYCj9Y5+KG9cB7vGf5PYclM
         FNYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dJqCBNBJQ/yJp3haclQsF4Uw+98TvlH+Pu7ZymumLkk=;
        b=rmoKztJgKTdcjDBaCODcgQxxAE20jGN6oRBp558tuLftTaOMrF6R4GkK/oADP14o6c
         eSxs6lC8DPIC24e8loNLZcOiGidk/ExH0BiUUDFRJWuF26/GS7LtzcZ+NvG0/ryutRk4
         fApYC09kRFwJvQzlCyVN1vrIgHpJcAZ8Yk2queCO8OFr/2stCdBmab0ho/P1YQAAHlLr
         qpahNZesTlnm8Zo8vFr24l2JZLRYzD4Knzs594Gs83QQx5pDiXBCwhp32zHvvXWo6BWC
         lRk+oU8kfl4Upuk37RmvQhexKrqlV8biriICR0cjQCLBqRNpY9ixg35NpfrkVgcZ88ND
         yLEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532W11ILOt/yXpTjNukquzIxtE/NvC599eWQ7uugoIzTOrh8MhLi
	c/L7jBLFQCOe1rLzHxNw0KY=
X-Google-Smtp-Source: ABdhPJwhD9T5AiuKhtZPidR9S8J2J9COU91BGdQ11++7gKbgYvJhm33HEktnYVjbYEq/3j8xYlT58w==
X-Received: by 2002:a05:600c:3783:: with SMTP id o3mr14784377wmr.123.1625486134128;
        Mon, 05 Jul 2021 04:55:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:69c7:: with SMTP id s7ls6294047wrw.1.gmail; Mon, 05 Jul
 2021 04:55:33 -0700 (PDT)
X-Received: by 2002:a05:6000:1acb:: with SMTP id i11mr15039350wry.120.1625486133358;
        Mon, 05 Jul 2021 04:55:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625486133; cv=none;
        d=google.com; s=arc-20160816;
        b=wlw7MKvyke3JNHw0LU2103a71BgxKiqQZ25i4cc29Pdg4MAoSCgIViiot4wybsaPyv
         E/RIFZUq9ISAOJt6J+66Fw3kdSd4xWoFpHpGUQgm1ZK7G86QuV9Z4RRo08z3Wnlzfgjg
         yldYNsQYXAQ+/JkHlVuG6gNPrSecYBRS8hXVBY4zgwRoz7XkXTdlaWKirqgZZFTPOG9E
         jJbBVw8pY7eS2oc6YaDq55oh3ODCwkNJdU4tc1F7XDqSychQZt+6TxoywKu/SDBsaG8C
         oyYubqFJmyLzpgihknK2O5LyjrlZbnSZxORDFNH9Yhw1UHQMUB9QVxdi2hLJAUzjQS0s
         iYAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Pq7bP+MTawU/za6/1KcKOrsotUVcyEKhovbCd0LbYxs=;
        b=RAT231bUCU75FbKJ/Ovxw6Luvwm1yAOwUSHKXOlL0HP2COCrXor8VMQxCB44baF8n+
         iR9XK2ay4WFzKvqN/bARNwj21v/WDq627fIihmi5q49U7I703J9GWh8ID9Gt8+M9J3r4
         eB2M3M+EBdrN/13vIevCnfLzIPfx2BTYcXD8qKogNvML1uEDSfY8e0EixETqkbVA1/AS
         iGvJa+i5wdV68LmSC1GrHkn88M5qlYrArdASBaPt7kN3F5uaOE9Hojf5DtzIIxHgbTaO
         9Jcy+ZLUwd0cEU/LxC7QjQn3BBAhrPDzYGEjVOVQ+x2mHKQcPv9BEYwoAhTa1al8Ydxr
         ROLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=a+qDzygS;
       spf=pass (google.com: best guess record for domain of batv+89f591086bfeb560eb93+6525+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+89f591086bfeb560eb93+6525+infradead.org+hch@casper.srs.infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id k3si523031wrx.1.2021.07.05.04.55.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Jul 2021 04:55:33 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of batv+89f591086bfeb560eb93+6525+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from hch by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1m0NBl-00ADQL-7P; Mon, 05 Jul 2021 11:55:09 +0000
Date: Mon, 5 Jul 2021 12:55:01 +0100
From: Christoph Hellwig <hch@infradead.org>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, dvyukov@google.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, Andrii Nakryiko <andrii@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Vlastimil Babka <vbabka@suse.cz>, Yang Shi <shy828301@gmail.com>,
	bpf@vger.kernel.org, Mel Gorman <mgorman@techsingularity.net>,
	Alexei Starovoitov <ast@kernel.org>
Subject: Re: [PATCH] Revert "mm/page_alloc: make should_fail_alloc_page()
 static"
Message-ID: <YOLzFecogWmdZ5Hc@infradead.org>
References: <20210705103806.2339467-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210705103806.2339467-1-elver@google.com>
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by casper.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=a+qDzygS;
       spf=pass (google.com: best guess record for domain of
 batv+89f591086bfeb560eb93+6525+infradead.org+hch@casper.srs.infradead.org
 designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+89f591086bfeb560eb93+6525+infradead.org+hch@casper.srs.infradead.org
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

On Mon, Jul 05, 2021 at 12:38:06PM +0200, Marco Elver wrote:
> This reverts commit f7173090033c70886d925995e9dfdfb76dbb2441.
> 
> Commit 76cd61739fd1 ("mm/error_inject: Fix allow_error_inject function
> signatures") explicitly made should_fail_alloc_page() non-static, due to
> worries of remaining compiler optimizations in the absence of function
> side-effects while being noinline.
> 
> Furthermore, kernel/bpf/verifier.c pushes should_fail_alloc_page onto
> the btf_non_sleepable_error_inject BTF IDs set, which when enabling
> CONFIG_DEBUG_INFO_BTF results in an error at the BTFIDS stage:
> 
>   FAILED unresolved symbol should_fail_alloc_page
> 
> To avoid the W=1 warning, add a function declaration right above the
> function itself, with a comment it is required in a BTF IDs set.

NAK.  We're not going to make symbols pointlessly global for broken
instrumentation coe.  Someone needs to fixthis eBPF mess as we had
the same kind of issue before already.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YOLzFecogWmdZ5Hc%40infradead.org.
