Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNHBRODQMGQEKZV5TPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E24183BBC59
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 13:44:52 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id u2-20020a2e91c20000b029017f236536cesf5402307ljg.6
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 04:44:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625485492; cv=pass;
        d=google.com; s=arc-20160816;
        b=uVaoZ2rkc5t6XrgCcZNabLLcffGT1gTL1xzgohaTnkhSEKo16lN80D11kkzlyx43Qq
         nXFqL8irnVo7QBis4L5T4SxLc9aijmkOCSPVO+MACgOWGo16dT5UwdZ8dTKNaQDbWJkF
         PB7olMKaVceALIit4P7eaVctzLdS6cMimLU5IbpHLhPlVe6LIJd1JPrdrnmGW5PPXnrJ
         O0vHhTY8Q+k75x3pMgQEr8NFUDCa7h3p2nk0KlOsDpXJMFTnHjO2qNj1Hu0mYv2JqrOX
         cSJcS0IWn8Jv6GpMLcLprDIyQ2Ohr1xHY5GBn7JBKVjV8zdMI8cekFqxIzom/ZXlMUfE
         CSxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=cRox9t/ucG5yd90h+YJ0i5CNf4B/nnGmH45ricFvcpw=;
        b=QEdq5ntLuH/65mOeKCREMHpRJJT3V7pFU+EmYDxuToJ4TwYhiKcQlM2fRmEpnFd/ui
         9Ri27I8HMCmIQVok2vsx/FBB1y1fYUrh96zzU8YCzvylan2Nmu2x+gJMP2oaK+q9UUkd
         P6O9FSoRH6Uwa9Scsy/JluldWBmiZk3oXH+tLcvaa2NlLPwEeFtO4tzXLHC4FgqbAlWr
         SzDjS/Zwznpzd9HV9OtupiNcye4GrVr4cB/BRRleXSxjhfiohHGLpeRgSi23Z0N/8Mpu
         gSy0Fap0Uw/I/qVZJ8BXb0mFtLgNj3zdmja+Sqbh+oX5gewQi9eBPRZXfwjCPx3j5lXP
         LwJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uVl/FVYJ";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cRox9t/ucG5yd90h+YJ0i5CNf4B/nnGmH45ricFvcpw=;
        b=sVSTewqyAwjUbdR8jzqsISjO7TMIq+3Z/oogS8ktcXlNQW+VA3GE3XMM6gvb9hnxs+
         155QbbA7OOVcTvo2I/we1L/suSlnXhlK2UDtNQqNblPdSWDDgM59jzGtDhcEmF+e0/Jb
         KFYTRLmd/HlBX18Q0ANcZomo6VLnSPk5gyooHjy/PEvtgx1nqh4nohH/n7bmZ1zSMxar
         gt8faN/ry2X7YqrAnJNNdqSCC0h/gw4Hz/CK0gNGMkYekpVzWS4lyM2QajT+ciEjDx7U
         +t5eihIU5qR4DGvHeVaOy2Cw0fzNGEEyytSWUt+cCQFb7U/RFoGmJB8iIuqiL5/DKeXe
         JNhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cRox9t/ucG5yd90h+YJ0i5CNf4B/nnGmH45ricFvcpw=;
        b=r+zbVGcGvaAHyoLOOsWuK4g35li2v4iyWOwu9OfQDIAu83a8agPCaAq4Ad5G/PyhtT
         fzrdaNgThydgEvFJXJQZl+ACw40f0qrLtiLKQ74P4rzBJ8FdrRezqZwzIcCpIIgo+VIC
         C+WpcfXh740LMeqmyxKoi0jHz3hfn7tiR0nJGHFAwZ2+5DWkfbpEUeVOhVVEoWXQJvHE
         QSt8Si24djj3fvuvvxmGO4pCDSrLKIBH6UBu81KfPmT5iKccfZq2YkVHWyZwDMmvkQJ0
         QMZSWmS/WQ4elW06FNynkv73k+lt46j+5fNCui293IkO9ied0c0A3g8Rw//X9MMRPz4c
         m7ew==
X-Gm-Message-State: AOAM532L2zWqnsr79drHrtDupucPTzZF4yQyBAmV49eLDFGLZolwuKt6
	N7mQ56sUMCefRA/xMXmpf3k=
X-Google-Smtp-Source: ABdhPJz9pTvWCcbP3Cx6Vsrz3WgVbVjLj7HAYc0JHtwsPYFjyHQPSPIF2ZQDX4azn5BXZ5Datha2lA==
X-Received: by 2002:a05:651c:20d:: with SMTP id y13mr2886538ljn.342.1625485492522;
        Mon, 05 Jul 2021 04:44:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1025:: with SMTP id w5ls2967639ljm.0.gmail; Mon, 05
 Jul 2021 04:44:51 -0700 (PDT)
X-Received: by 2002:a2e:888f:: with SMTP id k15mr3075231lji.368.1625485491405;
        Mon, 05 Jul 2021 04:44:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625485491; cv=none;
        d=google.com; s=arc-20160816;
        b=DGNi4EUpmUYb7rcZAIlfQl0kYX0X6V05cyFM+2bgPuukiOPI0d8mjcZ6l223mgaqJW
         8uj+BYMtzvjAUv57ga/RFrs1qMpz39cweL8fbFE0yppcWrSczhgUav1ED3FxlmBmfnpK
         rDqC5VWJQgBJBd+qps7eNVGUfdoUUA88xjx7PTCwTeunkU2dvtfwPZJWwO3fLgRcgWll
         hHWFeTfeakWyrK81MhXRxaov2xPPc2+5sed6QJkwaD8VxGJ69VMtZkms08WCOw8EQGKt
         gGQ6Pu1gpHQZoI0DYwCIj6sYiTk9J+VmN8RbjKjt8ZuaS47AmEd2+oM0GB2yjCUiNhbn
         LDdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=JP655Kr0pQo2WIEbmEE6zI777FgwwqQfTWCo3Yd5U5Y=;
        b=QOHK5TOrmnkQWUEA9VLNYDB0VvWCPGFBDJVtdhDspfTsJ5uBpIyh5O6Onl+KRKlItk
         NPPKlGi7mwsPG4V9dm5ZOEbgEBFdZlwMQCyJw8eB0WQ3Z/bbvfSmu0AY4SYQQzJmUok/
         zAZkjUjvG2lMhHC1VHHxBKe4070iPxpBA2vPBf1dyPcKYICseQ9j9L7RilGaqqIZ0FrV
         vsLNzRChn4XgqSesK563cJtRTlOJ50TFb+pWogdktU70MB+ALMtonbQOpOkOt6nJKccl
         q0z6FXru5oOBijaEuBh4csOHTbeqj1OC7zK4gcsBTu4H6ra94OLdbNkYC/c85kGr2eHq
         n5KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uVl/FVYJ";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 187si61829lfm.5.2021.07.05.04.44.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 04:44:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id h18-20020a05600c3512b029020e4ceb9588so591912wmq.5
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 04:44:51 -0700 (PDT)
X-Received: by 2002:a1c:25c6:: with SMTP id l189mr15148080wml.49.1625485490745;
        Mon, 05 Jul 2021 04:44:50 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:dddd:647c:7745:e5f7])
        by smtp.gmail.com with ESMTPSA id r16sm15313150wrx.63.2021.07.05.04.44.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Jul 2021 04:44:50 -0700 (PDT)
Date: Mon, 5 Jul 2021 13:44:44 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mel Gorman <mgorman@techsingularity.net>
Cc: akpm@linux-foundation.org, glider@google.com, dvyukov@google.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, Andrii Nakryiko <andrii@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Vlastimil Babka <vbabka@suse.cz>, Yang Shi <shy828301@gmail.com>,
	bpf@vger.kernel.org, Alexei Starovoitov <ast@kernel.org>
Subject: Re: [PATCH] Revert "mm/page_alloc: make should_fail_alloc_page()
 static"
Message-ID: <YOLwrMBk6TymR74k@elver.google.com>
References: <20210705103806.2339467-1-elver@google.com>
 <20210705113723.GN3840@techsingularity.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210705113723.GN3840@techsingularity.net>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="uVl/FVYJ";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as
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

On Mon, Jul 05, 2021 at 12:37PM +0100, Mel Gorman wrote:
> On Mon, Jul 05, 2021 at 12:38:06PM +0200, Marco Elver wrote:
> > This reverts commit f7173090033c70886d925995e9dfdfb76dbb2441.
> > 
> > Commit 76cd61739fd1 ("mm/error_inject: Fix allow_error_inject function
> > signatures") explicitly made should_fail_alloc_page() non-static, due to
> > worries of remaining compiler optimizations in the absence of function
> > side-effects while being noinline.
> > 
> > Furthermore, kernel/bpf/verifier.c pushes should_fail_alloc_page onto
> > the btf_non_sleepable_error_inject BTF IDs set, which when enabling
> > CONFIG_DEBUG_INFO_BTF results in an error at the BTFIDS stage:
> > 
> >   FAILED unresolved symbol should_fail_alloc_page
> > 
> > To avoid the W=1 warning, add a function declaration right above the
> > function itself, with a comment it is required in a BTF IDs set.
> > 
> > Fixes: f7173090033c ("mm/page_alloc: make should_fail_alloc_page() static")
> > Cc: Mel Gorman <mgorman@techsingularity.net>
> > Cc: Alexei Starovoitov <ast@kernel.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> 
> Acked-by: Mel Gorman <mgorman@techsingularity.net>
> 
> Out of curiousity though, why does block/blk-core.c not require
> something similar for should_fail_bio?

It seems kernel/bpf/verifier.c doesn't refer to it in an BTF IDs set.
Looks like should_fail_alloc_page is special for BPF purposes. I'm not a
BPF maintainer, so hopefully someone can explain why
should_fail_alloc_page is special for BPF.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YOLwrMBk6TymR74k%40elver.google.com.
