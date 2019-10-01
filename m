Return-Path: <kasan-dev+bncBDMODYUV7YCRB54FZ7WAKGQE6EBT6FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 96C76C4287
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 23:19:52 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id q18sf40782627ios.8
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 14:19:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569964791; cv=pass;
        d=google.com; s=arc-20160816;
        b=NUYfJJVddUl2tMCB9rlEKMjTe7iVUYbWztJ/tQiMHt0YP32iqRDOE/aKav+5DWByJT
         W3EKNqg8Y2THfdtBimAHnipbAk21ihq1qJ192zLs1veSiUNqp5it708bDTOx7AP+dxUI
         q2vkr1nUHEVgOb6mC1mwWgEyuBpFPN5heJ2PcmNgGs1Mu64vEIFM2eHPL70zLL8x9L5s
         zkyqNLAt0CbWQu9RXRL3/YkG/wIhvO8FMDh4kyJ2jKDbmGFGN+y6JmwmvR6o106bm/Aj
         eZWR2XZbc/fLUFSH9+nU6cYpuzDhaZkOzijVZOvzdlDa3yzL38Xoz34GHHlPvwvTM2V0
         rV+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=u5ydr3G0kQiSYJ1XTCeXsEF3XODNw67Y5vBQxJ7eh+s=;
        b=MJ7zHEdqswRi/np0hV4pL/yMFkoQjRrjwiw9frd85SxheNjIUOfq0R1o9EDLRTByv7
         ZqT/HSOvTdS+Id102+PjVw0aB8CmjG67tKff6ddRF1exsX39mQLezNkGrbCWdLDz0QXl
         NIHVPDJULxnzOxuOsZ/Dkli2ZAeJhy/AdBx5BZeGSF6rLTozJczkgWHZ5H5LEofM0vMq
         lp6wHtXtBeVgCQnWWFAlfDSRbjC1wIZfO0V8qqRQj7tIZFj/UNfKRLgXHEdsmNQagqKJ
         z+skaJ0joxeFgB1XrAX0JxxP/ip2UnS/VeYDjz32GWcCBqZEQMHujO7aCiLAaw/bTHye
         jyHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@joelfernandes.org header.s=google header.b=xEclNzVy;
       spf=pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=joel@joelfernandes.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=u5ydr3G0kQiSYJ1XTCeXsEF3XODNw67Y5vBQxJ7eh+s=;
        b=cXYjW0J1ZKmjDw42w0+lwnCR3RTpla1RttIij9HN5VykmT+d0hZzWMXplwvmneoVfF
         eswu6bhO35ckAYHid+A3cw/S/LHlVsx3Vo4malZCDDv878T1UPM2/VT9qhEVhCNdRV7E
         ok2ijOd5/Vak7c2jgz5XXQQgNGhAc3UvFeFL1i1ewJSyhYcXU7DkMVOokWqgByAVG19p
         ZMkT5aElIZDiXOu+iTUrmq9QKZButR2/QOWASEqEBdCxXhvTeEAVIeUefUAYp5rtgqeU
         CePbMuApjMFrTHeFndVsKhYZDd+MtC135knDDvoLVRSqmSp9kE9nizBY/RdFHwhyDodF
         r9tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=u5ydr3G0kQiSYJ1XTCeXsEF3XODNw67Y5vBQxJ7eh+s=;
        b=MFUBdkUtaALWGnT5EPFWUelX5QIT0MnP1yv4xzOB4u2l2w2mxs9HLbh1c9sqkHfl7g
         hP03w3Dga5O1cFM4wzGvbi94APE2VlvD9qeMhdjE1nzzVv9ehVNcgfgSmuB5u5PXq/gV
         KCLHYjuBSm5U6gDdTg/zUnUC5BF4srl6d8u8iXEuZra1MmnulLkSKS7FAGd0oXsrKjl+
         /yMdGGRDoMAHFem8zEcYE1DaMu+6FsLmU/Kk4Wne2zDdw6AvJjW21zWrkNh8rE1/uTq9
         2aLcHQItkwqEq5WxHpcoHFrmA4HWG/ilvBpvtj6CcykIjcH/mRGvCrC1bgejCqJoBF18
         5qiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVp/70pL6BY09ZNTX4JjC6aHXTt68WDNf4Q7E/TRhh94kCBFP6f
	1aJ3YATo7WqWnO42+/9VkVA=
X-Google-Smtp-Source: APXvYqzAg5aHWCz+aFLvOIhte8Q73zbv2JUTp93/VfOuAwHQpr/Vfc47+NmuBnuzzKInoI04sy/rfQ==
X-Received: by 2002:a6b:6d0c:: with SMTP id a12mr256169iod.122.1569964791599;
        Tue, 01 Oct 2019 14:19:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:6a0c:: with SMTP id l12ls16922jac.16.gmail; Tue, 01 Oct
 2019 14:19:51 -0700 (PDT)
X-Received: by 2002:a02:712b:: with SMTP id n43mr466049jac.2.1569964791217;
        Tue, 01 Oct 2019 14:19:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569964791; cv=none;
        d=google.com; s=arc-20160816;
        b=qFF/77ap7ecnZ2WwmJXZwWSPu3PUPOAvPJA216a7TUWl+jpueDiADkPDSu6jcBf9BH
         2tEh+5R+0iG/38gPfvazPzcyJkjafEFq0k5RwWc2ooXlwa370MdT18agJys/pMb8jqwf
         gokPF0574Fv1y7l2gKdPeAssIPwJm/7UuwSDh2Zz9/lMMgE+fOpu8hZCJtE85xPcBRzl
         Y/vP1A6TXH7g7cwhAKYXZVscqXBXw5N40m5kpPN2JkxSfVC0u9U2f2XSKjJLeiJ4nSDN
         Awl9vw1bDW+bID/HV688zBCnf+7MHMtAmbROuLoPC1jXAo1Ma8REkLXv7rIg6xJhSftH
         J68Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=INoMgnqhH49ZFKFHhyaP4EdT7D9OjFM4A6O+XvHM0Oo=;
        b=hIrwLeD6RV4MEppPjofDaE0Zef/R0qg1N/ESP8sW87y8FI5sGLxWHepyFcN5LDTgtE
         x1AUuBEFKKobydHMeOR44378EmH3CEAOzmJX6QkYTb92jwD7B3DvYVxCdk4xA3sxzmsS
         R1sxkrPYJRHuGTejWICLA+IT6R+aDM5Duu5QEUNNGMFuXsSpkjUtGzRzC/7hMvzTlEao
         fbQ0b6BP3i4/ZyGAy8lmHXcPrnlOGIgWXxRGboHdM9zTNS3hcn5+hnpFF2iBELqHkHT4
         g3inf2xtSO9udF15duYI0sGG5DUUR6VhRdX/UUt93de0w4+zSAflEIO16sclQEHdBd7q
         oEVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@joelfernandes.org header.s=google header.b=xEclNzVy;
       spf=pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=joel@joelfernandes.org
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id b206si1135765iof.0.2019.10.01.14.19.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2019 14:19:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id y35so10607813pgl.1
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2019 14:19:51 -0700 (PDT)
X-Received: by 2002:a17:90a:21a9:: with SMTP id q38mr239494pjc.23.1569964790305;
        Tue, 01 Oct 2019 14:19:50 -0700 (PDT)
Received: from localhost ([2620:15c:6:12:9c46:e0da:efbf:69cc])
        by smtp.gmail.com with ESMTPSA id e3sm3080069pjs.15.2019.10.01.14.19.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Oct 2019 14:19:49 -0700 (PDT)
Date: Tue, 1 Oct 2019 17:19:48 -0400
From: Joel Fernandes <joel@joelfernandes.org>
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>, paulmck@linux.ibm.com,
	Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>,
	Anatol Pomazau <anatol@google.com>,
	Will Deacon <willdeacon@google.com>,
	Andrea Parri <parri.andrea@gmail.com>, stern@rowland.harvard.edu,
	akiyks@gmail.com, npiggin@gmail.com, boqun.feng@gmail.com,
	dlustig@nvidia.com, j.alglave@ucl.ac.uk, luc.maranget@inria.fr
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191001211948.GA42035@google.com>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: joel@joelfernandes.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@joelfernandes.org header.s=google header.b=xEclNzVy;       spf=pass
 (google.com: domain of joel@joelfernandes.org designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=joel@joelfernandes.org
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

On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> Hi all,
> 
> We would like to share a new data-race detector for the Linux kernel:
> Kernel Concurrency Sanitizer (KCSAN) --
> https://github.com/google/ktsan/wiki/KCSAN  (Details:
> https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> 
> To those of you who we mentioned at LPC that we're working on a
> watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> renamed it to KCSAN to avoid confusion with KTSAN).
> [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> 
> In the coming weeks we're planning to:
> * Set up a syzkaller instance.
> * Share the dashboard so that you can see the races that are found.
> * Attempt to send fixes for some races upstream (if you find that the
> kcsan-with-fixes branch contains an important fix, please feel free to
> point it out and we'll prioritize that).
> 
> There are a few open questions:
> * The big one: most of the reported races are due to unmarked
> accesses; prioritization or pruning of races to focus initial efforts
> to fix races might be required. Comments on how best to proceed are
> welcome. We're aware that these are issues that have recently received
> attention in the context of the LKMM
> (https://lwn.net/Articles/793253/).
> * How/when to upstream KCSAN?

Looks exciting. I think based on our discussion at LPC, you mentioned
one way of pruning is if the compiler generated different code with _ONCE
annotations than what would have otherwise been generated. Is that still on
the table, for the purposing of pruning the reports?

Also appreciate a CC on future patches as well.

thanks,

 - Joel


> 
> Feel free to test and send feedback.
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191001211948.GA42035%40google.com.
