Return-Path: <kasan-dev+bncBCII7JXRXUGBB6FNV6OAMGQEOP35KQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 378AF6419F5
	for <lists+kasan-dev@lfdr.de>; Sun,  4 Dec 2022 00:08:41 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id x10-20020a05600c420a00b003cfa33f2e7csf4553624wmh.2
        for <lists+kasan-dev@lfdr.de>; Sat, 03 Dec 2022 15:08:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670108920; cv=pass;
        d=google.com; s=arc-20160816;
        b=P3EtH/sp9QOqXW0GZ61IpyxQPeJu4BBc+ct+mecKPo4FpSUi2uHnkTkSbvWaALa/7G
         FYn8MmCw8IBrvqlIse7Y+g/h74rMWMSftDoa6RoJ2zDdbB34KTLQ6FN5jNgO7MN7hMIs
         3SrxlrswYOK5PjTkxBGTFdHT8+/1OrbpPSwaluDLRq46MsGjRU9w4BdSmzVvJSZRJn4x
         4OCqQ6H4keD3n9KFeQTDj64gjXKobwvgkRm7CkFSt8Kz9jJqfI7INHrmG/ykmDDcG0cz
         rM10yifm4U/ISipj8UOId9BqXWZXYP1AL4fAAUJFmM9k7c2FcMuAOzm5/ClLsC/UBX7B
         nWsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XeOMU1Ak0ifdrrZyIHXM+Mg4R/BodNt8LtshwMrvrm4=;
        b=IOfvGCMspeHvNxuLylUOC4UDlVtH5BbN3swEDIvM5sN1ZR0k42fBRdrecUl/Eh3NVw
         LqULXBSPUd5gLw2B5sWlS8oIMQfnuTdUC21oND8p8c0C9fxQrzLXniTT/XLvSV9nLce3
         jqfmalO+u1nzmoafIkShXPs8qUxv4Y1LYOYh/ZJfFLSjip0q7NVnooyahRtihY4tBr/q
         HhygXVMFhZm0xEUfouNhk+N8Cc498EckvMfL30wHT0H1DahXjGWn8ekoQL48n87EBxMj
         UB3Pstai1+4KbquRgOjMfWXHlUdR8sj5pzK+IzbBcaUQeRjNWqeqCqvIQThkRV5NhZ2O
         cuhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=h+QJvpnd;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=vWVy8GgB;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XeOMU1Ak0ifdrrZyIHXM+Mg4R/BodNt8LtshwMrvrm4=;
        b=J8bKSM+7NKteKyFTrxbokj1ovIYJTFdQAHNjafClCBaoFzN0iewIj9VERokNKxvvex
         hX+Cgtp1N1cnqXxJ7iG64lvmGdrdsGaSlCX3DroDcaFaa6xohX4Bmzb+kYQcwuRQ4402
         uySn0E5d+hjqXMG/U0iG7bRAv/taiasgaUuq9mzCUITX+dG+zHwDfLn1cRQmpnHUo3El
         uF2lDfqxWCH/9LwhC6sB0SrXRgo+FjJTtCEBA0g5Kz1Lzu7pSoH2/NeXONgrMTs9Wt9X
         0nnTfJQuhFglolE51ksm5hTYdgLCIK5kO3giTYkIbCfPapnOEusljnATfREJS53MJkhc
         SJ7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XeOMU1Ak0ifdrrZyIHXM+Mg4R/BodNt8LtshwMrvrm4=;
        b=ENmsubYR3KO3pBZG+G5JJZaRMo1mal0IIOT6tMwudwZ6O6hwVP+G/P/IWt4vVTLDvv
         4eR0tHYxX9oJe0coIpOrq+ByEwZmpJzT7XqhNpWCXsXsNJ2XWR0M33yZ8QDKAIA60tsR
         VcBfOiujiqPZMOfE5Nf5jQ6ZoFvdSjx4Bu+sJpaGQuw2/a8h3dT0VM1I0CcFtHRQKz/Y
         r+zsrotgvcbML165JhIQmyRK79H41JoT/qdy7ilmG9mEHSLf653oi7bRTUxih0yvHw0m
         FsOjnSPoQLee87OtVpP4bhDU33Ypj1ZtAWtR7kEFhNQYh0XbzFFpR4rDkWgBJvESLCN6
         wBvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnHj3As6CVswolwMQLblJWqdCSRnC2OUNcpm13eN5Qr4AWHmkDD
	wcDKkDrkMTanUDx2414FjjM=
X-Google-Smtp-Source: AA0mqf6bhb2S8xQQgP0XKwO+Ne+Q3aaFwtyFZ6871UiWw4gLCYf3CMUCozckBWblTiZEFxF8rVjN+A==
X-Received: by 2002:a5d:5445:0:b0:242:c41:c880 with SMTP id w5-20020a5d5445000000b002420c41c880mr22347333wrv.469.1670108920558;
        Sat, 03 Dec 2022 15:08:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6f1d:0:b0:225:6559:3374 with SMTP id ay29-20020a5d6f1d000000b0022565593374ls3129838wrb.2.-pod-prod-gmail;
 Sat, 03 Dec 2022 15:08:39 -0800 (PST)
X-Received: by 2002:a5d:464c:0:b0:242:2ac1:375 with SMTP id j12-20020a5d464c000000b002422ac10375mr11169754wrs.432.1670108919492;
        Sat, 03 Dec 2022 15:08:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670108919; cv=none;
        d=google.com; s=arc-20160816;
        b=HhwHHMuC426IOFTxQKBdJkqfIUi3OHBst4M4u9robuK0/hyJcD1NuZm1tNh0uFXhy6
         uwarS8xfdHYnN5QB502jMeA3UmH5DjhHCcYoIDmg+BZP3b+aPEnv976RZUoViBrs2FaF
         +kKdq7Z3pQrUtkYHn5wnyspWCZ+xjzjYleDO4ru5Pdghbab6MXOqHJRzqkqPjY3fbtF3
         sJWzU5YviqEGzVrFEp928CFVZ5ElcSpQAQBc0ZM0nGO3fCfiMjyTLGzOI+AFYGacL0Mj
         omI6St7YaKJDF95HqmcZAKiGDHTXkd5XFn0UEEXjY+U9v3jkS0MmNXDrkX9/IAjXTp1a
         2+8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=+CO9rF9Z3sjMwxpNknlXTJ5cZA3lSjQQRNAnKsWpV0A=;
        b=kzF5L67sNm2Zai2pyiFc9anmatDjNVPriO44xK+hINHwVURz28O7luomAFCxXbOG5z
         8aL5Ojg/Nh4Nrk7FK/OguJ9pYNtHpYyjpb3RZUcOqpI0/zm4VUvjULfPNquCvFAf2WyZ
         zrvKP7dMpTzOG6Ep+mC+0X/hZppp5Z9S06PycuHHuTRpcqrVQ67Ic19XZceYszi8gWFH
         T+7DM5CB3LQg5S07Y6I/F7l/2p3LMAtuyIZZ9Mg2bfHL4P1/VEpyUfsIoHGxzsRDMh6j
         l46urqgMcNoI44mDIPQwqVsuOc9U/AAB7Wk66MQuwPvP/r4JLO7GHvDdr96rCIzpny8j
         yRWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=h+QJvpnd;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=vWVy8GgB;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
Received: from nautica.notk.org (nautica.notk.org. [91.121.71.147])
        by gmr-mx.google.com with ESMTPS id c4-20020a7bc004000000b003cf1536d24dsi562480wmb.0.2022.12.03.15.08.39
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 03 Dec 2022 15:08:39 -0800 (PST)
Received-SPF: pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) client-ip=91.121.71.147;
Received: by nautica.notk.org (Postfix, from userid 108)
	id 3784DC01A; Sun,  4 Dec 2022 00:08:48 +0100 (CET)
X-Spam-Checker-Version: SpamAssassin 3.3.2 (2011-06-06) on nautica.notk.org
X-Spam-Level: 
X-Spam-Status: No, score=0.0 required=5.0 tests=UNPARSEABLE_RELAY
	autolearn=unavailable version=3.3.2
Received: from odin.codewreck.org (localhost [127.0.0.1])
	by nautica.notk.org (Postfix) with ESMTPS id 3DF9AC009;
	Sun,  4 Dec 2022 00:08:42 +0100 (CET)
Received: from localhost (odin.codewreck.org [local])
	by odin.codewreck.org (OpenSMTPD) with ESMTPA id 1bfa2785;
	Sat, 3 Dec 2022 23:08:31 +0000 (UTC)
Date: Sun, 4 Dec 2022 08:08:16 +0900
From: Dominique Martinet <asmadeus@codewreck.org>
To: Marco Elver <elver@google.com>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, rcu <rcu@vger.kernel.org>,
	open list <linux-kernel@vger.kernel.org>,
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Netdev <netdev@vger.kernel.org>,
	Anders Roxell <anders.roxell@linaro.org>
Subject: Re: arm64: allmodconfig: BUG: KCSAN: data-race in p9_client_cb /
 p9_client_rpc
Message-ID: <Y4vW4CncDucES8m+@codewreck.org>
References: <CA+G9fYsK5WUxs6p9NaE4e3p7ew_+s0SdW0+FnBgiLWdYYOvoMg@mail.gmail.com>
 <CANpmjNOQxZ--jXZdqN3tjKE=sd4X6mV4K-PyY40CMZuoB5vQTg@mail.gmail.com>
 <CA+G9fYs55N3J8TRA557faxvAZSnCTUqnUx+p1GOiCiG+NVfqnw@mail.gmail.com>
 <Y4e3WC4UYtszfFBe@codewreck.org>
 <CA+G9fYuJZ1C3802+uLvqJYMjGged36wyW+G1HZJLzrtmbi1bJA@mail.gmail.com>
 <Y4ttC/qESg7Np9mR@codewreck.org>
 <CANpmjNNcY0LQYDuMS2pG2R3EJ+ed1t7BeWbLK2MNxnzPcD=wZw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNcY0LQYDuMS2pG2R3EJ+ed1t7BeWbLK2MNxnzPcD=wZw@mail.gmail.com>
X-Original-Sender: asmadeus@codewreck.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=h+QJvpnd;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=vWVy8GgB;       spf=pass
 (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as
 permitted sender) smtp.mailfrom=asmadeus@codewreck.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
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

Marco Elver wrote on Sat, Dec 03, 2022 at 05:46:46PM +0100:
> > But I can't really find a problem with what KCSAN complains about --
> > we are indeed accessing status from two threads without any locks.
> > Instead of a lock, we're using a barrier so that:
> >  - recv thread/cb: writes to req stuff || write to req status
> >  - p9_client_rpc: reads req status || reads other fields from req
> >
> > Which has been working well enough (at least, without the barrier things
> > blow up quite fast).
> >
> > So can I'll just consider this a false positive, but if someone knows
> > how much one can read into this that'd be appreciated.
> 
> The barriers only ensure ordering, but not atomicity of the accesses
> themselves (for one, the compiler is well in its right to transform
> plain accesses in ways that the concurrent algorithm wasn't designed
> for). In this case it looks like it's just missing
> READ_ONCE()/WRITE_ONCE().

Aha! Thanks for this!

I've always believed plain int types accesses are always atomic and the
only thing to watch for would be compilers reordering instrucions, which
would be ensured by the barrier in this case, but I guess there are some
architectures or places where this isn't true?


I'm a bit confused though, I can only see five places where wait_event*
functions use READ_ONCE and I believe they more or less all would
require such a marker -- I guess non-equality checks might be safe
(waiting for a value to change from a known value) but if non-atomic
updates are on the table equality and comparisons checks all would need
to be decorated with READ_ONCE; afaiu, unlike usespace loops with
pthread_cond_wait there is nothing protecting the condition itself.

Should I just update the wrapped condition, as below?

-       err = wait_event_killable(req->wq, req->status >= REQ_STATUS_RCVD);
+       err = wait_event_killable(req->wq,
+                                 READ_ONCE(req->status) >= REQ_STATUS_RCVD);

The writes all are straightforward, there's all the error paths to
convert to WRITE_ONCE too but that's not difficult (leaving only the
init without such a marker); I'll send a patch when you've confirmed the
read looks good.
(the other reads are a bit less obvious as some are protected by a lock
in trans_fd, which should cover all cases of possible concurrent updates
there as far as I can see, but this mixed model is definitely hard to
reason with... Well, that's how it was written and I won't ever have time
to rewrite any of this. Enough ranting.)


> A (relatively) quick primer on the kernel's memory model and
> where/what/how we need to "mark" accesses:
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt

I read Documentation/memory-barriers.txt ages ago but wasn't aware of
this memory-model directory; I've skimmed through and will have a proper
read as time permits.

Thank you,
-- 
Dominique

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y4vW4CncDucES8m%2B%40codewreck.org.
