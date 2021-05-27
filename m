Return-Path: <kasan-dev+bncBCV5TUXXRUIBBHPWXWCQMGQE66BZ3IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B796392C31
	for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 12:57:33 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id p5-20020a17090653c5b02903db1cfa514dsf1512493ejo.13
        for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 03:57:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622113053; cv=pass;
        d=google.com; s=arc-20160816;
        b=PhEvDEW1Nckf42+Or1v1vIYCG1T/4UEKYf9sj2B7NvXpyOZgEs2IXDitGhrav8KVyz
         kpQzJeuFqco/658vJLQOQ0+h1Qu9SFHIDDWx9gl4IkZZ1m8vNS9PvQBqmzI2ZIRi4sne
         fC9gng8/nDl2MuMQgypqPsn51yoDkKohQxZJmC+UP8tlbH2m361Wkf6DwlU0kL3wIVIj
         caZkszIehu4mq7d8pgVNCvb0rJZPfYERgJemGxD8z8oJWmSS7TfTl/RkQaLviTd11x1s
         P+b0s8EDNflHbXanHhhxC5yMd2dLjZDvWAd2Hh9of94bnvMhBVok0ZU7FasU4uV4f1qH
         w53w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=IAMLOoJDLthkP3KBfb6Gxl4JpXaFkqlSec+UiO9j7EA=;
        b=ryvVWsWqU/fj/xZmM0RY6fxp8DBldzFEN0vGScYQBKEKWQzAkYhe9PSRPlCPiuHo4u
         NzTLPX6ZPFSqSye3dXwVARo/fKYWdwqv0RLHSxnG5+N6fJzjimZkwNUmjNfIwf09mVL4
         iFNandYlYJhoxYesxIGeC1pA4iQXl1niPAOIoOv8WwjvgaaTgY1z/yCwDcnXCy5Mc8+Y
         wVWCxXb7MP12WY+ER4XnrMEPQUdJYKtBE7OTKJk0Dp4XV3t+nym4ceXg4uh72yBTCDk7
         ahsDPjpa3tI6Py19fzWxklgah+0n8QC2KsCQ2kL8OqHqSpidwuOmDs8wbzqwiZOP1MOC
         NIdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=UVTh0DJM;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IAMLOoJDLthkP3KBfb6Gxl4JpXaFkqlSec+UiO9j7EA=;
        b=qSZbG5mayYlbC8mvDNkA34MU82aSat3g9L7YwfSoKqt3Yh/bRTcH5fy5pMFUPnw6oV
         LsdypMAw6CwJNo3JhKiv9sPuMsK86YGEU7CpvFpNdJEGPF/7gtaceuGFysRhxuLPrw2m
         lFe4bLFlRQnjrwLwxQtfF7C5bXj6C45Yb4QuSA66seIA8J5rGeYP4FTi77i1cUAlKPqd
         M2VnDpUIVcZHy6deNEJ0EgujbgRd1XZRLkWtHEDmerNJttilNA+rkR50JQtKvSi7apKU
         t7xOYeldgmy2vi6bVG8g67wKC7vdeUC76LZEKLrGEFYyqStkwcCp5LTOOA5Ss1BdP4Gf
         NnDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IAMLOoJDLthkP3KBfb6Gxl4JpXaFkqlSec+UiO9j7EA=;
        b=quTX1I2v8YXWsDV3aoglEBMSjTdmLg9npazczIuF8EH+lgd1ibOiReifN/23yBkPp5
         0s8cQV+EXYIVLawJMglV4wCv9QFcl4mfNIqRao54qQ0TGAhx9WXczWwzy7D6FoRImH+p
         eGtmsy3qGzfrf/2QIQQgKlIoF+/vxUnyW6tyw5rhVoUJ3GFGZggXYBhDZAnZlR+9gRlz
         WwDEBSz6S3Ur2QJ2uNs3eqFrqBSObux1S5rFspzDkez0vzLql6hRZngUhOYgHOCceFKm
         GiPBnXI120LUG6WxQJrxlHxR25JckyBl7U/fDbkoosW17KZm16vRzeUS+kImjRnlurkk
         1W1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/ITFMOGi1ab8NmqWaUsOdl2mAHbA5iSMF7Dj/2Pr34Cz4IUyr
	YuXZf0ui09UKt6rp73Zah5c=
X-Google-Smtp-Source: ABdhPJwPJPG6HSQN/VBblmA/s66gpWLsDYZi+r0bOOvWJf3w17keiB/6pfikTVqyG7lF7O5ci/q1vQ==
X-Received: by 2002:a17:907:2486:: with SMTP id zg6mr3044384ejb.406.1622113053244;
        Thu, 27 May 2021 03:57:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:318b:: with SMTP id 11ls1344996ejy.2.gmail; Thu, 27
 May 2021 03:57:32 -0700 (PDT)
X-Received: by 2002:a17:906:3bca:: with SMTP id v10mr3119110ejf.121.1622113052407;
        Thu, 27 May 2021 03:57:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622113052; cv=none;
        d=google.com; s=arc-20160816;
        b=nHJWeEpMgJCt1IAcT9f5BUWRELBiUqdmUGJHhrKBdbmtbHDZy50wIL9kFTWAVTiJX/
         3mWCaDDpYAoaTbnM85UgQDB4IkIV/PFPWNm26muF4PHzRsai2Tlo/JozlLIuh1edyAjD
         4SHTHli0rcrwaL8ljjbEoTtxZEZvd57dWRt3ScOhAoY0DZJZk7AgBHqVkgrf/f3v31CF
         1g5nJ5Y9X1IvfsLSNXbQYkNwP7d2fg37JUabj9Vk1kcd6TPsqPbWfmskoDid0K7lGdu+
         2q7uKS86ttigGNQ53J+BLFC8EyMlNxb+1+tPsmEJzZ5fM20wOeUwKWwdc+L6SLxn/6os
         XLAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pYhSL9rZ5yWbPh3GEPzpn/Iur2XiYh2pZd2OnaDaVY8=;
        b=hyVgQTchXzb0ulkH07aF3c1E7BsjS+wc9GGPZf5O8QBvVW2SZ8q/rKYU/S3DxrmFq4
         TZU1sv4NFVtzHe/7AxX756W2b+iCeKIDogHVyDlH2sWH+hQ6CcRKKbVwky2wSny+Ilmo
         F/Wo6sQrANnZ6QaznizvYUfmW4gkCqapNS7HrzatABbp9+betZiqeVNuq45Ub53wkHnF
         hhMtRbpEJ8fjsIOeOYtEkbvPGEJueRtpi1Bwbf/5DkuMbGy9FK81EMiAUWHwvI4PeFDj
         WoI3MmK3Mvl8MV7SKF+hVQEn6NIjckRgGlHv8H0WEajFz4kLjPgTzK74kyNoVllKef+J
         yDRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=UVTh0DJM;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id cc21si117537edb.2.2021.05.27.03.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 May 2021 03:57:32 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lmDhX-005Rlg-15; Thu, 27 May 2021 10:57:20 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 68E1C30022C;
	Thu, 27 May 2021 12:57:17 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 42BBA2C80046A; Thu, 27 May 2021 12:57:17 +0200 (CEST)
Date: Thu, 27 May 2021 12:57:17 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: mingo@redhat.com, acme@kernel.org, mark.rutland@arm.com,
	alexander.shishkin@linux.intel.com, jolsa@redhat.com,
	namhyung@kernel.org, linux-perf-users@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	dvyukov@google.com,
	syzbot+142c9018f5962db69c7e@syzkaller.appspotmail.com
Subject: Re: [PATCH] perf: Fix data race between pin_count increment/decrement
Message-ID: <YK97DXkDbhH5BMdI@hirez.programming.kicks-ass.net>
References: <20210527104711.2671610-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210527104711.2671610-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=UVTh0DJM;
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

On Thu, May 27, 2021 at 12:47:11PM +0200, Marco Elver wrote:
> KCSAN reports a data race between increment and decrement of pin_count:
> 
>   write to 0xffff888237c2d4e0 of 4 bytes by task 15740 on cpu 1:
>    find_get_context		kernel/events/core.c:4617
>    __do_sys_perf_event_open	kernel/events/core.c:12097 [inline]
>    __se_sys_perf_event_open	kernel/events/core.c:11933
>    ...
>   read to 0xffff888237c2d4e0 of 4 bytes by task 15743 on cpu 0:
>    perf_unpin_context		kernel/events/core.c:1525 [inline]
>    __do_sys_perf_event_open	kernel/events/core.c:12328 [inline]
>    __se_sys_perf_event_open	kernel/events/core.c:11933
>    ...
> 
> Because neither read-modify-write here is atomic, this can lead to one of the
> operations being lost, resulting in an inconsistent pin_count. Fix it by adding
> the missing locking in the CPU-event case.
> 

Indeed so!

Fixes: fe4b04fa31a6 ("perf: Cure task_oncpu_function_call() races")

> Reported-by: syzbot+142c9018f5962db69c7e@syzkaller.appspotmail.com
> Signed-off-by: Marco Elver <elver@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YK97DXkDbhH5BMdI%40hirez.programming.kicks-ass.net.
