Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGOETCEQMGQEDIJ7OEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 3261C3F73D5
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 12:57:30 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id h14-20020a056000000e00b001575b00eb08sf1886090wrx.13
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 03:57:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629889050; cv=pass;
        d=google.com; s=arc-20160816;
        b=DnFKtuYpE+V7eIlpk8KiGCjjOxIKBxotdqCYHDm9aEtER4lEhdCFoirNzC6udmfEHm
         znd6lPSkiqOafDFSQvLvHFNgsZtuXAP7MwsB3AItxxt48Ku21YhnFdGKukDh2AFeYUmo
         pClwy/Mn9gnoYzBL3/OxWQTM06BVmjE5G/h9YdSx818VTL39KTDqJOtGHHbqpNDxJpIB
         TYs8qc1trsx1x5DHKl83/lxKOGOBLL3QSpQImio9zk7ikzw0ytjXCYLxMC+3MZqKwWm6
         nyfo1zpefbcZgz8XUWnqQCKb39cTgszyScVcPGVUGOquv131a+aWdF7OidxNIDdJP6vM
         u6mQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=VcmsdCsEqCmOH/5RODZeOUoUXADcljI3F75XZ1KcjsU=;
        b=xXCH6nUWukd1EVhbVffI6bVmsUuSrBvHZiRC/a/AADITQ8Gxpn4e5DTy4qkqgPyaU1
         VcO4ziWRV9cOQe84ATAJN3gAisFjJdwyRz8FNrQ4OajkK2eM+cWyy2P1ncPCXJUo4nwz
         llzPajRllRUrzLKdRjWxtifbBEoCvC821ZojR8AOvYY0FJ3TNR/6cPvGGEg3t33rD1o5
         WYLvqKPer5LN+N63E/4xPqOPuXft4ws+U/s0xnAr9OGQyA4EreLYAyHE3amNxWGehmG+
         TbfLqZGEOLMSi5OEAeukpzCWeQW4rA4ERwPHiRCIntyPRSW4+tZeZbQS4lFHTI0/Uuhn
         iLCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="CPnzfp/h";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=VcmsdCsEqCmOH/5RODZeOUoUXADcljI3F75XZ1KcjsU=;
        b=GiWVmrsOrXM0cPYf7kVPQP7OPVJXQgzDvERfNwsgi84F3TTU84r79ZmyWT/Bx2kWY1
         PoQwZFbTxHajzcnvZkQyf3TGoeCCp5ix1+AQFlDZLWaBfAzcJUML9QP1rFJvpKQbKgdR
         IvyX86YSSvv41LQ16SB8MgmlMCAwcSpoh17txLSRpih8iUGK5K2JQOXvuGqubq09468F
         rSKdAQ+8+0C5f8CzyYm9BmY08TJzoJkbQNsxVyRW3jZOaBsrcixK+yocRXhk6pbcMpK9
         5RTDdQz9+0d8cxrF1LY9U7mE1TIVfiK0LeXMenBS3PAt0Qt1rfqaHZ2rSvYj6wNeVd1W
         nfWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VcmsdCsEqCmOH/5RODZeOUoUXADcljI3F75XZ1KcjsU=;
        b=t3t3FX87Nmk8pTq4O2Ev+d6lgUBNz7J9kD/B2RYnwO1HqJOly+x+s9uZ3I9EWyVPoZ
         HiveqA6OuAbqpsSfesmnL/caW6gbUkdIoWRNzRIz5ZidjiHhNf9gBai6S+VS8HbOHuhR
         P8zS4xsSTjMtOo5zO06REbrkJH7tc7lnKAEykvJd6ovsmwqdAwSfzMqS+eLwaE/2dF20
         BPxZ/KT/Oinmpv5qqOA64QfElsHLYZYK2WGCrpp5wuHVbRQhe9dX6yyxtihLDB/sV+wV
         rkqsYSCL1WiORCR+lZ/8rXZUuKohV+KAEz/xDobBTAWBq7744k+E5jQvQe4i2VsmsZRc
         hosA==
X-Gm-Message-State: AOAM533Gdm6O9hiZe4Hbxyr+2ad14Cbnis0oI2vaB+u9EuHga6ODZNHX
	ZUqqB2zbrvx89V9GBPif/Ww=
X-Google-Smtp-Source: ABdhPJwJjW5HSDpzCd2ntFwUcRNGh+6iwG7au0LlqMyzcXa2e5Q4K09z8TdJIK/j7IDS1hIiVlK3Hg==
X-Received: by 2002:a1c:e919:: with SMTP id q25mr8974871wmc.28.1629889049977;
        Wed, 25 Aug 2021 03:57:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6251:: with SMTP id m17ls2312457wrv.1.gmail; Wed, 25 Aug
 2021 03:57:29 -0700 (PDT)
X-Received: by 2002:a05:6000:9:: with SMTP id h9mr25350750wrx.396.1629889049070;
        Wed, 25 Aug 2021 03:57:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629889049; cv=none;
        d=google.com; s=arc-20160816;
        b=RkXa36dAwOVkrtYqb6g/xIujkcy1PZlbKjtSZnbvVovsDQIQaFpIY9RPS0TcjO858L
         WVc8/7pXXPjrnQDgGYzDWVVDvMUaivfoSuOwJTMbPnDkgxZhAVKAxwjTjQUbasyJlppD
         AO12tChjakHZ0p2pdl83+X7zuNr44QJi7f4Osb8D3cGfzjfDkY++uMGpQKyBMI47BjMi
         sBRq3gN8wQ/r6dp/OdjPd6M/TJ78GuwgK9ax3gJ8c6yeHT5gJxfHUc0IaJiFGbtCFmFs
         wyrZ6mp+lMoshCXjB1a+/LNFO6p57H7gQbvZLGffFU1O5peHEQ4Bd/au7aAnMFLDGXYb
         ZC8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QtpP3tcoZvxE8r2Ab9yioe6Y4u6iLyGn82K3C5J43jA=;
        b=OSJwRxfpP+EqBX3hy0xTy2TUngrIQMgQyUPQXPo8lM+PNXQAMLe2En55ZGQG1/Ae91
         5Xi2DE/ppbXFYIzojjaWqBWwy9ku5P2Y0OIf6dOwzkTjp24ui4PnJ4wj7WJpgCt+IeDN
         ahPIwoXtQWmPx/jfrKWa1aISHiAuvgsrNDeP5n5b8aAsGs749tKBz7S0OH3wD/Pl2LhQ
         8pE/SDTdX8HbaJKGkc0fFYaU+m3z2Ge0uEU6CnzBbET1iq8Ktn+S9RPjh++dfJip9l9Y
         glyIHy17Zq1IuEgb3MpRaPBUexvaj+fMY6IJLR97TKdjV0Pddy7/kMImTYA5zHmyDEXj
         rrdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="CPnzfp/h";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id g17si168541wmq.4.2021.08.25.03.57.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Aug 2021 03:57:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id k20-20020a05600c0b5400b002e87ad6956eso2608716wmr.1
        for <kasan-dev@googlegroups.com>; Wed, 25 Aug 2021 03:57:29 -0700 (PDT)
X-Received: by 2002:a05:600c:4fc6:: with SMTP id o6mr8926193wmq.122.1629889048587;
        Wed, 25 Aug 2021 03:57:28 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:2fcd:1452:4b71:155d])
        by smtp.gmail.com with ESMTPSA id d7sm21305866wrs.39.2021.08.25.03.57.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Aug 2021 03:57:27 -0700 (PDT)
Date: Wed, 25 Aug 2021 12:57:22 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Russell King <linux@armlinux.org.uk>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH 0/4] ARM: Support KFENCE feature
Message-ID: <YSYiEgEcW1Ln3+9P@elver.google.com>
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
 <CANpmjNMnU5P9xsDhgeBKQR7Tg-3cHPkMNx7906yYwEAj85sNWg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMnU5P9xsDhgeBKQR7Tg-3cHPkMNx7906yYwEAj85sNWg@mail.gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="CPnzfp/h";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as
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

On Wed, Aug 25, 2021 at 12:14PM +0200, Marco Elver wrote:
> On Wed, 25 Aug 2021 at 11:17, Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
> > The patch 1~3 is to support KFENCE feature on ARM.
> >
> > NOTE:
> > The context of patch2/3 changes in arch/arm/mm/fault.c is based on link[1],
> > which make some refactor and cleanup about page fault.
> >
> > kfence_test is not useful when kfence is not enabled, skip kfence test
> > when kfence not enabled in patch4.
> >
> > I tested the kfence_test on ARM QEMU with or without ARM_LPAE and all passed.
> 
> Thank you for enabling KFENCE on ARM -- I'll leave arch-code review to
> an ARM maintainer.
> 
> However, as said on the patch, please drop the change to the
> kfence_test and associated changes. This is working as intended; while
> you claim that it takes a long time to run when disabled, when running
> manually you just should not run it when disabled. There are CI
> systems that rely on the KUnit test output and the fact that the
> various test cases say "not ok" etc. Changing that would mean such CI
> systems would no longer fail if KFENCE was accidentally disabled (once
> KFENCE is enabled on various CI, which we'd like to do at some point).
> There are ways to fail the test faster, but they all complicate the
> test for no good reason. (And the addition of a new exported function
> that is essentially useless.)

I spoke too soon -- we export __kfence_pool, and that's good enough to
fail the test fast if KFENCE was disabled at boot:

	https://lkml.kernel.org/r/20210825105533.1247922-1-elver@google.com

will do the trick. So please drop your patch 4/4 here.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YSYiEgEcW1Ln3%2B9P%40elver.google.com.
