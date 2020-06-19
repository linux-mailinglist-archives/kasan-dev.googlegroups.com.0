Return-Path: <kasan-dev+bncBC7OBJGL2MHBB37RWL3QKGQEVG27EFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id D0C8A20098E
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 15:09:03 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id a3sf1371703ljp.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 06:09:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592572143; cv=pass;
        d=google.com; s=arc-20160816;
        b=aLPYz9GIv2IkisxFr00oN42zueYwILzUHdsh+Ib9osMcvEfjEM+wpfqva4wKSVZh73
         4BoUDIuykEvxCjk77EgWMxrUusUBxk5+7VweRMDbX5kaeNPIxORApllLW+g+gNaiQE9+
         APh/O7O7KtSKBM1OBOZqtYmYOXtfP5CTdiX2OPfmzuHkBaGp1zVI3/MTilhCvUfaeG7l
         v29FaUqpF1cYuJcI+ty36yZ2iRn7jELk1YriP7qTiGK9BmNuYouW17qfUFpmC8aDgVcE
         qGGdBKNkgrdAF2LD1mfXtdFgmCob+yGh54z9F+645VQk9kgwUSouqT0o20h9kf9mgafH
         uEPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=izbx6Q3zGICK6yuuXSlMtQ7F/cyJQchxCxRu9BHxdmY=;
        b=T/zD+fIHBw6sE/lLr941ereftSB5ZpXnajovCeTZAk5yoImnBmN/Qel5uD2DWupt1o
         IBtN3VewE7KrVJqAXQg0VDLwuaMQB6T6bWvaKSJH9a9HZLFcJpb99+s9bKSXhrozHNxb
         Jkhc4brNCRfol/e2Ivbbq3VXNxosAqcQCVxFdaDr7UY9Mn96WQq3y3IODQ7IoRXkDcbN
         zDV3OWIkNhudJHdzJvcIWHd9Fs0DD7petf/JEX3nAXxgtMCtd5CStUxkaX9YK7mRwIBv
         uXaVMBc/26jV1GtsRkMgjPQUWHb+aaY1k9v/XUAanp4G2gHY+opnSTv/+ei58iiThC0J
         PmIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s51VJ2AJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=izbx6Q3zGICK6yuuXSlMtQ7F/cyJQchxCxRu9BHxdmY=;
        b=MCMcRPj0/W3rPDGFlq0yOoGnZ+Bz6ZtFPXb249fZGT/5crU5CZjnYBa8IBokDHEA+1
         amVkDZOEGmc4iovqiYQ8zOAGV6QqR0Qd/QojauJegC4zKC865WW1Q01ioxdTt4r0B/vT
         Sq6v9NKInhR6CLooZOnXJO1tQibHEQ63/bM+o639PLRm65bHu6qyfvwEtUa3vy+ZXqiD
         rL0GMy9qI5jtbaqYBHR/nB4XMsWLxhZpMUPNdR53jGLsrMKpVG912reLka5Sl5oseqr+
         cPVF213gOvwmWagFkUupMfZIAOPe/+6GX94LDzSEQizGrki+ASpmmUVCU2BRmFRruJNC
         m87A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=izbx6Q3zGICK6yuuXSlMtQ7F/cyJQchxCxRu9BHxdmY=;
        b=T3iHdhpp4IAIk/5kNbcQhIypRbU0kbTmRrHJ4FQRkGXgs1dHi6EKhdILgnYDeFNTgd
         /5/wXebplr3pNikm1qmXDcAueqvPiyEhz8/XdqV2HSb9lvsqbloe2gkq8Zd/HKArMFRo
         azGoZiPbZ9FjsUZSeK00hlVpSAOInWJJ+WqzlPHFI6ulOEpDo0+3FY1txU1bLmQvbTsI
         MHf89TiLrauoXrrlLgTxdjDJsrGjHVKxi1XlMu7x/Sl0VSc1glzRKMdqLrZidLqdh42o
         b1YhTgi9leXImIuXpxcdOi0iIclrqf5AM1Ajj71/uqZrreU3qt/+IrxCT2gDrbV28V7Q
         xROQ==
X-Gm-Message-State: AOAM532J/GTeJAN9nu70WIn3n+GM47yXtzgt4ALjebB1jiXYLyYmzVJm
	6Lx06faXANiy5o1D79c6JI0=
X-Google-Smtp-Source: ABdhPJzw7Nf98hyqf+Z4gbyLQlLZxRile7e2w6XlXYFaczJBXlV4oHb0vdPHwE948+MUzHaE1oRxtA==
X-Received: by 2002:a2e:b0c2:: with SMTP id g2mr1962110ljl.241.1592572143385;
        Fri, 19 Jun 2020 06:09:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b61c:: with SMTP id r28ls1988473ljn.5.gmail; Fri, 19 Jun
 2020 06:09:02 -0700 (PDT)
X-Received: by 2002:a2e:9cd2:: with SMTP id g18mr1983733ljj.81.1592572142145;
        Fri, 19 Jun 2020 06:09:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592572142; cv=none;
        d=google.com; s=arc-20160816;
        b=eGonv27/vJhxRYYIeSNFLDYXRZdZpaWa4xcwzusvmwL/F79EoDL8i2gGb4Xy/tZ1No
         wPh3TBx/NksxvVupkWF25L2yf/8DX/NSHLpwnxT4F2SFJ4IUCUz/8Yf1kXi7k/RzvA6/
         3btC+36dHe1ZoeXD5aYxxaLbd0OjtAMgfGbHFrlQ/BoGVCWXQpQgKuijUeyqfex5YMDw
         DRJGlFPjQISA4aXY3vyWRhvcvH3Wzb+PG1k/CcFju+k+VlFiseRcMRxfCDYOR0/reANB
         +W78H+L9zfAFKwnPuzETMvSkmr6cjTcWjNfQs5DEbDzSsHEbnxAlSKp4tirLsriYjsqu
         4sKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=hkaiyEZZJRb5o68eRM8OXrKVJpHe/SaB4GyhmokAbLc=;
        b=MarCFRTR1EKe4+XHdhUSIHn5fDQ0+EYE9CSc5vHeRogpJvHeky0ytsWCLny06bYB50
         JAO983uCQKP5MUwDXfmijTQIALhNBTQuULMTYK9JGWS+aVjUxrArb/9fXZtL8iIonbEU
         3yhkMciC+9L1zjVgn2sgPnOHYhie1mjVgPNyV2QfCjMDxNR+fhtAHwGupQqMo0IwBOUx
         BoNbv8BGK+VGnrSYzlCBbbpLxWfK0sq/XvxVpbghsjW2mvIkibsVABx92RzN6y37/3ew
         f0G3Y4+nKyJj9wp9uY2+YVRYeeBAVrNcr2Fegp7DIKWA/PqcgCk5xFPtbB2se+Q0h5gl
         UkcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s51VJ2AJ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id i17si419900ljj.5.2020.06.19.06.09.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Jun 2020 06:09:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id l26so8377131wme.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Jun 2020 06:09:02 -0700 (PDT)
X-Received: by 2002:a7b:ce1a:: with SMTP id m26mr1738337wmc.166.1592572141387;
        Fri, 19 Jun 2020 06:09:01 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id f9sm7099710wre.65.2020.06.19.06.08.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Jun 2020 06:09:00 -0700 (PDT)
Date: Fri, 19 Jun 2020 15:08:54 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Oleg Nesterov <oleg@redhat.com>
Cc: Christian Brauner <christian.brauner@ubuntu.com>,
	Weilong Chen <chenweilong@huawei.com>, akpm@linux-foundation.org,
	mm-commits@vger.kernel.org, tglx@linutronix.de, paulmck@kernel.org,
	lizefan@huawei.com, cai@lca.pw, will@kernel.org, dvyukov@google.com,
	kasan-dev@googlegroups.com
Subject: Re: + kernel-forkc-annotate-data-races-for-copy_process.patch added
 to -mm tree
Message-ID: <20200619130854.GC222848@elver.google.com>
References: <20200618011657.hCkkO%akpm@linux-foundation.org>
 <20200618081736.4uvvc3lrvaoigt3w@wittgenstein>
 <20200618082632.c2diaradzdo2val2@wittgenstein>
 <263d23f1-fe38-8cb4-71ee-62a6a189b095@huawei.com>
 <9BFEC318-05AE-40E1-8A1F-215A9F78EDC2@ubuntu.com>
 <20200618121545.GA61498@elver.google.com>
 <20200618165035.wpu7n7bud7rwczyt@wittgenstein>
 <20200619112006.GB222848@elver.google.com>
 <20200619123552.GA29636@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200619123552.GA29636@redhat.com>
User-Agent: Mutt/1.13.2 (2019-12-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s51VJ2AJ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
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

On Fri, Jun 19, 2020 at 02:35PM +0200, Oleg Nesterov wrote:
> On 06/19, Marco Elver wrote:
> >
> > For the change here, I would almost say 'data_race(nr_threads)' is
> > adequate, because it seems to be a best-effort check as suggested by the
> > comment above it. All other accesses are under the lock, and if they
> > weren't KCSAN would tell you.
> 
> 	if (data_race(nr_threads) >= max_threads)
> 
> or
> 	if (data_race(nr_threads) >= data_race(max_threads))
> 
> or
> 	if (data_race(nr_threads >= max_threads))
> 
> ?

data_race() is a catch-all, and takes any expression. So all of them
work. If both nr_threads and max_threads can be modified concurrently,
your 3rd one is cleaner; if only nr_threads can be modified
concurrently, it'll be the 1st one. In general, the one with the least
amount of code wrapped and least amount of data_race() added is the one
that should pass code-review.

> > In an ideal world we end up eliminating all unintentional data races by
> > marking (whether it be *ONCE, data_race, atomic, etc.) because it makes
> > the code more readable and the tools then know what the intent is.
> 
> Well, to me READ_ONCE/etc quite often looks confusing. because sometimes
> it is not clear if it is actually needed for correctness, or it was added
> "just in case", or it should make some tool happy.

If there is real concurrency, it'd err on the side that it's probably
needed. But yes, if there is no concurrency, there should be no ONCE.

Also, if you remove all ONCE, run a stress-test with KCSAN, KCSAN will
quickly tell you which ones were needed and which ones likely weren't
(but of course that also depends on the test cases you run).

> And I can't resist... copy_process() checks "processes < RLIMIT_NPROC" few
> lines above and this check is equally racy, but since it uses atomic_read()
> everything looks fine.

It's racy, but not a data race.

> Just in case, I am not trying to blame KCSAN, not at all. And yes,
> atomic_read() at least makes it clear that a concurrent update is possible.

The use of a marked operation (here atomic_*) means the compiler and
architecture know about your intent that this is used concurrently, and
consequently will not mess up your code.

Whether or not the concurrency design is free from logic bugs, is
another question.

Without help KCSAN is just a data-race detector; but you can also
recruit it to help you find other bugs: for things where bugs won't
manifest as data races, but e.g. an atomic_set(&var, ..) is not meant to
race with other atomic_sets -- but concurrent atomic_reads are permitted
-- you can use ASSERT_EXCLUSIVE_WRITER(var) together with the
atomic_set. We also have an example like this here:
https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html#c.ASSERT_EXCLUSIVE_WRITER

Also discussed in more detail in: "Taking KCSAN beyond LKMM" in
https://lwn.net/Articles/816854/ [ For the RCU-specific examples there,
I would have to refer to Paul. :-) ]

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200619130854.GC222848%40elver.google.com.
