Return-Path: <kasan-dev+bncBCO4HLFLUAOBBOXMYH3QKGQEDOUKVMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id BAF04203307
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 11:13:30 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id u15sf6582923wmm.5
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 02:13:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592817210; cv=pass;
        d=google.com; s=arc-20160816;
        b=tDxJ696zrQnB9wgEOh3EJspeqJ3lgIqKW/t/OnAUtvc6mVkRmW5cKkDK/NILHTgSh2
         rxcAhDf8YkzdOSiP85zpML8uqm+xP1P9c33prhQfH3O/YyHex7lf217Gdy9fsURGWxbh
         myPwvjt+CM18KALr36gBFeY1xNjwxh8nVYdMkc/Swx01zRZq7ehp6JxypCGrfjmHHbjE
         vpUNU4soK7M7yxW0ubAiEPQ1ez/Xk1FbyOlr8qdKrbcV8p3TigG6KBLJdtT6IWTXtTks
         GMx5nyHXAPecMFF5/N/cgI/ePWVXqvFOL/uD93QIF2mt/dBJoNIySY0H6PE5BZ9esIJx
         NDig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=L3l9vBWKcBQjJSXzWRUUZjiKOorG44PEWhCqqnge1JQ=;
        b=D5s54wuFjnwCuwumi8obaNrqAeIqAXg0CYHZuGbSH5fxyYY7fUiXWRUycyiLe+csCH
         3IkSgODJEoXczKx6SAtJ0UIEKq7f9+vPnIENsrHRG1N60iGS91QKURM94OLk63Iy1rwH
         jc3MiX8F4aBHC130D3QKASpJYqC09PcRPrfY3pQrZcYIijL3opnIsXgPaADd3EGcsgCa
         uK38xGxjFxlVrRnEBSt6Of14LBOdiwxD7IB9+pEEpAzLyzXDGca660zd8p6lFQyUzBhW
         myWJ0aGDCUftd6XC+bCq3aZb3w5lOY8aO8b2xU2fGCkNdBR/vZibIO4pdnm4LiCYukFr
         diqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 91.189.89.112 is neither permitted nor denied by best guess record for domain of christian.brauner@ubuntu.com) smtp.mailfrom=christian.brauner@ubuntu.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=L3l9vBWKcBQjJSXzWRUUZjiKOorG44PEWhCqqnge1JQ=;
        b=ZnOowHVFm7x1117/rmp67RJ+IpRnwfrGGM6dnADFnNUfded30J6cyJubr3QXUKCgj/
         yj0XONydN5Rj7nuDwsPmkGIUPPGaB+K/pkUCrz5rXbIa7rnmYiuasjGTfB0lq3Inp/Dx
         IQAAv1BEdXN/dlobEuLvz5PPDx0RAoNIPpFP0TiA+66WDMr3j5XL7U7lb/SwH1M6ygy+
         9PSHvsue27rfk+OgX8QLVnndBhTYhqdcA/DibjNemVfi3FOmMhigE2vSWtlvPnpm+hH3
         wLJIxrp5OWrbCFjMffWN1MiH8ua+B1WuqEKRV9NNvlzxVtr+XVruttlg2KHI+xYVI+ZA
         Y/3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=L3l9vBWKcBQjJSXzWRUUZjiKOorG44PEWhCqqnge1JQ=;
        b=QRpYhKHXAARk4Zzgq2rilRk/YGr8mMIkxilYCvBGa1+uvZJyU5Vmgl1BeM4BOybWuy
         VniIlFarV4iNz2P+Iqb/rFKbkDSyO/rKTI0NjDyZiFc+1a48ssCYFvz8oQiOq0woD/th
         mq1Iv+Ab9H8DPAu4ZS0SHP6Kjbl8Gh54O5KKNMdqZhKMfaZkSoG8d/X9NWJ2IEflXRE1
         1Sq8QBKfmYhmZTyb4tm35r1ovTCR675186y7l3Lsr0zeZ6EWNjHfvGYlJjgWkWQ5/jpu
         yIdbD7+mZctkM7WaZ6uL6LtUu4HdZ0GcaGYdo2i8dfUf4Kab9XxiXPOE6afGMAlwjthH
         8FPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/9htnF9eqviohdlyDMAzFMzBXYRcNiKKttRCOmGxlLUv1HnUr
	aSlRaKlBsvz4Mc1BFVqgEdA=
X-Google-Smtp-Source: ABdhPJx13L731Nv6Bus8rTCo/xFBHfIxirKHJoLrVLn++/s2+6PPhtFAwil6EKk8oO+LT8LGgS6Kag==
X-Received: by 2002:adf:aad7:: with SMTP id i23mr18049645wrc.331.1592817210491;
        Mon, 22 Jun 2020 02:13:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:82ca:: with SMTP id 68ls4414895wrc.2.gmail; Mon, 22 Jun
 2020 02:13:30 -0700 (PDT)
X-Received: by 2002:adf:e6c8:: with SMTP id y8mr19094318wrm.40.1592817209996;
        Mon, 22 Jun 2020 02:13:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592817209; cv=none;
        d=google.com; s=arc-20160816;
        b=pObrT+KKxNY8FVIu8HixMY9UExSQpToRV35u/sXDlm2p40lb2kUTMNovOKo4ua7vXZ
         hV86bt4GDU+sBQocsgHzLOvLloVB2NEFlMzBEMZR/twz1V7RtPx4f/75KIAMJPu1xSi5
         DHaMBQWcrY5SVhEWT3e57JBJFtjekANQVjqN7CDm/bALbWdjv6ASJR1uqyZveuxVqxSi
         9bBHivxXL0gGqnbhtOuUQXNb3oerF1IKfehM1J98hX1C8ufTumROYBbY2AG7RWNZI7uO
         0oDWOwG7vBQD+UJbSfqvteACB6P1pW2T1Grph+XGlSwbwgr5deu2TVbD+ttaVmp9GYjX
         g4yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=iPlqAmgLbti2vUc3mUqTEh6T5ZCeMaRUHyLmSpVPJfI=;
        b=hbgP4+Jbbb8um4n+lwcnVVBfqa4tHBlSDUr/YjA9WqQyGN4oPMX1PySauRJiOpgYB9
         w3RRq8fz6oRpVsZwvcnjX3lY3ldGeNcNxYoMK800aBLVt7kSof6bhQ835RW9rbQSbh8c
         8cbKonUX5CdGBpOmYe4raXfOquapQF3BmUeFtsOJed8pyeuCeiLlgceTDBUUs2oygVnM
         lM/DI6wFaDKOSm3/QlBoEHrZ1vjY2u3q4BeedZZNUBtCLgkgafXRaBE3rAnNpgrmh0Uo
         UZQ85TJCNuUhU4rLJ+MRD4SC5Mfks/G8Gn0me9qrcLG7aAhl+iHRZGlfxdlSs9MjviJM
         hTOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 91.189.89.112 is neither permitted nor denied by best guess record for domain of christian.brauner@ubuntu.com) smtp.mailfrom=christian.brauner@ubuntu.com
Received: from youngberry.canonical.com (youngberry.canonical.com. [91.189.89.112])
        by gmr-mx.google.com with ESMTPS id b6si478009wrj.2.2020.06.22.02.13.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 02:13:29 -0700 (PDT)
Received-SPF: neutral (google.com: 91.189.89.112 is neither permitted nor denied by best guess record for domain of christian.brauner@ubuntu.com) client-ip=91.189.89.112;
Received: from ip5f5af08c.dynamic.kabel-deutschland.de ([95.90.240.140] helo=wittgenstein)
	by youngberry.canonical.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.86_2)
	(envelope-from <christian.brauner@ubuntu.com>)
	id 1jnIW1-000839-PU; Mon, 22 Jun 2020 09:13:21 +0000
Date: Mon, 22 Jun 2020 11:13:20 +0200
From: Christian Brauner <christian.brauner@ubuntu.com>
To: Marco Elver <elver@google.com>
Cc: Oleg Nesterov <oleg@redhat.com>, Weilong Chen <chenweilong@huawei.com>,
	akpm@linux-foundation.org, mm-commits@vger.kernel.org,
	tglx@linutronix.de, paulmck@kernel.org, lizefan@huawei.com,
	cai@lca.pw, will@kernel.org, dvyukov@google.com,
	kasan-dev@googlegroups.com
Subject: Re: + kernel-forkc-annotate-data-races-for-copy_process.patch added
 to -mm tree
Message-ID: <20200622091320.iabedb7uksdipjkt@wittgenstein>
References: <20200618011657.hCkkO%akpm@linux-foundation.org>
 <20200618081736.4uvvc3lrvaoigt3w@wittgenstein>
 <20200618082632.c2diaradzdo2val2@wittgenstein>
 <263d23f1-fe38-8cb4-71ee-62a6a189b095@huawei.com>
 <9BFEC318-05AE-40E1-8A1F-215A9F78EDC2@ubuntu.com>
 <20200618121545.GA61498@elver.google.com>
 <20200618165035.wpu7n7bud7rwczyt@wittgenstein>
 <20200619112006.GB222848@elver.google.com>
 <20200619123552.GA29636@redhat.com>
 <20200619130854.GC222848@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200619130854.GC222848@elver.google.com>
X-Original-Sender: christian.brauner@ubuntu.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 91.189.89.112 is neither permitted nor denied by best guess
 record for domain of christian.brauner@ubuntu.com) smtp.mailfrom=christian.brauner@ubuntu.com
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

On Fri, Jun 19, 2020 at 03:08:54PM +0200, Marco Elver wrote:
> On Fri, Jun 19, 2020 at 02:35PM +0200, Oleg Nesterov wrote:
> > On 06/19, Marco Elver wrote:
> > >
> > > For the change here, I would almost say 'data_race(nr_threads)' is
> > > adequate, because it seems to be a best-effort check as suggested by the
> > > comment above it. All other accesses are under the lock, and if they
> > > weren't KCSAN would tell you.
> > 
> > 	if (data_race(nr_threads) >= max_threads)
> > 
> > or
> > 	if (data_race(nr_threads) >= data_race(max_threads))
> > 
> > or
> > 	if (data_race(nr_threads >= max_threads))
> > 
> > ?
> 
> data_race() is a catch-all, and takes any expression. So all of them
> work. If both nr_threads and max_threads can be modified concurrently,
> your 3rd one is cleaner; if only nr_threads can be modified
> concurrently, it'll be the 1st one. In general, the one with the least
> amount of code wrapped and least amount of data_race() added is the one
> that should pass code-review.

max_threads is a sysctl so can be modified concurrently while being read if
I'm not mistaken so probably:
if (data_race(nr_threads >= max_threads))

> 
> > > In an ideal world we end up eliminating all unintentional data races by
> > > marking (whether it be *ONCE, data_race, atomic, etc.) because it makes
> > > the code more readable and the tools then know what the intent is.
> > 
> > Well, to me READ_ONCE/etc quite often looks confusing. because sometimes
> > it is not clear if it is actually needed for correctness, or it was added
> > "just in case", or it should make some tool happy.
> 
> If there is real concurrency, it'd err on the side that it's probably
> needed. But yes, if there is no concurrency, there should be no ONCE.
> 
> Also, if you remove all ONCE, run a stress-test with KCSAN, KCSAN will
> quickly tell you which ones were needed and which ones likely weren't
> (but of course that also depends on the test cases you run).
> 
> > And I can't resist... copy_process() checks "processes < RLIMIT_NPROC" few
> > lines above and this check is equally racy, but since it uses atomic_read()
> > everything looks fine.
> 
> It's racy, but not a data race.
> 
> > Just in case, I am not trying to blame KCSAN, not at all. And yes,
> > atomic_read() at least makes it clear that a concurrent update is possible.
> 
> The use of a marked operation (here atomic_*) means the compiler and
> architecture know about your intent that this is used concurrently, and
> consequently will not mess up your code.
> 
> Whether or not the concurrency design is free from logic bugs, is
> another question.
> 
> Without help KCSAN is just a data-race detector; but you can also
> recruit it to help you find other bugs: for things where bugs won't
> manifest as data races, but e.g. an atomic_set(&var, ..) is not meant to
> race with other atomic_sets -- but concurrent atomic_reads are permitted
> -- you can use ASSERT_EXCLUSIVE_WRITER(var) together with the
> atomic_set. We also have an example like this here:
> https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html#c.ASSERT_EXCLUSIVE_WRITER
> 
> Also discussed in more detail in: "Taking KCSAN beyond LKMM" in
> https://lwn.net/Articles/816854/ [ For the RCU-specific examples there,
> I would have to refer to Paul. :-) ]
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200622091320.iabedb7uksdipjkt%40wittgenstein.
