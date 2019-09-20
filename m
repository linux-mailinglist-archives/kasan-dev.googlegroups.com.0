Return-Path: <kasan-dev+bncBDV37XP3XYDRBZH5SPWAKGQECJZFELA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A37FB95AE
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 18:31:32 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id m14sf2475302wru.17
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 09:31:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568997092; cv=pass;
        d=google.com; s=arc-20160816;
        b=GQ2ecMfRCdPUYejskG8JnMs3myTMe68gEe4bdqjPR0p5/b+mAS0c4EJ2hbP0wpWPW9
         RBPhekdsjpUNmWoEwDx7wgCS10OEDRFe0ckf0jVTUAM6C89vU1tQsm2nc1SaKYHrYDRQ
         Ikl5mfvkr8lHnqPbgt37CkZqziDoqtQUqh36EMKEIAD9JZHZ6z/k6SffCe5JqOGAoD8b
         X1ibq4e5i1fvgQtajz82nw71UdigBeEWTg2RLbGozv/pFcbTkbtHbGzlWiq7PvNgr0Xn
         n6CQKh6mJSjtTJ5Vb4jciZ8r4rVAkbX4QwN7KNGsVgFcrSOe+oYJM2j1rPqyv/kygjrp
         N0kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=0x4kEjN26fsvC6XC0V53QoYYBJjBDSt8gW+POMUMYiI=;
        b=O86/KY/HdBTIr7jV7XVyGH7IpVfrbPgdOQDWaglXZ6xcKtvuG2n0Mrfj/rwUqKs3JL
         NE7vObrP8x70EazMXjG/1gAFTQNhbVHzMUrwTT5zgyHHqyITtJUMrHhzzj19P166wDRS
         KLcJSHNSIgjFBA/RU71augV1dgpB7eXV4K+tSxxsuYBrFHPcXrCP2ue4qZLRfG0im7WC
         22m8whMLtoyEUYj+s9Fg2MVWs+Zpu675pHbkOAlWeKbE8z3eASG3JucZEN8YwJSkTc21
         crTnDf5T1exKS/8paC22DBT7CK9PJxu8UfauqW481vLy19ocQLnIrqZKG2HePGz4dbSq
         Y8Zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0x4kEjN26fsvC6XC0V53QoYYBJjBDSt8gW+POMUMYiI=;
        b=PFtYj1EQ9yaEXqLCvzTyvwRpKYITwZ7YA7FrjF3xfJDyV129EZWO2qGJlu2tzkByZ2
         rwyRHyN8OKVG0dA1r62/J+9OeV/DpjeX+pId3lvWzNBzEcg9nK1ANuIEncI5m/JiGG5j
         rQu0OinbDvDkur4OLX5DvZinsAe8Fr/3ycARBPDVFWzkEusdZsdM5BRmSJ9ZodYQzRVO
         9gliVeDM5f8FNP/kdWxd12MbLNGvNbmiuPECg9t6CZmkR/BbV+DOL8CrwUGD8dd0ssyG
         a5Nybw24otah8zEH2wvHl3j4Jd+XQ98AH2nN3y8QQs7Fvne0iIpwANAPadLleHdFsNYX
         sHPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0x4kEjN26fsvC6XC0V53QoYYBJjBDSt8gW+POMUMYiI=;
        b=uF7IBtyKEN1hwTVy7Wf+gnSR2+HZGt58EEOhPmyk6NerfVExiHoRKpzGiSRb2pLt+s
         Z50Lrw2svTk79NY4oRh0poFmlbNRhlFLsFp+ek0MdxuJwh8H1MFqvK4eHcvubiuS+z94
         mNtsA2AU/cutF95zH6YqXVLMWzDdbdFxu5mAClL06xEXJ033GG2KMDywEnohJ7Y8K4Vn
         moxQlsu47rbffQCnyWHm2BlAZTcP6jYbI++fCRt0AttMD8cEOZ52AGCHt2IE20aV4kX5
         Q9lkieJJB4t/6JW4HXEqRygOgERXVb3eDo+gp8oyklObV56i5n3irppMWV3i+a0SskEV
         FLRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXO3ng4+PStjod8IdQHiFa/b28ATUnDzlxd1PtyLbhfQZE4K1/P
	HXTatFvGvQHk5CoX5MbnU0I=
X-Google-Smtp-Source: APXvYqyQKiDtHj207OSS6A3qpO2n2Xz4IEASMesCWEN3Wwla5Vnwj/YXF3IViJpHZvWsI9GG4IbUeQ==
X-Received: by 2002:a1c:b745:: with SMTP id h66mr4056662wmf.70.1568997092169;
        Fri, 20 Sep 2019 09:31:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:b1ca:: with SMTP id r10ls2050443wra.6.gmail; Fri, 20 Sep
 2019 09:31:31 -0700 (PDT)
X-Received: by 2002:a5d:4f11:: with SMTP id c17mr12808233wru.227.1568997091568;
        Fri, 20 Sep 2019 09:31:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568997091; cv=none;
        d=google.com; s=arc-20160816;
        b=X5fb5SV72Z4/jYW60XEFIcX5AlfMXychklxwNaVzYuaUpzp9vDVpKZWYL2UZ5Q6sKY
         9u56Xwl4V8CNDmVjKMRUe6TnMq0m0o0we7ZYJf4p0AqOD0qlHV5ew7QpSvwwswQSMG/O
         KSe3+CTdl+txw71SKgxHBTrzK9onemZySyZVjmwLttXnP8D+9oVSZwFt9cbN9YpUGkP1
         AxJJ+eSac8IiiOK79rVKuJZqnQ9MPiG7v49rsIpx7cXjyf2DDMGLfm8Ai+nSH5KCYZeH
         OKbLf8Pa3L56ZquvqbtucYNdcZNrU2TdT391BaHq8u8DlDkW9Mt7mWPBBKorNU2UxkPq
         bJQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=s3unpMgOm3xIrUPGVdKeRbnRcKEIImFSUY0v31tSpJ4=;
        b=GoFiN3230SafLnZyR1A6pwJyGxNbyiatYYZK6UxUpJog9/8sPTVjQfNd4kQPf/H1sY
         RLI8/pvJDmSY0iqOzAGhPV9II9Mtlt7UzMlRKoVAum6bPBbDtZ0lvJbrXk55E7cNABde
         YQIJ0S0oYU/t80dkBF/S5T2GHGhqrK4ot+reROX2pm3qlGrD91Y5PHPaftS2qVsOvcjR
         8lpnTJyMJJsT9HjE6hDB/MMPLhGHTFIkW1ECCzAcjFhWLHBmtOcCgur8P5NFrNeQIO1i
         nN00zVZjnXmCaldC/J/rsrQOr3n+Z/cPxkxpQRFXLEvvGr36UGCJRCUuk4TlXH+xSF/W
         RMGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i7si158459wrs.1.2019.09.20.09.31.31
        for <kasan-dev@googlegroups.com>;
        Fri, 20 Sep 2019 09:31:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A0090337;
	Fri, 20 Sep 2019 09:31:30 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4C4CE3F575;
	Fri, 20 Sep 2019 09:31:28 -0700 (PDT)
Date: Fri, 20 Sep 2019 17:31:25 +0100
From: Mark Rutland <mark.rutland@arm.com>
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
Message-ID: <20190920163123.GC55224@lakrids.cambridge.arm.com>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

Hi,

> We would like to share a new data-race detector for the Linux kernel:
> Kernel Concurrency Sanitizer (KCSAN) --
> https://github.com/google/ktsan/wiki/KCSAN  (Details:
> https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)

Nice!

BTW kcsan_atomic_next() is missing a stub definition in <linux/kcsan.h>
when !CONFIG_KCSAN:

https://github.com/google/ktsan/commit/a22a093a0f0d0b582c82cdbac4f133a3f61d207c#diff-19d7c475b4b92aab8ba440415ab786ec

... and I think the kcsan_{begin,end}_atomic() stubs need to be static
inline too.

It looks like this is easy enough to enable on arm64, with the only real
special case being secondary_start_kernel() which we might want to
refactor to allow some portions to be instrumented.

I pushed the trivial patches I needed to get arm64 booting to my arm64/kcsan
branch:

  git://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git arm64/kcsan

We have some interesting splats at boot time in stop_machine, which
don't seem to have been hit/fixed on x86 yet in the kcsan-with-fixes
branch, e.g.

[    0.237939] ==================================================================
[    0.239431] BUG: KCSAN: data-race in multi_cpu_stop+0xa8/0x198 and set_state+0x80/0xb0
[    0.241189] 
[    0.241606] write to 0xffff00001003bd00 of 4 bytes by task 24 on cpu 3:
[    0.243435]  set_state+0x80/0xb0
[    0.244328]  multi_cpu_stop+0x16c/0x198
[    0.245406]  cpu_stopper_thread+0x170/0x298
[    0.246565]  smpboot_thread_fn+0x40c/0x560
[    0.247696]  kthread+0x1a8/0x1b0
[    0.248586]  ret_from_fork+0x10/0x18
[    0.249589] 
[    0.250006] read to 0xffff00001003bd00 of 4 bytes by task 14 on cpu 1:
[    0.251804]  multi_cpu_stop+0xa8/0x198
[    0.252851]  cpu_stopper_thread+0x170/0x298
[    0.254008]  smpboot_thread_fn+0x40c/0x560
[    0.255135]  kthread+0x1a8/0x1b0
[    0.256027]  ret_from_fork+0x10/0x18
[    0.257036] 
[    0.257449] Reported by Kernel Concurrency Sanitizer on:
[    0.258918] CPU: 1 PID: 14 Comm: migration/1 Not tainted 5.3.0-00007-g67ab35a199f4-dirty #3
[    0.261241] Hardware name: linux,dummy-virt (DT)
[    0.262517] ==================================================================

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

I think the big risk here is drive-by "fixes" masking the warnings
rather than fixing the actual issue. It's easy for people to suppress a
warning with {READ,WRITE}_ONCE(), so they're liable to do that even the
resulting race isn't benign.

I don't have a clue how to prevent that, though.

> * How/when to upstream KCSAN?

I would love to see this soon!

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190920163123.GC55224%40lakrids.cambridge.arm.com.
