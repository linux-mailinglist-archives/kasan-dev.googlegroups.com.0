Return-Path: <kasan-dev+bncBDAZZCVNSYPBBNHMSPWAKGQEBL5TNGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BB34B949B
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 17:54:30 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id u123sf2898047vkf.8
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 08:54:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568994868; cv=pass;
        d=google.com; s=arc-20160816;
        b=H3/V11ps+DgCLm2H3bAY3lOR4VwWwYfCHEXbWh717XRYZs3h/fXyBZwHl3UEBnxx/t
         b/fSxl9GRKhLsuTUIvQCeDbPygzOCwhVoVMI9252Vhm/z/IbfEoyanOOSgRSFZEZ4KwW
         2msL07W23O1Aj1VX/2ayaLRilF8SPMDQs3BIUCnQUXokxmqEa+QB7dp34SWcOB1o71nf
         Kadl7BLg6+bVusizhxav/Ze7BlKb4xSWjNMJUMqAspgy5VBNcTGA3Nynz+pmCqNBBvKM
         2s9p+MLvi8BsSwg8eCtBJ8452cbBP8bkBxUayeNuPDJgiX/ocAseNODuXlQDSxcu1qxT
         w0fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=rMwHLW/mnA27kx4FCgI92u57wI2aKAU3OG2pOAIafBE=;
        b=gwdXJ6X7vx8veig4QbfU2t+cwI8jNKeiw+H6cDtR4dFRUmfC2f1nce0AUCaq1mquJx
         eUKyLVJ/QFO6OON8O+bAIjLOFp9h9nI+EkLUMlRGz7ls2pHZtn5GOHEYp+aU/RdCSKIZ
         /ouoE5/JjicSSlRZlPWAhxoGKB2Jmr8TOanMHpwTHXP2+KmAe6tD9j0yC0vRABiMCzhQ
         nl853bmeBLFoApgIk/DYNa0fQjvVz7WGXRb+xelE211EQ7ipeSMsDnVC4Hmf/b15D4pI
         ifE7pO6INQHOldu7rkSIGoBV3GxMKD28MyQs+1W5CmZIouYBhS/uob3TRnjvotOq6c+b
         L6Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=bbTzVipQ;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rMwHLW/mnA27kx4FCgI92u57wI2aKAU3OG2pOAIafBE=;
        b=dXcYZ5AUH/bEerDs5FOyFYMkFCU3CNHHfBfx/VxCHdBTEK9JS6HUBGJZQzIR+2RZNP
         rRi5ZGiyI5Xr93tltvHKHc5jHDzsHF7aeJFzjcHJUWQUOTdc2zhXaNRw7QSENuQKRUCI
         M0oHDhuOKZimNHftHvIEKL1RPMvqJJLe1lvRzGKd5UZP1aH56++0mHq5uOXlwWPVj5/E
         gkEMN9x4FIH4CosNsRQTY9dMkGrZgXYNqOk/ARobrcEMpemho5BZqXiaNMOuyX8GQf3y
         vu+oj+rfsRXMUHJIxGSISup2ElcnW79ChHb2YgoEobl/cVf/57qadScEMQpjWMCJ/pCX
         gmMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rMwHLW/mnA27kx4FCgI92u57wI2aKAU3OG2pOAIafBE=;
        b=OEmaTbcC/Yv+6NEQujN1VDj/VwrhQ1c7sGvlM80PeFnpBG7YknUEEBRlaAN3ANrSgZ
         UnGpq0DbmWlnXMnk6TIsP36xpd6PgNDK66M8EY4eHY/ATSZ3a38diviv/8+sB4ve6vF6
         HdwuFw0OSej7N14Kiu/mvnBCLZe/EpajhxbxfHwWUeJxlo4kbLBIlU8Ms2s34lzjmh3d
         Nl5L3vCe3BeOkkR92+oXPdMcoZNuOZvOZjVpUwGJL22iaSyPb7LAClQC1/wwdoYZEfA7
         x4xWkOONuVgaYfRPgbBrenPbtpE2EkAtUrFZLxM7yv05bQZyMse2UX6F562uALiFzuvJ
         HTFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVWFEyOE1ADSY/HEhZe5DdeCH6BDQ9sxkxULqlnVvKPADjcO4bf
	BJkzzuy4YC5YFUvZpc3pZAo=
X-Google-Smtp-Source: APXvYqzSzSKWdwd+q/NYbjtzRfzWNgt0LipqvmbOwsxVesNqfMgOITpItmOd0E5Ot/b/leuqivty9g==
X-Received: by 2002:a67:1e87:: with SMTP id e129mr3152246vse.179.1568994868666;
        Fri, 20 Sep 2019 08:54:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:1684:: with SMTP id 126ls789186vsw.4.gmail; Fri, 20 Sep
 2019 08:54:28 -0700 (PDT)
X-Received: by 2002:a67:df06:: with SMTP id s6mr3045289vsk.170.1568994868373;
        Fri, 20 Sep 2019 08:54:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568994868; cv=none;
        d=google.com; s=arc-20160816;
        b=nC/TM21gtmD0lYZiG/178s7PPaMWBxSDNPuMighFeq/7J9llBSZ8GMdQdsgxoVvavU
         eeA53N9LB8qKgJjjh2A7oj3ltNU3MZ84ghMrA2wegFZVu2Uy8abjY48SUroK4fOq7xND
         pSOL82JaYGuDEi0EBEQybwbdcGGuQD2cRGldlVBQqcs0uqDWZayIJeiqA0dfSSbjqLUx
         PqHfX5lgsY2QsGJzvNJcjvRLUCReBOZi+tfH6TfATxosSgD+n/cPterb7YmV51dxwsSg
         3EjQNVLWcR6ohE+kieJKmnGM7r/RMeTaoxiJVnYpmOUsFqpyMQDA7maSM1072JanHnGi
         H+zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=hSNyPKLLmygnPBchyfHN97oiH6P+a0yze9eJXxgENQk=;
        b=O1jrxQdnuG8d/ExBhX9s69lf+jXFpOxp615rtd8x8MEG6/z7o0ulR9CKECnD1csW5Y
         XbXqx8fPbHeTnXT8Vr1noVjx9xQAq1JaByDdcYGRRbQDbvkvo8ErTRGuTweWVxiLYfbl
         tEMAATIi804XwF37rQkiOIoFy4X9b9JdzD7IdKBW8utT4FZIAoq1qVNVSwF5jRlER1cH
         jcArSGcHcZCWjt683B6K5OUPTh5iV0P5WqIKjqB5FASF49fPPUTcja0rWXcq9wrt6vcy
         B7XoHB0OC/jGiph/braVt0CXBSp0+Qx8jwjP3zvBZxR5Zg6ApF82FA8DTd9gCpGHDFTg
         dbzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=bbTzVipQ;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r72si215577vke.5.2019.09.20.08.54.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Sep 2019 08:54:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 444BE2086A;
	Fri, 20 Sep 2019 15:54:24 +0000 (UTC)
Date: Fri, 20 Sep 2019 16:54:21 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>, paulmck@linux.ibm.com,
	Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>,
	Anatol Pomazau <anatol@google.com>,
	Andrea Parri <parri.andrea@gmail.com>, stern@rowland.harvard.edu,
	akiyks@gmail.com, npiggin@gmail.com, boqun.feng@gmail.com,
	dlustig@nvidia.com, j.alglave@ucl.ac.uk, luc.maranget@inria.fr
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20190920155420.rxiflqdrpzinncpy@willie-the-truck>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=bbTzVipQ;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

Hi Marco,

On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> We would like to share a new data-race detector for the Linux kernel:
> Kernel Concurrency Sanitizer (KCSAN) --
> https://github.com/google/ktsan/wiki/KCSAN  (Details:
> https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> 
> To those of you who we mentioned at LPC that we're working on a
> watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> renamed it to KCSAN to avoid confusion with KTSAN).
> [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf

Oh, spiffy!

> In the coming weeks we're planning to:
> * Set up a syzkaller instance.
> * Share the dashboard so that you can see the races that are found.
> * Attempt to send fixes for some races upstream (if you find that the
> kcsan-with-fixes branch contains an important fix, please feel free to
> point it out and we'll prioritize that).

Curious: do you take into account things like alignment and/or access size
when looking at READ_ONCE/WRITE_ONCE? Perhaps you could initially prune
naturally aligned accesses for which __native_word() is true?

> There are a few open questions:
> * The big one: most of the reported races are due to unmarked
> accesses; prioritization or pruning of races to focus initial efforts
> to fix races might be required. Comments on how best to proceed are
> welcome. We're aware that these are issues that have recently received
> attention in the context of the LKMM
> (https://lwn.net/Articles/793253/).

This one is tricky. What I think we need to avoid is an onslaught of
patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
code being modified. My worry is that Joe Developer is eager to get their
first patch into the kernel, so runs this tool and starts spamming
maintainers with these things to the point that they start ignoring KCSAN
reports altogether because of the time they take up.

I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
to have a comment describing the racy access, a bit like we do for memory
barriers. Another possibility would be to use atomic_t more widely if
there is genuine concurrency involved.

> * How/when to upstream KCSAN?

Start by posting the patches :)

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190920155420.rxiflqdrpzinncpy%40willie-the-truck.
