Return-Path: <kasan-dev+bncBC4LN7MPQ4HRBMP6U73QKGQEWKDTW2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 15EFC1FCC4F
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 13:32:02 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id a10sf661579lfo.23
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 04:32:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592393521; cv=pass;
        d=google.com; s=arc-20160816;
        b=hYjHYiPe+1hMcCmtnAbjo/krFNDiTqMUYJAvsxfwC75SXjc/FklKytt7SD+luA02a8
         rAnTLkO7zG4UCDR7GBpuXQUETBaVNeVOesy2CLLUNzmGgMDbdc6yAoK9tFHL4fQpZj0E
         pluth5DYFFn/QGqLMDUhtCYb7ck78bpP4S/JbaaM2s3wiNJJ6fbvC+E/1eShlEgGXqI9
         wwvrEJw8RmtAELslZSdhtRVc3FfLTMvLRMdlFri75xWrD/N/LGWhYNqg4tjGxg9l/iZO
         8GRQWzWE2IYoFSqP6/l87WqHPeGW8RJ8sUc7DFQdOZDsKBKcxqZRaYpZRuEpwxdtGZcg
         Qdxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3sABCUgNh2SgSiRSA+gtfApdhHXiLGSYq3Mzx/4vOgE=;
        b=UxH8AvGb2qGgg2rd6VYOgh4vNmO7Zo6hx5Skv1KcTzi56eFj9MIL/b68LBh0POk2R0
         NTdwmfLQ8GvvCTYYPNOTXTDOGIiGrPFDquBpOJQ88PDmn6cAbVOEyun4kVr25XzYz3lb
         44n5lJqCOBrSfPCTR3yCSB4Hs/mb8tzQlDfqU3MSwEqMCCP+5e6fIWO5BM/WGNH/4I7e
         cWG7vJwvqJqT8PCwIqATUZCQG6rbNK6PLSNKscw/cG9jh2QNkZPsEU5t6Qq5WDfomhb6
         EFOhng7qkSBudNe2HGocjEsXJY1xCpSd4FCksQRQl6gQiQY1/Mpr6Qrbk5Y3/SNv9sZi
         CRHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mstsxfx@gmail.com designates 209.85.208.68 as permitted sender) smtp.mailfrom=mstsxfx@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3sABCUgNh2SgSiRSA+gtfApdhHXiLGSYq3Mzx/4vOgE=;
        b=W/pzy9t5rb9KHtepyKExcZJD2YpU5jnmSTTBYZIQi3pGDpsJqCzywKliyXtlJMMvcn
         +MAzhiy+Oz1jQDY0JR5pRdnoUJb/D83Ns0UMq9kQkjTMen7j46CesZM1LKpt5l/xL12k
         yzZtpJDYsEhlMRfdJp3AzLZMygMcYsTntGMrLWHHy9w9MxthP5wZfXe5NqGvYkSBuaIB
         1/iAZnSX4A1C94yTso42xqJNhdzR4020R15qE3wfEF0SdrpLOEtIsWOcFxsnbOyQOzrz
         ycwraGp+JgeLTQr9IJ5ZDBF65eRSi7ccglbX8eZZ89cmgfnUf7+Tbl2xnKrDEUx6waB8
         9KOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3sABCUgNh2SgSiRSA+gtfApdhHXiLGSYq3Mzx/4vOgE=;
        b=UYkHeq1TZMSbN65hFzYPN87nqN6593GOpjcRdnzTrc2j5ANf92S3LLKLMgjfGVmiaJ
         B9NS3tNODWg5s0SvPP2P5N+NgHI3BpijqFuBKCw1w0zPIyOSdIvj7SuVcUfEhFZXYnwA
         +pCwk2prIzUQZ2DMSCVQKVWngkTjU+L0fmacrAutifpKY+Gf02+ZuCe1fg6O0k4Agyr+
         lFv6f2PIQE8N1DlDSHnbjaFb/JbeLmJArHm0lAawqrI1WQVHeOg8lq//uhtRbB3RkwOU
         hMI9gFB7Wa9ZSjcOwh6f/IiM6y/ZIlBzU2JvI+3liU8FBM1K4SDnEGMjpxwthtV7w/34
         JGbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Bwu6ADHcsS6BabGwMrw+XV1SBiNImSBb/8nG4swaXpdwp1aGL
	rUM84YS7spnQDxeZ5p8E1Bo=
X-Google-Smtp-Source: ABdhPJzKQg4uqXZXY4AUIdlxoLonSGjuZwxECrpJegE15c5RbeK+/jLaMYHhHqc88/8CZQf/ESIHIg==
X-Received: by 2002:a2e:9147:: with SMTP id q7mr4022877ljg.430.1592393521604;
        Wed, 17 Jun 2020 04:32:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c188:: with SMTP id r130ls649086lff.2.gmail; Wed, 17 Jun
 2020 04:32:00 -0700 (PDT)
X-Received: by 2002:a19:4301:: with SMTP id q1mr4330212lfa.96.1592393520882;
        Wed, 17 Jun 2020 04:32:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592393520; cv=none;
        d=google.com; s=arc-20160816;
        b=AeqgKZL+mDT5OBO4V8N0EGYYl8WUEgnmwBQAQ+usTwUZsncr1xDlMY7MLiHWygAuY5
         lY/NB0mlW7py8rc9O5llPos7R6l0BvjAZx9vUeSxX7sSHaFyr0VwDxyrnJaJA6kOnPMU
         7QiDGW0iRIJL/uBcVCKwoGbLVNO6cmf1uF1hw1dfWvlhr+o9mz0MOYuX2kIW8M6PxDMP
         VNPo17DF5bPUWrSu25GzVY7/ojypAwTGuci5PcFqvgdn+culxRPkNeV06N1biJXocYsY
         pyaCKtVR9GhUnkddk8Tw3AZmOhpFog1g297Em6Pf/Q5uFvz07rAfafdUzuVPJ7cmk/Sy
         +Ocw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=FYdkGKfQbhF4PHnRrzgzko0Pu9PmmGSrtwLwQw3bXCE=;
        b=Fi6d27/upUhbCIEdeClZGcDkgzQMAFyn/7MhUZKvEaWZDQKfaz2SvW6lQ3MzI6lWUD
         uOQw8k3sKLYzcLE1YcRSvoCka73ZGBtMY/NvTwkN08cR2McF6h13JrSRzJZ4zJp5hw+B
         D6j5nHE41CGDDpbO8gORMWL7Yc5zbmWt55YMlXmYNLUy34Zu75RpKKRaoOoOngMksfn6
         UU522QHQEjBkr7aeUJgtkL6lZuhn7/tUdThlOvEH2SV9LDQx8k33VopCehsPmg3bN98m
         UY0x+5iajYDKJibh8+IFslld8oPIfJ13pYZGp0sj6iIlOTtYyu4FEUZUNSSAOUcez10b
         +77Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mstsxfx@gmail.com designates 209.85.208.68 as permitted sender) smtp.mailfrom=mstsxfx@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-ed1-f68.google.com (mail-ed1-f68.google.com. [209.85.208.68])
        by gmr-mx.google.com with ESMTPS id j19si604592lfe.2.2020.06.17.04.32.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Jun 2020 04:32:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of mstsxfx@gmail.com designates 209.85.208.68 as permitted sender) client-ip=209.85.208.68;
Received: by mail-ed1-f68.google.com with SMTP id k8so1667422edq.4
        for <kasan-dev@googlegroups.com>; Wed, 17 Jun 2020 04:32:00 -0700 (PDT)
X-Received: by 2002:a05:6402:3106:: with SMTP id dc6mr6587998edb.375.1592393520398;
        Wed, 17 Jun 2020 04:32:00 -0700 (PDT)
Received: from localhost (ip-37-188-158-19.eurotel.cz. [37.188.158.19])
        by smtp.gmail.com with ESMTPSA id y62sm12010608edy.61.2020.06.17.04.31.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 04:31:59 -0700 (PDT)
Date: Wed, 17 Jun 2020 13:31:57 +0200
From: Michal Hocko <mhocko@kernel.org>
To: Matthew Wilcox <willy@infradead.org>
Cc: dsterba@suse.cz, Joe Perches <joe@perches.com>,
	Waiman Long <longman@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	David Rientjes <rientjes@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
	linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <20200617113157.GM9499@dhcp22.suse.cz>
References: <20200616015718.7812-1-longman@redhat.com>
 <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
 <20200616230130.GJ27795@twin.jikos.cz>
 <20200617003711.GD8681@bombadil.infradead.org>
 <20200617071212.GJ9499@dhcp22.suse.cz>
 <20200617110820.GG8681@bombadil.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200617110820.GG8681@bombadil.infradead.org>
X-Original-Sender: mhocko@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mstsxfx@gmail.com designates 209.85.208.68 as
 permitted sender) smtp.mailfrom=mstsxfx@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed 17-06-20 04:08:20, Matthew Wilcox wrote:
> On Wed, Jun 17, 2020 at 09:12:12AM +0200, Michal Hocko wrote:
> > On Tue 16-06-20 17:37:11, Matthew Wilcox wrote:
> > > Not just performance critical, but correctness critical.  Since kvfree()
> > > may allocate from the vmalloc allocator, I really think that kvfree()
> > > should assert that it's !in_atomic().  Otherwise we can get into trouble
> > > if we end up calling vfree() and have to take the mutex.
> > 
> > FWIW __vfree already checks for atomic context and put the work into a
> > deferred context. So this should be safe. It should be used as a last
> > resort, though.
> 
> Actually, it only checks for in_interrupt().

You are right. I have misremembered. You have made me look (thanks) ...

> If you call vfree() under
> a spinlock, you're in trouble.  in_atomic() only knows if we hold a
> spinlock for CONFIG_PREEMPT, so it's not safe to check for in_atomic()
> in __vfree().  So we need the warning in order that preempt people can
> tell those without that there is a bug here.

... Unless I am missing something in_interrupt depends on preempt_count() as
well so neither of the two is reliable without PREEMPT_COUNT configured.

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617113157.GM9499%40dhcp22.suse.cz.
