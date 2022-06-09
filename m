Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN62Q6KQMGQEDTJKAGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id CC27E544CA4
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:53:11 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id az7-20020a05600c600700b0039c3ed7fa89sf10160865wmb.8
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:53:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654779191; cv=pass;
        d=google.com; s=arc-20160816;
        b=A2Mbsw8mPmxjdaxBo2bz/ooODOpFYn9YfdPOA9Ly5oLYXn9gzX3tn5qJIqxc7bsME1
         C6f7ZeC1zmn2KzUwDcePEhFXcHJm573ncFHrnKcC4QeaeOwrWajd0fw6m8P7zlfLSCdP
         4zNX3KX4XX6PgzKqd+TXu8DAZargFuhwWCyT9ZCq0k+2Bj9oFQQVb8m1k1VCp0KuhFQu
         87514MJaqPEejB7MtlggWTh//P1irQV2GNVdl3x5g/BVg70U9cglZ9J1/2l94kGCp3oe
         747q1s7h1E5FuTxS+p2+7zGMI1CQaBMlzE3F/gNtlIZEwyMH8dr4HzsCkn9WWY0gEHFQ
         XNbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=odrVdEvOIT6TQ8F3A/2sme4xDRCB9vaNfjA9WWata9U=;
        b=UoL+5fNguZa99LlKB9BBeRiCL9IavsE6sZnXa7hxzSGMrd9KoHHsTDQrJZ90IbiP+s
         u6Dp2MgIjTLL21wVqqmOX9gm0BEcOLEcFSRk5oOmrvU6pBJO36vOWHHOslxQRJj7kobN
         feU9UCJOf56I/iDJ45NpfkJHMmriE7H8o83yb8TXWLu/cCwymGplEUV26IsiphxuVCUw
         Clq17MplUCfEs440ENEXHKu4Pk3bzOHDozHpMBDn0rocBYxQ6XDby6DJdAqtiztsAcjH
         TBVRLGQSb4xQyPHi3wapA+4Lid4qcCGWJYoLOq8Ze1Iw4U2iaV3cbZB70kblBOrNRic2
         IlXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="ogxQx9/A";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=odrVdEvOIT6TQ8F3A/2sme4xDRCB9vaNfjA9WWata9U=;
        b=NUuRtrNPsiQbw01vOym/9akDWWV6ht4yvWjNNF+l544rzQywQOS/ZJka14dsBRFYe+
         RtdjMP6wHUS+1dXrhX0ZpuhoTthLXtrJugy5S6LEjXVQ56ZsT4GxbBjHkstWgJiodK4w
         PbrpzXRHTfvvWUnZy9ezqiLlx591oXJVjyr4zkPGd4MJ4uLE9ShG0lH/o2A2U4NsTW1W
         k5RbjqbWGZsMTwKdpBnxUsSGTLrmx/KHwg2+GwlOTcYWuttxEb4VDwOVB+gb6HenlWAQ
         jPHijiY8jrdguCVfSbrmynzy7Q5egBDxZPcHc3X74wQKe90R3Xk2KGslhqE8gqqUcJvi
         l+Kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=odrVdEvOIT6TQ8F3A/2sme4xDRCB9vaNfjA9WWata9U=;
        b=nmHT4V/0g9UYXitPX5EAoIY0NaSxl97nKrtBKvYQt2vRxFWRipY9RoEY9caw4jxZuQ
         O+At+eGga6aZXsFb8S1PIp+RXOE9bmOvg68QqzuPZxzowJJi7iSWNKAHFJamDHGE17h/
         /TXqMum5REHH08kXITYF3IfeznaEa0NsiS4qlps2oFzHSO9xHYEfd+ivzTNP1QXxIhyt
         4cklOdiT4hO+HnxTHN9PV6oGyLq6sS7ISqPYwBR2O6wtP8VckeC6VJmKloiU7M+4tfhG
         7tR87x6yvC5JRMTUeoEb6K+W2sz+k1D+XJiN0hAASaIkkBF3aw3RjMbpwQ9ueOYNgK5A
         V4lg==
X-Gm-Message-State: AOAM532PQ6r2hCsTgYB4MHvzwGobW8LjukbytGIgL7DkXl/FF8l6NecJ
	/W7w+JdvljS7i4xWk65ON1I=
X-Google-Smtp-Source: ABdhPJy5dpOq9s0C5acgRrxUvEyY75DMK5Ya1jnyk928MAdtLfsm1NfZ8fJaehUIwSIKnFjYvATZTA==
X-Received: by 2002:a05:600c:4f8e:b0:39c:52d6:3cc5 with SMTP id n14-20020a05600c4f8e00b0039c52d63cc5mr3283378wmq.84.1654779191395;
        Thu, 09 Jun 2022 05:53:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5848:0:b0:219:b7ea:18e1 with SMTP id i8-20020a5d5848000000b00219b7ea18e1ls1351745wrf.2.gmail;
 Thu, 09 Jun 2022 05:53:10 -0700 (PDT)
X-Received: by 2002:a05:6000:1842:b0:218:4686:493f with SMTP id c2-20020a056000184200b002184686493fmr18734031wri.287.1654779190046;
        Thu, 09 Jun 2022 05:53:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654779190; cv=none;
        d=google.com; s=arc-20160816;
        b=ZRn7ObDyGKrhc6dQMZRCKafaK0MlIlGVRw4GpsBSyv9QF9hjcwWSPzIntEmNvDCqkV
         EByEPgVcAiVu5Rkx/MIHA+z1eVv1ARldfc/3sSZgr2wSUVWNtRPNrNtHfA9QPxSNmyct
         G+a7C9emxozLgCMY0a6XAdk409LCKB4fnqyvzlUwjq+TZTnOKPWgMjLK4VI1f0TmNh+f
         yZNt+HoosjYLnZv8JkU5uvSJx4RVnu5Ok1Z54RpusRWyIpBmuDRsJi7hjojXhL8ncgCh
         raxzE/s14HtButnRCJBezNdH4pal3ZYrG4y0nPO98OdT/ZIZ2NbaX36ijW//g/YPrsMD
         sa0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xsbD60qIHanlKuWKt+8TLbFkRT3oM/UNVHEodPGa7yk=;
        b=N6zd81496i33aZxtTSGYZOGJ0WEd/3TWukYwkBVb5Mu99FPNVYLwBEmKhYLoRoy5eX
         ODqr8Jg9uaZqCFLOw29y2CcbZQQ66EjrqtAegA4TXp9Uzxhzqh25XikORhn5e/96F4dM
         xmhpBtUxn0p983OQBZxEnzjCe4PwWN7f6tL8xPuNLz9l8ZYGjiGNR1p+1F6zoxErg4L+
         G4Ec7CcyIMIgsajIbPyLNAogG0MkmXdiRLLo9nnTjwdoMUjtVs9he7zUas6H2VqRdyQk
         fWhRMmzPz+UC8gCmUg/cu2k1GuJ/Qh/OwE+ryPRCc1F61cveNatokgYjvNFxUw8XBDWR
         cjAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="ogxQx9/A";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id s13-20020a5d424d000000b002102a7531cesi962687wrr.2.2022.06.09.05.53.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:53:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id h5so32334082wrb.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 05:53:10 -0700 (PDT)
X-Received: by 2002:a5d:6c62:0:b0:218:3e13:4b17 with SMTP id r2-20020a5d6c62000000b002183e134b17mr20790347wrz.673.1654779189454;
        Thu, 09 Jun 2022 05:53:09 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
        by smtp.gmail.com with ESMTPSA id v190-20020a1cacc7000000b003975c7058bfsm27801688wme.12.2022.06.09.05.53.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Jun 2022 05:53:08 -0700 (PDT)
Date: Thu, 9 Jun 2022 14:53:02 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, x86@kernel.org,
	linux-sh@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/8] perf/hw_breakpoint: Optimize list of per-task
 breakpoints
Message-ID: <YqHtLvdLvdM5Lmdh@elver.google.com>
References: <20220609113046.780504-1-elver@google.com>
 <20220609113046.780504-2-elver@google.com>
 <CACT4Y+ZfjLCj=wvPFhyUQLwxmcOXuK9G_a53SB=-niySExQdew@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ZfjLCj=wvPFhyUQLwxmcOXuK9G_a53SB=-niySExQdew@mail.gmail.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="ogxQx9/A";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as
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

On Thu, Jun 09, 2022 at 02:30PM +0200, Dmitry Vyukov wrote:
[...]
> > +       rcu_read_lock();
> 
> Why do we need rcu_read_lock() here?
> The patch does not change anything with respect to locking, so all
> accesses to the container should still be protected by nr_bp_mutex.
> Similarly for the rcu variant of for_each below.
[...]
> > +       head = rhltable_lookup(&task_bps_ht, &bp->hw.target, task_bps_ht_params);
> > +       if (!head)
> > +               goto out;
> > +
> > +       rhl_for_each_entry_rcu(iter, pos, head, hw.bp_list) {

It's part of rhashtable's interface requirements:

	/**
	 * rhltable_lookup - search hash list table
	 * @hlt:	hash table
	 * @key:	the pointer to the key
	 * @params:	hash table parameters
	 *
	 * Computes the hash value for the key and traverses the bucket chain looking
	 * for a entry with an identical key.  All matching entries are returned
	 * in a list.
	 *
	 * This must only be called under the RCU read lock.
	 *
	 * Returns the list of entries that match the given key.
	 */

Beyond that, even though there might not appear to be any concurrent
rhashtable modifications, it'll be allowed in patch 6/8. Furthermore,
rhashtable actually does concurrent background compactions since I
selected 'automatic_shrinking = true' (so we don't leak tons of memory
after starting and killing those 1000s of tasks) -- there's this
call_rcu() in lib/rhashtable.c that looks like that's when it's used.
This work is done in a deferred work by rht_deferred_worker().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqHtLvdLvdM5Lmdh%40elver.google.com.
