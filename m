Return-Path: <kasan-dev+bncBCKMR55PYIGBBWVZYGMAMGQES2OA73I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3653C5A8FBC
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 09:18:51 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id m1-20020a2eb6c1000000b00261e5aa37fesf4910178ljo.6
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 00:18:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662016730; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZFny9kg8MLou/JuQXektZdnKqbPKC04uUl4UQqelrZycLRbLbAf/TqiKjnnPLrieLV
         zdRfPq3txR+i2bzc009rUBEInaIYRGJnbfVCu+0nikp9kTdQlHKrIpj3cbqpt3EbdXyh
         iD+v5vzH719ZOTxrNIuCYpAYVEFEuUzK2cAhchhGG436GN6MsrjJJCdjJlB/tzb8xQ1k
         k4wfYeKlaP3wgvvzS5zzYtysq3UJeIbLV6iVKGisYxwVL+uVntc2Ad2BG19UDuxUEtVl
         sno8UScxwA0gULg9xKvpJKhCAi2OiESzY4y5gnOPjX2wvCiDS8LF0ikgShbydrPXGc6N
         G9ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=cWkCB6BvFNyxkor1NLnLJd+fdN887ttg8ZQsjxW+qZM=;
        b=YqKHuGBKhTluoyuC2Oic6oSPxuYhoIO35Dgw4JcINhj6Mo3R/8mc1Pdhq4bl+HcNFZ
         7K8x/iXn1wIJ3kFK4oQUxWRmKyxpm7i5lDCIuTEUpRnNvqK9A9N0jEefOxdiOAKs7uqK
         HGHAZRzYjWLL5Q4fPKmdB2i0+4NQGeyr6/FU38UBG2OJuK2n8xOXEsPR0gtQ41BHnDuI
         oE3Tz90IPYIwMUqQVX0N9jgpqbq5A/KxPjZmQ1mNdY9adddmj/FNke9dqsKvR+xHwIMT
         VB071+7agvlkEq8bRKH67ZHNnfHxTZKPCQ1D9l9kViMqptMQCNQtz5/Yd2M1sd239vUs
         /2Pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="XxPpqvq/";
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc;
        bh=cWkCB6BvFNyxkor1NLnLJd+fdN887ttg8ZQsjxW+qZM=;
        b=onVFLvN/HI+1nmkaEdLDG86VcXVWPWPB9rFHcuDwjlxt2RERzDDrxbQP6jIaM//pZx
         ZZCuCcPCiSlSMNwGrtytPcnxXB8A5b8QWkISbAITmr0XDnFbVffHDZFLItZyHmOksn7o
         30hEfDpB+FQ2p0AX/YjeuysOLGqYtpbHPp0QaFaHg6nfGH7G1D/mWRTmnri7nBkIP1Ep
         668ZD9AWCMs3HvV+sl25aUCiWEHsuAe0bh5Io3U4ya8YeARIKExvAK4aVeKx3GglreOk
         diNWs1QtsK3CTF8hpkhvGyZZS62dSATbEItQTlDICtAC824EIQ0FWDkjCC+Id+3xg1e+
         nFpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc;
        bh=cWkCB6BvFNyxkor1NLnLJd+fdN887ttg8ZQsjxW+qZM=;
        b=sMQKQcfo82AtDh19x2IpI1+/L3O+isFF6ITNeD+3J7oTX/DtZVsBExtNls0wxkBk6E
         qJRINpWPhiiK6vhmCWBBKf6K2wACB0G8TqC1alx/MX+N66sPBY9l3B7KgRm5xvLymQiM
         Bk6FdHzSx5k++gp9eQmu6Rh6ltZPhOdEH/h2paA5W8vF8Z4mdeURo8gmRkukI1auY+Cv
         RiLUUz8sVdIw/VSFZAMERsiUtZww03ZxGg60SskhTozhhOCkpFu8eZKa7tC+TErAXdQU
         kS+5El481F13HqmrR5/danF1qXpTN8SmC1FyzJUUc+EVcuwZkSEEfyHYb8fq13LyRA++
         SuMg==
X-Gm-Message-State: ACgBeo3cTfTaMTsN/ur9kCbYHzVmyQkM/UDX2d9dtTcDTydcmR8PwYVP
	O7L/r8gBQqS26Qpp6ogeCbY=
X-Google-Smtp-Source: AA6agR6fUTlYlOClG4g/4DPnO0fDm6A7gwDhrZkCmHS1GUeB/zSzWp3aIBbcZl68S+jMV52WoP+6GA==
X-Received: by 2002:a2e:7411:0:b0:263:ed25:61c9 with SMTP id p17-20020a2e7411000000b00263ed2561c9mr6250750ljc.361.1662016730494;
        Thu, 01 Sep 2022 00:18:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc19:0:b0:268:a975:d226 with SMTP id b25-20020a2ebc19000000b00268a975d226ls161697ljf.7.-pod-prod-gmail;
 Thu, 01 Sep 2022 00:18:49 -0700 (PDT)
X-Received: by 2002:a2e:934f:0:b0:250:a7bc:2b8f with SMTP id m15-20020a2e934f000000b00250a7bc2b8fmr9432507ljh.512.1662016729023;
        Thu, 01 Sep 2022 00:18:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662016729; cv=none;
        d=google.com; s=arc-20160816;
        b=gwBarKqH20nOUGB1II74ALip9THlnURFRT9Ji0K4m8xYA3AhJ22Tt/OZo0YjRzTRZM
         Z3AFbHIwQ7YpNEJCaYIP8fAcLYaxP1vdgj1PVoKqaY2fctbJ8sJRnt6E08CM1UcGQA7e
         TEjoryEnisFXjuFTefPHi+Edulz5dUOPqfto9Ffqe93CZT3IjK5hX4dedKfAF84I2Zci
         DL9Zihfks1TdK/3mhboVUXLprNMFSTevD6lTNkhJD6LGGoTXICYynDML6lB01cWaqBXr
         K+7BYUyCegEuU00PfmXc4YoNJwujq6wS6/V6GJgBiDPcIboPn0/9aTH+Vu8eLfUP+QgU
         nLgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=syKqR2otOp+SJa2emYsY57+bVX7vmPgl46yq0SOCcY4=;
        b=k1CmpxRwCUPU6HbBQNGDeKcSCL2e3XjErry1WaLEtHTKoqj3zkkFSpX83BwqnORfcs
         oUCXaSqmJsIWsiYKzM0sjTw3X5hionveLXYWDNeHkCU/nTJx/6WyggmrhIGwET+2gT72
         gTPwRcllpvY5+A4ZChVelxdGdwsHXppdFueN8Sj/nfl99yziEw967n4e2yaGTd/H+WgE
         yHkRzP7R4S6v+ZYnf1CBK+zuMdE68bSmwry+TixFJ7pxCB1V3u0gWSuOGF5WcJE5t8dt
         mLUuj+AhgnhXFiEjQ1VCldwTfaWWrPS3pazuYx0Hvtn+j/XhwXt55cKYSI9ERz93JkLo
         710g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b="XxPpqvq/";
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id o7-20020ac25e27000000b0049469c093b9si559215lfg.5.2022.09.01.00.18.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 00:18:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 43E1B1FB16;
	Thu,  1 Sep 2022 07:18:48 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 098CC13A89;
	Thu,  1 Sep 2022 07:18:48 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id HuA6ANhcEGMwCAAAMHmgww
	(envelope-from <mhocko@suse.com>); Thu, 01 Sep 2022 07:18:47 +0000
Date: Thu, 1 Sep 2022 09:18:47 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	void@manifault.com, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
	changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b="XxPpqvq/";       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Wed 31-08-22 15:01:54, Kent Overstreet wrote:
> On Wed, Aug 31, 2022 at 12:47:32PM +0200, Michal Hocko wrote:
> > On Wed 31-08-22 11:19:48, Mel Gorman wrote:
> > > Whatever asking for an explanation as to why equivalent functionality
> > > cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.
> > 
> > Fully agreed and this is especially true for a change this size
> > 77 files changed, 3406 insertions(+), 703 deletions(-)
> 
> In the case of memory allocation accounting, you flat cannot do this with ftrace
> - you could maybe do a janky version that isn't fully accurate, much slower,
> more complicated for the developer to understand and debug and more complicated
> for the end user.
> 
> But please, I invite anyone who's actually been doing this with ftrace to
> demonstrate otherwise.
> 
> Ftrace just isn't the right tool for the job here - we're talking about adding
> per callsite accounting to some of the fastest fast paths in the kernel.
> 
> And the size of the changes for memory allocation accounting are much more
> reasonable:
>  33 files changed, 623 insertions(+), 99 deletions(-)
> 
> The code tagging library should exist anyways, it's been open coded half a dozen
> times in the kernel already.
> 
> And once we've got that, the time stats code is _also_ far simpler than doing it
> with ftrace would be. If anyone here has successfully debugged latency issues
> with ftrace, I'd really like to hear it. Again, for debugging latency issues you
> want something that can always be on, and that's not cheap with ftrace - and
> never mind the hassle of correlating start and end wait trace events, builting
> up histograms, etc. - that's all handled here.
> 
> Cheap, simple, easy to use. What more could you want?

A big ad on a banner. But more seriously.

This patchset is _huge_ and touching a lot of different areas. It will
be not only hard to review but even harder to maintain longterm. So
it is completely reasonable to ask for potential alternatives with a
smaller code footprint. I am pretty sure you are aware of that workflow.

So I find Peter's question completely appropriate while your response to
that not so much! Maybe ftrace is not the right tool for the intented
job. Maybe there are other ways and it would be really great to show
that those have been evaluated and they are not suitable for a), b) and
c) reasons.

E.g. Oscar has been working on extending page_ext to track number of
allocations for specific calltrace[1]. Is this 1:1 replacement? No! But
it can help in environments where page_ext can be enabled and it is
completely non-intrusive to the MM code.

If the page_ext overhead is not desirable/acceptable then I am sure
there are other options. E.g. kprobes/LivePatching framework can hook
into functions and alter their behavior. So why not use that for data
collection? Has this been evaluated at all?

And please note that I am not claiming the presented work is approaching
the problem from a wrong direction. It might very well solve multiple
problems in a single go _but_ the long term code maintenance burden
really has to to be carefully evaluated and if we can achieve a
reasonable subset of the functionality with an existing infrastructure
then I would be inclined to sacrifice some portions with a considerably
smaller code footprint.

[1] http://lkml.kernel.org/r/20220901044249.4624-1-osalvador@suse.de

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxBc1xuGbB36f8zC%40dhcp22.suse.cz.
