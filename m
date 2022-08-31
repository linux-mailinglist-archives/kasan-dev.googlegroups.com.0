Return-Path: <kasan-dev+bncBCKMR55PYIGBBSHYXSMAMGQEFCFN2HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 278DF5A7B9F
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 12:47:37 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id p36-20020a05651213a400b004779d806c13sf3578485lfa.10
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 03:47:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661942856; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wt8ZbewmbwjDecGgRdCeGyhPcHmHTqt8EQ6TYJkSil1AYE6CkT1lCyG7CbfRU/Hfat
         VjkkKymrOdJGnFbw7nFoFamSg42p5JEtX5Txu7yrSSthsra6ia6BdNL0BsKTWZ2hyzEM
         WMQhKqEmFcaWNGMoxFa/y2To0myS9NAoh3uup0j2X8P+AbRWBlRSErnMY3paXwyt9DCR
         xR+G2FFbPJLE0rEs6aU71J8ba0kXCg3cq/oK44vCpWc/u/x8eDYdZlNUG/w3inPYwjo3
         rxGgywrdzfcE/R8AtI95XmqO5w/6ct8ND/Hva4VItRORDUaHb7Vg1pgrG5jrjaOpWm3y
         4mFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=o11LlzfNTxlF17VElG+04/SPLxE9MyTjl5BwMjoNQYw=;
        b=fj1WexYf2bUI1RuWH3x5hcCcQ7tnJO+jAZE/gm690QbQjVY8/0FRkjHenYOd8xZD57
         ppxYT/9mga3zvSBmbNUNCabnMh1bD/Ql9ULPX2UP+c91bInWyaXkwIpOkZbWsnpi3fnW
         xzmod17iULiFJGpNrCzQ6lW0FG69Nrq6CHYIDevfwoNqXJhYh1CYwMd18bacO9zb+6i+
         fuGDz7YJBSxz9uUXeHy1RU/5qqVQOtOEBkXT0ptOjYGkrsxPB2qAHm5e4eZxPtR+NK0H
         EF0NYVJ/FLqHjJl/CNEinGbM4i7uBvGHNvnxu8+35poxWVls/z8gXhDlZHiS3Lh3LpuS
         pdXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=hx3jXnZO;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc;
        bh=o11LlzfNTxlF17VElG+04/SPLxE9MyTjl5BwMjoNQYw=;
        b=FetxuIavdH/bxbeiMEgx/a0iVlCzjQH0Sq/DHfla6yfyf5XZ85KJXDnrLGPYbem32D
         V8ynSu8k2gM4F0uz85XnF/6jYMBNvmo9ukKQ56ESNOt3jbmE5Y/To45yrz0ihW8iz1Bh
         fLHYmEMD1meux7n6u9jrcvILvDQjJrUKjaEy04Hhx8doq/EekuFJNgHWHu418uq4LZHI
         4TNoqr6VBlgcNV3NBwc+PURnExHjGtAtIk/9P1XuZvyMQL/Kkvw3bkMOuI6OiYAkTWUd
         ppu2Vt50vWcgPOI+Bg4Z/GGHlb/gQD9jETmwXRgpeIQe3OGv+qbXGc40UY6ltSAtFGzi
         PShA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc;
        bh=o11LlzfNTxlF17VElG+04/SPLxE9MyTjl5BwMjoNQYw=;
        b=TEWU/UBcD0ygGdsvEWD7rDeqf1qns4ahz66/TzbS/nkyllk76Y8CQv8vdkKMQuhWsm
         se9fkpMzHYU6+5dbKDtKDgOBmrTdHPHn3+mI41yl22PFuYBc7uvZZbE7tmMs7VCshoKc
         JlRBND3WR5dD7Zv6U76L6lJ0Xm6PwxxYokD39PrwQM6X6BWLg3j0Deq790r4taFzypBn
         GuGnALQ0nx5uXgEUZ0KGnDdIcfZQsrBkAuX8M+29HJhProesI0Ha7zx+6WrUP38T+gLA
         U6NK6WRe06s5/Jqkxg0owFbQTuQx2+YShHDc9K4hZnTbw6meyiL4wWFEkpeJnrul5B/g
         57qQ==
X-Gm-Message-State: ACgBeo19e99pU9yAkHIfDBd+un5oqNwWx2DvbMQ8NFLKgKhU+3RF7vcp
	i+tBR4mldBDr+SEfuIRUb8s=
X-Google-Smtp-Source: AA6agR6e3XiBeQqQpFkMAqPjvD/4x4Mi/OfWnhJ6cBrsUlPcEum4zRvU3WTKne1NWfS50H4mfxuD4Q==
X-Received: by 2002:a05:6512:159a:b0:492:d0c8:aec1 with SMTP id bp26-20020a056512159a00b00492d0c8aec1mr9906568lfb.275.1661942856577;
        Wed, 31 Aug 2022 03:47:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1c7:b0:25d:9c9e:d165 with SMTP id
 d7-20020a05651c01c700b0025d9c9ed165ls235669ljn.7.-pod-prod-gmail; Wed, 31 Aug
 2022 03:47:35 -0700 (PDT)
X-Received: by 2002:a2e:3317:0:b0:264:6516:93ce with SMTP id d23-20020a2e3317000000b00264651693cemr4473590ljc.212.1661942855117;
        Wed, 31 Aug 2022 03:47:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661942855; cv=none;
        d=google.com; s=arc-20160816;
        b=wFaMC1wqLOQR+dqLPuzzgLvxawBgL+vtFZ0W/v2OSvOUbuevcQFdQ8p3+9NjzprcIi
         pVAaLOgCNYVvlQSYpyRrsAS0skrVKlabfIZSZ0lJLpPKIjocotXC/PsSky66fm2mfTDt
         BK5DloPzFW4HpIBlBFbIeoIkhXRkuvOLQgqmFFPA5pugAOdTM0AfDgfBUKWMRjyDKZuh
         tGOn7DGphV1MDoYbfOHlES0XGt+bi3DXYhnINay9DLuTreimsgBREiQ51r+JLDNaBHX3
         DN6I0tSAGDPDpsCWey5DaJ6UNmH6nznoaWxPYtexVbz8P2r+l5Zkvtmtsetqkov9GWtm
         JiQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=aUzDVspS6J0BJDe/V//gF5+N5LyMdFoI/5xdVcYfQNM=;
        b=TahxGjg2kjWYv2JKtB/GR+E5WDl3QhG16uRnkzUl/0g24WeEvtZZcdJfCSzY0Z/am3
         ApIwv4OKx8lgQBN4J38hf6CLz/PU549Kr8NGWEwynWaEaxyAlGc1rgyyP4JfVTUucyAK
         DYJONsBYLyOAVuFkjGz4pPL1slsHkol5stLoGpTDLe8OMo3XeaggrMKfVx+MfwFaH7NW
         NQowW7iW9J2AUrMh4d/n1EH5uOTVeoju8srSD2kDy4eu+/Q8etRPvFQvNXLdsgByzqqk
         Sc+6W/+KXdGO3RrA8JvFytXB0ju4tyV08p+lFXUUQK9g785Sk1dgbiKA6/Z423mniviT
         o4mA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=hx3jXnZO;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id e14-20020a05651236ce00b00492d8e5069csi470662lfs.9.2022.08.31.03.47.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 03:47:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 136B61F9EB;
	Wed, 31 Aug 2022 10:47:34 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id DA44113A7C;
	Wed, 31 Aug 2022 10:47:33 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 3HtANUU8D2PVawAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 31 Aug 2022 10:47:33 +0000
Date: Wed, 31 Aug 2022 12:47:32 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mel Gorman <mgorman@suse.de>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Peter Zijlstra <peterz@infradead.org>,
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
Message-ID: <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220831101948.f3etturccmp5ovkl@suse.de>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=hx3jXnZO;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
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

On Wed 31-08-22 11:19:48, Mel Gorman wrote:
> On Wed, Aug 31, 2022 at 04:42:30AM -0400, Kent Overstreet wrote:
> > On Wed, Aug 31, 2022 at 09:38:27AM +0200, Peter Zijlstra wrote:
> > > On Tue, Aug 30, 2022 at 02:48:49PM -0700, Suren Baghdasaryan wrote:
> > > > ===========================
> > > > Code tagging framework
> > > > ===========================
> > > > Code tag is a structure identifying a specific location in the source code
> > > > which is generated at compile time and can be embedded in an application-
> > > > specific structure. Several applications of code tagging are included in
> > > > this RFC, such as memory allocation tracking, dynamic fault injection,
> > > > latency tracking and improved error code reporting.
> > > > Basically, it takes the old trick of "define a special elf section for
> > > > objects of a given type so that we can iterate over them at runtime" and
> > > > creates a proper library for it.
> > > 
> > > I might be super dense this morning, but what!? I've skimmed through the
> > > set and I don't think I get it.
> > > 
> > > What does this provide that ftrace/kprobes don't already allow?
> > 
> > You're kidding, right?
> 
> It's a valid question. From the description, it main addition that would
> be hard to do with ftrace or probes is catching where an error code is
> returned. A secondary addition would be catching all historical state and
> not just state since the tracing started.
> 
> It's also unclear *who* would enable this. It looks like it would mostly
> have value during the development stage of an embedded platform to track
> kernel memory usage on a per-application basis in an environment where it
> may be difficult to setup tracing and tracking. Would it ever be enabled
> in production? Would a distribution ever enable this? If it's enabled, any
> overhead cannot be disabled/enabled at run or boot time so anyone enabling
> this would carry the cost without never necessarily consuming the data.
> 
> It might be an ease-of-use thing. Gathering the information from traces
> is tricky and would need combining multiple different elements and that
> is development effort but not impossible.
> 
> Whatever asking for an explanation as to why equivalent functionality
> cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.

Fully agreed and this is especially true for a change this size
77 files changed, 3406 insertions(+), 703 deletions(-)

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yw88RFuBgc7yFYxA%40dhcp22.suse.cz.
