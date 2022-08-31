Return-Path: <kasan-dev+bncBDNOHB7NUMKRBDUWX6MAMGQE73EKFWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id A8D3F5A87C7
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 22:56:46 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id ho13-20020a1709070e8d00b00730a655e173sf5839585ejc.8
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 13:56:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661979406; cv=pass;
        d=google.com; s=arc-20160816;
        b=o27pMuikBl7cOzYgDSupgo0aDsWCG9wcP+i6j+bwMSLTEOt6VlMU4Cg1+zgb07dKGu
         vbHexaYQA4MucedGYVeSe//llUCzbG2QrkNE8UprDPn+80ZfZrI0HsvJn7s2RIwPY4xd
         IHSKGh9HRd646PnFif/neEMFBm49RgqGdN/K1ixNDnty8qmzrIEZraMeJOaHcplNxj6B
         O7RAWmYeiF5t6opNGfrG+Lz+br4lcgLpq3bPu7E8TNrydRzjZoye/muCatfobmbD8/ZL
         cBHhs7Gs3ZmKmfCWG5+58u8jk1GAIGgwP/SdNMLFtCE/ug1eZnIGbl0p9ld1ElfKiILn
         03Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZF5CForklrR8dj4keJAEW90hKsUn7QmZbnQSEhKDf/U=;
        b=Sgr7MZVl+dO+cfrbTOFxlTSaIDM/310mnrYZZ91J0k0bha5nUV36Dlngf/AdF+KAAF
         E7gV7u1iENp/rTo8aS7172hagwLaw0s7PmChV4O8zXQKyYCRKEJUIRsnovAS4GM5BD8c
         B8x0otR/UsTDY38mFm9K8CEIWXiLjFQy1x6wZPNkdE4WsAzcY/eLaSJCl/BF+Zl362tw
         1hL8B2MxB8j/Psl/sHFhDot4M/nUvkxEePkXUqI4lKHVAkOFeehEqTQB5JZRdlNgwCmX
         hHtCuxMzNQnGYEH2byeA+w4tj593/cKM9QzwT7Ra3kBowdN7DMT7FaYK4LazTWHfO3xU
         GBrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VyP3SbNs;
       spf=pass (google.com: domain of yosryahmed@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=yosryahmed@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=ZF5CForklrR8dj4keJAEW90hKsUn7QmZbnQSEhKDf/U=;
        b=b8otPoOkaezlJ3dLy9kkhH/MMP061kNdNwIez6OvW48LXUwM5gTRxlTMLH5swZAWR9
         +fEf6oRSQJyFiWQwxCLGCRho7AESxL8lhNqfxG/t7col7H2kmrRXe2aNP5tJoi0UzVDr
         e8QcYEdvRqtOpMxI/LCHFldzdL/kRI2vrj3v3cz+QP7ZOs5JIdRR3zCI9L4HMWqdMzUA
         2c17CahTkrxfHjrEh9r/TKeomnhrdTiSiTedP3yynwY7UaVwlsMS3Xi659SSU1zVr5Xh
         AgkNkcj20+5ukcNZPZ9iu+zmAeJeemDorezGgs5eWEstOM2EeUGXZn9Tl3HVDJSi8yC2
         Uuog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=ZF5CForklrR8dj4keJAEW90hKsUn7QmZbnQSEhKDf/U=;
        b=oZcEPbRWeK09dIxS4sV+oSj+322WhB/GuSVawAdJYUhlj+J1zzG1Q7BWpFs67NmtNp
         zBfVK1Sv7nw7QJdAVic38lkurtP1y3Ttkwh5drKnh/nwCCHPujUEsmkLMffZ7ubkpxR1
         iutl/EnKTWFO2SjjxFjETpzij1+EXCxgkxwAsp22qik3GtlMQTi7nUWCpIaT4k1sfLSq
         r52/gp7PP5AElLKewYoC+q6qVWRWhQK2TWWBekf/9kD4CWXUU8rE5sbv9rK0ldeiuUH9
         gPN5tj3Z74m+ulcJ2Z/TIILDYcd+gMNllo9ce7rKv23IRcqKbYZik1uhMNyVOyIltLkc
         lXCQ==
X-Gm-Message-State: ACgBeo1uXEVaosWBj8OcV4vELt3aYDRnkvfdZ1SBhdB8ghidbZi3uhuQ
	b3Wpn73UiNfm9ojr2C7MrFQ=
X-Google-Smtp-Source: AA6agR7kmzhYpgctqVH33nfryOzlajEybcsOvDfsUihLbKNdpZAkECk0L3qQN+oGL/gDwqd5GK5/Sg==
X-Received: by 2002:a05:6402:35c7:b0:448:95be:380 with SMTP id z7-20020a05640235c700b0044895be0380mr11808272edc.393.1661979406365;
        Wed, 31 Aug 2022 13:56:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34d1:b0:447:ec6e:2ee with SMTP id
 w17-20020a05640234d100b00447ec6e02eels371012edc.0.-pod-prod-gmail; Wed, 31
 Aug 2022 13:56:45 -0700 (PDT)
X-Received: by 2002:a05:6402:5190:b0:448:5bdb:b27d with SMTP id q16-20020a056402519000b004485bdbb27dmr14786421edd.49.1661979405338;
        Wed, 31 Aug 2022 13:56:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661979405; cv=none;
        d=google.com; s=arc-20160816;
        b=hUYPPnQZ32+MhTXSq+RdRsF6Fnhvn2CucsHyxzYVicGtqY9JZsI/Og4Tyb2wcKYKqD
         h+WeJGd7Au73Ir6Gwmmq/ybjsMarXcSYqTsLZ/25jLzeIOSysEvW0CfWHKdn7hDrUFLP
         3VZ8UE7Q8HD/dIyX838a0klU35j774JL9cwes0Ah1vFSgEKrn5LsNJYNfkSGK/twVZqk
         Rsd/uKwvXSrdyoBBKLAvtDDf3qSzNkjQFzXlOYHbvI+3WfmSmVsriGduXYS+5J/s8tsf
         JRkRfPFVsgDChbzMhGlsJhBJjnpGJBQu2gHhIhNW3QjoZBUH7M6uJHpfM2MvvtAEJU51
         j0KA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Q+TlttOrTWNB3q3o6Zbb04N1wsFemMMzZbBDHk1hdbY=;
        b=hLMsh9/Mp/Xet3hoGCKIZl2TCNTlys/Bkvg2HLz3hBuz+DiLRO8Sw1Z8PsGPPL+Ouv
         Pf2Ssksxq3MjRGHSDVcN2ckXD3IKmcxbnhDaoDvQeuqgwhDozQ0Ah/U0kF+VGiTfgsfB
         yiQLF3Dp4WCjzgBl6FyVRi8LJqsE327aBEKUHah7mfH1Y75RBgC/KTMBNSnM+EqaIEAQ
         cEt6EJ0+7/lqT0vFCB0ZqnjTOrDn/UmnZv2Y21jYrrQbSMD47T88ioH6mQsWsQdwwQ8y
         Nsgvku/LynY2HphvTUDurO1qUXWUq4DFGbwqON5DYcbP70m3386yspUAIY8KLTlF85nt
         4gcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VyP3SbNs;
       spf=pass (google.com: domain of yosryahmed@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=yosryahmed@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id y26-20020a50e61a000000b00443fc51752dsi18385edm.0.2022.08.31.13.56.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 13:56:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of yosryahmed@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id k9so19841051wri.0
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 13:56:45 -0700 (PDT)
X-Received: by 2002:a05:6000:1188:b0:220:6c20:fbf6 with SMTP id
 g8-20020a056000118800b002206c20fbf6mr13193874wrx.372.1661979404912; Wed, 31
 Aug 2022 13:56:44 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz> <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
In-Reply-To: <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
From: "'Yosry Ahmed' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 13:56:08 -0700
Message-ID: <CAJD7tkaev9B=UDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Michal Hocko <mhocko@suse.com>, Mel Gorman <mgorman@suse.de>, 
	Peter Zijlstra <peterz@infradead.org>, Suren Baghdasaryan <surenb@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Johannes Weiner <hannes@cmpxchg.org>, Roman Gushchin <roman.gushchin@linux.dev>, dave@stgolabs.net, 
	Matthew Wilcox <willy@infradead.org>, liam.howlett@oracle.com, void@manifault.com, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, Peter Xu <peterx@redhat.com>, 
	David Hildenbrand <david@redhat.com>, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	Steven Rostedt <rostedt@goodmis.org>, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, Shakeel Butt <shakeelb@google.com>, 
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, jbaron@akamai.com, 
	David Rientjes <rientjes@google.com>, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, Linux-MM <linux-mm@kvack.org>, iommu@lists.linux.dev, 
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: yosryahmed@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VyP3SbNs;       spf=pass
 (google.com: domain of yosryahmed@google.com designates 2a00:1450:4864:20::42c
 as permitted sender) smtp.mailfrom=yosryahmed@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Yosry Ahmed <yosryahmed@google.com>
Reply-To: Yosry Ahmed <yosryahmed@google.com>
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

On Wed, Aug 31, 2022 at 12:02 PM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
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
>

This is very interesting work! Do you have any data about the overhead
this introduces, especially in a production environment? I am
especially interested in memory allocations tracking and detecting
leaks.
(Sorry if you already posted this kind of data somewhere that I missed)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJD7tkaev9B%3DUDYj2RL6pz-1454J8tv4gEr9y-2dnCksoLK0bw%40mail.gmail.com.
