Return-Path: <kasan-dev+bncBCKMR55PYIGBB36622MAMGQE3VYDVCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BE975ACD72
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 10:12:32 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id c18-20020a2ebf12000000b0025e5168c246sf2610113ljr.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 01:12:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662365552; cv=pass;
        d=google.com; s=arc-20160816;
        b=xJQKlUiiFV8TeGXR2wVhos5vxwSB8tsQak5+tk93OHYX/cJmKMViCqFjnpQbwhWkr1
         rLFoPkiukBcfmhPmJozxQPkpQkhZlCo7k385AkarLcjVu/8VNrozOWgyEcckHvvXpght
         feRHBoelJnGcBVcJcSH7AnwZoZ8xFj2KBL7pQFAj1NJeLlVVMDjG2kTvrhy9l9PJHPZy
         d8ddz9TzLiKA01I3o8r/66J18Emqu9ih+/9IfVZyMQLeH9GdIyPHCHMidtP5Y3RW70Ng
         Jm4AuqXdIXW8fjCzpq0avxjaVne1mpeaap5UXSS3oxYKM+oB9E1ZHUoJWwE92lr7ZkQh
         OtwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=DWBz/NOjAjUwTdZIqqf6LI+A3a1vuTbwBii5umP2Q0g=;
        b=a8cwTWYS8kVq03moPXeBOj5J3i2Fd27Uug2QBajPtrjk9O/9JXOlLH3Vn6sNCi0TWH
         6sY6DA+/QfBYCfHocPWLD+M/ydA3/TGWpA4AzT1hS+qk+NTuZdS2a/D46Vvdy1dsiTTN
         pldN1dXjlVOYEPDJoKvPpdY6Q1opIa51LzCcHutOlGV/N1hBUlTeHKKJ4DXq6jYTTNGZ
         zRlQhzeaB0wU90amSgERz2/uLYtsfnKOS8NMVKuuHIBWkFrQGuiRNfE8jtD/r9IEY+2c
         Htt7pMXPGqQ0m9JGOeBWTWrrtnAk5cLD3FZ16r+1110ZbPnedXV8UhnWOGQNyGmTKLaD
         Oc6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=hvJuONTl;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=DWBz/NOjAjUwTdZIqqf6LI+A3a1vuTbwBii5umP2Q0g=;
        b=tX1NZBOpOhxixZ49o8DGz2SI5tRvp4Isive3A8wwdFYBn92cahuCSkxLp/sFytogyS
         iWTttTmUgjeZke6Q/SbvkcRlWILlVD2Hcc9pi5LCP+zp8kZscAfX/+/wUXBl0xdNY0k9
         m+xLjd0O3GFoXkJNirv7ldHnImD9Y4hi4sxpVpPI4XPGfHOQPQjb6WNn9SN77svYcp5+
         73/B9bhoOZdkO2+G0QndEcH5b3V2X5IsPJpm2eG16xAIBzPfPiuR8tjQ8EgPsQgMtkYC
         aAb7i0J/DK/dDtMpl26ypafYfYeCW0trw0KEm0zvjFaHTSTUBZDN8Off7y2JNPXNhn9X
         Hgeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=DWBz/NOjAjUwTdZIqqf6LI+A3a1vuTbwBii5umP2Q0g=;
        b=U95Nh9XvOHhSLa7+NCq/Q5H4xi9cdTyL/Q/W7E1fQj47W7dv/0VFjbuW6mq0BNetWa
         UiZEGm8ccWydL4Lfn0LmEDy0q07jDPc259oZXvXV4UaEQuJRwr1G5ce289iwPT11ZLQt
         JytBSXyFA+MgqKCaY/fWJTGMXPCWtVgP2KX0nxWA9nWULGFErMFlIGUIbu7OuTQHzu+K
         e7907mlZUmdhE5T6b3QTNKLWEvqvLDxfn7xDBHx0z/iqYqobAZHK8qKe/WvGPuhSLUtT
         eZnop8hWDwTJweWUKzJaYo4BrzfayzH2ENqczwTQw4h2LKrwmwOBsaJ+ncKaB/iPf6V0
         CzZQ==
X-Gm-Message-State: ACgBeo3W/RQ2ox0pacLht2wNp7+Amtay8+LiY0x2ddNt9k8pJRQd1C6m
	TmIafhtaSZUhNyg0JK+AZZo=
X-Google-Smtp-Source: AA6agR4u3r7J+HpdhXF/5yNBYKk/OAcbj8cPNpT0v5d+pBv457i2NG7mQOOKWNOL3pe7s9j43OH9Cg==
X-Received: by 2002:a2e:94c7:0:b0:265:6126:6562 with SMTP id r7-20020a2e94c7000000b0026561266562mr9739177ljh.150.1662365551660;
        Mon, 05 Sep 2022 01:12:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls4329067lfo.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 01:12:30 -0700 (PDT)
X-Received: by 2002:a05:6512:151f:b0:494:af94:9f59 with SMTP id bq31-20020a056512151f00b00494af949f59mr3714134lfb.587.1662365550182;
        Mon, 05 Sep 2022 01:12:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662365550; cv=none;
        d=google.com; s=arc-20160816;
        b=DHajzZio8yN09DSNzD9fadDmsZT+608Xz3mYPzoSLeX5B+0M1nPdRshV3iiGZl/h6y
         ahRW/jg8TpVT6lo6PvtnoS7CYkGTc0P6fbM2KfCuXjl9PotTeZvMFvZrvzPo6rPUAXvE
         Y/vnWv7ZMIk/9r3P09ykS0yRLMZbKgZZF+EPLN5EP8pMDTbEHYunJYoezbdHWa3KY0Ct
         a8unfHZmwyKzmjvjOnwnMZBjPIqFZals+/7VvhpxMl7xwEKp2JY60Ylgi6wfHHO+HTF9
         t3q71mOmX/sLUC5cDJtCkFwbnUdAEylqSDpvUm2TV8h+mI1Bgqzr+m6LmfaJxtoySbMg
         r05Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vLBCtbeiMkaT10it/2QfW3oy9NGXJ0931FNcJJeTs+E=;
        b=MizBou698126yDqswYEgDbd2c0DJtvn6JBrekBAf3X8bKm2C988KD+duBKwgCcOGkm
         lOUAjnJ9HXNpasE8zCD089qalNrLZd+RJPfqy+dqYekeanwVbSz3mjxbsf00nR2m95j7
         jaLZvPZNI30Zq7WAy4rRLc5rX5yj7LJIV7Ukx+YfcCYlLr2uDiirIMRCtKq9EFAbzJey
         QfXQcLDo8MI0T5n4YrjgXJv3bUP0GBuuxmGEjabsua+sqpePW0vAjXDn6ZB8FyfnK4aY
         bSy23fUjJbgbf4hV4caB33OrLoYShnhidNokhX38LrfP1TScCk9aSXIkiCmieLjEiNYS
         jxLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=hvJuONTl;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id i24-20020a2ea238000000b002652a5a5536si343994ljm.2.2022.09.05.01.12.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 01:12:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6CC095FCCC;
	Mon,  5 Sep 2022 08:12:29 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 4046313A66;
	Mon,  5 Sep 2022 08:12:29 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id vpI8D22vFWNpBAAAMHmgww
	(envelope-from <mhocko@suse.com>); Mon, 05 Sep 2022 08:12:29 +0000
Date: Mon, 5 Sep 2022 10:12:28 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Davidlohr Bueso <dave@stgolabs.net>,
	Matthew Wilcox <willy@infradead.org>,
	"Liam R. Howlett" <liam.howlett@oracle.com>,
	David Vernet <void@manifault.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Benjamin Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Christopher Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de,
	jbaron@akamai.com, David Rientjes <rientjes@google.com>,
	Minchan Kim <minchan@google.com>,
	Kalesh Singh <kaleshsingh@google.com>,
	kernel-team <kernel-team@android.com>,
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <YxWvbMYLkPoJrQyr@dhcp22.suse.cz>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpFrRwXXQ=wAvZ-oUNKXUJ=uUA=fiDrkhRu5VGXcM+=cuA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpFrRwXXQ=wAvZ-oUNKXUJ=uUA=fiDrkhRu5VGXcM+=cuA@mail.gmail.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=hvJuONTl;       spf=pass
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

On Sun 04-09-22 18:32:58, Suren Baghdasaryan wrote:
> On Thu, Sep 1, 2022 at 12:15 PM Michal Hocko <mhocko@suse.com> wrote:
[...]
> > Yes, tracking back the call trace would be really needed. The question
> > is whether this is really prohibitively expensive. How much overhead are
> > we talking about? There is no free lunch here, really.  You either have
> > the overhead during runtime when the feature is used or on the source
> > code level for all the future development (with a maze of macros and
> > wrappers).
> 
> As promised, I profiled a simple code that repeatedly makes 10
> allocations/frees in a loop and measured overheads of code tagging,
> call stack capturing and tracing+BPF for page and slab allocations.
> Summary:
> 
> Page allocations (overheads are compared to get_free_pages() duration):
> 6.8% Codetag counter manipulations (__lazy_percpu_counter_add + __alloc_tag_add)
> 8.8% lookup_page_ext
> 1237% call stack capture
> 139% tracepoint with attached empty BPF program

Yes, I am not surprised that the call stack capturing is really
expensive comparing to the allocator fast path (which is really highly
optimized and I suspect that with 10 allocation/free loop you mostly get
your memory from the pcp lists). Is this overhead still _that_ visible
for somehow less microoptimized workloads which have to take slow paths
as well?

Also what kind of stack unwinder is configured (I guess ORC)? This is
not my area but from what I remember the unwinder overhead varies
between ORC and FP.

And just to make it clear. I do realize that an overhead from the stack
unwinding is unavoidable. And code tagging would logically have lower
overhead as it performs much less work. But the main point is whether
our existing stack unwiding approach is really prohibitively expensive
to be used for debugging purposes on production systems. I might
misremember but I recall people having bigger concerns with page_owner
memory footprint than the actual stack unwinder overhead.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxWvbMYLkPoJrQyr%40dhcp22.suse.cz.
