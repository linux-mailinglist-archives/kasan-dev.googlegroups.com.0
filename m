Return-Path: <kasan-dev+bncBCKMR55PYIGBB5PK3OMAMGQEEFUY25Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 904B35AE0EC
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Sep 2022 09:23:34 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id l19-20020a056402255300b0043df64f9a0fsf7095989edb.16
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Sep 2022 00:23:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662449014; cv=pass;
        d=google.com; s=arc-20160816;
        b=r4i7hBusdcIw1J9oDc8fH/spR5jGhJGAevtMVN58GkmrRvBZjVY7S01bi4n5NdSNlz
         urefE3LG7dV4/UwCNm5e+KrNMj7bovBJLxL1s1HPrydyJpGXAAS3ZYJFtVVQH2kBIc46
         /vM9/HRqfcjctnnNxDZt1z4gJYxKRaXA4KkxBqj3xW5B0VmKOBk7Q/C5xsNYWwR/0abe
         1U8/7S3aqdRu8y4Afmpr8foIboVcfbLT1nHKh6OV2xV6GFK3YDRdTuSon5TSRk5/kbnh
         YS6CWY/6ur5dZL401qWCmp7aoGSeRTJAj98f7WJKK5pPgVK1cviG0XOxI6pu6LkaRZQz
         AU0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=k0Wr0IwBTp5xWaVkIG5vGqDCnJaDZ8JJj7wRjJaCXHE=;
        b=xehCyG6y6jo0WaR2833AsgUl+soyzksUir7YvOXDmy9L0xuxGoKiHQqAW7G+xg49iT
         EttWz0gCAZIvyKro7xPS+4OP2FXlhZnb/uzkb3HHqmYG8G0AMCCvGzBHJEaIB+h91lB1
         DYPbaZ81ul8g3Sl40f4POyN+U84Ota8dgDlN9EBGBpeZp0kj6eik5n/QmKzoYKDfZ9xE
         wmseF4dithDi9mIkMMKv6uRwY4OYBp3Iho9aTCmV2JxYLN8j3/RXOzYwJxkwZnoNVSN+
         k58cCZScJxs25X7WucjpjKbL2vlqgKXQxiEfJnimtiqepSM6l0GX7RqsObumDM+lcTJQ
         01Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=WccstuGc;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=k0Wr0IwBTp5xWaVkIG5vGqDCnJaDZ8JJj7wRjJaCXHE=;
        b=d67/UB6DR5avynR2qiSJG7Bqg/4A3ZphT8mr34dQiLR8o8y+U/m0MU2R7raI8DbiVv
         nUwULwm/mHcjtdBJTK+2D9kGtGGV021bdlOf8fBqv3mXell57bwSQbdoz+oBZdSt2Hz2
         0+WcdXEOtE4PhqXYo0Nfif+gyCUAdfPVs8GjyTwqVzpf+7Ilp7DSU/u7FHxhYGg+NkhR
         trzgUVYL/OLRl+r4vafdzArCJ1omNWwadRPuM13appvko4Z0l7iP6Xquvwa/UKWmusUD
         5wfxrk6D4+gDjCbdnin8C1Vp0+xYh+UlNI5J74WMGPCF4905V18/CY7bFjBGpaO7RlNh
         1NSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=k0Wr0IwBTp5xWaVkIG5vGqDCnJaDZ8JJj7wRjJaCXHE=;
        b=YL1yJafQ1Gxhr7hXmInJPPD1kJZAgJdcrj0x6MqRN3TZ7xHS3N9Fk2SUiIMv0/Q/eP
         2VI6uUhTHxQqK9psjIo/Y3a1E84g88g407l6pIfmq7tzDAfMyQc8UqhK55VrOSaYc9Q8
         gLLQunYb2N3CSr1md0orRz2c0Cm4MlAIb7hTjLatfoPITMyXtYD3b3JGnjysy0iVp75c
         HSI0pTGwdVhKaU22FZZod9GVw74GXsGQPWdxKYAfkL5bF33jN3SQ8h8gjWAaOV6j/gAr
         Ffu0USXWOr+A9m0079aBdJWgQgwCX7PYupHPjvEYvNU4apwFLQ6PYwYQ+T3Qnd1UU5zN
         WLRA==
X-Gm-Message-State: ACgBeo2gdZHT6g/HmE4XI7f6a3hUliV/kc0hV9PpKkfgSEN5PlLmqjJ7
	sjdwcgdu41t3+/GTQLVGXEs=
X-Google-Smtp-Source: AA6agR62770q99qkVt/rF+ySJZs/ns1FgN/2bPmd89PZnB++iGEAQySNl+//DiH8vUjSI7WyZuKckQ==
X-Received: by 2002:a05:6402:cb2:b0:44e:4336:d2a0 with SMTP id cn18-20020a0564020cb200b0044e4336d2a0mr9435925edb.209.1662449014134;
        Tue, 06 Sep 2022 00:23:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:40d2:b0:43d:b3c4:cd21 with SMTP id
 z18-20020a05640240d200b0043db3c4cd21ls802687edb.2.-pod-prod-gmail; Tue, 06
 Sep 2022 00:23:32 -0700 (PDT)
X-Received: by 2002:a05:6402:5002:b0:444:26fd:d341 with SMTP id p2-20020a056402500200b0044426fdd341mr47394074eda.351.1662449012724;
        Tue, 06 Sep 2022 00:23:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662449012; cv=none;
        d=google.com; s=arc-20160816;
        b=FcdI6kzgzb67mx64flAQ0JM2SeQXRw3Eh5y4NiQMAoKIPQf6jYP+EWzO1p5jpWOxBK
         IxnklC06SJ3XvzhnhNRv+8ZcKhKLQRo7zPa4a5XFpZGtdHHndjR9/Nz+JN6wn31i+VPA
         c8SFlR54HWFMKOwbG/W7lYk7XqNu/CycoD1MTYhOnVKwdm6ydwemVr7UORiosXqUtu6B
         dBdqGiQNBH91OhvV5xDN0uaieDonbmV3vxiYCHc9e+Y0p5ypiKr4z4fAZ3Guk6Sk/CTC
         KAF7fmrM4foUjIK0PhphfYLEACjOgSlaiXVqcDGj/R598csEsh5Ti+YWGJj8cIhU2kmb
         1bqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yWige9mo0MBBtPav5dIlbqrSvO7RJRBpbBUTOf+sq9M=;
        b=M9AKFI7q7fQoCMU6wfhVp07MXtZUPN9maQjMyUMxeIN4fDsmBDEmX9hfwy6zfX0Qgz
         nb1CpvGg7C54fnfrUr/MRBQMl+2Ml5vG/uH1z4C+kLMnutas2KWXGX7ffjdZ0xuJOo3q
         nrZtHlkLmWjr2euaZDt3S9snh5J0tZshV9wh6v/xcR8VwqO60B/t2J2q3njP5hx1kvBf
         0D7qNjRFVCjNAeSd/YKceOqVYxHNdPhV0Lbc5RghLosF8CADEAP9stwIoBeHd337fT2U
         GWplqN0Tco1xabpm6H/HGzIR3w645/piGD21yCyNj/dYwib1tCWICq2epUhVBRQKamlX
         Y/0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=WccstuGc;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id q5-20020aa7d445000000b0044db0bb77bdsi401153edr.5.2022.09.06.00.23.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Sep 2022 00:23:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 4F2371F964;
	Tue,  6 Sep 2022 07:23:32 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 2160313A7A;
	Tue,  6 Sep 2022 07:23:32 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id f8r7BnT1FmOCNAAAMHmgww
	(envelope-from <mhocko@suse.com>); Tue, 06 Sep 2022 07:23:32 +0000
Date: Tue, 6 Sep 2022 09:23:31 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, Mel Gorman <mgorman@suse.de>,
	Peter Zijlstra <peterz@infradead.org>,
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
Message-ID: <Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
References: <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
 <20220901201502.sn6223bayzwferxv@moria.home.lan>
 <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
 <20220905234649.525vorzx27ybypsn@kmo-framework>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220905234649.525vorzx27ybypsn@kmo-framework>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=WccstuGc;       spf=pass
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

On Mon 05-09-22 19:46:49, Kent Overstreet wrote:
> On Mon, Sep 05, 2022 at 10:49:38AM +0200, Michal Hocko wrote:
> > This is really my main concern about this whole work. Not only it adds a
> > considerable maintenance burden to the core MM because
> 
> [citation needed]

I thought this was clear from the email content (the part you haven't
quoted here). But let me be explicit one more time for you.

I hope we can agree that in order for this kind of tracking to be useful
you need to cover _callers_ of the allocator or in the ideal world
the users/owner of the tracked memory (the later is sometimes much
harder/impossible to track when the memory is handed over from one peer
to another).

It is not particularly useful IMO to see that a large portion of the
memory has been allocated by say vmalloc or kvmalloc, right?  How
much does it really tell you that a lot of memory has been allocated
by kvmalloc or vmalloc? Yet, neither of the two is handled by the
proposed tracking and it would require additional code to be added and
_maintained_ to cover them. But that would be still far from complete,
we have bulk allocator, mempools etc.

If that was not enough some of those allocators are used by library code
like seq_file, networking pools, module loader and whatnot. So this
grows and effectively doubles the API space for many allocators as they
need both normal API and the one which can pass the tracking context
down the path to prevent double tracking. Right?

This in my book is a considerable maintenance burden. And especially for
the MM subsystem this means additional burden because we have a very
rich allocators APIs.

You are absolutely right that processing stack traces is PITA but that
allows to see the actual callers irrespectively how many layers of
indirection or library code it goes.

> > it adds on top of
> > our existing allocator layers complexity but it would need to spread beyond
> > MM to be useful because it is usually outside of MM where leaks happen.
> 
> If you want the tracking to happen at a different level of the call stack, just
> call _kmalloc() directly and call alloc_tag_add()/sub() yourself.

As pointed above this just scales poorly and adds to the API space. Not
to mention that direct use of alloc_tag_add can just confuse layers
below which rely on the same thing.

Hope this makes it clearer.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yxb1cxDSyte1Ut/F%40dhcp22.suse.cz.
