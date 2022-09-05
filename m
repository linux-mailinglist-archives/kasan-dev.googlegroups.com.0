Return-Path: <kasan-dev+bncBCKMR55PYIGBBJHQ22MAMGQEZ4NNBTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id AE5D65ACDF3
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 10:49:41 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id p19-20020a05600c1d9300b003a5c3141365sf7155582wms.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 01:49:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662367781; cv=pass;
        d=google.com; s=arc-20160816;
        b=ToH/VIKIG2nucjiDeDM+c+/+3Qy5+/zpDRpytAh1BM8dDycB/krxyAV8uthz/ZnEKj
         g+ym+15q/ltkKgWTdMsu4OCACaEcDSAmpx7D27fXjFIqbsGXl7HHR9CGFByvM+0PZnvC
         t3wJhui6YbFsGUAp8/ySEoT0EFOd4DBF7FgOGNl8Z755NhRs6LAhBjDU2YZPYqY6F/5Q
         TkfOMtsjEmJspLRLGJfT6o5SDKl34wOjE69hjaZ2iL7Rumv5BFpBdrO/WdaHP/IakmRp
         Pn8JLg6AK8FJDOAXL3EqUM7cOyZ8cFpHQN3HcvTbQ7/b57KeAod+uaw8zKUBBW3yUTkv
         j5uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=riL0GCCwc6WcVSXpfSgF3ULdZ6fltQbEM/2Jdf2K54k=;
        b=Vh6CkuP/bAEKtaGm/70CrbpToCcXo2wkA5J4Xf50RN+qROqLwxwOOCJNi9gjZrCLGf
         KwLOJ7A2g1z1r4Q0U0c/qdzzY/avrQXOfrVB+MTEYxLQ+qu0ZwxF/76jVehJdIOmiA5W
         n5HwiZZToZEmosWGRD2A+tIulGzr0DAyTGwcK1SJAw1jtHdPiMfXTemNoIc4TH6MfcOM
         nH9HsikNeq3xV7IsBp/wp7o/N+ZUtQ2jFMDcxr/DE0aQpApYVIDj/fanq0HH7fl5xfMV
         IJV/xVDqxn1tKiGIJNPYiv6VUjXwLmq71wOjPUGChVSuOb1PDwGRpFlL6wq0PLhgI1yS
         L0PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=naI5Af2D;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=riL0GCCwc6WcVSXpfSgF3ULdZ6fltQbEM/2Jdf2K54k=;
        b=f6QU5kuQWPyrTFpgLvOYzUmuEl9MwSqtfJtanleSW5FambuMrQCsVs/fkiPDakvyJV
         mNgAv0nGzcnC8fEhLCcFEpxUe1YRVhVrkV9TB6w7xCgla+mlvFaSvrYDdA0Hb9gxaNGw
         /JNTp6JJo4EzC9X2KL4qKEKYisYfkszGi+ipSKmO6yPzamM7w1p7xBqaNoMnHaaJC3oa
         tnkx/yzXuAOD0xwVmVoMTL6U4RY8M+UjQIxaYTfWpPmo232RjO9iBycEHJCwQvGJjv9H
         Ha9BlqQpUaC+qmh4qoUumDoCq9DduVrUwuO7CELl3I1ls+ItP6lJeynkElXVLaDjV6Jv
         n+rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=riL0GCCwc6WcVSXpfSgF3ULdZ6fltQbEM/2Jdf2K54k=;
        b=OfrZPkzhPehSjSzYH6lD9HBViz2jC+0Q1621LQ67Zyh+G+/4ZmIijvyRFOGNn/3YaQ
         YoHTRwH10JLws62vcd/jtK81T/yZ35Ffpq/qaqhIIqNjICs/eAA6kgRYsfE/nTN4TPTB
         NZkhbwNFlvO6W7RhAmwfa/aa3fai2dmKxrCj+vTwld1N/ix1C99TYq5/KnziplpKQSv9
         IKCQqWMsebL4+xKnbQz5s8cnJ5cKo4StBTOhpO8jrIUop37Rg53L7vvNKFJhKLgo9EQT
         r/2A5XY/1NiQEdDVnlfNJM9SjdBJudrHHrn/Mnl62GdTjdEL2qa715pN20Eeg+Kd582a
         EJaQ==
X-Gm-Message-State: ACgBeo23aCFPTTURctNtw8SRHWY/gY1QzyNd3ZI7BDckLbT1D6QMXLyD
	gMjGH+UfHg3/lIXoeEin/Zc=
X-Google-Smtp-Source: AA6agR6fOhFoj9FWfYHkJ1s3XOjqqn/5l3Ldjxxk106ylkFUXhRdm6QJvrE40KJvEkmpsT7i1QdR1Q==
X-Received: by 2002:a1c:7708:0:b0:3a5:5543:cec4 with SMTP id t8-20020a1c7708000000b003a55543cec4mr10281895wmi.47.1662367780946;
        Mon, 05 Sep 2022 01:49:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:60c7:0:b0:228:c8fc:9de8 with SMTP id x7-20020a5d60c7000000b00228c8fc9de8ls609184wrt.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 01:49:39 -0700 (PDT)
X-Received: by 2002:a5d:64ed:0:b0:225:11d4:76d1 with SMTP id g13-20020a5d64ed000000b0022511d476d1mr23584669wri.579.1662367779732;
        Mon, 05 Sep 2022 01:49:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662367779; cv=none;
        d=google.com; s=arc-20160816;
        b=R7dnru7VtpUtKPoZ1Lb1snEpzSST4W3Z2hEfQv7MabIfFWl8zRgMYJga0o3fxr1i58
         VduL3//PwyRirPXd7KC9tUTHfjmEDmRyA1UUkBb4ksQ0EFlyPrbqjoIDQpPmpCoNehfE
         pI5W5tacM7nrI8R+7LnDae/HM+bi7SztK4HMkLqlrpZDqRiilWv1KFwBMF5UyIMFgg8T
         X6EEWTgmLUMDtcW6ASl2s8g3H1IBbiryM0tItIPAm/IgZjr9+7V/grlufypT44EkwKTV
         Wq7CgaEyerIQ8SsvxYDwSltrplK+/V0yk/XmVg+pihyMxRMlrjVzv4dTYwycblL8e3xF
         RJXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xc3ngfTbFfRO12fCwmaAUkvuolnuXfU1jb4qhmTTa9o=;
        b=Z0k2AcLintbKTvEDpRkA7hwjcTMYdCr19MEw0QwPTP0pgL1OMcifBseosGKwVXW2WT
         GNY+qyTWyETBd1rrKehrwjpxqbC0SCo2lYvsangs01zDGxdOsiwQGaXmWT+kf1COG3a4
         xGTQHdyVCYZBr7hjfunM5PN0pGi0suuOJzr9Ju5zIISBiS4RCmWngREcMemCmya4w8iA
         uxh00Ga/y1t9wcjwA0S8iJYhZxmdAo7aFwqczqsgmgGZ8jfYnN0bwCVwQSRcK58KQz+X
         VvjL3QOj6LgDRjBEdnQGUmNbe+Rx7+CIaY8S2lEKkbO7n8vuWZizKEXKlkZYuWSlzD+Q
         fjFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=naI5Af2D;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id c7-20020a05600c0ac700b003a83f11cec0si477351wmr.2.2022.09.05.01.49.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 01:49:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 5BCEA38129;
	Mon,  5 Sep 2022 08:49:39 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 2A198139C7;
	Mon,  5 Sep 2022 08:49:39 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id UM+9CSO4FWMqFwAAMHmgww
	(envelope-from <mhocko@suse.com>); Mon, 05 Sep 2022 08:49:39 +0000
Date: Mon, 5 Sep 2022 10:49:38 +0200
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
Message-ID: <YxW4Ig338d2vQAz3@dhcp22.suse.cz>
References: <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
 <20220901201502.sn6223bayzwferxv@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220901201502.sn6223bayzwferxv@moria.home.lan>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=naI5Af2D;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as
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

On Thu 01-09-22 16:15:02, Kent Overstreet wrote:
> On Thu, Sep 01, 2022 at 12:39:11PM -0700, Suren Baghdasaryan wrote:
> > kmemleak is known to be slow and it's even documented [1], so I hope I
> > can skip that part. For page_owner to provide the comparable
> > information we would have to capture the call stacks for all page
> > allocations unlike our proposal which allows to do that selectively
> > for specific call sites. I'll post the overhead numbers of call stack
> > capturing once I'm finished with profiling the latest code, hopefully
> > sometime tomorrow, in the worst case after the long weekend.
> 
> To expand on this further: we're stashing a pointer to the alloc_tag, which is
> defined at the allocation callsite. That's how we're able to decrement the
> proper counter on free, and why this beats any tracing based approach - with
> tracing you'd instead have to correlate allocate/free events. Ouch.
> 
> > > Yes, tracking back the call trace would be really needed. The question
> > > is whether this is really prohibitively expensive. How much overhead are
> > > we talking about? There is no free lunch here, really.  You either have
> > > the overhead during runtime when the feature is used or on the source
> > > code level for all the future development (with a maze of macros and
> > > wrappers).
> 
> The full call stack is really not what you want in most applications - that's
> what people think they want at first, and why page_owner works the way it does,
> but it turns out that then combining all the different but related stack traces
> _sucks_ (so why were you saving them in the first place?), and then you have to
> do a separate memory allocate for each stack track, which destroys performance.

I do agree that the full stack trace is likely not what you need. But
the portion of the stack that you need is not really clear because the
relevant part might be on a different level of the calltrace depending
on the allocation site. Take this as an example:
{traverse, seq_read_iter, single_open_size}->seq_buf_alloc -> kvmalloc -> kmalloc

This whole part of the stack is not really all that interesting and you
would have to allocate pretty high at the API layer to catch something
useful. And please remember that seq_file interface is heavily used in
throughout the kernel. I wouldn't suspect seq_file itself to be buggy,
that is well exercised code but its users can botch things and that is
where the leak would happen. There are many other examples like that
where the allocation is done at a lib/infrastructure layer (sysfs
framework, mempools network pool allocators and whatnot). We do care
about those users, really. Ad-hoc pool allocators built on top of the
core MM allocators are not really uncommon. And I am really skeptical we
really want to add all the tagging source code level changes to each and
every one of them.

This is really my main concern about this whole work. Not only it adds a
considerable maintenance burden to the core MM because it adds on top of
our existing allocator layers complexity but it would need to spread beyond
MM to be useful because it is usually outside of MM where leaks happen.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxW4Ig338d2vQAz3%40dhcp22.suse.cz.
