Return-Path: <kasan-dev+bncBAABBPV63GMAMGQECO7BP4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 388EC5ADA56
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 22:42:39 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id y15-20020a2e7d0f000000b0025ec5be5c22sf3210958ljc.16
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 13:42:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662410558; cv=pass;
        d=google.com; s=arc-20160816;
        b=V1cjOPA23K4k25hkC2jhJEO0bw8wL6xemBZHqV+q+FTRf5JbgOli8ygnYWNBsUjo3T
         OPSGpleOPLpd6FfBFFXWiqIMsImGNkPRdNrZ5rHY1BZkjReRKG44CEGI20QE9oc1jUke
         JkXiMt17vbdKra0UXnDw3JjDxmIlFORJAapB7Ro4R8+wykaXq8lHCA89NLd6uj8shMq0
         b7sHzVASV7NqEtHgLkgcKQiwN516t2d0SIl6rCMSJOukHEPpa5RJ4uRPYuCTKs+9RPKE
         5iCVdkmmy0yRgbOOzS+uZMaflS72G0DBTFBtItYXoWVJUocDW9SwMWvGT6tLHxbR6NDI
         LX9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=d2PhALF0m3xB7pXUpCtnbpI7sNQPA/odqT2IyT5QYPI=;
        b=a/gOXdekoXntlOGlvN/0uGW5xMflCcn8kiEnqwqZ+IovrUnmaszJPxObmsRbKi0G92
         /cKVg5Xjy+WzmsqavXT2jMIXBopPs8M6+fZYIc/11HZxVJYsuTe933cx9YeYS550TTgh
         Xi4bUMHI8oehFxHTU9UQtfMlae/jBn6lNtPBc69mN71h0ph/uH09mq9nwJ8GHexdIcJQ
         TToTMHQ1zf210WO9CrHwvQboDZpLrbh1ti9BkN2ZQ4uIW6CF3sPG+Bnt9h/BwftHoNnd
         t8zlUUgYcCmrxCy5cvP/SzmL2GDnMJHY0KjrffHoKiECo6vdDB4I+WDfB0HF4jPQFbNH
         O1mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hnmt3aHZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=d2PhALF0m3xB7pXUpCtnbpI7sNQPA/odqT2IyT5QYPI=;
        b=O8crJA7IkhgeWjsCwUf2DDPkDniJmbTqIl8dNb7cfEgDFRj7BevUBqjF4bp2mYgWhX
         x5giiBUgXUlBDH30lhQQIX2SXPmAK/d/o/5HpM8Vj1dpdT8d/FQLT+RzQ5cXDsi1baQM
         0TPH9YAN5k+Tw3zs7ByAfQHOlISb4yN0G8vV0fjeLlM+XCx6NB6czcQdUVKVfzC80dgc
         m2lrNL6qC/B9w3u05yoE14Bvp6bK6OtYQa/UaS43hd6+ycqBARTeSnykC20wE6wk5Qno
         dwYaXdC95W+BnQmMJgiLHhx5PDLzJ700oJwPvgGjpgh4aKEhCRBCEkHcdayy0BT7m72v
         zYAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=d2PhALF0m3xB7pXUpCtnbpI7sNQPA/odqT2IyT5QYPI=;
        b=3OTQfVyE/3Yze+3M/sHDUqVTo+cVCDoQGP6hkDYwUYogD69PSS4q2s/te0VrkV7V9E
         p+eQ4r4yhAEYauIKM5k0si6AOm18/ahCmjgfsZvKAsIz08x5w4qcMJhndRZPMtlT4esA
         kTE+LNYcfxd3s7NQYIOsipTwKJg6YQzH0FYWBIQKnZgZN7vpQ5dh4k1s4zRzSolJu/6l
         SCQ6VXZv2YEUM3do2buUh5hKmiKXsSebONqm17XywYW/yWQqXTP5TaY9I7FttGUFlZHn
         VIz8KCuV68xzz1mnBSLjy16Ra+h4w5cvZLkyplES6UZ+VztWYBHWyrQw2KAt2rWXd0Gp
         ER/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo20w7ODnCp+dK3Xq3ZT2+/eTAr+RMGTS11/5CCug6OYX/xFriN5
	49vvutPLdTart+mqM8+2vao=
X-Google-Smtp-Source: AA6agR5EyP0NUwOw38gVjig3LjiHdSuYh4p9CdlhX1g7dzbPG3tiMtgBwHodWrya013HEzBsusgnsQ==
X-Received: by 2002:a05:6512:398e:b0:494:a211:db80 with SMTP id j14-20020a056512398e00b00494a211db80mr6156944lfu.402.1662410558441;
        Mon, 05 Sep 2022 13:42:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e5:b0:497:69:64f6 with SMTP id n5-20020a05651203e500b00497006964f6ls175358lfq.0.-pod-prod-gmail;
 Mon, 05 Sep 2022 13:42:37 -0700 (PDT)
X-Received: by 2002:a05:6512:2248:b0:48a:f8f9:3745 with SMTP id i8-20020a056512224800b0048af8f93745mr15627408lfu.256.1662410557562;
        Mon, 05 Sep 2022 13:42:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662410557; cv=none;
        d=google.com; s=arc-20160816;
        b=wk77lbCgCKsYXHqOK+N5WkCB/iC2cSHHA3kg9e5hgrKTyDEmht2RD6Qn+43Klfj8SM
         ZzuPUX6lTek938z0CojTfgv0iOi5fiNMRBC+o7XTBp1gOfLDvHkKgrXxJ03cY1BHVtWC
         kvjOLAWWRyFi4WWwqG8181BY1UkzXRhxEkjbNQDpm95R+K6O9GvtiNIZ6CPYcJvd6peL
         dnSI1hXE6I+m0gdoAXMgeilAcT8x2RnlhPxe5T0VPg2HE6E0mVJbbfVbgIGImlacT60h
         Q/11GUr8AhCKocZC9DeL6GkSSJo02u9WtQiKeMzr0kAstzyG1lH1oSMOxSgCcpPr2GxG
         SsuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=WiGoaCLsrAtGX5WjZ54R9ZEwhVpr8CfiS3GHCMjFnnI=;
        b=ruv7P76GjMTuIfabmqCWJYw2JQh1Grb01gOnOJmgcOd0HehNeOjrIu1wIuCDobK3wV
         OxV5SSay3qKywMjMw26mEb3XQhv3VtabVapVkVJd5gdPm9F2KQOsfOEVl2z/78TLaK5J
         fPuhwGUd2LNauqZ2HWjWwIAvITk3dqlzxidyQGGrddXV5Cpih/pVIBG8inRP+L9HwqMX
         b8WSdz1KPd2zrohvM0EeAGtb0xP1hbrSVP74M8rXazGbbb331HFPRvt2CqSGWaH5BwRK
         GxVg3ECFO9A+x8wUOyhL6Xw0ycOFVixaHvdkqhhECSlmFi548EmyR3D7AMTSDaEUEp/w
         KlkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hnmt3aHZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id 4-20020ac25f44000000b0049465aa3228si319581lfz.11.2022.09.05.13.42.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 13:42:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
Date: Mon, 5 Sep 2022 16:42:29 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Michal Hocko <mhocko@suse.com>,
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
Message-ID: <20220905204229.xqrqxmaax37n3ody@moria.home.lan>
References: <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
 <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
 <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
 <CAJuCfpFrRwXXQ=wAvZ-oUNKXUJ=uUA=fiDrkhRu5VGXcM+=cuA@mail.gmail.com>
 <20220905110713.27304149@gandalf.local.home>
 <CAJuCfpF-O6Gz2o7YqCgFHV+KEFuzC-PTUoBHj25DNRkkSmhbUg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpF-O6Gz2o7YqCgFHV+KEFuzC-PTUoBHj25DNRkkSmhbUg@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hnmt3aHZ;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Mon, Sep 05, 2022 at 11:08:21AM -0700, Suren Baghdasaryan wrote:
> On Mon, Sep 5, 2022 at 8:06 AM Steven Rostedt <rostedt@goodmis.org> wrote:
> >
> > On Sun, 4 Sep 2022 18:32:58 -0700
> > Suren Baghdasaryan <surenb@google.com> wrote:
> >
> > > Page allocations (overheads are compared to get_free_pages() duration):
> > > 6.8% Codetag counter manipulations (__lazy_percpu_counter_add + __alloc_tag_add)
> > > 8.8% lookup_page_ext
> > > 1237% call stack capture
> > > 139% tracepoint with attached empty BPF program
> >
> > Have you tried tracepoint with custom callback?
> >
> > static void my_callback(void *data, unsigned long call_site,
> >                         const void *ptr, struct kmem_cache *s,
> >                         size_t bytes_req, size_t bytes_alloc,
> >                         gfp_t gfp_flags)
> > {
> >         struct my_data_struct *my_data = data;
> >
> >         { do whatever }
> > }
> >
> > [..]
> >         register_trace_kmem_alloc(my_callback, my_data);
> >
> > Now the my_callback function will be called directly every time the
> > kmem_alloc tracepoint is hit.
> >
> > This avoids that perf and BPF overhead.
> 
> Haven't tried that yet but will do. Thanks for the reference code!

Is it really worth the effort of benchmarking tracing API overhead here?

The main cost of a tracing based approach is going to to be the data structure
for remembering outstanding allocations so that free events can be matched to
the appropriate callsite. Regardless of whether it's done with BFP or by
attaching to the tracepoints directly, that's going to be the main overhead.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905204229.xqrqxmaax37n3ody%40moria.home.lan.
