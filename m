Return-Path: <kasan-dev+bncBC7OD3FKWUERBF42YWMAMGQE7I7ABGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 475C25AA446
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 02:23:52 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id e30-20020ac8011e000000b00342f61e67aesf435213qtg.3
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 17:23:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662078231; cv=pass;
        d=google.com; s=arc-20160816;
        b=UothZcKL6AMBBUW2T2RX9cMOM5RvQfktLs0wXvlyxIkFuaqmmZsXXtaoFeEzg+lpaJ
         2dGt1mYzxr8IhJshv5FQBSKi/uh1+lvGkyApaIkWxJnU5ADUk/skjvBeJ7KLtOtBk57B
         EPoBuY9zsx75b7vNsCnt8RTcQNQGvWoFFdWPQWe7Xk2OzTUNRnzJrYYAGLBdzYUaEWbu
         +Cd9jw4wuAdNT3C/5tXTeUdQL0dxYk0LdDHe6lXwVpkxzqrCxxcVl6akVEn96JihOAV/
         lsCRGfTZNbGfC4Zu0G/PfOnis1Iy98qZmg7BpoDYftRqFmE7W2ut+8pXlnjnD+P977ah
         g2Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eI794xs6hCJ2u4ohPDShFu7e3RIegVhaEgBGd5/FXbQ=;
        b=xdpLLXkTcCMOPpqb3ZJpMbfK+uJ/NXZrFFn+zpAaG6ZCJwb5xwjyqHGaqZqNAsVts9
         aqIm29igD3hLMWkJ1tQwXDLwS8GFl9uG6txPxnRPooELaVnYPE+nwzngOK8E4B9y+Na1
         VKHLIySrUK3ZFOyr6RPKCr6RfhXeeL362XcU9Af/Q3M2gkk9AOSzpy7q3mmFeaUPSC+T
         rMgPztVsf5/aOpbOe9Xr3sgGIB71Et3llXzbxQpgAE4Bs6E0Ea4NbToKR5XFNcQ6q491
         vkKfRz0m9IVO/GVYFdk+vfqwXFC9AnQ9uQWDqWM4AH3dBZx4uOabKMuKezLH2Xrv2NeD
         cY+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=G77qRohb;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=eI794xs6hCJ2u4ohPDShFu7e3RIegVhaEgBGd5/FXbQ=;
        b=hX0/ILc84GoT9TKqLAl/eZ/iDip4gk5aVWS1YGURqkmce5YKO5NMkcgutL1fIuR7WE
         qr0ijrPIFddr5l17t8iM9CAfVzObIiNBKmL8ZrS971FZhFPxD5V8KvCoc3L89BBzZkCZ
         vjtwfngbmagycfETw6ws+zcOiHYNdOBZmvFI6rmCAa1vAcOdeiNrcbiyc6sDJgJTxdkG
         GV+Erprep9BJsKgsAlSbuSgUEEdQzLK2L90WbjEH7RYJVYTv9jvm07QWmScFk0nxsZ/2
         8r9lndt5J6m7tM7gw+8Qb2CHSZVKimSldy4Doz+0ZO+Ozud9lecjnYBeas/niTTwCOLB
         32TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=eI794xs6hCJ2u4ohPDShFu7e3RIegVhaEgBGd5/FXbQ=;
        b=DwrwX09CJmOKEUCFLe73p2vuEwF+vLPy9mV2DbdqtwVRLwPk1MH4bhzBZVbIaLt99V
         KZqgsdu9o2NlPi1BfuW+bGKHxP5SPZBNfpKY+Qr76AvppB+LlwivskllFY1xriKNMlvi
         tcrkJ1WwjDKDauCeH6EaUFdvzrZEIw5ujX1oxmFUTuMz19uRXVWsWdbvwKNY2u3KDTZK
         PlrzAOGiCzuEEnvSAorz5bLYXAnMmjOsP7Jp44tMIBeBVVsQekjfK0+/6bHzo/fIYB8V
         d/s6ezfcbQTBIryLY+ES19L/qK7ZrNEGuidGVZXBDcqCA/Ii7Llo6IBOJXPLWykCeVY8
         cYDQ==
X-Gm-Message-State: ACgBeo25NxCwVJC6B4i2GsGs9U/7xdSeuL/glTSjvYMv6/z/fFTG+y7p
	Ut8FV3+/Fc8sibMW7UcEVYM=
X-Google-Smtp-Source: AA6agR7/f69UDZCJNyaslZ1LwRV2D6s+MyEEnON1uCT8Ka0aYbrUDTQHNWKrHMQVhQpbT0hJl1EAYw==
X-Received: by 2002:ac8:5884:0:b0:344:6d9a:1e43 with SMTP id t4-20020ac85884000000b003446d9a1e43mr26961709qta.623.1662078231217;
        Thu, 01 Sep 2022 17:23:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:12b8:b0:6b9:4aa2:f6 with SMTP id
 x24-20020a05620a12b800b006b94aa200f6ls2600740qki.2.-pod-prod-gmail; Thu, 01
 Sep 2022 17:23:50 -0700 (PDT)
X-Received: by 2002:a05:620a:12c3:b0:6bb:f708:585e with SMTP id e3-20020a05620a12c300b006bbf708585emr22283907qkl.490.1662078230709;
        Thu, 01 Sep 2022 17:23:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662078230; cv=none;
        d=google.com; s=arc-20160816;
        b=WhzYenSFteUaCSCkNh7G0rua0u1V7g6bYWmjor3Xz2Nlq1piR4oBrqK3E4PyMkC6d0
         Rkni1RJeOlyRihMlzyAS+Z+w/T6gw2N41Y1smvQpyhhXx5mwA2KhcF0vjn5wBgbBR+U8
         zdXMP9hmiMMoa++s8tburINWNmUVzMz/r+Kk8u6sWbuypJjJnySb/LqCPOebaqlYcmmQ
         c+5Pf5E1S/UJcOdt8+SjrIdf8PxMUgBc1VdxlUB95tDE0VxrlcdaAMaPmvggt5bOzxR1
         pzVHwRbj+qfQVthfjz7Ad33bUMqa7XNFf3ciNoztYBk7ddJ+s+wPYxCLqJrGmprSEZ5u
         qJCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=id/aU8twWVdV/Bsd/keLwAwE0+9+WzWIEZXVP3pbEN4=;
        b=XWOy8xn8KoeNKpRiu8a1x0iQwIIFar7ouUdnc5yPLXQPBCy3TcVozp7EuBhloNF3NN
         ZPs5z6KU0zWjn9kLmLeIl4vPIdTkgoeUlyWIkwoBs524Vewykkgo+LJeTVEXbyG2S9dk
         kak39IxravDkgHrHG/SWe0RG7Rt2EdY83uEXzmRsoZOfevEiYmL7dahvEKz2Cj1Arqp1
         shy1WMvewuGwZtv38bpEEfquAlWTa2x7D7B3sVXV1FGRl+mEKOfs232ZUzqmyqWr8H7M
         5y94h5Q9/lWplteF2jCDRlO8PXDQn/xSFPfGeWRQjeTOfKx+1HJo6YBnuveEzxDkFQZB
         wPew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=G77qRohb;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id 5-20020ac85945000000b003437deaebe4si8988qtz.2.2022.09.01.17.23.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 17:23:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id 193so1033345ybc.10
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 17:23:50 -0700 (PDT)
X-Received: by 2002:a05:6902:1366:b0:691:4335:455b with SMTP id
 bt6-20020a056902136600b006914335455bmr20559494ybb.282.1662078230135; Thu, 01
 Sep 2022 17:23:50 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <20220830214919.53220-12-surenb@google.com>
 <YxFB3tlMqakx+hiL@P9FQF9L96D.corp.robot.car>
In-Reply-To: <YxFB3tlMqakx+hiL@P9FQF9L96D.corp.robot.car>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Sep 2022 17:23:38 -0700
Message-ID: <CAJuCfpECU8NsC_kUSE7ef33_HUkZP5S2rEbxOvfnmM2Qb4TKBA@mail.gmail.com>
Subject: Re: [RFC PATCH 11/30] mm: introduce slabobj_ext to support slab
 object extensions
To: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Michal Hocko <mhocko@suse.com>, Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Mel Gorman <mgorman@suse.de>, Davidlohr Bueso <dave@stgolabs.net>, 
	Matthew Wilcox <willy@infradead.org>, "Liam R. Howlett" <liam.howlett@oracle.com>, 
	David Vernet <void@manifault.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Laurent Dufour <ldufour@linux.ibm.com>, 
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Benjamin Segall <bsegall@google.com>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	42.hyeyoo@gmail.com, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Shakeel Butt <shakeelb@google.com>, 
	Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, jbaron@akamai.com, 
	David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=G77qRohb;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2a as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Thu, Sep 1, 2022 at 4:36 PM Roman Gushchin <roman.gushchin@linux.dev> wrote:
>
> On Tue, Aug 30, 2022 at 02:49:00PM -0700, Suren Baghdasaryan wrote:
> > Currently slab pages can store only vectors of obj_cgroup pointers in
> > page->memcg_data. Introduce slabobj_ext structure to allow more data
> > to be stored for each slab object. Wraps obj_cgroup into slabobj_ext
> > to support current functionality while allowing to extend slabobj_ext
> > in the future.
> >
> > Note: ideally the config dependency should be turned the other way around:
> > MEMCG should depend on SLAB_OBJ_EXT and {page|slab|folio}.memcg_data would
> > be renamed to something like {page|slab|folio}.objext_data. However doing
> > this in RFC would introduce considerable churn unrelated to the overall
> > idea, so avoiding this until v1.
>
> Hi Suren!

Hi Roman,

>
> I'd say CONFIG_MEMCG_KMEM and CONFIG_YOUR_NEW_STUFF should both depend on
> SLAB_OBJ_EXT.
> CONFIG_MEMCG_KMEM depend on CONFIG_MEMCG anyway.

Yes, I agree. I wanted to mention here that the current dependency is
incorrect and should be reworked. Having both depending on
SLAB_OBJ_EXT seems like the right approach.

>
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  include/linux/memcontrol.h |  18 ++++--
> >  init/Kconfig               |   5 ++
> >  mm/kfence/core.c           |   2 +-
> >  mm/memcontrol.c            |  60 ++++++++++---------
> >  mm/page_owner.c            |   2 +-
> >  mm/slab.h                  | 119 +++++++++++++++++++++++++------------
> >  6 files changed, 131 insertions(+), 75 deletions(-)
> >
> > diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
> > index 6257867fbf95..315399f77173 100644
> > --- a/include/linux/memcontrol.h
> > +++ b/include/linux/memcontrol.h
> > @@ -227,6 +227,14 @@ struct obj_cgroup {
> >       };
> >  };
> >
> > +/*
> > + * Extended information for slab objects stored as an array in page->memcg_data
> > + * if MEMCG_DATA_OBJEXTS is set.
> > + */
> > +struct slabobj_ext {
> > +     struct obj_cgroup *objcg;
> > +} __aligned(8);
>
> Why do we need this aligment requirement?

To save space by avoiding padding, however, all members today will be
pointers, so it's meaningless and we can safely drop it.

>
> > +
> >  /*
> >   * The memory controller data structure. The memory controller controls both
> >   * page cache and RSS per cgroup. We would eventually like to provide
> > @@ -363,7 +371,7 @@ extern struct mem_cgroup *root_mem_cgroup;
> >
> >  enum page_memcg_data_flags {
> >       /* page->memcg_data is a pointer to an objcgs vector */
> > -     MEMCG_DATA_OBJCGS = (1UL << 0),
> > +     MEMCG_DATA_OBJEXTS = (1UL << 0),
> >       /* page has been accounted as a non-slab kernel page */
> >       MEMCG_DATA_KMEM = (1UL << 1),
> >       /* the next bit after the last actual flag */
> > @@ -401,7 +409,7 @@ static inline struct mem_cgroup *__folio_memcg(struct folio *folio)
> >       unsigned long memcg_data = folio->memcg_data;
> >
> >       VM_BUG_ON_FOLIO(folio_test_slab(folio), folio);
> > -     VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJCGS, folio);
> > +     VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
> >       VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_KMEM, folio);
> >
> >       return (struct mem_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
> > @@ -422,7 +430,7 @@ static inline struct obj_cgroup *__folio_objcg(struct folio *folio)
> >       unsigned long memcg_data = folio->memcg_data;
> >
> >       VM_BUG_ON_FOLIO(folio_test_slab(folio), folio);
> > -     VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJCGS, folio);
> > +     VM_BUG_ON_FOLIO(memcg_data & MEMCG_DATA_OBJEXTS, folio);
> >       VM_BUG_ON_FOLIO(!(memcg_data & MEMCG_DATA_KMEM), folio);
> >
> >       return (struct obj_cgroup *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
> > @@ -517,7 +525,7 @@ static inline struct mem_cgroup *page_memcg_check(struct page *page)
> >        */
> >       unsigned long memcg_data = READ_ONCE(page->memcg_data);
> >
> > -     if (memcg_data & MEMCG_DATA_OBJCGS)
> > +     if (memcg_data & MEMCG_DATA_OBJEXTS)
> >               return NULL;
> >
> >       if (memcg_data & MEMCG_DATA_KMEM) {
> > @@ -556,7 +564,7 @@ static inline struct mem_cgroup *get_mem_cgroup_from_objcg(struct obj_cgroup *ob
> >  static inline bool folio_memcg_kmem(struct folio *folio)
> >  {
> >       VM_BUG_ON_PGFLAGS(PageTail(&folio->page), &folio->page);
> > -     VM_BUG_ON_FOLIO(folio->memcg_data & MEMCG_DATA_OBJCGS, folio);
> > +     VM_BUG_ON_FOLIO(folio->memcg_data & MEMCG_DATA_OBJEXTS, folio);
> >       return folio->memcg_data & MEMCG_DATA_KMEM;
> >  }
> >
> > diff --git a/init/Kconfig b/init/Kconfig
> > index 532362fcfe31..82396d7a2717 100644
> > --- a/init/Kconfig
> > +++ b/init/Kconfig
> > @@ -958,6 +958,10 @@ config MEMCG
> >       help
> >         Provides control over the memory footprint of tasks in a cgroup.
> >
> > +config SLAB_OBJ_EXT
> > +     bool
> > +     depends on MEMCG
> > +
> >  config MEMCG_SWAP
> >       bool
> >       depends on MEMCG && SWAP
> > @@ -966,6 +970,7 @@ config MEMCG_SWAP
> >  config MEMCG_KMEM
> >       bool
> >       depends on MEMCG && !SLOB
> > +     select SLAB_OBJ_EXT
> >       default y
> >
> >  config BLK_CGROUP
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index c252081b11df..c0958e4a32e2 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -569,7 +569,7 @@ static unsigned long kfence_init_pool(void)
> >               __folio_set_slab(slab_folio(slab));
> >  #ifdef CONFIG_MEMCG
> >               slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
> > -                                MEMCG_DATA_OBJCGS;
> > +                                MEMCG_DATA_OBJEXTS;
> >  #endif
> >       }
> >
> > diff --git a/mm/memcontrol.c b/mm/memcontrol.c
> > index b69979c9ced5..3f407ef2f3f1 100644
> > --- a/mm/memcontrol.c
> > +++ b/mm/memcontrol.c
> > @@ -2793,7 +2793,7 @@ static void commit_charge(struct folio *folio, struct mem_cgroup *memcg)
> >       folio->memcg_data = (unsigned long)memcg;
> >  }
> >
> > -#ifdef CONFIG_MEMCG_KMEM
> > +#ifdef CONFIG_SLAB_OBJ_EXT
> >  /*
> >   * The allocated objcg pointers array is not accounted directly.
> >   * Moreover, it should not come from DMA buffer and is not readily
> > @@ -2801,38 +2801,20 @@ static void commit_charge(struct folio *folio, struct mem_cgroup *memcg)
> >   */
> >  #define OBJCGS_CLEAR_MASK    (__GFP_DMA | __GFP_RECLAIMABLE | __GFP_ACCOUNT)
> >
> > -/*
> > - * mod_objcg_mlstate() may be called with irq enabled, so
> > - * mod_memcg_lruvec_state() should be used.
> > - */
> > -static inline void mod_objcg_mlstate(struct obj_cgroup *objcg,
> > -                                  struct pglist_data *pgdat,
> > -                                  enum node_stat_item idx, int nr)
> > -{
> > -     struct mem_cgroup *memcg;
> > -     struct lruvec *lruvec;
> > -
> > -     rcu_read_lock();
> > -     memcg = obj_cgroup_memcg(objcg);
> > -     lruvec = mem_cgroup_lruvec(memcg, pgdat);
> > -     mod_memcg_lruvec_state(lruvec, idx, nr);
> > -     rcu_read_unlock();
> > -}
> > -
> > -int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
> > -                              gfp_t gfp, bool new_slab)
> > +int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
> > +                     gfp_t gfp, bool new_slab)
> >  {
> >       unsigned int objects = objs_per_slab(s, slab);
> >       unsigned long memcg_data;
> >       void *vec;
> >
> >       gfp &= ~OBJCGS_CLEAR_MASK;
> > -     vec = kcalloc_node(objects, sizeof(struct obj_cgroup *), gfp,
> > +     vec = kcalloc_node(objects, sizeof(struct slabobj_ext), gfp,
> >                          slab_nid(slab));
> >       if (!vec)
> >               return -ENOMEM;
> >
> > -     memcg_data = (unsigned long) vec | MEMCG_DATA_OBJCGS;
> > +     memcg_data = (unsigned long) vec | MEMCG_DATA_OBJEXTS;
> >       if (new_slab) {
> >               /*
> >                * If the slab is brand new and nobody can yet access its
> > @@ -2843,7 +2825,7 @@ int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
> >       } else if (cmpxchg(&slab->memcg_data, 0, memcg_data)) {
> >               /*
> >                * If the slab is already in use, somebody can allocate and
> > -              * assign obj_cgroups in parallel. In this case the existing
> > +              * assign slabobj_exts in parallel. In this case the existing
> >                * objcg vector should be reused.
> >                */
> >               kfree(vec);
> > @@ -2853,6 +2835,26 @@ int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
> >       kmemleak_not_leak(vec);
> >       return 0;
> >  }
> > +#endif /* CONFIG_SLAB_OBJ_EXT */
> > +
> > +#ifdef CONFIG_MEMCG_KMEM
> > +/*
> > + * mod_objcg_mlstate() may be called with irq enabled, so
> > + * mod_memcg_lruvec_state() should be used.
> > + */
> > +static inline void mod_objcg_mlstate(struct obj_cgroup *objcg,
> > +                                  struct pglist_data *pgdat,
> > +                                  enum node_stat_item idx, int nr)
> > +{
> > +     struct mem_cgroup *memcg;
> > +     struct lruvec *lruvec;
> > +
> > +     rcu_read_lock();
> > +     memcg = obj_cgroup_memcg(objcg);
> > +     lruvec = mem_cgroup_lruvec(memcg, pgdat);
> > +     mod_memcg_lruvec_state(lruvec, idx, nr);
> > +     rcu_read_unlock();
> > +}
> >
> >  static __always_inline
> >  struct mem_cgroup *mem_cgroup_from_obj_folio(struct folio *folio, void *p)
> > @@ -2863,18 +2865,18 @@ struct mem_cgroup *mem_cgroup_from_obj_folio(struct folio *folio, void *p)
> >        * slab->memcg_data.
> >        */
> >       if (folio_test_slab(folio)) {
> > -             struct obj_cgroup **objcgs;
> > +             struct slabobj_ext *obj_exts;
> >               struct slab *slab;
> >               unsigned int off;
> >
> >               slab = folio_slab(folio);
> > -             objcgs = slab_objcgs(slab);
> > -             if (!objcgs)
> > +             obj_exts = slab_obj_exts(slab);
> > +             if (!obj_exts)
> >                       return NULL;
> >
> >               off = obj_to_index(slab->slab_cache, slab, p);
> > -             if (objcgs[off])
> > -                     return obj_cgroup_memcg(objcgs[off]);
> > +             if (obj_exts[off].objcg)
> > +                     return obj_cgroup_memcg(obj_exts[off].objcg);
> >
> >               return NULL;
> >       }
> > diff --git a/mm/page_owner.c b/mm/page_owner.c
> > index e4c6f3f1695b..fd4af1ad34b8 100644
> > --- a/mm/page_owner.c
> > +++ b/mm/page_owner.c
> > @@ -353,7 +353,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
> >       if (!memcg_data)
> >               goto out_unlock;
> >
> > -     if (memcg_data & MEMCG_DATA_OBJCGS)
> > +     if (memcg_data & MEMCG_DATA_OBJEXTS)
> >               ret += scnprintf(kbuf + ret, count - ret,
> >                               "Slab cache page\n");
> >
> > diff --git a/mm/slab.h b/mm/slab.h
> > index 4ec82bec15ec..c767ce3f0fe2 100644
> > --- a/mm/slab.h
> > +++ b/mm/slab.h
> > @@ -422,36 +422,94 @@ static inline bool kmem_cache_debug_flags(struct kmem_cache *s, slab_flags_t fla
> >       return false;
> >  }
> >
> > +#ifdef CONFIG_SLAB_OBJ_EXT
> > +
> > +static inline bool is_kmem_only_obj_ext(void)
> > +{
> >  #ifdef CONFIG_MEMCG_KMEM
> > +     return sizeof(struct slabobj_ext) == sizeof(struct obj_cgroup *);
> > +#else
> > +     return false;
> > +#endif
> > +}
> > +
> >  /*
> > - * slab_objcgs - get the object cgroups vector associated with a slab
> > + * slab_obj_exts - get the pointer to the slab object extension vector
> > + * associated with a slab.
> >   * @slab: a pointer to the slab struct
> >   *
> > - * Returns a pointer to the object cgroups vector associated with the slab,
> > + * Returns a pointer to the object extension vector associated with the slab,
> >   * or NULL if no such vector has been associated yet.
> >   */
> > -static inline struct obj_cgroup **slab_objcgs(struct slab *slab)
> > +static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
> >  {
> >       unsigned long memcg_data = READ_ONCE(slab->memcg_data);
> >
> > -     VM_BUG_ON_PAGE(memcg_data && !(memcg_data & MEMCG_DATA_OBJCGS),
> > +     VM_BUG_ON_PAGE(memcg_data && !(memcg_data & MEMCG_DATA_OBJEXTS),
> >                                                       slab_page(slab));
> >       VM_BUG_ON_PAGE(memcg_data & MEMCG_DATA_KMEM, slab_page(slab));
> >
> > -     return (struct obj_cgroup **)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
> > +     return (struct slabobj_ext *)(memcg_data & ~MEMCG_DATA_FLAGS_MASK);
> >  }
> >
> > -int memcg_alloc_slab_cgroups(struct slab *slab, struct kmem_cache *s,
> > -                              gfp_t gfp, bool new_slab);
> > -void mod_objcg_state(struct obj_cgroup *objcg, struct pglist_data *pgdat,
> > -                  enum node_stat_item idx, int nr);
> > +int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
> > +                     gfp_t gfp, bool new_slab);
> >
> > -static inline void memcg_free_slab_cgroups(struct slab *slab)
> > +static inline void free_slab_obj_exts(struct slab *slab)
> >  {
> > -     kfree(slab_objcgs(slab));
> > +     struct slabobj_ext *obj_exts;
> > +
> > +     if (!memcg_kmem_enabled() && is_kmem_only_obj_ext())
> > +             return;
>
> Hm, not sure I understand this. I kmem is disabled and is_kmem_only_obj_ext()
> is true, shouldn't slab->memcg_data == NULL (always)?

So, the logic was to skip freeing when the only possible objects in
slab->memcg_data are "struct obj_cgroup" and kmem is disabled.
Otherwise there are other objects stored in slab->memcg_data which
have to be freed. Did I make it more complicated than it should have
been?

>
> > +
> > +     obj_exts = slab_obj_exts(slab);
> > +     kfree(obj_exts);
> >       slab->memcg_data = 0;
> >  }
> >
> > +static inline void prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
> > +{
> > +     struct slab *slab;
> > +
> > +     /* If kmem is the only extension then the vector will be created conditionally */
> > +     if (is_kmem_only_obj_ext())
> > +             return;
> > +
> > +     slab = virt_to_slab(p);
> > +     if (!slab_obj_exts(slab))
> > +             WARN(alloc_slab_obj_exts(slab, s, flags, false),
> > +                     "%s, %s: Failed to create slab extension vector!\n",
> > +                     __func__, s->name);
> > +}
>
> This looks a bit crypric: the action is wrapped into WARN() and the rest is a set
> of (semi-)static checks. Can we, please, invert it? E.g. something like:
>
> if (slab_alloc_tracking_enabled()) {
>         slab = virt_to_slab(p);
>         if (!slab_obj_exts(slab))
>                 WARN(alloc_slab_obj_exts(slab, s, flags, false),
>                 "%s, %s: Failed to create slab extension vector!\n",
>                 __func__, s->name);
> }

Yeah, this is much more readable. Thanks for the suggestion and for
reviewing the code!

>
> The rest looks good to me.
>
> Thank you!
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an email to kernel-team+unsubscribe@android.com.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpECU8NsC_kUSE7ef33_HUkZP5S2rEbxOvfnmM2Qb4TKBA%40mail.gmail.com.
