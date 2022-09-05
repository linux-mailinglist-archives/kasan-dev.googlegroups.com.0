Return-Path: <kasan-dev+bncBCU73AEHRQBBBNHK3GMAMGQE4ISXMPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id CF89D5ADB41
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Sep 2022 00:16:21 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id z4-20020a5b0a44000000b006a1c47c36besf7273611ybq.15
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 15:16:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662416180; cv=pass;
        d=google.com; s=arc-20160816;
        b=G73wVAK8QT5YD5Ip5ya4ypxuKuTdcWBGPww8gcXfZZ0lLcELZpsZfer4R7ymYcuhnk
         bRxSYcu9sYotadbCI+XmmiCog9Br+oIM1qd39zeM+Lo1ZDVOBWy3I+prbD8s0XZQe9UN
         qyubfCFCSZLVnLfUR2avoEqDOS1ZxNP8fRIKN181CR2NqrrnNl7Ox5uqey8I4dBa4GS0
         mTvz2dtCe+rozpyf8z4/6UiULjmAFgXAcILj3cUp/jaNvYP44KEuKpKmqG0KC5LJm2zV
         JN5tj70TfbykDunmAbptJWT/r2DGC5AqYJvxI+ihyu402BiUpHKlf7m3936SL0e0A3Sb
         hPAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=2+skDKnzvLcETr0ForUYnKSUAuZ+fWrBUKXBqJZg3d8=;
        b=RUezMNcVWl1XWdaN0zlFcFLPaeVIvx3mgzRK/6dmu0mVdVtHnkR/qLXA63fFsOj4gm
         oxdvKWtIePxMGtyl0fDJfYnS/M7dOCQG7eJaExqRt/UIFffUIrSt0N0/W6xTGWTy3kE0
         mUxNbfOjo7ROmsGDuaTSP00a50bUzq5R5V+LWSzCRjAYv/DpT+oIRuqrZ0iaTWUGwXZq
         MYWaQGKNe9GBvSP7/fG2cLU0xEdaEMl5RQZjDYJYOLtM3H1nLWUfZgTr3d2Zhh1uHof2
         5yjdONxo1G/mmvcgI+28r2SOyC//GEZL2DmejkFrP8vnltenRcmTxjjkOa2A52Xycwag
         Xg8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=a78l=ZI=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=2+skDKnzvLcETr0ForUYnKSUAuZ+fWrBUKXBqJZg3d8=;
        b=Yh/Zu/XTFuGOxiBWRZXlhrXNbrkhRyfJFsGEKGHeT6a99obJuG7Nht6TdUSRoG4Qtw
         Ldl6YF59904MlnPkpRVStotbv77a51j0wmFTaA01d7sK7xaAM/L7LfYIPuGTiPh0O+/Z
         QXYoBeba+zUWBohJKEKdxYx/QY3pVFRfeVdx7UyN/Otj1ydegQUkX5zn/EYVZu4NFLJE
         ndeFZsDebxpbS78ZbrlA/S9/TWmQIIDu791I3/vjuwZ+Puc+SO3vBLRfkng1V6CC0XWi
         wEukLPMWipfZLG/IOWqU4RJsUrxvMbic/mF+i05JhBTx9LxW1rmUzg3MBGmEOR4xFvxc
         CK6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=2+skDKnzvLcETr0ForUYnKSUAuZ+fWrBUKXBqJZg3d8=;
        b=EOgry+ewLD0rN+DMWos0xiqervRrk2IHPCPaII5qH5SclAXbameYQgCNwkSjlnelK2
         vw9hdhJokloYqvK3meoiHl9qlU3BaF2gDvHY934YYSwaUolDVz83ubdUkSiC3SRW7DdD
         Q/LzNgNOYjKNMCo/g+3atDJVUraSRXqBCWq/tz4TdticvJtgqdDwX3XLqL3mX4VSZyUp
         uhXuo6VmCQgd97alMDZW853gHBPp6wIJOw/7zLEWixgypsLVwvukubxewGkph0bEotbw
         Xb47BXV5Yef2oRyWLAvruFK7+IWDk0WMK0BKkF7KI7rwFaJ1k/qGoTUJviYwrEkzMOeT
         6KEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo23Bhp8frt8Kkv552tUVsx37uMrGhH6Pn5n6rTZ00/jLDPku+fa
	yvP84X6csI5qxp6rRSDmJOw=
X-Google-Smtp-Source: AA6agR7dnQa4tbDCcKKmzpnu9rayUznWEFzmccScW+YREGCUy7pf1rEdXFzSod8d98F1jP3ZEebWOg==
X-Received: by 2002:a05:6902:1c9:b0:67c:12b6:f30c with SMTP id u9-20020a05690201c900b0067c12b6f30cmr33206743ybh.342.1662416180560;
        Mon, 05 Sep 2022 15:16:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:3c2:0:b0:335:4596:25ac with SMTP id 185-20020a8103c2000000b00335459625acls5087048ywd.6.-pod-prod-gmail;
 Mon, 05 Sep 2022 15:16:19 -0700 (PDT)
X-Received: by 2002:a0d:f685:0:b0:343:bd3d:80b2 with SMTP id g127-20020a0df685000000b00343bd3d80b2mr22764784ywf.485.1662416179857;
        Mon, 05 Sep 2022 15:16:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662416179; cv=none;
        d=google.com; s=arc-20160816;
        b=ImW3FzpjytOZKKYrhIboeLExn8432PD3IVpZY87O6VgCy1/e+TOhnV/1MiLygKMTrV
         lNrVGVWhpWvNHtevtyCMDRP/C0exHQZ5Ax1fmV4DdS9aw6qimcyqgwjt+rdgCzfi2LE3
         xzoeQhgOedBhLVx2df2qlDaGXHWC5WB5Ya7hfopNhKNgZh0N+VGe9iYPBs0qUiashyIf
         8iquIkWM8m4DwCua9BRdW1TjPeHKoZCm2wwINXRL6Aj6TGodS1Ee4V2Z2FsMbTT9Uj0c
         rWOuBncyedM4qRJnGm20O7q1ev5LJf79zX+63BhRW4JmcU6QIjzNtaEz6tvlVoubnmeK
         +1Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=Q4/Z/bg2kDTI6m5rA82hAkQ9BqEdQlGB5olkGauA4tg=;
        b=cIlYLORlxgiOzTxk7dNRx5EwYRnYszOWW0ZWx8HME6KQfmWC47yfOVC8g+bv27RmfH
         dxvTCcQ5OQB7IW0p2fUuzjNPLAWvPfaz2wTXEzN9P4iSlYe6ntTP/2PDe4e9WFQeXahM
         6gh9klW7HgPOkLQ/ziCiuvzwtmBtcF8j2CmBMVgLj9eSklcprCekHO1NjgI/H27PrZf4
         a/YvMwGzE8QL4s7I0phGg01F+f2y7n8oGcaZ5o2XaFA1iim47ELRyfmu3s0sOjkMUObJ
         /xAZTPxlklhNzlbWnkBQg9wvpRK+f7Lst96zDp/xRzYyRI9zzwqjbiYVOKSiRUnYIb1E
         7CWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=a78l=ZI=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id m2-20020a81d242000000b0031f111d36bbsi971969ywl.1.2022.09.05.15.16.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Sep 2022 15:16:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5612C60AFF;
	Mon,  5 Sep 2022 22:16:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7D5E2C433C1;
	Mon,  5 Sep 2022 22:16:13 +0000 (UTC)
Date: Mon, 5 Sep 2022 18:16:50 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>, Andrew
 Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>,
 Johannes Weiner <hannes@cmpxchg.org>, Roman Gushchin
 <roman.gushchin@linux.dev>, Davidlohr Bueso <dave@stgolabs.net>, Matthew
 Wilcox <willy@infradead.org>, "Liam R. Howlett" <liam.howlett@oracle.com>,
 David Vernet <void@manifault.com>, Juri Lelli <juri.lelli@redhat.com>,
 Laurent Dufour <ldufour@linux.ibm.com>, Peter Xu <peterx@redhat.com>, David
 Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 changbin.du@intel.com, ytcoode@gmail.com, Vincent Guittot
 <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>,
 Benjamin Segall <bsegall@google.com>, Daniel Bristot de Oliveira
 <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, Christopher
 Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Shakeel Butt <shakeelb@google.com>, Muchun Song
 <songmuchun@bytedance.com>, arnd@arndb.de, jbaron@akamai.com, David
 Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, Kalesh
 Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>,
 linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev,
 kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, LKML
 <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220905181650.71e9d02c@gandalf.local.home>
In-Reply-To: <20220905204229.xqrqxmaax37n3ody@moria.home.lan>
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
	<20220905204229.xqrqxmaax37n3ody@moria.home.lan>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=a78l=ZI=goodmis.org=rostedt@kernel.org"
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

On Mon, 5 Sep 2022 16:42:29 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> > Haven't tried that yet but will do. Thanks for the reference code!  
> 
> Is it really worth the effort of benchmarking tracing API overhead here?
> 
> The main cost of a tracing based approach is going to to be the data structure
> for remembering outstanding allocations so that free events can be matched to
> the appropriate callsite. Regardless of whether it's done with BFP or by
> attaching to the tracepoints directly, that's going to be the main overhead.

The point I was making here is that you do not need your own hooking
mechanism. You can get the information directly by attaching to the
tracepoint.

> > static void my_callback(void *data, unsigned long call_site,
> >                         const void *ptr, struct kmem_cache *s,
> >                         size_t bytes_req, size_t bytes_alloc,
> >                         gfp_t gfp_flags)
> > {
> >         struct my_data_struct *my_data = data;
> >
> >         { do whatever }
> > }

The "do whatever" is anything you want to do.

Or is the data structure you create with this approach going to be too much
overhead? How hard is it for a hash or binary search lookup?


-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905181650.71e9d02c%40gandalf.local.home.
