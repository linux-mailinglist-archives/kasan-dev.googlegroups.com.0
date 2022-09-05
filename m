Return-Path: <kasan-dev+bncBCU73AEHRQBBBBFB3CMAMGQE442LRQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id EBAB15AD5B7
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 17:06:44 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id u27-20020adfa19b000000b0022863c08ac4sf765509wru.11
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 08:06:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662390404; cv=pass;
        d=google.com; s=arc-20160816;
        b=ygQPGSOlAEXJ63rtyaonkJlnMgChJqqNvwP+VtdUL3UW9GvSqg+nh8gWamYrxD0UeE
         JMbrtggwbs1b7VJUpLsR92+ljWeoB0GuqRjEMHx3ayPnDW3s6oZKH6T2UWrmp/cp1c8M
         224ySyf+NVIgllGel5YpxzeLXo6rtDeKMajYsS9iNzq3dFNzCBaEDN1wFJJbpF0bn9Vb
         5iDHuLUAiuhMsI1d+zERFsEsNtIA+bLFMFmBVYH8LgkD4x4e/lkMjE3Mrt+R3UmX16ql
         8ClZ65H3JMn+XVEtYyP/U+j5/1NWt8M4id1TOaGxllFoleATj3xs5rOP1kTQgV5y2B/k
         NSnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=mlYLnJGapS93CZtVtfpUhPxzDNArVcFz7W1wqSQUQF8=;
        b=X57La2RxBzcZCTYGQG4jpD7JSwKyQ4HY/ltd/22+84FXK98xZ6JnHcsPtALX1Uqigl
         ERPiG/0+OUb1Ie10zx8fwxmURyp9dI/GsvQmbl5LpTcSqONwiazuVX6zjUoQ4ySQcYAj
         p3bcQhYbGKRo3alE+QStSfkXj1EWBg3o9CfTerv+i1gZzKpaYF+SYGrecrrNxMpSf6mQ
         gSGaIhuruq8Rqx3pxErB3TzJXRHyN4pzlHV0ZWPzxUXYB3wg3V4HcZ6kbjR0tOeqr4sa
         /NPbAN0FxaGcV24jJkQI2znkZ8xKBIO/AVyLfrM5xtTOw7AQ1M+iABH4Nbbr8IpQEUXr
         GE8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=a78l=ZI=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=mlYLnJGapS93CZtVtfpUhPxzDNArVcFz7W1wqSQUQF8=;
        b=Kf/mVDBkNYGaezGT8gDH4gUJNAv3e4++0lbocEzgdaA2dA+5WUq/F/cjhCyogDN0h4
         xBduw0wX3YnVOCMiF3hOfFHPZrYRNrziSwYMm+xWnkm98fBKJQ7jqjb/1LrdHxNLzt7+
         JNYl050Wo/sdZyGOwHjLq0cKZt2gi9gaL9zjdtYC+Dde4cr4IP+unHhs/pYouJFcf+gU
         NZt4jq65BcHN0tnEBW5WHHv2GO0YLCdFRk3hVVUoh+326RUH98fUZvG2x5sAYPaefnZy
         l/DLhN404KPcfJ6ufVQpkttETwcnM7aOPM3W9q0G4YSDIxbvmzAkszxNHDWiWLqoB1P6
         +rzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=mlYLnJGapS93CZtVtfpUhPxzDNArVcFz7W1wqSQUQF8=;
        b=Tdnwuob5D4wVAr6PTV7XMPJIkCbMxI0iYWzb6vIlCukxiS58j08B7p+IdX5LuAX5AY
         3fAgsWixPwOWjOyMwgqsYjE1W/Pl0fb2WPx0eL+NmrxToqbo0B+KvwTQaMBVFoMZ4xIR
         bTym1wMag4w1V9lmvcT744Uv7KYrLNDyKnJZAURRPREHEW0RA6RDFyPKP7XKWomov6zo
         KWmuc51n86Pu3IymDv6SOnK6FhWagHG7zObmDw+x+4TG+Wg2Xw/jQN8diL1NmhtUr/Ch
         NhrLyyKELWWwHdfM0K3229XpalN2wn9MUBxJTLjPc+TJ50KqG2SPRiroOsYGWaaUCWvK
         YYag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo39c38vY2osounIPYnrx5Mw+QzWBNw+4l5CszUZ+navzQPMZoxv
	w83JhmhSbvhBleqBLcgk8uo=
X-Google-Smtp-Source: AA6agR4wfcCAT5g4XQ1XMW/xp5jF9O9YtpQGoYI5cIemBHzAPsWaoHuN78kGjauo8hO5jIG5JnsaXA==
X-Received: by 2002:a05:600c:3482:b0:3a6:e09:1ebf with SMTP id a2-20020a05600c348200b003a60e091ebfmr10774428wmq.173.1662390404558;
        Mon, 05 Sep 2022 08:06:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d22e:0:b0:225:26dd:8b59 with SMTP id k14-20020adfd22e000000b0022526dd8b59ls4216809wrh.3.-pod-prod-gmail;
 Mon, 05 Sep 2022 08:06:43 -0700 (PDT)
X-Received: by 2002:a5d:4d83:0:b0:226:d08d:35c8 with SMTP id b3-20020a5d4d83000000b00226d08d35c8mr25345195wru.4.1662390403440;
        Mon, 05 Sep 2022 08:06:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662390403; cv=none;
        d=google.com; s=arc-20160816;
        b=szTdIomQdj2H5JdZ/lJGnhGakO7dlOszSvAHEvTZS5+fWW1USCtcLaYALWU3TjbxZf
         /Y1w8gBu0UXOAYuNX0OAoJ7eR/UFmRmURrTqPMvoR3euh8lBl1uHMF9FFcEoNuSCW1FS
         5Noa8Uf7Yt0Vd3o8mfYL3RwMMrXx2fVVrhlZ9K5MPNwxbWk4vhxCzsCvCNEJX2bH/fsP
         1UyYiDONUT9puBShj6P+fYLlP7ewDZkJtkmT+11Qa2ZSf/TSBlLVeh2NoJKBdr1t3tWJ
         tqqjG1f+1vECC2AyM9Q9bk+C44hL6GbxiBVVq9KBrWsu77Ia40HPO87d7MRw6N4Zfx0T
         CsRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=rPJUgF9yv0gYkqv4kZoUagGWRaHUFejHuYAYFEk46Yw=;
        b=CWy4AHPY8gteI3c1MXXs/+pqcDzD8o8ddDwjtVoW7RNJ3P145wZSnIBGb9cS1IolsC
         0deX6+IswA3kxR4u9WFNT6EcqlK4Rae1b0l3cejkiU2b3Y8wlyZvCt18nsGTYYKrtscV
         /4E2kdQxgl72cSosvzO6rvPXZ4v7YlRTFaexcrhdJhzGYG/MFEAa4xKgMb90wp4YoEDq
         yHdCyTWqs5dv5kUc32tXCA4JUCsai9X/mUUorJ3SSvphR0f8y40RYnwReb2gl/tjQN2g
         KKE/VAC8stgTsDHmPyFHaakbX0fABUMfbYgyaNRSWbZckiStp3fBwcDSE4nRpTAhsvrQ
         Z6ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=a78l=ZI=goodmis.org=rostedt@kernel.org"
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id k126-20020a1ca184000000b003a5a534292csi889274wme.3.2022.09.05.08.06.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Sep 2022 08:06:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 00378B8119C;
	Mon,  5 Sep 2022 15:06:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 99AC4C433D6;
	Mon,  5 Sep 2022 15:06:36 +0000 (UTC)
Date: Mon, 5 Sep 2022 11:07:13 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Michal Hocko <mhocko@suse.com>, Kent Overstreet
 <kent.overstreet@linux.dev>, Mel Gorman <mgorman@suse.de>, Peter Zijlstra
 <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>,
 Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>,
 Roman Gushchin <roman.gushchin@linux.dev>, Davidlohr Bueso
 <dave@stgolabs.net>, Matthew Wilcox <willy@infradead.org>, "Liam R.
 Howlett" <liam.howlett@oracle.com>, David Vernet <void@manifault.com>, Juri
 Lelli <juri.lelli@redhat.com>, Laurent Dufour <ldufour@linux.ibm.com>,
 Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>, Jens
 Axboe <axboe@kernel.dk>, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com, Vincent
 Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann
 <dietmar.eggemann@arm.com>, Benjamin Segall <bsegall@google.com>, Daniel
 Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider
 <vschneid@redhat.com>, Christopher Lameter <cl@linux.com>, Pekka Enberg
 <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 42.hyeyoo@gmail.com, Alexander Potapenko <glider@google.com>, Marco Elver
 <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Shakeel Butt
 <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>,
 arnd@arndb.de, jbaron@akamai.com, David Rientjes <rientjes@google.com>,
 Minchan Kim <minchan@google.com>, Kalesh Singh <kaleshsingh@google.com>,
 kernel-team <kernel-team@android.com>, linux-mm <linux-mm@kvack.org>,
 iommu@lists.linux.dev, kasan-dev@googlegroups.com,
 io-uring@vger.kernel.org, linux-arch@vger.kernel.org,
 xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
 linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220905110713.27304149@gandalf.local.home>
In-Reply-To: <CAJuCfpFrRwXXQ=wAvZ-oUNKXUJ=uUA=fiDrkhRu5VGXcM+=cuA@mail.gmail.com>
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
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=a78l=zi=goodmis.org=rostedt@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=a78l=ZI=goodmis.org=rostedt@kernel.org"
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

On Sun, 4 Sep 2022 18:32:58 -0700
Suren Baghdasaryan <surenb@google.com> wrote:

> Page allocations (overheads are compared to get_free_pages() duration):
> 6.8% Codetag counter manipulations (__lazy_percpu_counter_add + __alloc_tag_add)
> 8.8% lookup_page_ext
> 1237% call stack capture
> 139% tracepoint with attached empty BPF program

Have you tried tracepoint with custom callback?

static void my_callback(void *data, unsigned long call_site,
			const void *ptr, struct kmem_cache *s,
			size_t bytes_req, size_t bytes_alloc,
			gfp_t gfp_flags)
{
	struct my_data_struct *my_data = data;

	{ do whatever }
}

[..]
	register_trace_kmem_alloc(my_callback, my_data);

Now the my_callback function will be called directly every time the
kmem_alloc tracepoint is hit.

This avoids that perf and BPF overhead.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905110713.27304149%40gandalf.local.home.
