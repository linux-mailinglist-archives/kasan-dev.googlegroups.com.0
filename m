Return-Path: <kasan-dev+bncBC7OD3FKWUERBIPW3CMAMGQEDRALQ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id B7B415AD8D4
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 20:08:39 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id p8-20020a5d9848000000b0068e97cc84b1sf5316633ios.23
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 11:08:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662401313; cv=pass;
        d=google.com; s=arc-20160816;
        b=D3+uT6e6iI1U+bHJgKjZs3gHmj9yV/lEcEN0ePnWyCxBzHvnSR6OBczXqDdYqE8Nr7
         cGRJwSnjvXT9oxK8YTQi7dc8hBocD8PclJBItSCqyji7C8NsmXvsei7KWCR5rd7gm7pJ
         qFnRoAbciCK6MhuB3ZYK94QPuWR89NR9826zV0XII/PwiW/zFCMdnZuW1KLyR7rCaePh
         pzL3rLqGWB8QigOEBphouVqPnwNf+n96OO9pk8091AoVBPvwK+1SUnTuyDkgYVDVqD00
         oe2WD43Dmyeqe1LzFlgBVsXofoZb/guKbnKr3q+kxpoU0iWMmtOP2jfHLaL3ah2xv3p1
         zUcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GVoOji8AieUgx0+BLE6qed4jCY1UZOHP+cGc3o+psN0=;
        b=F2Iw6rYC7JFnrhipVJhYJmoaBxdPUgHU6OcC6Effxhzr+0zYiATKgPURmI80amrehv
         Q+1kk57AQT9s9sCgG37hS14P5hnbK4ufsUMKvX6fhU/BFnZlP/RqNmryJUSGckARt6Dc
         H4ZUZkjz1errqYzRVvQBL5v0bNi3rvq0FRiMXiQVdCdrCw3Ngw9YBZ7XXQrdFas7e8VR
         ipZJcX+ESQ2xtiwqyFu8cVRjBzuT7aO4WotbhbNDM+BjTBZfXAU18DAlalYVB23Ug7rJ
         LshroL/wvwjBkSOxD0RMmN6MzQBzlRKJ5p1uu0I2JWOztWJ6/JOC+jrqPqA/8oacytra
         4dHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BWl6tEU0;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=GVoOji8AieUgx0+BLE6qed4jCY1UZOHP+cGc3o+psN0=;
        b=Ngolu3Zdp5arZLhn/fbht/iPSMn32ZAGKmk874yuglyGpAvwebR4nn0hym4zw2ZaD+
         1bDxIvuUwwxyBiHFVcns34jFLNtrgGZyw0ZZeWHB2rq4XFeouBaAvje2eDf5ep+4orsQ
         ZMWVxQC/gVWCYS4J756+P54hVzYOp8Jd2xaweBRSF5Cn83gqCqqSgnOoJHXIT0IhYmny
         6eXfYCxRT27DQfXYQABxgEmwP2WK0eoQ+av4GBUexeH/HY0ImuyswTtPIuIkpuHZbX3a
         fMq6EhVstfqXY9ksc6mlCGg6/zrEjcdyL3HG7qF96AcZ/8ovVc42LJqt6KHc2bQkcq/I
         66+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=GVoOji8AieUgx0+BLE6qed4jCY1UZOHP+cGc3o+psN0=;
        b=yobe/mcEOMyNpQepkTf/RzE9Bc51FnjyYQ1/jkFb47mA8VFjOm+UgkOOxiBJAlJ5Sp
         vzwTPvOENX/P6qLj7A2JxkJF4L55yIwUH5Kw6WQ/i3F3DUwmgfexMC1jzE5vFW04X7I2
         ZcW4l06UkYUi6PHaC2AqWiNNZoBXBQOeXGDjO9H5AcP5vt36+y4HlmdRqZfEAVIhUQSK
         wJaVnm/GCi+2gyjafpwzX1IeWeiK4BHup6CQ4JF87r09CLs1mVspC3E4zGiII7HJdKfY
         AFT9VeZF63iczzu+78oNyPfJgTUAuRrRglvcQ5FLsdHPucUoZoP9tDORulH+ZdMfAkv4
         wLig==
X-Gm-Message-State: ACgBeo3QXSkFuoZoCI9LfyxNKOECpxDgXwbNkY0+ptdqiAIGSS/UES9v
	BglBknzMk0FNpM5/od17byA=
X-Google-Smtp-Source: AA6agR6aFeIthpifpPZEQiFCk7eVWF5HktrOHPMKBkShEB9+whWxH1ILY/lx3h71aglMTzfSDLhUPA==
X-Received: by 2002:a05:6638:34a9:b0:346:c305:3f87 with SMTP id t41-20020a05663834a900b00346c3053f87mr25569367jal.42.1662401313426;
        Mon, 05 Sep 2022 11:08:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:63c6:0:b0:343:44a5:a2d1 with SMTP id j189-20020a0263c6000000b0034344a5a2d1ls303226jac.0.-pod-prod-gmail;
 Mon, 05 Sep 2022 11:08:33 -0700 (PDT)
X-Received: by 2002:a05:6638:2041:b0:352:52ad:c4c4 with SMTP id t1-20020a056638204100b0035252adc4c4mr3773579jaj.122.1662401313025;
        Mon, 05 Sep 2022 11:08:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662401313; cv=none;
        d=google.com; s=arc-20160816;
        b=TypzBbvbO5gKUW4rC5qbdHH1R3aRDcsFm9gC3xMaDqhzoqJMWVARFT6xQEGvXOhnNZ
         ic+EEvWWFbwYOjR/HpqJjeQHny4DUAyR77IUbm9diqfqTw+aGhi1FirKDkrbB2E3aogr
         dUrP2czWkyCunpyWCfpoLaeWc+0PRZWV7B6N3OSTfrpGHKvqHPo50RXbjBEgmnswhr0x
         NUF1BR8MZx0m61YWaDRdTjZOcjS+Lh4SqVpYQR9NrcHn9QGKcEb+rNC2ychCxyHHfaFJ
         7/Yzvo5iGIgscV6DowHKLjVDEmYl1wmVgnyCYJUkcaQYIVoTOFr5NDQgnrCnsQVeP1XK
         i2cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hbTvjCqXtfZwCNAPDugxhLvbO4tPW4uXsytclFMPf88=;
        b=MGARuRS/67rfUusffmKSeTmU2vkhePPqB9al1HOhdSb9/4wMFRQgYoC/LS1t9G7v4d
         cNd++y7P9mhQKBEvNOO1Gl9NdPMv7wmunCmAekkUTcCb99YbyVTGYUWtldsSnUY/ed9d
         ehWB1Y5zCq07qXzj/MEjCuXl5PMIiFOXIIuYcOM0f0ryy01iySoB1R+X3OrRT3shtRGZ
         pcFiG2D7x7fzcZqvTOA/7XmJFquGS1riFTKfP9GTcmNuWY+R/FvtWW8q/UR7MpRqA3ou
         Vaa+p6YDwBSJb2TPvEzyenbqwFsqVYymW4F3EDxFInKGd3A6ag0wifV+XvjsT6HSnEzW
         fxnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BWl6tEU0;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12f.google.com (mail-il1-x12f.google.com. [2607:f8b0:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id b13-20020a056e02184d00b002e8ece90ea6si644287ilv.1.2022.09.05.11.08.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 11:08:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::12f as permitted sender) client-ip=2607:f8b0:4864:20::12f;
Received: by mail-il1-x12f.google.com with SMTP id k9so1769648ils.12
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 11:08:33 -0700 (PDT)
X-Received: by 2002:a92:ca06:0:b0:2eb:391a:a2a4 with SMTP id
 j6-20020a92ca06000000b002eb391aa2a4mr16719486ils.199.1662401312639; Mon, 05
 Sep 2022 11:08:32 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz> <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz> <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
 <YxEE1vOwRPdzKxoq@dhcp22.suse.cz> <CAJuCfpFrRwXXQ=wAvZ-oUNKXUJ=uUA=fiDrkhRu5VGXcM+=cuA@mail.gmail.com>
 <20220905110713.27304149@gandalf.local.home>
In-Reply-To: <20220905110713.27304149@gandalf.local.home>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Sep 2022 11:08:21 -0700
Message-ID: <CAJuCfpF-O6Gz2o7YqCgFHV+KEFuzC-PTUoBHj25DNRkkSmhbUg@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Michal Hocko <mhocko@suse.com>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Johannes Weiner <hannes@cmpxchg.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Davidlohr Bueso <dave@stgolabs.net>, Matthew Wilcox <willy@infradead.org>, 
	"Liam R. Howlett" <liam.howlett@oracle.com>, David Vernet <void@manifault.com>, 
	Juri Lelli <juri.lelli@redhat.com>, Laurent Dufour <ldufour@linux.ibm.com>, 
	Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Benjamin Segall <bsegall@google.com>, Daniel Bristot de Oliveira <bristot@redhat.com>, 
	Valentin Schneider <vschneid@redhat.com>, Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, 
	jbaron@akamai.com, David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BWl6tEU0;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::12f as
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

On Mon, Sep 5, 2022 at 8:06 AM Steven Rostedt <rostedt@goodmis.org> wrote:
>
> On Sun, 4 Sep 2022 18:32:58 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
>
> > Page allocations (overheads are compared to get_free_pages() duration):
> > 6.8% Codetag counter manipulations (__lazy_percpu_counter_add + __alloc_tag_add)
> > 8.8% lookup_page_ext
> > 1237% call stack capture
> > 139% tracepoint with attached empty BPF program
>
> Have you tried tracepoint with custom callback?
>
> static void my_callback(void *data, unsigned long call_site,
>                         const void *ptr, struct kmem_cache *s,
>                         size_t bytes_req, size_t bytes_alloc,
>                         gfp_t gfp_flags)
> {
>         struct my_data_struct *my_data = data;
>
>         { do whatever }
> }
>
> [..]
>         register_trace_kmem_alloc(my_callback, my_data);
>
> Now the my_callback function will be called directly every time the
> kmem_alloc tracepoint is hit.
>
> This avoids that perf and BPF overhead.

Haven't tried that yet but will do. Thanks for the reference code!

>
> -- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpF-O6Gz2o7YqCgFHV%2BKEFuzC-PTUoBHj25DNRkkSmhbUg%40mail.gmail.com.
