Return-Path: <kasan-dev+bncBCU73AEHRQBBBD53XKXAMGQEQ7JH2ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CF5285718B
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:26:09 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-6e43356d7eesf397034a34.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 15:26:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708039568; cv=pass;
        d=google.com; s=arc-20160816;
        b=q6jvV6j5K/u1HHNNEXuzmLj789gI5f2Yjjm5kp1oWrgptlkdDu2TP9p9gvNxn2Lydg
         GdsntxAPfkKY/N1Brzum5ADyRyhIlNAi3dhON2to0dC8935jyvoo6LzPvWiNJzbW9yO6
         H83tFxj8B4xSX8iFHL575oxmUhC5GsN+5LA9Z7zfcbz28PWo9N3TeA0P5QZ80ZvqXaDP
         pQApD+RisrmJaxMgbjYIWGg5AN5ZRV6/hy67iBzQ7NgaUCo+NHaFXRzwWusVDmuhcgM+
         Ke+iBVFK+3I53BPhxEuJm68x772SXpGxYo9fkJaRDnYlJbVGtj1MZiHz7V3odeiZ+c92
         vOsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ptMhjneAgHEQd5VcQLH1N0KeCJbdy4h2pZlM+9wp3bk=;
        fh=JcaWoqelY572EcQaWdTX+hAtAVzVq3In0uuf9Nx2DPo=;
        b=l47A22dF/txKYa/oYH6gpE1ZDqc3elngGokLrmo8jDQoLGKQe+KBCMuDUVDF1cj5Le
         G17YxhgDIm+703SLbqQdq1c4dTWCaB1JLjhOA5h4IPFJ8mQsC4jM9QqUHbobcxwPrpyR
         yzNXE5sKj3eJFZO1//dlUkiJARPVy8fCHOKUaCk/SxWv+HB7C8C/qyfvWG2nfY83/gM6
         WsIOFF31rclqbQJh9TRIM8KH6tlnCU1kVjxszfjY0DXzEJ2DRZxLbqprTNuMR2xN22Q9
         Po4OPUf5l+4ZF0aO7yTjQeEGpuYJMiLaCU+gkvek/eUYWuoKRWWff8jEw7wyj41QxuIm
         +iDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=YdmF=JY=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708039568; x=1708644368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ptMhjneAgHEQd5VcQLH1N0KeCJbdy4h2pZlM+9wp3bk=;
        b=TTTGE6hmm50xAyP8GvcodUrPTjVXxHSpa8lP41ECzulxwXquAtyaJioYbdKXSeyvkw
         XSCsDdkTAVebH2tRlfeOzT+GiF29xQtEG4Ror0XimDyRJwOB6yhQv35xpX3CHLb7sPn9
         Jr6rUaGfr551W+oiSeVY+SFCT7lf1UYVs5Dv9VjXh2Q2sGlQOrBXFPpeWs1Kheke3fCt
         kFLpEXNWAe994YHalCxRagbmprNJXLWD/HcNxUw+RU09hSdWcoXPVTS1Lf47oytaksD7
         j8VGZowGUmpD7QH63kI8NYGiEoJ3venCjBWwPBsp4EwK2YWpDvbZD3sUkpt/t8GK0Juq
         OF0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708039568; x=1708644368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ptMhjneAgHEQd5VcQLH1N0KeCJbdy4h2pZlM+9wp3bk=;
        b=YAq6MPWkKozJmCM3KFsdfjG3uZPNSWdz+6Ft74mt7iimHAT/K8wsxlsInRr0bXZRgn
         tlwr1788DyCZapsrWkxy+OjtbFq54PArk0Hbk2UASEZ6Pe4Jt+NlxHeCqjePef+mNoPl
         AVAB74T195KK5haDHGoSPQQSTwYjKqIjh+ixU+2qC8NPbergr0f+woQGGeh//fmGkeYa
         0T6lt6DK+S7uMPBcB+g+8jWom2LiXpMTjYNRqLmQPUd4C/g15EprwQ6NAqajkjExnSNK
         ZhUAYI33LNdl2rZlWbXVRkIceCArUy2AX5Zti27rz70fN1o2IwLIECSvYIcGSgSNo1No
         9wZg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXnBNucYTn3i/lL44G0xr0LY4C9oYVLA6v+sp1ERAwKiQYmgzwR9tQ+OiiomprEeIkgIIF93ZgFDr9zvR8kQc1h/C0SukOiGA==
X-Gm-Message-State: AOJu0YxCw56pXrYWUFcChuycuLzXD67Q6z2Y3jKub+X1GksTHFH/r3ef
	PRkVY9jTwoAiDHzSbuRu/tabpTKi1aX7jF2fJ8Fa7kKZWZuRyyt7
X-Google-Smtp-Source: AGHT+IGXXKhf3prRrRLcSLFwas5vxgMc7FXjjOnXHd3RYgSDKh8mV+4I4FlnMDklB0QDqFWv8KdCHQ==
X-Received: by 2002:a05:6870:5b92:b0:218:9e23:6826 with SMTP id em18-20020a0568705b9200b002189e236826mr3590868oab.3.1708039567622;
        Thu, 15 Feb 2024 15:26:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:15c1:b0:219:ab53:aa67 with SMTP id
 k1-20020a05687015c100b00219ab53aa67ls262078oad.2.-pod-prod-05-us; Thu, 15 Feb
 2024 15:26:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW/7xV3hAST+9+B19rfn3WacHoKTBJkuaFjtRNBFfD5PUlPXCZIzL8YA12ljZmsO7SdqdIk5OAbT6TEbmx3qV9O/zHA4mMLudNGmQ==
X-Received: by 2002:a05:6808:15a:b0:3c0:320c:8c3 with SMTP id h26-20020a056808015a00b003c0320c08c3mr3640004oie.32.1708039566871;
        Thu, 15 Feb 2024 15:26:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708039566; cv=none;
        d=google.com; s=arc-20160816;
        b=R0bOGlkhwv/svKNxOPVs5fcdYd3zsRHmPjyf3CC6Ogi80sjb2j3mDiJSfi0Giqt75l
         3E8TWuCzdickn/S7jO4f3qetRteVeFkQzOnf05XGghWhFZ7byVrHcRqeQ15ZJZlxH2kG
         p5RcSCmP0f7Zbql+EKeMhxpsd13qR7prLyDgfnQy2/1J27VR/ZW0ZO5aQnjNOKlM7VsG
         /thAEgkZ4Dg8NPLvu7YgjVoRg/sMTaoni2u2d6J3WwwgMwxA4IkUvon9XfmBHDdGgVxO
         xad/+NJ7yPEqUSfW+zck6qwJ4KJ65XoQExQ8H/J5lSvB5s4qXocUZ2Q5rQPa2NIi2hVO
         eZ8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=6XgPAigeqGXK136gymMYpZlF5a7viw1K17zUDVmMoKE=;
        fh=yAsR8mz6OHt7FqUIcMxTq2xSLRkYQrfOXi2SdkYqlko=;
        b=BE38a0kKuXK/EL1z8VzVsyKnPzgddiCEly1pbjWTcwNoOpgUuyu0gCs+9cGuy5bYso
         Fv75ILNHbXFrJQI5CsJmQiadMxDaVwhuzIUzu4sgQzCrgGLjcXMsgracjcScPlBcGo6P
         xsm2wGIoJwhJ3B6gZf5DlpsSvdYMDidpLW8DuoaOs3OPKjYbI+lYRee44ZeBBGXGiljS
         9VgL6ui5jsp8D8OadVEtmS/XkHBqBB+kBjZlAOaUxEQ0BBz+f0c+RhDh+j9iQqCoawdl
         3utOcy5o6KNYf8CIzo7zxSKugYr+ea6je0SFcCJ6lpk5yWq+X4kUJxIPqw97bl8pgpQq
         ZeUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=YdmF=JY=goodmis.org=rostedt@kernel.org"
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id v19-20020a05622a189300b0042c5830b4d1si187965qtc.0.2024.02.15.15.26.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 15:26:06 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id C3EEECE293D;
	Thu, 15 Feb 2024 23:26:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A6610C433F1;
	Thu, 15 Feb 2024 23:25:55 +0000 (UTC)
Date: Thu, 15 Feb 2024 18:27:29 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan
 <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 akpm@linux-foundation.org, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in
 show_mem()
Message-ID: <20240215182729.659f3f1c@gandalf.local.home>
In-Reply-To: <20240215181648.67170ed5@gandalf.local.home>
References: <20240212213922.783301-1-surenb@google.com>
	<20240212213922.783301-32-surenb@google.com>
	<Zc3X8XlnrZmh2mgN@tiehlicka>
	<CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
	<Zc4_i_ED6qjGDmhR@tiehlicka>
	<CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
	<ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
	<320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
	<efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
	<20240215180742.34470209@gandalf.local.home>
	<20240215181648.67170ed5@gandalf.local.home>
X-Mailer: Claws Mail 3.19.1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ydmf=jy=goodmis.org=rostedt@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=YdmF=JY=goodmis.org=rostedt@kernel.org"
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

On Thu, 15 Feb 2024 18:16:48 -0500
Steven Rostedt <rostedt@goodmis.org> wrote:

> On Thu, 15 Feb 2024 18:07:42 -0500
> Steven Rostedt <rostedt@goodmis.org> wrote:
> 
> >    text         data            bss     dec             hex filename
> > 29161847        18352730        5619716 53134293        32ac3d5 vmlinux.orig
> > 29162286        18382638        5595140 53140064        32ada60 vmlinux.memtag-off		(+5771)
> > 29230868        18887662        5275652 53394182        32ebb06 vmlinux.memtag			(+259889)
> > 29230746        18887662        5275652 53394060        32eba8c vmlinux.memtag-default-on	(+259767) dropped?
> > 29276214        18946374        5177348 53399936        32ed180 vmlinux.memtag-debug		(+265643)  
> 
> If you plan on running this in production, and this increases the size of
> the text by 68k, have you measured the I$ pressure that this may induce?
> That is, what is the full overhead of having this enabled, as it could
> cause more instruction cache misses?
> 
> I wonder if there has been measurements of it off. That is, having this
> configured in but default off still increases the text size by 68k. That
> can't be good on the instruction cache.
> 

I should have read the cover letter ;-)  (someone pointed me to that on IRC):

> Performance overhead:
> To evaluate performance we implemented an in-kernel test executing
> multiple get_free_page/free_page and kmalloc/kfree calls with allocation
> sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
> affinity set to a specific CPU to minimize the noise. Below are results
> from running the test on Ubuntu 22.04.2 LTS with 6.8.0-rc1 kernel on
> 56 core Intel Xeon:

These are micro benchmarks, were any larger benchmarks taken? As
microbenchmarks do not always show I$ issues (because the benchmark itself
will warm up the cache). The cache issue could slow down tasks at a bigger
picture, as it can cause more cache misses.

Running other benchmarks under perf and recording the cache misses between
the different configs would be a good picture to show.

> 
>                         kmalloc                 pgalloc
> (1 baseline)            6.764s                  16.902s
> (2 default disabled)    6.793s (+0.43%)         17.007s (+0.62%)
> (3 default enabled)     7.197s (+6.40%)         23.666s (+40.02%)
> (4 runtime enabled)     7.405s (+9.48%)         23.901s (+41.41%)
> (5 memcg)               13.388s (+97.94%)       48.460s (+186.71%)


> 
> Memory overhead:
> Kernel size:
> 
>    text           data        bss         dec         diff
> (1) 26515311	      18890222    17018880    62424413
> (2) 26524728	      19423818    16740352    62688898    264485
> (3) 26524724	      19423818    16740352    62688894    264481
> (4) 26524728	      19423818    16740352    62688898    264485
> (5) 26541782	      18964374    16957440    62463596    39183

Similar to my builds.


> 
> Memory consumption on a 56 core Intel CPU with 125GB of memory:
> Code tags:           192 kB
> PageExts:         262144 kB (256MB)
> SlabExts:           9876 kB (9.6MB)
> PcpuExts:            512 kB (0.5MB)
> 
> Total overhead is 0.2% of total memory.


All this, and we are still worried about 4k for useful debugging :-/

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240215182729.659f3f1c%40gandalf.local.home.
