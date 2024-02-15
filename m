Return-Path: <kasan-dev+bncBCS2NBWRUIFBBHFUXGXAMGQESNKQFMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B204856CD7
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 19:38:21 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5115b1e3facsf1291961e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 10:38:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708022300; cv=pass;
        d=google.com; s=arc-20160816;
        b=fNvgtg7faiBaPjoGcpX0AfvUjz5fWqggijT8AHk9pcrrsC1ktZ2BrgmnXpfZA7hR83
         KYHwzUf6T3W30fTlxK67oJpPqc3xt/2bl9zbkY/rjkDzTHe4Vm9QhtKeoWpHsVy3Nyk0
         Kb0IKgTId4WLe7LE8WVRGEXCoU+n365fFNHA03g85ktLMryhPmxKR+K6oZdQO70DlilW
         x1OLc45wMblDIwVAeEaoWCTsF2ySnGSXqUuMmzx5viBbM5e/3RZ0GlejpEoXxK3rFEpI
         o79BYfvqvRIJj4v+RVbHS8pgemVKoqMJ7o54XuyjQoZbnJkE68J+f2zEbcFkHlrdbEJI
         c/RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=m7V3J9lktQBMJaOQPt8ARrOgCTlGnZBZljeLKytO1IA=;
        fh=NZBsIXWWl35Je3VHcKOfdRNWo9HvSNJKhQ2mqV/Z9wU=;
        b=BEF+y6YgQUzlbCHuM1MySUU7sZ+xuyDaZc1muELZzZ3nZy/hAGh8jofnafRhFI7Vwq
         S2A817Sejs8ljkbgdj++h3fkUzmasEUbFYoUXsEvFNoVsKbrFJ44X5BIO0WTtNxulCMz
         Td+8T+BOIKYZyJ4kkrqW967+dLLBdWkjuMj5JMNOAL7HaTLJZxfonq8DoYJJOoS9j/7y
         47JkKkFkdZ41s6QnLuu1WzwA+bDUtp2trO7I4pfpSTHX0j5PXNogO5BqjVz4EYgVHKIO
         UJVXGIEHJxXeeA0MgwaPcbqHJw1F84p0EW8uz49Ewn1r82W35zfm3WSHrq4sGMtsiY+V
         dp+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="JN/LPHA6";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.189 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708022300; x=1708627100; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=m7V3J9lktQBMJaOQPt8ARrOgCTlGnZBZljeLKytO1IA=;
        b=T0tCCZE5aEYuvTppVnqvHLN62Kd0Rv+NEatL0CGIItb1QELzEIV+gED0/ZIsliwzno
         gX2tl71BDYUmkvQQYNaRGKnS0xWBkMKAqUw6XiyyDRllQc4iGILxUwbTXWglMtXvQqSA
         iVJKGdhstdU8Pxc7Qef6yETb2WDWSi82THLQUuHukjXPPRlR9nVja3t0S9aVRFh8fVP6
         7CRm0MJWWUrQEq0M7kvRUnE2CuPSImA73l8wdYg96nkZWeSVK/eImiqzETahJF9ns20A
         c+u7locPN4e2RAI95oaJEPmabzIz+9sqncXTxul9mef9/CiGYygTPL5UcyLCnBKAYN1Z
         JOiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708022300; x=1708627100;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=m7V3J9lktQBMJaOQPt8ARrOgCTlGnZBZljeLKytO1IA=;
        b=bQx+QewMWTzNFnYZHn8oOXWnhCWYqZL5VU6/lMow3swZNowNFn+BjsWvupQMyQNzWM
         qm6rNQu6vxmOOVILO2kfTQq19lbZczQHRzHNNurV8cGmvaLXbVpWLLgWyu3ZKmtuLXJO
         302H+6hxOxMiSfjJGRskA+yIjb0EfxqfpYFopBvQTWorzJpzaBG23cLoFbeW8nVi8c6s
         WB6bsGlB+aewpZgOH1xuyNE/DF9u8zWY/NhQGrODtKiqUfhWwd+EtE1mFN+3EKIXT/49
         Q6dkxGM91nbQXMt1hcZI8ylr2VsFYSjW6PkiXsk1ROSb1l5VpYaS/Sg0/+s252zog949
         AF3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXYrBMmXGebU+PZiYqGG+MKSNzVSmqtJIgkSREFIiCue+KiiRGZpD8AW9EIjDbBmUV62n+q9/iP7zVJF2jSHDvbLM8SkCqsAA==
X-Gm-Message-State: AOJu0YxwVUro8ZNT1F4ub3aRt95N4wmq4+S0PV7b5mN2dfSbz7hWKD74
	q43SNuM10uLV25abfmqfiSF6Mb2IXfjU5UaA5EY6EVLwbvMZM94Y
X-Google-Smtp-Source: AGHT+IF5QQ8/Dc4wk73Ox4JmBKPBT432NZ3qHcGiLMnyVP+IQ2ZKdDg6G2Lapv2XoIzOV2EB602pOA==
X-Received: by 2002:a05:6512:36c5:b0:511:9e11:f16b with SMTP id e5-20020a05651236c500b005119e11f16bmr2028855lfs.8.1708022300289;
        Thu, 15 Feb 2024 10:38:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5293:b0:562:1a24:52af with SMTP id
 en19-20020a056402529300b005621a2452afls30088edb.0.-pod-prod-05-eu; Thu, 15
 Feb 2024 10:38:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXoCcDHJzA8hY07bHnQsxLG4fILlcXrOu9loS0JZCDUsD2d1iwNX0oBLbqpzR9IYNbLIzOtnzb7eTuQMTSaGg7V078BQtnoY8flcw==
X-Received: by 2002:a17:906:468a:b0:a3d:6ef6:9192 with SMTP id a10-20020a170906468a00b00a3d6ef69192mr1827690ejr.16.1708022298655;
        Thu, 15 Feb 2024 10:38:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708022298; cv=none;
        d=google.com; s=arc-20160816;
        b=kgehTIoGtwAVrriM+wxAqX9ojpGcNE/oYGle/Ao/n3kT21LJcV1RNqjLRWR6hVYjIY
         AX2YLzGZjmmCNKy7elakxRnqtzpOJO1xvsOj4vEznzmyvG35BPCt4xOaNLQyFrPd9DH/
         VtZkxM6WtBcYZxxDRMavwBjh+WcYeNhflPY+87oPC0Eoo6JEVuhp40GnUQHHX/5qJ6ZR
         3UaJPQU2rmbJQU/ekJL9dR8WS5dtJsYvJoN3WmFBnYYKyY9um64W4In5KP/Lcu+mEQYH
         N5zYLxrReGiq65yP8kv0YzbtUk0tzbqSfBQBJLbggMIbRGhNYU/H/zRUAnARZ9j3stVY
         6M8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=MX5iN/R1aA7qp1uBjwVKqzgAyTA6O01vDbmEmEpF1HI=;
        fh=ehKi8kNWGQ5h25Xod4jlxvellAh0+h4N7jJOW8PiP+Y=;
        b=xKGpeH0coNofx4myMtOH2krTIOrvBV+lwWwEeQjwEcvaQ6MKdhg2AnLV2/mFAjxzHt
         VwQqSocsxsxSkygFk7cP/Iub4zTO9OSlv7HSyHHkJq7olN1ajvY6HzUoEyWBUQj3BFeD
         44B+OLTF1TBduDMlcEgJznxNJwp2JLwIkAQbLv0doBtrLwAQiWm+ZVOkdhYbnHrHfLs7
         2fjRgZ4tcqjrRDFMarqu2EPlFDctmvwSbfdLYwWjuKBAwJ41R9wiqrtS9AnQayPWm+kT
         7nVIFUtdPW9U552S2VgClveFB7+bHvQAC/BFTXx1SZIUb4yZBHYqfxBUMt8TBQMUtD9M
         mQJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="JN/LPHA6";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.189 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta1.migadu.com (out-189.mta1.migadu.com. [95.215.58.189])
        by gmr-mx.google.com with ESMTPS id v3-20020a1709064e8300b00a3d6acddb2bsi77863eju.0.2024.02.15.10.38.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 10:38:18 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.189 as permitted sender) client-ip=95.215.58.189;
Date: Thu, 15 Feb 2024 13:38:03 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <qjw54t5doykhej63f5l5k7zee4fuiekkdp7px67f3bgu7y4bec@2akbmyhn2ubz>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <CAJuCfpFCu73eCMo-hd=vvvMhGjEuOwvkcGb2DuDssHC5soNFGw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpFCu73eCMo-hd=vvvMhGjEuOwvkcGb2DuDssHC5soNFGw@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="JN/LPHA6";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.189 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Feb 15, 2024 at 10:33:53AM -0800, Suren Baghdasaryan wrote:
> On Thu, Feb 15, 2024 at 10:29=E2=80=AFAM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Thu, Feb 15, 2024 at 08:47:59AM -0800, Suren Baghdasaryan wrote:
> > > On Thu, Feb 15, 2024 at 8:45=E2=80=AFAM Michal Hocko <mhocko@suse.com=
> wrote:
> > > >
> > > > On Thu 15-02-24 06:58:42, Suren Baghdasaryan wrote:
> > > > > On Thu, Feb 15, 2024 at 1:22=E2=80=AFAM Michal Hocko <mhocko@suse=
.com> wrote:
> > > > > >
> > > > > > On Mon 12-02-24 13:39:17, Suren Baghdasaryan wrote:
> > > > > > [...]
> > > > > > > @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, nod=
emask_t *nodemask, int max_zone_idx)
> > > > > > >  #ifdef CONFIG_MEMORY_FAILURE
> > > > > > >       printk("%lu pages hwpoisoned\n", atomic_long_read(&num_=
poisoned_pages));
> > > > > > >  #endif
> > > > > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > > > > > +     {
> > > > > > > +             struct seq_buf s;
> > > > > > > +             char *buf =3D kmalloc(4096, GFP_ATOMIC);
> > > > > > > +
> > > > > > > +             if (buf) {
> > > > > > > +                     printk("Memory allocations:\n");
> > > > > > > +                     seq_buf_init(&s, buf, 4096);
> > > > > > > +                     alloc_tags_show_mem_report(&s);
> > > > > > > +                     printk("%s", buf);
> > > > > > > +                     kfree(buf);
> > > > > > > +             }
> > > > > > > +     }
> > > > > > > +#endif
> > > > > >
> > > > > > I am pretty sure I have already objected to this. Memory alloca=
tions in
> > > > > > the oom path are simply no go unless there is absolutely no oth=
er way
> > > > > > around that. In this case the buffer could be preallocated.
> > > > >
> > > > > Good point. We will change this to a smaller buffer allocated on =
the
> > > > > stack and will print records one-by-one. Thanks!
> > > >
> > > > __show_mem could be called with a very deep call chains. A single
> > > > pre-allocated buffer should just do ok.
> > >
> > > Ack. Will do.
> >
> > No, we're not going to permanently burn 4k here.
>=20
> We don't need 4K here. Just enough to store one line and then print
> these 10 highest allocations one line at a time. This way we can also
> change that 10 to any higher number we like without any side effects.

There's no reason to make the change at all. If Michal thinks there's
something "dangerous" about allocating a buffer here, he needs to able
to explain what it is.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/qjw54t5doykhej63f5l5k7zee4fuiekkdp7px67f3bgu7y4bec%402akbmyhn2ubz=
.
