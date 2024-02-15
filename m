Return-Path: <kasan-dev+bncBCS2NBWRUIFBBIVQXGXAMGQE74XMW7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 839E7856C94
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 19:29:55 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-51145df2a08sf701607e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 10:29:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708021795; cv=pass;
        d=google.com; s=arc-20160816;
        b=gRSZDPCZm3OGOy6Fr9yu7ydQjk960VrDXWcirCco4ptKKIQPJs4MKgzbs7CECNGjJn
         QIWOHImK7Dmqs4H69VQsov1avcTBCsJNqy7tJIAoh25ogiYohXI94ww0W8ibyLFRN12k
         C3cH4tZErMLErZ1ulm+W2fBcYRnyavZrNrYQqJq+ZRhZ3rCE3JsVwIfFgj95G6/FNjlN
         AHxjtNehIGf1TRhxTYmk8Jofqt0BJDOsfM2BuQgRZaP1m1eszCtPOZAVQe2v3sxsMsqI
         rH202AS2PoxS7PRZUOXyJqDFFXSSs8eAz7vcjb6INxPag3QyTcUQ2kTtKQ/tJcWA9RUl
         jUFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=JUP4G9huTOhtsns4kkuEfz+UO/HrBGAf5UtBatP6o5M=;
        fh=fYS87XAv1U4MyHL+yuYgSLmShciXNNnQmfW0N+KAMfk=;
        b=cRyLWipV9DNQ2V6h/2296+JM/jukJqgYteKg2xXevaqIdxryynxnyu719Kw8ZnRdWN
         rbxEPA9f0/mYH077nUmt765C+2LuuTPxgzJ+0iq2FJDu92uNlpDTjeqTnnYrS8fMRBH6
         Ky9rfRjQH6XZb2W2pisCpzPtAkcZnO0Zvy09ZWE85RqMHadJ9S3KmzJ4QeUzqxX51MoD
         ewvJB7qhX+CsjHj8iVirvKW+WnTz60dyRXaBbKIj4wTejxjLRDbsMmODAJiUbeCpHSLN
         wimNcAgOk9jSgM0z9a+X7IuFSadzaSymcj82qpVRnC3TmmsXEO1+lrr0REj0dlzy6tLE
         iXig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=f0hAZFJH;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708021795; x=1708626595; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JUP4G9huTOhtsns4kkuEfz+UO/HrBGAf5UtBatP6o5M=;
        b=O7Qv+BGgvmTyLUFgBvb83UIR8u7tyz6BwGZbxAMEslnCwTh0gXQgK3sUg2Mw27UB1+
         GMH3zlTc+JrKy4tZP6rnyOhJWLUK1jjL0jr+GEU+c7PE4WnlOHo0PYMEdhidhhNEhmLn
         zAXf0rX7x0q7MKQC0O6sU5qcroNMUV6RU0BbIiNiQhrHY2t4+xGFYVuUtpvy6CPPg8/9
         eyCujD9MJoaOavdRYuHAuSv06zIM+KKjZlQsXt+oW3Qmn4Hz0c66UVl16K4YbgZwlB7j
         ebUYqiDeS0AO7XRQKRVzcH/pNii0PQt0N/POoGWmJQXVBmjYxivPoxAV2QkipbcWppMI
         0ztw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708021795; x=1708626595;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JUP4G9huTOhtsns4kkuEfz+UO/HrBGAf5UtBatP6o5M=;
        b=qzcYroCu0S4mGFOKf0fZJCrQWYeZL9YUhZ6RJ+B5RTu0XiPACfsUtkZ0fhHXXZZQgP
         sgKDnCmyRF421hMT+qSSjE2rUWLklpAoMblsdfW13qHDTA+97hpZN+BHBegkO95HiwZZ
         6K2kDeIor0/R/zZf1nD4T/NoE9i6UbTI3AMwe0D7CN6HiQEJwHdz33ZJ1xKYeNXGoz0a
         lzhqI6rq9qFyFSQL7JeNFtMrNWKN/ndFBYE4FOcR897S5tUn22e7+BHQfsIqFhXVoLUy
         uQE5Qd9uK4eSxWafTlUNg9LMoLSwNZFB86c8Wf5dHuaDu+N/wokgeLXvEX5PC45lsl2e
         3WJg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZv3lC7vKvd8s1sbCl70alV1dZTRUB4MJ6AT1qYupCttOXEU+7iFwGicCnQaLdEl4/VTGVOaUz8nQOdYR4UMpb/1XZk2yCoQ==
X-Gm-Message-State: AOJu0YyM9rfWhbskAnrjPZJ88z2yX5quXVVj70ZoEPDf96rHNJd/wot+
	rn1dlCgcvi4t8QyuXUnLaC+mfP6kWMBH9C3mSRXeIMfPS80RyPa0
X-Google-Smtp-Source: AGHT+IERMtrK7zXNA5Z8oJlhy0th4CKRLph9O5R4qh3MPPvQsT+XlcsAY61U8KinaCdJdWaaDn+58Q==
X-Received: by 2002:ac2:41c8:0:b0:511:463c:32c1 with SMTP id d8-20020ac241c8000000b00511463c32c1mr2048587lfi.19.1708021794207;
        Thu, 15 Feb 2024 10:29:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2346:b0:511:4906:32c0 with SMTP id
 p6-20020a056512234600b00511490632c0ls12325lfu.1.-pod-prod-00-eu; Thu, 15 Feb
 2024 10:29:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX6CkZjsy9TIz+vRt0Y/I/sWQlsfoZ/YEMTfSmsHnOCClvrfBGCcYauj8pbOIb02aigNhtYAPKbF+361Akpa/XewulQ1s8Q7i+g3Q==
X-Received: by 2002:a05:6512:200a:b0:511:7b80:2265 with SMTP id a10-20020a056512200a00b005117b802265mr825290lfb.5.1708021791904;
        Thu, 15 Feb 2024 10:29:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708021791; cv=none;
        d=google.com; s=arc-20160816;
        b=GbZnALe6jJBeh4GfOqhW7laFImTVf55QWyIYoXJaBeqfL+OERTfRSNdnGsyL8G/nB7
         XjaczdiSY/CsLYtRaX3v163R1i8Gb3ZzP93DYm4QF1AS+4KQ5/Yo+6BWxvrpRjwAdv3g
         lVFLBGlnqdfhphk1hEvA/xxMmegqLG8lxacbEOfmh0qD0vcf0ffUasy06DhE1dXfuRbZ
         W0ya03k8hd6Ae9A1VrutDUc4SWUiI+RAihmENHZfa0NdlJFOEg5lg+PE7ivge+A4r9n5
         W6zHr8ktchdSOg31zrAizULPwxgKpGTx+VKDiZlIeNEb/juQhrXpjsgRRkAXFJ/5hGnz
         5xKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=hhfBmJirNsqHXJktLhuMpinYcutoXu2NT5NVAvXIUmQ=;
        fh=ehKi8kNWGQ5h25Xod4jlxvellAh0+h4N7jJOW8PiP+Y=;
        b=IFKoa9T+Cu2cDPDzupM0CHLVMqL1rvfI1R0BPvCZWuRJ66qOZdI/scLxJdaT0Dqqju
         1qyWdZ3xqNC4zPxDpwzrpy7yFJDMw9nK3zpKJCYttO2az18b/nxSiYgnk5KdRNy/OjOH
         h+leOXTFDJJhFtvXILueOOLL46zIbS/F8ACLl/7nTHSn2Jlbs8t87/91vjOIzlX0pdfc
         +nGlG5t9oNg7fdXTZE1ksRPmaPjsshbJWDVPy7fMdiB/KL4fe/lwiwxHnV6I9jlDl3Ne
         d9UAmOUeCWHAcN4YGCdy1tQ/nvywwwvQr733oYdocs3jESqN0vuMW2TiAUMnK/d24Y95
         EPOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=f0hAZFJH;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta1.migadu.com (out-179.mta1.migadu.com. [2001:41d0:203:375::b3])
        by gmr-mx.google.com with ESMTPS id a6-20020a195f46000000b00511429b36e7si142487lfj.1.2024.02.15.10.29.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 10:29:51 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) client-ip=2001:41d0:203:375::b3;
Date: Thu, 15 Feb 2024 13:29:40 -0500
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
Message-ID: <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=f0hAZFJH;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Thu, Feb 15, 2024 at 08:47:59AM -0800, Suren Baghdasaryan wrote:
> On Thu, Feb 15, 2024 at 8:45=E2=80=AFAM Michal Hocko <mhocko@suse.com> wr=
ote:
> >
> > On Thu 15-02-24 06:58:42, Suren Baghdasaryan wrote:
> > > On Thu, Feb 15, 2024 at 1:22=E2=80=AFAM Michal Hocko <mhocko@suse.com=
> wrote:
> > > >
> > > > On Mon 12-02-24 13:39:17, Suren Baghdasaryan wrote:
> > > > [...]
> > > > > @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, nodemas=
k_t *nodemask, int max_zone_idx)
> > > > >  #ifdef CONFIG_MEMORY_FAILURE
> > > > >       printk("%lu pages hwpoisoned\n", atomic_long_read(&num_pois=
oned_pages));
> > > > >  #endif
> > > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > > > +     {
> > > > > +             struct seq_buf s;
> > > > > +             char *buf =3D kmalloc(4096, GFP_ATOMIC);
> > > > > +
> > > > > +             if (buf) {
> > > > > +                     printk("Memory allocations:\n");
> > > > > +                     seq_buf_init(&s, buf, 4096);
> > > > > +                     alloc_tags_show_mem_report(&s);
> > > > > +                     printk("%s", buf);
> > > > > +                     kfree(buf);
> > > > > +             }
> > > > > +     }
> > > > > +#endif
> > > >
> > > > I am pretty sure I have already objected to this. Memory allocation=
s in
> > > > the oom path are simply no go unless there is absolutely no other w=
ay
> > > > around that. In this case the buffer could be preallocated.
> > >
> > > Good point. We will change this to a smaller buffer allocated on the
> > > stack and will print records one-by-one. Thanks!
> >
> > __show_mem could be called with a very deep call chains. A single
> > pre-allocated buffer should just do ok.
>=20
> Ack. Will do.

No, we're not going to permanently burn 4k here.

It's completely fine if the allocation fails, there's nothing "unsafe"
about doing a GFP_ATOMIC allocation here.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw%40meusbsciwuut=
.
