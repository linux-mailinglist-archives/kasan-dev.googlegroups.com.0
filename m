Return-Path: <kasan-dev+bncBC7OD3FKWUERB4MT7CXAMGQE5DBZCQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 78262869BB5
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 17:12:35 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3650bfcb2bfsf36673665ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 08:12:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709050354; cv=pass;
        d=google.com; s=arc-20160816;
        b=M2kgEpPe2IENdKS5Rw0STULtM1lgW7ogYZOh6HzF7jSJFV5CDcDxTXuECOVyP7LYzI
         1cNWPvaWhkHFZSH2UDisoMQltbey8SqIvkPTN0GErpCj9sh4kiItQASrPS1C9Ok+LlQG
         bIWHoeXzqEgTfzWC5m1lNnE5yOYdzmq+SyJbQCnc7a5W02Kqgo6vHdB8/3o8C6n/RsYK
         MFP/ULPS5wgg2pE5NZFeqFyWp69BeLxB8tfRv+x3FaziFTJv+wTGRdCx5UUuUb0lXnd8
         vDC6uBpX0cnXK18BXL30TEHdfz3RNufVzlNB+2TEDReDDDnfWsuafptzEQs0RVW/tDwS
         xv/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QMygLBlea8lyc7naVM+wkslzsCJRpfTs0cxZ++MK7Pk=;
        fh=tukggT+8OuOepi3yEAR0eSvG6f+WOFrj6hZAb+mce8c=;
        b=iEXxc3IhWr8rqFtmOCXBAEt2IMkM6VJtpAELGkFEM5ADxk4ym5RUZEFtXr6fWhJIZF
         HO6msKaIqlGvfFVffm2WdRguxnQcCsdmSmbYieqDrW16kB5/yU8hGAUk8i7+xLjyxDbg
         0Q83Bp/FJPYYcR7DUGzSmK/dlLKE6ayBVL1U0VovmDjdiAc6a4SngXIcxwM09EgANDtF
         a2FMZUZMThuZuMBlvibjsB150YZdnaq8Euri1agRGFjVtHapVn8GyWT3PUBrihFLTVav
         vj8HP8jCEuW3+9UoSIwjgl2424yxHw27ro1/PYlyxUgK8AVFz4/U2C75qy3mI477IZFh
         kL4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QzA1emPn;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709050354; x=1709655154; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QMygLBlea8lyc7naVM+wkslzsCJRpfTs0cxZ++MK7Pk=;
        b=QfxhT/ZZ+rmVKLxc1ZfRG81VYKTAcnEUcnEBK4vR00uY4bb3bPJO/2AgPx/RqPvGWC
         PdPwYiBB8jvp9VOvF+D5Z5v354Gma249uq5HTbrgCpdTCTT/kdxqs+GRAVYxQ3NPzWQF
         v3DukMPi7kWvDg91+4MUTzmcNRggyjZU/QQ6bPEmb+HUXY4ukrmmsja5+6Dvx620GYKV
         Munv+ixPFsxPK29iOz6oYWztoOFvDfM5AkjqgfaG4gG68UROMRbPfKgwf1uQl+nXHb2f
         un8wQlts/2OnMKzyCShyPsR5tG/TgeG94D2DqNgGfrsXlBzB9zdHd0oeqeX6dqqtLdYv
         dFHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709050354; x=1709655154;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QMygLBlea8lyc7naVM+wkslzsCJRpfTs0cxZ++MK7Pk=;
        b=m/QxCveqwaQrplF73Gi24AUceTOFg8q8UdEnG4k4rOuceO3TH5fM4yDj6M/YuSMH/U
         QY1P6SL14ii2ddQXeH/sKRKiGpTtpecgcNpV9sRqTVGpPMCI2Yfng7I8yr0xOdGA6/1f
         cX3Tm/C2SqjuxjW82USBmNFRyC2hgotgkRCEWMyWVY08KQpyWIsgaKdSbmq+qP6dV9vd
         NNC3nkM3wMu7W3K+txYycF3nuz3bq2l+jKocoS9OogKKSUWJQY+6daf6HQkOK+FgIDpK
         no8+FVVxEyZSiSF9gAQKvGSClexwRHObgBXq6bwu/tr8W1s1OLkrYO9M/VoTu8dxz8o1
         3ZAw==
X-Forwarded-Encrypted: i=2; AJvYcCXwW2skyQS/d7DCiyNli5FhWdcpzacgOOGO3CuB+qedvVNSznajX+PpFaXYHJ1PPjC+WvP0R1jLrgqxNvvJrPOfr+I3AzAP+A==
X-Gm-Message-State: AOJu0YzYEhTUXwJPu0zkPhf9igu7ytRjIT3E6+8z9eW7HGj5lGE1kwp/
	durO1UiqVYAwfJ3nw8uWGk2UVgU9bdTG0Kuj3forjGyKeXpnrpf9
X-Google-Smtp-Source: AGHT+IEuXLeI5Hs2IFs12gGdpjvBCC+Z2XTDhJfq0GTqr8SnRs9xkxCtlg+KPlYiHlottyUmKKcFsg==
X-Received: by 2002:a05:6e02:ec6:b0:364:e54:9fad with SMTP id i6-20020a056e020ec600b003640e549fadmr7971733ilk.2.1709050354045;
        Tue, 27 Feb 2024 08:12:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c4b:b0:364:ff62:9c77 with SMTP id
 d11-20020a056e021c4b00b00364ff629c77ls2486203ilg.2.-pod-prod-00-us; Tue, 27
 Feb 2024 08:12:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX+ILmFc91CrdED+PYTEuzhacsxesjDDq4MceCoXY4fdhDvw75cLHF6mgbzfQ1qcQOvs7n7WLZ5ZQkI7WNrtOY2umuRkozVTG3OqQ==
X-Received: by 2002:a6b:a0e:0:b0:7c7:a554:9011 with SMTP id z14-20020a6b0a0e000000b007c7a5549011mr7044626ioi.10.1709050353209;
        Tue, 27 Feb 2024 08:12:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709050353; cv=none;
        d=google.com; s=arc-20160816;
        b=nWDPiOsoHn2A86FnAvx/So+b3SbswYHsBdP93P3hN7L8esk50u8+7sTmd023IUM3x6
         JqQL0Au4uTPCXIfty625p2vKTQLSX9Qpc8BfGqA3tWQ/ho2JXktS4Lkb8A/zNfUcV60S
         gbIsS4Fy0t6dqqgGn1uxXgPkQeSyAoorMkxXwfSNuHgE9Ev+62jxk9oQVt1Lp5pKzSlw
         by2pBEV6Ef+z8yx2Gq5OH3hvM5shTo6G9uKdQ80GPAe2LO00WTKaIptsDTaXHbJY/5mQ
         OTA4PoASkZ+4m8lbLCJAw2YAS0/VBp+qhRvZih8JAcMA4KjYwH4+1erWt/2rK+nuFI/a
         nqgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dNhcz6LZWcGFo7q9Dz7N+i5BDAre97NpDL4CFWNtFMg=;
        fh=3AaQRf/0v3QGanLuk3vYn6Ozuset73/qIUb0cO3S8DA=;
        b=hLcOWzfUZ752Y8bvg5pGTuih5KDPOx6D+aX520Yo+IiaK2CWZVMIxhW9TuFGBgvkqE
         3+pMHt9dEMMZfjkcRCN7A83TeuZbQiD9CuYlK7A0L2LP2fsDHr2t113mgYhXQqruSVrs
         jlTEyLrcRB7FSHISCHhHKxXBNDfez059XvB6zXRhGB8QG0aM47DnO3/jCKlihSSf1D1v
         D6/Io6DODPDD/ll3/i89GRR5/9CQ8x3UAecmrRdzoV53P8ziwnLVsiBaCcYVZneWDQ1M
         2Sersia3ZBFV1XECx6Z70RhRNEMfXT4M0MlqWYtXj+CPrzfDQqOlLcFVTgUbjQvFQLxO
         jApg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QzA1emPn;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id b23-20020a056602331700b007c769ed87a8si288880ioz.1.2024.02.27.08.12.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Feb 2024 08:12:33 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 3f1490d57ef6-dc6cbe1ac75so3674388276.1
        for <kasan-dev@googlegroups.com>; Tue, 27 Feb 2024 08:12:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXWaIh9Ild0eftUr2B+v+5SAGHHQcwLQsm4566rSVc7sf3ITxCNJHAtZCkf/UynWJW4TzdrfbnX9WH4IX73YsJRH3BzXxOMscTIug==
X-Received: by 2002:a25:c501:0:b0:dc2:2f3f:2148 with SMTP id
 v1-20020a25c501000000b00dc22f3f2148mr1714724ybe.29.1709050352173; Tue, 27 Feb
 2024 08:12:32 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-32-surenb@google.com>
 <ae4f9958-813a-42c8-8e54-4ef19fd36d6c@suse.cz>
In-Reply-To: <ae4f9958-813a-42c8-8e54-4ef19fd36d6c@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Feb 2024 08:12:21 -0800
Message-ID: <CAJuCfpFnqGLj2L5QdnMWYxX6ENqc0Gnkc3pjURu7CmGtNMhE1g@mail.gmail.com>
Subject: Re: [PATCH v4 31/36] lib: add memory allocations report in show_mem()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
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
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=QzA1emPn;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as
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

On Tue, Feb 27, 2024 at 5:18=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > Include allocations in show_mem reports.
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>
> Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
>
> Nit: there's pr_notice() that's shorter than printk(KERN_NOTICE

I used printk() since other parts of show_mem() used it but I can
change if that's preferable.

>
> > ---
> >  include/linux/alloc_tag.h |  7 +++++++
> >  include/linux/codetag.h   |  1 +
> >  lib/alloc_tag.c           | 38 ++++++++++++++++++++++++++++++++++++++
> >  lib/codetag.c             |  5 +++++
> >  mm/show_mem.c             | 26 ++++++++++++++++++++++++++
> >  5 files changed, 77 insertions(+)
> >
> > diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> > index 29636719b276..85a24a027403 100644
> > --- a/include/linux/alloc_tag.h
> > +++ b/include/linux/alloc_tag.h
> > @@ -30,6 +30,13 @@ struct alloc_tag {
> >
> >  #ifdef CONFIG_MEM_ALLOC_PROFILING
> >
> > +struct codetag_bytes {
> > +     struct codetag *ct;
> > +     s64 bytes;
> > +};
> > +
> > +size_t alloc_tag_top_users(struct codetag_bytes *tags, size_t count, b=
ool can_sleep);
> > +
> >  static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
> >  {
> >       return container_of(ct, struct alloc_tag, ct);
> > diff --git a/include/linux/codetag.h b/include/linux/codetag.h
> > index bfd0ba5c4185..c2a579ccd455 100644
> > --- a/include/linux/codetag.h
> > +++ b/include/linux/codetag.h
> > @@ -61,6 +61,7 @@ struct codetag_iterator {
> >  }
> >
> >  void codetag_lock_module_list(struct codetag_type *cttype, bool lock);
> > +bool codetag_trylock_module_list(struct codetag_type *cttype);
> >  struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttyp=
e);
> >  struct codetag *codetag_next_ct(struct codetag_iterator *iter);
> >
> > diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
> > index cb5adec4b2e2..ec54f29482dc 100644
> > --- a/lib/alloc_tag.c
> > +++ b/lib/alloc_tag.c
> > @@ -86,6 +86,44 @@ static const struct seq_operations allocinfo_seq_op =
=3D {
> >       .show   =3D allocinfo_show,
> >  };
> >
> > +size_t alloc_tag_top_users(struct codetag_bytes *tags, size_t count, b=
ool can_sleep)
> > +{
> > +     struct codetag_iterator iter;
> > +     struct codetag *ct;
> > +     struct codetag_bytes n;
> > +     unsigned int i, nr =3D 0;
> > +
> > +     if (can_sleep)
> > +             codetag_lock_module_list(alloc_tag_cttype, true);
> > +     else if (!codetag_trylock_module_list(alloc_tag_cttype))
> > +             return 0;
> > +
> > +     iter =3D codetag_get_ct_iter(alloc_tag_cttype);
> > +     while ((ct =3D codetag_next_ct(&iter))) {
> > +             struct alloc_tag_counters counter =3D alloc_tag_read(ct_t=
o_alloc_tag(ct));
> > +
> > +             n.ct    =3D ct;
> > +             n.bytes =3D counter.bytes;
> > +
> > +             for (i =3D 0; i < nr; i++)
> > +                     if (n.bytes > tags[i].bytes)
> > +                             break;
> > +
> > +             if (i < count) {
> > +                     nr -=3D nr =3D=3D count;
> > +                     memmove(&tags[i + 1],
> > +                             &tags[i],
> > +                             sizeof(tags[0]) * (nr - i));
> > +                     nr++;
> > +                     tags[i] =3D n;
> > +             }
> > +     }
> > +
> > +     codetag_lock_module_list(alloc_tag_cttype, false);
> > +
> > +     return nr;
> > +}
> > +
> >  static void __init procfs_init(void)
> >  {
> >       proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
> > diff --git a/lib/codetag.c b/lib/codetag.c
> > index b13412ca57cc..7b39cec9648a 100644
> > --- a/lib/codetag.c
> > +++ b/lib/codetag.c
> > @@ -36,6 +36,11 @@ void codetag_lock_module_list(struct codetag_type *c=
ttype, bool lock)
> >               up_read(&cttype->mod_lock);
> >  }
> >
> > +bool codetag_trylock_module_list(struct codetag_type *cttype)
> > +{
> > +     return down_read_trylock(&cttype->mod_lock) !=3D 0;
> > +}
> > +
> >  struct codetag_iterator codetag_get_ct_iter(struct codetag_type *cttyp=
e)
> >  {
> >       struct codetag_iterator iter =3D {
> > diff --git a/mm/show_mem.c b/mm/show_mem.c
> > index 8dcfafbd283c..1e41f8d6e297 100644
> > --- a/mm/show_mem.c
> > +++ b/mm/show_mem.c
> > @@ -423,4 +423,30 @@ void __show_mem(unsigned int filter, nodemask_t *n=
odemask, int max_zone_idx)
> >  #ifdef CONFIG_MEMORY_FAILURE
> >       printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned_p=
ages));
> >  #endif
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +     {
> > +             struct codetag_bytes tags[10];
> > +             size_t i, nr;
> > +
> > +             nr =3D alloc_tag_top_users(tags, ARRAY_SIZE(tags), false)=
;
> > +             if (nr) {
> > +                     printk(KERN_NOTICE "Memory allocations:\n");
> > +                     for (i =3D 0; i < nr; i++) {
> > +                             struct codetag *ct =3D tags[i].ct;
> > +                             struct alloc_tag *tag =3D ct_to_alloc_tag=
(ct);
> > +                             struct alloc_tag_counters counter =3D all=
oc_tag_read(tag);
> > +
> > +                             /* Same as alloc_tag_to_text() but w/o in=
termediate buffer */
> > +                             if (ct->modname)
> > +                                     printk(KERN_NOTICE "%12lli %8llu =
%s:%u [%s] func:%s\n",
> > +                                            counter.bytes, counter.cal=
ls, ct->filename,
> > +                                            ct->lineno, ct->modname, c=
t->function);
> > +                             else
> > +                                     printk(KERN_NOTICE "%12lli %8llu =
%s:%u func:%s\n",
> > +                                            counter.bytes, counter.cal=
ls, ct->filename,
> > +                                            ct->lineno, ct->function);
> > +                     }
> > +             }
> > +     }
> > +#endif
> >  }
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kernel-team+unsubscribe@android.com.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFnqGLj2L5QdnMWYxX6ENqc0Gnkc3pjURu7CmGtNMhE1g%40mail.gmail.=
com.
