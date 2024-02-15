Return-Path: <kasan-dev+bncBC7OD3FKWUERBZVZXGXAMGQELD3VUTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 379F2856D19
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 19:50:16 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1d932efabe2sf206005ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 10:50:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708023014; cv=pass;
        d=google.com; s=arc-20160816;
        b=jpJiUETwOsiLYnHPaLHYD7nhInkJzRFnANQfgnB2IC+QnXsCbvbe8NBXguoGZ55E+W
         vAXbGRx7PQ58fsi6zjXcr0O6ZGOvP0fHXNYsiYbiJiaudsy/3WM8lkL2C7zR4pTZ2dVa
         xLASem+qomC536sPvPnTe2yFodLFCphzKUShjpZO72rbENziW3la39+0VBuX+vh83GT+
         ciOSlPj/OYH7lkHSSi8WrwGNIktbwCos8yTYPyCp0ACkJCzAWi/KcZY7ptaDDRCIBalG
         g9KRh/4GYR+jqSmnbiyq7BqMHKh+yZ49MwUvatBbHEKAOfdyLUUVAxlDGW/QCZwvQGIL
         iyfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N11cOcAoirOetqfW2tjKL75GDTBHr6gCE5w54Gn6yOI=;
        fh=XsZe2jjZyTbHir486YxgXmzu0mRtdXHowjzNTmmgW6U=;
        b=DljGp/zsWQjxOzewC01cqO8STW6Pjrg8LVwh3Vc8q4DkwjcOg4brFgmkgpWltFKxry
         gsOmBBpnQZ/PyRWLI+uKB0X4C09oRCgNEQfZYHTG1unafnmVBsB+nV8SX1h/3Maj3KPh
         FHKATeaFG+DtVqqUWCvO5d9ATt2j55kwXWePprgbjCOHb7+wHGpToWkx/SIk10Zlb1/b
         Rnng/1lVVaH67pzMAknuyEf75OHMpVv3YjAWJH6LYirgzvZY1B4tM5CQYrXEAj3AHuMd
         Z3ovvbb/irNenmSKKTkVEHipJyAk+G83sk6rYhte8Erv4+RZ9M5oLBrqmOthkFPVWdXm
         hU+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YrseHBMI;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708023014; x=1708627814; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N11cOcAoirOetqfW2tjKL75GDTBHr6gCE5w54Gn6yOI=;
        b=WzJqOBwxFVzCxekwb0mmCY71HfjqD8prgl8kihkKOKrkSd1lp+EL+5aS4HXatH6GRy
         THf7SK/PevoTA9knQKE6YRYw53A3vyk3nT3tPQWNhVXmDtpxcRvrV/af1+a+5ikV0eDk
         Zb3QsmFKWflQxicmVrra/+hcuB3z4M09qq+LII6EZG0ijb5oEBbT+b4Tk2uGQ8hEERfG
         S6vg8GgHFz51jDtJtqP6PHrmD9aQdFjhOzMj7fTfdJNkr2/aum3ZyLS6C2HzcsZnmGvj
         AFTsRVDi5NV6Ooy4ELtWNSn78IFnD2zTmfWhxVM+3iQIfvZ528pjK/V9JYsbmNNSGW8S
         zu+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708023014; x=1708627814;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=N11cOcAoirOetqfW2tjKL75GDTBHr6gCE5w54Gn6yOI=;
        b=miorSFMUVi80F5OAcc4ooTbmPiYGErJNSSwWO28vs5rBokxGT6Gfijpo/t65o6z/SO
         sQIgwhNd3aDavrBBWoMpPranHoiy8GpgLy8rh1YmBj1gnoRAQAx4p2JyIwQ0XJlJdEEd
         pbUnrDeoWsMA10YCTMYsldEGqSeHNOLMt6XFQAXosY0KjK0uhznbiC292UfLRcTJ/Asy
         BjK3Oonmv0/+qrAPV1dRKOTpr+8icujEW3hAEM88hEVxhaHyROI2DrDGRxObKJ/DnAr1
         wbbPmre0iRTYQrP9UQHThq2QW0BEmtrRsGqRUy5/xiNKiA0EzTqOUX/XZ6dKqHLQKWzh
         JY2w==
X-Forwarded-Encrypted: i=2; AJvYcCVvB+WWYZPLEAJ681Ug8Sd+2WXF+zyGlwfjlz69eBNsE2QEH1MCv3LGO67NAr4JDvkG0lyX8sMo8O+xK7Vs1GsQHLBalTg5rw==
X-Gm-Message-State: AOJu0YyEcqbAES9emwBlQSOXwKynTe7KUxhuIasKrdj+o55U/CnP23AH
	dXxZrj6vQdx87LTy/TpT5pqtAH9l/XWGJNbx+q87B5XEjhLnai+W
X-Google-Smtp-Source: AGHT+IHORnpPlKGJmOPIuLGMvG2U8IA2tgUcUFyJqPVxfFuUrAxhnwr4EL88X1fI9p/NyI2P+fGQpQ==
X-Received: by 2002:a17:903:88e:b0:1db:9a8d:a598 with SMTP id kt14-20020a170903088e00b001db9a8da598mr29650plb.27.1708023014417;
        Thu, 15 Feb 2024 10:50:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5742:0:b0:598:fb75:89d6 with SMTP id u63-20020a4a5742000000b00598fb7589d6ls19323ooa.0.-pod-prod-00-us;
 Thu, 15 Feb 2024 10:50:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVJ4QXFbF7JWNcF7KvLDSbKSsMsRgbBLN/2/B6t+gr9Pv24gxowC2AkbPTCNAMOBU8GUYEP9vQN+NaMwyqPM2vE6Qhz/FoDtN0mnA==
X-Received: by 2002:a05:6870:9710:b0:21e:5c6b:af5c with SMTP id n16-20020a056870971000b0021e5c6baf5cmr95018oaq.10.1708023013463;
        Thu, 15 Feb 2024 10:50:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708023013; cv=none;
        d=google.com; s=arc-20160816;
        b=p0RuIYCujPFxHRlMM+GmNgrTMWOnNlkiW1cVjLgE7M2crrkSy0ArJFUmB6aKVUVsn/
         S+CuKOE18F6srjaG5lAVupCYs520LD4X5EaUWUV4uOCftMHHzmG2iGp+7qmJVooRYc/t
         WLbgi2/V5yxRPDuIky1WRKbMis4yYQ4X2Bw05MY8gupbXZ0Rob6PDbtNKaYwuqi7fLuI
         pbHVekwcQhaIX79bPUBHOnzYcvjAodcFHGEwHQntIXWgYit97PHX+NkDuRLXpQkBxCTA
         Q2wr4/HwbXR1sQ4jK7xnxOl0qusWX7E+naz0T+4YBBl8BGkD3zhPLyWdmYWDEdTI8LAe
         eXTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WUlsSeO8LefyO4xLZYNJ9jNHAOJrLbOdsT9pDfMZXA8=;
        fh=7KfM0HcUReYYpfN36kcP7RKD0kDMXM/9UreuMWixIgo=;
        b=g+2aa4lW9dgPNNpjMNRXsIQKdCFkLJ/1JbvCC3/1ehr0769Ru3Dzu/Lyy+5TL/fZqA
         VegEcGpfKRQyNgyVp+vKVeRP6A4T5C+1l5y93cSPHUJG4HPEPgcztDgbSJEq9mduWHVz
         dO/StAu+3l2b283ctwM75wfSGfpb1DP19lVuB3slzbqavhWeCOEoqzHJMKe61KEfPsoa
         Ms+PMCXAjAri98H2mj6T5AIKoJ1EkRzByFudsdMWmQQTUiASJeCDB60vDZbGeDBk6uRM
         OLR4QF+JBmizkA1KMfM2DRsWo++MzJfYGnaI5XaBoPptrgVYelqvISZmXac56+/RLfcM
         3yFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YrseHBMI;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id i14-20020a056871028e00b0021a216d3a62si142696oae.5.2024.02.15.10.50.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 10:50:13 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id 3f1490d57ef6-dc6cbe1ac75so956528276.1
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 10:50:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUtJZMicI3dgr9clcxE4kAgMEafWTvWnmRiPuzpZWE4i0XQxC46pTINsqZcP+XxKXi1g4dsam8LUiApvkjpWsB1LOiThpDaSOT7rA==
X-Received: by 2002:a25:ae28:0:b0:dc2:4fff:75ee with SMTP id
 a40-20020a25ae28000000b00dc24fff75eemr1999749ybj.3.1708023012635; Thu, 15 Feb
 2024 10:50:12 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka> <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka> <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut> <Zc5a8MsJyt27jeJC@tiehlicka>
In-Reply-To: <Zc5a8MsJyt27jeJC@tiehlicka>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Feb 2024 10:49:59 -0800
Message-ID: <CAJuCfpH2EF8DZhBp_7324ka7mnMkUdWyqTs+ZiMhwjm_nmcwZQ@mail.gmail.com>
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
To: Michal Hocko <mhocko@suse.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, akpm@linux-foundation.org, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=YrseHBMI;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as
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

On Thu, Feb 15, 2024 at 10:41=E2=80=AFAM Michal Hocko <mhocko@suse.com> wro=
te:
>
> On Thu 15-02-24 13:29:40, Kent Overstreet wrote:
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
> >
> > It's completely fine if the allocation fails, there's nothing "unsafe"
> > about doing a GFP_ATOMIC allocation here.
>
> Nobody is talking about safety. This is just a wrong thing to do when
> you are likely under OOM situation. This is a situation when you
> GFP_ATOMIC allocation is _likely_ to fail. Yes, yes you will get some
> additional memory reservers head room, but you shouldn't rely on that
> because that will make the output unreliable. Not something you want in
> situation when you really want to know that information.
>
> More over you do not need to preallocate a full page.

Folks, please stop arguing about it. We have more important things to
do. I'll fix it to use a small preallocated buffer.

>
> --
> Michal Hocko
> SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpH2EF8DZhBp_7324ka7mnMkUdWyqTs%2BZiMhwjm_nmcwZQ%40mail.gmai=
l.com.
