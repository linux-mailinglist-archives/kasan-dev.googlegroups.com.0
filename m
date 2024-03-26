Return-Path: <kasan-dev+bncBC7OD3FKWUERB2OTRGYAMGQEKHQKTRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 100EB88BA59
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 07:23:39 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-69680a9fe29sf25446516d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Mar 2024 23:23:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711434218; cv=pass;
        d=google.com; s=arc-20160816;
        b=jPGjLMrwLX2UG9aUhfUC+TVBZ2d8JLM5jBBw/zr101v1vmytXpNAgxvywrQlHQU+Zu
         RZivB1wDD20ARGkKCCv0qtPEjqPQPf8Vq5HBKjdql+rebmpxnZSC3zLsnntIPoUqOusm
         xEeuDWox+J2XdDDkKvQuwFvMswWvEy0AqBNzKgHxkGyN8vRhrTzMEZO9EvtKe6D8tui7
         RyxTuLeXs8p89Q6bClUOQ+8Z2KFGiLtKBvxCIe7+OI9GsCS5XMiwxItCCNoBUQC/RTGo
         o/cUniM+0a2QutTR8xmx2zFIFWFo3MjQmVOfy84reS2L7+2vlqqv0txVmyFe6OT1B8gI
         nSgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VEa+SK4QzHfxuqAotW/ye5UFS+JBqECCdSa0QNoxeIs=;
        fh=VLk3incaZcjVLnzaO1pEJ0CHKltuYdOdiQejeuhvwKA=;
        b=h//gh3E/2Hx5/BgzHYF9he3uc+C32KFfzzK9P0No5OpSYbf00LZR8lIrFC1uwtlz8L
         YJGrjpKVknUbuXVTkq+LgAGsaXIc4xLh/f3rzG4SiTxYSXpe0kjTrTa5ahAIftz9KoBP
         E59eD62/JeWrkFpyaJ/r+bSPEgZ4ATAkWpSfiYOG0hooX2RJukHWix4T3kfKdFcBBtX6
         gihuFUWBDLcMV2yqHFyoUSQTi4RbEd103Q4OYPmYE4bN7RZn0b/XL8+1Sh/4ftaU7J/d
         UN4eSDJe4k0ovHuyuzeoKK4r4Wjq6STyao+Ew4dQFfDYd4wD+8aDohxTY5p0T0rgssyb
         CacA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Pa5+4h/e";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711434218; x=1712039018; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VEa+SK4QzHfxuqAotW/ye5UFS+JBqECCdSa0QNoxeIs=;
        b=RdupwN1+oQ65jpUDGSA+ILEeDnwJUIP5Z0kp0x1T7YDGGX/Fdr/ejeIVgzGKh+uLrB
         6c6FhM2D51LYU+6xFkAClbHoZtVrXaP+tOXszHKbkag18GSIscqS+Ybmj1halGW3/K65
         6NCeX5y+LAONWvBLKBdVA07iJsRqxcPUfsv79Hk2PW8COzu3bXh5gS3Nt/ZQd6jxbNBD
         4YE2dOTXZ6nGcPd3SldYFTrOOMBI1gsZQ580vZBFD/8FRNQEv0jMm4etb1+f/oCaSqp+
         UbphkSJYzr//hLT+jn4s11k6UpKkqoI3DeJXZrT8SiEqAsca/fqIW5TEb/OXKzmdAzSE
         71GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711434218; x=1712039018;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VEa+SK4QzHfxuqAotW/ye5UFS+JBqECCdSa0QNoxeIs=;
        b=G3Xot2rple265VQj0Uj4PGrLWZ2wil8pfZ4UU4SvuOtoD1NwS5usFx3fszdLI/NJem
         2d0L8pZFwsiqvM50uLRlC442AwBPjPOJRLAh8Ri5xxTKZLOfyyCCFwUzyeM070EiRCIS
         IwQ6X6vfSCooiPGVIs2PaxqNhrdOh5jFcPZ2RW6BQNbdKg15biPe1WS89+z3i8SdkqI+
         8hdh+zGrskrOZshrvT0VFj3bcdQuP9i8Od4nzzzKp3FgEPyECdVwgC8d6MNcjFyE5tsM
         +d3FWotBdWVPs12ecdhT8N9d6ycFuY2fSP25VxmYMRn5C2+JCMqMcSSXGDYeYE+31/Qs
         JiLw==
X-Forwarded-Encrypted: i=2; AJvYcCUGlaRxdrotbL+cJJIr/aYDS/Zm5TF9yUDlIJhrXwbjGHxIBs0T43eC14pp68NJJvm9cKtptIKNSR2V6uaAHnPsY9FRGUNdYg==
X-Gm-Message-State: AOJu0Yw0NNdzYAXYiWJtFCQApz+lWgLSTW02CkoBrSDZO/UEdjlTHo+u
	ABMYdM+WdxFHaTbKQKFmvvTl97bCjBOqJFeOjPu8YYTt+yoSrobK
X-Google-Smtp-Source: AGHT+IGXW5eJiY3ie91Z5+TrZHBGO0mKsF3uwdmsSj4dM9c2KEIa4O8OWZCwsI2JO/UjVyxf4Dz9Fg==
X-Received: by 2002:ad4:4f03:0:b0:696:7e64:1a38 with SMTP id fb3-20020ad44f03000000b006967e641a38mr8113864qvb.52.1711434217627;
        Mon, 25 Mar 2024 23:23:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2425:b0:696:9623:7249 with SMTP id
 gy5-20020a056214242500b0069696237249ls1280186qvb.2.-pod-prod-04-us; Mon, 25
 Mar 2024 23:23:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4s5DL8VR5NFjcJgMxZMWQaYux4rCh9gqrj7Smib4upQ+u0jnY1DRUPLYN/fLp0rcObUzotlqxr4prqKDoPmDDddoIJ5Gt51YTPQ==
X-Received: by 2002:a05:6214:2406:b0:696:4c42:e66a with SMTP id fv6-20020a056214240600b006964c42e66amr11303760qvb.23.1711434216976;
        Mon, 25 Mar 2024 23:23:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711434216; cv=none;
        d=google.com; s=arc-20160816;
        b=wGafjZt2kxbHIOGENyv+N+6OleBlusl8vh/foGz5NbYYn1tiUpW9XN0/3WHl1Uafmh
         bFrJoV7yP37SAh440LWKF5vJ0VA+4kYF+oKeaIKDz2cMWQDPLigOPLxry7gTsote4U3B
         XpCb0Eh0lI6P8U1BkIcdLcwzJXIOrajqHQy/UuHA1BcWfxXiIlhUNJqGsXKmsM1l0Ct2
         kl9wE7j2cuMVLFB8HOGuErTEO2x/uLHSkMoDTOsFvC/JNujMvxzEk8XY0YQK5SnXs4BL
         AO7vzo6/bsi7ySa4EksyXLAvE6LWjxUwWD+ubLYNRfQNfhVI8j1h9ZckxlU7HJ4BGNYB
         gkFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hY2WNNA6khj/wLxlBTVDg0e/YVgDEc7zpROxMWd3xhs=;
        fh=CYRphQKWO1ZcZAxrnkOB8tCi7yuQpYcwgGEHmWNtmUw=;
        b=KhCxDdCytGdt6XmDeqvjQNeIOYDIogdvXRZdHiVQZDcIXqR/LA7kFAj+UKPLJBE9ia
         cUMrwV0rNymHqNTZRpLY5OjYXNsIduClhQcva0yn/VXawkczl6XAW8hh33XU4a+bzfoU
         7D/1JywTivUejkloHEsS5wYwqKb0pHvPcdRTWnYHnaurAd+39n6TTi2sUekveKYkVREs
         HWThU8Sc7P6GMbFSSvdT1J7k9RyTNTiyHT2DHKuwlikuUPDLZt4/uQoEI3YffTA6ef2H
         GLUeFdPH2x5a6XhefQoaD1HhKiNbSdn9FqpJzc59KAQxaM0+krUfy+OACUDR93hRIoNm
         sZuw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Pa5+4h/e";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id i11-20020a0cf38b000000b006965f40ae76si650523qvk.8.2024.03.25.23.23.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Mar 2024 23:23:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-60a068e26d8so57723997b3.3
        for <kasan-dev@googlegroups.com>; Mon, 25 Mar 2024 23:23:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV8qDG8+pGva5lBbytbnat0r+P8Go3Y3u3begThy6ZNnhwOloQ43zccDpe+No9KyBXeS7DEEJf0V1B8YpU3Gtwj+ko9s/DQ2+PMYg==
X-Received: by 2002:a05:6902:4d3:b0:dc6:d457:ac92 with SMTP id
 v19-20020a05690204d300b00dc6d457ac92mr7166050ybs.31.1711434216382; Mon, 25
 Mar 2024 23:23:36 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <20240321163705.3067592-15-surenb@google.com>
 <ZgI9Iejn6DanJZ-9@casper.infradead.org>
In-Reply-To: <ZgI9Iejn6DanJZ-9@casper.infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 Mar 2024 23:23:25 -0700
Message-ID: <CAJuCfpGvviA5H1Em=ymd8Yqz_UoBVGFOst_wbaA6AwGkvffPHg@mail.gmail.com>
Subject: Re: [PATCH v6 14/37] lib: introduce support for page allocation tagging
To: Matthew Wilcox <willy@infradead.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="Pa5+4h/e";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Mar 25, 2024 at 8:12=E2=80=AFPM Matthew Wilcox <willy@infradead.org=
> wrote:
>
> On Thu, Mar 21, 2024 at 09:36:36AM -0700, Suren Baghdasaryan wrote:
> > +++ b/include/linux/pgalloc_tag.h
> > @@ -0,0 +1,78 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +/*
> > + * page allocation tagging
> > + */
> > +#ifndef _LINUX_PGALLOC_TAG_H
> > +#define _LINUX_PGALLOC_TAG_H
> > +
> > +#include <linux/alloc_tag.h>
> > +
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +
> > +#include <linux/page_ext.h>
> > +
> > +extern struct page_ext_operations page_alloc_tagging_ops;
> > +extern struct page_ext *page_ext_get(struct page *page);
> > +extern void page_ext_put(struct page_ext *page_ext);
>
> Why are you duplicating theses two declarations?
>
> I just deleted them locally and don't see any build problems.  tested wit=
h
> x86-64 defconfig (full build), allnoconfig full build and allmodconfig
> mm/ and fs/ (nobody has time to build allmodconfig drivers/)

Ah, good eye! We probably didn't include page_ext.h before and then
when we did I missed removing these declarations. I'll post a fixup.
Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGvviA5H1Em%3Dymd8Yqz_UoBVGFOst_wbaA6AwGkvffPHg%40mail.gmai=
l.com.
