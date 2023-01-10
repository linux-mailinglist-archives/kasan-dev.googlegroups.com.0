Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5GO6SOQMGQE7AUHLDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id D5874663BD4
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 09:53:09 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id h12-20020a17090a604c00b00225b2dbe4cfsf4505892pjm.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 00:53:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673340788; cv=pass;
        d=google.com; s=arc-20160816;
        b=HG7/e9xW924NyaAJTmkLVVvdwgTHML6BmTx1lPBlBtztUq2rRhmGluruXcyNm5nX/j
         2DC/OyT9jGEP4hMaLQrr6mrAPPhDQymDL6PbeJJSANqmxcAJUc9CadES9dK77ht3mo+2
         kRRhL4mXTntlsfT/pAjoNh+rFTDI/fSd3Rj75baDMHRwFkO96N/dyvxdVQOATHKQ9hj6
         THl5CyGH9W/kTSB0y0FAnqJhL3eOXnwC2pnDpnVm9MrqYkLQZjF5Y5CFol5LOWtxPJZj
         68fobrygqgOfa8416xHP6uXiA9iuQuGGKhnoJuKsE4M31bo6hlQ3WcwyA/tfLzwTi+wN
         KZbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+Hjxuos0+3wfRAWwVTKJj7erGVmYziP4z9KE11CTVcQ=;
        b=PJb77AqN5GiII7NnfvVJa7US8RfF4QJBu7q3Rhz51/VTAK2I5hFVklbgIAe25Jqkid
         w61lz5zQVhQkarS17OdkfE55Vs1qICQ+0lNugXNwDvEDvsgvOhOEYnOyl0gkwe+nfPZH
         9S4fC6hcS4RMNpa1qtQuEBogmcR9BAhJaC/4yC0en2yOTwd4He3Hnrw+QOky9hgi5484
         x0oJ/6hk5sc9VPMhH3aFtCnWzotwBms2OV1lP51TFaOLLzNJcv70sIGCcnG5XKSbHq83
         +uMrcgGWMGJE47AW4aPLN7Jln8cMDE5Fro2qCuGPuI8wV76C+CIbjpZxfLrc7WWd+zbq
         u1oQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lbCmyLed;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+Hjxuos0+3wfRAWwVTKJj7erGVmYziP4z9KE11CTVcQ=;
        b=T068gCja0+piU53GYD1Cy7QIWVfNu6FM9ZfHUDkI0nhsDfjraFrPxpDIwif2SURJm+
         Ssyg7vUAgSw1v7zIhWmitsypUe1TTXlLaFfYTnQmDkHZjpaOIJrhf18e78Vgek9qUXh+
         EOt5Q17rHFwmCA7R8FF85G7y3z1vZ8jWYeNktoZChTKwDBYhu2l3fxL00PADMc0NVPEs
         rVWeQXs6WgF68uUv+WaXfQePCwH2jLQFfIB5mY9ytLIHAkxKs4bWGh9x91rEhGojBomj
         GkjJ7Yl8SYlE9oJT06UmF3c5/x8vvt3JHWtmW65YrdYDXmDpUgYGJB1ev96nApBf6SBD
         O6bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=+Hjxuos0+3wfRAWwVTKJj7erGVmYziP4z9KE11CTVcQ=;
        b=1oSHWs8y2Iqg7+bOOGL/rwsrnXVOYbsxAHF5H5QTErU4VZSxtDRhyzD2aYCL3bC/x4
         6ofWJIP3AHdfM+tBjfo0qZSaXSp5ngtiFkewkNzu6A6R/cnZIDg17xiUrfIqgiEDBOTL
         ti3i8zf4bIEG7JNZc5flhaoIs1M8ScOFdJ1UzmdIol0l9vFSFAGnPa4RDhNrW5UuKJVu
         p5AuE+oSHewR/PaXe+Y3QRqHpSti7h3Q+NsZiPkw+oNwjXRnnqpJdlp1Vug8uPFwkhjY
         z7g8ReeAD+ENHv1qOjvJyBIRQ/qqQp6wv+CgG0XAzqvfrrpnrZr5GIv2hirypnqO+I3H
         ql3w==
X-Gm-Message-State: AFqh2kp1562bpndvvg4ebvBcDJ6/UMCJAwEpWznUR/yVV+pYmFYRmOKk
	uASEexDV3qGB6g59BycVd9s=
X-Google-Smtp-Source: AMrXdXsOcM8bMU3ZU9ssHwA5CEB1Kat5B8ugZ4KYlGwsppDIJLyaZqHQBjzUZDUHbqN6yD1kiXhCOw==
X-Received: by 2002:a17:902:e382:b0:192:8426:2142 with SMTP id g2-20020a170902e38200b0019284262142mr2315255ple.10.1673340788215;
        Tue, 10 Jan 2023 00:53:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:b82:b0:580:9ccc:dbac with SMTP id
 g2-20020a056a000b8200b005809cccdbacls1731599pfj.11.-pod-prod-gmail; Tue, 10
 Jan 2023 00:53:07 -0800 (PST)
X-Received: by 2002:aa7:8a42:0:b0:582:34f2:20f1 with SMTP id n2-20020aa78a42000000b0058234f220f1mr34219456pfa.11.1673340787426;
        Tue, 10 Jan 2023 00:53:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673340787; cv=none;
        d=google.com; s=arc-20160816;
        b=0Qsyk/uSWN9Z6B/HKLQTj+7/g8keB6Iu1EJVQKVkjlGIGc+2QCi9LAPF1zK5DAMuiJ
         xek/LfgLQNYQjzBy+Nli9sGIUE6jodLdLV5I9SpFXsda13nqxIzU2rfXfGXt4VvAzZmK
         QUiiR0ppT20eNCh4ncyoTPM+0Bxa8sERbJh6Lq++4A2gveZy+2yPm9B5e0i//lqUKDYT
         itW140grFkpRGCLPaZfhBF85cjeWULhm6myC5YUGIq0+DblgIBQq5F5iTndJXL0ORclR
         fxkb5ff4B+WLSpZxm4keUfef4C1dD/7hAqv7NGunSaSGL4UmDtiQpAQzBiPcDOOyhdCi
         FZhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=19QYjJTilGk/RhxRe6+HhMCtJmIsJ5ED63/iAKX6oJs=;
        b=LIghMpg3Do1/ETAV2twBHrywmIENlW5HFzeve4gYME/3v4b8kStCMtHHbrUKni+2Jh
         ks2jXELVLN4uok60CKknZ+g0MkDSSeZWMXIm4ZjEMSZkk9O9hLiKdNvVlpg6Q2Dwd0Nn
         UuewteT/1L0eA2pkmIWbHJ8nJXzEukXQ/bzN31x/CV7FQ406JbbVtjcBbnlEvOh6WTjG
         0BkH7d0JlWccaSaTI+dcTnOE20ZSoh+JkajK3eykuDwHRR4PctexDEnyN7/B+YgfTz70
         UV3rZUTrEkYB1ATqCzUbBs/8rq9F6Q+46MiGtmGAS8PHVDpYNdPOJR61CzkydufsXS3H
         /uFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lbCmyLed;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id h123-20020a625381000000b0056ca3420e5dsi910623pfb.6.2023.01.10.00.53.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Jan 2023 00:53:07 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id l139so11065113ybl.12
        for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 00:53:07 -0800 (PST)
X-Received: by 2002:a5b:b47:0:b0:6fe:1625:f1f5 with SMTP id
 b7-20020a5b0b47000000b006fe1625f1f5mr6647952ybr.549.1673340786873; Tue, 10
 Jan 2023 00:53:06 -0800 (PST)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-11-glider@google.com>
 <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
 <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com>
 <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
 <CAG_fn=WjrzaHLfgw7ByFvguHA8z0MA-ZB3Kd0d6CYwmZWVEgjA@mail.gmail.com>
 <63bc8fec4744a_5178e29467@dwillia2-xfh.jf.intel.com.notmuch>
 <Y7z99mf1M5edxV4A@kroah.com> <63bd0be8945a0_5178e29414@dwillia2-xfh.jf.intel.com.notmuch>
 <CAG_fn=X9jBwAvz9gph-02WcLhv3MQkBpvkZAsZRMwEYyT8zVeQ@mail.gmail.com>
In-Reply-To: <CAG_fn=X9jBwAvz9gph-02WcLhv3MQkBpvkZAsZRMwEYyT8zVeQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Jan 2023 09:52:30 +0100
Message-ID: <CAG_fn=W4mX1WN0_24wpeNWynEUkApO2QzwavKqer3F3wttOndg@mail.gmail.com>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
To: Dan Williams <dan.j.williams@intel.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Marco Elver <elver@google.com>, 
	Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lbCmyLed;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> > >
> > > >
> > > > -- >8 --
> > > > >From 693563817dea3fd8f293f9b69ec78066ab1d96d2 Mon Sep 17 00:00:00 2001
> > > > From: Dan Williams <dan.j.williams@intel.com>
> > > > Date: Thu, 5 Jan 2023 13:27:34 -0800
> > > > Subject: [PATCH] nvdimm: Support sizeof(struct page) > MAX_STRUCT_PAGE_SIZE
> > > >
> > > > Commit 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE")
> > > >
> > > > ...updated MAX_STRUCT_PAGE_SIZE to account for sizeof(struct page)
> > > > potentially doubling in the case of CONFIG_KMSAN=y. Unfortunately this
> > > > doubles the amount of capacity stolen from user addressable capacity for
> > > > everyone, regardless of whether they are using the debug option. Revert
> > > > that change, mandate that MAX_STRUCT_PAGE_SIZE never exceed 64, but
> > > > allow for debug scenarios to proceed with creating debug sized page maps
> > > > with a new 'libnvdimm.page_struct_override' module parameter.
> > > >
> > > > Note that this only applies to cases where the page map is permanent,
> > > > i.e. stored in a reservation of the pmem itself ("--map=dev" in "ndctl
> > > > create-namespace" terms). For the "--map=mem" case, since the allocation
> > > > is ephemeral for the lifespan of the namespace, there are no explicit
> > > > restriction. However, the implicit restriction, of having enough
> > > > available "System RAM" to store the page map for the typically large
> > > > pmem, still applies.
> > > >
> > > > Fixes: 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE")
> > > > Cc: <stable@vger.kernel.org>
> > > > Cc: Alexander Potapenko <glider@google.com>
> > > > Cc: Marco Elver <elver@google.com>
> > > > Reported-by: Jeff Moyer <jmoyer@redhat.com>
> > > > ---
> > > >  drivers/nvdimm/nd.h       |  2 +-
> > > >  drivers/nvdimm/pfn_devs.c | 45 ++++++++++++++++++++++++++-------------
> > > >  2 files changed, 31 insertions(+), 16 deletions(-)
> > > >
> > > > diff --git a/drivers/nvdimm/nd.h b/drivers/nvdimm/nd.h
> > > > index 85ca5b4da3cf..ec5219680092 100644
> > > > --- a/drivers/nvdimm/nd.h
> > > > +++ b/drivers/nvdimm/nd.h
> > > > @@ -652,7 +652,7 @@ void devm_namespace_disable(struct device *dev,
> > > >             struct nd_namespace_common *ndns);
> > > >  #if IS_ENABLED(CONFIG_ND_CLAIM)
> > > >  /* max struct page size independent of kernel config */
> > > > -#define MAX_STRUCT_PAGE_SIZE 128
> > > > +#define MAX_STRUCT_PAGE_SIZE 64
> > > >  int nvdimm_setup_pfn(struct nd_pfn *nd_pfn, struct dev_pagemap *pgmap);
> > > >  #else
> > > >  static inline int nvdimm_setup_pfn(struct nd_pfn *nd_pfn,
> > > > diff --git a/drivers/nvdimm/pfn_devs.c b/drivers/nvdimm/pfn_devs.c
> > > > index 61af072ac98f..978d63559c0e 100644
> > > > --- a/drivers/nvdimm/pfn_devs.c
> > > > +++ b/drivers/nvdimm/pfn_devs.c
> > > > @@ -13,6 +13,11 @@
> > > >  #include "pfn.h"
> > > >  #include "nd.h"
> > > >
> > > > +static bool page_struct_override;
> > > > +module_param(page_struct_override, bool, 0644);
> > > > +MODULE_PARM_DESC(page_struct_override,
> > > > +            "Force namespace creation in the presence of mm-debug.");
> > >
> > > I can't figure out from this description what this is for so perhaps it
> > > should be either removed and made dynamic (if you know you want to debug
> > > the mm core, why not turn it on then?) or made more obvious what is
> > > happening?
> >
> > I'll kill it and update the KMSAN Documentation that KMSAN has
> > interactions with the NVDIMM subsystem that may cause some namespaces to
> > fail to enable. That Documentation needs to be a part of this patch
> > regardless as that would be the default behavior of this module
> > parameter.
> >
> > Unfortunately, it can not be dynamically enabled because the size of
> > 'struct page' is unfortunately recorded in the metadata of the device.
> > Recall this is for supporting platform configurations where the capacity
> > of the persistent memory exceeds or consumes too much of System RAM.
> > Consider 4TB of PMEM consumes 64GB of space just for 'struct page'. So,
> > NVDIMM subsystem has a mode to store that page array in a reservation on
> > the PMEM device itself.
>
> Sorry, I might be missing something, but why cannot we have
>
> #ifdef CONFIG_KMSAN
> #define MAX_STRUCT_PAGE_SIZE 128
By the way, KMSAN only adds 16 bytes to struct page - would it help to
reduce MAX_STRUCT_PAGE_SIZE to 80 bytes?
> #else
> #define MAX_STRUCT_PAGE_SIZE 64
> #endif
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW4mX1WN0_24wpeNWynEUkApO2QzwavKqer3F3wttOndg%40mail.gmail.com.
