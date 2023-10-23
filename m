Return-Path: <kasan-dev+bncBDW2JDUY5AORB3NY3KUQMGQE2GDY2GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 68C107D3C06
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:16:47 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-581ed663023sf5510179eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:16:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698077806; cv=pass;
        d=google.com; s=arc-20160816;
        b=tv6KjQLwqDF5jW2oVOsbTx8TrALfK3WPVZY7qLezxPaeDmE082no59mPVxgxP6zg63
         utGdcQIP5Y40KLWVDO3KnFEd+7bHkY0Ar6f2xs8N9naiwU8X4xuNqc95IeyJE/u5GE9f
         uo9jf0oiRUuCzyvlBW7qgTaJdumK5EYjeHa0Ft/HhNGrK66uoD59LWX1Bi7ro5XLK5rv
         0GWVWGMi5qrk633jZg+mJdFqcu38NKQYKjsMZHBpHu73k8ixzcHZ+oR1hOmQIlqoN6j3
         zrFvq0vUyLPy46VT9XHVg9gic/kTR8izlcHfrRt7y7Y1d0qMjxT6/iFtb9w8eePgFDZh
         Zkug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=QgkcvFlJRTvzrgjAsqDbkbWBx2HyObNVr8Q91PFYEis=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=waFK3edsUiAmrUawSgkxiVrZEuhYHSfBpE1Zum5Y+zDXz+ZFkpNZB833OKIu110Crq
         t/DjwpHOT0+jl3wQ9k0N+Sk2+XOoPqySMEq7tGhifYzafzb5mELHjCsz4/OuYVP6DHeP
         mGCQwyISskf80L3iTOuD6vjQ2EVEMab6mS40TbpapO4LacZh6WAqCBrTD2xAz1HcyknA
         6C2nS/HCEyGyJVQaeUenQb+rlMNY50yTrpetXdDKctxQDPxXVDmWX8laIy4PWiaG0/3l
         v8ngJ8DQecnnXKTv3qDNkk+YVP69wgXXiVoOBIg58pWMXOWnvCJ8IuWauomJ+c2+MmFQ
         TuVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="mbQ6hkD/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698077806; x=1698682606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QgkcvFlJRTvzrgjAsqDbkbWBx2HyObNVr8Q91PFYEis=;
        b=t+jibOjP4VmLtIAYpZEHkk99BCr9bOt9uhcstrRl5IARG+9ghAVGvRSIqQcOhyPXlt
         6T5F+wU76oOzb4/1bfJd3FJ5t+jATsRf4eTprwxZrrxLTl7rjU8N/DmPHgkvFbrvVeGM
         nA+ybtylZ27V0fvRobEiRpqy4aeorQ+QzP44+i6jujUSPCjDVruFfit2o0kg/ETf8Wnl
         Z5POsLw/ANgyj2+pGh/2hbqyAH1Irdsnf+6LpPGuTIU7DFYa/8rtyzz2Tr8aQVxcMclz
         0k0EkCuL+mv4HfZ4JFZfR8uT+WgkJdm0LEZdDeGBPtTk1Tt8Ips48S/YVLKy8yvOjbdQ
         rA+A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1698077806; x=1698682606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QgkcvFlJRTvzrgjAsqDbkbWBx2HyObNVr8Q91PFYEis=;
        b=TvdPq/d1jlmbhFW9VLdLMjzOdanL+0B0WJEmh8IHlbtIyNZg84ZkJ56OoAyxBR8i7u
         +V58QTlfcpoISchUWDbhDPdN5Ph6Uheb9hnuEDdULsqks2TqjxeaaBGWkJn8AWSNM8sZ
         KGm3UZp9AIRZVzQa0IkdZwATHaU/FHLd5VQ+3GZy/ENr0ZSGPJuhkKGIvj7EhJEih82R
         fRVPqXmuZKX5JqJgA2FSjY5uFeoA+BemQ7kwQcHtNLPKv/4ieT9iudpA9I3DsHLfmqQc
         etE30noXjHRyRykGkDO3QKmpFihGWjbc9WkE2zEBtPUBl/f8zj93lBWuLRps/uj15nhF
         CLdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698077806; x=1698682606;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QgkcvFlJRTvzrgjAsqDbkbWBx2HyObNVr8Q91PFYEis=;
        b=fadSLqWl9fSfxwAcxDUtoeHm5ftPjr6V4jEov/IG0RyFymKPYz3Z34LroPELoM7siQ
         upHw015jAHsmwfJI6UFrImmwlQ0xfFOHvumXSaeuZuVNyH5/Q0Ldy8H3wgCeaVm8DxoL
         rjn2LLhsRTWBK+/B/oWaueKjnCnoS8uJ6O4HwUQsu66Yy7pFm8ObjRMaYMLMqPOsdwOU
         CC0SwPc7LPeiDBny4RyvK87Nazx59/1b5gZsRGs8ZLnigxOHwS08uIw2GOZRJEv0H0pM
         xAARKhUdT1BHV6hxIv046x8MMMXD9xFves4SUaC0wRduB7hdnpnD6wnKte+2NP4icQ8P
         Fw6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxZG2mt0r5mEUOU5HPxe9p9WdIEvWULt+AGhVopBqda2anT9PfJ
	mwMkB6vCbTADff3WieZULGM=
X-Google-Smtp-Source: AGHT+IEB7Hd8xMgxpkop9F6AisqGReyLBX02/WSziN4nA6r2uXpLygiQxrIllYGBckABa2ZA1XlHLw==
X-Received: by 2002:a4a:a78c:0:b0:581:dd3e:dbce with SMTP id l12-20020a4aa78c000000b00581dd3edbcemr8972812oom.0.1698077806009;
        Mon, 23 Oct 2023 09:16:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:37d7:0:b0:581:d9c2:d789 with SMTP id r206-20020a4a37d7000000b00581d9c2d789ls2492310oor.1.-pod-prod-03-us;
 Mon, 23 Oct 2023 09:16:45 -0700 (PDT)
X-Received: by 2002:a4a:dc88:0:b0:57b:dcc4:8f1 with SMTP id g8-20020a4adc88000000b0057bdcc408f1mr9090966oou.8.1698077805152;
        Mon, 23 Oct 2023 09:16:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698077805; cv=none;
        d=google.com; s=arc-20160816;
        b=lg+UgCOzvU8ybCCIZhV9ztJrbCkCHte8NOh/x0knfm0hphwK3EfQ1K3O0o1wPtyCQ7
         29URYfO6wuJzJhVbPRaxvNW7RQU431MJlrdCQsJIzWwdtgvkgSNht/i13CD4SRmDeTlY
         DPJ6R9Knco1dd1/OWW3dfayrJ0DlAdR5aENCjHX2qoVGzNJnEchRjMkaxiHVYlsTA7cB
         ePAwAu/XQID6NVOk8tqvYEGdumtsG1i119ZMBZBtiWE0LbF0p20YZUCg+Sh5wrRXyuQr
         Uc9EXY2orfPvR75mEFW8z28YW3RqTnrMHAnveI3JID+um8k+pknURH4FpHzaNIDRzpsC
         WwXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HgO08PRy6IyNU2zj7g2IPBwXTxM3jF14s2Iin9hZx7o=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=BOzDMzWmS9vwWF0Yahs7QFSeCzWrcad5GBNs+jlbWLa2Vy12WrMtqikGtqfIBb0+22
         2NH/QNZMrDT6ddGnxYjXQe1EhE0jzTpA9NJycdbs6+isj9JDd2+P/SNYxlWGl4CxeJ9K
         yjF2s00rXy5Gta268qZXHY6wAeq13VgkuVU7XfMRhoznmIP6Cit907ZtpqqVIzEwCj43
         s8SD6lu5LVdE4AWjlRbQEbeohpWFeWL9gwLRn7mmlQW1V5BKwX1a/kZKjP4VqX/g24Ks
         WHrX5GtU6E1jEdO0C3Ehvd1upV4I94Eae9QVKK7OFrfMTS9lQqYWcX0mhiemuxhYWFei
         CiWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="mbQ6hkD/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id dz26-20020a0568306d1a00b006c44affd0c6si623545otb.2.2023.10.23.09.16.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Oct 2023 09:16:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-27d425a2dd0so3000975a91.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Oct 2023 09:16:45 -0700 (PDT)
X-Received: by 2002:a17:90a:195b:b0:27c:f845:3e3f with SMTP id
 27-20020a17090a195b00b0027cf8453e3fmr9585255pjh.1.1698077804386; Mon, 23 Oct
 2023 09:16:44 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <bbf482643e882f9f870d80cb35342c61955ea291.1694625260.git.andreyknvl@google.com>
 <CAG_fn=VspORKG5+xdkmnULq3C64mWCb-XGDvnV9htayf5CL-PQ@mail.gmail.com>
In-Reply-To: <CAG_fn=VspORKG5+xdkmnULq3C64mWCb-XGDvnV9htayf5CL-PQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 23 Oct 2023 18:16:33 +0200
Message-ID: <CA+fCnZfp7V411qf_6miCzSg_5w7HwkHwH+NWLLy8C62P0hEN-g@mail.gmail.com>
Subject: Re: [PATCH v2 07/19] lib/stackdepot: rework helpers for depot_alloc_stack
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="mbQ6hkD/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Oct 9, 2023 at 11:00=E2=80=AFAM Alexander Potapenko <glider@google.=
com> wrote:
>
> > +static void depot_keep_next_pool(void **prealloc)
> >  {
> >         /*
> > -        * If the next pool is already initialized or the maximum numbe=
r of
> > +        * If the next pool is already saved or the maximum number of
> >          * pools is reached, do not use the preallocated memory.
> >          */
> >         if (!next_pool_required)
> It's not mentioned at the top of the file that next_pool_required is
> protected by pool_lock, but it is, correct?
> Can you please update the comment to reflect that?

I'll add a clarifying comment above this access to the previous patch.
I don't think it's worth to describe all locking intricacies of the
existing code in other places, as atomic accesses are removed
altogether later in the series anyway.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfp7V411qf_6miCzSg_5w7HwkHwH%2BNWLLy8C62P0hEN-g%40mail.gm=
ail.com.
