Return-Path: <kasan-dev+bncBC7OD3FKWUERBFOPZSRAMGQEGVUVWSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DF986F6362
	for <lists+kasan-dev@lfdr.de>; Thu,  4 May 2023 05:33:43 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-559de0d40b1sf94896887b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 20:33:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683171222; cv=pass;
        d=google.com; s=arc-20160816;
        b=R0nw5UAvVv9/VAXDoyoaT0gN+eZlYv0JPK+W9aQcuk093h34PQgQ+mVrgNDz/G6p7X
         GxBX2YiDhF1TBpetYNmZIeuY3w2k6tkQxWvBOOuMKbBgXJOz44tny8x6QvACxsHcXSdF
         25ReuKNzKOJw4FqRB1TiUi/gAZW80PfJytFMmZB3YVb3gknMWkl/tkctFjG5bMrkscWW
         GYq6d6eajBwT8Bp+cF3IIgQCTsPan24s4Xp9xaBbsyTNdmMdBSoq+Pg36j2p9HUZhW8i
         8AnVYTHKMfyeasH1YWBHrr9/SZyUvxPFWTCgxW2bRBupjqPNkM8IdjP9s76FkYGJ2LBF
         s/fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DxCqGZXErINdjtct8kxtO+9r+r2IoW5R7JeDDd5RfhI=;
        b=NXnr3Na2pGgJEbW246/SYMPS+W9G9UhxJBrKL23ihjezzayH81YLsTF4aToew2SUx4
         Bdr3l82Hvbvge6X1RfnijS8RCA3WZEBp6/yDc0BiXEw335LxEXC5Pal0lb1xMKbAsO9D
         OoRN/5vuBIOy28QkQbpGWf7RiqkE/Rw6JuH91jvHzZMgZLXUQLCI0dRtq6gtiLOEhmFN
         0rjTEPdKJiiebL/RdM84m1QiFUJ2IwF+T4yOJG0lkaesfRZHq3tQI6t0QzNuBkFysiUS
         tthQwCp0pIbC2WrvglYYNwQGAQfJED1NywltHaqZzNJFrnXAFWKS5VTMgRbU+4SYEWJW
         SLwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=lL+P1HWG;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683171222; x=1685763222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DxCqGZXErINdjtct8kxtO+9r+r2IoW5R7JeDDd5RfhI=;
        b=hLQvUZXZLW8J6aP2/STo/Sbja9As36z6JFKB4dcGhvqcocjbPqY6PCrxI/Xxb2i7to
         YjVpLtwB7oMoWrU4pKEd3RitqD+EX6O+XIDkYwHmKf8vjX5NsIsqL71UOqZvMFXLMMiW
         PL+6TbGZ404kujeFii6BfxgDdMzbFpg8aKGefBoeiNyCSVzPcGXRkTfM5R6p7CqMCj83
         GL6PAsB4o2xE06UvV3WLHuL8oB78y09h+mhrB1ydCUT7Geyg6iZrzTsr8fzH4EFKQqZy
         oIf+OXUMZy9iPhSgM5+zZHkFXOuVfHDJVhbZR1mwuOcIuJY+hTho+rVqDMfjUnBQkyrN
         L/nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683171222; x=1685763222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DxCqGZXErINdjtct8kxtO+9r+r2IoW5R7JeDDd5RfhI=;
        b=TbHVJjzrFoFHRuAfU/WxNusA5w30qR+bOCAwGUZGqw7On7cfCyW8Qn/CTDjsv1pC7R
         gMZF+isEBuFS/wmH2tAqTGXVuvf4TE8pCWtD6YlVzNPzY/AIGVdEYHir45J9rn15LdV6
         CCd5aluHpdh3i6eECgrV2T0ie7hOD6MI3evxLvETMgTDPUvU6VYOuYptOQ74XakRgEQs
         409JAylpRDimSOZ2960vUO9B9jdQCIi7cxj4Vof2pP+fx3oTG4zU2NqORJITIEiKczBo
         U5KRHZLDLX6XmgB2gM6m9/HiFylNmLfg4wkElAuGs4n4jrlbB53JN3NWVzfqZnDFfFHz
         n+gg==
X-Gm-Message-State: AC+VfDzAkXRbnYQL7tcC6P3teblaKGnxZXWijFSRss+vvnTp3vstRvaG
	OxsQH53FYTm0+aeKlaJt6gk=
X-Google-Smtp-Source: ACHHUZ4xXsTrZF3hhZObOvdc4sl7hcgTVIDxgtll1mzagvLaTN0KvbRtmstINz2x2Lc5edL9TjqhQg==
X-Received: by 2002:a81:ef03:0:b0:55a:20a3:5ce3 with SMTP id o3-20020a81ef03000000b0055a20a35ce3mr407853ywm.3.1683171221914;
        Wed, 03 May 2023 20:33:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:248d:0:b0:b8b:fcac:82e4 with SMTP id k135-20020a25248d000000b00b8bfcac82e4ls11456099ybk.7.-pod-prod-gmail;
 Wed, 03 May 2023 20:33:41 -0700 (PDT)
X-Received: by 2002:a25:c00c:0:b0:b92:4f17:2d30 with SMTP id c12-20020a25c00c000000b00b924f172d30mr20331696ybf.49.1683171221184;
        Wed, 03 May 2023 20:33:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683171221; cv=none;
        d=google.com; s=arc-20160816;
        b=B+x0504KOm9HNacAJl2h+Ytr8QKVvWOoV9eqxOqX0QZjUAdVnMTXZUTDbKm52phx3H
         nH0VXnitgL7NfAPi5UWN1UF0//s5dK5ftltP+Oa/sPR/X46KE29MIYN34gXoSMdxD18v
         7Ddsm/n3oRIi5Snja+IRfrumKELwObhmlWDveIaVXwsF1aYJzuwKlt7tNKVPeFIprc1V
         HpVjkCus+WbYH5E0H6nh81b831d3/ltyKu30P0CKI2Kx/f/KKOLY53KcuMEWEILvQyhX
         ChK5a7xTv/vz7qI7ibV48H2h0SvNITijvXfBSbo7DqGHYYcqqoocgViYIYIlQaXsjPIM
         Uz1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ezowVIfZ+j5q5fnHBXFJgjQgqAlO13MfPXw7qEM899U=;
        b=mI+kA9w99glO24ZsA+rZGx0RRAHdYJsR9M4mOZqjh6xNQitBcLqdr/6omL5UDY8JEU
         hUSKvaUusqUhKnvSMPNmN0a6kcwX0cum4g/A2/p+d7R40xX4y0iCmFEFHK9ZkNWgf0ir
         eZNy3K77DktrmIKUywzhAf8Y9jZenkvi8R/zQGmZi+S7bfTVtKOvwCe59O4wZDdYbL3s
         LZlxqY6mQtSDBzqkghI4NkZJcNAZtJv3k3AJvKR76rlSeEoynYEfqGACa5JtPdY/mo3b
         umEQxkv+TIEoQDl3YG1oeqQrMWz5T58d8YWjFaVWSGsaE+yoyEe+0pLfuCVIpgexm5A7
         DgcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=lL+P1HWG;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id m67-20020a25d446000000b00b9dd5efe53esi896268ybf.3.2023.05.03.20.33.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 20:33:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id 3f1490d57ef6-b9e66ce80acso32200276.3
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 20:33:41 -0700 (PDT)
X-Received: by 2002:a25:b55:0:b0:ba1:8b5a:581e with SMTP id
 82-20020a250b55000000b00ba18b5a581emr1541686ybl.17.1683171220475; Wed, 03 May
 2023 20:33:40 -0700 (PDT)
MIME-Version: 1.0
References: <20230503180726.GA196054@cmpxchg.org> <ZFKlrP7nLn93iIRf@slm.duckdns.org>
 <ZFKqh5Dh93UULdse@slm.duckdns.org> <ZFKubD/lq7oB4svV@moria.home.lan>
 <ZFKu6zWA00AzArMF@slm.duckdns.org> <ZFKxcfqkUQ60zBB_@slm.duckdns.org>
 <CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
 <ZFK6pwOelIlhV8Bm@slm.duckdns.org> <ZFK9XMSzOBxIFOHm@slm.duckdns.org>
 <CAJuCfpE4YD_BumqFf2-NC8KS9D+kq0s_o4gRyWAH-WK4SgqUbA@mail.gmail.com> <ZFMXmj9ZhSe5wyaS@slm.duckdns.org>
In-Reply-To: <ZFMXmj9ZhSe5wyaS@slm.duckdns.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 20:33:28 -0700
Message-ID: <CAJuCfpGmc==xztXgiM+UUA5GGhxstB2r=yTjNUwSshaj5FpBFw@mail.gmail.com>
Subject: Re: [PATCH 00/40] Memory allocation profiling
To: Tejun Heo <tj@kernel.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Johannes Weiner <hannes@cmpxchg.org>, 
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, vbabka@suse.cz, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Alexei Starovoitov <ast@kernel.org>, 
	Andrii Nakryiko <andrii@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=lL+P1HWG;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as
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

On Wed, May 3, 2023 at 7:25=E2=80=AFPM Tejun Heo <tj@kernel.org> wrote:
>
> Hello,
>
> On Wed, May 03, 2023 at 01:14:57PM -0700, Suren Baghdasaryan wrote:
> > On Wed, May 3, 2023 at 1:00=E2=80=AFPM Tejun Heo <tj@kernel.org> wrote:
> > > Another related question. So, the reason for macro'ing stuff is neede=
d is
> > > because you want to print the line directly from kernel, right?
> >
> > The main reason is because we want to inject a code tag at the
> > location of the call. If we have a code tag injected at every
> > allocation call, then finding the allocation counter (code tag) to
> > operate takes no time.
> >
> > > Is that
> > > really necessary? Values from __builtin_return_address() can easily b=
e
> > > printed out as function+offset from kernel which already gives most o=
f the
> > > necessary information for triaging and mapping that back to source li=
ne from
> > > userspace isn't difficult. Wouldn't using __builtin_return_address() =
make
> > > the whole thing a lot simpler?
> >
> > If we do that we have to associate that address with the allocation
> > counter at runtime on the first allocation and look it up on all
> > following allocations. That introduces the overhead which we are
> > trying to avoid by using macros.
>
> I see. I'm a bit skeptical about the performance angle given that the hot
> path can be probably made really cheap even with lookups. In most cases,
> it's just gonna be an extra pointer deref and a few more arithmetics. Tha=
t
> can show up in microbenchmarks but it's not gonna be much. The benefit of
> going that route would be the tracking thing being mostly self contained.

I'm in the process of rerunning the tests to compare the overhead on
the latest kernel but I don't expect that to be cheap compared to
kmalloc().

>
> That said, it's nice to not have to worry about allocating tracking slots
> and managing hash table, so no strong opinion.
>
> Thanks.
>
> --
> tejun
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
kasan-dev/CAJuCfpGmc%3D%3DxztXgiM%2BUUA5GGhxstB2r%3DyTjNUwSshaj5FpBFw%40mai=
l.gmail.com.
