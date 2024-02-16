Return-Path: <kasan-dev+bncBCC2HSMW4ECBBC7SXKXAMGQED6WOLVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E76DD857359
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 02:23:24 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3641afea5efsf9359155ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 17:23:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708046603; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z69XIPKfsoKUYbJJs6FypVaGYB0LXL6tuVU5awqWKAdJm/PkE4BHqxeIXOT0kLkIih
         A6PqYYYL/selIV/XOVmi6v4RQq3iuxJlTj6vHWZzEelGNdQY9BtTp9guEP3eRbB0mIsb
         lQwLE7O51WQVtfBJk1aNLa3SqFTTZVGor3ZlvizAOBPdAJMe194MQnzjbL6QO/iMEWm1
         SdLtCxq7OnWxoibQypBr/crtjikX1w0hxDrMPAIWKVxW5+m+CNMpdIQX3OVc0yBjiGmr
         y8Lmz4NPnvuKZ9d4OxGEpFX+vOg6ZwPj6llNB6u4JYSHpjzaGxy154mqn7jK2ppz1xaH
         mCKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=SAeClVGR2mwzBgLn54Oh8Wap4iFiKGpFSqzmu/rgj8o=;
        fh=Kle2S2VlPaYFoPgrMklZZdIIkbvT6vD+YJ2nasoKseg=;
        b=olwIB+BxMgnSJ/SjZKhLcIMAUK/q9z8sV2L8YYeT2+blodHr+M2TVhqAO7SgZZFeoq
         ROqguZOrTy+ox0UqUvEjtARFJ5d0z1CAnH7FnRGRBgVvrFqJaByyrWf5G/6SH7IfHTsr
         mprJ9VbQs3WAD4pbNBvhi8JKlYryXLJk6OACV1q8P7XUKETvjnGT8sXvSP9FWJrSMXpC
         N9W25fJgeAV0LtbdG+1KeTlmXSmocXf8vDy2IjfpWe2s2pGpg+c/T/JreImQKbgDqtHE
         ZIXPitTQaqCO0CnIHnkuEcqO6YmG42SfZtBIPb/2fM1acSJAOeTrXMy8O20dvAMdvI5w
         4ywQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=bdJwmihC;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708046603; x=1708651403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SAeClVGR2mwzBgLn54Oh8Wap4iFiKGpFSqzmu/rgj8o=;
        b=Y0mdt8JaXqFqMC2WICopThg37KGLdWGEHDojmAJa/xEQGqf4vaj5NKP+5KxKPqk5qq
         2VPBZCS7RbYaPJimK2RscSDlgkAQ+6w8Z3B+3pNvzV1XbD4xPffYQq+WoAn1covkp44s
         ghLGOFjl4z3BLIOrYxmRPafycl1OMjxFJnqnzH4wGgZbu6Q2cq6a1B6tUqvTA/G15GtD
         8Y64NvTyFP5lD+NIl8OV9GY7vkDntnugq181t+BXuAaZego/DJ9kbmUGX2v2g7KM1pLU
         xJw6RT1UrWIHHM+/O21Zc3OB7yEhRA5Z2EK6t6iGK9zRn17zc6zFFIPyiBg4r0H5PdgY
         0ReQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708046603; x=1708651403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SAeClVGR2mwzBgLn54Oh8Wap4iFiKGpFSqzmu/rgj8o=;
        b=j9vdrbtZUioVDVei6JlTLmfO36CbSmflgR2k4DLvIUzjyC9HnidnCDSRQn1NDk3XI9
         1o+/hcExZNUCrdZD/sPZQ6DO6uF+g8RlS2A/BQJxOOuDPINYC2TrJGxcDhrM6ow9fI0D
         71es0Rmlq5LSmyEBURZ5WsUIZV2iQjWPfmZNA+8yHtvOPsidI5+PWoPTqA6VPSbrntw3
         Fx5MWPp1iGoOwdXDz33MeyoCxhRexagUZWewT7mK9aEkA6H65e/lZoUKyIhUSdsTly5X
         uOG7dCPZMJzwTM14OyKq9L5kYrNgtwifwZDkctTfFcVo+UDr+PH8QBb6/nwnUMZHklJA
         AUbQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXgn21SjclhHl7wM45Vb68J4QuTzQPmNxVmzDCrsDmc8SvdcJysUUibZLP3N/99RsCJzZVRk4mVKEnUhGO5pYVX7gy5KVzCQ==
X-Gm-Message-State: AOJu0Yw7PuLlnfGKocVi9ivn/Dk+SXq41FioYVlzCPdgMFVtJdxGTRXR
	WCi77M/3ooYyyV+N335JPyEZ7VYjvArsBOES3hjvGaIE5zB4OrqO
X-Google-Smtp-Source: AGHT+IGrCz16xfiAK1ezEotg9efXfx+z/JCn9DkQDQdwE1XY3LqiYXDit1/xlTZ1XQar22d7GF4Odw==
X-Received: by 2002:a05:6e02:12c2:b0:365:80d:9aee with SMTP id i2-20020a056e0212c200b00365080d9aeemr1258007ilm.31.1708046603666;
        Thu, 15 Feb 2024 17:23:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ca45:0:b0:364:f2cd:ef8a with SMTP id q5-20020a92ca45000000b00364f2cdef8als267312ilo.0.-pod-prod-09-us;
 Thu, 15 Feb 2024 17:23:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX0iMAXLqnoAOlpZvOkaaKUjxKF1N5tVNNu0xBxy/o/2d+a28qU4MtSIcJ3UCVV3JLuNVzFhdgleFP/rNyO526m4xD5s7kGvaEaGg==
X-Received: by 2002:a5e:c201:0:b0:7c4:8db6:659 with SMTP id v1-20020a5ec201000000b007c48db60659mr4534061iop.19.1708046601992;
        Thu, 15 Feb 2024 17:23:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708046601; cv=none;
        d=google.com; s=arc-20160816;
        b=gQKzmR2jcqb1A3AjHBwbMXQ0+6H8j8xIcTfvYjaN1iQFAxjYejgpmWHKG3PpRHWhdY
         qfah4Pjh3Siko8aziQA+TrymTdMDSJbScwaLP5UiS3TseGEleK8uf/ZcBKiZwXnqGmJ9
         sr/CcCPSD5RvLk3yGz849823jPf3o59kY9M0/NTF1kMovCIPEKk+gtUiLSDYdB8u9Rx8
         rl7sbGP47OL9PqIeejtx6qNwBJqo0SQdhkRfZgLiTzPGMuzxxmd1ebkD/LbRi98ajU3+
         iyGtKMtP6mahlGLSjikOG0JXyULFBNNkxY2KEloDHhwARMqGV7JJtDMmiJSdxc+9uau8
         rS1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=eLBxcB96LUnXdvE3EMMcNpcL8B6icUkLMA8zN7Nwyj8=;
        fh=mS/V1Zbs0o1pOC4v0GX+COZZFkvlApeGnQxSG/xu7LA=;
        b=L0OMCsUtQTbXdzZFpIJgZDwZ9p7qMkt564Hh+JffrLlCurLcNGuslwf6kwvYDpV2aQ
         gfVTtTUM9+Ef6H09CKfsO7NVYOIM9uO9jQPQWEQrPBeXRXHV/WWOF/Z63CIRy1Gx6/ll
         SRar4uqgSuXlcPseIczZNSkB6bCgFucML5S4omCUQTx5dHjtDMxS2Sln7ljdx95cvSYp
         weTZm1vh4gqUknbfjK3upL4fSq1mKMyaSgS5KeAHrDc2E7hCLha8If9eFyTYNeRrUab+
         aUHUIT8qrcyBWBZYk8trB+sLILFS4ScgLGdwZOl3B5cBEW4C9yQ9E2GiMbdRL6e5RGfa
         Qjng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=bdJwmihC;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id q9-20020a02cf09000000b00472c7ee34e7si195068jar.5.2024.02.15.17.23.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 17:23:21 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id d75a77b69052e-42a9c21f9ecso7635281cf.0
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 17:23:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVBPA4DPiP6LiXbtP27xmerg1is57WC+OeUYoRT44MZKlufV6dcx9HdB7pBXEWRmNq15gUrszcDoOcpwebxxCLKsXzHew3fPB6JIA==
X-Received: by 2002:a05:622a:1a94:b0:42a:48bc:f69 with SMTP id
 s20-20020a05622a1a9400b0042a48bc0f69mr4538976qtc.35.1708046601368; Thu, 15
 Feb 2024 17:23:21 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-14-surenb@google.com>
 <20240215165438.cd4f849b291c9689a19ba505@linux-foundation.org> <wdj72247rptlp4g7dzpvgrt3aupbvinskx3abxnhrxh32bmxvt@pm3d3k6rn7pm>
In-Reply-To: <wdj72247rptlp4g7dzpvgrt3aupbvinskx3abxnhrxh32bmxvt@pm3d3k6rn7pm>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Thu, 15 Feb 2024 20:22:44 -0500
Message-ID: <CA+CK2bBod-1FtrWQH89OUhf0QMvTar1btTsE0wfROwiCumA8tg@mail.gmail.com>
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Andrew Morton <akpm@linux-foundation.org>, Suren Baghdasaryan <surenb@google.com>, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
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
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b=bdJwmihC;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
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

On Thu, Feb 15, 2024 at 8:00=E2=80=AFPM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Thu, Feb 15, 2024 at 04:54:38PM -0800, Andrew Morton wrote:
> > On Mon, 12 Feb 2024 13:38:59 -0800 Suren Baghdasaryan <surenb@google.co=
m> wrote:
> >
> > > +Example output.
> > > +
> > > +::
> > > +
> > > +    > cat /proc/allocinfo
> > > +
> > > +      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_page
> > > +     6.08MiB     mm/slab_common.c:950 module:slab_common func:_kmall=
oc_order
> > > +     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:alloc_s=
lab_obj_exts
> > > +     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:alloc_p=
ages_exact
> > > +     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtable fun=
c:__pte_alloc_one
> >
> > I don't really like the fancy MiB stuff.  Wouldn't it be better to just
> > present the amount of memory in plain old bytes, so people can use sort
> > -n on it?
>
> They can use sort -h on it; the string_get_size() patch was specifically
> so that we could make the output compatible with sort -h
>
> > And it's easier to tell big-from-small at a glance because
> > big has more digits.
> >
> > Also, the first thing any sort of downstream processing of this data is
> > going to have to do is to convert the fancified output back into
> > plain-old-bytes.  So why not just emit plain-old-bytes?
> >
> > If someone wants the fancy output (and nobody does) then that can be
> > done in userspace.
>
> I like simpler, more discoverable tools; e.g. we've got a bunch of
> interesting stuff in scripts/ but it doesn't get used nearly as much -
> not as accessible as cat'ing a file, definitely not going to be
> installed by default.

I also prefer plain bytes instead of MiB. A driver developer that
wants to verify up-to the byte allocations for a new data structure
that they added is going to be disappointed by the rounded MiB
numbers.

The data contained in this file is not consumable without at least
"sort -h -r", so why not just output bytes instead?

There is /proc/slabinfo  and there is a slabtop tool.
For raw /proc/allocinfo we can create an alloctop tool that would
parse, sort and show data in human readable format based on various
criteria.

We should also add at the top of this file "allocinfo - version: 1.0",
to allow future extensions (i.e. column for proc name).

Pasha

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bBod-1FtrWQH89OUhf0QMvTar1btTsE0wfROwiCumA8tg%40mail.gmai=
l.com.
