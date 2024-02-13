Return-Path: <kasan-dev+bncBDH6XEHUZMDBBMO2V6XAMGQEZ3GUHZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D7EA853E99
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:29:07 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-68c4e69e121sf15079126d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:29:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707863346; cv=pass;
        d=google.com; s=arc-20160816;
        b=jaBxIibnyKIULpTLJKNqx9Az19i2Ic5SygQlHVC6QhCu0Xnq9hY65oPdrZlzK5pcg9
         4kFtPL8mSHAn7EyfUwyXVaSq0hVFx6SYG67X+DSKpSDQgdJUKCQRN0CGDXajvArcxQJz
         rzp+4y8jquJL+PrWiWx8zLJi2dEuy+PYLIsTgWm49GnHXvkhgIue34FFHHKfZ/widT1m
         PBRCTLgP33wxL473WgfVwnMQ+8jlJONyK8y4dO6ahv5qXvb1l5U1P4f1B5+pBh96JIeQ
         WMxT4ADHTQafR7dOP8/TRqQ8fXi+P1e8LFmaOzJQYLSdxFht9XGKzsu820L2gop+EhQl
         dHYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=MkxftWZkSKDsKi77FLIa96Iz0WElkueR6un2/wtdD9I=;
        fh=TBfJ2vtESinON5H379jX6rVcfVzVz+bJ+JkmkDd2XVs=;
        b=gTXsNsl7os/ivrfzfih2UU7xCA/ZehYifQKLDtueI/fPTAmeG7Kg7NMEaXfhknEbt4
         n5NdP343dhd1O7Vvtw/l2u6FTzFYraXSjYlhOH6uRflUwEdjNC5H5p5vLz0O+as0YgOz
         7xovg7UxJjzizWhVoK2uwqB81zAcJJF485wXB1n5Acv3vCa6y3LQ83raYd3GjPZZuH8p
         I1d+5KEMHz8EfFAWjXP7UWIwgPd8biId0Y4nORnC23ax7HNDvrQkwnDdbKQAq/gEALIo
         7pJ8tF1mVPtT8t+1ayC1yxOis5WGs9DkAqV3gs0DYMSLlKE0kIxJXraVu5WGQkj+0+St
         Htog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=t2w2IyHg;
       spf=pass (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=djwong@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707863346; x=1708468146; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MkxftWZkSKDsKi77FLIa96Iz0WElkueR6un2/wtdD9I=;
        b=odnAPdouw4birfJPIVR2bfymNXxnng0Wg+GyJa97Z5QMhs0ZLw3ttaoyW+S7RkIhJv
         +9yi6rLQKx2PIDK1kYPzwlXJ+c3Zzq89etpAHAwt071tuhrVSh5F1HUCxt5KL/86L90S
         4Uvzat8DF12GxFLiC4PvzPUGe1lbl72TXNgbqw8KdTA/BUmsN8IXBkWLWtxZUXRXi9fQ
         c0lTAiJ5O0nHkOEmTKlWx1yU+90f2rmmXNj55wpBZHx3NMuqujbLPENtqHoiuGrf8nCw
         QZUQo5FjNdbJGUDj3Uioskl2ZSFAa7gK8PLt82eI+Hmd2VGm9n4tbCpQ1/x0fB7HfT72
         hUrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707863346; x=1708468146;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MkxftWZkSKDsKi77FLIa96Iz0WElkueR6un2/wtdD9I=;
        b=XkuPlfSwpEwGb2zhuUr/tPY4KztP3GC1GT9QLzVx1XAXOUPX/a11Q52Xxz5qtWyGIy
         FFuxn1ek+GrArsqrHCFaDp/AIQrrz0y8yRx/7IHGlPuUvHuQsHAwr82ofhuSC1h1xfNr
         w5uGo1vJv8qylpBEPH2j8ZqpxaduqSnj5eUSozZtOsS/X/48Omo9SXWVv+8hELWlni3o
         HftDTGlHYIkEyl+uhoax3zJGzORjcMz7IwjX9vPNMgjgCNBvm1cSLwIjHmFuP1XTbTGz
         KAWChXViD/bhOoFnxT4E7/s8ZQDCSPKKBSynZjVeNF2x5RMwGebMZbWFkSiDx10vdY6H
         RWig==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVc4tyYXaV06Tvn0pMhESKwy93bs2kVuLVrEQoAjrl66eo9V3A0ROL6M2CM2BIwAwDaWd8HMMnc3wklBeD7Af9r1cieyOWMrw==
X-Gm-Message-State: AOJu0Yx52QAhJ/hDt1OYpJR2IFCF8FcfdVzpJ3VTx9vHWtVczWcHHTfV
	mw497XzdUkfPjitUCuGGElEwvHyEx/NsH3M/LHfjNbu2hbjYK/uG
X-Google-Smtp-Source: AGHT+IFcm2luHZG8Ku1OSML5eUFnU6kNYbnwAqiQ3B/91Y3yev1Ej/tN/eEvRxgcRCWmtJTuWftkSg==
X-Received: by 2002:ad4:5d6a:0:b0:68c:908e:eae1 with SMTP id fn10-20020ad45d6a000000b0068c908eeae1mr1188526qvb.26.1707863345821;
        Tue, 13 Feb 2024 14:29:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1d29:b0:68c:d864:e37c with SMTP id
 f9-20020a0562141d2900b0068cd864e37cls6310121qvd.0.-pod-prod-02-us; Tue, 13
 Feb 2024 14:29:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWK6c8ygjerOCzoXbAqnECeAHCOg2HQMIRrmwNzbo+zQOCWvy4o1KxawAXkRM4u8ulaWucMuDWi0fPNEjTtBT1Z3jDnx+0M99b5Uw==
X-Received: by 2002:a1f:ecc3:0:b0:4c0:258c:e4d9 with SMTP id k186-20020a1fecc3000000b004c0258ce4d9mr961389vkh.4.1707863344960;
        Tue, 13 Feb 2024 14:29:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707863344; cv=none;
        d=google.com; s=arc-20160816;
        b=N/oMLBVlh7nAXM6HdKdk7JL0BrklwUsUQmENf3sdjwTvojjb3KyRBsPdOOPE0wPTIM
         b4gUEX2z/X+u+mOqTmT1zIbmpUkf+wwmXNEZ3V/UlJhJXianNMkcfQQ9zvmMpuCk36D7
         DWx/GLX+fOPbmaBAHb6dMO4QAL7p0o0gP+AbK7JUwrdTe1PkDfrl70WD1WjFYuoNDVPz
         GBnnxqNPk5OQ4iVRW0Nvcu1bqrrTl21BpGuI32tBai0y3VIDEWH5bWcSINJiyj69pyAF
         kSDu9iRABBjNbETBJYB2Gey6COs9JIyVTYCzYL/K3o20K2xkX3wrc7r1OsR6pufWHrln
         FXPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=5ddWgNhnq+fPIWetsCxa21uWr5om61jygszjgbfV1p4=;
        fh=uLMLuHJPNTdpePaW3i9NF/wJPevz/ZE7liAwY/vLRJo=;
        b=rtB5lx+TOhyXdxgTBx5/oa6z5eAqoVzWKUC4KynnWH36c5i9f20jS0+YyyvdKEVxbL
         iXexQMleJb60+1uT2oBHVME5obDwp1lN6p0gixiWZq3E9HLdFKpB4lAZpUDWDNw/t0zK
         vgNRnVCbXq5MdxnfnAMIA99lXigW3PA7IU0fpNyoLaCFotIczrk+WjYZhOl3voQpFrUM
         sqBAMupNfp0tIwYkoBTotLwmGcA3fCMLgmBGeu1Wia3v097cQjoVB2r1eYth+SM7z11L
         n92e7ZZMHJpyzuC3wC+YGfBO/HglyaR7ObVTnKFuQSpeveLDkHf9JfRCvMw3GaD530cq
         MFZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=t2w2IyHg;
       spf=pass (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=djwong@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Forwarded-Encrypted: i=1; AJvYcCW8j0qEzIWG2e8yTdb+mUuDe0rgimZNhz1KeyUeZDfgKK3SIf3pqz9WpUFal0azPc3u9PWw3G97nSVs1oXTYl7dfiWRkmPq83HoLA==
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 3-20020a0561220a0300b004b2e6e4330asi972708vkn.1.2024.02.13.14.29.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 14:29:04 -0800 (PST)
Received-SPF: pass (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 9B592CE1B50;
	Tue, 13 Feb 2024 22:29:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BD0ACC433F1;
	Tue, 13 Feb 2024 22:28:59 +0000 (UTC)
Date: Tue, 13 Feb 2024 14:28:59 -0800
From: "Darrick J. Wong" <djwong@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kees Cook <keescook@chromium.org>, akpm@linux-foundation.org,
	kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com,
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <20240213222859.GE6184@frogsfrogsfrogs>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-14-surenb@google.com>
 <202402121433.5CC66F34B@keescook>
 <CAJuCfpGU+UhtcWxk7M3diSiz-b7H64_7NMBaKS5dxVdbYWvQqA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpGU+UhtcWxk7M3diSiz-b7H64_7NMBaKS5dxVdbYWvQqA@mail.gmail.com>
X-Original-Sender: djwong@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=t2w2IyHg;       spf=pass
 (google.com: domain of djwong@kernel.org designates 2604:1380:40e1:4800::1 as
 permitted sender) smtp.mailfrom=djwong@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Feb 12, 2024 at 05:01:19PM -0800, Suren Baghdasaryan wrote:
> On Mon, Feb 12, 2024 at 2:40=E2=80=AFPM Kees Cook <keescook@chromium.org>=
 wrote:
> >
> > On Mon, Feb 12, 2024 at 01:38:59PM -0800, Suren Baghdasaryan wrote:
> > > Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions to ea=
sily
> > > instrument memory allocators. It registers an "alloc_tags" codetag ty=
pe
> > > with /proc/allocinfo interface to output allocation tag information w=
hen
> >
> > Please don't add anything new to the top-level /proc directory. This
> > should likely live in /sys.
>=20
> Ack. I'll find a more appropriate place for it then.
> It just seemed like such generic information which would belong next
> to meminfo/zoneinfo and such...

Save yourself a cycle of "rework the whole fs interface only to have
someone else tell you no" and put it in debugfs, not sysfs.  Wrangling
with debugfs is easier than all the macro-happy sysfs stuff; you don't
have to integrate with the "device" model; and there is no 'one value
per file' rule.

--D

> >
> > > the feature is enabled.
> > > CONFIG_MEM_ALLOC_PROFILING_DEBUG is provided for debugging the memory
> > > allocation profiling instrumentation.
> > > Memory allocation profiling can be enabled or disabled at runtime usi=
ng
> > > /proc/sys/vm/mem_profiling sysctl when CONFIG_MEM_ALLOC_PROFILING_DEB=
UG=3Dn.
> > > CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT enables memory allocati=
on
> > > profiling by default.
> > >
> > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > > ---
> > >  Documentation/admin-guide/sysctl/vm.rst |  16 +++
> > >  Documentation/filesystems/proc.rst      |  28 +++++
> > >  include/asm-generic/codetag.lds.h       |  14 +++
> > >  include/asm-generic/vmlinux.lds.h       |   3 +
> > >  include/linux/alloc_tag.h               | 133 ++++++++++++++++++++
> > >  include/linux/sched.h                   |  24 ++++
> > >  lib/Kconfig.debug                       |  25 ++++
> > >  lib/Makefile                            |   2 +
> > >  lib/alloc_tag.c                         | 158 ++++++++++++++++++++++=
++
> > >  scripts/module.lds.S                    |   7 ++
> > >  10 files changed, 410 insertions(+)
> > >  create mode 100644 include/asm-generic/codetag.lds.h
> > >  create mode 100644 include/linux/alloc_tag.h
> > >  create mode 100644 lib/alloc_tag.c
> > >
> > > diff --git a/Documentation/admin-guide/sysctl/vm.rst b/Documentation/=
admin-guide/sysctl/vm.rst
> > > index c59889de122b..a214719492ea 100644
> > > --- a/Documentation/admin-guide/sysctl/vm.rst
> > > +++ b/Documentation/admin-guide/sysctl/vm.rst
> > > @@ -43,6 +43,7 @@ Currently, these files are in /proc/sys/vm:
> > >  - legacy_va_layout
> > >  - lowmem_reserve_ratio
> > >  - max_map_count
> > > +- mem_profiling         (only if CONFIG_MEM_ALLOC_PROFILING=3Dy)
> > >  - memory_failure_early_kill
> > >  - memory_failure_recovery
> > >  - min_free_kbytes
> > > @@ -425,6 +426,21 @@ e.g., up to one or two maps per allocation.
> > >  The default value is 65530.
> > >
> > >
> > > +mem_profiling
> > > +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > +
> > > +Enable memory profiling (when CONFIG_MEM_ALLOC_PROFILING=3Dy)
> > > +
> > > +1: Enable memory profiling.
> > > +
> > > +0: Disabld memory profiling.
> > > +
> > > +Enabling memory profiling introduces a small performance overhead fo=
r all
> > > +memory allocations.
> > > +
> > > +The default value depends on CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_D=
EFAULT.
> > > +
> > > +
> > >  memory_failure_early_kill:
> > >  =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
> > >
> > > diff --git a/Documentation/filesystems/proc.rst b/Documentation/files=
ystems/proc.rst
> > > index 104c6d047d9b..40d6d18308e4 100644
> > > --- a/Documentation/filesystems/proc.rst
> > > +++ b/Documentation/filesystems/proc.rst
> > > @@ -688,6 +688,7 @@ files are there, and which are missing.
> > >   =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > >   File         Content
> > >   =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > + allocinfo    Memory allocations profiling information
> > >   apm          Advanced power management info
> > >   bootconfig   Kernel command line obtained from boot config,
> > >             and, if there were kernel parameters from the
> > > @@ -953,6 +954,33 @@ also be allocatable although a lot of filesystem=
 metadata may have to be
> > >  reclaimed to achieve this.
> > >
> > >
> > > +allocinfo
> > > +~~~~~~~
> > > +
> > > +Provides information about memory allocations at all locations in th=
e code
> > > +base. Each allocation in the code is identified by its source file, =
line
> > > +number, module and the function calling the allocation. The number o=
f bytes
> > > +allocated at each location is reported.
> > > +
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
> > > +     1.16MiB     fs/xfs/xfs_log_priv.h:700 module:xfs func:xlog_kvma=
lloc
> > > +     1.00MiB     mm/swap_cgroup.c:48 module:swap_cgroup func:swap_cg=
roup_prepare
> > > +      734KiB     fs/xfs/kmem.c:20 module:xfs func:kmem_alloc
> > > +      640KiB     kernel/rcu/tree.c:3184 module:tree func:fill_page_c=
ache_func
> > > +      640KiB     drivers/char/virtio_console.c:452 module:virtio_con=
sole func:alloc_buf
> > > +      ...
> > > +
> > > +
> > >  meminfo
> > >  ~~~~~~~
> > >
> > > diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generic/=
codetag.lds.h
> > > new file mode 100644
> > > index 000000000000..64f536b80380
> > > --- /dev/null
> > > +++ b/include/asm-generic/codetag.lds.h
> > > @@ -0,0 +1,14 @@
> > > +/* SPDX-License-Identifier: GPL-2.0-only */
> > > +#ifndef __ASM_GENERIC_CODETAG_LDS_H
> > > +#define __ASM_GENERIC_CODETAG_LDS_H
> > > +
> > > +#define SECTION_WITH_BOUNDARIES(_name)       \
> > > +     . =3D ALIGN(8);                   \
> > > +     __start_##_name =3D .;            \
> > > +     KEEP(*(_name))                  \
> > > +     __stop_##_name =3D .;
> > > +
> > > +#define CODETAG_SECTIONS()           \
> > > +     SECTION_WITH_BOUNDARIES(alloc_tags)
> > > +
> > > +#endif /* __ASM_GENERIC_CODETAG_LDS_H */
> > > diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/=
vmlinux.lds.h
> > > index 5dd3a61d673d..c9997dc50c50 100644
> > > --- a/include/asm-generic/vmlinux.lds.h
> > > +++ b/include/asm-generic/vmlinux.lds.h
> > > @@ -50,6 +50,8 @@
> > >   *               [__nosave_begin, __nosave_end] for the nosave data
> > >   */
> > >
> > > +#include <asm-generic/codetag.lds.h>
> > > +
> > >  #ifndef LOAD_OFFSET
> > >  #define LOAD_OFFSET 0
> > >  #endif
> > > @@ -366,6 +368,7 @@
> > >       . =3D ALIGN(8);                                                =
   \
> > >       BOUNDED_SECTION_BY(__dyndbg_classes, ___dyndbg_classes)        =
 \
> > >       BOUNDED_SECTION_BY(__dyndbg, ___dyndbg)                        =
 \
> > > +     CODETAG_SECTIONS()                                             =
 \
> > >       LIKELY_PROFILE()                                               =
 \
> > >       BRANCH_PROFILE()                                               =
 \
> > >       TRACE_PRINTKS()                                                =
 \
> > > diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> > > new file mode 100644
> > > index 000000000000..cf55a149fa84
> > > --- /dev/null
> > > +++ b/include/linux/alloc_tag.h
> > > @@ -0,0 +1,133 @@
> > > +/* SPDX-License-Identifier: GPL-2.0 */
> > > +/*
> > > + * allocation tagging
> > > + */
> > > +#ifndef _LINUX_ALLOC_TAG_H
> > > +#define _LINUX_ALLOC_TAG_H
> > > +
> > > +#include <linux/bug.h>
> > > +#include <linux/codetag.h>
> > > +#include <linux/container_of.h>
> > > +#include <linux/preempt.h>
> > > +#include <asm/percpu.h>
> > > +#include <linux/cpumask.h>
> > > +#include <linux/static_key.h>
> > > +
> > > +struct alloc_tag_counters {
> > > +     u64 bytes;
> > > +     u64 calls;
> > > +};
> > > +
> > > +/*
> > > + * An instance of this structure is created in a special ELF section=
 at every
> > > + * allocation callsite. At runtime, the special section is treated a=
s
> > > + * an array of these. Embedded codetag utilizes codetag framework.
> > > + */
> > > +struct alloc_tag {
> > > +     struct codetag                  ct;
> > > +     struct alloc_tag_counters __percpu      *counters;
> > > +} __aligned(8);
> > > +
> > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > +
> > > +static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
> > > +{
> > > +     return container_of(ct, struct alloc_tag, ct);
> > > +}
> > > +
> > > +#ifdef ARCH_NEEDS_WEAK_PER_CPU
> > > +/*
> > > + * When percpu variables are required to be defined as weak, static =
percpu
> > > + * variables can't be used inside a function (see comments for DECLA=
RE_PER_CPU_SECTION).
> > > + */
> > > +#error "Memory allocation profiling is incompatible with ARCH_NEEDS_=
WEAK_PER_CPU"
> >
> > Is this enforced via Kconfig as well? (Looks like only alpha and s390?)
>=20
> Unfortunately ARCH_NEEDS_WEAK_PER_CPU is not a Kconfig option but
> CONFIG_DEBUG_FORCE_WEAK_PER_CPU is, so that one is handled via Kconfig
> (see "depends on !DEBUG_FORCE_WEAK_PER_CPU" in this patch). We have to
> avoid both cases because of this:
> https://elixir.bootlin.com/linux/latest/source/include/linux/percpu-defs.=
h#L75,
> so I'm trying to provide an informative error here.
>=20
> >
> > > +#endif
> > > +
> > > +#define DEFINE_ALLOC_TAG(_alloc_tag, _old)                          =
         \
> > > +     static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cnt=
r);      \
> > > +     static struct alloc_tag _alloc_tag __used __aligned(8)         =
         \
> > > +     __section("alloc_tags") =3D {                                  =
           \
> > > +             .ct =3D CODE_TAG_INIT,                                 =
           \
> > > +             .counters =3D &_alloc_tag_cntr };                      =
           \
> > > +     struct alloc_tag * __maybe_unused _old =3D alloc_tag_save(&_all=
oc_tag)
> > > +
> > > +DECLARE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAU=
LT,
> > > +                     mem_alloc_profiling_key);
> > > +
> > > +static inline bool mem_alloc_profiling_enabled(void)
> > > +{
> > > +     return static_branch_maybe(CONFIG_MEM_ALLOC_PROFILING_ENABLED_B=
Y_DEFAULT,
> > > +                                &mem_alloc_profiling_key);
> > > +}
> > > +
> > > +static inline struct alloc_tag_counters alloc_tag_read(struct alloc_=
tag *tag)
> > > +{
> > > +     struct alloc_tag_counters v =3D { 0, 0 };
> > > +     struct alloc_tag_counters *counter;
> > > +     int cpu;
> > > +
> > > +     for_each_possible_cpu(cpu) {
> > > +             counter =3D per_cpu_ptr(tag->counters, cpu);
> > > +             v.bytes +=3D counter->bytes;
> > > +             v.calls +=3D counter->calls;
> > > +     }
> > > +
> > > +     return v;
> > > +}
> > > +
> > > +static inline void __alloc_tag_sub(union codetag_ref *ref, size_t by=
tes)
> > > +{
> > > +     struct alloc_tag *tag;
> > > +
> > > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > > +     WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
> > > +#endif
> > > +     if (!ref || !ref->ct)
> > > +             return;
> > > +
> > > +     tag =3D ct_to_alloc_tag(ref->ct);
> > > +
> > > +     this_cpu_sub(tag->counters->bytes, bytes);
> > > +     this_cpu_dec(tag->counters->calls);
> > > +
> > > +     ref->ct =3D NULL;
> > > +}
> > > +
> > > +static inline void alloc_tag_sub(union codetag_ref *ref, size_t byte=
s)
> > > +{
> > > +     __alloc_tag_sub(ref, bytes);
> > > +}
> > > +
> > > +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, siz=
e_t bytes)
> > > +{
> > > +     __alloc_tag_sub(ref, bytes);
> > > +}
> > > +
> > > +static inline void alloc_tag_add(union codetag_ref *ref, struct allo=
c_tag *tag, size_t bytes)
> > > +{
> > > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > > +     WARN_ONCE(ref && ref->ct,
> > > +               "alloc_tag was not cleared (got tag for %s:%u)\n",\
> > > +               ref->ct->filename, ref->ct->lineno);
> > > +
> > > +     WARN_ONCE(!tag, "current->alloc_tag not set");
> > > +#endif
> > > +     if (!ref || !tag)
> > > +             return;
> > > +
> > > +     ref->ct =3D &tag->ct;
> > > +     this_cpu_add(tag->counters->bytes, bytes);
> > > +     this_cpu_inc(tag->counters->calls);
> > > +}
> > > +
> > > +#else
> > > +
> > > +#define DEFINE_ALLOC_TAG(_alloc_tag, _old)
> > > +static inline void alloc_tag_sub(union codetag_ref *ref, size_t byte=
s) {}
> > > +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, siz=
e_t bytes) {}
> > > +static inline void alloc_tag_add(union codetag_ref *ref, struct allo=
c_tag *tag,
> > > +                              size_t bytes) {}
> > > +
> > > +#endif
> > > +
> > > +#endif /* _LINUX_ALLOC_TAG_H */
> > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > index ffe8f618ab86..da68a10517c8 100644
> > > --- a/include/linux/sched.h
> > > +++ b/include/linux/sched.h
> > > @@ -770,6 +770,10 @@ struct task_struct {
> > >       unsigned int                    flags;
> > >       unsigned int                    ptrace;
> > >
> > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > +     struct alloc_tag                *alloc_tag;
> > > +#endif
> >
> > Normally scheduling is very sensitive to having anything early in
> > task_struct. I would suggest moving this the CONFIG_SCHED_CORE ifdef
> > area.
>=20
> Thanks for the warning! We will look into that.
>=20
> >
> > > +
> > >  #ifdef CONFIG_SMP
> > >       int                             on_cpu;
> > >       struct __call_single_node       wake_entry;
> > > @@ -810,6 +814,7 @@ struct task_struct {
> > >       struct task_group               *sched_task_group;
> > >  #endif
> > >
> > > +
> > >  #ifdef CONFIG_UCLAMP_TASK
> > >       /*
> > >        * Clamp values requested for a scheduling entity.
> > > @@ -2183,4 +2188,23 @@ static inline int sched_core_idle_cpu(int cpu)=
 { return idle_cpu(cpu); }
> > >
> > >  extern void sched_set_stop_task(int cpu, struct task_struct *stop);
> > >
> > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag=
)
> > > +{
> > > +     swap(current->alloc_tag, tag);
> > > +     return tag;
> > > +}
> > > +
> > > +static inline void alloc_tag_restore(struct alloc_tag *tag, struct a=
lloc_tag *old)
> > > +{
> > > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > > +     WARN(current->alloc_tag !=3D tag, "current->alloc_tag was chang=
ed:\n");
> > > +#endif
> > > +     current->alloc_tag =3D old;
> > > +}
> > > +#else
> > > +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag=
) { return NULL; }
> > > +#define alloc_tag_restore(_tag, _old)
> > > +#endif
> > > +
> > >  #endif
> > > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > > index 0be2d00c3696..78d258ca508f 100644
> > > --- a/lib/Kconfig.debug
> > > +++ b/lib/Kconfig.debug
> > > @@ -972,6 +972,31 @@ config CODE_TAGGING
> > >       bool
> > >       select KALLSYMS
> > >
> > > +config MEM_ALLOC_PROFILING
> > > +     bool "Enable memory allocation profiling"
> > > +     default n
> > > +     depends on PROC_FS
> > > +     depends on !DEBUG_FORCE_WEAK_PER_CPU
> > > +     select CODE_TAGGING
> > > +     help
> > > +       Track allocation source code and record total allocation size
> > > +       initiated at that code location. The mechanism can be used to=
 track
> > > +       memory leaks with a low performance and memory impact.
> > > +
> > > +config MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> > > +     bool "Enable memory allocation profiling by default"
> > > +     default y
> > > +     depends on MEM_ALLOC_PROFILING
> > > +
> > > +config MEM_ALLOC_PROFILING_DEBUG
> > > +     bool "Memory allocation profiler debugging"
> > > +     default n
> > > +     depends on MEM_ALLOC_PROFILING
> > > +     select MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> > > +     help
> > > +       Adds warnings with helpful error messages for memory allocati=
on
> > > +       profiling.
> > > +
> > >  source "lib/Kconfig.kasan"
> > >  source "lib/Kconfig.kfence"
> > >  source "lib/Kconfig.kmsan"
> > > diff --git a/lib/Makefile b/lib/Makefile
> > > index 6b48b22fdfac..859112f09bf5 100644
> > > --- a/lib/Makefile
> > > +++ b/lib/Makefile
> > > @@ -236,6 +236,8 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) +=
=3D \
> > >  obj-$(CONFIG_FUNCTION_ERROR_INJECTION) +=3D error-inject.o
> > >
> > >  obj-$(CONFIG_CODE_TAGGING) +=3D codetag.o
> > > +obj-$(CONFIG_MEM_ALLOC_PROFILING) +=3D alloc_tag.o
> > > +
> > >  lib-$(CONFIG_GENERIC_BUG) +=3D bug.o
> > >
> > >  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) +=3D syscall.o
> > > diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
> > > new file mode 100644
> > > index 000000000000..4fc031f9cefd
> > > --- /dev/null
> > > +++ b/lib/alloc_tag.c
> > > @@ -0,0 +1,158 @@
> > > +// SPDX-License-Identifier: GPL-2.0-only
> > > +#include <linux/alloc_tag.h>
> > > +#include <linux/fs.h>
> > > +#include <linux/gfp.h>
> > > +#include <linux/module.h>
> > > +#include <linux/proc_fs.h>
> > > +#include <linux/seq_buf.h>
> > > +#include <linux/seq_file.h>
> > > +
> > > +static struct codetag_type *alloc_tag_cttype;
> > > +
> > > +DEFINE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAUL=
T,
> > > +                     mem_alloc_profiling_key);
> > > +
> > > +static void *allocinfo_start(struct seq_file *m, loff_t *pos)
> > > +{
> > > +     struct codetag_iterator *iter;
> > > +     struct codetag *ct;
> > > +     loff_t node =3D *pos;
> > > +
> > > +     iter =3D kzalloc(sizeof(*iter), GFP_KERNEL);
> > > +     m->private =3D iter;
> > > +     if (!iter)
> > > +             return NULL;
> > > +
> > > +     codetag_lock_module_list(alloc_tag_cttype, true);
> > > +     *iter =3D codetag_get_ct_iter(alloc_tag_cttype);
> > > +     while ((ct =3D codetag_next_ct(iter)) !=3D NULL && node)
> > > +             node--;
> > > +
> > > +     return ct ? iter : NULL;
> > > +}
> > > +
> > > +static void *allocinfo_next(struct seq_file *m, void *arg, loff_t *p=
os)
> > > +{
> > > +     struct codetag_iterator *iter =3D (struct codetag_iterator *)ar=
g;
> > > +     struct codetag *ct =3D codetag_next_ct(iter);
> > > +
> > > +     (*pos)++;
> > > +     if (!ct)
> > > +             return NULL;
> > > +
> > > +     return iter;
> > > +}
> > > +
> > > +static void allocinfo_stop(struct seq_file *m, void *arg)
> > > +{
> > > +     struct codetag_iterator *iter =3D (struct codetag_iterator *)m-=
>private;
> > > +
> > > +     if (iter) {
> > > +             codetag_lock_module_list(alloc_tag_cttype, false);
> > > +             kfree(iter);
> > > +     }
> > > +}
> > > +
> > > +static void alloc_tag_to_text(struct seq_buf *out, struct codetag *c=
t)
> > > +{
> > > +     struct alloc_tag *tag =3D ct_to_alloc_tag(ct);
> > > +     struct alloc_tag_counters counter =3D alloc_tag_read(tag);
> > > +     s64 bytes =3D counter.bytes;
> > > +     char val[10], *p =3D val;
> > > +
> > > +     if (bytes < 0) {
> > > +             *p++ =3D '-';
> > > +             bytes =3D -bytes;
> > > +     }
> > > +
> > > +     string_get_size(bytes, 1,
> > > +                     STRING_SIZE_BASE2|STRING_SIZE_NOSPACE,
> > > +                     p, val + ARRAY_SIZE(val) - p);
> > > +
> > > +     seq_buf_printf(out, "%8s %8llu ", val, counter.calls);
> > > +     codetag_to_text(out, ct);
> > > +     seq_buf_putc(out, ' ');
> > > +     seq_buf_putc(out, '\n');
> > > +}
> >
> > /me does happy seq_buf dance!
> >
> > > +
> > > +static int allocinfo_show(struct seq_file *m, void *arg)
> > > +{
> > > +     struct codetag_iterator *iter =3D (struct codetag_iterator *)ar=
g;
> > > +     char *bufp;
> > > +     size_t n =3D seq_get_buf(m, &bufp);
> > > +     struct seq_buf buf;
> > > +
> > > +     seq_buf_init(&buf, bufp, n);
> > > +     alloc_tag_to_text(&buf, iter->ct);
> > > +     seq_commit(m, seq_buf_used(&buf));
> > > +     return 0;
> > > +}
> > > +
> > > +static const struct seq_operations allocinfo_seq_op =3D {
> > > +     .start  =3D allocinfo_start,
> > > +     .next   =3D allocinfo_next,
> > > +     .stop   =3D allocinfo_stop,
> > > +     .show   =3D allocinfo_show,
> > > +};
> > > +
> > > +static void __init procfs_init(void)
> > > +{
> > > +     proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
> > > +}
> >
> > As mentioned, this really should be in /sys somewhere.
>=20
> Ack.
>=20
> >
> > > +
> > > +static bool alloc_tag_module_unload(struct codetag_type *cttype,
> > > +                                 struct codetag_module *cmod)
> > > +{
> > > +     struct codetag_iterator iter =3D codetag_get_ct_iter(cttype);
> > > +     struct alloc_tag_counters counter;
> > > +     bool module_unused =3D true;
> > > +     struct alloc_tag *tag;
> > > +     struct codetag *ct;
> > > +
> > > +     for (ct =3D codetag_next_ct(&iter); ct; ct =3D codetag_next_ct(=
&iter)) {
> > > +             if (iter.cmod !=3D cmod)
> > > +                     continue;
> > > +
> > > +             tag =3D ct_to_alloc_tag(ct);
> > > +             counter =3D alloc_tag_read(tag);
> > > +
> > > +             if (WARN(counter.bytes, "%s:%u module %s func:%s has %l=
lu allocated at module unload",
> > > +                       ct->filename, ct->lineno, ct->modname, ct->fu=
nction, counter.bytes))
> > > +                     module_unused =3D false;
> > > +     }
> > > +
> > > +     return module_unused;
> > > +}
> > > +
> > > +static struct ctl_table memory_allocation_profiling_sysctls[] =3D {
> > > +     {
> > > +             .procname       =3D "mem_profiling",
> > > +             .data           =3D &mem_alloc_profiling_key,
> > > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > > +             .mode           =3D 0444,
> > > +#else
> > > +             .mode           =3D 0644,
> > > +#endif
> > > +             .proc_handler   =3D proc_do_static_key,
> > > +     },
> > > +     { }
> > > +};
> > > +
> > > +static int __init alloc_tag_init(void)
> > > +{
> > > +     const struct codetag_type_desc desc =3D {
> > > +             .section        =3D "alloc_tags",
> > > +             .tag_size       =3D sizeof(struct alloc_tag),
> > > +             .module_unload  =3D alloc_tag_module_unload,
> > > +     };
> > > +
> > > +     alloc_tag_cttype =3D codetag_register_type(&desc);
> > > +     if (IS_ERR_OR_NULL(alloc_tag_cttype))
> > > +             return PTR_ERR(alloc_tag_cttype);
> > > +
> > > +     register_sysctl_init("vm", memory_allocation_profiling_sysctls)=
;
> > > +     procfs_init();
> > > +
> > > +     return 0;
> > > +}
> > > +module_init(alloc_tag_init);
> > > diff --git a/scripts/module.lds.S b/scripts/module.lds.S
> > > index bf5bcf2836d8..45c67a0994f3 100644
> > > --- a/scripts/module.lds.S
> > > +++ b/scripts/module.lds.S
> > > @@ -9,6 +9,8 @@
> > >  #define DISCARD_EH_FRAME     *(.eh_frame)
> > >  #endif
> > >
> > > +#include <asm-generic/codetag.lds.h>
> > > +
> > >  SECTIONS {
> > >       /DISCARD/ : {
> > >               *(.discard)
> > > @@ -47,12 +49,17 @@ SECTIONS {
> > >       .data : {
> > >               *(.data .data.[0-9a-zA-Z_]*)
> > >               *(.data..L*)
> > > +             CODETAG_SECTIONS()
> > >       }
> > >
> > >       .rodata : {
> > >               *(.rodata .rodata.[0-9a-zA-Z_]*)
> > >               *(.rodata..L*)
> > >       }
> > > +#else
> > > +     .data : {
> > > +             CODETAG_SECTIONS()
> > > +     }
> > >  #endif
> > >  }
> >
> > Otherwise, looks good.
>=20
> Thanks!
>=20
> >
> > --
> > Kees Cook
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240213222859.GE6184%40frogsfrogsfrogs.
