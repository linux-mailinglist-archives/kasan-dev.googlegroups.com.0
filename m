Return-Path: <kasan-dev+bncBC7OD3FKWUERBQO5V6XAMGQE7QHV37I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DEBB853ECF
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:35:47 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1d968aebbd1sf53043975ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:35:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707863745; cv=pass;
        d=google.com; s=arc-20160816;
        b=gocUu3hRKqAQw9igU0mBPy/NuvOwV7z/FNohzJVD5QnvbZiRFNYXBTj/IgMtQeF7KW
         yFpJoLh9BXpozNZVqBV7Z4p0gXRftXOhOlhxM28UH+R9oKN6l/HczsAyLAGXyM7WZQrS
         PV4jkx/evX0/NkGwl/LoNmesEX9tNhYjzSTPwDEKlbPCPN/dRv+6ISxNZ7XotFU2UDYz
         MZmKdBvoa71vryUTI4H+h8o8QcG+kzvEHR4Yw2v8ZZyfWOhusIzsP5nJZtcf8LVMZUUT
         0cHu57loBbfprMQaHRBU/yOkexUry0hIxeaI2zpcvzgxt4Bo1qQTS7hbwcHJvXtRBXiE
         FySg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Pdqw6usrBJ6UoAmoCjqpLAg7yvuAqVKKUa+C9NM16pI=;
        fh=sXn/ddr+wcES1cy3yrO+Er/DgqUbNdhtU83BMVzR5Eo=;
        b=tiOUN3MYS48Cb7WBVjsse3ZL5711ovC4r4eDuJJXCeXl9lsGkEgd5TZRGeu57AdTXw
         OhvMq3eUMgU7Wr4QUyLwZUNh6B8q+v9x/Ehjh7vO8oAowWZm+v7wlPXFPs7Yr3pMkROy
         83T4xCq7QhY5PSVUvwjpZTdH5ciRtm36cFUkgGsPF0P9V62dqvy1ftbGcxndSUrA9HRE
         VPwQGNARXsERILFgpWyJW68/Rbov0fLhEPyQ4MzDPyp5ExV9J7NI1CMbD/kaawPu/18K
         iYym7CnB4mhruah7Vn8h7r0wZJp0koHcUNuyDPcqR8fDAbSU2+V/4ju6/RY5nXhHm+Px
         7Pig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XFN8jgDt;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707863745; x=1708468545; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Pdqw6usrBJ6UoAmoCjqpLAg7yvuAqVKKUa+C9NM16pI=;
        b=iAJyeWSPTqeLL1+KhbmNxyFAag9otmuXba2QC+oPUtM4kdPHE8CZBHYNcVJmD+hBca
         Vc93+CrV2ccl0gTN6ZRKlwXDDZH+n6ziUvV9FLJmQRCJFQ4CYGIqa72gDF7gKm8sHLDA
         gdlMh6tKUqgsyzid95ysgj8Pi3TkC5NjPgNu5iysg5GgT4vaCdGJGWuDnJDMrIDBpWmu
         bYTkkfPPStxQ7DCr+QdyLWq1LYHV3cgZY8bhmw3Bh62IVVLM0EbSEWMCmumzHb8MtoAb
         syW66ZyfGJvlUJKEi/0jD/AtFd2PXE48Jb2HueB3g/z6h3R7QVwxsvAmgOi8YJKIgzA1
         xfBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707863745; x=1708468545;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Pdqw6usrBJ6UoAmoCjqpLAg7yvuAqVKKUa+C9NM16pI=;
        b=VWtwHgZLZLGUSHhtqrSLUUjBSt1dlRxGDNbblypLmxU1duy1/JxY+IeUAqYvFPAJBL
         QH10oUH15Sopu7QAuVeYyMo5itKfgyx3Y9jOX6Z92rbHIYO6+WG1b584kUsQT4GGTqIU
         /GJKIwfMNytu8oiQV81iUM+EN7vruIGaYuOiOHDGqJ6QK56ZwJINzxU3olmtbLnQJBvV
         366G5O7oJPTeZeGs7Z+uGO3UXReRnBnjJhLiB9XWwXPLgoEa8J7HW6mvHP4a5Lsbaz/N
         9AWX6heQS3m2qA7X0yiBNmcdOx2S8qGAmfQC7dsuVckuGioukb517Ro+vCvnMZixUXEL
         Xj2g==
X-Forwarded-Encrypted: i=2; AJvYcCVeHQeY2sRurSoM/KC+qthjAJ+t9zGiIi/iArerMNwzRCcqvkRwdmMUpIeTsrHP5IEzS5oGzbNfmL7rWrto2OukCunyn4GWAg==
X-Gm-Message-State: AOJu0YwZWV+d2McTk7sHsd57V39jZ8iABYhaCwLoFXHAzKZm4IghEEzg
	4DIYrhyyDz5K0WgTb3U+02QpT6MND4mdBd9vrq+goA4RtQGTZR4L
X-Google-Smtp-Source: AGHT+IFbc4bIbxart8RRSO2M7vrrKaSoQs4cdBBD7xmXz8Lnd7jyLPVk/1k73aNbeIHK+VnsHj9cgQ==
X-Received: by 2002:a17:902:a3c3:b0:1db:4245:454b with SMTP id q3-20020a170902a3c300b001db4245454bmr835854plb.57.1707863745270;
        Tue, 13 Feb 2024 14:35:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:82cc:b0:1db:2ca9:b5b8 with SMTP id
 u12-20020a17090282cc00b001db2ca9b5b8ls873532plz.1.-pod-prod-07-us; Tue, 13
 Feb 2024 14:35:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXKohstDxBPY3qOo39nnURNFWzC5DBGu3TJ3smG7cX14i3copSj9EO+0tuOPJ5pnnNvYLznAKR4bXU2fBIT8DU+zqZx6Lo+3+P3dQ==
X-Received: by 2002:a17:903:64c:b0:1d9:5038:f116 with SMTP id kh12-20020a170903064c00b001d95038f116mr788062plb.34.1707863744089;
        Tue, 13 Feb 2024 14:35:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707863744; cv=none;
        d=google.com; s=arc-20160816;
        b=OVUJqdH4uRLaS3B1jgX/rV+D2lPVSRgZwxDBzw0JZ1g2FSQnXD8YU8rUrJVaALq5mk
         9Vc7vDVDDe7fW3qgQ+m2PWR+HXxciulHyNTOhcpDmeIjaTvPStrJG7KchX+WXr8+9CF0
         WACKEjDKnsDnnOcaKXZ8mBGHOZpX28z3FqarDGdg9R3ZsFYpXHLSJatm+Co7R8WJAS/x
         TwHaVT0yrL0c16cNrcCJwx8sUiZHFmSeYhwOg/dVjoi6XrKzQrGuYV90WcLOp3jNYeGJ
         EF6to6Zw9H/1ayiMHxHA3qx7oZQOMLTvYe/9t7tw77MLhu98ebWGyy5IceUss2g0gAXm
         KfUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jUsLVR3P0SB19JANt/xPN4v6+kSCzR6cwYVjnDvCcxo=;
        fh=g6M7SVpK+fYDvSKhJAt7EeKU9nX6+xBRMP6zb4uabp8=;
        b=rzHpkpkE+jpvLhWLc7YK9TX+VeLYPndigqzoeajTBH6zCZDyV1l/H3ieqfreH9xKoa
         7kZVPHd2gYBkAx4tvVmJE0jmzHXAj6vfMDcIJzYjqpjNvpOekOoYIYzZZf0lyxPAwWn6
         tHsTwXgneeiT5+WOYRh2HD43ZdlBkgaQKLaIunmatB3mB32XEazZo9nNhtIrR2Se0prW
         qdPeuL13mifzfrZ2Z2d12+wzcwxvWFvwvPGgAqPV0vAATFMHWO+HXxOpuretnI3jd1jm
         uJ5ZOZvCRj+57c1rityBEPxUIxCtjiN1rYtmoFwLc31YhrNSYETIh6wrdo85CohH/1ms
         UVcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XFN8jgDt;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCWA534HHkKtKfQYbXwdXmyM0CqdAAC6sjtuPDByo33D6oAGxzcLH9JO+zQvZ56WrdOpg5ge5RT/mGonDCfJyN9ZI1h0TuEsuHID4g==
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id ka5-20020a170903334500b001db35a50d43si171093plb.0.2024.02.13.14.35.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 14:35:44 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 3f1490d57ef6-dcc4de7d901so1204047276.0
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 14:35:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVgaYKcFJRbFLBEbx/pgMYmhr8eh2caYlqFQHo9xnqvmcfTvt9D4cT5XMNj7YyM88yzFCl8VLHVkrjx6F1tdmwtrjVULf4mi9bw/A==
X-Received: by 2002:a25:9304:0:b0:dc7:32b1:b7ea with SMTP id
 f4-20020a259304000000b00dc732b1b7eamr591085ybo.46.1707863742768; Tue, 13 Feb
 2024 14:35:42 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-14-surenb@google.com>
 <202402121433.5CC66F34B@keescook> <CAJuCfpGU+UhtcWxk7M3diSiz-b7H64_7NMBaKS5dxVdbYWvQqA@mail.gmail.com>
 <20240213222859.GE6184@frogsfrogsfrogs>
In-Reply-To: <20240213222859.GE6184@frogsfrogsfrogs>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 13 Feb 2024 14:35:29 -0800
Message-ID: <CAJuCfpGHrCXoK828KkmahJzsO7tJsz=7fKehhkWOT8rj-xsAmA@mail.gmail.com>
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
To: "Darrick J. Wong" <djwong@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, akpm@linux-foundation.org, 
	kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
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
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
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
 header.i=@google.com header.s=20230601 header.b=XFN8jgDt;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as
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

On Tue, Feb 13, 2024 at 2:29=E2=80=AFPM Darrick J. Wong <djwong@kernel.org>=
 wrote:
>
> On Mon, Feb 12, 2024 at 05:01:19PM -0800, Suren Baghdasaryan wrote:
> > On Mon, Feb 12, 2024 at 2:40=E2=80=AFPM Kees Cook <keescook@chromium.or=
g> wrote:
> > >
> > > On Mon, Feb 12, 2024 at 01:38:59PM -0800, Suren Baghdasaryan wrote:
> > > > Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions to =
easily
> > > > instrument memory allocators. It registers an "alloc_tags" codetag =
type
> > > > with /proc/allocinfo interface to output allocation tag information=
 when
> > >
> > > Please don't add anything new to the top-level /proc directory. This
> > > should likely live in /sys.
> >
> > Ack. I'll find a more appropriate place for it then.
> > It just seemed like such generic information which would belong next
> > to meminfo/zoneinfo and such...
>
> Save yourself a cycle of "rework the whole fs interface only to have
> someone else tell you no" and put it in debugfs, not sysfs.  Wrangling
> with debugfs is easier than all the macro-happy sysfs stuff; you don't
> have to integrate with the "device" model; and there is no 'one value
> per file' rule.

Thanks for the input. This file used to be in debugfs but reviewers
felt it belonged in /proc if it's to be used in production
environments. Some distros (like Android) disable debugfs in
production.

>
> --D
>
> > >
> > > > the feature is enabled.
> > > > CONFIG_MEM_ALLOC_PROFILING_DEBUG is provided for debugging the memo=
ry
> > > > allocation profiling instrumentation.
> > > > Memory allocation profiling can be enabled or disabled at runtime u=
sing
> > > > /proc/sys/vm/mem_profiling sysctl when CONFIG_MEM_ALLOC_PROFILING_D=
EBUG=3Dn.
> > > > CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT enables memory alloca=
tion
> > > > profiling by default.
> > > >
> > > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > > > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > > > ---
> > > >  Documentation/admin-guide/sysctl/vm.rst |  16 +++
> > > >  Documentation/filesystems/proc.rst      |  28 +++++
> > > >  include/asm-generic/codetag.lds.h       |  14 +++
> > > >  include/asm-generic/vmlinux.lds.h       |   3 +
> > > >  include/linux/alloc_tag.h               | 133 ++++++++++++++++++++
> > > >  include/linux/sched.h                   |  24 ++++
> > > >  lib/Kconfig.debug                       |  25 ++++
> > > >  lib/Makefile                            |   2 +
> > > >  lib/alloc_tag.c                         | 158 ++++++++++++++++++++=
++++
> > > >  scripts/module.lds.S                    |   7 ++
> > > >  10 files changed, 410 insertions(+)
> > > >  create mode 100644 include/asm-generic/codetag.lds.h
> > > >  create mode 100644 include/linux/alloc_tag.h
> > > >  create mode 100644 lib/alloc_tag.c
> > > >
> > > > diff --git a/Documentation/admin-guide/sysctl/vm.rst b/Documentatio=
n/admin-guide/sysctl/vm.rst
> > > > index c59889de122b..a214719492ea 100644
> > > > --- a/Documentation/admin-guide/sysctl/vm.rst
> > > > +++ b/Documentation/admin-guide/sysctl/vm.rst
> > > > @@ -43,6 +43,7 @@ Currently, these files are in /proc/sys/vm:
> > > >  - legacy_va_layout
> > > >  - lowmem_reserve_ratio
> > > >  - max_map_count
> > > > +- mem_profiling         (only if CONFIG_MEM_ALLOC_PROFILING=3Dy)
> > > >  - memory_failure_early_kill
> > > >  - memory_failure_recovery
> > > >  - min_free_kbytes
> > > > @@ -425,6 +426,21 @@ e.g., up to one or two maps per allocation.
> > > >  The default value is 65530.
> > > >
> > > >
> > > > +mem_profiling
> > > > +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > +
> > > > +Enable memory profiling (when CONFIG_MEM_ALLOC_PROFILING=3Dy)
> > > > +
> > > > +1: Enable memory profiling.
> > > > +
> > > > +0: Disabld memory profiling.
> > > > +
> > > > +Enabling memory profiling introduces a small performance overhead =
for all
> > > > +memory allocations.
> > > > +
> > > > +The default value depends on CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY=
_DEFAULT.
> > > > +
> > > > +
> > > >  memory_failure_early_kill:
> > > >  =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
> > > >
> > > > diff --git a/Documentation/filesystems/proc.rst b/Documentation/fil=
esystems/proc.rst
> > > > index 104c6d047d9b..40d6d18308e4 100644
> > > > --- a/Documentation/filesystems/proc.rst
> > > > +++ b/Documentation/filesystems/proc.rst
> > > > @@ -688,6 +688,7 @@ files are there, and which are missing.
> > > >   =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D =3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
> > > >   File         Content
> > > >   =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D =3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
> > > > + allocinfo    Memory allocations profiling information
> > > >   apm          Advanced power management info
> > > >   bootconfig   Kernel command line obtained from boot config,
> > > >             and, if there were kernel parameters from the
> > > > @@ -953,6 +954,33 @@ also be allocatable although a lot of filesyst=
em metadata may have to be
> > > >  reclaimed to achieve this.
> > > >
> > > >
> > > > +allocinfo
> > > > +~~~~~~~
> > > > +
> > > > +Provides information about memory allocations at all locations in =
the code
> > > > +base. Each allocation in the code is identified by its source file=
, line
> > > > +number, module and the function calling the allocation. The number=
 of bytes
> > > > +allocated at each location is reported.
> > > > +
> > > > +Example output.
> > > > +
> > > > +::
> > > > +
> > > > +    > cat /proc/allocinfo
> > > > +
> > > > +      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_page
> > > > +     6.08MiB     mm/slab_common.c:950 module:slab_common func:_kma=
lloc_order
> > > > +     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:alloc=
_slab_obj_exts
> > > > +     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:alloc=
_pages_exact
> > > > +     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtable f=
unc:__pte_alloc_one
> > > > +     1.16MiB     fs/xfs/xfs_log_priv.h:700 module:xfs func:xlog_kv=
malloc
> > > > +     1.00MiB     mm/swap_cgroup.c:48 module:swap_cgroup func:swap_=
cgroup_prepare
> > > > +      734KiB     fs/xfs/kmem.c:20 module:xfs func:kmem_alloc
> > > > +      640KiB     kernel/rcu/tree.c:3184 module:tree func:fill_page=
_cache_func
> > > > +      640KiB     drivers/char/virtio_console.c:452 module:virtio_c=
onsole func:alloc_buf
> > > > +      ...
> > > > +
> > > > +
> > > >  meminfo
> > > >  ~~~~~~~
> > > >
> > > > diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generi=
c/codetag.lds.h
> > > > new file mode 100644
> > > > index 000000000000..64f536b80380
> > > > --- /dev/null
> > > > +++ b/include/asm-generic/codetag.lds.h
> > > > @@ -0,0 +1,14 @@
> > > > +/* SPDX-License-Identifier: GPL-2.0-only */
> > > > +#ifndef __ASM_GENERIC_CODETAG_LDS_H
> > > > +#define __ASM_GENERIC_CODETAG_LDS_H
> > > > +
> > > > +#define SECTION_WITH_BOUNDARIES(_name)       \
> > > > +     . =3D ALIGN(8);                   \
> > > > +     __start_##_name =3D .;            \
> > > > +     KEEP(*(_name))                  \
> > > > +     __stop_##_name =3D .;
> > > > +
> > > > +#define CODETAG_SECTIONS()           \
> > > > +     SECTION_WITH_BOUNDARIES(alloc_tags)
> > > > +
> > > > +#endif /* __ASM_GENERIC_CODETAG_LDS_H */
> > > > diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generi=
c/vmlinux.lds.h
> > > > index 5dd3a61d673d..c9997dc50c50 100644
> > > > --- a/include/asm-generic/vmlinux.lds.h
> > > > +++ b/include/asm-generic/vmlinux.lds.h
> > > > @@ -50,6 +50,8 @@
> > > >   *               [__nosave_begin, __nosave_end] for the nosave dat=
a
> > > >   */
> > > >
> > > > +#include <asm-generic/codetag.lds.h>
> > > > +
> > > >  #ifndef LOAD_OFFSET
> > > >  #define LOAD_OFFSET 0
> > > >  #endif
> > > > @@ -366,6 +368,7 @@
> > > >       . =3D ALIGN(8);                                              =
     \
> > > >       BOUNDED_SECTION_BY(__dyndbg_classes, ___dyndbg_classes)      =
   \
> > > >       BOUNDED_SECTION_BY(__dyndbg, ___dyndbg)                      =
   \
> > > > +     CODETAG_SECTIONS()                                           =
   \
> > > >       LIKELY_PROFILE()                                             =
   \
> > > >       BRANCH_PROFILE()                                             =
   \
> > > >       TRACE_PRINTKS()                                              =
   \
> > > > diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> > > > new file mode 100644
> > > > index 000000000000..cf55a149fa84
> > > > --- /dev/null
> > > > +++ b/include/linux/alloc_tag.h
> > > > @@ -0,0 +1,133 @@
> > > > +/* SPDX-License-Identifier: GPL-2.0 */
> > > > +/*
> > > > + * allocation tagging
> > > > + */
> > > > +#ifndef _LINUX_ALLOC_TAG_H
> > > > +#define _LINUX_ALLOC_TAG_H
> > > > +
> > > > +#include <linux/bug.h>
> > > > +#include <linux/codetag.h>
> > > > +#include <linux/container_of.h>
> > > > +#include <linux/preempt.h>
> > > > +#include <asm/percpu.h>
> > > > +#include <linux/cpumask.h>
> > > > +#include <linux/static_key.h>
> > > > +
> > > > +struct alloc_tag_counters {
> > > > +     u64 bytes;
> > > > +     u64 calls;
> > > > +};
> > > > +
> > > > +/*
> > > > + * An instance of this structure is created in a special ELF secti=
on at every
> > > > + * allocation callsite. At runtime, the special section is treated=
 as
> > > > + * an array of these. Embedded codetag utilizes codetag framework.
> > > > + */
> > > > +struct alloc_tag {
> > > > +     struct codetag                  ct;
> > > > +     struct alloc_tag_counters __percpu      *counters;
> > > > +} __aligned(8);
> > > > +
> > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > > +
> > > > +static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct=
)
> > > > +{
> > > > +     return container_of(ct, struct alloc_tag, ct);
> > > > +}
> > > > +
> > > > +#ifdef ARCH_NEEDS_WEAK_PER_CPU
> > > > +/*
> > > > + * When percpu variables are required to be defined as weak, stati=
c percpu
> > > > + * variables can't be used inside a function (see comments for DEC=
LARE_PER_CPU_SECTION).
> > > > + */
> > > > +#error "Memory allocation profiling is incompatible with ARCH_NEED=
S_WEAK_PER_CPU"
> > >
> > > Is this enforced via Kconfig as well? (Looks like only alpha and s390=
?)
> >
> > Unfortunately ARCH_NEEDS_WEAK_PER_CPU is not a Kconfig option but
> > CONFIG_DEBUG_FORCE_WEAK_PER_CPU is, so that one is handled via Kconfig
> > (see "depends on !DEBUG_FORCE_WEAK_PER_CPU" in this patch). We have to
> > avoid both cases because of this:
> > https://elixir.bootlin.com/linux/latest/source/include/linux/percpu-def=
s.h#L75,
> > so I'm trying to provide an informative error here.
> >
> > >
> > > > +#endif
> > > > +
> > > > +#define DEFINE_ALLOC_TAG(_alloc_tag, _old)                        =
           \
> > > > +     static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_c=
ntr);      \
> > > > +     static struct alloc_tag _alloc_tag __used __aligned(8)       =
           \
> > > > +     __section("alloc_tags") =3D {                                =
             \
> > > > +             .ct =3D CODE_TAG_INIT,                               =
             \
> > > > +             .counters =3D &_alloc_tag_cntr };                    =
             \
> > > > +     struct alloc_tag * __maybe_unused _old =3D alloc_tag_save(&_a=
lloc_tag)
> > > > +
> > > > +DECLARE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEF=
AULT,
> > > > +                     mem_alloc_profiling_key);
> > > > +
> > > > +static inline bool mem_alloc_profiling_enabled(void)
> > > > +{
> > > > +     return static_branch_maybe(CONFIG_MEM_ALLOC_PROFILING_ENABLED=
_BY_DEFAULT,
> > > > +                                &mem_alloc_profiling_key);
> > > > +}
> > > > +
> > > > +static inline struct alloc_tag_counters alloc_tag_read(struct allo=
c_tag *tag)
> > > > +{
> > > > +     struct alloc_tag_counters v =3D { 0, 0 };
> > > > +     struct alloc_tag_counters *counter;
> > > > +     int cpu;
> > > > +
> > > > +     for_each_possible_cpu(cpu) {
> > > > +             counter =3D per_cpu_ptr(tag->counters, cpu);
> > > > +             v.bytes +=3D counter->bytes;
> > > > +             v.calls +=3D counter->calls;
> > > > +     }
> > > > +
> > > > +     return v;
> > > > +}
> > > > +
> > > > +static inline void __alloc_tag_sub(union codetag_ref *ref, size_t =
bytes)
> > > > +{
> > > > +     struct alloc_tag *tag;
> > > > +
> > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > > > +     WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
> > > > +#endif
> > > > +     if (!ref || !ref->ct)
> > > > +             return;
> > > > +
> > > > +     tag =3D ct_to_alloc_tag(ref->ct);
> > > > +
> > > > +     this_cpu_sub(tag->counters->bytes, bytes);
> > > > +     this_cpu_dec(tag->counters->calls);
> > > > +
> > > > +     ref->ct =3D NULL;
> > > > +}
> > > > +
> > > > +static inline void alloc_tag_sub(union codetag_ref *ref, size_t by=
tes)
> > > > +{
> > > > +     __alloc_tag_sub(ref, bytes);
> > > > +}
> > > > +
> > > > +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, s=
ize_t bytes)
> > > > +{
> > > > +     __alloc_tag_sub(ref, bytes);
> > > > +}
> > > > +
> > > > +static inline void alloc_tag_add(union codetag_ref *ref, struct al=
loc_tag *tag, size_t bytes)
> > > > +{
> > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > > > +     WARN_ONCE(ref && ref->ct,
> > > > +               "alloc_tag was not cleared (got tag for %s:%u)\n",\
> > > > +               ref->ct->filename, ref->ct->lineno);
> > > > +
> > > > +     WARN_ONCE(!tag, "current->alloc_tag not set");
> > > > +#endif
> > > > +     if (!ref || !tag)
> > > > +             return;
> > > > +
> > > > +     ref->ct =3D &tag->ct;
> > > > +     this_cpu_add(tag->counters->bytes, bytes);
> > > > +     this_cpu_inc(tag->counters->calls);
> > > > +}
> > > > +
> > > > +#else
> > > > +
> > > > +#define DEFINE_ALLOC_TAG(_alloc_tag, _old)
> > > > +static inline void alloc_tag_sub(union codetag_ref *ref, size_t by=
tes) {}
> > > > +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, s=
ize_t bytes) {}
> > > > +static inline void alloc_tag_add(union codetag_ref *ref, struct al=
loc_tag *tag,
> > > > +                              size_t bytes) {}
> > > > +
> > > > +#endif
> > > > +
> > > > +#endif /* _LINUX_ALLOC_TAG_H */
> > > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > > index ffe8f618ab86..da68a10517c8 100644
> > > > --- a/include/linux/sched.h
> > > > +++ b/include/linux/sched.h
> > > > @@ -770,6 +770,10 @@ struct task_struct {
> > > >       unsigned int                    flags;
> > > >       unsigned int                    ptrace;
> > > >
> > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > > +     struct alloc_tag                *alloc_tag;
> > > > +#endif
> > >
> > > Normally scheduling is very sensitive to having anything early in
> > > task_struct. I would suggest moving this the CONFIG_SCHED_CORE ifdef
> > > area.
> >
> > Thanks for the warning! We will look into that.
> >
> > >
> > > > +
> > > >  #ifdef CONFIG_SMP
> > > >       int                             on_cpu;
> > > >       struct __call_single_node       wake_entry;
> > > > @@ -810,6 +814,7 @@ struct task_struct {
> > > >       struct task_group               *sched_task_group;
> > > >  #endif
> > > >
> > > > +
> > > >  #ifdef CONFIG_UCLAMP_TASK
> > > >       /*
> > > >        * Clamp values requested for a scheduling entity.
> > > > @@ -2183,4 +2188,23 @@ static inline int sched_core_idle_cpu(int cp=
u) { return idle_cpu(cpu); }
> > > >
> > > >  extern void sched_set_stop_task(int cpu, struct task_struct *stop)=
;
> > > >
> > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > > +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *t=
ag)
> > > > +{
> > > > +     swap(current->alloc_tag, tag);
> > > > +     return tag;
> > > > +}
> > > > +
> > > > +static inline void alloc_tag_restore(struct alloc_tag *tag, struct=
 alloc_tag *old)
> > > > +{
> > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > > > +     WARN(current->alloc_tag !=3D tag, "current->alloc_tag was cha=
nged:\n");
> > > > +#endif
> > > > +     current->alloc_tag =3D old;
> > > > +}
> > > > +#else
> > > > +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *t=
ag) { return NULL; }
> > > > +#define alloc_tag_restore(_tag, _old)
> > > > +#endif
> > > > +
> > > >  #endif
> > > > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > > > index 0be2d00c3696..78d258ca508f 100644
> > > > --- a/lib/Kconfig.debug
> > > > +++ b/lib/Kconfig.debug
> > > > @@ -972,6 +972,31 @@ config CODE_TAGGING
> > > >       bool
> > > >       select KALLSYMS
> > > >
> > > > +config MEM_ALLOC_PROFILING
> > > > +     bool "Enable memory allocation profiling"
> > > > +     default n
> > > > +     depends on PROC_FS
> > > > +     depends on !DEBUG_FORCE_WEAK_PER_CPU
> > > > +     select CODE_TAGGING
> > > > +     help
> > > > +       Track allocation source code and record total allocation si=
ze
> > > > +       initiated at that code location. The mechanism can be used =
to track
> > > > +       memory leaks with a low performance and memory impact.
> > > > +
> > > > +config MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> > > > +     bool "Enable memory allocation profiling by default"
> > > > +     default y
> > > > +     depends on MEM_ALLOC_PROFILING
> > > > +
> > > > +config MEM_ALLOC_PROFILING_DEBUG
> > > > +     bool "Memory allocation profiler debugging"
> > > > +     default n
> > > > +     depends on MEM_ALLOC_PROFILING
> > > > +     select MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> > > > +     help
> > > > +       Adds warnings with helpful error messages for memory alloca=
tion
> > > > +       profiling.
> > > > +
> > > >  source "lib/Kconfig.kasan"
> > > >  source "lib/Kconfig.kfence"
> > > >  source "lib/Kconfig.kmsan"
> > > > diff --git a/lib/Makefile b/lib/Makefile
> > > > index 6b48b22fdfac..859112f09bf5 100644
> > > > --- a/lib/Makefile
> > > > +++ b/lib/Makefile
> > > > @@ -236,6 +236,8 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT)=
 +=3D \
> > > >  obj-$(CONFIG_FUNCTION_ERROR_INJECTION) +=3D error-inject.o
> > > >
> > > >  obj-$(CONFIG_CODE_TAGGING) +=3D codetag.o
> > > > +obj-$(CONFIG_MEM_ALLOC_PROFILING) +=3D alloc_tag.o
> > > > +
> > > >  lib-$(CONFIG_GENERIC_BUG) +=3D bug.o
> > > >
> > > >  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) +=3D syscall.o
> > > > diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
> > > > new file mode 100644
> > > > index 000000000000..4fc031f9cefd
> > > > --- /dev/null
> > > > +++ b/lib/alloc_tag.c
> > > > @@ -0,0 +1,158 @@
> > > > +// SPDX-License-Identifier: GPL-2.0-only
> > > > +#include <linux/alloc_tag.h>
> > > > +#include <linux/fs.h>
> > > > +#include <linux/gfp.h>
> > > > +#include <linux/module.h>
> > > > +#include <linux/proc_fs.h>
> > > > +#include <linux/seq_buf.h>
> > > > +#include <linux/seq_file.h>
> > > > +
> > > > +static struct codetag_type *alloc_tag_cttype;
> > > > +
> > > > +DEFINE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFA=
ULT,
> > > > +                     mem_alloc_profiling_key);
> > > > +
> > > > +static void *allocinfo_start(struct seq_file *m, loff_t *pos)
> > > > +{
> > > > +     struct codetag_iterator *iter;
> > > > +     struct codetag *ct;
> > > > +     loff_t node =3D *pos;
> > > > +
> > > > +     iter =3D kzalloc(sizeof(*iter), GFP_KERNEL);
> > > > +     m->private =3D iter;
> > > > +     if (!iter)
> > > > +             return NULL;
> > > > +
> > > > +     codetag_lock_module_list(alloc_tag_cttype, true);
> > > > +     *iter =3D codetag_get_ct_iter(alloc_tag_cttype);
> > > > +     while ((ct =3D codetag_next_ct(iter)) !=3D NULL && node)
> > > > +             node--;
> > > > +
> > > > +     return ct ? iter : NULL;
> > > > +}
> > > > +
> > > > +static void *allocinfo_next(struct seq_file *m, void *arg, loff_t =
*pos)
> > > > +{
> > > > +     struct codetag_iterator *iter =3D (struct codetag_iterator *)=
arg;
> > > > +     struct codetag *ct =3D codetag_next_ct(iter);
> > > > +
> > > > +     (*pos)++;
> > > > +     if (!ct)
> > > > +             return NULL;
> > > > +
> > > > +     return iter;
> > > > +}
> > > > +
> > > > +static void allocinfo_stop(struct seq_file *m, void *arg)
> > > > +{
> > > > +     struct codetag_iterator *iter =3D (struct codetag_iterator *)=
m->private;
> > > > +
> > > > +     if (iter) {
> > > > +             codetag_lock_module_list(alloc_tag_cttype, false);
> > > > +             kfree(iter);
> > > > +     }
> > > > +}
> > > > +
> > > > +static void alloc_tag_to_text(struct seq_buf *out, struct codetag =
*ct)
> > > > +{
> > > > +     struct alloc_tag *tag =3D ct_to_alloc_tag(ct);
> > > > +     struct alloc_tag_counters counter =3D alloc_tag_read(tag);
> > > > +     s64 bytes =3D counter.bytes;
> > > > +     char val[10], *p =3D val;
> > > > +
> > > > +     if (bytes < 0) {
> > > > +             *p++ =3D '-';
> > > > +             bytes =3D -bytes;
> > > > +     }
> > > > +
> > > > +     string_get_size(bytes, 1,
> > > > +                     STRING_SIZE_BASE2|STRING_SIZE_NOSPACE,
> > > > +                     p, val + ARRAY_SIZE(val) - p);
> > > > +
> > > > +     seq_buf_printf(out, "%8s %8llu ", val, counter.calls);
> > > > +     codetag_to_text(out, ct);
> > > > +     seq_buf_putc(out, ' ');
> > > > +     seq_buf_putc(out, '\n');
> > > > +}
> > >
> > > /me does happy seq_buf dance!
> > >
> > > > +
> > > > +static int allocinfo_show(struct seq_file *m, void *arg)
> > > > +{
> > > > +     struct codetag_iterator *iter =3D (struct codetag_iterator *)=
arg;
> > > > +     char *bufp;
> > > > +     size_t n =3D seq_get_buf(m, &bufp);
> > > > +     struct seq_buf buf;
> > > > +
> > > > +     seq_buf_init(&buf, bufp, n);
> > > > +     alloc_tag_to_text(&buf, iter->ct);
> > > > +     seq_commit(m, seq_buf_used(&buf));
> > > > +     return 0;
> > > > +}
> > > > +
> > > > +static const struct seq_operations allocinfo_seq_op =3D {
> > > > +     .start  =3D allocinfo_start,
> > > > +     .next   =3D allocinfo_next,
> > > > +     .stop   =3D allocinfo_stop,
> > > > +     .show   =3D allocinfo_show,
> > > > +};
> > > > +
> > > > +static void __init procfs_init(void)
> > > > +{
> > > > +     proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
> > > > +}
> > >
> > > As mentioned, this really should be in /sys somewhere.
> >
> > Ack.
> >
> > >
> > > > +
> > > > +static bool alloc_tag_module_unload(struct codetag_type *cttype,
> > > > +                                 struct codetag_module *cmod)
> > > > +{
> > > > +     struct codetag_iterator iter =3D codetag_get_ct_iter(cttype);
> > > > +     struct alloc_tag_counters counter;
> > > > +     bool module_unused =3D true;
> > > > +     struct alloc_tag *tag;
> > > > +     struct codetag *ct;
> > > > +
> > > > +     for (ct =3D codetag_next_ct(&iter); ct; ct =3D codetag_next_c=
t(&iter)) {
> > > > +             if (iter.cmod !=3D cmod)
> > > > +                     continue;
> > > > +
> > > > +             tag =3D ct_to_alloc_tag(ct);
> > > > +             counter =3D alloc_tag_read(tag);
> > > > +
> > > > +             if (WARN(counter.bytes, "%s:%u module %s func:%s has =
%llu allocated at module unload",
> > > > +                       ct->filename, ct->lineno, ct->modname, ct->=
function, counter.bytes))
> > > > +                     module_unused =3D false;
> > > > +     }
> > > > +
> > > > +     return module_unused;
> > > > +}
> > > > +
> > > > +static struct ctl_table memory_allocation_profiling_sysctls[] =3D =
{
> > > > +     {
> > > > +             .procname       =3D "mem_profiling",
> > > > +             .data           =3D &mem_alloc_profiling_key,
> > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > > > +             .mode           =3D 0444,
> > > > +#else
> > > > +             .mode           =3D 0644,
> > > > +#endif
> > > > +             .proc_handler   =3D proc_do_static_key,
> > > > +     },
> > > > +     { }
> > > > +};
> > > > +
> > > > +static int __init alloc_tag_init(void)
> > > > +{
> > > > +     const struct codetag_type_desc desc =3D {
> > > > +             .section        =3D "alloc_tags",
> > > > +             .tag_size       =3D sizeof(struct alloc_tag),
> > > > +             .module_unload  =3D alloc_tag_module_unload,
> > > > +     };
> > > > +
> > > > +     alloc_tag_cttype =3D codetag_register_type(&desc);
> > > > +     if (IS_ERR_OR_NULL(alloc_tag_cttype))
> > > > +             return PTR_ERR(alloc_tag_cttype);
> > > > +
> > > > +     register_sysctl_init("vm", memory_allocation_profiling_sysctl=
s);
> > > > +     procfs_init();
> > > > +
> > > > +     return 0;
> > > > +}
> > > > +module_init(alloc_tag_init);
> > > > diff --git a/scripts/module.lds.S b/scripts/module.lds.S
> > > > index bf5bcf2836d8..45c67a0994f3 100644
> > > > --- a/scripts/module.lds.S
> > > > +++ b/scripts/module.lds.S
> > > > @@ -9,6 +9,8 @@
> > > >  #define DISCARD_EH_FRAME     *(.eh_frame)
> > > >  #endif
> > > >
> > > > +#include <asm-generic/codetag.lds.h>
> > > > +
> > > >  SECTIONS {
> > > >       /DISCARD/ : {
> > > >               *(.discard)
> > > > @@ -47,12 +49,17 @@ SECTIONS {
> > > >       .data : {
> > > >               *(.data .data.[0-9a-zA-Z_]*)
> > > >               *(.data..L*)
> > > > +             CODETAG_SECTIONS()
> > > >       }
> > > >
> > > >       .rodata : {
> > > >               *(.rodata .rodata.[0-9a-zA-Z_]*)
> > > >               *(.rodata..L*)
> > > >       }
> > > > +#else
> > > > +     .data : {
> > > > +             CODETAG_SECTIONS()
> > > > +     }
> > > >  #endif
> > > >  }
> > >
> > > Otherwise, looks good.
> >
> > Thanks!
> >
> > >
> > > --
> > > Kees Cook
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGHrCXoK828KkmahJzsO7tJsz%3D7fKehhkWOT8rj-xsAmA%40mail.gmai=
l.com.
