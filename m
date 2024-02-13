Return-Path: <kasan-dev+bncBC7OD3FKWUERB376VKXAMGQE3ACK2SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 952E38524D7
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 02:01:38 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id 5614622812f47-3bd36b9fdafsf4839096b6e.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 17:01:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707786097; cv=pass;
        d=google.com; s=arc-20160816;
        b=gJVlubkcpi+1NkwhHMDoHRg/x7bs9h/vwZzcoSyCA9ejz/B0HwFiw9BaO02vyR3sEu
         9hWNfg0eR7L7nZhx6h5KhXHt3opSEADuzxXUMOCFC+9TEwumAAVnyUIOsz1jeFFwAoBL
         wPnWvTI14NFNh2ZgxxAgPgrZkvXlTvEXwRlIhf8SFeso3RSR/QGgKO1HlONIRbo5zEru
         mS2gfal/VB4LiUpeZ6+CgD7itdV79d/Cn6WSEI8WOIjVlry+gfs9j7Zo+b8MAG7zbSjY
         jtQfV9nBujReWHNIO4FHdv9PwqyiFaYqKJ30lfmKPkG9KR6Kd6yUtX3q620WTbtY5jJQ
         JoaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uUycN8s4hbYK/3Gaug0LO5CQDdXsvyuLzCBIO+k/Z0M=;
        fh=d327f5njXGF3hIuHHxpZtFzWCjb/lcjqJBedjdxXG9c=;
        b=O59zO4GouG0Jt0tAU4MB/fLfoRr9AOiVe82mG6wkBvr0P6kc92W0nEj4HYZ7hIAvyU
         PH/8e4lyOuHWJ5wmVmfq/g6pWD14J2bwdWUUKXC6OPFlL+uX8hHhcKsUfLGQPmiyOwnD
         VtSVR+fdYxktxa8ID2kts4uMPI7DLzC0NgJmBrUloATTIR8T9802qRjtm3GK5LB9Kpnr
         idYFepVXIjS3geWozeO5UWh8EjRPcbafZv/IyVts37SzSlNihcLhes56z/8qc6vhQTbg
         KpHyeov4X5W/HRvDwQsRbgPck53DhzpIO5LXUz5GK6MJ+O+YYkQLXzTQPYiSEAemKDJr
         DRxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=X2TifRkL;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707786097; x=1708390897; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uUycN8s4hbYK/3Gaug0LO5CQDdXsvyuLzCBIO+k/Z0M=;
        b=S19j8hSkQsyH/UeXkAJv0/g1LcWMrT+mofCCOwkd1h+K3ju53DauDlA9IXybAVGjvc
         592e8+hy3YQuGRp+cvs20Q0EEs0ztniajZUIdt+URBmNS0l4WQ8gu79Vwpxti1r1r97K
         AlApgPCfNgSPAld1Z14nrrUk5bR20mqgUlK1w6ElwSE2u1CBzYfaYWWABrpow3m3feYb
         eKPA6rdt5klwHKJKphULUttifMN9WSGAxwEmK9wNGntEtunn1iDW6d88uHG0duaUPJdH
         sx990f25RrZvrtAFk2oijaAPJOxx9XvKaRRM3V1uuMYRPWvwd1+RY1xuY9R1yB8UN3b3
         3+IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707786097; x=1708390897;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uUycN8s4hbYK/3Gaug0LO5CQDdXsvyuLzCBIO+k/Z0M=;
        b=IvBmv9fEE5gF/jBn6fvA29HNa3lTZmh53WO6VqfQNaePXbr394btd3K4P033XTFpTt
         hGdfW0fttHvVUVKrWB1N7pxeFDxEYiWBDnI4tlVNw2DUCm14uMU8QLXZPyuLLwh+zng/
         nA+joHnqKu/Q7SFRLuRb09pzVNOC/yw5w5G6R9fe1EcI4K3agRxLZRc3TjmaOWzHJUKl
         +qR7dRdC/yr/gn11tIWeORy5x01wWb0P6FDSTXr/dTnlYF7vqt17fXkGm44qmR3ogXAs
         5IMdK9WnKJBPBviKGna2ufM79xqQIyasvX/451eMVk/kJjOPnDdly2zXSUGrpxqzQuXD
         Zq5A==
X-Forwarded-Encrypted: i=2; AJvYcCUXpI/3kObcF5vQiD897Jcln6DphwvkawgpeRJx+h8FkixU11QVaXHnygjtm0cLeKcpjVNM4UtPZnHIE8Z41k1mP4evGCtZOg==
X-Gm-Message-State: AOJu0YzzUv1jXjvdi5kvpCmbFTCIaZu4c/3Olb7CaCacPOB+QrRwWXdE
	icPRR36wXf+WKDOZUJI6TScP9+BfpwoWVpSGJptJNT5gzyNq+WAf
X-Google-Smtp-Source: AGHT+IHxm2DYVMOfl5PSOLfRi80OPPOPHKV2wNzY32R+VvjNSG/bLHQBmxOH1ZmsvFPNxKzf+S7vzA==
X-Received: by 2002:a05:6808:2205:b0:3c0:1a0f:dc47 with SMTP id bd5-20020a056808220500b003c01a0fdc47mr10018184oib.41.1707786095816;
        Mon, 12 Feb 2024 17:01:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a24:b0:42c:5dac:d83a with SMTP id
 f36-20020a05622a1a2400b0042c5dacd83als3822154qtb.1.-pod-prod-03-us; Mon, 12
 Feb 2024 17:01:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV4udDeGIP+rk/r8KbQW8cbEuejP4VwAa61XvUt67Qk18sKJcDPmYpNgByK2H2pOjqh3eEzuYAG62h4Ma25/DfV25Cspg2j0fXu2Q==
X-Received: by 2002:ac8:7f52:0:b0:42c:7663:9b5e with SMTP id g18-20020ac87f52000000b0042c76639b5emr5891404qtk.54.1707786094422;
        Mon, 12 Feb 2024 17:01:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707786094; cv=none;
        d=google.com; s=arc-20160816;
        b=RB6IaECc+LmGJoN6aDyiTnAkI/sFfbPA4SRiDnYxBdI9feUgLRN0Q5+BkwW+CUeBj0
         p68DvnxfkcPsryQbEqHjtSDsRHMq+e5EBQpfibc0WfMjM181iS/VDAxa2/0FOnzRgzgw
         UbyQvMzYXxGyDyZK+q8STS1/OzdOAaWV9R2LpohqKx/dGPRCFsW5oXNF1m7PdGC2dtjI
         6Gzu8pFsVQv7/snqcANodNTf++A6VX88UEbYh+7gcYMHu6wRtIe8BDvREzXgeYWFl4S6
         MrChCgFqZPPDFjyltpSudGVnDZJ+FS8x9u5W1R6yvCkFNdkMpSIhQQkgWngT26m+kri9
         pCRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xmWnPsWYGgtp1IM7yrKjlI/adtDYC7jWpTo2p40Dxqs=;
        fh=+v62wFEKj7QM2OSg7OYfX6L6yflooAbf34EbiJk6M9M=;
        b=FJ2ydbpQgTRK8TKCBla7koRzJkMlifpZSBtZOKg4BgnodKO1qbCi0ALmrW2H98TAF8
         STbaKbHaDm2sypFIqJuj7s+FWjdfchq4Ur2If61pu8IoJiBZm9wgIwoTj4PMhQoZizWi
         if6CwBiONMrg17o8KVsieviEYoi1fp8kcVEzLpEtycK9KcbCzNvp8AERGbiht33npl2i
         EBOvolfxyuDyOf+r6uCEcyu5e6+zGCCUCJ5embKieKyG3gHYbP4cQYzBbHkbivqZLRip
         6kbg9egknXOkSEQN8ZsCSUMCdY3cyiWR0sYAmW7J1M2PIjpw4ZgSrg18qqs10Xjx/MiP
         Sdgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=X2TifRkL;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCURnO95pqrZkY8ThTdeWV4L5VsiGtCqCphiM/3TbE9joZgl3sjKXImdqYbEAJPlpvcjZExjZFAwACxWGjT9QkMu7UCMMpiGFJ7hWw==
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id o3-20020ac87c43000000b0042da8da3d03si158967qtv.4.2024.02.12.17.01.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 17:01:34 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id 3f1490d57ef6-db4364ecd6aso3318913276.2
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 17:01:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU3wh4gMgMpAWrQGymQ4OOvzRdZAGfJmEbaYUkB/bfOJh3pKIvCWr5p0DR/c2u1wQCsKueTlGEQAm4VxkU1Vwxq//ODGPMHaX9QcQ==
X-Received: by 2002:a25:94f:0:b0:dc7:48f8:ce2e with SMTP id
 u15-20020a25094f000000b00dc748f8ce2emr5138708ybm.37.1707786093566; Mon, 12
 Feb 2024 17:01:33 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-14-surenb@google.com>
 <202402121433.5CC66F34B@keescook>
In-Reply-To: <202402121433.5CC66F34B@keescook>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Feb 2024 17:01:19 -0800
Message-ID: <CAJuCfpGU+UhtcWxk7M3diSiz-b7H64_7NMBaKS5dxVdbYWvQqA@mail.gmail.com>
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
To: Kees Cook <keescook@chromium.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
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
 header.i=@google.com header.s=20230601 header.b=X2TifRkL;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b29 as
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

On Mon, Feb 12, 2024 at 2:40=E2=80=AFPM Kees Cook <keescook@chromium.org> w=
rote:
>
> On Mon, Feb 12, 2024 at 01:38:59PM -0800, Suren Baghdasaryan wrote:
> > Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions to easi=
ly
> > instrument memory allocators. It registers an "alloc_tags" codetag type
> > with /proc/allocinfo interface to output allocation tag information whe=
n
>
> Please don't add anything new to the top-level /proc directory. This
> should likely live in /sys.

Ack. I'll find a more appropriate place for it then.
It just seemed like such generic information which would belong next
to meminfo/zoneinfo and such...

>
> > the feature is enabled.
> > CONFIG_MEM_ALLOC_PROFILING_DEBUG is provided for debugging the memory
> > allocation profiling instrumentation.
> > Memory allocation profiling can be enabled or disabled at runtime using
> > /proc/sys/vm/mem_profiling sysctl when CONFIG_MEM_ALLOC_PROFILING_DEBUG=
=3Dn.
> > CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT enables memory allocation
> > profiling by default.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > ---
> >  Documentation/admin-guide/sysctl/vm.rst |  16 +++
> >  Documentation/filesystems/proc.rst      |  28 +++++
> >  include/asm-generic/codetag.lds.h       |  14 +++
> >  include/asm-generic/vmlinux.lds.h       |   3 +
> >  include/linux/alloc_tag.h               | 133 ++++++++++++++++++++
> >  include/linux/sched.h                   |  24 ++++
> >  lib/Kconfig.debug                       |  25 ++++
> >  lib/Makefile                            |   2 +
> >  lib/alloc_tag.c                         | 158 ++++++++++++++++++++++++
> >  scripts/module.lds.S                    |   7 ++
> >  10 files changed, 410 insertions(+)
> >  create mode 100644 include/asm-generic/codetag.lds.h
> >  create mode 100644 include/linux/alloc_tag.h
> >  create mode 100644 lib/alloc_tag.c
> >
> > diff --git a/Documentation/admin-guide/sysctl/vm.rst b/Documentation/ad=
min-guide/sysctl/vm.rst
> > index c59889de122b..a214719492ea 100644
> > --- a/Documentation/admin-guide/sysctl/vm.rst
> > +++ b/Documentation/admin-guide/sysctl/vm.rst
> > @@ -43,6 +43,7 @@ Currently, these files are in /proc/sys/vm:
> >  - legacy_va_layout
> >  - lowmem_reserve_ratio
> >  - max_map_count
> > +- mem_profiling         (only if CONFIG_MEM_ALLOC_PROFILING=3Dy)
> >  - memory_failure_early_kill
> >  - memory_failure_recovery
> >  - min_free_kbytes
> > @@ -425,6 +426,21 @@ e.g., up to one or two maps per allocation.
> >  The default value is 65530.
> >
> >
> > +mem_profiling
> > +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > +
> > +Enable memory profiling (when CONFIG_MEM_ALLOC_PROFILING=3Dy)
> > +
> > +1: Enable memory profiling.
> > +
> > +0: Disabld memory profiling.
> > +
> > +Enabling memory profiling introduces a small performance overhead for =
all
> > +memory allocations.
> > +
> > +The default value depends on CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEF=
AULT.
> > +
> > +
> >  memory_failure_early_kill:
> >  =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> >
> > diff --git a/Documentation/filesystems/proc.rst b/Documentation/filesys=
tems/proc.rst
> > index 104c6d047d9b..40d6d18308e4 100644
> > --- a/Documentation/filesystems/proc.rst
> > +++ b/Documentation/filesystems/proc.rst
> > @@ -688,6 +688,7 @@ files are there, and which are missing.
> >   =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> >   File         Content
> >   =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > + allocinfo    Memory allocations profiling information
> >   apm          Advanced power management info
> >   bootconfig   Kernel command line obtained from boot config,
> >             and, if there were kernel parameters from the
> > @@ -953,6 +954,33 @@ also be allocatable although a lot of filesystem m=
etadata may have to be
> >  reclaimed to achieve this.
> >
> >
> > +allocinfo
> > +~~~~~~~
> > +
> > +Provides information about memory allocations at all locations in the =
code
> > +base. Each allocation in the code is identified by its source file, li=
ne
> > +number, module and the function calling the allocation. The number of =
bytes
> > +allocated at each location is reported.
> > +
> > +Example output.
> > +
> > +::
> > +
> > +    > cat /proc/allocinfo
> > +
> > +      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_page
> > +     6.08MiB     mm/slab_common.c:950 module:slab_common func:_kmalloc=
_order
> > +     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:alloc_sla=
b_obj_exts
> > +     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:alloc_pag=
es_exact
> > +     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtable func:=
__pte_alloc_one
> > +     1.16MiB     fs/xfs/xfs_log_priv.h:700 module:xfs func:xlog_kvmall=
oc
> > +     1.00MiB     mm/swap_cgroup.c:48 module:swap_cgroup func:swap_cgro=
up_prepare
> > +      734KiB     fs/xfs/kmem.c:20 module:xfs func:kmem_alloc
> > +      640KiB     kernel/rcu/tree.c:3184 module:tree func:fill_page_cac=
he_func
> > +      640KiB     drivers/char/virtio_console.c:452 module:virtio_conso=
le func:alloc_buf
> > +      ...
> > +
> > +
> >  meminfo
> >  ~~~~~~~
> >
> > diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generic/co=
detag.lds.h
> > new file mode 100644
> > index 000000000000..64f536b80380
> > --- /dev/null
> > +++ b/include/asm-generic/codetag.lds.h
> > @@ -0,0 +1,14 @@
> > +/* SPDX-License-Identifier: GPL-2.0-only */
> > +#ifndef __ASM_GENERIC_CODETAG_LDS_H
> > +#define __ASM_GENERIC_CODETAG_LDS_H
> > +
> > +#define SECTION_WITH_BOUNDARIES(_name)       \
> > +     . =3D ALIGN(8);                   \
> > +     __start_##_name =3D .;            \
> > +     KEEP(*(_name))                  \
> > +     __stop_##_name =3D .;
> > +
> > +#define CODETAG_SECTIONS()           \
> > +     SECTION_WITH_BOUNDARIES(alloc_tags)
> > +
> > +#endif /* __ASM_GENERIC_CODETAG_LDS_H */
> > diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vm=
linux.lds.h
> > index 5dd3a61d673d..c9997dc50c50 100644
> > --- a/include/asm-generic/vmlinux.lds.h
> > +++ b/include/asm-generic/vmlinux.lds.h
> > @@ -50,6 +50,8 @@
> >   *               [__nosave_begin, __nosave_end] for the nosave data
> >   */
> >
> > +#include <asm-generic/codetag.lds.h>
> > +
> >  #ifndef LOAD_OFFSET
> >  #define LOAD_OFFSET 0
> >  #endif
> > @@ -366,6 +368,7 @@
> >       . =3D ALIGN(8);                                                  =
 \
> >       BOUNDED_SECTION_BY(__dyndbg_classes, ___dyndbg_classes)         \
> >       BOUNDED_SECTION_BY(__dyndbg, ___dyndbg)                         \
> > +     CODETAG_SECTIONS()                                              \
> >       LIKELY_PROFILE()                                                \
> >       BRANCH_PROFILE()                                                \
> >       TRACE_PRINTKS()                                                 \
> > diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> > new file mode 100644
> > index 000000000000..cf55a149fa84
> > --- /dev/null
> > +++ b/include/linux/alloc_tag.h
> > @@ -0,0 +1,133 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +/*
> > + * allocation tagging
> > + */
> > +#ifndef _LINUX_ALLOC_TAG_H
> > +#define _LINUX_ALLOC_TAG_H
> > +
> > +#include <linux/bug.h>
> > +#include <linux/codetag.h>
> > +#include <linux/container_of.h>
> > +#include <linux/preempt.h>
> > +#include <asm/percpu.h>
> > +#include <linux/cpumask.h>
> > +#include <linux/static_key.h>
> > +
> > +struct alloc_tag_counters {
> > +     u64 bytes;
> > +     u64 calls;
> > +};
> > +
> > +/*
> > + * An instance of this structure is created in a special ELF section a=
t every
> > + * allocation callsite. At runtime, the special section is treated as
> > + * an array of these. Embedded codetag utilizes codetag framework.
> > + */
> > +struct alloc_tag {
> > +     struct codetag                  ct;
> > +     struct alloc_tag_counters __percpu      *counters;
> > +} __aligned(8);
> > +
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +
> > +static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
> > +{
> > +     return container_of(ct, struct alloc_tag, ct);
> > +}
> > +
> > +#ifdef ARCH_NEEDS_WEAK_PER_CPU
> > +/*
> > + * When percpu variables are required to be defined as weak, static pe=
rcpu
> > + * variables can't be used inside a function (see comments for DECLARE=
_PER_CPU_SECTION).
> > + */
> > +#error "Memory allocation profiling is incompatible with ARCH_NEEDS_WE=
AK_PER_CPU"
>
> Is this enforced via Kconfig as well? (Looks like only alpha and s390?)

Unfortunately ARCH_NEEDS_WEAK_PER_CPU is not a Kconfig option but
CONFIG_DEBUG_FORCE_WEAK_PER_CPU is, so that one is handled via Kconfig
(see "depends on !DEBUG_FORCE_WEAK_PER_CPU" in this patch). We have to
avoid both cases because of this:
https://elixir.bootlin.com/linux/latest/source/include/linux/percpu-defs.h#=
L75,
so I'm trying to provide an informative error here.

>
> > +#endif
> > +
> > +#define DEFINE_ALLOC_TAG(_alloc_tag, _old)                            =
       \
> > +     static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr)=
;      \
> > +     static struct alloc_tag _alloc_tag __used __aligned(8)           =
       \
> > +     __section("alloc_tags") =3D {                                    =
         \
> > +             .ct =3D CODE_TAG_INIT,                                   =
         \
> > +             .counters =3D &_alloc_tag_cntr };                        =
         \
> > +     struct alloc_tag * __maybe_unused _old =3D alloc_tag_save(&_alloc=
_tag)
> > +
> > +DECLARE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=
,
> > +                     mem_alloc_profiling_key);
> > +
> > +static inline bool mem_alloc_profiling_enabled(void)
> > +{
> > +     return static_branch_maybe(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_=
DEFAULT,
> > +                                &mem_alloc_profiling_key);
> > +}
> > +
> > +static inline struct alloc_tag_counters alloc_tag_read(struct alloc_ta=
g *tag)
> > +{
> > +     struct alloc_tag_counters v =3D { 0, 0 };
> > +     struct alloc_tag_counters *counter;
> > +     int cpu;
> > +
> > +     for_each_possible_cpu(cpu) {
> > +             counter =3D per_cpu_ptr(tag->counters, cpu);
> > +             v.bytes +=3D counter->bytes;
> > +             v.calls +=3D counter->calls;
> > +     }
> > +
> > +     return v;
> > +}
> > +
> > +static inline void __alloc_tag_sub(union codetag_ref *ref, size_t byte=
s)
> > +{
> > +     struct alloc_tag *tag;
> > +
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > +     WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
> > +#endif
> > +     if (!ref || !ref->ct)
> > +             return;
> > +
> > +     tag =3D ct_to_alloc_tag(ref->ct);
> > +
> > +     this_cpu_sub(tag->counters->bytes, bytes);
> > +     this_cpu_dec(tag->counters->calls);
> > +
> > +     ref->ct =3D NULL;
> > +}
> > +
> > +static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
> > +{
> > +     __alloc_tag_sub(ref, bytes);
> > +}
> > +
> > +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_=
t bytes)
> > +{
> > +     __alloc_tag_sub(ref, bytes);
> > +}
> > +
> > +static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_=
tag *tag, size_t bytes)
> > +{
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > +     WARN_ONCE(ref && ref->ct,
> > +               "alloc_tag was not cleared (got tag for %s:%u)\n",\
> > +               ref->ct->filename, ref->ct->lineno);
> > +
> > +     WARN_ONCE(!tag, "current->alloc_tag not set");
> > +#endif
> > +     if (!ref || !tag)
> > +             return;
> > +
> > +     ref->ct =3D &tag->ct;
> > +     this_cpu_add(tag->counters->bytes, bytes);
> > +     this_cpu_inc(tag->counters->calls);
> > +}
> > +
> > +#else
> > +
> > +#define DEFINE_ALLOC_TAG(_alloc_tag, _old)
> > +static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)=
 {}
> > +static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_=
t bytes) {}
> > +static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_=
tag *tag,
> > +                              size_t bytes) {}
> > +
> > +#endif
> > +
> > +#endif /* _LINUX_ALLOC_TAG_H */
> > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > index ffe8f618ab86..da68a10517c8 100644
> > --- a/include/linux/sched.h
> > +++ b/include/linux/sched.h
> > @@ -770,6 +770,10 @@ struct task_struct {
> >       unsigned int                    flags;
> >       unsigned int                    ptrace;
> >
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +     struct alloc_tag                *alloc_tag;
> > +#endif
>
> Normally scheduling is very sensitive to having anything early in
> task_struct. I would suggest moving this the CONFIG_SCHED_CORE ifdef
> area.

Thanks for the warning! We will look into that.

>
> > +
> >  #ifdef CONFIG_SMP
> >       int                             on_cpu;
> >       struct __call_single_node       wake_entry;
> > @@ -810,6 +814,7 @@ struct task_struct {
> >       struct task_group               *sched_task_group;
> >  #endif
> >
> > +
> >  #ifdef CONFIG_UCLAMP_TASK
> >       /*
> >        * Clamp values requested for a scheduling entity.
> > @@ -2183,4 +2188,23 @@ static inline int sched_core_idle_cpu(int cpu) {=
 return idle_cpu(cpu); }
> >
> >  extern void sched_set_stop_task(int cpu, struct task_struct *stop);
> >
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag)
> > +{
> > +     swap(current->alloc_tag, tag);
> > +     return tag;
> > +}
> > +
> > +static inline void alloc_tag_restore(struct alloc_tag *tag, struct all=
oc_tag *old)
> > +{
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > +     WARN(current->alloc_tag !=3D tag, "current->alloc_tag was changed=
:\n");
> > +#endif
> > +     current->alloc_tag =3D old;
> > +}
> > +#else
> > +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag) =
{ return NULL; }
> > +#define alloc_tag_restore(_tag, _old)
> > +#endif
> > +
> >  #endif
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 0be2d00c3696..78d258ca508f 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -972,6 +972,31 @@ config CODE_TAGGING
> >       bool
> >       select KALLSYMS
> >
> > +config MEM_ALLOC_PROFILING
> > +     bool "Enable memory allocation profiling"
> > +     default n
> > +     depends on PROC_FS
> > +     depends on !DEBUG_FORCE_WEAK_PER_CPU
> > +     select CODE_TAGGING
> > +     help
> > +       Track allocation source code and record total allocation size
> > +       initiated at that code location. The mechanism can be used to t=
rack
> > +       memory leaks with a low performance and memory impact.
> > +
> > +config MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> > +     bool "Enable memory allocation profiling by default"
> > +     default y
> > +     depends on MEM_ALLOC_PROFILING
> > +
> > +config MEM_ALLOC_PROFILING_DEBUG
> > +     bool "Memory allocation profiler debugging"
> > +     default n
> > +     depends on MEM_ALLOC_PROFILING
> > +     select MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> > +     help
> > +       Adds warnings with helpful error messages for memory allocation
> > +       profiling.
> > +
> >  source "lib/Kconfig.kasan"
> >  source "lib/Kconfig.kfence"
> >  source "lib/Kconfig.kmsan"
> > diff --git a/lib/Makefile b/lib/Makefile
> > index 6b48b22fdfac..859112f09bf5 100644
> > --- a/lib/Makefile
> > +++ b/lib/Makefile
> > @@ -236,6 +236,8 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) +=
=3D \
> >  obj-$(CONFIG_FUNCTION_ERROR_INJECTION) +=3D error-inject.o
> >
> >  obj-$(CONFIG_CODE_TAGGING) +=3D codetag.o
> > +obj-$(CONFIG_MEM_ALLOC_PROFILING) +=3D alloc_tag.o
> > +
> >  lib-$(CONFIG_GENERIC_BUG) +=3D bug.o
> >
> >  obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) +=3D syscall.o
> > diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
> > new file mode 100644
> > index 000000000000..4fc031f9cefd
> > --- /dev/null
> > +++ b/lib/alloc_tag.c
> > @@ -0,0 +1,158 @@
> > +// SPDX-License-Identifier: GPL-2.0-only
> > +#include <linux/alloc_tag.h>
> > +#include <linux/fs.h>
> > +#include <linux/gfp.h>
> > +#include <linux/module.h>
> > +#include <linux/proc_fs.h>
> > +#include <linux/seq_buf.h>
> > +#include <linux/seq_file.h>
> > +
> > +static struct codetag_type *alloc_tag_cttype;
> > +
> > +DEFINE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
> > +                     mem_alloc_profiling_key);
> > +
> > +static void *allocinfo_start(struct seq_file *m, loff_t *pos)
> > +{
> > +     struct codetag_iterator *iter;
> > +     struct codetag *ct;
> > +     loff_t node =3D *pos;
> > +
> > +     iter =3D kzalloc(sizeof(*iter), GFP_KERNEL);
> > +     m->private =3D iter;
> > +     if (!iter)
> > +             return NULL;
> > +
> > +     codetag_lock_module_list(alloc_tag_cttype, true);
> > +     *iter =3D codetag_get_ct_iter(alloc_tag_cttype);
> > +     while ((ct =3D codetag_next_ct(iter)) !=3D NULL && node)
> > +             node--;
> > +
> > +     return ct ? iter : NULL;
> > +}
> > +
> > +static void *allocinfo_next(struct seq_file *m, void *arg, loff_t *pos=
)
> > +{
> > +     struct codetag_iterator *iter =3D (struct codetag_iterator *)arg;
> > +     struct codetag *ct =3D codetag_next_ct(iter);
> > +
> > +     (*pos)++;
> > +     if (!ct)
> > +             return NULL;
> > +
> > +     return iter;
> > +}
> > +
> > +static void allocinfo_stop(struct seq_file *m, void *arg)
> > +{
> > +     struct codetag_iterator *iter =3D (struct codetag_iterator *)m->p=
rivate;
> > +
> > +     if (iter) {
> > +             codetag_lock_module_list(alloc_tag_cttype, false);
> > +             kfree(iter);
> > +     }
> > +}
> > +
> > +static void alloc_tag_to_text(struct seq_buf *out, struct codetag *ct)
> > +{
> > +     struct alloc_tag *tag =3D ct_to_alloc_tag(ct);
> > +     struct alloc_tag_counters counter =3D alloc_tag_read(tag);
> > +     s64 bytes =3D counter.bytes;
> > +     char val[10], *p =3D val;
> > +
> > +     if (bytes < 0) {
> > +             *p++ =3D '-';
> > +             bytes =3D -bytes;
> > +     }
> > +
> > +     string_get_size(bytes, 1,
> > +                     STRING_SIZE_BASE2|STRING_SIZE_NOSPACE,
> > +                     p, val + ARRAY_SIZE(val) - p);
> > +
> > +     seq_buf_printf(out, "%8s %8llu ", val, counter.calls);
> > +     codetag_to_text(out, ct);
> > +     seq_buf_putc(out, ' ');
> > +     seq_buf_putc(out, '\n');
> > +}
>
> /me does happy seq_buf dance!
>
> > +
> > +static int allocinfo_show(struct seq_file *m, void *arg)
> > +{
> > +     struct codetag_iterator *iter =3D (struct codetag_iterator *)arg;
> > +     char *bufp;
> > +     size_t n =3D seq_get_buf(m, &bufp);
> > +     struct seq_buf buf;
> > +
> > +     seq_buf_init(&buf, bufp, n);
> > +     alloc_tag_to_text(&buf, iter->ct);
> > +     seq_commit(m, seq_buf_used(&buf));
> > +     return 0;
> > +}
> > +
> > +static const struct seq_operations allocinfo_seq_op =3D {
> > +     .start  =3D allocinfo_start,
> > +     .next   =3D allocinfo_next,
> > +     .stop   =3D allocinfo_stop,
> > +     .show   =3D allocinfo_show,
> > +};
> > +
> > +static void __init procfs_init(void)
> > +{
> > +     proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
> > +}
>
> As mentioned, this really should be in /sys somewhere.

Ack.

>
> > +
> > +static bool alloc_tag_module_unload(struct codetag_type *cttype,
> > +                                 struct codetag_module *cmod)
> > +{
> > +     struct codetag_iterator iter =3D codetag_get_ct_iter(cttype);
> > +     struct alloc_tag_counters counter;
> > +     bool module_unused =3D true;
> > +     struct alloc_tag *tag;
> > +     struct codetag *ct;
> > +
> > +     for (ct =3D codetag_next_ct(&iter); ct; ct =3D codetag_next_ct(&i=
ter)) {
> > +             if (iter.cmod !=3D cmod)
> > +                     continue;
> > +
> > +             tag =3D ct_to_alloc_tag(ct);
> > +             counter =3D alloc_tag_read(tag);
> > +
> > +             if (WARN(counter.bytes, "%s:%u module %s func:%s has %llu=
 allocated at module unload",
> > +                       ct->filename, ct->lineno, ct->modname, ct->func=
tion, counter.bytes))
> > +                     module_unused =3D false;
> > +     }
> > +
> > +     return module_unused;
> > +}
> > +
> > +static struct ctl_table memory_allocation_profiling_sysctls[] =3D {
> > +     {
> > +             .procname       =3D "mem_profiling",
> > +             .data           =3D &mem_alloc_profiling_key,
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > +             .mode           =3D 0444,
> > +#else
> > +             .mode           =3D 0644,
> > +#endif
> > +             .proc_handler   =3D proc_do_static_key,
> > +     },
> > +     { }
> > +};
> > +
> > +static int __init alloc_tag_init(void)
> > +{
> > +     const struct codetag_type_desc desc =3D {
> > +             .section        =3D "alloc_tags",
> > +             .tag_size       =3D sizeof(struct alloc_tag),
> > +             .module_unload  =3D alloc_tag_module_unload,
> > +     };
> > +
> > +     alloc_tag_cttype =3D codetag_register_type(&desc);
> > +     if (IS_ERR_OR_NULL(alloc_tag_cttype))
> > +             return PTR_ERR(alloc_tag_cttype);
> > +
> > +     register_sysctl_init("vm", memory_allocation_profiling_sysctls);
> > +     procfs_init();
> > +
> > +     return 0;
> > +}
> > +module_init(alloc_tag_init);
> > diff --git a/scripts/module.lds.S b/scripts/module.lds.S
> > index bf5bcf2836d8..45c67a0994f3 100644
> > --- a/scripts/module.lds.S
> > +++ b/scripts/module.lds.S
> > @@ -9,6 +9,8 @@
> >  #define DISCARD_EH_FRAME     *(.eh_frame)
> >  #endif
> >
> > +#include <asm-generic/codetag.lds.h>
> > +
> >  SECTIONS {
> >       /DISCARD/ : {
> >               *(.discard)
> > @@ -47,12 +49,17 @@ SECTIONS {
> >       .data : {
> >               *(.data .data.[0-9a-zA-Z_]*)
> >               *(.data..L*)
> > +             CODETAG_SECTIONS()
> >       }
> >
> >       .rodata : {
> >               *(.rodata .rodata.[0-9a-zA-Z_]*)
> >               *(.rodata..L*)
> >       }
> > +#else
> > +     .data : {
> > +             CODETAG_SECTIONS()
> > +     }
> >  #endif
> >  }
>
> Otherwise, looks good.

Thanks!

>
> --
> Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGU%2BUhtcWxk7M3diSiz-b7H64_7NMBaKS5dxVdbYWvQqA%40mail.gmai=
l.com.
