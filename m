Return-Path: <kasan-dev+bncBC7OD3FKWUERBIVYXOYAMGQEPIUTPYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DA3D8898CC8
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 18:58:12 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-dccc49ef73esf2026606276.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Apr 2024 09:58:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712249891; cv=pass;
        d=google.com; s=arc-20160816;
        b=oM4f1IriUEbxcjitwVoAKRerlnsMXFdR03AC7itjSRAEnqVsF1fTELotKsvnB6ozZb
         02WoJvxR9gr+tI7dpTGSqE/w/mfJE87oNq35TfJhxIx0t0aETUYIWsien83xlCjidt0Z
         g+SwRH0UcAJi37Ha/A+pGa4FHCvbCyvc0/nR29knsyK/0/wvA4HS3LeVQaYtum/T5Erg
         tsRR0uOq/4VCMAPE5EwROrY/J3dariwvWFbtf+YEYcuVSg1hYTDLvNiYciNYvDyvFHwO
         6F4UNj1N1G079wjStXe9JFc1rHZeZ4A3TYc/zo3UawBQj1SzucNLN1cZ7sVcsi4K6nV3
         nYEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k4fB+AAot87putTVfwi2FJDsjYiAFEXql+1iK04x49s=;
        fh=FwQlnyenjXPX5Y6WKjO7AlReqrfvNpUrC3myviuK4h8=;
        b=JPEYDLrW+xIf6QuJhitQFtY6/fEpInWJStasKPaGHmSoOkQOkmMqxEGyLLYObhQVC0
         AYeAZT3nM/+FL8BdRLn/V7qjHKHHDQfVDBqgxaC6K4ggQjlYpBlMgFUFU9FU+3u7a2ve
         Jeq8NNo9ToqLlkd5cfE3jA+E5XW/UZFJgSUwKCIJH5AyW5akLX/v+OdjrA4d62G6A31X
         DWbhOM2OFjTvpklphfZVPFZfqH34U5BXy2Bc2HAXSwtvDAEJAA6uSHJa3eirITrbjjYF
         Rct0rQyg9DDQKqwh+GNiDDIHJ9np8p+KtEvhoHW08Ar0tRKdQjMyWD4dTHgUiIsJNOSX
         FrEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xJGQ08IR;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712249891; x=1712854691; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k4fB+AAot87putTVfwi2FJDsjYiAFEXql+1iK04x49s=;
        b=A5iyySXgMHLiAy9OCq6sU+5wPHpDwNU22KQwdOD5LME3M2si0FTJY9DDRILkdRKIUb
         mhfH9x8UVclMFKuRodjTAK2BYrcOWdjVK5OZkt3CntM91xYzUg3Roh7W3rqTfaR7Mnli
         e83RDimogK/2RNOLK8b99dOKzUGZ37gkEJ6ak85F/uouBkbDY3EeI1R9GiQE1u9oQiOI
         qwpSk5FVLxWtvL9djQp7tH5SNDHKQkYvbDuEyt9NvcdN3Wqq+xgNBiYeXy7/J+Qw9wRZ
         KWdcvz2Jjpxz81+jNGKRbWln/25WcJ0XOqqitarU4zp8K9NxTxYuV7J0RDP8i7I4xHjr
         67IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712249891; x=1712854691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=k4fB+AAot87putTVfwi2FJDsjYiAFEXql+1iK04x49s=;
        b=Zbka6oVEkCVoUmcbJoVV2f/4SSxUh7G8efz6MI21mHX6BdJ/pLoR6RT13cN/A4dOyx
         wVK4s7cKi1rSGvCwbXyFBo/Cby08smsDwW4Cv3x/gucHKWrIDjyZxmfnL0po90n0V8ql
         5ZqVlxlGB6CNH7Pf1AsEZz0a437B+9Lq+MIDWnt8ftdaDKR43QMM9jwL+n52BHTcEbrD
         hOjcIeoRGnc9Bh/jvDwXW9Ery/NAjTtmwnkIoo2dlA93Afur4xEw1ynn5JHtS2oC0xA6
         7C1nRw9GAOztAX0Bz0VxsIrmSGsKqYdEXb6jj3eTllW6j88A/upcoCLMg5IUKOh6Ld74
         ZQhg==
X-Forwarded-Encrypted: i=2; AJvYcCWCj6PA1DD15Oj+n9EBxBpv2wrpQHrYewzlcz1IvO0siRkl1LQPlItWmqYKYixgNZ+p013d/3WMjPnjbp2+XR5L0IkpdQUCDQ==
X-Gm-Message-State: AOJu0Yy4PYPLaMx1W4CEkXF2iZ6Mq6GovlP1/Gn1+VQp7FyppV0ijD4E
	53/gYodWtYSKuygENSZB7BhSSdcRjeZAA9NuEQgrUykhZMEj6365
X-Google-Smtp-Source: AGHT+IHZwrUlv3nbt9f0C2GY4J3tJJJMuZa4Z31u04qe8bzwvxihCnSPqzpTtoWFduN5+Cfpzmi12A==
X-Received: by 2002:a05:6902:d1:b0:dc6:bbbd:d4f4 with SMTP id i17-20020a05690200d100b00dc6bbbdd4f4mr2890421ybs.33.1712249891011;
        Thu, 04 Apr 2024 09:58:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2a8c:b0:696:920b:5e1f with SMTP id
 jr12-20020a0562142a8c00b00696920b5e1fls1610639qvb.1.-pod-prod-04-us; Thu, 04
 Apr 2024 09:58:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwfOa0RVBhNlDIXsCcOU/UGHg0O/5DzRtG20IQvaXriCKvVmMeKhtR4+10sM56sgS5nJutJ1C3KM3HyydHUks+5MIpwU/jeVKI9Q==
X-Received: by 2002:a05:6102:34c8:b0:476:f078:2526 with SMTP id a8-20020a05610234c800b00476f0782526mr3049921vst.15.1712249890275;
        Thu, 04 Apr 2024 09:58:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712249890; cv=none;
        d=google.com; s=arc-20160816;
        b=WdeIoZUugx6EVD974xBVClSXLh8xOF/T48zqpTWfYm4SBlrP5xVi/S0utC6FD1t14B
         qRCiQEKFoaKMgosM0D7Y5OeYMjA+3+bVY6ZOv3t0kSCzZOrFOFgjim8Tjdh2HQQZYXl9
         T+1lsxMe+G0cdfv+tNY79Xn8Dx0W+wwSiFUWnctEhupR+2c6x9+lTia2hQjbGAzzWQ5b
         d2F+EPkIf6jiaLKGjaz9FI86RBA9iri0yYCmxLuLDb7t2vLIoyVMp6+we2Q2dozWLSWX
         v/6gD+u3HCDaa4DJPXHc2q3MpZZjCfOzFDP4u7OjxKWyfg+E+616k6YlscETm0uIvPdZ
         7U6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SnNkrv9amLNSOChMZU1xiNRngWLHsWRGHJdyDWSVIjQ=;
        fh=TE3jYfY+CZ/3xDQgphUo3TCJ1LbponhyRV1p+o24VLc=;
        b=TQ9AK0ZRErDQJsQ/s/0aYdRmBI5Uw3dozooFk41173sEG3YqU4dvMkznNnR+Ldr2EO
         f7V4TsI6bmKDB4EAw7EmFWqRaG+5geygtmPE/cCxcSmAiBF0CzXuptl62xF15V0i599c
         sWqADK2yIagfjoInok55pjVjmlKxIXnZhB94Br6bSKnFg8dEmUYy9aVAX/aMv1G7bwMy
         nsYH5BwzyXMIbsW1sejVX2T9X6+/PS8c1kmz/2wSLZMweFMkkueIfRWKCc14Hxx+Vxmi
         8cdj3vBoEMlxl3jCixXKicBV/X/QuM5iETGbKCePn8l2RAN6hSCLKXICO8PIMqgxi2oP
         QrYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xJGQ08IR;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id qf1-20020a0562144b8100b006965f40ae76si807642qvb.8.2024.04.04.09.58.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Apr 2024 09:58:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-61587aa9f4cso11336597b3.3
        for <kasan-dev@googlegroups.com>; Thu, 04 Apr 2024 09:58:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV0+qg//+2G7yM/K+/rmzEJ0z+hYsLPvGAwg77ZykBAqSPpmLP+gtWPidc83TMrzMvhxe7Wn7A2M9f/Py8vqFb2256EdpqdfNGzRA==
X-Received: by 2002:a5b:481:0:b0:dcc:9d30:58a0 with SMTP id
 n1-20020a5b0481000000b00dcc9d3058a0mr2683124ybp.64.1712249889460; Thu, 04 Apr
 2024 09:58:09 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <20240321163705.3067592-6-surenb@google.com>
 <20240321133147.6d05af5744f9d4da88234fb4@linux-foundation.org>
 <gnqztvimdnvz2hcepdh3o3dpg4cmvlkug4sl7ns5vd4lm7hmao@dpstjnacdubq>
 <20240321150908.48283ba55a6c786dee273ec3@linux-foundation.org>
 <bliyhrwtskv5xhg3rxxszouxntrhnm3nxhcmrmdwwk4iyx5wdo@vodd22dbtn75> <CAJuCfpEO4NjYysJ7X8ME_GjHc41u-_dK4AhrhmaSMh_9mxaHSA@mail.gmail.com>
In-Reply-To: <CAJuCfpEO4NjYysJ7X8ME_GjHc41u-_dK4AhrhmaSMh_9mxaHSA@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Apr 2024 09:57:55 -0700
Message-ID: <CAJuCfpEGJHs=ygb2_PNcqEy__dvhby5N7dvwnno=3pDEvE1+2g@mail.gmail.com>
Subject: Re: [PATCH v6 05/37] fs: Convert alloc_inode_sb() to a macro
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Andrew Morton <akpm@linux-foundation.org>, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
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
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xJGQ08IR;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112d
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

On Thu, Mar 21, 2024 at 3:47=E2=80=AFPM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> On Thu, Mar 21, 2024 at 3:17=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > On Thu, Mar 21, 2024 at 03:09:08PM -0700, Andrew Morton wrote:
> > > On Thu, 21 Mar 2024 17:15:39 -0400 Kent Overstreet <kent.overstreet@l=
inux.dev> wrote:
> > >
> > > > On Thu, Mar 21, 2024 at 01:31:47PM -0700, Andrew Morton wrote:
> > > > > On Thu, 21 Mar 2024 09:36:27 -0700 Suren Baghdasaryan <surenb@goo=
gle.com> wrote:
> > > > >
> > > > > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > > > > >
> > > > > > We're introducing alloc tagging, which tracks memory allocation=
s by
> > > > > > callsite. Converting alloc_inode_sb() to a macro means allocati=
ons will
> > > > > > be tracked by its caller, which is a bit more useful.
> > > > >
> > > > > I'd have thought that there would be many similar
> > > > > inlines-which-allocate-memory.  Such as, I dunno, jbd2_alloc_inod=
e().
> > > > > Do we have to go converting things to macros as people report
> > > > > misleading or less useful results, or is there some more general
> > > > > solution to this?
> > > >
> > > > No, this is just what we have to do.
> > >
> > > Well, this is something we strike in other contexts - kallsyms gives =
us
> > > an inlined function and it's rarely what we wanted.
> > >
> > > I think kallsyms has all the data which is needed to fix this - how
> > > hard can it be to figure out that a particular function address lies
> > > within an outer function?  I haven't looked...
> >
> > This is different, though - even if a function is inlined in multiple
> > places there's only going to be one instance of a static var defined
> > within that function.
>
> I guess one simple way to detect the majority of these helpers would
> be to filter all entries from /proc/allocinfo which originate from
> header files.
>
> ~# grep ".*\.h:." /proc/allocinfo
>       933888      228 include/linux/mm.h:2863 func:pagetable_alloc
>          848       53 include/linux/mm_types.h:1175 func:mm_alloc_cid
>            0        0 include/linux/bpfptr.h:70 func:kvmemdup_bpfptr
>            0        0 include/linux/bpf.h:2237 func:bpf_map_kmalloc_node
>            0        0 include/linux/bpf.h:2256 func:bpf_map_alloc_percpu
>            0        0 include/linux/bpf.h:2256 func:bpf_map_alloc_percpu
>            0        0 include/linux/bpf.h:2237 func:bpf_map_kmalloc_node
>            0        0 include/linux/bpf.h:2249 func:bpf_map_kvcalloc
>            0        0 include/linux/bpf.h:2243 func:bpf_map_kzalloc
>            0        0 include/linux/bpf.h:2237 func:bpf_map_kmalloc_node
>            0        0 include/linux/ptr_ring.h:471
> func:__ptr_ring_init_queue_alloc
>            0        0 include/linux/bpf.h:2256 func:bpf_map_alloc_percpu
>            0        0 include/linux/bpf.h:2237 func:bpf_map_kmalloc_node
>            0        0 include/net/tcx.h:80 func:tcx_entry_create
>            0        0 arch/x86/include/asm/pgalloc.h:156 func:p4d_alloc_o=
ne
>       487424      119 include/linux/mm.h:2863 func:pagetable_alloc
>            0        0 include/linux/mm.h:2863 func:pagetable_alloc
>          832       13 include/linux/jbd2.h:1607 func:jbd2_alloc_inode
>            0        0 include/linux/jbd2.h:1591 func:jbd2_alloc_handle
>            0        0 fs/nfs/iostat.h:51 func:nfs_alloc_iostats
>            0        0 include/net/netlabel.h:281 func:netlbl_secattr_cach=
e_alloc
>            0        0 include/net/netlabel.h:381 func:netlbl_secattr_allo=
c
>            0        0 include/crypto/internal/acompress.h:76
> func:__acomp_request_alloc
>         8064       84 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>         1016       74 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>          384        4 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>          704        3 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>           32        1 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>           64        1 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>           40        2 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>           32        1 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>        30000      625 include/acpi/platform/aclinuxex.h:67
> func:acpi_os_acquire_object
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>            0        0 include/acpi/platform/aclinuxex.h:67
> func:acpi_os_acquire_object
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>          512        1 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>          192        6 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>            0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>          192        3 include/acpi/platform/aclinuxex.h:52 func:acpi_os_a=
llocate
>        61992      861 include/acpi/platform/aclinuxex.h:67
> func:acpi_os_acquire_object
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 include/acpi/platform/aclinuxex.h:67
> func:acpi_os_acquire_object
>            0        0 include/acpi/platform/aclinuxex.h:57
> func:acpi_os_allocate_zeroed
>            0        0 drivers/iommu/amd/amd_iommu.h:141 func:alloc_pgtabl=
e_page
>            0        0 drivers/iommu/amd/amd_iommu.h:141 func:alloc_pgtabl=
e_page
>            0        0 drivers/iommu/amd/amd_iommu.h:141 func:alloc_pgtabl=
e_page
>            0        0 include/linux/dma-fence-chain.h:91
> func:dma_fence_chain_alloc
>            0        0 include/linux/dma-fence-chain.h:91
> func:dma_fence_chain_alloc
>            0        0 include/linux/dma-fence-chain.h:91
> func:dma_fence_chain_alloc
>            0        0 include/linux/dma-fence-chain.h:91
> func:dma_fence_chain_alloc
>            0        0 include/linux/dma-fence-chain.h:91
> func:dma_fence_chain_alloc
>            0        0 include/linux/hid_bpf.h:154 func:call_hid_bpf_rdesc=
_fixup
>            0        0 include/linux/skbuff.h:3392 func:__dev_alloc_pages
>       114688       56 include/linux/ptr_ring.h:471
> func:__ptr_ring_init_queue_alloc
>            0        0 include/linux/skmsg.h:415 func:sk_psock_init_link
>            0        0 include/linux/bpf.h:2237 func:bpf_map_kmalloc_node
>            0        0 include/linux/ptr_ring.h:628 func:ptr_ring_resize_m=
ultiple
>        24576        3 include/linux/ptr_ring.h:471
> func:__ptr_ring_init_queue_alloc
>            0        0 include/net/netlink.h:1896 func:nla_memdup
>            0        0 include/linux/sockptr.h:97 func:memdup_sockptr
>            0        0 include/net/request_sock.h:131 func:reqsk_alloc
>            0        0 include/net/tcp.h:2456 func:tcp_v4_save_options
>            0        0 include/net/tcp.h:2456 func:tcp_v4_save_options
>            0        0 include/crypto/hash.h:586 func:ahash_request_alloc
>            0        0 include/linux/sockptr.h:97 func:memdup_sockptr
>            0        0 include/linux/sockptr.h:97 func:memdup_sockptr
>            0        0 net/sunrpc/auth_gss/auth_gss_internal.h:38
> func:simple_get_netobj
>            0        0 include/crypto/hash.h:586 func:ahash_request_alloc
>            0        0 include/net/netlink.h:1896 func:nla_memdup
>            0        0 include/crypto/skcipher.h:869 func:skcipher_request=
_alloc
>            0        0 include/net/fq_impl.h:361 func:fq_init
>            0        0 include/net/netlabel.h:316 func:netlbl_catmap_alloc
>
> and it finds our example:
>
>          832       13 include/linux/jbd2.h:1607 func:jbd2_alloc_inode
>
> Interestingly the inlined functions which are called from multiple
> places will have multiple entries with the same file+line:
>
>            0        0 include/linux/dma-fence-chain.h:91
> func:dma_fence_chain_alloc
>            0        0 include/linux/dma-fence-chain.h:91
> func:dma_fence_chain_alloc
>            0        0 include/linux/dma-fence-chain.h:91
> func:dma_fence_chain_alloc
>            0        0 include/linux/dma-fence-chain.h:91
> func:dma_fence_chain_alloc
>            0        0 include/linux/dma-fence-chain.h:91
> func:dma_fence_chain_alloc
>
> So, duplicate entries can be also used as an indication of an inlined all=
ocator.
> I'll go chase these down and will post a separate patch converting them.

I just posted https://lore.kernel.org/all/20240404165404.3805498-1-surenb@g=
oogle.com/
to report allocations done from the inlined functions in the headers
to their callers.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEGJHs%3Dygb2_PNcqEy__dvhby5N7dvwnno%3D3pDEvE1%2B2g%40mail.=
gmail.com.
