Return-Path: <kasan-dev+bncBDW2JDUY5AORBXNJ6G7AMGQEMX2ESKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 40DC3A6AC5F
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 18:48:15 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3912b54611dsf655748f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 10:48:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742492894; cv=pass;
        d=google.com; s=arc-20240605;
        b=ExYJHpTHe4lYeP4f0xLn8pPNMIJYdD3SoD07ffYr7aD70dgZd/p3x7n3ciATUplDNd
         hQuM+w0KS9ik3MXkM/8N3CIFBdAeRyLatKuoisqt3K3BcnboDYUjBjvdmnDnmXsw3fVE
         VPb7dy1BtYMrgokobpIaY80Bw7wVwwBOxZOw+Kh0N2FoTtQERlModymEhnsypS21sIMy
         AQ6rSl9SPsuY5Ohi5btfWLk74LZF2/qm4srPymgxkzJjiMue+Z+qPiFPTMGphnAFtWHI
         48d0Zhie1FAINIaL6fh03UkBTj3bis8IbXWcZ1k+x47W7hao1Hg7aK6A40CKHMPwASQ/
         4hGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=0+awIBvWHIl7FDGOJEUqAu2MKOWrgSDNJEDtaL25rRk=;
        fh=uPXTvOfG6/veJ2Jnav0Gi/nFA0dTStvFg7XyEmycZr0=;
        b=DVNepmDa4Z5h7m15PRFA8HJhIyQWkZxvmXexDejrNzLYtEsTEWQWzE9LvHRTdVCiIn
         VPamYKBIR2YQlm8jvAbO8Da770ZzgZ5cxFLV57x2a0IRGISfA0NPXwEtbarrnaK568bO
         +kI3VeUeiYYfMfFsCnClutbMUbYbgtyJi81fmGwTwHrbWWmCao4LVnzGo1suKeBaIswM
         nL9zOhxus3OlKAoVf72UuEx0oyPdI80xGxDw/1c9vUGH8YtTO0gNCSA7mzN57OfBTvKl
         5/NA7b57l2wJtwxyHZCj8ubUr1JScImYQIJX6SJwuFsIvAf2aEAfYjv0XpgKSgJXfVYr
         rDjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lT1+xF+U;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742492894; x=1743097694; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0+awIBvWHIl7FDGOJEUqAu2MKOWrgSDNJEDtaL25rRk=;
        b=eWTbPCH+fIgX49r5ikOOnvo5r6bKYli9bPgcvgcgLnSizq6zJes276rH4Vmaujjy9W
         VPZ+bqXk/wjWHXaSfgc9mtA07+C/PdaanqBvOtDITDkug8WYRZUqUy5WeFcbR0tmqlA8
         0e8p1sL4S+UxJzaCo7Ee1q0iWacNc7I+JUsouO7C8JaemxfQliGzlyflox3ttA6KYzT8
         r5kWN84R/uP2PQMwfbsXCEjk9c/W6aRFu4ZKXA/MjUIx0gzhhJJwdPpdsRdHcvUqW0t9
         Vx99B+0T4LXfvHOWU7oKKSF9tu8cuaGbARLgLrCHiBhSOEvq0CEz8/x5FNX3Kiu5I4l8
         ycVQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742492894; x=1743097694; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0+awIBvWHIl7FDGOJEUqAu2MKOWrgSDNJEDtaL25rRk=;
        b=Nt4PWhdEiK1g9LbbFGyWV6H0auwKb2ezUMuIRXLlDn6GkzaTdyI/21onjcsJYIUr05
         NTG1Gg59h6OSx4Y9eKfAjqv10w4vku4+2jRWVM40Rt+sndENTq2ykUXSRgD1KOqEKdK7
         ejkJJbH91zSIO/49Kh0g1vS8gLhMlV01ojz+NpoShRP2EQCeZbPNQrMrXtSD58QkeT4Z
         qFi5C3k7e3j/d74eiMn80LJPJjL3xqtM+x4TynZBfFBb1CqVqzTopXD94AfGfs+Ntoxp
         9fRe6p92HqfpvQ2DNDWKsRWVo90Seh+F0qrGWle+ssb+Upn6J/p9GlvjtsAS2C4ILTyG
         LlqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742492894; x=1743097694;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0+awIBvWHIl7FDGOJEUqAu2MKOWrgSDNJEDtaL25rRk=;
        b=X4P1zTH0OQhRG1ogtWWTuhLJkS8erQvjptYz7ygxywLpwqpH1xTjE5Uhe4281ktwdI
         8b7u/jR5s+BwKLYCXQerB7ZYnlDGRGALydyggwLk5L52CaeERizJSe90pJXH8vdWY0Hq
         O5Sl/QwDzK0VhpNWPqMIcQxuq322BxsCm09+x7yuX8d53O+F45vMhhPO/mj4Uj1xvGg5
         Pb9RU5DQvNsKZcTNk0CAUqwI44T6HqGXXzrzFdbnxGrrlwZWQT7o4cz6ACWT6im9mOcs
         cT4kRBVY7zICRmrTXhsE8OdAxENlsErTSKw7oep64AiTOdgEXsBvFM/yHnsA4x83C18e
         CHSw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX32rcUo+NtCzbOaqiJewph36wQhN047rTUiO4laXSGWSWSYhKV+2zL82aGT/XQZhTI3LjA2Q==@lfdr.de
X-Gm-Message-State: AOJu0YxuVSJ7p5vrY4CMwJlKNBEyfMY2gCKcgZK3z6zjA3oq8Zhg3nxW
	Eq1v1FLUuoBBazyK1kMcFGiFrroldIN2R308eo3k7+6hzVIwjA1O
X-Google-Smtp-Source: AGHT+IGASIqJpKSxhyh14157oCK/MTFb8hHljy2xjUyBthWiT+Iq5SbrI/9RWoP675Z7GQZ/n4U7gQ==
X-Received: by 2002:a05:6000:184b:b0:38d:e584:81ea with SMTP id ffacd0b85a97d-3997f940541mr391082f8f.45.1742492893880;
        Thu, 20 Mar 2025 10:48:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALR47SbGN1ummJDSji6T+U1rqdF6v144qn/smNFaqIJ2g==
Received: by 2002:adf:e50f:0:b0:38d:c0d2:1328 with SMTP id ffacd0b85a97d-3997ec0e976ls172952f8f.1.-pod-prod-09-eu;
 Thu, 20 Mar 2025 10:48:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtBPthiPhUlidEqt6SqEn3iWSjA0ox1cPSHmnnfQ5XKCe6jXZ4YSZhib10RhRqcAT32B7YU8Wa1Pw=@googlegroups.com
X-Received: by 2002:a5d:64af:0:b0:391:2bcc:11f2 with SMTP id ffacd0b85a97d-3997f8f8321mr522024f8f.1.1742492891199;
        Thu, 20 Mar 2025 10:48:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742492891; cv=none;
        d=google.com; s=arc-20240605;
        b=hsAsBLHSBo/DB7AFcfQk7PPOoP5R5ir99zkl+e40gXfir+RFEEpSkzlNNRnJ8gvjrL
         T1Jyf92Q8PCfDIhf1Pdy+P/LCkaBTexrdVbQWNCfNXra/cfqtjzXaXFa2vt57NKmyP8I
         PABg9XAUKdJ/FVGXpgbm+85i2NZ0wJetgPfPdC9SwK0KDsqbodkfSW21fLeqgeyRAbqb
         ani7Tkk8ogZLVgAWKyQ/M3ORIYLvpp1in6XALvQXZS9gQNCtYJKVGn1J7NStf21YIOIN
         zq6Js7puGwz7Z4c5wNbRrGSqm4vSRpSI9HGXECCfJPgfFgX/6YnKudVe+7wylK6K4P1D
         +irw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dwSKT5FP1BR6N00hLzmPIGh88EZ/x1So/4f2vrksFwI=;
        fh=Xlc1dwXlKL4UgSu/gtTng96dlgLq9kw6vD0StXlTS1U=;
        b=RqTMWv0kOsxHyhS6+E8oLdG0LKck+sJJEdJfvcnzLtL8KHYSGJ+1dGYxL81hgKKoER
         TxttKjfBKSOHCDEhG2DhDnu7UKt7JGeh2y1pNkEyVy+Ohsq+DBgeyjRZ5KrsI8DtAvlh
         GBW6fvYUgbmjbY99497+nzEQcTPgMj/OCEzUriQursVpZYa1um8anQw9MAelZA5T7GUu
         +2Tn4B9Bl1lfUTP0/0BadL4JYxtjaXubxfT7soIqXPX4tUDKZQE8pT6PqBAo23i8p5vb
         D79kn2pMyvuIOdPQO9sdLxkj0HArHTQJUh8jgAvaKGMTysbc8zKD7DVDK905Zql9JkOI
         9y2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lT1+xF+U;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d3ad4422bsi5491955e9.0.2025.03.20.10.48.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Mar 2025 10:48:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-391342fc1f6so878239f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Mar 2025 10:48:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXxsKczGekvYrSxZokPhy4Lka+/TGn37b6WfDnQUlFGQ4Upd//hRt1iUThravstYfPjiS4++RcY4Ng=@googlegroups.com
X-Gm-Gg: ASbGnctggBfXYH/Z0T8EdsbO2MbiUwgLw1/EXpELKCjfPMsmt+wW6gzov+6UYpTB8Vm
	dE5MbxEhBxG+pbd6ZwC8FHRQ5He5f56GLlP9o+UgTYIr+DLsAryZgHyNA1vTgWNZgpRzbcCaEbq
	6FuMa9XePM6rYM/FONw9+varf+3ks9m87InOjhPA==
X-Received: by 2002:a05:6000:178c:b0:391:47f2:8d90 with SMTP id
 ffacd0b85a97d-3997f9017e3mr432989f8f.20.1742492890311; Thu, 20 Mar 2025
 10:48:10 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <383482f87ad4f68690021e0cc75df8143b6babe2.1739866028.git.maciej.wieczor-retman@intel.com>
 <CAPAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw@mail.gmail.com>
In-Reply-To: <CAPAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 20 Mar 2025 18:47:59 +0100
X-Gm-Features: AQ5f1JqHDM1qyWMQ9k-CyIbid1-RFpNXLnQroNsDKT1dsMHC48onaeej4RSJngs
Message-ID: <CA+fCnZdZpiu+guJjE20f8kwzwoPkx4X=JveQpeU38USEvFyZ7g@mail.gmail.com>
Subject: Re: [PATCH v2 09/14] mm: Pcpu chunk address tag reset
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kees@kernel.org, 
	julian.stecklina@cyberus-technology.de, kevinloughlin@google.com, 
	peterz@infradead.org, tglx@linutronix.de, justinstitt@google.com, 
	catalin.marinas@arm.com, wangkefeng.wang@huawei.com, bhe@redhat.com, 
	kirill.shutemov@linux.intel.com, will@kernel.org, ardb@kernel.org, 
	jason.andryuk@amd.com, dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	ndesaulniers@google.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lT1+xF+U;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Mar 20, 2025 at 6:40=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
> On Tue, Feb 18, 2025 at 9:19=E2=80=AFAM Maciej Wieczor-Retman
> <maciej.wieczor-retman@intel.com> wrote:
> >
> > The problem presented here is related to NUMA systems and tag-based
> > KASAN mode. Getting to it can be explained in the following points:
> >
> >         1. A new chunk is created with pcpu_create_chunk() and
> >            vm_structs are allocated. On systems with one NUMA node only
> >            one is allocated, but with more NUMA nodes at least a second
> >            one will be allocated too.
> >
> >         2. chunk->base_addr is assigned the modified value of
> >            vms[0]->addr and thus inherits the tag of this allocated
> >            structure.
> >
> >         3. In pcpu_alloc() for each possible cpu pcpu_chunk_addr() is
> >            executed which calculates per cpu pointers that correspond t=
o
> >            the vms structure addresses. The calculations are based on
> >            adding an offset from a table to chunk->base_addr.
> >
> > Here the problem presents itself since for addresses based on vms[1] an=
d
> > up, the tag will be different than the ones based on vms[0] (base_addr)=
.
> > The tag mismatch happens and an error is reported.
> >
> > Reset the base_addr tag, since it will disable tag checks for pointers
> > derived arithmetically from base_addr that would inherit its tag.
> >
> > Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> > ---
> >  mm/percpu-vm.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/mm/percpu-vm.c b/mm/percpu-vm.c
> > index cd69caf6aa8d..e13750d804f7 100644
> > --- a/mm/percpu-vm.c
> > +++ b/mm/percpu-vm.c
> > @@ -347,7 +347,7 @@ static struct pcpu_chunk *pcpu_create_chunk(gfp_t g=
fp)
> >         }
> >
> >         chunk->data =3D vms;
> > -       chunk->base_addr =3D vms[0]->addr - pcpu_group_offsets[0];
> > +       chunk->base_addr =3D kasan_reset_tag(vms[0]->addr) - pcpu_group=
_offsets[0];
>
> This looks like a generic tags mode bug. I mean that arm64 is also
> affected by this.
> I assume it just wasn't noticed before because arm64 with multiple
> NUMAs are much less common.
>
> With this change tag-mode KASAN won't be able to catch bugus accesses
> to pcpu areas.
> I'm thinking it would be better to fix this on the pcpu_get_vm_areas()
> area side by replacing
> this
>     for (area =3D 0; area < nr_vms; area++)
>         vms[area]->addr =3D kasan_unpoison_vmalloc(vms[area]->addr,
>                                              vms[area]->size,
> KASAN_VMALLOC_PROT_NORMAL);
>
> with something like
>     kasan_unpoison_vmap_areas(vms, nr_vms);
> which will unpoison all areas using the same tag.
>
> Thoughts?

Just a side note: KASAN doesn't have proper handling of the percpu
areas anyway, I even had to remove a related test; see [1] and [2]. So
I think for now we can go with the simplest/consistent solution that
prevents false-positives, whichever that solution is.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=3D215019
[2] https://bugzilla.kernel.org/show_bug.cgi?id=3D215758

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdZpiu%2BguJjE20f8kwzwoPkx4X%3DJveQpeU38USEvFyZ7g%40mail.gmail.com.
