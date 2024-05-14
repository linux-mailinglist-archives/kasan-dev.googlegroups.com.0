Return-Path: <kasan-dev+bncBD4IBNO3YAGRBSO6RSZAMGQEHNQYTNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 78B1B8C4EA0
	for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 11:30:50 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-43e1a913c49sf1116951cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 02:30:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715679049; cv=pass;
        d=google.com; s=arc-20160816;
        b=ut36FgUn0orYsbjxp1rKN5020KOBBNlgZ2UAcIXQogWLozZqlZ2BwDBV6s8tBA3wJe
         LiN0rqMjqFRyNuJtP3mprbIAZJ/8BSe0MCD/gvaraoyK8EabhXqT/M9cDcjnCJfSfWqV
         hpQl0ohB+cvFb990pWj5ebqva+Ks4hfadxrbT1CKe1hpudYO7xPADcJFsbYgiVI+iuwe
         7qGV7AdvDmgmNW8nc9GWl+d9FGkr9a6DHIetMsGf0OwqvB0exVmrjv2UWcCgUNf8f7Kg
         G4aX3jX233k3m+wsu9b0YN8gQDrb92q6eC9PfGlz6QLdbgmtUV8ab9c0JJzTtqyHUVqe
         jhxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=e+Y97qgDmekIR7hrGZQcYWmWxWjX2DA+Tear37bWqdc=;
        fh=E9wUwXQ3zTqCYracGr5obhczlkNHihiBb+mWI+zgBa4=;
        b=rWMVfo5YxPnc31uwFtmI3j7jDf7GlgIQVePKm/TUwjd303SSZTW1z77i115aMzjbbc
         m+9KwMtlI5talrRRxYl0sayVTE6O/RgzJAEc2VDoyqBj88rgqcHs8NfMcBiLqc2cCjHa
         cqWNh9QWJfM5yhqELk7m7GOTSlt48sgUox58G1ln0WsYg6LFMaNVoolPzVcFnll+JXgv
         l9cMQoheGbe+NBUaNI9VLMe3uj4LCHhWXgV3CCWxwSbVpcOpW8s2wfIX5JcUGtXNaEki
         wsbeM7osyqZdv+6JU+qykx/qpPsgOPzXQaHDDC/f2cSEAYtmP8dBwst0fZ07/hvjcqaU
         3XXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lDKaSR7X;
       spf=pass (google.com: domain of 21cnbao@gmail.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=21cnbao@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715679049; x=1716283849; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=e+Y97qgDmekIR7hrGZQcYWmWxWjX2DA+Tear37bWqdc=;
        b=PNYubEQQyToAEm9stmx3N3jwBKOeFONX9SPnPqCmkLzdekT1laXXVJmF+Gp+fasupQ
         SZk31Cz+ofvDF+M8PUhCetzBl/SXRiBbY1c0ce3feLYBA7jQls9gIznUKC0Q6QEE6kIl
         z1V4UCJfAH+SqykjhUwqSWVY+UWfLKXfVcMIgr5H8jrSM0V26/tz69Bmsm0bwZlX26yC
         fXI/05oEvGu787Tgujyaml0kgnmkpS5nGroCl3HE1eQr51n7vf5t+WT1ct3g0RBYSbQu
         7MnP+IoRG0garB09mK1zQ8VCHad4quc9fuyVxEzitN9NFWRZ9ImrR+wqGnFCBvBjI9+L
         cf9A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1715679049; x=1716283849; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=e+Y97qgDmekIR7hrGZQcYWmWxWjX2DA+Tear37bWqdc=;
        b=H1vZoCWDKIDQfs9cn/xKRfWMXhzqIXG+R+0c+Np7vXRCKxrkwt5Q+5nu7fe8oaVtB8
         97I8B5IgOk7Vti8ucCoJOWtOrK0LldRrimgtBa8RhXQUllIP7K9IJN/YwsLlWciN/7Fk
         Kty6+hbYlDvyUrIcwzOvrm5QW9ObXXgtvvlmrcroG8IFeToZNSbysYWfkp2y3MWurWEB
         dZvB5ct/ufO14oIkgGlsfh10lhlkxFKWvpKkGaI+2GyFA7E8NIotb+wd7PUpRUZr7EnB
         ddMB1bJILNxAtdZ4btdgwtU4ZZaqAyaYK1CH974BddwHj5+lsq9kWrsO0ysVDsB6Mvmz
         /svA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715679049; x=1716283849;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=e+Y97qgDmekIR7hrGZQcYWmWxWjX2DA+Tear37bWqdc=;
        b=ou2OZYy71cNcXDMQmSqhGX/xt/fsue/g8Pyqz4Gu9c9wsML27kbKn/CzmzsZtICopF
         OtP9B1yvIwYFYxTcNi3X38McvJqC7/nUBbfcHsmuntchPsg0O3KHlPvWeAkG+SV13Q1s
         8idy3pFSPs5mprCmisBwylmRvXx8djtaF4yBeCt9IqKklj4UX+Q6iNRXUYzkDEJy50wb
         OYzf+0jZqRS7fFn0KVul/leYQ0Kexw+U2mkA+bGkoDJPqtNN/FCfEuAJYIR3c+qRT8E9
         7sSquBDzG6T34spvO3v8edVHQd8OhglTmnryKsR1TbtvWNJ802Svg0e0xG5tFpHXYX3Q
         C9Sw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXntHqOPeABZOISEdwc5ThIDwFNvdhhKRb5LkRjm63IcrBAqAR/Hqi/1XB3zkXdx2ksP3mIcAmPbC+LlDdUZT/coOusENpMzw==
X-Gm-Message-State: AOJu0YyhCHqZgDfHkhsSEN5LklUAv35mFfPMktCDiNM64rf61FTNuPT1
	qaMzPbjbRzj1uWzEq2tNTKX51Kiy/NkTSd95Re+U0IhbtPnoZkbp
X-Google-Smtp-Source: AGHT+IHIlZCbXxmt0g5xjZdvIN1kjzXCRFJ/ePyAXQzAjR2fdCW+tUzsdsI6DvVfdJ07cqmpQAwA7Q==
X-Received: by 2002:a05:622a:1dcb:b0:43d:dfa2:216f with SMTP id d75a77b69052e-43e094d0189mr7084191cf.6.1715679049222;
        Tue, 14 May 2024 02:30:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:253:b0:43a:c471:8fae with SMTP id
 d75a77b69052e-43ded91760cls81276021cf.1.-pod-prod-09-us; Tue, 14 May 2024
 02:30:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUESS4S7tMXtk8+oIvGoUZ7+S9MB1wnzgGbQr+QR+CVWjdR3EPzBVz3yl+3c+M1A2tHe0+u9de9GbMrcUf7vWN8Hnk8nsNG8NgKAA==
X-Received: by 2002:a05:620a:a1a:b0:792:c478:3201 with SMTP id af79cd13be357-792c75975c2mr1327282985a.26.1715679048392;
        Tue, 14 May 2024 02:30:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715679048; cv=none;
        d=google.com; s=arc-20160816;
        b=Q3KPnrxe3z+2xXz3qtO6JF4wLYRooxcfEHyx5w+qyybKt58HDyTkqUL5tBARJjx0la
         lzG1Vp58VWbd4V54MGa3HhmRXAX5sxgov1BPSzjALp6Ne8Yl7UjP8h/7Q1iUzNQhHisw
         FD823Y7H4MaFFYZKf/FGG/o9NMI/4umePlOFMZReTp3PyjmuCCGdXBnyxTF/CzqPtV5A
         r8xdcDXCaF8dK/RRcQ2xwkgfqwEI2tIomRUkfEbW45oz6BE51yTt6JNBnkJsw3YPqJLr
         yJ1nl476fTftetq26vgdJCH2Mi5OliG0xzYAil4ViO9VQ9Y/fluK6dMj6LuSxO+gSgt9
         pBkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wdHFnHTcKzscSCgje4pLV0ENAixI1q19eindkQ9bbmI=;
        fh=zMvZjL7bvJd20Ji6h5DYNbRd9vRDMvDs7ueUHPu82Ao=;
        b=HCZUy8nUn6pJ8ECDQ2344smk6INfalWK2e91jx7glq5d5gKzszL3au7zNg8eZW+3iv
         8SB3fAPxKkjJS7TIcp0FdQpeImPy533v+5AmcG/NZM6//5ws05eJ39FGMCf0q2zBqjrb
         NJS/Qr+c3j8QhvuqTggioKxyeVP6H1wjjvo6mvYvyX0cbuJr3FluHGCsjguvQ2wCTwuG
         +MdCmQQhy4N8vqfT8pwtS/sqYH0LkqV3qLcI1GjdduzCfti1ofGJZtuazS9Rwj0zUre2
         CugTLxNL3yDHD1/Mpx5ajgBFWVSkIKTFnSieVLZk86f1LPenSVJCbuDE64gjXyy5gy1C
         hVTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lDKaSR7X;
       spf=pass (google.com: domain of 21cnbao@gmail.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=21cnbao@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vs1-xe2a.google.com (mail-vs1-xe2a.google.com. [2607:f8b0:4864:20::e2a])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-792bf340147si66499985a.7.2024.05.14.02.30.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 May 2024 02:30:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 21cnbao@gmail.com designates 2607:f8b0:4864:20::e2a as permitted sender) client-ip=2607:f8b0:4864:20::e2a;
Received: by mail-vs1-xe2a.google.com with SMTP id ada2fe7eead31-481ed99e0bfso378289137.2
        for <kasan-dev@googlegroups.com>; Tue, 14 May 2024 02:30:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXYaE/Ii0sUiRpT08HyER8Sz8N10B25zXF1rIW1GoRv6gd3Z+VmT7/fvGJyeO1L/ZTLwfT4KCIGGQvGyAbXmcSNZv4EcWuxI2MWBw==
X-Received: by 2002:a05:6102:2acc:b0:47e:f686:ccf with SMTP id
 ada2fe7eead31-48077e83663mr12661860137.23.1715679047234; Tue, 14 May 2024
 02:30:47 -0700 (PDT)
MIME-Version: 1.0
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
 <20240508191931.46060-2-alexghiti@rivosinc.com> <CAGsJ_4xayC4D4y0d7SPXxCvuW4-rJQUCa_-OUDSsOGm_HyPm1w@mail.gmail.com>
 <CAHVXubiOo3oe0=-qU2kBaFXebPJvmnc+-1UOPEHS2spcCeMzsw@mail.gmail.com>
In-Reply-To: <CAHVXubiOo3oe0=-qU2kBaFXebPJvmnc+-1UOPEHS2spcCeMzsw@mail.gmail.com>
From: Barry Song <21cnbao@gmail.com>
Date: Tue, 14 May 2024 21:30:36 +1200
Message-ID: <CAGsJ_4w_mOL5egHV9a3+0vcZV6ODvr=3KFXevedH19voSCHXwQ@mail.gmail.com>
Subject: Re: [PATCH 01/12] mm, arm64: Rename ARM64_CONTPTE to THP_CONTPTE
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Ryan Roberts <ryan.roberts@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Ard Biesheuvel <ardb@kernel.org>, Anup Patel <anup@brainfault.org>, 
	Atish Patra <atishp@atishpatra.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-riscv@lists.infradead.org, linux-efi@vger.kernel.org, 
	kvm@vger.kernel.org, kvm-riscv@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 21cnbao@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lDKaSR7X;       spf=pass
 (google.com: domain of 21cnbao@gmail.com designates 2607:f8b0:4864:20::e2a as
 permitted sender) smtp.mailfrom=21cnbao@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, May 14, 2024 at 1:09=E2=80=AFAM Alexandre Ghiti <alexghiti@rivosinc=
.com> wrote:
>
> Hi Barry,
>
> On Thu, May 9, 2024 at 2:46=E2=80=AFAM Barry Song <21cnbao@gmail.com> wro=
te:
> >
> > On Thu, May 9, 2024 at 7:20=E2=80=AFAM Alexandre Ghiti <alexghiti@rivos=
inc.com> wrote:
> > >
> > > The ARM64_CONTPTE config represents the capability to transparently u=
se
> > > contpte mappings for THP userspace mappings, which will be implemente=
d
> > > in the next commits for riscv, so make this config more generic and m=
ove
> > > it to mm.
> > >
> > > Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
> > > ---
> > >  arch/arm64/Kconfig               | 9 ---------
> > >  arch/arm64/include/asm/pgtable.h | 6 +++---
> > >  arch/arm64/mm/Makefile           | 2 +-
> > >  mm/Kconfig                       | 9 +++++++++
> > >  4 files changed, 13 insertions(+), 13 deletions(-)
> > >
> > > diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> > > index ac2f6d906cc3..9d823015b4e5 100644
> > > --- a/arch/arm64/Kconfig
> > > +++ b/arch/arm64/Kconfig
> > > @@ -2227,15 +2227,6 @@ config UNWIND_PATCH_PAC_INTO_SCS
> > >         select UNWIND_TABLES
> > >         select DYNAMIC_SCS
> > >
> > > -config ARM64_CONTPTE
> > > -       bool "Contiguous PTE mappings for user memory" if EXPERT
> > > -       depends on TRANSPARENT_HUGEPAGE
> > > -       default y
> > > -       help
> > > -         When enabled, user mappings are configured using the PTE co=
ntiguous
> > > -         bit, for any mappings that meet the size and alignment requ=
irements.
> > > -         This reduces TLB pressure and improves performance.
> > > -
> > >  endmenu # "Kernel Features"
> > >
> > >  menu "Boot options"
> > > diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/as=
m/pgtable.h
> > > index 7c2938cb70b9..1758ce71fae9 100644
> > > --- a/arch/arm64/include/asm/pgtable.h
> > > +++ b/arch/arm64/include/asm/pgtable.h
> > > @@ -1369,7 +1369,7 @@ extern void ptep_modify_prot_commit(struct vm_a=
rea_struct *vma,
> > >                                     unsigned long addr, pte_t *ptep,
> > >                                     pte_t old_pte, pte_t new_pte);
> > >
> > > -#ifdef CONFIG_ARM64_CONTPTE
> > > +#ifdef CONFIG_THP_CONTPTE
> >
> > Is it necessarily THP? can't be hugetlb or others? I feel THP_CONTPTE
> > isn't a good name.
>
> This does not target hugetlbfs (see my other patchset for that here
> https://lore.kernel.org/linux-riscv/7504a525-8211-48b3-becb-a6e838c1b42e@=
arm.com/T/#m57d273d680fc531b3aa1074e6f8558a52ba5badc).
>
> What could be "others" here?


I acknowledge that the current focus is on Transparent Huge Pages. However,
many aspects of CONT-PTE appear to be applicable to the mm-core in general.
For example,

/*
 * The below functions constitute the public API that arm64 presents to the
 * core-mm to manipulate PTE entries within their page tables (or at least =
this
 * is the subset of the API that arm64 needs to implement). These public
 * versions will automatically and transparently apply the contiguous bit w=
here
 * it makes sense to do so. Therefore any users that are contig-aware (e.g.
 * hugetlb, kernel mapper) should NOT use these APIs, but instead use the
 * private versions, which are prefixed with double underscore. All of thes=
e
 * APIs except for ptep_get_lockless() are expected to be called with the P=
TL
 * held. Although the contiguous bit is considered private to the
 * implementation, it is deliberately allowed to leak through the getters (=
e.g.
 * ptep_get()), back to core code. This is required so that pte_leaf_size()=
 can
 * provide an accurate size for perf_get_pgtable_size(). But this leakage m=
eans
 * its possible a pte will be passed to a setter with the contiguous bit se=
t, so
 * we explicitly clear the contiguous bit in those cases to prevent acciden=
tally
 * setting it in the pgtable.
 */

#define ptep_get ptep_get
static inline pte_t ptep_get(pte_t *ptep)
{
        pte_t pte =3D __ptep_get(ptep);

        if (likely(!pte_valid_cont(pte)))
                return pte;

        return contpte_ptep_get(ptep, pte);
}

Could it possibly be given a more generic name such as "PGTABLE_CONTPTE"?

>
> Thanks for your comment,
>
> Alex
>
> >
> > >
> > >  /*
> > >   * The contpte APIs are used to transparently manage the contiguous =
bit in ptes
> > > @@ -1622,7 +1622,7 @@ static inline int ptep_set_access_flags(struct =
vm_area_struct *vma,
> > >         return contpte_ptep_set_access_flags(vma, addr, ptep, entry, =
dirty);
> > >  }
> > >
> > > -#else /* CONFIG_ARM64_CONTPTE */
> > > +#else /* CONFIG_THP_CONTPTE */
> > >
> > >  #define ptep_get                               __ptep_get
> > >  #define set_pte                                        __set_pte
> > > @@ -1642,7 +1642,7 @@ static inline int ptep_set_access_flags(struct =
vm_area_struct *vma,
> > >  #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
> > >  #define ptep_set_access_flags                  __ptep_set_access_fla=
gs
> > >
> > > -#endif /* CONFIG_ARM64_CONTPTE */
> > > +#endif /* CONFIG_THP_CONTPTE */
> > >
> > >  int find_num_contig(struct mm_struct *mm, unsigned long addr,
> > >                     pte_t *ptep, size_t *pgsize);
> > > diff --git a/arch/arm64/mm/Makefile b/arch/arm64/mm/Makefile
> > > index 60454256945b..52a1b2082627 100644
> > > --- a/arch/arm64/mm/Makefile
> > > +++ b/arch/arm64/mm/Makefile
> > > @@ -3,7 +3,7 @@ obj-y                           :=3D dma-mapping.o ex=
table.o fault.o init.o \
> > >                                    cache.o copypage.o flush.o \
> > >                                    ioremap.o mmap.o pgd.o mmu.o \
> > >                                    context.o proc.o pageattr.o fixmap=
.o
> > > -obj-$(CONFIG_ARM64_CONTPTE)    +=3D contpte.o
> > > +obj-$(CONFIG_THP_CONTPTE)      +=3D contpte.o
> > >  obj-$(CONFIG_HUGETLB_PAGE)     +=3D hugetlbpage.o
> > >  obj-$(CONFIG_PTDUMP_CORE)      +=3D ptdump.o
> > >  obj-$(CONFIG_PTDUMP_DEBUGFS)   +=3D ptdump_debugfs.o
> > > diff --git a/mm/Kconfig b/mm/Kconfig
> > > index c325003d6552..fd4de221a1c6 100644
> > > --- a/mm/Kconfig
> > > +++ b/mm/Kconfig
> > > @@ -984,6 +984,15 @@ config ARCH_HAS_CACHE_LINE_SIZE
> > >  config ARCH_HAS_CONTPTE
> > >         bool
> > >
> > > +config THP_CONTPTE
> > > +       bool "Contiguous PTE mappings for user memory" if EXPERT
> > > +       depends on ARCH_HAS_CONTPTE && TRANSPARENT_HUGEPAGE
> > > +       default y
> > > +       help
> > > +         When enabled, user mappings are configured using the PTE co=
ntiguous
> > > +         bit, for any mappings that meet the size and alignment requ=
irements.
> > > +         This reduces TLB pressure and improves performance.
> > > +
> > >  config ARCH_HAS_CURRENT_STACK_POINTER
> > >         bool
> > >         help
> > > --
> > > 2.39.2
> >
Thanks
Barry

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAGsJ_4w_mOL5egHV9a3%2B0vcZV6ODvr%3D3KFXevedH19voSCHXwQ%40mail.gm=
ail.com.
