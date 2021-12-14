Return-Path: <kasan-dev+bncBDDL3KWR4EBRBP7A4OGQMGQENJDIYHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id C2F2A474BE1
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 20:28:00 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id 7-20020a6b0107000000b005ed196a2546sf18685527iob.11
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 11:28:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639510079; cv=pass;
        d=google.com; s=arc-20160816;
        b=MHD5eI+M+Zb8UsF+WIpmf5gKYQXYbPQozFFCX4un4zex8wP668knFdVifghuBgqjQ9
         GPZ5lSSaK6sO0Q7EtmWiLrTInN2p5LvPifAmJ8N273IBwDeuXYHJWaRHwZRVkqfJK3nf
         TDvDFJShh62+UTvmBPJnOhO9aiobVZYDz4tkqha/aR0NZOcStA4XRA5LWYs7yqGKKOx/
         SgREw15n1tabWJiiHcdCBNTa+z8hXE6vwlXKznHTC/C8l6PgBSUTR5uXXsQPDD1KWWt2
         rouc6acNeDYndj6+wi49mkwhKdQyNNcX+Q9aPo8fQS07Gk2k4Chs5K4udcxbBKQDTSja
         2yCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/iPyLFYV5vJff1gelmIqzy3jQvzLWgTca051vJ31FNA=;
        b=PhZuqIdnvN3jaecRoSXb5dZdZ9sWuix2vYtxzGGIIJJ1L8+bD+CRq3U4atYItaz5Ao
         PsmDSI5iNaZHGnb5BP5UqWVx8v/Z0M6HJW3TsoE8B9Fqese/RE3HBRq1EZREAlZjjh6Y
         Em8zNhBKVbUWJ4sw5XwN/9IXnGuPJaQ8r3ZiTBtEI8XPn+Ehfa9BQRC2+8Ws043CtVQH
         dJEXLu7UOJtsFGCmzGrxL3tRYUFe9ucDlg33BFkk8EqFd8aohxBK8fSYpPrsCGtMPvsv
         ommauBRnZbLeKf94vc5d9j0/pjTXyPSFGV0ZUX3EbFWfJXSqQrwxmHiEwZ2rCpgtKmIr
         v+VA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/iPyLFYV5vJff1gelmIqzy3jQvzLWgTca051vJ31FNA=;
        b=QSlQ6Z+or9NA5WzA+D5X3LyQyKDSwReQvRTfdsSyfcdLoiCGH65wxIvpkmPkEXjV79
         KIyryyyMyGKL2yOphPIR48wYOMKkqD4NMaNQEbsEPTAPSny8o8DZRq007kQJ62YoRYNx
         XJyadRdKG1azxJWblEuPY6tUeRr/sPue8AVnVWz/jKSLEYqlh43eg8gpvNWF/L//PFyd
         egHOeDaJTULgqsuYbTEG1NWc5GqUoVKwq3z8yJvhQadDnt2uzTDsCkV4MgNKF397JzzA
         29HMYKvvaYgCMiSC0d3iWJkhbmqZdB3UFbqL7vZXjy5rPi+YQRK6QcPrpId93hMhQgWn
         2RGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/iPyLFYV5vJff1gelmIqzy3jQvzLWgTca051vJ31FNA=;
        b=TN7yewCgrPyntu8rzaja7uBrwuYUaI1YT8Nljutp/nvqQXFXiNwQ2/nlt9uWsU1wia
         K4sPy/tgZO1zVDehyxlDR+ybOlIUkFsEYDoTQLVNwAHRbJbggkvF7vAsG3PclauL9HkV
         yfCRvMgxMLC7eVyfVA1PBbqfvj+7ll49NUeHqXEVDBGa/Gc/CP/PfqKm4+iYC+FQohKc
         42mqiN5baG7aKEvDhUTJjpXy/YJH7O7nN73C6RsOfchtDDv04MEUZZgL1OyA1g3zKWW5
         KXz/do59tQ74dXjY9nM7uJ7WRn53H+qi+DGaBjNIfErg+YsyZQtqYAmDeZESv/LbQZMb
         q3pQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zYuCy8wRku2wsuXw/DFdZh/MzYs+t8y25kjp5Ii/GY1FwpoZY
	IKsqPEGTkf0vZKIgTvV/BDY=
X-Google-Smtp-Source: ABdhPJxSonk0XbejMepNPGUtfjKETUg2jMQgK2nnGbLxQX5xkUq7N/mLs/sHvTy7K9iU4BtpE00tqA==
X-Received: by 2002:a05:6638:2651:: with SMTP id n17mr4024052jat.328.1639510079192;
        Tue, 14 Dec 2021 11:27:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:411b:: with SMTP id ay27ls3522398jab.10.gmail; Tue,
 14 Dec 2021 11:27:58 -0800 (PST)
X-Received: by 2002:a05:6638:45a:: with SMTP id r26mr4006664jap.791.1639510078810;
        Tue, 14 Dec 2021 11:27:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639510078; cv=none;
        d=google.com; s=arc-20160816;
        b=f1o7kAxqqkqtfZulQUFPc2nyNEiiyvmgSDow+8MjEeTR25TjFYMTxXvTMXqJPUeXT4
         I1fsvdhA+gOiI5YSNWMQ9jOvQOM7JstxANGLh3Taz5XiZ8Cv7J7bty2YiQsYWc4+503l
         6mQUnEn5CvQouDvsiLDE3BJ8iL90WfcCvmJzc8YKWsMmCJwQAS4tBeX8PdA7BHYET7aT
         GAtn7QSl0Y1Fh5l6Xk/O7cDNU2zkpFJG3cVZ02d+tCIs+NyL029a5vsS2QmZ1/xzkxc0
         i6lpJtCciapOJiAkbcaRxMhC2+7CYgcDBnZycaNSrp/ITrwJ6g5kgrVSwAWgGrsE3uMu
         2w7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=HGjfbGesUCf3SzJM1BZH87BMaHmjCvPpotzjfn2t3qg=;
        b=jeSbctsjQJWQODdx/1CDDtNz+juiyJ3BoBCc+aScejrLHuqk9lOzsxhSLsykfLhC7W
         gPFsRO8U4YTXRUJB4X9jvEljio9j2J1SNnVIQpjq01avNYonAqq+L50Eyj5v39NK5ejQ
         RUVFdnMgDGGD+6vGDrGNZvvghagjvhUEjTIpsnxwGCqD5QYppvNmoe1r7Ij7YExowcNa
         T3NBdNR8S6KSBaRnIGomYZFIEki0W01s8zG2RC7GdMYpPd8wFS6Hr5MUBIG1EhJHn4jS
         BpkuuacmWx7QZvkvgmuwQGOq+dGAOwxR6k7dCuR9GKhazoPnLeGPd1JCS/FWCI4xAgtn
         wfhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-2faa6b53fcbsi130817173.13.2021.12.14.11.27.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 11:27:58 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 79707616BD;
	Tue, 14 Dec 2021 19:27:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 174C0C34604;
	Tue, 14 Dec 2021 19:27:54 +0000 (UTC)
Date: Tue, 14 Dec 2021 19:27:51 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v3 25/38] kasan, vmalloc, arm64: mark vmalloc mappings
 as pgprot_tagged
Message-ID: <YbjwN0YlDV4hm3x6@arm.com>
References: <cover.1639432170.git.andreyknvl@google.com>
 <d91e501aef74c5bb924cae90b469ff0dc1d56488.1639432170.git.andreyknvl@google.com>
 <YbjQNdst07JqbG0j@arm.com>
 <CA+fCnZftd93rARJ+xpUApimkgTsN0RRmiSVnrUMkCvdSu4-tcA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZftd93rARJ+xpUApimkgTsN0RRmiSVnrUMkCvdSu4-tcA@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Dec 14, 2021 at 07:27:09PM +0100, Andrey Konovalov wrote:
> On Tue, Dec 14, 2021 at 6:11 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > On Mon, Dec 13, 2021 at 10:54:21PM +0100, andrey.konovalov@linux.dev wrote:
> > > diff --git a/arch/arm64/include/asm/vmalloc.h b/arch/arm64/include/asm/vmalloc.h
> > > index b9185503feae..3d35adf365bf 100644
> > > --- a/arch/arm64/include/asm/vmalloc.h
> > > +++ b/arch/arm64/include/asm/vmalloc.h
> > > @@ -25,4 +25,14 @@ static inline bool arch_vmap_pmd_supported(pgprot_t prot)
> > >
> > >  #endif
> > >
> > > +#define arch_vmalloc_pgprot_modify arch_vmalloc_pgprot_modify
> > > +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> > > +{
> > > +     if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
> > > +                     (pgprot_val(prot) == pgprot_val(PAGE_KERNEL)))
> > > +             prot = pgprot_tagged(prot);
> > > +
> > > +     return prot;
> > > +}
> > > +
> > >  #endif /* _ASM_ARM64_VMALLOC_H */
> > > diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> > > index 28becb10d013..760caeedd749 100644
> > > --- a/include/linux/vmalloc.h
> > > +++ b/include/linux/vmalloc.h
> > > @@ -115,6 +115,13 @@ static inline int arch_vmap_pte_supported_shift(unsigned long size)
> > >  }
> > >  #endif
> > >
> > > +#ifndef arch_vmalloc_pgprot_modify
> > > +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> > > +{
> > > +     return prot;
> > > +}
> > > +#endif
> > > +
> > >  /*
> > >   *   Highlevel APIs for driver use
> > >   */
> > > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > > index 837ed355bfc6..58bd2f7f86d7 100644
> > > --- a/mm/vmalloc.c
> > > +++ b/mm/vmalloc.c
> > > @@ -3060,6 +3060,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
> > >               return NULL;
> > >       }
> > >
> > > +     prot = arch_vmalloc_pgprot_modify(prot);
> > > +
> > >       if (vmap_allow_huge && !(vm_flags & VM_NO_HUGE_VMAP)) {
> > >               unsigned long size_per_node;
> >
> > I wonder whether we could fix the prot bits in the caller instead and we
> > won't need to worry about the exec or the module_alloc() case. Something
> > like:
> >
> > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > index d2a00ad4e1dd..4e8c61255b92 100644
> > --- a/mm/vmalloc.c
> > +++ b/mm/vmalloc.c
> > @@ -3112,7 +3112,7 @@ void *__vmalloc_node(unsigned long size, unsigned long align,
> >                             gfp_t gfp_mask, int node, const void *caller)
> >  {
> >         return __vmalloc_node_range(size, align, VMALLOC_START, VMALLOC_END,
> > -                               gfp_mask, PAGE_KERNEL, 0, node, caller);
> > +                       gfp_mask, pgprot_hwasan(PAGE_KERNEL), 0, node, caller);
> >  }
> >  /*
> >   * This is only for performance analysis of vmalloc and stress purpose.
> > @@ -3161,7 +3161,7 @@ EXPORT_SYMBOL(vmalloc);
> >  void *vmalloc_no_huge(unsigned long size)
> >  {
> >         return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
> > -                                   GFP_KERNEL, PAGE_KERNEL, VM_NO_HUGE_VMAP,
> > +                                   GFP_KERNEL, pgprot_hwasan(PAGE_KERNEL), VM_NO_HUGE_VMAP,
> >                                     NUMA_NO_NODE, __builtin_return_address(0));
> >  }
> >  EXPORT_SYMBOL(vmalloc_no_huge);
> >
> > with pgprot_hwasan() defined to pgprot_tagged() only if KASAN_HW_TAGS is
> > enabled.
> 
> And also change kasan_unpoison_vmalloc() to tag only if
> pgprot_tagged() has been applied, I assume.
> 
> Hm. Then __vmalloc_node_range() callers will never get tagged memory
> unless requested. I suppose that's OK, most of them untag the pointer
> anyway.
> 
> But this won't work for SW_TAGS mode, which is also affected by the
> exec issue and needs those kasan_reset_tag()s in module_alloc()/BPF.
> We could invent some virtual protection bit for it and reuse
> pgprot_hwasan(). Not sure if this would be acceptable.

Ah, a pgprot_hwasan() for the sw tags is probably not acceptable as this
requires an unnecessary pte bit. An alternative could be a GFP flag that
gets passed only from __vmalloc_node() etc.

Otherwise your original approach works as well.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbjwN0YlDV4hm3x6%40arm.com.
