Return-Path: <kasan-dev+bncBC7OD3FKWUERBPNSQHDAMGQELYZQ5IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id BB180B502EB
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 18:43:56 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-45dd66e1971sf41662665e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 09:43:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757436223; cv=pass;
        d=google.com; s=arc-20240605;
        b=A2SkDNPmM/T6gDUOI01poKuWUpzmrOqCLwCMT2as5Aw43WP3nI7GZdkxw2hANKDYh5
         lTqwMtoD/no1LVsFgJ/94PNy8Bu+Rz1qJSggS4lLChgFvwhjA6MIHPy+3s18hjUGdWiA
         MfbF+kyqdJbSR4w84usxidPywAon/l7SsR+9nCVNR0cpbcula/XhBpYtDWo7DqVw816V
         d4wbo5NvQ7Bie8A2PlnpAKRz6ktNuVzabTjY8IFTyh1cuh3vO1peCL0V1sO2yiP9OqEQ
         8Fkfk5/mm5ECviW0b6ROsvcKlc4sIjElhQayE7D/Lgre1SyUJfzCd+HntwITTnolJTF0
         KhFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JMBU9gwMp0xuFw67H3DS7gkN6YGUUsPxCUv4I/vGF3s=;
        fh=YLb/yiremoK0dic4rSdrkMegabMyTAbmsBQaX+9sNao=;
        b=NfBcZ/OCLzFg506x4mii3EjX1mCiffBHLy5lbQIA9gJBkOaRiPeJQmAn+k1G6uYhco
         /ple1r5Y3wuiYKjUKfogTZh77Yzx5PLO6vymlJC5DGbfNU9JliRqWgnklBC1HH2avmTQ
         YPVaQPRsZ92iJv3V4UUXTBTQiA1mt6x/S5EBYvgslSRDRIkF2GxZ0nBwrQQgGvCxEpNn
         QbN6uYT5mRM8BZg8iZvj14YD+zele8V3/+O34zC8YzaXrUPCwRGWdFOMw+ed000Cu4gG
         B+BNSW/G//efXdyvjAASLsumiEdYiRNSIu7q01ErzLPWUl0d+XNtWlvvdh0v87afu7/S
         Hk1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uCquChGZ;
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757436223; x=1758041023; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JMBU9gwMp0xuFw67H3DS7gkN6YGUUsPxCUv4I/vGF3s=;
        b=LXCqI7FVj48nP7o5KOvPWRi6AGfgrE+I8aLLlqs7Mr89NhLpn1xceJWpaw0JHBrgVl
         0AGePZHp6CEvEInrpWcOnV6AUIz27rNg4W9OQYJCQLLbwyqhQ5CzEGxe+1OB817dtq/Y
         1ffUTeH8jO1PdHp0N0GOnOhgo5oxTpTb93l/HFkOWbm2RcsKbS+RB8eHOi77oHHdxl6G
         2yct7h3tWw0QgyrEgKfejcH+sl//0nErKuliVNFxpz8m/BrvZ5v2Hiby/XhcbBSm6lQQ
         ffGpo6cMG0gHK86lCt//oCR9w/W1/4T5KADbOfAIGvO3MAcdfA4SL9l+YrtEqhDGFOAH
         HQDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757436223; x=1758041023;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JMBU9gwMp0xuFw67H3DS7gkN6YGUUsPxCUv4I/vGF3s=;
        b=fHNpyMj7fnzGl0CPsXfsnEabc1K1qFydyDysk5+Cxgv3y9huG3YHLOoLKS8CpzLIvB
         qqgRuGif1WBPb+Q6ZisSS5QQ1m8HfCH1gvk+LW7DI7WsBr4jTvEkZP7tE4xFVUtYGIvz
         2HbZ0CwmYGyAudLs8lBj2cEE58ApoeX3q9q9w8jCiHEGIYxZ+t3EMapIVOBTzx2KwI9q
         UUOp4J44mAEXZpuW4mC6KgONKART7P4S8/fCnA7ttfRXIPAq71jYsRz9obIZgQlu77Y9
         SZ7Bs3XxQKIzVQI4JRii4OsjTSJRqqbmqnjuAovi3GGUTb4VPCYivzp7vGSrinNYenq8
         CiTw==
X-Forwarded-Encrypted: i=2; AJvYcCUhui/d1hJyqSX72lzyGYrMFrcRPZuU4ylnZGk4UPyhZJLQVPc0U5Ee5B++O4eGziMtILQa/w==@lfdr.de
X-Gm-Message-State: AOJu0YzMJTnbBSCkXMznYih3X2nw/Vrvwsjih/5u4Sh5+FEpHsJFV2H6
	YZai6Xq8FEKzTAl5bSvlIyfGsjJC9rO4THGZz+qn/CdiaYSluoWoMYUC
X-Google-Smtp-Source: AGHT+IFl9/G31mWGM3ixacDbYwQ0cumQ7vxF+D3AgQfs4Gnm2g4edE8+qmMhmDitMkgXqGI3vYKQgA==
X-Received: by 2002:a05:600c:681:b0:45c:b5f7:c6e7 with SMTP id 5b1f17b1804b1-45dde66c67fmr69025585e9.0.1757436222520;
        Tue, 09 Sep 2025 09:43:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfNJqGO40hXTSIxqgGy1dQtzWY7rVJKvXCPQScJNKBQcw==
Received: by 2002:a05:600c:44c6:b0:459:e761:bc87 with SMTP id
 5b1f17b1804b1-45dd80726e3ls15197615e9.0.-pod-prod-02-eu; Tue, 09 Sep 2025
 09:43:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWV/7v7sEJ4LKWpCO5pkOU/JENVSi8ieTqq0guLHWwpQl+eiereBdROgdQL0Oy127b35fQUCrluCoU=@googlegroups.com
X-Received: by 2002:a05:600c:4ed0:b0:45d:e28c:8741 with SMTP id 5b1f17b1804b1-45de712289emr60791595e9.29.1757436219649;
        Tue, 09 Sep 2025 09:43:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757436219; cv=none;
        d=google.com; s=arc-20240605;
        b=Cib9EdsSOmUmjFEvZ+gQmTIZdXa+7tmWIAZfr2oh0RxEOOV8qo19JVZhZpFFtg9QIi
         wDzOUr2KgtOpCdM2GC2A2GTL2K5SMci5lUcOREjkXHi031/vFBL1di5gR4AwHT083T2K
         ZYTQE3XWnRoZiZHZ9vCOa1tIrz6QdFZJmip79BPe8NTmoUZCwQq/91XNJtOe3z1ei7jf
         nLf0WFuTs2D7GRgaD69ghAW+0JfJZlAx9PCNmz53S9ISsSwjWZKuivoBbPVhpS4sWkk7
         C9FBTRYZVLLomJt7KZEIvlXndt8DxQMd7FutI3iwG+jsOEnvVfuXmAPeRom/eaxXIooj
         /eNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=X9zR1ns6r4tli6kgpMkZXeVyHg9onE4yZmroH/q5x2E=;
        fh=sOlwzVtLf9qFFEhsr5SDI0FQ4k+EV4DEchhjLN6tMY8=;
        b=BLtqNssAbvTZ0HK8OTPI+CWQHAuKSJFyXUUyNd8tHZ9wFmk0EUCDFhObLj+uCkGPNb
         GhvZO2WRhof6CA27ua7Mur8CrY62PG18HuHj1uJrRcKENukqRy0X/awtaEJ6qawYt/ST
         v0dAEWGTKWJpT8vMfxpIw80Ol+qyuB2HdATe/saxwfEm4s48/bPuw7PEiEc9hh1HTPYU
         YdVfvrHfdzE1oN8d6shoUJ5/g9HJnYlWqYtprQVrXJq+MT7JUhavon/VFlL4sF6H0kQl
         qh6BmJp68onN/aItj+SJQEVUOsXdLSKBrYhu/KQGP4EOmigp2vr3lrv8eAq15fk4Ekqm
         CIPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uCquChGZ;
       spf=pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45df14e7c04si495085e9.1.2025.09.09.09.43.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 09:43:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id 4fb4d7f45d1cf-61d14448c22so35a12.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 09:43:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXWcmvpxEE6RL7/033zisUws9fl8w+uMa2YnqpUGyIgihBAaxetpRIymC8MmrD1XI/JqtIndtecnpU=@googlegroups.com
X-Gm-Gg: ASbGncv79thXRfJ2mWrsOtgfeTaHc0FimxyyIL/qwD2TMW19t4L9AyQufNIzEnwstSD
	AxGr8n/7WQBIwjTkGd8jOORNUU/Yv9RxoLI0OEfAk8oVlLtsLodAjvI32RmRi4CTfZG4Ok0Opmv
	XAF6rcivT+/9PfLZa2HLsIVnaNa5tpqCYCM7qfPFl0l8a9z65iMmvVME6DfvnHQA0k/5ri8cdCu
	jnwzrN6iGISJSyEfG/NT4GgnB5/WH+ADZHtBhY5+d0CV+tiSEZqo8I=
X-Received: by 2002:a05:6402:4024:b0:61c:c9e3:18f9 with SMTP id
 4fb4d7f45d1cf-623d2c4dda5mr356673a12.3.1757436218862; Tue, 09 Sep 2025
 09:43:38 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <ea1a5ab9fff7330b69f0b97c123ec95308818c98.1757329751.git.lorenzo.stoakes@oracle.com>
 <ad69e837-b5c7-4e2d-a268-c63c9b4095cf@redhat.com> <c04357f9-795e-4a5d-b762-f140e3d413d8@lucifer.local>
 <e882bb41-f112-4ec3-a611-0b7fcf51d105@redhat.com> <8994a0f1-1217-49e6-a0db-54ddb5ab8830@lucifer.local>
In-Reply-To: <8994a0f1-1217-49e6-a0db-54ddb5ab8830@lucifer.local>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Sep 2025 09:43:25 -0700
X-Gm-Features: AS18NWB56jIrhZDM4c-qSVZLOkH6X6dA_iJA_IjgEAuDFh14nG2Q8lK0Ov1ujjQ
Message-ID: <CAJuCfpEeUkta7UfN2qzSxHuohHnm7qXe=rEzVjfynhmn2WF0fA@mail.gmail.com>
Subject: Re: [PATCH 06/16] mm: introduce the f_op->mmap_complete, mmap_abort hooks
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: David Hildenbrand <david@redhat.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>, 
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Heiko Carstens <hca@linux.ibm.com>, 
	Vasily Gorbik <gor@linux.ibm.com>, Alexander Gordeev <agordeev@linux.ibm.com>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Sven Schnelle <svens@linux.ibm.com>, 
	"David S . Miller" <davem@davemloft.net>, Andreas Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Dan Williams <dan.j.williams@intel.com>, 
	Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>, 
	Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>, 
	Oscar Salvador <osalvador@suse.de>, 
	Konstantin Komarov <almaz.alexandrovich@paragon-software.com>, Baoquan He <bhe@redhat.com>, 
	Vivek Goyal <vgoyal@redhat.com>, Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>, 
	Reinette Chatre <reinette.chatre@intel.com>, Dave Martin <Dave.Martin@arm.com>, 
	James Morse <james.morse@arm.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, 
	"Liam R . Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Mike Rapoport <rppt@kernel.org>, Michal Hocko <mhocko@suse.com>, Hugh Dickins <hughd@google.com>, 
	Baolin Wang <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>, 
	Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org, 
	linux-mips@vger.kernel.org, linux-s390@vger.kernel.org, 
	sparclinux@vger.kernel.org, nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, 
	linux-mm@kvack.org, ntfs3@lists.linux.dev, kexec@lists.infradead.org, 
	kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=uCquChGZ;       spf=pass
 (google.com: domain of surenb@google.com designates 2a00:1450:4864:20::536 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Sep 9, 2025 at 2:37=E2=80=AFAM Lorenzo Stoakes
<lorenzo.stoakes@oracle.com> wrote:
>
> On Tue, Sep 09, 2025 at 11:26:21AM +0200, David Hildenbrand wrote:
> > > >
> > > > In particular, the mmap_complete() looks like another candidate for=
 letting
> > > > a driver just go crazy on the vma? :)
> > >
> > > Well there's only so much we can do. In an ideal world we'd treat VMA=
s as
> > > entirely internal data structures and pass some sort of opaque thing =
around, but
> > > we have to keep things real here :)
> >
> > Right, we'd pass something around that cannot be easily abused (like
> > modifying random vma flags in mmap_complete).
> >
> > So I was wondering if most operations that driver would perform during =
the
> > mmap_complete() could be be abstracted, and only those then be called w=
ith
> > whatever opaque thing we return here.
>
> Well there's 2 issues at play:
>
> 1. I might end up having to rewrite _large parts_ of kernel functionality=
 all of
>    which relies on there being a vma parameter (or might find that to be
>    intractable).
>
> 2. There's always the 'odd ones out' :) so there'll be some drivers that
>    absolutely do need to have access to this.
>
> But as I was writing this I thought of an idea - why don't we have someth=
ing
> opaque like this, perhaps with accessor functions, but then _give the abi=
lity to
> get the VMA if you REALLY have to_.
>
> That way we can handle both problems without too much trouble.
>
> Also Jason suggested generic functions that can just be assigned to
> .mmap_complete for instance, which would obviously eliminate the crazy
> factor a lot too.
>
> I'm going to refactor to try to put ONLY prepopulate logic in
> .mmap_complete where possible which fits with all of this.

Thinking along these lines, do you have a case when mmap_abort() needs
vm_private_data? I was thinking if VMA mapping failed, why would you
need vm_private_data to unwind prep work? You already have the context
pointer for that, no?

>
> >
> > But I have no feeling about what crazy things a driver might do. Just
> > calling remap_pfn_range() would be easy, for example, and we could abst=
ract
> > that.
>
> Yeah, I've obviously already added some wrappers for these.
>
> BTW I really really hate that STUPID ->vm_pgoff hack, if not for that, li=
fe
> would be much simpler.
>
> But instead now we need to specify PFN in the damn remap prepare wrapper =
in
> case of CoW. God.
>
> >
> > --
> > Cheers
> >
> > David / dhildenb
> >
>
> Cheers, Lorenzo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpEeUkta7UfN2qzSxHuohHnm7qXe%3DrEzVjfynhmn2WF0fA%40mail.gmail.com.
