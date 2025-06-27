Return-Path: <kasan-dev+bncBCCMH5WKTMGRBRMN7PBAMGQE4DZCVCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FBF4AEBD4E
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 18:28:59 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-6114de00d07sf23460eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 09:28:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751041734; cv=pass;
        d=google.com; s=arc-20240605;
        b=UqUe7znzW4Pw4AJsAsQINFnOgD+74zrzOsqEbDZLm4qTzHDo0IZt0gtcrwQ7KIwuUE
         fLdG71fZpZGzauut2dU4F65wF4iZZelGPuLmBPzVDGCluA44p3d0BVoZ3rifyjyDx20s
         m4Ccx7Zl6O0UPziNOQDoAYcO4OkX70fVwpY23aygtzxWjxfyiPwygZ8eD/9DePP50f7Q
         IXuk0J9zfpuucJF3hC87Ez7GyDI79dhDQcVqtxGyQ+Oww2whamPIReZk9ytLdrCJnO/e
         H2n8O37EfMM+0Bf0eWryjScqPIbbdPWN2lGAqFA5kpnBiyISRI8xhLskSXFYE531rdFl
         nDhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ayUuvCvnM1BaQ7KrXa0c/0Gmljms8Rwzi2yQLHCHNg8=;
        fh=RMwb2m1+AypuTAnM9wnYbk2CtH9DzIKWkVn9SMcu/hg=;
        b=etYlqsemMq2QUp5ouuQ2rNIgTtiakUse0dKFCBeGnSxt+eBysZYNjDUtmMx0M8A4wb
         XrrTCXxLKLjEZ4bIXcJgzY6fFL3QlNhsLLZ+93S5PGglsd39COpxW3Pv0QkuMMjbQN6d
         YEBtgmj/MK2ZHNH7QlvfRAM9qo0q8lJahmwoTJXVPEHD5rOO7dfZR56VPP2u78WCui8G
         AqaKrSL7YZyxCEuNKjLbXyF9Yt8iAjoxgaLb3BkSprFhtSAUF8KZd01i/azXHJnZLKxW
         Z08QRG9TMcR4fXvBBg4UKAneJFwFcFLjtMAjiRkyI2Sjn77bGcBgoogoOqDsl0pj9YaJ
         AUtA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ofW4NKxY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751041734; x=1751646534; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ayUuvCvnM1BaQ7KrXa0c/0Gmljms8Rwzi2yQLHCHNg8=;
        b=p5K+ZPLkgIRW2ddr8akkC5dOEhIEKvuZT1ZpKx/Y8rzUF2vu6vWx3BsiYXLDulutlJ
         ewZyp64G/V5tH6pBlGnpD+fxapDkgcp8PMj/haxXPwtSgB5cm5HGINjqHJGORSMHxZ4Z
         u28gS+ttCfgq6AJNBVBdFDtYNm1mOuf9AOV+E9S/8qoNuKMHRj78OJIt+AzoT+jJjZ6C
         UjqQOUxSAJAzFFg13mLAt0NqccUcm/if5vp6Nb9ipgpp6envUxVDOI8nkFhAIWZLVtT2
         +/3WLL4XQH5X1jf82p1mI847/72m8EO7CPp6BBD82gub5xJ4XQ+ctTWnHDbZlvtvsqEa
         PK2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751041734; x=1751646534;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ayUuvCvnM1BaQ7KrXa0c/0Gmljms8Rwzi2yQLHCHNg8=;
        b=mvSp79pFwcfOEZCA8CQCl91uUGIxjMLleHkTh7GCGHMJqoMJYgHB6+12zxSv89jWta
         zaD3J6c48Fl068lzd5PqXlHmdq+v/WWjKcl8eyN7sKHO6iCJj4Gjd9N1MUnb3hWFWAhQ
         GF/fU33qEuzL3pwC9bdR30+on/Ja3nyBu/G1kzUPiY1P3TF8SYwBkOS3/0P1kszD53em
         pJvK6E4yvLTCPD6ynkaav6JLPgHBuHCbC5f1smiT3CqNsk/7YTQL43vKfOtKdXNZYNRa
         23awrlsR861mvwxZQpV9fshU7Cu+jqyFVIObW48eXo4jfRn4TB9hkHUqzMrW1L+xpU4N
         kvtw==
X-Forwarded-Encrypted: i=2; AJvYcCVn7pnCXrWGIZnzLMR9augNBFWOpAAdaE3QX/aHOrtGEufHa3oP/WUnc+fMnS/qnv6rPd2veA==@lfdr.de
X-Gm-Message-State: AOJu0YxtKGFH8V7y85sviPwWOBl3VFizMAuMNh3qEqIZZO7Xnr9PFuHt
	2PLMFLJabJCdSA88DepbqAUez5CcwsG7IZA61zXvsEfYy59X4cU5sMbI
X-Google-Smtp-Source: AGHT+IGfu5qDP4wfDDGp1+jwJ0SI52ofnYtCEQUzNcdEA3IrLGL43wnU2JMQJTxvYBu/dVCvORE13w==
X-Received: by 2002:a05:6870:8910:b0:2c1:ac88:4a8d with SMTP id 586e51a60fabf-2efed7378f3mr2517703fac.30.1751041733737;
        Fri, 27 Jun 2025 09:28:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcJdaHAjd0nahU4RRnGgy5cNnHmxFN0ZPw3BV4mzqZDVQ==
Received: by 2002:a05:6870:6eca:b0:2ea:701f:7255 with SMTP id
 586e51a60fabf-2efcf1ac833ls1039622fac.1.-pod-prod-07-us; Fri, 27 Jun 2025
 09:28:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/e658Xx7AEfCpYc46xXnja+iXmpvCe5tvxO7y8KtCVPmBI1j8SZCCMC1IHy5yoIDeNOGsm6BIBF8=@googlegroups.com
X-Received: by 2002:a05:6870:a99b:b0:2e4:4617:f6e1 with SMTP id 586e51a60fabf-2efed451a35mr2614130fac.2.1751041732150;
        Fri, 27 Jun 2025 09:28:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751041732; cv=none;
        d=google.com; s=arc-20240605;
        b=U1fUvlIVeMQDBhMko9p7AdDNROH97beyQUvqvP/pTNNDhKTq/AfzUopgao4R0YmkRL
         LB/Tb+DNDVE7wOS8sA6MDad6tiqpWJK5Kn/K0wlKl4xgIFSc+YBtk1gBZZsPWUfLZ2yc
         OnVM0g38Om/WjHggxSptnK56/TMaIhdNmgW3DZTKBCyzxfFZ9F4HDatEN0mPAyS3M8vZ
         uzxVYgAQQIkansKu2huaLibOXmpHzc/k0IdZ4K0ZvQRPCeIOgsYxrLoqR819RD+1FT6f
         rDqcKqBhwf03zXB26jIeySWxaIxWsNehLwwNQYgYNkbAPnZ/jyJinAANsF39VN23sRRb
         d6DA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Pwe6yBI0hTTSV4QKO/x65G0lF6NWazoC/YzcyBgyfJc=;
        fh=DwAuAH9ZtGkT5QzhC9AQ3sxIFvyLouyUxxaWBghOm1Q=;
        b=KTUcJtZuwkr2yaDa7Re0WhJRB+egPRiBf/SFz+9hwo6/DXFOrockHjq+jHpfl86wjw
         pNUoAdwR6ubNMTDx/WiTiGxPUyhX9PY9vR9pdivljofALtGEP6qaj7SGCL8L/sOic4/j
         l4w/m352CXbfSsziOL4YigrWlKipI2j1y0R4XnxzoAIchmP5aEPCtnfVbzzXGbdS8NGe
         m0OOCQH9P0UnPQGwuqWNoj6aDIjVHJpf30VvrYj6wvQLHNpsZFqD7y753eA0DQ8iPp63
         I9Pb3XYNdM3ee3MBMyO7cz3a0Vgou2v9lopYV1AK4QtoujiP1V+bKjn58kVrqNyG6fSg
         9XyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ofW4NKxY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2efd4c2626fsi205149fac.0.2025.06.27.09.28.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Jun 2025 09:28:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id 6a1803df08f44-6facf4d8e9eso216526d6.1
        for <kasan-dev@googlegroups.com>; Fri, 27 Jun 2025 09:28:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVzpjtShD54Gm0RUOFZHERnhXLk4rw5xA1ThdqJvnmsBGvQt5zcbD4s5OHmABt14cpjlkcwzkIZIQY=@googlegroups.com
X-Gm-Gg: ASbGnctHoPlz5ZP8Qb5G6N7181tlmrYstvcKkquknARmyyQk3VVdxt8raon+L9eHCrU
	wyqzECmGrIv9mQlv2qw9tCt+dzOXBsZuTH+8ORvFTlfGm8QwiPBI+EvhMDufMVuMfqgSQHGOUpb
	xSzqfVr/IY2hiwq11IbF8C1RWF0jVZ8bXQ/MBMM+UbtFFsyM8vISTbtSd3g77Nuwp4iRaLOOmoP
	w==
X-Received: by 2002:ad4:5c6b:0:b0:6fb:33f7:5f34 with SMTP id
 6a1803df08f44-70002ee7d52mr61421106d6.43.1751041731049; Fri, 27 Jun 2025
 09:28:51 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1750854543.git.leon@kernel.org> <cabe5b75fe1201baa6ecd209546c1f0913fc02ef.1750854543.git.leon@kernel.org>
 <CAG_fn=XWP-rpV-D2nV-a3wMbzqLn2T-43tyGnoS2AhVGU8oZMw@mail.gmail.com> <20250626184504.GK17401@unreal>
In-Reply-To: <20250626184504.GK17401@unreal>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Jun 2025 18:28:14 +0200
X-Gm-Features: Ac12FXzk502TgF39Kdk9rDaSo7SztNg9o8ROEHR27kqxNaOw7yX3TSWKD6zOmLM
Message-ID: <CAG_fn=WeK8q2g0bRna+fFx+ks4HbfoG3Tnw8PpSdmfdH=3+S=A@mail.gmail.com>
Subject: Re: [PATCH 5/8] kmsan: convert kmsan_handle_dma to use physical addresses
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>, Christoph Hellwig <hch@lst.de>, 
	Jonathan Corbet <corbet@lwn.net>, Madhavan Srinivasan <maddy@linux.ibm.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>, Robin Murphy <robin.murphy@arm.com>, 
	Joerg Roedel <joro@8bytes.org>, Will Deacon <will@kernel.org>, "Michael S. Tsirkin" <mst@redhat.com>, 
	Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>, 
	=?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	=?UTF-8?B?SsOpcsO0bWUgR2xpc3Nl?= <jglisse@redhat.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, 
	iommu@lists.linux.dev, virtualization@lists.linux.dev, 
	kasan-dev@googlegroups.com, linux-trace-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ofW4NKxY;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jun 26, 2025 at 8:45=E2=80=AFPM Leon Romanovsky <leon@kernel.org> w=
rote:
>
> On Thu, Jun 26, 2025 at 07:43:06PM +0200, Alexander Potapenko wrote:
> > On Wed, Jun 25, 2025 at 3:19=E2=80=AFPM Leon Romanovsky <leon@kernel.or=
g> wrote:
> > >
> > > From: Leon Romanovsky <leonro@nvidia.com>
Acked-by: Alexander Potapenko <glider@google.com>

> >
> > Hi Leon,
> >
> > >
> > > Convert the KMSAN DMA handling function from page-based to physical
> > > address-based interface.
> > >
> > > The refactoring renames kmsan_handle_dma() parameters from accepting
> > > (struct page *page, size_t offset, size_t size) to (phys_addr_t phys,
> > > size_t size).
> >
> > Could you please elaborate a bit why this is needed? Are you fixing
> > some particular issue?
>
> It is soft of the fix and improvement at the same time.
> Improvement:
> It allows direct call to kmsan_handle_dma() without need
> to convert from phys_addr_t to struct page for newly introduced
> dma_map_phys() routine.
>
> Fix:
> It prevents us from executing kmsan for addresses that don't have struct =
page
> (for example PCI_P2PDMA_MAP_THRU_HOST_BRIDGE pages), which we are doing
> with original code.
>
> dma_map_sg_attrs()
>  -> __dma_map_sg_attrs()
>   -> dma_direct_map_sg()
>    -> PCI_P2PDMA_MAP_THRU_HOST_BRIDGE and nents > 0
>     -> kmsan_handle_dma_sg();
>      -> kmsan_handle_dma(g_page(item) <---- this is "fake" page.
>
> We are trying to build DMA API that doesn't require struct pages.

Thanks for clarifying that!

> > KMSAN only works on 64-bit systems, do we actually have highmem on any =
of these?
>
> I don't know, but the original code had this check:
>   344         if (PageHighMem(page))
>   345                 return;
>
> Thanks

Ouch, I overlooked that, sorry!

I spent a while trying to understand where this code originated from,
and found the following discussion:
https://lore.kernel.org/all/20200327170647.GA22758@lst.de/

It's still unclear to me whether we actually need this check, because
with my config it doesn't produce any code.
But I think this shouldn't be blocking your patch, I'd rather make a
follow-up fix.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWeK8q2g0bRna%2BfFx%2Bks4HbfoG3Tnw8PpSdmfdH%3D3%2BS%3DA%40mail.gmail=
.com.
