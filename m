Return-Path: <kasan-dev+bncBAABB7PSUO2QMGQEWKIROZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E57D941468
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 16:32:31 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1fc478ff284sf1832105ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 07:32:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722349950; cv=pass;
        d=google.com; s=arc-20160816;
        b=0PdjdH0Gq/cjS4j1rHqXQ8PZhXNw/DZaAkuDI9dq/zWBkjBk8qtoeYLzFEUg7fgOet
         mSwqzAX1yf4l8yp4mwW3LfGSDKDnDIr+Xcunogqir9GbIb0iCV2OM/QAEP6QrzLIc4lo
         BeoYqVKA9Vu7S/cVxrzsajJ1qemeuZq2t6EFyOhgAEy2E6lQWplPHLV2HcFy1dOs18op
         7lpAYVKGvcvKOpNTL/6t+NwWc0iLZfpUKg8KJy4mol+rpxpQGtbgWtDyrygFoxCsXsUR
         d6yFFlIqr35RZ5TomXnUAS+vYDMY6DUM1x292nyKgK+ROVhKxJVEff1x33o4qabuwy/a
         jFBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=F6/4+RNwCDeER7xKrrpF14oBHhauTjU2QvAjvRkOCwg=;
        fh=bjlW27feYQNH7vYKcAeF2FNxB8H+/LNqodpvcnBpNbM=;
        b=mViF1QDblE+D3fNIw+W5a+i5gNKZffs3li8FWeS/sFCA53otLGd0kZPv6EBuxHrl4s
         pylYQpIluaMxeWXgedodLmpdZZyCqA4pHebKVh1Fwq+PxCVIav3gvDuyfmz3qlMV2pMu
         ILxiiCI3LrvCq7KE+39jhKkiONAIByvTArkJYwVmc1MSK2pi1Ef9aWlx2ydb+BhBVv5q
         qEy/VJPiCfL24p8HlKdejL4Yg3IoJ0TaPH1B/Bt79XiKXo4CN2UdXmPdfA2q/KE3dLz9
         OkxrlOwEPyCFCRfD22pOgFkKCv2eVTRwIscOXkyG1tfGbsRMRKd3A3iBtuqlQX24cLMf
         joUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=APhoxjyX;
       spf=pass (google.com: domain of dakr@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=dakr@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722349950; x=1722954750; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=F6/4+RNwCDeER7xKrrpF14oBHhauTjU2QvAjvRkOCwg=;
        b=ZLIUjbQPizeu9BrnmWqaCDTMG55xNinnSq3WO6ezoODD3uR5wQfa2RAPZACM270+sG
         8ByB4/odF6Q1rItnff6lMvERdGzigwktk1alKV/iG5WdvWZF1tbGSdhYtSkjuEtmffFc
         1EsH9FMZm/hsx7MBVqwhlEXZ12fODfWbc3//fgjVUKeNAg2Y/dHk2mgPxg7q0axsGodP
         12oeHUj7R8azKW9Lb8ab1v30EcK2AU1tWc4hYP/tQKNN4ALhsuTEwqTJG/GXZtc3fy9D
         paLLpind009OITvGuZ2PG+2bR6KKi2sIFKzOMgU9KSRfvxAnAlWkOgVi7OWqyHxB/zev
         iuEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722349950; x=1722954750;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=F6/4+RNwCDeER7xKrrpF14oBHhauTjU2QvAjvRkOCwg=;
        b=UNuYreb+EESVeW3NL3aTKscsmj/FHjSNl2O6ulcehhKVhB2j4iV7Fnqkq5lb6fnJT9
         yvzPrCyIYkkjqhIJNKs91keTby2vPlnhqu87fBtd3/KVJcoTIS5Oeaiq1kgxWWfwDsdO
         z7oe6XeizgqiZlC/AGrrrkad957WmePyQSKHZJwKuupBKzBXQmEDNM0zsr9AeC9w1xKC
         6OhdJJV2AvjGzhMgtlOatm36Fs1Lkt5uxM8+DlKTwl1ZSHegDzWSa5ug3ejz3Rmlsu6J
         1Pb5lcrcv/5YkV94ojviwH8Fg7MBna3UVNlb61+kq+julD6a2KsrQ2tGtSSvyGByr+10
         9XOw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUo+Tdphr0SZ/XPGwjQYI7kZAZBDbRlZs7u6DsdRGTZXGR7taPObsq9LQfX0qng3ZMaGdT58vMO/RAgpOD+cTOqmbIw3lHsoQ==
X-Gm-Message-State: AOJu0YyNE+bm2ppQnGOl6YR4L2Y3NyhxkE658kmdPnWCsMqqEhJucYtd
	IY98O55kxSTdaIwnAp2Zkb87l34z1opgbdz2PF5IdKMnbdZXB4KO
X-Google-Smtp-Source: AGHT+IFRbS/LjrmedsiObUdor/mkOxIlVFNmkkarhxYwc5msXaDagiec1DHPjt02GCfEKIDNgzwAkQ==
X-Received: by 2002:a17:902:eb8f:b0:1fb:b39:ce4c with SMTP id d9443c01a7336-1ff3785096cmr2340805ad.8.1722349949632;
        Tue, 30 Jul 2024 07:32:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1a8b:b0:706:7564:770c with SMTP id
 d2e1a72fcca58-70ea9e2a448ls3391773b3a.2.-pod-prod-07-us; Tue, 30 Jul 2024
 07:32:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV9xnlBHprwYH+yFxV1EoeiX/4SS2HiGYTqWnpxoR9I1/cWyDHPZbuwadiVWc5IBVbZw2nph/egK5q7FyXYTsCwXHDjNyhE/Mmkbg==
X-Received: by 2002:a05:6a21:3406:b0:1c4:7138:ad1b with SMTP id adf61e73a8af0-1c4a1510556mr9164764637.54.1722349948572;
        Tue, 30 Jul 2024 07:32:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722349948; cv=none;
        d=google.com; s=arc-20160816;
        b=aeOMse2WlcZsHePVx/gqhwVQ5z6wZT4LT+RS5eUIynOsHWw4ORixGU7UxsSg17W51z
         BI2bPb8laaZ8Y3wiJrBEGRUYh4v7o+hd390g5r7RpPGtD1wrVaEo1Ls73bCkd1NXxPVi
         In7H0LMshcrGc6/wVmVAvMSGDJBKeu5UQTRyxnfIAorsUy6OIBJETL4sZneMAauc/0jv
         3OhbWuLqmXFPu62xwjad1Oc7aprS3wZOCnvZjOIvUI/RejTCBccExNYomqUu3OWwqPyI
         JdKh8BMAZ9A7BPrU6can/GdKr8jOisNJ3WI1/HmNrc8SZ1MOY5ZD8ixcJL62EzxzeSCJ
         jiPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=y0OqFpEW/LDALC/kx7R+Xa89XiiMG2r64AxNfOe0Q4k=;
        fh=wxxr8O6T05pi/TXUho/j+VY9T7tjq5GxtDqHwYHZHYM=;
        b=C8CL02gw0w8SF1I2SPIkY0LWqvinP1lBVMkpBC5ZqbHAl1fd63bskp35poHRYzuwKU
         txQcj0aIV39LfR6+hqMz/hAvUAPirHeFC/7NBkOlg1XSR4engSFg6YLiYOqoRumanZLs
         wt2Da2EBsEfuJvqrR5jzgueenhyy+gTeGlLA/2RRSiucKXfY56LUwMAQUWs9nHC7ZtjU
         tNLCPA5wv4tC1U2dWRmJT6n+WONRkr4nv1mEqC5rmsc5P4wjdJjc/5wBjiSKhxZbH1FX
         6HVA05Bh4Ql+Sx5IsuRfJHk9zZX96TlaTaWeGzcKiCTdAEQ3UuF70mgzUMCH1fJzmeLx
         Fxag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=APhoxjyX;
       spf=pass (google.com: domain of dakr@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=dakr@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7a9f5f2d1absi693748a12.1.2024.07.30.07.32.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 07:32:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of dakr@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E462E61F38;
	Tue, 30 Jul 2024 14:32:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E04DBC32782;
	Tue, 30 Jul 2024 14:32:22 +0000 (UTC)
Date: Tue, 30 Jul 2024 16:32:19 +0200
From: Danilo Krummrich <dakr@kernel.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: cl@linux.com, penberg@kernel.org, rientjes@google.com,
	iamjoonsoo.kim@lge.com, akpm@linux-foundation.org,
	roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, urezki@gmail.com,
	hch@infradead.org, kees@kernel.org, ojeda@kernel.org,
	wedsonaf@gmail.com, mhocko@kernel.org, mpe@ellerman.id.au,
	chandan.babu@oracle.com, christian.koenig@amd.com, maz@kernel.org,
	oliver.upton@linux.dev, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, rust-for-linux@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v2 1/2] mm: vmalloc: implement vrealloc()
Message-ID: <Zqj5cyBCSu8bxsLJ@pollux>
References: <20240722163111.4766-1-dakr@kernel.org>
 <20240722163111.4766-2-dakr@kernel.org>
 <07491799-9753-4fc9-b642-6d7d7d9575aa@suse.cz>
 <ZqQBjjtPXeErPsva@cassiopeiae>
 <ZqfomPVr7PadY8Et@cassiopeiae>
 <ZqhDXkFNaN_Cx11e@cassiopeiae>
 <44fa564b-9c8f-4ac2-bce3-f6d2c99b73b7@suse.cz>
 <ZqjnR4Wxzf-ciUGW@pollux>
 <d0234a41-811e-40a7-b239-e51b35862adc@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d0234a41-811e-40a7-b239-e51b35862adc@suse.cz>
X-Original-Sender: dakr@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=APhoxjyX;       spf=pass
 (google.com: domain of dakr@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=dakr@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, Jul 30, 2024 at 03:58:25PM +0200, Vlastimil Babka wrote:
> On 7/30/24 3:14 PM, Danilo Krummrich wrote:
> > On Tue, Jul 30, 2024 at 02:15:34PM +0200, Vlastimil Babka wrote:
> >> On 7/30/24 3:35 AM, Danilo Krummrich wrote:
> >>> On Mon, Jul 29, 2024 at 09:08:16PM +0200, Danilo Krummrich wrote:
> >>>> On Fri, Jul 26, 2024 at 10:05:47PM +0200, Danilo Krummrich wrote:
> >>>>> On Fri, Jul 26, 2024 at 04:37:43PM +0200, Vlastimil Babka wrote:
> >>>>>> On 7/22/24 6:29 PM, Danilo Krummrich wrote:
> >>>>>>> Implement vrealloc() analogous to krealloc().
> >>>>>>>
> >>>>>>> Currently, krealloc() requires the caller to pass the size of the
> >>>>>>> previous memory allocation, which, instead, should be self-contained.
> >>>>>>>
> >>>>>>> We attempt to fix this in a subsequent patch which, in order to do so,
> >>>>>>> requires vrealloc().
> >>>>>>>
> >>>>>>> Besides that, we need realloc() functions for kernel allocators in Rust
> >>>>>>> too. With `Vec` or `KVec` respectively, potentially growing (and
> >>>>>>> shrinking) data structures are rather common.
> >>>>>>>
> >>>>>>> Signed-off-by: Danilo Krummrich <dakr@kernel.org>
> >>>>>>
> >>>>>> Acked-by: Vlastimil Babka <vbabka@suse.cz>
> >>>>>>
> >>>>>>> --- a/mm/vmalloc.c
> >>>>>>> +++ b/mm/vmalloc.c
> >>>>>>> @@ -4037,6 +4037,65 @@ void *vzalloc_node_noprof(unsigned long size, int node)
> >>>>>>>  }
> >>>>>>>  EXPORT_SYMBOL(vzalloc_node_noprof);
> >>>>>>>  
> >>>>>>> +/**
> >>>>>>> + * vrealloc - reallocate virtually contiguous memory; contents remain unchanged
> >>>>>>> + * @p: object to reallocate memory for
> >>>>>>> + * @size: the size to reallocate
> >>>>>>> + * @flags: the flags for the page level allocator
> >>>>>>> + *
> >>>>>>> + * The contents of the object pointed to are preserved up to the lesser of the
> >>>>>>> + * new and old size (__GFP_ZERO flag is effectively ignored).
> >>>>>>
> >>>>>> Well, technically not correct as we don't shrink. Get 8 pages, kvrealloc to
> >>>>>> 4 pages, kvrealloc back to 8 and the last 4 are not zeroed. But it's not
> >>>>>> new, kvrealloc() did the same before patch 2/2.
> >>>>>
> >>>>> Taking it (too) literal, it's not wrong. The contents of the object pointed to
> >>>>> are indeed preserved up to the lesser of the new and old size. It's just that
> >>>>> the rest may be "preserved" as well.
> >>>>>
> >>>>> I work on implementing shrink and grow for vrealloc(). In the meantime I think
> >>>>> we could probably just memset() spare memory to zero.
> >>>>
> >>>> Probably, this was a bad idea. Even with shrinking implemented we'd need to
> >>>> memset() potential spare memory of the last page to zero, when new_size <
> >>>> old_size.
> >>>>
> >>>> Analogously, the same would be true for krealloc() buckets. That's probably not
> >>>> worth it.
> >>
> >> I think it could remove unexpected bad surprises with the API so why not
> >> do it.
> > 
> > We'd either need to do it *every* time we shrink an allocation on spec, or we
> > only do it when shrinking with __GFP_ZERO flag set, which might be a bit
> > counter-intuitive.
> 
> I don't think it is that much counterintuitive.
> 
> > If we do it, I'd probably vote for the latter semantics. While it sounds more
> > error prone, it's less wasteful and enough to cover the most common case where
> > the actual *realloc() call is always with the same parameters, but a changing
> > size.
> 
> Yeah. Or with hardening enabled (init_on_alloc) it could be done always.
> 

Ok, sounds good. Will go with that then.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zqj5cyBCSu8bxsLJ%40pollux.
