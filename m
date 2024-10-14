Return-Path: <kasan-dev+bncBDCPL7WX3MKBBC4BW24AMGQEBCIAOXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C55AB99D84B
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 22:35:24 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e292d801e59sf3909072276.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 13:35:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728938123; cv=pass;
        d=google.com; s=arc-20240605;
        b=b6DAXkAnKckhFp7RNlJIZKjRUCtDJS+P039owOcVcIFx1/M20cu4ZBinkAzN2ZEGXI
         XD9RyYxljEM+gRSt86+W6n5tIOIPH5j0AabrvXmtRBXLMDL2LK9avjMLdFwvafBVUQIQ
         AWWsRX47Zak+r0ZqZYDU33LbzIqI2DwiowpWlr7Q1E2oITHPLywlzZO+Vc3Om3Pytfl9
         sXWUtxgOSlCXWYgldbRMzLEaDyEB1y3x4eYYPo2zETcu4uKHJ2Jn463ISYNUWqNeVJwL
         hw5bUXMCXL4N/Plrz/H88d7Tnqmu6wrRrmizt4jrFj1/AE9uXxu4al+WSder03UZ+9Zf
         uJXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=c8LpQloYUfJpfijJhPPWL3eIerK8+mvwqTxBQT42eIw=;
        fh=dtUxNF302wvK1ycQ+wT9jkcqgPw0QLXFRFAp93VVvDE=;
        b=ca1ISt9hrlppeFuuugNVYLCr3h5ivoUMQqk4mt6nP/49xT2AfCXSnDCBfGrJVzlkIU
         ewH8Tn2UVLu+KdDuVMJT1r2gM0G6O40CTV8vEQyp6dZzoW5g00oZCcTrqmBRX6VQH2Ej
         WffdjlYb8K97ZCWHi3O3+nwmd36K6WTdf+WJqrR3+mK7oR7Fo/eJa78C43Y1PoI1ykc0
         t0G71R/s/kWgWMps0LN5Rdw09STjfGaIFBZcLjLKExWierS9GAXm8iAMD7aY3PkDBx/l
         tY/c0DfV0k+PDCxEk/z/wyXqMc61k5pnVNJgIFBRAlhGehuzjlZ/4iy5QE0b4RAehxlX
         vHjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Ect6gHv/";
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728938123; x=1729542923; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=c8LpQloYUfJpfijJhPPWL3eIerK8+mvwqTxBQT42eIw=;
        b=bWrMalbX0UNaiKJh37YtNXaEbYMYlyuaZFJWA82tfDf5LjXFno+InX3ZYZXZW4cPCw
         pXdm6FauU6TN24jv26nGTnCKrRzwMr1UmXzZ0ck7TqxXmB+acGQRdBnaP0Z/oauZLKc2
         4ulOoyx8vozKTaCepxJONSXeqYfuvHG+gXx7OPSb4nwJowU7w7Bs1f64e4AtGt3+6HMd
         50pmjQQSwbt6qWV+IYPYl5CVAd1qEdwc6pBQas/cgl5HKCwYMFK9iqp8lRyKS4RHP4Ng
         7GwShjkKgi1n1ibIh5hCklHICdB08LAvQ8VFup2lMWkwsH4E9IBHVQIC6O/L9jvO2XeD
         ePBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728938123; x=1729542923;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=c8LpQloYUfJpfijJhPPWL3eIerK8+mvwqTxBQT42eIw=;
        b=G8BSLgEdkntDyv3DdlYvD087L7Fo7dV53QUOBG/7vDA2Ep2yCOEcDGaZMZOIPM3f+O
         U2G2gYHOnspfkKT4/W1XcvBKB5IFF7iJ0fg5t0Lci+P0aabgO5GCOTGLr4FB6rCuS5/2
         G5hEdAGOOF9FhLWSSK609DuF+f6brVjNvMzRv5075cTjx3BKDPLGSrvFBp2UrI9mT1Rw
         W1S+J2z7p287DHjKfJwLS40rGbxY4JvGs1EdI0aIqCpKDuJ0NscVBqdE1H0QLJxpDSsy
         QUAnrA3c0ipY8s4NuehvP2Zmm+pZLWjLrLLJsCDjzkSEDsLyvUTaQwOhmmYCIqOd3U2C
         o0aw==
X-Forwarded-Encrypted: i=2; AJvYcCWOaMSJoOHdbkvXITnsLF04uyAV2rQZPiYRyFx3SwCBH/R2TmLiLtL2QR1f8lkTkLdTHXVHQA==@lfdr.de
X-Gm-Message-State: AOJu0YzIQ4/fsT2Zd464WOJSl9cBggUO/qQMmlQZkkAdP1qQmB3sVjDY
	xhKmvZISZm8pwYBRGbz5eYNawVpdeZiQnexNVqeM/n/AXZkvJD7r
X-Google-Smtp-Source: AGHT+IEGSUCYSTo26l8x0KsudvmgXWBEwahrUSzuSBqUfzqH7cfNo0eXjx+JwiNSXRrZS4H+5gD2Sw==
X-Received: by 2002:a05:6902:2789:b0:e28:6758:fb0e with SMTP id 3f1490d57ef6-e2919d8369emr10354597276.16.1728938123295;
        Mon, 14 Oct 2024 13:35:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1008:b0:e22:59c6:5d26 with SMTP id
 3f1490d57ef6-e290bb929d1ls3595911276.2.-pod-prod-01-us; Mon, 14 Oct 2024
 13:35:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWvAqOKLeOmps9avFYeY32c8xc72UuWX0GUnzk2VgAMzqJ68d2UiCkLx4gnUz15Rx4LJD3Ku9iDHwE=@googlegroups.com
X-Received: by 2002:a05:6902:2789:b0:e28:6758:fb0e with SMTP id 3f1490d57ef6-e2919d8369emr10354556276.16.1728938122608;
        Mon, 14 Oct 2024 13:35:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728938122; cv=none;
        d=google.com; s=arc-20240605;
        b=cqvgYpeB5h0DrPDTqK9VxBSDmt0twFJHjez3XmchGrwgOy4Dx9IAKufjzGHyiUJmR9
         pF0A94lEPqggzs9mpAUUJJSwE98tz5I1byU/J6fnAaDf4T4DA6h5SxNAs2fAD1e9F+s/
         IVB5KRNVnLxipe9zAmHBr1n5AUNyI0ll2UdyUzsUNt6s2CcxkfLDTA4bB2Bk/Uzi6/r2
         r8OzMW7V7RDTrGHDkD9ulwTFATtXcqg97B9NQJUyNaZLZCVGarlAxxS+VL/my95+qq3l
         MnTUr6BJgbd0bbeibXx83ZpAa3+ua0+y8F5uLSncVsGFCLHteSgEWMKoDe11vA7mXA55
         peaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ppi7+dgoi6Dcu/mxMR3vNRKUMuBcP1Y/URA6z3Ogy0s=;
        fh=ofw4oKRr37WavHC1fi1M9dLVkSw81dqrzN1euilub0E=;
        b=A04l0g5wuPJv3MdMhSJRyFv0zdw7JXuJcAsVFAd+vtU3Oo3orCQ/6sGYvy7KGYp9SH
         DV0tsgH5NNXZpgrpT7Lk4pFyLDtvEGulgZ+e6K6ESp8crbuLDbEgtgs8cjFzMhaYmHFP
         EHXHLEfVXM1nSwxCCGSaFURfzaV2SrY+HeFsRlBI3k2kWJn04hs7S8X5H2gnOMx+/Qks
         qEQnyLVJNRjbsQMNZAlgPBhsKTvjPqeu16qER0V7L8Ar/QBaiQCSlbEGUsH4HvnWjRL3
         5sig/mVM7ur23hB+h86AZy8g/Z+C1qm0Jc2eQ5fajXNLHqt76SU7afaffolB7P0B1w9/
         qEaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Ect6gHv/";
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b1148e493csi39284685a.1.2024.10.14.13.35.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 13:35:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A76A85C5BFD;
	Mon, 14 Oct 2024 20:35:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B59E6C4CECE;
	Mon, 14 Oct 2024 20:35:21 +0000 (UTC)
Date: Mon, 14 Oct 2024 13:35:17 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Feng Tang <feng.tang@intel.com>, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	David Gow <davidgow@google.com>, Danilo Krummrich <dakr@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	Eric Dumazet <edumazet@google.com>
Subject: Re: [PATCH v2 0/5] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
Message-ID: <202410141330.CAF56E3@keescook>
References: <20240911064535.557650-1-feng.tang@intel.com>
 <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
 <CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com>
 <49ef066d-d001-411e-8db7-f064bdc2104c@suse.cz>
 <2382d6e1-7719-4bf9-8a4a-1e2c32ee7c9f@suse.cz>
 <ZwzNtGALCG9jUNUD@feng-clx.sh.intel.com>
 <a34e6796-e550-465c-92dc-ee659716b918@suse.cz>
 <Zw0UKtx5d2hnHvDV@feng-clx.sh.intel.com>
 <0e8d49d2-e89b-44df-9dff-29e8f24de105@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0e8d49d2-e89b-44df-9dff-29e8f24de105@suse.cz>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Ect6gHv/";       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Mon, Oct 14, 2024 at 03:12:09PM +0200, Vlastimil Babka wrote:
> On 10/14/24 14:52, Feng Tang wrote:
> > On Mon, Oct 14, 2024 at 10:53:32AM +0200, Vlastimil Babka wrote:
> >> On 10/14/24 09:52, Feng Tang wrote:
> >> > On Fri, Oct 04, 2024 at 05:52:10PM +0800, Vlastimil Babka wrote:
> >> > Thanks for the suggestion!
> >> > 
> >> > As there were error report about the NULL slab for big kmalloc object, how
> >> > about the following code for 
> >> > 
> >> > __do_krealloc(const void *p, size_t new_size, gfp_t flags)
> >> > {
> >> > 	void *ret;
> >> > 	size_t ks = 0;
> >> > 	int orig_size = 0;
> >> > 	struct kmem_cache *s = NULL;
> >> > 
> >> > 	/* Check for double-free. */
> >> > 	if (likely(!ZERO_OR_NULL_PTR(p))) {
> >> > 		if (!kasan_check_byte(p))
> >> > 			return NULL;
> >> > 
> >> > 		ks = ksize(p);
> >> 
> >> I think this will result in __ksize() doing
> >>   skip_orig_size_check(folio_slab(folio)->slab_cache, object);
> >> and we don't want that?
> > 
> > I think that's fine. As later code will re-set the orig_size anyway.
> 
> But you also read it first.
> 
> >> > 		/* Some objects have no orig_size, like big kmalloc case */
> >> > 		if (is_kfence_address(p)) {
> >> > 			orig_size = kfence_ksize(p);
> >> > 		} else if (virt_to_slab(p)) {
> >> > 			s = virt_to_cache(p);
> >> > 			orig_size = get_orig_size(s, (void *)p);
> 
> here.
> 
> >> > 		}
> 
> >> Also the checks below repeat some of the checks of ksize().
> > 
> > Yes, there is some redundancy, mostly the virt_to_slab() 
> > 
> >> So I think in __do_krealloc() we should do things manually to determine ks
> >> and not call ksize(). Just not break any of the cases ksize() handles
> >> (kfence, large kmalloc).
> > 
> > OK, originally I tried not to expose internals of __ksize(). Let me
> > try this way.
> 
> ksize() makes assumptions that a user outside of slab itself is calling it.
> 
> But we (well mostly Kees) also introduced kmalloc_size_roundup() to avoid
> querying ksize() for the purposes of writing beyond the original
> kmalloc(size) up to the bucket size. So maybe we can also investigate if the
> skip_orig_size_check() mechanism can be removed now?
> 
> Still I think __do_krealloc() should rather do its own thing and not call
> ksize().

The goal was to avoid having users of the allocation APIs change the
sizes of allocations without calling into realloc. This is because
otherwise the "alloc_size" attribute used by compilers inform
__builtin_dynamic_object_size() can get confused:

ptr = alloc(less_than_bucket_size);
...
size = ksize(ptr); /* larger size! */
memcpy(ptr, src, size); /* compiler instrumentation doesn't see that ptr "grows" */

So the callers use kmalloc_size_roundup() to just allocate the rounded
up size immediately. Internally, the allocator can do what it wants.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202410141330.CAF56E3%40keescook.
