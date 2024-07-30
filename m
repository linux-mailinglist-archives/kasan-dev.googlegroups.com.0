Return-Path: <kasan-dev+bncBAABBU6OUO2QMGQE2UI2VBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 227369412E1
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 15:15:01 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1fc478ff284sf1653965ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 06:15:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722345299; cv=pass;
        d=google.com; s=arc-20160816;
        b=hQ7KxpcLgZdJ8gjxk9Cz1dMDGn/ngKAuNuh1OT8mL7+b8nR3Qho3NClPoUczXEh7HW
         CRayn3CV0LPaImzLUamv78P7hVwYKYQFVk+IztcnJgNjt+jEn6kaKNJdcz0mDaGKDpN3
         6w9s7SwXOUO/WNTES/7tVQ4p9gBSM7egVKYdZcicW1cwWp07/U9eEr1XwUScDtCD4B4I
         +nkmfj1UkiCR04F6oZQG/uBvVp1B79+yTbbqhR4FpNEuJBKbj0D4WWsr/9mwoitgYMdJ
         IYqrq+a5v78X+OovQPSF5PiDDpOwV5WBfODnq+cFi79dsqfWCa/i9utR6MjAJmi0Xqs9
         dFMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=EDrjbeMx1zBDPAWeKq/PNZcP2941UfiAFK2hdPzOuls=;
        fh=RmGWyEa+AmK/DCnvm4fN0qCOnQsNXZMbzpK7RajJ9WI=;
        b=pillvqBvNYw/iSkTTnSY4P0RiOG/UNtGu5LLFO/E+r+gpj26CjGNbMCMzhKoHzsblK
         8BfIfrOtBx1RhVDB0vy8Kvc3QVrI1TyaGK5xWO9V29StP5MjHs/KXt0mMzgoHufGtMM8
         Lv0IOoiUZI7dhKx0SdkPC7TOVU/f8yRLFr3r9ZXZLzlUa8YHypwvB26aq2QrZtLne+Mi
         B2wu0kcEmmbiAyvIfO8IVaKXwazrhlmBbLbvm6eOZ5LOAjlQE+oboXHWtg/HQeyT7bbq
         PzDj3lvm1sRqkXlUR2U1K4kPLRbJpgZlxtaD0vAXyAmAzjAarneA3ja6HrVyhK2w4NMy
         kNiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PDLf5vP9;
       spf=pass (google.com: domain of dakr@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=dakr@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722345299; x=1722950099; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EDrjbeMx1zBDPAWeKq/PNZcP2941UfiAFK2hdPzOuls=;
        b=Q+q+gfjsX+q8hK4x3QvsxivbobFw0ffoRIQ5oY+uFg4+iawEt+bNN3gOA3kT8VOcOm
         toFD0CT+KJLXZixsQu5vrFt7Hg1xdOpULiIsDpMf9TgV3EON+yDOwY2Ja0yxGV7TAN7t
         2i0tpoLHcjKml73f1YCJfiBhYeQdgA7IWl4qU8UzfruM8T73HcLac5jwifz59e3aK32r
         ttKMRhxaLodUZXjHKM4wmC5Pucc2Xp3HzzfiJrwYDQYq4DZ33uTlXbT+9myqZ7zhDU3z
         XAhU7El1XN7XfX1zY+yK6pJpStoi/e2MoD9sdQdaolJHvVoPOmxVOm2/RGqDXLzvGSuV
         EQGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722345299; x=1722950099;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EDrjbeMx1zBDPAWeKq/PNZcP2941UfiAFK2hdPzOuls=;
        b=P34ki3hCreaQGvS6bojhgKxfnOeQ+bC4rF6lU+aEkoPU6pUjtJhGd2Is10H4e1U6eZ
         Eqizm0sdVdRx1OYEVYfIxDzIm1qYC6khMePH0s6wB3LK8ccAG9RoTr/CvaRP2OwdTeWg
         D0AYY6vMuicVRUPZoMrbC1our943jQcoFpvUP0sv9OS6j1+FgyONzT2jpQ7su0Q6a7TG
         BsRmIDUbkR8SKPyfWZFLliHt9ucUnZtTmYZE791Slx0gclodY9Pa+SdmeP14+bNfyMXp
         dDy8ovte/VPtrBn+uQ6de60XmKEj8I9UvpL2aG9BrKmsbupAqLqrE/aSTW3AuMJkttYv
         T9hA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXyMrYQnNkwjBXEbnGkGzAZa0b01z6olL3nONdN66AvWief5ADZZEUZKv8itvtL6xzko0twSwjjVel6dUpTRwjcPo7f+K27Bw==
X-Gm-Message-State: AOJu0Yw/m19tCSoMQrJlbSF0491qdpUpM94gaejjMbE5nD/vYVyQO0mG
	mVKE+oRPCkYtKVGdxhPEPJNS8kSt0Jlep7E5sjhhrPfTfSz1Z78e
X-Google-Smtp-Source: AGHT+IGCaj1KlOeKtFdGYlcjwRBQYfFdX9v+rx24t1tvcTJvT6Do1OHAij0TM3xoUiIsmHXtnPaQHQ==
X-Received: by 2002:a17:903:2ac7:b0:1fa:191c:fe4e with SMTP id d9443c01a7336-1ff38c677famr1645605ad.21.1722345299413;
        Tue, 30 Jul 2024 06:14:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c70c:b0:2c7:50ae:5c1b with SMTP id
 98e67ed59e1d1-2cf233b6653ls3668363a91.2.-pod-prod-00-us; Tue, 30 Jul 2024
 06:14:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyP7/gxFcUay+Zp3ygTbI6QHVBI9uENBjfB2BbSiMICvCCObsyHgB+/FWQA5Fz8+n5UpqgqZyUFDJypuQ8FNXT6i/hDFgKyZY/1A==
X-Received: by 2002:a17:90a:67ce:b0:2cb:58e1:abc8 with SMTP id 98e67ed59e1d1-2cfcab4c7bfmr3165569a91.21.1722345298127;
        Tue, 30 Jul 2024 06:14:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722345298; cv=none;
        d=google.com; s=arc-20160816;
        b=MR9UEhO/3EefxnqFuWBN2/SJQnZRCM/EI59IXIdOt58hkv7XCaYnCToeGNC1BkHswW
         lC+72qS/nSTWa3YO7TWQ4WOp7z/479ybzg1WDiBC0MfLtc1sxS9HPbkG9gSi00D7yZIz
         SnJgPHVvL9ry16fM0JKrrAVLBv+0uaMfQ3XVpw9544ASQSObWOHieyS/ZtKQ/C5eSmKw
         W9uTuhi94WHVc6CPK1GtBJzoUSaqEO1D3LM3FoQ7DO8gTneQ+rCGnaTrTB8yqxGSH3wZ
         jg8CWSpaQcKSr7m1wZF1BTzjmEPrY4+IDCoRCOMXpkxh4e9DGOpJKu7RLCXAd7BuFfvf
         h1mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=aORqCZnl/5dPLxmiOJW4MSZlynTa9JBYDsQhaV8fBPo=;
        fh=wxxr8O6T05pi/TXUho/j+VY9T7tjq5GxtDqHwYHZHYM=;
        b=MrHGxUJoFZvVvz+4RlpmHenVAahEzYwePIvw26lRC3dBnBlug/L28r6ubPcgxIZUXZ
         67C+yn/p95n3BtCXjd1WUFs8WCHiL050N4a+lFvOSCFDa3h3cFr/nX7TO2duRVhgElWh
         1Xo+pOsLtF4f5gCfk0WGdR8T3Z74/9vU7+acVYCz/wH+EzNS3aYaXKF5E+tDz+xISpQO
         5j5Er1IQvndyCKExk1RnQyRxxHtOnKD81tKE2tNdYmcGlD0hhhnU1Hy3wdIGN2gX7U8p
         tepv4ety0ItGAGMG3z6yC1+bJGGk2l5QTyksG4Pklhs48wExWVBkhwzAUIQlSEBqH6yi
         /7Eg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PDLf5vP9;
       spf=pass (google.com: domain of dakr@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=dakr@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2cdb75ff1cfsi702386a91.3.2024.07.30.06.14.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 06:14:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of dakr@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id E75B4CE0ECD;
	Tue, 30 Jul 2024 13:14:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 80495C32782;
	Tue, 30 Jul 2024 13:14:50 +0000 (UTC)
Date: Tue, 30 Jul 2024 15:14:47 +0200
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
Message-ID: <ZqjnR4Wxzf-ciUGW@pollux>
References: <20240722163111.4766-1-dakr@kernel.org>
 <20240722163111.4766-2-dakr@kernel.org>
 <07491799-9753-4fc9-b642-6d7d7d9575aa@suse.cz>
 <ZqQBjjtPXeErPsva@cassiopeiae>
 <ZqfomPVr7PadY8Et@cassiopeiae>
 <ZqhDXkFNaN_Cx11e@cassiopeiae>
 <44fa564b-9c8f-4ac2-bce3-f6d2c99b73b7@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <44fa564b-9c8f-4ac2-bce3-f6d2c99b73b7@suse.cz>
X-Original-Sender: dakr@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PDLf5vP9;       spf=pass
 (google.com: domain of dakr@kernel.org designates 145.40.73.55 as permitted
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

On Tue, Jul 30, 2024 at 02:15:34PM +0200, Vlastimil Babka wrote:
> On 7/30/24 3:35 AM, Danilo Krummrich wrote:
> > On Mon, Jul 29, 2024 at 09:08:16PM +0200, Danilo Krummrich wrote:
> >> On Fri, Jul 26, 2024 at 10:05:47PM +0200, Danilo Krummrich wrote:
> >>> On Fri, Jul 26, 2024 at 04:37:43PM +0200, Vlastimil Babka wrote:
> >>>> On 7/22/24 6:29 PM, Danilo Krummrich wrote:
> >>>>> Implement vrealloc() analogous to krealloc().
> >>>>>
> >>>>> Currently, krealloc() requires the caller to pass the size of the
> >>>>> previous memory allocation, which, instead, should be self-contained.
> >>>>>
> >>>>> We attempt to fix this in a subsequent patch which, in order to do so,
> >>>>> requires vrealloc().
> >>>>>
> >>>>> Besides that, we need realloc() functions for kernel allocators in Rust
> >>>>> too. With `Vec` or `KVec` respectively, potentially growing (and
> >>>>> shrinking) data structures are rather common.
> >>>>>
> >>>>> Signed-off-by: Danilo Krummrich <dakr@kernel.org>
> >>>>
> >>>> Acked-by: Vlastimil Babka <vbabka@suse.cz>
> >>>>
> >>>>> --- a/mm/vmalloc.c
> >>>>> +++ b/mm/vmalloc.c
> >>>>> @@ -4037,6 +4037,65 @@ void *vzalloc_node_noprof(unsigned long size, int node)
> >>>>>  }
> >>>>>  EXPORT_SYMBOL(vzalloc_node_noprof);
> >>>>>  
> >>>>> +/**
> >>>>> + * vrealloc - reallocate virtually contiguous memory; contents remain unchanged
> >>>>> + * @p: object to reallocate memory for
> >>>>> + * @size: the size to reallocate
> >>>>> + * @flags: the flags for the page level allocator
> >>>>> + *
> >>>>> + * The contents of the object pointed to are preserved up to the lesser of the
> >>>>> + * new and old size (__GFP_ZERO flag is effectively ignored).
> >>>>
> >>>> Well, technically not correct as we don't shrink. Get 8 pages, kvrealloc to
> >>>> 4 pages, kvrealloc back to 8 and the last 4 are not zeroed. But it's not
> >>>> new, kvrealloc() did the same before patch 2/2.
> >>>
> >>> Taking it (too) literal, it's not wrong. The contents of the object pointed to
> >>> are indeed preserved up to the lesser of the new and old size. It's just that
> >>> the rest may be "preserved" as well.
> >>>
> >>> I work on implementing shrink and grow for vrealloc(). In the meantime I think
> >>> we could probably just memset() spare memory to zero.
> >>
> >> Probably, this was a bad idea. Even with shrinking implemented we'd need to
> >> memset() potential spare memory of the last page to zero, when new_size <
> >> old_size.
> >>
> >> Analogously, the same would be true for krealloc() buckets. That's probably not
> >> worth it.
> 
> I think it could remove unexpected bad surprises with the API so why not
> do it.

We'd either need to do it *every* time we shrink an allocation on spec, or we
only do it when shrinking with __GFP_ZERO flag set, which might be a bit
counter-intuitive.

If we do it, I'd probably vote for the latter semantics. While it sounds more
error prone, it's less wasteful and enough to cover the most common case where
the actual *realloc() call is always with the same parameters, but a changing
size.

> 
> >> I think we should indeed just document that __GFP_ZERO doesn't work for
> >> re-allocating memory and start to warn about it. As already mentioned, I think
> >> we should at least gurantee that *realloc(NULL, size, flags | __GFP_ZERO) is
> >> valid, i.e. WARN_ON(p && flags & __GFP_ZERO).
> > 
> > Maybe I spoke a bit to soon with this last paragraph. I think continuously
> > gowing something with __GFP_ZERO is a legitimate use case. I just did a quick
> > grep for users of krealloc() with __GFP_ZERO and found 18 matches.
> > 
> > So, I think, at least for now, we should instead document that __GFP_ZERO is
> > only fully honored when the buffer is grown continuously (without intermediate
> > shrinking) and __GFP_ZERO is supplied in every iteration.
> > 
> > In case I miss something here, and not even this case is safe, it looks like
> > we have 18 broken users of krealloc().
> 
> +CC Feng Tang
> 
> Let's say we kmalloc(56, __GFP_ZERO), we get an object from kmalloc-64
> cache. Since commit 946fa0dbf2d89 ("mm/slub: extend redzone check to
> extra allocated kmalloc space than requested") and preceding commits, if
> slub_debug is enabled (red zoning or user tracking), only the 56 bytes
> will be zeroed. The rest will be either unknown garbage, or redzone.
> 
> Then we might e.g. krealloc(120) and get a kmalloc-128 object and 64
> bytes (result of ksize()) will be copied, including the garbage/redzone.
> I think it's fixable because when we do this in slub_debug, we also
> store the original size in the metadata, so we could read it back and
> adjust how many bytes are copied.
> 
> Then we could guarantee that if __GFP_ZERO is used consistently on
> initial kmalloc() and on krealloc() and the user doesn't corrupt the
> extra space themselves (which is a bug anyway that the redzoning is
> supposed to catch) all will be fine.

Ok, so those 18 users are indeed currently broken, but only when slub_debug is
enabled (assuming that all of those are consistently growing with __GFP_ZERO).

> 
> There might be also KASAN side to this, I see poison_kmalloc_redzone()
> is also redzoning the area between requested size and cache's object_size?
> 
> >>
> >>>
> >>> nommu would still uses krealloc() though...
> >>>
> >>>>
> >>>> But it's also fundamentally not true for krealloc(), or kvrealloc()
> >>>> switching from a kmalloc to valloc. ksize() returns the size of the kmalloc
> >>>> bucket, we don't know what was the exact prior allocation size.
> >>>
> >>> Probably a stupid question, but can't we just zero the full bucket initially and
> >>> make sure to memset() spare memory in the bucket to zero when krealloc() is
> >>> called with new_size < ksize()?
> >>>
> >>>> Worse, we
> >>>> started poisoning the padding in debug configurations, so even a
> >>>> kmalloc(__GFP_ZERO) followed by krealloc(__GFP_ZERO) can give you unexpected
> >>>> poison now...
> >>>
> >>> As in writing magics directly to the spare memory in the bucket? Which would
> >>> then also be copied over to a new buffer in __do_krealloc()?
> >>>
> >>>>
> >>>> I guess we should just document __GFP_ZERO is not honored at all for
> >>>> realloc, and maybe start even warning :/ Hopefully nobody relies on that.
> >>>
> >>> I think it'd be great to make __GFP_ZERO work in all cases. However, if that's
> >>> really not possible, I'd prefer if we could at least gurantee that
> >>> *realloc(NULL, size, flags | __GFP_ZERO) is a valid call, i.e.
> >>> WARN_ON(p && flags & __GFP_ZERO).
> >>>
> >>>>
> >>>>> + *
> >>>>> + * If @p is %NULL, vrealloc() behaves exactly like vmalloc(). If @size is 0 and
> >>>>> + * @p is not a %NULL pointer, the object pointed to is freed.
> >>>>> + *
> >>>>> + * Return: pointer to the allocated memory; %NULL if @size is zero or in case of
> >>>>> + *         failure
> >>>>> + */
> >>>>> +void *vrealloc_noprof(const void *p, size_t size, gfp_t flags)
> >>>>> +{
> >>>>> +	size_t old_size = 0;
> >>>>> +	void *n;
> >>>>> +
> >>>>> +	if (!size) {
> >>>>> +		vfree(p);
> >>>>> +		return NULL;
> >>>>> +	}
> >>>>> +
> >>>>> +	if (p) {
> >>>>> +		struct vm_struct *vm;
> >>>>> +
> >>>>> +		vm = find_vm_area(p);
> >>>>> +		if (unlikely(!vm)) {
> >>>>> +			WARN(1, "Trying to vrealloc() nonexistent vm area (%p)\n", p);
> >>>>> +			return NULL;
> >>>>> +		}
> >>>>> +
> >>>>> +		old_size = get_vm_area_size(vm);
> >>>>> +	}
> >>>>> +
> >>>>> +	if (size <= old_size) {
> >>>>> +		/*
> >>>>> +		 * TODO: Shrink the vm_area, i.e. unmap and free unused pages.
> >>>>> +		 * What would be a good heuristic for when to shrink the
> >>>>> +		 * vm_area?
> >>>>> +		 */
> >>>>> +		return (void *)p;
> >>>>> +	}
> >>>>> +
> >>>>> +	/* TODO: Grow the vm_area, i.e. allocate and map additional pages. */
> >>>>> +	n = __vmalloc_noprof(size, flags);
> >>>>> +	if (!n)
> >>>>> +		return NULL;
> >>>>> +
> >>>>> +	if (p) {
> >>>>> +		memcpy(n, p, old_size);
> >>>>> +		vfree(p);
> >>>>> +	}
> >>>>> +
> >>>>> +	return n;
> >>>>> +}
> >>>>> +
> >>>>>  #if defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA32)
> >>>>>  #define GFP_VMALLOC32 (GFP_DMA32 | GFP_KERNEL)
> >>>>>  #elif defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA)
> >>>>
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZqjnR4Wxzf-ciUGW%40pollux.
