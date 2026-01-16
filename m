Return-Path: <kasan-dev+bncBAABBV66U7FQMGQER7QGMKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 31598D2D907
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 08:57:13 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-430fd96b440sf1076103f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 23:57:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768550232; cv=pass;
        d=google.com; s=arc-20240605;
        b=F4sHTESjrENI5CydzilzDWrokIv6UGrz6Yg4lhrVOXW50AT6Z89VXD+CsM6hNYTsxr
         vNRYYz3e9DsoRELNcAbIvVEROgPivbLZL2LW8BkYFis6uoAk3Y11JCVOCueFx8WMxoV6
         gBfCE+Cz3MJZiIknC5UwFYRApAErbyMpdiuKN83/4WYw2iFYz3+tbefcl9PAug8tuXZ9
         1HNtGxVA2HkcfKE0rnGI9NU6dXXJUgqdqeHL13ay8AJzmjnenP+QHYxZEivzXZzJ8rBM
         jEM5LJ3TW52UsxaxQkCqMqTNkdyPji4GqKJuJz/bwB+vRSbmHEO0ufk0WsjHUKIctXvm
         dW/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Og23K5+aClWIEgSj+OIaP25UGGESoPDTRjvZ8uGUm4E=;
        fh=aRlZasa+TXlHF0nTZTrubg8/QSewkOAXEM3JU9Sy9Ys=;
        b=gEkaxMk9epooFXHUhs0KQKXXFLNTVgBajOcCQF3yyyEypkdOGg34d3en/MjZuG307C
         /EGczx+j9Jy6KCaoJysh1bkmNGxy6B6lGVEumZ9KwmXg5UqMku5HQKyPwtMzz8R6BC9X
         JuuuPiiLIvYZjPC/Lp2NsVUioA0xYDsqbIe2AD9NnzN01eKfDEXL80EOc3jncDtBdWcT
         kg0AC6DmyHhNHb81mA0grts9kjv1kJ+HLhr6jV8Z1KNe1ZKWnUMeVZORVAnVes5V82yM
         S9TyOIuP0MOaZ5k46fQNQbPjTJBdHSzLk94AiufYsusD7KF4KmkB4LRdo0krG5khPWry
         ZhEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TymSe3fT;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.178 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768550232; x=1769155032; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Og23K5+aClWIEgSj+OIaP25UGGESoPDTRjvZ8uGUm4E=;
        b=H/du5rYPzxI2me1qLDbaW26M+vAvS5iDB+DjaAPk9ruRoXIEEyKSnxjliSZhtFbU3N
         9OTDHpFg+vzZ/OEVdlcZf8OjEaG6StOEeAwdTBvPEEmnAnqRzMNzhP060NIajiOxV9Xi
         J8+9VePciJE6JiFy9RlGDHOdlRh1yEf9ukJ1IAzQg922MBYEro1aJv+DUcixrmXaC9+n
         XINHio7iRuDT6y8JZuhAFdBt2+JsAsGScCFtdZInEcq4DVVndX46acyEt8HJqGBNjPbY
         mowW3RtL2NJW/kwlNOoZN0il6tB8SJsm1UxjkmErJPErwnTrT2pAL02s1NrwZa9TzyUp
         3TUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768550232; x=1769155032;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Og23K5+aClWIEgSj+OIaP25UGGESoPDTRjvZ8uGUm4E=;
        b=UgS11RrRAPkjXoaTC8hXD9++use52TOH8iCCwAEg80GG1HPQQ60EAgM3ZpJHahHPlY
         I7sEHZceDe3xsKmo15ZMon28awTezyYE1p3G1eZ4wa1zQEjKKwgMLe1aO+rcrEIbZ4Fo
         w4LLD+YZ/T7KSeGBpO+6Kqr4GlhCbTY3QGTbRbHK00MAZ0s5MYM0jV+DvWPr3Ew2DAi3
         nlc5x+wSANybtPhbgbATbDu3sAdp7vI7v2g44VEO/9xBIaa2tC3mmuPAihzuzjv2LCpX
         0kReoJhihyC6rrhBDJwwMOmgpCAPie2OcOkxIODY3S8G9om991OvpmDnWpn9LHjujS2S
         DEPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUPuFI7UaRtBNYA/iY/W21VTfcU5G6FQOHdcNkcICp/ym1DMbneccD5qybjx+wNLa5YmzmtQ==@lfdr.de
X-Gm-Message-State: AOJu0YyrZtFGWULnnv3J5R6yM1wFKAhA0p4edimCNCowbVWOvrqtUrCM
	JSLclgV+ERULUXQV3KsjeG9CnuKWnWCYsDOvxw6RdWNsyHHydKQuzGfS
X-Received: by 2002:a05:600d:644e:10b0:47f:1a8d:4f30 with SMTP id 5b1f17b1804b1-4801eb0efbdmr14475835e9.26.1768550232486;
        Thu, 15 Jan 2026 23:57:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FRCLY98kh38PXKQhyhVu7ZIGJvVH2qdv/eiLPGcwy09Q=="
Received: by 2002:a05:600c:3592:b0:477:5a45:da9e with SMTP id
 5b1f17b1804b1-47f1a8df136ls11222595e9.0.-pod-prod-04-eu; Thu, 15 Jan 2026
 23:57:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUuKLzeX3FNVHO5nMFOr9OwP9c2XyS52mcm1ybSbp8yubECWDDhgAYX5almGOSpKes04N2sTTG3zP8=@googlegroups.com
X-Received: by 2002:a05:600c:6206:b0:477:8b77:155f with SMTP id 5b1f17b1804b1-4801eab5255mr20275885e9.8.1768550230948;
        Thu, 15 Jan 2026 23:57:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768550230; cv=none;
        d=google.com; s=arc-20240605;
        b=bqt5oTHRB3wzi5xQk4dMVljIAUGuekZkdehx/kkHlcxg5yJkVDoTYK1t6orF9YmoGE
         Qvmu5jpN97VNb1ataJODQq+r85JbdmMrJquv3GqmBFAXsp1pkSuJvgU4phOIXOPHdR4/
         4UnSEWUqmEgfcnxzjyMwgM3bHkxFdxAe4XxFp1WO+VTY/uNeMVgOaAxbH0sWzNPR2Uuv
         qdG4LGsZDgPAAJ4ij+qR9VNMzA/GT1wMN7JelDcbT3cF5rbIsPHqLzH8WM9PQ59Umt0H
         yVn3Lcu378d0HDjWGjjMrzAG4OEHGdkWSTSxfsuwwwApch9v2quDRX9Bk4IwH5vRxMgO
         GPRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=8PsGNXpmMoDJe1yHU7yqWS6tBazZC3oE9e62iQ9nE4c=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=SAt/HMpziW1SNEQ5QzOuE5uGOoOVXF+lCd/VqXH72dQOuSBEv4KJWvKf8C+WxVHPUj
         /oLHUkiu0l0/JY+wZPm6q07ymEqzXEdmVGTyExLjW/St9d62MwFz3CDPO5iqM4WDVu9B
         Iur1MPEUexQ0jKh/gObHrCqueeQpND84DCvCd60qdd7/BtPgmF9w2mGzC2jghpifiYMJ
         jG8AEa87320kBbVRJ7GMU8+npxqXW6L9YSszE5SLo7bN1tF4ujk9Oo3GQKmHtb17qMV8
         OtSxRUsngMKYpw6m2iFYZXTDV6oBf14rd4CxIN8gEm4CYQhLhgHTFftEU8rF1pXKXTPv
         +WtA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=TymSe3fT;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.178 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-178.mta0.migadu.com (out-178.mta0.migadu.com. [91.218.175.178])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4356994f0dcsi41759f8f.5.2026.01.15.23.57.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 23:57:10 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 91.218.175.178 as permitted sender) client-ip=91.218.175.178;
Date: Fri, 16 Jan 2026 15:56:58 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC v2 08/20] slab: add optimized sheaf refill from
 partial list
Message-ID: <5lmryxzoe2d5ywqfjwxqd63xsfq246ytb6lpkebkc3zxvu65xb@sdtiyxfez43v>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-8-98225cfb50cf@suse.cz>
 <38de0039-e0ea-41c4-a293-400798390ea1@suse.cz>
 <kp7fvhxxjyyzk47n67m4xwzgm7gxoqmgglqdvzpkcxqb26sjc4@bu4lil75nc3c>
 <bb58c778-be6b-445e-a331-ddaf04f97f0e@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bb58c778-be6b-445e-a331-ddaf04f97f0e@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=TymSe3fT;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 91.218.175.178 as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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

On Fri, Jan 16, 2026 at 08:32:00AM +0100, Vlastimil Babka wrote:
> On 1/16/26 07:27, Hao Li wrote:
> > On Thu, Jan 15, 2026 at 03:25:59PM +0100, Vlastimil Babka wrote:
> >> On 1/12/26 16:17, Vlastimil Babka wrote:
> >> > At this point we have sheaves enabled for all caches, but their refill
> >> > is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> >> > slabs - now a redundant caching layer that we are about to remove.
> >> > 
> >> > The refill will thus be done from slabs on the node partial list.
> >> > Introduce new functions that can do that in an optimized way as it's
> >> > easier than modifying the __kmem_cache_alloc_bulk() call chain.
> >> > 
> >> > Extend struct partial_context so it can return a list of slabs from the
> >> > partial list with the sum of free objects in them within the requested
> >> > min and max.
> >> > 
> >> > Introduce get_partial_node_bulk() that removes the slabs from freelist
> >> > and returns them in the list.
> >> > 
> >> > Introduce get_freelist_nofreeze() which grabs the freelist without
> >> > freezing the slab.
> >> > 
> >> > Introduce alloc_from_new_slab() which can allocate multiple objects from
> >> > a newly allocated slab where we don't need to synchronize with freeing.
> >> > In some aspects it's similar to alloc_single_from_new_slab() but assumes
> >> > the cache is a non-debug one so it can avoid some actions.
> >> > 
> >> > Introduce __refill_objects() that uses the functions above to fill an
> >> > array of objects. It has to handle the possibility that the slabs will
> >> > contain more objects that were requested, due to concurrent freeing of
> >> > objects to those slabs. When no more slabs on partial lists are
> >> > available, it will allocate new slabs. It is intended to be only used
> >> > in context where spinning is allowed, so add a WARN_ON_ONCE check there.
> >> > 
> >> > Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> >> > only refilled from contexts that allow spinning, or even blocking.
> >> > 
> >> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >> 
> >> ...
> >> 
> >> > +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
> >> > +		void **p, unsigned int count, bool allow_spin)
> >> > +{
> >> > +	unsigned int allocated = 0;
> >> > +	struct kmem_cache_node *n;
> >> > +	unsigned long flags;
> >> > +	void *object;
> >> > +
> >> > +	if (!allow_spin && (slab->objects - slab->inuse) > count) {
> >> > +
> >> > +		n = get_node(s, slab_nid(slab));
> >> > +
> >> > +		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
> >> > +			/* Unlucky, discard newly allocated slab */
> >> > +			defer_deactivate_slab(slab, NULL);
> >> 
> >> This actually does dec_slabs_node() only with slab->frozen which we don't set.
> > 
> > Hi, I think I follow the intent, but I got a little tripped up here: patch 08
> > (current patch) seems to assume "slab->frozen = 1" is already gone. That's true
> > after the whole series, but the removal only happens in patch 09.
> > 
> > Would it make sense to avoid relying on that assumption when looking at patch 08
> > in isolation?
> 
> Hm I did think it's fine. alloc_from_new_slab() introduced here is only used
> from __refill_objects() and that one doesn't set slab->frozen = 1 on the new
> slab?

Yes, exactly!

> 
> Then patch 09 switches ___slab_alloc() to alloc_from_new_slab() and at the
> same time also stops setting slab->frozen = 1 so it should be also fine.

Yes. This make sense to me.

> 
> And then 12/20 slab: remove defer_deactivate_slab() removes the frozen = 1
> treatment as nobody uses it anymore.
> 
> If there's some mistake in the above, please tell!

Everything makes sense to me. The analysis looks reasonable. Thanks!

Just a quick note - I noticed that the code in your repo for b4/sheaves-for-all
has been updated. I also saw that Harry posted the latest link and did an inline
review in his reply to [05/20].

Do you happen to plan a v3 version of this patchset? Thanks!

> 
> Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5lmryxzoe2d5ywqfjwxqd63xsfq246ytb6lpkebkc3zxvu65xb%40sdtiyxfez43v.
