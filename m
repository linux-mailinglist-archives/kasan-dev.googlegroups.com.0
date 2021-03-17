Return-Path: <kasan-dev+bncBDBIVGHA6UJBBW4AY6BAMGQEQIH6FSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id DA3A533EBA9
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 09:39:55 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id a2sf18941858edx.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 01:39:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615970395; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q4/9FiDmoPLwq0EBlEYEjg2AzP64nz7J5xQNTsuWQXuPdm/K5OpgKtKxhcL9UwNNv+
         SR0VJ9h7t6f4i24Xiefh67gyEIA0hjwaT670NuU4EoJ1+t4tukO3vWWI39PCX6RfOB0V
         MZpiZ+cknYiOMkx9DjLHMcqg4DUZrROc5iiiYofELi7qN1t81+54Z84GXLQ2viwg1eCU
         NX37bxamLg3MunI2WrakSibcNCurUpyjq6d9PnCoQTAWkUpmmuYS5wdsW2iOLJ1/nilr
         yMMoowZ8Finbsv/M9/Us/2xcq+U+XjzRjHl9a+AZ1ahEI4SFbq9R/5i0h4vK6pw73bFO
         w4LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=FFofq2RX9wMtzFsH53ewq+NkU7JAzMH/IDE0yQJAmZI=;
        b=EAqoZMUbOP3SOoFn8uRp/gawSExE0bsgo7nVtXSX2PhQhkp+hw5GjWNVidyfzaGrbx
         1Y+rzwTjX3t/YNbFeSzl0wh4ySpkknoiD9JuSnJwk6S+u3ucF5BmkipDGyRU4YGUmVMR
         CzgkkF5opnT7ey3/PYVrnnAzD3vzvgXvz5clcknQgk6GdydHzqCoqNofjz+azuF0W8E8
         2cBX6fsOuX4CV7/mrdqrzfvq/siuGFNjAztqNjINDddWz6no/mLMArv/XIPHW33NTS1q
         b3EbqYLYGVaGEXQv4J1dR2JvRa9UVaaQgYi8QUdNdGiJtT64tbyxYTu+1YCKb//lF7Gz
         HmqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=lhenriques@suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FFofq2RX9wMtzFsH53ewq+NkU7JAzMH/IDE0yQJAmZI=;
        b=j5YVG+SeBkOzLOLl8WWmVhjdlH6icFZGIPMUFCqUJGY+ujIzB9w6nDuuw8seAQcIJM
         X0wh3h51ubt5kfCuAgYco1eFY9sFTJdsv88mtt0J9xdXq8MhHTsmgfJD989rNQsbdB29
         OF9v/i2+NOTTz1u+5qGL2369we26E0kxbL2AApbWl6oXZGP2YuIzTfL1N50Is4I1ZCTC
         qrtVgu+sMbnw6BU4cXs3EIPp+fIlaMx0DPXgbVMnw4PMu3a5akKb11AS1+lfVchGO4w8
         zrMfkzzSN0gidzIB9hIOX8uirXSoOzsiAhexcR9edUPehekRE7S7HelkVayPVPvjSJOt
         OLiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FFofq2RX9wMtzFsH53ewq+NkU7JAzMH/IDE0yQJAmZI=;
        b=uCvw0G05yEyWFl77o6A1azjogLchmGslh2zq4wQSyymNDsSMDMDU5vztzLHoQpbQJF
         N6y6nbNDhNXB7buNzEI3BdHrrtF6esf1RZpDt7RNEJP47H5D2r0td4K8xHsv2fwjsiZY
         eL5zk/w5JVsuOqaCtHkkXWfcootToOqEeyRGUwaGjSAim5TCc0IhmgZC4tutq3OOzQZo
         KvGucGR0cdhNffP8kHby2awLSPcrdGxqitBw66SECzsouQt9SyskLBe4tUQ9UJYzALcJ
         qEuwLgk8zynbyZueEPCjqJzaMHSzvFr+/BoqsBXxL8VsmDpoIW0MAiVWhFBaw2net3Yb
         Ds+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322tMcBGn4VFYaqtU1hAyJf2F/2pKer60HRA4dyh4u+DCHOcroR
	Z892eA1CK2TEb73h/TYjKJU=
X-Google-Smtp-Source: ABdhPJzn4cqn1sFrkDFLdBvmPR17r+RbrtCWsDZH8k11SF8NzvRONW3jwaFcq51sORYAOVa9XgRAMw==
X-Received: by 2002:a17:906:a8a:: with SMTP id y10mr35194089ejf.288.1615970395465;
        Wed, 17 Mar 2021 01:39:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1553:: with SMTP id c19ls9938752ejd.1.gmail; Wed, 17
 Mar 2021 01:39:54 -0700 (PDT)
X-Received: by 2002:a17:906:7c48:: with SMTP id g8mr34548738ejp.138.1615970394536;
        Wed, 17 Mar 2021 01:39:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615970394; cv=none;
        d=google.com; s=arc-20160816;
        b=fzQnyVFDXMaFOyuKyfqL8m2XMibbSCzuh5MEiX/YbsZMb0m1mpMSprhudGHeO93wgO
         yhFEmkt9m3/+x5YN0UGQwRfaV8XivMgGkq5W7d4kVTc/gtne37fbQOEF6oto/CqvKHXV
         rdxfDQWgyTRoAA18jqBya9TgjhODuWXz6FQQxAjpAVm0ado+49u6C8ZzV+0lVM7LQwJR
         HK8+BejomgKx5of/6ilCWQKd+kboBccdNgLaTH3GuAmm13N5KqAQm/h1J1Vgj2guVU/T
         qjwOiid9p5jlSJ0CU6qSoEh4e4Xpqup4zBE5vo5B8WFxDfJAgtFnhPayC+yPBqoqCIQq
         MXPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=AlAUH7bwdrjivrT9uZ+CR+sH5fqe0zHXBVXal3/uAd0=;
        b=lNyoP+PrfsQ4lPKhyqQmaoS0pC8ggRYXj8hTez/+Ko4+05TIozKAxi59aXBXb8pBNw
         oLdOzemBigAcAr3B35fqXrp8LCcj/d1XbtrQKkPN5OSgzcf5pkaa0CroJdgIsccNaFoC
         CFiScLgSsNv8U0nez9V+9J1MCABf+Yu2+GrAEjnAs0Jz85D5H+wQV6IpdasXVB3gfW58
         UJQQ5ezEAimZ7JLT8Hk2DCgFQz8BA85ypUrZG/vlklRw3i1cWt4G0GbHX4WpjYsOh4n9
         1lZrDUKGclYyQ4eWwNhYCSWS4TpiZ3nB5pMfK9vZmwEju5+ahkIJi7gGmsopyxAytyFJ
         BH/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=lhenriques@suse.de
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id r21si278815ejo.0.2021.03.17.01.39.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Mar 2021 01:39:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 0AB47AE47;
	Wed, 17 Mar 2021 08:39:54 +0000 (UTC)
Received: from localhost (brahms [local])
	by brahms (OpenSMTPD) with ESMTPA id 090c966d;
	Wed, 17 Mar 2021 08:41:08 +0000 (UTC)
Date: Wed, 17 Mar 2021 08:41:08 +0000
From: Luis Henriques <lhenriques@suse.de>
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: Issue with kfence and kmemleak
Message-ID: <YFHApOWeDRWncdrQ@suse.de>
References: <YFDf6iKH1p/jGnM0@suse.de>
 <YFDrGL45JxFHyajD@elver.google.com>
 <20210316181938.GA28565@arm.com>
 <YFD9JEdQNI1TqSuL@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <YFD9JEdQNI1TqSuL@elver.google.com>
X-Original-Sender: lhenriques@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as
 permitted sender) smtp.mailfrom=lhenriques@suse.de
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

On Tue, Mar 16, 2021 at 07:47:00PM +0100, Marco Elver wrote:
> On Tue, Mar 16, 2021 at 06:19PM +0000, Catalin Marinas wrote:
> > On Tue, Mar 16, 2021 at 06:30:00PM +0100, Marco Elver wrote:
> > > On Tue, Mar 16, 2021 at 04:42PM +0000, Luis Henriques wrote:
> > > > This is probably a known issue, but just in case: looks like it's n=
ot
> > > > possible to use kmemleak when kfence is enabled:
> > > >=20
> > > > [    0.272136] kmemleak: Cannot insert 0xffff888236e02f00 into the =
object search tree (overlaps existing)
> > > > [    0.272136] CPU: 0 PID: 8 Comm: kthreadd Not tainted 5.12.0-rc3+=
 #92
> > > > [    0.272136] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996=
), BIOS rel-1.14.0-0-g155821a-rebuilt.opensuse.org 04/01/2014
> > > > [    0.272136] Call Trace:
> > > > [    0.272136]  dump_stack+0x6d/0x89
> > > > [    0.272136]  create_object.isra.0.cold+0x40/0x62
> > > > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > > > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > > > [    0.272136]  kmem_cache_alloc_trace+0x110/0x2f0
> > > > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > > > [    0.272136]  kthread+0x3f/0x150
> > > > [    0.272136]  ? lockdep_hardirqs_on_prepare+0xd4/0x170
> > > > [    0.272136]  ? __kthread_bind_mask+0x60/0x60
> > > > [    0.272136]  ret_from_fork+0x22/0x30
> > > > [    0.272136] kmemleak: Kernel memory leak detector disabled
> > > > [    0.272136] kmemleak: Object 0xffff888236e00000 (size 2097152):
> > > > [    0.272136] kmemleak:   comm "swapper", pid 0, jiffies 429489229=
6
> > > > [    0.272136] kmemleak:   min_count =3D 0
> > > > [    0.272136] kmemleak:   count =3D 0
> > > > [    0.272136] kmemleak:   flags =3D 0x1
> > > > [    0.272136] kmemleak:   checksum =3D 0
> > > > [    0.272136] kmemleak:   backtrace:
> > > > [    0.272136]      memblock_alloc_internal+0x6d/0xb0
> > > > [    0.272136]      memblock_alloc_try_nid+0x6c/0x8a
> > > > [    0.272136]      kfence_alloc_pool+0x26/0x3f
> > > > [    0.272136]      start_kernel+0x242/0x548
> > > > [    0.272136]      secondary_startup_64_no_verify+0xb0/0xbb
> > > >=20
> > > > I've tried the hack below but it didn't really helped.  Obviously I=
 don't
> > > > really understand what's going on ;-)  But I think the reason for t=
his
> > > > patch not working as (I) expected is because kfence is initialised
> > > > *before* kmemleak.
> > > >=20
> > > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > > index 3b8ec938470a..b4ffd7695268 100644
> > > > --- a/mm/kfence/core.c
> > > > +++ b/mm/kfence/core.c
> > > > @@ -631,6 +631,9 @@ void __init kfence_alloc_pool(void)
> > > > =20
> > > >  	if (!__kfence_pool)
> > > >  		pr_err("failed to allocate pool\n");
> > > > +	kmemleak_no_scan(__kfence_pool);
> > > >  }
> > >=20
> > > Can you try the below patch?
> > >=20
> > > Thanks,
> > > -- Marco
> > >=20
> > > ------ >8 ------
> > >=20
> > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > index f7106f28443d..5891019721f6 100644
> > > --- a/mm/kfence/core.c
> > > +++ b/mm/kfence/core.c
> > > @@ -12,6 +12,7 @@
> > >  #include <linux/debugfs.h>
> > >  #include <linux/kcsan-checks.h>
> > >  #include <linux/kfence.h>
> > > +#include <linux/kmemleak.h>
> > >  #include <linux/list.h>
> > >  #include <linux/lockdep.h>
> > >  #include <linux/memblock.h>
> > > @@ -481,6 +482,13 @@ static bool __init kfence_init_pool(void)
> > >  		addr +=3D 2 * PAGE_SIZE;
> > >  	}
> > > =20
> > > +	/*
> > > +	 * The pool is live and will never be deallocated from this point o=
n;
> > > +	 * tell kmemleak this is now free memory, so that later allocations=
 can
> > > +	 * correctly be tracked.
> > > +	 */
> > > +	kmemleak_free_part_phys(__pa(__kfence_pool), KFENCE_POOL_SIZE);
> >=20
> > I presume this pool does not refer any objects that are only tracked
> > through pool pointers.
>=20
> No, at this point this memory should not have been touched by anything.
>=20
> > kmemleak_free() (or *_free_part) should work, no need for the _phys
> > variant (which converts it back with __va).
>=20
> Will fix.
>=20
> > Since we normally use kmemleak_ignore() (or no_scan) for objects we
> > don't care about, I'd expand the comment that this object needs to be
> > removed from the kmemleak object tree as it will overlap with subsequen=
t
> > allocations handled by kfence which return pointers within this range.
>=20
> One thing I've just run into: "BUG: KFENCE: out-of-bounds read in
> scan_block+0x6b/0x170 mm/kmemleak.c:1244"

FWIW, I just saw this as well.  It doesn't happen every time, but yeah I
missed it in my initial testing.

Cheers,
--
Lu=C3=ADs

>=20
> Probably because kmemleak is passed the rounded size for the size-class,
> and not the real allocation size. Can this be fixed with
> kmemleak_ignore() only called on the KFENCE guard pages?
>=20
> I'd like kmemleak to scan the valid portion of an object allocated
> through KFENCE, but no further than that.
>=20
> Or do we need to fix the size if it's a kfence object:
>=20
> diff --git a/mm/kmemleak.c b/mm/kmemleak.c
> index c0014d3b91c1..fe6e3ae8e8c6 100644
> --- a/mm/kmemleak.c
> +++ b/mm/kmemleak.c
> @@ -97,6 +97,7 @@
>  #include <linux/atomic.h>
> =20
>  #include <linux/kasan.h>
> +#include <linux/kfence.h>
>  #include <linux/kmemleak.h>
>  #include <linux/memory_hotplug.h>
> =20
> @@ -589,7 +590,7 @@ static struct kmemleak_object *create_object(unsigned=
 long ptr, size_t size,
>  	atomic_set(&object->use_count, 1);
>  	object->flags =3D OBJECT_ALLOCATED;
>  	object->pointer =3D ptr;
> -	object->size =3D size;
> +	object->size =3D kfence_ksize((void *)ptr) ?: size;
>  	object->excess_ref =3D 0;
>  	object->min_count =3D min_count;
>  	object->count =3D 0;			/* white color initially */
>=20
>=20
> The alternative is to call kfence_ksize() in slab_post_alloc_hook() when
> calling kmemleak_alloc.
>=20
> Do you have a preference?
>=20
> Thanks,
> -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YFHApOWeDRWncdrQ%40suse.de.
