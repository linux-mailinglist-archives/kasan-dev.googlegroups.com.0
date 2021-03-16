Return-Path: <kasan-dev+bncBDBIVGHA6UJBBM63YOBAMGQE4AYF3OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3916933DB1B
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 18:41:08 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id k4sf13869072ljg.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 10:41:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615916467; cv=pass;
        d=google.com; s=arc-20160816;
        b=AzaxKmypgbs6lJBUVAvKeCKmwS5EHsWIwbZg2qdwnH+GQgmqghf+OSl+4L34iYeiFu
         mGnuCKKHyWYMlQBjXopzpBAt5M4uf61ZT93ZVB9bfWnT4ZywNJLpgBm4W2RFTxshuuOV
         tOcybYA7x4eSKBYA7RoAN8/zMwSpCi7nRTs1s7uqCzO6wYSGeLQhZWkcVrvXYJbb9psy
         J/cJfRKT/f3pff5Yvq6ROVJ4Etdwyqf6NJokhKUALcx5HPKYEwOX/VNIzPz2KMlnv09B
         igLTIfFtsMamZf52/PCdtc2jasW1lshY/fIq5m05ygGEy1Zt3mrv33rJ5oKJuc0RHFqo
         0cWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=E9SneIiYf/rP1dRxhR66UW6iZDDEHCCZyyahbAeBZ5s=;
        b=An56TQxm4SxZAPdlRh63rReSv2NrCIuIgPYN/Z4YWjb3rBZ9LoYaqxp3fxlngyhPlV
         1I1RQzlJSegphtRTz8LNaX8vlXiT6HxXfVsRKSqq1GuJ+uNbjMwAXIvuQUHyeyyko5tq
         F9CPE80yJwq0VDRF3y9KdrSzvw72M61gdlogl8iSt8k+1XV88UmkyIAIyZJ/yhj8puzM
         Q9NQ0l2dbIZoDkj2RY733rF0dxMDEFGzmFzz0Xzu4DWDCcuLAp3djEMu/lAvClLejYbv
         olrR2roRdgrrSa8qCJ+wGhjtE2EBL1pCiz+t6omY4qCNfhF7RFicWOuhKqvqkodi0U0s
         aUCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=lhenriques@suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E9SneIiYf/rP1dRxhR66UW6iZDDEHCCZyyahbAeBZ5s=;
        b=rPFaxMVNEPQztiVd4IvjpYT8ebaeDpgRNYNWXgTMZV5fpYEjf9Vail/ckuksWfJ2ad
         H6xkFJPyAOaXpIMt/tJ7/30S5i/P8Cm0mRK5uRRf163pNJY1wurPo1v7Zb+DR6MpJ1Eo
         l5c5kAea1Tm1zzxApAgx3tf7sYK15xnEVLEwAIELVzIzQMKiK5tgRvGpheBGdT5GgjrW
         skTSDYLBzN7ggOAwRvc2RHehdIYlS8X16z8k5w2uyFoWS8fgaAIwnGtQl0y/mJ0E2lok
         S9xnDhz6nxSoOgOs3k7v58/lBp5nV8Ou+aNLbQVTYbka4zjT7+a6hD7uQu+Xzz35J7WS
         ycdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E9SneIiYf/rP1dRxhR66UW6iZDDEHCCZyyahbAeBZ5s=;
        b=lHuejGWa0NraTT3SyUuBKKfWnn6Sl2sizxINLmL2CtPzts5Uz658QTb4I2ZzkGeQpw
         sE3xFeK0LRnNe5Dm+eD2hN9SNSwg/n0g1DAgvzvbOwXDS03pv49HkxppmRPCbL3Mh2Bz
         aC2O5D+bRW98nhWU5WhAxqjadIbeDycA0cygbVm+kydicZRwyxgJ7V6UrJxHXfUpEsWp
         hIcKiCklc+ynlY2HbNZ4MYj3xz9PeZ0YXWFQ4G/e3wxyC+M1mpy2VOqqHwwnoK6Y/Quf
         1WJUMaWmySjWOFSgJJ4HH4XAkf8nxo2i6Op/r1E2FsddzTlepcnzJ16Y0L+CY72mVy6Y
         jRdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532WvK8OOcJNXHaas3H9TFVh1HqTAQG22KJnx0iiLJwBRF+h4gE3
	q1eRP4Nn2sDOOcItiNm8bQU=
X-Google-Smtp-Source: ABdhPJzpeRxAKGllSCafEYfHtTjcuyA1tO9zgfyatvhhxA1urPLTo1Ywc2bjEAN4qDK2/gGMHFKkkw==
X-Received: by 2002:a19:607:: with SMTP id 7mr12160368lfg.433.1615916467797;
        Tue, 16 Mar 2021 10:41:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls4705705lff.1.gmail; Tue, 16
 Mar 2021 10:41:06 -0700 (PDT)
X-Received: by 2002:ac2:48ab:: with SMTP id u11mr11732325lfg.79.1615916466709;
        Tue, 16 Mar 2021 10:41:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615916466; cv=none;
        d=google.com; s=arc-20160816;
        b=dlf5UZ/DrC8Wvi1Qk2gMVeF0J5Ma0eJP5LEBzhDS2Ld6fcuwRyQfT6GBt7zgpUIVDo
         0DhN+sgh72MiA+CWtAF5IYplEKhs6Iri44cJlGZrnNSeU960krAz8gRFTv/IL+huh0Gv
         eGoB2cyRZ4QJbMxZiWrL9to8chWYymOT2K5vi4Ba4MQLxxq6J/8p2z3LDUN7RNEJXxsk
         41ooGiPLETAJUDy1frLM6VGZ0d9ciOpLGhKJGIh3Rt9qpBO1tp4BMPIh165jqL9M7TFi
         ff5oFuM9YZZK/Wk27tsohHvdEUuT7yE5wawYEYfRKN2L8A8OAYwQxoYMpSJYGzf6pEWe
         21DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=eyrARzBmKQXtVBzU/YrZtOZnkyW/Z8yY4+R8daqS+I8=;
        b=uzDpdDF86EUeBwrLkKj0ReCVjOXRCmxW28VItYHJ2XzLLLTym91razCi5g4Ukuk/60
         b60BhA02HgqVeCA7EvLp633WGeGbBGn/2FisK5y8iMmwRfkgpR3hcKrWQ7XzL3YGOakn
         RciRxDJl8INXOC/KzBmZFdHE25OhFDDzq/VtA66/3Do5wIu7/uFz/ng6QCSruJpXGrfD
         97U69Q1fjiIGYDGb7BV0PQ/ceBl9o70egoXLBDh58aTSiLnZS9VKzzQCcwpgFGcNMO5S
         bXoJRybAZFsCtSMZWW/caUBJqrUMZVJ+jzMyRaXSyrPIHTFqe1M1a2+UzK0jHAreOqiC
         XLUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=lhenriques@suse.de
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id z2si659089ljm.0.2021.03.16.10.41.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Mar 2021 10:41:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of lhenriques@suse.de designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id D90A1AC1F;
	Tue, 16 Mar 2021 17:41:05 +0000 (UTC)
Received: from localhost (brahms [local])
	by brahms (OpenSMTPD) with ESMTPA id f6ee1319;
	Tue, 16 Mar 2021 17:42:20 +0000 (UTC)
Date: Tue, 16 Mar 2021 17:42:20 +0000
From: Luis Henriques <lhenriques@suse.de>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: Issue with kfence and kmemleak
Message-ID: <YFDt/PunpQydUAq/@suse.de>
References: <YFDf6iKH1p/jGnM0@suse.de>
 <YFDrGL45JxFHyajD@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <YFDrGL45JxFHyajD@elver.google.com>
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

On Tue, Mar 16, 2021 at 06:30:00PM +0100, Marco Elver wrote:
> On Tue, Mar 16, 2021 at 04:42PM +0000, Luis Henriques wrote:
> > Hi!
> >=20
> > This is probably a known issue, but just in case: looks like it's not
> > possible to use kmemleak when kfence is enabled:
>=20
> Thanks for spotting this.
>=20
> > [    0.272136] kmemleak: Cannot insert 0xffff888236e02f00 into the obje=
ct search tree (overlaps existing)
> > [    0.272136] CPU: 0 PID: 8 Comm: kthreadd Not tainted 5.12.0-rc3+ #92
> > [    0.272136] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), B=
IOS rel-1.14.0-0-g155821a-rebuilt.opensuse.org 04/01/2014
> > [    0.272136] Call Trace:
> > [    0.272136]  dump_stack+0x6d/0x89
> > [    0.272136]  create_object.isra.0.cold+0x40/0x62
> > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > [    0.272136]  kmem_cache_alloc_trace+0x110/0x2f0
> > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > [    0.272136]  kthread+0x3f/0x150
> > [    0.272136]  ? lockdep_hardirqs_on_prepare+0xd4/0x170
> > [    0.272136]  ? __kthread_bind_mask+0x60/0x60
> > [    0.272136]  ret_from_fork+0x22/0x30
> > [    0.272136] kmemleak: Kernel memory leak detector disabled
> > [    0.272136] kmemleak: Object 0xffff888236e00000 (size 2097152):
> > [    0.272136] kmemleak:   comm "swapper", pid 0, jiffies 4294892296
> > [    0.272136] kmemleak:   min_count =3D 0
> > [    0.272136] kmemleak:   count =3D 0
> > [    0.272136] kmemleak:   flags =3D 0x1
> > [    0.272136] kmemleak:   checksum =3D 0
> > [    0.272136] kmemleak:   backtrace:
> > [    0.272136]      memblock_alloc_internal+0x6d/0xb0
> > [    0.272136]      memblock_alloc_try_nid+0x6c/0x8a
> > [    0.272136]      kfence_alloc_pool+0x26/0x3f
> > [    0.272136]      start_kernel+0x242/0x548
> > [    0.272136]      secondary_startup_64_no_verify+0xb0/0xbb
> >=20
> > I've tried the hack below but it didn't really helped.  Obviously I don=
't
> > really understand what's going on ;-)  But I think the reason for this
> > patch not working as (I) expected is because kfence is initialised
> > *before* kmemleak.
> >=20
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index 3b8ec938470a..b4ffd7695268 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -631,6 +631,9 @@ void __init kfence_alloc_pool(void)
> > =20
> >  	if (!__kfence_pool)
> >  		pr_err("failed to allocate pool\n");
> > +	kmemleak_no_scan(__kfence_pool);
> >  }
>=20
> Can you try the below patch?

Yep, that seems to fix the issue.  Feel free to add my Tested-by.  Thanks!

Cheers,
--
Lu=C3=ADs

>=20
> Thanks,
> -- Marco
>=20
> ------ >8 ------
>=20
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index f7106f28443d..5891019721f6 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -12,6 +12,7 @@
>  #include <linux/debugfs.h>
>  #include <linux/kcsan-checks.h>
>  #include <linux/kfence.h>
> +#include <linux/kmemleak.h>
>  #include <linux/list.h>
>  #include <linux/lockdep.h>
>  #include <linux/memblock.h>
> @@ -481,6 +482,13 @@ static bool __init kfence_init_pool(void)
>  		addr +=3D 2 * PAGE_SIZE;
>  	}
> =20
> +	/*
> +	 * The pool is live and will never be deallocated from this point on;
> +	 * tell kmemleak this is now free memory, so that later allocations can
> +	 * correctly be tracked.
> +	 */
> +	kmemleak_free_part_phys(__pa(__kfence_pool), KFENCE_POOL_SIZE);
> +
>  	return true;
> =20
>  err:

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YFDt/PunpQydUAq/%40suse.de.
