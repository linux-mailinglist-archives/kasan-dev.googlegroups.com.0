Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBQNSRCNQMGQEJROIAGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C708615CCE
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Nov 2022 08:16:19 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id bq6-20020a056a000e0600b0056bcbc6720fsf8731309pfb.22
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Nov 2022 00:16:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667373377; cv=pass;
        d=google.com; s=arc-20160816;
        b=FdIuD9gmn8fxhY95WybrFkDSushKgm9fHx6cVLPBnk61idFeq1sBAQmIrPF40a1wKx
         WWjebSP/oF2AlvjhzoVZysdceOv4+EPDp+KQ2tIUCOwbP61xRI9xdUaKy3fJEAqmHQOu
         XaAMRqbye0sVSBJr6QPnYw31ar/6v4684xQjsh1505JEgVs5wXRcHN8ba1SBlcU9IPkP
         a4TYrnY4f5d7da8IK0CYuIvZoojpLS3crCBAxNNehvYIOqit9+1jlDZmKf0hI6VXrud/
         6oVjE7L7mQlbSuxV0O0J2/f1NXFNe9Qt+12tXKS7DqYuVt51OQPwDsWZ3zdBCxUFn/fF
         YD1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=LKUoKAcPRU0NlNVAWM/XeAqbltXXJou1OfkiGVPrmDw=;
        b=OTPGe7S5bkzslEMPaADhza29d70oCxM1xpUQSuvBj0uoAP3bU/jo7EBj5d4frfDkwm
         IKI795C3v/7fZAvWR8YfIGQ6fesSSqT7Z9TFlqp0CaXVedc7wp9M+YjUQWKt+Jq3H93o
         I3SFykAZWCo8Xv8Y+TDOQbb5uQbj95fSP4kMv3ZtODvLiPCCnlRbwP/v+tVdfgNaI4zm
         p7HIRVIpp/+jgq83madnz09O5XoM4rQ4rR+74c9gZUfTFkAlyBDactI51oh+r4WMOZvc
         iOVv9KySx2E1hAX8P73ATBwlSjTXG6dUo5VfPdWX8UoRB9TkEy9T/gn2F7Is5eo9y5r0
         0mWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RfYfUanU;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LKUoKAcPRU0NlNVAWM/XeAqbltXXJou1OfkiGVPrmDw=;
        b=QueoToEnN9coKvTdfa7xEhZXuFqQ7Gdi1XA8Q9ceRgIldn7hw9cJ9D+z76IQwvmXv3
         OC5CJMviWU2Vl5/VPQpFvuWo8oSpv6cByg0x75oijl32V7xkazyk3lHydHbGDGByCJUP
         7vsJiA/iCQze4/k5uZVxWyyujy80xSLjjS7ju+Dib9+tmhsEG2y4VJs5S+qDZB7yJhIh
         z7GUr4U9tQeCXTEUE/I2s68EtDKnF1eKaKTrsAdw/xrgod5HjTWw4vF2Ga+EDtv+o3RW
         tIeVMT5XipLHmx85i8LH/4kcTGjOP+fBAhvUKGQ3g1pWmtPE2AARRfNsozPlHMrdYdQ3
         wDCQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=LKUoKAcPRU0NlNVAWM/XeAqbltXXJou1OfkiGVPrmDw=;
        b=kRylUevEFSu+NZNpJt2pMIVf4fMlFL8T1o3W1xzz+Qdd53ymbCD4k+Wk1z/57o48du
         Peo1Zm88U4MlW/l1T2QKc/bYqUL/jyhwH1Meh8gIdP3Cf2+XsGrsvxkVhre9q9Hfabcp
         Yy7Qja969YnHH4Z2ejrtDUV2cAnhvmhh+9PCJ6BjBBXYkPonsPPdkKW0k7KxzsObKSOO
         v8HFPUPkPOucLUkUpgqnvLGC3gRsrnFB0sX3eY+vNcCmZvgMCRcdh/k5FZBwT+P5bwBj
         hVT0pwkrBs96dtnn88D7OdC2e7XDWTBck7QPnN8Z1qy0k/dRvLhl3Ugy17pWC6voBwoy
         uXuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LKUoKAcPRU0NlNVAWM/XeAqbltXXJou1OfkiGVPrmDw=;
        b=bvRVkX6w0z4Lj4M/5Y5rxKGkdGLeVItlBsEytXKSiqRat5FVW8hzjw157Stlvxml4t
         NgSPViDLV1iNnM6hQ7j8QMxUJ0oK+OAkZ2PkE29UDLISP0z0RRlHD0bCV8JZDaIGi90Q
         dbgF6bvFDpIXrdHV2K1tZcqN99ybjUvAzuam2XFGVldO/0aym+qAiGeQIPavgTyNzOXt
         Ylncf+2bYJxP/51D/3onND4gWffO5CJrtdnSQcWSAHWfx4tDKcxsob8I1TTlQONsk4Zd
         7+LDrM+kgUq8EsS/pxoKQq+Z3ydvGxFsP7iQr6DbW/eV9yCDyDCMrnZIia2qpnd4iHS5
         XYPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2gAfD9R15CB5Oq7DQl3y5pJf+zdbSjRYfK94a+rwRji5Auw1Ln
	WIcFjJnoHo6MfuOgRGzBwlY=
X-Google-Smtp-Source: AMsMyM4+AVCzdFzbukJYq9GX2izcJs5uWU5MtlEEJQ5hfc9/SJ+e1q1Cu7yz5f9/Ti67DSOUdFcAQw==
X-Received: by 2002:a63:69c2:0:b0:46a:eeb1:e784 with SMTP id e185-20020a6369c2000000b0046aeeb1e784mr20207708pgc.589.1667373377403;
        Wed, 02 Nov 2022 00:16:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eb81:b0:187:1dd0:1221 with SMTP id
 q1-20020a170902eb8100b001871dd01221ls6055406plg.1.-pod-prod-gmail; Wed, 02
 Nov 2022 00:16:16 -0700 (PDT)
X-Received: by 2002:a17:90b:33ce:b0:213:e25b:9448 with SMTP id lk14-20020a17090b33ce00b00213e25b9448mr15507958pjb.44.1667373376515;
        Wed, 02 Nov 2022 00:16:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667373376; cv=none;
        d=google.com; s=arc-20160816;
        b=vdoDdZ08fCJtD4aFGDnxR2naVj2Z4TtcIDWZ3kgP6FQrU9Sm5GKQk1+bCzCreNKjLi
         5tlthCUumSkWjK10q6MOLIYOIsffncFl7L7+jwLegMvm4oToYt5194QStE9nXeIb30Wb
         qbkV9MAqm0bavKSGO9seEqVTkkjvG9QLzUF3s7Bo56p4akTAvtR0NQLylbceu6I3hBKY
         8Ja8nQC2Ls6lO/JKu5uglFzOkuL5K8cR54vmK6DvBoPImobGBsZ8Rr3ClMh04Y4mOoNp
         tmqODCvdYwksdjrbjX7Hssw0O+j7+tKZlXobRNqzrb53pQqEvAneduFjFAJ3hmNnV41r
         Y5lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JxnaJtGnHY9c3pR6sfYcqGHFdJa7CTSVoKFDBdpZd/E=;
        b=M3Cy4LvAcC59b/YDr/NGu5jCCc9uCsD5ni7ezwMsdSEuhjpfX+0I7AMEVSwVGxVZmf
         MIBuJneqaV+mAvRitTOs71fG5VDmQi7wJpQDmxbUfoEt5KbZdWN2Iq/FwATHpxJaLA2a
         oYP0ePWt5GerDQivqbcoUTr4C8odkerIV2NtoQ11doEtRFR1tTzjW4n0xsmoQhdlyoSW
         IYWMqI0vpSXO+GoBM6UMveJZG0cQkvE/0B4hfrVkCz9zrb+YNDcTh/k9s/sty1LitAaB
         PlYONXow+VmHB6e0hWgHc6+NJmDtKLgAOInVyJObif2+jUFxzgUJ9EL1Ck5Dtqwdsqsw
         RRNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RfYfUanU;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id j1-20020a170902da8100b0017824ebedc5si369177plx.1.2022.11.02.00.16.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Nov 2022 00:16:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id k7so6021477pll.6
        for <kasan-dev@googlegroups.com>; Wed, 02 Nov 2022 00:16:16 -0700 (PDT)
X-Received: by 2002:a17:90a:e147:b0:213:bd97:d6b7 with SMTP id ez7-20020a17090ae14700b00213bd97d6b7mr20173753pjb.199.1667373376131;
        Wed, 02 Nov 2022 00:16:16 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id 28-20020a17090a195c00b001f8c532b93dsm747383pjh.15.2022.11.02.00.16.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Nov 2022 00:16:14 -0700 (PDT)
Date: Wed, 2 Nov 2022 16:16:06 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Feng Tang <feng.tang@intel.com>
Cc: John Thomson <lists@johnthomson.fastmail.com.au>,
	Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	"Hansen, Dave" <dave.hansen@intel.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Robin Murphy <robin.murphy@arm.com>,
	John Garry <john.garry@huawei.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	John Crispin <john@phrozen.org>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	"linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y2IZNqpABkdxxPjv@hyeyoo>
References: <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
 <Y2D4D52h5VVa8QpE@hyeyoo>
 <Y2ElURkvmGD5csMc@feng-clx>
 <70002fbe-34ec-468e-af67-97e4bf97819b@app.fastmail.com>
 <Y2IJSR6NLVyVTsDY@feng-clx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y2IJSR6NLVyVTsDY@feng-clx>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=RfYfUanU;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Nov 02, 2022 at 02:08:09PM +0800, Feng Tang wrote:
> On Tue, Nov 01, 2022 at 07:39:13PM +0000, John Thomson wrote:
> > 
> > 
> > On Tue, 1 Nov 2022, at 13:55, Feng Tang wrote:
> > > On Tue, Nov 01, 2022 at 06:42:23PM +0800, Hyeonggon Yoo wrote:
> > >> setup_arch() is too early to use slab allocators.
> > >> I think slab received NULL pointer because kmalloc is not initialized.
> > >> 
> > >> It seems arch/mips/ralink/mt7621.c is using slab too early.
> > >
> > > Cool! it is finally root caused :) Thanks!
> > >
> > > The following patch should solve it and give it a warning message, though
> > > I'm not sure if there is other holes.  
> > >
> > > Thanks,
> > > Feng
> > >
> > > ---
> > > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > > index 33b1886b06eb..429c21b7ecbc 100644
> > > --- a/mm/slab_common.c
> > > +++ b/mm/slab_common.c
> > > @@ -1043,7 +1043,14 @@ size_t __ksize(const void *object)
> > >  #ifdef CONFIG_TRACING
> > >  void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
> > >  {
> > > -	void *ret = __kmem_cache_alloc_node(s, gfpflags, NUMA_NO_NODE,
> > > +	void *ret;
> > > +
> > > +	if (unlikely(ZERO_OR_NULL_PTR(s))) {
> > > +		WARN_ON_ONCE(1);
> > > +		return s;
> > > +	}
> > > +
> > > +	ret = __kmem_cache_alloc_node(s, gfpflags, NUMA_NO_NODE,
> > >  					    size, _RET_IP_);
> > > 
> > >  	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, NUMA_NO_NODE);
> > > diff --git a/mm/slub.c b/mm/slub.c
> > > index 157527d7101b..85d24bb6eda7 100644
> > > --- a/mm/slub.c
> > > +++ b/mm/slub.c
> > > @@ -3410,8 +3410,14 @@ static __always_inline
> > >  void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
> > >  			     gfp_t gfpflags)
> > >  {
> > > -	void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
> > > +	void *ret;
> > > 
> > > +	if (unlikely(ZERO_OR_NULL_PTR(s))) {
> > > +		WARN_ON_ONCE(1);
> > > +		return s;
> > > +	}
> > > +

Thank you for suggestion!

I think the holes are:
	kmalloc_node_trace(), kmem_cache_alloc_node(), __do_kmalloc_node()

And want to suggest:
	What about using VM_WARN_ON_ONCE() instead?

> > > +	ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
> > >  	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
> > > 
> > >  	return ret;
> > 
> > Yes, thank you, that patch atop v6.1-rc3 lets me boot, and shows the warning and stack dump.
> > Will you submit that, or how do we want to proceed?
> 
> Thanks for confirming. I wanted to wait for Vlastimil, Hyeonggon and
> other developer's opinion. And yes, I can also post a more formal one.
> 
> > transfer started ......................................... transfer ok, time=2.11s
> > setting up elf image... OK
> > jumping to kernel code
> > zimage at:     80B842A0 810B4BC0
> > 
> > Uncompressing Linux at load address 80001000
> > 
> > Copy device tree to address  80B80EE0
> > 
> > Now, booting the kernel...
> > 
> > [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #73 SMP Wed Nov  2 05:10:01 AEST 2022
> > [    0.000000] ------------[ cut here ]------------
> > [    0.000000] WARNING: CPU: 0 PID: 0 at mm/slub.c:3416 kmem_cache_alloc+0x5a4/0x5e8
> > [    0.000000] Modules linked in:
> > [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc3+ #73
> > [    0.000000] Stack : 810fff78 80084d98 00000000 00000004 00000000 00000000 80889d04 80c90000
> > [    0.000000]         80920000 807bd328 8089d368 80923bd3 00000000 00000001 80889cb0 00000000
> > [    0.000000]         00000000 00000000 807bd328 8084bcb1 00000002 00000002 00000001 6d6f4320
> > [    0.000000]         00000000 80c97d3d 80c97d68 fffffffc 807bd328 00000000 00000000 00000000
> > [    0.000000]         00000000 a0000000 80910000 8110a0b4 00000000 00000020 80010000 80010000
> > [    0.000000]         ...
> > [    0.000000] Call Trace:
> > [    0.000000] [<80008260>] show_stack+0x28/0xf0
> > [    0.000000] [<8070c958>] dump_stack_lvl+0x60/0x80
> > [    0.000000] [<8002e184>] __warn+0xc4/0xf8
> > [    0.000000] [<8002e210>] warn_slowpath_fmt+0x58/0xa4
> > [    0.000000] [<801c0fac>] kmem_cache_alloc+0x5a4/0x5e8
> > [    0.000000] [<8092856c>] prom_soc_init+0x1fc/0x2b4
> > [    0.000000] [<80928060>] prom_init+0x44/0xf0
> > [    0.000000] [<80929214>] setup_arch+0x4c/0x6a8
> > [    0.000000] [<809257e0>] start_kernel+0x88/0x7c0
> > [    0.000000] 
> > [    0.000000] ---[ end trace 0000000000000000 ]---
> > [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
> > [    0.000000] printk: bootconsole [early0] enabled
> > 
> > Thank you for working through this with me.
> > I will try to address the root cause in mt7621.c.
> > It looks like other arch/** soc_device_register users use postcore_initcall, device_initcall,
> > or the ARM DT_MACHINE_START .init_machine. A quick hack to use postcore_initcall in mt7621
> > avoided this zero ptr kmem_cache passed to kmem_cache_alloc_lru.
> 
> If IIUC, the prom_soc_init() is only called once in kernel, can the
> 'soc_dev_attr' just be defined as a global data structure instead
> of calling kzalloc(), as its size is small only containing 7 pointers.

But soc_device_registers() too uses kmalloc. I think calling it
after slab initialization will be best solution - if that is correct.

> 
> Thanks,
> Feng
> 

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2IZNqpABkdxxPjv%40hyeyoo.
