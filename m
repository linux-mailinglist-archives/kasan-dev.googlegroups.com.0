Return-Path: <kasan-dev+bncBDK7LR5URMGRBXWVW6DAMGQEMCHYN3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6902A3ADA11
	for <lists+kasan-dev@lfdr.de>; Sat, 19 Jun 2021 15:02:23 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id q7-20020aa7cc070000b029038f59dab1c5sf4893734edt.23
        for <lists+kasan-dev@lfdr.de>; Sat, 19 Jun 2021 06:02:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624107743; cv=pass;
        d=google.com; s=arc-20160816;
        b=U/MHrUk66531wpi4SeOHVoRbXxU+HKAD0UN/XG+x8Vd7L16dxRtUcv2ud7/SGI5Gg6
         dTHnFdqEIXaQCXUAkwCM1hdlpa5VCebVyh1fDt83pNBUX0qEbP4OV1VHqKUv2pvX4e/0
         kz7CMG1gvi3oUuiAvxVNdXl2q8YmkfjK5k4We1oMetJBMOxAv8NxzRqdhSZ6Dgr2nZWm
         x1Pv9Eba0qhbUAqrEqwHctF/0MQeSXl69iu+YOWmWOSgiZ+jbPaNtoa7THbmI7HhWyzC
         R+JwrC4QU9PMfZTSpJuq8FfsGKIsWUgHlzXzuVZH5XQPLsmfD20R34awHG/jf9LRiJjA
         o2tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:dkim-signature:dkim-signature;
        bh=ng1jT+iULeswU8NpMwu5RS8+5KzIEAsIE6Qf4nO8E7c=;
        b=e/CavhgLYAXYrZZCbwX/YLEUAkA8O4jfGTwpSOkncCt7Qto/EbgubNoTOgjFsSo2Vg
         53+woOEODthYiscNNE5cE89YDgefiz0ZKuoSadVrHYN79CfcG+cXzSbEOYAOFpgSNpVJ
         G19mxfhiytutQlo6d0KKmomBbD9i41oJYhqUn/2U19+fK02qkM/08c32IEqgjg1dPfph
         Q/rUQydb8nC2tkPTrajaH3+zR+jqA1joi7dQzYQVW00w4N7LGCq0zX4PZle2Brh30SPt
         JVGhh/XlHoNt9Heye4CQ9mbjU4vJyCKhc7E/R0pnNMbXPIqSSnSbG1rPycO7NatRHAFP
         Z89g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gAsCSsWa;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ng1jT+iULeswU8NpMwu5RS8+5KzIEAsIE6Qf4nO8E7c=;
        b=dTg50IEXr4+154QqsTB+3ALhb5ZEpKTy+0yWe/9yPG4m8vKo1HgWK1/RgOkv0VLm3v
         KmBpsS72Eay5FFt/Uo/oQifIWGYs5uhHXa/IhiF6gXcjMSCZ8toK6NOf3uFWs8mmthkN
         beR1b2RMLyhllyIPxVJeADTxyJtPGnNk60llRKx3+UxHeE2qeLAAUyT0Iq8OoXsVCPG+
         2XjnsTeDeDYhkgX0SJR9SsMJuIgXINfrqeaWFFaHt7DbD3rDAoqVPCbLhEP77H18UsUJ
         QEznMpo32OA+7WOF9NReLmvSqK4M6gQRtn4e4mgFqH41/8/5G308EpZ5vHSrNgkvnunZ
         mt9g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ng1jT+iULeswU8NpMwu5RS8+5KzIEAsIE6Qf4nO8E7c=;
        b=qU/PszKYntJZi2eBtsWefq/M76Welv6UG6SHnP17S3Xp1klmwOTB7pz+SxBeTLhUUk
         u2urdAtHWVaZE/ScaJOVY9C/qe/GL5Nme04e07iPnZWvJ6MtHui7NSl6J5lmSW0YOHh1
         5tfF/wsXxTONUin6xLgjF72JxR3mr5V+PU2jyS2/SwhhtCAmbCrClKXExIP7JM+IJM7S
         Kze2xO3cVCwBDG2eFls+lR1q3sZFRyhav7JzC7yhxghH7rnlIIMgbu2a7CssfclQ2HT4
         BS806jE+wbdsy8FyRp/+XDx8focdmuLbZASGrKCJYIAushi6KFgVSpYC5FyE0gumJ63w
         sn5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ng1jT+iULeswU8NpMwu5RS8+5KzIEAsIE6Qf4nO8E7c=;
        b=PdYbx1u17963sjGAPrwVkFph7J1DI+q2aaaybapy6xzrju2zBJNNQS99ko9uCDMuNz
         +8NQSTGA9QLx626JUEoAaaBmbbsXaYxhDFHWAtKCDo8sXnvS2mkAccQgH0Ka2utd0Jg9
         uGkNSfCDNT7A6a9wcEx9EQxfMpNC47BL4frmt6UP4qV2A4H/Us3c3Wc0lkYyNym/CYGs
         nQUNkK2yg3DtsuP8yQkZ5y2zxYCbQFs12/N6e0cM7kdzfH7vEjqMstkHbDwYgojS0xmQ
         2lyUKAgcrZE5NhxWlVn46MvdVZpc31dZTu/zOBxzqFphIKz0G+E4gtL5n5itX+q6EPKt
         owuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53375E2l3v/aioR7lP2yrODFiv/Kirz9l6p3ShfC9ex6JKQT+6H5
	H7eOCCN35KLt4JCvc5Wxy5I=
X-Google-Smtp-Source: ABdhPJyfi8zTY2jMM9sIQ0ne5V4jNWIzqp3+Hxhr60F1hn8wS+UV8+/FedV97KvPk7cfCejnctD2pQ==
X-Received: by 2002:aa7:d818:: with SMTP id v24mr10539440edq.22.1624107743079;
        Sat, 19 Jun 2021 06:02:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4404:: with SMTP id y4ls3987293eda.1.gmail; Sat, 19
 Jun 2021 06:02:22 -0700 (PDT)
X-Received: by 2002:a05:6402:5191:: with SMTP id q17mr2016135edd.321.1624107742015;
        Sat, 19 Jun 2021 06:02:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624107742; cv=none;
        d=google.com; s=arc-20160816;
        b=Yy5qglRbAARFd3AGbrFFacad5OxrK7xKNb+gr0enfIQxBSte+Zy+tiYHBaCQKoztCS
         6QDwBo6gnrgsKd31T1y4DOS2OJcjYO/Trl4hglYB6NIoYA4OeDymUnGLT3oAHt0kDnwb
         mb9tjbus6phTwYET4LHP01GSLIkCeZLFJeLaPp5F30O8+1sWAzU/ARqfGIKXQTZBGWXr
         xN+7cGWC5jDCLO9c4i7Dya+S7RUhSdVOr2bIFKpeT5HJvwH8huqxc7u6rNqz9EcwtMOe
         DEjDYSILzYJ0eQug0fld306A1gM9zu3pFeQWrHxzShgZhmsUrI7LSgdVcKIGVfJIVBP+
         w9rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:date:from:dkim-signature;
        bh=HUeqKt3RtgMevbE/ABbBGv3TkFoWafk2RAOPNGWgrN4=;
        b=BCow+ZuL4DhTViAvJITy+I4XL18h6u+J9/tXtQU6YJAxo1oJ5V7UyhRfTmoyjaZa7J
         YFkayVcFuIDbW+s6I+qugt+iyR+zORqwIvy9WXHNGzef6D57vHD2Q0vFcQtKumL1PTEY
         TaiOUIKzq4BnocZSz487mbhDrL3z1qyvpcVRmRAbSwJcNWBQrZ9MBeKaORRMjFN2SiJV
         id5IHQhc1dXinicq+QUpeUW7sh1hcMkd2wqtZp+HUvq+artm2y92uQgCwgR2ktUsK7mD
         gG1d3LtTTw8GneZZFb2/5ETE8zbcrmeNJDsXOzsuS0hoJg1Fo7TAwc2ydWoWautSrB64
         8kIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gAsCSsWa;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id e26si439053edr.3.2021.06.19.06.02.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 19 Jun 2021 06:02:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id a11so8564484lfg.11
        for <kasan-dev@googlegroups.com>; Sat, 19 Jun 2021 06:02:21 -0700 (PDT)
X-Received: by 2002:a19:6902:: with SMTP id e2mr6999176lfc.326.1624107741056;
        Sat, 19 Jun 2021 06:02:21 -0700 (PDT)
Received: from pc638.lan (h5ef52e3d.seluork.dyn.perspektivbredband.net. [94.245.46.61])
        by smtp.gmail.com with ESMTPSA id g28sm1223273lfv.142.2021.06.19.06.02.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 19 Jun 2021 06:02:20 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Sat, 19 Jun 2021 15:02:17 +0200
To: Daniel Axtens <dja@axtens.net>
Cc: akpm@linux-foundation.org, Daniel Axtens <dja@axtens.net>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Andrey Konovalov <andreyknvl@gmail.com>,
	David Gow <davidgow@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Uladzislau Rezki <urezki@gmail.com>
Subject: Re: [PATCH] mm/vmalloc: unbreak kasan vmalloc support
Message-ID: <20210619130217.GA1915@pc638.lan>
References: <20210617081330.98629-1-dja@axtens.net>
 <1623922742.sam09kpmhp.astroid@bobo.none>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1623922742.sam09kpmhp.astroid@bobo.none>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=gAsCSsWa;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12e as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Jun 17, 2021 at 07:40:49PM +1000, Nicholas Piggin wrote:
> Excerpts from Daniel Axtens's message of June 17, 2021 6:13 pm:
> > In commit 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings"),
> > __vmalloc_node_range was changed such that __get_vm_area_node was no
> > longer called with the requested/real size of the vmalloc allocation, but
> > rather with a rounded-up size.
> > 
> > This means that __get_vm_area_node called kasan_unpoision_vmalloc() with
> > a rounded up size rather than the real size. This led to it allowing
> > access to too much memory and so missing vmalloc OOBs and failing the
> > kasan kunit tests.
> > 
> > Pass the real size and the desired shift into __get_vm_area_node. This
> > allows it to round up the size for the underlying allocators while
> > still unpoisioning the correct quantity of shadow memory.
> > 
> > Adjust the other call-sites to pass in PAGE_SHIFT for the shift value.
> > 
> > Cc: Nicholas Piggin <npiggin@gmail.com>
> > Cc: David Gow <davidgow@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Uladzislau Rezki (Sony) <urezki@gmail.com>
> > Link: https://bugzilla.kernel.org/show_bug.cgi?id=213335
> > Fixes: 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings")
> 
> Thanks Daniel, good debugging.
> 
> Reviewed-by: Nicholas Piggin <npiggin@gmail.com>
> 
> > Signed-off-by: Daniel Axtens <dja@axtens.net>
> > ---
> >  mm/vmalloc.c | 24 ++++++++++++++----------
> >  1 file changed, 14 insertions(+), 10 deletions(-)
> > 
> > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > index aaad569e8963..3471cbeb083c 100644
> > --- a/mm/vmalloc.c
> > +++ b/mm/vmalloc.c
> > @@ -2362,15 +2362,16 @@ static void clear_vm_uninitialized_flag(struct vm_struct *vm)
> >  }
> >  
> >  static struct vm_struct *__get_vm_area_node(unsigned long size,
> > -		unsigned long align, unsigned long flags, unsigned long start,
> > -		unsigned long end, int node, gfp_t gfp_mask, const void *caller)
> > +		unsigned long align, unsigned long shift, unsigned long flags,
> > +		unsigned long start, unsigned long end, int node,
> > +		gfp_t gfp_mask, const void *caller)
> >  {
> >  	struct vmap_area *va;
> >  	struct vm_struct *area;
> >  	unsigned long requested_size = size;
> >  
> >  	BUG_ON(in_interrupt());
> > -	size = PAGE_ALIGN(size);
> > +	size = ALIGN(size, 1ul << shift);
> >  	if (unlikely(!size))
> >  		return NULL;
> >  
> > @@ -2402,8 +2403,8 @@ struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
> >  				       unsigned long start, unsigned long end,
> >  				       const void *caller)
> >  {
> > -	return __get_vm_area_node(size, 1, flags, start, end, NUMA_NO_NODE,
> > -				  GFP_KERNEL, caller);
> > +	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags, start, end,
> > +				  NUMA_NO_NODE, GFP_KERNEL, caller);
> >  }
> >  
> >  /**
> > @@ -2419,7 +2420,8 @@ struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
> >   */
> >  struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
> >  {
> > -	return __get_vm_area_node(size, 1, flags, VMALLOC_START, VMALLOC_END,
> > +	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
> > +				  VMALLOC_START, VMALLOC_END,
> >  				  NUMA_NO_NODE, GFP_KERNEL,
> >  				  __builtin_return_address(0));
> >  }
> > @@ -2427,7 +2429,8 @@ struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
> >  struct vm_struct *get_vm_area_caller(unsigned long size, unsigned long flags,
> >  				const void *caller)
> >  {
> > -	return __get_vm_area_node(size, 1, flags, VMALLOC_START, VMALLOC_END,
> > +	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
> > +				  VMALLOC_START, VMALLOC_END,
> >  				  NUMA_NO_NODE, GFP_KERNEL, caller);
> >  }
> >  
> > @@ -2949,9 +2952,9 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
> >  	}
> >  
> >  again:
> > -	size = PAGE_ALIGN(size);
> > -	area = __get_vm_area_node(size, align, VM_ALLOC | VM_UNINITIALIZED |
> > -				vm_flags, start, end, node, gfp_mask, caller);
> > +	area = __get_vm_area_node(real_size, align, shift, VM_ALLOC |
> > +				  VM_UNINITIALIZED | vm_flags, start, end, node,
> > +				  gfp_mask, caller);
> >  	if (!area) {
> >  		warn_alloc(gfp_mask, NULL,
> >  			"vmalloc error: size %lu, vm_struct allocation failed",
> > @@ -2970,6 +2973,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
> >  	 */
> >  	clear_vm_uninitialized_flag(area);
> >  
> > +	size = PAGE_ALIGN(size);
> >  	kmemleak_vmalloc(area, size, gfp_mask);
> >  
> >  	return addr;
> > -- 
> > 2.30.2
> > 
> > 
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>

Indeed hugepage mapping was broken in regard to KASAN. 

Thanks!

--
Vlad Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210619130217.GA1915%40pc638.lan.
