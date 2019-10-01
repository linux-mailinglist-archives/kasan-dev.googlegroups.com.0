Return-Path: <kasan-dev+bncBDK7LR5URMGRBLGPZTWAKGQEHDY4EGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 35E0CC3111
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 12:17:17 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id r22sf3945660ljg.15
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 03:17:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569925036; cv=pass;
        d=google.com; s=arc-20160816;
        b=qM+K6N7A+vYqFLp/uj1MSvCXgRk9o8q7Shj3+t3Y+6149ZzmwXgU6KO4OelXbRRmPA
         yOWxLEu4BsiBDHIWVT8Z/O/WGoIj6IDF38g1avkG0Juq1y9GEcfMaNnDu5UTYpfoA36O
         BkIqnGOVSod5x2cSaGn68fmqMHU62tvcXI33Z3kQOchGpfi7Qcuo6riRuwrPnNbgfDeY
         JE8Eg8xtQX+zVd8V1JIt1Bq/NMxQio7QxkShHJix0+u3TEi/3U174nLib4xf16eO6k02
         0EfPrryDl77bhAj5BtbNYUaeRmWOtpx+5ysVo7/PBoL0jyyjvLQ09UrKK7C5UJ7od83+
         Ur8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:dkim-signature:dkim-signature;
        bh=sp3n2wb0XgLdDoeuCsVw+E8rpuwl6aFPk9w4VWXNMNg=;
        b=Ss5Zhz1gKvivYlknjMCF7DCT6+juc+BTGfWyOxXha6dMKf7SAgtuqTfRA9cbP1lNaz
         xKEV+i34t+PQgT34VrDQVGPi8CfB96vTB/HdNA7FIqjqn4TlKSKAF6xyjc4LJxEHFUxO
         3B3QX2R6SZc+JtVzB28Pbh6R6Olqf2CtbwZ3cSGyFW+YV8ZUvN5tLUO/JvwmirgMX5rj
         iEx+cITCQxlD3u+xzaProhVu51ZO1X3AuivW6g7q2REhM6W9Vb7fQSzIM8Z9h2F0p05y
         VSnH5skRvcFKuOQzp/XTkU0ZSg8ke1XfshTTiQYt0FCxSkzWbrWQneHu4hq2V3uVMapD
         6h0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=iyTT0tp7;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sp3n2wb0XgLdDoeuCsVw+E8rpuwl6aFPk9w4VWXNMNg=;
        b=XOSjIKBtPw93Ub+nySY7gtgWQKGsFO+fABEo68dLsk7IHrihvUjZJVnIHViqxKWi6Q
         TKZUz906OEZfQNWxA3P3Nq7XVjGotCZDGW9dAZeM11syOZKU+9Ceb4u7MCz7xm3oR3ab
         8RGvfo8ML8ydGn7fyOjQURP1Y8ZwKc9zAlcDj1mDJC+mBbFh+z88TpYthmwVePgMOyEt
         flzluvpZkGVcvOIsE5A+YxaVHW3cd6I93Cd1s5uG1aHhi1oaitzZNU71OuDYrRNif7F9
         tbXVp/uZ1XqW+xK5JSlhtit2zFgJ37MFlm3i9ktVvGMxz9AX7NMz77Y6UVHbOJIok3qT
         2ggQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sp3n2wb0XgLdDoeuCsVw+E8rpuwl6aFPk9w4VWXNMNg=;
        b=u3inz0B5jJEacJt7tOOCRBbS7blLp6FhtjemlQIrzrftwJwF7/lZLUKoh4vYpUHqsK
         OCx5LlzIsT8BjT/DSgumAG0sMVhsQX+7SFaIp4PF3hoEahoezg223FCKbrVZDWkNP9IW
         /Jozt6vK29gdoCeN1GzpIE11CqnGKxMgyaWlkfv4xDolBdTZEEAlIwrRFsV+eoic+Yms
         U62O6MMPh7ORv8XgnLnEXp5uHQsmBhQCGhiaPiXw0KQXLpSetqsLf11NXez/q4BAlz68
         NaLgnJ30eMXoPt/21p39xDqbWV3m7Zk0XFMeKqvRLfD/t/5Ssek8qfVSyFm23Vqu7B3t
         ZN+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sp3n2wb0XgLdDoeuCsVw+E8rpuwl6aFPk9w4VWXNMNg=;
        b=AGNPCA/LeLWtaMuMU3x3Nz4Ec8l9ijtO39pD5TEwPWQSial1nn3f3g2M60/Q8yBoYm
         yO7RWQc+dYzqtfKWIyUu3JBgXT4lQ0Ssvw7DjjTkzhyKMzxsYuFiVTYkjVVlp/rHTuu2
         C0MBBtrMGLeo6K1nEYr1SSVafnc6oijziiDtlV/yz9LdFNRdEuM1qHbt35DSIm8M9PSI
         m383Hs++8oGpZz5xxZoR1Ibc7z+rVuNimaATX3r59x0AohR9l5j6F/e+yfs12O/vD8W2
         uyAjL7MLSl1D/tEklG0K9ZpiwdJDzlMP9qgUo2D7rXX1+5C1b+b02x1gV8hKI8olhmjK
         ksfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVddiqCxnSoF0v7iUOEwBTlU6SA8XLZtK62U3/u7073SjIXakTQ
	RNbCb3f1pwhmEzvbXs26gyU=
X-Google-Smtp-Source: APXvYqzQ3bT8t7ntF3GZk4RsSBb7aU3KpfPVWPQFfqObBIYkvXna+w+vJsIQz22pbnOpx446hz6WNA==
X-Received: by 2002:a19:4f5a:: with SMTP id a26mr14161267lfk.116.1569925036750;
        Tue, 01 Oct 2019 03:17:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:559c:: with SMTP id v28ls1454026lfg.10.gmail; Tue, 01
 Oct 2019 03:17:16 -0700 (PDT)
X-Received: by 2002:ac2:5ec1:: with SMTP id d1mr246552lfq.83.1569925036192;
        Tue, 01 Oct 2019 03:17:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569925036; cv=none;
        d=google.com; s=arc-20160816;
        b=N1LTR556YK7jeF6cvMCMRgr7PCnnCmWRG+2SfgvwMjhvOx5JuThZyE13d0lxv3WG21
         yZOh9+iPAcaZUuyg3xY3ueRE62YXrlwgBeFG+XMmqIuHN02cCf6LbpnHUkWVTNyyGuWt
         U7Aww41hWHF707AqckOvT9yQ1jKO25ikw4b6xNCVUYcRCE74YOaXACTKgqPslJpANpbl
         0TZvuVBUAb4+X9MD17IHbdcNv1N8mKT0U7/F6tktjnvr79EdLma6d0jSai3gozURVqLJ
         TyUBb3aGTrLmaOWMTmOKMh3clK+nUQRrTGwHExxMjjjaHkb9a13Fu6J4TJFqZAaAE71w
         thRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:date:from:dkim-signature;
        bh=FHRobxW8BCnp6m8ULWiX2Kwd0/E8VfgVZeuErnZpDKE=;
        b=YBTlhtTVJtd2oapBdvE0a5IuFiFRsLFIo0a+7/PxDP7NN0cPwaSDaXUw6qYdVove5t
         aWN9onGmqZ3RTZ+g+X0gWb9X9S4TZSa71wIxy/KsIM9C4kwIS+xiBOz00XVVxMZAlpnu
         bIDlVhfHcfOZkZrdX7QsfUZZ32PXk1meuHLUwBAEIwwq2/RW+cKQR/qzhEk2/Q4WB52s
         gPV5nIVUbK7sKCtyzGL7nXqfuwF9CQYQdaisoMe5pQNG0z2BmoJ4Hpv1tH7zA0olr0cx
         Oq3Gh+1ANe1v/JzmJQaLNUgUrwLeOPajwto4pP2fD9s0Awq8vnt1qyt816lHdKn3ZtY6
         t79A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=iyTT0tp7;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id c25si971232lji.2.2019.10.01.03.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2019 03:17:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id n14so12686389ljj.10
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2019 03:17:16 -0700 (PDT)
X-Received: by 2002:a2e:8084:: with SMTP id i4mr15814978ljg.119.1569925035845;
        Tue, 01 Oct 2019 03:17:15 -0700 (PDT)
Received: from pc636 ([37.139.158.167])
        by smtp.gmail.com with ESMTPSA id u8sm4877959lfb.36.2019.10.01.03.17.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Oct 2019 03:17:14 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Tue, 1 Oct 2019 12:17:07 +0200
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, mark.rutland@arm.com,
	dvyukov@google.com, christophe.leroy@c-s.fr,
	linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20191001101707.GA21929@pc636>
References: <20191001065834.8880-1-dja@axtens.net>
 <20191001065834.8880-2-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191001065834.8880-2-dja@axtens.net>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=iyTT0tp7;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::242 as
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

Hello, Daniel.

> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index a3c70e275f4e..9fb7a16f42ae 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -690,8 +690,19 @@ merge_or_add_vmap_area(struct vmap_area *va,
>  	struct list_head *next;
>  	struct rb_node **link;
>  	struct rb_node *parent;
> +	unsigned long orig_start, orig_end;
Shouldn't that be wrapped around #ifdef CONFIG_KASAN_VMALLOC?

>  	bool merged = false;
>  
> +	/*
> +	 * To manage KASAN vmalloc memory usage, we use this opportunity to
> +	 * clean up the shadow memory allocated to back this allocation.
> +	 * Because a vmalloc shadow page covers several pages, the start or end
> +	 * of an allocation might not align with a shadow page. Use the merging
> +	 * opportunities to try to extend the region we can release.
> +	 */
> +	orig_start = va->va_start;
> +	orig_end = va->va_end;
> +
The same.

>  	/*
>  	 * Find a place in the tree where VA potentially will be
>  	 * inserted, unless it is merged with its sibling/siblings.
> @@ -741,6 +752,10 @@ merge_or_add_vmap_area(struct vmap_area *va,
>  		if (sibling->va_end == va->va_start) {
>  			sibling->va_end = va->va_end;
>  
> +			kasan_release_vmalloc(orig_start, orig_end,
> +					      sibling->va_start,
> +					      sibling->va_end);
> +
The same.

>  			/* Check and update the tree if needed. */
>  			augment_tree_propagate_from(sibling);
>  
> @@ -754,6 +769,8 @@ merge_or_add_vmap_area(struct vmap_area *va,
>  	}
>  
>  insert:
> +	kasan_release_vmalloc(orig_start, orig_end, va->va_start, va->va_end);
> +
The same + all further changes in this file.
>  	if (!merged) {
>  		link_va(va, root, parent, link, head);
>  		augment_tree_propagate_from(va);
> @@ -2068,6 +2085,22 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
>  
>  	setup_vmalloc_vm(area, va, flags, caller);
>  
> +	/*
> +	 * For KASAN, if we are in vmalloc space, we need to cover the shadow
> +	 * area with real memory. If we come here through VM_ALLOC, this is
> +	 * done by a higher level function that has access to the true size,
> +	 * which might not be a full page.
> +	 *
> +	 * We assume module space comes via VM_ALLOC path.
> +	 */
> +	if (is_vmalloc_addr(area->addr) && !(area->flags & VM_ALLOC)) {
> +		if (kasan_populate_vmalloc(area->size, area)) {
> +			unmap_vmap_area(va);
> +			kfree(area);
> +			return NULL;
> +		}
> +	}
> +
>  	return area;
>  }
>  
> @@ -2245,6 +2278,9 @@ static void __vunmap(const void *addr, int deallocate_pages)
>  	debug_check_no_locks_freed(area->addr, get_vm_area_size(area));
>  	debug_check_no_obj_freed(area->addr, get_vm_area_size(area));
>  
> +	if (area->flags & VM_KASAN)
> +		kasan_poison_vmalloc(area->addr, area->size);
> +
>  	vm_remove_mappings(area, deallocate_pages);
>  
>  	if (deallocate_pages) {
> @@ -2497,6 +2533,9 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>  	if (!addr)
>  		return NULL;
>  
> +	if (kasan_populate_vmalloc(real_size, area))
> +		return NULL;
> +
>  	/*
>  	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
>  	 * flag. It means that vm_struct is not fully initialized.
> @@ -3351,10 +3390,14 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>  	spin_unlock(&vmap_area_lock);
>  
>  	/* insert all vm's */
> -	for (area = 0; area < nr_vms; area++)
> +	for (area = 0; area < nr_vms; area++) {
>  		setup_vmalloc_vm(vms[area], vas[area], VM_ALLOC,
>  				 pcpu_get_vm_areas);
>  
> +		/* assume success here */
> +		kasan_populate_vmalloc(sizes[area], vms[area]);
> +	}
> +
>  	kfree(vas);
>  	return vms;
>  


--
Vlad Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191001101707.GA21929%40pc636.
