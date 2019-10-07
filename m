Return-Path: <kasan-dev+bncBDK7LR5URMGRBC7C5PWAKGQEACE3LXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C0CD5CDCC3
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 10:02:19 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id m6sf2981557wmf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 01:02:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570435339; cv=pass;
        d=google.com; s=arc-20160816;
        b=YGRrEqyFKdOt4jebfGilqqYSW+gIBDT6ZEhimAYRgXbzSiMem1i1xATYddxEak5CKP
         b2+Ktrr46PlznzZSTvMGwYCKwh6IInUpUPOIp0oDzV5cmUUIg+zCYnvgJSHv4Z2lXVRn
         5JAqPxWeNVTu/amL8ofGIAbgYgY9S//W+Sl0IKb+XHgVrRfg2I9YKFfJdeKOcgO+wIoq
         QR8KUbWh0/AnLiV6AeEinbu7aJfD7GFiefebOhyftCoq3DBbvTrQPLzAUerm5+1VnIbU
         Q9lTym38fTWr4Npb6iLQ80miBxJd6xjklKKoh5D+OXIQBd/uAQdJcIA236QR2c4dSwHR
         8vNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:dkim-signature:dkim-signature;
        bh=uybKN6HagaEI9PTK9nLYuTc1ufcRNK7R/AXtoqAh9Kk=;
        b=DYNGx5M+DYBXPMlcS1YQbfeWgNR3S7N1oDOKdcPOXEFYhDsmjbevUnhL1leXwagcvB
         n6CeGSGrgn4RW8AUlegOPeItbAqKtdZow/nZU+etdmTVVsj6lstZA3XWmsVXwpTrsr/y
         tp49NLXTBl9UmhQIKCbSZ7H1o4iD7BzodYEGZFDX04ziqNG81tfQ48XMTBiYDSK3j51z
         6KHCe2gTRTyHsIABLA51Y2toIdpLvrzcYdeEfUuqc97/R3Ta1FIGVWkuE7oohRtFFG37
         EVHI6ArJ5cbicdGv+61iaKv71xEk4PAuTpZRAXCSxfspKP+5/tXZ61yBgYJZm9H3vLLS
         DsWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=YKX80zqK;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uybKN6HagaEI9PTK9nLYuTc1ufcRNK7R/AXtoqAh9Kk=;
        b=rceXv8AEKIma1b3vx1HTRwQM0IXeK/I7syG3Q3OcLLsECw+LtfQFBeDEHkfcmrBePw
         FdkMuGtaITg8UBlNjZzM+MKphJHW3AjaktdIyL+8lArXkv9MBbW189d8F4OW6zxTDqrJ
         xT4bxAc5weqp5zwHYsBS5hs3y3gIxjuSRX77eScd4x7FQdLSWSDcA+xyGyFde9kvCwS6
         TPrf7fp7/7Dxzu0LCXwGIClbt7z41aTu2CCkMonwK3MuKUbRV6OzjscTbrLLQhVbZlO2
         Ychly4yX8qiVL2E/H/gBHrpV5zjWRczmmI6U0zPn4XxUZQlXEyQFHfnbHsWSjrFsZZAW
         USOA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uybKN6HagaEI9PTK9nLYuTc1ufcRNK7R/AXtoqAh9Kk=;
        b=Kl98YlbCV+hdCeibZg6VDWt4IxiFrqc4atCinEuNiGKwiQG8V0x5jbKwoCnX172t5h
         CczOJgMH5Js5lbWVie2SrUr2K8SdywvrBRqwyAggAP85ERFjh8YOZLGAOtLUqNfH5BZ8
         W1Pa9RRdF0K99A54AIbnRK74IOEyMSZDbhxI2vXk6roo5zeLa78A91EL/MmU0aK9wD/j
         GUXyo+PDXt61hRlJCDUcy/DbwWkMRGmYi1NZzspkXSDV71mXeDeLHevrTLVcqgumHil3
         g6H14lQDN44pavTxVsaF+sDfSoNWP9aEBCk5e3dn3AQi/J4JCv8Mx/JEjDB8oR9lH8oX
         iV8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uybKN6HagaEI9PTK9nLYuTc1ufcRNK7R/AXtoqAh9Kk=;
        b=Gj4dWY/swUkpW09mgJPPmnb2tQHyFG0c/B04PxdJKg3kUNZp55tNBCYC1JYLyUw/fE
         iFKA4OB3+6TzRg0E3HtzHPAk/qI9dO8Yw2XrMchB3N7I8cqIObKf9L34/072UP2YkUd5
         tq/XbKJG4wXbGRwKafRXIISdavPpfL21JWlELi1Res+rf4h/dZMqI1TQkJHT0lDjcnQU
         XaOI52Fcc8u/uKPzA9gyVaHXxxQUx79lRw+pcAaaZzKFH5pmwbTOPuRDFCdNBhV1lCbj
         SP47CSnpqoHvLB4UvOBl1c+Pes0QEODU4XpT8Rm+HAznTyVxDswsPA3j/xbwfuE1kQFT
         LNlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVxdgOADxxT6bxOP1SzEkzd6UzJu4TycPSChglzPtsedg/PPVSZ
	7b/VPxdlpEAgnnNTyjacVPM=
X-Google-Smtp-Source: APXvYqwc9pcqmslXV10lBOtMnW9aBBnrxMCRSAG1HBrJ9WWi07YomkHKxeuQSkCXmpIDe/vaLtAmiw==
X-Received: by 2002:a7b:c94a:: with SMTP id i10mr8766023wml.40.1570435339428;
        Mon, 07 Oct 2019 01:02:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c0d9:: with SMTP id s25ls3747766wmh.4.gmail; Mon, 07 Oct
 2019 01:02:18 -0700 (PDT)
X-Received: by 2002:a05:600c:2252:: with SMTP id a18mr13922665wmm.141.1570435338956;
        Mon, 07 Oct 2019 01:02:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570435338; cv=none;
        d=google.com; s=arc-20160816;
        b=X3h3PPbzjPiXxZ9F88zpNt2FV9uXEtzbBQ5SGZMH3ucE3Yg/c5xb+vHucQU6VLGDy0
         f5lagWtGw8kLZbWbUl3nbC6pkcKZHrBXcuM/PuJJwD92EUOvaETIkDHmLbZ/4LR5BEUD
         bC9ejxVvXbcnTvy19Fw9mBdoshL5Z6O3PCkATWwr3aoV3RmQfI68MgYXUraAIEUD2in+
         wRWsruPFEV7AHSL2mmKNR4qWkCY912S1wStOG5V33hUH/kfWr8xIDnsVVT4ZriivdVPI
         LG5ph6qq4YXWXBF59GY3KZhCvH2Le9icpTX4Krq4+XIP6XK4g3fJ/mONZYho98YdgSkT
         YVeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:date:from:dkim-signature;
        bh=dD+rwXY/nYOWBAq4CYmtKPehya96hW8MC3evJji/Yec=;
        b=erJgYp7uT3YWkU/vofgxcNE9gvuNDg5gSWpwDpyG0bMVPoItcbHP61I/P3VBFT5muz
         XMhnRwdSf58FP6JWL6s7S6nKh9JcoD742RFhEewjHA0TLAk0I8FYmADKTFoJtbSEwzTu
         YO8DQggcFfxzAyrLxNJVVIXwbCzv0zbFbOuAsOdNNJ6m7TuEliny+FuMlx5B+72F5cwT
         G4zKnwHb5GfH+KVcJ2IonSDmtM7WD3WccuhW/dRt2mBom/oOCCojoYdz8yfwYHaDX+5m
         Ug4GahwRGl5uhpde+2cFVV3gpkvqx+H7CAy1wn3ngoCfiGeSb5HpFnvzkUzaTmCIL16e
         ChXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=YKX80zqK;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id q137si1022690wme.3.2019.10.07.01.02.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2019 01:02:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id t8so8507008lfc.13
        for <kasan-dev@googlegroups.com>; Mon, 07 Oct 2019 01:02:18 -0700 (PDT)
X-Received: by 2002:ac2:4a8f:: with SMTP id l15mr16241092lfp.21.1570435338163;
        Mon, 07 Oct 2019 01:02:18 -0700 (PDT)
Received: from pc636 (h5ef52e31.seluork.dyn.perspektivbredband.net. [94.245.46.49])
        by smtp.gmail.com with ESMTPSA id f21sm3218392lfm.90.2019.10.07.01.02.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Oct 2019 01:02:17 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Mon, 7 Oct 2019 10:02:09 +0200
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, mark.rutland@arm.com,
	dvyukov@google.com, christophe.leroy@c-s.fr,
	linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20191007080209.GA22997@pc636>
References: <20191001065834.8880-1-dja@axtens.net>
 <20191001065834.8880-2-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191001065834.8880-2-dja@axtens.net>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=YKX80zqK;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as
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

> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index a3c70e275f4e..9fb7a16f42ae 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -690,8 +690,19 @@ merge_or_add_vmap_area(struct vmap_area *va,
>  	struct list_head *next;
>  	struct rb_node **link;
>  	struct rb_node *parent;
> +	unsigned long orig_start, orig_end;
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
>  			/* Check and update the tree if needed. */
>  			augment_tree_propagate_from(sibling);
>  
> @@ -754,6 +769,8 @@ merge_or_add_vmap_area(struct vmap_area *va,
>  	}
>  
>  insert:
> +	kasan_release_vmalloc(orig_start, orig_end, va->va_start, va->va_end);
> +
>  	if (!merged) {
>  		link_va(va, root, parent, link, head);
>  		augment_tree_propagate_from(va);
Hello, Daniel.

Looking at it one more, i think above part of code is a bit wrong
and should be separated from merge_or_add_vmap_area() logic. The
reason is to keep it simple and do only what it is supposed to do:
merging or adding.

Also the kasan_release_vmalloc() gets called twice there and looks like
a duplication. Apart of that, merge_or_add_vmap_area() can be called via
recovery path when vmap/vmaps is/are not even setup. See percpu
allocator.

I guess your part could be moved directly to the __purge_vmap_area_lazy()
where all vmaps are lazily freed. To do so, we also need to modify
merge_or_add_vmap_area() to return merged area:

<snip>
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index e92ff5f7dd8b..fecde4312d68 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -683,7 +683,7 @@ insert_vmap_area_augment(struct vmap_area *va,
  * free area is inserted. If VA has been merged, it is
  * freed.
  */
-static __always_inline void
+static __always_inline struct vmap_area *
 merge_or_add_vmap_area(struct vmap_area *va,
        struct rb_root *root, struct list_head *head)
 {
@@ -750,7 +750,10 @@ merge_or_add_vmap_area(struct vmap_area *va,
 
                        /* Free vmap_area object. */
                        kmem_cache_free(vmap_area_cachep, va);
-                       return;
+
+                       /* Point to the new merged area. */
+                       va = sibling;
+                       merged = true;
                }
        }
 
@@ -759,6 +762,8 @@ merge_or_add_vmap_area(struct vmap_area *va,
                link_va(va, root, parent, link, head);
                augment_tree_propagate_from(va);
        }
+
+       return va;
 }
 
 static __always_inline bool
@@ -1172,7 +1177,7 @@ static void __free_vmap_area(struct vmap_area *va)
        /*
         * Merge VA with its neighbors, otherwise just add it.
         */
-       merge_or_add_vmap_area(va,
+       (void) merge_or_add_vmap_area(va,
                &free_vmap_area_root, &free_vmap_area_list);
 }
 
@@ -1279,15 +1284,20 @@ static bool __purge_vmap_area_lazy(unsigned long start, unsigned long end)
        spin_lock(&vmap_area_lock);
        llist_for_each_entry_safe(va, n_va, valist, purge_list) {
                unsigned long nr = (va->va_end - va->va_start) >> PAGE_SHIFT;
+               unsigned long orig_start = va->va_start;
+               unsigned long orig_end = va->va_end;
 
                /*
                 * Finally insert or merge lazily-freed area. It is
                 * detached and there is no need to "unlink" it from
                 * anything.
                 */
-               merge_or_add_vmap_area(va,
+               va = merge_or_add_vmap_area(va,
                        &free_vmap_area_root, &free_vmap_area_list);
 
+               kasan_release_vmalloc(orig_start,
+                       orig_end, va->va_start, va->va_end);
+
                atomic_long_sub(nr, &vmap_lazy_nr);
 
                if (atomic_long_read(&vmap_lazy_nr) < resched_threshold)
<snip>

--
Vlad Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191007080209.GA22997%40pc636.
