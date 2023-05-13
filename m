Return-Path: <kasan-dev+bncBC32535MUICBBOEI7SRAMGQESNAUGTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B104E70142E
	for <lists+kasan-dev@lfdr.de>; Sat, 13 May 2023 05:30:01 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-763646b324asf1573036639f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 20:30:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683948600; cv=pass;
        d=google.com; s=arc-20160816;
        b=caucZ8SzFys3F0b3on01pkifl2cZb1ER0e0yV2c2AH5yuz/RcUrIaKF9iDr5nDyDMe
         OSI0nntxbV/iG8zOBnHLnyjxNNPtXStXbuDZzhZHYHrAr4Jetq3GgkvYKIjk3h4CfjoI
         UTWM7j7mTxf8oa26vjnyvBgDLC6+3DECUsnACEcRaXFJXI4oFjeX6vM1reI9cs3dvEWt
         +TUgByEpHTgquTjUL7DE7JrdSWAzT8TY3oC3G1ktcMR4nJz2ltTmRqdvTWk2jUO0vBUY
         e5V4NppWzgdnhVVc3rC4uTo+/Ui3NtmRfRXl0GAUwY5pmOYvxQIPxTWneQUgGZYveMO/
         dZYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :subject:organization:from:references:cc:to:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=gAd/YsarGAEYIPOyArhSo6pcnUL0VYf4uOTcQKlKA30=;
        b=tXRIeOIZqmo5JNDWQm3yk4cY9ZM71kl5lw31Xj40YDq90kFwj92v+KFRJ+dFq3Asmm
         zt8UwkeE8aP8RwX5i8Q4lZItEqwSAkhl0GczkCnjU9W98h86CnSpi+q0y1Z2t7Zi0Tlp
         td0WN/2l6wZdRf8fM9EEFRxM6j2o696uzkrv5+4USrGFLBIxStmFN+JYZuHeRICtg2fh
         Lk69OmX0SISWWQ78M9NVB/2YfqrT/pSjDZQEMKSdWMWbncqPW49FjWR4qp6u6G2H1+JU
         litljwrP+FosYQ3HUexabxgVN1Rowj+IoLQiEheFCcqS2XRr8SDuesshF19V2GJbUrFM
         XE+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="KQm3+J/O";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683948600; x=1686540600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:subject:organization
         :from:references:cc:to:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gAd/YsarGAEYIPOyArhSo6pcnUL0VYf4uOTcQKlKA30=;
        b=BLsE30Kvn2D6eAkurd7eV8qFiRFc37HqYZ0UzYWvEGallysZgX83FKGGkQ0Fo7OMmn
         NWiQFm8C1ZImhX5pu8Ol0KbgapBk7cvvLej0kJxFTtWGKkQOkJnGYUhu8GF6h7JKXrow
         yP5D3y4iTL0iRJpN5a39xbXgR8gWwC7ps1SM+Zeg5ybA3F2ZEgvbTgI730f9wwwnaU7n
         zqmuFICb2HA/C6mHN9JMG5vSrKeHrJHZbDF5gWN8G+pAPWWCCrXiByhWHndqltzaSOly
         54U7sgXHqMyz8jeLWjoKLyI2ahYQ92TJlQwZgm3q1nCuTO8oc9+Hrmn2p8GI52kWpmYT
         yH4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683948600; x=1686540600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:subject:organization:from:references
         :cc:to:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gAd/YsarGAEYIPOyArhSo6pcnUL0VYf4uOTcQKlKA30=;
        b=W2N3Sz074e4cPYs1ERVL2CUvBDeOqEs8s4lNrtPraXGYZmRPDFZPlQ+GODl4D0SV86
         DILNgRW2EiX1kRlr4VrvHtKzui5fhcPUc/gNw9RRhKLDmzfmxG1frrH3Y0wk5aACdNNz
         RffEykXSyJxaeW51UoD1z0ZXS3ODX6dYSaH9m9MIPYhxligUKyFooECfeXyKf5j/jYey
         N7+NBopFkcAl7F7dutxRwwSCc5ulf7jbBbi+AKrm9xBOKjU04ftUQaWGPuHjK8vIDiLV
         HRKNv2xD5+/NrlSGJVIRpZ6FmBjBLSQlY0tOZEb9Oklob2sYpWoln2hJk87/R7+n505K
         Dtbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxPcl51kyVspEUsuL4XXQ8gRSrVNMUsFsMqAdvEOR0nng/MAd6j
	8RyUZ+Xk/W+ob8LsCkU2QdA=
X-Google-Smtp-Source: ACHHUZ4R/bFUxWwB0zx5zO7s+ePchjbaKheszlF1vLmLh1S2BAKBkBsTK+Iwib2VY7Rjhs6zjib1eg==
X-Received: by 2002:a02:94a9:0:b0:40f:77a4:7e17 with SMTP id x38-20020a0294a9000000b0040f77a47e17mr7947162jah.0.1683948600211;
        Fri, 12 May 2023 20:30:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:d45:b0:32c:8565:84fc with SMTP id
 h5-20020a056e020d4500b0032c856584fcls95982ilj.1.-pod-prod-08-us; Fri, 12 May
 2023 20:29:58 -0700 (PDT)
X-Received: by 2002:a6b:6d06:0:b0:76c:7b40:9b6b with SMTP id a6-20020a6b6d06000000b0076c7b409b6bmr5720078iod.1.1683948598670;
        Fri, 12 May 2023 20:29:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683948598; cv=none;
        d=google.com; s=arc-20160816;
        b=Gr6ZUBu408942b9bODumbL6zGbBz8CPcc6LKBldWP8NPksSkIRw7yvMxtN6Q8Rhadn
         +7MeO8A9Ayo9ymP88G2MwhmEZaXXWPToQ8f7mXfQcq8raznw0RmZXdAp8QgYTwj58TpW
         xVaavFOMQg5mbY0JATLkIMgCa/kBE6Uyyks1UXFT234piX+PFSSUoYWs/U1wNJ1/u0TE
         roR0fENqFKdqhVHE+pA51venrsIwbYc+PGfohykl82zNLxDVFlAROqsi1R7r0JXJnLr3
         svyCNEklhLbCi2eK9qCh+cZX1Rhrgn8M07hl2rlCoNyQlS+huuG12MQqST5gS+nKuThj
         /wzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:subject
         :organization:from:references:cc:to:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=AjyiA8CSsNyrBFAulIeEup4nb5qDAbNqRQ7zOVhw7pM=;
        b=QRRMJ9PtLPKK6yKQstOm9DdwEpc75qPraTvSg2+GmrIrxhwNOJt6tXxpRCI9IPvatK
         TosS+0Jgf6ABbm3UgSXRd/As3rlz9OwmwoAB1rQl06owfc4Hks1v8LAF3P2YiaF0Jq/+
         +GMsrIEqkVxknoF5dc0aviny6T+BzFdAKkBakgJXAKtu80a4VUusstDC3DMsOW/u6MN1
         26+vvK2bLPqEqUYMtXWY7cF3dK0/pd8pJM7VnpEnhhTA/T7QaMAOUAJej1YvDTOkBlbw
         w0LNR4tomToWxw1s3SguX/rwA6U2PCiU9ROHgckU4fhvxreFcgZvYrRsWiW+iA3M3yMF
         2xiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="KQm3+J/O";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id v4-20020a056638250400b0040fc30ac205si1530855jat.0.2023.05.12.20.29.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 May 2023 20:29:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-qt1-f200.google.com (mail-qt1-f200.google.com
 [209.85.160.200]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-361-s4xBW-tQNZegd98mIMGcsQ-1; Fri, 12 May 2023 23:29:56 -0400
X-MC-Unique: s4xBW-tQNZegd98mIMGcsQ-1
Received: by mail-qt1-f200.google.com with SMTP id d75a77b69052e-3ef6decfabeso64821591cf.0
        for <kasan-dev@googlegroups.com>; Fri, 12 May 2023 20:29:56 -0700 (PDT)
X-Received: by 2002:ac8:580e:0:b0:3ef:52ac:10d2 with SMTP id g14-20020ac8580e000000b003ef52ac10d2mr43450064qtg.43.1683948596196;
        Fri, 12 May 2023 20:29:56 -0700 (PDT)
X-Received: by 2002:ac8:580e:0:b0:3ef:52ac:10d2 with SMTP id g14-20020ac8580e000000b003ef52ac10d2mr43450038qtg.43.1683948595851;
        Fri, 12 May 2023 20:29:55 -0700 (PDT)
Received: from ?IPV6:2603:7000:3d00:1816::1772? (2603-7000-3d00-1816-0000-0000-0000-1772.res6.spectrum.com. [2603:7000:3d00:1816::1772])
        by smtp.gmail.com with ESMTPSA id l20-20020ae9f014000000b00755951e48desm5710604qkg.135.2023.05.12.20.29.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 May 2023 20:29:55 -0700 (PDT)
Message-ID: <7471013e-4afb-e445-5985-2441155fc82c@redhat.com>
Date: Sat, 13 May 2023 05:29:53 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
To: Peter Collingbourne <pcc@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>,
 =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 vincenzo.frascino@arm.com, Alexandru Elisei <alexandru.elisei@arm.com>,
 will@kernel.org, eugenis@google.com, Steven Price <steven.price@arm.com>,
 stable@vger.kernel.org
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-2-pcc@google.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before
 swap_free()
In-Reply-To: <20230512235755.1589034-2-pcc@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="KQm3+J/O";
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 13.05.23 01:57, Peter Collingbourne wrote:
> Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
> the call to swap_free() before the call to set_pte_at(), which meant that
> the MTE tags could end up being freed before set_pte_at() had a chance
> to restore them. One other possibility was to hook arch_do_swap_page(),
> but this had a number of problems:
> 
> - The call to the hook was also after swap_free().
> 
> - The call to the hook was after the call to set_pte_at(), so there was a
>    racy window where uninitialized metadata may be exposed to userspace.
>    This likely also affects SPARC ADI, which implements this hook to
>    restore tags.
> 
> - As a result of commit 1eba86c096e3 ("mm: change page type prior to
>    adding page table entry"), we were also passing the new PTE as the
>    oldpte argument, preventing the hook from knowing the swap index.
> 
> Fix all of these problems by moving the arch_do_swap_page() call before
> the call to free_page(), and ensuring that we do not set orig_pte until
> after the call.
> 
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8c61020c510678965
> Cc: <stable@vger.kernel.org> # 6.1
> Fixes: ca827d55ebaa ("mm, swap: Add infrastructure for saving page metadata on swap")
> Fixes: 1eba86c096e3 ("mm: change page type prior to adding page table entry")

I'm confused. You say c145e0b47c77 changed something (which was after 
above commits), indicate that it fixes two other commits, and indicate 
"6.1" as stable which does not apply to any of these commits.

> ---
>   mm/memory.c | 26 +++++++++++++-------------
>   1 file changed, 13 insertions(+), 13 deletions(-)
> 
> diff --git a/mm/memory.c b/mm/memory.c
> index 01a23ad48a04..83268d287ff1 100644
> --- a/mm/memory.c
> +++ b/mm/memory.c
> @@ -3914,19 +3914,7 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>   		}
>   	}
>   
> -	/*
> -	 * Remove the swap entry and conditionally try to free up the swapcache.
> -	 * We're already holding a reference on the page but haven't mapped it
> -	 * yet.
> -	 */
> -	swap_free(entry);
> -	if (should_try_to_free_swap(folio, vma, vmf->flags))
> -		folio_free_swap(folio);
> -
> -	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
> -	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
>   	pte = mk_pte(page, vma->vm_page_prot);
> -
>   	/*
>   	 * Same logic as in do_wp_page(); however, optimize for pages that are
>   	 * certainly not shared either because we just allocated them without
> @@ -3946,8 +3934,21 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>   		pte = pte_mksoft_dirty(pte);
>   	if (pte_swp_uffd_wp(vmf->orig_pte))
>   		pte = pte_mkuffd_wp(pte);
> +	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
>   	vmf->orig_pte = pte;
>   
> +	/*
> +	 * Remove the swap entry and conditionally try to free up the swapcache.
> +	 * We're already holding a reference on the page but haven't mapped it
> +	 * yet.
> +	 */
> +	swap_free(entry);
> +	if (should_try_to_free_swap(folio, vma, vmf->flags))
> +		folio_free_swap(folio);
> +
> +	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
> +	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
> +
>   	/* ksm created a completely new copy */
>   	if (unlikely(folio != swapcache && swapcache)) {
>   		page_add_new_anon_rmap(page, vma, vmf->address);
> @@ -3959,7 +3960,6 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>   	VM_BUG_ON(!folio_test_anon(folio) ||
>   			(pte_write(pte) && !PageAnonExclusive(page)));
>   	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
> -	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
>   
>   	folio_unlock(folio);
>   	if (folio != swapcache && swapcache) {


You are moving the folio_free_swap() call after the 
folio_ref_count(folio) == 1 check, which means that such (previously) 
swapped pages that are exclusive cannot be detected as exclusive.

There must be a better way to handle MTE here.

Where are the tags stored, how is the location identified, and when are 
they effectively restored right now?

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7471013e-4afb-e445-5985-2441155fc82c%40redhat.com.
