Return-Path: <kasan-dev+bncBD52JJ7JXILRBWEFRORQMGQEY4DZHOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 282DE70416F
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 01:40:10 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-33539445684sf12264555ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 May 2023 16:40:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684194008; cv=pass;
        d=google.com; s=arc-20160816;
        b=XBEB8GCZv+INDXawDRqjFI0sbKGfrku3M6R8wjynW2yOysEQIqWUEeywGXGNysKMg6
         prrOeh8PiQp22I4RPBqoUKKgfzi1+MSgccmeulOeX0MnE/rzSF3rs9rE/1lk5ViE/2hv
         RAL3dIYbz0JHEqIVOF/srwKJKi5tXNIq6+Ht7VHCgTgBv1f4b8k0iD4XLc4dhwwN+Y5Y
         KCzTwnLb3bGn0IYbvSp4ZsBwuD4u/WUMKgpyiyrlU0go838T3jvBJhD/VFyobaIzoprK
         QA+HufvYFyC5Q1/Q7h2ZttZi1d3onwootFoFobFqLZkyTYWsSAZgEXwOmFXVwa4MnzRW
         h2fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=y9IDfUXuUW6tmGGCK+nhAO79ZeuVk5nXXRnFl5jtpsk=;
        b=zLi2/DKqDUdL8An0UPo+pQ+lBPdf0AVIX/exWV63XotgC+a9OReTyHBvDIix64Cgne
         MyQnEmTK2Ab9EcBUIkK8T2DAAm3uv8sAfzRIVcALqFswAL8NPV1TqkZJof6pAj31NYPu
         Rhsy/mGkdnqGi75kNsgyjEW0R8zoSV9cZ1crCXh8MumD38tRwtzvgAUjW6T8LQUevF4b
         k3FpVnJ/XmuylByXkxP3a2BaMElX6N2ZP0AEi6Jl+fHqlqM8g6sM2E9UoDrrbJYUpCWu
         D7aXaN/OwWKalpi8UAHIFjTRbPAwnO24CCi2CP8ul5G2nMNjyrh3WeV8G1YHxtR1qaSM
         D/lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=oBqogYyz;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684194008; x=1686786008;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=y9IDfUXuUW6tmGGCK+nhAO79ZeuVk5nXXRnFl5jtpsk=;
        b=oG0LhUoqIpGnA+u/Rxe+0seEM1bLOaUomwvjiUEGwPUjSNX+ikobHl27kvL7ENG3I0
         qQ8wLmiB5FyBgVQHtBKSjtSVJMRZOQN9dfpl0+zVAiWD8/mRm69Wv8ThM4y78QxxUSD5
         beDoqEc6EDOPCFYCU0O2xUg4J2CC2hFaBTunlfKAL/WlLaKyj0R+8WUliTBAguhQAp2A
         bqKbtCE90ItcGDY4UpNwTZRSI5CaTbzKtPpFzG/qPUqdsqR9LNN59ejJW4MGCm5MHM6c
         7Dze77Tk567NGdf++oC+j2wmP6iryxO5hFTtBMrLK4/L4yjMuaLtSeHcMHhATVpAlSN4
         dyPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684194008; x=1686786008;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y9IDfUXuUW6tmGGCK+nhAO79ZeuVk5nXXRnFl5jtpsk=;
        b=T9l/SbkqTWPR9PC7JJjDCzTrDjdby35QDkuo4pi36h0sdkzccgZlS7Mx84MJPO07J2
         U8QH4pSS/bewBPhulTPATxO3+D0sV5xYFfj3mvCFFRJG745SAgXcHdgEaz38nRBJVEJB
         r3kPXYmU93YJgu+4dzqbtzMTkn5Yjg/u9A2Pc4sR49Npy6bYMWHGIMlDdFll2M8zrcs5
         uV6hcDTfAuDLpOqdHPi5L5GIoY1cA/qgSkIuTPCNDqZxrGXdxRuvNIhwHV4JPethF0gr
         1ymcyLpB6f79acrsHFK1HAtwNGKAlg5TOTkwXzUkFfD9Io31hhUGG4nZ32r1n9aY3S7e
         A8fw==
X-Gm-Message-State: AC+VfDzqPX7a8H3EP8Zp/CeMuUkmjhQkce/CvxHzW+JoZ1z/srSg8SqQ
	bdX3Ulbf3soN7NRz4cq5KS0=
X-Google-Smtp-Source: ACHHUZ6pXgtVsZwrSVjuEsbWisMhvQIidqJXTT5zxusd0N5We6EQ5/8KVFJKy4DaRwWVx85Q0weFiA==
X-Received: by 2002:a02:862b:0:b0:418:81f5:6f39 with SMTP id e40-20020a02862b000000b0041881f56f39mr5286611jai.3.1684194008476;
        Mon, 15 May 2023 16:40:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:220b:b0:337:81d1:da40 with SMTP id
 j11-20020a056e02220b00b0033781d1da40ls1471223ilf.0.-pod-prod-09-us; Mon, 15
 May 2023 16:40:08 -0700 (PDT)
X-Received: by 2002:a5d:9819:0:b0:769:a826:2818 with SMTP id a25-20020a5d9819000000b00769a8262818mr778684iol.16.1684194007963;
        Mon, 15 May 2023 16:40:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684194007; cv=none;
        d=google.com; s=arc-20160816;
        b=bbjy8eT/qg8amh7f36usvxX/u73jXzytO9KSf328GYAcwQyFzxOROXkg6k0D8RV+TG
         m6WOfn0KUuZCiOAXLNweMUu36lUlD1KvS4bRHuIGiAVbei53PbifuzYZ8Uiw0dExTecU
         reHpBjkzBZDzBPEjomY56ohV33WQQn9LAakiychuBuFrJt+bev1Mnu6XeiS2kMeeCN0Y
         vc425mzsnmBtFt0S4bQgkVlYqlOtUzKhqVjq0OZrI7Dv13kOwPBf/RMOv8hxiUPbYpaF
         Av/ySGRf+6Tw9dMcEVNC0JoutqfilPH3tPqU7f5GVELD6VFbFeyblUgZBHSoSa2b2f3h
         q6Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OVvfLhysB+0iy4Qip8pj9vBPM/PIR3p9BpZ5jtYRcn4=;
        b=MXjEgeO6BT1CxG9rpvBWkSujjFRdFs3IsFQqyYDtr4XsNUWLqOe4I/dM+gi8HisAuj
         MIkK1eIzzuUmIng1lr1+Cn9mcXip/jnQB3TjIkS7e0iHmTr/xcW0Jsqpxhd36CEl6qee
         xA3d7lLF+S50tq7fRyG5EJNawX+f+QGXXAviibe18eBwBySs7Z0vFBIuwo37k3Jze7Sm
         1VPEKcyD+18Wg4teIQKBSDyDYW2l+o2Q79cnYjdpzmU6wT8BtZHxhpv0ziDc/zGYiTx+
         b9JXbVc4WdI3wWCOjQwL7frGTV3gESHLTo/7FoZqSiIlFP98I/xXAQsTMvrzs5lKJE9g
         ttwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=oBqogYyz;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id bk14-20020a056602400e00b0076c863e1ef9si1877062iob.0.2023.05.15.16.40.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 May 2023 16:40:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-1ac65ab7432so781325ad.0
        for <kasan-dev@googlegroups.com>; Mon, 15 May 2023 16:40:07 -0700 (PDT)
X-Received: by 2002:a17:902:ec85:b0:1a6:970f:8572 with SMTP id x5-20020a170902ec8500b001a6970f8572mr17131plg.3.1684194006948;
        Mon, 15 May 2023 16:40:06 -0700 (PDT)
Received: from google.com ([2620:15c:2d3:205:c825:9c0b:b4be:8ee4])
        by smtp.gmail.com with ESMTPSA id d6-20020aa78686000000b00640ddad2e0dsm12303707pfo.47.2023.05.15.16.40.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 May 2023 16:40:06 -0700 (PDT)
Date: Mon, 15 May 2023 16:40:01 -0700
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: David Hildenbrand <david@redhat.com>,
	Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	"surenb@google.com" <surenb@google.com>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Casper Li =?utf-8?B?KOadjuS4reamrik=?= <casper.li@mediatek.com>,
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
	vincenzo.frascino@arm.com,
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org,
	eugenis@google.com, Steven Price <steven.price@arm.com>,
	stable@vger.kernel.org
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before
 swap_free()
Message-ID: <ZGLC0T32sgVkG5kX@google.com>
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com>
 <ZGJtJobLrBg3PtHm@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZGJtJobLrBg3PtHm@arm.com>
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=oBqogYyz;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::62b as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Mon, May 15, 2023 at 06:34:30PM +0100, Catalin Marinas wrote:
> On Sat, May 13, 2023 at 05:29:53AM +0200, David Hildenbrand wrote:
> > On 13.05.23 01:57, Peter Collingbourne wrote:
> > > diff --git a/mm/memory.c b/mm/memory.c
> > > index 01a23ad48a04..83268d287ff1 100644
> > > --- a/mm/memory.c
> > > +++ b/mm/memory.c
> > > @@ -3914,19 +3914,7 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> > >   		}
> > >   	}
> > > -	/*
> > > -	 * Remove the swap entry and conditionally try to free up the swapcache.
> > > -	 * We're already holding a reference on the page but haven't mapped it
> > > -	 * yet.
> > > -	 */
> > > -	swap_free(entry);
> > > -	if (should_try_to_free_swap(folio, vma, vmf->flags))
> > > -		folio_free_swap(folio);
> > > -
> > > -	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
> > > -	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
> > >   	pte = mk_pte(page, vma->vm_page_prot);
> > > -
> > >   	/*
> > >   	 * Same logic as in do_wp_page(); however, optimize for pages that are
> > >   	 * certainly not shared either because we just allocated them without
> > > @@ -3946,8 +3934,21 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> > >   		pte = pte_mksoft_dirty(pte);
> > >   	if (pte_swp_uffd_wp(vmf->orig_pte))
> > >   		pte = pte_mkuffd_wp(pte);
> > > +	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
> > >   	vmf->orig_pte = pte;
> > > +	/*
> > > +	 * Remove the swap entry and conditionally try to free up the swapcache.
> > > +	 * We're already holding a reference on the page but haven't mapped it
> > > +	 * yet.
> > > +	 */
> > > +	swap_free(entry);
> > > +	if (should_try_to_free_swap(folio, vma, vmf->flags))
> > > +		folio_free_swap(folio);
> > > +
> > > +	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
> > > +	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
> > > +
> > >   	/* ksm created a completely new copy */
> > >   	if (unlikely(folio != swapcache && swapcache)) {
> > >   		page_add_new_anon_rmap(page, vma, vmf->address);
> > > @@ -3959,7 +3960,6 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> > >   	VM_BUG_ON(!folio_test_anon(folio) ||
> > >   			(pte_write(pte) && !PageAnonExclusive(page)));
> > >   	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
> > > -	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
> > >   	folio_unlock(folio);
> > >   	if (folio != swapcache && swapcache) {
> > 
> > 
> > You are moving the folio_free_swap() call after the folio_ref_count(folio)
> > == 1 check, which means that such (previously) swapped pages that are
> > exclusive cannot be detected as exclusive.
> > 
> > There must be a better way to handle MTE here.
> > 
> > Where are the tags stored, how is the location identified, and when are they
> > effectively restored right now?
> 
> I haven't gone through Peter's patches yet but a pretty good description
> of the problem is here:
> https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com/.
> I couldn't reproduce it with my swap setup but both Qun-wei and Peter
> triggered it.

In order to reproduce this bug it is necessary for the swap slot cache
to be disabled, which is unlikely to occur during normal operation. I
was only able to reproduce the bug by disabling it forcefully with the
following patch:

diff --git a/mm/swap_slots.c b/mm/swap_slots.c
index 0bec1f705f8e0..25afba16980c7 100644
--- a/mm/swap_slots.c
+++ b/mm/swap_slots.c
@@ -79,7 +79,7 @@ void disable_swap_slots_cache_lock(void)
 
 static void __reenable_swap_slots_cache(void)
 {
-	swap_slot_cache_enabled = has_usable_swap();
+	swap_slot_cache_enabled = false;
 }
 
 void reenable_swap_slots_cache_unlock(void)

With that I can trigger the bug on an MTE-utilizing process by running
a program that enumerates the process's private anonymous mappings and
calls process_madvise(MADV_PAGEOUT) on all of them.

> When a tagged page is swapped out, the arm64 code stores the metadata
> (tags) in a local xarray indexed by the swap pte. When restoring from
> swap, the arm64 set_pte_at() checks this xarray using the old swap pte
> and spills the tags onto the new page. Apparently something changed in
> the kernel recently that causes swap_range_free() to be called before
> set_pte_at(). The arm64 arch_swap_invalidate_page() frees the metadata
> from the xarray and the subsequent set_pte_at() won't find it.
> 
> If we have the page, the metadata can be restored before set_pte_at()
> and I guess that's what Peter is trying to do (again, I haven't looked
> at the details yet; leaving it for tomorrow).
> 
> Is there any other way of handling this? E.g. not release the metadata
> in arch_swap_invalidate_page() but later in set_pte_at() once it was
> restored. But then we may leak this metadata if there's no set_pte_at()
> (the process mapping the swap entry died).

Another problem that I can see with this approach is that it does not
respect reference counts for swap entries, and it's unclear whether that
can be done in a non-racy fashion.

Another approach that I considered was to move the hook to swap_readpage()
as in the patch below (sorry, it only applies to an older version
of Android's android14-6.1 branch and not mainline, but you get the
idea). But during a stress test (running the aforementioned program that
calls process_madvise(MADV_PAGEOUT) in a loop during an Android "monkey"
test) I discovered the following racy use-after-free that can occur when
two tasks T1 and T2 concurrently restore the same page:

T1:                  | T2:
arch_swap_readpage() |
                     | arch_swap_readpage() -> mte_restore_tags() -> xe_load()
swap_free()          |
                     | arch_swap_readpage() -> mte_restore_tags() -> mte_restore_page_tags()

We can avoid it by taking the swap_info_struct::lock spinlock in
mte_restore_tags(), but it seems like it would lead to lock contention.

Peter

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 3f8199ba265a1..99c8be073f107 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -25,7 +25,7 @@ unsigned long mte_copy_tags_to_user(void __user *to, void *from,
 				    unsigned long n);
 int mte_save_tags(struct page *page);
 void mte_save_page_tags(const void *page_addr, void *tag_storage);
-bool mte_restore_tags(swp_entry_t entry, struct page *page);
+void mte_restore_tags(struct page *page);
 void mte_restore_page_tags(void *page_addr, const void *tag_storage);
 void mte_invalidate_tags(int type, pgoff_t offset);
 void mte_invalidate_tags_area(int type);
diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 812373cff4eec..32d3c661a0eee 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -1054,11 +1054,11 @@ static inline void arch_swap_invalidate_area(int type)
 		mte_invalidate_tags_area(type);
 }
 
-#define __HAVE_ARCH_SWAP_RESTORE
-static inline void arch_swap_restore(swp_entry_t entry, struct folio *folio)
+#define __HAVE_ARCH_SWAP_READPAGE
+static inline void arch_swap_readpage(struct page *page)
 {
-	if (system_supports_mte() && mte_restore_tags(entry, &folio->page))
-		set_page_mte_tagged(&folio->page);
+	if (system_supports_mte())
+  		mte_restore_tags(page);
 }
 
 #endif /* CONFIG_ARM64_MTE */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 84a085d536f84..176f094ecaa1e 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -38,15 +38,6 @@ EXPORT_SYMBOL_GPL(mte_async_or_asymm_mode);
 static void mte_sync_page_tags(struct page *page, pte_t old_pte,
 			       bool check_swap, bool pte_is_tagged)
 {
-	if (check_swap && is_swap_pte(old_pte)) {
-		swp_entry_t entry = pte_to_swp_entry(old_pte);
-
-		if (!non_swap_entry(entry) && mte_restore_tags(entry, page)) {
-			set_page_mte_tagged(page);
-			return;
-		}
-	}
-
 	if (!pte_is_tagged)
 		return;
 
diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
index 70f913205db99..3fe7774f32b3c 100644
--- a/arch/arm64/mm/mteswap.c
+++ b/arch/arm64/mm/mteswap.c
@@ -46,21 +46,23 @@ int mte_save_tags(struct page *page)
 	return 0;
 }
 
-bool mte_restore_tags(swp_entry_t entry, struct page *page)
+void mte_restore_tags(struct page *page)
 {
+	swp_entry_t entry = folio_swap_entry(page_folio(page));
 	void *tags = xa_load(&mte_pages, entry.val);
 
 	if (!tags)
-		return false;
+		return;
 
 	/*
 	 * Test PG_mte_tagged again in case it was racing with another
 	 * set_pte_at().
 	 */
-	if (!test_and_set_bit(PG_mte_tagged, &page->flags))
+	if (!test_and_set_bit(PG_mte_tagged, &page->flags)) {
 		mte_restore_page_tags(page_address(page), tags);
-
-	return true;
+		if (kasan_hw_tags_enabled())
+			page_kasan_tag_reset(page);
+	}
 }
 
 void mte_invalidate_tags(int type, pgoff_t offset)
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index 5f0d7d0b9471b..eea1e545595ca 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -793,8 +793,8 @@ static inline void arch_swap_invalidate_area(int type)
 }
 #endif
 
-#ifndef __HAVE_ARCH_SWAP_RESTORE
-static inline void arch_swap_restore(swp_entry_t entry, struct folio *folio)
+#ifndef __HAVE_ARCH_SWAP_READPAGE
+static inline void arch_swap_readpage(struct page *page)
 {
 }
 #endif
diff --git a/mm/page_io.c b/mm/page_io.c
index 3a5f921b932e8..a2f53dbeca7b3 100644
--- a/mm/page_io.c
+++ b/mm/page_io.c
@@ -470,6 +470,12 @@ int swap_readpage(struct page *page, bool synchronous,
 	}
 	delayacct_swapin_start();
 
+	/*
+	 * Some architectures may have to restore extra metadata to the
+	 * page when reading from swap.
+	 */
+	arch_swap_readpage(page);
+
 	if (frontswap_load(page) == 0) {
 		SetPageUptodate(page);
 		unlock_page(page);
diff --git a/mm/shmem.c b/mm/shmem.c
index 0b335607bf2ad..82ccf1e6efe5d 100644
--- a/mm/shmem.c
+++ b/mm/shmem.c
@@ -1784,12 +1784,6 @@ static int shmem_swapin_folio(struct inode *inode, pgoff_t index,
 	}
 	folio_wait_writeback(folio);
 
-	/*
-	 * Some architectures may have to restore extra metadata to the
-	 * folio after reading from swap.
-	 */
-	arch_swap_restore(swap, folio);
-
 	if (shmem_should_replace_folio(folio, gfp)) {
 		error = shmem_replace_folio(&folio, gfp, info, index);
 		if (error)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZGLC0T32sgVkG5kX%40google.com.
