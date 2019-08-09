Return-Path: <kasan-dev+bncBDV37XP3XYDRBHWSWXVAKGQE7DEEKEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id CF5B487A4A
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 14:37:50 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id m26sf850840wmc.3
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2019 05:37:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565354270; cv=pass;
        d=google.com; s=arc-20160816;
        b=oXvxHh2Kqm5896JisITNCRtxD7lfvbkD1NU5/TL4YLCE2UIOMWtqMz6unWv/6vReVS
         JfwsXEkAyQMLfNvzvMs9UjANY0Dt5wfVBCp4PCr6j4Uzj581mD6/E8u9LzUKA/xuc/m+
         gCNF3Q9j7cLo9nbkuC/Zm9soCbrXyv+EvdY6O37Kd/eyvXQSA0OG6QNJO9pyHjxuU20k
         NIPIZ5HEvPb+CMJlVQ+Ly0ubfdott9qhbsUdEMkyZgHrVSnImr7ykmbUdQnreXMUuAz+
         m789pgUbdh6c9IjCCkuj6GUKp5O3Pfj878uO+FgYJMUYM60usuq2wqmQtVlRjZuceZ+7
         Z5JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=KEFh4TsCpY+CWMpDLGfkOUpGgAgWrnNcYaBmhEq8Rj0=;
        b=tYBJ13SgSWLB9m/0Wq2B/MCY9tHzlFk0hpX8TsnmsnG5o1G+Vsx4FNNxAKTbHYkjMt
         DXmXbDzXNlG/GHxaof5JFVl3kIh1nz3rz9e1WBADH+swXojuIf++Uk0WtKKMEs9NrRyP
         uUCGw2O21YB2CiE/Xi6t76iPT0oPClQiVJoXP1LVhXCaqCkDhqGia/s0+TI3JB4cEcVv
         jwP7nRg4Fm31XwEHiTjoqHFIDkLMLZUPPlwLYcSQRTjetqKlanWpFjbO7RKWG+Jz7q5N
         Bmx3XIEeMKPlhy770QiP0QWPAx1xdOeiTq9QEcfiCVpIcvmDFwRlq+N+D5CFnI3QX6PX
         Q/gA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KEFh4TsCpY+CWMpDLGfkOUpGgAgWrnNcYaBmhEq8Rj0=;
        b=HYtg0ce1q0hYqxU3QQS8PK8hXcgQtivQfrIFtshx5kTtK7nwsObcsKRPjjTdfkCCmK
         n5HthSgLyJlawW9vXIW4SyuKLZRpm1BXYd6DgNHVtYZ1OOoj38dWHYfIJ9My7QBVS/Zf
         EnKMJhFtHRJRa4PpIZS/MDnXHD0Vhj4I4Vfal0lZ7qvA63+pcz0L21fbkxVoUN6eCMks
         b3el1HsuIivd31Dp+W2WhVc+WqRla4ux1uAhxKtI7Ne2C+beXi4tkU7v25zvqs/5Q2Ra
         55xTN6FNxXvnQ6JwaiF46S5JQQddUnV2SIg5Z2mG0J+wcPQEoLpSASyt1ewaOZKiOrtl
         +Y2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KEFh4TsCpY+CWMpDLGfkOUpGgAgWrnNcYaBmhEq8Rj0=;
        b=k6DpyjeUIA/4kSFg7+pYYUJWB/wHAO5RtuwoBfb978fPCNly9KQoikZ0RGXtBnKXak
         FvOHO//4Q9IkhtnDKkeOBxKMrKY1Bc45bDhttD5iWX0J3kpU34Ba4i1e7XYyRRYGz7Lm
         8twwBk9+BB2aMb+IiWQR41/qwysz2rqLysui0S70ag5iicd3HpJELCCbrZ9pCbF5Ayqr
         SZLdPJWHwmbK9c3ZRgvYpxzy5IyhrbYWBZJbOrVFFXZmmXuJBsiEJ3nveA9CgrBTrbTY
         +49e3tTd9SKJWN0ELgiYmZFwT+KQl4jEGdXbmM8P34Hp6n40MmfDXE6IOHRiIqIwncgw
         GclQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV8m0T4dlY5gbC4K2B0gTh8vr6LOndpziBOjg2U2OwE8GJOyTJZ
	j+C2vtRP+69xv7+sPzUxGVQ=
X-Google-Smtp-Source: APXvYqzG5CufB6KiilRk+9QVDhYeKE/MobPIoBiWnu9S+oZa6osp+QriLBay+pt44TbxM5KmO8M3eg==
X-Received: by 2002:adf:ca0f:: with SMTP id o15mr23665837wrh.135.1565354270577;
        Fri, 09 Aug 2019 05:37:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7018:: with SMTP id l24ls1024017wmc.3.canary-gmail; Fri,
 09 Aug 2019 05:37:50 -0700 (PDT)
X-Received: by 2002:a7b:c8c3:: with SMTP id f3mr11200182wml.124.1565354270094;
        Fri, 09 Aug 2019 05:37:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565354270; cv=none;
        d=google.com; s=arc-20160816;
        b=kU8oAYlra1CZ0U9vghySZXitxzLZLgRYBAuibjdg/Nv38QjORESeveop2x3BiEX338
         3deWk/w83gmq/5oEpzRRRvHpFQd048HARo0/9kZlpLXekbhN09uW6LNf1W3zFL16g79E
         8lJ42dAu5aushw4BD6mnleffS2If+UXTbEIif+yuED2m15zlC3oQzNrDWc+pnN84PquR
         CjEIcaU9Beq2lUeZMrh1Xwz8hDe3y3fY56L3BtrADUZXEf/JKfg6lGCq82mqlOKxAfQ0
         nxpIB2VRcoAPXu3FRolxKNBaM91R4LwVSunMAch2zP/5hE5GkmtehRj3WiLf6/7/V6TS
         QCTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=XdCTuKRi/cDaELo87hK/o8ea88inhbHFfAajS7lpSSY=;
        b=b1NgN3eA0PDGv9NhFrgGGb21OyziAuRslwxfKzEPtKgq3zd3W++21CFYBgdcHN+2vI
         VcMWD22M4kNsYRR6TSih9X0swu2FnjHV0e6vDUb6frQwhtysGvH+pC4jLhRXROtrhSGy
         gsflhyfMDbtm/jXME80FQe0Cvi+gGVVMPEM/pjhsBQljkx17iFgUZJXbld9FlwmbT7zG
         117FrzEoQM3dIsXndKlgpScJerPR1T8amKKaiINxn21sAhTD1WiZLP1Z0ZjB78eqRywe
         SpMyqqzYqHy3u2tDAb24VI2w4eTwWEr+yL6QquWqaLNHuUyXUX0a2qZoKPoBEWnmHu5c
         Hm0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y4si1933414wrp.0.2019.08.09.05.37.49
        for <kasan-dev@googlegroups.com>;
        Fri, 09 Aug 2019 05:37:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6739D1596;
	Fri,  9 Aug 2019 05:37:49 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2EBDE3F706;
	Fri,  9 Aug 2019 05:37:48 -0700 (PDT)
Date: Fri, 9 Aug 2019 13:37:46 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, dvyukov@google.com
Subject: Re: [PATCH v3 1/3] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20190809123745.GG48423@lakrids.cambridge.arm.com>
References: <20190731071550.31814-1-dja@axtens.net>
 <20190731071550.31814-2-dja@axtens.net>
 <20190808135037.GA47131@lakrids.cambridge.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190808135037.GA47131@lakrids.cambridge.arm.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Thu, Aug 08, 2019 at 02:50:37PM +0100, Mark Rutland wrote:
> From looking at this for a while, there are a few more things we should
> sort out:
 
> * We can use the split pmd locks (used by both x86 and arm64) to
>   minimize contention on the init_mm ptl. As apply_to_page_range()
>   doesn't pass the corresponding pmd in, we'll have to re-walk the table
>   in the callback, but I suspect that's better than having all vmalloc
>   operations contend on the same ptl.

Just to point out: I was wrong about this. We don't initialise the split
pmd locks for the kernel page tables, so we have to use the init_mm ptl.

I've fixed that up in my kasan/vmalloc branch as below, which works for
me on arm64 (with another patch to prevent arm64 from using early shadow
for the vmalloc area).

Thanks,
Mark.

----

static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr, void *unused)
{
	unsigned long page;
	pte_t pte;

	if (likely(!pte_none(*ptep)))
		return 0;

	page = __get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);

	/*
	 * Ensure poisoning is visible before the shadow is made visible
	 * to other CPUs.
	 */
	smp_wmb();

	spin_lock(&init_mm.page_table_lock);
	if (likely(pte_none(*ptep))) {
		set_pte_at(&init_mm, addr, ptep, pte);
		page = 0;
	}
	spin_unlock(&init_mm.page_table_lock);
	if (page)
		free_page(page);
	return 0;
}

int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
{
	unsigned long shadow_start, shadow_end;
	int ret;

	shadow_start = (unsigned long)kasan_mem_to_shadow(area->addr);
	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
	shadow_end = (unsigned long)kasan_mem_to_shadow(area->addr + area->size),
	shadow_end = ALIGN(shadow_end, PAGE_SIZE);

	ret = apply_to_page_range(&init_mm, shadow_start,
				  shadow_end - shadow_start,
				  kasan_populate_vmalloc_pte, NULL);
	if (ret)
		return ret;

	kasan_unpoison_shadow(area->addr, requested_size);

	/*
	 * We have to poison the remainder of the allocation each time, not
	 * just when the shadow page is first allocated, because vmalloc may
	 * reuse addresses, and an early large allocation would cause us to
	 * miss OOBs in future smaller allocations.
	 *
	 * The alternative is to poison the shadow on vfree()/vunmap(). We
	 * don't because the unmapping the virtual addresses should be
	 * sufficient to find most UAFs.
	 */
	requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
	kasan_poison_shadow(area->addr + requested_size,
			    area->size - requested_size,
			    KASAN_VMALLOC_INVALID);

	return 0;
}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190809123745.GG48423%40lakrids.cambridge.arm.com.
