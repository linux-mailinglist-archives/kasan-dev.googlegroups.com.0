Return-Path: <kasan-dev+bncBCZP5TXROEIJZLEQW4DBUBECJUTOS@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id DF589977DB9
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 12:38:21 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2d878377fc2sf3023022a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 03:38:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726223900; cv=pass;
        d=google.com; s=arc-20240605;
        b=JSqHiiAyj1ajedCFf8qsW9ghAylvYo5uL58KDe1X4Ty6gWPFd0La9PfyzM7cYaiQWG
         o9GniK3/hE1thdNj01BQHrdEvUYs6EvMfh6ICpI/YUiILZu5dD6UYdtnbNpYW5sQ1tdh
         F3RM0uprs4LwvSvDhXiMyvq3O+LhaVdDEN9t6jdrAawyPEGhWgylTh5PWb4Dk4qdan8y
         eGnmxSQkd9sJuaudBFx0nWh3/aa4oRHqjiWrgNrSEwvVS0gWY/04LP2uMm3WnRzBZpAi
         aheg0YUBR3jU3mvtQRYNbxJ6GL3zAk5mkxTLq9eHiiX5uu0uSnJgA5d8iYC3hSj8Gf9O
         J6QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=XcMsTWu0g6hSJM8VbEsbJk38p0YEcVW1x0c+5g1E/YY=;
        fh=DbSkD61rVoD3LzF+iS0EwsnQO0Y58vPYvn08QHz5njw=;
        b=FMPzrmcG8xmll0rCrKp3YThqe7z1Bj31W8WpAL2gmQSbZ5pImsKInO/kJhiZpSdpV5
         NXaMoxA970usUStBiQNwGe/pEXOOnVCp64/9XIhCzdAUPUXwuID3osTv8QiIjob+k08z
         A03CvQs+eLsMlZh4kje5mMXS0FJD/bvUC9OO6k1vefwIqZ1M7E0G/oHfgtrEfoo+fAC8
         N8JfwoI7Z32Er1DhezwjaNXGmcAlUh2X11a2XZp2+How3X7AF4DWPE0ddwpDXZL0PM1m
         Ee31KCas1XinMa17oWaMWHQLZk2NqQLtA8sy8yEbJKWoysMBnjoqC3k53CanJ9149zIF
         BVsA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726223900; x=1726828700; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XcMsTWu0g6hSJM8VbEsbJk38p0YEcVW1x0c+5g1E/YY=;
        b=WJWLjhtN5sKfbzWw8hTsvIUFTq/ofEwzMKpH8hzsyWDzd+7NSOH2UvIlS8EUW8YUtm
         GBHnmP+5HqmhddpkdHQlWHnwJNR8s/DggViUVn8/d2GgUxqzy3AAOHSjupeAM6ZWkHY2
         E+IHZbgPJdyRYHypKPNW/JBRqGCuX9m28TqYTAOQOsPfCEqnK9m+u/zAqsuymg1ucWw8
         ycz2/jKZWMGVshTLMBQ5NdrRDWQhMQgTqSrcCDMvz3fR/Q6DQng917X1u1a4oclRSItb
         eZp4OcOjqTjg6E9EzbWeVcdqQt3ORCPENm6i3qTSHUmTThlU0swlIG9Sr1U0C+xhW/cn
         +HKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726223900; x=1726828700;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XcMsTWu0g6hSJM8VbEsbJk38p0YEcVW1x0c+5g1E/YY=;
        b=d1ZarISjAJUhStyU24Tmdy8V0+Z7b4X4IqI/OeP0VYoCh5dIroGuQ4Bu8aqe+4pScx
         hoPx2d8MtQFWb0LydsbLd9+YYxHS7G2JcoWXFtuOcVFmVdat50XNLKs9o6V+5rP4tDbu
         JM5nkXpFXTPno82aJfHPvq2L3NKAWGRMoktnnINDPI1me3z+u7yuG57H7gwMrN0K3JQJ
         TVouXywtSCMELHyHVk0SjceahZ3n/y2HAN70ZXnEKIR1ST/jG4bw9DzQ9aQcQSkPo70i
         JJWUvK+X4LWGYDFn8MIlog4VNkdI3DBZnyJqqIYETjRtQjiPU8HI6XeIu1HTXTWu7s9N
         EuBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXgckzHsw6BILf40VqKtVQNx8BbKs07ALeFuh7Pll3etoRJPsS39t7x1ZjvQStmcT8tsA+hOw==@lfdr.de
X-Gm-Message-State: AOJu0YyfXWBpMH3OzCkmhiTolmLGktWm3zOtNhZcKqfTDez5J2lMnShY
	e+o72Ed7bYR77R7NeHtmI3YY/5ha/IaZMIR3TulgC65EY/oHjMu2
X-Google-Smtp-Source: AGHT+IFGM2I5W56jIhZfQ+maJ/E4fOC7/u2aGBysm5l8ClIt5AW63OEqM40vBHcfTrHWn8FVp4sXdA==
X-Received: by 2002:a17:90a:2dc8:b0:2da:55d9:a7d9 with SMTP id 98e67ed59e1d1-2db6717b819mr21063022a91.2.1726223900253;
        Fri, 13 Sep 2024 03:38:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2ece:b0:2d8:b259:449c with SMTP id
 98e67ed59e1d1-2db838ccb31ls1640497a91.0.-pod-prod-00-us-canary; Fri, 13 Sep
 2024 03:38:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWYeqjoRY8zw7OxJ0Evb3xfd1ZISdjBEJfHhb5HrWjHUVhAo/Y9uYMnZmwZOEnHkPB+sNokKCKWoyw=@googlegroups.com
X-Received: by 2002:a17:90b:4a4a:b0:2d8:ea11:b2db with SMTP id 98e67ed59e1d1-2db9fcb8f61mr9677586a91.16.1726223898855;
        Fri, 13 Sep 2024 03:38:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726223898; cv=none;
        d=google.com; s=arc-20240605;
        b=hj/8b2lL8wdW8W5FWH3oleBZuiWVdJguDqJrdxERP0Eq8O5uvwjjLbGxakW4NqeXzz
         bXNa243a/AiPCobWbZZYaTqj3Ke2U1gjwSzEYHcamqN92SHcJuS5TKL646u8GYnWGQS8
         oao/fH7j4aSkQSgT5gn4C6pTKq/b2ALadLOVkhdDNJciOoOwOIHOkm5FFkC9y0JQ5vCy
         FGVI2N8v05eeMObNmNdIKUhstSp6GA2V+MhPbN208LQoP+384Rj76K0tP5sllwTpkk1Z
         ZkYwiyuWD/DYmix6PHuOFgO2E0HOfmYxuhxMQD9YXuB++h3JHWbVw/g00HoZp8iTls5L
         FSDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=doayacLmV+Vy4SawBth08MwzOQeB0L0yKdadJmao97Q=;
        fh=l25RvBe/s6YfacKeFKBjedFkF4JxPl5LsFp+0trKl/I=;
        b=WLIOxeoEyq4rlErc6IahkcfBezzkunoiNORH6APUMxDR2fAa6RdP85EEHA0BzrB4iH
         su/WEOIadggI8/ItoUhc04Jd2zhv654jN/wmth+tQIypqsrSyDAHlz5oq6wzDZJOyejx
         uvJTIGEuz9xwIgDM+Oa/1yycm9xQxORsWxhtsOb76A4xxWDq65sxdH/hz24N2itCUCcy
         xKfSi0ttd3KJi2orlfke6UrzdaIaZoPY2dk6s29JoR61N0woXEIcScx5zgud0QXRYGnD
         tpjV9WIZx7AgC5RqF6xnS02aTGkDiKbIbvtkAK1rfIDj1A7B5JWcbLnAUSXFe7r6x/Xf
         FGFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2db6c1a8e82si589438a91.0.2024.09.13.03.38.18
        for <kasan-dev@googlegroups.com>;
        Fri, 13 Sep 2024 03:38:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4ECBADA7;
	Fri, 13 Sep 2024 03:38:47 -0700 (PDT)
Received: from [10.57.82.141] (unknown [10.57.82.141])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 404C83F64C;
	Fri, 13 Sep 2024 03:38:11 -0700 (PDT)
Message-ID: <f918bd00-c6a4-498a-bd17-9f5b32f7d6a7@arm.com>
Date: Fri, 13 Sep 2024 11:38:09 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 4/7] mm: Use pmdp_get() for accessing PMD entries
Content-Language: en-GB
To: Anshuman Khandual <anshuman.khandual@arm.com>, linux-mm@kvack.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, Dimitri Sivanich
 <dimitri.sivanich@hpe.com>, Muchun Song <muchun.song@linux.dev>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Miaohe Lin <linmiaohe@huawei.com>,
 Naoya Horiguchi <nao.horiguchi@gmail.com>,
 Pasha Tatashin <pasha.tatashin@soleen.com>, Dennis Zhou <dennis@kernel.org>,
 Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>,
 Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>
References: <20240913084433.1016256-1-anshuman.khandual@arm.com>
 <20240913084433.1016256-5-anshuman.khandual@arm.com>
From: Ryan Roberts <ryan.roberts@arm.com>
In-Reply-To: <20240913084433.1016256-5-anshuman.khandual@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ryan.roberts@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ryan.roberts@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 13/09/2024 09:44, Anshuman Khandual wrote:
> Convert PMD accesses via pmdp_get() helper that defaults as READ_ONCE() but
> also provides the platform an opportunity to override when required.
> 
> Cc: Dimitri Sivanich <dimitri.sivanich@hpe.com>
> Cc: Muchun Song <muchun.song@linux.dev>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Miaohe Lin <linmiaohe@huawei.com>
> Cc: Naoya Horiguchi <nao.horiguchi@gmail.com>
> Cc: Pasha Tatashin <pasha.tatashin@soleen.com>
> Cc: Dennis Zhou <dennis@kernel.org>
> Cc: Tejun Heo <tj@kernel.org>
> Cc: Christoph Lameter <cl@linux.com>
> Cc: Uladzislau Rezki <urezki@gmail.com>
> Cc: Christoph Hellwig <hch@infradead.org>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: David Hildenbrand <david@redhat.com>
> Cc: Ryan Roberts <ryan.roberts@arm.com>
> Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
> Cc: linux-kernel@vger.kernel.org
> Cc: linux-fsdevel@vger.kernel.org
> Cc: linux-mm@kvack.org
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
> ---
>  drivers/misc/sgi-gru/grufault.c |  4 +--
>  fs/proc/task_mmu.c              | 26 +++++++-------
>  include/linux/huge_mm.h         |  3 +-
>  include/linux/mm.h              |  2 +-
>  include/linux/pgtable.h         | 14 ++++----
>  mm/gup.c                        | 14 ++++----
>  mm/huge_memory.c                | 60 ++++++++++++++++-----------------
>  mm/hugetlb_vmemmap.c            |  4 +--
>  mm/kasan/init.c                 | 10 +++---
>  mm/kasan/shadow.c               |  4 +--
>  mm/khugepaged.c                 |  4 +--
>  mm/madvise.c                    |  6 ++--
>  mm/memory-failure.c             |  6 ++--
>  mm/memory.c                     | 25 +++++++-------
>  mm/mempolicy.c                  |  4 +--
>  mm/migrate.c                    |  4 +--
>  mm/migrate_device.c             | 10 +++---
>  mm/mlock.c                      |  6 ++--
>  mm/mprotect.c                   |  2 +-
>  mm/mremap.c                     |  4 +--
>  mm/page_table_check.c           |  2 +-
>  mm/pagewalk.c                   |  4 +--
>  mm/percpu.c                     |  2 +-
>  mm/pgtable-generic.c            | 16 ++++-----
>  mm/ptdump.c                     |  2 +-
>  mm/rmap.c                       |  2 +-
>  mm/sparse-vmemmap.c             |  4 +--
>  mm/vmalloc.c                    | 12 +++----
>  28 files changed, 129 insertions(+), 127 deletions(-)
> 
> diff --git a/drivers/misc/sgi-gru/grufault.c b/drivers/misc/sgi-gru/grufault.c
> index 3557d78ee47a..f3d6249b7dfb 100644
> --- a/drivers/misc/sgi-gru/grufault.c
> +++ b/drivers/misc/sgi-gru/grufault.c
> @@ -224,10 +224,10 @@ static int atomic_pte_lookup(struct vm_area_struct *vma, unsigned long vaddr,
>  		goto err;
>  
>  	pmdp = pmd_offset(pudp, vaddr);
> -	if (unlikely(pmd_none(*pmdp)))
> +	if (unlikely(pmd_none(pmdp_get(pmdp))))
>  		goto err;
>  #ifdef CONFIG_X86_64
> -	if (unlikely(pmd_leaf(*pmdp)))
> +	if (unlikely(pmd_leaf(pmdp_get(pmdp))))

Just a general comment about multiple gets; before, the compiler most likely
turned multiple '*pmdp' dereferences into a single actual load. But READ_ONCE()
inside pmdp_get() ensures you get a load for every call to pmdp_get(). This has
2 potential problems:

 - More loads could potentially regress speed in some hot paths

 - In paths that don't hold an appropriate PTL the multiple loads could race
with a writer, meaning each load gets a different value. The intent of the code
is usually that each check is operating on the same value.

For the ptep_get() conversion, I solved this by reading into a temporary once
then using the temporary for the comparisons.

I'm not sure if these are real problems in practice, but seems safest to
continue to follow this established pattern?

Thanks,
Ryan


>  		pte = ptep_get((pte_t *)pmdp);
>  	else
>  #endif
> diff --git a/fs/proc/task_mmu.c b/fs/proc/task_mmu.c
> index 5f171ad7b436..8bb90f877dc5 100644
> --- a/fs/proc/task_mmu.c
> +++ b/fs/proc/task_mmu.c
> @@ -862,11 +862,11 @@ static void smaps_pmd_entry(pmd_t *pmd, unsigned long addr,
>  	bool present = false;
>  	struct folio *folio;
>  
> -	if (pmd_present(*pmd)) {
> -		page = vm_normal_page_pmd(vma, addr, *pmd);
> +	if (pmd_present(pmdp_get(pmd))) {
> +		page = vm_normal_page_pmd(vma, addr, pmdp_get(pmd));
>  		present = true;
> -	} else if (unlikely(thp_migration_supported() && is_swap_pmd(*pmd))) {
> -		swp_entry_t entry = pmd_to_swp_entry(*pmd);
> +	} else if (unlikely(thp_migration_supported() && is_swap_pmd(pmdp_get(pmd)))) {
> +		swp_entry_t entry = pmd_to_swp_entry(pmdp_get(pmd));
>  
>  		if (is_pfn_swap_entry(entry))
>  			page = pfn_swap_entry_to_page(entry);
> @@ -883,7 +883,7 @@ static void smaps_pmd_entry(pmd_t *pmd, unsigned long addr,
>  	else
>  		mss->file_thp += HPAGE_PMD_SIZE;
>  
> -	smaps_account(mss, page, true, pmd_young(*pmd), pmd_dirty(*pmd),
> +	smaps_account(mss, page, true, pmd_young(pmdp_get(pmd)), pmd_dirty(pmdp_get(pmd)),
>  		      locked, present);
>  }
>  #else
> @@ -1426,7 +1426,7 @@ static inline void clear_soft_dirty(struct vm_area_struct *vma,
>  static inline void clear_soft_dirty_pmd(struct vm_area_struct *vma,
>  		unsigned long addr, pmd_t *pmdp)
>  {
> -	pmd_t old, pmd = *pmdp;
> +	pmd_t old, pmd = pmdp_get(pmdp);
>  
>  	if (pmd_present(pmd)) {
>  		/* See comment in change_huge_pmd() */
> @@ -1468,10 +1468,10 @@ static int clear_refs_pte_range(pmd_t *pmd, unsigned long addr,
>  			goto out;
>  		}
>  
> -		if (!pmd_present(*pmd))
> +		if (!pmd_present(pmdp_get(pmd)))
>  			goto out;
>  
> -		folio = pmd_folio(*pmd);
> +		folio = pmd_folio(pmdp_get(pmd));
>  
>  		/* Clear accessed and referenced bits. */
>  		pmdp_test_and_clear_young(vma, addr, pmd);
> @@ -1769,7 +1769,7 @@ static int pagemap_pmd_range(pmd_t *pmdp, unsigned long addr, unsigned long end,
>  	if (ptl) {
>  		unsigned int idx = (addr & ~PMD_MASK) >> PAGE_SHIFT;
>  		u64 flags = 0, frame = 0;
> -		pmd_t pmd = *pmdp;
> +		pmd_t pmd = pmdp_get(pmdp);
>  		struct page *page = NULL;
>  		struct folio *folio = NULL;
>  
> @@ -2189,7 +2189,7 @@ static unsigned long pagemap_thp_category(struct pagemap_scan_private *p,
>  static void make_uffd_wp_pmd(struct vm_area_struct *vma,
>  			     unsigned long addr, pmd_t *pmdp)
>  {
> -	pmd_t old, pmd = *pmdp;
> +	pmd_t old, pmd = pmdp_get(pmdp);
>  
>  	if (pmd_present(pmd)) {
>  		old = pmdp_invalidate_ad(vma, addr, pmdp);
> @@ -2416,7 +2416,7 @@ static int pagemap_scan_thp_entry(pmd_t *pmd, unsigned long start,
>  		return -ENOENT;
>  
>  	categories = p->cur_vma_category |
> -		     pagemap_thp_category(p, vma, start, *pmd);
> +		     pagemap_thp_category(p, vma, start, pmdp_get(pmd));
>  
>  	if (!pagemap_scan_is_interesting_page(categories, p))
>  		goto out_unlock;
> @@ -2947,9 +2947,9 @@ static int gather_pte_stats(pmd_t *pmd, unsigned long addr,
>  	if (ptl) {
>  		struct page *page;
>  
> -		page = can_gather_numa_stats_pmd(*pmd, vma, addr);
> +		page = can_gather_numa_stats_pmd(pmdp_get(pmd), vma, addr);
>  		if (page)
> -			gather_stats(page, md, pmd_dirty(*pmd),
> +			gather_stats(page, md, pmd_dirty(pmdp_get(pmd)),
>  				     HPAGE_PMD_SIZE/PAGE_SIZE);
>  		spin_unlock(ptl);
>  		return 0;
> diff --git a/include/linux/huge_mm.h b/include/linux/huge_mm.h
> index e25d9ebfdf89..351d6c72af9e 100644
> --- a/include/linux/huge_mm.h
> +++ b/include/linux/huge_mm.h
> @@ -369,7 +369,8 @@ static inline int is_swap_pmd(pmd_t pmd)
>  static inline spinlock_t *pmd_trans_huge_lock(pmd_t *pmd,
>  		struct vm_area_struct *vma)
>  {
> -	if (is_swap_pmd(*pmd) || pmd_trans_huge(*pmd) || pmd_devmap(*pmd))
> +	if (is_swap_pmd(pmdp_get(pmd)) || pmd_trans_huge(pmdp_get(pmd)) ||
> +	    pmd_devmap(pmdp_get(pmd)))
>  		return __pmd_trans_huge_lock(pmd, vma);
>  	else
>  		return NULL;
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 147073601716..258e49323306 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -2921,7 +2921,7 @@ static inline spinlock_t *ptlock_ptr(struct ptdesc *ptdesc)
>  
>  static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
>  {
> -	return ptlock_ptr(page_ptdesc(pmd_page(*pmd)));
> +	return ptlock_ptr(page_ptdesc(pmd_page(pmdp_get(pmd))));
>  }
>  
>  static inline spinlock_t *ptep_lockptr(struct mm_struct *mm, pte_t *pte)
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index 05e6995c1b93..188a183205b3 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -367,7 +367,7 @@ static inline int pmdp_test_and_clear_young(struct vm_area_struct *vma,
>  					    unsigned long address,
>  					    pmd_t *pmdp)
>  {
> -	pmd_t pmd = *pmdp;
> +	pmd_t pmd = pmdp_get(pmdp);
>  	int r = 1;
>  	if (!pmd_young(pmd))
>  		r = 0;
> @@ -598,7 +598,7 @@ static inline pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm,
>  					    unsigned long address,
>  					    pmd_t *pmdp)
>  {
> -	pmd_t pmd = *pmdp;
> +	pmd_t pmd = pmdp_get(pmdp);
>  
>  	pmd_clear(pmdp);
>  	page_table_check_pmd_clear(mm, pmd);
> @@ -876,7 +876,7 @@ static inline pte_t pte_sw_mkyoung(pte_t pte)
>  static inline void pmdp_set_wrprotect(struct mm_struct *mm,
>  				      unsigned long address, pmd_t *pmdp)
>  {
> -	pmd_t old_pmd = *pmdp;
> +	pmd_t old_pmd = pmdp_get(pmdp);
>  	set_pmd_at(mm, address, pmdp, pmd_wrprotect(old_pmd));
>  }
>  #else
> @@ -945,7 +945,7 @@ extern pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp);
>  static inline pmd_t generic_pmdp_establish(struct vm_area_struct *vma,
>  		unsigned long address, pmd_t *pmdp, pmd_t pmd)
>  {
> -	pmd_t old_pmd = *pmdp;
> +	pmd_t old_pmd = pmdp_get(pmdp);
>  	set_pmd_at(vma->vm_mm, address, pmdp, pmd);
>  	return old_pmd;
>  }
> @@ -1066,7 +1066,7 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
>  
>  #define set_pmd_safe(pmdp, pmd) \
>  ({ \
> -	WARN_ON_ONCE(pmd_present(*pmdp) && !pmd_same(*pmdp, pmd)); \
> +	WARN_ON_ONCE(pmd_present(pmdp_get(pmdp)) && !pmd_same(pmdp_get(pmdp), pmd)); \
>  	set_pmd(pmdp, pmd); \
>  })
>  
> @@ -1270,9 +1270,9 @@ static inline int pud_none_or_clear_bad(pud_t *pud)
>  
>  static inline int pmd_none_or_clear_bad(pmd_t *pmd)
>  {
> -	if (pmd_none(*pmd))
> +	if (pmd_none(pmdp_get(pmd)))
>  		return 1;
> -	if (unlikely(pmd_bad(*pmd))) {
> +	if (unlikely(pmd_bad(pmdp_get(pmd)))) {
>  		pmd_clear_bad(pmd);
>  		return 1;
>  	}
> diff --git a/mm/gup.c b/mm/gup.c
> index 54d0dc3831fb..aeeac0a54944 100644
> --- a/mm/gup.c
> +++ b/mm/gup.c
> @@ -699,7 +699,7 @@ static struct page *follow_huge_pmd(struct vm_area_struct *vma,
>  				    struct follow_page_context *ctx)
>  {
>  	struct mm_struct *mm = vma->vm_mm;
> -	pmd_t pmdval = *pmd;
> +	pmd_t pmdval = pmdp_get(pmd);
>  	struct page *page;
>  	int ret;
>  
> @@ -714,7 +714,7 @@ static struct page *follow_huge_pmd(struct vm_area_struct *vma,
>  	if ((flags & FOLL_DUMP) && is_huge_zero_pmd(pmdval))
>  		return ERR_PTR(-EFAULT);
>  
> -	if (pmd_protnone(*pmd) && !gup_can_follow_protnone(vma, flags))
> +	if (pmd_protnone(pmdp_get(pmd)) && !gup_can_follow_protnone(vma, flags))
>  		return NULL;
>  
>  	if (!pmd_write(pmdval) && gup_must_unshare(vma, flags, page))
> @@ -957,7 +957,7 @@ static struct page *follow_pmd_mask(struct vm_area_struct *vma,
>  		return no_page_table(vma, flags, address);
>  
>  	ptl = pmd_lock(mm, pmd);
> -	pmdval = *pmd;
> +	pmdval = pmdp_get(pmd);
>  	if (unlikely(!pmd_present(pmdval))) {
>  		spin_unlock(ptl);
>  		return no_page_table(vma, flags, address);
> @@ -1120,7 +1120,7 @@ static int get_gate_page(struct mm_struct *mm, unsigned long address,
>  	if (pud_none(*pud))
>  		return -EFAULT;
>  	pmd = pmd_offset(pud, address);
> -	if (!pmd_present(*pmd))
> +	if (!pmd_present(pmdp_get(pmd)))
>  		return -EFAULT;
>  	pte = pte_offset_map(pmd, address);
>  	if (!pte)
> @@ -2898,7 +2898,7 @@ static int gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr,
>  		if (!folio)
>  			goto pte_unmap;
>  
> -		if (unlikely(pmd_val(pmd) != pmd_val(*pmdp)) ||
> +		if (unlikely(pmd_val(pmd) != pmd_val(pmdp_get(pmdp))) ||
>  		    unlikely(pte_val(pte) != pte_val(ptep_get(ptep)))) {
>  			gup_put_folio(folio, 1, flags);
>  			goto pte_unmap;
> @@ -3007,7 +3007,7 @@ static int gup_fast_devmap_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>  	if (!gup_fast_devmap_leaf(fault_pfn, addr, end, flags, pages, nr))
>  		return 0;
>  
> -	if (unlikely(pmd_val(orig) != pmd_val(*pmdp))) {
> +	if (unlikely(pmd_val(orig) != pmd_val(pmdp_get(pmdp)))) {
>  		gup_fast_undo_dev_pagemap(nr, nr_start, flags, pages);
>  		return 0;
>  	}
> @@ -3074,7 +3074,7 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>  	if (!folio)
>  		return 0;
>  
> -	if (unlikely(pmd_val(orig) != pmd_val(*pmdp))) {
> +	if (unlikely(pmd_val(orig) != pmd_val(pmdp_get(pmdp)))) {
>  		gup_put_folio(folio, refs, flags);
>  		return 0;
>  	}
> diff --git a/mm/huge_memory.c b/mm/huge_memory.c
> index 67c86a5d64a6..3545142a5dc9 100644
> --- a/mm/huge_memory.c
> +++ b/mm/huge_memory.c
> @@ -1065,7 +1065,7 @@ static void set_huge_zero_folio(pgtable_t pgtable, struct mm_struct *mm,
>  		struct folio *zero_folio)
>  {
>  	pmd_t entry;
> -	if (!pmd_none(*pmd))
> +	if (!pmd_none(pmdp_get(pmd)))
>  		return;
>  	entry = mk_pmd(&zero_folio->page, vma->vm_page_prot);
>  	entry = pmd_mkhuge(entry);
> @@ -1148,13 +1148,13 @@ static void insert_pfn_pmd(struct vm_area_struct *vma, unsigned long addr,
>  	spinlock_t *ptl;
>  
>  	ptl = pmd_lock(mm, pmd);
> -	if (!pmd_none(*pmd)) {
> +	if (!pmd_none(pmdp_get(pmd))) {
>  		if (write) {
> -			if (pmd_pfn(*pmd) != pfn_t_to_pfn(pfn)) {
> -				WARN_ON_ONCE(!is_huge_zero_pmd(*pmd));
> +			if (pmd_pfn(pmdp_get(pmd)) != pfn_t_to_pfn(pfn)) {
> +				WARN_ON_ONCE(!is_huge_zero_pmd(pmdp_get(pmd)));
>  				goto out_unlock;
>  			}
> -			entry = pmd_mkyoung(*pmd);
> +			entry = pmd_mkyoung(pmdp_get(pmd));
>  			entry = maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);
>  			if (pmdp_set_access_flags(vma, addr, pmd, entry, 1))
>  				update_mmu_cache_pmd(vma, addr, pmd);
> @@ -1318,7 +1318,7 @@ void touch_pmd(struct vm_area_struct *vma, unsigned long addr,
>  {
>  	pmd_t _pmd;
>  
> -	_pmd = pmd_mkyoung(*pmd);
> +	_pmd = pmd_mkyoung(pmdp_get(pmd));
>  	if (write)
>  		_pmd = pmd_mkdirty(_pmd);
>  	if (pmdp_set_access_flags(vma, addr & HPAGE_PMD_MASK,
> @@ -1329,17 +1329,17 @@ void touch_pmd(struct vm_area_struct *vma, unsigned long addr,
>  struct page *follow_devmap_pmd(struct vm_area_struct *vma, unsigned long addr,
>  		pmd_t *pmd, int flags, struct dev_pagemap **pgmap)
>  {
> -	unsigned long pfn = pmd_pfn(*pmd);
> +	unsigned long pfn = pmd_pfn(pmdp_get(pmd));
>  	struct mm_struct *mm = vma->vm_mm;
>  	struct page *page;
>  	int ret;
>  
>  	assert_spin_locked(pmd_lockptr(mm, pmd));
>  
> -	if (flags & FOLL_WRITE && !pmd_write(*pmd))
> +	if (flags & FOLL_WRITE && !pmd_write(pmdp_get(pmd)))
>  		return NULL;
>  
> -	if (pmd_present(*pmd) && pmd_devmap(*pmd))
> +	if (pmd_present(pmdp_get(pmd)) && pmd_devmap(pmdp_get(pmd)))
>  		/* pass */;
>  	else
>  		return NULL;
> @@ -1772,7 +1772,7 @@ bool madvise_free_huge_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma,
>  	if (!ptl)
>  		goto out_unlocked;
>  
> -	orig_pmd = *pmd;
> +	orig_pmd = pmdp_get(pmd);
>  	if (is_huge_zero_pmd(orig_pmd))
>  		goto out;
>  
> @@ -2006,12 +2006,12 @@ int change_huge_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma,
>  		return 0;
>  
>  #ifdef CONFIG_ARCH_ENABLE_THP_MIGRATION
> -	if (is_swap_pmd(*pmd)) {
> -		swp_entry_t entry = pmd_to_swp_entry(*pmd);
> +	if (is_swap_pmd(pmdp_get(pmd))) {
> +		swp_entry_t entry = pmd_to_swp_entry(pmdp_get(pmd));
>  		struct folio *folio = pfn_swap_entry_folio(entry);
>  		pmd_t newpmd;
>  
> -		VM_BUG_ON(!is_pmd_migration_entry(*pmd));
> +		VM_BUG_ON(!is_pmd_migration_entry(pmdp_get(pmd)));
>  		if (is_writable_migration_entry(entry)) {
>  			/*
>  			 * A protection check is difficult so
> @@ -2022,17 +2022,17 @@ int change_huge_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma,
>  			else
>  				entry = make_readable_migration_entry(swp_offset(entry));
>  			newpmd = swp_entry_to_pmd(entry);
> -			if (pmd_swp_soft_dirty(*pmd))
> +			if (pmd_swp_soft_dirty(pmdp_get(pmd)))
>  				newpmd = pmd_swp_mksoft_dirty(newpmd);
>  		} else {
> -			newpmd = *pmd;
> +			newpmd = pmdp_get(pmd);
>  		}
>  
>  		if (uffd_wp)
>  			newpmd = pmd_swp_mkuffd_wp(newpmd);
>  		else if (uffd_wp_resolve)
>  			newpmd = pmd_swp_clear_uffd_wp(newpmd);
> -		if (!pmd_same(*pmd, newpmd))
> +		if (!pmd_same(pmdp_get(pmd), newpmd))
>  			set_pmd_at(mm, addr, pmd, newpmd);
>  		goto unlock;
>  	}
> @@ -2046,13 +2046,13 @@ int change_huge_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma,
>  		 * data is likely to be read-cached on the local CPU and
>  		 * local/remote hits to the zero page are not interesting.
>  		 */
> -		if (is_huge_zero_pmd(*pmd))
> +		if (is_huge_zero_pmd(pmdp_get(pmd)))
>  			goto unlock;
>  
> -		if (pmd_protnone(*pmd))
> +		if (pmd_protnone(pmdp_get(pmd)))
>  			goto unlock;
>  
> -		folio = pmd_folio(*pmd);
> +		folio = pmd_folio(pmdp_get(pmd));
>  		toptier = node_is_toptier(folio_nid(folio));
>  		/*
>  		 * Skip scanning top tier node if normal numa
> @@ -2266,8 +2266,8 @@ spinlock_t *__pmd_trans_huge_lock(pmd_t *pmd, struct vm_area_struct *vma)
>  {
>  	spinlock_t *ptl;
>  	ptl = pmd_lock(vma->vm_mm, pmd);
> -	if (likely(is_swap_pmd(*pmd) || pmd_trans_huge(*pmd) ||
> -			pmd_devmap(*pmd)))
> +	if (likely(is_swap_pmd(pmdp_get(pmd)) || pmd_trans_huge(pmdp_get(pmd)) ||
> +			pmd_devmap(pmdp_get(pmd))))
>  		return ptl;
>  	spin_unlock(ptl);
>  	return NULL;
> @@ -2404,8 +2404,8 @@ static void __split_huge_pmd_locked(struct vm_area_struct *vma, pmd_t *pmd,
>  	VM_BUG_ON(haddr & ~HPAGE_PMD_MASK);
>  	VM_BUG_ON_VMA(vma->vm_start > haddr, vma);
>  	VM_BUG_ON_VMA(vma->vm_end < haddr + HPAGE_PMD_SIZE, vma);
> -	VM_BUG_ON(!is_pmd_migration_entry(*pmd) && !pmd_trans_huge(*pmd)
> -				&& !pmd_devmap(*pmd));
> +	VM_BUG_ON(!is_pmd_migration_entry(pmdp_get(pmd)) && !pmd_trans_huge(pmdp_get(pmd))
> +				&& !pmd_devmap(pmdp_get(pmd)));
>  
>  	count_vm_event(THP_SPLIT_PMD);
>  
> @@ -2438,7 +2438,7 @@ static void __split_huge_pmd_locked(struct vm_area_struct *vma, pmd_t *pmd,
>  		return;
>  	}
>  
> -	if (is_huge_zero_pmd(*pmd)) {
> +	if (is_huge_zero_pmd(pmdp_get(pmd))) {
>  		/*
>  		 * FIXME: Do we want to invalidate secondary mmu by calling
>  		 * mmu_notifier_arch_invalidate_secondary_tlbs() see comments below
> @@ -2451,11 +2451,11 @@ static void __split_huge_pmd_locked(struct vm_area_struct *vma, pmd_t *pmd,
>  		return __split_huge_zero_page_pmd(vma, haddr, pmd);
>  	}
>  
> -	pmd_migration = is_pmd_migration_entry(*pmd);
> +	pmd_migration = is_pmd_migration_entry(pmdp_get(pmd));
>  	if (unlikely(pmd_migration)) {
>  		swp_entry_t entry;
>  
> -		old_pmd = *pmd;
> +		old_pmd = pmdp_get(pmd);
>  		entry = pmd_to_swp_entry(old_pmd);
>  		page = pfn_swap_entry_to_page(entry);
>  		write = is_writable_migration_entry(entry);
> @@ -2620,9 +2620,9 @@ void split_huge_pmd_locked(struct vm_area_struct *vma, unsigned long address,
>  	 * require a folio to check the PMD against. Otherwise, there
>  	 * is a risk of replacing the wrong folio.
>  	 */
> -	if (pmd_trans_huge(*pmd) || pmd_devmap(*pmd) ||
> -	    is_pmd_migration_entry(*pmd)) {
> -		if (folio && folio != pmd_folio(*pmd))
> +	if (pmd_trans_huge(pmdp_get(pmd)) || pmd_devmap(pmdp_get(pmd)) ||
> +	    is_pmd_migration_entry(pmdp_get(pmd))) {
> +		if (folio && folio != pmd_folio(pmdp_get(pmd)))
>  			return;
>  		__split_huge_pmd_locked(vma, pmd, address, freeze);
>  	}
> @@ -2719,7 +2719,7 @@ static bool __discard_anon_folio_pmd_locked(struct vm_area_struct *vma,
>  {
>  	struct mm_struct *mm = vma->vm_mm;
>  	int ref_count, map_count;
> -	pmd_t orig_pmd = *pmdp;
> +	pmd_t orig_pmd = pmdp_get(pmdp);
>  
>  	if (folio_test_dirty(folio) || pmd_dirty(orig_pmd))
>  		return false;
> diff --git a/mm/hugetlb_vmemmap.c b/mm/hugetlb_vmemmap.c
> index 0c3f56b3578e..9deb82654d5b 100644
> --- a/mm/hugetlb_vmemmap.c
> +++ b/mm/hugetlb_vmemmap.c
> @@ -70,7 +70,7 @@ static int vmemmap_split_pmd(pmd_t *pmd, struct page *head, unsigned long start,
>  	}
>  
>  	spin_lock(&init_mm.page_table_lock);
> -	if (likely(pmd_leaf(*pmd))) {
> +	if (likely(pmd_leaf(pmdp_get(pmd)))) {
>  		/*
>  		 * Higher order allocations from buddy allocator must be able to
>  		 * be treated as indepdenent small pages (as they can be freed
> @@ -104,7 +104,7 @@ static int vmemmap_pmd_entry(pmd_t *pmd, unsigned long addr,
>  		walk->action = ACTION_CONTINUE;
>  
>  	spin_lock(&init_mm.page_table_lock);
> -	head = pmd_leaf(*pmd) ? pmd_page(*pmd) : NULL;
> +	head = pmd_leaf(pmdp_get(pmd)) ? pmd_page(pmdp_get(pmd)) : NULL;
>  	/*
>  	 * Due to HugeTLB alignment requirements and the vmemmap
>  	 * pages being at the start of the hotplugged memory
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index 89895f38f722..4418bcdcb2aa 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -121,7 +121,7 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
>  			continue;
>  		}
>  
> -		if (pmd_none(*pmd)) {
> +		if (pmd_none(pmdp_get(pmd))) {
>  			pte_t *p;
>  
>  			if (slab_is_available())
> @@ -300,7 +300,7 @@ static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
>  			return;
>  	}
>  
> -	pte_free_kernel(&init_mm, (pte_t *)page_to_virt(pmd_page(*pmd)));
> +	pte_free_kernel(&init_mm, (pte_t *)page_to_virt(pmd_page(pmdp_get(pmd))));
>  	pmd_clear(pmd);
>  }
>  
> @@ -311,7 +311,7 @@ static void kasan_free_pmd(pmd_t *pmd_start, pud_t *pud)
>  
>  	for (i = 0; i < PTRS_PER_PMD; i++) {
>  		pmd = pmd_start + i;
> -		if (!pmd_none(*pmd))
> +		if (!pmd_none(pmdp_get(pmd)))
>  			return;
>  	}
>  
> @@ -381,10 +381,10 @@ static void kasan_remove_pmd_table(pmd_t *pmd, unsigned long addr,
>  
>  		next = pmd_addr_end(addr, end);
>  
> -		if (!pmd_present(*pmd))
> +		if (!pmd_present(pmdp_get(pmd)))
>  			continue;
>  
> -		if (kasan_pte_table(*pmd)) {
> +		if (kasan_pte_table(pmdp_get(pmd))) {
>  			if (IS_ALIGNED(addr, PMD_SIZE) &&
>  			    IS_ALIGNED(next, PMD_SIZE)) {
>  				pmd_clear(pmd);
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index d6210ca48dda..aec16a7236f7 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -202,9 +202,9 @@ static bool shadow_mapped(unsigned long addr)
>  	if (pud_leaf(*pud))
>  		return true;
>  	pmd = pmd_offset(pud, addr);
> -	if (pmd_none(*pmd))
> +	if (pmd_none(pmdp_get(pmd)))
>  		return false;
> -	if (pmd_leaf(*pmd))
> +	if (pmd_leaf(pmdp_get(pmd)))
>  		return true;
>  	pte = pte_offset_kernel(pmd, addr);
>  	return !pte_none(ptep_get(pte));
> diff --git a/mm/khugepaged.c b/mm/khugepaged.c
> index cdd1d8655a76..793da996313f 100644
> --- a/mm/khugepaged.c
> +++ b/mm/khugepaged.c
> @@ -1192,7 +1192,7 @@ static int collapse_huge_page(struct mm_struct *mm, unsigned long address,
>  		if (pte)
>  			pte_unmap(pte);
>  		spin_lock(pmd_ptl);
> -		BUG_ON(!pmd_none(*pmd));
> +		BUG_ON(!pmd_none(pmdp_get(pmd)));
>  		/*
>  		 * We can only use set_pmd_at when establishing
>  		 * hugepmds and never for establishing regular pmds that
> @@ -1229,7 +1229,7 @@ static int collapse_huge_page(struct mm_struct *mm, unsigned long address,
>  	_pmd = maybe_pmd_mkwrite(pmd_mkdirty(_pmd), vma);
>  
>  	spin_lock(pmd_ptl);
> -	BUG_ON(!pmd_none(*pmd));
> +	BUG_ON(!pmd_none(pmdp_get(pmd)));
>  	folio_add_new_anon_rmap(folio, vma, address, RMAP_EXCLUSIVE);
>  	folio_add_lru_vma(folio, vma);
>  	pgtable_trans_huge_deposit(mm, pmd, pgtable);
> diff --git a/mm/madvise.c b/mm/madvise.c
> index 89089d84f8df..382c55d2ec94 100644
> --- a/mm/madvise.c
> +++ b/mm/madvise.c
> @@ -357,7 +357,7 @@ static int madvise_cold_or_pageout_pte_range(pmd_t *pmd,
>  					!can_do_file_pageout(vma);
>  
>  #ifdef CONFIG_TRANSPARENT_HUGEPAGE
> -	if (pmd_trans_huge(*pmd)) {
> +	if (pmd_trans_huge(pmdp_get(pmd))) {
>  		pmd_t orig_pmd;
>  		unsigned long next = pmd_addr_end(addr, end);
>  
> @@ -366,7 +366,7 @@ static int madvise_cold_or_pageout_pte_range(pmd_t *pmd,
>  		if (!ptl)
>  			return 0;
>  
> -		orig_pmd = *pmd;
> +		orig_pmd = pmdp_get(pmd);
>  		if (is_huge_zero_pmd(orig_pmd))
>  			goto huge_unlock;
>  
> @@ -655,7 +655,7 @@ static int madvise_free_pte_range(pmd_t *pmd, unsigned long addr,
>  	int nr, max_nr;
>  
>  	next = pmd_addr_end(addr, end);
> -	if (pmd_trans_huge(*pmd))
> +	if (pmd_trans_huge(pmdp_get(pmd)))
>  		if (madvise_free_huge_pmd(tlb, vma, pmd, addr, next))
>  			return 0;
>  
> diff --git a/mm/memory-failure.c b/mm/memory-failure.c
> index 7066fc84f351..305dbef3cc4d 100644
> --- a/mm/memory-failure.c
> +++ b/mm/memory-failure.c
> @@ -422,9 +422,9 @@ static unsigned long dev_pagemap_mapping_shift(struct vm_area_struct *vma,
>  	if (pud_devmap(*pud))
>  		return PUD_SHIFT;
>  	pmd = pmd_offset(pud, address);
> -	if (!pmd_present(*pmd))
> +	if (!pmd_present(pmdp_get(pmd)))
>  		return 0;
> -	if (pmd_devmap(*pmd))
> +	if (pmd_devmap(pmdp_get(pmd)))
>  		return PMD_SHIFT;
>  	pte = pte_offset_map(pmd, address);
>  	if (!pte)
> @@ -775,7 +775,7 @@ static int check_hwpoisoned_entry(pte_t pte, unsigned long addr, short shift,
>  static int check_hwpoisoned_pmd_entry(pmd_t *pmdp, unsigned long addr,
>  				      struct hwpoison_walk *hwp)
>  {
> -	pmd_t pmd = *pmdp;
> +	pmd_t pmd = pmdp_get(pmdp);
>  	unsigned long pfn;
>  	unsigned long hwpoison_vaddr;
>  
> diff --git a/mm/memory.c b/mm/memory.c
> index 3c01d68065be..43953a6d350f 100644
> --- a/mm/memory.c
> +++ b/mm/memory.c
> @@ -189,7 +189,7 @@ void mm_trace_rss_stat(struct mm_struct *mm, int member)
>  static void free_pte_range(struct mmu_gather *tlb, pmd_t *pmd,
>  			   unsigned long addr)
>  {
> -	pgtable_t token = pmd_pgtable(*pmd);
> +	pgtable_t token = pmd_pgtable(pmdp_get(pmd));
>  	pmd_clear(pmd);
>  	pte_free_tlb(tlb, token, addr);
>  	mm_dec_nr_ptes(tlb->mm);
> @@ -421,7 +421,7 @@ void pmd_install(struct mm_struct *mm, pmd_t *pmd, pgtable_t *pte)
>  {
>  	spinlock_t *ptl = pmd_lock(mm, pmd);
>  
> -	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
> +	if (likely(pmd_none(pmdp_get(pmd)))) {	/* Has another populated it ? */
>  		mm_inc_nr_ptes(mm);
>  		/*
>  		 * Ensure all pte setup (eg. pte page lock and page clearing) are
> @@ -462,7 +462,7 @@ int __pte_alloc_kernel(pmd_t *pmd)
>  		return -ENOMEM;
>  
>  	spin_lock(&init_mm.page_table_lock);
> -	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
> +	if (likely(pmd_none(pmdp_get(pmd)))) {	/* Has another populated it ? */
>  		smp_wmb(); /* See comment in pmd_install() */
>  		pmd_populate_kernel(&init_mm, pmd, new);
>  		new = NULL;
> @@ -1710,7 +1710,8 @@ static inline unsigned long zap_pmd_range(struct mmu_gather *tlb,
>  	pmd = pmd_offset(pud, addr);
>  	do {
>  		next = pmd_addr_end(addr, end);
> -		if (is_swap_pmd(*pmd) || pmd_trans_huge(*pmd) || pmd_devmap(*pmd)) {
> +		if (is_swap_pmd(pmdp_get(pmd)) || pmd_trans_huge(pmdp_get(pmd)) ||
> +		    pmd_devmap(pmdp_get(pmd))) {
>  			if (next - addr != HPAGE_PMD_SIZE)
>  				__split_huge_pmd(vma, pmd, addr, false, NULL);
>  			else if (zap_huge_pmd(tlb, vma, pmd, addr)) {
> @@ -1720,7 +1721,7 @@ static inline unsigned long zap_pmd_range(struct mmu_gather *tlb,
>  			/* fall through */
>  		} else if (details && details->single_folio &&
>  			   folio_test_pmd_mappable(details->single_folio) &&
> -			   next - addr == HPAGE_PMD_SIZE && pmd_none(*pmd)) {
> +			   next - addr == HPAGE_PMD_SIZE && pmd_none(pmdp_get(pmd))) {
>  			spinlock_t *ptl = pmd_lock(tlb->mm, pmd);
>  			/*
>  			 * Take and drop THP pmd lock so that we cannot return
> @@ -1729,7 +1730,7 @@ static inline unsigned long zap_pmd_range(struct mmu_gather *tlb,
>  			 */
>  			spin_unlock(ptl);
>  		}
> -		if (pmd_none(*pmd)) {
> +		if (pmd_none(pmdp_get(pmd))) {
>  			addr = next;
>  			continue;
>  		}
> @@ -1975,7 +1976,7 @@ static pmd_t *walk_to_pmd(struct mm_struct *mm, unsigned long addr)
>  	if (!pmd)
>  		return NULL;
>  
> -	VM_BUG_ON(pmd_trans_huge(*pmd));
> +	VM_BUG_ON(pmd_trans_huge(pmdp_get(pmd)));
>  	return pmd;
>  }
>  
> @@ -2577,7 +2578,7 @@ static inline int remap_pmd_range(struct mm_struct *mm, pud_t *pud,
>  	pmd = pmd_alloc(mm, pud, addr);
>  	if (!pmd)
>  		return -ENOMEM;
> -	VM_BUG_ON(pmd_trans_huge(*pmd));
> +	VM_BUG_ON(pmd_trans_huge(pmdp_get(pmd)));
>  	do {
>  		next = pmd_addr_end(addr, end);
>  		err = remap_pte_range(mm, pmd, addr, next,
> @@ -2829,11 +2830,11 @@ static int apply_to_pmd_range(struct mm_struct *mm, pud_t *pud,
>  	}
>  	do {
>  		next = pmd_addr_end(addr, end);
> -		if (pmd_none(*pmd) && !create)
> +		if (pmd_none(pmdp_get(pmd)) && !create)
>  			continue;
> -		if (WARN_ON_ONCE(pmd_leaf(*pmd)))
> +		if (WARN_ON_ONCE(pmd_leaf(pmdp_get(pmd))))
>  			return -EINVAL;
> -		if (!pmd_none(*pmd) && WARN_ON_ONCE(pmd_bad(*pmd))) {
> +		if (!pmd_none(pmdp_get(pmd)) && WARN_ON_ONCE(pmd_bad(pmdp_get(pmd)))) {
>  			if (!create)
>  				continue;
>  			pmd_clear_bad(pmd);
> @@ -6150,7 +6151,7 @@ int follow_pte(struct vm_area_struct *vma, unsigned long address,
>  		goto out;
>  
>  	pmd = pmd_offset(pud, address);
> -	VM_BUG_ON(pmd_trans_huge(*pmd));
> +	VM_BUG_ON(pmd_trans_huge(pmdp_get(pmd)));
>  
>  	ptep = pte_offset_map_lock(mm, pmd, address, ptlp);
>  	if (!ptep)
> diff --git a/mm/mempolicy.c b/mm/mempolicy.c
> index b858e22b259d..03f2df44b07f 100644
> --- a/mm/mempolicy.c
> +++ b/mm/mempolicy.c
> @@ -505,11 +505,11 @@ static void queue_folios_pmd(pmd_t *pmd, struct mm_walk *walk)
>  	struct folio *folio;
>  	struct queue_pages *qp = walk->private;
>  
> -	if (unlikely(is_pmd_migration_entry(*pmd))) {
> +	if (unlikely(is_pmd_migration_entry(pmdp_get(pmd)))) {
>  		qp->nr_failed++;
>  		return;
>  	}
> -	folio = pmd_folio(*pmd);
> +	folio = pmd_folio(pmdp_get(pmd));
>  	if (is_huge_zero_folio(folio)) {
>  		walk->action = ACTION_CONTINUE;
>  		return;
> diff --git a/mm/migrate.c b/mm/migrate.c
> index 923ea80ba744..a1dd5c8f88dd 100644
> --- a/mm/migrate.c
> +++ b/mm/migrate.c
> @@ -369,9 +369,9 @@ void pmd_migration_entry_wait(struct mm_struct *mm, pmd_t *pmd)
>  	spinlock_t *ptl;
>  
>  	ptl = pmd_lock(mm, pmd);
> -	if (!is_pmd_migration_entry(*pmd))
> +	if (!is_pmd_migration_entry(pmdp_get(pmd)))
>  		goto unlock;
> -	migration_entry_wait_on_locked(pmd_to_swp_entry(*pmd), ptl);
> +	migration_entry_wait_on_locked(pmd_to_swp_entry(pmdp_get(pmd)), ptl);
>  	return;
>  unlock:
>  	spin_unlock(ptl);
> diff --git a/mm/migrate_device.c b/mm/migrate_device.c
> index 6d66dc1c6ffa..3a08cef6cd39 100644
> --- a/mm/migrate_device.c
> +++ b/mm/migrate_device.c
> @@ -67,19 +67,19 @@ static int migrate_vma_collect_pmd(pmd_t *pmdp,
>  	pte_t *ptep;
>  
>  again:
> -	if (pmd_none(*pmdp))
> +	if (pmd_none(pmdp_get(pmdp)))
>  		return migrate_vma_collect_hole(start, end, -1, walk);
>  
> -	if (pmd_trans_huge(*pmdp)) {
> +	if (pmd_trans_huge(pmdp_get(pmdp))) {
>  		struct folio *folio;
>  
>  		ptl = pmd_lock(mm, pmdp);
> -		if (unlikely(!pmd_trans_huge(*pmdp))) {
> +		if (unlikely(!pmd_trans_huge(pmdp_get(pmdp)))) {
>  			spin_unlock(ptl);
>  			goto again;
>  		}
>  
> -		folio = pmd_folio(*pmdp);
> +		folio = pmd_folio(pmdp_get(pmdp));
>  		if (is_huge_zero_folio(folio)) {
>  			spin_unlock(ptl);
>  			split_huge_pmd(vma, pmdp, addr);
> @@ -596,7 +596,7 @@ static void migrate_vma_insert_page(struct migrate_vma *migrate,
>  	pmdp = pmd_alloc(mm, pudp, addr);
>  	if (!pmdp)
>  		goto abort;
> -	if (pmd_trans_huge(*pmdp) || pmd_devmap(*pmdp))
> +	if (pmd_trans_huge(pmdp_get(pmdp)) || pmd_devmap(pmdp_get(pmdp)))
>  		goto abort;
>  	if (pte_alloc(mm, pmdp))
>  		goto abort;
> diff --git a/mm/mlock.c b/mm/mlock.c
> index e3e3dc2b2956..c3c479e9d0f8 100644
> --- a/mm/mlock.c
> +++ b/mm/mlock.c
> @@ -363,11 +363,11 @@ static int mlock_pte_range(pmd_t *pmd, unsigned long addr,
>  
>  	ptl = pmd_trans_huge_lock(pmd, vma);
>  	if (ptl) {
> -		if (!pmd_present(*pmd))
> +		if (!pmd_present(pmdp_get(pmd)))
>  			goto out;
> -		if (is_huge_zero_pmd(*pmd))
> +		if (is_huge_zero_pmd(pmdp_get(pmd)))
>  			goto out;
> -		folio = pmd_folio(*pmd);
> +		folio = pmd_folio(pmdp_get(pmd));
>  		if (vma->vm_flags & VM_LOCKED)
>  			mlock_folio(folio);
>  		else
> diff --git a/mm/mprotect.c b/mm/mprotect.c
> index 222ab434da54..121fb448b0db 100644
> --- a/mm/mprotect.c
> +++ b/mm/mprotect.c
> @@ -381,7 +381,7 @@ static inline long change_pmd_range(struct mmu_gather *tlb,
>  			break;
>  		}
>  
> -		if (pmd_none(*pmd))
> +		if (pmd_none(pmdp_get(pmd)))
>  			goto next;
>  
>  		/* invoke the mmu notifier if the pmd is populated */
> diff --git a/mm/mremap.c b/mm/mremap.c
> index e7ae140fc640..d42ac62bd34e 100644
> --- a/mm/mremap.c
> +++ b/mm/mremap.c
> @@ -63,7 +63,7 @@ static pmd_t *get_old_pmd(struct mm_struct *mm, unsigned long addr)
>  		return NULL;
>  
>  	pmd = pmd_offset(pud, addr);
> -	if (pmd_none(*pmd))
> +	if (pmd_none(pmdp_get(pmd)))
>  		return NULL;
>  
>  	return pmd;
> @@ -97,7 +97,7 @@ static pmd_t *alloc_new_pmd(struct mm_struct *mm, struct vm_area_struct *vma,
>  	if (!pmd)
>  		return NULL;
>  
> -	VM_BUG_ON(pmd_trans_huge(*pmd));
> +	VM_BUG_ON(pmd_trans_huge(pmdp_get(pmd)));
>  
>  	return pmd;
>  }
> diff --git a/mm/page_table_check.c b/mm/page_table_check.c
> index 509c6ef8de40..48a2cf56c80e 100644
> --- a/mm/page_table_check.c
> +++ b/mm/page_table_check.c
> @@ -241,7 +241,7 @@ void __page_table_check_pmd_set(struct mm_struct *mm, pmd_t *pmdp, pmd_t pmd)
>  
>  	page_table_check_pmd_flags(pmd);
>  
> -	__page_table_check_pmd_clear(mm, *pmdp);
> +	__page_table_check_pmd_clear(mm, pmdp_get(pmdp));
>  	if (pmd_user_accessible_page(pmd)) {
>  		page_table_check_set(pmd_pfn(pmd), PMD_SIZE >> PAGE_SHIFT,
>  				     pmd_write(pmd));
> diff --git a/mm/pagewalk.c b/mm/pagewalk.c
> index ae2f08ce991b..c3019a160e77 100644
> --- a/mm/pagewalk.c
> +++ b/mm/pagewalk.c
> @@ -86,7 +86,7 @@ static int walk_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
>  	do {
>  again:
>  		next = pmd_addr_end(addr, end);
> -		if (pmd_none(*pmd)) {
> +		if (pmd_none(pmdp_get(pmd))) {
>  			if (ops->pte_hole)
>  				err = ops->pte_hole(addr, next, depth, walk);
>  			if (err)
> @@ -112,7 +112,7 @@ static int walk_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
>  		 * Check this here so we only break down trans_huge
>  		 * pages when we _need_ to
>  		 */
> -		if ((!walk->vma && (pmd_leaf(*pmd) || !pmd_present(*pmd))) ||
> +		if ((!walk->vma && (pmd_leaf(pmdp_get(pmd)) || !pmd_present(pmdp_get(pmd)))) ||
>  		    walk->action == ACTION_CONTINUE ||
>  		    !(ops->pte_entry))
>  			continue;
> diff --git a/mm/percpu.c b/mm/percpu.c
> index 20d91af8c033..7ee77c0fd5e3 100644
> --- a/mm/percpu.c
> +++ b/mm/percpu.c
> @@ -3208,7 +3208,7 @@ void __init __weak pcpu_populate_pte(unsigned long addr)
>  	}
>  
>  	pmd = pmd_offset(pud, addr);
> -	if (!pmd_present(*pmd)) {
> +	if (!pmd_present(pmdp_get(pmd))) {
>  		pte_t *new;
>  
>  		new = memblock_alloc(PTE_TABLE_SIZE, PTE_TABLE_SIZE);
> diff --git a/mm/pgtable-generic.c b/mm/pgtable-generic.c
> index a78a4adf711a..a5045d0fc73e 100644
> --- a/mm/pgtable-generic.c
> +++ b/mm/pgtable-generic.c
> @@ -51,7 +51,7 @@ void pud_clear_bad(pud_t *pud)
>   */
>  void pmd_clear_bad(pmd_t *pmd)
>  {
> -	pmd_ERROR(*pmd);
> +	pmd_ERROR(pmdp_get(pmd));
>  	pmd_clear(pmd);
>  }
>  
> @@ -110,7 +110,7 @@ int pmdp_set_access_flags(struct vm_area_struct *vma,
>  			  unsigned long address, pmd_t *pmdp,
>  			  pmd_t entry, int dirty)
>  {
> -	int changed = !pmd_same(*pmdp, entry);
> +	int changed = !pmd_same(pmdp_get(pmdp), entry);
>  	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
>  	if (changed) {
>  		set_pmd_at(vma->vm_mm, address, pmdp, entry);
> @@ -139,8 +139,8 @@ pmd_t pmdp_huge_clear_flush(struct vm_area_struct *vma, unsigned long address,
>  {
>  	pmd_t pmd;
>  	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
> -	VM_BUG_ON(pmd_present(*pmdp) && !pmd_trans_huge(*pmdp) &&
> -			   !pmd_devmap(*pmdp));
> +	VM_BUG_ON(pmd_present(pmdp_get(pmdp)) && !pmd_trans_huge(pmdp_get(pmdp)) &&
> +			   !pmd_devmap(pmdp_get(pmdp)));
>  	pmd = pmdp_huge_get_and_clear(vma->vm_mm, address, pmdp);
>  	flush_pmd_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
>  	return pmd;
> @@ -198,8 +198,8 @@ pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *mm, pmd_t *pmdp)
>  pmd_t pmdp_invalidate(struct vm_area_struct *vma, unsigned long address,
>  		     pmd_t *pmdp)
>  {
> -	VM_WARN_ON_ONCE(!pmd_present(*pmdp));
> -	pmd_t old = pmdp_establish(vma, address, pmdp, pmd_mkinvalid(*pmdp));
> +	VM_WARN_ON_ONCE(!pmd_present(pmdp_get(pmdp)));
> +	pmd_t old = pmdp_establish(vma, address, pmdp, pmd_mkinvalid(pmdp_get(pmdp)));
>  	flush_pmd_tlb_range(vma, address, address + HPAGE_PMD_SIZE);
>  	return old;
>  }
> @@ -209,7 +209,7 @@ pmd_t pmdp_invalidate(struct vm_area_struct *vma, unsigned long address,
>  pmd_t pmdp_invalidate_ad(struct vm_area_struct *vma, unsigned long address,
>  			 pmd_t *pmdp)
>  {
> -	VM_WARN_ON_ONCE(!pmd_present(*pmdp));
> +	VM_WARN_ON_ONCE(!pmd_present(pmdp_get(pmdp)));
>  	return pmdp_invalidate(vma, address, pmdp);
>  }
>  #endif
> @@ -225,7 +225,7 @@ pmd_t pmdp_collapse_flush(struct vm_area_struct *vma, unsigned long address,
>  	pmd_t pmd;
>  
>  	VM_BUG_ON(address & ~HPAGE_PMD_MASK);
> -	VM_BUG_ON(pmd_trans_huge(*pmdp));
> +	VM_BUG_ON(pmd_trans_huge(pmdp_get(pmdp)));
>  	pmd = pmdp_huge_get_and_clear(vma->vm_mm, address, pmdp);
>  
>  	/* collapse entails shooting down ptes not pmd */
> diff --git a/mm/ptdump.c b/mm/ptdump.c
> index 106e1d66e9f9..e17588a32012 100644
> --- a/mm/ptdump.c
> +++ b/mm/ptdump.c
> @@ -99,7 +99,7 @@ static int ptdump_pmd_entry(pmd_t *pmd, unsigned long addr,
>  			    unsigned long next, struct mm_walk *walk)
>  {
>  	struct ptdump_state *st = walk->private;
> -	pmd_t val = READ_ONCE(*pmd);
> +	pmd_t val = pmdp_get(pmd);
>  
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  	if (pmd_page(val) == virt_to_page(lm_alias(kasan_early_shadow_pte)))
> diff --git a/mm/rmap.c b/mm/rmap.c
> index 2490e727e2dc..ec668c48bccc 100644
> --- a/mm/rmap.c
> +++ b/mm/rmap.c
> @@ -1036,7 +1036,7 @@ static int page_vma_mkclean_one(struct page_vma_mapped_walk *pvmw)
>  			pmd_t *pmd = pvmw->pmd;
>  			pmd_t entry;
>  
> -			if (!pmd_dirty(*pmd) && !pmd_write(*pmd))
> +			if (!pmd_dirty(pmdp_get(pmd)) && !pmd_write(pmdp_get(pmd)))
>  				continue;
>  
>  			flush_cache_range(vma, address,
> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
> index edcc7a6b0f6f..c89706e107ce 100644
> --- a/mm/sparse-vmemmap.c
> +++ b/mm/sparse-vmemmap.c
> @@ -187,7 +187,7 @@ static void * __meminit vmemmap_alloc_block_zero(unsigned long size, int node)
>  pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
>  {
>  	pmd_t *pmd = pmd_offset(pud, addr);
> -	if (pmd_none(*pmd)) {
> +	if (pmd_none(pmdp_get(pmd))) {
>  		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
>  		if (!p)
>  			return NULL;
> @@ -332,7 +332,7 @@ int __meminit vmemmap_populate_hugepages(unsigned long start, unsigned long end,
>  			return -ENOMEM;
>  
>  		pmd = pmd_offset(pud, addr);
> -		if (pmd_none(READ_ONCE(*pmd))) {
> +		if (pmd_none(pmdp_get(pmd))) {
>  			void *p;
>  
>  			p = vmemmap_alloc_block_buf(PMD_SIZE, node, altmap);
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index a0df1e2e155a..d27aa1ebaad6 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -150,7 +150,7 @@ static int vmap_try_huge_pmd(pmd_t *pmd, unsigned long addr, unsigned long end,
>  	if (!IS_ALIGNED(phys_addr, PMD_SIZE))
>  		return 0;
>  
> -	if (pmd_present(*pmd) && !pmd_free_pte_page(pmd, addr))
> +	if (pmd_present(pmdp_get(pmd)) && !pmd_free_pte_page(pmd, addr))
>  		return 0;
>  
>  	return pmd_set_huge(pmd, phys_addr, prot);
> @@ -371,7 +371,7 @@ static void vunmap_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
>  		next = pmd_addr_end(addr, end);
>  
>  		cleared = pmd_clear_huge(pmd);
> -		if (cleared || pmd_bad(*pmd))
> +		if (cleared || pmd_bad(pmdp_get(pmd)))
>  			*mask |= PGTBL_PMD_MODIFIED;
>  
>  		if (cleared)
> @@ -776,11 +776,11 @@ struct page *vmalloc_to_page(const void *vmalloc_addr)
>  		return NULL;
>  
>  	pmd = pmd_offset(pud, addr);
> -	if (pmd_none(*pmd))
> +	if (pmd_none(pmdp_get(pmd)))
>  		return NULL;
> -	if (pmd_leaf(*pmd))
> -		return pmd_page(*pmd) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
> -	if (WARN_ON_ONCE(pmd_bad(*pmd)))
> +	if (pmd_leaf(pmdp_get(pmd)))
> +		return pmd_page(pmdp_get(pmd)) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
> +	if (WARN_ON_ONCE(pmd_bad(pmdp_get(pmd))))
>  		return NULL;
>  
>  	ptep = pte_offset_kernel(pmd, addr);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f918bd00-c6a4-498a-bd17-9f5b32f7d6a7%40arm.com.
