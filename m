Return-Path: <kasan-dev+bncBDZMFEH3WYFBB6GMYDCQMGQEZDCQI3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3ABD4B398C0
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 11:50:50 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b109affec8sf19274841cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 02:50:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756374649; cv=pass;
        d=google.com; s=arc-20240605;
        b=XHkbJUQc44Bat2VvvsEqmZMwh+vWd6eIDF0RVESo3a6Pkc9o1HsvPSU1qOwrCw7rAD
         y3ayu0T4VyWnWeEsSFnXqkKkav5zLu1fCP8ys+yylxQNWzNpwUvG6hgeJlwCSVL/M1yp
         mb8ZALkwhhQszEnioGlYq9lL2h3T0spYctDit6iOcUhhPJI4pob7lUhoCHqDaa/FyY77
         7pOGjcisxNsnLEr3tNP6TNlxyF/vQqBRSPrb4vbF6U7i+oK8/1VPBJRqldtNxXVtnyfy
         mv06JcKq8O3wqFyRPrfKrqaxcBrp2TrB0+Z+SvNch2Abqp1gkHzmJH4InQVg5ywIc6+t
         3Mvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=wXCKmd+58VOWwA79QLL9zg4babbeQLjF7WY2kTKL6uk=;
        fh=DFY6177O+Vf6S/KAMJ9N3xs6vLMBA4SQCT+qA8qXTFQ=;
        b=hAgwJEUtospXf1LXUpMxsJyrZaOuXF9EZImz6BWVBd0YLT3un+E3bQ2fsJff01C+qq
         9QX6mrbPV2ip5V2BxPdaWmOyR5xoxJdC6IWfVqzTT80aYBwE3Qx1Ce2+orZ/JT5aFIYb
         1/lXbVj4Z6IIvd4voioKl9C0LeETBHha8Jb7hOUrrAjUn3by5yHWEuV2D+CyvXy+JZla
         z0EwYJvakM2VNC4aropysKnX4Ngi6ipYZQzbuw943e4QfJC/CUq64EBBf+rD4+8PBG8o
         3KkCPjhXb9t0LYCoE1ZlanROMGp+ohyTUKqzUGNs4/5TcMCkQMKfcmdEcMfsXOJAFxlD
         9sUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VtsLfDMM;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756374649; x=1756979449; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=wXCKmd+58VOWwA79QLL9zg4babbeQLjF7WY2kTKL6uk=;
        b=Pv3pht2tAYcGOr+xkLx4XMK14enKVe6HDbdelN6gDEelEpCD/kolJcVx6fmFrLcSgi
         2dOcNYwkMJqhfc+YcvqXF1Ka5wF6E+nxNFJnkoxvRv4IhAVfb7g/HyHbUBp9NhgvsAbv
         mdgoKpcCHLGnuywMzz7T4xw1z5LC9jttofUYjR6nL9duCUbjphB+JAZvMQtT9hq3jNXr
         mEdcYUpo48RyV2CqgdOH2ROnsEYPyOQhpFupRhO7jDNTAETJcgdlBbGcM2+t66tCuan5
         hEzlbsewrHrVU9RfWdqJCz2hfRvTMv4iWqAfKpgxSo+afqcDyxSQUoe9UCJdkfoRcWp3
         ehLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756374649; x=1756979449;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wXCKmd+58VOWwA79QLL9zg4babbeQLjF7WY2kTKL6uk=;
        b=vbxABRKm3nM/dJfDteF7oLwb6n5WKeqQTD+Btt6qq6bJkPX6EjxWXzezMWvGgMywF6
         gpqBqfmU/iz62VpsKmlsb70XRRNx9j5G87Gd+OEqriI/3ImY7Nh3zGgIesfBCnFs2SBr
         oQ9Mr07T7GvSHcjJxNfrfAhzxFv8fSFgUFwsdgFW9+bZG774hZHrpJXaPP6vNRUv3Ibs
         ZPGEJ8HMGhfF3oNej1yMSt4b9pRpQ2QBmaH6UrERMEamUevRmuMRqntstuoHCHTvgetz
         JbvmzTCnjzPK5rMh7rQL5sODvoxe4x2rMRwBFehYEE3H3E2IV+hUzrpFSyqJh3elLeqg
         kOyQ==
X-Forwarded-Encrypted: i=2; AJvYcCV95gsapLfxZyh4kXyQRJSQzTxhnST6l35yVVQW+Jv9swHklK70hKXVriHNI8vh7p9uhVhoTQ==@lfdr.de
X-Gm-Message-State: AOJu0YyVa4LYTCFnq4Lynob0M4wfPii/jyV0gdtPycAvtbraJzxsA+RC
	6mK9/6KV1frWDkGQWez1GYV4s208oAIR2azmy3euTsWPp72StnVhafHb
X-Google-Smtp-Source: AGHT+IGhim+MYSsyRfTU6Wgm4nbvp37JttYYVES48iLt1jB8wwDUxc/zbrYaTv2XWrCUT8ScZ0zbJg==
X-Received: by 2002:a05:622a:1b0f:b0:4b0:82d9:7cb5 with SMTP id d75a77b69052e-4b2aaa2d0f1mr263565871cf.26.1756374648921;
        Thu, 28 Aug 2025 02:50:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfVMAJawj3795AlAhdAa8bKlcxL/Zosi1swwnbUJ4bcXg==
Received: by 2002:ac8:590e:0:b0:4b2:deda:ce94 with SMTP id d75a77b69052e-4b2fe8da446ls8432541cf.2.-pod-prod-02-us;
 Thu, 28 Aug 2025 02:50:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcL5CeQRf2ZybqqAtYirK9pZnw5Sin+zN1baITRprpIHJ1dHbXpjyr1XsNC23ZhpQG/5UiscKxyFQ=@googlegroups.com
X-Received: by 2002:a05:622a:540b:b0:4b3:27e:72d8 with SMTP id d75a77b69052e-4b3027e7eebmr12333871cf.40.1756374647688;
        Thu, 28 Aug 2025 02:50:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756374647; cv=none;
        d=google.com; s=arc-20240605;
        b=QpdMiU2dpHCQO4pIJQJhdpfBwHXpBJK9Pqjhe8jdLQPgJiSrbaCTRiUBCzG0bPgBsC
         VKq0x8ci7cgSZkfO3158sR47nEZrXxfERkk/lYLOw0F71kg6LUMxRWywyU2yi9ovkK18
         9sl64PUEtsYyj2U+mUIei71QwnJYMmyR08DsE6+NxZWXxT+i/GPadUFQYgPtIRDCOxhP
         QeF8Q0nHai3Vr9kfmm2M4FuEj7fST7RbRyNoJxFH9tjL7xq8Des1Xwq4ygF0H2y3GPQG
         NCgkyQeCDwUldRoBWK16zlcXhja3LTz5nwCKIC9r5wZNtORw4+WZP9qT6Ir3+QR7xYWS
         uLQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=OWMmShU4ImOjLSMeztpkWV2T1IIAbIIXzuHR+ONfz1E=;
        fh=at7K52t9JiAlP81txEpmPy6YN/OwkiVzI8mnb2CenhY=;
        b=EQlT9+jtAfQGcmEcXCsVLaCrXK2v89MKmMYRewK71rLa9MIyfHhHaejWnX57Ws1TsD
         zlZE+IYwuwV8fAEZnj2Fj/VdidhetYBT7HYikFL3YhZn0zmRJzZLWrtzuQdrkdDlhriz
         Q6kLQX8b1uHGDMrLXmSf6NSUYt8rwvgIRLAY9Yu5wNtWRqxg0+z6VflJOIRDEtMIimiX
         SVAQWqFA+noJ7fNni3TkjeCd8kdvZk+5FgbJBM0F9ky6NPmqdJnsK5W1P+VT3h+ByEFh
         Zs25+WtvNZf015SVoysd3Rj7LxZ+4dPlAmblJMcdidKDeBOB/9KjxzQK4jYYExSE71oj
         cabg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VtsLfDMM;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7fad4ebd372si2125985a.2.2025.08.28.02.50.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 02:50:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id C9D12602CD;
	Thu, 28 Aug 2025 09:50:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F2032C4CEEB;
	Thu, 28 Aug 2025 09:50:22 +0000 (UTC)
Date: Thu, 28 Aug 2025 12:50:19 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com,
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com,
	trintaeoitogc@gmail.com, axelrasmussen@google.com,
	yuanchu@google.com, joey.gouly@arm.com, samitolvanen@google.com,
	joel.granados@kernel.org, graf@amazon.com,
	vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org,
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com,
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz,
	kaleshsingh@google.com, justinstitt@google.com,
	catalin.marinas@arm.com, alexander.shishkin@linux.intel.com,
	samuel.holland@sifive.com, dave.hansen@linux.intel.com,
	corbet@lwn.net, xin@zytor.com, dvyukov@google.com,
	tglx@linutronix.de, scott@os.amperecomputing.com,
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org,
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com,
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org,
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com,
	mhocko@suse.com, ada.coupriediaz@arm.com, hpa@zytor.com,
	leitao@debian.org, peterz@infradead.org, wangkefeng.wang@huawei.com,
	surenb@google.com, ziy@nvidia.com, smostafa@google.com,
	ryabinin.a.a@gmail.com, ubizjak@gmail.com, jbohac@suse.cz,
	broonie@kernel.org, akpm@linux-foundation.org,
	guoweikang.kernel@gmail.com, pcc@google.com, jan.kiszka@siemens.com,
	nicolas.schier@linux.dev, will@kernel.org, andreyknvl@gmail.com,
	jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org,
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v5 07/19] mm: x86: Untag addresses in EXECMEM_ROX related
 pointer arithmetic
Message-ID: <aLAmW-UV6hv9k1LT@kernel.org>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <c773559ea60801f3a5ca01171ea2ac0f9b0da56a.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c773559ea60801f3a5ca01171ea2ac0f9b0da56a.1756151769.git.maciej.wieczor-retman@intel.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VtsLfDMM;       spf=pass
 (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Mon, Aug 25, 2025 at 10:24:32PM +0200, Maciej Wieczor-Retman wrote:
> ARCH_HAS_EXECMEM_ROX was re-enabled in x86 at Linux 6.14 release.
> Related code has multiple spots where page virtual addresses end up used
> as arguments in arithmetic operations. Combined with enabled tag-based
> KASAN it can result in pointers that don't point where they should or
> logical operations not giving expected results.
> 
> vm_reset_perms() calculates range's start and end addresses using min()
> and max() functions. To do that it compares pointers but some are not
> tagged - addr variable is, start and end variables aren't.
> 
> within() and within_range() can receive tagged addresses which get
> compared to untagged start and end variables.
> 
> Reset tags in addresses used as function arguments in min(), max(),
> within().
> 
> execmem_cache_add() adds tagged pointers to a maple tree structure,
> which then are incorrectly compared when walking the tree. That results
> in different pointers being returned later and page permission violation
> errors panicking the kernel.
> 
> Reset tag of the address range inserted into the maple tree inside
> execmem_cache_add().
> 
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v5:
> - Remove the within_range() change.
> - arch_kasan_reset_tag -> kasan_reset_tag.
> 
> Changelog v4:
> - Add patch to the series.
> 
>  mm/execmem.c | 2 +-
>  mm/vmalloc.c | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/mm/execmem.c b/mm/execmem.c
> index 0822305413ec..f7b7bdacaec5 100644
> --- a/mm/execmem.c
> +++ b/mm/execmem.c
> @@ -186,7 +186,7 @@ static DECLARE_WORK(execmem_cache_clean_work, execmem_cache_clean);
>  static int execmem_cache_add_locked(void *ptr, size_t size, gfp_t gfp_mask)
>  {
>  	struct maple_tree *free_areas = &execmem_cache.free_areas;
> -	unsigned long addr = (unsigned long)ptr;
> +	unsigned long addr = (unsigned long)kasan_reset_tag(ptr);

Thinking more about it, we anyway reset tag in execmem_alloc() and return
untagged pointer to the caller. Let's just move kasan_reset_tag() to
execmem_vmalloc() so that we always use untagged pointers. Seems more
robust to me.

>  	MA_STATE(mas, free_areas, addr - 1, addr + 1);
>  	unsigned long lower, upper;
>  	void *area = NULL;
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 6dbcdceecae1..c93893fb8dd4 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3322,7 +3322,7 @@ static void vm_reset_perms(struct vm_struct *area)
>  	 * the vm_unmap_aliases() flush includes the direct map.
>  	 */
>  	for (i = 0; i < area->nr_pages; i += 1U << page_order) {
> -		unsigned long addr = (unsigned long)page_address(area->pages[i]);
> +		unsigned long addr = (unsigned long)kasan_reset_tag(page_address(area->pages[i]));

This is not strictly related to execemem, there may other users of
VM_FLUSH_RESET_PERMS.

Regardless, I wonder how this works on arm64 with tags enabled?

Also, it's not the only place in the kernel that does (unsigned
long)page_address(page). Do other sites need to reset the tag as well?

>  
>  		if (addr) {
>  			unsigned long page_size;
> -- 
> 2.50.1
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLAmW-UV6hv9k1LT%40kernel.org.
