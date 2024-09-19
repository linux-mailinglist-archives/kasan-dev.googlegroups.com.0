Return-Path: <kasan-dev+bncBCSPV64IYUKBBMFUWG3QMGQE4VARRAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f61.google.com (mail-lf1-f61.google.com [209.85.167.61])
	by mail.lfdr.de (Postfix) with ESMTPS id 60ECB97CCDD
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 19:06:58 +0200 (CEST)
Received: by mail-lf1-f61.google.com with SMTP id 2adb3069b0e04-535699f7a6bsf1001404e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 10:06:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726765618; cv=pass;
        d=google.com; s=arc-20240605;
        b=lpyRKc5tqbIz4q4GY092WiNje3/5+pMIqOWlYV9ll8f6+rjsIBJy7bqI7XvMHpXgl9
         gq+2EJOj6PJpihHyZ09iO3EGe6ivTWO6sM2NNBiNqL61pO8oTmd6ZOqlV6zrtVKSj8Tn
         2bKraUl5YC/rybOmV7kt0gRR+0BKyZXhPC5tVaVloycAfvkWmLDetRl8pN+pFvSK7+0A
         V7WA4nV+oYv/SQ+LpHsAJv1yUDiEpV6Gt50Df3OgVkQlB4WHWO5mWFToJv7jBVtHpGZt
         RNl3c07dg01srf4NJy6cX8ElutaVAbKK50X7NIQowhliYEIc3ojeIqv2uRVtQgxGENOU
         mkxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=USL2v/tdnIoeGZh7X58pLNROVgau4A1ERv07ttsg2ak=;
        fh=c3QKqtdH3X8LXPQ0WpayVmcKboe4ed4P0q55IO9EX7Y=;
        b=GibsH3q0nPbjLPRNk5fGqDqCAmWAaDmqEddmzJQ1/Bs64kjGlL1yVA0q4MiGwWahio
         OIldb9XmefAFHUiqucDBhl7PgD9rNfpmImkkD1sErRwGOAiJILXYt/Y7KYGACJ1wua9S
         w2RxVLqB5W3rzFFotuCCaP6RlH5gb0K2A34bb8YOsnhHoBt62Q0FRrBZHQhM5JLUU7+N
         t8TWWBm5htEPrbuLmjDwe/PUmalwPg8AZOL2KZ34hJtqrCBbpmwMZEURcmhISMQioMAH
         RX0wjfOZuYYd0SyYh+zK3PiKlLs2oUbHePnzaE4LH/02O5Ygz6PCm6hQjht09Wt/tM0R
         NSfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=an6X8ydO;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726765618; x=1727370418;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=USL2v/tdnIoeGZh7X58pLNROVgau4A1ERv07ttsg2ak=;
        b=hxx9lUGLJIXksywQKIMP41FJm6LzvMfqYoIuZadD3kMARzCm1/ZhJFVabo0nYb+lLJ
         A9CDX6/fGJEuP70N8spqS8A6dctPQUuabKBA8oo7pgyjVhBSfy4eKeXq8NDw1HxctFiJ
         XI63GxyxVBHSi/OCxp1KdvIy7zyCDeLUn3OP9UPzMVEtArxJnr/RlDqas9aAh7ZI/9XT
         4iQKpjZs/E24uIUCSqNthbi6jfyfsVMK8KtyuEqkfDODlIwCCiwzaJZX/qJaT3tdUiB0
         hu290MlWHJyhEvrVhaDJ61mjOgI6zZA5JhYUYRQlTG2OlnLoCy84cCDJ2a6GGUgI+ZYy
         qwCw==
X-Forwarded-Encrypted: i=2; AJvYcCW2JeRiQY9xCYekjlObktsge+7vQzPBxDWtuzph6XWY9diuDk53k5z4LI5fiul88JIgETpEjQ==@lfdr.de
X-Gm-Message-State: AOJu0YyhLW4nlWFQuBOtyCqLRuH7KEcZA3wMTnC8NQZyK5vTKN0s5YKF
	LQxUXaFunimWVPPAQXofI/8lqPWhkxAdkF7qdCU7drbjgwivKH2j
X-Google-Smtp-Source: AGHT+IEJQ7Cw3b4bPf/BENsXMpPMHyC+sbRqnxAhgxZq2iDr3ZzI270y7XSrXgJfrNssyPU4SHvUmA==
X-Received: by 2002:a05:6512:15a7:b0:52e:9ac6:a20f with SMTP id 2adb3069b0e04-5367ff2502fmr14636068e87.37.1726765617107;
        Thu, 19 Sep 2024 10:06:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5114:b0:42c:af5b:fad2 with SMTP id
 5b1f17b1804b1-42e7473e231ls24055e9.1.-pod-prod-04-eu; Thu, 19 Sep 2024
 10:06:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX7mVUnrg5ONV+NOQ1GkiFJ4ZojWAQKWZik6JufZ+pgcR6rGsFiGn8XM39m6QF6qywxU9KMYTRd1BM=@googlegroups.com
X-Received: by 2002:a05:600c:3115:b0:42c:b949:328e with SMTP id 5b1f17b1804b1-42e7add1478mr477315e9.31.1726765615130;
        Thu, 19 Sep 2024 10:06:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726765615; cv=none;
        d=google.com; s=arc-20240605;
        b=GH6m9tztQFuXD/Lu6X71JytT6FEuqCtOJR5UhyzCoyUE2pFZNnXMietrbw/xXlxuDb
         MeZibYA+Qeyt409eDx+AdTkCYHzN4YDSTVGfVFoOiwKRMWGgyIVxtsArZcuLTvsNz4lg
         BDlY/TUKIqFpUzV9KbnqBOFiEFqsBQNcFqP2Askg5t6VRfBLSYpsFQsmyL0BNxgZ3qck
         F2TR+cPizHxojvaQXSJS5NF/hd/b3ox8EeLAjAlOhjPG8J+mjXktUNLnxGKPcqB391fy
         nrG13VP6YYEFcII24exIHtplbIj1AbiUS1dAl+FqUaMrzzC30WrXZ4DIrxt++4Sq6fXG
         WSJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=6mai/1zkLhhmEUxeaWpVi/QzAXrwkM3agGKBk9/iEkI=;
        fh=vvFsAELp3/ijmy+VyjXHqEgJwr2AV/p0Vw32McP4bZ8=;
        b=aX6tisYnskF+tY3/F49/I7HKaaH+Y5na//g1SAYJ6bI6gk0ziAIRv7TauPJpOzhhxw
         lKkywIC5lOBPP4Zu08Yvx3DLWwBgG3AdI9KsXq5AiI4RbRKzEAi5dhwEVI7IZd0pk3yo
         5XgENWgIYGeh7v8sEPOlDv9qNXa3q1EiA+m3AIIvhIcrQdYCdYDu5mtlg+9mXCtcFrhK
         6NGt+IsaWgXUF37o0UTbzmyzJFuzqh0rRjHDATKljzcuTVjawQhBW8yASFMGtl589TFJ
         2QnJeOO9S973PN2vYNhDheu3HV6ZRccK6c5XhNuAJWpXTXo+DdnQIa/NQhETKGk/t3+W
         UFgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=an6X8ydO;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e75465a87si530695e9.1.2024.09.19.10.06.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Sep 2024 10:06:55 -0700 (PDT)
Received-SPF: none (google.com: armlinux.org.uk does not designate permitted sender hosts) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:53624)
	by pandora.armlinux.org.uk with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.96)
	(envelope-from <linux@armlinux.org.uk>)
	id 1srKbe-0000gQ-2J;
	Thu, 19 Sep 2024 18:06:14 +0100
Received: from linux by shell.armlinux.org.uk with local (Exim 4.96)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1srKbV-0001gs-1e;
	Thu, 19 Sep 2024 18:06:05 +0100
Date: Thu, 19 Sep 2024 18:06:05 +0100
From: "Russell King (Oracle)" <linux@armlinux.org.uk>
To: Ryan Roberts <ryan.roberts@arm.com>
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
	kernel test robot <lkp@intel.com>, linux-mm@kvack.org,
	llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
	linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	Dimitri Sivanich <dimitri.sivanich@hpe.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Muchun Song <muchun.song@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Miaohe Lin <linmiaohe@huawei.com>, Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>
Subject: Re: [PATCH V2 7/7] mm: Use pgdp_get() for accessing PGD entries
Message-ID: <ZuxZ/QeSdqTHtfmw@shell.armlinux.org.uk>
References: <20240917073117.1531207-8-anshuman.khandual@arm.com>
 <202409190310.ViHBRe12-lkp@intel.com>
 <8f43251a-5418-4c54-a9b0-29a6e9edd879@arm.com>
 <ZuvqpvJ6ht4LCuB+@shell.armlinux.org.uk>
 <82fa108e-5b15-435a-8b61-6253766c7d88@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <82fa108e-5b15-435a-8b61-6253766c7d88@arm.com>
Sender: Russell King (Oracle) <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=an6X8ydO;
       spf=none (google.com: armlinux.org.uk does not designate permitted
 sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
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

On Thu, Sep 19, 2024 at 05:48:58PM +0200, Ryan Roberts wrote:
> > 32-bit arm uses, in some circumstances, an array because each level 1
> > page table entry is actually two descriptors. It needs to be this way
> > because each level 2 table pointed to by each level 1 entry has 256
> > entries, meaning it only occupies 1024 bytes in a 4096 byte page.
> > 
> > In order to cut down on the wastage, treat the level 1 page table as
> > groups of two entries, which point to two consecutive 1024 byte tables
> > in the level 2 page.
> > 
> > The level 2 entry isn't suitable for the kernel's use cases (there are
> > no bits to represent accessed/dirty and other important stuff that the
> > Linux MM wants) so we maintain the hardware page tables and a separate
> > set that Linux uses in the same page. Again, the software tables are
> > consecutive, so from Linux's perspective, the level 2 page tables
> > have 512 entries in them and occupy one full page.
> > 
> > This is documented in arch/arm/include/asm/pgtable-2level.h
> > 
> > However, what this means is that from the software perspective, the
> > level 1 page table descriptors are an array of two entries, both of
> > which need to be setup when creating a level 2 page table, but only
> > the first one should ever be dereferenced when walking the tables,
> > otherwise the code that walks the second level of page table entries
> > will walk off the end of the software table into the actual hardware
> > descriptors.
> > 
> > I've no idea what the idea is behind introducing pgd_get() and what
> > it's semantics are, so I can't comment further.
> 
> The helper is intended to read the value of the entry pointed to by the passed
> in pointer. And it shoiuld be read in a "single copy atomic" manner, meaning no
> tearing. Further, the PTL is expected to be held when calling the getter. If the
> HW can write to the entry such that its racing with the lock holder (i.e. HW
> update of access/dirty) then READ_ONCE() should be suitable for most
> architectures. If there is no possibility of racing (because HW doesn't write to
> the entry), then a simple dereference would be sufficient, I think (which is
> what the core code was already doing in most cases).

The core code should be making no access to the PGD entries on 32-bit
ARM since the PGD level does not exist. Writes are done at PMD level
in arch code. Reads are done by core code at PMD level.

It feels to me like pgd_get() just doesn't fit the model to which 32-bit
ARM was designed to use decades ago, so I want full details about what
pgd_get() is going to be used for and how it is going to be used,
because I feel completely in the dark over this new development. I fear
that someone hasn't understood the Linux page table model if they're
wanting to access stuff at levels that effectively "aren't implemented"
in the architecture specific kernel model of the page tables.

Essentially, on 32-bit 2-level ARM, the PGD is merely indexed by the
virtual address. As far as the kernel is concerned, each entry is
64-bit, and the generic kernel code has no business accessing that
through the pgd pointer.

The pgd pointer is passed through the PUD and PMD levels, where it is
typecast down through the kernel layers to a pmd_t pointer, where it
becomes a 32-bit quantity. This results in only the _first_ level 1
pointer being dereferenced by kernel code to a 32-bit pmd_t quantity.
pmd_page_vaddr() converts this pmd_t quantity to a pte pointer (which
points at the software level 2 page tables, not the hardware page
tables.)

So, as I'm now being told that the kernel wants to dereference the
pgd level despite the model I describe above, alarm bells are ringing.
I want full information please.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 80Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuxZ/QeSdqTHtfmw%40shell.armlinux.org.uk.
