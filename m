Return-Path: <kasan-dev+bncBCSPV64IYUKBB5EJWW3QMGQE7PGE4PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-f64.google.com (mail-wm1-f64.google.com [209.85.128.64])
	by mail.lfdr.de (Postfix) with ESMTPS id AF24D97D3DC
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2024 11:48:37 +0200 (CEST)
Received: by mail-wm1-f64.google.com with SMTP id 5b1f17b1804b1-42ca8037d9asf11786905e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2024 02:48:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726825717; cv=pass;
        d=google.com; s=arc-20240605;
        b=TLYWTdUqDdI0FKaUZxfskmapH+Ya/N8mNpj9o5bYlQRh/Ok7CubBEyGTI1ILOXn+vV
         7wFSwslmzS6/KIurzIC3BvktiD/4bqM2xTsvJ7QOAMZOAJN4CaK07u8QIYHM9a3399sA
         O2VgoCglJjq4gbuRzfmBjYVTGqMow+9LEA7YzPWxehjdbRah9qOyAcDbPYZnUigGhiCA
         gYLnUyi6cMm0NFuBf7V4le7iS3kqLeOXBUWPGMmQ2hJPk56FSCRV4i650E0iqmX7nHKm
         ek0p3KIzICv0H3JFEBiDD3fjKrw5VmgQ4YisBAwrng6bAlUAo2LG/lvDLLXmA1+Xtesu
         lzyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=Pqy4Bh3bosoPEHdV4DTOoEL9wYvSVPCxoK1NQmJjbl0=;
        fh=5m3llkjKFdtNzM9lgtnnc1s6rbF8N+NWRClYHHJeEiU=;
        b=K6mh3fj7VMxcX6vTIs8ZS2UEC0hpcGJCt/uISSh8FCE3vinf6LNa9wQS/d1m4JJLGo
         kle0T6tciAAuZBb2aCQNrgjlqneqtp4N+QeVee7DQJePEASWMrzTIL3OjRSNLjTl59cj
         7FFzCs0BYRJsRPyFY5j99qeA2X4EcpD9e3cVu1AXNnhOxQbbtMcgKAb9AyDqQgeoyou5
         b2v068k0g9uK7DazVRTB/eOH/joTZHZ5tfiJaqqwtwkkwDX7c5PRzu2ATYJ5PV9Ie70N
         nb8pRr1VPE7+XTmyxVljEea0wKlNo4FfBdkVxQLPqpj5OMrBQNH1kWlsObLHpuyLBnxB
         dU5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=FCaBAyrk;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726825717; x=1727430517;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Pqy4Bh3bosoPEHdV4DTOoEL9wYvSVPCxoK1NQmJjbl0=;
        b=FIdcYyNxRt3DfP4+slI22pvqT3yZ6Mm68b4GfwR/DhVh6VZ/NS1IL+93gWRpFacleA
         JQIL/zM16fRepZ5KNhEnDycSl7HFJsMhBnDAuEKiHuFnJ00lQk1HU3Ivx0Z0z3wKGzql
         MG3FPaymWQ6ZsKte5UGNsDykdOslygT7AEqUrInrNjWnCHTGY+GU4KWSR6d/ujLGk9Aq
         YdGE1KcXpp4Kz7XpFXFJzZP6CpTRbjsXX/C6pVHu673xHCn0GGRCWCEmdgXr218PAWh4
         +vZuxNo3/hz+ON8Pe3LjmWnEihyiF7uKiJTP6pieMYkI6bhQKnkhv0BQA6R4f2NGDhR6
         yQRA==
X-Forwarded-Encrypted: i=2; AJvYcCWFVNCqIUiRLuCYj8SaaW3ui05Cw7K5HedlbAzOUhuzIGLkdoyeRHp34VjrsTssYVBeXryCdQ==@lfdr.de
X-Gm-Message-State: AOJu0YyzawB7G5/QlMG2jgAe0Crgh/f6tKcAW6n9Q10XJi9Wg8gjQalS
	u9l3VjK5ITCTVDFEAdCJ0csRsootyvjb5lEtAXUaUIlDDjayRE8c
X-Google-Smtp-Source: AGHT+IGZh1r3iBYpfvUTBPrE9EB09yNO93C+0RsHcZfRuPFJtKxBmP0SHmfgIvxWO8UeAiSOiTjaPQ==
X-Received: by 2002:a5d:4f92:0:b0:374:b24e:d2bf with SMTP id ffacd0b85a97d-37a422c01e2mr1195300f8f.27.1726825716433;
        Fri, 20 Sep 2024 02:48:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5983:0:b0:374:c0b6:44ce with SMTP id ffacd0b85a97d-379a860c2dals272007f8f.0.-pod-prod-04-eu;
 Fri, 20 Sep 2024 02:48:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVsmHlFYRI0oCy3ypSBf7VDmcYrfYzda9w6flKvEBfjmY9NLm1BqQlFZpXoGSBQlbGr2QDqMPxDEGo=@googlegroups.com
X-Received: by 2002:a05:600c:1d08:b0:42c:bad0:6c16 with SMTP id 5b1f17b1804b1-42e7abe21c2mr17167125e9.2.1726825714597;
        Fri, 20 Sep 2024 02:48:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726825714; cv=none;
        d=google.com; s=arc-20240605;
        b=A6W1HDtI1leTt5j4LIC7uVZlEcMQ3XxOPQQd39jwV8L5Cliu1vQlcOH/THz3hPyfmg
         QzkAF1U3mmzkKlLtfPZ15HDK2Ikmh+VawvRkfXh1e0XJLQgoM+leZZs4xrhJEBMFEicp
         fuvORXQhbGMFvp3dcFJ3faPqIsWivBu+kp+N1ttf0EQSGuSImUjLiq0B2ZNyuRWzbtEM
         /YeYyAbIlNxeT9kWMi9aDzoy732N1EqW6e4WKvE2RqaI3mNBir7e7IZvSJdIlf+OpjWB
         AUOOYtpy76PNf4+iI1q4ceNQQtb0Fs0rWCwI/gMrf8v5ef9VVxC95rg4BfABpAmeoZa6
         DNrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lqLyI3VFGw/HAwz/TUdgSpSC7qmKkHxnZTuEYK+TROA=;
        fh=vvFsAELp3/ijmy+VyjXHqEgJwr2AV/p0Vw32McP4bZ8=;
        b=Wni06f8k6F8/HXTGEXTduu/Ja02FDpPoinTrphRQxS757whL34NcMwe1ysOgGeXrYJ
         RNQ1Uzaz6FOc6q0JjlL0B/7HAZQfJicuSss55CRL9zUWDEQOiZigazQ1diWHGWmhR2bo
         knogMJtD4BGmK5307zuoipWb1/+ASFVeiP5F5PDexDkcZ7wVoajDUjhANZY/5RfaK1dI
         rzBzkak1gRxHA26DjDt1x5yaugVp8WszyZ+fMrcLL5+N/xdsHPA1RT/R0nomSqMNIO7I
         PanpiBvt+WdC5LIDKSQhiBl7gq2Q2v3DDvJjkrS4CbUpgTFSDQsaQdFEafaNm7+XSP34
         hiNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=FCaBAyrk;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e6c718f09si2308555e9.1.2024.09.20.02.48.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Sep 2024 02:48:34 -0700 (PDT)
Received-SPF: none (google.com: armlinux.org.uk does not designate permitted sender hosts) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:33476)
	by pandora.armlinux.org.uk with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.96)
	(envelope-from <linux@armlinux.org.uk>)
	id 1sraF3-0001NG-1b;
	Fri, 20 Sep 2024 10:47:57 +0100
Received: from linux by shell.armlinux.org.uk with local (Exim 4.96)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1sraEr-0002Qp-2B;
	Fri, 20 Sep 2024 10:47:45 +0100
Date: Fri, 20 Sep 2024 10:47:45 +0100
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
Message-ID: <Zu1EwTItDrnkTVTB@shell.armlinux.org.uk>
References: <20240917073117.1531207-8-anshuman.khandual@arm.com>
 <202409190310.ViHBRe12-lkp@intel.com>
 <8f43251a-5418-4c54-a9b0-29a6e9edd879@arm.com>
 <ZuvqpvJ6ht4LCuB+@shell.armlinux.org.uk>
 <82fa108e-5b15-435a-8b61-6253766c7d88@arm.com>
 <ZuxZ/QeSdqTHtfmw@shell.armlinux.org.uk>
 <5bd51798-cb47-4a7b-be40-554b5a821fe7@arm.com>
 <ZuyIwdnbYcm3ZkkB@shell.armlinux.org.uk>
 <9e68ffad-8a7e-40d7-a6f3-fa989a834068@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9e68ffad-8a7e-40d7-a6f3-fa989a834068@arm.com>
Sender: Russell King (Oracle) <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=FCaBAyrk;
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

On Fri, Sep 20, 2024 at 08:57:23AM +0200, Ryan Roberts wrote:
> On 19/09/2024 21:25, Russell King (Oracle) wrote:
> > On Thu, Sep 19, 2024 at 07:49:09PM +0200, Ryan Roberts wrote:
> >> On 19/09/2024 18:06, Russell King (Oracle) wrote:
> >>> On Thu, Sep 19, 2024 at 05:48:58PM +0200, Ryan Roberts wrote:
> >>>>> 32-bit arm uses, in some circumstances, an array because each level 1
> >>>>> page table entry is actually two descriptors. It needs to be this way
> >>>>> because each level 2 table pointed to by each level 1 entry has 256
> >>>>> entries, meaning it only occupies 1024 bytes in a 4096 byte page.
> >>>>>
> >>>>> In order to cut down on the wastage, treat the level 1 page table as
> >>>>> groups of two entries, which point to two consecutive 1024 byte tables
> >>>>> in the level 2 page.
> >>>>>
> >>>>> The level 2 entry isn't suitable for the kernel's use cases (there are
> >>>>> no bits to represent accessed/dirty and other important stuff that the
> >>>>> Linux MM wants) so we maintain the hardware page tables and a separate
> >>>>> set that Linux uses in the same page. Again, the software tables are
> >>>>> consecutive, so from Linux's perspective, the level 2 page tables
> >>>>> have 512 entries in them and occupy one full page.
> >>>>>
> >>>>> This is documented in arch/arm/include/asm/pgtable-2level.h
> >>>>>
> >>>>> However, what this means is that from the software perspective, the
> >>>>> level 1 page table descriptors are an array of two entries, both of
> >>>>> which need to be setup when creating a level 2 page table, but only
> >>>>> the first one should ever be dereferenced when walking the tables,
> >>>>> otherwise the code that walks the second level of page table entries
> >>>>> will walk off the end of the software table into the actual hardware
> >>>>> descriptors.
> >>>>>
> >>>>> I've no idea what the idea is behind introducing pgd_get() and what
> >>>>> it's semantics are, so I can't comment further.
> >>>>
> >>>> The helper is intended to read the value of the entry pointed to by the passed
> >>>> in pointer. And it shoiuld be read in a "single copy atomic" manner, meaning no
> >>>> tearing. Further, the PTL is expected to be held when calling the getter. If the
> >>>> HW can write to the entry such that its racing with the lock holder (i.e. HW
> >>>> update of access/dirty) then READ_ONCE() should be suitable for most
> >>>> architectures. If there is no possibility of racing (because HW doesn't write to
> >>>> the entry), then a simple dereference would be sufficient, I think (which is
> >>>> what the core code was already doing in most cases).
> >>>
> >>> The core code should be making no access to the PGD entries on 32-bit
> >>> ARM since the PGD level does not exist. Writes are done at PMD level
> >>> in arch code. Reads are done by core code at PMD level.
> >>>
> >>> It feels to me like pgd_get() just doesn't fit the model to which 32-bit
> >>> ARM was designed to use decades ago, so I want full details about what
> >>> pgd_get() is going to be used for and how it is going to be used,
> >>> because I feel completely in the dark over this new development. I fear
> >>> that someone hasn't understood the Linux page table model if they're
> >>> wanting to access stuff at levels that effectively "aren't implemented"
> >>> in the architecture specific kernel model of the page tables.
> >>
> >> This change isn't as big and scary as I think you fear.
> > 
> > The situation is as I state above. Core code must _not_ dereference pgd
> > pointers on 32-bit ARM.
> 
> Let's just rewind a bit. This thread exists because the kernel test robot failed
> to compile pgd_none_or_clear_bad() (a core-mm function) for the arm architecture
> after Anshuman changed the direct pgd dereference to pgdp_get(). The reason
> compilation failed is because arm defines its own pgdp_get() override, but it is
> broken (there is a typo).

Let's not rewind, because had you fully read and digested my reply, you
would have seen why this isn't a problem... but let me spell it out.

> 
> Code before Anshuman's change:
> 
> static inline int pgd_none_or_clear_bad(pgd_t *pgd)
> {
> 	if (pgd_none(*pgd))
> 		return 1;
> 	if (unlikely(pgd_bad(*pgd))) {
> 		pgd_clear_bad(pgd);
> 		return 1;
> 	}
> 	return 0;
> }

This isn't a problem as the code stands. While there is a dereference
in C, that dereference is a simple struct copy, something that we use
everywhere in the kernel. However, that is as far as it goes, because
neither pgd_none() and pgd_bad() make use of their argument, and thus
the compiler will optimise it away, resulting in no actual access to
the page tables - _as_ _intended_.

If these are going to be converted to pgd_get(), then we need pgd_get()
to _also_ be optimised away, and if e.g. this is the only place that
pgd_get() is going to be used, the suggestion I made in my previous
email is entirely reasonable, since we know that the result of pgd_get()
will not actually be used.

> As an aside, the kernel also dereferences p4d, pud, pmd and pte pointers in
> various circumstances.

I already covered these in my previous reply.

> And other changes in this series are also replacing those
> direct dereferences with calls to similar helpers. The fact that these are all
> folded (by a custom arm implementation if I've understood the below correctly)
> just means that each dereference is returning what you would call the pmd from
> the HW perspective, I think?

It'll "return" the first of each pair of level-1 page table entries,
which is pgd[0] or *p4d, *pud, *pmd - but all of these except *pmd
need to be optimised away, so throwing lots of READ_ONCE() around
this code without considering this is certainly the wrong approach.

> >> The core-mm today
> >> dereferences pgd pointers (and p4d, pud, pmd pointers) directly in its code. See
> >> follow_pfnmap_start(),
> > 
> > Doesn't seem to exist at least not in 6.11.
> 
> Appologies, I'm on mm-unstable and that isn't upstream yet. See follow_pte() in
> v6.11 or __apply_to_page_range(), or pgd_none_or_clear_bad() as per above.

Looking at follow_pte(), it's not a problem.

I think we wouldn't be having this conversation before:

commit a32618d28dbe6e9bf8ec508ccbc3561a7d7d32f0
Author: Russell King <rmk+kernel@arm.linux.org.uk>
Date:   Tue Nov 22 17:30:28 2011 +0000

    ARM: pgtable: switch to use pgtable-nopud.h

where:
-#define pgd_none(pgd)          (0)
-#define pgd_bad(pgd)           (0)

existed before this commit - and thus the dereference in things like:

	pgd_none(*pgd)

wouldn't even be visible to beyond the preprocessor step.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 80Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zu1EwTItDrnkTVTB%40shell.armlinux.org.uk.
