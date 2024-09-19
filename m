Return-Path: <kasan-dev+bncBCSPV64IYUKBBZOVV63QMGQEBYMHKMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-f55.google.com (mail-ed1-f55.google.com [209.85.208.55])
	by mail.lfdr.de (Postfix) with ESMTPS id 5860297C69C
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 11:12:07 +0200 (CEST)
Received: by mail-ed1-f55.google.com with SMTP id 4fb4d7f45d1cf-5c24b4a57b4sf498393a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 02:12:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726737127; cv=pass;
        d=google.com; s=arc-20240605;
        b=gPQHNchrBVmmRw5UgnYoD+ErqPPJU+PD8ohPqCqOcz83mMRL204Rdj0W9PeFFAKvoH
         YTHL0i2CY9H/k1OsO9fCHYoLK5OPs5E5Vos7ujWQhg2sBt/dW8I1WbmfxGN4GGEc8zDC
         VVf2DTBUbnUpWcyjeNE0ArnyMV0dks5AO+MDWYXmgWk462fxbu/er+h2+olVYqtcs3Uy
         uxQPtBuj0ISMwEvpO08LnoTnDTfh+vIGgkHxZl/+qTMXs/CdKe0C+65DzqfBUgPOt100
         cTDdVAxmv4A9wPDjCsMFZs8bAb6edJKoPEdW9Ntj+bJLOuABKgCNKiVvBTx68YgSTl8m
         Q23A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=aEG7Zulf676y/1QwTff7vD8KsFWpmuKxLaeCCaKDxz8=;
        fh=oYuWhwCx5git7Jbj0q5jZzCX/TWjr+ZpyrHJV9krEUQ=;
        b=DX7OeW4H7EmNTAhXJ4wJOLkOgn+rrTWYWXZZ+tNUyI6KnvBPgEautA5xgZOpfdM2pQ
         9XK0FjEfNZFdzn41IW66UNftCIDIDOJ6PjqQI0CH3wfCu0UvfhbbdYloob/Ge+dPwjAF
         9t0hVCCnrY0nxwSBv1nUstCSlQWN7sPsaV11SnHiQPEswEaJYx61FZC3hgqQ6F3j/l3f
         uCGquXUvtvNjekyFrHNfrMo74Vw9dq/8lLlRVcQVMOkOv+YBU1srhAgnqoqWym4iWrid
         VLcpG966P71naAMvv7YytgMRAeyfC0PDHLy9hnyjltFoKeVX/ctrPY4HCcClYO9qZwCk
         vzAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=KxWAU0sA;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726737127; x=1727341927;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aEG7Zulf676y/1QwTff7vD8KsFWpmuKxLaeCCaKDxz8=;
        b=LGcez3y7Iq+gpNXq71f7lowumNoB+kY2PXfRCq8BajeCpXF+hGctFW/J11GbiVYivz
         AGoudVWUaKXy8zqokb1KjXZo+RFaNYUlcN3Y9wrK4pctJHrU+relHLlmeBUBv3vGdw6r
         T8COxDQfDMH/MUrt+Y60RZqy+LvvvDJG47fNcdEB9Yaf9k9cgV8xZAmmoyQ4EzLq44Bm
         l7RpGViEL7ISsKxxtVgd//CdSLzz1R29nV2IGk01tjVI4U0SId0Lz5ExapGz+jPgRXEB
         yKr0gavyoBwGMvK9rtxfK1ZqoVTtSuJxI2YUnDtlBHe5hrHaGVRq/0O/Y+qVWuxLgGcw
         7T1w==
X-Forwarded-Encrypted: i=2; AJvYcCXVdBAzD8HFzOv6lNBmKdK9NwyaAbpmC0vkmQu0OdJIkMHmljjkvopnLIhmkP/bw6vE7yQXyg==@lfdr.de
X-Gm-Message-State: AOJu0Yy+T7FtjBlAAhR38DYA96KaFHh3Zp6IAaxL7Vxixpi4t7PSOPjQ
	fTKEjwtDAHqHzF+wXnGSdMB+Da/1UwL5j38m4T+5CEf2x4o6LbMs
X-Google-Smtp-Source: AGHT+IE82jfWmQZFrkN3KHpycyHE/YfYGvV/yhvmiRBbZG/P1eU3mnWP/hR/qEHZF12XwbSAN03vVA==
X-Received: by 2002:a05:6402:d08:b0:5c3:cb1d:8176 with SMTP id 4fb4d7f45d1cf-5c41e2ad471mr16031068a12.30.1726737125814;
        Thu, 19 Sep 2024 02:12:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35cf:b0:5c4:2278:28dd with SMTP id
 4fb4d7f45d1cf-5c459953550ls609548a12.2.-pod-prod-06-eu; Thu, 19 Sep 2024
 02:12:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpvyDM2ig8YABbPf145CY0zx23eQukDxtNRDwHHo2uEHjBNj6vLdXuu8U5FAECrzJy+uw+YBlzuoE=@googlegroups.com
X-Received: by 2002:a05:6402:42d0:b0:5c4:2fb1:416f with SMTP id 4fb4d7f45d1cf-5c42fb142ccmr13528008a12.29.1726737123925;
        Thu, 19 Sep 2024 02:12:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726737123; cv=none;
        d=google.com; s=arc-20240605;
        b=jMeGmjeQGLVnO94ryXB/RvB/E1Awli3sjq1Z76UyQXDDaemseVKnp60yQmAS58wfgY
         YJO4/0ovLvjDQ/97MDnQHpTFIHb4LUnzr2MBCYxREhSp25ZmaAdzLC2zV9DSxAT9Qm7m
         tKv6Pb0YqdHWRt/MtO1JEj4LlHsimyE+iQoIdHYHGD6TIznUer1CAEc2yCHYkv6b0Cci
         WeGfJXMdYUwJFh9X0k58lOepf8uIiqb/bKrFo1BrefyGshHr6TAhwHVxHI4doLLN4TFV
         p4424ed4xeKWHMn7YV4Y9/VBwZ6UGgCikLg/GszGIYq6JrBM9d9PgKw1ijgDnmpHw5Fa
         G6vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XSYMeRXWsqrG7F+YI4a+nTQDZpFZ8nCNoB9zSp4g67c=;
        fh=YehCnJWJ8ydYMqqQH63ECl1nAqLkbWGsb3FK5dl0ebA=;
        b=BEXzA0n07x3rCMIdewSY51dd3kYBmxfDntf6FrfWsAJCETqBYaadjx+svteEV5iazZ
         9NmsyIE85rN1wKNexjJNnRSkMCWdR9qr/foDP+Vfr4gHT7KeBlixdQcbT38RLBy77NwM
         9OZyvHOfQp83T2puEhDNUIothlZ077Hw7qgwsuWc4J1DDfGt4ZegK7Eed8oDMbWTT5k/
         ef5+Xyu10SwU62/mBYQ9/P3tUXSpC41Pe524I4e3feedhflz7PjYp+bqL5eru1EGJZ9V
         WcWy4Q+NX1kan8e9uXJhSQFnGwQbHYH9Y8A1ZMRDN6RBFSfJASE5dZuD5KMgOTaNBI9v
         4YUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=KxWAU0sA;
       spf=none (google.com: armlinux.org.uk does not designate permitted sender hosts) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5c42bb51dcfsi222263a12.2.2024.09.19.02.12.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Sep 2024 02:12:03 -0700 (PDT)
Received-SPF: none (google.com: armlinux.org.uk does not designate permitted sender hosts) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:59440)
	by pandora.armlinux.org.uk with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.96)
	(envelope-from <linux@armlinux.org.uk>)
	id 1srDBz-0000GJ-37;
	Thu, 19 Sep 2024 10:11:15 +0100
Received: from linux by shell.armlinux.org.uk with local (Exim 4.96)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1srDBn-0001Rd-0M;
	Thu, 19 Sep 2024 10:11:03 +0100
Date: Thu, 19 Sep 2024 10:11:02 +0100
From: "Russell King (Oracle)" <linux@armlinux.org.uk>
To: Anshuman Khandual <anshuman.khandual@arm.com>
Cc: kernel test robot <lkp@intel.com>, linux-mm@kvack.org,
	llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
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
Message-ID: <ZuvqpvJ6ht4LCuB+@shell.armlinux.org.uk>
References: <20240917073117.1531207-8-anshuman.khandual@arm.com>
 <202409190310.ViHBRe12-lkp@intel.com>
 <8f43251a-5418-4c54-a9b0-29a6e9edd879@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8f43251a-5418-4c54-a9b0-29a6e9edd879@arm.com>
Sender: Russell King (Oracle) <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=KxWAU0sA;
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

On Thu, Sep 19, 2024 at 01:25:08PM +0530, Anshuman Khandual wrote:
> arm (32) platform currently overrides pgdp_get() helper in the platform but
> defines that like the exact same version as the generic one, albeit with a
> typo which can be fixed with something like this.

pgdp_get() was added to arm in eba2591d99d1 ("mm: Introduce
pudp/p4dp/pgdp_get() functions") with the typo you've spotted. It seems
it was added with no users, otherwise the error would have been spotted
earlier. I'm not a fan of adding dead code to the kernel for this
reason.

> Regardless there is another problem here. On arm platform there are multiple
> pgd_t definitions available depending on various configs but some are arrays
> instead of a single data element, although platform pgdp_get() helper remains
> the same for all.
> 
> arch/arm/include/asm/page-nommu.h:typedef unsigned long pgd_t[2];
> arch/arm/include/asm/pgtable-2level-types.h:typedef struct { pmdval_t pgd[2]; } pgd_t;
> arch/arm/include/asm/pgtable-2level-types.h:typedef pmdval_t pgd_t[2];
> arch/arm/include/asm/pgtable-3level-types.h:typedef struct { pgdval_t pgd; } pgd_t;
> arch/arm/include/asm/pgtable-3level-types.h:typedef pgdval_t pgd_t;
> 
> I guess it might need different pgdp_get() variants depending applicable pgd_t
> definition. Will continue looking into this further but meanwhile copied Russel
> King in case he might be able to give some direction.

That's Russel*L*, thanks.

32-bit arm uses, in some circumstances, an array because each level 1
page table entry is actually two descriptors. It needs to be this way
because each level 2 table pointed to by each level 1 entry has 256
entries, meaning it only occupies 1024 bytes in a 4096 byte page.

In order to cut down on the wastage, treat the level 1 page table as
groups of two entries, which point to two consecutive 1024 byte tables
in the level 2 page.

The level 2 entry isn't suitable for the kernel's use cases (there are
no bits to represent accessed/dirty and other important stuff that the
Linux MM wants) so we maintain the hardware page tables and a separate
set that Linux uses in the same page. Again, the software tables are
consecutive, so from Linux's perspective, the level 2 page tables
have 512 entries in them and occupy one full page.

This is documented in arch/arm/include/asm/pgtable-2level.h

However, what this means is that from the software perspective, the
level 1 page table descriptors are an array of two entries, both of
which need to be setup when creating a level 2 page table, but only
the first one should ever be dereferenced when walking the tables,
otherwise the code that walks the second level of page table entries
will walk off the end of the software table into the actual hardware
descriptors.

I've no idea what the idea is behind introducing pgd_get() and what
it's semantics are, so I can't comment further.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 80Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuvqpvJ6ht4LCuB%2B%40shell.armlinux.org.uk.
