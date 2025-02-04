Return-Path: <kasan-dev+bncBCMMDDFSWYCBBBVARG6QMGQEEFPBKTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 39481A27893
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:36:08 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2ee5616e986sf16583928a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:36:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690566; cv=pass;
        d=google.com; s=arc-20240605;
        b=QAo7gpW/zSQeYcIeM9yHy2JmalGjxKwg0010r11EUIS6DUPKBT8I8daB1Ut1dz6mWm
         Z3D+xYpneC+3GlsoKTwR2Qv7TOPcCWc06x1diHOxO0V7q6YZfTF0btHaRSAVfcS8riiQ
         DWJUj1GQlDNjhkjYC1HAfIOm3VqWfW9ebYOwN3bRgO/hZNxL+hjem6kvt5BHXTdNE++x
         hok2GB8oEK3sXHvUzMGaLjGWS7EthABurrjpTMG6qwO/W25v8nMleWUKIulckOotDakk
         CByZd20m0d+zepVWidoLB4dHeXvMmx6Zk13mDHa0FCtT3xvNmMGhTSITF241j33qBfvy
         ITUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pKzheGG99CjT4U/tTaRfr0k3dJ3dra1JyAkQ1Jf+bek=;
        fh=zR+7eTUfF/QQzSP4oKGc+Fp3aPnadCcyBuqBRXzDb5k=;
        b=TLDiZ5BGABYENDBWbU4k6c7On/0ooBTgMbbLtQNlk6+UGGISPzXofYWgShZsnh93wg
         qssNzV5e3EcbrMo+2Uxzz/nC2MRgIlVB4QG4jnp/Jgvr8VrmmkSqBXdCnijZwRWW0VF0
         08l/F3y+IwxxXMk1mBZ6hQSgtoZ+7ors1NQ4/Xsj5kxRN4VJN3lQEZfNb7+qsWuDPuQx
         4YEzwPNiPCIR6Zd84WK/5YXQtsLgqW7bNGUlbIs8IiWqfW2bAKdbpiH0s1YSwn9fuN4r
         Tk1b1Z9CrxbHk0o0/eofAZsgpWGbOKtn1YXnMY4IwWtWGrV2A3KU1wGooImcLEPu8B2w
         We0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="Kpt7Oki/";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690566; x=1739295366; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pKzheGG99CjT4U/tTaRfr0k3dJ3dra1JyAkQ1Jf+bek=;
        b=BHN8WubGRhFP74k1HvXvEzV18NPJDYgGs2GRIyYOlkl83nC9ZO0PzvYq8F2mknOP8u
         VHeT+I4I3Y0+NlFQPbbXlrAEO/3SBmZpAmcKJAZTwClo9T2kIHaXWItBtT3eBp/oWetR
         vHvnZ3ZTGWMQLjlv2I8vMkP9eWEiKmvlh/x1D0J1vrNYxpoH61natC5xjyz+K9L1R8g9
         OxubKdkSuJh4aFnTsNjaVAKVHwyKtHNp5cVJNaMRPNXeSfOXaDK3oapmvgD89k4WzUJV
         V5Ksd2+hAqIcCDTKDrs2xCoIFOX4LM/TqVOl9+OUZgQ8y52/aXU7CcXcQ0SaNq70e8Zk
         bnFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690566; x=1739295366;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pKzheGG99CjT4U/tTaRfr0k3dJ3dra1JyAkQ1Jf+bek=;
        b=qnlWubs1GeS8N6fl3Y60lpKFkjFoJHSy/L+cnR9H0angVJ3+dLhnMJhrf/LVrB4qys
         ooXG5+Q9P9D8XV8eyJeXsv7dx6D9m9AVV3ALdeKKxoYRYJ0U+7E8mcmbwgZ/9Qie0iwf
         7X05+5eV4Yg6u8KxnGvRCHx+eUY7ih1e99C6TFonboTC+7nqhbZOzoZjbxIXJGPZXvs4
         8h1c+LXx2PUZBnT5BRct6E+5IpTofSkS8CsRQPBuPSFyPTXwywYZqJ7zbXi0wCeI4IxB
         iXuHslsIImAxwXkEdTGGbDV+CAfEzFzmzDRqWG5Wz2CBK4nIcHiKAS0XOGay1QND6QOi
         bYeA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2ajUxVgG0aOQDE1ydh6x0unljAnwDbub99svyD85MAPO9DtT68O8BWSWoaacEaCjNJaMA9g==@lfdr.de
X-Gm-Message-State: AOJu0Yy0BCxhoiIks+HMdCmWnOLO/OVisimEc2ToC4QVs3zmxmXEScq8
	WbM6HMAEOcVlSAswK7QOPT0KtbVjY2sUv3qP5V1cUAWyu3dXhLtA
X-Google-Smtp-Source: AGHT+IFvMp7QKQmPgCBph06V8GuNY40voxp3ybJcMXIF0VtGgU2J5xccY13gS7W0GcPouqP/FHE0Ug==
X-Received: by 2002:a17:90b:2742:b0:2ee:b4d4:69 with SMTP id 98e67ed59e1d1-2f83ac87677mr37545748a91.35.1738690566253;
        Tue, 04 Feb 2025 09:36:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d383:b0:2e2:840e:d4a7 with SMTP id
 98e67ed59e1d1-2f845dc1443ls5479285a91.1.-pod-prod-06-us; Tue, 04 Feb 2025
 09:36:04 -0800 (PST)
X-Received: by 2002:a17:902:ec81:b0:21d:ccb9:e2b9 with SMTP id d9443c01a7336-21dd7dd8601mr437435395ad.41.1738690563841;
        Tue, 04 Feb 2025 09:36:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690563; cv=none;
        d=google.com; s=arc-20240605;
        b=cwRdH8txMZwQxK11XYBiBGZOqdSqI0bBL7SUfWqxVmaWK61icirAqob1h7LpwB77WR
         n4ZI6ntMbyCVBWt1wnI8OjaFbL8CH7xs4KUDPR6vk3rR+bDhee1K6uZjcxcPxH5LGSTb
         R/lOaxBbt3/Cz/dRdr/+9LWZXmD80iboyJ7pDSEqBQUB4d7dLTLpyQ2fRKNKrCjqvj58
         eXh4e2C9YACH+LaeJ+CQGNkeoUne4bPcGvqYrql5f2grAz0CI4X6OLAFFfiVe1XFudTf
         W54aYsGDMtldBcomlUVAYWlY5r9scQ5gWJimol4v/aLsIqIW/8nZ89pM/NcQtuNXMHLh
         9OfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=o0QxH8z6cj5lUaoAwjX8vI7JCJobGz53CoJ6O2LJ4cM=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=jXaiw/fPGMWfPsP95QrT3Ii0BTK2Q0GsL4Tki9iO+KgXKGbkIQrt9Hc250e7j2/TIS
         QiZY6Ye6oQ1yGZt1u8Fu/bl4gHeEgKLZMD09DQZmyo/taw4XkoJ426dasW60pSbrSALi
         QeB6VZANXklHAh3hL4HDQjRIcUNVQeaw+dyP40viqX6/RmPrIv7b0yQs0RKHCekhodv/
         xFgLBLP18QbK2ESF91qdgi1crmIedV35tIa8akVIA0b3hBSXK3GIBFiwqx6JkJ5/YMqN
         5pVOK0IQNCyM02z+YHJ/0cD6aibgMt6aCu+yMok8jNq3yU4NKesD29asrGy0xczeuNl4
         W6ew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="Kpt7Oki/";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f9c3161cbdsi123252a91.1.2025.02.04.09.36.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:36:03 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: qZmYSo9YTxGp0fXSA5NCug==
X-CSE-MsgGUID: JUKEVYSXTletALP8jtHmKw==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38930674"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38930674"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:36:02 -0800
X-CSE-ConnectionGUID: PpX6VWM3RaGBO1JoNfSfGA==
X-CSE-MsgGUID: vYDFTil1TqeMDIrSmNQ1tw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866647"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:35:50 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: luto@kernel.org,
	xin@zytor.com,
	kirill.shutemov@linux.intel.com,
	palmer@dabbelt.com,
	tj@kernel.org,
	andreyknvl@gmail.com,
	brgerst@gmail.com,
	ardb@kernel.org,
	dave.hansen@linux.intel.com,
	jgross@suse.com,
	will@kernel.org,
	akpm@linux-foundation.org,
	arnd@arndb.de,
	corbet@lwn.net,
	maciej.wieczor-retman@intel.com,
	dvyukov@google.com,
	richard.weiyang@gmail.com,
	ytcoode@gmail.com,
	tglx@linutronix.de,
	hpa@zytor.com,
	seanjc@google.com,
	paul.walmsley@sifive.com,
	aou@eecs.berkeley.edu,
	justinstitt@google.com,
	jason.andryuk@amd.com,
	glider@google.com,
	ubizjak@gmail.com,
	jannh@google.com,
	bhe@redhat.com,
	vincenzo.frascino@arm.com,
	rafael.j.wysocki@intel.com,
	ndesaulniers@google.com,
	mingo@redhat.com,
	catalin.marinas@arm.com,
	junichi.nomura@nec.com,
	nathan@kernel.org,
	ryabinin.a.a@gmail.com,
	dennis@kernel.org,
	bp@alien8.de,
	kevinloughlin@google.com,
	morbo@google.com,
	dan.j.williams@intel.com,
	julian.stecklina@cyberus-technology.de,
	peterz@infradead.org,
	cl@linux.com,
	kees@kernel.org
Cc: kasan-dev@googlegroups.com,
	x86@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	linux-doc@vger.kernel.org
Subject: [PATCH 07/15] mm: Pcpu chunk address tag reset
Date: Tue,  4 Feb 2025 18:33:48 +0100
Message-ID: <e7e04692866d02e6d3b32bb43b998e5d17092ba4.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="Kpt7Oki/";       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Content-Type: text/plain; charset="UTF-8"
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

The problem presented here is related to NUMA systems and tag-based
KASAN mode. Getting to it can be explained in the following points:

	1. A new chunk is created with pcpu_create_chunk() and
	   vm_structs are allocated. On systems with one NUMA node only
	   one is allocated, but with more NUMA nodes at least a second
	   one will be allocated too.

	2. chunk->base_addr is assigned the modified value of
	   vms[0]->addr and thus inherits the tag of this allocated
	   structure.

	3. In pcpu_alloc() for each possible cpu pcpu_chunk_addr() is
	   executed which calculates per cpu pointers that correspond to
	   the vms structure addresses. The calculations are based on
	   adding an offset from a table to chunk->base_addr.

Here the problem presents itself since for addresses based on vms[1] and
up, the tag will be different than the ones based on vms[0] (base_addr).
The tag mismatch happens and an error is reported.

Reset the base_addr tag, since it will disable tag checks for pointers
derived arithmetically from base_addr that would inherit its tag.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 mm/percpu-vm.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/percpu-vm.c b/mm/percpu-vm.c
index cd69caf6aa8d..e13750d804f7 100644
--- a/mm/percpu-vm.c
+++ b/mm/percpu-vm.c
@@ -347,7 +347,7 @@ static struct pcpu_chunk *pcpu_create_chunk(gfp_t gfp)
 	}
 
 	chunk->data = vms;
-	chunk->base_addr = vms[0]->addr - pcpu_group_offsets[0];
+	chunk->base_addr = kasan_reset_tag(vms[0]->addr) - pcpu_group_offsets[0];
 
 	pcpu_stats_chunk_alloc();
 	trace_percpu_create_chunk(chunk->base_addr);
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e7e04692866d02e6d3b32bb43b998e5d17092ba4.1738686764.git.maciej.wieczor-retman%40intel.com.
