Return-Path: <kasan-dev+bncBCN77QHK3UIBBPX4436AKGQEZ5UE6VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id C437829D191
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 19:53:51 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id w189sf264383qkd.6
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 11:53:51 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HxpnAqDkSYeUGnJPRAWC6maZN10YcTGxwFYZG4U0Y5A=;
        b=UVGxf7F7vqBttmlCW54vuLjswgpF3pwkFsFBWa2sk3zjQRRRe89SBLOwK9KqRTnX+e
         WQEnYJoW3/lY7UaXMrZywICgh+IrVo99XUMml5Ot5bBgVKrgP+qzot5jOiy6mUzb+Cgt
         DfAGvvTRTKi1wp8LMwJzASOU2eXecNuDqVM6Cdpcd0G9d+MQqMHktNCQOeyocMxYQa+W
         6DE9gSSTQAyJGztvD8n1woLMPGjfX0EFxITEz048GXG1ZxgIA+MbOoQO5ayLJ/ez/RGE
         afl0bLzC8KAOg7KUmeb5qiPEGCSK3RnnZGYJEoobMLj2y8SZF8Dsm3DDPAR/3CBfKFks
         4IUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HxpnAqDkSYeUGnJPRAWC6maZN10YcTGxwFYZG4U0Y5A=;
        b=U+AoZAcC0m3pshwm0Fv0ocXYoQh6QqgWeflrQjw2V0m+o/8bIeWuewBQRGIQG375Cd
         z6zRx/YvMSUZt1lSX490Gcofb48d2jcRzTqooHOXOe1plLc6nEGNLGS9oaJ3I0gYc/Xn
         SeoGx5x1YFTZdXQnC0ZVlSf3xKUcRNIguzVerQh98kAHLIsbl5xyp37qD92J6eb5hfVN
         y3gwRZ6Lx0Fp2SLbx8rVqwlR3mMqrkAiji/hdPFO+Yxn0qMAy9PxopGqYITzn9vtI2c+
         bcFLh0DVGIhSmGQd8QueAClet+r4N6OjXbPgQiPYLjGdIQ02un6lOPSMJa6YSiFmybXP
         NRzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Oi9Ufm7TUWNg165MvcT8W9WfNLXs5h2kBHwhyVIEuNAxVVqAz
	vdixW15z8GUG3e27T8GWVB8=
X-Google-Smtp-Source: ABdhPJzHzu59V6ISelalcRi6fkw4jQZwYE0npSxP7V53Y2E2XFVzPtHgxcYevzDurDytD7hQtPnWPw==
X-Received: by 2002:ac8:ecb:: with SMTP id w11mr271029qti.113.1603911230593;
        Wed, 28 Oct 2020 11:53:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1352:: with SMTP id c18ls195013qkl.5.gmail; Wed, 28
 Oct 2020 11:53:50 -0700 (PDT)
X-Received: by 2002:a37:68d0:: with SMTP id d199mr264776qkc.408.1603911230145;
        Wed, 28 Oct 2020 11:53:50 -0700 (PDT)
Received: from hqnvemgate24.nvidia.com (hqnvemgate24.nvidia.com. [216.228.121.143])
        by gmr-mx.google.com with ESMTPS id g16si23779qtp.0.2020.10.28.11.53.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 28 Oct 2020 11:53:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 216.228.121.143 as permitted sender) client-ip=216.228.121.143;
Received: from hqmail.nvidia.com (Not Verified[216.228.121.13]) by hqnvemgate24.nvidia.com (using TLS: TLSv1.2, AES256-SHA)
	id <B5f99be410000>; Wed, 28 Oct 2020 11:53:53 -0700
Received: from HQMAIL111.nvidia.com (172.20.187.18) by HQMAIL107.nvidia.com
 (172.20.187.13) with Microsoft SMTP Server (TLS) id 15.0.1473.3; Wed, 28 Oct
 2020 18:53:44 +0000
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (104.47.58.169)
 by HQMAIL111.nvidia.com (172.20.187.18) with Microsoft SMTP Server (TLS) id
 15.0.1473.3 via Frontend Transport; Wed, 28 Oct 2020 18:53:44 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=LcFPQ+Lu8NRGsc0hU3VO841M6CUgCNfePBWPOyr7Mu/ITaRg2qLdcBVDaBoutJ+MJi+YnWPhqsLNdgqM6x3VTBPBmw45KJSnqz8+wchby8vCzGUm+0F/K4IswCk0mqK2Hsg9bQcGF0cxc8Uu2nCpLe6qKBZ0qwsEll/Nci5LiAn62B7M4avwENduf3soVOTritN5icZ7Jvcb+cozk1Uj4oIHOtFRxwij20ALkyvzNw1dc14FHEMqSmYkG4ONHobLPcl+UQOn8VVMvA2oartzz8E+/PLvirZERbw2ExSyNuUsjV8dkrA5Ajg/nIPuGkdKSCocxGssNS1iaOYOEcX3Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=YjnFmVRHDs222kZEwa4GZhPlUPzdcatFGZwVKM3UH1Y=;
 b=aIEJI9uCEee88f8BU0RUGu7nWdd4BSPP0LFdsbBZ9ib94UrfDpsqSzuQea2A/2vQ+KNZf61BLe3m8v3vd7wG453WyzYz/3oSPC89IyluEnDBlHleBqFaiZyQScRUKzWO7YkH565z2vDjDa2mCwtysSVVjarxPk+vwpsOSMf5By/C1UY1SZUw3zH+hthoFvKkaYWh9eo4pCnVBicrf8DVYRTL3pH6rF1h362uuXGWd3D+lJ+mK2GBxD49luzoB28vqU4lCYSYP68BH/IZrQr6w8jokg+RdEwaWcn4EE1S4SURejyK3YOHVtdQkRc9JKvXksfCa6Wr7xHbL3yS/JYsRw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from DM6PR12MB3834.namprd12.prod.outlook.com (2603:10b6:5:14a::12)
 by DM5PR12MB1659.namprd12.prod.outlook.com (2603:10b6:4:11::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3477.25; Wed, 28 Oct
 2020 18:53:42 +0000
Received: from DM6PR12MB3834.namprd12.prod.outlook.com
 ([fe80::cdbe:f274:ad65:9a78]) by DM6PR12MB3834.namprd12.prod.outlook.com
 ([fe80::cdbe:f274:ad65:9a78%7]) with mapi id 15.20.3499.027; Wed, 28 Oct 2020
 18:53:42 +0000
From: Jason Gunthorpe <jgg@nvidia.com>
To: <linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, "Tom
 Lendacky" <thomas.lendacky@amd.com>
CC: Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Borislav Petkov <bp@alien8.de>, Brijesh Singh <brijesh.singh@amd.com>,
	Jonathan Corbet <corbet@lwn.net>, Dmitry Vyukov <dvyukov@google.com>, "Dave
 Young" <dyoung@redhat.com>, Alexander Potapenko <glider@google.com>,
	<kasan-dev@googlegroups.com>, Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>,
	<kvm@vger.kernel.org>, <linux-arch@vger.kernel.org>,
	<linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>,
	<linux-efi@vger.kernel.org>, Andy Lutomirski <luto@kernel.org>, Larry Woodman
	<lwoodman@redhat.com>, Matt Fleming <matt@codeblueprint.co.uk>, Ingo Molnar
	<mingo@kernel.org>, "Michael S. Tsirkin" <mst@redhat.com>, Paolo Bonzini
	<pbonzini@redhat.com>, Peter Zijlstra <peterz@infradead.org>, Rik van Riel
	<riel@redhat.com>, =?utf-8?b?UmFkaW0gS3LEjW3DocWZ?= <rkrcmar@redhat.com>,
	Thomas Gleixner <tglx@linutronix.de>, Toshimitsu Kani <toshi.kani@hpe.com>
Subject: [PATCH rc] mm: always have io_remap_pfn_range() set pgprot_decrypted()
Date: Wed, 28 Oct 2020 15:53:40 -0300
Message-ID: <0-v1-025d64bdf6c4+e-amd_sme_fix_jgg@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: MN2PR11CA0021.namprd11.prod.outlook.com
 (2603:10b6:208:23b::26) To DM6PR12MB3834.namprd12.prod.outlook.com
 (2603:10b6:5:14a::12)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from mlx.ziepe.ca (156.34.48.30) by MN2PR11CA0021.namprd11.prod.outlook.com (2603:10b6:208:23b::26) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3499.19 via Frontend Transport; Wed, 28 Oct 2020 18:53:42 +0000
Received: from jgg by mlx with local (Exim 4.94)	(envelope-from <jgg@nvidia.com>)	id 1kXqZo-00Aqpy-KK; Wed, 28 Oct 2020 15:53:40 -0300
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nvidia.com header.s=n1 header.b=GxQ9oqbW;       arc=fail (body hash
 mismatch);       spf=pass (google.com: domain of jgg@nvidia.com designates
 216.228.121.143 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
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

The purpose of io_remap_pfn_range() is to map IO memory, such as a memory
mapped IO exposed through a PCI BAR. IO devices do not understand
encryption, so this memory must always be decrypted. Automatically call
pgprot_decrypted() as part of the generic implementation.

This fixes a bug where enabling AMD SME causes subsystems, such as RDMA,
using io_remap_pfn_range() to expose BAR pages to user space to fail. The
CPU will encrypt access to those BAR pages instead of passing unencrypted
IO directly to the device.

Places not mapping IO should use remap_pfn_range().

Cc: stable@kernel.org
Fixes: aca20d546214 ("x86/mm: Add support to make use of Secure Memory Encryption")
Signed-off-by: Jason Gunthorpe <jgg@nvidia.com>
---
 include/linux/mm.h      | 9 +++++++++
 include/linux/pgtable.h | 4 ----
 2 files changed, 9 insertions(+), 4 deletions(-)

I have a few other patches after this to remove some now-redundant pgprot_decrypted()
and to update vfio-pci to call io_remap_pfn_range()

diff --git a/include/linux/mm.h b/include/linux/mm.h
index ef360fe70aafcf..db6ae4d3fb4edc 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2759,6 +2759,15 @@ static inline vm_fault_t vmf_insert_page(struct vm_area_struct *vma,
 	return VM_FAULT_NOPAGE;
 }
 
+#ifndef io_remap_pfn_range
+static inline int io_remap_pfn_range(struct vm_area_struct *vma,
+				     unsigned long addr, unsigned long pfn,
+				     unsigned long size, pgprot_t prot)
+{
+	return remap_pfn_range(vma, addr, pfn, size, pgprot_decrypted(prot));
+}
+#endif
+
 static inline vm_fault_t vmf_error(int err)
 {
 	if (err == -ENOMEM)
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index 38c33eabea8942..71125a4676c4a6 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1427,10 +1427,6 @@ typedef unsigned int pgtbl_mod_mask;
 
 #endif /* !__ASSEMBLY__ */
 
-#ifndef io_remap_pfn_range
-#define io_remap_pfn_range remap_pfn_range
-#endif
-
 #ifndef has_transparent_hugepage
 #ifdef CONFIG_TRANSPARENT_HUGEPAGE
 #define has_transparent_hugepage() 1
-- 
2.28.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0-v1-025d64bdf6c4%2Be-amd_sme_fix_jgg%40nvidia.com.
