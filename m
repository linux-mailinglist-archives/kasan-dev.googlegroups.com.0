Return-Path: <kasan-dev+bncBAABBHOVY33QKGQEQXJRDMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-f184.google.com (mail-oi1-f184.google.com [209.85.167.184])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A00F204A8C
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 09:09:19 +0200 (CEST)
Received: by mail-oi1-f184.google.com with SMTP id a17sf9638823oid.19
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 00:09:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592896158; cv=pass;
        d=google.com; s=arc-20160816;
        b=B6L3PHMR+OAAfGFFX3KvG5oRVcYDdc+t7j8NUVyxWoLcS6tvLujCf+B1Ngehm/byKS
         THGvymbQ+ix1aLYkLjIydRtp1l/bkhclndM59hcHqwjt+CFKtOe+u0UgFsr12dGedLxK
         mkGBLpl9wIsDLidUYzCybyxBUPx/Tyqx83Qc2ObryG9nRjQwMA8AEZ0q7XTd0P/OmN/F
         fWMVlBdK5sPAwmO/K5lOkAdnJBogIhNuNsaCGJ5csTphPVsnv5e6i30Da7fwvUcmio7N
         IggF9+sZ5Fv1G1CgmsJjGyuPlDyT37ILW3HNoQV5HDrh6KAmhoxrmY0i0z9ObpDxs+bX
         S+/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:mime-version:message-id:date
         :subject:cc:to:from;
        bh=lu3vmVTcnpCvvZtRJknfczIztYkOjAEB4NkDLH28wAM=;
        b=EAdB7yq6rwigmOGN1QIJsaZprccWJiK6F2iDISAiNpvB+xn4Yx0Bs7OPAZROdyoPXo
         AWHzX6b9x9M6RgU3QjG2cDdQGlF93gC08mWqwal6YF4sDZRhYqvnJjJX8uN46xKQM9dE
         lNxHdtZO5qZk3STvymbjPJeaEYsH3yNLq7K8Q/4eGUDFFwRwrXKeqSDn+qL4H3XGyFNs
         HV+GvzYjW9xbxNg1JcRRoQzPOempab3Rtl4e92gez5WHI0kzTdTbamGuth9Qqdw0Al/5
         Itt/zSd1W6HWif/zOrI4lOv6gdo9XB9S1F9k2f+WIgMnb+2o08aW+OsSZCKor3E8rvYk
         tWzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=KWgMqyKu;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :sender:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lu3vmVTcnpCvvZtRJknfczIztYkOjAEB4NkDLH28wAM=;
        b=BqbG6sVXIfKfB4hjZzeB8CIzUN/hsPHJXmASSWGYZ4lLGVuyRX0rQQdmMI1YF3an2c
         UyoDgnG7GH4xVte2jF4+JNYrYesUVoHUeKUD9UlvwG/AQkC9q02Ql2fpSYHnZrKs4u5z
         A53pWG0naE1ugVpSEV+iyYanwr/XMd2KYYj0na99Eb3R5dX3jbp28GCtdLuRoH+J4Whx
         AcvSzbA/GpuOSGnR9aJ9FGxN+ISZYDuMOxwZKOmyyzLFxef7jvDP0GGRFKzdx/+zxg9/
         sxVQw+NJN+WNHf4YsDAU9Yug8PzvkoQ1gomiY0y81YSMEMKqjNdQgnWe0O5Yss/JPo3Z
         vo1A==
X-Gm-Message-State: AOAM531+O0L11iZWUjfFUKF8VLAcAf+kX8cl3UBJn0Haw+kwzHbcJQCH
	xFi0CvSFnOyUwz031UOVT+Y=
X-Google-Smtp-Source: ABdhPJziB13UGDGTmOHHLiUmmSzH/CFo1DPPDirwuSpmpFB1NI++BnDepcOWAXGsj28D2BIqv4M5Tw==
X-Received: by 2002:a9d:f63:: with SMTP id 90mr16680862ott.159.1592896157888;
        Tue, 23 Jun 2020 00:09:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:370c:: with SMTP id r12ls313352oor.11.gmail; Tue, 23 Jun
 2020 00:09:17 -0700 (PDT)
X-Received: by 2002:a4a:b34b:: with SMTP id n11mr17616844ooo.41.1592896157638;
        Tue, 23 Jun 2020 00:09:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592896157; cv=none;
        d=google.com; s=arc-20160816;
        b=OeYOvNDHxIWisxYbCCRQHpa+0c93SrlYEdUCUTjven5+GAfbPkv3s+iHeYeyj7eNPq
         Dyje5jwIM9CFnH5+tiySIf6LmM9GmZlFnK/VHoZwm4SCG9zyRyouDGJlysyexqY9tnVA
         TqPqAcHgyAtgqlHETk1nspY9ZUx3jlT883+zng3BAWqpETd51xGb5LHwHrV+i8fQIt3o
         4hGyG8HUzyUyIVAh2DIB28OKOdleBVSfBahO+z477Geas5JdBPsbFz+oiO5DHzk7+t9u
         XAcIJkObwz/8wT0TN5q6OsNg3k3lBuQV4LwuLOPkBn1FlUzxKNrYaF0wynYf/wrgfUEC
         7hJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:content-transfer-encoding:mime-version:message-id:date
         :subject:cc:to:from:dkim-signature;
        bh=BEzvUu7HEyJ1F0G9oxSdGmOWyNtabOkN4vT0Gxd3ZDs=;
        b=wq66HMLgeRRkiKH6RnNL5jPht+uvNixOljaHtSkQjS1VR1F+mZWGMcmCBJv85wrkdP
         nx0vFN9lR9JgGD6drIJfAOGxGLTu8Mr4wYdQHdBCIxevQvEjZzDUFrWWw2ksHZ/dC63F
         AoEVdz1JrZpKJQPVSnqxWcOy1dAx90Xm3nlmNu2LWdDnQw978KVrLWDInVLlNG3gREti
         1QRhEST94kDn8qCphJjB0QA2drlUcauuH2CxS29N92i245cXTt3KazBhyR4DqqDuKAvj
         EEq5xxltl4IZT5ethtT422aCxMNf9IcPfqFB5Ha02B5CwzXN9+Dg5EepwO6BEYlnoG44
         a6cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=KWgMqyKu;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c22si1404777oto.3.2020.06.23.00.09.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Jun 2020 00:09:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail.kernel.org (unknown [95.90.213.197])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7EB142083B;
	Tue, 23 Jun 2020 07:09:16 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.93)
	(envelope-from <mchehab@kernel.org>)
	id 1jnd3Q-003qib-Tq; Tue, 23 Jun 2020 09:09:12 +0200
From: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>
Cc: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	Ram Pai <linuxram@us.ibm.com>,
	linux-mm@kvack.org,
	"James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
	Eric Dumazet <edumazet@google.com>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	linux-ia64@vger.kernel.org,
	Shuah Khan <shuah@kernel.org>,
	Tony Luck <tony.luck@intel.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Sandipan Das <sandipan@linux.ibm.com>,
	Fenghua Yu <fenghua.yu@intel.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Christoph Hellwig <hch@lst.de>,
	iommu@lists.linux-foundation.org,
	Alexey Gladkov <gladkov.alexey@gmail.com>,
	linux-fsdevel@vger.kernel.org,
	Bjorn Helgaas <bhelgaas@google.com>,
	Sukadev Bhattiprolu <sukadev@linux.ibm.com>,
	linux-pci@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Akira Shimahara <akira215corp@gmail.com>,
	Ingo Molnar <mingo@redhat.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Will Deacon <will@kernel.org>,
	Dave Hansen <dave.hansen@intel.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Kees Cook <keescook@chromium.org>,
	"David S. Miller" <davem@davemloft.net>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Jan Kara <jack@suse.cz>,
	x86@kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-media@vger.kernel.org,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Gerald Schaefer <gerald.schaefer@de.ibm.com>,
	netdev@vger.kernel.org,
	Jeff Layton <jlayton@kernel.org>,
	Paul Mackerras <paulus@samba.org>,
	linux-parisc@vger.kernel.org,
	Haren Myneni <haren@linux.ibm.com>,
	Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Mike Kravetz <mike.kravetz@oracle.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Borislav Petkov <bp@alien8.de>,
	Alexey Dobriyan <adobriyan@gmail.com>,
	Thiago Jung Bauermann <bauerman@linux.ibm.com>,
	Russell King <linux@armlinux.org.uk>,
	Jakub Kicinski <kuba@kernel.org>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Helge Deller <deller@gmx.de>
Subject: [PATCH v2 00/15] Documentation fixes
Date: Tue, 23 Jun 2020 09:08:56 +0200
Message-Id: <cover.1592895969.git.mchehab+huawei@kernel.org>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Sender: Mauro Carvalho Chehab <mchehab@kernel.org>
X-Original-Sender: mchehab+huawei@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=KWgMqyKu;       spf=pass
 (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=mchehab@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi Jon,

As requested, this is a rebase of a previous series posted on Jan, 15.

Since then, several patches got merged via other trees or became
obsolete. There were also 2 patches before that fits better at the
ReST conversion patchset. So, I'll be sending it on another patch
series together with the remaining ReST conversions.

I also added reviews/acks received.

So, the series reduced from 29 to 15 patches.

Let's hope b4 would be able to properly handle this one.

Regards,
Mauro

Mauro Carvalho Chehab (15):
  mm: vmalloc.c: remove a kernel-doc annotation from a removed parameter
  net: dev: add a missing kernel-doc annotation
  net: netdevice.h: add a description for napi_defer_hard_irqs
  scripts/kernel-doc: parse __ETHTOOL_DECLARE_LINK_MODE_MASK
  net: pylink.h: add kernel-doc descriptions for new fields at
    phylink_config
  scripts/kernel-doc: handle function pointer prototypes
  fs: fs.h: fix a kernel-doc parameter description
  kcsan: fix a kernel-doc warning
  selftests/vm/keys: fix a broken reference at protection_keys.c
  docs: hugetlbpage.rst: fix some warnings
  docs: powerpc: fix some issues at vas-api.rst
  docs: driver-model: remove a duplicated markup at driver.rst
  docs: ABI: fix a typo when pointing to w1-generic.rst
  docs: fix references for DMA*.txt files
  docs: fs: proc.rst: convert a new chapter to ReST

 .../ABI/testing/sysfs-driver-w1_therm         |  2 +-
 Documentation/PCI/pci.rst                     |  6 +--
 Documentation/admin-guide/mm/hugetlbpage.rst  | 23 +++++++---
 Documentation/block/biodoc.rst                |  2 +-
 Documentation/bus-virt-phys-mapping.txt       |  2 +-
 Documentation/core-api/dma-api.rst            |  6 +--
 Documentation/core-api/dma-isa-lpc.rst        |  2 +-
 .../driver-api/driver-model/driver.rst        |  2 -
 Documentation/driver-api/usb/dma.rst          |  6 +--
 Documentation/filesystems/proc.rst            | 44 +++++++++----------
 Documentation/powerpc/vas-api.rst             | 23 +++++++---
 .../translations/ko_KR/memory-barriers.txt    |  6 +--
 arch/ia64/hp/common/sba_iommu.c               | 12 ++---
 arch/parisc/kernel/pci-dma.c                  |  2 +-
 arch/x86/include/asm/dma-mapping.h            |  4 +-
 arch/x86/kernel/amd_gart_64.c                 |  2 +-
 drivers/parisc/sba_iommu.c                    | 14 +++---
 include/linux/dma-mapping.h                   |  2 +-
 include/linux/fs.h                            |  2 +-
 include/linux/kcsan-checks.h                  | 10 +++--
 include/linux/netdevice.h                     |  2 +
 include/linux/phylink.h                       |  4 ++
 include/media/videobuf-dma-sg.h               |  2 +-
 kernel/dma/debug.c                            |  2 +-
 mm/vmalloc.c                                  |  1 -
 net/core/dev.c                                |  1 +
 scripts/kernel-doc                            |  7 +++
 tools/testing/selftests/vm/protection_keys.c  |  2 +-
 28 files changed, 114 insertions(+), 79 deletions(-)

-- 
2.26.2


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1592895969.git.mchehab%2Bhuawei%40kernel.org.
