Return-Path: <kasan-dev+bncBDQ27FVWWUFRBPVMVSDAMGQEUGJAOHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id C6EE03AAFB5
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 11:30:39 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id c15-20020ae9e20f0000b02903aafa8c83e7sf644635qkc.21
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 02:30:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623922238; cv=pass;
        d=google.com; s=arc-20160816;
        b=nkDZDui3V9MWPvqMYOgvWNO7VtypbfhrOGqUzHWz5NkYYRdd+VBAcwozCi/kCs8nCd
         kWELkOWQxPS129ySpx6hKIMk2GrX/OOZzDaH8r11BlAcyd8MCQaUCZQblDjd3dPCAMWx
         tynRQQreSwWjEbCUgFpd2SAZB98g8RDXk/ffU9GWITeTokyn8UoKe5xLopWNPTwRBFz0
         bOQrK95nubITj6ynFFAmHK8ASi7veoxoF/NmgufafGKkBtO7oqd0kayG9sjZ1dSheaec
         9/L1d9COhCz4gyzCIzsOOJzjaNv4QZ7Tg3vFvfsl6uIidl4PfDqI/IzBE/x+s4YPkNwH
         fMDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=XcvezamTBNQg/CTonmXpAYQsEVfLddGaJ7afsDo30cM=;
        b=pcExvR7pKJ02Qn2kPaFZmh8ugZ2vdKkEjGjC0GffhVtJvk0qS9zDlfpngjKYHAlnHN
         GBWSFZkggVmDfMeEO8rQhPMoTizo3Crx6lBO4yDFB4gX0T1kApSfBCYjaL4BlD1NAGE7
         Ip62rQSDY3w+PKSSImSe6p8oZY5tXedzWELuY1nIWo8HBIctK59eMqcZ0BgUPnJCZ+fp
         VJn0vfjHgaeegq6mrGWe8itaQaPha3+j0zhS2t7iUTSsnO1RyXi1I8pw3fwxEFNx18Qb
         9Lp+vBdf5mRLfxI9QyHAoiLkMb12XC5Y12/og3eGT8YfB2vTPfD1GMsXmVRzeS3h8tT7
         AzIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=pyG2ezEo;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XcvezamTBNQg/CTonmXpAYQsEVfLddGaJ7afsDo30cM=;
        b=n8yrGzHsX1Ct3fcjjQg6hBl9JUA/C/9sNSRJeLx6etA9DQBvHtfwxzw++u3HlkWWNk
         OZ/eWgHDpbYYdy0GH3OrsDihX3wLYxYlUgqNQjxkie8LQlHKOEAGPL/lb11NfT1DCNzl
         1h0UmQKxYyPdBGMPJlO0b/k+S+tyVkLL3i4+4ZHxeDK2KlLdc6nJ6W0MV6b759ERKTHg
         ONhc2FHG1YjNgwiVHkINtpAHOD14rNe01/Pyz9MQSOIAE+BaI0VZ6XaCYImmY1xCyVQH
         +GcMYZq7zVI4jgU+JXVWb7bu7fdgJmd5koQXWLUBz1DzKyQEyd2LrPBQuau5FtMBCuq5
         0iwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XcvezamTBNQg/CTonmXpAYQsEVfLddGaJ7afsDo30cM=;
        b=I1Lw37qwjUY3rfBjfl2J93jrT5A7BDS0OatWwzP+epMh7atPcUYDhfMHbcFwtzFauv
         E58Z3eqMtAzLJwsO225hJXngc8ORRYSw5pOZXzEsH8qn8nWqiDOmmwW3pBVRg6pvvPVS
         EgZIInnb7j0rghdYXEaz1VHEmgsJb4XskVthO23tet7IGULh30TE9CO5T+Zb0cFqoRve
         IbXas/ygA1Ih3fFZ2bTxgch+lN8u/KYjCIL2BA8yLBUPRVM7eLLYaEiCoG/jr7soJRb2
         aBgM9XRgWErg2vT60Yu2jFFrXPAFoF65EgKE5VcyjrvFCnzJ2qCojhsdr5hWmUdgIe2B
         bjUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533bkIAeX+Z8nvM839S3t9YgC3/r8vm+4MoEiNp1dhho15h5EW98
	dPNFU25Dfs/tgPWkiZ6+LwY=
X-Google-Smtp-Source: ABdhPJwF0S7PaYigHnAr7oc7BIBuz3etij0nGiwkvV007FTnibZpk6Rc7uqK4EaGUQckwn4dAV06Sg==
X-Received: by 2002:a05:622a:c1:: with SMTP id p1mr4185140qtw.13.1623922238784;
        Thu, 17 Jun 2021 02:30:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4049:: with SMTP id i9ls3672253qko.5.gmail; Thu, 17
 Jun 2021 02:30:38 -0700 (PDT)
X-Received: by 2002:a05:620a:2221:: with SMTP id n1mr2708619qkh.317.1623922238328;
        Thu, 17 Jun 2021 02:30:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623922238; cv=none;
        d=google.com; s=arc-20160816;
        b=p3EseQTQrQX2Zc1PNHk2hFJjpa5lw1zZWChvwjLtzt2XPjiBmmMrXQ2tEQOT+P1kNR
         INB+AuWX18tmwzINfyZ+bCjZYE08Dc0xMLzCau/HLE9lAQ2/JyTlAKlz/wdTPKoG7NsQ
         3QalziyNEhLnjqG1aG2X9ooRcFBeXTD62aPgrjLOx1HVDexTCEhTarD4li8umIB1Rulx
         gjKekyPPbc34i7OAYP0S9gmAyxgQeHN2+80Iwcj9jRvgZKVjh1twP1nrPRHlgQdaWmky
         sz34EpePDJuYlJPlk5D2bkeFiOPDTsBVrilLMf+boHCHdoyEmpagm1S5QD6OlmYcoCaV
         qWIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=SYbkYhz8dgvzCxm2xx3ltQCVLS/WASlN9bfsoiUbbWc=;
        b=lwuc1muE6pM61vYef7jehXUiLpKLYfy+CpwJv33lkw83A/CKRY4v7xzEbziwGEeKOR
         9pkA+3QqWbsMpiUqgoar2WIXmP9OosHLCL1G65bc4fWgQU4QlhfavTX4znZsMTlVX2QD
         KtAYhjRx9dOZH3lT+sKD4dqdBTIZMF+19HUyOwwhlhznzFJdmtSJpKaaxIoEZvYD5rrF
         TwpvSc/t+q9K14lnVGqEv3+Ms7uGqN+cguFup+kfiftkRABST9BEorC++Q0EWjgS3cRo
         kbXid62jCErd4VDULYwiRNhUClD68+b9UmNCgllTGguDoCHRtySAal2qUBBsnQ0Ci1Es
         FYJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=pyG2ezEo;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id j16si203070qko.3.2021.06.17.02.30.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 02:30:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id e20so4524486pgg.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 02:30:38 -0700 (PDT)
X-Received: by 2002:a62:b502:0:b029:2ec:a539:e29b with SMTP id y2-20020a62b5020000b02902eca539e29bmr4319275pfe.37.1623922237921;
        Thu, 17 Jun 2021 02:30:37 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id fs10sm7733847pjb.31.2021.06.17.02.30.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 02:30:37 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	elver@google.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v15 0/4] KASAN core changes for ppc64 radix KASAN
Date: Thu, 17 Jun 2021 19:30:28 +1000
Message-Id: <20210617093032.103097-1-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=pyG2ezEo;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU. I've been
trying this for a while, but we keep having collisions between the
kasan code in the mm tree and the code I want to put in to the ppc
tree.

This series just contains the kasan core changes that we need. These
can go in via the mm tree. I will then propose the powerpc changes for
a later cycle. (The most recent RFC for the powerpc changes is in the
v12 series at
https://lore.kernel.org/linux-mm/20210615014705.2234866-1-dja@axtens.net/
)

v15 applies to next-20210611. There should be no noticeable changes to
other platforms.

Changes since v14: Included a bunch of Reviewed-by:s, thanks
Christophe and Marco. Cleaned up the build time error #ifdefs, thanks
Christophe.

Changes since v13: move the MAX_PTR_PER_* definitions out of kasan and
into pgtable.h. Add a build time error to hopefully prevent any
confusion about when the new hook is applicable. Thanks Marco and
Christophe.

Changes since v12: respond to Marco's review comments - clean up the
help for ARCH_DISABLE_KASAN_INLINE, and add an arch readiness check to
the new granule poisioning function. Thanks Marco.

Daniel Axtens (4):
  kasan: allow an architecture to disable inline instrumentation
  kasan: allow architectures to provide an outline readiness check
  mm: define default MAX_PTRS_PER_* in include/pgtable.h
  kasan: use MAX_PTRS_PER_* for early shadow tables

 arch/s390/include/asm/pgtable.h     |  2 --
 include/asm-generic/pgtable-nop4d.h |  1 -
 include/linux/kasan.h               |  6 +++---
 include/linux/pgtable.h             | 22 ++++++++++++++++++++++
 lib/Kconfig.kasan                   | 14 ++++++++++++++
 mm/kasan/common.c                   |  4 ++++
 mm/kasan/generic.c                  |  3 +++
 mm/kasan/init.c                     |  6 +++---
 mm/kasan/kasan.h                    |  6 ++++++
 mm/kasan/shadow.c                   |  8 ++++++++
 10 files changed, 63 insertions(+), 9 deletions(-)

-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617093032.103097-1-dja%40axtens.net.
