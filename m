Return-Path: <kasan-dev+bncBCMMDDFSWYCBBNUE5XCAMGQEEJKGNFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 05002B22884
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:31:36 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b08d73cc8csf151999841cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:31:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005495; cv=pass;
        d=google.com; s=arc-20240605;
        b=A0HYiyOqC2wj43Sso6zRYx9TjvE3U95QmqwA2DbQie+WVlIAqBuID9iknkxw30ptGU
         9SigPtenTKiGkppNwe07QXowAoglW0bRbjQN5ASO/Wvl5k6gvb0TcjHCzkUZSbcXH/th
         bmptjFQjLaUFFJvdFFdw0RCidSo0+sO2qCBejGgo+R+qotRUvWyFlUdWfeW/5Vdd6hFd
         VKWmYoBlFUTxc6AJXq339lNkGTJqBKidAhvIg596K3sWTt2DvoLXyAktQ00DOhbZfbae
         nMDERI/c/TYR0dQWTd2YlHxxVkyYM0CLD2LjJhpk8DRRFCdRtKXrDYSwCyw9Il8S4mEJ
         lkPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KW89EOi1oCwEmmQ2uGJ5QSiTX67grnZX5DmBTlEyQQU=;
        fh=znZH7AsqH+0/KjbgqYGNHb4zZvByVeRxHRYnpJhbOGc=;
        b=ILTMBiMPhzRove+e/qIesB1kfvhvtdUf11O/fo1cAIXsdwLetLJ78PHE25/Z7TUKGb
         q5EHeZP85jpLkscnstT2snPoD1AOmr6UVJs3tdEAeKYcX5Ffdr+TzgFkQLQBbr39zm4y
         7oLftramWtyHbpfgoZxlHNESoTayT7ASf3qVp3Ta9jcSuUXSRFtv7jJkf3Z8tTcUEMH0
         P5055VjAxrkF9XiNR+wydmQ9i4IkXrb5XrOMZ+jcuACIQ3CITlSvCg4dHTUUnaf0y3Qx
         r79iYPAEJwan2FKBqtMDidHqSZ7V8wFJhVAtynWbXgs5MpDOw1zgVpoYsKTIuMRTG2lj
         cOAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=N3t2UaKe;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005495; x=1755610295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KW89EOi1oCwEmmQ2uGJ5QSiTX67grnZX5DmBTlEyQQU=;
        b=lG95yaEQf7MK3HS/cFJJkOyl4cqhWQfda6C/a2fq/uMZXMWJ5jR5aJOWgIBOYMywNc
         Wod5HwJ4l1Kjiw/JA5dMzXP7oHygTKlawn/tal+pyp8wc8euLZy0tUozxta+2JQI4AXP
         09K72JNNndTPx4uJhxx2Hviw0f+/+zvzPPK84tt5ji1m2gI4EWZbR50l/EtR+F5eL7Ho
         ATFYAemlMuN+KWG4DfFaXmf1l8yM1lwIQ23YSAKD02IVV17QycsMMWFK7rFBl3/tacV0
         s7b2I+3j0N+YllIix3SXMfNIn6wr42UH+3Dlr9TwCVLJ9FvJob9KUb4rpfPJMCQ9Ln8X
         5DLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005495; x=1755610295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KW89EOi1oCwEmmQ2uGJ5QSiTX67grnZX5DmBTlEyQQU=;
        b=LrVX98QCv1kGWmaoUkc5mGw6ANglbvxNQH3pwFpVXWrIxjZNcwUODdC++fZNoXz2Y+
         PyS1QRftt/IWi2vh8G5BZMhGIhH6GKwbiQA0aeALQMPnlqYRvr6WfXP2SfHZ812VN//T
         /MNf57ymj+JPcNtCI3UQB8YhrnGyfENTrNhbGg/hM5tKzX1efvrVz6gsr1I0ugXcZsAa
         d8N6qf/mnOhp8p1Oec+m+woWzFtU8pCDT1bqtv0nAL5Gv3gQfQNz8p+AQ5jce7FRHBpp
         ixzAmQIYWvnzMzten3MXfvgCAmWAWM0lmMrgSfutSlZRS14N3O9XN7uMn3pLnf4iSR/B
         xhGQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUS/P9DCE0Gl117ta2HysV/N0DBp5Xgmgo2zb7fVfDFm/tbuCyy4gyzBfK9K/ZIrwqszM2X6w==@lfdr.de
X-Gm-Message-State: AOJu0YwYMCV/rQbnsWelJLVguSfg6UYXRsT7pTmRrBq4Bc2i34eKvZf1
	lfAJCxiGDUfVYORXBNP/DKAPSEWuLaYQ+OdxJcmbeIbkKXVlHMf8+MIE
X-Google-Smtp-Source: AGHT+IEAVLt5AJDoezIG3IfJI7+Hso4l4k5Xps4J8EdpMunqg1QWE4ODzOp0KtveZ29JiMdX1BQnug==
X-Received: by 2002:ac8:594d:0:b0:4ab:5929:21f7 with SMTP id d75a77b69052e-4b0ecbe7628mr42035431cf.21.1755005494425;
        Tue, 12 Aug 2025 06:31:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfNgjKfwdRqtIfLSnJ/R1dEcKtugXzvxTKz2dx/yVbnuQ==
Received: by 2002:a05:622a:178c:b0:4b0:7b07:8987 with SMTP id
 d75a77b69052e-4b0a06ee47bls95540631cf.2.-pod-prod-02-us; Tue, 12 Aug 2025
 06:31:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/ac96vMOcETIryVQSqm3maMYjKw77oz26U/NucO8DvBifYBo65nW4fMQO0V07CmMWllnZr33DNx4=@googlegroups.com
X-Received: by 2002:a05:622a:2605:b0:4b0:38b2:380a with SMTP id d75a77b69052e-4b0ecba9dcfmr53399191cf.11.1755005493042;
        Tue, 12 Aug 2025 06:31:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005493; cv=none;
        d=google.com; s=arc-20240605;
        b=UtGfIFBnlhwskCob/4AaRMdCgTCMTsi4jK4XSeeMi+BIjC4cxqwCSW0HpXdtlHtmop
         9vK/5dmmI+nhdhIb62wjFEeia02VuDTtRz73EF4oQnlXLTtm65KYUftVSmBn5O9EDcH4
         0wZMTgZB0izurkf6r2llvNvLteRfZJcdUdbkpjja4xpr6C/P8tjR2uvySHiINtR7lAc0
         KSz/G32VwnlePaArM9Wm1AVNnPAG5e/gwfjeCzTlqLn93aA6j/+6rolyqrGvDWfI1q66
         5KFhP9xv3lKxmCjQA+blEiSJ1t+lFTUN8S5oHnRyB+d1xThzlA1GiZfKPcm0evpVMXiN
         Rchg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UaXh7Xddpcfv0yQ5STl7x2etaL4f9n7dStroyuuwHaY=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=dCfptzgRMqC/6cjecFasAGK/QU0ULrZ5+i1l4aTMU5ZE8A7bgdro6HjDMYL0kwb3X4
         zFqoHxwGZrOko5J/UsQ/2I4vauprWbqlepXjLq+dL1iLKg8z8ez6WTVIaL3H3Ha0ztcZ
         rB7onPHSJgpAmskrLr3GoTOffLQWeivy2ihWqdsc70MrxQhiowQ1d+u8cF/kX9XZQUmm
         sR0rr1P8uGeGcy6HPjBOUeMG3Iq92T6jOQFERE2lFvZarHzMfrFsFpidbP0RyBiitb09
         AK6cPBqEQgauTfia7h7dGOOiL+GS2YYcdT5PnHpgJ2Et57PUlwgFene4C0vfU7WQm6Ls
         3oag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=N3t2UaKe;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b0c5d1f85esi3136411cf.2.2025.08.12.06.31.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:31:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: VjfUE1XkT2W8WHooeUuDCA==
X-CSE-MsgGUID: ZDqrTFifRHqJ/E4/5/L5zg==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60904129"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60904129"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:31:32 -0700
X-CSE-ConnectionGUID: +neUmvM8S5Otg3Vc0KnEog==
X-CSE-MsgGUID: oyi06oYNTk2MyPzECSScWQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165832138"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:31:09 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: nathan@kernel.org,
	arnd@arndb.de,
	broonie@kernel.org,
	Liam.Howlett@oracle.com,
	urezki@gmail.com,
	will@kernel.org,
	kaleshsingh@google.com,
	rppt@kernel.org,
	leitao@debian.org,
	coxu@redhat.com,
	surenb@google.com,
	akpm@linux-foundation.org,
	luto@kernel.org,
	jpoimboe@kernel.org,
	changyuanl@google.com,
	hpa@zytor.com,
	dvyukov@google.com,
	kas@kernel.org,
	corbet@lwn.net,
	vincenzo.frascino@arm.com,
	smostafa@google.com,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	andreyknvl@gmail.com,
	alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	jan.kiszka@siemens.com,
	jbohac@suse.cz,
	dan.j.williams@intel.com,
	joel.granados@kernel.org,
	baohua@kernel.org,
	kevin.brodsky@arm.com,
	nicolas.schier@linux.dev,
	pcc@google.com,
	andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org,
	bp@alien8.de,
	ada.coupriediaz@arm.com,
	xin@zytor.com,
	pankaj.gupta@amd.com,
	vbabka@suse.cz,
	glider@google.com,
	jgross@suse.com,
	kees@kernel.org,
	jhubbard@nvidia.com,
	joey.gouly@arm.com,
	ardb@kernel.org,
	thuth@redhat.com,
	pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	maciej.wieczor-retman@intel.com,
	lorenzo.stoakes@oracle.com,
	jason.andryuk@amd.com,
	david@redhat.com,
	graf@amazon.com,
	wangkefeng.wang@huawei.com,
	ziy@nvidia.com,
	mark.rutland@arm.com,
	dave.hansen@linux.intel.com,
	samuel.holland@sifive.com,
	kbingham@kernel.org,
	trintaeoitogc@gmail.com,
	scott@os.amperecomputing.com,
	justinstitt@google.com,
	kuan-ying.lee@canonical.com,
	maz@kernel.org,
	tglx@linutronix.de,
	samitolvanen@google.com,
	mhocko@suse.com,
	nunodasneves@linux.microsoft.com,
	brgerst@gmail.com,
	willy@infradead.org,
	ubizjak@gmail.com,
	peterz@infradead.org,
	mingo@redhat.com,
	sohil.mehta@intel.com
Cc: linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org,
	llvm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v4 17/18] mm: Unpoison vms[area] addresses with a common tag
Date: Tue, 12 Aug 2025 15:23:53 +0200
Message-ID: <fd65b0ec35f52c6bc714ff333241b828ff74604d.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=N3t2UaKe;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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
KASAN mode. It can be explained in the following points:

	1. There can be more than one virtual memory chunk.
	2. Chunk's base address has a tag.
	3. The base address points at the first chunk and thus inherits
	   the tag of the first chunk.
	4. The subsequent chunks will be accessed with the tag from the
	   first chunk.
	5. Thus, the subsequent chunks need to have their tag set to
	   match that of the first chunk.

Unpoison all vms[]->addr memory and pointers with the same tag to
resolve the mismatch.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Move tagging the vms[]->addr to this new patch and leave refactoring
  there.
- Comment the fix to provide some context.

 mm/kasan/shadow.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index b41f74d68916..ee2488371784 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -646,13 +646,21 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
 	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
 }
 
+/*
+ * A tag mismatch happens when calculating per-cpu chunk addresses, because
+ * they all inherit the tag from vms[0]->addr, even when nr_vms is bigger
+ * than 1. This is a problem because all the vms[]->addr come from separate
+ * allocations and have different tags so while the calculated address is
+ * correct the tag isn't.
+ */
 void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
 {
 	int area;
 
 	for (area = 0 ; area < nr_vms ; area++) {
 		kasan_poison(vms[area]->addr, vms[area]->size,
-			     arch_kasan_get_tag(vms[area]->addr), false);
+			     arch_kasan_get_tag(vms[0]->addr), false);
+		arch_kasan_set_tag(vms[area]->addr, arch_kasan_get_tag(vms[0]->addr));
 	}
 }
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fd65b0ec35f52c6bc714ff333241b828ff74604d.1755004923.git.maciej.wieczor-retman%40intel.com.
