Return-Path: <kasan-dev+bncBCMMDDFSWYCBBEMQWPCQMGQEWN7OOPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FB50B34BFB
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:31:16 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3e6754b0ec1sf137660155ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:31:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153875; cv=pass;
        d=google.com; s=arc-20240605;
        b=QnygmVsylNZ3IZBEOBwuQXaYyQ2lSNLoOcBPbwoWXo+uhNcnsg+wTUR97iyVnTeots
         Ov5k5e8Kbo9ZhKZr17NcQSAyeGnarmYdf0gQ51LbOxSK2dk+ReuGqRLZoXjIWC66A65R
         +9U/3XnP1ccg21QpuMhRVv5ByebgYdXkj5xPFBj0hEq95AGUWksp54mRslR7YZkxffAb
         rI/Ni7u9izdDWGINlakQqzW+2dmHeAW0unf1yOvlyZWex4lWS6NoLyA49qLaog7ZTTT6
         agmhcUSznPtq+M0c6W/8yYIgZMlgvPsJG8Qb593hrHc248FD2utU0jdoC4+CdU4OkKLM
         cFJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=w1OVjiCCCyomln5R8nEYhKUfB4fmAb+KUWnAJ6Jn1co=;
        fh=Vt0lH47XGiK7vHPEIBAZ+qmYBitkGTOU8RDO0ya8k9o=;
        b=afDcqBwxNhLuD1scGlLChxskoBS3onnkADydHyYQrBZzBfsqyLBbfBqghLOfADTSD+
         7wf6/T1vfTbpPFMIVyROZbXc+VcIbFU4MPSVeBHGaY9Fa0Rhz95XNV9b1N5Zb9fgF2Wq
         WfXemNyTWH0wXol4VFQBPMp6czSh3zly42a+O5/8EqzszZVIBSCSWxlVrgbWUzGCL0e+
         88I5MLevrwFdY98Odl3EYaJ3a0pRFW41tdQX6TdmDBTHjCLuxSBzQzFGAyZTlvWAB8hj
         6NQvo2GfYFa1F3X7Qr7smqyD2mvVRuWkXDGKh7G5g66rXPAfegECNDm3FAVMXwkigkQH
         94ww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="D/ljeTl7";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153875; x=1756758675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w1OVjiCCCyomln5R8nEYhKUfB4fmAb+KUWnAJ6Jn1co=;
        b=KUhqKRPtUBOHaT2K19/+n6OPsdv7+JimvoB40jMO2QKyfIml003yUSSVmWKmWrocyx
         fZJTL7D6yAVso0VMBheoTOS5bDnja5Umt0FrF25/DpY4fvfx+LzvdWqBj1g5N/QL9WZV
         iC5Qz3jv7cz/NIVB6b8QjyXqd72H5gH+29BPbGQOg8eQJKyhWBp89hzq6VcYj0pwMbLs
         LOHIHu9yg3PK1+unKWOmukVRKIJ6Q4vT60lx3NFOsUiznW2inU2ofIoFteghV8EbH+mc
         TlaSIn7UYX7t48+fI86gsDn75MM6Q0POZN2LflK3tBT+mqpU3AmnVIFeufaJcPO8GOBq
         hUgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153875; x=1756758675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w1OVjiCCCyomln5R8nEYhKUfB4fmAb+KUWnAJ6Jn1co=;
        b=XSywsCZ/6qQDfJiP4C7A9M0cnxLUDRqG69XhJoVYOrM+Tumk+5GIAj+DcUu0l8bxvt
         ThYO/ncc0ht1dy07/+VNt95PZhN+C3gOyoDemKAT/UCEqqdzLKRYxe4wxpOqJdrUSD6y
         2ZvgVsKop6nx/iIJDTeXsjLBAdKYm/41vcLBYHe4gSK/SdE2dRC8PzaPI3mxUH7h88F6
         jvtNmiAH2EAYcaFfUIIxnletnu8aPWwYcjEGKKij5t++XjN3UZJc0gu1NQsgvCHOX8Ri
         d7DgEdXzJlN+wFnr9cWGm0kk+8RmZPE9Q+zWzcaWhR9S0A7NaQZWYWgflZ303sKOtapS
         jfDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVcF6iHHx+FWV5kBKxVKRSRIKLKkYJqUZSfmD3zj0L6VFODkTGT0PYpBwDwlKPS5VT0Tc0Jog==@lfdr.de
X-Gm-Message-State: AOJu0YwgLT2jdqm2UkJb0bNPZTb+F+BBbTf1UjRh9lGdw05pwQZnVxMf
	NOpxtshqpTVgkUAf60MJJVDbxt9N8e9sgqIRmm3Xx+nDRt1CXpIonlxp
X-Google-Smtp-Source: AGHT+IEoeMUwJq64UfehVRxLFmtTW3lr6uzftTs7VJXD8TYzJsn7gEHbaTm/5JienI36T2Qd3/7siQ==
X-Received: by 2002:a05:6e02:1aaf:b0:3ec:ab8:9b43 with SMTP id e9e14a558f8ab-3ec0ab89d8cmr71195615ab.7.1756153873879;
        Mon, 25 Aug 2025 13:31:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcE8Pen5TK0dPfY7f2b0/ae/DpQ8WvCILf5oSFsvxRj1g==
Received: by 2002:a05:6e02:4811:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3e6835fdcfals50047795ab.2.-pod-prod-02-us; Mon, 25 Aug 2025
 13:31:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXY3b9hkREFucD1pboqSZCKPGibHlS5WHrb3iaz2YbIOP3Ia21N1iYCgDdGrCFsz+o+ccgwIghs5y0=@googlegroups.com
X-Received: by 2002:a05:6602:2c13:b0:886:eac3:d5d with SMTP id ca18e2360f4ac-886eac30eb2mr206394239f.2.1756153873051;
        Mon, 25 Aug 2025 13:31:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153873; cv=none;
        d=google.com; s=arc-20240605;
        b=dsJchRh/AD5uyrFZNKpe+oJJADPZMgGwQ+05bgXWGd77koIYfbvLJRzeMzyadRMrjx
         SLzVgTBDNNfs8zH92L6bcr86D0V/zc0TehpG47QVonK9xFFoAxTyN+t2PUAgf4xRraMg
         JL1mdt4oLevPOylel4Lw0LYOEWZlz1HRUX5SuSTC4oVqFBlViMUQRiU4glNgMWNOhYjS
         MNWyQLVS0lx4HtI8Hosf5ketsFCT14+5kXWPn3fRzrSThGt2A5BqN9ypovUwdZY/gDf0
         K8U3U7nA6PQg32aViZd7JoF4G6rkRabb0H00GJ4UoR0ZLm9Dycrgnh9S5AvjXK4FvcC8
         chrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qByZNR5hO3dUXGXI9QaSwPLK/rlDhrexMNx3Hyo52Qk=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=gvc0BAx7/BDP9fa2sjKgvIPXUHXywPOFFvq3KBl/tA77Xu+PA+0wUQvifWlhdPeiKF
         E56TyoXp6ypJsTtm6f5/QBVSbLyC/DUq1e5obJwO5sQgG8hiP03Pp1aCwLHGJ6RZ485E
         cJDtycljJSWJVSqAkwI5P/IZp9nbQrvg2vn8DAAMuM+0Eu+WoDAjrj/c3y7Z6wXdmzDA
         AqV1BQjnrCEZjFfc8A8sJ9MtMnZIAPgAkfojxbjW4R6JAXVutTSVG0YBVEofdCPgyeAw
         V9lJdGD8/J+hYqjZP+UcCXetyoRUh2ihLOgRNTos3RO6msiRKPF7pRaGOWca3p1QoXmj
         9dHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="D/ljeTl7";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-886c8f8b80esi35916639f.3.2025.08.25.13.31.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:31:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: R/pcdKnHRgmUgfXtrtNQ3A==
X-CSE-MsgGUID: /MlBp+V9QgWi7/LEuURXfw==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68971079"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68971079"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:31:11 -0700
X-CSE-ConnectionGUID: MQA+TzInQqevwz5W19OOTw==
X-CSE-MsgGUID: GAgjeP88RDmDgTZRoDSocQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780957"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:30:49 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: sohil.mehta@intel.com,
	baohua@kernel.org,
	david@redhat.com,
	kbingham@kernel.org,
	weixugc@google.com,
	Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com,
	kas@kernel.org,
	mark.rutland@arm.com,
	trintaeoitogc@gmail.com,
	axelrasmussen@google.com,
	yuanchu@google.com,
	joey.gouly@arm.com,
	samitolvanen@google.com,
	joel.granados@kernel.org,
	graf@amazon.com,
	vincenzo.frascino@arm.com,
	kees@kernel.org,
	ardb@kernel.org,
	thiago.bauermann@linaro.org,
	glider@google.com,
	thuth@redhat.com,
	kuan-ying.lee@canonical.com,
	pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com,
	vbabka@suse.cz,
	kaleshsingh@google.com,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	alexander.shishkin@linux.intel.com,
	samuel.holland@sifive.com,
	dave.hansen@linux.intel.com,
	corbet@lwn.net,
	xin@zytor.com,
	dvyukov@google.com,
	tglx@linutronix.de,
	scott@os.amperecomputing.com,
	jason.andryuk@amd.com,
	morbo@google.com,
	nathan@kernel.org,
	lorenzo.stoakes@oracle.com,
	mingo@redhat.com,
	brgerst@gmail.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	luto@kernel.org,
	jgross@suse.com,
	jpoimboe@kernel.org,
	urezki@gmail.com,
	mhocko@suse.com,
	ada.coupriediaz@arm.com,
	hpa@zytor.com,
	maciej.wieczor-retman@intel.com,
	leitao@debian.org,
	peterz@infradead.org,
	wangkefeng.wang@huawei.com,
	surenb@google.com,
	ziy@nvidia.com,
	smostafa@google.com,
	ryabinin.a.a@gmail.com,
	ubizjak@gmail.com,
	jbohac@suse.cz,
	broonie@kernel.org,
	akpm@linux-foundation.org,
	guoweikang.kernel@gmail.com,
	rppt@kernel.org,
	pcc@google.com,
	jan.kiszka@siemens.com,
	nicolas.schier@linux.dev,
	will@kernel.org,
	andreyknvl@gmail.com,
	jhubbard@nvidia.com,
	bp@alien8.de
Cc: x86@kernel.org,
	linux-doc@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v5 16/19] kasan: x86: Logical bit shift for kasan_mem_to_shadow
Date: Mon, 25 Aug 2025 22:24:41 +0200
Message-ID: <169510f5490cba60916b144398543a489c31e2c1.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="D/ljeTl7";       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

While generally tag-based KASAN adopts an arithemitc bit shift to
convert a memory address to a shadow memory address, it doesn't work for
all cases on x86. Testing different shadow memory offsets proved that
either 4 or 5 level paging didn't work correctly or inline mode ran into
issues. Thus the best working scheme is the logical bit shift and
non-canonical shadow offset that x86 uses for generic KASAN, of course
adjusted for the increased granularity from 8 to 16 bytes.

Add an arch specific implementation of kasan_mem_to_shadow() that uses
the logical bit shift.

The non-canonical hook tries to calculate whether an address came from
kasan_mem_to_shadow(). First it checks whether this address fits into
the legal set of values possible to output from the mem to shadow
function.

Tie both generic and tag-based x86 KASAN modes to the address range
check associated with generic KASAN.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Add this patch to the series.

 arch/x86/include/asm/kasan.h | 8 ++++++++
 mm/kasan/report.c            | 5 +++--
 2 files changed, 11 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 5bf38bb836e1..f3e34a9754d2 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -53,6 +53,14 @@
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
+static inline void *__kasan_mem_to_shadow(const void *addr)
+{
+	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
+		+ KASAN_SHADOW_OFFSET;
+}
+
+#define kasan_mem_to_shadow(addr)	__kasan_mem_to_shadow(addr)
+
 #define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
 #define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
 #define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 9e830639e1b2..ee440ed1ecd3 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -648,13 +648,14 @@ void kasan_non_canonical_hook(unsigned long addr)
 	const char *bug_type;
 
 	/*
-	 * For Generic KASAN, kasan_mem_to_shadow() uses the logical right shift
+	 * For Generic KASAN and Software Tag-Based mode on the x86
+	 * architecture, kasan_mem_to_shadow() uses the logical right shift
 	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values (on
 	 * both x86 and arm64). Thus, the possible shadow addresses (even for
 	 * bogus pointers) belong to a single contiguous region that is the
 	 * result of kasan_mem_to_shadow() applied to the whole address space.
 	 */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) || IS_ENABLED(CONFIG_X86_64)) {
 		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0UL)) ||
 		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0UL)))
 			return;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/169510f5490cba60916b144398543a489c31e2c1.1756151769.git.maciej.wieczor-retman%40intel.com.
