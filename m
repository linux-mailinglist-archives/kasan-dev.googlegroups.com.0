Return-Path: <kasan-dev+bncBCMMDDFSWYCBBO4QWPCQMGQENCVCAAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 69CC2B34C05
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:31:57 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-61bd4dcf6b8sf1048882eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:31:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153916; cv=pass;
        d=google.com; s=arc-20240605;
        b=GP7uKSHMn0DzK3zoRG2pYDoJlDSEtFnE7MbRw7VCUMuxPNoJ+Zqor7rW5HluCUinys
         hELih/adoR3WD6tKEOgpaWIRytej02szcenXVraViNsabXSpbaroeKdFb/ydXdnIowiw
         7HxXQD1J7w+7IMJCWE/VC3JDdcOANxS4et1gO5L3tZTc7mXPMNmtyZZUYxIUfOokbtg6
         jaSFRcsdl89ztK8RSelsSjc6WBAiEuOPnhO8h79PNuYDHhT0y5rBlIOjbMEY1CAxFne0
         bBx8nISqq7y/5xeBr2RWdrwKBGY0y4dwyrjdrbiiaFXIljPbqlMTP+jeLvP4sREjO6/O
         5K4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8KklOzo4GciSWSUdAR/H1oAs1hZgZpd8XvQVV8QhzbM=;
        fh=45G/jPTdP328cCN5Pxh/U2fqlU7VnGLN/xY77KeE6YE=;
        b=DObDGljIuguYVzn4laIeVyUcIvekyGeTTpoQgOsraRE6UfdV4IR9Eyi9B+8Wruz0RD
         TdLDmgKhilh9NoxTk4llBQvFzTDfYK+vvQEMb2pRDFMYTrvdzyA7HRYJIMLSVV418U4k
         +I66HmqfGF7GTy/gMfHfTSLnQ0yyCENvrSctoPEYu7EUBjLxdcFoPeTk47/1mT4GPMqr
         FvhRHW0gEZrvmAAwFcmSNjz9ney30K4IgcMxxYVpQSQF+ZRuwvsARMVu4/nNnPC4okpo
         mqjyhcOV5ANXZeRYgcwRT0OqA/4lqrhV8GGsVmeK+UxoEutvoinx1k1LHZY98HYdt1s7
         Gspg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=kDtkLOyt;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153916; x=1756758716; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8KklOzo4GciSWSUdAR/H1oAs1hZgZpd8XvQVV8QhzbM=;
        b=WlyKqe5kTBqVI+G5jc7rxFZZfORVcLNu02ekCP7DRIhSw3LHCqHE1qh+4/4euB5vhW
         0hM+jeV2PGO56kJUxQ0DkWxHeI65LS5KEgwOAL+HmEGBgzp+rfW+0LFiJrAcP6lHQNFN
         U+MZeVbN2ONMCirKgiOQOh+h3qpihV7VPjZ+hbI4zsbCVChRTZyuYnjpUHVFttYfpit6
         OeIHn7Wp0prxl/Di0kRuNnCeOcNiYRpn70RnIUXZtBeo1j/osWpN0uI98TPicvFHj92g
         C2UQFgAPwXiKB9XtUmJQoqX8kG7aZ92wbnYFJuQU2PCs743FH/E9HLx/9xiB7zaKNRwM
         78GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153916; x=1756758716;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8KklOzo4GciSWSUdAR/H1oAs1hZgZpd8XvQVV8QhzbM=;
        b=rNNByFCGXTFDTtPNU+fBLn4+TkIm3bK8crBAKvANQxGQKssAOcEQlsFkuqSmfFykXa
         tp+bAjJZRHSNqaOHH5T8vVKdl6eTFlfAgODHvYqgWsFrzficXGkfnLhr55gVffISc4T6
         WwO58XngOOWJObECRuYkO4KI9a57ZnYwF33gYOEsYTxuvoI53n5HkcXkyvO2FDh8/saU
         P35eFrXXlskv2F7JUQn3tFGDV+E0832CJKNrgwTs1xtRS+lqLjeksrl2qzKKRz/aTXAy
         QyPBWK16hBg/T6jG/HtOyCDgsnWJWsAfxM/tZjoHZWIcQ+nTqYwrkC8rOf/aJFz8K6LK
         8mzQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUlqTRLHqy162GwMQ6JmAnXRakdgYss2TIKOmuSObirj2+y7deqwHqwpSKHHG5MkmLc8b9GOA==@lfdr.de
X-Gm-Message-State: AOJu0YwxYFtFbw9Q7tU4JCal10WDKB7W0cgaCmslrz2xhgD47VF5xKLd
	l39wL7byDpVEcwTgzzUzsXw+8DyzIrmT1KUwW3Bj7rV8pzd6NeUQdzXQ
X-Google-Smtp-Source: AGHT+IHwLc18Rtpw+642e1/byNkyyYok8HEFXxmlmFtnwb2k/rFIazDKSslXhqomt0Zeg0tSCDsF8A==
X-Received: by 2002:a05:6870:a1a0:b0:315:31d7:c601 with SMTP id 586e51a60fabf-31531d7fdd1mr1528012fac.39.1756153915659;
        Mon, 25 Aug 2025 13:31:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfaVoeIKWwKjvk2zoBou3XzZ8xydMUDE51XHihJ22bkMw==
Received: by 2002:a05:6871:a312:b0:30b:bc0f:66ba with SMTP id
 586e51a60fabf-314c1da53a0ls1632189fac.0.-pod-prod-04-us; Mon, 25 Aug 2025
 13:31:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAF7KBbbPMlNE5aS+Sbq+thDj+8p7cl5LEavIznc4/fTyCy7PgcA+jG5emtNA/6hoGhrhfXsu71ew=@googlegroups.com
X-Received: by 2002:a05:6830:638a:b0:741:2506:b102 with SMTP id 46e09a7af769-745009e13e7mr6377036a34.8.1756153914174;
        Mon, 25 Aug 2025 13:31:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153914; cv=none;
        d=google.com; s=arc-20240605;
        b=kz13uAv7JNpflZvzahxpDPXIlXv0HvQdx2LWwoycqa1sVN7I5igCYmktImYc1jn59D
         oDAZgmw/80guqrL8QSQCf/fGnS7EBWrKbk47mO4U5e+uiO7jazkXsriMx+1qAbxjWzZV
         OFqqNVIvsn57DP/RtNhchfB7mYeD9WCpicKfbhkKlfDjCDDolXVfwxVaaiGAkwKht4QO
         2ko6pA5vVmAj/QvIGMsJnCgA7QrD6Mf4ZeSfgnfUJjJv1hksMXJIK5dWCMkfljRc4g7p
         HNujN6KN1AsiUz2Y58UcOKGF9kZU45i472oHTDl72fc9CaZqj9HtCNszmz7uWSpErmZ3
         7X5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UaXh7Xddpcfv0yQ5STl7x2etaL4f9n7dStroyuuwHaY=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=J9jzLreCxCnJBHlD3pcuILT7vChWnMqmm/JsepigKVPfQMY0qWERLCppqDVqlHED3Q
         jb8qGxJbUx+bj1KXSvyQ67s3+0KTkEuzOShlDMef5HKayxLTe81WNk4J0Qmi1swjgXzG
         GOjfzcf/X5IEEWJKKCNjBlklWrwNjhcGOVJwvP5F35A4kjEpDIjomUz1VtvDFx2WwEb3
         exx7VrdFfJcLlKppyYX91YVF0UiPJAHIe+hO5ocbuwXDd7Q0piuZpQ1QQJLj2btrs0PJ
         uxVwIrtII3ScpSF4WFAs47P/qFQ1lUNVqWDzYNvtrYr+s3OBgLfn1ACn/LeUvs/5vgfW
         linA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=kDtkLOyt;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7450e452104si356172a34.4.2025.08.25.13.31.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:31:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: b5y9QR/cTdmCA6yDAy0QlA==
X-CSE-MsgGUID: 2fIVQsHPRoy9k0Msy6Ec4Q==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68971199"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68971199"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:31:52 -0700
X-CSE-ConnectionGUID: Z6d3VSXbRamxE0DAKuvOBg==
X-CSE-MsgGUID: HqbNGGRlQTeuW6G+Ue7lgg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169781025"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:31:30 -0700
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
Subject: [PATCH v5 18/19] mm: Unpoison vms[area] addresses with a common tag
Date: Mon, 25 Aug 2025 22:24:43 +0200
Message-ID: <3339d11e69c9127108fe8ef80a069b7b3bb07175.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=kDtkLOyt;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3339d11e69c9127108fe8ef80a069b7b3bb07175.1756151769.git.maciej.wieczor-retman%40intel.com.
