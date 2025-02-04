Return-Path: <kasan-dev+bncBCMMDDFSWYCBB3E7RG6QMGQE4YR43WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CFD3A2788B
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:35:41 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-467b19b5641sf121405311cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:35:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690540; cv=pass;
        d=google.com; s=arc-20240605;
        b=iEXZuKhiIxsIfq1HOZusP9xCc82lhBXoJx/yNpfJT/NYlmmv/uwlnU+Ba5UNj6VS4f
         mZQvzLWh257dIPZpCpMZYKq3JshnlOqt/BZCAQqJ2CPfoTdpnq/OwmtyrgwzHA+6WvYa
         vhjvmXfAjvYJ1SCnfqKRlA9iqzgs5UxB+f06mrJo2Q6xrlZnYm4MBqYAwuPRMxgOhYl3
         4+snL+ry95ic7sDYDMX0gPYM6YmXBYhlkT+JnTtUFWYJBxzb3K+9utIo9zIaRSevtcZv
         6avpT0itkuqnKx/n7buSgRVhDbfuDFZzaSoR5qu5QcXMu7oj1lTHpqkRNlzDHiYPJXvO
         rDnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pZFqRoUYwlWxsWVN71MTY/pde0D71c/sHejXJwVrX1I=;
        fh=SmNrtaRkTWVdrI9HT6ZvrUDcNrFxLoF1M0XbuJ+DqcE=;
        b=Yggl4X1C3qcW8+SUd70jIrCi6KMq9NvmKz3jYI5wUrigNmX/xrI+aRzX++T2gwBW6P
         xadT186/TzvvbAuXXb5F4FxvFWzo060MksdbKXd4LtAvf3AKiGZpD0Gr6hpJSBK15XRp
         agDZecohUenSCuXi4o04pHMopG0KIbWqMPJWfshLYPVOIjpYiPOtgPQy/VxJOtW37xEt
         qfzW+CnMRpFUy/ryUaKCLd0CJnEJiYjeXl9pf7SIgDElSB38jym9Yxt0xlIxDh2jNgwX
         xSNoDrLTPGpnJuT28vxZ6sPhZFUH8jR/YhzgW8FmMVV+Ro86prpvdnZt1mIkXtAfDyh5
         yKBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=YrldGYiJ;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690540; x=1739295340; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pZFqRoUYwlWxsWVN71MTY/pde0D71c/sHejXJwVrX1I=;
        b=Q4tbZQinqbBMUx0IYeBkxM7xTL0vgpF4SJpITIh3KUid/G7hHbUo+4saaBKNisTwqE
         blKCr1PMfbvKjoiPh4wdeBPwOfOwR+c7xcbOpQlyd2WvXx1BsW98kOqMWuI28hRu3N1U
         ZSteQc909j00eWa9hhWt/hWHHpJyKjCZH0lBClbXxVKLstjCwnH4lu43PUeoiqJ3DOaw
         hRi9fon0MkFXfehYZjtIxnN6VjVH8hdU41wJuamMsfwTWbrUYu7cf6B4/D6kfsyIY1XF
         EnD1TeszH6SCUAjFmm6tmy9bxUND8Q+Ort+3SWCcEF3uFh/euWF3S6Hv2oAsLXDtqpmZ
         Nt4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690540; x=1739295340;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pZFqRoUYwlWxsWVN71MTY/pde0D71c/sHejXJwVrX1I=;
        b=f4Nv9Ly5kMRO9lJYfN+BWJqiAJ7uEjv1z1G+uBTqkg9Q/YN/EvfdC4FoXdP5c39GXK
         iBpiW20CKg7QZZUwdbgRTrea2cfzk9NVqFq9s7a0mHgj2whRjUAnndYgbv5mG2zuxDZ1
         igJ9zc3QQarNFRGEdGslqNgshcpG+1xjRa55aJmJGuFLnBeQntgMQIcdA5YH5jmCl9zA
         KhpQH3YfhZKLZ6x4KyyM1TDfdBT/svy60AdhXOmzLPxqmbd8wRoaLu9ZnkDTtl/4+HwZ
         ClnFo7+1a2cSrpVbq17MOLrO0MwapjmVU/VjCJRZD7fjyNW+diyP+LlWWYvS0ezGIe14
         3EjQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVP+kI60CEnnaNmBM90r5IQY0gDXvxtVeoOWvg20nGZ6X61c3nRdKuJ1E2BucSvBjgf6riQ5g==@lfdr.de
X-Gm-Message-State: AOJu0YyUxTdKdJoDm/f8r9DnvyDAuR57QzCGbecEer+wFr/CO/6SkoCE
	qQ9lt0KqeTCtnxzRApONcmZOgjfMvHAFXGnsy+GB4i6WiQg+zfDp
X-Google-Smtp-Source: AGHT+IFvGQxNnrw6QPSQOhAwW0e/3VSdZRSQJx/NnnNjt9JQmZlXFnUyZxKLeSem/cZmzZMp5gCd4g==
X-Received: by 2002:a05:622a:544f:b0:467:867b:ff57 with SMTP id d75a77b69052e-46fd0ba140dmr431849841cf.44.1738690540385;
        Tue, 04 Feb 2025 09:35:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6d06:0:b0:469:63f:ce11 with SMTP id d75a77b69052e-46fdce99e81ls29373211cf.0.-pod-prod-05-us;
 Tue, 04 Feb 2025 09:35:39 -0800 (PST)
X-Received: by 2002:a05:620a:178b:b0:7bd:bafc:32b0 with SMTP id af79cd13be357-7bffcda119fmr4646445285a.47.1738690539688;
        Tue, 04 Feb 2025 09:35:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690539; cv=none;
        d=google.com; s=arc-20240605;
        b=NmPxAqhrJ/cIZ78G+ykCZqwfd48J4y1qqQy5mvAkUUM1nAO17LLKXCVO9BDGaOhNiJ
         h6rf5kRUooF3o/iOvPA5qRiyw63z+yEN1yvts+33L3z6NksT69lG4Te+sh+XFfCR9IsO
         4eT2g/qwS44Pu6s+AupVNq4iIhf+56Uggy1CwbPe0uVt4bXsP9V2LqE8fWr7PPB31oE6
         /YUY1KhTvtdweNHjYHAMn9AEQACDzEuPl3S08OL9tTcmH2J0VwLtXjz3rlEn5z7nFOJd
         r/vKtOC2oQLzsDvpGjLZcy3ZrxcZAswFrn6HVlVZ5n3KDj0QfK6ztrJwUBsyYwDG1UjX
         eYfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hd/rmwwNUxEWJaueMUiOYmy433JWOqfiDFpi9akupUI=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=H+w0pMc+VxjzrFvvPdeUG3CawEK8N96c+3kwDjlqOy8j6VWSG+fU40yI+sZ8OXxJLX
         aduvA54THGZMqKEf4H3gsZofzNajy5fikT/a6h/wG61xF8A3uWv/7Us3DbiHjb1xVHtI
         G6nXiqHm3wo0zL5OvXu5Ow4uhGpeTp/Zj8kWiiShntJOly1j14aURL6ydXSMNHfyoDml
         euGOkGcEYj+QkN62ciAYKWLji5KKntQv6cAwiil2EJFYHlxUj+YSGNN7UGmiprGNkrc3
         xN6cCeniuk2JeJDjIDL9JIg6GlaGUpK1E93exi7hUnqA87eTlMsORpwxnok2yQqXreu6
         h0YA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=YrldGYiJ;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c00a7f1b62si51809985a.0.2025.02.04.09.35.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:35:39 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: AYN7jpJgT1SVop9apd8orA==
X-CSE-MsgGUID: IyZZ5crFTuu/0kjD6fF3Tg==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38930574"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38930574"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:35:38 -0800
X-CSE-ConnectionGUID: BjNSJDU0RVuIyvdxJ63vGQ==
X-CSE-MsgGUID: INVQujqZTM+d6XKry25vsA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866530"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:35:26 -0800
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
Subject: [PATCH 05/15] x86: Add arch specific kasan functions
Date: Tue,  4 Feb 2025 18:33:46 +0100
Message-ID: <911ad4b9f001bca4c274b60144b1db80eab2015f.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=YrldGYiJ;       spf=pass
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

KASAN's software tag-based mode needs multiple macros/functions to
handle tag and pointer interactions - mainly to set and retrieve tags
from the top bits of a pointer.

Mimic functions currently used by arm64 but change the tag's position to
bits [60:57] in the pointer.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/include/asm/kasan.h | 32 ++++++++++++++++++++++++++++++--
 1 file changed, 30 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index de75306b932e..8829337a75fa 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -3,6 +3,8 @@
 #define _ASM_X86_KASAN_H
 
 #include <linux/const.h>
+#include <linux/kasan-tags.h>
+#include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 #define KASAN_SHADOW_SCALE_SHIFT 3
 
@@ -24,8 +26,33 @@
 						  KASAN_SHADOW_SCALE_SHIFT)))
 
 #ifndef __ASSEMBLY__
+#include <linux/bitops.h>
+#include <linux/bitfield.h>
+#include <linux/bits.h>
+
+#define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
+#define arch_kasan_reset_tag(addr)	__tag_reset(addr)
+#define arch_kasan_get_tag(addr)	__tag_get(addr)
+
+#ifdef CONFIG_KASAN_SW_TAGS
+
+#define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
+#define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
+#define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
+#else
+#define __tag_shifted(tag)		0UL
+#define __tag_reset(addr)		(addr)
+#define __tag_get(addr)			0
+#endif /* CONFIG_KASAN_SW_TAGS */
 
 #ifdef CONFIG_KASAN
+
+static inline const void *__tag_set(const void *addr, u8 tag)
+{
+	u64 __addr = (u64)addr & ~__tag_shifted(KASAN_TAG_KERNEL);
+	return (const void *)(__addr | __tag_shifted(tag));
+}
+
 void __init kasan_early_init(void);
 void __init kasan_init(void);
 void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid);
@@ -34,8 +61,9 @@ static inline void kasan_early_init(void) { }
 static inline void kasan_init(void) { }
 static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size,
 						   int nid) { }
-#endif
 
-#endif
+#endif /* CONFIG_KASAN */
+
+#endif /* __ASSEMBLY__ */
 
 #endif
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/911ad4b9f001bca4c274b60144b1db80eab2015f.1738686764.git.maciej.wieczor-retman%40intel.com.
