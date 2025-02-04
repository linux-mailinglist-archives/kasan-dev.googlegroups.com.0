Return-Path: <kasan-dev+bncBCMMDDFSWYCBBQ5ARG6QMGQEJOOKX3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DA090A278A1
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:37:08 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6e42459ad81sf29271916d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:37:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690627; cv=pass;
        d=google.com; s=arc-20240605;
        b=XYLKl3HyZyCkkcF5H46bE3eM+QcMet2hdNHe6QhkIUxCe+ce4i4xOsNewufu9kxCy0
         TD6Q6EzPvgTG4fVXx880hxJM3gwXZMy9o1BTvYoTvu6YpkxaOvn7dsYu1y9UE+af7mL/
         KnuMLZKWC6oN/T4U4JZ8oNB4rfd4atPXj/s3OAlvgW4G0GCGGpseeQbsEueQAMG2ki/L
         RMbi+jN/IQvjVzfLAe7/yY82X3jBLHFjkSPYCflSiIxPX6MxLxs6LDOQXdpViaqPwG+A
         rDWCi8DQE8eDOzd8xxiLuatac0ytRT1ACABSONY2j/ClS6u7sCedKYsMfIqFy3pbkGIR
         UjXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7gfsSkj8Le6pQLqFhduQl1L7KNywbufRlFmAUkmnJ+A=;
        fh=g/Fe7pivz2oGz4ClOe8Dyh0xIRmIKsfckLe0RKWiv2o=;
        b=TGVDMI8yJGA4aRJQ69f/jzV8tdR86Nb5xqHrHZiAiZczV14KOVLuS1Jl0ZMnYe7EpB
         K36upFaV5oQTH4JGD5kmQKhLzrU2eO+Gi+ujK0Mu0GsZEaMYQ1YEdWXyRPW93OBCcf1a
         XXbK2+eEms5BkSFXLD91In9XHSxKPHjqSnrdoawx/y/xs8DzLjBVqVupZ16yMT5bc4i5
         2sFbbQgHK4lkCMhmchWHXocq0JM0Oe/VCHy202BxxZ90WPMuElkQ+XUqu0wnZD9uZsuW
         NSJDC57m5lbGa7GEcLeVA/ageOoiqP6yC96qWkOlHAnNlN7lxJ2E39aVrdGTA4wqY08j
         jalQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=A9DnbX4Z;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690627; x=1739295427; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7gfsSkj8Le6pQLqFhduQl1L7KNywbufRlFmAUkmnJ+A=;
        b=cnIZi5NwwWvxia71XyIsMlFoc3VigR9ycOT3ODmo053PO8PbyAHTisz1TfJcmiqRZE
         7Cnn5y/dH5DLTqm2I7ToLmdZvKX+EObFL6a8P1RhN58KsxVCiS8ZeuE7SMrC7LHo+H1O
         hoVTaHfp4G6nvYWDsiyGUaLK9IBWGHh+ArC41ti5Q1AcwJ2WzD7SvyB46g10brkuMXEW
         VTDPaXfJioDDaIrp/DuVHO6HE7x5mVnuOBPRP+SJui/eOqJHuiJ/kkCDQqpif+LTGP6Q
         DXav2p+t5B7lA5WmexBoKj5vEiDxBRQpq04tdoQPKPNiIiM0AojDRpfHnPfh38Nw2u3u
         3uWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690627; x=1739295427;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7gfsSkj8Le6pQLqFhduQl1L7KNywbufRlFmAUkmnJ+A=;
        b=lSa+hchz9XSVYyUHlIYvsYLwt7dguxoVLH5LnSiUdQBUdcwLmlFqwEnlE85JhId8k3
         /vqvfc9CA4hP/Ja+bvjBuKS+dfIuStL0XgfJjBRJM3Pl5CZerjN89g8vUcS39LtOLY7M
         RZJ9gHjDwzBmuAIglz240GLk9ki2QOdoB92L53krXM5OUdb3HXrNEczLEWGKXp7biUdX
         E7RbLGvsLfiqIGmcLdO553QbfFBiD8j8V0uxpKXoru02+8tMf5Y2U6ctWDdYzUmv8hLj
         /nOAHzMBgIPHydB7VxVHxAXWXM+fyvcSJrWBhOrw8igJdYIORWCz24A2Olg0x5f2/vqm
         PL+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVHa+/uu1c9/s7TR1V4qcIzIanfnQDerXQCa0Miv4ehOf5RA6ZXshF3bu4GO9EdyFM5d7T2GA==@lfdr.de
X-Gm-Message-State: AOJu0YyPKS4lyJKaPx8AMLQiUHD6qw1lQi6kQMSljsscFGoReR7bbR1Y
	tocpZhKNeLJ+NLdSUeFakBAcNmkRifkS4dxYcAajkxegrFpg9vT6
X-Google-Smtp-Source: AGHT+IGWAyKaWc8xNwBznuJvVBbxXz1pxBwGItI1SKKefP+yPSmadwZ+Q0sCcmggYV+yIYM/EPOgrg==
X-Received: by 2002:a05:6214:5d87:b0:6d4:142d:8119 with SMTP id 6a1803df08f44-6e243c7859dmr415213476d6.42.1738690627535;
        Tue, 04 Feb 2025 09:37:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e38d:0:b0:6d9:1375:552e with SMTP id 6a1803df08f44-6e422802b02ls22547476d6.0.-pod-prod-06-us;
 Tue, 04 Feb 2025 09:37:06 -0800 (PST)
X-Received: by 2002:a05:6214:3007:b0:6d8:e5f4:b969 with SMTP id 6a1803df08f44-6e243bb7e81mr437472186d6.10.1738690626761;
        Tue, 04 Feb 2025 09:37:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690626; cv=none;
        d=google.com; s=arc-20240605;
        b=htSUybKPPZ9P1tthe45K71zXAC2o/lki7s/PYz1Atq6iT9Ml3zRRsvXSXLVgUC9Dx3
         zIqVNjnEOhlMq8Kzdk0gKrZ5ogkoSrtAjtS/DKjpffEa/biuCYkESlHjii+bSFEb9a54
         /1DtI11sBmqPMwMJlu4cJ8FPJlcZi5wiSI+N5dA+3Qmw2C8qOFF5g8K5v8/1iWGm16JP
         jHPBaOFm+j81xWJiF/pH8OkxdkfeUX3WswdNdHFAq4St2/y9ClCcVsT7CR2P7CwrFFaS
         JOg0JB4nufs+rKYfFDtApL/Py+nzixI/1GPU0r5Sa/pCEJ/0OMIczJ/pGKqLzLgAbe7l
         sBCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9cP48FhwOS/LMk0h6akqBPktUCXlskOxYu2pQkbZsrI=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=NWK2kUoFICKUFpOGMzuE7gLV1m+damUJWfAbd4kmJXd8ZVj8AWk1otwyRYZgkFmOQ+
         fGJ2J5pe4KPV2hni/DDyfcu5BoZOIMI7jAm5U4lyc/pdCNVvAcKsB6evi24s3FUbp8Y8
         9tNrAGWzjTfAH3PRAahT/eHHXZr8GwZKf+zjuKy5Ew2LcM1HaMbTGIda0hKfRyyG4cs2
         IL0/33aHclZp+HdKCvDs0bDFvx8zut+FiBmmXfIabQG5YvgFEFLKpeNTzda3JL+2UQOJ
         q1BpStLq5b4nqvncfO58TTnhHKHeTMX7e9fgFKFQvXR7mxywDM0yC/CaXEsJDY8JiuHj
         SJpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=A9DnbX4Z;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6e2543da95asi5388936d6.1.2025.02.04.09.37.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:37:06 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: aplJgUKZTz2pAhEuqp5z7A==
X-CSE-MsgGUID: OpTmEiOJS0ui3hEEgvzP3A==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38931038"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38931038"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:37:04 -0800
X-CSE-ConnectionGUID: F7WrZE34TJC30qp8xAUvrQ==
X-CSE-MsgGUID: 1Ko21FfoQgSOsBU65eanYQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866985"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:36:51 -0800
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
Subject: [PATCH 12/15] x86: Minimal SLAB alignment
Date: Tue,  4 Feb 2025 18:33:53 +0100
Message-ID: <162610a0af3e04e2f42872401461b1d62ec78fbd.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=A9DnbX4Z;       spf=pass
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

Adjust x86 minimal SLAB alignment to match KASAN granularity size. In
tag-based mode the size changes to 16 bytes so the value needs to be 4.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/include/asm/kasan.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 8829337a75fa..f7a8d3763615 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -36,6 +36,8 @@
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
+#define ARCH_SLAB_MINALIGN (1ULL << KASAN_GRANULE_SHIFT)
+
 #define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
 #define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
 #define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/162610a0af3e04e2f42872401461b1d62ec78fbd.1738686764.git.maciej.wieczor-retman%40intel.com.
