Return-Path: <kasan-dev+bncBDGZVRMH6UCRBA7XR63QMGQEFDWVWEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B57F977B6E
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 10:44:53 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-718ea791e44sf2129672b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 01:44:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726217092; cv=pass;
        d=google.com; s=arc-20240605;
        b=VWX7upEuwB2rzjy5Y5fQ10n0wyj6JPDTOh1i3SVOSRHd1raV9UHMb0avoTqnsYPao0
         +j1rkWllH4B/ODVS9ajMhxKRDg8RV75qmsz1JEhmndRrGIbKjHDiU13U0P5rvCEN4as/
         sD2WDd4nXicQI516zyYQ80CJcAebttMJhKztgq3QR7Wpt25tiUt8W+POYFZ2VEc8Amir
         PvXuHa2WbpRFCqk+Z+cVlsl53zFLDZycaQ8nJlBuITY5EZj8rbtk4fqMdHhv69DL0ubO
         Q1lpkwcAyt4eGs6nxnfS6h6BCIxDA7sGWI1r2fgoXx8HpUZFDPYoRTbZgMWh6911Z9jP
         t6lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8kyVbM7fCY8rJxA3ISrvMlFelOEo3GidBmDKjJOvdDM=;
        fh=EyDtSOL+GlX1DbJ2R6E5LZA/nbv0HsmyToa7tN/jzmU=;
        b=efenJHqh/WMtezBumpIWYHq0SQuSfK1zXJ3nXwiUtztjAFEyGApynWlye0BB+Sy6kp
         jFgl71XXExc+lRGmQRd9IJxZFVgXsjvoGfyhl3uV658t3l2D9a8yrMIF/m+gXPih7t5K
         lh+mh+H2DjQpNLun1jAxZ32JUc6W9OMCP7GoodG0KQfqNlWRjwiyHgp1jyi96GKqz2ih
         UDCQzQgIbcnhHxMBjiq0K/k2Med0m44vVXD8bXiF3cr6vhkPdbcjiYmrtEt8zRuiRVng
         IMNwW0b4iSW926uUJna404/tNyVOFP8DiTTcru2fZKUsK00nQttK2uF81w/uCBCZMal3
         JGxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726217092; x=1726821892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8kyVbM7fCY8rJxA3ISrvMlFelOEo3GidBmDKjJOvdDM=;
        b=eEkLBB953ieie/bkAgmRKOOAGJevfei5hnt0nXJxo6o/7EhsXadIJk02putkJSBc9L
         ojPJT82L7e6zKXn6VMPUbnrDwhQpE79ybLy2Jnq7s7cJjbceAGWPHXqYCrdA1Q2STho7
         OpR8OsfNlpj7e4YxyQs3uuXQWks6ryP+AiHzo3XEdsPmjIUOASFUku3gxD0IQp8kR7J6
         l7uLcNcjzSSuqDdP913ag92zx5uUrl27zIUroBuhSVwsmVOVJNN/bsKvvKbNDZYL+wz1
         VllD5ADhauub64c5dc4lb7N2Uuqiwc/248fVvaiv6gLsfDFt+zuVjsWgVSQeAGpR4NI6
         FTvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726217092; x=1726821892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8kyVbM7fCY8rJxA3ISrvMlFelOEo3GidBmDKjJOvdDM=;
        b=UDwLMqjpc6DLLmmCwGeJXRb2MhZFAeU9LZRY7LccPTj0Pd5Al9/iKoh5vMsUySn6/+
         iWdR5IfWYtn8CJ34AIE5RdUS7Crnbxn5q+XMPH4XzFF6y7Q+84AY3zh5UMqned/Vpuh+
         riB9Rnqh3Z/9Xx26rFwzpctZwo9zDpdzQcyib/UykX22WVhmWp78DCoV9fKwX35s7IEL
         ESJOv0fYlLPyT1Z1GMoWZVMyhuSrRB2iTg/q+QkghMUWzfBL5PtQvymkPIcpoz5nuvB6
         yHQZgFzDlPKmLIYvOIOvp6b27KPRQ4SBz2Nhu7BVMWdzRBJKsp1pccfaQbM1OpkcIyju
         OCzg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrAljy6od02FPUv89M0Akmkw7/KfmKE1JmhDeTln1wLEytQFAfrAXA2L90qlbyhb/0UQCPtw==@lfdr.de
X-Gm-Message-State: AOJu0YwLgsuAu263a8w99tlN6HyV4gF3Y/qxMuUcg1k7Mjkpnb0A8TNB
	H8GJp7G71EHT039F/rUnO3UsN+lE15W/vcszoWwEqzQtcjTj8GZj
X-Google-Smtp-Source: AGHT+IEcZKfK6r3FofI9J/HUS/vX0OCKlsBbCw1ScWoidFptKmQh/hesEEKgPk4Py1+Vroc4Bl+qug==
X-Received: by 2002:a05:6a21:2d86:b0:1c6:fa64:e5bc with SMTP id adf61e73a8af0-1cf761f985cmr6972327637.34.1726217091764;
        Fri, 13 Sep 2024 01:44:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:17cb:b0:2cb:57a2:d478 with SMTP id
 98e67ed59e1d1-2db9f63b0cfls1174594a91.1.-pod-prod-01-us; Fri, 13 Sep 2024
 01:44:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlzOqKTvinddb+OoOWqNI4jPyZzTZI5navQVi00xpHTo7cVfOVGvkYHX6X/VIsZ/VeJgVxPF6n+3k=@googlegroups.com
X-Received: by 2002:a17:90a:4b09:b0:2d8:e19d:f8d1 with SMTP id 98e67ed59e1d1-2dba005218amr5796921a91.30.1726217090295;
        Fri, 13 Sep 2024 01:44:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726217090; cv=none;
        d=google.com; s=arc-20240605;
        b=kujOKjNuWFqbPTu6yYT6FFq1fily4ZUPezaIBeDzSbBSeFOzCVC6Gt7F47YWF7rCBY
         zHZhk6e5iGs0XVw4GmGpnNte/JMylAcJcmDduNbU7xKAZO2jG2Yu1lYgqJKI7HIV62KE
         WOXnwbBxElkl8zLb0vngHYsGONcfoo51arKt18g87gWez060sZm23ji/ycinRY6/9rlT
         2gih5DtQWlVEyg+ezAUVefD0RYg9bb6qGELBBoCnKq4/AfC129yQaKB+aLPRvwpDACgI
         eiD/2BclwV02ym5AIHRcL/Gr4H4pIhXmSsNc/4luwWhO/zHXt4yyGrx/NuQNf9wjwt7M
         ZbzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=6lpxn0RtcL6Fkqv+YkOVwAEEKQgcrbZLeJiP74sUbcE=;
        fh=hcfUAbjVo1Onr/A6btw/6+DWx1lfMgdriCz1FYQJQQM=;
        b=PtNj9aMH1va8zglC/ypK7XInwST0yM3XXEtVhRugNQZ0rbpKtFhPM0s3VdVns9ASr5
         gsEgYFk7OJPM5v7WxS+LMixy0wIps/8FD0re86JvXrL69dV7vSmoxLzz83vBw3D9BQ3G
         j5wRVF3vYhIT59yULC5YfxW6Lar2tRJWMREli1lASC4Y5gWWMrN2KkVdI/a2URP5CqEE
         LridEyeEqACCEx+5H9jLAFhTL5uWxv3T9E7mxrnfnFHpIFVLUNXEFS0t44R5JOQmwxmp
         KgoymSYKRv2maZmk2ab4zj5k/Um71u3hrRMpPXQWzUo3HenKfXcEhRb9TyQuvjQevZmo
         JExA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2db6dc9977asi567791a91.1.2024.09.13.01.44.50
        for <kasan-dev@googlegroups.com>;
        Fri, 13 Sep 2024 01:44:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 98C101477;
	Fri, 13 Sep 2024 01:45:18 -0700 (PDT)
Received: from a077893.blr.arm.com (a077893.blr.arm.com [10.162.16.84])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id D42DA3F73B;
	Fri, 13 Sep 2024 01:44:44 -0700 (PDT)
From: Anshuman Khandual <anshuman.khandual@arm.com>
To: linux-mm@kvack.org
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	x86@kernel.org,
	linux-m68k@lists.linux-m68k.org,
	linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Guo Ren <guoren@kernel.org>
Subject: [PATCH 1/7] m68k/mm: Change pmd_val()
Date: Fri, 13 Sep 2024 14:14:27 +0530
Message-Id: <20240913084433.1016256-2-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240913084433.1016256-1-anshuman.khandual@arm.com>
References: <20240913084433.1016256-1-anshuman.khandual@arm.com>
MIME-Version: 1.0
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

This changes platform's pmd_val() to access the pmd_t element directly like
other architectures rather than current pointer address based dereferencing
that prevents transition into pmdp_get().

Cc: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Guo Ren <guoren@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: linux-m68k@lists.linux-m68k.org
Cc: linux-kernel@vger.kernel.org
Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
---
 arch/m68k/include/asm/page.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/m68k/include/asm/page.h b/arch/m68k/include/asm/page.h
index 8cfb84b49975..be3f2c2a656c 100644
--- a/arch/m68k/include/asm/page.h
+++ b/arch/m68k/include/asm/page.h
@@ -19,7 +19,7 @@
  */
 #if !defined(CONFIG_MMU) || CONFIG_PGTABLE_LEVELS == 3
 typedef struct { unsigned long pmd; } pmd_t;
-#define pmd_val(x)	((&x)->pmd)
+#define pmd_val(x)	((x).pmd)
 #define __pmd(x)	((pmd_t) { (x) } )
 #endif
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240913084433.1016256-2-anshuman.khandual%40arm.com.
