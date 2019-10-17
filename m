Return-Path: <kasan-dev+bncBDQ27FVWWUFRBBEGT7WQKGQEYQWLENI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 306CBDA30E
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 03:25:26 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 204sf569301yba.23
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 18:25:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571275525; cv=pass;
        d=google.com; s=arc-20160816;
        b=GlKSuuduVdXnSGRYZ+LaySpIN3IV4w6EmSbMpZM1mMBJCyDDqx96MNeGyuTjKBNTN2
         ySfH4AToePu32TsBb3a04zXS8czLYhUubHkb1W4Xo7Ut6BfjAC93MmKo0tSMmLj8l/kc
         w/MCYZk63gBH4bM9X5KABqHv7ZWHFDqFU8/OuvuQodQTxER8AqomVNxGtlSJjKb3iu7z
         aonWcQg4RiYqOjzRaCbIIvIcT4hdSgvmmH9PmJ+EWNVjh2C+nWZQXQup1WprT8doUJmV
         Q5R4mE9wbt7Hcs4Fsbd0KkFYV06zWUxf2kFx3ylSjYc0SwFe8XdUPvZESpcNfC8eMXfW
         bLGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=g4kBUbaK5lWGKS9AcWq1FjM65N0PPjbkU1jya/NCRXg=;
        b=Dti/5g7N61e1C4TfTa8fNDV1NS9V/6XsjtWHDn3eT+6xBczHrFawARYI67wSCYyhlu
         FilWUnO6DqP/RztMl+Da9NUjYkYeBkvq5nmDJGtncjg/KhgHiS3ZL/Oxuk+YvySppRce
         KD3oCKE+fBkXmHbHi+x4X/qgxwdP/VTjLcqhr+tyMLIyG/m3nLr+rGiAgjMTeHT8iTZm
         dYKAn2MIu/K7CJNu15WmDNOKpJ63aQ5/4oX4A3ycQifn3EEtr68yiOlROAjT8Dk2tsjH
         tufPTW81nav6J8Th/W12hgF+l0ewDQQSHE7w4WPSe0XOoQFoPZDlwOGz28l0Ayc9zZkY
         OjKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=m1ApeOEB;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g4kBUbaK5lWGKS9AcWq1FjM65N0PPjbkU1jya/NCRXg=;
        b=BnAOMZJTdrYyGolG17R8tMPQns64Pm1oAgaWDYi/RxbPoMVOmLIslQDWU+OBeiyQBP
         nbcKG8uRqw2I48D1APdriYwKlZXy1PJzev3fzcra39DIYFiNXO2egkpZEiKy1DxiHVAr
         rRSk6smDIrV5h20re2ltsiSmlqH3QQ+DQYkhlIEd/zzMbn/WzRPG0SM4vAYSDn9u/zws
         F6v4XD8pKpMHAEa6UEQngxd1DKmEnXh8+bh4bMOJqunxN+1ahMPCX+ivNDL7JHLCYNud
         TSF4RCEPxwdON+9YinpOM8wiNEk5EQts0K4wGF4MNygyX1kTmSe/f1mK3ZuphhzyWRAO
         cTUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g4kBUbaK5lWGKS9AcWq1FjM65N0PPjbkU1jya/NCRXg=;
        b=I4N1vW5MZ3yH2yYtxm/GAO9ahd2RSgKpw3c2CSU5hApFFZzZYS+8/aJxV5KvsKOofO
         occvHDY6vQMGUpQivG134np3hdoFPtHhqpyQ19nj1MSVzoVaQxBWq1JYznYkmCwYJ6Vm
         R5lJ6XX6I3/nzUuEO8mcm6Hh7A899XIE/3alEe/naFkmpClj/sLY3F6HBXSjKMBRvC/m
         +N3OMcVcBvQw1XHm6lRINn458fwqGmXADU6HOkfyWuQvhV6Ytmi1W/NT2jXCGIQBfaTg
         9al/hVepdC8guNTLO2mjW97rRTx2vuEWH+YG5CCmuzKnBv5nmzwZYckQz9jde6bJA2pN
         QnWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVlVVOSKvehlJ0FdzZdOj+81beaouumi3lNiF2n+ii94ViOn08p
	IRJmubs1Oa4pEd/KgegGgmU=
X-Google-Smtp-Source: APXvYqz+jK7Jo55bor5vtvjpIiILoyOjovgfa/9bLE77+rz8kx2VGiz2G/nSZEj4f7/TiCLrVfZ9Jw==
X-Received: by 2002:a81:4320:: with SMTP id q32mr943276ywa.464.1571275525152;
        Wed, 16 Oct 2019 18:25:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8410:: with SMTP id u16ls89715ybk.0.gmail; Wed, 16 Oct
 2019 18:25:24 -0700 (PDT)
X-Received: by 2002:a25:ad0e:: with SMTP id y14mr470400ybi.429.1571275524674;
        Wed, 16 Oct 2019 18:25:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571275524; cv=none;
        d=google.com; s=arc-20160816;
        b=AYAJRIoPfuKCE6Z64ymdnTDPqCnrukJKmHq4OrOYLVZSA4FS08uM/x8ZS6YmC287Z6
         FsL7j2Vkqizi9LdiERBih4x0zGu6GRYXKTc6yoCf05BVRVg/IH2Uj9KyyVGVEb1TQWJs
         1sAVZwcP8O9iKDSX0MHkAiiHXHI3PF8TGlHl87D/uQlT+qgMS5aszmoQeF/P1pTjQThA
         WMvHpmqNw48aeriVOluQx9Husdp/GWXaY7YZmDEgqRXo7D1PQui4lOvGiLme1jM1S8NV
         iaFKLHjJbxCPXiTmM+8nckKXCyqbJksMlnpT0AMiIlG1KxKC9692HaIn5pjsps1epGRw
         yPAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=whmCcgz4VjZeRv6SREyqmZaNFMJpz8TJQeqtX9KJOOU=;
        b=dMsWAj3JkIeOgXm+o6oL38lUEKSe9/ZRinR3yV8la5Mznhv8lxgvvCJPyeEVDOxj/r
         Jq5jQhubSlMmHSzn5NhUtnVqlGEannqO209J5YMkNEII8rLwFHec6b5dGg08caL+V0YO
         1oa9coJ+sYu00B0i4JwdWTQ3ME+cT7HFhZocn5UH42INdhB/6EcZkr5JGbqugjdx1LzH
         rYvAyKBMalkyC+nVHjvVnEy65M0EpuNIfTG8EI/oPux9pXwOguflACCBbNfJwBMLw3pV
         uyjeDfV6+VcFZfVqoIF0S8icHvW2uxkyMT06pvTAeErVYZ1SVZb6SwOLrBYKdVnS1qcw
         +NlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=m1ApeOEB;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id p140si27194ywg.4.2019.10.16.18.25.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 18:25:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id w8so290781plq.5
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 18:25:24 -0700 (PDT)
X-Received: by 2002:a17:902:9a88:: with SMTP id w8mr1250860plp.129.1571275523512;
        Wed, 16 Oct 2019 18:25:23 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id 14sm340879pfn.21.2019.10.16.18.25.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2019 18:25:22 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v9 2/5] kasan: add test for vmalloc
Date: Thu, 17 Oct 2019 12:25:03 +1100
Message-Id: <20191017012506.28503-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191017012506.28503-1-dja@axtens.net>
References: <20191017012506.28503-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=m1ApeOEB;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as
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

Test kasan vmalloc support by adding a new test to the module.

Signed-off-by: Daniel Axtens <dja@axtens.net>

--

v5: split out per Christophe Leroy
---
 lib/test_kasan.c | 26 ++++++++++++++++++++++++++
 1 file changed, 26 insertions(+)

diff --git lib/test_kasan.c lib/test_kasan.c
index 49cc4d570a40..328d33beae36 100644
--- lib/test_kasan.c
+++ lib/test_kasan.c
@@ -19,6 +19,7 @@
 #include <linux/string.h>
 #include <linux/uaccess.h>
 #include <linux/io.h>
+#include <linux/vmalloc.h>
 
 #include <asm/page.h>
 
@@ -748,6 +749,30 @@ static noinline void __init kmalloc_double_kzfree(void)
 	kzfree(ptr);
 }
 
+#ifdef CONFIG_KASAN_VMALLOC
+static noinline void __init vmalloc_oob(void)
+{
+	void *area;
+
+	pr_info("vmalloc out-of-bounds\n");
+
+	/*
+	 * We have to be careful not to hit the guard page.
+	 * The MMU will catch that and crash us.
+	 */
+	area = vmalloc(3000);
+	if (!area) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	((volatile char *)area)[3100];
+	vfree(area);
+}
+#else
+static void __init vmalloc_oob(void) {}
+#endif
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -793,6 +818,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_strings();
 	kasan_bitops();
 	kmalloc_double_kzfree();
+	vmalloc_oob();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017012506.28503-3-dja%40axtens.net.
