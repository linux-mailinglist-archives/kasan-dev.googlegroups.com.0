Return-Path: <kasan-dev+bncBCXO5E6EQQFBBANRW2UQMGQEVHOHWCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EF837CB3B7
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Oct 2023 22:09:39 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1c6336be7c4sf23115ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Oct 2023 13:09:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697486978; cv=pass;
        d=google.com; s=arc-20160816;
        b=z/xD0vurMDUpzLjsat+rHEBNee4vZkPhkpGEnl+KoUafXwHI78CTfU7V6c5hwJiD9N
         cg/0VzuP9/9cuYZpN6Z1Ly5VT+EaRnMPPRTxVkOZiSezmCNWErvnyJvXF9YRenDHa8Zz
         VW3CU66caywf9/vQn0CU2Avijg0y13Dlh1uSB9BsbEGv3L9TiO166ICxcwwEcJpr8xIE
         OA+BTzJe7V9p9GJqFdi2YzxDQBom9zue0Yj6TJPxsfQ1Uk07251/vLYWO26/ZN0n4i0A
         +1TLsFYK3YV/8ZZf1OcFcAN6qyPmgzgvF594M2HSSa3cFH9oDOWkH4jKw6OdAWpCcoO0
         dTwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=nhfrrrsV0GBcArSzO//5w0LGI6y7kpDUcLHuUkE3oKc=;
        fh=se4dObbLPf77uXKpSBaA+TzURjkN2R3/UgFS9fscKcI=;
        b=TjvDPdhPP2WE2NXQZi+EQj4n8ZqH8nTk2TAsDGFnQymKv15VjSEuhBK5DcTb3HkJ3q
         XdPt6pxYR0WHQ+RllNAk7xS9pECsiTIzACQhuK5FgQNCsn8lVX+DiNEqs/h8ldSBxqwt
         XM+GC5BgT0mA4Lk40vX20ZswhodEInsDCUvd2JmeZJIwujgj99+DiGScD+LIMYfu0Gg4
         nlbNG9mHGk+54qX3XfYae2wp1h6ojmZlCHoYZAAeso6N7OQCpPwdzPUlq0lRhesMz1Lh
         jxfMWYy34qPVYIApRCgZqTFd/Y803pQWPcgP+zSKvsw3d3HGQ+FSAeSuJO0DA4Q+6gXZ
         oT4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oWcP2frN;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697486978; x=1698091778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=nhfrrrsV0GBcArSzO//5w0LGI6y7kpDUcLHuUkE3oKc=;
        b=keci8wGx7BqlckDY3eMlHgKs7j6kovUFNWvDjRQCsprk/jYSWyIPUDTNP0OB+cOqnF
         OD850ZRu3gtfAF4Vax3vmP6bizElTvZ7LI+bTEtLVLx9kgovnQ1oVo1+ZkjjVsFXu+ip
         CkSPSF2R+oyeEwwv6yW3sWqwC9ro3EmOyqHJLD7Ug5aNICClvq7JdUid6AKZ1XV75rcB
         Lq8BVLrhWQMnlkpOvkfnKPPnM9bbP7FWDtxfFRJSWKlfhzaUHaai6tpGO6xvcOnFSGM/
         MMhDao7OHir7V4xEzMEPI0jPSZx+vjxA6ht2u4v2CeZ/0kZkfrU0ZNi0umSYCfE8BSUK
         +b+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697486978; x=1698091778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=nhfrrrsV0GBcArSzO//5w0LGI6y7kpDUcLHuUkE3oKc=;
        b=Iwhm9Xo1L8Ga8c/0tXm5VvCLQc+J9yRVy8xTbEiv4JIR8vduMVTj9vrhFGq8we9M6m
         U1p5FXqRNODc23ItCormPGnfAur8l/lgH+MdOmIPaq/u+oy0uw/n/2fhO1Vwa5pciZ9+
         +Jbgp3PxhYq0gV0/vcU4Y9bH/fS7UJgBHNPQMRKSDWr56P7GPRa+SPkeL59FbO4XTDZr
         LsudnrKV4ruXjLl6hT6K0Ol6IT6MYtmW+i/pU9wr5rX1XkuXTVklM/aRFfGFlUAN7Mdl
         tIe1VNOfCuAb9ITuJ7Dqeu3coZ+tdgkMGlUACtRl1RYF++Eee07X+JykS6mZF8BDotnm
         uWRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzViHSJPDxON2h7CmfFx4XQI3zpKGL1J4x/GNI1egmguFEhtOCb
	N6m3P0pEOjl4AWX6PggBI+s=
X-Google-Smtp-Source: AGHT+IHCK2Q5LN0IeMk7xhgaW8PS+Mth+0jNGYO0hcM57eGuClzyodQcF8L25JNeGzmB7CBf4K3FvA==
X-Received: by 2002:a17:903:1c1:b0:1c9:af6a:6d0d with SMTP id e1-20020a17090301c100b001c9af6a6d0dmr42384plh.9.1697486977456;
        Mon, 16 Oct 2023 13:09:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1f14:b0:1dd:651a:720f with SMTP id
 pd20-20020a0568701f1400b001dd651a720fls4286193oab.0.-pod-prod-07-us; Mon, 16
 Oct 2023 13:09:36 -0700 (PDT)
X-Received: by 2002:a05:6870:3c8a:b0:1e9:b0be:d004 with SMTP id gl10-20020a0568703c8a00b001e9b0bed004mr162858oab.47.1697486976620;
        Mon, 16 Oct 2023 13:09:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697486976; cv=none;
        d=google.com; s=arc-20160816;
        b=bSpXDPkllDckRyoUU1YfJEP78A3lHsL9Cnb5aXyesoU7EGvslnDAt9zW2uy2Rljaic
         850m87/Wo+Wpd4C32r7MrYQRXSFmFym2TCpi6nvKRBicrDMv5s/qughAf+RgzGbeTc7S
         /OCJf3mZu/KYnIQRVcF+633UTV/eZRaFwCSQlgyKkKyw/sqpJ2SW5EE9NxN5w6GJdDl5
         fODpi4X8oFtM6rXEZJDle+m8/c1ESBtHZsRYXj6nsd8QgOEJBKZ77utOXMmKWcZMyGkV
         RtmSmzDs/tM+dqOzaD3FQeA9gbJLIUL10fsyYK2Ri+L6ug7xxzaJmRvofvNgzOWLN1rd
         M6wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Uo1ZehGmOuEfx6L9GXwB6nLGeI303wsPbYuWTFD2g2A=;
        fh=se4dObbLPf77uXKpSBaA+TzURjkN2R3/UgFS9fscKcI=;
        b=z98CwRqDdDqfd/MjCMPCX8ZIKf3FPsA1bHIICr1ec1FGo6QZ32sSdm16eQpCM7ZCMv
         U+q8PnbemdFlIeVQql/C4Xwixkx/WVzDzEJJT+W2ksk1ERtgDmVv93NeU8VhbC0Ea81j
         lBtHm/NKBu09Rc1NsHfRtFfk3K/QotkCkeLCy+I8XA2INI5tJeFj1u5YzZ3Gsk9Dh3Zv
         2tJMV+CWO+rbPEn4IGGXjCc61Le6Br9LUd1wz+IDTJ4OC+YCYimBJS+HFmOtZ8F2XJyT
         SMWbz7ZX+AYugbGEecYoFPsQ1dOnN29aZjAkd1wjG1cS8izKMpnafmqg61LmaEDooZi+
         DfAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oWcP2frN;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id lc22-20020a056871419600b001dcf3f50667si971682oab.0.2023.10.16.13.09.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Oct 2023 13:09:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E9EC060F6E;
	Mon, 16 Oct 2023 20:09:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8126CC433C8;
	Mon, 16 Oct 2023 20:09:30 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Haibo Li <haibo.li@mediatek.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [PATCH] kasan: disable kasan_non_canonical_hook() for HW tags
Date: Mon, 16 Oct 2023 22:08:38 +0200
Message-Id: <20231016200925.984439-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oWcP2frN;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

On arm64, building with CONFIG_KASAN_HW_TAGS now causes a compile-time
error:

mm/kasan/report.c: In function 'kasan_non_canonical_hook':
mm/kasan/report.c:637:20: error: 'KASAN_SHADOW_OFFSET' undeclared (first use in this function)
  637 |         if (addr < KASAN_SHADOW_OFFSET)
      |                    ^~~~~~~~~~~~~~~~~~~
mm/kasan/report.c:637:20: note: each undeclared identifier is reported only once for each function it appears in
mm/kasan/report.c:640:77: error: expected expression before ';' token
  640 |         orig_addr = (addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;

This was caused by removing the dependency on CONFIG_KASAN_INLINE that
used to prevent this from happening. Use the more specific dependency
on KASAN_SW_TAGS || KASAN_GENERIC to only ignore the function for hwasan
mode.

Fixes: 12ec6a919b0f ("kasan: print the original fault addr when access invalid shadow")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
It looks like the comment above the function needs to be adjusted
as well, and it's possible we should still provide it even for
hwasan but fix it in a different way.

I saw this a few days ago but didn't actually send the patch right away, so there
is a good chance that someone has already produced a better patch, just ignore
my report in that case.
---
 include/linux/kasan.h | 6 +++---
 mm/kasan/report.c     | 4 +++-
 2 files changed, 6 insertions(+), 4 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 485452e8cc0dc..72cb693b075b7 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -468,10 +468,10 @@ static inline void kasan_free_module_shadow(const struct vm_struct *vm) {}
 
 #endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 void kasan_non_canonical_hook(unsigned long addr);
-#else /* CONFIG_KASAN */
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 static inline void kasan_non_canonical_hook(unsigned long addr) { }
-#endif /* CONFIG_KASAN */
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 #endif /* LINUX_KASAN_H */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b738be3b6e5cc..e77facb629007 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -621,8 +621,9 @@ void kasan_report_async(void)
 }
 #endif /* CONFIG_KASAN_HW_TAGS */
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 /*
- * With CONFIG_KASAN, accesses to bogus pointers (outside the high
+ * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
  * canonical half of the address space) cause out-of-bounds shadow memory reads
  * before the actual access. For addresses in the low canonical half of the
  * address space, as well as most non-canonical addresses, that out-of-bounds
@@ -658,3 +659,4 @@ void kasan_non_canonical_hook(unsigned long addr)
 	pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
 		 orig_addr, orig_addr + KASAN_GRANULE_SIZE - 1);
 }
+#endif
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231016200925.984439-1-arnd%40kernel.org.
