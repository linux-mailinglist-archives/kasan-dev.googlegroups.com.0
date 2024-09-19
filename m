Return-Path: <kasan-dev+bncBDS6NZUJ6ILRB5FFV23QMGQEHLGW3DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A86FA97C2EB
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:56:54 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-39f56ac8d88sf5819165ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:56:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714613; cv=pass;
        d=google.com; s=arc-20240605;
        b=EK3HW8vYsKTjZ/AeT5tI4LCM3I8L0xvmBmEFXek+0G77TuwK8AF4MaDbnzbOIHFgxV
         6TZYLdP1/SVelv0M8yuumAvM3iMDBagcygpfqN7KpWlChkX+gG0QE6OX9xVEL4Pmamkv
         FP9FVrbxTvtdEG7lnWseaF4EJV7Eb0DprKQetFELTwI3JePI+R1bIgaXXHl5ZHDq/bFX
         sT1DkOADGm3WBQMFVEnWpJ3bvUbCm2PPIW2oF9Yh0nJrb8iGSKLZLd4c3WjCL4vpvkXK
         LGg44//tHFGfGLOlvS3zrAazhBgkw+mhXaoajYhehIRIsoXJ8G+Uz7GAXnf8TTnaOdHz
         eBPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=HnfiRtup9T37PWMuIXUPRD9FKfpHitYd73t++UMYrJ4=;
        fh=4CpGkg7EivcPqQMe5O3b1e+RVIQf0jhvQPSEnYjA6lw=;
        b=c20+NAIJ8xpUIxTSsgygynwJ9GbLm9kciDp+K0zmbB6PpfoTey50/Xo7Y+4isjxdzY
         npIPuwoZcqlSj6kztYKp2HhJ4kskiKxBeXxr2ihccnpgrcuULc7ckU9I+TmTW+6xAxx0
         ytJy3LavPF8gRUbpdm5ng33Bcj1AszRDdF/4MDao/xbMHy/PdPmrpNo36jJu8sphX8ze
         RDDuKBAJa0w4IyyPY6Jth7NgvrGKiU6fqsPuzKjibjX+uVT/sNZwtcEqv7GxikAn2/Pf
         oitWG1cPNFgjMeY8Gp6825SXYw2jbSndz71Ze83FivzVhutmrFUwy8FJkuVUjTNn3nEI
         IHew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=F9lJwTp3;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714613; x=1727319413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HnfiRtup9T37PWMuIXUPRD9FKfpHitYd73t++UMYrJ4=;
        b=d0vyblrijSyu4EGXNpvgr/Bjp9ZKyGR8H531zVAWJKw8ENEA4Iiwb64VlJ/sznKLYn
         zHMuL7EhKbG1ip5GuA856hM7x46esFQinWmHqdOUM20/NsNEyyWv8wceP5SvKBrHeG3O
         pby973miMNVI1Lcz7v6FZ6LUbWWshAmcyTHaBOaTkrCSXvKoTCjMHHKdD508tseHKFsL
         QaxDqq5GRfTj+di9yk8JHR/OZkt1k4ihfJYCSBT8eyFfdgdDcFgbeJ87ic504JlScncB
         7oMZpbYQ32oiUb/HdGInff7I7J1xqsptuLcX9AUROgxVoLdSRYFNTt4qDm59FdhCmlG2
         srdg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714613; x=1727319413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=HnfiRtup9T37PWMuIXUPRD9FKfpHitYd73t++UMYrJ4=;
        b=Lt+ltV6OLS2VZuwMaY8r1H2vvNqb0cZekwBMZ7mP00jzfc8nLoW4WCUJMOldhsTVAp
         sSrONCgSXmFsp07Gv2b1ZmjN3YR6FmGLA0lZC0IsxEsUuXQkPZMht5OS+oZiA9ub3mkD
         hYMBwX2xzrWMKM0XHdyJY3uxq6JF/QlmhBDvDPASHDPvFqDcpo7pyg2kFQW4aW6Ay1U9
         P9gLnn5vl0nZ64cCJKUGQS0obxH65ctr+yHdjrZd6pJFbdmkzNmlrYUlvqLORhJBjRuS
         6svE2rcq4g12YJbt4Dwfk6wiCsD4QzgkajagILPLbaAgaJY69oogJGlo83qnRdG2d+y4
         SDmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714613; x=1727319413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HnfiRtup9T37PWMuIXUPRD9FKfpHitYd73t++UMYrJ4=;
        b=HhM74NSGE1JhmJiWhi2SnYybVGOWuQ8pFn0K1QQoOfULMkoG6DzQT1ZaxbFO57yZx9
         oJowJg4GgetdF/TDSl0IWA0S4gWMJmtTT6W/4SYK9efMIuAz4ZyY85639HgOsNk7UZ0B
         XKejZ9P/SjdhM7ULJoMRajiSugti4aVcKbPxWfJE3+BmVtShzNEWnL/591rHxRbS6ZUv
         m2tIL2E6v4AX8T6JYi0FoiLI2ja9ppMQGsWH1YGpx3aXHjgEiqHT6O/j3X6RJ50YuVzp
         Q6vlqmQS3YVx07bOA41wbTIGUPNbcYZMiF3uew6cwDwzNqrR+12r6WSqybnw2L+Iewy8
         HIpw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW/5+IBU7oubXvBcpouo/j4Pp3Xaq2jzxfevDjNiPmOFmKRNKb23Hz5S5+0xPyxKGOJWUwhPQ==@lfdr.de
X-Gm-Message-State: AOJu0YwxRkI7zRL8TkDy4caFKX6HN+vmYV9UQWX/F793SRKWi2pnGQGw
	Ftfcv/H2gutpyMIp6GSa5sySpC7Nsv6rcXXzmjzepoDnOewb2bDZ
X-Google-Smtp-Source: AGHT+IFB+pvMMMLJCnI2h6XAe1JXmRZjzN2OPGjJIYCD9OaId9REXLB/+pWE0oaDjQ2wHl9YyMu3ew==
X-Received: by 2002:a05:6e02:2147:b0:3a0:a641:b7c7 with SMTP id e9e14a558f8ab-3a0a641b998mr100763685ab.4.1726714612969;
        Wed, 18 Sep 2024 19:56:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c8c:b0:39f:608b:a7ac with SMTP id
 e9e14a558f8ab-3a0beff2376ls2809475ab.0.-pod-prod-05-us; Wed, 18 Sep 2024
 19:56:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3wKp5B4stGUDX3dYYlWFHCIO88tiz80vX5bQ8eXdLTdR5WsT1SuEv24WnZ+RcwHfqQZ/YlF2q2oE=@googlegroups.com
X-Received: by 2002:a05:6e02:1542:b0:3a0:91e7:67cc with SMTP id e9e14a558f8ab-3a091e770ecmr171541185ab.13.1726714610956;
        Wed, 18 Sep 2024 19:56:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714610; cv=none;
        d=google.com; s=arc-20240605;
        b=Z8BJcbbr4ArOyTfY4GJnosCFaoGL9lc9XbQQZGrcUuQRaBA+NSRH4XKP+f8OkC9haj
         q/wIeJLIVeskTwyajvskedqGgGlZ3rqT85KW42LZrpD4sVunIO2MPZaQ2tdsn7AoE/vh
         Aso2hwj2XxsL/N7Iv9lj/SLd6SNq+GHX6F+cdtQhGh443WljTISlYxPzgOBxeX6eptiD
         ypZeFCQBH67j11sCqk4aykzeRHJuGxT4rm9nAfM7bCqG1AJIKQVZHIdE7KgoST9pxnmN
         mem+sdW7gOGW9pG1yP7jMySNdRyMq4YW1Nrdxe8+V/rkZ6gO2G1rhoQ0T7Jg0T8ILkDB
         aBmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=U+q0qzhvgy5Htf+jNoj0jpwh62QEw37SjQucvD3DcJc=;
        fh=eY++g7S8NoXkMmazFdrlR0pHDG0x54kvH5/IUfgjeDE=;
        b=lHgKq4a1/2TGfm7WmrfH1rLqGWXZBoXBHPHmh83WXv1DL7dYTXbVq5grSw+x6X0gnd
         sta2XJHMO6IhyG+8tE3htHzy/8fC5Sdqh3kUPGwPW6DVkz15YM7QltPp0Y+F/hn7Xczc
         mUVDBLnPaKzGlvidynyJMqCJTr3XF16yv0GOrO1Y6yW94ftJedKZ/fMCDjOYDkv7skcv
         UWQ9YRj2DP723p/Bi+Y7Zd9A/ZsDlaTXXPpPB7ieRtPquNEccrHzDmyu6Sv0U9cFDz2N
         ks+bHk6MgyfBPm/PLh+DqOHcRloDUoc1SOCaMAGB7NXtTR/2tMeOKK7MugQQtELmV3h4
         g6zQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=F9lJwTp3;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4d37ec58918si445312173.4.2024.09.18.19.56.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:56:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-20543fdb7acso3502395ad.1
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:56:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUEe1yM74waqIK5kFES4ojF9AYbTsL5yTC49VILnpG3F8RlGJVSYBlcIvjeUnpDOtXjHFCFQcIwH+A=@googlegroups.com
X-Received: by 2002:a17:903:2452:b0:200:869c:95e3 with SMTP id d9443c01a7336-20781b42cfcmr332110025ad.4.1726714610017;
        Wed, 18 Sep 2024 19:56:50 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.56.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:56:49 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	Nirjhar Roy <nirjhar@linux.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC v2 05/13] book3s64/hash: Add hash_debug_pagealloc_add_slot() function
Date: Thu, 19 Sep 2024 08:26:03 +0530
Message-ID: <b8a835318147d3b8edd0e3236f5dcaa18789de16.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=F9lJwTp3;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This adds hash_debug_pagealloc_add_slot() function instead of open
coding that in htab_bolt_mapping(). This is required since we will be
separating kfence functionality to not depend upon debug_pagealloc.

No functionality change in this patch.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 13 ++++++++++---
 1 file changed, 10 insertions(+), 3 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 82151fff9648..6e3860224351 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -328,6 +328,14 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long lmi)
 				     mmu_kernel_ssize, 0);
 }
 
+static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
+{
+	if (!debug_pagealloc_enabled())
+		return;
+	if ((paddr >> PAGE_SHIFT) < linear_map_hash_count)
+		linear_map_hash_slots[paddr >> PAGE_SHIFT] = slot | 0x80;
+}
+
 int hash__kernel_map_pages(struct page *page, int numpages, int enable)
 {
 	unsigned long flags, vaddr, lmi;
@@ -353,6 +361,7 @@ int hash__kernel_map_pages(struct page *page, int numpages,
 {
 	return 0;
 }
+static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot) {}
 #endif /* CONFIG_DEBUG_PAGEALLOC */
 
 /*
@@ -513,9 +522,7 @@ int htab_bolt_mapping(unsigned long vstart, unsigned long vend,
 			break;
 
 		cond_resched();
-		if (debug_pagealloc_enabled() &&
-			(paddr >> PAGE_SHIFT) < linear_map_hash_count)
-			linear_map_hash_slots[paddr >> PAGE_SHIFT] = ret | 0x80;
+		hash_debug_pagealloc_add_slot(paddr, ret);
 	}
 	return ret < 0 ? ret : 0;
 }
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b8a835318147d3b8edd0e3236f5dcaa18789de16.1726571179.git.ritesh.list%40gmail.com.
