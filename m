Return-Path: <kasan-dev+bncBDQ27FVWWUFRB5VCR3ZAKGQEZYNSNKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2506715A0CC
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 06:47:36 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id q4sf724714pgr.17
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 21:47:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581486455; cv=pass;
        d=google.com; s=arc-20160816;
        b=eetbQ3SriuOJ5jCyh8h+Qt9eWzhT7m5dRRU52Gqd9UMjNLVh/45IMsAx86VTRd9L0H
         wekCKNpl4vM/5HEGmdx2+EneqUafDYz0eRXeX8htqnEk+fia0dftBRcYaYWUI+p9eQTn
         d4+Qu6RBZEzXEI5Hp5ePjUpBak33QMRvH2ti1STExb9ChbeMzRcC5Pq7vhK4K6sINPEe
         8zK1SPB2wWtR9xdjTys6Bc0OJU/DVGCjh98R8Uh+lGPr8ksY0UiVynNmzK0Z9YIJWxbJ
         CHzQn8Gnh9efZurm49g4axCWUhDaw6qRuPclVdjqvN5nwrOEv95DLRvBjXJkrBPKRd1t
         1hTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VrYtnRVD1ytOUcbXaMFLMR48sgsdPEEWg4Gc+HGDkLw=;
        b=dMb/wuMOgVs4RpRukq4ttAOBXcj4VbahFvXiq7QDJqnYWsPINH5ZpAzRgQNGgXLNZZ
         syxXXhP3errQqdONE4vJ1GX2oZifFePGvIltSBvkk8fiyhlydFhb9Refdcpfl74j7srP
         bDbxU4xuBzRve8WLMW67apuUNaGkHDtQJwMDqW1WuCYAep0I7RO1wKtXHNgdL0is8C/k
         LMzeWWU4S5qcvxZemXvWJ0jqqtzJAY9WSGY3/+kV1naUN4CvUh/OjqjuqVsu6TBVJDJM
         efXzu4kQZxDzipGz0SUY/rELY2isNtew5bRzXM9P1LYYwLPMiqsqIiUcXDaWLhcPqUN6
         5Osg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=L46dDlkO;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VrYtnRVD1ytOUcbXaMFLMR48sgsdPEEWg4Gc+HGDkLw=;
        b=EYFKPH2/Z4hM923z/Qejv9+kO5wvtsdTUpogC62WjJONHNeN6OJbipK5HN6zs+y/bq
         aGGO75aXlo1sNO99lZV2Yinzjr1TtZ9/uOwmxKDz4SKARVYeu85YUmwhkNs1PhAWCNLW
         KbXKdOnqXFHZs6B+47xbODLkeP7OoKAnsETl51oMsHGtZnLGsZdMjL4QGUZ2yFpghfV+
         iMefOAA3tvKTLIuNtVUyQb8HWAuPwt9Zqj7TCuIrN69X41iF4EsABwZ8jQUnzERUoDIS
         cX+zdWSnP2uQzPedv2TelzBpVBIho2jaY7jNpMD0NH5CuAlAEBEAVbpTOd+/3ZXROiec
         1qvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VrYtnRVD1ytOUcbXaMFLMR48sgsdPEEWg4Gc+HGDkLw=;
        b=erJlj0Zy+zjBxxhau8Y9OuDz1wj91v6qyeqvaRLNo1NqY3b8GbB9Fv2mqEsctrTf4d
         ptwDvEQ1Ms+LHbaud5prr0wOjPeekkp+hqnf1mZaybTHM6cYNfaQrum2IxE/R0xEwonD
         jzSPQ9wTlnqDb5iAKpD8zuFRgmSWS9AWZhu1nxKzGiMajhlJBd8rfskLv0PuxuIj6+fy
         rYZaaoD4AphpdRLt96xshwv+Wk4SV54dPPZ6kTY+Pjzs0nZQWyyYse6yNsamy1EFNxEa
         bo2WS3Pw2mfFebDtLAdISwVZ3AWgolxSMvQgS18ry9mMMXzmG0BH7CUcPWtBbty+94Lv
         xxgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXs9/xhIxm38BIJIn9aSMSgZ5wlAmUfh1rYAivBqFZlt48afS7L
	hUYNWwcnK/DZ3GP6pCPYVj4=
X-Google-Smtp-Source: APXvYqz9Ll1Ps512WVpmS6KVcZxzVhWO+srifotz/SZuR+IhWzMYtfGjKn9JnvGG8MnxP7mkBl6ngA==
X-Received: by 2002:a17:902:528:: with SMTP id 37mr22199226plf.322.1581486454807;
        Tue, 11 Feb 2020 21:47:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9687:: with SMTP id n7ls6789005plp.2.gmail; Tue, 11
 Feb 2020 21:47:34 -0800 (PST)
X-Received: by 2002:a17:90a:b008:: with SMTP id x8mr8249204pjq.106.1581486454277;
        Tue, 11 Feb 2020 21:47:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581486454; cv=none;
        d=google.com; s=arc-20160816;
        b=RFOEDj6WCfyW7kDxapx6CkuA4P/CTp+3eIM1x4IhRuYLrPKrIFJtKhl9TBP6AVarhJ
         RfogP2UZNg78e9JEE/j+tnLZrCvH+uDL7BEfLw1N7wLIpP1HvLDc4MV+oOt8kKer12XW
         CvfInsAOob1Dmma2bZwOJ0T2urhNzSD+vcPhh5L2naqlbNZpB/mxtXEh3v0JulwxHokQ
         u8N7SGMNBq7YbHXJUljyURi8RdThafhsC0Sxh6pqKm0l6mDpo4iieHxXCCpLoASb/TuW
         m8Vh3Gr8D2srKI3Ygsoonqgyr9oOkzU/8OLmzvNwosB36sI+tjM7JUBUK6TH24DGF2H9
         WSQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0eDFn39gIg7xtZfHp4ELa6UyXk2yfoJL9wFZ1T547PE=;
        b=p24DyvKHWEOXh10JzAXCQBzUVZE3pBWAsLtKvYxL9bgrnAL2ItHQqNovCr1PRA9hI+
         5GlesuviTyfvHz5HlTo4bMaYJI6WZmcaEO+0S2K0YC2/zTccZqmZmYqG4xh4UPvuz11t
         w4Jna2Mx7UBUj6cPm/Rcz6tohADHpwNjmcY4SnYob8P/R/03y2lSvKamzwZAWbA4QPh5
         sANzkQs1+s5pcnAEqOVgdG6/COgEK3I9ZF41faL1hQgfEzGTh2gNHY5GFBmKi0scuIr6
         Wnwc0Ras9uINUH7VdiluDZbQZfbVJGtUqBljNmRzDrpTVMvgNSwlg+6E2pgAdSAn/vdS
         HHwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=L46dDlkO;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id m11si118035pjb.0.2020.02.11.21.47.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 21:47:34 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id q8so660019pfh.7
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 21:47:34 -0800 (PST)
X-Received: by 2002:a62:2cd8:: with SMTP id s207mr6815093pfs.247.1581486453988;
        Tue, 11 Feb 2020 21:47:33 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-65dc-9b98-63a7-c7a4.static.ipv6.internode.on.net. [2001:44b8:1113:6700:65dc:9b98:63a7:c7a4])
        by smtp.gmail.com with ESMTPSA id d64sm6160498pga.17.2020.02.11.21.47.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Feb 2020 21:47:33 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v6 1/4] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Wed, 12 Feb 2020 16:47:21 +1100
Message-Id: <20200212054724.7708-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200212054724.7708-1-dja@axtens.net>
References: <20200212054724.7708-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=L46dDlkO;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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

powerpc has a variable number of PTRS_PER_*, set at runtime based
on the MMU that the kernel is booted under.

This means the PTRS_PER_* are no longer constants, and therefore
breaks the build.

Define default MAX_PTRS_PER_*s in the same style as MAX_PTRS_PER_P4D.
As KASAN is the only user at the moment, just define them in the kasan
header, and have them default to PTRS_PER_* unless overridden in arch
code.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Suggested-by: Balbir Singh <bsingharora@gmail.com>
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Reviewed-by: Balbir Singh <bsingharora@gmail.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/kasan.h | 18 +++++++++++++++---
 mm/kasan/init.c       |  6 +++---
 2 files changed, 18 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5cde9e7c2664..b3a4500633f5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -14,10 +14,22 @@ struct task_struct;
 #include <asm/kasan.h>
 #include <asm/pgtable.h>
 
+#ifndef MAX_PTRS_PER_PTE
+#define MAX_PTRS_PER_PTE PTRS_PER_PTE
+#endif
+
+#ifndef MAX_PTRS_PER_PMD
+#define MAX_PTRS_PER_PMD PTRS_PER_PMD
+#endif
+
+#ifndef MAX_PTRS_PER_PUD
+#define MAX_PTRS_PER_PUD PTRS_PER_PUD
+#endif
+
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
-extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
-extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
-extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
+extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE];
+extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
+extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 
 int kasan_populate_early_shadow(const void *shadow_start,
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ce45c491ebcd..8b54a96d3b3e 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -46,7 +46,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 3
-pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
+pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
 static inline bool kasan_pud_table(p4d_t p4d)
 {
 	return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
@@ -58,7 +58,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 2
-pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
+pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
 static inline bool kasan_pmd_table(pud_t pud)
 {
 	return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
@@ -69,7 +69,7 @@ static inline bool kasan_pmd_table(pud_t pud)
 	return false;
 }
 #endif
-pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
+pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE] __page_aligned_bss;
 
 static inline bool kasan_pte_table(pmd_t pmd)
 {
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200212054724.7708-2-dja%40axtens.net.
