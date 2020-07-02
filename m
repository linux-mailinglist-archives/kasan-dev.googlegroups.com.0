Return-Path: <kasan-dev+bncBDQ27FVWWUFRB4MY6X3QKGQE5KDV2GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id E2BE7211A51
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jul 2020 04:54:42 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id 18sf8132740ois.18
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jul 2020 19:54:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593658481; cv=pass;
        d=google.com; s=arc-20160816;
        b=zQFI/GRk0Sp05T2fnsEL+n0u4CDCucNB0PlaQJai7IHFdkncvpVzvZlJY2R0Dlnzwa
         tZdHKbDjuBiy/u8yZyuhRSH+7peid/vQw6PkyTci+DN+sFb3vEmijmeiI1Y+BpbcsWJB
         wp7ijcZFAeZcoV8Gym5JPk00x9yydg1fWzwQd/8n263P5YfMldlYEC0/70mHL9WfBOa9
         Bhj5F+V0URcdD9q8Hptt0tiP9ch2LkzegGIV54Hl1HXuWfmTPV3aqfXBFG9CCS0ojH5Y
         q0nLUvUBS8VF7D3F7cDtDH3YKCpkBPeBpHkHDyJGZ3MyGyedyvheOt++/vE63S+CDhjr
         +3og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/iQYTd4Ptx5x01gGYdGMH0fVK/hl98lkkskPU9cnVt0=;
        b=isG2+HPsgaUQhEIfVsZfAmqOco9wm3FxqfcBLaiYZ27HyjXrt+GpRzY+UuPCq+SvoT
         pFuhpXIzvnrWhLRs4g9HG9OnKdCPgP1ZXfqjX6JcUstaxbXBZNNrKJXr1HhOw3oXWp79
         A6KWiTseu3xDp+n1nQSRpyAeaXv+WCgu0LiT8/TZB/n7nIOUeJvVI8BYbj7tI6BLN0eY
         rJriPQGD7nTSL4xm1ZbyZpfvb1jTWXMenxNoRFiPGJwu/ug8qHlQRp+FElXmkQ2wc7el
         HqHDKWlQJoEPzP5qfDfHD1pb6QdPJuKciH8ttnvsIQkSFULORPF81sW5027wCgrCG5jP
         nNKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=l8Hhhj8s;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/iQYTd4Ptx5x01gGYdGMH0fVK/hl98lkkskPU9cnVt0=;
        b=RhzHx9RcFfPFpw8KAMSLszPowWG91HRbg1xdJNsDWCEpYHehtUF+N4+BTvwG/iBULV
         PWUUOtJ88JvrpH53HlxYV0+ey0F2jKqOVtGL02vv1zZXVc3SdMzhfNc1qH/VX7pgqIBg
         UA5tjBG6oYXcXl5E8kHGmVhBwGVNlNXgpQWBnCsnZp4lxiT4KmaasIWZxF7iH4vZEECz
         CTBKXHMEVvsTvZwXMnwEmcYnBvNvbzlcELouBSohUlYHns+8a9OIu4t0yQSdrCU1j2Ns
         SkzMueo0piLNogoV0sgIkMaJX/L+Tu7cPZF1nZdymiyrbNq98Y+pKw72oS6d9fth8/sJ
         o7LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/iQYTd4Ptx5x01gGYdGMH0fVK/hl98lkkskPU9cnVt0=;
        b=Pi6tWR2EDKqVbYOmnVEPaocRHDCzproOm2dhXmFTkWvCjMqx8J8roNla4yEHs4A6vG
         VwC2Wh5EfNJEdTEqRsOGTsPb5Aot+tGIE7auZS1klKTV+WcBJcLMryx/rqs4Dik7xaM5
         KAEqSzAV3IdJXEocOBlMoBtUIKRDdqIYhMy0JvNZCmCXr1ZknHjcn0QpqutoN6hqsK1g
         CKl+7h9SHCvn2z7VPpTQUD0afOciiZN8whajkUbxcW71sjaFWclUllsRAwBSh1F+G3VR
         vjw50DEHl0e6ZEvUya4Hn57t8ZxsQldbu+15XLgYl9f1fnScLkn1cFhdm5G4piz2Dc06
         hZTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5318wpR4jKAJUZr2+EqEROjWCOwSpAVefQQJWOhGEiyFrib1YWJ4
	Oxhv8xqfTBfp08Xbd7+O7jI=
X-Google-Smtp-Source: ABdhPJxLVjfWCLDfDnQblyu65sQZO4WDN78hYbiYnpsIMRAU6GeTrDB2HdoRYR3Zsnxl0Yr8iBKK2Q==
X-Received: by 2002:a4a:3702:: with SMTP id r2mr5226671oor.33.1593658481733;
        Wed, 01 Jul 2020 19:54:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:159:: with SMTP id j25ls988691otp.8.gmail; Wed, 01
 Jul 2020 19:54:41 -0700 (PDT)
X-Received: by 2002:a05:6830:10ce:: with SMTP id z14mr17141669oto.135.1593658481353;
        Wed, 01 Jul 2020 19:54:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593658481; cv=none;
        d=google.com; s=arc-20160816;
        b=S5BSQDBd2ZnONQCYY+nyRv9D6KsIhqNgvZUVviUYv8eWg1XT6sQu4MtMTFe1XH3Vcb
         NSbnggHrlHtHwO5kVQy5/gUz4kuQamAexxb7uFtkD1gJ8VzxVT/efuXibrkKQF0q5HlJ
         8TC41PvKa2n7mDIWLGvc1TH8/FQrZT54Nmv86CpCzgLmkxVaKtRYi0xS0BXznWuhgGyf
         vjq+bzH946G+jbQHDK8senV+6Z/V0W/fUzKUkTODqKilN46LxVfW7GW5uNx4QIwKdXYg
         4fOSboYtCPawKiU4d3Xug06bTqLbpsEIU38GUHX6NaIjCnG/JsJvTsK+mpQG3d35gymH
         RkSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jEAbvp0NcKYXLPlKcCam8GQvvafUBgcVOJIj099LJII=;
        b=zd0UgZwIqRtYr88JxyRC5XzVbHNaNrFGM2kJps6mhcDTGwTvKisoEh87MMNY/ZEbL2
         Ut0BrbeVfJxrxzNIfKlg+Od6wv2ytHXWhTLbUAFwXDgVRlsn84vb8GKGL8LKxgXFJEAm
         MMBswithQiGfxox3CfTTaboaLmMlZ6PkwWwonxGP6/ZXSn8vhzY+R4Z2qjzPb1SrJ/K2
         ARrgoUq+tqsCJ+yBiDfXNNX4+nHdHoXrZLwqOWrb+rE9jUxoJI536+nNG84tsy2o9AGc
         XiUPk4SIbNFomtKH0otju4yWlH7kiBGpOMzOWrXncEv+DiwVYiaZ4Q+9ixMWb6bFCis3
         Sf1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=l8Hhhj8s;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id n6si322874oor.1.2020.07.01.19.54.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Jul 2020 19:54:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id u8so11489723pje.4
        for <kasan-dev@googlegroups.com>; Wed, 01 Jul 2020 19:54:41 -0700 (PDT)
X-Received: by 2002:a17:90a:bb84:: with SMTP id v4mr20987849pjr.162.1593658480672;
        Wed, 01 Jul 2020 19:54:40 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-3c80-6152-10ca-83bc.static.ipv6.internode.on.net. [2001:44b8:1113:6700:3c80:6152:10ca:83bc])
        by smtp.gmail.com with ESMTPSA id 140sm7127309pfz.154.2020.07.01.19.54.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Jul 2020 19:54:40 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v8 1/4] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Thu,  2 Jul 2020 12:54:29 +1000
Message-Id: <20200702025432.16912-2-dja@axtens.net>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20200702025432.16912-1-dja@axtens.net>
References: <20200702025432.16912-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=l8Hhhj8s;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as
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
index 82522e996c76..b6f94952333b 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -14,10 +14,22 @@ struct task_struct;
 #include <linux/pgtable.h>
 #include <asm/kasan.h>
 
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
index fe6be0be1f76..42bca3d27db8 100644
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
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200702025432.16912-2-dja%40axtens.net.
