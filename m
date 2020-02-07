Return-Path: <kasan-dev+bncBAABBM7H6XYQKGQEJFSJZPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id E6E22155948
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2020 15:26:59 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id ck15sf1985192edb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2020 06:26:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581085619; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z/DB5ULbNbXDfrxiya/nOl8iw3o+0RkT+WXawud+JvOp1NQp1r2gU8NEma4nMMu1pm
         i3t0LYRuk0xv8TAV085xm2lnPBfaNVUAS636w2u+ZYxnFh73oLxmy22yEhmuY8pDmQTk
         IuNseq+fmQvlEHrsGHNH0gFrCh5Sb6wzCXWd/DX6whvlg+UB/4GkWUggRIGfo81uUYkB
         u3EZkrTQB/kU7PBvdaDJ3dd2jolSKlAcDgWymdQAZPX/Sc15y7cFu1JGK9oM7nxhc4DV
         Y82Tde7qoNIgB2fkUjVGUaA/4YXQh8JeX5n8TY2wL9B4NjtX7thtHRZ8aPzu9uSJmG04
         POzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=V3VjQQjRYS+d3VbGOVQh1rQlxEq/c6uWJ3TVnmLJWno=;
        b=FUjdDa0zwQmwq4XLiBLRH2MrhHSJtL5CIkmOeRmT8Sri++a711UUE27ymv5ci5W8uU
         /cmJYWqNra54GouKFXRYe9a+IEnbqCvfc9bDCVxZVJVumoRS5XDHNaYU/u2KO4/bn+X1
         Dxyayv29g0jGrVUHhUpaIKe2QW2B+3dOqPKISCo4FEeMQOcniHYTUc8MXN22L+KaZnNz
         iS+4LP/Mt+eYlakyPL1H47qLH4WU1C/pSD1+uaeTJ4lw9QI2wAqIA/2w4UWlkw6TQRDg
         NJLmpf0OOVyBKsgsFzpYCA/V4eC4pOCJ06Q/O61jrJKXjVr3v8qskXN+vj/pWTRN54ka
         iMaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=J1eAAW29;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=V3VjQQjRYS+d3VbGOVQh1rQlxEq/c6uWJ3TVnmLJWno=;
        b=lM8+ZzjDrV0qpSKR9CBTYZrKk/ywpjtGa0P2NHbWt7RERVHLCXT76qGOtO1aKD2IEg
         rEgsnouyHPBV3XlJDa1ouBaA61L/a0DoyiksKVyhomyuBQd4cdkjvMw/16wnkO43Erim
         0Ep1+sYWPOa+dSYgh0C4VKgfQNALMobcHnCZyZ7zfDNN114tIKLT14VHTLH7aFI+GuYe
         hHZ42826HzmFUSK61WnfihPNa+T4XaRlDRBv7EfYqqnEYXzRBMll+t3m9sx3kq4fnLZR
         D/+D2Wx4TeXZ/7xxCnJ9r/8JF8o2t/hIYRa9d3kyX1/vRovsprmrsQmowGMC1nb2Q1Ur
         128w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V3VjQQjRYS+d3VbGOVQh1rQlxEq/c6uWJ3TVnmLJWno=;
        b=FnEDKEGA2BpMa3nU525fpY4nCvCAMIxLDJnKY7usgETGvfqIhHNjJDFo4LtuFpUEUF
         Ut0hAJ3h1e9Y6MP+Ojo1n3+gNRq4xZb3v29ZLZFIUhP2eAQC4pGqpwIDONApmX7rrNvk
         qsUuPaHdxVQenakskNZZ24m2MnoPz7sz9QcG1qu8tc2ykv4mVGKCHsuObr3qYW8nM9+h
         V5Ie01+cVuAQDw2TO+3C7Wg+lzomEq22luey8/kDxuSTSs8+fbIsAZxtAatkWHPTo+Kz
         60QPzu4tPCCBsqzL25wb/FabwcJVFkV6AvmrabZwQEsm1UHPVnKwMvUh5OIcV83ElwCR
         nyZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUHQvW1dpoMYu5hVWm7XLW0JbD4uinPW6DFWk18du0LytEhMUx9
	JN+5LD/WoUAv70p4ZXq5x4Y=
X-Google-Smtp-Source: APXvYqzXJKByGLGTKs2Plj/W+W6ywh2u3TsMf0+e5pyqPsCAdVeG6Njc7HcLsrOOPay4cdzzf66jnA==
X-Received: by 2002:a17:906:4089:: with SMTP id u9mr8755340ejj.184.1581085619665;
        Fri, 07 Feb 2020 06:26:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:bfe7:: with SMTP id vr7ls59857ejb.1.gmail; Fri, 07
 Feb 2020 06:26:59 -0800 (PST)
X-Received: by 2002:a17:906:49cd:: with SMTP id w13mr8869011ejv.324.1581085619278;
        Fri, 07 Feb 2020 06:26:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581085619; cv=none;
        d=google.com; s=arc-20160816;
        b=SlqmM5Zpgfh94cBcoiGtY6jHPEQnv+OOPwWwkISF32a6f4tcBJdlJj8pF4EIDJ5nHK
         MWpfUUDD1g5NZl8zevmeSAHA1e13OLkLJFGby2gTUMyJXwLQRo9i+uD5i/1oQFNMpVKS
         Lxe+NPaBIktzCGpL3qLh+qlQPW0tgl458L8ngGttk9tvDRln+Q9DuBlADe973ZkhrM33
         8MOgqD8HjKi2Qs8nyaniavHtINGZT68JNQFsS+c3+QccO2Q5nIYh6evdXmxi7vCRB5qf
         IcjDo9VVQOJMZT080mjw8rdXc2kc5oGBBTqS3wNUgqq0zEQ1GfDconjBjyxgCFXHsz2X
         XIMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=thYUobt6pp4eEud8l8vCKfukm0gTsC+SY9nMHyqvvms=;
        b=LbWARdOchglo2r2BPQ2mbar2dZ4p5cShGMwzVeq9YUypSFEFT4iVW8kzmZA2FK0zRk
         zxFgM5u28jSTzgWCvJPIXOrlFB2+VgifDQgufi7yAvnWWztwL2fyvqH2hxVfhKgVl6QZ
         C6EjL5ce4C1LJN7JzCjjTH03HsXDSKMqoxL9kjw1uEf64J//tLf7WkLa6CrKtGmENjmI
         aVW6y7A+kUS3HAgoxbyv7WlVl0LilMSWAWaqh13IS8ntRixPbNVRtiiG0tZgH/8O+Isj
         LOyD+IDCKrwczdcwZiuqfu9hYfcysFpOcCEICMGSCwsBIDzYCqYzSPoBUb9iG2GjNLmE
         KK1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=J1eAAW29;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa5.hc3370-68.iphmx.com (esa5.hc3370-68.iphmx.com. [216.71.155.168])
        by gmr-mx.google.com with ESMTPS id df10si169947edb.1.2020.02.07.06.26.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Feb 2020 06:26:59 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) client-ip=216.71.155.168;
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa5.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: NbCBsYaY7tmZHavhqZHrbPJ2IHI7GEcD1su+OtjP6Feuh7t+T6eFm5iKhfT122oG8TD/O3R8jw
 C5g0kaQf1sgi6i8GcO+rDSWiFdeM6ww+sxchmgZSpu1Ngha9qM0EQzQdNSAaRt8Bu7M5x2Bkbn
 kDUjOTCdTHUFqKjA6qLuOGaJDttPGeQ9ydKYf6zzUacaY7RFxrX6j7R3mqaLyNlRpVq1pDJScF
 Bg8JDVmtoM4n0+LyzPPxNHsH0+1tlVZxNMup64noARhGcmZ/Hao+6WQaKQ8zkTwvKLNKggLICd
 weI=
X-SBRS: 2.7
X-MesageID: 12479583
X-Ironport-Server: esa5.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,413,1574139600"; 
   d="scan'208";a="12479583"
From: Sergey Dyasli <sergey.dyasli@citrix.com>
To: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, "Stefano
 Stabellini" <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>, Sergey Dyasli
	<sergey.dyasli@citrix.com>
Subject: [PATCH v3 1/4] kasan: introduce set_pmd_early_shadow()
Date: Fri, 7 Feb 2020 14:26:49 +0000
Message-ID: <20200207142652.670-2-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200207142652.670-1-sergey.dyasli@citrix.com>
References: <20200207142652.670-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=J1eAAW29;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as
 permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=citrix.com
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

It is incorrect to call pmd_populate_kernel() multiple times for the
same page table from inside Xen PV domains. Xen notices it during
kasan_populate_early_shadow():

    (XEN) mm.c:3222:d155v0 mfn 3704b already pinned

This happens for kasan_early_shadow_pte when USE_SPLIT_PTE_PTLOCKS is
enabled. Fix this by introducing set_pmd_early_shadow() which calls
pmd_populate_kernel() only once and uses set_pmd() afterwards.

Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
v2 --> v3: no changes

v1 --> v2:
- Fix compilation without CONFIG_XEN_PV
- Slightly updated description

RFC --> v1:
- New patch
---
 mm/kasan/init.c | 32 ++++++++++++++++++++++++--------
 1 file changed, 24 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ce45c491ebcd..7791fe0a7704 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -81,6 +81,26 @@ static inline bool kasan_early_shadow_page_entry(pte_t pte)
 	return pte_page(pte) == virt_to_page(lm_alias(kasan_early_shadow_page));
 }
 
+#ifdef CONFIG_XEN_PV
+static inline void set_pmd_early_shadow(pmd_t *pmd)
+{
+	static bool pmd_populated = false;
+	pte_t *early_shadow = lm_alias(kasan_early_shadow_pte);
+
+	if (likely(pmd_populated)) {
+		set_pmd(pmd, __pmd(__pa(early_shadow) | _PAGE_TABLE));
+	} else {
+		pmd_populate_kernel(&init_mm, pmd, early_shadow);
+		pmd_populated = true;
+	}
+}
+#else
+static inline void set_pmd_early_shadow(pmd_t *pmd)
+{
+	pmd_populate_kernel(&init_mm, pmd, lm_alias(kasan_early_shadow_pte));
+}
+#endif /* ifdef CONFIG_XEN_PV */
+
 static __init void *early_alloc(size_t size, int node)
 {
 	void *ptr = memblock_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
@@ -120,8 +140,7 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 		next = pmd_addr_end(addr, end);
 
 		if (IS_ALIGNED(addr, PMD_SIZE) && end - addr >= PMD_SIZE) {
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			set_pmd_early_shadow(pmd);
 			continue;
 		}
 
@@ -157,8 +176,7 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 			pud_populate(&init_mm, pud,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			set_pmd_early_shadow(pmd);
 			continue;
 		}
 
@@ -198,8 +216,7 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 			pud_populate(&init_mm, pud,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			set_pmd_early_shadow(pmd);
 			continue;
 		}
 
@@ -271,8 +288,7 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
 			pud_populate(&init_mm, pud,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			set_pmd_early_shadow(pmd);
 			continue;
 		}
 
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200207142652.670-2-sergey.dyasli%40citrix.com.
