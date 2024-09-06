Return-Path: <kasan-dev+bncBAABBHPY5K3AMGQEYPD7VPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 478E996EDBA
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Sep 2024 10:23:59 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-45677d056c3sf26744101cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Sep 2024 01:23:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725611038; cv=pass;
        d=google.com; s=arc-20240605;
        b=K9rxzxOOsCciQhWp1tdmBx7V+RkslnGhjsx6WY1YKbBgmCDFZeToaFOVgwaZ4NwZDp
         PoQnWS65tGguYZiUfzWbh6JmOueYpurxgPFpZqpk6x3ZWRhqQzFJ4IbDdKy+DEcOERPu
         vcAnskoAlvVI55U5ZsqRlZY+q5WwhHrVg75snmdRTs3tqWU0nV6VPuv+BqBEdiv530Xc
         LAPwQCHAa7JjK3KMGIPBWGNYZQc/PPtiDpjojnhdK0ky6aeGZpcwEFrYSWPyR4UHs0Kj
         SGETqPwzsqxgQGsNrYXkjWvOVVRIzkYZ5nKtNMcCFV+3XO1oglNAkn2xkZE75cNv+LEH
         3vqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=NQosgl8FxEfkxjH2fbwXoVRyBYjxihcGBJ7O63t23Jg=;
        fh=ZWZ+mxwhMhkXMc7p48uohFxbbZWoJQFA4hTCKCiM2PU=;
        b=CIDnuj+ED2HFiuAqHA82Z4MwWVFyL3HyWNm8CwVYjZHQa0/cw4vfp/ZaKQdK/ezwjX
         nqlUMmrIMvwJfYBmHHKFcXilYQIGirMIDZgZgfGck/4dYx5+mFNVDuV/ou8R+9gJmZOy
         vTDIqPHi1CIwRKwgg4tkqu/aE4W6jK5+5CJrCWCQCwqNDgxrUeNJnZYQYsTLvq3MPIsL
         wCm+ruT5Th1XvMppdS+XdtvfqPyRqPipjgiEJYMMXn46wH2chXOTDAjd76zI/pLl3yIU
         5ASXToDIkuv6vSn0PgVNoKgbiIo3IWQgXkcmD6kkY/9Akh0GxxS90+FXhLz7fBC9z/ld
         PlcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@uniontech.com header.s=onoh2408 header.b=ShqhxArB;
       spf=pass (google.com: domain of wangyuli@uniontech.com designates 54.207.22.56 as permitted sender) smtp.mailfrom=wangyuli@uniontech.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725611038; x=1726215838; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NQosgl8FxEfkxjH2fbwXoVRyBYjxihcGBJ7O63t23Jg=;
        b=q2i70IV7RX4Rk4PF6C5aVSd+rre6JpPaYJaxt2Cv0Ariety9U0/7xb0tuGOKrLvoao
         dZG+xRvAj0mROubadO6e+qQm/3y7hRBMQWO7SNzryl0ZfM0gMAQpqntfu68Q1ms6drcM
         jEo3/xBDCvAzoZLlJ4FOUOO/neJokOfBTG9HVWdtDDx7D60CgvJPvhNIlGhyZ4A6es5N
         Z6TxT/pmXLObN1H/MtptkJgnfnR1kQeyTv2Jwt+W3aFX9KYaaieaxFFJmMjZHnufVfrC
         irj1j8MEyB4pr7Wfnr2+rqnkE6qXTl8tcai0PrFIo6O2VRgzf+azzB2NGrrUIpqjEJrI
         1J1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725611038; x=1726215838;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NQosgl8FxEfkxjH2fbwXoVRyBYjxihcGBJ7O63t23Jg=;
        b=Z9AGymmYQeVFnQMQLq1JFYLjkUGyYQRA+O1SaPJVX00hXqKGiPfNz36561nDxIU+Tt
         U15O5rJqs7mQJCo3Rn+mARZFkL1twBJlwrlP7SwCotNxbD612o8zUaIINLgu9jy2a1kp
         lMiBUzyxllMgPdGxT6s+BYSvE3CQOwuXlWDm3Z4xRL7fHFqzWJW54d7zWx0WF3c0DIm1
         v6b5DTwc9DLZwgGITjTLuZjZRdwfsSp4hCT7z+7lNSy3LFYgYQus0hh0+m/bWS7P5LX7
         sp8uMt1agTZNwi98Gq7Jq03N/ZKPQWvFkvUTHNPAzqIeut+Z/pVXIR02C0WtOckEL77a
         9Eog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXpc1mM7cf8vWYyOEV3BSQ+qQK/eNVd4BKAgHgvdbmI1irAmR7XYpBkNYN5s5xWZ3NZuU+RYQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy4wkm4nY0iYPqcrG6AhdE0bBALV7PLeFmBxy84dl6HKxccBJ/Y
	o1AQoiR28dD+pNy2ViJGN1I/I0pIWigmerBcWeJJsffakAmNlnMs
X-Google-Smtp-Source: AGHT+IH7v7Vd+3SvddhBW+1xPvnzKYdp44Wp1GWz8jPsdvkN/NO6v6+zFqrx2fS8lQ1+0jwo4YiaRQ==
X-Received: by 2002:ac8:57d0:0:b0:457:cbf6:ec80 with SMTP id d75a77b69052e-4580c744918mr17596261cf.43.1725611038067;
        Fri, 06 Sep 2024 01:23:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:15cb:b0:444:b60d:daa5 with SMTP id
 d75a77b69052e-4580b78268dls8374351cf.1.-pod-prod-07-us; Fri, 06 Sep 2024
 01:23:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1KIDjrngH1F1pYNZewaN9QT61I3sE+3VlSKvevwuqP9RcCErP/GrGK7ml0JFsWogVb3FP3jKpbec=@googlegroups.com
X-Received: by 2002:a05:622a:199f:b0:456:80fa:617e with SMTP id d75a77b69052e-4580c66ff87mr21563841cf.2.1725611037477;
        Fri, 06 Sep 2024 01:23:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725611037; cv=none;
        d=google.com; s=arc-20240605;
        b=hKkS0REbBcjT+nkb92Vt1GT47jONwu1ViHrrZsYZZUqAW9Ks35okHMbTplRCNwwErV
         37HF9MIGHbe18+SalJICpclHcvTU/Ar2PcTgVAUixZwttWSkJ1F7uzASUvrKaiLLBJfW
         WhEyj1AJVUBZMG0xLZ3KXvMrQulV2+ro2Qrv7w6mwL0OO8CG78Gq9PVJy+q5rwtvAju4
         ire5wZRZ14m/sKNtQQ+33lqDfSDl/V74yULxt0INw/GElQQzat7gdpydFsiC2Pu5QW7H
         2S14eYseno5CQDIfRHkZ8D6kdp8HtuTpY3kDkI5k8Cee3Ch/QhHKPzhrxdj0mKMozGm1
         IFpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=c2Y6hDcW5soaI9k7gniI980VucnVpsyCwVOK429FvIA=;
        fh=gZAG9vHOZ16B4SEK/V8lEUbRtGWfKWOwkMT9Yi15/RE=;
        b=bt3WD0UPD8E0CoSQsKrlsp071hm1szRNJ4s0TVHnxgKQop+NAw60hO7nryIlIO6UdP
         L2hRjXM6UA1Xr+84Mm7s941r9D+ckpxXmcreQWVNc668mHGXzyx6r4iBCFpaHkj42xgF
         MFJP81TNHEvQ5lOZ7Q4Y7IZ9tOrbOWNFaPtlYIOrW8lXz2QiKcdCVK8zXejT0bKHH+O2
         li271dYRZb9fqhje99aNKKVSHY3oxY1PEWUg58xyqVhKweTQpFDpQOmU2qhKeesnCcK/
         NhrmzdwaFYLVyCZ3494dGeFzD3kPzS6UjG5krDXLdi+7cQJlVGgsQNVHQC/oSGEoEWxT
         /FhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@uniontech.com header.s=onoh2408 header.b=ShqhxArB;
       spf=pass (google.com: domain of wangyuli@uniontech.com designates 54.207.22.56 as permitted sender) smtp.mailfrom=wangyuli@uniontech.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
Received: from smtpbgbr2.qq.com (smtpbgbr2.qq.com. [54.207.22.56])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-45801dd2ec8si1585281cf.4.2024.09.06.01.23.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Sep 2024 01:23:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangyuli@uniontech.com designates 54.207.22.56 as permitted sender) client-ip=54.207.22.56;
X-QQ-mid: bizesmtp82t1725610993tbhs3wew
X-QQ-Originating-IP: gB/3WYVXTwnwfUfShFtfuqtn/wTOkf9uPbAVVydCjDE=
Received: from localhost.localdomain ( [113.57.152.160])
	by bizesmtp.qq.com (ESMTP) with 
	id ; Fri, 06 Sep 2024 16:23:07 +0800 (CST)
X-QQ-SSF: 0000000000000000000000000000000
X-QQ-GoodBg: 1
X-BIZMAIL-ID: 10217785498291060438
From: WangYuli <wangyuli@uniontech.com>
To: stable@vger.kernel.org,
	gregkh@linuxfoundation.org,
	sashal@kernel.org,
	alexghiti@rivosinc.com,
	palmer@rivosinc.com,
	wangyuli@uniontech.com
Cc: paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	anup@brainfault.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	rdunlap@infradead.org,
	dvlachos@ics.forth.gr,
	bhe@redhat.com,
	samuel.holland@sifive.com,
	guoren@kernel.org,
	linux@armlinux.org.uk,
	linux-arm-kernel@lists.infradead.org,
	willy@infradead.org,
	akpm@linux-foundation.org,
	fengwei.yin@intel.com,
	prabhakar.mahadev-lad.rj@bp.renesas.com,
	conor.dooley@microchip.com,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	ardb@kernel.org,
	linux-efi@vger.kernel.org,
	atishp@atishpatra.org,
	kvm@vger.kernel.org,
	kvm-riscv@lists.infradead.org,
	qiaozhe@iscas.ac.cn,
	ryan.roberts@arm.com,
	ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	vincenzo.frascino@arm.com,
	namcao@linutronix.de
Subject: [PATCH 6.6 2/4] mm: Introduce pudp/p4dp/pgdp_get() functions
Date: Fri,  6 Sep 2024 16:22:37 +0800
Message-ID: <0BC12DAA7222E361+20240906082254.435410-2-wangyuli@uniontech.com>
X-Mailer: git-send-email 2.43.4
In-Reply-To: <20240906082254.435410-1-wangyuli@uniontech.com>
References: <20240906082254.435410-1-wangyuli@uniontech.com>
MIME-Version: 1.0
X-QQ-SENDSIZE: 520
Feedback-ID: bizesmtp:uniontech.com:qybglogicsvrgz:qybglogicsvrgz8a-1
X-Original-Sender: wangyuli@uniontech.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@uniontech.com header.s=onoh2408 header.b=ShqhxArB;       spf=pass
 (google.com: domain of wangyuli@uniontech.com designates 54.207.22.56 as
 permitted sender) smtp.mailfrom=wangyuli@uniontech.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
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

From: Alexandre Ghiti <alexghiti@rivosinc.com>

[ Upstream commit eba2591d99d1f14a04c8a8a845ab0795b93f5646 ]

Instead of directly dereferencing page tables entries, which can cause
issues (see commit 20a004e7b017 ("arm64: mm: Use READ_ONCE/WRITE_ONCE when
accessing page tables"), let's introduce new functions to get the
pud/p4d/pgd entries (the pte and pmd versions already exist).

Note that arm pgd_t is actually an array so pgdp_get() is defined as a
macro to avoid a build error.

Those new functions will be used in subsequent commits by the riscv
architecture.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
Link: https://lore.kernel.org/r/20231213203001.179237-3-alexghiti@rivosinc.com
Signed-off-by: Palmer Dabbelt <palmer@rivosinc.com>
Signed-off-by: WangYuli <wangyuli@uniontech.com>
---
 arch/arm/include/asm/pgtable.h |  2 ++
 include/linux/pgtable.h        | 21 +++++++++++++++++++++
 2 files changed, 23 insertions(+)

diff --git a/arch/arm/include/asm/pgtable.h b/arch/arm/include/asm/pgtable.h
index 16b02f44c7d3..d657b84b6bf7 100644
--- a/arch/arm/include/asm/pgtable.h
+++ b/arch/arm/include/asm/pgtable.h
@@ -151,6 +151,8 @@ extern pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
 
 extern pgd_t swapper_pg_dir[PTRS_PER_PGD];
 
+#define pgdp_get(pgpd)		READ_ONCE(*pgdp)
+
 #define pud_page(pud)		pmd_page(__pmd(pud_val(pud)))
 #define pud_write(pud)		pmd_write(__pmd(pud_val(pud)))
 
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index af7639c3b0a3..8b7daccd11be 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -292,6 +292,27 @@ static inline pmd_t pmdp_get(pmd_t *pmdp)
 }
 #endif
 
+#ifndef pudp_get
+static inline pud_t pudp_get(pud_t *pudp)
+{
+	return READ_ONCE(*pudp);
+}
+#endif
+
+#ifndef p4dp_get
+static inline p4d_t p4dp_get(p4d_t *p4dp)
+{
+	return READ_ONCE(*p4dp);
+}
+#endif
+
+#ifndef pgdp_get
+static inline pgd_t pgdp_get(pgd_t *pgdp)
+{
+	return READ_ONCE(*pgdp);
+}
+#endif
+
 #ifndef __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
 static inline int ptep_test_and_clear_young(struct vm_area_struct *vma,
 					    unsigned long address,
-- 
2.43.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0BC12DAA7222E361%2B20240906082254.435410-2-wangyuli%40uniontech.com.
