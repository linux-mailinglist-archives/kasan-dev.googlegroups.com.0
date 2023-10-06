Return-Path: <kasan-dev+bncBAABBXOKQCUQMGQE7NMXHFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 813CE7BBBA0
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Oct 2023 17:18:55 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2c131ddfcfasf19514791fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Oct 2023 08:18:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696605535; cv=pass;
        d=google.com; s=arc-20160816;
        b=p/GrKZzD3NlhGwsIQXGnv7hXMixLIDdYtO2yiMa2MIfEaFr8pcVgf6YeEnIvYIYO7i
         HGVR1+8MvaJUnXew+MqxnJZyCbXrX8ZFaqHyUftwrD2p6Dp0J5USeZTryg6+Ds8R/VCL
         jJWsrtwLbsMkL5DBa8tXukQ3W3elYfA2zZEWUHSQWDw6VkKwYw5mTNR596ZURPbs0hvz
         XWgLlor/TwvpobkUvSlzzculsjwUuFZ5YA+kuwlDuIormaKBJ+fwbVKaa3IZ06iD4cPE
         lC1cONaEIFLtyhWZhuw0KoNu35faM4Pc0kM+WT3mXw7QtcuBIYRPj04DvNp3qEDR0VFS
         5jng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QCJ2+UCtBn7kDm4fXtIC7xYwnGLVtS3JNcwFEPGObK8=;
        fh=MvduW7TtfFJGfZiC/W6aaLQjI7EqApwiKAwimfBfFME=;
        b=Aq3LvJG7AmErIUcOPDqpzU+vT0lnGtynS2xPsnQdgAO9daFVQlUnNoF23EP+zrb4So
         rgcbju29r2YxMOIgp5jI9V4yH15MKCHuNd+02ZzrDVAn7fmpiA0x6G45hCFVziXpDNE5
         9xVAQMyd8z8gSAceT6WfgfIJIauC1t/gRPs9QNEBkrzPc0By7SeJXsUmLffFUjQzMW47
         GyiYvBOB8SDQxsNJh7R3Iajctz16En/0HHfbVDmVYaPQU7mRpbUJm0lyfB+srecIOIvB
         Eo7nnboOc2+4hukK70yVWgBAM5BubQyfuGxzGkafnKJfJeoa+vDQ3V5bMVenjZLwTtic
         Aq7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vlDt89zq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696605535; x=1697210335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QCJ2+UCtBn7kDm4fXtIC7xYwnGLVtS3JNcwFEPGObK8=;
        b=QLkbm/nTGjnM3YMKw9rmH6JsEtfsJGNsrRx+rUZ9DbxDMgMSOfrdLxG37jdh4UIWtZ
         bWG7taTjI6Unl1SENkomvtLcG+8PM/rxy8NnkGHjAkn6y6kn01ewlimfFUzLqR7xJGBf
         n6MtcsKjFjK8X5KxH9/riwijbC7+7bYHRRsziT2cM717J6TH6Q+2MuBPlsriFmAP0H79
         s5fLLVA+h4m/543nnkmKMc67YEqJipROf290zKJkGjxYmKsp/mACsCmX0B5O8629yBR3
         S0XBdtDrV+a/nwKePcmI4kzyXtDW6WgtzU0K5KRV/k9TuzzNRBJW3vlb6wVITQM2Tb8X
         u+nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696605535; x=1697210335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QCJ2+UCtBn7kDm4fXtIC7xYwnGLVtS3JNcwFEPGObK8=;
        b=dfeEVfp9v6Xeio31fpZdECnZLy/YQo0HnPP2MDj2PwunkYci8Ht5gkH1q4oOfNiFyH
         6hSD6YVy4wSnCvx1tWfxunFCHdWRsfamulsnbzNguPYHwVHD+f+lNxdMM9OVAkYDaJiJ
         n6+EDX0H6Gl7d18tpwWonM0ZReKPB1GHsN1puW5tVulnt3fsC6Zlg592mR08xn1NHVtA
         mhvLLvGxXYwpAgiisu58SMBmBeB8wxUXSSgkUpzRmADleYrdzZt5s+CAmDeXzsJ0lYGI
         3hP40fv01kCUqU8QM3USWrehKDWo1qlosVUdAcV0fOPYQl2M3OXdlw7WYFNrLQhuNIKD
         oSPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yya5UlMovI6BYgGID0PKEdvPq+vYROh7NjRPeyU/U7D75oWYQEx
	Smo+bhNQMFnR4Ec3RB1wVUo=
X-Google-Smtp-Source: AGHT+IGOjhKv0ZqDXdo4fjVEFv872ge5KL917Xxf9w0/p0RjGzXcgM/lt9IqVsS+aN98MDQbVTjYHQ==
X-Received: by 2002:a2e:9a84:0:b0:2c2:8e57:24a7 with SMTP id p4-20020a2e9a84000000b002c28e5724a7mr7978132lji.21.1696605533575;
        Fri, 06 Oct 2023 08:18:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1511:b0:2bc:e36a:9e4a with SMTP id
 e17-20020a05651c151100b002bce36a9e4als29414ljf.2.-pod-prod-03-eu; Fri, 06 Oct
 2023 08:18:52 -0700 (PDT)
X-Received: by 2002:a2e:98da:0:b0:2bf:f68a:b129 with SMTP id s26-20020a2e98da000000b002bff68ab129mr7140618ljj.36.1696605532063;
        Fri, 06 Oct 2023 08:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696605532; cv=none;
        d=google.com; s=arc-20160816;
        b=VV1p+VHSSuYMozCNFJ/EY3jlG1IdRoSuqNdZL/X+qROWKNyPyzhUuLZfel/wuMOAD+
         mLioE4V3nbru+lp873HE/zb2Tk1IE4vJ3aWaNdBVb/dULzCaat0NOJOz++Gvp5GheCtN
         QJhU6LvY/8tOEeWj1hwg3jerzZ6hNKYRX+5C9Nnim26IlKjMxYtx0nslaxjPDL4H4th/
         M22Wqx/Geveak4V6IgCpSBxUHf8hzV0Nk2ZgKAIgKWfEQ2mwWg0di20e4hEJcfvqASQW
         Pc6Cr+OjN0sguW9koDzkT6Kyxw5lZ7W4DrcLCI+xdbFDLDTqt+G/gKYMDjNQtSTBkwtL
         qE8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=d2bfkEo5JYZuK7Cv8VAKlPll7M52jynkOgAjxxr9P8w=;
        fh=MvduW7TtfFJGfZiC/W6aaLQjI7EqApwiKAwimfBfFME=;
        b=XJPLCf0acc2EUuyMCnLubbQNDOLxTSJFGyT1Hj43dNf8sN5hfqXpqVyKqPz/9aDPRz
         iCYXFwjs6y6IWqiEGPSvHhg62JLko79EooUWu7rsW5Sf/TTV7GqmmELeqbuycVXnNJVC
         GexZZLziA6jCXwN5pIoC/m+PhREJ2Sj8HeDq4YPnHjq7LR0vmj20rGhm5JGG8mP6uT6z
         bPjKQFjRdy2hGNBQFLqPhzEwMj48FAI1TN2pUn3RcfUVHma7UzmGVI7AwGT40It9/HX6
         fiA+WGDOTgmbMdXhKgmIoDSGJ7QUYjdRys5FtfVoO9/geaoRR82xkaaxhhUU+Y1R+aTq
         OEkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vlDt89zq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-202.mta0.migadu.com (out-202.mta0.migadu.com. [91.218.175.202])
        by gmr-mx.google.com with ESMTPS id n26-20020a2e721a000000b002c282c67bfasi212199ljc.8.2023.10.06.08.18.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Oct 2023 08:18:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) client-ip=91.218.175.202;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 3/5] kasan: use unchecked __memset internally
Date: Fri,  6 Oct 2023 17:18:44 +0200
Message-Id: <6f621966c6f52241b5aaa7220c348be90c075371.1696605143.git.andreyknvl@google.com>
In-Reply-To: <cover.1696605143.git.andreyknvl@google.com>
References: <cover.1696605143.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=vlDt89zq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

KASAN code is supposed to use the unchecked __memset implementation when
accessing its metadata.

Change uses of memset to __memset in mm/kasan/.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 4 ++--
 mm/kasan/shadow.c | 2 +-
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ca4b6ff080a6..12557ffee90b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -538,7 +538,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
 
 	start_report(&flags, true);
 
-	memset(&info, 0, sizeof(info));
+	__memset(&info, 0, sizeof(info));
 	info.type = type;
 	info.access_addr = ptr;
 	info.access_size = 0;
@@ -576,7 +576,7 @@ bool kasan_report(const void *addr, size_t size, bool is_write,
 
 	start_report(&irq_flags, true);
 
-	memset(&info, 0, sizeof(info));
+	__memset(&info, 0, sizeof(info));
 	info.type = KASAN_REPORT_ACCESS;
 	info.access_addr = addr;
 	info.access_size = size;
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index dd772f9d0f08..d687f09a7ae3 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -324,7 +324,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (!page)
 		return -ENOMEM;
 
-	memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
+	__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
 	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
 
 	spin_lock(&init_mm.page_table_lock);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6f621966c6f52241b5aaa7220c348be90c075371.1696605143.git.andreyknvl%40google.com.
