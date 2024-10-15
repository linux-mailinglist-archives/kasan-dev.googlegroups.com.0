Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBHUNW64AMGQE3XIRAWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AF8F99DB98
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:38 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-286fa354e34sf4203517fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956063; cv=pass;
        d=google.com; s=arc-20240605;
        b=ArMB1Ol7+Jm8c5XJLJ76oCfkTCBDd171DMCLfrIUOgsD2qp8XLZBVsjpYhgi6KVdu8
         75yuFlsxaOHF2jUJZVZGbp0EaiwxUR0nKVBeeOH+Emch7vPe3CBE/98mGRanWQrfqR/M
         PTdXMmt54xMdM18mHy03qO7Fmq1EeGTrkaSNaBo5Pl5rSPGrDeTsUQOCz2imxXcFASMB
         G58TOveU1+NF21ibhDRcZ0fm3cbZXZMXfILtbvlASomqODQITHFgOFTjWgqxizuCccdw
         JBeDKaapQVe6N16gaA92jElRI1WI/B6K0Ff6o2CJwh93Ka1Nq1Bsuf9MAE/61KaRVlyA
         Cp1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ihnHJG7kgU1WyNDJBw1svWzN7041fsCqHX+8F08upcY=;
        fh=rV0ZVtBqRuaE+Gk/CFYOM2nZ5oQ266xA48yMIZ5afCQ=;
        b=EOPVyeLZmMtMYeNJgIEwl2qFvU7McyiDjgSVoZRPJ35tyi5E//LwOKx+/D7f4iS79N
         5KEgB30/E21qIQ2AnogmfUXiHqXIj+bD8PZvP67elXU3dJu99PvNBFbPYKO3y32j0pK5
         D7cPcBPTZcFvJQroc9m4C9kg63MN4Hcf1umtaqcUr+xodPaUm0Xam1nYGiTVxQWcoc5N
         5sH5z82zkav6ZctlbvLLdCas+if891RjQyKl1MVWR+wujKPaykNapORfeEz6l4iUE0fi
         F43MS+8/8aRGABGSBzYJFmdpcuOeKtQUMc9L7mr3LMXYbb7jfT4ZduGLCvW2Bd8oYanE
         avlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fOu3YZhS;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956063; x=1729560863; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ihnHJG7kgU1WyNDJBw1svWzN7041fsCqHX+8F08upcY=;
        b=ArmRwPeyn5Ip4T1oZ4CcY+YMJY98KLTH7tJOTy38USXLoD34K9cpO+Afhg4xFEFr48
         yXH8xvsnRIuX8B9dENmNfRpfQOekPqwl8wehZmrlUqQJ81coOnQgH6DpdhrENoxe0HSV
         dGODV0qToQvjsuWT6jZVHBMsnQTCI+kEAT4Wwd7Yd8/Q55oJ3Xvw1SLD8mR3LW3nvWJV
         dwGTsrInmrYmtVh4ca+l/Hdol3lUNfd5PQrX8GGYCZBHE7P1kmV5OA8j80Hm23K9uCfl
         ICo4KhDQlOWtfVfKoaXfnQheR3G/xpeaF0MhVXN+sp6qOAhGRvMWn9eBwcsTr7dkjqia
         YsWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956063; x=1729560863; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ihnHJG7kgU1WyNDJBw1svWzN7041fsCqHX+8F08upcY=;
        b=Ow5kxjK/gfOAQ+uyXZPQyitNn57RSwi2XOecd2TNNCryYBVHiMnBOgiv7bKuttgxQZ
         7Ti7NKkQD+8M9+iqkHJm8x1C3E+JPRiBVXjJ2TZuK6rRtRHSwkCe4kBOHsMKjzH1EHgc
         MoEj/+xdyBsqgAJZitVwQOWdh1vhFppc0h8MbsU8BPuFETMv2PCRCt/1bOhriV/sN+Hh
         TzxVTVOjVT4CJ4vm68P5VZ4PACDH/Zf6KQJwTXkkWalyNEKs2IT25Mym/hgSUoIpT56U
         s0dYulwuzY9gv3kurs/afcbY17W4IbHtXggsVwnTfzcItmxWuf7SkAPmvegsDeeEd8OR
         CBrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956063; x=1729560863;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ihnHJG7kgU1WyNDJBw1svWzN7041fsCqHX+8F08upcY=;
        b=c4MLRSpi3eHCet3h35jwqEJ9ZQk8c5koCBePg9jGz661l7tqG0BxfWTtQ94v0bCDA3
         0NDNrFbD4638OSkigDfdXSc++K16tdqLR50/+VmTD2rKPk5P0+jT0np5I2Sr9NXp0IXT
         ObpszeIpQYX7KPg3IZow5eY7EgrhiNG2oAfr5iY+CdoO0CgxccqrkwilPkhYgOYaVfXV
         oHcFmNz4DKQ4WatOzzfqbcCB4reppwBDvOipWNBmsXusPMCKsV/qRdfn/CopYbCN4eTq
         EkrH60l0pe44JUlp44eJZ8QmzGHWXcop0b/JGDRr6c0HngwFbT/IhIMDTKr5ntKUUBpW
         pVhg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWZ4VTtLEIG+ZzkzZQzPwClOOHTfAO6jgVDUwIReztUYVIvcHOEstT0qhrfNQrIKBL7LFuCyw==@lfdr.de
X-Gm-Message-State: AOJu0Yw4blLiDB7O8AB1Pjde6SLeleXMkrunF0S8tP7IKdS4UG2DhYAy
	KPuO3p78mXnXhbsoTHvfO22NeAj4O1wuHmB97YrHn9wkGFoGXvtw
X-Google-Smtp-Source: AGHT+IFVdr4DsOJYd5WYa+fxa08Uz/FLpF/wgLCnsLAtHIItvsBhYH616caNTKF5Yfghj3FF6CBz0Q==
X-Received: by 2002:a05:6870:b514:b0:277:d360:8971 with SMTP id 586e51a60fabf-2886e07b24emr8830960fac.43.1728956062698;
        Mon, 14 Oct 2024 18:34:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:580b:b0:288:93de:9ec9 with SMTP id
 586e51a60fabf-28893deb32bls701946fac.2.-pod-prod-03-us; Mon, 14 Oct 2024
 18:34:22 -0700 (PDT)
X-Received: by 2002:a05:6870:854a:b0:277:cc6e:15de with SMTP id 586e51a60fabf-2886dd5a731mr8298376fac.4.1728956061864;
        Mon, 14 Oct 2024 18:34:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956061; cv=none;
        d=google.com; s=arc-20240605;
        b=Dl5nE8oISJKl3Fn7g7CrmMCcaAXdOrbmsUZQDvOlAeePaGLPUciSDFTcns8g47ANoy
         U3FDpil+6LZ1I5b8pwJz/UlLwmhX1cedtlju7d+vTmXHsevtaSeYy+9Sl6tv+kaIkHcB
         StVzDmwpYnRs9SVoWoGkv6guZsrCf1bs6X7KP/ZtwK/Ve00gdFW2FOmHkA0HqNw+TNvv
         /BXPkt3xSZe1LC4xZ5PM0c7QQAf9Zqc4nX53qvvKHXElnCyIpp7ybUBxqlHUHWLQAhHR
         e2GH10nsLp87L+sXd/ZsXGUj6+O0kIHVt46wwFEoMYJtcfxJeGItz+wSozzwjkDdGwyO
         K1qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oTnklaF1aF0bTWeWldi91Sj9bwNgHQZw6gVAVQdUYd0=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=O1nqsaNgKw0V5DOblHMqev40YmUbOqEpzNsiwrYvMWtmJIUOYjEIH91eDkmasjwsrN
         yqm8QyTniO09dTYkV9aObAsjSCR/vmSAeiJ1PJw2UMBpiTYn/XPXDTBk2yp2pl65Wn64
         Bm4wyIVPgPxKHAzVhLYMmrql/zrCgnNRb0kEVB+hgBMO4gli3Teff2SrU5ZthuBZCPdl
         j6E233NZKpX3R/58hQY/OOf4ckUTrTo8D005nI5DJ18jHeQDtd2SJQgIggc7pIcbWxpA
         g5xv0S5zHFbDqfrBiMJTcEyd70m4EeQ8mbKjsOD3rK/7YaplZ4kaVMf9C/8MYNAOaBG2
         slAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fOu3YZhS;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-717fba431f7si12435a34.4.2024.10.14.18.34.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:34:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-7ea78037b7eso1812987a12.0
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:34:21 -0700 (PDT)
X-Received: by 2002:a05:6a20:cfa4:b0:1d2:e92f:2f48 with SMTP id adf61e73a8af0-1d8bcfa7ef1mr19096796637.40.1728956061028;
        Mon, 14 Oct 2024 18:34:21 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.34.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:34:20 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC RESEND v2 07/13] book3s64/hash: Refactor hash__kernel_map_pages() function
Date: Tue, 15 Oct 2024 07:03:30 +0530
Message-ID: <efa3cff65f71cf492702e835250667cb976b9e6d.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fOu3YZhS;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52f
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

This refactors hash__kernel_map_pages() function to call
hash_debug_pagealloc_map_pages(). This will come useful when we will add
kfence support.

No functionality changes in this patch.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 030c120d1399..da9b089c8e8b 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -349,7 +349,8 @@ static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
 		linear_map_hash_slots[paddr >> PAGE_SHIFT] = slot | 0x80;
 }
 
-int hash__kernel_map_pages(struct page *page, int numpages, int enable)
+static int hash_debug_pagealloc_map_pages(struct page *page, int numpages,
+					  int enable)
 {
 	unsigned long flags, vaddr, lmi;
 	int i;
@@ -368,6 +369,12 @@ int hash__kernel_map_pages(struct page *page, int numpages, int enable)
 	local_irq_restore(flags);
 	return 0;
 }
+
+int hash__kernel_map_pages(struct page *page, int numpages, int enable)
+{
+	return hash_debug_pagealloc_map_pages(page, numpages, enable);
+}
+
 #else /* CONFIG_DEBUG_PAGEALLOC */
 int hash__kernel_map_pages(struct page *page, int numpages,
 					 int enable)
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/efa3cff65f71cf492702e835250667cb976b9e6d.1728954719.git.ritesh.list%40gmail.com.
