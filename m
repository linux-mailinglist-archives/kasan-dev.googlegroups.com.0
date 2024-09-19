Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBBVGV23QMGQEMMXI22Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 73BC197C2F4
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:57:12 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-6d4426ad833sf7231247b3.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:57:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714631; cv=pass;
        d=google.com; s=arc-20240605;
        b=dVpClLcoH4EGNpcdOl5ZdwTsIiYuMhr0kbcWlvEh37DJSt0qPUfw04wUtBZfpJAOCy
         95NrwTAO35x2c3XkZ49pdRQaXZU8waKAq7Mc2Vg7CwpyQ9n+lhCuySJuknOogXU16Vw/
         lmVjZakuELEso1hFr4QcY4RdrzXzeQKdl9V5Sc4qCeMLJ6hXnVvtrKbbGkTW78Cb2Df/
         Qe9XdTWiTmyIK+C+r67P0d3gerBgwzHydCEYugqv4PkC4vbM6Yavmn5aaPfXXjNI7rq8
         00EV/W5hsB5Mlub1PP8jLdSUpb7F2snoTs7gHE41w6T6Vkz4Gi0vRl1oO+AEZCLdAgkn
         CKwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=RTAo9yL6uijAfdWRfQ6IG978d2vArJVv6IJWmCd6mNI=;
        fh=9dW8h4CcVxJoY/mFeQZ31WwuHzZRyrnxw3YAtW+U14g=;
        b=Tz0gwbcUjswhn6qxesZiD+GIIxA58fgivUeuNF1v1s7eFbtfYio4q61bAkVkPhv0Dk
         +R/wfT6JLCT6NZDv0eH1Y3mva6H2SQbqIm4mUghbQugYBv4xlrV9Jepe/SR/MsFIk9FX
         1aA5OIbvHpPTj36+2+0xnu2c2fZDX7yUbzn1zFO6msshNAmdYTOpZP4Rq6sKSS9HfhRI
         z/2iUIMF0NT1LR4PaF6MeX129Tal0gFioQPVpok8b4lHLKeTtdjzsMAcGGLi1hbzmXo7
         WJivXMQRIAd6972J0CDLLzxJqKxqMZ/tfY8da14BTkqxoduZeWbWblOLrjBO+loitrKX
         qUng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Krd8l94B;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714631; x=1727319431; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RTAo9yL6uijAfdWRfQ6IG978d2vArJVv6IJWmCd6mNI=;
        b=lGvvo4Likcb1tG2esSCW5MgDu88ZpJ6CBuoiWHXdVvOskIBGEFqu53a7PWY2NkFhxa
         Mij41zPyOVln4t14OhlsxgFRSmuO9RtjT78Mh2pmf6NHvTlI1dkjXq//IRd8kgOcVoZl
         Elo7RvHREv2T0L6u6wMgqfx93cYZKK9/a3iCmKupRYskINhvWKGdEER/uLzXSJl2Mce/
         jTHpgDVOZ6HarNzMzQJwflal3jCNDiirhdvfXZV1FE4r7aTglJ/8ViMX/mFG+i3Zf0pb
         75zgBoHyzR58w+lzGp2fPo2M4BMcaGGFJbnYLvzs5SJ+APuAybRFDtdegaoy0j9xh15x
         ZSjQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714631; x=1727319431; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=RTAo9yL6uijAfdWRfQ6IG978d2vArJVv6IJWmCd6mNI=;
        b=MoWvqzg1q8XApCh7ouyPvUvrw2mh/iCsOabRTScD2hR8PrpueNdZTDmfWxisTk2MtW
         aZRt7xCrhgm8WbrEuUx4p7Vdv6UyNNfsnP9ATPKMl7Cc7kyWIwYxruowW20scMX2lunj
         vq2HOfyFkoX2c9M1Fz0SdXGCbipE4JFduYjbEzke1Xb4JSeTEEHyH9skzGk2h1ZnhWco
         TZMKJT97fFCyECiMRO3XJqw4qMamJ+TiL8gyWdhkq+EWt4pMW75ug2jNv4I/sHrgxRIr
         ruHu7EJGL0zTZ//EL928Fb2ZF5DGOrTamMSkTrv14n2mjVmUhaRlRgMVm3JphQUc3EWH
         sbUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714631; x=1727319431;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RTAo9yL6uijAfdWRfQ6IG978d2vArJVv6IJWmCd6mNI=;
        b=l+SDwSzcAJNeDsna8cmExpvNcPERw4O/eHPCOgcG8TbT+7NTMsk5W6FIBiLpyG50zj
         jMx5y96d12MyLlXUbnRQaZOciPHo8+YoIMd7D7IHVs51B28KpK6wgkPFhAlrVrEWMMvf
         xo0fcVwUw3Ole/R07/49C9hHXEkhLpyRjVBf49WjjNVk+y0hccbN+VASCb61sS1BcdsM
         OyFxeAMzEIW4ZhLpa7tdewTtBIAGlPFXnolLK6wM9/prNbUq0bVejpzgeZE9oq3wvgWW
         xl5QzdQU0cvO6N3lv/TTyYhgbnB7jrhlXj0YNi90FMkuwc3dhTRFNE9D1LPICI0rHzxi
         zxEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVG6426Y6APUoEgcGj2kAeoNDvkoOnYZH2yR72ISMEaPQBZlCjTBExUugIm16m61rgTR8bDw==@lfdr.de
X-Gm-Message-State: AOJu0YxmbZcUwsTjyR+4lDZHyaa3F78tEXLcc0kBoaKmJrRaGKBty/Jr
	GH/EDi1tj1vgbbuw9gRXorjBQS7ww4y6DXOyv9/Pyrsc25gR3nhV
X-Google-Smtp-Source: AGHT+IHOmTOKqQ9H+Qph3MEPhDe/Qk9WMwTlmxpYYvsVWssLbckrXRxU6wc0/0UD3KH3y6n/F4MZBA==
X-Received: by 2002:a05:6902:220d:b0:e13:e0a1:6bf3 with SMTP id 3f1490d57ef6-e1d9dc5b629mr17125391276.47.1726714631073;
        Wed, 18 Sep 2024 19:57:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:18c9:b0:e20:db8:7862 with SMTP id
 3f1490d57ef6-e2027e5f588ls558021276.2.-pod-prod-02-us; Wed, 18 Sep 2024
 19:57:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqjqOIVZr7NwkGZiLZydFnZO4pl6SjrlIbaZVeDc3z+tN28WAt1l2X5VD4UHvnIsoJ9jpO23BsNDA=@googlegroups.com
X-Received: by 2002:a05:690c:110:b0:6db:c12b:4d76 with SMTP id 00721157ae682-6dbc12b4eb1mr157808197b3.29.1726714630311;
        Wed, 18 Sep 2024 19:57:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714630; cv=none;
        d=google.com; s=arc-20240605;
        b=Mx8XoHt8AtzQvpSkVoGYGxkBGUTGW1AcXYak4IGQPzbvL57Q4UHu12lbH8mxH6CxDk
         q9AKKTqvu3n0YG/C/Wg4QERshiMDAv5YexpUjQvpf7BchzrjUqR/QHFGiuDnrufc8OHh
         CorWA6TkuXE4FkVirl5QqvukYuWPoey6lJVbWNzBLYOXhtOKgmH51BtpXm8fnr5ostnu
         YYnlcHfzLCuwLwPFmHizP5T0tF6Xa2aA5YZcxz3AK/BjGpsrR1jN00RJVsXOuMbfB+e5
         QoafFszkG2U0Ep8WmkMl8P1yooppK5Tn0WF83L8A3mOAH0zdAoaD8H2BpOGBnKanOrob
         holA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jpwPGGqxMjTTALmPRltkI2obnVC0TIxSM0BTVcrrVEU=;
        fh=XD6CkjJyHV0M3gMrJ85W4LmGcIP14u43S8lxwHMO0sY=;
        b=a1sognjRukdrJzCHHgQLKX+ekouoW//uLTR5YWSy4XLJANUWcoU/9P2BOPo4ssGawu
         LOrkk5qL8GPGueetr1gWjbosTr8Jmhhc/UnlTEe3r5H8fTcpjJaL2ipTvLxlOnrijfUj
         ZbGSA+A+LdRxqxbTw+TdYhYOr7jBAqE2l9uRIkneRqEN6cUMjLwBPjaF7glaJsCcLuBF
         VJFZsSzzdW5bCHv1HOApsGxNJ4m0zjpiRRBIW/IAjtLKCd5kBvHG3WIHoQW659Okodvf
         HZlkpYTedZbMd6C1FemIYBQklhAgVHmtJQNdQArwNe7Rj7JB8RPXChkLNEd9V5Dk5vkC
         FCNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Krd8l94B;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6dbe2ed969csi1329377b3.2.2024.09.18.19.57.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:57:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-2054e22ce3fso4209805ad.2
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:57:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWWYycSGSZfQH1OI+6VhBNaIM7zIpRv359N+UJQPLaKHauvEp3ztVm/1/xjLA8DUA7ac6CKJt36nP0=@googlegroups.com
X-Received: by 2002:a17:903:2b0d:b0:205:9220:aa37 with SMTP id d9443c01a7336-2076e35f0a0mr358517625ad.22.1726714629566;
        Wed, 18 Sep 2024 19:57:09 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.57.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:57:09 -0700 (PDT)
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
Subject: [RFC v2 09/13] book3s64/hash: Disable debug_pagealloc if it requires more memory
Date: Thu, 19 Sep 2024 08:26:07 +0530
Message-ID: <8fa0c82332bfaa4c4766372ca0573021dbd8a85e.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Krd8l94B;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::633
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

Make size of the linear map to be allocated in RMA region to be of
ppc64_rma_size / 4. If debug_pagealloc requires more memory than that
then do not allocate any memory and disable debug_pagealloc.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 15 ++++++++++++++-
 1 file changed, 14 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index cc2eaa97982c..cffbb6499ac4 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -331,9 +331,19 @@ static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 static inline void hash_debug_pagealloc_alloc_slots(void)
 {
+	unsigned long max_hash_count = ppc64_rma_size / 4;
+
 	if (!debug_pagealloc_enabled())
 		return;
 	linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
+	if (unlikely(linear_map_hash_count > max_hash_count)) {
+		pr_info("linear map size (%llu) greater than 4 times RMA region (%llu). Disabling debug_pagealloc\n",
+			((u64)linear_map_hash_count << PAGE_SHIFT),
+			ppc64_rma_size);
+		linear_map_hash_count = 0;
+		return;
+	}
+
 	linear_map_hash_slots = memblock_alloc_try_nid(
 			linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
 			ppc64_rma_size,	NUMA_NO_NODE);
@@ -344,7 +354,7 @@ static inline void hash_debug_pagealloc_alloc_slots(void)
 
 static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
 {
-	if (!debug_pagealloc_enabled())
+	if (!debug_pagealloc_enabled() || !linear_map_hash_count)
 		return;
 	if ((paddr >> PAGE_SHIFT) < linear_map_hash_count)
 		linear_map_hash_slots[paddr >> PAGE_SHIFT] = slot | 0x80;
@@ -356,6 +366,9 @@ static int hash_debug_pagealloc_map_pages(struct page *page, int numpages,
 	unsigned long flags, vaddr, lmi;
 	int i;
 
+	if (!debug_pagealloc_enabled() || !linear_map_hash_count)
+		return 0;
+
 	local_irq_save(flags);
 	for (i = 0; i < numpages; i++, page++) {
 		vaddr = (unsigned long)page_address(page);
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8fa0c82332bfaa4c4766372ca0573021dbd8a85e.1726571179.git.ritesh.list%40gmail.com.
