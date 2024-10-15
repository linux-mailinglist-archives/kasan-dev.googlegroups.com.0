Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBNUNW64AMGQETF2TMVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 696FF99DBA3
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:48 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3a3c27c72d5sf12638615ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956087; cv=pass;
        d=google.com; s=arc-20240605;
        b=bNjvM1TuSsBKFocvCesS92IxbGiuCf7raOYsWxFm0Kv8tdD8jOrejys+3smq7jFf1H
         rPGPouRFae4xEe+UGIFijgkdGFYlF7B4aAQ+YqLAshfplQ6CMLgveId9pMUgkFbTI996
         ItcVlCCtH3mOLJZYj+BVr2NicIOk1B9Yltt1w5UK/uzhSqTHdZQbydXjIRhc95uw0ZFs
         TjYdi6M780doJRvrfF9b+aQUfhmB25GbX36woPIXHm9FowRHHaMYWSMjYs7yxjiBluoC
         e/nfZ6edzIGazhtoY7xfHCGRp7HOlM4L1tpL+4eu+lfZEulVquALjTc8wZHurPk95teH
         fC5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=wQz177TtIxsy8BbfuH2WAyodHt+Ybe1Nk9/gZHYLYRY=;
        fh=Qk28ljNB/nS5hZ7vDutrbm35D6iRwbVbjl/6OJjq7s0=;
        b=Tm4HTZpwEGDAMglj61RMhRnPutzjxUxys6Grwa1EuiASNj9qsTZexBxr3a5slsZHOK
         out0PyQzAehEw+qaLJ3K7b5Lx899ID7Pl/wpxZFZZ5ZiOOkYIU0OQPXVmMZvv046j8Dr
         b6RA/QnVdc137TbWZS1rnKLFlW4B7GeESp7E2MTI7m6se3c1nZFc5y1JH8FH80OL0ifb
         ynUo0cjZNacs/qeDjYnig1Arx3JiMzcaRtK7b4mkdMV+c++RNXfvLX830q+35T3Yvnj/
         XehdYB+dmCqbuMIYHN9TJDUPoJ33KUHx/q/Ds+3QYUKaMzcqQ+qwjWgb+s7bukGYCJVG
         XaXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SLiNRUhZ;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956087; x=1729560887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wQz177TtIxsy8BbfuH2WAyodHt+Ybe1Nk9/gZHYLYRY=;
        b=NmjfppxOo8RzXX7kRns72wJhq27k7k9brCad362gBVUD803oRwS2z7At4qixeWo2ff
         CJ/o+Pn6AhTWOGMReeBGwilpj9iZRItxjzx/J8guMqLO9cHUNmYSjlYjSOFxjjaFlIxU
         qw88UeTRmUhT5AhIJwIRTrxmUTc/U0aAXRJfM1h4RZ4Ul9VDVzknnx3V+h8AemcUm+Ea
         tIbYFHWzxMRtCA1s93LOR7U+As31zBHUn7tMevqDQdJJOZHHK9rDWOGQdck915XG5LPN
         pMC0+yV0hQ9M2EolyIURdbgSPfa1bDfgEdFJUQelpcieStXE0qfJPfVeKIRx0KZLgWDq
         +C4g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956087; x=1729560887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=wQz177TtIxsy8BbfuH2WAyodHt+Ybe1Nk9/gZHYLYRY=;
        b=SKiSVaYsa+a1mEFDF/zts6JZDVWxagvKB/jUKyhDaEmHrhz4ybnhacul6K/nUMh4pm
         kxV37t/sa5CJsPZ8/E9YfNZ1Sq3MIPLIpW+48jkfj5vF37AEWLjMNRectLZtAQP9WT3t
         LRx/WxsvGfVSZDaaRabf1nZ5HnkrFt6dt3/vnzidWJ7EOTM0Nc2NWsTyL6sJMQT0BAw3
         dmsdtstaxQa5TnrwIxVIKoU1py9TX5pRQXgS2JMsJte3mMBpWMox7I+Xq3yUqiZiy0zq
         yBLdDW1SfucLXOvoZzu+o9ebZyQH5e1vuRAZQrbIdIK0EVerr3/FW260B36yI4Qr7Smd
         JaBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956087; x=1729560887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wQz177TtIxsy8BbfuH2WAyodHt+Ybe1Nk9/gZHYLYRY=;
        b=kuLAwjHN46VlnZMxLPSuRrtyfRPiBdae9NOay0RkX/sdP4aTGL/fETJv2j2CSiNbyX
         gTUi/YeH58VI70mK1zmvTGT+LL3IVBei2pIv3ifntCO4Vk3oky00irm0iNF7UpikGrP4
         EVXcNoNA+I46lDwcthZFrA6xZ2ZLbWur21pqNlhi7vetC58ZoNfurqTKyusg/5nGHOrO
         o3IuB8gYc2NmJsIF4G3o6jbq7xzOpAZ0Jc+9vxGpThXU3cjC9pkHk31Tt8e68cMa1brx
         FXXLU7QUhAm1W3WGzEWfYyQFjh6Qz7lcE2soQt+QEWIaKIbMq6PC3HbH4z4SXN9vEUjT
         VjtQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVaZQmeHy/AL3osSiYtFHvhdYdruJpyprAfZE0vnpAPPGmtAqjqjip4Muh8avRlQH4FJq1UhA==@lfdr.de
X-Gm-Message-State: AOJu0YxwLh7io/tdS7bcVhfEyQ5cPYPBg5vjK/eTDKl8k25/WXSSKB1S
	E0cMdV1rSbByiRhDkmiQv1eiKC61AuwH15iYOcGL08L9a1SXf3hh
X-Google-Smtp-Source: AGHT+IEywFmr/wwvf5R74CvZqwioaOu1oqk5sXNu4YvA5SdOT9AxSQ3OJM8JkhE0W4od1AOgojQNIw==
X-Received: by 2002:a05:6e02:198b:b0:3a0:9c20:8070 with SMTP id e9e14a558f8ab-3a3bcdf03f4mr65420725ab.20.1728956086896;
        Mon, 14 Oct 2024 18:34:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:b49:b0:39d:50e8:d14 with SMTP id
 e9e14a558f8ab-3a3a742b26cls5098735ab.2.-pod-prod-06-us; Mon, 14 Oct 2024
 18:34:46 -0700 (PDT)
X-Received: by 2002:a05:6e02:1caa:b0:3a0:bc39:2d8c with SMTP id e9e14a558f8ab-3a3bce0fc22mr75670745ab.25.1728956086044;
        Mon, 14 Oct 2024 18:34:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956086; cv=none;
        d=google.com; s=arc-20240605;
        b=FMw5WgrFV21dAd2YH4PjOGOZX9lWdm/+HDaaj1p3PKRcy9GPo2T6Ibo20Uvoihab/l
         jrKHzjFewBalRLGzEq6DcfPuw0CLio/yj3HMf4BPzmhp84SFPkAB4rhSAXtfMobT4CNa
         0S2R9IkJ7Plw4CG509kaiGYDb8vrOJr0gzHYZi0rnI5FzLPoleEBcuxNeS5o51MWG7kN
         xMz4prx4nAXOC8rHb+O7pCDoAEONsNQxBWju+g+/lJWNxLMt+/86PcdsjQbWkQl6niXh
         xM4nshBuVPROCFwdXFyJo6nPXFXMd656zWird+oEUOL9FpYCPaBwCUaGYZP6UgZIKKEQ
         qJLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=t5daj1tikBz1GmvjDxbc2gCsvgSNJoz/zYutj+6dtSk=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=ShGJdvh1TU7HX0nuVcWAaX8ju8w9Ffd5+DqfVYQ8+63WSZidqy4Bv9W56LReC2HLqH
         VjvUc1R2LvGeL06sUL+ORF9cMNJTV5YLI2BnSPt4XfiUYT/T91Bu8Oq6XJpCax6qYWvC
         s6yWEumXjFLhKF9YwEZKwsSGZCUBqFJ9tDf4ZTc7FrSbkh9Ev3u1phC1eRvu5bXYDr9h
         +abssl07z1GMqLifuNsUzfoFEMabYPu0AIibbQ9XIaO1gN6dcI9fngN47E43R2MpZKJF
         HOB7wEagj4ZuZCQr4wbCl/IYkQE5Vo/zyoxVvW4rMDlIJMm6ndFNdIcjsp6UwgLdCg08
         MKdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SLiNRUhZ;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a3d7165c8bsi132615ab.4.2024.10.14.18.34.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:34:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-71e4e481692so2399802b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:34:45 -0700 (PDT)
X-Received: by 2002:a05:6a00:3e03:b0:71e:3eed:95c9 with SMTP id d2e1a72fcca58-71e4c1bfba9mr15531178b3a.22.1728956085196;
        Mon, 14 Oct 2024 18:34:45 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.34.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:34:44 -0700 (PDT)
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
Subject: [RFC RESEND v2 12/13] book3s64/hash: Disable kfence if not early init
Date: Tue, 15 Oct 2024 07:03:35 +0530
Message-ID: <29cca55915a923d1823644b37fa571234f9ea549.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SLiNRUhZ;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::429
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

Enable kfence on book3s64 hash only when early init is enabled.
This is because, kfence could cause the kernel linear map to be mapped
at PAGE_SIZE level instead of 16M (which I guess we don't want).

Also currently there is no way to -
1. Make multiple page size entries for the SLB used for kernel linear
   map.
2. No easy way of getting the hash slot details after the page table
   mapping for kernel linear setup. So even if kfence allocate the
   pool in late init, we won't be able to get the hash slot details in
   kfence linear map.

Thus this patch disables kfence on hash if kfence early init is not
enabled.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 53e6f3a524eb..b6da25719e37 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -410,6 +410,8 @@ static phys_addr_t kfence_pool;
 
 static inline void hash_kfence_alloc_pool(void)
 {
+	if (!kfence_early_init_enabled())
+		goto err;
 
 	// allocate linear map for kfence within RMA region
 	linear_map_kf_hash_count = KFENCE_POOL_SIZE >> PAGE_SHIFT;
@@ -1074,7 +1076,7 @@ static void __init htab_init_page_sizes(void)
 	bool aligned = true;
 	init_hpte_page_sizes();
 
-	if (!debug_pagealloc_enabled_or_kfence()) {
+	if (!debug_pagealloc_enabled() && !kfence_early_init_enabled()) {
 		/*
 		 * Pick a size for the linear mapping. Currently, we only
 		 * support 16M, 1M and 4K which is the default
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/29cca55915a923d1823644b37fa571234f9ea549.1728954719.git.ritesh.list%40gmail.com.
