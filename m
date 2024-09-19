Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBE5GV23QMGQEV4SAOSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EF2A97C2FA
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:57:25 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-7163489149fsf500535a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:57:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714644; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kd/TEnpukArXm5K3wTfzAQt+WE91tM4QUikW2ZUB02Ipyma/CbKCzWD3vOgP2F8/tg
         6aMiGGlCy1YkW2s3ebBc6Ra5F49frie6KWHYHR0z90FmkF+UzyGpEQWxBU6G6i+dOtHV
         jpuwGkUGOdZIw2LrsbD3kDI9XehYkEoLW9jPPkqnZajIwLggG9nTkTk5iffhtXriS/i9
         OlBowN1TrihTGoyzjloB4FZUseRj5R+tCwPuwhXQ3igoSoa6ksSntSsHKxoq7NbraReG
         BEqU4MWm33hkitA36h7TXLzK/0Nf/vRWKZmRni5kVdzbu955tWCfDOaV8sm3H1ZmxQ5V
         m4rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=wTird2D7Bx6HekmJvI32SWopy472v7uoiWobN9aZfe4=;
        fh=VhPMr8MnEn2oJQMXeM+p6YFjgV/3+A++x9sjuq7r0OA=;
        b=gB6RxozUUZ5wmT36Tys2jM8bJGA2L7cR3OINu+j60OL3dd+BTHCE4cHh7gaRJrR6mL
         /PL1lUgFptBmfi5/MIDDAtOwHB3HYgq7v1UTO5SJKwikoxlvqhDNTc4pBBshW5sR+q3c
         0bMLZnULi34r5tYyY/7DGt+3t2M1fujlZmmVop/63Ss6Q689VieB3r2wRVAFX0HAxLKO
         uRA9tMb4ZGCpp++TVZBUscL9jehf/FdW76sBrUxWaBfCGdKUohmhfv3rBt3+mIFsMvNO
         39/T4Ml+o+5OSk9RAiuFpM1ed9Oh0bBiKfD9wJYlbAO5QhwV+eGurUntr1xxUMx9y61E
         MLHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QCOq8oWF;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714644; x=1727319444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wTird2D7Bx6HekmJvI32SWopy472v7uoiWobN9aZfe4=;
        b=VJsICAKFp0HzR+L9pXuIq+Z1/AAKHg5BdCh/SIxFm2dPLlhvDqOOIuBMiLen10//Bn
         JaPUcOfR1eJjqK9NizOSsZOMeJj51cDkhYD0Is/5qErcQWjIMbsSluf/xeVdI2+XzIRi
         sWUOY3kM5chMu3hD11EfZZ1cXlzc2eauShjzHy1a4in5MZpuIHlGnD3cQUkipQcDR50c
         wOIKuNvCrVhCFDRMp66beRjEJNaKSSGY6IVBw855weNgqOUuA5KL4GulTb6rtHRcKCwY
         Bqfvo0q7RbqwqlENNtL7C7THMTzUgHUD5xxs3r2IUtzjroQmOH3rOilJTcYc7IChu+ZO
         j8Xg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714644; x=1727319444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=wTird2D7Bx6HekmJvI32SWopy472v7uoiWobN9aZfe4=;
        b=NNe2pb+JrR1Y1wkfBjGJ4f1pYxAl52x3P7g9YjDNe+zUZAo/827vCqgSlhuQMd061t
         Unz4PP8A3eljJgfdW6M61Tj65ORrTvqwse45lF3If46nkcelK6RIz+oDwhPvm17Lcl9g
         0wjxQ8HasWFTqjmb+GrCwN2rqAQJgDcD6bIl4OyQtPfSRJiI1z904IYREKqX2kaMt8wg
         jbOXrl46S1sS0ZQYuCJOzfuuRqqucMUVTi2Z06UfKF5OwjXfy++aFOjRycWIsy2Y559b
         /TdH2d0YBTcE32cxy3dzfsBW6wAgBAytKYAVIYBanhLwMKpHkvlc2M6GVvTeaYvaWC0a
         a3lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714644; x=1727319444;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wTird2D7Bx6HekmJvI32SWopy472v7uoiWobN9aZfe4=;
        b=uJKP1d67LN/dotMwuZuQsbH0XnU3GBqDZBBRWzbK6151F65OpOZJjDyYZPwLDzOdln
         zMdiiiIXp6y2vgDKyYcz2XfIZtBmqDPbjvDDhhmcEBSYUtpU35+UyL8bUZkGD9sMpkmV
         OfO8YBe1g4D7FweJvZ6mTGPAGyAuAvlgTjEtBtZzplFUkTZADNBH3upOiPPxq0f/1KLC
         J7BekkPYJ1MypTTJTHCFbaXyI9uWuBqmJhocRxVitJEdceGjVWCyDy/NCJ7ukMIYXX8b
         umAB1IiYbd/7s4mBFB3I0hHfEMd0jT6CIz6QV0auUYGTZ31bkJvnaoeSrPQZ8apx0/9L
         InoA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGG7A+hY8vWbNyzmIjE/yc/k49C/yMIidueENep3VeGsJjmiO28IvEq5GXY2FD4c1QFDNK0Q==@lfdr.de
X-Gm-Message-State: AOJu0Ywf4k2JiD6lGRFnxpEIFIcfBPMtKpIhrjYJFJpN0PvAL+1fCJ/9
	skhtGmXSWxcvub7yhniRvD5pzNeOnkqR8BbUt3ibrILiqAxnMiXz
X-Google-Smtp-Source: AGHT+IFuhqhoBiYasU68Kma1BsA0jCrWoW4/lbxpTXfDOlTTdn+VM2hJRbsARsI9VRl5Usnhvur1cQ==
X-Received: by 2002:a17:90b:4ac4:b0:2d8:8f16:17a1 with SMTP id 98e67ed59e1d1-2db9ffcc1a6mr31804528a91.14.1726714643849;
        Wed, 18 Sep 2024 19:57:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3b81:b0:2d8:f11e:f7b with SMTP id
 98e67ed59e1d1-2dd6d35dc3fls365681a91.0.-pod-prod-03-us; Wed, 18 Sep 2024
 19:57:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0eLPlvjR7fc4yhxeuESQmHWfGrEttrcKdIt3c6lEb11CC9pV3xgeDD7fJQVgdpJW+oIP0eL7jUi0=@googlegroups.com
X-Received: by 2002:a17:90b:4a4a:b0:2da:7536:2b8c with SMTP id 98e67ed59e1d1-2dba0082fecmr32804640a91.36.1726714642605;
        Wed, 18 Sep 2024 19:57:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714642; cv=none;
        d=google.com; s=arc-20240605;
        b=KbG/3voOrtTbXg2kzjCNigELUHZXpDVc029qG/BoF+NhNdk4dDsvgWuPzCcEWDDh64
         HMiJ83PGG4pImkWXZFJLFoF1hmWty7vXWYtFzAU7Nqpm71hVknbLd+FIlQrWOwSVrwmB
         1BavWStzfomZjo3e1GqeY12sElN9M00Tb53B8V4JohI9ttyOMJl3/gKfbQLstLlPLFG2
         ws0JmTKkQ5Gu08KkrfkhfwfoDjhGJnvxiaPlXnqkIp0YF/wpTgXqYFJiOCpwBF9O+032
         B9n2Rcu6a09GWym/EiZWC0DtGVMZeGB3++Nv9t8lnuL1V3oKvseZcBo7oRe/xNP80OFC
         wqhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=t5daj1tikBz1GmvjDxbc2gCsvgSNJoz/zYutj+6dtSk=;
        fh=NXGfaS8ye3QZv33qU7CbVqRPOb1HInK8fpMWAoecmwY=;
        b=NTRy4upmkk2tg6M18ikN/7vHRrdHHbvVsJhRlMind7R5hsgXk+4SF+c+lwF46GE0Wo
         XuBfsu3dcgupT7ACE8iDjor/Mq5bImYSadEbPNsBrTuXYFsHx6xISzk8LUUdM/I2Z2Vc
         i/HPmtydgk+ZXTElHHZxLNO04QAsAXERp7Ns8UiIgqFXRYBupXScLVXxizpaKAFSexQk
         XCGNCRnQIp36iDjmKFXbr8iCcxrF29/sob5tGxEnMPpbjiQDLt5gdOCMwuFEI9VmaCug
         G/mLBos1LwYP0ztWfHvsh6mGEeXG+RY/+/Z5Jy0inma183IHVEct2COUks7ZQQsRfwqR
         vr8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QCOq8oWF;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2dd6ebc25c7si50258a91.0.2024.09.18.19.57.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:57:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-2057835395aso4877265ad.3
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:57:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV/yCcg96KDapnVUa9wtCpcvwifLzrimSQ4NOL9QVp5OM4ob0fiHl37aFc8AjFJKd04gG7teboQcRs=@googlegroups.com
X-Received: by 2002:a17:902:ea0b:b0:206:8c4a:7b73 with SMTP id d9443c01a7336-2076e414901mr370597715ad.50.1726714642162;
        Wed, 18 Sep 2024 19:57:22 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.57.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:57:21 -0700 (PDT)
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
Subject: [RFC v2 12/13] book3s64/hash: Disable kfence if not early init
Date: Thu, 19 Sep 2024 08:26:10 +0530
Message-ID: <43e00322c775645a251c4526484d5bc61c62850d.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QCOq8oWF;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::631
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/43e00322c775645a251c4526484d5bc61c62850d.1726571179.git.ritesh.list%40gmail.com.
