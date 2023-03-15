Return-Path: <kasan-dev+bncBDKPDS4R5ECRBU76YSQAMGQELEX5XLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E8C36BA5BA
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 04:45:25 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id t2-20020a17090a4e4200b0023d27ab43b3sf305356pjl.7
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Mar 2023 20:45:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678851923; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vzar+TEA4eqnDJNp+SB0EcnkOf2snuux+0hKYwiEfPKoEtngIDQc0UCbHgItrbHlFn
         ZmeL0a0jlJswgJHEKDTtQ+NIzpjdGMMW87JYFz7kvJdjHjCt+e/mF8epjTYp5NMhQazv
         aXcOtHn7mR21/3VckpC+mPWQbDB51HvqbfXLC36pwROkQTcQ4uxHmTJOmTjD9SffXnlb
         VODSYzb9oMrKpg1cdKAkar+uhUuaZpX3HakU5/TKqBE78rDrraL3SHq0ZcTVKgyy6n0C
         8OQFqakUF4D19Pv54vXopNdiEZJ1UwdDi/9qxuKdEFsjzX+sJ6YscUXzFCrgNNKgppiQ
         eP+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=m8rKOpMbEgxZl54PyAN8o9GkkaFtewew5kzmTSUt678=;
        b=t4wgsEa7WwRf1Nc2hz9GT6XUNo28LNUsmZ/FISxa02mfAE0IVCn0XsGCFNP5UpmkFe
         WZCRNFqJgdNW0V2BY9FEQRA5OwxODXMkwPo92CFj3ymnT4ZusPokSliQ1Y+rAEQsNN6C
         LF77MWQnzc1nLovyRMTM85o3Sal0sk9bQUEk8DFj+cnHjhyvhx7PAj9VpEw9zOda2GqV
         oMu8IR2rgZm12M5tf64xd1QmdqWRCiLOsVAReUuzog3bU8ph+558ORW71updlbZhauOk
         8m93yBOUrhRYfOjWVmXtBlJu1AcPX/XlTxq6WBATJUFibZkZu+kXjt6mpZdz37sN1T2o
         P8CA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=dg0Zc85b;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678851923;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=m8rKOpMbEgxZl54PyAN8o9GkkaFtewew5kzmTSUt678=;
        b=UazjyEv+K/cBt3Yemkr7TxpPTrScJM6n7kk1BIBuGS44w877TzyZ/q3f2q8qs40RIj
         m1SRdgKvD9YF2l82BnTmCMsPDZAvhOXosFed+NYFi26ovh1MF4stn3ky0fQeWXkAEB1c
         HZKYXhrls1VogQ8bG6FlJAnC51RnnNmvQkZ5iKxDWyewND4G9E32dSqa6qtx3P2K+Tt+
         JgY8IIQIGaeyILaGOSvW8kZtDlX2wgNJAkJf+Jt8KsCKktY6Yl96/IkmORa+HjiO7J4V
         aAhR6ylFDU8l6FRllnXLo8rRMyjU4DbMx1LFYY5etcz+isVtpTdnTKZF1N6Ays+17E+7
         FqMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678851923;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=m8rKOpMbEgxZl54PyAN8o9GkkaFtewew5kzmTSUt678=;
        b=W+h9xZ8DGyr4jdGDcci863sbkse2MFTEspcGl29OLyJUw5sMZ7mkinY5VHKB/MsUwz
         UZw/UJ4KSxF706poQhPLNziRpKaC3T5Q2WEOAL4fCfzQVY+cTlyVKgGQUV8vWcYwD8nC
         XuWkGLGGQnn9gZnabMWM48b6C7oQJOk7xpNuKGF3JpvVGInifhHhHznSrs3tmkF2wAYW
         Xxhp+nVuEMzzzkYC7eqrAmTAByZ2pIWRClbqho/XkX0nwIM/0pWguiiZW8Dm5Mivrsro
         334WAkweOzRA/G7wfKwDi1UAImJgJujasEiVVtqkGl8L6ywgzjwdiE05NMb0/hPmqRr7
         NkFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWGk5WzIs77Buy+cVxoOvs58noG+8+Po0NOVdXIHIRpZ9a0busk
	OgiEWCO9ScXb8K2Al7ZwbxM=
X-Google-Smtp-Source: AK7set96Uri70cQTR90u9J5Fa+y4gUSbl27V/Y6puZ5rlSCEE5SE6+ymeh7EPHRXw0KsAOPuQOyL1g==
X-Received: by 2002:a63:2950:0:b0:503:2678:4f14 with SMTP id bu16-20020a632950000000b0050326784f14mr14224794pgb.8.1678851923490;
        Tue, 14 Mar 2023 20:45:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8997:b0:236:6df7:76b0 with SMTP id
 v23-20020a17090a899700b002366df776b0ls669911pjn.2.-pod-canary-gmail; Tue, 14
 Mar 2023 20:45:22 -0700 (PDT)
X-Received: by 2002:a05:6a21:33a1:b0:d5:2927:65ce with SMTP id yy33-20020a056a2133a100b000d5292765cemr5775645pzb.9.1678851922691;
        Tue, 14 Mar 2023 20:45:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678851922; cv=none;
        d=google.com; s=arc-20160816;
        b=Oou66o3xYUO6exo0WRuVtK9W/JXSRTFmSR6RbavJm+6Z2y440/HKIksTAo/Arc/Xf9
         +ZUmiMuXn+7fDpb7xNKw0OmGc0ikZqXzof3DMfs0yfwx7GPF9PJ5jbcj0fJGYu8vHnh8
         aT/VH7lRThB/SUeBtUNKt/fl4UVwJYWB+G/Q1uz1slIP9/U25IqraGeIg04iOFjxtxSw
         bN3S0E0Y3UJaSuBFpaFjEhybGoiPMG6uWblDciwzCVN1ZGAK9SGn6um/4/Q3PaXEjk7V
         J3MLfz6rDwIKD9uQRNMAVenBRgC9GhBsaed/NCZYpftaNMnD9Zd6QT2l7dO7vVfZ+a7A
         GxFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ufxsYZFIRnn+ldduLkLg4bGkJpmUn4VR4A6IuCdxW00=;
        b=LgQ4PsY1dqDCTcwAgo6fQ3z6I1jygagW9Sl8A6GtpeoEof5z116oyTMRUTjP7ZPvbT
         s8fShHoXitSGvKIQtGpaGSA42ks4PlJoU/kgsTFZLVtodPjJhuohHJCvoAMH9xp7+s58
         /9fzfu26+jNqAsU/nWZZkS2w7ICbsyLBHZEK3Y/Qdfcg1DjTsFD9nm6hund+uxF1mkg1
         EDSzEKHZ1OAz7Cie6gLGUlavP0CH2JpJEnDWI2Ad7HO7rTcn/jcPVEWm9pWVa4yzAZeL
         WznlJT4KBNO1nCoiEHiM0vM2BZQpZr8U6X6yOucHKtsucaJy9cSy1eDFopPIeHhFQZ+q
         tFzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=dg0Zc85b;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id m1-20020a056a00080100b005a8da742642si172871pfk.1.2023.03.14.20.45.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Mar 2023 20:45:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id i5so18719444pla.2
        for <kasan-dev@googlegroups.com>; Tue, 14 Mar 2023 20:45:22 -0700 (PDT)
X-Received: by 2002:a17:903:187:b0:19c:1455:d588 with SMTP id z7-20020a170903018700b0019c1455d588mr1227815plg.0.1678851922251;
        Tue, 14 Mar 2023 20:45:22 -0700 (PDT)
Received: from PXLDJ45XCM.bytedance.net ([139.177.225.245])
        by smtp.gmail.com with ESMTPSA id q23-20020a170902789700b0019f0e766809sm2436258pll.306.2023.03.14.20.45.17
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Tue, 14 Mar 2023 20:45:21 -0700 (PDT)
From: Muchun Song <songmuchun@bytedance.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	jannh@google.com,
	sjpark@amazon.de
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	muchun.song@linux.dev,
	Muchun Song <songmuchun@bytedance.com>
Subject: [PATCH] mm: kfence: fix using kfence_metadata without initialization in show_object()
Date: Wed, 15 Mar 2023 11:44:41 +0800
Message-Id: <20230315034441.44321-1-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.37.1 (Apple Git-137.1)
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=dg0Zc85b;       spf=pass
 (google.com: domain of songmuchun@bytedance.com designates
 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

The variable kfence_metadata is initialized in kfence_init_pool(), then, it is
not initialized if kfence is disabled after booting. In this case, kfence_metadata
will be used (e.g. ->lock and ->state fields) without initialization when reading
/sys/kernel/debug/kfence/objects. There will be a warning if you enable
CONFIG_DEBUG_SPINLOCK. Fix it by creating debugfs files when necessary.

Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
 mm/kfence/core.c | 10 ++++++++--
 1 file changed, 8 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5349c37a5dac..79c94ee55f97 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -726,10 +726,14 @@ static const struct seq_operations objects_sops = {
 };
 DEFINE_SEQ_ATTRIBUTE(objects);
 
-static int __init kfence_debugfs_init(void)
+static int kfence_debugfs_init(void)
 {
-	struct dentry *kfence_dir = debugfs_create_dir("kfence", NULL);
+	struct dentry *kfence_dir;
 
+	if (!READ_ONCE(kfence_enabled))
+		return 0;
+
+	kfence_dir = debugfs_create_dir("kfence", NULL);
 	debugfs_create_file("stats", 0444, kfence_dir, NULL, &stats_fops);
 	debugfs_create_file("objects", 0400, kfence_dir, NULL, &objects_fops);
 	return 0;
@@ -883,6 +887,8 @@ static int kfence_init_late(void)
 	}
 
 	kfence_init_enable();
+	kfence_debugfs_init();
+
 	return 0;
 }
 
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230315034441.44321-1-songmuchun%40bytedance.com.
