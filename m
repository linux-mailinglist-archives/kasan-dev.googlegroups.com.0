Return-Path: <kasan-dev+bncBAABB7N532SQMGQEIVA6KFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 60C76759048
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 10:29:51 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-1b0812d43a0sf816959fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 01:29:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689755390; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xf3VvxA88AVANkPWtUwTlZLWFdc/mQY+k9GWuSgSwoC9Ct46WGvsE2mSwPd48Fh8dP
         pSXlpTQ/hZ8iL4sFFWpAfmc7E7CAqTbJ60PUUw7lDHYy5gv8Ot7PGjerWDxvcWvvw+q4
         1hCJiZ/UMGLzkvc36dL6+951ccbYL8D/clAbqGRaGqJVHpx0HnOAauKDyJAtUXdbz7Pj
         KHu8h7VFgIVpZimkuCIrAk4kWOLQRM+VKaHpUbBk5dHv0O0jp6UJWfi6fxt+q/Ano4SW
         7C7SAm2XnjHYmZK9RoNq99n5F8Y7WwRsIYiwG0t0qqIzcHhTqDP6k40ldSIDTkWESJoL
         463Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iZlKKg1W3TauT5RfT8tSCkr4kmpJhC5DMOavnph/D74=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=VYaIY63IrvQBxBmopa3SLrGnw1mjnKeo2DNBIhtf5+haAyjDOD0Sx9kOlkGt/HjWyE
         b/m4Nd3mH3f+wpbmfoJxnQiCKBg8UK7Mjgq7jD0zEtg3wvU3tsDvn6QGwzOUAzlGnYPx
         M3rdQDTPo0tEA2mMCcAQVqwF8AJDHYvKNapLtJfKsybL3MOSYuVZq+u0vXVLv63uhoWk
         LGmQKtC2l4yfiL0Cv31+JfR0vMfvwZNfhkWU+RlQ6oAfR6glzjm4IqJEUVKaDHAeWMm2
         UdD1k6fTg2RnYUfeZVYe+FkcCGKTMJgfK3GvyTC5h0GzI9fMjs4keQFOSGZH6loNVDJV
         M4Ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689755390; x=1692347390;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iZlKKg1W3TauT5RfT8tSCkr4kmpJhC5DMOavnph/D74=;
        b=NjvahCFp+EmZ+gBUg/xbcLZ7Q1rD/dkxFxpCTkIl/iINilKsPfpcofh5TgajuMrBdx
         C2cdb8j7XJVOgO1Ni9FdW58aimb4XGqQI8iVy1bhkP8H+ea6f1a0vyjpyih458aV5Tki
         hsOUihrKsV/KR3xb/KUedRe/6ep9N8/HzRDL5351qcNzwvlra2icl6M4OZd2QaoJ3nXX
         LJZPwOp2P2ZTySv1EL+FZXBiV1ohV4SC2EThdy3tiOfA0znSmUgmhvQoHBZ9l0D+B6U8
         /PU+JldLtunLxclePE3/b9jYlWHh1wF7Bwg5LwqrjIa/odODfnhn7JV3BpZGX7UOFIkk
         bXyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689755390; x=1692347390;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iZlKKg1W3TauT5RfT8tSCkr4kmpJhC5DMOavnph/D74=;
        b=SRom/LOoTWiXwTDbfgheSkHyLgT68mBZEEjympeKae9XGBvJKV7/TKjjPGRcXLzqEO
         Q2nYEQUa/C3DjaTEqhQIjgjUFIGGScLQf/3L85KDdcTeNCBOFzojAtNwTOeFThvEYNMj
         hpOc9BtgArxypdf0Zm0xDVu+TLzrNj5jQDAvOWxG6LB5Chss3s1ltClIDnYyAy5CJ0m4
         ieeNAYhC9rA2caeEXgGGAwMcHVZLlfRYB6KLTa0hioiYiFX9/AH4IFDXeD4DrDJUETRl
         AQky+PXRGbe0DO6a3s5/UOvglzE9RcTmqM+4sQvbfG89uqkJX33gBoiK5kQa/9V2Co+i
         mybw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLavdeMamZ1eSRiv/y/0u/tsUkedkIsBuVGCGcpsD29K6q2ZayW5
	P4Xms/v9ghYWxjWFFbLA1ns=
X-Google-Smtp-Source: APBJJlG91QKTvsSZo89j2lmaSJ5wZ8ZWgWkcKYDOHzq7cpXnS6p8Nl/83x19ZUIAq3g6JJR0redkNA==
X-Received: by 2002:a05:6870:46a4:b0:1b0:6bc6:f608 with SMTP id a36-20020a05687046a400b001b06bc6f608mr1153757oap.24.1689755389864;
        Wed, 19 Jul 2023 01:29:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9a20:b0:1ba:cb89:5d05 with SMTP id
 fo32-20020a0568709a2000b001bacb895d05ls1118062oab.2.-pod-prod-00-us; Wed, 19
 Jul 2023 01:29:49 -0700 (PDT)
X-Received: by 2002:a05:6871:829:b0:1b0:45cb:706e with SMTP id q41-20020a056871082900b001b045cb706emr1082706oap.28.1689755389474;
        Wed, 19 Jul 2023 01:29:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689755389; cv=none;
        d=google.com; s=arc-20160816;
        b=Q67K7LxxURSKKIVka1TtgbZ/rEGOeoZF88aJ26WDPEhV9k/MGzmbD7k5gADmY53bnw
         f+Pz7LpwSmVElfoC0dar30GWkkGRnHpFbd5iEHlcv8YYpXN6NnNTlwc0PYPtBWPCJFvu
         dEiDCiiUt85Pj9bNsC7OlQq5crlYCJNggoMWRSiQdoDCkiQ754/2GJ9f7sE05dqDZcY1
         zx2oTpXWxdEGVxEIV6LcP0DKIOmEDb4vQa92VmjWT0MIhAr1pE6AwhazoXds8im/Qamn
         ghZSBr3TEOsL9200V9qYUEXuNPePpSh4BH5+Kz76fCeJ1fssQdBwBnT4BvV/WlAKPLYb
         oKMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=KC9YfyphoSzaLmOt3LMaqSzSLLAiqFOHvQOOGBBNcIY=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=g6sf/iVk14h2RZK1fFCkIjmBvIgJ0Fo5wb5s47qE30niJZAYZsW399W8wH21t5MnO7
         wM5uJKTpRYfTfysHxsJYEo9CWO7b5Bc7cjt2YPs5I2/cqvVZ3Si8YlSTTdcoqCBGn6Tg
         vfuNeaXfCNYbgiP4nna4ffvZa4veqWG7ltDmf1tzffAkqsdNhRjYdlShY+8FlNC/Aiks
         klZemFXfAO60outo3ZFcCrM4tMwezgWO/Jd2Id41/o7+ULcLFx5ioN1I+lvUWaWScZPp
         5cs75g9c8fTeCx8xzl/HBhxWdqHx9emltmGAqWSv5+NWBGYsZ+TdCwQWM12Pz6G5zSgR
         g7cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id fu25-20020a0568705d9900b001b730b9901fsi356012oab.4.2023.07.19.01.29.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jul 2023 01:29:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 945de7dcea5f491fa0c7b85e294a5a7f-20230719
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:d1643b96-a21f-4a4b-a76a-72ceb643f1eb,IP:25,
	URL:0,TC:0,Content:-5,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACT
	ION:release,TS:5
X-CID-INFO: VERSION:1.1.28,REQID:d1643b96-a21f-4a4b-a76a-72ceb643f1eb,IP:25,UR
	L:0,TC:0,Content:-5,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTIO
	N:release,TS:5
X-CID-META: VersionHash:176cd25,CLOUDID:c9f5d58e-7caa-48c2-8dbb-206f0389473c,B
	ulkID:230719161451G039KJPT,BulkQuantity:1,Recheck:0,SF:38|24|17|19|44|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:0,File:nil,Bulk:40,QS:nil,BEC:nil,COL:0,
	OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_FSD,TF_CID_SPAM_FSI,TF_CID_SPAM_SNR,TF_CID_SPAM_FAS
X-UUID: 945de7dcea5f491fa0c7b85e294a5a7f-20230719
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1086783333; Wed, 19 Jul 2023 16:28:19 +0800
From: Enze Li <lienze@kylinos.cn>
To: chenhuacai@kernel.org,
	kernel@xen0n.name,
	loongarch@lists.linux.dev,
	glider@google.com,
	elver@google.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: zhangqing@loongson.cn,
	yangtiezhu@loongson.cn,
	dvyukov@google.com,
	Enze Li <lienze@kylinos.cn>
Subject: [PATCH 3/4] KFENCE: Deferring the assignment of the local variable addr
Date: Wed, 19 Jul 2023 16:27:31 +0800
Message-Id: <20230719082732.2189747-4-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230719082732.2189747-1-lienze@kylinos.cn>
References: <20230719082732.2189747-1-lienze@kylinos.cn>
MIME-Version: 1.0
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
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

The LoongArch architecture is different from other architectures.
It needs to update __kfence_pool during arch_kfence_init_pool.

This patch modifies the assignment location of the local variable addr
in the kfence_init_pool function to support the case of updating
__kfence_pool in arch_kfence_init_pool.

Signed-off-by: Enze Li <lienze@kylinos.cn>
---
 mm/kfence/core.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index dad3c0eb70a0..e124ffff489f 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -566,13 +566,14 @@ static void rcu_guarded_free(struct rcu_head *h)
  */
 static unsigned long kfence_init_pool(void)
 {
-	unsigned long addr = (unsigned long)__kfence_pool;
+	unsigned long addr;
 	struct page *pages;
 	int i;
 
 	if (!arch_kfence_init_pool())
-		return addr;
+		return (unsigned long)__kfence_pool;
 
+	addr = (unsigned long)__kfence_pool;
 	pages = virt_to_page(__kfence_pool);
 
 	/*
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230719082732.2189747-4-lienze%40kylinos.cn.
