Return-Path: <kasan-dev+bncBAABB3PD5OMAMGQE7URUWRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E4865B3109
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 09:57:35 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id a19-20020aa780d3000000b0052bccd363f8sf658029pfn.22
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 00:57:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662710254; cv=pass;
        d=google.com; s=arc-20160816;
        b=u/L5MzSqjWKxSavQhyzjzee6RwWIC7Dm/KGlKIolXc8ONG/EDWC+cQn5rOBUV0ly1R
         1mxS60M500P2x2ufyXtSa4KcoVLuLHiF0waMIHd9oQQ9xYAx8Vx2aMubhc65Vjvfer2f
         h6nmAclraPrznXADo/7Az1jQXQMBkwEwCykKp7JMPb2f931FuLR37ouIkEqSR9CELTPG
         AbnZ8XLm5OLPhI2KWD+ft46glAuboLKm/oo2y0jYE75DafZV9Tt/Ppk9cK2aWCdk+n4c
         O+m5xoi9RubXuuwSk6UhYlO/ViHd+Mxiwiy4CCJIwngfKM3uBsuwRfAwHFhHJstGBHbY
         4jMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=Sr0/Cm46ZZAcWIV0psd+1LmztulQq7I4JIV/IxPNIkA=;
        b=cLOkv/bY+XlnoJWVTbMli/IBXDN/xh5tRtIL+gRJdu+ZLKwJxgpfwPZZ4BoP2YNP6b
         0Tx1tfyZQWGAMLNZLSjYTzwT0Q+ggf5XxPK1PU7ttsO8TOSQW21CrRTeZfk7pxqLK0C1
         i9O0bY7qclLy9w5a+jYVYPHsdGdb7+dbEtlliG2o7gJJuWG2sujlNlteanDrW+r2ikAi
         eiS7GsvU81jGRauExqAQlUvCpORBe2qQzoNgClG5pMTrCx+ftleWGRrtcchaPIpW+uK8
         XV8wTfwMsBPbefYUY/JKHZJ8GD+EKbhNco9dE0g2mH8O0NWHJeqRRhgEL8OEtpCGy+i+
         9BMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date;
        bh=Sr0/Cm46ZZAcWIV0psd+1LmztulQq7I4JIV/IxPNIkA=;
        b=CIxP9tFOMDj82Lsu3fkTiH6wDzK1udNwBiqvQZjRRTXNt6qrLvoQHS7sdjeidpLl0w
         eENQip+DK3JKSVCmhAAqih/5Irgfr4NMFSssjVAUGr3pk76/t0ZJhORgFKn+LL82J9SV
         QIO6IrbWLZq8IbXHbP9pbe2DQ03yHA6yvOv49ytAArS+7uetEQqnGxb0BGiWoYuZGGD4
         NvHQcp3dlwkoUyl2eye8HGd/oxSn8c/5rezzNSBDF4XLUk9100GQmJksvQRXqMyYVBRq
         qqtGLyQPLJdxuDxLiFuBFTxFg90PybMU2WnvryzHJFZQ/wHWHQIm4Ad7Bxia+XwkIV84
         axTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date;
        bh=Sr0/Cm46ZZAcWIV0psd+1LmztulQq7I4JIV/IxPNIkA=;
        b=yFdRTfXDyLmNY9JgrD9CD2TO1tiVoNdVQ8uoIZxqzJPCn/nNe1fOuYRTEQd2u6U54y
         CbhFPHAHwjmeNcwzl3WirfCGB6vgxY6peJ9j4ZFrn5RBaxBELchjbTRRRn+swcperyu0
         Nk3CfkwILmQAW7j7eQEtU8KbD7ElEKe5496wB3YBqv3AZu86SSEzye6N8b6T5w7qOaNg
         LzX383XpTh8EMukG/kXDrMF/j/EZ+8vold78dksSByIKVwRD8jwguSNSHojxzstgn4gs
         be/q6EhKcoOY8UECQG7Axr2TLLc6gIqNWDSzHTHUKmfSSWVtdliU4SfQ3mU1DC6WxVfE
         DleA==
X-Gm-Message-State: ACgBeo3xd6f/8dtb6QPK6iMCz1BJNPSp/jy1mgU8DJxUz5TvaazAZibG
	AibVwOSPiKPPAl22DbQFEuo=
X-Google-Smtp-Source: AA6agR4tsVffnh6nh6TssrM58upt8ZBVi16jjDJVbT9iWjbiLtIUqSo/jZbARX3W/VDmimghOClcow==
X-Received: by 2002:a63:515d:0:b0:42a:cf33:4320 with SMTP id r29-20020a63515d000000b0042acf334320mr2619282pgl.21.1662710254024;
        Fri, 09 Sep 2022 00:57:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dacf:b0:176:9478:2315 with SMTP id
 q15-20020a170902dacf00b0017694782315ls1504977plx.9.-pod-prod-gmail; Fri, 09
 Sep 2022 00:57:33 -0700 (PDT)
X-Received: by 2002:a17:90a:d589:b0:200:4228:d6cb with SMTP id v9-20020a17090ad58900b002004228d6cbmr8427735pju.78.1662710253427;
        Fri, 09 Sep 2022 00:57:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662710253; cv=none;
        d=google.com; s=arc-20160816;
        b=CTzzwMiNFTwbxEOVHJNc428wowKQIvOonBvXLx30yj0n7qRH6JlgjYrkihM5JDuQ4b
         1RCTOztxiNusRojtBImKFkDqVUiJFN6Q/NqlmAwLsv6nAkv3TnTRKN8xKqhiAGi5PVQR
         TB+LPerUzNudTXAty8bzkvCHsjT5rDK1V4yOYWHfk7u2I6Q+jOErWswLWpLGn0rxxio2
         WvbxClzcvailWppYB2h1gpDJ0p0zn+8yNJf6pne96nqh0wexOXU+Aze0ace8ONIQMbff
         vF6/64DyOo/bz6CaNSOOPbB2w/gNWf6dR+KVFLIah9FXePDpf2KFs1eEI1xgwuY2Uvsm
         3h/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=t/XrLnh9dZBSEhabXVViw2WefuZ4HcX2J79lqIU8v8k=;
        b=RtPI95s7PINH0Xn0zzhwTrUPlW1pftpoD8/iSC83RzgCKkqfGYFBblhcaGciUlddTb
         ZshiEkXwwLcEPAgjeBu5jvqR/DFicTEVxCgZrS77EL7Zz+1tEUrEk3eETroPaSMNyjbs
         7gWhU1YE146IT/+W0A4tE6F1fWqxTUjVs2npDG8ahi4xDlCWBRQW9/CGuwveeb7omnNO
         rgUoBCpzmzVe2e9thHqvR4PnAAABc2tVniwwNPrhuCEQ2I5GiH97dJ84epVKRSxuCK7l
         rK41+2Gbl53cWH3iHdSyWMIMxMAJ4YuUEzatmOM3cACwvavwNHhPcjwcWDWJ1ScsTmtq
         agdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id ls17-20020a17090b351100b002002faf6c49si31600pjb.2.2022.09.09.00.57.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Sep 2022 00:57:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggpemm500022.china.huawei.com (unknown [172.30.72.54])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4MP7Zt5BqpzHnlH;
	Fri,  9 Sep 2022 15:55:34 +0800 (CST)
Received: from dggpemm100009.china.huawei.com (7.185.36.113) by
 dggpemm500022.china.huawei.com (7.185.36.162) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Fri, 9 Sep 2022 15:57:31 +0800
Received: from huawei.com (10.175.113.32) by dggpemm100009.china.huawei.com
 (7.185.36.113) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2375.24; Fri, 9 Sep
 2022 15:57:30 +0800
From: "'Liu Shixin' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, Liu Shixin <liushixin2@huawei.com>, "Kefeng
 Wang" <wangkefeng.wang@huawei.com>
Subject: [PATCH] mm: kfence: convert to DEFINE_SEQ_ATTRIBUTE
Date: Fri, 9 Sep 2022 16:31:40 +0800
Message-ID: <20220909083140.3592919-1-liushixin2@huawei.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.32]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpemm100009.china.huawei.com (7.185.36.113)
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.189 as
 permitted sender) smtp.mailfrom=liushixin2@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Liu Shixin <liushixin2@huawei.com>
Reply-To: Liu Shixin <liushixin2@huawei.com>
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

Use DEFINE_SEQ_ATTRIBUTE helper macro to simplify the code.

Signed-off-by: Liu Shixin <liushixin2@huawei.com>
---
 mm/kfence/core.c | 15 ++-------------
 1 file changed, 2 insertions(+), 13 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 8c08ae2101d7..26de62a51665 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -719,24 +719,13 @@ static int show_object(struct seq_file *seq, void *v)
 	return 0;
 }
 
-static const struct seq_operations object_seqops = {
+static const struct seq_operations objects_sops = {
 	.start = start_object,
 	.next = next_object,
 	.stop = stop_object,
 	.show = show_object,
 };
-
-static int open_objects(struct inode *inode, struct file *file)
-{
-	return seq_open(file, &object_seqops);
-}
-
-static const struct file_operations objects_fops = {
-	.open = open_objects,
-	.read = seq_read,
-	.llseek = seq_lseek,
-	.release = seq_release,
-};
+DEFINE_SEQ_ATTRIBUTE(objects);
 
 static int __init kfence_debugfs_init(void)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220909083140.3592919-1-liushixin2%40huawei.com.
