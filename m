Return-Path: <kasan-dev+bncBAABBB562C3QMGQEL6T6VVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 27EC69860C1
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 16:32:41 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5e1ee2185bdsf3107238eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 07:32:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727274759; cv=pass;
        d=google.com; s=arc-20240605;
        b=FB05zZB+b0AiYGFta5c3H+/OTxbZXBv97nKlppjNE67Vjapu3QzF9PUqsSaO4pKD7K
         MRFDuehv8IRP54QFXpFqnLUYzRn/PsQj0fVariNsQ/NtQkuMJPPsAktNAkpyzc/JSfgO
         qsXn3XJNtQUgpPEBZJR7HwW+eXo4yFuA4P5qNKXA+RB79y3DFk+OJKbvkwFVLUUC2K0Z
         FhpuaEG+wnZN4bdz1k50RxwGCS0SfbY6lyAmI70LWtT7hY6ImSrz232GKFahMMMeH8sD
         GhjLdzbWeZF5gJsCHMpFJpiRezsbt2usLszdHxRbT57I0STr6Md/g1mLXZf9PNQwwlps
         Tu7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XvOXl/1hBhY5NOw5N3qVvRu61Z7R5oQYE6QSsc4EGB8=;
        fh=2cRvnLsV7KyqzlNqAgd4OW6rlC/3bC+HdjoURTqW3j4=;
        b=dd2pxyV4MxCUrzE3OvlODPBs0xKiVo+su1aSrgb/3rykXiCtzlFpqgEbFt4XCVewUm
         EFDHComPjiK20YEgJDOdJdjkreKmHaZjSzsZUu5Yi6YJqsMZKCuEBPCjqdBYx9hnMO5L
         HWqES0AdGkYEithIC6fVx8bxFLm+fAOpxMgGwkX+x2ayWTJ3uOKA/tn0GQietolf8gJE
         n8O/rbBbxsJWx0nsJDX3yexDBMsaETEnbYdexpNFCRbi/G6uQuZBhbBzwgFfu/oKNUB3
         kDBGam0VzXqO+z1/vKazL8cKvBySl2tF4gEF/mDxdV7XXtjzw047D2Pihpl6+YYgSA89
         u7TA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=dfL9K7oa;
       spf=pass (google.com: domain of ranxiaokai627@163.com designates 117.135.210.5 as permitted sender) smtp.mailfrom=ranxiaokai627@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727274759; x=1727879559; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XvOXl/1hBhY5NOw5N3qVvRu61Z7R5oQYE6QSsc4EGB8=;
        b=EFp82BQL1qgsofcRCDcAZpTs7VMKFOhgh883x/tZ5JaFciKqIYKUdNHpebzhPlNhbf
         3+LS3JW6CRHnyEaJxTWZWliToo7wiE7pNX0arJq8zjtYDM8+ibIBCMHhSAU52ToRxlDT
         /fnrTGgw+KpD35Got0MyRhmTXa/Mad11/FvvQ9gy1wADGrRAaGpTJNSOPGD435uAOSKQ
         ye6AgxHsZTCNiU75/YLzsk2b7zeFwt1hu58OvMinvBFgHYCaixyb0UkiYptGiaJ2/7YM
         fJpY7hriajOkLdjNO0e8+qRSFU8Te24I/wWDTEMQFjYeYQANgsZDQ7+yvXZq1JUIdnK3
         JHag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727274759; x=1727879559;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XvOXl/1hBhY5NOw5N3qVvRu61Z7R5oQYE6QSsc4EGB8=;
        b=iQ18gjkZ8SAp4hZX+yVAXzkiZCsYQa2jh05sk5EYSvbQTRpQ3lZBbjz1tU6MUed8HJ
         +jgO6dgXHlPHudRoU1n2G4WwelEjM/EiyKL/NS/F0qOfM7vrW+F2yFmDnQodAban+k6d
         Oc4chlwLeOzOANpZgIv9R0YMNx8u0ELmd9OCD6/FelTpDa6XmW7OULht2rru4rHFhF7T
         lCqVdGUnkDRMlwr59jaSFewbCGC42O7FvQSfPgbwmnXKJfhUnj2fd56qgsiiaq/XCInW
         PDXlW8bNbTyxhDlXJ+w0SB3oieKTD7OZLtNV8EwIS/F0SDyu27aNh2bOeReSDY7fQZE1
         /Pkg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6e0Hwi95Bi21QKNULCCZ75U3qwhO0YCsoAFnK6rMmWbd+j/ol5nLfr5QMv4nmiy9BVQXiuw==@lfdr.de
X-Gm-Message-State: AOJu0YzWFO36pkDrsCjHUTnybhPqAIRbNG46cbam45tdO+MwlnEMjkKz
	0NeEizlTZQ2QtBWG0r9CArQzsl9NmieKLh9irDzMBi6q4UeRkS3y
X-Google-Smtp-Source: AGHT+IGD8qwvQU8FpyGV54CBNgEifx1OEbIBsLwT9INoZL4uKNJrJRIM1lUHMpxXDRI4T+RfgfhW4w==
X-Received: by 2002:a05:6358:7246:b0:1b8:4d13:9422 with SMTP id e5c5f4694b2df-1bea86a7193mr126433755d.26.1727274759389;
        Wed, 25 Sep 2024 07:32:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:289:b0:458:355c:362b with SMTP id
 d75a77b69052e-45b16357b0fls11785521cf.0.-pod-prod-06-us; Wed, 25 Sep 2024
 07:32:36 -0700 (PDT)
X-Received: by 2002:a05:620a:4625:b0:7a9:bf31:dbc9 with SMTP id af79cd13be357-7ace73e20famr530353685a.4.1727274756329;
        Wed, 25 Sep 2024 07:32:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727274756; cv=none;
        d=google.com; s=arc-20240605;
        b=EaC3oa4kFaxRnj8GZYuNTK6Hi78xoDRuCknxbVDPaEIt2faow+am22MNahgmTvb2Oz
         nEuD5oZe+AXe44uARHwwGJgmuL5/u44Eur0Wa2Wu+2WQH3lE+XsNOXrhYnZxV4Htcu6r
         SaVEzMzXSnJGokJmEC/ti+zQ4tBT04BnwXLJthjIFxhCgMtPWfAKO6/A3zcIoHae233T
         ubFDeySUQk6OHYwHe/x8//Ws6fZViOJWYYV47LoFSyj/QaWS3R1puKs0jbrlmdEv67/4
         fw0OYFaadF9AwIh3Gnck1Jiq64QxaA/KfvBxmB2oEMOtyPohJlpAgQKx92m3GKPjDLAC
         Ai6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7/NB/v2fjTsmnyeIo9rDAFMjTCqI92mCnWuv5aDhiWo=;
        fh=soLd1rxl5Zg4+HEDKR/GyOBvVj1EgNzTFg1l3c/vbe0=;
        b=SE2Pc0FYqg9G6blDF94T13cgqx6+aeuQl6ImUgMLrTaVGj3j337ZA3q0Eq5ib1egVi
         wDwK7gn3h6ERs/3x0zDuPkbwBuUuSpkFX7sRy/F7Yd7ersmBFQg62ZUp+QPhUVHgcMC2
         Ue0v7udfoIhY814KDK7lX2dTcEQqIN6T5n2yYetyVSlcGOerdXcWCs1QdhwaOm7a/gqs
         3BqyY7B+5kCX80pE8Vmysb7TVTm7+sA5YMS0wfTQzTPpK1S3Oduyr88lMdjzRI42x1F6
         Mp+nmYQUBD3eRt6rS4kgFS67FoGUfsSS9l07halS1/xeTXTWNLoSb58YDV3nBEKWdHGh
         KgAw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=dfL9K7oa;
       spf=pass (google.com: domain of ranxiaokai627@163.com designates 117.135.210.5 as permitted sender) smtp.mailfrom=ranxiaokai627@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
Received: from m16.mail.163.com (m16.mail.163.com. [117.135.210.5])
        by gmr-mx.google.com with ESMTP id af79cd13be357-7acde497dddsi16463085a.0.2024.09.25.07.32.35
        for <kasan-dev@googlegroups.com>;
        Wed, 25 Sep 2024 07:32:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ranxiaokai627@163.com designates 117.135.210.5 as permitted sender) client-ip=117.135.210.5;
Received: from localhost.localdomain (unknown [193.203.214.57])
	by gzga-smtp-mta-g2-2 (Coremail) with SMTP id _____wDn9EXeHvRmGMqpJA--.33673S8;
	Wed, 25 Sep 2024 22:32:14 +0800 (CST)
From: ran xiaokai <ranxiaokai627@163.com>
To: elver@google.com,
	tglx@linutronix.de,
	dvyukov@google.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Ran Xiaokai <ran.xiaokai@zte.com.cn>
Subject: [PATCH 4/4] kcsan, debugfs: avoid updating white/blacklist with the same value
Date: Wed, 25 Sep 2024 14:31:54 +0000
Message-Id: <20240925143154.2322926-5-ranxiaokai627@163.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240925143154.2322926-1-ranxiaokai627@163.com>
References: <20240925143154.2322926-1-ranxiaokai627@163.com>
MIME-Version: 1.0
X-CM-TRANSID: _____wDn9EXeHvRmGMqpJA--.33673S8
X-Coremail-Antispam: 1Uf129KBjvdXoWrZFW3Cry7CryxtF1xuw1UAwb_yoW3CwbEq3
	ykXay8Kr45JFZxur1v93yrXrsYy345AF40va4fKa47J3Z8K3ZIkFZ3XrWqgrZ5uFWxGryr
	A3s8Krn8WryftjkaLaAFLSUrUUUUjb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUvcSsGvfC2KfnxnUUI43ZEXa7IU05l1DUUUUU==
X-Originating-IP: [193.203.214.57]
X-CM-SenderInfo: xudq5x5drntxqwsxqiywtou0bp/xtbB0hhlTGb0HcIX-AAAsF
X-Original-Sender: ranxiaokai627@163.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@163.com header.s=s110527 header.b=dfL9K7oa;       spf=pass
 (google.com: domain of ranxiaokai627@163.com designates 117.135.210.5 as
 permitted sender) smtp.mailfrom=ranxiaokai627@163.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=163.com
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

From: Ran Xiaokai <ran.xiaokai@zte.com.cn>

When userspace passes a same white/blacklist value as it for now,
the update is actually not necessary.

Signed-off-by: Ran Xiaokai <ran.xiaokai@zte.com.cn>
---
 kernel/kcsan/debugfs.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index d5e624c37125..6b05115d5b73 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -142,6 +142,9 @@ static ssize_t set_report_filterlist_whitelist(bool whitelist)
 	old_list = rcu_dereference_protected(rp_flist,
 					   lockdep_is_held(&rp_flist_mutex));
 
+	if (old_list->whitelist == whitelist)
+		goto out;
+
 	new_list = kzalloc(sizeof(*new_list), GFP_KERNEL);
 	if (!new_list) {
 		ret = -ENOMEM;
-- 
2.15.2


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240925143154.2322926-5-ranxiaokai627%40163.com.
