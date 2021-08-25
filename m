Return-Path: <kasan-dev+bncBCRKFI7J2AJRBJEVTCEQMGQEFODTM7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 846363F718F
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:17:30 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id i32-20020a25b2200000b02904ed415d9d84sf22760347ybj.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 02:17:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629883044; cv=pass;
        d=google.com; s=arc-20160816;
        b=OrJMvaQ0JRAvWjqS1r1bzpKepZ3giib50uLks3GTu2ofjwBvoMti5lStFChsV90VxI
         FZiy14OWliYq+iMGJXErbH9zZxjoGexyNvWzZqnW6Iok7De1CqVU6Tw+/fLWoScSG1/9
         7bnmH/WkuxEsVjd9Yc/3aSUUn6hEPwO/8Iu21wLhrsE03xOFea5sqCaGA3Z2mheV6JyO
         L1bz64rOaETeKwzDjfWfjIBa4NrL6lr593yMYXK8NcVMVFSpfb8luobp1X2p9R/kK9Uf
         P1MQcMQAFd/gUb0/vrNsPtpCdVgCZ9w8HO4/ek0XGlg8zfAjLahlhUMF33nOTWZeP1Z1
         7kkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LqSDG7WZbigOHvajphDMYTH8IhWxw+63MuHLJNcRoq4=;
        b=BzAvurX+dtcSFGyZjGf8tCP3rivHzyNzVzUI3BTvUOT/KZYq0rrhNJU/zjkqzQ9OLM
         C1QOe3V1oaBDt/n3sltJmm6qTCvAb27y4GZuz82jmTpeTuEp+wZDVpEGG3+n6+bGMTOK
         yGmZ5qJFYZuV0R4Yiwr0lqx3i1ICwUj7fC8BQNqEdJNo6xS5dB51VXKCDfYqnmFEqbsd
         IfszpgMWJPCP1O+fWzn/bA1IGmdeKnmeKfNnEXCoTQmegXrlnehhnfMtPV+muedj/bmO
         slfRKK6l01APRMQEqjGNNUOD3W87DLhjE+d5VqgN2q7H/HhH0tVWMPF2BW9KG/EZA3Hy
         hipg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LqSDG7WZbigOHvajphDMYTH8IhWxw+63MuHLJNcRoq4=;
        b=YGRyfJfI70zS0v0PgPXccrFd50Mh6rr+W3NKCqtIS2vDgFIlgygU+p5w/nER9MO+5Q
         UhKXzcBw/IQ09oq4u2Ph70aCNsDO/IdwzL+9IaigCPmvWaUypOValrbBH2cP/PTgCgXe
         wVzSyvOx7M9Pg5cRPwt28A5KWaJUZ2vSZKCniBSVNh/3GVPjZBppA/ysNwCXkBifxrwi
         BYYmYNGo3gX+wOEaf1eFxluDcajmPMvBn9SRlyK28JbJRIutZNgpeeBru349BAXkwWl+
         jicOf6RJqo2bXhyEZBrJ8Z5u7MnAd/ct00GPUBORE1tL2kg5EYa92J/d6l8vV0d+XWO7
         xXSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LqSDG7WZbigOHvajphDMYTH8IhWxw+63MuHLJNcRoq4=;
        b=QtLBBb2tiG+8Zj2aAmZbMp/eZyyAr9CRRQsfc78HvAIoDJoMQ+H/loCjamDVg8dkYc
         S+3/nugFKm9BkCffKhBgDSzpYUvDuHNl26nNK2qIxJ967kPXiF5cr4pUCjQP0QAYPtz0
         DY2xywNPQrm1sbqVejFR7lhOJwa2We+G7BzM1J2kzuf14pSc2g7HBwPqYSLZGfwriu/v
         csq+3PlhLGogv9OjwN1aPjWrJ+6ywpfz4jAk1O7SuCxG8dHxZlCrtHZ/S33b/ycs6HwL
         eZi3VXESOPJm42bPruGNGYqNdkH9WCJJmFxsfCf8cyT4/FWrKW/KsfmHDyi/iMvzLloY
         lUfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304l0Rpwq++VhHTUFtlxNcNalb2hv/NU0cESca5cZKu8+F2/oQA
	bF4FAiWzeof0k2JusBvBA2g=
X-Google-Smtp-Source: ABdhPJwgJfoLy+bM8RO09cNqu7t6yTTGDFw90BJv5uByY0PubHFf0MV1eY/uIsTets88quLan7G54A==
X-Received: by 2002:a25:6ed4:: with SMTP id j203mr53976319ybc.429.1629883044315;
        Wed, 25 Aug 2021 02:17:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9a02:: with SMTP id x2ls917201ybn.0.gmail; Wed, 25 Aug
 2021 02:17:23 -0700 (PDT)
X-Received: by 2002:a25:4907:: with SMTP id w7mr56122939yba.393.1629883043799;
        Wed, 25 Aug 2021 02:17:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629883043; cv=none;
        d=google.com; s=arc-20160816;
        b=h4pd1h0rBWa/JQBkv8UQeVjejh9WXDFVNaY7kGM4o8FeyDSRj5LKlbSHlUsS+UiBYr
         4vFiv5y6p+TP+xP109kw3PRa83v1FHMF9xOonnaFVJ2cuptK/h31ocRWY2Bq9Er3vm1T
         3tAairczP4xk+SECUhNT3yLFkglpGv8I+oGqBF687zOPoHmADoRZ+lOXNyFyqVvsNxFJ
         20nx8op4lXLVgm2IJ6xydUE0VIE5WIKTxnnC4EYC5+ugt4JmLhhGvLoRJq8m2XgfC+CW
         22LR7NqAXY/TjaJTdZc3HFTiXgU0xoiJFRJGQDsaYsp1ZTbFqxAXeasmkcCcD1BZBJW8
         C6+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=vu1/ZabvXBkUenwaF+XXh+J/aaOJWXEFu5L/HOzQTC0=;
        b=ZHYcorHq4aQRqshQ7Ng3nO4KSnCHY/5zoi9ulZslE4DDtVeDUS/k9H6tAI4Jm7Vn1e
         u2zz2WHI/0Oo4Y7h+GfHO0jHQr6yS4ICb7ZQdgtq9nvQBrkpOm7fdPDl4wy4EEGDU7UV
         hGnN5H78q+uYrNM/zaQ5r0ay0GalL4fh9ePU8I3bZ8TaAKyFUoR1dkYBQzvAFkMRDEVk
         ztOuNo288tnr6quAzRIlDRsMCvDqlNDEFMa1bw3blD9S3kFPTaKivIfgLHHSwKzn5YoE
         O8OtpfBrgAFHLGcLRG9Z5HQJYYfQxA8dssPNLN8Nt+dHWpB4ON4GctFjU3L4Nfe7HKK6
         iTBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id x7si826518ybf.3.2021.08.25.02.17.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 02:17:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.54])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4GvgN03z70z1DDJf;
	Wed, 25 Aug 2021 17:16:48 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:17:21 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:17:21 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Russell King <linux@armlinux.org.uk>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH 2/4] ARM: mm: Provide is_write_fault()
Date: Wed, 25 Aug 2021 17:21:14 +0800
Message-ID: <20210825092116.149975-3-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

The function will check whether the fault is caused by a write access.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 arch/arm/mm/fault.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/arch/arm/mm/fault.c b/arch/arm/mm/fault.c
index bc8779d54a64..f7ab6dabe89f 100644
--- a/arch/arm/mm/fault.c
+++ b/arch/arm/mm/fault.c
@@ -207,6 +207,11 @@ static inline bool is_permission_fault(unsigned int fsr)
 	return false;
 }
 
+static inline bool is_write_fault(unsigned int fsr)
+{
+	return (fsr & FSR_WRITE) && !(fsr & FSR_CM);
+}
+
 static vm_fault_t __kprobes
 __do_page_fault(struct mm_struct *mm, unsigned long addr, unsigned int flags,
 		unsigned long vma_flags, struct pt_regs *regs)
@@ -261,7 +266,7 @@ do_page_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
 	if (user_mode(regs))
 		flags |= FAULT_FLAG_USER;
 
-	if ((fsr & FSR_WRITE) && !(fsr & FSR_CM)) {
+	if (is_write_fault(fsr)) {
 		flags |= FAULT_FLAG_WRITE;
 		vm_flags = VM_WRITE;
 	}
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210825092116.149975-3-wangkefeng.wang%40huawei.com.
