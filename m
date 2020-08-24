Return-Path: <kasan-dev+bncBDGPTM5BQUDRB3XMRX5AKGQEV4EJWYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id BC15E24F3B0
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 10:12:31 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id o22sf1013854otp.10
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 01:12:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598256750; cv=pass;
        d=google.com; s=arc-20160816;
        b=yCy5x0VeC2qekvdi4IuKNDG7r7j7QmC9szxWekHzPxhLtGyupV+oBpXmG6mhP3pyOg
         mWrqqpba31yH2Be/E3DDlmU8KPEXJuc04z43TV+RLiEi/VS+HHDyIDZBrsFQ2vb0Wkc2
         gvTm4wncBoCU8nL4UlChwi26r4ayfC/BapBdo2yYv4RRlXhBJ2dJl0koQpnRNfXFDJQ8
         v96T7ZyIe1FP3u+XSVAlGdbQWKsScfnkaR0dEjGmQcfzJxPeo7XVqr7j9aRDKfw/CPWe
         Tdw4G97enT9+rgJxEZ0b79f2Hcfenik9ebxJKTd6V4KfkVwRBDJVM9NRSuwa5ghn7/mO
         4leQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=7MShI8xyaJMC1W46jEwFGZe4uM7KXlgHYCfyZSzhKpo=;
        b=UTwQUcLEkIofGqWJPnYCRzf30GpbVSg5CxDzce+o8O2pNmEMp0IU0mJbt2Cyqg1liX
         vAo8sAXRUq/sIpnX1JSRSWu8P9z99jy6hD5d6bkXI2b9DnzBI20bsiom9uxcSzrW3lL8
         ebD9tdhUZBGUdR5AINKIa6yIJR+zNgj2T78FOWNz5vj/9lhcWcbn4GdvcWnyA0W2hdh7
         6gxe6FGjL4nPpllerQhrL8S3eZ9ySrS29Vu2h6EkQ99ZgIQBM4EvRAaJ4SyNE+3cq4km
         50pByT1vVoIlZxmiz3Pr/pz3pHewbi9fisIHqJUdgX6hY04Fvz7B9C2WuQppGVETOKjW
         3fqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=kpoLH2aZ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7MShI8xyaJMC1W46jEwFGZe4uM7KXlgHYCfyZSzhKpo=;
        b=lS+d1OgPP5bswtouMmJ59R18AhJLslR3Wcf6vFF+T5ddH6yGNzD2lIPl+0/fHzT/at
         jbn/7wGoedmG8+Wdm7AOxb+smufYMaSMtEl0s0A6MVFKfycPqQii8y6kiEnWoLLDY9N0
         k4cmzLv0uc+WGh0RuDFg/HPXDhcq34rahcDBWEimwOkJ2V2FFeulwhgC3dS6SAyQkpxD
         6NnwIv4MG6CiJt4EshYk+jo1eyA1IYSTeAYYbeLY2sZlhosFjCrvTJPD1DY1c3DayWTy
         aR7uItTI7a3AOndQlvVCHqRw7G3aHTPT2e6/6eCJ0GR4/LjdjAIJHofVF3sC26AApWia
         oLKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7MShI8xyaJMC1W46jEwFGZe4uM7KXlgHYCfyZSzhKpo=;
        b=q0FvPReQlUoyKQxSN20L27m8wsFdetN75dXv3cuN7wu4rwctHQRYxAT/KZ0AduAW+Q
         49K3Mw3NFBPyY/Egp/JHm2M2tOtsvorsX+/dzNXYVILUowUIqQUQKHTwAYrb4KNWVnth
         UG/grOXaxazN74AAwsV53UtTd+gYeKhZhl5nTi8NhwluvxAUye4puR3+XpjoAQ09dJgh
         bFQhsFgVfXpYR/NaVYI47yJ5LRFUc/N5XYYE6Io0tOA67pbL7vACTjRpXyFVC8b8MbV3
         KTchradnuc/gGuUY5wCKRJxDcpYkFJrEPmHhk64un37PKrOWyd0k7c6Ql/8SMIymY0x0
         SiWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ixq/zgHQ8gzEpHRnokZz6u4Jdj3lifccN25dgY4HXTZI7GvME
	lYKqlrV0H41thS8QLR59AOM=
X-Google-Smtp-Source: ABdhPJw5AZSxjnihVWJla1T/FfSUfLqMtwkwALQKSM1tx6SZidsyt2uYK12gRdav/Fd2w9Ewrc59rw==
X-Received: by 2002:a05:6808:10a:: with SMTP id b10mr2303819oie.160.1598256750752;
        Mon, 24 Aug 2020 01:12:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4745:: with SMTP id u66ls1799044oia.11.gmail; Mon, 24
 Aug 2020 01:12:30 -0700 (PDT)
X-Received: by 2002:a54:4e85:: with SMTP id c5mr2551450oiy.60.1598256750449;
        Mon, 24 Aug 2020 01:12:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598256750; cv=none;
        d=google.com; s=arc-20160816;
        b=ov23ynLWlm4OLjS3ZjoTy+PfsMIcSKAdmbLhUVHcdHHKxcLUMfkOKt3UDisL+bHof8
         n5KFuL/qWAuQWEvhxVx/pFCynFzSSXfAkzCssmjek8KsqhkqM35TW32QTGLTfwM75tBp
         ddS43v33LQ9fRNJaM+I8hLrRVts+pApM5YmkRB7nxdZmeetZbESN6/KkUb4IjLCKUxDW
         DgMhYw03+7m77A+zyBk38LwT0sJ55y0LG3F5Nix/uZfIC6eAtfRCaMF3S/HXjMmfK2CM
         MGjh5NQk9XmyksPgL7fRMF24iGORP0voHAjpk2GoLjN6T0rEKFhnLzMWuxruZ9IWQGGM
         +IsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=HDzXMXMz+Dzcg9DxfMTu2qwgwLYa3ujPve0aUqFM/KA=;
        b=ilCDF6ATh9SQUIQuKTfJP2EHCr8/H2U5qvb+h8kr+jubn97uHmPFbXKlyacwcVHD1v
         /y0G7i90o09eTRm0pg7SLYduhgNAdin58FM+lgvDb7UJZ0szTlkGpZgmLsPyA/+yGHfF
         MlaM5g5/IWBSlzDuP2dreUGBoE47rjs4JJgbSdwgCnHvhU+KgY82kYGtAx7FzKy3v/C5
         Nao+TDcEmX+451fZFb+cB5cOUkSco/DpywOgKvOnhtTTTBUUf56cdMcSGx/gwEpTpMUd
         6/aCmbtgUOkiFndGVgDaW9RfNfQYmoLAEOm6WgcVniMQtz1jo/qPL5T2MVmYEX0Qjs3s
         FVYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=kpoLH2aZ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id i19si386242oie.3.2020.08.24.01.12.29
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 01:12:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 0e1feef9c4bc47e6955e9d1135fde177-20200824
X-UUID: 0e1feef9c4bc47e6955e9d1135fde177-20200824
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1710976290; Mon, 24 Aug 2020 16:12:25 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 24 Aug 2020 16:12:24 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 24 Aug 2020 16:12:22 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v2 3/6] kasan: print timer and workqueue stack
Date: Mon, 24 Aug 2020 16:12:22 +0800
Message-ID: <20200824081222.24919-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 5E5BAFD4F7B10F653AFF65497632B9740AE0E97ECCFB021D2E7A102F9709DC8E2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=kpoLH2aZ;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

The aux_stack[2] is reused to record the call_rcu() call stack,
timer init call stack, and enqueuing work call stacks. So that
we need to change the auxiliary stack title for common title,
print them in KASAN report.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
---

v2:
- Thanks for Marco suggestion.
- We modify aux stack title name in KASAN report
  in order to print call_rcu()/timer/workqueue stack.

---
 mm/kasan/report.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 4f49fa6cd1aa..886809d0a8dd 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -183,12 +183,12 @@ static void describe_object(struct kmem_cache *cache, void *object,
 
 #ifdef CONFIG_KASAN_GENERIC
 		if (alloc_info->aux_stack[0]) {
-			pr_err("Last call_rcu():\n");
+			pr_err("Last potentially related work creation:\n");
 			print_stack(alloc_info->aux_stack[0]);
 			pr_err("\n");
 		}
 		if (alloc_info->aux_stack[1]) {
-			pr_err("Second to last call_rcu():\n");
+			pr_err("Second to last potentially related work creation:\n");
 			print_stack(alloc_info->aux_stack[1]);
 			pr_err("\n");
 		}
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200824081222.24919-1-walter-zh.wu%40mediatek.com.
