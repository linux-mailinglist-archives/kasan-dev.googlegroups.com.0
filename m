Return-Path: <kasan-dev+bncBAABB3VFSXWQKGQEJA6V5QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 868A1D6E70
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2019 07:02:39 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id u64sf7789615vke.18
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 22:02:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571115758; cv=pass;
        d=google.com; s=arc-20160816;
        b=jzLQJpx3C4lunYb/EAB6zSncwxEaMCwZ8PCBGQ5mX+X+tfK99abYbteDP5VX4gajSQ
         p692H41WdFU1Z7fIR0iv17IhzlWxevswu7yg1jhzB3WVZlrjEv2fxLwqmpXNbVLBlTiW
         bEDDGmAxpj1AlsU9sroBdehvpdhQHQD0ujWvs8d0owPTyTKXYfrOadLomPc1xi4kifEe
         USJEPyQIba/qsbx6VZYZIrN94q5mbkdGjfEw5hZ58VDtJnnxkLGqklIOR8YGzIn0+6El
         VorQp4LhjZpbL84ijSXbcuOkNyu6pci4Fqt34DdFaONH3jdCt9qysUC6gnWMChG1vNck
         VGGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=+U7wmfZm0+0WEmUsscI2cK3RwrIJBdM2vDKgMRO4+nI=;
        b=iL50ssu6mpIQriPAaEI9Q/kks4hVLxo2eJv4LsIfuLsMS4TyihbHNUiUReVUBNXr2A
         j8mG1llCDtWJdhcyJT6OfP8jnIfw1RUGAp67l7jKS2KlPpUukP6k3XzKcKWByijBffLU
         SR+9aK1XJx7K8zn/DhF0z3nmB03Fqw80EY2XnLKejGH+h3Fz7TCxNVSlCV4Iwb1U6KJJ
         J0U0/nbUM5XtUGnWgdY5KnUzIzwSIDovfLNO1DwOr0QEsSTQOuw0HhKxMqhRP95oKkzY
         vxK6ffX+LT5ICG7po7RhSh2a8BNf2tvDj+TKid4nPvOnIsJJ7qidY1vatsy/mvm5JrTJ
         caFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+U7wmfZm0+0WEmUsscI2cK3RwrIJBdM2vDKgMRO4+nI=;
        b=M8g/D2p/AWc1qgc7Ttf+RcrGZcZRKs+cP42q3sNwSlORjAcjWOTZ4HL3hKf7eJ7y+0
         nr7hKW38CL+OyqX29cejMFsEPYhR4FmUkCDaDHfjczwMBCI1KQhcNZE584Vq/9qP4n8M
         +5Iicklch2uG3xvxib+dZmMjTZIZ+8tFSBZH8APWrjTwjpFDqtpQOdMngJiE6AtrBOuk
         aR7czxuWGGqbWhl+iVu7I6ljuCxjVzL4DZMCmfYCn0qtCyevjJO29VkoeEswA3jGugIY
         QVw2YAR7CIPAbkFyVhy+64lZnRwyQn8clRAJvm5ZfvNMUDLDPnjKbHInWIdfLHMnWVvr
         AMJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+U7wmfZm0+0WEmUsscI2cK3RwrIJBdM2vDKgMRO4+nI=;
        b=aEQ4BkAeutZkR4sqPdggV6vPR02TzC+jyBVmjgbfQSm1oRPFWfXucAgqWNiMYEWGbH
         EgkScaXRnMPaJFXnSRURqRbIkKOpsrpV9LVaDawSr8wsSm9nbeOuib/Zeg6yPPCuiLT/
         0x9IMITBjiQ+eAH/2/nnZaGcbEhpzneBOpcE1DuxT3rkROHBKfwCHr4JsDW82WvYlUUX
         ZRfZmxN5m/FVOcFPPqpPqMkp1NZsfiuEC6a/H4UNQJrk+ojfGyIpxIjZaqeHF9Oi0oFP
         y5pirSXUn5pRMOlafQeyDjO8+8+ByWA95ol4SzO/nK1WTc9ev8CWM93UyhITvCmsmmeg
         O+2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW7hvlgDa3DSTuI32Mj4ArWd0+aKN19CnhpwQQwuXmJoukQXIok
	hYuwMSNF7xGJIY1HoZQZBBM=
X-Google-Smtp-Source: APXvYqx7pW+bRM4mGqQiab2m0mkIdbYBqXharW/4T/DinoNhNtTXF2c2ba1LGkgvszGcOGj9UshyZA==
X-Received: by 2002:a05:6102:414:: with SMTP id d20mr19168176vsq.173.1571115758549;
        Mon, 14 Oct 2019 22:02:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:35e8:: with SMTP id u37ls860546uad.10.gmail; Mon, 14 Oct
 2019 22:02:38 -0700 (PDT)
X-Received: by 2002:ab0:b6:: with SMTP id 51mr13766140uaj.2.1571115758169;
        Mon, 14 Oct 2019 22:02:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571115758; cv=none;
        d=google.com; s=arc-20160816;
        b=SWIrqbRbL8g2Lc2jus3/ApYfeBn2UUDRNPK7vfufHTG3jYixtq+9WhPgVIto7Mgy4j
         T7fRNUJ45tBIa0yH1oKMGI2SzpcnZwebZtGmdHj+2vjt0YLUb0Fzebz7cMRjxlBex7cT
         uzI0YXvdm8JEPf7lM6uq0O+FkLoVNGHO+eYbgaVcYnyl3Rr5OGL6CFtxEkvg9VLnZX+w
         aQxKviPsZz6E4hFLOZjmvqaIyT9Bv5SB1HGa3b2qoMkWKhXw9LbjmsaGu4UXCrIAOCgP
         9MKZyDaG68tyOrGjZlln3V0wbXdmR0Zo6C7hs6ayeNq328cq52NOCH8NkYnXPR1Z4pa8
         rAhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=AOnbhAxZKUPhDl3erX8sCfBDgQz5TkhEn3TpyuU6OzI=;
        b=H5OCjH5vOvpJAUovDPL+otXK4AADkfEKX/UKLG9xtqmlZMdQtIR3pE8w5xTfNozLKA
         aOoFdWv8T/5fdmKaLgS8z0YDPKZGzIj3mp+GYxMbt1ybGtCFTQD2b/iZK0uMDgW1Wsey
         W8E86surzuWfdWceiID+V080pymgsgg4Of1qnGHWehSmWUtcCGR3S3MMxuWGb0QhHwFs
         JwdYn9dKsoFR60Y2WhLsY19RVpXVz8lrTzlcjeMLsT2SR40YKUHc9SLtindI3G8kqhYr
         VSd0sYlzCKglqmTGAv6V+GzJP2NPNDlE3KM8tvwqe9hMFszA/uqXMhsocZe60fRFVt6V
         0O4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id y14si696918vsj.2.2019.10.14.22.02.35
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2019 22:02:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 62f03084beeb45c09eb9d12c94df3f27-20191015
X-UUID: 62f03084beeb45c09eb9d12c94df3f27-20191015
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 706590738; Tue, 15 Oct 2019 13:02:33 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 15 Oct 2019 13:02:29 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 15 Oct 2019 13:02:29 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH v2 2/2] kasan: add test for invalid size in memmove
Date: Tue, 15 Oct 2019 13:02:30 +0800
Message-ID: <20191015050230.20521-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 76C7B23B7010F871BB120DC39271DA7F14504898BA30BE7C2D2C7F7C49CAD97A2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

Test negative size in memmove in order to verify whether it correctly
get KASAN report.

Casting negative numbers to size_t would indeed turn up as a 'large'
size_t, so it will have out-of-bounds bug and detected by KASAN.

Changes in v2:
Add some descriptions for clarity the testcase.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 lib/test_kasan.c | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 49cc4d570a40..06942cf585cc 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -283,6 +283,23 @@ static noinline void __init kmalloc_oob_in_memset(void)
 	kfree(ptr);
 }
 
+static noinline void __init kmalloc_memmove_invalid_size(void)
+{
+	char *ptr;
+	size_t size = 64;
+
+	pr_info("invalid size in memmove\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	memset((char *)ptr, 0, 64);
+	memmove((char *)ptr, (char *)ptr + 4, -2);
+	kfree(ptr);
+}
+
 static noinline void __init kmalloc_uaf(void)
 {
 	char *ptr;
@@ -773,6 +790,7 @@ static int __init kmalloc_tests_init(void)
 	kmalloc_oob_memset_4();
 	kmalloc_oob_memset_8();
 	kmalloc_oob_memset_16();
+	kmalloc_memmove_invalid_size();
 	kmalloc_uaf();
 	kmalloc_uaf_memset();
 	kmalloc_uaf2();
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191015050230.20521-1-walter-zh.wu%40mediatek.com.
