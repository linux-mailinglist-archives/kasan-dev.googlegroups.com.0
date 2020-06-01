Return-Path: <kasan-dev+bncBDGPTM5BQUDRBW432L3AKGQE25ME4NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id F344A1E9CF1
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jun 2020 07:10:52 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id i12sf7702467pjv.6
        for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 22:10:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590988251; cv=pass;
        d=google.com; s=arc-20160816;
        b=MIh9qNFNQBGVNF2FaaDFqbd4aeeLSRmgrW1Kff57ESHBwJH+qCpepL9sIqu7BoozIj
         DcHv7KP2KEyaEDUInYn1pxDenikUpqT8EGPYMRquTmQWs5kS8Obs7Fhcjfbe8tp2lsag
         Ga1eC5i7yWQ64bIGrCxLYsUqRyWFcB4jJAiLpEVRznpbZxj2AXS7HED4qWrBnaT6bQMN
         71FF+JzWPpGrEntWYY4ynFxeg1+TDLl70UzA0bfNOJJnCQy92fCvY5/y/vQFC03yeTNI
         RHXwzaHlp/uuXbPki3nsq4lll/YSXxBtAGoPb1FRjR+R3w/JLJtlp1Jvs7RB0tE38fFb
         Xm8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=CMZJHtFYVjXXCEG9O+d9Ewf/vj2ghGJgJpjPfi58JmM=;
        b=ivE1yO/xdsXLXEMKTZV3cJZLcuVfuQQzuBHIwKQ8ecRJAIEE9hqeMHjaO9obtBfAiu
         R/XKsfPcKe7OymWR1YAn9HCNifszL87MCCx0B6LdyUv2z6JVZLioepB7czTOhi/hJeVj
         R3WBs9zPv3bp7IcyhkPuthSrABb3P75SAEudSfaqrFAIe3iW4iD7AlagKNdN854nFSMM
         /CQYj3w5m35qXcgJE4yDYyfx1+JWt90ennHSOamrMZpTzMOZc6KfUKygdCH3Qb89/BGy
         Ks5sMeM+3FSasm6tff7aBYKX+/1GO2ZCDExHcDG+bWNM8q/BVspyUTi5UCqaxWIyfr3x
         Ygug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=DoVUV87u;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CMZJHtFYVjXXCEG9O+d9Ewf/vj2ghGJgJpjPfi58JmM=;
        b=tRH1ji1oSo9IlgYp85RcLE62JQDUllekOKdpDI5JMQvBmMVs9O9QgebJQGeksTeusd
         fcHcKfsKzXWf6Fq+UbruLtVB7ekFShlWm1dNw9raWEhvcURfWBWRWtDi5TOSR8EqUYoR
         pVVsRrOr7j0NBTtFwbkncio7h3OIE3Otle1ufbu+ha1m1/E20qZOVprnmw0PIHVjE+GQ
         Py8Qj1nutQu434Kjyr0UeUgpoiV4Lb5m2BrteEBwOEQFmUnlQqq0Ez+qtimIOGQJnbHT
         c2pldFilqBCdN8sDyBL4Alp0QQPtmbHHfSpZ2U/+wD4m6KBuK0PudVyerQWrwZ0sC/vP
         1Unw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CMZJHtFYVjXXCEG9O+d9Ewf/vj2ghGJgJpjPfi58JmM=;
        b=mznHm21SsKhXRKkF8JCKiccIGK/q0z320FqhtaaefnD0ntIZalDFYL7x8vu/YhiUtv
         O+8xBffkCcGpW+boEC42pS+vEXpdppZOch0hXSOU2fyKpSRic78ouUxDaGTk//CsmAtJ
         Sx0Fcxn7UUQtGIFiV0LSlFeI6vnPOiN09VfOWcJt75lMeL8FM3zenZ3k0+IAXpmwqgiZ
         Ngj6/lQiUYyuynflPB0798/3U712qC7cWb2euP6XtEK9xDH+w3dkLSQZFxCtvXGbb4hQ
         xLUqrNKKCtdUdfBwqJUpXPrV3gRCwNvsDutV7ZtkUuUmR09ykwisWZtEvoiP2adWOcq7
         wB/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/ZJK+9VXnGwlpquOPYHrmZOh15AkyBYU61m5GXltgVlf01zST
	lKSmwpHKq703UP+WvhTTi8k=
X-Google-Smtp-Source: ABdhPJy2TzFrWJwcRYHxx9vePU9AzkALo8iThJ/6PKyhWrvs0pOFvI2hR/bhkh1D9IyeGVXC/dowMw==
X-Received: by 2002:a17:90a:aa8d:: with SMTP id l13mr22306268pjq.92.1590988251731;
        Sun, 31 May 2020 22:10:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e283:: with SMTP id d3ls6164032pjz.2.gmail; Sun, 31
 May 2020 22:10:51 -0700 (PDT)
X-Received: by 2002:a17:90a:c004:: with SMTP id p4mr22577145pjt.170.1590988251412;
        Sun, 31 May 2020 22:10:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590988251; cv=none;
        d=google.com; s=arc-20160816;
        b=ycUIRsGacSVc5kAl2KEK4bZ65/sYx7F1kFaUPh9QhAAaeDlr1uH0McsqIBvk4TM4gJ
         CEfpvnzAUQULURg03Mp6bAiZ1CvrOQHSyzl3G+Rlp/0sEn5MmImZRrr2jWJpyf1cO+wx
         dknaaJH34Oz37qC8qJiCDkmpK50mBFh7m3mj6udyfAMz4T9YFCJTs5+nAvlFA4Ykk1VV
         ISzq9B1MV6oXWTkKaqBnXoH6Rfv2cSjD1WpVZlQxk5CCvtv44X0gj3mW4nYAbP4s53ih
         ODghU3RaHvpVFeUa9YFqHJJPv2Ey15OuxLOy+W67hV5uaHjfKMMLXGv+iVm+f6cKZRXx
         kfMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=yDR7fBW0w3Clej91Pw1AhT0fTfnOfzcSfnAFnKMCDeY=;
        b=0/9e4N4PCzIZEV0jyApvvb+WpW5kNgSKpbrWQnsz0f9ChFwu80rhCtLkYDMA3UXOP7
         85PILySFLx4lFtykbNK42Ig4T/KveZpykSQxAETgEbtnrXem7DN0QOfg8//Nq8nvX3ZV
         FDEfHC4Oz+inujbPa71uZfO3zpCdFExFL3DOlOKJ1F8rcLwZENbYhpXJ+Nx8AgqRXUEZ
         DnGEhzQIYZB2ZVoIzl4owx/LA+sxjKGHpLDGBhM0ZQxx9GKj6fTHhYx97KHqz5hsPN3j
         Eh6IVGYmvUCY9ivXgITPL3P2NdK7FPrqWps8bWuZF7fXL0l/KgR5lt61wkJ4JB/F0Kpi
         w1XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=DoVUV87u;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id k138si955795pfd.1.2020.05.31.22.10.51
        for <kasan-dev@googlegroups.com>;
        Sun, 31 May 2020 22:10:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 69160eabfc9d4a57b299d63ae5a5b5a1-20200601
X-UUID: 69160eabfc9d4a57b299d63ae5a5b5a1-20200601
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 638810319; Mon, 01 Jun 2020 13:10:49 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 1 Jun 2020 13:10:41 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 1 Jun 2020 13:10:41 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v7 3/4] kasan: add tests for call_rcu stack recording
Date: Mon, 1 Jun 2020 13:10:45 +0800
Message-ID: <20200601051045.1294-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: D8A8F87A7EBE82FF4344D1D95091710F4072036184D117EAF9E3DB45434009172000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=DoVUV87u;       spf=pass
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

Test call_rcu() call stack recording and verify whether it correctly
is printed in KASAN report.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Reviewed-and-tested-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Matthias Brugger <matthias.bgg@gmail.com>
---

Changes since v6:
- renamed the variable name in testcase

---
 lib/test_kasan.c | 30 ++++++++++++++++++++++++++++++
 1 file changed, 30 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3087d90e00d..19c72c1501ef 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -792,6 +792,35 @@ static noinline void __init vmalloc_oob(void)
 static void __init vmalloc_oob(void) {}
 #endif
 
+static struct kasan_rcu_info {
+	int i;
+	struct rcu_head rcu;
+} *global_rcu_ptr;
+
+static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
+{
+	struct kasan_rcu_info *fp = container_of(rp,
+						struct kasan_rcu_info, rcu);
+
+	kfree(fp);
+	fp->i = 1;
+}
+
+static noinline void __init kasan_rcu_uaf(void)
+{
+	struct kasan_rcu_info *ptr;
+
+	pr_info("use-after-free in kasan_rcu_reclaim\n");
+	ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	global_rcu_ptr = rcu_dereference_protected(ptr, NULL);
+	call_rcu(&global_rcu_ptr->rcu, kasan_rcu_reclaim);
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -839,6 +868,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_bitops();
 	kmalloc_double_kzfree();
 	vmalloc_oob();
+	kasan_rcu_uaf();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200601051045.1294-1-walter-zh.wu%40mediatek.com.
