Return-Path: <kasan-dev+bncBDIK5VOGT4GRBEV77CCQMGQEGXCWO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id BF5AF39DDA7
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 15:30:59 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id w10-20020aa7954a0000b02902eac51f8aa5sf5712501pfq.20
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 06:30:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623072658; cv=pass;
        d=google.com; s=arc-20160816;
        b=TSEDFH5LQsm+/RXZuE77A3nIVJLVdbLDXWyuBL3/oUQKF4Aizs7/onyzSyxbtg8NVT
         FJa3gqCZosbrWk97CLUaGfh405JaLwci3cYUGM/mW4uepe+/6ygpzhiPkV7OoMMJ2slE
         aUr4UpxsKNMJ1+aE7vvh0pxOSMB4S2xieWfdaehoZ73cvHbM6GMDNi9a2WCtCKtw/Dsa
         lubbpapy2k73PWtZWh1FXKJPMwtdmLPfrUZR0aPe2lE6VsgMGO2GydVKO6A/oUK18EGV
         rodaiE45xiKfggQgqk1RiukBnWb/6pHdBaoXyZn9LMgwDofsaCxrZ7jxpx3oZl8JQplc
         cGxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JWrCPC+MuRusZLjq6nWcsNBbHrMkRTm76+I0XUEzEbQ=;
        b=DDG0O3TnlhDrTGdeA26VXeCDbhxhVp1W+sMa8FpQ+JSdX+B42+0LSvpDbIYDCUz7u+
         2vxfhMV/9YPmWX+pfi98TiBytaivtiN6DNvKsdosIm6n3w2WUQhECUsUKZciGAZxaJW1
         kgD9aIRGGmmrYuEN6VqVNbx2AzNAjDl42A4TblTBt+tKKQ9eoqfRWshS0it0im2JsH8c
         f1yzrApANh6GdLhp6FZylVc34DnwKl7ErvYGRdm8svsYj08S5YgXItRXRr9qmaG8ngyZ
         VMfoWWeO0yNLuajqjMje4REPTPzv/u2QrSBwmi+gczlRAWHLgZOmlqB84LQ5ToVw7Wg+
         /ziA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=thunder.leizhen@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JWrCPC+MuRusZLjq6nWcsNBbHrMkRTm76+I0XUEzEbQ=;
        b=NQ+gfZ680tvVS93ILqJ8eTT9J27SzxJe4YkdNkRWgA+1reBDNM+uwB6m2gvm2DDUd7
         EeqWF1eFjriVEsOMJFlbv4BIAR2If5tolaUMYlZ4jg/GCFyu8YgJtpXQLRbhQKovOH37
         sSfFmWlY0Uo2QVgvk4TMDMZkzUOzheZowU3kgLT0+qzOP9XCyJ3qcduoro7byWwBu7+c
         jQetVleV8ZWFuQvFbQncvepdRKx+0GpqUpTGXYtDDsXCqa8NJDTtkVOB4qRvMC9jjBha
         UMG+bDHLWZejOY06qwenzATqnfNSBnrbER/v+W1UP8afVlNGF/e/2omJtXqJ8Q78stnX
         J+Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JWrCPC+MuRusZLjq6nWcsNBbHrMkRTm76+I0XUEzEbQ=;
        b=kcAG1gRy8ijUNLpartNgvjWIZE8Qkucyaajtp5yg37wbDAuO3znfyw7Cw3lucGE84A
         DU26ifFB8EdKes1lNjZX4WH2W1lLTnwHPC7gHehucE4f6+udGkpK8MEHyqUkoobSDVGr
         r3gAlmsHZP8P9CQNiyQhhcR0fIMAnRuafnu2V6FWgAazDNfpu5i7UlOL5gaQxTKviS7o
         OuEGb7f+bJ3blvh7sXknwE7KUIEfkw73y9IzY54XlQvxNeETbPdHcEpM5ycHQKHQ18ew
         wqpidK8iy7uqxPYujJqyEKHjgmR0KMoOSmYWmO/taYTYbyltbL4Apdw5d7iEnc3jcbnP
         CY/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530aTi8f5IQOFy1T44ub6L8BG8wx8zmUiKKX/1LgD2tMY9XPlrW6
	eVMwry53yXpNxeXCEZ1MZL4=
X-Google-Smtp-Source: ABdhPJwqGqY8ydMiNdpNlOJb1ldelLAjHlvEuB9b2BbZK3buV4VSiqaLl8Zfq7Kgw1VqtC0dWhsRnw==
X-Received: by 2002:a17:902:ea02:b029:111:75b5:439f with SMTP id s2-20020a170902ea02b029011175b5439fmr8421966plg.85.1623072658510;
        Mon, 07 Jun 2021 06:30:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:b256:: with SMTP id t22ls304779pgo.8.gmail; Mon, 07 Jun
 2021 06:30:58 -0700 (PDT)
X-Received: by 2002:aa7:8e5a:0:b029:2e9:10d3:376f with SMTP id d26-20020aa78e5a0000b02902e910d3376fmr17205549pfr.19.1623072657906;
        Mon, 07 Jun 2021 06:30:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623072657; cv=none;
        d=google.com; s=arc-20160816;
        b=IPbh5OEKd6wb9cEsObf52K2wD6SNgWIYMp12c4qKW1jPGPslLgvhSweOIs3IQIiMvX
         soYNyojbmIMCEzirsd9jQB+IpmJj5/rLUKRW6VH4JyAif/m1II7+CFXh6O//PD7YJ4WC
         hkKb/86cGOP/oTz02ylO/YaSjpce4FTyyB84fwe5sQcDu+1KbisCc6MOCO9inuXB2U3/
         eyVB0ZWqBNU1rXA6fhcuz7dWSWxu0LowEngUHYmZrIOnvpf8aTE64dXq/e8zcbqk9Jqm
         BXl13/50a/HutzLX/6JG84Ig36ORMI+6tTk6J+2A7PWiUGZwHEOCiu9rJIJ/1WLyInBL
         NprQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=q9zou71Zr62E01YXL0PQ03EtQaCxMmruIKr4sDj3qIo=;
        b=M/bZMGkC8QPQoRHzomJnJKc1sNT0RBH4JkBocovqRth75E7PTrFcp84WgcX+HHuc+A
         poDDENwXBeWII3D0uIH22pORfbAwi5e2WJXSla0xeJjWP538n01PxVZsDtJuURUi834h
         dDqRKrduwmgjp553EKZPeIa3e+fniV4Ph2ycnY2g1mhVORqnvvhtw76qqnxi68VsT6nz
         cgXja5BK7erzLJDiBfTj44+Mz7U3vZ0j92y6hmi7Z2YSzYYQoIk6zFvqFipLn25aDL3x
         KGo1cUJw9e42rYyP4YSzI+N1CC5OAPt8l3HZCAZp+OMIdUezUSuN7tdcNTotp17sut/M
         iZ4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=thunder.leizhen@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id t17si843322pfc.4.2021.06.07.06.30.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Jun 2021 06:30:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4FzDf55tkzz1BKP0;
	Mon,  7 Jun 2021 21:26:05 +0800 (CST)
Received: from dggpemm500006.china.huawei.com (7.185.36.236) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 7 Jun 2021 21:30:55 +0800
Received: from thunder-town.china.huawei.com (10.174.177.72) by
 dggpemm500006.china.huawei.com (7.185.36.236) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 7 Jun 2021 21:30:54 +0800
From: Zhen Lei <thunder.leizhen@huawei.com>
To: Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann
	<daniel@iogearbox.net>, Andrii Nakryiko <andrii@kernel.org>, Martin KaFai Lau
	<kafai@fb.com>, Song Liu <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>,
	John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Luis Chamberlain <mcgrof@kernel.org>, Petr Mladek
	<pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Sergey Senozhatsky
	<senozhatsky@chromium.org>, Andy Shevchenko
	<andriy.shevchenko@linux.intel.com>, Rasmus Villemoes
	<linux@rasmusvillemoes.dk>, Andrew Morton <akpm@linux-foundation.org>, netdev
	<netdev@vger.kernel.org>, bpf <bpf@vger.kernel.org>, kasan-dev
	<kasan-dev@googlegroups.com>, linux-kernel <linux-kernel@vger.kernel.org>
CC: Zhen Lei <thunder.leizhen@huawei.com>
Subject: [PATCH v2 1/1] lib/test: Fix spelling mistakes
Date: Mon, 7 Jun 2021 21:30:36 +0800
Message-ID: <20210607133036.12525-2-thunder.leizhen@huawei.com>
X-Mailer: git-send-email 2.26.0.windows.1
In-Reply-To: <20210607133036.12525-1-thunder.leizhen@huawei.com>
References: <20210607133036.12525-1-thunder.leizhen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.174.177.72]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 dggpemm500006.china.huawei.com (7.185.36.236)
X-CFilter-Loop: Reflected
X-Original-Sender: thunder.leizhen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.255
 as permitted sender) smtp.mailfrom=thunder.leizhen@huawei.com;
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

Fix some spelling mistakes in comments found by "codespell":
thats ==> that's
unitialized ==> uninitialized
panicing ==> panicking
sucess ==> success
possitive ==> positive
intepreted ==> interpreted

Signed-off-by: Zhen Lei <thunder.leizhen@huawei.com>
---
 lib/test_bitops.c | 2 +-
 lib/test_bpf.c    | 2 +-
 lib/test_kasan.c  | 2 +-
 lib/test_kmod.c   | 6 +++---
 lib/test_scanf.c  | 2 +-
 5 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/lib/test_bitops.c b/lib/test_bitops.c
index 471141ddd691..3b7bcbee84db 100644
--- a/lib/test_bitops.c
+++ b/lib/test_bitops.c
@@ -15,7 +15,7 @@
  *   get_count_order/long
  */
 
-/* use an enum because thats the most common BITMAP usage */
+/* use an enum because that's the most common BITMAP usage */
 enum bitops_fun {
 	BITOPS_4 = 4,
 	BITOPS_7 = 7,
diff --git a/lib/test_bpf.c b/lib/test_bpf.c
index 4dc4dcbecd12..d500320778c7 100644
--- a/lib/test_bpf.c
+++ b/lib/test_bpf.c
@@ -1095,7 +1095,7 @@ static struct bpf_test tests[] = {
 	{
 		"RET_A",
 		.u.insns = {
-			/* check that unitialized X and A contain zeros */
+			/* check that uninitialized X and A contain zeros */
 			BPF_STMT(BPF_MISC | BPF_TXA, 0),
 			BPF_STMT(BPF_RET | BPF_A, 0)
 		},
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index cacbbbdef768..72b8e808c39c 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -656,7 +656,7 @@ static void kasan_global_oob(struct kunit *test)
 {
 	/*
 	 * Deliberate out-of-bounds access. To prevent CONFIG_UBSAN_LOCAL_BOUNDS
-	 * from failing here and panicing the kernel, access the array via a
+	 * from failing here and panicking the kernel, access the array via a
 	 * volatile pointer, which will prevent the compiler from being able to
 	 * determine the array bounds.
 	 *
diff --git a/lib/test_kmod.c b/lib/test_kmod.c
index 38c250fbace3..ce1589391413 100644
--- a/lib/test_kmod.c
+++ b/lib/test_kmod.c
@@ -286,7 +286,7 @@ static int tally_work_test(struct kmod_test_device_info *info)
  * If this ran it means *all* tasks were created fine and we
  * are now just collecting results.
  *
- * Only propagate errors, do not override with a subsequent sucess case.
+ * Only propagate errors, do not override with a subsequent success case.
  */
 static void tally_up_work(struct kmod_test_device *test_dev)
 {
@@ -543,7 +543,7 @@ static int trigger_config_run(struct kmod_test_device *test_dev)
 	 * wrong with the setup of the test. If the test setup went fine
 	 * then userspace must just check the result of config->test_result.
 	 * One issue with relying on the return from a call in the kernel
-	 * is if the kernel returns a possitive value using this trigger
+	 * is if the kernel returns a positive value using this trigger
 	 * will not return the value to userspace, it would be lost.
 	 *
 	 * By not relying on capturing the return value of tests we are using
@@ -585,7 +585,7 @@ trigger_config_store(struct device *dev,
 	 * Note: any return > 0 will be treated as success
 	 * and the error value will not be available to userspace.
 	 * Do not rely on trying to send to userspace a test value
-	 * return value as possitive return errors will be lost.
+	 * return value as positive return errors will be lost.
 	 */
 	if (WARN_ON(ret > 0))
 		return -EINVAL;
diff --git a/lib/test_scanf.c b/lib/test_scanf.c
index 48ff5747a4da..84fe09eaf55e 100644
--- a/lib/test_scanf.c
+++ b/lib/test_scanf.c
@@ -600,7 +600,7 @@ static void __init numbers_prefix_overflow(void)
 	/*
 	 * 0x prefix in a field of width 2 using %i conversion: first field
 	 * converts to 0. Next field scan starts at the character after "0x",
-	 * which will convert if can be intepreted as decimal but will fail
+	 * which will convert if can be interpreted as decimal but will fail
 	 * if it contains any hex digits (since no 0x prefix).
 	 */
 	test_number_prefix(long long,	"0x67", "%2lli%lli", 0, 67, 2, check_ll);
-- 
2.25.1


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210607133036.12525-2-thunder.leizhen%40huawei.com.
