Return-Path: <kasan-dev+bncBDIK5VOGT4GRBAVA62CQMGQEUXLU3PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id A687C39D356
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 05:18:28 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id z3-20020a17090a4683b029015f6c19f126sf11617444pjf.1
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jun 2021 20:18:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623035907; cv=pass;
        d=google.com; s=arc-20160816;
        b=hdITsO2pR0f//P8bUcEuRjfIE71sP2pe6hYKxrhj8YkEgLGJQBxRrZut2YgfLbN6fe
         Te5EPjogQprN0dIZvcmVkHMmrX/EJmLLG21iqQEPu6+H9PLohvJlXVMeReM0Kdb994SG
         MKfldSdD0tZid9ZyCtlrFtluCQewwguGpVeVBfdeJG435DvIdVELXpOVJca7pYQV4nOE
         fl2Xj34Ls/fOxrgyG4T/F+DP8FsQCnYdHxx6PDKFWvX0PxuA53v+1HfmpXSdfiArRLO3
         hceFr5WpIt0Iy4C535r9FdMp02hSJTHeWnxbFuHpqK4XfmsA71LcP9zNZziEPudZVahv
         GiRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=skV1Habt4OtgdrPqOVzVquuMUET0CJ1DHzn2wpJdfSA=;
        b=crBBjRW9c10FU+sdAOuD3V+9WLgkYXKUFE2Byv9eaZ8KnHZswFSO+kiX9D+3KJvgBu
         7k+6SuBxrTeyT1l+i5Y+q0FbihQsSyMo3wISJ3281GxM/JlVIulaO4NcMF7B01qw9Opg
         Uv2J5K/2ibC24OwbImSdBE7/5h1KvALrR/GYijqaAoB91ZzkICIqMQUj9WuHvYn5eZ8J
         JXFeFglb+GsPIOoS0CZvTuksYGcb2up1AHHnlWV+SRNKqFAXQ8GAg+zYDawjl7iRD203
         z2ctZC+UJ64aD4OrYgo5bNl/kODFC9bGSBXxfYPGsxRQL4PSOgmSlTg0hhiEmVECBOrt
         gV/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=thunder.leizhen@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=skV1Habt4OtgdrPqOVzVquuMUET0CJ1DHzn2wpJdfSA=;
        b=XNbcxzQpZzCH0Xw8m7h1UY2yBgnJMRu9MS8Qvx1pqDQtR2dm0taeY4RTuvIiWv/9C7
         wIktZJTktwtBklAq4YhnngONspdHPcL8WOdzdZ1K7tkRBqneQMHPlT1ryV9kR7vw9N7v
         zi93pNXiPTgcMdNFUvRuw4f+HanJ0H5RrXgncu1kpeQBdhvF25cx0VmG5kcCTpHAX1tK
         W4yMG+1WJWgwasAN0JtVxcqoA04BJB03SFbwjFbbw8PPbps0RrWJe41YTf2+LLjGha44
         aWX3wxh+ALvNNoAcLkKAhdJ3KwoksP8ulRtzURIebkhxxeuifsTFr2nCsCbJlbP5m0Gg
         SdDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=skV1Habt4OtgdrPqOVzVquuMUET0CJ1DHzn2wpJdfSA=;
        b=IAdqlwz//NU4JwGerxJzhLj8ux1uQi7PB/5SgBzCZ+h9PCVgsQPfFCU/nygly1Aa7c
         2gVvKftkIpRy96FA9hOm7BXyUD6C5qw+szngSnLMl4cK++Uwu695j+1O5HISdnNeJ9iy
         Gtn9uWithPsqwGC1dyOkKZVx7eTekTxP+JyWlMaCCIflAZcXGa0Svdo+OOcCDIRGFPvu
         zCpjkpcaLfCQvFh1nhjNwto2K6OhTpeus3QezF5If0spxqMBqu2WfowXvwXTbijygmi5
         FXXkZonfNHy2hiBqmgkofs9lo+KlVdr8fnE3ksjTf6RDJ2x+VsVaBp8cdxfpJivYpWBW
         R56A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532blar+PjnU5UYWeENoFUzrc0PDqhj2IhSdtcA2sm3R04OD8VQc
	rESsyq3MJRnoziHzO95efCE=
X-Google-Smtp-Source: ABdhPJxDe4IgtZL/y35kdlMsINi0PP4AMsfPCUhmbuhaOuU32Qr2ktFdeKAs8bS8dCGTI2npV2GrDQ==
X-Received: by 2002:a17:90b:3142:: with SMTP id ip2mr12109255pjb.63.1623035907058;
        Sun, 06 Jun 2021 20:18:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b48a:: with SMTP id y10ls7475897plr.7.gmail; Sun, 06
 Jun 2021 20:18:26 -0700 (PDT)
X-Received: by 2002:a17:903:2309:b029:113:19d7:2da7 with SMTP id d9-20020a1709032309b029011319d72da7mr1020619plh.55.1623035906569;
        Sun, 06 Jun 2021 20:18:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623035906; cv=none;
        d=google.com; s=arc-20160816;
        b=sB6AK9Gd1+nDeWLyBUBFZiIyxSy64rMJUX+p5irNFfhsV0CTSwilFNvWAbTCHJV5S/
         UJuGfT60oyQGcnjRRgGg9yehkhzhxNT9pqPsyeiopeBj21+MSR65G/sfLObUIa6Axphz
         CpmiACD304OTN9BK0X3w/KlnXgqrfuoc0CywqMgB/tF69WkFe5TI8+NAcUXjfUhRD/Af
         GMb+vBLfcFIFQT/SPTXJng2f40LyK0ygVvCNKCqzwuyY0lM5qHSmAhQlgRrA/4yeqFP9
         96OA/n553v48mdpPpv6Xyx06yHxRneFJDAspgbsvX0ROPJiZ4OufveDFcoTPb3C8PyxF
         OL6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=4LXBEE/CFrOu8vvJsbV46BTqJap3ifJc62mHrbOTLt0=;
        b=MD/Q/zZ6jm330S2fiuAwX1UOngmVPo5UiJwtx+Yuj1qHpwrle2/Uk/vVGqgUmyDkS3
         h/qF7yp9vhVt2I27eqnEmSY/6SxTeYXQCwQp3Tf4bCk84f8sQx8j73yaRhylWMpCcIel
         8e68M8JCQgk6u2q6xMK/Zv2p6VCdYxDD5pCA9iL7nhK/BR6LakavemITSxuJLW+TfX09
         xKytyipQasAXjWybEBnegZDfdePeV0RF57qGIHWINRDk4XeqZvVyxBy3/xqhQciAyjP3
         aFvQSdbrLcojy1emLz27Wxjvri7fsNns+hknZBwVtKqf4/A9L1Bgv2Lnoy65Tl+xdoKm
         6rQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=thunder.leizhen@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id ob5si312073pjb.3.2021.06.06.20.18.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 06 Jun 2021 20:18:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.53])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4Fyz5g1QY7zYrcy;
	Mon,  7 Jun 2021 11:15:35 +0800 (CST)
Received: from dggpemm500006.china.huawei.com (7.185.36.236) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 7 Jun 2021 11:18:23 +0800
Received: from thunder-town.china.huawei.com (10.174.177.72) by
 dggpemm500006.china.huawei.com (7.185.36.236) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 7 Jun 2021 11:18:22 +0800
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
Subject: [PATCH 1/1] lib/test: Fix spelling mistakes
Date: Mon, 7 Jun 2021 11:15:37 +0800
Message-ID: <20210607031537.12366-1-thunder.leizhen@huawei.com>
X-Mailer: git-send-email 2.26.0.windows.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.174.177.72]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm500006.china.huawei.com (7.185.36.236)
X-CFilter-Loop: Reflected
X-Original-Sender: thunder.leizhen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.187
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

Fix some spelling mistakes in comments:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210607031537.12366-1-thunder.leizhen%40huawei.com.
