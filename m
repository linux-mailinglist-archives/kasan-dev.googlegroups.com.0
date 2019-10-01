Return-Path: <kasan-dev+bncBDQ27FVWWUFRBLPSZPWAKGQEFWNKQQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D2DAC2DA1
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 08:58:55 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id k13sf28184125ioc.11
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 23:58:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569913134; cv=pass;
        d=google.com; s=arc-20160816;
        b=KZDrzSmbU/D8cJbbtdcwO6SbVr/3JYZP15WOpr2zW+DbwZJYP8Vbh1iVd7WNG1m6y8
         VdZhvKaVMOhmUlD5B/ijCMu7sISKiSWyMX8GIMaAlei7r9yXKhd8e4TbvcV9dacd3HR0
         dsFiKKnLB9kdjlBuFh0FcCpwl9NLvLliFtX9O0UEAZ4stWqasaj3KTru+zKEt7B+zjaM
         sUxKyKPN9HNukPA75khw7FxmE92jBhk5ILYj0rswENO6uDqZVlNR+z6S7ijMxksLPJ3p
         2evoNF1z+SBFN98oUwWflqO4ytOWPCwPh4qGu8T+KAjpoe7Ti5X5eiYr4naiMS/XW6wF
         lQfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EpwN0Za8XBLTDmTZN9a0Ird09s+uU5mUmBi3VXyZLVA=;
        b=iALB3o2xfVNC4niAppWQlive9H5JrvQxhRnhgTYoCIAhoiRRt9GvnJrI+Z5A8ipjkF
         GbJDeCjBQAl68ufcRlWJjC5jYnvGEvDBii5HW3wTvPiuwlIz1eeWSBwYZCVvjgbcItmc
         Gbgj+f3Wkpv9Vr/xQsovpfT4dfKW3zsQ8MIQ7ObDf1z63sSxgcBGpf8oIGiHwP3+nLrw
         Kl52Vw3khpPlSXzMz0zvli8le8Nun2fptyDj/ApZrgLeTV82+qVPiCVvIWJR2iJLT5Iz
         Va5fdgzzAJTKhabDfwJ1dbSD3CHUtyhztzglE+/z/8nRu83E6vJcukQ4u/rkOnfzTI6I
         5LEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Gx7gIW3x;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EpwN0Za8XBLTDmTZN9a0Ird09s+uU5mUmBi3VXyZLVA=;
        b=ozYPk/0hF41Y7DfFJ7X8GnuSOhbpDCPclw4s0JOhLbPH59Hzoe7JvHnuHE0hJvtjbe
         wr6Zlb4rkCeyfo+tIbyXvE1bKUG3HyP55zc7pScnFqnutDAX9hs9x83kXy5eapvZCtDE
         ij/MX9nepqaeiOddz4ZXYm6e3idJUkrzzsrV9eqhQnAszOKxQHSfT4B125RnSjtKO7t0
         KL13uS1Elzn1qI/XXBu6ixCLBBowtadwxZWisIslBCoaZTOOtsRNFJhoKIwVBn8HTyGn
         1R/0Twh/McFpVtO+iugrYQryZl0lYrUtMpkplBjuPAwu2peoMlvXbgtTqeYBqgN1h5kj
         ublA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EpwN0Za8XBLTDmTZN9a0Ird09s+uU5mUmBi3VXyZLVA=;
        b=KM5TEb8v+wciudTgiQ5jvXqa/iHBodxbvGqcDacQ1ZtfTfCu2nJAyLGBGVQr+MMFmN
         m0mKW+VDzu85muiGu3Dm0979EotBfsq1bEdwtv9+TDgdJ8iDBfsiv3a78tx/YuDYgGsC
         bHuEbtDeOF0X0bIwEMhChB08kv8kea4VW2SzbIjwZCCklPzHCbNqHwMCsA+OvRSEouX8
         KR9fGZUCT3ckKeMHrMAhyOdRk/CZYzdAkmwpG/TBhgBfFeOsHPNhJ0Z/u5jisr/8svB3
         R+iQYWCDtxDluhYmveFxMQ9e9E64Z0hrdD93irdQd8YbqfPtHn2LV8HeGrBWip3IXwjl
         Svvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVGp/L3EwIFH5CT+tNPd8+On9QJluNdGQ2efbiiA0AQcS+yEsCf
	YsQubUnH6QV7wGVbsEm8fq0=
X-Google-Smtp-Source: APXvYqybeRqaSI4XXKTKJ4HnA4t4Nl/god67hI0/gMKi68LV7wbogw+ctwyYsGohmEg0hqCHDwVeEw==
X-Received: by 2002:a5e:8404:: with SMTP id h4mr25573646ioj.170.1569913133798;
        Mon, 30 Sep 2019 23:58:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:54e:: with SMTP id i14ls2868691ils.11.gmail; Mon,
 30 Sep 2019 23:58:53 -0700 (PDT)
X-Received: by 2002:a92:2903:: with SMTP id l3mr25010410ilg.109.1569913133460;
        Mon, 30 Sep 2019 23:58:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569913133; cv=none;
        d=google.com; s=arc-20160816;
        b=fWLEKJMCzVUuRix/gySd0JSsUL4fXR00fRtM8HnxxbNQe5ncMChpT2YOfJCkp1kdIn
         BgKTxwjaiM7pXBoeim6W/976BO5HLpenPD+q7s62gcKoWNkSPgp6BYS24IbtLtvXX4r6
         mhhjf5bE6nzqbT2eQXjzo/z/DAldiEv9LPWIz2TWARB9fog8GKcukTtSMAvoWX8gDR65
         I/S7C3zRcqzV52RWoNOwaWQR4ZAjAc49h+Hb5HgAEphHLhmiZ/lD7fXwy0iT6fWDds2E
         OVtfCG+gjU73q8kszYzVhRDXHnwEu1mff8JCFfHEYfjoDoOcrOcfm6YIN0HyVx6kuvTA
         RINg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HNDV9DT7O32N2h9l7CrACdWJSzNVfR3Dv9pnUT55kOg=;
        b=rUyFocIuPU6gOwltYgAiKEFBIYapDmD1Dgpof0OARAA/kmrigP0EVC1ii1EFuI4+ZN
         DwWyspM+ofUQtMNsWo4KCJVCY743ZxlD3s0BCun4j9Ut7Bf2kRq0S6VSBWseDo1u4h6K
         tSYEzymzd0qoLfvgEWneQGhzo6R40opdwG/gzI4JuoRn3Rc6Yz6/R3/gqp1LGYrjbjI1
         8mfU3x3Ts8kGk8Ij84E8uli15ABan3P4a0MZcrF0n4XkbSObjZ0v+JBs3mc0AtqMxHjn
         CvAi4JHowdIO1sCfsCsf4fSgvwpWkuUwgTOFJEpTH3z8e/Wq7Vkwo+IidfGbuaR9/aJa
         NRnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Gx7gIW3x;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id x3si778996iom.2.2019.09.30.23.58.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Sep 2019 23:58:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id 23so423408pgk.3
        for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2019 23:58:53 -0700 (PDT)
X-Received: by 2002:aa7:9a5b:: with SMTP id x27mr25409842pfj.232.1569913132672;
        Mon, 30 Sep 2019 23:58:52 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id u31sm29081976pgn.93.2019.09.30.23.58.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Sep 2019 23:58:51 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v8 2/5] kasan: add test for vmalloc
Date: Tue,  1 Oct 2019 16:58:31 +1000
Message-Id: <20191001065834.8880-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191001065834.8880-1-dja@axtens.net>
References: <20191001065834.8880-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Gx7gIW3x;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Test kasan vmalloc support by adding a new test to the module.

Signed-off-by: Daniel Axtens <dja@axtens.net>

--

v5: split out per Christophe Leroy
---
 lib/test_kasan.c | 26 ++++++++++++++++++++++++++
 1 file changed, 26 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 49cc4d570a40..328d33beae36 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -19,6 +19,7 @@
 #include <linux/string.h>
 #include <linux/uaccess.h>
 #include <linux/io.h>
+#include <linux/vmalloc.h>
 
 #include <asm/page.h>
 
@@ -748,6 +749,30 @@ static noinline void __init kmalloc_double_kzfree(void)
 	kzfree(ptr);
 }
 
+#ifdef CONFIG_KASAN_VMALLOC
+static noinline void __init vmalloc_oob(void)
+{
+	void *area;
+
+	pr_info("vmalloc out-of-bounds\n");
+
+	/*
+	 * We have to be careful not to hit the guard page.
+	 * The MMU will catch that and crash us.
+	 */
+	area = vmalloc(3000);
+	if (!area) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	((volatile char *)area)[3100];
+	vfree(area);
+}
+#else
+static void __init vmalloc_oob(void) {}
+#endif
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -793,6 +818,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_strings();
 	kasan_bitops();
 	kmalloc_double_kzfree();
+	vmalloc_oob();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191001065834.8880-3-dja%40axtens.net.
