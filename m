Return-Path: <kasan-dev+bncBD53XBUFWQDBB7E2QTDAMGQETXH74XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id C9DFFB50D4F
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:32:46 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-32d4e8fe166sf6563607a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:32:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757482365; cv=pass;
        d=google.com; s=arc-20240605;
        b=KdyqnuBjQpow+0XM0lpAkelya/BKaYJCZ41ftdj0YrYYTE21FBDR8qqksMaxvIkDwn
         xkAhorkwyGaYN2TtD8ng2gD7i0s14WpgieRlwM7k4kajFF6vM4hK0mvewiBMwiioB4Ro
         WiN+oOBHXGf9AiQo7fgfhoVEbTseYV0AcRL+1a7XqEX+nd9ph9gBNcFNNvrAQPIiS9a7
         1qPm58MM5/hNpqVTlJ+ZZRjTV6s7a9kWlP73Jka9K9wF/jlEqdDftZberaZpwJFyo1gy
         zswFn55oghMnyst5w3APkEEG+GEOXGKrE2mojm9RojIU9aLl8cR1KyDZbDX4IvNFwFh4
         eO0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=sQmOL6u2OfqwOg1+Yh/cIgwtm62/wohrAZu40FTRNZw=;
        fh=x8PAC0uxwjNHP04nvTXuvRqoQWYGCaNRIBRu/ogzlsg=;
        b=AlEnHYRmI6RTgDorr6KtQeVuDxdDafKmm8UgpnnXXeHQi7CFEJYfA77jbXRbAZMsfc
         yCniX9RLD3S7EEGQryjTia0gsKgnW7ykKYVk3rsmrF+6UOmg4yuXvj25t6+7h3dISrtt
         LhmFstdAsOGTOpHueqSM6nptgdgATlGe5JxwQtrZOxo7VmMQffDEdtyM3Quzr3FXxelk
         QDB5xKQkCjLmx1UagX9MeaMZorpyh2Cgt72EFc/gVvvqABo7nLgwjcKcXKzLVSRqk1yn
         dX/rGEtShr5YKqnfH5ZPKm1YAtsvtq1Bkfl3SAE1998CWMAQD/9bhvICtp4wPO9lLQzV
         BT8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HCBA2RFA;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757482365; x=1758087165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sQmOL6u2OfqwOg1+Yh/cIgwtm62/wohrAZu40FTRNZw=;
        b=Y9TA7YuTgAp8f1z2OfvvcTMSBaB0dPUezA8uGfpHG+NMC/aXZerv2CsqGs7qPCmB2R
         gW8Ac7+/6fKblpHCUT7ytVOeT4BWmnTlSTMddAn+l9XpvtV/vMXHNdM/jtq1MMImM0EC
         j6NLwsHu5YndVs+AOMAyf5JZjoVqK1U1HlJIPY4jUhplS2nucRrphS5sQuzhwoPigJfY
         qcJp88J1xINptFEIuAz/swGEuAzW8UeFM4xNkjELiuveBCfKV9YzVbxGzGjOsR11qUFB
         SkXyFVNPY7ppWW/g50hLc+PLI4tw6AJkpwCfpJpvUbz/927VOhWfDj7i3CiuMwKt1EQ0
         aR6g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757482365; x=1758087165; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=sQmOL6u2OfqwOg1+Yh/cIgwtm62/wohrAZu40FTRNZw=;
        b=Mt6n/6Zt1tquwAwApg+ip9Pa8+Jkth6QncOfSlmiaGVWPbTdhMaBA/dNjYh2M9Tv9R
         YNr4BUJYqvpajWwXwQltajUQeEQJY1Q3Xmj6npduIS9got6rDV4hg+pXDuUiBLfMdlP4
         ZazdPFtuZunuhyfkMM72dZZl7OZSp4vCdpSvcXXzeXzoXG1cxrJExm9GgiGwQglF+4N3
         Dm/OxSIrIwKmHHwRUsv6e3HoEax4mIGabXqcDq/X2hsbJbkXIhMnzoFcyuJeDB0BHFrl
         s9VWGMT3+zU7ZmNYIXVwRGUJr1b/ModENvLNMaU39DpVGmJlHYZH92BExN0C0GSRAAoi
         oJQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757482365; x=1758087165;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sQmOL6u2OfqwOg1+Yh/cIgwtm62/wohrAZu40FTRNZw=;
        b=PbLSP5+QKOUBRFeEVbVwq9wKvys6VWI7s/uabIuEmUr2mUa88PdAuav1Ls9bFqwCAF
         RlDgpGNr4TOK3yrKoEZpIktpcUpBCeEmChLOCbADraClIfCNe2t21dsxD9VZKRl/AAVs
         lFQ1Rbdj43G6sGMoyp0UotNUQ6sVDyHNfZemo8M0nLIwjXlYWKbMcUVCMJdWMfy69n0C
         azXfb9GZFT9U45sCBS0ub2MBvBR4xV21b3JZn7B3AHGwkmHkDVWrcXt3MXcSZW9xnBIT
         hExJ/O5aUzZd2//Lpyl/RSxGlnHdHYGk7EczdbKj5jrW0g7aDJqZGNJc2HTzu55LE6Tr
         GLdQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUhAlVpbCWFi551HRG2UuObZVfkiSc5FcQGuS+oRjEPVFu+XCREFCscHkQsfxx60YnPgd/68g==@lfdr.de
X-Gm-Message-State: AOJu0YzN4dVSSRjHAGRjb42vfDPRoozdKNP03ulvNjLRsK8zESpLa6fL
	nEf9s7HfUE8hRlRsziJ+/K08aOXag985fwgesUXL/7Tv6Apu98nsqVLf
X-Google-Smtp-Source: AGHT+IFUDMzT+SWvvEzUye6rr5OriJmKWgWZrj1Xi+KFgHvoy2DRj+00dMEDdHb7fbgB6iLed9hTlA==
X-Received: by 2002:a17:90b:1ccc:b0:32d:90c7:c63b with SMTP id 98e67ed59e1d1-32d90c7c6e3mr11887524a91.30.1757482365101;
        Tue, 09 Sep 2025 22:32:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7dfshSzna66PglVbdDEhP8D/rEcEKqf2XoTum94EwBuw==
Received: by 2002:a17:90b:188a:b0:32b:d501:1efb with SMTP id
 98e67ed59e1d1-32bd50130dfls3864607a91.2.-pod-prod-06-us; Tue, 09 Sep 2025
 22:32:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXhWsWEIWTHTRNUHQPIRuwu7Arn4scO7MdAXCu/ISw4pRd4/zq6JVzuzg9x4+sm/INrzzQHIpirMiQ=@googlegroups.com
X-Received: by 2002:a17:90b:1ccc:b0:32d:90c7:c63b with SMTP id 98e67ed59e1d1-32d90c7c6e3mr11887409a91.30.1757482363206;
        Tue, 09 Sep 2025 22:32:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757482363; cv=none;
        d=google.com; s=arc-20240605;
        b=ZxPb+4q/p7uAgkx6mGMeAW3KBkviyNL0NnuTjHdKyy46b+23knVnCmcpe4g9mv427f
         lv/yu/ipWCfOKr4lAiKuRUhBtTXThAljY9VO3gEFo1BWRgnNp/F8gFEjMDORHgQpjHhN
         f9yVJSDb3+F8sNpzMDTZQCahK4haCzO5t/4zw0EaogRkKqtSP/9itvfLsYsYXrXXfOWp
         LXSdSmXTy+GEs5EOXnM0g6XG33H3fSKY5INfa2UZltsPLElNFc+beFEyEv4DHZlvKfZz
         j+adZjNVQ4uNgSMTAiAh67JmletnOicI1+CU64PivMoq+HeVJH9Txg0IyKKUw3+uUuMB
         zznw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6XwqTGxkvpDU8btF6MhrnM15w2tp20A0ZzctuT/hXIw=;
        fh=9FSOoJsW9TIPsMVYlbgBd7iEoB3+hKgEeFdr8kPWVy0=;
        b=MnomVlRx47xaSWFT3KIisx5bJ2vFK2czCccWjxm4ugyM6roAOyqEJYFk40W8TXiE/N
         o3+NwjNZ1k0rIloZ+4y9PjsiH7vhgIn+utdRqj/BGET59H/ys/UwJ9Kg6BcOcwsNb1mu
         DixRGYmOS3GRbflete1JVxbNOIkvz65ajJLtfvxRU/O+HP6b8pS0GPYGLRIF3ZeTNnko
         mHcF2iROpKZGquT+4XdA16lnoVCpS9aVtFhXl42s+Trj/CSut1GyZLHhj17JQ0YTXzS/
         uCv5//VEE910HDDvXyamZ66xTK9NObOZ2R8mDx8owYEdDbGGU8TtkSyr9ZwSDatKPzqb
         mVWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HCBA2RFA;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32daac103a9si158709a91.1.2025.09.09.22.32.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:32:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-7722f2f2aa4so8235326b3a.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:32:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVHf+RTsDnHVL49gTup1QBxCZJ/ttDL0BzuCyxYJFCWKfJLUf67IkJ0ozZEnm0MY0z3YEi+e/7fPjk=@googlegroups.com
X-Gm-Gg: ASbGncsVJswT+GXj7oT+6uCF15aks34EL7JpfFtpGcFBZ/s+g4/TQleHALEp6bBu7mr
	XRW05sgMsGUiz7rnXCbP+cOXpgUECDkg2Y021lTni+7hSGOVvD2dipR4B6H6UtP4fOMNi0qPeKV
	tkf4LZBZGLxdsba68UZCs8d5SQ15OHk5FoIbLcIXOFPjuytEnV9vY+Mtgv8FPNwh3TpR/jcJPf8
	nA15aGaJ1wee3ikclravk7yVAsNVrB0eIYnx2ym5XSrSW5QVRhfKfyHY7lhhAp0iFxCbP4YndHw
	uRHOnTRb5Y+a885PbpFufD+Tb1kcjjGEIscs7CVvpEOA1eyBBHFMvMFFGymWvzIWT0JvTVGVB6F
	2RhGtMYHPAe8jMn7ciAdvmh2AhVSEbl586nqUcCZ/rnug/aVYIIjfQdfZz4IF
X-Received: by 2002:a05:6a20:3d83:b0:250:429b:9e56 with SMTP id adf61e73a8af0-2533e9476eamr22673752637.8.1757482362704;
        Tue, 09 Sep 2025 22:32:42 -0700 (PDT)
Received: from localhost.localdomain ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7746628ffbesm3870342b3a.66.2025.09.09.22.32.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:32:42 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	"Naveen N . Rao" <naveen@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v3 12/19] mm/ksw: manage start/stop of stack watching
Date: Wed, 10 Sep 2025 13:31:10 +0800
Message-ID: <20250910053147.1152253-4-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910053147.1152253-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <20250910053147.1152253-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HCBA2RFA;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Introduce helper functions to start and stop watching the configured
function. These handle initialization/cleanup of both stack and watch
components, and maintain a `watching_active` flag to track current state.

Ensure procfs write triggers proper stop/start sequence, and show handler
indicates watching status.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kernel.c | 55 ++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 54 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 8e1dca45003e..9ef969f28e29 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -17,6 +17,43 @@ MODULE_LICENSE("GPL");
 static struct ksw_config *ksw_config;
 static atomic_t config_file_busy = ATOMIC_INIT(0);
 
+static bool watching_active;
+
+static int ksw_start_watching(void)
+{
+	int ret;
+
+	/*
+	 * Watch init will preallocate the HWBP,
+	 * so it must happen before stack init
+	 */
+	ret = ksw_watch_init();
+	if (ret) {
+		pr_err("ksw_watch_init ret: %d\n", ret);
+		return ret;
+	}
+
+	ret = ksw_stack_init();
+	if (ret) {
+		pr_err("ksw_stack_init ret: %d\n", ret);
+		ksw_watch_exit();
+		return ret;
+	}
+	watching_active = true;
+
+	pr_info("start watching: %s\n", ksw_config->config_str);
+	return 0;
+}
+
+static void ksw_stop_watching(void)
+{
+	ksw_stack_exit();
+	ksw_watch_exit();
+	watching_active = false;
+
+	pr_info("stop watching: %s\n", ksw_config->config_str);
+}
+
 /*
  * Format of the configuration string:
  *    function+ip_offset[+depth] [local_var_offset:local_var_len]
@@ -109,6 +146,9 @@ static ssize_t kstackwatch_proc_write(struct file *file,
 	if (copy_from_user(input, buffer, count))
 		return -EFAULT;
 
+	if (watching_active)
+		ksw_stop_watching();
+
 	input[count] = '\0';
 	strim(input);
 
@@ -123,12 +163,22 @@ static ssize_t kstackwatch_proc_write(struct file *file,
 		return ret;
 	}
 
+	ret = ksw_start_watching();
+	if (ret) {
+		pr_err("Failed to start watching with %d\n", ret);
+		return ret;
+	}
+
 	return count;
 }
 
 static int kstackwatch_proc_show(struct seq_file *m, void *v)
 {
-	seq_printf(m, "%s\n", ksw_config->config_str);
+	if (watching_active)
+		seq_printf(m, "%s\n", ksw_config->config_str);
+	else
+		seq_puts(m, "not watching\n");
+
 	return 0;
 }
 
@@ -176,6 +226,9 @@ static int __init kstackwatch_init(void)
 
 static void __exit kstackwatch_exit(void)
 {
+	if (watching_active)
+		ksw_stop_watching();
+
 	remove_proc_entry("kstackwatch", NULL);
 	kfree(ksw_config);
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910053147.1152253-4-wangjinchao600%40gmail.com.
