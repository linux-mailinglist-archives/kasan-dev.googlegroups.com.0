Return-Path: <kasan-dev+bncBD53XBUFWQDBBCM3QTDAMGQESDAAL2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 44F42B50D52
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:32:59 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-77278d3789csf13757798b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:32:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757482378; cv=pass;
        d=google.com; s=arc-20240605;
        b=YUhuIYR7jpgUm1jZ9sUBp0GwmTFV9u5ay7DvT2gnEI8oXzc5Z2vYezteVJmUUB+eMz
         sZSjyvlfi6a9IwS8NrUhQ1Cyb2QVZCVNpFDZDYtCMuHxKDTobsVDZeRtU3br6umeKUy1
         ErxibH5+LFDmXJFLIMEssZYMU+lfrTQ7VySBizU5xkg5zugyQyLxEH8eFtnmUWhXykOs
         DK1rwyYjwvhtQen+Uzq7Tyrrz//joBoq6OBwAw6e8fXPCQftt9pYlkSgFd8htCglU1D4
         4t2kzEMdIFM0ukDDv4xGxAKPb2BXGdXXVPP7q3HDxBPlvJLHOLo3Pk+5Y9ZOVQh9afTQ
         rc1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=LShsnfJVp+mgRshUky7Owi741D54QC9ANhjssEvg1+8=;
        fh=mAvmB6Z8kj/mR9fkSmjPlOEQikQh49xUp64M92+AwbM=;
        b=S+yfxjBTlWd3uMjnpp8XcZ+7NnWeNs8/bN2wepR+ycOVqJymUSt8s3F9OGVyaTz3Md
         UsPqgAfdrbL4UL+GPtlTJbT1CFklPYz87fS2fcYhbmLwzSXVL1IaVsseEvpG4lxVJvoL
         Gylk6HxEMtU0h6Lz1lRtSu4lbt3QOfdCC5GKjSNIJodvqPddYScPdSJWcEQu4QCnPhu6
         ZMN/CXn2ssQdYtrT0XYrOMkX/p9+ld5u849DUgyuA+LACKQgCL4E8IHwPWKlv/lVoMrW
         /oBDnlqxJVSfd/C8N3XnrJ177vI5VAE0+f/Y8cHpkNxzXhJTi7tHX75T+tQAucO4Ltua
         jy4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YuU2OgMp;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757482378; x=1758087178; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LShsnfJVp+mgRshUky7Owi741D54QC9ANhjssEvg1+8=;
        b=vfAYR4451pbsVSMpQ8TRdgtzkNJp6ipWAmMC1Tww7aJy043zzaVI/opO4QQP0aPZxB
         pet04z2+1Oh6QXz3LboqmEsB/qlniQeDZ59Fsax66UjjEvV/mdSXyAYo7KQheU0VMQoR
         ziU7ltmhlNbIvisTop/XF+fGa5AgcwY1qD4V0oBS6hepSn3Ogn4RUhogEdGRWWMrt2pP
         9GJ0VDONq9wBKvxbLwkcO9Jq8Fs7dsIxdu3/Gx5tRoWMmRcAwe0k/zgeLzuk6lL47DDq
         rgm0/P13+L2Q2YbHunsvHbg6kmrlNabiNd4kyhwvlk8xmBG1swZ0OgBRekRC3riOsGis
         6ZbA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757482378; x=1758087178; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=LShsnfJVp+mgRshUky7Owi741D54QC9ANhjssEvg1+8=;
        b=QfRqwp+JA9CkeCJexHgDYMEicPaVo8GeyFkb8UB+rM32vTLa05uBfCvOoFpjvZWPRH
         aWeMNdDwtC1UCcy/zAaBXGxPVL8Tkf4Wm7McIRSvqlin/4r86mZXa4mFtmTurABSs3kn
         55nsQzlIPI447LmWsF7SxaJerilBpeuGVGlzGvSuKwkOJ+7ZWw6IRc2VNHnq28MpiOaQ
         rjoQ4HqM3y/kljIl/3NbzMBYXh2aT4yJv5N1Muz4PMHLXMEgRPrQS6nXYvYki1+F5Qm9
         Ll8+N/7jvcX/Ce6ZnVruQDNMzgfdZYVhijbDR2H5uOXYaZZWxdzT9QdTM/PZzrMAHFPv
         aTTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757482378; x=1758087178;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LShsnfJVp+mgRshUky7Owi741D54QC9ANhjssEvg1+8=;
        b=JTf4Uyqw3B3Ag+OqsiYLgjOvYhJv5xI4YWvihgYcpnnXVKfBO9ir4pcr1FT89/Ph1K
         uwjSX504IzVcSnMtop52z/FLs/ShIppoWv6SmIRJr1oNYZuwGqVFhJhrGY3kCmK8WtlD
         7igGT0wajy4l8ZwcX0jO9ICG//KnyoxW37VbSDFM585KF5kHph7CVHgBQhQHoLwIHRh5
         bpjf4SLwEFHeq9WJR0fREVyGJMYpjpA5tb8TN+swawgtZeapV+xMPSlOGBHfHfDm8TRS
         zl5vaeJrHrUFCgd1vbVFdGPLx5CD1ZOAB/WXfiJuypenRwzSELDAvbQrkkzzh7vlmDKP
         qNlQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUzEjkgxFOPQRGC+D7pDHg+r1DKvHgkBWPTXm/r893reb+xXhAEJEkRBY8YiBeRaoWx/qfA2g==@lfdr.de
X-Gm-Message-State: AOJu0Yy11Jh/CEf4ArCCT3WXHkNYo6ZMMHV2oztXwv7tD/Bw09UNaOsS
	39I3Z54hnilAkhNnBer28/aNZG5LS7er4rIf+k0KLxwOStAbVeylGOJU
X-Google-Smtp-Source: AGHT+IF7vIJQSBVF91JHY/PJnHCPa2GUejHUlES3X23yuBiqIb8sMRoJSmsGhgUanosQotb15DXiLA==
X-Received: by 2002:a05:6a00:1598:b0:774:52b9:b17e with SMTP id d2e1a72fcca58-77452b9b3d0mr9500131b3a.30.1757482377787;
        Tue, 09 Sep 2025 22:32:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfse8boHU7LjaG1to/ytNW+XqxNZ46VByzpfoP3dq4sLw==
Received: by 2002:a05:6a00:f0c:b0:772:3ae3:bbb4 with SMTP id
 d2e1a72fcca58-7741f0b65c6ls5201017b3a.2.-pod-prod-03-us; Tue, 09 Sep 2025
 22:32:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVA1iQGyf32Y75A55ml/mzI2P1IVJHyjZm0A0kjpqFqnYqqGX7tcOxWBtAWeOhSixCodJR9/ZS9M1A=@googlegroups.com
X-Received: by 2002:a05:6a00:b80c:b0:772:4589:124 with SMTP id d2e1a72fcca58-7742def4b3emr14595899b3a.20.1757482375561;
        Tue, 09 Sep 2025 22:32:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757482375; cv=none;
        d=google.com; s=arc-20240605;
        b=ZlH4NWyaFebnZY1zDyC4NJlep5Qb/8NBRfDPJ2T3qCr/gQ5kV/fLc9KzIC+ML55lFI
         LcQaGF/q/+lclKWbvSMD+3RjRoKb3chS4lP1w92EraGa+rkXxKhtoyXrIkIWWcSws/p0
         YAAIJcfnA1xX03e3Okumg9qw2Bhey9dAWpKYrFBkfdO7I+dCTf/a+tJLXaNwwn8vCRds
         3GEA32CvTl3D9yT5llKx/ey9VcnuViMfpoU0p6IJLrCHeEmcLdBnRzxCIqIQUihnEXTZ
         YfnCMAKqLjlnsTNFGpP6nrMEEzLK/wotHLyc6uSst9m6sVJ/qXaI8s0sbL/TDfPBWkPd
         tRZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qrAud60iSU3AEw7FPtcpLe0K/xeVWiZU0ZsMgXrQnOs=;
        fh=C7BHC3pO1BGeN44LktfKtIGLqoAJEoLW2rSvb1HZjQ4=;
        b=g9AKgHEXV6HRTISznfIzo0rbTegMtHrlMGfYSRZanckmdy0A764+x5wUDbI2GHgYw4
         1+siYgvtW2dvt9olZ62Sh4Hx33Q6KisqfHw833ogxGy3ZVkppDtAmSpoRmWjdyLTKwy/
         VMgTAHWwbApkcV/UeZ379uq8pGj7r8j0TiWTGWRqamfzbvQMhm4UX3tx4ko1X0wONLNr
         UxsauZu3fjrop25+7kUEJ7U0PxtCYw9J1zBT4DxsvBoIQcvUpaPtvpcFPg+zTD1pA8xn
         dkjY7g5PO4wG3InRXD4tvNU3hhoKdn8989t9NQGxSMC8i24biUdYDK9paDmrUeqp1Fj7
         F7yQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YuU2OgMp;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7722a26697dsi1313228b3a.1.2025.09.09.22.32.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:32:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-77246079bc9so7519228b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:32:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXYWvDbFJJ9waNExvqcX3GTdfCoe+aaNWyXyLGZ3FmtTZhCBmt59u8EfoTgyseqlM/FBR21cXwUI/k=@googlegroups.com
X-Gm-Gg: ASbGncu2J1gHPVmsTI1e9CI+k/lmHD7xa6F1sq00BpdRAaPO7LhleX4CpoVBm6Vkx+o
	K+EFdJodtU2jtdE89l1AZuMhoTsmJnbheZNEeIKEojWhjxKjY+vpQwuUWuRBIt6z3fCl6miu7ae
	EZZUjT6t8OqoBtOp7p/asgzvmtAyRzPLGdozVUGc1wkuVnO+58YL19Uv+FZwSL6t06AmR/Nm5HB
	t8ce7o9wgM1SI79k+Bgzy52G5Oru4B08jp0G9wkWvGUW+OFsnfk/6mdZjoJXRkadGRwQFOY/vot
	QOw9I7wZ4LL89+TQKD+gRw7N3asDx4oj9DmGXDPKbmbSltc8Zco0dIJpazqQlAnzWUrY4JaEMqp
	K5WFnJ35MRaG0KbC3QGaU5CMg0U5Tn1Lw83k3GTPvdnxhd77LGA==
X-Received: by 2002:a05:6a21:32a4:b0:252:2bfe:b668 with SMTP id adf61e73a8af0-2533e572dc2mr21000740637.4.1757482374278;
        Tue, 09 Sep 2025 22:32:54 -0700 (PDT)
Received: from localhost.localdomain ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7746628ffbesm3870342b3a.66.2025.09.09.22.32.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:32:53 -0700 (PDT)
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
Subject: [PATCH v3 13/19] mm/ksw: add self-debug helpers
Date: Wed, 10 Sep 2025 13:31:11 +0800
Message-ID: <20250910053147.1152253-5-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910053147.1152253-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <20250910053147.1152253-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YuU2OgMp;       spf=pass
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

Provide two debug helpers:

- ksw_watch_show(): print the current watch target address and length.
- ksw_watch_fire(): intentionally trigger the watchpoint immediately
  by writing to the watched address, useful for testing HWBP behavior.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |  2 ++
 mm/kstackwatch/watch.c       | 18 ++++++++++++++++++
 2 files changed, 20 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 79ca40e69268..8632b43b6a33 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -47,5 +47,7 @@ int ksw_watch_init(void);
 void ksw_watch_exit(void);
 int ksw_watch_on(u64 watch_addr, u64 watch_len);
 void ksw_watch_off(void);
+void ksw_watch_show(void);
+void ksw_watch_fire(void);
 
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index d95efefdffe9..87bbe54bb5d3 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -185,3 +185,21 @@ void ksw_watch_exit(void)
 	unregister_wide_hw_breakpoint(watch_events);
 	watch_events = NULL;
 }
+
+/* self debug function */
+void ksw_watch_show(void)
+{
+	pr_info("watch target bp_addr: 0x%llx len:%llu\n", watch_attr.bp_addr,
+		watch_attr.bp_len);
+}
+EXPORT_SYMBOL_GPL(ksw_watch_show);
+
+/* self debug function */
+void ksw_watch_fire(void)
+{
+	char *ptr = (char *)watch_attr.bp_addr;
+
+	pr_warn("watch triggered immediately\n");
+	*ptr = 0x42; // This should trigger immediately for any bp_len
+}
+EXPORT_SYMBOL_GPL(ksw_watch_fire);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910053147.1152253-5-wangjinchao600%40gmail.com.
