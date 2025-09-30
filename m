Return-Path: <kasan-dev+bncBD53XBUFWQDBBVUI5XDAMGQE6IWMB5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9441EBAB0EA
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:44 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-336b9f3b5b0sf2908014a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200343; cv=pass;
        d=google.com; s=arc-20240605;
        b=KSpWo6D0RrkN39vPpgYZDUpdFfV/aZFSN9bYuJzzSiYmTJ8AeJXGTtcktoljPXAoV2
         EsMS+ABS8N01WXE7mz8PdOAgkxzqkcaYNXIn8fXKYdRfr8ZZ74mBWEe7j3rvo3kR44hH
         qm1xn0insGyDcFpQBPJBcecxgbQZoQSHd+VzE9emu5monV6pzK1JTeMw4TEI4nujub2g
         RXcMMKxAecDMiGUuZIru1dtgfHIqvJwRuzR60LaTv7bKRDCo3kDHHUlzq4qQbKyeuyKK
         lWevC8GrKcCNvnoJsj/fa/EeKwy5tvwhssaQJv5+zxqGJnDv4tRPv9AjoXygO3BfWp6z
         XUMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=CidWvHni8LvCi9XlIOoMHlMCLNamaGtuDgEkSfwzkZA=;
        fh=JHYeYMc30fY6C0r98dCsteeyZLHoQ0OAStN4/LCIbHM=;
        b=KM0BsVPtLbH/pT4ewkYtBrJJyrVGloKzyPDK4r3fmGDbEVXoIW1r+8jUjBKeAM+vqz
         /7/ZAi/Fu7c2YL2z7iQwE7Oi1s0dIVr710xINGF+MqDmjHOOw1JItbKkBTnnoIeZNeCl
         Q1IZISNOcoCQ+u8o1NJdBJo/Ku5eF5wd5vcu/u6WYGvyyIpDeOBvN51BvUNMnyI8p4NU
         eyW+cfQdRMHtOEY12zF6isDxs4GtSbLqQVp4I3aH4ldb+/EXo9HPMAbdBsBs6hppwCYl
         erw419Agy588p/jEVBh6YrS97ISBfFq8A1hR7iOifP7H0HJo/xhG0EfRbu8Dhxo2qBuF
         YQAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mtlx1amR;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200343; x=1759805143; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CidWvHni8LvCi9XlIOoMHlMCLNamaGtuDgEkSfwzkZA=;
        b=KYHCirjncJOc0zNLO1ArjzkVGxOmCebod7HFlzkSOgWMyHfzZwed+1Rj74Pv/vfqFk
         3WHx7Hrbl9rMLJf0qo9mR78U9XL38/6N1ULD5nmGfrVVdSUxiUZ067GdVZ+fkjGmRtI9
         5ZyNtau0hOhQ64T1CsaTGsSeURvMhILCcX4m3ukUVAqKkwdfH2BUl1u3UIaqQEPfIVQW
         BT0fw48Efutd2P6czm/i2HzIUUahHuiqzJw1t+L7OK9mD46bP/sgQwSI/nXxDl5359fL
         scmY0/Pv8rMyK6hP5wwW/wXTOLtnQA6nDK00hZfIMgMfrRYxmj2pwkh7luEj8ce2bkNq
         NCQg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200343; x=1759805143; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=CidWvHni8LvCi9XlIOoMHlMCLNamaGtuDgEkSfwzkZA=;
        b=XZuUNFsYF0wUbhX7l6pF04EEOubidz28ndSchiOTQb0V8/rdFVhqmTtQITMebN72mF
         wkM/mM6ov0BRIkWgZq+/P2PGB6RW4HQwOz2JxjTTc5mjANhv96E5AyBvHKy6GBiaNJO+
         xUpwn7rbM1RB5ypRSThR7wEPztBIOr3SiJv5rDmRVbxdT94U+LeUe/+R6LvrLuetmEQY
         3nCrpuN5w60bhrAxKp+HJGMzF6i5wmGPfnnpkXE9f4zPQTsk20+CduWlU1N0wQ6gigDU
         nCj589QQf+j+RkZ/ZZacaOxqrfPqbtDhaEKrjyI81aNEoLvFcOY8vGtZg9oOK+3Y86qW
         v5UA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200343; x=1759805143;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CidWvHni8LvCi9XlIOoMHlMCLNamaGtuDgEkSfwzkZA=;
        b=pfYjL64vyc0lxJcXolhIBKOCKB1IZl4bBcXzqG6HXGej6dZtKnE3DkyUjmgEEcPD2k
         nxmpCK5idO2PrVDsW/59STh1glA1A24r195fZv7ilH4l34JzTAYVSg/sir18nfQwFOnG
         l1hqQSmgFFt8XG5avN7nLR2qx35yKn3JlJxPfTED/xT9POG9PLvqnKEE4nzdEp57TifV
         EmKSMnMYbHEs6O0rX7HotG/10116eD3jfnlO/n9ObeVwiwGUxNtRhy9JtsV89wsi+gWt
         /vaaiq2mb51Y7nfUnwF+F3vaM5ilQnHx8RPzQz5j5vwg+wDYb4oYOp6z/66rQt80hsFY
         7vVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVAcwLGOgFx3Im+LxsbLkDbApRlUIsqjZ9N3bvxUirFXkh0+hkHEiD/xxRjCBKJ+V1XfqLRMA==@lfdr.de
X-Gm-Message-State: AOJu0Yw8VHs+JGFVkiEu9Ca6X1sLlyac6YaRjnwQVutxjpQuoN0u/mtA
	y4wmIzsEpnMDhaWCG8MFIcU05n6Cj7ew31A0iCrpTjEmjjrWNRgQ/eiZ
X-Google-Smtp-Source: AGHT+IGTfC5y88s+hARXL5A2XkuGvRXpfv5ZV34NYjhpDxEYmScq3dzwsoL+7/wCjFWbf6SvQFKBdw==
X-Received: by 2002:a17:90b:4f4b:b0:32e:859:c79 with SMTP id 98e67ed59e1d1-3342a15e6b6mr22486977a91.0.1759200342984;
        Mon, 29 Sep 2025 19:45:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7MlpbFM/urA3EXMiowI60pxihM3mDhLvKiZZ/LBwG2UQ=="
Received: by 2002:a17:90b:520d:b0:32e:43aa:41e2 with SMTP id
 98e67ed59e1d1-3342a496f3els5013971a91.0.-pod-prod-02-us; Mon, 29 Sep 2025
 19:45:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbQXo0cC/3fPPhbIwDNq4AUcY+y23lGWHt+Pk8p3+Xpb/ImNZPOpETLF+PQBB0RsoV0fUKz/VkX50=@googlegroups.com
X-Received: by 2002:a17:90a:bf0f:b0:32e:3830:65d5 with SMTP id 98e67ed59e1d1-3342a3013e9mr12884324a91.36.1759200341710;
        Mon, 29 Sep 2025 19:45:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200341; cv=none;
        d=google.com; s=arc-20240605;
        b=bd7R2WpqjsHZdhREMuK5vTM9Sd2ZqgTpNGTw3M6Ekd2HPw8JVnuPNUOohDvsjIXJyT
         bZt8j/lQlIJ4sMWYC5KdbR3QHsaxHyt1oZcEYqpB8fwhtyB5kOWDcqF2pnT8pqZzs2al
         zL9OAopgQWxk6Q5hEIUS6lTiPMqInLjN86ax4DCAgOqK1K2GJ+5DSnftPvulHaqTl5R7
         xWtDlzVHVfAs2G+PwLGMHQFXAYl94O2/P7++x5QtBud3U1SSflr+4MzcuVLF+91ux9aA
         IvLyxm3T6Lyvb+DwjWLHW4g4w9Y/jVXdjGyinAymW9OjP7IabXfgb4UB3Xv7TtDsVn8a
         gRHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UmaGbmiuxIsK0xKTEWJ/f7gfwC2bw8p0SOLh4b9Z4FY=;
        fh=FClhk6pzD8DlxySlTCmL3BHYZEzSeOAKLHTzWNueA6Q=;
        b=CfdiDUMV+QvkjcSPiy3+6HFY56h3KFRB8mOK9dHNsnuvDS/9/kiHg7njfRwFYR+duL
         XKd7sIOE0pi2MB/B4j5eQ++vpE2fnSKmYIOVJ8QGwb09M2J/IMr3pKayFN1D4UXQyBGm
         S78u7zQO16xLaN9QvpPnwmfSmOG1uzoOS63IBMraFs4pUgTYkIluSnVJzp/CzwtIZtVH
         CZk/BEMRF3OlBofGGaRML0K3ogR6vN8BstpYA6jVt3/TI2CHBj10fuqtLgep6BvQwH89
         cdkKRKpEJjUYRiuX/JV9rt8KR88KpbXLsI7SD4DIXCzFCz7by3KHfufXV/EDQMudww5H
         paug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mtlx1amR;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3399cc87741si18907a91.1.2025.09.29.19.45.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-78100be28easo3958903b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUnt8cXN6p8KeGMbnAPF153sZmxytRXgM93gsuy0FeC7RJmsQdj/ss8gScNGnzI7sye7nWWRBlxeHQ=@googlegroups.com
X-Gm-Gg: ASbGncv99ldSrc3HVCKliB66UFl/y9IKTep4BNMXIgR7vmm5YiTKv6BxUdbQ/tc4m0R
	k8asKbE76dNbJlb1s1CtFCBt74mI0ZFAqzmsPSoPfrRccCjzOUxxUbBqh5oRRLp76uMQZXTZVEP
	PA+ZnWDY9ABrfVMHi/Ev2rrvQMPuLii7+JBfcLpylGdQ6h7GX+uF32i7c9tv1BUHFBz0m8fzw+e
	228+dY3s47jXlQMkMyPs5v/xI+Xhzv3f+LFLxxEmxA63unkaituPkvis4Q3Ov0waDD0jzl1AVnb
	GsFn1Apnd3jCBfdP5PlZkY4c1u9FMcEF3wu7rjtd4U+20AaDfgwOAC2gtDhRvorTuOUGntdxc5x
	jYgb/LpjBe+HaPb108JejyyWI6rWVrlgYS4NebEM9C/sjWNQ03mYOJn0oBmwJJKbLAIykm+3DtI
	57
X-Received: by 2002:a05:6a00:26ed:b0:781:2ba:ef14 with SMTP id d2e1a72fcca58-78102baf1e4mr14490364b3a.25.1759200341230;
        Mon, 29 Sep 2025 19:45:41 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-78102b64cc6sm12378142b3a.71.2025.09.29.19.45.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:40 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Cc: Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v6 16/23] mm/ksw: add self-debug helpers
Date: Tue, 30 Sep 2025 10:43:37 +0800
Message-ID: <20250930024402.1043776-17-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mtlx1amR;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
 mm/kstackwatch/watch.c       | 34 ++++++++++++++++++++++++++++++++++
 2 files changed, 36 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 4045890e5652..528001534047 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -52,5 +52,7 @@ void ksw_watch_exit(void);
 int ksw_watch_get(struct ksw_watchpoint **out_wp);
 int ksw_watch_on(struct ksw_watchpoint *wp, ulong watch_addr, u16 watch_len);
 int ksw_watch_off(struct ksw_watchpoint *wp);
+void ksw_watch_show(void);
+void ksw_watch_fire(void);
 
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index f32b1e46168c..9837d6873d92 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -269,3 +269,37 @@ void ksw_watch_exit(void)
 {
 	ksw_watch_free();
 }
+
+/* self debug function */
+void ksw_watch_show(void)
+{
+	struct ksw_watchpoint *wp = current->ksw_ctx.wp;
+
+	if (!wp) {
+		pr_info("nothing to show\n");
+		return;
+	}
+
+	pr_info("watch target bp_addr: 0x%llx len:%llu\n", wp->attr.bp_addr,
+		wp->attr.bp_len);
+}
+EXPORT_SYMBOL_GPL(ksw_watch_show);
+
+/* self debug function */
+void ksw_watch_fire(void)
+{
+	struct ksw_watchpoint *wp;
+	char *ptr;
+
+	wp = current->ksw_ctx.wp;
+
+	if (!wp) {
+		pr_info("nothing to fire\n");
+		return;
+	}
+
+	ptr = (char *)wp->attr.bp_addr;
+	pr_warn("watch triggered immediately\n");
+	*ptr = 0x42; // This should trigger immediately for any bp_len
+}
+EXPORT_SYMBOL_GPL(ksw_watch_fire);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-17-wangjinchao600%40gmail.com.
