Return-Path: <kasan-dev+bncBD53XBUFWQDBBUUI5XDAMGQE2MH7KWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C71EBAB0E7
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:40 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-33bb2e3a481sf9744270fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200339; cv=pass;
        d=google.com; s=arc-20240605;
        b=i0SruECKNVSsTo+9OiDRm41wScj2RWk3GLeDMRIejNAFbF8xSXneyVta7TbD9MnA+P
         0ihm9/mgSacuJESu4uVu4s6uYjjf/3T4BwFiKzl+szP0SjZDeiJC5X7Mdu0440oLONIT
         ydiHIG2DO/8LrevexXoybf85PdNljBXUpoRjoMNx2oINxQM7VmCvKqlVnHMWxWCzAHNW
         k3LySS65UQ8TbQTBJRuPn97cBzjN6FSqLWj21VGRAhBSzxEFGhDNMF2k1UTjt/68XzRC
         S0JDz8WwmBIGCHOtAxY1x6KD5b7U/OsPyHjsr7gARNUuQcfUNz6uc0oQfRWwQ6vkrL6L
         LvAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=+pmR8prFOfS0Cl3e4jAmNiwSIdxWipZLoUKDz00i7ag=;
        fh=dBfkTprou9of1S9n6hnANk4TqU9BTjIycfK4RHKreHM=;
        b=YmRLZjNPHZpv/qccMaDO37pBwOj5ZL/Qel616d587Y9PM74AX7PikU85ier3P0E9e3
         g2hxenZPK6yyiZ6+opc5ITAqJuY6kRGgdlSc4LjRxZquplSNRPeJE9HWNWefJkfg/zzx
         hTAxBWcFw+gveeZtvK2Q4pVpjuyC6AoEHzrTugEy/OpqlP19cXSRZM40Mn5FKXLzVvW7
         EYHlBVdrNCscImAwUcaGwjG6CbQ1Acxq0NKih670Hc8yUL92FX2aC6zl9b4P8OWse5pz
         Hvocy7SArbpvUbkxQ3Ls2S9RhkQUkueFPx8QgGCWhGyovj46TmvKQhNdb2A4/eKqit4C
         49LQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=imFmHb4J;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200339; x=1759805139; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+pmR8prFOfS0Cl3e4jAmNiwSIdxWipZLoUKDz00i7ag=;
        b=c470ztX+eN948mRq9vMGKfb7W01QCSBUMZgIE5GwNhK43tfAHXkwh3SevjQNVYRvTP
         qBBHx6v5n5vhlCpdbsYn9ds0U0ly4/PljVc0ZklM9r5Mw04s6pMAtwOdDxxSW0lAlImp
         5BVKXmdDM/rMpdjLEwRwT9BJS1/FnJ0oYjXpR4gm8Squ5swI2BEGl3LrUVDfIZc3h9EV
         E67gm5y+Rk2G9e4MYAVKo6MMr9n1BWVKUp4a1HQGBAk1oqIv3sa6WWovlQN/XFrB6EoJ
         WRRq2lQEPYh8BS3ZJtxBzqWT9fdFpUB0b/JsKe7RGB6Q7IIxy1ojd4qZ/GI9Zl3MWCLf
         HtIA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200339; x=1759805139; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=+pmR8prFOfS0Cl3e4jAmNiwSIdxWipZLoUKDz00i7ag=;
        b=cIFPoQndJDESj/qS8r6YSPjDLb7O6t8cPgAg21Zuj5MOuypgYKRdgL9ho2aU38SPIb
         RSpUCMZphCg3FWAB3MixJE4PGIMLZF8JrUk0sOndqhPNLzzjQ5aclQ02oL7ygxfFnD+q
         0HfrucSqB/Mq/Kv/GeSjba8RVShqxSNYBzDtQ06GQ1Q8CELcKvHlQsMCR61rfzhXCzEs
         X7rG+FYbS2gx5CVN0oZNu7XVPBSKhsNt2uQgpO+DCiui68776ZNHSX2scPUgLY1Bs15L
         FnW/O/mPz0LKaABDcNMiCAyxNXCRH/DsLFtzjGPzMgyfaJLyKGnsuck781N4w7dg0ps+
         IL2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200339; x=1759805139;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+pmR8prFOfS0Cl3e4jAmNiwSIdxWipZLoUKDz00i7ag=;
        b=XIOJTN829CwmTH6QBsaWcMHqZV3k1Le2F7x8r4jUioX9U3sOYqBR+TgXZh+lYNvXYR
         HceprmYJ5in2vO8zqyWsfoBpy6poEkKqwqkxRH7RXtcNih/sFPaQ/hAWyYAp/wmdN51u
         bfAAixqBa4sWuJ4ZssBp8zvN3QlQvWL4DWvve/+M0JD3ATBrdv5jFgbe/fQegE4EWzPp
         vqPbW4WP6QPiGZqh30MlYIYLx/a8gN3CVIiQhDAA23MU0o0j07YzIg1//6s8HYbF1Pov
         T6Wy7ixTZiqTjcHNimK5ICuZY2ga6PjLXdayVkcBnSnu2aAe3bLOfu0XtROcUjC7sdvZ
         e6nA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVs322Pxge7u7hKw6lxdYaAYM3yymFaoy3Zo5/S5gbLHy2Zwt8U2y3AGzRA+CaJwvBCyudDxA==@lfdr.de
X-Gm-Message-State: AOJu0YwyU2EDhGG+cV6GVBklifZKm17dtKtZoYzc9T0HEvGqTYkjChGN
	XuF2r45NprABM+q5IKy9TOBvPpRRsuB16Rk/mZ/ZPCUj64V7P2uSuTns
X-Google-Smtp-Source: AGHT+IHG8HsT+KloSgkobsr1rM2DX6Y0hfj7Vn+LrLGdJxCmeVNHHtj74znKY4kVinMLluV0O/iLUA==
X-Received: by 2002:a05:6870:23a9:b0:395:4428:a07 with SMTP id 586e51a60fabf-39544282cc1mr88929fac.39.1759200338827;
        Mon, 29 Sep 2025 19:45:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7UOpToPr85p2Ywiuv8nyVpTA4FaI2TZlqu/1bdqle/tQ=="
Received: by 2002:a05:6870:eca8:b0:330:f9af:ee37 with SMTP id
 586e51a60fabf-36164776491ls2653280fac.1.-pod-prod-01-us; Mon, 29 Sep 2025
 19:45:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV38IsGgdxxxRz4DpZyyF+viAGDT5CaDDBTGV+k92QsG/6gPx+n8CQo8cnyDmec20QSuDuZw3RPA4k=@googlegroups.com
X-Received: by 2002:a05:6870:c6a5:b0:315:c0bc:4bb6 with SMTP id 586e51a60fabf-35ebee23f8amr9456069fac.5.1759200337883;
        Mon, 29 Sep 2025 19:45:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200337; cv=none;
        d=google.com; s=arc-20240605;
        b=dA1tACYW3Nc8L7EHLSmwaLjWTk3/HD4nyFjENCzp7WEg/CYAX9od0TzpSG0GalORdo
         knmwyzP3QBEYflgIFVF1Jc51avTP5QgJlJ6vBlbZL/CFwu+pERBq4LJb5nYHTdXHwKJj
         0SOU3jK5fG5am2GgPKhNGmUzry1XNpxtu+5e+ZFbs80NNHBhE4tWwgOhu754qlJo76q3
         G/NTmypHDfs3e7Ch0BxZh6DFjczwrygMgqgNnmuZBwM+cEpqJ/uFCel2WH4ys6ZZM9cK
         Y9/g4DRr60LkKpO04AWNWOvJfOecnfeM5oaSCcVGJqDM0dMigjmS9ak2H7qzzzKZnwjx
         lIlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kFRia/GHfKKxxNt0IUc2kN+EVm0fmr2Lz8hq8oGCXGU=;
        fh=YdtNqgpO1tLkrdaEakIUwf9xlpNI/LkugQEr2/8ZfSc=;
        b=cW+odAX7l3wI1Cs3DP9I3nPonGCow7/Ii3eT6C9wo+E/ROKGyMUYf3hufajmHWUnvy
         ZoqGaJPu9u7TdThcAx5LHImbgAlg35vN6L7TgGYgaKhRJviz6awBGbYKFPCCWn8rj/sw
         jXfWhr+Ul5A+tfPbK0/GeEYPpM3Id2pvuay4dcp2giU0s4uV+YNmVKaQHcakG7bXY3el
         vLOEBJsTRy3HvlZbaW6qZPwCrZ+eb1mrWUywG5rt2TMmxsTmezB81JvyRK7W6e0XbgwL
         pvF7tNWMDywdiDZ1E+spfyn4wJljYlh4xv/bQbUimqZmCjJFfpNsGYrSZEohkiyGC3KZ
         dvUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=imFmHb4J;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-63b1698dd73si493851eaf.0.2025.09.29.19.45.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-2897522a1dfso17720315ad.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXDvDkBs3O+xIwUSugDY8NipHIhxQ+Wts1n5SHOTm2oWyqe1kyDFHt/N1kwKflwX1POo2lVyrwpwLU=@googlegroups.com
X-Gm-Gg: ASbGnct4syWCDcRtI0nxQjf1fPNXfpw3tEc8agi5dT5CVxowjTKzxksj/K0q/nEDgK4
	KCcH3X2jGI4GPxslxt5bmPNt6hTydweAEVAmcTQFw0XB2I1uuk6ZlCGZqtu3otjbDuQm5mdiedm
	Mx0Q1OUhRnUyATI6ahpW4rejamwdztVRnJ3Q0xf4XOQ2XfIS7ltjUL69t2s9wcOmNUTsGP2Bsu7
	DftH0lX/JtugMYYbGD4JxClfXhqd4j0ECO6k9FGb77h1ktGXWGw1sqvlWybX2PMCSKJyCvhT88E
	20mEJLp+7gQ4xgFZnPa+ytMf7ZaGWQoU8oT7UGBGzcQEUt/SfVXJo+8Q8Kok55ZXZ48DC5DB2vB
	VONu3EvJGNzjQba3LSWFXFOokrTOnOoOvubJJQZTvKWjLgQsdqQvGNqjJTj5+p7jb5Q1QuVHphJ
	pd
X-Received: by 2002:a17:903:2442:b0:250:999f:31c6 with SMTP id d9443c01a7336-27ed4a3165amr204393375ad.32.1759200336891;
        Mon, 29 Sep 2025 19:45:36 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b57c55bf378sm12519152a12.50.2025.09.29.19.45.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:36 -0700 (PDT)
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
Subject: [PATCH v6 15/23] mm/ksw: manage probe and HWBP lifecycle via procfs
Date: Tue, 30 Sep 2025 10:43:36 +0800
Message-ID: <20250930024402.1043776-16-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=imFmHb4J;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Allow dynamic enabling/disabling of KStackWatch through user input of proc.
With this patch, the entire system becomes functional.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kernel.c | 60 +++++++++++++++++++++++++++++++++++++++--
 1 file changed, 58 insertions(+), 2 deletions(-)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 898ebb2966fe..57628bace365 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -14,6 +14,43 @@ static struct ksw_config *ksw_config;
 static struct dentry *dbgfs_config;
 static struct dentry *dbgfs_dir;
 
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
+	pr_info("start watching: %s\n", ksw_config->user_input);
+	return 0;
+}
+
+static void ksw_stop_watching(void)
+{
+	ksw_stack_exit();
+	ksw_watch_exit();
+	watching_active = false;
+
+	pr_info("stop watching: %s\n", ksw_config->user_input);
+}
+
 struct param_map {
 	const char *name;       /* long name */
 	const char *short_name; /* short name (2 letters) */
@@ -117,8 +154,18 @@ static int ksw_parse_config(char *buf, struct ksw_config *config)
 static ssize_t ksw_dbgfs_read(struct file *file, char __user *buf, size_t count,
 			      loff_t *ppos)
 {
-	return simple_read_from_buffer(buf, count, ppos, ksw_config->user_input,
-		ksw_config->user_input ? strlen(ksw_config->user_input) : 0);
+	const char *out;
+	size_t len;
+
+	if (watching_active && ksw_config->user_input) {
+		out = ksw_config->user_input;
+		len = strlen(out);
+	} else {
+		out = "not watching\n";
+		len = strlen(out);
+	}
+
+	return simple_read_from_buffer(buf, count, ppos, out, len);
 }
 
 static ssize_t ksw_dbgfs_write(struct file *file, const char __user *buffer,
@@ -133,6 +180,9 @@ static ssize_t ksw_dbgfs_write(struct file *file, const char __user *buffer,
 	if (copy_from_user(input, buffer, count))
 		return -EFAULT;
 
+	if (watching_active)
+		ksw_stop_watching();
+
 	input[count] = '\0';
 	strim(input);
 
@@ -147,6 +197,12 @@ static ssize_t ksw_dbgfs_write(struct file *file, const char __user *buffer,
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
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-16-wangjinchao600%40gmail.com.
