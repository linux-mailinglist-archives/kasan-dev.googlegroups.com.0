Return-Path: <kasan-dev+bncBD53XBUFWQDBBWVWZ7DAMGQEWXQOCRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4737CB99A8B
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:51:56 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-4248b59ea91sf118538385ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:51:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714715; cv=pass;
        d=google.com; s=arc-20240605;
        b=AA3ATaSWpxK4cTiFfELcXtsdE/h4UnNdRMh52DoJlTsD04bx/BB1kEqWcN72KrjiKI
         RbmCKWlJBIGXKnsoMqkJQfcFRdogYbK7wzzEjODvKj+W+riZv5qEdjHJNeJu353l2pH7
         BA/8rO8fL0cvdFnz1S6dX4i9aQx4PJx3cxL3obQ9IwFMRnvt/sE+DvjhPEfTmU7tpWKy
         09kuf4/zhXVhzAuCiUYTgsXUBVCvzDxQqGk5Zz+qbzU80+piBTiEz5bPBAtHOLqsyY3n
         crrKguyGAKbKz9OolIOx8u0ZYUgOELSTmwLjqPAVusKn3HS/hD3/0WZBh/k94gfSvHmd
         ZyHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=RiKL/kTvFcskmbV6Cz+XaVlrOiJF2bYk/f+0DWY7l8k=;
        fh=QUc+4bBwzvnghHK2otf8YhNATVX6sICPPShFuwGl23Y=;
        b=Yvht9MdY8yy01DEVzYfTLUgQemEIH6ETEw4ZKQFS+fv38REuadU9M2wtHIKXb8+Spu
         8UYqfkL56OrrSd52NFJ64+wvFMnpbjzf1AMkJtUln7CkmbrEJ2uBm3Jgffv78EYrkrL5
         /FBJRLIzvIXQjPso9bsLSnytuKyGdZhZwy8cwTDLbsjX3YK3RDfcVc+3kt6ZNuUOynlr
         lxTwYugeJc2Ui0s9ZQv+Gz0C4/8hRX5Sce7giUisPjS1fGREYof9QcsbCbXAW39wNdsm
         E5GrYnYUE2Su6nIIF0/CBkjj7QRMpUhQcRLDLAu+hS0Vu9YJaERDHlPeUbOsp+/QivQ3
         UIzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AtU+E1OV;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714715; x=1759319515; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RiKL/kTvFcskmbV6Cz+XaVlrOiJF2bYk/f+0DWY7l8k=;
        b=g8wzZCTnTbZRS1yaU01JY5MwGhiyODVZC6OgWDXpCHAmmJLoELRyvbYzcITAJndqO0
         IMeF8IoN10Pe9YHY9ZT3AYjamXZg5tApYTkmrQ8s0CHvCV0jLE4pnygUyvVvWDjkeW1a
         PmjTkrzDC4/ztUtX7iZG2o16uIK+Ug76GKUs2Yw3aejTtWvvHa42miIS2Z8sV+dnBbkV
         aXBPkkC5XUYwZLxRHRGxmiCY2mfEwkN9WzjHi5ix7vruzZOOel5UgLyNYQ6TfrTCcPCs
         jojb/bvG8EY1+f9UVnWbDeuiuZkiEfVpE7uiE6KT9pnLN+1qgBIPqswTje3nkKRKyJtP
         V+8A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714715; x=1759319515; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=RiKL/kTvFcskmbV6Cz+XaVlrOiJF2bYk/f+0DWY7l8k=;
        b=ZySzD9b3G1ndUn9Hfx9jcAJb5jDVomSpabxvpEeUJqnwdZTUAjhEFeudrkJW4FK9uQ
         599WeWJNa/GaCndHBAxFiiaQODTvz6L68/Dx3G/ZldrzVJAxDrNR976tJLRFsdxTLg/Y
         imiTlwJYjQGbParQBeS6YOzELUnjk1W1vUo2yHZi7f3p91jqLVztClvRIMhqGYjwn/WR
         WG6LsXQ0YItuRVOh1sgcsL/LiXPJZgt/V4r6zC1Xe2pgv3bioFi5yuN+qFpbkRHI0D3x
         Yk7BIfEh9SlY7Nb+EVdLhR3rF5ylkqLwheLTOhvv+pmIc4h/69ioiqzw0llVFmi223+V
         XfnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714715; x=1759319515;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RiKL/kTvFcskmbV6Cz+XaVlrOiJF2bYk/f+0DWY7l8k=;
        b=V1U7LM3MXeXyRKpnVrxIfexKzIgGzn/7Kij8lhYMZ7Swv0zQVxPa2bsXNNM0RzQppr
         exgmnSHisLabAyW2IHyzmCSysZhUmfBCPIIGmWTCrDWZLnFr7NdlF+8yfEvElHiN1XZf
         dvRUO6rlxsND4gqIXMLdHAHez2EsIuSTZMPrJL/4vb8QsYT/zL7RKekRigSq1GbZpHm1
         f8qeKWkZsa6dgzrcix4xCUfYXDeyW/Y0Dru4m3IYQrgt5O2iLQwwTUCzbeOkKQ4BoZ1a
         8RKq233EWhuJ9KjYCVpQZ8AEdeOsb1rMWMgXPrjT0aS1uOtGN6Jiq/RL+rEhtSTmRwDW
         cVkQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXyX86OIi2TMH2vlfsmK9z3hzabrc/I43Ed9L5ikY+iZPG1XKYCMoxWZfXECnkOxUlFHKgLIg==@lfdr.de
X-Gm-Message-State: AOJu0Yx8Y7PAtU0oOJ8sTGv9UHVoSIU+eKNw1j5/q0RN4/UWEEF7lIvw
	KBE2CoTorvfE+63V+zGLpYELUpyzIKLBRV2ebqMk5jq2T/HRTIfD8F73
X-Google-Smtp-Source: AGHT+IGlMPslDixoA1Zfmj728pvQG7+gPwQtRdpHw90GMKPwlEZStFijRuzEd0SX4tNIYqmZyhT/jQ==
X-Received: by 2002:a05:6e02:1fce:b0:424:689a:c69 with SMTP id e9e14a558f8ab-42581e2e28bmr97760275ab.10.1758714714709;
        Wed, 24 Sep 2025 04:51:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4sDYhJMFwQf+yDDTTN9LWFGOj+sho/OXIY6FXXytXeZQ==
Received: by 2002:a05:6e02:4401:10b0:425:8b08:8d7a with SMTP id
 e9e14a558f8ab-4258b08904dls10390295ab.0.-pod-prod-05-us; Wed, 24 Sep 2025
 04:51:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzv+/Fb2ISRorFJ6x3ZNlUy9v/FYi0U8y5Om+nR1JeVcfagGI8r+eOnMIEqtGuo5cdp/84taajIKw=@googlegroups.com
X-Received: by 2002:a05:6e02:1b05:b0:423:fb83:6958 with SMTP id e9e14a558f8ab-42581e17171mr90147315ab.2.1758714713583;
        Wed, 24 Sep 2025 04:51:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714713; cv=none;
        d=google.com; s=arc-20240605;
        b=jf2/Aogqiy4DxKEjDfw5DwEhbZu1myXerckWYnIwjaBuhUEix3RzUQNKNC4T6ovRRS
         x0t9rsPjYgzthgmyIYcdYwnc+bdo3MjWsdB5otUMl0nPYAtDiVIcVPu87c5PuAuihUL2
         hvdIFSFd7QG62U8BGZucxa+OLU+boYp/ttFpamkQ9XSNF4WJwKTiilh9CAjGk5JOzuwA
         /lGAoFtvjQXDectg+L0PurCUak81TvRfuWFD992J4dsdt/OrNfvE3xxZUKAmNGazOmXI
         t/8/1KB7rfLOeR1BR9NjwMpkI6dFZ6I5Il6bQ4Yc3AtIz1g/gs3Ftnir7nA4l8NCmyx3
         GbwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eGY4NXn9SYrwp2MIROIAsCXd8mHWC2w3iRZMJXUxzyw=;
        fh=getbh31Sl6EnJpY4yY1poTdjMhUcqaXBfHMtRMQ+k70=;
        b=UcyRoi00MDwSUqkainqMiPlbyawTxTbbGy5Id8aUx1/ViTnOtnLeQM15RELBkr+D9A
         bMqInhWk2fJ9EeOKPFSF2CqPkvAw80TkiO4O8mD63HejFfZjk1cHb85OctWVJYit3+gV
         uvkwx6F6AMkkEf0dZmsPDbnXcVaMURx5OfJRXi+IYM+eF48cEZQ2TEBD+fD09nlHwvLe
         Wk0h2ITZ9ehgd5isnd8SiQ6jEeCLTlDxdARbQbrChBgiTIosRCVV3Egc3ggqg00BXWYv
         puGwop9xk2jjl5YqhLhOZXb1PnZu6GmoCI7127y6s7QxqqcH1Sc+AYzJLLsf2D6d3NgM
         YkGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AtU+E1OV;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-42571a85adfsi4494055ab.5.2025.09.24.04.51.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:51:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-279e2554b6fso25958075ad.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:51:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUwjMCNzGZDlOoSNXRJAW+O2bkrzCRYRWmtyuhgvYnLw7q60j+gZkdsgcCO/oK1ca3agLk/eellk4Y=@googlegroups.com
X-Gm-Gg: ASbGncs0vTLFnrEZxUODvYBDBNT3dNW0GaEF6wfP4wshiLBmXY9NGWUgyxGtMQ4MPJu
	B+Tmo+wk+mMfxSbXv1SJ5jjbpGccFCAvsE5cbQH2c/NO9ugsgIyigNRyLzSVSX5r4yXbFYwzzUa
	ITUhv4aV5k4/Bd95tMyzqbns6eTSI8AtY59dGPNDWwm1eTQBJZBImO0v/iiXBc5c0tKewVSTxva
	Ykd+yzSblu20V3oLcu2czWLoBln0axlWklUOP4BDlQgkLSCFKeU/KKxShthU2REuOnfCeuanlIw
	iHoeVWP0artAZsC3YZVtC+4aGQQDB4o2pu3GQgJPEmLSIAywDH155HYuxvh3axHqcs5EKZzE3lh
	0UTqRVN9LV1ViAiYkleyd4CaqG19lhJf9RCiS
X-Received: by 2002:a17:902:e885:b0:25e:5d83:2ddd with SMTP id d9443c01a7336-27cc678336emr76685615ad.45.1758714712744;
        Wed, 24 Sep 2025 04:51:52 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ec0a7f443sm19635565ad.105.2025.09.24.04.51.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:51:52 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
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
Subject: [PATCH v5 05/23] mm/ksw: add ksw_config struct and parser
Date: Wed, 24 Sep 2025 19:50:48 +0800
Message-ID: <20250924115124.194940-6-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AtU+E1OV;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add struct ksw_config and ksw_parse_config() to parse user string.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kernel.c      | 112 +++++++++++++++++++++++++++++++++++
 mm/kstackwatch/kstackwatch.h |  27 +++++++++
 2 files changed, 139 insertions(+)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 78f1d019225f..3b7009033dd4 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -1,16 +1,128 @@
 // SPDX-License-Identifier: GPL-2.0
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <linux/kstrtox.h>
 #include <linux/module.h>
+#include <linux/string.h>
+
+#include "kstackwatch.h"
+
+static struct ksw_config *ksw_config;
+
+struct param_map {
+	const char *name;       /* long name */
+	const char *short_name; /* short name (2 letters) */
+	size_t offset;          /* offsetof(struct ksw_config, field) */
+	bool is_string;         /* true for string */
+};
+
+/* macro generates both long and short name automatically */
+#define PMAP(field, short, is_str) \
+	{ #field, #short, offsetof(struct ksw_config, field), is_str }
+
+static const struct param_map ksw_params[] = {
+	PMAP(func_name,   fn, true),
+	PMAP(func_offset, fo, false),
+	PMAP(depth,       dp, false),
+	PMAP(max_watch,   mw, false),
+	PMAP(sp_offset,   so, false),
+	PMAP(watch_len,   wl, false),
+};
+
+static int ksw_parse_param(struct ksw_config *config, const char *key,
+			   const char *val)
+{
+	const struct param_map *pm = NULL;
+	int ret;
+
+	for (int i = 0; i < ARRAY_SIZE(ksw_params); i++) {
+		if (strcmp(key, ksw_params[i].name) == 0 ||
+		    strcmp(key, ksw_params[i].short_name) == 0) {
+			pm = &ksw_params[i];
+			break;
+		}
+	}
+
+	if (!pm)
+		return -EINVAL;
+
+	if (pm->is_string) {
+		char **dst = (char **)((char *)config + pm->offset);
+		*dst = kstrdup(val, GFP_KERNEL);
+		if (!*dst)
+			return -ENOMEM;
+	} else {
+		ret = kstrtou16(val, 0, (u16 *)((char *)config + pm->offset));
+		if (ret)
+			return ret;
+	}
+
+	return 0;
+}
+
+/*
+ * Configuration string format:
+ *    param_name=<value> [param_name=<value> ...]
+ *
+ * Required parameters:
+ * - func_name  |fn (str) : target function name
+ * - func_offset|fo (u16) : instruction pointer offset
+ *
+ * Optional parameters:
+ * - depth      |dp (u16) : recursion depth
+ * - max_watch  |mw (u16) : maximum number of watchpoints
+ * - sp_offset  |so (u16) : offset from stack pointer at func_offset
+ * - watch_len  |wl (u16) : watch length (1,2,4,8)
+ */
+static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
+{
+	char *part, *key, *val;
+	int ret;
+
+	kfree(config->func_name);
+	kfree(config->user_input);
+	memset(ksw_config, 0, sizeof(*ksw_config));
+
+	buf = strim(buf);
+	config->user_input = kstrdup(buf, GFP_KERNEL);
+	if (!config->user_input)
+		return -ENOMEM;
+
+	while ((part = strsep(&buf, " \t\n")) != NULL) {
+		if (*part == '\0')
+			continue;
+
+		key = strsep(&part, "=");
+		val = part;
+		if (!key || !val)
+			continue;
+		ret = ksw_parse_param(config, key, val);
+		if (ret)
+			pr_warn("unsupported param %s=%s", key, val);
+	}
+
+	if (!config->func_name || !config->func_offset) {
+		pr_err("Missing required parameters: function or func_offset\n");
+		return -EINVAL;
+	}
+
+	return 0;
+}
 
 static int __init kstackwatch_init(void)
 {
+	ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
+	if (!ksw_config)
+		return -ENOMEM;
+
 	pr_info("module loaded\n");
 	return 0;
 }
 
 static void __exit kstackwatch_exit(void)
 {
+	kfree(ksw_config);
+
 	pr_info("module unloaded\n");
 }
 
diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 0273ef478a26..a7bad207f863 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -2,4 +2,31 @@
 #ifndef _KSTACKWATCH_H
 #define _KSTACKWATCH_H
 
+#include <linux/types.h>
+
+#define MAX_CONFIG_STR_LEN 128
+
+struct ksw_config {
+	char *func_name;
+	u16 depth;
+
+	/*
+	 * watched variable info:
+	 * - func_offset : instruction offset in the function, typically the
+	 *                 assignment of the watched variable, where ksw
+	 *                 registers a kprobe post-handler.
+	 * - sp_offset   : offset from stack pointer at func_offset. Usually 0.
+	 * - watch_len   : size of the watched variable (1, 2, 4, or 8 bytes).
+	 */
+	u16 func_offset;
+	u16 sp_offset;
+	u16 watch_len;
+
+	/* max number of hwbps that can be used */
+	u16 max_watch;
+
+	/* save to show */
+	char *user_input;
+};
+
 #endif /* _KSTACKWATCH_H */
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-6-wangjinchao600%40gmail.com.
