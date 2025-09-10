Return-Path: <kasan-dev+bncBD53XBUFWQDBBN4XQTDAMGQEQD7JBMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 68712B50D23
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:25:13 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3ee1d164774sf4831715ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:25:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757481912; cv=pass;
        d=google.com; s=arc-20240605;
        b=E3tqZkE9chcqU1EtkM58w9UE6JtYtCkLuAxZO1VtXRiYeobDAipNrzoRRkdJPjjIIF
         iEcSefjgTlA8x8dCLoAo/S9tnsUJMS99IM3mfg8S56g+tyEtaNrYKWRrKmkael6LnhgZ
         GJJ3L/VHS5R3KW1+LVxKWWAkxBub1hhlO5yg56UlTeOHZDWgdqITbbUAlBzVIwoV2rvk
         6N2CdwsrlzgcoRG5COERyLAgsgPMUcGq+ZjsY80ECeYJHZNG3Tdv3MIZm1a9BJmAj2lK
         CbDjwHuXGlPKfRIAfKAdt/7H258bFI4wqNIboR3yAO/3Mfvzn7jtM0gMBP2fYmdFuVQV
         rqrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=O3AiflYA3FU5i+MlPgMGv+aBjZpw1K99IfAFFdMyumE=;
        fh=IN6P2o7pf7npZs+AJ4Kgtmr4R0o7WbNDnwj/SDRbtVU=;
        b=Xvzy6ZWAtcWDoGzocfQ9AJAZhKB7z4EZlFHtglYL4cEUTA/3eDLU/78ON8gUxxzsc9
         QnJBO27D7/wp5IXlb+KJ4dABXwH7MvrxeuZiSzPVrUVVzWd2P/NWCvP2+YrneAOiSOu9
         oy5DvlUIvB46czrHJeDRgLiVXavHAc1k7klV64PYN6QX4MRuU4YCSe8FsvnUdl8LbK59
         6/J7Gq4J7iwrQILPF6L7zeBk6gXfbfOqn9YKIvspcuZSoWdEjQEQuhYiQ/2Y7N4FlIDu
         keLl0xTCqxLtJxg/yK0hsrShqIwcRBXpKfpGgAbFEhU5yP/Rm+Sd8qnyaIvCuyCQhSn9
         ZdYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iZs+z8Zl;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757481912; x=1758086712; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O3AiflYA3FU5i+MlPgMGv+aBjZpw1K99IfAFFdMyumE=;
        b=jNa/fGQFCeqbWAR5xRG6oMKf2RohfleyiIcx5uHJIEV027tIcvjkNo8Ih2/7Zm+bM/
         gGlABJcw+qhkNOkvOZMtkvaYw9GFrGtA4n2riXwAqZWiclvyyufIprR1KlhB+ALRuWin
         Py2KWvY8NZm78pUfLDXTR67+Ajb+8F0ogksj2MLiE8CjV9c0VpbuxJGofQJRcMJ1H3O2
         MuYlj0/ViE+HU05sHcPjcjkLRkPTPOe/QN8dM9b700uAnWGaL+bRtLvl5waQXe6w6Wc0
         uX7VXkOzz1YA6s68sbUv0RlPTbeoTxP2kLm2WJ1wda8XBWfWhGl3yn+2Dv4JagooPgtv
         t8yw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757481912; x=1758086712; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=O3AiflYA3FU5i+MlPgMGv+aBjZpw1K99IfAFFdMyumE=;
        b=T/nXMYyU+rSdhprUDOWJG1jitjkF1AWrWSnXStYN8Zl+YILq/1jbtGSv8+ILzE2b5w
         MkLjcdGkS7QwJZ1HjpQNFQpa+dvFNXuIMOP7i9rOZ43CJDM0+g7NmfmhLDIUol+yZ6JZ
         KVnPVYBqVa89RjGZ/VzaQdCBeg3+9AeS2EIoNPacmTxCDMlGDX7xE7zIeIhF8cPIdmd9
         AirVYhgwmLDErCSSLhBtw1MBbtiOT/OhbyBZ11Bn2wJOCWc7M7+sbrUL7fLYBPkMDiCt
         sQVTMMFkWjtJcrcRFL5atRwimeSxeeoSHBKWV2HbXMzBypVGvMRgqAEtZNJ6Vpff6KeL
         74UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757481912; x=1758086712;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O3AiflYA3FU5i+MlPgMGv+aBjZpw1K99IfAFFdMyumE=;
        b=W4jAhF0AMe8hAj/ANQDEUwJb4KqTVo0zQY5wOc2TMsPoNDrLq8OgTkNcpPu9N8rsLt
         ikjgn6wKuXvN7pDdPrUboTHE0ed/0PXOhhMF3MlsZ5t7V1pIyAgZ2CFVh+9TWaVo2X5+
         7RPAVDoQDL5x7VlVsUuiBVjzB5eUGQYvpDsGhtEZRvbDyccO8xYrX8Yz/bDexiA3jk8T
         kZj1y4rOes8SIob7Dh3MW694F6xuZ8gOEcDiZf/ovatpXBgfVpEnizjgSn6QYS80PTFb
         tc2SP6DAcw87LKk5xO0Wwt0KQENj9dqXcEemqH5hx06Zq0/qFE0hbdRK/plDbWZ6FCx0
         TDnQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsq5Y+X5PgOa7wF1B87nXOcdHeKZ0lDrcUfKWYTib1h79x6325CClTjv4YJBtsMbz58GLTbw==@lfdr.de
X-Gm-Message-State: AOJu0Yyt1LdnStN6/Q5KorH1HC3xsHnQJonphA22zwIVbJtjMBtuxPCl
	J1kLhCumCeFwMzkOMRjLedKwACu5+tMnY0HzLxkcDbx/8jUg+7ZV42Jy
X-Google-Smtp-Source: AGHT+IGzPFuD2NwHc+MHUnShHg7Jg5OTcnaHsBqg7Ff11XDrJlZ4SX19H2DSqpYQNCutkMDh9PScJA==
X-Received: by 2002:a92:ca0b:0:b0:40c:cf06:ea2a with SMTP id e9e14a558f8ab-40ccf06eaf4mr122791435ab.2.1757481912138;
        Tue, 09 Sep 2025 22:25:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe897dmZ3V8G+yr0JMmEnYgakgOAj9LF/FPJDrEHyTFgA==
Received: by 2002:a05:6e02:180d:b0:3ee:60af:4e5c with SMTP id
 e9e14a558f8ab-4168ee92097ls2196365ab.1.-pod-prod-00-us-canary; Tue, 09 Sep
 2025 22:25:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXEDSVa2SDo0LgXt7CV3etSz+PY5q8Wlu9kodq0zRNuScyB9PcL6oTfPLWTgaTqnmQMio30w2x+s2k=@googlegroups.com
X-Received: by 2002:a05:6602:6418:b0:886:c49e:2839 with SMTP id ca18e2360f4ac-88777a5ac41mr2185655339f.9.1757481911099;
        Tue, 09 Sep 2025 22:25:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757481911; cv=none;
        d=google.com; s=arc-20240605;
        b=FWfMuCI8tjVzohFQt+MHU2JieumPNI9+V2idJYZ4l7NhLRQLgibjMQpWq/+NDOWDUs
         2WMNYEuAKwJex6Lb0LWQ0IXWZLKZjQdR+uK+1cpVJ3qtrrTQGUM4dKgZV5f4CSRUBVDM
         JXnHSWAbQt54TFuvNx6qblmyWeD5Oeo0FJw+tUQr1SoRRbif0rxKgjhztsBVQP8KBy//
         I4a4PqXryPZFtaqgK0u6o57sx7dhi+Ed853JFZOzMcqgt6cLvJ8eJD+fvtPHSneN783i
         cPKnZ39sa4yTd1cw1QPGyja7BuWCTBv+IUbfI7N0Yc5Nt3qaTduugIATRggxSf4Oxn7n
         2Hzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JWZ0kuFk/JGga2KckHsx8bbCMGd9rBXEdZWbqFyn8fw=;
        fh=2gQw4eNqff4urSzEo8HBf52Uu4oa6oqOVOkWByWTKaw=;
        b=SbP41pxO4u3WPDHS7vBbGea4ZQA0grclG4nTP8rcs7FJAT936IIqwxnOwH7+6H27pa
         s4vYa6zVIlcdvJ1UikbZ8+vTsL6Ww2pLkMP3vpCkQ10cZupFxlbSr7CFQQ48qhUMVxXO
         DqheBKPDblznOMPWi7tcwCBMwlCAST19TWpfIuSJRlRV/SxPhh6Zw+vmqN2Wq1S40vg/
         CvoJCBGA+pGOtxo3mw6JvsNHkfr8KFTjkQP3wt2AxdKPwijTUPoiuIHlNXx96P03vRYg
         uNLGjeRVf/TUJiqZJj81OJ4OzMwB51D/46B8kUfGoBsh/vksjA3XoOMs6z1AE6mDBzHa
         oaww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iZs+z8Zl;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8876f77c02bsi56637539f.4.2025.09.09.22.25.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:25:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-2518a38e7e4so3639015ad.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:25:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUfL/7kkrktecDsd/fXtwtYn77fPVE4bYsWvNXjvBmqXLvmdtgAcrOM4uluGgleSjVO1aWzLKfv5XU=@googlegroups.com
X-Gm-Gg: ASbGncsG2JRFmzZ2Q7IFiRHGYZuKpQ81FGeIbokzq376ZwAKEz3ZCc/nwBRhVLEdOgG
	9X7GdhG+wfKlwVs87N5k1w4Hxb6iSsn83Ih2G0jKnMrhXoyGP4OdRYMxgOLYWj3E49Z7YRVJXmh
	Wmg6brqjJ1GkC3EnNoXDfdbroWjtqngWnGUwfN/ASpzQmYKmamVZUXaG6haaYIlQfEwuBWiW0Pz
	/ktBa4PKj0TROoKqI+OCcYL5JAWrfPf1wr7v5f7uBT+1X5OH4sflcV3Gpq0tsCBVNYDG1aVpJTH
	ewqhUdtrIRjw7ZVsiR6nqRSY2CN1S8WKcC9KsvHDewQd61XBiChA4fvQFRFoFzrASsryQHqBpq2
	Fr3fNQGO+Vab+Ynby/Bjn9P01geosMuetNA==
X-Received: by 2002:a17:902:f78f:b0:24c:e9de:ee11 with SMTP id d9443c01a7336-251788fcff7mr180480145ad.17.1757481910286;
        Tue, 09 Sep 2025 22:25:10 -0700 (PDT)
Received: from localhost.localdomain ([2403:2c80:17::10:4007])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25a27422ebcsm14815125ad.29.2025.09.09.22.24.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:25:09 -0700 (PDT)
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
Subject: [PATCH v3 04/19] mm/ksw: add ksw_config struct and parser
Date: Wed, 10 Sep 2025 13:23:13 +0800
Message-ID: <20250910052335.1151048-5-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910052335.1151048-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=iZs+z8Zl;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
 mm/kstackwatch/kernel.c      | 91 ++++++++++++++++++++++++++++++++++++
 mm/kstackwatch/kstackwatch.h | 33 +++++++++++++
 2 files changed, 124 insertions(+)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 40aa7e9ff513..1502795e02af 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -1,20 +1,111 @@
 // SPDX-License-Identifier: GPL-2.0
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <linux/kstrtox.h>
 #include <linux/module.h>
+#include <linux/string.h>
+
+#include "kstackwatch.h"
 
 MODULE_AUTHOR("Jinchao Wang");
 MODULE_DESCRIPTION("Kernel Stack Watch");
 MODULE_LICENSE("GPL");
 
+static struct ksw_config *ksw_config;
+
+/*
+ * Format of the configuration string:
+ *    function+ip_offset[+depth] [local_var_offset:local_var_len]
+ *
+ * - function         : name of the target function
+ * - ip_offset        : instruction pointer offset within the function
+ * - depth            : recursion depth to watch
+ * - local_var_offset : offset from the stack pointer at function+ip_offset
+ * - local_var_len    : length of the local variable(1,2,4,8)
+ */
+static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
+{
+	char *func_part, *local_var_part = NULL;
+	char *token;
+	u16 local_var_len;
+
+	memset(ksw_config, 0, sizeof(*ksw_config));
+
+	/* set the watch type to the default canary-based watching */
+	config->type = WATCH_CANARY;
+
+	func_part = strim(buf);
+	strscpy(config->config_str, func_part, MAX_CONFIG_STR_LEN);
+
+	local_var_part = strchr(func_part, ' ');
+	if (local_var_part) {
+		*local_var_part = '\0'; // terminate the function part
+		local_var_part = strim(local_var_part + 1);
+	}
+
+	/* parse the function part: function+ip_offset[+depth] */
+	token = strsep(&func_part, "+");
+	if (!token)
+		goto fail;
+
+	strscpy(config->function, token, MAX_FUNC_NAME_LEN - 1);
+
+	token = strsep(&func_part, "+");
+	if (!token || kstrtou16(token, 0, &config->ip_offset)) {
+		pr_err("failed to parse instruction offset\n");
+		goto fail;
+	}
+
+	token = strsep(&func_part, "+");
+	if (token && kstrtou16(token, 0, &config->depth)) {
+		pr_err("failed to parse depth\n");
+		goto fail;
+	}
+	if (!local_var_part || !(*local_var_part))
+		return 0;
+
+	/* parse the optional local var offset:len */
+	config->type = WATCH_LOCAL_VAR;
+	token = strsep(&local_var_part, ":");
+	if (!token || kstrtou16(token, 0, &config->local_var_offset)) {
+		pr_err("failed to parse local var offset\n");
+		goto fail;
+	}
+
+	if (!local_var_part || kstrtou16(local_var_part, 0, &local_var_len)) {
+		pr_err("failed to parse local var len\n");
+		goto fail;
+	}
+
+	if (local_var_len != 1 && local_var_len != 2 &&
+	    local_var_len != 4 && local_var_len != 8) {
+		pr_err("invalid local var len %u (must be 1,2,4,8)\n",
+		       local_var_len);
+		goto fail;
+	}
+	config->local_var_len = local_var_len;
+
+	return 0;
+fail:
+	pr_err("invalid input: %s\n", config->config_str);
+	config->config_str[0] = '\0';
+	return -EINVAL;
+}
+
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
index 0273ef478a26..7c595c5c24d1 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -2,4 +2,37 @@
 #ifndef _KSTACKWATCH_H
 #define _KSTACKWATCH_H
 
+#include <linux/types.h>
+
+#define MAX_FUNC_NAME_LEN 64
+#define MAX_CONFIG_STR_LEN 128
+
+enum watch_type {
+	WATCH_CANARY = 0,
+	WATCH_LOCAL_VAR,
+};
+
+struct ksw_config {
+	/* function part */
+	char function[MAX_FUNC_NAME_LEN];
+	u16 ip_offset;
+	u16 depth;
+
+	/* local var, useless for canary watch */
+	/* offset from rsp at function+ip_offset */
+	u16 local_var_offset;
+
+	/*
+	 * local var size (1,2,4,8 bytes)
+	 * it will be the watching len
+	 */
+	u16 local_var_len;
+
+	/* easy for understand*/
+	enum watch_type type;
+
+	/* save to show */
+	char config_str[MAX_CONFIG_STR_LEN];
+};
+
 #endif /* _KSTACKWATCH_H */
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910052335.1151048-5-wangjinchao600%40gmail.com.
