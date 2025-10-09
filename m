Return-Path: <kasan-dev+bncBD53XBUFWQDBBQFKT3DQMGQEZQYA7HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 0790ABC8A20
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:58:10 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-82968fe9e8csf304239885a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:58:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007489; cv=pass;
        d=google.com; s=arc-20240605;
        b=lckTceYyF4mJbZbD6xhfVoOQim1IUFPc/kopLGmEr4xq61MQdh+EcbKmzzc93BpNcp
         5oVP2TDZjzLutdblWjyf8g8eLwGdFG5mvPn/pNIgCPzjRLThXsaJXPHofF5WoO03rYTu
         SyO2demnOM+QXrKwag06UBlj2JFuwXP8byeUW8h1D4DIuXfY37/U37sqIFIkBjMJx3nh
         +0EWcA1AgkBzHLo+oEKAxbWIwTQZp7frrugNEanGIDGQb3o7gDHykeKY7Q7vvKcnzj+t
         77Ei7yZXf8r0yYHTnb2DeiMo32cJbt6nXxq+6QYuya1NBXXLDxL0qnccWGICZAY9fCKd
         P8MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=AUpOdr8W/AGzMsjnxcwAUbLmV73fIs0Ny03eP4n7OxY=;
        fh=xxHDux0XwBmeuy/ZGQGtggpgjigD3fgx14iDePLwLoI=;
        b=dX7L9p0eV6B+X0KIsEvNKNl84zOJ6whKqMl2ttEKe19AGPzmIzqaWcNnkJTTsZYQi4
         ba71cVet4pYSHR07MIQc6PjlSIDRLQbglPvHMVCs6XiGlSF4di7cbV/dM7kT81P5sv5v
         K/0JWwLHn/NBWXj1v2t9Rx8eWPi1JVBw2WKpHLDUMRRgMHic93bgYSmsbPrahMK8OQhs
         +dnJEigM9e/EXwFJSeHSFKQpNDpoJtebIqJRJ1f5roMA6AZ0qPs/HzKG/BG+htkMhIjh
         11T3q1eM3NqJAmhqIqj7cS0XY3r+omooZMBlslaqlis/KIReoZY9hky3eUCVV96wwsqB
         igKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DLQgKGHk;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007489; x=1760612289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AUpOdr8W/AGzMsjnxcwAUbLmV73fIs0Ny03eP4n7OxY=;
        b=xxDLpM4MW5uMepDYEd6fBpKYrpQWw0EaKTrdAXsXQAXuRs7Kv5ugzn7woMAjkVvjqV
         Ow8s6yMTYAsffAwB2997jRMAFzzSUBCPCsrkCjK1wP2OuX6NCUUeP5LTf8N4AyEehf5A
         Rtx4uWUDWdwc4qYIrK2hQSGCsRfgad7z1xExgp9isuTdgCtOWFCjuFV0eohakqLR39xJ
         cJIr7URdPVXl4cAFie4HcJTIuRxq020l//iUjLFXWKH2o5macEgram0BtbiNz/mhGnIM
         m/URZMlUplv72uyJY9uwAEaKdIbowYZ+1z3TRSgTcXN4W0tgyBmiehRrGs+REL9Tt6UA
         f7fg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007489; x=1760612289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=AUpOdr8W/AGzMsjnxcwAUbLmV73fIs0Ny03eP4n7OxY=;
        b=cDewjMjP4iUr92dTKvdcJLZX8331XXT6IiP4LwceJ2tp+Q1XG8F5wBCWKbtXf669O5
         419RS//6u4BEQyG1ERKPFxfzNV4czt1FtLVHNNUPK0kAAflnLVk3vVhUiU/jTplMVE9p
         zUaDv/iZ7T+K+mEaEdH+DJB/jdqucsS3HnxZl+lVNEo7nGMFuugRN1DjEGcQvEfDtoF1
         nzVANHyMgIRjdHrIQ1Zd+9aMEn5xkRJphj4tsksSqpCdFUCRzknbNVY7j44HpqpHg6rL
         aH6yXTZoBNzHUSGZJQF8k2tc2SfxFVAcVfNs5dQ2T9h4oG0ywoOTKYdLL9OuPG05gknq
         VSuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007489; x=1760612289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AUpOdr8W/AGzMsjnxcwAUbLmV73fIs0Ny03eP4n7OxY=;
        b=i/QjUaEqAKhuR4tZA0Bx9H7rJU0t5ZdXtUwVJqurqNB16zmIMClZoXr6NWebIm1GkU
         tegAtV3p39sDOTtyS2wROAF/FcDQ6Dv6IJgyUWN29OTqkhVtBWLMTcYsuPnDi6TdjaDl
         q6lpjSpYluIFQgZBPGArBXTyqI2J9BJhAOH1W+mytpAZ+nd3mT6XkGAoZcUmUCode90G
         yc5fjMFuyaLIYCbeXct4gNFP/zUgXUcLQJFYBVXL/bxbyxBCrTckb2bk+I1sxdzKDyfy
         SorYo6dx6d3xc1Tdpu9a9le+VvBW4uqPDLMb7nWvk9tjwSp8q/bLzRjjkb28vH01dSAo
         sddg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2F6op2ONiOjeptuVfjXvmxtgJIN3IdHu1RfJkOLrRQH5iNLtnVJ/tnn+UzxC66ZW5mvXQaQ==@lfdr.de
X-Gm-Message-State: AOJu0YwJ3MQ/9PCUVcw1W5oDUdB6zwfoXbUomIDUNKLU/lV3zjvJm0D7
	9inn83Pkbvzug/UioOwmh81jn6aW4tOqqNJrO8vqSImMJnZvrfMFN1CM
X-Google-Smtp-Source: AGHT+IGkWZMtSHYBGXlR82hdGyLgrHaq/Fxz8Zr168Id8en7zIACsZwYxAJDxurPGUgWu1yPC2aExA==
X-Received: by 2002:a05:620a:1a9f:b0:864:c43:865d with SMTP id af79cd13be357-883523d711cmr1063463985a.54.1760007488691;
        Thu, 09 Oct 2025 03:58:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd64zHj3F6QZ0KMwpEhhZjF8PK4f111sJVqroMJrMOoxxw=="
Received: by 2002:a0c:ec4e:0:b0:78c:3f6:27af with SMTP id 6a1803df08f44-87bb4eb1814ls13107316d6.0.-pod-prod-05-us;
 Thu, 09 Oct 2025 03:58:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUai9MkvTmPgUYYjdETIbwWd750EieZsCInITolF4zfFW2P8Y9+bEdzuNSw5UCp41Glu/ByU8OuYNM=@googlegroups.com
X-Received: by 2002:a05:6102:c8b:b0:59a:79c:f277 with SMTP id ada2fe7eead31-5d5e233f0afmr3089432137.17.1760007487959;
        Thu, 09 Oct 2025 03:58:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007487; cv=none;
        d=google.com; s=arc-20240605;
        b=he10ysL5LlEa7T7RDpMGEeNjqRM+9qokIsLPpZ3oMsAAY2XNql2S82cgYeTUkcoa8+
         0Eb731kYrAk7Fy0flFdLaWYKAr4L3Wn1kSiQ8yFsiIJdIt9VY7Jz9HJjTE5eoS6lAyyl
         dS8QUEtPYJS7fyMU0FuPk3fE670dq7Qv91JlQ9nbjCIOXcZyb6GJ9YSe5b0NreHJhGjt
         j/zObX1c3s8cPfqN7maS4CAP2d0AqYMgt5Ll4solSk4eu7InzyN35e2lDDUeGgHqbqib
         2fo+zP4tjxZMFoqAvoPJWvpZvRyPpT8DwF4rw0WsJt9Lim0BgOhSm3Hfke3tTWK4Bwwn
         jLqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kFRia/GHfKKxxNt0IUc2kN+EVm0fmr2Lz8hq8oGCXGU=;
        fh=KfMr6d215ztwjoRYAvS97KmstvUkWJvVYjxT9sLEHdw=;
        b=X9lvLvZHtZ8Bn8R1v64Vjik5AgQEVi1znvSUGfc6yFB2pp7pOSkSHfvF4OP0bMFJ3v
         8BeUPsvlTWyuy4HIquBkFWaLjzYpnXNGXNYfivzfZkvTxaAoxqOiBGO6eH4oCJnXozex
         eprkHNGZaTdWAIXn92rveIWilJWMg1Ebzhb696Y/CxGttocgCc2SPGZU+N7zr9ovKGQ2
         tbsyco8tWcL9uNG9uVQDAcfyydt/CJsYLIp+3nxCodXDxFQPqvqMvQnNdZcW6EHHVbiC
         PG7zmSjk0bfP/qc+qNQ9X99old7+XMHF9t0TiT0r+xFtRR5lO1CdtSKD1lG1fCLWOB/Z
         wkyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DLQgKGHk;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-930b21cc541si91018241.2.2025.10.09.03.58.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:58:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-28e8c5d64d8so7527605ad.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:58:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXssVst7d1LsFM0rG5J7vUmMGx80J/BWOHEvWdFSBuryrK+7g4SJPjkKA661jjOgKAFqcSpGaLzKNs=@googlegroups.com
X-Gm-Gg: ASbGncsjpy7+CnLsEvMVKdi4oM8qo9gadw0LSSNiS9eG0Ig3M5uxDpwjxesTQoeGDuP
	0WfYROsvYdnYrZJvJRLc9iFvlHi4J2m3babYym2+F9JMVcCiYQSQbAGs8+AYTtoRAjXAX1MvEpt
	tpQ5mENU4ciSATMMA7nCRsRE/vfMbUEznAhCKRglkCwfRTlDVoltTjMhKwEgK4fiYfsI+M2sDud
	+vRilMJ6JhSy4puMWUOGAdHYK4fhXU7kOHeXNWgrRUShoVgCBXcCMFsHNOcvh1zCqClGTazEgfl
	Jo9MdS205J6b88+NH8/tKxrZnuG9A4/niHAJd9fQYKbd3LowMKO5cRrgTxGHihOMcFpIZKkmFMZ
	rgEl+cVjNaoK568ANuemKs6x/tjMNgB1GY6vemwdTIMYtjqGDUxATc2fffACsqfqjA2UWCls=
X-Received: by 2002:a17:902:e94e:b0:270:4aa8:2dcc with SMTP id d9443c01a7336-2902737c5e9mr92201005ad.19.1760007487406;
        Thu, 09 Oct 2025 03:58:07 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-33b51105813sm6628595a91.10.2025.10.09.03.58.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:58:06 -0700 (PDT)
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
Subject: [PATCH v7 15/23] mm/ksw: manage probe and HWBP lifecycle via procfs
Date: Thu,  9 Oct 2025 18:55:51 +0800
Message-ID: <20251009105650.168917-16-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DLQgKGHk;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-16-wangjinchao600%40gmail.com.
