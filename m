Return-Path: <kasan-dev+bncBD53XBUFWQDBB75WZ7DAMGQESTQU2AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C322B99AB8
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:52:33 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-77f3feba79csf4759337b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:52:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714752; cv=pass;
        d=google.com; s=arc-20240605;
        b=lCnqzNGNkvc/o98w441kqsFjYpLffH1voCO5/dA0Y6FHz4ott4daKgHTHEdoNcdTB3
         FhHtw+59Pwa1EmrE99vGv05588QBE2q5taLPfG+1RC1tGKbXGBv/RCWdOICoL54ugFPX
         FjB7ktFz4D4q64lJGsO6J7g4oCpbUNclLGVbtPYwQaIyGCLvgVwQkw8S1FEGPL2XkmQG
         TnkxB7Aiqz1yDRZAh9fXXOcq2sKJWOZvamVLEVwd2JhQqfUlMR9/ZfblPrkfhn6/kVr7
         j9GgERX84gY3fqX17E9BPkJrekxhXKv7brM96bjCpWpVhopRpCOAkrd9hrkdMKHLkUr6
         IQFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=YJXTGQe23rUN/x5PR25q+yRFt4lHEUvveZLeT2xkcic=;
        fh=yxgGY8UwjnzwmdeL8K65RTCuNACYPHw35uKeVSh/uqs=;
        b=abD1lh49kZupWyG6jWWlaqcuaWwduwjVODoqEkXGIYneygW3PF8CroRJuDayrBNzZq
         f9yUQcLX8x18A5HYKEOoNuHFOPJyqateQ8Rio4SAb/7GGayLDh/16SRePWgLUMoBdVjQ
         I+51UqFiemMOP97jjyEu/1EiiISEEbc+BYDBixS/p04bc52lghYxfgPoO2mWemgIwtGK
         7sxO+TzKpsc0O/7GEofwGwvDIKCWO3RcuhhShxZL69C3eHuv7jLCdXjS6Urt5u/H9FqA
         X4gFQog0lLtIwuasgMNCmO4nABjz9LwDPlPX5mCT08m3cHlM7duykBnVRb8PoVfoOd81
         8qqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SIyZA+GE;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714752; x=1759319552; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YJXTGQe23rUN/x5PR25q+yRFt4lHEUvveZLeT2xkcic=;
        b=QiVro/mbN4ct/CyfOFZdFd02GAE2GtzsPxTtKpFmMgq1Z81dswRJbUnzQ/TQGFGWrN
         clX/SsPG1VYz5GGFXkZt3131LgMASHpshk/btLNKFgx8om53vEHkYeLbJWor/+0lAiGt
         24LCizhDMkQtkOlx0N8EpuUQfQglqtZdwtTVUOB7hsD2782uIJoQ4G43tznkKthY5wq0
         9wf8PiFdOGIZibZIiAKvmc8cVseFZo0oUoPOHoroaxNZ9MShbTKoC2uNAWyMG6GSS7So
         UEkXsnGRcjWx4+IUa7vvF5hp+1z9Om6yh76lQqjb4XQeogvACeQcGLSA07cRGcUO6yku
         xv2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714752; x=1759319552; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=YJXTGQe23rUN/x5PR25q+yRFt4lHEUvveZLeT2xkcic=;
        b=XX6VQr+bvRA00xsriCW9TVbWdFP4B+jhAJqD9ochpWDNbVJqYYX+jW2YCD17jApQ4a
         omfB25/lsACy61qVhqMEc+pp6t87d3Jv2mtkuprQn4LD3iv5V/jDhS0lrbQRX7zw3Wid
         ljZScL4u8EF93hQyIblF7lTNDpNk2gJXCdQHBVtOq6BQv7ehTd8bO+wPhA7N8HZhJld1
         l3VzYe5ylk1QBwbUt+CPDSb1ZMv2RZvBkd5osfCxyFQAoxe6aatiyiowuv9NacKtfvbc
         jQBeRTL7xFuhoxepO+epsYZrX0IXDzOdQnWxoWwBkZY++2AcItsoYJRRphly8em5YFNA
         WsOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714752; x=1759319552;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YJXTGQe23rUN/x5PR25q+yRFt4lHEUvveZLeT2xkcic=;
        b=C6YoSRR1FhWKmY0JNoDDgReBDOxEc5jrAtmnIU8yfNzDCFEA/FFk17Qxtrecfj0u+7
         PEUkVBrtmixMCxTFLwlvH1Zd2zRdrDIvRtY31VcxakXQlJdNaD1ije0DknMAKVyoUf08
         GumcuwDeMAhRwcRSerYCQWWNEd2J3TIwM3Q6KfViSUd1LdWGhMf8yWgq6RJwZwgJzSGo
         MCUSrGfbZzmNCnrXcQdKT3WtnEHIfL1uj6zAHOKpoDMMdSZMCIhYIZ/n1viXGZYElACe
         LuIGSpaMf27RP5ctuUkmyIc+kHQQAha6Q4x3ODHyEsgUwAOTgjHp/tYekhqQsqkUOuZo
         Hl1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXzAwzOp+fMKTq74NGjEVJ01PtotazGyslDTm/x96vddJYRmfW0oHX3yqoI+eVczZVZFpbhsQ==@lfdr.de
X-Gm-Message-State: AOJu0YyU1YidNJ7CNR0qk++ntAN5E3VTT/uqfTSUYQ5WmAUc41lF1vcN
	IX4dbcnsZHZ8Tj4SDgKurX5io4wcxfJra9nwzJUtt+tfuIVO8vbrIRla
X-Google-Smtp-Source: AGHT+IGii4Rn+Vev0ZJr9juzAY/egH2dumLn+TdN3kIpXDlwRKUtgDyVv5zX0nmVIa6NXGSj8pirPg==
X-Received: by 2002:a05:6a00:4614:b0:772:934:3e75 with SMTP id d2e1a72fcca58-77f538dffe5mr6673486b3a.11.1758714751917;
        Wed, 24 Sep 2025 04:52:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5WLHe0VQocp50rXi7x0owmg8F1P19PguFp7gRKu1m/Qw==
Received: by 2002:a05:6a00:1b:b0:780:f901:ca95 with SMTP id
 d2e1a72fcca58-780f901cbfels127606b3a.1.-pod-prod-03-us; Wed, 24 Sep 2025
 04:52:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcyAx6P0SQ1zYC1WqunmFufdPvY8OnEbFzQAh5Mj7xaM8m8qwbn7r3pl/bJAaxcr7hO8q6a5YtHsw=@googlegroups.com
X-Received: by 2002:a05:6a20:7f9f:b0:246:9192:2781 with SMTP id adf61e73a8af0-2d019c03a96mr7206711637.47.1758714750463;
        Wed, 24 Sep 2025 04:52:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714750; cv=none;
        d=google.com; s=arc-20240605;
        b=ACqEvIoOidHGkHxi7bZBBLCglUw/LvSIBHaO2zUDOuPL7kFuoATvhk0CMdEQc6QQWj
         Fcc5Qwn+dE7qUcmGlA88rl+gixxPmXoNTfVd14E4+Xz9abtwqSBEinm9yft7V9LUb9Ed
         yNiIfJwzb+YPYFLfkVKmP7Psp5oTOROTkiNkyh/a7pcVGkHPgeeHvUhVDoyadNIgRhg7
         QOA0skcdO5VMpnBmogZ641IdsEwruMHX0+yiFMi7lHa0bnxSPw8zYJaYthqCCKqI5dn8
         UAH8U81ppLTggx7BH3nhHYWjKdotFlspkhc0GehG0LDUfi+SAIk+bP+AMHK7cqXHhwdE
         tJqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CDvSRov2FamkqE0fpRbb1mATCdcadu0+ybcKu6XxB6c=;
        fh=VifBl9ByvqZIknxxs74ckEPukCbzxD8GeyU1khL9OMw=;
        b=DtOMbVAfUrHIvZY+ctpR0jDdeoMbuw8knqnrIpU8/VQlLlfj3zwPTiO1YiWupMXcYh
         Qo8PHSqXr1HjxfLtqhZ4bxn9CmmoDsWge5LwMRny2r6Nzdul/R+AKkrvjNZG5y3+FQhQ
         yoLvaPwMXFTX9DdOGfwrwktyv5496nJ929mCoHsfpLzmniizLc4BSbuUMo+jjwOwvLck
         8OiEHSCngpeLIqVBOe5wmVQ0Go6+aNyV8HN6fd1XXAEsdpZOb81z4u32oIV/dwXS5c+X
         2DjiPOKJArk7gcM/LB8kEnmv4QVUrsbyaiKwME4lmI365aERwSrjIR8kcU2/MKmP1lS7
         qHyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SIyZA+GE;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b55161c213bsi506057a12.5.2025.09.24.04.52.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:52:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id 98e67ed59e1d1-32b8919e7c7so7622705a91.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:52:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWl+UfOLPnCb3cIjq/0v3+f4dKC3w+oo9ND/qPnY6wZo2ur0eJpmcvNPWCGX3UWS9Z9wXEpv1Zrihk=@googlegroups.com
X-Gm-Gg: ASbGncv8ohzBsGvdb38CIrsJMDNKuUwgBNQtn3o4SbPck6/34DhPbSFFVvzMylHGTFx
	e9r5Uysn4sZ8TqlA8kpfzWSVKHtIU2B0zr0/oJgv4FbB9dxwbA9NqFVnhfC9YCAcSyloE6z5vq7
	ngW5IWwq8hfw32SHyNPMtSARTp0/Y0VJPrZ36WGgZMJsF/AK37wGhemMSFVNv040oqba97ak6vD
	GWQOCP/Og4ZeH59UZTiuu58ZY9hAtEuzS5RloEMtTAdD+wKgWdasLLiBgtoaEbDJLWiwWSvmWHb
	75U6uqE2U7oxUX/2VLN/2zUTnpJI7EaOv4E0yLh4UPXaCh4J6isGNYAJX9HAJwZQ84Lbtrs33C3
	xstQssvl9k3540KZiSfBVqbWCAg==
X-Received: by 2002:a17:90b:1844:b0:32e:87fa:d95f with SMTP id 98e67ed59e1d1-332a98f6f1fmr6851528a91.32.1758714749765;
        Wed, 24 Sep 2025 04:52:29 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-3341bd90587sm2190418a91.6.2025.09.24.04.52.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:52:29 -0700 (PDT)
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
Subject: [PATCH v5 15/23] mm/ksw: manage probe and HWBP lifecycle via procfs
Date: Wed, 24 Sep 2025 19:50:58 +0800
Message-ID: <20250924115124.194940-16-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SIyZA+GE;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
 mm/kstackwatch/kernel.c | 55 ++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 54 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 4a06ddadd9c7..11aa06908ff1 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -13,6 +13,43 @@
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
@@ -126,6 +163,9 @@ static ssize_t kstackwatch_proc_write(struct file *file,
 	if (copy_from_user(input, buffer, count))
 		return -EFAULT;
 
+	if (watching_active)
+		ksw_stop_watching();
+
 	input[count] = '\0';
 	strim(input);
 
@@ -140,12 +180,22 @@ static ssize_t kstackwatch_proc_write(struct file *file,
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
-	seq_printf(m, "%s\n", ksw_config->user_input);
+	if (watching_active)
+		seq_printf(m, "%s\n", ksw_config->user_input);
+	else
+		seq_puts(m, "not watching\n");
+
 	return 0;
 }
 
@@ -193,6 +243,9 @@ static int __init kstackwatch_init(void)
 
 static void __exit kstackwatch_exit(void)
 {
+	if (watching_active)
+		ksw_stop_watching();
+
 	remove_proc_entry("kstackwatch", NULL);
 	kfree(ksw_config->func_name);
 	kfree(ksw_config->user_input);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-16-wangjinchao600%40gmail.com.
