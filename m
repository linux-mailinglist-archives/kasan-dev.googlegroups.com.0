Return-Path: <kasan-dev+bncBD53XBUFWQDBBK43QTDAMGQE5G4LUOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 56E32B50D65
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:33:47 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2445806b18asf80907045ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:33:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757482412; cv=pass;
        d=google.com; s=arc-20240605;
        b=jhCXP1EO7oYHKPzcZZyR16KguaCHbVXHe6UhO5taXnBfgZWHb1ToatazZGcdOsCafs
         rY0gJkEDXNAcUcmTmpszeof7otrmaTODBlDc0/fsE7S5cWk4qW4K5+FK+1n5PjEJhUWY
         k80wWBXN2foMeUzXIBInAmMuT8nOOMtZlfcLQhMJvDipdGtxrRdisycrEcusG7g0rbhM
         SR1d+4rOxaJBv6HSMuuG8Pf3Ge2rxu8/N23D9yfYP3qsab0Jg842/vpOw/qZ0+UywbLw
         HlyaueluF4SOEZ/yEg9pAKf7PJpuptN2c7fEMY5dgZ0J3jIR/I8iNx9iQb+qjZmqHsph
         cmzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=fx3sfYexHMpJ12pnBauoZq47+feY7Uao8KwZAdh5BtU=;
        fh=iM2yh/5xcLHZZ2eozD6YdZTv9sw20eCYGfQIsTGDJ54=;
        b=bIKhZJTg7DxiZvOjPj1QpLlbqH+DiIizDMJzFtmVwyWkqyv86EUa9Huajs1c2NpYSd
         1QW8uNQswTkM3JpM/VSLSNbUct/f0StkpC0vqDNPjO8l+6Y18stEVvsTdytllc75MSDE
         Zw+skVxEOWcbwCq8QpZ3lIwTzdecGBJwVqdqzHNVUTGFErXcH+xMJRCRTpZuksylpLTN
         vuObzpP1BLgD+wSQe2q6kqeUKB9QyexdXHw3cq6CLIFw7jgnL2HBwJVqN3nJjEqh1/qU
         OSozoXG0/2LuxctUaS5PNZmt80gMH59a6EnMp2A1NyjFPS6WpfTsZOzPoJfnTurtHJ/6
         WX5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eS6zsU0e;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757482412; x=1758087212; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fx3sfYexHMpJ12pnBauoZq47+feY7Uao8KwZAdh5BtU=;
        b=Yw6mr+jeH3uInFJZMWqFI59O2eb92HW7TcuQL1fdy4hlTVPEg+VzPuN2PrnOJJ4H98
         +QEO6z1B0bT9j688xT346DbTkNHCbp/u/OecCohb76bo5ezidD6gXJ2c0Ve+KA+3eTSA
         IdcYv4l9S07Sb65anSC2KPK9ZsDRYq1Q4ZKNWAMBcvTjzf5yyKkEGFsiyvA0AVIC7ku4
         RLvbLWgCaWuWIQ1Sk+8Ccfe8ie/rKZ/See3IBLF//JS3axeTY7c1a/vQXQCXhFV8farn
         KSfWxWf7kXu3X6jeIrmEfh901EJtMM4JoHixdwDCcGuV4AcZlXhc+tEMpsBgl/d8l+Wj
         r+gw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757482412; x=1758087212; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=fx3sfYexHMpJ12pnBauoZq47+feY7Uao8KwZAdh5BtU=;
        b=PBNjdMHJeR6oDSMBvf9MVIVnV1jTPI7YDCIxuI+YxYvdHKg0zJ6G8GMdshI0g/dJPv
         VSCnMx0fgWmX+vYze+a2hU0XVUnCHsKKhjgAmPFWFYK3sW1QPX57SkNvS4SCy4pytNJM
         ThTgGPpv8VX1XkwdVczJtVFUWqMee3+p6nasc12KXLxRdjmRQihNhYmMgylo9fbYaptr
         RlN2E72VsKI9onGRXnasd84PQ/6eHoummwxq5eariJwhiZKpoyuEjOrYj796aFu18q85
         24jBSpFGFkMfFb0YnzUWQJTEcbIeJjCZ1/CA2CAqvj1mot/AiH5mwQ88gKaCI0hO+qhn
         AvCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757482412; x=1758087212;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fx3sfYexHMpJ12pnBauoZq47+feY7Uao8KwZAdh5BtU=;
        b=pVpDgFT1uM1dkrTYjrXgTzMR5eyeidWsOv6PmzQTGDRwNW/BoVghuajFdNKJuvXfKt
         y5FMQEcVmtAxG6p9JXwRvW+2Hp0GzELDJpdaXdSgh/4SnmmkmEjTVaxEUZsv/FRsa49f
         9FIW9gmiWzyYRUAFEPsI40gGEM6ILkZmagcM6UKiG2T6a5rOl53X56z7mKnFnbDKtdsS
         rPVvh0SIvN0OirCC2btfNQ61o0y2GWXJXIptDniP3jHpo6qNNlMoeb0KX4osVKfyZEgo
         LrwWeQclr74CrBKlXlC+UmRFm1/ZrfysmGGPyBi9533BQN9NWM7wmkm6lY/3OtviFI+x
         981w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdZxZqCdH3aHDi2h7FhM8gEmiy3bkBk+2eZJuGV6AhoqsESDVBphDZgF3FlxdWZY4gBMacDA==@lfdr.de
X-Gm-Message-State: AOJu0YxoDz9nvULG0y0OzV050ABc9qNU64EZZtJnaxFOR350CYP3UWUd
	84Rxi4YkMJa842IAt4DmEwch2SiqC5vVhZJMSXirqhRLdpw1kJ8iIot5
X-Google-Smtp-Source: AGHT+IGcInWKiqvQaQcwwukISZ5S/gM5/BFwLEQOoeyBvQuRtYOaB2GgHK8E0L3JpeBUvt9dIkL7XA==
X-Received: by 2002:a17:903:230a:b0:24f:30dc:d3fe with SMTP id d9443c01a7336-25170e428f3mr198191415ad.29.1757482412018;
        Tue, 09 Sep 2025 22:33:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6eptip30FeZtx5mT+rZkoZuHIfvDr2vbITCeHuRxH23g==
Received: by 2002:a17:902:c455:b0:246:3293:4e0a with SMTP id
 d9443c01a7336-24d53d219a4ls40272345ad.2.-pod-prod-09-us; Tue, 09 Sep 2025
 22:33:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuRrHi8P6PGKxai9dM4/hvMy6yIoHa3Rf5u2sl+/XE0gEs2W7BswqIeq003k/10X2kX1OUI+OBRW4=@googlegroups.com
X-Received: by 2002:a17:903:228f:b0:24b:4a9a:7038 with SMTP id d9443c01a7336-258d44d7145mr58596945ad.61.1757482409764;
        Tue, 09 Sep 2025 22:33:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757482409; cv=none;
        d=google.com; s=arc-20240605;
        b=kZFrlvGtMjvwzMrYFAwwigEwDYrjmqZuswmRYQ3g0kLj4/7F6fMfhmNGgIl4/g/IDg
         JLDlZDPlLZtyLn4zdpKMMpav49Jteyts2NOaTl1qPthzDvF/aPlyvMMh6PBiWU6uDLre
         Z3Ul8pc/J7phhGECW+z+CaLzt9HgFRcaWdEtuI96EHl8l2mWQCGfTdKBZcsEjablZQjW
         E1+A0WPVm8h13Yq3jQr5Zel6QC+qwLDXWBZDfKbJzXFSpwIS2AvMy3doFTRP9fD23Ixf
         7bTbiEX0HUL6EygenteHbG6dECCB6bx0/IBqPqwKXz3JkpkAiXdeBsFvR8tGUypsk9Ky
         /i6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nFJjjziwY/SMZUE7K7JOobhYkWwkFReGMU9dNIU9Js8=;
        fh=sWl8IVy0X11ssy7lA5wuokjGJy+3PGyRnFq26iTMIFI=;
        b=QtC6uwmzLtrdOrT1V3UGlZY9+j8nxMGl0dUfQwtIw+UZkVKS/iQ4d3ivAx6/akYRPd
         2ubl55Y814DYq++itZ8koivhnHSYfPxR0UaJH834EXbz6FIXR3CX4Mtm2NFsnyyOSJkj
         hPLUlbE/qsS/BUD/0ZcQUWb4qAZsuLTJfZHD/xr4PyfgKdbdajJpNfhGOd+cI8tTPaAQ
         swBBR63nenR9N8oQ8M/mGnasHIbSjRqMijiLb88I9xDRDGiL4CPJv2UoHcd7Pohp0HrT
         mOXAyD2n1O5CDZhcpC1/lEq/SquKe7LVEva8sbfCnEx51cOzZNycYAnAOrJ3dTMNjby9
         4abw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eS6zsU0e;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-24cb28c3131si7321015ad.2.2025.09.09.22.33.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:33:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id d2e1a72fcca58-77251d7cca6so5398503b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:33:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU7kDUGiJ+R1LegwW3D374+PSO3TPABjekZ1VqZo1jGdBDN8UFC6OSSFhZT84/vJMnNwNjBF4Ih9H4=@googlegroups.com
X-Gm-Gg: ASbGncsxYDJ8Z9FLvgJbrJwucdZG6BWYhSwr9UxwU3LLscAgnhcs2faVCVclJveor+X
	mkXVpLmvlcI9vC0tBqh3W03r4MPNuy2KwDvganNKGkgSKVMiCfmCebiwIixGh+vAJ94c9ZKcTz9
	Myttz0HxQVXDtUzOrefIlcf1y3j3wvRDKqq15NH4zKPHkTXrzX6K203FZzKwXld9oBW+pN7yxsu
	XAB2fQ0dlGNBQVZAJXSWCCEgxhIg6pYx3AHI1BvjIhiGgyQ3zx565pO18+21LmjGJO0ULIEr9Ig
	XopW14MtAvUQ1RiXWRkS/dJmLoZKPWn2E+Ve3QYZIqVb3hy0ffjgrfaZSAoCwvGlaC+i8gbtzqj
	65wkYUcYLecbaIADI999Mz517SlHRVQA4NnVNalkKiBwfnxcZHvXS3KLfXdeV
X-Received: by 2002:a05:6a00:3c8a:b0:772:4d52:ce5a with SMTP id d2e1a72fcca58-7742de4244cmr15474546b3a.26.1757482409245;
        Tue, 09 Sep 2025 22:33:29 -0700 (PDT)
Received: from localhost.localdomain ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7746628ffbesm3870342b3a.66.2025.09.09.22.33.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:33:28 -0700 (PDT)
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
Subject: [PATCH v3 16/19] mm/ksw: add silent corruption test case
Date: Wed, 10 Sep 2025 13:31:14 +0800
Message-ID: <20250910053147.1152253-8-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910053147.1152253-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <20250910053147.1152253-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eS6zsU0e;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Introduce a new test scenario to simulate silent stack corruption:

- silent_corruption_buggy():
  exposes a local variable address globally without resetting it.
- silent_corruption_unwitting():
  reads the exposed pointer and modifies the memory, simulating a routine
  that unknowingly writes to another stack frame.
- silent_corruption_victim():
  demonstrates the effect of silent corruption on unrelated local variables.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 93 ++++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 92 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index ab1a3f92b5e8..b10465381089 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -20,6 +20,9 @@ static struct proc_dir_entry *test_proc;
 #define BUFFER_SIZE 4
 #define MAX_DEPTH 6
 
+/* global variables for Silent corruption test */
+static u64 *g_corrupt_ptr;
+
 /*
  * Test Case 0: Write to the canary position directly (Canary Test)
  * use a u64 buffer array to ensure the canary will be placed
@@ -61,6 +64,89 @@ static void canary_test_overflow(void)
 	pr_info("canary overflow test completed\n");
 }
 
+static void do_something(int min_ms, int max_ms)
+{
+	u32 rand;
+
+	get_random_bytes(&rand, sizeof(rand));
+	rand = min_ms + rand % (max_ms - min_ms + 1);
+	msleep(rand);
+}
+
+static void silent_corruption_buggy(int i)
+{
+	u64 local_var;
+
+	pr_info("starting %s\n", __func__);
+
+	pr_info("%s %d local_var addr: 0x%lx\n", __func__, i,
+		(unsigned long)&local_var);
+	WRITE_ONCE(g_corrupt_ptr, &local_var);
+	do_something(0, 300);
+	//buggy: return without resetting g_corrupt_ptr
+}
+
+static int silent_corruption_unwitting(void *data)
+{
+	u64 *local_ptr;
+
+	pr_debug("starting %s\n", __func__);
+
+	do {
+		local_ptr = READ_ONCE(g_corrupt_ptr);
+		do_something(0, 300);
+	} while (!local_ptr);
+
+	local_ptr[0] = 0;
+
+	return 0;
+}
+
+static void silent_corruption_victim(int i)
+{
+	u64 local_var;
+
+	pr_debug("starting %s %dth\n", __func__, i);
+
+	/* local_var random in [0xff0000, 0x100ffff] */
+	get_random_bytes(&local_var, sizeof(local_var));
+	local_var = 0xff0000 + local_var & 0xffff;
+
+	pr_debug("%s local_var addr: 0x%lx\n", __func__,
+		 (unsigned long)&local_var);
+
+	do_something(0, 100);
+
+	if (local_var >= 0xff0000 && local_var <= 0xffffff)
+		pr_info("%s %d happy with 0x%llx\n", __func__, i, local_var);
+	else
+		pr_info("%s %d unhappy with 0x%llx\n", __func__, i, local_var);
+}
+
+/*
+ * Test Case 2: Silent Corruption
+ * buggy() does not protect its local var correctly
+ * unwitting() simply does its intended work
+ * victim() is unaware know what happened
+ */
+static void silent_corruption_test(void)
+{
+	struct task_struct *unwitting;
+
+	pr_info("starting %s\n", __func__);
+	WRITE_ONCE(g_corrupt_ptr, NULL);
+
+	unwitting = kthread_run(silent_corruption_unwitting, NULL, "unwitting");
+	if (IS_ERR(unwitting)) {
+		pr_err("failed to create thread2\n");
+		return;
+	}
+
+	silent_corruption_buggy(0);
+	for (int i = 0; i < 10; i++)
+		silent_corruption_victim(i);
+}
+
 static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			       size_t count, loff_t *pos)
 {
@@ -88,6 +174,10 @@ static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			pr_info("triggering canary overflow test\n");
 			canary_test_overflow();
 			break;
+		case 2:
+			pr_info("triggering silent corruption test\n");
+			silent_corruption_test();
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -108,7 +198,8 @@ static ssize_t test_proc_read(struct file *file, char __user *buffer,
 		"==================================\n"
 		"Usage:\n"
 		"  echo 'test0' > /proc/kstackwatch_test  - Canary write test\n"
-		"  echo 'test1' > /proc/kstackwatch_test  - Canary overflow test\n";
+		"  echo 'test1' > /proc/kstackwatch_test  - Canary overflow test\n"
+		"  echo 'test2' > /proc/kstackwatch_test  - Silent corruption test\n";
 
 	return simple_read_from_buffer(buffer, count, pos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910053147.1152253-8-wangjinchao600%40gmail.com.
