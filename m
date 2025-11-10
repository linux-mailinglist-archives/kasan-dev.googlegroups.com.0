Return-Path: <kasan-dev+bncBD53XBUFWQDBBC5KZDEAMGQEFNWPBCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id E4E3DC48019
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:38:37 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-340c261fb38sf7444499a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:38:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792716; cv=pass;
        d=google.com; s=arc-20240605;
        b=dmSBpyhnJ5bL30EXlQfjEoty1keMEHoZ8mtaARvCaAABQJNz7ZJ8+KQpt50IWA00fe
         hCiARpuDaRquBdbX4LMVNj3blCRwHTpBbsVeL+7zCEZgstspj6d4JUtvDsrLChJzrF5d
         UBM4N8AagRWuL2snEYsVOLswV7Qzre1o8DfSFJn8HIMW08hhUN5QxUB1mR7A0LQ24OkY
         3qAJVjW2Gm8l4l9T+1CJWegmyV38RvGbO4Rg6g5Vc0SZdxZTjXuqsrLmPT9chECiTkfQ
         L6yhKO0ViqOB5Ls7cnoZQC5pxTzFPkOyhHPNCBq9VClumVLPjmRYhGw9Tsrl8uy8j/7U
         M7AQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=sR61+W1gTo23LmnOQCaU8yUEqfUT5aCF2c02vcNy034=;
        fh=R34LS52Ve6HaFKOghPiddROnEG0q4RrWWXzondijOUM=;
        b=TZWjliS7/QZ5iBii3mbkprbtInHBN5LyUBACPJsClH8Nxhsimz3AQZaLz3bdxAEe1l
         9vnCdLTP7a7XhYMHPTH+At7QX4FmI+QHy6ipGXtJt/6XY7dWaDrddVjQKOnvXZ8UN4JD
         jBIRLclTuOKy4iAp5sVY4ILt5Zy72jtY2cpZrMzGrzvuWdLHFr+RcA7Uu388A0ISDix5
         G3T6ZgwipjxVawWkql1g3Hooz3upx5dahLBLIVaI87w+NiwKlW1CpQiqPYD014bLGHOd
         PKLsXC4em9PmKCYUTxjGr12MqDDh5FNjC27FN8cI1/mh5fMIDgR/tCEj2U40eK9IEdNA
         5/Ig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ii3QN9ph;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792716; x=1763397516; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sR61+W1gTo23LmnOQCaU8yUEqfUT5aCF2c02vcNy034=;
        b=WIM+06buSNVs2wnMEibXM8tzah9ryWiYncSRAzE6pltFIezF+J7Kfy1K9QrFPBLDkF
         h6FV2pdRbFNhen68wLGk4x/YKgh9mWS3bKasMsF3wavoz0Ki0DvZ7wK+FZymMaeWwU4o
         r+QgwsKASh9qaxQWVQlkVpRSY12DVOry4QY2cfd8UM9cZksDeDi11+yX6+PvSHumFR/X
         V5ZbGjE5Jg2gzZxHm4jTPFPQYhSiw9ATup2YT8nCx0Gu7zREdTyjaPbpndalb/ApCWc1
         X0wc6z4GKAHCX8jGo/6a/MCBpQ3SG33C2N7QFRSNkisj7wv6yJllb8q5zeBdDBQEBiI4
         YEdg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792716; x=1763397516; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=sR61+W1gTo23LmnOQCaU8yUEqfUT5aCF2c02vcNy034=;
        b=VS/kP0VOyeAA8RglrXVFDibpm+BRXQI7DqzvzJJ7eVpTUSaE8FpaxYYb7SEDxI2c3A
         cyoqH4VC/H/PgdNCfHW9ct4deHRacm+etppMHB3CfJHr5wzsu/SK3bda89amdRrBQh5+
         TstZgf3IBfx3XEywDnBKY25bDzPRNwb1rbvGrSUpuj1gpRkeu21QR2KKB4auduRUr2l/
         ijCPYpbBeimS++gqjCvtRVUYKbgBgUGTtxioKfj3Vuga2q0tABzi0XmH2lDYoqRtEBI+
         okxG7QGnHpHWWiYACKY2xyirTUqsyvl98c1NokZKR5KPbplYk92E+RBauIGwVnWeIwtf
         XfTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792716; x=1763397516;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sR61+W1gTo23LmnOQCaU8yUEqfUT5aCF2c02vcNy034=;
        b=qD6cSiy9VJyfkqM/W84TCVsM23fmrYFg0uF4EcHBSWgNAQuW/sG1CHtRu5TVMD06Zx
         BEXuHCrmEyYGiMtZJHFwNBEiQ7MMWFRjgn9QOgeKx2IjDN1Zby7RfnOZvF+fjXJBLgP6
         +rZ61664DkVDoVxL6jEoCBJqX5HSPVgzQgKQ6A98fd5pUqyBjfdJW8xavKKG4G5IGv7b
         bteEMNWz9VdLil0WNTa4LGEzTxq+TIZ2WDGOVOliGjAOgDCq/HuYGbkVJVk2yD0MJkBk
         9k6v9dUQdaCmk1qjMyK+CXpRhRqh2flsIJ7+uiBAuOKXLlmWMoNxe+Upx4oXcIgI60aZ
         dxOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVUWlB5RB5uCTfkJx1ge8OrbEVgFXjZbGnnT5KbsrP2Bn21NKqOL5TNNbDnm00fwe6E0ym3LQ==@lfdr.de
X-Gm-Message-State: AOJu0YwjkBa5WEJB3icmj54uJSBOxPT9AnhzOu+ZQIWz0mMrZvzkazDd
	2SnEl+5oeV9s3MiMWVIn7KAsx584PW8jVxqmc+aNGn61nEbpFBxuYxoj
X-Google-Smtp-Source: AGHT+IEMb0fg5lwpr6rlHkK/o+hk9o9sMDCjflBTWSLdcRF+BhP1QJcTAZjuxlAH+Hk61+kyh5pr1g==
X-Received: by 2002:a17:90b:42:b0:340:cb39:74cd with SMTP id 98e67ed59e1d1-3436cbc3d9fmr10734095a91.32.1762792716189;
        Mon, 10 Nov 2025 08:38:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+autKqRA70+4moL5IwZY5r8vpBTh7N6x0YtUqgiQA9/4A=="
Received: by 2002:a17:90b:4b41:b0:340:fbbb:6661 with SMTP id
 98e67ed59e1d1-341cd1605b7ls7155887a91.0.-pod-prod-01-us; Mon, 10 Nov 2025
 08:38:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXKY0BbXDLcBb+qf5HFQ2RTaLfW2w0/HYj038PbB4HunTCKpG9w55e6Ss9klIWLLNdWzyQ543SfsbQ=@googlegroups.com
X-Received: by 2002:a17:903:19e7:b0:298:2616:c8e2 with SMTP id d9443c01a7336-2982616cb76mr39029035ad.53.1762792714915;
        Mon, 10 Nov 2025 08:38:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792714; cv=none;
        d=google.com; s=arc-20240605;
        b=SPO+Gnqca1yiYrNan7NpUlVRr3W8JjfoqUw6uz8CXR3MYjMfISQz1eOefMsQtPWuuM
         KGOWHQJrcpsQfdQ++vklhEHLuw+oVMtGcYZ9tEhAKZlcwUHdDDFyLewczLHXH8ufZrLk
         aKCcmVngLc8AvC5PrK7XzSLJBrTVMLjiM2HsA6UpHsg7BGpXXFH48RCa0xhhPoUlmKEx
         iznmg8uxWbJwF6SGshlsSbrK3RdmjM7BWfeKPXNMWgctfnJmbgs6HXLVswGq3Uxa9sXB
         4/JxWlV0arEa78U7nMRwMf5ABRPALNCOfBG1y074E5xKumFa3MqSzaJIFDAXiwnho5BN
         7evQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=Y3GxOA64nlDPTJib953n4vjoIghnHFGUI3myXADNt+s=;
        fh=nQfxLxqCc90vRnkJ6r7ToasA7cU1uIKp4x+wdCu2sm8=;
        b=RnHDZ/a+0VmEPvEL8S4sDwQZewUY+hhINo+rR+fVAhqBeS+7fsZiU1jkmhuwAirCXr
         qEhl7B267CxTnVKnIsG2lvrvXjxVY1KtZG98Gk1xfUfISbndRefphY5uuQB/LPsE6GjJ
         iIeLeog3djAqTil57qhbs4sIE0ylnSk+Ts8xRAfpbasKdVIA6+vDaHRnZ0cDpqwV2yb8
         PdgwcjAMC16CH0YICelsmG94jxv/F6aHRc6/M1LMOB6Fu0rPi8bqwsqgLgiJLbnWin9+
         0xiVJQbnvB8J91RQLDNoWQx/KU5CwNDU25kLwhF22omfGPwK1ahPmKdx7Kg81td0qQx/
         Ptbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ii3QN9ph;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-298147dc082si2739515ad.7.2025.11.10.08.38.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:38:34 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-780fc3b181aso2715887b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:38:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUWdoeyIXB0DylWvvEqxlCtGq6b3qb+NtWaxELJPAeI6OMPFYrxnqYCTV6yt42DWntGUMcotPjMsC8=@googlegroups.com
X-Gm-Gg: ASbGnctOskzFUR01ZxW4EJahO9LI8uqP6KfqZpjRxcpD2XIzvf3obPJ1T36yJbtvkoP
	a6IPPybr4DTZOkwAN3ni8RdYZyJMyVa9MQBCJypfCPRcsLW30ZGuST9orwRAKAQPlwzHlUcGK8r
	vTkcuoJqJ5G9RKTfGdIAlfxbXzo8WuPeSBlAEr9rsqG9e4Inws3hqzXQQEL4orXBSvWh2bkyUrt
	5i4mXBv2GQczC5TcDDGZ2WqBZ0tNerFAc2or5IQDbZaMlMR/nCoMQvWv8Jt91Id6DEKhjAhhbT2
	pUcbElgRMlPJNAo6wLcDrke8waPxLazk/CPnjetu0cf6KhyDJRcSu2Hi8p67z9d/U8Fs2AoyLYS
	0sHbku7zKWY65F0ulemVE9B3hvLDLbDeKgl68fqeSkMkKHc19cONifprjpLx7Hij/3qusSmkTKr
	/7KlID1y4pOKu9ggdGpHKtvA==
X-Received: by 2002:a17:902:da4b:b0:295:fc0:5a32 with SMTP id d9443c01a7336-297e53e7aa7mr114885545ad.3.1762792714416;
        Mon, 10 Nov 2025 08:38:34 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2980c51b8c9sm52389295ad.47.2025.11.10.08.38.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:38:33 -0800 (PST)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ben Segall <bsegall@google.com>,
	Bill Wendling <morbo@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	David Kaplan <david.kaplan@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ian Rogers <irogers@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	James Clark <james.clark@linaro.org>,
	Jinchao Wang <wangjinchao600@gmail.com>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juri Lelli <juri.lelli@redhat.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <kees@kernel.org>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	"Liang Kan" <kan.liang@linux.intel.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Mel Gorman <mgorman@suse.de>,
	Michal Hocko <mhocko@suse.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nam Cao <namcao@linutronix.de>,
	Namhyung Kim <namhyung@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Naveen N Rao <naveen@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Rong Xu <xur@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Will Deacon <will@kernel.org>,
	workflows@vger.kernel.org,
	x86@kernel.org
Subject: [PATCH v8 25/27] tools/ksw: add arch-specific test script
Date: Tue, 11 Nov 2025 00:36:20 +0800
Message-ID: <20251110163634.3686676-26-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ii3QN9ph;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add a shell script under tools/kstackwatch to run self-tests such as
canary overflow and recursive depth. The script supports both x86_64
and arm64, selecting parameters automatically based on uname -m.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 tools/kstackwatch/kstackwatch_test.sh | 85 +++++++++++++++++++++++++++
 1 file changed, 85 insertions(+)
 create mode 100755 tools/kstackwatch/kstackwatch_test.sh

diff --git a/tools/kstackwatch/kstackwatch_test.sh b/tools/kstackwatch/kstackwatch_test.sh
new file mode 100755
index 000000000000..6e83397d3213
--- /dev/null
+++ b/tools/kstackwatch/kstackwatch_test.sh
@@ -0,0 +1,85 @@
+#!/bin/bash
+# SPDX-License-Identifier: GPL-2.0
+
+echo "IMPORTANT: Before running, make sure you have updated the config values!"
+
+usage() {
+	echo "Usage: $0 [0-5]"
+	echo "  0  - test watch fire"
+	echo "  1  - test canary overflow"
+	echo "  2  - test recursive depth"
+	echo "  3  - test silent corruption"
+	echo "  4  - test multi-threaded silent corruption"
+	echo "  5  - test multi-threaded overflow"
+}
+
+run_test_x86_64() {
+	local test_num=$1
+	case "$test_num" in
+	0) echo fn=test_watch_fire fo=0x29 ac=1 >/sys/kernel/debug/kstackwatch/config
+	   echo test0 > /sys/kernel/debug/kstackwatch/test
+	   ;;
+	1) echo fn=test_canary_overflow fo=0x14 >/sys/kernel/debug/kstackwatch/config
+	   echo test1 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	2) echo fn=test_recursive_depth fo=0x2f dp=3 wl=8 so=0 >/sys/kernel/debug/kstackwatch/config
+	   echo test2 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	3) echo fn=test_mthread_victim fo=0x4c so=64 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test3 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	4) echo fn=test_mthread_victim fo=0x4c so=64 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test4 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	5) echo fn=test_mthread_buggy fo=0x16 so=0x100 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test5 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	*) usage
+	   exit 1 ;;
+	esac
+	# Reset watch after test
+	echo >/sys/kernel/debug/kstackwatch/config
+}
+
+run_test_arm64() {
+	local test_num=$1
+	case "$test_num" in
+	0) echo fn=test_watch_fire fo=0x50 ac=1 >/sys/kernel/debug/kstackwatch/config
+	   echo test0 > /sys/kernel/debug/kstackwatch/test
+	   ;;
+	1) echo fn=test_canary_overflow fo=0x20 so=264 >/sys/kernel/debug/kstackwatch/config
+	   echo test1 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	2) echo fn=test_recursive_depth fo=0x34 dp=3 wl=8 so=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test2 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	3) echo fn=test_mthread_victim fo=0x6c so=0x48 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test3 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	4) echo fn=test_mthread_victim fo=0x6c so=0x48 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test4 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	5) echo fn=test_mthread_buggy fo=0x20 so=264 >/sys/kernel/debug/kstackwatch/config
+	   echo test5 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	*) usage
+	   exit 1 ;;
+	esac
+	# Reset watch after test
+	echo >/sys/kernel/debug/kstackwatch/config
+}
+
+# Check root and module
+[ "$EUID" -ne 0 ] && echo "Run as root" && exit 1
+for f in /sys/kernel/debug/kstackwatch/config /sys/kernel/debug/kstackwatch/test; do
+	[ ! -f "$f" ] && echo "$f not found" && exit 1
+done
+
+# Run
+[ -z "$1" ] && { usage; exit 0; }
+
+arch=$(uname -m)
+case "$arch" in
+	x86_64|aarch64) run_test_${arch} "$1" ;;
+	*) echo "Unsupported architecture: $arch" && exit 1 ;;
+esac
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-26-wangjinchao600%40gmail.com.
