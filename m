Return-Path: <kasan-dev+bncBD53XBUFWQDBBMNJZDEAMGQETIPZTEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 44855C47FB3
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:07 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-433689014fesf23574175ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792626; cv=pass;
        d=google.com; s=arc-20240605;
        b=NjhalzHbcDKI5Q6cOty2jacK/a74elUqLe7flP1xQ9ZR1l3usEAkX4dbAPFbzOP5A7
         7mhh3lyVobiPSHKUvt/YkaTbQm4y/g0Bfoe68TlGz4oG2x1Khjoh/7wLPTPM0PcW3Wqr
         JaWS7uwT4MZdJNYtvsynj4GoHVV1wR91pWQRbsDxesUhhOp0fTITo3c/P2ZsLYUkSmJx
         nzvzfMD2TqivK97zb5jMEvfsvoTFm1MRhc0cM+jK90tTLqPJEmD4QkDJh070UYjDfOhw
         1j5ngoc+mMAEMpM6VD9k0FUUUDoHQaoNENrpm7v6m9NJNoyGrNi3QpilKRgDv/AY2Xd6
         xKLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=loex+D2rzSKXmh0Eyaofoaxf5pREgws8XPHioeuQ5YE=;
        fh=UJhoxqWUaL1IzzJN0ddeJpKLo70WqWELORKvqrSxr84=;
        b=SB6cAHE3p988szhZNOGbS0O+s/xYiTfRIrez849oXTP5dkkcD0m1uTO47FPKy4uMnD
         63r3dJSGORI1uVrmnvjkXV0jRTxca7y8T/a9Xk7cM6kEuTTcGNR9TSIhX36GIBMlR22R
         CV8b/Ex5HmqBPCGz8u580I34AsRx5C0+qZ3XPHEYpC+U4D8w1VFSzR7IrEdT3HFBnRGh
         EwIICR6TuQc2g0fqhhgVylhjLd0cRLOH3ZjVm9TZdJ+JW9D+uMro54iFnk+agOfvoAJb
         z833xB7ewPtFcOHT/J9u7dcc/fZRPDM08haO5oZRHQuUewPHEpnwe4SsYAsa+/S46rFI
         z5Zg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ti2MKj2p;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792626; x=1763397426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=loex+D2rzSKXmh0Eyaofoaxf5pREgws8XPHioeuQ5YE=;
        b=XjIG9rVgau2BBOjWXjJzux1Vnkc4opSwr6wK43/hEkxdEpojTEkS9g/jTa2XGEy0WT
         208S1X5m2NVNpC/cN+q8JghbUoE2Sw2gWWlk52LLKxueOAdt/xidb3qA3fTdJPwrhkym
         h6nwYauBKXes5er8oJaBBKZms935AnS0wPdxaIFe8kJ18KhcHWPhURLcVIXrk5eTbNSn
         5P3yaR9OY+97DrWUKS70pLeevJ8gLWS+fmC6ilRX884lvxLKQcs9w4fJN7DyKWelHRAZ
         uXofdVDBT1O6glOlrbv6l7J7Rm2bYktVehLNnU9PmabTnGMQc910snmMO/to6kbdHpJv
         ChxA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792626; x=1763397426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=loex+D2rzSKXmh0Eyaofoaxf5pREgws8XPHioeuQ5YE=;
        b=hDh8hVVcbXlojFYRW8dTliEQtD+fMYrNdByqQ42h4Nd1ruD+Y1muZhITwL4rhP8aq9
         GNz2SU+VqLuiVVCaeQvm/RxR0iYmkC5QZvP/A1BLCF8vkL4KHmgWxfK0d0GIcEIvUdF9
         EkXo44R1In+S4agLTOLNET/dauA61xeiJM3NRqED+EFWN9nw5VuByezkxUqsSbIw9fYI
         Mylrxc5zNO8BN2Htrn209Mvj3ufBxsM1MogYixnioudTkyZjnPEo4zTpum2YKd0nwg+j
         6RHhjlwnHN991v27w/TtvvxdyDK6JtZEuDq2Ov4cmz8Yya9lNnd3a2ov/HZ4XqzVFIIq
         zgJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792626; x=1763397426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=loex+D2rzSKXmh0Eyaofoaxf5pREgws8XPHioeuQ5YE=;
        b=ChqcNAQClAi3qic2kIux6Q8MZFQg98MsBgZoqsNmgj7LSkm3ptVOL3OFWGSTl3YP65
         GkS8HE1Kz+OiiAbEnhQWU4t6QpyiSZ8xxanUZAX+vuUvYLAtvEOibaikKsmki2PsfZnz
         gGgoek2pjJqwzEqrFD+s8TP3QH46eCQJetncmXK3TZJhY6ounNU2AyLIoogYRLAptxEU
         13LuisVZOqm6AgtGldVo1VOMUjahz1UrLPJH8JFukhUaPFC5ePUeWER89L4D5XzPvZVg
         0nGGeNDvx1Ebc6XBTQp4tJXV+bPFPDsf7isACkszbdy0DQ/Um566mibxfeMXKDUYL8Op
         gUvQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWYHfb9pVq6AbMDz8MoHZDR2h4QMsTpjbVEtJYlAWcP4qZrFDIoB3utNUXvvAqwNSEcYeZwJA==@lfdr.de
X-Gm-Message-State: AOJu0YylugWyGrCqOAasBuwoFvQXJf0CsOn+dbycQlgUNAl7RS9pUPkO
	Em+lhxpVWiFhav/923fs0BN/FvAL/extmSZKYUt2woDyTM2VZurUKGNH
X-Google-Smtp-Source: AGHT+IGLzDgYuDYSnuiM/f71190mlfZdVDkJOhTzGugZUqT6Jgf5upHoDsXJppNF9ROGku/9JW0PSA==
X-Received: by 2002:a05:6e02:3d82:b0:433:51fd:4cda with SMTP id e9e14a558f8ab-43367e65ca8mr121443525ab.25.1762792625665;
        Mon, 10 Nov 2025 08:37:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZfQDY2B3ru+mgqw7bxXOaKMClobPYvfVQIKpjtoYISGg=="
Received: by 2002:a05:6e02:1648:b0:42f:8af9:6cb0 with SMTP id
 e9e14a558f8ab-4337a9165ecls9875485ab.1.-pod-prod-04-us; Mon, 10 Nov 2025
 08:37:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXRLIxJwbpuZUXrcR6zBeF67WQycRJgmLKNJzCmFw/5mNVUvdlODb8XQ7k1KZLjjLqBDpmBYDVM4go=@googlegroups.com
X-Received: by 2002:a05:6e02:3c85:b0:433:8365:50af with SMTP id e9e14a558f8ab-43383655325mr40737385ab.24.1762792624788;
        Mon, 10 Nov 2025 08:37:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792624; cv=none;
        d=google.com; s=arc-20240605;
        b=echJaitQT4J30Rba25IuGSmaWRJpLGCa3jJTYgpr6AbtGvg+eP8LcAmG4jKw7LzGIY
         0m2l4hWfwcm5zSppY+68gb/sfEe6aFyP5TGkJNKhkxqw5CO6/SmInvNWWuWcYjyF3Z9f
         cYhEJaT+8ctaBlDvv/JVR+6Ct2JVzPhyNz0PPvVowZpr9LHI2p+qGL0OgluRp6dK13z2
         3IYMwnjGJjj5ABlz05WJEtv/kJ8Oik3s+aXbX2WVYQ/Qfhh6+mZnjYJ16Q8rIvxDqT5r
         1O81rE5THScLQk4GgC/zQG3E/j9Rzi0+0eP7etQbAvKy+i4NvMti1EQA53zpZT9Z9dSI
         DGIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=ouGNoGCEWNf78k//tY5pOloDk6SH5B0un9nqZ5MFRzI=;
        fh=0jHkaH0ms8l2y/jLkV1u/z6Zez6gxO1yFimZmb9TlTc=;
        b=EuVw7Jh9eDLJIv4gWrv8Ql8JEXj2c+9W/ZKFIUKkrEivqT0K0Lny2aRL03BA1MCNzi
         08nfTtI+ocoqZ16KQAHBBE4fJY+6QYrmC0wTlrPxieNYtQdIh0FDqXxZn6XEMRoytF0H
         +6gsSy8NSUd6jCgA/T3rSpbBHkts5v/ibMtd01vR9yGl/f0jr0bv0S6/RtN8My3Uduk3
         ZfODD/6LujKFeH2tC1LYVAn7pd/mivXS1W2oDd2Ejp4CHBd94X3W3/coCeUf/k6y3tJ6
         Y14lVJCX8z0bS22gQBTjkFsR7hT55m9RRv+WrzHjrEXSM5tW0PwbqOZg7yzLPHKJqGkw
         A9rQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ti2MKj2p;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4334f4c20e8si4796295ab.4.2025.11.10.08.37.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:04 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-29806bd47b5so8841995ad.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUnXtTVDYz6w+HUT+9tSi1UWHHSaHqHcuTNlZkELd9znsVlL55V/GHX20L4P3iCxHSWLlZt+MOjvxI=@googlegroups.com
X-Gm-Gg: ASbGncuf2ekWVca+VmhCN+4+YQLgIHh3L2vA5CDSHu9eWiTpZqiXgDnoZMGkN+IKj3I
	DwuAa0bUDFdgdcljRW7JHT3wFnj6qY26HwXor/CD34TpU6uFO6i0o/lYVq+11WJG6b+8xEy774K
	WDprMuuWhsgjMyT6i+QKArDFNm0ASdUqaZEx4+Ow4CYOPsRQgz8orqtGQwrxBPWvkGAc+Z3Y3DF
	Hx5J/xgr1hv5OqWEX5RGJf7us+uAzjS+TthX7wFxB+LwJjHBTzC1zAyWadyiKzDMhdFEVnA2/eE
	lurbCX5Yj0XkzfnenQrAJIP6jKxmSgU24u91jjgOwXPCRTfDZ4qjGjT7Yy5JAxsVxWFz2h7c+h5
	y+7IFj1HX6n8BdiJ9NW+m0gLiCqLnZhiNbzCMy2eYgxN3YFj4Gzqf1b6V2grG9h8n/GHRosEtIw
	kLCqBOgsrdLH6kEr0oLdL3eQ==
X-Received: by 2002:a17:902:ecc6:b0:294:f1fa:9097 with SMTP id d9443c01a7336-297e56d621cmr108081745ad.34.1762792623885;
        Mon, 10 Nov 2025 08:37:03 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-297df996d31sm88101695ad.13.2025.11.10.08.37.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:03 -0800 (PST)
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
Subject: [PATCH v8 05/27] mm/ksw: add ksw_config struct and parser
Date: Tue, 11 Nov 2025 00:36:00 +0800
Message-ID: <20251110163634.3686676-6-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Ti2MKj2p;       spf=pass
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
 include/linux/kstackwatch.h |  33 +++++++++++
 mm/kstackwatch/kernel.c     | 114 ++++++++++++++++++++++++++++++++++++
 2 files changed, 147 insertions(+)

diff --git a/include/linux/kstackwatch.h b/include/linux/kstackwatch.h
index 0273ef478a26..dd00c4c8922e 100644
--- a/include/linux/kstackwatch.h
+++ b/include/linux/kstackwatch.h
@@ -2,4 +2,37 @@
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
+	/* search canary as watch target automatically */
+	u16 auto_canary;
+
+	/* panic on watchpoint hit */
+	u16 panic_hit;
+
+	/* save to show */
+	char *user_input;
+};
+
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 78f1d019225f..50104e78cf3d 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -1,16 +1,130 @@
 // SPDX-License-Identifier: GPL-2.0
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <linux/kstackwatch.h>
+#include <linux/kstrtox.h>
+#include <linux/slab.h>
 #include <linux/module.h>
+#include <linux/string.h>
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
+	PMAP(auto_canary, ac, false),
+	PMAP(panic_hit,   ph, false),
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
+	if (!config->func_name) {
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
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-6-wangjinchao600%40gmail.com.
