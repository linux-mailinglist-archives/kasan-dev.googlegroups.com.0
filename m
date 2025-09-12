Return-Path: <kasan-dev+bncBD53XBUFWQDBBRHER7DAMGQETAV4JFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 33A9AB548FE
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:27 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-252afdfafe1sf19657065ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672005; cv=pass;
        d=google.com; s=arc-20240605;
        b=YeJU/nf6LIj3JcS+HEItuBF4MNuQJ99LeZv8CEF3ho2pOMU/g52XzHH6Oc6MvlZBa+
         DPtOqH14p1bQ7JwqM0npDwbEweTeqVJ4AjdFkOsA682+U3ZxnUTobvfokvznU659+6HR
         iGMKOWYrEBEtH0bqzxe+UIUI6YcDsBc5vdoLft4g8Sy7cvTFiB1LAWKDKCMbUJ2KQyUw
         liL0O6cd45f6mXtcI9Kg5va8IzjhQkdZ3C1Pj4asvdjT0kbe0gGWck9GxVMgmKgVqsHS
         gafO60eSuCBQPmjW5VgJRqz8vjVoNU9LZ96/hITLNN+0lHuOIevwWRO2zCmgSsYfCEWQ
         zlXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=44GdH/4ZMwDaWFMjnRSWHZtma9HwNlsCCzwXw2je/54=;
        fh=h+PlzBKqsHJN4stXdhrMDbxJiCtOQkQWiYVnvVuURU8=;
        b=dj8kPBvt4fiLxvS0Ujd6F1orcEd4+59vBuKyxizZ6QPzsleLKFMVGhKlXEyfqrBnh1
         M0l00l+6u0AFwmqi9LD1RdIGdrycRJ2dAxRoDlWVTE4k04+A8V1gTj7IkayVNTDCytZl
         L7lJyzVxZWi1fyTdMysJujzDCzZdDiV1VzpwZa+CF9Z0i9ToAFne3WIcvqt1bTAfxufx
         B7Aa0cJv6aCl4zDnqXWx4Y+Fac7x/AiPFLufGCkalFCeSPiEVjBD1rsl0ma+mlatI9hj
         8Dr0pwD7+dL4b9cHx0BhCMllx206X7PGG7y6IZ2zfBNRLPx9kZ9uvNxPhAkcbwwN5dZL
         rpSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=l4lUCHzw;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672005; x=1758276805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=44GdH/4ZMwDaWFMjnRSWHZtma9HwNlsCCzwXw2je/54=;
        b=s5w76dE5Bnux1Uobvqk1h1Oo0RVJ8h76Gt8fV4b4faGa0Mdss97dfq1DyJcvFhkIki
         wNrTl+zPBfkLceOuoavA9naN8jE+rEn6u7M7ve/Dx5sWRkJlntL1lkQ8WquA6bt652Ft
         q4RVMkzSmiYqMTgs0j+gdp0lIgIc7DYvq6XZNdaen/UWanmanFV0af8FRPXoNClgR3E5
         YngZPakdg/ckLcj1EYUy7u4Zzw11+TwRKIFU0O/h4nTteWx9bNjk9HWCUJLHGP0CC9Sw
         Hk2C7Dx9rPCO7TcMir+u/HGx3A+BMspMWUWlIAI+mB3UzGicv4qnlirzsDjZLqvCvNA9
         mRmg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757672005; x=1758276805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=44GdH/4ZMwDaWFMjnRSWHZtma9HwNlsCCzwXw2je/54=;
        b=KV8XfpP8OetWwZ4QaidyVW/xOyBn1c2vTR37RVq2V4d6A5CGOsp+fDBxPe911cQn+v
         Wk/xM4HS+3MQq5lyjoZh/OanXu3fhP3+Rtk77xoSrZbJGqWNVofdcVOdbQ8CqpQC5yvh
         xyjgmagfsFzmI4NG/d7SK92o7nSz8EC4qCU6qMWAYJKG4EzMow3FI4X4nhVmWiEc3FCa
         avQiLSVdEeTWLHhJXcfFY6KtVEmdY3cuLmcKpFI0p+BCelB8+bAPmXaxnlJ2jRsge2Q4
         2TbdatBrsAT+4bRhXXkrmJJQYo2JilPfWxVjhfKfrEp6dV6YuM/NmFLd07ntBpjl4X2S
         NVNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672005; x=1758276805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=44GdH/4ZMwDaWFMjnRSWHZtma9HwNlsCCzwXw2je/54=;
        b=BkocgxA+ZH+yMKsoA3qcZU+p1XYj1pr0zcBKRNicPsQ+q8OfgPN9Lkx1rEOhucl2OP
         9dULEaN3ZS9ITW7/MM8o8O+rBK2l07gYbxkzlDkO41NyC5atl6XIg0fZKoDnZTT4ARdN
         lwMOL9wVJvcnclwt9HVKFM5vKm6R40eekgEHAXRLDlKtu4/YNIgYwpHNZ/KMyq+YtMDX
         1ckVi12j6iXFZt9a8OVeYYPE57UVuJ3GMYctSsV8Gut7XEOpxZRjHuLms9rL10DoND9Y
         GMambxujvp3Vnv2ZndyqngDBKFWiM7wvIYOfnuULQMVeUSfNAe5zV2EfiZxsdHh/2UUa
         l97A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVg6UtptOKnXJGsXC9qt+uLQ90qr1zX09OgLWIAzngwUax391viW3NIv5/H7nZRPqP0/VlX2g==@lfdr.de
X-Gm-Message-State: AOJu0Yxstgvdv+jRTJxsp24XmSTXGgG+pInJuuRe8gCv12Zy6qV1Taqf
	rz1voMvEqhejntigAhlqci8c9lMwiWUyP/BSIBM/uoJqrrONSBxTSkq5
X-Google-Smtp-Source: AGHT+IHmwQ60dGnPxet0yYg2yWHtRs+mAFDC/QIl4qX/DUQn/cK2z7WxrwZxY50KtJF/PhvXBTw9jA==
X-Received: by 2002:a17:902:ce89:b0:252:1d6e:df75 with SMTP id d9443c01a7336-25d2666103amr26747275ad.41.1757672005585;
        Fri, 12 Sep 2025 03:13:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6dKuuOv1grXe1VZzV/XkaeAYvidc/KLMWeAqmuQv6iDA==
Received: by 2002:a17:90b:3849:b0:32d:efd9:d13a with SMTP id
 98e67ed59e1d1-32defd9d2d3ls440079a91.2.-pod-prod-09-us; Fri, 12 Sep 2025
 03:13:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4/Yc5lJ5rTKhMlWKJL34UKiFpCnwpBM/CRfZdp0v0Gzc1Wr4CIdvwVrYfrs7O44UlaqnO1rb29Jo=@googlegroups.com
X-Received: by 2002:a17:90b:3d0f:b0:32d:e6b5:95d1 with SMTP id 98e67ed59e1d1-32de6b5976bmr2459618a91.17.1757672004028;
        Fri, 12 Sep 2025 03:13:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757672004; cv=none;
        d=google.com; s=arc-20240605;
        b=G3bppHmR4ZrMtcxt16WK53y6EQ3Qo3KPX57UacvizlhdpX4wA3jQhwZuoi13YMdMc4
         44r2187LC+wOzX38b1khF22GWUxrNfXHOz7Xa/wfRwHt0okGvbfU6VBkO9wYpot95POB
         X9cG8BHA4E63Mswv/5vKs8l73x9ol9XtR0DVOtWsLp7GNga43IiPFus5tr1RbJ4/3XoR
         YMolQDVQSTy7pGeWasDijdh8DLIYhf7aikWVCDR6CdKNiqSYskuc9GY/48hrRYRxCnL1
         ut2Ntz08RmwbihDb19hNixqmKfnFZv23HnfoWY+gUVj5nl18ET8RdPh2BPsvJyFqrCUv
         j+Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VbQZ2RA/ceP/Xd/vXrNH7xFxG1mfw2BEk3J2LPmN1HA=;
        fh=8Dvy9jFp4G7vjBuMK4AIJpw6I2TdIuxp4FtH0p/8SFA=;
        b=Q7lj8L4/WFvr9/SeYn+L0G93VV14vcmNv0IN3Bda6JJaMfZkqMJwOik3PZanos14IG
         jSx5x8KfNpIr3qmCYM/lLj4hJW5K0VZJSR4jVWiJyq2sGqCc+3PEwp/BneTu3Zz/UY2A
         k8J821f/1zraSI6Q5QM7CXusrItB1StjMyq+qQrtPdhfbEeYtatqBGoVixOaR9ycL71A
         Akm2uXayWdZOP2l7DlQDkds/ZJAIlY1vcz6ThfphS6QSDsAMZZu/h/mSXGnisaioIpzN
         hn52pzKWJ9/oS9O1l0UnC3Pktv3afAtn+jgEwKgA3qpm1a/uFFnRRTJsPeYq6vnaiPtT
         8KNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=l4lUCHzw;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32dd989ac67si60707a91.2.2025.09.12.03.13.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:13:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-32d9086276eso1731070a91.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:13:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVoyWUvH9F2uebG+FRr4ybisdb3sdFgKDJPNS+UIFRd4twdioLJW3swA/0CXJC/4kAKimQFCmLl3Yk=@googlegroups.com
X-Gm-Gg: ASbGncuiQEGr6aqohRyDz9U0YqNr3NZ7o3B9QeaxgPQF7Yu0ZNttcTbJa6RDJT9U+Gm
	9gJSc4F502TPCUEuh8ag2Meb0g8SqFEKdun/pj4ResannrX8g9v5hN64H16oI2Wb+T3xnv5tQe8
	ShSOQpgRzKoY88ZpzozfsmAs5fMNZB3uU4Dm+prCZfn6x5ZxkPIWXiprIe99ZiFO01ZXo3Ncxkv
	/5wkgR6OkvVaZK1KXY1h9fC1yMJ6UeIu4P5gHK1UeEOlvySX15a3tpEld/KC5FlLt90mHM6+jEW
	pens8G1SMO8rRBdbH8D3+FjuS7lZDT0cL9760YvDp6njXd3P3wt6o29lDFSVcF1EJs1MvxcQuLO
	+FabX82rgA25Z7Xi3n5lBEVmWVgVIKaPWKlg=
X-Received: by 2002:a17:90b:2b46:b0:32d:7093:7f6b with SMTP id 98e67ed59e1d1-32de4f96188mr2888054a91.30.1757672003490;
        Fri, 12 Sep 2025 03:13:23 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-32dd98b3ea0sm5091462a91.18.2025.09.12.03.13.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:13:22 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v4 17/21] mm/ksw: add silent corruption test case
Date: Fri, 12 Sep 2025 18:11:27 +0800
Message-ID: <20250912101145.465708-18-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=l4lUCHzw;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
 mm/kstackwatch/test.c | 96 ++++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 95 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index ab1a3f92b5e8..2b196f72ffd7 100644
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
@@ -61,6 +64,92 @@ static void canary_test_overflow(void)
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
+
+	do_something(50, 150);
+	//buggy: return without resetting g_corrupt_ptr
+}
+
+static void silent_corruption_victim(int i)
+{
+	u64 local_var;
+
+	local_var = 0xdeadbeef;
+	pr_info("starting %s %dth\n", __func__, i);
+	pr_info("%s local_var addr: 0x%lx\n", __func__,
+		(unsigned long)&local_var);
+
+	do_something(50, 150);
+
+	if (local_var != 0)
+		pr_info("%s %d happy with 0x%llx\n", __func__, i, local_var);
+	else
+		pr_info("%s %d unhappy with 0x%llx\n", __func__, i, local_var);
+}
+
+static int silent_corruption_unwitting(void *data)
+{
+	u64 *local_ptr;
+
+	pr_info("starting %s\n", __func__);
+
+	do {
+		local_ptr = READ_ONCE(g_corrupt_ptr);
+		do_something(500, 1000);
+	} while (!local_ptr);
+
+	local_ptr[0] = 0;
+
+	return 0;
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
+
+	/*
+	 * An iteration-based bug: The unwitting thread corrupts the victim's
+	 * stack. In a twist of fate, the victim's subsequent repetitions ensure
+	 * the corruption is contained, protecting the caller's stack.
+	 */
+	for (int i = 0; i < 20; i++)
+		silent_corruption_victim(i);
+}
+
 static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			       size_t count, loff_t *pos)
 {
@@ -88,6 +177,10 @@ static ssize_t test_proc_write(struct file *file, const char __user *buffer,
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
@@ -108,7 +201,8 @@ static ssize_t test_proc_read(struct file *file, char __user *buffer,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-18-wangjinchao600%40gmail.com.
