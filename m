Return-Path: <kasan-dev+bncBD53XBUFWQDBBYVJZDEAMGQEFJUPX3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 13083C47FE6
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:56 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-7b0e73b0eadsf7219555b3a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792674; cv=pass;
        d=google.com; s=arc-20240605;
        b=lnwHW6qAguQomkimbCadqTypJH1iZy0XYjkA2iu/HRSZ1Yo9g5BxQ1yo8rX4+H4Hfk
         84GuBWcGjpNkCJyEgKRgdobxU1OyCGlNW3LEjFIKPl1qQWcMrXDJzQw1rzbSVSqAGXJq
         3Bb1Rtc0dmG2+wz7CSnb61a8mFtO1aeD/l+SFKU6wI0VgYuK37APxOWs99LcAGTaGIEs
         7pQmgLQykZaAEC5lBgNIIeYpmuvRbWPETMH1w3KH4o9jiBXfVWVXXOvuZEWJm4eVqZRh
         QYKY9xbn3lUU9oHVJf/EL9XJ0tb6L1z0iDeXgdz1kMFnYA3bE0i20EuoYL+/xdQhYhf6
         AkOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=NZlYlrC7HilgXgR26AjLlHvUPt8nUwLVTBO5iK8FVNQ=;
        fh=S3r4kwB5d60ZlbCYP4YoxuNawau0fapX8Lnw2MK2Q9Y=;
        b=DLwGR5dnJ3tkH5l6h9svBrYPdlPpXhdnUDMtMed/gymm+mQd3JGIU+NgbZXKXtO40B
         HCnJ8FJ1xJvYW1NEVpihyDcYrMoUPUrT59JFaamaeMVq1CDiS4qrBnKvv15QkhASgo6U
         rjxemklwC3j/o8nTGVqAeBtB35Z2Refve83CMyu7Ew9tHhx/vg1VXWhimO84JaPLR6eA
         vRh48h3Wi2k7IYGQ0tUfMZJ3MMufhRJEPz8x9v/NY9aM90wcYuYGHRXpAB+EbG2FxLZv
         evgynG1XspLz0s6v6ceXT+uLrb0LFctJwYkAMh5aPXW1fvjM+rb36PCQ/vpUh//+aqGh
         YtAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OUtxl8Xv;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792674; x=1763397474; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NZlYlrC7HilgXgR26AjLlHvUPt8nUwLVTBO5iK8FVNQ=;
        b=sG7XL3GIuuW5+EUr+Jbg93Y8pjrnseLpqkEWagqxC7qtQfIaKZS+J587hZMAQfgQGa
         kPNK9TUASb4Q0R59TRP9HgA1Lq7lCUZofsxx5TdVgKYd7qTr6VNs7Wo2dWdjBzIq9MwL
         Q0GXlMglI79YFGqdIMb8Xpv6EdmrfeUFXk7zf0EHrk442+34zstY19HkU79rhcbRvvcY
         z/vWVJk26PQayuz/BumR5YpGG+ay+BzG+MxHqmgems0xMy9wq5d3iFlTCu4kwXeZS2Ua
         CiD5ymX4NDoBs0BF2/pEKL1J88SFQX5wnePLbC9e8e0tK/xCKGhQw5tGOVFpZCyFtEK5
         ZNpw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792674; x=1763397474; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=NZlYlrC7HilgXgR26AjLlHvUPt8nUwLVTBO5iK8FVNQ=;
        b=BvVFGtWLCt+AEWsbBhfcNjOTyBRwrsiwjvBB8St7F9H+kOmj/0Mx0B6uUZ14IFhTNv
         oRX3zBFwarOVVFXvRy/LMnUbhmud+skHIMISAAvOLCSdlYNgelHZeq0w/zkC0Oprhhnx
         UFxf/Z81V611EoqfM0xhyTdpouITckPzZ7IhL+/bnnT3DFOuPTZGCW4DcJ/lFK9DhwsI
         1Izk089t8fqrlaB3hwDd+iQSOOSEEGFZ27gf6kc0UAj80YYGVd0oSw5IaY0weEQdaBHl
         xYWGRh91PdtSgiGWivTxYqH7SNCg6BxiKfZVlWCB+favN4/9wmFN76nqUAQWRD0MsVIR
         p8nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792674; x=1763397474;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NZlYlrC7HilgXgR26AjLlHvUPt8nUwLVTBO5iK8FVNQ=;
        b=N0A1u25dXFk+4ncCfZ/A4nJCh3ahdNwIX8MS2c0VIDS2SAt2sq7Mkkn9VKcOqMjJY8
         7P2uxx5J04L9ouW4Yq+sBG7BPISHLT5ywS8hdDPfqjAEd+fq6nGIFWQg6R7fZH69ez6D
         JejS+7vmZpqavnpaUjrRNU2hSpZfBL0yDbHk5/eb409QZvmDWa0DYLdw6peCv/QPUuJI
         4lz7YM+uD5H2hZEJGaFUpajYJiSHGGeV86G7epdE187HkPqL4PRLsMaz50fNrnKrQcA1
         3tjGBc4ZrWJzmWo6BEVj4+rjtlgLHsCSlyQWTppZmEcib1SyX+HyPtV6dNtHjhyVr1vm
         Phbg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVoS/5ianiGD0lyt5z+AHOwrLqDrxZ5P0spGlNVY8FAwYcKJBKrlzJsT0XHGdmSgO1vUWB2g==@lfdr.de
X-Gm-Message-State: AOJu0YwcW64G14BkQ3NhV2x48RvLt/tNRgJBzunMubIajJFDpO61e+QB
	VkNxz4iQRzGpi1Dq199yZ626iA1+8SNf4KxKaSYXcOd5wBg8Uw4dZIAv
X-Google-Smtp-Source: AGHT+IFoA/awbCGlJsc12JnsphG9W8q6myLlWTqXwQ+zL+zEODRyruwH9dwOUcKQ/jTVbXGypGXWOQ==
X-Received: by 2002:a05:6a00:1a91:b0:7ae:8821:96c3 with SMTP id d2e1a72fcca58-7b227591ed1mr11172070b3a.32.1762792674416;
        Mon, 10 Nov 2025 08:37:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a2CceJe0AFQxCEJt3iL2N91OFcvZ5JtO6+4G8+RoOIhg=="
Received: by 2002:a05:6a00:7701:b0:77f:19a2:eb01 with SMTP id
 d2e1a72fcca58-7af7d3e708bls4523440b3a.2.-pod-prod-08-us; Mon, 10 Nov 2025
 08:37:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXkg3gaHCCH7v5YWxpRznNHYYJrb9HKcA8NvJIXjxl51ekIOpqTPtEj5aomE+/cy1uYO7dTw7uB/5Q=@googlegroups.com
X-Received: by 2002:a05:6a00:3cc5:b0:7ab:995a:46c7 with SMTP id d2e1a72fcca58-7b225ad6f57mr10856835b3a.1.1762792673076;
        Mon, 10 Nov 2025 08:37:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792673; cv=none;
        d=google.com; s=arc-20240605;
        b=MFybWYcfQxy4F1T8n7sDphJInHr4KcP4R6o4t7lvc7yPRgFyITCRbiSQnlkiVeTrPl
         O7Ru+QehVA/Wf2oeeXYjxY5FO4m3x6c1YhgUTUgkGgVlYU+HyMuQXkZzz965B3hZSBd9
         b3wcaiXzcRHClQP0iyPPQo32lGe+IKKoRJ5yI8lFO7fe7ZHXMNtg91QrMFUpTnWyrzEc
         rShuWSz0gkSnJnaoxI9LAbKiDRMOLG80k0zU0IFDUckb8prOZ98GDcEd4rkzg49sQl/R
         bMWPuMLYZSoYIN3AZg95KZynGN0KBVawXMMK/x7mCIUxnG+P9VkszoCdF9/y9ufrBtzG
         Yj7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=Z475VFvVTEIt4JwZ3YGODDVB/J4Mi7oiMRjRIDfUacs=;
        fh=2T5DlYe3msSGyMm+wJ37GH2NNlAnSyBqLUKwMdboWoM=;
        b=E1SdAcHugxihlOj2k2abhHNwUUhKOkAEcbFX3M8veFELLCl5tofMfzx52dAlqiLL8I
         c9ZTa1apLltNdNhQ5iKYRiS9hJFZ3+a/mEK5RvKmmhm++5Ef60AMsOY0Wdm2phlHKDP8
         QRoadkiKpnO7OWeCNYqP7hjH0bt25oDe2m37/8mUKvw9c+ucs0NpnRDMfyotQqKZgOa1
         /IVgjv5FtcNOahqC3jX3IadVixsOWhwjaJBfsx8RsCFtwA5t6vrtFHOwey0nq7c0qJIO
         vcYFz138W2JTAQvz5xX7StJjKCbA/ogy11wXwI0CHr3drVYTg6k4dD7AazlhfRTeOnXH
         Eo2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OUtxl8Xv;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7b0cb3a3883si294661b3a.3.2025.11.10.08.37.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:53 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-3436a97f092so2885549a91.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:53 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWM1zZAujp5K6qV8y3NUpV+xvNB8A9S+NtdQVFf1SydAKtzQ4kSVTyHq1IQZzzHIGqX5/0stetP43E=@googlegroups.com
X-Gm-Gg: ASbGnctZq+yk1C05KaCpNPbIDF24S4taeB9hCHgNggeZFvjZEQD1wHvS/4TjKiLed9/
	tgN3BhaSMwsoKKm8KDrwUHds6JDWh6QylCvf6EERQU3ZOn+gVlWp4AiVg6OrPmaHdgxKvsJBkto
	1A0y4O3IU1dA7P9zaIb4MzIhtFhJnWgxzUwT5BmWj7HFY+DfBOfG70Bp32V6dXIsLqMMgnqo7LE
	+Td2hh2q1TWeL/hIlvajYcGeppPfzz9PW3GjTejBKIGhnbPvcxGVA4cW96acrw9Jm8xEdSTku2g
	z5+IDJ6ml9dD228G2KK4u+qp+XUIhIdgaVd+gxVdz9ECZ1WbaFl3XAcxRx0fHeI28Ts8fRcGlbE
	ZZvq+Z8T9WYaNo+q1/vaLQbtaEKxLOEswHWTeGEqoYGyf6Zb7oBdUnLcQzRJKWuiCXWWl2ANbAY
	IiCgIGt9W4GkQ=
X-Received: by 2002:a17:90b:2d0d:b0:341:d326:7354 with SMTP id 98e67ed59e1d1-3436cbda0e8mr11097915a91.37.1762792672604;
        Mon, 10 Nov 2025 08:37:52 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-341a68ad143sm18023453a91.3.2025.11.10.08.37.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:51 -0800 (PST)
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
Subject: [PATCH v8 16/27] mm/ksw: manage probe and HWBP lifecycle via procfs
Date: Tue, 11 Nov 2025 00:36:11 +0800
Message-ID: <20251110163634.3686676-17-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OUtxl8Xv;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
index 87fef139f494..a0e676e60692 100644
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
@@ -119,8 +156,18 @@ static int ksw_parse_config(char *buf, struct ksw_config *config)
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
@@ -135,6 +182,9 @@ static ssize_t ksw_dbgfs_write(struct file *file, const char __user *buffer,
 	if (copy_from_user(input, buffer, count))
 		return -EFAULT;
 
+	if (watching_active)
+		ksw_stop_watching();
+
 	input[count] = '\0';
 	strim(input);
 
@@ -149,6 +199,12 @@ static ssize_t ksw_dbgfs_write(struct file *file, const char __user *buffer,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-17-wangjinchao600%40gmail.com.
