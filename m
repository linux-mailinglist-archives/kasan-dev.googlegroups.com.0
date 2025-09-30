Return-Path: <kasan-dev+bncBD53XBUFWQDBBZEI5XDAMGQEZ4ONVUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id D2312BAB0F6
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:57 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-43f5a4c494bsf3108190b6e.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200356; cv=pass;
        d=google.com; s=arc-20240605;
        b=SzVGc7F5IEW0CpKyok6SuVd5JTEoahuLdYtOPJkoC1gDjj3WJgkXLgQfHdXoxlGCBE
         Pwly5gCA7Q7zkIy+xNxtq+UV3aSj/MUzSM3BsVg3+nAi+Q+55t481TBSKADwuwOIRTMe
         ukFTJ8Y2Y1jWMMuQ3g2AHyXkdkhgsNPungv1y4SAtpy1XWaWgRA5ct1To29uHGNi5CXJ
         VctUCPkr0dNr3HdvvPMLaMvcCkUAIAtxWMv4ldVS8e4lCywBaYaCO4g24avvIYmxLkyJ
         Tm3FSENcjyU+VzgLtYRDXtDYCTxbojAoaCvu1XgvVnlO9M6QOdIAHYFUzQsObBe1g0Cf
         nVFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Gw7eUAZygzPa+Sc+w0s98yQNJJE9laKFpipJb43cjNU=;
        fh=Mu2y51G7Kvc9vzDRNDm/n+wekSFYKwOVzKeLSxo2hoY=;
        b=Ngl3U0LgxjwGRWkyZfHLUbQ7OR4S7OpyUtCXdDx8aC495wLMGFLVVBHmPDzUpEfk03
         DxC+WLn3mpMUF4gRYCfrmsAVPsjnGgr0UDjDEsOgcO13mRknceoygp4yiV9DXu+7pddo
         7snojMEvJFwXEQFM5W8xxlD3QsfQvsVt8sSbtrQvBzzYFm7HyPA6JCCkdrI3yCuGg2rk
         DaXWXKH0pXgWI4kK+3psP9pr7OQqUiSivC8B0j3CtzAM3dEpuqXeNWyxh4lq4jnHg/vH
         hVuDXWnJmcYBkAVJdkdgzEFwIQOA5H5VWH6f88QmAxhOSweAE/Vc4sOzSsSi96pGFYSi
         KCoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=d1+GLd9w;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200356; x=1759805156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Gw7eUAZygzPa+Sc+w0s98yQNJJE9laKFpipJb43cjNU=;
        b=YUlFAGfiZJEu4F5BmfVD58qb5aWDTP16OhGTsjsvRAP1kx1qBqhWoN2reVGmJ4GkpL
         9wZOAV1Kzq+HnZiWXvMKywnbzi9rQGD+tkKBDhKqtFzXoNqqKqgnFvDEd+iGOVz4LaIC
         VV4qSYzhLU4TsTEhYksDqFKH04ae6Uq6rtXkXOm+xgScN57/atjsIsBiA94aTNrqUiCS
         B27Rx+pXQYmKMUpkrcTCKx9Ou7VfitysTKj9ACMSveV2+ahid01Pwz4cUjes3wu23fZo
         URDeSFIxr1AKJkxMi5LhcjtiuNQsufvR9+RpYwN/ByA2V4oq9UiobSLsVKMD2i8/b+us
         vJWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200356; x=1759805156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Gw7eUAZygzPa+Sc+w0s98yQNJJE9laKFpipJb43cjNU=;
        b=IZmO484PzTRY+0aziS35fodlnaXVWEohgzL7Vg+spqEtMs/X71l+LQ5N1nmsiz+xmu
         02P/q6qKOsS8adD58468fBrVYI1t9U/RLtLn7R7KDnSREIl2zUBmXcHuqUQxiSct4V0I
         ZO+bTTctJkwbCpSaWlErsS/JMZrUB+/f6dGtM9e19HC5d60HaWzo4kJEihgNquy872vS
         gD90liqTcITe+30c4tmcKhe/20t/FE5vtmRoZZ8oIAButCWnFJJWoKNwV8Uctnc2NABo
         DcW6xyOJQT9g5H4s5zG3GLQcwyPgJx5gnPwUmosfwDx+94w5KaEmswTXLnaF4nmCxZCX
         O6Tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200356; x=1759805156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Gw7eUAZygzPa+Sc+w0s98yQNJJE9laKFpipJb43cjNU=;
        b=kBL5/GjZG2r2IzlpDPeqRPAfZhvpD6uj1QzMeKs56nc1Vp251wG68nSrAolpRjVVyJ
         fpTwse3HmcbX6Q1GMmHIqpTcNibY11NE+lG6IE/RM/tLzjHqIzfyw3sZefJolAHBuz6s
         Z40ptDPaoSHGud+FUwnunwhRgYk1vcEho2unBYdjSk0RlIQ2pQSOlk8D4KDXSDZoAsXi
         d4GK40lCMw5ZwvuNRU/JnvakrZJZHHJ8aJjM2SNVigWfY9YtU7AMQ4Xuj9o7riH4oIAk
         BVyRDAAy5FpCqW+Mc5qgvB8N6nUad7HeoFyBG6AUejQYJ/ZJdR5N5+ZuyxplyUZ+DxG7
         +nKg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUDNtJGhNQVBuKEhim7E/uu/7UnTR+vz+MPefsWW8Nd2dUkJPgvB3CkqzqQpqdlBPCybSN0kw==@lfdr.de
X-Gm-Message-State: AOJu0YxEeTMBFbYzMw5b7y5BfZD8BAoVntyC5s86RxS+EyZBaZIgVzT9
	oWRFKs2PuF7y7qcQ3+iE2nsrjcA9UBKXVhtuciUZTyobci477C4ZnHNK
X-Google-Smtp-Source: AGHT+IEt3+Wd6hkh8VGYc4vWUxWKH6Wz65O77GffgbZndB7KvAQuBWUB4Y5ymA0c+e62a1zFXrQLBw==
X-Received: by 2002:a05:6808:1484:b0:43f:60b0:382 with SMTP id 5614622812f47-43f60b0085bmr7521253b6e.40.1759200356448;
        Mon, 29 Sep 2025 19:45:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4C6ZCIxlyQ1x1A1Va3JRjucIdSX+hoOQJkLdOQR1Kziw=="
Received: by 2002:a05:6820:6085:b0:63f:4c9c:31ac with SMTP id
 006d021491bc7-63f4c9c31b2ls1057204eaf.0.-pod-prod-09-us; Mon, 29 Sep 2025
 19:45:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXGfc2oRrD9PhYlqHGCp0g8AualKeynQFvkJdlbvSdu55pwCsdDBiw8BP4XI1Hk6WvaKcw5zrc6J8g=@googlegroups.com
X-Received: by 2002:a05:6830:82da:b0:758:349d:fa87 with SMTP id 46e09a7af769-7a049f29db0mr7718536a34.24.1759200355557;
        Mon, 29 Sep 2025 19:45:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200355; cv=none;
        d=google.com; s=arc-20240605;
        b=G9w3HQ64sqryYsbPp1xuufBLCf7CmfI+7qojmuUkfv6HwvZd1gBEStENdH8Ee0p/Tc
         UWwr4+YVVDDawzd1u4Jb46k91ACOqqV9XtiLK382MoehfVQE4M17OoFI3wjsIziqMyTd
         vPv6InLkaa2Imd2YCErrUnoNCuy1BGezTMkF/MPFtsj6Cd0u9TaxZqq+8WHLPT0R41de
         IuZK0FWrqiGexJPbzlXBqI9UfYVXfLYoBjQqO2qOtDjiG6ogneiTVBfeysq2eJoSls0w
         SUmKBCK6tUgOROcsBB0ja9wOwr0r8wwKPYdusF7ucC2rnPUXt32RgWtYcdfCq8f9ewlk
         QPSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ANupiyfNlS++I01zMHP5Qbsc6Wgfn8wZLgNnwRsiWjA=;
        fh=H4tkWy8nHamOZ3bwTIyE7HZAXKCl0Bx7S0VK3Mlw5Uc=;
        b=CVpQ6Yk2Lw7/U2sqZPWn9IvB+/+MFaaitV6T/bD9iGwhx1Zo0p08O+O45VsTSNFWHz
         RJyvOf+10HmIwfYohyId2pteGeUdiupNnro6SZhAt3jAgszjqKa+nKo7NqlGf4FQ1DB/
         UA20y8iQPKMGml33ugRwbJFT0bWRq+u7GixXpk9VYXNSg7DZ07wuN9F/c9wFkg0F/hXd
         O1HswPh0Kqfoq1j5HTxQ0vJphrwe0oG1KTilKn120/HrV9+mP/H1AWpMKTu4hADVfZQ3
         FlHuoJscwjd/5I1AYYKrjOU+hU2BtQhVL4gRQx8eBRwyR1M9/6FhNvPVTs4cQdbJBY0w
         LezA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=d1+GLd9w;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7a23156a272si542705a34.2.2025.09.29.19.45.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-780292fcf62so4128389b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUGZdH7gqaIuBGhDDvUJ1GsbeTpQokRfXE+h9FsxQpqT3VLV0IuzdQzgT5re99bQwLwKFDncf8uRFU=@googlegroups.com
X-Gm-Gg: ASbGncsvIzEivqK7Glc9lY8nD6YcLs00cmmABAyXrKiWjgREh97NnCPCeBawxSPjqL2
	3F/f16YgIheGlBy6fxC6ZTmU2PV1yLoTtDarwFFkNo/KaIuJQlDmEOF0MbsEgu2nL21rExDXkGu
	4Fxkr5QuE2JytVSp/7LzBKGJb3yngXXQZnWbrmW307K+Y3lNFS3AH+0JUrH3A4HiZzBXOOEkNX9
	qmssEGaZ0QsiE8AC7T9e3I7W7g0Jx9RuNPpVupHRyDSp+vwhCKe1RFMPPD6JI9g/ruRj74NZIjz
	Ir06V6AJv6dvdzh2w3FnebdCutIEFfpybfFY/aXYa8gufZX7kb1pUhWGfqUw0tSfHFqe4Ja8Acf
	bHalOifjJ5xl8ElmCkrCJ2kO9Ab4/4NbJTldB0fGYUgy+qzYQI7ufx9BNyTwCXV4FKa7UtR2aDc
	wq
X-Received: by 2002:a05:6a00:3cd4:b0:781:261b:7524 with SMTP id d2e1a72fcca58-781261b762bmr11615416b3a.14.1759200354649;
        Mon, 29 Sep 2025 19:45:54 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-78102b2ec47sm12565336b3a.50.2025.09.29.19.45.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:54 -0700 (PDT)
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
Subject: [PATCH v6 19/23] mm/ksw: add recursive depth test
Date: Tue, 30 Sep 2025 10:43:40 +0800
Message-ID: <20250930024402.1043776-20-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=d1+GLd9w;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Introduce a test that performs stack writes in recursive calls to exercise
stack watch at a specific recursion depth.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 22 +++++++++++++++++++++-
 1 file changed, 21 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 012692c97a50..203fff4bec92 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -18,6 +18,7 @@
 static struct dentry *test_file;
 
 #define BUFFER_SIZE 32
+#define MAX_DEPTH 6
 
 static void test_watch_fire(void)
 {
@@ -46,6 +47,21 @@ static void test_canary_overflow(void)
 	pr_info("exit of %s\n", __func__);
 }
 
+static void test_recursive_depth(int depth)
+{
+	u64 buffer[BUFFER_SIZE];
+
+	pr_info("entry of %s depth:%d\n", __func__, depth);
+
+	if (depth < MAX_DEPTH)
+		test_recursive_depth(depth + 1);
+
+	buffer[0] = depth;
+	barrier_data(buffer);
+
+	pr_info("exit of %s depth:%d\n", __func__, depth);
+}
+
 static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 				size_t count, loff_t *pos)
 {
@@ -71,6 +87,9 @@ static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 		case 1:
 			test_canary_overflow();
 			break;
+		case 2:
+			test_recursive_depth(0);
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -92,7 +111,8 @@ static ssize_t test_dbgfs_read(struct file *file, char __user *buffer,
 		"Usage:\n"
 		"echo test{i} > /sys/kernel/debug/kstackwatch/test\n"
 		" test0 - test watch fire\n"
-		" test1 - test canary overflow\n";
+		" test1 - test canary overflow\n"
+		" test2 - test recursive func\n";
 
 	return simple_read_from_buffer(buffer, count, ppos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-20-wangjinchao600%40gmail.com.
