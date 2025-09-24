Return-Path: <kasan-dev+bncBD53XBUFWQDBBYV2Z7DAMGQE6FJD4DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 234FCB99B6E
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:00:37 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-3307af9b595sf4794039a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 05:00:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758715235; cv=pass;
        d=google.com; s=arc-20240605;
        b=kT+aWXV9zoE27aMhHxwcSoWiJgDnoAB6Ui0B58cV+rhP61k5PpRrfJH854ZAsrpSn/
         zDEA7+HveegYKo7ch0CPdLHUR4sg3eMyz3f7sP6mWjYQdP/OEK1wk6/kKkWuYHPCk83W
         lo6n39Lwa0/gRmJX6kLV33psETvouqOYNs+A25G3mbcRKMvdi3msqH9U15V7bAN3/gCa
         XsBAti6Nquo28cKp4iT2/TJG1HQ/xw/uOyaTJ1JMEvjDAT7Ri9lqbS909LzcJ9odsVUV
         H1qbUMy9KdXK5Aynefg6R3OBiyUw+6jxniSSbNM2dIw3JPkE/IqJs1Fk9wXfOG360Pzf
         0jMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=M4InHCDngr7U6IoppX68RMF4Xbc4RqGO1htSM7TDa8Q=;
        fh=Ry4kihXMtBerPl7OD2TCYlbaoSifdSPWbiUh+1y07lE=;
        b=L3U4leUuc6Lw6N35nSws+wFohg7FUtznoOvVfbKhVTtTSIHWHZfdZIQYpCE124l7OZ
         1YWoIAY7lzVGU5T1Q41imcCFnyMLK6AC9A6qvDKOiBAQButAQ0FVwbT57FOUp6eaRkH+
         +gN6hEqX2Hvc+qPq4lTn/1N7PBA+Va9HAEiZQBBvaRwqBGEhVKl6vxE0rZ1l8Uwh+lsF
         beE9TpUJRe7aSlErgARd7JzihqPlYbj+zO1FeY+q/QM+SBTIpc9pR9rd0kcBLlYJZHgZ
         jv6/9YNfG0RAeUFwuL+F0vbIR5dD8vIzTnMpj6KNhVli4wNJxzVO0ucVizD59ccVDY7b
         rlYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VknaxuM3;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758715235; x=1759320035; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M4InHCDngr7U6IoppX68RMF4Xbc4RqGO1htSM7TDa8Q=;
        b=MpzW2T/VTLCjGB3gyhsU+TVZOrzm0cpB1IL1HdCGUKeVokEpPHELGo0tmaLKgJCgvM
         vnTNYSnNCmk0iRf60NLG8FCRjnlCu6XldHIG23+SLbYx8Fx6/svEMWvsoHPOqxsa/feZ
         u1Zx6+f8C21KtC/kL9W9ULV80UWyJQrEJWEt7nAC+nTN3I54zU7eG2doE877g49BCSry
         V/uXQJKodYUmprvWkEZ4atqt3TRZU1mBZlH5lpJewMywoIcU7qZgUq0sFPYSIFt/Fm7p
         Y8DgZeZv7adIRT0hQlj6/tg+bGMpA/o/Afgwz6MRot3yIk7JBk97h5wO5MFPR3ACMQ7b
         k0WA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758715235; x=1759320035; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=M4InHCDngr7U6IoppX68RMF4Xbc4RqGO1htSM7TDa8Q=;
        b=LWrs1bGi+dov0bQjjNkH4aZyii6UL4YNGVmd9t5G5eDknZyqWWNX7a1hdlTNTr9rqB
         +W7vPIuXXY59yXn9uiAm0y7cTOfUwKf6zm3M7lIXCwmrd9k1pPT+lUiGwmBS0osYcGZI
         PNsDYrdjYaODgKF682r2vuAVV2AwmzyrVPcmvlXBzPZs6myl8DEhc5MP1ve4usUEUX6Q
         8m76FocEfzBwmaJoFfA0KPbumX/pCNsQzzGEZilAM3EsqL2OZeBGmljc78u3sTNLLOFf
         a5U7tTL6NlH7JWG5cGPbItb/QUJTg3c4La6SOUBVFMi0Thte03pto0RJWfSbQplab3uT
         S1eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758715235; x=1759320035;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M4InHCDngr7U6IoppX68RMF4Xbc4RqGO1htSM7TDa8Q=;
        b=RJV2GjauXxPoGuFNhyS1f2ddXVkAeM/1HymPMdPTExa3D7VORFIF6WywMvYZWgqVOs
         qBqw/Gm0GEID7MknyAzNU1O60wbT576Kn6pDkuOwhI7HzJxijf7NDQsdlSOTHfRvZAzR
         kRay9MO68CzLReC8SHIfHrEr0DAbIGaIPEZ1sWOuFGvdlY0sCk8oKMerKvg3wGsblKJe
         8ZTLVW728IV4zgUHHk+2o8QEbQmAAOvyUQDaPcQ9z1NjtHe5P8Tzn6Z5GzgYHxFUJ+wd
         sYPVxbj+s6rGMeEPxSeXywxyOcsY8U59KQYcx8EC1NC49jTvhWUtiHwoAIWRF+xh3FVA
         ejiA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXqHi1tA7wvqd43LIEJNWQvdszEe4j0WinDUkOmwfbhPPDNN3bUP8LTpfMMLotraJCQ/9iemg==@lfdr.de
X-Gm-Message-State: AOJu0YxlBTbyDKOiWvKO4YBU3izB7V4SfVVjgxqAYBuAsUoFaEYNXuXS
	x2KiIRgK5EXEUXLfN+kHBI1JaUGItCYPhUKReEtCO5A4V1HAQY8XPVLi
X-Google-Smtp-Source: AGHT+IEAafGqIuIDjvjua58umWlF3LRhJLLJ/WdIrpE87ISUyUwBnOluWKq8KrqS2IDCWZFxxhimBQ==
X-Received: by 2002:a17:90a:f944:b0:32e:87fa:d96a with SMTP id 98e67ed59e1d1-332a95e2926mr7111718a91.26.1758715235328;
        Wed, 24 Sep 2025 05:00:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4PD5ryS+1cPs2vY3Se8gp0jYC1rRbWj/fqpSO3iiLP5A==
Received: by 2002:a17:90b:3a85:b0:32d:f96b:10e5 with SMTP id
 98e67ed59e1d1-3306517631dls7520187a91.1.-pod-prod-02-us; Wed, 24 Sep 2025
 05:00:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXgREJNGFWukSiHCo4MgDl70ob8WYqYk/ekDrDb4B9NPzhba/60tSz81OiG/EsVCKgPscCPMwFRUvo=@googlegroups.com
X-Received: by 2002:a17:90b:38c7:b0:32d:d8de:191e with SMTP id 98e67ed59e1d1-332a94f5841mr6760103a91.10.1758715233823;
        Wed, 24 Sep 2025 05:00:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758715233; cv=none;
        d=google.com; s=arc-20240605;
        b=A7S9Yc7ApkexPANefuJ7leYbW8c/8ZsNLXODU/H6RkTNejJ05YnnIn7hlvNJio1jp2
         I17nl/IMCVPRhc9kufg407GgpEowOPhzP7sAUKSHoqKPnu+xgYsq0FAj0Sv5f2fCexY7
         5Nqe8xQlx9zm6mEMOac/ErPix0p1U7/J3/NSnq+S0dQO/HeHnhK9p/KqG7yynp4wn/jp
         wJI4xrEq0jjA4NhdfiOI2ShH7ZtaJmC+tWyqxm3AsUpUj4vIJ762m/9IESw+E/rbzwqA
         jGyNB4wnwKrD+4rygr9WwUDNjmRaTQdKqdIugJrjfywentgrK1Kw2FaOKbMQ+uDrQhyJ
         Ovig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UG3CF7kwzv6QR3Bvbfu+t4H41didNmIt1FZDrUojazQ=;
        fh=fLxPVWta9YWgaQqGtzJB0eMCY8zwljItt0LQ49Igyxs=;
        b=PTbANDrbRf+1kPIBWZmBi3r266slt3eoKlegZPGDBzf8QkxVEd9WRNMU6aAppLJjbU
         LjE+fLEmAVqgzC+mb+tWYqTLS6gpy0arMgF/WTe7yvWzYvvMBougurmFCrgzoFVfdXyU
         pX6DfQwjAdvD8gUq/nGjEzOwFrYUF5DvNQCOZxqtecv2jvcWY9nvcfOA6EY+64VclhN4
         s3sD27Cw67wlDPCpCbQ07Jb+WtL4rBeTBqMaazZsFC+0eAr5J0w1UpwtX1awQwBaa8f7
         PJ3TqaCgBXwaiI2A7TMD1FM52tqqOkCpLtlZ23asm+pB3K+/Q0fcwgAxpkYWeEE0mzpJ
         eWyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VknaxuM3;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3341bd8966dsi71943a91.3.2025.09.24.05.00.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 05:00:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id d2e1a72fcca58-77f41086c11so2869210b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 05:00:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUPsB/6pVFsug+v7IupJiHi8LMgllrTRT65N/kXGNTo1dxxpEWaGQ9AmkLqMDj8q09uFUorMkOb4Kk=@googlegroups.com
X-Gm-Gg: ASbGncuwb4M0XMhHaVmISp/VNuQpcSogP+0JZUtNCfPkN1+96bs/cPs5NDdkv3TAdLj
	1yOXZZVAaYW4ni2rTdTq7SzStDmc5SW/eaaR1jXS1alZpVNg4lWh770icYZcrbWV6/muRMdA/6P
	ZZxiWaI+HFD5qEayGaAtVrk2ONavQp97iR8GjBb1RaMzkj+dZi1Ihyk6+YgDyyVIzu7vuYM1PHj
	fRnjYEH0tXWUJAt+IcLmDqe7J2xVHABKwhY6sunXnKo44nFkg9A8N+OG5a4azJoKmCe4kMV//iC
	di0nZV6aGeZPKkztIQ2SBlZ1NT7doIn7nfWvjiLsSSmvqb3pSOvmR/nnxQ4s/OhFn8M6WP/CR4R
	qEjmvWV9jVgkAvuvAW8gxoWTSwiB2HO2ONw==
X-Received: by 2002:a17:902:f609:b0:26d:e984:8157 with SMTP id d9443c01a7336-27cc13808fcmr63875775ad.8.1758715233064;
        Wed, 24 Sep 2025 05:00:33 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-269802df57asm190476695ad.67.2025.09.24.05.00.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 05:00:32 -0700 (PDT)
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
Subject: [PATCH v5 19/23] mm/ksw: add recursive depth test
Date: Wed, 24 Sep 2025 19:59:25 +0800
Message-ID: <20250924115931.197077-4-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115931.197077-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115931.197077-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VknaxuM3;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
 mm/kstackwatch/test.c | 20 +++++++++++++++++++-
 1 file changed, 19 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 740e3c11b3ef..08e3d37c4c04 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -57,6 +57,20 @@ static void test_canary_overflow(void)
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
 
 static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			       size_t count, loff_t *pos)
@@ -83,6 +97,9 @@ static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 		case 1:
 			test_canary_overflow();
 			break;
+		case 2:
+			test_recursive_depth(0);
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -103,7 +120,8 @@ static ssize_t test_proc_read(struct file *file, char __user *buffer,
 				    "Usage:\n"
 				    "echo test{i} > /proc/kstackwatch_test\n"
 				    " test0 - test watch fire\n"
-				    " test1 - test canary overflow\n";
+				    " test1 - test canary overflow\n"
+				    " test2 - test recursive func\n";
 
 	return simple_read_from_buffer(buffer, count, pos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115931.197077-4-wangjinchao600%40gmail.com.
