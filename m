Return-Path: <kasan-dev+bncBD53XBUFWQDBB2V2Z7DAMGQESYDRQVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FDFCB99B74
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:00:44 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-61bfe5cccadsf1243817eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 05:00:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758715243; cv=pass;
        d=google.com; s=arc-20240605;
        b=eHaTLc+qcyucUzTBcU5XQV7ysiVYBnEwTy6psg6YyqXiDcCoQ/QGrRXBk7mmoNvqyT
         b/fe3T63+bSUeQ0VDW2vrPYaX5+5XqvjuB/SJyEGaQgaYkQmZvJDXoVfnB8Q+S8Ll2MV
         1uYv3bXPG9bv/NCysxQiZtI7n0AIKbI1OWuX0t7CQsMK17L8ClDG3Ugy+6KS4LPVDRJs
         FoCSHZxlTp1jz4sXEnJ/N4rouC7AIGMQbQ3KsM4Eb3X0fTBA65c0DkAvCfuU6lqdW5bj
         aw/EOcPb9wqWUXyOWFi2eT4jQLHLghhBJcEDLkKuYNG5IsM2IiC3Ky/5NTgRQSBMQ2a6
         sBsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=f/EnDz0wCsQzZpbUmGqOYp1geZEtOonwga+edgP6X5w=;
        fh=fXLxrk2fUIfmFZdVFBvvManYNRDPD28c/fKmbGa+8qg=;
        b=j7H+fmCkjbc69ET3GBSSvAUr0EMWRxsnMpWEkgy6Baqor3UCRaeqf0GSh2UcyVFkOd
         lv/ABpO4g4LSOF9yWOCOPLjNa43R389svXcIujk7G1EtwyalWaFz8GNCS3+l9DJslObA
         tEY9/FuQ0ScFwpHo0kOVYSIDqzQ7vUfPcfCzVg02t3n+wGoTGHIJaimzdhrswoWhpO/L
         /j1C/IG8SXiYdd08zaGqzq4ZXWNo1jAKhcReqYmSFGXe8W5rtaBOy7jTPZnGhGbsm3BQ
         H02KvXU+zztqWK1IQSQCGuX6nMg0qlwKn2JdydPFT+uXtktOllqlPfYnG5FxPUV1kFGQ
         DSfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=am0QWqNv;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758715242; x=1759320042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f/EnDz0wCsQzZpbUmGqOYp1geZEtOonwga+edgP6X5w=;
        b=EY/bXFgxdsURwOuHj/4er9L/R+AVKA7nkhURWcGitGNvJmh4Ol3NPqzJrwl01uWBYr
         6VQpVz1S3m5E3zB5IIFF3WJ+UJi9ggm40OV8ZzSF3t+nv+9iqUXD1m3K0eZqMe8Q2QoC
         O1KjxqiM416LW93gSjzwzZb+hy7RkkKoLm6myyhWafVwldBtYazASFIl6a39tD+ITOvQ
         A4tzUwyNIGMcC3zC9zd1G6z1LSpdbt6DwoiAWW4I/l2FMajiaX4Rvc3G5tUxwW5kC/nu
         JhOiuuX71mkpm+BJyigRPyEtnwhzgfk3sagE8dSHEVP7woe3lKubz9YdmoMntEW8uLuS
         YrFw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758715242; x=1759320042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=f/EnDz0wCsQzZpbUmGqOYp1geZEtOonwga+edgP6X5w=;
        b=h5uTpxzmiNvhEs6nQi1nl/LAcBggGkXpiDntdzUr1sJRbFTEqeGgz8QuE5gr7BnYhz
         VYtop7PtuOntvoA+vGxGTksqxobsF8HJSStyi2eXvANxEQ2/attZQdLU/KoAlRoY7pxJ
         54NCGs25JgskJD9eKEeVO1oaIlQlmb/4H0lOtS9E4n8DcxQ+ua4CKiVtalUk/QOwr3lE
         tPHnc6TnvhLZVbjd18LqQ5zHNAxR1xr93TzlGTSb1MaRVPJopYirZI12Ra4N34sJWgsb
         PIOq0svuVsTjHBaWZTSmv0taCvuZOtgRjY8/IjpcgfEtTp5EK2bAW7cJ1P6tJCyUOko0
         nDdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758715242; x=1759320042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f/EnDz0wCsQzZpbUmGqOYp1geZEtOonwga+edgP6X5w=;
        b=FEnp3+6wCxuEpbvmBIjACpppwEx0VOpryFGkdRQ2MN+/ab2r5jKHxopB3/UdjYhMpH
         N2PdMkkCKAUQfzgQohLvGmrkhZN8gh255Aw01YKIRJjDpPtla6lcGTYWhy9rh3xJZQTz
         LSWPw1a7XxEfbTFaMNjFgTntkiBJ551QK/7SyMrhvKkUOkiUPlz/xX7WGqMSrRmQBNv0
         BRYIwN1U6Elx3FbTIG5uopA3266nXN8XjggVtj3Vf9VBSk+EB5LFA/MaHByMKsPnhiFa
         tfgyEm0tXbHJjHZ4byY+/1fbsUEba7h/6JvSylJOgsQdSji7dQ+45IpjNaj6cix3Iy6v
         cZ3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUYLR7vdHUIaByUpNOqeNsJdYKuAx6cdSmctvpfgwXDUOKTaKtyOb6GCJMGqEZyZj0mTm0apw==@lfdr.de
X-Gm-Message-State: AOJu0YyiG//DsNu1+J1ceJHw3k9ZKqvnB9amkud06nFo5S/NpdRdVUae
	SibcD5HdX7yGO+aV/0p5JqHVT/4am10zX52I9HHh9iRfj1aZmnONF9tD
X-Google-Smtp-Source: AGHT+IHLJazDEDHYhnTrdZLsN3cN5twOZhbehGf4ToarRIsxyOP/z3eo1BojlcTY8Rkxm1+ubUoRUg==
X-Received: by 2002:a05:6820:16a1:b0:62f:4868:ef47 with SMTP id 006d021491bc7-6330bf72226mr3247579eaf.3.1758715242339;
        Wed, 24 Sep 2025 05:00:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd74QKybZlMC68hnKD9sY1LhvlUQ7FB/r2CgMN/Zd8O9ng==
Received: by 2002:a05:6820:c08d:10b0:623:56e6:cdf8 with SMTP id
 006d021491bc7-625df6ca6a3ls1474960eaf.1.-pod-prod-04-us; Wed, 24 Sep 2025
 05:00:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2B1THkgIfIeI0FyFRhEDuhgMz9YdlqGFnxy2WaWQm9KMeZaCbzz9zdArrUMPmwueoBfyWpZvAQek=@googlegroups.com
X-Received: by 2002:a05:6830:2807:b0:741:aa58:d500 with SMTP id 46e09a7af769-791425055a5mr3587741a34.3.1758715241397;
        Wed, 24 Sep 2025 05:00:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758715241; cv=none;
        d=google.com; s=arc-20240605;
        b=IXZmDeR1gNHSGkXOrGgVDqiyRR4PmGCGIfTiONKoQY0frn1l2XwMBf8D6QOG37t5Ui
         ySKAK2wlBCEKOQXDKSitQSOQP8Iffmy1PKtSNi0xYNwUFIohVJ57pbSgxgu6S49JaLfY
         Zyh3NgmPV0hThAgUabNakIEvL2kRs42juyWwDUFrt9O5ITCIrWvwh/U4xhPyYyYmEepg
         2nKqtTdDEvDuTRaASj0B2FDk6CTQsv3f+03sa+TF2SnOBYs9OEd+EhuXAgnsz2hFeSZ3
         zEppaNvduIFmvevhLSOLqmxqCqqq2TguLR9tx97L+H6hp2VSlP74WSEF21hy1dme9wFf
         Hk1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1NT8+IPFZig8CTJZJveFgxRKV2ZOTWE6XU6N/gZkl8A=;
        fh=fymvx1IRXEWBdLt8HcshU+GNBbqKTkSvnFoo8iGndIA=;
        b=SP+8VCf6nZQDFQNiGpdKXJC9S3IOYL+RS8/PDMEkvJMj9JP0mKN4phTVKY87mksmB+
         ogqD0lejYdvXang8Q1VamZiqbiBBE9TxcCIEjYDX8itsA66ZcZjdRHlSQBoxFZiNXXcL
         0y6twa2H/8GKmRSlGZeuKys3JCZzs6IJyxg3e5qw3WTEy4I7gKvgq3WyZwcRLklSfRJq
         Gtqg1zP2SnxQ2cgJ8dTmxaJJU6oyoFlWUTRaXGq2pnG8LTZEjooXqE+411cBLcL/5BeQ
         vH4gTV/d1oZwrhQX12hxyfOt0Ncot1yVZa8aXkvmSYgFbRm8PVUOZGCX5uUdwiNQuAvh
         HRuw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=am0QWqNv;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7691b5e50c1si198478a34.2.2025.09.24.05.00.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 05:00:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 41be03b00d2f7-b557367479eso826244a12.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 05:00:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCURn/BLqqudoO+uf/YUbaGMo/vi1kbVvQahvWLgkVDRqjoeIzFWYA3GM9NotrAY9OS1MmKhuYG1ALU=@googlegroups.com
X-Gm-Gg: ASbGncsJC8ZxiAb4RGQxhdJoZKMIBJ+8evq4YO2yuWDAjZhuEwDAjxW9IwDey4U7S9G
	tA0lTeG3NQkHhM9cYlizDEdaY8h+MPtiWgdZcvXLz86FlAqvTGzLn6n1QGKUWBh/DkMh3k1Vrv/
	pnTII18xfc5InXoEEHCM+ycN+7m0Lup5/6DEu6GUBx0Ft8XRQcNf/+sXC3VWSzBOn0tI6GK17Ou
	Dz02Qu74PuP0oggskqAEhA9NztECG784CX8mHxg8bGy5mQJA4dcLISz5eOBMoOFJXjlvV7q3HUG
	yRigeR+dRvKMPuYQjhfms+saUumcXbqvtpi/GXNcbbszfFBoF71sMmQ/Dql02AxJ9PmytG5rg4q
	S4pq9l308VVy/aaLFuWQEZNI=
X-Received: by 2002:a17:902:e5d0:b0:267:a231:34d0 with SMTP id d9443c01a7336-27cc5623567mr72404795ad.42.1758715239864;
        Wed, 24 Sep 2025 05:00:39 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-269800531e8sm191473635ad.29.2025.09.24.05.00.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 05:00:39 -0700 (PDT)
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
Subject: [PATCH v5 20/23] mm/ksw: add multi-thread corruption test cases
Date: Wed, 24 Sep 2025 19:59:26 +0800
Message-ID: <20250924115931.197077-5-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115931.197077-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115931.197077-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=am0QWqNv;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

These tests share a common structure and are grouped together.

- buggy():
  exposes the stack address to corrupting(); may omit waiting
- corrupting():
  reads the exposed pointer and modifies memory;
  if buggy() omits waiting, victim()'s buffer is corrupted
- victim():
  initializes a local buffer and later verifies it;
  reports an error if the buffer was unexpectedly modified

buggy() and victim() run in worker() thread, with similar stack frame sizes
to simplify testing. By adjusting fence_size in corrupting(), the test can
trigger either silent corruption or overflow across threads.

- Test 3: one worker, 20 loops, silent corruption
- Test 4: 20 workers, one loop each, silent corruption
- Test 5: one worker, one loop, overflow corruption

Test 4 also exercises multiple watchpoint instances.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 178 +++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 176 insertions(+), 2 deletions(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 08e3d37c4c04..859122bbbdeb 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -17,11 +17,12 @@
 
 static struct proc_dir_entry *test_proc;
 
-#define BUFFER_SIZE 16
+#define BUFFER_SIZE 32
 #define MAX_DEPTH 6
 
 struct work_node {
 	ulong *ptr;
+	u64 start_ns;
 	struct completion done;
 	struct list_head list;
 };
@@ -30,6 +31,9 @@ static DECLARE_COMPLETION(work_res);
 static DEFINE_MUTEX(work_mutex);
 static LIST_HEAD(work_list);
 
+static int global_fence_size;
+static int global_loop_count;
+
 static void test_watch_fire(void)
 {
 	u64 buffer[BUFFER_SIZE] = { 0 };
@@ -72,6 +76,164 @@ static void test_recursive_depth(int depth)
 	pr_info("exit of %s depth:%d\n", __func__, depth);
 }
 
+static struct work_node *test_mthread_buggy(int thread_id, int seq_id)
+{
+	ulong buf[BUFFER_SIZE];
+	struct work_node *node;
+	bool trigger;
+
+	node = kmalloc(sizeof(*node), GFP_KERNEL);
+	if (!node)
+		return NULL;
+
+	init_completion(&node->done);
+	node->ptr = buf;
+	node->start_ns = ktime_get_ns();
+	mutex_lock(&work_mutex);
+	list_add(&node->list, &work_list);
+	mutex_unlock(&work_mutex);
+	complete(&work_res);
+
+	trigger = (get_random_u32() % 100) < 10;
+	if (trigger)
+		return node; /* let the caller handle cleanup */
+
+	wait_for_completion(&node->done);
+	kfree(node);
+	return NULL;
+}
+
+#define CORRUPTING_MINIOR_WAIT_NS (100000)
+#define VICTIM_MINIOR_WAIT_NS (300000)
+
+static inline void silent_wait_us(u64 start_ns, u64 min_wait_us)
+{
+	u64 diff_ns, remain_us;
+
+	diff_ns = ktime_get_ns() - start_ns;
+	if (diff_ns < min_wait_us * 1000ULL) {
+		remain_us = min_wait_us - (diff_ns >> 10);
+		usleep_range(remain_us, remain_us + 200);
+	}
+}
+
+static void test_mthread_victim(int thread_id, int seq_id, u64 start_ns)
+{
+	ulong buf[BUFFER_SIZE];
+
+	for (int j = 0; j < BUFFER_SIZE; j++)
+		buf[j] = 0xdeadbeef + seq_id;
+	if (start_ns)
+		silent_wait_us(start_ns, VICTIM_MINIOR_WAIT_NS);
+
+	for (int j = 0; j < BUFFER_SIZE; j++) {
+		if (buf[j] != (0xdeadbeef + seq_id)) {
+			pr_warn("victim[%d][%d]: unhappy buf[%d]=0x%lx\n",
+				thread_id, seq_id, j, buf[j]);
+			return;
+		}
+	}
+
+	pr_info("victim[%d][%d]: happy\n", thread_id, seq_id);
+}
+
+static int test_mthread_corrupting(void *data)
+{
+	struct work_node *node;
+	int fence_size;
+
+	while (!kthread_should_stop()) {
+		if (!wait_for_completion_timeout(&work_res, HZ))
+			continue;
+		while (true) {
+			mutex_lock(&work_mutex);
+			node = list_first_entry_or_null(&work_list,
+							struct work_node, list);
+			if (node)
+				list_del(&node->list);
+			mutex_unlock(&work_mutex);
+
+			if (!node)
+				break; /* no more nodes, exit inner loop */
+			silent_wait_us(node->start_ns,
+				       CORRUPTING_MINIOR_WAIT_NS);
+
+			fence_size = READ_ONCE(global_fence_size);
+			for (int i = fence_size; i < BUFFER_SIZE - fence_size;
+			     i++)
+				node->ptr[i] = 0xabcdabcd;
+
+			complete(&node->done);
+		}
+	}
+
+	return 0;
+}
+
+static int test_mthread_worker(void *data)
+{
+	int thread_id = (long)data;
+	int loop_count;
+	struct work_node *node;
+
+	loop_count = READ_ONCE(global_loop_count);
+
+	for (int i = 0; i < loop_count; i++) {
+		node = test_mthread_buggy(thread_id, i);
+
+		if (node)
+			test_mthread_victim(thread_id, i, node->start_ns);
+		else
+			test_mthread_victim(thread_id, i, 0);
+		if (node) {
+			wait_for_completion(&node->done);
+			kfree(node);
+		}
+	}
+	return 0;
+}
+
+static void test_mthread_case(int num_workers, int loop_count, int fence_size)
+{
+	static struct task_struct *corrupting;
+	static struct task_struct **workers;
+
+	WRITE_ONCE(global_loop_count, loop_count);
+	WRITE_ONCE(global_fence_size, fence_size);
+
+	init_completion(&work_res);
+	workers = kmalloc_array(num_workers, sizeof(void *), GFP_KERNEL);
+	memset(workers, 0, sizeof(struct task_struct *) * num_workers);
+
+	corrupting = kthread_run(test_mthread_corrupting, NULL, "corrupting");
+	if (IS_ERR(corrupting)) {
+		pr_err("failed to create corrupting thread\n");
+		return;
+	}
+
+	for (ulong i = 0; i < num_workers; i++) {
+		workers[i] = kthread_run(test_mthread_worker, (void *)i,
+					 "worker_%ld", i);
+		if (IS_ERR(workers[i])) {
+			pr_err("failto create worker thread %ld", i);
+			workers[i] = NULL;
+		}
+	}
+
+	for (ulong i = 0; i < num_workers; i++) {
+		if (workers[i] && workers[i]->__state != TASK_DEAD) {
+			usleep_range(1000, 2000);
+			i--;
+		}
+	}
+	kfree(workers);
+
+	if (corrupting && !IS_ERR(corrupting)) {
+		kthread_stop(corrupting);
+		corrupting = NULL;
+	}
+}
+
 static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			       size_t count, loff_t *pos)
 {
@@ -100,6 +262,15 @@ static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 		case 2:
 			test_recursive_depth(0);
 			break;
+		case 3:
+			test_mthread_case(1, 20, BUFFER_SIZE / 4);
+			break;
+		case 4:
+			test_mthread_case(20, 1, BUFFER_SIZE / 4);
+			break;
+		case 5:
+			test_mthread_case(1, 1, -3);
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -121,7 +292,10 @@ static ssize_t test_proc_read(struct file *file, char __user *buffer,
 				    "echo test{i} > /proc/kstackwatch_test\n"
 				    " test0 - test watch fire\n"
 				    " test1 - test canary overflow\n"
-				    " test2 - test recursive func\n";
+				    " test2 - test recursive func\n"
+				    " test3 - test silent corruption\n"
+				    " test4 - test multiple silent corruption\n"
+				    " test5 - test prologue corruption\n";
 
 	return simple_read_from_buffer(buffer, count, pos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115931.197077-5-wangjinchao600%40gmail.com.
