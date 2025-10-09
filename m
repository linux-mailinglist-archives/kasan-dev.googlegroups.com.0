Return-Path: <kasan-dev+bncBD53XBUFWQDBBVFKT3DQMGQEPXWIFJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id C3156BC8A40
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:58:43 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-27ee41e062csf18531555ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:58:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007509; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qcn3/o2cad+ViP6n4nPwGOUBT4zNqRzrhk88BvdWbxFYPPhor5f56ifr+Dc2EZah+h
         tv9GH687/wxFl8RDJX0Rq3ON5AQDBaHrCEb3bBDT+PxzGPLn1M7VHLvYenXjltQd8c/B
         dsmKJwgwhsIr4Gp2rzBKVgCuBFsPb7pUZwHrv66zCuUUvv3LqWZ0kIFPUnZ30f7SftQX
         KenqBPJFIu986ZCfoc/ybG3XQeE+atRrLG8wmOjez2YHwLMzlxzXHsoYlVRniysnbLNy
         rvxo8A6pRyJtDeJCVVGywgqJpoJg4colOcXTsem0wMvmgmycxGpQbg7kqlQ9PVZoSAwy
         XfiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=6PuA29J6GCwBADLVAy4D96YLVWGBLWcvrZZlfhaEhhg=;
        fh=G+6EiDMZ2DAbYo7Dc2UStob8KCJ9wmhEfBv2Hjvr9j8=;
        b=kbIa4yV4PqGR7QbTYrkv2Nvito781u9VD37Bj/m7WDsiVlydhUeQJx2wu/HR/Jr/ML
         5qTmboaI/IGU13mjCRKGzhDRDBndE1CS5/wRGcBH854qLE0kMdqNIyUmlZaawmdIvUdA
         h9APzRyW5gN1Yi+UnfFfo3H7X6b3xznJnT3g+zOlOg//Ya2lzdhgoutRi+AYImzEKjC5
         24kXXs4QNgSw25pSsZImvGrnIoGXyfI1bCWBE5tU4TipurFGGo+UVO74NpApY8GnfZKx
         eqnOOhayWvgV78WJMDfWKdc7vRcpX9FsbQW7vBgqYw/cldSiqQrVUqOSA4HTESne+3Hp
         GRuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U+f9+k52;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007509; x=1760612309; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6PuA29J6GCwBADLVAy4D96YLVWGBLWcvrZZlfhaEhhg=;
        b=YAruxTe19W0t6tbUqFq84xGzox3c4qzCCXcUd41miu+jMryS/34iXjKv9wqxUExAkB
         GmgjBqCSndZbj6G4v9VBMhN5nRPb6v31e+qwZmuhNzLtKpcECpakZG0aNoIRnTlt2nJs
         XGo1l2SR385z7ps1Kv6D+BRZRdRH2jPrq/ehyLbPgy/XgmOTYcMd1z/pjaqGpd2DldGN
         SQEX0VPZp3YkCRtp1Eiw1K0dNlaGG36MIWBtOH8SY+Jz4CgB0bOuMXteCy+EHUmv8oZj
         Yce0z8NFQwBkvmc5SPkMk6tR6Zug58yt/f4cKMKru5IQezWOb2iX32uXBTc/Ec83Zcsy
         Gkfw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007509; x=1760612309; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=6PuA29J6GCwBADLVAy4D96YLVWGBLWcvrZZlfhaEhhg=;
        b=KTDHa1PKjGi0ll4B24r15pzWEa6C3b8eD/Lfaf3wbrIh4PHtA47HjTb7Gr6nSblbqH
         E2B32E3B78meAIWeeLxjDRE4VMj7kvI9UNQbXcw2Pt4yGjZMrUIYelswvGr6mJOX9jfp
         WgG3XiVfq1iRFOVQeWLsU8NngxtmXDJgrEM1taCjyZhflh2qJlRMlnUfIRafLS9C4G7+
         222zaFTXz1MP1yK0b60hfWHLCpi8C+I8OFocjNZkbLoO1FzrpJE59pdyVFnm6W/I0F1p
         ZZUar6NGJiXXbKIrSX8DkK0Msyg7gfrlMDshWLQ3HmhWCuhxAuwO1qnaEJ7SaAXijC32
         +4/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007509; x=1760612309;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6PuA29J6GCwBADLVAy4D96YLVWGBLWcvrZZlfhaEhhg=;
        b=IW1go2gluWhrCDsBvqfQkN7CvSgJaRP4F7DAHnsOBDSQWbXULEiKJttIOLVuTRq9tr
         Y6p4KLJ6Tyz9YmjaP41lYQE/0DZCd3FRtz7Kwakhaa6brdgjZmJp5pWRCAXDS+BHuoUi
         SGtayvJxWpu7vgOoj69gwx3h6f+zQUbKA3m+bl2M2MH1IZRwE622u/uJAuIMQNnAmWPe
         HQN00Xh/MXVm/+fOj/qYHBksdCUUO/WCRXynpPbhUILsQAG5yOsmE/EMQgZqUw0R3NiI
         jqeJY71JkWgAjnaBXjeGr2anjFaDsoFmtyMovOcnAZhfWbz//HGyl67Bh8Y1gFW2pM1w
         9KOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWpAcd98vfPy1tDnAmoQUYfBC+YxQoCBbyRFUb/+S+v0LYShx72S8lIEFfIFqDE/Xi+1q9J2w==@lfdr.de
X-Gm-Message-State: AOJu0YzMOzxQnR6UrLBy5/CFH5HPQuwUn/VdzNUE/yK++aFvG/VufQWD
	Du4ncELNoHXtqDNSf9PEFnRc1xB0CqgwM6g6vzJk6iWVXeoWAbXKz9me
X-Google-Smtp-Source: AGHT+IE55F5p46t0UI1pCf1hfX82DrXWtY1tabeGlLiMK6kBUq7nSyl8CTfkEwNtzAHiwsCyrUT9yw==
X-Received: by 2002:a17:903:ac6:b0:28e:c9f6:867b with SMTP id d9443c01a7336-290272c516dmr85924745ad.23.1760007508828;
        Thu, 09 Oct 2025 03:58:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7trbrLaVuD54WonaKtikZ/apC416a5U0RvbJ7qfIT6MA=="
Received: by 2002:a17:902:d9d4:b0:28e:cc52:e2f3 with SMTP id
 d9443c01a7336-2903586c3d9ls7988345ad.2.-pod-prod-09-us; Thu, 09 Oct 2025
 03:58:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQL9NZyKLhq2uD3K0z0FE4527kHQ7+QEe8bJQyWfQXHxsDQWoY70nkpLg/6ojzStNyKL6KGg6+47E=@googlegroups.com
X-Received: by 2002:a17:903:2b03:b0:264:70e9:dcb8 with SMTP id d9443c01a7336-2902739f408mr86330645ad.55.1760007507376;
        Thu, 09 Oct 2025 03:58:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007507; cv=none;
        d=google.com; s=arc-20240605;
        b=P4xSvoSDgIcth0rGzexMeKsqVa7G+cn/rMzBRRj5fhI6RSL8iSBi0HERvl8KPnyp76
         bhnD6bjfAulyusXm/P0bq8sWv/UQw4/7yGjS2meUwQHbKw6Ij6ONOV/lAgzqu0Heec3+
         TagXzL8R6zXU6n5WGg+hmcdO/Y2FEIDqsPPcVDOr/Ek+JeiFrm4CyptmKPGpt5r6/s1J
         FiP4TJyPvZVTsGPWtRrxA1U5RMfhpSowapEoYU61agJoR+UjOQR5+haxEMeICIJ/ONZp
         8saSAESj/w+tRdik5Jm2edF/x0pxSASvk/u3yd4CJtf/IvGF75JdEIEW5rfWGO336p9R
         8Y0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wSXL/rVpDaFhkpWTVL2v5h6JspYJZAfxl9VpOD0Az0s=;
        fh=f6lPXVBilkFJ6mQrlYq1OF7Ht5lAT4gytTWxxzpd5Kw=;
        b=VCukqEZesY81YrZguDSLa49pqLJcZoqAe/T+RkuYoC6uX6Z9Ll5BM/jF0OzhU4FFWM
         lhnXsW6qWyyRGvNn+oraARAIoFD6Ll4Pi+cdIa8ZmHAYi/eREO27sLo7xBCw0ueSwCLn
         jJcJ4UUV5M2S0xZK3y2VadxgP9z9+v7DwpLkXD0Jhzjytry3Zli78L6pbkxtCr3kiYoZ
         QgFsRNavumlhdpzrESvX4+UZzPtJVtc+TgzmJKyx+UGa+qjbqnaN1TL9IBNvR03eiLU+
         KvnuNr6oSWnoTanE8CxmPGHjFR2+7jOtD3Od/VQv/wqb0pOkUzwVTpuvvHHh9HHFYoxL
         vbHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U+f9+k52;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29036275a7fsi880005ad.4.2025.10.09.03.58.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:58:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d2e1a72fcca58-789fb76b466so723942b3a.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:58:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW3LiSm3QDWP2FGrF0yvMM/hnRTo5hM0pgGrqVcV9Ehimqw7Iq4qjcSG+bVe6bfrz1v/jdZ5Cnr8iE=@googlegroups.com
X-Gm-Gg: ASbGnctIxS43gDhpIJCnbZqGdNHK3b3vgGQekk4V+FsyeezLMgrRADWDI5hBlEO1cPJ
	cTleiCfld8xpEZtBu/sYCSLv6sCT3u2wyu046AeeJxB8leb+f7DqMNgK+xRwrGOqxi8pcyIpFx7
	8pHgJhd5SQYpBY0Ks6TxhcxuOW+MZOphzkKgpKdLdsW7AT4a8247Vw8zaODRsLTOGI0v9/EHTpN
	gvaiuizodK7g4rDvl8/mo38E+53xXFqzFJHSg1Nak1aYTR4TL6sT9k1MhcfiklF/cQS7FxysZhv
	9wOHOCS4usnEgjG77SE866OwxfH7WY+AvKgYVRwxfaElsILcOhrDmj0s7e+UAKjPnskjDmSH/oZ
	CB3hKih45PoRLkC250x8oeOIcYwzceFD8VsuCrra3P2U2ZKabK0Cs3F517Ax6bzKgMfVlgzk=
X-Received: by 2002:a05:6a21:6d9d:b0:2b3:4f2a:d2e9 with SMTP id adf61e73a8af0-32da813936fmr7303953637.9.1760007506754;
        Thu, 09 Oct 2025 03:58:26 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-794e33efe73sm2503138b3a.73.2025.10.09.03.58.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:58:26 -0700 (PDT)
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
Subject: [PATCH v7 20/23] mm/ksw: add multi-thread corruption test cases
Date: Thu,  9 Oct 2025 18:55:56 +0800
Message-ID: <20251009105650.168917-21-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=U+f9+k52;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
 mm/kstackwatch/test.c | 186 +++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 185 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 203fff4bec92..2952efcc7738 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -20,6 +20,20 @@ static struct dentry *test_file;
 #define BUFFER_SIZE 32
 #define MAX_DEPTH 6
 
+struct work_node {
+	ulong *ptr;
+	u64 start_ns;
+	struct completion done;
+	struct list_head list;
+};
+
+static DECLARE_COMPLETION(work_res);
+static DEFINE_MUTEX(work_mutex);
+static LIST_HEAD(work_list);
+
+static int global_fence_size;
+static int global_loop_count;
+
 static void test_watch_fire(void)
 {
 	u64 buffer[BUFFER_SIZE] = { 0 };
@@ -62,6 +76,164 @@ static void test_recursive_depth(int depth)
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
 static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 				size_t count, loff_t *pos)
 {
@@ -90,6 +262,15 @@ static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
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
@@ -112,7 +293,10 @@ static ssize_t test_dbgfs_read(struct file *file, char __user *buffer,
 		"echo test{i} > /sys/kernel/debug/kstackwatch/test\n"
 		" test0 - test watch fire\n"
 		" test1 - test canary overflow\n"
-		" test2 - test recursive func\n";
+		" test2 - test recursive func\n"
+		" test3 - test silent corruption\n"
+		" test4 - test multiple silent corruption\n"
+		" test5 - test prologue corruption\n";
 
 	return simple_read_from_buffer(buffer, count, ppos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-21-wangjinchao600%40gmail.com.
