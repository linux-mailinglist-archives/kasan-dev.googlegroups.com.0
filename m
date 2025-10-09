Return-Path: <kasan-dev+bncBD53XBUFWQDBBTFKT3DQMGQEADEXO4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 194BBBC8A35
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:58:43 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-7bf89feb9c1sf385000a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:58:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007500; cv=pass;
        d=google.com; s=arc-20240605;
        b=WS0JtDxQ4sF5uBGDWxPXUXA1E/0Za2/mbSPa7y5PLI40dFQWEP5rlwIYHGMV19De+t
         1QgrcB18WHZU5gMyWig2K3zQDkXHwIJWVc/Qnt0/YwDeoh/J1Ia+xUK0yvAaqacwC5RA
         wRd9o3YAWl4QKhrdM8UsqM0c6e+e2kPnyQZtGZ5ucU92D4XNFytbzGo+SAttH/cFejtB
         6fjCAnwMjVTVJzLsFGTBdykwTUjYLEYhkd0NLHRZC7L2HvopOs62zxNDB85zErSMnqAO
         Rn5PAogmTZ6+YnMG1koy00whFHBWW6dCZj5cKHuZ4ZRnmyDEi4Vs9Jrl0Yy1CZp/oJ+f
         xxnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=UVv6vdjlvfaFgx2u4Nl6d0HApNgPFjAydkKuglS24gk=;
        fh=GAjt4i2/NqADxubu02prnBEHEEtlee+NQRJAkCQIPaY=;
        b=a4PMHBmGZiQykQnIbaLEBnOx5OlNarm9YzYC/ZZiMcNrJgY25NO307vjQtl/bUlHPB
         lxBHOV9DgbarjEzrJNwwAFnpr4wf1YP0f3S556O6aEI2PNq70QGVMZhXXQR17yWXMg9k
         zyrSZRLZa5sDBLGMUgtxz0XfekG1IdSM4OxUWNQtDi0WQ30dOpNSw2sSA82fp63oEAJ7
         +Tzazg6Wn0eX6d5TEkK+LZRxQsNWM5IsrFCvrXt4Lz4Erw6I0OLpFIqrq3EybLGxS5k1
         /DhrU4+aosGf1ALDiy9sjB5TysF7gI7y/+HFXluJigzpJN/ZTBxeI+FzCU621pPjNrBd
         qkpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="T8C/DPK1";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007500; x=1760612300; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UVv6vdjlvfaFgx2u4Nl6d0HApNgPFjAydkKuglS24gk=;
        b=oguMeZTDQF7uSHnKfm1LwLhhw6sXRKkNPM4k3Mgib1BZtxPdD36ldoDOZIyreJSIcs
         qKb1bqCNAsV9yJqPclRHaLHx8iMiXNm8S8ssXBPvjxd4HNFLpI+EFIufv29dTgrC2zWm
         xdl84bcpGmSzRkt3lv8P597+2Ua59MwcKNA6/XS8GfCbEZnw7dlba0UrFhB8nY4cQRoq
         Nw5vk0f32mBKQxsn/VysfXJ8NWuNyKrHWDOu0WR8caGCUJjiKboz1DU+uXxHdB86w1k5
         OXsMy1oP2NRygZaWZacao7TeQGafAmb0phN0Ppcf5N10pQlRwuRntVGr/SjoCdxjFYc0
         m0Sg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007500; x=1760612300; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=UVv6vdjlvfaFgx2u4Nl6d0HApNgPFjAydkKuglS24gk=;
        b=cbuifI2yiPtfJ2AkTxozhhmN6dKRDwCZkldYPUJ8apmUxTBRYZzsBoVk1FNOXK9TIu
         zcvSvg5kiyYm7S6/MuPZc1jNcUfNBXE4OtICingUtZAnHDjaZUcDcNEZ0avhA2X5GvYA
         13O/b8zGn7pTTjtvRq+Yja1sRKrClb2w5x5p1Vmusb1a4LhCXIXVe2RwzwDLrX5e5aFD
         RJolygLBG6fyp+yloGMwtTjypU+eEDfaE9qkHgxzG1khO5AA2yE8i6R/XLZrtdbEZfka
         P18lHwx1bsAOkg41ynMK67n7tWu59UYYbD3Cq3i06keJH3Wj46fpVHTDg2JIRC3wFigi
         Q44A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007500; x=1760612300;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UVv6vdjlvfaFgx2u4Nl6d0HApNgPFjAydkKuglS24gk=;
        b=EQiXwNSlivjx4exUHm8BeWVD0iDIGSQ2cTxGO22KD6MLYABTzan4/oQqOawgLICGJ8
         +Kyq6atuFI6LOaoUNQMVa4JUwwz3Cs8aF7tDxz2uPgo2F1vA+O4cAS+SgEopaodlVZik
         8xPon+5pJQNGXK+GXVfUdatG3sqkDZENR/CHRTBDwjFUTCPcuUOl2Vn1T37YZqZWHgue
         ocjQre3BidLaX8H0oijoC//hLOSuhmTaQn1SXR5ZkEiZ0G8LOkmr5ZwY03VEbfeYedzz
         0o4BL7DO+nkMb+Gi32NAiPFLlY0xtE6x8zylBBGOdtfzzbqtB2ExIRNnqSDkLb660Ug2
         3+mQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZWubSYkr7RmIy7PT+Wg15FIRKN2ktid3S794G1yb8l8aEOT9Q/jdPFt3p9ALKs9Dn9/wS3g==@lfdr.de
X-Gm-Message-State: AOJu0YyFioU8eVOQwO7avDmyg4+Ik5ujzEbNC4HuNXqycXl67qG29bvI
	SSeIQCiEJftSE+mItNNvF+bEghOGSfJYaaOSpokkrO8t+qNYeadE3Fs5
X-Google-Smtp-Source: AGHT+IHzr2bhowJh5dzN+tsKaoCnjTQ2eKWotOJuvIKQYNysYBK6k9luKSXMECLouYiqpZm5xlYcaw==
X-Received: by 2002:a05:6820:4619:b0:639:4656:f9a3 with SMTP id 006d021491bc7-64fffe16f80mr2654486eaf.4.1760007500423;
        Thu, 09 Oct 2025 03:58:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd60pv6+F5zXy+JRhV4ZBYcH/HDA/hPnCXx2QqP6zvndXA=="
Received: by 2002:a4a:e9e1:0:b0:62e:5dca:218d with SMTP id 006d021491bc7-6500ede6321ls193756eaf.2.-pod-prod-02-us;
 Thu, 09 Oct 2025 03:58:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlunddsGyxFUuveTm1+A4jUG752qf+7SC8ceYUrifXV4tQLwc/158nrE0jfS0w8emrcjagW3g5gYQ=@googlegroups.com
X-Received: by 2002:a05:6820:2384:b0:643:e4e4:656a with SMTP id 006d021491bc7-64fffea4ef9mr2789216eaf.7.1760007499657;
        Thu, 09 Oct 2025 03:58:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007499; cv=none;
        d=google.com; s=arc-20240605;
        b=KCrLckjVv9/61mXCVCWvBjpvDkUfoymZ9PIeEyK9wOlY5S220rSEeb0HFc34B6i9sq
         8cW3PQAWTgDcpdF/VvGMDNhZNtapVPn8/vQmHp6Rp9fJGWCkBVunTR3BlULmAXs+gToN
         I0W95o56IMM+Cj73JXp4eJV8Laln/uGYksDufr5BBfgw9z8888+NCbpKZXxuUcp8zmpF
         zcWyjwBumiwUh0hXK0w9SM+RcebhiaeSKJmk9WEGFbEgIpf5EmU+VPELeotlxUSCI76L
         1H8ONRsVnYVY/M6+eYPj5+1txUGSUCEeHVa/CCMqXSE9sOWO/J0h9ce6bJo1Tq8Cf3i5
         cwQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OyJZmUduTn6h/ct8/Xe3ui1NubLI+U0SzVd7OlZC6q4=;
        fh=Tl8VLGsufNPDGoAz77BohHFeJpVwGphEjWP/Ln0zhj0=;
        b=PoSp/vw7trmXI6CVUUCO+iQKdDKDR5tkVMNH5/gqLcjcLpp0CY9mwEze4Yz4fkakwb
         hlo9vAta6C62Eg0kItKd6nREMoorfpxI+QIoEfjzKv0VXyOLzII7Fwm6398GPDiWRQw3
         LOyyTeE0tXh0DCx19q6zkISUbAHi2jGlvLqXVRv3jL9YTolDKmoWCclcSXMHBpPupKRw
         dHGRXGPkcUWdCY7IcGw/m3lMitFm9iH7hA5ohtG55ECeXTauWdJGouPv7ABuxrK26t6A
         Vvv5Z6Q3FOnpof5f4tHnxPpDqiA1kgmScFbLfg/BpH0uGdqO0gN8BbbIQYZEE5MixMcw
         Xu/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="T8C/DPK1";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-64e18ece48csi66376eaf.1.2025.10.09.03.58.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:58:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-32eb45ab7a0so944982a91.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:58:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV5W/Lpjd2HsXommZ18z5JqeYxLLzsULxuQDH5bT0KJwkoBqb896toA2ilx9Kl40HLepPkzeaHg64Q=@googlegroups.com
X-Gm-Gg: ASbGnctow91pBV98iqPp/Ij05OnMOvtLpX+BqgYaSihh9FXR0cPAGFm8INyTcB34la1
	pjTdvBEi0+D6rWYWhqfgaN1LXldoBNB945KmQwm7hsmliZIpVvp1p2jEeLU2GCgoxmE4+xHw6hM
	wwyWY6eVqzeBGSK0nMEp58pu9lI5Hjp7jp65kFXFfP3LJj4pLV3jHmABMVAtlgZ9WOub5RDpIaC
	veCYz+2WtlVuUzz9AL7opLy437G7kxNQ/itva2lQdY80Dxv0rzfYx9O7FQfXBi1HdJ+1DNH59RK
	Z5K2AWoQiN/swSE6GwBF51y4l1iluaa1kGU0WZw399UCC1QEE5KrrevarC4wothfxEH5j8C3Jrm
	JNRd1EdtLJ1E0ZuX/VRgyUOEKbt4fNViMl2FmmGK/LYgFxr6w7pO9MLlRSZt2ZBLEX+sEaww=
X-Received: by 2002:a17:90b:17c3:b0:335:2b86:f319 with SMTP id 98e67ed59e1d1-33b513eb68fmr9866604a91.35.1760007498698;
        Thu, 09 Oct 2025 03:58:18 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-33b511135a3sm6725691a91.11.2025.10.09.03.58.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:58:18 -0700 (PDT)
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
Subject: [PATCH v7 18/23] mm/ksw: add stack overflow test
Date: Thu,  9 Oct 2025 18:55:54 +0800
Message-ID: <20251009105650.168917-19-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="T8C/DPK1";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Extend the test module with a new test case (test1) that intentionally
overflows a local u64 buffer to corrupt the stack canary.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 20 +++++++++++++++++++-
 1 file changed, 19 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 80fec9cf3243..012692c97a50 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -32,6 +32,20 @@ static void test_watch_fire(void)
 	pr_info("exit of %s\n", __func__);
 }
 
+static void test_canary_overflow(void)
+{
+	u64 buffer[BUFFER_SIZE];
+
+	pr_info("entry of %s\n", __func__);
+
+	/* intentionally overflow */
+	for (int i = BUFFER_SIZE; i < BUFFER_SIZE + 10; i++)
+		buffer[i] = 0xdeadbeefdeadbeef;
+	barrier_data(buffer);
+
+	pr_info("exit of %s\n", __func__);
+}
+
 static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 				size_t count, loff_t *pos)
 {
@@ -54,6 +68,9 @@ static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 		case 0:
 			test_watch_fire();
 			break;
+		case 1:
+			test_canary_overflow();
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -74,7 +91,8 @@ static ssize_t test_dbgfs_read(struct file *file, char __user *buffer,
 		"============ usage ===============\n"
 		"Usage:\n"
 		"echo test{i} > /sys/kernel/debug/kstackwatch/test\n"
-		" test0 - test watch fire\n";
+		" test0 - test watch fire\n"
+		" test1 - test canary overflow\n";
 
 	return simple_read_from_buffer(buffer, count, ppos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-19-wangjinchao600%40gmail.com.
