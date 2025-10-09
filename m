Return-Path: <kasan-dev+bncBD53XBUFWQDBBLFKT3DQMGQERYFPGLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BC8ABC8A0B
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:50 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4de2c597a6esf40745091cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007469; cv=pass;
        d=google.com; s=arc-20240605;
        b=lqY8/5LoszqAvrtESkNNxb1DI46j1ReCrwLHFTL2a7ukaSFfcQCd/2zUDQnS2Tyg5P
         qJYuy4+WOu7pIRgkauEhaqf2yxbrKx1Um5o0Pjgbr+OA4HCHXUOmwDlluKFmFvKhK4lx
         J7PU1oQj4x2YpnZiROONi7MARBovUleJULnHtDDX5oinKY+M74yAXxDz/plb4izn6W//
         QTGRhAj+HCp1jFXO8Vdl3s0VzxGVWa20VpPuYORT+8OqUgg/z1G2WDvNbo8PyovHecbR
         QowXMworEmQV4LkghZ2pV13z78UrqVQTxLMnUAq6cpNHH+6/ql2vm726J/VZOPleHK2o
         GG2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ubDmtzFb9jaLygICGWBRG7Kkp/V3c3COAtUUlmXpTOk=;
        fh=B1X8sHKvewQ8zNnQPg/kVsz+DYPEoaHbtghAr0SdOO8=;
        b=PDgGMmQ2ahFkzxeZsbzuPyM9vqezT1hF9HCwN2jxiM8NNzEmhHTTqhTlr+l3dIT8yb
         iEMmQgzsQ1xDvMWHrN5Kusy+gHuok548Ujm4YTENeN17gIF+P2IxV8+h9V0lNqpHTnf0
         g98b7tDg0+aAq6XVxai2b8GC1+pExYZkclWzAOPAoCtyxq38f4OdrUfCOQOXuHE9zAV/
         Z5JYDsaSps1HyP8oJJj5YaaCfroVefxprMqhByUKv+i3CpsX/8/1kifAyAiouQI2luFk
         FHKHuGl53daBoqxADD0eCHmWvDqzrUXrhpbDEy4yf10Fs/G1RBJalI1pKmJVR3R7gWKl
         pjjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=T0qhKoda;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007469; x=1760612269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ubDmtzFb9jaLygICGWBRG7Kkp/V3c3COAtUUlmXpTOk=;
        b=sBNPRm6uqxecMH2Q89wQfIWpTCzSJs7GdVvAG9Z5okja+ubWlzHN9fowEiV6l3oJ9l
         P9aNE+QblQ2RQWiUoJC2UuIyZKdQjELesvqbz4jp9IrqAVkgPQ7zlhz/kEbqdIrhFFg7
         Iky0Bmh4flEittAqOIfMz05qT91ODneQkR7ecbIimRTO0vNHsUNa0KWcPdooKOdZyGcB
         ZcpxjEWGSApaT8VhYYEjodj9NRm7G6G/0CjUU7PdqBAW33pLJFda2nDFphzcan/zGKe8
         v7bj3itOqXECtSQSohHkfciXgEbdIfswjfqCdaqPj3oiC/LTjMhM/ntVgrN0C7WSJpJ2
         rY4Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007469; x=1760612269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ubDmtzFb9jaLygICGWBRG7Kkp/V3c3COAtUUlmXpTOk=;
        b=mOcjtTS3o0MHsnq9kK+exUDK7Z4QQZwMYw+0YQ/pN3F4Cy3qAWVKUC27aqAeQ61xRt
         JaTWeHHSywrDXX3+Se3JIFkL+aE5AN0Lf8zuaoIYOBCMohhgIW35+NPS91ZgWK97hNxK
         zVzQpMB5EZ4FqMENFCeqzPnLCAKjbTTJDvVsjCZfadijIU3j+RekT+ca/BC7rRVnA518
         rrtXtnvLJNVBraRETyXZlCqT8hHqovoN6WSdlqGCEw1STPsx53NLqjE2PQQSlajzc5Zb
         p5jA6apD2LSnf9ORCbnXSWvXu64o0L284RdzWZ6BBbsxg6NH1Vxs/LHIgT0WSyRi4tyE
         gIrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007469; x=1760612269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ubDmtzFb9jaLygICGWBRG7Kkp/V3c3COAtUUlmXpTOk=;
        b=WLYFJ+ciM9q3hnE8kGUNxddMznYbLzlbZfm+hZahEVSULt8bvtVGh+jpTvq50GL/sX
         TqwdZPt/mKdeFJmOAyzYc11IJ5y5x9RxaAh1fTLSy7S15mkJ6citBNT2ia+cugwITdTu
         v5vg3YYHSh+Xz+iFJt416+sCD7T3TrE7QJXV/7nHGzW5FlxMkOeI/ETdsENg0/dvJajB
         wVkwUqBdoY04r7IK53G7lMns52RDYU7iBz4v20i16c4edklsEtpn2KGVwfT0ftWT0GPV
         ghuikJCDFxvdYWbDLFoRCIM21wUy9JgeSDK3Mkgyi25MpuXh6utqbFj6SCCw5DWFxKy5
         BBAQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV8cZux0IdsoECK3vt6iIBr1ObeLEi4AQUaNtoAWO+yDa/Trae0NcNFdVrMHOCzxRzbSAvgvA==@lfdr.de
X-Gm-Message-State: AOJu0YzSVSRC62bmQf2iezPapFnOVJhaVH2tusEqZFKPMnVpgGS5KCFg
	MCQZsgH6+XP5igvCyAx1dru2zSU+RsJZbWGFdjTkQe7LpJwWw3N+7eza
X-Google-Smtp-Source: AGHT+IG4Uj2KDMGiHlCzju71XJ5od1GnPVqC/J1CW1GbRCpFBnd/62y2L5WU0A8PUjuNnxYxqWo4ng==
X-Received: by 2002:a05:6214:1cc6:b0:851:746c:e6c9 with SMTP id 6a1803df08f44-87b2d63dca8mr101396906d6.31.1760007468976;
        Thu, 09 Oct 2025 03:57:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5v4r0cgXmNcfKlEwebUhrAAAITAv5zf5Bm9DQNE73gVA=="
Received: by 2002:a05:6214:a06:b0:70f:abbb:a05c with SMTP id
 6a1803df08f44-87bb4fe9a31ls12890766d6.1.-pod-prod-04-us; Thu, 09 Oct 2025
 03:57:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUSmTG5FPT6MOxFqoUXqzZ2xMOtys1RmbzPAI6nujmIs3L8384MwB6ToIhMyZ9LOvkZO79vLShL5/w=@googlegroups.com
X-Received: by 2002:ad4:5c6b:0:b0:76f:6972:bb89 with SMTP id 6a1803df08f44-87b20feb968mr82463646d6.9.1760007467998;
        Thu, 09 Oct 2025 03:57:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007467; cv=none;
        d=google.com; s=arc-20240605;
        b=WAtH4mtTjyDeimxZ2IvJrENZddLTcWFj8QTXMMnFlPMTlXtpqOnBF59I1cRLL3tjLc
         CTqK9F/8QgN9rLq0NsoxsSEbeOyf9luWrbXk1BVcDSd8HbK4uPGlAncxUMk39E+/HbA/
         6dUnvcVvaVrCyvDLyQdwdWipJOnKK0K6+CRK+QO/RqEyS/6NZkWB26xFYM/CVS3mJyfF
         8/phdiouQVZt1/mMY2dEIr8I721Ba1QecNq2I3wjeL9x0HQgHzFxX8/XwSCb6iqkI4nH
         kHcdryQe9ynROj1DbRZjVSH8g8UQNsiuk+4qdg4ydwUutmUblHYw9r2EcKzIfJI9r+9l
         PQeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VplC5p74+BCL3Xjzqw2UL/AL1hevTQUKrGPaYOT40mY=;
        fh=DIOqBgMRbkVq11eapnHQzch4qrPrT0AehnmuaKnoJIk=;
        b=JuAhBPR2PxkHtz1b31oCkVvvWbqFP6LtAxx4gXzWXyfkNcA/+J+VUMXxRlkrDWz0qn
         yxsyLT95dN+2qVk1PhO+7w/aSCxRn4937oiJAXnMi+G9jPaZyp7zSrjw6nlDsC6wC4NB
         LSCHQSAf6/FqupqDWT+wqbP7koDjm4k8n19pqnZu8ONf/wD2vvJJCMNyG59WVht91BiN
         ah51MpSi9QEnUIMW1GDvygsrB9/rlCvOgsAKeZIcV41+nLQfH+OavBoB11uX1vA8fvfK
         lbGKY+Rgyzq3vrS6gFnewg2LPx/Csvnekg5ajWdy7ElD6Sj7x6v+1l+7kLiblAf767FO
         W9uA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=T0qhKoda;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87bb5bc5919si758116d6.5.2025.10.09.03.57.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id d2e1a72fcca58-7811fa91774so704822b3a.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXaQM+GPAyI1RJfr34jINOxWTdosZpLmrC2M2RoBFx1SgK4wpr7sNj8pheGajYwo2Q0KGe/FrBJbnQ=@googlegroups.com
X-Gm-Gg: ASbGncstCTFz9DfoEklrdYfiZDdF+5774Csi9A5/oxbOJL7NaMO8NF1AUvmYvJec7Xw
	wQTbOTKc/JIizKyYcWOoJRuBgka/rJBmMWZNWsUudvtlMplg/NgT3KqumIHVpEL+r9vk7nkEOcO
	5k9fzxynD1qK1MoSYsHNN/mWPjfhhlPicndCoS6RoORiWOThG1rU96UikIEN7liaVBAejZf5jTV
	hz3ea/ZbhDN5CiS+GT90k36+X7tr+XAbcg99Q8vtF/8/ccBVS2XawRJHcSo40ZVSm4SpRcg2YOT
	TLWYWqi0iRsu5QR2oIso8iRZemZ7B/IKwiKmY3pt8lYizhRZv4/PPxpLo2we6k9GtgNxvD6lLPQ
	eHBeCw49XaY+ptoCz5Vo8MHji6n/yrhFrw8q4EZL9aSjKv3FD2PGOxOF0nQkH
X-Received: by 2002:a17:903:2342:b0:28d:1815:6382 with SMTP id d9443c01a7336-290272e3ed2mr91929215ad.46.1760007466971;
        Thu, 09 Oct 2025 03:57:46 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-33b5137dfa9sm6632975a91.15.2025.10.09.03.57.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:46 -0700 (PDT)
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
Subject: [PATCH v7 10/23] mm/ksw: support CPU hotplug
Date: Thu,  9 Oct 2025 18:55:46 +0800
Message-ID: <20251009105650.168917-11-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=T0qhKoda;       spf=pass
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

Register CPU online/offline callbacks via cpuhp_setup_state_nocalls()
so stack watches are installed/removed dynamically as CPUs come online
or go offline.

When a new CPU comes online, register a hardware breakpoint for the holder,
avoiding races with watch_on()/watch_off() that may run on another CPU. The
watch address will be updated the next time watch_on() is called.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/watch.c | 52 ++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 52 insertions(+)

diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index 722ffd9fda7c..f32b1e46168c 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -89,6 +89,48 @@ static void ksw_watch_on_local_cpu(void *info)
 	WARN(ret, "fail to reinstall HWBP on CPU%d ret %d", cpu, ret);
 }
 
+static int ksw_watch_cpu_online(unsigned int cpu)
+{
+	struct perf_event_attr attr;
+	struct ksw_watchpoint *wp;
+	call_single_data_t *csd;
+	struct perf_event *bp;
+
+	mutex_lock(&all_wp_mutex);
+	list_for_each_entry(wp, &all_wp_list, list) {
+		attr = wp->attr;
+		attr.bp_addr = (u64)&holder;
+		bp = perf_event_create_kernel_counter(&attr, cpu, NULL,
+						      ksw_watch_handler, wp);
+		if (IS_ERR(bp)) {
+			pr_warn("%s failed to create watch on CPU %d: %ld\n",
+				__func__, cpu, PTR_ERR(bp));
+			continue;
+		}
+
+		per_cpu(*wp->event, cpu) = bp;
+		csd = per_cpu_ptr(wp->csd, cpu);
+		INIT_CSD(csd, ksw_watch_on_local_cpu, wp);
+	}
+	mutex_unlock(&all_wp_mutex);
+	return 0;
+}
+
+static int ksw_watch_cpu_offline(unsigned int cpu)
+{
+	struct ksw_watchpoint *wp;
+	struct perf_event *bp;
+
+	mutex_lock(&all_wp_mutex);
+	list_for_each_entry(wp, &all_wp_list, list) {
+		bp = per_cpu(*wp->event, cpu);
+		if (bp)
+			unregister_hw_breakpoint(bp);
+	}
+	mutex_unlock(&all_wp_mutex);
+	return 0;
+}
+
 static void ksw_watch_update(struct ksw_watchpoint *wp, ulong addr, u16 len)
 {
 	call_single_data_t *csd;
@@ -210,6 +252,16 @@ int ksw_watch_init(void)
 	if (ret <= 0)
 		return -EBUSY;
 
+	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
+					"kstackwatch:online",
+					ksw_watch_cpu_online,
+					ksw_watch_cpu_offline);
+	if (ret < 0) {
+		ksw_watch_free();
+		pr_err("Failed to register CPU hotplug notifier\n");
+		return ret;
+	}
+
 	return 0;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-11-wangjinchao600%40gmail.com.
