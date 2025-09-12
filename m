Return-Path: <kasan-dev+bncBD53XBUFWQDBBG7ER7DAMGQEOK3WC3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 939F9B548E9
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:10 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2507ae2fb0fsf14172715ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671964; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ixcda+hZieSjwDIMTSjEgEwJGD8BbxdMhWgLhA77GrYrUBTU8uRfmc4qdQYJ8zYzZb
         8mg1Ai5yVKkqJo4uBQ7HhgotbTmRQLhEuCG+DQxFCZc3qOrOeSeemnoMreoKMqdEVNze
         ZyTWA+2HwUiaScJOBQi8UMmt5nX41uRT7OGB1JchwxC1Da42p3ppuc/IQnKIV/W1gG8H
         yUffyJGijWzNLeVib0X8yNZYwFu1KX4QYYkOsK5/bPY/UQhw2+dq0mLRdp70KpAk5ZX5
         tKJqyCocFCucvL2iOZQWEHmO/kda3GHSHcolYVqW3QvCBkqb8iEaSmvno2Kv0J47qKcZ
         eaPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=udtwjXvQ+PKffl9W452a1f9YCYGvzKkputvCKlrMZr8=;
        fh=JOpGdHv87PkwAA3Beyqqrt2rPUSfCzO88jBZxZxyfHU=;
        b=dc0u7tJwwdkRE5ssQi8aH1V8zetNsLnws5FBIzGAU5lib45KBNxbt9fQPdF5Swz3uu
         O28FN76OqFEITVvaQPUjyBZ+qTRaAncq/BzL5MaIJepnGyaRdie6/mBj3ySxG1PxgEGB
         pzla4B9kU4mTsLhfQQTISfU4ClFa5xcJnrvO/m+YVxoH1xB8gr7AtayffcdXIMl2YnD2
         Lg7zrdWUh1sk1oTqaXiCjAzuetjNH6ixqCFKQJN6VeshsVoNrsahXDfRJ7M/Hdc16Ouz
         LDTTR17EKok/QaHgnC+8OqYc8I+fM5PyKLQI/3bxSW6/Zc1eYSKdGA+KTvPeN6woKo1P
         GAPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Pr34HD8a;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671964; x=1758276764; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=udtwjXvQ+PKffl9W452a1f9YCYGvzKkputvCKlrMZr8=;
        b=bI0I8R+LztUZGpq0X70fUF7y6EgzUZgRkhI0pzdH+3tXDu97pqqZjisza0EWCU7hHf
         6j5VShVqMDt2mz8hs7BBXRH0GtgVc6PuzdZ8wyoQHZbFCFR/0x6EtRZWJBsXpUin4VAm
         vcm/ncBrjVZr4iwRLd9y+rkZpgoiX4hoWb69BAx89OmyheibNM4LQ7o91Uu68idDzCW1
         FQYS9NY8CiGef56zaeXSfdI2VEL+zaaM4RVUyluPYQypBvAjnACxk53hqVlKlyBw7gAO
         FeibgYmmTkd4ICBmo1C2vs5DYT/lbaji+oMhYV7wegBlgbL/2Xa6ttykGR3xBpqYJdY2
         QFJQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671964; x=1758276764; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=udtwjXvQ+PKffl9W452a1f9YCYGvzKkputvCKlrMZr8=;
        b=ZDz5HSJ+S61FLM9dEOf2BsMt/pXWCbtsPBWJSRaH+vxppVWmUM8mci21OFCm02LLDF
         w9Q1wcAc9wnmX9XzrOcXdJFxqrqgUBLFweFGpYS81XPxJGqsUVQ2VAQjQOIWGuKvdizC
         0ZTNTQa8xfstFmHGfCeEzCstMF9bju/Xt1gGgipRH7ddH3CexbwIaDP2lo6i0QKSeimM
         YoqNmISNgz0+LkCc+EJBkF9+emnM2e1c8lrGb6ZZ/e+npmVIZmDHfn/NZMG6PIVASDa8
         R9Ye2W8k8GHrwSGI0gMKwtFcP5c0KdPIuN68yp7R7ayVzfwANbxOg0jdh2Khwt8ZSSdS
         at7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671964; x=1758276764;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=udtwjXvQ+PKffl9W452a1f9YCYGvzKkputvCKlrMZr8=;
        b=ExAyXOiNufYLLIJP6ZVJkJ5SLuP7iwimcEgHEwYA3lprkwpY//NSqdHyAma9BimLIf
         CkEU6OVtJZ02VqNML9odV74TX0sE5e7t6c0mNyXid9cB4/PbpaOCHHLEosygYYdMNdXJ
         j1AgfQXWdZ2tUtgGieSee9xmimVAanQuX4qoTQVtlMAHEwMZWAqnNXcmbaQeU1v67/df
         TyCTMbJl6ZytU55StDuRzvsT52rHx/v7KWW0hSy8np7oDXGgcR32+MGGIIWybSqIPi/b
         eRVoeGy43Do41Verq0EiTpUUZpq8O/w8Chubff/nQwUbLyPebFnZ0aCiUJWYFzos+29R
         IrtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXHMGWIz3OauJv5mIDIfBfFH5W0adQv6ovS43O8yi+ugXN+TytfCZ0vRjzIzD9/JDldRwv7PQ==@lfdr.de
X-Gm-Message-State: AOJu0YzW1xQkYjQcd1uYtaOTwqmOYf3OK8FbZQkP01ckcQaL/AgxhuWU
	+pM7LzCqPFnPhAMHGpWMNfKCtqL7P7liRG3R2ainzUvtwLruhndPLdb0
X-Google-Smtp-Source: AGHT+IG8Mi6A8uBp/x1xbdglpGgivtHSVStqr7t7P6frqp+ho62G99QZTr0CweVzeZLK9TV94CuGmQ==
X-Received: by 2002:a17:903:2410:b0:24c:9a51:9a33 with SMTP id d9443c01a7336-25d24e9df3dmr24094235ad.22.1757671964205;
        Fri, 12 Sep 2025 03:12:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd49Kyw36wjYqMPy11HVJs1HXjsd67rjeXAivq7FOCqh5g==
Received: by 2002:a17:902:ec90:b0:24c:e095:e767 with SMTP id
 d9443c01a7336-25bef05898bls19225855ad.1.-pod-prod-07-us; Fri, 12 Sep 2025
 03:12:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1pp8iiu/ZGDhUCZ+9cTSf3wdCy8cQizNKuJg6SeEcIq5MbC4FaSfciOJ3/P2e7OSQLCe2UP/S/W0=@googlegroups.com
X-Received: by 2002:a17:903:284:b0:250:a6ae:f4cd with SMTP id d9443c01a7336-25d26e4381dmr25293125ad.44.1757671961548;
        Fri, 12 Sep 2025 03:12:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671961; cv=none;
        d=google.com; s=arc-20240605;
        b=HONgpnGwJV4jdecJ28M6katATW5ehBaba6STlGYqASwGQm8Mf8TcuygKU1ORywOI71
         KOxFUNjipIONPmBWfCfr3rN/EJ1dP/prXCaJm4e1VkrJK2OeyPM3aXPYEzXWgry+yklM
         Pqm2NllJkmmFUYcMqCfWCDC4j5JSO1Jf7KnMwTDnqaWqIlWHxHOMJRPJhMiIDDDuLQaW
         8xjCx4bfsawMKw4A6CzCecdMJzmDVT2aRJbbHKZwlIGJWzqs7Zgn0mDi7ouejM4Q3zxY
         JHNbDrTaZtt319aITavp+CSarfZtxl/P30vRBcKszDci5TngUxinCQmjDY/8DRvqObSp
         TsSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UTRhetdXz/AlDveQ7cC4oIBX48CBF691SylMydPRcTY=;
        fh=/QSn7YtWWVIyogC+I1JauTgvXILCRV7t8knZlVdFyVk=;
        b=fWtIpgcQcw5bMldbInD6aRXLNtIRRX1QK+83zQGtdePYfdjR3rAw0ue9x1LHmTw6Sy
         7cHMtuKT1ClKfhuxr9Zc6TPNACwhXXH5zrVDx8//YdsbHIAHPijkHmdPMiIfU9023WQ0
         HCxBbeSP5B1DtqFYX/8S+uapN9x2WIMjIoLYcZD783NF1A6Ws1dnIgb/wt2r8txv3zEQ
         mBQFE7wyRqEiioaVCMC7gLFp1K4uNr1Zj9Pb6iSYqZZ9TCqn1HQQm4qANYV846n3VlNo
         K7IHMo+Z2zgnIqmiSaQn80qb1Rfprl803gR1p3ljPYLYKx55DJaqlwTgZqCd9xFbLXqH
         KHhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Pr34HD8a;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-25c398a2d54si1655075ad.7.2025.09.12.03.12.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 41be03b00d2f7-b4fb8d3a2dbso1255944a12.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXQ8mHOYDxDXBK+TDuwgypNjepPFNbKJGd1FHK6QZIu4iGHoPjJT9jYumydT8X4J7fk42Fq5MX/gbM=@googlegroups.com
X-Gm-Gg: ASbGncsmvsGx0Z94cBs3ctBl28ETktPnppiej+3UHoSlfSxFTsy0+KC2uBOXL29FdDf
	Q1FaJ2DAwWQN6DyXvFgKxo9wKpPkRZlqnVbzdN1BzCNP0egJI7SDTClrXylOuciHMdanYRFD4hi
	PKN9UyD8PY30s3dXsODjvjfZ4dGgJmHnrQ5JDuF6drOvRwj6xeLXzXk5inRzHPwyYewoDxtgX0J
	xMfJzzrg+hBJlhabgXKUzQwcZ1LnvnIcVkkM4qW+o4bcOGU2ZvAGG1P4hPNB4driRHaKcyjyIIT
	5rdvo5xpoInhVC7tephurg2ix5rxC/Ox5CxVB4AQzqZnetOEvmGPzSaHmFEhk30aKX3j57bEuvH
	G5NB9wDYfaDCCHbvTGw9tQ++IPxJvcPx7tmwiagb8hCF3+Tq4XA==
X-Received: by 2002:a17:903:3884:b0:24c:d0b3:3b20 with SMTP id d9443c01a7336-25d2675c1fdmr26411195ad.37.1757671960988;
        Fri, 12 Sep 2025 03:12:40 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b54a398cfbasm4325375a12.39.2025.09.12.03.12.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:40 -0700 (PDT)
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
Subject: [PATCH v4 09/21] mm/ksw: support CPU hotplug
Date: Fri, 12 Sep 2025 18:11:19 +0800
Message-ID: <20250912101145.465708-10-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Pr34HD8a;       spf=pass
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

Register CPU online/offline callbacks via cpuhp_setup_state_nocalls()
so stack watches are installed/removed dynamically as CPUs come online
or go offline.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/watch.c | 36 ++++++++++++++++++++++++++++++++++++
 1 file changed, 36 insertions(+)

diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index 14549e02faf1..795e779792da 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -1,6 +1,7 @@
 // SPDX-License-Identifier: GPL-2.0
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <linux/cpuhotplug.h>
 #include <linux/hw_breakpoint.h>
 #include <linux/irqflags.h>
 #include <linux/perf_event.h>
@@ -61,6 +62,32 @@ static void ksw_watch_on_local_cpu(void *data)
 	}
 }
 
+static int ksw_cpu_online(unsigned int cpu)
+{
+	struct perf_event *bp;
+
+	bp = perf_event_create_kernel_counter(&watch_attr, cpu, NULL,
+					      ksw_watch_handler, NULL);
+	if (IS_ERR(bp)) {
+		pr_err("Failed to create watch on CPU %d: %ld\n", cpu,
+		       PTR_ERR(bp));
+		return PTR_ERR(bp);
+	}
+
+	per_cpu(*watch_events, cpu) = bp;
+	per_cpu(watch_csd, cpu) = CSD_INIT(ksw_watch_on_local_cpu, NULL);
+	return 0;
+}
+
+static int ksw_cpu_offline(unsigned int cpu)
+{
+	struct perf_event *bp = per_cpu(*watch_events, cpu);
+
+	if (bp)
+		unregister_hw_breakpoint(bp);
+	return 0;
+}
+
 static void __ksw_watch_target(ulong addr, u16 len)
 {
 	int cpu;
@@ -117,6 +144,15 @@ int ksw_watch_init(void)
 		return ret;
 	}
 
+	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
+					"kstackwatch:online", ksw_cpu_online,
+					ksw_cpu_offline);
+	if (ret < 0) {
+		unregister_wide_hw_breakpoint(watch_events);
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-10-wangjinchao600%40gmail.com.
