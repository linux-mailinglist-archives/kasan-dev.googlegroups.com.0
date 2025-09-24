Return-Path: <kasan-dev+bncBD53XBUFWQDBB3NWZ7DAMGQEDF6NKYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C2EFB99AA6
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:52:15 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-77f2191717fsf3042961b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:52:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714733; cv=pass;
        d=google.com; s=arc-20240605;
        b=EXw8hX5PGiYYOJS+fZkiAFyGZ+sZvkDIMWcituCSbCERFELj6IRAgec3aQXvm0/pRQ
         GuWBP/hauV5v4ASfx3y/B2kX4+35BByeqx3erzbVdzRXlLSJRum6TI0gK4dEjED5Ygy0
         f78BbJ5NCpqahLQ63c882DV60F6cEMhHbhC/ImF/qGG+i3EAsbHFSQyr6sIr58zXScJj
         3SwCiia4dmR4sZ0Sd/LBBO4ZsBDIwSlgcwYhmpKO6GSkfP5Zx0m5lqYpOh7JTgL36/F5
         4/zx9pRF5xae8MmqPXA2J70A4qmVZRQa+gmC+SozqK8M6EKIeVaOXUr9LzxhheoqY8DH
         a7gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=xke8DFOJ+8H0wdqqvvoNzvJr1jvL5oWxe3cOicfuIXI=;
        fh=a+sOK/K+RgNRKE8GzOfWYRnXptsUYmg2fCJOrS3PKhk=;
        b=HD3GOY4MPXY5q5km6laAKO4Ix5cEh9QKqq2QIthcxdzVn1+xnU2znLaTeTtOS6RbiG
         +Bhyy4ekE+AVtQ1xhMrXUcwMrR8XC4jbFoPtFvb79vNfzIl+ynsr22W0uFAPlLYFwGLy
         5XtchH7wYfVJqo5nF+qNSabh+EC7VK+eCZvgVe/CV9RT0Je5h0NhOJDnUFq6P0YCOaoT
         ECha+X9hz94FTXXRXpCFATd6y6o+qOOdAM5iaJ81th1ZF30Bgp9+/gFw7bhuw7lnsUSh
         hnEZmZsgMfWeJLr9Cvsl6ZBLYU2b9QiSInET1EyjDpIwdrAWHpqrJsSgnKJs1PonexMF
         Gbjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dATCfG7P;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714733; x=1759319533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xke8DFOJ+8H0wdqqvvoNzvJr1jvL5oWxe3cOicfuIXI=;
        b=c7xFUBFiGdbVCm0f74gXYoRxQWEywUOVDPx6JofLsxyrFOGl8O+1k5eABAWpkt19/B
         J4cmBPc4QorAIrLEpFwOG/skVrWggwbCS6U85g0FU0OZPVMe0DGbGs5rswo9WIgn6xD9
         a5kjY8gLNTPjD2uQFAziv8UgC40wIO+V4YYO7OEi8GqHuMMTy4+1vFIGPUb7/qHX+Vcy
         dCJPK7KSEYnBmS1E/Jj0YHCVsPcjy6eB8S/PHBcpZtpdd4KIMtd/eHl0OTqFySFeD4XJ
         hFtudOR0j+oYn15lhmfnvpFb/WpOQHgGgoAatEnXkjhwMd2/k/X5GCqOdBHybceWnA8p
         KKgw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714733; x=1759319533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=xke8DFOJ+8H0wdqqvvoNzvJr1jvL5oWxe3cOicfuIXI=;
        b=lkxtoDkzkxlnlUakmNBgOEjQtTe0KYXw4zC+IGVuBiOpYOAm3HOeeWfJ2bstbY0YMB
         rti+pzWAq8nNsD7NVP57aMFR1fNwPOgLPfOyTVWGVDwBgZBeiGs8J8MEw1F7/n79zmqz
         /h2Yo6a7PrAsHlvcvR96fVUFZrp26RvLV435dVFiOGLcKISfhETJOzF60srPoiUvy11O
         z0o1BeUVZnOStuWFlJisdfhr8aMIU/jVOmqdupJcyUa8PHLH7vlI71rSfhz0Au3OYHv3
         A10CqThOn0xtwNnt+R0f0+trwVNE2x4N1kylV3192BI5uyfKMf33V8xMw9QGHK7W34Ec
         IqFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714733; x=1759319533;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xke8DFOJ+8H0wdqqvvoNzvJr1jvL5oWxe3cOicfuIXI=;
        b=rKwKJ8vqLtGQq0KSmJ3i+Fr7Q+5cfSZbodGrF0NycPQv/xLNvtvEOiJYZdt66yNnTS
         4/3nOUEManBvtvTT/kE+DtuAS8XeffBRyxGqQ4j58/EQM9BRkenRsuTNMWG5QUoRPvdI
         m08ouPsHTJTG4fj6DmknXdevSlGGEKR6E8LvBZ4UHReBni4QeCldWhSQaIL4vo5bYMXM
         0KQk3+aRGrz6bAem3cBFFhvc+HSXcyh3+tnwv/3Q/fsDLJStPvgYIvnlZx1QL1wC1126
         0TkR+v3fsg1I8BQQ6upoRlf3AVMM+ZqAqUKRxRgzXfJTCn1q0QWOEOZahq/lqjxcc2z4
         tPyA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVehI5kIYPVAxKOKf3r0HH2SD24c2KizKJLQGoYGCJA8GAUxgA4vr4doTgdtm+1o6F6InirSw==@lfdr.de
X-Gm-Message-State: AOJu0YxddKL0skpsx7DeysWmZA4zkfM6t9/KxMkA+p88ysnYUzs3W3ub
	OX+9v4b9NWWnZl5bBBmTDa1ARoSD4fAbbvnpngo3wA/pEbl2Q1w+fr1Z
X-Google-Smtp-Source: AGHT+IEnqW37kmB4xpAm/4WszxvR8AubAztWOASy7/czaR9TC+VBW6/OKt4x4y72wBT0i+vx1wS4dQ==
X-Received: by 2002:a05:6a00:6081:b0:780:fb3f:9127 with SMTP id d2e1a72fcca58-780fb3f94e6mr136717b3a.19.1758714733524;
        Wed, 24 Sep 2025 04:52:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5AChT5Hs0c+z6cNtfcTdSUG96gJMbmp/rHYb2IvvRP+g==
Received: by 2002:a05:6a00:7d5:b0:77f:6ab4:c999 with SMTP id
 d2e1a72fcca58-77f6ab4cf2dls660285b3a.1.-pod-prod-07-us; Wed, 24 Sep 2025
 04:52:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXGKx8zAXhlpdC3FN0Fsmiu2TbELBG/uNvG+ZWzESpflk8rduaddWAZT216auSvVxIvcXzpbBWBOM=@googlegroups.com
X-Received: by 2002:aa7:8891:0:b0:77d:9aa5:3bb0 with SMTP id d2e1a72fcca58-77f538b5d17mr7183794b3a.9.1758714732008;
        Wed, 24 Sep 2025 04:52:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714731; cv=none;
        d=google.com; s=arc-20240605;
        b=UaMuCZ8UfZFhhIcdT9LqgbbQJ4Rer3c7LrKBJZ649vsz97XF86R+yjLsd4JUkwdrHW
         aBFcx/ifg1MlRPNP8tN05085WyJnJ8E4B0BgTwmooVxgB2GOCzGI85McTFrj++ogv7yz
         9OgGfqmHV3DB9kyjZsYRCsP640R5Sy0unH+JrufYnz5CMywW7t3Nzyj8ZZkT+7nEtLJz
         UP6Jyza6JtZT/2CeUuTRWwsiC5XDPZWfG4qdW+yqFw3/IvsMvhpZKxqAnQVxR5a7mpzw
         ouKwPqMR7HPoQ1Izg7sHmCzONvf0l3KDIO4/BWOKjDjG4Z16Bm6VPJGwKrx3vnDTHlvB
         rLqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VplC5p74+BCL3Xjzqw2UL/AL1hevTQUKrGPaYOT40mY=;
        fh=H7pBAqeldgTwQ71ZFafBA8dtCJ4vdw8Cswp6QK+ydQI=;
        b=GTPDNoKP55bFX0QkM8jwX29/hQvxbpSZ2XYLkZLQdIoefYTrnryzY1gUL3JUuM5xxU
         kZUDbsCwENHJUnoGtxL2AQwaFB7bnqUS4T/c7JXuEl5x5pZ4WL6czZA6fWZwKtp6hnPM
         k/qmRiHe6L+JDHEqEMG2xUco5STQF6AYSVbPrT+/0AIzjCaLwcAC65wFA3bGvBqj8p4a
         JBNiE5MrXVZU+lfwGeJb4GgSjYOVvCqroi2jZIDj9J4Yswa7Of39KpOH0mum3/XRpaWM
         Dm1SsQ6Swrq2m4zOdPhVwAjkCg5nB+XMIOgtn0MpHz4UAjYCZTo2WF6RZdmA9r/ToYYw
         KtAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dATCfG7P;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77f6443ecd3si102109b3a.0.2025.09.24.04.52.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:52:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-279e2554c8fso34136035ad.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:52:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXEHH5ev6dhgjSgoFfxYZjvdsea4yxPaA5pk+ZuLefU3T5bi0HVObitHnvvDUeLHxklIgZ60HMKko0=@googlegroups.com
X-Gm-Gg: ASbGncvBs6WW76XO15hh8qrLugAVAwZpxPEdFEsW36+SuIeS4wqVrJwehQBZVAL1uPJ
	37MpllTMlghpOQP0GsKPFQerC5SDuJWrH5t7tij2cLp+2tKleHNAO+j9cjSEOsKQER3j0k8TKCQ
	pOs2mzvkYm6WzMBxipgevFGxb3utxcieJuWvrRNLfstRUEyICjPk3/IKSvFYdl60AaNlkqHzxgw
	ZHe0AEPlC4bHAA1wnZB09hANQqyYrAjIRYu6Aighi1DpE+ntXtxA2OvzlNV06Xykah8CQB4bWXG
	kN5PaWChnUmQWwSxlQuVlSMGu60kXYm2K2DhmiVvlIpFxgIgGYWv0NTkCfrO97tYrexCUEC2G0M
	NSaIlgnSu2ipy2AZLfzE8wec+rA==
X-Received: by 2002:a17:903:230a:b0:273:31fb:a872 with SMTP id d9443c01a7336-27cc2aa7dc7mr73054015ad.6.1758714731497;
        Wed, 24 Sep 2025 04:52:11 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ec0eb4293sm18798485ad.138.2025.09.24.04.52.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:52:10 -0700 (PDT)
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
Subject: [PATCH v5 10/23] mm/ksw: support CPU hotplug
Date: Wed, 24 Sep 2025 19:50:53 +0800
Message-ID: <20250924115124.194940-11-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dATCfG7P;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-11-wangjinchao600%40gmail.com.
