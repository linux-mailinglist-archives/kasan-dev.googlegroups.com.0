Return-Path: <kasan-dev+bncBD53XBUFWQDBBFXER7DAMGQEDM35XTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id D111EB548E8
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:12:40 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-76e2eb787f2sf1756853b3a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:12:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671959; cv=pass;
        d=google.com; s=arc-20240605;
        b=KaH37h4G2R3bcnUAO52uMv5gAtLY5rVHM+oa1nIYZpHt0RpvfUnyYDBqdQH+QrpbGN
         U5bnHBvmirXlYn5vJ57IdLFpq+SwYKDOudXUHEykGjf+lxsoNIknkQjpZ6YRACNBsDqm
         o0le/Yo8OCDCmWqp4xVGUeALwQfw/GTxL17Uf2V4ZU2pUycHUE5YlBpEoTA0J6fBeY9j
         ZVGjAA7hbwALYHLjMyAYNfLzGfzg+iLazrJdnAh16c1/xLiiwPM3x6UCb+f3X7+pj193
         RGGCnzSacADSbvmjnxmdhWiK65tJs6q6XmrCjhpPq4sYJapPafan4c19+84yyZ//+Mc1
         stZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=UvzY+JOEVziDU6R/GSilK11FOyYL83fykqpwhGHRt1Q=;
        fh=rTSBKRzj5DOz265FDah7JVpLxIVm3rVcsAoE5dxrkCk=;
        b=D9+/Eti+GjuK9T3y9vn1syfT/GnLdVgKSBds7R2hHDhn5ek59Jz1671Gfl/C8qcVCb
         FcbCZJypImxFP2i2vvLE71HYrPtD5cekbl8qOAbiLT+/H55lRWApoB6CwQ4++s+HRSVt
         GzVkaWIEOnX+1XCHl+dTkWX2ILgZK1u5Kn8tFymJMImvlRx8bi+L/qmcUeZEB/StMN4y
         zUMxkn3lwQ/jQG7S1/0x6MZAWW41EZa/eYJE5eEUMtO6d6+InOi7xEFdXviSMp80KPCN
         CUHUdQ6+dQ7iMjKrFB+zhErKsvwyifoIFdnwgwSt7eIe2jaLiApdkObtcXP/ZVOBCjwK
         wfyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bWFYuRAo;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671959; x=1758276759; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UvzY+JOEVziDU6R/GSilK11FOyYL83fykqpwhGHRt1Q=;
        b=XTpFU6EUb1tzBMIIHLUX8A7t6UNKnNLjgbBoRnC/hsobjX9h9s6xjVlo21t17YA+qu
         bmVC4Zzw3mRj3q2ftHilvCcXmz3CLOIipSumS3gvP+XDilJaFFkuvlpmQkrSS6hhtGNi
         8lvvQ8iMQcEvWGrypz/Rezz3N6k4Oqw/lr5DFNSByFNfAEbqviZrMK8uIURFxWhPcup8
         UAliJjqXQ4CAPwmEc9/ErsyYQURMDzW7gPm/NwmMGGV1p2jUOPB+cEqGuD9lhCxWgsfR
         9kmk1Yd2Be62XINCsnMV9S4+VlGaBXLgSD5gu3+IVj4ingvfr/TLSxCphyGOHu3sG/rm
         exCQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671959; x=1758276759; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=UvzY+JOEVziDU6R/GSilK11FOyYL83fykqpwhGHRt1Q=;
        b=Ij6/CPLPvkpUJnMYKPHaWmFk5ut7szTfaPWOSaamNVbKWyaxS0ZKh5YOkcKVbsxpuL
         8IrqaEJXf85yk7kgjrzssi8iS0VFSIA4mgvFOjtSsRZiGZHy9eYkvZ3dyV9WET3WVMhf
         psb/A3Vijar2QmqyP3JNwApr/4jIehzom8YUGXW+VsYc9OZFYEOEAIfPuqm3no39tGMm
         ONtZTdUgHyrWAWhLxSmwDZ4sSU1QxtdNT7QB4/hXvkRygC0rcc5si1dKm8adVSvIrOgi
         JHV3N4hV0AVhAoWKfQqTtyJLGEE5qmE6HuV7EXm8IoFH0kX8k30EBdKO7mMPJHaKT0L5
         RrpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671959; x=1758276759;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UvzY+JOEVziDU6R/GSilK11FOyYL83fykqpwhGHRt1Q=;
        b=g4M2Ea4roxe0j82zW0c1Ie6J9UbpKKf+Xoj+qGJxEm+OjLreUoFhg0XCrs6IWUM5T2
         PEF2rp+Y5Uz3zfvWKT9lqVrbAltOM0KqvTVvyfWewPx98zFy4GxGoPKoTXL3Rw0u6/7Z
         FrG9y+DhkaZpM8gB8tX7+o4+x/AmYnwUw5qyvBpm6w8OryuCmyyjpcXFxaeK4LIj1CgS
         YX8SqaLbqBAn2IPOW/m3g2N02/mflpIpKTmEvldeReXe96iDftJKsx4Fj0gdj9kVlpxs
         YieRjgUVHHMgeMC07kBcG7FBJug0vS7dqYg0yLO6V6THGdpswqHckfm7B6iLPNCzOC5m
         yp6A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUzbA7VEiYpQQUedMweZhX8aNkwBiqo9MNiYMwIIj7Fm5KrJq30xX8K3emNq0br2oGd+GOuQQ==@lfdr.de
X-Gm-Message-State: AOJu0YySE8Yv4lgGi7Sm9o1R6AwEosTn/GScdRpXTGlyhmdNgTzk3jsA
	5d3X6FlgCNCz9Vw202go1zmJPEYSv2G/byUhqqQ5qGJk6MCfgJkDBmKD
X-Google-Smtp-Source: AGHT+IGvovYS2BDLp2wHZHIcpzmArk9/CauJqbDnhjKoGVUFQYurU+LErMZ0DNsjbOC75b/Av8TtlQ==
X-Received: by 2002:a05:6a00:139a:b0:772:7215:e513 with SMTP id d2e1a72fcca58-7761216bef4mr3152205b3a.17.1757671958804;
        Fri, 12 Sep 2025 03:12:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdYRZzNvSxr2Rkm+x1woBSjt/kOwuLOUZ0Tc5CXWtS/fQ==
Received: by 2002:a05:6a00:4981:b0:776:150a:33ae with SMTP id
 d2e1a72fcca58-776150a3529ls614167b3a.2.-pod-prod-02-us; Fri, 12 Sep 2025
 03:12:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUqNIYtti2aWt99+NvKnbqQMSwRYwVsX6xQ7DuZD2y9rfKhh4kAq4B+VDnLJcLfrBO1NbO0gAwfyJ8=@googlegroups.com
X-Received: by 2002:a05:6a20:258a:b0:249:3006:7573 with SMTP id adf61e73a8af0-26029fa0d2amr2846189637.5.1757671956932;
        Fri, 12 Sep 2025 03:12:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671956; cv=none;
        d=google.com; s=arc-20240605;
        b=UyulUdXSATKI9YYcWRtxVP0I00kBLsl0ak1HSDbkiOfY81IMK/VygHm49kts5rzM3A
         xjMfYnPPhFqsLEjmwb9h/uw4hxM/XBIzyAEYW5OvbqkAfYVCK9j3RNYkxZYznF4ji2IN
         b7toJE9ybUNcbJKJENe+icgHDTxjSJYZsVFEVSPMnqLlLn9h7XsFe+plcQMqcJhk0TCe
         1ymhS3HoCEdZZXYHDRrsWAT5Vs8un7SvFXc6TXAthAMpKOdI+E1yLkbpdrU3hKFkw2gN
         ORL7EFOMwccdeSB2W2N91D5HwgiJx0/m7BHBJe//v/xQWd/JuGXOc+ZBu3n2ffBIvGVo
         KCjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jBWUZGT7AQZjVN5sSaCPPhxiXndvcDbF8VJhhLu7a/o=;
        fh=7iY/WyN2loyBU7xgpBjiMw3zOGyLQvxWCI5uz1XRC40=;
        b=Hi3+HeWmsUY08ZeXkxz0+bQffes1gNCu321MPFdQyab/1/QJHKlDufxpYCAPljPxJA
         7pVR1TnkBUCH8AMmLFXKgn6FlmzpwQxpRjTFB52b5QQGSUdy3V7pyB6+bXPCXt2Qi7Gi
         2qbNUyiy+GtEr0HyS3SBjbiPpA/hOTgJZXnZ2yrB2+ipZQy6Z7+L2xSglGo/YiswzIQh
         Lcv/hxLRYWfVPIwA3gk0xujE7mSjKb221E/p+AFxPyzmjfgza8p3qyFAx9La8L6uzgDb
         NYzFME4zVIQforOhZQuXlzXrne7wYbrva7/m4oOINVbDbbhrbxN0B0nP9u5rPa8E+1mJ
         J5rg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bWFYuRAo;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77607b487f2si173452b3a.5.2025.09.12.03.12.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id 41be03b00d2f7-b4cb3367d87so1131340a12.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUp8CjsWac08S2xVhoIr6R+MqE3lQhdaOzC3eCHfxwPxz3F9abcsysriR1Nwg9YQVAewAULy71O49o=@googlegroups.com
X-Gm-Gg: ASbGncuOqxnF00O+6sM8hN2X4FnNkM90mIelhPY2tDrKdb6jMN6vHDI4mMq5eotQl5f
	fwgqqixgtfaP6HdzDN953e8PIgBRBRW7zoY5rk5DLo4nnuaAgwY05B5I7Tu60+XVPDckiUkr7IY
	25E2VegPpRmV3VRHV2fv3drC2vd2dkvf5oLXTGT1Zr5gr6+gLSbLMW8mmbpClh2IljIBCQ6VcYa
	mYPtKGm5b9cge/rluQ22DWzCmjZF63Q0VEOF5VDQL/NvN8BmxAv30y//QlyiMLo/EPd+8xJ4XwJ
	7naXpXD+RzKNk+79qxxR0GAF4Obyp/fZhFRcVT9t9+PkLJ2FLxGuNgvf3NeSb94ojSUooy/Ly0u
	5kobQLBVHzoJpnjkik0jo19fBI2BL6EweXmBERmcBRrpfMos8gQ==
X-Received: by 2002:a17:903:3c4d:b0:24c:cc2c:9da9 with SMTP id d9443c01a7336-25d24bb3201mr28288785ad.14.1757671956234;
        Fri, 12 Sep 2025 03:12:36 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25c3b307073sm44099805ad.144.2025.09.12.03.12.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:35 -0700 (PDT)
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
Subject: [PATCH v4 08/21] mm/ksw: Add atomic ksw_watch_on() and ksw_watch_off()
Date: Fri, 12 Sep 2025 18:11:18 +0800
Message-ID: <20250912101145.465708-9-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bWFYuRAo;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

The atomic_long_cmpxchg() ensures at most one active watchpoint exists at
any time, with ksw_watch_on() succeeding only when no watch is active
(current address is placeholder) and ksw_watch_off() succeeding only when
the caller knows the active watch address.

For cross-CPU synchronization, updates are propagated using direct
modification on the local CPU and asynchronous IPIs for remote CPUs.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |  2 +
 mm/kstackwatch/watch.c       | 73 +++++++++++++++++++++++++++++++++++-
 2 files changed, 74 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 3ea191370970..0786fa961011 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -41,5 +41,7 @@ const struct ksw_config *ksw_get_config(void);
 /* watch management */
 int ksw_watch_init(void);
 void ksw_watch_exit(void);
+int ksw_watch_on(ulong watch_addr, u16 watch_len);
+int ksw_watch_off(ulong watch_addr, u16 watch_len);
 
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index d3399ac840b2..14549e02faf1 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -2,6 +2,7 @@
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
 #include <linux/hw_breakpoint.h>
+#include <linux/irqflags.h>
 #include <linux/perf_event.h>
 #include <linux/printk.h>
 
@@ -9,10 +10,16 @@
 
 static struct perf_event *__percpu *watch_events;
 
-static unsigned long watch_holder;
+static ulong watch_holder;
+static atomic_long_t watched_addr = ATOMIC_LONG_INIT((ulong)&watch_holder);
 
 static struct perf_event_attr watch_attr;
 
+static void ksw_watch_on_local_cpu(void *info);
+
+static DEFINE_PER_CPU(call_single_data_t,
+		      watch_csd) = CSD_INIT(ksw_watch_on_local_cpu, NULL);
+
 bool panic_on_catch;
 module_param(panic_on_catch, bool, 0644);
 MODULE_PARM_DESC(panic_on_catch, "panic immediately on corruption catch");
@@ -29,6 +36,70 @@ static void ksw_watch_handler(struct perf_event *bp,
 		panic("Stack corruption detected");
 }
 
+static void ksw_watch_on_local_cpu(void *data)
+{
+	struct perf_event *bp;
+	ulong flags;
+	int cpu;
+	int ret;
+
+	local_irq_save(flags);
+	cpu = raw_smp_processor_id();
+	bp = *per_cpu_ptr(watch_events, cpu);
+	if (!bp) {
+		local_irq_restore(flags);
+		return;
+	}
+
+	ret = modify_wide_hw_breakpoint_local(bp, &watch_attr);
+	local_irq_restore(flags);
+
+	if (ret) {
+		pr_err("failed to reinstall HWBP on CPU %d ret %d\n", cpu,
+		       ret);
+		return;
+	}
+}
+
+static void __ksw_watch_target(ulong addr, u16 len)
+{
+	int cpu;
+	call_single_data_t *csd;
+
+	watch_attr.bp_addr = addr;
+	watch_attr.bp_len = len;
+
+	/* ensure watchpoint update is visible to other CPUs before IPI */
+	smp_wmb();
+
+	for_each_online_cpu(cpu) {
+		if (cpu == raw_smp_processor_id()) {
+			ksw_watch_on_local_cpu(NULL);
+		} else {
+			csd = &per_cpu(watch_csd, cpu);
+			smp_call_function_single_async(cpu, csd);
+		}
+	}
+}
+
+static int ksw_watch_target(ulong old_addr, ulong new_addr, u16 watch_len)
+{
+	if (atomic_long_cmpxchg(&watched_addr, old_addr, new_addr) != old_addr)
+		return -EINVAL;
+	__ksw_watch_target(new_addr, watch_len);
+	return 0;
+}
+
+int ksw_watch_on(ulong watch_addr, u16 watch_len)
+{
+	return ksw_watch_target((ulong)&watch_holder, watch_addr, watch_len);
+}
+
+int ksw_watch_off(ulong watch_addr, u16 watch_len)
+{
+	return ksw_watch_target(watch_addr, (ulong)&watch_holder, watch_len);
+}
+
 int ksw_watch_init(void)
 {
 	int ret;
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-9-wangjinchao600%40gmail.com.
