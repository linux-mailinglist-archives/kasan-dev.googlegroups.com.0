Return-Path: <kasan-dev+bncBD53XBUFWQDBB6FJZDEAMGQE7CDKC7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 4876FC48001
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:38:18 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4edb35b1147sf40132051cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:38:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792697; cv=pass;
        d=google.com; s=arc-20240605;
        b=LxA7bF2gebAngoqX/PHTx0pZwZYDBgSJnWScY0ZiU4YSLM/DkeANrwixYhtXHygv3g
         3wA743Wl3Kgr4hq8IfnovQVmqTHgv8+x7hSN1Bc1lhXv+OiEat9XVP3XThJL2X0NrXuQ
         Uiesu7jXBD7fbRTPmFeY/D+qLH6qn7GuPHlxwOb5IHX+mLvXmNPSc/QEGll+QjH5WW89
         OELe1C8ZpB+4w0AA+/rQOfF9Sm+7mKseNkz3xg6UOmlf/2Z3AtOzZlVKAGYk48tD6oC5
         ICh82XoQrGDR/pNQXvrwqVfKbD0JTEtr3nXFJ/2JGKIoPk8eyf8c7f3sO3XbpZaXhhVW
         NC6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=/dG/sSVGNU2+NJtcYOpI84rrwNGW/62z41oihQYOchw=;
        fh=SUl33QNWsix9DLyXGBv9kGmA/0wDuA03LZwY0BHpQc0=;
        b=Y385VnLvABs+rKEmVf+3HefxuvP0KWXboDRp3CL5uLm8S7O4nAXLKu8td+xW4CjVRm
         3kwz5i6UFMo2j1h1XyXUlDoNxsM3rvUl4cGrlbSAP63HoMgCKF2e58Ti8ihjlFpnsvSc
         Vs+v3PtbcgqNqLc37lfDvHOdzOcH07iJ8q7M8ZHb/mcI9+d4KOW1JYBXhX4X2xDLCeEd
         In41obUs6K6UmIQ7+NyxB5hqQFLWMY5gr+4h9ElSQb4OvukgCcuHku5/kyFYh0HDli6o
         QMCAcQWQBh4agIeVL/pDaAKUTEVesUJ/tdIk608ZduT0p06QUlCf9F9YI/gSvYTxFkoy
         V9yQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="c/wZeVEK";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792697; x=1763397497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/dG/sSVGNU2+NJtcYOpI84rrwNGW/62z41oihQYOchw=;
        b=rSTCoN8Dj1sVBZG/27PMIBiZ7lZ1MnWCbAtPJ8AMMbYMu9LhP+P1k6xWH5yDOSUcQ2
         XBcrVDD/6hZcF/xii6bNxFR2emp5StlGTvujzfaPWFKCS6NKTAEShISdH86p7mUL8lLo
         ePmicxQ1c15WJ8extUaC5cNLZ3b4691dtbu5o8Sj+4n4CH7N4pcR41h33lTRiNezhDg+
         mKTii+N46mfhyUcFSfOzlYDuMsFsJE4rJ1ETKxL7nNnIAQX8JO5qn3P2YFLnebYDepdL
         vgV++wK5Wyege7wvkJ4LIjSF1w7JgF93zWvvtDpwhTH3Yc1Pz9uIiyrB+eDj8tMZa9Jo
         eQFA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792697; x=1763397497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=/dG/sSVGNU2+NJtcYOpI84rrwNGW/62z41oihQYOchw=;
        b=CFi65eIQx5XuArW1jYhtj+Wxxe2A4Q9sXFmQWfg0KOJf+QNpA+gJpzygQkhxftH8ED
         Hj9SLbb86TxynP/2UbdulTXV857xnKngOKeSLGkp/CEaNBnHcVHpSwaTleuZosEcMRpN
         z0ocMxWeYuKqQmqaHVZn3X6loNI4qLS5j50Op/u9Pp7kmoEweSJuV24M4J1OiGJlhHcX
         JM72gQrlngxZBiWjDq58l8LZfgv+MpEKLusKxUtpDIzn8u5hroi98hll/jXcKgBasUdu
         VuTBQc+20yHCJTQP9YH0IuXHRuzJmi1l3bkK8CnB4Zviy4sH5TLqoqv3IH9cGlPWEh8N
         95vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792697; x=1763397497;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/dG/sSVGNU2+NJtcYOpI84rrwNGW/62z41oihQYOchw=;
        b=p5LlO0FqAy9gwUJhC+/WfsNQDE4mJL2+I0lolQ81I0GgEpUc3kJfQAffeKddwsDNxs
         HU5JlyyThF6k1dldENW/if6w3Ea5VBVu67y91mxwIGFexVFQp48/07Qyx5pA39nFHL3W
         IDwljy7mW02kLy6ALuHqEDbiAGNokO/WnML6l1re/4WvNaqxBY8vnmdu8OTAGU7zaj5f
         MouJk9HB+TdSxUT8KXcyUGwQqKIi1HtPHdEMJWfpW9y8H0AKNcH2U910Fz3UVQ45Qg6J
         XeT07ZVr6wL+wPtiGjULsGEdR/kTnFgMaqzmhMDq1uhcvAcyfAl3vQBeY5zQTpH/cX1K
         1HKQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVzynloomEBVXTMcDV0E8UiXU6UicZkMGll4JnrjYDiiwLr/bduYsusLJ+zaCSrOLZ/t8oerw==@lfdr.de
X-Gm-Message-State: AOJu0YyOotp8oQ8qEbzDX8TKYqj04K6XpY8AvmzFZgAVoMPHXRpnN0pt
	A5hksJikH6Z6W28x44hn6gJvKs5A6hEVjKMs5hE6tK/flFfbQ0wg5fcI
X-Google-Smtp-Source: AGHT+IGxp069isbw2t2u4wfuGSMvdr+CMVetsWbdX620DJTkTdQZ25Q9xqzfC+wbXqt928BQO7yMVw==
X-Received: by 2002:ac8:5983:0:b0:4eb:a82b:bc2e with SMTP id d75a77b69052e-4eda4fb4060mr101875511cf.58.1762792696648;
        Mon, 10 Nov 2025 08:38:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bW/Q7lsGXiDyO8nGXhKQVwtQhMe5oL7KW4JB020WHf7g=="
Received: by 2002:a05:6214:1cc7:b0:882:3d7d:3964 with SMTP id
 6a1803df08f44-8823d7d3a49ls43914326d6.2.-pod-prod-02-us; Mon, 10 Nov 2025
 08:38:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXJKY36kx2X07esJtel+ExuBhWatoVp4Sxm43KM5Fy53JmsQbq0blthdp89IfRIrALIfxIT2q+Rphc=@googlegroups.com
X-Received: by 2002:a05:6102:50a5:b0:5db:cfb2:e601 with SMTP id ada2fe7eead31-5ddc47b28e6mr3161638137.23.1762792695820;
        Mon, 10 Nov 2025 08:38:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792695; cv=none;
        d=google.com; s=arc-20240605;
        b=L+OFukCNc9tlvhTDsdplfPiRTjw8D/+eBRqUBSJW1fXJ9GcKWfFbHy0MUTD9y+MSmz
         wDvdmiZulJzDVaHy2XQiRzWiXOJg2uRmO9gYPKAoLYvAZyaLPpAMsZmIl0ECTgB/Tsz3
         oHpbNE4ktjkbTZyZX3R9UKlZLw4on62ksohTAV61OZogjuAKsR68Zhrs1Xx0ft46/XDq
         k8/opt7wie8+DAG2aDiz/d9jy21hn8nbB/YHP7J9gF68GYhpx2tTEX1xcejxd6Lzoc/v
         9Yf7owjoSwJtZ5JpPIUH5dNwP5WmYgC9gXrBsnc7S85VfwZxMQZ/ypOoGarKDooZxq2L
         GGzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=LZgTPWUg6fgnNgIWmgc5f2sdICO+ed5Q8W3qiS9yQCY=;
        fh=sW1wFB0z1UvlbooiM7fvFMqgFLSBUum/c80dJj3nxjw=;
        b=BH38uvitPuVUPJurhZ234APJVWB2/FmgO5hd7d0jvNDydDnIR219reFTu2IpK10+vT
         NsH9/hHG/xV7Mrhqs1dVVP0QT2V5nh2MtSooug+qfDfCNi7sNjJnnz8Uq8mIzBjmw5jW
         +DRDssn3+QU6qn5wlXQlGTguZcv9c2Id+T2pzzJEat87UCgc6VMWiLZmobk+bWDFTuuS
         NEDbmn5pNSgYsyCLoFK1iz7PaLOVpg8kuaNcKZ4IjnkBAEIZRuS5irjB6juvppXqunXm
         8vqbWa7C7iaGn6wAvSog707asiUB/u5V8hb9Fn32y0RDu1eQvDrZpWYabNSj7V0hgCYn
         /+8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="c/wZeVEK";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5dda1f73f4fsi358335137.2.2025.11.10.08.38.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:38:15 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-b67684e2904so1986985a12.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:38:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWXuD1MmMYfTEe6FHV+rfKObwf2lcF2iaFOolmr74ZuXO4VEqncXyvExWdRJll7yTul2ed70T/Qnc8=@googlegroups.com
X-Gm-Gg: ASbGncsTZKlPhDCIGUrr+3tmH5JM2YkMfVacwALe3iqBSzKQDE9Xa8q4jgFmq5czXOf
	8sx9G3tjImHY+ytRfPnGBVkC3DB/SSxuCSyt1CpiedUvi9iUxxTVvFvyjyKHJV9xajVdnvrbC5W
	6eGKtvhbBAmzq+gu8/pvwCKKbk8UR8lOBHgDLxsuJphWOrALs9sUu6JI+ZlJP/tjZryhGcnCFpO
	Z8wnttjKHqvMYiQcBrs4adyWNqBXqNoot2eZIvOodM4isobaHV/ooN1EgL+0LQFB9P/ZGHhDhQ7
	Bw3hSVc1sBoNn2V1VRsXa51hq9OQVaLP3R4F7atAprHqzJ4gxuWX9S1ajBtmCfrv8InqdRtCAsv
	OkXtxEfrMCKcgwQD4DQj8t61OFoaOyfgn5Nwg3wbyAlJlx1YlzWAxF2G8vNZXKzAUiXNimPu/+9
	Y5TvZug51s6QXo0AZqYOZoDw==
X-Received: by 2002:a17:903:244a:b0:295:59ef:809e with SMTP id d9443c01a7336-297e564e380mr115227515ad.24.1762792694655;
        Mon, 10 Nov 2025 08:38:14 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7b0c953d0a6sm12288816b3a.12.2025.11.10.08.38.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:38:14 -0800 (PST)
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
Subject: [PATCH v8 21/27] mm/ksw: add test module
Date: Tue, 11 Nov 2025 00:36:16 +0800
Message-ID: <20251110163634.3686676-22-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="c/wZeVEK";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add a standalone test module for KStackWatch to validate functionality
in controlled scenarios.

The module exposes a simple interface via debugfs
(/sys/kernel/debug/kstackwatch/test), allowing specific test cases to
be triggered with commands such as:

  echo test0 > /sys/kernel/debug/kstackwatch/test

To ensure predictable behavior during testing, the module is built with
optimizations disabled.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>

show addr of buf and watch_addr of test case
---
 include/linux/kstackwatch.h |   2 +
 mm/kstackwatch/Kconfig      |  10 +++
 mm/kstackwatch/Makefile     |   6 ++
 mm/kstackwatch/kernel.c     |   5 ++
 mm/kstackwatch/test.c       | 121 ++++++++++++++++++++++++++++++++++++
 5 files changed, 144 insertions(+)
 create mode 100644 mm/kstackwatch/test.c

diff --git a/include/linux/kstackwatch.h b/include/linux/kstackwatch.h
index 6daded932ba6..7711efe85240 100644
--- a/include/linux/kstackwatch.h
+++ b/include/linux/kstackwatch.h
@@ -40,6 +40,8 @@ struct ksw_config {
 
 // singleton, only modified in kernel.c
 const struct ksw_config *ksw_get_config(void);
+struct dentry *ksw_get_dbgdir(void);
+
 
 /* stack management */
 int ksw_stack_init(void);
diff --git a/mm/kstackwatch/Kconfig b/mm/kstackwatch/Kconfig
index 3c9385a15c33..343b492ddbd3 100644
--- a/mm/kstackwatch/Kconfig
+++ b/mm/kstackwatch/Kconfig
@@ -22,3 +22,13 @@ config KSTACKWATCH_PROFILING
 	  stopping. Useful for performance tuning, not for production use.
 
 	  If unsure, say N.
+
+config KSTACKWATCH_TEST
+	tristate "KStackWatch Test Module"
+	depends on KSTACKWATCH
+	help
+	  This module provides controlled stack corruption scenarios to verify
+	  the functionality of KStackWatch. It is useful for development and
+	  validation of KStackWatch mechanism.
+
+	  If unsure, say N.
diff --git a/mm/kstackwatch/Makefile b/mm/kstackwatch/Makefile
index c99c621eac02..a2c7cd647f69 100644
--- a/mm/kstackwatch/Makefile
+++ b/mm/kstackwatch/Makefile
@@ -1,2 +1,8 @@
 obj-$(CONFIG_KSTACKWATCH)	+= kstackwatch.o
 kstackwatch-y := kernel.o stack.o watch.o
+
+obj-$(CONFIG_KSTACKWATCH_TEST)	+= kstackwatch_test.o
+kstackwatch_test-y := test.o
+CFLAGS_test.o := -fno-inline \
+		-fno-optimize-sibling-calls \
+		-fno-pic -fno-pie -O0 -Og
diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index a0e676e60692..b25cf6830b15 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -235,6 +235,11 @@ const struct ksw_config *ksw_get_config(void)
 	return ksw_config;
 }
 
+struct dentry *ksw_get_dbgdir(void)
+{
+	return dbgfs_dir;
+}
+
 static int __init kstackwatch_init(void)
 {
 	int ret = 0;
diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
new file mode 100644
index 000000000000..2969564b1a00
--- /dev/null
+++ b/mm/kstackwatch/test.c
@@ -0,0 +1,121 @@
+// SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/debugfs.h>
+#include <linux/delay.h>
+#include <linux/kthread.h>
+#include <linux/kstackwatch.h>
+#include <linux/list.h>
+#include <linux/module.h>
+#include <linux/prandom.h>
+#include <linux/printk.h>
+#include <linux/random.h>
+#include <linux/spinlock.h>
+#include <linux/string.h>
+#include <linux/uaccess.h>
+
+static struct dentry *test_file;
+
+#define BUFFER_SIZE 32
+
+static void test_watch_fire(void)
+{
+	u64 buffer[BUFFER_SIZE] = { 0 };
+
+	pr_info("entry of %s\n", __func__);
+	ksw_watch_show();
+	pr_info("buf: 0x%px\n", buffer);
+
+	ksw_watch_fire();
+
+	barrier_data(buffer);
+	pr_info("exit of %s\n", __func__);
+}
+
+static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
+				size_t count, loff_t *pos)
+{
+	char cmd[256];
+	int test_num;
+
+	if (count >= sizeof(cmd))
+		return -EINVAL;
+
+	if (copy_from_user(cmd, buffer, count))
+		return -EFAULT;
+
+	cmd[count] = '\0';
+	strim(cmd);
+
+	pr_info("received command: %s\n", cmd);
+
+	if (sscanf(cmd, "test%d", &test_num) == 1) {
+		switch (test_num) {
+		case 0:
+			test_watch_fire();
+			break;
+		default:
+			pr_err("Unknown test number %d\n", test_num);
+			return -EINVAL;
+		}
+	} else {
+		pr_err("invalid command format. Use 'testN'.\n");
+		return -EINVAL;
+	}
+
+	return count;
+}
+
+static ssize_t test_dbgfs_read(struct file *file, char __user *buffer,
+			       size_t count, loff_t *ppos)
+{
+	static const char usage[] =
+		"KStackWatch Simplified Test Module\n"
+		"============ usage ===============\n"
+		"Usage:\n"
+		"echo test{i} > /sys/kernel/debug/kstackwatch/test\n"
+		" test0 - test watch fire\n";
+
+	return simple_read_from_buffer(buffer, count, ppos, usage,
+				       strlen(usage));
+}
+
+static const struct file_operations test_dbgfs_fops = {
+	.owner = THIS_MODULE,
+	.read = test_dbgfs_read,
+	.write = test_dbgfs_write,
+	.llseek = noop_llseek,
+};
+
+static int __init kstackwatch_test_init(void)
+{
+	struct dentry *ksw_dir = ksw_get_dbgdir();
+
+	if (!ksw_dir) {
+		pr_err("kstackwatch must be loaded first\n");
+		return -ENODEV;
+	}
+
+	test_file = debugfs_create_file("test", 0600, ksw_dir, NULL,
+					&test_dbgfs_fops);
+	if (!test_file) {
+		pr_err("Failed to create debugfs test file\n");
+		return -ENOMEM;
+	}
+
+	pr_info("module loaded\n");
+	return 0;
+}
+
+static void __exit kstackwatch_test_exit(void)
+{
+	debugfs_remove(test_file);
+	pr_info("module unloaded\n");
+}
+
+module_init(kstackwatch_test_init);
+module_exit(kstackwatch_test_exit);
+
+MODULE_AUTHOR("Jinchao Wang");
+MODULE_DESCRIPTION("KStackWatch Test Module");
+MODULE_LICENSE("GPL");
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-22-wangjinchao600%40gmail.com.
