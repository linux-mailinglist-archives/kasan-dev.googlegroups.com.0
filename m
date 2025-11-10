Return-Path: <kasan-dev+bncBD53XBUFWQDBBZ5JZDEAMGQEKDC46SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 57E4FC47FEC
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:38:01 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-656c93b4b63sf2263798eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:38:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792680; cv=pass;
        d=google.com; s=arc-20240605;
        b=RcypPFVFkQaHtfJbY5MFgiSbDfii56n+ZpqOA6vJM1BpSQBazY1Gdcwj2tElYZkNoM
         P0uHxPBaqAFF/bkzgTJW4PMFg0IlIVE1f6iXf8h5gHodawF4pz9kTzQm2F06F00coZfI
         paflnSqKq4c0oCBzQuXNvp76B8gfphCZPt65oG2dvG+TnTH2uD3jj/ST7ecAb6WeRl5r
         1whYfhnwwPN1H3oowCYXpeTEykB8Kt+PcvjL8RZMW9cvC6R63/1itzJPoc1tW8ebrDPA
         ov9VDjKc3LtIY6mjOpXvOFZzr1EGP85J9tsq1NWo+cW73K2i3zRVaTRNRxNhUbfZYf0e
         jFEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ETIyWbTCzjhqaQHjpMZC3pMx3pUmKIml27/O1c3QHmE=;
        fh=M7PxaMNMKqOLf0IoGUsn5TdGkCkS4zzAnxZ1tYZ3ySQ=;
        b=gsSKFVIKmonj4DjX3fX6RKtzr1Q7UyIEBcgq2WPea8xSDl4/WAUvlU3X97qmb3BVHM
         Bpq13AC7Lfb9rClRBh+BFcHwFzGncrq9A83Zn9KNmREdoHYHugqDl/xWxf7uWIGacRL0
         Ga0tDEKHhenMRpGcXuw9Wr0li+PRKBQr6cZ+qKIL0McHlkiFlHsm33sxwcrqKPrB1Euc
         /RBkU1K3NC3kaXJYV0mpiXZNrJu2jlERj1+euhtdApwytrMK3nrbTqzhNX38og1mf/Gv
         JnFl3fnbksBJMpDkBGe8SXDcoXBYwtnYZNb9SRkdV2YmbXmZil6VOTv5+HGKKgA9S0KF
         aC7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=i4VvdvAg;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792680; x=1763397480; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ETIyWbTCzjhqaQHjpMZC3pMx3pUmKIml27/O1c3QHmE=;
        b=ZVsefcZaCSL+A5gHX/7R8xmA98ZkOKqBnA4XB9f/Tis6BTX8ohDbp1CiqUhZdjl1nM
         nJfrR7KAKPFOaSSG0QrU6vfrWqKPphM8G0XRFlZ/bog0qtanXVslbLGy1FIUwN3askZG
         ZdOdG7Tw++kD8OM+nWckrbSJRIZsZ9LQKqLqdUOa6GRI/qoTb0Q3Spvem4sQecqOmUPg
         dgoSCSt6G9EFMEnobgyHKFxyBKZLKhaZSVlXq/0S/HV76VElOZusinzinRxAD+4YMfee
         JmEjslJEwrmI3Owa4vg0XzzlNm+GbzhUvDw7VN68dG/Y6KCSzG4fMDDZ+zh4VYzvqZbh
         vPIw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792680; x=1763397480; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ETIyWbTCzjhqaQHjpMZC3pMx3pUmKIml27/O1c3QHmE=;
        b=fw9lu9XlPDB+pnQPEQRgVHsezxYRNsDEarg6MW2ktr9egq3wGxtsABfrTQy177OCTy
         QaxzsrKYdBsrpYIVdt2nmIf1ThuNCuTBGxWgLywQ4XNG7luJgxqwzqT1k7w8+1oVkxP1
         NuaEokhCwNe/LR2ht9ebl2ejQI103AwUlIXZCLLLVS+LHWWJV0Jny/cIuk0awhR0CBVQ
         CAdxAG2Q/AbGGfL962icGqDuNRMLn1Euuu8UOfoLIfIUVUYEy8nXZg+Q71iX7zuyitnK
         +6nY4AgPyzB9Oc61g1P5UsqO3rRTt9B4oHhpVoLs3QPu1uvkf2oynt4ed1JuKNWKIxkX
         QFvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792680; x=1763397480;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ETIyWbTCzjhqaQHjpMZC3pMx3pUmKIml27/O1c3QHmE=;
        b=fVPb96YjfSoNu2cQ/X62pl636v/hO+MU/h4VQneC9nYskjeWxERYrCbAqvmr6Gi4Sa
         iQIPPJHfgs5H6j6hBIKuRV1g/hFqKXt8OJIv8UL43Q+oO+/cA/1HURBAPubno7XSeiWB
         u0wicGX/gYPnnB3wn0z+eajmOxGjeKko27qCu+Ue1Lyj4S7W+LkBERL6UWfQyylqbS4u
         r7Z7AkWVw6AhsS9pdq1iGdh96I2GcCxW2xVVEFsjEDa/WGV8cVJbFKgeacIFVe+0fP8e
         QbunyTOHGkRQMsMzYvdCjXNbConvVzOoL4+dzJucZYfs/Dngb551OfO4d4FLEHT6kQtC
         FO3w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW21UEZYsR1qD+mYO0+fDnKmBPKxCcKPvyCl8Wm8PTH2U7Or5MuiNdvdkC8TbIgButZM90tsw==@lfdr.de
X-Gm-Message-State: AOJu0YyuQf1o4z8ass64PxbBCmBHQ49pGl9XjoGjUB1EJE5Mkb/u8GnS
	oWoDaR2XhqlIlfYhagvpkEaemYHiZwhK5zxGcaLHccfEPaDbKdog5ZxU
X-Google-Smtp-Source: AGHT+IFu+H2+XD3JIA9lUapb/9ZP5x5BxGOZosXemzOZbGHd+bH8Q+G5L+F1Qg//w6XHoP5qmqalWA==
X-Received: by 2002:a05:6870:214b:b0:3c9:7e9b:632b with SMTP id 586e51a60fabf-3e7c289ef43mr4646220fac.30.1762792679730;
        Mon, 10 Nov 2025 08:37:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YapG0Bs2/QYUQOFZtWq09Oum6UWtgt7/Xof9Irb7loqg=="
Received: by 2002:a05:6871:d615:b0:3c9:732d:60f2 with SMTP id
 586e51a60fabf-3e2f4d5d2eals2947318fac.1.-pod-prod-02-us; Mon, 10 Nov 2025
 08:37:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWg2jAu/7cZBk9sJR5+4JHuROUJFnNDktxwBGejVftv+jdLKnD4hxI24Bzrwb7TIeVGlP0Xg3qvg6c=@googlegroups.com
X-Received: by 2002:a05:6808:399a:b0:450:340:2692 with SMTP id 5614622812f47-4502a19b49bmr4585866b6e.14.1762792678845;
        Mon, 10 Nov 2025 08:37:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792678; cv=none;
        d=google.com; s=arc-20240605;
        b=XbLcSkJkzXtyQQ7IimhZRqgLMd4FZEcDZ7nuh34bBEfFkZSoMLriEdsjDw4SAx9uDh
         Oa93dd1D0yWfHwjIpWb4Y1fYwU82JcZ9ue+hxI4nkEfCgqd/et2QqrVklXI6QrBZ2w1O
         voTSsN/b1dhBPHS+wOEmoytG+kmJXJqJitdUWVbzyZqO2iK2+9TvZHxuS+2HzL/3kOHc
         aF3lfld2kSyrgr5lTNYbDZnl63N8xCMfBSBQnQ+jfclfnM6rZ27BvDz9A3BN7gFGYSnQ
         fZXUvrWK7MX4UeJiAsx1+RRHRAHs0sfLQ2QlycxKg1i/iHzWFv1CCZJktrckHC6qFeO/
         O0Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=IoYSCz9IZK+WTJVuSJ5kdqWuXYPyBcWSfVrsNGbuyIk=;
        fh=RAZ9WM7ihtgaS+m4InG8AXLWauAioG9v3rHRWzqzoVQ=;
        b=Hsmc/TOJGqOZuaitoHIQMXoBTeK13iEbdPnm6/wweCVGCwbkLXZ/Acgn4KuIUXv++M
         bmtVOnBpvb1LrO4ugJj7jvCCtwVeJMRQW8fX1kVa6bLrfrwPMQPImj73J057Vkg+4ufV
         +shNQZhxMUaVj/II0BRjVfG+wq23Q/bQ8WdRW5Ut41Ru3N+UHHxw1uEuUo3iA1G3aqsf
         murD/OZ1mrVqNu0nqeRgaivTl8awqWfZTUm3UK9G0pJTvQAZ441CcZEjRl6RUHYqHNMh
         aidsvj+f2/zoFePt/FW2nqzyjIm4vUraDgODFODHGCDCaiu2AAIjg/c2i+DAGc0FTH6T
         Hcvg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=i4VvdvAg;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45002a69288si154698b6e.5.2025.11.10.08.37.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:58 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-b553412a19bso1849655a12.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXuzF+G/43LkKEC+kMTFr3sIqrsqZ9Rnk/xv7IX8xQzulBtvZMFxmA47oWNUyUO54ubN9MUQjcgL+A=@googlegroups.com
X-Gm-Gg: ASbGnctQGNB5NQRRO2jYbSqhO9c6OQJ0xOs8OdSluWgdq/FGODYZAESZWTRXc0IMUcZ
	Eec4ULx6nsmRg/wKD5GtQwPa7BT46UJ5ofYa+gF2z5hP6vPJ0DzaI84HqRcaYQqqtefa/5tbJE5
	4nLvUDS30VO0xXT7bPKt986OSBG7pdCuRDuLDRSHecFdh9zGJOEXvFUXcohRefd3fYYVphmQbKW
	vuR/+EUy/Y3Ws7jpJmsMgzoGbTmH5MAer+EovEjPUmMx4JFhOHyhrS6ymTIsbdcx/Q3dtqlDfI/
	EWzPW0xPlmSKnppMdExx47+nMNt9OyHJm5Tx/rurnR7ALtEhxwl5IPvPSQUGjVipcsyxCnVkmYW
	7ar13qUUjSlocm0qplBFv9WCNjYlcABTXqGJczpecikn4221pdhFDGdQsV9EAeTcRgMiLYDYbx3
	0DiYo4vImHUMw=
X-Received: by 2002:a17:902:e80e:b0:271:479d:3de2 with SMTP id d9443c01a7336-297e5624c9fmr126791755ad.13.1762792677804;
        Mon, 10 Nov 2025 08:37:57 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29651ccec88sm150510135ad.107.2025.11.10.08.37.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:57 -0800 (PST)
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
Subject: [PATCH v8 17/27] mm/ksw: add KSTACKWATCH_PROFILING to measure probe cost
Date: Tue, 11 Nov 2025 00:36:12 +0800
Message-ID: <20251110163634.3686676-18-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=i4VvdvAg;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

CONFIG_KSTACKWATCH_PROFILING enables runtime measurement of KStackWatch
probe latencies. When profiling is enabled, KStackWatch collects
entry/exit latencies in its probe callbacks. When KStackWatch is
disabled by clearing its config file, the previously collected statistics
are printed.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/Kconfig |  10 +++
 mm/kstackwatch/stack.c | 185 ++++++++++++++++++++++++++++++++++++++---
 2 files changed, 183 insertions(+), 12 deletions(-)

diff --git a/mm/kstackwatch/Kconfig b/mm/kstackwatch/Kconfig
index 496caf264f35..3c9385a15c33 100644
--- a/mm/kstackwatch/Kconfig
+++ b/mm/kstackwatch/Kconfig
@@ -12,3 +12,13 @@ config KSTACKWATCH
 	  introduce minor overhead during runtime monitoring.
 
 	  If unsure, say N.
+
+config KSTACKWATCH_PROFILING
+	bool "KStackWatch profiling"
+	depends on KSTACKWATCH
+	help
+	  Measure probe latency and overhead in KStackWatch. It records
+	  entry/exit probe times (ns and cycles) and shows statistics when
+	  stopping. Useful for performance tuning, not for production use.
+
+	  If unsure, say N.
diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index 3455d1e70db9..72ae2d3adeec 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -6,7 +6,10 @@
 #include <linux/kprobes.h>
 #include <linux/kstackwatch.h>
 #include <linux/kstackwatch_types.h>
+#include <linux/ktime.h>
+#include <linux/percpu.h>
 #include <linux/printk.h>
+#include <linux/timex.h>
 
 #define MAX_CANARY_SEARCH_STEPS 128
 static struct kprobe entry_probe;
@@ -15,6 +18,120 @@ static struct fprobe exit_probe;
 static bool probe_enable;
 static u16 probe_generation;
 
+#ifdef CONFIG_KSTACKWATCH_PROFILING
+struct measure_data {
+	u64 total_entry_with_watch_ns;
+	u64 total_entry_with_watch_cycles;
+	u64 total_entry_without_watch_ns;
+	u64 total_entry_without_watch_cycles;
+	u64 total_exit_with_watch_ns;
+	u64 total_exit_with_watch_cycles;
+	u64 total_exit_without_watch_ns;
+	u64 total_exit_without_watch_cycles;
+	u64 entry_with_watch_count;
+	u64 entry_without_watch_count;
+	u64 exit_with_watch_count;
+	u64 exit_without_watch_count;
+};
+
+static DEFINE_PER_CPU(struct measure_data, measure_stats);
+
+struct measure_ctx {
+	u64 ns_start;
+	u64 cycles_start;
+};
+
+static __always_inline void measure_start(struct measure_ctx *ctx)
+{
+	ctx->ns_start = ktime_get_ns();
+	ctx->cycles_start = get_cycles();
+}
+
+static __always_inline void measure_end(struct measure_ctx *ctx, u64 *total_ns,
+					u64 *total_cycles, u64 *count)
+{
+	u64 ns_end = ktime_get_ns();
+	u64 c_end = get_cycles();
+
+	*total_ns += ns_end - ctx->ns_start;
+	*total_cycles += c_end - ctx->cycles_start;
+	(*count)++;
+}
+
+static void show_measure_stats(void)
+{
+	int cpu;
+	struct measure_data sum = {};
+
+	for_each_possible_cpu(cpu) {
+		struct measure_data *md = per_cpu_ptr(&measure_stats, cpu);
+
+		sum.total_entry_with_watch_ns += md->total_entry_with_watch_ns;
+		sum.total_entry_with_watch_cycles +=
+			md->total_entry_with_watch_cycles;
+		sum.total_entry_without_watch_ns +=
+			md->total_entry_without_watch_ns;
+		sum.total_entry_without_watch_cycles +=
+			md->total_entry_without_watch_cycles;
+
+		sum.total_exit_with_watch_ns += md->total_exit_with_watch_ns;
+		sum.total_exit_with_watch_cycles +=
+			md->total_exit_with_watch_cycles;
+		sum.total_exit_without_watch_ns +=
+			md->total_exit_without_watch_ns;
+		sum.total_exit_without_watch_cycles +=
+			md->total_exit_without_watch_cycles;
+
+		sum.entry_with_watch_count += md->entry_with_watch_count;
+		sum.entry_without_watch_count += md->entry_without_watch_count;
+		sum.exit_with_watch_count += md->exit_with_watch_count;
+		sum.exit_without_watch_count += md->exit_without_watch_count;
+	}
+
+#define AVG(ns, cnt) ((cnt) ? ((ns) / (cnt)) : 0ULL)
+
+	pr_info("entry (with watch):    %llu ns, %llu cycles (%llu samples)\n",
+		AVG(sum.total_entry_with_watch_ns, sum.entry_with_watch_count),
+		AVG(sum.total_entry_with_watch_cycles,
+		    sum.entry_with_watch_count),
+		sum.entry_with_watch_count);
+
+	pr_info("entry (without watch): %llu ns, %llu cycles (%llu samples)\n",
+		AVG(sum.total_entry_without_watch_ns,
+		    sum.entry_without_watch_count),
+		AVG(sum.total_entry_without_watch_cycles,
+		    sum.entry_without_watch_count),
+		sum.entry_without_watch_count);
+
+	pr_info("exit (with watch):     %llu ns, %llu cycles (%llu samples)\n",
+		AVG(sum.total_exit_with_watch_ns, sum.exit_with_watch_count),
+		AVG(sum.total_exit_with_watch_cycles,
+		    sum.exit_with_watch_count),
+		sum.exit_with_watch_count);
+
+	pr_info("exit (without watch):  %llu ns, %llu cycles (%llu samples)\n",
+		AVG(sum.total_exit_without_watch_ns,
+		    sum.exit_without_watch_count),
+		AVG(sum.total_exit_without_watch_cycles,
+		    sum.exit_without_watch_count),
+		sum.exit_without_watch_count);
+}
+
+static void reset_measure_stats(void)
+{
+	int cpu;
+
+	for_each_possible_cpu(cpu) {
+		struct measure_data *md = per_cpu_ptr(&measure_stats, cpu);
+
+		memset(md, 0, sizeof(*md));
+	}
+
+	pr_info("measure stats reset.\n");
+}
+
+#endif
+
 static void ksw_reset_ctx(void)
 {
 	struct ksw_ctx *ctx = &current->ksw_ctx;
@@ -159,25 +276,28 @@ static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
 				    unsigned long flags)
 {
 	struct ksw_ctx *ctx = &current->ksw_ctx;
-	ulong stack_pointer;
-	ulong watch_addr;
+	ulong stack_pointer, watch_addr;
 	u16 watch_len;
 	int ret;
+#ifdef CONFIG_KSTACKWATCH_PROFILING
+	struct measure_ctx m;
+	struct measure_data *md = this_cpu_ptr(&measure_stats);
+	bool watched = false;
+
+	measure_start(&m);
+#endif
 
 	stack_pointer = kernel_stack_pointer(regs);
 
-	/*
-	 * triggered more than once, may be in a loop
-	 */
 	if (ctx->wp && ctx->sp == stack_pointer)
-		return;
+		goto out;
 
 	if (!ksw_stack_check_ctx(true))
-		return;
+		goto out;
 
 	ret = ksw_watch_get(&ctx->wp);
 	if (ret)
-		return;
+		goto out;
 
 	ret = ksw_stack_prepare_watch(regs, ksw_get_config(), &watch_addr,
 				      &watch_len);
@@ -185,17 +305,32 @@ static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
 		ksw_watch_off(ctx->wp);
 		ctx->wp = NULL;
 		pr_err("failed to prepare watch target: %d\n", ret);
-		return;
+		goto out;
 	}
 
 	ret = ksw_watch_on(ctx->wp, watch_addr, watch_len);
 	if (ret) {
 		pr_err("failed to watch on depth:%d addr:0x%lx len:%u %d\n",
 		       ksw_get_config()->depth, watch_addr, watch_len, ret);
-		return;
+		goto out;
 	}
 
 	ctx->sp = stack_pointer;
+#ifdef CONFIG_KSTACKWATCH_PROFILING
+	watched = true;
+#endif
+
+out:
+#ifdef CONFIG_KSTACKWATCH_PROFILING
+	if (watched)
+		measure_end(&m, &md->total_entry_with_watch_ns,
+			    &md->total_entry_with_watch_cycles,
+			    &md->entry_with_watch_count);
+	else
+		measure_end(&m, &md->total_entry_without_watch_ns,
+			    &md->total_entry_without_watch_cycles,
+			    &md->entry_without_watch_count);
+#endif
 }
 
 static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
@@ -203,15 +338,36 @@ static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
 				   struct ftrace_regs *regs, void *data)
 {
 	struct ksw_ctx *ctx = &current->ksw_ctx;
+#ifdef CONFIG_KSTACKWATCH_PROFILING
+	struct measure_ctx m;
+	struct measure_data *md = this_cpu_ptr(&measure_stats);
+	bool watched = false;
 
+	measure_start(&m);
+#endif
 	if (!ksw_stack_check_ctx(false))
-		return;
+		goto out;
 
 	if (ctx->wp) {
 		ksw_watch_off(ctx->wp);
 		ctx->wp = NULL;
 		ctx->sp = 0;
+#ifdef CONFIG_KSTACKWATCH_PROFILING
+		watched = true;
+#endif
 	}
+
+out:
+#ifdef CONFIG_KSTACKWATCH_PROFILING
+	if (watched)
+		measure_end(&m, &md->total_exit_with_watch_ns,
+			    &md->total_exit_with_watch_cycles,
+			    &md->exit_with_watch_count);
+	else
+		measure_end(&m, &md->total_exit_without_watch_ns,
+			    &md->total_exit_without_watch_cycles,
+			    &md->exit_without_watch_count);
+#endif
 }
 
 int ksw_stack_init(void)
@@ -239,7 +395,9 @@ int ksw_stack_init(void)
 		unregister_kprobe(&entry_probe);
 		return ret;
 	}
-
+#ifdef CONFIG_KSTACKWATCH_PROFILING
+	reset_measure_stats();
+#endif
 	WRITE_ONCE(probe_generation, READ_ONCE(probe_generation) + 1);
 	WRITE_ONCE(probe_enable, true);
 
@@ -252,4 +410,7 @@ void ksw_stack_exit(void)
 	WRITE_ONCE(probe_generation, READ_ONCE(probe_generation) + 1);
 	unregister_fprobe(&exit_probe);
 	unregister_kprobe(&entry_probe);
+#ifdef CONFIG_KSTACKWATCH_PROFILING
+	show_measure_stats();
+#endif
 }
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-18-wangjinchao600%40gmail.com.
