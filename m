Return-Path: <kasan-dev+bncBD53XBUFWQDBBFEI5XDAMGQEOIVMKZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D54DBAB0A5
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:44:38 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-9048fe74483sf638407139f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:44:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200277; cv=pass;
        d=google.com; s=arc-20240605;
        b=MifW4x9FuUBVVR+nkAOAEhBczcW2hX2jbo9GXSrVKKQbUexio0sfVAKCFULubz3ozg
         AFg1Pu3L+awLT9Ms6MJPjvWjJ1Pm8LDcgAzXEkLzZXJy0iMg7VJg/I109p9S2kVvO0Vd
         odbRLgPfe2AdnAI+puxgjEm9zeTUSVReAVmd3+17P2/GJCsSStRjiWk9PNG0mJUInWyG
         6MEzHeW11peBF2Oxxe/kBp7LNCI5QAHjJYDc/tKf6NZgATnRT6x3XWoFzWE0UI9niVXr
         tL7VPuQQJXOVJYU/oZ8txWjbnJ7fuLrPjOwpGCLw8ehkCFYdd73afBgP4rfybCxHwcZF
         127A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=o7d3R44F6mRwBeqQ9xZjgjUZzhoEY/8/S7x1oO1iOdI=;
        fh=uYbi3whhZq1Ea/Xn2KTHel7DDRZvd75cUf9j83zO/js=;
        b=LlrxRmt/5gI/DSVDNQwpwfXUAYmLX5I23Wlq1xRgNUo3pnJNaHsH3vv8dVA5eIV4lO
         YznRmLhVxv/TlirNSjt/zbvf27Iiy0kxFEc8OcECVP1RC/oGGrm6J1ft+7KUECeKhz80
         Yxe9kW1SQTcp+VK9YuplMkWgVTOhYCZ22nAY+YZ1VfKe3KrBYcFoO1PaH4WLM5LJUM5C
         yL2oHDfoEV0mtnQxc/uQUcgjU9RHZTZOt93gY34QOTk+7DzYz0L376L2aND5aiXS2wZ7
         RR4r9a2i1ybJdjkFusqMSruRXz0J8NBqvNVsehatF2f4mzhP2VBOWXehOZwKpz12dZD1
         C2Tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mw+iW3bb;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200277; x=1759805077; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=o7d3R44F6mRwBeqQ9xZjgjUZzhoEY/8/S7x1oO1iOdI=;
        b=T2ywgNTln+EbJI4y4pYTPj2VixHiuFaP1EY41evP9Y2K5dSHzn70SJ0twmlvCju2Yq
         rWhENSPjQJdDd+yylt+NZzRvMqJHlLN8Uj82pt9tVGveiIyF2KXLPrtawCed6mBNwnfV
         bWv+P2W6GCd7QAqWzM19cW5UdtjrGd3lgnnEbEianYXNpnRP6u4i2mMpPIPjcjAJNA9n
         ryt3Bm+vFUCxyIWjYWirVaLcg+Ze2ScemlVFHPGCO/yTHZYwG+lP0cmDaQwHCcZtP3wZ
         qQsEpjU6SGH85+uRpX9JwMhbGROsLWF4qoe8k7u8SSsbNydcsUAZXqtD/CjH0+t6J/Dv
         IOPg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200277; x=1759805077; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=o7d3R44F6mRwBeqQ9xZjgjUZzhoEY/8/S7x1oO1iOdI=;
        b=lrHfwv7yDUv1w157mDxquhzoWUkGlQHFFvf9E8JoYgxr1PYPEI19EoYQtv4sGYPjV2
         7Py+w8tQpLkoP23uEh1XhU/getM7qhtp3hhVXgscv+CTCuI8Pk07v4dIiNoitrsVDGy8
         uUlLD0oIYc6EwFQNyR+Yypunui5VBY7zBE8Pc0AXRpXr5V1BZB5OEjWzbiqNE2yE66Ir
         dUj00EelIq9PUPL/JBJZWwA6rQ9N0nDIgg9a+Lxeooj8xK0rT1WvufbNsrzooKY6X5ZC
         oEOovvRQXZeWt9EiL1kraaGhHt6WcrMus8hlQSG22utK0oibQzGZAVW3Do8SL4g8za6A
         3VMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200277; x=1759805077;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o7d3R44F6mRwBeqQ9xZjgjUZzhoEY/8/S7x1oO1iOdI=;
        b=SFmWDt7HCFiSf3vP2hnYYCa4C3Gsq21FcITDtskyjcgusP86APvADHDzlGLm84VS1N
         6Bv3Xhk/12kA3OtsIe4oPmdLDx1zwEyfxveCEJwxA22pzphIoB64la5h+Q5Y7tPNmDHC
         6rHxU8ZmSxYVdTxDMe0bCurmrylidRb5BilkW9oVzd2edgn/YTmI+P1sDJ5MiMzDUSPt
         aNbMHPPgktlnXgo6YB5wikYRs1h/bULkNQAg2gZyzhRmiY0V1L8XO7YiT6ZUjrWGocm8
         k3lOeS7hX/mNgp07ADFo8oLormHUqzi5lW0MEtVWKzmWRnWnwe7I4gSBaIZuAyRipgvY
         C+lg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXJ8ely51vAf5GBDUxNW7Wu2xJGX+5yAoM8HfTuMJNJhDl4KAdJxnjCgtwi9EAcpg3xkYdQHw==@lfdr.de
X-Gm-Message-State: AOJu0YyFA7xLTJBuxRCZN+2PdcOSu9+2JTJJVTD5Fe18bMLg7+Rph4Lw
	y3u08Jx2G8C7To5+6ZBbG0YleA9grjev58Kgx30y+ad1iL4cnQurO+jh
X-Google-Smtp-Source: AGHT+IGSf1RY7O5bxzFU1T29+PJG4DCC3PDeBAuIt7cq/kfRmOA2m0ZffOWKt/b5760CkSw3i2eu0w==
X-Received: by 2002:a05:6e02:2186:b0:428:d63f:e723 with SMTP id e9e14a558f8ab-428d63fe981mr119326625ab.21.1759200276736;
        Mon, 29 Sep 2025 19:44:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5sFCNDKjCGdAsnwATEFmvJfLwNlAkVphwjg9d8nnsazw=="
Received: by 2002:a05:6e02:4404:10b0:41c:6466:4299 with SMTP id
 e9e14a558f8ab-42af8a96040ls14697445ab.1.-pod-prod-07-us; Mon, 29 Sep 2025
 19:44:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyIH2w0RJvNlShVlEKLfjpYkhhE1im9BQvf6d0xhgct7baj9joN0ayJWLZQ0zHx2JWcRqr9RGEToo=@googlegroups.com
X-Received: by 2002:a05:6602:3fcb:b0:932:bdf:2d with SMTP id ca18e2360f4ac-9320bdf041amr336953639f.9.1759200275911;
        Mon, 29 Sep 2025 19:44:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200275; cv=none;
        d=google.com; s=arc-20240605;
        b=KPDEPM80nEMaPFK/Lx0HstVHep9oJ8fuPAz9VY9709grGRXIojYW90uUf4+/TnomFU
         5Z34+W2aK62MrolWbfpslxWCQgut1QmU+s4p8cLFv+udMYOtENuTEoJJsAUCh4ZLhdMP
         hv81rVaSEOBES9h5c4LuQsD72Ln/BubMGWoN+hRlLOIlzBw2UKPtScD96AntzotvMMol
         RoJ8sXBEB1p4DmgK03rO7ENPyfqC43N9Ay0tgNeZVW8Kis3+TtQLIt44LVp98h4VRPSk
         jGLxZi0IK6w4YrxDdjFc/DgtWul5ojNOEkZVy0VZ84MCVzWY/d0oekKjfRUe1TjO0L0W
         4VaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DLL9szq8LgdVljgQmrpuYN0dKjRbhwJ4oBDbEm6eF/Y=;
        fh=0PVavHRk5zG28kduodCAzuHj1egr85EjeVGZKqe8tZc=;
        b=Td9pJhjyYPTgn5Py774PG1vkshVoepW3Ji/Fheo4kbGOTLxw3ccpTU2cqXNNTxz6hQ
         pSEnzeJbvajRf11L+uSkM921uFMeRz1x6PX2HK3waxhngb0TgObl8dja5QbInqJAPhKI
         HytE+o5DeH5suzpLVS2qXgSv/SIR/Ld1bRCfK/C61LjalCFeFsCKHbHl3nt0cJCJeVSs
         shg9kvmzGaq7aKB0HHnAJ8sRUta/05tlHOffJjQ/LNi9kuKLK7KmqWv0h53ebEFEUXFo
         MZgFblv87OepYU+eP+m/zA1Bu93q5z+6b9OHEY+EoiD9IjCDD45aL9TNkdk/t1hfWedo
         lN8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mw+iW3bb;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-9040a31f0d2si60130139f.3.2025.09.29.19.44.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:44:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-781db5068b8so2293923b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:44:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUziFt5R/K1vf0g0uTbhIsEt0PUToXFj7PqjEYMBS/3N995vMHiVLaPZYSVocJ3WhyXRS/OJaJIKRU=@googlegroups.com
X-Gm-Gg: ASbGncvUvT3BeDswl4F7BaPX/m7I9o0SgmwkQtD2KA+4316jOtILvmE9ItE3+n82Fki
	GesHArbH1lLO1OzlXQH2rMm8btTU0uVOzo9a24FRJGeqJEtcfe2RTEdP/JHHPenrJ7m25YWwzg2
	qWurcbKr28TMdhH8rl6rMrvScQUZGw1MaLhWbYftE30+V20ylqL0M+n9Ll2tp8zRxc+RTlYVKEg
	9upV/RRjlrQTboYp17n9b+OmCgpjVYnSpbWrK7YTK9NiRD+sNH68J/EPfKQWtacTPxoQPnhk2Pp
	3+3PnKNWM1u3TAnIpUQLpl8SNwZ1HOazqFrc6eQnDFH4JoCcp4Q2GHtiyV4yZApDWdXBbRrbYWZ
	umfmpnkcxiWNQj9eU5jh3EeKP6bGycRsLK3NfryM46TAX6datJeMf92bP8d3AqTS75QntSBhsQA
	0/
X-Received: by 2002:a05:6a00:4b46:b0:77f:416e:de8e with SMTP id d2e1a72fcca58-780fceb5040mr19851033b3a.26.1759200274983;
        Mon, 29 Sep 2025 19:44:34 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7810238f11esm12449091b3a.19.2025.09.29.19.44.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:44:34 -0700 (PDT)
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
Subject: [PATCH v6 04/23] mm/ksw: add build system support
Date: Tue, 30 Sep 2025 10:43:25 +0800
Message-ID: <20250930024402.1043776-5-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mw+iW3bb;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add Kconfig and Makefile infrastructure.

The implementation is located under `mm/kstackwatch/`.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/Kconfig.debug             |  8 ++++++++
 mm/Makefile                  |  1 +
 mm/kstackwatch/Makefile      |  2 ++
 mm/kstackwatch/kernel.c      | 23 +++++++++++++++++++++++
 mm/kstackwatch/kstackwatch.h |  5 +++++
 mm/kstackwatch/stack.c       |  1 +
 mm/kstackwatch/watch.c       |  1 +
 7 files changed, 41 insertions(+)
 create mode 100644 mm/kstackwatch/Makefile
 create mode 100644 mm/kstackwatch/kernel.c
 create mode 100644 mm/kstackwatch/kstackwatch.h
 create mode 100644 mm/kstackwatch/stack.c
 create mode 100644 mm/kstackwatch/watch.c

diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index 32b65073d0cc..24f4c4254f01 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -309,3 +309,11 @@ config PER_VMA_LOCK_STATS
 	  overhead in the page fault path.
 
 	  If in doubt, say N.
+
+config KSTACK_WATCH
+	bool "Kernel Stack Watch"
+	depends on HAVE_HW_BREAKPOINT && KPROBES && FPROBE && STACKTRACE
+	help
+	  A lightweight real-time debugging tool to detect stack corruption.
+
+	  If unsure, say N.
diff --git a/mm/Makefile b/mm/Makefile
index ef54aa615d9d..665c9f2bf987 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -92,6 +92,7 @@ obj-$(CONFIG_PAGE_POISONING) += page_poison.o
 obj-$(CONFIG_KASAN)	+= kasan/
 obj-$(CONFIG_KFENCE) += kfence/
 obj-$(CONFIG_KMSAN)	+= kmsan/
+obj-$(CONFIG_KSTACK_WATCH)	+= kstackwatch/
 obj-$(CONFIG_FAILSLAB) += failslab.o
 obj-$(CONFIG_FAIL_PAGE_ALLOC) += fail_page_alloc.o
 obj-$(CONFIG_MEMTEST)		+= memtest.o
diff --git a/mm/kstackwatch/Makefile b/mm/kstackwatch/Makefile
new file mode 100644
index 000000000000..84a46cb9a766
--- /dev/null
+++ b/mm/kstackwatch/Makefile
@@ -0,0 +1,2 @@
+obj-$(CONFIG_KSTACK_WATCH)	+= kstackwatch.o
+kstackwatch-y := kernel.o stack.o watch.o
diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
new file mode 100644
index 000000000000..78f1d019225f
--- /dev/null
+++ b/mm/kstackwatch/kernel.c
@@ -0,0 +1,23 @@
+// SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/module.h>
+
+static int __init kstackwatch_init(void)
+{
+	pr_info("module loaded\n");
+	return 0;
+}
+
+static void __exit kstackwatch_exit(void)
+{
+	pr_info("module unloaded\n");
+}
+
+module_init(kstackwatch_init);
+module_exit(kstackwatch_exit);
+
+MODULE_AUTHOR("Jinchao Wang");
+MODULE_DESCRIPTION("Kernel Stack Watch");
+MODULE_LICENSE("GPL");
+
diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
new file mode 100644
index 000000000000..0273ef478a26
--- /dev/null
+++ b/mm/kstackwatch/kstackwatch.h
@@ -0,0 +1,5 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _KSTACKWATCH_H
+#define _KSTACKWATCH_H
+
+#endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
new file mode 100644
index 000000000000..cec594032515
--- /dev/null
+++ b/mm/kstackwatch/stack.c
@@ -0,0 +1 @@
+// SPDX-License-Identifier: GPL-2.0
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
new file mode 100644
index 000000000000..cec594032515
--- /dev/null
+++ b/mm/kstackwatch/watch.c
@@ -0,0 +1 @@
+// SPDX-License-Identifier: GPL-2.0
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-5-wangjinchao600%40gmail.com.
