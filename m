Return-Path: <kasan-dev+bncBD53XBUFWQDBBOXER7DAMGQELPM4F6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DA20B548F7
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:16 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-24c8264a137sf18175595ad.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671995; cv=pass;
        d=google.com; s=arc-20240605;
        b=S8+3vPTMZjqd9jGiwJlZV/g1xXPJwe83EQR3aJbD91t16sUnUupI1HqPTPq4m2dm8I
         M4E4PeHAv5iWO6ko4rv4IfIqzKl3tBeVOsJKSWwJh3AWiNNTi7bwEcYMsS+qoKkgptvr
         Hv51G3Mb+LewwbJGUaX+SCcMG/xKx8b7wTO2fsUHM2JPS66elfrJKQQCQfUlCPzGM6qb
         EbL6waijSqoGFT1Vv02Mo4Aw4lfiCOx0tJZCxCEoYXxdCcx7YTwiqLxZjVIQaPsCGRiU
         Io1AHu06sh2I4OkDWVfml3wvo6UtVnMHuvyZ/xPlX/a+kzYi1LaLrxYRYK7qsnwpBcV7
         IAjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=LqaFX6wQZ6PzkBRaDbe3h4VPeOC/Xd7ScL1TY2Aop7A=;
        fh=WHrIc53Mh1Izr1qDLvJZsG7AvLzALWINSQkLeO+cFBY=;
        b=eW9fy0eD/43/khau1OoRbP4VFj3U7LwEJbIxuADopceO5wuHXZZhjbu+ow5+0BY8iL
         Xnh0pLzhEsd7ZNpbDXVIsGuxF7eYfSV3nkKAs94F6+8+bai1l3ebKYa6AXvObAuXZjmI
         fsdFcX0TwxymPqCCz4RwX4RvZMgjqUnyLnorYJvh/ev6HSqkq8vmG7O3VmQPnFuD77KC
         q311i7rfKIdSWrc83aOHKnJpLJC/XV6fCVJC4kIR9LiQwN+u2+BJbj5s+5AWrNlcVi+P
         50TBHraSoIr3d6Yk1tys3F1UUp9wFmKqPKJNUvXYRqw+VSAQcZFLnbpfQsNdkMC2YBf4
         R2hQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Tg0ZmU+q;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671995; x=1758276795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LqaFX6wQZ6PzkBRaDbe3h4VPeOC/Xd7ScL1TY2Aop7A=;
        b=P8RbcuAFgZq/qGq+E63xKozkSPO+s1dZ6XMUZKuBydlnnzMJKR7EfDBZwNpvWCMK3t
         REziG+uDhk+6Dn9pN+qNTx2Tk5fAwVDKiu6QWGExBXt3hY2uChzv8qqiN8M4pdAI+O1m
         YBtbbUga9F8zbKC8NqfAgMt6ljHhRO+e78OCjvrnod2I2R/RaV3AT0xPvgS5xmvyngxC
         aF0AX9WOQC841oO8y1ewRX9kBrjg9GD4pgMASMBVz3WpvGe0r/hBe3Iv4/KZV6CRCtNy
         78/ADAczAejBIVToB7uLM5BkeirYZCs0Qq8iiLFW9v2pVNxzbbuIBmS/Xadlqi86mNFS
         97MQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671995; x=1758276795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=LqaFX6wQZ6PzkBRaDbe3h4VPeOC/Xd7ScL1TY2Aop7A=;
        b=Doxu++Off79FA1y56q59qWGQW6gz9TSxu1qy4UfWJzgiFKZ800azOtr58/MMrgxsVw
         SxGGy1VY8Fi3fweYn3gnbIHoiBOJZyYmV7ooYXXXHxRaFhbY8Qxkc3q73ttXTaUwoPGn
         N/4YE2wcPs4OU4rWRJNlARiRbgrG0+lMqASrAA4cFfGqYftbm+6tAT5XoVDgrfBcrSEX
         lhmyo+uMc+kdRE+wIwkXJ24bReFvvwEzliCi8Hj1CYhu0+XDj/7LEpxQ1GBIi0UWFPqB
         qbl8HFnf7dzaAVrSpiGO8ebsTiwAw+dTJtcool5cNu2G3o47IeZh97NU1NwMJtyIdVVX
         Cn9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671995; x=1758276795;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LqaFX6wQZ6PzkBRaDbe3h4VPeOC/Xd7ScL1TY2Aop7A=;
        b=GRXBmm0lCdCMbVBVOSi4GjVA5rgGgb0qbjtDB0P+dZHeQOZdtfZq33q6CdaMAsE3PL
         U5FjOzx1W1HNliso178oWH9yCM1cRnjOr4CVYuE2/5NVdoDKhZKE4HSRMNC5OK7B5Bun
         r2S3RIyazGSdvmRc/wZvnYy8Td3mUOiJ888Tazn3FDO57snVie/luAqU+Wzo6IzI+4Ob
         BI7goZVljWLUHdxcwCxoeUGaUE4zx9oYJeu/2P79yKSE7CLT7McyZDgiCMEurQ9WHlLT
         QJ66/0+k/2LMemKoWgMx3D0gfyO08cPLmOJGaJ5zrWj974ECzXYHvsx2h7wHsm+wK6ua
         RIcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVA2Co7UOqA1cCet48nE/TvS6WxRRqd9NRpT7993/Yz3ubQLg57WRpZCZ2Zvz6F5ytYNcFXxQ==@lfdr.de
X-Gm-Message-State: AOJu0YwXF4rP2K8saoYK9rKSgRFjM72Zeyv/fkl4QVaCcUkibrD/HHFH
	Jc3F0RHMlOTrSuRGfJ56QsZ6sDiIq5aHLP0RHpRBTRsneEPt4G4Hvsx0
X-Google-Smtp-Source: AGHT+IFvNPzVj3uAcDXNMz1aDiA37IEFWUr2UvFacRl5+x0TfsKf49blB/7walz7TFxZT+t5S701Ew==
X-Received: by 2002:a17:902:c40d:b0:251:a3b3:1580 with SMTP id d9443c01a7336-25d24cac4eemr32568805ad.6.1757671994875;
        Fri, 12 Sep 2025 03:13:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd65sAi9or94+Bdcx2K1wYSYrq60l6+8+Bw3QkGVNTAqNw==
Received: by 2002:a17:902:f603:b0:24a:990b:75e5 with SMTP id
 d9443c01a7336-25bec0b60b3ls17661125ad.1.-pod-prod-01-us; Fri, 12 Sep 2025
 03:13:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2rUzAA4j7j3/RS5X+44lN71UlB9z2jeYlmIsDB+X4iTYOGIZlMGtOHk+//zOfoSwZi+kkGF+1hSs=@googlegroups.com
X-Received: by 2002:a17:902:c40e:b0:24c:6125:390a with SMTP id d9443c01a7336-25d24cabfd1mr28527725ad.10.1757671993336;
        Fri, 12 Sep 2025 03:13:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671993; cv=none;
        d=google.com; s=arc-20240605;
        b=VwvjlSMNWaKr0zlSbawyOwni4j3y1dKg7gBV5ix9BlJB+ndUY81fyoBqPfw6ONFis4
         ZNJN44kr5GUJlYjST+6XC33YxDCFeS/iiyXH0q4TmCoCmefXS0g4ndzcZ8L36X1trdt+
         Vz53L9u0iMhblskPR1U3bWTEFuxO9gZ0zTuUaRLquD+5so3SAlsimjtUm7Hau/UDlNAC
         HpQ+MajrAJ5V2GYtdeJO4jO3phqdvFizXCJoG1XTi5K92/ahz6f22RrhL+AydszlGSKk
         H2tLsYRKH+A+ajBpKbYRRt+TPVPSMBRhF+5DqqZ5cwH0tDqVFomB0oG2Exk8iNz+hMzM
         MfXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Hza3KqRNKGSLYWfBSKXFsxDeH0DXXBXA3429C+Yqz2A=;
        fh=MPJdWSOa6g6JuJrExR6qJruQuA9LQk/7V5OLgagad3k=;
        b=HPOaSJLK//wbIfrWwLymeU7DUQh7Y5aOL48loJbnZmtTFl514JZkAhL6NAGaZdnKeA
         j3hC0W02JN6Q7lownLQ7BitWBppEF35yyjjHbqvInmz/1YuKnyvaNN3b+nxWnkCXhI3Y
         WJWMF9WrZ3E3OfyCDHlK8K3KHFSwnJEEYyoPD95PD1ICVNiO3ScbpD67rwvKfAQHJ6I2
         g1sZiRvflrZTmIozk6zzJ95JpK3JHuxO4bNlN2U0WFBor9SeznqXFMNx6F7dloaPRKhB
         Qt2qvLpUbSUw67hDM/VhONokdDc/93ZXuMXFSsO2ihqbgoIXNjsta4kN8f+YE6oEmMSP
         mOpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Tg0ZmU+q;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-25c370a502fsi1661515ad.2.2025.09.12.03.13.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:13:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-24cb39fbd90so15150305ad.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:13:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWkHF31+0wSrXd7Qz/5wBpKvPFsNjcREnJtYUZ8R05vW7AtdpRflq/EImJ1Akjw1vH3mhrnT5mCfG4=@googlegroups.com
X-Gm-Gg: ASbGncv4ICmgl4RHf4JtdXiBxTTST1WgB1lmylx3BC4w9sgw3zRcdEaJUIP5TFhakoa
	KX2ScQopS2B4Z02aqAXcEE6ZBv9Fg52xhoWq9vYh5SsXiz+H0p/mOlAPMYwWk1IuYuC6C6Hz5Rl
	oefav1vnDKO/zODpsTdu45dvgfzh2pfeaFcza0mNbH5yEyVTAPIbUToqh6OS7sAbAGTWx+3majl
	3RpUQkdpRPtzAUlndcNV54sybi6I3MFDSXT8fLk18qr6GaXp+tXdL5vTrdHJUg8mYJJ0yjvO3xO
	J43oEK39b4hlypur4qeED1rVZKA7U2r5BWh/3HrIj3KLfLz8KcSCLHx5B//qTJG2T50aMsKrZck
	FNfpEUQm9JO/34uMc/uIKEl1RtN1FLRW7i9U=
X-Received: by 2002:a17:902:c407:b0:24c:784c:4a90 with SMTP id d9443c01a7336-25d24cac4e3mr30450705ad.1.1757671992780;
        Fri, 12 Sep 2025 03:13:12 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25c3ad33ed7sm45397685ad.102.2025.09.12.03.13.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:13:12 -0700 (PDT)
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
Subject: [PATCH v4 15/21] mm/ksw: add test module
Date: Fri, 12 Sep 2025 18:11:25 +0800
Message-ID: <20250912101145.465708-16-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Tg0ZmU+q;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Introduce a separate test module to validate functionality in controlled
scenarios, such as stack canary writes and simulated corruption.

The module provides a proc interface (/proc/kstackwatch_test) that allows
triggering specific test cases via simple commands:

 - test0: directly corrupt the canary to verify watch/fire behavior

Test module is built with optimizations disabled to ensure predictable
behavior.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/Kconfig.debug        |  10 ++++
 mm/kstackwatch/Makefile |   6 +++
 mm/kstackwatch/test.c   | 115 ++++++++++++++++++++++++++++++++++++++++
 3 files changed, 131 insertions(+)
 create mode 100644 mm/kstackwatch/test.c

diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index fdfc6e6d0dec..46c280280980 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -320,3 +320,13 @@ config KSTACK_WATCH
 	  the recursive depth of the monitored function.
 
 	  If unsure, say N.
+
+config KSTACK_WATCH_TEST
+	tristate "KStackWatch Test Module"
+	depends on KSTACK_WATCH
+	help
+	  This module provides controlled stack exhaustion and overflow scenarios
+	  to verify the functionality of KStackWatch. It is particularly useful
+	  for development and validation of the KStachWatch mechanism.
+
+	  If unsure, say N.
diff --git a/mm/kstackwatch/Makefile b/mm/kstackwatch/Makefile
index 84a46cb9a766..d007b8dcd1c6 100644
--- a/mm/kstackwatch/Makefile
+++ b/mm/kstackwatch/Makefile
@@ -1,2 +1,8 @@
 obj-$(CONFIG_KSTACK_WATCH)	+= kstackwatch.o
 kstackwatch-y := kernel.o stack.o watch.o
+
+obj-$(CONFIG_KSTACK_WATCH_TEST)	+= kstackwatch_test.o
+kstackwatch_test-y := test.o
+CFLAGS_test.o := -fno-inline \
+		-fno-optimize-sibling-calls \
+		-fno-pic -fno-pie -O0 -Og
diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
new file mode 100644
index 000000000000..76dbfb042067
--- /dev/null
+++ b/mm/kstackwatch/test.c
@@ -0,0 +1,115 @@
+// SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/delay.h>
+#include <linux/kthread.h>
+#include <linux/module.h>
+#include <linux/prandom.h>
+#include <linux/printk.h>
+#include <linux/proc_fs.h>
+#include <linux/string.h>
+#include <linux/uaccess.h>
+
+#include "kstackwatch.h"
+
+MODULE_AUTHOR("Jinchao Wang");
+MODULE_DESCRIPTION("Simple KStackWatch Test Module");
+MODULE_LICENSE("GPL");
+
+static struct proc_dir_entry *test_proc;
+#define BUFFER_SIZE 4
+#define MAX_DEPTH 6
+
+/*
+ * Test Case 0: Write to the canary position directly (Canary Test)
+ * use a u64 buffer array to ensure the canary will be placed
+ * corrupt the stack canary using the debug function
+ */
+static void canary_test_write(void)
+{
+	u64 buffer[BUFFER_SIZE];
+
+	pr_info("starting %s\n", __func__);
+	ksw_watch_show();
+	ksw_watch_fire();
+
+	buffer[0] = 0;
+
+	/* make sure the compiler do not drop assign action */
+	barrier_data(buffer);
+	pr_info("canary write test completed\n");
+}
+
+static ssize_t test_proc_write(struct file *file, const char __user *buffer,
+			       size_t count, loff_t *pos)
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
+			pr_info("triggering canary write test\n");
+			canary_test_write();
+			break;
+		default:
+			pr_err("Unknown test number %d\n", test_num);
+			return -EINVAL;
+		}
+	} else {
+		pr_err("invalid command format. Use 'test1', 'test2', or 'test3'.\n");
+		return -EINVAL;
+	}
+
+	return count;
+}
+
+static ssize_t test_proc_read(struct file *file, char __user *buffer,
+			      size_t count, loff_t *pos)
+{
+	static const char usage[] =
+		"KStackWatch Simplified Test Module\n"
+		"==================================\n"
+		"Usage:\n"
+		"  echo 'test0' > /proc/kstackwatch_test  - Canary write test\n";
+
+	return simple_read_from_buffer(buffer, count, pos, usage,
+				       strlen(usage));
+}
+
+static const struct proc_ops test_proc_ops = {
+	.proc_read = test_proc_read,
+	.proc_write = test_proc_write,
+};
+
+static int __init kstackwatch_test_init(void)
+{
+	test_proc = proc_create("kstackwatch_test", 0600, NULL, &test_proc_ops);
+	if (!test_proc) {
+		pr_err("Failed to create proc entry\n");
+		return -ENOMEM;
+	}
+	pr_info("module loaded\n");
+	return 0;
+}
+
+static void __exit kstackwatch_test_exit(void)
+{
+	if (test_proc)
+		remove_proc_entry("kstackwatch_test", NULL);
+	pr_info("module unloaded\n");
+}
+
+module_init(kstackwatch_test_init);
+module_exit(kstackwatch_test_exit);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-16-wangjinchao600%40gmail.com.
