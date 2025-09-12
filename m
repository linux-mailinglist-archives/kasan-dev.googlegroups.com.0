Return-Path: <kasan-dev+bncBD53XBUFWQDBB37DR7DAMGQEJPJTGVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 097DDB548DA
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:12:02 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-24e04a4f706sf19328855ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:12:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671920; cv=pass;
        d=google.com; s=arc-20240605;
        b=L0AGhL4FGSgJv7v9ERiTkt+Hvk6XCWtH7hKsEVLd/W+Gv2yhHOtC2kYMLlXDq+P9me
         rJ9H3ZA+rpFoxHhH9oY7JfMyShtugkKrzb/CdXuUPQ6MIdiDMOzAiDH/djbDuoSjsCUw
         HN5LO1RkJkQf03WWn7FIYFUgvaFzeJ77c3k70wVj/6NxzwpmZ1Qj1zWGJSpAUOr6dzBd
         bypKM1/97JmgJJcz2fkWm6TCt6JJudWvEztC3VKwAcc+be2knEmbqi8IU0NDBi3k7Tql
         armMHQQGX/r8OSGE4wk4NWrHEVRbgXECoOazxrGVX59a1cMw4QYtR8FkbBcZ8HgyH+Qx
         QZhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature:dkim-signature;
        bh=aGAGpQraTVvmG/d2iIzEx/nm2QpX1eT7Zth4XrF+FJ4=;
        fh=sLI0Qqwa8yeBi4BWTLrKNa8+EQG7Es9hm8MO20FRSYg=;
        b=flJrHdtyYZTXKDHMuEbVrkK4U1Qn9OMP5N54DzEd8tWtwvKCQiP41dKjJ/x591jK3m
         tLheVZVqiBMXv1SHB2i4PI/TbJGsiwuviR8UptC17PGq/fhiNqY6e/65+A1oBzuFHIMY
         /o8xzUKQCDDnNYU/pLirvDc9KFYA3YHDvJftAuUI9Y3DzJYkB3S0hJRwCq1PndEGRBOc
         QCMHc0aFdOobC90Uw7svWNLj/D097ZlPjI/Ql3cjuuSPRluoaRgPc1O6b3a6RGpZbDsE
         816rmkRvBQiZVR/XbZo/A4YWdIrbAxvbHwiMroatw5sMoBEjvv0Ke9/cDmriIv9ZtpOJ
         h0lA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bBezFPTE;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671920; x=1758276720; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aGAGpQraTVvmG/d2iIzEx/nm2QpX1eT7Zth4XrF+FJ4=;
        b=hWUqh/uDwSNu3yBXNwBXv13Ol7pUS4nxn39D8i8NVbABWSRbEp5iFCsrRx8X8V8j04
         WY7hb6XLpaKOuwy0P6UECQYrlmRR7dY4cV8lAat+qIjr5OsRdkmRLEUYns+3qfTrrih9
         elonTbRFsGwaCBz0dgpmd/dXV3F1SZdqdJ5yQOizSl6SntPsJRGGtZn6HtPsiCd6coo2
         SR2RBTrMpHQG2Fim/gEMzI1q8GxQWlUs1yRm0O9EdgCMzELWsny5U/EItvaIvMgaw59I
         F5d9HJoERjzwV00uPJs3EN2zvFcbWPd0ZxO37nWG7Uu5lgfpBtvu+zB8Tlnr0blau6ZM
         ZS8w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671920; x=1758276720; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=aGAGpQraTVvmG/d2iIzEx/nm2QpX1eT7Zth4XrF+FJ4=;
        b=ideqgA3YkIEWNiMNMWCtOlZ5bmxdhmSj24cVdnS2P+4dfSHw467oXfj2tTZ9LZmuD/
         us6s0EF6joYJtFEA/dq63+ZTnwj47Y1IqRIqxHcjntl1la27sm0bkw/MTnI5ZjSZCxDr
         LQWOYpwTxnmAKXeuRrLlo4JhqVvcB9OAx5arhU3NTNRIuZE+uPuTZ74sRYMKJEQGFd8Q
         BzzMQyw2qebueUKCpadTaY7AjAxzy69ZXdcamVf1dyh5pV6P3e1joSdMqgHejQRUQY/n
         GP83ABI17DPo9Tp/hZBpuNSaV0x6VZYiSo2c89jmMx92IeN2KHB/1pG7ZDsqSDPxPzgT
         W96A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671920; x=1758276720;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=aGAGpQraTVvmG/d2iIzEx/nm2QpX1eT7Zth4XrF+FJ4=;
        b=b+pTSwQ3pCnBuvNgneylusOtPAs1AX5pquBECzs2kh0CILTgd9uON/vfJTAuNzteN9
         sDuZTKtK28+FlRiYHubiToCYm36HcPSCwKXya67ZIK0IxSX0J3MX1+6luh8kniTzAx6N
         PLZ6aA3rWoH5YaS4In8AoW4fNH3nKKvkznEUwkARLApYDYHuzYY3zTPO96uaB7RZ1Bs5
         RN+uGL+BCYg8Baz2M4+0xcEfOZWxMHypeXqR/Dhrs7becdMOPUS6Ya6cN+r3tNn8j22v
         owv0DbTrXKm6rGpgJgqxatXeCbvEDVbiiHjOFlBhh/CPA3m7Tw/gZLRY9L2zcJFrsLvv
         +OcA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXIiCg5a4Vgb22LVBBkVGFRA9Nvz5htb9qTSZuefRbLTwe6IkEJrgevjH3hb7ceif2a5hQsOA==@lfdr.de
X-Gm-Message-State: AOJu0YwWIR3nfQAQyU6Y+0RbLNYvhF8s7IPxIvrTHtJWtGTjaZubyrr1
	qTEFz0ubFcsZ22Eb1QuE7OgnjkocdUGv/J7BTv96eN2vCILPigQOE9Xm
X-Google-Smtp-Source: AGHT+IH0NvCpPEbyGicrg6hmjXdnn9DgWE1XqN3/L2PE6dNd7UEws0y5O3hwM9Iq6p7b01CQimLpWQ==
X-Received: by 2002:a17:902:d490:b0:246:a56e:b155 with SMTP id d9443c01a7336-25d248c9c02mr24531595ad.22.1757671920096;
        Fri, 12 Sep 2025 03:12:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7IjFNRZlqBqxi0Z2RqLLV+NKsMsszlOHsD0FXfwiHfVA==
Received: by 2002:a17:903:93:b0:24b:b55:9343 with SMTP id d9443c01a7336-25bed9f799fls14276305ad.1.-pod-prod-09-us;
 Fri, 12 Sep 2025 03:11:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWLY6b5MNGG7e93eegznNLkCPol05EDSPDYu5eCvDy/KOckBs2BoBUHn9wScgNnbKQ2xjfQj568kBk=@googlegroups.com
X-Received: by 2002:a17:902:b491:b0:24c:d08d:c0f5 with SMTP id d9443c01a7336-25d26a58dcbmr25309735ad.49.1757671918535;
        Fri, 12 Sep 2025 03:11:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671918; cv=none;
        d=google.com; s=arc-20240605;
        b=eDTQ9MIstxwaq19ZKl8xooU398AW08qbhr9bKf78IRU4b6xAK9/2FyeSr6j2hfFH4F
         0GMgsf9azbaUXsaai6joLCoTX54qycVABeZPS3y3/PIPxDBJy8sEjxeiNyBlOJMVu4+x
         RRHInIDCuE4cvACihE2iXSfodYkmfJiGZN4YNP+8pfIIkxx2MUL8as2I0TLOlxj+kHnf
         lk+1/vV8g6hGQHv5iGBd4SG84Bq+cqDB4SrRbYNcZiMzCsk2y5YiHS9zIK08NLMGIGaQ
         8oGxLBGS35PTc4HMB5f2dvy5etTyAgVgwn9TUnLbDAcawLtm8TsBWyOYjuSsuKEG/z1h
         3WRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=a0RAur8Marng0nhbSNOQRJYXrBS2GdOE60OklyU/Dxo=;
        fh=ISTk6snnU9DTK8lTHOFhpbtolqVmivhZbs5zV2mL/SY=;
        b=YqloP+LhI7sj69jZsGJKb2sIx44Lo/IvZjo7Ag1HdPVqo6WwMSU8w9kqIr21ip6OYe
         wt6AF5VNuP86Z6BaWZQPWT/JKB1Zv2eOFsfvCA/lUcuNtih5KihWR10CTDrKEYfX6CYf
         2g8lKweTe0yFrxfv++BFEiMaKsubo7ixYfa3tQ/rrLl3l67aEAipAlcborPhHtLNudRK
         LLdNh1UYTDKCEDpLxFhDOpRXzSEAq2xzzJPEOav1dMOsf7SLOFPhC0skzlyTUMCRydYB
         XUXuveI438+Ue71avo9B+6RaTb1TPS70d1lKlbmp40Bry2w9Fy8y0/4kEmoCTDnZjNLM
         zLpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bBezFPTE;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32dd98b9072si156104a91.3.2025.09.12.03.11.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:11:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-7704f3c46ceso1606480b3a.2
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:11:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW5uxaF+jp0k3AthtDPHkSLQmsN7j3JeEeFFT9n6FvXes+Mms3cEfS5tHbubyooUx3zEnXEkquyLnU=@googlegroups.com
X-Gm-Gg: ASbGncubFLiBO+4abHxVx/dyd8QTIC1YZnqtL70pwllrPqoiEaeWoKk9GGBwu4thV/9
	6VYpyQG2MXV2SWbmClfB4C8LCAuoo4aH4wuN5rT+TwiIjlxkTQylyv5x+9OV3Lk71/XAkp/7G/F
	Khe+M03ogWaTsFFT/XPdUhB5e3Kf8q652ZFLgNhahuk2AqEiw1xWv+7olGs4j7SiatFM5JE4Y29
	LMAFMEpvsPdgD5lcg8CpiBL5MkQ9NFVabWessBV0tSppTfZeAtd0fsAH1GyE/qZArzElIyA1u8p
	JIuo3UEOetK8IwWPxlvogPKesyB3o1+9H/suTTPxW3ZXhdjwfmmsycZgKNWiXr/Ds+QN2iibv9G
	M9PdOqS9cnYxGaDdkxKrjbSZlP2hJ1rRySRAGLMRc2hHhWjab+A==
X-Received: by 2002:a05:6a00:194b:b0:772:5271:d1ba with SMTP id d2e1a72fcca58-77612061e2emr3147992b3a.7.1757671917940;
        Fri, 12 Sep 2025 03:11:57 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77607b18371sm5059816b3a.49.2025.09.12.03.11.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:11:57 -0700 (PDT)
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
Subject: [PATCH v4 00/21] mm/ksw: Introduce real-time KStackWatch debugging tool
Date: Fri, 12 Sep 2025 18:11:10 +0800
Message-ID: <20250912101145.465708-1-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bBezFPTE;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

This patch series introduces KStackWatch, a lightweight kernel debugging to=
ol
for detecting kernel stack corruption in real time.

The motivation comes from scenarios where corruption occurs silently in one=
 function
but manifests later as a crash in another. Using other tools may not reprod=
uce the
issue due to its heavy overhead. with no direct call trace linking the two.=
 Such bugs
are often extremely hard to debug with existing tools.

I demonstrate this scenario in test2 (silent corruption test).

KStackWatch works by combining a hardware breakpoint with kprobe and fprobe=
.
It can watch a stack canary or a selected local variable and detects the mo=
ment the
corruption actually occurs. This allows developers to pinpoint the real sou=
rce rather
than only observing the final crash.

Key features include:

  - Lightweight overhead with minimal impact on bug reproducibility
  - Real-time detection of stack corruption
  - Simple configuration through `/proc/kstackwatch`
  - Support for recursive depth filter

To validate the approach, the patch includes a test module and a test scrip=
t.

---
Changelog

V4:
  * Solve the lockdep issues with:
    * per-task KStackWatch context to track depth
    * atomic flag to protect watched_addr
  * Use refactored version of arch_reinstall_hw_breakpoint

  Patches 1=E2=80=933 of this series are also used in the wprobe work propo=
sed by
  Masami Hiramatsu, so there may be some overlap between our patches.
  Patch 3 comes directly from Masami Hiramatsu (thanks).

V3:
  Main changes:
    * Use modify_wide_hw_breakpoint_local() (from Masami)
    * Add atomic flag to restrict /proc/kstackwatch to a single opener
    * Protect stack probe with an atomic PID flag
    * Handle CPU hotplug for watchpoints
    * Add preempt_disable/enable in ksw_watch_on_local_cpu()
    * Introduce const struct ksw_config *ksw_get_config(void) and use it
    * Switch to global watch_attr, remove struct watch_info
    * Validate local_var_len in parser()
    * Handle case when canary is not found
    * Use dump_stack() instead of show_regs() to allow module build

  Cleanups:
    * Reduce logging and comments
    * Format logs with KBUILD_MODNAME
    * Remove unused headers

  Documentation:
    * Add new document

V2:
  https://lore.kernel.org/all/20250904002126.1514566-1-wangjinchao600@gmail=
.com/
  * Make hardware breakpoint and stack operations architecture-independent.

V1:
  https://lore.kernel.org/all/20250828073311.1116593-1-wangjinchao600@gmail=
.com/
  Core Implementation
    *   Replaced kretprobe with fprobe for function exit hooking, as sugges=
ted
        by Masami Hiramatsu
    *   Introduced per-task depth logic to track recursion across schedulin=
g
    *   Removed the use of workqueue for a more efficient corruption check
    *   Reordered patches for better logical flow
    *   Simplified and improved commit messages throughout the series
    *   Removed initial archcheck which should be improved later


  Testing and Architecture

    *   Replaced the multiple-thread test with silent corruption test
    *   Split self-tests into a separate patch to improve clarity.

  Maintenance
    *   Added a new entry for KStackWatch to the MAINTAINERS file.

RFC:
  https://lore.kernel.org/lkml/20250818122720.434981-1-wangjinchao600@gmail=
.com/
---

The series is structured as follows:

Jinchao Wang (20):
  x86/hw_breakpoint: Unify breakpoint install/uninstall
  x86/hw_breakpoint: Add arch_reinstall_hw_breakpoint
  mm/ksw: add build system support
  mm/ksw: add ksw_config struct and parser
  mm/ksw: add singleton /proc/kstackwatch interface
  mm/ksw: add HWBP pre-allocation
  mm/ksw: Add atomic ksw_watch_on() and ksw_watch_off()
  mm/ksw: support CPU hotplug
  sched: add per-task KStackWatch context
  mm/ksw: add probe management helpers
  mm/ksw: resolve stack watch addr and len
  mm/ksw: manage probe and HWBP lifecycle via procfs
  mm/ksw: add self-debug helpers
  mm/ksw: add test module
  mm/ksw: add stack overflow test
  mm/ksw: add silent corruption test case
  mm/ksw: add recursive stack corruption test
  tools/ksw: add test script
  docs: add KStackWatch document
  MAINTAINERS: add entry for KStackWatch

Masami Hiramatsu (Google) (1):
  HWBP: Add modify_wide_hw_breakpoint_local() API

 Documentation/dev-tools/kstackwatch.rst |  94 +++++++++
 MAINTAINERS                             |   8 +
 arch/Kconfig                            |  10 +
 arch/x86/Kconfig                        |   1 +
 arch/x86/include/asm/hw_breakpoint.h    |   8 +
 arch/x86/kernel/hw_breakpoint.c         | 148 +++++++------
 include/linux/hw_breakpoint.h           |   6 +
 include/linux/kstackwatch_types.h       |  13 ++
 include/linux/sched.h                   |   5 +
 kernel/events/hw_breakpoint.c           |  36 ++++
 mm/Kconfig.debug                        |  21 ++
 mm/Makefile                             |   1 +
 mm/kstackwatch/Makefile                 |   8 +
 mm/kstackwatch/kernel.c                 | 239 +++++++++++++++++++++
 mm/kstackwatch/kstackwatch.h            |  53 +++++
 mm/kstackwatch/stack.c                  | 194 ++++++++++++++++++
 mm/kstackwatch/test.c                   | 262 ++++++++++++++++++++++++
 mm/kstackwatch/watch.c                  | 181 ++++++++++++++++
 tools/kstackwatch/kstackwatch_test.sh   |  40 ++++
 19 files changed, 1266 insertions(+), 62 deletions(-)
 create mode 100644 Documentation/dev-tools/kstackwatch.rst
 create mode 100644 include/linux/kstackwatch_types.h
 create mode 100644 mm/kstackwatch/Makefile
 create mode 100644 mm/kstackwatch/kernel.c
 create mode 100644 mm/kstackwatch/kstackwatch.h
 create mode 100644 mm/kstackwatch/stack.c
 create mode 100644 mm/kstackwatch/test.c
 create mode 100644 mm/kstackwatch/watch.c
 create mode 100755 tools/kstackwatch/kstackwatch_test.sh

--=20
2.43.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250912101145.465708-1-wangjinchao600%40gmail.com.
