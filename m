Return-Path: <kasan-dev+bncBD53XBUFWQDBBSFWZ7DAMGQEP7XB4UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id A0037B99A76
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:51:38 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-244582bc5e4sf73364985ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:51:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714697; cv=pass;
        d=google.com; s=arc-20240605;
        b=XVyiKQzZ7EA9gLL70pLYmboc4uH07dkD0kUY3o3E9zOmYkFnSFFu9kVhfAD3PSSyIO
         bgX4KxY6GqOnv9ci/AJECf0KmQqQAYZT4eAKedwzmoKYJvAykM1yjWazQ46vU88/CWx/
         tdwTX++iOwGW9bVaJ+fgwyZBfjQI8RnW4F8ftHPwU87H/pycyGsbbMmpVh+ENmR9nRhU
         Q4xm2NAl9EjeQzniBVZKCnkKcH7J4WyAA/7ZLlt639cHOSpdW3sEbNsZl7IwFoBUKaAA
         yabcw5/WQA/YNt4JpCO3fRjqDiTjdiTOCSnSlC3Lty4C3WS5iagHDLSBpqcmRYLrtH+N
         Y5/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature:dkim-signature;
        bh=rRmStByABxubOrNrjSsw5iOgnQbRAiAhnZCOYN6MMJ4=;
        fh=63xyLFqP/ZuKs4q51uTM6e2pCnFGoB1tl0qeL5WQDrE=;
        b=kfV313bPyBbzwuJwXKDhhN9ESEuxKKdTYOm64vHRYe/ENf5A8U04CTjqlZvo+Mmb0N
         1LrP5TRTsZUW0NYXddOOiVuodu0/CoM1KWu/Oz+FimCzlZhoCrNjqX1S7imYY3tsU5+O
         p14se1d/5sHcJVcZLKhIaNEiTaOxjMEP9oaaucj3xDg2I/632K5gApJw6zZ3vymwMBhS
         lqDCWFSd4sCW9ICzzHdAXbTrVwmu8IupzPt6VEHvGn4PMmCet3DxcXy9qufODBvOekiU
         5KDj1WBJ+p/4Rat4/WQXXbY8y551iYlL+FT97xX+641XFJCJXxEb6VdZT3cE67ocHtSu
         1Hvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FxYHm+iw;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714697; x=1759319497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rRmStByABxubOrNrjSsw5iOgnQbRAiAhnZCOYN6MMJ4=;
        b=uk9wDmGNHrGK8EK/23hgiD9NIsLwJ/iyBPBcRLWRyKkGJllqAP91cJTOklM/1upPgD
         FqOxrGkE10xw3dDAYnRKD7h8efuj9sREB6a+aYBb7FAsAxxpSYTlmgQyYXzP6P/oMUYa
         MZCED062mSY8yl91lagCzq5BZLscWqfXLG26N6A1kfZT8x188kZR6U3mV35Hy2wplMBI
         XQeG1kG76iZ6pz5DPCtVcxXqsRxipD8xxAwmVhJ2VKoMabUAunAXasT2lTwdyUV4AsCB
         UgJas76KNaMjI7q/qooMj2x6afdlTiIZkaLPZY3OQymocx9EwhWGBXlf3gFHl5IA2kvc
         pd7Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714697; x=1759319497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=rRmStByABxubOrNrjSsw5iOgnQbRAiAhnZCOYN6MMJ4=;
        b=VQZOaYVBC8v+5EAYwROZN6zni87z8QUgsxn9uppzkrbmy6YM81waArejYAXrlgv24n
         ck2wY9wyg9K2LTmv+0YLO7KJb/Qg2rQmgkSuwR1OWkxNDOdXznHyyb7uBgHAKDwiHYo8
         ATF/dvBuvwOkoTnvSUrQl/cTmcwu2sA7gmKLYHSmvuIXcLScWY0tXsPzggUPzyXlxKX7
         LyaUxvTlDAhX94sYPwota1KDxQtZqXDQbTSL2e17OkPPuai0lKfHje/uHNuloPG9yYyG
         oUkxwHMp4THZ3doae9yYIgo3pizqk9VzcSDqcaaI7lDX4Udhu82aV7taz/xSYUZXPDgC
         OhJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714697; x=1759319497;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=rRmStByABxubOrNrjSsw5iOgnQbRAiAhnZCOYN6MMJ4=;
        b=YviOPElb618g9untd7KoIH5TL9zLBkFV7NpJqQ6QoAZ4FqRYW17WMQB0cMMeLGKY2m
         zhL0X+yngHoIOsQCd/augmVubbL5NJWob9jvGwEtOgg1wH6ckfdF59Opk4Wy/W/y5O5l
         m26CX1RHiVGbzepcnga5RNpCKLgoBuFgC9biel2AEw42jZ8etO+uKr4RbM55UVyWLBlt
         +JjoLRA6CcU2L9gL8mj/4FJAN7a4jJ567wNZnXfLTLLmogf++1mIo4vzil1QT+52BRQd
         iZyT3h7aiAYfdf8NKd7ApQ35iZ4CjyH12Y/Jgy4akrOAah2wSVYrbWMSXKPpatbvWnIB
         Tdkw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUs6g9488BzpiaAsYuLqA2p4Lf/TPUnVXgWKW/pVY1RHpsGuf3X9aRAb0EzEdG4jaZrLRaS1w==@lfdr.de
X-Gm-Message-State: AOJu0Yw+38GHDF1z68aM1IyRl77Gdzfu62/z9h6O6GRQzBiJ/t+WXkHa
	yChQaw/L9pAhKFmFmjIpmjJQgY3mHpUcpmPk+c9AX5d0yZwsrbTnYBEV
X-Google-Smtp-Source: AGHT+IHQjvMb6nMkfAi7IiXy6iM0u4Lsiz8bdMSqFsyaEASmeyIVciUktJoHt7TIPWIMqZW2M66DBg==
X-Received: by 2002:a17:902:e84e:b0:263:7b6e:8da0 with SMTP id d9443c01a7336-27cc185395bmr82399905ad.15.1758714696818;
        Wed, 24 Sep 2025 04:51:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5FtHwkigmoXxg1rDK8wuw38TTnZEphSgrZzdxGo4jrug==
Received: by 2002:a17:903:34c3:b0:265:760c:9785 with SMTP id
 d9443c01a7336-26984061378ls49624925ad.1.-pod-prod-04-us; Wed, 24 Sep 2025
 04:51:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVaM7bh9EnAqg3ulSORi15Cjf1MbMMu8XNA7nBgYxQqD0G4WUaBGtgaA/NpvB6ACS52tsiccNQrgIM=@googlegroups.com
X-Received: by 2002:a17:903:3bce:b0:24a:fab6:d15a with SMTP id d9443c01a7336-27cc185851emr65163055ad.20.1758714695295;
        Wed, 24 Sep 2025 04:51:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714695; cv=none;
        d=google.com; s=arc-20240605;
        b=INka7jS911DlbRTmzIr/6fKi9duGa4nGvB4DROpl5NAX47CsH36p6xPUqi61KCsrGl
         wgk85BDj1fH/Itc1DA8RF6nxDqhti2YRxruID37LHtQyY/RIsRpHVll6n83AdlDzxWB/
         0fv2ONdNihhQAA8sxN/0jYVSB7LwElSre8xCZ4LLzhabQcyNERPFIIa5NzjE04StyeUP
         Jmp88p/bCl5XjUF4kzeqB1MWShjBqNfNqUu7afCYik7gL34cGBFGtQkOUM+/eVIzuWRv
         Mnn5niYfXHC7rYQkXdlonV8Tzw+cozYHe7OhqcCgw836h22B8ccdq4p6N660wxmknpxJ
         yq4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=IkFW7ZSlDKq/LZM+zK73rBzgP1/UKF25L/8hqnEAXa4=;
        fh=b/wsI6OXuXTHhtFTY2kXF+djryh4se7x1REionA+RSA=;
        b=IdQWsLfzd3bl7DO1hLXwMJvHcUAVMquD6RsQqYPj4K7zS7IPA8R4Y2sqp2VZtCHjFL
         vUjd1fEQLyj3j5QX0yQsx0WdmImRY4+8ScBbC4af56WXTnWrBPjYpvnYW6Uz74jdpju0
         8BfxcWcsmzrpHmi968p/dC+/B/a7yPf+0+miVG3qxrfLD+GPMtXLA/EFsSQrJQkKzM/O
         iRT/VbphQSlFyenUjpgWiSVUs0NiVxxBvO8QUwDDFUMxTU5auM6Uq3XsQ49EUQhJ8lh+
         oYI+ZXzLTKLxHZbblEje66Irkff8yif/Iv2OhBqAexbpeBC6ZQZfpIoWH2n+uMVnmdpq
         JBNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FxYHm+iw;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-27ec0a7ed96si673495ad.7.2025.09.24.04.51.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:51:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-2698384978dso56720625ad.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:51:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU5w5a4DfTpSq8a6TUdPVfxFk4eQkXEx0oSHyzSzAeeAFN1IusQbOg2yaTi940r6Wh77q5X0EAPNTs=@googlegroups.com
X-Gm-Gg: ASbGncsINTpQhoMKj/Gze9q0BZhNP8U8ZvMZc7wY34NH0BC3DM1/E+EYMx3aBPdCVEw
	apQyBCAnv3mfmbkkaIGLQQZfNmtJ06WztjV8x2vnyzmLPBfVA4x518SchClhdLZgC0IDn/MvW87
	GP7VnS5M6E3zurnPKVRg6PuaXYA24qQdrA3PoIj4eEsMemoHsU/2bOLVs6soYBmk/4t+F5SQd4t
	fWvUVQu/ak6tm98RRY6hG5Enj9ggVc29H2VIi1FxpFji2fr2ulXtK0hk9bRLPVebXLXscTOPTBX
	JNuCh2tWOrbx1/yXwhXqLPKsw5tTutc5uhXe4wR5r5XPESGv8FXhupIBVSLh+NSHAH+abkS3acx
	fD6sL9+Pu3dFm1D98kTvzu7lZWw==
X-Received: by 2002:a17:903:3586:b0:240:9dd8:219b with SMTP id d9443c01a7336-27cc61bd32dmr78200575ad.49.1758714694622;
        Wed, 24 Sep 2025 04:51:34 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-269802fe096sm189570425ad.104.2025.09.24.04.51.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:51:34 -0700 (PDT)
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
Subject: [PATCH v5 00/23] mm/ksw: Introduce real-time KStackWatch debugging tool
Date: Wed, 24 Sep 2025 19:50:43 +0800
Message-ID: <20250924115124.194940-1-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FxYHm+iw;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

This patch series introduces KStackWatch, a lightweight debugging tool to d=
etect
kernel stack corruption in real time. It installs a hardware breakpoint
(watchpoint) at a function's specified offset using `kprobe.post_handler` a=
nd
removes it in `fprobe.exit_handler`. This covers the full execution window =
and
reports corruption immediately with time, location, and a call stack.

The motivation comes from scenarios where corruption occurs silently in one
function but manifests later in another, without a direct call trace linkin=
g
the two. Such bugs are often extremely hard to debug with existing tools.
These scenarios are demonstrated in test 3=E2=80=935 (silent corruption tes=
t, patch 20).

Key features include:

* Immediate and precise corruption detection
* Support multiple watchpoints for concurrently called functions
* Lockless design, usable in any context
* Depth filter for recursive calls
* Minimal impact on reproducibility
* Flexible procfs configuration with key=3Dval syntax

To validate the approach, the patch includes a test module and a test scrip=
t.

There is a workflow example described in detail in the documentation (patch=
 22).
Please read the document first if you want an overview.

---
  Patches 1=E2=80=933 of this series are also used in the wprobe work propo=
sed by
  Masami Hiramatsu, so there may be some overlap between our patches.
  Patch 3 comes directly from Masami Hiramatsu (thanks).
---
Changelog

V5:
  * Support key=3Dvalue input format
  * Support multiple watchpoints
  * Support watching instruction inside loop
  * Support recursion depth tracking with generation
  * Ignore triggers from fprobe trampoline
  * Split watch_on into watch_get and watch_on to fail fast
  * Handle ksw_stack_prepare_watch error
  * Rewrite silent corruption test
  * Add multiple watchpoints test
  * Add an example in documentation

V4:
  https://lore.kernel.org/all/20250912101145.465708-1-wangjinchao600@gmail.=
com/
  * Solve the lockdep issues with:
    * per-task KStackWatch context to track depth
    * atomic flag to protect watched_addr
  * Use refactored version of arch_reinstall_hw_breakpoint

V3:
  https://lore.kernel.org/all/20250910052335.1151048-1-wangjinchao600@gmail=
.com/
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
  * Reduce logging and comments
  * Format logs with KBUILD_MODNAME
  * Remove unused headers
  * Add new document

V2:
  https://lore.kernel.org/all/20250904002126.1514566-1-wangjinchao600@gmail=
.com/
  * Make hardware breakpoint and stack operations architecture-independent.

V1:
  https://lore.kernel.org/all/20250828073311.1116593-1-wangjinchao600@gmail=
.com/
  * Replaced kretprobe with fprobe for function exit hooking, as suggested
    by Masami Hiramatsu
  * Introduced per-task depth logic to track recursion across scheduling
  * Removed the use of workqueue for a more efficient corruption check
  * Reordered patches for better logical flow
  * Simplified and improved commit messages throughout the series
  * Removed initial archcheck which should be improved later
  * Replaced the multiple-thread test with silent corruption test
  * Split self-tests into a separate patch to improve clarity.
  * Added a new entry for KStackWatch to the MAINTAINERS file.

RFC:
  https://lore.kernel.org/lkml/20250818122720.434981-1-wangjinchao600@gmail=
.com/

---

The series is structured as follows:

Jinchao Wang (22):
  x86/hw_breakpoint: Unify breakpoint install/uninstall
  x86/hw_breakpoint: Add arch_reinstall_hw_breakpoint
  mm/ksw: add build system support
  mm/ksw: add ksw_config struct and parser
  mm/ksw: add singleton /proc/kstackwatch interface
  mm/ksw: add HWBP pre-allocation
  mm/ksw: Add atomic watchpoint management api
  mm/ksw: ignore false positives from exit trampolines
  mm/ksw: support CPU hotplug
  sched: add per-task context
  mm/ksw: add entry kprobe and exit fprobe management
  mm/ksw: add per-task ctx tracking
  mm/ksw: resolve stack watch addr and len
  mm/ksw: manage probe and HWBP lifecycle via procfs
  mm/ksw: add self-debug helpers
  mm/ksw: add test module
  mm/ksw: add stack overflow test
  mm/ksw: add recursive depth test
  mm/ksw: add multi-thread corruption test cases
  tools/ksw: add test script
  docs: add KStackWatch document
  MAINTAINERS: add entry for KStackWatch

Masami Hiramatsu (Google) (1):
  HWBP: Add modify_wide_hw_breakpoint_local() API

 Documentation/dev-tools/index.rst       |   1 +
 Documentation/dev-tools/kstackwatch.rst | 316 ++++++++++++++++++++++
 MAINTAINERS                             |   8 +
 arch/Kconfig                            |  10 +
 arch/x86/Kconfig                        |   1 +
 arch/x86/include/asm/hw_breakpoint.h    |   8 +
 arch/x86/kernel/hw_breakpoint.c         | 148 ++++++-----
 include/linux/hw_breakpoint.h           |   6 +
 include/linux/kstackwatch_types.h       |  14 +
 include/linux/sched.h                   |   5 +
 kernel/events/hw_breakpoint.c           |  37 +++
 mm/Kconfig.debug                        |  18 ++
 mm/Makefile                             |   1 +
 mm/kstackwatch/Makefile                 |   8 +
 mm/kstackwatch/kernel.c                 | 263 +++++++++++++++++++
 mm/kstackwatch/kstackwatch.h            |  58 +++++
 mm/kstackwatch/stack.c                  | 240 +++++++++++++++++
 mm/kstackwatch/test.c                   | 332 ++++++++++++++++++++++++
 mm/kstackwatch/watch.c                  | 305 ++++++++++++++++++++++
 tools/kstackwatch/kstackwatch_test.sh   |  52 ++++
 20 files changed, 1769 insertions(+), 62 deletions(-)
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
0250924115124.194940-1-wangjinchao600%40gmail.com.
