Return-Path: <kasan-dev+bncBD53XBUFWQDBBA4I5XDAMGQE7FHGTAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D97B1BAB090
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:44:20 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-78e30eaca8esf152623666d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:44:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200259; cv=pass;
        d=google.com; s=arc-20240605;
        b=lCEJBt9o3IKevktHDPDYoJeWPC1ZcPH9L6mPfKdvhv2gBmI2RoNxmGTzxpl/bdlXFT
         38zPuBDM70tulk1pxV/DVH49XdDSyduJjthH6iWnbbxphLW31rQ+Wxxm1Fje0hSTmIgq
         AxJS3Nc1Lpv3X/ZEksgQELPFp7nJt7DB8JRqPO0QdtY/O+7Uf8SK3RUqo/ehsZ0C3iWE
         qq/9r6D6wQO6c7TYPGI2b4M3tSQorK2oM1Z/ilADHYGt+vlFCd8IZ25Ag/gtDgHH60Ez
         QbHr5lDCw/Sto5eStm88naHOO2dIS7/w1t/t/0g0Zki9HBjUO7SwgPxE59eAyAyXMciI
         z3dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature:dkim-signature;
        bh=qIViZbSRnccfASyUX/gK/MO3riGcxk+NPrBOJ5Ujd6Q=;
        fh=IIvybftLySNO+UI/kAxM4rCYlt4G3JPKROITrMheqCs=;
        b=HIoqProBKuWhVi2rv1q0Mo9Vy+xQDZiMw9ztChTICwQ2WdDrmhp3Z4xhZtcH7AikLt
         3AriWqqfT5iuecLnevg0UQcA3P5QQ9njy3kzivjvbs2BbBsM0MgioYPklHgIe3QrXAY1
         WNjtJ2nVo9mUbXtqCNwP8kjYjji38nAOSHF+3+XFXiX2ijdvXpu3ggvO9wt4BMAmkILn
         UVUBlaG+7HOBqKQc7RwlQ3nIPvsLMVOSUKoAr2KD8Z2oBBkh7ozSafIqVx5mzOI4FOv1
         l66+4eFKoBCxlD+pEU9MuFj0AztID+DCoXu4T8qEbQW1G8vu05Ux0bSF/mOJICMXxQyW
         OMCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=H6xOnB1w;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200259; x=1759805059; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qIViZbSRnccfASyUX/gK/MO3riGcxk+NPrBOJ5Ujd6Q=;
        b=NodxCD/gHqkpzLxN2yU55AHG2hzvRbZG05Ism1Q/xd2licSQgT5lSETcT7XDImhdtR
         XcDBC4QbS+5bdQ+eoItwtnGG6hbZjOcjCCLQDoNwmj+GTJ0blk/mRTxpaPI/pk68WWdL
         ZIAlke4+CWz4iRjI80gbtQVVNtE4XagnJlPYClrQogo9WF3ovVWgjxC6NBxRkYV7ncBD
         2k0DjY6P1fpuHt7RVHvyRKDMAWnNf6qNouKmqCHQf4eIZiW03wJXBzSk7pJweB7RJv4p
         srqHI+fTp87Pb1O5X4s9Z9PuFUTcpsk+OcGT+nJudqWfq8Inq6gbitO4YNs4sLJsnQAI
         kH2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200259; x=1759805059; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=qIViZbSRnccfASyUX/gK/MO3riGcxk+NPrBOJ5Ujd6Q=;
        b=MgA0DqZMbF5KmI5HjcvR/RNZonuG/SVnfrDZqVJMEuwv3U8uzH8fv9VSqfAZCZxxhb
         jBdqn2lCpPT6CySaPoBcJVf7QaizCFISNnbh+YHiX/wOuGzMqubeuPN4EFZ5xNWWkU2N
         4IlmOaWQndBv5t7tVtAIzKIU3WucVrqfXq52CSd88DjFQNA5nYOuX5WILlJCaJAy+YB5
         HpdxPNZM/G8XlCghs90e41mZ5+yQUKEVrw1I/tTQLJYgF6dyGwrQOXP2IJ/LckqHFtH4
         x7Ykl95V/rbIE8aY5yTYofW1Ux2hTUZcZCRbyiIXc/UEu3mB/a9L6weeg+SDhKoyMWYW
         8CMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200259; x=1759805059;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=qIViZbSRnccfASyUX/gK/MO3riGcxk+NPrBOJ5Ujd6Q=;
        b=K+kUk37Z5rm6cqQ8KHF/LU/S/BPq1uizv1QYWvypfymth1teZ6Thbg3ePV/6M5HPsZ
         9wTEi4rwoe7WRvRIYFk+mcx3lKkXbWcHQaV62FAq1Dk1OGn0bP7u/98rn20QIaZcjWda
         2wLi+cqrygOxBz31gz1leXDAqoXJ1tk0BOtTaicNW0xCrtJiEN/HsKAvc3Riv5BF3GUK
         mmlkiefXZN35epvgdHUysRyJh1gSyBlFJFGDTqU0Y++lhy2zo4P7vpXtEJP9l8sU2aym
         WTbtAY2v81uuOG3zBDDw9uwweAyUR60SUkCLz6+yPnAU5cSwY/BeP3i6cU/LoJn3h7Q1
         DWOw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUeu9R5qtaAHInrdqfhRhmiPCEmoiAPgLk95VHgo8VdA9FNumuwDC5TQug6aY1VDjx3ltVxdw==@lfdr.de
X-Gm-Message-State: AOJu0Yz5/16mzZfArwyM2FlhXKwokpJlz7qvahJAu0CKwM/rsee6F3D3
	6esNAa0qcOvrNzk1qwc6jsB4pfwhYCEZtCx9KXhMAJm2/YEU3JIWAFQh
X-Google-Smtp-Source: AGHT+IEpLm3FoBPuSBZKrpoD9sbspsmHBFaqjyBiMMR+UdB0OePhfGe2EJ+1hFdXVYI1W2iq7xFJcA==
X-Received: by 2002:a05:6214:2427:b0:806:7173:3af5 with SMTP id 6a1803df08f44-80671739302mr224172006d6.55.1759200259267;
        Mon, 29 Sep 2025 19:44:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4GqHGiN2NlameewdXH2KAvC2gqUaqGke3yujr/ZyWXEg=="
Received: by 2002:a05:6214:5549:b0:70b:acc1:ba52 with SMTP id
 6a1803df08f44-7fd805ef9e3ls90731946d6.2.-pod-prod-02-us; Mon, 29 Sep 2025
 19:44:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUlfJrFyUcbg6sim8IGKxBx9jETP2jfgxtJtV9mqz6aSvNvEx+Li2vAoCqVFwiivgTrf921buHdCE4=@googlegroups.com
X-Received: by 2002:a05:6214:2349:b0:86c:1f66:e2eb with SMTP id 6a1803df08f44-86c1f66e430mr14773756d6.33.1759200258322;
        Mon, 29 Sep 2025 19:44:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200258; cv=none;
        d=google.com; s=arc-20240605;
        b=e4ULT12C6GLG94s9QtE9VM99fAVGeSmkEpd7J+/wpcGcfFcWTuk/zz5BmMSi2EcMFi
         P9wRGWSpOMi76BeQfw+gg6HeU2IIMqq2hpdXfF51mfG4VXAQlzIi4f/+gl5+aIjRvLu3
         x0IAOQRaTug4Fv6eyermFNCzo1YR37dssUK254WV2Uiwd39Xi1RZMb9hiR/vIuTQ7F9p
         DNE84b+gxYJvj/ZrdwB1omFMEIC88YwrlENnkVUb5mFDQRQ41NbmZitsVQR+7pvS9rB5
         aLWHxZfYCTuLqtnpIPK7xISxlszG257DXHrn0jVBUrKyn8Ahufpshk1nnehogSqT8lIs
         EQEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=oBLHnI+e6tAOqeHvXlDdht1mTbtW+pSP4ewzl28Opg0=;
        fh=XQSk26guKPnt5/3siDpedR+9lhRLQZ2OGxX8FwxARO4=;
        b=Rhx74zNZBCIoyugOp5T9lLhho9pZFP2oww8HS9RG3K7l9MgzDEvYD8Ii9c7S3VZCyw
         qJmDT0ksG/QiEgfo8VUNJMs7jldSHm4K4jbFKmnZqSTJqR28StA76J6VFgRWaf3T57of
         UzfISBfaOX7d+L8T68AJlI7aionLpwr8Kd3Awhse38hIrhMEuIrzFe6MismLszVJmmAO
         0AdSp+ANnGZWOhHvxviUz39TSBbeMtq5hmq113Hu639OtYsPAssgiI1B9DcIEfmOt4s8
         NCmEbTw6zDwFY3u0k1M9C17Ibe1/Kc7YPSF2tnLj3SC77nTE/DbYWklq4cHE4KIPQkVT
         zCKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=H6xOnB1w;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8015b6ea19dsi270386d6.3.2025.09.29.19.44.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:44:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 41be03b00d2f7-b57de3f63c8so3052024a12.3
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:44:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXmnjSuEok3hgehX5wzT2AYsTSNu4E2fNWgIz3vkfJP13XBISUQlnYf05836NH76zyKtUjG3TIDVKw=@googlegroups.com
X-Gm-Gg: ASbGnctPVGPCuX+xe11ARMRycpwb3EqMoIqLmuzRAEKoTIML//9TpRxYez1ghFUyPTT
	Mji3RZaG35gelRpCgOWEzvDKB5KXX1TwPoVstHTO97QFFqnyUPiQ5hCqXvcEiO7YT8XzYHKZ1zJ
	juT4wbLnsJMpqYU1LkPDMO2O3ctzF8VvRtCGePWFpMecOoc1vSd6lmmofAZfkLX0dPLShob1fe9
	cmoWVWvY+36Ip1r/YgMG2og0jHLYAhPKBHkEjqVFDsjpr536EO3bjbE+mMjI/s35zn4q/Vg5/g4
	O5vpkrlxT6Y+bBSYqFiaxSCDjF63fM5JR6nP3x7HR7dg/p4hRKYcIQZ1ZTgc1lIVfnQBjG3DP42
	5yw6pwam6/L3Gz4CoeVRhy0s5suSYZldY0P9XytQBMM3DZ3j0z9aAu+eEaEPELrn1WsL7W4g1pb
	D/
X-Received: by 2002:a17:902:c409:b0:275:f156:965c with SMTP id d9443c01a7336-27ed4ade26bmr209883395ad.52.1759200257156;
        Mon, 29 Sep 2025 19:44:17 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed66d3acfsm146037925ad.20.2025.09.29.19.44.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:44:16 -0700 (PDT)
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
Subject: [PATCH v6 00/23] mm/ksw: Introduce real-time KStackWatch debugging tool
Date: Tue, 30 Sep 2025 10:43:21 +0800
Message-ID: <20250930024402.1043776-1-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=H6xOnB1w;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

V6:
  * Replace procfs with debugfs interface
  * Fix typos

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
  mm/ksw: add singleton debugfs interface
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
 Documentation/dev-tools/kstackwatch.rst | 314 ++++++++++++++++++++++
 MAINTAINERS                             |   8 +
 arch/Kconfig                            |  10 +
 arch/x86/Kconfig                        |   1 +
 arch/x86/include/asm/hw_breakpoint.h    |   8 +
 arch/x86/kernel/hw_breakpoint.c         | 148 +++++-----
 include/linux/hw_breakpoint.h           |   6 +
 include/linux/kstackwatch_types.h       |  14 +
 include/linux/sched.h                   |   5 +
 kernel/events/hw_breakpoint.c           |  37 +++
 mm/Kconfig.debug                        |  18 ++
 mm/Makefile                             |   1 +
 mm/kstackwatch/Makefile                 |   8 +
 mm/kstackwatch/kernel.c                 | 292 ++++++++++++++++++++
 mm/kstackwatch/kstackwatch.h            |  60 +++++
 mm/kstackwatch/stack.c                  | 240 +++++++++++++++++
 mm/kstackwatch/test.c                   | 343 ++++++++++++++++++++++++
 mm/kstackwatch/watch.c                  | 305 +++++++++++++++++++++
 tools/kstackwatch/kstackwatch_test.sh   |  52 ++++
 20 files changed, 1809 insertions(+), 62 deletions(-)
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
0250930024402.1043776-1-wangjinchao600%40gmail.com.
