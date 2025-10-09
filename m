Return-Path: <kasan-dev+bncBD53XBUFWQDBBBFKT3DQMGQEU2PJ3OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AB1CBC89D8
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:10 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-43f48ea2607sf271034b6e.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007429; cv=pass;
        d=google.com; s=arc-20240605;
        b=EkJFW+/YPyILJWfuPyTdqFPidoA82YD8ppWMbAVTcXPBGmFGELf9aT8gmDlIwgpL+J
         MqnpwNJk3A5d+2VMcjtcWhkkQvSfkmDOorAavnXXNIzksr3/gRv7D4TLaRWvppcb4wHK
         BSLqOnWN+PCnSkUjbbASWg20sM07SIUIZN0hHu9DzUGNWKFP7a3Zye1h5HKOqchoQPsn
         VEVvrmSm076d2gyvkKfRdQvKYkEIanYmnjwM+uLAkfAZwTkXuHLiMIGamJ2nShqApesh
         Gqh5KrtiRm+NF0p/LGh4xOh+RFO8iyfTbIkSqZfupA1Dva2v0V5Xo9x5ziTgtQyPh0i6
         Vz8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature:dkim-signature;
        bh=g1b+gexjL1zdxNCUHZGzvua2r4rg6uxhm+WVJdyar3E=;
        fh=WKxT0eDKR6bwzhgZvJR4iEFarIVpl/m+8gtcHAvLbcY=;
        b=ZJx1+IFl8GQXp8zfzwhuJlB6d5RnpBJWkp3r1W3DTuD21zK0bbVAn+Lj/4t2qW6rtl
         9sLoz+KgAVViI2GnCb4f1061oErBJu3p26/L5w/yYW1NnYQQocaaSGzsJVVdrsIDtKKj
         x0kBjpwqhgBEkAIfHsmXUhnHLe5mkM8JRplbn7LqpvYSm0xWHwrEZa+Td97WXttO8u0v
         vMPa18GInuALkSgkcXItB2s/DHKOHzS3C+lba5Q0daRJ1C58W2dJcK4PyG6fulgBBVSO
         ajHeCg9gS+21CvnDitUKfNNiiai4Z7gemLOgf1TjbTbFnb18drA2S2yXGCRT3K0YIz/c
         DzzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Opf3AW6B;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007429; x=1760612229; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g1b+gexjL1zdxNCUHZGzvua2r4rg6uxhm+WVJdyar3E=;
        b=qqfFVE3Yd890sJJANTgkXhydiljzQLHAT8IU9cCUFfs2TDmWvMru3I9mNofYU+M6wj
         YGGwEG5h7TD4QFi2svjNwE4zNucC41HvGsfLGK7EtRztS416Z6Cn0ohv2Idq6bMjPCsb
         NkanOsUHUTQEBaDwzMdUhhTpqCliOjNK3KHOfwELVMHZbeFFCwMniHwZmS8ONzqkpkAG
         UezZZAjyQMZZmYqGVIJxnX+OA3gL5rcZRA0/BhOgDuY6HIbhZ3jAoFUb0LrhWuFP1+pj
         j+RyM/h9yfydZSOYkpmEi0IDyGEvL/UtG/aI3lmtxqCJXIaEcai+8w+Y6NyK3e5Cy2ky
         aFbA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007429; x=1760612229; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=g1b+gexjL1zdxNCUHZGzvua2r4rg6uxhm+WVJdyar3E=;
        b=JYlszGG3/142niYYvbozdDtODLE9QZEVkUon6avYHZSFSg7q1UxxVJC87L/LTEjq9B
         +aY9LlG/ThaeKXdWV9WfHhLMALdkvATPesd7h91M0qjsKTnyAPRQ0SmQ051eZa645yYv
         D2OffcFw+MSmlx2PejfF4xey6z+STYYWlyXqnqQhrmCHSl0AXJnPt40Pd2u47ByryTqm
         6acacZ0nZLicfWrxUIyANQL61RrJ4MMjd5jDVPCJPcYV1Cw4fWUwZVNrHECUngH7P+uW
         A4G/IPEIME/Sj946isVsmKYNm86UiZ8hdnDKnLVA27+8uLeMnIb+d3SF42IDpgSYLRt3
         LERw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007429; x=1760612229;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=g1b+gexjL1zdxNCUHZGzvua2r4rg6uxhm+WVJdyar3E=;
        b=ZKkFbgG68MGoicRQLhQQQkkNfubbvtx5GBJchgI2eDpo/fGGpVwAd0rxT2DkIFkD/+
         +/K3gjbPQT2+ULYOvt9whvgKhkbocmHlXt0zAe1Qh09sGSDifXjPhzqej0FuNANNLpP2
         7T7ikRBqnnWC5P3L7lMXrRv5bOxHoR8OdLZ3CJ+06I6y1MVcXyAcKRAcFht9+F6+Tcl2
         NRdP7ed7FcC/IkDDI0L5HfHlaGTat0aFKTiGY+LkWHMAQr7zY2MxODJlxYYr0ANGnHsy
         ypEkfuKwJXDPgtSDLLo9Ycy58dcavHblw7vSIZ6RTocEN9Ubh8bweeJoscH4Y86umeHR
         r+MA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXGgZL99qPxEHffkBZCK2c1e3xab2sf2xSaSiyT8cqrT8nU3+kwv52QEl2MVizDbDTfKScUJQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw3/CCSx0Vz42ZCmm9OeWkpqNY83LFTSMFpxxJLqT9Zt30gCeL8
	W+mDUqY/mjB8uVAPQLqmXCEH6L8/nh+XQX0lIzmCz4C0i/uP9pGIgxYj
X-Google-Smtp-Source: AGHT+IF6g1/p9kWLCxlHpPsPZ6Xo/1VmG3Ggob4RKHiqB9xGeGQ2RUdSLFxo7TbSyfC9ZEjtMImrQw==
X-Received: by 2002:a05:6808:1906:b0:438:8ad:16b9 with SMTP id 5614622812f47-4417b395966mr3334986b6e.32.1760007428925;
        Thu, 09 Oct 2025 03:57:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4HMn7pGCAPtuyCUUM2egipk8cN+WQ9xssxMN9xXogI3g=="
Received: by 2002:a05:6820:173:b0:621:767d:34e6 with SMTP id
 006d021491bc7-6500edc9fe3ls203345eaf.1.-pod-prod-02-us; Thu, 09 Oct 2025
 03:57:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWMX2vxL9kvrYUQJxJauxvALVQke8kibJ+9Ren9Jg3ktkEMrVNF+EgPPe6X44LZyE4PC/dR4KQtsFI=@googlegroups.com
X-Received: by 2002:a05:6830:7197:b0:7b8:f2a2:46b8 with SMTP id 46e09a7af769-7c0df7df8dcmr4162409a34.17.1760007427934;
        Thu, 09 Oct 2025 03:57:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007427; cv=none;
        d=google.com; s=arc-20240605;
        b=VAgIF20n0ZlAPEV4+mJH+YmYl/vNTMOdd9U5J1JPzT+VLw+4dN/9KlXBlFRYZo3+5A
         D9GyxHmK7fh0XDgIplBpGawLp8mf2Z16n7bGRypIPY1V+T/FtV7ru9jxW4YRQlsAQ7xw
         XE8e+iMeLusLUp3re7c2HaG27mmHbO5nYwy9b58uJsZcjD7xs7mh7Czu/SCQG0zZcB5Y
         xDjGvU/JYQVby3zGkS1HBzhJZZ/c9d67qubnINmH8MRpeyMaVWeTiKXfhu+FCY7CDXeL
         JRqWad4jClpG26HwZDB6cUDhBzx5NC5XFuS2soluPR7N/2+DH1lZX2amO1LT00ApyvXl
         Gxvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=r/KVNrCgkP/CpH67njDEKsgcguKTfOKueucBYEp6ELs=;
        fh=IOFedpvjXuRFP9T0vWyaTmsrOWP4lLoD7zBgXebZFdQ=;
        b=aEpFjf+HnKHb6UyVnuiTSVDMGYnpztowplwe4BDTqnd0rWn+TZ+zcnlv3AJgPb4nuU
         WUSGLAMIFp+BgN9rTFIcwErxBdxV2xuB8OCW4N/VQ9L0IuYqP7z+CA5x0R9sGTKuTbGG
         p03+CbPWOY6NsNraoACNTvsSp0PP4WmjoxQojiilWclkvOpA2PJKXPAO+fQIt2Yods52
         ZNqlDdo6wVaVja2z4P7wDlU+kD2cuSWsCX0ISiMXWXNnIfMnphbYv13Re5mOUu8SMLFH
         pNTkNRBhy6MC7NK1Aolmwbl0Rq/rC+jzK1DcNo8N/kEaPJVCiToj0D2i0k+PbZYkxBpO
         cJjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Opf3AW6B;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7c06be0892asi78741a34.5.2025.10.09.03.57.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-781ea2cee3fso793286b3a.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVuuFPAITpwCkhuQWuOyDXYuvsfB/+aFsMISn0yPlW/3+1SjF2qgOC72zlqbCOqK+Ql+5hMG+Rd7Bo=@googlegroups.com
X-Gm-Gg: ASbGncvZ55zWXV5AnP05CGUglI5BrNZwGf1MHPu0nredcz/CKWUmAUar/reL29Z9e8s
	4s1hSTTdZd6VnYUqh6KMDRKpKz+mwViqc9JyaFtBxroDXhdN2h6qFNCAGj0HVa+m2rlxD/DN5JA
	TzwCPW5um7XaUtLGSuGMAxgkDn0y9ekRZtWV4yvCnZAdVmM9gjSPFHBf9759smYoz0l7H4DmFzl
	SNw+apR5mVUpsUgVDD2exF8usgcJ1TUC7k4DDk99DzI7yfedipIqRZVB7co/7phKHlBNLR3+UEF
	r1J78NqaYlodTci8DjlRUCCO37uIYQn0BqsEOFfttZeGYSzxvJHiz0Bmc3x3tNbSo2OVssyEOKb
	wb9deLbNK7OCCTkQoBxyAF0Nop2pBbUPBE6c1/RFod8ZyID3fh5RDtpEkV/KV
X-Received: by 2002:a05:6a20:914f:b0:2c4:c85a:7da5 with SMTP id adf61e73a8af0-32da81345e5mr10045407637.6.1760007426930;
        Thu, 09 Oct 2025 03:57:06 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-794e34e6f17sm2514275b3a.82.2025.10.09.03.57.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:06 -0700 (PDT)
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
Subject: [PATCH v7 00/23] mm/ksw: Introduce real-time KStackWatch debugging tool
Date: Thu,  9 Oct 2025 18:55:36 +0800
Message-ID: <20251009105650.168917-1-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Opf3AW6B;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

V7:
  * Fix maintainer entry to alphabetical position

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
0251009105650.168917-1-wangjinchao600%40gmail.com.
