Return-Path: <kasan-dev+bncBD53XBUFWQDBBS5WZ7DAMGQE5UBS2CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id CA118B99A79
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:51:41 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id 46e09a7af769-74a30209044sf8895508a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:51:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714700; cv=pass;
        d=google.com; s=arc-20240605;
        b=eEoaDEvawP6RJcp+z4UhHCxVbpk80bWxKAON1CejPN7aprod0hknMSttlmQP0lc8lQ
         whj2Y9M728hemhgHxC2t7akEIbM2T1CXwE9qRF+IQyTsFUSSjtUcDjB4wdRErevY0xg3
         KvyrSkvqZLuboKPpRDq3WxF5tizqQW2Ly44EEY/hy6fePsUxzeJp8zZj7tR12TgLOlAu
         oTOohF9LR+5gOqjca/RMdJhJRlhSi3yJJDuj126abQ0I5pR5Y4XYG+vZJOaTNE1iXkDv
         sNGDmqb87pUWi5WMIVAQ/3WWPgfDhgZHC9e5SDbfO1ELkj4tmQBrc4dFVlz9YW94Gvi4
         /GSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Caro7Ah42NeIlUV9L3G53QqnwalMUI/KScInXF4RtTY=;
        fh=KTpOptM5Xmi9FW01fQUcuX7JuA0VVJ0QHruntIzvmuo=;
        b=Y9V/llJKlzr6A6m2F92jwFBPyCgxd1GdjOMXbUxVXHayg3YcBKdoxR+Y4b+QCykItw
         OzD+CiolZQJkyUg9qUAso7Ftqf4fSRshSWBuRc57FgQCQzZhNhKjLUTYQxYv9kqPb2er
         4nCaYnF8EzS8V58GIU8UHSSN5HX2St1Dyas1cO8O/THwM5GcKNEimiXSJMWlrFfFnTl1
         fY8IVvO+xAtEips36ydScRbilsQmBbFrN+aVBnWvc3dW3yKPhywowxBTgwT0Eyz8Kk1h
         ySq0UEFFAVA2sHetcwC1BdlzCE//inaGAqNFw86fu3wJ4RpmBbQufJk0E/jtzacgT6Ad
         FMfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aXAi80mR;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714700; x=1759319500; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Caro7Ah42NeIlUV9L3G53QqnwalMUI/KScInXF4RtTY=;
        b=s3NXACtFDEIdHsFE0SdCJubFVjzms6uMgeQ9N0ksBf7oIUJ8QIAXsOBjiX7sBNr593
         gINy498ow4iXw5H9dyjar5q6nVGRS2X65iMIpu0S9mrYhzr7r/ZyerpLzQ0JFMCgXESt
         1YzBN+N2xaTXreaUAkqjMja8uwrbQffDkk+2FpoKFofL2rkXHXbQ3bKa2kNx7wWMLpzu
         TELQMg94M6CvivjGVmPN/MXJKHXKPYNqD6GD6JHzE+LvvlElQt00ZkqDsVLnj1RIXUvp
         Ss3tjeB/Ju8TkU70GfbSQm7yFr1t4XzhxqxqncWFG2DhsKuhoTFgRKBQChUDCRIhGfkq
         pD9g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714700; x=1759319500; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Caro7Ah42NeIlUV9L3G53QqnwalMUI/KScInXF4RtTY=;
        b=RAYt6Cy2r0ycM6emzsZ3WR/PQ6HqfjahvCLgeMLWrkBoe48NdpZNEZlHKVUmGRsdbX
         ZOy/HJ5ktHdkExex07bVJYDDtSejN19pE/9dzLLfoDYYj4T3He30ESto9eFR5ErgIreJ
         mK2tpTQCILLNCNG/gAVKuRfrl1K/OXiYd1vOLpXXbRjGGVCapEp0Y57PjpLb3arKzqtB
         zPocnHV+eOwLLg3AcBLxkMAZ6cX7rZOAgtMZDAMjDFUu2qqPLOaQt89C7NovDTI+ln7j
         G6K3C+IhC7ipT41TE2p34YlC77stXfFA6dboRjEyIZ+cDCythnzaQCpothFFpi4AfmQL
         SssA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714700; x=1759319500;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Caro7Ah42NeIlUV9L3G53QqnwalMUI/KScInXF4RtTY=;
        b=t0FXXnwWe5cNEFvOs87FOC2slidUKEuMGTD8Nn0Sx6c4s51bqTNfvE68qA4XY25K7W
         fDr2B/+5O7LyBGShqJpw6bBFla/O3JkNxKVk8z38WVVrVS7gbRHImEyUkwMfdfzHQAxf
         geeBH/o8kKoo9fhez4YjzEENGu1J8fa2VTCEyOU5lhPdTDI8lQ9WO3XcTW4SkGPb3dCZ
         tADJmfFK83CRzxw6JjW5uTydXEJWSOO5q1EiJNeFw/YYsoXdpokmuKwDHCvJPBPlSprm
         CtswKnzZsxRIJLHf1M/VNztdqGRngriJ3gRDcU4ws33BitYJ5hmzCtFRXdDh8lGalpaf
         fZpg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWNNd7oJII+yZa4J4TFORx/H1bIw7HCmaDfsJv3z/UOluWkxd3OTIXaL88vr8c3Z8uJ5XJO8A==@lfdr.de
X-Gm-Message-State: AOJu0Yyt0WzLu8gx53yam47rJHYjDynd9UK1Pmev2GTE0K0yeUWfeTgo
	6kxzO/YWqdnZ5dYg+h+vPDdm58q/zekIAg7zjgywnWRGvTHhvTRBnu9u
X-Google-Smtp-Source: AGHT+IFWyn4jAq3AkN90nMObhNOi5QPXccOwXHing+KMjk8CiH38pQkfB3RKJXkJFkGMoeD6eof0+w==
X-Received: by 2002:a05:6830:61c5:b0:756:a322:2f1 with SMTP id 46e09a7af769-79143c24f6emr3668601a34.7.1758714699957;
        Wed, 24 Sep 2025 04:51:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5d6EQsnKvbB8z793HbXXXWOrauGx6inGJfPycwEn9LUg==
Received: by 2002:a05:6820:4d45:10b0:621:9037:df1c with SMTP id
 006d021491bc7-625dc27ba7fls3328399eaf.0.-pod-prod-08-us; Wed, 24 Sep 2025
 04:51:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWvziGRy/iY6Ix44dFD+QwwZL2FcoQJYt3HuOlB9xsG5ztUv163SnmP9e6v0mrr37CCoKoEAakMbCU=@googlegroups.com
X-Received: by 2002:a05:6808:23c4:b0:438:399b:a894 with SMTP id 5614622812f47-43f2d431078mr3622145b6e.44.1758714699078;
        Wed, 24 Sep 2025 04:51:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714699; cv=none;
        d=google.com; s=arc-20240605;
        b=bePoLX7kh9W7vByY/FF0ap5hF7nk4mPO0gxf/5IVSyj9w0Xerni2pWFTvGu5in4AWI
         KrmG6wrKSOTh2yeU3KuUFW7Le/YUMpP13khrSFpW2I7IjH8vm3QKe0uE80F76GAWsEGK
         A5BwuZoouLgwk4NfdsY6FR21ejEVe+1B5qL31m9zPlYjZI1Vf2+tsnhDYGsmbz6dUt6h
         41tr1NuOduOlcpDbszFMPRl17CgI8k9emUXilhehUrCq6e8eiD0O7Ex7GmJnVPtFzHbZ
         MhVlh4YuKPWEJ6jK4y9F+JEMV+szY6uZGJX9Tz1fbDgs3VqNNqEfEm38tm/j3ezUdMbj
         7RbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kk8QwiK6ueKhbPm+iybiDp/pMjWX1cNh1XEGnvIxiQI=;
        fh=ALfczD9cpygsfAf3JoYaqYtJDzEVOpGfsesUWKEdhSI=;
        b=aPSerZ8w/EYWTSfkd6PINasfhNduGtd+/dvZDoHh1v7m+7WSjF0na+KMbp3GUmEW2j
         hJcsViI7fAHqzlR78G9NG2Bn9DKwijY6q8sEvXr5XB8AQD6eeBhoyeajvTjmsa1l1YMV
         DzvDAV1k5/9DLMmtv3lCp3U0WfJVQSVxkSGs+PG/KReiLjJWCKE5Y4i17ckpXujW2WDn
         Tab1v7ufeizxW1xUEczGa6IxzM8casRoOfXXf76ek23YrVz0WFfHL+Kfuva7DIY16SVn
         EGncd+tCQpGLtZ8kv/5XEB+/HESsylO6b2c85p+yZQrIJcp9LtPIQHlymT9oI8P5bwLI
         bBPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aXAi80mR;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43d5c4be986si843706b6e.0.2025.09.24.04.51.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:51:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-b5507d3ccd8so6113654a12.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:51:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWEN4HNTgv8SJ3JdSSLrkDUOvfA4Ua9Gh8P43Lqc1KgGkPIlKjA86bNz8wY6LvseTtQrf2EfspgQks=@googlegroups.com
X-Gm-Gg: ASbGnctun9Nwk1x+fj+KyBPXhTCR3K6mkZsg5mVv8+XpMNMiKGW5kOzGzVCfwp+U7cl
	HqpOqIYLsvRR8BSbh9DHlGZfUI6X6qsnIjeyXKfLA5Uq6L5NBDG5UuGxBGm7WHNARew0m31Znce
	SW5/+O3mpMRjQHqDD/3t33ojq4ERVydz/u3iI/oVSGMhh3iTTloa0N0IXjxKzJRLdV4VkvXBm+7
	AHOf4AHqOem/Dn6Nev+L0tfEm6s/1tq9euWRiOjruAEzoQ0VlvJzoWuE2UV58AnjltwTSv4yCbq
	KtHgGoEv0wK0kuKMV+cFKV7ReLJi7KqsQ+09vcOfEHAuCbFa2oUYf0h50pfwzkOjPfRyK/TmAYE
	9q+C7/dGqMxJwUAHSP8MXVxb87A==
X-Received: by 2002:a17:903:2ac5:b0:24c:cb60:f6f0 with SMTP id d9443c01a7336-27cc836c460mr70569105ad.58.1758714698477;
        Wed, 24 Sep 2025 04:51:38 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-26980310ff8sm185687145ad.110.2025.09.24.04.51.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:51:37 -0700 (PDT)
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
Subject: [PATCH v5 01/23] x86/hw_breakpoint: Unify breakpoint install/uninstall
Date: Wed, 24 Sep 2025 19:50:44 +0800
Message-ID: <20250924115124.194940-2-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aXAi80mR;       spf=pass
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

Consolidate breakpoint management to reduce code duplication.
The diffstat was misleading, so the stripped code size is compared instead.
After refactoring, it is reduced from 11976 bytes to 11448 bytes on my
x86_64 system built with clang.

This also makes it easier to introduce arch_reinstall_hw_breakpoint().

In addition, including linux/types.h to fix a missing build dependency.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
Reviewed-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
---
 arch/x86/include/asm/hw_breakpoint.h |   6 ++
 arch/x86/kernel/hw_breakpoint.c      | 141 +++++++++++++++------------
 2 files changed, 84 insertions(+), 63 deletions(-)

diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
index 0bc931cd0698..aa6adac6c3a2 100644
--- a/arch/x86/include/asm/hw_breakpoint.h
+++ b/arch/x86/include/asm/hw_breakpoint.h
@@ -5,6 +5,7 @@
 #include <uapi/asm/hw_breakpoint.h>
 
 #define	__ARCH_HW_BREAKPOINT_H
+#include <linux/types.h>
 
 /*
  * The name should probably be something dealt in
@@ -18,6 +19,11 @@ struct arch_hw_breakpoint {
 	u8		type;
 };
 
+enum bp_slot_action {
+	BP_SLOT_ACTION_INSTALL,
+	BP_SLOT_ACTION_UNINSTALL,
+};
+
 #include <linux/kdebug.h>
 #include <linux/percpu.h>
 #include <linux/list.h>
diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
index b01644c949b2..3658ace4bd8d 100644
--- a/arch/x86/kernel/hw_breakpoint.c
+++ b/arch/x86/kernel/hw_breakpoint.c
@@ -48,7 +48,6 @@ static DEFINE_PER_CPU(unsigned long, cpu_debugreg[HBP_NUM]);
  */
 static DEFINE_PER_CPU(struct perf_event *, bp_per_reg[HBP_NUM]);
 
-
 static inline unsigned long
 __encode_dr7(int drnum, unsigned int len, unsigned int type)
 {
@@ -85,96 +84,112 @@ int decode_dr7(unsigned long dr7, int bpnum, unsigned *len, unsigned *type)
 }
 
 /*
- * Install a perf counter breakpoint.
- *
- * We seek a free debug address register and use it for this
- * breakpoint. Eventually we enable it in the debug control register.
- *
- * Atomic: we hold the counter->ctx->lock and we only handle variables
- * and registers local to this cpu.
+ * We seek a slot and change it or keep it based on the action.
+ * Returns slot number on success, negative error on failure.
+ * Must be called with IRQs disabled.
  */
-int arch_install_hw_breakpoint(struct perf_event *bp)
+static int manage_bp_slot(struct perf_event *bp, enum bp_slot_action action)
 {
-	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
-	unsigned long *dr7;
-	int i;
-
-	lockdep_assert_irqs_disabled();
+	struct perf_event *old_bp;
+	struct perf_event *new_bp;
+	int slot;
+
+	switch (action) {
+	case BP_SLOT_ACTION_INSTALL:
+		old_bp = NULL;
+		new_bp = bp;
+		break;
+	case BP_SLOT_ACTION_UNINSTALL:
+		old_bp = bp;
+		new_bp = NULL;
+		break;
+	default:
+		return -EINVAL;
+	}
 
-	for (i = 0; i < HBP_NUM; i++) {
-		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
+	for (slot = 0; slot < HBP_NUM; slot++) {
+		struct perf_event **curr = this_cpu_ptr(&bp_per_reg[slot]);
 
-		if (!*slot) {
-			*slot = bp;
-			break;
+		if (*curr == old_bp) {
+			*curr = new_bp;
+			return slot;
 		}
 	}
 
-	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
-		return -EBUSY;
+	if (old_bp) {
+		WARN_ONCE(1, "Can't find matching breakpoint slot");
+		return -EINVAL;
+	}
+
+	WARN_ONCE(1, "No free breakpoint slots");
+	return -EBUSY;
+}
+
+static void setup_hwbp(struct arch_hw_breakpoint *info, int slot, bool enable)
+{
+	unsigned long dr7;
 
-	set_debugreg(info->address, i);
-	__this_cpu_write(cpu_debugreg[i], info->address);
+	set_debugreg(info->address, slot);
+	__this_cpu_write(cpu_debugreg[slot], info->address);
 
-	dr7 = this_cpu_ptr(&cpu_dr7);
-	*dr7 |= encode_dr7(i, info->len, info->type);
+	dr7 = this_cpu_read(cpu_dr7);
+	if (enable)
+		dr7 |= encode_dr7(slot, info->len, info->type);
+	else
+		dr7 &= ~__encode_dr7(slot, info->len, info->type);
 
 	/*
-	 * Ensure we first write cpu_dr7 before we set the DR7 register.
-	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
+	 * Enabling:
+	 *   Ensure we first write cpu_dr7 before we set the DR7 register.
+	 *   This ensures an NMI never see cpu_dr7 0 when DR7 is not.
 	 */
+	if (enable)
+		this_cpu_write(cpu_dr7, dr7);
+
 	barrier();
 
-	set_debugreg(*dr7, 7);
+	set_debugreg(dr7, 7);
+
 	if (info->mask)
-		amd_set_dr_addr_mask(info->mask, i);
+		amd_set_dr_addr_mask(enable ? info->mask : 0, slot);
 
-	return 0;
+	/*
+	 * Disabling:
+	 *   Ensure the write to cpu_dr7 is after we've set the DR7 register.
+	 *   This ensures an NMI never see cpu_dr7 0 when DR7 is not.
+	 */
+	if (!enable)
+		this_cpu_write(cpu_dr7, dr7);
 }
 
 /*
- * Uninstall the breakpoint contained in the given counter.
- *
- * First we search the debug address register it uses and then we disable
- * it.
- *
- * Atomic: we hold the counter->ctx->lock and we only handle variables
- * and registers local to this cpu.
+ * find suitable breakpoint slot and set it up based on the action
  */
-void arch_uninstall_hw_breakpoint(struct perf_event *bp)
+static int arch_manage_bp(struct perf_event *bp, enum bp_slot_action action)
 {
-	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
-	unsigned long dr7;
-	int i;
+	struct arch_hw_breakpoint *info;
+	int slot;
 
 	lockdep_assert_irqs_disabled();
 
-	for (i = 0; i < HBP_NUM; i++) {
-		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
-
-		if (*slot == bp) {
-			*slot = NULL;
-			break;
-		}
-	}
-
-	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
-		return;
+	slot = manage_bp_slot(bp, action);
+	if (slot < 0)
+		return slot;
 
-	dr7 = this_cpu_read(cpu_dr7);
-	dr7 &= ~__encode_dr7(i, info->len, info->type);
+	info = counter_arch_bp(bp);
+	setup_hwbp(info, slot, action != BP_SLOT_ACTION_UNINSTALL);
 
-	set_debugreg(dr7, 7);
-	if (info->mask)
-		amd_set_dr_addr_mask(0, i);
+	return 0;
+}
 
-	/*
-	 * Ensure the write to cpu_dr7 is after we've set the DR7 register.
-	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
-	 */
-	barrier();
+int arch_install_hw_breakpoint(struct perf_event *bp)
+{
+	return arch_manage_bp(bp, BP_SLOT_ACTION_INSTALL);
+}
 
-	this_cpu_write(cpu_dr7, dr7);
+void arch_uninstall_hw_breakpoint(struct perf_event *bp)
+{
+	arch_manage_bp(bp, BP_SLOT_ACTION_UNINSTALL);
 }
 
 static int arch_bp_generic_len(int x86_len)
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-2-wangjinchao600%40gmail.com.
