Return-Path: <kasan-dev+bncBD53XBUFWQDBBB4I5XDAMGQE5RA64PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id AECFBBAB093
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:44:24 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-818bf399f8asf92863806d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:44:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200263; cv=pass;
        d=google.com; s=arc-20240605;
        b=bwgKACObeWPwblqcFghi1tdULklOv57CA3y8CPg2GrR80362n3n4BFc9IDJBhgz6ko
         AaRIfg+mfRbJ4wYonwOOClduXBmOh4sc4gOBQ/zrM+JRemXQLtiTCWO+gOYsFyNrw53E
         FQscJevxM8xqfkzLYTlfZz0Z3RwoeBsAZYE9ZIezn7qMh5rYyh0ZQLIbn6F94mxsGmSQ
         mAot9aiMR+iF19q7V0LiN3ajx2o6g8fMV7LdiqALegtK3mQ1q7S/2YjZ5tUVigSryNfA
         zu/orzjz8Ms+cIrvmbPrDmYk1hbZ7qInwaI3JgtW1cJA/SzsjhIzOJawpakwcDcu8LVU
         PAKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=lnA1OpWERzoKE32cnIpaKxgg5La3tH4sjNhDjMvl/tQ=;
        fh=vnibRXGoMSuO3+/lKESjHV3QBjd8PzXm0xIKAhbbpsE=;
        b=EwNeXYj3eTR8GD0u/bFqY3Vu2aPXVJcZuNESC8Zl4O2E+nb3YawZB0uhkmOFGjOT//
         7w7LMwlK3WOsy+X3cc9mTTu/tAycsFJEFLlXWbwAy6Vri5pLUmHuHHK4+D9Y5mJCQc79
         QCdFHkUMhEIohRCw/t0GV9L+Xv4MGLDfAfRAJbQbrCMmMBaEHZVGG6c3ftmMGjBFWrdL
         qmn2sDOsNIVQ8PWCUnb/j1LtGY2aOjrm/qMEaY/4icXchh3gXBg6YXC/Sznv663I+tJx
         i9FexnJ3J0GAciCzsuZhY4ocvXDlrTSsG8iKyhL3rUF9nO9Zsdi2usP88gbIIz4vzsLd
         e+kQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MEask2kh;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200263; x=1759805063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lnA1OpWERzoKE32cnIpaKxgg5La3tH4sjNhDjMvl/tQ=;
        b=RBGpyxOeZ6PZFW2rhJ9AR931POz6XdZLT+KSrhkml/fO1z5CXO0BbFMq3qQlcbnvSU
         Ugt4fx/xqFzq8a+n6kcgcNn/Po0rc+b4R23F0M+zLRCpBOaMq5t/lnvE5fGIJKl8O4jU
         o82foMPHhKKlKeX3ZF1DgA/J8waOX/SGiL5IZWVumhWxquc9xbKeurIImM94raE5YGMa
         Cq9EBGEzzVRrgUppYFYim8d5h8wV1ZYRIKYrl6Px7kaarNHIJmLX6ZrwEO9ax+ax5JNO
         0P2HDEZXiD7MEpIj46KqSHBZCZ0Z4AFkAKOs5unHDlWh5nSkKe8WJbkQ1YURQj4wAfBB
         yqYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200263; x=1759805063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=lnA1OpWERzoKE32cnIpaKxgg5La3tH4sjNhDjMvl/tQ=;
        b=a16Zu5NAnLKDZqkQFaUk5G2fjeDpCr40pf4QzomCHYcaCwZMp8C+fj7ujsfqCqjOrF
         QQUDjMJT6eJLMR1z3+j5714DHDOA5euoSyzai4f8ebfY8nVOiGqazYwNEa4Gk0c+Z7TC
         9D7/oQPwbwOg7z6zTVjso2xPrLkzsBBfPjf7dBuUmzDogfn1Js4nr7Jb9SqpvEwH20zv
         9cNl9Z7ND/+yXx/j+0Hpgc1rNQ5anYK2Xe8zoFkWyhxZuQ0is4BVR8cY/kiHKq2TvQIb
         FWnQLj5S1pYVVgcmyB6+eQLrsj0bIP2jDjrKT5CDd+ttEBlIB7Poc6ImDZAkLdDoCUyG
         c7FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200263; x=1759805063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lnA1OpWERzoKE32cnIpaKxgg5La3tH4sjNhDjMvl/tQ=;
        b=dPInXbqH8LL1Zc93+mQarcIDKP6yijp29fcWVwDW3bGxJyjM2jdrGPSDnV78m2SYWZ
         RZfnaMSiZEE72WczBJhytE5wyO3dh4Dohb4Q3SQKSyZXYEe/dGys7WWuN8zY5fUq4+7n
         gpPw6FnrJ/8Sa7aED8nn0PduL2NdK6HRHcB8dMMfDoFN09m1qmyMxxgvSJc40tVkSHgf
         1/JXLL80saYzjA9D/D2lvBZr5X+ZfwiKUPPF0eDFzfQtesD+43tG6hLT/r5ZlNROQ/A+
         U5vu1NFB3jjhAFwkxnBJldvP6RSr6DOusfLuC5eFF9ezr017ka7NgewxT7rmaR+I92WN
         fydQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFEMtK9dFfNFSNg1olge2//TzsSGh6oy7m+Z57K5RnFNp8NpMzKpr4ahALA35JQgMoGiSl1w==@lfdr.de
X-Gm-Message-State: AOJu0YzALhhFZ7PFDL+chQT4AguQ8m95Sd9cKECHCLjYMooHZhA212u8
	4WSjfgxb5gWsQDi2YeEP5gBh/4DSXulb9M0/ws6nHSbTciMKI72w2Qug
X-Google-Smtp-Source: AGHT+IGUtxt5epFjUyxMq9nd9dZK3fIpSxycsAFlkX33EX2Dytq6oo40iEgKw1PHjrktJFvT3E++uA==
X-Received: by 2002:a05:6214:ca9:b0:78f:2ee8:cf41 with SMTP id 6a1803df08f44-7fc25dedf53mr255043666d6.10.1759200263383;
        Mon, 29 Sep 2025 19:44:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7aX/zHsneM9dwDiM5fCQMi7tniiNV7ou7xXijSeoBeRQ=="
Received: by 2002:a0c:fb05:0:b0:70d:bc98:89ea with SMTP id 6a1803df08f44-7fd82a4efc0ls101130446d6.2.-pod-prod-09-us;
 Mon, 29 Sep 2025 19:44:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXIDcARyo4c83MocYzE2/bKK5DOHDNy/XLymeC5E8pES5dxE0VLYo5vldloCHm2QsqAkf1aenHS6Zk=@googlegroups.com
X-Received: by 2002:a05:6122:1d0e:b0:544:79bd:f937 with SMTP id 71dfb90a1353d-5509a620bddmr94016e0c.15.1759200262545;
        Mon, 29 Sep 2025 19:44:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200262; cv=none;
        d=google.com; s=arc-20240605;
        b=aiOOjg26oCoNSyr5JAlZQB39m7AhuZ/VpIOiZScVImezNPEMGvXVKCtViCWOJjXdD5
         MovA0MoTuwhJzOJysq5gmbRC2RsheGNjz7j5h2pGQl2EgUxyIa/fusipBNNQfz2sCQcl
         5RVTv90fQ4bIjj1MFVP0/l9D010GNB5Am/ewKN0V6FTPwkeTbwE3+VCwijkVs7hYu7D9
         LKJlg3rSltA/6AdZHIa2Q6aLk7R+YlWX6d2LFHiOeZBTWZCB6o3iLgv2ivfu+t9L8G70
         um93tGDuch58q/EILcy9SgS1DQuGba+BJ5unCLSV6Db0yP0rcUEjhbmx6lGm1/onp0BM
         Tdsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kk8QwiK6ueKhbPm+iybiDp/pMjWX1cNh1XEGnvIxiQI=;
        fh=QKCpOxNMmUxld7paDcOxlzT0aDR+6KLjboTqYz68cFA=;
        b=HZ3Ife2vtfu342AiV2RKNHsN7UFx4xsX0H7TlfpVL9G+TDWEJObRGjtIMhu2Kh3ILH
         It4EseCnLZPYZEbxE8dh4fuUe/FK0Ib0BOUWCA1RsgojVXs95kSgi7V2DPe93/Tb7g3j
         CNBwxcJ1PXzCosLYxCRM2WWXU8DAtml51DOMlmUbJWbVHaPVLHYazCrO7l1HvHuP7NeS
         HEswbzxzCou98+8T2mOn6R8R58ny6n8+YWTnahxjOJtnUlzLwy01DS8ey7JxTA+QTznx
         Y30xN09fEsJbejNuPlCJJy83iJv3UqT1OHf5WhkOn/FdCgKwRg26Dc4OTWUJsbthjrve
         GQqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MEask2kh;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-54beddd78cdsi538136e0c.5.2025.09.29.19.44.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:44:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-7835321bc98so2473452b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:44:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXeLi4QX36VEszAu3k2IuS8LrOEKRl8nnsX3sVqWjmHNrrdaLVEauA/LmsV2vRGrn8rXvA4vKqwGkU=@googlegroups.com
X-Gm-Gg: ASbGncs6t2jCJQV4V1F1ENyBnTBLGUyybHUAE682wLf6/M/Ait9Uj5RpMXXTdC426u/
	cMrIVA/jl1PL1ZVp4pKsYMqbss7wq9tIRbICjTUYbWQfOmSMUZuUXwrkr059iN+vwUNow9MWDpl
	0dh4QutvG+wqDeR2q0x/2abcrE/efEfFXXF7p8xCizVkv7TZpjHShz00nq5uvDzJJ3XXc9JQG/5
	b9Xmmg8pZGdYn6WeygaA3D21CIhCO2D/OXxYOgInwYU8EoBsVCY+VOrjodKstyw5YlTli30HQJn
	JzFDhh1fHiUfnrGOQQXDCFoQTPC8S9ibEdfop+eZC47NN/VCcqSwpO8ct1WkEU+tGW0JP+BrVPT
	mjBvc1J/voC48Wfpe5OHgkLztNh8Ucx3CDEwr5qI6ddL3IEtfLCwS5s1wkqzPwK/2bhtF5Xxpo1
	Wf
X-Received: by 2002:a05:6a20:e29:b0:2ea:41f1:d53a with SMTP id adf61e73a8af0-2ea41f1d8femr15753456637.41.1759200261084;
        Mon, 29 Sep 2025 19:44:21 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b57c55a0ef3sm12386161a12.37.2025.09.29.19.44.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:44:20 -0700 (PDT)
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
Subject: [PATCH v6 01/23] x86/hw_breakpoint: Unify breakpoint install/uninstall
Date: Tue, 30 Sep 2025 10:43:22 +0800
Message-ID: <20250930024402.1043776-2-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MEask2kh;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-2-wangjinchao600%40gmail.com.
