Return-Path: <kasan-dev+bncBD53XBUFWQDBBNVJZDEAMGQEP55EMCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AB89C47FB6
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:12 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-34188ba5990sf6722177a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792631; cv=pass;
        d=google.com; s=arc-20240605;
        b=T3kG6TtapgrMOBJSE+wDxFxL0dcQVv/WWoYmVzOrbe/u0G1XAbcPK+1pViNPwDYFrH
         KB2XLqXPZvXjxqirgVFMWFH42uQ7NiCqnRcRvpaVcIm33bEdKC9vDrQJsj+lA/q767Nx
         d7EsmBHF5M0Fbuv1CqpORJR6YMeL6ufGToa0mvpmoBgdPjZ8p57vd0CvsqSnptQPzlT+
         8spx3sKc3J702D2H5DQcP+ev68xaC3+XPntmu67hRBg9Bn6gZr3pJbSHOJUHi1NCX9JP
         fyzU8MZGZbU2sWY9WrPQVDeHj/x4e3GaHdLsY6q5yMNysvaZPv4RfugcHG7iUXfN7VyD
         IFEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=RZSGQptnxgsOTZxDrSjx6/23f9fQYX0gx02IMGTfBAs=;
        fh=i0MeIDdVh2pDgFiEkpQ5EHMzfDPefEI9b4zPF+d8Vp4=;
        b=I5t0fudSZymvD+XSyiSnxQ6au21O6tgzbbWKG969gNLDX8N/ozZj/Iz7QGg9yzozaY
         waUJPKnm9JAu6XsAGwpxlYcqZikspf9fyr/rJXmFeSM14AchPcxRBvOqZfLA86SOypHr
         OpveqKe+sB0+konlgPggnsfIb8Y+iY6M/a43hu0JqRLkLNwka+OotgJpaU+G5aJDE8G2
         0+h2Iq2bTpRqraZ53NTZ+JzTQnXd4TRwXAZX4LwoxeAT1ncrUkOxAcE08xuzTsgL9b2J
         o/LcbChdlTuMcERzh6c1wso2KgSA5zv/UvPmPYzfM7rSmCetqcmF4AD0Ca6tqX2jRLnT
         wgBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="JNwnf/W9";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792631; x=1763397431; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RZSGQptnxgsOTZxDrSjx6/23f9fQYX0gx02IMGTfBAs=;
        b=IRnJ49rg+CzZhwLUo4EIMdLw0ZvIdzn+ISqqh965HzI8hx4IL2B7dYE9NJZKhsSg9K
         VEfOyzlHf6KFH7reIi6nkOvdGqEB+5ANrfmsoPLzEDF2bydD2yrsO5jXVGZmSzxzj1ue
         R/hBDFuI+lOoxrzu8M6LRvHJUXo048QN7YzWmns6Q7kselor1FwVvHeYltwGnhPo3MgA
         hT7JcxX5o+9GsKIxhYCnbmONpxYO8V7BXh5f70NR8NfmqsAbmAgkHGNFr/WaPotEpsjS
         tPaJW/KPqHCfqJVgIU241Jo202DmfjO2FNTWyYRpsa0hiWRolzfYgPzLREsGe2XM0SLx
         dSTw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792631; x=1763397431; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=RZSGQptnxgsOTZxDrSjx6/23f9fQYX0gx02IMGTfBAs=;
        b=hTcHiXJKnO5LaN5UjtR2WNPa+Aru0oCewgNbcX+DQZlE+qk3y3az6GS5bksTcP3R1E
         9TUo5kq1fzjCm1cnKPY3+vdyxAEAiUnmw0+HOZ16UKl44p3rKZDXU28T9/2TTuxL9/C+
         RZaEgMqOVmxZmGGwCx74argkoiVEoF6DYd9bXGyaLM7ZMZgItnjAc04KcKubeTlSBR7S
         UuAH+NfLuC8mpXmFH5d75ruR4XIn5I3Sgifbdc7X+Gc5LsRh/pfZ5Zl0TiRMFdyYbsh8
         8bfplFgVoFJ5Q9GDcp/zgrOByJL6ekmHD3gOzEwhwBetffomf+YcE6KrPQFQOt2O5VuT
         ygcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792631; x=1763397431;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RZSGQptnxgsOTZxDrSjx6/23f9fQYX0gx02IMGTfBAs=;
        b=dvLxQ08KZtULtHXhE2FUWFOLwRERO1VmyG3ER6RGM+nTj3L42/1tWwcCmaIEqLdsz9
         xZZpaf5eiYszru6aX7WyjyoDIlqbVqIrNoVzjG5TF8mNtP1BPm3sjfdl42mux0KL7XJy
         ysnF7UIhMtvS7PyuCjHXO0z08QuT+tR5RA1vAmQM0XSVhwEnLFhlHKLeuQimJ5j1FzT9
         MH93IXxPnjkuxxJPUCtLqr2VpGMbGSB2dll9KAnq1vJBISizpcG0mLsLlQXDf6MeRHDP
         9BNNXjuwbiMzmXVIIpGK80LD9TJ1dnkuzHjpN6o2purh63HTOUfkwW4L0j5Aix6sgtCw
         J0vQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVqnJKDOLVQzkdIcyxbRiHGjb/lPaNXoIDFSmWxXYDymphekixt/jdgRijU071GgFMESrBJnw==@lfdr.de
X-Gm-Message-State: AOJu0YzeZLIyuM+/jJ/H4zZcawPxnjzY4AE/U+FQbjW/q/EPHBrSK4PD
	6W1XPbMfTyQf9rMktSPpKen55nQ6Yz9GhyCbHXxysjX5Q+r/ncmLuInP
X-Google-Smtp-Source: AGHT+IHBVp3W6BK8awBJsS7P4F6JDKvrYgQ376B2Os/KVmXXopj4nC0N1HACOql5UIJhMpMniVpYUA==
X-Received: by 2002:a17:90b:58ef:b0:32e:70f5:6988 with SMTP id 98e67ed59e1d1-3436cbca50emr9903246a91.32.1762792630622;
        Mon, 10 Nov 2025 08:37:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bPySBaiFew2PVPW5GuOYVBU3Y4iNjw0iwAuWlzUhrZfQ=="
Received: by 2002:a17:90b:1d90:b0:341:1d2:286c with SMTP id
 98e67ed59e1d1-34362ab7d12ls4195266a91.0.-pod-prod-08-us; Mon, 10 Nov 2025
 08:37:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWlowAMGVAEu/halrAUCdWV39OFb7zAY8ZVHrC5Orw7m/25k3nmpHNoZxJgTfIwx9ebFWqZDJ91rpQ=@googlegroups.com
X-Received: by 2002:a05:6a20:7f8f:b0:34f:ce39:1f47 with SMTP id adf61e73a8af0-353a1ae3029mr11135155637.38.1762792629176;
        Mon, 10 Nov 2025 08:37:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792629; cv=none;
        d=google.com; s=arc-20240605;
        b=RnHV91zpJuvoWhiaH7FewBYpbQIHotkpLj2zKRvlYhZhzAkzlVX9hRbIoseUg2GUa7
         vjiEvdd5FhCCdmkAYqfALRC1W6GyAGKQ/dg0ktk1NlNNhkgxSzzKZsp19M4eywjrPB9I
         abwemuspMR4WGJp7pQyEReRd9jEmDJoMVBqi8O9Mb+7mNBnKCkcWZxvx9WgsPYY3rcwA
         PZQiSNKg8jVA/F8JF0yJUCYDSUkn3lwi2/yT5oHPFeSTDts62Yiz9JY3C8HRJUUgvNnK
         AjGWwYQvXwFZCudfKEZ8TnsugKTCLRqOXnLn4JAL1wp9QhigMTv0M1wOP8k2h11Q/wis
         NVsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=RDpE0CvbPiS95CD/e7bDhFl1FHfdcNhWeVLe6GjR39g=;
        fh=t8OwC2Za9wUDX4/7jdUCV3+abOGZzNNe1J/H9+SiS3k=;
        b=PlXePOaDV7JnqzGYSXUYjVwnzre75xV0bA9QoerHqMV5rdeJxs2KQhwnf4Om4d0koL
         mJjilx+0ZwG+BV6ggs1gmogr4GmnSHU4ljUBKLJFY3K+ich4qqAOjOqwhCpr8Hm/xB+g
         uiPwedu3uS8s2I+TsFpqVzqn36DKSOvihPxlnDv3f8ZUwDr3i/WJHg0UJjc4Z8wQnDrQ
         FWkvAVC66bac7GFl/1AdPTBROEVIAJKu27DnTTrIuvucGq0RV7goZCiJ/zDZwjgixrd1
         9KTVMPrFsK2gH1Az4g8stvx5fKpVkOAyrWlf23xUea4KwpjtQb0F3gsmu73diIgJBpVX
         I5jg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="JNwnf/W9";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7b17be55bbcsi377814b3a.1.2025.11.10.08.37.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:09 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-2964d616df7so41370525ad.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:09 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV2DhNYvrPmrrRBa9KdqjAyWlldd1kdDPR9xFUaKtzApq9+rovZYl6NPdj/R+SCmRJPRWyxjNr5v/4=@googlegroups.com
X-Gm-Gg: ASbGncuOwyG3v20J/EKSpmRSHjWdIuYrG09ym2cFdElODV48msJYrQ4CbBpVH3eF7oM
	rQxo1F9QS8sS+zVCMVtLw6NSizbJoPxKq6xUpEfUtjgD0Bl8FNtpgIr0LgVNSKeJ/TrnM9tfvxo
	jgdDyg5873gMJcD8JYUGEH1tEr67slrTPHdLxkqOZZNoAYbUyP3Xa+mN2HDPUAOKbmFo/o8TXG6
	/8UOMd0B3GtRbE+c8O6f2ROYcdA5psn6bLVapdne7gY3nrsnkYevoxpi42+IN6dncpq4Sk5h5B5
	RIGQHKs5kPGMFJhrOWA7LAHF5u+kUSya8Mmp+R9TYn396NiPHVNIi1vagn61EBQ31ok/FdEYDGq
	+Rx/SbvzdlaFFhVZzYXcqR/+L8M4t7Stuj6PYPTzW9DcLyIPLJLyPaqxkT42VTgQEt/aZU9s5gd
	g2pb+LwPJhtHJirD/hfdIA8g==
X-Received: by 2002:a17:902:d481:b0:295:9b73:b15c with SMTP id d9443c01a7336-297e56f9c21mr125602655ad.42.1762792628683;
        Mon, 10 Nov 2025 08:37:08 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29650c5ce87sm150073335ad.29.2025.11.10.08.37.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:08 -0800 (PST)
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
Subject: [PATCH v8 06/27] mm/ksw: add singleton debugfs interface
Date: Tue, 11 Nov 2025 00:36:01 +0800
Message-ID: <20251110163634.3686676-7-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="JNwnf/W9";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide the debugfs config file to read or update the configuration.
Only a single process can open this file at a time, enforced using atomic
config_file_busy, to prevent concurrent access.

ksw_get_config() exposes the configuration pointer as const.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 include/linux/kstackwatch.h |   3 ++
 mm/kstackwatch/kernel.c     | 103 ++++++++++++++++++++++++++++++++++--
 2 files changed, 103 insertions(+), 3 deletions(-)

diff --git a/include/linux/kstackwatch.h b/include/linux/kstackwatch.h
index dd00c4c8922e..ada5ac64190c 100644
--- a/include/linux/kstackwatch.h
+++ b/include/linux/kstackwatch.h
@@ -35,4 +35,7 @@ struct ksw_config {
 	char *user_input;
 };
 
+// singleton, only modified in kernel.c
+const struct ksw_config *ksw_get_config(void);
+
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 50104e78cf3d..87fef139f494 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -1,13 +1,18 @@
 // SPDX-License-Identifier: GPL-2.0
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <linux/debugfs.h>
 #include <linux/kstackwatch.h>
 #include <linux/kstrtox.h>
 #include <linux/slab.h>
 #include <linux/module.h>
 #include <linux/string.h>
+#include <linux/uaccess.h>
 
+static atomic_t dbgfs_config_busy = ATOMIC_INIT(0);
 static struct ksw_config *ksw_config;
+static struct dentry *dbgfs_config;
+static struct dentry *dbgfs_dir;
 
 struct param_map {
 	const char *name;       /* long name */
@@ -76,7 +81,7 @@ static int ksw_parse_param(struct ksw_config *config, const char *key,
  * - sp_offset  |so (u16) : offset from stack pointer at func_offset
  * - watch_len  |wl (u16) : watch length (1,2,4,8)
  */
-static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
+static int ksw_parse_config(char *buf, struct ksw_config *config)
 {
 	char *part, *key, *val;
 	int ret;
@@ -111,18 +116,110 @@ static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
 	return 0;
 }
 
+static ssize_t ksw_dbgfs_read(struct file *file, char __user *buf, size_t count,
+			      loff_t *ppos)
+{
+	return simple_read_from_buffer(buf, count, ppos, ksw_config->user_input,
+		ksw_config->user_input ? strlen(ksw_config->user_input) : 0);
+}
+
+static ssize_t ksw_dbgfs_write(struct file *file, const char __user *buffer,
+			       size_t count, loff_t *ppos)
+{
+	char input[MAX_CONFIG_STR_LEN];
+	int ret;
+
+	if (count == 0 || count >= sizeof(input))
+		return -EINVAL;
+
+	if (copy_from_user(input, buffer, count))
+		return -EFAULT;
+
+	input[count] = '\0';
+	strim(input);
+
+	if (!strlen(input)) {
+		pr_info("config cleared\n");
+		return count;
+	}
+
+	ret = ksw_parse_config(input, ksw_config);
+	if (ret) {
+		pr_err("Failed to parse config %d\n", ret);
+		return ret;
+	}
+
+	return count;
+}
+
+static int ksw_dbgfs_open(struct inode *inode, struct file *file)
+{
+	if (atomic_cmpxchg(&dbgfs_config_busy, 0, 1))
+		return -EBUSY;
+	return 0;
+}
+
+static int ksw_dbgfs_release(struct inode *inode, struct file *file)
+{
+	atomic_set(&dbgfs_config_busy, 0);
+	return 0;
+}
+
+static const struct file_operations kstackwatch_fops = {
+	.owner = THIS_MODULE,
+	.open = ksw_dbgfs_open,
+	.read = ksw_dbgfs_read,
+	.write = ksw_dbgfs_write,
+	.release = ksw_dbgfs_release,
+	.llseek = default_llseek,
+};
+
+const struct ksw_config *ksw_get_config(void)
+{
+	return ksw_config;
+}
+
 static int __init kstackwatch_init(void)
 {
+	int ret = 0;
+
 	ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
-	if (!ksw_config)
-		return -ENOMEM;
+	if (!ksw_config) {
+		ret = -ENOMEM;
+		goto err_alloc;
+	}
+
+	dbgfs_dir = debugfs_create_dir("kstackwatch", NULL);
+	if (!dbgfs_dir) {
+		ret = -ENOMEM;
+		goto err_dir;
+	}
+
+	dbgfs_config = debugfs_create_file("config", 0600, dbgfs_dir, NULL,
+				       &kstackwatch_fops);
+	if (!dbgfs_config) {
+		ret = -ENOMEM;
+		goto err_file;
+	}
 
 	pr_info("module loaded\n");
 	return 0;
+
+err_file:
+	debugfs_remove_recursive(dbgfs_dir);
+	dbgfs_dir = NULL;
+err_dir:
+	kfree(ksw_config);
+	ksw_config = NULL;
+err_alloc:
+	return ret;
 }
 
 static void __exit kstackwatch_exit(void)
 {
+	debugfs_remove_recursive(dbgfs_dir);
+	kfree(ksw_config->func_name);
+	kfree(ksw_config->user_input);
 	kfree(ksw_config);
 
 	pr_info("module unloaded\n");
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-7-wangjinchao600%40gmail.com.
