Return-Path: <kasan-dev+bncBD53XBUFWQDBBXNJZDEAMGQEHA7VBRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A0EAC47FE3
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:51 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-295592eb5dbsf29082355ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792670; cv=pass;
        d=google.com; s=arc-20240605;
        b=JGucNg/gx2+KPxjXbQpqoD0DcfNj9i73upGvhmiiZ0JP/nqNMowkq/U9DW14AgMFls
         m50T3Niw6J7HjhKjnzC5nEeISDvZCqXOJn+UFvgiFB6h9WmNjRu2L2cg7ZJhVYfPaqzV
         LH8uFU0eUk4L0tvj0rVn4mK0p7kwSPx3EcGg5OA96gheyqiQgfNg/VqDe878WlYLKXL3
         e3iEEsRbnk95QtpG8j8a1z/PMd8a+C/+GBLLx6ULZFfaspmsiKtwB9CLMbkgMBUmQonn
         1gQhLFv+UVUZ19G38y4KPkN/j8bw0RzKHa1/sz2c/YKv31uR3HlgK1fH8BigboS2k4+x
         GZ1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=fMVhOSeqVhkwvRx7xoSlAgTvVO9DBAD/31WEO1ai2Kw=;
        fh=ZMUz5s5wpochvIzbDVbd79kegJSuCI/hz3NYefQcrMQ=;
        b=JaUkfNRZ8h/rWL+kt2BHELQipJLY5El/in1QQ82m+YQyXoOXKGOghiAm5t68xII4MP
         ooP+UMmwiZS/zYcoN42cIkUo5FgVL+IJkWRdSFtVJTLXzYzBN02cfwO+hhsHSwebm76s
         x4HrgHBSqxXJ9Xn8gdQdWPK4jXlcXVPeIsTF1JMz5L9VCqwRUm63HmgaTHVvGnxxWgL0
         pQMWiYdnvg80B4WvKYYGYpJ+yda23L4LFy+jaLZQ+Y3lnp+UtxkxSFp5eDtsnTRHzbNo
         15nwV2+RnlpETAgGXc5+bJcOEfpt+FTiU8GwvIF1GKgL16QVPgJ0jRjo+KvJH2c1X1RX
         mfqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FBKOk464;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792670; x=1763397470; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fMVhOSeqVhkwvRx7xoSlAgTvVO9DBAD/31WEO1ai2Kw=;
        b=Hxk3/h7mExjxFng9C8laBll3CLR8WYfXdKCORAAh4RMksAsf6XW/gQuktmQ8NvgtIc
         AZjUoBPi+OVNVomnCmlOjTwLYcG8zaqs9iiDfelqDOXw1/IxPsWM8PTeLznadGMOeHET
         tY5NlRGSx3Nh3bcbvTdqBqez6z+kKmTT4iPsQxPRu9f4hwkAZvrHRnE0mL5Gr2q2GKwH
         Lsd21d2exltE3Ig6VDTLRGzNwSJm+zib+Bn2HlImawsGyTX3cTby5SCJ5ILE4jctYMmc
         XqBV2dfJSCv77LqXaw6BroaizXXsVExkOvjzGn2HPw/ffmFG/F0kkixQtSas5BseaTc7
         xvMA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792670; x=1763397470; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=fMVhOSeqVhkwvRx7xoSlAgTvVO9DBAD/31WEO1ai2Kw=;
        b=DGu2VMGyqEqUVOtALP7kI4UoG6Onnz7ONq20wxHSyX7zDvLF158BqOn+dqTQ9BXCEn
         //cn/PxT/Wo8VDehIMyWL2i0MCyxOEtVdiMakUMneC9Ec9ymWceh5/AKWTD+P7eBdDdp
         DwoDjB83hG1rSyPLRBjJVzqu8dU5Ljj9yKXCz/FAXEbyf7HrdWblA2sBg91MiTJSQBgc
         LfakMCToJRTmMk+t7T5EQo35V4VOP0K3WZRR/hFJ9bpxLojxsOgWPS+2FbSfJ8mE1mAi
         t1T/z9XER89ByDGidBgGAbImW5irEUAODfSLGiNgjiSU4HQj+wNosvC2rXJSZR5fGST+
         nrdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792670; x=1763397470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fMVhOSeqVhkwvRx7xoSlAgTvVO9DBAD/31WEO1ai2Kw=;
        b=CcuB1aaaL0CQOizhkGWnIl7opjyDs0SPu7Ts/8OoLYlTKMsU17ByDWoQFxNmJbzN8n
         wmtns3MKnD+YjArPlRDLCHamtVa4E61RSgyqa+mJ6DGA5FBCQA9j/0sQVU0LfRd6POjO
         p1Wqtx7gbZ20Vj1vXHQgIyZS0hVseVuQPvYy7Emf+ydJSpaa1GepjhLfUlp4CFYQR5kn
         ZN574+1GMdElbf9udeOu0880rM8qRHPTrVD90tu9AOBM2wLYroqfr4LrNiiQc/f2Ki/o
         GBoquAOHoFHwlRKwsUC5hr0RoJbjBCB9eoaN0QuhTWugdTXy0fCEx6+gUYjCXvRjANpF
         JkiA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWIF2wwDyVOlAKhv08ZOV62fbDStbhyGwrZNFazx90X5+scPxOiqmZN+Dwf2mtq8TVKsm4c0w==@lfdr.de
X-Gm-Message-State: AOJu0YznE969WfFpmhHARJPLdV2xOZtuApNpTvWRe3XWbFb0alw6TNFE
	Mhk9tx8Y6l3fo8Is2xFxzwvJNAODHWoqadE1rzTsyh5KvbLuNii9AHur
X-Google-Smtp-Source: AGHT+IH0PKz6XHqIpQmzwR/l1JFz6P6eWORJzp+0E16nihx/wRL/p8+8eOYtEXwJlXJKzjcXcJGglw==
X-Received: by 2002:a17:902:744c:b0:296:3f23:b909 with SMTP id d9443c01a7336-297e56c9e07mr89024455ad.39.1762792669745;
        Mon, 10 Nov 2025 08:37:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ahxioQXU5P/OEuujP522Xad1VcvYlXY3Uo23HD/wCMiQ=="
Received: by 2002:a17:902:7b94:b0:295:586a:9d87 with SMTP id
 d9443c01a7336-2965231f700ls14264525ad.1.-pod-prod-05-us; Mon, 10 Nov 2025
 08:37:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXeFZ1WmcvUOkgVH3r7bnE6gliJR1Ge01Crdc8iaHN6wq9yBitY9YtsQaSyxXv2IxAOM+hQM37bGsk=@googlegroups.com
X-Received: by 2002:a05:6a20:244d:b0:34e:c920:35ee with SMTP id adf61e73a8af0-353a1be1288mr10936079637.19.1762792668340;
        Mon, 10 Nov 2025 08:37:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792668; cv=none;
        d=google.com; s=arc-20240605;
        b=XdJUkRcD92nhg2d0NoVL4Jmmwb2LeiD1x2PD4hE2/FmJTgY1jbGuqSPzJH8UeeymsR
         vi9TJUChYFDjmtuNXsSgyl2gvIriMpxxKH8CPDlsHSS3uJfNkqQw/CaUmcydFH+IJwQa
         7wkIzFerpKhM7EzKWRow1Y0CP+JgXzWn8p2RQUjSbpHJONR66spUk7KwzMysXWkLLy5U
         tOs0WdXGNezacLbFnO+xQuJ7pX0k6Vej/edovrGPRcG0ldgyy7oVPP37wTUckQ2M/mIr
         q4ywbIzvYTfwABEAYXBqv1Kn4tVIOyOIBnhDrxNDky9/b8CFG5XXLCzBqsRNMjLqyuTq
         MlKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=mbgbln0r/0DljbZ66YwwMMl7cTrgB9t9J30U0WpMJ+k=;
        fh=bb+Ti8OGGkmTqdc0XpLea0jV148ZbmVJd8A7WqOb0Zc=;
        b=VKo+2QSekCq/0RcshGBoOh9MX43jtu7xOnaPvFb42U+gPhizQn8eAUNoV2XrmmYDLc
         VGTykr/AcysXVtE2/Al0Km5Ope6voV575kvExMfy0XOXV/ycLrkDLZvkJ0Gk88hcgYRd
         1yUT/h+Aw9LxCvdmFTvtA1qbhskH3eyQ+CAS1mmYRZUC7vOjxtTo0fhjPLzES61wz+AM
         P60cE6TP7930IVK08HS3dMP9VcHdHTsPdhCuIbcc0NvI0DQ+dCw6Zwluzk7B6Ra6pedn
         6cyzqme3XxrWtxuZMjn+VVZvWNaFcezOAht40BJ9tnH3OGenOJ9eWw3exAJ+W3zY7vo8
         2JQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FBKOk464;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7b0cb3a3883si294610b3a.3.2025.11.10.08.37.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:48 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-297f8c26dc7so15263245ad.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXUhFXukay4cRd85oig2jNYo9pH5D6DHz09Xv3WkaDWjEHBTOcEgQ6kTEqzEYBUJ6YJT8rOSonmaCc=@googlegroups.com
X-Gm-Gg: ASbGncuYByTK5CxW+p4/QkzdmF9aE5GrE5mWHtkj8uQ2VoMpyY0naO9/trmavmkgNeF
	+nYxWszNfskmCDnEuxcLLXt/J9x8UhDJmL/NO/Dkb/SYsh0z8I7amLmdWvRZvmnYhkR9MJ8SZsx
	3HsTVFgLc5JCsDIEl1YTLO2QWmpMmNDE2H9pNOZwbcdfD50CehIMiuz1F4eelWTwKYq/HV9mlvY
	MaREIScRAHHczTI393bgJFFF9I6kykmvpBvDS9z35ttjEXI0Wm8X0xtU2JQnSefrH5nTZL/wXUp
	leuTICmV5yqTcRsMlRH3MLbEhv7PTxlADdmt7EKmpTir4IL75hm2u+PatbLgSb+6U2TzZtXK+j1
	dq2lFtqwFxxIoB/Uog7M88aIVz3Li/1+yGDIv4n+Fw30K4UMi77wAi19V2geufnSXEo5/hoOZ1I
	1/VE0uJDxsrZg=
X-Received: by 2002:a17:902:ebc1:b0:294:cc8d:c0c2 with SMTP id d9443c01a7336-297e5663a67mr107303455ad.27.1762792667923;
        Mon, 10 Nov 2025 08:37:47 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29651c92cddsm154610615ad.83.2025.11.10.08.37.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:47 -0800 (PST)
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
Subject: [PATCH v8 15/27] mm/ksw: limit canary search to current stack frame
Date: Tue, 11 Nov 2025 00:36:10 +0800
Message-ID: <20251110163634.3686676-16-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FBKOk464;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Use the compiler-provided frame pointer when CONFIG_FRAME_POINTER is
enabled to restrict the stack canary search range to the current
function frame. This prevents scanning beyond valid stack bounds and
improves reliability across architectures.

Also add explicit handling for missing CONFIG_STACKPROTECTOR and make
the failure message more visible.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/stack.c | 29 +++++++++++++++++++++--------
 1 file changed, 21 insertions(+), 8 deletions(-)

diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index 60371b292915..3455d1e70db9 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -64,15 +64,32 @@ static unsigned long ksw_find_stack_canary_addr(struct pt_regs *regs)
 	unsigned long *stack_ptr, *stack_end, *stack_base;
 	unsigned long expected_canary;
 	unsigned int i;
+#ifdef CONFIG_FRAME_POINTER
+	unsigned long *fp = NULL;
+#endif
 
 	stack_ptr = (unsigned long *)kernel_stack_pointer(regs);
-
 	stack_base = (unsigned long *)(current->stack);
 
-	// TODO: limit it to the current frame
 	stack_end = (unsigned long *)((char *)current->stack + THREAD_SIZE);
+#ifdef CONFIG_FRAME_POINTER
+	/*
+	 * Use the compiler-provided frame pointer.
+	 * Limit the search to the current frame
+	 * Works on any arch that keeps FP when CONFIG_FRAME_POINTER=y.
+	 */
+	fp = __builtin_frame_address(0);
 
+	if (fp > stack_ptr && fp < stack_end)
+		stack_end = fp;
+#endif
+
+#ifdef CONFIG_STACKPROTECTOR
 	expected_canary = current->stack_canary;
+#else
+	pr_err("no canary without CONFIG_STACKPROTECTOR\n");
+	return 0;
+#endif
 
 	if (stack_ptr < stack_base || stack_ptr >= stack_end) {
 		pr_err("Stack pointer 0x%lx out of bounds [0x%lx, 0x%lx)\n",
@@ -85,15 +102,11 @@ static unsigned long ksw_find_stack_canary_addr(struct pt_regs *regs)
 		if (&stack_ptr[i] >= stack_end)
 			break;
 
-		if (stack_ptr[i] == expected_canary) {
-			pr_debug("canary found i:%d 0x%lx\n", i,
-				 (unsigned long)&stack_ptr[i]);
+		if (stack_ptr[i] == expected_canary)
 			return (unsigned long)&stack_ptr[i];
-		}
 	}
 
-	pr_debug("canary not found in first %d steps\n",
-		 MAX_CANARY_SEARCH_STEPS);
+	pr_err("canary not found in first %d steps\n", MAX_CANARY_SEARCH_STEPS);
 	return 0;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-16-wangjinchao600%40gmail.com.
