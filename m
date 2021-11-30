Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6E5TCGQMGQETJBRSFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FC3D463301
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:46:01 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id g19-20020a2eb5d3000000b00219f21cb32bsf7545001ljn.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:46:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272761; cv=pass;
        d=google.com; s=arc-20160816;
        b=zLWbP/Yri8pMTB1+NzBov2FsNjrxtv98znsREVtZxnMLstzr/TS2BGG2Qhd2YpMfVm
         nbf2HAsWXi+viwPe3FGD2FOQh1b4vvN2Yp4vC1GdsUKjyURqYx+wVJDjkEchla2VJLTi
         XTJ3jhKcsmG5WTpQGA/oIWqCG88Zl9hn55xewtqrPY7lzmgsBIwx7dDX3g4OPH7C+Nn/
         b/w3PgBbqck6KY9f4c0PfxC8fYBGvyzlB3HGNROWWTMJ7lzwzxBmlZM5q31vPd3Xr+YQ
         xKEm8m38Vu6tOKaYSLE+U1S827A/54rtK65R7Lr53TfqQ5D8zub+u354TY8hTO/E1pWc
         R/AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=vvGbMnTyTyP8kQQMPi42MWHPN44DtQMoV63GUZmW9zg=;
        b=lepftG17ri23tWMr7JuihVpjk2+N2Cx+L2UuOoqWM3Wud2pO8pl8/xLkBlt73ZHX1q
         mNRxO6AJNvU/KkmmAKVEyi7Qzyx5v2OvN2XwGcrXOlKxg5I++2yEZi1MO7lMwaMra53k
         f6haIyUYkxxzw5s7mSgQfaEx4R1bF3M/iyqe5kcUWpt/cR+No0WmiXyHoJAdNRNU75pS
         igwajZXRp8fpliqE/yNe3R3q/M+IHLlbwPjINvrn4AqcB0os5nrJbHO34vtxI1CVUs3G
         B/fMJGepk9vwgymS55RMpQVAzfi1zTeorPHXANnGHk4yUfusOtR3nrIFctAoQleymTq3
         m34Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AxG+zGUA;
       spf=pass (google.com: domain of 39w6myqukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39w6mYQUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vvGbMnTyTyP8kQQMPi42MWHPN44DtQMoV63GUZmW9zg=;
        b=lX6EhWUByj1x33M6z+4qbZtly0TTdYP41+FG8bBUddfJ0YEyu4cn/xJ9mW7+wv80+V
         3Weiofl+QcYxLlHFDN7H84orUtpTKYQJZiMZr8JDep81EgJQlWBvit/4TctrSwuqWDeK
         +SEYOyOaXxfQSD/vMVRFXT4Zvji2qQ6bauuXq/QzMHtGVlltqMOYCXT7Nf+B6Lo8BEub
         uMYv1R/KwJ9mNwv2aSBDQMQq5JG7gomDMby0bFJm+lvAez/uoySue2+zk7PKIaa67m7R
         83NBt6u17z+rgeNaqR7xFvnp2G4xFMVClFK/W3yrIHB/O/tTpMelV5o6Pm4eDWw/RCFf
         wvIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vvGbMnTyTyP8kQQMPi42MWHPN44DtQMoV63GUZmW9zg=;
        b=2Os3LJ3tWBK6YQ31rE6pwFA0WvAIWlPVTD/igYSHgexpYoSeF9s0ywfcgHVJVSelwR
         aZL4aB7QiHw3KZ2M4fRnfZzSK1z0SR7MSY5evcGjngghR9GoL+meG7+ATdW65ML6XrXa
         P/WH9FUxHOyESCTPaJqb7wbui3xSs9pBdShgfqR7U/WE8eLbb5I/0OWEDELEtOtflj+v
         uroIewZO8vqLMyF+9a/9sQ24soHoxofS6+iOnEkUtGNzDqfMyGAT4I+S2SDNKV2ZrilD
         ys1y3h8uEDkXq+MLj0mosWfjhRUvBGerwwojf2zalPQTOF24ePP3AnF0VNqoZClDCNc+
         E/lw==
X-Gm-Message-State: AOAM530/3dCAOxSnftFSrKd+jAD/8u+xOH1zCSu5vPtmPtZvCRUpV23r
	Qv8Fe47BUx25yURUSxxVmTA=
X-Google-Smtp-Source: ABdhPJw+omL/zyoTu3fEYzD03x8qrvq5ICuLrb23JebZHqcw5dlTyGxYeKMC1ugy5EKqpUlR1kXk1Q==
X-Received: by 2002:a2e:a726:: with SMTP id s38mr56323553lje.415.1638272760932;
        Tue, 30 Nov 2021 03:46:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls454784lfv.1.gmail; Tue, 30
 Nov 2021 03:46:00 -0800 (PST)
X-Received: by 2002:a05:6512:3f28:: with SMTP id y40mr2281805lfa.609.1638272760011;
        Tue, 30 Nov 2021 03:46:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272760; cv=none;
        d=google.com; s=arc-20160816;
        b=OEWt05r5Z1oes+abFX7Vdw53s8phhxS544CRWoM0L3vsAuntvrixI9mgasWh4RiYoX
         5vuAXS9FfY9N2rE6bA2vEHxluJhXgXN+xG8sq+45Bj6DfI/UG/6jRaAT1AShuAsUg3eC
         fWeMOWBFJ9/ZLDLqWG4BL5JVYCyzXMOk3JPaaoxUZ889UkNnA00XkmxlBSUsNmcowv3s
         DYzSYLL8jvoFasYabt6clUNa2UhBPk+tCWd0ZtcAV1dtY2d6s2mXHc1BZl65z2Zvyv6X
         Wh/1wVbj5ww1RqTOlES4FWt4vuQ64I2w6WmoY3UURCIM0QDpFYnttb4oxb10CEly8T/q
         nyGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=1F+MofKXejp7ry8lfe8Rm0bUxzdx8s4N4hiT9E57RpU=;
        b=fJrvGJ+06+CJ6dznTUG7nPSbRUlSc7qOu11VGH1oF92a6PniN1rtkNE534Zorrjb3L
         nrnnUW3nz4OKs6kd2YSzW77VOEkrPLNb86S8oMYmFzF7uxyR0bUxMaZgRk2uSinz7xr8
         LYCITbZRr2m75IvbPo5iNzvaFMbXS6ixbXtQ+pyMupPsL79dMycKzH24E7EF+jGDvn/J
         5xKkdHEmzGi+LfyAiRBIcIrEtnZjcXUU0hprU2IDVqu42pQKnVobX2KgjU3bal6Ohwkk
         FkgoOpkVloysC9Amqk4PzPNaU2lF4UVY6mSTOF4MqYlIwYuqZR0WL8vQc8vbe5eja6EP
         saUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AxG+zGUA;
       spf=pass (google.com: domain of 39w6myqukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39w6mYQUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id t18si1368015lfp.0.2021.11.30.03.46.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:46:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 39w6myqukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id j193-20020a1c23ca000000b003306ae8bfb7so10280778wmj.7
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:59 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:1d1b:: with SMTP id
 l27mr624656wms.1.1638272759191; Tue, 30 Nov 2021 03:45:59 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:31 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-24-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 23/25] objtool, kcsan: Remove memory barrier
 instrumentation from noinstr
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org, Josh Poimboeuf <jpoimboe@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=AxG+zGUA;       spf=pass
 (google.com: domain of 39w6myqukccakr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39w6mYQUKCcAkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Teach objtool to turn instrumentation required for memory barrier
modeling into nops in noinstr text.

The __tsan_func_entry/exit calls are still emitted by compilers even
with the __no_sanitize_thread attribute. The memory barrier
instrumentation will be inserted explicitly (without compiler help), and
thus needs to also explicitly be removed.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Josh Poimboeuf <jpoimboe@redhat.com>
---
v3:
* s/removable_instr/profiling_func/ (suggested by Josh Poimboeuf)
* s/__kcsan_(mb|wmb|rmb|release)/__atomic_signal_fence/, because
  Clang < 14.0 will still emit these in noinstr even with __no_kcsan.
* Fix and add more comments.

v2:
* Rewrite after rebase to v5.16-rc1.
---
 tools/objtool/check.c               | 37 ++++++++++++++++++++++++-----
 tools/objtool/include/objtool/elf.h |  2 +-
 2 files changed, 32 insertions(+), 7 deletions(-)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 61dfb66b30b6..a9a1f7259d62 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1072,11 +1072,11 @@ static void annotate_call_site(struct objtool_file *file,
 	}
 
 	/*
-	 * Many compilers cannot disable KCOV with a function attribute
-	 * so they need a little help, NOP out any KCOV calls from noinstr
-	 * text.
+	 * Many compilers cannot disable KCOV or sanitizer calls with a function
+	 * attribute so they need a little help, NOP out any such calls from
+	 * noinstr text.
 	 */
-	if (insn->sec->noinstr && sym->kcov) {
+	if (insn->sec->noinstr && sym->profiling_func) {
 		if (reloc) {
 			reloc->type = R_NONE;
 			elf_write_reloc(file->elf, reloc);
@@ -1991,6 +1991,31 @@ static int read_intra_function_calls(struct objtool_file *file)
 	return 0;
 }
 
+/*
+ * Return true if name matches an instrumentation function, where calls to that
+ * function from noinstr code can safely be removed, but compilers won't do so.
+ */
+static bool is_profiling_func(const char *name)
+{
+	/*
+	 * Many compilers cannot disable KCOV with a function attribute.
+	 */
+	if (!strncmp(name, "__sanitizer_cov_", 16))
+		return true;
+
+	/*
+	 * Some compilers currently do not remove __tsan_func_entry/exit nor
+	 * __tsan_atomic_signal_fence (used for barrier instrumentation) with
+	 * the __no_sanitize_thread attribute, remove them. Once the kernel's
+	 * minimum Clang version is 14.0, this can be removed.
+	 */
+	if (!strncmp(name, "__tsan_func_", 12) ||
+	    !strcmp(name, "__tsan_atomic_signal_fence"))
+		return true;
+
+	return false;
+}
+
 static int classify_symbols(struct objtool_file *file)
 {
 	struct section *sec;
@@ -2011,8 +2036,8 @@ static int classify_symbols(struct objtool_file *file)
 			if (!strcmp(func->name, "__fentry__"))
 				func->fentry = true;
 
-			if (!strncmp(func->name, "__sanitizer_cov_", 16))
-				func->kcov = true;
+			if (is_profiling_func(func->name))
+				func->profiling_func = true;
 		}
 	}
 
diff --git a/tools/objtool/include/objtool/elf.h b/tools/objtool/include/objtool/elf.h
index cdc739fa9a6f..d22336781401 100644
--- a/tools/objtool/include/objtool/elf.h
+++ b/tools/objtool/include/objtool/elf.h
@@ -58,7 +58,7 @@ struct symbol {
 	u8 static_call_tramp : 1;
 	u8 retpoline_thunk   : 1;
 	u8 fentry            : 1;
-	u8 kcov              : 1;
+	u8 profiling_func    : 1;
 	struct list_head pv_target;
 };
 
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-24-elver%40google.com.
