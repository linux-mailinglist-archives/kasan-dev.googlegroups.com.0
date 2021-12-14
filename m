Return-Path: <kasan-dev+bncBCS4VDMYRUNBB75J4SGQMGQE3NDIFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id CCAC1474D90
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:47 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id v10-20020aa7d9ca000000b003e7bed57968sf18215505eds.23
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=xnnWijBsP3PZDrb/qdngegBqWhCNNh1/jsJ36qgklXTdVY44vEa63k7EgAQ68zp46P
         fb6XaxTq8WRRFnlsxGQs2J+F7Pa3rlElXS5b9yjaoWE0bHJFhN5BctByRz+5s+7QPOr+
         9f+0RUksnUn3EhFZGSdHL7lwXkQZomMWmCw/efUKvSSS+SuTQ4FZSR/ykM4Yqz7NqAux
         0V2B3V4w44cxCNCu69v2Bg0pfWgJBubnZdq2edkOGTJUFBrYWciJESrf4Up+KZKuqUIc
         6a78z8IvsaX2Wj25pthQVofxq15ElE/ieMEHq/rs7wxJ8dUNwj9rCIwqL7tBRxFxlDUa
         P5Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Fjz9S8uPnmo1G17RxjXuIcmbwDfbOgh/E3a0+Y61xmQ=;
        b=TIMzU0Z++vg5UzTU5+ysXaBykZYZ2ItBUNbBO5E9r8Ho84VfdOusdQsv9DOJbQbrn+
         VJBV6kjkKV7vZNVCCSE8CUPZu+2THzS3C4MMwVbGGlM9PdP5LtG6ybAi5L9z+4pTZZnr
         0yAjbsYgXB3Runc8FqsMmw24wGXTEZiIJ3Li20TSx0Mw7+9hoOTTwWvJKjC1sR/VCGz1
         jCwbyGF7rc+vHGmpywLtPtrbjWJeWI8/XNl/IOysz/ryDb/mloztrdTkpzKO8VA7pjgQ
         M9NzAN4WjKbKg5eOb2Gfwsq7l/p9Wg0SzjQlcBaltSyEN1+aWF0ZI+wG7QaymKV+p6UW
         xk3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gefQyCSi;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fjz9S8uPnmo1G17RxjXuIcmbwDfbOgh/E3a0+Y61xmQ=;
        b=kcnpIiw2CsDDwc+MBu+mc2i8MbymH458E77qRLqUn6Qk0wW+0QO2BUbTR7iTyJWN9n
         Y+Congq7GvvYY5Dpy81CZqRCUNdDF/I01nkpbegimv0FMtLB3EuCT7gfXyl68sX+4tff
         od+RPMtUxo8k1ckyznHfTU19d+1JYOSw1+Aw8dE/95tgYFg+kmA9NXVE+RtiUb38x69b
         OAvv6HsI/SFCj4FNviVc2lWQ/mHnYOfOcAXrAxLhmZy/uzIqo4NqQesN24V8hLd/zamI
         mGAcehah2zxvGWvtUIAch7BmjyAxVH4uKfZBUZxl/GYRcd+l7lSbp6QaZofGF/4thwBm
         GpHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fjz9S8uPnmo1G17RxjXuIcmbwDfbOgh/E3a0+Y61xmQ=;
        b=dFbGh7GN5QQ32zg9j8ZwA7UqXc0IPp9ZM74TcLFrnyJ6Rir2sH+3dOKaodMPHFofGl
         rT6LpJhqbRlRXEVqWONyn24G223MoUrVUdyrUDiVF1p/PZeVuDRi7MDpOnB7sqCx2Yfg
         RvpBOpMYy/JWDivw3HX1xOzuGypdXH/vnzY+Ghsr87Ybh6uEZ+zkJb4f1JHRbZ7f13hj
         GmytG19msWhMqBu5cnvf2NfL6JSOtUOvSaHdyaioHb0vsPEWzkcc86u53/xZdpbb+Fl/
         2uaMPQMSABfS1trqPP4ngaOUkJy2cNabaXzmqNvcHDSWj40uAY+DfNs4szGD2aRmE6N1
         cCGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Sqv4fAunL9nymEbBzZ573LqVQUK71jFW/eEyCbf6cHzx9zEaf
	RHAZjHLThORnjyRWapWolyI=
X-Google-Smtp-Source: ABdhPJw9/NS5ggpueU+nhHiMAqw2OAywfFUnIj6SSB6zsaBAsmW6zjjejfzmxflMBIwnoiMJuc2pAw==
X-Received: by 2002:a17:906:384f:: with SMTP id w15mr2607805ejc.60.1639519487475;
        Tue, 14 Dec 2021 14:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6da0:: with SMTP id sb32ls23349ejc.8.gmail; Tue, 14
 Dec 2021 14:04:46 -0800 (PST)
X-Received: by 2002:a17:906:6a1d:: with SMTP id qw29mr8060025ejc.610.1639519486568;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519486; cv=none;
        d=google.com; s=arc-20160816;
        b=h1XkJxXVDvdKbAK56oUMgfXGo3xe7P4igHUHBP6id73WmOVslfmQ1hBPN620uGi+fZ
         F26gu22QyAxjrAOzRe44eluWsEb5WrsiHhqyhj8f8YkfGwg0uAGnMDKK/ofr6WQ2vOvd
         pD73YC2OfHl5KR5TIhyq32zTiRPxCGjOc3YqJi8/4YvFXP/w5DBn/J90ljnmgYxn0hyu
         8tshFwPPGMqo2ZZmUIKoSjsjbBDVEjB3YtjpGsisB+RW6D+5qH1ge62CxU6eCnidUW35
         Xpij1Hdu4JNcTnvP9P7NAp6C3786FBspe1gbj/U/3BB/4dF9mP9WGxf0AWtInQzNahlw
         Lw6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rawqvDEZ7tgJlFJpFKIkeQoE2f8LZwjAwqa4rrvm3ZQ=;
        b=AuJeJ/5nEhi9W6OJnPQKhv0muxUrx+PfYijjq4u88l8dU8VPurcUobOLERT6+T15mU
         0wo8Ur6d7zh7VsjB1qLEyE4Gm7UsyqiceKyly6/d+39YyF5tigmORx9O+nAiAbOo03Gi
         bG6YpHKi0MRyzLn0Yfl2y20Cl6WRGjDYRe5Q1xwYSpCrQ+7BNqOtLzQvudOEf60hM0ch
         gE99/TlSMujkjXDr0gzqosQGzZdzvHPRZv+u4VVotUSBj2NmD7j0jAdGLHVNsr6JwWdF
         rN2J34g8BHrLOyTchmpQFhhWZoHHDd219JkLFUL2AYCJRrwe/DcQKf370D0FnPeqrHiq
         h7sA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gefQyCSi;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id fl21si7333ejc.0.2021.12.14.14.04.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 876056176A;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3EF5EC3463F;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 866485C1E8C; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 23/29] objtool, kcsan: Remove memory barrier instrumentation from noinstr
Date: Tue, 14 Dec 2021 14:04:33 -0800
Message-Id: <20211214220439.2236564-23-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gefQyCSi;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Teach objtool to turn instrumentation required for memory barrier
modeling into nops in noinstr text.

The __tsan_func_entry/exit calls are still emitted by compilers even
with the __no_sanitize_thread attribute. The memory barrier
instrumentation will be inserted explicitly (without compiler help), and
thus needs to also explicitly be removed.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Josh Poimboeuf <jpoimboe@redhat.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 tools/objtool/check.c               | 37 ++++++++++++++++++++++++-----
 tools/objtool/include/objtool/elf.h |  2 +-
 2 files changed, 32 insertions(+), 7 deletions(-)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 61dfb66b30b64..a9a1f7259d628 100644
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
index cdc739fa9a6fb..d223367814017 100644
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
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-23-paulmck%40kernel.org.
