Return-Path: <kasan-dev+bncBCS4VDMYRUNBB75J4SGQMGQE3NDIFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 17293474D92
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:48 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id w16-20020a05651c103000b00218c9d46faesf6003271ljm.2
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=XyT5uxLMy2X/LxPlphLicueC9s14xFwVJhSy3VjXnJAcjG6tj5shysz3cTmSwVXSnA
         oMV7FKhPQ4jf8D0do3QdyVTXqVnf27OTvW8P2Ejx42dqK6ld/oCtCFCnu03Lf3xsmLag
         604TULlHuGvt2KvisyCuq49Pe1TCaCKzyBJsEMxd+F2mTAqjrGeYKrUHSqOefERcIuNw
         qiem0dwAFMRUSXoYbBpyU7Oo8oNet1IUIvq6iioaJg9criGLf3j/5h+TYPTnWuDK2bd/
         ejjZIec6e+U/IWmLf489Bpyt05ejFAYROcRmLxFCCwxEhERxpzgZb+wOWYSiGEN0ngOv
         UOwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Di0F4IGk1NnCNRvQ0u0N+O/c2qqoHa0xGocQdyEkt3k=;
        b=EffjpbrMoI6dXHs6aOES038fj9c23WGmYlj/pzyMJLvdEO+7BsS4Apx3DkdKIXI1E2
         CmPPrkLER2vs2XwZwKsRwlThxPLW4iaERTSB3R4+NmucSy+aO31fzRuy8wb44F6dfsBh
         Ex0wLZ+fa7lkXOYTD2hskUwND2087V01K5K8KnuXF+ONfeeZjKyfa/IbstjOhzMjR8Rs
         DFWt85F/2OmvrXHHCRrekWA5j++1BwX+LZ4o/rjdG1UaIsFygAt5Yk49C+yyAlRhxgRW
         SIubbQC8YS1uFgQS8/3qIly5VAd551FVPctKhH7kbproeDIEGyIhFVXiGqMKAL/K1rsS
         JhSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V16I2l4B;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Di0F4IGk1NnCNRvQ0u0N+O/c2qqoHa0xGocQdyEkt3k=;
        b=n0Z/h5W5NIZYrC9gM4BIBJ7gEZB+iwA0B3pJjRrLhLep2lHBL5lYpKLrlm7TJGF7/h
         kjIeIvQD69QiRSZsDIf2IcHf3aWe5CdS2erziBilYHFxwkeA/Xs7ZeCsLoyUJxJWvQKl
         c90PzilxSajEyBeOn3IBy7OJuDdt1+e1/lRCmFdtVLOuycd1QozMLicN12wV7QdXS7YM
         Dpby1z5DhLVL5wZbYtOCwcbsgso5sCzbHKSN7ljfz0zaMn80HBwUR/ibNIXWAuFj2xr4
         kp68886nv9rnjicKxMPxKrXPDmla0Hhel7VFDM+68cH8oZFsUkhaUopkOmQKRTAlAmtl
         CXvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Di0F4IGk1NnCNRvQ0u0N+O/c2qqoHa0xGocQdyEkt3k=;
        b=AIH6q5xFG76GGE8U0Cbu3YVyfa29E/pEz44X/vX7gQDHNub2RIXelA5QrKmWrtlKnn
         DdUM5hrOPBK/tsd/znCCYKRiMIUJu7AMZQEl3bCEA6FxECBovZoHrBybnSFvHzfbtlGq
         2aii4vFWymrOtS72yZ0oHgj5upzO53yuMsmHi++dCAYioIXm6zBuw9L5bN5b6UplR41P
         CJK+9/TcTJoT5FZjYLCNGfoIG34YSygkslDbEMSi8fnlwE56xccf/8GRnnvXRkuzUQgq
         pJpkF8taLzTwKi+85VYvaMesLbKgmI63GH/VPllL5irtKXv8Ie6bO1xo9sILwC4FNIhS
         UT+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53157Vo4lqcPAI+B3YSYpXNunpHlKoAXEI9pwCHhZsynV0h957iO
	IJ70yb25ES7oxqrFLerQSRo=
X-Google-Smtp-Source: ABdhPJyNcN/qiQaKk0knT17WeHXErzNGkG4gvxyUcrRet8nSpN0wVzApu1xEIdVmyznE8tne5sBouQ==
X-Received: by 2002:a05:651c:12c9:: with SMTP id 9mr7460862lje.474.1639519487316;
        Tue, 14 Dec 2021 14:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls98126lfv.1.gmail; Tue, 14
 Dec 2021 14:04:46 -0800 (PST)
X-Received: by 2002:ac2:5316:: with SMTP id c22mr7052927lfh.477.1639519486250;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519486; cv=none;
        d=google.com; s=arc-20160816;
        b=mR7i8/xSdIJOFhRaXkZ5z7nTWQ/Pu9uQfyTRCofRVdQbd/V99UW5l52ZKHnTvhC+lr
         jwfvjRjg0Rlg1WXCzikI7cRTTjUux28jElYn4zbsUeuxxS/mjXTfSgzvoPk457Y2BWK0
         /96zUiqa6KhDriQIOeBIeQH3CNSPddzVSzQFeatAXPb2B5eSE+2O7InT551vGjim3v5y
         xjgloBhR/dccSWMgWkoAe6iEjHHyVWjz/oFK7y7yGhwmNAXfAgT9k2xqV+lKn8G2il9L
         c/en0CGxuscu5uIRYpOt03QxDyA9MlQYRm3UXChu3I5WAObxTq5x17zN825go5aA5b+C
         Bh3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PbtRFesdi2oRHX6NIZWODALZt653pIrdNIoPkwZHmOI=;
        b=br5tn9/F38c/MQeVlJoHj1e17eSnVF2brMGUHpt9hic6s1v97bJGqI2hdMmeCy2glO
         7B2Oao5p+Z9cyDGsQSSXzJbuK6ZzyyNDoDD5Ri58IDEnD3IUIYq9jN4ePky/FVNQ/FJ0
         onaQsNOQRay2RGj+TtPCcGB5U7JJ2f10TQoxGM38RcsHmigKyj5IVZq+9m/cLp9+RJyE
         mW241DucEHX1DnmMypMt/c3LbrouNT6d2DQnZU5EtyA6eK4xerEGQEaOVtdfS1KieYHQ
         s6clS/eQSLgc1bU76gW1+f/KMrgWJjrsLRryU5REH1ls4LOwrYK56YlVuzzx71c0ZCuQ
         R6jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V16I2l4B;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d8si5658lfv.13.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D786D61740;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 206E7C3462C;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 798205C1962; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 16/29] locking/atomics, kcsan: Add instrumentation for barriers
Date: Tue, 14 Dec 2021 14:04:26 -0800
Message-Id: <20211214220439.2236564-16-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=V16I2l4B;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Adds the required KCSAN instrumentation for barriers of atomics.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/atomic/atomic-instrumented.h | 135 ++++++++++++++++++++-
 scripts/atomic/gen-atomic-instrumented.sh  |  41 +++++--
 2 files changed, 166 insertions(+), 10 deletions(-)

diff --git a/include/linux/atomic/atomic-instrumented.h b/include/linux/atomic/atomic-instrumented.h
index a0f654370da3a..5d69b143c28e6 100644
--- a/include/linux/atomic/atomic-instrumented.h
+++ b/include/linux/atomic/atomic-instrumented.h
@@ -45,6 +45,7 @@ atomic_set(atomic_t *v, int i)
 static __always_inline void
 atomic_set_release(atomic_t *v, int i)
 {
+	kcsan_release();
 	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_set_release(v, i);
 }
@@ -59,6 +60,7 @@ atomic_add(int i, atomic_t *v)
 static __always_inline int
 atomic_add_return(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_add_return(i, v);
 }
@@ -73,6 +75,7 @@ atomic_add_return_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_add_return_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_add_return_release(i, v);
 }
@@ -87,6 +90,7 @@ atomic_add_return_relaxed(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_add(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_add(i, v);
 }
@@ -101,6 +105,7 @@ atomic_fetch_add_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_add_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_add_release(i, v);
 }
@@ -122,6 +127,7 @@ atomic_sub(int i, atomic_t *v)
 static __always_inline int
 atomic_sub_return(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_sub_return(i, v);
 }
@@ -136,6 +142,7 @@ atomic_sub_return_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_sub_return_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_sub_return_release(i, v);
 }
@@ -150,6 +157,7 @@ atomic_sub_return_relaxed(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_sub(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_sub(i, v);
 }
@@ -164,6 +172,7 @@ atomic_fetch_sub_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_sub_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_sub_release(i, v);
 }
@@ -185,6 +194,7 @@ atomic_inc(atomic_t *v)
 static __always_inline int
 atomic_inc_return(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_inc_return(v);
 }
@@ -199,6 +209,7 @@ atomic_inc_return_acquire(atomic_t *v)
 static __always_inline int
 atomic_inc_return_release(atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_inc_return_release(v);
 }
@@ -213,6 +224,7 @@ atomic_inc_return_relaxed(atomic_t *v)
 static __always_inline int
 atomic_fetch_inc(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_inc(v);
 }
@@ -227,6 +239,7 @@ atomic_fetch_inc_acquire(atomic_t *v)
 static __always_inline int
 atomic_fetch_inc_release(atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_inc_release(v);
 }
@@ -248,6 +261,7 @@ atomic_dec(atomic_t *v)
 static __always_inline int
 atomic_dec_return(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_dec_return(v);
 }
@@ -262,6 +276,7 @@ atomic_dec_return_acquire(atomic_t *v)
 static __always_inline int
 atomic_dec_return_release(atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_dec_return_release(v);
 }
@@ -276,6 +291,7 @@ atomic_dec_return_relaxed(atomic_t *v)
 static __always_inline int
 atomic_fetch_dec(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_dec(v);
 }
@@ -290,6 +306,7 @@ atomic_fetch_dec_acquire(atomic_t *v)
 static __always_inline int
 atomic_fetch_dec_release(atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_dec_release(v);
 }
@@ -311,6 +328,7 @@ atomic_and(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_and(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_and(i, v);
 }
@@ -325,6 +343,7 @@ atomic_fetch_and_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_and_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_and_release(i, v);
 }
@@ -346,6 +365,7 @@ atomic_andnot(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_andnot(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_andnot(i, v);
 }
@@ -360,6 +380,7 @@ atomic_fetch_andnot_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_andnot_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_andnot_release(i, v);
 }
@@ -381,6 +402,7 @@ atomic_or(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_or(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_or(i, v);
 }
@@ -395,6 +417,7 @@ atomic_fetch_or_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_or_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_or_release(i, v);
 }
@@ -416,6 +439,7 @@ atomic_xor(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_xor(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_xor(i, v);
 }
@@ -430,6 +454,7 @@ atomic_fetch_xor_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_xor_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_xor_release(i, v);
 }
@@ -444,6 +469,7 @@ atomic_fetch_xor_relaxed(int i, atomic_t *v)
 static __always_inline int
 atomic_xchg(atomic_t *v, int i)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_xchg(v, i);
 }
@@ -458,6 +484,7 @@ atomic_xchg_acquire(atomic_t *v, int i)
 static __always_inline int
 atomic_xchg_release(atomic_t *v, int i)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_xchg_release(v, i);
 }
@@ -472,6 +499,7 @@ atomic_xchg_relaxed(atomic_t *v, int i)
 static __always_inline int
 atomic_cmpxchg(atomic_t *v, int old, int new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_cmpxchg(v, old, new);
 }
@@ -486,6 +514,7 @@ atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
 static __always_inline int
 atomic_cmpxchg_release(atomic_t *v, int old, int new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_cmpxchg_release(v, old, new);
 }
@@ -500,6 +529,7 @@ atomic_cmpxchg_relaxed(atomic_t *v, int old, int new)
 static __always_inline bool
 atomic_try_cmpxchg(atomic_t *v, int *old, int new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic_try_cmpxchg(v, old, new);
@@ -516,6 +546,7 @@ atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 static __always_inline bool
 atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic_try_cmpxchg_release(v, old, new);
@@ -532,6 +563,7 @@ atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
 static __always_inline bool
 atomic_sub_and_test(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_sub_and_test(i, v);
 }
@@ -539,6 +571,7 @@ atomic_sub_and_test(int i, atomic_t *v)
 static __always_inline bool
 atomic_dec_and_test(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_dec_and_test(v);
 }
@@ -546,6 +579,7 @@ atomic_dec_and_test(atomic_t *v)
 static __always_inline bool
 atomic_inc_and_test(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_inc_and_test(v);
 }
@@ -553,6 +587,7 @@ atomic_inc_and_test(atomic_t *v)
 static __always_inline bool
 atomic_add_negative(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_add_negative(i, v);
 }
@@ -560,6 +595,7 @@ atomic_add_negative(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_add_unless(atomic_t *v, int a, int u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_add_unless(v, a, u);
 }
@@ -567,6 +603,7 @@ atomic_fetch_add_unless(atomic_t *v, int a, int u)
 static __always_inline bool
 atomic_add_unless(atomic_t *v, int a, int u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_add_unless(v, a, u);
 }
@@ -574,6 +611,7 @@ atomic_add_unless(atomic_t *v, int a, int u)
 static __always_inline bool
 atomic_inc_not_zero(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_inc_not_zero(v);
 }
@@ -581,6 +619,7 @@ atomic_inc_not_zero(atomic_t *v)
 static __always_inline bool
 atomic_inc_unless_negative(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_inc_unless_negative(v);
 }
@@ -588,6 +627,7 @@ atomic_inc_unless_negative(atomic_t *v)
 static __always_inline bool
 atomic_dec_unless_positive(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_dec_unless_positive(v);
 }
@@ -595,6 +635,7 @@ atomic_dec_unless_positive(atomic_t *v)
 static __always_inline int
 atomic_dec_if_positive(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_dec_if_positive(v);
 }
@@ -623,6 +664,7 @@ atomic64_set(atomic64_t *v, s64 i)
 static __always_inline void
 atomic64_set_release(atomic64_t *v, s64 i)
 {
+	kcsan_release();
 	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_set_release(v, i);
 }
@@ -637,6 +679,7 @@ atomic64_add(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_add_return(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_add_return(i, v);
 }
@@ -651,6 +694,7 @@ atomic64_add_return_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_add_return_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_add_return_release(i, v);
 }
@@ -665,6 +709,7 @@ atomic64_add_return_relaxed(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_add(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_add(i, v);
 }
@@ -679,6 +724,7 @@ atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_add_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_add_release(i, v);
 }
@@ -700,6 +746,7 @@ atomic64_sub(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_sub_return(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_sub_return(i, v);
 }
@@ -714,6 +761,7 @@ atomic64_sub_return_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_sub_return_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_sub_return_release(i, v);
 }
@@ -728,6 +776,7 @@ atomic64_sub_return_relaxed(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_sub(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_sub(i, v);
 }
@@ -742,6 +791,7 @@ atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_sub_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_sub_release(i, v);
 }
@@ -763,6 +813,7 @@ atomic64_inc(atomic64_t *v)
 static __always_inline s64
 atomic64_inc_return(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_inc_return(v);
 }
@@ -777,6 +828,7 @@ atomic64_inc_return_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_inc_return_release(atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_inc_return_release(v);
 }
@@ -791,6 +843,7 @@ atomic64_inc_return_relaxed(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_inc(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_inc(v);
 }
@@ -805,6 +858,7 @@ atomic64_fetch_inc_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_inc_release(atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_inc_release(v);
 }
@@ -826,6 +880,7 @@ atomic64_dec(atomic64_t *v)
 static __always_inline s64
 atomic64_dec_return(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_dec_return(v);
 }
@@ -840,6 +895,7 @@ atomic64_dec_return_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_dec_return_release(atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_dec_return_release(v);
 }
@@ -854,6 +910,7 @@ atomic64_dec_return_relaxed(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_dec(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_dec(v);
 }
@@ -868,6 +925,7 @@ atomic64_fetch_dec_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_dec_release(atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_dec_release(v);
 }
@@ -889,6 +947,7 @@ atomic64_and(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_and(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_and(i, v);
 }
@@ -903,6 +962,7 @@ atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_and_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_and_release(i, v);
 }
@@ -924,6 +984,7 @@ atomic64_andnot(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_andnot(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_andnot(i, v);
 }
@@ -938,6 +999,7 @@ atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_andnot_release(i, v);
 }
@@ -959,6 +1021,7 @@ atomic64_or(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_or(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_or(i, v);
 }
@@ -973,6 +1036,7 @@ atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_or_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_or_release(i, v);
 }
@@ -994,6 +1058,7 @@ atomic64_xor(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_xor(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_xor(i, v);
 }
@@ -1008,6 +1073,7 @@ atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_xor_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_xor_release(i, v);
 }
@@ -1022,6 +1088,7 @@ atomic64_fetch_xor_relaxed(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_xchg(atomic64_t *v, s64 i)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_xchg(v, i);
 }
@@ -1036,6 +1103,7 @@ atomic64_xchg_acquire(atomic64_t *v, s64 i)
 static __always_inline s64
 atomic64_xchg_release(atomic64_t *v, s64 i)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_xchg_release(v, i);
 }
@@ -1050,6 +1118,7 @@ atomic64_xchg_relaxed(atomic64_t *v, s64 i)
 static __always_inline s64
 atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_cmpxchg(v, old, new);
 }
@@ -1064,6 +1133,7 @@ atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
 static __always_inline s64
 atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_cmpxchg_release(v, old, new);
 }
@@ -1078,6 +1148,7 @@ atomic64_cmpxchg_relaxed(atomic64_t *v, s64 old, s64 new)
 static __always_inline bool
 atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic64_try_cmpxchg(v, old, new);
@@ -1094,6 +1165,7 @@ atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 static __always_inline bool
 atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic64_try_cmpxchg_release(v, old, new);
@@ -1110,6 +1182,7 @@ atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
 static __always_inline bool
 atomic64_sub_and_test(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_sub_and_test(i, v);
 }
@@ -1117,6 +1190,7 @@ atomic64_sub_and_test(s64 i, atomic64_t *v)
 static __always_inline bool
 atomic64_dec_and_test(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_dec_and_test(v);
 }
@@ -1124,6 +1198,7 @@ atomic64_dec_and_test(atomic64_t *v)
 static __always_inline bool
 atomic64_inc_and_test(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_inc_and_test(v);
 }
@@ -1131,6 +1206,7 @@ atomic64_inc_and_test(atomic64_t *v)
 static __always_inline bool
 atomic64_add_negative(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_add_negative(i, v);
 }
@@ -1138,6 +1214,7 @@ atomic64_add_negative(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_add_unless(v, a, u);
 }
@@ -1145,6 +1222,7 @@ atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
 static __always_inline bool
 atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_add_unless(v, a, u);
 }
@@ -1152,6 +1230,7 @@ atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
 static __always_inline bool
 atomic64_inc_not_zero(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_inc_not_zero(v);
 }
@@ -1159,6 +1238,7 @@ atomic64_inc_not_zero(atomic64_t *v)
 static __always_inline bool
 atomic64_inc_unless_negative(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_inc_unless_negative(v);
 }
@@ -1166,6 +1246,7 @@ atomic64_inc_unless_negative(atomic64_t *v)
 static __always_inline bool
 atomic64_dec_unless_positive(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_dec_unless_positive(v);
 }
@@ -1173,6 +1254,7 @@ atomic64_dec_unless_positive(atomic64_t *v)
 static __always_inline s64
 atomic64_dec_if_positive(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_dec_if_positive(v);
 }
@@ -1201,6 +1283,7 @@ atomic_long_set(atomic_long_t *v, long i)
 static __always_inline void
 atomic_long_set_release(atomic_long_t *v, long i)
 {
+	kcsan_release();
 	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_long_set_release(v, i);
 }
@@ -1215,6 +1298,7 @@ atomic_long_add(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_add_return(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_add_return(i, v);
 }
@@ -1229,6 +1313,7 @@ atomic_long_add_return_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_add_return_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_add_return_release(i, v);
 }
@@ -1243,6 +1328,7 @@ atomic_long_add_return_relaxed(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_add(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_add(i, v);
 }
@@ -1257,6 +1343,7 @@ atomic_long_fetch_add_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_add_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_add_release(i, v);
 }
@@ -1278,6 +1365,7 @@ atomic_long_sub(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_sub_return(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_sub_return(i, v);
 }
@@ -1292,6 +1380,7 @@ atomic_long_sub_return_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_sub_return_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_sub_return_release(i, v);
 }
@@ -1306,6 +1395,7 @@ atomic_long_sub_return_relaxed(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_sub(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_sub(i, v);
 }
@@ -1320,6 +1410,7 @@ atomic_long_fetch_sub_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_sub_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_sub_release(i, v);
 }
@@ -1341,6 +1432,7 @@ atomic_long_inc(atomic_long_t *v)
 static __always_inline long
 atomic_long_inc_return(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_inc_return(v);
 }
@@ -1355,6 +1447,7 @@ atomic_long_inc_return_acquire(atomic_long_t *v)
 static __always_inline long
 atomic_long_inc_return_release(atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_inc_return_release(v);
 }
@@ -1369,6 +1462,7 @@ atomic_long_inc_return_relaxed(atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_inc(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_inc(v);
 }
@@ -1383,6 +1477,7 @@ atomic_long_fetch_inc_acquire(atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_inc_release(atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_inc_release(v);
 }
@@ -1404,6 +1499,7 @@ atomic_long_dec(atomic_long_t *v)
 static __always_inline long
 atomic_long_dec_return(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_dec_return(v);
 }
@@ -1418,6 +1514,7 @@ atomic_long_dec_return_acquire(atomic_long_t *v)
 static __always_inline long
 atomic_long_dec_return_release(atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_dec_return_release(v);
 }
@@ -1432,6 +1529,7 @@ atomic_long_dec_return_relaxed(atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_dec(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_dec(v);
 }
@@ -1446,6 +1544,7 @@ atomic_long_fetch_dec_acquire(atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_dec_release(atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_dec_release(v);
 }
@@ -1467,6 +1566,7 @@ atomic_long_and(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_and(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_and(i, v);
 }
@@ -1481,6 +1581,7 @@ atomic_long_fetch_and_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_and_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_and_release(i, v);
 }
@@ -1502,6 +1603,7 @@ atomic_long_andnot(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_andnot(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_andnot(i, v);
 }
@@ -1516,6 +1618,7 @@ atomic_long_fetch_andnot_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_andnot_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_andnot_release(i, v);
 }
@@ -1537,6 +1640,7 @@ atomic_long_or(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_or(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_or(i, v);
 }
@@ -1551,6 +1655,7 @@ atomic_long_fetch_or_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_or_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_or_release(i, v);
 }
@@ -1572,6 +1677,7 @@ atomic_long_xor(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_xor(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_xor(i, v);
 }
@@ -1586,6 +1692,7 @@ atomic_long_fetch_xor_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_xor_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_xor_release(i, v);
 }
@@ -1600,6 +1707,7 @@ atomic_long_fetch_xor_relaxed(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_xchg(atomic_long_t *v, long i)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_xchg(v, i);
 }
@@ -1614,6 +1722,7 @@ atomic_long_xchg_acquire(atomic_long_t *v, long i)
 static __always_inline long
 atomic_long_xchg_release(atomic_long_t *v, long i)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_xchg_release(v, i);
 }
@@ -1628,6 +1737,7 @@ atomic_long_xchg_relaxed(atomic_long_t *v, long i)
 static __always_inline long
 atomic_long_cmpxchg(atomic_long_t *v, long old, long new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_cmpxchg(v, old, new);
 }
@@ -1642,6 +1752,7 @@ atomic_long_cmpxchg_acquire(atomic_long_t *v, long old, long new)
 static __always_inline long
 atomic_long_cmpxchg_release(atomic_long_t *v, long old, long new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_cmpxchg_release(v, old, new);
 }
@@ -1656,6 +1767,7 @@ atomic_long_cmpxchg_relaxed(atomic_long_t *v, long old, long new)
 static __always_inline bool
 atomic_long_try_cmpxchg(atomic_long_t *v, long *old, long new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic_long_try_cmpxchg(v, old, new);
@@ -1672,6 +1784,7 @@ atomic_long_try_cmpxchg_acquire(atomic_long_t *v, long *old, long new)
 static __always_inline bool
 atomic_long_try_cmpxchg_release(atomic_long_t *v, long *old, long new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic_long_try_cmpxchg_release(v, old, new);
@@ -1688,6 +1801,7 @@ atomic_long_try_cmpxchg_relaxed(atomic_long_t *v, long *old, long new)
 static __always_inline bool
 atomic_long_sub_and_test(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_sub_and_test(i, v);
 }
@@ -1695,6 +1809,7 @@ atomic_long_sub_and_test(long i, atomic_long_t *v)
 static __always_inline bool
 atomic_long_dec_and_test(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_dec_and_test(v);
 }
@@ -1702,6 +1817,7 @@ atomic_long_dec_and_test(atomic_long_t *v)
 static __always_inline bool
 atomic_long_inc_and_test(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_inc_and_test(v);
 }
@@ -1709,6 +1825,7 @@ atomic_long_inc_and_test(atomic_long_t *v)
 static __always_inline bool
 atomic_long_add_negative(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_add_negative(i, v);
 }
@@ -1716,6 +1833,7 @@ atomic_long_add_negative(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_add_unless(atomic_long_t *v, long a, long u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_add_unless(v, a, u);
 }
@@ -1723,6 +1841,7 @@ atomic_long_fetch_add_unless(atomic_long_t *v, long a, long u)
 static __always_inline bool
 atomic_long_add_unless(atomic_long_t *v, long a, long u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_add_unless(v, a, u);
 }
@@ -1730,6 +1849,7 @@ atomic_long_add_unless(atomic_long_t *v, long a, long u)
 static __always_inline bool
 atomic_long_inc_not_zero(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_inc_not_zero(v);
 }
@@ -1737,6 +1857,7 @@ atomic_long_inc_not_zero(atomic_long_t *v)
 static __always_inline bool
 atomic_long_inc_unless_negative(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_inc_unless_negative(v);
 }
@@ -1744,6 +1865,7 @@ atomic_long_inc_unless_negative(atomic_long_t *v)
 static __always_inline bool
 atomic_long_dec_unless_positive(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_dec_unless_positive(v);
 }
@@ -1751,6 +1873,7 @@ atomic_long_dec_unless_positive(atomic_long_t *v)
 static __always_inline long
 atomic_long_dec_if_positive(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_dec_if_positive(v);
 }
@@ -1758,6 +1881,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define xchg(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_xchg(__ai_ptr, __VA_ARGS__); \
 })
@@ -1772,6 +1896,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define xchg_release(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_release(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_xchg_release(__ai_ptr, __VA_ARGS__); \
 })
@@ -1786,6 +1911,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define cmpxchg(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_cmpxchg(__ai_ptr, __VA_ARGS__); \
 })
@@ -1800,6 +1926,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define cmpxchg_release(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_release(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_cmpxchg_release(__ai_ptr, __VA_ARGS__); \
 })
@@ -1814,6 +1941,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define cmpxchg64(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_cmpxchg64(__ai_ptr, __VA_ARGS__); \
 })
@@ -1828,6 +1956,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define cmpxchg64_release(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_release(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_cmpxchg64_release(__ai_ptr, __VA_ARGS__); \
 })
@@ -1843,6 +1972,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
 	typeof(oldp) __ai_oldp = (oldp); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
 	arch_try_cmpxchg(__ai_ptr, __ai_oldp, __VA_ARGS__); \
@@ -1861,6 +1991,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
 	typeof(oldp) __ai_oldp = (oldp); \
+	kcsan_release(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
 	arch_try_cmpxchg_release(__ai_ptr, __ai_oldp, __VA_ARGS__); \
@@ -1892,6 +2023,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define sync_cmpxchg(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_sync_cmpxchg(__ai_ptr, __VA_ARGS__); \
 })
@@ -1899,6 +2031,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define cmpxchg_double(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, 2 * sizeof(*__ai_ptr)); \
 	arch_cmpxchg_double(__ai_ptr, __VA_ARGS__); \
 })
@@ -1912,4 +2045,4 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 })
 
 #endif /* _LINUX_ATOMIC_INSTRUMENTED_H */
-// 2a9553f0a9d5619f19151092df5cabbbf16ce835
+// 87c974b93032afd42143613434d1a7788fa598f9
diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
index 035ceb4ee85c9..68f902731d018 100755
--- a/scripts/atomic/gen-atomic-instrumented.sh
+++ b/scripts/atomic/gen-atomic-instrumented.sh
@@ -34,6 +34,14 @@ gen_param_check()
 gen_params_checks()
 {
 	local meta="$1"; shift
+	local order="$1"; shift
+
+	if [ "${order}" = "_release" ]; then
+		printf "\tkcsan_release();\n"
+	elif [ -z "${order}" ] && ! meta_in "$meta" "slv"; then
+		# RMW with return value is fully ordered
+		printf "\tkcsan_mb();\n"
+	fi
 
 	while [ "$#" -gt 0 ]; do
 		gen_param_check "$meta" "$1"
@@ -56,7 +64,7 @@ gen_proto_order_variant()
 
 	local ret="$(gen_ret_type "${meta}" "${int}")"
 	local params="$(gen_params "${int}" "${atomic}" "$@")"
-	local checks="$(gen_params_checks "${meta}" "$@")"
+	local checks="$(gen_params_checks "${meta}" "${order}" "$@")"
 	local args="$(gen_args "$@")"
 	local retstmt="$(gen_ret_stmt "${meta}")"
 
@@ -75,29 +83,44 @@ EOF
 gen_xchg()
 {
 	local xchg="$1"; shift
+	local order="$1"; shift
 	local mult="$1"; shift
 
+	kcsan_barrier=""
+	if [ "${xchg%_local}" = "${xchg}" ]; then
+		case "$order" in
+		_release)	kcsan_barrier="kcsan_release()" ;;
+		"")			kcsan_barrier="kcsan_mb()" ;;
+		esac
+	fi
+
 	if [ "${xchg%${xchg#try_cmpxchg}}" = "try_cmpxchg" ] ; then
 
 cat <<EOF
-#define ${xchg}(ptr, oldp, ...) \\
+#define ${xchg}${order}(ptr, oldp, ...) \\
 ({ \\
 	typeof(ptr) __ai_ptr = (ptr); \\
 	typeof(oldp) __ai_oldp = (oldp); \\
+EOF
+[ -n "$kcsan_barrier" ] && printf "\t${kcsan_barrier}; \\\\\n"
+cat <<EOF
 	instrument_atomic_write(__ai_ptr, ${mult}sizeof(*__ai_ptr)); \\
 	instrument_atomic_write(__ai_oldp, ${mult}sizeof(*__ai_oldp)); \\
-	arch_${xchg}(__ai_ptr, __ai_oldp, __VA_ARGS__); \\
+	arch_${xchg}${order}(__ai_ptr, __ai_oldp, __VA_ARGS__); \\
 })
 EOF
 
 	else
 
 cat <<EOF
-#define ${xchg}(ptr, ...) \\
+#define ${xchg}${order}(ptr, ...) \\
 ({ \\
 	typeof(ptr) __ai_ptr = (ptr); \\
+EOF
+[ -n "$kcsan_barrier" ] && printf "\t${kcsan_barrier}; \\\\\n"
+cat <<EOF
 	instrument_atomic_write(__ai_ptr, ${mult}sizeof(*__ai_ptr)); \\
-	arch_${xchg}(__ai_ptr, __VA_ARGS__); \\
+	arch_${xchg}${order}(__ai_ptr, __VA_ARGS__); \\
 })
 EOF
 
@@ -145,21 +168,21 @@ done
 
 for xchg in "xchg" "cmpxchg" "cmpxchg64" "try_cmpxchg"; do
 	for order in "" "_acquire" "_release" "_relaxed"; do
-		gen_xchg "${xchg}${order}" ""
+		gen_xchg "${xchg}" "${order}" ""
 		printf "\n"
 	done
 done
 
 for xchg in "cmpxchg_local" "cmpxchg64_local" "sync_cmpxchg"; do
-	gen_xchg "${xchg}" ""
+	gen_xchg "${xchg}" "" ""
 	printf "\n"
 done
 
-gen_xchg "cmpxchg_double" "2 * "
+gen_xchg "cmpxchg_double" "" "2 * "
 
 printf "\n\n"
 
-gen_xchg "cmpxchg_double_local" "2 * "
+gen_xchg "cmpxchg_double_local" "" "2 * "
 
 cat <<EOF
 
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-16-paulmck%40kernel.org.
