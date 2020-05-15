Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZW67L2QKGQEXN4DGRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C37F1D52FC
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 17:04:07 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id y16sf2071578pfe.16
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 08:04:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589555046; cv=pass;
        d=google.com; s=arc-20160816;
        b=QxKPGfCaiiQc93pK4d/YgNcVI3zx+9xqtRl++gc+5+mnTdZWpuShVH79IyexZwiy53
         fMEj+VyF08rwiW6/9QKLK3PsUJ+xRRFuihOwhk7coB6sj3C0nAIu4mN0RpHl+KP1CYnp
         jYHcIUd5eUxNYj5c1nu5RM6XPMVLDrmq22NnhrZIZdXcbgy8CkXNZzE09NGazPdlelaq
         LA+UkRHNQZBwltp8lEjEl4RRazpE2rdVvv0LDfmK9Cyrg2JQziEvBnjannVKI+5X/GtK
         IiC06sKsIwNLOG9I+cz7kX2WL3mzxl/sGFxAVw+j1mNdWBBbp0enjpwhInrmMlUhYceL
         0Pvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=e4bVvSMTMN2FwFFJIBLp2y+K5dJzotuw42hp41EtI9E=;
        b=rok5jE7sDnU55qTDQxA8Mb4b7CEqes4lv31bCEMmGLN5kn73sHfTRPB2nMe6TiCRzb
         oI/9Jn42uLxXijISJIQq4eqV78b+HH7alCb5dUVbjQ5NMO8CLFVOQNYhPe4bip37shLW
         9l/XgCVr41iWwgpDFsYulffkdq6F7FTx3tFnZvShsvF8dlyUykmYV0+yizXeS+Ctw0sd
         KDjbVntsZRy+ywcWf1g9MmWQuuD92XgelQWn7SAEBqZZY4c7mntWXDIykS+78lgW4kQ0
         2eQRlVhap+hLpj8sggnci1PE/9/0Tib0DDvSujCk5fr7lQrST4CqaaANtiBUpbDVqLe7
         I7qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H9vVXern;
       spf=pass (google.com: domain of 3zk--xgukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ZK--XgUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e4bVvSMTMN2FwFFJIBLp2y+K5dJzotuw42hp41EtI9E=;
        b=lHi5KV5xDEOU+AX1V2wFBzqv+8eqtQC8iki/gsmlulaB/6RrWSOqyIn6HXsHknDfGA
         ypnPSmmx8zWVFXPg9D/YriTiiBhc89viAHxSrhSSSJYAuOwBpZc71MlQrIz68UTurYzI
         wh6JOFef3Ac2E50liRSjaWsJskX0SG2kQIYirqoDkzKkGVP+7PYtfAzOGk7A+5WgOWUI
         IzlVKHLOd8oALFoMB5OiP1iJPELGw/JmZZGwqAkyuGWSnqE0Bcpf1JaYvQWPK6b74LHg
         Q+RCFFoAnFwsVbPKwYioVLL2ApKcg69AoyH7leh0EU2yi9uIm2NmGInRsKKgi4DBJiSf
         r3XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e4bVvSMTMN2FwFFJIBLp2y+K5dJzotuw42hp41EtI9E=;
        b=p0yXch20aS5yn8iHeSicstBmZTOfbqKDA5c+KM9TgZlQFp9oSqjh7jqIeeJzd76ZuR
         oIdf9HjF1ZlKhXaRVOs96WymVn9+DKSxwrpYyekH7CIk4NKqWCdL3PipbXwW8vFO0uY7
         MflY77x5p4F94r8nWDmRCAF+Azv9biNUI2ti1AgP+sVvr3DD1U5+2w8eVcWvKA/P1GNR
         YZF/19CRir7zNQ63dh+Sprb7eW8L7r1aMtL+O+y2taElMFXDPR/lYMTiEb1kef0rF07s
         pFn/jHE5SEZuXEcIBuehPPh6Sf9A1tohfQPuVl+Kmvr6ZWeIJ/bYWjhdx5tZNRf8dlVb
         D2LQ==
X-Gm-Message-State: AOAM5307rcwDxfv9zzWYIEHPLKwGiWGPQoZCExHgjbydmS8GO+xOLyPu
	VKvTIAreKeV2zYsL06L3lZA=
X-Google-Smtp-Source: ABdhPJxM8QisN3sDgFrEr3s41z9w68qVaoFpdP3Qw2r6dcIBcm/KV8XVULwtQfBFWH4mWgAilltGrw==
X-Received: by 2002:a65:4947:: with SMTP id q7mr3596833pgs.23.1589555046114;
        Fri, 15 May 2020 08:04:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2944:: with SMTP id p65ls825636pgp.2.gmail; Fri, 15 May
 2020 08:04:05 -0700 (PDT)
X-Received: by 2002:a63:ed02:: with SMTP id d2mr3592947pgi.119.1589555045632;
        Fri, 15 May 2020 08:04:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589555045; cv=none;
        d=google.com; s=arc-20160816;
        b=gJRKeK4goCHgVgs8yR72Iw9yiYhzVwXthhrkqwvcQNl9aUzgaeZ6+xjCmm94HpONDE
         1s0P4+zT3P1BgdoSneflGEA3ILBVOsPzcGfaXLYB7csllQo3kMxEOnFMsaViAZcB8xEh
         aqSOfHHKuV59LxI2h39+nAkiNPDcsmR2xOXEAa0L8Xoa53IlBrePiJQ3QSrfwQ9EboiE
         7ATql1a7J6eXtMVjYryQgNoGYc1wxWjFZbbOOz5WZdvx8/3UR6/Q8NvmRJrMzpLe7cq5
         y4z90i0BotTVjdlCuMHoEaX2sVcxdG3XnKOGmgYngQleImk1yrYME3Y7EUJXfLfgGR4l
         iacQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=bOmDunhfUaahaaiKVLHLTe7nnH/k9WP55G/+iETR4Xc=;
        b=Jf/dnqS4DeAurumUiBAqtJQEfphKulETDt3nb1sTQEOrX3g1BE54douGfDvGgEpxwK
         XsF48iPm8qhSatibPy+vNgSOxlMAew3hDPXDdsY87OiR0DxwUnhLdnMMAE+9TFjc25w/
         0CfPrN1HovgGQiVRVGReFOGv28DeyHg7CpkZyJRzGaKJHVQAZrHqR+IdiwMfLO61GhQp
         1tc5vg2zk7eWTFOkh4TzenAcxSpy/IacjgjJ9W2tCNKe26x99dADbEOwGKs9mniRoFch
         +uuLT4po5zbjelbnJeqjOch/XmPW3+MbUXbAedMt21V4CKHO2GrvlS4+a6SXoJvJNdcP
         ExFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H9vVXern;
       spf=pass (google.com: domain of 3zk--xgukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ZK--XgUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id q34si151742pjh.2.2020.05.15.08.04.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 08:04:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zk--xgukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id y189so2871828ybc.14
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 08:04:05 -0700 (PDT)
X-Received: by 2002:a25:d786:: with SMTP id o128mr5956484ybg.519.1589555044732;
 Fri, 15 May 2020 08:04:04 -0700 (PDT)
Date: Fri, 15 May 2020 17:03:36 +0200
In-Reply-To: <20200515150338.190344-1-elver@google.com>
Message-Id: <20200515150338.190344-9-elver@google.com>
Mime-Version: 1.0
References: <20200515150338.190344-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip 08/10] READ_ONCE, WRITE_ONCE: Remove data_race() wrapping
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=H9vVXern;       spf=pass
 (google.com: domain of 3zk--xgukcbkdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ZK--XgUKCbkdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

The volatile access no longer needs to be wrapped in data_race(),
because we require compilers that emit instrumentation distinguishing
volatile accesses.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 17c98b215572..fce56402c082 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -229,7 +229,7 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
 #define __READ_ONCE_SCALAR(x)						\
 ({									\
 	typeof(x) *__xp = &(x);						\
-	__unqual_scalar_typeof(x) __x = data_race(__READ_ONCE(*__xp));	\
+	__unqual_scalar_typeof(x) __x = __READ_ONCE(*__xp);		\
 	kcsan_check_atomic_read(__xp, sizeof(*__xp));			\
 	smp_read_barrier_depends();					\
 	(typeof(x))__x;							\
@@ -250,7 +250,7 @@ do {									\
 do {									\
 	typeof(x) *__xp = &(x);						\
 	kcsan_check_atomic_write(__xp, sizeof(*__xp));			\
-	data_race(({ __WRITE_ONCE(*__xp, val); 0; }));			\
+	__WRITE_ONCE(*__xp, val);					\
 } while (0)
 
 #define WRITE_ONCE(x, val)						\
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515150338.190344-9-elver%40google.com.
