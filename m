Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMGD5SBAMGQETUEHBVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id F137A347715
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:37 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id k4sf1319390ili.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585137; cv=pass;
        d=google.com; s=arc-20160816;
        b=0RSutHgw3J2qyAL4Gar0C87CtPitikyy+ukKe/FWe7RTeDJnO+vq9yYuPedzCWjsFO
         T0ZXMOd2dEQh/e8Wp82OWZklCa7I2076uJV3tGWjBnIlVGYlckomVkTGXiqGepRicTpT
         cXEYvXMFFxmB/27+Ti8U9Gqf4iod3VYObOZeoXY7GeprUlACsr4oRrXUw44taJgzJLSi
         Q0scXGoy6BY/aNW0DkT4XJpO9aJcdS3S421YcSvQt2iTYnHMBgWWCcmgf7e/X431dJly
         ZzJ389rtRw5MtXYl3Iuv4Ys07xS+U1bgfakMaEIn2aV3tkf7/UZpwIm7PReZzoc892ad
         qHoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Wf/yoEI2SpvMpAzr6K2oFsOOuBummHYcg3ZtrntK6qQ=;
        b=GaUpWbFT9He1vM5AWC2ET/UWtX2L8an/yk/UNO4/QivP1e7nrAcpxMvMuCaZ8vMiMr
         n2ZO6cw4/QKHVd2QL3uF3WcqrlOmj+Q4xkpshE2kD2pZFImAPOPGSicy+lKlBRuZtK3U
         nmE5IKBL4jXcEIknBY5tBXCyP5NBd8QHdKnB1w4ukv6hTHKiTmXlxK5lqTiYlr7nCnIs
         ZvmfjyGAIGsgAX00KK4fD7aiGbssTOIvtWDEIha5S/XFSbtGmw0zYQ9ElTBE+TSY3D3a
         ZouWJZ8WnHGzD3WjA4nXGFaAdg9gdYz11VLFNoGZ1p2ySE9UlRbuoLemVCrgeMrHJX/+
         on2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eB0ckdgL;
       spf=pass (google.com: domain of 3scfbyaukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3sCFbYAUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wf/yoEI2SpvMpAzr6K2oFsOOuBummHYcg3ZtrntK6qQ=;
        b=j4pIMi9SKytr9QVkkY7vEkKBFHo1yhPmP7AZBFtMpW6R+FtrgjG6Mh2B7FSgMgmhAB
         R0QRTETwzqGeBVusn2Ods1T4sSxa7qWLVaJhPWEzjG4jQhKaSMoqqKV6ZdDmyCO+vKT5
         PtmyTr0ejEo/N9uTikZHnpLyBNTTYnLu/hvP4ylTPNPRRNkEyh/BLBYdsgJG8fT/byOO
         KBN5ibLSC1Bzl90d/l//ywLzb8sAIU2QJD7wmgo469JBMtMZZ3gEg2xoc75pz4rQKaVq
         5ozBFKKNHEXFCQv/iWk7jGRomC8uGJ0bieiw2bj7sU1mhn9ABg+lMqtDkcjaPdAkuYbJ
         F94g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wf/yoEI2SpvMpAzr6K2oFsOOuBummHYcg3ZtrntK6qQ=;
        b=U6cieTTSxvyFYSPgU9LrTMkBTnVfz97N/V0dIwXhUKAM7lyS+FptCkMGAy1f1YuHb0
         reyPOYi9xWXixMFMx9SNq9DLxLYR4S9aW5V++hbcd02lXRuqvb3CAcDAVrteu4a+WUWg
         MGLxdxvEPlxfdtwtNevjUf8kaDmRklaWXBdyvJxr5l5SmjLPyRiNzr5RNqo1yWPSPttk
         1TYZiPjoRnW/EcIREm3uq0XR1TE/sFsLiqUoTcUp1chEszG5rHXvEyFKAf1PP5kbIRE3
         xVaptDnTEj029Q26p3GoYttXlcmh9RQNVMVVLiZEmsZ2Ew1zhOpJkT6w9AnpfZziARh3
         9f6g==
X-Gm-Message-State: AOAM530LnxX7FaIR3gtBHRio8MUBXfVQuDPrnjCKNAsY/QhYvGuUWLqP
	uBE6U9+uwlqVC9PuEu41Xf0=
X-Google-Smtp-Source: ABdhPJx6CE74rU/HgjRyhVgNwLwy+pFxrv3hWk62ugTDH+t+iv3H2jal912WKiTgU2x53k1QS56hqw==
X-Received: by 2002:a5d:8416:: with SMTP id i22mr1995482ion.32.1616585137029;
        Wed, 24 Mar 2021 04:25:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3046:: with SMTP id u6ls246846jak.8.gmail; Wed, 24
 Mar 2021 04:25:36 -0700 (PDT)
X-Received: by 2002:a02:c6b4:: with SMTP id o20mr2345316jan.124.1616585136689;
        Wed, 24 Mar 2021 04:25:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585136; cv=none;
        d=google.com; s=arc-20160816;
        b=QjcIwQICpkp+qIcbxlOlhDagYIKhtpUD91pCI9t4sutHikvBRIbTrEcRZY4U2dcR01
         DCwb1bqAgwjIm3HcQPzMCvKrt0klLyrF0zbHPhpJP0dzve3SRA77e8ffF4aRBfV2iWa0
         9lqpM4CExCBoe8Gkb1TxlkWpc2hfhYB896c6yJ9oEN7+cp3nsw0mbg/mb/7W1KxBOrQp
         7aT2A/oobzBJUOXaDsoBeyb8dsqKueivbL0vfOsTw3eFaKMjTGxoP805RePpSZgVg76v
         I7gdqUP57dV6cZqyo6eGcy2cKXQHHHnzgdoH1ji70vW7N12j9dmNjuDCXoisim8+wsxg
         LOHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=yTQtN+ZnokJzpQVm2BawzGlkCzsy9LGpOuPbrdojTxI=;
        b=SZvR9htfWSWqrR4235XtgavxW1OssdojrqcYIf/6KMgp9mG6Jnn8xSgWZ6nKp3gzzM
         QugJbk998eGYWljcfjZT15PYHvk2qpZrYBBffduL+erJruUNrFygi7cvPU0X5nKwQqzx
         u0V+Xssu/ZzSKMwI6/AYuio37IfXVRwaHju3TEgadgbVWXP9EZ2z7+b2xSLvh39tQqF/
         6TEGTHARZsLBU7VxIB9F+qaMPfHtrp2WnQX2exhg4LUvqMIOp69YCAOdLOVVeKyFVWz5
         R5yL7ePDlRkQMMsLG/SgO040reKa8kYUbFMAUrErtNv1yT6hWGtoLqNE8QsyPyUup7mT
         JK0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eB0ckdgL;
       spf=pass (google.com: domain of 3scfbyaukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3sCFbYAUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id y13si62021ilv.0.2021.03.24.04.25.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3scfbyaukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id dz17so1118039qvb.14
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:36 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:ad4:50d0:: with SMTP id e16mr2718629qvq.37.1616585136104;
 Wed, 24 Mar 2021 04:25:36 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:24:59 +0100
In-Reply-To: <20210324112503.623833-1-elver@google.com>
Message-Id: <20210324112503.623833-8-elver@google.com>
Mime-Version: 1.0
References: <20210324112503.623833-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 07/11] perf: Add breakpoint information to siginfo on SIGTRAP
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eB0ckdgL;       spf=pass
 (google.com: domain of 3scfbyaukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3sCFbYAUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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

Encode information from breakpoint attributes into siginfo_t, which
helps disambiguate which breakpoint fired.

Note, providing the event fd may be unreliable, since the event may have
been modified (via PERF_EVENT_IOC_MODIFY_ATTRIBUTES) between the event
triggering and the signal being delivered to user space.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Add comment about si_perf==0.
---
 kernel/events/core.c | 16 ++++++++++++++++
 1 file changed, 16 insertions(+)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index 1e4c949bf75f..0316d39e8c8f 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6399,6 +6399,22 @@ static void perf_sigtrap(struct perf_event *event)
 	info.si_signo = SIGTRAP;
 	info.si_code = TRAP_PERF;
 	info.si_errno = event->attr.type;
+
+	switch (event->attr.type) {
+	case PERF_TYPE_BREAKPOINT:
+		info.si_addr = (void *)(unsigned long)event->attr.bp_addr;
+		info.si_perf = (event->attr.bp_len << 16) | (u64)event->attr.bp_type;
+		break;
+	default:
+		/*
+		 * No additional info set (si_perf == 0).
+		 *
+		 * Adding new cases for event types to set si_perf to a
+		 * non-constant value must ensure that si_perf != 0.
+		 */
+		break;
+	}
+
 	force_sig_info(&info);
 }
 
-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-8-elver%40google.com.
