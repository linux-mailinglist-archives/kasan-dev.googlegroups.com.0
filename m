Return-Path: <kasan-dev+bncBAABBMHNSH6QKGQEHP5K4MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 94D0F2A897D
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 23:03:29 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id f9sf1393221ool.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 14:03:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604613808; cv=pass;
        d=google.com; s=arc-20160816;
        b=ir8bH3oKvz/4X6f2bL7KKTSatOurSe6MiTklBZPiCBi6y33SJ/5u66zL3ASUYkEtDM
         BAsW3WjtjWLSnPBTVznKchUfM/7nReG/v7xB5jHKLimNKEr+3ED9TnBoQ2pf8grbZDSs
         pVP0MUNfcHjnP37CfMxt6txTllY0ZpqUyleuDLyLORVuKlACUQc2joFJ3SHj3tTAiYRc
         PBIptw0CsNqPtTl8lk5JpmaGRW9YXMqN3A7nbvS+5j6wrMVITvaW8rsgZ2TsmdEHpqfC
         jeiuUUrkfCRPZjw8MkktfUB+FyU+97f0h7V8MgJY3GIbC5lG5KEYZIUziGQ6awUMRgng
         Gc3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=dDctCqsQ3ENzo4KQ+fI4+Mg1pG0p2nQE57upvgh0zKk=;
        b=a/jee6SgMvYiKwC6hfPjoYqy99u2hPiWTAyMuCDtJuuGeQyl93dEYlrpntWgJNIm1h
         /7vIeh7/sSYcJc597AwbOZkT0AgQQwZafYHABm7Gzc0Fefdrs/SjDlBzx5s3u48DVb1e
         p4hdDyJe6wH1MNMp7PFOcFSHYkczW/C4E04z0O+QvVg1IVsVcAGXJYbsL2vyqZCgtzmq
         h+HLkVX+bIfgpuncc5JSu+zRaP+Fo7AtW7IIYUpvpoYLpAZIeAAOnmOyLUtxVHt0mhQq
         xcdpI18ccWKhkffctKn47iVCJiGQeIkwi7gthDiJ8XuZjcNIFNSVoXNiDZqb+tuBUkd6
         oGog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Jpi8vFYw;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dDctCqsQ3ENzo4KQ+fI4+Mg1pG0p2nQE57upvgh0zKk=;
        b=ssete0EhEqTup7QswFdXVB0jXusla3oMlH+PdN9VOgxiZeHl+gP0ibGAI+kZEoOT5q
         jX22mzhq7Xkb8pwQ1S0NXJAm7wEx3K9+JdwAHEgqR9uJI0nG+naJDHJIE5RdGndoA0Zi
         QA1ebVCeUy6RVPg5ywegxSnwD4emfylADsxdZ0Mm4F15rujwN32BdYH9GB9a+xvBMCuu
         3LhAe553+cP5hAhI9LQi7MU8v/T2d+k2CVPe+ufuIq4QbMAOCbrE9BFrw/CjQYxsn9Gp
         f8rOLrviG/A7zm0suRNf70y2YeZTfPBehgZnC0ZlZhugf8/F8t6C8/ihzhzwnqedJ8HR
         RFIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dDctCqsQ3ENzo4KQ+fI4+Mg1pG0p2nQE57upvgh0zKk=;
        b=p6im94awSQOXMMgCR920Chpc70OcH3RBknaQubgFQGj8AJYp0pUUKdaUydkF1MqCpM
         spRiIWTs5k7OUrVoxampJMY8xiARfvKekNTSP5WvUa2DZDJgRqtf7Ogl0fJ8vohGrr5Y
         0v4iISGVQNa0/f51VQ1FJkNXv+5QvFAAq7UOiGfy+vO6rfSDRnUrIbjWbfNIwwbdGYX1
         gM8XEsuupUQklyBHi/k+O8rL+e+/UZNSTgzMlcwfIvQ0WY3XuZBOA1VPRmi/YO0SYM+u
         tJU7vQnSnrRjNrYkHH8GG7wNkLmg5sTzXXI7ukn527oFH72pE0iwnvoSNyFYWu9TA6zo
         UE4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532i4Z89Lal0y+T7ZsCcQdkGSIFmVF0KENWZ4HKyo9XK5vyqMsOf
	MO1VwnmgBoOA1XCgBHFujRI=
X-Google-Smtp-Source: ABdhPJzaf9EK/DjGO969Vh7x0IJdsZVPite798JP8uJsTZVA3Ecq/8Y9QG0YD1A+1qsYw5X+uxEQHA==
X-Received: by 2002:aca:ec97:: with SMTP id k145mr957435oih.163.1604613808488;
        Thu, 05 Nov 2020 14:03:28 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3108:: with SMTP id b8ls797306ots.5.gmail; Thu, 05
 Nov 2020 14:03:26 -0800 (PST)
X-Received: by 2002:a05:6830:1e95:: with SMTP id n21mr3288215otr.49.1604613806673;
        Thu, 05 Nov 2020 14:03:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604613806; cv=none;
        d=google.com; s=arc-20160816;
        b=UKIi10hd+Q8DpF9bxPgfOtHorBCdf5Fe1ry/Tx1LZ+NrKYCJbLcmvwuM7ttY4DyMUD
         dcJFtwtbpi9//OULkJid18pWxkVwSFvoR7vIIFLvFJfYbcktj0taJPNadOAPUfNZ1xLX
         RZNIqIG1hyPTvM1jnSmJRzl7DPRr2SqeUHbNTpDcY66cNNsgZAqn/uAvRbnXj9md9qXW
         198wbSCZnx2w6LaATJj4kDi01L9qPwE2KyYkCR6YciRcCQX8gWRQw5dzUWhrm7Bfyz6J
         S5lawdck6jmjPyPSt1/Daj4AcSpn0j4dAwsvbUn6fFwfapKouM6mD2/BMTDvEpJlx64J
         u+RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=xKMULEpOfBI04klAXWZHIkY2FMbwD1Yaxglwahy21Yw=;
        b=KSwqT46SEqSrEr6TSX+I62G9QuoDdUHZn++7PiumEPlX1nrcDMdLFeOq24kjoa88Os
         OUH1QiB3B9W+QClVkOJTGaQ2PSMwr8Zq6AS4IdlE8aTVgfSifNaJS8JJmiZSuafl7qOD
         fQdMmI9bgpya7vUBYrR1bKOuQFsDAi1axdaxRSSdimmA47rxGeW9S+Zb37Fy5w674HmY
         WG08p1xCbiGIk0ZawszpBs+Vhq5JWsm37FN1DMOsS+cITjVzJg3ByOVgRSdU4nIT8JnV
         qxnr72sdnmsP4UlfAM9IQAGoSm3oSl//sFAEDbs3f9Z0gRmE+hqngKwF9xyH3Zu0aRW9
         /+aQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Jpi8vFYw;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e13si301780oth.3.2020.11.05.14.03.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 14:03:26 -0800 (PST)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9AB5120936;
	Thu,  5 Nov 2020 22:03:25 +0000 (UTC)
From: paulmck@kernel.org
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
Subject: [PATCH kcsan 2/3] kcsan: Never set up watchpoints on NULL pointers
Date: Thu,  5 Nov 2020 14:03:23 -0800
Message-Id: <20201105220324.15808-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20201105220302.GA15733@paulmck-ThinkPad-P72>
References: <20201105220302.GA15733@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Jpi8vFYw;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Avoid setting up watchpoints on NULL pointers, as otherwise we would
crash inside the KCSAN runtime (when checking for value changes) instead
of the instrumented code.

Because that may be confusing, skip any address less than PAGE_SIZE.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/encoding.h | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index 1a6db2f..4f73db6 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -48,7 +48,11 @@
 
 static inline bool check_encodable(unsigned long addr, size_t size)
 {
-	return size <= MAX_ENCODABLE_SIZE;
+	/*
+	 * While we can encode addrs<PAGE_SIZE, avoid crashing with a NULL
+	 * pointer deref inside KCSAN.
+	 */
+	return addr >= PAGE_SIZE && size <= MAX_ENCODABLE_SIZE;
 }
 
 static inline long
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105220324.15808-2-paulmck%40kernel.org.
