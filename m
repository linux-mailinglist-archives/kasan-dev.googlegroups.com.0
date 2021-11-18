Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFEV3CGAMGQE3HPTKOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id BA6A7455652
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:00 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id b133-20020a1c808b000000b0032cdd691994sf3994881wmd.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223060; cv=pass;
        d=google.com; s=arc-20160816;
        b=bqM8R4XCYpFxiNOK7L1oWJWOB3oPJyALE3nRDyZTuw1NkInA6NrHVNHOMWpqYN9rSI
         V42wlksHQ2jqZoclJ8SD+kolxVbzSLaPWoiFU2RR06e93H/N9CUqnMaeUExKoeWaLVq3
         qn8AaMIIn0cFzcdjsLP63k7D5UK144McHbl0hod7Dq+tsBsI2ejBWoutcb8/M1fi50/y
         QXcD75MjQtETl64ah4k0/LJ65qpd3eig67Kx8zqQUxNCI/T3u24zBYYNKEN5Jvim0Opg
         G9bkZGFDowbcQsKqT+KpyjJiFsLX0LlxzCyq7/hJCYXCCKN5tNd74sTjdK1wnk2jYSNG
         dkTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=wQrK/suWY6e/UNkqMByQnCjGnLKD4mltsOV0NwcHz50=;
        b=vTSHU2L5CJf4/Q7ow3M+otKEAV+Isv+LNtw65Mlc1pjCvqKm0+Xc1FdzSasMx5aeYB
         9RodUltPtX8VCJ5wQ05OwjNnAtDQs4UpkJLSRlGLC+puWUkBbxctXhqEV3QofSeWSfVw
         1swxv1AwcUH6dxdb3IAkFZW8OCoUCgpWdcJc/h5hFlaOBcZC5V3RxJXLeE2PxPFRO7lC
         Kvm5flQcpUZ4rvcAdj8pqL0KrWpegkvmYhR6KyKqD//psJ8i+x2H1eCx76lU+1yWWGTk
         hl8wqKqy+swTbunuddMwz43ESp1JBooXf5BWbgWsirAmbEycepaqxgX2uD516P6X/+yN
         lMWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XyT5v0i6;
       spf=pass (google.com: domain of 3kgqwyqukcrmx4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3kgqWYQUKCRMx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wQrK/suWY6e/UNkqMByQnCjGnLKD4mltsOV0NwcHz50=;
        b=lPiXBT9FnVnTiA5vurIs+y2D9dewbDHY10ggo4tX8UC5uTuTIKqkCSlBm3e3xL/IX7
         1SWVtkBSN/s9fPo8hdaKZy+flgZUGyBkkCwgFGjeaL/8g1lydUHJGguCR40kd5bgC+9v
         hjLD0v+GwWBA/B0pD3riklyKbabiY2SoT5LkqON8AqN4seOsQORKup03WWBVlWhjNSeP
         z073iCq7vdYfOVC4LfmEeSpWcJ7A9aYTumbQ5CNd5Z+/MH+tYt/VorDSd6xURsFJvC0o
         xpTEfNmh/pgxL4ryhfUkrWtFKylTZbKeLBuA7e+UgsMkg4uxdnX5lBNiThZ7LSxrEiaB
         /9NQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wQrK/suWY6e/UNkqMByQnCjGnLKD4mltsOV0NwcHz50=;
        b=QBu9/lz362rZxZjm5GS+wBtw5hi9nuY5oaHlyNbY4RrRbaepMOArP45OwNzSPnmokT
         dHR/dEOm4I2AYzdMHhBhGJFT4pBDeJuWN+wD7xcfET+yoqBmaRcgTG/68A/qa7ZGFjsL
         5WCu9kcwYzTDfVBuU+xEqa1BhA2jqCTk5ZEk91PfAA1oGK+fZ7wSToARvTguaZnhOh7d
         Xr5DUNTCCmqQ1tkvCuIVWkXuoQgGweQATJfQMpxG/iByQCPXGP/fJfevc/bt7Tujq78B
         gAKijLC0GiIdOhsqNfG8AOFfJwX+A0CTTfuBgQCygbKZ7NoXTrLOD+LbZ6qMxF85OCdG
         bfEQ==
X-Gm-Message-State: AOAM53324TZzP4M7zCb7SzlwXK0j1RwrPBHtEdurJLZEFQYUxT2F+Mqo
	JFK/sorHni2IpCc4BzxJDcc=
X-Google-Smtp-Source: ABdhPJzqOJRg726ErGTaTk13kW3uhpbBlcrdqcDwIDP7NRssH654HME3tNCg/DR6PWtJA0OJ6gx7AA==
X-Received: by 2002:a5d:5651:: with SMTP id j17mr28737765wrw.166.1637223060513;
        Thu, 18 Nov 2021 00:11:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1943:: with SMTP id 64ls1165392wmz.0.gmail; Thu, 18 Nov
 2021 00:10:59 -0800 (PST)
X-Received: by 2002:a05:600c:a05:: with SMTP id z5mr7655498wmp.73.1637223059533;
        Thu, 18 Nov 2021 00:10:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223059; cv=none;
        d=google.com; s=arc-20160816;
        b=y+Tm3MeCdf9ndfNYcxu7RE2l1U/wZUz1VOsgvsJN9DgF+nFRNxnaS1et319jw23tlY
         T/m0H+MJaUFDspXPj5RDOvFSmxMWHXgWYkoPQ62T5hBr7TjH4m4axHOygp6z6qblP/pA
         gIjpj/mVxxn8027RXzWpuEJxU7lWj17B0bEeKhA4AsxxeG/S4cHSj11MmdQUFT9bZCEe
         lbr1qey4ssQe4YNfhy1CnjDA6gy2Cy5Nd/+bbwPeUlt8McjKHjykXsxS9E8iF4fbZMOq
         bLWtqF084BGQj6MIu0GXa1kwWGOVI/GDA8iOULBgd/1KhvRhxXlgdbVXu1BKWXIR4uIP
         dfYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=SHlXPesj/sMVN1b9WbUeHFHzMLC0KZiq0qGR6QmTL6E=;
        b=gonW+N0x0P0Iay2KyMtk9irfZXoIn1ccV4U4LcZxsS471FS59UmlHtqmYvoJr7COZ6
         i8qE9WuQ61Ps9pMI6c3/ZREPsnW/B45tVsLqN1ySlFhwGX7uQ8e1c5VK0CdiXP2IZj0t
         f9b/LhojrjZ0Oe8gRZ9CllBXzYc8siDE6kT0UAnM4KagJPmfHutlaNx9kvYsWOxhpR2Q
         2+Mo9jZV0F3J52xJmhHUmmFpEkK3zvH3/OkyXGd9g+3OWvkTIGeElnl+PbI2dh4JO+km
         RFv264BuID5HQjgZL2kny1jJVVDKPoqQL/UWyw5N9asbUFN3t+WmfKf4PcQ5a1np3tvN
         zFRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XyT5v0i6;
       spf=pass (google.com: domain of 3kgqwyqukcrmx4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3kgqWYQUKCRMx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id j14si171787wrq.5.2021.11.18.00.10.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:10:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kgqwyqukcrmx4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id v10-20020a1cf70a000000b00318203a6bd1so2718433wmh.6
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:10:59 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:24c:: with SMTP id
 12mr7649392wmj.124.1637223058978; Thu, 18 Nov 2021 00:10:58 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:05 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-2-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 01/23] kcsan: Refactor reading of instrumented memory
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XyT5v0i6;       spf=pass
 (google.com: domain of 3kgqwyqukcrmx4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3kgqWYQUKCRMx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
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

Factor out the switch statement reading instrumented memory into a
helper read_instrumented_memory().

No functional change.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 51 +++++++++++++++------------------------------
 1 file changed, 17 insertions(+), 34 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 4b84c8e7884b..6bfd3040f46b 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -325,6 +325,21 @@ static void delay_access(int type)
 	udelay(delay);
 }
 
+/*
+ * Reads the instrumented memory for value change detection; value change
+ * detection is currently done for accesses up to a size of 8 bytes.
+ */
+static __always_inline u64 read_instrumented_memory(const volatile void *ptr, size_t size)
+{
+	switch (size) {
+	case 1:  return READ_ONCE(*(const u8 *)ptr);
+	case 2:  return READ_ONCE(*(const u16 *)ptr);
+	case 4:  return READ_ONCE(*(const u32 *)ptr);
+	case 8:  return READ_ONCE(*(const u64 *)ptr);
+	default: return 0; /* Ignore; we do not diff the values. */
+	}
+}
+
 void kcsan_save_irqtrace(struct task_struct *task)
 {
 #ifdef CONFIG_TRACE_IRQFLAGS
@@ -482,23 +497,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	 * Read the current value, to later check and infer a race if the data
 	 * was modified via a non-instrumented access, e.g. from a device.
 	 */
-	old = 0;
-	switch (size) {
-	case 1:
-		old = READ_ONCE(*(const u8 *)ptr);
-		break;
-	case 2:
-		old = READ_ONCE(*(const u16 *)ptr);
-		break;
-	case 4:
-		old = READ_ONCE(*(const u32 *)ptr);
-		break;
-	case 8:
-		old = READ_ONCE(*(const u64 *)ptr);
-		break;
-	default:
-		break; /* ignore; we do not diff the values */
-	}
+	old = read_instrumented_memory(ptr, size);
 
 	/*
 	 * Delay this thread, to increase probability of observing a racy
@@ -511,23 +510,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	 * racy access.
 	 */
 	access_mask = ctx->access_mask;
-	new = 0;
-	switch (size) {
-	case 1:
-		new = READ_ONCE(*(const u8 *)ptr);
-		break;
-	case 2:
-		new = READ_ONCE(*(const u16 *)ptr);
-		break;
-	case 4:
-		new = READ_ONCE(*(const u32 *)ptr);
-		break;
-	case 8:
-		new = READ_ONCE(*(const u64 *)ptr);
-		break;
-	default:
-		break; /* ignore; we do not diff the values */
-	}
+	new = read_instrumented_memory(ptr, size);
 
 	diff = old ^ new;
 	if (access_mask)
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-2-elver%40google.com.
