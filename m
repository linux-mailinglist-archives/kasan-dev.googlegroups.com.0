Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCGW26MAMGQE6IMHSGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E4B45AD27D
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:49 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id f18-20020a05600c4e9200b003a5f81299casf5303482wmq.7
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380809; cv=pass;
        d=google.com; s=arc-20160816;
        b=n//hVG2vaKT2+K4VzACDwFI7LEcR2GoirouusNaHhUGLSezldxBOTVAtTkmS9xinTq
         hWEajmYoIzqZgcw7HryvglKcFYJWa5GMp298JeK8MmlHnVCLq7XPFcUx1jfxIUCL99MV
         K85u25I+upw84UNZZatSPaZj7ASVKhxooQ2ipV1qC68OIiKyZiMZfcP/LAgSM0Lly9q7
         +vj702fth+uUZVdpUZUrpLPolE9i84okcUnIIJEAFImgQzp0i4TUHxelXBW4T9lNDNYl
         oesio8it/SU+99k31D3ABsQdGqTqYefhJHAw0i0YTHkPqTXaGPf3UtXEqK0466gE9wfP
         FOwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=xeXOhr9rgWPc11Mw4A6Av+t1Ct45uTIEsS+JvrdWvzA=;
        b=y7c4vZqXT/XngsrcB1G+mY3Zh8gbu7ryYPoAtFp7ggW8cvFPtM46A2ox2HEeFK/pLN
         oLPAH1Nw1z3DiVRo4KfcuglGPzpRFI3zSX2LllVMulIrUCNOB5/HkMjHpavuGHG7++d+
         qJCOm51ZrvtMCClwl2Kx6dPF0511YaiZzugKTM0tJzFWrj2r/sAJage8lw11okUxl43I
         aTI6wnWlH0Lz5TMu2/iYDKryNbgTZ/J3Ru+S6wWiVKR81kHcCwYCoJ6pZKWSl38kAiSS
         6+yqDuZD8I3nOM4sh2YEgTQdVMH9SDAj74BtR6/bERNJC0A86Wou4q3t6I+w5gnkFMHI
         GCXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=THOF30Vt;
       spf=pass (google.com: domain of 3b-svywykcvq274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3B-sVYwYKCVQ274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=xeXOhr9rgWPc11Mw4A6Av+t1Ct45uTIEsS+JvrdWvzA=;
        b=STSrTeppq0Xc2ep5yUN3Iw1mw5pJ5bzGfKf4xEbdOCzZPlG/bDZ0821EoVuOLGEEvn
         OPHjCvuJZo85ulH5GKqP8dZOQl3ErnAUqZrsbIMSVCyuCjEXd35aA/q5P+vqFJQtOARh
         SnS8Qnt8CUXuyPfluOc7yN8RUF8O6ulr7zPnHsidoK7biqZ3IgQ6eOAP1+bAKKCmtUCL
         QOhddfQpmQi5jq8qDmaA3sYqqZuZHGWvFOHNTmV2jlRlJQEiBlBS8Zme80zNVy5CieEt
         3GWsgMX/bDxErN9Vb8XoYFTpRp+6MAXFLCXBgvFJEjIKh4+XgCIEEmEvNBfTmorq24Mn
         /uyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=xeXOhr9rgWPc11Mw4A6Av+t1Ct45uTIEsS+JvrdWvzA=;
        b=X3WJ71N+iV2zaT4OOMWGFXJJTBElbjma0ImtJPJsnc3eqs7q3JoVPnX7+gq6kry82U
         GkH0GGT5j9sKvNqjeGj0Feyvu3re3Z/yU5dMGUjPi1sFolFp1Cd9Y+3TGtSudiIqM+0N
         7xBupfucVU6Z4JZ9vkq+3U0mwr+KeJ1HZEy9IES9g6vZGNZY1xkITuDcN8PXmO2bcZ8x
         5Xohg7fXvV8Q2z924s573YHYvDFuiEZ2GJPljE6u4RW5kUrLzeAIISsIVe+LzORBtVeT
         P69DeG/FWzoeIHljG7Rxhavr3Qon3lY9TTio8PuVL8XMdCrM7qRaZyhac7yylE210Al4
         YMPw==
X-Gm-Message-State: ACgBeo1VQSLZ3Sf8FC+/xjaXaCE+dyixWH6zWq8qfThjHaBSzGHgy6kb
	tBuuu7kS4KIZ0BB0IZOoNCA=
X-Google-Smtp-Source: AA6agR648hNtCTIvz6/McT+qQ8cSx/1aQ9J95f5jJFGIbiTL99hQ0dXAL4oeqIU1R0z2sgjwpIG8Ig==
X-Received: by 2002:adf:eb0e:0:b0:226:db7d:6fed with SMTP id s14-20020adfeb0e000000b00226db7d6fedmr20867526wrn.626.1662380809005;
        Mon, 05 Sep 2022 05:26:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5b08:0:b0:225:6559:3374 with SMTP id bx8-20020a5d5b08000000b0022565593374ls3547807wrb.2.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:26:48 -0700 (PDT)
X-Received: by 2002:a5d:434a:0:b0:21d:aa7e:b1bb with SMTP id u10-20020a5d434a000000b0021daa7eb1bbmr25951599wrr.619.1662380808034;
        Mon, 05 Sep 2022 05:26:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380808; cv=none;
        d=google.com; s=arc-20160816;
        b=dLA27oQnvNE/FMEIPY7Y/vc2JArW5yz7O7L6bKJYP6LcQJQLYyHPGGioMAMFWh64Bn
         HcpXOpied5kN+bSKp8NzuakW/20qhzQq99PTeUjP/k2DNqP1uDA/HJOkc3Q2MGQRb13G
         91vd/V20vZeJE2NOiyTyQ2iik8nsMNsqOqPACDwkD8ya7jMhTax7yHgmWGiUd8eFHl3J
         EoQZSKiw9HUJgNurWrROPMm4EIfMfj0edtVQ05wFQYkhCoEtXU2ZK+I124VgKQ5YIT8d
         dymth9HoQZYIokIcWuvFzVaPdLFbHz6czihjIQ/jTFhIbC/mi790qx6JNiNthBwwTwOe
         aXCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Rbxz0iuc7RXxWgIfjeSrHOuiWEHvXH2VAJuclXEfLdg=;
        b=FodgxT+wyXjQNYnhN9rO1v9ahYBJ+S/45s6H5le2mHe7ZpmLjCzCdDi3R2PUg4HFqK
         HKvl6Uzfx+5QGV/LJC0Tc14SslSmYZvA7/k7IhddkV1M9YrrJzT6kDsLaNjtDsr6ehy8
         iZDvjOS19F6DsmtLq4bHvOrEhE9lLII86y+joaCvA3Wu6ELEwhAMNcqcsmkB3kunes/X
         Ddix8SUJ913FUKJUr+ydro1kgTC5C4aye12T80ZSp/6WpOMvSBMR+wDB+alFdYeC09h7
         kT6BfNgEUFCYB4E9JpPgIBvYPebKXIa2PbeYTqiMb3xgFSgDLUbbR73jAIIoI+Jb+t70
         R3TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=THOF30Vt;
       spf=pass (google.com: domain of 3b-svywykcvq274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3B-sVYwYKCVQ274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id az17-20020adfe191000000b002206b4cd42fsi358614wrb.5.2022.09.05.05.26.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3b-svywykcvq274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id p4-20020a056402500400b00447e8b6f62bso5760319eda.17
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:48 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:aa7:cb87:0:b0:43b:e650:6036 with SMTP id
 r7-20020aa7cb87000000b0043be6506036mr44091595edt.350.1662380807787; Mon, 05
 Sep 2022 05:26:47 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:48 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-41-glider@google.com>
Subject: [PATCH v6 40/44] x86: kmsan: don't instrument stack walking functions
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=THOF30Vt;       spf=pass
 (google.com: domain of 3b-svywykcvq274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3B-sVYwYKCVQ274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Upon function exit, KMSAN marks local variables as uninitialized.
Further function calls may result in the compiler creating the stack
frame where these local variables resided. This results in frame
pointers being marked as uninitialized data, which is normally correct,
because they are not stack-allocated.

However stack unwinding functions are supposed to read and dereference
the frame pointers, in which case KMSAN might be reporting uses of
uninitialized values.

To work around that, we mark update_stack_state(), unwind_next_frame()
and show_trace_log_lvl() with __no_kmsan_checks, preventing all KMSAN
reports inside those functions and making them return initialized
values.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I6550563768fbb08aa60b2a96803675dcba93d802
---
 arch/x86/kernel/dumpstack.c    |  6 ++++++
 arch/x86/kernel/unwind_frame.c | 11 +++++++++++
 2 files changed, 17 insertions(+)

diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
index afae4dd774951..476eb504084e4 100644
--- a/arch/x86/kernel/dumpstack.c
+++ b/arch/x86/kernel/dumpstack.c
@@ -177,6 +177,12 @@ static void show_regs_if_on_stack(struct stack_info *info, struct pt_regs *regs,
 	}
 }
 
+/*
+ * This function reads pointers from the stack and dereferences them. The
+ * pointers may not have their KMSAN shadow set up properly, which may result
+ * in false positive reports. Disable instrumentation to avoid those.
+ */
+__no_kmsan_checks
 static void show_trace_log_lvl(struct task_struct *task, struct pt_regs *regs,
 			unsigned long *stack, const char *log_lvl)
 {
diff --git a/arch/x86/kernel/unwind_frame.c b/arch/x86/kernel/unwind_frame.c
index 8e1c50c86e5db..d8ba93778ae32 100644
--- a/arch/x86/kernel/unwind_frame.c
+++ b/arch/x86/kernel/unwind_frame.c
@@ -183,6 +183,16 @@ static struct pt_regs *decode_frame_pointer(unsigned long *bp)
 }
 #endif
 
+/*
+ * While walking the stack, KMSAN may stomp on stale locals from other
+ * functions that were marked as uninitialized upon function exit, and
+ * now hold the call frame information for the current function (e.g. the frame
+ * pointer). Because KMSAN does not specifically mark call frames as
+ * initialized, false positive reports are possible. To prevent such reports,
+ * we mark the functions scanning the stack (here and below) with
+ * __no_kmsan_checks.
+ */
+__no_kmsan_checks
 static bool update_stack_state(struct unwind_state *state,
 			       unsigned long *next_bp)
 {
@@ -250,6 +260,7 @@ static bool update_stack_state(struct unwind_state *state,
 	return true;
 }
 
+__no_kmsan_checks
 bool unwind_next_frame(struct unwind_state *state)
 {
 	struct pt_regs *regs;
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-41-glider%40google.com.
