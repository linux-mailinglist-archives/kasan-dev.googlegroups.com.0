Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4X6RSMQMGQEOAUJG3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D1ADC5B9E31
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:26 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id q17-20020adfab11000000b0022a44f0c5d9sf4562121wrc.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254386; cv=pass;
        d=google.com; s=arc-20160816;
        b=XAAQFTtez/CYWu9FXOQDUnEDbXlPWe6m/HPdxYggNStzRNwixnfM3wcDtqfJUub+1l
         hUPMDlup5lYOH9vOuDvW1nCdvVaTFicSyA8CKletUYzxB1CaUmYao70ybSLPm6zFkyne
         xccNLIaWYbWRcDVGbJr04wbF4nR0fRIJs0K/h/GuZOO9UHfjynTWiP23kQdY67gYLNj2
         Edisp/J2sezRFURayIsvEdSWw6iMcsLAZeErQk9gJloTHzWl/obAOtRn9Wf71gPwJ8r1
         fVz1oLBhaJg7rTYmcrvz8R7yDrz91uonqc0QGwbw3NKFju4MONtujOFg9cDC2YmDF8eB
         t6uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=3jduLfS3bTdDeztj1SwnBA9hCluOdfPqcGIdxSBV1nM=;
        b=uZLkBFgWGHgLxnL4SZ3EwYppqxfW4ZmGr+Azd4eCMJYd9ScGFA0OW1mn9mM+MK/kvO
         VU5uwYM3rYnP6/ACEuKTaJbUjM2jMEgvF71Q16p+oBifR+1F64jNHgkqpOH8Glm0E5ki
         JMqvfyz7DDoCmqLuCsjoDkyYJvhtM2tbInKTpgzagaunOuC2WoJ5oOXANgpPg0ZRO9Hv
         O5kyuaWDSyqoQA01ZXG8OyvKxLAKV3L9B8D2s50D/q7CroiG+NlDHuYvjNvywyd8yYNQ
         gzuajVXlyR/nHfKEYziDuiSDifOLQsKsqGMJXaks79SS1ANDnaWZZ5HWmm5c5+tjum9Q
         ma8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F6VwgljK;
       spf=pass (google.com: domain of 3cd8jywykczsbgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3cD8jYwYKCZsBGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=3jduLfS3bTdDeztj1SwnBA9hCluOdfPqcGIdxSBV1nM=;
        b=d1KTYwLjb713ocmd97TsR1HjpMJwWQKaGhEam9Y5vx/Nt9lEMGD8hxYlti+5W0rIuU
         pyYTqGvcG802QHp7Zalm5ZJ5i0WX0gTDOQ2z+jQt/BPvFM/8lppIIV6usik708j3QoRM
         oR1/ug9k125NInYRbJY/bzIAMhwAMY/Uarw1D7ScEOu0SNSQwQvmEX0bJiuvn6N3TrIj
         DaI2K39Pr8IVTdr2YRRZJEnFpJOueOYN7TU6IH+PB1CIR0haurZC+fbNlbRkjsVoKHqU
         2k+Y+mzuoy78sBvbYagRi6x/meZwdV4lOhubyCLDIKn/goVahlDjWFNkVtx/jty+j6v0
         OGgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=3jduLfS3bTdDeztj1SwnBA9hCluOdfPqcGIdxSBV1nM=;
        b=zutKZ/xcdX/JpLmNS0uq9fCNDQ5UGAJQYONU86oZn2vymiW9nizN7fK2gDx4hE7J8D
         BmZd+knCoCMFAMOK1qtEShvWu97LHzZ/L6NMkOlnJfGTc0tA9/UScR9cnDI5hvH9YtDP
         Cuk1ueGbVIk+NKL0GqxgNHp88F9Hx9pBY9V8FhVc/MADbrZMqzJ9snk4G9SY7goyPVMK
         GOxiPh2AbOf5+OgIRgdxLeBIKAE1OF2q3B9TLTOQHL9KuFebjmDII8017cH6FU/ytgkY
         qogB/wmiQAPOCV2iq1DLg6MfANDDogXBtIn5rkYKBm484tu0CeRDv8ebcTcua7GW6Lfh
         cfUw==
X-Gm-Message-State: ACgBeo3+iD9jmKq/Zm92lW06DPUlKXEjxuu/YrwIkyKYcpxoc6E6JWr4
	MJIgi632d4KD/PB/htGWPto=
X-Google-Smtp-Source: AA6agR7yWnGYVxdUNJIPs/PDRaQqgnJX4d79GkQzMp5pL+5PIo4zPfcmWyVgzmfcyLVmWo//z6/C2g==
X-Received: by 2002:a05:600c:2e52:b0:3b4:622c:1b4b with SMTP id q18-20020a05600c2e5200b003b4622c1b4bmr7172036wmf.153.1663254386304;
        Thu, 15 Sep 2022 08:06:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c97:b0:3a5:a469:ba0a with SMTP id
 bg23-20020a05600c3c9700b003a5a469ba0als8142562wmb.2.-pod-canary-gmail; Thu,
 15 Sep 2022 08:06:25 -0700 (PDT)
X-Received: by 2002:a7b:ca46:0:b0:3b4:7ff1:4fcc with SMTP id m6-20020a7bca46000000b003b47ff14fccmr7215437wml.47.1663254385257;
        Thu, 15 Sep 2022 08:06:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254385; cv=none;
        d=google.com; s=arc-20160816;
        b=J3JSzWd6Q4CreEq06mOFisAf9w9AG5LrrM+NIJw5K7Gf58DLp37UovfYBm0xGPG2vt
         3gUpd6I/MSo0i5A/vqSvpFOc12arInioozTNM7YHNaDrb9+GyVAT1hR4NdXWaQhLq0oM
         nUh/gtF5QTXsAPQimY6zWDkjlASCUlDgYp5Z5cWHI1YCm8QMNwCwOzzbwPERXecggknn
         /eO3pMYJqWFRWdJE4hqjd37Gu0JD2Riw7vuaJ9ePY9SmFnjYm+At/EuDhQbMqpafUb/v
         VmTmFKqqp5EpX6R1nQysg2mrd747YKG6xdeth7vcQFC/XPzPpvfs5TR7G9mU/07Opr0n
         +HJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Rbxz0iuc7RXxWgIfjeSrHOuiWEHvXH2VAJuclXEfLdg=;
        b=iizARu6tZHwRiUFbDdesKuEwAFSvqu9v8F2ec3SP5pGDhTS3TL5cr9/cmADXqmZQ9Q
         k1K5aD8p4FUdJTLjOK2J4q4HcxwX1yJRElzQ7kC4s3au1+w5N4V0yCuhBKuKaTeOdzS7
         GY0jb1uRidEiYJWdZ9O0C2JLKaOFoy6wljy4pnj3jbB/Xr8vu1EObCuR12CfxMgx9sEo
         2GpSKczSfmuUCUiA5rZ/G6vz+yLrMvH3u3up8BVGNqlhi0+tomKc50CWnjTvXRwZZobF
         qrYoO7260JyoJf+2ZMLSgTclwSxHIuvgHVg4nxqUTbxg+KtZPmBDupyds9vTXPcKZLK7
         A4Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F6VwgljK;
       spf=pass (google.com: domain of 3cd8jywykczsbgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3cD8jYwYKCZsBGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id q25-20020a056000137900b0022a450aa8a8si43346wrz.6.2022.09.15.08.06.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cd8jywykczsbgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id go7-20020a1709070d8700b007793ffa7c44so7737247ejc.1
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:25 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:270f:b0:451:b5bd:95dd with SMTP id
 y15-20020a056402270f00b00451b5bd95ddmr251653edd.215.1663254384829; Thu, 15
 Sep 2022 08:06:24 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:13 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-40-glider@google.com>
Subject: [PATCH v7 39/43] x86: kmsan: don't instrument stack walking functions
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=F6VwgljK;       spf=pass
 (google.com: domain of 3cd8jywykczsbgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3cD8jYwYKCZsBGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-40-glider%40google.com.
