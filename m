Return-Path: <kasan-dev+bncBDA5JVXUX4ERBEHDQTFAMGQE376WWDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C178CC1EE2
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 11:16:49 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-477563a0c75sf28882385e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 02:16:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765880208; cv=pass;
        d=google.com; s=arc-20240605;
        b=J9rgsXNhkrYG5GmC2zEbUDKJwHDd0lINEb8q50iWZbtFIlTLda7qcdrmJ1ZDwYs6lR
         VxrqINQSj81i+hly/1Z9owUXa0yyUKi46YRAYBN5w/VCr+ofR3/SzMW8DEXJh9Vao1Rq
         TvXcpVsI+PcTWT2rRkp6UrUPQqVWC6zTzjTeqK6eyT6IcE/lqAJUEGuUAlcVMhcnwVw0
         DBnHw1Vb3QMm3Qri5e0FA8mzxUNKqXjqTi0V8rKpdlbzPPtRoH1NnPu3dCAxQTpfz9Nu
         62PCe6/S7+JGddYc8az1NiQ+/b9yQakQsuFLNspDetqn4JHwD2KSKBpLazXoOmBtec2b
         axJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=3e7azSNgi6hCDpwXUN/8Azw3XZCe1SYXZzUzoAkWuBI=;
        fh=hyqbfBTiBH0NaX3XsP+EgBJj2I8aVgNx3uYLYnK9rI0=;
        b=cF39inQO2+HruPBCr16QuHRNLwqxqIGfwxw5nTRrrn2aSh7hmF4Rr4zKPGFqONpvRi
         bZz7X24RjK8K0Fa+wvEKMfXNRtgyf8iZ2tTaQPF08n+zgs1IJcrJyFGZCVNm25gCGz11
         wEaSuroI8CT/l743B1KFyVWrDBEyxiZhFDHj4mLe14qGYg3urusI1aRQjpMCjGZdCHlK
         S9lnYkTGRCrU1kKwRSbMzfLCzQ1IInkhtrwY3D0MTgEfL0hfw9eQCbSR5dpDK6g2p6Tl
         jWn0ScGLTU7BSYcO7gyFcux88MD7NwWHelf2qSNaGzc57mBc1krBHXx5gwSkCp2jMp4I
         gdSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sVvxF0VM;
       spf=pass (google.com: domain of 3jtfbaqgkcuyriksuivjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3jTFBaQgKCUYriksuivjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765880208; x=1766485008; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3e7azSNgi6hCDpwXUN/8Azw3XZCe1SYXZzUzoAkWuBI=;
        b=NSeKmCWHkB2hcbWbTqpy+HbKi2YU2M8ceEoK/yecA1zfi580LvSn1JFKNNfIL0wTps
         QCbe9vtvNZU67/RWzkf5a7iTaLgj2/IR+e4SRZm3tvVSfQILaaVzDxSSVkx/4hTXVvEi
         FTfva2bC+Gd1xO2M4WvYWoua9XAZ28uqFOXvUuBGbZQhoR+xgRZcajJ4AsYeycnoW7OX
         PNXJTrlBs+1WvAwCwrd3+WCCqylBdIvMeuhZD9EpP016M/VhUifKfP39T19rSLbYXbOL
         JQXlbLJ4MhIckua7jNqftb5wD+Z3S4QcKrnZ1LleoKAlZCFPC2X1gmEZt3a989VE+zjS
         cy1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765880208; x=1766485008;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3e7azSNgi6hCDpwXUN/8Azw3XZCe1SYXZzUzoAkWuBI=;
        b=SwhYEhmfeXjaAdvb+NEm1G+uj628aOllKR0TtBfchrepM4QNyOF+znG8zO0JSbSqu7
         5O2+pGqSRTtQdweNgJRvb+VaR2CqTdPbROJDPODNgei27jod2Bt/CE18qWveEargl+es
         H0OOhabqZqMvSl23UNxAenC5fZaiEAZ3i+3N7ekDWDPwhI/lj9jsb/YKYgBMj3nAexLv
         uAI4UX6DZLmzPoWe+kmNLJUkOTSB78PE8pMAsfJKAgRSsREChOEsxBN8AjxkVai15A01
         fvzUgTsubi8QNA8xjv+Xz7iUZhL/7Et9ma5jLqt6lDu5hQMI/sSbRy6I25TniyUELoLk
         p4Bg==
X-Forwarded-Encrypted: i=2; AJvYcCXbgJQdIQUUUs2nsBEhoEE1LwJOeoUWjvIEHYj6bvPEBO+Dp+Tws6CSOEoAQiRi9DFzAlolYA==@lfdr.de
X-Gm-Message-State: AOJu0YwyC2X3tbsw8NHW30kjIez9+9uMvJG7w2LxddKFOoyxdW/VHpm+
	5cl5GmLy97NMmvSdbos3aDZNk+bwT+SnOBxgN7OpLF8ITMR0V/kUzElC
X-Google-Smtp-Source: AGHT+IG1CAAekF1IJMCRh93EHt0sG8U2t/s0rdKXN5olCar1Tf9P+hktNeiuCy3/9l2bmHOHwUt61A==
X-Received: by 2002:a05:600c:190c:b0:479:33be:b23e with SMTP id 5b1f17b1804b1-47a8f907d4cmr160324705e9.17.1765880208572;
        Tue, 16 Dec 2025 02:16:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaycA2tcD10EZg+A6Nx0IKoxHSJ5lyjBqa9GIoPsIj1ag=="
Received: by 2002:a05:600c:3593:b0:477:a036:8e82 with SMTP id
 5b1f17b1804b1-47a8ea1a3d6ls25631695e9.0.-pod-prod-08-eu; Tue, 16 Dec 2025
 02:16:46 -0800 (PST)
X-Received: by 2002:a05:600d:644e:20b0:47a:9574:b75f with SMTP id 5b1f17b1804b1-47a9574ba21mr95064315e9.33.1765880206156;
        Tue, 16 Dec 2025 02:16:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765880206; cv=none;
        d=google.com; s=arc-20240605;
        b=lavT/qkICLr+Qwr3QAk6fMmD6x5+gpNnHzPorcTmSDDFxpbpPui1GxflVyqkpjzc1I
         YH0FFI83Zhn35brIR+3MXDyeadCdfWSVzSu+KSzu09AOIeUNF2jANIBDyLhVKljTGAYH
         eMrJNMqITlyegL3wvQcOV1VhrqeYUBAFzWkQ+YzsabVib9HuS7mGklxfF9cHdMW13ifl
         cO6LLNeUo3C1NMBjuh89YU0O4P6AA1xEPUuAsGplA3VDPHXRTvtOmswnDjMhEAo9XBO7
         UbSlRLApd84y76OTM5Vi2KfeFXoKUFrH5yUtRONhWFag2hlrLEBsT7jAIr1wehA3zTiQ
         pnyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uP2brnCrErMSve8D4fzLeDUYWZS9bjiXvF2HnuazcK4=;
        fh=x2ubLsttaGNDEohungEU+QxSNGIjpxcBkXhQGHGw3fc=;
        b=M1UQ8ZXwOj5l3TFcz3eFIrHR0gDANXtLUe6qBurGC8CGC0yPNzgOloHZjBfzkkI3Xb
         79qPi/xZ4Vm5ZnJlputyBhQChBWTXF8JaOV5oYidvXO+2wWyYIRtSokH/ycDm/5pCw/E
         wLurO+20ohVl/D4eUBURbOVQjdbFXBSZSg0BwemzIfrBmlJqH59CHs3uxHkD8suFLKgG
         L48TgLcdhC5WIfdAsoihi/BX91Gy8YUMHHesdbbANsbUuVW/RCpywqg00A/3dfWGwbYq
         76B/h8KC0jcdJThLnfFuh66TS1r07H5degrZtvJIzIfb/VehSOT025cZs0jxvN8quzA8
         6bdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sVvxF0VM;
       spf=pass (google.com: domain of 3jtfbaqgkcuyriksuivjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3jTFBaQgKCUYriksuivjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47bd95f2a35si107825e9.2.2025.12.16.02.16.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 02:16:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jtfbaqgkcuyriksuivjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4779b432aecso23276435e9.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 02:16:46 -0800 (PST)
X-Received: from wmsl5.prod.google.com ([2002:a05:600c:1d05:b0:476:ddb0:2391])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:820f:b0:47a:829a:ebb with SMTP id 5b1f17b1804b1-47a8f90656dmr126613995e9.19.1765880205747;
 Tue, 16 Dec 2025 02:16:45 -0800 (PST)
Date: Tue, 16 Dec 2025 10:16:34 +0000
In-Reply-To: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
Mime-Version: 1.0
References: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
X-Mailer: b4 0.14.2
Message-ID: <20251216-gcov-inline-noinstr-v3-1-10244d154451@google.com>
Subject: [PATCH v3 1/3] kasan: mark !__SANITIZE_ADDRESS__ stubs __always_inline
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, Brendan Jackman <jackmanb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=sVvxF0VM;       spf=pass
 (google.com: domain of 3jtfbaqgkcuyriksuivjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3jTFBaQgKCUYriksuivjowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

The x86 instrumented bitops in
include/asm-generic/bitops/instrumented-non-atomic.h are
KASAN-instrumented via explicit calls to instrument_* functions from
include/linux/instrumented.h.

This bitops are used from noinstr code in __sev_es_nmi_complete(). This
code avoids noinstr violations by disabling __SANITIZE_ADDRESS__ etc for
the compilation unit.

However, when GCOV is enabled, there can still be violations caused by
the stub versions of these functions, since coverage instrumentation is
injected that causes them to be out-of-lined.

Fix this by just applying __always_inline.

Signed-off-by: Brendan Jackman <jackmanb@google.com>
---
 include/linux/kasan-checks.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
index 3d6d22a25bdc391c0015a6daf2249d6bea752dcb..9aa0f1cc90133ca334afa478b5f762aef9e5d79c 100644
--- a/include/linux/kasan-checks.h
+++ b/include/linux/kasan-checks.h
@@ -37,11 +37,11 @@ static inline bool __kasan_check_write(const volatile void *p, unsigned int size
 #define kasan_check_read __kasan_check_read
 #define kasan_check_write __kasan_check_write
 #else
-static inline bool kasan_check_read(const volatile void *p, unsigned int size)
+static __always_inline bool kasan_check_read(const volatile void *p, unsigned int size)
 {
 	return true;
 }
-static inline bool kasan_check_write(const volatile void *p, unsigned int size)
+static __always_inline bool kasan_check_write(const volatile void *p, unsigned int size)
 {
 	return true;
 }

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251216-gcov-inline-noinstr-v3-1-10244d154451%40google.com.
