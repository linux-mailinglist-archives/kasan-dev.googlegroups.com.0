Return-Path: <kasan-dev+bncBDA5JVXUX4ERBEPDQTFAMGQERCCRLSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 00EF9CC1EE5
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 11:16:51 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-594cb7effeasf2209798e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 02:16:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765880210; cv=pass;
        d=google.com; s=arc-20240605;
        b=jQby4ZpOFJ1Ei59xzURSLSer9ZrF1JETgUWxAD5M8QSqvHAnPCIBStp+JP7DABNQwZ
         YbtUCky8DV7IM6Ntw6cXJVUKhTJKwHAr5LhXnyyXwCLfNPGuEbV0xteor0JZWYpnlv43
         fwkNvmNbJhotJ1AFB6szvzsPVLHXjiMsetJav1fInfyn2EfOwmvOwQvUhDagUg/HlC+t
         P/oyxaROhL7W18QJ88nehP52Fg5RwoItG1/jCQYZC7kEkaRyd/QxchkwoVZTvkB5fQ7+
         2ZhOXa0XM7X9UjtRz950q/NWqkZP84yvWGb7fIb+QNtZO8ndXHk4T+a1L5BRFg3g/N6F
         0H9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=2o1UHD6rxFAfXGsXQf7FX62t2MntRG6o2rCP3G4M0mQ=;
        fh=qtnpx/q6rKtILcenzZuM9AKgQqu4m8uv+KZ8I3wBxCI=;
        b=IuIUBBHmlyEmYXL+H09rJktcypSYpba2IDjLblZF2Mi0vsxY2tQHW69s+BgVNU9hY4
         3Gt0TgjEDJBoC5P/iI95ONsH7GdkSbxdeQ8xzUL0Ir6Hwftprbx7Kg+IG7wDsp5Jx5i0
         YeKsATQOn1+hrgo14opZF1zJMQQNivMHFrQVXfq7C+KxrBTtrE72Pot+g/Cu3bxwYuBL
         4kYERdm7/TnsOVRavkSeDortwFzMq61Kiyap69kgC0VMNH7mKvIl1ulperzvq8388Ovq
         PdQkhdjS1BECrcwgeUD3qsA/Q9mBxxFLSP2Uo/Z2F5p8jXk460L0L/wB+IrotLoT7w66
         Ytfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DBFfcqXM;
       spf=pass (google.com: domain of 3jjfbaqgkcucsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3jjFBaQgKCUcsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765880210; x=1766485010; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2o1UHD6rxFAfXGsXQf7FX62t2MntRG6o2rCP3G4M0mQ=;
        b=JQbcdknagdPbtpezZ6A7dmQUz5Kn+5QOC73wpu5kyVsOFftLlK0HizrzwIWir9SDhs
         DtbbD717VgiGrEMzRtiEuls2A3fiP1Wpa7zs1mCVMsHsjlZrPEHy+NDYEhCEB+McnEqx
         K80a+MxE+xoPTlg+yoe4G0H4KIQw2oh4n+/Bieoc213LSHjzFqXbAYVFG4Jr6Vop+gvW
         gTrcaTePl/mtxR+GQyP4wxbj4Ab3t9/CyV1YyNCdY84u0/wQ+aoWNtQb2NTCCHdLwz/I
         n7c1NPfQIMOmLdFdma7O1WFkiAU/JcRKXEchYj7M9Ff/relofJR0GZRtlu/1+U4yS2Rb
         RPug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765880210; x=1766485010;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2o1UHD6rxFAfXGsXQf7FX62t2MntRG6o2rCP3G4M0mQ=;
        b=FRhIkf2jX4FZkwokOmJF6JYkHkdxT2tE5ONZAKVGeeo/dZXKMOGcVjtaJaC2ghc8dV
         e0lnQLUSdYHIyQONqrFa31jl7/H/7xx9Y4ie8c6nAzjG16WoAoR+FZJLESODnGCrJsAy
         Yff5IssC1upH67e4JOmSXW0GzVsTu0+oVxZqngzHB7X2mmuUbHWS1ZVty/ex+d5rarF/
         VSkPw6lQ5SlEsevR1Tf+2yoTGGXW9m20lBlk8/sYqFXiy4EOkRy9bS3QA5W+8GfUyYQH
         FLtdT7tYrm0g9enucxD7xms4CGAl9iPKWb+wMogHlqiglrA5meNrQNUrSRQRU2c2Zw2N
         3v4g==
X-Forwarded-Encrypted: i=2; AJvYcCUhXPAqH2a20MLwQyxHa1JpSsQCvo+X0Xy30Kh/NPQlW9WvsnKLSop7eTyi6lzQGjH4bRVNaw==@lfdr.de
X-Gm-Message-State: AOJu0YzmtsVh7J9XOhnKy3wCVIzyjq9mzdMODwx9hYc8un7rZmLi8+aF
	2Bv2sUcDlfyoHAyk+2SAEjcww9yelPXXZ4TcAcJT3gS9AfCUpOy4B8vo
X-Google-Smtp-Source: AGHT+IHxDekT21xPgJrA4J5EmCfqPBtCXq3cv7/8ua+d0xbJ2ox6Qx7e/KwSnmjIq+kxypLvzkgYOw==
X-Received: by 2002:a05:6512:1191:b0:592:f521:188a with SMTP id 2adb3069b0e04-598faa97aedmr4795819e87.49.1765880209997;
        Tue, 16 Dec 2025 02:16:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaNARTRb1K69KgfNneQyuvlZ53p7SuD494apnjPJlLBGQ=="
Received: by 2002:a05:6512:2211:b0:598:f96e:8c4d with SMTP id
 2adb3069b0e04-598fa390e50ls1308823e87.0.-pod-prod-09-eu; Tue, 16 Dec 2025
 02:16:47 -0800 (PST)
X-Received: by 2002:a05:6512:3b07:b0:598:f289:6c9 with SMTP id 2adb3069b0e04-598faa2558emr4485326e87.10.1765880207415;
        Tue, 16 Dec 2025 02:16:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765880207; cv=none;
        d=google.com; s=arc-20240605;
        b=MNEuwIaybUH8249UgnD7Zo2F2iNQ+3JJOeaJ665a1wZx0Qe+ntyPyU5skhg+UJ2Wug
         sTcmVFDxCeNy5ecGJPbwpywzcBtpkx2HhalVbQhAuL7sGOx9MWYJo+Y9mwjPZynGZevc
         iEOHGCzTrm5BDDB+iWhhSw3qWMIN+LtPnFkvfWa+6d+4pxyY+6JJ3jdS9xp4kDM95Df1
         BWtv2mPj6tkPcibxjgSxnKpcIc42xmCcNSTrgi+qpwWPhJJd4WJVtXmYhOCjnwLhSTLO
         QTbJQJbgEMQmPySd6CvrjjvJNcAjGUP/634H0/k2QNgOrDHGXQ+QXg3SVQ7vmGlzfNeV
         Td1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=mIaoUkPmmOJUMbaBzFd5RgQ3q7rdKEgi166V60yfEd4=;
        fh=x2ubLsttaGNDEohungEU+QxSNGIjpxcBkXhQGHGw3fc=;
        b=JURU58I3F/nvXmsJRzswm8qEvtNFDd+Hbp73zvJ/BiRpsCj7jQbc4dEj5fIG8mem1B
         08UMoHrpRQLD8JhiPc0yKJ51AfrprWu5TNqjVAvK62MgjSVm58EGciojn9XRqUB2Qjc8
         RIRhBO3b+SJyachupdgJoeq9uDhEEEhkB1Bxa5nDf/5b9rMq5P78XmW8rjAwCjiunVUd
         l8HZe/aO0c6hgu8NPaH03RPyLQ2FD7yV1NHbzud3d+O9egAFavm9FWDMWgik9Hqmz0xT
         XhtfCNLeB0pNNXEdydYZ3abZLbe3OtkwXZ46A/rSRQmZXUsaVEpC8a2sfYUd7y176pRn
         DZ3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DBFfcqXM;
       spf=pass (google.com: domain of 3jjfbaqgkcucsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3jjFBaQgKCUcsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5990da111e6si35098e87.1.2025.12.16.02.16.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 02:16:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jjfbaqgkcucsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-431054c09e3so312523f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 02:16:47 -0800 (PST)
X-Received: from wmbhi3.prod.google.com ([2002:a05:600c:5343:b0:477:c551:bdb9])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600d:6405:20b0:47a:935f:618e with SMTP id 5b1f17b1804b1-47a935f64d7mr109743225e9.15.1765880206873;
 Tue, 16 Dec 2025 02:16:46 -0800 (PST)
Date: Tue, 16 Dec 2025 10:16:35 +0000
In-Reply-To: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
Mime-Version: 1.0
References: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
X-Mailer: b4 0.14.2
Message-ID: <20251216-gcov-inline-noinstr-v3-2-10244d154451@google.com>
Subject: [PATCH v3 2/3] kcsan: mark !__SANITIZE_THREAD__ stubs __always_inline
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
 header.i=@google.com header.s=20230601 header.b=DBFfcqXM;       spf=pass
 (google.com: domain of 3jjfbaqgkcucsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3jjFBaQgKCUcsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com;
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
KCSAN-instrumented via explicit calls to instrument_* functions from
include/linux/instrumented.h.

This bitops are used from noinstr code in __sev_es_nmi_complete(). This
code avoids noinstr violations by disabling __SANITIZE_THREAD__ etc for
the compilation unit.

However, when GCOV is enabled, there can still be violations caused by
the stub versions of these functions, since coverage instrumentation is
injected that causes them to be out-of-lined.

Fix this by just applying __always_inline.

Signed-off-by: Brendan Jackman <jackmanb@google.com>
---
 include/linux/kcsan-checks.h | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 92f3843d9ebb8177432bb4eccc151ea66d3dcbb7..c4c8e03e53459f5030ca33f9103a9bde49fd3820 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -226,10 +226,10 @@ static inline void kcsan_end_scoped_access(struct kcsan_scoped_access *sa) { }
 #define __kcsan_disable_current kcsan_disable_current
 #define __kcsan_enable_current kcsan_enable_current_nowarn
 #else /* __SANITIZE_THREAD__ */
-static inline void kcsan_check_access(const volatile void *ptr, size_t size,
-				      int type) { }
-static inline void __kcsan_enable_current(void)  { }
-static inline void __kcsan_disable_current(void) { }
+static __always_inline void kcsan_check_access(const volatile void *ptr,
+					       size_t size, int type) { }
+static __always_inline void __kcsan_enable_current(void)  { }
+static __always_inline void __kcsan_disable_current(void) { }
 #endif /* __SANITIZE_THREAD__ */
 
 #if defined(CONFIG_KCSAN_WEAK_MEMORY) && defined(__SANITIZE_THREAD__)

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251216-gcov-inline-noinstr-v3-2-10244d154451%40google.com.
