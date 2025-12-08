Return-Path: <kasan-dev+bncBDA5JVXUX4ERBSGW3DEQMGQEYHGEANA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D6BFCABBB5
	for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 02:35:06 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-647a3af31fbsf3961412a12.0
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Dec 2025 17:35:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765157706; cv=pass;
        d=google.com; s=arc-20240605;
        b=edJvEYk0G6n5jne3j2XOLNH28WVI9jKUC+ey9pKO7wwpSheFDrCVNL4xcdGosRENAR
         h/Nz6CwWLt1oEsuo1pq5mhZKlw7JUI1ZH9vIGa+SgK1eWcqUw6p7m28DwU3z1q9gU1cW
         Tj9VkIiJvSzuKxOaqy8dAQqIqAi7N6DhpMYY/eRpCAYaQC2y/z/hfgiAi720Khlooj51
         WBpvB+vJic0WD3pdgw9nua2jd7FIzmuuzl2d0/aYOMWpgOt46FQ1GS+/qfzrVbp+rUaD
         vQpZIi9HTA0Q/ofKxn0KLoEp5rpS75cvQ86FxABImdTToQYSaTrVaDiSO9BRJoQaGZp2
         r6HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gqBVrKEcIfNkAiq2pZ/1liXqGxpKjXrmIunLKj2+uB8=;
        fh=ws+4iGZ1JYGUcNvQbxc59FnqDsDF+3ud/+IATTh52d0=;
        b=hs+M7dKpWht8teAiszgj6brnLGZDAOGOFrFoGMHph7J4qfCOpu0sskVkAFlIxyj8It
         wo0F8VLAoOJZC72O2iR+5VNnJ9KPzZeXexYdjGCVoiTyTZ3uEn7DMbESzz3h+wF/S+qw
         L1L67BG+8FdeYZxMGKMN/rOYuzPObRe8bNHAdHCQUC/CAYCi938N5NlhM49rFy3Pj/Fo
         aTQW1AEfbE0TZ6xwDE02nigB6KWoHi9BTCU0Fgb7oN8aqIgNlJ4g1i2K36CGlX0VAlCo
         oq33Xr8xvw4wtXdkAJNCP8gA/dBOnfycNty2Z6Da7uh00l7hbo8nLKR3L9K/VMzVvo6u
         fbhA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nM7aZp3S;
       spf=pass (google.com: domain of 3ris2aqgkccuulnvxlymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Ris2aQgKCcUulnvxlymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765157706; x=1765762506; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gqBVrKEcIfNkAiq2pZ/1liXqGxpKjXrmIunLKj2+uB8=;
        b=cVKovAoCTTKNDOAztXsoI9VmfpikfVDKGEdT2UlQDNp1lCIMPkxdOPrRc8YSJIVD0x
         3Vapi+XDEfScWDqUG3+NuNLZkMjquFamKORXfsarifdQhLdO7lhZQ+NgFj8sHK2nh37X
         hyqMKcahfbV29mNsnfdmvq+zY6AlZvKfrZww2P7SfoScAdEq2gqDAhnaW224MvW/j1ZT
         0T1STAyIr5NQkp+yysWNV44E4pNlMokeFg5hJOdcjz9M8MGQap6q6Gklzpzsy0TWsjCo
         34B2Dw6tqh3FDW5r2FIjnmSXCWCqg97kAo4G7670X6hXO0YfFTQrLNNYyeOBDElUVQ03
         15Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765157706; x=1765762506;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gqBVrKEcIfNkAiq2pZ/1liXqGxpKjXrmIunLKj2+uB8=;
        b=t7vw3PFcci/14KuppDK88ROt0tRn6hvlxMScac+7sHERVcUKUT4KsgTgQONc4ufCNO
         okX+fbIHS7wwqAE39SEkGacW6ZO2IvTys1atxlHXbBhvuDMt7UTsbDqISTdhbSdl7b7g
         MYLayIVpVO0ENxp61bpApYkC/AnjhLz6c0jZBJpB6JY11F7XaTyHz464NJEXVz8Krl7v
         Nt8DCxI4EulapiBrgT4D6cAnhmIEp/wbB1e5ElugepoXPEHCKDePdllS+tWUi1JBauP3
         S7VIOFR//xMlWcQJ/1bqa7WIYkSVPoR8gySZ06KgOxaVHnNQ5wRF5vSgk/1tnW3kcRZf
         kobw==
X-Forwarded-Encrypted: i=2; AJvYcCVxrMWM0cjFS/55q4HIqBQaz3NkVxrHeug7XgA19WleCziyXqlA7XDXFszlt7ATFQ/8kI6CpA==@lfdr.de
X-Gm-Message-State: AOJu0YyqjUB4ZuQq9UkcDeiGZz5xXeSCf3ED1HWUIkV+6oQe2qWJ9KLb
	hlvppW0gAFvx19Dm8cmzW8lixGhSH7cfh2qhptx6owO7zverl6Ote4Jl
X-Google-Smtp-Source: AGHT+IGIxO/Cmy9D3/2ZQr9ukqD4r5YkVhvG6anPqd+iBzb4sCWMZ1yyJjzkRDyLWfHDoV/LGmu07w==
X-Received: by 2002:a05:6402:460d:20b0:649:2347:e15f with SMTP id 4fb4d7f45d1cf-6492347e1a5mr3137899a12.31.1765157705523;
        Sun, 07 Dec 2025 17:35:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaENXyPfGDqcuP8ci6R6z7hHjFoxh0SnuUN6R9tQSl1Jg=="
Received: by 2002:a05:6402:f15:b0:640:ad82:2e60 with SMTP id
 4fb4d7f45d1cf-647ad5b23e8ls2973356a12.1.-pod-prod-05-eu; Sun, 07 Dec 2025
 17:35:03 -0800 (PST)
X-Received: by 2002:a17:907:3c93:b0:b40:8deb:9cbe with SMTP id a640c23a62f3a-b7a243058f9mr547599666b.2.1765157702846;
        Sun, 07 Dec 2025 17:35:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765157702; cv=none;
        d=google.com; s=arc-20240605;
        b=Gmzi6leq+Cs1Mt5HATFxkzxCcAW0QL0EanrtKIW2nYRooSYTEYwtRl9wfPdtl+UxnB
         H0j9fdBWKBVns1133UDyX3Fhdix9RDZWNRKLh6iMvhsi3cikngemzWCzjxc9uiHcmedw
         LoXdYkvcix5TdFhQWX3cO+9hyFQpAoVMv9ljD63SlQmRLUSq5G/I5l/+ywX6JBqYWMnc
         5Vfe8+BphgA+CQPwSGd+mmfkOsf6AXkvRcaFoXkjWcrO+NNdE4fr70dL7Fn/RbJ2Cob/
         7pr6U2T8UcvYxIHoBXEm1oeaadOk3+7vA3pv7hBEMmFcXU9o/uU/IbZqHq4InfJiyhQ8
         OG0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=p5d1/KP4GxMhsEhwScdwPIgTBK+KcZfvdYekHvom6ic=;
        fh=61XVfOX0mCGReeZztWfTUJNvZ+DGfh5Hp0WwR2VbiWQ=;
        b=kmBVmEq1+emEYBb0Jq3FIvWWO15VQP7jrBI3oT9uNbhHUe2vLW/bRZKTjVZUq/IrCS
         sOCguxT0mq8QsE9x7FaA6qmF9cfFS6tmXsxdujtqESeuLEvB5DIX1Nt7A2qll1U7JAyB
         XPnEX7nC15haMEU2BFNjZrPQc6kfSQVXQVeTXA+8YaY4yeRFpp3pFT3bH+lEY2JMv9KU
         I9WgSi0E2JLu2zFOE2JqDh/+/a/pb42nfnpiV8cyMLX3kS3k/1PLxmmDdsgtuImGTAT0
         wY71XmdCHSV8QAaWNKnqMjYjKXY0rTIzyw5eRHJMX/VCbAtRwMJGzOI9C/p7xTxywmFT
         SAGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nM7aZp3S;
       spf=pass (google.com: domain of 3ris2aqgkccuulnvxlymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Ris2aQgKCcUulnvxlymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b79f4936304si22066166b.2.2025.12.07.17.35.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Dec 2025 17:35:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ris2aqgkccuulnvxlymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-42e2b9192a5so1890356f8f.0
        for <kasan-dev@googlegroups.com>; Sun, 07 Dec 2025 17:35:02 -0800 (PST)
X-Received: from wrno14.prod.google.com ([2002:adf:eace:0:b0:42c:c2d6:29a])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6000:2f88:b0:429:c4bb:fbd6 with SMTP id ffacd0b85a97d-42f89f48525mr6497770f8f.31.1765157702413;
 Sun, 07 Dec 2025 17:35:02 -0800 (PST)
Date: Mon, 08 Dec 2025 01:34:59 +0000
In-Reply-To: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
Mime-Version: 1.0
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
X-Mailer: b4 0.14.2
Message-ID: <20251208-gcov-inline-noinstr-v1-2-623c48ca5714@google.com>
Subject: [PATCH 2/2] kcsan: mark !__SANITIZE_THREAD__ stub __always_inline
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Ard Biesheuvel <ardb@kernel.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Brendan Jackman <jackmanb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nM7aZp3S;       spf=pass
 (google.com: domain of 3ris2aqgkccuulnvxlymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Ris2aQgKCcUulnvxlymrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--jackmanb.bounces.google.com;
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

(Note: the GCOV isntrumentation itself also appears to violate noinstr
in principle, but it appears to be harmless - basically just an inc
instruction).

Fix this by just applying __always_inline.

Signed-off-by: Brendan Jackman <jackmanb@google.com>
---
 include/linux/kcsan-checks.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 92f3843d9ebb8177432bb4eccc151ea66d3dcbb7..cabb2ae46bdc0963bd89533777cab586ab4d5a1b 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -226,7 +226,7 @@ static inline void kcsan_end_scoped_access(struct kcsan_scoped_access *sa) { }
 #define __kcsan_disable_current kcsan_disable_current
 #define __kcsan_enable_current kcsan_enable_current_nowarn
 #else /* __SANITIZE_THREAD__ */
-static inline void kcsan_check_access(const volatile void *ptr, size_t size,
+static __always_inline void kcsan_check_access(const volatile void *ptr, size_t size,
 				      int type) { }
 static inline void __kcsan_enable_current(void)  { }
 static inline void __kcsan_disable_current(void) { }

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251208-gcov-inline-noinstr-v1-2-623c48ca5714%40google.com.
