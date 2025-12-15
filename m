Return-Path: <kasan-dev+bncBDA5JVXUX4ERBIF677EQMGQE6JJQOWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C164CBD535
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 11:12:50 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-37fd65cb85asf12972771fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 02:12:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765793569; cv=pass;
        d=google.com; s=arc-20240605;
        b=RsIDAT7Dfb5ibMEhSVSy8HVhCJ21NdRSOQH0U7XUwhNVddC5lj2igAxA7yNKoADMdu
         MrRmg5DVgh91wJ7ggrOJg2duiM0yC3rbYxrgWhRuRzlYjuB6FeU/21j9GkYR1cJwz5ub
         DAeMBu0MxFTbLpdkJ6dG468lRVi3jHtaYJErzoi6Q4rwDi2uI8lSQc2JewsY2gmRmfor
         j+SDdTp/FDgyTFZ7YAnzhvmmsp+ps1x8dhC+7udNxS7vXbUgDDuGSCuclFZHiXAzQwpK
         h57Hi6ROFjBmvTtkZLs3xSohmf7k6KDxJXOQT82WSKopKOsNaz/8s7rm3cA/OW1i5XSr
         eI3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Ev8yPdoy705/ntgnNgP2yQIWzOyP2oU/sb/K5jzbCMM=;
        fh=0AQA0bv1/JMqqH4nvqeQOImwVDYq81E/6n+iVIbll4k=;
        b=ls5k19prcNi96kOaZa+cle/lhLPZL+zNQWmTT1OTeTu1vNUW1m4NUgL3oNGKEneI6G
         jxnpfvrCHCHPc10kohFsm4TuO46AkqzNDS6CEyAmuLwapdkxo4+ItHqJ+znv7Q9XFQ2D
         zOKTbJvLAMSXSQ/hNYILVs9zuUggkgw7R9s+dtxZgFSLjqYDEbwcKvYoQi5IOfyBbqKM
         joQE3YcFPiZs6qjW1YuioG7RY7DQNzpCaRw+AR3QAcxVHBFYXcYzQOZVJUhqB9fKhO7r
         1wumGduqjmnYOZp9uX7VnWpTNNb5lhTzD7VH+pP43IngMUUoHqqM5ZVXcumVEaEdGbsr
         XLRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MKNagVIN;
       spf=pass (google.com: domain of 3hd8_aqgkcswriksuivjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Hd8_aQgKCSwRIKSUIVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765793569; x=1766398369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ev8yPdoy705/ntgnNgP2yQIWzOyP2oU/sb/K5jzbCMM=;
        b=dM7CD2B638fzs5RDyWW73/qN9lwyDZJ4iTyUacMBhji0a2d6Qn3Ezs7DkKaEzBogIO
         RhNhdtSSoBaux9z4uA/+ReJQKMHpP9YqJQGduexrVwJTKCSxzDv70mLRln6lI4NX9Ff4
         g75XHBuU3YP/6pU2onNZDfAX4DuHUk2xTC/cVwQJt+NgZUocL4YzPEGEX54xMGaPVxIB
         0tSbk0HDZtlBT/mXrRVvjGab0BYMPX4a1Gy3RfOoHZynPoIaawjzJPjSAKYpeaORJGyU
         mp6JN1xGHKiEl/jovGWTdrlnVIFgtw8xZsaNaP0LtTx1v73a3GXL/xMa4ahcbmPsY9bT
         Qiww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765793569; x=1766398369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ev8yPdoy705/ntgnNgP2yQIWzOyP2oU/sb/K5jzbCMM=;
        b=b1dcaCRuUyBW+KXq6lQ3vMoSLN3G3O/ELlEoCCRdodpvXQY44Xw/WlbMkTUOY7yEX3
         0xan6uRnnetFX0X8t2kYPSNU7KdXytCNNmc1W+RY0Us3sO+cR9nKegNUbtArkoktnoLH
         RQCqhOqBYEMzpAVJqyLJa43VcbLjg0jEFTaDFNzr1vxB56Zdlx1Ef09yaawp7ajKHvtK
         Eq0oJqLvrjDpEmJTOv2nCDSIYLeJIyT1yH/qFVhVuunlGu5XlMTD7BWx7nbS5KIVeKiJ
         3oKe4ZNOlddFzqAiwlCLp0DLK7+95vxBMZJGJJDsmVj8csu25qsyS5HKbGZH+iyWWqsL
         wzgQ==
X-Forwarded-Encrypted: i=2; AJvYcCV2I/qeFaClUYVNWRpZTz+2g+fBzykRADBnBIjokfiKChKdZJCZf8K3nwqBxoclOINF7OacYw==@lfdr.de
X-Gm-Message-State: AOJu0YxyQMvBTahgO4JUMeSjGpvbXSM27jcXNdy+i16tDKyXY7eiDkJN
	pW3X/1VLQPIDZVlT4QnuZ96kZwgHSTHyEXJw0y45TIXtMHubssdnJPpY
X-Google-Smtp-Source: AGHT+IGU6M3HZO0YJG+d3Xz6iBbdStCQoAReHCYj6EcJbg7Yg8RuttQb+Z82oLeUmBX4d9rQD0xilw==
X-Received: by 2002:a05:651c:19a6:b0:37f:c5ca:b722 with SMTP id 38308e7fff4ca-37fd0725b38mr29426031fa.6.1765793569219;
        Mon, 15 Dec 2025 02:12:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYu12yQWYRwr7kdZhemdM6vrXnhOZOIEfled9hxgTFE8g=="
Received: by 2002:a2e:9793:0:b0:377:735b:7cbf with SMTP id 38308e7fff4ca-37fceebfbc0ls5418321fa.0.-pod-prod-08-eu;
 Mon, 15 Dec 2025 02:12:46 -0800 (PST)
X-Received: by 2002:a05:6512:1154:b0:598:8f91:a03e with SMTP id 2adb3069b0e04-598faa9a579mr3713230e87.50.1765793566475;
        Mon, 15 Dec 2025 02:12:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765793566; cv=none;
        d=google.com; s=arc-20240605;
        b=Z3flGEGZl0Ery+p9eH10yX6Hqupyey30UI2U+os38PpOHL1yjHjDCWKytgZ9b+S4OY
         6hT3812U4QMs+8UYYngM159+O8faHwZQZnxS4KTepkZSqVxIi6bdVeuN8Bs39lIt1g9E
         +LWbMAZOTc6RAhm0poLfK4eNNAV8NT8nAQuOaXYMVt1e1UboKa/OZg99puqD0wVBlGT1
         BasxrKF9RYeHz8WdyttRobFkDEDoTXAYzG6jOkoZ5ghMDKcP6a51X4fwGA8rp+Dt/5fV
         TMZCCbCuByoab3UAj3MdD8N6BXlcsjLSMag+AhwmMx1rXXsIbpH6V5gtoIFJrfOmuuGE
         tgAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=bshBqgsRdcmZdxF7GIqf7PfJK3Mj7lfZN/mjH8j2lVs=;
        fh=61XVfOX0mCGReeZztWfTUJNvZ+DGfh5Hp0WwR2VbiWQ=;
        b=LWcZtJVsy6+qOVZkT/BQpscCnwOWGRrf8gq5gTv9j0GVR9uGaGGpH8W9uSkpUjByrp
         SumScEf0pNz7Sev2H4R3dyXjiR6yOfsGXdjWWVbsxj946Nz9BkaEDLDiz/qYS7PJOrVb
         7d5QxNOJ9dqQNrGkE+HTUF/J31dWLmcKcoSdm5c7+QO2BqnlceBEETcnqcDZf8P6UfdX
         ifI9qvcYewv9Wl9IJ2ge1UmljsMBao5QLUg48j+Iz02q1AcugCCHwBkYNVi+sGqsK4kE
         dKQmNQXGlqlnFMJrPYhSxNcfFagoepXFJm/u4MB8PUXEAXEhxCPYh4jTdsputtfDNCC/
         bxvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MKNagVIN;
       spf=pass (google.com: domain of 3hd8_aqgkcswriksuivjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Hd8_aQgKCSwRIKSUIVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37fdebecd1dsi1227921fa.1.2025.12.15.02.12.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 02:12:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hd8_aqgkcswriksuivjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-477771366cbso24057405e9.0
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 02:12:46 -0800 (PST)
X-Received: from wmbgx1.prod.google.com ([2002:a05:600c:8581:b0:477:9856:8f53])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:4f84:b0:477:7b16:5f88 with SMTP id 5b1f17b1804b1-47a8f8a7f7amr110860185e9.6.1765793565696;
 Mon, 15 Dec 2025 02:12:45 -0800 (PST)
Date: Mon, 15 Dec 2025 10:12:40 +0000
In-Reply-To: <20251215-gcov-inline-noinstr-v2-0-6f100b94fa99@google.com>
Mime-Version: 1.0
References: <20251215-gcov-inline-noinstr-v2-0-6f100b94fa99@google.com>
X-Mailer: b4 0.14.2
Message-ID: <20251215-gcov-inline-noinstr-v2-2-6f100b94fa99@google.com>
Subject: [PATCH v2 2/3] kcsan: mark !__SANITIZE_THREAD__ stub __always_inline
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
 header.i=@google.com header.s=20230601 header.b=MKNagVIN;       spf=pass
 (google.com: domain of 3hd8_aqgkcswriksuivjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Hd8_aQgKCSwRIKSUIVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--jackmanb.bounces.google.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215-gcov-inline-noinstr-v2-2-6f100b94fa99%40google.com.
