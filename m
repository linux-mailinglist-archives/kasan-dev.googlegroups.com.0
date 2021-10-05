Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR7A6CFAMGQEIK7UUBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id ABB35422432
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:24 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id w26-20020a056808091a00b0027630e0f24asf10603811oih.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431623; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lx8H2q2GIwVZg7KwUzCxYQXIwhXfn9K5IbG8TB40RdFlm4myhcFNEeOVc/rNfPzWVO
         XagJ3d5LybANUt+XkEhd1bZtaQKQEOombIZvmMcSiwhE8sTioohkVMQMrNqUrOgrRXD7
         8iq9gHG4fPj9D+AUmc1wnqIeJPw6dUAWNiJyPTwawUv9k/3i2Qql4asko7crnP/P+8GD
         EU8KHgmw5rbxxN+wgbGbv0e67am2Q42+WvLv20taIcX+ApiA55NZWrQG50XS8N4+f7aT
         eqF4BJMfCgDXbjezMaVRMkmjsFu2Sk4JErukFm85cKHK4B1xMO+GvWIB6uv4MLmk5IOn
         rs1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5g1OTu9N3PcL8oTPz4R/yVtZhsS1ny/khlescLpVGY8=;
        b=KVl5DqwPuyrdN0YDtpFjQ4pqhcOI+FEUdS+mhVs56nCmrmuYbiigVF9f9NZT/h+4O/
         PT+3gmRmBJOwYAu4IE/KrF0W2I+d0Bz/V3+SUoOgyeqSSeNbXLcSvQFZrvoYb0kT0GDn
         moGCRmqPP05vjAwT0UbKAmfrW1UKVy7PZeBN3WETQL77g5Fcd163Dm8VxQhw6Hvk2RuN
         IvS/8V1LdusYiIrxYnVF+FSvA7+xiLWlrMSoedv8QTn6eSKVTMOmB7hHifaoaYs34jOj
         9tQE90GpNJHooSLEhPeeIVzIJ6hpDTmwztbBH6k6YGeLxaOmEx5mXViGDpZs7RQRbqRY
         mg3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BbV5uAK9;
       spf=pass (google.com: domain of 3rjbcyqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3RjBcYQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5g1OTu9N3PcL8oTPz4R/yVtZhsS1ny/khlescLpVGY8=;
        b=l4U+4kZT9UzjW+iMF0yAoL3oKeCmNM62xJm9DSmVP0Gv3Vo8HayZ4PaHSGAZWTlA3a
         qplg+IxHrKnlT60xajYCBVpEWJLUutDK33Mlqj2O2wWg+o5W0N7CV3f5+0+pHOc3onuz
         nhTR5Fv9menKYfx1YpCo4iDJyhN5gjArnWMJ4/Cxne8JsG1nAsiUAeZ8UjFMXIGuA2FJ
         oMe7mbAvLKk5has1sMKB0ai1qrUuGflt4bljOYQSzQsZK0zn81O+x/gsbW4z6fcC1xa+
         p6DbdFsIHH8ZCokVf1O4gS/CZ9odMTasbw+wb9JZmzyqM8y9yuLooA+l1FDfxEA/4aNP
         HVAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5g1OTu9N3PcL8oTPz4R/yVtZhsS1ny/khlescLpVGY8=;
        b=Zh2nDZoXKIqzgJkHmd+sbhZ/EP6WZ4OQmv1oZzGWzdISnBffdRFjTEdbSyX8XsuqVL
         dASeXCMPF4+2/6tDUsETefpeuKt9wQ56lTujxAbYcEGG91BKgS1jfkf0Dw5nD8R2iKLn
         +cQHyig714wqyTXl/qf9IoLXhOyuLp0o7i9lc+CFcR1BH4/Y6DoYxrYp27pD0iFSzpZu
         BDhwq2JZuJ4bswIYXoUr1iup56kEa03Fke09BDejkVDronDzOLs9gxlstEM2SIiKuUZ6
         D41ObTX82qFfop1Av85B2EWJEzB+sQi/qGmb511QfxpnaT9rTTe6bdJgIKgshjjJL/0B
         IClA==
X-Gm-Message-State: AOAM531HYtmNYq2UuGedqbvlvZlMP/YBbSZCx4XOYQEPf6u5tbWTSz6Q
	P+cEQHEMYPHhJ/+QgGobIN0=
X-Google-Smtp-Source: ABdhPJxFyjsafOGnRsZLzIp6FTQ6zamZMbHBltUr07BimiXqrxLJC867WuwdtBsF3MLJ23NlkEgLnw==
X-Received: by 2002:aca:190c:: with SMTP id l12mr1863143oii.103.1633431623667;
        Tue, 05 Oct 2021 04:00:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4bd8:: with SMTP id y207ls5783489oia.1.gmail; Tue, 05
 Oct 2021 04:00:23 -0700 (PDT)
X-Received: by 2002:a05:6808:318:: with SMTP id i24mr2007800oie.60.1633431623353;
        Tue, 05 Oct 2021 04:00:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431623; cv=none;
        d=google.com; s=arc-20160816;
        b=p14GrcwXBlgpSbzNmNaMqFI8aIBGOjI5t574pXU7rKamzd9WdMGiTppR7FO52GIkSm
         OnJzloYFwlioxNxx/YOC3rt1rSQ58IQRLbyECTN8f8dWDKzcO+4QCs1VpvbYkfC9W7gy
         YLIqg0rIVFLPVO8pdcx/0ivO9mdDwvvk5/6tQz4IrseUTiJmYLzFc5x7apPr4jjTfMbx
         kyft1CGU45bhtAmp8w+wFPPnY6I8s0IEvtUJ5pVH7CnFHukxJovV8AVlFiWcQhu4ZK6C
         ZUbpeAxytKWCRScedtFWNroUFZB2IsM3GlQ9L2rjqN0igCq0qCr8CNzV/iTaXBHCbKaG
         /Mdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=aJbTcuURS/chesQOBDsBj7S41hJcRc/zL/qDV/Um5us=;
        b=wCc2VYxjFfOJ+rrQsSEHwnuOSXgUhhTglsqTaPBU+ef5oXarKHVL26ptsm0VMCFuM5
         zq7cvrF61xlw8r6ghWNRYaWWHUl3SZTJ1UwWsRyHL04MicCvvH9CZTkfwu2SC7yAVAJk
         7ESP5PtTjXzADmSSGwGXc6OhnV8iR+XOOrtsXcXgMu+NAkeCFUp4p/65HSxihuSLzJsO
         wdU4ZCJGrndT02fmFPGBzTiGbVR1q8cVuWsEIzNSRHu/9je+65V2e/JjTo4A1lj+JGFG
         8aBMpWNDmrUCV9u5kryTUlQ/eG6263dp/j+P4TWAW0xhpUyJAGGB3neh2coGoVxihHWa
         mtmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BbV5uAK9;
       spf=pass (google.com: domain of 3rjbcyqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3RjBcYQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id m30si1737753ooa.1.2021.10.05.04.00.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rjbcyqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id r13-20020ac86d2d000000b002a755d36425so487485qtu.14
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:23 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:6214:1022:: with SMTP id
 k2mr27294558qvr.53.1633431622928; Tue, 05 Oct 2021 04:00:22 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:59 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-18-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 17/23] asm-generic/bitops, kcsan: Add
 instrumentation for barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
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
 header.i=@google.com header.s=20210112 header.b=BbV5uAK9;       spf=pass
 (google.com: domain of 3rjbcyqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3RjBcYQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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

Adds the required KCSAN instrumentation for barriers of atomic bitops.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/bitops/instrumented-atomic.h | 3 +++
 include/asm-generic/bitops/instrumented-lock.h   | 3 +++
 2 files changed, 6 insertions(+)

diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
index 81915dcd4b4e..c90192b1c755 100644
--- a/include/asm-generic/bitops/instrumented-atomic.h
+++ b/include/asm-generic/bitops/instrumented-atomic.h
@@ -67,6 +67,7 @@ static inline void change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit(nr, addr);
 }
@@ -80,6 +81,7 @@ static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_clear_bit(nr, addr);
 }
@@ -93,6 +95,7 @@ static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_change_bit(nr, addr);
 }
diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
index 75ef606f7145..eb64bd4f11f3 100644
--- a/include/asm-generic/bitops/instrumented-lock.h
+++ b/include/asm-generic/bitops/instrumented-lock.h
@@ -22,6 +22,7 @@
  */
 static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_clear_bit_unlock(nr, addr);
 }
@@ -37,6 +38,7 @@ static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
  */
 static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___clear_bit_unlock(nr, addr);
 }
@@ -71,6 +73,7 @@ static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 static inline bool
 clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
 }
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-18-elver%40google.com.
