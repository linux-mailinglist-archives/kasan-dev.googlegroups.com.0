Return-Path: <kasan-dev+bncBAABBO7JRHEAMGQEEZW2PUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C037DC1D28E
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:10:36 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-7916b05b94bsf10856816d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:10:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761768635; cv=pass;
        d=google.com; s=arc-20240605;
        b=NJveVEo+ZYLxIW9Wdhui3P7/yrLQIzNtWRyTMMfw/fD5I2mKCWaMb13Lyy35r5QFRb
         BB9y8y9k5FWANVEZSqcIAfImraEDp83AQMGjRkOgCgjRE9haLYSbctf5C6YFU9u20S5g
         jE9RpPGuRx5u0gRenQGru9Cu4T3s2WnTRx2QsTKFPZVVlX3s9kvfYxyqZQvcKwh8s3C+
         zOryXZdieQL84rv7tPPp5tXxOLrsi3RVJxukiHz6t/aDqJGYa02cNTYfAtUeecC17PSy
         kkrwbguDBHJsl4Ch/MB71KiVJ7fVJM1Ch6JdYY8cEj78l9/Mh7C0BB3A17Yqfe/ADIkI
         Apfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=mdK9LRk+JjraDyE+/L84auGQXq/urBNsiw8dcQDq+IQ=;
        fh=jRgAcxWQe07xdDYVGjgUYghSZZF4dVCuOMt4ifzIXd8=;
        b=LY50lqlw/3sb+QMCOy+TDsIX+PKQ0Ge4ga3I7Qqk3w5lwgk65T7MbC1qIETlCHhg/b
         i0vYh/NR6bXc6RVA6aBBoojOLDDcc9h9QKZYWHu6OIB+pviCS9Fe4Bi1nj2/fnf0cxco
         F39FM4d+5R0Naj5lB/Pq0gsoZprIikEpn9YU9pf8SFMWLAGceM9VhDSAFdZup47neGp1
         wbQMXjvxSG1xo/i2gGediINZ/PRzwtdzIeRw+BPst25f20/RghOo9oa8MCsIeK13zW2v
         snL8klkj6DKuZavTNTl/kmmslJO6kJCL0zZ/52DOtwr2wLhpzcHZVqb+hRIfddaml98r
         KLrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=IAf8Yf83;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761768635; x=1762373435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=mdK9LRk+JjraDyE+/L84auGQXq/urBNsiw8dcQDq+IQ=;
        b=UXLIQL9VrJygM+7sChSHXyVfH2AuGM9B/Ix7FJPUdFXyKM0AIJMqLz5Tj3v1aL0etz
         wimJ6sY9tK0wmvqoiLpoWWwUXAhGb5NPFtDWFrU42MxVSpUoYx2i8HL2PNAJdQpM3bcG
         nuVDhCQNaeh5cteq4O9HibmUgQYmpRuQ8ezTe3PD1XcEXgIwArVt2Dc+A4N+iSXwJHCF
         WNpkUBPGgFa9v0odvbCmpPnk+F8xF8PqQMtaw2hZFlfAPKRRfLo6fIiRbgGRyrULhW7U
         KaRBtI3u9jgeq0eCqlX0QZKmQEAjaRdiJomT4NEzdLkUBtSFAjLeSaiKrr9f2kSB1y/B
         U7pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761768635; x=1762373435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mdK9LRk+JjraDyE+/L84auGQXq/urBNsiw8dcQDq+IQ=;
        b=L0Z8VK2KX9TBeJcrtJDQQRY9jaBirvB1Jpfsul9cGE6WBaG6OzDkbrso73mnQF2hwF
         0S08eX2nYHA5rCy1f2Ua5IFbInwSMBdMoARHFyGUvfQcAzcPG88nILD2CtWynewIAPXX
         RPiK8QvdmXOWLvnhljPv8S0QTRMxAbvMFjpnciWbOqhKb997tBLbhrWBakP/Y0DwT2mo
         oZPdFBo0ni532qwVgdey1/SaMJugri5k9S3Cx5+qXHfKgDp1djfs3SJWB55f5gorzlQB
         WcGRe4mkMUvmYyDh6zclJHFUucTuesdAoE63hXfheW3nOCfpzqGbOYlnkLfA95X1c0d+
         LkxA==
X-Forwarded-Encrypted: i=2; AJvYcCXmSntZa6wQy8PSf8SYpXN0NMT+7owJBWfLSUdg3HJaAUQMlGMysDetBDvNXDlt88sKMZFxlg==@lfdr.de
X-Gm-Message-State: AOJu0YwwVhbYz0kFfwxzadG1T7kCNmH2JHW4SmO7rsks0yvaJGWrrsBs
	e0N7fJanHa7+XzEPdIB6Bn+uUGbu1072u2J2Nvrpn/jetZOa5HzD1EUr
X-Google-Smtp-Source: AGHT+IHAshHxrtQVGsX5YKhEmps1V4NHbefgotOH7mzRchTScriR/RdUXDRAPyUDXS1dRcX0CcQCZg==
X-Received: by 2002:a05:6214:268f:b0:817:448e:b12f with SMTP id 6a1803df08f44-88009be74femr48976136d6.35.1761768635593;
        Wed, 29 Oct 2025 13:10:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bT64eCThxyrCUY54n7Xa9cngPA0ChKlNTUNznswBz48w=="
Received: by 2002:a05:6214:5502:b0:87c:1e10:ae60 with SMTP id
 6a1803df08f44-8801b245554ls3612616d6.0.-pod-prod-06-us; Wed, 29 Oct 2025
 13:10:34 -0700 (PDT)
X-Received: by 2002:ad4:5f87:0:b0:7eb:c8ca:c137 with SMTP id 6a1803df08f44-88009b7155dmr52522366d6.29.1761768633891;
        Wed, 29 Oct 2025 13:10:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761768633; cv=none;
        d=google.com; s=arc-20240605;
        b=i85AaBd/hLznwPgWuj7FE5OxNF1L7QaJNKaUfaVmVozzMSFlh71byFiKT7AQ7WD6v0
         NXNoZTBtcCHZ9RLHfHQHNDg8+Tn4zSYd/TRdRCEfT3fkY+baHZaFzUm7SNonWj7JI/Ih
         wbT03O1SLExybR5AJJP+sjjjKhEQ2IGEKcJhe2ZkrHxqiU19yK0/QrFYpLVc3ytyr0N+
         g1r48Rmcfssh0dePm4J2nufMhiql7QosmZNXK7wKvi88zMdqZ+hq1rfwUM/xAqr+11fG
         1l4rTn6mj5OXyQL5RFryFZhsE7bANymFTFvKio8iBGbsmUs2kjjBC4uw3ArL8rSbi1tj
         KRYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=S2a1Kw0sC3CsXwE/Uet1J3QooijcrYchVxhPMvMQoO4=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=Tvp2WPdEtHpVcOxl4KLlCVJtvQzSHNkcmeBNQ0+Lo0/L5ilSrDKsGv2mdFs+2Rd3lk
         crV8gjYIj61CYdDoUnXSgy9JiG4pahDwdOabSCl2GIMMGltyQMbYEflJSYqkiH+XNoTg
         tm6wM2aHIj2YYdupj/Xm9+PEMP36YFq4MFA6dSe6H76+KdntvbFa5VVlK9mn/CgzYNEJ
         vaxGtx7rwJIAGQeb/0TFtL4BjdD9HM5w9S5zZkE55apthgEvbay36Abexxuutagk6I+g
         vib1sQMiG2RUN2ENUJRY1VyFPxBQNkCpxZqbStDsgyeQN91GOCeNYwZ44ulGdfrXhBt3
         BEEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=IAf8Yf83;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24418.protonmail.ch (mail-24418.protonmail.ch. [109.224.244.18])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87fc65ebd63si8024716d6.1.2025.10.29.13.10.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:10:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) client-ip=109.224.244.18;
Date: Wed, 29 Oct 2025 20:10:26 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 16/18] arm64: Unify software tag-based KASAN inline recovery path
Message-ID: <0a21096d806eafa679798b9844ec33bf8a5499a4.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: ab91b91b5b8eb35edef4ae212700531bcd4f5e1b
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=IAf8Yf83;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

To avoid having a copy of a long comment explaining the intricacies of
the inline KASAN recovery system and issues for every architecture that
uses the software tag-based mode, a unified kasan_die_unless_recover()
function was added.

Use kasan_die_unless_recover() in the kasan brk handler to cleanup the
long comment, that's kept in the non-arch KASAN code.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
Changelog v6:
- Add Catalin's Acked-by tag.

Changelog v5:
- Split arm64 portion of patch 13/18 into this one. (Peter Zijlstra)

 arch/arm64/kernel/traps.c | 17 +----------------
 1 file changed, 1 insertion(+), 16 deletions(-)

diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
index 681939ef5d16..b1efc11c3b5a 100644
--- a/arch/arm64/kernel/traps.c
+++ b/arch/arm64/kernel/traps.c
@@ -1071,22 +1071,7 @@ int kasan_brk_handler(struct pt_regs *regs, unsigned long esr)
 
 	kasan_report(addr, size, write, pc);
 
-	/*
-	 * The instrumentation allows to control whether we can proceed after
-	 * a crash was detected. This is done by passing the -recover flag to
-	 * the compiler. Disabling recovery allows to generate more compact
-	 * code.
-	 *
-	 * Unfortunately disabling recovery doesn't work for the kernel right
-	 * now. KASAN reporting is disabled in some contexts (for example when
-	 * the allocator accesses slab object metadata; this is controlled by
-	 * current->kasan_depth). All these accesses are detected by the tool,
-	 * even though the reports for them are not printed.
-	 *
-	 * This is something that might be fixed at some point in the future.
-	 */
-	if (!recover)
-		die("Oops - KASAN", regs, esr);
+	kasan_die_unless_recover(recover, "Oops - KASAN", regs, esr, die);
 
 	/* If thread survives, skip over the brk instruction and continue: */
 	arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0a21096d806eafa679798b9844ec33bf8a5499a4.1761763681.git.m.wieczorretman%40pm.me.
