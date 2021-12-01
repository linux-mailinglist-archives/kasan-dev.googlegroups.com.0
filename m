Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFNIT2GQMGQEX72435Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 8724E46518F
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 16:26:13 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id t9-20020aa7d709000000b003e83403a5cbsf20656458edq.19
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 07:26:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638372373; cv=pass;
        d=google.com; s=arc-20160816;
        b=QJO/t0PbqLSJ0mr1ugx5zgo5Igkew/iHxni5Ad26CRU6H90Hc/vCJBp0s9JR7rlB1p
         tAtMI93UTbDQokEP7GvwzDAafBe10kQ28oUDdPK2nryUyG41JAI7I5/FDzlNt6OWrZXG
         1HF0qPRNjjKGXnBCAoFA5yyMraHcmwCK7+1ykf2m81v7tNfckh9SRYxuVMrrL9vnGYoc
         VbP3/g+yij2/S3GDpQA3VIyQR0PwE3MQtANi6QtYaC7klXl0aCSxxd9CDuhXJ4bKD0ob
         gE/HFDtE3BUzXSQ7QE7pycov6rF1iH7/rP0OQ4Co9Sf4wjnaRX0/A8783utS0xHckIoG
         jYFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=8xohtr3hjq/Rg9f46XoUXUwGp4XiuBsv4sbEBRiEClM=;
        b=rZlwTuVckGOfkVQBGrTLlfiN0ZwrUp6/4gQdAFbUT3rRMJ68IPfnu+JQqulQXHa0lL
         VUh1TEgd7PoTsLrgnvQtG5heM9RhZJmPq+I1KFi/6Hd5UbMF21VL6YS8dRXr/k03P+ju
         uwEVpqY8DmE4XQL5kYGElawr0ILlc2oj8GMBouZCFG4usWoH4flKicQFY2BZxeZzjZhg
         MYs1mpmOiDYacp60iqh8QQyw+kvASp2Q9RHGvIVr1kjEkHpWybAEAVoWDU48Q8JU9kn+
         XCbFTeCBNvEx/ZOGIaaKbRe+5lf7b7WocCANhndEd2eRK461IiEAsHUX4hBMZFJ8Izy8
         8E1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=L4KrD9fy;
       spf=pass (google.com: domain of 3e5snyqukcewszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3E5SnYQUKCewSZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=8xohtr3hjq/Rg9f46XoUXUwGp4XiuBsv4sbEBRiEClM=;
        b=OybthYqpRyBtgike0eTA2ofmiqIPs99/CCfVrOjfnXRO0YxGjGvapxvspfILqX3AP0
         ctU62hz7vr2c95igsd2G2ZcP4NhbZIgbzlLo0+YeYwGisBsswyawgBXwH3LTFVDTdUFL
         FJetjKGtntS+wM/AT6aP7rmE5bG5xRv3DA7+RtSZpfjKkRuE+TWGzWCdvv62vsxTuJSE
         Qfx0MwRWQ/jSArAEgtYwsqLR3WXm282QnWCBz9COmFBV2QL8imKy2Mpz3TCJdhD11GvS
         5qapb52pUf/eGGoXRPk6TMQGzWHDyZxInpj01a6TpCcePMIaPO0mOA1XrlX5hUOTM8Am
         RHgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8xohtr3hjq/Rg9f46XoUXUwGp4XiuBsv4sbEBRiEClM=;
        b=aDPrQgSZmLEZmR2mOsNzXWSCEyWDwkRjJOkzmqY1HYJCDa44H9i6anmO6tzpq3W+jT
         6LoyKapmci2o6cfpUnC9tgDMZIAOWwXfyJYE+LhcZt0fS4SyobXqn7F+3+J5JfDkBj5t
         BlAKel9ZwCLcObSFDc43c3e7F2vZIcRS/GRhgYyKePndSWbeyWV0z6gwSEKzHl34T8N5
         Zx3qq9Biasn1VD+L2tWdb3XcmBzougStEcf53Qb1Rjcll2g5ZgYzYcxKuwzoebzL3BL3
         vYhrdADFMDm+V1e0MWRZ54VfY+ar7asQR2uZCgWGNY5Ws03b8W51JkK7TDqNHFsYZORM
         XQyQ==
X-Gm-Message-State: AOAM533yeQLi0CUjY+9ElAYK86lxRtkoT/PDVuMwGhkmI4P2NzwFeidd
	CJWxRXiTgxSs2qSPyPkYWOk=
X-Google-Smtp-Source: ABdhPJzFRWNdpqvU2kq6wW5wA+s/GKGFAAe5XgkSRsM7y3yClOlJfwvhgGrHJShV+ePMUKcek6YDUQ==
X-Received: by 2002:a17:907:3d94:: with SMTP id he20mr8339626ejc.75.1638372373255;
        Wed, 01 Dec 2021 07:26:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:3e9d:: with SMTP id hs29ls1202581ejc.2.gmail; Wed,
 01 Dec 2021 07:26:12 -0800 (PST)
X-Received: by 2002:a17:906:6b13:: with SMTP id q19mr7759338ejr.221.1638372372218;
        Wed, 01 Dec 2021 07:26:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638372372; cv=none;
        d=google.com; s=arc-20160816;
        b=rnIlXC6edX0QPrp8DzqOptBJZ6AeopYTs6/gmm4Csepk4ymsoJfTPRINkHyQkX76M6
         qoUpxtp5eMgV51gpawaU3RYWgO1ZDBvyBdLgjlc98V/QxvdiXyC+880EDOqqv8L8Q3PE
         5jOEoMZzXFzz4fz+AgzBD+P9+GSE2tY8CFrG4xeX8tiZiccK+ctpEaYvvVpkgnK+Df+w
         CXa4xNrogP5I0FaqZn4RPucw9jm77AaTQdHLgIRYi0ybaFmuFEhVXhuObO4JtqNFzhET
         hSRMBZuu09KRKbvOk6zqG6ddUw4STNTdcyyNftU7pOM71XaaVUMoVoYyIuJ+tJXHZQC6
         Z+qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=KwI6f4Z+SG6OLZ2CA76lIDj1HnRQns/gAAi6BnRl9xE=;
        b=JCJrdcxBf+WNUG7ZEIwfBq8SfkqORO2OhDb4y/Fou9yjx6RuqImdQQGx1MlHSg+oK3
         bDX6IA/nxvh5rwnLscKybRTM4f4RrW2Yd76eVBo88r7+kEYPy9Rw8pfHg7eQXW34q2Pr
         iM95fmg7pLQHUcxZekIVOnFWu1f/xuBXBjXFz7xBcF/DRTaU+iRCS20+kMK94d17mIsE
         bk8dzCcpmn8RFzDk7mS6AUlTIUz95zZdUY2IqkXG5sdaBqcIUfQlsFNdhYaxbt7Tn9Tt
         OUBZ0zpxN9qTetFU98rZ6XWDeNYtlppT6GmtZnE+tgnieDlHFo0oZH3RHbTIwgke9VMC
         mjfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=L4KrD9fy;
       spf=pass (google.com: domain of 3e5snyqukcewszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3E5SnYQUKCewSZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id s8si5639edx.4.2021.12.01.07.26.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Dec 2021 07:26:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3e5snyqukcewszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id v62-20020a1cac41000000b0033719a1a714so12424133wme.6
        for <kasan-dev@googlegroups.com>; Wed, 01 Dec 2021 07:26:12 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:95ad:1401:cf07:6d1a])
 (user=elver job=sendgmr) by 2002:a05:600c:4f0b:: with SMTP id
 l11mr21247wmq.0.1638372371145; Wed, 01 Dec 2021 07:26:11 -0800 (PST)
Date: Wed,  1 Dec 2021 16:26:04 +0100
Message-Id: <20211201152604.3984495-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH] kcov: fix generic Kconfig dependencies if ARCH_WANTS_NO_INSTR
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Peter Zijlstra <peterz@infradead.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Nathan Chancellor <nathan@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=L4KrD9fy;       spf=pass
 (google.com: domain of 3e5snyqukcewszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3E5SnYQUKCewSZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
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

Until recent versions of GCC and Clang, it was not possible to disable
KCOV instrumentation via a function attribute. The relevant function
attribute was introduced in 540540d06e9d9 ("kcov: add
__no_sanitize_coverage to fix noinstr for all architectures").

x86 was the first architecture to want a working noinstr, and at the
time no compiler support for the attribute existed yet. Therefore,
0f1441b44e823 ("objtool: Fix noinstr vs KCOV") introduced the ability to
NOP __sanitizer_cov_*() calls in .noinstr.text.

However, this doesn't work for other architectures like arm64 and s390
that want a working noinstr per ARCH_WANTS_NO_INSTR.

At the time of 0f1441b44e823, we didn't yet have ARCH_WANTS_NO_INSTR,
but now we can move the Kconfig dependency checks to the generic KCOV
option. KCOV will be available if:

	- architecture does not care about noinstr, OR
	- we have objtool support (like on x86), OR
	- GCC is 12.0 or newer, OR
	- Clang is 13.0 or newer.

Signed-off-by: Marco Elver <elver@google.com>
---
 arch/x86/Kconfig  | 2 +-
 lib/Kconfig.debug | 2 ++
 2 files changed, 3 insertions(+), 1 deletion(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 95dd1ee01546..c030b2ee93b3 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -78,7 +78,7 @@ config X86
 	select ARCH_HAS_FILTER_PGPROT
 	select ARCH_HAS_FORTIFY_SOURCE
 	select ARCH_HAS_GCOV_PROFILE_ALL
-	select ARCH_HAS_KCOV			if X86_64 && STACK_VALIDATION
+	select ARCH_HAS_KCOV			if X86_64
 	select ARCH_HAS_MEM_ENCRYPT
 	select ARCH_HAS_MEMBARRIER_SYNC_CORE
 	select ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 9ef7ce18b4f5..589c8aaa2d5b 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1977,6 +1977,8 @@ config KCOV
 	bool "Code coverage for fuzzing"
 	depends on ARCH_HAS_KCOV
 	depends on CC_HAS_SANCOV_TRACE_PC || GCC_PLUGINS
+	depends on !ARCH_WANTS_NO_INSTR || STACK_VALIDATION || \
+		   GCC_VERSION >= 120000 || CLANG_VERSION >= 130000
 	select DEBUG_FS
 	select GCC_PLUGIN_SANCOV if !CC_HAS_SANCOV_TRACE_PC
 	help
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211201152604.3984495-1-elver%40google.com.
