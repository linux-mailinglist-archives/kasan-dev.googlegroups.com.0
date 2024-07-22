Return-Path: <kasan-dev+bncBAABBKEA7O2AMGQEOOLWZPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A9DA9394B7
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 22:25:14 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2ef2abc51b9sf16372311fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 13:25:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721679914; cv=pass;
        d=google.com; s=arc-20160816;
        b=k/B3qvjrxRSjSjXQL/St0lB24wo6qFfqVMmTJk3+5H1ju87mNFoZrkEq1KMavG+wbR
         rISJ2WmZb+9cIDAVH5YeR+1xaHuAU1QnsM4+Xb73wzQV4LiWIKBOyVF+e5QscErsPPgt
         QxL03tYNulc6DlKiipvji/W7hixelSoGC+MdeWAcYpqP1rLam9SaDLpKaYABmK3qBXE7
         SZa550+p2PS+xanPPbC3CVlHaM0cUQn1DiySZQTZObwbL+oh5kzdXVF6gVIp1ORXovXO
         m+w6IKEASzkfGoO9bfctCrVrji6H28CLCFkBzrZ5/NnFWChCt5C9AxG+hcl1uxR/HIHW
         H/TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=u1pT+kyjjKKO1qAS54z3s94cBHiFBhJLkse0uI6e8l8=;
        fh=QRP4uNpkUJ3t2Qq03lCMAFwzrEE/nml1yCE01qXH94s=;
        b=ieCsiyL6XnEJI951VFn9z7uKs4OfxAwl/Mkn/XlH3iX6lH+nbbEZ2K+5LXLV729QRK
         nrMrLJZeaKJniyaEqwqjDCqWUqGu5qOHuQR6qMc1ww/jbNBLyWumSDC2AjbzBaDI7wYE
         qLMxIRKGJ1DaqkNrSLlkyHgbv6dNpFaIKXNx+GREU0k9WkJBaTLsYV1yMbiZCoFy3VTF
         N4qL5nQixjzJnUYH/d2DtCaqEStzp9tV/rOdgO6GG5UZGYtW6YQlNjEg55zswkY0Sl5w
         URCpzS9dd5+Q97cuDtF2baYHnFoc70Jlw5JEYIGYBHU+GLjDprmMKddY+ZFq02ehyOFk
         i4jQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IOi5c60b;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.178 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721679914; x=1722284714; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=u1pT+kyjjKKO1qAS54z3s94cBHiFBhJLkse0uI6e8l8=;
        b=F8eBMntcXGvmfOHeILP+GzknFE0vW+FBGRonCqqE3TgQtcYBAtsGKe1+YVJsC5swIB
         ZqzodYzrVOz/3btfApiHA3w+iVhWoDPbED2PeErk3BgkcuGepHW8W0SBxbcMoj+J+LbV
         OyBESQbP0bGSE1gKjapT9nw89AVXgvGEoJn2mPz9RBcbAIYsqJsa7jYr5+a/ONqkpiel
         dkTGx/qCd6Y6/F25obkjnckdo0mZlfhcUqHzpOzPBwy5bmAXDB89MKkglM26NaXwXzTC
         qsF7I2dda9Rm+pAJgg0AacjU6cEy/izQ5gTlBn1l+fXyz1SQUCaohS+pj324F7a5V5bh
         bAPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721679914; x=1722284714;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=u1pT+kyjjKKO1qAS54z3s94cBHiFBhJLkse0uI6e8l8=;
        b=uO+ayLrj++CaOkXi27jeMzfenmchcKTW2Ac8qQtmBQ0djBXDIyS7eci3F6h7CIIPVO
         8xbSTbOddcJtGmrBwB2zDFKYY89sdKM2ysriXIviw82sLdytd8ceJorxDctfUfJKnXKA
         2sl6ExBd9Wd+gXcJsFbX1e5E37W93kiw/wkoCe1Ot/TA+hXf+C0PZKpOOu5FMitMkLue
         00IDiv/T+NPHAt9rd/JAuGa8bf1F0KAN14Z8ZZxIQkla94hZrVRNKXhreoINlpunMTDM
         kZIC+P42W+hi7XBZH9+Bzf1QX4/1By1UNOdBwOJBCbFzueGDDR5C2rWkwloXpy5/RUK9
         H2+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWG6prl9JZFNodXD7qExS9phcorsYL/6RsVa849SQuxiaPdEMovRBXFz8cwCxJjTBLGF/i51mRoya6H9VFNoIMoCYK8lOHZ+A==
X-Gm-Message-State: AOJu0YxNVXoB2RRyG3I6rSQ3b15whMMzeaz5ytDpLgoucCL4zIrrq+VK
	WdnsOg/HZ5G73Slah/B6NaQsph5yeTwQHZR6/wlX7bq45MWh+L2D
X-Google-Smtp-Source: AGHT+IFs9R7JZBOZiaQHUP6FKKUhKqEjfCz9uDOPj/St378XsQ5asn4Y3ck6aReTsl1539cvBomGBQ==
X-Received: by 2002:a2e:2a86:0:b0:2ef:5d1d:773f with SMTP id 38308e7fff4ca-2ef5d1d7809mr22221681fa.24.1721679913025;
        Mon, 22 Jul 2024 13:25:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bea4:0:b0:2ef:1eb3:4736 with SMTP id 38308e7fff4ca-2ef1eb348dbls11465951fa.0.-pod-prod-08-eu;
 Mon, 22 Jul 2024 13:25:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVEQfsuU87QPp3Y3E6zWsrSvx+a93bRkhtucUlKjElRFGblobUaYlpOzUGJfpURLXsKvZjq6G1Rp0OPDS3iZJq0G2Q1hC5gSMTbnQ==
X-Received: by 2002:a05:6512:2820:b0:52e:7f18:176b with SMTP id 2adb3069b0e04-52efb533676mr5700712e87.11.1721679911416;
        Mon, 22 Jul 2024 13:25:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721679911; cv=none;
        d=google.com; s=arc-20160816;
        b=bcmhzgLJPr2YTzGqUJZvNINojRX6hnzqYkyuIvsl7hJagExzWPdvu9IldsTk7vkBoH
         RZagArRf0HY4tmzdoM5oI7zFgdSk0bLH716SemFmscFIh8QqT+GRDRC8mTQ8wN4aHRdL
         NeDJ6GQqJ0iWG+KjgWwVgko3NHzAij+gJQiQCbwB/m1wIs8rxsFmRLYnzQqQT0347+7C
         jwfN2BVyTh+LdtGCHNdCCG4+FrtYrnsm+qcTFvVUFmnjdozdIRCcGwaeChNQKkH6nYIi
         lXji6+MFR6oI3LG8SQ35+qZsEYHx2NW4yBb+qBxX/bM1RpveDOOqIo6QTJED4zr3wxrp
         qmUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=8/k2ZwHfUaSJhfPH5Zkk+TCGlgAiYiwAht3Bf0GZAMY=;
        fh=Y4krL/DOby5GWSUTrEl+07ppV2VW7xI7DATCUl0J4C4=;
        b=hho6/q049e3MwdANgphjBq/parNN0Ddbgv5nj9eolTBJVbpp2KLAW61HomUfdAUpZZ
         /2KFYOahqYrrelzmWpnMM6mVKWH99QdWWfxrPZbCvh7LaGr6TuQcarriiXe7uZusMr1V
         C7+Bv7J2swzuhRRMprsbxVuRxoMOFFeVNzocwwQOqApNX3U9TSsUs+lTruGxWGbkMTt/
         fVDALGzNHGoLRUtW7FNZnP3h5/2e3usPNURP96fk4GYTYPc0nsVj64VBrLsC4wSx7a+X
         g17b01moqYt9RK7PT26FD0EaTxtC3dah7OC9iO59iURxmagzJaT/2JSTsYo8aFg16zM7
         bkig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IOi5c60b;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.178 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-178.mta1.migadu.com (out-178.mta1.migadu.com. [95.215.58.178])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52fc148f7a4si37583e87.6.2024.07.22.13.25.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Jul 2024 13:25:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.178 as permitted sender) client-ip=95.215.58.178;
X-Envelope-To: dvyukov@google.com
X-Envelope-To: akpm@linux-foundation.org
X-Envelope-To: andreyknvl@gmail.com
X-Envelope-To: nogikh@google.com
X-Envelope-To: elver@google.com
X-Envelope-To: glider@google.com
X-Envelope-To: kasan-dev@googlegroups.com
X-Envelope-To: linux-mm@kvack.org
X-Envelope-To: tglx@linutronix.de
X-Envelope-To: mingo@redhat.com
X-Envelope-To: bp@alien8.de
X-Envelope-To: dave.hansen@linux.intel.com
X-Envelope-To: x86@kernel.org
X-Envelope-To: linux-kernel@vger.kernel.org
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] x86, kcov: ignore stack trace coverage
Date: Mon, 22 Jul 2024 22:25:02 +0200
Message-Id: <20240722202502.70301-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=IOi5c60b;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.178 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@gmail.com>

When a multitude of kernel debugging options are enabled, they often
collect and save the current stack trace. The coverage produced by the
related routines is not relevant for the KCOV's intended use case
(guiding the fuzzing process).

Thus, disable instrumentation of the x86 stack trace collection code.

KCOV instrumentaion of the generic kernel/stacktrace.c was already
disabled in commit 43e76af85fa7 ("kcov: ignore fault-inject and
stacktrace"). This patch is an x86-specific addition.

In addition to freeing up the KCOV buffer capacity for holding more
relevant coverage, this patch also speeds up the kernel boot time with
the config from the syzbot USB fuzzing instance by ~25%.

Fixes: 43e76af85fa7 ("kcov: ignore fault-inject and stacktrace")
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

---

I'm not sure whether it makes sense to backport this patch to stable
kernels, but I do think that it makes sense to take it into mainline
as a fix: currently, the USB fuzzing instance is choking on the amount
of coverage produced by KCOV and thus doesn't perform well.

For reference, without this patch, for the following program:

r0 = syz_usb_connect_ath9k(0x3, 0x5a, &(0x7f0000000080)={{0x12, 0x1,
0x200, 0xff, 0xff, 0xff, 0x40, 0xcf3, 0x9271, 0x108, 0x1, 0x2, 0x3, 0x1,
[{{0x9, 0x2, 0x48, 0x1, 0x1, 0x0, 0x80, 0xfa, {{0x9, 0x4, 0x0, 0x0, 0x6,
0xff, 0x0, 0x0, 0x0, "", {{0x9, 0x5, 0x1, 0x2, 0x200, 0x0, 0x0, 0x0, ""},
{0x9, 0x5, 0x82, 0x2, 0x200, 0x0, 0x0, 0x0, ""}, {0x9, 0x5, 0x83, 0x3,
0x40, 0x1, 0x0, 0x0, ""}, {0x9, 0x5, 0x4, 0x3, 0x40, 0x1, 0x0, 0x0, ""},
{0x9, 0x5, 0x5, 0x2, 0x200, 0x0, 0x0, 0x0, ""}, {0x9, 0x5, 0x6, 0x2,
0x200, 0x0, 0x0, 0x0, ""}}}}}}]}}, 0x0)

KCOV produces ~500k coverage entries.

Here are the top ones sorted by the number of occurrences:

  23027 /home/user/src/arch/x86/kernel/unwind_orc.c:99
  17335 /home/user/src/arch/x86/kernel/unwind_orc.c:100
  16460 /home/user/src/arch/x86/include/asm/stacktrace.h:60 (discriminator 3)
  16460 /home/user/src/arch/x86/include/asm/stacktrace.h:60
  16191 /home/user/src/security/tomoyo/domain.c:183 (discriminator 1)
  16128 /home/user/src/security/tomoyo/domain.c:184 (discriminator 8)
  11384 /home/user/src/arch/x86/kernel/unwind_orc.c:109
  11155 /home/user/src/arch/x86/include/asm/stacktrace.h:59
  10997 /home/user/src/arch/x86/kernel/unwind_orc.c:665
  10768 /home/user/src/include/asm-generic/rwonce.h:67
   9994 /home/user/src/arch/x86/kernel/unwind_orc.c:390
   9994 /home/user/src/arch/x86/kernel/unwind_orc.c:389
  ...

With this patch, the number of entries drops to ~140k.

(For reference, here are the top entries with this patch applied:

  16191 /home/user/src/security/tomoyo/domain.c:183 (discriminator 1)
  16128 /home/user/src/security/tomoyo/domain.c:184 (discriminator 8)
   3528 /home/user/src/security/tomoyo/domain.c:173 (discriminator 2)
   3528 /home/user/src/security/tomoyo/domain.c:173
   3528 /home/user/src/security/tomoyo/domain.c:171 (discriminator 5)
   2877 /home/user/src/lib/vsprintf.c:646
   2672 /home/user/src/lib/vsprintf.c:651
   2672 /home/user/src/lib/vsprintf.c:649
   2230 /home/user/src/lib/vsprintf.c:2559
   ...

I'm not sure why tomoyo produces such a large number of entries, but
that will require a separate fix anyway if it's unintended.)
---
 arch/x86/kernel/Makefile | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index 20a0dd51700a..241e21723fa5 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -40,6 +40,14 @@ KMSAN_SANITIZE_sev.o					:= n
 KCOV_INSTRUMENT_head$(BITS).o				:= n
 KCOV_INSTRUMENT_sev.o					:= n
 
+# These produce large amounts of uninteresting coverage.
+KCOV_INSTRUMENT_dumpstack.o				:= n
+KCOV_INSTRUMENT_dumpstack_$(BITS).o			:= n
+KCOV_INSTRUMENT_stacktrace.o				:= n
+KCOV_INSTRUMENT_unwind_orc.o				:= n
+KCOV_INSTRUMENT_unwind_frame.o				:= n
+KCOV_INSTRUMENT_unwind_guess.o				:= n
+
 CFLAGS_irq.o := -I $(src)/../include/asm/trace
 
 obj-y			+= head_$(BITS).o
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240722202502.70301-1-andrey.konovalov%40linux.dev.
