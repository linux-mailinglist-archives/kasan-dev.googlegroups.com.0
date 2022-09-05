Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBWW26MAMGQEOEP355A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id CAB315AD278
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:47 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id o16-20020a2e90d0000000b002681c6931a3sf2811944ljg.10
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380807; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mapt+t0ayHyGPPEwdjBYH7WgicS/Hkv2tP1pcj9Xlj9T7gDbTshEig3IPgImN5OkeA
         0UOdbn8J/C/9DTTRIFZ1a9YViQPqcnsb6nRoq870kp0zi99x1CAi01aN7po6EuU4KlFN
         GRWsk+d39AR3ye3u3CPyNrTG4P1aNJC7axTddxfaRjaB+PENylO0SpCclhVEd+NWoEE8
         RWu8q4F9S3CZGORdVZ6yZQB4r0aXAjFxlX/vCr39iJuwiXJOGCPd+hw53s7KSndcZJSp
         Pv/9mM2Fg5pK4Z5WiftTI5We+wL8yIVKrrZ+jot4Wdtzat0tHdb/sViWxi6nmAelEqGl
         sT8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=t8sH8uX+O6Fyhd632Bu/sIYzH5D4dc2A1D+FKZ8HpiE=;
        b=Rvp0/Oim0wLoAm1MHJe9klXruqWCnIvzuYbfWmuAnOroXcYwfEtyG8naKztLKL6m0a
         vg1aXMsqLNOlRx0C8+uU9knH8Ir1IPPpMOV6YFFbQophqvQgG8i0YnGm/35v74d9UPtZ
         mVmouzV/5J2fUcoTed998Nflxvsjpf72omcfZ4GDQHsQCEEYgIVuk0CKX1yGqFU8SEeu
         UkVDU0puh1Nfvu61/ZeKD+RJzDzbDiCSi0Le2vdtYIdkyj62wzzSR759n/eiA4FSyi8H
         vTZ2demGDFic9yXBunXXo7AaKNFFtqJF7nljxWJ8zS2dEnI+MakxxCT0KxIEo/iCNLka
         9yyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ddTOCduO;
       spf=pass (google.com: domain of 3bosvywykcvez41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3BOsVYwYKCVEz41wxAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=t8sH8uX+O6Fyhd632Bu/sIYzH5D4dc2A1D+FKZ8HpiE=;
        b=rzSGKAPwnc/SJ7e+8mb3MWFU/HCA14Vc7oZ8cRcKWUs+zGkEn+ipudGK1hyKGCcK82
         7rD/QenkTQVrU4r29B+lbtS/sVtRyoumXvSTSkq+rT0pAS/f1RvccAKzhL3vPRjhu1z1
         80fd2B20Wp+591JjgxkZZJFFDcXHLL8cVISFYnLU3YS20s94ohcqjQIk9PJhYcG0n3FI
         VB4T7aoBFwffmvVC+NePsK5PtZGaGU9vigsIOR06gsWt1VJm8dTEa8HKTGxn3SombOxV
         iD29ydtDFsEEahQDl2j6eTyOTHTHh6MTYl117ebFYaxnTUZ1i+Pkv8IcoQCWiHJ+4yZe
         gP0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=t8sH8uX+O6Fyhd632Bu/sIYzH5D4dc2A1D+FKZ8HpiE=;
        b=gPPtjj5Y61Y4Ze8JERDdc/3V4ZaOpduDuophVVtXmp4Vh+202yknfl9H3plwMsE9g1
         m/JSHOWdak/sEEES/kRp9QqCEwaiT6Htfn/cI3drtGHom2AMdoAZONMZg32jMCFbsFmn
         jfOd/uT0k+wCmQR5Lcrng0CglqPmoV4G1DKlMcmnxZPCWXlgXjjLxoRv88AXjp7lNaJc
         2gIJ7xI4H28U/nLX0eHc9jbF4L2dxzcoWeLoYU9WAN1O/qodrgcW5n3eWHEetxZwAuSw
         xG2ifdIxxiS2BX2eSMiCDy7S/+4GpZ+92b/8C1tbt9hXl+i9IyPcd9WsLkmf8y5/WDTx
         sydA==
X-Gm-Message-State: ACgBeo1fJyjKhB95q4QbAVH3itYJslwwyAR1h/84HfFvaI+T7qg7xtm9
	NYBmxjPWVRMb9ghcV7TRf34=
X-Google-Smtp-Source: AA6agR4BQTWJHQh/nS6DG+ilT3koJcO3KnmGanCkh4Ihs5hwU92VqFNXKgZQS+xVT42+vV9Wt4MtYA==
X-Received: by 2002:a05:651c:105a:b0:267:5d3d:2b25 with SMTP id x26-20020a05651c105a00b002675d3d2b25mr8865375ljm.370.1662380807185;
        Mon, 05 Sep 2022 05:26:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:150f:b0:25f:dcd4:53b4 with SMTP id
 e15-20020a05651c150f00b0025fdcd453b4ls1562627ljf.3.-pod-prod-gmail; Mon, 05
 Sep 2022 05:26:45 -0700 (PDT)
X-Received: by 2002:a2e:321a:0:b0:265:7c0:ec37 with SMTP id y26-20020a2e321a000000b0026507c0ec37mr9918116ljy.60.1662380805302;
        Mon, 05 Sep 2022 05:26:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380805; cv=none;
        d=google.com; s=arc-20160816;
        b=V3nUpqHx1lhZLWJFdQt3ZO10V01YFRlys92ebN0xhXd0eMOM8s5hwnWGk9+SBssbEL
         +2Dd2E+cLAKdsExhbckT/4GT/yW8bLMEtoitKQ/Bi2nxL8Z8tWOxqOX4wHlwP557DOV3
         tbsPNOn1iSh6nsNc9toH3yPeyxycJ9oTJ3BQp2kvs6WfInL3SfBEpFRZkHJW9bnrJ9gW
         VjOkKXBQVzeXKZnj9nJMsRhhnhKI46RKolYQsPAlAdl/ZZMZFdOOLM1jlMZ2J9JzWnpz
         DV5SSjhyzhehfVl605Iw9sVJXz9G5haktv+Supi1QbHSovO2F6jxurKwADJ1NqQp7W0f
         Q5OA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=y7GARGHGPpfPMqaRIp9ae7D7QgvYSCiDFPeV4nzQ3Rk=;
        b=x1M+pMkOjGmMB2LcNuGceQHxyn2GLBIOt9xLkpVylGdYqi7l5gonOTtyyFDGkL4thF
         gCDp7ilZcq9EXjpUPjWUd9+XecPo5e0NSKG4QH3CiqCUSp2vY0wbU2I+Us4QK4NV/EEJ
         1ZYwFLaSgtNs91rPGstPMM6kXVIcXuSEgd9egFo0FKhW7EZxJupsoIDmna0R/8+/DgaH
         skMec9r3w8uSTZRyGOsRYuRvfi94+rRy4/iFjJZvvltGwgOnjXDLShGLMvhOCuniAgcC
         Nw1Bkxl3agIx8sTXVT1QgSivbjzxvUEl6eRcRrnfO+SsgKX1w6Y6kUfY6c5YEcuIdBQU
         H1zA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ddTOCduO;
       spf=pass (google.com: domain of 3bosvywykcvez41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3BOsVYwYKCVEz41wxAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 4-20020ac25f44000000b0049465aa3228si278555lfz.11.2022.09.05.05.26.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bosvywykcvez41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id l19-20020a056402255300b0043df64f9a0fso5759020edb.16
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:45 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:906:fe46:b0:730:ca2b:cb7b with SMTP id
 wz6-20020a170906fe4600b00730ca2bcb7bmr37494826ejb.703.1662380804705; Mon, 05
 Sep 2022 05:26:44 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:47 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-40-glider@google.com>
Subject: [PATCH v6 39/44] x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS
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
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ddTOCduO;       spf=pass
 (google.com: domain of 3bosvywykcvez41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3BOsVYwYKCVEz41wxAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--glider.bounces.google.com;
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

dentry_string_cmp() calls read_word_at_a_time(), which might read
uninitialized bytes to optimize string comparisons.
Disabling CONFIG_DCACHE_WORD_ACCESS should prohibit this optimization,
as well as (probably) similar ones.

Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I4c0073224ac2897cafb8c037362c49dda9cfa133
---
 arch/x86/Kconfig | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 33f4d4baba079..697da8dae1418 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -128,7 +128,9 @@ config X86
 	select CLKEVT_I8253
 	select CLOCKSOURCE_VALIDATE_LAST_CYCLE
 	select CLOCKSOURCE_WATCHDOG
-	select DCACHE_WORD_ACCESS
+	# Word-size accesses may read uninitialized data past the trailing \0
+	# in strings and cause false KMSAN reports.
+	select DCACHE_WORD_ACCESS		if !KMSAN
 	select DYNAMIC_SIGFRAME
 	select EDAC_ATOMIC_SCRUB
 	select EDAC_SUPPORT
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-40-glider%40google.com.
