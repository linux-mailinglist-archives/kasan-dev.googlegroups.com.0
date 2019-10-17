Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDXOUHWQKGQEN7MCX5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9344CDAF55
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 16:13:34 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id p15sf521328lfc.20
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 07:13:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571321614; cv=pass;
        d=google.com; s=arc-20160816;
        b=X03+//YhGMC4tRpys761tAqNBOK9rS34QfXTWaynk7+eEzGdy+RA0YAq5W2Jb7yCKv
         TxpTQAqNCyZSovG2vME+cMg39wF9F9AF6DF5SfS4Gt9i/05/PY57nd3PJGiQD+5dAY6f
         gx5H6If3xHLzleXHoaU+ZIQI/c5v5JrJHMEhhT3OSV0hSwGytbGMP8ZeOZceT/1L4GLo
         ka3ZN9RtHJaN/Hm/kkNd5ZNKZu67fM6PnQClExkSBb/E2LioVKrJdqAHAYtd+/eq8KLs
         o5B+kinXfqKurGPRfpzyAONSqAWpFddSsErffqiEVpUhB/+MCcMCePmzQikbQ+v82VK5
         RfZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=zkK80oD0YwXIhcuKvJ0eey+yN1fWOYsJ3956Jcm1Kkk=;
        b=rBgwToPOwtTUhKKJ4xmWtX3Py8c6i6vq1d3nilGbiso8wdsEFtu48CRW20p6+6xgyw
         xcZaFOA4Ujtb1EfUGvk5Ml2Y6NM+drP1gwzvHGKGior9e9CC4fxuZu82Hy5wP86+8K4t
         BlWJrXD2djoXKzuvKz/f495W+6wDzYv7nSdYSyskotPVrJBJYNdgaAdO5y1GUjI6Gt7Q
         ckz4gnqzjTSQ1DsWVeOw9a2miEy1l/seL6DYKxluUPaW+Fg1CmBIov9P54aZX553So1x
         hpQV/saFRjTixM1c7swrru4o3rY1w63JDNItL7fSWYv4VJZlmW7lKzzCsPAIrbv1VO9l
         pZxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Txn+PJN2;
       spf=pass (google.com: domain of 3dheoxqukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3DHeoXQUKCY8x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zkK80oD0YwXIhcuKvJ0eey+yN1fWOYsJ3956Jcm1Kkk=;
        b=pNrE83ixneMd5BFD6vPUlwto1MlY/fTf9U/4QnxxKrnF79y/bbK/QzrRlVdd9Zk124
         JRHUHGIeoRBWFqHl8n9bkX+Hq46bcdU4QqWPz+FZATuQL1lsP/xJN/OkdqUJKj3ZXJVh
         UVAaLS/uGvQpHgaW6JsqxuO49+fe5go/iq/hjSO4YnFqD60Hv+zhMhVoYCldVIc2Mvpf
         Bq5/zJCEg+zPA5rN0SG5Au+h3RB5URXrqa6jDuP5VKVqfU0i7KsEGmJeOYu7JDNdB8Jg
         6Ywhb8VlSEGSLEEcebCPGxHysYoVZU4EvjA6qLyXWOMuewkzFzNWwhdIv4e7BfEQdjj9
         X6bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zkK80oD0YwXIhcuKvJ0eey+yN1fWOYsJ3956Jcm1Kkk=;
        b=fvY/Dl7EJS6igkV2cYUuOxnXUCmCL7MQqTCr4TRAEw4YQ/99+ZX80q9MtxpAo6QduE
         3Z6VPmVzGThb+RZL4IkjaaenmgIGeTsf4eRPyg1/dSJ8MwAFVqpIssuf/mVySJgRuiru
         b1bjKTy2xnuVsSkM58Fo1QzfYhGJqpPkpgOAXCbf5ICLV84jfRDJvESi+38mtLPxCPKg
         k0ZFkCyvSpPkpoOkD7wVK+rFzEYkVpYe6VgiKomZDAGLLlcHDYscE/Ks6CTze1sjvuPF
         q6YsEWIMRLfOgP9M6wkDjBlhFYH74z5rEM/ZY7Pqz4/Qcp6Z3mn5pKlZr+Mhb4eYZS0g
         pDMA==
X-Gm-Message-State: APjAAAVdBvqumm74Yx2kSLduZHwuk7Mb4gf3wzZVWwbg7hhu2bx3qfIh
	RPvgvMhbx0fFZnHeubIx0+E=
X-Google-Smtp-Source: APXvYqz13flApt1VxyWpNe4H9PU9G6+1z/+DSMLs4bsfrbHZQmXiOtoVzuD8IJxxI5jjQfwMtacxcg==
X-Received: by 2002:a19:c505:: with SMTP id w5mr2572096lfe.115.1571321614156;
        Thu, 17 Oct 2019 07:13:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:46dc:: with SMTP id p28ls236885lfo.1.gmail; Thu, 17 Oct
 2019 07:13:33 -0700 (PDT)
X-Received: by 2002:ac2:4a83:: with SMTP id l3mr1676794lfp.73.1571321613530;
        Thu, 17 Oct 2019 07:13:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571321613; cv=none;
        d=google.com; s=arc-20160816;
        b=DPLyIQHoc/e0pQshjIKQw6dXMjqHMwJJGXQZZLQAV3gbzuxWPSZaL7sX/aiFxYWsmO
         f4CubIkCehNkdSpQWjXjGgHdmXa1RQTj1U/lt6vX+8CY2m74CDs7MROZIeRe5FjYw/mv
         uSUzpt42hkpWroRD3MCxgMsC0tNFQxVJVax1aLErSZOcAcv6Zb1YxKP+8xp0Jrt1Vak0
         H9wJyNwm405rKnLhgjYr7qYpJrWcAfKuSs4BzxB8Os/3iPzueCuawGdUTGynL2YfdyvE
         2vByD4ToYMXUCSEhxkyBNj+PU1IA9nVaxnrYjoHvSVHfkS1I/yHuH+ilDTAithCNaHL7
         u1Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=WM5MzufDPT1JiTPvFRdmsbnktj5wkQpb+gi5I/mGgvo=;
        b=Id7/WoYPb/tVvIsSwXE49Mv41kWRLzGna0xvjfO8rQrehCS2x70K0hS6qkXO740Yv8
         aP4qibIEPH2YiYBrFnE8GLN21kFIREVgOAURddS2j3zTjkuko5QT7BWknhfns1LnQAIp
         o9+Ta6QhxMYkOAXUQ/ISLfBD754k6YrpxE+6XAJzdQsgFInAc245kY4BBFrpOIQMagLO
         0To7b4eSMiVuWROToplRhTXPN7jnBCAJOMlCmZH4woIQMB+VDy5G5Le+5k8ba1CwkRxe
         Ac9z9DDx8mx+g2mEXrdDljgBhOWHmXPtldVzpzSP7fBVVoaT3lECOM7dOky0Ii4DweTV
         c5Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Txn+PJN2;
       spf=pass (google.com: domain of 3dheoxqukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3DHeoXQUKCY8x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id z4si179341lfe.4.2019.10.17.07.13.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2019 07:13:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dheoxqukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id r21so1121957wme.5
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2019 07:13:33 -0700 (PDT)
X-Received: by 2002:adf:d850:: with SMTP id k16mr3398476wrl.204.1571321612447;
 Thu, 17 Oct 2019 07:13:32 -0700 (PDT)
Date: Thu, 17 Oct 2019 16:12:59 +0200
In-Reply-To: <20191017141305.146193-1-elver@google.com>
Message-Id: <20191017141305.146193-3-elver@google.com>
Mime-Version: 1.0
References: <20191017141305.146193-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.866.gb869b98d4c-goog
Subject: [PATCH v2 2/8] objtool, kcsan: Add KCSAN runtime functions to whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@linux.ibm.com, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Txn+PJN2;       spf=pass
 (google.com: domain of 3dheoxqukcy8x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3DHeoXQUKCY8x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
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

This patch adds KCSAN runtime functions to the objtool whitelist.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 044c9a3cb247..d1acc867b43c 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -466,6 +466,23 @@ static const char *uaccess_safe_builtin[] = {
 	"__asan_report_store4_noabort",
 	"__asan_report_store8_noabort",
 	"__asan_report_store16_noabort",
+	/* KCSAN */
+	"__kcsan_check_watchpoint",
+	"__kcsan_setup_watchpoint",
+	/* KCSAN/TSAN out-of-line */
+	"__tsan_func_entry",
+	"__tsan_func_exit",
+	"__tsan_read_range",
+	"__tsan_read1",
+	"__tsan_read2",
+	"__tsan_read4",
+	"__tsan_read8",
+	"__tsan_read16",
+	"__tsan_write1",
+	"__tsan_write2",
+	"__tsan_write4",
+	"__tsan_write8",
+	"__tsan_write16",
 	/* KCOV */
 	"write_comp_data",
 	"__sanitizer_cov_trace_pc",
-- 
2.23.0.866.gb869b98d4c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017141305.146193-3-elver%40google.com.
