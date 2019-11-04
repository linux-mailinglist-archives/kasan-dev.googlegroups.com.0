Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLPLQDXAKGQEN6JU6RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AFCAEE251
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 15:29:01 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id v5sf2449068ljk.6
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2019 06:29:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572877741; cv=pass;
        d=google.com; s=arc-20160816;
        b=mIN1xSKMoKb5dlzi3Q4pZgyT4g8AhITDG4fQ3DawS4cV1hsUKPsLtBLwMPUtuW+kji
         C+onlrmREILVTyKjrE0S/ATZO7Yqnzo/trP2j5jFFaW52hvkRBTHW3OgsOC3iabobi+o
         99M12KXn0cdulhAD7ygbQ5mf025rFi8t1guhuM7oyIu7Fa+FDiZ2w08BxFgk23tlw6CD
         RJeUx510V6Xie6pRwQGFdpS+2YJdKbXfo8UPoRlG5p4l9YswfysuKsdhPFnQbUD2SWgm
         jq/PHHotigy1KR7smsqbODw0OMNVpf4h2xqDO9fJfet0U1dWrn46AT6h2d7CI1JM2G3O
         9XIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=CDqzOHV2JUsdzYcj2ZVFbDzlobOXqCgY4EzrMkBtADs=;
        b=frB7LUtaq8aL5KsAhPI4BdUslG9TJCgIy3II8+DRLp5zi7boFhNxJQuqmQYAh0nA0f
         pE9WrAZ3ZpapWDpsq2XyGTcZp/BwduqaMo3i8tzizEnQpnR4FmMmSOusgQ4VxNAb1u2s
         aDKB3GZSPpWdlKeS+KphbbaXUHjfE9705boUKtsq6sJ9G1TffERLssMvTRw/iNNvI6kS
         XJBVQrpz+YC+TZnhej33fP5EZ7EkUpeEGYPHXw9S/eIZGFFcrSR4ZBbSsVQieuUUb1En
         jicQiiVtc+vnouY1j0GmJB9q7eX232RhUzF/2/9Zku5uWvPjlBTT72aAf6ke+2LNliqo
         gh/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HjfM6Wvb;
       spf=pass (google.com: domain of 3qzxaxqukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qzXAXQUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CDqzOHV2JUsdzYcj2ZVFbDzlobOXqCgY4EzrMkBtADs=;
        b=BfuDEv5XvgfOf7CLDwHne99FS0luKtaZRSdRzMnZH5dUQZQfu+blsTrimSN9BkTDAu
         3U2MZjUDXf4epvfxu8Mv/KR/c+sNUTj5/pF0dM9SMjZM73VMzW32xkLr/kI0caoPgcyu
         W1SZZ+go8JeHVxe/vRELvnh9k8i+TL2hyWlCJ5lQMW9teYd4bLaGPitBOh1IUGb9tMPN
         6GJ2hCTtTCNRiTHVNQ/IIRtvgq3RUrUIAJYSnMW2qBBQqJ8WjMAxjNAggyqBNFPOsBuG
         InoqIbCh9yQXsKDv9JhDxs23kYFjhRmB4wcu5c+oElCLqPcivl8bnZHf3SBw6Xy6guj8
         weeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CDqzOHV2JUsdzYcj2ZVFbDzlobOXqCgY4EzrMkBtADs=;
        b=XWQaRj3fDSVeZdVWeJFJedE0JBjriOVcMdDhlYkaFte1iI1MIYYCotucK4zxE4bKUu
         eymcl7tR8iwYE1br1FE2vcSh06WunzzZtL/ikIe3n2be1MNBpy3CRq+Tyvm7dvaCxonQ
         j7fS8m3qgrPiYoueRQ3Ec8gdxYNv1z2QV8ZUemUIy2Bv3AHJ4bbz8cG7TGHe0efbss6k
         jS5jbHLxXAg2cBAW/Vo5h4iRYZcnfAzm9pikZ+4RY2NPubwyktLV2KmtxDOeArWc7kmR
         LsnKO3teuqk8vxPGvOZ0yUsl9xc5u3c0kPwK8k5XOjxoV5/ynDipgMKPeDV5XnRLyIg5
         7RTA==
X-Gm-Message-State: APjAAAU4jaQGs7C8hYcIYjoaDhC1tCup6iFwKT1flv1LagHO5WiuiTsV
	XS0MP4TLW56OrRta5y+oPys=
X-Google-Smtp-Source: APXvYqzUlXHSrX7GT2TQX2poozC6VXjfbj3GMKuA7O4sTWsIj1jXvAjZWlUxRH/M8LNg3RjfJNijDw==
X-Received: by 2002:a2e:2e03:: with SMTP id u3mr2202122lju.115.1572877741181;
        Mon, 04 Nov 2019 06:29:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6715:: with SMTP id b21ls1281033lfc.15.gmail; Mon, 04
 Nov 2019 06:29:00 -0800 (PST)
X-Received: by 2002:ac2:4a8a:: with SMTP id l10mr9245374lfp.185.1572877740484;
        Mon, 04 Nov 2019 06:29:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572877740; cv=none;
        d=google.com; s=arc-20160816;
        b=d/N1vm3ayrhRdk7URE91fiGjO7EGMoHlDbWbHKZWgEyYhrIFCZ+QW0HUJPwpueKGLH
         qvBWFcEkCB2nj/UfhWuvAXDvBCWFnVT/woHBRSgHnkqz/rdZUG2DU9MkJ4gKQNsL287k
         7FRAh6GlCDY3V2a0vo9+4mCTEcKuKmz9z1iFM/4W9bcwk/Sg+upt9b2VcU6hv/5hDIIF
         iftO86QVW66McGJfBGcr4SjA05C0L3TH02fhpP54m2sCthzmcOi9JbtLaVvkQyzDkNfB
         H8/E4VFGgCteC2n5x+dk/t2YZ6C9JLsxiPLK4SJzngxHfHCIomn3Jf2CXkY7XtFNJGB6
         nQqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=aW4SA83XYvfgMU7wkWAC5rLE2H9FWpbhI6EjHgaPF1Q=;
        b=zseNWiQZ/JXrhct0QFP+igcRVS03Na/1vXo2YxjBgoB5uIqhIRJ9kzHW3kSoHofhdp
         EJkgle04FHVLJ3RTkiCkMi0CC881KJUdYsBaAUTiJUcWoNuahxW+4tb5KfiVpUTwMkC3
         F8IL4FY/1IpGuf5sIMGV5LhWoMVsEwe0kATtiG0qm7Qt7r4nTfw6SRMnjwIyFQFrXiYw
         d4eaBs7zoQ9oyBh3O15vnF+6sCmsGlppj8wCoT+0hi/ytNYQZ/p9tJUYZ7fBybPVdtWp
         uEi+T/wNwbQPO4yDaQXn1L8EEBxgZ14ocwwBI5fHE+0uygW0uetV3xqJUc4vwTro/8Sx
         BmXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HjfM6Wvb;
       spf=pass (google.com: domain of 3qzxaxqukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qzXAXQUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id k20si452138ljg.0.2019.11.04.06.29.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2019 06:29:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qzxaxqukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id l3so2031491wrx.21
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2019 06:29:00 -0800 (PST)
X-Received: by 2002:a05:6000:350:: with SMTP id e16mr25109889wre.276.1572877739417;
 Mon, 04 Nov 2019 06:28:59 -0800 (PST)
Date: Mon,  4 Nov 2019 15:27:39 +0100
In-Reply-To: <20191104142745.14722-1-elver@google.com>
Message-Id: <20191104142745.14722-4-elver@google.com>
Mime-Version: 1.0
References: <20191104142745.14722-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v3 3/9] objtool, kcsan: Add KCSAN runtime functions to whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HjfM6Wvb;       spf=pass
 (google.com: domain of 3qzxaxqukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qzXAXQUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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
v3:
* Add missing instrumentation functions.
* Use new function names of refactored core runtime.
---
 tools/objtool/check.c | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 044c9a3cb247..e022a9a00ca1 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -466,6 +466,24 @@ static const char *uaccess_safe_builtin[] = {
 	"__asan_report_store4_noabort",
 	"__asan_report_store8_noabort",
 	"__asan_report_store16_noabort",
+	/* KCSAN */
+	"kcsan_found_watchpoint",
+	"kcsan_setup_watchpoint",
+	/* KCSAN/TSAN */
+	"__tsan_func_entry",
+	"__tsan_func_exit",
+	"__tsan_read_range",
+	"__tsan_write_range",
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
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104142745.14722-4-elver%40google.com.
