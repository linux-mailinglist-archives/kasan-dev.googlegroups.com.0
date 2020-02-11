Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUXXRHZAKGQEMVCFBUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 630AA158C4E
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 11:02:59 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id y21sf1036354lfl.11
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 02:02:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581415379; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yj3SyJP3cEIG9f76tMI8171MADsokdGqzcx114kME1uyN8VzMeYezQ/VaRxhdhmav2
         KEpSg9l7jbwvyL/fS8XzkSmrN8X3rnXG8NUAiM6+3VQEP0IgOAnPpNnrB88kCjyhgPbA
         I4hqWfSWXG/PcUhDZWLxv8agnjJw/ysFrG+OPLCjKWYTcAuAli2zBCa30Gk9GxLPR6wU
         lnaVUyQxWn07hMsu9kETGXfTYLwbweh6dZKU42ic3pHoL9jqyxb1EEuZwSYC9r5tC0rR
         HtW2P9Gf74MQQvLLClyNoPUCyToI/8xXTzueV1IK9UUW0Uo8gEKNUhOkTA80c7gkz6R8
         un9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=EVRxeSjVMW7Ce7tE3BY77Uh2vzVr5+1MXlpS47xVgVE=;
        b=D622+J8Qk0UHlbrqZrXFbw8Z4NcN9wfnjNnDbpoMl71HPeVLOtcm3uh18QcldWGz3d
         jsi947yWdt7WeI8whuG09QMypFtP8DjijZ8CEGChdM3ayBci8mGliKtCyMHkeN7NHRDm
         ze7dSrOwqUDTPvpdRn7hXwiAqDeJfoq8cx89na/C5vg4+ioxUl2K6nQPsnMEbS+D6R7U
         HoEpBIcF+O4TFcGccx30CCsXhMIhWduQbwJOkkPFxMYRPPW9mRFRwiyK+BOvzhSmTnoP
         ZQmQKnuenN19Bs+DhW0W4uxveSfFQdRwXMYzMKiceMo2Ido7lGhz51TvvUgLQpd7YO0C
         2tKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FqQJM5dW;
       spf=pass (google.com: domain of 30xtcxgukccou1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30XtCXgUKCcou1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=EVRxeSjVMW7Ce7tE3BY77Uh2vzVr5+1MXlpS47xVgVE=;
        b=ClPsyt1KLO4MbFVX/tZKkrDaF4H/Pw8dE/TvVgT4ONiNnLeVNzo13pyBFNiwVtumlc
         mr50ThJn9lEtKT8JLb6XYIL1qZyfFMpxGOeSXCJGOL4y//7J6LZR5NGsk8udq+rRF8XN
         kcbRZvtoqweQtoRQc3OLlGMPv9mshfAPeRfjvwPPjX+xVa7wBCeVkae9Wvapo+GpEyNI
         f1n89ekhgfF7npwi2gkt77vPAXJFoepj2NluG3GOcYz/FayR+X2A48KST/baCyDqPRDw
         MYAPHc/Jp3Iv0J8gLgx3ibEe32qMm4P73pWIyvzDbCiWX5f0nMEQo5wZZ9fE2WA9+p/M
         TAZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EVRxeSjVMW7Ce7tE3BY77Uh2vzVr5+1MXlpS47xVgVE=;
        b=JCCG5r4fErZDVcVVSxmnfTfHkElYu++nCwN2Wxukkgsh6IgHeinYrw+X29qjLN0KyS
         TbKk1f98dYD+PJ0y9gHJFfY7H6MnOCtS/cZC3dsNpBi3fgOUkaRSQ4/yrwuqnWSNt34R
         aaNKNI2gCj6iPhiZaX5vS2K/35bXxd/dFfXgOD9md5b+9RFTu6I+k8pQgyoJZ9FqWtmi
         PWMn3G7o90XnBkwXNzZSJnbJ3U3wrXctz/RHOo5bycsCeesdvoS6j0k9Hpr6ikx/9KJQ
         oA7n/AIIsO2bDlpbXGa+3TTy5QtbnQEHiBoWbUrQ0y6gq2Ly9x1+2y5ObUyPVgTnmo63
         kZ+g==
X-Gm-Message-State: APjAAAUn7MQK/KwbyBG0TumwB5M28bs5u/2RsPQSxvO5NHZihezCBnjA
	/G7q1V/6i6c6s0Su7O9nQ0E=
X-Google-Smtp-Source: APXvYqwI+0CfJsNC91c3Hbl4Qqzm0oTLjt2jSheDqUj12JJNrRJPupsZnUbF593NaqGdzYdW2yR/hQ==
X-Received: by 2002:a05:651c:120d:: with SMTP id i13mr3716323lja.173.1581415378883;
        Tue, 11 Feb 2020 02:02:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:518f:: with SMTP id u15ls1277763lfi.3.gmail; Tue, 11 Feb
 2020 02:02:58 -0800 (PST)
X-Received: by 2002:a05:6512:284:: with SMTP id j4mr3193584lfp.109.1581415378018;
        Tue, 11 Feb 2020 02:02:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581415378; cv=none;
        d=google.com; s=arc-20160816;
        b=hxnKt6QwM0n1c9RV6xdaBNjNL8kvtBj8WZ0fYl1B2j8j4PhQF6zoQm8YGRDSx4qJxy
         JrUdH+M5W28q38E5dFxepf/5/YCggpwAwcfagjEPkBZKSylBhOGI0uCBDehRX/hQfVIZ
         eV2JiOA47IdS+jHww383I5babjsTdk/O4v2tpBS5TLjRrDQUdmW7z4cBhew9+VIQYXgS
         FCxVCCYzZes6Tc/5Wc/rtEe1X3p9QfA1kYX2vd4Odc+zl88qrD2J9t2O3vqzfBJEFdGh
         UZC/lXJ/l/UR1qCwPRpu+FVQ7Dz2ckz5J0q7vyjiC64PVoMTIldpoUAmA9JLwMyLmgid
         UoUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=4ErgepGfDI3yrrGPodBZCow6kOhTX1ReLVCDrlwlOKY=;
        b=ywUZ6ILlj7byAzARFpsgt1pRGsn1b4MTkErBiOg/zQPBCswWwiO8AyJ0FVVXuzFDE6
         1AGZpHobpKYtjdUs5QIkwPTUlWjjBIFN1r/hAtS0cIVL8DXYG4tEX98CPS6uH9P3D8nK
         CnuVS4PhB2A/Lu222+yARV6jahpuErBNwOZEr7wxhcfWpbZ56nGZ2LgWIhZu9e1LEn9f
         BDLliwPvUTER3jnXkRBuCTqawqbfndHDa+VzqaydP12avugX1b3v4MToPABVzGRKGL8s
         yfORDdVjd2llYKbbOtCGK5u2UtXCGdgmGyoovHwnhw/4a8yr6tcQlf3g+7eG48XotR68
         kq+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FqQJM5dW;
       spf=pass (google.com: domain of 30xtcxgukccou1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30XtCXgUKCcou1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id b29si197076lfo.2.2020.02.11.02.02.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 02:02:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 30xtcxgukccou1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id j4so6596694wrs.13
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 02:02:57 -0800 (PST)
X-Received: by 2002:adf:fe43:: with SMTP id m3mr8140672wrs.213.1581415377060;
 Tue, 11 Feb 2020 02:02:57 -0800 (PST)
Date: Tue, 11 Feb 2020 11:02:43 +0100
Message-Id: <20200211100243.101187-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.225.g125e21ebc7-goog
Subject: [PATCH v2] kcsan: Fix misreporting if concurrent races on same address
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FqQJM5dW;       spf=pass
 (google.com: domain of 30xtcxgukccou1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30XtCXgUKCcou1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
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

If there are at least 4 threads racing on the same address, it can
happen that one of the readers may observe another matching reader in
other_info. To avoid locking up, we have to consume 'other_info'
regardless, but skip the report. See the added comment for more details.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Improve comment to illustrate more concrete case.
---
 kernel/kcsan/report.c | 38 ++++++++++++++++++++++++++++++++++++++
 1 file changed, 38 insertions(+)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 3bc590e6be7e3..abf6852dff72f 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -422,6 +422,44 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 			return false;
 		}
 
+		access_type |= other_info.access_type;
+		if ((access_type & KCSAN_ACCESS_WRITE) == 0) {
+			/*
+			 * While the address matches, this is not the other_info
+			 * from the thread that consumed our watchpoint, since
+			 * neither this nor the access in other_info is a write.
+			 * It is invalid to continue with the report, since we
+			 * only have information about reads.
+			 *
+			 * This can happen due to concurrent races on the same
+			 * address, with at least 4 threads. To avoid locking up
+			 * other_info and all other threads, we have to consume
+			 * it regardless.
+			 *
+			 * A concrete case to illustrate why we might lock up if
+			 * we do not consume other_info:
+			 *
+			 *   We have 4 threads, all accessing the same address
+			 *   (or matching address ranges). Assume the following
+			 *   watcher and watchpoint consumer pairs:
+			 *   write1-read1, read2-write2. The first to populate
+			 *   other_info is write2, however, write1 consumes it,
+			 *   resulting in a report of write1-write2. This report
+			 *   is valid, however, now read1 populates other_info;
+			 *   read2-read1 is an invalid conflict, yet, no other
+			 *   conflicting access is left. Therefore, we must
+			 *   consume read1's other_info.
+			 *
+			 * Since this case is assumed to be rare, it is
+			 * reasonable to omit this report: one of the other
+			 * reports includes information about the same shared
+			 * data, and at this point the likelihood that we
+			 * re-report the same race again is high.
+			 */
+			release_report(flags, KCSAN_REPORT_RACE_SIGNAL);
+			return false;
+		}
+
 		/*
 		 * Matching & usable access in other_info: keep other_info_lock
 		 * locked, as this thread consumes it to print the full report;
-- 
2.25.0.225.g125e21ebc7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200211100243.101187-1-elver%40google.com.
