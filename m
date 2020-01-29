Return-Path: <kasan-dev+bncBC7OBJGL2MHBBON4Y3YQKGQE3JBJRSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AC3C14CCE8
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 16:01:13 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id t3sf10174315wrm.23
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 07:01:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580310073; cv=pass;
        d=google.com; s=arc-20160816;
        b=su9+FYBE2H+Z2N5sp2LMvDu/Ett/7AuiYRsZfiKn2Mn7gVbkNUCNDmEE1ATTysxSEY
         YxReXiarwj6QqcM2rMPq8dEmYoKsPspa0xVHTwT1JkMjgxnyMAsAsx+YKMz/rYCEfs2k
         8OJKpS65zcFU+6wGoFYUIyrBANlZUjdN6vwZ1MM3hDQ2jwjsPCm0DD62SOYt9labpG0E
         J/Qc3VctBaVz7sykeHGfbe5Lky7FTv34Nr9sUdSil3Z4Mfg3meWUdxTHLFoETqw9qhWC
         wzINl6DAw29FcP0xPkWl9lUcnEwXviUDXmiaTLPrnxIU5vHtH5yEqlUuNWYcaha86J8G
         Cw6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=UNPfnSRNQeKoE77cjK3a25J9Edsi5fquBfJ/cHeLnCo=;
        b=Zl/pPYGHdaD559b0qf4RDbMfFtBvOkj019ryVY97D8RHkFXWLqwSLFK7SCLg5ZlsqZ
         kdTrXUFZlvWYxxW0bpi27/PrkNFsqUQsna1qCT6yhdql6gTj6b5FV2aI+xTud2EvyA1k
         nlS77qqFpMbiww3Eku/pOlAC11T5/jT5EBcA+S7xEDYIxb+1Zic7f2QwamZSPpcbvssd
         7GBgA33RHwZXKQL1Hc+5NgSeHYQ66BLnNwlgNPsbsl1asyOyRq9+2HuyxQWgRttyy+Xq
         CJyl8CEuptfO3GJrSc3Z4CH3NusT4JBkwmF0coVng3GIQxAeXJsFPMwloc6osj1mep6H
         r0NQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QZytvrIW;
       spf=pass (google.com: domain of 3oj4xxgukctmtaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3OJ4xXgUKCTMTakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UNPfnSRNQeKoE77cjK3a25J9Edsi5fquBfJ/cHeLnCo=;
        b=Wk4/3xCnKrpp9aOpEVBfyCtU7F005ccQ/1KCfQU/LX9V01F499oXZKZ4eGMmPxhonV
         rrrwF9ntcLTlUAS3gsDodU4/ioiwBX1xdzpQhTjwp0tXxXGWPiSrsOm05+e75iageTXo
         IUS3Bzuby81Xb+SlFh4UvXO1LmbF33D6e2Bt6hEIpgplPU9Of979QnzfqzhArQ+z7Kmb
         e65b+0gNljx+Dh2GhjmtrsqPYuxuEtdMOJdtv15PChrB1zoEA049KscR1u+aAPPb/HaE
         na+Wy1O8OhBEcJYfh3foF+LcGiu7r3PxI+flrol3d2t1Xn9LQdIIE5V57DiXVpEfe7Zv
         O+sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UNPfnSRNQeKoE77cjK3a25J9Edsi5fquBfJ/cHeLnCo=;
        b=XyXIwxaPBMVXv6R9K8IagdWzHaEMlYZMP52eYNBUZRWq5zLaBVf1ylUAWZGZTfx4b+
         nwpVpG5GNIC4bW4QGwwxyXiMjM6DqAPkcYBgBomfa03N1uMqiWyyLFve+pzcOp7OjRfP
         lmsGTJoQ2Gt08IbCuxPYaqoqiGj0pkn4jATNHuzNiBJoGYI1JOrVRutkmoA4nnrW0GTZ
         ULHmRqCm59XyA3QYt+AoMnBJ6K7fXsUEeOv61ZYBRnBrvE2Cw22w88hEVslDLU/iONJn
         5DfCnuo/uztf8DLmhDmMNXLdS6ag1p486U4s7uVK/XjUu+zvOgjhQHbpICLLHwDhh6iK
         Ksdg==
X-Gm-Message-State: APjAAAU+X1UDA4xTNA+baNl19UyLKKZp2h0P4EULo/Kkw6Moh+E3KJuX
	A93QBY2/y7t7FH3Fy2fcRtQ=
X-Google-Smtp-Source: APXvYqznHnKe4Jty+lF9omgouE6EpjQ4E2Wh6WliK9IpptqB9ccAQF2vZl9OkT56N926U4ETe8Egqw==
X-Received: by 2002:a1c:7205:: with SMTP id n5mr12520483wmc.9.1580310073296;
        Wed, 29 Jan 2020 07:01:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:247:: with SMTP id 7ls5257835wmj.3.canary-gmail;
 Wed, 29 Jan 2020 07:01:12 -0800 (PST)
X-Received: by 2002:a1c:7215:: with SMTP id n21mr12648482wmc.154.1580310072641;
        Wed, 29 Jan 2020 07:01:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580310072; cv=none;
        d=google.com; s=arc-20160816;
        b=zWgqfz8gHiZ8rX8cDms3BnDmnBtQv9KID4mfyQZAYgveTMScjxQ9FnTAg4h2yPga/C
         vtDhPJxAz/bnluVO/ttQ7TLs/M6WEzS/NyVBj6W6hsKMzT4XwrTgFBPCh0nhoghyxx27
         POnWtei+UiuehjoCNoam7xGT0Xu4Xn6zEuNI2ID/oTdOP0GZ5rnmCh0wHgolk92I/Kc8
         8vFdyHnIKUJ9rhRNnIUAdAreSsGZE8RCVAH3dQmMYRcQpYYDqd6bewRskLA50n7m5GxO
         yanh4AU92R7VqmOn8kSW2Ode1FTfS01uCP+L1vtXm5VYeVS/J23MRf0KrDgmYyYJCIMZ
         hGug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=MCBz1zj6EK5lhXzgufWO0flG14sfalDmNzlYHd383TA=;
        b=aozr+V2tDaUtdFLTiPjpvOadFrU+VYzpSnu941S6aMyVPI32QQip2WKb3qqFvda+p1
         HgSB6ILW1h2876vv8+8KjTkYhGjns8IBTzlGAvhYdqoR2ZMF4qL0hHS9gzd/u+v7ufDU
         XtcbtHqPqDfpndgRtceZVlzTU1O9uLVNyA4LqND2/toK2ddRzNgOFSg+b+SP5nahFcdV
         ldcRP+MR/I/UsD4jGvP50RJ375u499UodZ348pXP91FnjAArJuGNDt8vFdK9tXuy58cz
         IihbK+wUrJXgBuAjHVhQweqBK+f/ni5DPqfTSGAH+ZWbDdPTJTXjf0e7QcN7/jmjP+Px
         qZ1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QZytvrIW;
       spf=pass (google.com: domain of 3oj4xxgukctmtaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3OJ4xXgUKCTMTakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id j7si2777wrn.1.2020.01.29.07.01.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Jan 2020 07:01:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oj4xxgukctmtaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id d8so10177799wrq.12
        for <kasan-dev@googlegroups.com>; Wed, 29 Jan 2020 07:01:12 -0800 (PST)
X-Received: by 2002:adf:f54d:: with SMTP id j13mr35917050wrp.19.1580310072038;
 Wed, 29 Jan 2020 07:01:12 -0800 (PST)
Date: Wed, 29 Jan 2020 16:01:02 +0100
Message-Id: <20200129150102.2122-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH] kcsan: Address missing case with KCSAN_REPORT_VALUE_CHANGE_ONLY
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QZytvrIW;       spf=pass
 (google.com: domain of 3oj4xxgukctmtaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3OJ4xXgUKCTMTakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
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

With KCSAN_REPORT_VALUE_CHANGE_ONLY, KCSAN has still been able to report
data races between reads and writes, if a watchpoint was set up on the
write. If the write rewrote the same value we'd still have reported the
data race. We now unconditionally skip reporting on this case.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/report.c | 27 ++++++++++++++++++++-------
 1 file changed, 20 insertions(+), 7 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 33bdf8b229b5..7cd34285df74 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -130,12 +130,25 @@ static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
  * Special rules to skip reporting.
  */
 static bool
-skip_report(int access_type, bool value_change, unsigned long top_frame)
+skip_report(bool value_change, unsigned long top_frame)
 {
-	const bool is_write = (access_type & KCSAN_ACCESS_WRITE) != 0;
-
-	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) && is_write &&
-	    !value_change) {
+	/*
+	 * The first call to skip_report always has value_change==true, since we
+	 * cannot know the value written of an instrumented access. For the 2nd
+	 * call there are 6 cases with CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY:
+	 *
+	 * 1. read watchpoint, conflicting write (value_change==true): report;
+	 * 2. read watchpoint, conflicting write (value_change==false): skip;
+	 * 3. write watchpoint, conflicting write (value_change==true): report;
+	 * 4. write watchpoint, conflicting write (value_change==false): skip;
+	 * 5. write watchpoint, conflicting read (value_change==false): skip;
+	 * 6. write watchpoint, conflicting read (value_change==true): impossible;
+	 *
+	 * Cases 1-4 are intuitive and expected; case 5 ensures we do not report
+	 * data races where the write may have rewritten the same value; and
+	 * case 6 is simply impossible.
+	 */
+	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) && !value_change) {
 		/*
 		 * The access is a write, but the data value did not change.
 		 *
@@ -228,7 +241,7 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 	/*
 	 * Must check report filter rules before starting to print.
 	 */
-	if (skip_report(access_type, true, stack_entries[skipnr]))
+	if (skip_report(true, stack_entries[skipnr]))
 		return false;
 
 	if (type == KCSAN_REPORT_RACE_SIGNAL) {
@@ -237,7 +250,7 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 		other_frame = other_info.stack_entries[other_skipnr];
 
 		/* @value_change is only known for the other thread */
-		if (skip_report(other_info.access_type, value_change, other_frame))
+		if (skip_report(value_change, other_frame))
 			return false;
 	}
 
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200129150102.2122-1-elver%40google.com.
