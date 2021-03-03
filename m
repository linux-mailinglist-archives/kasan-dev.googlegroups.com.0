Return-Path: <kasan-dev+bncBDLKPY4HVQKBBEMO76AQMGQEVCQQFTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EB1032B971
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 18:27:45 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id s10sf2099792wre.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 09:27:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614792465; cv=pass;
        d=google.com; s=arc-20160816;
        b=RRrvGcf1H0XVqmdryREsnszLoYWJZxx2c94QIXIDvFMr+l6mL/9fUld2ET1VV7V9fs
         RI7quqCqjHurx8Ck5/jACwiHHGP3qvR4hflR1D8Rj3GNyxTYPYX4f6szfxv2bj4LrZLw
         WvdaZQOEq52R5lCZY4mG+pntwnEceuikoweWYCszcXUv3d1Na74tHJ41vOWNqCaW7thi
         ZpZDAiCULRFFEa5yQaCK8mIEk4ouaVWorkoqsv/tGW9E4eWxR4reAFjELx9Xn9h4x6d3
         27vuYGKroP1Y4rJ5MnHLBgJpba6Y3ihuGAR+KbhLBojHfl+8DrjVxO1+C4aZYZQ58W+2
         F8jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:cc:to:subject:from:message-id
         :mime-version:sender:dkim-signature;
        bh=Hmf1TM/K0gkULlcU+TQ/kZGcmbKObdaGD71FVuMR1m8=;
        b=DWyb5AuGXmqL5cYY/4pmSrxt8f7esCJjKBz56YIRFA2ew5YopjojwbsFIN9wpSBqzu
         LEdnbPyaD1IUjf2ASj1HpSL69rDMmbx8pEII2OvMx+aMJlpXjwItTRoLK3gi50L0nZn7
         IQsreJBdvTCSUUhE6PNjVRlcGhw/YKzJWS0NFknc3Qt9peSyRuteE39tbRCNec2iHLaE
         FREsKYdWuV1VNGhh3i/c4cvoIcRhooY/7EbabLfONaxyi5O6XqJOMDnDtXcwJnl8k7k9
         JNlmAsB7lOYBBRLkJB9qlc3ugFjY8w6L9onLLF3+L6ky6TjoVXBLD/gSBLr5NZhNnyR/
         xGwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:from:subject:to:cc:date
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hmf1TM/K0gkULlcU+TQ/kZGcmbKObdaGD71FVuMR1m8=;
        b=sEBqA5vQFl5EH4x9irtlWtQI3EK8aW8hb+ybQEHEp5peLfUw3CgAU1AI4kInwBEutU
         jyP9L+hDzK53KrftplS4KkxLFQjPELj8umfyDfn+IAJ2HnSJHviX2qP+VpL994F1hMYf
         c7HCncOBBuSDPKHnd1KBkaqAtH6pVePgfgAtS2bmp3h83G3YWTXFe6vXtvfOoBWbPlMp
         0k+4ZUjAgznis/772j3gaQAEP/mnmPi9uTxnKDvIFFyXDJmQ86symAFk+TDrdKX+51mm
         r6pmhWtZ1HIYNUH8uZg77uVaI8CCJK90DaaNtj5LGfJD3wz9iV1DdmSQU37tEzQUHNcv
         R+Qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:from:subject:to
         :cc:date:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Hmf1TM/K0gkULlcU+TQ/kZGcmbKObdaGD71FVuMR1m8=;
        b=JEm2NXcMqaAovErFn/2a2ZjK2oIUObNV6jCEo871+CxIRK5bQQyMoeZ0Y1EFzO8g4n
         FDTfWevJS7UuERPKQ9zKyPy1DSl5Ju1QgTdiPv4lnoIqfBS9Asfh6NTp6MVQb+TtLLhz
         +d8dt12kPJnZnQ/amKOTrIh/TdxZvQH7XsV6Cszi9QywY00Hz9J6LgwcgpBsthMICUs8
         TneyW8ILH9SkShzljIwwV61gWRpAu2kykIlNKfbrqAF5GY5pnFbyTdPYS6vP+UDW7Gzi
         aJ407Ld1CYd8+t2iXI8VrtmMD9B7dpembQJQ/46unYLam9CZoutFWAInsQgQcPjCy+35
         Q2cg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5339jhIscFpeqUUkEVMskNiqOKQLn59sj5d+kw6j4HpCocigo0gc
	Ku2tE3Tu03MDaRoNxJSj24k=
X-Google-Smtp-Source: ABdhPJy8KROw1Ogv7yYbKj94S8rj/B90O965FIyIWx0LpFXSsSxGaNu0v+VHpKc1GzbmdEc+IoW2lQ==
X-Received: by 2002:a1c:6605:: with SMTP id a5mr54925wmc.85.1614792465423;
        Wed, 03 Mar 2021 09:27:45 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:60c2:: with SMTP id u185ls1512848wmb.2.gmail; Wed, 03
 Mar 2021 09:27:44 -0800 (PST)
X-Received: by 2002:a1c:32c4:: with SMTP id y187mr88937wmy.120.1614792464569;
        Wed, 03 Mar 2021 09:27:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614792464; cv=none;
        d=google.com; s=arc-20160816;
        b=OZfWaN8ZO+VyhTAtvvjt+XzVwbVaw7ACrsC9B8Ep/DWyHtVINZJTZr681A0bGLOs9/
         90wR+CueaZmgqNBgGjI7ftB7lyw3fvksal2o1M3jwwFvZlD9hG0YEgZ9bl4Rb6rv6M25
         gq/b3b7fd9+cvfXlXujLf3mD7F61ovZMHzVo48/JK760IYAijtzukJV6onGm9qgOrwIj
         fsss16ITMY1I1pvB2NCpUTSLhrcbpXBV2bjTNtCwRJPAyhNXEwzj7zSo+KBWg0g2X2kA
         v0ajNLzaWE4l61ncLXkJgAzxTUEXbOEMxhzLHCI460hpko73TaOzlyvHxXnqg7xRefTO
         9w1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:cc:to:subject:from:message-id;
        bh=p6EuyC6w2DeYISnwohQkHFq4ntcOYmUvEU7UrC+Wjrg=;
        b=Qlz14Bmo/4eVgD9wu1MrOe13l2QQB7bTDTheyFPr7zhEpv9MgKmFBODJWxDtZ92qq5
         YxYbGVSDJffUVQ/ysuN8N+2aVkz91V0582gLnUeWj4ELBl7A0E6zaXs3K5J6OER82xjC
         m6+L8kM1RDxbcHA7Ml1KxJZGRcK+tsA/50fA4hRkgisSypiEpnnYWusFaeTwzLfXU2mU
         6HTjWtxRaVySWZvKW5849OL6bA9x+PbSWPQ2GC9/aX0RuYykMJyR9bcZ28V/vPDia/AI
         /ZAvenzlU0KzVEo+mNi9ELAIY8Wt4xN6H1hZ1eB4kbxMAC5tkJvvv/uQjYj7NygB6zNI
         70hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id y18si1084198wrp.3.2021.03.03.09.27.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 09:27:44 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DrLYC63phz9tygT;
	Wed,  3 Mar 2021 18:27:43 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id hir2rm8ii5Yn; Wed,  3 Mar 2021 18:27:43 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DrLYC4z7Cz9tygS;
	Wed,  3 Mar 2021 18:27:43 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0BCED8B7E8;
	Wed,  3 Mar 2021 18:27:42 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id RsjDGPmwO4Gn; Wed,  3 Mar 2021 18:27:41 +0100 (CET)
Received: from po16121vm.idsi0.si.c-s.fr (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 9BFAA8B7DB;
	Wed,  3 Mar 2021 18:27:41 +0100 (CET)
Received: by po16121vm.idsi0.si.c-s.fr (Postfix, from userid 0)
	id 40E9C674B7; Wed,  3 Mar 2021 17:27:41 +0000 (UTC)
Message-Id: <20dad21f9446938697573e6642db583bdb874656.1614792440.git.christophe.leroy@csgroup.eu>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Subject: [PATCH v2] powerpc: Fix save_stack_trace_regs() to have running
 function as first entry
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
    elver@google.com,
    rostedt@goodmis.org
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
    kasan-dev@googlegroups.com
Date: Wed,  3 Mar 2021 17:27:41 +0000 (UTC)
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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

It seems like other architectures, namely x86 and arm64
at least, include the running function as top entry when saving
stack trace with save_stack_trace_regs().

Functionnalities like KFENCE expect it.

Do the same on powerpc, it allows KFENCE to properly identify the faulting
function as depicted below. Before the patch KFENCE was identifying
finish_task_switch.isra as the faulting function.

[   14.937370] ==================================================================
[   14.948692] BUG: KFENCE: invalid read in test_invalid_access+0x54/0x108
[   14.948692]
[   14.956814] Invalid read at 0xdf98800a:
[   14.960664]  test_invalid_access+0x54/0x108
[   14.964876]  finish_task_switch.isra.0+0x54/0x23c
[   14.969606]  kunit_try_run_case+0x5c/0xd0
[   14.973658]  kunit_generic_run_threadfn_adapter+0x24/0x30
[   14.979079]  kthread+0x15c/0x174
[   14.982342]  ret_from_kernel_thread+0x14/0x1c
[   14.986731]
[   14.988236] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B             5.12.0-rc1-01537-g95f6e2088d7e-dirty #4682
[   14.999795] NIP:  c016ec2c LR: c02f517c CTR: c016ebd8
[   15.004851] REGS: e2449d90 TRAP: 0301   Tainted: G    B              (5.12.0-rc1-01537-g95f6e2088d7e-dirty)
[   15.015274] MSR:  00009032 <EE,ME,IR,DR,RI>  CR: 22000004  XER: 00000000
[   15.022043] DAR: df98800a DSISR: 20000000
[   15.022043] GPR00: c02f517c e2449e50 c1142080 e100dd24 c084b13c 00000008 c084b32b c016ebd8
[   15.022043] GPR08: c0850000 df988000 c0d10000 e2449eb0 22000288
[   15.040581] NIP [c016ec2c] test_invalid_access+0x54/0x108
[   15.046010] LR [c02f517c] kunit_try_run_case+0x5c/0xd0
[   15.051181] Call Trace:
[   15.053637] [e2449e50] [c005a68c] finish_task_switch.isra.0+0x54/0x23c (unreliable)
[   15.061338] [e2449eb0] [c02f517c] kunit_try_run_case+0x5c/0xd0
[   15.067215] [e2449ed0] [c02f648c] kunit_generic_run_threadfn_adapter+0x24/0x30
[   15.074472] [e2449ef0] [c004e7b0] kthread+0x15c/0x174
[   15.079571] [e2449f30] [c001317c] ret_from_kernel_thread+0x14/0x1c
[   15.085798] Instruction dump:
[   15.088784] 8129d608 38e7ebd8 81020280 911f004c 39000000 995f0024 907f0028 90ff001c
[   15.096613] 3949000a 915f0020 3d40c0d1 3d00c085 <8929000a> 3908adb0 812a4b98 3d40c02f
[   15.104612] ==================================================================

Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Fixes: 35de3b1aa168 ("powerpc: Implement save_stack_trace_regs() to enable kprobe stack tracing")
Cc: stable@vger.kernel.org
Acked-by: Marco Elver <elver@google.com>
---
 arch/powerpc/kernel/stacktrace.c | 24 ++++++++++++++++--------
 1 file changed, 16 insertions(+), 8 deletions(-)

diff --git a/arch/powerpc/kernel/stacktrace.c b/arch/powerpc/kernel/stacktrace.c
index b6440657ef92..a99bd3697286 100644
--- a/arch/powerpc/kernel/stacktrace.c
+++ b/arch/powerpc/kernel/stacktrace.c
@@ -23,6 +23,18 @@
 
 #include <asm/paca.h>
 
+static bool save_entry(struct stack_trace *trace, unsigned long ip, int savesched)
+{
+	if (savesched || !in_sched_functions(ip)) {
+		if (!trace->skip)
+			trace->entries[trace->nr_entries++] = ip;
+		else
+			trace->skip--;
+	}
+	/* Returns true when the trace is full */
+	return trace->nr_entries >= trace->max_entries;
+}
+
 /*
  * Save stack-backtrace addresses into a stack_trace buffer.
  */
@@ -39,14 +51,7 @@ static void save_context_stack(struct stack_trace *trace, unsigned long sp,
 		newsp = stack[0];
 		ip = stack[STACK_FRAME_LR_SAVE];
 
-		if (savesched || !in_sched_functions(ip)) {
-			if (!trace->skip)
-				trace->entries[trace->nr_entries++] = ip;
-			else
-				trace->skip--;
-		}
-
-		if (trace->nr_entries >= trace->max_entries)
+		if (save_entry(trace, ip, savesched))
 			return;
 
 		sp = newsp;
@@ -84,6 +89,9 @@ EXPORT_SYMBOL_GPL(save_stack_trace_tsk);
 void
 save_stack_trace_regs(struct pt_regs *regs, struct stack_trace *trace)
 {
+	if (save_entry(trace, regs->nip, 0))
+		return;
+
 	save_context_stack(trace, regs->gpr[1], current, 0);
 }
 EXPORT_SYMBOL_GPL(save_stack_trace_regs);
-- 
2.25.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20dad21f9446938697573e6642db583bdb874656.1614792440.git.christophe.leroy%40csgroup.eu.
