Return-Path: <kasan-dev+bncBDLKPY4HVQKBBJFR72AQMGQE33TFN2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id AF37F32B873
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 15:09:42 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id j6sf8450855lfg.8
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 06:09:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614780582; cv=pass;
        d=google.com; s=arc-20160816;
        b=HXeyYBHJmkThQGmIPJDuctawTbLMhehZ+pmJf2frJhzg6oZX9P1CP0h3B3UlLFw96s
         phHKkFAB8EiHL4eSP1I1MFW3OFtV0dy3Ue6HGaXxtvkjHhvw1oNfqoOrAanqMMyTELj1
         aoORdCe16c9K+cDG8uowidOHV3zQMuL2WWJmdt259/mXB9Ho9bryrt4SQAz8w05T1+rb
         +9nef6wuOnZ2OYPs3sofEDRXYqc7nd/23G3utic6kuQ0bfKq251uuuTRBi3kHRRXDZfW
         AYl96CNoFZI8iJefeJ71ce9yNWHyGzVb7io6T+vK6WFqeBv+0Zy/jj/jGzyYcFhSRnfD
         inJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:cc:to:subject:from:message-id
         :mime-version:sender:dkim-signature;
        bh=zpaN9uAzF63PxVbF6ExMO/f3Gexd2s5uvK6oL556tes=;
        b=doTq3F+pxu4szKdW86nB3wGTLgGZQ4nJfEGMi4RpCBv4LHeEQ/H7LviV7rdt5G3wkM
         wAJb6pZ0wVYi3MSw5Q/HDlDDwPYVErenPfH9vc5wvWnJf27ijGD9Ng/jJse87i9m2yUU
         isOJ9JHw5O/BDLOtLbqXYaCVXY8kvzNyDT6pXn+HyrWWy54ftaJ1Ck0zb7YCOTYFs2J9
         pJKKpVxCPRSW5ixIpJsQCksYr4ipUS8IcyZKmZ84RbfSJqn1VHaPO8P6BoCJtXnVMSN4
         UalVAlVpZtX1CDrDtsm7JPijRiBSQhCHck6Vh2W4iHccnmGoDh7lamSDXvGB3zc0dQDJ
         2dFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:from:subject:to:cc:date
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zpaN9uAzF63PxVbF6ExMO/f3Gexd2s5uvK6oL556tes=;
        b=HX0DWarvciXUUaVUNS1tAbOZQ4ltR4b53Tn6m980kfmF2zdWpxcjrv/ECkfwOS/7Th
         PuVTDnFzaA/OPC65/7n/9dHtqE0NNKk5q+ECHfRWSJntNl9ns3rbc1Am7xlmMMld/TXI
         HSbBkVCIMbIjde3Sw15dq95vnMKAVkUD5L/npjMAiNZuK18h9Mxdq+5/o/3FkXTz8ycx
         j+bvcxMR4YAlhyD40oCvcoor3c9z5ExRAL1hmJTpRdbuGXuptmFOJPrywQJSzD4JwFqt
         ubLeulGVmou+ah0kN848/uJqu9EFmcntHHZeiKjcoaDVe/O4u+ar/m7JQZe5DmIarOOr
         LYlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:from:subject:to
         :cc:date:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zpaN9uAzF63PxVbF6ExMO/f3Gexd2s5uvK6oL556tes=;
        b=tZsFaPfw8dWNlByUPTDo4qrqTZyXtE+NqpkWsA/uLbWUZm0xS+w/zmJnqTFvm9CJRR
         Z9zpDv/vuU3fsoKSlANeqYPjc9MKaReBlDscLw3FfGb1bYIV1xT1vM08/n2EcLfMk3Z1
         vSPOTXYXeqpYLAPHKYqz6/P26wZnYmSQDvQO7kivEXz47pUcpHT5Th2BD8vvwLVhfBSm
         GQH5D8Af2bvK3PxXyp9LD34xVoITrTa+zKqQjVZ6QWJ22AkD2eorDOS6aPdW2Qn8Q+3J
         /MyTEz7n8Xwid9z/kD7KdwnF1tjD9XfWoMBnvOBNfX3L+XEEJnCH8VvCwQ+mzJYo32h6
         Wrgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532H4o3zA0QnWtiK9WhVyydJcAS3PUtOCbvvaxtvdX0V8XTlPJ3Q
	+mGT1m++7XbL3lhK8VkJSRo=
X-Google-Smtp-Source: ABdhPJwS/lkKY1eepbpUkjG9KIHLuRFTLvET05FPmMCOGEm8LBOhMzkYCTUgIsuMxvt0dUzhP4F4Ig==
X-Received: by 2002:a2e:b894:: with SMTP id r20mr15443777ljp.222.1614780580747;
        Wed, 03 Mar 2021 06:09:40 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8503:: with SMTP id j3ls510625lji.6.gmail; Wed, 03 Mar
 2021 06:09:39 -0800 (PST)
X-Received: by 2002:a2e:751b:: with SMTP id q27mr15105499ljc.463.1614780579730;
        Wed, 03 Mar 2021 06:09:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614780579; cv=none;
        d=google.com; s=arc-20160816;
        b=Hu1fj6dpQNi/XM++QO3e+O+8HyhqitSa4otRJ0Svyx6JemkATn9unwFYh51WfJU6E1
         z2dnVp+EUZnyP6vIMihKsG5+mY4bbSgxuDpB3kG3ELBoxZPxJNtIalySrAk+0WwojzW0
         KVipnMcruGbqU/6jyfrFhB/5AHtnjP4YRXnEJKDDaowvd2acFXnX31T1GZVabOnlbXEb
         qF1fR6lRs8w2fFdSadwcEow7lSTbeqtG9Egmr8EfxAR8/hKFjRhuE+2QZOQmRsFE2Dcv
         XlswI+uLb3jMyR0Iv7H7wU/nckj5BP424lFOkSNDsh3L8iHOXZthZtrYRsXw0xFL9Kvj
         AmZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:cc:to:subject:from:message-id;
        bh=l/p1X39VuZElZhOZ6xVEBAlTWC+/6rHEZxEZgA07NL8=;
        b=E2fugyPVXIlVCQKNXLVbaq44eUnDQW2V7nQz0QLwFdiFqAUcEe/xISFg5T+cfIN3yp
         /JRUI5xRgamlT2Z4unKR29/hI/ZHmTS9BX1L8JnKfpUzG/We7MNKcDrb01dgdsj+q5Y8
         W/m0srfNj3HWKzMxZXXth6/MfeAfUUZ9uLKR8iq5p5fdQfjZBZQLdX1/E/0qFe0ylIyN
         0wvSbR+iFgsK6uMEJLOanC3sZPYB282kRw0J//FSUcpo/ENb9yl/uGME/A+OjgkWOpFY
         jJF3Q/F4aKnuJ5aE3QpXfv/I752rpTlvAMa/QH8wqo4PxhoHZ5oLOEsDBci1uy6iRdrl
         PKMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id e30si123297lfj.11.2021.03.03.06.09.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 06:09:39 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DrG8f5Lgjz9txvS;
	Wed,  3 Mar 2021 15:09:38 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id BmtD3ZeiCm8X; Wed,  3 Mar 2021 15:09:38 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DrG8d71gjz9txvR;
	Wed,  3 Mar 2021 15:09:37 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id E17E78B7DC;
	Wed,  3 Mar 2021 15:09:37 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id MMqpxlpSce9Q; Wed,  3 Mar 2021 15:09:37 +0100 (CET)
Received: from po16121vm.idsi0.si.c-s.fr (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 792218B7DB;
	Wed,  3 Mar 2021 15:09:37 +0100 (CET)
Received: by po16121vm.idsi0.si.c-s.fr (Postfix, from userid 0)
	id 3B0D5674B6; Wed,  3 Mar 2021 14:09:37 +0000 (UTC)
Message-Id: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Subject: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
    elver@google.com
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
    kasan-dev@googlegroups.com
Date: Wed,  3 Mar 2021 14:09:37 +0000 (UTC)
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

It seems like all other sane architectures, namely x86 and arm64
at least, include the running function as top entry when saving
stack trace.

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
---
 arch/powerpc/kernel/stacktrace.c | 42 +++++++++++++++++++++-----------
 1 file changed, 28 insertions(+), 14 deletions(-)

diff --git a/arch/powerpc/kernel/stacktrace.c b/arch/powerpc/kernel/stacktrace.c
index b6440657ef92..67c2b8488035 100644
--- a/arch/powerpc/kernel/stacktrace.c
+++ b/arch/powerpc/kernel/stacktrace.c
@@ -22,16 +22,32 @@
 #include <asm/kprobes.h>
 
 #include <asm/paca.h>
+#include <asm/switch_to.h>
 
 /*
  * Save stack-backtrace addresses into a stack_trace buffer.
  */
+static void save_entry(struct stack_trace *trace, unsigned long ip, int savesched)
+{
+	if (savesched || !in_sched_functions(ip)) {
+		if (!trace->skip)
+			trace->entries[trace->nr_entries++] = ip;
+		else
+			trace->skip--;
+	}
+}
+
 static void save_context_stack(struct stack_trace *trace, unsigned long sp,
-			struct task_struct *tsk, int savesched)
+			       unsigned long ip, struct task_struct *tsk, int savesched)
 {
+	save_entry(trace, ip, savesched);
+
+	if (trace->nr_entries >= trace->max_entries)
+		return;
+
 	for (;;) {
 		unsigned long *stack = (unsigned long *) sp;
-		unsigned long newsp, ip;
+		unsigned long newsp;
 
 		if (!validate_sp(sp, tsk, STACK_FRAME_OVERHEAD))
 			return;
@@ -39,12 +55,7 @@ static void save_context_stack(struct stack_trace *trace, unsigned long sp,
 		newsp = stack[0];
 		ip = stack[STACK_FRAME_LR_SAVE];
 
-		if (savesched || !in_sched_functions(ip)) {
-			if (!trace->skip)
-				trace->entries[trace->nr_entries++] = ip;
-			else
-				trace->skip--;
-		}
+		save_entry(trace, ip, savesched);
 
 		if (trace->nr_entries >= trace->max_entries)
 			return;
@@ -59,23 +70,26 @@ void save_stack_trace(struct stack_trace *trace)
 
 	sp = current_stack_frame();
 
-	save_context_stack(trace, sp, current, 1);
+	save_context_stack(trace, sp, (unsigned long)save_stack_trace, current, 1);
 }
 EXPORT_SYMBOL_GPL(save_stack_trace);
 
 void save_stack_trace_tsk(struct task_struct *tsk, struct stack_trace *trace)
 {
-	unsigned long sp;
+	unsigned long sp, ip;
 
 	if (!try_get_task_stack(tsk))
 		return;
 
-	if (tsk == current)
+	if (tsk == current) {
+		ip = (unsigned long)save_stack_trace_tsk;
 		sp = current_stack_frame();
-	else
+	} else {
+		ip = (unsigned long)_switch;
 		sp = tsk->thread.ksp;
+	}
 
-	save_context_stack(trace, sp, tsk, 0);
+	save_context_stack(trace, sp, ip, tsk, 0);
 
 	put_task_stack(tsk);
 }
@@ -84,7 +98,7 @@ EXPORT_SYMBOL_GPL(save_stack_trace_tsk);
 void
 save_stack_trace_regs(struct pt_regs *regs, struct stack_trace *trace)
 {
-	save_context_stack(trace, regs->gpr[1], current, 0);
+	save_context_stack(trace, regs->gpr[1], regs->nip, current, 0);
 }
 EXPORT_SYMBOL_GPL(save_stack_trace_regs);
 
-- 
2.25.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy%40csgroup.eu.
