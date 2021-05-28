Return-Path: <kasan-dev+bncBDQ27FVWWUFRBPWAYKCQMGQEWA5XRQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 24910393E27
	for <lists+kasan-dev@lfdr.de>; Fri, 28 May 2021 09:48:16 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id t10-20020a1709027fcab02900fd1eb0b2e8sf1033265plb.22
        for <lists+kasan-dev@lfdr.de>; Fri, 28 May 2021 00:48:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622188094; cv=pass;
        d=google.com; s=arc-20160816;
        b=MFgeP+OKvVwdHmnUNBtkDerj8RAbt3AK4EwLR1VBxUZdpUfU0ylm9LSdJdbdD/rwMM
         LdMgxXIPaWP2eLdswOz44I+F77ItWUZQxG6qRtbFj4bWCs0ApQCI5YYK72j1l8HHLDi0
         0Z2BNyoA4t/vQv8RK9eUddXdOawITg3U2FWjQACP2zwjWFBMwy1xb/Kz/uQheZ6yJgPa
         IChiGzqFGO9TOwJ0fAP11W0laI8hINeIGnKHTswQxzoU/yKum+B9KaDmJFrin7+Kga4L
         TMRzLzGEfUVuwZUdBEE/43vwJXRdN9mosWOZjB8BWjd1J2G3WtMCA0Aj3hFOYUazTUOm
         EesQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=AXL1jtKZ+f0pdD0bLZhEfF73iGS1pEQ6xqeTcN4TcUM=;
        b=xcYIqBVnb5jigEsXrcvkrkflvSCFTmLlYWKtrH83ZMWv/vx7NxgCRFRvjdMuu68CJV
         iQ+8jr0v+Ch/h7ONoVsc/eIRIlVoNFqkESxjL3e4Atq0peRW0t9T5zp2hr5FGhXd0uv9
         2XPNR5wRIljh9hHOvLrsPMsRkPKSbjwErfp8eyZxPsFGUsvrZfl3msl2kVZaD8heL7Ck
         IM5WymiVuD0MRO2otYJX5ANR28ax/JbLgBU+r68RGAA41mEgl6nxoTVuH3OlIR+IEWsg
         62ex4Pzb48wk7QWHZnaaQvAwOCLhpwg2ENTuLyphOnsst0vMJYDckVqYA+XxEdi4x4u2
         gFQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Ioy3+gdj;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AXL1jtKZ+f0pdD0bLZhEfF73iGS1pEQ6xqeTcN4TcUM=;
        b=Ocqog3EDrizFF7nB3IBQqF2SAWmW4hh5MD60Vhu8qaMYEYZXiLJVXSMV9TxKPkTHkB
         hmIjP7EKlJornpV1wIAOlm3QQnhB+pImz4OorCY/y0qArstTmKSZW+7RcuOINVbL0EY5
         LRX3L5oIFavx0On3g/QtZ8gmAmV5AXGO3tIQYu8UpFtC07IaovtfK+WPWwI6wVBLPuP5
         IBwLR/uGgZky9xb5hD6nLZiRJ0gwxv311//yF/Gupn5vDjuKDj3gCAq++RwMr6he7w/P
         RTOManXL0XD1RiNyD5/faBd6FtCzUMGOgm4/bs9Kx4AEEwRcvfJ12xncVYbGHfTe0x4l
         jqMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AXL1jtKZ+f0pdD0bLZhEfF73iGS1pEQ6xqeTcN4TcUM=;
        b=GXA7SZOLbjh+z48Je18JGqFSSS1ZyfISeiVRcf04lkkP0heQzIWDRyB74N5q+pEvMq
         j8/rIYAPNJPSpJetZr1IceVE5kMURuMo2CnTVQfzXRBNFSd/r7kAt15eR6iLiBA1+jNM
         FsRG0UMmZdGcneCJ+snCpzg2UdQjEkFYQUZbPq9pGxKHDSEMhIwZTWmuJCYLXmCzk7/d
         uDMyRmAfDDjd7G+1EqvjceiHCeFqJcOnFHF8SI7QP9FodYWAPbwrWYQZ1L8uqTVRmHav
         mPVOQR2H3YjA9cnmEDlxni5X4KoQ/GW2afzCLRSG9LcRSygV6kY+wlDLUsnPoPTXzLOG
         7Ssg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533LAQp/mf2GMu9oQYTVLeFICQWlkpd97BE5pGk8XckIgnmrtIrR
	Fm28/D8yCUo13hA+BBrI7FE=
X-Google-Smtp-Source: ABdhPJwZuh42VkfVaXkR1h8URcpSeTMR/eWIU9lVJHHn1cYPX4mjSYa+OlolxdjgbfAhYPd+AcxQ5A==
X-Received: by 2002:a63:ff22:: with SMTP id k34mr7666121pgi.336.1622188094764;
        Fri, 28 May 2021 00:48:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:aa8d:: with SMTP id d13ls3170061plr.5.gmail; Fri, 28
 May 2021 00:48:14 -0700 (PDT)
X-Received: by 2002:a17:902:db01:b029:f6:4a13:1764 with SMTP id m1-20020a170902db01b02900f64a131764mr6949040plx.25.1622188094153;
        Fri, 28 May 2021 00:48:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622188094; cv=none;
        d=google.com; s=arc-20160816;
        b=SrP8ZXaZ7Tey0tXjPeItbjyGfRgJkaiED7tDVkMED6ye3Fya2gYzHXZSXsJvAV8SI6
         Wbo3zAmsVR7j5Xcxx3BVhXETueDVbtVcLuNnQXWFYw+kw/vZA2h2B4CB3XiqjVUGmAG8
         kJScCBK2AMH1ZPm+dXzTH1bMTFn2VcfqPoZTK9sfR7V1Dl0GQK43b/4t2+jL5kBCh46u
         IsYhmoL7QMvW0X7L4jrRSZ8ULwmG7dKgJc+MMqmIpnsRnOYGWFF9tzrCTKIcKdJIC5fx
         hKGky534xeWMKG3RUnDljRQZ+4hRqjmIAJTuGllyrDj/EWqPoiShmCeasVpQLpc/6bhZ
         2QYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=O0+UwnOWvhSyGbBwcAEHiHt/a9TX3pdq1WbWKHN5EuQ=;
        b=l9AIR71BDAcTPC0a/d+JKe4nhy1S0qq01934j/h8aWdFzs4x7uMSSGwHCPJuyHnytn
         rBh8v3OgJvV6M48CrerbGy1pzgN3jSf/IA3cI7J5++6bfI+SkQ18Se919Ts/wS26EHFy
         /cbMgqdLWcqRyYGMKnywX2N2YxNFvEo6ZeDzjumarkBmCzeJJ6rOyWTSnvwu9Kw1wmX1
         Oo4Cv2DDZr2TFRwXE24hCJifWXZYG5nbir/VXleuQsO4nUSMTkKS+WgzOykRq5e0mKR9
         Ve8Z0DznrmoWIY5aEcCN7CGsnrQFyFFt4oBHfm+rm6YcQlTQVh2GIkEQ2K9P36gDNIyZ
         AjVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Ioy3+gdj;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id b8si603378pjd.2.2021.05.28.00.48.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 May 2021 00:48:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id x188so2608347pfd.7
        for <kasan-dev@googlegroups.com>; Fri, 28 May 2021 00:48:14 -0700 (PDT)
X-Received: by 2002:a05:6a00:24d4:b029:2da:8e01:f07f with SMTP id d20-20020a056a0024d4b02902da8e01f07fmr2593270pfv.44.1622188093772;
        Fri, 28 May 2021 00:48:13 -0700 (PDT)
Received: from localhost ([101.178.215.23])
        by smtp.gmail.com with ESMTPSA id d3sm3713492pfn.141.2021.05.28.00.48.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 May 2021 00:48:13 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH] powerpc: make show_stack's stack walking KASAN-safe
Date: Fri, 28 May 2021 17:48:06 +1000
Message-Id: <20210528074806.1311297-1-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Ioy3+gdj;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42d as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Make our stack-walking code KASAN-safe by using READ_ONCE_NOCHECK -
generic code, arm64, s390 and x86 all do this for similar sorts of
reasons: when unwinding a stack, we might touch memory that KASAN has
marked as being out-of-bounds. In ppc64 KASAN development, I hit this
sometimes when checking for an exception frame - because we're checking
an arbitrary offset into the stack frame.

See commit 20955746320e ("s390/kasan: avoid false positives during stack
unwind"), commit bcaf669b4bdb ("arm64: disable kasan when accessing
frame->fp in unwind_frame"), commit 91e08ab0c851 ("x86/dumpstack:
Prevent KASAN false positive warnings") and commit 6e22c8366416
("tracing, kasan: Silence Kasan warning in check_stack of stack_tracer").

Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/powerpc/kernel/process.c | 16 +++++++++-------
 1 file changed, 9 insertions(+), 7 deletions(-)

diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.c
index 89e34aa273e2..430cf06f9406 100644
--- a/arch/powerpc/kernel/process.c
+++ b/arch/powerpc/kernel/process.c
@@ -2151,8 +2151,8 @@ void show_stack(struct task_struct *tsk, unsigned long *stack,
 			break;
 
 		stack = (unsigned long *) sp;
-		newsp = stack[0];
-		ip = stack[STACK_FRAME_LR_SAVE];
+		newsp = READ_ONCE_NOCHECK(stack[0]);
+		ip = READ_ONCE_NOCHECK(stack[STACK_FRAME_LR_SAVE]);
 		if (!firstframe || ip != lr) {
 			printk("%s["REG"] ["REG"] %pS",
 				loglvl, sp, ip, (void *)ip);
@@ -2170,17 +2170,19 @@ void show_stack(struct task_struct *tsk, unsigned long *stack,
 		 * See if this is an exception frame.
 		 * We look for the "regshere" marker in the current frame.
 		 */
-		if (validate_sp(sp, tsk, STACK_FRAME_WITH_PT_REGS)
-		    && stack[STACK_FRAME_MARKER] == STACK_FRAME_REGS_MARKER) {
+		if (validate_sp(sp, tsk, STACK_FRAME_WITH_PT_REGS) &&
+		    (READ_ONCE_NOCHECK(stack[STACK_FRAME_MARKER]) ==
+		     STACK_FRAME_REGS_MARKER)) {
 			struct pt_regs *regs = (struct pt_regs *)
 				(sp + STACK_FRAME_OVERHEAD);
 
-			lr = regs->link;
+			lr = READ_ONCE_NOCHECK(regs->link);
 			printk("%s--- interrupt: %lx at %pS\n",
-			       loglvl, regs->trap, (void *)regs->nip);
+			       loglvl, READ_ONCE_NOCHECK(regs->trap),
+			       (void *)READ_ONCE_NOCHECK(regs->nip));
 			__show_regs(regs);
 			printk("%s--- interrupt: %lx\n",
-			       loglvl, regs->trap);
+			       loglvl, READ_ONCE_NOCHECK(regs->trap));
 
 			firstframe = 1;
 		}
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210528074806.1311297-1-dja%40axtens.net.
