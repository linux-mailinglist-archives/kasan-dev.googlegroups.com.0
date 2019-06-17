Return-Path: <kasan-dev+bncBCUJ7YGL3QFBB5OCTXUAKGQEXO7VIMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id EB5AB47EB9
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 11:46:30 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id j7sf6748717pfn.10
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 02:46:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560764789; cv=pass;
        d=google.com; s=arc-20160816;
        b=PrIdxkG/l8Rt10M7ro6tC4tyqmB5TiiL2XKds5feyQPLlnsnV42DlwI0Ut0Wd67NCG
         acqD4tEo2A+twat4yJXheCyQM77EvFfN9en3Ifp6QKaXudTtjPMWB0+BFiyCtkWrj+3X
         hg6GKbuYdh9SF9LJA7hcZtisjg7+/YKf6S/LOByCqZlGilUBgGnYfDIFdx899uXnsxla
         +ZeGq45K76s0T3zkELKJ+RMKFheuCi62BuO1PdTau9cdNTIIovGLz901IC3cEFjtth6n
         PGMvrB/samjXc8MZnUlSWw9G4TrqANHj04uDdLClo2NyLq0G/9SgTFdAsGDIm28u1XiZ
         8XpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date:from
         :cc:to:subject:sender:dkim-signature;
        bh=C0EnvO5SvxPgxcLRwGELJewwfENr5Nb91LfLxySiQtU=;
        b=YiZw4IduO22v8gcZsFfbrQNd7j2/G9q+k342xFDG85iUrjuBPUvNTqbqkVZ5sQqyeP
         DqWlesrgOriOdL5nXZCcOTr8a66gmxc9jDVLYzuYOj/E7sabc6iDQFsEgseObp1kwo/D
         DIN6K3mMPlxHYGN8gzCHLS/w5olrygyYfVSJw9JC/cK8+OuKsLTXg5Gj1oD7EhIcNL60
         aYqjm6HuaBKwPh1QjFa8Six01esY7jW9endtW+QxDaeTC4mu8NgunxNxdYOexEwgP2Tz
         yBC7tQAdp4vKuCbLunAntNTDspjA+Mri+GOOMcwgUHcFYEaP9XNRNuwefdXkyLwVHhoV
         6NbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="zk/6T1FE";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:from:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C0EnvO5SvxPgxcLRwGELJewwfENr5Nb91LfLxySiQtU=;
        b=TuIjO+zZwSG9hMBWLd2kmbiHMVpReE57biRmiF4kJ9TMonYzncCPtWvS72r/z+PfCw
         U6NuLi+NZ87YOAyBnJA/2t4sWaW5w07i3J2OWZGxD3QT4zsH1utqOoLs92Jv7EjoxC9z
         KGMKicVnNa93D4T7V+jwtyZ9Qm60xrkOOqAPkwv3HZwveJoiiBGEsBFWQcgCFtsvqBrJ
         imbMjSqiCHMnxFznLYsAQKUKy9s+9tZIOklvqVGP8CfYkIVZiKg3uiQ3EzdCGnyMrdgN
         RADnUmQ0gikWKHwteSOkdoWGSwJFibr/+v098xyhUVJREYafC1nLVQBJcmjtjz4YUJSZ
         skww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:from:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C0EnvO5SvxPgxcLRwGELJewwfENr5Nb91LfLxySiQtU=;
        b=Rz14axlZ0TloX1dkycfglXdGeBPJayhck6B1zNeouXYAbmcDWXerlEOP6mwCjDxAmk
         CTwoYS3oxOLatxE4akYB+6G0IZqN93Nawc9FvetoXUEqUnTDNAQFwoX9QTkDodMRW0py
         l5i78YPb4idNEpsJX4x/5JkxY7TaejgZk3fVecrm1r2VXB0h9ntPEqg3RvOKwfSKlisS
         Z03092JvMDytyKy5FMHXW9XzCUuf3A2Rz2tUkVbe6WIDexCpyXb70NZh/aT7KLzSRWNF
         FuXNgFL5e7yhOnkVcb/UakES2Ji5Qh81C0ipHKYHE5FJo3HfBAZujnWIE5Cz9s52ciGt
         re1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXE5cX5wgZ4O9wFC0OPNzmBdNxMDB2Is93VsJ7JzMhA072MtX8A
	qKtS2H8vBhIB5Lxk1LYW+Xw=
X-Google-Smtp-Source: APXvYqwTST/gm29TSUcHrhMYGyhdvgbsgZwbQlRO0S6ZF92DnFT+oDbexZfdof8Od6iLEGapo8osFA==
X-Received: by 2002:a17:90a:350c:: with SMTP id q12mr15886145pjb.46.1560764789100;
        Mon, 17 Jun 2019 02:46:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:e509:: with SMTP id n9ls3456400pff.2.gmail; Mon, 17 Jun
 2019 02:46:28 -0700 (PDT)
X-Received: by 2002:a62:3543:: with SMTP id c64mr30069174pfa.242.1560764788121;
        Mon, 17 Jun 2019 02:46:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560764788; cv=none;
        d=google.com; s=arc-20160816;
        b=rd9Jb6gWdPrmX2yuzoO69DNWkrdOuG/XxvikXHL5jz52WtMTOH9xvC73CGkv0wPJKK
         rc9/Px1ffK7GGPkzpN6zoLKQNyenpHwH3qtUOR0bFyXbabnnkX80CzRZtikPd0iuKFbV
         SLoEfFb5qBBEeXN0hT7+ui42uSxuVEJHQ5Il1ZDAwuoFGcQtZTBkkXPC0243r5yLUMOi
         kI0pMsDaLpoysNFlG3s8T421epgMQNEteeNKW8PwDriG9HTPd/et6+vKfl98a6nUIB5O
         AG7hm2q6/tLU9rTNPQGRRl+dBX1jLZlBMCjGQG5H8WyNhbZ2RP96dpNszLAiqlKn0Elr
         1tHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:from:cc:to
         :subject:dkim-signature;
        bh=dlV80nCQd6TUqGT8x/+IbRrskatxSj/+3HZkhGCDRdc=;
        b=fj6difqwgIBbxuif++/H49PdVX95rf65ylZo9tq2x2KLAKS64mkWavrYq1WIW9Tbd7
         +/JNcuI+hg3sg2Rr+qsAAuTxsg2gHyZHGQkpYK7Pd0hQ6gieoe76KBRN+UkcAB1beBAQ
         y40fsLEUYcKP/sN0FVbeZfM6ksCFxI7Nc5jyzSkgbxyeFz+BUfwu3pOrnQnXt4yLeIa2
         2BgCbrkCO86XULAVaoTa1F69k3OtP8ryoV961osI8nRahpuwYc/t+alJgyvvwfPAWPI1
         MkDMTs4rdQpqTL1Pfw+vofwEZznNlAB4yWH42QC/l37CW22merltvbfLyNb0fe995YeB
         0J6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="zk/6T1FE";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n16si100819pgv.4.2019.06.17.02.46.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 02:46:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (83-86-89-107.cable.dynamic.v4.ziggo.nl [83.86.89.107])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 497A62087F;
	Mon, 17 Jun 2019 09:46:27 +0000 (UTC)
Subject: Patch "x86/kasan: Fix boot with 5-level paging and KASAN" has been added to the 4.14-stable tree
To: 20190614143149.2227-1-aryabinin@virtuozzo.com,aryabinin@virtuozzo.com,bp@alien8.de,dvyukov@google.com,glider@google.com,gregkh@linuxfoundation.org,hpa@zytor.com,kasan-dev@googlegroups.com,kirill@shutemov.name,tglx@linutronix.de
Cc: <stable-commits@vger.kernel.org>
From: <gregkh@linuxfoundation.org>
Date: Mon, 17 Jun 2019 11:46:25 +0200
Message-ID: <156076478530254@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-stable: commit
X-Patchwork-Hint: ignore
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="zk/6T1FE";       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org
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


This is a note to let you know that I've just added the patch titled

    x86/kasan: Fix boot with 5-level paging and KASAN

to the 4.14-stable tree which can be found at:
    http://www.kernel.org/git/?p=linux/kernel/git/stable/stable-queue.git;a=summary

The filename of the patch is:
     x86-kasan-fix-boot-with-5-level-paging-and-kasan.patch
and it can be found in the queue-4.14 subdirectory.

If you, or anyone else, feels it should not be added to the stable tree,
please let <stable@vger.kernel.org> know about it.


From f3176ec9420de0c385023afa3e4970129444ac2f Mon Sep 17 00:00:00 2001
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Date: Fri, 14 Jun 2019 17:31:49 +0300
Subject: x86/kasan: Fix boot with 5-level paging and KASAN

From: Andrey Ryabinin <aryabinin@virtuozzo.com>

commit f3176ec9420de0c385023afa3e4970129444ac2f upstream.

Since commit d52888aa2753 ("x86/mm: Move LDT remap out of KASLR region on
5-level paging") kernel doesn't boot with KASAN on 5-level paging machines.
The bug is actually in early_p4d_offset() and introduced by commit
12a8cc7fcf54 ("x86/kasan: Use the same shadow offset for 4- and 5-level paging")

early_p4d_offset() tries to convert pgd_val(*pgd) value to a physical
address. This doesn't make sense because pgd_val() already contains the
physical address.

It did work prior to commit d52888aa2753 because the result of
"__pa_nodebug(pgd_val(*pgd)) & PTE_PFN_MASK" was the same as "pgd_val(*pgd)
& PTE_PFN_MASK". __pa_nodebug() just set some high bits which were masked
out by applying PTE_PFN_MASK.

After the change of the PAGE_OFFSET offset in commit d52888aa2753
__pa_nodebug(pgd_val(*pgd)) started to return a value with more high bits
set and PTE_PFN_MASK wasn't enough to mask out all of them. So it returns a
wrong not even canonical address and crashes on the attempt to dereference
it.

Switch back to pgd_val() & PTE_PFN_MASK to cure the issue.

Fixes: 12a8cc7fcf54 ("x86/kasan: Use the same shadow offset for 4- and 5-level paging")
Reported-by: Kirill A. Shutemov <kirill@shutemov.name>
Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
Cc: Borislav Petkov <bp@alien8.de>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Cc: stable@vger.kernel.org
Cc: <stable@vger.kernel.org>
Link: https://lkml.kernel.org/r/20190614143149.2227-1-aryabinin@virtuozzo.com
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

---
 arch/x86/mm/kasan_init_64.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -194,7 +194,7 @@ static inline p4d_t *early_p4d_offset(pg
 	if (!IS_ENABLED(CONFIG_X86_5LEVEL))
 		return (p4d_t *)pgd;
 
-	p4d = __pa_nodebug(pgd_val(*pgd)) & PTE_PFN_MASK;
+	p4d = pgd_val(*pgd) & PTE_PFN_MASK;
 	p4d += __START_KERNEL_map - phys_base;
 	return (p4d_t *)p4d + p4d_index(addr);
 }


Patches currently in stable-queue which might be from aryabinin@virtuozzo.com are

queue-4.14/x86-kasan-fix-boot-with-5-level-paging-and-kasan.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/156076478530254%40kroah.com.
For more options, visit https://groups.google.com/d/optout.
