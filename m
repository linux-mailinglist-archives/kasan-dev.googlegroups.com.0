Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBMNWZK4AMGQEC6HEW3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id CF0F29A449C
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:30:27 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-20e5df3e834sf9170335ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:30:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272626; cv=pass;
        d=google.com; s=arc-20240605;
        b=iHFhdfBD6IFqv0KhJ1DMFIU/2sn3TEY5KpOxhlAoYWso3O8AHSN+b6CNwBpNiJFqQn
         exPDzv9lOb3KKfjC7TW5NcmReikhxo3giv9u5RovMcmTnHR7TgZD/NW1ZBoCVImfsyba
         +NlNjrMhz9RtiReMImTZO8VxgEO0y4FfUauYc49b1i1oMoN8jNSea+yydaV+1IYf9eXx
         4rX/ItFbs44nO8nO4U9MbaugB8mmIA0V4UsKoo+z7aLh8RfhpDLYm+cG5UG5+v07quMl
         Lvti0kuZxN0dw/3TGkgcTVlFn9dPWcq/kiLI7aeKygANm2p+p36lSPHHfHJg1x9uL7bJ
         clRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=auYce02AEvYUm4fIFkCDHBwMYpFj28ne86RgICcL/WQ=;
        fh=KiSWIdBmjSfiifupnYyOhUGkZMybVoMsQmIkky9oyOw=;
        b=hJVwaJoq1cEhKrsTVcwaziU09cFJ45gOH26LTnabYa0+eMTV4k2B6uB8lCLILDWhel
         HiRHkGUTv06i+HiKB+MqklTqsk9dUYF39xKmO5KQWO3DbZEhVgyVV+rhfb7wT0GDJOs2
         4yKdMOXtV4VSyCU3gqRtvsdpHKp9ld33qbDy5afzPyQJZpuFwVj2tNR7oPsGZsTzR136
         G4HSz3GScDihYmiVPIq3tLY6A3SEk5wPRvifbD53L20U+wiV7c+GCDjMl/5/+ROQbR/7
         ibVuHG6WXtQww+1RJjQ/IvDF38dRB7LOoH57itPQQ5uMtJ4TtHDM+sbl/sgqrGgoqA6u
         bDTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DchzKKDs;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272626; x=1729877426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=auYce02AEvYUm4fIFkCDHBwMYpFj28ne86RgICcL/WQ=;
        b=Jtb9WmHOSMWaBzZGlZ2TF1lS3GDeeOVj0/XqS/WGeEzOJj+8tatma/Cp+QQAR6JE6s
         MZAJh2H/PdTI8BqeYP6/OT85FXa7prVIIoVS6O+N7w3shbJNZoSIQNtLLsgdDQ0ag3RZ
         kSKooihjSyQrXISt9r7O0ONvmFzmjH4DsT2UrZp+WG+ZbvT0/NwN6UOR3N6u0phh3HFQ
         4fzZne3CildNUG0sXQ3oedeN/lGh03VlkvneGjm7nySd3Uah3R8YTN4TEmlQgk6CrO1C
         LGDJLm+HOl/nI813L5CoZUUEVqhPh/Vmnhjl0VDNmP52JJ54AJiHg6ouOk8+oo5ONyAf
         iakg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272626; x=1729877426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=auYce02AEvYUm4fIFkCDHBwMYpFj28ne86RgICcL/WQ=;
        b=S52QCfUMErBBxEZq2ejueTXCyJSY8s2pbec/PxuMRfX6rwLdpnidUmG0twSmSeVsqB
         6WTh9r1C3urHb54vxO2Wc8P4oyTzXyJTWd55BBeA1N7td6EcE0EvsZwCU2lUaB6tMmGt
         051wrMeqs/Ge5zPawSFyBurqZUW2GL/SqxmB3x4oknKZ+kQz2CIyW0WGU7s9cgP6MtC8
         rFcq3Bsa8uOWytZarfEbdPfvgUDhfrybKv72ic44y3RDy9vr7IPAZkLyis9vi0EBqByQ
         dO5J7cCry8aiFxd14b8nSP+JcVQuAgEmuHQxfDbrrhPgI01g5NoTZOvCbVEFVDnLsiZf
         DmYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272626; x=1729877426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=auYce02AEvYUm4fIFkCDHBwMYpFj28ne86RgICcL/WQ=;
        b=ocX9NAyGiuO9Ujltq6WThxNYAgU1zWxTHkJSzTHAqY3tCpSfn+JoM9TmICm/1+qF9H
         uFdCk337fDUt+2GMq0tQgQqWys1TTd03V8PjX+3wE0xVayqXSK236iFL8OI8VyetH7mo
         VKkZWRqRjKlNR8rTtRGSneZ7KB83LQBg0GYQG4ujnuqqmfcHwAYtsgpP702vAapcryjP
         ZhnR66wSsq7avjPjFjRY+kOZ8dslYnbASAcQFYC7V573ItCKTR/9BoYIKT985Lw77Q5t
         g7HrWmTKNzpdA4nIF9kuFyPHRH803sCYSSHRRiEC6+pIgS5qnk6xwvrJtdDfXB7UZnlW
         PLWw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV26Cxa/Z1an55TirqHSrm3qhSOURssbANSxH+A1XRvDT3E7fJ4j/mVB2wKaQ/JovdnuZvwdg==@lfdr.de
X-Gm-Message-State: AOJu0Yww9HTTPVY0M1mMO5OkVEJ3Nv70FuNoYExMvd9Vyeh3kvwgQRYw
	0vyaWNQMOQOAWRdw98c/YE7Ly7wEUzMkKUlLwGFQaB9tiwC6QinU
X-Google-Smtp-Source: AGHT+IHBBnznDQadF1iclJ2Kt7DTu8IUPEotPlSY9Qqo5xwDr09kGRFPy9NxzVoAwQ+e90JlBBDPsg==
X-Received: by 2002:a17:902:ce0f:b0:20c:6023:2268 with SMTP id d9443c01a7336-20e5a91f157mr41548075ad.40.1729272626143;
        Fri, 18 Oct 2024 10:30:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:da85:b0:205:874d:6a6a with SMTP id
 d9443c01a7336-20d47bcca46ls19217185ad.2.-pod-prod-04-us; Fri, 18 Oct 2024
 10:30:25 -0700 (PDT)
X-Received: by 2002:a05:6a21:1519:b0:1d9:1f2f:fbdb with SMTP id adf61e73a8af0-1d92c503d0amr4770237637.25.1729272624720;
        Fri, 18 Oct 2024 10:30:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272624; cv=none;
        d=google.com; s=arc-20240605;
        b=aduqq27mrJjgnTPJi9qbY+zHSvSKfUX0QFojzQBcEVvwXJziFLK899YrPPY+xaEj3E
         vSD4bchsHObbZZY07bzSpVT9nHtPTT0/3SpMxT9NG71X92kLR5Ds+WYl4YtPNPUJZJCu
         wDDPU4gmGVEIoUEU8h+Txq9SAURBqqaURtsgvpYt79D4EauRdkDnXUrZEAodvLXVI2n2
         NKzY8juA6wKanJPBYnTDjOkIIWa2q6bsC4h3ITRH2/FIswTjDzlDpW0TnCLSZ4dgfkcs
         phveJIEIfJk4RkNQBY4Ruo2lP5eLosotKFDMyCWC7Qf/LleGxAxor8o+NP4LiKwBdnFY
         xToQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZFpXrhpElIx5U0caqw8WXCQdQvrJMpAq6qiRpCPXwmQ=;
        fh=LbsfU9OIZC9T5pvBT9rrCWBYngVvNq6pmOpHR6dSp00=;
        b=KfdfIlUwEi5MSF3eeAuA/KOXSw5M4t1gz4omjv+pvFA1jjqF3OPy9utry5AY6B618i
         +lLC/ENTQQ2pzjRddyoqFHDgxTsJsD3rroY8fn1kCFbKKoDQqj54RbnS9wlxOZSJIscX
         6+cI+hkwIqQNmCrSDVc7R9zjW5zBg3bSL2Q16+LOEaHzJXmAcvy8OVD4iLranLYCZOk8
         BCosChpK8a9e5YxaPSJPVtYfy0YvB9e8AvFHse8I+9KEdhDVYaF5y/AuAjtZ1ivL/CPe
         MV6pMy4LkrOqbXQg+lEpTwXGSXl9sWeXsF93/BNWolYFwb2CNAHUk61WQjjybbbgJsYu
         Ocgg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DchzKKDs;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71ea358512csi97078b3a.5.2024.10.18.10.30.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:30:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-71e4244fdc6so1725337b3a.0
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:30:24 -0700 (PDT)
X-Received: by 2002:a05:6a00:1390:b0:71e:148c:4611 with SMTP id d2e1a72fcca58-71ea3124252mr4810440b3a.6.1729272624262;
        Fri, 18 Oct 2024 10:30:24 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.30.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:30:23 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>,
	Disha Goel <disgoel@linux.ibm.com>
Subject: [PATCH v3 01/12] powerpc: mm/fault: Fix kfence page fault reporting
Date: Fri, 18 Oct 2024 22:59:42 +0530
Message-ID: <a411788081d50e3b136c6270471e35aba3dfafa3.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DchzKKDs;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

copy_from_kernel_nofault() can be called when doing read of /proc/kcore.
/proc/kcore can have some unmapped kfence objects which when read via
copy_from_kernel_nofault() can cause page faults. Since *_nofault()
functions define their own fixup table for handling fault, use that
instead of asking kfence to handle such faults.

Hence we search the exception tables for the nip which generated the
fault. If there is an entry then we let the fixup table handler handle the
page fault by returning an error from within ___do_page_fault().

This can be easily triggered if someone tries to do dd from /proc/kcore.
dd if=/proc/kcore of=/dev/null bs=1M

<some example false negatives>
===============================
BUG: KFENCE: invalid read in copy_from_kernel_nofault+0xb0/0x1c8
Invalid read at 0x000000004f749d2e:
 copy_from_kernel_nofault+0xb0/0x1c8
 0xc0000000057f7950
 read_kcore_iter+0x41c/0x9ac
 proc_reg_read_iter+0xe4/0x16c
 vfs_read+0x2e4/0x3b0
 ksys_read+0x88/0x154
 system_call_exception+0x124/0x340
 system_call_common+0x160/0x2c4

BUG: KFENCE: use-after-free read in copy_from_kernel_nofault+0xb0/0x1c8
Use-after-free read at 0x000000008fbb08ad (in kfence-#0):
 copy_from_kernel_nofault+0xb0/0x1c8
 0xc0000000057f7950
 read_kcore_iter+0x41c/0x9ac
 proc_reg_read_iter+0xe4/0x16c
 vfs_read+0x2e4/0x3b0
 ksys_read+0x88/0x154
 system_call_exception+0x124/0x340
 system_call_common+0x160/0x2c4

Fixes: 90cbac0e995d ("powerpc: Enable KFENCE for PPC32")
Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Reported-by: Disha Goel <disgoel@linux.ibm.com>
Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/fault.c | 11 +++++++++--
 1 file changed, 9 insertions(+), 2 deletions(-)

diff --git a/arch/powerpc/mm/fault.c b/arch/powerpc/mm/fault.c
index 81c77ddce2e3..316f5162ffc4 100644
--- a/arch/powerpc/mm/fault.c
+++ b/arch/powerpc/mm/fault.c
@@ -439,10 +439,17 @@ static int ___do_page_fault(struct pt_regs *regs, unsigned long address,
 	/*
 	 * The kernel should never take an execute fault nor should it
 	 * take a page fault to a kernel address or a page fault to a user
-	 * address outside of dedicated places
+	 * address outside of dedicated places.
+	 *
+	 * Rather than kfence directly reporting false negatives, search whether
+	 * the NIP belongs to the fixup table for cases where fault could come
+	 * from functions like copy_from_kernel_nofault().
 	 */
 	if (unlikely(!is_user && bad_kernel_fault(regs, error_code, address, is_write))) {
-		if (kfence_handle_page_fault(address, is_write, regs))
+
+		if (is_kfence_address((void *)address) &&
+		    !search_exception_tables(instruction_pointer(regs)) &&
+		    kfence_handle_page_fault(address, is_write, regs))
 			return 0;

 		return SIGSEGV;
--
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a411788081d50e3b136c6270471e35aba3dfafa3.1729271995.git.ritesh.list%40gmail.com.
