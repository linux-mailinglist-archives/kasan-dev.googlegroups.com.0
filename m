Return-Path: <kasan-dev+bncBAABBEXXVHVAKGQE4M3MPSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1644F84588
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 09:19:48 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id q11sf50217263pll.22
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2019 00:19:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565162386; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y+QvRV+j7HriQdV0ZIrbI7vqDM0RiqdHsq2G7UaE4W4y8Fxo6ri1bg0dT9Z5qI6tUc
         tVMj22YmMC5QGnw0gs3T0Sb3jXmL6OVkMzEwffrAsVoLXxRfwmAIsMgpy6eQXxWREByo
         jRL6DpGgpU8EQmkBqVJLmdOXExVXuUKkorzWAaCeEgasE9XDEr3tdzgZlJkF6vFAwcQc
         sentOkrpg1HmNpCSIeG3rCuQhfEpfoRodkZaaxRoTfHcpCGtCiGDZ8nGwV7ApwYZa3vU
         lv1ONIFxnr2VwsXOb/pb+Itq7OuGdcVe/rxfKAJJihyFu4JE+ZIKApvH/K2HKQ1GTfnb
         bZsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=N1orNbaFjRB6Czyd7E+OorM9D++uzDldAaq+DkeDceo=;
        b=b7YIV2hu8W5VYtakKnkXGkh2G4iacDYtNjatJYSZkCrXNge6pWXe1pmYb4UtuXeEss
         c15f9FpS4SdVY46QrNGfj21kgc6X00keVQhAcag6fIwihuYYRfy1AYsZigqipdYhPEno
         Q9SqE4ao6YIFYXBFAJYoSFWr0OPXWfhhBeOc6iTjOIxA2ioP7bVTu9KDI1zuwpCt/vm8
         BiS6gqAmVP2YOw7ZqRQHaEul0bEMxbVUx5rrfKRH/Ltt0b65DsmF5QFutL0ASkf20Ai+
         wXNFwYu1Qa8+njxi+l5HUOu+Z7++TDi6Mp4XfB9/oaUIY+PPCk/wVQblGm2ywOPDmc6+
         mH4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N1orNbaFjRB6Czyd7E+OorM9D++uzDldAaq+DkeDceo=;
        b=Hm/mk4RxBnecn0BViDXndN95gykP21Og8Uv62u8yVbZro0IYZeoyY8oXEGxM1tbpwO
         IlwT5JqtHER05ODo8OrZCdN3Oqyu1y+UvXLsP7pD5ZQeoqOJfq/8xuGBe4HkNDPtujoY
         S8r1AIoqFJWPgnfEM98hFbWjfrJtkk59IugSoWPoz9DYn56g+MhW8hWx95Idpt32kBIb
         2ydesCeOPZgceyhc9njTgLDHREFjGvGyPdyrmbqsX1XicaQBmaorVkI+LBw/EPY0xkw3
         9FFcnvHtgMTX1Sf2Pzv4Y53fuR/rDqOwmwetWqXeOy+c7Rh41oeqAt1oWLPMU2A8pqsU
         OPPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N1orNbaFjRB6Czyd7E+OorM9D++uzDldAaq+DkeDceo=;
        b=uMtwrvWTKkC6z9TlKTin9YOvkU6TKpSauADWnuQpItAILo9ma/gIWoLFwW+u1EilAW
         sHjrVsKjoyFxYZWVEmBNiAKxdnjx/Y6t3Qr8d+0HS/txuLnBk9eO3mIYNaAzLI5iWfn0
         wXwfJoLwGledEhurmEUw2k02+Oy6f0gyGe6EwQbdwG6K3KfUkNFM1cB+cTd/IhV8dG2k
         5N7BnNhp8AT7pry8nrCmuXVq3WTmXlaZZNNkmIAxwURDJ9bESYLrGo00c8sHynFZi0SY
         /bVgx8XPUBgkstnl+Wcr4f3DaV3QHwOYnGzheUT5PVCMNlJxFLUbiVKBeRC3hgHYc10Z
         G+0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXHj9UwFtwow22p1lbzVkxlvRpxRUR6HpgDH4Zd2/9TNxCyFZOI
	FRH2VXD+UYICkVLedppo6eA=
X-Google-Smtp-Source: APXvYqzb3GBls+lNfrH3KGqfPE2zmLGAuC0DlwahSvoUl2h0hs7YX7QrnKjfHNQgsBfN6FFazVnMyw==
X-Received: by 2002:aa7:8ad0:: with SMTP id b16mr7849733pfd.45.1565162386746;
        Wed, 07 Aug 2019 00:19:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3787:: with SMTP id v7ls1870416pjb.4.canary-gmail;
 Wed, 07 Aug 2019 00:19:46 -0700 (PDT)
X-Received: by 2002:a17:902:ac86:: with SMTP id h6mr458196plr.79.1565162386377;
        Wed, 07 Aug 2019 00:19:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565162386; cv=none;
        d=google.com; s=arc-20160816;
        b=ru/c+wUKTZiNIbdP82R6qopYVR8jz6z4bdagu7rZOEon/7lKlM6FWBvlAdTa9gKFuo
         puB0d8jHYX4F4hRj+eNrtYLcRQhTrjmm0ddHoo8wXNA1LFQ/dz480U/9LVDASeEvmD58
         UkGtvY0kQ+eMAwVwrpvJ0h2N7/YN9cs+C/n6q357eycco4p2B58gWH4B78drC9sVIia9
         enPpB5CEkqFHP8dc2Jb0x3ml/qiBXddCVSms9fA30v0zm5gQpXKVYbw2eymeFCr82a7b
         1CiCpUty/DkOXm+V3C53rbjgCkNTlB2i9Nxan5oWGUWsY78Gd8bXKLjbNugC3yEVOYup
         9QoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=2FtLF+/iQpPWQnVRfMwsbiODoPwVVcFi+aii2A/OYrI=;
        b=JAr5yCIJ09shiDIxVNLiorswClAhAwlbHUNiwj+sNOju7UpI4cBGRceemBoM58+R8Q
         3DOn8b9l5D1g4i70FVLbz6ptkTZsmhMYqORzKV0vHgH4xHYlnghHKEFvCO9CsyKofLQi
         9Dr9iag2dP4lLtkGr+N8ylaFOvh4tj6JbnunpDkHfqv/cEyN3aHo4sx12PVVBHQOyIMl
         45X4S0r4O3q9lacCZgaCT6AzYvnz1PEg8X8asXc0BzgESOO6m7PZ20Ca5f7jc/OCx6Tj
         QGnXX0WrlyhXwC0fcZXy7lshelaEuhm2Y8p83ahURxSGwc5fLJp1IYaFyrYWfoRcafgq
         6n4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id i184si3226438pge.5.2019.08.07.00.19.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Aug 2019 00:19:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x7778SIa027025;
	Wed, 7 Aug 2019 15:08:28 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Wed, 7 Aug 2019
 15:19:27 +0800
From: Nick Hu <nickhu@andestech.com>
To: <alankao@andestech.com>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <green.hu@gmail.com>, <deanbo422@gmail.com>,
        <tglx@linutronix.de>, <linux-riscv@lists.infradead.org>,
        <linux-kernel@vger.kernel.org>, <aryabinin@virtuozzo.com>,
        <glider@google.com>, <dvyukov@google.com>, <Anup.Patel@wdc.com>,
        <gregkh@linuxfoundation.org>, <alexios.zavras@intel.com>,
        <atish.patra@wdc.com>, <zong@andestech.com>,
        <kasan-dev@googlegroups.com>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH 1/2] riscv: Add memmove string operation.
Date: Wed, 7 Aug 2019 15:19:14 +0800
Message-ID: <a6c24ce01dc40da10d58fdd30bc3e1316035c832.1565161957.git.nickhu@andestech.com>
X-Mailer: git-send-email 2.7.4
In-Reply-To: <cover.1565161957.git.nickhu@andestech.com>
References: <cover.1565161957.git.nickhu@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x7778SIa027025
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

There are some features which need this string operation for compilation,
like KASAN. So the purpose of this porting is for the features like KASAN
which cannot be compiled without it.

KASAN's string operations would replace the original string operations and
call for the architecture defined string operations. Since we don't have
this in current kernel, this patch provides the implementation.

This porting refers to the 'arch/nds32/lib/memmove.S'.

Signed-off-by: Nick Hu <nickhu@andestech.com>
---
 arch/riscv/include/asm/string.h |    3 ++
 arch/riscv/kernel/riscv_ksyms.c |    1 +
 arch/riscv/lib/Makefile         |    1 +
 arch/riscv/lib/memmove.S        |   63 +++++++++++++++++++++++++++++++++++++++
 4 files changed, 68 insertions(+), 0 deletions(-)
 create mode 100644 arch/riscv/lib/memmove.S

diff --git a/arch/riscv/include/asm/string.h b/arch/riscv/include/asm/string.h
index 1b5d445..11210f1 100644
--- a/arch/riscv/include/asm/string.h
+++ b/arch/riscv/include/asm/string.h
@@ -15,4 +15,7 @@
 #define __HAVE_ARCH_MEMCPY
 extern asmlinkage void *memcpy(void *, const void *, size_t);
 
+#define __HAVE_ARCH_MEMMOVE
+extern asmlinkage void *memmove(void *, const void *, size_t);
+
 #endif /* _ASM_RISCV_STRING_H */
diff --git a/arch/riscv/kernel/riscv_ksyms.c b/arch/riscv/kernel/riscv_ksyms.c
index 4800cf7..ffabaf1 100644
--- a/arch/riscv/kernel/riscv_ksyms.c
+++ b/arch/riscv/kernel/riscv_ksyms.c
@@ -14,3 +14,4 @@
 EXPORT_SYMBOL(__asm_copy_from_user);
 EXPORT_SYMBOL(memset);
 EXPORT_SYMBOL(memcpy);
+EXPORT_SYMBOL(memmove);
diff --git a/arch/riscv/lib/Makefile b/arch/riscv/lib/Makefile
index 8e364eb..9a4d5b3 100644
--- a/arch/riscv/lib/Makefile
+++ b/arch/riscv/lib/Makefile
@@ -2,6 +2,7 @@
 lib-y	+= delay.o
 lib-y	+= memcpy.o
 lib-y	+= memset.o
+lib-y	+= memmove.o
 lib-y	+= uaccess.o
 
 lib-$(CONFIG_64BIT) += tishift.o
diff --git a/arch/riscv/lib/memmove.S b/arch/riscv/lib/memmove.S
new file mode 100644
index 0000000..3657a06
--- /dev/null
+++ b/arch/riscv/lib/memmove.S
@@ -0,0 +1,63 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#include <linux/linkage.h>
+#include <asm/asm.h>
+
+ENTRY(memmove)
+	move	t0, a0
+	move	t1, a1
+
+	beq 	a0, a1, exit_memcpy
+	beqz	a2, exit_memcpy
+	srli	t2, a2, 0x2
+
+	slt	t3, a0, a1
+	beqz	t3, do_reverse
+
+	andi	a2, a2, 0x3
+	li	t4, 1
+	beqz	t2, byte_copy
+
+word_copy:
+	lw	t3, 0(a1)
+	addi	t2, t2, -1
+	addi	a1, a1, 4
+	sw	t3, 0(a0)
+	addi	a0, a0, 4
+	bnez	t2, word_copy
+	beqz	a2, exit_memcpy
+	j	byte_copy
+
+do_reverse:
+	add	a0, a0, a2
+	add	a1, a1, a2
+	andi	a2, a2, 0x3
+	li	t4, -1
+	beqz	t2, reverse_byte_copy
+
+reverse_word_copy:
+	addi	a1, a1, -4
+	addi	t2, t2, -1
+	lw	t3, 0(a1)
+	addi	a0, a0, -4
+	sw	t3, 0(a0)
+	bnez	t2, reverse_word_copy
+	beqz	a2, exit_memcpy
+
+reverse_byte_copy:
+	addi	a0, a0, -1
+	addi	a1, a1, -1
+byte_copy:
+	lb	t3, 0(a1)
+	addi	a2, a2, -1
+	sb	t3, 0(a0)
+	add	a1, a1, t4
+	add	a0, a0, t4
+	bnez	a2, byte_copy
+
+exit_memcpy:
+	move a0, t0
+	move a1, t1
+	ret
+
+END(memmove)
-- 
1.7.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a6c24ce01dc40da10d58fdd30bc3e1316035c832.1565161957.git.nickhu%40andestech.com.
