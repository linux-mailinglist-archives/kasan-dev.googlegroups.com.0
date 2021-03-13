Return-Path: <kasan-dev+bncBC447XVYUEMRB64KWKBAMGQEVTTUHKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E988339D3F
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 10:27:24 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id o15sf12942454edv.7
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 01:27:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615627643; cv=pass;
        d=google.com; s=arc-20160816;
        b=AAH3grNPp4zQts9fztzmIpbYUzDQwAhXJ7k+CbyJCPz09YgaLitn+l85E45kFCvLsf
         /p7wgjtVca2mV/bPem/LBVp2Ps8vIvdhIXwz4fBLKCvGhuTMvezqkphTixU3TQEsevw1
         sk+DyoU9Q53tfxyx4uaFsdXRndR3Z3W9X2OYOxBDMGk3G1jVDldAF9NUo/yYAQh+Cvsf
         ckQwDzGWMrkoExsLs4BU7kfIe4UvtCMFAtmX4GlwPaxpTCyY/OU1iplQ8fkxq+EaLfyK
         SZP2rNKbF9t9SpldBYdXcbOqwBqTsJXuIFOVZ0HiRKhcWqerh5US/Mk9KqK9US78lfIC
         9a3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=H5bpz0jYKD7mSvadC4ZE8UvPjjrER1unhz72oeLitdU=;
        b=ycBPaluN2y7g3m/LHLMTIvpSJQQKFfFZgYXwTzVMtjXFD3BRlTIRTMEGMlM8NRdcJs
         V96qZcBUMK3ngmP9OLaMRythBo/IWk5OyNW0EWDwr26VpLWrLuowKwlACWyMkTaun4H3
         3tLc16n+PYacuvb7AirLivUXUmGcSWs4nJJkuHN6czFw3a2hhg/+LFYYvI4EU32e7pSF
         5H2aiF1LXCUXkYgDAfz7vEZh0vasnKLKPOXOA5D5XPjfbBsTpGbeykT6EblZCeAYCfyZ
         BCKXnLkHosCYqz4gNQfII+ZXw+RiKtDAKzChjsomlfHHTQYyPnFACRC0ucS8oKE/NnNB
         jGLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.233 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H5bpz0jYKD7mSvadC4ZE8UvPjjrER1unhz72oeLitdU=;
        b=jQHzbEhvX71jeBIDAyrU3C+P5lQPWnVzM7QTpemVJi0lDXagTx7u4LIcCLfQZEP5he
         eu0ECl9n5nZOfpaSZGw/TUwuGZROCiRQCbjDrOSpMeOMelxxf01olw+63dLHPUZlIUy2
         7+QzX8XySuiKqKyIJUuUoqyIs3QjteYhvk/0u0kuB38RTEjOVG8nvuMVDoAPDUDtpQi8
         wCakf4PLQT3FgtlXgm/JWZAsGZKbIo+Hl/Uq/WgMPi7sBCOapth1NL90c7u47lOCn/oF
         0FSIiWXjW8Kvz4hg3qVRDxdemJiCnX6/6duDKUmqO745tii2tydGKtJw3m1+HFRAXaDf
         sUBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H5bpz0jYKD7mSvadC4ZE8UvPjjrER1unhz72oeLitdU=;
        b=gBm65lhp6mhz36nKAA24zOqcuRlCSV0lqJ5Dr8eUPqnbzsCCT9PMucpEi8PXQ8gMuV
         FYLaDLb8u/erldohg4YUQ4eY0DLuW7+47o3zy4y+kwiiWuQBdV88xHzND80evxt0gFnr
         uZ91y9eZUAp4cqaXEalL35gSHLt4yOvFQo+H4OtfGZ/RSa16Edox+ZJQe2/MGv3KwV7L
         rWZ4+TqLWo2MQDKqt74vIhMHwN3ov0F1Dwl1yhiZxu75LE0EAn58kzeKfw+vh8PbUgnT
         h+Y9OQJyhMfVQ6Mjw1hk1j6H2mQEQMEWaKUGhxCAXmO+s8nFoKiEMDT7oyhFTs+zHT2V
         mmtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533uxUTgGODVlmXxn9FnWjIH5NgD2S5sMJ0LT6jTKTIoOhIjrfJJ
	HSYe9mcqkc1AddL2f1q50ec=
X-Google-Smtp-Source: ABdhPJzk54hDpQL4VFn8C1PZXFP9SuH2oV/pvFQ9m/Ps/BeouzE/gEAJS29GDwIotaRNFS4DlyppZA==
X-Received: by 2002:a50:ee10:: with SMTP id g16mr18765828eds.215.1615627643844;
        Sat, 13 Mar 2021 01:27:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:eb82:: with SMTP id mh2ls3463033ejb.6.gmail; Sat, 13
 Mar 2021 01:27:23 -0800 (PST)
X-Received: by 2002:a17:907:72d5:: with SMTP id du21mr13464096ejc.167.1615627642994;
        Sat, 13 Mar 2021 01:27:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615627642; cv=none;
        d=google.com; s=arc-20160816;
        b=Awzihb+r7vQFA75lIM+8Silnl47Fn12XvZROCZ8Ld6XsMBW/p+5RLHA7vtAzC/o/v3
         O8K+Arwt8o4jTLEa8MEcMUrLSFjuS8EgyVzR5KbyB+TDcAhNYpTszB8h1K+z6gtjzr7D
         fIzMR3J4W21WcIYgsj2lp1v7n88Zkgmfw5eZSH/f2y4S47hOWEMawVOY0fKtHW+YzLWS
         tZ+UOrkhIkvS02FQHg+YYcuRBiLRAugY1u2Y/gHC3nEgmq/MVjlPpuJkxM3l1SE15Vtn
         SLwK1IWhcJYn1xt0USbkzMnSjdqDE8+wIZQ+Rdczm+X9AHnGGc+Jb4ySVrjs5+3/A2sS
         wruQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=WFcLtBl6RmKjsIRqwG0zx8sBRO6mPYJiXhHMrLe6GlE=;
        b=S300fUiZWCE9fMTyKjJAXtP6/x8omZ5rRjqiZatOg7v29A1JTr+LZ1VJWkdHRvlWRi
         qBaMKeJPGXJpEUc+9OWlTgdMY9eCNGLZ9zFFgmnZeOpoUMy7VFpWisUmIGXFDIohQOo4
         aUF8Y3krLR4X1cLzb80tSgkhuZjuhZWQWbRgw4NeX47SSl6hpcEGw8K6dV57Z65L1Rgb
         Vh0fQytPYd2lG37DhP/uMXr+OsOxQsXoOGaRkAa5HPWyIjBpO4pLtWOGtMsn4hF6ubN9
         sGZHv2DPBZkAyW/mvfnIadvH6g+Yn1WAQaLHEJPopUGpjfAPzeZPlyYxaljCR9vGWvMi
         97rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.233 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay13.mail.gandi.net (relay13.mail.gandi.net. [217.70.178.233])
        by gmr-mx.google.com with ESMTPS id w12si305008edj.2.2021.03.13.01.27.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 13 Mar 2021 01:27:22 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.233 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.233;
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay13.mail.gandi.net (Postfix) with ESMTPSA id 14B0980004;
	Sat, 13 Mar 2021 09:27:20 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH v2 2/3] Documentation: riscv: Add documentation that describes the VM layout
Date: Sat, 13 Mar 2021 04:25:08 -0500
Message-Id: <20210313092509.4918-3-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210313092509.4918-1-alex@ghiti.fr>
References: <20210313092509.4918-1-alex@ghiti.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.233 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

This new document presents the RISC-V virtual memory layout and is based
one the x86 one: it describes the different limits of the different regions
of the virtual address space.

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 Documentation/riscv/index.rst     |  1 +
 Documentation/riscv/vm-layout.rst | 63 +++++++++++++++++++++++++++++++
 2 files changed, 64 insertions(+)
 create mode 100644 Documentation/riscv/vm-layout.rst

diff --git a/Documentation/riscv/index.rst b/Documentation/riscv/index.rst
index 6e6e39482502..ea915c196048 100644
--- a/Documentation/riscv/index.rst
+++ b/Documentation/riscv/index.rst
@@ -6,6 +6,7 @@ RISC-V architecture
     :maxdepth: 1
=20
     boot-image-header
+    vm-layout
     pmu
     patch-acceptance
=20
diff --git a/Documentation/riscv/vm-layout.rst b/Documentation/riscv/vm-lay=
out.rst
new file mode 100644
index 000000000000..329d32098af4
--- /dev/null
+++ b/Documentation/riscv/vm-layout.rst
@@ -0,0 +1,63 @@
+.. SPDX-License-Identifier: GPL-2.0
+
+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
+Virtual Memory Layout on RISC-V Linux
+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
+
+:Author: Alexandre Ghiti <alex@ghiti.fr>
+:Date: 12 February 2021
+
+This document describes the virtual memory layout used by the RISC-V Linux
+Kernel.
+
+RISC-V Linux Kernel 32bit
+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
+
+RISC-V Linux Kernel SV32
+------------------------
+
+TODO
+
+RISC-V Linux Kernel 64bit
+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
+
+The RISC-V privileged architecture document states that the 64bit addresse=
s
+"must have bits 63=E2=80=9348 all equal to bit 47, or else a page-fault ex=
ception will
+occur.": that splits the virtual address space into 2 halves separated by =
a very
+big hole, the lower half is where the userspace resides, the upper half is=
 where
+the RISC-V Linux Kernel resides.
+
+RISC-V Linux Kernel SV39
+------------------------
+
+::
+
+  =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
+      Start addr    |   Offset   |     End addr     |  Size   | VM area de=
scription
+  =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
+                    |            |                  |         |
+   0000000000000000 |    0       | 0000003fffffffff |  256 GB | user-space=
 virtual memory, different per mm
+  __________________|____________|__________________|_________|___________=
________________________________________________
+                    |            |                  |         |
+   0000004000000000 | +256    GB | ffffffbfffffffff | ~16M TB | ... huge, =
almost 64 bits wide hole of non-canonical
+                    |            |                  |         |     virtua=
l memory addresses up to the -256 GB
+                    |            |                  |         |     starti=
ng offset of kernel mappings.
+  __________________|____________|__________________|_________|___________=
________________________________________________
+                                                              |
+                                                              | Kernel-spa=
ce virtual memory, shared between all processes:
+  ____________________________________________________________|___________=
________________________________________________
+                    |            |                  |         |
+   ffffffc000000000 | -256    GB | ffffffc7ffffffff |   32 GB | kasan
+   ffffffcefee00000 | -196    GB | ffffffcefeffffff |    2 MB | fixmap
+   ffffffceff000000 | -196    GB | ffffffceffffffff |   16 MB | PCI io
+   ffffffcf00000000 | -196    GB | ffffffcfffffffff |    4 GB | vmemmap
+   ffffffd000000000 | -192    GB | ffffffdfffffffff |   64 GB | vmalloc/io=
remap space
+   ffffffe000000000 | -128    GB | ffffffff7fffffff |  124 GB | direct map=
ping of all physical memory
+  __________________|____________|__________________|_________|___________=
_________________________________________________
+                                                              |
+                                                              |
+  ____________________________________________________________|___________=
_________________________________________________
+                    |            |                  |         |
+   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules
+   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel, BP=
F
+  __________________|____________|__________________|_________|___________=
_________________________________________________
--=20
2.20.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210313092509.4918-3-alex%40ghiti.fr.
