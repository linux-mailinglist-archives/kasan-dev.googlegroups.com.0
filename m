Return-Path: <kasan-dev+bncBC447XVYUEMRB6HCX6BQMGQEMUGJOQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 56ABB359548
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Apr 2021 08:17:29 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id gj5sf1110750ejb.19
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 23:17:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617949049; cv=pass;
        d=google.com; s=arc-20160816;
        b=cNAUQjkgAaHsmHE7tyOFx/LWHg4mz4ToPns6Eqd6G7bG7xzd3Z6g4dFEibU42PXL5k
         8Lc6sXWkGV+uZWFQ6mS/1lz9fmB2KiQypyBe7BMKqX/YjIk2GrUb81F9B7oP4BdREgt1
         57TWIU3Inza6SmDBh2oaKYYeoAxGZ1PE3Z9Rn9CwVplKtNgK0wj30X8fvMKmgm17cCIR
         G22+p2ILRsFlY4ezKyoKebe+Agld9i+ItzQuu86hS3OdZweQ/EDO2o34ai4sJ0gYK7HZ
         XrUEFwd6P6MH7ETLBGP2LhpfySj5L/3LxZ0hvDmYQ5jERJq2TdS2WMHQgebVJf1/0NLf
         dBFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=92QQ77Wn8p044nh7qffMpaQbaBxFYxVOFBNUrfg9E10=;
        b=YjfGAosYcwOYys8ZKiqGMVW7BXuBISMQf1arBKQNZTex45mo8wWAbQ1o9tXsV3Vfzy
         xVxIjpRNTR7CylFP589WYYQe2DhWd6QjUNugX+EsqrXR7lm2hNpE9hWe4n+O3w3FqKwc
         +JG/cpUXJesUuTwjde6euNv2ipT0oZfrSHMTIr56nOQIEcqnUN2k+qqiSjHyxf8Y4eM1
         TLvT/WPb8z16LFb6B9XscZ2EER69E6/8dlu2VhMysg1coGA+G9nYXOgh5WpqM2Cy8Jg2
         76UexE6aa9CPgP4d1R20cNg+dedTggikU0DLI1hQweGhIh5TXlrehh36i+p8xyk2x82i
         xr7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=92QQ77Wn8p044nh7qffMpaQbaBxFYxVOFBNUrfg9E10=;
        b=Hdv8k3j07Rd3hBgZqDsp9GN5iRqpBLFfMxbUsu7wCzT7sycYtiKenA5mIeQQDA4Wpu
         LnmWCN9JCuoIieE5MhSi1kGetTumWiI2J0XqAugws27Pf9XZOUQcvxXxd0Hf8zqcEtsU
         +Imw+OBQ/bT3bI2C6Pc+KBvoRyt6b06ZnO+q7Y1a9JoR5WRaopDDXBl/tUlVCuhyuHBT
         L6R/B6YVktusha4TrjLH+pCBn0gwI1KuTVOL993f6TFVUUbPLF6MaVzUrKnis4Vbj8Ri
         enC7hui4HAawPza3u45HVDhV6Jh4eR62I02YuSq5JTV10AdzJ6MtZFYvlQBhJ1HacAC/
         VerA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=92QQ77Wn8p044nh7qffMpaQbaBxFYxVOFBNUrfg9E10=;
        b=dbr8FPyGChCk4HHNMGPgHDmhoLM2o4IBofjhwiLQcII4j+OrUgJ4pyU28jBLfAnSWT
         OlU3nXJRWBjaWvjCw0cf6DF9WaAzEpm/+vkW0gvP5AQgocmEt0L06JxLpg43cvHgj16C
         IkNw2ypI8o75UIKuRLctlMLf4oACX3Pqze/Bj/osH8KncbrVW6rRAB5efrWyIW0X2fMr
         D7HDx66NediGZjvCwvcWqlmf+wwUj6Ey0WGdpVrYeEzjHe7sSlqa1iTRlX+pYLCPsaRF
         6Fkvc9xPMkEcHTHs936vf/2SvGfAilXHC6ECHOLl6ongX3XpGCofCeq+J00GoBODY9KY
         13/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532QC3yXzaGZswdSVk20ro+KV2vasSRtNrOu43diqvKg/XhWD64x
	Ca9Q1T4t2P11GkXSnTQtMOo=
X-Google-Smtp-Source: ABdhPJwbWr1LhzRHkdQngNvRJ5y4CTslQy/aLB9wtUgizWUj+eHWyjdYfz2zqQvs/9Y9fzCcoVUAJQ==
X-Received: by 2002:a17:906:190d:: with SMTP id a13mr14605690eje.330.1617949049086;
        Thu, 08 Apr 2021 23:17:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1901:: with SMTP id a1ls4575369eje.0.gmail; Thu, 08
 Apr 2021 23:17:28 -0700 (PDT)
X-Received: by 2002:a17:906:2dcb:: with SMTP id h11mr14805617eji.278.1617949048171;
        Thu, 08 Apr 2021 23:17:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617949048; cv=none;
        d=google.com; s=arc-20160816;
        b=a5bKUkPuyjCfd0UL4A+L14K4REbw73Nmx2xbGnmYBbyFHycqlYRM3CNPsaOasePiWJ
         YbP9kk/8a/i/YA6bo4UGVWaM2VNc0INuU6NtmrwMgCEZDp9cFCZ/tPGwhiTxFKM+560x
         +I0k+cFgzbM4PZFbtl4sxCr6CzsRJ2mGRQO1IfjvTqduAsRGDtccAFlWONJKOmAPzCji
         s3s8eewaIgX2TyivPc5LLacbr2OKWczpro+JZ5ZQ4iDjexx/7fIHT+gazODoo1o1mZqZ
         NGmWJkssiZMTrYlj0p/9oCo3WOEAEcc2hQXI4zmq/Gr587oixdFHg8L/GvML6bwAGXOk
         Q5ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=WFcLtBl6RmKjsIRqwG0zx8sBRO6mPYJiXhHMrLe6GlE=;
        b=vMou6W7/l0L2IRGz+ei7NQW/AXBIPCuPjI9sTvcAQve9D15pkQiRZydUpeCmhixA4Q
         jggtzw1TGxrDwD5kuXf6N6FNt7EuyU+NK5/QU9UkiHBZk39WeGMWdJhKofUR46FspDUz
         BEd0EQAA5z0cqnJ3twepB8UULfnpgpkB8HoYB5hALW5m7wwuuMyyAQqzfbdjCic2EDSd
         /fH9+aTGNuVxKaQ+PUUjZjWqR6w0ckDMPT+3NGA5QfZzAILA7NJJSQO0OmFce2/SPSK6
         j7MHxclY40rpyXEaCCOA9FnNy+nygyHyhk4MLe18EbitAh+XLahyhKMbpiHDe5obsgO1
         vScA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [217.70.183.196])
        by gmr-mx.google.com with ESMTPS id c12si308563eds.0.2021.04.08.23.17.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 08 Apr 2021 23:17:28 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.196;
X-Originating-IP: 81.185.169.105
Received: from localhost.localdomain (105.169.185.81.rev.sfr.net [81.185.169.105])
	(Authenticated sender: alex@ghiti.fr)
	by relay4-d.mail.gandi.net (Postfix) with ESMTPSA id D86D3E0003;
	Fri,  9 Apr 2021 06:17:23 +0000 (UTC)
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
Subject: [PATCH v4 2/3] Documentation: riscv: Add documentation that describes the VM layout
Date: Fri,  9 Apr 2021 02:14:59 -0400
Message-Id: <20210409061500.14673-3-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210409061500.14673-1-alex@ghiti.fr>
References: <20210409061500.14673-1-alex@ghiti.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.196 is neither permitted nor denied by best guess
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
kasan-dev/20210409061500.14673-3-alex%40ghiti.fr.
