Return-Path: <kasan-dev+bncBC447XVYUEMRBDNHW6BAMGQEZQKKWWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id B164B33A3C5
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Mar 2021 10:12:45 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id y5sf13541609wrp.2
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Mar 2021 01:12:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615713165; cv=pass;
        d=google.com; s=arc-20160816;
        b=HpNMbHyYC/2sOA95/nHYBsxEnohaflfCKhj7NMlSX9xvUqL/TdoL+FdveIA1gLy4Gf
         BUPTPJFMrbC/GkMQwhRdAeZ48Ydyp7rkVsj0mrNwptxazFy8ppZu0ojp2Jp5OJH5fh91
         sWlJg2BlWiKrmrNXpLrpfgbYl5TnEm324ruBil1tf6LoYRRdjEFYpipoh9dsinb7nUVb
         8xZ+S71juP9tchJuenrTkzOHTtYh0CaSqWRoyzK4vFzzVMhV9NmC03+pTCaANgeDT4CL
         1uVyLR4PYIVcyGbmKDpV/cEyQ86aQnBewaWvexfA/WNdsZZX3SPdFbC47nMEjsrQRGVC
         lQ6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=fc4ZVXvBhaCW2q7CeIGCOdtpBYypacbso2J3VZ0G3pw=;
        b=rGdf5HOSc/G3vWt+oR/4EMFlwrsONULt/176+2zj4GsIaBlz5eCpUpdkHsNxvDLZlG
         8wNuln4xkLS40rgdR1t+ZJvIrLJekedV13GN8Xz6du0cuqLe060nORdga8IP0a31k+W1
         SYiB3oYbFnO7RlNeGnWjALf0esuihsbKsFLHCmSl9VTSzCiQZ1/BqFfkZeuOKXwGl18e
         4LcAkXJ+WPkEew9J41sr3FtISonJC9+F7IoOE54outnADnqLP5HzOfgV2z+4ciL8HBKC
         JhjWOOW+UQ2nvv2zC9RWwqK7/nP11Djg56ljoXIgWw7+0pXz3JNYUE9lDb6Wpt1GeFi0
         Gb7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.233 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fc4ZVXvBhaCW2q7CeIGCOdtpBYypacbso2J3VZ0G3pw=;
        b=mXGrfIf9caixj6YR7hcY5IxknMhBwW6uF4ZzERIn5b6glgb/DNSBUbFGD+S2yCOFZH
         C05/wWwczHO71OV3lPDh0yQpuVpSh5OIhKjIaeQCFlfTLWKl466iYJ3y3QBCRniYCi7E
         ldpnWSJQUX7/Ez5hx1j6Pi3AaeTH+ZTW/KM76FpuKGcyKzhfV6owj2DZQLtuqQ0J6oNo
         I3cV9SmWYRYX4J2TCUP6PBk+4zZbF24pw+YoDv2ASdN4eoIdreSE+c0BNNEDED56Nds4
         EuHHBposu5R+gBNLMjCMCDGbaawoFGTwEAJUUdDTyK91DX6s6gogj2NIB+lIwnk5QO6X
         +3Jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fc4ZVXvBhaCW2q7CeIGCOdtpBYypacbso2J3VZ0G3pw=;
        b=Zbv1M8rw7CPdlXx7mJxGPXbXj0yZHKFsyU/zsWcMJmKHbiKcgRPsMFquinCLaP/SrZ
         nYSrbug4lOy+McA+fZx5WnbWcySYUQi/J4EHpv/EoL9t95MJfaHHsoofP4bvzzwaeRWN
         O6e/4UwwG89x/5Ail7b+AXxT+9xp1VsQ1+u2pOS8caeChkyYA0SPlw1syGiyzDbVGEYj
         cezuilgbpcRttwmIUllxUyf2zvNU4okgjOO6JaflhMosAM/gHjdCb3P35Cgcj81tJz+X
         nuJB1HkKqPW+xyJqa8jzYp0mME9o6o8/4lx7tbdrQkXfFZzDVi7nbyfqpXcAWKGFpBV6
         5pyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530OCwWwCBEsySyrZI6qjbVosh8ev/yP41pr/UEyh+Y0aP8OdSPJ
	IH7XbEow6KNuuyf9S7IJTUs=
X-Google-Smtp-Source: ABdhPJyk4ZleiPBnha7onuqxrkRdj1ZNwxRDeOZgvdtmmOgvZYCniJVv8HpfuOZkHh9/uTR2vcgHkw==
X-Received: by 2002:a1c:f702:: with SMTP id v2mr20428012wmh.131.1615713165518;
        Sun, 14 Mar 2021 01:12:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:24d4:: with SMTP id k203ls2329328wmk.0.canary-gmail;
 Sun, 14 Mar 2021 01:12:44 -0800 (PST)
X-Received: by 2002:a1c:195:: with SMTP id 143mr20476848wmb.81.1615713164741;
        Sun, 14 Mar 2021 01:12:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615713164; cv=none;
        d=google.com; s=arc-20160816;
        b=jiDNBqTv4Abq3fjgHlHSg25v2UhLxmxlShD4VybCUHRYDHknIIOZ6rwALnhpJKx3Wq
         u3C3suBvDa10uvj6cuLXe1GJZlVOtvgfE3ymb4cIOubORkJLGekthWCnZyLGS//XmcK3
         AeUzrsRAslqLypU8KqWawkvNP6qqHKF5BHKQ9UaX1CNfUArTiYaz1GQ3TehB0y2NU93v
         kWbfOLz5JMbmriKZLd1X0VPNcp1pB6rKwKSXW+FKwUII1wtq74Lm+CUV5ppDr4jwbuFc
         E6PsbdRGPwsk/cgFrhXnfWQxQqW9NajQ6+YDREsBGqjhSlcAEik9T34ZpCwAa0f8H2DH
         +Z5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=WFcLtBl6RmKjsIRqwG0zx8sBRO6mPYJiXhHMrLe6GlE=;
        b=CKIf55Z0aqMx5RJABlqC/lF9kHI5aXge2vlc0tjXhpPAS4XIMS/NAPipPZxTv0f4Wc
         oClCUB29yNfQfSoGxLCR0wrT3pnCTkFXjIkDPKQy73tJxf3oA0dk4zftEod8VxiZ0knt
         bW6NApHXTlJzQpd5EGosGxdxXN4rMEdjAJiHtHpZAY6O3lrGCRcGh7Di1GSxIIiGE7h5
         e+nvl0wCEiYfL6dGyIqDCvXnbwGwYHGlLS3+6dfnoaHluh+fOq8Jp2K8zzEdYMMx8Mvf
         ACxwjCEsYtIw/POUkPY9kpC8y9QchfMOmtttv0LM50o3lal6jUm9/oiUz2s8tSt77u73
         EzNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.233 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay13.mail.gandi.net (relay13.mail.gandi.net. [217.70.178.233])
        by gmr-mx.google.com with ESMTPS id y12si415144wrs.0.2021.03.14.01.12.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 14 Mar 2021 01:12:44 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.233 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.233;
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay13.mail.gandi.net (Postfix) with ESMTPSA id 990DC8000D;
	Sun, 14 Mar 2021 09:12:41 +0000 (UTC)
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
Subject: [PATCH v3 2/3] Documentation: riscv: Add documentation that describes the VM layout
Date: Sun, 14 Mar 2021 05:10:26 -0400
Message-Id: <20210314091027.21592-3-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210314091027.21592-1-alex@ghiti.fr>
References: <20210314091027.21592-1-alex@ghiti.fr>
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
kasan-dev/20210314091027.21592-3-alex%40ghiti.fr.
