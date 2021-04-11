Return-Path: <kasan-dev+bncBC447XVYUEMRBUOOZSBQMGQELA7YG6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B28F35B624
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 18:44:02 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id s13sf4925171wrt.21
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 09:44:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618159442; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oj42mMh6PgN2v4MEH8Um6UDX5Udm6ifcuhOp56/SD0rdRCMDHCLvAW7jJhXvr04QQn
         E2aOPKPhuxj0qaRJusUB447no/iXNvV/iz3w608tTvzjQoZGldbEdlAKoC7t/Sm5i9Md
         OTS5nYjjq7rJMdpQ8C/gnD4klcElM5jBpPO9pm1f9pEoVBLM6qGmw7jpJlkSqD/U8C2C
         E9a1OFn33pl9ga8cfJ3tWUEBCvCEM1M+TvDALfPhEatId1GVKXiqF+A9PGF4kCpU2G21
         2lQK0kbE9kpntW4CZmePo3+ITFMAKvdF3gBx6cmZ+aKiGqkkpeKy2+4CDB/VIrCvCKdC
         /EQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=xQXHvC8+Z1aOFz6B7BvN5MFgrbK6RbuLjxsHrfDS1Mo=;
        b=N4nSnStyK6PZKGYH2VwHS8W4T3oRaMe7wq7Zuf9qhtx4kUcrNucZYIbdZ6PX40vmYz
         ak84h3GFezHusZFBFko+/PH14Uc+++aJLDgtmML7wvhy/YquGjx43h3gt4svQg6Ie0pJ
         rdUnYi5/XxmCAvc5qz3/xr8r6BtmtZhFD/vc37CP5aGtqexs7s5WzExeh1rwUN2HIj3A
         jRF5ejjbdmMwQlzoKad5OcmC0A8HxoD2Z7l2kJbXSJQFGL/L0gg7qw1BgJwsde8D/In3
         xoixU1xms0cuYpgTkoN44P5/TMDeFZylvwJ8wKIwGNQ+5XbHVmqKc7XqbtRUkgI/5KwS
         jtwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xQXHvC8+Z1aOFz6B7BvN5MFgrbK6RbuLjxsHrfDS1Mo=;
        b=gFAe69dcSIuhIdYH7NJaF4WyjTcMzubFedLQay/+cjkQBWRjfDiTxVr6JbA/qDXw3c
         EzihhXd1vNJewqeDIK2z7qmAIwk9lS5weVfSDFDQTSH6y9U0ZpfvkIynmmxZRiStm8Jr
         dLjuY43V8Vel8kVLrI+FMzkI0wzUmoyxSU+YluR4Pz9vEZOZt2OgXY/uB6g2mb+t/UXl
         dHzqeRgDNBYgA78rHjN/eIyMwYv7JjM18pWd5EXrrCMgf6RvshZyj44gaTjyqB9V80Ff
         RwO7dgCB2TpRv+fOsnqJBEXf2f/K3XSMUQz15K5iFUYhDo800h+8oh6TlMiXf8zxLlgk
         Rr/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xQXHvC8+Z1aOFz6B7BvN5MFgrbK6RbuLjxsHrfDS1Mo=;
        b=s+Hvr72X4AXzdzPJ9F4FrTMI7AfUh2nT+SzakhYAgc+0GwDmWXUs2bbip47R1iFns0
         K5i5+A9uYyZ8GSROpXOUpXnXKDCwWSwAY5q+r/1iM4JuC8JaDJsyV4s3FXg8lluuWlgr
         H+ROHuOgWigRvlbuQE2ruxIo9lliYWKbkSACS90bJeiZfPbtOawvcpNC20xApal6xVQG
         wuZ/3INnN+LEbf2kpsQXgP1rm7hpmRi1XeZN/guVq+bRpdBWPsLeNex/5/UPwdSA8K28
         zddizcxR1nBwd4o8isZhBh08wyNcc+hcs79wxTI05+UfL9z/QGW1P7wcLMOXgyZI4SCq
         meXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532O6z//Nz7EyUSyOWZ9euYD1Fh9Hq+v66YHpM+04W4aNvowob9Y
	mHXQnMYSsRb95yIEpUSxDpc=
X-Google-Smtp-Source: ABdhPJyMi+VUI/BN0aKdrGUhWzacV9xsHycmtfqIYuI5oLi6SQAUSFL3UWhMmNs6cMTjO10zxwZg/w==
X-Received: by 2002:a5d:4592:: with SMTP id p18mr29176669wrq.244.1618159442030;
        Sun, 11 Apr 2021 09:44:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6804:: with SMTP id w4ls176618wru.2.gmail; Sun, 11 Apr
 2021 09:44:01 -0700 (PDT)
X-Received: by 2002:adf:e741:: with SMTP id c1mr17037748wrn.49.1618159441260;
        Sun, 11 Apr 2021 09:44:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618159441; cv=none;
        d=google.com; s=arc-20160816;
        b=KHgsnfPhZZkjzUZrrz00C08HOhk5XPFzPUrtME4iVCTNG7LWWpIMkGk0zydbl+0wuW
         PTn4btmVqVfX5ZFaxx6a2XJNEADh9Q6oIMIN/ulrqSJ9T0MiF0gFic2/mvGXCLhPuXfU
         jw15jLjtOIeEvkYcqutu76s7MVHwF9CI+p0duQthSay64vlq2DpRdNjBs+tbzXIUVXBX
         EYbj/Rdm7AuEPuyIg6VgoENVN/Ff8TURl5kc/MO5jgi8vmFs61uFa3vJhQAeoal14pg5
         +lTayajfKqcAtnWl0YATwMRPcHX7ZTokv74qEB5JzSd1cKOAG0yxKKmb2c8uXGIDmqZc
         uFvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=WFcLtBl6RmKjsIRqwG0zx8sBRO6mPYJiXhHMrLe6GlE=;
        b=bzEC+Hjezaj1EaBM5FiPpQyXpbxFQQviUJ88z0xm0N8RHtJdlbFIWBPwNjZbb9x5Ma
         wmvX6Xkn/lHl57BIH8exeFKFswGnTNQSwZWLgbmNttrQla81by6HmdC6ZI2CdrBZ2Uv1
         92cnSVIcwJDr/tapyHz71HSaP+VQrsaiHa0YgHqlu7LzG1F5oGP/aNeD0JlnUrHBOIXX
         Tag1NEd54sFpbCT0o69KEbBMtj/553nL0EjMwGZWPqjVmxouk8B5mT+I+IkEP+XKFwQ1
         750BbnrRfFMcMLh6PLrS0xF9aoZUGfTal4qRlX/74yQ/QBQiGS+E/hMBRKKUI0UJh920
         CeUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id p20si675283wma.0.2021.04.11.09.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 11 Apr 2021 09:44:01 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id 3288320004;
	Sun, 11 Apr 2021 16:43:56 +0000 (UTC)
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
Subject: [PATCH v5 2/3] Documentation: riscv: Add documentation that describes the VM layout
Date: Sun, 11 Apr 2021 12:41:45 -0400
Message-Id: <20210411164146.20232-3-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210411164146.20232-1-alex@ghiti.fr>
References: <20210411164146.20232-1-alex@ghiti.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.200 is neither permitted nor denied by best guess
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
kasan-dev/20210411164146.20232-3-alex%40ghiti.fr.
