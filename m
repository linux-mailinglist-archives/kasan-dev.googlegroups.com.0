Return-Path: <kasan-dev+bncBC447XVYUEMRBR5V3WAQMGQEI2NITWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id DDD10324BB2
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 09:07:35 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id q13sf1404693ljp.23
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 00:07:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614240455; cv=pass;
        d=google.com; s=arc-20160816;
        b=wZJuoa3H1Cn1EyfaOcYtP+dJlL1el7BMUxMZU3GfrdPlMGMs2UsZqDlZ////qurwCq
         NJ4DxQWg9limJ2x7W2UFMeXgApT5RX0/KtOCBRlIoCLWBBuiFLC5Vc/zpuhm9GrRBEUP
         MMM31ynTcP78hP/6mkwvM5o3iFCBMSiDcRA/7pcQjFBJ5IsMBoP31OfSDOTTUTQsw+jV
         iCLc1eQ0T9Mz/z9oSr/Ih0qU4OD+wVc7z7JKPtLnEmrJLlA3oRi6Iyk3KQeuwQ2SUMWG
         gLWfpFqrBps1SS1wu9j/rWxDW39VEVRaBnBXu8ypa0MFls7UzUloFkqbIKm9SdlGVIkV
         aipA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=NGh4J3AqfZGTyOF5kXsjJSdcsWw0so9MlBT54K+YRDk=;
        b=mrfvfvsUBxKxF0m+5isFYMMIFi/k9Bc+TcaQIkcOzIw+PAoDYUjt7wLGuH7Kkn34Mt
         e5nNkQ5zUGi08/XIWtmfDMUyJIPm8pflW7PdbyM7EfF/LoYKzFo022OPCk1omi8ghY7c
         /+BV+8EEkz8cL1tLH2J3xgw7gEFtYCNEpr9VOrXJgqmRKaoUzEnwtA3G0rieGgE3+Yzc
         CmJxh/6T//9Hzv7/IuIS9foeI42Maw6g2z6Ow9nDbHkd2JdSiVkO3SnMo0Ovn/2SrJ3m
         gbYLBgilu00Xp87QeTd6dEAVfZtyI1RUXwpPbkZdRZSSLHC4WlnHBxjL96+Kseoy+66b
         ZOQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NGh4J3AqfZGTyOF5kXsjJSdcsWw0so9MlBT54K+YRDk=;
        b=iRyMg2ZHlFqE49ElQDMSiF3fgdooJIwVndJr2d9Uxpmfv/9OVCxaDFkbMq2RcmvDdM
         SG3xflTjW6ekpRV9W7PpthxbsWbXVk1lpjH4/r9B7Tomi1TsfMyYoy7AQLU8oqVqNlCD
         h82EEIUYMdwmu6sMrDa2nJoEgtudiQdD/qZ2mCKRcvnVK6xaBYZ+bKibpbWDfYxby/Z+
         1mt312Ai7TYZGtXRFd7aIoXYIjZiYiBteUZRL6zfozFWT4DvKFNRv0RC7XxCN+4Xn4Zu
         vVqGJh05m1gnJ2q0AgpY9VxMUwZmnrpOeZOhgWRgierdA+HJ4pUFXyoqdHUerXIvqbsj
         7EZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NGh4J3AqfZGTyOF5kXsjJSdcsWw0so9MlBT54K+YRDk=;
        b=T0TmdS8day4UrGGf1bi3W9ZOZMmJnqvUFdYczP6nxzpu+gquPXWn5UBwvOgMtTWaIh
         kaxbfNApfSlkj3h+3JPx+hTep9k39mZdecccRyc4RucaXJanIFjn9IX69rIUUHtw1VFL
         MPHJHNon6Q427QkEaYsG85i4vpjmrAnsubMZWiFE0RkKF/BwB6VKLJ3jVCfKE+dTRLoE
         snVlAAr+Qjkd2d0dgwPOlI9LRyxjfK7HeNrjcemGJ9IOXHLCJYZe80LiYx6GCc564NBF
         qgXiXqgYl2jgPZ5KpGEz7bBZt7TisASuyZ8/9AVL9oyZqn00PnATfAT6zAwBCg3XjR63
         ketQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533IKEv7klUlyAOUBsWwfRs5uTbN+fIJrWgTpuKnmSH0lsoBliKy
	X0Wq0dCDqxmckLCtEIlweTY=
X-Google-Smtp-Source: ABdhPJyIrfyJ1W9ELRLrTriCaE1d6O6tp/tT29bSDxpPlJsPsy6J7nYQkBODPBfpolW9CXT24TBXDA==
X-Received: by 2002:ac2:4acd:: with SMTP id m13mr1210916lfp.201.1614240455369;
        Thu, 25 Feb 2021 00:07:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a409:: with SMTP id p9ls591119ljn.0.gmail; Thu, 25 Feb
 2021 00:07:34 -0800 (PST)
X-Received: by 2002:a2e:9e42:: with SMTP id g2mr1013240ljk.94.1614240454396;
        Thu, 25 Feb 2021 00:07:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614240454; cv=none;
        d=google.com; s=arc-20160816;
        b=JdldSlx2JZ/FjLXEaQPAApzN4Cj4kHZcfn3gnmfPJQ5yCvLuUQgcYevTaIEt4MU78F
         QzEtgyqpl/u+1FHFHPocpfT9+EBZVm2y8fMjpIKasMuDSmXFhtowX745gNHJeieq2NkE
         /u8GUkCiEtwUiD6i8yooy9LdS2mCBvr/6qQn7UZyklyhVa6JPr9lwSZfFCHJLRFwbmw0
         H04RutnNfihnGvreuo4/2jTDyN5HzL3JgidN5Oq6xtegkwpEXKg6Vk854ujyPN4ZRA0/
         c9vo0lfOuvhbhD4hF7vyghknneYF3eluTanryKeda9YLnmyhCNVE/BdZQc4iCZVwYcZL
         w4QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=F6pdI9z3UQbsR5ipulUys7eGQja2lsllBCEK4vYtI6o=;
        b=ST/3izZqWZQlsE8AslowkpE0sUtWcklMgmR+iDjbqLrOqWXLuC4L014D0QbZtmqF/f
         LbUALUANfsTzWcjJapd0NcSP1tS9sJhbg3MfXBfnXlTGUeXnttrV59R5Ua1jFL0tusIq
         Wlr7oskCqpa7shB2ewE5qXyroGs0bmAOs8bMuY7meMXAiUblOxo25G6wQJLsFZ5jKt8O
         HabE0CRCwqLlWkeSwghiotBNubjQ50h5J4bPhkoBiULPLHWpkRPg2/FTC1uZCbfJDk/1
         lycuGO/8xDstLaMtA0dVu0kwGKI2zMA4C1bZVQ0NYoazn7rWknTS9Ldn0glJIXe7bMHN
         OZJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay5-d.mail.gandi.net (relay5-d.mail.gandi.net. [217.70.183.197])
        by gmr-mx.google.com with ESMTPS id x41si152967lfu.10.2021.02.25.00.07.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 25 Feb 2021 00:07:34 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.197;
X-Originating-IP: 81.185.161.35
Received: from localhost.localdomain (35.161.185.81.rev.sfr.net [81.185.161.35])
	(Authenticated sender: alex@ghiti.fr)
	by relay5-d.mail.gandi.net (Postfix) with ESMTPSA id 8DAD41C0006;
	Thu, 25 Feb 2021 08:07:26 +0000 (UTC)
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
Subject: [PATCH 2/3] Documentation: riscv: Add documentation that describes the VM layout
Date: Thu, 25 Feb 2021 03:04:52 -0500
Message-Id: <20210225080453.1314-3-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210225080453.1314-1-alex@ghiti.fr>
References: <20210225080453.1314-1-alex@ghiti.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.197 is neither permitted nor denied by best guess
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
 Documentation/riscv/vm-layout.rst | 61 +++++++++++++++++++++++++++++++
 2 files changed, 62 insertions(+)
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
index 000000000000..e8e569e2686a
--- /dev/null
+++ b/Documentation/riscv/vm-layout.rst
@@ -0,0 +1,61 @@
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
+   ffffffe000000000 | -128    GB | ffffffff7fffffff |  126 GB | direct map=
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
kasan-dev/20210225080453.1314-3-alex%40ghiti.fr.
