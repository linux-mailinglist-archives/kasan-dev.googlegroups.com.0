Return-Path: <kasan-dev+bncBAABBJOYYCHQMGQE3JLXDWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 368D549B960
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jan 2022 17:58:14 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id bn16-20020a05651c179000b0023a6f7f0bfasf1731457ljb.23
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jan 2022 08:58:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643129893; cv=pass;
        d=google.com; s=arc-20160816;
        b=KSi8K3p8nzqnxGzLeUJ76kc6PGj4O26UIuTUyra1AB3P4528hLfI1+EcKZJiC8t8di
         Xi9R0lhj9+Kd2bVRIlRdqMKGtJxkiriLbqdkZdQSkn+MWXZmfw2zyLUGjLtWUyueSu9O
         eqmxfuOT+3DMQExxJqhWpYIaMd/mAa+sJgTnxDdCrPVNlzQahmTJ8OOrsMWuvTQSphlg
         QZ+FL4lQiHqUGGRRsg3k3rBYsW6VK4t2DO8AbHnYxzM/5J3S1U92VuP+KecOre4U6rP6
         K2TsnjqjXVRo15BWpMQuljRX74vvMbr0MDatcx5Vh4AINUucYesS8lMI3donsZwe03O+
         spyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=C/47hkQqMQB+kNkVFOOOV9WW34ui0iWvI+6Q6xSwdJU=;
        b=hx2ciAyuE4mtrc8ipFrM/k8R0ElBT2Xydg++/xDzQ5fb7zf+/SN7SAjlhsmruIqMEO
         1vfOHs5zp5tT4aw95Or6ELv+8PWBxfPZ1YbLlCKyN9xfWCpLArcC/6sh1rPUMpL+1c0d
         E7qxstthPZhph6++Iy42M1LnetiIftgupuGseBWy2g+JgySJUDGqEifeWbcC8WM1uEc9
         JxDe6X7FXCI/8uKL4BSAcuLtVTYJQ+7lY4E+SItXrpeb1xhgnKrGpNPpYL1jXMM7d6lV
         YW+eaqW60eHifn48ZwnqDqqjT43te2zJN6b1qCawWcF6Rh5siMGtKxEnhMwH2T108H5N
         gnVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EakeZI4K;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C/47hkQqMQB+kNkVFOOOV9WW34ui0iWvI+6Q6xSwdJU=;
        b=qGtxe4jwTfK5z+e7/64lfNNIs9YtUnPGGef6f93NHPP6PpaQqsW4ficVjQgQy/7xRf
         frwxwJDzfT+MQyck2ZCBEiR9O66KTbUTcgBHrP3kafY3bWxAzVOjgYjlIFZHJbGDqcEj
         fZblrPC9U0AjwmK2cavBGdNlI7Ok039KSBlncVIComX+nZA1yD2yvTyFNvlcLZ4ZpqtI
         PqFo6Yq1XIqbRckLSMWaPj3a51CVDM/8VtARbQGgSV8FLBzSF4XGls4WgUmozRxl+sWg
         xWNWwI/vAOwQO1aijweKs2LRQ3OJlagHbmEaTQJbZlSmawDhy4BrphSnDhoFFNPpxLs3
         DNHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C/47hkQqMQB+kNkVFOOOV9WW34ui0iWvI+6Q6xSwdJU=;
        b=1rQggM+b7jzOU7OfjW6fsdjWjN72CliVAJZOI/LmSj65VwlkrQ2eXsl0K+9P0OEr9T
         ObIRL2pEozJuGnL8uvg3Ru10SzA79TNDmsZJ9yHyDv4USNLGWISRzI2eR1xA5T42iQtE
         faF89TJvCQGeJG3SmHJdUNY3XfS4prlVPTyrZyNeeGAILfZSf31HMjQFzX2dlXOuip/5
         SI7KYlvke9rX7nXc0hPz764zB2ibP61mKg+ovu0Y77AT1maoZRsyUdeSgdedmtJ7DEcl
         nvDgcVhkY3WV3hEEToWkgUSqmNRivbgZmBGeiJa0DKM29lSJrldEqUuVjjyp3sC8s6xV
         65iw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5314omPBmIGQizgL1RAsHdMnsKZP+zwj6oFSpSRoHREMcwBf2hSt
	pbALegrHHvg+R4QMmgQoJME=
X-Google-Smtp-Source: ABdhPJz7Oi/fO+tGbc3yWp67bw8qrtC8bJYWjScsDpThV52MiSoLFnCjIdQwZ7bmBtZ0JDRBkx+nXQ==
X-Received: by 2002:ac2:504a:: with SMTP id a10mr14980831lfm.662.1643129893567;
        Tue, 25 Jan 2022 08:58:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a550:: with SMTP id e16ls3041686ljn.11.gmail; Tue, 25
 Jan 2022 08:58:12 -0800 (PST)
X-Received: by 2002:a2e:9d8a:: with SMTP id c10mr14679951ljj.141.1643129892733;
        Tue, 25 Jan 2022 08:58:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643129892; cv=none;
        d=google.com; s=arc-20160816;
        b=EoyYIxNeatBTqtY0I+TIuziFNc9wpuY6irqS/32SzVYyJnnDepr52mta9zSJK7oqHs
         ODPE0ErRh9OpPaCRwRD3DrBUmxsvdh8nc5MA6UvDiTnl6NQm4Z2AXvr6pmMG4fcj7P9+
         MciTe672MfZ0zY2hWZLVNS+PLo2cFgMbZ1SgRnxS71hUWIAOsCPVyEXaDWmNvUKLfT2h
         c0/IFxl0p2+DWWpBQhNth306oYbb6Dv9T6myPLk8+d6hbyUVADHD9QJvnJO1fjSMnVys
         uNmXZ+gQHPeYZBA6jNuXI1EyO1u9TI/qdIinSu7gmgeCXCpIKusKB1qyB6dr+rYh9+aD
         UEIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=zkCDdh6mXOYYxG6U56xlCkKFxOj1jSZ9X/4mOt1DOiA=;
        b=0A7tesahB2lWnAFFaq2pleclqEcHJOzU4P7RfW+HURK/nH8xCg8nAqEhhbl9RmFTGV
         eG8txiPwhQ5adPxDU9ixEzYH2TW3ExmLzmuAhrojc7P7h4XNmW2xRuYZbXMovmldXrh/
         JTLoVDuKslMM6vVViuheIp57+68p+Y4aJJeYKu4FnXWQ9H23VzrH3Qj+CUQHKAaGaS1R
         0o/tkwfrNdjaOEMlqdxcVJSo02cLD2WfoQl4WOtVlFSMbcqpSlFGbmzpF5TGCXz8vWkL
         gMvs5dbdDzeOl5HM9lSM8pgJIe1W63lI05fohlM71ObsSQwO7BwVGAYWa9NbrsthJJdw
         FbjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EakeZI4K;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id i10si720636lfr.5.2022.01.25.08.58.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 25 Jan 2022 08:58:12 -0800 (PST)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 48BE260907;
	Tue, 25 Jan 2022 16:58:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CADE8C340E6;
	Tue, 25 Jan 2022 16:58:07 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH 0/3] unified way to use static key and optimize pgtable_l4_enabled
Date: Wed, 26 Jan 2022 00:50:33 +0800
Message-Id: <20220125165036.987-1-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EakeZI4K;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Currently, riscv has several features why may not be supported on all
riscv platforms, for example, FPU, SV48 and so on. To support unified
kernel Image style, we need to check whether the feature is suportted
or not. If the check sits at hot code path, then performance will be
impacted a lot. static key can be used to solve the issue. In the
past FPU support has been converted to use static key mechanism. I
believe we will have similar cases in the future. For example, the
SV48 support can take advantage of static key[1].

patch1 introduces an unified mechanism to use static key for riscv cpu
features.
patch2 converts has_cpu() to use the mechanism.
patch3 uses the mechanism to optimize pgtable_l4_enabled.

[1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html

Jisheng Zhang (3):
  riscv: introduce unified static key mechanism for CPU features
  riscv: replace has_fpu() with system_supports_fpu()
  riscv: convert pgtable_l4_enabled to static key

 arch/riscv/Makefile                 |   3 +
 arch/riscv/include/asm/cpufeature.h | 105 ++++++++++++++++++++++++++++
 arch/riscv/include/asm/pgalloc.h    |   8 +--
 arch/riscv/include/asm/pgtable-64.h |  21 +++---
 arch/riscv/include/asm/pgtable.h    |   3 +-
 arch/riscv/include/asm/switch_to.h  |   9 +--
 arch/riscv/kernel/cpu.c             |   2 +-
 arch/riscv/kernel/cpufeature.c      |  29 ++++++--
 arch/riscv/kernel/process.c         |   2 +-
 arch/riscv/kernel/signal.c          |   4 +-
 arch/riscv/mm/init.c                |  23 +++---
 arch/riscv/mm/kasan_init.c          |   6 +-
 arch/riscv/tools/Makefile           |  22 ++++++
 arch/riscv/tools/cpucaps            |   6 ++
 arch/riscv/tools/gen-cpucaps.awk    |  40 +++++++++++
 15 files changed, 234 insertions(+), 49 deletions(-)
 create mode 100644 arch/riscv/include/asm/cpufeature.h
 create mode 100644 arch/riscv/tools/Makefile
 create mode 100644 arch/riscv/tools/cpucaps
 create mode 100755 arch/riscv/tools/gen-cpucaps.awk

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220125165036.987-1-jszhang%40kernel.org.
