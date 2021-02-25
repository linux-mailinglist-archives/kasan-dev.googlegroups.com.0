Return-Path: <kasan-dev+bncBC447XVYUEMRBONU3WAQMGQEP247F4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 93C0D324BA9
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 09:05:14 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id a19sf1933558lfj.15
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 00:05:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614240314; cv=pass;
        d=google.com; s=arc-20160816;
        b=hAZd10dtsYkzycXHvFY0ag8CbL0Ae6N51WnV+ka8PIv1i0LXPA8mdxi4zyIVYMDHY1
         DEBm+dVMITobk6LyYSVyyeEPsfeh068T5MSgyENlQyvG5zZOlcnbN2ujqkDqzfy3lN5V
         i0CsdWIEjLWRnbJ1Jsjwfa8xkH50jlXCaF8RsMo/8jtlFsPECBLNb4s8Pj1+v3T0ZMsH
         cl83yWVXYxlltBvLjZpGqNGsuoQTQyS58g9+kCUXQeU5AuZNgr+CiBY6wPIgi9DCtMSq
         Xkooh0XvZQG5NvOTruxBI4Jv09WIJ/S5+I0ADP0ullk5dcWjon+upXAApwf1bfu2fG8K
         KGhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=50WJNTYv8VYsJm7XuRgBxWS2XMJzK4PS8iphGB0KXv4=;
        b=bY8E+1Ee9KhvD8GDVLlu1m89q3/esoe1LJXHb6AoiJQ8ZZzcVguF4g5PTi3ezEkee2
         5swzyVSL49VydIKVg90n8jJkRmhfFfi9IeZ/muvVDpWmon1Pj+5+4gZ5h5GvrRSiP9vS
         Hvf5+Ma8hKpZG+45Zr1bsC3jg2NumFKFvWmBycmqmwY76ojQOSVawQXQHn3iD4QoSYdj
         cBnvY4jkAKD4uIwA3okxwuCTVb9xoNJYbbg5GUQTMMIPIEoAv+iuGRyor64A3DlSE3Qw
         sgVtvQcFtgeGfUs5l+Ev16Zg5OyiUEG6tZbKvkAh2+kAusvMmL6176uPTb8Uq5MrIPXT
         Epdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=50WJNTYv8VYsJm7XuRgBxWS2XMJzK4PS8iphGB0KXv4=;
        b=ZbHVBEAa9/xxEzOVrnmqCyZ+xqewyfVmq7ysXwFQ528zunvfZ1c8n7QBpzf3RBT1tP
         6EnZszzkSioJmhB6Qijlj9CROLtc913XopFteu1wuwb5LEx4BAucWkXuWBg7jMjFGuYT
         kKDnVj22UIbcu9N73yVQ7rKsbMBTRLFwXnxAp4Hbo/3CNK6B7rdNiJevgrOiwurcdE3r
         RZqae2JFg5NMjh1DQG64eZ8AYOMsRmCXKUZFNGPMwLu1cinTM0F3HzG4kKIhBiIvdiHZ
         XZfVKTIsjmm7xSLTHs6Tb0tR88bpi50VUln6JZw+w87x7/ct9uIlo2+iDeqRMbyewjyQ
         zsOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=50WJNTYv8VYsJm7XuRgBxWS2XMJzK4PS8iphGB0KXv4=;
        b=AxoWOqY6l+jc1bF4BCYah7XAMT3cHJ+EGqTXuOes5UOqr4Pf0441H6EEQdjmmATgKG
         DAjy11pOBxBqjwmrh/EmXvgTDKnlNDZccXREebF6usQ7DTgh6r0k/dDFaYvW+DXtlakM
         O8xFqPI302gFEe2mjCu0CPTPtqZWD8CS/PA2C0YOvLMXLFr2t/QBv4mLVtk+6Mv1Clgh
         K8uH6nkhZ4emB2laeVXeBF/46ryMhWNX/Pnl9+q1WcQweedzCt0pqdMirE6/Byw3E8/S
         G70kq43ta7XxlwH/LZRmmsBPM9eptUhDXfy9BfRMBcH2oeGT1RWI/Oi5a8QuIfgLvr3K
         jmGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/ICCI9fjfArIsKMKxsnbuk2T3Prs7D0uB2hLAYjhP3MCn5/at
	kJ2f9bqmEictlL5z6fMlXHA=
X-Google-Smtp-Source: ABdhPJytMPaMhGt2eDaZPmWux2BfbNY2V/9kcKy7A2yX5RC40bqzUI5M+5KKuOG/25Ly6BHw3GYtlw==
X-Received: by 2002:a05:6512:3046:: with SMTP id b6mr1278704lfb.407.1614240314090;
        Thu, 25 Feb 2021 00:05:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls641949lff.1.gmail; Thu, 25
 Feb 2021 00:05:13 -0800 (PST)
X-Received: by 2002:a19:ee14:: with SMTP id g20mr1294748lfb.355.1614240313112;
        Thu, 25 Feb 2021 00:05:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614240313; cv=none;
        d=google.com; s=arc-20160816;
        b=iv2BgKmkt3mClosRpRtXutu3f0GpPE19OJ/6W7rzW+wG2CBQGVF1l323lfevAM0m+h
         KsswOZqQqkXfS9Op1FnA7T3TlkLjRo3g5cBbm3t2bVjJuFjiUQEX8fqbK+3LiD98Z95k
         AoGzHkXnhrm173UktqKynTT5Ue4zZoB4/lQNRg9Av2/sPakoQOzIvYm5VsFj/MhxIxW7
         Eg/scHi72CQ+ps1ERoMjUGAatUxhUcbKhK1yKFN3cnoLNCYF2/X7IjG/mdAIjmuozkh+
         B1zswnqgKR0f9HGE20+lElrOGqNDJnmKfs+LlwmsZ8F9TTplJBNMAdntw8XDzzRSbssC
         /T3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=zly2Ry5YXSL5utLsGmnSDhcl4t0gzeHVdGQlsZANfVs=;
        b=Cv4fMrzkPYuR3XLOKNdANxgUxgR+fNBGcH54q10i7NyOYX9Fs2iO667Nu3Q+hjrGYt
         6fITiEH7s5F9GTcWz86iaNYkMNDWuQ8sY5GP8pw1E4tSwc/YBGLGSADwI5VdRC34NIWU
         CZkMb4uUIywTEgojyWP+7wmGdBgjmN6VeaxzFUnFNThcJkVX+KyMIenDnqEuHbfHNnCF
         JiYMPEnbXzqCbY++DKfoDVvEgvH8T/gdbXrhz6OsyiWz+zopAO0wNAFyxP4tA2RS3STK
         Y/DxnmMQdYkJ+B1jwXp5cnJBN/n1INiYlofER8DLYJke2TVZfyx1Y2N2uA3pzvECuj03
         olcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id c8si225212lfk.1.2021.02.25.00.05.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 25 Feb 2021 00:05:13 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
X-Originating-IP: 81.185.161.35
Received: from localhost.localdomain (35.161.185.81.rev.sfr.net [81.185.161.35])
	(Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id 8449C240013;
	Thu, 25 Feb 2021 08:05:05 +0000 (UTC)
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
Subject: [PATCH 0/3] Move kernel mapping outside the linear mapping
Date: Thu, 25 Feb 2021 03:04:50 -0500
Message-Id: <20210225080453.1314-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

I decided to split sv48 support in small series to ease the review.

This patchset pushes the kernel mapping (modules and BPF too) to the last
4GB of the 64bit address space, this allows to:
- implement relocatable kernel (that will come later in another
  patchset) that requires to move the kernel mapping out of the linear
  mapping to avoid to copy the kernel at a different physical address.
- have a single kernel that is not relocatable (and then that avoids the
  performance penalty imposed by PIC kernel) for both sv39 and sv48.

The first patch implements this behaviour, the second patch introduces a
documentation that describes the virtual address space layout of the 64bit
kernel and the last patch is taken from my sv48 series where I simply added
the dump of the modules/kernel/BPF mapping.

I removed the Reviewed-by on the first patch since it changed enough from
last time and deserves a second look.

Alexandre Ghiti (3):
  riscv: Move kernel mapping outside of linear mapping
  Documentation: riscv: Add documentation that describes the VM layout
  riscv: Prepare ptdump for vm layout dynamic addresses

 Documentation/riscv/index.rst       |  1 +
 Documentation/riscv/vm-layout.rst   | 61 ++++++++++++++++++++++
 arch/riscv/boot/loader.lds.S        |  3 +-
 arch/riscv/include/asm/page.h       | 18 ++++++-
 arch/riscv/include/asm/pgtable.h    | 37 +++++++++----
 arch/riscv/include/asm/set_memory.h |  1 +
 arch/riscv/kernel/head.S            |  3 +-
 arch/riscv/kernel/module.c          |  6 +--
 arch/riscv/kernel/setup.c           |  3 ++
 arch/riscv/kernel/vmlinux.lds.S     |  3 +-
 arch/riscv/mm/fault.c               | 13 +++++
 arch/riscv/mm/init.c                | 81 +++++++++++++++++++++++------
 arch/riscv/mm/kasan_init.c          |  9 ++++
 arch/riscv/mm/physaddr.c            |  2 +-
 arch/riscv/mm/ptdump.c              | 67 +++++++++++++++++++-----
 15 files changed, 258 insertions(+), 50 deletions(-)
 create mode 100644 Documentation/riscv/vm-layout.rst

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210225080453.1314-1-alex%40ghiti.fr.
