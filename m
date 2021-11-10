Return-Path: <kasan-dev+bncBDAOBFVI5MIBBNGVWCGAMGQEGT4UULY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id B26C444CA84
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 21:25:24 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id g81-20020a1c9d54000000b003330e488323sf1356289wme.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 12:25:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636575924; cv=pass;
        d=google.com; s=arc-20160816;
        b=SNs9wkQpU00ReMn2K8NAzX/7QXDft2HDhANJzD6Q7K1hjKEuQ8U//m7kFzqRkIpSd6
         pKdwzlKskl3H3YvQA7Bm5fL9clgHhh+f6NdWwOT6UDfBdUXvIF7/ObTZsvQAJMV0197X
         B4tTW8CYwFMz/gkoMPjtZx4bESGUdpvRcywsXGfVvxSo+jG4T9MNTAiO+IzWTqTX6sSO
         l/6p8dBZPFGM/q7PVn5GLFJhWVkpVojzTGwEBo8ybwg9duEBDLVHs8gKZQmqw77E1R0L
         JT/2dMiVapLLX46iF10NaEUWnJ7zio5GhXrMHQ5YOkkoi1z70FQ+vvIU911DcWELrflJ
         Mhaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=+NWXzaWMash8wOcSS3tdBVlmjKhZRWbV6YH9ifNr8u0=;
        b=m3IQi7YjyhnGbim3UGdM8s+PcLXiIRa+K8Y3eqrIKDVKZ/qAE5NbBhqsTv2SPuCnUb
         dbgvdJhkDnPREUFj8sbmQf1zRkdtuc169g0LwQQIsmVgUlx3gQWfY6NEV9Y7NPX0SzJ5
         QZJlOOMJ101RPCekf6ERNpmjO3MGS4/Mcm4K8KnyK5VJdDZ3aLf40rDiZZ7riI42dVni
         0sOWUYEwJ/ebe5bMeExa4tIjlTvR9ydXdhbWQ6bnjz+CWOGGMSVu8pfHYDLePerjbgHy
         qkW67w+A7AjRQyw0qt8wIZ2B2x74b0BtJwvCYClSGHeegV+cq3D6C0QjreIUryZH9mZw
         NWNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+NWXzaWMash8wOcSS3tdBVlmjKhZRWbV6YH9ifNr8u0=;
        b=WStfNwEaDtVmqAM9Y2jQGS5EUkskU3Own/8clBIfIUzGlPySk+WS6Gim/abzXzaur2
         Znz9FvUk2ZMpDFRvWL0SUDn/nwqkY00KwUtFdw6FC8OS8asod0Ec/KJOoiUrDhNKoAqu
         VtvJL4yEpJibMp41a0K+Gc9hpFLQC3RysoCcayAFv0v+BDhxJTLCP8vg1rKuHRRRkN/d
         3hDTlpVHF1Foa3K1LFpbZ4u4/rrODEXz2zCEX7rJBLzZ5afefJeJXfSHqJ+5YJxhn1ob
         eLAuAmg9uwrb+FQHbvU2gmFA88vOrqVKru/LW+4enk8mCIOLHmXHU+9SPXNWWhSeHKBo
         WMHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+NWXzaWMash8wOcSS3tdBVlmjKhZRWbV6YH9ifNr8u0=;
        b=h7TBIUk0v+xO8uMt3pQjvjdRgCnbiUNpYPFzYtaxTILA5S4X3qSJ2nZ1J/vOIuRpCh
         YYAM6/8Dx0wQ/MrXldV0hDwfaQ9FbBI/boIXyU6tCWFUHsdjWli2SJKqsQ9YVS8e1dMj
         h2LUGKhOzSYnI0R2Z9cqCqmpayvE0SmlRp30CINiKRR0Q2gYBikKnNgcJ2NuYurP64Rv
         23TxsoXy1CklalhEqWFmCWClao00phLMK5Pq170PIyp5WqShy6FFxwvsSAAGnQLNbMLl
         3AUyLTi/QG07AwMYoKgs9xLDL0+CqHHhgoahWGts71iLESmjHeyiVOysFxE1gLrJpYRD
         vaZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OlhhCfAFhKTi8/Y/8MC2hPI0lVgCtXheppsM6/IDzHTux+A2M
	vLe03u872EkVEfUFw6CchNQ=
X-Google-Smtp-Source: ABdhPJx4hbkvCCUfI8CQEzBkB8qo+qs4UGwghfDhtG4K0f25/HKWwc4GnDcY+lItBgJ14ZxVCcO7uA==
X-Received: by 2002:adf:ecca:: with SMTP id s10mr2137568wro.405.1636575924519;
        Wed, 10 Nov 2021 12:25:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls1303812wrr.0.gmail; Wed, 10 Nov
 2021 12:25:23 -0800 (PST)
X-Received: by 2002:adf:e54a:: with SMTP id z10mr2268814wrm.328.1636575923622;
        Wed, 10 Nov 2021 12:25:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636575923; cv=none;
        d=google.com; s=arc-20160816;
        b=ZdTiYRcOuqeDZSt3rc7LE8XgtJRPMdeeuVgW5wjrOuwJ9DjG5kpQb7hBkr3eU09YzR
         2fmhTgxib+33ea5szaOU9rWvJJD4b1pgm/kGEGdFGq/2pXYP5Ae21cJ3hvb+iuXn+TUD
         eavlLqAXYWRlsOzy+qwG03JfUN7G5tDSJuYEYOpwLLjFXgrO9TKO7v6GTmk6nACV05uo
         6zVVp1iQL9lzzRiYv7QeYMmFbWzxH0GtfCM+saGakK3QqU69K1olN44NxqB3DTvGptDM
         RC7Ip9hNrN3UkP50aEGxn+YlP2iA5G2WEKjnQ0C8n+hshsE+VeLaH6o+FhU6RbXYTADQ
         PSZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=vDRB+DLJl5QLcyUD2bydGrfLgrUhoBks4IsbcFBSoYU=;
        b=mTElecBVJMsNvA8cdzZXxQa6M2hQXJtqKic6n+zQqjEruz/NmWXkpgTO6IKPBH6gYg
         tAJKx/fNxgLQMU+SIIpo8647hrZupoIJHlymBbHOFjfKNJDejTQqqkTdu5Jeq1VDiCcY
         sZktggseyl/Z5khxXHrXq/kw+np8ZKT7jlagFOpEY22ZcszysOedlKpifCr1uRSCECL3
         m448wIqhkFVZja5F31E2VJ/HclLoZ3a8/aYUJM6bMRDy2GAfyjglwkrivFHi2gekT3P3
         98JMamRazLr9ZCgnDsbTE589UIeap6aza6JhqdOknNv3kzv++T5A7JAO9HUv5WQE9hCh
         bI1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i17si60382wrb.1.2021.11.10.12.25.23
        for <kasan-dev@googlegroups.com>;
        Wed, 10 Nov 2021 12:25:23 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B0346101E;
	Wed, 10 Nov 2021 12:25:22 -0800 (PST)
Received: from e113632-lin.cambridge.arm.com (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 7A8C83F5A1;
	Wed, 10 Nov 2021 12:25:20 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linuxppc-dev@lists.ozlabs.org,
	linux-kbuild@vger.kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH v2 0/5] preempt: PREEMPT vs PREEMPT_DYNAMIC configs fixup
Date: Wed, 10 Nov 2021 20:24:43 +0000
Message-Id: <20211110202448.4054153-1-valentin.schneider@arm.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi folks,

Thanks to suggestions from Mike, Frederic and Marco I ended up with
something that looks somewhat sane and with a minimal amount of crud.

Patches
=======

o Patch 1 is the meat of the topic and could be picked on its own if the
  rest is too icky.
o Patch 2 introduces helpers for the dynamic preempt state
o Patches 3-5 make use of said accessors where relevant.

Testing
=======

Briefly tested the dynamic part on an x86 kernel + QEMU. x86_64_defconfig
gets me:

  Dynamic Preempt: voluntary

and appending preempt=full gets me:

  Dynamic Preempt: full

Revisions
=========

v1: http://lore.kernel.org/r/20211105104035.3112162-1-valentin.schneider@arm.com
v1.5: http://lore.kernel.org/r/20211109151057.3489223-1-valentin.schneider@arm.com

This v2 is completely different from v1, so I felt like I could get away
without writing a version changelog...

Cheers,
Valentin

Valentin Schneider (5):
  preempt: Restore preemption model selection configs
  preempt/dynamic: Introduce preempt mode accessors
  powerpc: Use preemption model accessors
  kscan: Use preemption model accessors
  ftrace: Use preemption model accessors for trace header printout

 arch/powerpc/kernel/interrupt.c |  2 +-
 arch/powerpc/kernel/traps.c     |  2 +-
 include/linux/kernel.h          |  2 +-
 include/linux/sched.h           | 16 +++++++++++++
 include/linux/vermagic.h        |  2 +-
 init/Makefile                   |  2 +-
 kernel/Kconfig.preempt          | 42 ++++++++++++++++-----------------
 kernel/kcsan/kcsan_test.c       |  4 ++--
 kernel/sched/core.c             | 17 ++++++++++---
 kernel/trace/trace.c            | 14 ++++-------
 10 files changed, 62 insertions(+), 41 deletions(-)

--
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211110202448.4054153-1-valentin.schneider%40arm.com.
