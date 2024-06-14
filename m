Return-Path: <kasan-dev+bncBCWPLY7W6EARB6X4V2ZQMGQE4GLLBQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id CE47F9082B1
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 05:52:29 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5baebb314a1sf1639397eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 20:52:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718337148; cv=pass;
        d=google.com; s=arc-20160816;
        b=AoYW/0FidSfjpniM2Jum45oUl4h/KSpsPjer23tZvJ8ki7wISnpTXQtTjwI7TTAQ9f
         gzsoHw55kL+lvZ4dhnCCMrnxA8tWWdmW/ECiB/g7IcOHYeoNpiHbvHbd8uFHLR1hQm8o
         7+CGglD+iWDPVleKB9E4LY5ZudAc0ZAXolUIEKWf/OEaRpRUU8t6bz+J2odXAI39KOQE
         AEy3H8V42RYYyEuUaIsbVTdOuGm/Op/NPbLfRtkOiopo5KYpvs8oFyi/2cOgQcgQ/Xbm
         RI9FlEsOhcJsa9DRsLRF7FwR03W9VrzZc61j/h77HrumXi3gb0AKHCU9m/skbVWfsUWQ
         UR2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=PvfiyYVFGR2u4/i1lwaZtpIvz3gm3F3jjU/+i+NitAQ=;
        fh=N32jraJ3jrpkyKFlhaz1XdqqKuVqJZ62w1udEY3Q6wE=;
        b=oGSnG0iPyoTZ5PgRy5Z5BNth42JbGsdvs5OAjfmEFaaTxV5oetckSSSC4Sz6sHqGM3
         je+xdxifYNz69iawec76yAfzzcTzvsCnRzDPVfrIlBRYamksQ1UOXAI+BkopcQkYwG1F
         B9O6QnIbHEzumL3yDW/eT7GCtQ4g7mPl00vYCnEPIFIRsuAhQCXKdLM1T2yXy7JGclXa
         7MfQWoYMN0E1eISnxw2yAqGxRGLJ0CXIbjkyolKRsRBJFBluZmnoidTGPJbyeLdKfcwR
         piAY/z5hJ6U82TEh9cmXjqyuJPVmEK7dtrhIF/dQuuJ8eea4TarG3rYvMGQH2yIsR4Wm
         N6ZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718337148; x=1718941948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PvfiyYVFGR2u4/i1lwaZtpIvz3gm3F3jjU/+i+NitAQ=;
        b=BOh1sHQOsX6ca2dUDUhMy6ZwBDHk7NE/xDS3iOlYM7clGfaKpOF4aI8kYJD7/fDZTq
         CXA0udeGiwUqQEDayEfWX8AUl5mqKRA4xKBvjhUfPThH8KLOJfbtXp0kDFbaK5KdIMWr
         L457JA2Rh1tDyy2gJh9qI19kYM3g2OzG2gBuatx08XYT/F8D7dOYsyHzbE1SGyeybddD
         C7D8zT0JA1iY2vjN3zgbn7tEpa/nCFp6nZbXiLZaSEjf9HCfKZyDwBsa7lhw6JAm6DI8
         EjQS1EzWM92zN5yCH3H4hRuSZkJd7dMh3d/Rq0UkgWGRHIAqJJPexasX7UdTkBvCb4xy
         KJ7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718337148; x=1718941948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PvfiyYVFGR2u4/i1lwaZtpIvz3gm3F3jjU/+i+NitAQ=;
        b=EjbAytlP/HlKfjkn3NCAbzIiNgQGqxCPWeqB2kbdIJD1GRSBqFq1VXwM39SH9GKhfZ
         ilA9DKAHhHHFe8yhQ4AhagIZlFkPZxKMil5NrG/SdnwkFCcNkruv5bFOxpUXon4OsR0+
         VYn6NKTf6wlV0y5LxLOZS2Ev4Vhk0/t+Mmd/nnuu6AbiYMCHl2+sY43LEdgBx/UNRza9
         ARA+dPXxcu2VBjgr4oUjSUKo50NwV3lABv6pYnbjUwwPMIjjeAb0DrsXjB6k2IucPCeB
         kLsWy/KEmqjJw20/iDeE52yglziUvkOex2odt6z0rLaU/Gvey/4QgphI0jVRuYlFaAn8
         vQuQ==
X-Forwarded-Encrypted: i=2; AJvYcCVK2xfQv+BvtnGuJ4cNFMzcEnynv0jsS52YuZsRqMrp9OPm0dNv18OggWr1EKhauAR1bRRG3qnM3PDpeynHcKxdcWYk1ZcRwQ==
X-Gm-Message-State: AOJu0YwizO4KNvGmitTNXydQpJ7LqMnNWHQnnhGwvgEju8oxsQNz1aUS
	vcseLuGlihyLck8I7jz+PsEBcLUZKE+DJPHwf+UW8LftiZoynUZA
X-Google-Smtp-Source: AGHT+IHmpfe3IEpxVe+q1Smug99KLKWMiZyNNKQzIjnqjFBReRtmnlFVS9E5+XuscUHbKNZhnsTS9g==
X-Received: by 2002:a05:6820:509:b0:5bd:15fc:8fe5 with SMTP id 006d021491bc7-5bdadc5a924mr1430264eaf.7.1718337147140;
        Thu, 13 Jun 2024 20:52:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:1704:0:b0:5ba:a73a:6de7 with SMTP id 006d021491bc7-5bcc3e0189als1270340eaf.1.-pod-prod-08-us;
 Thu, 13 Jun 2024 20:52:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUkG6E4Yqb1N6ZV/IG767fz6RjC8S/3h+uSc9lGfhX4HQtSp1FAEuF5LJEIIxtFnCU+HD7NstxbPz1uPqoF2UB/QGFjrU4zY1P/TA==
X-Received: by 2002:a05:6808:f05:b0:3d2:304c:982e with SMTP id 5614622812f47-3d24e983eaemr1864895b6e.42.1718337145838;
        Thu, 13 Jun 2024 20:52:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718337145; cv=none;
        d=google.com; s=arc-20160816;
        b=pBkR23/C+GO9ej2h2XPmlfYsv0ev9KONV0zDFFV40zarBwQkaYy5zY24Yb1NTp3pDp
         rCtUh/sGGiw1LWk91i1zgCJuECLqWtUGnm0y4TIpCQ4AxHy45KB4iU3gmZpB0BCtmybj
         sHGPWCuYF3wyuxmdzvvADwMBkoKBH2UHpR5Un3VcURu/Cv/s96mjk3CM4hMtBGIstcbJ
         +7Bx7++3s1L9ZrqliROuf5A40Qv2d+Vhrkz9En8JDQTXUr8JrepNG0K0R6XySkdn6/8f
         sRYjzBRtFXFmt6mz6E2gUG5ncHbcdQ9+qBZhqRej3Sa3QGw1UBd142Fv2nm2+VkxuPoD
         Yw2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=DbBui2JqDDl6fIDcmlExHQt1FjC8XceesytnkhGF4wM=;
        fh=v8nlEsPtC8QOgAMy9+ceT2RXXasdZQBfytgK0uDUtEc=;
        b=M657kBVsKmKD9mGwu2dnqRN54ERwtbtZYZjPI/M9jwUKu77zEzAAF9V5ZiJ8NRmgxq
         8zI6itSMwpazZclkwozA9pBksNRP9yTJrJzRwe4QhIIl8gvNntB5eAweFgEm6fxdSb86
         2/hzblBLlHncW16lAx7eDDhvwmJZZjiDur/XR8mcdgThevIfSImjBZZ7xonDnjkjVLJ1
         gGqKU4hQRibaKoiqscoyBoMFlCKsOtyCqf5NS2jyZE6L4MsChMrvtQN58k1HDvQcJ02l
         Fu2lUrhZjfS1Z2A9RcaAkbC5/1QLM30DZk2fmyYL1iP9f4lP+dZZCzEkZMy+xjRSoNsR
         xhVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d247740eb2si130956b6e.3.2024.06.13.20.52.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 20:52:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from mail.maildlp.com (unknown [172.19.88.105])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4W0lcG3JDfzwSLw;
	Fri, 14 Jun 2024 11:48:14 +0800 (CST)
Received: from kwepemd200013.china.huawei.com (unknown [7.221.188.133])
	by mail.maildlp.com (Postfix) with ESMTPS id 8297B1402C8;
	Fri, 14 Jun 2024 11:52:22 +0800 (CST)
Received: from huawei.com (10.67.174.28) by kwepemd200013.china.huawei.com
 (7.221.188.133) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.34; Fri, 14 Jun
 2024 11:52:20 +0800
From: "'Liao Chang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <ryabinin.a.a@gmail.com>,
	<glider@google.com>, <andreyknvl@gmail.com>, <dvyukov@google.com>,
	<vincenzo.frascino@arm.com>, <maz@kernel.org>, <oliver.upton@linux.dev>,
	<james.morse@arm.com>, <suzuki.poulose@arm.com>, <yuzenghui@huawei.com>,
	<mark.rutland@arm.com>, <lpieralisi@kernel.org>, <tglx@linutronix.de>,
	<ardb@kernel.org>, <broonie@kernel.org>, <liaochang1@huawei.com>,
	<steven.price@arm.com>, <ryan.roberts@arm.com>, <pcc@google.com>,
	<anshuman.khandual@arm.com>, <eric.auger@redhat.com>,
	<miguel.luis@oracle.com>, <shiqiliu@hust.edu.cn>, <quic_jiles@quicinc.com>,
	<rafael@kernel.org>, <sudeep.holla@arm.com>, <dwmw@amazon.co.uk>,
	<joey.gouly@arm.com>, <jeremy.linton@arm.com>, <robh@kernel.org>,
	<scott@os.amperecomputing.com>, <songshuaishuai@tinylab.org>,
	<swboyd@chromium.org>, <dianders@chromium.org>,
	<shijie@os.amperecomputing.com>, <bhe@redhat.com>,
	<akpm@linux-foundation.org>, <rppt@kernel.org>, <mhiramat@kernel.org>,
	<mcgrof@kernel.org>, <rmk+kernel@armlinux.org.uk>,
	<Jonathan.Cameron@huawei.com>, <takakura@valinux.co.jp>,
	<sumit.garg@linaro.org>, <frederic@kernel.org>, <tabba@google.com>,
	<kristina.martsenko@arm.com>, <ruanjinjie@huawei.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <kvmarm@lists.linux.dev>
Subject: [PATCH v4 00/10] Rework the DAIF mask, unmask and track API
Date: Fri, 14 Jun 2024 03:44:23 +0000
Message-ID: <20240614034433.602622-1-liaochang1@huawei.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.174.28]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 kwepemd200013.china.huawei.com (7.221.188.133)
X-Original-Sender: liaochang1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=liaochang1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Liao Chang <liaochang1@huawei.com>
Reply-To: Liao Chang <liaochang1@huawei.com>
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

This patch series reworks the DAIF mask, unmask, and track API for the
upcoming FEAT_NMI extension added in Armv8.8.

As platform and virtualization[1] supports for FEAT_NMI is emerging, and
Mark Brown's FEAT_NMI patch series[2] highlighted the need for clean up
the existing hacking style approach about DAIF management code before
adding NMI functionality, furthermore, we discover some subtle bugs
during 'perf' and 'ipi_backtrace' transition from PSEUDO_NMI to
FEAT_NMI, in summary, all of these emphasize the importance of rework.

This series of reworking patches follows the suggestion from Mark
Rutland mentioned in Mark Brown's patchset. In summary, he think the
better way for DAIF manangement look likes as following:

(a) Adding entry-specific helpers to manipulate abstract exception masks
    covering DAIF + PMR + ALLINT. Those need unmask-at-entry and
    mask-at-exit behaviour, and today only need to manage DAIF + PMR.

    It should be possible to do this ahead of ALLINT / NMI support.

(b) Adding new "logical exception mask" helpers that treat DAIF + PMR +
    ALLINT as separate elements. 

This patches cherry-pick a part of Mark Brown' FEAT_NMI series, in order
to pass compilation and basic testing, includes perf and ipi_backtrace.

v4->v3:
General Enhancements
--------------------
Commit messages of [PATCH 04/05/06] have been enriched to outline the
implementation details, motivations and potential effects. This might
improve develper understanding and review efficiency.

Specific Changes
----------------
1. [PATCH 01] new utilize the existing helper maco in sysregs.h to
   generate the "MSR ALLLINT, #Imm1" instruction. Additionally, helper
   names have been renamed to start with msr_pstate_ for better
   discoverability (as suggested by Mark Brown).

2. For [PATCH 04], due to the barrier side-effect of writing to PSTATE
   fields, it is unnecessary to call pmr_sync() in
   __pmr_local_allint_restore(). Add a table in comments to depict the
   relationship between the type of interrupt masking and hardware
   register configuration.

3. For [PATCH 05/06], function names have been revised to better reflect
   their purpose:

   local_errint_enable()       -> local_irq_serror_enable()
   local_errint_disable()      -> local_nmi_serror_disable()
   local_allint_mark_enabled() -> local_irq_mark_enabled()
   local_allint_disable()      -> local_nmi_disable()
   local_errnmi_enable()       -> local_nmi_serror_enable()

4. For [PATCH 07], A bug in local_nmi_enable() has been fixed. The v3
   version is overly complex and included an unnecessary write operation
   to PSTATE.DAIF.

5. [PATCH 09] introduce a slight optimization for NMI handling. Since
   the intermediate step of marking IRQ TO-BE enabled is no longer
   required, dropping PMR before acknowledge PSEUDO_NMI is also
   unnecessary.

6. [PATCH 10] migrates CPU idle contex save/restore operation to the
   newly introduced logical interrupt masking helper functions.

v3->v2:
1. Squash two commits that address two minor issues into Mark Brown's
   origin patch for detecting FEAT_NMI.
2. Add one patch resolves the kprobe reenter panic while testing
   FEAT_NMI on QEMU.

v2->v1:
Add SoB tags following the origin author's SoBs.

[1] https://lore.kernel.org/all/20240407081733.3231820-1-ruanjinjie@huawei.com/
[2] https://lore.kernel.org/linux-arm-kernel/Y4sH5qX5bK9xfEBp@lpieralisi/

Liao Chang (8):
  arm64/sysreg: Add definitions for immediate versions of MSR ALLINT
  arm64: daifflags: Introduce logical interrupt masking
  arm64: Sipmlify exception masking during exception entry and exit
  arm64: Deprecate old local_daif_{mask,save,restore} helper functions
  irqchip/gic-v3: Improve the maintainability of NMI masking in GIC
    driver
  arm64: kprobe: Keep NMI maskabled while kprobe is stepping xol
  arm64: irqchip/gic-v3: Simplify NMI handling in IRQs disabled context
  arm64: Migrate idle context save/restore to logical interrupt masking

Mark Brown (2):
  arm64/cpufeature: Detect PE support for FEAT_NMI
  arm64/nmi: Add Kconfig for NMI

 arch/arm64/Kconfig                   |  17 ++
 arch/arm64/include/asm/cpufeature.h  |   6 +
 arch/arm64/include/asm/cpuidle.h     |  24 +-
 arch/arm64/include/asm/daifflags.h   | 376 +++++++++++++++++++++------
 arch/arm64/include/asm/mte-kasan.h   |   4 +-
 arch/arm64/include/asm/mte.h         |   2 +-
 arch/arm64/include/asm/sysreg.h      |  27 +-
 arch/arm64/include/asm/uaccess.h     |   4 +-
 arch/arm64/include/uapi/asm/ptrace.h |   1 +
 arch/arm64/kernel/acpi.c             |  10 +-
 arch/arm64/kernel/cpufeature.c       |  61 ++++-
 arch/arm64/kernel/debug-monitors.c   |   6 +-
 arch/arm64/kernel/entry-common.c     |  94 +++----
 arch/arm64/kernel/entry.S            |   4 +-
 arch/arm64/kernel/hibernate.c        |   6 +-
 arch/arm64/kernel/idle.c             |   2 +-
 arch/arm64/kernel/irq.c              |   2 +-
 arch/arm64/kernel/machine_kexec.c    |   2 +-
 arch/arm64/kernel/probes/kprobes.c   |   4 +-
 arch/arm64/kernel/proton-pack.c      |   4 +-
 arch/arm64/kernel/setup.c            |   2 +-
 arch/arm64/kernel/smp.c              |   6 +-
 arch/arm64/kernel/suspend.c          |  10 +-
 arch/arm64/kvm/hyp/entry.S           |   2 +-
 arch/arm64/kvm/hyp/vgic-v3-sr.c      |   6 +-
 arch/arm64/kvm/hyp/vhe/switch.c      |   4 +-
 arch/arm64/mm/mmu.c                  |   6 +-
 arch/arm64/tools/cpucaps             |   2 +
 drivers/firmware/psci/psci.c         |   2 +-
 drivers/irqchip/irq-gic-v3.c         |  29 +--
 30 files changed, 490 insertions(+), 235 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614034433.602622-1-liaochang1%40huawei.com.
