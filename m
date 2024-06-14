Return-Path: <kasan-dev+bncBCWPLY7W6EARBCH5V2ZQMGQEIU72N2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id B165C9082B9
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 05:52:42 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-795589ae41fsf204159785a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 20:52:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718337161; cv=pass;
        d=google.com; s=arc-20160816;
        b=YgnseSrbM3IXK+qktIdwy8Nk6Ji7x1gp1HJdZApy0k75KFq1lF9PNF5x6YMakc1nk+
         e80euF99q0TGozo1S1YlSLfUIuv66MzhJXfEgY0cjAHlVp+NpkBQ8SyLsoCojXhPho3L
         6NmjTWHvK0iNxDdkTroUtKtDGqa5iOOQDCSRER1b596zKLUBBPT1Ib3LeJBqk+nlKWk6
         63h0LtE4t/QwdUjrVCeOUsgpg/uloV80U1aNtIylhE0eoPMcVvRiGrgbDI7CfOBNzx9D
         IRFELtXZDhm3fp2KIF66g4ghkzNnKCuLed/0VF6gFpHHHx80FZMNvjPwnTkhfJBn1iE4
         Gw9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=eIRVSoUnzAvbs5aijbtu4QFmbEaIJaPuUd/cM7EjkrA=;
        fh=uTcCn07cetzRnY9FjPzD5tAUqWf4qW2FGntzGz3tboA=;
        b=FJ++jxkA8Iu7lzzjMl0K/L+w2Nv/1yj7nSBgP2IS6i+v31HOiGf/21OEe7d19bj/fT
         wwPMbqbA0i3+9Rj1mpHVUYDMyhnpCnyzGiAzKZGSQbiPBq12IPvH65gheU3iWOdGgxld
         JZpTpTlciuNjqeo3yvYdxMb5WCkreqvfsH8TQsRAG86jLPOrI/u3P/GjpUc36y5UH7bJ
         InWUivp+N3KtsPdT5oa3Y1lOHaCL8vMxHI63G9bUuGaxT5cYfeTsHun3qAOEzQdrp2Lf
         zVG1/zsqB95iGluODImgluOiRB634x2aZ+A4o3eQWvziNeAJ3+dKiIpHeD9XOeYRVSHX
         95tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718337161; x=1718941961; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=eIRVSoUnzAvbs5aijbtu4QFmbEaIJaPuUd/cM7EjkrA=;
        b=JdRXs+sTmja9bQn2x6KR+PL8vM9IpkhWSrTJpAv386xT4+myXt1ozwctbnLUMGL9f0
         sgXUN4IM4SpzrCpfUuAqRaGjU6zf9bGhrUKwiRUGG5URBXhPI0byzWGlDO7rwtopDgMX
         uJ3Pz1KtaHhDqXkbes1ZppRpKRyy8d9Z6kuORtaazNoxhXTX2EABH/fiL104VoAxcjlc
         oODlUCbYMKJMDyR7WDIp6arUAjnH4G52z7gYS0c3rZFCT3d0m44YTWZWknbAe1TNjMV8
         z19a8yTcsSRBa/LplljhqZbTsjv3La+MyedAkkkCITodHatyAz9MmzFZ1yYrtWTdg/QB
         5EWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718337161; x=1718941961;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eIRVSoUnzAvbs5aijbtu4QFmbEaIJaPuUd/cM7EjkrA=;
        b=iLvXJHX8gddU8XzergjO6zwtRoWagRlPqDpbfLNVHy6voCgdUvdpRdjTEYB+MPyGtT
         Bgig3q1vVxlvf0ScZCLgoSdnymj8OCtZqn0kyLCnqKhG4wFSpfrZ4ioaTJLgVfQMLsI4
         ygIRoUw6aP9xUhE7XdNQ1paZBibLCpv/7nXKTEbiMU/MNElb97r4M3fp1reXF+Ct241X
         rgMy/c49w1Joxo+0YVE61psTnGcLi0p+R2qAaykugQDXEXjIEkBGlN3GRPaeBwMaMpUG
         UtQpOHB1ku8ZiraqTImSaKubEnSBfUtsSrFwhkOJ3uW6Jvb5/jqs6GBqzEDQsXvzpj9H
         NR4Q==
X-Forwarded-Encrypted: i=2; AJvYcCWlrd3UNI5ZTt4UGqSygRCAVkbWzZF+d8i56IeUc5Gm0fi+/2w1CsF2+tZlZ3dB0cBo2GxJdQ9zEeNekZfu6IHpQchFg3BY0A==
X-Gm-Message-State: AOJu0YxnPVgkIrmBRCm8LU0dQJsEr/acLfGmVCl7J96D40j+GN8H5R+9
	VFT8h+TLsPwRHz2auMovxg4YMtcvx2hTPPYzvdEpVEVviHDdmTbR
X-Google-Smtp-Source: AGHT+IGBwDD9DbZsG2Lqc8xTrnBGUmiUe3we0c9Z62nY2k7g6pxYe9j2VjpkZWZNJv4Dh+JKzXV7Cw==
X-Received: by 2002:ac8:5f54:0:b0:441:569f:7065 with SMTP id d75a77b69052e-44216b4285dmr13633161cf.58.1718337161039;
        Thu, 13 Jun 2024 20:52:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:57d3:0:b0:43a:cbe9:f171 with SMTP id d75a77b69052e-44178db898fls23415721cf.0.-pod-prod-02-us;
 Thu, 13 Jun 2024 20:52:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDZC4nj6siaPe5vCtbnpIqJLfnYMYIPk8USGqVj3/LAjsLfFlTG9taeaY+/qpcdCpFj7pG9FeUpcxxFljvFxcixXOzdPUfHC+AhQ==
X-Received: by 2002:a05:620a:17a5:b0:795:4dea:e51d with SMTP id af79cd13be357-798d23f9ca0mr199136085a.13.1718337160270;
        Thu, 13 Jun 2024 20:52:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718337160; cv=none;
        d=google.com; s=arc-20160816;
        b=Dd23kQrKj0PnGFt4hjYV96PeIhZVN0nI51RmuA2yvf9g8JnKk+6hsMWqWWocrhoqqE
         +up4oNAzuD9NUR+8zbmVQdKple/2OKAfrN0eARbGXxXEEVU22k4ZB1eMbhAx/axSMpq9
         wcLjxg1cOzP85ZovW4l4RjIZLD4nmOiC5HjlsUIEoUIEu9JnXzF1LNpmNbG+5QsOFA/3
         cGa2TUkmo6UIhcuBbyCA0tDL1bNs4juGPYMaJ42YcZErba0To2d+KGLeV5jH39FckR+w
         7rjuW/2FS9R4UsA3HS2FcHEBkKP7FBxIhAjGebsNXByoBKaebCPFjPYnWNnVPzqAVXWK
         FO2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=DaN1SMCR60lDeFAUerjh8xqvCvE/Cdk/mBwasATa9Xk=;
        fh=v8nlEsPtC8QOgAMy9+ceT2RXXasdZQBfytgK0uDUtEc=;
        b=hSSZmnHgS2cOVYy3xMY+gwP9g5j8Fc2RR5oVdo4LOeAj0I4CEYDwRBHo9vK4CCsiD4
         gjbHR5aNYnQh/sHKNZ0iDmfYLB9wSBWcdtczBQC8NWwfmaTdZqHxdCdlR4hOBKm6qRde
         Q3ZXmH+PUQg//PEV9HamYT4Dkw3GJL48ptv3bs+uORU5neskT3PnzAPV3L6zNx4vIaxC
         rmwM96E8OqbGGzraiaLS2UHo78LR0UrVllQgA/EuOR89UGYTEBuJ+yveV8+c+lrvxAha
         BsAcTpxi2eShFRpqZjgLnbUpppoJSliRl/Cv8a0xW4XdYAeK9L0qakOS+BNFuMUkSg6/
         mkgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4421bcf67f7si73891cf.1.2024.06.13.20.52.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 20:52:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from mail.maildlp.com (unknown [172.19.163.48])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4W0lbp6jQ5zmYfM;
	Fri, 14 Jun 2024 11:47:50 +0800 (CST)
Received: from kwepemd200013.china.huawei.com (unknown [7.221.188.133])
	by mail.maildlp.com (Postfix) with ESMTPS id 57E03180060;
	Fri, 14 Jun 2024 11:52:37 +0800 (CST)
Received: from huawei.com (10.67.174.28) by kwepemd200013.china.huawei.com
 (7.221.188.133) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.34; Fri, 14 Jun
 2024 11:52:35 +0800
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
Subject: [PATCH v4 08/10] arm64: kprobe: Keep NMI maskabled while kprobe is stepping xol
Date: Fri, 14 Jun 2024 03:44:31 +0000
Message-ID: <20240614034433.602622-9-liaochang1@huawei.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240614034433.602622-1-liaochang1@huawei.com>
References: <20240614034433.602622-1-liaochang1@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.174.28]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 kwepemd200013.china.huawei.com (7.221.188.133)
X-Original-Sender: liaochang1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as
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

Keeping NMI maskable while executing instruction out of line, otherwise,
add kprobe on the functions invoken while handling NMI will cause kprobe
reenter bug and kernel panic.

Signed-off-by: Liao Chang <liaochang1@huawei.com>
---
 arch/arm64/include/asm/daifflags.h | 2 ++
 arch/arm64/kernel/probes/kprobes.c | 4 ++--
 2 files changed, 4 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/daifflags.h b/arch/arm64/include/asm/daifflags.h
index 4eb97241a58f..01c7123d5604 100644
--- a/arch/arm64/include/asm/daifflags.h
+++ b/arch/arm64/include/asm/daifflags.h
@@ -16,6 +16,8 @@
 #define DAIF_PROCCTX_NOIRQ	(PSR_I_BIT | PSR_F_BIT)
 #define DAIF_ERRCTX		(PSR_A_BIT | PSR_I_BIT | PSR_F_BIT)
 #define DAIF_MASK		(PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT)
+#define DAIF_ALLINT_MASK	\
+	(system_uses_nmi() ? (ALLINT_ALLINT | DAIF_MASK) : (DAIF_MASK))
 
 /*
  * For Arm64 processor support Armv8.8 or later, kernel supports three types
diff --git a/arch/arm64/kernel/probes/kprobes.c b/arch/arm64/kernel/probes/kprobes.c
index 4268678d0e86..efcf6d478dbc 100644
--- a/arch/arm64/kernel/probes/kprobes.c
+++ b/arch/arm64/kernel/probes/kprobes.c
@@ -180,13 +180,13 @@ static void __kprobes kprobes_save_local_irqflag(struct kprobe_ctlblk *kcb,
 						struct pt_regs *regs)
 {
 	kcb->saved_irqflag = regs->pstate & DAIF_MASK;
-	regs->pstate |= DAIF_MASK;
+	regs->pstate |= DAIF_ALLINT_MASK;
 }
 
 static void __kprobes kprobes_restore_local_irqflag(struct kprobe_ctlblk *kcb,
 						struct pt_regs *regs)
 {
-	regs->pstate &= ~DAIF_MASK;
+	regs->pstate &= ~DAIF_ALLINT_MASK;
 	regs->pstate |= kcb->saved_irqflag;
 }
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614034433.602622-9-liaochang1%40huawei.com.
