Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBTGNST7AKGQEHOV563A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id D1E6C2C8A75
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 18:07:25 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id o19sf1943261pjr.8
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 09:07:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606756044; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ulq0LFCgvxa+Cm1kzy2Ijn38berbcnWB3esKDdmPLI+mJ+OmpbwB7HYAbB9SaFCqqm
         /epeHzmYUT1OsnJX3QDK74IBLv4YeW8EJDJcM3T8iOD4//QvOVBtky8Epvm8k3QzNxNd
         EGoqR9WdAqTINtzNEiU408KkSPoLy29IP3aCousIuoGlm1GXMcEHeO95m9VsRJfe39T+
         5mF+wpfrfFGBYmkV5IhBrNrFka21q6l53+EwvXiNkQTH9aJ/+JbpaFJfk9xF6dfY0l7B
         DgbpwE169JIp3QMOIuH3yAMZ2kDUXAbe7fM9N4j6m5RHhmGImnejUS5vCWvBseSrtFRv
         VU6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=5jfeaQowe8ImCf07teY0mprYZG8AttiseLCLD0+xSR4=;
        b=O8oAsuGC1IAQeFXk/3VBp8DqMe/163ocfKCTwhulfHj2Z1I4378Zl9vybEFfHnA/zR
         +4PRvCblstwZtIVNlLnjeEo1JV4P3K9nN5p4wk/nDExPLNRVP9rNYUvAUCkWdrG1SXls
         CRavPnm0eIyLJjTpyNsOmB7N0f5hojY3JM35tdW/G1X9Zer41nu2GPCLFHrfmPr7viI9
         zTktCmpEgWkinuG4N98JKlqEU15MYmhbCzD/DgdnsVdWpYV1TKOOuo+QN0Q82T8O9FqF
         E4ETwwxL5czlWDaKiuW/zIeduChUwpCnee+c8XNskg6Uw8rpIaZKBqbdMCxFhAkbBwNc
         3fmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5jfeaQowe8ImCf07teY0mprYZG8AttiseLCLD0+xSR4=;
        b=tMRsQkQIXpOis31sx3L0a2dUXa9G4MCiD2abaAMoDglQPRD9EOmEGvV6NLj+P9NF5N
         GcyZeInNix/R8c3AZZ7XvlP8ZvWqG2lMc/NslIeiPxED1G80Ll5LxSIqwDLzMiEdz+NZ
         Rwgxa0BM9b705lArl99nemVrUKMyc1d4tOgB1p6Nyw00tnuSiawedxQj7zUogqJIEsm4
         ofHw6GohOGY7zR5iyakZIt028yhVnN4kjci3u8WXH2Yvnv8KAG41ztlVRt+teySvNgWg
         czI1EENXqiFejLHGpNI8zHbhJAHn2VQaraAAsJayJbgM0HshFRF4HKbjswyxgY9i95ao
         XhJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5jfeaQowe8ImCf07teY0mprYZG8AttiseLCLD0+xSR4=;
        b=oXJpB3id9OoOtxzP5UEVh8Bmr4KGn52vgz/7u5Z6TvFKJJNvb5uH5nCaPgPtXO8C9v
         S1B1dZwlJY5dbjamlEAef4IIAMJygOUi1Rk6QKT5IlTSUzc233frxaDbFZZXMwviHduM
         TqYNw8jLi/x3v5QFuVNPxIl4jXq9l9LWqVCt3Nr+wbojHkWaHDViMw3bP2MTqWl3kyAi
         QKApD9wXgQfVhP3mp5+L6HqaNqG9sB9ftbqBIw8TXcnN263G12G+N7VKvwgFsui12vuM
         hsNSQTuKLXh+8jVNadUwZIzneM8wLusX9GvxvMqRnjo1pQ6C4T6SvtKI+sOZz0W00NM1
         ELFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Kwo1VbDGB7W66NJwLYxaoC1pdK63KOKNGD1zAbKu9oyN0KZgn
	IwqmJNwbUBtPngOYBALO25g=
X-Google-Smtp-Source: ABdhPJzpsGtL44b2m8sFMNOK1uGQCgDfN6EP5WFMQ3uLGXgVFzVINF/AZU7bnXOeLp7/bHd8t6topQ==
X-Received: by 2002:a63:c64:: with SMTP id 36mr18665120pgm.255.1606756044451;
        Mon, 30 Nov 2020 09:07:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8681:: with SMTP id g1ls6143526plo.9.gmail; Mon, 30
 Nov 2020 09:07:22 -0800 (PST)
X-Received: by 2002:a17:90a:bd0c:: with SMTP id y12mr22788597pjr.154.1606756042332;
        Mon, 30 Nov 2020 09:07:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606756042; cv=none;
        d=google.com; s=arc-20160816;
        b=lmzIJY94Pq8qkfEUODyZd9Vb4jySJlgrCHFMdSBedysjEge1LUuWcXnnme/LSt8zvD
         MaoDBGBW9SMILHg9Vqe8pd66P2EqXuHHqrANk6Mm188Y8KBg2MCfw6B5dV1ASl+Ao9xr
         JB5o1ETkKLx9XzdGAcSkcJqvTIGSukxkV+uhCY7lw+AXTqWArxgabNU9vFg/1B5S+uVH
         aC/sm+yEdpZOk2XJrGgPqhBEZU85YBiInAQbDKCxXmnWY8fSCdKPmCztLb3hqV6XWieH
         fB57+gl3iWnffSUJyiIzG4gGKMdc7yk5h9oP6yRU9iC3hOQqkmnaUFMasmUWGNgg3Q4l
         blFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=7pPmV6BLdydsRhg/qK34ba4laSrQp1jyoZQnXHCZcUI=;
        b=0KjUfTk/2/lC8lcYJT/uxUT79K69VvNGt/O1HYfjSMA7YjQpxQPuoMhNMhb8WZcm7y
         93k14zRLMX9Q7KW3w9sOrf7F6Ls+NFdaOcEMuUXzE6rK6kaWZkgGSmmUSrjlSUJz9hTJ
         odGrmRGNz3X6y4kVHmC41VduGkxjh1PyghU44L1FTJ2l1LD/bDb9kGE3l/Y0u09RqdzD
         chY2v1ASLwUMTyY2rwr7Kn3KSgS/WJLdjPy6u5ZFRmuG3+Ib4ihj1YHsJbO7RlwspsCG
         aXCyz0qJv5gblAz1h44dLPZKD8spkfbw8ON7XcKYTFNA4Di5A9Tc8iWeByfMyyxsAj1Y
         j72Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j124si1091657pfb.2.2020.11.30.09.07.22
        for <kasan-dev@googlegroups.com>;
        Mon, 30 Nov 2020 09:07:22 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 379281042;
	Mon, 30 Nov 2020 09:07:21 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 51F8F3F718;
	Mon, 30 Nov 2020 09:07:20 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>
Subject: [PATCH v2] arm64: mte: Fix typo in macro definition
Date: Mon, 30 Nov 2020 17:07:09 +0000
Message-Id: <20201130170709.22309-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.29.2
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
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

UL in the definition of SYS_TFSR_EL1_TF1 was misspelled causing
compilation issues when trying to implement in kernel MTE async
mode.

Fix the macro correcting the typo.

Note: MTE async mode will be introduced with a future series.

Fixes: c058b1c4a5ea ("arm64: mte: system register definitions")
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/sysreg.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/sysreg.h b/arch/arm64/include/asm/sysreg.h
index e2ef4c2edf06..801861d05426 100644
--- a/arch/arm64/include/asm/sysreg.h
+++ b/arch/arm64/include/asm/sysreg.h
@@ -987,7 +987,7 @@
 #define SYS_TFSR_EL1_TF0_SHIFT	0
 #define SYS_TFSR_EL1_TF1_SHIFT	1
 #define SYS_TFSR_EL1_TF0	(UL(1) << SYS_TFSR_EL1_TF0_SHIFT)
-#define SYS_TFSR_EL1_TF1	(UK(2) << SYS_TFSR_EL1_TF1_SHIFT)
+#define SYS_TFSR_EL1_TF1	(UL(1) << SYS_TFSR_EL1_TF1_SHIFT)
 
 /* Safe value for MPIDR_EL1: Bit31:RES1, Bit30:U:0, Bit24:MT:0 */
 #define SYS_MPIDR_SAFE_VAL	(BIT(31))
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201130170709.22309-1-vincenzo.frascino%40arm.com.
