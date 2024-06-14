Return-Path: <kasan-dev+bncBCWPLY7W6EARB7X4V2ZQMGQEJM5FAVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 775319082B3
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 05:52:33 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5baf272e4c7sf1555446eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 20:52:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718337152; cv=pass;
        d=google.com; s=arc-20160816;
        b=jgEf4YN3WiNgxLhkpUh35WxzsN1IJtleiuW9/8UU7AyBQnpUZFllAZ86xbHDXz/hiE
         dT8orSgwSb3nMWkY2/zBYNvwL9ejViWKOFJqUnkzkyiE664cljknOWLzkeEx0VUo2/I2
         GbFTbsD6iSbfoezvlNSedlu8T9AV9MyLUGcat63Pt4Ucmk8FOh1a87x4QjfzKNaMrsQX
         +Ifm/c0LTrEljdsQCJDbgDQgcu4rdeb9AGPUkaCKEssrNmL7/kqGwplJMEKKzdAKXymK
         /B87gNxAsXJKyHvIrkz6eNvcN1xJUP6Vm3f9Tv9enshp3umMQ4uhe8agnD3GdiTG1Kp1
         mu6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=37UPPJ89PbKPejtOcz0yx4rNxqw6rM5FSFymzMZ9RzQ=;
        fh=L5ZXuOBiTNy5CAnaZmLue4YjRZpPZTeXHNYwTFEYaxI=;
        b=JwyZW7WlZgBEhP8+crBFxaL/B4oihHfkG0uQ/UC2fDM4QStTgSMYsUwVRXPKOq/S95
         kk3rcct3otnq94L0qpkCfA1KKqVikv48Sv8HrTPDe7f0d7TQFEathbk4Wxz34sItyrJe
         PkahdLn14/JQakVetGo07DiTfA8N8WmXzPPHzXRSWqCWGsnol46Nv4q44CqNFpKPJZ/P
         s0jIKKbjzMYfw7ST9afOzlS4I9ouhE/e1hKoPW+0yDpfmggNN5ivYLnpmeVwfTV1oc5Z
         1ytOroQv7HFv5xSYFEUSFgqP2H4p9LF/pg67BoliXzZIff4iS48sneHDohKBnqPGJElS
         REkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718337152; x=1718941952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=37UPPJ89PbKPejtOcz0yx4rNxqw6rM5FSFymzMZ9RzQ=;
        b=heAETfOccaKqc44Gx6ZqUqBWHcnENLIVF5UCSOhnPxBV2mey7zjhaFM2QVMehHXVEW
         IJwPoxZ416MkAZuil4dDWJeqlfeKSzTUjQGGyqs2n8Pj7r68eUUIBVO6wiWruG76B/V2
         uR7HXWFCEEzoTc8tp8mNEOCf9sFhvdR0cZHhJx7qi1DKLmy4lO6bTsFE0gxBbvLw5E5A
         +L2ddPTTVLXTZpmg8VOtUIPBRoi5eJWlmPTUVGWxhrBsn5nQW3Y+lHfBy2kunA0K1oM7
         nSWubgmGUkvkkXfGqI2pSvuVpNyVJ5kL37o4fI0gqtHPowKUWaR6p3+v47jw4c3msrhe
         D71g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718337152; x=1718941952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=37UPPJ89PbKPejtOcz0yx4rNxqw6rM5FSFymzMZ9RzQ=;
        b=rnfX8fJPgyh4GXNPv0EXZoLNwiInbMikinlhBKlpsT5klD8jJfr44b1sFKkl/Vz34+
         zyfYb8tI7T5tsy+TlOUPYj2qaJoKC7TIAdt1SrU1wbp/7DFq5/Mc4wTkSCimBx2E3aLb
         W10FAKB1tgCIFS0HlEtrI1PmdnTLFh8q3+qdjxKVu/A2vwKS2chjrhGe757mS/IPIj9u
         cNncJ9MKzlTJCO/KXkiWS6YZNcYlBpa55PSwavdHdaEYPbcPhVxMFhOunv0re1iuyNJR
         OygBdc66VR+4yju60254SZOMLMr6kF41j75McddATbfLaHnVBfeCi5uxl9qx/+LEgE9t
         kmHw==
X-Forwarded-Encrypted: i=2; AJvYcCVJ7SrEl8htRnGcLnCUMsH5kMsaRDLmtXt9NFgIJl/yuRp2t93ebjpplT+Meuw5hr1T8MUnPX8yikQKRkAcRT6EFNWTZAlqwA==
X-Gm-Message-State: AOJu0YyjQoqzXoXaGhklv+FAAi2B/VV2uPHUce3216bMAl0B/vdep2AH
	opJgxikNyvWR/BnAd1o0mSISimad8aFOsx/vLIRu2BqYJVdGwLRh
X-Google-Smtp-Source: AGHT+IGFpVOD5SBMxB8UX6noFb7Y/QnYZHnfnQFRv8oIgHLDt5E67yo8tQd8oVLQ5a4OJweMFhXnwA==
X-Received: by 2002:a05:6820:2220:b0:5ba:f5f3:987b with SMTP id 006d021491bc7-5bdadb84d41mr1803638eaf.1.1718337150947;
        Thu, 13 Jun 2024 20:52:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ad82:0:b0:5bb:16d7:7402 with SMTP id 006d021491bc7-5bcc3e251c3ls1287508eaf.1.-pod-prod-06-us;
 Thu, 13 Jun 2024 20:52:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuLRq8bUckYa4vHF586yUkvzEI94JlJ/FPB1xH+8FY9F5AP6H4UD38XzfbMM43BBB+fXAnsZG/oV/FalJkdv7K2MddZSXQ1hn7iQ==
X-Received: by 2002:a05:6358:50c6:b0:19f:44b0:d6a2 with SMTP id e5c5f4694b2df-19fa9ddec98mr204920555d.4.1718337149986;
        Thu, 13 Jun 2024 20:52:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718337149; cv=none;
        d=google.com; s=arc-20160816;
        b=o/JcHQgHcxgyU4CJe/y9TkTal+G3Lg3R640DxEfxzoMwBK0oVpKaR52CfGah6IvYtp
         k3WKngBmQX/ohYW4i3ACVVEX14zGui53psTNxbbkE6qgNABM/cmPWLwQEdnghnFbiLu7
         dwi1JHVsOqN7YH0TaMoWxBY1IjoBUS5LWPThlfIzE5iQrbaTJzpFwbxgdXsGuPGDtZ+q
         Vefomb98D7OBr67IRhT4ae3QePnOD9DLdz5ePy6zSF8xrkZuTC4w9PUpJ8L010X5l1H6
         jZS1RQr8nzveDmtFuh61jBUH2mTGm1VzGHA5wQC0ghGPya7IbBqzsnJqvz9f6EQ/GX8p
         hq1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=IEHwCa/a2UXR+qVRlSakqP7H+5ZcC4v1dud7hdIu4MA=;
        fh=v8nlEsPtC8QOgAMy9+ceT2RXXasdZQBfytgK0uDUtEc=;
        b=deHlrAs1Zyqebn1iXrhziMxbPSmue5MEFQt0xR6zZxu+hb+OgLdDWtbYk4VNLbTs6y
         rQf52kXVptJrADjV4nhdPONFcltSGOjazWnoH8fK9QLFCDLS5V8uDNtYpAFgcvAUsxaf
         JJFZnFFEpBYPwtOtZs8Q4gHc+p31o4mfQvuamX7729LSReyQPj8WNezhSbJocBksQAKc
         G/Nlr8sC0avBKzjIPz/uIBsoSekglhoHZgnPH6Wmt+FeRvH4tWD/LB7JDD+oJE18fEv0
         1L6g03qghu4JCF86WXXLtwKcvy1j+1RuV9EjgTqR6UYcp0FFzq+wUOAZQkpYKChb7KFT
         oJCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-6fed4d08039si151714a12.0.2024.06.13.20.52.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 20:52:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from mail.maildlp.com (unknown [172.19.163.174])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4W0lgR6s9Wzdb7r;
	Fri, 14 Jun 2024 11:50:59 +0800 (CST)
Received: from kwepemd200013.china.huawei.com (unknown [7.221.188.133])
	by mail.maildlp.com (Postfix) with ESMTPS id 1C0A214066B;
	Fri, 14 Jun 2024 11:52:28 +0800 (CST)
Received: from huawei.com (10.67.174.28) by kwepemd200013.china.huawei.com
 (7.221.188.133) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.34; Fri, 14 Jun
 2024 11:52:26 +0800
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
Subject: [PATCH v4 03/10] arm64/nmi: Add Kconfig for NMI
Date: Fri, 14 Jun 2024 03:44:26 +0000
Message-ID: <20240614034433.602622-4-liaochang1@huawei.com>
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

From: Mark Brown <broonie@kernel.org>

Since NMI handling is in some fairly hot paths we provide a Kconfig option
which allows support to be compiled out when not needed.

Signed-off-by: Mark Brown <broonie@kernel.org>
Signed-off-by: Liao Chang <liaochang1@huawei.com>
---
 arch/arm64/Kconfig | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 5d91259ee7b5..f00fecef0fbc 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -2140,6 +2140,23 @@ config ARM64_EPAN
 	  if the cpu does not implement the feature.
 endmenu # "ARMv8.7 architectural features"
 
+menu "ARMv8.8 architectural features"
+
+config ARM64_NMI
+	bool "Enable support for Non-maskable Interrupts (NMI)"
+	default n
+	help
+	  Non-maskable interrupts are an architecture and GIC feature
+	  which allow the system to configure some interrupts to be
+	  configured to have superpriority, allowing them to be handled
+	  before other interrupts and masked for shorter periods of time.
+
+	  The feature is detected at runtime, and will remain disabled
+	  if the cpu does not implement the feature. It will also be
+	  disabled if pseudo NMIs are enabled at runtime.
+
+endmenu # "ARMv8.8 architectural features"
+
 config ARM64_SVE
 	bool "ARM Scalable Vector Extension support"
 	default y
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614034433.602622-4-liaochang1%40huawei.com.
