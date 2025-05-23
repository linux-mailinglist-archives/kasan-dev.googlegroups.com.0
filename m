Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDXYX7AQMGQE6XJHJAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 449BAAC1B06
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:44 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4853364ad97sf101158831cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975183; cv=pass;
        d=google.com; s=arc-20240605;
        b=cZrwvauuMfdqctox6gy6DAczYQW3pXMwl2FEt571wXvYVhvZDQGs6Cij/q9TEwlHcc
         Nd8PfdbJi94Cef7c1/6mGzXxI1q2SGwM5zNBx7rk69q7VgKImdx3aTLeGnmv+9vlESxq
         6wSm7ZzqfBxamtOuyGpnI0dmGHGgO73CkY09cv4xhlSrzb48ig9SoV0ZT5qb4Ky1aNGj
         Z09YERGO8q124OMzklz+6sKsTTQuVAq7MsCGuvwWlYCErvEPXImnc9nJPKwrMGu+FGrL
         nuSt+hOnAUoRORZCy3OMw1uz9HF+YsfwBZLonNiKD4UV0ehPAxUC5gKk73K7ZnMo7yG6
         Rkmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=7kjHUpvwdk2ugqmp9NJZPwpBmXN4mvp8z6zlvXC8EAc=;
        fh=RJC/mx3MZDcO/eOHdNp2eErdwN45iPfGnmhWkNDrTjk=;
        b=AvxDvrTWVQqKA6zcWg69pW3IzB1jiSthUvMiKu6ncdxYN9SpzhC9UfxuVLEf6gvKqf
         dpkwCoJjWIsZHjgW375bCxQJ8O91Z0/JnIVCPSygvoeblGOgF5BlaFGVmQ0I3w1byCq1
         gI0dI8mvlo+lnCeP6+tNBSk1mfIGkQ0klliHReQ0HBTGRTqKulgUBtVmNr/mL7/3VwMH
         Sz7H8iC7hXYMiQACwaV+xWWCpvfkDOkk4dmH2Kv3HMG09nHVepJC1cC178xcBllIgvii
         RK5gJrXoUD+Rq+vQPqYA5nMcD/pAjsZml5N6pEJA9LXhSQY1bD3dCLkmf5QKsx84G1Tv
         am+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=op8RRRGe;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975183; x=1748579983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7kjHUpvwdk2ugqmp9NJZPwpBmXN4mvp8z6zlvXC8EAc=;
        b=UtZGPlnNJd5VouQ5eGiT8pCh0o/gcVwMWfCd4PNqGRv3IPBuplB02F7m3ANsPRz1F/
         cexGHfwnmrwOFizomNWErCcto8u4o4totExm/oqoapil/PfYRtOsJCd4br60fxEjXDbZ
         nBl4HGOoa9mAD69f5Nl9ywPae99taLphqQ3M/D5ANvCeOpBmxYM8+5SRXTYQlapJTGzS
         mdXDQgzsmVfrmM5fS4kf32V7IZ9gYLvV6j3+678vjgFlFomhFwSkTjqRcmlOskO2uUG/
         egqfEzdnOfegZbSS6GpSsW/v7YuECz41bTe6lM10NcULq0oFzk/IMn6Crran3X9Cm1lv
         2fNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975183; x=1748579983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7kjHUpvwdk2ugqmp9NJZPwpBmXN4mvp8z6zlvXC8EAc=;
        b=JFgTv0Ynw2o0MsGiEUepcqP/Ocf/3zKSaFAeB24Z40qFYIDZKXS9klCyL9uTODqZFq
         NffmXdPWZORJX6Hd/NzY86Ed+l0e2ChyewHLhnABu7/wM+MwLihYvUmoGe1R5EZ5xoH4
         w21f9ZWepsqkgNmk9GkmsoJ+jQX33d9jrEdr5DEZWC9lrr1qzjZ1KUbNVQAhMqptD5LJ
         fTr4zISFs+26JpDTADw+YxyXeoZlYaAcUMN2x9XgnSWh88u0gamfNf8DtE/4Wgnw1v6d
         zjwAi7TaV78aFiWMmZ59Cd5Sdto0qFTYgcN69s3yE8GsXvPBmhP15NYLC//xYYLEVtPv
         0HCw==
X-Forwarded-Encrypted: i=2; AJvYcCVhvPOvDMPfSCTNu2uz2Y9WxMsNxqDT3SkWMOIRUnOBBhnHDVGZpF1DhcWYgB7OGnvfjl1R/w==@lfdr.de
X-Gm-Message-State: AOJu0Yx7YbdXc/7GHkL3SRwMeqAJ3wxlbgK8dSzOswYy8ZepahGSPEJk
	a3xdp9XpHvTxdrc0LxSaKYDyHEJ7YHW7H7KwlTtHpNxHsgYC7ML+8bk5
X-Google-Smtp-Source: AGHT+IE+CETid7vdKK5Fqqcz5WlKmuDsysvS45ymHx/1kC7CFX+sLrk40qQI62ESnk5g4hx+Y9Pe8Q==
X-Received: by 2002:ad4:42c6:0:b0:6fa:980d:52f with SMTP id 6a1803df08f44-6fa980d061amr592296d6.23.1747975182930;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGsmR48SirlTuA4zpmTgt+No5IkdhsaUtRUqzAmfCFVcg==
Received: by 2002:a0c:e343:0:b0:6f8:afe1:86df with SMTP id 6a1803df08f44-6f8afe18758ls14384336d6.0.-pod-prod-08-us;
 Thu, 22 May 2025 21:39:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5uVGA4Q2lER78Gvs6Lw8PookS7ygG6S25XWaig1V08KWr3uUY5HTuclJFCh4MfpNHKng0ptgBrk0=@googlegroups.com
X-Received: by 2002:a05:6214:268c:b0:6e8:fcc6:35b6 with SMTP id 6a1803df08f44-6fa93a28ff6mr26994116d6.2.1747975182018;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975182; cv=none;
        d=google.com; s=arc-20240605;
        b=LgfI/INunM0pw+RQa1iTCumE84WqxTDgSpqaVtBZyU5YBphqa38wpZS9E/zp47zXyY
         2mDZH+pbkVKeZPWp1YzP11sN4LPm3MwYP9D6n8kTXeQ5OyM+Br8aqtz5Hvs7ca2tgjB1
         kiHsDayCgRo/p+aWnWfT7SfQJwsXWcR0QvTv27TbF1ptuCpji2+vE7vvP0anmKf1LpSP
         6eJj7r/UIi6Pgd9hi+AfPXQNVizEZwsNVQypCdKMg4B4BEy4hHK5r/8YPnEj41b5Eiqt
         md4CpHDBDJ2S9GRzLzMkNK3VUC98D9EFuGi9GryCcXktps1zZqkVjXNu5pXrVA7rW1Hq
         rs8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OlTZo2YHN4mUSlk4pxkhvoD5faV7hXNmgVvajUQvWZ4=;
        fh=1mGvQB+beZethHSWNHgHunMlow7jmS9UUH2wiws9ft8=;
        b=Rqqkmi2ZVMqnslTIPFuwDa2N3kyhjn1YxxgcdbQCRGiLZyQUP4zmhH1S64uzxAk45+
         VXsFvtijndA2wlpknHVxs2SktNpRt0ELqNii3q8NuSe6UDm1Tiul0RJnGT/xqo7jTlRC
         Ll4lqu5v/pqptlDaMe5if/ggKREXr0VwuT+cyX31McTELi7nEaAcaIlpGB+NGGPl2Ayd
         o2MFtKJ3rvnuGKzXAsAaPJYffTMEOftwJp8sHZe+pY7jJ0R259rkzHPPJUy6rtYEVyZl
         Nic/Ip8bz9Hj8p9xEawLVClywzy3LjeB5n8ex0qT4xVe+swc6XMmVO2HGDYPsE65XGdC
         zMNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=op8RRRGe;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f8df29de88si1453056d6.7.2025.05.22.21.39.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 802AAA4ED23;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3784AC4CEF2;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v2 06/14] arm64: Handle KCOV __init vs inline mismatches
Date: Thu, 22 May 2025 21:39:16 -0700
Message-Id: <20250523043935.2009972-6-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1393; i=kees@kernel.org; h=from:subject; bh=snrRkduazq+CuYpLqIIgLSyyFGO/4xQDvfJjkALfmd4=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v3/OeF2xrGn/ecfjBwO7efZdOCt4+rf88t0n3N4wb Z+3/dJegY5SFgYxLgZZMUWWIDv3OBePt+3h7nMVYeawMoEMYeDiFICJ3LzFyHBy2+63G546VX1g 0Vi7P+DmOWnH15LfT2QGVG0KzD0V33ie4Z+ZkuwqZaEtna8zJ9x43F2j86WpmZGvafXnHuZ8IQF la24A
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=op8RRRGe;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

When KCOV is enabled all functions get instrumented, unless
the __no_sanitize_coverage attribute is used. To prepare for
__no_sanitize_coverage being applied to __init functions, we
have to handle differences in how GCC's inline optimizations get
resolved. For arm64 this requires forcing one function to be inline
with __always_inline.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Jonathan Cameron <Jonathan.Cameron@huawei.com>
Cc: Gavin Shan <gshan@redhat.com>
Cc: "Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>
Cc: James Morse <james.morse@arm.com>
Cc: Oza Pawandeep <quic_poza@quicinc.com>
Cc: Anshuman Khandual <anshuman.khandual@arm.com>
Cc: <linux-arm-kernel@lists.infradead.org>
---
 arch/arm64/include/asm/acpi.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/acpi.h b/arch/arm64/include/asm/acpi.h
index a407f9cd549e..c07a58b96329 100644
--- a/arch/arm64/include/asm/acpi.h
+++ b/arch/arm64/include/asm/acpi.h
@@ -150,7 +150,7 @@ acpi_set_mailbox_entry(int cpu, struct acpi_madt_generic_interrupt *processor)
 {}
 #endif
 
-static inline const char *acpi_get_enable_method(int cpu)
+static __always_inline const char *acpi_get_enable_method(int cpu)
 {
 	if (acpi_psci_present())
 		return "psci";
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-6-kees%40kernel.org.
