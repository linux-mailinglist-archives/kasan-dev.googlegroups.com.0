Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB3GSSSAQMGQEB2BSNBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D758318B3D
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 13:56:13 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id f127sf6000328ybf.12
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 04:56:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613048172; cv=pass;
        d=google.com; s=arc-20160816;
        b=envI1hQyjQinX7jjWoYz2sclAvBxgYd7+0ykb12D9a+QBxfO3ol1A07cuZY5sczXaO
         UAmGxo95+dg9KlUpuQ5Mn/OAzrSLN3sOZ/f8m5Q1eyVs3AOCBKoV4ahzNSl4Gbh3U26y
         siecQcwapV8K2ndj5Oc0cyiFZgfa7oZCY/sqxUi8Suwdaj6uf9YdvSzBr02ikYehccxS
         R4IpyxaWPhU384KrFmlyU+d6S0s/d/EXBz4hoNCa8H7NKuzPEzqyIWNtEO9Tl2R+uIAN
         2y3hekG0zLcg8968gWJtbHv7FHvLvR8wsvImX2h+UHVZHq5uIeGuuqYCzDZK9N8KcL+7
         E2gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=Wt0CJ9XiebOWrDXEW4hMNEm3Re6XxaDLwVDrqeFNDDA=;
        b=P7g8QBd+27Y6irtO1B7j8rL1F13cYNGKnKrhn1336etHHr659Kn6gJLWON8kVVJkGd
         AEJ7EXiTkBHK1grjpKaF1Mt5QEaYVcIklXN0CyBOX4iyz7HdWoXrOi91rHwnLbAVaric
         1tY09bP0m5Wb6dgp1b683Jl8S78Xn/beFHiPCsstQpEpArZOhTsAKjgDNKitaGnA/oB8
         N/IfV1j8NuBKXd6PQQWa7nqkPOzrZ5bgU9GInAlPjEFqwkRGyRCO/fFkncyvuHIRupV0
         aMky+WdLSqkkSaHZhk/teAJMKgAD+eCdXThHVTolaYRnA0bJ9n0VzueqC11ZqK8nENH5
         9j+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Wt0CJ9XiebOWrDXEW4hMNEm3Re6XxaDLwVDrqeFNDDA=;
        b=Jl0f4mQSkc+PkkoCUP4ilnWEQGO8R9wTmURc/U3VjgLAxKS0gZoJN/w10Dkq85bgpB
         6TXfzSYX/A6gkjQgKsjvPWPonDfuHTc6GfJw3fxfBWB9uSpNihsVvd4MkQbzxoJolxYV
         umud5kvj2+hg+RXlyY6pasYgheszwAPgYCAy3EeoTqciU8Z74gf2dXXL3qlhgqLpNXGl
         nHIEBIms+P9Tv366fKTnFNQ6IfhHUifGomuEPwCYZMTIcPEUP1HrYN9j9UVGNvjIIa1B
         t+L8YpZ5ZqeYFqPE4zrMTKeDCBRrWW5dnOrN8zL4eeHWMAYO1G6CtH0SZTXWDjRtB/uz
         5rIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wt0CJ9XiebOWrDXEW4hMNEm3Re6XxaDLwVDrqeFNDDA=;
        b=Ohh6KVBfZYI0TxlAMvAth1fWrzhPm+Q5VqCoCPn00SjfkLuAaj2K1d3/WWlSPBblMi
         uxZr+Xz0y0SsjuK7nKqkgJFh0fjxj5UZBf+f1hs6reM0OrBSf//7kqt+SJSVc36ixi0h
         jRHB1SPW0PeNraOHrTyP2IoE4LgqTaQnvlRAIgKRI6j0MT036b+qND+wRstBWPqppZ6d
         FMpV6PchPPSbCIyXyKUVuBATR6KTeE2Pea9Ye26cMMOFrXk/vdyRvLR4k0aE6/l4nVyL
         C51mWPzzuPstH3sh/7fOC5wOEYIbURNgGsQilP3yBo8kuQx0Q73/MlbRwCn6ngpHro5i
         qRJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53063FZn87lTzhx2nxt92ba+j27Q5EDM5EGnGMOkoICBnZcUT28/
	DM8OJB/NWjom9b78YnBGkhU=
X-Google-Smtp-Source: ABdhPJwtKDONFJnXM3l6XieFpUFkKYeCnx/AiIyevmR8d45Wb9NclxisRceP7AWzQFzEufeIRu+lMg==
X-Received: by 2002:a25:324b:: with SMTP id y72mr10047526yby.233.1613048172274;
        Thu, 11 Feb 2021 04:56:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9987:: with SMTP id p7ls887487ybo.11.gmail; Thu, 11 Feb
 2021 04:56:11 -0800 (PST)
X-Received: by 2002:a25:a08f:: with SMTP id y15mr11442357ybh.349.1613048171924;
        Thu, 11 Feb 2021 04:56:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613048171; cv=none;
        d=google.com; s=arc-20160816;
        b=vR/kCbCddiRDlPmlTjQqx7PyIsnN4urMdAnAcvsChT/awcJbjtzzzrO8pLISKXtO8L
         XdjSmZZrpIGU+EGeArtmTY8kZVXb0Py0kBvg6evs+V6SxmKfVtFs3aZ0kfZyxX9/kpNX
         /MZhN5OAszjeYF+5Iu282S0tFgem50Gwfd7/FqBxNDkYHEQqvUhZBbk8teHHgaUMsrfw
         JRGLAxpi9EIwMM7031SshV7fvlf5Fpz7553dNP2od8rr8/9OGmzb2HbSgciN/5lyA2mK
         1i1ZYmuRG7U7wKx8zF4yfr9zHP+9bZqA+UKidUWiIKt3OWfW8+kLzVsJNOONttntqBiI
         tafA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=nIurJyYnXooAph7japWF0bvwzDIzi3mVj0piGVE3cOg=;
        b=SmSVPvnPp9UglvW/0r+p4WbHNsXlVPy5dArWQxDohV/0FVEr2MUFwdazUKhKBAlyx0
         iFe6Vz3KMQKjDt9eOTIBcBzfRQ9fjgcZ3qGSzJP/INvY1yIKEJAb6MPoHNAM+JTOCfWP
         XiKPqBn4YcwkK29jmEyAL6y0yB4jh9cUMTRlZDUNBd3St8cJ4Kv8jePQSjCoDwxgezsL
         rbX1jbLz46SB+zFe1fKoDg95irUnBv43Sb/L7fS/2rGk2SqMJj8WXuelnIRoH5Yajmr9
         cZGmw2bMsNbT7v1yxZuVBje+nQMl65bGPw9+i6xW9uAHFRKOEFleYKcZ/VSZ3aDg3Y1P
         AOaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s44si352237ybi.3.2021.02.11.04.56.11
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 04:56:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 399B5113E;
	Thu, 11 Feb 2021 04:56:11 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1D4743F73B;
	Thu, 11 Feb 2021 04:56:10 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH] arm64: Fix warning in mte_get_random_tag()
Date: Thu, 11 Feb 2021 12:56:02 +0000
Message-Id: <20210211125602.44248-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

The simplification of mte_get_random_tag() caused the introduction of the
warning below:

In file included from arch/arm64/include/asm/kasan.h:9,
                 from include/linux/kasan.h:16,
                 from mm/kasan/common.c:14:
mm/kasan/common.c: In function =E2=80=98mte_get_random_tag=E2=80=99:
arch/arm64/include/asm/mte-kasan.h:45:9: warning: =E2=80=98addr=E2=80=99 is=
 used
                                         uninitialized [-Wuninitialized]
   45 |         asm(__MTE_PREAMBLE "irg %0, %0"
      |

Fix the warning initializing the address to NULL.

Note: mte_get_random_tag() returns a tag and it never dereferences the addr=
ess,
hence 'addr' can be safely initialized to NULL.

Fixes: c8f8de4c0887 ("arm64: kasan: simplify and inline MTE functions")
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---

This patch is based on linux-next/akpm

 arch/arm64/include/asm/mte-kasan.h | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mt=
e-kasan.h
index 3d58489228c0..b2850b750726 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -40,7 +40,12 @@ static inline u8 mte_get_mem_tag(void *addr)
 /* Generate a random tag. */
 static inline u8 mte_get_random_tag(void)
 {
-	void *addr;
+	/*
+	 * mte_get_random_tag() returns a tag and it
+	 * never dereferences the address, hence addr
+	 * can be safely initialized to NULL.
+	 */
+	void *addr =3D NULL;
=20
 	asm(__MTE_PREAMBLE "irg %0, %0"
 		: "+r" (addr));
--=20
2.30.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210211125602.44248-1-vincenzo.frascino%40arm.com.
