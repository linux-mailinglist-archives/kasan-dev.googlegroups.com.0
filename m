Return-Path: <kasan-dev+bncBDHJX64K2UNBB7WSR23QMGQE3V622TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 10CA297771F
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 04:54:56 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3a0862f232fsf16430825ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2024 19:54:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726196094; cv=pass;
        d=google.com; s=arc-20240605;
        b=HdoygHS8lADuLnNPv3UHXUG+LChuyXEdCQ8CE5ZJQHJx2Ofm/54YuamR0xlUZ+IAUj
         bK0nn3Bv++W5aHdqI89bIW0PbefiWEn6XYDtTBHIKpeOaUdi4gqIf2UK8vTCVh02hTdm
         lrdwrgQbTNQvF3zXoz+IhqirknGh01Dy9aOeI+a3d7dTsW/TfBablA3g4i70OE2LIabS
         /bqe/G2Qh5O3TIXccGnpJJGTQGXptYrcjnx2Mi3+t1u3Oegb7SQVteqwIOJ0rPBuClja
         Pu/AC2AATreaTis4zbiMfkSLRBFF6f/IU3D/+eWlvBL6f1hLQVXv6ogKeWfkJeYlSDzV
         h93w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SlWlOadfVW/Plqje/M/HY1RZCm0Pn2w0VW6Vi8rKSTw=;
        fh=fcRmprG0E0qUVH/UI3XtSC8HVKwoy5BVLebtr+YcmQg=;
        b=fncwculVQWf83deba6zJo+flNwB3VZhWQJ4MBoDK+kE1z/BrWvOhjEsz70oileKKcG
         3DP/W277U1419NMVqK+N7jxMUmerUZN9f36a6j2BmCGL/y1Dia5MYLIeoNwG3OVWSnCS
         XIQc+6JUVcB8poZ7O8yEtcK84RWhp2s6Tpmi4ASTHc/uOJPU3r+X5VWEHTco55GK4WrG
         mD+q0Qh8qYlkHNR3cxS41DcPYwW6F+SWPKBdFGKM0gXHhuXw2EIWsp+6Yv4dzt2TsC5Y
         xoSr3aBOULPcxQUUaI1K2PMh73qBjk77tU6fJ/8JIdqmD+E7KGtaUuSXrkMoCXcGDXhu
         pIjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=BF0475CS;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726196094; x=1726800894; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SlWlOadfVW/Plqje/M/HY1RZCm0Pn2w0VW6Vi8rKSTw=;
        b=kaXlTfcIE6GChv3ZAGyw49ByhxfVWbszx4qFQ3ItdKakwB5USf3Nbjdgnmj0C+g7JN
         d1VN7rAGY5xvtO9wf0ump/fIY3zbWhqDDt+GId8McyWrYScnCoytoVb2KIXLzrsEz+wI
         R/vHY0ANVcPXd0Rmienf5NxSOEhG7V0n5pcudlZLclAP+eazufP7zVP1tr6ZNLDMCpQI
         +0UuNeKNR88h6mTzkWTKGWInhjqNqBzmNLrZJgpJ4OkkYurjLnrfc5Ln0HKWe8k/OkEM
         zf+s9EwoTDWjTl1+KSojdTWC7GxqYDohadlyidvuNmvShKKQIBnI3+fcNXHqNbNfo9f6
         wQuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726196094; x=1726800894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SlWlOadfVW/Plqje/M/HY1RZCm0Pn2w0VW6Vi8rKSTw=;
        b=EaBRSzf+1t9aO8TpzkNfiuoGLPdpiHXkOb0HpkIIQLKfTcoFRjIcozBK3ZwtX+0p2J
         APxlCoYFefShyKkLm7oQdGr2M7LsRT56amV3XxVSWywjuP0KGGkYwWyZCkRN00ldFYzy
         rnf/geY3jM4qNoHHXLO5+i0+KOEc2NuH2OArIHJzvJmJhrxD/H1zCwipKy4EMcqou+Jj
         SXEaRop/Smeu+kXZ6/ja/P/4xYgfYH5fmlUrnHMf4POvkc2ia9d6hapAxnGRvAz+p1J2
         tMDDVCIOw3y/o41bkC6v1lAU9iV0nRIVOH1jWWV77a75QjzSBx+8ZVAbNjkFzRkNWRfH
         wB9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU53DhKwp83jC8y4J0W87CVQCkpO/qMB5tvcHC3pP9N4jMuliK5sejE2U+NMutBWtZfEz6Kzw==@lfdr.de
X-Gm-Message-State: AOJu0Yxk1XNAaBYUkCmN+DmV4KX2WjD7sGtIH4qmsrpMz2y3CwRJhBdw
	Pb1LsaaDm2XD81rAp5bdOhPGOGT8By8ZPOD8cKz3TQyqCHajHdSF
X-Google-Smtp-Source: AGHT+IGxB4tnUr9sqnqp8eB79Ldih6Qvkn2AKd2/LBxnDjxwpkKzVo6a2hsLsA5yC7q/BlT3bO00kw==
X-Received: by 2002:a05:6e02:174f:b0:3a0:5388:494 with SMTP id e9e14a558f8ab-3a084971b1amr53215245ab.23.1726196094441;
        Thu, 12 Sep 2024 19:54:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:19cd:b0:39d:52b9:5478 with SMTP id
 e9e14a558f8ab-3a084090238ls10325615ab.0.-pod-prod-01-us; Thu, 12 Sep 2024
 19:54:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQ0p3gg130rHYuonDqJ2Kl1GCuDCpxgPjhvhqyGXdWNmkHpzjRI21lAXZEqDKlUmH8S+7O4fr1TvQ=@googlegroups.com
X-Received: by 2002:a05:6602:1555:b0:82d:2a45:79f6 with SMTP id ca18e2360f4ac-82d2a458bf6mr422296839f.11.1726196093433;
        Thu, 12 Sep 2024 19:54:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726196093; cv=none;
        d=google.com; s=arc-20240605;
        b=Jao77CuqXK7GryChrJpBShpPICeAdF1vtLKOVqWmCP1yXjuVo+Sj70TUpyRQf29C4D
         5i4q4CrSQPWALCQzRiFASbbPFtDztubWVomXChVo7Dd5FgmxfbEcCcCSHT+J51RbMxHv
         Uhh11unwIWgULFIxgoBWt/eZuAqUt23yp7jNapEqcsLEL+qodvLacSz9nHmcvor56+vj
         Es0Kd67ePRZ4Ffhq01QkPiAoeQFbHxeFeQbMafuXcJ6xhnwUnfw3HExqtkfwXM1e870c
         5RuBHSbOT/P1jAqhd5E/IEljD03rS8XBftTv7M1N6ffRcFg84d1X6zjDQvlzafHwtmsv
         1cIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=J/P8PUdJnvCleQHGflHWKJwQSU5jI0eeDWaSn23VHlk=;
        fh=hj/jqYs4sQ39RrihNmo2qVNSSHCtINr4XQX4R8VAEGI=;
        b=fz92oYWscHzUT7qL4vTFKqWhMCbBHxJf1OQAjdQbGFUrkejt649cvK+zhIn+SIn9OW
         5Wunp43ZrGNDxLIFBR6ikD/ibM88c3ivetWhG+rz84DeXQwyMZT+oYNvdQKaHI82fz2z
         IsdYIQtAxl1JBobPAWD/9Tz5NCb1d6PaXDG5klZDQSs5E2NBaqiphFOX+AyAXND/6U7u
         W1XZil4FjCN2nEJm2n3mZEhtku9hx639CnIMBrUCB9IFBGLQE5H2NZipY0FtyOrWCWXH
         o7nB6U2LOJ2tX/pd3qvsRclOHnDD0VzMtWTE0M0wInhiTyolipRHfu0/fPAjv7GDOIc9
         69wA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=BF0475CS;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4d35f439336si166362173.2.2024.09.12.19.54.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Sep 2024 19:54:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-1fc47abc040so15168905ad.0
        for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2024 19:54:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUr4rX7KqKWflNeQQmwoTuzWTNUGt+1OQbQzEoR7s/xv0shul1Ig+XkxyVYY7p56bnxw0OYXL7EzNc=@googlegroups.com
X-Received: by 2002:a17:903:185:b0:205:8425:e9c6 with SMTP id d9443c01a7336-2076e43fe94mr56673625ad.52.1726196092428;
        Thu, 12 Sep 2024 19:54:52 -0700 (PDT)
Received: from ghost ([50.145.13.30])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2076b01a329sm20082975ad.290.2024.09.12.19.54.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Sep 2024 19:54:51 -0700 (PDT)
Date: Thu, 12 Sep 2024 19:54:49 -0700
From: Charlie Jenkins <charlie@rivosinc.com>
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
	devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Subject: Re: [PATCH v4 07/10] selftests: riscv: Add a pointer masking test
Message-ID: <ZuOpeSDO173y8Ut7@ghost>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-8-samuel.holland@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240829010151.2813377-8-samuel.holland@sifive.com>
X-Original-Sender: charlie@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=BF0475CS;       spf=pass (google.com: domain of charlie@rivosinc.com
 designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Aug 28, 2024 at 06:01:29PM -0700, Samuel Holland wrote:
> This test covers the behavior of the PR_SET_TAGGED_ADDR_CTRL and
> PR_GET_TAGGED_ADDR_CTRL prctl() operations, their effects on the
> userspace ABI, and their effects on the system call ABI.
> 
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>

Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>
Tested-by: Charlie Jenkins <charlie@rivosinc.com>

> ---
> 
> (no changes since v2)
> 
> Changes in v2:
>  - Rename "tags" directory to "pm" to avoid .gitignore rules
>  - Add .gitignore file to ignore the compiled selftest binary
>  - Write to a pipe to force dereferencing the user pointer
>  - Handle SIGSEGV in the child process to reduce dmesg noise
> 
>  tools/testing/selftests/riscv/Makefile        |   2 +-
>  tools/testing/selftests/riscv/pm/.gitignore   |   1 +
>  tools/testing/selftests/riscv/pm/Makefile     |  10 +
>  .../selftests/riscv/pm/pointer_masking.c      | 330 ++++++++++++++++++
>  4 files changed, 342 insertions(+), 1 deletion(-)
>  create mode 100644 tools/testing/selftests/riscv/pm/.gitignore
>  create mode 100644 tools/testing/selftests/riscv/pm/Makefile
>  create mode 100644 tools/testing/selftests/riscv/pm/pointer_masking.c
> 
> diff --git a/tools/testing/selftests/riscv/Makefile b/tools/testing/selftests/riscv/Makefile
> index 7ce03d832b64..2ee1d1548c5f 100644
> --- a/tools/testing/selftests/riscv/Makefile
> +++ b/tools/testing/selftests/riscv/Makefile
> @@ -5,7 +5,7 @@
>  ARCH ?= $(shell uname -m 2>/dev/null || echo not)
>  
>  ifneq (,$(filter $(ARCH),riscv))
> -RISCV_SUBTARGETS ?= hwprobe vector mm sigreturn
> +RISCV_SUBTARGETS ?= hwprobe mm pm sigreturn vector
>  else
>  RISCV_SUBTARGETS :=
>  endif
> diff --git a/tools/testing/selftests/riscv/pm/.gitignore b/tools/testing/selftests/riscv/pm/.gitignore
> new file mode 100644
> index 000000000000..b38358f91c4d
> --- /dev/null
> +++ b/tools/testing/selftests/riscv/pm/.gitignore
> @@ -0,0 +1 @@
> +pointer_masking
> diff --git a/tools/testing/selftests/riscv/pm/Makefile b/tools/testing/selftests/riscv/pm/Makefile
> new file mode 100644
> index 000000000000..ed82ff9c664e
> --- /dev/null
> +++ b/tools/testing/selftests/riscv/pm/Makefile
> @@ -0,0 +1,10 @@
> +# SPDX-License-Identifier: GPL-2.0
> +
> +CFLAGS += -I$(top_srcdir)/tools/include
> +
> +TEST_GEN_PROGS := pointer_masking
> +
> +include ../../lib.mk
> +
> +$(OUTPUT)/pointer_masking: pointer_masking.c
> +	$(CC) -static -o$@ $(CFLAGS) $(LDFLAGS) $^
> diff --git a/tools/testing/selftests/riscv/pm/pointer_masking.c b/tools/testing/selftests/riscv/pm/pointer_masking.c
> new file mode 100644
> index 000000000000..0fe80f963ace
> --- /dev/null
> +++ b/tools/testing/selftests/riscv/pm/pointer_masking.c
> @@ -0,0 +1,330 @@
> +// SPDX-License-Identifier: GPL-2.0-only
> +
> +#include <errno.h>
> +#include <fcntl.h>
> +#include <setjmp.h>
> +#include <signal.h>
> +#include <stdbool.h>
> +#include <sys/prctl.h>
> +#include <sys/wait.h>
> +#include <unistd.h>
> +
> +#include "../../kselftest.h"
> +
> +#ifndef PR_PMLEN_SHIFT
> +#define PR_PMLEN_SHIFT			24
> +#endif
> +#ifndef PR_PMLEN_MASK
> +#define PR_PMLEN_MASK			(0x7fUL << PR_PMLEN_SHIFT)
> +#endif
> +
> +static int dev_zero;
> +
> +static int pipefd[2];
> +
> +static sigjmp_buf jmpbuf;
> +
> +static void sigsegv_handler(int sig)
> +{
> +	siglongjmp(jmpbuf, 1);
> +}
> +
> +static int min_pmlen;
> +static int max_pmlen;
> +
> +static inline bool valid_pmlen(int pmlen)
> +{
> +	return pmlen == 0 || pmlen == 7 || pmlen == 16;
> +}
> +
> +static void test_pmlen(void)
> +{
> +	ksft_print_msg("Testing available PMLEN values\n");
> +
> +	for (int request = 0; request <= 16; request++) {
> +		int pmlen, ret;
> +
> +		ret = prctl(PR_SET_TAGGED_ADDR_CTRL, request << PR_PMLEN_SHIFT, 0, 0, 0);
> +		if (ret)
> +			goto pr_set_error;
> +
> +		ret = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
> +		ksft_test_result(ret >= 0, "PMLEN=%d PR_GET_TAGGED_ADDR_CTRL\n", request);
> +		if (ret < 0)
> +			goto pr_get_error;
> +
> +		pmlen = (ret & PR_PMLEN_MASK) >> PR_PMLEN_SHIFT;
> +		ksft_test_result(pmlen >= request, "PMLEN=%d constraint\n", request);
> +		ksft_test_result(valid_pmlen(pmlen), "PMLEN=%d validity\n", request);
> +
> +		if (min_pmlen == 0)
> +			min_pmlen = pmlen;
> +		if (max_pmlen < pmlen)
> +			max_pmlen = pmlen;
> +
> +		continue;
> +
> +pr_set_error:
> +		ksft_test_result_skip("PMLEN=%d PR_GET_TAGGED_ADDR_CTRL\n", request);
> +pr_get_error:
> +		ksft_test_result_skip("PMLEN=%d constraint\n", request);
> +		ksft_test_result_skip("PMLEN=%d validity\n", request);
> +	}
> +
> +	if (max_pmlen == 0)
> +		ksft_exit_fail_msg("Failed to enable pointer masking\n");
> +}
> +
> +static int set_tagged_addr_ctrl(int pmlen, bool tagged_addr_abi)
> +{
> +	int arg, ret;
> +
> +	arg = pmlen << PR_PMLEN_SHIFT | tagged_addr_abi;
> +	ret = prctl(PR_SET_TAGGED_ADDR_CTRL, arg, 0, 0, 0);
> +	if (!ret) {
> +		ret = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
> +		if (ret == arg)
> +			return 0;
> +	}
> +
> +	return ret < 0 ? -errno : -ENODATA;
> +}
> +
> +static void test_dereference_pmlen(int pmlen)
> +{
> +	static volatile int i;
> +	volatile int *p;
> +	int ret;
> +
> +	ret = set_tagged_addr_ctrl(pmlen, false);
> +	if (ret)
> +		return ksft_test_result_error("PMLEN=%d setup (%d)\n", pmlen, ret);
> +
> +	i = pmlen;
> +
> +	if (pmlen) {
> +		p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen);
> +
> +		/* These dereferences should succeed. */
> +		if (sigsetjmp(jmpbuf, 1))
> +			return ksft_test_result_fail("PMLEN=%d valid tag\n", pmlen);
> +		if (*p != pmlen)
> +			return ksft_test_result_fail("PMLEN=%d bad value\n", pmlen);
> +		*p++;
> +	}
> +
> +	p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen - 1);
> +
> +	/* These dereferences should raise SIGSEGV. */
> +	if (sigsetjmp(jmpbuf, 1))
> +		return ksft_test_result_pass("PMLEN=%d dereference\n", pmlen);
> +	*p++;
> +	ksft_test_result_fail("PMLEN=%d invalid tag\n", pmlen);
> +}
> +
> +static void test_dereference(void)
> +{
> +	ksft_print_msg("Testing userspace pointer dereference\n");
> +
> +	signal(SIGSEGV, sigsegv_handler);
> +
> +	test_dereference_pmlen(0);
> +	test_dereference_pmlen(min_pmlen);
> +	test_dereference_pmlen(max_pmlen);
> +
> +	signal(SIGSEGV, SIG_DFL);
> +}
> +
> +static void execve_child_sigsegv_handler(int sig)
> +{
> +	exit(42);
> +}
> +
> +static int execve_child(void)
> +{
> +	static volatile int i;
> +	volatile int *p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - 7);
> +
> +	signal(SIGSEGV, execve_child_sigsegv_handler);
> +
> +	/* This dereference should raise SIGSEGV. */
> +	return *p;
> +}
> +
> +static void test_fork_exec(void)
> +{
> +	int ret, status;
> +
> +	ksft_print_msg("Testing fork/exec behavior\n");
> +
> +	ret = set_tagged_addr_ctrl(min_pmlen, false);
> +	if (ret)
> +		return ksft_test_result_error("setup (%d)\n", ret);
> +
> +	if (fork()) {
> +		wait(&status);
> +		ksft_test_result(WIFEXITED(status) && WEXITSTATUS(status) == 42,
> +				 "dereference after fork\n");
> +	} else {
> +		static volatile int i = 42;
> +		volatile int *p = (volatile int *)((uintptr_t)&i | 1UL << __riscv_xlen - min_pmlen);
> +
> +		/* This dereference should succeed. */
> +		exit(*p);
> +	}
> +
> +	if (fork()) {
> +		wait(&status);
> +		ksft_test_result(WIFEXITED(status) && WEXITSTATUS(status) == 42,
> +				 "dereference after fork+exec\n");
> +	} else {
> +		/* Will call execve_child(). */
> +		execve("/proc/self/exe", (char *const []) { "", NULL }, NULL);
> +	}
> +}
> +
> +static void test_tagged_addr_abi_sysctl(void)
> +{
> +	char value;
> +	int fd;
> +
> +	ksft_print_msg("Testing tagged address ABI sysctl\n");
> +
> +	fd = open("/proc/sys/abi/tagged_addr_disabled", O_WRONLY);
> +	if (fd < 0) {
> +		ksft_test_result_skip("failed to open sysctl file\n");
> +		ksft_test_result_skip("failed to open sysctl file\n");
> +		return;
> +	}
> +
> +	value = '1';
> +	pwrite(fd, &value, 1, 0);
> +	ksft_test_result(set_tagged_addr_ctrl(min_pmlen, true) == -EINVAL,
> +			 "sysctl disabled\n");
> +
> +	value = '0';
> +	pwrite(fd, &value, 1, 0);
> +	ksft_test_result(set_tagged_addr_ctrl(min_pmlen, true) == 0,
> +			 "sysctl enabled\n");
> +
> +	set_tagged_addr_ctrl(0, false);
> +
> +	close(fd);
> +}
> +
> +static void test_tagged_addr_abi_pmlen(int pmlen)
> +{
> +	int i, *p, ret;
> +
> +	i = ~pmlen;
> +
> +	if (pmlen) {
> +		p = (int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen);

I am trying to put something together with
https://lore.kernel.org/linux-mm/20240905-patches-below_hint_mmap-v3-2-3cd5564efbbb@rivosinc.com/T/
to ensure that the upper addresses aren't allocated. This is only
relevant on sv57 and PMLEN=16 hardware where addresses could overlap.

> +
> +		ret = set_tagged_addr_ctrl(pmlen, false);
> +		if (ret)
> +			return ksft_test_result_error("PMLEN=%d ABI disabled setup (%d)\n",
> +						      pmlen, ret);
> +
> +		ret = write(pipefd[1], p, sizeof(*p));
> +		if (ret >= 0 || errno != EFAULT)
> +			return ksft_test_result_fail("PMLEN=%d ABI disabled write\n", pmlen);
> +
> +		ret = read(dev_zero, p, sizeof(*p));
> +		if (ret >= 0 || errno != EFAULT)
> +			return ksft_test_result_fail("PMLEN=%d ABI disabled read\n", pmlen);
> +
> +		if (i != ~pmlen)
> +			return ksft_test_result_fail("PMLEN=%d ABI disabled value\n", pmlen);
> +
> +		ret = set_tagged_addr_ctrl(pmlen, true);
> +		if (ret)
> +			return ksft_test_result_error("PMLEN=%d ABI enabled setup (%d)\n",
> +						      pmlen, ret);
> +
> +		ret = write(pipefd[1], p, sizeof(*p));
> +		if (ret != sizeof(*p))
> +			return ksft_test_result_fail("PMLEN=%d ABI enabled write\n", pmlen);
> +
> +		ret = read(dev_zero, p, sizeof(*p));
> +		if (ret != sizeof(*p))
> +			return ksft_test_result_fail("PMLEN=%d ABI enabled read\n", pmlen);
> +
> +		if (i)
> +			return ksft_test_result_fail("PMLEN=%d ABI enabled value\n", pmlen);
> +
> +		i = ~pmlen;
> +	} else {
> +		/* The tagged address ABI cannot be enabled when PMLEN == 0. */
> +		ret = set_tagged_addr_ctrl(pmlen, true);
> +		if (ret != -EINVAL)
> +			return ksft_test_result_error("PMLEN=%d ABI setup (%d)\n",
> +						      pmlen, ret);
> +	}
> +
> +	p = (int *)((uintptr_t)&i | 1UL << __riscv_xlen - pmlen - 1);
> +
> +	ret = write(pipefd[1], p, sizeof(*p));
> +	if (ret >= 0 || errno != EFAULT)
> +		return ksft_test_result_fail("PMLEN=%d invalid tag write (%d)\n", pmlen, errno);
> +
> +	ret = read(dev_zero, p, sizeof(*p));
> +	if (ret >= 0 || errno != EFAULT)
> +		return ksft_test_result_fail("PMLEN=%d invalid tag read\n", pmlen);
> +
> +	if (i != ~pmlen)
> +		return ksft_test_result_fail("PMLEN=%d invalid tag value\n", pmlen);
> +
> +	ksft_test_result_pass("PMLEN=%d tagged address ABI\n", pmlen);
> +}
> +
> +static void test_tagged_addr_abi(void)
> +{
> +	ksft_print_msg("Testing tagged address ABI\n");
> +
> +	test_tagged_addr_abi_pmlen(0);
> +	test_tagged_addr_abi_pmlen(min_pmlen);
> +	test_tagged_addr_abi_pmlen(max_pmlen);
> +}
> +
> +static struct test_info {
> +	unsigned int nr_tests;
> +	void (*test_fn)(void);
> +} tests[] = {
> +	{ .nr_tests = 17 * 3, test_pmlen },
> +	{ .nr_tests = 3, test_dereference },
> +	{ .nr_tests = 2, test_fork_exec },
> +	{ .nr_tests = 2, test_tagged_addr_abi_sysctl },
> +	{ .nr_tests = 3, test_tagged_addr_abi },
> +};
> +
> +int main(int argc, char **argv)
> +{
> +	unsigned int plan = 0;
> +	int ret;
> +
> +	/* Check if this is the child process after execve(). */
> +	if (!argv[0][0])
> +		return execve_child();
> +
> +	dev_zero = open("/dev/zero", O_RDWR);
> +	if (dev_zero < 0)
> +		return 1;
> +
> +	/* Write to a pipe so the kernel must dereference the buffer pointer. */
> +	ret = pipe(pipefd);
> +	if (ret)
> +		return 1;
> +
> +	ksft_print_header();
> +
> +	for (int i = 0; i < ARRAY_SIZE(tests); ++i)
> +		plan += tests[i].nr_tests;
> +
> +	ksft_set_plan(plan);
> +
> +	for (int i = 0; i < ARRAY_SIZE(tests); ++i)
> +		tests[i].test_fn();
> +
> +	ksft_finished();
> +}
> -- 
> 2.45.1
> 
> 
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuOpeSDO173y8Ut7%40ghost.
