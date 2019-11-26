Return-Path: <kasan-dev+bncBDV37XP3XYDRBJNV6TXAKGQEZ5S74SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A9AD109DF6
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 13:29:26 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id l20sf632169wrc.13
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 04:29:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574771365; cv=pass;
        d=google.com; s=arc-20160816;
        b=xah4BKkIH3htnhYihrEf0cHeESd69Ip1nKJRLq+mLVJmP0NTPNK/3InluT7gufSHVU
         3GKdEgLx8GDe0z9E58SlN8+JXjxhPSwxmNmlZzyyL3JQG22NKowTcr9N+TLViC++XFe4
         pNAOiwEEkSDqbsPm1iC7ys3+dYmKXAdMJ+AQsK7apFVzEXIVawvZxh/bTVFWHSYhjlfC
         Psm/jzZKuWzyxx/+P5b2qb0R7MiQei64C1yWiobXorhQmAPi3xAlZd3wwMdZI25nYWVu
         nZoibrQf7GsJLWgMkIgLL6yVGBLerZP3QkRgfVbuvTgzSiU+ie1EH90ympZN8oyx+TNY
         PDpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=8Aj4OZeJCpcAxqDgeMqQFueJ7kPbfF8SHgV0yiPKZfo=;
        b=aqzANAE9Yhx6UFhOBQgHDh+1W56Mf+7sypfqOeHIhZyA1O1QDBgaj++3N2TOxkrK/T
         jjHGoffnyoVgw8xyjYkA2XlBjkEG3ZJ4x18MEua/I5RzjWFXI4YLX1zagvHFSki45ub1
         7TFtJXIO+r36UcVJFr6AD73FgZUHNdLny+p//G/cQPA/iJ9RgqLgKuEoZknmSNTdkZc4
         fdbVCBsnh6YUMlZ701MKU8bbfcPcoJ8HIiOZim5JoFCz9w5IN4uXeBURlNmqNz429D3L
         sY1t3ypTtda39NE9lAKfH+Vfz/AhkJmSLmSnjb1C4fmq1odpmvpcNiyE3l1X8ItT3hkg
         PNIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8Aj4OZeJCpcAxqDgeMqQFueJ7kPbfF8SHgV0yiPKZfo=;
        b=XWK4xCALx6MAR7rQjYpS5lqAQ8WZPyImGxhGxsx1jKFostO/9ZmR136JNQxTUugzYU
         EYUbGRzTjYJMfxfsozbe/myQqFq0IdBNlI47mNwgQk8KpmFJc23dZeC7LtYby6HkyJaA
         FxDvr1VdbGESSYOYf3nkQURdQSZr/mTd7s+qJL8gsF4sHSGv8Mjq3QYk54FkjQYlmqI/
         e6yPm3R46OJYcBJFQ1uyQurhrAefPfvhc7+uOIwejg8gLZ1ZYUrpyxKx1GVGc/6v3tIV
         merjvhpRATKvl61libdaXYrEJR05ZIzHGw88cFj6oMH4wGxLxVLCIbo2I2uvYwy8Z/UJ
         YhFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8Aj4OZeJCpcAxqDgeMqQFueJ7kPbfF8SHgV0yiPKZfo=;
        b=Qd322bX65YcxxphJcSpIOgFeITFsdgJjuZjYH5SvnMBdQGV/Mm8qqUIeKxIFaV2ahj
         1amFgtxGuBr9iNCTwDTbb+7WO3x2mM8hJHLN5t02jfInbNn28ZFaWCizBMXTrEFS7lcS
         OV7oyxTGjNAh450OV+Fa0iZcTBy4cE9OuCByWGbwQlliraKRqtyRqTgFMnZYNX/jAJZB
         4TnISbxTCy7HEbhFe4joyTNI7T4BfU/suChTAm6hWrLfvog8A2NvzDzZLnJtHH/VaBlX
         Xp1PKluzlWJGFJ7g5UGVCP3lhXdtFZLMuC65uhyCCCDADLa+8BjH/zjcyq2GU4Cb7UQc
         iqDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWm/J8b7US4Jonx/PfkKmcBbVGIiAcX4xz7i8G1eLb9/0J5+tXy
	BB1BzgSPddzgKxaGwwDse6M=
X-Google-Smtp-Source: APXvYqxepK8B6twMm2kk2FDw084DlDNfiFr2UF8t8jpEWPgbkqgyc7II4C4xHy3uC7iFIzMTsLwPTg==
X-Received: by 2002:adf:f010:: with SMTP id j16mr37999997wro.206.1574771365833;
        Tue, 26 Nov 2019 04:29:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1008:: with SMTP id a8ls8617744wrx.3.gmail; Tue, 26
 Nov 2019 04:29:25 -0800 (PST)
X-Received: by 2002:adf:dfc6:: with SMTP id q6mr3362201wrn.235.1574771365224;
        Tue, 26 Nov 2019 04:29:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574771365; cv=none;
        d=google.com; s=arc-20160816;
        b=brHYgHw/i1omEkbdmEXrPlG01s3s2zI46jeGBsaAPYCmgM6iPHQ3Ce/YD0M3Hkfp1y
         b4SUC4u2/O/7SS//fjNratdC8W+YKbkJv26cW6cvgjdogWxZ8l3Wbt19bu8rc4UCQ8Ub
         rwqaYlnctvloz+Mha5MVBGJy9BvGMbToWPHEH+u39Mpn/sY8/ilwABL/JyJ4Nx4FlU84
         7v/NlTT5/yGthk/jG2SM4hgamzMUNH31o7GfYY8vpyQsuXTuqwSqwQUyHghGPc7WPw+Q
         MGVN7DU6pOvjnopN1FuUIXtKZtsf49W6ESmPauR9d9LvsimlVsCvRWqT6lggYz2MlMB5
         C2hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=lWwz/9kDrHPU7oL02b+cP8DiPcz80JUDFWe9OuDOHR8=;
        b=ueWR+YPSAqjrWtdw3MkrHlrqDTAbkA5w8zIx9qzoyleC/80IYk1OcDj7ogLjaAfT5v
         dJPuqineLhObIwjXT7Vr4gvAryPJoWhmgaLquDvE8lADXjM+sTk+TLzbyWB/zZOH5QLf
         XImCImbXT5k9R4vsG2pWP0IA6RVMwF9kMby+bV+j9E9aevPsV1bWu3hdSjnpMkPG1Ow9
         iZYsS/tJ0sB3wxhXLep6JwGtu7QPwOu1jQCwInGn/skHcSSGr659c7Ook0x1oezTsiPY
         lQGSKv5Bi2sahKRfhKPjNLvltAyoxgTFbhy34jsNdUl2EDm3PZN9fqQM+wT7paeaknPx
         Degg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id q128si99950wme.1.2019.11.26.04.29.25
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Nov 2019 04:29:25 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 511831FB;
	Tue, 26 Nov 2019 04:29:24 -0800 (PST)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DA5563F52E;
	Tue, 26 Nov 2019 04:29:22 -0800 (PST)
Date: Tue, 26 Nov 2019 12:29:18 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: will@kernel.org, peterz@infradead.org, boqun.feng@gmail.com,
	arnd@arndb.de, dvyukov@google.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com,
	paulmck@kernel.org, Randy Dunlap <rdunlap@infradead.org>
Subject: Re: [PATCH v2 1/3] asm-generic/atomic: Use __always_inline for pure
 wrappers
Message-ID: <20191126122917.GA37833@lakrids.cambridge.arm.com>
References: <20191126114121.85552-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191126114121.85552-1-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Tue, Nov 26, 2019 at 12:41:19PM +0100, Marco Elver wrote:
> Prefer __always_inline for atomic wrappers. When building for size
> (CC_OPTIMIZE_FOR_SIZE), some compilers appear to be less inclined to
> inline even relatively small static inline functions that are assumed to
> be inlinable such as atomic ops. This can cause problems, for example in
> UACCESS regions.
> 
> By using __always_inline, we let the real implementation and not the
> wrapper determine the final inlining preference.
> 
> For x86 tinyconfig we observe:
> - vmlinux baseline: 1316204
> - vmlinux with patch: 1315988 (-216 bytes)
> 
> This came up when addressing UACCESS warnings with CC_OPTIMIZE_FOR_SIZE
> in the KCSAN runtime:
> http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> 
> Reported-by: Randy Dunlap <rdunlap@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Add missing '#include <linux/compiler.h>'
> * Add size diff to commit message.
> 
> v1: http://lkml.kernel.org/r/20191122154221.247680-1-elver@google.com
> ---
>  include/asm-generic/atomic-instrumented.h | 335 +++++++++++-----------
>  include/asm-generic/atomic-long.h         | 331 ++++++++++-----------
>  scripts/atomic/gen-atomic-instrumented.sh |   7 +-
>  scripts/atomic/gen-atomic-long.sh         |   3 +-
>  4 files changed, 340 insertions(+), 336 deletions(-)

> diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> index 8b8b2a6f8d68..86d27252b988 100755
> --- a/scripts/atomic/gen-atomic-instrumented.sh
> +++ b/scripts/atomic/gen-atomic-instrumented.sh
> @@ -84,7 +84,7 @@ gen_proto_order_variant()
>  	[ ! -z "${guard}" ] && printf "#if ${guard}\n"
>  
>  cat <<EOF
> -static inline ${ret}
> +static __always_inline ${ret}
>  ${atomicname}(${params})
>  {
>  ${checks}
> @@ -146,17 +146,18 @@ cat << EOF
>  #ifndef _ASM_GENERIC_ATOMIC_INSTRUMENTED_H
>  #define _ASM_GENERIC_ATOMIC_INSTRUMENTED_H
>  
> +#include <linux/compiler.h>
>  #include <linux/build_bug.h>

Sorry for the (super) trivial nit, but could you please re-order these
two alphabetically, i.e.

#include <linux/build_bug.h>
#include <linux/compiler.h>

With that:

Acked-by: Mark Rutland <mark.rutland@arm.com>

[...]

> @@ -64,6 +64,7 @@ cat << EOF
>  #ifndef _ASM_GENERIC_ATOMIC_LONG_H
>  #define _ASM_GENERIC_ATOMIC_LONG_H
>  
> +#include <linux/compiler.h>
>  #include <asm/types.h>

Unlike the above, this doesn't need to be re-ordered; for whatever
reason, linux/* includes typically come before asm/* includes.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191126122917.GA37833%40lakrids.cambridge.arm.com.
