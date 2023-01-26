Return-Path: <kasan-dev+bncBCT4XGV33UIBBPEVZSPAMGQE5P2WEMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A49467D98B
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jan 2023 00:20:29 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id n16-20020a05600c3b9000b003db127e03c5sf3229288wms.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 15:20:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674775229; cv=pass;
        d=google.com; s=arc-20160816;
        b=d+CD8QBby5HBaJRjTGqkzffRr3J5Qc8y/ZhE8ScyR1T9UA+yUMFD6Xyc7IkN6ulOCQ
         aPdUTRV5Mwa7ywVmUn2YhMSXns9lEDNux1wwii1D9YhkMtqr1XZOQBlpZZN17A/jMyb6
         h9WHVwZW8cK+RDUzzw+/vbfYOdhxSsjJXPEGkrnDA9xWWd5G7uUVT5UkPV4LoNqB8sbQ
         MZLqOSsfVDUNUrTYN8l8pFCILCE3P16PGKhJEfeAPUuYGvAyeJdsami0RxbnAEd2zzZd
         HbNBanfSyPRFvj+t75H33rVfyaTfQArkr5eoVSVYQK7RGh5l6M6u3buD6rdtWXsSPGu+
         7SIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ZIAGfxsrTQB5yD98yYLm9j96rF93Wz+JK7kOW1B5FeA=;
        b=zgYtpApcaolaCsPbLr4ZLY7ap3GJQjE2gUBXTW92DnjGdyNo5DHuhmIGfSD2OhnwNc
         6fazqaCe+oR6e9O7Jx6sjibLho+Pfk5U8nHkZCFxiHCH9/6cI7WYl8Unl2Kc1hNO7e0/
         CB0nSArveAFtZWx6wjBfdvFwi7zJM/iEvl/JjaIbkFfMossst3XpFY653UY+4HcZ/ojZ
         eUn0XkCrlvjLaBK3hSYZmxpO2TwuKc6mbDJnbFDvUaYrz6FqclSGwybT4CLpTc48cPtA
         XdpgZggujaKfpV+xb3dPsjtuCoCd8OaGFuqi+jaOP/0iXd4Z6IbrYUy9qrPgf26Us0dw
         KrbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=wfU526Qe;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZIAGfxsrTQB5yD98yYLm9j96rF93Wz+JK7kOW1B5FeA=;
        b=mjVyuue1J/sLri2wRN0BFNkIDCs14L0OIpCqeP3WOuP6gAqHYOnyHLUJ6zY816vkFJ
         X3lqU/riXd1fRVTFZcatEJBaToYlCLPCfihRHR0Ex8BnFdHTW+0X98Ir3tLO5FZCb6Pf
         sLHaz7r0N9LoxRV2iYOeUVvVzzL/Rvm/PpbOrCtKmk7mNNxAgm5Mu11PHnux61l41xfp
         K/lWkMU3SU3FGaBF1vcdU0JQs4a6MREVNVhstjAQwrS2+ajhdU6+NGZFktb5VlFmUGzs
         I5pUUqxPwtoqbO0xhTMSPF6tY4fZlcbR+wWWDH2S331Ceec48/PhBQUhO7JjKbyYrZRq
         kHMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZIAGfxsrTQB5yD98yYLm9j96rF93Wz+JK7kOW1B5FeA=;
        b=lxbUNjkeSa0NRhRqqz3A1XNCPYlP7eUd/0kZPUrI7dUrNPrfcEtb8wV3g45aN+2ov0
         VPB4vkJxRpe631wLB4PHS1hDcvIdKkHC7aq0BdPWKzbSe3A4CmCFuBKKihPgbvUxtyPm
         uNABCVPIit6hhRVIMWlH+T3UJ+GlxetTCilmuelA3lSGPTm5sc9U+Rfy4m24L2iYmJMX
         +FviV2GzHptKwEldE6awayyNrMbG5ef59gpCR/WnFnF6PB1FFF3aV/O633OGPvmQiSgE
         7glrJcAAPe8OLNxYLrGi8bOk8liLTJic5/SXPvml3tRq2YN9mi3pZkldx15t6GBps3Ah
         VIMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVgH3ugMbP0gEx5w+0nhYxYzZlc6fUGEDaFS/fx0tsqCuVdSh+B
	U5wWnqeitW7QCr45pJjMdzg=
X-Google-Smtp-Source: AK7set/iwpMeAPyppRh2tpehQvCb0CfsUILAK8NXpWdYaTWO//BUpWXmLA9qelORtnYNGvWo4SK5hg==
X-Received: by 2002:a1c:2b01:0:b0:3dc:20e9:8f0d with SMTP id r1-20020a1c2b01000000b003dc20e98f0dmr374746wmr.54.1674775228817;
        Thu, 26 Jan 2023 15:20:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1ca4:b0:3cf:afd2:ab84 with SMTP id
 k36-20020a05600c1ca400b003cfafd2ab84ls1885196wms.2.-pod-control-gmail; Thu,
 26 Jan 2023 15:20:27 -0800 (PST)
X-Received: by 2002:a05:600c:5386:b0:3da:f670:a199 with SMTP id hg6-20020a05600c538600b003daf670a199mr36639859wmb.36.1674775227488;
        Thu, 26 Jan 2023 15:20:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674775227; cv=none;
        d=google.com; s=arc-20160816;
        b=yV/JGtZIhnRY4xBWnjv7NRTs64wKtV81osxwX447WbI+BUcBUyf0hZ2PPSVw0tGJew
         74mlk+j/0wGgBCujVClj0msaBSW9//HSwPoWBQbIBqfr+9IQByufl0NylKDK26baaxfC
         ohNcZmnT5y8q8CpKSPUp17WciqdEiHNYiprWS1v2yLgM9ghkQzStrpjBqJhyNvYkhz3z
         N1XPkQ4QX8DFvp3oJJgvJVC67HeU+oJ14DuxyqwJGUJKNCJvZ4+ng8cNeAsRP7dMDaXI
         IIhzhWLKz4/BhHzVqeIkPxk/TFSoWXYqITTO8bThhVArAZ+knyvU/lwCStQXR+z2AhM1
         w5Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cUxhMLW3rDCvoI8cfswvZyeAZJb4HVbmTo1x7ufLhJQ=;
        b=j4Bv98Fzpkkf/VIX7u81DFZ60wYWyTAoLSFpLC9wNqAFV/1DDyIhNZyqdoJEDQZ0dG
         sv/33BjrmCaT6WAXxa7ohomEGsOjcpMwS4gqj/v9TvLGuhaSrYyNm2a7HO/KCG9FJm22
         UVzCyMrDL/TII+jvrHmQAaoFPnND/RMWmteQ9uJNr37JIuRwbnb6m8Qrze93gE93bcqu
         zeDjn+qwQVhWx3EvhpqlEOCc5KqQZt9pQt/ivvtQv1GBDbIFUs8SlPxK7Hnk9rH1I4Nr
         5Lv40k6Qr+nbum90p01LI6fUZ5gsYNP1IOnj08bJ++9O6VbYLnPS2S1w8wzcHxN0Lvan
         JAIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=wfU526Qe;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id ay6-20020a05600c1e0600b003d9ae6cfd2esi224113wmb.2.2023.01.26.15.20.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Jan 2023 15:20:27 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 2EE8EB81ECD;
	Thu, 26 Jan 2023 23:20:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 74A8FC433D2;
	Thu, 26 Jan 2023 23:20:25 +0000 (UTC)
Date: Thu, 26 Jan 2023 15:20:24 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 linux-mm@kvack.org, kasan-dev@googlegroups.com, Nathan Lynch
 <nathanl@linux.ibm.com>, Michael Ellerman <mpe@ellerman.id.au>
Subject: Re: [PATCH] kasan: Fix Oops due to missing calls to
 kasan_arch_is_ready()
Message-Id: <20230126152024.bfdd25de2ff5107fa7c02986@linux-foundation.org>
In-Reply-To: <150768c55722311699fdcf8f5379e8256749f47d.1674716617.git.christophe.leroy@csgroup.eu>
References: <150768c55722311699fdcf8f5379e8256749f47d.1674716617.git.christophe.leroy@csgroup.eu>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=wfU526Qe;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 26 Jan 2023 08:04:47 +0100 Christophe Leroy <christophe.leroy@csgroup.eu> wrote:

> On powerpc64, you can build a kernel with KASAN as soon as you build it
> with RADIX MMU support. However if the CPU doesn't have RADIX MMU,
> KASAN isn't enabled at init and the following Oops is encountered.

Should we backport to -stable?  If so, can we identify a suitable Fixes: target?

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230126152024.bfdd25de2ff5107fa7c02986%40linux-foundation.org.
