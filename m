Return-Path: <kasan-dev+bncBDCPL7WX3MKBBVURT7AAMGQEXVKYU2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C943A97312
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 18:50:32 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-60601184d87sf3161870eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 09:50:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745340630; cv=pass;
        d=google.com; s=arc-20240605;
        b=LbSSjJIwCkqdNzRTEfpRmKJz1LWD+sHflE0xhrPAJ1PufBIe3NlDS7EKmTOTrKlJhL
         v3alJzMd4zSGlhqT0MBVdkpVJJMi1yIQoIqh56v/3ebs4WYcc6gvaTVeeICCsQasQth1
         86/0NAjyJjsyCgkFG6+5qUAlz6A4QeQQ7TzjxozRRhu0wL/CxmUwny+nBS2e72xx4J6V
         /XuOTOuZEfu/UT3xcqlL5duvmxkBC9gC4yFv5lLT8D23JP4b63y7IW48/XwxDyFEiIqq
         ZTQAdV2ib+8lo5EtEo8ytlEIyX5U4/OtF6MF3qBkwyQFDflOzLejbW0EE8sNadthfOR8
         NMVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=RuhxBC97FWEqINLlyTZRR4fNvG736ggmJV5m82jR0wU=;
        fh=JrX/+7QxuPAIw4ejN94gipaX0jfGUrH5GL8htupumfc=;
        b=QPUbAv7lCikn8d8EPlvgCslk3M3pevlPJla4Jp6raU6EYPhUfErI67enfJFp8HC/Xb
         EUr5p84rElNuI2/4SBwtUYq7p9DzWJGeX9H9ewadP8/sQc1qX2VsW89l1QkSaEDYMmOL
         1ghRD4Mi1ajroRAVya5EdVqKrdSbbVC9pme/xmqsH888e+c5r9VzWlW6ap/zp4+EUiZz
         9Otq0m0DeYFL2XIiKfEb1Dd7/Dy+iXD9khnTbp72P3zKxhXYei0af5Qstx62b48erzYd
         X535xvwmnGGeiXHxQROU3xyjPg5R4Hw2zREqs7g5wwAJbktu6R6oLBuck31Rb4Pa5niQ
         tgdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=K56C1Rmx;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745340630; x=1745945430; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=RuhxBC97FWEqINLlyTZRR4fNvG736ggmJV5m82jR0wU=;
        b=Gz5rVj0JkteUoSM1xyqyA5r9LCjRQknaypm1kT8a41TsoaLd5JlX68dFOwKwbzdC/Q
         YgxF1lBpXogrdwBU72AMGMcUe1eBfSw8giqXsxYwIit0sM2tm+GLEIaTeuNa3/4riX1S
         d+9BLuX+p0PrEvURwC1tPB2OZ4RKJfDuLMOUu6jNX/Fx1awm1Be/jbNKGuK6D4gK57ir
         FYVp0vCWqrMwL3bMLEjYvFBicpLJ7gJ9HkJeiAcGaDTNzx+nz81TVnQvu9kH+hL/NEZv
         iPVt1YmILoKCNJfgrul5mzCWE+NoHtN9n1+LJL/XwAEYiOyGrQsEFa+FquaHgDb48XaF
         bWNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745340630; x=1745945430;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RuhxBC97FWEqINLlyTZRR4fNvG736ggmJV5m82jR0wU=;
        b=wSNcKLkU+m8LpU4d+tHbMdDjg03YxL32hMf51u+7ORQ6itJGVIxamrFeal5wNKFOmI
         qL+Jfg6mCDTCUc3K3sTOJUsV4QfWjQ2qtlkLfW8eMZ9d6LXCHDyBNyAPClpy52emgTdn
         NnO04xRaDS/igxqknOlq4Rau2ldVid33QgXEe1LGetcduzHsjk5u8J3NZKZUTuezFlAw
         kBEVDuhKyYTbRT3aqAfdnIbR+cmazNdfEPU5Vqur5eLLFvOLDBvpnZUzdjikVUETVVgl
         m/ZPyKykRLkZRX3LeUNiZwoOEWT9x2WJ70td9GmUHzxbYQW3xZe2ae4rUJan9Cpu/xZj
         rgUg==
X-Forwarded-Encrypted: i=2; AJvYcCWM0ezEj2BmfSdNCwtHCB4f3urWEzgdusSgBycz0B4yTC8fIebRkKBs561L6LV1+/+A3vrZJA==@lfdr.de
X-Gm-Message-State: AOJu0YwqPci5T5BD12fU7YZJ6d6F2UB1ihB3P9NYjBSgqGbvy8JBVG8k
	04W5O4ibHQs/OW3RUeF0GuKamZLstoQe4pnNkzdQagExPUD3aT5H
X-Google-Smtp-Source: AGHT+IEhDRMe5LJwmIgcdRiSPIMwO8SRLKoimkDF0UHdLhsCsxkh2w64PQt7j1ogYTuySQkVfliZ6A==
X-Received: by 2002:a05:6871:d80a:b0:2d4:ce45:6983 with SMTP id 586e51a60fabf-2d526a2dc1fmr9197997fac.10.1745340630475;
        Tue, 22 Apr 2025 09:50:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIPfimG3LsCN8QmNFMQTNv30BoSzVjGZygsQTbX7JKg1A==
Received: by 2002:a05:6871:788d:b0:2c2:33d9:946e with SMTP id
 586e51a60fabf-2d4ebf02eb1ls2534091fac.1.-pod-prod-08-us; Tue, 22 Apr 2025
 09:50:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpFZSJW8iEEp9zt4UeDwx0N9srqRRw+HslDMeYdYFEqACSy35MBL+2xmYvnznjL0qU0MzYowTO+T8=@googlegroups.com
X-Received: by 2002:a05:6871:ba0a:b0:2d5:4899:90c with SMTP id 586e51a60fabf-2d5489a2887mr7041525fac.7.1745340629149;
        Tue, 22 Apr 2025 09:50:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745340629; cv=none;
        d=google.com; s=arc-20240605;
        b=DLXPDfLvb2BeAdJFNEqjoSpHhSPpNqzjwopemF7ybcPss4vzH4gWifogbGXuGAEmaV
         CVkDaUkW0mLQv1ZxPvGMDUsphSZsgk7w1jnZBIjz27kJIYfOcjDLo+xfPFjAqGFBkJRh
         wRKBKrqdJHfKRQBsEO/QLfuUwLKu7Iqgo8hD1wc852/Eza7kGGPJHYjV3YBVYzpXALJu
         V0pFus2wJBZi9nwcrs0IGMRBoOLf7gDQGS7UOGrqgtisBt+xG3e1DkCBlydScY2KiQEJ
         2PDMDZYtamv1S/9dIqL6xDd5HZcLpko/vdWgKUkfJPA6S89qFGFFE+tpR2mqjeYQF2Wd
         0Klw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=I+ZIvprjLuWp/yEqxULPe+90NsvvPV0RP3+xhVQmqww=;
        fh=Zi1DiPI5BKKQHBqKwWz2XDPc2/spRgnEkvhtTBuysWs=;
        b=HKHtg4K/4kEM+wssisaetSmJ3gY+GXlcK+lNUjuNZeojom358Uu7IkEUeS9PcJx2sh
         AU5eGrbsf3LChKoABqFiPxy2Yv0XqCiVwQaKI8XIfFk8YM4rIalAar0v3kCHq8wckHD6
         WwaR+4Rartu/TKoBd9onuAExmtIhXF25ZLJV4EQY0pvp3xdOctqDM8eGKu1VepGrJI8y
         xqv9W+d9Ovo8yY8wXXYQg3AlVCl+XUUQqWE4CVFQe2HR4GPj1xy7qB3+lZSBGhyC+cYV
         /TeacXIzruIUmJL9H+ZjSbtAigDsK+1EJysBkuGNa2AYmMz6e/vIgDiyInsbgekJ4uG4
         fyJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=K56C1Rmx;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2d5212c9856si296429fac.1.2025.04.22.09.50.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 22 Apr 2025 09:50:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 125AF43F30;
	Tue, 22 Apr 2025 16:50:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 67DF4C4CEE9;
	Tue, 22 Apr 2025 16:50:28 +0000 (UTC)
Date: Tue, 22 Apr 2025 09:50:24 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Erhard Furtner <erhard_f@mailbox.org>
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com
Subject: Re: BUG: KASAN: vmalloc-out-of-bounds in vrealloc_noprof+0x195/0x220
 at running fortify_kunit (v6.15-rc1, x86_64)
Message-ID: <202504220910.BAD42F0DC@keescook>
References: <20250408192503.6149a816@outsider.home>
 <20250421120408.04d7abdf@outsider.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250421120408.04d7abdf@outsider.home>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=K56C1Rmx;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Mon, Apr 21, 2025 at 12:04:08PM +0200, Erhard Furtner wrote:
> fortify_test_alloc_size_kvmalloc_const test failure still in v6.15-rc3, also with a 'GCC14 -O2'-built kernel:
> [...]
> BUG: KASAN: vmalloc-out-of-bounds in vrealloc_noprof+0x2a2/0x370
> [...]
>     not ok 7 fortify_test_alloc_size_kvmalloc_const
> [...]
> > I gave v6.15-rc1 a test ride on my Ryzen 5950 system with some debugging options turned on, getting a KASAN vmalloc-out-of-bounds hit at running fortify_kunit test:

I'm not able to reproduce this yet. What does your .config look like?

I tried this on Linus's latest and next-20250422:

$ gcc --version
gcc (GCC) 14.2.1 20250110 (Red Hat 14.2.1-7)
...
$ ./tools/testing/kunit/kunit.py run \
	--kconfig_add CONFIG_KASAN=y \
	--kconfig_add CONFIG_KASAN_VMALLOC=y \
	fortify

both showing passes:
[16:14:44] Testing complete. Ran 26 tests: passed: 26

What other debugging do you have enabled?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504220910.BAD42F0DC%40keescook.
