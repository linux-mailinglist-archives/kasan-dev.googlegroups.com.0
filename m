Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBP6TYKKAMGQE47T2JLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D5A5535E69
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 12:36:48 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id m19-20020a05600c4f5300b003974eba88c0sf2486632wmq.9
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 03:36:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653647808; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZZRZvw5s+ETqw9J74ydfS4v+F1MiGYQgHHq9BmBIRuCsfQ3qydI1OSWrf0bqtOrkMR
         pi0NxHrbWtVdX6DsSDi3WnG2u0ruy2SiPO0q4/NH0fXpLM3R3gCWbkN/aIQqWgCmAqpn
         KxH3xlzig/d0LDEL/UeY+kwmE8lUEvXnV/iwy9m6ra8v1YD9qxjjhjZU9w2iwDs2jMCb
         oi+3b7zj7a+ZP56iahY745uWRBfLf+CD5hIQGzD1HxOnNxnCU9J+jxDT9eSil8Rew3Lr
         XVSU1pzJwXgGUW26brnjRR299CajCqvB8dOTSF8NrbqHiPxueH1uq1pZOaPd+oc52pJC
         qAlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=sG/tM7UbYu76e3iGuRlZ+q0fA+xMkWtveJyZiGNtVTY=;
        b=WMjRSzsMp+yATuAFXWzzAsvHdR+F3U383IbXG8MZeMF2i2HQZaxNt5xvfvXgUVIvNd
         ghjP706apuSpqLdTZMRyq/fhtj6Aw0ZeDJryK62cyZmKDFxc3qEx+sD/qALPuAeypJ9M
         USi4Qe/f0EKr7iIMVCQ30wHF1mX2ONZgqIbOh0vku9ddAY2hr4wL3c1wCemsp9fEqxeL
         IJNNhU2zuf7V0iPsTP+bWJi7XGBz0tAhkNnzcBxYXxVHhE0hWWt0kTVVHKEEKmhwlicr
         gEAEKVPk0wpEu0+vqFesDixZCJqqp7X0T+rA01HbN2y/uNF9TBx6hqyRXcZXpOnwFBKO
         dFhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=v8PW7lP0;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sG/tM7UbYu76e3iGuRlZ+q0fA+xMkWtveJyZiGNtVTY=;
        b=mley4bTzJID9cETOjXKfXAozaPKffO+2Y9LqPqZV+TQjMZGVQhWzI+IVK+bG5HynC8
         jlRLLPswIgNDdSa3jcCe3X0mLdUdRSVBeI0Ye7EHVInvKkDda9NKcorm7NbZcE8rC5L7
         mKmHuCufdGYdBB6hROI4a+VZk7XosqH0ouvFkSZenjhvjwt/rr/rsF9Qsyi6Dt8rvtoS
         u7oPA7McnejP19BBCYWfm4yMGxjlql9N8BmOFtHSvZS7TlM769WJozlqNm/pwqe4lDif
         4HpJgTqJ0lGEO0mbjXUFUZYzCpNGc1DBVHVnFLbjSxZqmLfjpjdT9tCRZ8rxeOozxF8d
         3SuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sG/tM7UbYu76e3iGuRlZ+q0fA+xMkWtveJyZiGNtVTY=;
        b=NhIZfW0ZvcZ6M1KbfydkeYTyGzoIRfhRCbk4x3ojoMVUlQpMNqmpEzmuhKAG1KR36Q
         hre+Vnrr/rrrw1neZpHneJqG2FTIGRGQtgaqPWTkZ2pjQKv0zf4JCDNr0TQY+/WqBI4K
         Y0x9io+i0s2DDUE0QiBGIZWE0PIYcsl4MXIcMS7AwVMfIqnNOWZFn5TvHsyrHOVfhteO
         nKPS0GEdTLRVdhtPMGT/T/WHcqxnXETPGv33K45o7sJnSDj0i3lPz7zninhqOYRp62nM
         Jh8xACJO8pfC6k1ad6oHvLiGJjIfXoQQ8GOmbrv+yMUIKs0gesq65VzZtwSBVQyjwWCg
         ITMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532lYhZQHJ+vJwn8yObpoerSbrEIPiobNiCV439/ezvoUTd8kVM0
	4tH4WO1wBvYTybgNSMTIWJY=
X-Google-Smtp-Source: ABdhPJxvs9fmSQ0FRXht9D8/K2VcJnCGW0N+8vtxLa0pn8M32iLbpKXZEyJdRytSkCpqS3qI4eO7Kg==
X-Received: by 2002:a5d:5241:0:b0:210:acc:9a2c with SMTP id k1-20020a5d5241000000b002100acc9a2cmr6136528wrc.660.1653647807838;
        Fri, 27 May 2022 03:36:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c1b:b0:397:70f8:bd74 with SMTP id
 j27-20020a05600c1c1b00b0039770f8bd74ls3403549wms.1.canary-gmail; Fri, 27 May
 2022 03:36:46 -0700 (PDT)
X-Received: by 2002:a1c:4d0d:0:b0:397:30f6:b62b with SMTP id o13-20020a1c4d0d000000b0039730f6b62bmr6345757wmh.155.1653647806797;
        Fri, 27 May 2022 03:36:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653647806; cv=none;
        d=google.com; s=arc-20160816;
        b=AFWMdTSYyTwvNSE3RLfDWIbq9oE0BlSLJXjUhEuKvNjIZEJkX7ZSEehANwS1uojBdo
         ThIp4BILll/3Ey8H3s23vyEC+AGViqorNldGuq1AHyL8+8QvXBW750ZF69xDO9lr/zxV
         q2EeFpdzshtHYL7LjqrWChCpH36r8TpSicBwpfk4nwXOIOBq6W2iTzqYdqwZ3rBzSRha
         QHMW5ov/3cDCM7xHMzw4nlFSdz+H/AAfbzPAjElrB4ur9oSNIx4Z30KMIFPPHSnRVe5x
         jCBc2fC1SKiQBP9k1RGMwprqIT0PB1+BrGWrMv8junj5WhsrWss5ZzOd0OomMm6pxh/M
         OuPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=IF9nCsay9b1zL7n/9831jhzI49UpiZKBNI0m2nwfxfA=;
        b=MBi9ZCGO3qvr7Z5XegWGCXVtSOhIswGEnZhlcCTXILSdM/iAxK+7iNbukjRX8g4gRT
         nEf1Tl6CWZg3zwiRQcCOR2jqvycvy8ty97RMnqh9+l5iKV8can+uXkCpJkC0xOBBHVMZ
         7idZR0+d+T+9PG7m4RtAxUP9mEeS6lfazANnhL8W6tznYrjxQAzj7Y/8x3zU30Ajx+Mq
         tETH/lr39F5HUGqGI7JSTSuNZYWMTBUuCl3Lzk2Hcge3bnVStuGEwtSneNl3mVKBXoHn
         lZC3DvqTnUR5xsRR4nFHthZfOexBuS4QYwrtLRsOeAOmZGdXnT1KnrUFpqUkAf9Byn3B
         CC4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=v8PW7lP0;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id d11-20020a05600c3acb00b003973d014ec1si71267wms.1.2022.05.27.03.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 May 2022 03:36:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1nuXKg-0060dp-WD;
	Fri, 27 May 2022 12:36:39 +0200
Message-ID: <69af5884316c279102fe64d654326de946463641.camel@sipsolutions.net>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: David Gow <davidgow@google.com>, Vincent Whitchurch
 <vincent.whitchurch@axis.com>, Patricia Alfonso <trishalfonso@google.com>, 
 Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com,  Dmitry Vyukov <dvyukov@google.com>,
 Brendan Higgins <brendanhiggins@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org,
 LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>
Date: Fri, 27 May 2022 12:36:37 +0200
In-Reply-To: <20220526010111.755166-1-davidgow@google.com>
References: <20220525111756.GA15955@axis.com>
	 <20220526010111.755166-1-davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.1 (3.44.1-1.fc36)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=v8PW7lP0;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Wed, 2022-05-25 at 18:01 -0700, David Gow wrote:
> 
> ---
>  arch/um/Kconfig                  | 15 +++++++++++++++
>  arch/um/Makefile                 |  6 ++++++
>  arch/um/include/asm/common.lds.S |  2 ++
>  arch/um/kernel/Makefile          |  3 +++
>  arch/um/kernel/dyn.lds.S         |  6 +++++-
>  arch/um/kernel/mem.c             | 18 ++++++++++++++++++
>  arch/um/os-Linux/mem.c           | 22 ++++++++++++++++++++++
>  arch/um/os-Linux/user_syms.c     |  4 ++--
>  arch/x86/um/Makefile             |  3 ++-
>  arch/x86/um/vdso/Makefile        |  3 +++
>  mm/kasan/shadow.c                | 20 +++++++++++++++++++-
> 

Btw, it looks like you also forgot to git add the (new) file
arch/um/include/asm/kasan.h from Patricia's patch?

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/69af5884316c279102fe64d654326de946463641.camel%40sipsolutions.net.
