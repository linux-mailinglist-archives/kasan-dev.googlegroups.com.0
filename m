Return-Path: <kasan-dev+bncBCP4ZTXNRIFBB5EQQ32QKGQEFEHE4FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BD991B5B49
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 14:22:13 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id s12sf1675180wmj.6
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 05:22:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587644533; cv=pass;
        d=google.com; s=arc-20160816;
        b=PIYs6ZOnH8ecZaBxaKk6J/Pc/6jiEDBwIPicuKtiqrOf+zdbOMFv72YYyEg91JtXyb
         3BtJgVmM71UhIxOanxG7/6vHW/a8NO8i6tVg7tpktBTzU4MMlzJk9IWQY81VREaVE+7B
         HbiwSzOyfN/8cAWTUaa/zbQKRZsaJVk50FM/UuFHNdqqmQd3pMAq0dU3UAb9zAoGMLz2
         60k592/Oa4g14waGMw7NO0nByscKB0LKC5X8OkHNslFEHkR6bPbyB+8ysd7CBKw5PGGO
         1dDYtjkhLWAfDFJBLFOX7jjsEviXGbra6j2iSkb6+zVibEqYxwYd50HDQiHkFVWj7ORp
         VIPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=EvP1vb25j098GIR84pUvTOfS94ZCcOvvWMthMAqLqr4=;
        b=UL5U3SxZXN7kjTPNjMjQ2kxOVxHzUX87Na8BK7BGuwSd6BzUBO9Wl0HxUPtVSjq/Ah
         /drU2sa7jl3asRv3KD9etR5cg/R7ELj20NCj8Nd71Dq5jqFCUca8cxuZi8gBYt6fdGpk
         c1hxz1lTeVukYP05hKJgDZR/UA7l7JMM+9yPep3AViYhTWCzwOcwuSGbtiCOI/TIoDth
         CEfbqHwvnNSHv0uBnXPvF6vZgYC/3Hvvy2SPgkKYATGdsaDjZmdwQeScS5BIH9ysRQuc
         2pKb2mTWSf8XlbIUy6Yf5bKK3j+kg0GWyzNGNVmzx23Z0J8ttq/nCXJ9bf89IFrIBsnr
         siPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=h36WYByY;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EvP1vb25j098GIR84pUvTOfS94ZCcOvvWMthMAqLqr4=;
        b=HxxlOFzvjTCn5Un9OflFJBkBCvxPyRPD4J/eMqcvINBlu66VqP8N5IoYxXhPLuQKTC
         YhT4Lbwno8VGVQMEkuu+UspP3Ol17E0yMfd3xN2/zWeig4HWNoQEjOdSWHGedOilh6v6
         yU+qy8z8bBuQsAti7C1wsI3fmImI5i8EdcKHLFJYG0oS+3od02zXmtJwW8Khxo5oHiUc
         eEReR28Zwiid9uAHH70pC/L1kT/4ImKqIM1+n+K6eXIe1alM4YLg2iJP21c1/EB+7puB
         jJ+Hzk5Vx2BlqMAjUHXkXfLJwEaYsp16XSgtlBJ5aFkvp5vT2OyxVLogy1s4nt9FX+xW
         uTIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EvP1vb25j098GIR84pUvTOfS94ZCcOvvWMthMAqLqr4=;
        b=ecaOxDF80Tks6UR8orIiYv23JWB/GAFRyWXqwLn+ELDos7vy/EVjlAks85nwhirw84
         9dyn4Mgf5Cd6RdF20rjH/wvSSYYzjRICM1wRQZ6G1aW9SjmNwh9HUHlyFW/OHtvIiE+m
         axZt7dWyRioCir32lHIas59LwSAZlhqigpxAPXMWH8uUAis3xcmbcojqGzeFBOeAXyRG
         2fQKulVNHv5LEy597Jx5ispCIJPy8x0/Kiy+YivqKdmawtg89DLIFdwx/77x0Eg9P+zu
         PWXsFZdcYGtkubj/cO3R+z8rB+5dE3PJ80KSZaXNVQ6T5EmjaBO0HcuPjzKeHEgaitL/
         kilw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZIyRYc0y6IgFNIQYmKs1z47tPHOfN9dAT8FBUM5nIts2k3nzJg
	Dc7Fujvs4UsbH/uifuTwImQ=
X-Google-Smtp-Source: APiQypKqSUARnHq2yb+JQ4obF4lJIksvTzcyS9+W7pEnM+xnfImRzuKZrMJrlwpBQ/h2t4v6OGjanw==
X-Received: by 2002:a5d:5646:: with SMTP id j6mr4913734wrw.207.1587644532905;
        Thu, 23 Apr 2020 05:22:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:618f:: with SMTP id j15ls4356620wru.3.gmail; Thu, 23 Apr
 2020 05:22:12 -0700 (PDT)
X-Received: by 2002:a5d:6607:: with SMTP id n7mr4944989wru.150.1587644532424;
        Thu, 23 Apr 2020 05:22:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587644532; cv=none;
        d=google.com; s=arc-20160816;
        b=C1/TH4jBy3KGkAa96DrzrJyA+y5JheADZiahMI4a653uNfOket/IYHWTNEbMCwxcx6
         o0e6ePklq/vVJETFBPUqDiq9ZgDMUC4DlryfdgqMMEBYl+6LOrc/SVrAvHlCkHzyphyK
         Kg6Tjpl9nmhMVoW/tSDmcYyjSWy3RcevtGFL1oqtDk2lo0WO6rppGZOK3MvlzxhcahGC
         zhLoRHPtH97/8nMz2WZTpMBuNimSxZ39QuMq7vJ1f6xXYItad0z8Hj5pQ7S3yuVBjl8M
         hX6iBA0MiSyOgU+x5H8R8iHhDwBX6UY8wku6eQ2uj8zrAugH+7NDhg8nTQco+oijBSKn
         9S2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=S2N8P4pdalpon6U3pQ+glPhfHT9z58j7kBQKbXloCSY=;
        b=GqVI9cJXsZIY++6cofGBZpXSRI91HXkuEQaPJLbgqDLFhppY43wH+6ZdXlUzEP3rM0
         D60YI4F0Ij1rmqeIL3bgjgLUVGTYIOq5qsgZEueQQ9h5Kx/CzzOVgdb2tez7lKgc8J0e
         0TPcY6S5Ths2ifesPsnAMQWaqXHbJNTsgjFjjjt4IrOwsCy2fWvooRJxQq2K3+xnFfP7
         U+b9ruxu6dw6vIQDCuszdROFT4/G0A4LXAd86z4W2fOZ5vj5DZakSVqgq4k/l9Sptf77
         wMGLtMQJR9An6O2j8NMuKCkoBt4G8Zjp1556x5/31vpKjPOG2klEh2PUsKA4bwlzcZEE
         1FLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=h36WYByY;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id u15si143060wru.2.2020.04.23.05.22.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Apr 2020 05:22:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300EC2F0D2E00329C23FFFEA6A903.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:2e00:329c:23ff:fea6:a903])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id B57AA1EC0D27;
	Thu, 23 Apr 2020 14:22:11 +0200 (CEST)
Date: Thu, 23 Apr 2020 14:22:08 +0200
From: Borislav Petkov <bp@alien8.de>
To: Qian Cai <cai@lca.pw>
Cc: Christoph Hellwig <hch@lst.de>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	x86 <x86@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and
 pgprot_large_2_4k()"
Message-ID: <20200423122208.GB26021@zn.tnic>
References: <72CCEEC2-FF21-437C-873C-4C31640B2913@alien8.de>
 <DD433C5F-2A08-4730-B039-8E0C25911D10@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <DD433C5F-2A08-4730-B039-8E0C25911D10@lca.pw>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=h36WYByY;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Thu, Apr 23, 2020 at 07:21:50AM -0400, Qian Cai wrote:
> Cool. I can only advocate to take another closer look at this patchset
> (it looks like going to break PAE without the pgprotval_t fix),
> because bugs do cluster.

So, I took the pgprotval_t fix and tested it on two boxes. I'd
appreciate it if you ran tip:x86/mm on your machine too. tip-bot
notifications coming up.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200423122208.GB26021%40zn.tnic.
