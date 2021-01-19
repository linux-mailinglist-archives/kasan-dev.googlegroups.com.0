Return-Path: <kasan-dev+bncBCSPV64IYUKBBIHVTKAAMGQE2QXBF2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-f64.google.com (mail-ej1-f64.google.com [209.85.218.64])
	by mail.lfdr.de (Postfix) with ESMTPS id E609A2FB57B
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:55:28 +0100 (CET)
Received: by mail-ej1-f64.google.com with SMTP id b18sf4159081ejz.6
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 02:55:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611053728; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZNeoZhI9bpXjwG19g9+HBC34vuM7Yq1yhB8cjyyjImHJZN7eE2zBpq7s00TLHfGE6Z
         Hg21J+RZ45xGdUN5ER7wPCSWlWMyEtDeMA0pfDDj3Ggrdl7KShI6LolSkt9ALa49yHe3
         3h+UODeBGsdu1oBNEbpZ4Qd4p4kkyiebCQDKt6tXno7TyhOUEsz1uec6zD2vCHfEeq+k
         H4QuuxeAL8tBaj5759aN8M8BsZQLJLn6T2JOircWaVJ08NNQfDOQw/WKZcWGN8iHGJum
         pWAR6FYVgHu63Jf3S64g5vil9i/MLJbdobn1wgUlDl3ey46W0rDY/SVsL1yioWVrcozV
         Ft6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=IYyf0peUWuFSraCVR7HDIxBFomzaiqCmyNjRBc9JYbs=;
        b=GzOJoMBgUCfHWI7X4P+aAVM8lmtBd4ARydAHV8RDFqM5tnPToEdY++6MhJVqmmJEm9
         38LwDWv/UyQQ75zNnzr4Yw8QlNcVEWeFNUjxAcotSZZFcbcqESfFexKhiDYjvjCv1USK
         mAExDP5E9QIPaWK1Yq+v4U1VX+ZqznC/ue4fRMAUZEtnlMPDJa6h+VFU/CVR25rzH21Z
         iXCdZQBwTuNLJHTWiyapmXcYho9rMsWAzXz5NXwcifFF3fcSm+HPf9xJi9sj/XmCm8pV
         dBCcSYf7uh3RNx+fF23XdCwtRGO0LxPbFJILgdmOx38BSJ/H8gssFekmadPdYxvPOaTu
         fJ4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=icziEYGD;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IYyf0peUWuFSraCVR7HDIxBFomzaiqCmyNjRBc9JYbs=;
        b=QxmfgOKvQo/UCk5UlTfiiZsUDrbat3fFE7zesUAN8JJg6DYS4CHhDWa8u7IscetXVY
         k3pzA+Qv6CbbaLCVa291PMjHTbTlicd/5cff+wW4iOAAwE8+TOEQp/E34XThrwIADAYd
         LikwusUbRS1pr5gcdQR8Kr+5uDaTrB7rT2bnR4Q9jSN44BxvxrjHi/1UhsK+FmVhIZnU
         1rhzXhx5r2WB+WQYIx/S6cv+vQQyaHCJT7Q0xcBOCA16DtZ81IYxMO5STie2ak5V/gzR
         pQV8hkrGmjDtR70WIr+1Bk+ItFViOdCmTQPwPjz7Q7xbCYS90+ENz1PdBpWHvCKzL3Nk
         B5DA==
X-Gm-Message-State: AOAM5304RnzCyghn2igL2rHuVF3jksROvT/QsnTUv+KDA6GylmGbwkbw
	syKwlI7c7JPUKr1FNLK0MrE=
X-Google-Smtp-Source: ABdhPJwd5AuWqy2v8HqnMTvhZvYu9ENMj+JevlJRDnL3k8Tr+keSgU2JZ+6q6FXd54BosI5rxScdnA==
X-Received: by 2002:a05:6402:c9c:: with SMTP id cm28mr3011619edb.281.1611053728703;
        Tue, 19 Jan 2021 02:55:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:cb0f:: with SMTP id lk15ls999595ejb.6.gmail; Tue, 19
 Jan 2021 02:55:27 -0800 (PST)
X-Received: by 2002:a17:906:a2c5:: with SMTP id by5mr2676001ejb.356.1611053727874;
        Tue, 19 Jan 2021 02:55:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611053727; cv=none;
        d=google.com; s=arc-20160816;
        b=mrcLzcqTF6QmhiAyICBV1guDZTDp83Ym2kTcBqk88pE+FNDzW5h3jXHt8+HzHVgBlI
         F4UvQT2Vl4lqc55qqgmFfLx7o/sfdIdHlzypNTMtA5+DjzzOiaXYqQo5Nia7dcAKCYfz
         MTDqLwTuiRdbEu89IvQROjHyUTIaVKL9z75l88wkO811vsLSRkp/JGoGJkh5dIOcGPrF
         Ti6aEedw23RGBiAINPPkrzX2gtZkklBiGJfXqIQQ73bpUW9yhSGi2TDFKPn5DCpz0l4j
         vXcVT+RRGFLe7HbMDW12wadESKKg9b9NHqXeXSuQLxUiSgTNLHtqo+78GDq1ZIjWM0Pw
         nTbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=yYjCJm0NaHXJ5lQO93HUKi5kDcNPXbb7+T3VlcBRWE4=;
        b=w/4kUfhlPrFkEhYNAfDnN2fhDNxAn0U5nItn/tOSrUfnLUfHbwIPKYq1WdHDLwoO4Q
         qfedxIrMsOwO+i8a1fZ7Xp5D06ssTohv1J3K8rUqrSUuDWoNedvf4xDRqrcp/P99QA/o
         YaHXcF4qgxOEB1RBfR3dH6mM/E28pBhKp24f/m6SpqgbB53///jZKXRFcQBxpfEVjA69
         eDss9eQ8MsnTqWjJmPEex2c2g2jGm2eK3caY7pXxEknMj/fcMv6OmNLXbgbYsUYQwvfx
         f+HcZxyP/wEibHh3c0GtjOFlCpqcuNWpBZwkVAzgUrYG6SS8OpaGOrlJqdoogkhxw6Mh
         GF4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=icziEYGD;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id mm17si191154ejb.1.2021.01.19.02.55.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Jan 2021 02:55:27 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:49926)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1l1ofR-0007Gw-10; Tue, 19 Jan 2021 10:55:21 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1l1ofN-0004xC-Oq; Tue, 19 Jan 2021 10:55:17 +0000
Date: Tue, 19 Jan 2021 10:55:17 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linus Walleij <linus.walleij@linaro.org>,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzkaller <syzkaller@googlegroups.com>,
	Krzysztof Kozlowski <krzk@kernel.org>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210119105517.GG1551@shell.armlinux.org.uk>
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <20210119100355.GA21435@C02TD0UTHF1T.local>
 <CACT4Y+aPPz-gf2VyZ6cXLeeajLyrWQi66xyr2aA8ZCS1ZruTSg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+aPPz-gf2VyZ6cXLeeajLyrWQi66xyr2aA8ZCS1ZruTSg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=icziEYGD;
       spf=pass (google.com: best guess record for domain of
 linux+kasan-dev=googlegroups.com@armlinux.org.uk designates
 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
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

On Tue, Jan 19, 2021 at 11:34:33AM +0100, Dmitry Vyukov wrote:
> My first guess would be is that current itself if NULL. Accesses to
> current->kcov* are well tested on other arches, including using KCOV
> in interrupts, etc.

There is a window in dup_task_struct() where the new thread info has
a NULL ->task pointer, but this will never be the current thread,
and so would not affect current.

If we do have a NULL current, that would cause the kernel to explode,
since a context switch to or from such a case would dereference a NULL
pointer.

So, I think your theory is highly unlikely.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119105517.GG1551%40shell.armlinux.org.uk.
