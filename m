Return-Path: <kasan-dev+bncBAABBGHNSH6QKGQEMK7TONY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A7A4C2A897A
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 23:03:05 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id a3sf1280096otf.23
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 14:03:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604613784; cv=pass;
        d=google.com; s=arc-20160816;
        b=CwLFyVoexBMFlL0dHg86deGlt9NbCu/FkZ/i+nE0yjDVFzP1k2EryuG2nSTaPSAK3e
         kat1/6HQk4C4ttjL8xyC+3vRVjXXEKxuMYb3EuDo9UTMVU5DLT6VGbWN54aBz8YtaVfe
         FenpLiz300tWWfeDTjAiXC+bSH0918I+f0B/bll7smqge+XXAbsNnrrlNxfAXzHe8NjG
         Jk7gbjL2Jy2RH2sOiKDIIdRlEA8FTNEf183khaLnsZDcVEtlyjxmKwC50jJyx/q8JYfs
         v59lZ8L4QGBRMnEyH1IEe5jIkGbb1yqSIs6gIUB546Tvhem0ku9wWzy3QRvQincpbs9H
         bR1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MtP6nbTuJtFUlkC/WKGFzmIoi596b1SIxCRHTMyjiH0=;
        b=HvTYEh6Dci3He0Bzw0Ev5JC9ecesQp8OwJX+3PK34bpOsVT86kiyF98w9jl0W4UoKc
         BldNmT3yAFGHmub+Yb694+1xi5QdGSNsydmiQXpINd6y+NkCtOW22cjHviuJg835Tgge
         UB7yoAl6zWYlDhOzXF7dyIt0PQWlK3Lq4116tq+Vkr9St6LbxG1GFIuwtJen6Ocvhj7s
         WVVBbGjL3yJwNmrzAZM/gbbTYWSWGq+m1/U+JydxJGo0CFZv1vE1A65VeEgP18B8UbNp
         NgFOzyUosSzatMSuyYpxwMFVV9j4g/2yTcT6pBIVQsOmC2k0Q2BtuTi66gy3QodH9yx2
         U+mQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CVX6R+tW;
       spf=pass (google.com: domain of srs0=ijhg=el=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=IjhG=EL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MtP6nbTuJtFUlkC/WKGFzmIoi596b1SIxCRHTMyjiH0=;
        b=L9mvR/xS5vreeSDIG30eCqbvG6xRB9nKDeIuALKTQHfciMmzI0ZZ6RXqpFk9E+JuYm
         RdDu+OkCIw5wh0LMZmelLAVAalXis1r8y3hNUg+9kctPhmf3H1JKmFnj0wng2YR4gubT
         X8H9vP+swYFm9d6ZLENZJYEQ96+6m6LgbMMhYM+sx/vBBEXde1C8JAdKu48o6bcUC80d
         Fd+HBmFq8VSsBxpwlpodmp2yLykXRVGx4cwif0yG5R8Z1dyb+GpwMhxtn8VBEfGnWTMr
         R8iWdskYOzyWp9Ze1ZVeIU3MISzlsxmqUjR1yU1r6K7FcQNMVEMFh300kvKCGnWy99Rv
         H3iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MtP6nbTuJtFUlkC/WKGFzmIoi596b1SIxCRHTMyjiH0=;
        b=cmSzhvH2/W34oXvL7wLx1HmxUk4SCGnZeGwWBPViRXRUyBDhD9q7RL7MjUF9cZw9rk
         JOwod2cZsL8yaM+HfDO5tOhdUJhDI+TR1Z7crWgyUl4xJbErj5iJsoeXgUDaQyqT4Eib
         GATQV4nwWWqQyThz9G3mMDJwrBnVeeUsPpmjkS0OwNUiUPJrufKcUCBn1F5X056a5SHe
         n+CeaMIoMT+3UjJS9ikMg6znfwPhjIdFboWpqpFPcpoQbN7vNWXApUwv6wWZ2901Elgh
         hthU6z1YqasHVZRVn/V4IZ/q9/RdeUz02xW6wE7V2/FFZnXEWThBFPg4Jn28q21i3RlW
         QQug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326PPo55ZP+HRZIXv3aVIpDbZO0L9DSiSsKoTDYaQtSKSqHUhYK
	J5ytFSh72gUAMFqvEyJsu+Y=
X-Google-Smtp-Source: ABdhPJzBitSPeOZggs2aBPH7DB9XoOLpXNdeAjs56UPtU3aOmQ+c+r0l574lBaTAs+QnCbPPxTnETA==
X-Received: by 2002:a05:6830:19fc:: with SMTP id t28mr3229389ott.16.1604613784356;
        Thu, 05 Nov 2020 14:03:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6b0f:: with SMTP id g15ls807748otp.0.gmail; Thu, 05 Nov
 2020 14:03:04 -0800 (PST)
X-Received: by 2002:a9d:aa8:: with SMTP id 37mr3228144otq.286.1604613783926;
        Thu, 05 Nov 2020 14:03:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604613783; cv=none;
        d=google.com; s=arc-20160816;
        b=wz0hl7iyUYHjMKIIxIYFQtIkMpoaFQkaUAciprqDlpiNfyuPCnOHLyX6xp9WzskjAL
         hhhgIUAa3bRk8/PhM0X3kEaeR7TNDGPO4kH/VHB+DxqIVih5GydJcNe3snleU3/j8vSo
         8I61+glqB9ff2xh9IHbmxXaR2BzJDrUu+ME31D1RlXULVbDvfVBNXZBWNkeGd6Z08YYI
         pJUA5KtItKpvo9UdSTy8/8dyeGUW2y+PPUWfiCfK8rLZqbOIZiROE1hCfJQByVuG9VZy
         fEZXzl/zeCtPw7OjQveBoUt515KkFaL3s3WOKG4h3x/9LmLGFvPU4bd0bZwpI0crU5Sj
         aCYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=YwM0QrD+Pjq4wBXb4p05y4VR7wY/1bAAxWeYorXKgbQ=;
        b=HU6TeFBcqFN1naPyW7JrWPJrn/p/I9lRm7FYB9htXE4chw2uwlaM4muICRlkSUlTuH
         7toavhJsPBKFSxbC3H3ii3nwB9dWaVP8Gkv0AN1ICdJA3WNvEwwkVcv3DtNtJHpW0an3
         LlYVnIeE7A3kyuSoItJRHUJ0W2OSpTvuhkMBMttYCi9Yp5mxVsa8pQLA9+THjea+bKxn
         WYcWLEjs0SsPhZx2kN7Zvs1BIRyhJT0EgmRPP9Man4CLxGK83mdGkUHR2waCOjJTeV3R
         xcHjITAXUaMq+t2aoOOrHee/1X/MSiSDwOhnRZNNGgpA4m8lMrUMU61RPKng4yC3LYRZ
         wHDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CVX6R+tW;
       spf=pass (google.com: domain of srs0=ijhg=el=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=IjhG=EL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r6si481751oth.4.2020.11.05.14.03.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 14:03:03 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ijhg=el=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C5C2120728;
	Thu,  5 Nov 2020 22:03:02 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 64EF23522A76; Thu,  5 Nov 2020 14:03:02 -0800 (PST)
Date: Thu, 5 Nov 2020 14:03:02 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/3] KCSAN updates for 5.11
Message-ID: <20201105220302.GA15733@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=CVX6R+tW;       spf=pass
 (google.com: domain of srs0=ijhg=el=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=IjhG=EL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hello!

This series provides KCSAN updates:

1.	Ensure that selftest address is at least PAGE_SIZE.

2.	Never set up watchpoints on NULL pointers.

3.	Fix encoding masks and regain address bit.

						Thanx, Paul

------------------------------------------------------------------------

 encoding.h |   20 +++++++++++---------
 selftest.c |    3 +++
 2 files changed, 14 insertions(+), 9 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105220302.GA15733%40paulmck-ThinkPad-P72.
