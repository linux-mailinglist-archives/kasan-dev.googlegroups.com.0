Return-Path: <kasan-dev+bncBAABBVVAZD5QKGQEQVHLUHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4203427B1EF
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Sep 2020 18:33:28 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id m8sf2510391otf.23
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Sep 2020 09:33:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601310807; cv=pass;
        d=google.com; s=arc-20160816;
        b=OKyG5v6LZFIUysp2axuMesktBPHV95ZB8eF9VEdS5n2ERT5r2pA145xlAqD/SXCmi7
         +VNcimMDemd2yiR1YXANRcCSJrGCiScvJWNDWmoHad8yjW09D5oCODvSxNUYeBtAG+OG
         RrkOvVwWR/Rca3mQnDUVpJMEXv2/94toLeF1j3yRpx5JhuW9LD0kFmyT5hihLJa2DN7c
         +LQDG0XJOGI5bRcivAhzirdkMzVQl7BTsoUP15XKahuAQnQCgwxUOIijD+cRA3xT7Kmp
         v4bEo1Ur5pLVOLrvYBI9ypMidni+1cwrL2UxPCRIJRRlbjF28UlSipjmd/zGp4c77voR
         K/pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=EDYAk4dKHS+66eJTv4BeRzD0vgkoAyVXRoiKME1WmyI=;
        b=N+v57b0SIa1YlyO6mh8jq8XLLDB+9wXp4KecF3qW1hdxcyPL4KY7SkRhhakfwSV/A8
         +woNfHA0qrKZ55/ZptXMZdRKWsqjI7736eVO5TDm487CzhWuJxopq0iuNaCkytGncJXW
         sw81CxaSegw7kVkC1KC90hJuXH8snEQ5FqjroWpW+DcpaugJwvHdUsUdQhfwqiY4H4Mv
         MUUNgAdTavT8oqegAQRqLrf2ftrH3S7Ws+GXkoHDp64k6iFjyhqm4m2GGRqi/vHAh9fl
         suth50hmPfArmctFSTLLd2V9yNXbFg8Tkx9tn0adUMod1QPFnUgYK6nv+QaIuwAY9Th0
         SY4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DG3A2KkP;
       spf=pass (google.com: domain of kuba@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EDYAk4dKHS+66eJTv4BeRzD0vgkoAyVXRoiKME1WmyI=;
        b=Uc8Gsw2t9+9wEhBFMY5JgjbfEmoyATPAaZK62THQ3/aoFRiTqQtK0FwbR4Xi7d6Jf2
         386ELTlVVE5VRPOjsM6Jw1XeQkWk+2HvKETEhDKw/BzUq8WtsDrbf1KcLDq1Qg+sDT9G
         +6iG+vcqE6uKOJykAJTsDczknXhdW1VKw9tD1nGDN0Z5BL3pUhGj6R6GIJlzZquq1akn
         wMgRErimE1jhF3f+9KbogWpRGYZPFkszoBQ0f7Ac2f8OQOsnl9vRog2Qxgz/gCJMud3J
         +rQca8Idr73Pieg6eOvU3bW/8trMch2UwW3X6FCvN68t84R0p09HomLl+YU3q0n/xU2r
         gpsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EDYAk4dKHS+66eJTv4BeRzD0vgkoAyVXRoiKME1WmyI=;
        b=Zm+xhJAO4LSlJdugZoCW/YeO772JN8W2zX2n68KOqABzGs0OMSc5hYqiXKECZrPC31
         Y893xDhrrYV0lUoV7d7nsTr50ssMiWKZo1IdGLH9LhGRygck6MlwG5WNnYfNxK0fjmD0
         +I9reiKl260MjzXCjvS645v/ZPQWZnLVJxXCIyMqpNi5WInHWbgk3ALTJe3d5Jr3KG+I
         msWDg1vxoCLfFvk+lpuPawK/mdx81mAQ0Jr5UXziNLxtl+R/8RiJrkWA5q5Ub+YRKVUF
         3i4xeXkSL4Sbl406HpDPobLLcofjhzvQoVRQccjwRiVYGOeQOSyyPunOGE+7DHdsJhnw
         5MbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531iB6xfiVECKoIW7mDaFr5lrB/6iaptBDWwQIjpK0sjrP8kNE5/
	XmFHJWhkpt7ePFTffkgJ5zk=
X-Google-Smtp-Source: ABdhPJwCsSGOl5qIxXI+HkiqWQp63GoEFFm1Ovca8xNDM0rJ8JBYtVDeT3Ln1mnPzLnTasTeUoxCfg==
X-Received: by 2002:aca:7588:: with SMTP id q130mr1384915oic.73.1601310807001;
        Mon, 28 Sep 2020 09:33:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:119a:: with SMTP id u26ls411894otq.6.gmail; Mon, 28
 Sep 2020 09:33:26 -0700 (PDT)
X-Received: by 2002:a9d:785a:: with SMTP id c26mr1541932otm.180.1601310806706;
        Mon, 28 Sep 2020 09:33:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601310806; cv=none;
        d=google.com; s=arc-20160816;
        b=0jQvj1RYFRLGcriQBPZkMSqHWiLoMaDjHNsACiLhPGERv9ovfCS/4MBEMu6BJpgGcD
         G8hGPQYET2dSZGPkOOAFHAoFPu07I2v/VjoRW/FnJhwWg1055KMnmKh42Y1Wfd+N6tUg
         NHeXE6NahIIlgVAWo955Q4NGfz6RwVVwxZw+ThxzeIuhG21P3yuZxNNdlTy7RwqYQxP6
         LFJVpOjgXQnoNOTwj2ecwY8lSeq0j4sgzMXfrK1857J+rmx39uhlNumiOlQmul3QmbMq
         vLejSP0eQmp8HhLWYyA1rCjHH3mlfvRNBEcNQ8WQajI1KGcd/tsD16Y5Z2UyzwxHwyI8
         eyLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5X20NUiaWkK9tLKF7Iw6boikC6d8QqcfUqvmA+4t63I=;
        b=LnJB7soWA4KfQzPbwYLJAbjgvqLhJzEkctHjoIhO/5d47TJOzrf643DlpQ2/ZjJuTZ
         NtFlhHJshQ0eTwczfvt0AOI/YhwLp7nCTV4wuUloFtmP7hkYa8kA1cTFxqdrAY36brml
         uzGXe/gSH+RqGr0KySDBPFJPBpKE++DMqwxVskiePCSjppfg9YXdTxMp0jMDaJm3TX+v
         EuEjWSvqlPFtnoyrR/xtleyVsloAF+LnYsLKkzPflESGeUCJjnNBOrEwwkbQJFY2Bf4c
         0xkOd8TfxwTCpqtSItJv1qJyQu+e9C5YNjcylxVHFnDvd/CRY8FQB6In4MnQLTGoVC2g
         Y/0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DG3A2KkP;
       spf=pass (google.com: domain of kuba@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u27si143718otg.5.2020.09.28.09.33.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 28 Sep 2020 09:33:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuba@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from kicinski-fedora-pc1c0hjn.dhcp.thefacebook.com (unknown [163.114.132.5])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 712F1207F7;
	Mon, 28 Sep 2020 16:33:25 +0000 (UTC)
Date: Mon, 28 Sep 2020 09:33:23 -0700
From: Jakub Kicinski <kuba@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML
 <linux-kernel@vger.kernel.org>
Subject: Re: KASAN vs RCU vs RT
Message-ID: <20200928093323.06c82fdc@kicinski-fedora-pc1c0hjn.dhcp.thefacebook.com>
In-Reply-To: <CACT4Y+bK+0aeJb_2ULmouuH3+_OPOqMTtv1UOp2td73cqcZL-w@mail.gmail.com>
References: <20200925184327.7257b6bb@kicinski-fedora-pc1c0hjn.dhcp.thefacebook.com>
	<CACT4Y+bK+0aeJb_2ULmouuH3+_OPOqMTtv1UOp2td73cqcZL-w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kuba@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=DG3A2KkP;       spf=pass
 (google.com: domain of kuba@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=kuba@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Sat, 26 Sep 2020 08:57:32 +0200 Dmitry Vyukov wrote:
> On Sat, Sep 26, 2020 at 3:43 AM Jakub Kicinski <kuba@kernel.org> wrote:
> >
> > Hi!
> >
> > I couldn't find this being reported in a quick search, so let me ask.
> >
> > With 5.9 I'm seeing a lot (well, once a boot) splats like the one below.
> >
> > Is there a fix?  
> 
> Hi Jakub,
> 
> FWIW this is the first time I see this BUG. I don't remember it was
> mentioned on kasan-dev before.
> 
> The commit that added this BUG was added in March 2020, so is not new...

Talking to Paul McKenney - it appears to be a known and hard to fix
issue inside RCU, KASAN is not to blame. Sorry for the noise :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200928093323.06c82fdc%40kicinski-fedora-pc1c0hjn.dhcp.thefacebook.com.
