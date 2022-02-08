Return-Path: <kasan-dev+bncBCLI747UVAFRBC7WQ2IAMGQEGFMKHXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B6534ACCCE
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 01:36:27 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id m8-20020adfa3c8000000b001e3381fdf45sf66037wrb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 16:36:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644280587; cv=pass;
        d=google.com; s=arc-20160816;
        b=PApWVulhZC6bCQU/rvPsMtlLP6mlFs9URzxBMgpOMn4adN0mc2nXYwW/MQpJfj0Qjx
         QQyXh2bLb+e2zNgVWz1x60dJJc/5t8cGbh07nf0LWKd9sVdOafQJ1XxoKAHbrf/XP9fs
         /c1JxBXdIX1gD/x8maN4OWIfDNXo/+05jl2WMTvBdn1VJEiiSJUItfe/gBhpqhcW2+yq
         l1hxwzlBivyOkAzdt/qvv3nuVQyV03mwYsDpoPtDxbimOYDteVt5T9TwIbcsX3+EChYL
         aEJW3WRdZ5tXqGOnUwNxnqeMRbA9/KR10ylpqJBu4EM+F3bG0FQNLwfYpbjx38dWVMx0
         fGiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:sender:dkim-signature;
        bh=3mIZHy305KvuOyA30XYhbJ0jaRqtvgDk2Y8yyQr0vVw=;
        b=afv6TJN8rOxIC0T/Kd6ZQRdvqog1zLmVsLsvGJ7Ql890PRtAacZV671yfr/FiovJoF
         3dJ3xr/8rp1uJXvwCEHcB50oCaahQdzkZdkx9XjAFmgxlniVnBshbKy7Lc9hJJQTHh3m
         Ua+EwXKa7TApv52CA2EkHG5e2klb9FojjhZ9lYD2jDIdlRrP6U+iWTeQNbJgVObaRx77
         QnKITfggdK/ECR4Hu67zWRyqlsfJ4rg6pMYK1W8bsAtcX/zmabopRNP1/mbTAu+EpRiG
         eTCAFL7b2X62WaCqCH6TFA0RTJPTd3zRPgB9j8Yf3s3yD+y4uk6lMkvtdwXLXJlr2pg9
         fMTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=A2f5wHJE;
       spf=pass (google.com: domain of srs0=1djx=sx=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=1DjX=SX=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:in-reply-to:references:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3mIZHy305KvuOyA30XYhbJ0jaRqtvgDk2Y8yyQr0vVw=;
        b=QYZs6LaVapTqTYrF+bEaKBl+u6M2V9/DfmUpqo2x0GGtwLhMlUIiMtt6cLYW5MYi2P
         NZUFPx3JTb2xniqoVt01yYgxaOjh6xCANBJCnX/6zX0sv5sWZ/5DRO8RC4185k7Q1CV4
         YLzGAUaFwWxNDGT239c0EKtTFQbIrJoaoWG9whUhjy1KVJokHcxdUVVnnPpSenBHtly4
         Xg2jjIrVYdzlVS/LBvGLMOzZ+/Y2HFKf5UC3aKVYmXApJjEl8VTGPGjjP7R5umAItASa
         Ir+1bA8KSFg0BqydIjk6TYXie6N3zGjm8W6by+npFK40H1bEU53xCj9NYmNO3s6tBzgF
         TAMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:in-reply-to:references:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3mIZHy305KvuOyA30XYhbJ0jaRqtvgDk2Y8yyQr0vVw=;
        b=RohS0Lm8by8qAsvwcRYAqf+Gu/pB580f/o13dKXTUvtHNQ609iNq3s9yt2MSR92ERM
         +AhdlJDqI/kHL2eNjHKDyCxrdMbXD0hMSL6DfL8p5e2c3khHD5rnRBELnUo7YiEPjvao
         SbR+ytzyB9og/B2kl/AEZWWlEvitwcPFQrcWFxWIHaq1HBkyaivfG+xUcU8keAUYhJdP
         jjBX9jQIPjpasCQ069ZJomO4nDZw9FyrqjQ/l8VFYZtDPX9qDiCZcMU+T+1F0GHE59VX
         IMWDkd6iOOwCxXudoyGbO7qUsAqVwJyRvs3jo8q74If0TlJXb5gnNR3SySni9azqzoHq
         f8rg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MAgEOn2pIPyxBt87uSWgZmmDVxcAG7OuwZL2Krz8jCZ+KlSuB
	tmJmJ7c6YHQOnvxp+egwKUs=
X-Google-Smtp-Source: ABdhPJxFS5+hxmMGRodTWJ9b0eJHQCl1186CYdA99uaHpo/i98ULdOf99a8X8oHt+36JJO0Hedm+ww==
X-Received: by 2002:a5d:6d87:: with SMTP id l7mr1500402wrs.326.1644280587283;
        Mon, 07 Feb 2022 16:36:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3596:: with SMTP id p22ls337650wmq.3.gmail; Mon, 07
 Feb 2022 16:36:26 -0800 (PST)
X-Received: by 2002:a05:600c:34c2:: with SMTP id d2mr1058663wmq.120.1644280586465;
        Mon, 07 Feb 2022 16:36:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644280586; cv=none;
        d=google.com; s=arc-20160816;
        b=Uuy/tsWeb0H29dCfZRZjT+AjcZTu4WoNFIooh8OF2PXUFsupLehbRmYKEFVT+2ZFP+
         TNia1PYII7W48Ast/WcQvJwibUXuBhEie9sfXVRErgVVgffpj4HXinwXJ1ogbKbK29C9
         6iW9xzaoC7LhacAJ0Xz0qb9ekIyxN3OrRQNUjKrCZzZNMYHhXzjsa8MgNcYTZo8tdDUe
         +dRmjqv4cEk3bhFNvuwAeP+HL00tda9rENVgYPjOm0RMEexxNmLsAGHnzz9hxW1tQM2t
         +rRBc7eDyzHDCGN8f/71UM2Zdue4vGHPfuv2kGPyAkeD3t0iPbacBJjMYiOm9dQM8u+e
         xhfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:references:in-reply-to
         :mime-version:dkim-signature;
        bh=yJt8rbu3AYDoBNc/EdQTMBvSLH8yRYqHWGRsR+89oog=;
        b=dZmd4DKHbqm1pH1EpXjYstR9pDYm+Op6Hx1UPoIHxIKPmYyJfnqxcoeyfTo6dkijEu
         exU5dVt1sGGTR2SaKhmiEED6YnpYn7UgcU6Y72CMniWPoQ0w0byKWXPIs1DgANcWwj0P
         Mj2ZjXsICT05b8MsIZiqHtY2gSQExzt4Bad21bjLJy2QLfWU0803X0Kpl4Vf9udIah3R
         fVtdzA+97BARP0RBRO0FC8Pp7eVjSmbcs5WMEWY1yWmcRvzdg4El2/AXRtPWM1RuN0+Q
         UrnyyDzftqb+Jj91Av0i19TKfEZOe2ewIOQdnQsxm9lI8mo4rFCovrtoX9vTpkg0Ac0n
         FO0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=A2f5wHJE;
       spf=pass (google.com: domain of srs0=1djx=sx=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=1DjX=SX=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id ay18si411745wrb.1.2022.02.07.16.36.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Feb 2022 16:36:26 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=1djx=sx=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 14794B80E8C
	for <kasan-dev@googlegroups.com>; Tue,  8 Feb 2022 00:36:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A8742C340F1
	for <kasan-dev@googlegroups.com>; Tue,  8 Feb 2022 00:36:24 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id b2d9397e (TLSv1.3:AEAD-AES256-GCM-SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Tue, 8 Feb 2022 00:36:21 +0000 (UTC)
Received: by mail-yb1-f181.google.com with SMTP id y129so8820474ybe.7
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 16:36:21 -0800 (PST)
X-Received: by 2002:a05:6902:14d:: with SMTP id p13mr2403206ybh.638.1644280580410;
 Mon, 07 Feb 2022 16:36:20 -0800 (PST)
MIME-Version: 1.0
Received: by 2002:a05:7110:6254:b0:129:4164:158b with HTTP; Mon, 7 Feb 2022
 16:36:19 -0800 (PST)
In-Reply-To: <CANpmjNPVJP_Y6TjsHAR9dm=RpjY5V-=O5u7iP61dBjH2ePGrRw@mail.gmail.com>
References: <e10b79cf-d6d5-ffcc-bce4-edd92b7cb6b9@molgen.mpg.de>
 <CAHmME9pktmNpcBS_DJhJ5Z+6xO9P1wroQ9_gwx8KZMBxk1FBeQ@mail.gmail.com>
 <CAG48ez17i5ObZ62BtDFF5UguO-n_0qvcvrsqVp4auvq2R4NPTA@mail.gmail.com> <CANpmjNPVJP_Y6TjsHAR9dm=RpjY5V-=O5u7iP61dBjH2ePGrRw@mail.gmail.com>
From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Date: Tue, 8 Feb 2022 01:36:19 +0100
X-Gmail-Original-Message-ID: <CAHmME9oPGnAQ23ZGGJg+ZZRDjG8M+hkqvTko1Zkrc5+zQYUvVg@mail.gmail.com>
Message-ID: <CAHmME9oPGnAQ23ZGGJg+ZZRDjG8M+hkqvTko1Zkrc5+zQYUvVg@mail.gmail.com>
Subject: Re: BUG: KCSAN: data-race in add_device_randomness+0x20d/0x290
To: Marco Elver <elver@google.com>
Cc: Jann Horn <jannh@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, pmenzel@molgen.mpg.de, 
	"Theodore Y. Ts'o" <tytso@mit.edu>, LKML <linux-kernel@vger.kernel.org>, 
	Dominik Brodowski <linux@dominikbrodowski.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=A2f5wHJE;       spf=pass
 (google.com: domain of srs0=1djx=sx=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=1DjX=SX=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
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

Hi Marco,

On 2/8/22, Marco Elver <elver@google.com> wrote:
> Jason - if you're interested in KCSAN data race reports in some
> subsystems you maintain (I see a few in Wireguard), let me know, and
> I'll release them from syzbot's moderation queue. The way we're trying
> to do it with KCSAN is that we pre-moderate and ask maintainers if
> they're happy to be forwarded all reports that syzbot finds (currently
> some Networking and RCU, though the latter finds almost all data races
> via KCSAN-enabled rcutorture).

Oh that'd be great. Please feel free to forward whatever for WireGuard
or random.c to jason@zx2c4.com and I'll gladly try to fix what needs
fixing.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9oPGnAQ23ZGGJg%2BZZRDjG8M%2BhkqvTko1Zkrc5%2BzQYUvVg%40mail.gmail.com.
