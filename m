Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBLP4ULZQKGQEJCLUGEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 26C971815D7
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 11:32:14 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id g11sf1484126edu.10
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 03:32:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583922734; cv=pass;
        d=google.com; s=arc-20160816;
        b=EH8tNgarS/Q8rIbBKhujzpa6DS5Fl03U9phKjLGRcqjHTvaO7SJeS6BnByxOynYuTF
         do43Z/s27Xmopd1rcLn9Rw1aKguPRQq3HD/ICcVE2Fglk0AQfLFLBOdoBCtepdN7RyBm
         gJiEMHUb8iswFK18+e6HO1AuaCAZJCdl+TLFc5TL/SkJodYmit0e9Kul33cgMXt2g4Xn
         /7W6F8JUDRm+y4hD0QkebJGB78y5vkM8kFLpsGfUwsOWI0eg12qNhhKmMiX1hcn4acbd
         FR85qAonLhe810QgMpFAr96bHgLRXCFwshI2/CO96naTytLj11B4jxhLEoRdq4ZUUmry
         9olA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=ip6ok80rid1U1Rmg3QHoFofV9Spe5f9cnQONPIiq8zQ=;
        b=mrkwUZ9FOd1kAOzKHN2msf/47A/brLHRMZCVrhi5zOv9MEkosQg5nPawfqI83H+Gsx
         7MqWGvWiKhph9W+n4yPLS47M+TEr1PdiYhDQTmf/SivBFptcyHFrXOOb8oeW/N3r/60G
         4GGrgz0qxIC8RA/cAjKCSciIHQbspYklG6+OybpZYJfs2rn//0+WzTdOM74YdiX7Blqw
         qfto07L7CHrlJo4NeQhJv7c6ftArqpLk4Pcp7dFjADLf8FUSvuc5VhwmpYLMpR64f9mF
         S8WwYJeks/gzRO5yl126JXDjRqqfPpJlxtnnuMOyJItQYTc7mLxvKQFpmtK3DSXJUzP2
         KrEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ip6ok80rid1U1Rmg3QHoFofV9Spe5f9cnQONPIiq8zQ=;
        b=NXpihThJDbGT4Bk9ETSJAPRP856fcjanr78SM4z72i/8zPgNnHm8Q6PFwXcWD8nKp6
         cIQwf+ghtHGO2WS58KqH2SSRK5PG3KPkaNSgbWmvceBzoWvM2VtP4mqXE58wDGFpX9pe
         Rp6tVaraX6FFnbh4W0vIkesE49l3DLjch6n1Y6RSV6ZdbahPXTRWeV/f/6IM/3DLiSfg
         p+kwF/mrISc5+IRCc501EdcQBIS2hon78SkkdiqctXYxVgVajIDH9F1/pkXuZumCWLuu
         Ky/9yj5bLZf2p3SIfW+XuAWrvcH4Un1VsCHLCG9QqvhcMRydk1jymb19fOUcWTPpZOCc
         wJGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ip6ok80rid1U1Rmg3QHoFofV9Spe5f9cnQONPIiq8zQ=;
        b=TaBA8LaO6jBKeOW9+Uv/J2a0vZEJiCD4B9doji160ckG5Ob4+ZEttmnrLqsvjQOMKd
         XHxBBywOrVfQ6+nImdZQQLvuZu8SGnoQ5IuJuV5BQ4VObU8c4gos4YixjhWxQI6rg9Ld
         5eVQmZoKOrfUnGRzydNbhEUgpSzjLtJJbbpsTOL7f4nUn4uVjW2W4LId0TK9xIGB355N
         FHj5fbsVqz8F+CoPZ3g6yU7yyyJdxyUEYPJ8n8SryOeI/4QcQZSeXsh9+aMCQuJTJYle
         znGBhPYVQ/BGgSaqKGRc8Jpuj16lLGjtBHsX1cRgGOrulebPKYRLPgNhNBuzuiVX7r69
         736Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ36eZHFO+CDLKuVv+K+FFdWgjs0FJUmXwe4Pg652kThJPWeZQP9
	Mt9rNPRpKxv5VOmQi0DzviY=
X-Google-Smtp-Source: ADFU+vt4xJOmwQImT1rR9ljhziRE8HP8ySP2oPn8L5PUbnwc5jgMwovrRk3HGCCPHvqLgjx4ucgBBA==
X-Received: by 2002:aa7:d98b:: with SMTP id u11mr2201635eds.318.1583922733915;
        Wed, 11 Mar 2020 03:32:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:278c:: with SMTP id j12ls1153053ejc.5.gmail; Wed, 11
 Mar 2020 03:32:13 -0700 (PDT)
X-Received: by 2002:a17:907:4303:: with SMTP id nh3mr1864143ejb.24.1583922733368;
        Wed, 11 Mar 2020 03:32:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583922733; cv=none;
        d=google.com; s=arc-20160816;
        b=yN3yvFKk//KL78ebL9P4kpILimhFtQ7qQzbYKGEpPNt07u0SiMGGSTxoPa2AuiUtGC
         FKGsq+b9jDsBIgEbNBbWcm+y/nJD/7JZnbRzvZoLOC8xMTED2QQAB4QgikxiwN0n7ITF
         feW7r/apy6k0zWITO/o55hLFrPejURgW0EtQTK/t3xMM3YBryMDx8PqvQTx4Xuqw4BYG
         NrN4RBPtDASmoKJohmTKgk4G3r/GIv6ZiBVOskPQIO1O/ipawBi7kpUivpiVg9wdGKcM
         LHdAW+5b8i+2V4JROoOfCB/6/Ypn7uJK5TgfBo7ITIGJP38LmF8/wU3Y6Pt0AQBDYeXw
         4JpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=3LfebpItnr8UT53yyDeaqk12MrsoCu98ryFWrZq5vmk=;
        b=PZ2EIJMZQBZIH61d/7QJ4vXcePyM3ycxzoAgFry2MzpjLavzLZtAwmzUfC2Cf5HXnE
         GSG/BBHSEvqCHxoSSkVujrzZaG11D6YJ/g1jxZj+yn21IN0P5oHJvZb9jRqOtdW6fkL2
         mWpw0kr5WH6r5dDa9/Gatr03o25erI2YHg3I4SXjLtUkF1g3x/lJ4fVhxSKYuYJCwkdw
         ZHFFLP0LJA3foI1jivG7phPnwMa5F06B7LZSqkM1Tl1bMh+sRFV7cJBmdNE1AzSv3l9N
         6W+GCDuNmo7kbAi4B1lwT+U8sUx7kxiRSYSJxfdqFZG65/Qg/ZvNF3xeuyO17xApfVN5
         cKsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id h10si98080edn.1.2020.03.11.03.32.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Mar 2020 03:32:13 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1jByeg-0013Bw-GU; Wed, 11 Mar 2020 11:32:02 +0100
Message-ID: <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike
 <jdike@addtoit.com>,  Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins
 <brendanhiggins@google.com>, David Gow <davidgow@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML
 <linux-kernel@vger.kernel.org>,  linux-um@lists.infradead.org
Date: Wed, 11 Mar 2020 11:32:00 +0100
In-Reply-To: <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com> (sfid-20200306_010352_481400_662BF174)
References: <20200226004608.8128-1-trishalfonso@google.com>
	 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
	 (sfid-20200306_010352_481400_662BF174)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.2 (3.34.2-1.fc31)
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

Hi,

> Hi all, I just want to bump this so we can get all the comments while
> this is still fresh in everyone's minds. I would love if some UML
> maintainers could give their thoughts!

I'm not the maintainer, and I don't know where Richard is, but I just
tried with the test_kasan.ko module, and that seems to work. Did you
test that too? I was surprised to see this because you said you didn't
test modules, but surely this would've been the easiest way?

Anyway, as expected, stack (and of course alloca) OOB access is not
detected right now, but otherwise it seems great.

Here's the log:
https://p.sipsolutions.net/ca9b4157776110fe.txt

I'll repost my module init thing as a proper patch then, I guess.


I do see issues with modules though, e.g. 
https://p.sipsolutions.net/1a2df5f65d885937.txt

where we seem to get some real confusion when lockdep is storing the
stack trace??

And https://p.sipsolutions.net/9a97e8f68d8d24b7.txt, where something
convinces ASAN that an address is a user address (it might even be
right?) and it disallows kernel access to it?


Also, do you have any intention to work on the stack later? For me,
enabling that doesn't even report any issues, it just hangs at 'boot'.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4b8c1696f658b4c6c393956734d580593b55c4c0.camel%40sipsolutions.net.
