Return-Path: <kasan-dev+bncBDW2JDUY5AORBENZ32VQMGQEQCLYMEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4262080DF8C
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 00:34:43 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-67ac7372fd8sf63155346d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 15:34:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702337682; cv=pass;
        d=google.com; s=arc-20160816;
        b=kkpNhVysTxRhYMaXe7b1EZLDJey/TTPQq1zHAxNy7P+S4P4w1GgBX30GjwkXENWfSt
         S1D+hCWO4F6SugaGwutabw5oA/L6BGIIsHRhZ3gyGixOzvtwq4I1aIahiMkSUgo21DC6
         UO+kLFs8tk4sZkMccHqZnReHcxeMOHbroXqT/S+xKCxGtpEvkC339e/e1EbWPYPsU9RV
         LJ/uLA4v6w9iJOr8azF0zYVQKkAyN6tUKOFbg6VnABaJbYuyRh/gQGdL8Uf05YWljz8C
         02MqXaICuLgzitm8XooiPXShTCQbb5iN3A5ylWPcTGmaYyhFEleB25lzqsnaEZuuqLlM
         ci0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=PA7xtFffoSOUBTMRBYWANfle/+sLgXGs10m8Qs1uSbM=;
        fh=fIkoRfvdeRH3cg3ZH8hJ1PhQNcAAo/OESIECt6xy+YI=;
        b=LxjfMsDdxxKDWRn8us7TwXDanGXEFaOwvR0mTocYCyvksASjOnRC4lA4jZkQVwXHD4
         udLcYvBsFTbfxAivlYM+aTFQ1xpABeO9mRV3NvpANPbV9FBqWZffequ2vIPTziGjn8bf
         ZXPymKgJrbO1/1m27s2QcJvTZLjh8BzB2hPlhlLvpB3oEFdFzCTQNGVPSHQRUU4lTs7P
         uGPfR2fSJdy/uFcyItzA6dFSftgQXUKR9vMD2kSF7qdcvwUKyDLEx5aWTBXUVIqsbIG6
         /4mVZnBzON573DC+ELdT1PuxL6tFJId0+Gn2g1B4EdhdTHBqzwB0C3BdiTLR2N8WCs3m
         s+Mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MnLAQwSn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702337682; x=1702942482; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PA7xtFffoSOUBTMRBYWANfle/+sLgXGs10m8Qs1uSbM=;
        b=qVytYF1pUK2c+ZELsCkm3FuHEnet0gYACzq7XzDpJ2qWLyE4Mtraf4eNbiH96VDNCl
         WcsWKxmC8SQxuJrWXgcZWHrqWEZqSoDdtdBbH37Ql3f/kdiwK69Z++Ovxt92mS15fJFz
         JUmnlln803Va0TlpMvMdH2BVwlumWa2lSU2XkkJGZVugAoCq+4tHaTeFAGCFBS4kLB4x
         y7UHjDOJOmvhUmNRDpliWNPt0W1lznU1EDHW01ZX1EndHaQN1EJNh3rRWql9rQ9JlMCs
         EcZacSlLn1u4VNTCe9nYD/aVdLwnz6U6woocIZ5/+8/aZ6/QBMd4q/dQuQqC5iT/7V3j
         GilQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702337682; x=1702942482; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PA7xtFffoSOUBTMRBYWANfle/+sLgXGs10m8Qs1uSbM=;
        b=Kgk46tEJIb7TCHpFON8tl94sY7YVNylxQ35wRvELOpXn6yUuaBVyucFicHH2lo7pMk
         QlRqW9MSzjPj30XtvJQdwIpY+9+vROZYmfIUlZGgiHFnYZRxyah4GMkAn0JK+lWUmuRk
         E8hu/pnshIlES446UQmyTYvIGGrTAb0kAmsxAG36Uo8QNBeNlX9mwuCdVnnmDBMix9fr
         noUoKUMI6hVr1zKN58CaAU4iLMyiWCTNBenYXuZxsrozDFmbYGTZ4Ftplz7SD4pCwcYG
         /KLF8nyG2C7VNiqna927MUJsp9/v6w6S0NDLtLOzK/VYsOuYWey09c83iuTA/ifYSyaG
         +RFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702337682; x=1702942482;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=PA7xtFffoSOUBTMRBYWANfle/+sLgXGs10m8Qs1uSbM=;
        b=HEKUi87CRVuc0Uc+8FyE0QpeD+0rq1IzXPGDFl4vgM2uZ1PmxS6yDW5+zu/GTVqrnn
         d3DH5RVPddVjFdcXx+pDsd+r4AOiZcvAZFF78ktevRKn02DIy9ZPurwcS7FcDFz7MsZT
         vZ/zQGX++AOldh4wNoVJDoRvMaSgcZAUW1Hk3jWAFUdp6u+KwuO1ITNnFehNtso6V7+K
         lWb2D1u0vs3NItRuaYergSD0PUYkIGtYJPp6PsS4yPl8Xim54LE3r0t3eaxZ2icLT8DN
         0TNzXfm5sCjoYHTgz3+sohRvDi3iALikw/52luW096grg8Lwn8+fJrBuJNrEH2ei+JCX
         clzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxb5YP+2dwh1V6eZnrzS6ZGi+RK3SKM7p1ySYY1CUJCWvYlTJtX
	Or80OL3wzds8NiGyfNxMD8g=
X-Google-Smtp-Source: AGHT+IF3NAyktxXiddTgGBYWhgS+VO4AKFx0CbyuAe65uRsVrqS8pCZWpT9/zf3dSJbUBtctp4npFw==
X-Received: by 2002:ad4:57d3:0:b0:67a:93b7:c880 with SMTP id y19-20020ad457d3000000b0067a93b7c880mr6090388qvx.11.1702337681941;
        Mon, 11 Dec 2023 15:34:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e647:0:b0:67e:e84c:a16f with SMTP id c7-20020a0ce647000000b0067ee84ca16fls41440qvn.0.-pod-prod-01-us;
 Mon, 11 Dec 2023 15:34:41 -0800 (PST)
X-Received: by 2002:a05:6122:4444:b0:4b2:c4e8:7367 with SMTP id cy4-20020a056122444400b004b2c4e87367mr3477077vkb.5.1702337681236;
        Mon, 11 Dec 2023 15:34:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702337681; cv=none;
        d=google.com; s=arc-20160816;
        b=xXr0uWw7W6vJj1u2rsrCEF0bHiKPcknVQtvqRCzTBa8isX3yQ1WkU2A13DDvf6zJzx
         wzfEEWZU4z41agE2SRcg/w1Z3AQsliyxNDamfQGekDUYzgzfQeHzUj3VgLfb3raUahM8
         Rrd6IVwM9U3n4hSvBEADB2kCG2hhLvUUm5GwVA0AavEjqlayrdn+azJb/BAAC20bvBXU
         cw1/as4O9/mS8EObL1kBUmbe3jFoLHXXg/0zXn3WcEyQv6dky2V+wVsRFRDbwREZSEna
         NpQ2zJyN37AQIyXsIk4KskwLLSK10/Q9WemmmSMMx7XfcEH84TVqFq+Avpur3WtGE1E6
         6yvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Zj5yF/LOMqFmWASjwn3eASB6sdQw2wrv8SVS8cU7WP8=;
        fh=fIkoRfvdeRH3cg3ZH8hJ1PhQNcAAo/OESIECt6xy+YI=;
        b=QpTlG+TqR3DtXm66KXx/jOymYsMVjWrS0KlXAf/Xv4lNDuhU6AupOSPTuwH2/Xhp8m
         +Zr3sttOzv2KeMt6fYAH87fy6RvHCumvm6R/1GLS6OHJ9Ba5Aa3s52bsoOoAjRbkvUvY
         Ghg7YFe29WBoC9eJ0QebeN0IGfsHSfUzU9kh32+D/yk4dD0rMmJVjSQSpe+qFX7xd6Ty
         VOrui7jXsW2RXCQBdnuZs7StQcp5aJ9XRJ3rcK74Kj3D4CVeA+TY4udF89XEO+sZUsIC
         AzazvG8fx9iTFp1MVANmtLw3iJzfvsE+BSMftA1TeoXHqkXNe3b+UYLrqEdogA3rO8JB
         mqcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MnLAQwSn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oo1-xc2a.google.com (mail-oo1-xc2a.google.com. [2607:f8b0:4864:20::c2a])
        by gmr-mx.google.com with ESMTPS id n1-20020ac5c881000000b004b2c71cd532si1048696vkl.5.2023.12.11.15.34.41
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 15:34:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2a as permitted sender) client-ip=2607:f8b0:4864:20::c2a;
Received: by mail-oo1-xc2a.google.com with SMTP id 006d021491bc7-58e28e0461bso3008372eaf.1;
        Mon, 11 Dec 2023 15:34:41 -0800 (PST)
X-Received: by 2002:a05:6358:d598:b0:170:2abc:6e34 with SMTP id
 ms24-20020a056358d59800b001702abc6e34mr5572511rwb.19.1702337680509; Mon, 11
 Dec 2023 15:34:40 -0800 (PST)
MIME-Version: 1.0
References: <000000000000784b1c060b0074a2@google.com> <0c079048-79ef-4e50-8fe2-a9626e40b363@I-love.SAKURA.ne.jp>
In-Reply-To: <0c079048-79ef-4e50-8fe2-a9626e40b363@I-love.SAKURA.ne.jp>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 12 Dec 2023 00:34:29 +0100
Message-ID: <CA+fCnZdHFSbgmBx1TFGs4_BxK8eaTCmCSj_Ewz0jGF=khLJG9A@mail.gmail.com>
Subject: Re: [syzbot] [kernel?] possible deadlock in stack_depot_put
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: syzbot <syzbot+186b55175d8360728234@syzkaller.appspotmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	"kasan-dev@googlegroups.com >> kasan-dev" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MnLAQwSn;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sun, Dec 3, 2023 at 11:33=E2=80=AFPM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> On 2023/11/26 6:07, syzbot wrote:
> > refcount_t: underflow; use-after-free.
>
> #syz set subsystems: kasan

Thank you for pointing this out! I've debugged the issue, will send a fix s=
oon.

> By the way, shouldn't pool_rwlock section be guarded by printk_deferred_e=
nter() ?

And for this one as well.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdHFSbgmBx1TFGs4_BxK8eaTCmCSj_Ewz0jGF%3DkhLJG9A%40mail.gm=
ail.com.
