Return-Path: <kasan-dev+bncBCMIZB7QWENRBNMRT37AKGQED4V3AWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D0022CBCFE
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Dec 2020 13:29:42 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id x134sf541620vkd.17
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 04:29:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606912181; cv=pass;
        d=google.com; s=arc-20160816;
        b=TJHU7Qqr69A0Wdhc+qH85Wl7AhUsAhmziKnf92Md1MGQaT1knwaTSJxVShiYm5Z7pS
         PKlCZ6NBzSuqWoKC6Ls/0UyaY7ND902X3VovxO80NnCbFaxbSI/8tMvHTWuwza1DiLNz
         r/fCNxNvfbcp2KSQbVfU3fMx/v/Dw+bnzJhgK2mwYfeqZW1hKx5gkDxnk0gVuE1Ie4wT
         mkX0IZgu+PsQKX2TIseQBO0rat/kqMg2FD+6niw7wxS7m1i4ZzxW8sCOu7XBH88eWz3E
         qpo/rf6lvNj/8Zo22sGgQ2eaNWTEXppjUfdDvVI6eNwPBByvv2oJD/hwWkEkvke+x4Ot
         KQAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lHZVrTcUJ17GcgudxIaSE8L2NZ/c557MqeuTsjTNvWQ=;
        b=cmegh+wHKt/DlB5BBc//MlTLw7i4uX/ExLBtmPWjX+HxYnY4VB/R5W8CI/SGYXXPb9
         uAYf6wi+IhO74sreirHWgV1x3lnytiuflRQ5w1ob7mAWZBTVepYHAdQs7nD1w0si58Gw
         DQRk687JG1pAruWMWNd1jW0Erfcb890DsanguHYsRqYCIFMX5RaAVB8dKxHMJbD4e3k8
         7rJ3jbhUgQifSeACe25ZI1VuaW1xJzRW47cTWmRmIUpruc1CT7jWohZxWTWCX+TJigac
         21A4KRDgJKQg7VHo2k2l2y18kYezXa55OCd90BrQX5RGC2hUI+t7mWJ88Bh83iY5Tkkg
         iKCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=L0aJO8R5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=lHZVrTcUJ17GcgudxIaSE8L2NZ/c557MqeuTsjTNvWQ=;
        b=L9QM7NV2o1lyAsoJookZg1aSDbf1lBvjhEGsrfiJeOv6E1XERRhYLzwi/lKQDWcy0l
         V3gm6xPZUlJCMobzi4j2BT7IGprOAHmwLzNPizXtqQIWW9j9kcDAHO8/bBp9CvzbjNY9
         ccTNv7GQ6OKf/4toNqiIevbBR+OcOQhIFp6+2Z35SsTYsgWHbsHK5ab3WSFgP/Xukz+J
         fFMbbb1L9zXn6ijPK5qKGjS6dIYed9ChDJ0fxErDy2byop3qdE50g3Hx5L81ZDb30IKz
         Uk2AsJm9gVByZp0IBeOPm1vgY4Y6UUKMHVrgP0WsPpVmTDKv27yL2p630ZRqPIa71Vs8
         /M7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lHZVrTcUJ17GcgudxIaSE8L2NZ/c557MqeuTsjTNvWQ=;
        b=Vn9TxJG39hlzqdL/c7qkBdMxMHPK022XaKAFiLRHdXYEOYI+7EqP03AzQ+3ta+OHUj
         26jaP/eTXq5w2jZYeQyYIT8v9mHJoTOMy+j4sxNALsMVdDVQJn7A9zIPKcEf3jYZs1As
         3IIKlWtpDfGdJAHXCY+tk51KQxgq9eb1YTvU33tI1EIP4S9DDDji8q2dre6EmJXxd2/U
         UQBKEhMMLsJ1jtpLNWv7wimNosHd6WV9mPnc8xllT+OUj0o0Q4v550megvNZePXrWEXF
         kfnFgPcPBpYOW3kQLWSUiCg44LLdCSZ4vq3AdbQPH+RZZu2nBfRwFzgAWRWwtPad9ULb
         A6PA==
X-Gm-Message-State: AOAM530PBEwI1UbleTTRXSb7hAdPVQyI2PrrnBhMxVP1CcD6XCYRsdry
	6goFa99Vq9SUBsjNLPitNEw=
X-Google-Smtp-Source: ABdhPJzhI96qI2CLFlgsf271ueLx4CuztRWklPzUb2y2p3xSiqgSVS99BQJV7iwDQaWuNbsxMDVwLA==
X-Received: by 2002:a67:fe01:: with SMTP id l1mr1159796vsr.53.1606912181283;
        Wed, 02 Dec 2020 04:29:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f315:: with SMTP id p21ls184817vsf.6.gmail; Wed, 02 Dec
 2020 04:29:40 -0800 (PST)
X-Received: by 2002:a67:2ac1:: with SMTP id q184mr943312vsq.57.1606912180736;
        Wed, 02 Dec 2020 04:29:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606912180; cv=none;
        d=google.com; s=arc-20160816;
        b=X9hcQBIRQb8vHFlaLg4ZRqA8QxYkHwcYe6pcXepi7WCnHcbRvWtCGQHa2M3bGEk9cJ
         ovkuiLFbbGqYLgbju+o7kde2PvHLVUYQ1CqNLZS6uGU8PHR1heMEsWQZGGSNc38dFi6f
         cpn1uuS3C4UNoKM1AWB77hhZippQU9kBgbKecvD5+ZqjSTIlMO6sHB5d0tF4hBGtK4ZD
         5Xh98tMWBSvCJpK07LPI1DjoQnMlF8BQhYHBSR/yR1tYWBO7fij5O6M9gbIyXgxKbKhc
         i8R5OA4UDhLNDSndddo7Yldk/fZA7remn5Da5vGYdO9S58xqVxgLaj2I7qzTFNupaRNJ
         GEgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oZp0RUraoCSi77F76M21L+iHBwIwaTBVmBtfRNAx9DI=;
        b=c2AijYWTmonQy4tZ8JUUimI6FuZqas+Uuii9pQX61gAlf9CDJNYr9wey5XRLxQ5iFf
         w/8gG3KrFZaoeH2q91GA07h1klXHMcaG8p7cRz2alWk4Hg25qPC7RlbiUkUwRk171zAg
         lwMfB4TWIADaw9LPRZ8sQooXsone/w12Sau35mpNS4XF/JBPhuQ0fqc4IF7VlgCcMMxK
         2QCiiWp9Wm4CceNedtfteI1NccuKv73nCXGzfF+iFxMPOYVjMuSkty8P00yypntDyclI
         1OGASVMCOptmMIUtDl58GmeakxuEiTC58i9be6cZ6HENLGL4XGrP0zEHeD+GV3aT/JRW
         Lqyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=L0aJO8R5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x732.google.com (mail-qk1-x732.google.com. [2607:f8b0:4864:20::732])
        by gmr-mx.google.com with ESMTPS id b25si138092vkk.5.2020.12.02.04.29.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Dec 2020 04:29:40 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::732 as permitted sender) client-ip=2607:f8b0:4864:20::732;
Received: by mail-qk1-x732.google.com with SMTP id n132so951183qke.1
        for <kasan-dev@googlegroups.com>; Wed, 02 Dec 2020 04:29:40 -0800 (PST)
X-Received: by 2002:a05:620a:1005:: with SMTP id z5mr1027443qkj.350.1606912180161;
 Wed, 02 Dec 2020 04:29:40 -0800 (PST)
MIME-Version: 1.0
References: <CAD-N9QXFwPPZC0t1662foXgHh6_KEFpGGB01hWWryBL=ZsBs0A@mail.gmail.com>
In-Reply-To: <CAD-N9QXFwPPZC0t1662foXgHh6_KEFpGGB01hWWryBL=ZsBs0A@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Dec 2020 13:29:28 +0100
Message-ID: <CACT4Y+ahZ5qtC5wa+pCKYoyrVQ79EdVbJD4jFZvYMkPw8LpzXg@mail.gmail.com>
Subject: Re: Any cases to prove KCSAN can catch underlying data races that
 lead to kernel crashes?
To: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>, 
	Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=L0aJO8R5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::732
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Dec 2, 2020 at 1:05 PM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliangabcd=
@gmail.com> wrote:
>
> Hi Dmitry,
>
> I hope you are doing well recently.
>
> I am writing to kindly ask if you know of any cases or kernel bugs that p=
rove KCSAN is able to catch underlying data races that lead to kernel crash=
es. Before asking you this question, I searched data race bugs from Syzkall=
er dashboard for my experiment. On one hand, I tried KCSAN crash reports, b=
ut it is hard to locate a PoC for reproduction. On the other hand, I found =
some race bugs that trigger KASAN reports or WARNING. Then I disable KASAN =
and enable KCSAN, however, In two cases(65550098 rxrpc: Fix race between re=
cvmsg and sendmsg on immediate call failure and d9fb8c50 mptcp: fix infinit=
e loop on recvmsg()/worker() race.), KCSAN did not report any problem durin=
g PoC running. Finally, I failed to find any cases to prove that point. The=
refore, if you know of some cases in which KCSAN can catch underlying data =
races that lead to kernel crashes, please let me know.
>
> Thanks in advance. Looking forward to hearing from you.

+Marco, do you have a list of "worse" data races caught by KCSAN.

I only remember this one:
https://groups.google.com/g/syzkaller-bugs/c/mzwiXt4ml68/m/GuAUQrWtBQAJ
which is not exactly a crash, but I would say it's worse (it was
ignored and closed as invalid...).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BahZ5qtC5wa%2BpCKYoyrVQ79EdVbJD4jFZvYMkPw8LpzXg%40mail.gm=
ail.com.
