Return-Path: <kasan-dev+bncBCH2XPOBSAERBFMGT37AKGQEO2IRG4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 74C6B2CBC5F
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Dec 2020 13:05:42 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id n186sf1602906ybg.17
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 04:05:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606910741; cv=pass;
        d=google.com; s=arc-20160816;
        b=W8QItdKhI8xzjsy3DixpJ5+WpKj0aRdi7ZzIsMOic+x0+QmRHzseixAD98yRKN1tW0
         HlufcOmyLciQWV4qjTJmOLeeCWfSwLljuQM9it6F0fGhpTG9jV/g6ARteBrvVps6JJjj
         vRW8Wd019QWalg60zXOcMz6MTf28yiPGMnS9aZITB5okfz6Yfh+N6LEab4fRypNNlfXf
         IjtfY8Pr+IPM9So60caLgIqiOVS3f13PV8sGRjPVmKFDpX1Va92y3J97jyMNS5V5dbrW
         Uxk6G7BmZgbnGwJftj9L7/JZ0UhbsWxi10TuG59Y7WITqWBxw+DL/dK/MBVyxm5OprzU
         Fv3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=utJnrVgdBWYKIyNy+1klWmaBpOgkTi6bDor/S1cSpkg=;
        b=IP+X2+UguDtAUoya8j58QshCeWQJx5xnfKsecuttlWVJEoHWZpibOEF9n+tV73tuTm
         FDU5DUhwHGp6gMYRIoXUw3pgD0/gs+FuL8lvfkkR38LVqLieO3I8uix7P9nPgG1Xj34G
         JWoPG7Ax1IyA7zrnJOsfUQBLrIKyVZIwF8MURJpcLgqdBf6WiywnleaKC0IIlFb5uEzF
         1HigrkyF4BbNW3ccCBzbuRBtGvuK3nOpKzENK5+PdufNtoh0AIvWbBzoVBGneUyGIaG/
         ghlj0oZVHT/KeJQT+8Vq6vTHAvSYzWQ4A2KzZFdmGlQk19Ap1i2nXqD+55zRRqH8+tya
         cQ3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nQbTUh3t;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=utJnrVgdBWYKIyNy+1klWmaBpOgkTi6bDor/S1cSpkg=;
        b=axHILlVFJ/bYy+lGyQwR18R5Vf1HGKNBou6NrJsF0FV/ZBQsc9pPH6kDCQqH/TcD+u
         m9kckLPn9ZBFpFx8/h9KNyots8SUQm9OkrVqVzLsoCFtDUO26zgnZWdT+GZF9SnD9kNV
         4hphc0bAtY4KYRJgslJwPlw308qEIgAzq60XOSbSW3VEeLa3hxPudi2tUxVNHW+l4jmH
         6lhOd7pL+SGnpirlja4UwfchpbsgjgR1dtp39OmuQ+pCdmMHtA+VvmpQ6rijqOk3fIjb
         lAnNS/CunwJ0zDuwNmx4IwbH12569n5cG02HUwcsvMrhwh7YKFUfwUMNgp7NwwL7/AR7
         E+lw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=utJnrVgdBWYKIyNy+1klWmaBpOgkTi6bDor/S1cSpkg=;
        b=WfBPGK83RRWzXNypyT+1xHbEc3LTwp35jF7u8TtELfVXygdQgcvr8AVgQRv9j5ONOZ
         9l9iMUJk609QxL8UDpAUWgAiVLAOyiM/pC6Cd4plW+o3gACCWZ1qlMi/dtgtC86NDXiS
         KXAnMyeNC8oIJTtVYEo1mGfFWK+0CgiuI8OugkOVCqgZ2hSMnepEx98iKtg6xxRFfMRy
         yxlEcyvYMCikDrMrkNZJaMbF9SveTlC9nuOm2aXdzGYRO2l2akIe023VezYBvmvatVk0
         rE/jHtBER4ghI37dtBR6I4aKSpeJIC9KXVHD60KkNKnGbCmuUyW9wbw9zsWpUNUVyhxG
         0vpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=utJnrVgdBWYKIyNy+1klWmaBpOgkTi6bDor/S1cSpkg=;
        b=c8Emqz+dpvHnRNeasnL3YDFbY2L5CPvQ8uN+Vzj6h6zhisyGxrSAbxqHv1RFnUw7nd
         dVyEXR2RfYuKrxsWST32+PKAXXHYJZvopDf+ajqRAW4C3M/x7TvyXWEcPYpw6F9VUXn/
         W7ys2p+DNTofiJGiCKHaiO9v/geGtJ2JmqqnyeC1ADba+J7LKT2kSV66eU43eVD/Tfcw
         yrHh/IhelP7M0foWyCey3SQ77rihA/QhFHmn3In52Qqw3E6TzL/Wr7tbsoSXzuKvfD+i
         wvLyLyGMbHO6Vjb8541EyDYqUf2wbjL66o2+wBr3sRHntXrGSGZK0Nwy6qSYLNDdiVEG
         q9SQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532PeB2hQD76XOC4PHR5vhW0OvKS/KGBbHgIMcWe4mWpal8aubSM
	S1u9NSvAHYM73tiVuWssu6Q=
X-Google-Smtp-Source: ABdhPJxn2fWfpNW+d7R/mW1pOtfFYs/FalSZZeKngpc6U8VvKMrZRpFw72um3zDRVTyieWh6YGSZyQ==
X-Received: by 2002:a25:b886:: with SMTP id w6mr3111934ybj.144.1606910741304;
        Wed, 02 Dec 2020 04:05:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ce49:: with SMTP id x70ls878397ybe.4.gmail; Wed, 02 Dec
 2020 04:05:40 -0800 (PST)
X-Received: by 2002:a25:5202:: with SMTP id g2mr3029979ybb.311.1606910740822;
        Wed, 02 Dec 2020 04:05:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606910740; cv=none;
        d=google.com; s=arc-20160816;
        b=t3dNy6H6CzfgWbOzTnv3iihIfER1QlvGQodanmB5E76WEesUKea4y0pCW6fRlGWGte
         V5OJNqXMGbIackP1TkJk6JpH6sJWqNYoLRQi41mBsXoTpVlIQQnRPSNx80XiS+C/LgCe
         VB/ecirjhPUkBalni8dfjBb8q5cERSPAvahfiK1cjv6s/UooXK6ewlD9NsPhEu2CSNcA
         FgV/fbfz2VZKMOKKrP1yMG128nnTW+J30kA/sJ8/Jywl70XNbvxWwJCvQ0+QGmWAQ3xd
         /vRnw1BjAGpIsBADQmyKys9jYxAk4nF9nCRZtdGdivmIHlKHv3+/AnyrJW1kEA+TwOv1
         HK0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=Pe/hEdT/9rmLmmh70lDhQI9tRTkkbDo4a4oU7RzRUSo=;
        b=lWH6t6otCgGcBbkW+bJeEWLsNUA8YUnlYe8QNBDfbZrSedy0VNEeUlLv6AQU2jmvT+
         PjxxEW2wkJy6DeDoogbmpbs5DDjcwkmB0fNVS9MNu+1SplM7V2x9eeTmC+DoUBEfaGNS
         sDKIkVtNy5Tfj3Va6HcsAkdOQVQQ4RKGBvmN5vXlLnQcLeDqoxUwy/GNMzzEFzLVy8lD
         G0RtELYgMh9pkYrw/GeAwjNqMgtKuqmzOHQB6684xewGa6vuIRA8XBMF+cRWsP96Nbcs
         7wINOvtrbteQMT+p2TZ4PKyY2pAVTC97mwM6xLO6oWUeJAnfyGAYiPumNbijBk+1mzRp
         kq/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nQbTUh3t;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb2b.google.com (mail-yb1-xb2b.google.com. [2607:f8b0:4864:20::b2b])
        by gmr-mx.google.com with ESMTPS id m3si143362ybf.1.2020.12.02.04.05.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Dec 2020 04:05:40 -0800 (PST)
Received-SPF: pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b2b as permitted sender) client-ip=2607:f8b0:4864:20::b2b;
Received: by mail-yb1-xb2b.google.com with SMTP id x17so1375516ybr.8
        for <kasan-dev@googlegroups.com>; Wed, 02 Dec 2020 04:05:40 -0800 (PST)
X-Received: by 2002:a25:2e0d:: with SMTP id u13mr2634530ybu.247.1606910740522;
 Wed, 02 Dec 2020 04:05:40 -0800 (PST)
MIME-Version: 1.0
From: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Date: Wed, 2 Dec 2020 20:05:14 +0800
Message-ID: <CAD-N9QXFwPPZC0t1662foXgHh6_KEFpGGB01hWWryBL=ZsBs0A@mail.gmail.com>
Subject: Any cases to prove KCSAN can catch underlying data races that lead to
 kernel crashes?
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="000000000000dfe96d05b57a0f09"
X-Original-Sender: mudongliangabcd@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=nQbTUh3t;       spf=pass
 (google.com: domain of mudongliangabcd@gmail.com designates
 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000dfe96d05b57a0f09
Content-Type: text/plain; charset="UTF-8"

Hi Dmitry,

I hope you are doing well recently.

I am writing to kindly ask if you know of any cases or kernel bugs that
prove KCSAN is able to catch underlying data races that lead to kernel
crashes. Before asking you this question, I searched data race bugs from
Syzkaller dashboard for my experiment. On one hand, I tried KCSAN crash
reports, but it is hard to locate a PoC for reproduction. On the other
hand, I found some race bugs that trigger KASAN reports or WARNING. Then I
disable KASAN and enable KCSAN, however, In two cases(65550098 rxrpc: Fix
race between recvmsg and sendmsg on immediate call failure
<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=65550098c1c4db528400c73acf3e46bfa78d9264>
 and d9fb8c50 mptcp: fix infinite loop on recvmsg()/worker() race.
<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d9fb8c507d42256034b457ec59347855bec9e569>),
KCSAN did not report any problem during PoC running. Finally, I failed to
find any cases to prove that point. Therefore, if you know of some cases in
which KCSAN can catch underlying data races that lead to kernel crashes,
please let me know.

Thanks in advance. Looking forward to hearing from you.

--
My best regards to you.

     No System Is Safe!
     Dongliang Mu

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAD-N9QXFwPPZC0t1662foXgHh6_KEFpGGB01hWWryBL%3DZsBs0A%40mail.gmail.com.

--000000000000dfe96d05b57a0f09
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>Hi Dmitry,<br></div><div><br></div><div>I hope you ar=
e doing well recently.</div><div><br></div><div>I am writing to kindly ask =
if you know of any cases or kernel bugs that prove KCSAN is able to=C2=A0ca=
tch underlying data races that lead=C2=A0to kernel crashes. Before asking y=
ou this question, I searched data race bugs from Syzkaller dashboard for my=
 experiment. On one hand, I tried KCSAN crash reports, but it is hard to lo=
cate a PoC for reproduction. On the other hand, I found some race bugs that=
 trigger KASAN reports or WARNING. Then I disable KASAN and enable KCSAN, h=
owever, In two cases(<span style=3D"font-size:medium;color:rgb(0,0,0);font-=
family:monospace;white-space:nowrap;background-color:rgb(255,255,153)">6555=
0098=C2=A0</span><a href=3D"https://git.kernel.org/pub/scm/linux/kernel/git=
/torvalds/linux.git/commit/?id=3D65550098c1c4db528400c73acf3e46bfa78d9264" =
target=3D"_blank" style=3D"font-size:medium;font-family:monospace;white-spa=
ce:nowrap;background-color:rgb(255,255,153)">rxrpc: Fix race between recvms=
g and sendmsg on immediate call failure</a>=C2=A0and=C2=A0<span style=3D"fo=
nt-size:medium;color:rgb(0,0,0);font-family:monospace;white-space:nowrap;ba=
ckground-color:rgb(244,244,244)">d9fb8c50=C2=A0</span><a href=3D"https://gi=
t.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3Dd9fb8=
c507d42256034b457ec59347855bec9e569" target=3D"_blank" style=3D"font-size:m=
edium;font-family:monospace;white-space:nowrap;background-color:rgb(244,244=
,244)">mptcp: fix infinite loop on recvmsg()/worker() race.</a>), KCSAN did=
 not report any problem during PoC running. Finally, I failed to find any c=
ases to prove that point. Therefore, if you know of some cases in which KCS=
AN=C2=A0can catch underlying data races that lead to kernel crashes, please=
 let me know.</div><div><br></div><div>Thanks in advance. Looking forward t=
o hearing from you.</div><br class=3D"gmail-Apple-interchange-newline"><div=
><div dir=3D"ltr" class=3D"gmail_signature" data-smartmail=3D"gmail_signatu=
re">--<br>My best regards to you.<br><br>=C2=A0 =C2=A0 =C2=A0No System Is S=
afe!<br>=C2=A0 =C2=A0 =C2=A0Dongliang Mu</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAD-N9QXFwPPZC0t1662foXgHh6_KEFpGGB01hWWryBL%3DZsBs0A%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAD-N9QXFwPPZC0t1662foXgHh6_KEFpGGB01hWWryBL%3DZs=
Bs0A%40mail.gmail.com</a>.<br />

--000000000000dfe96d05b57a0f09--
