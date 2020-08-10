Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBS62YT4QKGQEHFNP3CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B14C24052B
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 13:19:40 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id j63sf5368168oih.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 04:19:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597058379; cv=pass;
        d=google.com; s=arc-20160816;
        b=x1eZM4P+wjYIsiLzSEWahAJjr90/iV1mHwfZjRzkJPNXjZpWWSRCnO0R9R4Z/ELktm
         ckGxV1m0BsCyET08CH1VxKwIitqwCFb3c1qgrcpGiAnEVxzLHgiLOINgloeuW7hzzmOK
         2t/e4IZQAe/f7HyBG/iv8QCayJbL4yNkGCVe3jLM5AC/AUann8qApRVOjwEhJwSh/1GH
         SiQYsjatR1OrkFrOV/3DL0fJ5uZgKDej7ajrTMDtzg3a48IR75lpCjryJFA+NlhyzKXb
         h2Er5OuwXNwsN9VYyXFT/B5oHU/nKyUL5PXbnRb6Vx3rpi0+j3HWMIlO3yAJ8E2KOaqf
         uYGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=cjKPw6DOqpKFcObvHjfFInKB5yuMjl2/45W12YHNjco=;
        b=rIdbjbmCj+Veq/301gtNaRGNjHAGcGZks4BfAuOhHcz2bXj26tYwzXmj5JAs6Zj1ak
         S3raoWScAeeNLNH+eWuV+Mb3mU9oX6CJktTFYqIVeZnaa+xCHod7mOyCFYmLci1NI0uL
         CmTFcxm29gIAlbpS14kvMPvN5pCfSpquaZA6BcvnsCsjz+lV2xuVBUXg6Y8z/7TWHCpd
         /3FAfK/5Kk9YnXHE8yQ4COt8HUffZU3tNSYjOe8p4omKNmtLVxU1k7ggB6Yn48nTY72i
         9ePz5jNoVk/Ve7LdJXUr4G8h9rlCl4B9o7+XIOv0t97P6YmMDG3k3ObrK08NRudHpV7E
         8oUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=AC8ZVjcV;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cjKPw6DOqpKFcObvHjfFInKB5yuMjl2/45W12YHNjco=;
        b=J85v4vVV8SyxwW8V7oekdVb0ePaTWZgKOySI83TN9QHHVuwLjyqjf+8XfiRldl+eHR
         uFwxOStuPuLTivFAQbJGV4TlwNhlLMod4hf2qHgCK7ERuyt9jWxgAGfW6xV1V1RV+U2t
         PyoLpMEoWU7Ep4DXGZ+dUukeTrczkkFc7eYZaRqnlIYQJ1Yvgg6VISQD6RLjNGKmjQZo
         s5t0wsrdGA+nizg/NaugTwoMVyhgTNyxAXx4Qp3BLx/Ee9Qxdv1r9vH1M54drpPyI0N6
         CeFSuhEfeOGF414KhP0i+1ddVAA6FLJjgkcVR7gp6B6SyW6sjehmLGKaiHJcwK5fZIlR
         kXXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cjKPw6DOqpKFcObvHjfFInKB5yuMjl2/45W12YHNjco=;
        b=XBbRG4pLiu9YItcqe+2xse0GBSBUXeL0YtYDUSqU9Yxyp+jprkG87qYXq3DiYyTKZ8
         JNDqxuwV6/3UIldfJAM5Vuu+ltiNkdTjaIlwRj+MLzRLpAdjVIRQacUJK3NZ+N/RKJSI
         YvK1be3QQ9xm2nwQEgQDeeFLXI2DGZVGg7Jk4Wi0R/L0J3uV6WQadCTncmxvs3mUl5Io
         yd7VE1KZ1eLOsO1D7eAUS9285cDiZsNaHsAILssL8nngNa3u385VpDkdMdYFqJ2lBm4v
         //WsRZd7BobuqAuvqPXmieUzbtcO5vUXFR9D5ehPo8iZ9kCPwV3RMsZ0yRinZUmt1X0K
         smmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532mkqj1O0/6bBme5ENug0NssdfVT2/wV9ZG9oUMh6KwsQAPB1c0
	+m70bKwZU1pS4h6B7gbVm4M=
X-Google-Smtp-Source: ABdhPJzdynmfjYO3eKBlET85l1pbE3741vMx1ktGxDu36OtXiGbp5B2S1BPedFmAHDRRrnjRsV7ESQ==
X-Received: by 2002:a9d:6218:: with SMTP id g24mr364810otj.48.1597058379222;
        Mon, 10 Aug 2020 04:19:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c78d:: with SMTP id x135ls3510666oif.1.gmail; Mon, 10
 Aug 2020 04:19:38 -0700 (PDT)
X-Received: by 2002:aca:4b54:: with SMTP id y81mr279443oia.54.1597058378818;
        Mon, 10 Aug 2020 04:19:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597058378; cv=none;
        d=google.com; s=arc-20160816;
        b=t0YEaLfMhEIRJYBuQQwVz1mtGhucje1ttlW7Y/P9eg/RxLNR8ggecwrY2MM0ML84HK
         jKACATsrSSC0kzxhzU0jnJs2rHiP9krwvkQs1lEG1I8JAOoic8kZQY/4ABgcRlWu4KAl
         PXA8/QzXN5lIPqdtHTYl5WwFw8+QfbBnMuKjOpPhH+qNoyhiccRhUDnIdxghLaEIqLBo
         3s57r3HXEYEkd3nnURXV43TplfCuJrIruL3vkEbC6A5vuZxstuRgzBLdJV0VZi/FTO69
         5o3H69HD61vuFrUJ3KK79Gj9zu+y1UN++6Cxw1eLGbtyP47MY4+Ej1BeHWy4bIeHAsDY
         yqug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=jBoqTcJjXqs5aO9SnK52GQyuo0v59XIXZ4pSXxs8r7w=;
        b=jeFeMk2/HnVlRVHv1+vGFAd2WBiAaB/oLRXzwcS8GgUWOu6Mb8Y/2vb6/QoxT/w38F
         I4hG7mtr+avmEKOXrhNVERjLEe07XCAr/PeMXnupzNzO9XOo5v/Rxicf906z444l06a/
         9u515TOIadvtGgUF68ertGZwn6qBKRXr+iDaZpHvi8Wyu9IU7lb9l/RJX2zyItEFAh1j
         cLMvNa3qxraGCYgPvx3Xm09hWxVJ7shvyL51j3IL8gaP0wTlW9h0mtXaLhlK4qDesIa/
         RswLF2r0EtD+HhrzlS4wMV5rf+VwzACafmTBbNUursmXvqrmTD2/8wLZGx3pt64IxuPL
         bGyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=AC8ZVjcV;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id w1si968588otm.5.2020.08.10.04.19.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 04:19:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id m7so7878238qki.12
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 04:19:38 -0700 (PDT)
X-Received: by 2002:a05:620a:142:: with SMTP id e2mr25276476qkn.418.1597058378182;
        Mon, 10 Aug 2020 04:19:38 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id 78sm13980983qke.81.2020.08.10.04.19.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 04:19:36 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH 0/5] kasan: add workqueue and timer stack for generic KASAN
Date: Mon, 10 Aug 2020 07:19:35 -0400
Message-Id: <B873B364-FF03-4819-8F9C-79F3C4EF47CE@lca.pw>
References: <20200810072115.429-1-walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>,
 Lai Jiangshan <jiangshanlai@gmail.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>,
 linux-mediatek@lists.infradead.org
In-Reply-To: <20200810072115.429-1-walter-zh.wu@mediatek.com>
To: Walter Wu <walter-zh.wu@mediatek.com>
X-Mailer: iPhone Mail (17F80)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=AC8ZVjcV;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Aug 10, 2020, at 3:21 AM, Walter Wu <walter-zh.wu@mediatek.com> wrote:
>=20
> =EF=BB=BFSyzbot reports many UAF issues for workqueue or timer, see [1] a=
nd [2].
> In some of these access/allocation happened in process_one_work(),
> we see the free stack is useless in KASAN report, it doesn't help
> programmers to solve UAF on workqueue. The same may stand for times.
>=20
> This patchset improves KASAN reports by making them to have workqueue
> queueing stack and timer queueing stack information. It is useful for
> programmers to solve use-after-free or double-free memory issue.
>=20
> Generic KASAN will record the last two workqueue and timer stacks,
> print them in KASAN report. It is only suitable for generic KASAN.
>=20
> In order to print the last two workqueue and timer stacks, so that
> we add new members in struct kasan_alloc_meta.
> - two workqueue queueing work stacks, total size is 8 bytes.
> - two timer queueing stacks, total size is 8 bytes.
>=20
> Orignial struct kasan_alloc_meta size is 16 bytes. After add new
> members, then the struct kasan_alloc_meta total size is 32 bytes,
> It is a good number of alignment. Let it get better memory consumption.

Getting debugging tools complicated surely is the best way to kill it. I wo=
uld argue that it only make sense to complicate it if it is useful most of =
the time which I never feel or hear that is the case. This reminds me your =
recent call_rcu() stacks that most of time just makes parsing the report cu=
mbersome. Thus, I urge this exercise to over-engineer on special cases need=
 to stop entirely.

>=20
> [1]https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after-fre=
e%22+process_one_work
> [2]https://groups.google.com/g/syzkaller-bugs/search?q=3D%22use-after-fre=
e%22%20expire_timers
> [3]https://bugzilla.kernel.org/show_bug.cgi?id=3D198437
>=20
> Walter Wu (5):
> timer: kasan: record and print timer stack
> workqueue: kasan: record and print workqueue stack
> lib/test_kasan.c: add timer test case
> lib/test_kasan.c: add workqueue test case
> kasan: update documentation for generic kasan
>=20
> Documentation/dev-tools/kasan.rst |  4 ++--
> include/linux/kasan.h             |  4 ++++
> kernel/time/timer.c               |  2 ++
> kernel/workqueue.c                |  3 +++
> lib/test_kasan.c                  | 54 ++++++++++++++++++++++++++++++++++=
++++++++++++++++++++
> mm/kasan/generic.c                | 42 ++++++++++++++++++++++++++++++++++=
++++++++
> mm/kasan/kasan.h                  |  6 +++++-
> mm/kasan/report.c                 | 22 ++++++++++++++++++++++
> 8 files changed, 134 insertions(+), 3 deletions(-)
>=20
> --=20
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20200810072115.429-1-walter-zh.wu%40mediatek.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/B873B364-FF03-4819-8F9C-79F3C4EF47CE%40lca.pw.
