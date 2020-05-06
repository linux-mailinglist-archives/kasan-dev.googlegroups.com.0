Return-Path: <kasan-dev+bncBDGPTM5BQUDRB6FPZH2QKGQENOYP2BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 530A31C68C4
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 08:23:53 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id n47sf363982uae.6
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 23:23:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588746232; cv=pass;
        d=google.com; s=arc-20160816;
        b=RR12pqoJHhlfszyVy/Kafm0AG5y98MXpi4gxbA5HYcYNVRKPa7+vFfMXU6U1R7LaEG
         5PAiRDsQx7mH5SfqAaZ6efiGkQmZphm4PAcmMefnzqPSA9wuOe1YcdIZtr2WiDoTtgVO
         rPI3T73gdD4fRzIiB6GCV7bvSgUKXlI9NZX4x3xElToclTHzVWzqHFSGruAC+cdP2bTe
         iMq74rf0l8jbnhWj5/hnYaHQyTmXhtSicuujy2w5ZOxpmE9A7WxpaQ4z1aHcWVq/Z3y4
         TvFerAqlD1rD92Kazv3m77Q+qAnFzHEQfGQLIbN0AdoFrcO035HJ0nvdQkdVYVcN6XnG
         8gDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=srqwNwp2H1YLTCcGm3rlBQ2zC7R7FRG3EPb9a0jYVyw=;
        b=MUhg6umJiAoxtqN3anOBQkMa35601UjOyfk1Qq9uGstrhqwUmf/DXhhokbbSLlI8Di
         WGaGs+FI296BZkJq9gACjWyFD7mVFYImR+eBZ7RNRj+VbcyBgUq8cQm2t3BwFaoVHKnp
         Vsej0CjNHyRpP6NbQLrfhfKUyONiPkUClu/t/IltX4oA2F3g7ykVu1lmqDy3Ifsgtz+E
         v5KfmZjgbY5YszIXup6cSeDrNCDBySFaJE4rXCcMrg+WtkFjSifz16UOvhtYwDS4IT+u
         WNFbfwTQRlx14a+xGQNh66il4+O8xsQG8pApD7lHKhq6VJCMNBJ/xDoSJai3HmFngOJf
         8tjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=YdPweka6;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=srqwNwp2H1YLTCcGm3rlBQ2zC7R7FRG3EPb9a0jYVyw=;
        b=PoavPImaUQYnA4WAMWi6C3qEBkJxNeOnn2jYiuKrrUrrrpGgA1dMuxVk4HK2LKrv88
         466pkSfhytJwRls1Cf/zKVdRcxKjOsRVahiX5fREjYeE0+LAIr+PxSFLdJpEFxTRyt6I
         iLlY5zBRJZMMSrbDCajacR/b/YArJZGI/MVolLFNYbOrKAgM52+aOSGuJSISLiwWEfve
         ARVf0On5lo8beftW0C9bkOzO4S5bbrcpaXMKGW11KXDHZF9dR4pcrgS9oyQaEHuvkPAd
         hHRxSYix8jcWssNV5GOBq6a2IDOVjf83l6/iJUasx8+uSPij0M671On6Xcfj+bXn+zrq
         H0dQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=srqwNwp2H1YLTCcGm3rlBQ2zC7R7FRG3EPb9a0jYVyw=;
        b=iRTKJiygCRUlG0URIOogfkmvWeI6CrR/Wu0E9D3lMZOw//+ml7To+cn6G/vWRxJRz/
         mjPwQXoJwGNGo3xsIoaWUrMuZo7f8Ln02nWNCpJQKYjEX5Qg11tA6q0MyPUvhnnT6K/6
         sBNFB0m369bWa6LyvTWEno0h0ds1t9FNsZ/bU9/Np4DdWw0ozhNaNhmR+Ee427hzd45K
         d8Ax/l18Xhv1SNcqwdtWKYkrrznq9FDWJaKpyEMZiMVxZwb2h+VEVE3G1UJUR1+Ehav9
         HuZigcAVVyCKlVuIJLkERlTS5igCF02fIsHtyf59vYbzDrdeLy38TaSl5XlmvFvtshiX
         Ttww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZaUSDb4UqSXqx8/uz/A/R56cDCqX5E6X90HZQkRDfprDp5mYEX
	uN57n2+1Ylejzk//Ps/sKH8=
X-Google-Smtp-Source: APiQypL85M3KF6KgiKiUDC4oGU14KVJ0DMw627YQeYB7BbWnuyTNkqIlYf8NkpaIzY7Ob6n9IuC8gA==
X-Received: by 2002:ab0:2859:: with SMTP id c25mr5691794uaq.57.1588746232392;
        Tue, 05 May 2020 23:23:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c319:: with SMTP id r25ls145516vsj.4.gmail; Tue, 05 May
 2020 23:23:52 -0700 (PDT)
X-Received: by 2002:a67:c482:: with SMTP id d2mr6602052vsk.37.1588746232039;
        Tue, 05 May 2020 23:23:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588746232; cv=none;
        d=google.com; s=arc-20160816;
        b=uWG+iQ98fcDgma+hA7w5XpAka/N+QgtuBNAoLuR8LN3xlwWmJsFGSHBN9O4pidQpW8
         lJJWubmhzc68RAdMmJS5eJ/E6G/y4C0GPeS84zpcLZdauv6+dSuuy8mTiZS4bHvDornM
         z+rwhf2QQ53x3pFmqtMlaBuZNtCRiSdmt2nN0C9tqKOzO3BHuHj9Ioerw/DA5O6JoTeH
         f67YHyaDlrHtivsfXVP8dvPBF0Pe7L//2EJ71sZvIMbS0t+UUiwz04huaQ1RHmMlaHek
         RPp+7c4J/H6VW1yIIMZ4TkRLKu1MUIygJzl2WU9pY2dX/vn4iQjrFrGJYFSRQPnB8y1o
         5nbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=EMtEpkXEvK9nfHRYvG1dhOQ8iE+qMOZdMvGDu7QjaPw=;
        b=Id8chO3Bb9ELIEFAjYGJtBfUz1fS7ueDUE8YGOSQ1P3Gkf1eXeTMPzjTmlWSXAl9HA
         bUTsP5DB0tGB7ZINPUkKpqngV4TXUOreFiWyoBZcY2WAF7nYg9vDRqlxIY7SQDmddgps
         1wMJZLo8jfo6wLuIQlxDKk5twYUdJHGDJt3SarQ9GTqNvnLrrAds+ehyTXfcbomo7g/t
         sWzMGwJFZKhAKoW1uzFXMV50i044eMbMeAPxK0O3C4VDfdCPqWHwyGc4HykdP4wASQAi
         vNr2+dJLgvg5P/jqYUNT2bEKTGWFs/vEZiHLNgEvgHUSIhtTZRe6oaWVkO+hZ2v5ubFR
         SmWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=YdPweka6;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id y11si99454vkc.3.2020.05.05.23.23.51
        for <kasan-dev@googlegroups.com>;
        Tue, 05 May 2020 23:23:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: f60d58e8e7534651a6dc3844e569535c-20200506
X-UUID: f60d58e8e7534651a6dc3844e569535c-20200506
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 460470072; Wed, 06 May 2020 14:23:47 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 6 May 2020 14:23:38 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 6 May 2020 14:23:34 +0800
Message-ID: <1588746219.16219.10.camel@mtksdccf07>
Subject: Re: [PATCH 0/3] kasan: memorize and print call_rcu stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Qian Cai <cai@lca.pw>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, "Josh
 Triplett" <josh@joshtriplett.org>, Mathieu Desnoyers
	<mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>,
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Wed, 6 May 2020 14:23:39 +0800
In-Reply-To: <2BF68E83-4611-48B2-A57F-196236399219@lca.pw>
References: <20200506051853.14380-1-walter-zh.wu@mediatek.com>
	 <2BF68E83-4611-48B2-A57F-196236399219@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 42DEFC715D66F1062290FF153DFF6751FECE0CF316B54F13B8825BE6B87E4B562000:8
X-MTK: N
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=YdPweka6;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Wed, 2020-05-06 at 01:53 -0400, Qian Cai wrote:
>=20
> > On May 6, 2020, at 1:19 AM, Walter Wu <walter-zh.wu@mediatek.com> wrote=
:
> >=20
> > This patchset improves KASAN reports by making them to have
> > call_rcu() call stack information. It is helpful for programmers
> > to solve use-after-free or double-free memory issue.
> >=20
> > The KASAN report was as follows(cleaned up slightly):
> >=20
> > BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60
> >=20
> > Freed by task 0:
> > save_stack+0x24/0x50
> > __kasan_slab_free+0x110/0x178
> > kasan_slab_free+0x10/0x18
> > kfree+0x98/0x270
> > kasan_rcu_reclaim+0x1c/0x60
> > rcu_core+0x8b4/0x10f8
> > rcu_core_si+0xc/0x18
> > efi_header_end+0x238/0xa6c
> >=20
> > First call_rcu() call stack:
> > save_stack+0x24/0x50
> > kasan_record_callrcu+0xc8/0xd8
> > call_rcu+0x190/0x580
> > kasan_rcu_uaf+0x1d8/0x278
> >=20
> > Last call_rcu() call stack:
> > (stack is not available)
> >=20
> >=20
> > Add new CONFIG option to record first and last call_rcu() call stack
> > and KASAN report prints two call_rcu() call stack.
> >=20
> > This option doesn't increase the cost of memory consumption. It is
> > only suitable for generic KASAN.
>=20
> I don=E2=80=99t understand why this needs to be a Kconfig option at all. =
If call_rcu() stacks are useful in general, then just always gather those i=
nformation. How do developers judge if they need to select this option or n=
ot?

Because we don't want to increase slub meta-data size, so enabling this
option can print call_rcu() stacks, but the in-use slub object doesn't
print free stack. So if have out-of-bound issue, then it will not print
free stack. It is a trade-off, see [1].

[1] https://bugzilla.kernel.org/show_bug.cgi?id=3D198437

Thanks

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1588746219.16219.10.camel%40mtksdccf07.
