Return-Path: <kasan-dev+bncBCT6537ZTEKRBKVWUGOAMGQELE6LUOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C3F363EA77
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Dec 2022 08:43:40 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id x203-20020acae0d4000000b0035a623fce1asf718374oig.10
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 23:43:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669880619; cv=pass;
        d=google.com; s=arc-20160816;
        b=uyjSoNFVDRx8IUs9mB01f52jjmQZe9ugpX9+PWU89raCc7vtT9mIHADntUmL+y44cd
         AblH/bBHZlA1Pb1d+UaE8OHRaTvhpbrq09g174Ccn2EksGsfRaJPOvvJLva3yNnFeCQw
         x7BngrXQ773PbSb6hj5j8yVN+nJw8HVhnYR/ILFkoGgaTx+jFBBclSqA30yYIoJxW+/j
         m5tzdsvFYJKWZ3Hj8zmsfe3z1/uBMpHsuZPgwP1YG6Bjzu0XG1uGlH2KDfY7yktFo+ic
         HB24skkGMDkqqGwSkSdWs2qRh1l3A7MCkmrt7PufbhoC6Fybhwi3fjCeePLGdDu7p++b
         9yDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=GCpaOZvOuZeQ5Op7tl1l8oNOgd/VuisiYy4sA0lVxgc=;
        b=GV7+jjq9WeaZC/drwaL9jrg0SYugzZLMaTOrxws+KWkmdYLfiMkYZxuVlTBCkuwTjg
         NXpBaNzl1SJ4l/lce0zkFTTZgqs+LLS2vw1n2yawbIR/KulLQqI2wM5WUacHwQO/N0N2
         IjcdOelZBTICJL4beyHqdeokYVKy04wM70OYg95J+QYO8fFnDbQ7OyJQuw4pe8lcC/Eb
         esThwRrAvQ7uGVSSn8bB6FHxgJra/jnm84kc/dBt+SfuXysb11xvgqL+yf/LJkfB39Ap
         mGpnPrg/YVEsbQypJVgHaM7QQh9xxVYA3brse9FTPDJBJ9FPlwUYE64MQdWcb3X9xlHS
         XFlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=kJrxYS8i;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GCpaOZvOuZeQ5Op7tl1l8oNOgd/VuisiYy4sA0lVxgc=;
        b=cCNDqxrLaH/2UzMm1qaQ1+k8fCQPK9cErG28zYyjlixbRacKz17K0olpeX0hKsLMt1
         Bh+6STEQoNKC9MjCD/NHNtr+ypyRd4LkBuEtSi74wPrrV8Vm0owR2qsIxo6qVOMKgsLD
         j6vBPflklkErpgz0/5tvz1XbPN0w8qdCU8gHajwU3BcXDqyQbinJD9Ls9lUrpI1Tme2z
         zoAFmqzokZsZLI+oL1AA+XiG/4h0iEI7kq9jjwA//HSsJkIu0u8F0QP5Y6ZFJ1w5uhny
         Y/TcGb37H7MgorgGAjaCCTzRO5fOHDS8mXfdCOeA0r1YeoWMamBRcPlkpI908nH9DgjY
         KBfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GCpaOZvOuZeQ5Op7tl1l8oNOgd/VuisiYy4sA0lVxgc=;
        b=ri4RILmIYxoB2i2f2gAbmSYfbgOXbhTAWeWyXxouWpzm/PiN4wav/97qkrrzDOcu/C
         k83D7rnK/3VKDBBQlC+YJmxjPBITsxod5n2ZwCOjABSZE4sXFZ6pBOOJFHGRmbFb9KyE
         p6wApYcYeqtn4C0wi7WLNLeb/nx5u4+GQeF2nk1aza8Tb+nOLrHfZ/2ilVjT2SC9Vy3L
         //uPVPYsgcc5qeoi/kaA0NoohKY5y/551QZqDQXsWqKQL173TLlUbKEy1FcbxJj13+wV
         RsOErpOQmxemPqyWVwubqE+g/Mqgs0xrNN1+7PWQaCw99WJ03cqzEWAOOG2fJMzcRWRS
         xYRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pn/GI+l8hzRXLDZqvhpfEJP2L5E+dVWW5lYxXcoEJCQta3xkXUZ
	zINban5vRmWeBgQMYdjEmn8=
X-Google-Smtp-Source: AA0mqf4Pbk4cN3YQHRTkWP41n9VCwjV1c1ER5aKSDXE5moJFqvKPsn8+/D6RhaaUk0s765znxS43sA==
X-Received: by 2002:a05:6830:61ce:b0:66b:e4e2:8d25 with SMTP id cc14-20020a05683061ce00b0066be4e28d25mr32573519otb.152.1669880619033;
        Wed, 30 Nov 2022 23:43:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d892:b0:141:8ce4:295a with SMTP id
 dv18-20020a056870d89200b001418ce4295als456556oab.10.-pod-prod-gmail; Wed, 30
 Nov 2022 23:43:38 -0800 (PST)
X-Received: by 2002:a05:6870:ed4a:b0:144:ae9:4d5 with SMTP id ex10-20020a056870ed4a00b001440ae904d5mr2981573oab.127.1669880618401;
        Wed, 30 Nov 2022 23:43:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669880618; cv=none;
        d=google.com; s=arc-20160816;
        b=F7tsuwKn0CflOhg2WnRLVh1ZzbR+4B4yzyJSfOyyhkIK2BSHvrki9qyse1IlaWLKSQ
         ffJP2FcQdxDIwrSJhnUXVM27sZJLmpgiNDlXRvdo788yalIP8eP+Ys83mvc3SOU4Kh0a
         JHghe6a9Lj5yAPeUdtoSORcREBfYPVRJ0qiYLZmPmH/pN/wJ+MsB4HwRV9XlIhPMkFnh
         bEdn5CuRC1VtoX0/dSdoSggvRxzsWAwXWEStiXyemSav43gaCV6ljFOuqJvcyRS3eJZB
         0vTO//OamCPN53+Dg9atYCl9oYgiHJf3PhEI1zXxY5DEM2cVxzTgghDyzoWLIZD/hd2z
         Kvng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n/cSfJyuw306M41Dp+L+BI0/0zq6sfGvI8BbkoukRHo=;
        b=EgNYdqI1kviWFCcOHF8FUwPcrVBCRa2D2l48w8DWQdAatEEmC3Cp7mEIjtJ8CLf/cy
         I2as75iUtVdZuuUSIgtRHZfxcBOiaE5oNVFAj3wtNoWW9kAW84kB0djPU2ADKfw8LCYD
         LYwu+kkTf7rNWr6XW2c6vz1tSwy1seZRmZUjNG4dG3+gUksqZ5R7Tk5t+1mXrq1vZb53
         ZNZE/yD4ehO/HtlVFF86Rz5FAER/15jqzXdHtiA0J/8rZIjHt9JS655UPS3cod1s7NNg
         cxuWAH6Td9/PfRndUHNeJ/ZiIS34Ato3PXC+zdqTOoS4n5hJGg7K+c2PQ0llch4Zrca1
         34MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=kJrxYS8i;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id u20-20020a056871009400b00143cfb377b2si376235oaa.2.2022.11.30.23.43.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Nov 2022 23:43:38 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id 189so965523ybe.8
        for <kasan-dev@googlegroups.com>; Wed, 30 Nov 2022 23:43:38 -0800 (PST)
X-Received: by 2002:a25:d782:0:b0:6f5:6b11:8110 with SMTP id
 o124-20020a25d782000000b006f56b118110mr19813207ybg.560.1669880617677; Wed, 30
 Nov 2022 23:43:37 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYsK5WUxs6p9NaE4e3p7ew_+s0SdW0+FnBgiLWdYYOvoMg@mail.gmail.com>
 <CANpmjNOQxZ--jXZdqN3tjKE=sd4X6mV4K-PyY40CMZuoB5vQTg@mail.gmail.com>
 <CA+G9fYs55N3J8TRA557faxvAZSnCTUqnUx+p1GOiCiG+NVfqnw@mail.gmail.com> <Y4e3WC4UYtszfFBe@codewreck.org>
In-Reply-To: <Y4e3WC4UYtszfFBe@codewreck.org>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Thu, 1 Dec 2022 13:13:25 +0530
Message-ID: <CA+G9fYuJZ1C3802+uLvqJYMjGged36wyW+G1HZJLzrtmbi1bJA@mail.gmail.com>
Subject: Re: arm64: allmodconfig: BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
To: Dominique Martinet <asmadeus@codewreck.org>
Cc: Marco Elver <elver@google.com>, rcu <rcu@vger.kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, kunit-dev@googlegroups.com, 
	lkft-triage@lists.linaro.org, kasan-dev <kasan-dev@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Netdev <netdev@vger.kernel.org>, 
	Anders Roxell <anders.roxell@linaro.org>
Content-Type: multipart/mixed; boundary="00000000000008f9c705eebf61a4"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=kJrxYS8i;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

--00000000000008f9c705eebf61a4
Content-Type: text/plain; charset="UTF-8"

On Thu, 1 Dec 2022 at 01:35, Dominique Martinet <asmadeus@codewreck.org> wrote:
>
> Naresh Kamboju wrote on Wed, Nov 30, 2022 at 09:34:45PM +0530:
> > > > [  424.418214] write to 0xffff00000a753000 of 4 bytes by interrupt on cpu 0:
> > > > [  424.422437]  p9_client_cb+0x84/0x100
> > >
> > > Then we can look at git blame of the lines and see if it's new code.
> >
> > True.
> > Hope that tree and tag could help you get git details.
>
> Even with the git tag, if we don't build for the same arch with the same
> compiler version/options and the same .config we aren't likely to have
> identical binaries, so we cannot make sense of these offsets without
> much work.
>
> As much as I'd like to investigate a data race in 9p (and geez that code
> has been such a headache from syzbot already so I don't doubt there are
> more), having line numbers is really not optional if we want to scale at
> all.
> If you still have the vmlinux binary from that build (or if you can
> rebuild with the same options), running this text through addr2line
> should not take you too long.

Please find build artifacts in this link,
 - config
 - vmlinux
 - System.map
https://people.linaro.org/~anders.roxell/next-20221130-allmodconfig-arm64-tuxmake-build/

And

 # aarch64-linux-gnu-objdump -D vmlinux|less search for p9_client_cb

Attached objdump log and here is the link.
    - http://ix.io/4hk1

> (You might need to build with at least CONFIG_DEBUG_INFO_REDUCED (or not
> reduced), but that is on by default for aarch64)

Thanks for the suggestions.
The Kconfig is enabled now.
CONFIG_DEBUG_INFO_REDUCED=y

> --
> Dominique


- Naresh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYuJZ1C3802%2BuLvqJYMjGged36wyW%2BG1HZJLzrtmbi1bJA%40mail.gmail.com.

--00000000000008f9c705eebf61a4
Content-Type: text/plain; charset="US-ASCII"; name="objdump-p9_client_cb.txt"
Content-Disposition: attachment; filename="objdump-p9_client_cb.txt"
Content-Transfer-Encoding: base64
Content-ID: <f_lb4rmdbt0>
X-Attachment-Id: f_lb4rmdbt0

ZmZmZjgwMDAwYTQ2Y2FjMCA8cDlfY2xpZW50X2NiPjoKZmZmZjgwMDAwYTQ2Y2FjMDogICAgICAg
ZDUwMzIwMWYgICAgICAgIG5vcApmZmZmODAwMDBhNDZjYWM0OiAgICAgICBkNTAzMjAxZiAgICAg
ICAgbm9wCmZmZmY4MDAwMGE0NmNhYzg6ICAgICAgIGQ1MDMyMzNmICAgICAgICBwYWNpYXNwCmZm
ZmY4MDAwMGE0NmNhY2M6ICAgICAgIGE5YmM3YmZkICAgICAgICBzdHAgICAgIHgyOSwgeDMwLCBb
c3AsICMtNjRdIQpmZmZmODAwMDBhNDZjYWQwOiAgICAgICA5MTAwMDNmZCAgICAgICAgbW92ICAg
ICB4MjksIHNwCmZmZmY4MDAwMGE0NmNhZDQ6ICAgICAgIGE5MDE1M2YzICAgICAgICBzdHAgICAg
IHgxOSwgeDIwLCBbc3AsICMxNl0KZmZmZjgwMDAwYTQ2Y2FkODogICAgICAgYWEwMTAzZjMgICAg
ICAgIG1vdiAgICAgeDE5LCB4MQpmZmZmODAwMDBhNDZjYWRjOiAgICAgICBhYTFlMDNmNCAgICAg
ICAgbW92ICAgICB4MjAsIHgzMApmZmZmODAwMDBhNDZjYWUwOiAgICAgICBhOTAyNWJmNSAgICAg
ICAgc3RwICAgICB4MjEsIHgyMiwgW3NwLCAjMzJdCmZmZmY4MDAwMGE0NmNhZTQ6ICAgICAgIDJh
MDIwM2Y2ICAgICAgICBtb3YgICAgIHcyMiwgdzIKZmZmZjgwMDAwYTQ2Y2FlODogICAgICAgYWEw
MDAzZjUgICAgICAgIG1vdiAgICAgeDIxLCB4MApmZmZmODAwMDBhNDZjYWVjOiAgICAgICBmOTAw
MWJmNyAgICAgICAgc3RyICAgICB4MjMsIFtzcCwgIzQ4XQpmZmZmODAwMDBhNDZjYWYwOiAgICAg
ICBhYTE0MDNmZSAgICAgICAgbW92ICAgICB4MzAsIHgyMApmZmZmODAwMDBhNDZjYWY0OiAgICAg
ICBkNTAzMjBmZiAgICAgICAgeHBhY2xyaQpmZmZmODAwMDBhNDZjYWY4OiAgICAgICA5MTAxYmE3
NyAgICAgICAgYWRkICAgICB4MjMsIHgxOSwgIzB4NmUKZmZmZjgwMDAwYTQ2Y2FmYzogICAgICAg
YWExZTAzZTAgICAgICAgIG1vdiAgICAgeDAsIHgzMApmZmZmODAwMDBhNDZjYjAwOiAgICAgICA5
NzgzNGIyMCAgICAgICAgYmwgICAgICBmZmZmODAwMDA4NTNmNzgwIDxfX3RzYW5fZnVuY19lbnRy
eT4KZmZmZjgwMDAwYTQ2Y2IwNDogICAgICAgZjAwMDM2MTQgICAgICAgIGFkcnAgICAgeDIwLCBm
ZmZmODAwMDBhYjJmMDAwIDxldmVudF90eXBlX3NpemUrMHg4PgpmZmZmODAwMDBhNDZjYjA4OiAg
ICAgICBhYTE3MDNlMCAgICAgICAgbW92ICAgICB4MCwgeDIzCmZmZmY4MDAwMGE0NmNiMGM6ICAg
ICAgIDk3ODM1Y2FkICAgICAgICBibCAgICAgIGZmZmY4MDAwMDg1NDNkYzAgPF9fdHNhbl9yZWFk
Mj4KZmZmZjgwMDAwYTQ2Y2IxMDogICAgICAgNzk0MGRlNjMgICAgICAgIGxkcmggICAgdzMsIFt4
MTksICMxMTBdCmZmZmY4MDAwMGE0NmNiMTQ6ICAgICAgIDkxMWM4Mjk0ICAgICAgICBhZGQgICAg
IHgyMCwgeDIwLCAjMHg3MjAKZmZmZjgwMDAwYTQ2Y2IxODogICAgICAgOTEzODQyOTQgICAgICAg
IGFkZCAgICAgeDIwLCB4MjAsICMweGUxMApmZmZmODAwMDBhNDZjYjFjOiAgICAgICA1MjgwMDQw
MCAgICAgICAgbW92ICAgICB3MCwgIzB4MjAgICAgICAgICAgICAgICAgICAgICAgIC8vICMzMgpm
ZmZmODAwMDBhNDZjYjIwOiAgICAgICBhYTE0MDNlMSAgICAgICAgbW92ICAgICB4MSwgeDIwCmZm
ZmY4MDAwMGE0NmNiMjQ6ICAgICAgIGIwMDA2YTIyICAgICAgICBhZHJwICAgIHgyLCBmZmZmODAw
MDBiMWIxMDAwIDxrYWxsc3ltc190b2tlbl9pbmRleCsweDIwZjA3MD4KZmZmZjgwMDAwYTQ2Y2Iy
ODogICAgICAgOTEwYTgwNDIgICAgICAgIGFkZCAgICAgeDIsIHgyLCAjMHgyYTAKZmZmZjgwMDAw
YTQ2Y2IyYzogICAgICAgOTdmZmYzNDUgICAgICAgIGJsICAgICAgZmZmZjgwMDAwYTQ2OTg0MCA8
X3A5X2RlYnVnPgpmZmZmODAwMDBhNDZjYjMwOiAgICAgICA1MjgwMDA4MCAgICAgICAgbW92ICAg
ICB3MCwgIzB4NCAgICAgICAgICAgICAgICAgICAgICAgIC8vICM0CmZmZmY4MDAwMGE0NmNiMzQ6
ICAgICAgIDk3ODM0ZGUzICAgICAgICBibCAgICAgIGZmZmY4MDAwMDg1NDAyYzAgPF9fdHNhbl9h
dG9taWNfc2lnbmFsX2ZlbmNlPgpmZmZmODAwMDBhNDZjYjM4OiAgICAgICBkNTAzM2FiZiAgICAg
ICAgZG1iICAgICBpc2hzdApmZmZmODAwMDBhNDZjYjNjOiAgICAgICBhYTEzMDNlMCAgICAgICAg
bW92ICAgICB4MCwgeDE5CmZmZmY4MDAwMGE0NmNiNDA6ICAgICAgIDk3ODM1YWMwICAgICAgICBi
bCAgICAgIGZmZmY4MDAwMDg1NDM2NDAgPF9fdHNhbl91bmFsaWduZWRfd3JpdGU0PgpmZmZmODAw
MDBhNDZjYjQ0OiAgICAgICBhYTEzMDNlMCAgICAgICAgbW92ICAgICB4MCwgeDE5CmZmZmY4MDAw
MGE0NmNiNDg6ICAgICAgIGQyODAwMDAzICAgICAgICBtb3YgICAgIHgzLCAjMHgwICAgICAgICAg
ICAgICAgICAgICAgICAgLy8gIzAKZmZmZjgwMDAwYTQ2Y2I0YzogICAgICAgNTI4MDAwMjIgICAg
ICAgIG1vdiAgICAgdzIsICMweDEgICAgICAgICAgICAgICAgICAgICAgICAvLyAjMQpmZmZmODAw
MDBhNDZjYjUwOiAgICAgICA1MjgwMDA2MSAgICAgICAgbW92ICAgICB3MSwgIzB4MyAgICAgICAg
ICAgICAgICAgICAgICAgIC8vICMzCg==
--00000000000008f9c705eebf61a4--
