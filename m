Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBXHY2DXAKGQERKEDVKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 958B4102C44
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 20:02:53 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id j134sf15911388ywb.11
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 11:02:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574190172; cv=pass;
        d=google.com; s=arc-20160816;
        b=MPeeeP+c6qo53L2i1OWDnjJImhcobFc4JuZ52nLiao1e/GdLr0VxfEHWVhdo/LwogP
         aC/rvUq5paaWZHMizV3MKd5H2w6m3BomtjDXcXQphsTqeyDFostKb7579tT3vfeIHF2F
         vnYvMZQY46CaCZsTVP4FxugmqbHTJ4SIr02rDpmqSKRovxJCmbOtT8m9UWNGFRNwPxkz
         ebbpfNa06Ucmkw9TqE+TRd3gQRt7n8LAjp/yxQGoMzcJioVnT/ufnJ7OCsKGGFlPF5Rm
         WSxuf5wrN8zyK+bUfEBhnqBO9PY3XCftdWWQx4lVxOXpwIqa9TyR+p3CTPj3Uch/3Yp6
         9DUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=AIJpSiActzrxFTF+5md06Nc46ieIZd3llyGVLGfT8kM=;
        b=iNhp5mEQ919x7FB0JuMlRJx9nsTNgcFn8hHxfIW4zWA0HurresG6Gn8hgufC/icv6T
         5Pr3cdSp/99D0Q4ck9e9azSo6f8cgzDisx8eln8wN6qNP7mnW5MIjzPSh786F+3ZLL1B
         AeCaklysP7/Pk60ko78ANc9g4x8qw7Dq+KnkBGdR+z0Ej2pvA7GoLPP//r/Ym1ccc2n1
         Pv+V9jXvGN0wSDxul7RbQbqLxaHHLmgNbZJLnhRaSXNmC9QyTNm7zgjq1qBX1wunOvTW
         At/kG71+KiOLPN7Ig+xaOfDRKTqHkqdfma9Yrkno+mmfGiT5BmOSB2LfPg9EF8Itt6GI
         eOUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=sQhEDOK4;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AIJpSiActzrxFTF+5md06Nc46ieIZd3llyGVLGfT8kM=;
        b=HQVhQyyE+WlVJFjh8DHltOHrPkFop6rMnacPTHScwAIuuIS9wXov1tRl3hRH8bxQy/
         YuHW9ZM1bUcdu6Qas3QeuOKQEEmSQjBT7JpZoWKlbvwuNZjZfN36RWGds+zLuEKgMbV/
         7T6Z7nUdnA60sDLb15kIcrG+01yQcF1t+Oqaga+SD02DCNiGvm2V9MXOfeCvDYeAsO9g
         gXAz8t92EOkjEXp2a8pde3ty4IGkahjrVlBddFyk5roTINeTtVxDaiVIznxgE2QayNuz
         M4Q3t8BOEH05dVNR6b6AyVpHyX7B59mfh5s8MaPpbjNHMT0Gg3WB10+OAo/S4V7IYXoF
         N3Ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AIJpSiActzrxFTF+5md06Nc46ieIZd3llyGVLGfT8kM=;
        b=dmv5Mp4im56U3P4802+5RsiDH0tiWz66Bb7tSHCzmno65qk71v4E0CWaZ7EqqjO9x0
         8QaiwIcscd5BXK/4sAPgI0Mr050VHVxrtwYUi0Sl0vUa7QrC2oNc80Rcj8oxTm23ETcI
         I77NQP5DfIHmIwA57QRunVhyll26YnVLB64C217onJcOT200Wxz4XJvs8A0aJeQnP+41
         cKOiQLgzSMYJLt5/rgMERSHudzSWV3SCrRHT2M3BBzQX7h0ni4dqZ1SmIs4CqhBr6ccD
         UqHktVzhppZS7sHLuldCB3gic0h3ZSxdjrygoCDYji0j2n83yv/04xHLkyR+N4oC5l8n
         UNKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU7/UIz8uF8iEyU+p3I9QUK/qxYZo0ZBeb27mK/YPOuFgNkVlXF
	jpRt0gcx5GsnUz6h/tql8I4=
X-Google-Smtp-Source: APXvYqynLzYPblr86zcXfknLsYe6+oxV6k3rZPlWDRORZ5a312d+TDl0XPMBjtISvUSDkTG5A9H2HA==
X-Received: by 2002:a25:580a:: with SMTP id m10mr18887255ybb.10.1574190172197;
        Tue, 19 Nov 2019 11:02:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4114:: with SMTP id o20ls3655635yba.13.gmail; Tue, 19
 Nov 2019 11:02:51 -0800 (PST)
X-Received: by 2002:a25:cccb:: with SMTP id l194mr30308409ybf.449.1574190171684;
        Tue, 19 Nov 2019 11:02:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574190171; cv=none;
        d=google.com; s=arc-20160816;
        b=qaJ/0MAlbDE40aZTV7rWcx0rfWwEcPX5VkWm1g7GC5Uw/ewnRcmd07N4vImz0pO2gj
         rCBAMzlIiMshW7a/KNJji37dCXi0EwywYAp2b4uH56wcYpd2BDN6+mn4gZCisIkFAM6N
         xW0tnGAjRR1Aub0BMq3lhQTVZJCS8RdbtPM0zFCvIu7d3ngiw8vpQVDq6MxTw0LsZ/cX
         a1c/USISbxMFvDj2KjJI8bGLenopQhkFxKi2o0Gly6tzjC7KXqbuEABdfH04K3wmVRi2
         hNOqlwoH0lk/o9BEiaLduFXcmnBsMQ7mAN9La6sANbp0Np+tP9pgVYsiPxPAvbSZnBZ4
         EYBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=nOtlx8W5kFFOHYOOqCInicVcS9VMgxzZJDB6vPZYj8Y=;
        b=gp7ZCL9zNifPyhvuVnLtSaI6sDn2mxaPIOEN2DYWMvnHmGU3ZaS3FgloRGn/PqK3xL
         ovdEmxB+8xV/2DnQfMkRDKK+csx3eq3+2J4qT2nokfOkOPoveXr4ikYTI0lwvSbK+coq
         6rv9rQewwq5hDtdtkRjv0ymFeWaEj75acHFMIi1A7u357Ccz0DGg36YL8ggMuXfYCf4R
         783gln1jPznuHZdK6R3+MhLG5FwOirO/9AlKOiOM5fF+pHXR2zq366LpMyijQdaBw8sc
         KO8aGRc6a6r291ia5zO8nYK0hb+CWKTE6t5GB4EVHITZipdJ6q1mMyos47ycT4CHadck
         lF+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=sQhEDOK4;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id r185si1181293ywe.2.2019.11.19.11.02.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 11:02:51 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id e2so18847414qkn.5
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 11:02:51 -0800 (PST)
X-Received: by 2002:a37:6643:: with SMTP id a64mr31950602qkc.144.1574190171109;
        Tue, 19 Nov 2019 11:02:51 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id w5sm10384776qkf.43.2019.11.19.11.02.49
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Nov 2019 11:02:50 -0800 (PST)
Message-ID: <1574190168.9585.4.camel@lca.pw>
Subject: Re: linux-next: Tree for Nov 19 (kcsan)
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>, Randy Dunlap <rdunlap@infradead.org>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>, Linux Next Mailing List
	 <linux-next@vger.kernel.org>, Linux Kernel Mailing List
	 <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, "Paul E. McKenney" <paulmck@kernel.org>
Date: Tue, 19 Nov 2019 14:02:48 -0500
In-Reply-To: <20191119183407.GA68739@google.com>
References: <20191119194658.39af50d0@canb.auug.org.au>
	 <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
	 <CANpmjNMpnY54kDdGwOPOD84UDf=Fzqtu62ifTds2vZn4t4YigQ@mail.gmail.com>
	 <fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org>
	 <20191119183407.GA68739@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=sQhEDOK4;       spf=pass
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

On Tue, 2019-11-19 at 19:34 +0100, 'Marco Elver' via kasan-dev wrote:
> On Tue, 19 Nov 2019, Randy Dunlap wrote:
>=20
> > On 11/19/19 8:12 AM, Marco Elver wrote:
> > > On Tue, 19 Nov 2019 at 16:11, Randy Dunlap <rdunlap@infradead.org> wr=
ote:
> > > >=20
> > > > On 11/19/19 12:46 AM, Stephen Rothwell wrote:
> > > > > Hi all,
> > > > >=20
> > > > > Changes since 20191118:
> > > > >=20
> > > >=20
> > > > on x86_64:
> > > >=20
> > > > It seems that this function can already be known by the compiler as=
 a
> > > > builtin:
> > > >=20
> > > > ../kernel/kcsan/core.c:619:6: warning: conflicting types for built-=
in function =E2=80=98__tsan_func_exit=E2=80=99 [-Wbuiltin-declaration-misma=
tch]
> > > >  void __tsan_func_exit(void)
> > > >       ^~~~~~~~~~~~~~~~
> > > >=20
> > > >=20
> > > > $ gcc --version
> > > > gcc (SUSE Linux) 7.4.1 20190905 [gcc-7-branch revision 275407]
> > >=20
> > > Interesting. Could you share the .config? So far I haven't been able
> > > to reproduce.
> >=20
> > Sure, it's attached.
>=20
> Thanks, the config did the trick, even for gcc 9.0.0.
>=20
> The problem is CONFIG_UBSAN=3Dy. We haven't explicitly disallowed it like
> with KASAN. In principle there should be nothing wrong with KCSAN+UBSAN.
>=20
> There are 3 options:
> 1. Just disable UBSAN for KCSAN, and also disable KCSAN for UBSAN.
> 2. Restrict the config to not allow combining KCSAN and UBSAN.
> 3. Leave things as-is.
>=20
> Option 1 probably makes most sense, and I'll send a patch for that
> unless there are major objections.

Both option #1 and #2 sounds quite unfortunate, as UBSAN is quite valuable =
for
debugging. Hence, it is desire to make both work at the same time.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1574190168.9585.4.camel%40lca.pw.
