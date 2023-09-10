Return-Path: <kasan-dev+bncBAABBX6T66TQMGQEQTJSCHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D099799EEC
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Sep 2023 18:08:01 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-d7b9eb73dcdsf3208195276.0
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Sep 2023 09:08:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694362080; cv=pass;
        d=google.com; s=arc-20160816;
        b=ponhhoE09qjYuSXx5jECfqyiLkKimqZKDp2whCCioePX95lUl2lFGMMnf0K37kDQzp
         m3+wmsdpRhvWY+2BGBftgHm6+u8oaOpUdWSZIjx1encLnuCJ9O9r6dmVPvLkEkZWBACg
         ASrnVHgkMl0jMs7TAaOQE6ZWJ1KWFJQx2jvYLM7wj7RyikIVC9+wLis3ZnuQP/rG5Jsc
         IjvduuI2NylOUzKlVRWIwb1I56zpqMjHlK7hALQ37bRn3VdH2Yht6rdAZAWcVeh5mUXM
         eANS42nT5zPz69zz/N1yq2X9RHPx72T6uGYMHRBzrL+5gR5bSLkxXG/QfF/fBJSTU595
         yUyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:dkim-signature;
        bh=dv7dE5sY4EJ+n+UeKRtL4LdNbZE4sLSW6SzIhqb9+9k=;
        fh=cw6EbsTTO+jd0Mffn0MpxpOsh4uW0IfYYXJDZMV1Xa0=;
        b=yOcfxtIY5x5zocbiNfL5D2AsVjtKwHv253iF5p6LlLV3N615fJHK7NdxWpCGWtVrED
         AIqCcfsYo/v/WRuW7i24OnKxbJIED+g4+CJHX1/WBlmJagnPN56VLLzn7+jhSBDVEmzx
         r5rlC+MGz3lnptB1dnYfHCJdLGs4ZhPZ0M4tCA0wOJTIdSOKcwgkw+TDX4xgsaHoO5wn
         S49839I2akKrWSjOOo6FLIcMWTUOz7bjT2eoEDtgCDNSJ1j/SIKn488ZuXlyuJvT4sih
         a6oNe9kjiMZakv31ii+V0BwL8GsOayDNFoQgGqHXO1GSVHW73R0oUkr+nBb8fzjtFZG9
         muAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@xry111.site header.s=default header.b=l1DZFW7Y;
       spf=pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) smtp.mailfrom=xry111@xry111.site;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694362080; x=1694966880; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dv7dE5sY4EJ+n+UeKRtL4LdNbZE4sLSW6SzIhqb9+9k=;
        b=VBFmE1Bxcfurn1OG3byyCJCykybux02+dl2DpkKkyzuxjIJmBZYUycnD85hD2bc/SL
         XGklQIgk8qyiWQuu6w0s4Xsa2Uf0TNwKVuNhlt3O3Fc69eXG3p/aKCMVW5uLJthvj+eL
         fb77+YOqnCQqVhg8vc2RcFQ3ql7gtg8cPtJg/p3q8Dj/G34fUnmZ+a2fMoV+UayMaKj5
         c31X0doj6shrS0vxIpUs9qGrTm/l/CqZZTRyryNg9KxM54eMzjSOGP+wjQjofJQu3W7c
         NStc31LBCjNH/CZwGiYMgU5NPVv6/rT5kJ5l5dh+08apCjxD5BBfx65pphVXl6UtAB5Z
         ugjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694362080; x=1694966880;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dv7dE5sY4EJ+n+UeKRtL4LdNbZE4sLSW6SzIhqb9+9k=;
        b=E4W5KI2QuB2g6n9A4C1QqHqFeRhri8kopKuoY4rX2Gzek7JdpjhdRq4GWmL2QtmTpS
         l/n2pLBo7p77S/CLvxnRe1/4eyyNbJVqGEH52c+XIvjAk4e+wLVDQhHL/jXkbjCkn2Qh
         NdcC5Th9udxbCgvG2WnY+iXOu6yJ98zzXBGo9VThIhdptG529G83V3b6qicNm/d+3mdF
         xJ1P6YOmfbrlkzD7qF4wCmoP5q8GGA5PhNUbDsSFGX2txXr3he7srElglirkbV1k33SD
         QSvnAI8IQHo1HfEEOpLvG1iwHAlspEt4RblHv2hF3vKl+PEkcynV6dmAfYUcnwu/WkDT
         7P9w==
X-Gm-Message-State: AOJu0Yw21k7FhgcYYeNYH1Oqe5rWsalxbavkvsohWJ7iNgZLzgkAGlql
	kCHb9fkW4DlKMgy3FPEhgCw=
X-Google-Smtp-Source: AGHT+IFe2JTS1BqNXE1+IR8x9SYQPI3KQbzCk/oXpp2wOqH1fULR0gc+v4Gl/6jJ4Dl+pOz9Yp2dRg==
X-Received: by 2002:a05:6902:1141:b0:d77:f518:ff59 with SMTP id p1-20020a056902114100b00d77f518ff59mr8462212ybu.11.1694362079715;
        Sun, 10 Sep 2023 09:07:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1141:b0:d05:4fc7:6cd7 with SMTP id
 p1-20020a056902114100b00d054fc76cd7ls862647ybu.0.-pod-prod-04-us; Sun, 10 Sep
 2023 09:07:59 -0700 (PDT)
X-Received: by 2002:a81:490e:0:b0:583:9e6c:eb69 with SMTP id w14-20020a81490e000000b005839e6ceb69mr8077580ywa.42.1694362079060;
        Sun, 10 Sep 2023 09:07:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694362079; cv=none;
        d=google.com; s=arc-20160816;
        b=kuD6s1E7BrHvDlqYXQsKS7IQ5+RKZh4yiVE1Ya/QCs24YgfhZuQDtJmHgNMnQKZQmi
         ljAG5mv47v29HZStFfL/eRiIWjnX8cBw4xsYNJBxfNZrHclqyWjzRTz5AdUB1P56QCE9
         Py3mc4bprAtNXUDNu18Pxmvu3vddEPzWGqoU06/ZRZXksyAcpWj/JRmrzn10wRIxPEBm
         HUJPtsCeF9V/3FlXeakT+joaLxPiAZHVQLefKyxkc4eT2Su+CsKxHxe/DsTMmmNxBE9V
         Db9ptsGjKSSxULJR7dBe0oiu9kuEAyDl9Iehh4CjWy00YqGTuPnvS9rnaITbKGkJe7ux
         euBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=Nxvwr3UyOjCueB1Qh0ByM6tTtpE31cdPxaDGzo0tJ0c=;
        fh=cw6EbsTTO+jd0Mffn0MpxpOsh4uW0IfYYXJDZMV1Xa0=;
        b=HXhQfjt4velwfU8aWuzPE2ZwwdfXkB36lK0pq14LMRPlt9vUkqOfCXsxhldiBtoeA4
         9K6xmcOdQUcSCZjoLd87pk52xgJlBCG692ppegx8Yxfe82cA8zZdZ+Cvh2IvsqTVu9IM
         jMs91yNuy/If+HgmtTXq9JC9TLrFAy8Pg2Wdx2Ad49nxTJa2pq7xZ/JzTSPSlhZ88BhN
         1AkruMSZClPASupwHyyyJ0qDFhUV+9rW64QFh1b1r5iPNDz3KCRMqyIWahfqMEYXB/bm
         pbtaMOsg2Dgal0fgHodAq7E/emXBZitHirFlpyZAwSMeRnkRYlfkjK7DesOkmqoretib
         tPOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@xry111.site header.s=default header.b=l1DZFW7Y;
       spf=pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) smtp.mailfrom=xry111@xry111.site;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
Received: from xry111.site (xry111.site. [89.208.246.23])
        by gmr-mx.google.com with ESMTPS id db18-20020a05690c0dd200b0058cb6211ff8si1086251ywb.4.2023.09.10.09.07.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Sep 2023 09:07:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) client-ip=89.208.246.23;
Received: from [IPv6:240e:358:1101:700:dc73:854d:832e:2] (unknown [IPv6:240e:358:1101:700:dc73:854d:832e:2])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-384) server-digest SHA384)
	(Client did not present a certificate)
	(Authenticated sender: xry111@xry111.site)
	by xry111.site (Postfix) with ESMTPSA id 76A79659C0;
	Sun, 10 Sep 2023 12:07:52 -0400 (EDT)
Message-ID: <ed3d5214b0a84486080993b56c0de45accfe4fce.camel@xry111.site>
Subject: Re: [PATCH 2/2] LoongArch: Allow building with kcov coverage
From: "'Xi Ruoyao' via kasan-dev" <kasan-dev@googlegroups.com>
To: Guenter Roeck <linux@roeck-us.net>, Feiyang Chen
 <chenfeiyang@loongson.cn>
Cc: chenhuacai@kernel.org, dvyukov@google.com, andreyknvl@gmail.com, 
	loongarch@lists.linux.dev, kasan-dev@googlegroups.com, 
	chris.chenfeiyang@gmail.com, loongson-kernel@lists.loongnix.cn
Date: Mon, 11 Sep 2023 00:07:46 +0800
In-Reply-To: <66522279-c933-4952-9a5a-64301074a74a@roeck-us.net>
References: <cover.1688369658.git.chenfeiyang@loongson.cn>
	 <8d10b1220434432dbc089fab8df4e1cca048cd0c.1688369658.git.chenfeiyang@loongson.cn>
	 <66522279-c933-4952-9a5a-64301074a74a@roeck-us.net>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.48.4
MIME-Version: 1.0
X-Original-Sender: xry111@xry111.site
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@xry111.site header.s=default header.b=l1DZFW7Y;       spf=pass
 (google.com: domain of xry111@xry111.site designates 89.208.246.23 as
 permitted sender) smtp.mailfrom=xry111@xry111.site;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
X-Original-From: Xi Ruoyao <xry111@xry111.site>
Reply-To: Xi Ruoyao <xry111@xry111.site>
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

On Sun, 2023-09-10 at 08:51 -0700, Guenter Roeck wrote:
> Hi,
>=20
> On Tue, Jul 04, 2023 at 08:53:32PM +0800, Feiyang Chen wrote:
> > Add ARCH_HAS_KCOV to the LoongArch Kconfig. Also disable
> > instrumentation of vdso.
> >=20
> > Signed-off-by: Feiyang Chen <chenfeiyang@loongson.cn>
>=20
> When trying to build loongarch:allmodconfig, this patch results in
>=20
> Error log:
> In file included from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch64-linu=
x-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/options.h:=
8,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch6=
4-linux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/tm.h=
:46,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch6=
4-linux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/back=
end.h:28,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch6=
4-linux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/gcc-=
plugin.h:30,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 from scripts/gcc-plugins/gcc-common.h:7,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 from scripts/gcc-plugins/latent_entropy_plugin.c:7=
8:
> /opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch64-linux-gnu/bin/../lib/gcc/l=
oongarch64-linux-gnu/12.2.0/plugin/include/config/loongarch/loongarch-opts.=
h:31:10: fatal error: loongarch-def.h: No such file or directory
> =C2=A0=C2=A0 31 | #include "loongarch-def.h"

> for me. I tried with gcc 12.2 / binutils 2.39 and gcc 13.1 / binutils 2.4=
0.

> Reverting the patch or explicitly disabling CONFIG_GCC_PLUGINS fixes
> the problem.
>=20
> What compiler / binutils version combination is needed for this to work,
> or, alternatively, how would I have to configure the compiler ?

Hi Guenter,

This is a GCC bug.  It's fixed in GCC trunk and the fix has been
backported to 12/13 release branches, so GCC 14.1, 13.3, and 12.4 will
contain the fix.

The fix is available at https://gcc.gnu.org/r14-3331, you can apply the
patch building the compiler.

Sorry for the inconvenience.

--=20
Xi Ruoyao <xry111@xry111.site>
School of Aerospace Science and Technology, Xidian University

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ed3d5214b0a84486080993b56c0de45accfe4fce.camel%40xry111.site.
