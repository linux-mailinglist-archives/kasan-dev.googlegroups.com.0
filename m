Return-Path: <kasan-dev+bncBDS6HKNKXIEBBS4V5CKQMGQEY7MNPDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A89D55BBD9
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 21:53:49 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-3178996424dsf86679957b3.21
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 12:53:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656359628; cv=pass;
        d=google.com; s=arc-20160816;
        b=lkynB7iRX9cACXSlMLqpD1pRiHp8wqQY4aP5H7fpxhLNYQnclZN5b4GCaWPo+xv7OH
         NfdicvyCHNMTEiHrgQJgu+ixBFaHGVcaOs/t2S28r+2B7a29YnuAD/i1QE1mY86NwzFF
         Huc80TABWnGflSDbSowgt/tefRXUn3HMpS+B6MMj84b7i/hS/JOwntLFYMyv+HHmO+Vb
         rTsY/TmyfvUAXo4+0u2yKEULp4ZR7Hkhw9AlXyuv4CAGbpGMjeIhg+81mfKB8ejUKrkR
         3ueZBGOC9CBGof7qi4dp1LtIUUBqnSascCl90CsVN8pG4la7e1MI1nX6qH2IgGqEBfew
         6YdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=o/01+pJlXO9hLqgjOYcI5rspFYa6pVicwl3MmWnUlmo=;
        b=Z4afo/xMHWXcaslTpw1VBd7PxDKeoztwpRymBa6GMH7Q5O3j2gv/42s7hr1Vxl7f6O
         VJMHa5OgpJJRa8mE/k1JE+8KD+sCJ18hGqbQru8lezSLn2yYFbNqnDJFnDukekOHhpPx
         ckZT8/JeR6cMZl5bb/c2iGyAEO9Bg6xGtK6TMlVsjrc/lqlO65qmve9U6LGDOx//xIa1
         p/4HWnzPEPMHMJXEENCAWCDq6ifqz9NRgN0M+vT9Vbo1iDWqpr/l1wIfwL+rRFt8R9pQ
         2jP990pxPGrPAcVCwHwOo4VNEf3d7KK1dRj/hZ9MEUI9dwQTL/BmFDxTcfI5t2vt+ZDV
         HEOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@networkplumber-org.20210112.gappssmtp.com header.s=20210112 header.b=ryYp2naL;
       spf=pass (google.com: domain of stephen@networkplumber.org designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=stephen@networkplumber.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o/01+pJlXO9hLqgjOYcI5rspFYa6pVicwl3MmWnUlmo=;
        b=i3e9ExTvbFVMLHnRy3EflRZeKSpGdR7UkYfmWV4g08XpHJSLJwTvV7k9lqqyv1gD7M
         /A3LPqTrpimvOCCI92x0Vfnp1SdJEqFGshPaIbsNWh5VG4g2HngP5hS7feSfaNyzR9ep
         SuKdFTM8LBQaRDPTCldq4MjwZG3vH3jBanCf8vdC5TADBsjfKjmWANUOx/IhQVKG+S0+
         qtB1DeREegAWs1JvVH8ZgkwXdXxccIQIv1XZBR76E4w/UH99FNUjF4KVd6LkTnydPP16
         XISJg7yQ+uA9K3s+hMUM/RKZa2f67YcGnXtWY4WJvp5/gfzM4+2KVqv5t69oq0hEohLx
         cVQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=o/01+pJlXO9hLqgjOYcI5rspFYa6pVicwl3MmWnUlmo=;
        b=WnadSmwwPNP1Bz65dpQNtv2jRiS12dQr90hdLYXkdXs2uf03/tUoii7SB3lGqzmueM
         ErcPYEmPmjB8XpKXp+iFGuJPcWFh5+NVqtZx3U/xqnVxTtfdswHM0WZbW7JjpgYqhhiw
         N599+qfzfhlMEXpSrD+VZ/jaTPQoGKi4kxnnELR0r/vn2gamb32wMuKMk3AaGSTGEPIW
         FUB85LtH+HwZzEJe4nkHww4mRCpJqRfF504c4DZKZ4t2R1rzYAsCO2VFsqxAUpNd1y6r
         Rol58yEMmAiBgkDgRffeVRhilRfWazFRp9GdmCmFb/HLPMzs/pEu6ziUeiNpmgH/cwML
         Oh5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9pexuzXsMzLan5ZDZpj63UzR/4ODHh6c2tKYSMKNAHExHQ3iMd
	9JTFePIoUQSDqrpW+WFYCc0=
X-Google-Smtp-Source: AGRyM1ucXTL3LHwxGW5+0UovjBWeYMDA3VyHi4a5XfecI0VciJnNvGxXOIv9RGuxP0GpbDW2AUwtkg==
X-Received: by 2002:a81:4857:0:b0:318:48dd:4165 with SMTP id v84-20020a814857000000b0031848dd4165mr16978112ywa.481.1656359628038;
        Mon, 27 Jun 2022 12:53:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1001:b0:64a:f1d8:396c with SMTP id
 w1-20020a056902100100b0064af1d8396cls20775746ybt.1.gmail; Mon, 27 Jun 2022
 12:53:47 -0700 (PDT)
X-Received: by 2002:a05:6902:10c3:b0:669:3dc2:f014 with SMTP id w3-20020a05690210c300b006693dc2f014mr16726096ybu.159.1656359627479;
        Mon, 27 Jun 2022 12:53:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656359627; cv=none;
        d=google.com; s=arc-20160816;
        b=oldKR3ttHWKGlU1TMRJf4l3drUPcHZ/ERAL0rGdSCQ4MDwrUa7RLnLvmcz4J4vg/F0
         kocdtchmVaaWgQEixhqaHF++DA4aTAXrBHML9XUbOMVnJfNvaKujsbSobinp3kouepDY
         tuqY/uotJ6+cD7qcjRuhm8OvJoKN8q4rOkQ6TLBDkbYzjcK6pYclVrdh5nyyaaXbqQoK
         THco3u/JQ9GAeb3YZjpW0CfoKrPRYPtTQ+uvX0Cr/0cZPlL7F6BZt0dLBpXQFRBP8Fvo
         lmTNdgM9sM9ur1g1lbXM+jiwClRkKmXXSjI9b7cAb7bMk3O7QPNR0p+fEkeunP40nAGN
         Ud0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=k/l4LcE4w+6LYrCo6/Ek+44r04gbnpHm9yyPA0qKR6A=;
        b=jjANFjTrzoOqXF3Z3hMKLNHhR65nWZBXe/V0An6n3GP3f0OrzQ0DAv1cVe08phF5n/
         ZfT5ENnsRaWibmEtRbmqHHBsaCfJqq297ybTMR0HxAqWlVaA6Svq6lR90EhggrzAQsbS
         YhB0y0PJ7vEA8WEGPEATjy3tXtB1utHNZLL8LuAAOqaEmggO0FJ7Dr+wyVUXmRDIvn3z
         9kQ+55eDEmHbPtMkHD+GoziEBQ+6Leply7JOQVOEDqNSGW/NMlhHS2hkgOqVyWJWQUv1
         VMnvQJ0R28iH8r2QZNqBSpqNo1Ju7tF0zvg+JYctFFJOJvd9D0RuV2ty+m+E2rcBzFJa
         KHBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@networkplumber-org.20210112.gappssmtp.com header.s=20210112 header.b=ryYp2naL;
       spf=pass (google.com: domain of stephen@networkplumber.org designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=stephen@networkplumber.org
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id r9-20020a819a09000000b0031332987bdasi478125ywg.3.2022.06.27.12.53.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jun 2022 12:53:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of stephen@networkplumber.org designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id r66so10068216pgr.2
        for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 12:53:47 -0700 (PDT)
X-Received: by 2002:a63:7a5d:0:b0:40c:fcbe:4799 with SMTP id j29-20020a637a5d000000b0040cfcbe4799mr14428539pgn.297.1656359626928;
        Mon, 27 Jun 2022 12:53:46 -0700 (PDT)
Received: from hermes.local (204-195-112-199.wavecable.com. [204.195.112.199])
        by smtp.gmail.com with ESMTPSA id c16-20020a056a00009000b0051c1b445094sm7821510pfj.7.2022.06.27.12.53.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Jun 2022 12:53:46 -0700 (PDT)
Date: Mon, 27 Jun 2022 12:53:43 -0700
From: Stephen Hemminger <stephen@networkplumber.org>
To: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org,
 x86@kernel.org, dm-devel@redhat.com, linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
 kvm@vger.kernel.org, intel-gfx@lists.freedesktop.org,
 dri-devel@lists.freedesktop.org, netdev@vger.kernel.org,
 bpf@vger.kernel.org, linux-btrfs@vger.kernel.org,
 linux-can@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux1394-devel@lists.sourceforge.net, io-uring@vger.kernel.org,
 lvs-devel@vger.kernel.org, linux-mtd@lists.infradead.org,
 kasan-dev@googlegroups.com, linux-mmc@vger.kernel.org,
 nvdimm@lists.linux.dev, netfilter-devel@vger.kernel.org,
 coreteam@netfilter.org, linux-perf-users@vger.kernel.org,
 linux-raid@vger.kernel.org, linux-sctp@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com,
 linux-arm-kernel@lists.infradead.org, linux-scsi@vger.kernel.org,
 target-devel@vger.kernel.org, linux-usb@vger.kernel.org,
 virtualization@lists.linux-foundation.org,
 v9fs-developer@lists.sourceforge.net, linux-rdma@vger.kernel.org,
 alsa-devel@alsa-project.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH][next] treewide: uapi: Replace zero-length arrays with
 flexible-array members
Message-ID: <20220627125343.44e24c41@hermes.local>
In-Reply-To: <20220627180432.GA136081@embeddedor>
References: <20220627180432.GA136081@embeddedor>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: stephen@networkplumber.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@networkplumber-org.20210112.gappssmtp.com header.s=20210112
 header.b=ryYp2naL;       spf=pass (google.com: domain of stephen@networkplumber.org
 designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=stephen@networkplumber.org
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

On Mon, 27 Jun 2022 20:04:32 +0200
"Gustavo A. R. Silva" <gustavoars@kernel.org> wrote:

> There is a regular need in the kernel to provide a way to declare
> having a dynamically sized set of trailing elements in a structure.
> Kernel code should always use =E2=80=9Cflexible array members=E2=80=9D[1]=
 for these
> cases. The older style of one-element or zero-length arrays should
> no longer be used[2].
>=20
> This code was transformed with the help of Coccinelle:
> (linux-5.19-rc2$ spatch --jobs $(getconf _NPROCESSORS_ONLN) --sp-file scr=
ipt.cocci --include-headers --dir . > output.patch)
>=20
> @@
> identifier S, member, array;
> type T1, T2;
> @@
>=20
> struct S {
>   ...
>   T1 member;
>   T2 array[
> - 0
>   ];
> };
>=20
> -fstrict-flex-arrays=3D3 is coming and we need to land these changes
> to prevent issues like these in the short future:
>=20
> ../fs/minix/dir.c:337:3: warning: 'strcpy' will always overflow; destinat=
ion buffer has size 0,
> but the source string has length 2 (including NUL byte) [-Wfortify-source=
]
> 		strcpy(de3->name, ".");
> 		^
>=20
> Since these are all [0] to [] changes, the risk to UAPI is nearly zero. I=
f
> this breaks anything, we can use a union with a new member name.
>=20
> [1] https://en.wikipedia.org/wiki/Flexible_array_member
> [2] https://www.kernel.org/doc/html/v5.16/process/deprecated.html#zero-le=
ngth-and-one-element-arrays
>=20
> Link: https://github.com/KSPP/linux/issues/78
> Build-tested-by: https://lore.kernel.org/lkml/62b675ec.wKX6AOZ6cbE71vtF%2=
5lkp@intel.com/
> Signed-off-by: Gustavo A. R. Silva <gustavoars@kernel.org>

Thanks this fixes warning with gcc-12 in iproute2.
In function =E2=80=98xfrm_algo_parse=E2=80=99,
    inlined from =E2=80=98xfrm_state_modify.constprop=E2=80=99 at xfrm_stat=
e.c:573:5:
xfrm_state.c:162:32: warning: writing 1 byte into a region of size 0 [-Wstr=
ingop-overflow=3D]
  162 |                         buf[j] =3D val;
      |                         ~~~~~~~^~~~~

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220627125343.44e24c41%40hermes.local.
