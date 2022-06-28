Return-Path: <kasan-dev+bncBDPYNU65Q4NRBMGL5GKQMGQEBJQKJ5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2110755BD56
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 04:21:38 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id p10-20020a631e4a000000b0040d2af22a74sf5922134pgm.5
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 19:21:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656382896; cv=pass;
        d=google.com; s=arc-20160816;
        b=TTqhvGiDduFnQVTv8k861fjgleGNj8Iw3i4a+ZU1UiNc+39UY4GtER1vOzsSj88zse
         +mz1bZzaPnFxT4ZgJQgLqobgzam5FER2I1Bd8G0kFC6UF2s1PX1svMJ3vXUY0RdgMaZJ
         AzJ+XG5WAGYPVhxyY9IQfD0uUhqK+2Y06Uwr42aofTSneVW9gbfTCXpYRTvqDzQQpiAi
         Gk1811bkF+VAqFK/IuMj+W8DBbe2wyIw/Su/oc0qCp54fk85AOOBywgG8IpDuDs2v0N4
         I0sGO9l7bMMwHlQxyBW0xeSdkzZnQ+4a0kExhWq9ugpdGUK24c4yPRstZYc2rqG5u5qi
         rHpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ucronO4yrDFQ/JGuykEel5fvZ9JqhS2nHPAqtZ8N0xw=;
        b=sVjhKugz2yyQ9/+mRDCadEdBG7jxvEGyrc5wEX9UH61M4otynBR0L2YHJfaKr9NspH
         F0BTd/VXhyvLKEMhRnU46BB/zIm/Lw6pUbzohUCEEwUYjXG3xjQE2QmaVKt47JTf8tn1
         MCVsJXk9ZryRlL5wQRmW0Cy5GsGhapeGsjis2Ybno7zjM96BcqDnwoqNlPlLk1t2PXWD
         OFrMTURreXa7CGbY3D5G2uNFlxRhhyhaUjlIsWPGP8/JFcVzDL56feMng84V7qMxrFpf
         4FMBa3A3Nyu2sRMFWQ0Un/iFi14SQBoEnTtMj+9TduTGxcX7Zw1lW25GGZ6ucMcoblhW
         CEXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GyqsByaD;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ucronO4yrDFQ/JGuykEel5fvZ9JqhS2nHPAqtZ8N0xw=;
        b=WRB7S2SAqi6gY1IAn/mjxfs8/ALSSLbx/GE5wBcBVn4ZqmWDxPtliYY5eOJcYiaf+S
         6MUsBn+iIcgy05IrYZ/JT0pqcuLkoyNhnKhXLpbUOBGy/7TzCcA7GSzPoE+DGkCnj7gI
         1FjtP3/2sqKmv4aDAlllrxtki2jdF3mn9nLZiSHVBU7Ff8y+noGhw+DpqAdWB9gZlECd
         KUvPSgXh2qkJBiYiJ/Dmze/2kY6k7G8Li0qEkqgbblLvvQk6OCVYh7rCnQ3t4h9SHTWR
         9NjvYsrTqCYanSA0CuAkcUaQ7Hfs5k8SpzU8efu6ktF5XF4heyeALMMwZAq3a2QfO9Dr
         rT8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ucronO4yrDFQ/JGuykEel5fvZ9JqhS2nHPAqtZ8N0xw=;
        b=ycKIifff8b/SgJakHgdhlyLEnxzVjrRVZBCETYf7IcQdU0QbiyjdefcAUHnWnEkO23
         9V7bNpzJBwoZwwzSGs68gvCqI2dLo93juZtOyglEYrMFQRS3kgq0BqZrYRUp7qSTrpVx
         RfdtOfmHVrfkCtb1XWF6K8nrqqUxAbqIFgEAYOiM3eAcsUN/BaSSTyCbvRmy6tpmgeV1
         4BluKOEGjJFtWaKW61OI0OhS11dvMhfQI4GY+AF1PaPqaSiaN75uSf4yalMenLxgL1uK
         oqeivIPGEtT3u3X8gKTTTJ2f+VyvjJs22qi+zC8OwmdEZJQakYa1uT3XOJMwgT1//sRI
         TH/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+1b0DBrDYyGxtbkWUgV23bbz8wC/7Gd8kAvnoG5DGJeAJdYz1F
	tcQR5BPDnE0htkCQzNMavIg=
X-Google-Smtp-Source: AGRyM1ufXVvZDLuh9OCYNPOOHJ2tnAmpYwSzrZ3PY7aN61xktoDsA8ys+z9INI9DaEd95P2NQt8ejw==
X-Received: by 2002:a63:b105:0:b0:3fd:a875:d16 with SMTP id r5-20020a63b105000000b003fda8750d16mr15363433pgf.209.1656382896478;
        Mon, 27 Jun 2022 19:21:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:eb11:b0:1ed:22f7:5bc6 with SMTP id
 j17-20020a17090aeb1100b001ed22f75bc6ls6562317pjz.0.gmail; Mon, 27 Jun 2022
 19:21:35 -0700 (PDT)
X-Received: by 2002:a17:903:41d0:b0:16a:55e0:6c3d with SMTP id u16-20020a17090341d000b0016a55e06c3dmr2579850ple.21.1656382895648;
        Mon, 27 Jun 2022 19:21:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656382895; cv=none;
        d=google.com; s=arc-20160816;
        b=eZbUdjpudEyhB1yd3E2oGvWjE6j1xEp68TWgO5ztxdXWYt63/a5JciBIpXRsaoRTMG
         VVxVxNh+6E28aHjG5vkchdpxc2BBLW7UzkCM3VWzjGo/gxTCMfTwpBCEs3VVaD37KMCQ
         yYiVRPdV/fiI98rILziTvFTb/nHqurhLt4I25E1LGykUhdmul+8qjwBBWt8+78KX6IXN
         UCHOFmpQfjdsvAZ/jPZIEL/RPdq5BF/4cApkQC1tIiyWrW5n91xA2ScpnOESc4AuNo4b
         55FFtiNd5NSDBbTHWEUWLPQYw1NR2kyIpeyA8eCmfz+mkHLjE1/HabjWAn2UleuHCZVz
         7Ajw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ulqk+cEaNXHl50r0UfdEglq/v3UovGtRCwIRozCeJc8=;
        b=sNcI7x/uSHI6cLIw+83o5idzgAYYNP/LO+ygDHsO/NTGnBLDA0vEDWtwcA9PrRgJYc
         u7zCNA955oUvtGkTl+HueFv2EIzIZKMWqnVezLltgmYcQqmOvfqdgwJVxO3GYVoN14Y4
         gnGN+Lqxzm5V9yDnhPQsTdW+T6aMOA/AHKKysTz0Kw1gbkKOj0dr4X2kZyWy2pKA44EM
         gHgEO/lH0Smfy6Ed6+zNLNPuoLpBqu0TtyoRxkyrUcetoluOrDssvvs/YcVHY1dW7oWN
         uX8CSLqbA5WIQRxc7zxFM5mdWef4aVcaz7r3OWYm/g9fJ2saeBT5khUwnKYx2x7xII8R
         +BLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GyqsByaD;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id s1-20020a17090302c100b0016a0397a608si437641plk.7.2022.06.27.19.21.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jun 2022 19:21:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 11460617BC;
	Tue, 28 Jun 2022 02:21:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F3298C341CB;
	Tue, 28 Jun 2022 02:21:31 +0000 (UTC)
Date: Tue, 28 Jun 2022 04:21:29 +0200
From: "Gustavo A. R. Silva" <gustavoars@kernel.org>
To: Jason Gunthorpe <jgg@ziepe.ca>
Cc: Daniel Borkmann <daniel@iogearbox.net>,
	Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org,
	x86@kernel.org, dm-devel@redhat.com,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	linux-s390@vger.kernel.org, kvm@vger.kernel.org,
	intel-gfx@lists.freedesktop.org, dri-devel@lists.freedesktop.org,
	netdev@vger.kernel.org, bpf@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-can@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
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
Message-ID: <20220628022129.GA8452@embeddedor>
References: <20220627180432.GA136081@embeddedor>
 <6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637@iogearbox.net>
 <20220628004052.GM23621@ziepe.ca>
 <20220628005825.GA161566@embeddedor>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20220628005825.GA161566@embeddedor>
X-Original-Sender: gustavoars@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GyqsByaD;       spf=pass
 (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jun 28, 2022 at 02:58:25AM +0200, Gustavo A. R. Silva wrote:
> On Mon, Jun 27, 2022 at 09:40:52PM -0300, Jason Gunthorpe wrote:
> > On Mon, Jun 27, 2022 at 08:27:37PM +0200, Daniel Borkmann wrote:
> > > On 6/27/22 8:04 PM, Gustavo A. R. Silva wrote:
> > > > There is a regular need in the kernel to provide a way to declare
> > > > having a dynamically sized set of trailing elements in a structure.
> > > > Kernel code should always use =E2=80=9Cflexible array members=E2=80=
=9D[1] for these
> > > > cases. The older style of one-element or zero-length arrays should
> > > > no longer be used[2].
> > > >=20
> > > > This code was transformed with the help of Coccinelle:
> > > > (linux-5.19-rc2$ spatch --jobs $(getconf _NPROCESSORS_ONLN) --sp-fi=
le script.cocci --include-headers --dir . > output.patch)
> > > >=20
> > > > @@
> > > > identifier S, member, array;
> > > > type T1, T2;
> > > > @@
> > > >=20
> > > > struct S {
> > > >    ...
> > > >    T1 member;
> > > >    T2 array[
> > > > - 0
> > > >    ];
> > > > };
> > > >=20
> > > > -fstrict-flex-arrays=3D3 is coming and we need to land these change=
s
> > > > to prevent issues like these in the short future:
> > > >=20
> > > > ../fs/minix/dir.c:337:3: warning: 'strcpy' will always overflow; de=
stination buffer has size 0,
> > > > but the source string has length 2 (including NUL byte) [-Wfortify-=
source]
> > > > 		strcpy(de3->name, ".");
> > > > 		^
> > > >=20
> > > > Since these are all [0] to [] changes, the risk to UAPI is nearly z=
ero. If
> > > > this breaks anything, we can use a union with a new member name.
> > > >=20
> > > > [1] https://en.wikipedia.org/wiki/Flexible_array_member
> > > > [2] https://www.kernel.org/doc/html/v5.16/process/deprecated.html#z=
ero-length-and-one-element-arrays
> > > >=20
> > > > Link: https://github.com/KSPP/linux/issues/78
> > > > Build-tested-by: https://lore.kernel.org/lkml/62b675ec.wKX6AOZ6cbE7=
1vtF%25lkp@intel.com/
> > > > Signed-off-by: Gustavo A. R. Silva <gustavoars@kernel.org>
> > > > ---
> > > > Hi all!
> > > >=20
> > > > JFYI: I'm adding this to my -next tree. :)
> > >=20
> > > Fyi, this breaks BPF CI:
> > >=20
> > > https://github.com/kernel-patches/bpf/runs/7078719372?check_suite_foc=
us=3Dtrue
> > >=20
> > >   [...]
> > >   progs/map_ptr_kern.c:314:26: error: field 'trie_key' with variable =
sized type 'struct bpf_lpm_trie_key' not at the end of a struct or class is=
 a GNU extension [-Werror,-Wgnu-variable-sized-type-not-at-end]
> > >           struct bpf_lpm_trie_key trie_key;
> > >                                   ^
> >=20
> > This will break the rdma-core userspace as well, with a similar
> > error:
> >=20
> > /usr/bin/clang-13 -DVERBS_DEBUG -Dibverbs_EXPORTS -Iinclude -I/usr/incl=
ude/libnl3 -I/usr/include/drm -g -O2 -fdebug-prefix-map=3D/__w/1/s=3D. -fst=
ack-protector-strong -Wformat -Werror=3Dformat-security -Wdate-time -D_FORT=
IFY_SOURCE=3D2 -Wmissing-prototypes -Wmissing-declarations -Wwrite-strings =
-Wformat=3D2 -Wcast-function-type -Wformat-nonliteral -Wdate-time -Wnested-=
externs -Wshadow -Wstrict-prototypes -Wold-style-definition -Werror -Wredun=
dant-decls -g -fPIC   -std=3Dgnu11 -MD -MT libibverbs/CMakeFiles/ibverbs.di=
r/cmd_flow.c.o -MF libibverbs/CMakeFiles/ibverbs.dir/cmd_flow.c.o.d -o libi=
bverbs/CMakeFiles/ibverbs.dir/cmd_flow.c.o   -c ../libibverbs/cmd_flow.c
> > In file included from ../libibverbs/cmd_flow.c:33:
> > In file included from include/infiniband/cmd_write.h:36:
> > In file included from include/infiniband/cmd_ioctl.h:41:
> > In file included from include/infiniband/verbs.h:48:
> > In file included from include/infiniband/verbs_api.h:66:
> > In file included from include/infiniband/ib_user_ioctl_verbs.h:38:
> > include/rdma/ib_user_verbs.h:436:34: error: field 'base' with variable =
sized type 'struct ib_uverbs_create_cq_resp' not at the end of a struct or =
class is a GNU extension [-Werror,-Wgnu-variable-sized-type-not-at-end]
> >         struct ib_uverbs_create_cq_resp base;
> >                                         ^
> > include/rdma/ib_user_verbs.h:644:34: error: field 'base' with variable =
sized type 'struct ib_uverbs_create_qp_resp' not at the end of a struct or =
class is a GNU extension [-Werror,-Wgnu-variable-sized-type-not-at-end]
> >         struct ib_uverbs_create_qp_resp base;
> >=20
> > Which is why I gave up trying to change these..
> >=20
> > Though maybe we could just switch off -Wgnu-variable-sized-type-not-at-=
end  during configuration ?
>=20
> No. I think now we can easily workaround these sorts of problems with
> something like this:
>=20
> 	struct flex {
> 		any_type any_member;
> 		union {
> 			type array[0];
> 			__DECLARE_FLEX_ARRAY(type, array_flex);
> 		};
> 	};

Mmmh... nope; this doesn't work[1].

We need to think in a different strategy.

--
Gustavo

[1] https://godbolt.org/z/av79Pqbfz

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220628022129.GA8452%40embeddedor.
