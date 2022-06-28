Return-Path: <kasan-dev+bncBDPYNU65Q4NRBN5E5GKQMGQETID76KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D98A55BCC7
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:58:34 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id b18-20020aa78ed2000000b0052541d34055sf4520276pfr.23
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 17:58:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656377912; cv=pass;
        d=google.com; s=arc-20160816;
        b=BP1eH+TE+OdpYtT+h1Epiqj5nA4T/vFZ573rsbF2THZ/VNSCHoZTIt7dCoVZ7eZDmO
         WvzlVWViNV3fJiI5ceKGCyfpyJWnuJcoHZh+V1UtQtis+ykQy+10/4g1DQn1ixpyhZQY
         zqcdPk3gs257HiRd29igsxqAYNWkiyHtqpzWN4znAHNwnfXTn8C2koUZWTu17IEme+kY
         KNayc5erERIfQPWGBBRyd1UN4WexXCZQh+2VvstQyl8gjnksC/2nAxILuojntytze4CV
         KjMvRMf6iPVDYdzbx/O4ijr2X9GX1hO+lR2btfIyVxMhNTMJU+v7kqiy80+1IBZrnOJ7
         rqMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KCkQvBhu2zN43Dsa2tHDzLeSAGnr0Iet9tz7LnWOSgM=;
        b=o96EICjDKl5FKQDBRjrbLGpb/YlS+qmrISDK2gCYa7tfLGnkRslVLRlJMlUJKW56LF
         T531prcIJ9TU1yF89ODbCh+bPTtE3+iGS0L+7ddsZF+EYR/cAygZ8XwWyqR0yw/fopVn
         vByPOgl/+CBb6flyDAvEbpp1hlnY8jvC7t49vbL4lpjTpxUvcWYwBRwB5w4uddb32H+f
         urvqPcr+5Rw8JkWtmC9XA5vS9C3zKg4gE4KZd9iXQyW0+xEWY6EBNQOWQH82QqVrNEv1
         ZqILGMokklugNLYbytWys8XDLwMm63VIgwYetsJQf+DbZp6ugj4HFboJ/fOhwVvqg2m4
         2O2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rmtqPrxs;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KCkQvBhu2zN43Dsa2tHDzLeSAGnr0Iet9tz7LnWOSgM=;
        b=hH7tEikLwG5+FfpvYNI3UJm8jVYUZ3gSJs6itZJkclbzK+0QPB0hCuJ9FzPMRpFrSI
         Hdc5xetqDw9xbL54Y0JUIhrypWxk34BCFlXok4rw4pMwVzEU3ZowDSRrtygSy7UXP4Ar
         GY53sA1fat4/r3GvjmO7tzWvQappaP8c7bTqYnnLjO86zvjhBB+DV0wnT3k3NuHtSoFM
         W1X5mme4UXxOHNd8ynES7bhiIOJ7zsKSF9DfTk/uJ5aQ9Nap46S0vvUsm1tXTSZPmVk/
         /NhSc/IIP2eISLwDX7x222izUWb2Ko7L8tW+ZqcopiSsA5mtLZ63HgzKS+Kr6ZjKcIAv
         1Zng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KCkQvBhu2zN43Dsa2tHDzLeSAGnr0Iet9tz7LnWOSgM=;
        b=oYbK9u7otfn3rd7wTaeU9w+YfvtiKI5Z3R0YfjpKbXXYaaEFxj9m1yZoM+gc6IfpF5
         Zfi44DFVd2ofpMJOhFTBGdi4AJIjWY76HhvLfe33ieIxpYzMpdBB8mG1rUP2UTA1NWP4
         M69reEg+fHZO8FCU8FECajU89tWmiFNv6ecT4VI8QSggf0NKmPmi1qvnkrDleuMtKSrF
         k1UnkGOwZrKLmvUS4TpQTdeAR0ALCe9dwCOfuXPzzDvyMY0iZxSbJJU9/Ib85JpAFrk2
         7Z5oER8A/+AoOdqp7u57zaW1axthzpAfCgjp9AAUePHzu+KHaq+A9B+HCl2WPKsRPJtZ
         o/RQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+nZ8EdAqbnNGnDh8qf1+AQcoJoYh4nytH24rdSzBse+hwGckCH
	vDNFQIp94fBn1pOujlBq4nM=
X-Google-Smtp-Source: AGRyM1uVyuWuVeWBi/MPEYJrx3s0MCqC2iPuwst4R9e2Bm/sJGK6dw8mOY/7Wf9WbKxtFAk4vX0Wbw==
X-Received: by 2002:a17:902:e850:b0:16a:209a:971a with SMTP id t16-20020a170902e85000b0016a209a971amr2247334plg.163.1656377911967;
        Mon, 27 Jun 2022 17:58:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2ccb:0:b0:411:51f1:84a8 with SMTP id s194-20020a632ccb000000b0041151f184a8ls564530pgs.10.gmail;
 Mon, 27 Jun 2022 17:58:31 -0700 (PDT)
X-Received: by 2002:a63:91c1:0:b0:40d:33cb:3d57 with SMTP id l184-20020a6391c1000000b0040d33cb3d57mr15536475pge.10.1656377911292;
        Mon, 27 Jun 2022 17:58:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656377911; cv=none;
        d=google.com; s=arc-20160816;
        b=R799/r8v7Pr/IxnBEQ+h9tiche5OtnP53OqOy2Fg6fWW92OJSsLEMQEpTpIPqduOHP
         OH6WCHtotTAmi/WJUk20U4KyAODrjYhUAQHinIi0f7bWyqUzXKULbCa4/ukmf3tOQ8xv
         pOjN1LX29ENQT5rRllzTADYMzo65yAbDsNYblVJiFGCbkD00uBzBGtRKCG8dvHCggHAe
         IsTN/Z8YxBTbZPnhIvYkJM5fdxheM8+RjCeKz0fgw3xUWlpfzK4jMnCl6BEwlkXWC8qm
         KIPbVJvficVQCISFOR2qCTmq2/ap17Q3RbYMLhk9DTLXBkwJtLwifyaiTEwzFuGKfg1/
         COCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=FnuEByhlLOETaCt9p00l15nxUzK4cS1FJXHJqiDfAkQ=;
        b=as0pQofS8C/zrke9SwR5s08LLl3A9gFefvuskHYhpEjgcy/0MA1fOUQr3Qo9bB6jzE
         fvXUsqVqeR99ECBU50sziK8ZHatH5wphPh29gVikBftWDpCe/dDqjYRVseOhtPdif/33
         46fnGUaoxtRCAqbFH2YQt2XziTRPff2QADMh2kBKgwbXpVLfclwZUAwYlcioObPp46iv
         p5HzqNT0/sFP6NDq/UoHJsNE/h4Lq5MZRf/OqEbmXYPWG62Bzn6OG4pELpm5tiQU1rV4
         My3g1qcNfmD5qxKkRukITiqGehNieloOlVOW+g2XN01WlLAChyHh0S+BwkBnuvh6SM8w
         +/+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rmtqPrxs;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id lr18-20020a17090b4b9200b001ecb6b8678fsi577043pjb.2.2022.06.27.17.58.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jun 2022 17:58:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of gustavoars@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B6EC2616BE;
	Tue, 28 Jun 2022 00:58:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BBEABC341C8;
	Tue, 28 Jun 2022 00:58:27 +0000 (UTC)
Date: Tue, 28 Jun 2022 02:58:25 +0200
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
Message-ID: <20220628005825.GA161566@embeddedor>
References: <20220627180432.GA136081@embeddedor>
 <6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637@iogearbox.net>
 <20220628004052.GM23621@ziepe.ca>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20220628004052.GM23621@ziepe.ca>
X-Original-Sender: gustavoars@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rmtqPrxs;       spf=pass
 (google.com: domain of gustavoars@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=gustavoars@kernel.org;       dmarc=pass
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

On Mon, Jun 27, 2022 at 09:40:52PM -0300, Jason Gunthorpe wrote:
> On Mon, Jun 27, 2022 at 08:27:37PM +0200, Daniel Borkmann wrote:
> > On 6/27/22 8:04 PM, Gustavo A. R. Silva wrote:
> > > There is a regular need in the kernel to provide a way to declare
> > > having a dynamically sized set of trailing elements in a structure.
> > > Kernel code should always use =E2=80=9Cflexible array members=E2=80=
=9D[1] for these
> > > cases. The older style of one-element or zero-length arrays should
> > > no longer be used[2].
> > >=20
> > > This code was transformed with the help of Coccinelle:
> > > (linux-5.19-rc2$ spatch --jobs $(getconf _NPROCESSORS_ONLN) --sp-file=
 script.cocci --include-headers --dir . > output.patch)
> > >=20
> > > @@
> > > identifier S, member, array;
> > > type T1, T2;
> > > @@
> > >=20
> > > struct S {
> > >    ...
> > >    T1 member;
> > >    T2 array[
> > > - 0
> > >    ];
> > > };
> > >=20
> > > -fstrict-flex-arrays=3D3 is coming and we need to land these changes
> > > to prevent issues like these in the short future:
> > >=20
> > > ../fs/minix/dir.c:337:3: warning: 'strcpy' will always overflow; dest=
ination buffer has size 0,
> > > but the source string has length 2 (including NUL byte) [-Wfortify-so=
urce]
> > > 		strcpy(de3->name, ".");
> > > 		^
> > >=20
> > > Since these are all [0] to [] changes, the risk to UAPI is nearly zer=
o. If
> > > this breaks anything, we can use a union with a new member name.
> > >=20
> > > [1] https://en.wikipedia.org/wiki/Flexible_array_member
> > > [2] https://www.kernel.org/doc/html/v5.16/process/deprecated.html#zer=
o-length-and-one-element-arrays
> > >=20
> > > Link: https://github.com/KSPP/linux/issues/78
> > > Build-tested-by: https://lore.kernel.org/lkml/62b675ec.wKX6AOZ6cbE71v=
tF%25lkp@intel.com/
> > > Signed-off-by: Gustavo A. R. Silva <gustavoars@kernel.org>
> > > ---
> > > Hi all!
> > >=20
> > > JFYI: I'm adding this to my -next tree. :)
> >=20
> > Fyi, this breaks BPF CI:
> >=20
> > https://github.com/kernel-patches/bpf/runs/7078719372?check_suite_focus=
=3Dtrue
> >=20
> >   [...]
> >   progs/map_ptr_kern.c:314:26: error: field 'trie_key' with variable si=
zed type 'struct bpf_lpm_trie_key' not at the end of a struct or class is a=
 GNU extension [-Werror,-Wgnu-variable-sized-type-not-at-end]
> >           struct bpf_lpm_trie_key trie_key;
> >                                   ^
>=20
> This will break the rdma-core userspace as well, with a similar
> error:
>=20
> /usr/bin/clang-13 -DVERBS_DEBUG -Dibverbs_EXPORTS -Iinclude -I/usr/includ=
e/libnl3 -I/usr/include/drm -g -O2 -fdebug-prefix-map=3D/__w/1/s=3D. -fstac=
k-protector-strong -Wformat -Werror=3Dformat-security -Wdate-time -D_FORTIF=
Y_SOURCE=3D2 -Wmissing-prototypes -Wmissing-declarations -Wwrite-strings -W=
format=3D2 -Wcast-function-type -Wformat-nonliteral -Wdate-time -Wnested-ex=
terns -Wshadow -Wstrict-prototypes -Wold-style-definition -Werror -Wredunda=
nt-decls -g -fPIC   -std=3Dgnu11 -MD -MT libibverbs/CMakeFiles/ibverbs.dir/=
cmd_flow.c.o -MF libibverbs/CMakeFiles/ibverbs.dir/cmd_flow.c.o.d -o libibv=
erbs/CMakeFiles/ibverbs.dir/cmd_flow.c.o   -c ../libibverbs/cmd_flow.c
> In file included from ../libibverbs/cmd_flow.c:33:
> In file included from include/infiniband/cmd_write.h:36:
> In file included from include/infiniband/cmd_ioctl.h:41:
> In file included from include/infiniband/verbs.h:48:
> In file included from include/infiniband/verbs_api.h:66:
> In file included from include/infiniband/ib_user_ioctl_verbs.h:38:
> include/rdma/ib_user_verbs.h:436:34: error: field 'base' with variable si=
zed type 'struct ib_uverbs_create_cq_resp' not at the end of a struct or cl=
ass is a GNU extension [-Werror,-Wgnu-variable-sized-type-not-at-end]
>         struct ib_uverbs_create_cq_resp base;
>                                         ^
> include/rdma/ib_user_verbs.h:644:34: error: field 'base' with variable si=
zed type 'struct ib_uverbs_create_qp_resp' not at the end of a struct or cl=
ass is a GNU extension [-Werror,-Wgnu-variable-sized-type-not-at-end]
>         struct ib_uverbs_create_qp_resp base;
>=20
> Which is why I gave up trying to change these..
>=20
> Though maybe we could just switch off -Wgnu-variable-sized-type-not-at-en=
d  during configuration ?

No. I think now we can easily workaround these sorts of problems with
something like this:

	struct flex {
		any_type any_member;
		union {
			type array[0];
			__DECLARE_FLEX_ARRAY(type, array_flex);
		};
	};

and use array_flex in kernel-space.

The same for the one-elment arrays in UAPI:

        struct flex {
                any_type any_member;
                union {
                        type array[1];
                        __DECLARE_FLEX_ARRAY(type, array_flex);
                };
        };

I'll use the idiom above to resolve all these warnings in a follow-up
patch. :)

Thanks
--
Gustavo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220628005825.GA161566%40embeddedor.
