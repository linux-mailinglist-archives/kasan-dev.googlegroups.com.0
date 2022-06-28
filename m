Return-Path: <kasan-dev+bncBCUO3AHUWUIRBF445GKQMGQEWG72OBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id DE9C655BCBC
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:40:56 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-31814f7654dsf90503167b3.15
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 17:40:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656376856; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uujl1wH5VIH0uWjmI/LEl08gejTBBoQV2wNBsBmeHF0TJYKu90VlFu5QxTziURy0mT
         unHDU4WFLIxxvEFYaIfgQb21Chv6NCFyMde6fHqH4S3oLKn+dGnCIUCjXFU23FlFRtV2
         ALnWyGOt0NEte3B7ZQzdByg9z4c8YZ16mtXhSMc4dURpEdl9ko2KFc9sceDFWRW73L29
         wb9BahC9aq6wfI0H20V4o0i6x+X3tt5pZWooVxuwRIhVtMUbpslMIO0wM4F9qToAeRJ+
         BcYPjtOLW8U5CWyfyQWdkWMFXe+XSx6lxSmYSNZK7pgLycuGeid5rO1qmsO21cceQ2rj
         A7pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1myvbqNc/O78snpDyJxDeAcb4FuG0sMypXMpyJr6IcM=;
        b=0q5bTFkKXGglXEgoZxtMnKXvp2J47T7f2Texilcao60O7cfayprq7wB1Fw97pGanTi
         FRUWUf6+aKaMhmAJr8tW/jHSIugAY/oV5CTCjoooC0Cmw5mqQVaYZbzDsnnwx2e5mR+y
         HGPMzLxMI/75aoLsyZdmrsMiExScSVXuy9oFJIIrcJGf08V1NUOZdaGOapY9c4tpfrXW
         NUDyVQ/PiQ0nmj0CzVa7nswbV2GM3RfDTS5ZUzBrw8d62InLTREeWvGb8G9BqTL6o89F
         N4rsMZ19QVlcd3YQRa837+EgviDWMWAvvFSyfK9gNa/WDYu32JShwjZ/pkn0ahKVFu3C
         P0qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=QGfGz2Xe;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=jgg@ziepe.ca
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1myvbqNc/O78snpDyJxDeAcb4FuG0sMypXMpyJr6IcM=;
        b=XZIF0Er2/M1rOKmHIc9c2phdnqb3as86JjUs7RvAPFkZNtG448KTYdYfTPHJpV04gF
         pokN32GdM4pe1W7Cz0GY13A7jNwR6i8QTbxYIzZjYsUiv10frI7/dQm79pJFQ5u8umdq
         hf8t0NuWFmLX7ODzMGiWU31I/FcQiObZMyRDKPBow9pV9iHM38JsnyE5ThPGiOPusxOa
         eTf9pgjSW6aDGw1/Xr3L8pmWYMQ0/1EmD49/8Upe8m3RewnDxP9TrjBhEP2LouHU4kaV
         sUnEG/CsWg0TNXgLszucStDpPsgQg7tYKpFEMnajAiORtTYNwRht+dNObytet/sjdqdo
         nV0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1myvbqNc/O78snpDyJxDeAcb4FuG0sMypXMpyJr6IcM=;
        b=E7xKlzH/RMZax8RBE5kHm8n1+a9NLRDljjuqOHyBKZYio6jk7VKM2kbGwmUgBRpPaL
         yCV/4k7IGrYZb4GccJIgNFRukyUARhjEaylBiLEvA3YPhT6NlgFjBpkj/Xlud2vV2sll
         +TIoMU8jptRDbEVVN5qQaqOPHeTX5tAVzjc+11v0lONrlyMCAN6RPECUY3jhk9a2h++L
         ajHtlsCtXxrlDVsgOfXqK10BVCAhKPXNzR01AssarfOPn0iIulw2KgPDUHl277EaicyD
         iCNtQxhItNZ9W1B28DHrmHcPRI2bSaWiAWMMqhvqfE/ix2HaaQkI5s3VmVDDK0B8n3N4
         8etw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+qBSRXW22qz1Q50FHBEcwbmI67X5udahtILxkVDqqXlGR9d3U/
	rSxud1m8wJzKtmkrzpcptgI=
X-Google-Smtp-Source: AGRyM1vryyXF5/Nkbyv4WlSuDmk3L0wkCahddplShJIlSB+a7uRb7msPi1uSdBs4YRAe2k3ZCH3YJg==
X-Received: by 2002:a81:101:0:b0:314:5477:aae0 with SMTP id 1-20020a810101000000b003145477aae0mr18565026ywb.253.1656376855926;
        Mon, 27 Jun 2022 17:40:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:be54:0:b0:668:a643:5b48 with SMTP id d20-20020a25be54000000b00668a6435b48ls20778938ybm.7.gmail;
 Mon, 27 Jun 2022 17:40:55 -0700 (PDT)
X-Received: by 2002:a05:6902:100d:b0:66d:1ccf:a5e with SMTP id w13-20020a056902100d00b0066d1ccf0a5emr2750728ybt.340.1656376855085;
        Mon, 27 Jun 2022 17:40:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656376855; cv=none;
        d=google.com; s=arc-20160816;
        b=pSzIcpXy6sJhkiX2vhP6qEBqpCg8asPgfwhsExB0T98I6mcsLlQMdl3PrFOPsIA38Y
         4BfVZx5PTP5/YsMyY2OAhZWSO2pH6m6L1AgDEaulhzmIxDFCjgJubvn4FIDM3vJ+4hKS
         OHyxqYUmBGLQy7UNOfGLDRh0fIeSwO5BasJcEY91cKQPKfTfsEZBxMhTXap09t+eG/6I
         +Czwt2St4hLPY6lsk1bKGUMGLI4+WPEYeBXJRf63dOx1xzOJZ9eykL9Ei4jPnNM94rwD
         vXr25aCzoAVRwJU56nAx9wUA0gkN2mG16a2/1K+LQfwXHJA4r7WwzlUHSfRoCVHvL2t0
         fKRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=nrCjPCGAs4MTUiLBt7Ijf/MJPuIyH6lM8yqPhdyhJD8=;
        b=WS205hrPX/2xBCwILidqnhyyofDdLvSe1v9jQywJ2Z/aDuO/Q28dZtGWqcQ0pzEP4J
         87NZnaGtMIgdZoWgX2gmfUABVK5oPmpoTqmfATPXhnb6UYoOqvcFfOdDqd2uAOlw5pFQ
         kTc8MF1pMvFMRMhKMAjmjmuDPme9YOHvRGoHQk3yJ5ReicLndKamGRjM2Quw2VPLROtT
         0hwSbUVzIVKn1+Mh8s4dXPwbpx+hSzw7GjNw9CoP0nJbyaKMEBOEXQNiYkiSROe6OYMu
         NUy9GVb+ir2AHmdFyfRUh5/b619AuNpTBeGOMlYyRIvRsuJ20zmzkUfmBf098uNrZesJ
         AYJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=QGfGz2Xe;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=jgg@ziepe.ca
Received: from mail-qk1-x732.google.com (mail-qk1-x732.google.com. [2607:f8b0:4864:20::732])
        by gmr-mx.google.com with ESMTPS id w67-20020a25df46000000b0066ccd85e4b8si213246ybg.1.2022.06.27.17.40.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jun 2022 17:40:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::732 as permitted sender) client-ip=2607:f8b0:4864:20::732;
Received: by mail-qk1-x732.google.com with SMTP id n10so5147648qkn.10
        for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 17:40:55 -0700 (PDT)
X-Received: by 2002:a05:620a:1450:b0:6af:1999:5f4c with SMTP id i16-20020a05620a145000b006af19995f4cmr7538467qkl.301.1656376854703;
        Mon, 27 Jun 2022 17:40:54 -0700 (PDT)
Received: from ziepe.ca (hlfxns017vw-142-162-113-129.dhcp-dynamic.fibreop.ns.bellaliant.net. [142.162.113.129])
        by smtp.gmail.com with ESMTPSA id x11-20020a05620a448b00b006a768c699adsm10335849qkp.125.2022.06.27.17.40.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Jun 2022 17:40:53 -0700 (PDT)
Received: from jgg by mlx with local (Exim 4.94)
	(envelope-from <jgg@ziepe.ca>)
	id 1o5zHg-002iu4-9Z; Mon, 27 Jun 2022 21:40:52 -0300
Date: Mon, 27 Jun 2022 21:40:52 -0300
From: Jason Gunthorpe <jgg@ziepe.ca>
To: Daniel Borkmann <daniel@iogearbox.net>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>,
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
Message-ID: <20220628004052.GM23621@ziepe.ca>
References: <20220627180432.GA136081@embeddedor>
 <6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637@iogearbox.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637@iogearbox.net>
X-Original-Sender: jgg@ziepe.ca
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ziepe.ca header.s=google header.b=QGfGz2Xe;       spf=pass
 (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::732 as
 permitted sender) smtp.mailfrom=jgg@ziepe.ca
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

On Mon, Jun 27, 2022 at 08:27:37PM +0200, Daniel Borkmann wrote:
> On 6/27/22 8:04 PM, Gustavo A. R. Silva wrote:
> > There is a regular need in the kernel to provide a way to declare
> > having a dynamically sized set of trailing elements in a structure.
> > Kernel code should always use =E2=80=9Cflexible array members=E2=80=9D[=
1] for these
> > cases. The older style of one-element or zero-length arrays should
> > no longer be used[2].
> >=20
> > This code was transformed with the help of Coccinelle:
> > (linux-5.19-rc2$ spatch --jobs $(getconf _NPROCESSORS_ONLN) --sp-file s=
cript.cocci --include-headers --dir . > output.patch)
> >=20
> > @@
> > identifier S, member, array;
> > type T1, T2;
> > @@
> >=20
> > struct S {
> >    ...
> >    T1 member;
> >    T2 array[
> > - 0
> >    ];
> > };
> >=20
> > -fstrict-flex-arrays=3D3 is coming and we need to land these changes
> > to prevent issues like these in the short future:
> >=20
> > ../fs/minix/dir.c:337:3: warning: 'strcpy' will always overflow; destin=
ation buffer has size 0,
> > but the source string has length 2 (including NUL byte) [-Wfortify-sour=
ce]
> > 		strcpy(de3->name, ".");
> > 		^
> >=20
> > Since these are all [0] to [] changes, the risk to UAPI is nearly zero.=
 If
> > this breaks anything, we can use a union with a new member name.
> >=20
> > [1] https://en.wikipedia.org/wiki/Flexible_array_member
> > [2] https://www.kernel.org/doc/html/v5.16/process/deprecated.html#zero-=
length-and-one-element-arrays
> >=20
> > Link: https://github.com/KSPP/linux/issues/78
> > Build-tested-by: https://lore.kernel.org/lkml/62b675ec.wKX6AOZ6cbE71vtF=
%25lkp@intel.com/
> > Signed-off-by: Gustavo A. R. Silva <gustavoars@kernel.org>
> > ---
> > Hi all!
> >=20
> > JFYI: I'm adding this to my -next tree. :)
>=20
> Fyi, this breaks BPF CI:
>=20
> https://github.com/kernel-patches/bpf/runs/7078719372?check_suite_focus=
=3Dtrue
>=20
>   [...]
>   progs/map_ptr_kern.c:314:26: error: field 'trie_key' with variable size=
d type 'struct bpf_lpm_trie_key' not at the end of a struct or class is a G=
NU extension [-Werror,-Wgnu-variable-sized-type-not-at-end]
>           struct bpf_lpm_trie_key trie_key;
>                                   ^

This will break the rdma-core userspace as well, with a similar
error:

/usr/bin/clang-13 -DVERBS_DEBUG -Dibverbs_EXPORTS -Iinclude -I/usr/include/=
libnl3 -I/usr/include/drm -g -O2 -fdebug-prefix-map=3D/__w/1/s=3D. -fstack-=
protector-strong -Wformat -Werror=3Dformat-security -Wdate-time -D_FORTIFY_=
SOURCE=3D2 -Wmissing-prototypes -Wmissing-declarations -Wwrite-strings -Wfo=
rmat=3D2 -Wcast-function-type -Wformat-nonliteral -Wdate-time -Wnested-exte=
rns -Wshadow -Wstrict-prototypes -Wold-style-definition -Werror -Wredundant=
-decls -g -fPIC   -std=3Dgnu11 -MD -MT libibverbs/CMakeFiles/ibverbs.dir/cm=
d_flow.c.o -MF libibverbs/CMakeFiles/ibverbs.dir/cmd_flow.c.o.d -o libibver=
bs/CMakeFiles/ibverbs.dir/cmd_flow.c.o   -c ../libibverbs/cmd_flow.c
In file included from ../libibverbs/cmd_flow.c:33:
In file included from include/infiniband/cmd_write.h:36:
In file included from include/infiniband/cmd_ioctl.h:41:
In file included from include/infiniband/verbs.h:48:
In file included from include/infiniband/verbs_api.h:66:
In file included from include/infiniband/ib_user_ioctl_verbs.h:38:
include/rdma/ib_user_verbs.h:436:34: error: field 'base' with variable size=
d type 'struct ib_uverbs_create_cq_resp' not at the end of a struct or clas=
s is a GNU extension [-Werror,-Wgnu-variable-sized-type-not-at-end]
        struct ib_uverbs_create_cq_resp base;
                                        ^
include/rdma/ib_user_verbs.h:644:34: error: field 'base' with variable size=
d type 'struct ib_uverbs_create_qp_resp' not at the end of a struct or clas=
s is a GNU extension [-Werror,-Wgnu-variable-sized-type-not-at-end]
        struct ib_uverbs_create_qp_resp base;

Which is why I gave up trying to change these..

Though maybe we could just switch off -Wgnu-variable-sized-type-not-at-end =
 during configuration ?

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220628004052.GM23621%40ziepe.ca.
