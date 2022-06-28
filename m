Return-Path: <kasan-dev+bncBCF5XGNWYQBRB5EA5WKQMGQE64B6WBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id A022C55EB64
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 19:55:01 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id y8-20020a05620a44c800b006a6f8cd53cbsf14019236qkp.5
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 10:55:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656438900; cv=pass;
        d=google.com; s=arc-20160816;
        b=EZ/Ld8Re43ecdxScbYk0BAYZN/va0rYn1bZJftGjElukWpWZpRAZGPDFit8xRCaYru
         ig1SgAvnTB8SCyCBZxcL+VaVYBpFEZFW6vyofpFcOzXeMzxJ0aU3d+A2sEm1/IRxnUUA
         ycWm8iIqWSgHSILqww8qW4cEoPtzd/oeFX0YHkR2f5Rrtxp1SYCjR431EBNkiSLx/Q5D
         WWG8ipNQJ2tu+e38yS1xSBER2wCtcRlREUlt8F0tIiCMKmZEA1I/SxcwN2lLFFrP5hQ9
         WxHMJOkAwIe1NxkVQWgBC3J7q9bzmalgOzDGYVi+WxvDFjymgv/Y6fkj6kDXkcZktCVk
         Fomw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=ZvJvTq7o3yr25z7IL1JdyeHWZEtlbNOSSvUBB2Uc7pY=;
        b=i5Foe4bBHWHVSWIBPIRK4pQu+yHD/SqRlS1gAXGN0NLdPa+rpSFP3b9j7FbJdNuT1v
         lBQe+i+VBPbyR0Cvxxl1b9bijVuoPSiRX6tEeu7H8injhN41emqQZ2cytfdPYJa8zmyn
         69QtHflZ3atJMeFFRQexEyN4akB+CxnrGVYOjHlscMGIDvAgJtTJzXSI++G4+t/KTrQz
         +DYcpOAFSVj45RpXksDkZ5SjGHgu1EELHg/Nfx/KvX8QNN4TIRl5RTILOkKh0RNYfAku
         7ptVveDqh5vEO5x4is8ZLeCwrvAfNbeeTxKEIoIbK6zKNlbwli2HcHiq4m17uNup7nU4
         jV4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Lpc3rw2l;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:content-transfer-encoding
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZvJvTq7o3yr25z7IL1JdyeHWZEtlbNOSSvUBB2Uc7pY=;
        b=QLSh2uhcxsnnoBeLJAfIlpeJ/EwChE/yJmNi0qmOVRILmqrCAzuZSR5IaYDuqNmGFy
         AcCOxuwMgcsOZU1hGss0OOFUaFH66W05v42AW74bvi78SGHIq16Jc0GmK8D2Y7o0qPe2
         P8hFKR2vSlXnw70iZJq/+m/yyATXgoLglvZhN+ReRM/UFnuzS5xDZJqAW4agJO+zrU/A
         sJgm5o7HKnNybgzrWDPB0tD5+iUAqwN03oMRa2G1+273O2LThIkvob9+5hHezNgW84U+
         auUrTqUDs9Bc/UlvQlTAzjq4bCGr/ZI6o9q+m3sYjOrRp4u0zOcQ97nHiDVZj4KmhNyj
         l6oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZvJvTq7o3yr25z7IL1JdyeHWZEtlbNOSSvUBB2Uc7pY=;
        b=N3BYIrEAoO0DoYIi89FEhzN+1MyAyjtDduae7ngh0q8X+J4cpIsjvY7vgKdSeXEkKx
         7uFACJ9nElRS7O4dE2vuK0cAaDPjmXGF3XyZg50XQbS6CB997auiWslhdmAQNBCYWAna
         ecn5L+cPyIU1YKGqykRJM7HReETFkzFuGFk9KlppndZesArJX5erDTe9hglG0zNckbat
         qjuTz1vV58xVlzKPKpRN/bdkn4WDfsKcFQrbEyuQioEjxeP6HhaqsYqmAGDhC0RA6oDL
         aTPzLw25I8yOhcB8oyhdcubowCQ48eV/OuapS4Z3jc1nIdC2KKBc95QvfLsHE8z1iFcR
         9EZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/IBxq9l73Vuf7RPcgQ2Ir+e9XDdXI2zgVLYd4HOll8lfjCUh+1
	LGgvS+JZttkP032vz01pe3w=
X-Google-Smtp-Source: AGRyM1si2LUOyS1OaD5cbEkp4dkFop9DUOVtO24/U2RoT4wJb3t0DHJuhmRie7EvELvrj9Cd0EkT3Q==
X-Received: by 2002:ac8:5b84:0:b0:305:18cc:1635 with SMTP id a4-20020ac85b84000000b0030518cc1635mr13982574qta.289.1656438900463;
        Tue, 28 Jun 2022 10:55:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:d849:0:b0:470:3da3:17b4 with SMTP id i9-20020a0cd849000000b004703da317b4ls11664611qvj.2.gmail;
 Tue, 28 Jun 2022 10:54:59 -0700 (PDT)
X-Received: by 2002:a05:6214:c47:b0:470:7273:da3a with SMTP id r7-20020a0562140c4700b004707273da3amr3399725qvj.2.1656438899908;
        Tue, 28 Jun 2022 10:54:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656438899; cv=none;
        d=google.com; s=arc-20160816;
        b=QRZNAG7YHq3UiaMwnDLcP1aZMLi8jOYXSvYBC/i7snBHIBshwsmiS121+cCb7odbhc
         M4LzXKMWMVTvc5KSpracF0RD6ryTr8GPKPq9ebV+/a19F7JeB5518kZUtmZ2oMKyNQHc
         +51INXk+pKBUb2IIegAVLKNGSzR+7+b/8rjq9IIm25Uk4/z0dvUMifbCWWRizmY5Qaz+
         W5P5IylJDT/XO7RzV/LKYNpv8y+wnHr90Sny+8UMttjEUSpcZZC1pVlL1aiUVtahFqSs
         PhNuuLrE0FPFJQ3jxXEBN8QWtY8ekgpD18g407i9yBLffLFg0NL0NcDqhg9O+Uc9kg3q
         CGdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Ifakbg1KSXljeCc2KlqlOz+XfzIBohlTVCEx+b5hm2Y=;
        b=BnymRocjs2mXI7MZEL6/HCYht7ZHE1QMnkEylhwvM4NMhNTAT9NYPhzOU+LMhlXTQj
         /z4cszUNAu+eVPiaWDRVNiQQ2Oj/3LjtuPq0A3Z7y/UwHM6s4op/M26ubJGHYzoV9QNE
         Z7n8NAWaUNmmzBAQD7Ifiv5J000Lqo5YSX+Vyd0suby2V2yS/GkqsrqrK9KsqVrX4dyZ
         bdkybwRXpcwrhxr0ZjP37ybLhv8/ZC4pRddWV+xq50C9/98LhVn/oPFMVwqGejL8mVNi
         UCu8+S/bUOE9b22Se6wv0z398XATvp+iEpAN537oosMkpCVGsQLiUAWqb1ObrA61FPAO
         fyzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Lpc3rw2l;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id b27-20020a05620a271b00b006af20058c99si318778qkp.4.2022.06.28.10.54.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 10:54:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id jb13so11737792plb.9
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 10:54:59 -0700 (PDT)
X-Received: by 2002:a17:90b:3b52:b0:1ec:db2a:b946 with SMTP id ot18-20020a17090b3b5200b001ecdb2ab946mr838564pjb.229.1656438899502;
        Tue, 28 Jun 2022 10:54:59 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id f15-20020a170902ff0f00b0016a84d232a6sm5432810plj.46.2022.06.28.10.54.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Jun 2022 10:54:59 -0700 (PDT)
Date: Tue, 28 Jun 2022 10:54:58 -0700
From: Kees Cook <keescook@chromium.org>
To: Jason Gunthorpe <jgg@ziepe.ca>
Cc: Daniel Borkmann <daniel@iogearbox.net>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-kernel@vger.kernel.org, x86@kernel.org, dm-devel@redhat.com,
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
Message-ID: <202206281009.4332AA33@keescook>
References: <20220627180432.GA136081@embeddedor>
 <6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637@iogearbox.net>
 <20220628004052.GM23621@ziepe.ca>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220628004052.GM23621@ziepe.ca>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Lpc3rw2l;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Content-Transfer-Encoding: quoted-printable
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
> > [...]
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

The issue here seems to be a collision between "unknown array size"
and known sizes:

struct bpf_lpm_trie_key {
        __u32   prefixlen;      /* up to 32 for AF_INET, 128 for AF_INET6 *=
/
        __u8    data[0];        /* Arbitrary size */
};

struct lpm_key {
	struct bpf_lpm_trie_key trie_key;
	__u32 data;
};

This is treating trie_key as a header, which it's not: it's a complete
structure. :)

Perhaps:

struct lpm_key {
        __u32 prefixlen;
        __u32 data;
};

I don't see anything else trying to include bpf_lpm_trie_key.

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

This looks very similar, a struct of unknown size is being treated as a
header struct:

struct ib_uverbs_create_cq_resp {
        __u32 cq_handle;
        __u32 cqe;
        __aligned_u64 driver_data[0];
};

struct ib_uverbs_ex_create_cq_resp {
        struct ib_uverbs_create_cq_resp base;
        __u32 comp_mask;
        __u32 response_length;
};

And it only gets used here:

                DECLARE_UVERBS_WRITE(IB_USER_VERBS_CMD_CREATE_CQ,
                                     ib_uverbs_create_cq,
                                     UAPI_DEF_WRITE_UDATA_IO(
                                             struct ib_uverbs_create_cq,
                                             struct ib_uverbs_create_cq_res=
p),
                                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^=
^
                                     UAPI_DEF_METHOD_NEEDS_FN(create_cq)),

which must also be assuming it's a header. So probably better to just
drop the driver_data field? I don't see anything using it (that I can
find) besides as a sanity-check that the field exists and is at the end
of the struct.

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202206281009.4332AA33%40keescook.
