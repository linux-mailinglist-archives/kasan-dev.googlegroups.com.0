Return-Path: <kasan-dev+bncBDWKPJPUWQNRBMXN46KQMGQEIJCXSBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id F035C55BB9B
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 20:28:02 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id p6-20020a05600c358600b003a0483b3c2esf2612040wmq.3
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 11:28:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656354482; cv=pass;
        d=google.com; s=arc-20160816;
        b=sh/dzkygqLUq/JIiBL/XQuJtjhuOE7GiuKfK8R9HzXYFjcWgcclPsVlV2JYtTAjNnV
         SxqkUqk1l7ZLGeYeUyQIAPopvO4Ke8KOazKLoQph5GoB1leOKhSl+MSCwbDOKVZeH/pZ
         vec25b0+PSX5t6cXMsOxbQo0dvybBcsUwqhpuW1JKAW7WwheC61QYs0uM6evf8v4KFFK
         3KEylMwIRVwF0cDyX2QPmIEWjL3el1med1FugGgNkx8j0w2toJrQrWlAPoaJOprlJtYR
         XKDrIBrA9/IoPCH81No8LFFpN+CPypznxH3CR4tTK9gcyY2+EEiHbkys1K44qZEfdvtJ
         GX3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=Aaib0OWj0sH1d4lW+F7TO83TIoei8ZkYEgs47I0CC/E=;
        b=HvphYRxvO4hLB4Xi2uBWcJ6jq5dhhGikbdsvv4Y7vsNkom6Rm8gP5aIuHaKPKIfd8m
         R4S5XF0yaW53feHdpYL3yT0yp1sHF8BDLybqDSC9ju8FyVpBZfP4PRwqg17l5zOlN5C0
         g4i5W5ySKFQ01qhbRprK4Wcqtol8eIvYeTdFoh6d5kt57eBTOVodaq/FrKjSm5Hhz/hf
         8D158IsVQDMD4NFoMhchvvcsyOe8nwx09fTvcVYzt+tPbnW0ncvIxlmIUPgrWw5C4hJH
         TrQbicAstK5TEDU2czLU4+6K9pXimsvITGUgx2//aJYmTATvS67quQ9REz5bfX4+ynZN
         iGxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Aaib0OWj0sH1d4lW+F7TO83TIoei8ZkYEgs47I0CC/E=;
        b=tICdB1YKAYS3FPpIqPe1tEwmbb4dkfzrBfAWKnijtMYxfqB7qfVucMu9XOoFe0B4Lb
         1JcKP5DH3jRoOe4mRce1bF83+g/c/mcnkRtfhf13nzG5/z0m4vCTx5pgTGhuhgzu8iWo
         YW8PDIVNCGt0cfZ5sXjzK1BtxzfVAKgIjSAwoA9roJmboko03waiQjbVDTruT3pnHkUg
         cN30277ohMIC0tnFHYQNjNaaxGsTOqIa/I0jXIydykboMh1A5nCUjdB7AFzc9wTnPsyC
         ErUp1oVVg91mNhg+BQyS+vOu0rP298E4k3/yvGUJ9G+gYjzF1ENvfdT9TdmcgPjrxL+Z
         OZ8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Aaib0OWj0sH1d4lW+F7TO83TIoei8ZkYEgs47I0CC/E=;
        b=jq7/HzLWQmysIniPQUUJPsSC3iMzG45wmQUbzW09Qgzf9lgreuhmc+duo8SjACrr/B
         GV71mYyuo+1jqalXhFeFJrg100+EmBc223gSgsfv6uszd8bVi0JSeAP5NCfjoxVrdh19
         IgpiMDjHwFIB8iS6jvV2ZL6EcCHLrYCu5zPPn6fHPaxaDspAOd76WUHf+NO0Kp7KyyRJ
         XSUvOgXU34Hkpi4y0Fw0Ehmp9MW6C7vfbEm3RtGPCgfiTdZiwkCRPE04ujbItakHIAWR
         3exxnKBNYiRkZ01RFccnOdn5yF+TNoZti6AuozOrqMp/Ni0vAWt3Cy+FLh0XR/i4X52S
         S8+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora840n8nfQRJW5QVErk4UYJ08relZl091ACUGdcbmLZn1vXVcG2P
	NQGHrblz2RzHuGDVcQuSgFk=
X-Google-Smtp-Source: AGRyM1tVZj694dLOSR9OOnfsWZ1HQ4RWznwZP805ueBpcUJNZeE4suU42xrmbMIS0Kv40unkHBmSQg==
X-Received: by 2002:a5d:470d:0:b0:21a:3dac:8bcf with SMTP id y13-20020a5d470d000000b0021a3dac8bcfmr13967565wrq.113.1656354482501;
        Mon, 27 Jun 2022 11:28:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb04:0:b0:21b:b3cc:1640 with SMTP id s4-20020adfeb04000000b0021bb3cc1640ls14252670wrn.1.gmail;
 Mon, 27 Jun 2022 11:28:01 -0700 (PDT)
X-Received: by 2002:a5d:6309:0:b0:21b:9455:cf with SMTP id i9-20020a5d6309000000b0021b945500cfmr14186460wru.354.1656354481253;
        Mon, 27 Jun 2022 11:28:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656354481; cv=none;
        d=google.com; s=arc-20160816;
        b=yX8ax2qZZAavX7PSQTHroBXaK0+8TbAE6wyaMO2gnU0wDoyKhUQhllJj2MEgC+4yP/
         SZIg13ITC2WDY8/hcnzcaDB6CyxefOC4m5jywVg6SG67I8EGtQLLMCNYV2f3twKWqg0W
         Lkn9FLE+XVoPu85GpN9tUMPgCAoyevNw/75GwkUZD7bK2WGsKgwkEsubbHolYjO7d07M
         8ysXO5ov6YCPkxtuCX5y9pn6XscMRWx6Ycxo2MdQzpEb1/cviLxvOEu4AW8DEyyYcjKf
         vUxlziOXNqG7zDuA/edbFtgrJK0bA6ubKO/tH6FCnadCWNe8WcpLIsocrLQF0hL0VCyY
         Yj6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=AXbYc1DfxA1uzkELOZ3xvJsCsFp/8g/0yhmM1jF7ilY=;
        b=ajQ9z9i7PQ1pATxEeY/uoD68CZkHoppBFahcKI8iV4tW88n9crRrCQgsjGqxeOsVL9
         VoSaW7JZp5NsL123S9mk5wZI2we3/Gn/+/2m7A8R+wbTZiBL5GkEdrua4UZEuMDRdU3R
         /IxkIbzQTREFpjz4j6ICMwEWOrqwtV2TvFYgrrOQB3i9DfgY2Wq4YYit2T8isU5plu50
         EBeaedcTVfY0wxttYjF3Gi8934RFwMLjCHDs/pkaKIMBXtBgakC9c62oNJ7gs4WFluh4
         3LY6dLlwO5vg4nlohXuyRQvAvdSHEq2AWZcAPtXxYteVT0hnQtcnpo8irp0edVj/aU/9
         116Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
Received: from www62.your-server.de (www62.your-server.de. [213.133.104.62])
        by gmr-mx.google.com with ESMTPS id ay30-20020a05600c1e1e00b003a033946319si433896wmb.0.2022.06.27.11.28.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Jun 2022 11:28:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) client-ip=213.133.104.62;
Received: from sslproxy03.your-server.de ([88.198.220.132])
	by www62.your-server.de with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)
	(Exim 4.92.3)
	(envelope-from <daniel@iogearbox.net>)
	id 1o5tSV-000G0X-5e; Mon, 27 Jun 2022 20:27:39 +0200
Received: from [85.1.206.226] (helo=linux.home)
	by sslproxy03.your-server.de with esmtpsa (TLSv1.3:TLS_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <daniel@iogearbox.net>)
	id 1o5tSU-000TKD-AF; Mon, 27 Jun 2022 20:27:38 +0200
Subject: Re: [PATCH][next] treewide: uapi: Replace zero-length arrays with
 flexible-array members
To: "Gustavo A. R. Silva" <gustavoars@kernel.org>,
 Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org
Cc: x86@kernel.org, dm-devel@redhat.com, linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org, linux-s390@vger.kernel.org, kvm@vger.kernel.org,
 intel-gfx@lists.freedesktop.org, dri-devel@lists.freedesktop.org,
 netdev@vger.kernel.org, bpf@vger.kernel.org, linux-btrfs@vger.kernel.org,
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
References: <20220627180432.GA136081@embeddedor>
From: Daniel Borkmann <daniel@iogearbox.net>
Message-ID: <6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637@iogearbox.net>
Date: Mon, 27 Jun 2022 20:27:37 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <20220627180432.GA136081@embeddedor>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Authenticated-Sender: daniel@iogearbox.net
X-Virus-Scanned: Clear (ClamAV 0.103.6/26586/Mon Jun 27 10:06:41 2022)
X-Original-Sender: daniel@iogearbox.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as
 permitted sender) smtp.mailfrom=daniel@iogearbox.net
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

On 6/27/22 8:04 PM, Gustavo A. R. Silva wrote:
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
>    ...
>    T1 member;
>    T2 array[
> - 0
>    ];
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
> ---
> Hi all!
>=20
> JFYI: I'm adding this to my -next tree. :)

Fyi, this breaks BPF CI:

https://github.com/kernel-patches/bpf/runs/7078719372?check_suite_focus=3Dt=
rue

   [...]
   progs/map_ptr_kern.c:314:26: error: field 'trie_key' with variable sized=
 type 'struct bpf_lpm_trie_key' not at the end of a struct or class is a GN=
U extension [-Werror,-Wgnu-variable-sized-type-not-at-end]
           struct bpf_lpm_trie_key trie_key;
                                   ^
   1 error generated.
   make: *** [Makefile:519: /tmp/runner/work/bpf/bpf/tools/testing/selftest=
s/bpf/map_ptr_kern.o] Error 1
   make: *** Waiting for unfinished jobs....
   Error: Process completed with exit code 2.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637%40iogearbox.net.
