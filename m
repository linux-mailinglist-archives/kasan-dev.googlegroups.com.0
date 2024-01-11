Return-Path: <kasan-dev+bncBCUY5FXDWACRBAESQGWQMGQECYPBAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3793682B59A
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 21:01:06 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2cd853c15adsf11357461fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 12:01:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705003265; cv=pass;
        d=google.com; s=arc-20160816;
        b=ydSq+uzstzb30MVlCh8zkyxds8nlN4TIHDhF7mI+KpGr7vRvVGIvyG2MCDt/K42vzf
         gPMZMtUnDve5+mYxSSqZz7S2NQGHCHnEewI0zqs7/uq+OHIetnyrtCSPLhOo/RwEdrok
         LlOJ5FBbwTMCXR+MD7KpNgcCTZT2z9yAkv54mZX3MnXx89IfM5LJmCgU8pkoUgzaN+mq
         qhz67FNZ5rSG1kq/1l1BlAyvvUlMST7zfCgJ50+VEp4kUApzKWt4hSC9jnxEkaDCSSZT
         1BbwInO5T24Uf6NneQJE6AvyxFneWw0CobF8KMmUgcYFhL4ZokMDyZ85ZofjSOLmWMLR
         R16g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=qZwuTlESyac9yecgf3KyA0+dUp4xzso26Ua9MnZGxHE=;
        fh=ZJ0NZ8AQRkZSiH8KlDE2U8gDQTDcD4o+PXLVSJ3H2O0=;
        b=EFbd9x8jVh8NNfSWz0oQOFZidDBRh5sO3i1QioOKCoYcgLWGqBkGSI92l6xL7/8vq+
         8EfpRhnfAXcsLGhfjWKd7gACregjSGeF+IAwvpCkG99OocIRHp+AF4eN+WrAfm5dfePW
         z340Q5FqPVBUCNS6DGK8qmMIfl+hLcO9wpns9aXAVatxfbQ0bkKoLKQ2yqFMEBRPOQ5z
         e0ckg1e7Lj+gQgLkTzEK/JKKOAB1xOGTegFcORlBZkXBHdpPsfy6QUCypJxqjHhCSgDD
         QkBAJMNSd7IrtR3Kzo1KpRUc53pQiNWaj4MVo2KYHR4Jy0s6MUNzMTYHNpDEWC1dhWd7
         cDcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=deejydPh;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705003265; x=1705608065; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qZwuTlESyac9yecgf3KyA0+dUp4xzso26Ua9MnZGxHE=;
        b=Dj2776iMYILyGVfTKa/ZX5No3e/YYABr8n6maDdM5mce406B7WjYtc8GJCTcMKdfzB
         WwYlG8KnOeMD2v8MfqPByi8YME6ogWuhIMxaNQT/VROFXbrk5e2S5PJwk/2JxRw8UfdD
         5SilGAKW17LBp0G6cdXY2b+M8ik0HHNfSIpkrwNsHptnvgec/HFfUai8YBn3VImuozDs
         c1SAVCj90IdKElSO5e7wyKZ6GZS+r6VnfFnbEc74SQlpTOcc/5KAis3mFbVWIattWfFQ
         oeL4iQHzPDFKYkep7PPza6E8sNFAXPjEOxesEyRgnzxaEU0jTwf8T/bav3zBF5GpIJYV
         5Utw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1705003265; x=1705608065; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qZwuTlESyac9yecgf3KyA0+dUp4xzso26Ua9MnZGxHE=;
        b=fqAyeba4f+x/4J8B1GFH+N4035Wgm6JiIQHihSyfEDvOReTX0VbKs5gWB7j8LWNH5s
         eOzvJt0hm4MhdgPYzrTJ7t8Q0gT+qWIrEPNT+7DEEUN1o735VoxS192nVKsT224JnWB/
         s1w8MXuDrzYY1L8C7kBj4+IXCD2xjKIjUf/j5tpRknfjqHbq2i2Al8Zwrp8lkfgM7IMa
         i76a3Z07TCm3zqxxtkpS13TnMxJoMkPiNcZJssnz6TES57gr20g6l7q/RjRlewWf3vwC
         pDeQ6Mz70IsDN4iA8i2jNeuc75RJsAJGfctTqOuW4u8TiX9zUvBAhsjsr3A1/WXE47pV
         xDgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705003265; x=1705608065;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qZwuTlESyac9yecgf3KyA0+dUp4xzso26Ua9MnZGxHE=;
        b=BMhKreifN0NyOgbtj2ZRU08hX7Ukr15uOS0nfLsaQM85qCV2w23+Q+rUWd+MXjRjQd
         TdAHe01BR/wBeyOGYvOd1Z6r1DsFx8XCCa7CuwmF5PMZI3KovjDDKqe0ab+lS3KbpTGP
         yAohLPuzZze3dq/uVr+5suxzJ5ZFbWCXYi4HYkoGHDPz8pzo2A6dG/+RpRKa7dWT59Re
         0Ho1trXHsKF5Tiw5faIbBE5bwLsZuLiJm/XEqP+fq12YHqv7HD8WUXdOTaThIKzMQBkj
         H73L2FmDdBL6nqDQAn3IdbD1SVi8iUvj4Spcqr0Ny5pO/cyZjxo6AFb8JKBOK9qRvXIK
         OFxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxhZVpY2jb2tSZNfTRcpmgOsL3Zo9fgrVwD2PeeNcAre5pEOnF5
	gtDqOTPz55um/Zn/vkwgQkE=
X-Google-Smtp-Source: AGHT+IF3Nzf3UAWs8aat/08jo3hYjpfDfjzZBZbSq2IZf7NK8D3WnAbkaPvqz1jeGtxYeW+7O6s6bw==
X-Received: by 2002:a2e:9283:0:b0:2cc:77a3:62fa with SMTP id d3-20020a2e9283000000b002cc77a362famr161512ljh.16.1705003265127;
        Thu, 11 Jan 2024 12:01:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:be89:0:b0:2cd:7dee:aa33 with SMTP id a9-20020a2ebe89000000b002cd7deeaa33ls973049ljr.0.-pod-prod-09-eu;
 Thu, 11 Jan 2024 12:01:03 -0800 (PST)
X-Received: by 2002:a2e:98ca:0:b0:2cc:d8a0:46ce with SMTP id s10-20020a2e98ca000000b002ccd8a046cemr144027ljj.91.1705003262946;
        Thu, 11 Jan 2024 12:01:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705003262; cv=none;
        d=google.com; s=arc-20160816;
        b=c3Jmxolyv8vdTsYJO3KxR6we0dHxtDO78Kly2JeKyP/7z0O/DnUrTlDZ1pD3WJ/ll+
         2Hm4/gkeShGOUojml94Up2o9g4tv3N9qSh28e7fMgx4Dq1y7s4s8qWcdkBt2zc9czuer
         3cWUw9jO8XKdDRUI/wzWOivvNvEXqa45VMNYYTyQAwCjUNKqRFvrr/ZLssgyQkrea6Vb
         Wzzq31us4uZGGvlqhwcs1o03QY7OXX3y9bZfgeWhcaA9SBZV4gvQe+OsvL1I9qVus18c
         5aMJz65/eBsTrNdXqnUBEtlYdj9vp8SGw43H1MnfbdURj++FvDrrAK4bt2b6G6Mw7atz
         rK9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HAL60ZiXYTrQWwc6XvTjBF7mU0s/R7MUfIaHS38evWw=;
        fh=ZJ0NZ8AQRkZSiH8KlDE2U8gDQTDcD4o+PXLVSJ3H2O0=;
        b=P1PDjCQkFYBq6Smsj5KLa/gZ0mgnAUir/KnQ+FSAdQ1T5c5OampeRkfxPdAf5+0fMm
         7Wp1uVPphtEkeOljrJ80e+kyFvEC38ZTkGjFIm1rkk32SqlTpRIet1d7WpYBCKxxU4Nz
         oYeV/zQxK+u6Wf8uNc2cHv9IRCXvQzEyBdzPZV3X871vSTGDsVVlOf5pboQJqVm55tQR
         XS+Y+1TdvZdv5nDRPBFYC7BfvoLlEfQclXvh/ZzdIXDEpnf2HPv2uZ32smbt6hDNYn2L
         qMpF5U7J8+f2VmQ0pAaKDmmBSZwImkOO/MVhcyjgDvgNpMVlajrXI0WLAEojqZ7FJyTC
         7yVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=deejydPh;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id w25-20020a2e9999000000b002cd6347ba65si62004lji.5.2024.01.11.12.01.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Jan 2024 12:01:02 -0800 (PST)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-40e5f3b390fso9589155e9.2
        for <kasan-dev@googlegroups.com>; Thu, 11 Jan 2024 12:01:02 -0800 (PST)
X-Received: by 2002:a05:600c:6548:b0:40e:52a7:ac58 with SMTP id
 dn8-20020a05600c654800b0040e52a7ac58mr243439wmb.65.1705003261872; Thu, 11 Jan
 2024 12:01:01 -0800 (PST)
MIME-Version: 1.0
References: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
 <20240109-update-llvm-links-v1-1-eb09b59db071@kernel.org> <6a655e9f-9878-4292-9d16-f988c4bdfc73@linux.dev>
 <20240111194001.GA3805856@dev-arch.thelio-3990X>
In-Reply-To: <20240111194001.GA3805856@dev-arch.thelio-3990X>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Thu, 11 Jan 2024 12:00:50 -0800
Message-ID: <CAADnVQKFv2DKE=Um=+kcEzSWYCp9USQT_VpTawzNY6eRaUdu5g@mail.gmail.com>
Subject: Re: [PATCH 1/3] selftests/bpf: Update LLVM Phabricator links
To: Nathan Chancellor <nathan@kernel.org>
Cc: Yonghong Song <yonghong.song@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	clang-built-linux <llvm@lists.linux.dev>, patches@lists.linux.dev, 
	linux-arm-kernel <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	ppc-dev <linuxppc-dev@lists.ozlabs.org>, kvm@vger.kernel.org, 
	linux-riscv <linux-riscv@lists.infradead.org>, linux-trace-kernel@vger.kernel.org, 
	linux-s390 <linux-s390@vger.kernel.org>, 
	Linux Power Management <linux-pm@vger.kernel.org>, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, linux-efi <linux-efi@vger.kernel.org>, 
	amd-gfx list <amd-gfx@lists.freedesktop.org>, dri-devel@lists.freedesktop.org, 
	linux-media@vger.kernel.org, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>, bridge@lists.linux.dev, 
	Network Development <netdev@vger.kernel.org>, LSM List <linux-security-module@vger.kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Alexei Starovoitov <ast@kernel.org>, 
	Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko <andrii@kernel.org>, 
	Mykola Lysenko <mykolal@fb.com>, bpf <bpf@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=deejydPh;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Jan 11, 2024 at 11:40=E2=80=AFAM Nathan Chancellor <nathan@kernel.o=
rg> wrote:
>
> Hi Yonghong,
>
> On Wed, Jan 10, 2024 at 08:05:36PM -0800, Yonghong Song wrote:
> >
> > On 1/9/24 2:16 PM, Nathan Chancellor wrote:
> > > reviews.llvm.org was LLVM's Phabricator instances for code review. It
> > > has been abandoned in favor of GitHub pull requests. While the majori=
ty
> > > of links in the kernel sources still work because of the work Fangrui
> > > has done turning the dynamic Phabricator instance into a static archi=
ve,
> > > there are some issues with that work, so preemptively convert all the
> > > links in the kernel sources to point to the commit on GitHub.
> > >
> > > Most of the commits have the corresponding differential review link i=
n
> > > the commit message itself so there should not be any loss of fidelity=
 in
> > > the relevant information.
> > >
> > > Additionally, fix a typo in the xdpwall.c print ("LLMV" -> "LLVM") wh=
ile
> > > in the area.
> > >
> > > Link: https://discourse.llvm.org/t/update-on-github-pull-requests/715=
40/172
> > > Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> >
> > Ack with one nit below.
> >
> > Acked-by: Yonghong Song <yonghong.song@linux.dev>
>
> <snip>
>
> > > @@ -304,6 +304,6 @@ from running test_progs will look like:
> > >   .. code-block:: console
> > > -  test_xdpwall:FAIL:Does LLVM have https://reviews.llvm.org/D109073?=
 unexpected error: -4007
> > > +  test_xdpwall:FAIL:Does LLVM have https://github.com/llvm/llvm-proj=
ect/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d5? unexpected error: -400=
7
> > > -__ https://reviews.llvm.org/D109073
> > > +__ https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fcf4=
1d121afa5d031b319d
> >
> > To be consistent with other links, could you add the missing last alnum=
 '5' to the above link?
>
> Thanks a lot for catching this and providing an ack. Andrew, could you
> squash this update into selftests-bpf-update-llvm-phabricator-links.patch=
?

Please send a new patch.
We'd like to take all bpf patches through the bpf tree to avoid conflicts.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAADnVQKFv2DKE%3DUm%3D%2BkcEzSWYCp9USQT_VpTawzNY6eRaUdu5g%40mail.=
gmail.com.
