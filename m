Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB54LZXWAKGQE4VVL3LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B050C342D
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 14:26:33 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id y189sf14427642qkb.14
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 05:26:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569932792; cv=pass;
        d=google.com; s=arc-20160816;
        b=tftmlyhkNyxUdl7+mnEuPow2w9y1UpIANzZlBFuL7AuE0+KaK0Za5aoG8DzQgdOKZg
         Bk5wupip7Bq7KWE7KIbu+KBqryATnvraSrba2psF7xvSE9hNtmFBLFJSK2Tr302Nn2WY
         eAjBJ2xfdRIf1Emgbn0y2cgVjjDLj84zTCELopxRSQbMwASQ4G/uYVY4Wbdv1QgLBtek
         vgSlrd4QcsDlCxScmBUL3j3X1MjbfJVXdWjTzY/6XCa6sq/eNn3uzN2ER+ZhIByJFTx2
         A4AlRz4T2DqwZGLum5ja8+6wo9nsRTyOvlX2QGgb7g0QbUsSFt2PADSZBADyrOoYSc3R
         HoMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=vdVtPL5eBlnMYZU/iVKN/SV6+Ga9P3mYS6nSlcFF7SQ=;
        b=Nbp8oGuPsaQXH6eppPw4b1/qwvCevVZcpw3TUkx9fqKvmbV33/SB3jVxnwlzR010vE
         5TUoKbCsNdOzCUVpcLmQawfmw7ugPpkrFWGyRt/Ua2aALxhoB9IVTSkc/Y2a7qjcJcE1
         9V+qD7YPC59SVprC/QapLdnO2nURIodcEA2gd48Sx8yb4I3cVfrGTLBObbDxfNSrDjTX
         BB78fIqyXZcUO12WCNJBU6+vfuiENDTE21wVH22YE2Pz3EKOEWFgiJ5iVWJlxt1lgIsj
         GkIib+8Bn3LpvPOfEHWJ5PPY4LNKEIu95jjmD1cG/DgsjkNXTwUmbS5BxE8nt27nxMTe
         pxpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ou1cPBP9;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vdVtPL5eBlnMYZU/iVKN/SV6+Ga9P3mYS6nSlcFF7SQ=;
        b=gDEmKwHKsW0Xgfy61ByvdTxkosDfjgSif8QebKBdrkU+jKziJYe6qdVB/zPORGiZT0
         Cb/XN5XVww9KYqRXT/C/cYXinDEbfMRimKKJl5FHiwqbCPL5m25y9/XIwpxtsmB7NSST
         d94xpSv9/sDmxJEj8KT7I5bc5GYKyDV86CVqeotKALBfPUFAGrhDDzNa7cdrSBuuDee3
         TPaeoKyZLEnY6FnGdJza6W8gMW90mgRnt//TxW2qi4gobLJTQVz5khN+CZVKu24v4M5s
         reljE+uKJ++mvp7AOzcV6EL8MhetlKjOHHbrUYl6yn1pR6h/FEkkoYZZEiuCTd77+7Tc
         eZGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vdVtPL5eBlnMYZU/iVKN/SV6+Ga9P3mYS6nSlcFF7SQ=;
        b=Vg0U+Fw0f2qx2yIIaQpYkl14am88p9wPQE0NT8B5uZIC2H8kfXPhriY+wLKfXDHmhB
         hXdf1WCiGz3JQhDwZ92Y8lz6fK+aScxPb8+PEPYueDbp8NfFRU7vYMDsA4/fCxoiCiB4
         W/F4KFR/FHkndGbKHzoBCURXJvuZ5zBycrPdQkdwihSG8iaRfwzW7i3iwLDHdW+ALeXf
         59B02fOGblsPcKFlky9n/mn+A7Dsa5IqPa1TTN7h49oZWhCODh0A6zuiPALI8I//7ujk
         2Ne78RtZUd3Pf3xrUegtvbyfgWMaErfFFGv2gE6ite40+mK0F7L20pe/sE4SxZ2knvzU
         A28Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU4j/DXP3e39h3AEeCgQK/zl/7cMW5W33s+X2v/SouW6o4mX5Gf
	F1HO6fkydMEPME7xqShpVgE=
X-Google-Smtp-Source: APXvYqzLPvu9xCDRG/VYG9NxLbAjnkf+PX5MAY3RZjHc9jyMVR6y+olFX5qFfuKy46suhOp7FE0zKw==
X-Received: by 2002:a05:620a:14af:: with SMTP id x15mr5550608qkj.170.1569932792038;
        Tue, 01 Oct 2019 05:26:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:aac8:: with SMTP id g8ls2964590qvb.10.gmail; Tue, 01 Oct
 2019 05:26:31 -0700 (PDT)
X-Received: by 2002:a0c:abcd:: with SMTP id k13mr25089062qvb.69.1569932791725;
        Tue, 01 Oct 2019 05:26:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569932791; cv=none;
        d=google.com; s=arc-20160816;
        b=zQwdVN183JAGhgWnsDmoTFbG1z5oW9c7rEY6eWmBPQDr2Lc51QFXidqLyzhzjU+GZv
         Nhis02/EBuMZrcTLq5Y5IBhgM3CabuLsVIuwmK2BPIkuUkLcCox4BpYAPPFjnLg3L1U3
         WXW+o8BQIv0Nh348YNhqRpENaqEgSHv7/QyZ2Uub4VbCyzcd5i7UxCIlg99+vu4OIOF5
         2CfewxbkkgqONthvllO6deIc/hV+zMZl/LPQWYJMFmH3mNyDrxwGHD/Oa7Fnxi8UC/YD
         EUENfmsHukM4VM0/1OPiqZIy55HZ7LYg18swI0UmDx08ZHm4Bkv9kDcB3SD9GlW1V2Fi
         IviQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=r9jiZXdMxIIkyZWDEljTg7/li1H7K2+Hf7E7i2HKYGc=;
        b=wVuHk9y5zuiTp1ykS5MlYMe0A3Opv1uWDKj5P2JIAyQWPmlsWXCCrfZgRk9ltSdtpE
         oSHbI28hni1b6ClvaWpUa3xB4h6APJMNeGuyv+Q3TJB37afL/CumTuHOqn+G0PLeEcHp
         j3D8DuXiuiD3q0mxX6zYUkEoBf+qMnje5vE/wcK5aV0YUOBtMHE/rhjNYcwGO1owJ/ec
         FwMer8L3lLCiwxf35Ak+k57jYFAzOdf4yfZ2FajRua7aNHLhRx2Gse7Q6PfLFbZ2rxzS
         Z2nASrjG4HpUjeFFA1vIxJBlXPs6dxtRrFobigBqy/BAEgnG/E/4c2KTnOnJH2oE5tCc
         QNxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=ou1cPBP9;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id o13si660081qkj.4.2019.10.01.05.26.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2019 05:26:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id 201so10938343qkd.13
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2019 05:26:31 -0700 (PDT)
X-Received: by 2002:a37:b184:: with SMTP id a126mr5748865qkf.105.1569932791327;
        Tue, 01 Oct 2019 05:26:31 -0700 (PDT)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id z5sm7042642qkl.101.2019.10.01.05.26.29
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 05:26:30 -0700 (PDT)
Message-ID: <1569932788.5576.247.camel@lca.pw>
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace
 from debug_pagealloc
From: Qian Cai <cai@lca.pw>
To: "Kirill A. Shutemov" <kirill@shutemov.name>, Vlastimil Babka
	 <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, "Kirill A.
 Shutemov" <kirill.shutemov@linux.intel.com>, Matthew Wilcox
 <willy@infradead.org>, Mel Gorman <mgorman@techsingularity.net>, Michal
 Hocko <mhocko@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, Walter Wu
 <walter-zh.wu@mediatek.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Date: Tue, 01 Oct 2019 08:26:28 -0400
In-Reply-To: <20191001115114.gnala74q3ydreuii@box>
References: <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
	 <731C4866-DF28-4C96-8EEE-5F22359501FE@lca.pw>
	 <218f6fa7-a91e-4630-12ea-52abb6762d55@suse.cz>
	 <20191001115114.gnala74q3ydreuii@box>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=ou1cPBP9;       spf=pass
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

On Tue, 2019-10-01 at 14:51 +0300, Kirill A. Shutemov wrote:
> On Tue, Oct 01, 2019 at 10:07:44AM +0200, Vlastimil Babka wrote:
> > On 10/1/19 1:49 AM, Qian Cai wrote:
> > >=20
> > >=20
> > > > On Sep 30, 2019, at 5:43 PM, Vlastimil Babka <vbabka@suse.cz> wrote=
:
> > > >=20
> > > > Well, my use case is shipping production kernels with CONFIG_PAGE_O=
WNER
> > > > and CONFIG_DEBUG_PAGEALLOC enabled, and instructing users to boot-t=
ime
> > > > enable only for troubleshooting a crash or memory leak, without a n=
eed
> > > > to install a debug kernel. Things like static keys and page_ext
> > > > allocations makes this possible without CPU and memory overhead whe=
n not
> > > > boot-time enabled. I don't know too much about KASAN internals, but=
 I
> > > > assume it's not possible to use it that way on production kernels y=
et?
> > >=20
> > > In that case, why can=E2=80=99t users just simply enable page_owner=
=3Don and
> > > debug_pagealloc=3Don for troubleshooting? The later makes the kernel
> > > slower, but I am not sure if it is worth optimization by adding a new
> > > parameter. There have already been quite a few MM-related kernel
> > > parameters that could tidy up a bit in the future.
> >=20
> > They can do that and it was intention, yes. The extra parameter was
> > requested by Kirill, so I'll defer the answer to him :)
>=20
> DEBUG_PAGEALLOC is much more intrusive debug option. Not all architecture=
s
> support it in an efficient way. Some require hibernation.
>=20
> I don't see a reason to tie these two option together.

Make sense. How about page_owner=3Don will have page_owner_free=3Don by def=
ault?
That way we don't need the extra parameter.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1569932788.5576.247.camel%40lca.pw.
