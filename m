Return-Path: <kasan-dev+bncBCF5XGNWYQBRBGXDQ6NQMGQEFY3P4TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id ED760615B66
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Nov 2022 05:27:07 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-13af11be44dsf8426582fac.21
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Nov 2022 21:27:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667363226; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z0mgx6RKlum6Qwh92zAmtcBTuvkd5p7bNP6GbDbZOi6TYZGun/1yu9v3qDEBaTzDiS
         tJpOkn21QXkikJi5ETFBzA0xk8scsZU9XoKUlVxgkkfl/KJN0IQqCPmDDRzYgHbVo5Uz
         WldgOeC6XaEARMU0AQ2zYT4tFfpvi0XBh/tFRtdaDQmdPzqDqYFlhTgoApHH1yXkeBwp
         ZzX+kbP6YxdW5OVK6O6Uu2sf0w6sP7Uk4vio6Ew5JB5z5jlksQbHGkW7qcOZdegAeATN
         tl/JRzwK3S5dEfVkOPydJxaBfz+2bCrtQUy5uLW6tXaKLnXGE5oXjQiGG80ZWuwogeY4
         epEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=WMbv4m5iQHDQA9utExN+5bYd+4SubRtNUX16BZRtgNM=;
        b=iCwYRrCkDinMseZFEAsAdQfralO1H3R1OjX9UpqjnSZlNti9ZBEhO2zVStOc4at7dX
         pt9kATk7NJlgJXSA8w8MOwVxRh1rHL1Vx6YcBBsRgOZk/ycHfBd+yGfJLrXPe9xhLIHM
         CwR3mgOcuDsZGVc8iTPgsQygoFpmcWPX2JW9VxOJBfLwM40Yts5HjfMqQy47ROwl2QG6
         RpJ9tG+R9l/3u1Aia3Vkh8Z/cJRBsZmOprJEINOqU1uS1RYxA99CUiM6BqBX7Xp6SRl8
         EN8Ox10G3OwKfN4ppoXnNP4c2t3K9Ixg+5qqZomdr4iwmZIq+/LDMemIlhFtVt5QmErX
         KXhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=IvJWFukR;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WMbv4m5iQHDQA9utExN+5bYd+4SubRtNUX16BZRtgNM=;
        b=TaJB6dY8Q67bT9xQUzSrW8VXUcAClaYEZehH9hT9CtsjP4EHcr4mxVm73Ltq3t0TkL
         YWiZ25zNKkVNNlYaaIRyuSSjXUayBxfml+eF7YDAdoWJuYXq9U7SNeNRyiwPNIXJkSQ5
         WabN51edOjxdXzQucpy2h23tj1LVlT0ygYYDH7nFpMrP30ZLPcDWA6+9GZ9YDQcTslFA
         zrBIR1POJonJq1Hp7TSkuqivY0agSPKvnJI1GU+M2UJcbNKIcsFa5qP6nqHBBfB++Dvi
         2lH26vKUeuITQXr5TpXU5+VOcW4RSLeQT0I+Wi4pvGbx6Pz2dSgMnxcnmTNIJG8XtQwx
         YADQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WMbv4m5iQHDQA9utExN+5bYd+4SubRtNUX16BZRtgNM=;
        b=pI3lCGI4cY+dG0EyLjIjPHzZbdOeV9Xq0V5zL2BvgoToCaFB/c1dcRzCyt7hI114QH
         TtghuAYDTnGoQ6lCV8LfgSmeMCiAfpyy03wLLSeazfFjNmiXlvNbVXVuQbJ719gMAqUH
         ceHrJEEFhIhFlHk0ncd++kKh2sCrGaFrDPVZ/z1teFRlkj68PoioX6k1Cx1rhgCsfHQ/
         5L9YuYlu1QvB38cCQJ4J7jdyHvtrr+X8I9Z/sRcKTuqmktA1/A/mzpNODg/NHq1u/NEU
         ja26eSLy26W2r4lW7q+CKDhXfX/MZUnj5/GW3yo9UNqRenJ6Nb67cOW2ILQ5N2vf80hY
         dvIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0czUxz9p2uAdiu913ZqByLtlNfzef2RUoazqTv7IdA1REKC4ak
	31nv6n4sapOIQbMhyzYrXdo=
X-Google-Smtp-Source: AMsMyM7vW1Mv02azw1scondmYPApRmC8use3Jdfy4P1vpRpD/Ecb/3BsywA77sDTtCdPUX+U+IhDGw==
X-Received: by 2002:a9d:f43:0:b0:638:c3c4:73ee with SMTP id 61-20020a9d0f43000000b00638c3c473eemr10784697ott.186.1667363226586;
        Tue, 01 Nov 2022 21:27:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4f08:0:b0:357:5ddf:b56e with SMTP id e8-20020a544f08000000b003575ddfb56els4330778oiy.7.-pod-prod-gmail;
 Tue, 01 Nov 2022 21:27:06 -0700 (PDT)
X-Received: by 2002:a05:6808:11ca:b0:34f:9c50:7c73 with SMTP id p10-20020a05680811ca00b0034f9c507c73mr11856976oiv.86.1667363226196;
        Tue, 01 Nov 2022 21:27:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667363226; cv=none;
        d=google.com; s=arc-20160816;
        b=yGl+XFJD07t6uKV8MELL+Jwh+gO72YTY08P5gtAvWhYacXzOK9AqoU5Iilk4P/NVCV
         O7/i+iXddoY9bFQDH+nHSYit1JPXBXgmv+uXcIzmY7FItxr0Lu5qL8gDxfkOocs8u4V4
         DKaOqU0/i+qbE4m3YmeOdu6ZHtwo8uHhaGL8jDfZdiBwVBp11yVjLfu8a2S5dx1TatyZ
         fKWmOm6t8zxCFZ9W4zoWeTwI95nPOTNLuVvNsACop/Y0FIIBcmj/BBnBMbRd2e9KjF6R
         S8Hgi425zVo9fn8frZRR3kyKX2u/WV9hX9cziOaRobb4S3bHLgdgi2XHTcuE+aME+Isc
         NYVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=oqi0XqbkG3Dus9YH6EgfJKa6MhfGCNy0Tx+UnxgxZV4=;
        b=nYZBjvI4wwE5H6b+PhWsBccfE3SfCsalv6mZFsuJnODWVu/w+t6+IuLW2zOSmarquB
         Gww1KT3LdoFGZzzJqJ3P8t/4AaLP0GNRQCPyAVghQ8PQB2QDhVNMnV1wk0k24ENfIt85
         P/I1Y8PZYzLskaisLQm6NmaKQ/bpasXPu3+YukZ8ThmnXCz3NplNi9XDqOThFiY7l2m4
         9TBF8zjAdqlfdsX+O4yGCEogPwh98uSTaPnrmZRhe4LY4/mXjqPrELV2p4ljHiftu0Uq
         gX9ndMff6FglEWcWle1KMNjuB17knc/nlBS+dnv41SC2SYTt1QJglJYZBBXpdwz3vXVL
         KwPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=IvJWFukR;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id u20-20020a056871009400b0013191afecb8si794102oaa.2.2022.11.01.21.27.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Nov 2022 21:27:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id v4-20020a17090a088400b00212cb0ed97eso834893pjc.5
        for <kasan-dev@googlegroups.com>; Tue, 01 Nov 2022 21:27:06 -0700 (PDT)
X-Received: by 2002:a17:90b:4a46:b0:214:27dc:a111 with SMTP id lb6-20020a17090b4a4600b0021427dca111mr2485292pjb.28.1667363225489;
        Tue, 01 Nov 2022 21:27:05 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id l4-20020a17090b078400b002009db534d1sm375509pjz.24.2022.11.01.21.27.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Nov 2022 21:27:04 -0700 (PDT)
Date: Tue, 1 Nov 2022 21:27:03 -0700
From: Kees Cook <keescook@chromium.org>
To: Jakub Kicinski <kuba@kernel.org>
Cc: zhongbaisong <zhongbaisong@huawei.com>,
	Daniel Borkmann <daniel@iogearbox.net>, edumazet@google.com,
	davem@davemloft.net, pabeni@redhat.com,
	linux-kernel@vger.kernel.org, bpf@vger.kernel.org,
	netdev@vger.kernel.org, ast@kernel.org, song@kernel.org, yhs@fb.com,
	haoluo@google.com, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Linux MM <linux-mm@kvack.org>, kasan-dev@googlegroups.com
Subject: Re: [PATCH -next] bpf, test_run: fix alignment problem in
 bpf_prog_test_run_skb()
Message-ID: <202211012121.47D68D0@keescook>
References: <20221101040440.3637007-1-zhongbaisong@huawei.com>
 <eca17bfb-c75f-5db1-f194-5b00c2a0c6f2@iogearbox.net>
 <ca6253bd-dcf4-2625-bc41-4b9a7774d895@huawei.com>
 <20221101210542.724e3442@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20221101210542.724e3442@kernel.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=IvJWFukR;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, Nov 01, 2022 at 09:05:42PM -0700, Jakub Kicinski wrote:
> On Wed, 2 Nov 2022 10:59:44 +0800 zhongbaisong wrote:
> > On 2022/11/2 0:45, Daniel Borkmann wrote:
> > > [ +kfence folks ] =20
> >=20
> > + cc: Alexander Potapenko, Marco Elver, Dmitry Vyukov
> >=20
> > Do you have any suggestions about this problem?
>=20
> + Kees who has been sending similar patches for drivers
>=20
> > > On 11/1/22 5:04 AM, Baisong Zhong wrote: =20
> > >> Recently, we got a syzkaller problem because of aarch64
> > >> alignment fault if KFENCE enabled.
> > >>
> > >> When the size from user bpf program is an odd number, like
> > >> 399, 407, etc, it will cause skb shard info's alignment access,
> > >> as seen below:
> > >>
> > >> BUG: KFENCE: use-after-free read in __skb_clone+0x23c/0x2a0=20
> > >> net/core/skbuff.c:1032
> > >>
> > >> Use-after-free read at 0xffff6254fffac077 (in kfence-#213):
> > >> =C2=A0 __lse_atomic_add arch/arm64/include/asm/atomic_lse.h:26 [inli=
ne]
> > >> =C2=A0 arch_atomic_add arch/arm64/include/asm/atomic.h:28 [inline]
> > >> =C2=A0 arch_atomic_inc include/linux/atomic-arch-fallback.h:270 [inl=
ine]
> > >> =C2=A0 atomic_inc include/asm-generic/atomic-instrumented.h:241 [inl=
ine]
> > >> =C2=A0 __skb_clone+0x23c/0x2a0 net/core/skbuff.c:1032
> > >> =C2=A0 skb_clone+0xf4/0x214 net/core/skbuff.c:1481
> > >> =C2=A0 ____bpf_clone_redirect net/core/filter.c:2433 [inline]
> > >> =C2=A0 bpf_clone_redirect+0x78/0x1c0 net/core/filter.c:2420
> > >> =C2=A0 bpf_prog_d3839dd9068ceb51+0x80/0x330
> > >> =C2=A0 bpf_dispatcher_nop_func include/linux/bpf.h:728 [inline]
> > >> =C2=A0 bpf_test_run+0x3c0/0x6c0 net/bpf/test_run.c:53
> > >> =C2=A0 bpf_prog_test_run_skb+0x638/0xa7c net/bpf/test_run.c:594
> > >> =C2=A0 bpf_prog_test_run kernel/bpf/syscall.c:3148 [inline]
> > >> =C2=A0 __do_sys_bpf kernel/bpf/syscall.c:4441 [inline]
> > >> =C2=A0 __se_sys_bpf+0xad0/0x1634 kernel/bpf/syscall.c:4381
> > >>
> > >> kfence-#213: 0xffff6254fffac000-0xffff6254fffac196, size=3D407,=20
> > >> cache=3Dkmalloc-512
> > >>
> > >> allocated by task 15074 on cpu 0 at 1342.585390s:
> > >> =C2=A0 kmalloc include/linux/slab.h:568 [inline]
> > >> =C2=A0 kzalloc include/linux/slab.h:675 [inline]
> > >> =C2=A0 bpf_test_init.isra.0+0xac/0x290 net/bpf/test_run.c:191
> > >> =C2=A0 bpf_prog_test_run_skb+0x11c/0xa7c net/bpf/test_run.c:512
> > >> =C2=A0 bpf_prog_test_run kernel/bpf/syscall.c:3148 [inline]
> > >> =C2=A0 __do_sys_bpf kernel/bpf/syscall.c:4441 [inline]
> > >> =C2=A0 __se_sys_bpf+0xad0/0x1634 kernel/bpf/syscall.c:4381
> > >> =C2=A0 __arm64_sys_bpf+0x50/0x60 kernel/bpf/syscall.c:4381
> > >>
> > >> To fix the problem, we round up allocations with kmalloc_size_roundu=
p()
> > >> so that build_skb()'s use of kize() is always alignment and no speci=
al
> > >> handling of the memory is needed by KFENCE.
> > >>
> > >> Fixes: 1cf1cae963c2 ("bpf: introduce BPF_PROG_TEST_RUN command")
> > >> Signed-off-by: Baisong Zhong <zhongbaisong@huawei.com>
> > >> ---
> > >> =C2=A0 net/bpf/test_run.c | 1 +
> > >> =C2=A0 1 file changed, 1 insertion(+)
> > >>
> > >> diff --git a/net/bpf/test_run.c b/net/bpf/test_run.c
> > >> index 13d578ce2a09..058b67108873 100644
> > >> --- a/net/bpf/test_run.c
> > >> +++ b/net/bpf/test_run.c
> > >> @@ -774,6 +774,7 @@ static void *bpf_test_init(const union bpf_attr=
=20
> > >> *kattr, u32 user_size,
> > >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (user_size > size)
> > >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return ERR_PT=
R(-EMSGSIZE);
> > >> +=C2=A0=C2=A0=C2=A0 size =3D kmalloc_size_roundup(size);
> > >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 data =3D kzalloc(size + headroom + ta=
ilroom, GFP_USER); =20
> > >=20
> > > The fact that you need to do this roundup on call sites feels broken,=
 no?
> > > Was there some discussion / consensus that now all k*alloc() call sit=
es
> > > would need to be fixed up? Couldn't this be done transparently in k*a=
lloc()
> > > when KFENCE is enabled? I presume there may be lots of other such occ=
asions
> > > in the kernel where similar issue triggers, fixing up all call-sites =
feels
> > > like ton of churn compared to api-internal, generic fix.

I hope I answer this in more detail here:
https://lore.kernel.org/lkml/202211010937.4631CB1B0E@keescook/

The problem is that ksize() should never have existed in the first
place. :P Every runtime bounds checker has tripped over it, and with
the addition of the __alloc_size attribute, I had to start ripping
ksize() out: it can't be used to pretend an allocation grew in size.
Things need to either preallocate more or go through *realloc() like
everything else. Luckily, ksize() is rare.

FWIW, the above fix doesn't look correct to me -- I would expect this to
be:

	size_t alloc_size;
	...
	alloc_size =3D kmalloc_size_roundup(size + headroom + tailroom);
	data =3D kzalloc(alloc_size, GFP_USER);

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202211012121.47D68D0%40keescook.
