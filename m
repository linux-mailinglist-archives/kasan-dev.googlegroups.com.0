Return-Path: <kasan-dev+bncBDBZNDGJ54FBBGWZQ6NQMGQEO7FWYZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 323F4615B46
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Nov 2022 05:05:48 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id bd33-20020a056a0027a100b005665e548115sf8470376pfb.10
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Nov 2022 21:05:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667361946; cv=pass;
        d=google.com; s=arc-20160816;
        b=nNcisHpW21Oe6MB0v4HXXDdtgPddtae+EyOPaRHenbEN6VLeDfkHSot8otwZXuo2xT
         bZ+BfAV3jjGPu7Q+vXadFv91x8gohNc+KQ2f0oIV79ncjeL1AdJoxsvZ6Vr+ewKRNsdt
         ZTl4AcL//NE5w2+Lz89hFGHOXS76ji6GLfEh3psM9tnHM1rcJirvqe5dcLAFe3aCENk+
         7/tWanmcjJ9Lh1+Fvprz90+dVrMvtrXpx2ZQK2JSRz2KeRwjaKYNGSm0GuYhwbs20VL2
         ML2bdrxLOlf8oMlI6Xu55+mu3wZPfZA6zlkvfUOcALMm3bnPfor9WSj1/QTFdP7VCpnY
         1vRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=wCeSoQAz7y90gO11jPHhIBaEQKffWs5cP+RM8CquaHU=;
        b=LGfvTJG5dQnjPBEHUlkuyRgu4Tc2FhEmntQ7N7hoOcg7SwJqHcug1Wkud+GAkhCMFj
         vW5VCDycsFU+vN9KzWWBEaftEto75wfFU2kYDBS7ksliBlTThCxv8oa2powqMIWKYiCz
         ZEXbUS+trB77gupq42vM8OXSGfDlqga0iM7Intgh1owtYTsvVI9wLqQ7Ju9z6wpz3Awi
         VgBT4bvEcqB3a8wqeOmiww2sfK/NBYMlJWgGj9vJF2sxdwS+pZtW5dOcsR83SzFMyV2A
         vrsbuVYFeKxMXhK5GZVdFMmriBh6domu0M4w0Vq9DmjFAfBKKemWwJV3C3bO83vD+VHk
         0+Kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eXzxB4AF;
       spf=pass (google.com: domain of kuba@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wCeSoQAz7y90gO11jPHhIBaEQKffWs5cP+RM8CquaHU=;
        b=K7vTAbnYOuoNge/Do6FTU9OdJbIRFNSdH6E/AHx2J+DELp2T9bbf2YzCaVI+82GRA0
         w8v3P2d5n6ZAUmnsKkEpxZTel+Anp0eifzQAT9IIWj0SRZxyviN3mSyS4H77Jzf2L6a9
         0jh8zqhzQip7FaFzrv8+OSRJH0VUEMdi2JYQt3POnUL90TvV0FnGdHWU58RFKnojWOSD
         Xnz1ARfetMyOHNFf8m/GC/7zg2iDsgd5UUDmHcuiNhpNZgkFBQXrlIgbsIT8PH3mHZin
         6+SmqdCsi4Iv5N6CMlaN4jkZkoaU3O2wxx1p6BtrXXlaYFOhnFctxdSTrYePTNLW+dOs
         /AFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=wCeSoQAz7y90gO11jPHhIBaEQKffWs5cP+RM8CquaHU=;
        b=LsByDOD/Axz0LGE7N4ea1cffZo8QdD8D9Dx1u9GjXvgrQ825/XkUOvsbOR1TWxzTxY
         ieQOMmPNDvj87JNp70iM8uWq8cnQkBcFWNlYGoxtzcwTx/tEjiVEZ9p4hF2JtLgkJbGd
         OpwMhI4ZRXYLT8B1uXoiqGVy9rOXOQxYCZRBtOik6FrURPeqZ3ll0tm7c1tnPOl5K4oF
         9nv64qC3DVwW5n8pw6b6HsC9N+g7weWmioj8L7Hgx/CHnxBFpzsmFE4fpdNJbh3cy131
         2A/mZL5CfMgY4oxxRQjS7rpqPLrTPdqTP4jUfISSj6CX6XVpJm6lY+xdlcGj0eTzlv+W
         5NCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf00r/i5UQCy41JatCdJqX8NfY7ZKhX3rf3mMZO2ryBTMYnn4hoF
	qWGWwbPITQ9YkvWTj1trpsI=
X-Google-Smtp-Source: AMsMyM6hITTXwcgazvaCZ+C/bIHsCVs1+uLA5DWQhJNfKCKZ2UevCJ7IvPxu/YtuG80PAWjn+weRuQ==
X-Received: by 2002:a17:903:50b:b0:187:11e:5f1f with SMTP id jn11-20020a170903050b00b00187011e5f1fmr23115518plb.41.1667361946352;
        Tue, 01 Nov 2022 21:05:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1515:b0:56b:bd09:d1f1 with SMTP id
 q21-20020a056a00151500b0056bbd09d1f1ls6588855pfu.1.-pod-prod-gmail; Tue, 01
 Nov 2022 21:05:45 -0700 (PDT)
X-Received: by 2002:a63:1748:0:b0:46f:18be:4880 with SMTP id 8-20020a631748000000b0046f18be4880mr19951640pgx.128.1667361945466;
        Tue, 01 Nov 2022 21:05:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667361945; cv=none;
        d=google.com; s=arc-20160816;
        b=MspR1JMutkKPZhJm5KunlxRXcqpr6Ly3lFXP5y0RsodN6KiT0An4rspbVP4qfjmkZF
         WzCaoWgOKLhQd2dohlB+jF8warTjEZM9KKo9cBb2ew5NA1CeXfzeQhBjxwBZHXC+huAh
         jvcpUfsxyu2rT9GRgFcsxVbJCqKYap2KvqC/swqBJyo3pE3Vn0eSWshvfT8UBJHrv05E
         z34QNt8BHZLHbsBrxSqcjRDxDT7n8QvHMZP7NFmGBNY+Y2h+Wwsu4aKjjPU7OZQgdtFX
         HvPONr5isvZiVOYd9kWkuFNcBXl/Bg1WtQNhPqInODVpgstYVzhPktExk6xwXKZsjJ4v
         fuDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=rp5I1boLJZbL3hHmHV8f15Kx1AVUlLHCu0J3tBWn6bE=;
        b=oMulS8Hij6bPh7aNyMjSpmca2fnO/r53ZByoNsj3fDgGhn13N5OTtQ6uk1NKGhB9AA
         fKyq9ZeoEc7n0SMFaB7yz8KyKvHTQ6ux4d/M89Sn/62L8KwA/mDqYK2iedYtwAZd4d9i
         L/uy5uPLodPmWGks1PemKHUySsZtrQLJOSyQ4nrD/dvYFkvPkShmyYxSIXEEVGNDs6r8
         ja1DArdwZt7Qb71j5r2ZfsAhHYFP+smHUSFPKQrvi3KjhpUaSpHZh9ZdTHWe54x6z9fY
         jJWKJRDjiE88Td0I885phd5lDjw3pBLVtchlc7sj4DFbzOR7Fg+a0HMTh0xE54pFjSIh
         WzIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eXzxB4AF;
       spf=pass (google.com: domain of kuba@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id x15-20020a170902ec8f00b00174ea015ef2si521669plg.5.2022.11.01.21.05.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Nov 2022 21:05:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuba@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D9329617DA;
	Wed,  2 Nov 2022 04:05:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 92E26C433C1;
	Wed,  2 Nov 2022 04:05:43 +0000 (UTC)
Date: Tue, 1 Nov 2022 21:05:42 -0700
From: Jakub Kicinski <kuba@kernel.org>
To: zhongbaisong <zhongbaisong@huawei.com>
Cc: Daniel Borkmann <daniel@iogearbox.net>, <edumazet@google.com>,
 <davem@davemloft.net>, <pabeni@redhat.com>, <linux-kernel@vger.kernel.org>,
 <bpf@vger.kernel.org>, <netdev@vger.kernel.org>, <ast@kernel.org>,
 <song@kernel.org>, <yhs@fb.com>, <haoluo@google.com>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Linux MM <linux-mm@kvack.org>,
 <kasan-dev@googlegroups.com>, Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH -next] bpf, test_run: fix alignment problem in
 bpf_prog_test_run_skb()
Message-ID: <20221101210542.724e3442@kernel.org>
In-Reply-To: <ca6253bd-dcf4-2625-bc41-4b9a7774d895@huawei.com>
References: <20221101040440.3637007-1-zhongbaisong@huawei.com>
	<eca17bfb-c75f-5db1-f194-5b00c2a0c6f2@iogearbox.net>
	<ca6253bd-dcf4-2625-bc41-4b9a7774d895@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: kuba@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eXzxB4AF;       spf=pass
 (google.com: domain of kuba@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kuba@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, 2 Nov 2022 10:59:44 +0800 zhongbaisong wrote:
> On 2022/11/2 0:45, Daniel Borkmann wrote:
> > [ +kfence folks ] =20
>=20
> + cc: Alexander Potapenko, Marco Elver, Dmitry Vyukov
>=20
> Do you have any suggestions about this problem?

+ Kees who has been sending similar patches for drivers

> > On 11/1/22 5:04 AM, Baisong Zhong wrote: =20
> >> Recently, we got a syzkaller problem because of aarch64
> >> alignment fault if KFENCE enabled.
> >>
> >> When the size from user bpf program is an odd number, like
> >> 399, 407, etc, it will cause skb shard info's alignment access,
> >> as seen below:
> >>
> >> BUG: KFENCE: use-after-free read in __skb_clone+0x23c/0x2a0=20
> >> net/core/skbuff.c:1032
> >>
> >> Use-after-free read at 0xffff6254fffac077 (in kfence-#213):
> >> =C2=A0 __lse_atomic_add arch/arm64/include/asm/atomic_lse.h:26 [inline=
]
> >> =C2=A0 arch_atomic_add arch/arm64/include/asm/atomic.h:28 [inline]
> >> =C2=A0 arch_atomic_inc include/linux/atomic-arch-fallback.h:270 [inlin=
e]
> >> =C2=A0 atomic_inc include/asm-generic/atomic-instrumented.h:241 [inlin=
e]
> >> =C2=A0 __skb_clone+0x23c/0x2a0 net/core/skbuff.c:1032
> >> =C2=A0 skb_clone+0xf4/0x214 net/core/skbuff.c:1481
> >> =C2=A0 ____bpf_clone_redirect net/core/filter.c:2433 [inline]
> >> =C2=A0 bpf_clone_redirect+0x78/0x1c0 net/core/filter.c:2420
> >> =C2=A0 bpf_prog_d3839dd9068ceb51+0x80/0x330
> >> =C2=A0 bpf_dispatcher_nop_func include/linux/bpf.h:728 [inline]
> >> =C2=A0 bpf_test_run+0x3c0/0x6c0 net/bpf/test_run.c:53
> >> =C2=A0 bpf_prog_test_run_skb+0x638/0xa7c net/bpf/test_run.c:594
> >> =C2=A0 bpf_prog_test_run kernel/bpf/syscall.c:3148 [inline]
> >> =C2=A0 __do_sys_bpf kernel/bpf/syscall.c:4441 [inline]
> >> =C2=A0 __se_sys_bpf+0xad0/0x1634 kernel/bpf/syscall.c:4381
> >>
> >> kfence-#213: 0xffff6254fffac000-0xffff6254fffac196, size=3D407,=20
> >> cache=3Dkmalloc-512
> >>
> >> allocated by task 15074 on cpu 0 at 1342.585390s:
> >> =C2=A0 kmalloc include/linux/slab.h:568 [inline]
> >> =C2=A0 kzalloc include/linux/slab.h:675 [inline]
> >> =C2=A0 bpf_test_init.isra.0+0xac/0x290 net/bpf/test_run.c:191
> >> =C2=A0 bpf_prog_test_run_skb+0x11c/0xa7c net/bpf/test_run.c:512
> >> =C2=A0 bpf_prog_test_run kernel/bpf/syscall.c:3148 [inline]
> >> =C2=A0 __do_sys_bpf kernel/bpf/syscall.c:4441 [inline]
> >> =C2=A0 __se_sys_bpf+0xad0/0x1634 kernel/bpf/syscall.c:4381
> >> =C2=A0 __arm64_sys_bpf+0x50/0x60 kernel/bpf/syscall.c:4381
> >>
> >> To fix the problem, we round up allocations with kmalloc_size_roundup(=
)
> >> so that build_skb()'s use of kize() is always alignment and no special
> >> handling of the memory is needed by KFENCE.
> >>
> >> Fixes: 1cf1cae963c2 ("bpf: introduce BPF_PROG_TEST_RUN command")
> >> Signed-off-by: Baisong Zhong <zhongbaisong@huawei.com>
> >> ---
> >> =C2=A0 net/bpf/test_run.c | 1 +
> >> =C2=A0 1 file changed, 1 insertion(+)
> >>
> >> diff --git a/net/bpf/test_run.c b/net/bpf/test_run.c
> >> index 13d578ce2a09..058b67108873 100644
> >> --- a/net/bpf/test_run.c
> >> +++ b/net/bpf/test_run.c
> >> @@ -774,6 +774,7 @@ static void *bpf_test_init(const union bpf_attr=20
> >> *kattr, u32 user_size,
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (user_size > size)
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return ERR_PTR(=
-EMSGSIZE);
> >> +=C2=A0=C2=A0=C2=A0 size =3D kmalloc_size_roundup(size);
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 data =3D kzalloc(size + headroom + tail=
room, GFP_USER); =20
> >=20
> > The fact that you need to do this roundup on call sites feels broken, n=
o?
> > Was there some discussion / consensus that now all k*alloc() call sites
> > would need to be fixed up? Couldn't this be done transparently in k*all=
oc()
> > when KFENCE is enabled? I presume there may be lots of other such occas=
ions
> > in the kernel where similar issue triggers, fixing up all call-sites fe=
els
> > like ton of churn compared to api-internal, generic fix.
> >  =20
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!data)
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return ERR_PTR(=
-ENOMEM);
> >> =20
> >=20
> > Thanks,
> > Daniel
> > =20
>=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20221101210542.724e3442%40kernel.org.
