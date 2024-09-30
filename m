Return-Path: <kasan-dev+bncBDK7LR5URMGRBMEE5O3QMGQE5GFG26Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 030FE98A85E
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 17:22:26 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-42cb471a230sf34401355e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 08:22:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727709745; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wx3grMi8ARcHXK7TGkTBQsVa17ftiNySNamOVMSkASHNlrufTmBU9rS/x5YSiSSSDz
         UB10GA3r/E/vlA9idWm9oX/PwcXl423veO+SlKEq+UDXTL+ECwRCwv6TNLslxCC0qOiZ
         fBOjNxA8pjCfKxLXQ6c46HqaLJbNRzzJXY2kKDCA7+GsC04ypNysjNkhVqnYcly+duGx
         fUqtXo5M+KmSY5pSkibiXiCAwvtiUZBeY/Sci0F4+bAJ5yk5+MZEz2xhA881jp2tA10w
         Uii+pyzt2PrnG7HWEGjtMMvq6TY1KQOPk5iFdJHTx8PPxCPzzQUDWDZPFb7RewyTvBkd
         RJ1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:dkim-signature
         :dkim-signature;
        bh=KMOP4Bp/4DK+PGOykWsXhBBAj1NZjBLAc23Zuo+VgVo=;
        fh=JXDyNMv9r0j+oUvkeFWpIFWaP4dbqExKSE1O7FVvCw0=;
        b=hN1zMLw+777EXjsHVxs7XkNsuv/o6T73HfTpI/jRkxzFpstnTF0xyuUBCA/x/yEgiK
         N95ZexyIW2oAPCP4IDr+Skcx8bypiHDiy3xuEfYAVhciY2Zl+dfdupy3OsokPemm6GA9
         0LL9rYOulvxyCcCUEL6+znHT6C7gM6f2a90mPvIfSljiU4txvo5krQ7RdfkhK2eXziyS
         plXjP69GmouRKAaO4cfMPkw+YYwCNZe5rA2MmHMtH8iwahd2SbSlyA8iuo+Ag/2C+OFY
         EoAkrBNJ8jvRNEPvo1iRe7jqZjnRmwGjsEYpwJjPhU/6+FbAxtR73E0oULmVfgBQCzUl
         slfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kAVfNqN7;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727709745; x=1728314545; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KMOP4Bp/4DK+PGOykWsXhBBAj1NZjBLAc23Zuo+VgVo=;
        b=ClI/XJIWkPC4U2n4cEzsBav8PhgKqZ+jtHU7suN1spa5+yiG+8GU0mtv6LFJAdZ9vv
         WGMLmMd523BHfjwDXIW+rT9sblh2Y5sJqzJ+OPYwDEJGfr7aOlby3+2NtCYWm43M8mHP
         1jc6uypj44pMRCrpm/hUmN9nPMXh6U2dKzm6Bw48zybikuiI4HYAXzTtEsT7ttqQBRCj
         jzElyDncMZSa1RD5FZCqfhXam5w53urxVAblbNl2Z1Fh8jsrkoQS1WzI/6QF/j5mpnJe
         1O20oGXdBooA9+76brOgDllETDAQlpkVknxpf9uHK4GmVvhRXGDqfo87F9dRayWVEqx4
         u68g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727709745; x=1728314545; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:from:to:cc:subject:date:message-id:reply-to;
        bh=KMOP4Bp/4DK+PGOykWsXhBBAj1NZjBLAc23Zuo+VgVo=;
        b=Gs6WLtYPfm6VyEAg876FP9HPJHqPDd44R5p5FHqej7E2EXwy6G93+9vfDpciw6F9Iu
         UAY1W/5cJODqCnO6vu/nGSCyB5mXWT4seUZbZufmI4NXEyK9B/2FhIYGWz2g/c8I6Bee
         RmGqjC7RcNm8VIJgrKTdelp4obngKQjCBCYzrga99bDkvzZRXJc+MmwTaY9zBpJLiBAQ
         WXM1mbCRl6OrQLhgSEs4wdIyb9fPP5slOaBRNU6NAA3h2tSkR5QbuPIBoXQWssvzWOIZ
         gIl2J3AkEdWG1+VKEWJ2Z0KvuKPjzE4GoZbPcHXxHXqmkGQoZJfzQc4Blm8j1kutGsZe
         k+Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727709745; x=1728314545;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KMOP4Bp/4DK+PGOykWsXhBBAj1NZjBLAc23Zuo+VgVo=;
        b=CX0+LimL9BwfBkJ7oO+6k3xX1A0QHUmibnHK9iOmBc8kETSUMKTEXM2Zx4EqfSps+C
         XPitVuJ4SzdjZ9O3dK5dUVRiB4IOg259h40oJ/rvXEOiP7RQ+/IJrEPK/7qwxcMhgDhM
         oZcAJtCgfx+oJlRmPmZcbHq501t9fEqqDq21B639WPdIZv3dT+IxxLnyg4WwZMycxrwp
         qEc0T/nZvaM7NLs3DeT5luIpjCCUA6/ltVxvAQ/A3K3UmwIsYx/2SFr5RXmbqlu41QKh
         x5fd99TYEXrJuSZvzcRFhJNek3LcQzg+bsy7c5Av1/7Dge/9VD08r3aIeFCfM0oj68Ji
         x71w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0gon4LeA8g9S5KDqNvbwUIL68LFtZK7xrZDWEd0F0eTooFlWEYsDi9PD7V/sK4zq05XuNAQ==@lfdr.de
X-Gm-Message-State: AOJu0YxZPQGz47cYC1W7WwhzW0qRavE6tVt6euCwJw6fQshq0cVeUXYk
	QSovNwDyZ3jns3Mf0JSCRCZIPQUonmCOQB4HaY6E0YyLYl56fnxh
X-Google-Smtp-Source: AGHT+IFWanVWU4HCTp4HPLMy1F4CFQO6nCKNk4gfAg6vDbs4lUkQksCnOfdls2jvtT6v3SXuF1DWPw==
X-Received: by 2002:a05:600c:46cb:b0:42c:bb41:a077 with SMTP id 5b1f17b1804b1-42f58497f0fmr78655075e9.23.1727709744896;
        Mon, 30 Sep 2024 08:22:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b9c:b0:42c:af5b:facd with SMTP id
 5b1f17b1804b1-42f52229b87ls3460145e9.1.-pod-prod-02-eu; Mon, 30 Sep 2024
 08:22:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWi9/CvEv+HYR1u60g5XYasz2XwdAI9OJUPEwOB7U79EiqDPfFENhdhxGuj5rK3Pit4hcEJlCSeavI=@googlegroups.com
X-Received: by 2002:a05:600c:1f89:b0:42c:b52b:4335 with SMTP id 5b1f17b1804b1-42f584347b0mr99372215e9.10.1727709742983;
        Mon, 30 Sep 2024 08:22:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727709742; cv=none;
        d=google.com; s=arc-20240605;
        b=h40IfmPwcWj/bl8RsieFR1pH2sfYdGAn9pC7MugR6OLCHac9o/eq4rgq3Zs4JqccdV
         yM2vNfSvAC1u9hgaCPaWYA3z54FrYYLPwjwtO2U+oqUqmjTz1/w8jKnvaNBU5tSmm9RP
         zthgaroP69UhK6m3c9YLaOBPi/bPqHXJCQy+s3QnUx/NygwtRx0IGs2aFKUkz5fv03Yv
         779/CCW14GptwCZw1MkP0pwuJfR18eyunLPIV3Bz52BDm3wJ1+y65gbj2nqg2TnounqM
         mRVSAjHzAL/lfyPzh6glLAkurAvGin2qQh7/KL3DASaNX12Ku/zwkAUzlKpmqlPBMAsQ
         RTbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from
         :dkim-signature;
        bh=R8XhM/SVrfi8Z4HLnJdUMQS7Li3/arNhnHXWrKzEAUM=;
        fh=DhBb3BsmFZ43dyO019x/OYTtlK8KAp3Y18oyObSMNyg=;
        b=brUopZM8Q8vGsASVLTieqWOpR30a3B+KztvCoabAUK0wa0zwpiWRZJW4c+XnhQSX7l
         guDHPI9XHkePI7UPZXSIE1JWE8iKiStwNmlfQ8eXtGp9w1Jk4+3S13CMcnzhcruCwTlt
         LOHQ3x/HnqL+bnOdziPSi3vL5PhI8CYPyL90fWTV+6vEEIpXPnapzG6e6thVKDfjoZx2
         XOvsAg6rzFzjpelsOUA86Sqqv4gp8p6rkR9wF87XMIYwR7TAPwPbwDPHtD1+x44u9Po5
         s9DU/lWkT+e/U0SZNwj6l9O55/J+IzoRUUcgRc3eazIl/PHZoTRZlh/RZ+oqWkZG8v0D
         5tHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kAVfNqN7;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42f5c927b91si3696825e9.1.2024.09.30.08.22.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Sep 2024 08:22:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-53992157528so1510370e87.2
        for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 08:22:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW4BV4FxkD1JdsSKftTbrVPBdy0YABEtvE7E7Za4TskjVSxV3ZjeyX35CUCv6Yjd7vlTB8Tgw7nq50=@googlegroups.com
X-Received: by 2002:a05:6512:eaa:b0:52e:a68a:6076 with SMTP id 2adb3069b0e04-5389fc6d4d5mr6096930e87.49.1727709741703;
        Mon, 30 Sep 2024 08:22:21 -0700 (PDT)
Received: from pc636 (host-95-193-102-146.mobileonline.telia.com. [95.193.102.146])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5389fd5f5d1sm1255598e87.114.2024.09.30.08.22.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Sep 2024 08:22:21 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Mon, 30 Sep 2024 17:22:18 +0200
To: Huang Adrian <adrianhuang0701@gmail.com>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, Adrian Huang <ahuang12@lenovo.com>
Subject: Re: [PATCH 1/1] kasan, vmalloc: avoid lock contention when
 depopulating vmalloc
Message-ID: <ZvrCKmsDy9UiEYcr@pc636>
References: <20240925134732.24431-1-ahuang12@lenovo.com>
 <20240925134706.2a0c2717a41a338d938581ff@linux-foundation.org>
 <CAHKZfL0D6UXvhuiq_GQgCwdKZAQ7CEkajJPpZJ40_e+ZfvHvcw@mail.gmail.com>
 <ZvWI9bnTgxrxw0Dk@pc636>
 <CAHKZfL1jUs1Nh=aqnUrLLMiwb-F15kPc-fqC6i0hRaw0HbtMLw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAHKZfL1jUs1Nh=aqnUrLLMiwb-F15kPc-fqC6i0hRaw0HbtMLw@mail.gmail.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=kAVfNqN7;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12d as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Hello, Adrian!

> Hello Uladzislau,
>=20
> On Fri, Sep 27, 2024 at 12:16=E2=80=AFAM Uladzislau Rezki <urezki@gmail.c=
om> wrote:
> >
> > Hello, Adrian!
> >
> > > > >
> > > > > From: Adrian Huang <ahuang12@lenovo.com>
> > > > > After re-visiting code path about setting the kasan ptep (pte poi=
nter),
> > > > > it's unlikely that a kasan ptep is set and cleared simultaneously=
 by
> > > > > different CPUs. So, use ptep_get_and_clear() to get rid of the sp=
inlock
> > > > > operation.
> > > >
> > > > "unlikely" isn't particularly comforting.  We'd prefer to never cor=
rupt
> > > > pte's!
> > > >
> > > > I'm suspecting we need a more thorough solution here.
> > > >
> > > > btw, for a lame fix, did you try moving the spin_lock() into
> > > > kasan_release_vmalloc(), around the apply_to_existing_page_range()
> > > > call?  That would at least reduce locking frequency a lot.  Some
> > > > mitigation might be needed to avoid excessive hold times.
> > >
> > > I did try it before. That didn't help. In this case, each iteration i=
n
> > > kasan_release_vmalloc_node() only needs to clear one pte. However,
> > > vn->purge_list is the long list under the heavy load: 128 cores (128
> > > vmap_nodes) execute kasan_release_vmalloc_node() to clear the corresp=
onding
> > > pte(s) while other cores allocate vmalloc space (populate the page ta=
ble
> > > of the vmalloc address) and populate vmalloc shadow page table. Lots =
of
> > > cores contend init_mm.page_table_lock.
> > >
> > > For a lame fix, adding cond_resched() in the loop of
> > > kasan_release_vmalloc_node() is an option.
> > >
> > > Any suggestions and comments about this issue?
> > >
> > One question. Do you think that running a KASAN kernel and stressing
> > the vmalloc allocator is an issue here? It is a debug kernel, which
> > implies it is slow. Also, please note, the synthetic stress test is
> > not a real workload, it is tighten in a hard loop to stress it as much
> > as we can.
>=20
> Totally agree.
>=20
> > Can you trigger such splat using a real workload. For example running
> > stress-ng --fork XXX or any different workload?
>=20
> No, the issue could not be reproduced with stress-ng (over-weekend stress=
).
>=20
> So, please ignore it. Sorry for the noise.
>=20
No problem. This is a regular workflow what is normal, IMO :)

--
Uladzislau Rezki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZvrCKmsDy9UiEYcr%40pc636.
