Return-Path: <kasan-dev+bncBCB5ZLWIQIBRBHVPZSRAMGQEZLP5DXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id E5DA16F62E4
	for <lists+kasan-dev@lfdr.de>; Thu,  4 May 2023 04:25:36 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-51b8837479fsf5304540a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 19:25:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683167135; cv=pass;
        d=google.com; s=arc-20160816;
        b=Piukqe+PYDV1hF2TEBT6IIAcPefy1t1O6EecLOz/vJvuLLdcxUPjZhAIyQdCjDh9uE
         FaLKkrWzEqmJZP1Ok2+o7QwU6Erv/faUiHRDhcAUiv+ETXA6/Z0+b1Jty1SPLzsC/EpF
         9/kUrt3VF7bRw2Q0e0U2wfc7ptZjWP1V3gOepJXZsrVeXjuszDd6sryg5Ttl5A33K7w5
         XSinWDsyJiSEJBcFU2hFvDghZGXsjmUq/t9jxtjkuQY6gHs3LbJgJQckHKgeuI1kxZ9a
         590QVmESq56CLGNg/Tbln3Z1hgmnAmVpeC9bCJZgPMXc8qKljkrveitRqOQ+3XIFAb82
         7dQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KLJ483lyqhc4FYj1qPZwmk0GI2Dl16yN80g4xrM67rs=;
        b=KmCwcMvrmuVbLAaOurIZDxAYeRPonGgxL+/IApIXi9kXL9qvScfa7s/7jkzeUtL6Cn
         0U1U9BlnBerAADpiyV6eKcSZztqT5m4RW2BrDVHAscwGnLNuodhdMqvV4f13BmcFlpR+
         K4mFugjWIjCoHw/hIpH2mQ9CtkLJWVdOFok8CjeQMOyl1xry1YjZvHap+0cNWwT321Nn
         +IrlD9brWQInZcfiFTAvQMUzoZOb3PMipn9hUHa9irPw3OR1VxvOVcKcitO1dYYW6elf
         DxwHq9Cqubu9lknq+eIu7N3fCvLy3lJQBMN6BvIidBeELZoRuxIkbgmP2JM9Qd3CpnJ9
         Crnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="Ej2D/q1g";
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683167135; x=1685759135;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KLJ483lyqhc4FYj1qPZwmk0GI2Dl16yN80g4xrM67rs=;
        b=GlsYKp0bk1B3uXWNezjX+KgC4gj2hYNY+kQxQrR+XvXJD2vIy4pV8+q47eiGdKmbZL
         FcPye0xP/Cwcq8/ahTM1IEC6p6hRm2qLoG/SA2OSZg66gcfkWNxXG7OVx+rmlIffAUs2
         L6aOzfXugLdp5m8YPZ7FvpKPpAj4YOF3cZTHE0xT6tYEzE9s7d2PARHBSK5J1f+thXE8
         HELpiig1TR0/qje8U8M6SkG5U9Ho+w0oEaV2eMLd9tDtQSAhKs9wYhG2TPZfZyzVckwn
         yCyGnt3zXKYY4GLkwpMh1Hir3xnTTod8DCb1arvveGvtnazYasFsyGZTI+twKzXriNGj
         WbHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683167135; x=1685759135;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=KLJ483lyqhc4FYj1qPZwmk0GI2Dl16yN80g4xrM67rs=;
        b=TUrBjtUGd0B9UQYn8zaA2QpB9j1HCFiRefoQM/9WtXZe9c4YKwPDtK41b89Nv+3tGg
         PEregpjfDlBnYhP8b+3wuJjdw0r3lx6ERWYYM6aI3QPetNmV10NFibeJs3R9m5cA/DHr
         HqJOSdjvUzlHcgOzvcvultwEcWNhpUQxxAdV/GoCb+osYok2Z0Y/GV7fL7w/DyK4xNxu
         1jOmeX8sNdoMb+FyMjdx7TM3LNVJ7/nUxCKFPrq0VMraUDh7dGSmPjTqjk0v8TJV4Xf8
         25if7ySl7igp29OLfLfR1lpSwFeP0RCt9OiF4Blt7L4ZzShPQ1BierZaXvJTqYD7dIy7
         svFw==
X-Gm-Message-State: AC+VfDxYfF83BOK6D3x4iZnbpEBNHhmYvfl7fmofIP+3X5D67dYTwlnC
	+XsUZW0wnuG1zVBfkPqHS6w=
X-Google-Smtp-Source: ACHHUZ4A2ZTxRZoou0kIKgGuSXiBgme4qaq+ccrePYgYSyyeNzjVC/o9yNdS8wJuH+FIMfcnQ9VANg==
X-Received: by 2002:a17:902:e809:b0:1a5:2a44:a1e4 with SMTP id u9-20020a170902e80900b001a52a44a1e4mr632946plg.13.1683167135096;
        Wed, 03 May 2023 19:25:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2447:b0:194:d87a:ffa6 with SMTP id
 l7-20020a170903244700b00194d87affa6ls3725458pls.1.-pod-prod-gmail; Wed, 03
 May 2023 19:25:34 -0700 (PDT)
X-Received: by 2002:a17:90b:1bc5:b0:23c:fef0:d441 with SMTP id oa5-20020a17090b1bc500b0023cfef0d441mr665555pjb.33.1683167134055;
        Wed, 03 May 2023 19:25:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683167134; cv=none;
        d=google.com; s=arc-20160816;
        b=eVlb4o9wmyKucr9p027ZO+Qv7EJcQvpjEYxYAkN6g7OPuAVWg4UZUp09AO4kZlNa+e
         0b7087q+/XfbbAZMeuWlBY1zETFQckkPXN8/+mhM2FYQR2jG7y9rjjwC40fi2E7dfN2e
         p4JdQ9yO4BMBnNhuQVOr2nfEIsRr65txfiyzyNUaNmkgwVnXWFo0FZYSC/dzeHYtDRui
         8yTQj2GYjx4Dcz4FR547jSM5yk7x3KDaHR16GZlqXGU4BkIfeK4zHvBlZfXqbLu3NZvO
         U7QbTa5KMGbGvhPFr9fam1hPk1RhdbjLhMDfBH0y72aG5vSHDVdxt0+lLdFEj9ki01DQ
         tSQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=X+UY7cUQaVo4x4W0WCSPsCuWeI5BUJEgh7i3Xst55/Y=;
        b=Rtw1szhK5gCfQZwdzATATzy2yF27u9IlARmjCt4qjnTHzP87UY8VpBbew+PPhXq/X+
         qu+CzgIulTEk0hAsAg6UPDODdwD4hfaeFTY4ubdUGn1EtwHtIUEW8niax5vTXyxphco8
         xhsBM23P1GG6ODt1XpuEcDbHDMx1D+Yj4t13zdznDbl1LXTDnCwtnG16Wo+6BkRnVeAs
         FZxGgokU5oat/lpvtvKdNOwZ4xSeW8fKpslpS4HaEHi7J9mzAZeMeKosTcqEKR265HF+
         rTJPyHpHEqlI8Tb84LV4gUBJxzwkMeFdJBj3IWfVUFVYAu3n1EzewY0VNyBf/R2zgTkA
         ijvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="Ej2D/q1g";
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id bk3-20020a17090b080300b0024de50e3455si559260pjb.3.2023.05.03.19.25.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 19:25:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-1a50cb65c92so44608015ad.0
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 19:25:34 -0700 (PDT)
X-Received: by 2002:a17:902:c94e:b0:1ab:2758:c8a4 with SMTP id i14-20020a170902c94e00b001ab2758c8a4mr2512871pla.0.1683167133231;
        Wed, 03 May 2023 19:25:33 -0700 (PDT)
Received: from localhost ([2620:10d:c090:400::5:6454])
        by smtp.gmail.com with ESMTPSA id w4-20020a170902d70400b0019ac7319ed1sm2987721ply.126.2023.05.03.19.25.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 19:25:32 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 3 May 2023 16:25:30 -1000
From: Tejun Heo <tj@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexei Starovoitov <ast@kernel.org>,
	Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFMXmj9ZhSe5wyaS@slm.duckdns.org>
References: <20230503180726.GA196054@cmpxchg.org>
 <ZFKlrP7nLn93iIRf@slm.duckdns.org>
 <ZFKqh5Dh93UULdse@slm.duckdns.org>
 <ZFKubD/lq7oB4svV@moria.home.lan>
 <ZFKu6zWA00AzArMF@slm.duckdns.org>
 <ZFKxcfqkUQ60zBB_@slm.duckdns.org>
 <CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
 <ZFK6pwOelIlhV8Bm@slm.duckdns.org>
 <ZFK9XMSzOBxIFOHm@slm.duckdns.org>
 <CAJuCfpE4YD_BumqFf2-NC8KS9D+kq0s_o4gRyWAH-WK4SgqUbA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpE4YD_BumqFf2-NC8KS9D+kq0s_o4gRyWAH-WK4SgqUbA@mail.gmail.com>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b="Ej2D/q1g";       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62e as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hello,

On Wed, May 03, 2023 at 01:14:57PM -0700, Suren Baghdasaryan wrote:
> On Wed, May 3, 2023 at 1:00=E2=80=AFPM Tejun Heo <tj@kernel.org> wrote:
> > Another related question. So, the reason for macro'ing stuff is needed =
is
> > because you want to print the line directly from kernel, right?
>=20
> The main reason is because we want to inject a code tag at the
> location of the call. If we have a code tag injected at every
> allocation call, then finding the allocation counter (code tag) to
> operate takes no time.
>
> > Is that
> > really necessary? Values from __builtin_return_address() can easily be
> > printed out as function+offset from kernel which already gives most of =
the
> > necessary information for triaging and mapping that back to source line=
 from
> > userspace isn't difficult. Wouldn't using __builtin_return_address() ma=
ke
> > the whole thing a lot simpler?
>=20
> If we do that we have to associate that address with the allocation
> counter at runtime on the first allocation and look it up on all
> following allocations. That introduces the overhead which we are
> trying to avoid by using macros.

I see. I'm a bit skeptical about the performance angle given that the hot
path can be probably made really cheap even with lookups. In most cases,
it's just gonna be an extra pointer deref and a few more arithmetics. That
can show up in microbenchmarks but it's not gonna be much. The benefit of
going that route would be the tracking thing being mostly self contained.

That said, it's nice to not have to worry about allocating tracking slots
and managing hash table, so no strong opinion.

Thanks.

--=20
tejun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFMXmj9ZhSe5wyaS%40slm.duckdns.org.
