Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2UC7OKQMGQEXVQFE4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D3075563073
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 11:42:03 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id o10-20020a0568300aca00b0060becb83666sf966129otu.14
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 02:42:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656668522; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lv+p6QnOJcJJprG3vAq+7zOUVkyVzXZAJ4T6LCCHm2XEfKK/px0rJ44fZ8CC/z8M58
         RRvwv1UobX0bXEH9S/FKdR4fIyhqdI5eIQv4z34awblCMgPiPT5xiVKTpjrU2NQ90X36
         iceF6+jt/qjx2olLTkvZukP4nPLTDcQeBUqWf3AKvwVK6AO/XOGWHWgD1NTxwlMXNUEm
         hbYJdBF7DRR2DAPEGdeJcQbeLlYL9d2yGb2w6GkQbijNLCWyWdb4sKZxBvRQrgthzOXA
         c0Zog6RT51OcmBRKSuUi4oIxg0ZaKdYEI59AVz3tdts67iuBfK9ZE+vMJ9/Xa48EKkEh
         qx6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OfRxQghvdI971diDPE4eNj8mOAzvtKAUqUyJ4yh8PDY=;
        b=CFGAVKZtwLvmxVQrJs53GsBEb7SZwStxJL9fncWVwAwHMZWiG/hhnhR6pqVgbFTF1M
         TIc+1b/hW75bScSRsJJgmAvpXX0ZAhBWi3hTUTcozI/j6588nXhEM3A51KNiy9Xj+WbN
         mj+ImsDax5Ea4qyzHpaww1E68J3N71kvraHLxEtzhyU6Vpx+ZInc+ZHImgjQ4/+iLlPn
         3tbuVGS9FnDnUwN95g1ALEOdgSyaJeADyBrVmhT9tT4K+eeo6HhZQ/4rAkSKGxjgaoOJ
         vm4jMNwyMRenahWWOTvQDfRX6Hq5goAMcH0p9ol4QU9v9R0FDf56axrKyxguCkFr2zip
         GQwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="o/icSX7E";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=OfRxQghvdI971diDPE4eNj8mOAzvtKAUqUyJ4yh8PDY=;
        b=VQJZ+eMH9pMJelTfsWHrbb83v6kGf8+LZNlM5iAROdxBeFdDxAw9YZAIlS3SjkcGLN
         xc0vmMT6WT6F9YRpFUKFiyE+xj/gbRERuNL0hmCbR37436AQ6MuNm+c6yXBVnJ5givQ7
         ai/6CHA9tBIB3jkoYS0RNKUWoEl9vSaNqgaNDxlLw166J7r17iOUq4EejcvWoktneHuz
         JXJSA61zv4Z7Ew08VvFxn7gGV6xCECacl3ugIrVMKffgTV3+xNeFQ6/ZtagyUa4nryJG
         l/sfECaikZWnOrA0q8HFfbOyZcwkXnBRuTTZJH/Legxy+Bn37wfSA0/+5SZu99jRb/+V
         /9mQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OfRxQghvdI971diDPE4eNj8mOAzvtKAUqUyJ4yh8PDY=;
        b=0VurXfhrcrfxLO62EuRfHXeINYUM9hBATmfPtfzrLAQI2Fks4B1qBhwoayooqnaEs0
         MfEfRzPPLybARwfWztqJjGtD4lnizEVy5J3YoXshMBFYtDc5tjwDA5E4ROE3HqMaSHb2
         AmcnhyNpV5L5SziL7ooBkVQx3nwrDP0IpXV67UzTYB0j00VPnxgUAQwBPK77jr7/trJB
         5yEphmWPDRAqzy8do/r0FimTPcP+i6T4tRnU2y5og5n5NclTa5l4zwnhZMZRB0a+PWzG
         7c2ygWOkf4a0NptPlBmBkLKAo3ujBTVlAy+54JYwhDkAD1uGF+NV8/gukBK8IvytEzNX
         I/kg==
X-Gm-Message-State: AJIora9QYTy7MkFUcCvrNfzh8irnghX6HKZsXjTc9dVvkcj8EnEjFncP
	CBHzMPaJbdxd2P8xHRVQoOg=
X-Google-Smtp-Source: AGRyM1ukQ02ovwuzTw4bwx87gXzC1bDVsRHUR9iwBEmuq22VPs1r6kMe8ZoZ9aH+S8IXJgZG+czO6g==
X-Received: by 2002:a05:6830:6517:b0:614:d582:77d7 with SMTP id cm23-20020a056830651700b00614d58277d7mr6198207otb.323.1656668522457;
        Fri, 01 Jul 2022 02:42:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2013:b0:337:8d3e:3bdf with SMTP id
 q19-20020a056808201300b003378d3e3bdfls628417oiw.3.gmail; Fri, 01 Jul 2022
 02:42:02 -0700 (PDT)
X-Received: by 2002:a05:6808:118a:b0:322:35d7:77f2 with SMTP id j10-20020a056808118a00b0032235d777f2mr9865626oil.79.1656668522093;
        Fri, 01 Jul 2022 02:42:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656668522; cv=none;
        d=google.com; s=arc-20160816;
        b=UzVuIY05NvRgci/7Dx6oRhTm65X5HU39wuLvmHjr1urL+a4yTjp5csP+xNKcUxbsYG
         vGgzIjd211/eUN3o2Nz+rROQPmxDYywgibCG4fN1SBv18SxLUXp09bwVu/x/EtGZ2SQ3
         eCGT9+dbdOCW6TKhiZP3A9W8YObYoLizbxDgBpA9p8IYs47ulfcN+D5OJ5kCmTZuAJMW
         MX9orEAbQc2P+rAC39r/PJZAQrHYu3WKexGuo88yxT/7Ddaqwof5vDI4IITBjQQP+bel
         Gtb8lukEKqr1Xuzk3OnaH68yIEg5w+RIiv6qS1M/27HvV7ggXpj7iAbTenB9UTyVQLPa
         wjVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7WkaE4UplPR9g6PXITQSoGxqocYmDuMj7V8IXNG4nHE=;
        b=rU3QSOliR5R2HlLZeYx3hB0Y7SZA+Sf8Gm8P+B5GHcXdS08MdzFnA2D6497wYAuUbD
         L0aMADHKiQLKF8NX7SUSiCMvVQt2W5be/KVNOhkcamlmpQikvtpQQ+vu8uogrSbovxqw
         vLdARSjkuHCH5KrXsRGkGSsZ1z+bPhaNXmQVDgQeOJMP/di6Z9AM5MdgMY82wdkSQhGq
         CXu6hH/ljmG1zhD219R+B50FKSu4aYpgZH4i9DtapYagvr81o/nMadM7bQPoQfaryKTy
         PttL0lNHMLDXLmLyUe2mqZ5ihIVKb34BTb61mC+NXQo0g5w9LFvWnIsUHh8dv8ViVnx0
         Ow8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="o/icSX7E";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id r21-20020a056830237500b005e6c62a483dsi1018502oth.0.2022.07.01.02.42.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 02:42:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id i7so3044807ybe.11
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 02:42:02 -0700 (PDT)
X-Received: by 2002:a25:94a:0:b0:668:df94:fdf4 with SMTP id
 u10-20020a25094a000000b00668df94fdf4mr13606867ybm.425.1656668521567; Fri, 01
 Jul 2022 02:42:01 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-9-elver@google.com>
 <045a825c-cd7d-5878-d655-3d55fffb9ac2@csgroup.eu>
In-Reply-To: <045a825c-cd7d-5878-d655-3d55fffb9ac2@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 Jul 2022 11:41:25 +0200
Message-ID: <CANpmjNOeyZ0MZ_esOnR7TUE1R5Vf+_Ejt5JRQ1AoAmhkCrVrBA@mail.gmail.com>
Subject: Re: [PATCH v2 08/13] powerpc/hw_breakpoint: Avoid relying on caller synchronization
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	"linux-sh@vger.kernel.org" <linux-sh@vger.kernel.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, "x86@kernel.org" <x86@kernel.org>, 
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-perf-users@vger.kernel.org" <linux-perf-users@vger.kernel.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Jiri Olsa <jolsa@redhat.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="o/icSX7E";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b30 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 1 Jul 2022 at 10:54, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
> Hi Marco,
>
> Le 28/06/2022 =C3=A0 11:58, Marco Elver a =C3=A9crit :
> > Internal data structures (cpu_bps, task_bps) of powerpc's hw_breakpoint
> > implementation have relied on nr_bp_mutex serializing access to them.
> >
> > Before overhauling synchronization of kernel/events/hw_breakpoint.c,
> > introduce 2 spinlocks to synchronize cpu_bps and task_bps respectively,
> > thus avoiding reliance on callers synchronizing powerpc's hw_breakpoint=
.
>
> We have an still opened old issue in our database related to
> hw_breakpoint, I was wondering if it could have any link with the
> changes you are doing and whether you could handle it at the same time.
>
> https://github.com/linuxppc/issues/issues/38
>
> Maybe it is completely unrelated, but as your series modifies only
> powerpc and as the issue says that powerpc is the only one to do that, I
> thought it might be worth a hand up.

I see the powerpc issue unrelated to the optimizations in this series;
perhaps by fixing the powerpc issue, it would also become more
optimal. But all I saw is that it just so happens that powerpc relied
on the nr_bp_mutex which is going away.

This series will become even more complex if I decided to add a
powerpc rework on top (notwithstanding the fact I don't have any ppc
hardware at my disposal either). A separate series/patch seems much
more appropriate.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOeyZ0MZ_esOnR7TUE1R5Vf%2B_Ejt5JRQ1AoAmhkCrVrBA%40mail.gmai=
l.com.
