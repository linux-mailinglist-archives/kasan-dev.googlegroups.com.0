Return-Path: <kasan-dev+bncBCR5PSMFZYORBAV32SOQMGQEVGOISOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5668965CD1D
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 07:32:36 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-1505e7d844dsf6132165fac.6
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Jan 2023 22:32:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672813954; cv=pass;
        d=google.com; s=arc-20160816;
        b=jlMOnF4QQopKBB+YkA2uVmXqtmImHujZd9EOWwcUef8peeS/hwiIAg6RjrmiTkKJsy
         jVPHDpqfIxs5ahYEAyPBho07enhiEjdge5TQMGa9/BIm0gd7DjvtTuWJfizozaNlqIW4
         hGFS4KngIDi4gMBeOKjKji+sfWIH5Fl9mjRzUct5CS5GI33eHUu9hq2XZ4wQjfQimja9
         HTPdtCPxNNAsTnt5OTHsK2WnRVGLUbP/NJpbp32IN3Yocj1S35FnfLe6IK1fYblLLmZc
         YBXRaBzluA6Rkg6lOlyVdfXXHeXnp1GZ+/ngygMYbHFlsEzhtWzSfMPx01vFJjR8JZG+
         49SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Fi4TSnvPTPgIzhjEjAMHYjd6hGmuj42H3mVmncpyQ/g=;
        b=J2bf7yzU1gcz7JDyIzTr0z4hy1h0YiGLjWcQHCidXa8cmHSWlpUvKCoZ8n1/Mx3rbs
         3WPXsJGmVX43vjz0DhDNTcpkNLg7xTbgOKJJ9t9GJU6qFyfTfbTQsetxFeLLcLMPXbXq
         ak+6ikpcPYvMKXojSDrsAO96SnVVrRKRu5QJry+Sg4WmERDjC1Gj3FlVQEWvwhiYPTLM
         7lwjNNdHZ3mL3MmnIyWJ3W2NES4j5zvkOmdp1yPskh/ahfbjhjQoeRRTPYSqMShLPVOm
         s5qii1J4xTsVRn87U+WzlVn5W0rCWNEFzgCBPkaFhv9j6Ec5z90M1O1EVuvqicXAJeBG
         EGaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=O4NB1Mbe;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Fi4TSnvPTPgIzhjEjAMHYjd6hGmuj42H3mVmncpyQ/g=;
        b=igU/D6em+GNnINl4jRUSWTuemJXaVyICzS6pOOphCmVFxvs4sY7LBHUyt5Mx25ry3l
         xenOoo5v5lGF3jcMW2g9MpEpGtj6F0n0Y16EDsIHewcwNUZkXw5or8VI5s96In3HehEk
         nzUCoISs75vI4IgSvMPkP21vQ7UwAuMBO/buN2Lo+f25wN9Vh/4ctO9Ayk9ZXKLQMhBz
         uDVHUTwAnPV2worV2sC1SMFTQQWKoKvKHbaEAhVcQRrX0TCrvDN5+XES6HR3DstfmlKd
         1E/MCBJhn1w+0LFkU8yLspzQXfQuwDAH9sjhGjQnICRH7whNfAYBsFuNjkqIKJ0U4hO8
         nUVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Fi4TSnvPTPgIzhjEjAMHYjd6hGmuj42H3mVmncpyQ/g=;
        b=kB82k4uJXkpNZ6HaZta7q8H6YHcu0ra3wHvPZRcPt4KPpnVdoHg2g+oIaExiKHqOfi
         5A09zhr+zNM65F1Z2qpJUhg0fYyoS5d5nuAYfaWWbT+YxppLgewGqjjMDqMOCXVCBz6V
         zWoZAxK3FwQsyuoncTGJo8KNsOoPeSsn0v6dzcLuW4tgHOmuAFdGXC9lFE0qWVUqpHqr
         60mWYkbGzfwxI7MgIhrWZIPY3gjfa367eYias1+R9VgC5bCecnCWUQAoXY3lChUYJ+45
         N+nc+pxk0K1fX7FP2b3p45ifHM0gp9wR9biSccModMbx215fnTiFnNA5KSX8FLAq46By
         o1Bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krlpRMKUIesMcbHM6B8EZ2z6GUXCbwjJ30+hMzop7r9QNWJumut
	jzKUj3HJVKHXgS7tYfCinYQ=
X-Google-Smtp-Source: AMrXdXs/QghkW8lsuve5PUavFGumy+PvPUihRRHm4dS/31+VRTFJ13ACQ/OWpsncWUTjXzs6jUyMZQ==
X-Received: by 2002:a05:6808:d4c:b0:35e:2395:89b0 with SMTP id w12-20020a0568080d4c00b0035e239589b0mr2194904oik.13.1672813954646;
        Tue, 03 Jan 2023 22:32:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c782:b0:143:408e:349 with SMTP id
 dy2-20020a056870c78200b00143408e0349ls6050888oab.6.-pod-prod-gmail; Tue, 03
 Jan 2023 22:32:34 -0800 (PST)
X-Received: by 2002:a05:6870:ed93:b0:13a:e032:46d2 with SMTP id fz19-20020a056870ed9300b0013ae03246d2mr23668900oab.6.1672813954234;
        Tue, 03 Jan 2023 22:32:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672813954; cv=none;
        d=google.com; s=arc-20160816;
        b=aC0e2zyqA7KmYcSvu8qnACbfbhQJHzzF/bvqtrNjlJZ2RyP/Pfx9PpHA84o6uoDaEQ
         HsrpaoQSuAt4uIx4GDpq3pGx6YIkbCIiATuRN4BEhZargpRDOrzUUCnYDpaOvcXgWgFS
         vxVM8jjZ0MWfYOXzmE80uP36zzM8gBc/0TuujepVyHFaWLnEjw8jrpU54zwxm1nfdr1F
         WxAPovLeo0LOLBFBK+6kYW54OgyVKdPuWP0gv/HYZMbr2FXsa5UUPfZKhFLPDIcotr8J
         pHffwRn2J7ic6LZ4FiJD+/KkKEG5Ctk0vqmG9FdJl6Ol/D8OG3Cq43t9JD5pLRyesxp/
         kpuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=yy1Ja7/gN5t53Ult7n0CLa7oWDzh1zFh5lkAWxcgdt4=;
        b=e8E/XHts93mYe275qo3XLFrwZPmIHlXJ0O1dPJTBhyh3TwdQ/Fj78z1Gjl5suNGoR8
         iA2Ybz+R3BZ8drjvs+H9P80d2yK6Ch12HncdOhY5vglfQc6b8vLDfTwYI3yYfdCIM16z
         RHkWzWVzaWGed06Ne8GB87XqnlCMpERzz6YaB+e4Ni/Ooy7jTxjkcsJbAeTZjC2pJuhn
         fcoEpd64M+V3kRcg526ULdlUeBNtv7yT+CqJdAfnyMZaCg5GwsXQ/IgJsQjUFPmp11D+
         zJMrn6nSg5n8M/fe8UcjH8IwKEuXcWRJBvjTUNbyXMQCTsaXZIyocaHY9VhcL0J4A3UP
         NcJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=O4NB1Mbe;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from gandalf.ozlabs.org (gandalf.ozlabs.org. [150.107.74.76])
        by gmr-mx.google.com with ESMTPS id ej18-20020a056870f71200b0014f9cc82408si1772971oab.5.2023.01.03.22.32.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Jan 2023 22:32:33 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) client-ip=150.107.74.76;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4Nn0C04FZWz4xyt;
	Wed,  4 Jan 2023 17:32:28 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Geert Uytterhoeven <geert@linux-m68k.org>, Rob Landley <rob@landley.net>
Cc: linux-kernel@vger.kernel.org, linux-media@vger.kernel.org,
 kasan-dev@googlegroups.com, Linux-sh list <linux-sh@vger.kernel.org>
Subject: Re: Build regressions/improvements in v6.2-rc1
In-Reply-To: <CAMuHMdVX4Yz-zHvnwB0oCuLfiNAiEsSupcyjfeH+1oKTfQKC9A@mail.gmail.com>
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org>
 <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <397291cd-4953-8b47-6021-228c9eb38361@landley.net>
 <CAMuHMdVX4Yz-zHvnwB0oCuLfiNAiEsSupcyjfeH+1oKTfQKC9A@mail.gmail.com>
Date: Wed, 04 Jan 2023 17:32:24 +1100
Message-ID: <877cy24xon.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=O4NB1Mbe;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as
 permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

Geert Uytterhoeven <geert@linux-m68k.org> writes:
> Hi Rob,
>
> On Sun, Jan 1, 2023 at 2:22 AM Rob Landley <rob@landley.net> wrote:
>> On 12/27/22 02:35, Geert Uytterhoeven wrote:
>> > sh4-gcc11/sh-allmodconfig (ICE = internal compiler error)
>>
>> What's your actual test config here? Because when I try make ARCH=sh
>> allmodconfig; make ARCH=sh it dies in arch/sh/kernel/cpu/sh2/setup-sh7619.c with:
>
> [re-adding the URL you deleted]
>
>> > [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/ (all 152 configs)
>
> Following to
> http://kisskb.ellerman.id.au/kisskb/target/212841/ and
> http://kisskb.ellerman.id.au/kisskb/buildresult/14854440/
> gives you a page with a link to the config.

It's possible there's something wrong with the toolchain setup, I don't
know much about sh.

But it's just the kernel.org crosstool sh4 compiler, nothing else fancy.

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/877cy24xon.fsf%40mpe.ellerman.id.au.
