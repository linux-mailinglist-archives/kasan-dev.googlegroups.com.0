Return-Path: <kasan-dev+bncBCSJ7B6JQALRB2NS632QKGQEDZ6FTZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id CD2FC1D3D47
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 21:18:02 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id s12sf6888otq.16
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 12:18:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589483881; cv=pass;
        d=google.com; s=arc-20160816;
        b=InYWSsla0EB/oQgGNyjyFK8O0fBrKFfskaS50Qr7gykBfA6CfziK4OgHuBPRYxPh9o
         Tl1Js7MZ98jlTuDczPdFwuTveVthUcN7uI17N/uknnSVwn4H1A+p52pxn+fiXgvbLaLz
         /IERFOTj3/O/bBEjXVrrRm3VCIzrzbBOR5P9UdBDLrWdHDtjar09goxafc1QyKGsqk07
         1nCevv3HS8yvdZhmbfVO5JcS4L7OSBO/f38wI+aLIFVgFMP7Cv97B3cka50gKxJC/OUL
         InYl17qLVjjc0Xj1whZGWa4A+gF3TmgMDx/haV/2LNIR/hWl89LUhxHKl2p2J+vAZz+O
         2iCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hLKdR8vhs2mYtTFj3VrYgSAWo1fPDotzXqONJTNayTE=;
        b=0JrRrF3mc/p4K9Vhjh/eMqX096stvnr45Qcii7lNzfau2yrgS1Cghd1tA43spD4WnE
         XpCoSiK7rC+izhXesFu77OLjjQzrekGnJ8KVBNnhW6A8SYAUfaQ6ugGqAwYWuRDFR5iu
         INebiN6mlTgMW2AsSr24aUNaz4Fk9vVNhD8DSbRHtI+1/R3X96QIio7qKAUGQ7MovGiH
         bc+GaC6vRiSN/pqK3LwPj1M0H9H96jX73FPjvO95zGxh6U/BsCfiB/z3869aJhGttmrx
         cuoo6kI2oGQx0zMBgoNwiAONiQUrzYxV3jdK6t6SNS5wlD2SamAfNY4Fc6tyu0CgpUTv
         YenQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Ms6OI7Nz;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :in-reply-to:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hLKdR8vhs2mYtTFj3VrYgSAWo1fPDotzXqONJTNayTE=;
        b=baXCjreBFRYBIIWj3Ec+EXmThpndd1X1lN8Rrq1G8Vmp5OEvXyI6spsSBS+cv+Zvrs
         LCNTFL33Sy/ly9u6v+AfMZLcosmkHAp1o2+ej7Vko/T5cm84tGa7RL+8d8rVZgY+Yo/B
         akknPw0HAjK75fj2OqlCejwQGX87PHGWFA9ISdE5p49X3wM+45htU10m5xQwsPpXHSIr
         7J1N93i+kzwF431yCiHzpOAOe6gCKi5m3QapFYhnOCE5DNsCA5kSO49nqJFMSG0/KIgr
         mFvmYm/ebd1N1cvVMKtIpGFRRsxKYyQjEkUfDEwKtfvZqCJwELnwmchEZep6FHy9Vzw5
         CFLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:in-reply-to:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hLKdR8vhs2mYtTFj3VrYgSAWo1fPDotzXqONJTNayTE=;
        b=GSkGm9MNvoIf1jSm227irbykGjsILF8Q8hpYu/2aQ3Qz61hFBa5u07kmkv72uD7pg2
         7sMRKr/cNXpin2mz7tZkjsSzzE56eailGDh1Oo8UV2WHd099jtqOqb/HQ6D9QYMgRYKL
         8Aj0ZVWOVzRofp6CTlMJnJ7S++jEzydWREv04GbAtau14l2QteIEHXSUSZ9AaP6eGFXr
         wOqfh564bXATztCHSDkuIbXUzr3nrFnelwYhQNuZ/dbfjUrLDiQV1q0KCWvDrXknjM4+
         HTDC4guzOZ+0v4KAqBvA2hsP+sl6zspbw4R3SEybK1af3Nc5V/3/7os2TKvgxPjYKoFz
         y4mQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Vs0d3LWvcBavjaItFoy+kCm1sMBczZjeeWs1CilV5ouWeyCZE
	gEYOoT97PFxyibzkeSNSMnQ=
X-Google-Smtp-Source: ABdhPJxg+b6xjZZVubzlDdbDlZtVSbXItOr8zv8Nk+T4PU4Wm/XfUOq1iNq4G9oC+EEetYgMUzUx/A==
X-Received: by 2002:a9d:7b4b:: with SMTP id f11mr4676685oto.126.1589483881794;
        Thu, 14 May 2020 12:18:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:a6ca:: with SMTP id i10ls205072oom.10.gmail; Thu, 14 May
 2020 12:18:01 -0700 (PDT)
X-Received: by 2002:a4a:8253:: with SMTP id t19mr4858870oog.69.1589483881487;
        Thu, 14 May 2020 12:18:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589483881; cv=none;
        d=google.com; s=arc-20160816;
        b=mxGGlPBDWaUWW48MvVWYV6TS/yp9yJqxflkNspMXXuKQKzHCf+UWsF+G4mAtNVpp9V
         13IZ+Zkj88Llo83eMGG/jrFa+bFf9N6Qf/+7qAi9Hghu2sFOLROiBnW8Pg+7w9+1c2nI
         lMV9izqb7ACpTw02P9CWsTS9Q1uNwrSLxSZFAKFdIthDHlts5hH2jiSHhGV8E8Hicwbh
         PUifnQxN4AjGMOFQRU+Jgb0YN0XxSRwz5C0Y1csgSsJiUU9z6+JZF3JXtfvTUc76HnMo
         XEu+xclXjFdzFf+0Bj6WN3X0gr3RrYDZeGuQ5mvmQAm2eX8cFgvCWC4NhweliCxVMcbc
         W4ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FpW3HF/nXi6w/16EHqbkmBkfp8I3MKk4SsBbt2uDHKA=;
        b=oCYMF+ROXGkiDCXuSHmU1k/YNKZazhjN1gLgK8/9gCyaju6p+W34HV5Fp0cywzuX5p
         a0TR9FmVz5StVsa2OH05M9CWLixrvtxSKmrG8kyiuRN+OMcJ40HhoieDeLmpO7HDzpZ1
         R72C2b+Iy1yOoKEj2ymEgNk2GsnwucBxl/DvXV6JSOXuOAs5zknOs2dnXl3DP0ag32pY
         4BRRh/8sxoQP+mqdtLOhyBRRs9nRgAKJJq/3i3irbN1ET9/lYONXkkAnDeMKOL+tebuz
         rYBkf9H1Csqi+MrK3liihLYU0w2gBIGX4xBrXRLDLoqwiQkRxUuEKjqDLBqyaBGQ62AJ
         9eLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Ms6OI7Nz;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id h17si415103otk.1.2020.05.14.12.18.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 May 2020 12:18:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-432-UuF2PNiJMLK52lSrNKaRQw-1; Thu, 14 May 2020 15:17:59 -0400
X-MC-Unique: UuF2PNiJMLK52lSrNKaRQw-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.phx2.redhat.com [10.5.11.13])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 48D0C1B18BC0;
	Thu, 14 May 2020 19:17:57 +0000 (UTC)
Received: from treble (ovpn-117-14.rdu2.redhat.com [10.10.117.14])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 39E9C7D951;
	Thu, 14 May 2020 19:17:56 +0000 (UTC)
Date: Thu, 14 May 2020 14:17:54 -0500
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Marco Elver <elver@google.com>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: ORC unwinder with Clang
Message-ID: <20200514191754.dawwxxiv4cqytn2u@treble>
References: <CANpmjNNLY9EcSXhBbdjMR2pLJfrgQoffuzs27Xrgx3nOuAUxMQ@mail.gmail.com>
 <CAKwvOdnQaeQ2bLqyXs-H3MZTPBd+yteVG4NiY0Wd05WceAad9g@mail.gmail.com>
 <CANpmjNPLgFdFpHzj5Hb_1CfFzPMmqy3z1O98N=wsr8kQ1VS9_Q@mail.gmail.com>
 <CAKwvOd=0Ducgnkf8tzNGH10_UJSk56Ff_oSyGMddBCyG3Xt5Gg@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CAKwvOd=0Ducgnkf8tzNGH10_UJSk56Ff_oSyGMddBCyG3Xt5Gg@mail.gmail.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.13
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Ms6OI7Nz;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 205.139.110.61 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Thu, May 14, 2020 at 11:34:52AM -0700, Nick Desaulniers wrote:
> > The stack traces of the races shown should all start with a
> > "test_kernel_*" function, but do not. Then:
> >
> >   sed -i "s/noinline/noinline __attribute__((disable_tail_calls))/"
> > kernel/kcsan/kcsan-test.c
> >
> > which adds the disable_tail_calls attribute to all "test_kernel_*"
> > functions, and the tests pass.
> 
> That's a good lead to start with.  Do the tests pass with
> UNWINDER_FRAME_POINTER rather than UNWINDER_ORC?  Rather than
> blanketing the kernel with disable_tail_calls, the next steps I
> recommend is to narrow down which function caller and callee
> specifically trip up this test.  Maybe from there, we can take a look
> at the unwind info from objtool that ORC consumes?

After a function does a tail call, it's no longer on the stack, so
there's no way for an unwinder to find it.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200514191754.dawwxxiv4cqytn2u%40treble.
