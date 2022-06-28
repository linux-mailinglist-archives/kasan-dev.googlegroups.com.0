Return-Path: <kasan-dev+bncBCQJP74GSUDRB2O25KKQMGQEIDSPYUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id E1D5555BF12
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 09:27:39 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id b13-20020a170902e94d00b001692fd82122sf6581082pll.14
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 00:27:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656401257; cv=pass;
        d=google.com; s=arc-20160816;
        b=IcfXD1Mw+xDY2bSykPwdDy2cC+QnmbbnJMFFAFdtXp8b8heGV+IKzR6zSf2bSG4Cep
         EjhtO5iOgSEjs9smzJTuui5CLCFiZmelVvLlTzSUMBmJPz+RcaFO3olU+/J6n9VhcToN
         uQ45KkMGFekINIKyegWVi1NiTdOchfxW8aGJEDLT1gR/htXOJzWRGOlLI1WKXipIX0E0
         gHwOE43Poq5/Uwka263mpmQMQKntMdBVF9pbeGwq5SLwGbt1VUanAt3axgX0/+8VEKVs
         U/6JMLvem7nv0Osj67zpx3Pg1kvCmSOMtBr5j1q8/j/ptBNtF/by2aKVDsYZ3InlmgJ2
         Ly+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=fIr20AkxLyqu9arrJSVw3UINlTwZDrXqQedjFkOsJHY=;
        b=UcCFjdVFdf9PItP35L4H+KGBa8jRVWWHwTlbPwnWeFjwz+zgRoPBv0sBrE3/9vQf8t
         Q3FlmLSQGeMEmI7QCTxphiU1DuSxL9igx3QO6Ja30ulUQPxU0YOWF3uLZMzIclScU2e/
         Y37jaWYqPyZg5bKt25C96hAmiB3sNQndilgJtmHcpN8+ValAdcaKjIHoCrNkcSKatYWJ
         wPGZS851HFGe1K6G3HvSV8Wkl95Ce8o3vUXahZT2VdPOJ98HSN3bc55A+J/kyBgJjxeT
         imBzCY1n9hCk5gq2iZswcul2cS6upp8v/ULIt9BVy5haYThb10iwfqAqea2D9cE/ErRy
         sDwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.170 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fIr20AkxLyqu9arrJSVw3UINlTwZDrXqQedjFkOsJHY=;
        b=ZCX/H4xBraXKLhxfsVxOBDrt83kD8JtXIRogiPSE2i4EsZPJvHAIInTR3uwAOY0Y3V
         0R6QpC5S8pq7STrKtQKzIFnGY8dKWDSBm9hbOyXXtP/lvub0yIbw1PsUDol0b5wpml1c
         0IlwHMFEBqgY2Idw/aVaKvqsy5ubY9XcFSRcxnEYrkKm/dwMtxbpL1wdD+BhRmzn/PpX
         3a1D1Iz+MHsW4Eb/lQ4MJPS9ERp/j+elvOYS4mkgcZFXnK7JL70hVJb32GHNLBIC3j1L
         MdUiZzOntBb1W1GSGDnjq/7JVXFJpY8uomlmR9587D7phLOtSNF1bUy6sUbCg4dd9J5f
         6a3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fIr20AkxLyqu9arrJSVw3UINlTwZDrXqQedjFkOsJHY=;
        b=Xob3VY7qkYHNpwICWiJomWF5SDx0s01oyvzO878uxmsV89SsQn+JygSjzjZ+OYm6AC
         RfsxFqz5Rc5/HtG9zGx0Gagi1RSGrpmmvLEsHerC0uAMTpH0Cs6oexGMmas8qLZdXd+W
         WhPmTy0CGMn7UlhESAztQ+FvDGn9yRdQ6mxeI4FEUMh9GiCpBT1ff06f4ZthmHI+HLzz
         UEfesmNdLx1dJmqs02IWcAgTSbNNrW/sk3vqohuYP//OipVYoSiP1g1IqT1DVQsPhW8x
         rOBMehtaJTdLalA3wf+2SVej5FdIMuwbc+9NUO1Fm+9IvaK4vHZCF+6grL9huojS6bEb
         mFAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9MbGHxE+rmeHIe84ujLmegeUtZd0txNSwOJZ7kxEEM8Pm9/RZ6
	OZ0LR5/NpNtVpwyLVZgYhJE=
X-Google-Smtp-Source: AGRyM1uE1TeWOaomFg/SMcKp+JspFZ80Pxvphu/IKRI7Y98xFLrgtAx6I4c6QN5DYmdhab7hsghBtg==
X-Received: by 2002:a17:90a:ea07:b0:1ec:fe4f:f850 with SMTP id w7-20020a17090aea0700b001ecfe4ff850mr20173721pjy.59.1656401257307;
        Tue, 28 Jun 2022 00:27:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2a85:0:b0:411:442b:bb79 with SMTP id q127-20020a632a85000000b00411442bbb79ls1265270pgq.1.gmail;
 Tue, 28 Jun 2022 00:27:36 -0700 (PDT)
X-Received: by 2002:a05:6a00:1150:b0:524:dd4e:dba2 with SMTP id b16-20020a056a00115000b00524dd4edba2mr3294568pfm.41.1656401256521;
        Tue, 28 Jun 2022 00:27:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656401256; cv=none;
        d=google.com; s=arc-20160816;
        b=hAkKub8VTasiUCTwAxOfZ5wuR89m/2XiVmrRKEATPct06ETN9Ntlf/IyiMdhpMSUj2
         M03b7f6xEKBbEbvrnA7ICqh0gplKPiXBXyb558iylUd2slqYMZNx2vxDc8m20sSut2rg
         JcBxolz/CKYeBVIPZb56h6qSN+4WFoj6TBDRX6n5khZMt06v1KxvEvm8Cjn5hVghU0Ve
         7wcFwczp3PGL5PBRjjvxz+H4iYRB28HaguROce5wdgILRkkVMbDfAIx+6HVn3P9jDRI2
         F1WLg2MpJxTqgrEaMUlcYfPJo3Hqsdtsyx6eqH+uhkhol5+2cNpHgglTduA2EXXUrUXo
         x71w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version;
        bh=hwgLtruPC06mcRCnQAsf+kJqHCP1mf00hTNnpiQ34M0=;
        b=fW5YAcjT0IstzJHg4GVEJ/X+UMfD0PL5UOiRAV8Ry/6sPPkMf7NekVfroOzQmERzon
         yv0MCr7AhQwlmOXxIrhCL9gwaaXw0UW8jELHv7p9Wr5yZCh8X+uj7DaLPlcvW+FpDUMH
         e/aDMrd13oRHzOvUOn/9rr4Adcfk1av3R7MP8EK5D8DjIqzc853k9qeRUOTog7uQyFsD
         44l7XVXJv3oNl5bg2Za2zNg9M3HfrB11QuZ5coKtFyLUJkRglNcsmKluuvt+lROPk8OK
         CTSUES561THoGS2c6Nf2pAcLZERgYM9/UAMLg62n1JbPeUAVfQowR3macvACC440EwpV
         tSvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.170 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-qk1-f170.google.com (mail-qk1-f170.google.com. [209.85.222.170])
        by gmr-mx.google.com with ESMTPS id ei22-20020a17090ae55600b001ec7258c14esi34955pjb.1.2022.06.28.00.27.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 00:27:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.170 as permitted sender) client-ip=209.85.222.170;
Received: by mail-qk1-f170.google.com with SMTP id z16so4150097qkj.7
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 00:27:36 -0700 (PDT)
X-Received: by 2002:a37:a488:0:b0:6af:4bb:fea9 with SMTP id n130-20020a37a488000000b006af04bbfea9mr10480384qke.380.1656401255644;
        Tue, 28 Jun 2022 00:27:35 -0700 (PDT)
Received: from mail-yw1-f175.google.com (mail-yw1-f175.google.com. [209.85.128.175])
        by smtp.gmail.com with ESMTPSA id g1-20020ac87f41000000b002f93554c009sm8794794qtk.59.2022.06.28.00.27.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 00:27:34 -0700 (PDT)
Received: by mail-yw1-f175.google.com with SMTP id 00721157ae682-31780ad7535so107492447b3.8
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 00:27:33 -0700 (PDT)
X-Received: by 2002:a81:a092:0:b0:318:5c89:a935 with SMTP id
 x140-20020a81a092000000b003185c89a935mr20762801ywg.383.1656401253054; Tue, 28
 Jun 2022 00:27:33 -0700 (PDT)
MIME-Version: 1.0
References: <20220627180432.GA136081@embeddedor>
In-Reply-To: <20220627180432.GA136081@embeddedor>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Tue, 28 Jun 2022 09:27:21 +0200
X-Gmail-Original-Message-ID: <CAMuHMdU27TG_rpd=WTRPRcY22A4j4aN-6d_8OmK2aNpX06G3ig@mail.gmail.com>
Message-ID: <CAMuHMdU27TG_rpd=WTRPRcY22A4j4aN-6d_8OmK2aNpX06G3ig@mail.gmail.com>
Subject: Re: [PATCH][next] treewide: uapi: Replace zero-length arrays with
 flexible-array members
To: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, dm-devel@redhat.com, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	"open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>, linux-s390 <linux-s390@vger.kernel.org>, 
	KVM list <kvm@vger.kernel.org>, 
	Intel Graphics Development <intel-gfx@lists.freedesktop.org>, 
	DRI Development <dri-devel@lists.freedesktop.org>, netdev <netdev@vger.kernel.org>, 
	bpf <bpf@vger.kernel.org>, linux-btrfs <linux-btrfs@vger.kernel.org>, 
	linux-can@vger.kernel.org, Linux FS Devel <linux-fsdevel@vger.kernel.org>, 
	linux1394-devel@lists.sourceforge.net, io-uring@vger.kernel.org, 
	lvs-devel@vger.kernel.org, MTD Maling List <linux-mtd@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux MMC List <linux-mmc@vger.kernel.org>, 
	nvdimm@lists.linux.dev, NetFilter <netfilter-devel@vger.kernel.org>, 
	coreteam@netfilter.org, linux-perf-users@vger.kernel.org, 
	linux-raid@vger.kernel.org, linux-sctp@vger.kernel.org, 
	linux-stm32@st-md-mailman.stormreply.com, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, scsi <linux-scsi@vger.kernel.org>, 
	target-devel <target-devel@vger.kernel.org>, USB list <linux-usb@vger.kernel.org>, 
	virtualization@lists.linux-foundation.org, 
	V9FS Developers <v9fs-developer@lists.sourceforge.net>, 
	linux-rdma <linux-rdma@vger.kernel.org>, 
	ALSA Development Mailing List <alsa-devel@alsa-project.org>, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.222.170
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Gustavo,

Thanks for your patch!

On Mon, Jun 27, 2022 at 8:04 PM Gustavo A. R. Silva
<gustavoars@kernel.org> wrote:
> There is a regular need in the kernel to provide a way to declare
> having a dynamically sized set of trailing elements in a structure.
> Kernel code should always use =E2=80=9Cflexible array members=E2=80=9D[1]=
 for these
> cases. The older style of one-element or zero-length arrays should
> no longer be used[2].

These rules apply to the kernel, but uapi is not considered part of the
kernel, so different rules apply.  Uapi header files should work with
whatever compiler that can be used for compiling userspace.

Gr{oetje,eeting}s,

                        Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k=
.org

In personal conversations with technical people, I call myself a hacker. Bu=
t
when I'm talking to journalists I just say "programmer" or something like t=
hat.
                                -- Linus Torvalds

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMuHMdU27TG_rpd%3DWTRPRcY22A4j4aN-6d_8OmK2aNpX06G3ig%40mail.gmai=
l.com.
