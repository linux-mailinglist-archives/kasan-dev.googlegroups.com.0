Return-Path: <kasan-dev+bncBC27HSOJ44LBB75FZWTAMGQE3JXM2CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DB747755DC
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Aug 2023 10:49:05 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-51e55ff2fa1sf13303a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Aug 2023 01:49:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691570944; cv=pass;
        d=google.com; s=arc-20160816;
        b=rf4TCk4tGC04Bbd7wNY23raycb1nMKOYzk7U4XABTIeuYLT02FMXmX1gWygP7n9hFK
         E/B9jqJVAB9Bza7F8PokOhu21rWX3KjKjYmCuvU8W5/wbVe2aWCb1NZa9ezyqFcTiPXT
         iXsnsn9mDuSbb7bJ5EAImuF56njHdtJMEqWJ9DBy/bgjQPDVE/fc6F0Io/mCFjBE0Gnc
         sOopYktzkLOrvKejgh6kNkwT7OKe1ptNkl8plywNAFlkIQ2gjvHreNTGTsCErh0kNCvW
         DihjBssW4sWHLeNhl2tq6JcbXNHNFPc8mmYKq+HzWQrzLqCStakWHLIJpHx88uoH56rv
         j5MQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=3jev1brsnqD/dDbENX2Rp7uSvndJsoYZYD/jTH31y5g=;
        fh=JIkFQASawXMCqBko/fC7zmc/okISu6jjFIL1x4yRIiY=;
        b=w/VHmvXWFD4omd2s3I1xI/WX3jEQ8tbEvZ0vWhp7vd5ka1OOPg/p6dag5wgjFyHMUk
         yQ2RoA1Q8nc1OwGFXckVTdFiLlwfyC23G8WDF5NJupYPaS+L5vU9OL0R1afkS79VwFGx
         mD5vKOos6LXzdROsM0kU14StmEz5IB3FohQt3yusJWCesq4tQdiIqSKP6fzs609ybOWS
         l+1stmix6AnICV7+CVw6XR3mwv2VRDxmXkbDs62Ci8jN6fQ05WVQ6nVyy1rC1rUsvgS6
         PcWsIbxfvmTZW6m/BAqzPBKGSCCtEY0o9Hl5yx/QLqD1bldKBqT5aVaYhfH7yqAjE39L
         KIrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691570944; x=1692175744;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:mime-version:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3jev1brsnqD/dDbENX2Rp7uSvndJsoYZYD/jTH31y5g=;
        b=ny7FjpAgRYOV3i8aOzEGEsa3ftaEi4/Sy4cbIlibztnqUPma2eIppMx9rmnm/AzMm5
         E1Tt0YtVySW3CjsjenBN8YQj5c7Zw48BWarfpyK9XwRBsExXDyiP4xxQCtYFwnwjOgJN
         hxLhJb0WqUiLGjwICS+It1OmZng5+h8GjYSL2dIx0z1217ytLP2115bTNFGx4SVcLi7p
         s0d5kjUOq4rTDeO+rBJdQf1IoK+5PmeqjYcqKGO+QyGopvm+WSsMSVvUmkVXHa0cD1/p
         W7tqxQZts/1wcsgbbCp8QTy10DEd0EYoStv1LxiGUZp/I1a3JgGpQ0jjDG+r74ahxWXH
         AW8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691570944; x=1692175744;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3jev1brsnqD/dDbENX2Rp7uSvndJsoYZYD/jTH31y5g=;
        b=jOG2NgI+7oQmDp2Oo3Tm4gnJfH0PD3SneGTek+to3xWU5JN46x7N/c/FuGK29SPcQU
         9hTnHWs86+RbBONjDwQK1kqBpHNi8N6tDsOKe3cyWUibu/4gPLuyS7HwZILqOqIQl2nU
         LSU6EOrSBiHlQ0GePUgXCZ26homTCQEGMSkVANr/15r6yFrRzqSUNUqH3WnvrsHeBgM2
         PeP59iTPro+Wccq2NuBbNfl5IOUPArsaacX2R5sobirYzs9/1gIngo2qpMigykI252Qb
         URw8S9KUnILhNhCCIhj9ZqI1cxoA7FwlKFH+b2nn/o+y4JCbeFAdoPmz7Lgt+NNXntIA
         Ly7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx/SuznHsUPre5fJ+HaxWL2VRGzERJ8shD692hfLpiFrdghSRJd
	IlKQA6IXS7CCobTc00oPtZY=
X-Google-Smtp-Source: AGHT+IG1vaLJvVDSi49aq3k/IXeSjTYN6kfvYQmo+BHUDz0lqU9Mqi4R/qcKQenneS3svyyH9WViWg==
X-Received: by 2002:a50:a45a:0:b0:51e:16c5:2004 with SMTP id v26-20020a50a45a000000b0051e16c52004mr56077edb.6.1691570944100;
        Wed, 09 Aug 2023 01:49:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d348:0:b0:521:e522:ba52 with SMTP id m8-20020aa7d348000000b00521e522ba52ls152623edr.0.-pod-prod-08-eu;
 Wed, 09 Aug 2023 01:49:02 -0700 (PDT)
X-Received: by 2002:a50:ef10:0:b0:522:1e2f:fa36 with SMTP id m16-20020a50ef10000000b005221e2ffa36mr1749833eds.28.1691570942495;
        Wed, 09 Aug 2023 01:49:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691570942; cv=none;
        d=google.com; s=arc-20160816;
        b=MyAu/14LX6ea7z3fPD2Z0+vwxY128xZ92yS6Uf1yt4i39LntUIkEQra9AFR46UI04I
         MivRRR5zhQEK97tv1EfSk0FekaKAjIqZFJPl3HlX1qTroZ09tj4sVM+UmVWklMtScuEI
         I2o2u9326jjZIFD8MSFhdO4Sf2Ptd8R2uL1z2U0PoOwD1/PvcPVuQEVcoDIhYSHjuQpg
         XjhvU3+fMPY86sqoDK6hsByh4uVAJWaWSfhpqFpllW7n76wRHrL+UlBQb/IvJr2jqUeu
         Ue174asyv7OJWxoEe1/xJfZVyv/QsSg2MQPP0mUTLKEQGrqVvR4xN+N1PTXk58QcSsSg
         AFNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=rHucP+uSLAvJUIIkbPSdjoVqh8hzY5NZq+h0xCfEcWQ=;
        fh=JIkFQASawXMCqBko/fC7zmc/okISu6jjFIL1x4yRIiY=;
        b=Jyn2rnM3bp9G/ueiadW8NAJPUTZGVghVPtpOiPtBOf3fQdr91KQrHSqgQooVt0DXK4
         TL29hkAVquMgRYTxjY1riDN1ZbRsmgnEgzJ/G2DZ/UgYkE2+Nio/ej656AhSIMWVnH5+
         /rfnE60MGOZIwtDEv1wYlXJxX3+SM9uNi8CXZd1zYCFsp+uIK96K7gG3Mt/XSe779jYg
         yRC/klWz9NfdrwxGOFUIS+c7R+cWrGRb1Uhe23RI8TqwdZXO1Fmxm73XGtgtOc94NwZt
         OOYPX8totOPh8kB+wyWuhHELlv+dVPVQVozEz3SCaeNZxhp9dbCqZqi0u8Axj74rzhuE
         QEgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.86.151])
        by gmr-mx.google.com with ESMTPS id d37-20020a056402402500b0051e6316130dsi1004549eda.5.2023.08.09.01.49.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Aug 2023 01:49:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) client-ip=185.58.86.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with both STARTTLS and AUTH (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-265-c5R6OnldN9G1uT9xX-Cmaw-1; Wed, 09 Aug 2023 09:48:57 +0100
X-MC-Unique: c5R6OnldN9G1uT9xX-Cmaw-1
Received: from AcuMS.Aculab.com (10.202.163.4) by AcuMS.aculab.com
 (10.202.163.4) with Microsoft SMTP Server (TLS) id 15.0.1497.48; Wed, 9 Aug
 2023 09:48:54 +0100
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.048; Wed, 9 Aug 2023 09:48:54 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Petr Mladek' <pmladek@suse.com>, Andy Shevchenko
	<andriy.shevchenko@linux.intel.com>
CC: Marco Elver <elver@google.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	Steven Rostedt <rostedt@goodmis.org>, Rasmus Villemoes
	<linux@rasmusvillemoes.dk>, Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: RE: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Thread-Topic: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Thread-Index: AQHZycNoqz0YrpkIvk2kVFpZOdRD+K/hpuug
Date: Wed, 9 Aug 2023 08:48:54 +0000
Message-ID: <900a99a7c90241698c8a2622ca20fa96@AcuMS.aculab.com>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley> <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com> <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley>
In-Reply-To: <ZNHjrW8y_FXfA7N_@alley>
Accept-Language: en-GB, en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: aculab.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as
 permitted sender) smtp.mailfrom=david.laight@aculab.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=aculab.com
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

...
> If you split headers into so many small pieces then all
> source files will start with 3 screens of includes. I do not see
> how this helps with maintainability.

You also slow down compilations.

A few extra definitions in a 'leaf' header (one without any
#includes) don't really matter.
If a header includes other 'leaf' headers that doesn't matter
much.

But the deep include chains caused by a low level header
including a main header are what causes pretty much every
header to get included in every compilation.

Breaking the deep chains is probably more useful than
adding leaf headers for things that are in a header pretty
much everything in going to include anyway.

The is probably scope for counting the depth of header
includes by looking at what each header includes.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/900a99a7c90241698c8a2622ca20fa96%40AcuMS.aculab.com.
