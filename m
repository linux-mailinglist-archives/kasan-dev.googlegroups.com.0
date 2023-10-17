Return-Path: <kasan-dev+bncBDYJPJO25UGBBJGOXKUQMGQEN4I42MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id E395F7CC760
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Oct 2023 17:24:21 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-32cbe54ee03sf3559088f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Oct 2023 08:24:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697556261; cv=pass;
        d=google.com; s=arc-20160816;
        b=JDo7CgirExHZeHJBFAg0n190kqzNsXliwNJGGgnieFxoKo2Kyqjmudf7pPxPN+VtfM
         p6f8EAKwxsQ2f4ctHMtWsdISzyMwMPqTGDQ1+hinUvhCNKZrY5HBjMUPUh9LuSphyVWC
         ja2R1BglXuFNkW3VwfLVK9KyXIbT0R3vgZ9TrzYb4RNWNhL5dVmp+bpuF/83T4UYEige
         sO/gw+2tLwTNX1MPT4HBkoymzf6wDsf9Db9rdgbf5Ot3J0LhpQHWny3wH2VAREonC/cW
         DizRVp34QHGA8IULcuI2M2ELIiZcvihaI/+gsGb5AtO1/TjRH7VIk0po5j45hyVBeE0W
         eb3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pgEomTskP5vqOjXYmHk4OxS5YOY+LHcUCGZq48M+tsc=;
        fh=vqXZi9gxeMzqmPnv/InKLu6SV6iKt+SKklRsePoGBS8=;
        b=auVCSah7xsjnzhmefkFwWni6JfPm7bzphAX72SIh/KlkacqP05hMitEZX/HDrOnLbA
         7FB5k29XOWSoVammhsIqouC00YDNA8uqT4ZAvc1bmo4/qXk3oplaIC2P9q1Gj5TthNOw
         1cxKQzDxYqs5UB7JiREF8Pj61gl8+OAsprfgbhHPRQLLO+BUsoTgYpNNzSM2U1pvwjOW
         sYcye0LaiY8xoYT0RGQz3cDHGSfJWW8SZUn8REU4Sw+9hMtzteKH1Pu0oTWBQ30dyKm2
         QeN+696Hlg7CNwpfJ7zJm8etCYgOY0HAa03MMx5RhrOpvGtCc2xGwLukHrGsP73KpQU3
         9/zQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YW5yXih0;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697556261; x=1698161061; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pgEomTskP5vqOjXYmHk4OxS5YOY+LHcUCGZq48M+tsc=;
        b=twA59IgyqdLyyJPHNeUcnribvStAVZRKxxFo3lIsOTiPd3xdrYzIeAXbYa8LbstTYQ
         YbjYscAr7Ipr1dwe9LxQ+oIb4MoY0m/xD3+OqJ8NpucvemueaYMM2ykoqxd43qDIqaK9
         dfF5P0DeTru0aYqIyogjyqg2wUuj3WIVsKCqGo6y70Yp/eSQYhFs44aQcBALOmKgo9tn
         quhOIOy5tX+GWjQ5f3d6rHZ2x5iEjC0tLYQEncmXovYbUkrDqoskX4615ha1YuFiZ92D
         +XoXZueJHXzDF5f0FbNU3M3V6La/1rIykwx/WNSS19M0J3YTiHFjb9UlMmyPv7vtcJko
         AgIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697556261; x=1698161061;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pgEomTskP5vqOjXYmHk4OxS5YOY+LHcUCGZq48M+tsc=;
        b=LVgBts/ul/XOOfJn6E42c65TYiBCP+jmsYKw8Ez+cRvsH0+BVYyogSBjf2nlwGYMnX
         BrUJtpSI/IsSaW9d36xFQjHeTxF31shKRJvYg2sCAfFxnsCdBW43AfXK3/9xCGBJjRRN
         mYuPHVk7p9/vr0Wyg4O1f4eYhIiPV05fES3x0YyHsflTLUoKbCwc7gRkPupZW123RNaY
         ofldZfh5QCGIMXz4z7ZLEkCG732UDjX3KfMZLsLlw4j2jmLMCrAjG2iArDgGTUUSmHUl
         wet24c2bHi7AONQ6Y8B63usMtHmalgMHZyKb6IhdWHbKB4TwrLDgDQb4ZkZ6sbKGIN+z
         eTag==
X-Gm-Message-State: AOJu0Yx1F6XtbQAbxJrE2RQnNLDr7no0LXv0c47/CUnUwI/EfXT6YB3o
	qFrL9r7KjIIMm71fJuPT+UQ=
X-Google-Smtp-Source: AGHT+IHIzwFbgnmj5PjKtu4R6kZRDcLqgJGmZ6IYvkYlb412P228PzRX14ijRK9E2W3czDqjc7aCZg==
X-Received: by 2002:adf:e3ce:0:b0:31f:db1b:7296 with SMTP id k14-20020adfe3ce000000b0031fdb1b7296mr2003800wrm.21.1697556260339;
        Tue, 17 Oct 2023 08:24:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1e8:0:b0:329:22d9:9fe8 with SMTP id g8-20020adfd1e8000000b0032922d99fe8ls71747wrd.0.-pod-prod-08-eu;
 Tue, 17 Oct 2023 08:24:18 -0700 (PDT)
X-Received: by 2002:a05:600c:484f:b0:406:4573:81d2 with SMTP id j15-20020a05600c484f00b00406457381d2mr1887049wmo.39.1697556258637;
        Tue, 17 Oct 2023 08:24:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697556258; cv=none;
        d=google.com; s=arc-20160816;
        b=ubfQuRRl9gqQE2Yqlr/Hbl6HDzto6da8YtnWu61IWbeHzIdcmg6oFyO0bHk8gyiU/M
         rEP3dN+5oBjncAUiQhRBl3+SMfDS1ABOIrWdvCAEZwqLIZC2utSlAQe7VEvBMP667KNV
         qD5TwcNxktRnYMd8Ij04lAKUgx/cfEtmeiLlC8ah2u6WIT/K5bVfYA+XpgXK1n0vWtiD
         70tRKU2S1on/UFdeLLsQhK5Q2w24jIcmCNsAukJdOa1ensYc77jUy//CABgCrtSfAVJ5
         zQpoaAfjuHWUve7c/ogVdH6FB/KVR7NLAcS+TD3HGG0LpQF7/a/jbGbXJ4qk6On1orVS
         14UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UJQt/dhfW4ljIETmg9qzLnjfnzaDOgcBSv1MQzSSlYg=;
        fh=vqXZi9gxeMzqmPnv/InKLu6SV6iKt+SKklRsePoGBS8=;
        b=Y/Mj0/C84+b+L05XSu9S8+zxeepma8QnCQgDb44ZLJzBsGj60VD/YLfShbBKTf6ACZ
         BOPnCvgHVIsaQ3HetUN+vs04aUpovegtqvWEAiuNitO9rXvoVT5lu3ie0NjZLGVJCUXK
         +/lHA5mIfzC42MG/QcPAIogCU5cHUsH4ebqaoXWHmm4iXzQE2mxeHHKSOcAPcIEV/hyN
         bSW4dJd7J4tYZ7t8BQTpsP/6+ZSynMWbcl9tPnxg2BxeiH+/uef9cbEpOF5fPcMTZatr
         SXHsmvGlZrHXhqALZ1BkSQn3bUDOwpPtXIOriJKiBYaKoH0eIYD/LeoEJ6lVgwML7e8+
         e27A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YW5yXih0;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id az32-20020a05600c602000b00401df7502b6si41988wmb.1.2023.10.17.08.24.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Oct 2023 08:24:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id 38308e7fff4ca-2c509f2c46cso55126651fa.1
        for <kasan-dev@googlegroups.com>; Tue, 17 Oct 2023 08:24:18 -0700 (PDT)
X-Received: by 2002:a19:6703:0:b0:507:b7db:1deb with SMTP id
 b3-20020a196703000000b00507b7db1debmr2213812lfc.38.1697556257664; Tue, 17 Oct
 2023 08:24:17 -0700 (PDT)
MIME-Version: 1.0
References: <20231012141031.GHZSf+V1NjjUJTc9a9@fat_crate.local>
 <169713303534.3135.10558074245117750218.tip-bot2@tip-bot2>
 <20231016211040.GA3789555@dev-arch.thelio-3990X> <20231016212944.GGZS2rSCbIsViqZBDe@fat_crate.local>
 <20231016214810.GA3942238@dev-arch.thelio-3990X> <SN6PR12MB270273A7D1AF5D59B920C94194D6A@SN6PR12MB2702.namprd12.prod.outlook.com>
 <20231017052834.v53regh66hspv45n@treble>
In-Reply-To: <20231017052834.v53regh66hspv45n@treble>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Oct 2023 08:24:02 -0700
Message-ID: <CAKwvOd=pA_gpxC9ZP-woRm2-+eSCSHtwvG3vsz9xugs-u3kAMQ@mail.gmail.com>
Subject: Re: [tip: x86/bugs] x86/retpoline: Ensure default return thunk isn't
 used at runtime
To: Josh Poimboeuf <jpoimboe@kernel.org>
Cc: "Kaplan, David" <David.Kaplan@amd.com>, Nathan Chancellor <nathan@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-tip-commits@vger.kernel.org" <linux-tip-commits@vger.kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, "x86@kernel.org" <x86@kernel.org>, 
	"llvm@lists.linux.dev" <llvm@lists.linux.dev>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YW5yXih0;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::22b
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

+ Marco, Dmitry

On Mon, Oct 16, 2023 at 10:28=E2=80=AFPM Josh Poimboeuf <jpoimboe@kernel.or=
g> wrote:
>
> On Tue, Oct 17, 2023 at 04:31:09AM +0000, Kaplan, David wrote:
> > Perhaps another option would be to not compile these two files with KCS=
AN, as they are already excluded from KASAN and GCOV it looks like.
>
> I think the latter would be the easy fix, does this make it go away?

Yeah, usually when I see the other sanitizers being disabled on a per
object basis, I think "where there's smoke, there's fire."

Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
Reported-by: Nathan Chancellor <nathan@kernel.org>
Closes: https://lore.kernel.org/lkml/20231016214810.GA3942238@dev-arch.thel=
io-3990X/

>
> diff --git a/init/Makefile b/init/Makefile
> index ec557ada3c12..cbac576c57d6 100644
> --- a/init/Makefile
> +++ b/init/Makefile
> @@ -60,4 +60,5 @@ include/generated/utsversion.h: FORCE
>  $(obj)/version-timestamp.o: include/generated/utsversion.h
>  CFLAGS_version-timestamp.o :=3D -include include/generated/utsversion.h
>  KASAN_SANITIZE_version-timestamp.o :=3D n
> +KCSAN_SANITIZE_version-timestamp.o :=3D n
>  GCOV_PROFILE_version-timestamp.o :=3D n
> diff --git a/scripts/Makefile.vmlinux b/scripts/Makefile.vmlinux
> index 3cd6ca15f390..c9f3e03124d7 100644
> --- a/scripts/Makefile.vmlinux
> +++ b/scripts/Makefile.vmlinux
> @@ -19,6 +19,7 @@ quiet_cmd_cc_o_c =3D CC      $@
>
>  ifdef CONFIG_MODULES
>  KASAN_SANITIZE_.vmlinux.export.o :=3D n
> +KCSAN_SANITIZE_.vmlinux.export.o :=3D n
>  GCOV_PROFILE_.vmlinux.export.o :=3D n
>  targets +=3D .vmlinux.export.o
>  vmlinux: .vmlinux.export.o
>


--=20
Thanks,
~Nick Desaulniers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKwvOd%3DpA_gpxC9ZP-woRm2-%2BeSCSHtwvG3vsz9xugs-u3kAMQ%40mail.gm=
ail.com.
