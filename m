Return-Path: <kasan-dev+bncBD4NDKWHQYDRB5UD7OQQMGQEJRCKIRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 24DAA6E691E
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 18:14:48 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-552e3fa8f2fsf50016317b3.19
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 09:14:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681834486; cv=pass;
        d=google.com; s=arc-20160816;
        b=QkMJ71S4GTj33fF3l1sj3xZmCid+jHpoDovqRj18+1ieW7c2XQ2NIiAJzF3dGNDx4m
         ou8jdoJDErPOecV+fqWBysqgEz0NncI7i70Jo5COIESSXKOAvpMXdsFsOb6WS32Q/FG/
         ZdJpYObTZhhWDAADD0nXAS0laafGo5UyHEIShOHDFwY7oNeWxF6IpkXwh87A6XBjS/UI
         Vgf+A+2hCnE2rne5NRswzY8eqSmYtCtdsWUX1paOgN4lGxdO2ivae2SRHB6CCzJ8m+8j
         avM9jbwQr4LKjrf1bLFd8wTS4K+W89+ytTKePO+HKGzcMRJ+NF+kkvAuk0zksaxyGC7y
         g0Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=etck170gEdmYZoJOK/52RmkVeRi6uCeAqHvC4Xewtf4=;
        b=WlCKFaXrMI654cQ/XcC9CIWBtgnmmlSe8jzdfm8KmQVmLeQGb8thNOarFooy2xQrBv
         k+cqActymU36olHiyYvyoqjhUat3MuaK6foHQIOQNHkNrcPEJEYucdJYjtuszbwKx69n
         yJna83eTkccJ5qaEXOnzSD4tMLjciO+Ug9et0dKJmegDymSHkW8s6x1D+ts86UQhYoer
         8w+PVdRVCScHp3gtuGSR1lJFAESMAFnPG3sLByZkCnVpniseCvmdQ3hcLGYY+afChQio
         oRRcOnYn0Leb38cJhCu53MckzhjGYt45Japhhp0b1WcTkVkgFcrM6DnDB3q3HI66pP/l
         +3ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XzDa6W5d;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681834486; x=1684426486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=etck170gEdmYZoJOK/52RmkVeRi6uCeAqHvC4Xewtf4=;
        b=ilOSLJPCy1YBi11+DIObvU5WarCFH1Jaz2MbkRZ1EsJ4/EeeOzLIMTQtZyt195ZwQG
         rTAW88lU43h4EPIxamzNJXBqQ3A9JeeqDFqYjV6r7TA7c9QXIzGmVGAripOIqgkK1B0H
         TqEz3v9s4AA9p96yF4x5oh6nMaESoYvm2DRdo9TisX5R58u0gmpgMNbP+vDcZxVE8SE7
         thysU2ziP6oz+1E7UMOCvgcTVq4eLnFQ3q6bXXAPkYs/+Tk6qGU8LyCtbHfy77u6R7qE
         nXlgAaLgcoQ8cLTBGqgyz42AlI7H0AQrD1a+twf2syQe1qSFOkPEco+hic3tmj0y+iHu
         sl9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681834486; x=1684426486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=etck170gEdmYZoJOK/52RmkVeRi6uCeAqHvC4Xewtf4=;
        b=D0iYHbwKoNPt2dp8J3dQ8NECQamBNIE8fq8vpaqAnP/G+OW7thFDAltWjPOgBgsK+p
         xB5mM2Wsgggun/X/F17qzYWAt0hLjBUcAZe7BcH/d5hBQDYQ5KWyKho+sB5gtQQyvUWZ
         xhNDWnNtGE3FkV9wNOcG3b7k5PfDz4THPAX9FbLcwH3d+o9zFhKYRCRrcr7Iz4wt2QUf
         7tbdedLLcv2Ujj7zcbpk4SVrB3OuB1Quewowj3vVufBttIeJ5vBc4BKDzjes0C3VUANt
         lpey1nwwCyb0oaFC6j0bpch2TEbT1/BMW/b8u3AlN/2SdgvBXqHfFfFJBgaePJjq5ffn
         GUXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9frDbBR3w/w84HG149EMyhyd6xXWy4gvPzcKbiXCC877WcRXxA2
	Nb8WmezscP7q4qvQMkEWmhI=
X-Google-Smtp-Source: AKy350bvVouE7xWNJJ7i3aL5ya3biKzYGXo/cjbXDav2XLWR0wI83bQHdPK78rw54+f5EkRUW0BIxA==
X-Received: by 2002:a25:cc03:0:b0:b8e:cad0:6e5a with SMTP id l3-20020a25cc03000000b00b8ecad06e5amr10027189ybf.2.1681834486749;
        Tue, 18 Apr 2023 09:14:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:97:b0:54f:7971:5e92 with SMTP id
 be23-20020a05690c009700b0054f79715e92ls12939087ywb.3.-pod-prod-gmail; Tue, 18
 Apr 2023 09:14:46 -0700 (PDT)
X-Received: by 2002:a81:6c15:0:b0:54f:b6b6:1906 with SMTP id h21-20020a816c15000000b0054fb6b61906mr415404ywc.24.1681834486210;
        Tue, 18 Apr 2023 09:14:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681834486; cv=none;
        d=google.com; s=arc-20160816;
        b=J+uxnjxZul/C4QT9wptUOCNqQTnc6nCoUOoYzkQ2bqyOiGPtXvnjUzQqxbEB1FiRD3
         heEhjOMI2JnX8dLPnft8xLBvXcZ13ff8D15Az8n5rVDT1HcMqpBOMt2kBV32g43bz+f3
         /nrkXHQJvkGk3BbAseHCnTZfyYaar0pzjYwlbva/GhxwOoaMZOFXUHsWB2TtoYRFpjcC
         di5Uknaw1jihYEFf3C0ddQynHMiXs/z6iBG3RfXa9zlt39Py3EWU3pWvXPqDX9/AjzCD
         b1yjBlT82ebOTVTCG856fk6FVWvBbW5ct3hZjdmCxDRZYXXRwBeGmeFPYqJNYPBWwTTE
         XL0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jC51PvInYKqVvEAoDa7+X8BBQ/C1Iht9TH/WVSOD9nE=;
        b=d/ltgkx80gGqUXVZNnLFpMA4tAxvQ+EdPSbzg0Si+/O+rufgzV35isaxWbbLZAOQKV
         QiiEy0aUMERR4bkHFZVV9jjrjK5VpzEF5QPAzEx0i+2iFDlbqUHpy42bCoFoV53InU1l
         lsmmX533Oe4FSvT123tqwJeiwIni2fHqSl4snl3GqgWjCc7pjXnUP2v6bVWqfx3bOncM
         jTWlE4ZTBNADmGnY4uvIhUZQvsRISBak+q/W32XckFIiMo2AZ801nSzVlFgUXrPoEAuk
         ildpug/K89ZCEdq9sVgxl/y3JNlAB+TIyJUE+wZCBHRl1TAA/jloT7+sO8YVOxkIWGVI
         tVHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XzDa6W5d;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e13-20020a5b004d000000b00b8d981f2bebsi854809ybp.3.2023.04.18.09.14.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Apr 2023 09:14:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id CDB5363645;
	Tue, 18 Apr 2023 16:14:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 24AD4C4339B;
	Tue, 18 Apr 2023 16:14:44 +0000 (UTC)
Date: Tue, 18 Apr 2023 09:14:42 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Marco Elver <elver@google.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Nicolas Schier <nicolas@fjasle.eu>, Tom Rix <trix@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Michael Ellerman <mpe@ellerman.id.au>, kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH] [v2] kasan: remove hwasan-kernel-mem-intrinsic-prefix=1
 for clang-14
Message-ID: <20230418161442.GA3753@dev-arch.thelio-3990X>
References: <20230418122350.1646391-1-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230418122350.1646391-1-arnd@kernel.org>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XzDa6W5d;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
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

On Tue, Apr 18, 2023 at 02:23:35PM +0200, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> Some unknown -mllvm options (i.e. those starting with the letter "h")
> don't cause an error to be returned by clang, so the cc-option helper
> adds the unknown hwasan-kernel-mem-intrinsic-prefix=1 flag to CFLAGS
> with compilers that are new enough for hwasan but too old for this option.
> 
> This causes a rather unreadable build failure:
> 
> fixdep: error opening file: scripts/mod/.empty.o.d: No such file or directory
> make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:252: scripts/mod/empty.o] Error 2
> fixdep: error opening file: scripts/mod/.devicetable-offsets.s.d: No such file or directory
> make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:114: scripts/mod/devicetable-offsets.s] Error 2
> 
> Add a version check to only allow this option with clang-15, gcc-13
> or later versions.
> 
> Fixes: 51287dcb00cc ("kasan: emit different calls for instrumentable memintrinsics")
> Link: https://lore.kernel.org/all/CANpmjNMwYosrvqh4ogDO8rgn+SeDHM2b-shD21wTypm_6MMe=g@mail.gmail.com/
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Reviewed-by: Nathan Chancellor <nathan@kernel.org>

Kudos to Marco for figuring out the 'starting with the letter "h"' part
of this issue :)

> ---
> v2: use one-line version check for both clang and gcc, clarify changelog text
> ---
>  scripts/Makefile.kasan | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index c186110ffa20..390658a2d5b7 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -69,7 +69,9 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
>  		$(instrumentation_flags)
>  
>  # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
> +ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
>  CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
> +endif
>  
>  endif # CONFIG_KASAN_SW_TAGS
>  
> -- 
> 2.39.2
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230418161442.GA3753%40dev-arch.thelio-3990X.
