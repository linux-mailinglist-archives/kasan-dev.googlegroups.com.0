Return-Path: <kasan-dev+bncBDOILZ6ZXABBBKMHSOOAMGQE2LXKUOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AB2363AAC2
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 15:20:26 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 13-20020ac2484d000000b004a22f42201esf3895560lfy.17
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 06:20:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669645226; cv=pass;
        d=google.com; s=arc-20160816;
        b=BtTObOCBXNvRXw7k4UF/BdUNa1PfMmU/+TsFJ2ZkoLXTMofTObgdYjya/TV8EtPWHP
         LUKMGOOQTdvUGgwOB4CFliQyf1b7vg5xCBMhi5067d8WymnBIzX40LwEZV6DxTZp/0ip
         wkmnY/fi0KQ3qg9IyMV2xoyaGk8wspp7poJABBr1x5u0Yn58njmCXeRkZQBXhbHImDVg
         g8XvFeISCXSZHrrJH7U4FGYPk167/PzmOFKpVJ4ighPlpqk/x2JKCqUwUu49G3mBwG5b
         ztJOt/aYJ0jzDvmlOhPHJWwZ5pWF7kiUuPY6Z34lqLCmj8dwZxRekOnHAWZqYz+y2rpY
         +C3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=7E163id6blaTkA3acZvbiYsWMTVIhDGKrW/cEW5wSN0=;
        b=DrtNZZLMV4SXUiGi2f3qRqyQKxN2qGP1d98jAWup8ol/7sqA2tod+nAEjB+FF5ZFZH
         EQ+ofLIFrejkyuHo3JhtqRI7rRw5LgbP2tSU4sKoSXT6jEBorMr3UxiHo42Vqy5Vi++p
         HeYLsy37Qte8WT5cKfQxMOlvdC+MDMDGu+0KLvapnMcKbYsOWZOXNflo1TLNujkWIy3J
         NAJU+Dgqbp8UK6TfKT3YHs0u2cKedqPctMnztfo8SIFIqTp2Q7SSzx4Ox9beiYdymZWs
         wC/fkPzOib6rQzaO0ERTR5yyq4N4uT+GQvGqrmmR2xmF8i0AKa4c126Ui0VV/0Mnd0+2
         tafw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=jrQw5V1v;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7E163id6blaTkA3acZvbiYsWMTVIhDGKrW/cEW5wSN0=;
        b=HhPXoOiqIJdvZodRJ8KFS5EQi16g/GUQiX69IncQU3fPDxq2DlmaIQSIX8yp3YX+rl
         bT7L6edyI0tk90mkOm7QgO+NiJTeZo1irdAu4H2JDvP3o/cT4IbsfrUrUpUVhWyNWs8C
         Pck197+NflR6/JBqsz3zo6YxKdBF13LukLx1Q3LHLoFRlUB7b/9Fa4R5p1xX9bY3Rz8H
         8dofOZ1E04N8lm//21aYVMoS2l9Vn2cr3js9VKNVdU16PqeNPKKa75WLYnmjaDetcwTz
         2EEYF35WO4iJgdEVOodKj3WgaFNwYEiIj/jXbRDwLgi1aIZjyUBOuIvm97UZevXPmt5j
         dliQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7E163id6blaTkA3acZvbiYsWMTVIhDGKrW/cEW5wSN0=;
        b=rtXRV5kM44EbJAcoZf8i4WxNAFuIje2D/xFS8KRqbgFfMjASJS2btBJokHVaCXdKry
         mpPV7Hth8E257LkOkPotktSqVPImx/cq3q/lXQEBRVTlM+W24+oCDccE/Nq/Ua9B6dBZ
         yNQqOOiyCW7z95ENvStrwT9YDKhRtHzTR1hzr9abGLoCKr9fVCV2N0q+bUL6A21U7IS5
         cYpFsRnsJ3kuCpDpKMiL/UYGiljNDd6t9tK1MZC04qVdc89fsKZbhZyig/ME0JyfXfOz
         S0vKd7WaNTs6X7SxxyYxXoWxwjQxWNVKn01+cz2E/PoVQ8GxhokuS5RrJ8hCCVMCy2vr
         5AsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plzPhXoR3aZ+2zpjM4oe88POQ4dF2E/qBZSFNcyZOGa3UFG0cTh
	BngK30cSIlqz91w8IGUnJP4=
X-Google-Smtp-Source: AA0mqf4pMrm+A2Ku3SejWzdLESn+HUuGIwVs/68vDn7w6W4tuG1oUCjMytD2aVSPs22vjwQIpSSKZg==
X-Received: by 2002:a05:6512:31d6:b0:4b4:f497:80e1 with SMTP id j22-20020a05651231d600b004b4f49780e1mr7769221lfe.119.1669645225694;
        Mon, 28 Nov 2022 06:20:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7212:0:b0:279:4599:dc1f with SMTP id n18-20020a2e7212000000b002794599dc1fls1718616ljc.3.-pod-prod-gmail;
 Mon, 28 Nov 2022 06:20:24 -0800 (PST)
X-Received: by 2002:a2e:b5d4:0:b0:279:5fa:8e7c with SMTP id g20-20020a2eb5d4000000b0027905fa8e7cmr15902039ljn.62.1669645224524;
        Mon, 28 Nov 2022 06:20:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669645224; cv=none;
        d=google.com; s=arc-20160816;
        b=zSaiFSBcIEZ0xFbPsjhOOG0BU3K/9J6OCuS3uKf9tFfC7uc37qh5oRdeVNR0029n0I
         C+8Rm7Z6DTdDYIjYiUg1s5LJSFkAMu0JGYq0zCqFwtVktWRsByg8M/0N8SQ8Uuen832s
         aNMw/CyTNhzy/nv095SQ+rorhze8lVLaOo745iTApbDtIQddonjuZ7AxOf2YLZG7ob+E
         L0qxaalRv/FggcQwvG3ZEtVLlBlpjMXwNEzeSamX2JkDZKKD5BxaCma4Ooub4pz6P3zq
         F4S8reM41mxehdKsGK8urWVvXV9nCU57rt+B1GVTpYnK4VodiK4ZlHMwTc3kqkTDMBjQ
         UnRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EjFqsuE9cNphk4gOSD8zOQ2dx5nFpRj2oii2XFa96hw=;
        b=nW8O7BF/wZnoXjudw3oOkwOdDff/C8gUfgmNOPATVe6r6X14GdGxJeAL0NEyQw9JUt
         C75qUzKEv7+aFaws79iQ1I62vvNTEYF2Ptf1zj/cox2i0l6zciChB6ANQnx4OH9Np1CK
         zT0KTcnd0mQZQoYcnyOVO/pGISuHwWEsNKHB9vmwoXf2VUAs7GhVvJGswjs8ZySAlJ7z
         yH8TVMMnzy2AKQdx6barrXcMeolC8SxlRXC5X7QlVSMXJlxaKkk2qGT/oj6g+NcIdptL
         Lxv/QSyB65/K1jg2okZrdmJ2/tSn2LbwViDz2d1uOFTB8MhKSfpDIVr3KTHKD1aCQyf3
         MA4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=jrQw5V1v;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id g8-20020a2ea4a8000000b00278f552596bsi519979ljm.2.2022.11.28.06.20.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Nov 2022 06:20:24 -0800 (PST)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id fy37so26127571ejc.11
        for <kasan-dev@googlegroups.com>; Mon, 28 Nov 2022 06:20:24 -0800 (PST)
X-Received: by 2002:a17:906:bcda:b0:7c0:80b0:7f67 with SMTP id
 lw26-20020a170906bcda00b007c080b07f67mr473326ejb.462.1669645224199; Mon, 28
 Nov 2022 06:20:24 -0800 (PST)
MIME-Version: 1.0
References: <20221128104403.2660703-1-anders.roxell@linaro.org> <5FC4A1FD-9631-43B2-AE93-EFC059F892D3@kernel.org>
In-Reply-To: <5FC4A1FD-9631-43B2-AE93-EFC059F892D3@kernel.org>
From: Anders Roxell <anders.roxell@linaro.org>
Date: Mon, 28 Nov 2022 15:20:13 +0100
Message-ID: <CADYN=9LT7xWScSiprwgB2DhTN-Mws7rxG33BRZwLktK7P_jzkQ@mail.gmail.com>
Subject: Re: [PATCH 2/2] lib: fortify_kunit: build without structleak plugin
To: Kees Cook <kees@kernel.org>
Cc: akpm@linux-foundation.org, elver@google.com, kasan-dev@googlegroups.com, 
	keescook@chromium.org, davidgow@google.com, Jason@zx2c4.com, 
	Arnd Bergmann <arnd@arndb.de>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=jrQw5V1v;       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Mon, 28 Nov 2022 at 15:09, Kees Cook <kees@kernel.org> wrote:
>
> On November 28, 2022 2:44:03 AM PST, Anders Roxell <anders.roxell@linaro.org> wrote:
> >Building fortify_kunit with strucleak plugin enabled makes the stack
> >frame size to grow.
> >
> >lib/fortify_kunit.c:140:1: error: the frame size of 2368 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]
>
> Under what config

I saw this with a arm64 allmodconfig build [1],

> and compiler version do you see these warnings?

Toolchain
aarch64-linux-gnu-gcc (Debian 11.3.0-6) 11.3.0


Cheers,
Anders
[1] http://ix.io/4h6w

>
> -Kees
>
> >
> >Turn off the structleak plugin checks for fortify_kunit.
> >
> >Suggested-by: Arnd Bergmann <arnd@arndb.de>
> >Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
> >---
> > lib/Makefile | 1 +
> > 1 file changed, 1 insertion(+)
> >
> >diff --git a/lib/Makefile b/lib/Makefile
> >index bdb1552cbe9c..aab32082564a 100644
> >--- a/lib/Makefile
> >+++ b/lib/Makefile
> >@@ -382,6 +382,7 @@ obj-$(CONFIG_OVERFLOW_KUNIT_TEST) += overflow_kunit.o
> > CFLAGS_stackinit_kunit.o += $(call cc-disable-warning, switch-unreachable)
> > obj-$(CONFIG_STACKINIT_KUNIT_TEST) += stackinit_kunit.o
> > CFLAGS_fortify_kunit.o += $(call cc-disable-warning, unsequenced)
> >+CFLAGS_fortify_kunit.o += $(DISABLE_STRUCTLEAK_PLUGIN)
> > obj-$(CONFIG_FORTIFY_KUNIT_TEST) += fortify_kunit.o
> > obj-$(CONFIG_STRSCPY_KUNIT_TEST) += strscpy_kunit.o
> > obj-$(CONFIG_SIPHASH_KUNIT_TEST) += siphash_kunit.o
>
>
> --
> Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CADYN%3D9LT7xWScSiprwgB2DhTN-Mws7rxG33BRZwLktK7P_jzkQ%40mail.gmail.com.
