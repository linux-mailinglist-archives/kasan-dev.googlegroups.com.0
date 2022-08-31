Return-Path: <kasan-dev+bncBDE6RCFOWIARBWWUXSMAMGQEHRUTYDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 321545A7A3C
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 11:31:07 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id j4-20020adfa544000000b002255264474bsf2210404wrb.17
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 02:31:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661938266; cv=pass;
        d=google.com; s=arc-20160816;
        b=ojaIvlivscGZeGTi2EVTBQyJ86s60rxo+o0WI18q1QfzbBYm3SMkrjbvoESpjp7ryd
         JqTZ7EBk4A0QxeLdv4/bzpE6rZGs1VeykwUPZSEb2eADeUNZTqjDXhP1lpJSpK38KRqP
         LmM/2NM0NgxSko4oHPCBbEZQ26TBm1EQOB/qPIV79QbbsMjHRMQiaBP2FpwrV7HnV+2A
         UcP2V+gbd1SoomelmbqOR1uRFPPCXVBgVlbAdzAutiFrNWlpltXDUCcI+TQsg6lvOkkb
         s94lalmsruiw8pUAXcjZdGFTPkDxJd9JiAcjvOKcCiZSzAtsNVp4Dy7CiLzqPjo+juj0
         Xn8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=CHiw7n0wtSiO0ZxtszXIcblYQUDV8IArkLocwj5C9No=;
        b=TRfc6c4U4SMp4tOxtCdroFAOCSev6n9LTAcmVjmHiwOdqXQ5E6AlIlBll8Figbsjzb
         AVINU7YhRkVOk899YuT+4zH9HiGbr308+QMChQwmIcqIvAHOtk6PKTvcVmNNI0qMkCqx
         UfGRUODdvfubr13IPZDXwPciNnl4rj1lvUSCvQbVEXVU1ocwYQYX6mXSzvfl6Ks9CEx2
         LKllRSaSCzGqpMy83TwA5wDvJ2qUQ6gz9/72SMK2fTc8tOlPz5RbV2ESryZ8S+LqEsbY
         LNVGev3vH9YWcNKDwNKo5Cla57/mTodjbITCyO/7lGlK+7zbDIL/56NNsdmhcd3LpVel
         ToIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=z3JWHYIE;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc;
        bh=CHiw7n0wtSiO0ZxtszXIcblYQUDV8IArkLocwj5C9No=;
        b=o04XUmu38UlcjcYBu1v5fx7oMNp7Klj08+325V3JMHcwaywQO8i+EhKqpehR+HtEZW
         XAzff1+pVZV99U0e9WA06xV3s1D733OnH/nXbJDoJWL1618adTCkqYwlwceTG4n+giQc
         Yvcidyt24H4jQQlXC+6ggzOkfXTeIzJp3dZRRDzJqlf7UsJ0HGiKnasbtrSavFFCrFRg
         H9bQMun1aWHrdpEZwAxZPgpBQ14tXcteGUPxlj5J9u6Iqpw2UsZ5NDeslSBTphX9tHi6
         Ke5Msn5zjwbS0qBS8gwcDiyb0YSqcYp8GyrIF2XutvzVCEipnwd6GJodMNR2hwFy3Mz0
         Ihjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc;
        bh=CHiw7n0wtSiO0ZxtszXIcblYQUDV8IArkLocwj5C9No=;
        b=kBkpEFAe2NEbMZiRGww8vpnKcC4LCq6ph3joNHsDh5U53RznyvRdN9Qq30NzR6HYDu
         2+s/fbnbt4yxt5o59G/xLFpGVNggfotweqZ5rrcV5spFnClp5KkfwNIkBWsJGtPCezUA
         gYlZ2vk9e6+WkwdkYVdR7b2DWaNGAPgw/gctjmtewPbnQIeDwwDHmnuqSvfk1Cl1UeBy
         oY1hxNPaUGWri3whiO1OdJg3zDzT2lmHXD5ahmnRRfwiPl8UepRMDDj97VuFSAMJcWG+
         tXohxzVnNoTjjFoJVHi/QlEPE3DLTo2L9iMJpdOt5ELaVaX3MJmAYoZO+k8DeGjkXGO1
         WGMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0Z/mFRZ+yZm9r3aeGb7QPolzQTmTmk5jgQh00dlW2FdBUVVIsK
	OmZcpYShR4w1CPh4RwlVHug=
X-Google-Smtp-Source: AA6agR6JJu7ZfxtXMUn2hlnnbUjk8ObX6F9tgZcxr6a+it4kgklZiXVDgrjPOX0vg0zP3UJUxWlRGg==
X-Received: by 2002:adf:ea91:0:b0:226:dce6:c344 with SMTP id s17-20020adfea91000000b00226dce6c344mr6608944wrm.3.1661938266588;
        Wed, 31 Aug 2022 02:31:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:502a:b0:3a5:a469:ba0a with SMTP id
 n42-20020a05600c502a00b003a5a469ba0als482372wmr.2.-pod-canary-gmail; Wed, 31
 Aug 2022 02:31:05 -0700 (PDT)
X-Received: by 2002:a05:600c:1d16:b0:3a6:1fa1:41f7 with SMTP id l22-20020a05600c1d1600b003a61fa141f7mr1325775wms.103.1661938265567;
        Wed, 31 Aug 2022 02:31:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661938265; cv=none;
        d=google.com; s=arc-20160816;
        b=Wfd21iNCqkU7xZCn7z4JFEIY7mTLBvA6Sfnq/fVyIQCO5MtI4WNZsyXMdmjHLN7790
         wUZ0WEw/7LTgYH9W/GIzIwTiHaH/4S/YAVPxutVqe0xaiQQ95N/+MoEr62Pcj/NjihMe
         vL4c76qu9vDpzvSshAj55o/FPqvPuXqf1ne5ihdy6cE/PptQns7jRjGU+n5/5nfyDi+Z
         LIqFhlE16yA7K3S4tkLJ1rOJlBFeZ7QUd3GuLiIgOv4Ne8hSuHdw+MDHcPsQCcceumdr
         Ql7kXAkDkvOOUF846h+hOqtevQws7bCTYwQqUGBzc5s9lnzhHoGULnDzJUDwoUOtnTyH
         MjAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mTMJgxNUn3NdL2Te+hOt7Np5Z6vrIBnPT95qbu1ijYo=;
        b=H+yfYD7dXMOao2Zv/TY0K2xfumXlImAY+v98dKO38jTYTqfWMv/MUkYmLaTy2xelxt
         9ztQU4kc4Cn0qe6sHBo9Wu/C15CuKR+kl0wChPjjzaunFf6NvJQ207wUrtxEhef3/EzH
         EETIZtd6WAdgCoBLebgyyX2HC/KHiMYamKSEbV8/4zjhlxYRKSIQiYnWLVNqUHlt1aJ9
         Wrhws9v+DBsUjHkCCCZcyvxT4xBDv6uc6+Hb5Y/1EiWe+tgKPulf8cFg9A8skmESKJ4D
         4MYbRqXROHIZntY6rTzT4S7fogfbITdWeW/S4HJ/JxpIdyYolJUSajiGf/lrbJa2/6Cs
         ojiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=z3JWHYIE;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ej1-x62a.google.com (mail-ej1-x62a.google.com. [2a00:1450:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id p22-20020a05600c359600b003a83fda1d81si108166wmq.2.2022.08.31.02.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 02:31:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::62a as permitted sender) client-ip=2a00:1450:4864:20::62a;
Received: by mail-ej1-x62a.google.com with SMTP id bj12so27116150ejb.13
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 02:31:05 -0700 (PDT)
X-Received: by 2002:a17:906:9b86:b0:73d:72cf:72af with SMTP id
 dd6-20020a1709069b8600b0073d72cf72afmr19921832ejc.440.1661938265272; Wed, 31
 Aug 2022 02:31:05 -0700 (PDT)
MIME-Version: 1.0
References: <20220827213009.44316-1-alexander.sverdlin@nokia.com>
In-Reply-To: <20220827213009.44316-1-alexander.sverdlin@nokia.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Wed, 31 Aug 2022 11:30:53 +0200
Message-ID: <CACRpkdYgZK1oaceme6-EEuV3F=m1L5B3Y8t6z7Yxrx842dgrFw@mail.gmail.com>
Subject: Re: [PATCH] ARM: kasan: Only map modules if CONFIG_KASAN_VMALLOC=n
To: Alexander A Sverdlin <alexander.sverdlin@nokia.com>
Cc: kasan-dev@googlegroups.com, Lecopzer Chen <lecopzer.chen@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Russell King <linux@armlinux.org.uk>, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=z3JWHYIE;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Sat, Aug 27, 2022 at 11:32 PM Alexander A Sverdlin
<alexander.sverdlin@nokia.com> wrote:

> -       create_mapping((void *)MODULES_VADDR, (void *)(PKMAP_BASE + PMD_SIZE));
> +       if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) && IS_ENABLED(CONFIG_MODULES))
> +               create_mapping((void *)MODULES_VADDR, (void *)(MODULES_END));

So the way I understand it is that modules are first and foremost loaded into
the area MODULES_VADDR .. MODULES_END, and then after that is out,
they get loaded into VMALLOC. See arch/arm/kernel/module.c, module_alloc().

If you do this, how are the addresses between MODULES_VADDR..MODULES_END
shadowed when using CONFIG_KASAN_VMALLOC?

> +       create_mapping((void *)PKMAP_BASE, (void *)(PKMAP_BASE + PMD_SIZE));

(Splitting this in two steps if probably good in any case.)

Pls keep me on CC for Kasan ARM patches, thanks! (Maybe I should add some
MAINTAINERS blurb.)

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYgZK1oaceme6-EEuV3F%3Dm1L5B3Y8t6z7Yxrx842dgrFw%40mail.gmail.com.
