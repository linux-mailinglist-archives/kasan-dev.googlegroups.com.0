Return-Path: <kasan-dev+bncBDL2VT427MERBOOVQSAQMGQEHRHDYVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 99D643131E4
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 13:12:41 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id p19sf460242lji.10
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 04:12:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612786361; cv=pass;
        d=google.com; s=arc-20160816;
        b=litDrKu0lM4x4hrJyeAfWbBFL874jhTJ1Mo8bn0QwYZvgPXcsiTmQNIXTkTFqWGjCz
         70F/UCb9pUSICT8TbztzDZrQEFZ6dB4RFyj8DpvbNKkq1A5156NWCA3LWspF/NY+Sowd
         CGNQVY2iZqnmiA6E1+US0IdK7p815AJ7q29CeAkvjS6f2SuXdjbBibLTSjummpLHMksc
         LWfwfCCB3fX68Se3utiZRMUqaqZftEYvC1DPoOFvIUsqT5UDbbOhZ6ZvSRSOUo+CONGE
         Yd1rrPYSyGP9HukjrtbVj+D0K27XExBGb89/ti9xtvewUhtnpe0inJbng4BxrQcWjNAz
         XkMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=01p5x6ARzLL5B/Rp63IVL5eeY/qCYmAtEkeQ9q18F7I=;
        b=B7PjyLiLw++2ETpw0KH3WFtdQ5Gc70epoLoqPyt7MuGVeLluUd0PAXsNE6olf7ughz
         ZmF3ij1Iv1eQ+jpJBxkXGml0ZcYk+aBVmA1F1ZpBaPj/1Ag0kUf2UnNlfpV26jbPO0yn
         5yc0HfDh/PMyc/Oj7dbquB/P2AxGe6WDPfB1Djg1wmQxBrEpX+BwgQBkBAzCkMFDOPL6
         NZlPW7ouwMJcrgv8n3lmHNbRCMEMwgwpKEcMpz0ZXEbn6iF1hGgl2XJDIoSJeGOP2k3r
         kMQkx1oafW/dQGU4vw3zjsV3aktSOVbGPN9V48jSu7+btlLovkROu0NlLdK9kP73w6OC
         HX9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=bp@suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=01p5x6ARzLL5B/Rp63IVL5eeY/qCYmAtEkeQ9q18F7I=;
        b=JhBq93nLgiwugLfB1P//fcR8oh3nmE2oPczWuGkZH43AeG2cSveTxdB2SYTWFut5+C
         IUFjI6zf9VKgOraaz/eEYFdlJw4xAbo7DVvHDS3ostmokjxd5E2aPZI/VlWyzeSzH35I
         qf5OQo1XPUA+i35tqM3hIhCDWfprZnhMBPWqeXoTz9AfI9NCBXg+9T5JcWU8MJfL2e2l
         QoDjx+ie0Jg29ZqmaCu3OSgOqN/XL4YeinxRI7uiqJ1QKAdkEkpsGKY9102qEzuGedJf
         XVtWHkQhrKHxRpcdaLMSPh7L6Wc8f85nA9KP7FzxOf0KcSZfNXmpZRGjKAAhuvbN2wZx
         4zHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=01p5x6ARzLL5B/Rp63IVL5eeY/qCYmAtEkeQ9q18F7I=;
        b=qD8fKOPrPWrzdCYHp20jpTr7kH4kLgQoGYZ8VOo7Xm40ywOBRIVHFLsNOxYSjxIyM6
         N55gi8XbjwhGNQhNAVxF2lnDh23jzwBDcLTAMlX1z4LSfvunv1bq8TefGM8/yVZeQeNC
         SP6Vnxsl4GjScel82vZSONjXd0mChVLVtzhLm3AqsmdpSNudFXotju9VlAiglQn+5XJa
         XPeTuYmTCM91tVlAuy1kazjtueitB0rIPIv/198JyOGdwyCNGwWg+N4xPmGik+eXFTqV
         o0bHGQdeH+2jpjt9UuexC+xPJ6lrue46qdt+Wfh1YrACMVvCdpOvblw9bMQaucWUs2rR
         +e5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GpYD+8Alvlw4gQz2SNE5G78HyNFVW0e+o8K016IIgGX+56T0/
	ZKIr5pYdiT2HZHGtpVbehRI=
X-Google-Smtp-Source: ABdhPJxhvEBnV6eYIXlMam7AVBF5qzO8Kb0H0lq5KBFo62xd9X1Kra05LS7OFC/+LjWd1V26AOuHNw==
X-Received: by 2002:a19:7911:: with SMTP id u17mr10412054lfc.214.1612786361208;
        Mon, 08 Feb 2021 04:12:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls3763684lfu.3.gmail; Mon,
 08 Feb 2021 04:12:40 -0800 (PST)
X-Received: by 2002:a05:6512:6f:: with SMTP id i15mr10659032lfo.426.1612786360296;
        Mon, 08 Feb 2021 04:12:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612786360; cv=none;
        d=google.com; s=arc-20160816;
        b=Nns3SlHwBgQIah59obr3sOhoqR7BVqfOSWi9PwmdPoRVJdXH6eBXX19T5G5BrZNUYM
         UMYbF6r3365Ngk8mtBHjqu1NeHDe4ex4SEr9j6kmagEUs+AdNMlMq39gneo9kfwTT87C
         cszXSFYgC1GW9z5+xchlOfRl+Ztf/4RuGsbZcO0BfPEbxZnOorLtbkaiAAPdSsZVn7Rm
         7dV8aUaHIUUbMM+yZnPk050cACznLOcVYMJWjGZ0WgYgaYaKuaVJwoPQy33fg03EPAgA
         ZPxOOaudWa517yFa+pneQVFUVQkhz/NR/CnV2H5R1SK7CBiAKLw/4Aauhm1SeQWeqPjz
         MhYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=DAOUoG3I7i2l7ObtBqKLCigFlXYFTGxgxiTwk7uNRLI=;
        b=bF/TEFTlST3IS1qHw7c/wf17kaOvJIGk7wLB5q9aWD+1yvt5fYknQBDLKpYLQsqZqr
         0P5kyoI0B5Siy7sNWUcFQukiLNZF5DFHTBqlVVV/54mH8PjXmuNpQ9qZfBsBrQuA3xXK
         GInMGVvVKs+lH+Xr+HVAUVl0+d9yppYd0i4upKHdCxVnFhXl40EHvIdd+S3bKySwyqIL
         iTOUGLvAr7wbs3wcNDm4tYF/QIsT6ZX47f2bRPziq9QNLr/qV+xYG85/3GFGjNftqde0
         hJUw74e5MhO6S2ho+nkp7gauycPvp3fuRXwPQX5gEHXs+fG1XdJIkduZoSyAIVK9R1yr
         NigQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted sender) smtp.mailfrom=bp@suse.de
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id a17si118253ljq.5.2021.02.08.04.12.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Feb 2021 04:12:40 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 75CCBAD3E;
	Mon,  8 Feb 2021 12:12:39 +0000 (UTC)
Date: Mon, 8 Feb 2021 13:12:27 +0100
From: Borislav Petkov <bp@suse.de>
To: Stuart Little <achirvasub@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Arnd Bergmann <arnd@arndb.de>, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	jpoimboe@redhat.com, nborisov@suse.com, seth.forshee@canonical.com,
	yamada.masahiro@socionext.com
Subject: Re: PROBLEM: 5.11.0-rc7 fails =?utf-8?Q?to?=
 =?utf-8?Q?_compile_with_error=3A_=E2=80=98-mindirect-branch=E2=80=99_and_?=
 =?utf-8?B?4oCYLWZjZi1wcm90ZWN0aW9u4oCZ?= are not compatible
Message-ID: <20210208121227.GD17908@zn.tnic>
References: <YCB4Sgk5g5B2Nu09@arch-chirva.localdomain>
 <YCCFGc97d2U5yUS7@arch-chirva.localdomain>
 <YCCIgMHkzh/xT4ex@arch-chirva.localdomain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <YCCIgMHkzh/xT4ex@arch-chirva.localdomain>
X-Original-Sender: bp@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bp@suse.de designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=bp@suse.de
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

On Sun, Feb 07, 2021 at 07:40:32PM -0500, Stuart Little wrote:
> > On Sun, Feb 07, 2021 at 06:31:22PM -0500, Stuart Little wrote:
> > > I am trying to compile on an x86_64 host for a 32-bit system; my conf=
ig is at
> > >=20
> > > https://termbin.com/v8jl
> > >=20
> > > I am getting numerous errors of the form
> > >=20
> > > ./include/linux/kasan-checks.h:17:1: error: =E2=80=98-mindirect-branc=
h=E2=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible

Does this fix it?

---

diff --git a/arch/x86/Makefile b/arch/x86/Makefile
index 5857917f83ee..30920d70b48b 100644
--- a/arch/x86/Makefile
+++ b/arch/x86/Makefile
@@ -50,6 +50,9 @@ export BITS
 KBUILD_CFLAGS +=3D -mno-sse -mno-mmx -mno-sse2 -mno-3dnow
 KBUILD_CFLAGS +=3D $(call cc-option,-mno-avx,)
=20
+# Intel CET isn't enabled in the kernel
+KBUILD_CFLAGS +=3D $(call cc-option,-fcf-protection=3Dnone)
+
 ifeq ($(CONFIG_X86_32),y)
         BITS :=3D 32
         UTS_MACHINE :=3D i386
@@ -120,9 +123,6 @@ else
=20
         KBUILD_CFLAGS +=3D -mno-red-zone
         KBUILD_CFLAGS +=3D -mcmodel=3Dkernel
-
-	# Intel CET isn't enabled in the kernel
-	KBUILD_CFLAGS +=3D $(call cc-option,-fcf-protection=3Dnone)
 endif
=20
 ifdef CONFIG_X86_X32


--=20
Regards/Gruss,
    Boris.

SUSE Software Solutions Germany GmbH, GF: Felix Imend=C3=B6rffer, HRB 36809=
, AG N=C3=BCrnberg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210208121227.GD17908%40zn.tnic.
