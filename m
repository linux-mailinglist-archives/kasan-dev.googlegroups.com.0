Return-Path: <kasan-dev+bncBD4NDKWHQYDRBBVWST6QKGQEPNPNE2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 81B552A9307
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 10:44:39 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id r12sf622773iln.3
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 01:44:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604655878; cv=pass;
        d=google.com; s=arc-20160816;
        b=DdaYJwJKMMrviNKGSYkcP9lTv3YhuFntQkjyJAYDZ5j5TY8f8/Zl8QseOYdV8vI5DR
         Ceo1BKIBbT5L77c836C5zktUd5DTF3r+jeM2BzCIDif7IfvbGuF/4jGuJZJNSIEJ9WMH
         K5G2ou+wNm4j/3wMqn6aqjiNss6l8AY5lKMd51e2CyHb1gJ9E8DaexbzWy7380UnCD+3
         WFO5bnRYcnyjyuCRYuNR5lbNliGg96/4liTIqAbuwT9T+2tM+bfQGcvXv5fl2iJjCnbL
         n4jMvRRkpjd9riORiWE9mobkVSn9jKVI8c8zDiYuQNn1aCtcay2SGK/kND7jmMfuI/7w
         zraQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=XpGkKRSxz5NnUes1p41dyCDK/MzJskVafFILFzqYSSw=;
        b=TmwLOgIVTJAGR6dKjeEzYZa1qu7YRks1+Z/didbbnEEaG8DuL9QYNjGcNCHvZyRCz1
         KtGy82m6BzJevTaoe4liXs4qlwM4Rsw/GPoS7SkF3f+CWsvcQ0pwLTObjGVhpKqU2xBR
         wGHv2qoQKk8xlXSmstHWMzg2w2X2VFmakS+lzguJVz6J09t0D0XDRTOmvbORh2b1RjVf
         eYN4XuoD1mm7vYr1zcYR5zeQjQ/0RJ3kPBEs/d2BBd48f9brBvNclC60b/ipLEjVMbc1
         RIyq4+k29AXXZlkubzprprMcV87kcUbmlzSb2zrL6U00MyczNToqOQ+J2+JhKD2h5W4b
         7r7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="tJ/08p9B";
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XpGkKRSxz5NnUes1p41dyCDK/MzJskVafFILFzqYSSw=;
        b=LUOyo1LkjtcRWAFgPrOUPga1DoeOPuUliPu5IuaTs/OBWiCR5YE95lgaDJJnsNWpEo
         2LBMfZF4gc8+i/sM3wabJLsFWnybhkljsF1zQwNj+2VVaspJ7jVERjderk+DiDx5oRcF
         MhMbr6lWk9QrYJjKhsKc91x2dSC0qj+th7rCKwnOFUbpI3///JYxcfN6+mMEzbqIhQ3M
         FBjGd1VWKIr1S1GmuTJx7IrJbOslMkr440ZrLyoBwdSAWq2hl3KCH9XCywlVAvkgTgr5
         E6M5+0o/WH/UIPpBIg/QFub1c5Z9W+6vFPesbUbsaKnSr0TVK6u16NuG9SZJf0P53ApG
         F9Dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XpGkKRSxz5NnUes1p41dyCDK/MzJskVafFILFzqYSSw=;
        b=LP3/cSKRvnxXBS0Hd5k22wiTsMiHj4YF+ncive1nwy6WT/ZkkA4x1iLpzlpNq8o9uP
         1Ma2dU+Prs3/bL3gRG/dfJh2AT/Benv9ocyoLNME+h7PE9KrYQjROTqJBBjWVlUkkmWe
         lDz6aIJE0nN4zJbF3AdaRdOJKKpbeMdaEVzg5bEPgwAcFDTParvG1JK+3neKaMU5c69F
         lNzOYfa/4BNHTXI08w9O4nfJHKzQf0yE0J9+fMmbVM1Wd4kZMWc4rq5AQP5YPzLy+tEZ
         5bDe6/4WEQ8kxl1F9bldpAtYlSnXUQB96EVFCg6ZneGpof0VWTZwbRXMByD0l2HNj++B
         pbEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XpGkKRSxz5NnUes1p41dyCDK/MzJskVafFILFzqYSSw=;
        b=GJj4m6Ymo1dmjd5TKSF0rhwHrPFGPHErcn+kJ8mk4ZbgmK8iAwSyACzgIlk2uGvOmh
         lxX9PqvyqyijiZ4pWT83fG1JvamHsRvNmq4KOZFqsiAWHWEFyOxBKwGrFc6i2G671E8d
         g0dGSeq5aMVIPfYIga2474Z4BpLIHiQ4iSIVeRkT49mR2D9j18bapWFx4XYqPQG9wzPz
         PH8fullI9TTGlxVDb43yXltRz/Tnl9iB92DU2XD1j1iwFa+r3kTpaIwPGj+GCTb2q5B8
         65NcTQwz7Tzudcpycb5QcEAPSNVFkIRCk4yj1aT5mGF9AJgCMoHvaOYO99/UuYcuuCTU
         YHQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531VKFQVPenQODay0AQUyLuhNSIhflMHKR4Knnh+tmHHL3TSPxMV
	jeLBnTJ48P+JXvFChQ5EQag=
X-Google-Smtp-Source: ABdhPJw/spWQgzlHi6w3sflhQ+SjIqGi+I7Cf8WZ1eOlJ6wjtAcb+/Ql3cLRewhHAgKBUKD/ufxdZQ==
X-Received: by 2002:a05:6602:d7:: with SMTP id z23mr844669ioe.142.1604655878296;
        Fri, 06 Nov 2020 01:44:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9a07:: with SMTP id t7ls164118ili.8.gmail; Fri, 06 Nov
 2020 01:44:38 -0800 (PST)
X-Received: by 2002:a92:3314:: with SMTP id a20mr796224ilf.118.1604655877958;
        Fri, 06 Nov 2020 01:44:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604655877; cv=none;
        d=google.com; s=arc-20160816;
        b=AER770gNhVbz3lKjDEu8GQPf3dKa126aSQRuMdzMuYFC3nxzws2+AZnYKb27HcyYSL
         9MefAXceDpluCbbwKddJ1lb85fi4WnXOtIuzMrbd0Jnx482BCIJrLfQEAQq5AL45Yj7y
         k1MBtf7js+D1zuz9lGteVl/rHI4Q9l5Rt18+5C2lorI0OHJ6ad72VtHpKb8ZcvbRGYW3
         7NVlxOItlKsO/seTZehw3s7x4CRqCK46hCdXWsBIeaKYwr4sJTkbWVajxOJPPgUg1sjG
         zY/jP3KLGRRlW+geminzpX0NzI2RT7xCRDF42ogxy11Ly4YRM+yyq75q3DYdRs+qyjPr
         1Tbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kKXmeFK4IT0iUDxEvASZoWTF63u7wMJJ7vCAA7uoI5w=;
        b=LXcM7rAkxM2SHFAsZTs67GS/lK7/D0ENBQhVOt62vOISots8a6tUqgHvvWQjdJBz2f
         HxxprWKGoTqckjMKFmD3lz1fzNEg46FYVD5hu9Rfpf0pXSDgzNBrYDmNGD4TLBU1DDLa
         mRBukGu4Dy3K7wGQYfGid3Uw7syxUNJxnzq4e8fXI5cGwUkAobma/0HUNl4lj2rZZ/z+
         CtRiCNNa5NuoHGcCdHJngIAgQg7DncTySf1+kIHIWKXWL3S2Pu7X24kacxSgkNHvrhRb
         /kbK6ZUWEPldtiEIQIwHXJE8JUqlqirOxkoDCw4AU3J0T0JJJXvZq4L4xdAuAAYJZ8zG
         apTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="tJ/08p9B";
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd42.google.com (mail-io1-xd42.google.com. [2607:f8b0:4864:20::d42])
        by gmr-mx.google.com with ESMTPS id i18si37884ils.5.2020.11.06.01.44.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 01:44:37 -0800 (PST)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::d42 as permitted sender) client-ip=2607:f8b0:4864:20::d42;
Received: by mail-io1-xd42.google.com with SMTP id n129so831322iod.5
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 01:44:37 -0800 (PST)
X-Received: by 2002:a5e:8916:: with SMTP id k22mr826518ioj.6.1604655877579;
        Fri, 06 Nov 2020 01:44:37 -0800 (PST)
Received: from ubuntu-m3-large-x86 ([2604:1380:45f1:1d00::1])
        by smtp.gmail.com with ESMTPSA id r4sm694366ilj.43.2020.11.06.01.44.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Nov 2020 01:44:36 -0800 (PST)
Date: Fri, 6 Nov 2020 02:44:34 -0700
From: Nathan Chancellor <natechancellor@gmail.com>
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Linus Walleij <linus.walleij@linaro.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Linux-Next Mailing List <linux-next@vger.kernel.org>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Russell King <linux@armlinux.org.uk>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Mike Rapoport <rppt@linux.ibm.com>,
	Ahmad Fatoum <a.fatoum@pengutronix.de>,
	Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Stephen Rothwell <sfr@canb.auug.org.au>
Subject: Re: [PATCH 2/5 v16] ARM: Replace string mem* functions for KASan
Message-ID: <20201106094434.GA3268933@ubuntu-m3-large-x86>
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-3-linus.walleij@linaro.org>
 <CA+G9fYvfL8QqFkNDK69KBBnougtJb5dj6LTy=xmhBz33fjssgQ@mail.gmail.com>
 <CACRpkdZL7=0U6ns3tV972si-fLu3F_A6GbaPcCa9=m28KFZK0w@mail.gmail.com>
 <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMj1kXFTbPL6J+p7LucwP-+eJhk7aeFFjhJdLW_ktRX=KiaoWQ@mail.gmail.com>
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="tJ/08p9B";       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Nov 06, 2020 at 09:28:09AM +0100, Ard Biesheuvel wrote:
> On Fri, 6 Nov 2020 at 09:26, Linus Walleij <linus.walleij@linaro.org> wrote:
> >
> > On Fri, Nov 6, 2020 at 8:49 AM Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
> >
> > > arm KASAN build failure noticed on linux next 20201106 tag.
> > > gcc: 9.x
> > >
> > > Build error:
> > > ---------------
> > > arch/arm/boot/compressed/string.c:24:1: error: attribute 'alias'
> > > argument not a string
> > >    24 | void *__memcpy(void *__dest, __const void *__src, size_t __n)
> > > __alias(memcpy);
> > >       | ^~~~
> > > arch/arm/boot/compressed/string.c:25:1: error: attribute 'alias'
> > > argument not a string
> > >    25 | void *__memmove(void *__dest, __const void *__src, size_t
> > > count) __alias(memmove);
> > >       | ^~~~
> > > arch/arm/boot/compressed/string.c:26:1: error: attribute 'alias'
> > > argument not a string
> > >    26 | void *__memset(void *s, int c, size_t count) __alias(memset);
> > >       | ^~~~
> > >
> > > Reported-by: Naresh Kamboju <naresh.kamboju@linaro.org>
> > >
> > > Build details link,
> > > https://builds.tuxbuild.com/1juBs4tXRA6Cwhd1Qnhh4vzCtDx/
> >
> > This looks like a randconfig build.
> >
> > Please drill down and try to report which combination of config
> > options that give rise to this problem so we have a chance of
> > amending it.
> >
> 
> AFAIK there is an incompatible change in -next to change the
> definition of the __alias() macro

Indeed. The following diff needs to be applied as a fixup to
treewide-remove-stringification-from-__alias-macro-definition.patch in
mmotm.

Cheers,
Nathan

diff --git a/arch/arm/boot/compressed/string.c b/arch/arm/boot/compressed/string.c
index 8c0fa276d994..cc6198f8a348 100644
--- a/arch/arm/boot/compressed/string.c
+++ b/arch/arm/boot/compressed/string.c
@@ -21,9 +21,9 @@
 #undef memcpy
 #undef memmove
 #undef memset
-void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memcpy);
-void *__memmove(void *__dest, __const void *__src, size_t count) __alias(memmove);
-void *__memset(void *s, int c, size_t count) __alias(memset);
+void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias("memcpy");
+void *__memmove(void *__dest, __const void *__src, size_t count) __alias("memmove");
+void *__memset(void *s, int c, size_t count) __alias("memset");
 #endif
 
 void *memcpy(void *__dest, __const void *__src, size_t __n)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106094434.GA3268933%40ubuntu-m3-large-x86.
