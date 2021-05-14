Return-Path: <kasan-dev+bncBC7OBJGL2MHBB64Z7KCAMGQE7FEWYZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F3EA380C20
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 16:45:16 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id e23-20020a17090a4a17b029015c31e36747sf10995708pjh.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 07:45:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621003515; cv=pass;
        d=google.com; s=arc-20160816;
        b=AyT6L2upvVRZjc8I/aO2K8qWNAucsCCCWX10YERsZxVilatqreTjeV/E0rGtjm9GzR
         rt2lW+JvmgMZMGSfIPce3/IYmlnau+nQzVwJpv3BVjQwz9nFaa62TgOrGDA4BjpHksgG
         ttqmQilJTFDVfIL2twGN+HxrMPPq/D1ImS87OVheIzufg+Fr4TdzD5nnIqA2iejbqa0Y
         1y+mv7xsUvvGHX6Wlk8OMXbNZg/lmoXNmyxpmUTR4Ih3SkMmo7wTQXdgjZh4CrXThmTD
         LmjJmcxsq+y1BqMyZpSY2p80TeMQ5WlEX2SRCyU1jqWVt3GrmsTXrn9cRNoy+/ICZUn0
         MwDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hMxd9eZlkgkjUr2bYw17MGIO03AAK+zcHge57fDJOtE=;
        b=VrGidKvrBFlGuozLwQ95iYxmM+x7Olhgs56XSKX0KjB7BU0AorVwmR6MqGn6NBr+0G
         ZL8ZdsaPTDac8ldR3Ua4z3edcZqycEC8WtfHlHPCnNxlKMS1N6yerSTvgk4VJ24dbcxF
         kwLocX2c4KKk/vgOXz7z+vEky+Xo0GrbLjiPMsgSmVtvJmWH0oY1DEuheJZyJ61kg/HA
         mATdVWebYyGe+CuD61Se1R6w0lt9yOOJWhnXzKHmUNgMs50kbLL3BYIQDYendmGPNOo6
         qL8ablEVX5JCMVeFJeb4nHfFDbwRFishur234wuFAOWoZP5vyNijADVOLGc6H6QK1c/C
         xbCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cCh4rJ+j;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hMxd9eZlkgkjUr2bYw17MGIO03AAK+zcHge57fDJOtE=;
        b=poqtf8oSw7d349KMxb8af9CnEeE0w0RztyBND2GknqVZ9ofagdrrrNH+54sp7XHxu8
         Aqy6rEsPJHf3wOpkP5GFN911Scafjl05zKO/zz5jjV4vMcKkuzthSrQtDWCINx56blnd
         f2LpbeXpmG/ccp4SHp5Xfwa5WCqCP2KOuLaExbRJkEqBWVk3OFHXuueJwJFNfs5yKI5b
         x3eZitFxGAAoV/yAJr0OY7sCek+27hmTTKo3tHD/ch2/xUQ+tAIqgHfIjaU2ShkgmmP1
         a/vEf/j2uV8S2WTIXTZVyOFOufGKLLk9l/Q1gAyVEF4COae3pjTTWoOzIim3k/70o6HK
         62cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hMxd9eZlkgkjUr2bYw17MGIO03AAK+zcHge57fDJOtE=;
        b=TcOCGGsjsE9WsYmm1DBAouz4A7dQt4/eTDCgfiM+nBpViUtKtf2y1YWQ416MZiYJlw
         48o4o44NbF5JpEYIyJB7COUbCDPaAKz1jGjZGWmxaf4dS/NPC3bv8Gc5ltQlE3JE2tC+
         89tUkJYW8TC8WuJ+L9R34sVe37qObnMAN2Ya/xd7WNg8n1fYVAn/UN/UbQkExSImwd5/
         K0bej4Ww60YfeZAHC49cBIURetjGEMVKjoNyOYe5DH8dfiK4V80vOzYe82YHMrL4f1cy
         f4U5uaAzhS0oqMViQG2QNvwiiulCRQwRUrWf4GiW3XZK2V2W/vIvrXE0rbS7wSsO0jcL
         TQSA==
X-Gm-Message-State: AOAM533BZpEl17ZnAhrRpmUHCkUzFV4vxDkLwP9nBLMqcBTlvXVLm2/7
	HhmLsIF2kaYQNx5gZM2psSQ=
X-Google-Smtp-Source: ABdhPJz8UA2dGOZu1AOJNe5eBS8oEOULK+n28/amnbMA+RS8DZtIicK++DQuftyvLZSEBQaQXPfBAw==
X-Received: by 2002:a17:90b:915:: with SMTP id bo21mr50712915pjb.27.1621003515213;
        Fri, 14 May 2021 07:45:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:fb0e:: with SMTP id x14ls3852895pfm.10.gmail; Fri, 14
 May 2021 07:45:14 -0700 (PDT)
X-Received: by 2002:aa7:85d0:0:b029:28e:80ff:cbf4 with SMTP id z16-20020aa785d00000b029028e80ffcbf4mr46265417pfn.59.1621003514532;
        Fri, 14 May 2021 07:45:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621003514; cv=none;
        d=google.com; s=arc-20160816;
        b=zhCoiN4Lvfv7g3w7mcbVhiM0zfatM2fTK2VL67K0BYxbeCCmFJXkZBHlL/TJBMLnT/
         DzXZmL4ExIr/WdRMoaEJZoINSaav/kJmS3VE5gJ8l8R/ACM77BlImnY1M9sAWnYlpRhw
         f1uAtyZWFA0fiC/55fuDUfPrxtX3rObVxcIQM1KzOFfayxc6lO+5DUjxOPt2hfGr5q0Y
         pUi7/N6+IaDShO9rmVVoIrqaQHXpMgmdD1MYYUiFx03g+Ru9ZBlhgu655G/QPg7SoTeI
         ndS8rchwohu9jFsL1WlSZ3fS6W9bjOs0WRQ4Wq0qqQ1A+mZnD9EJ+VltBqwpw88iXH96
         7ffg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a4ec9HrK4exLNdFoaRuR+1/fBbQJf79OPKrfXFd1y+Q=;
        b=HRoEOPJybqd05FaiNHXGKPg1JIog1a37iJwJI7p6ZOLN1jFo6vLr8Cl3CRkIM5jBUP
         EvrJi0ocLyzCD5tZlPxdx0MN2z1A7VUo1iMVdgvQNOHIC+8VfQ2mF3qWwL8I+ad9rS61
         ug5TfDYddn/87gG6nnJJhC3Q0oztNFqCjzSzi4H1g76aABK6VulJ4BOFAhlKUGlwHCnw
         vImgfFn3p9l2mGXIWsfEr1ONGywZSdjuBFE+1bCT+Oi/lj6N6JQf7TL99+G7aeXoUY3m
         OSI/NltfJUOVwQ/4ZdOoyUvGZtta8UWa5Ev0DLslwhmGupy/vJbd2ogGYhh3D321dzHG
         VAYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cCh4rJ+j;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x233.google.com (mail-oi1-x233.google.com. [2607:f8b0:4864:20::233])
        by gmr-mx.google.com with ESMTPS id x27si171786pfu.0.2021.05.14.07.45.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 May 2021 07:45:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) client-ip=2607:f8b0:4864:20::233;
Received: by mail-oi1-x233.google.com with SMTP id u144so4052074oie.6
        for <kasan-dev@googlegroups.com>; Fri, 14 May 2021 07:45:14 -0700 (PDT)
X-Received: by 2002:aca:408a:: with SMTP id n132mr34789902oia.70.1621003513688;
 Fri, 14 May 2021 07:45:13 -0700 (PDT)
MIME-Version: 1.0
References: <20210514140015.2944744-1-arnd@kernel.org> <YJ6E1scEoTATEJav@kroah.com>
In-Reply-To: <YJ6E1scEoTATEJav@kroah.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 May 2021 16:45:01 +0200
Message-ID: <CANpmjNMgiVwNovVDASz1jrUFXOCaUY9SvC7hzbv2ix_CaaSvJA@mail.gmail.com>
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Arnd Bergmann <arnd@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cCh4rJ+j;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 14 May 2021 at 16:10, Greg Kroah-Hartman
<gregkh@linuxfoundation.org> wrote:
> On Fri, May 14, 2021 at 04:00:08PM +0200, Arnd Bergmann wrote:
> > From: Arnd Bergmann <arnd@arndb.de>
> >
> > clang points out that an initcall funciton should return an 'int':
> >
> > kernel/kcsan/debugfs.c:274:15: error: returning 'void' from a function with incompatible result type 'int'
> > late_initcall(kcsan_debugfs_init);
> > ~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~
> > include/linux/init.h:292:46: note: expanded from macro 'late_initcall'
> >  #define late_initcall(fn)               __define_initcall(fn, 7)
> >
> > Fixes: e36299efe7d7 ("kcsan, debugfs: Move debugfs file creation out of early init")
> > Signed-off-by: Arnd Bergmann <arnd@arndb.de>
[...]
> >
> Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

Reviewed-by: Marco Elver <elver@google.com>

Thanks for catching this -- it boggles my mind why gcc nor clang
wouldn't warn about this by default...
Is this a new clang?

Paul, please also add a "Cc: stable <stable@vger.kernel.org>" because
e36299efe7d7 is, too.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMgiVwNovVDASz1jrUFXOCaUY9SvC7hzbv2ix_CaaSvJA%40mail.gmail.com.
