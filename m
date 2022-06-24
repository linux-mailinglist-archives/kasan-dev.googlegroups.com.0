Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRH72WKQMGQE6KQ3EXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 69F5D559620
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jun 2022 11:11:33 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id 3-20020a056e0220c300b002d3d7ebdfdesf1032351ilq.16
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jun 2022 02:11:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656061892; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jbt5xc9tcuFcje+u1dm+XjyP44wKxXXyvfLlWyojiLTEBtOMT5yOFO40XxO/gmoDlH
         wEWmG1Pu6S3ISG0r65GujDbeQDjWfFcrBFM6ZpHHGalFA3WtV7AkKuLvizqu7w6JNZR8
         3ku+6NK0VBmUaaQ6CkxpE7jQ475/M1wnX4qqRYNGxiRoms6mHuRMApGQbeQDeM7y7eIA
         XaI485o4zwmzceyUYtnJ1mt/zTfV+OkHk2QY0UYm6pKtyW1/dXeTukyfrT+8dTuF4IDo
         Lj1GSvUOj0KjLphayKoXzwoZUjdli5v7WSgGtMK64bW3Q2c4zRmBOUWW7GGSBp3M0Fdv
         2TDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kcPUqWZuvZ0NDXiUtbx1bVZpjmDWG2ppj4C5BkGB7Xc=;
        b=GG05NNX9nu16kfcMWdsKq5rxYTED5RVOwLurJFsojTS24oHJoeJ9aBOIQrXKRfEmM7
         805+GcwODmuhl/IrXnwFrpJER6BDcevXwegEhBqoTFhTaPRRIAY6BC8HUww8TueXXkdh
         aoJKH8KMDnTKEluf/faTR8N+QPhCg9z0mufZfIVfSWpuBf7c/iBfG0jfEEmXeIyac7B4
         rnQpU0aUMXHeR+Boa8DVWXGuEF1oOcI+Rngq8ue/sB9+rnFp4GrHpzrlKCvvOVGLbg+4
         7733fmNyWsMv8kk9zXanWx5iyLGS+86DPkMoknN8VhMBgf11yG3r51jhZ9o6X1xhA4SK
         ZQTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TOhxDmh9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kcPUqWZuvZ0NDXiUtbx1bVZpjmDWG2ppj4C5BkGB7Xc=;
        b=AddOE6rm/QXQMuExoS3+/iY1cSGSOnHI1yEswPpkvk68vGH64I6gqvrmBomWRjkZVB
         bLt1UbqC8K0TGjAiDPC/o/DjrZBL/Q6HhPToxgVia2lQYTRHyRJ7qfJMjkR0dbXmk/Eo
         bQHH1l3RwOAH8VEakF5IguSX+bsv6p8Q58k8svDdOpTbUs7m8DdYxlfUG9w5q/vtkWyJ
         dkK8SdpfJGF37rcx6CFpt1xaMiI329MGDPkaCSW9E/XR0SUPnghsNfli0ePQdUunJI+S
         z45WRyogM9xPEScxivkPJ4anVx+1RlT7tEsKhG+QiGjheTNf1a+pcgeIsL8NgbSLyJc/
         NVoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kcPUqWZuvZ0NDXiUtbx1bVZpjmDWG2ppj4C5BkGB7Xc=;
        b=UKhBReEPPbRZCbWtS/Waa9YFzGI0VRglQmnAnoLFk1MYlnzGgBRlCN7y8rbKGqO5i5
         gvNGLdkqiNeOFc0DINW1Xb1rMBCsv+hbmRDSaIRydet1rBXRWkWEFs2e0H/s9cVBdtSt
         Wov4+p7xehSTVaFb+7FIC2B90I/WGHhHTOdQ7uhwPXyjXJPzdOpagdvL+53NPLYo176Y
         ET12ml/O4aLW5C7ywWA1wykgky7IMIZVP0JWm7YSLiKhFz89MQSEFv46q70UfiITknfS
         nhJwszuzMNfrb4puCTvQ7YMmuNkOFEiXAYFTsK8sMc/jfeW37SWO6NqXOUR3ZBSFDlJD
         my6w==
X-Gm-Message-State: AJIora8jC0uSGi/qXfN4D80YuIxsT5qEOjT/h9N246XrIhKTZwIXGcLp
	tItL7+WAxvX9UCVich8KKCs=
X-Google-Smtp-Source: AGRyM1sWIiDGVnxar0vqmoLhanonj0vnHwHq/pf91oc+fskauSqyBUqJrD/wmS92mUEiduDu4p/Y1Q==
X-Received: by 2002:a5d:96da:0:b0:674:f433:3595 with SMTP id r26-20020a5d96da000000b00674f4333595mr3199886iol.184.1656061892259;
        Fri, 24 Jun 2022 02:11:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1ca3:b0:2d9:5a65:6cd8 with SMTP id
 x3-20020a056e021ca300b002d95a656cd8ls557858ill.11.gmail; Fri, 24 Jun 2022
 02:11:31 -0700 (PDT)
X-Received: by 2002:a92:cb50:0:b0:2d9:c2c:ca96 with SMTP id f16-20020a92cb50000000b002d90c2cca96mr7664646ilq.135.1656061891701;
        Fri, 24 Jun 2022 02:11:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656061891; cv=none;
        d=google.com; s=arc-20160816;
        b=nHkknJzIe1W5AgG8I9zNHfgcHeKakBkSprtgsnowZLDZtrucBra5ZXTCKe6ghqtOTy
         RAnaD4qGj2L/kxW1FLDc/JEKRuNvPl0t5XEp4IcKlyeIbo3nL62edmdY1ik7HSLsFVOV
         zY+6Cw4eRM12fSj1T/EyH/Dpdb/vAWSVk0qhM3gDh79Bg0RmV+iRk+SH/cOT/uCju5oW
         0Ng1OvACvpScRSJ0XWWnyJbaoHDce14ozKUddLT9zsB15Kv/wGwx4VCH15tvCyvrvCDT
         mSQX8KnyH+TRcu5By3k+iaLZZXORQgLvjXDMpyBDyhNzn0H9QLFRXKahDYs2H72Ewwiy
         +E+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hyQTQAZ3XspXZ2sNGfDrWiLVGkHDYE8Iizv5qBaCQ7M=;
        b=bHG+MT60I+xZE7k1ZRGrTI9DZXzT2rUXQd/MCPaehTMmWbPnYJcD5KpLVDdw2Z2oI6
         aGaBITCKI4Cr9DcIy+4z3ZZAfXb0ZRQqLsmxAX9hdopMXJZmq+YxyitEyPvBtoKxuXmR
         VfbU6nogl0bEJ2xz8KudcQmOiIc919lZLQN4kcWRUFzTx8rfPgUJePwT6oayIvSRGdr+
         cGK1gMKKCHC3rrF9i+EJ7LVszYH80nS07H2S3mxpyVE5F58RAZH2mM1K0V+1RO1ezrUH
         MBmtDcJJtLBcT/0pTFtSHJSMO3I1pFhAf85QmiUYFpGww6kjnPP8TtVCla0tKXrRaAro
         v7/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TOhxDmh9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id b5-20020a92ce05000000b002d6b599b5f7si91372ilo.0.2022.06.24.02.11.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jun 2022 02:11:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-3177f4ce3e2so18671227b3.5
        for <kasan-dev@googlegroups.com>; Fri, 24 Jun 2022 02:11:31 -0700 (PDT)
X-Received: by 2002:a81:574c:0:b0:317:7c3a:45be with SMTP id
 l73-20020a81574c000000b003177c3a45bemr15686171ywb.316.1656061891170; Fri, 24
 Jun 2022 02:11:31 -0700 (PDT)
MIME-Version: 1.0
References: <bf74019da22b3c6a750153cbc74ffe3fcdb0ddf7.camel@gmx.de> <YrV+Vu47VDGDQpx8@linutronix.de>
In-Reply-To: <YrV+Vu47VDGDQpx8@linutronix.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Jun 2022 11:10:55 +0200
Message-ID: <CANpmjNO+4uHo8sECw4e+hANQSHP+5UmFrZ2TgeRCsu2iuowYfw@mail.gmail.com>
Subject: Re: v5.19-rc2-rt3: mm/kfence might_sleep() splat
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Mike Galbraith <efault@gmx.de>, RT <linux-rt-users@vger.kernel.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TOhxDmh9;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as
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

On Fri, 24 Jun 2022 at 11:05, Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> On 2022-06-18 11:34:51 [+0200], Mike Galbraith wrote:
> > I moved the prandom_u32_max() call in kfence_guarded_alloc() out from
> > under raw spinlock to shut this one up.
>
> Care to send a patch? I don't even why kfence_metadata::lock is a
> raw_spinlock_t. This is the case since the beginning of the code.

Because kfence_handle_page_fault() may be called from anywhere, incl.
other raw_spinlock critical sections. We have this problem with all
debugging tools where the bug may manifest anywhere.

A patch for it already exists in -mm:
https://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm.git/commit/?h=mm-hotfixes-stable&id=327b18b7aaed5de3b548212e3ab75133bf323759

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO%2B4uHo8sECw4e%2BhANQSHP%2B5UmFrZ2TgeRCsu2iuowYfw%40mail.gmail.com.
