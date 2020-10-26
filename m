Return-Path: <kasan-dev+bncBC6ZN4WWW4NBBTOF3T6AKGQEGGFXBPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AE1B2996C9
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 20:26:06 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id t187sf6635313iof.22
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 12:26:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603740365; cv=pass;
        d=google.com; s=arc-20160816;
        b=B4/0iAxFZgaMKmoNHEcNbWUmScYLF8k2vw5M5ihp7UuhC++O2sEElVTyMJYm9o0Bqu
         2befEvwYCCRd1nQkUAG80HdAXQxDNu10UndIkL/xhq0PbKRjDO68P5yQiqZBQpHfy6iQ
         hySxYgmR+2qVxGIVhZI7Vwn6QOlAUhdO7An/Bhtg9IxgL6odCJbHkhV7HA/69cyZNkqb
         n0ZimvfbUXtMvvus129d/m788RXP7yXa46ZCUGb8fNWAMYCz8iH6huzhJyeIW2tTSyii
         WbvJcAXXkFHgFNulyG8OCQyrbnGDRJBAR4GXl3XD0gGFxCrEkRugvBZFCX6TpS8agRs6
         MbKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=To3v0fcfg+d7fEPt/E6F9X1u15huN3dyKLONrJy2TcI=;
        b=hRMvzmJhGnrJtb9hDiVzc2vtDLbbddxevRxpA5qqXFnrP4xQQfQfAOnriEakyMhd60
         533QeYI05uOi/pRNzaWx1CNUpQd16vW7FyuMvF9/u8UiOh2u5kSGm7zJS75mVfzLCLXk
         /rEEJLsma42mFTx5ecrK1GOcVMhrupIp3anV6VkmaOW6oamaPjbn7tuCQgdVHkVVd+hL
         7nWq//z32MNpMkqr2seEPaAUzaDsGyprRKSzoqGve0PjaGnb8QNHW+VC7kinLHqXda41
         NmzU2IXUc5jHWfmgTbb6UKUMMp1vkt9Wm3p2EqV/VjstEa3c8IK7k1POVkzUc+LPUCGL
         JVYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qjFXhgz2;
       spf=pass (google.com: domain of jidong.xiao@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=jidong.xiao@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=To3v0fcfg+d7fEPt/E6F9X1u15huN3dyKLONrJy2TcI=;
        b=cP1uQwaTlXgFtlnJXNFnXAi4ajNPL8AjlFJ70BehLnGeJ8+mkC+sgZEAEs+JbUkvx+
         NLnrHm6eovcvQsRLAHgKWUmGTUhRHK0nSmMcPGkUb3BqO9NGHXZKttqQklWG2gsEp4UB
         H5k8NcjOE3QxUIJ+TMSvRLmHzL0C1ThnXNrXmjHu+6ENahE5Z0J0xaNocdu6tQwcbfld
         Bh4Mm2o06vRyCi17385jzdTT/Ukc2xSdmvtqpDXkj6fZ29xbFcOYDP7/HFb0fGkNMKJe
         0i7arEOonuHacAV4VnIlRewT452sQ/sSwyTT+aF4L4Gyo5QccGIU+QNm8Z0mr0ImQhSe
         Q3Ow==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=To3v0fcfg+d7fEPt/E6F9X1u15huN3dyKLONrJy2TcI=;
        b=A9TdoXa2gQtGWtmeQsLHZRwIv/TFLj+uu5/zlaMqeivSZyUsiOaGlzPTQAfHrdGITh
         wdattE7O0T9/Z80H8RmJI3EkDtrNvJi73cno4HoZxto3azmW76R+yaRKTtLasciabl7J
         Nm87wT29yzcSIbtlmwZX3Fx+H5jjVssxlt21WZmvohlDrKLDXD5aaoQ5iLfyeQEhVDrn
         CztH13obm7TkVRgFnhxqE+2jOF4Ye5AQH9WYqYWIWY8wobYnh8I/0Xe/b9YPhpn3phSY
         aostWNh+VHTuKVpN5qT1WwYvbKzzRdKNYmfOjKwJgGOUfiC1N9C5dIlLFMR97lkFvXij
         SBzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=To3v0fcfg+d7fEPt/E6F9X1u15huN3dyKLONrJy2TcI=;
        b=SqbSH4hyVyCcCVsbv8IyX6hAfeamd+gxBHvC0+1EmF550+hfJlMeax9wvUU7/+p74p
         OamnF3ckzYeGJ9yVV9QRLPBuhjqeEQJwOuOTeQL9LY2b9sRcc7eJJB1HhXzzxv4cNYZF
         7uqe5yaxmURbhqzUgzE+dzwMJzCzKeqD+2neh8a8U2GttpT8LR8n6Evs8UydElgQ6doW
         o+PCVejcBl3WFh/tffxyyG6fkXMLGWZB6aEch11NCq58/0trURbTOMdjkWGC/S+F7Yiy
         2FM3lfpB0hsIKaYjFWxTG/VuxqD1FbY5SK0tjbT7E3lnQrkBzUxvGY3P1yVxB17Tbnvq
         tv9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532t6ZOPg31SdjMBwPry21idHkLWqK09TsdCF7r2jZDWEpW1KaTd
	fSu2U1oOtJIorUR2dc1u9yk=
X-Google-Smtp-Source: ABdhPJyGGUvYh4K0H9AGU6LQGwiu0AxzfIHnwk3wIEMTmNbEd6sU/3zBuzUZ7l65K4jEqwJjgf5BUQ==
X-Received: by 2002:a5e:c917:: with SMTP id z23mr12036743iol.38.1603740365199;
        Mon, 26 Oct 2020 12:26:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1308:: with SMTP id r8ls269535jad.7.gmail; Mon, 26
 Oct 2020 12:26:04 -0700 (PDT)
X-Received: by 2002:a02:9543:: with SMTP id y61mr13416370jah.64.1603740364811;
        Mon, 26 Oct 2020 12:26:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603740364; cv=none;
        d=google.com; s=arc-20160816;
        b=NTHyo1tDpJ+H7FDRRMhNMUp+P29lHRvYeDWES2/g4BiMEorhFJq4sndlLW6dImwPkp
         YFUUpryhlHPHg+PI8jiGdgs+U1rdEIKUDHqqFLR0DWN63OfcESqYOXf5C+cn2s3eNWbS
         S1Fk0f2VP80lRctIYobYUDXZZggJnw64tTvYwMWNM33t15TW5sNdZVvfwzl2/AEPu8lG
         FlGvYe+Bv2dL9okJwiFrnSvGLr6F5tpHoFUkS9FghooF3yjbMLJA2SBKROMegXZGxMG5
         7MlzunsiXN+NvPC6LHWWV4CWGqvPxIHnvxfnH9l319Clppj/Y4Dj5iCsUaw7+9d2XrIb
         jPrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=t8zHQDWotdDzPaV+Ia4r8xRp6haejuGNq6tWRUduRFg=;
        b=j+jJQh2u0y36PWB6dhJ0KhI9IPIT1oTEwpP6BdUsRMEQR2KtJSVHq/pjnBF3gVfrjY
         AvabQbJxeRj89ZXX9mfG4w82iUiWtEx2ZuwVYsYov6Ix1vY/Rq6VLTTcnyzwUPEBvewl
         mz5ARey1KwmdBjI636VkGQ9f9fu+Ljg3HAgIvFJPT6QsrZZ7Kd7yYxCVWzT28n3vBhsX
         g07GHb+uO4cgCNpy2c4OmD+rXiJqqghEyyYTIMvWu15lpDHvDgytz/7yql954+nBSd1t
         04zNkty35O9myS6qknk4LcGY+4q1YLoJU+Az3fhvhVZFAs1IpTJ4strpgoOHpbhNt9zp
         u7Fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qjFXhgz2;
       spf=pass (google.com: domain of jidong.xiao@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=jidong.xiao@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x142.google.com (mail-il1-x142.google.com. [2607:f8b0:4864:20::142])
        by gmr-mx.google.com with ESMTPS id l14si629485ilj.1.2020.10.26.12.26.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Oct 2020 12:26:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of jidong.xiao@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) client-ip=2607:f8b0:4864:20::142;
Received: by mail-il1-x142.google.com with SMTP id x20so4149763ilj.8
        for <kasan-dev@googlegroups.com>; Mon, 26 Oct 2020 12:26:04 -0700 (PDT)
X-Received: by 2002:a92:1943:: with SMTP id e3mr11759147ilm.140.1603740364534;
 Mon, 26 Oct 2020 12:26:04 -0700 (PDT)
MIME-Version: 1.0
References: <fbb6a417-0767-4ca5-8e1e-b6a8cc1ad11fn@googlegroups.com> <CACT4Y+aGLpDf_j7LziZZpNi0UVOBJzyhu-WV_hySQiMcCBQXLg@mail.gmail.com>
In-Reply-To: <CACT4Y+aGLpDf_j7LziZZpNi0UVOBJzyhu-WV_hySQiMcCBQXLg@mail.gmail.com>
From: Jidong Xiao <jidong.xiao@gmail.com>
Date: Mon, 26 Oct 2020 12:25:53 -0700
Message-ID: <CAG4AFWZvWRMYR-7+zv7RS-Khd25+AEgdyX4O86utTbTZ7QD3yA@mail.gmail.com>
Subject: Re: How to change the quarantine size in Kasan?
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jidong.xiao@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=qjFXhgz2;       spf=pass
 (google.com: domain of jidong.xiao@gmail.com designates 2607:f8b0:4864:20::142
 as permitted sender) smtp.mailfrom=jidong.xiao@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Oct 26, 2020 at 12:19 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Oct 26, 2020 at 5:30 PM Jidong Xiao <jidong.xiao@gmail.com> wrote:
> >
> > Hi,
> >
> > In asan, we can use the quarantine_size_mb parameter to change the quarantine size. Like this:
> >
> > ASAN_OPTIONS=quarantine_size_mb=128 ./a.out
> >
> > I wonder how to change this quarantine size in KASAN? Do I need to change the kernel code in somewhere (mm/kasan/quarantine.c?) and recompile the kernel?
>
> Hi Jidong,
>
> Yes.
>
> > Like I saw in mm/kasan/quarantine.c,
> >
> > #define QUARANTINE_PERCPU_SIZE (1 << 20)
> >
> > Does this mean for each CPU 2^20=1MB is reserved for the quarantine region?
>
> Yes.
>
> You may change QUARANTINE_PERCPU_SIZE and/or QUARANTINE_FRACTION:
>
> #define QUARANTINE_FRACTION 32

Hi, Dmitry,

Thank you!

In ASAN, the quarantine_size_mb doesn't seem to be relevant to
specific CPUs, why in kernel, this quarantine size is defined for each
CPU?

Also, what does QUARANTINE_FRACTION mean? if I want to specify 128MB
memory as the quarantine region, suppose I have 4 CPUs, shall I do
this:

#define QUARANTINE_PERCPU_SIZE (1 << 25) (i.e., 32MB for each CPU).

-Jidong

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG4AFWZvWRMYR-7%2Bzv7RS-Khd25%2BAEgdyX4O86utTbTZ7QD3yA%40mail.gmail.com.
