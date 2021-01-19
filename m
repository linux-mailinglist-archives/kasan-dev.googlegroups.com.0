Return-Path: <kasan-dev+bncBDE6RCFOWIARBFF2TOAAMGQET4HNIAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C8BE12FB651
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 14:22:28 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id m20sf7972155lfl.20
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 05:22:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611062548; cv=pass;
        d=google.com; s=arc-20160816;
        b=vLQT2Omh0XOAjZG98R/HRMBSJXTL/Y7N4F8KZx5ZJr83HoeXFF0iRi9+Czc6E1FvTk
         fKWhO4zpZQDTgtEI8kiJttfUULzpA9YFH2B37A3p3S/aT+tuTd5ZFzE/XNchzXIj7d0+
         Q6b/8C3xhJE3F8tJ0IJHVsNKpT4CrriEPpZH0DUYbrG/PdUD/t/GETpJJwDHacqxFLIx
         hDXKRFQVxwt0dc+H8zjq8Ke/UudLmQPQb8Ub82suGosOSTrr8i/JBuUmvWNFWPRRWIWd
         XgtPmyE5LUecVcyKmhT7mASCLEXWWsDh+XOOxlV4lb1e4X33AR+Vx/KxAnOhadIo2BjU
         Y9qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=A1PHByBbCSNqy4vsmOtuGEf4kZPciKzCqUtGiByuMT8=;
        b=g+wTmij6HIKIf97KW+/rsC9uYueXm2kqUoyszWBuFF4dmUgHtD9gcB+Igh8UMeA3hu
         aAmld8CEOn306yg+JQBoy+XrcZ+ptzlfyglDenwNiX8tvW6dwTciLKRmGILl/Kfv4/tQ
         w39FjY1ujbs3K8WCUqcFeSdkRzex5vj136tQBSdp5pGIXj3yr1DgI+/tripOsFbELP7y
         XN6zGZRdfxW7fXo85Gw5QGN+U0Qgs1n6AF3TZ3njXDwBpNC5C0iDEvemMnLJsyDcNvw8
         b3KL+enzRl8zvFDl02FS4CwRUo+0ZAGaIVv1Jshu0epjR1ijyaGOOI/WDQXr5VnLxquC
         I9rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="Vu/2Q2wm";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A1PHByBbCSNqy4vsmOtuGEf4kZPciKzCqUtGiByuMT8=;
        b=L+wymVzMcBDzfKyM/Qk2dQSOCyn71IixMUNiAbfJ28NysHWz3UlV56O3DCjq5VEVBB
         JHtgVoip0Bn8E+rP3ACD17lnSbLzJkC6LA6dBjzI2zMd6znOFDKgLNJvHqzMGkejOJgs
         SFFSkSM7+7L0U1d0G0ENfzreVWGz5RJC0VtDK32AyDnQb1DxGOWIblj1/VrO40thPiFu
         QMF7IbSIdayQms+iLIsTP28e6aKsin6eenT/MLMyll5LroQW1KNgDEzqaUNzK7gUlOPu
         kfuNgGg8WeJ+9ttzN5pqYxZgw3TTb6lDzaMyTARhHHcHlg9KZRM7dB5bXXrQfMdVQQcG
         eWAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A1PHByBbCSNqy4vsmOtuGEf4kZPciKzCqUtGiByuMT8=;
        b=LL88Zkn+2VolAkwpiJHtj+oCqCXjNx4HfQkKJG4QaPVQX8yhhdJNRndFgcn/WB98Fo
         fJ8o/Ovwg3dSghq8WjfZ3z/ZbZJKDYPIS2YfusVZV/0YnJHxkb2oclVkAIKmhMwacL4n
         RLlW9zCP8+w2+yzFEdElKTm0u3Jr1JMw2JNrLKIEHJg34ZH+P/60QaI3O2nwyBLXgoJ6
         oiS4r3CQY5U5DUW2XfuttdE/EaK5yLXSo+s6sMiDAK5GXlIT2SqTAWkBGnEadqc0GQdU
         qxSOyp5W12MHaz2xQjrU9fn27e3Al0WHwg4ykdnJRXlWGmHMAeJQaSAtn9lRCqQ3lTw7
         e2Ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qXwGO4es3AJkOFQR2rbnai0nIOlhNvwEPaDpRQJms+kaJyt51
	ydsi3vMVZwRPZfJyAWvzDac=
X-Google-Smtp-Source: ABdhPJya1RgdGzG2gwP6+4andJOMo0JsrMvItXwWdnHi+l8Gk2g9OAGLCEtcXaL3RgAxiprXIqiz2Q==
X-Received: by 2002:ac2:44da:: with SMTP id d26mr1712505lfm.221.1611062548346;
        Tue, 19 Jan 2021 05:22:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a5:: with SMTP id c5ls3330477ljn.10.gmail; Tue, 19
 Jan 2021 05:22:27 -0800 (PST)
X-Received: by 2002:a05:651c:30f:: with SMTP id a15mr1798093ljp.503.1611062547322;
        Tue, 19 Jan 2021 05:22:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611062547; cv=none;
        d=google.com; s=arc-20160816;
        b=jJP37mbCsio/gw6fpgddVE9tD4vLhgFfY29tlZ0jo1k99OUFcczUR7P/hBwLoJab5S
         xw8OBuRNRT594IZIfBATWFj5BXOMADjgQmaqLDv7Yc1aVNvhVsemM9zAbHcjNAeiClDg
         nzR0GyxQEO7wDE/TWMttVFQWLFv/dJff8MeMCiqX+xOMJ0g/YMoStERLAUZEZPkkS6Pi
         Ws69fyW+8UFfUyzxA82IxPc23uHEsUwvtTEEMqZ8080DFHpKMyMz4cLALKx0kza/CSH/
         IHfrrkdRWaltL6Zv+hwrVLdtG2TVQnPw9QPJGBHjd8BTfsX9xoAih6Hk+HSr0MjvPw1O
         6LBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JR0BOQdoAFuZHlu/zdybk4sP48Jxiy5FiTrzPMbPGlY=;
        b=GhCk3IpD/ezqMKyjbw/lRamrz8qV1VJpR2JrnxYJD0gwx0gAjiGA+Y8Sd6Y5OwA2Q/
         LmH9u2m6IjzyHYdGAMF8OKUEbKj97wwKka4ck/HupW87oLCwX7aRACHryEcdT8JZVv34
         mIYOuDCquO9xJ1WSGVbVSPf/eLsQzh11VajHBKzkXKNFkIDwyEVAIc+A0JzUkUa/5W+t
         Viftx8OI/S1Q3vN/fBf63AcAit6JdXxDSJt0l6NuhL2wQ1U8cgyOXBIMv+IDTztUQiKp
         wF0ijQmRuQXZ1ahhpRs6CfLug21uqPk4roJbt59oesVA2iQab68+K+Dvg6409B4Qdus1
         HQUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="Vu/2Q2wm";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id u25si890881lfd.11.2021.01.19.05.22.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 05:22:27 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id 3so1674669ljc.4
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 05:22:27 -0800 (PST)
X-Received: by 2002:a2e:3503:: with SMTP id z3mr2045331ljz.74.1611062547044;
 Tue, 19 Jan 2021 05:22:27 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CAJKOXPejytZtHL8LeD-_5qq7iXz+VUwgvdPhnANMeQCJ59b3-Q@mail.gmail.com>
 <CACT4Y+bBb8gx6doBgHM2D5AvQOSLHjzEXyymTGWcytb90bHXHg@mail.gmail.com>
 <CACRpkdb+u1zs3y5r2N=P7O0xsJerYJ3Dp9s2-=kAzw_s2AUMMw@mail.gmail.com>
 <CACT4Y+ad047xhqsd-omzHbJBRShm-1yLQogSR3+UMJDEtVJ=hw@mail.gmail.com>
 <CACRpkdYwT271D5o_jpubH5BXwTsgt8bH=v36rGP9HQn3sfDwMw@mail.gmail.com>
 <CACT4Y+aEKZb9_Spe0ae0OGSSiMMOd0e_ORt28sKwCkN+x22oYw@mail.gmail.com>
 <CACT4Y+Yyw6zohheKtfPsmggKURhZopF+fVuB6dshJREsVz8ehQ@mail.gmail.com>
 <20210119111319.GH1551@shell.armlinux.org.uk> <CACT4Y+b64a75ceu0vbT1Cyb+6trccwE+CD+rJkYYDi8teffdVw@mail.gmail.com>
 <20210119114341.GI1551@shell.armlinux.org.uk> <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
In-Reply-To: <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 19 Jan 2021 14:22:15 +0100
Message-ID: <CACRpkdYCoRFzt1V827Y2EMVpZwE4eH=DOBVYxOEhiqaJ0aFXPQ@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Russell King - ARM Linux admin <linux@armlinux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>, 
	Krzysztof Kozlowski <krzk@kernel.org>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="Vu/2Q2wm";       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

Hi Dmitry,

I created a minimal diff to vexpress_defconfig and it boils down to
this:

+CONFIG_SLUB_DEBUG_ON=y
+CONFIG_KASAN=y

This is really all I do!

On Tue, Jan 19, 2021 at 1:05 PM Dmitry Vyukov <dvyukov@google.com> wrote:

> Yes, I used the qemu -dtb flag.

I'm using that too and WorksForMe :/

> Error: invalid dtb and unrecognized/unsupported machine ID
>   r1=0x000008e0, r2=0x80000100
>   r2[]=05 00 00 00 01 00 41 54 01 00 00 00 00 10 00 00
> Available machine support:
>
> ID (hex) NAME
> ffffffff Generic DT based system
> ffffffff Samsung Exynos (Flattened Device Tree)
> ffffffff Hisilicon Hi3620 (Flattened Device Tree)
> ffffffff ARM-Versatile Express
>
> Please check your kernel config and/or bootloader.

Appended DTB works fine for me too, just echo foo.dtb >> zImage

You have to use a compressed kernel for appended DTB to work
though.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYCoRFzt1V827Y2EMVpZwE4eH%3DDOBVYxOEhiqaJ0aFXPQ%40mail.gmail.com.
