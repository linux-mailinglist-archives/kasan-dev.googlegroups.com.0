Return-Path: <kasan-dev+bncBDE6RCFOWIARBIVG57UAKGQEDOOPNLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CEC75D7F3
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jul 2019 23:56:51 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id q25sf7124lfo.14
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2019 14:56:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562104611; cv=pass;
        d=google.com; s=arc-20160816;
        b=yrCPGzVetWqsGA8JiSIj3ArYf9BhozwCRC0Cx+Ue+5FiKWku1697tGd5cDWpdutDN/
         aWEDa+q4aAw7U5fwGbODGgf50HcJlk/t4gXwubCOCd+v/xZNyP+mgTvtREjJEA/lYpGU
         7ckjwN6khGSklvhB2doj8fIi5xdMsWPDzTivnXwtxHtKTvLR0PJBkvZ2rnlDpx+xIsMB
         wPW7ZDEz0jjiNktEqI+TMfXdNqp8bZ1GGwQR3q8mKDXIPHl4fiwi5107kzGClKNTi7wq
         G4AIiaHyIBPyYMrCVmT7w7ZJRDdiYVjU/S6s11gA3qRbfq6Mb4sjXExCVcpXcHa/EZyM
         gI7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=GUxN0FeusjdvemK1X0J3mahKg7DBBeOXmiB0F5vxR9k=;
        b=anh6u8ISrUysP2xPTJyapAjba4hzq6NolRzo4+PwN2wwjaZtNVh4n0GVM/MFjj/6VY
         8ZHfWKSUABjf8oVmnO8OkWtPBo/b7MPEo8K/uYOSvsiRtf+UK/J1Wc2XQZJ+SxdWbin2
         XmZOLtj3WGjKO9k+0yiw9hEWejs7ZW+mmT0yELN019jHZQBAVedrhZI2tQt2dvtxGxFp
         muPN3Xxg5FQWHrLkDy32oZcEZ6qSoBDpX3FPwjeh7Bf2ajIUF0rSCKXfdhm3NgL7/Auu
         huWG3bDBG/qDbg3O+Nb5rJ+lZjCtPgJmrZg3MCUzBPw3QPipOKn8HdEe8tC3ycKilBDw
         /ahg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=chfL2Y+v;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GUxN0FeusjdvemK1X0J3mahKg7DBBeOXmiB0F5vxR9k=;
        b=IAmxvx/HDBg7dula80oKZJtW/5Uimm8dW8yRIundEPKJIK05Qh3bmIgBIwg8OS44Yf
         vt+e2Bdv+QFBszOU3XgMa11aXW6JQpkjnGDMhph+SFqcGprjIUqALx69AzWns4xJHOPk
         JsrksLlrs7Bk1F36+Wo3HEybtAjE1jX4n3x/fA2jTg3JnWinOQwvi/YErDH/VoCizqlU
         CQqUAKUgyxVJ3s6nFGteBUZO9DHAlQEm6oQyUzKYolqOZ1PchNE8K2s7RfKsmHZ+EA3u
         /jkTxnx2shO8Pu3o2lDaAe5S/VCSzRmycRizv5hS0qG9oxHgR05PTXF3nia0RGf2dNyW
         n/DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GUxN0FeusjdvemK1X0J3mahKg7DBBeOXmiB0F5vxR9k=;
        b=Zdu/7vdjot1tWk6zr9I4N0gQHv7+fqJgFsNttRr4hDclfJ+/uPhBqxbbnQkiaZ4KH/
         7neNv1AStpvIztD7IjRx7+8OlhSn9uulaOjy6jeR50PVTssdBdUNIeFUeLtzF4Gvd3hu
         NYSnLkGPAam3p3gTrqxwooKAUBjr7ZXwoJHH5pl2M0ryrysA+PTqXZK8ymAXilLekoZt
         bxo9p6CrTvhgHCAXzXfHtEgUqFViVtAG710ExFYlHQ80/pWHcblw29UQmpk0XSV15Xpx
         RpVq9uQay5Oi9qHxXJSmozzEEugmV88Xkm4JNMglj40ucAAmRjQKHa64wDS0j2i25aXi
         e1Jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV9WgZpIqbxhNCQrWsRA6Bo9vz6PcaV9PAvuRKayh2zU8ZH49yD
	xJFPoi9ktkxS5OVskvWBLKk=
X-Google-Smtp-Source: APXvYqzCNIoqpZ06CqNw85xq/GauLts+RqqS4ajDsnQQy8vw2zEVQ0F9V7wx5Ox5H81U4kfWct4W/Q==
X-Received: by 2002:a2e:854d:: with SMTP id u13mr19141861ljj.236.1562104610945;
        Tue, 02 Jul 2019 14:56:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:157:: with SMTP id c23ls16066ljd.8.gmail; Tue, 02
 Jul 2019 14:56:50 -0700 (PDT)
X-Received: by 2002:a2e:8802:: with SMTP id x2mr18497631ljh.200.1562104610467;
        Tue, 02 Jul 2019 14:56:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562104610; cv=none;
        d=google.com; s=arc-20160816;
        b=rAh6MR18did3V8m6C9Ny02bk2QZ7Li12TWI/uIDoRnkzdq4R1KNpyTdLK7+XC4HS9F
         HS87mbVOfbU0z554iSITqTI5UlmnRB8BFHs23/XJpZc34yfW+6EnyR0VDybQo2iNKdNt
         jtfqC93iMVbBZdOnKxoqnDtLnDReu3AU7T2VzfeQJHOmVn2hv200v4iCc4yAThNQ0F9A
         j4+Q5SJsk5pgjLF9atXCpABunjUvvwHcj7/ID2W+MqfqxKs6IqQecArJaNwm96vvfmsT
         v5vGcgUQUk5+nmi+akJRSN/VAJzRO+ynO5X1vtNHAP+ZYDhfDGwxa273QfUY2Ju2rk9J
         TpJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uy9P4Bv7MoU15f1hxa9HUk41ddeWB4vxhHhX7nu5AF8=;
        b=sBFQLzwvIWZUnS8PpwUwsTCYSgisy8VQ7IbQ7Bx0Mm79iDzBtZ1PYKptD393CNars5
         uaaaMKAxM9TNwk63QM2wDMyA1Lk2N1TpmxgntqcwgDmhKPyLvt0HljPcab/LNVtmQBgA
         lbsW2FA7m3shmS9a7sIn2AxgZ1g3DLUKM3TWQqtleZT9MjHYmbdr/whHIy2wx8DY00n3
         DHVd6gRq6tRSZAipB5hUIohLtl3BrcBnVEF1Cmchwp9pGbFCF2re+hlmXWPgR4X4PBxi
         +ZSUuCfhTCq0+7kUP45Jd1LFuguP+8XVuJgNxV0+vcSx3kjNcUdnVS8IMcZrCzmJa/M6
         TKvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=chfL2Y+v;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id r27si9278ljn.3.2019.07.02.14.56.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jul 2019 14:56:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id v18so152847ljh.6
        for <kasan-dev@googlegroups.com>; Tue, 02 Jul 2019 14:56:50 -0700 (PDT)
X-Received: by 2002:a2e:8195:: with SMTP id e21mr167967ljg.62.1562104610089;
 Tue, 02 Jul 2019 14:56:50 -0700 (PDT)
MIME-Version: 1.0
References: <20190617221134.9930-1-f.fainelli@gmail.com> <20190617221134.9930-3-f.fainelli@gmail.com>
In-Reply-To: <20190617221134.9930-3-f.fainelli@gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 2 Jul 2019 23:56:38 +0200
Message-ID: <CACRpkdb3P6oQTK9FGUkMj4kax8us3rKH6c36pX=HD1_wMqcoJQ@mail.gmail.com>
Subject: Re: [PATCH v6 2/6] ARM: Disable instrumentation for some code
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Abbott Liu <liuwenliang@huawei.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Russell King <linux@armlinux.org.uk>, christoffer.dall@arm.com, 
	Marc Zyngier <marc.zyngier@arm.com>, Arnd Bergmann <arnd@arndb.de>, Nicolas Pitre <nico@fluxnic.net>, 
	Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook <keescook@chromium.org>, jinb.park7@gmail.com, 
	Alexandre Belloni <alexandre.belloni@bootlin.com>, Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	Daniel Lezcano <daniel.lezcano@linaro.org>, Philippe Ombredanne <pombredanne@nexb.com>, 
	Rob Landley <rob@landley.net>, Greg KH <gregkh@linuxfoundation.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Masahiro Yamada <yamada.masahiro@socionext.com>, 
	Thomas Gleixner <tglx@linutronix.de>, thgarnie@google.com, 
	David Howells <dhowells@redhat.com>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Andre Przywara <andre.przywara@arm.com>, julien.thierry@arm.com, drjones@redhat.com, 
	philip@cog.systems, mhocko@suse.com, kirill.shutemov@linux.intel.com, 
	kasan-dev@googlegroups.com, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, kvmarm@lists.cs.columbia.edu, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=chfL2Y+v;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Tue, Jun 18, 2019 at 12:11 AM Florian Fainelli <f.fainelli@gmail.com> wrote:

> @@ -236,7 +236,8 @@ static int unwind_pop_register(struct unwind_ctrl_block *ctrl,
>                 if (*vsp >= (unsigned long *)ctrl->sp_high)
>                         return -URC_FAILURE;
>
> -       ctrl->vrs[reg] = *(*vsp)++;
> +       ctrl->vrs[reg] = READ_ONCE_NOCHECK(*(*vsp));
> +       (*vsp)++;

I would probably even put in a comment here so it is clear why we
do this. Passers-by may not know that READ_ONCE_NOCHECK() is
even related to KASan.

Other than that,
Reviewed-by: Linus Walleij <linus.walleij@linaro.org>

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdb3P6oQTK9FGUkMj4kax8us3rKH6c36pX%3DHD1_wMqcoJQ%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
