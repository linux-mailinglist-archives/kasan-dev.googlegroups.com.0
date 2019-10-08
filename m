Return-Path: <kasan-dev+bncBDE6RCFOWIARBFM26HWAKGQEQ5GI65Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 233B0CF53A
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 10:47:18 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id p55sf10766925edc.5
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2019 01:47:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570524437; cv=pass;
        d=google.com; s=arc-20160816;
        b=EKlANjm0Dvh/WNtI96HV7VogObfrJt0uanI/46UV7QGRxCLkJwMeqyqHnlVweVn2NV
         8zTc4khk5boE4TDHsyeXUJWj1jodUz4eKkhVMUzq1+d8b2tnqGYmi2QRignplbX7Da7X
         ydwOcToRNFCpZsaP8Rh6G+Acy1OKjT1BQCmKmfNFWm+YISC6k6t4ChxiOZmWeXE2D7/A
         msSh1BEcxOypNE98YPxzkpQ6iaNOnclCOAliMiManYfVyH66A/62O8Gnf4U18iCFvL7O
         1uKEVZhWCBVy8hffQCNJeK6PYcxFzHeiCBJO6K5Mllxx+crHbpiPcpUD3TEPyb1l72a3
         1JiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=l4hkVYhZUdo5LUUyQcgmgr8UvDHy+hW7gaefs6yNPwg=;
        b=Ou2/d6HhU+GQyDLkhWgCfjTmIUl/gbWU96nQ1i27UNyVjrjLqILC1bMGH8utYAzT3G
         +5l1rGK3h+pU2/5+6T1NeqK2kju0JPAXYd82S0LxoM7mHOSego6Vmd8TL3NYAoYedWtb
         Sxvo2RqMLbCfdCPolRzwKsZ97RRBDX5uSmKLH3UrzjDCxGen/bfolgg5JJDNIHzMWopd
         n4CESD6ngSRqZBGwDnD67AzLOxBm/PPtIgWBmACjGZrzfiIdvmpnR78/Dy18BcQTkqBW
         btlgvMev9Yt5YGJXSm0cHvrX7/En8QWeC8MycLowxaEGBvG7+NLigb/rNPszqSF+XzeI
         7eCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=BkRMuuut;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l4hkVYhZUdo5LUUyQcgmgr8UvDHy+hW7gaefs6yNPwg=;
        b=nwvLYY0ldkB46Y5KAl6O/1uYpUnQ+/uzwfQuQnfPmaTDlP26a4R9uEu7plZR7Ln+eo
         bZ3LNzbNW2PEWjDm8vPUZAq2GoieQEXybsJCe29Qit5QKTOMn488EhHvXKHe6hYjvmN0
         DsbvDvTQ59BHihFyaL6j68LRzfxE/fe/qm9u0xXLst4h9lFIurbQ4tuoi/X6qDPYr8xF
         ZTkrXGVE0Uu+kLaJNYlTJniRqjb1SeSz68Wc5Q/TbLYAtxJkse8vtG4rxKafo26RUeKx
         P+bgF9uxX13bOzrWQGd9up36F9fKY+QxIrSOm+i/PLgXrCd5ho0T4hEyS6I5HWNPF4PV
         SgKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l4hkVYhZUdo5LUUyQcgmgr8UvDHy+hW7gaefs6yNPwg=;
        b=HBQoke7McWHO60A+i+LPfg+ttfGEB8vPZL3HVLaYIppL3WxJv9zN85wfcwFvbUaZOr
         sjk6cKpXI1sfBBjf/Tn3EqjwdxWTp1B0qDPDCaSHQOstqNoXqLatZ1ki7QR80rj381eV
         zY3gu1kLUdpsUaY/kifG544uZzN8cwFA0j9SOVz+dlyJ3YOibf4jyVsS3tWveabLgBpR
         9R2w4UXv3m8I5VXQwlcdG+/B1iSwShzAstqN/Vg2C/ZXWja5JDkhlQOsk07O5Y9Kj2u8
         KsLd4xHPsk7U80bbMQU5mg9HH03+7Jbjfd2tbY5wt/5PfH4q5x6Y2w8Wu3QP4Csr4zsR
         gx3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWcBhv0Vj3JhEHUGmZssI8XvOkwkbQrrGALr0vassz77tKxZt2y
	B6Aqe1tPCmzmHQv2A7oBrwA=
X-Google-Smtp-Source: APXvYqxoBFaTwHEI2N0Cjpz4zI8VVfA7mQjnopA4fbpqkcssxphz+Us6qsUJcc7mzVcp+oz1CEIcIw==
X-Received: by 2002:aa7:dc4b:: with SMTP id g11mr33120987edu.70.1570524437860;
        Tue, 08 Oct 2019 01:47:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:ace6:: with SMTP id x93ls623101edc.6.gmail; Tue, 08 Oct
 2019 01:47:17 -0700 (PDT)
X-Received: by 2002:a50:af26:: with SMTP id g35mr33493753edd.129.1570524437395;
        Tue, 08 Oct 2019 01:47:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570524437; cv=none;
        d=google.com; s=arc-20160816;
        b=FAk1yQUUSj8Ry3Gp6P/rbuyzRfxnKzXFm5NuIXTSDKSDMU6ph90fU2g4RNVOcZbAgN
         Vpmj6zHEz8yt3eY8pu4MQgN+z5eaXFhSt+rthl1Xi4ToUFwX+2HCFK6+zVmHzzpu5Yhc
         XOx0D+zgnZBWgdZhRA3IMMTVGkkM8dxmvqeK4WjlDURZh7OKFBNe+aWd/BLk+1RhlLJ/
         FebNfW5/V142Gx2k7rmOsNpFZdFKDHatP/ZLqTnFrUCG6kFKrNQJ1HI1el0mJilyDns5
         C0QMFtJs5ulxInQwDv/SK3hbXt3Hp8wDkm/JeescDstRdiijRo8d/QqxW3gR2AE49jlD
         dLWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=l8gpydJYA0YDgp2JmqFlI7k3M5woSWANVYThPnzBSyg=;
        b=EG5dc+VAihabZooSC9I/MJMkB0uM1bBf7bjmQT/L2L1fD6ASHTbzdYC9WRNeEeOidk
         1dEOYc8SHMsANi/I9boDraeR6LxoNIMb2eX9nQZ0FAv2qtNvK9dfwDa9vvISIKvZD8VI
         b1pogLRE9XAd43Ms1d9C8wWV0aYkEvOy8gPwGtqKjRkPsFK9Qi9DE1GP/WxYYTwu8yHw
         F7CuhTvLpsWOoCT6u5Cj/HBb9cPnFxvfvI0rvIXw28wRvtGCpUtbxEm2k9lR6k+M1/d/
         01/6mmg4sQcFvHHox69FRc/wWAd2PTc174nVDcBuDX4/MqQ8J88/fUk6lchOZ27IW5Xe
         uZxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=BkRMuuut;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id q8si1640171edn.5.2019.10.08.01.47.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2019 01:47:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id d1so16593751ljl.13
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2019 01:47:17 -0700 (PDT)
X-Received: by 2002:a2e:63da:: with SMTP id s87mr20899729lje.79.1570524436968;
 Tue, 08 Oct 2019 01:47:16 -0700 (PDT)
MIME-Version: 1.0
References: <20190617221134.9930-1-f.fainelli@gmail.com> <CACRpkdbqW2kJNdPi6JPupaHA_qRTWG-MsUxeCz0c38MRujOSSA@mail.gmail.com>
 <0ba50ae2-be09-f633-ab1f-860e8b053882@broadcom.com> <CAK8P3a2QBQrBU+bBBL20kR+qJfmspCNjiw05jHTa-q6EDfodMg@mail.gmail.com>
 <fbdc3788-3a24-2885-b61b-8480e8464a51@gmail.com> <CAK8P3a1E_1=_+eJXvcFMLd=a=YW_WGwjm3nzRZV7SzzZqovzRw@mail.gmail.com>
In-Reply-To: <CAK8P3a1E_1=_+eJXvcFMLd=a=YW_WGwjm3nzRZV7SzzZqovzRw@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 8 Oct 2019 10:47:05 +0200
Message-ID: <CACRpkdbuwn-YBYd324OsfC4efBU_1pfnyS+N=+3DmrYOEKKFJw@mail.gmail.com>
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Arnd Bergmann <arnd@arndb.de>
Cc: Florian Fainelli <f.fainelli@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Alexandre Belloni <alexandre.belloni@bootlin.com>, Michal Hocko <mhocko@suse.com>, 
	Julien Thierry <julien.thierry@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Christoffer Dall <christoffer.dall@arm.com>, David Howells <dhowells@redhat.com>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, kvmarm@lists.cs.columbia.edu, 
	Jonathan Corbet <corbet@lwn.net>, Abbott Liu <liuwenliang@huawei.com>, 
	Daniel Lezcano <daniel.lezcano@linaro.org>, Russell King <linux@armlinux.org.uk>, 
	kasan-dev <kasan-dev@googlegroups.com>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>, drjones@redhat.com, 
	Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook <keescook@chromium.org>, 
	Marc Zyngier <marc.zyngier@arm.com>, Andre Przywara <andre.przywara@arm.com>, 
	Philippe Ombredanne <pombredanne@nexb.com>, Jinbum Park <jinb.park7@gmail.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Nicolas Pitre <nico@fluxnic.net>, Greg KH <gregkh@linuxfoundation.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Rob Landley <rob@landley.net>, philip@cog.systems, 
	Andrew Morton <akpm@linux-foundation.org>, Thomas Garnier <thgarnie@google.com>, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=BkRMuuut;       spf=pass
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

On Tue, Oct 8, 2019 at 12:10 AM Arnd Bergmann <arnd@arndb.de> wrote:
> On Mon, Oct 7, 2019 at 11:35 PM Florian Fainelli <f.fainelli@gmail.com> wrote:

> > > 053555034bdf kasan: disable CONFIG_KASAN_STACK with clang on arm32
> >
> > This one I did not take based on Linus' feedback that is breaks booting
> > on his RealView board.
>
> That likely means that there is still a bigger problem somewhere.

I will try to look into it. I got pretty puzzled by this, it makes no sense.

One possible problem is that some of the test chips on the RealViews
are not that stable, especially with caches. The plan is to test in QEMU
and hardware in parallel.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdbuwn-YBYd324OsfC4efBU_1pfnyS%2BN%3D%2B3DmrYOEKKFJw%40mail.gmail.com.
