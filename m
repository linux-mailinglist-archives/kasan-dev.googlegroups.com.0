Return-Path: <kasan-dev+bncBCH67JWTV4DBBKNCRDYQKGQE2GSAIPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 486FF1411F5
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 20:55:23 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id bc5sf7176609plb.15
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 11:55:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579290921; cv=pass;
        d=google.com; s=arc-20160816;
        b=jhbOZ/a8zsPlb18uilOSgDg6FO72n3HwXqCdEpCA2QzoNWfGRLRgRUBFRFVnt2Y5ze
         do0iMxVQga8p8aAsr941HMOMekbo8AAa+jgKtF+1nB8TBKFEIESHq7VtkgSouThZZ6GP
         FjeVB+LCbkgcozK4lvOUAfeysNU4WZ4mbHMNQE+1+eNbFkZBNIi06rFeBxtdRC5tRXQ8
         SXWwIAe9y7JN2wwFyugn71PFQJpDCqyUjtWFTkBY1qtAvlyHyw+iGnjQhKAdum8F7T7u
         bsjTUQax8OaJRCdj1rSYK0GjJ24AZkLe6nhd3mv/UB9V/iwQgwEiQgAJVwdTGnQbuLp9
         Lqdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature:dkim-signature;
        bh=j4dn0TFrVA2HeSSfMt0mcYOGONfVKFDrfJpJ1xCqVLs=;
        b=pvcCthahboueB8yrHc+mZIUZ4/xXperYKbul1iUaPWmnPeFS3hSMQVUClNE9sDiyWa
         GGcW3Dj8WrsTTXjvxO+JSdTvdSVne26sGpyf1dvgstLgHtSKLsY/9NCAp9NZvm3dx6VS
         uVz4ndlUPqwrVBuR0nv2K0hHQ/ucJjT8wYeQIEfdfLgCW6GQgXc2MKqryLi9WSk4Jdy2
         3lZmpqijK7zNpSMUFcW0a+FaD6ooQCaDgvdFMg86++AgNr0pVjWx22KT4yA0VybSkBY5
         IXPPeCbQsoV5ngnfQexXOfWiWPl9eyGr7G94DSQTa/oDF1CSNrldXxCeUalbkE9Pp1Yp
         a4sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=carExSaD;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j4dn0TFrVA2HeSSfMt0mcYOGONfVKFDrfJpJ1xCqVLs=;
        b=jUvboqR8lwd0+uGX2OTQKQpbHRrCMp7Q5hITaOze7pjcvuyJitJZuQDnKR5vloGyG3
         +K7khMJYop0tuMsBNrnH7rCHjYIFd0KWMGwtKdpdrxjJ8eskmKKKMInS+gB3bo1Lt7La
         04YzQPnnWAsejACLnujTg9sJLdg4A/OaqyFLDZxU3LJNm6pgY4vzXXbcbh8nraecRCmF
         6c4A/0L3GzNiZp2ygBpeCnrXPlzJoYq8hS2SgZspDv+HAXTuS29PnhkZ6QwmEO6h9/ny
         ipA2iKZI1q+MWMxy3LiviaOuhMdg7VSH+YjFB+9Tn8C5PsgyJKgrW9ctCD5AaT6tgmJ9
         V4og==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:autocrypt:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j4dn0TFrVA2HeSSfMt0mcYOGONfVKFDrfJpJ1xCqVLs=;
        b=ap0CTwfXjbhvoPQEM4CiwR1DBeK/HIxfTk5zDG6PRW2DXw44WB4y0NYA6N+LM45KBW
         /EzqfMY2BkwHEaMuHyuyHtYsH3Sz6K4mr+s5JnpMer8VTKRtQwbPzZqkxu+E8N/WS7OW
         P7wLDJ/8unnxcPqqh0ggFbxoBzaVYPCwAfhGX8GqnbSa4W7XPe9Y68+b5KhwUgHHWEFv
         l0FBtm9FH16GKZ9HKNd1VS9cglyMlulwEnl77MTsyELGV7OXcj7hpa+osxxx6wiz30aN
         zpqjg6ihHbQRiCK6u8iseR4deM2BHSew/iXon2E8k6kZioOkGEB2exawHir/ZcElu+5B
         tSDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j4dn0TFrVA2HeSSfMt0mcYOGONfVKFDrfJpJ1xCqVLs=;
        b=JlvBTngzZG3mM8r3eQWCwI3a0Vxh9FKQFB2qELb6dyEdj7jfcF5dcYeWNJ8xMCk5XR
         K7OnZYOk10M2GA0oXd5ZZ/jQS+2qks1hrIRKr+hepSbJRKLi2eqcdxPIuEuGaUfT4s08
         6s4k0/wQXFBIsHjuwdfrESSTttVXg8XAyCFO5oBEpfCW+nGgcjR4eP31zs1RrjR5kizE
         mz/6ES3MAIMikCDgVAA9kmz9MkGE+BJA67ofxj3FFggZMvGqfXcDQi40Licxa92LJZId
         hiKSnPRfB7lpUHXMM+zLpbzsoplU/mSYNqY/3nOZXZLz8I8i1Ltq5YVnigqguWxMpnM5
         u8Iw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVGjmgkDl9GWtLMWqn4djbdJ65eDE6tO9QjFHcG6V61gOQctnfA
	Xg2rfnklow6eqp1RdSpm9WA=
X-Google-Smtp-Source: APXvYqzdiRKJ2HI3wGOpbjrGkm9SmDZaE8k2n/S/h3ghOFOAkSC8NzTaU9BaHmZXDa04C4OxIWOs1A==
X-Received: by 2002:a17:902:502:: with SMTP id 2mr810852plf.151.1579290921250;
        Fri, 17 Jan 2020 11:55:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:93cc:: with SMTP id y12ls8011590pff.7.gmail; Fri, 17 Jan
 2020 11:55:20 -0800 (PST)
X-Received: by 2002:a63:cd16:: with SMTP id i22mr48830933pgg.239.1579290920625;
        Fri, 17 Jan 2020 11:55:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579290920; cv=none;
        d=google.com; s=arc-20160816;
        b=ZVobwAcRPcXl0fKMjjmYhFXFQBhFI5G8rNHqTT2ZkHIEORDZybHEeFErcnBJFzBR8w
         YAveD16qiKE7/bkSwGwJVXBM9QehjNeYdQ+jvNy/7tgRvRsvecV0V8ZxAY4YH2E1uz3t
         rw60vnTFLrEA2u65/pxb9WTyeeDi9/gPv5BGeEmMTixd+3wdVK0Cf+eBCKdsl7arG3jo
         PjIc88kaP6mhYydNVRz1VeafM5rMkU+gQOXIyNXi1bl564AxHJy7rhZPz04VXYk81fz6
         KqwWyHskrmnqQMPqsiet/VjUmQv3H5+YgcPNURNXY6+TAksWb3DEEr+0mkTY/c26Y2lh
         L0nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :dkim-signature;
        bh=IiuXeH7dTTItwF19R4yUyg5hKA81o7xWWmqrV1xz44s=;
        b=VbwGvFLfS8yVfgmDL7VKLAigotvt29zj2soZKB+JMb1IrSTFJdokTv50/arn9Qc46n
         76AIysyDb5c9TRCGPwlJAzKWOsL75vQtAGUEBXxtII/RY4hHyeFsfg8zKAOszy5WIQBK
         h321P6kIYP6zQbT5qlrUlztzTsu6r/jOEir4yi3xGVd/ypifRb737LhTizAboJa4ImQv
         nk8dCRyzXQeo8185mQk4CG0CN0+i3uRZZj8/OpXVWq+fbW9TmsIOiBPGN2ofswVpvlvu
         PwYMqoUopTbeRVdKtrQKjJw0o+k1KofG1HYb0qwUfPKaRJQEG03yaFJtHjQi1p5zyKgZ
         PV5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=carExSaD;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id cx5si240073pjb.1.2020.01.17.11.55.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 11:55:20 -0800 (PST)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id ay11so10277155plb.0
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 11:55:20 -0800 (PST)
X-Received: by 2002:a17:90a:8986:: with SMTP id v6mr7605726pjn.90.1579290920295;
        Fri, 17 Jan 2020 11:55:20 -0800 (PST)
Received: from [10.67.50.41] ([192.19.223.252])
        by smtp.googlemail.com with ESMTPSA id x4sm30096717pff.143.2020.01.17.11.55.15
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 11:55:18 -0800 (PST)
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Linus Walleij <linus.walleij@linaro.org>,
 Florian Fainelli <f.fainelli@gmail.com>
Cc: Marco Felsch <m.felsch@pengutronix.de>,
 Mark Rutland <mark.rutland@arm.com>,
 Alexandre Belloni <alexandre.belloni@bootlin.com>,
 Michal Hocko <mhocko@suse.com>, Julien Thierry <julien.thierry@arm.com>,
 Catalin Marinas <catalin.marinas@arm.com>,
 Christoffer Dall <christoffer.dall@arm.com>,
 David Howells <dhowells@redhat.com>,
 Masahiro Yamada <yamada.masahiro@socionext.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, kvmarm@lists.cs.columbia.edu,
 Jonathan Corbet <corbet@lwn.net>, Abbott Liu <liuwenliang@huawei.com>,
 Daniel Lezcano <daniel.lezcano@linaro.org>,
 Russell King <linux@armlinux.org.uk>, kasan-dev
 <kasan-dev@googlegroups.com>, Geert Uytterhoeven <geert@linux-m68k.org>,
 Dmitry Vyukov <dvyukov@google.com>,
 bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>,
 drjones@redhat.com, Vladimir Murzin <vladimir.murzin@arm.com>,
 Kees Cook <keescook@chromium.org>, Arnd Bergmann <arnd@arndb.de>,
 Marc Zyngier <marc.zyngier@arm.com>, Andre Przywara
 <andre.przywara@arm.com>, Philippe Ombredanne <pombredanne@nexb.com>,
 Jinbum Park <jinb.park7@gmail.com>, Thomas Gleixner <tglx@linutronix.de>,
 Sascha Hauer <kernel@pengutronix.de>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Nicolas Pitre <nico@fluxnic.net>, Greg KH <gregkh@linuxfoundation.org>,
 Ard Biesheuvel <ard.biesheuvel@linaro.org>,
 Linux Doc Mailing List <linux-doc@vger.kernel.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 Rob Landley <rob@landley.net>, philip@cog.systems,
 Andrew Morton <akpm@linux-foundation.org>,
 Thomas Garnier <thgarnie@google.com>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
 <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
 <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com>
 <20191115070842.2x7psp243nfo76co@pengutronix.de>
 <20191115114416.ba6lmwb7q4gmepzc@pengutronix.de>
 <60bda4a9-f4f8-3641-2612-17fab3173b29@gmail.com>
 <CACRpkdYJR3gQCb4WXwF4tGzk+tT7jMcV9=nDK0PFkeh+0G11bA@mail.gmail.com>
From: Florian Fainelli <f.fainelli@gmail.com>
Autocrypt: addr=f.fainelli@gmail.com; prefer-encrypt=mutual; keydata=
 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
 G10n8gCguORqNGMsVRxrlLs7/himep7MrCc=
Message-ID: <2639dfb0-9e48-cc0f-27e5-34308f790293@gmail.com>
Date: Fri, 17 Jan 2020 11:55:11 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <CACRpkdYJR3gQCb4WXwF4tGzk+tT7jMcV9=nDK0PFkeh+0G11bA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=carExSaD;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;       dmarc=pass
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

On 1/17/20 2:13 AM, Linus Walleij wrote:
> On Tue, Nov 19, 2019 at 1:14 AM Florian Fainelli <f.fainelli@gmail.com> wrote:
>> On 11/15/19 3:44 AM, Marco Felsch wrote:
>>>
>>> With your v7 it is working on my imx6 but unfortunately I can't run my
>>> gstreamer testcase. My CPU load goes to 100% after starting gstreamer
>>> and nothing happens.. But the test_kasan module works =) So I decided to
>>> check a imx6quadplus but this target did not boot.. I used another
>>> toolchain for the imx6quadplus gcc-9 instead of gcc-8. So it seems that
>>> something went wrong during compilation. Because you didn't changed
>>> something within the logic.
>>>
>>> I wonder why we must not define the CONFIG_KASAN_SHADOW_OFFSET for arm.
>>
>> That is was oversight. I have pushed updates to the branch here:
>>
>> https://github.com/ffainelli/linux/pull/new/kasan-v7
> 
> I just git Kasan back on my radar because it needs to be fixed some day.
> 
> I took this branch for a ride on some QEMU and some real hardware.
> Here I use the test module and just hacked it into the kernel instead of
> as a module, it then crashes predictably but performs all the KASan
> tests first and it works file, as in provokes the right warnings from
> KASan.
> 
> Tested systems:
> 
> QEMU ARM RealView PBA8
> QEMU ARM RealView PBX A9
> QEMU ARM Versatile AB
> Hardware Integrator CP
> Hardware Versatile AB with IB2
> 
> Can we start to submit these patches to Russell's patch tracker?
> Any more testing I should be doing?

Let me submit and rebase v7 get the auto builders some days to see if it
exposes a new build issue and then we toss it to RMK's patch tracker and
fix bugs from there?
-- 
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2639dfb0-9e48-cc0f-27e5-34308f790293%40gmail.com.
