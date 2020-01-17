Return-Path: <kasan-dev+bncBDE6RCFOWIARBH6DRDYQKGQEPWSCTDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id ECE6A141290
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 22:05:35 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id d21sf17290003edy.3
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 13:05:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579295135; cv=pass;
        d=google.com; s=arc-20160816;
        b=M/yNmkqlj+PO39FZwy8dIWdTLUB9EG7uohzUsJwoxRM89nW/sKaeVRELa0QMIPGJE0
         C0xEWv4P8uGM2xEH11Ak8B7C0pdDd0VNO8PGYsFQ4rK73SV7/wIDF5uaUgq86VD+0tIZ
         eBveseMpHu4ipf9OtYjYAKTgzuh83OEUuEGnu9DKCntluzPKRTS7f4zWKKEE760aoGir
         e/8VZkFaoQUOUyQe7cPWhdBWOVYgO5kceR6i43eH+HQ6EgFiUzHS87p80T7k79FeaJqc
         EFxwOandeo4xM0RcvfcGjTeIa0VvxmNpsUojc42VriqzYJK1U28VTfAr9ExIcCTRG1Q2
         fNsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=rkyu/5fp0X9rh2WGrMFd0atfCMw7TdOTC2xj1ywz2UE=;
        b=nXa36v6CtDMcHo6L6Q4OHRhz4Wius23Yjs/pLLISluozyFbl4yrEHa1pd1WGlU4WAv
         o+jj/Zb+Wr9i6zKP/yXsc7UT/WukrGwhvlPcBi/K8VDfnmf0uiklPGAa4we/XK7boAls
         Lno+ZCWZpEBs39S5w3xlPv6eHWQsfZerQXVhI1Dw3AkNrgZwoRYJHAFAnz8+UE9wL1Ao
         J7P0DPe8a2ONlkklD6EBpKUYXPibLMsGyyeGi2K2xnOeddJKUHLMib2jFQHuZwEEyXZc
         +kRkA8jv3mESpt/XoJ1gdfwZLXFVvV8IEztlTZH/83mgD3APpUNdHnTzKe3kWYxXDPd8
         rdgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=cHQbz9Me;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rkyu/5fp0X9rh2WGrMFd0atfCMw7TdOTC2xj1ywz2UE=;
        b=ki4VNvAVkhOZgO5nrXnv1Zyt7GufIpVrTxr0pHU6LxdIhyqN3kDwk7TK15XmRKY5f/
         MxUGPzRGs7+vq0ZUmdkoM+4pEUVaBfJ489Nd1ZgzIhJv4iAE/XRoY90aWiPiWZ1CEDwn
         UakfI1PCkR/YX+oVKotvfQB8kp1ijMNuyobH4klXo6VR9Qsk+CYQT2IF6EnoczjwVTdU
         Tm4Vjime/C0DlSFTvfvhDxUH5sSwdbSp6p5FEFNkf/O1zx6renX0RFwIW5Fn9mx7kNHb
         MBxwoFgmINlpO4HS/XBG1HOS14ZYIFXwaONOlm2XWj8NHnwsATBoaxpJXBd+G32YQib7
         zbjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rkyu/5fp0X9rh2WGrMFd0atfCMw7TdOTC2xj1ywz2UE=;
        b=UVBWxuZigg3TxnBZYe77mUrSw0I9zwro4s7IDC+IAL3NkttbTlAbEFRBU71l4Dd1Ep
         4Hq5uSO6cSHjCxc4OyCvcnNNpBafbJg6F23a0Zdg9rCrdyTR3f3shE457UnHc1udApVg
         ClUTpUu3+u5AeLPgkdvqaeS/jNI6sY7tXBqP9QkCehlbdfE/XOW9P0vOvC8pHabdQj6W
         BTH3GyT+TNmITNU7yz4XrVLz5g4jGCwKWmFFlkYVXMDsPNh9yxxwrZm8huS5/DYoeA5E
         HAFXNW2pC6xbvHYyerOWyyQ6xY73HtjVMb9CeaYq/ZpzzwsJYZFaGbaMN1Fm45cY0KKQ
         xgOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVKHLHGngyfhkF4mBQzCe3jRetrkOw5mcZExQN8exTKBUJpmTHw
	sn2HIZYa0J4q8JLjkqztios=
X-Google-Smtp-Source: APXvYqz6RWPM84Y0fUwal8cmen75x62ncAJjzcH89tFVr2tLo+hggiGJVH7rDIjtnSJUsS1bm0eTtw==
X-Received: by 2002:a17:906:b30f:: with SMTP id n15mr9696768ejz.236.1579295135640;
        Fri, 17 Jan 2020 13:05:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:355a:: with SMTP id s26ls7370578eja.15.gmail; Fri,
 17 Jan 2020 13:05:35 -0800 (PST)
X-Received: by 2002:a17:906:1ec8:: with SMTP id m8mr9946600ejj.355.1579295135133;
        Fri, 17 Jan 2020 13:05:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579295135; cv=none;
        d=google.com; s=arc-20160816;
        b=WWAPzPsUFrruUwKWjX542b0Q2RvZod7ZNgIX5cDYrQz+bzgq0ANxE0tPUf4dedoANO
         hDscR0eBHZcPHRPbBpL/sIZnoh/MMSfOhnTlRtHWHmBpgUsJ9f8o8e2TKmGAkgTU/VBY
         nCGUW58296rd1YPPSxxBiWCteurH8BxInF68CWey+yVXsoBplR5kiQA48Dl+L7laSrm+
         NE9Xx7lAe2cgXSVCiwY7rRCl8lBa0+EJAokJBUdLqhdmPilxfQ8TS7EzIcdnvNoMQkqN
         FU/O3IGHgy0+XEx0nSY1HVQy7F5Qg8sCIJm8q/b8ICysf2gNd1NPRNyQAbxV7HdaAHDV
         Hmew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZBkS9S8oFTr7ty1NIiAX5JrGRHx/96iPY51B8fxdR2Y=;
        b=x9IT4OGXTRYWHanTD0Sh+Q0inaxzmX0VpRT89q5e9PCV16CCA5wUL+Gnyd2YUrGK4M
         mt1W9pesIqbPmqb1Duqt8CTEU5DyEcKk6LUUtg0eUPdql1ofsr/vTWsnt8HvqV9Xql6M
         O8RlQ2z4OUjMiEOmNKE5OSc82SlYoSqhX9EYJAjmmScxuPxeNIC/ORFxTjnDiZUMeQim
         bNRVeoaiwO/Q6JRLybHDGAsdH+5MWkViN/wtw6enTALP1T9paLIppGIT3hljBKvdWG3G
         QTdRdLiI8X0Dg8nR1icYM74DMhb1JSLE0OscIE045nQ3Aut/z/RQPL+xGx+P9FFy3eV8
         0MTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=cHQbz9Me;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x242.google.com (mail-lj1-x242.google.com. [2a00:1450:4864:20::242])
        by gmr-mx.google.com with ESMTPS id ba12si1081351edb.3.2020.01.17.13.05.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 13:05:35 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::242 as permitted sender) client-ip=2a00:1450:4864:20::242;
Received: by mail-lj1-x242.google.com with SMTP id y4so27837045ljj.9
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 13:05:35 -0800 (PST)
X-Received: by 2002:a2e:9143:: with SMTP id q3mr6695400ljg.199.1579295134552;
 Fri, 17 Jan 2020 13:05:34 -0800 (PST)
MIME-Version: 1.0
References: <20190617221134.9930-1-f.fainelli@gmail.com> <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
 <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com> <20191115070842.2x7psp243nfo76co@pengutronix.de>
 <20191115114416.ba6lmwb7q4gmepzc@pengutronix.de> <60bda4a9-f4f8-3641-2612-17fab3173b29@gmail.com>
 <CACRpkdYJR3gQCb4WXwF4tGzk+tT7jMcV9=nDK0PFkeh+0G11bA@mail.gmail.com> <2639dfb0-9e48-cc0f-27e5-34308f790293@gmail.com>
In-Reply-To: <2639dfb0-9e48-cc0f-27e5-34308f790293@gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 17 Jan 2020 22:05:23 +0100
Message-ID: <CACRpkdYs-jeYO+8avOryJnXdWsB9AkPy7Q5FRQ1gGC1NU35MHA@mail.gmail.com>
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: Marco Felsch <m.felsch@pengutronix.de>, Mark Rutland <mark.rutland@arm.com>, 
	Alexandre Belloni <alexandre.belloni@bootlin.com>, Michal Hocko <mhocko@suse.com>, 
	Julien Thierry <julien.thierry@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Christoffer Dall <christoffer.dall@arm.com>, David Howells <dhowells@redhat.com>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, kvmarm@lists.cs.columbia.edu, 
	Jonathan Corbet <corbet@lwn.net>, Abbott Liu <liuwenliang@huawei.com>, 
	Daniel Lezcano <daniel.lezcano@linaro.org>, Russell King <linux@armlinux.org.uk>, 
	kasan-dev <kasan-dev@googlegroups.com>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Dmitry Vyukov <dvyukov@google.com>, 
	bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>, drjones@redhat.com, 
	Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook <keescook@chromium.org>, 
	Arnd Bergmann <arnd@arndb.de>, Marc Zyngier <marc.zyngier@arm.com>, 
	Andre Przywara <andre.przywara@arm.com>, Philippe Ombredanne <pombredanne@nexb.com>, 
	Jinbum Park <jinb.park7@gmail.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Sascha Hauer <kernel@pengutronix.de>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Nicolas Pitre <nico@fluxnic.net>, Greg KH <gregkh@linuxfoundation.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Rob Landley <rob@landley.net>, philip@cog.systems, 
	Andrew Morton <akpm@linux-foundation.org>, Thomas Garnier <thgarnie@google.com>, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=cHQbz9Me;       spf=pass
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

On Fri, Jan 17, 2020 at 8:55 PM Florian Fainelli <f.fainelli@gmail.com> wrote:

> [Me]
> > Can we start to submit these patches to Russell's patch tracker?
> > Any more testing I should be doing?
>
> Let me submit and rebase v7 get the auto builders some days to see if it
> exposes a new build issue and then we toss it to RMK's patch tracker and
> fix bugs from there?

OK you can add my Tested-by: Linus Walleij <linus.walleij@linaro.org>
to the patches.

Thanks,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYs-jeYO%2B8avOryJnXdWsB9AkPy7Q5FRQ1gGC1NU35MHA%40mail.gmail.com.
