Return-Path: <kasan-dev+bncBDE6RCFOWIARBV5WTKAAMGQEO6GKPFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 983052FB460
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 09:42:01 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id w4sf5303179edu.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 00:42:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611045721; cv=pass;
        d=google.com; s=arc-20160816;
        b=V0Q4fWntGAaOR5EFV8qQFOv8svEsJgvi1Fl3x38GLygpkVR4yr0RwOeYCWcxge2+z5
         Kvg02T2N7KOPtXmi8LeJL79UPCRhkcmD2xBmcIRgzGelesomoZEm8m7s/547qSXS1Eft
         L/1S81kxQH+o2ilPIcGG60fajuOTFm2rBrUcRpUse5L8SYYTrzo2sPpppuqpB5bs0TTN
         rIpGv5gX3wh5q0DKyYOCCBPbakIqAQC6zBBWClKzBdsOfZaU6DukXZHrZYtGEl993KKd
         wk04vybEOpUBO12mb4Plyu0xtz/K41LEoD63CyZ0MEtFnfFZo0WIZukXPpcH1O0PopKQ
         kebQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=OkGo3HCuBckgVA7PtfoT14t0d7sq5Er27LPhutCXC9A=;
        b=AdJTV3SA2hLZNVGr4HLfZTk7a7+s0E0A7aVD/GwigJV05CUCrrz6WrZ77BTLgnwdsN
         BcLB3Bf6WusNQF9XUHJi4sBFxqjShYeb7tXLERdeO81XgJgq5vCpovqXz8pgx2X+DjT9
         29vzdVZFKAJcLQ0e8vGTpm3HO6L4P6YppUHqqHQxHJHMNJRYzAbA14SJreTShu+9dSVF
         F3HAza7NbHjKPDA71N+rQ++IEo2p43l7uV3S8ps7W8XVFcud0Sd+ZfL2SsEQ4YcGuTRI
         Psk5jvEHQeQ65hBC4gze4jj765TKxX4AGyaMHKQlQ6WXDMBR9HTYH6gZzjW/Ud99soHU
         bduw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ITSlhwJR;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OkGo3HCuBckgVA7PtfoT14t0d7sq5Er27LPhutCXC9A=;
        b=h0nVI++olKZeDxxaZfKWMYTPsaE2GJch8lGTcG/rl/MoFTgrt9xAtwuDS/L6LaMkqO
         NM+kijUSa0uolrUbnNO/PL24m5z83u46hMAs4wxEb18cmYMOLO3NvOKxcUpokRjipsaz
         GZhzbYTI1wLHWRANRqLbNH00ZhqU/EU4dyItIrsrfuBHzsOuek+cWrbp6CsHqBsmZmvI
         fsgI+3mu4ztElZJiE1CgWOLobL6w0qTzR9B3Ijh3gt/x/GdeGL+kK9FIH92GdW3qJHad
         3S8O/Tgr40c7KnMhLKmReLFB769jJACuR4H7fKCKFKml3fd/33C9bF/e9AEhPbtn5Hy4
         Xpig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OkGo3HCuBckgVA7PtfoT14t0d7sq5Er27LPhutCXC9A=;
        b=aGycHM4Ie2ehP3wCk4005Adbv2uK2yMV4SBFgYLz177f2a4wC7tr/TQGPXPsJrvxk/
         n40cAN2Kt3PblAtoZuDx1xjvTbxczlDppcS3jLh4B3Tj0MegVZ0yg/g0VJNF+24PXBHa
         yaNXAp0zftIVkEZZxmFLLl2RzrrK4qqI084YIf4ZYXEN4PPT7spzPNikmvKI+Nehqg1g
         MIfMvslJQ0L6/1AOrTehKD47avob89PrTiqYSIFQX1GolHyHKZrKgM45pNIz0/2cboNu
         W1wzjIp5ZA6UABsrOqwrFnb5B7Rj2gTLJ/vCDK/tbwf2l0EDCfpi9Ti9plP+2ZLj1mh9
         fPFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533NMIeCpZPT5tu6nRVugT/2AdGhUhP8O5Y2crnGfy/vEqwiRutr
	jd2fcVJntYtXNQ+NB7cS8Vw=
X-Google-Smtp-Source: ABdhPJwbtJl48jMxu2x4838lJcRJXGH7qDU02djOuoWeq1+fI2s+qRN9tCijT9ZWQfYtq2kiGidbyA==
X-Received: by 2002:a17:906:2454:: with SMTP id a20mr2260536ejb.203.1611045719384;
        Tue, 19 Jan 2021 00:41:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:520e:: with SMTP id s14ls1995583edd.3.gmail; Tue,
 19 Jan 2021 00:41:58 -0800 (PST)
X-Received: by 2002:a05:6402:8d9:: with SMTP id d25mr2511687edz.278.1611045718532;
        Tue, 19 Jan 2021 00:41:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611045718; cv=none;
        d=google.com; s=arc-20160816;
        b=uCd9tux7CyRB7vOZY+/bMtLr1mr/nVgp4aAhI7IdWhbDq+z0J8z6DtZ1yLFLBXgH+m
         aadP4c+xo9Mz921rYm3LfJmdK8VTPdL2cM9ZYGNCC1S0/F3/oFbXkI2sJE+hP/wuYiAV
         uJpRF7YhRC0H6xSwLLRzP5v/Dea2tgc+N7m8rJVlA7e0n4WvFgsfATfzAK0FyPe8Jg3w
         bH1LzJfAAz5TXS22pSklnTy4+bGd81R89JYUhV5PUQ2o5pruBa/F8B6GbVNjD/qp75Hm
         EVnsuTaLdcxTGLRWLRk1rXf0iZE6tNdYh5Wsqo6T7/yX470UG0vGqPqUOYc3FcXDGxED
         el2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qVO3IBVdVAWg/xRH3KY/h9r4YK5LiBTS4U33uQ1vOYI=;
        b=Vgp2ap1DIJYxbx77xIwNq2JuSZAygoPu/t4XHQ6shRbNQ6DmrLi7JiuM8+gL7cxskp
         Rf5/vFs5vEoa5VYSh8PoWE2RyB6Y7DSjRTvQbAId+DBE7LVyyQCCZjKyFRHLqsFSNOtZ
         QrMkOaYQvQPd+pXJOm6kH0Jyu/LYqMVI9YE+SN4KNF2OuUhQpfKfdi2RUpxGnYjnu3m4
         XDcTIVNUqgEqPcAXftZRPEZ1uqc+S0wzcrczM5fwNcyLsCSEdd96I7hgLAVWlzOrRdSp
         qR8NqkWwE2Dhbn/oRkweilTGjIrvWywgrXbmvCoLQNOGgLNOZQs/fL4juqGmEZjJEWHc
         cvAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ITSlhwJR;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id m5si350914edr.1.2021.01.19.00.41.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 00:41:58 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id u11so20936828ljo.13
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 00:41:58 -0800 (PST)
X-Received: by 2002:a2e:85d1:: with SMTP id h17mr1459752ljj.438.1611045717993;
 Tue, 19 Jan 2021 00:41:57 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
In-Reply-To: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 19 Jan 2021 09:41:46 +0100
Message-ID: <CACRpkdbHwusWYgoQRd6kRwo+TfAFgzFcV30Lp_Emg+nuBj5ojw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Russell King - ARM Linux <linux@armlinux.org.uk>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>, 
	Krzysztof Kozlowski <krzk@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=ITSlhwJR;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Mon, Jan 18, 2021 at 5:31 PM Dmitry Vyukov <dvyukov@google.com> wrote:

> We are considering setting up an Arm 32-bit instance on syzbot for
> continuous testing using qemu emulation and I have several questions
> related to that.

That's interesting. I don't know much about syzbot but it reminds me
of syzcaller.

> 1. Is there interest in this on your end? What git tree/branch should
> be used for testing (contains latest development and is regularly
> updated with fixes)?

The most important would be Russell's branch I think, that is where
the core architecture changes end up. They also land in linux-next.

I think for the core developers this is the interesting tree,
the corporate users mostly use KASAN for fuzzing their
out-of-tree codebase and that is not of our concern. There can
be some specific platforms we want to test but they mostly
require real hardware because the interesting bugs tend to be
in drivers and driver subsystems that only gets exercised on
real hardware (not Qemu).

> 2. I see KASAN has just become supported for Arm, which is very
> useful, but I can't boot a kernel with KASAN enabled. I am using
> v5.11-rc4 and this config without KASAN boots fine:
> https://gist.githubusercontent.com/dvyukov/12de2905f9479ba2ebdcc603c2fec79b/raw/c8fd3f5e8328259fe760ce9a57f3e6c6f5a95c8f/gistfile1.txt
> using the following qemu command line:
> qemu-system-arm \
>   -machine vexpress-a15 -cpu max -smp 2 -m 2G \
>   -device virtio-blk-device,drive=hd0 \
>   -drive if=none,format=raw,id=hd0,file=image-arm -snapshot \
>   -kernel arch/arm/boot/zImage \
>   -dtb arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb \
>   -nographic \
>   -netdev user,host=10.0.2.10,hostfwd=tcp::10022-:22,id=net0 -device
> virtio-net-device,netdev=net0 \
>   -append "root=/dev/vda earlycon earlyprintk=serial console=ttyAMA0
> oops=panic panic_on_warn=1 panic=86400 vmalloc=512M"
>
> However, when I enable KASAN and get this config:
> https://gist.githubusercontent.com/dvyukov/a7e3edd35cc39a1b69b11530c7d2e7ac/raw/7cbda88085d3ccd11227224a1c9964ccb8484d4e/gistfile1.txt
>
> kernel does not boot, qemu only prints the following output and then silence:
> pulseaudio: set_sink_input_volume() failed
> pulseaudio: Reason: Invalid argument
> pulseaudio: set_sink_input_mute() failed
> pulseaudio: Reason: Invalid argument
>
> What am I doing wrong?

I tried it with both KASAN_INLINE and KASAN_OUTLINE this
morning on Torvald's tree and it works fine for me.
I brought it up with this and it booted (takes ~30 seconds to come up
on an i7).

Here is my config:
https://dflund.se/~triad/krad/vexpress_config.txt

> 3. CONFIG_KCOV does not seem to fully work.
> It seems to work except for when the kernel crashes, and that's the
> most interesting scenario for us. When the kernel crashes for other
> reasons, crash handlers re-crashe in KCOV making all crashes
> unactionable and indistinguishable.
> Here are some samples (search for __sanitizer_cov_trace):
> https://gist.githubusercontent.com/dvyukov/c8a7ff1c00a5223c5143fd90073f5bc4/raw/c0f4ac7fd7faad7253843584fed8620ac6006338/gistfile1.txt
> Perhaps some additional Makefiles in arch/arm need KCOV_INSTRUMENT :=
> n to fix this.
> And LKDTM can be used for testing:
> https://www.kernel.org/doc/html/latest/fault-injection/provoke-crashes.html

I have never use CONFIG_KCOV really, it's yet another universe
that I haven't looked into.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdbHwusWYgoQRd6kRwo%2BTfAFgzFcV30Lp_Emg%2BnuBj5ojw%40mail.gmail.com.
