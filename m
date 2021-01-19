Return-Path: <kasan-dev+bncBDE6RCFOWIARBWFXTKAAMGQEXWVL5AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 919A72FB46F
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 09:44:09 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id q13sf7806481lfd.16
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 00:44:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611045849; cv=pass;
        d=google.com; s=arc-20160816;
        b=PNUJ2nxfL1HSfayh1/9e8Qys1dLHP2vHOm+q4i6XHBIkKbNncLUGuIOucDuVzx87ON
         F9MUpMFsvXbrMepDwQqOzrn43BA61sTKBXSgDa6sqKf7BOkwFCEFQxyHK4dDAc1ZoWEz
         hdPZmOlYmwGZdLRoDSFpHpIi3nBUO8lIBRx8k39kn/VA4P1xmVIL8V2DxVO9Fq2OS4AJ
         FE/mZhKw4O7iYXZIW7OTPL2P2QZBc6jQBKMBn6wPOVPzUwUZPljAATjmp3DaWqAnwzXA
         +pwQeZwuu2Gl2ay75+ihwUaOAJVJV2Q1Ft92E617IUoolrWkVMKGAHyD3peNW2oTlI+y
         q3Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=jhHieF+S5fMaWztZ5z4D/cnIex2utB0xL2FvJ0hsGbw=;
        b=p4tEXwxaLPy+ChAywqw7sTuefIngT/fClSclrezcQ4JNRcSyR3ju+jjCnha6+227SG
         g8jn7zeqgjyWrXQYwKgCeM8vZpum2JKhvNSWuamarWSgikwSSEUpVBmKBU0FcywyrRik
         Ix93jzqX5eNrp1qf6w9iTVG8oiib3/5WLkCT4VnkZZKgIUm14B179jrKpNtDx0daU7b6
         Gd63T+LZhl3P4Wgez6rsArhDXkGy3n5Bgx5iikMx9tQ9dF8uxEb5uBNHVr8X6gtriFyl
         l0ffH7lFU78Cm72r4JLmwQTLS77XdLKWsjgmZWnP85MLlndbSU3JSudop+1zBc+4UgAx
         S2dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Dk7F7lue;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jhHieF+S5fMaWztZ5z4D/cnIex2utB0xL2FvJ0hsGbw=;
        b=dls7E335z6+8REwts4FKzWamCJTCo9ud2HrbX2Q3KrufnHwQTZIPtTAkwxWybV5+tC
         d8R25K/IquXoATwUSPvcWtMD2zcE1qjybNwkGkWZhDG+qy942FtqoTIjtbN3jiMpQMtU
         SRRCb+XaLgdMkArSXA66SglNrwDrS56+ecujfvv63A2ZGtMFCBcc6Goov4os//G39tml
         tUpubyWGcI+Ht66jzyxogmOFgcZnu9BA4BmVj4FiBYaReq4vRk4AeiM52i6BwaWDfWJD
         gQGN19qlR9xJnALu+Y01aDAjYDApIOPn6nMHhouRIe5MaCfi54+/007lW7NUbg6Vx20I
         bU1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jhHieF+S5fMaWztZ5z4D/cnIex2utB0xL2FvJ0hsGbw=;
        b=AcPGwfYUQhIA9sCVWdsE9iq9yVCvA4DvuZ6jpTQo9IJFSQCAPhjf9Unlmql9lzK0lP
         hHjVA97ge/wZf/Bz0MvbXSmUJmEhgq2YegTMHMRmioQ/L1HZgc5tsaZAaaarACT3xQrx
         tWDxYUmoqeNoLmBmmiAoyiUM1OK7zofx8ipQmXH1Uqfw1pio5qyOP0S70GFF3srMrNat
         Hemi7LWsDUkhDoF5YmBG0jwivRqW+PGHzY9f0u3VXW14V049kgaVi+FfuUn5aSzPTWfd
         oTKjoQynKvb33ask93HmvnUbCnEeglAm2bqvNe/9YjMRrGtsAiiJ1oW7gao4LEuuYwoT
         uG+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jXjh3VLyBNJloF8rhJGPfWjRD/QkYLAnqy6dIMIffTDR9Xmnb
	It3QKTOiqOrym7GDPca+6+Y=
X-Google-Smtp-Source: ABdhPJzKslh6KDOIzjtS04Pn3mdTp12UyQYnEgCKLh0IucsEM0EX8kXmdTDNfRWa/0hMVWXFLaHH9g==
X-Received: by 2002:ac2:58f7:: with SMTP id v23mr1509008lfo.26.1611045849117;
        Tue, 19 Jan 2021 00:44:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b549:: with SMTP id a9ls3157863ljn.1.gmail; Tue, 19 Jan
 2021 00:44:08 -0800 (PST)
X-Received: by 2002:a2e:9bd5:: with SMTP id w21mr1446490ljj.432.1611045848057;
        Tue, 19 Jan 2021 00:44:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611045848; cv=none;
        d=google.com; s=arc-20160816;
        b=tB4pdIqbNKX9FJ+li9sJJiih5C6Pc/UME34THdoG7sg5EFb/z5dyUVu1xTg1PvgHSN
         /fg77PsMEdpf3Po/0xQmeK5oOcwc5DWQWWX1GAB0G+e+SX769EfZUSzAAg4x6L1g6NMp
         l+4ZvoRln1wbtGCNe8Qv/JIGrGdUxiM04+AFSM8TFShzsqNOKSYIrpu4iWskBLqLOs5Q
         k4v0vY/nxk0z0d1ULbnJsN5fyPVgZ3ojd+PebPdKTy77u92ks1A8g1dt3q2zLAxls2o4
         9Zfox4G/8yTV+CvuhJyY5Jpo5JUwTBc5PfK7LYIw7UvTuAIMTrS8wiV3AXVykd7xqwu3
         ts+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yLqz0ZvSf3hPitGDh6pMKCcOrXZ5QDYwzUPOx5RMx40=;
        b=Q6A0TkCxJw+yTl11EiVmAnrSQbh4LwOeTZCUQlFy+mdRsVV7w9SJSQBgBUTVVLMzR7
         WLXVZ2KYnl5GWC3/80ng95VKyu9K4GkjmDKm7C17GtjDKOVkQtResT2yRAVv7vCu7pNT
         eh14qQAcwoO4Ci+IlGSJfKniTzCKqpFZyMAyuIkFYFD1G0JHbfIW3liA6DcePIXIbWGT
         ckzKCWmlW7Z7SA8Wm1AQu4u+RqIwjh6VCwI99A7OsOdv/5Z1tXdpSJ9CzFXM+a7I5AFs
         6hzR6Uux5zncGClaBHelq2Fs5bZF2nkSpqkV7D1+57HKKXn7TRyU6ji/k9G/4JeoR7E9
         Izjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Dk7F7lue;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id i18si837806lfp.2.2021.01.19.00.44.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 00:44:08 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id o17so27958159lfg.4
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 00:44:08 -0800 (PST)
X-Received: by 2002:a19:6557:: with SMTP id c23mr1322719lfj.157.1611045847840;
 Tue, 19 Jan 2021 00:44:07 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CACRpkdbHwusWYgoQRd6kRwo+TfAFgzFcV30Lp_Emg+nuBj5ojw@mail.gmail.com>
In-Reply-To: <CACRpkdbHwusWYgoQRd6kRwo+TfAFgzFcV30Lp_Emg+nuBj5ojw@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 19 Jan 2021 09:43:56 +0100
Message-ID: <CACRpkdYXyP4oB3zT=NZ2Hj0v0=Ch=V3jU-Pq7PFaxOfJ4vGZpw@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Russell King - ARM Linux <linux@armlinux.org.uk>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>, 
	Krzysztof Kozlowski <krzk@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=Dk7F7lue;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Tue, Jan 19, 2021 at 9:41 AM Linus Walleij <linus.walleij@linaro.org> wrote:
> On Mon, Jan 18, 2021 at 5:31 PM Dmitry Vyukov <dvyukov@google.com> wrote:

> I tried it with both KASAN_INLINE and KASAN_OUTLINE this
> morning on Torvald's tree and it works fine for me.
> I brought it up with this and it booted (takes ~30 seconds to come up
> on an i7).
>
> Here is my config:
> https://dflund.se/~triad/krad/vexpress_config.txt

BTW here is how I invoke QEMU on this:
qemu-system-arm -M vexpress-a15 -no-reboot -smp cpus=2 -kernel
${HOME}/zImage -dtb ${HOME}/vexpress-v2p-ca15-tc1.dtb -append
"console=ttyAMA0" -serial stdio

Using the DTB from the same kernel build.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYXyP4oB3zT%3DNZ2Hj0v0%3DCh%3DV3jU-Pq7PFaxOfJ4vGZpw%40mail.gmail.com.
