Return-Path: <kasan-dev+bncBCMIZB7QWENRB6PDTKAAMGQE6WPE2KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EABA2FB53B
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:18:34 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id q21sf34264379ios.14
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 02:18:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611051513; cv=pass;
        d=google.com; s=arc-20160816;
        b=GmWBMg6qDx3D6D7jQg5D2/rxQ0JOQCUz/yjl2V422iZe3Oeo6RbVZjQdTHV7XH1+UL
         JqgoZ+H0dUwt+CTpW+MrMtvyDrfvrwn0JFkdE4OSf1JCgpE52nWOelysPiPStspiVBaI
         IeGVRTxiq9tLjyFM39J1QxIn5ebk5nBmKah+DQYiODemynH0dBfDmEfmCWE/hKef8Pa0
         BYcV6f8Aj6RZGlS081ppRdLYXyYjXBhoyixtr8SULIOEScMfGCkJGQ3nBj4Yr02RK3Li
         B9knZe0zK1gqmR5Tb47pYKLtugfGF4Dzd3wIQfzn7BUHJTSzTeUBJGwVcU7sMxAsJmgg
         xpjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fLE7S/U5j4XPbYREcpQu+LZx1slpoGPeClewzMIAsvI=;
        b=XTHEEJSWQiqxgQvMrME1AI2a0Br2Ishj5fKKI7xrbL5jqkOKv/zbHtRtl10WC0bBOO
         5n8aZvwoGW+h60yxm9J8ggz7WLvzBQh2LPAehywvWvw3K3p/zaIaGaGoYPBAVIxerKEi
         XgtfZwHwufTDQpZE/jXG7xdt7uSVhTHRBPX3/HVzYd2qOJQ8lc964et+AIcoaEtlbWe1
         W+lO8DyIMnMcVNp/VbDMLW50wFPc2zOdR3M95F35+EJhGvGztORVBhRku7Hwt/7utyN+
         yYnNpYziA58VaOiB721BG4kX7jrQZPRSSzdJdF4yShD5/GTzer/6CIk1uLuzqX1wvyED
         eVAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=twGh+SxS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fLE7S/U5j4XPbYREcpQu+LZx1slpoGPeClewzMIAsvI=;
        b=aDJ1IHHGtLL92GBmzTYSNcDjOBIRC1+42+WwY2oYugoTFMzpTjnKPzEMzveiGkWLUI
         fhAaGJdzqjm5KQZyWGFlQTv2ApakykgeM77sKD2XaaLIiBox4ERxUxcxU7JJGu8nB6V/
         RkF+0T7TBQj92jXOU691Quu7Y6BC9wvjvoz5zgV8AUFLQrpL3AkwQLCnLi6AUYGznJD/
         Twl8JZ8u9n287lds0Tkue0omKaaNT5zTMiGAfYvvMYxfj3JdSWqY9oxRfnLSgsK1dl2a
         GAU0DDvUcC6h4UwLjZ+XpGCzp/wjQ1/rbXmISzfipO72AVs4z5/a++Jd0Hu77kV8HG+U
         xuZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fLE7S/U5j4XPbYREcpQu+LZx1slpoGPeClewzMIAsvI=;
        b=a/wXxgZO/DJ2RXT0tgAzAucx60LK6EMZe+KkjoaIviNgexz3W/2AIYeK17KucJMgvy
         kKUYUJrc117f9GtnDiZwNej8mEYPqZgpLWaSXNFOG4LxaZclk7ZdY4br7MugXbavOynh
         Y6wjhnsdz8bMisnaa68wsZu1y4O1CVXhlvbFLV+ei+FbaPjr3R02lpnoIoUc/MkRxH4A
         SaGtfhNSjB7xy1kdesSza4dqg+Y3+9KAnLf4qcOoAgsoHstKj/w2LbHqwO5vGyMa4sU0
         X3ddrGr4Ta2YAZxgzUrNfH0lPGvkkMueIWiJIzaSDdH3178mQJRTdA5Y1Dgppaf5l/PM
         sWUg==
X-Gm-Message-State: AOAM531a9rW5NVPhTwovrZnBrt4qQiO1yLZeIM8X0KOVYm60ktAgHD45
	ILj/QoZ8n4crIcPAFufrXjk=
X-Google-Smtp-Source: ABdhPJx24LJGsjcpr/4k8Fvaq7eStqPh+JZbYqM9O28bAYrfmbcRwORrX+QAC6nXnySm2qkiDxxDoQ==
X-Received: by 2002:a05:6602:3154:: with SMTP id m20mr2427716ioy.188.1611051513336;
        Tue, 19 Jan 2021 02:18:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d204:: with SMTP id y4ls196685ily.6.gmail; Tue, 19 Jan
 2021 02:18:33 -0800 (PST)
X-Received: by 2002:a92:870b:: with SMTP id m11mr2690460ild.134.1611051513031;
        Tue, 19 Jan 2021 02:18:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611051513; cv=none;
        d=google.com; s=arc-20160816;
        b=KppwJQzFAG3RMV1TZJaxzPhMG8+S9eX89WADHjiUM6fhYNMWVvIwCnxgDUFJydmcqi
         eH9ru7PeVzjpalnQUyFaOtkQgV2BsQuFwuYDQBpKHZhGfHoUUb51bYE5Y2sqBfd8tvtu
         6YwIiMXmjhcKCzEhDxdJS1KXC7RKPgdXqCHS4t7/GLBGohiE2UOXvf0gghhQ25VB7gIK
         AizkoBvw8LSWlyVNnwEwv7ZI1sGCyDTCDrAZiy6hXFsrNk2u6WfFmXDQuVglpPexMp6g
         xLtRh47RC7d5n1LLtWVUwrggQitd93O4oE98b6t7Mo4iM3qhKrtbbuHnoRDoPlmuDHN+
         uKEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=F4fkrRjlhM8fq929fmzPx7EjJGH2EJlXnVy3x9/5ork=;
        b=FSQ7i4uGSYPKLOkyGWcdhnLsPm4gQz3TyotwWC/EYAPAHv379szmGOKoNZ3sywuF8k
         8j1OtXjzE0In74+Oe5EBq/oWhDeBbPv0lWCJmnSR7CdCNXDL3StmpkBF51s/4LGQ6HD/
         bULL0lVt41JNZIpnIHDXTfZgjOcKr11ph4/09LeSxAPj5Yi2K/kulgtybpinhuzf4jZp
         4m4muwK29AooZP0qS7hg9GSvAmAKwAF5hnIy4NSZAJGwDzivgoGeCQT1FUlDjW5Z0TfZ
         wJEHP6SLmqxvw1wlMTwa/kDIkqqi9fRL19Ns8ClF2dSUppSFYIYda/EsA9VGno1pSctL
         oMHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=twGh+SxS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id e26si1565359ios.2.2021.01.19.02.18.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 02:18:33 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id 186so21289379qkj.3
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 02:18:32 -0800 (PST)
X-Received: by 2002:a05:620a:983:: with SMTP id x3mr3606082qkx.231.1611051512160;
 Tue, 19 Jan 2021 02:18:32 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+bRe2tUzKaB_nvy6MreatTSFxogOM7ENpaje7ZbVj6T2g@mail.gmail.com>
 <CACRpkdbHwusWYgoQRd6kRwo+TfAFgzFcV30Lp_Emg+nuBj5ojw@mail.gmail.com>
In-Reply-To: <CACRpkdbHwusWYgoQRd6kRwo+TfAFgzFcV30Lp_Emg+nuBj5ojw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 11:18:21 +0100
Message-ID: <CACT4Y+Ykw64aRm9xRxqiyD4h-bDNgXG7EnQOp56r82EA6Rzgow@mail.gmail.com>
Subject: Re: Arm + KASAN + syzbot
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Russell King - ARM Linux <linux@armlinux.org.uk>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Hailong Liu <liu.hailong6@zte.com.cn>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>, 
	Krzysztof Kozlowski <krzk@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=twGh+SxS;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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
> > We are considering setting up an Arm 32-bit instance on syzbot for
> > continuous testing using qemu emulation and I have several questions
> > related to that.
>
> That's interesting. I don't know much about syzbot but it reminds me
> of syzcaller.

Hi Linus,

Yes, these are related. syzkaller is a fuzzer, while syzbot is a
continuous fuzzing and bug reporting system.
It's like clang and a CI that uses clang to do continuous builds.


> > 1. Is there interest in this on your end? What git tree/branch should
> > be used for testing (contains latest development and is regularly
> > updated with fixes)?
>
> The most important would be Russell's branch I think, that is where
> the core architecture changes end up. They also land in linux-next.
>
> I think for the core developers this is the interesting tree,
> the corporate users mostly use KASAN for fuzzing their
> out-of-tree codebase and that is not of our concern. There can
> be some specific platforms we want to test but they mostly
> require real hardware because the interesting bugs tend to be
> in drivers and driver subsystems that only gets exercised on
> real hardware (not Qemu).

See my previous reply to Krzysztof re freshness of the tree.
I don't maybe it's just due to the winter holidays and usually it's
updated more frequently?


> > 2. I see KASAN has just become supported for Arm, which is very
> > useful, but I can't boot a kernel with KASAN enabled. I am using
> > v5.11-rc4 and this config without KASAN boots fine:
> > https://gist.githubusercontent.com/dvyukov/12de2905f9479ba2ebdcc603c2fec79b/raw/c8fd3f5e8328259fe760ce9a57f3e6c6f5a95c8f/gistfile1.txt
> > using the following qemu command line:
> > qemu-system-arm \
> >   -machine vexpress-a15 -cpu max -smp 2 -m 2G \
> >   -device virtio-blk-device,drive=hd0 \
> >   -drive if=none,format=raw,id=hd0,file=image-arm -snapshot \
> >   -kernel arch/arm/boot/zImage \
> >   -dtb arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb \
> >   -nographic \
> >   -netdev user,host=10.0.2.10,hostfwd=tcp::10022-:22,id=net0 -device
> > virtio-net-device,netdev=net0 \
> >   -append "root=/dev/vda earlycon earlyprintk=serial console=ttyAMA0
> > oops=panic panic_on_warn=1 panic=86400 vmalloc=512M"
> >
> > However, when I enable KASAN and get this config:
> > https://gist.githubusercontent.com/dvyukov/a7e3edd35cc39a1b69b11530c7d2e7ac/raw/7cbda88085d3ccd11227224a1c9964ccb8484d4e/gistfile1.txt
> >
> > kernel does not boot, qemu only prints the following output and then silence:
> > pulseaudio: set_sink_input_volume() failed
> > pulseaudio: Reason: Invalid argument
> > pulseaudio: set_sink_input_mute() failed
> > pulseaudio: Reason: Invalid argument
> >
> > What am I doing wrong?
>
> I tried it with both KASAN_INLINE and KASAN_OUTLINE this
> morning on Torvald's tree and it works fine for me.
> I brought it up with this and it booted (takes ~30 seconds to come up
> on an i7).
>
> Here is my config:
> https://dflund.se/~triad/krad/vexpress_config.txt


See my previous reply to Krzysztof re syzbot configs. syzbot can't use
random configs.


> > 3. CONFIG_KCOV does not seem to fully work.
> > It seems to work except for when the kernel crashes, and that's the
> > most interesting scenario for us. When the kernel crashes for other
> > reasons, crash handlers re-crashe in KCOV making all crashes
> > unactionable and indistinguishable.
> > Here are some samples (search for __sanitizer_cov_trace):
> > https://gist.githubusercontent.com/dvyukov/c8a7ff1c00a5223c5143fd90073f5bc4/raw/c0f4ac7fd7faad7253843584fed8620ac6006338/gistfile1.txt
> > Perhaps some additional Makefiles in arch/arm need KCOV_INSTRUMENT :=
> > n to fix this.
> > And LKDTM can be used for testing:
> > https://www.kernel.org/doc/html/latest/fault-injection/provoke-crashes.html
>
> I have never use CONFIG_KCOV really, it's yet another universe
> that I haven't looked into.

I looked up who added KCOV/Arm support to CC... it's turned out to be me...

I think we need to disable KCOV instrumentation for arch/arm/mm/fault.c:
[<802b36ac>] (__sanitizer_cov_trace_const_cmp4) from [<801228c8>]
(do_DataAbort+0x60/0xe8 arch/arm/mm/fault.c:522)


But I am more concerned about the following stacks. These happen in
the generic kernel files. The most expected reason for crashes in KCOV
would be that current is not properly setup. So presumably these arm
thunks call into common kernel code without proper current being
setup. Other arches (x86_64, arm64) should do it properly, so maybe
it's fixable for arm as well?

[<802b3ffc>] (__sanitizer_cov_trace_pc) from [<802e12cc>]
(trace_hardirqs_off+0x14/0x120 kernel/trace/trace_preemptirq.c:76)
[<802e12b8>] (trace_hardirqs_off) from [<80100a74>]
(__dabt_svc+0x54/0xa0 arch/arm/kernel/entry-armv.S:194)

[<802b3460>] (write_comp_data) from [<802b3728>]
(__sanitizer_cov_trace_const_cmp8+0x40/0x48 kernel/kcov.c:291)
 r9:00000000 r8:8a2f00ac r7:00000000 r6:dead4ead r5:00000000 r4:00000000
[<802b36e8>] (__sanitizer_cov_trace_const_cmp8) from [<801f6cb8>]
(vprintk_func+0xf0/0x2ac kernel/printk/printk_safe.c:385)
 r7:83f885a4 r6:dead4ead r5:00000000 r4:844f2694
[<801f6bc8>] (vprintk_func) from [<8367b7b0>] (printk+0x40/0x68
kernel/printk/printk.c:2076)
 r9:8a2f0000 r8:8456390c r7:8a2f00f0 r6:00000367 r5:00000001 r4:83f885a4
[<8367b770>] (printk) from [<801228ec>] (do_DataAbort+0x84/0xe8
arch/arm/mm/fault.c:525)
 r3:dead4ead r2:00ad0000 r1:ffffffff r0:83f885a4
 r4:0000001b
[<80122868>] (do_DataAbort) from [<80100a7c>] (__dabt_svc+0x5c/0xa0
arch/arm/kernel/entry-armv.S:196)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYkw64aRm9xRxqiyD4h-bDNgXG7EnQOp56r82EA6Rzgow%40mail.gmail.com.
