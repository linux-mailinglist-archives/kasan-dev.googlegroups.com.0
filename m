Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBRPK67VAKGQEFIFLVFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F6609891D
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Aug 2019 03:52:06 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id k22sf2298641otn.12
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Aug 2019 18:52:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566438725; cv=pass;
        d=google.com; s=arc-20160816;
        b=CAABjKH5i6yr22Bd+oPNzlfJx+LIuYkpUPmCky6Fqx3PHSi+wB1mo5XyngKS9k4AIK
         P/BdZjFE1ywBng1Dp0G2XIP4DV/fBrRLN/TcOmBcdhXURRqPIvGY6OXJ9GuXGmI2JPHx
         aRuC16WJa1G54i4ekb/remmkPjFep4vIo3XBRCOTiJit4V91unyBWfvKcfHohN2J+XL8
         RipyJuUhry9MUtjVOEnzNf95FLEA0V5s58XtSevTS4EQFPFDSx1Yy2l2KmQ76RFYQwj3
         1EzYmrM+2eOETwmKQlbWU1RW2VNyKXVkYhwIY9qy194CAfWCRL41pWPca4s00JaMCKzD
         06lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=szx2g2B/CSMhwBa+A5e6Wewdp22a90HUzM5nTTPzrKs=;
        b=Dsp9zZHJTNRPTY6NkUYBvE9fT/7+su4aIe4+tonTdDoBBsBIUZwa09S+sCWE51o+fs
         ATofMeThLMBmiUQvff/m7i988n1rwTl54dIx3myoT945FlcckloHnjw24u9zOEs4q7Au
         7mZMSxHtG20opCvALmYzPD6b2X5baryIclJIwSI+n76hkXa7SZ7vWWwnfJSvCsDSOs2E
         Ld7FiSCkvAN2eELjhQ4KfoHF52BtfSjzCn8hktj1mcdHfdvGmO4WmvYKXKLQSd12rvJw
         bTp1h2lIXD5veAxO+1JSnDpfuXIZv8WhxT+IjNdKtbdXPCCzKcYU+onnHBAm9SSwrARx
         sIng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=liA8TgG1;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=szx2g2B/CSMhwBa+A5e6Wewdp22a90HUzM5nTTPzrKs=;
        b=MgHw7k0ncNB2iBsJCTf/l7M6S11wa1pVkXKyndUWTuq0Y9++pdlG7b6JF5vTLVsLjk
         79qK66pZZRKJOs7TWXityeRyGF2pYE4XCvd8pLu/fp3M4rEliZXWp2n480it2qGFlq/l
         p7cCqHdgNbTVhcSa96Urp9wEijT4/tPx9X+mo7EdLa51IU75lQ8FGMCqVsKF7qu9Eb7O
         x36/SQkEf6sn2E/WhVdcxw1+LdTcYFnwCGc8nJ+tKoxAzmSF7XND1ZY3Gajz2WDbPsd4
         yCuSrGpNAxQH9183Qs/PmMgHVzCTCrKXPKwQRKcuq2NW/c1/YbxAgbLP0lA4IdZBxKVJ
         02pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=szx2g2B/CSMhwBa+A5e6Wewdp22a90HUzM5nTTPzrKs=;
        b=KocvC9G99h6AGBWCq7zSUPqD5wI44ZCGwQMSf8ikDboMjTicp2d1UWtQlzXUtohfui
         kHwRZz5w5o5thLgl2HVqhzZ2sOyGCDiRZKHS1y4Coyw6RSKl+rnr9F7k7ROrrZIWjrmw
         JUg3PHVnMVMNOtvwhiLAIOdD+mfwEomRL2LjCKFFT9ElKnIKaAZXdbVrXW0ic8WoNy9j
         ftGPfmZEXQzmUbljSywNEUXpIu1uOI/OtlFDrUCuCEKEdtKW/Bhh3P9wyK1/g9Zlqa1j
         Fck4UtBpTVJ8QgZLOyGMF0MiS/ONBoD7Ll0K++Zg5chdD+G+zM3U+yVxPLpXfHncn2cF
         fFkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXgox6diwt+m+LpUmkyfTvqRl7T2GKA/lC6dpbAInrMKiGb5s+4
	eTIR+n4pKNvRuY22lKsWjEc=
X-Google-Smtp-Source: APXvYqzuUbNS0lBq7hUcSoLq8EMhdvfFX6clekX5faGB+JLcDTeq6E1/uPbWITAHeMSQE+7TUdIeCw==
X-Received: by 2002:aca:5e8b:: with SMTP id s133mr2155113oib.45.1566438725084;
        Wed, 21 Aug 2019 18:52:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:450c:: with SMTP id l12ls710522oil.14.gmail; Wed, 21 Aug
 2019 18:52:04 -0700 (PDT)
X-Received: by 2002:aca:3388:: with SMTP id z130mr2147530oiz.81.1566438724258;
        Wed, 21 Aug 2019 18:52:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566438724; cv=none;
        d=google.com; s=arc-20160816;
        b=h/wsEfHyLinn7LK9UTMiweJePJ//5Yu19g01VdTMUMJF6pcnb4v5iUv5/60K/Zzorh
         hGFIXBlG31np9mKamHW0WqnS5njrB4zjoKQLZGf7FZS4QsI5sL3P1toRLm3gMj+J+SpQ
         fHM1sbBMV79GI5ikq9PGBVXhgrCOPygMr57tqqSjhlQcfns5t5S2ekNC0CVnAMHIpw21
         C0z7oD8zysCprK6qQAhmjKEp4IXTyGSYDsxJffLpHgW1L/baMkprQMh+wx3Pe9Pv4GkR
         WfRPlpHgrAwrIeUbffeC+mJi8LMPOxbU+mxZE+VQQKOpcE2LAE8916yitncTWpLWY4D7
         83AQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=f5/b6EM5llXI7wbQ95XKS+eTiQfi8CiOgyUNELxbz44=;
        b=SxZ+OwB116r0dDPk3xVCDMcI7c8I5xh238nGLfNstvGWmUKjUGJczCkyhXq65she0V
         anwfxJ4sAs+is1+ZDs1UB7YwUdl8u15gg8n4XMqWxuWY2chULJI178AFW+h1HIiS/i0q
         I7bTP0SM7KIekr8e86o8Z1LLYOXR2acXYZa/nV9hgSv6SahEVCXXb/cbStjinjV8Pyvl
         3cfsIgJ9KhqJODqYM9L/qryLC16W6mwaMG6LUXSFDvekC7xUwBO/r3fI+NHFgtrhLIF2
         9aVbllz8XHEsBOSUrUczcsm9BSI2UEU26I2QpHJwUt0eKqpLA+STMlqCxKbFi4gtLsTT
         4eew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=liA8TgG1;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id y188si980952oig.3.2019.08.21.18.52.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Aug 2019 18:52:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id u190so3747192qkh.5
        for <kasan-dev@googlegroups.com>; Wed, 21 Aug 2019 18:52:04 -0700 (PDT)
X-Received: by 2002:a37:7b06:: with SMTP id w6mr26784846qkc.436.1566438723558;
        Wed, 21 Aug 2019 18:52:03 -0700 (PDT)
Received: from qians-mbp.fios-router.home (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id d37sm7289872qtb.80.2019.08.21.18.52.01
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Aug 2019 18:52:02 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 12.4 \(3445.104.11\))
Subject: Re: devm_memremap_pages() triggers a kasan_add_zero_shadow() warning
From: Qian Cai <cai@lca.pw>
In-Reply-To: <20190822013100.GC2588@MiWiFi-R3L-srv>
Date: Wed, 21 Aug 2019 21:52:01 -0400
Cc: Dan Williams <dan.j.williams@intel.com>,
 Linux MM <linux-mm@kvack.org>,
 linux-nvdimm <linux-nvdimm@lists.01.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 kasan-dev@googlegroups.com,
 Dave Jiang <dave.jiang@intel.com>,
 Thomas Gleixner <tglx@linutronix.de>
Content-Transfer-Encoding: quoted-printable
Message-Id: <90D5A1E0-24EC-4646-9275-373E43A17A66@lca.pw>
References: <1565991345.8572.28.camel@lca.pw>
 <CAPcyv4i9VFLSrU75U0gQH6K2sz8AZttqvYidPdDcS7sU2SFaCA@mail.gmail.com>
 <0FB85A78-C2EE-4135-9E0F-D5623CE6EA47@lca.pw>
 <CAPcyv4h9Y7wSdF+jnNzLDRobnjzLfkGLpJsML2XYLUZZZUPsQA@mail.gmail.com>
 <E7A04694-504D-4FB3-9864-03C2CBA3898E@lca.pw>
 <CAPcyv4gofF-Xf0KTLH4EUkxuXdRO3ha-w+GoxgmiW7gOdS2nXQ@mail.gmail.com>
 <0AC959D7-5BCB-4A81-BBDC-990E9826EB45@lca.pw>
 <1566421927.5576.3.camel@lca.pw> <20190822013100.GC2588@MiWiFi-R3L-srv>
To: Baoquan He <bhe@redhat.com>
X-Mailer: Apple Mail (2.3445.104.11)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=liA8TgG1;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Aug 21, 2019, at 9:31 PM, Baoquan He <bhe@redhat.com> wrote:
>=20
> On 08/21/19 at 05:12pm, Qian Cai wrote:
>>>> Does disabling CONFIG_RANDOMIZE_BASE help? Maybe that workaround has
>>>> regressed. Effectively we need to find what is causing the kernel to
>>>> sometimes be placed in the middle of a custom reserved memmap=3D range=
.
>>>=20
>>> Yes, disabling KASLR works good so far. Assuming the workaround, i.e.,
>>> f28442497b5c
>>> (=E2=80=9Cx86/boot: Fix KASLR and memmap=3D collision=E2=80=9D) is corr=
ect.
>>>=20
>>> The only other commit that might regress it from my research so far is,
>>>=20
>>> d52e7d5a952c ("x86/KASLR: Parse all 'memmap=3D' boot option entries=E2=
=80=9D)
>>>=20
>>=20
>> It turns out that the origin commit f28442497b5c (=E2=80=9Cx86/boot: Fix=
 KASLR and
>> memmap=3D collision=E2=80=9D) has a bug that is unable to handle "memmap=
=3D" in
>> CONFIG_CMDLINE instead of a parameter in bootloader because when it (as =
well as
>> the commit d52e7d5a952c) calls get_cmd_line_ptr() in order to run
>> mem_avoid_memmap(), "boot_params" has no knowledge of CONFIG_CMDLINE. On=
ly later
>> in setup_arch(), the kernel will deal with parameters over there.
>=20
> Yes, we didn't consider CONFIG_CMDLINE during boot compressing stage. It
> should be a generic issue since other parameters from CONFIG_CMDLINE coul=
d
> be ignored too, not only KASLR handling. Would you like to cast a patch
> to fix it? Or I can fix it later, maybe next week.

I think you have more experience than me in this area, so if you have time =
to fix it, that
would be nice.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/90D5A1E0-24EC-4646-9275-373E43A17A66%40lca.pw.
