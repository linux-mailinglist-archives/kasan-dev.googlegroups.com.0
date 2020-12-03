Return-Path: <kasan-dev+bncBCT4XGV33UIBBT46UX7AKGQEGTZY2AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 160192CDFF3
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 21:49:20 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id 1sf978573vsj.21
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 12:49:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607028559; cv=pass;
        d=google.com; s=arc-20160816;
        b=hN+UUmNXy6NIlSZA7TCDI/OeQT6VoEUPQMqprokFPz8i7hgpbY/PDE+XfuBxZYWzts
         6XCXMPxDqnIvoZLaTGpeoSMOG5R9fQwYqXOvH2rHQjl9HBEGO+J9/U1t9ToFA5G0RgJH
         Cf2FSRDEjPraYG8rFE40P3cH7LWVqoWnvn4ntgSTa2xUmiZmrjCS7od9kIhgaV51Yfwn
         dw+hk8aoa6MorvIfZK5vH6CYOVSELAnhtL63e337jHHVEHdPvlGtuS96FLb8wXZb0OKf
         TdhoGYUfoUXO1luNHPBJ/+8Bc3/20a7FtMxXNCKB+Lz4v1Siw91s5plz0HwQwJyu2BFy
         JJXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=v2UoQY+syAJE0KhTxeW90Qcj2WdcFzwTO9IFH67X+dI=;
        b=f5qiKa/CbOLPW+G9CLnYC648RsToWDUgzxzeAYtZBmLvJs9FxrwBkuHScrPwbo44VY
         xrRvrVVQdyS/BtErPueEtmCCFn3+pvfZ1poZWaWa6cf7Hxf+Jp6tyY5wHHRAiXQ37yQF
         s5MH5dqP/m5ewH/dR9LqUX016Tcyak3Lod0v6+O8uC6JuXL5ViZGuxxfgAqID0UUZfeZ
         Vw3jeJn6V7diif583aacvQohQC3mmEQhUONqdsK200fmHTAESB90ro4VvxzDRnQyIWGS
         jXfBgxAclLeTU0p9zItUz6u9V4Ku32BcjNz12vbAsqkVVMG5UsZqSU8xb5d54mG7M4qk
         ro8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=gxZrBLg1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v2UoQY+syAJE0KhTxeW90Qcj2WdcFzwTO9IFH67X+dI=;
        b=aygvMe/mJetC5cQNEJzshW1/UVFV4EVP8o0F5MWE1/DmNHUaLjyelXFGW1fAyd6GTj
         Pl1t03/nVnVeFy/i/3peBlvFXlEBpiZ7HA56+3wA0e2SIY3GBPE0kkhPtaFLt3zYJu7F
         aLR61WTn/0IkamgkDLgQtS0Tyj9oDuEzeN4TbUDT1fEB3+miHiDh8LY+zEDtJKHfonPX
         wX8Cf8e1Ki4dHQMYy1RVIoV6CkChraRvDLgz+c024Da6T36MhEbEsj3VPc0tEQsLGHxE
         ceC/QsPhds1sjJoJwT53n4yDl7JzWMsG1yR1I8lJdHS6gOqqLCSTlwekMYNawFtEvPXG
         0Yjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v2UoQY+syAJE0KhTxeW90Qcj2WdcFzwTO9IFH67X+dI=;
        b=kV9M3iUpAuHA1Pk9umfg0pbtoDNuIxrZG1SOak3Qw5rdH/V8taw7srFJKPz2RkswQl
         fWa58s+KhnScGwrowD3tXcHuXpeD719+9ugLgGBkK46L50ZLqtA9j2MSJGE3rHo4q8sk
         +fgboDe2Bq0O8gH2NZ2tNrDW3D815AWAbVLa3CGEsI6mE6P20/84GQJonxPoH/kUw/rf
         WHMYGW95mAYIUeXf2bmx96DqDaUiAJjySBJ8zsa7T3Zlt6LrkwsgT6FrIiMQ5IXP6d1A
         JLz3e9nNT4E/OMB9dfRFdANiE9LRmj4xK8OS3au+UhyziWGO1jvAteFdJXgPbkkPiDmL
         17VQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PiF4xFQwOLLVnvStvb/J/+55MJvDpelsqKSgNGX7SQvaKRfe8
	Pk/JfdIRcThcpOE4oH5+3WE=
X-Google-Smtp-Source: ABdhPJwzpQh1Hcn3CvtTgPahiQcwgQNHN9RKLa0YJGUfCCu9CAl2G0IlOyz3T4CFuK25K5UV705hEQ==
X-Received: by 2002:a67:f646:: with SMTP id u6mr1189507vso.5.1607028559124;
        Thu, 03 Dec 2020 12:49:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ea12:: with SMTP id g18ls984103vso.9.gmail; Thu, 03 Dec
 2020 12:49:18 -0800 (PST)
X-Received: by 2002:a05:6102:501:: with SMTP id l1mr677438vsa.42.1607028558607;
        Thu, 03 Dec 2020 12:49:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607028558; cv=none;
        d=google.com; s=arc-20160816;
        b=F8zBF/tuBhaHpki8TvIV7/iuiUCrjRYbO/ZzLa49Yahvof7rZEC4c7ipWERpuvszB8
         BE9dHBnsbI0qakDgVFF/FXTi5lK3cGr/ztqSlBCclPTAOJRfaBFR8dcvnbmKiHjjjp9Q
         frWsgnY+qYBVXhuCSt5zRXIZ4b999MimJUYciCmLJTDajLpD721tDlji3YG+aCwlIPpU
         JfkASBnZA3t2pZOPjT2ih0ipXSfZ5vDzTy+xyNGlX6wFytJU8CQna1GnibiEembJuTDh
         pQr5e5HYngea7pcA+AFyHFhibD13/PIUmp3tEN9SkTHRQzFihnAErwsWlx0kudv/6tdg
         0/xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:dkim-signature:date;
        bh=fxMD3HagbWX8iHpC8AfOIPZAdw2x4fRx2NM5+fDxT/o=;
        b=XZCK5zTksxcFWjOshRpJ+JCVRVk3bENWRK6SjBwZu7o1wsSkyQ51/Zgfx+DsmKjVV4
         NEEtM2bw5b6b7tEXhkjfY2Xmb+DV8gmOj0eXxTfa3/+yB0Gvv8M8KY68vXjfZhJHrVny
         etJ+zswwae5yozqR69T6HHY/WxpfI9vIA4PbAYjQfA32/4S4tY8Ol9AWMP0CPMJXlJSn
         cHLPWZ+ryBB+6OAWd11Il/z215gnl06kHJRFpWdWh6PoDpbcwdvPmSbfYOTp8KsMc+u0
         MZoZI40Q3XKnp2y8uvKrhLHxPFjMqEHOB2p7DN5W65NfftvDu7flkPpzYQ8+TgTLdb5R
         7etQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=gxZrBLg1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f26si25001uao.0.2020.12.03.12.49.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Dec 2020 12:49:18 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Thu, 3 Dec 2020 12:49:14 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: alex.popov@linux.com
Cc: Alexander Potapenko <glider@google.com>, Kees Cook
 <keescook@chromium.org>, Jann Horn <jannh@google.com>, Will Deacon
 <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov
 <dvyukov@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
 <penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Masahiro Yamada <masahiroy@kernel.org>, Masami
 Hiramatsu <mhiramat@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 Peter Zijlstra <peterz@infradead.org>, Krzysztof Kozlowski
 <krzk@kernel.org>, Patrick Bellasi <patrick.bellasi@arm.com>, David Howells
 <dhowells@redhat.com>, Eric Biederman <ebiederm@xmission.com>, Johannes
 Weiner <hannes@cmpxchg.org>, Laura Abbott <labbott@redhat.com>, Arnd
 Bergmann <arnd@arndb.de>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Daniel Micay <danielmicay@gmail.com>, Andrey Konovalov
 <andreyknvl@google.com>, Matthew Wilcox <willy@infradead.org>, Pavel Machek
 <pavel@denx.de>, Valentin Schneider <valentin.schneider@arm.com>, kasan-dev
 <kasan-dev@googlegroups.com>, Linux Memory Management List
 <linux-mm@kvack.org>, Kernel Hardening
 <kernel-hardening@lists.openwall.com>, LKML <linux-kernel@vger.kernel.org>,
 notify@kernel.org
Subject: Re: [PATCH RFC v2 2/6] mm/slab: Perform init_on_free earlier
Message-Id: <20201203124914.25e63b013e9c69c79d481831@linux-foundation.org>
In-Reply-To: <1772bc7d-e87f-0f62-52a8-e9d9ac99f5e3@linux.com>
References: <20200929183513.380760-1-alex.popov@linux.com>
	<20200929183513.380760-3-alex.popov@linux.com>
	<CAG_fn=WY9OFKuy6utMHOgyr+1DYNsuzVruGCGHMDnEnaLY6s9g@mail.gmail.com>
	<1772bc7d-e87f-0f62-52a8-e9d9ac99f5e3@linux.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=gxZrBLg1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 3 Dec 2020 22:50:27 +0300 Alexander Popov <alex.popov@linux.com> wrote:

> On 30.09.2020 15:50, Alexander Potapenko wrote:
> > On Tue, Sep 29, 2020 at 8:35 PM Alexander Popov <alex.popov@linux.com> wrote:
> >>
> >> Currently in CONFIG_SLAB init_on_free happens too late, and heap
> >> objects go to the heap quarantine being dirty. Lets move memory
> >> clearing before calling kasan_slab_free() to fix that.
> >>
> >> Signed-off-by: Alexander Popov <alex.popov@linux.com>
> > Reviewed-by: Alexander Potapenko <glider@google.com>
> 
> Hello!
> 
> Can this particular patch be considered for the mainline kernel?

All patches are considered ;) And merged if they're reviewed, tested,
judged useful, etc.

If you think this particular patch should be fast-tracked then please
send it as a non-RFC, standalone patch.  Please also enhance the
changelog so that it actually explains what goes wrong.  Presumably
"objects go to the heap quarantine being dirty" causes some
user-visible problem?  What is that problem?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201203124914.25e63b013e9c69c79d481831%40linux-foundation.org.
