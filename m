Return-Path: <kasan-dev+bncBCFYN6ELYIORBFGDUPXQKGQEISOQSUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id C77E5113FB4
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 11:53:08 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id a5sf1563075edn.14
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 02:53:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575543188; cv=pass;
        d=google.com; s=arc-20160816;
        b=TQqWl38uTC+lDvfEz3Q79CNSw/KoERzIAhuKoIdY2+6thP5S4bErzM2he8xUmMK4pl
         D/9v1JGYp2Bk6NlMpWfZB3EaoU8agmSLl/+o6CXuusAlMnlX4NLzJtVbseRrCV1uP0ff
         pKqK4TaIr1I1VX5sPEGVR/nGcJba9mZMiKl7hDSEB1TvhSzuGdMIx+nvKfOxqCwD45LJ
         GFtNTUxOAm/L7B+4pk8DNWbH7Yzk8Yhb/VQvJ8ZdLyhBvg4AD6wY8jo7bH6tCOJ6zqxJ
         dyJtoGayznPqeTYUEAK7FZMKwHrY9nZB8RSk6s4ELLOPdBmF5ke6+Qkj+OMvNo3eABoe
         /Jwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=ZaEb9bgEWrnpgBI9xRl6C1zR1UIRiOSgioN5lSgZJgs=;
        b=JSlbmZtofFkxt3HMl5U23PBorpis4/DmpGUJ35KI63YnFWqVRZ9m3a5U3Ll48nTYp2
         yk4aKVSh3ACu9cKCFkFDkaI3JlMv2ZkJXYUL5ppayfRWLAPzQrtKyJ0na4NO9UrQ9VDk
         YpcFxJRQIUEnxlcojkAYt3HOvUuHmRUF5UaD/typc0DbVfmb7S7ZGcNRaaq+boAYkXgy
         2vCR6ZXteSs9VHkjSQnHKNpEuyxQ5NE3q0tzUpno+eT4UxDFPZd87bSvM0t5GWOKG2S5
         /D0g6O2AB9m9pDkdP50EZRBFgu4lYIASpU32PusPlfbC6n4PYpYaf/mMLov5NG3Ar+qF
         HhUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dlH+v8GS;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZaEb9bgEWrnpgBI9xRl6C1zR1UIRiOSgioN5lSgZJgs=;
        b=fVsSyAxo4b35cYXbbKhTESeKQvcCgu860a4a2Lwp140cngOf1mt5VYvKG7X8DYn38e
         nw8jFoI2NZQtsOPsNXXSXBTbTR3yLkMXCMo9ZmrH1Z7xPEIbX2bvU+B6o55xPsEPgJjX
         B3KqYeLkRjxsLuhRXX00NucAFNeBO68F6VlTbXzWBHlFUha6q0ASR6hQ8GPJFkhr4Uj+
         n6IbWo76X5my2a0zcBE+BgTE6zUw5AKWN7aGiOOOFsaS/j67Ut5vwZky1D+LurWiJ+1X
         WN8R+/CLHyOfBtnnBV7FYZ/jDErTwZEeiARIG2qWhxCs5AzMgBjHjXJqn97yXheRJ0NA
         sPVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZaEb9bgEWrnpgBI9xRl6C1zR1UIRiOSgioN5lSgZJgs=;
        b=iJzruSTysNgxILLsAPPoMcdovIFbEKG8UITH4i/ubxGrenhVG2ciT2qqpwkRvDFb52
         0O31SdW5jqSQkJ+3dNuY1mCkz4TM8pbzOeRSzrBiL/zLSzOh+shLa/tqtz7AihFRniQm
         Y5ECMa4sxmANDjpUjQ4cSdiibZif7NkULweF/NG9ROzWy5s/EmYWmZrVbvMQOTABqw2F
         0qYugeGIDdSJvv3h/axZOAReMmR2UjMiLcvr2jEHVi9CRmdbBJUnYLUe33h60TKiLdat
         xIajftkfGHU4SscF5i+0lqMAc/WzEwoZKW4TMtcnl6snG0Zzq2w+I8wHtmTSwNOYKBKb
         nV4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWextbqW2ehf7FmEezeTWlR/swhGcHwB+KEMpST/4K6GyKL6IMj
	9JFp++36QVrdeh2SoCdzJlo=
X-Google-Smtp-Source: APXvYqzmNLwQ7ABXBn4uOYZYbZPJ6Z1sBK1dnUp2TwRRU7+RxTDQVLnLb/cfKxYT7S0xxDNkZ40R3A==
X-Received: by 2002:a17:906:da04:: with SMTP id fi4mr8732964ejb.24.1575543188536;
        Thu, 05 Dec 2019 02:53:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:548:: with SMTP id i8ls666023edx.9.gmail; Thu, 05
 Dec 2019 02:53:07 -0800 (PST)
X-Received: by 2002:a05:6402:1d13:: with SMTP id dg19mr3706903edb.165.1575543187933;
        Thu, 05 Dec 2019 02:53:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575543187; cv=none;
        d=google.com; s=arc-20160816;
        b=NjRXj8ZrAJ1gi5SmClcvszGhkfCH0B2NOlZFwdJNg+cSNCK/lXVL53zGpi5VSo2Qws
         m6sOhj1etWVXzL65hGGrEXsHN7dHg9WTytqYIQoWl4oSzqyEWEl7iaAnqcgFCdPXMJVc
         46ABk93Xmhfr02subFMSteRq4NsDjV4pGVfFOi4BFwuqWnqlR4nytTOSKKq9ecZ6d2g2
         dbezMB9VTJOPNlo/i8KLH6c3oYyfRGpp2uiTZXmBUsSr1IY0n0m4WbW7zDJwC96Q9o7f
         UFVJWX8uRZwpyltCeFTUmBCDE01CuvggFvXYXQjRoEEJdSEpLFUC9UKsO8ac+cqOWAwK
         xlcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=VZ3pcvbIa/5GjW3TrOtnvfQxM6Nrqq/Ve/xoy67596c=;
        b=0oLPGqIBgsJxC3Q4SbxGvPmig9txDGE9afnS8Q83xOwALsgg0Ia90Pj0PMLOC4GCM9
         nxgS+Yjyw94OMXlFQJH9kt9hWQAEgmkMYQR/EnRFSVW0l7MoXxA5NgDv7Tcff7QGDwJT
         TT4CtzmPA/esKbtdb8Hvto9p9fHmGxQTe9CKkX6yX2GL1XMeyDTOGsaEtugy/tWqijNo
         Yc/4TV3RWURfU4o/fFYsB8/nLS86+2cY2+91NbJhRjZQ3hpTVXOSUZdILlOOnT3R14qi
         ZJnf7haVSXPn3I0ir5JnXuEsfUGWGss4+MzER0UPqt7y3BOI3MAK3/RfRl5mkV93T7G6
         x+BA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dlH+v8GS;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [207.211.31.120])
        by gmr-mx.google.com with ESMTPS id cw7si662475edb.0.2019.12.05.02.53.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Dec 2019 02:53:07 -0800 (PST)
Received-SPF: pass (google.com: domain of pbonzini@redhat.com designates 207.211.31.120 as permitted sender) client-ip=207.211.31.120;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-25-ZUwW-RS8P8KG9FjSOH_d2A-1; Thu, 05 Dec 2019 05:53:06 -0500
Received: by mail-wr1-f70.google.com with SMTP id l20so1362541wrc.13
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 02:53:05 -0800 (PST)
X-Received: by 2002:adf:c446:: with SMTP id a6mr9047821wrg.218.1575543184810;
        Thu, 05 Dec 2019 02:53:04 -0800 (PST)
X-Received: by 2002:adf:c446:: with SMTP id a6mr9047792wrg.218.1575543184607;
        Thu, 05 Dec 2019 02:53:04 -0800 (PST)
Received: from ?IPv6:2001:b07:6468:f312:541f:a977:4b60:6802? ([2001:b07:6468:f312:541f:a977:4b60:6802])
        by smtp.gmail.com with ESMTPSA id f1sm11989134wro.85.2019.12.05.02.53.03
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 02:53:04 -0800 (PST)
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: Dmitry Vyukov <dvyukov@google.com>
Cc: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>,
 Daniel Thompson <daniel.thompson@linaro.org>,
 Daniel Vetter <daniel.vetter@ffwll.ch>, DRI
 <dri-devel@lists.freedesktop.org>, ghalat@redhat.com,
 Gleb Natapov <gleb@kernel.org>, gwshan@linux.vnet.ibm.com,
 "H. Peter Anvin" <hpa@zytor.com>, James Morris <jmorris@namei.org>,
 kasan-dev <kasan-dev@googlegroups.com>, KVM list <kvm@vger.kernel.org>,
 Linux Fbdev development list <linux-fbdev@vger.kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 linux-security-module <linux-security-module@vger.kernel.org>,
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Ingo Molnar <mingo@redhat.com>, Michael Ellerman <mpe@ellerman.id.au>,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Russell Currey <ruscur@russell.cc>, Sam Ravnborg <sam@ravnborg.org>,
 "Serge E. Hallyn" <serge@hallyn.com>, stewart@linux.vnet.ibm.com,
 syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
 Kentaro Takeda <takedakn@nttdata.co.jp>, Thomas Gleixner
 <tglx@linutronix.de>, the arch/x86 maintainers <x86@kernel.org>
References: <0000000000003e640e0598e7abc3@google.com>
 <41c082f5-5d22-d398-3bdd-3f4bf69d7ea3@redhat.com>
 <CACT4Y+bCHOCLYF+TW062n8+tqfK9vizaRvyjUXNPdneciq0Ahg@mail.gmail.com>
 <f4db22f2-53a3-68ed-0f85-9f4541530f5d@redhat.com>
 <CACT4Y+ZHCmTu4tdfP+iCswU3r6+_NBM9M-pAZEypVSZ9DEq3TQ@mail.gmail.com>
From: Paolo Bonzini <pbonzini@redhat.com>
Message-ID: <e03140c6-8ff5-9abb-1af6-17a5f68d1829@redhat.com>
Date: Thu, 5 Dec 2019 11:53:02 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.1
MIME-Version: 1.0
In-Reply-To: <CACT4Y+ZHCmTu4tdfP+iCswU3r6+_NBM9M-pAZEypVSZ9DEq3TQ@mail.gmail.com>
Content-Language: en-US
X-MC-Unique: ZUwW-RS8P8KG9FjSOH_d2A-1
X-Mimecast-Spam-Score: 0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pbonzini@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dlH+v8GS;
       spf=pass (google.com: domain of pbonzini@redhat.com designates
 207.211.31.120 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 05/12/19 11:31, Dmitry Vyukov wrote:
>> Ah, and because the machine is a KVM guest, kvm_wait appears in a lot of
>> backtrace and I get to share syzkaller's joy every time. :)
> I don't see any mention of "kvm" in the crash report.

It's there in the stack trace, not sure if this is what triggered my Cc:

 [<ffffffff810c7c3a>] kvm_wait+0xca/0xe0 arch/x86/kernel/kvm.c:612

Paolo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e03140c6-8ff5-9abb-1af6-17a5f68d1829%40redhat.com.
