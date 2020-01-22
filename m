Return-Path: <kasan-dev+bncBDQ27FVWWUFRBRU5T7YQKGQE2FRL2DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 43404144AC3
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2020 05:25:44 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id c4sf2145348oiy.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 20:25:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579667143; cv=pass;
        d=google.com; s=arc-20160816;
        b=qI+80/VEafsmmgaXFeE9iOVjlXKIorWAh82bT2cqlieErwJEQKPCYAciEJJr6DSM0U
         zrChwTC6H9wNlWVdXtlVCM4L1xy16zvde4H5RrxZ4sHpCwCuzEGHiqvqn2ODmS+C2r7B
         CsFJygTyYYz0elfnOUrqIjvcc5hew1bB+RSFsTEqffDFAMHoGvTXf0koE8LtE6p/mAz2
         5rDGKvv5xey9xA66iTQGj70OZXSdFQ8YAQng6owPLLlrjgFDx8fbtX4v6GFSJIgVOQ6Z
         elHMoatPEH5Fz53AlFXGpk7F6XWi4FH2sYs3w1svdqychXGHMMf/5WhH0myGwApeI01P
         XqBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:to:from
         :sender:dkim-signature;
        bh=4QuQXDY4QIiDz8K5JHs5pWvp4fNdJMAeLhbnWoARH48=;
        b=K8iMVdF5SACWnqP3R/djq2c9Qt+fd3eYmh0xC+TT3TdAIASm/s2QwrysBbpA/U9nH1
         12S2qGTMGQnpCsdv1DFUGBs5US824JqRZ1zUaprCADW8w1AbnIxNjVH/qP0L7KM3V9sI
         vanOHk/DyqiyLtvtxM+CzqpfBv7VK15TGnfZ6ksBv/I++0DPJd9Ea6e9fbHbLqPEo0wB
         fEuR6wbf4Qm3WxgtQohWqKtvzo6hVZLJ+HDiJee2ljs2M3EUCm4nf5tgOApvMAtndYuK
         ERPsy6drmWExy+0LCOzX7sfoDJnlTB8La3louD+uFcPivFAgcd+6ZzOB1vjTCjbPyzCn
         RR+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=B5xvv8pu;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4QuQXDY4QIiDz8K5JHs5pWvp4fNdJMAeLhbnWoARH48=;
        b=M+St7rj6x7iveBMCwJewIggG27wPXLFE4tUkFxRDRYkEu6ctH8P+1mGyPjnjgQJ+5S
         dVGaeEiSAcIndF+6pjRPJ3q7iC7+KHAatjulH/FNUKx8qereK6qqNn7gCmIQxNRykQXT
         QA+UMEa8fHw9O1EBz5ouLSRwITrvjxHMFfSmFnRsvY3VEtS5NMQZiWtJbtzEjpxuMBsb
         b0UFngz+fKfURzbDG8t12SAOvZ++1oy4vlpay6NwJImQgiguCiH6rgQhS1txD5BTjJJ9
         chK+dNpImFuSx1sIDdlASL6gUIsCfCnMEaCyK/U6LhXCJEKrGp1Bi+QB8R4HG05RmyaU
         Ghaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4QuQXDY4QIiDz8K5JHs5pWvp4fNdJMAeLhbnWoARH48=;
        b=j5YCM2audJc0MrkEQzwu5pluYVB8qb+RMG1S1cjhoeUOxSJVP92f1FW7C6tBmIiryC
         V1wDF8iwg+poa0BWgesvjh7g4uIr9O4zLfQsnOte80ij4FFHQHppHXbgY1shdSop8z7m
         6DFJ6CMletVK1nAsmA4vjv0EpnUYPE10GRsrzSkVVVBOChXpf8C0gy3wtAW6x9CCtfUn
         Mc+UMYWMtE2OloObBBLf92Rt7MeOsGGVFVDU9ZXxx7cyuUBv8CKsun+I8Pj1hcyK8psM
         9gRZLor+7+2wpwIPm9OihOw7QMwDkKeoXSE9uQJ2ElFan0+xrUKT2jDXIz1HxookV4zh
         jYiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWznmCKMFtewC/rll6aLDX/CYDYWF+LcYg7pLLV8C4Y1VeWq2GV
	muAf1IaTZjQUsQ7WXZ1lr4o=
X-Google-Smtp-Source: APXvYqzPEW6k0yx29vVZoAX651/9591+soFrGEjFbynkXMwv8SoytDEZpIDCEAN6DX7K6qLv8eC1Jw==
X-Received: by 2002:aca:503:: with SMTP id 3mr5336721oif.24.1579667143026;
        Tue, 21 Jan 2020 20:25:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:72da:: with SMTP id d26ls6856781otk.9.gmail; Tue, 21 Jan
 2020 20:25:42 -0800 (PST)
X-Received: by 2002:a9d:32c7:: with SMTP id u65mr6058264otb.224.1579667142625;
        Tue, 21 Jan 2020 20:25:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579667142; cv=none;
        d=google.com; s=arc-20160816;
        b=tuglxvbo4Vb0GCR07kCEUB+r0qdZj6ozRY4hfLcmakTrQLtBAvvfMql/eFrlvJLncN
         0U1vZysevkj8dY7MfXKKRmzaiu+v9XlkdA6p2OCysvLJUkSx0MgEOglWjM32N78l5Grh
         vBSgvBUr+gyvV4KXQo5A9fC9bUJ4SkVpouAhYcLdUDRM7+rSAPcNcagIxkHZq0J7NEL6
         +UMff65G0hiQIu1k3LNZzMuo1xL3Kr1B2VGKxGagAI0nzze1KaVPMPP0WIdwnf0LxTnh
         3rtmjnsTKO+GmNL4w63ETGaWXG2Im36E1/e1VsLqVRBsnIOiPhy4RGtcAyx+uD4QISuK
         I6LA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:to:from:dkim-signature;
        bh=p46K/p7jyUoEmoJcNjNXBHco0qcUxklws/5FMtIPmj4=;
        b=hHpKJJOaTNq/jgiFy7U6UnU+19ppa1Pym5KMsOucWL8mxajnsCpI66LbLYPxsyKs7n
         KavqBfNRx6KzLB0vgo9926MBhIgz8J/5DpzZXCK2L+nq/5paoYbSmK/t96QFZ+fRed+C
         L/n0f04xjtb+TpTk6Egff7LtU96VB+jn8frqWdjpAg3sTs34ZWOeuqkU98nT2yZfFsxp
         Mqmk7wypmQeux1Y1fHfe9R1UOxSxEOkGtAbxBKUd4aJEmImGZgEb/tsPX8zMcQ9DlpWb
         SVyCZM7XAXeyW1YWY2FFJKV6amAqr4/Yrc2g8LRaqLj0Fn7uABioP0yTzs4/YuaU5ZFf
         F13w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=B5xvv8pu;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id e14si2058060otr.1.2020.01.21.20.25.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jan 2020 20:25:42 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id kx11so2500033pjb.4
        for <kasan-dev@googlegroups.com>; Tue, 21 Jan 2020 20:25:42 -0800 (PST)
X-Received: by 2002:a17:902:8484:: with SMTP id c4mr9022713plo.43.1579667141754;
        Tue, 21 Jan 2020 20:25:41 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-cc3a-f29a-38f6-dc23.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:cc3a:f29a:38f6:dc23])
        by smtp.gmail.com with ESMTPSA id d24sm45845707pfq.75.2020.01.21.20.25.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Jan 2020 20:25:40 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Subject: Re: [PATCH v5 0/4] KASAN for powerpc64 radix
In-Reply-To: <8a1b7f4b-de14-90fe-2efa-789882d28702@c-s.fr>
References: <20200109070811.31169-1-dja@axtens.net> <8a1b7f4b-de14-90fe-2efa-789882d28702@c-s.fr>
Date: Wed, 22 Jan 2020 15:25:37 +1100
Message-ID: <87muagjewu.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=B5xvv8pu;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Christophe Leroy <christophe.leroy@c-s.fr> writes:

> Le 09/01/2020 =C3=A0 08:08, Daniel Axtens a =C3=A9crit=C2=A0:
>> Building on the work of Christophe, Aneesh and Balbir, I've ported
>> KASAN to 64-bit Book3S kernels running on the Radix MMU.
>>=20
>> This provides full inline instrumentation on radix, but does require
>> that you be able to specify the amount of physically contiguous memory
>> on the system at compile time. More details in patch 4.
>
> This might be a stupid idea as I don't know ppc64 much. IIUC, PPC64=20
> kernel can be relocated, there is no requirement to have it at address=20
> 0. Therefore, would it be possible to put the KASAN shadow mem at the=20
> begining of the physical memory, instead of putting it at the end ?
> That way, you wouldn't need to know the amount of memory at compile time=
=20
> because KASAN shadow mem would always be at address 0.

Good question! I've had a look. Bearing in mind that I'm not an expert
in ppc64 early load, I think it would be possible, but a large chunk of
work.

One challenge is that - as I understand it - the early relocation code
in head_64.S currently allows the kernel to either:
 - run at the address it's loaded at by kexec/the bootloader, or
 - relocate the kernel to 0

As far as I can tell book3s 64bit doesn't have code to arbitrarily
relocate the kernel.

It's possible I'm wrong about this, in which case I'm happy to reasses!

If I'm right, I think we'd want to implement KASLR for book3s first,
along the lines of how book3e does it. That would allow the kernel to be
put at an arbitrary location at runtime. We could then leverage that.

Another challenge is that some of the interrupt vectors are not easy to
relocate, so we'd have to work around that. That's probably not too big
an issue and we'd pick that up in KASLR implementation.

So I think this is something we could come back to once we have KASLR.

Regards,
Daniel

>
> Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87muagjewu.fsf%40dja-thinkpad.axtens.net.
