Return-Path: <kasan-dev+bncBD63B2HX4EPBBFOGVCVQMGQEYF4YL7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C61A801266
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Dec 2023 19:16:55 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-285b77f7e1fsf2275424a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Dec 2023 10:16:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701454613; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rvq6VOLtoM1Piq/Ha0WIphEV5kwDS9bkdd3d8E7sDfzQ+hL17UskfTYp+BAR7huHbM
         6WngqYSZp0l1NZW142vTVly7ApntZ1hqLcERTSnQqCApEoM+r//K/1YOsKiu0mZqyBLf
         uXbagQGFeNIHEQIwqKAXUvg95mMrf+9V1k5VSdhvNZstTVKjPcNEG3ewZpaR8Qa+NZP4
         UxJNTtW5uZXo81f4/dfb0zZumqlmKJoo6etG3aizi0EhLOkqRwan9VMFHOkBrzXWAuaq
         kf7XkLmlTZZ1esAKRoAiLj7T+uAiFvqJnzAhHISBR9xcgI5P03uYuS8vwFln6ESqLLIk
         i2FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=k3wJBsphzA667CwNncdT93LUdCIV0zo4Ty5by+gLv0A=;
        fh=BCL3G4/EB/6E43qIQvqiTmSskf1MQ2+iKF4M83YUI6k=;
        b=PN2nPIKBk1bBakh7MMnhy70YEvKwlxevqegIy5NBoyzTJOWTsk8of1MOAOLVDzLNm/
         uvSNuwGbAwt6coFV6/ZQY+PZfE044xmWQg/wqZqYJ68bs6ltTrY/w+W8boQOQ/nv8+r6
         gLPgdvkv8tcWFjdWFBQr3SGFZcky9OoWkKa+AzjLR8tLLvxfxnoo+jFO6Ss8H+ouziZC
         pauKLhqwnxuC/E9WsWzjWEnV12XA7YKVC0+Yy2cpltbsGCLlXdVe+20zzyovEJL0zW7D
         MTFeQxnw3On8bVIvUaVmLG984wo6uBT6sz4I5jhE/hUAgE0EbsOHKXMDl7E4tzb2IMgd
         AkIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google2022 header.b=drT40XQu;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701454613; x=1702059413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=k3wJBsphzA667CwNncdT93LUdCIV0zo4Ty5by+gLv0A=;
        b=DItgEaobm4CFrwYrLTi0BUpGbikiH6qplXZQLoX/+MnWpTP9IBaI8S+LOLESBApPDv
         JWurCS1LHTlyH7l+mFiZcSli95CFH2rhTqEHpkowRoyMUHW76+S9j33dbnVWPTgD/dGw
         hMmeFryZ87SNVkwMzaLrp/F2gcxRB75U2RILuCkssGq0JaUH4gVIX6cMvGPT1M6unZKq
         wNenVW0yE2tnYKXeXJEnqJZkly4TVrpNub2229HtwEzQ4Se+ckN9/NZCO1834QqbEEHk
         J4l4gxcpZf/qKu2ufy+zrowQUCcCP5cAc2VnDuHMYHwcJI+8rZ0c3y5pouvDAmybbFKQ
         /Cqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701454613; x=1702059413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=k3wJBsphzA667CwNncdT93LUdCIV0zo4Ty5by+gLv0A=;
        b=mAuGWfltbv2wr3sGEhhaTcnCbCJxjFrOf89ubZwhpl6qCm1BQle15jg2Iv5IXtzAWn
         l263IjnCv6qKGhOXjSmzf2nx8Ghu1CRe9nAcjCcbxBAwwUkVzVyJXLYyiZoWZFfnhOoo
         1YFQdCWQHRVG86h0/KEKEoHJamR7z400rVYsypOSgluojAieRi7FxduRhZWayu4+SzsB
         y1GO1tuQpArnDmAWMq1EOuJ+K0MbyX6bdSW2+73PYwGY4sedgUMAeWIQbbAHHM4oAm3t
         eCnimklRloooJQ2rIJ6p4b31tWCewY7DpnkIyT49KyX4FohnfSAcTs75JayLdhN4aUBx
         M6Ig==
X-Gm-Message-State: AOJu0YwvV4tCeEbFR4p52EZoTNByssSG+CgoSE0KVwHhx94U11J/xf4u
	xvZvUkWfz39w0ew3Y+uPc5o=
X-Google-Smtp-Source: AGHT+IFcoTcmWOBoRbqVqJjRiGwQFn7uVlP+bFJnVwXy7oY4tPEPuKgpySKdnxuQS6bw2a9e7ngOkg==
X-Received: by 2002:a17:90a:df95:b0:283:a384:5732 with SMTP id p21-20020a17090adf9500b00283a3845732mr41485962pjv.9.1701454613295;
        Fri, 01 Dec 2023 10:16:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:389:b0:285:196b:e7b9 with SMTP id
 ga9-20020a17090b038900b00285196be7b9ls1250775pjb.1.-pod-prod-00-us; Fri, 01
 Dec 2023 10:16:52 -0800 (PST)
X-Received: by 2002:a17:90a:2f63:b0:286:5127:d9ba with SMTP id s90-20020a17090a2f6300b002865127d9bamr5554793pjd.8.1701454612230;
        Fri, 01 Dec 2023 10:16:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701454612; cv=none;
        d=google.com; s=arc-20160816;
        b=U5CT1N+DLWxWcOlpVZ6SWT6HagGLffpszpC/Syvf+UcFWns316DqUpGovOWGi8kuQf
         BcQUHZNMn39YudzUU6EcrlArWVfG3YmcZeWoHOQLrUXQ7qtnnZ0SQbPxN2d+I5fCtgfA
         JgX11VUR94ZQWJ4b93zKis7HSNxPb5qlLQJNcgCY7lvCcdxoagJZ9EsbLltRfEOCjPzD
         nRc1ykYI+nZyum+PuQ1DEcbFVcTQkteNWwlGy0Kbi884rT6A1LWkpQJ7tTpZjidS7i3t
         fN5tYaL+4SIAJHlW+EjqUOgPOa3TCNn8JlkK11Pb67a94eV7wubntlK8Ui+B1Yy26W5y
         LZ5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=4ebbCKVYhmxFesM9IONNBoJ5hFIr8xSzZ7n3Tl7QDgM=;
        fh=BCL3G4/EB/6E43qIQvqiTmSskf1MQ2+iKF4M83YUI6k=;
        b=X7GoJeMaw+8ObVzN5lIsOwnz7dUYetKMtIZmAaHAkTnJJuwlLVM08+H/LAx3AW+dCB
         YXCzUMhbBTMTKSu2XSsj620cDZTgKSSfKD7F1CA04+8x5L0AXqmRncrl9Rmw6dCav9I8
         4GT6lDNNWz32cVQXPdbtW3OJZnjscn/sr0dVoRSU5/+vPdR8jZ30CNAX82wSCjpuWEIg
         knWwquGmpiFfDiH9mEeLCSFPVCZfqzsxNIKv56B/UEKgum7Etmns8KZxVFob38iEtvbO
         Njv9z6cjWjg7z0okEug+eDQw+PYiPaO9MLTxmHaOXbC6Ntrx67WGBzg38/cWePRhVCht
         i+4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google2022 header.b=drT40XQu;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id nu8-20020a17090b1b0800b002864835846asi230463pjb.0.2023.12.01.10.16.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Dec 2023 10:16:52 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id 98e67ed59e1d1-285e54f32d3so426472a91.1
        for <kasan-dev@googlegroups.com>; Fri, 01 Dec 2023 10:16:52 -0800 (PST)
X-Received: by 2002:a17:90b:1dc8:b0:285:71b5:7b7d with SMTP id pd8-20020a17090b1dc800b0028571b57b7dmr26374435pjb.0.1701454611756;
        Fri, 01 Dec 2023 10:16:51 -0800 (PST)
Received: from cork (c-73-158-249-15.hsd1.ca.comcast.net. [73.158.249.15])
        by smtp.gmail.com with ESMTPSA id ds20-20020a17090b08d400b002801ca4fad2sm5439916pjb.10.2023.12.01.10.16.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Dec 2023 10:16:51 -0800 (PST)
Date: Fri, 1 Dec 2023 10:16:49 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com
Subject: Re: dynamic kfence scaling
Message-ID: <ZWojEV6Ct9J4pT2I@cork>
References: <ZWgml3PCpk1kWcEg@cork>
 <CANpmjNMpty5+g76RLy5uZARZAfx+Uzr+z5uAKMp-om9__2O77Q@mail.gmail.com>
 <ZWjMC9FXSEXZjNw9@cork>
 <CANpmjNMQMzsPan_1MB98h7M8c5qXeum35MEhohtuCA6OqC4LSg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNMQMzsPan_1MB98h7M8c5qXeum35MEhohtuCA6OqC4LSg@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google2022 header.b=drT40XQu;
       spf=pass (google.com: domain of joern@purestorage.com designates
 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Fri, Dec 01, 2023 at 12:25:01PM +0100, Marco Elver wrote:
>=20
> The problem is we can't "just" hand out virtual addresses slab
> allocations: https://lore.kernel.org/lkml/CANpmjNO8g_MB-5T9YxLKHOe=3DMo8A=
WTmSFGh5jmr479s=3Dj-v0Pg@mail.gmail.com/

Ouch!  I didn't realize that "kmalloc returns memory with a simple 1:1
virt->phys mapping" is such a fundamental thing.

Which makes me wonder.  Is there a solid reason why we depend on the
simple mapping or is that mostly because we've historically always had
it and nobody ever tried to remove it?  True virt_to_phys() is more
expensive, but CPUs spend a lot of silicon on making it efficient.

I did a quick grep and couldn't see any callers where making virt_to_*
more generic would significantly hurt performance.  So maybe...

...but I should resist the temptation.  I don't have the time for yet
another project right now.

J=C3=B6rn

--
You can't do much carpentry with your bare hands and you can't do much
thinking with your bare brain.
-- unknown

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZWojEV6Ct9J4pT2I%40cork.
