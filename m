Return-Path: <kasan-dev+bncBDAMN6NI5EERBOUDZ6EAMGQEDGTOLPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 054B23E90D2
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 14:25:31 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id z18-20020a1c7e120000b02902e69f6fa2e0sf816662wmc.9
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 05:25:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628684730; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ysg29zyQ9aiXKMw9cwBuoqgTF+F6Tbi8EpdvvwZOxrm4RR8NaBdxxC9HvKIyVBaKJB
         jNPZ4TXhhIg3QMGstFEby0qcMgKsaVGwkfL+NBCRdPkAaGqQrelkcOQPSwk2y8PpjlEt
         JbddnpcCbUJX3MUbUyfAwkMgFTqJfLb7mdF+h3zvKUOgmZabB9PDud7T5tgO5vQp1kb2
         QavWJvr74kTYiU3cnGap1PnHbuosa7dnXZDq1g2u15lRJZR1f+1/eAGi5zAufT4QpUKz
         ICQOv0U4NtF0HV3M3+ccmCM3uZjR/zQ0lMJeDwlm8e0dOPhYDX6myJ8z6Oq8NB943tO0
         DNNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=L/xGBoOKYHEO8tkKBBjPf6WAQLQvkcfj3kEEn3z7aNc=;
        b=Ki7aLL80Z/flXE0/6hGeWWsUH2owvG7iuRhDv0cAD54lTwf3+CR+WkoqOf1/V3jMWS
         FlSXpD9ucqRK0XdLhB8P8h0KsrM4fDDaeM1IAiV/FUoygRxrRHModr88RP2sX4SX78ML
         1yQU0eYktFLtmP6we5pSy1TImrbWigGDoOFb7nlA30te8zWqreUrubx7H9KV7G2h2HLy
         DKwcrcw3AvIhdCGy/g3FKgO4wb6eDRaJW6JR01YN7cmWnsiTEpMD0egeVDyElihwaO1h
         /dVyvSvNPzJLmeU5cWHIpyyflV5e5FiTq9gv9GW5UE/vF+rDGi67LrJWU/c8jeN4X8XY
         xjjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=eaojQdye;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=L/xGBoOKYHEO8tkKBBjPf6WAQLQvkcfj3kEEn3z7aNc=;
        b=aLNK4ILDDm4rG6YJyvAtpzdUPR8LycTwjIxN3gUETTHYed5YvouLBiESrcMT413Y/I
         XYUTlfqZvvnr+Id4SCeTrQYKg5u2CchNEg0sIDlhaIsioCXHg/5TYfLGdNk7IapPTqPH
         gyLpKdoDN+GBufIlBkXCRNWl37wbXPMyxmQ/8NFBZQozLz18mSXVJemrFXMVf1cjFcVR
         sa0acdvYAn4sMScmMsGXatQkRpK4z4ZgnfBo/WPVmDC71ta6VtMaPKUSgyAPZZdjNg13
         f8eLw7wOIjy4UTEsl3XZktX2/UGJtC8EQ84MZbNEBhO5xr1uccYV5lQUJb79BMh7GtcT
         Oc1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=L/xGBoOKYHEO8tkKBBjPf6WAQLQvkcfj3kEEn3z7aNc=;
        b=siW0zZ2P4DXyuR4YNEAvB5IwsHcEmjnKV4MNFs2yMAeOhJRNONQhlBns1Q7jPX+EMn
         BC+kxXgCd4haixIgGMYMIgRMwWNNMhCQW188VLUNVsENY9cT2g3Zpwn0ubj9V2TOn9LZ
         xlxppl3eVECcnCPPwMCge4l2tVLz5hG7fZQ81kSFTGqhRg/SvjoKiPfUmZmQezAD3NSy
         rDDaSjGt0LC2AZ/V64eSJx4qh3S3VICFQZFgemZ9cWrQzRi2NvOkLkOwBnsuTaOc6oNq
         VmM7q0OwWCNVsQP26ZiEA139QxdOk1cGN2zBRndg4/ROPnjRUAdV/SnoTnKCIKmjA8nL
         VYsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SkwB01xYoh/k+hKIDVao+SkahSqEIqajNceGcTUh94Wc7BGUX
	2EgnHhzLssBltBSVTFJ5mCk=
X-Google-Smtp-Source: ABdhPJwjhuNIkVum8RQM/qrnEj0qS+b8E4Y/SZ1nqB1HgCRxlJsrRlyMEeEIAVlP1y1Ney+VGCCL3A==
X-Received: by 2002:adf:ef0d:: with SMTP id e13mr37681596wro.390.1628684730686;
        Wed, 11 Aug 2021 05:25:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1:: with SMTP id g1ls3032958wmc.3.canary-gmail;
 Wed, 11 Aug 2021 05:25:29 -0700 (PDT)
X-Received: by 2002:a1c:9a8b:: with SMTP id c133mr21881378wme.103.1628684729741;
        Wed, 11 Aug 2021 05:25:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628684729; cv=none;
        d=google.com; s=arc-20160816;
        b=mu1yRHgmtE9OIWQ38029/jrANp9JZxFnF5n4TKDZ/Q4i4pkmJEHc/FQsMq2lyTX4tO
         5fjxYPhh9yF/MgYfckicMa/kHpQCSB6BcNpVP25HRmsSF0Wx/3YCtYEGxPcTGErQ418c
         PfAWw+SxAGrmX39S0Uuy9mQgw8SrrdA7ndz/eZo9MfMnSDfMeIA0+yT3cRIUU2dngK48
         Iz24CbGakzREk71P0Smzm7PWWCoCkJHS4gHcnNvO0TFliDYDbglabQe8bF1L+Dk0oKIO
         oytPjQz4acPDbVfgXyy7at0VzpcILh5E+tm2brTbXh3b7V891GS1QIvmx/7eXM5p6VUC
         LyyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=9Fc7r61LCYAdoePXBxI4aA4CJKIy5jDNHM9L9gFB7dA=;
        b=fTMquyJLQVaCcn3co+lgIorwykWA0E830Ab5S7gbr2DVaID30QSdUbYdVmCNtxZhvW
         YIt9JFdYhlZV5OydUz37018yursH2Q2mhI8AWYX7e12dBzQnuxFE0fhMNhKXzYudTnD1
         rbr+Nz7PzK3093MKYnn4ZFB8iCxtMWRVQ0TtPO4C78cWPIw9sYOrPHlNuV17vcajtssj
         pSezWTV2UZCdjd3DZudHg3HWLayqAUyF163pJu7g9d9RG6clwitI1MIAd1hiH13xWbBk
         d6rIrhgsGBLjxvCdoC8B6RhtDLCYiV8gqrnieh+E6BTEXX7XKcNxETWxLySxNxNaLjmJ
         5WAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=eaojQdye;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id h7si310898wro.2.2021.08.11.05.25.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Aug 2021 05:25:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Clark Williams <williams@redhat.com>, Steven Rostedt
 <rostedt@goodmis.org>, Dmitry Vyukov <dvyukov@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH PREEMPT_RT] kcov:  fix locking splat from
 kcov_remote_start()
In-Reply-To: <20210811090033.wijh4v37wlnny3ox@linutronix.de>
References: <20210809155909.333073de@theseus.lan>
 <20210810095032.epdhivjifjlmbhp5@linutronix.de> <87sfzhox15.ffs@tglx>
 <20210811090033.wijh4v37wlnny3ox@linutronix.de>
Date: Wed, 11 Aug 2021 14:25:29 +0200
Message-ID: <87czqkp3ra.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=eaojQdye;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Wed, Aug 11 2021 at 11:00, Sebastian Andrzej Siewior wrote:
> On 2021-08-10 22:38:30 [+0200], Thomas Gleixner wrote:
>> And that matters because? kcov has a massive overhead and with that
>> enabled you care as much about latencies as you do when running with
>> lockdep enabled.
>
> I wasn't aware of that. However, with that local_irq_save() ->
> local_lock_irqsave() swap and that first C code from
> Documentation/dev-tools/kcov.rst I don't see any spike in cyclictest's
> results. Maybe I'm not using it right=E2=80=A6

The problem starts with remote coverage AFAICT.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87czqkp3ra.ffs%40tglx.
