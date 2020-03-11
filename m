Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBIU4UPZQKGQEXWSCUUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 529C81816F9
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 12:40:19 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id n11sf1646945edi.5
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 04:40:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583926819; cv=pass;
        d=google.com; s=arc-20160816;
        b=F6fm4jprPC0N/G3chWScW4PuU3SbRAsvisGewPwJ2VvUwwKAqNR4uNUi1ov+R2DvM9
         iFaDCvd4ow88HxRTGOUq3ZkV4qPdtLr3QCo+tZ/g4SfYkcJTCRIP3V2YbN7PhHcyjVse
         CbL9u00SIyP4wM03Ol59b7jM+qMe9r7ZoYaCXtOftGTI1BJpBAKsczaqISOx1ZYyFgRF
         lph/nXKL0bG0h7/jnsHKnnYbE1+vaZCE1rKjPDV+tjcLQCv/2VY7Wp7TTjb11j7CLLGe
         zQv5xruTaIf0fUnBGAtuDsrF6eCs3M9mfi2jEPSqqvHu2uZi4UE9bbjJVqEnV2SRfoRo
         XKaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=Pg1JmpkbnMcztZEFkzBjAnkCQu3AVw8Z0OP866xuNFU=;
        b=sIcFldWRbKOKCFyJJZjMgoSF960ZIPCLo0gObcNHEyK0zZSIPPnjOFYOKj0wC/PKJ4
         fGLMiTg1kHyxNZuA2y0ktb8zxnemyhFh5QFqSzHcUTGJTIiWcZe1zI/Si1QFWszN1IAz
         KESCEPHx9/DhiAvTvHqu2rgJn0JxKi+6w+MXiSailzgTf2HBZrqBLuXQHcGXXkEglCye
         zFNvdOFjB5e9OdAOnR+UZnCN7U3tLVMeAvSDeif9UibQ4Pwn0FbPoU7ze4w7fye0mP5C
         eMH8e/vhsDvgtffyvjtVoURlnyNxyYqsOd7Dq1bIOKOc56H5/l4OACwTjTpLqGqkeTZ4
         hNnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Pg1JmpkbnMcztZEFkzBjAnkCQu3AVw8Z0OP866xuNFU=;
        b=rz6HqA/PkBm9UeXFzULr1Jm4//nfUsTynLlsCbI2XioMjhxp9hnIxcIPXcCcF8ieCG
         r/sMILBXXjr/vEhxVjvYgVJBDPbMNFigA/o/UNV+8v7zkiTsQWIjf7KZSownOP/OZXJI
         dRYtMJF4EavoFjCt4Gj87npO7rHzINQnmSgKrKv2zmmfq/9nKwUmUtJVAx+hztfLfiqt
         AqJ7qm2LgBRKDlTwcg+0yMgMYMtKTVYsP/1uC3zpo3SDnlSPQLVtZamcHCij/nmrYlqE
         9fR51vNl6wGHWUyUxg4ELCw3wFYptj3Z+kL5N3lxoxpqnZ7oiqO5GkqRXnUNZtQl7ljA
         KXqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pg1JmpkbnMcztZEFkzBjAnkCQu3AVw8Z0OP866xuNFU=;
        b=dgFt0jGYegT2XNjtNsjn1uxKfILpmioNfMyN/AkfnptG1EOcZK7pwEFOGRuog37JBH
         ZPjwLeoOySdrZM4ypTF1Y7wSiSxqjDf/V3e7ZRWz2HPArFfCnIhTnzteNPhaJSVcof6b
         XG7dpw6tddeltX175mQ06C+KrG7xxVw9SFwFGIn87yIMoHyKQIrKwoROa45eXjzA6unr
         h/UyaBiMzIfNaLMN4z5G9yHrzwdk3Uvzgr8xFI2eok7d4NknHLn+8Twv7onkXCousZf6
         xgQFH0ReDZkMamZHeZJtNoDYdJKKSI2ylhndGtNT4Cqs8SxMA2RsQvY6Ze04psfKEDiY
         8Eog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0ARl2ZI6Q1WpNUmG0Ylz/00QueW51015RcJuS5vZqVWizsnfan
	HW+KtIdb4CXJIwqMj1UW9LU=
X-Google-Smtp-Source: ADFU+vsropRd28eBSweuLhBgoquau8yBC65ZwmYyHWuANCCwFpjcKzJZnW0PLqAcXC+WdsDk0eV2oQ==
X-Received: by 2002:a17:906:edd0:: with SMTP id sb16mr1942433ejb.151.1583926819082;
        Wed, 11 Mar 2020 04:40:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:99d5:: with SMTP id n21ls358219edb.10.gmail; Wed, 11 Mar
 2020 04:40:18 -0700 (PDT)
X-Received: by 2002:aa7:d98b:: with SMTP id u11mr2476160eds.318.1583926818454;
        Wed, 11 Mar 2020 04:40:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583926818; cv=none;
        d=google.com; s=arc-20160816;
        b=C0XJ8DGe6G70LOyeJATBRzwkY6UOvBUx3ZiARGAHdbOH+mGW8rpspzfKyV6Rv/syI+
         1dJIOrbkbMUB+aRo8PZiXSfKR0HvYy+2PR/txXHlN17elrgkJ2bCFC1wRHWujRiq0UwR
         zciY0dAuQZuG2xMXn6s7dmnFeONA2t8wS8kpLBi71GWJxBhEYlKub1tEE2A7nhW4fuGt
         6yNY11gfQ4celgFxKPNc+g1p4Sk/R2ugEwS7sVy/3/B9Sc3G6O1nH7CGsGX63CyRG1O/
         S0lTJjJEz3Cw5hont9IAGl6yIL6rwqAfib6yctm48U63uiY01/EMVd/fAxt/uyTXNEMe
         Ggxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=Ozklw2Hhkyjkv1drDExj917NxmMqcqkKTitj6R9K+RQ=;
        b=mJ5jsFi13EV/oq5KVqLzrk1fdwVzGcKFYsrfTbhaby3BWYxBShf4WXBQs6b/fhqt9y
         x7m4gO9LjcnbQi5Sn3+ZxfF2B78DOUUrSjYFRHrO7l6T/JoWeLu0zwVBEj3xlAsQGQl3
         NdWX4LO/LVSE3V4OluX2XkHFRnwcgGapcWbc4w1j2IlTzA2Ts+68yhMUtGhx4SbwpSJ7
         oTiG5Q9RbgQt5wotaLrJgZ4hbnyEUcBIeedS+X+9utTMPs2yr3b1gSGYvDMRjXI9QeVU
         iZYyDJgv6MEREoYMBImaY8B0RTsc9KBhIAyYpZX5yKwXZQlDNRrK7oe8dZfn3+Ph1vFA
         gF2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id d7si90752edo.5.2020.03.11.04.40.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Mar 2020 04:40:18 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1jBziW-001C1S-CG; Wed, 11 Mar 2020 12:40:04 +0100
Message-ID: <e3bfa0844566db1a837534218fe128f66cfe2e79.camel@sipsolutions.net>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike
 <jdike@addtoit.com>,  Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins
 <brendanhiggins@google.com>, David Gow <davidgow@google.com>
Cc: linux-um@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Date: Wed, 11 Mar 2020 12:40:03 +0100
In-Reply-To: <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
References: <20200226004608.8128-1-trishalfonso@google.com>
	 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
	 (sfid-20200306_010352_481400_662BF174) <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
	 <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.2 (3.34.2-1.fc31)
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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


> Pid: 504, comm: modprobe Tainted: G           O      5.5.0-rc6-00009-g09462ab4014b-dirty
> RIP:  
> RSP: 000000006d68fa90  EFLAGS: 00010202
> RAX: 000000800e0210cd RBX: 000000007010866f RCX: 00000000601a9777
> RDX: 000000800e0210ce RSI: 0000000000000004 RDI: 000000007010866c
> RBP: 000000006d68faa0 R08: 000000800e0210cd R09: 0000000060041432
> R10: 000000800e0210ce R11: 0000000000000001 R12: 000000800e0210cd
> R13: 0000000000000000 R14: 0000000000000001 R15: 00000000601c2e82
> Kernel panic - not syncing: Kernel mode fault at addr 0x800e0210cd, ip 0x601c332b

Same if I move it to the original place from your v2 patch
(0x100000000000):

Kernel panic - not syncing: Kernel mode fault at addr 0x10000e0c7032, ip 0x601c332b

Not sure what to do now?

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e3bfa0844566db1a837534218fe128f66cfe2e79.camel%40sipsolutions.net.
