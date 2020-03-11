Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBYOTUXZQKGQEJNUG7LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A67FE182525
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 23:44:49 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id m29sf1305337lfp.4
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 15:44:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583966689; cv=pass;
        d=google.com; s=arc-20160816;
        b=iyUyncdyrNbnx+uJkEQ5GejKPsYJQZ7EK/vRxBAhFrR4fPCkY2vjm+nn41HjU0eP+Q
         DJBmjahlylyDBrrafjuhg+HipGdJER61ObUSWMs7ibOuMVetMYw7MW2fRoW8cNklz5Zh
         tNiwSPBBrXOlm5si2zMkBleXFdLFDhV50aqrPTHsm1W/vJpWwOhf7g8Or5CBBiV69ywE
         dJGUy9sYQh1/HvwVa1wqkzBlv/DSk4w6tdkXCGNXoN5fTSw6dPTCVdHZTu7wFNVzw5yd
         vhMrO1QNe7o0LleeVPlum7gYhg8rtGJjxVT2Ag76oJnwWvhKXnkwsE1ELih1PCy5lm0N
         /DAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=scSsEJ4XM8XKlNhcM/2hieMJJaOoJlOfIkHv2POofd4=;
        b=sR3b2jUMVfWb64XWtf6hsYQCkJpV0Lray6JXuQgXDUxDvqBfiY3wUlvh+/HZRmb/BP
         FJWwIYlqlL7U9t0okcwYEHw6pkhXZE4XL/rKQ6/6lI4D7zs3W9CumDI1vw5oW4Ly5PMB
         Oh9qWKO2C+fqy9UwT9rfGnP1TybQe7U8LhPvG0GKm90Wsj1geSN0vd1GYHIsDWXNp4sF
         HRR0H2CdtRvaUh3a5kb4ihDrNrXtgNGWL/o80JGyVebq2hCScxAs0GWogdMlaQMSNCIT
         4rJlBLTUWdMYkyhKqNjMUOtSOkJ7tBJBczXs/rVhEqXkDlEb8TjTQNIXyKEWXL6cSL6B
         rWmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=scSsEJ4XM8XKlNhcM/2hieMJJaOoJlOfIkHv2POofd4=;
        b=fne2eEB6h2co3NuONQiFvBnjProFjsNCn3sSgwbSeoppQ23sfY+nqpxOFjUosDc02U
         00cMUW6tsDpOW0pKJKrHELTMXYTUDc6Q5LJ5GT+AdPg9F+T1sZ3bl8lEfT5rt2VnuGJ7
         pqLzPn2B9ayA21kVNmHME8s5kPRAwuc1HzbKyWLEDHnzPYeQoU/+KPgisvqK9+nN8im/
         fBkTJ/SwASHC/Zc8DCuM80rkgdDrwNVrkEyxHcoCN1p+RwDleahzyaZVQaw4WyhA5jsD
         Ooi8ld97OWLLzpbE+ehwQZOZPyOP2tgIz8F03SV7ZrDdHr3/h9jSD4JbmuMQk6JlppHj
         6Onw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=scSsEJ4XM8XKlNhcM/2hieMJJaOoJlOfIkHv2POofd4=;
        b=stdJ3Zz9q37+8IQO+1FmGLw41XktEbgQrHX4sSOCDvgUjce5J/CaXTVm6iuwNu1MWS
         J7s/lZKe3AXy6oKBM6HyyzqOOwDZLon1aagjyY5mbd//xBmtZPvooDwk1AmBixRbAzeU
         DCsIbNCc2WH57JH5/rGIQe2hUbkpME+Uorp1ZZNGWeMU22dQcZlgmI8HhogFpNWLk8sS
         OEEDbCWSITxI6ofbRWNIK4sFqwroroNCEG5RnACVl7jXd9ZPkVcwxaIVLuJWtazqZQO7
         sbtiaV4cRqDEMW57Pjj1/9HBdvjTn6w7VFTOV8Kq+ce0aQ+qqmOINihPl+CmYJXMASX9
         QRMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0llTOg2bimLTuBfKVX5vHR00RrcWk0/k8rfemwPfR6gGq8naGT
	DAOiGPC47PYQiZOm5LpM5Rk=
X-Google-Smtp-Source: ADFU+vumFpnIPAtbKgB7JALpt4Q02hWycTguiIdUFlwYvVY8JzSzTsRQycDINnwLr0gowyrVUj6evQ==
X-Received: by 2002:ac2:569a:: with SMTP id 26mr3462093lfr.63.1583966689109;
        Wed, 11 Mar 2020 15:44:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:550:: with SMTP id q16ls694856ljp.1.gmail; Wed, 11
 Mar 2020 15:44:48 -0700 (PDT)
X-Received: by 2002:a2e:b88b:: with SMTP id r11mr3320211ljp.116.1583966688493;
        Wed, 11 Mar 2020 15:44:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583966688; cv=none;
        d=google.com; s=arc-20160816;
        b=VEHAYQfFzE/Jd3c/cnVTkIkfR9a0VUkG+jkDWuoTtHcTnNk6+4rn9yxbnU0+62FaF0
         R4gZRnyXaYs0JIkyhwTUf8uwX55GMSCsJ6JrDCqH5CRfJmPs9VLWMm6xVXVEKxWfmXPA
         rbo4PqIm/b94lr7wd7QaoQFZfzc+qMCp/SyBKlE1BI75/ta9W3Q+ufxExL4WeT1Rw/yY
         P7XQWGsK5sW0Jup5TSnifK/+ufGXEMRisuixkUjOiy+Q4+DqEyGRfuQmKHaL9d2jqk6Z
         FZV35+J6d+Femx/13Itgdy7ouPXplP5yXMZdHg0MaSZIqcqNAmQam4re1PTRq0DOeA5+
         6HAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=Np5sVl+jz1AQmSTMc0YDhjW9DPduTenXN5vRki8mXU8=;
        b=Qznm/HNcWHwLGdooeoY3SiUny6tHffcAEE9QsYhlWj1IP6zx8J9p1F+yhKAFMFxelR
         ZbivdpurVuMF8lcPQOWR6+Sj7USkYKIwY3YNkgpwP+2csCfqecdUdywLir0UPKsHUjjM
         fmLs7w9VARPk0vtxA6/4VdqEX71yeoCETChVsV1CFM006mTHCcI7MbnD/HDBwP6DoU5A
         5d8yuI3VrAKt1Z/TgLXTuta251UQ4phtz3jkF+yTcBRBHGDnQou7lwuKzwiY1oCOicLD
         +ZnIsimc6o7CBwIIgVtGb4rkqoj7Fe5nQLgbyRnYKuO8eDLzqaHQtssNmqRM6PcNHwXr
         0Ekw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id w6si158472lfa.1.2020.03.11.15.44.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Mar 2020 15:44:48 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1jCA5e-002chY-TR; Wed, 11 Mar 2020 23:44:39 +0100
Message-ID: <1fb57ec2a830deba664379f3e0f480e08e6dec2f.camel@sipsolutions.net>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, 
 anton.ivanov@cambridgegreys.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
  Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins
 <brendanhiggins@google.com>, David Gow <davidgow@google.com>,  kasan-dev
 <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
 linux-um@lists.infradead.org
Date: Wed, 11 Mar 2020 23:44:37 +0100
In-Reply-To: <CAKFsvULGSQRx3hL8HgbYbEt_8GOorZj96CoMVhx6sw=xWEwSwA@mail.gmail.com> (sfid-20200311_233314_128549_A453E950)
References: <20200226004608.8128-1-trishalfonso@google.com>
	 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
	 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
	 <CAKFsvULGSQRx3hL8HgbYbEt_8GOorZj96CoMVhx6sw=xWEwSwA@mail.gmail.com>
	 (sfid-20200311_233314_128549_A453E950)
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

On Wed, 2020-03-11 at 15:32 -0700, Patricia Alfonso wrote:

> I'll need some time to investigate these all myself. Having just
> gotten my first module to run about an hour ago, any more information
> about how you got these errors would be helpful so I can try to
> reproduce them on my own.

See the other emails, I was basically just loading random modules. In my
case cfg80211, mac80211, mac80211-hwsim - those are definitely available
without any (virtio) hardware requirements, so you could use them.

Note that doing a bunch of vmalloc would likely result in similar
issues, since the module and vmalloc space is the same on UML.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1fb57ec2a830deba664379f3e0f480e08e6dec2f.camel%40sipsolutions.net.
